// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{anyhow, Context, Result};
use gvm_gateway_e2e::harness::{
    E2eHarness, ListResponse, PortList, Report, ReportFormat, ResultList, ScanConfig, ScanResult,
    Scanner, SessionResponse, Target, Task, TlsCertificateList,
};
use reqwest::{
    header::{CONTENT_DISPOSITION, CONTENT_TYPE},
    Response, StatusCode,
};

// Covers the target lifecycle contract clients rely on before creating scans.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_discovery_lifecycle_creates_lists_and_deletes_target() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut target_id = None;

    let run = async {
        let resources = select_discovery_resources(&harness, &session.token).await?;
        let target_name = harness.unique_name("nightly-discovery-target");
        let target = harness
            .create_target(&session.token, &target_name, &resources.port_list.id)
            .await?;
        target_id = Some(target.id.clone());
        eprintln!(
            "created target {} ({}) for host(s) {}",
            target.name,
            target.id,
            target.hosts.join(", ")
        );

        assert_created_target(&harness, &target, &target_name, &resources.port_list);
        let targets = harness.list_targets(&session.token).await?;
        assert_target_list_contains(&targets, &target);

        harness.delete_target(&session.token, &target.id).await?;
        target_id = None;
        assert_target_not_listed(&harness, &session.token, &target.id).await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_cleanup(&harness, &session.token, None, target_id.as_deref()).await;
    }
    finish_session(&harness, &session, run).await
}

// Covers task create/get/list/delete around the discovery scan prerequisites without starting a scan.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_discovery_lifecycle_creates_lists_and_deletes_task() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut task_id = None;
    let mut target_id = None;

    let run = async {
        let resources = select_discovery_resources(&harness, &session.token).await?;
        let created = create_discovery_task(&harness, &session.token, &resources).await?;
        task_id = Some(created.task.id.clone());
        target_id = Some(created.target.id.clone());

        let updated_task_name = harness.unique_name("nightly-updated-discovery-task");
        let updated_task = harness
            .update_task_name(&session.token, &created.task.id, &updated_task_name)
            .await?;
        assert_eq!(
            updated_task.id, created.task.id,
            "task id changed after update"
        );
        assert_eq!(
            updated_task.name, updated_task_name,
            "task update response did not expose changed name"
        );
        let fetched_task = harness.get_task(&session.token, &created.task.id).await?;
        assert_eq!(
            fetched_task.name, updated_task_name,
            "task read after update did not preserve changed name"
        );

        let tasks = harness.list_tasks(&session.token).await?;
        assert_task_list_contains(&tasks, &updated_task);

        harness
            .delete_task(&session.token, &created.task.id)
            .await?;
        task_id = None;
        assert_task_not_listed(&harness, &session.token, &created.task.id).await?;

        harness
            .delete_target(&session.token, &created.target.id)
            .await?;
        target_id = None;
        assert_target_not_listed(&harness, &session.token, &created.target.id).await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_cleanup(
            &harness,
            &session.token,
            task_id.as_deref(),
            target_id.as_deref(),
        )
        .await;
    }
    finish_session(&harness, &session, run).await
}

// Covers task action behavior for idle tasks without starting another live scan.
// The current gvmd-backed adapter accepts idle stop as a 200 no-op even though the
// REST test matrix calls out 409 as the desired illegal-transition response.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_discovery_task_actions_reject_non_stopped_resume_and_accept_idle_stop() -> Result<()>
{
    let (harness, session) = ready_session().await?;
    let mut task_id = None;
    let mut target_id = None;

    let run = async {
        let resources = select_discovery_resources(&harness, &session.token).await?;
        let created = create_discovery_task(&harness, &session.token, &resources).await?;
        task_id = Some(created.task.id.clone());
        target_id = Some(created.target.id.clone());

        let resume = harness
            .resume_task_response(&session.token, &created.task.id)
            .await?;
        assert_problem_response_status_in(
            resume,
            &[
                StatusCode::BAD_REQUEST,
                StatusCode::CONFLICT,
                StatusCode::BAD_GATEWAY,
            ],
            "resume non-stopped task",
        )
        .await?;

        let stop = harness
            .stop_task_response(&session.token, &created.task.id)
            .await?;
        assert_idle_stop_response(stop).await?;

        harness
            .delete_task(&session.token, &created.task.id)
            .await?;
        task_id = None;
        harness
            .delete_target(&session.token, &created.target.id)
            .await?;
        target_id = None;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_cleanup(
            &harness,
            &session.token,
            task_id.as_deref(),
            target_id.as_deref(),
        )
        .await;
    }
    finish_session(&harness, &session, run).await
}

// Covers the started scan and report drill-down contract around the report produced by a completed task.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_discovery_lifecycle_completes_scan_and_links_report() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut task_id = None;
    let mut target_id = None;

    let run = async {
        let resources = select_discovery_resources(&harness, &session.token).await?;
        let created = create_discovery_task(&harness, &session.token, &resources).await?;
        task_id = Some(created.task.id.clone());
        target_id = Some(created.target.id.clone());

        let action = harness.start_task(&session.token, &created.task.id).await?;
        assert!(
            !action.report_id.is_empty(),
            "start-task response did not include a report id"
        );
        eprintln!(
            "started task {}; report {}",
            created.task.id, action.report_id
        );

        let completed = harness
            .wait_for_task_completion(&session.token, &created.task.id)
            .await?;
        let report_ref = completed
            .last_report
            .as_ref()
            .or(completed.current_report.as_ref())
            .ok_or_else(|| {
                anyhow!(
                    "completed task {} did not expose a report reference",
                    completed.id
                )
            })?;
        assert_eq!(
            report_ref.id, action.report_id,
            "task report reference drifted from start-task response"
        );

        let report = harness
            .get_report(&session.token, &action.report_id)
            .await?;
        assert_eq!(report.id, action.report_id);
        assert_eq!(
            report.task.as_ref().map(|task| task.id.as_str()),
            Some(created.task.id.as_str()),
            "report did not point back to the created task"
        );
        assert!(
            report.scan_end.is_some(),
            "completed report {} was missing scanEnd",
            report.id
        );
        eprintln!(
            "report {} scanEnd={:?} resultCount={:?}",
            report.id, report.scan_end, report.result_count
        );

        let report_results = harness
            .get_report_results(&session.token, &action.report_id)
            .await?;
        eprintln!(
            "report results page={} perPage={} total={} items={}",
            report_results.pagination.page,
            report_results.pagination.per_page,
            report_results.pagination.total,
            report_results.data.len()
        );

        if let Some(total) = report.result_count.as_ref().and_then(|count| count.total) {
            assert!(
                report_results.pagination.total >= total
                    || report_results.data.len() as u32 >= total,
                "report result pagination under-reported total results"
            );
        }

        let reports = harness.list_reports(&session.token).await?;
        assert_report_list_contains(&reports, &report, &created.task);

        let report_formats = harness.list_report_formats(&session.token).await?;
        let pdf_report_format = harness.select_report_format_by_extension(
            &report_formats.data,
            "pdf",
            Some(&harness.config.pdf_report_format_id),
        )?;
        let csv_report_format = harness.select_report_format_by_extension(
            &report_formats.data,
            "csv",
            Some(&harness.config.csv_report_format_id),
        )?;
        assert_report_format_round_trip(&harness, &session.token, pdf_report_format).await?;
        assert_report_format_round_trip(&harness, &session.token, csv_report_format).await?;

        assert_report_format_export_job(
            &harness,
            &session.token,
            &report,
            &pdf_report_format.id,
            "application/pdf",
            "pdf",
        )
        .await?;
        assert_report_format_export_job(
            &harness,
            &session.token,
            &report,
            &csv_report_format.id,
            "text/csv",
            "csv",
        )
        .await?;
        assert_json_report_export_job(&harness, &session.token, &report).await?;

        let first_results_page = harness
            .get_report_results_page(&session.token, &action.report_id, 1, 1)
            .await?;
        assert_report_results_page_links_report(
            "report results",
            &first_results_page,
            &report,
            &created.task,
            Some(1),
        );
        assert_report_result_total_consistent("report results", &first_results_page, &report);

        let top_level_results = harness.list_results_page(&session.token, 1, 1).await?;
        assert_result_pagination_shape("top-level results", &top_level_results, Some(1));

        let result_to_fetch = first_results_page
            .data
            .first()
            .or_else(|| report_results.data.first())
            .or_else(|| top_level_results.data.first())
            .cloned();
        if let Some(result) = result_to_fetch {
            let fetched = harness.get_result(&session.token, &result.id).await?;
            assert_eq!(fetched.id, result.id, "result id drifted on read");
            assert!(
                !fetched.name.trim().is_empty(),
                "fetched result {} returned an empty name",
                fetched.id
            );
            if let Some(report_ref) = result.report.as_ref() {
                assert_eq!(
                    fetched.report.as_ref().map(|report| report.id.as_str()),
                    Some(report_ref.id.as_str()),
                    "result report reference drifted on read"
                );
            }
        } else {
            eprintln!("result detail read skipped because the completed scan returned no results");
        }

        if harness
            .report_detail_subresources_supported(&session.token, &action.report_id)
            .await?
        {
            // These four resources are purpose-shaped report summaries. A
            // completed scan may legitimately produce empty categories, but
            // every route must preserve its pagination and typed row shape.
            for subresource in ["hosts", "ports", "applications", "cves"] {
                let summaries = harness
                    .get_report_summary_page(
                        &session.token,
                        &action.report_id,
                        subresource,
                        1,
                        25,
                    )
                    .await?;
                assert_pagination_shape(&format!("report {subresource}"), &summaries);
                for summary in summaries.data {
                    assert!(
                        summary.id.is_some() || summary.name.is_some() || summary.severity.is_some(),
                        "report {subresource} returned an empty summary row"
                    );
                }
            }

            // gvmd operating-system rows are not generic id/name/severity
            // summaries. Keep this live assertion purpose-shaped so an
            // upstream parser mismatch cannot silently deserialize rows as
            // empty JSON objects again.
            let operating_systems = harness
                .get_report_operating_systems_page(&session.token, &action.report_id, 1, 25)
                .await?;
            assert_pagination_shape("report operating systems", &operating_systems);
            for operating_system in operating_systems.data {
                assert!(
                    operating_system.best_os_cpe.is_some()
                        || operating_system.best_os_text.is_some()
                        || operating_system.hosts_count.is_some(),
                    "report operating systems returned an empty summary row"
                );
            }

            let vulnerabilities = harness
                .get_report_vulnerabilities_page(&session.token, &action.report_id, 1, 25)
                .await?;
            assert_report_vulnerabilities_page_links_report(
                &vulnerabilities,
                &report,
                &created.task,
            );

            let tls_certificates = harness
                .get_report_tls_certificates_page(&session.token, &action.report_id, 1, 25)
                .await?;
            assert_tls_certificate_pagination_shape(
                "report TLS certificates",
                &tls_certificates,
                25,
            );

            let report_errors = harness
                .get_report_errors_page(&session.token, &action.report_id, 1, 25)
                .await?;
            assert_report_results_page_links_report(
                "report errors",
                &report_errors,
                &report,
                &created.task,
                Some(25),
            );

            let closed_cves = harness
                .get_report_closed_cves_page(&session.token, &action.report_id, 1, 25)
                .await?;
            assert_report_results_page_links_report(
                "report closed CVEs",
                &closed_cves,
                &report,
                &created.task,
                Some(25),
            );
        } else {
            let unsupported = harness
                .get_report_vulnerabilities_problem(&session.token, &action.report_id, 1, 25)
                .await?;
            assert_eq!(unsupported.code, "not_implemented");
            assert!(
                unsupported.detail.contains("get_report_vulns"),
                "expected unsupported detail to mention get_report_vulns, got {}",
                unsupported.detail
            );
            eprintln!(
                "skipping report-detail subresource assertions because the current stable gvmd container does not support get_report_vulns"
            );
        }

        Ok(())
    }
    .await;

    best_effort_cleanup(
        &harness,
        &session.token,
        task_id.as_deref(),
        target_id.as_deref(),
    )
    .await;
    finish_session(&harness, &session, run).await
}

struct DiscoveryResources {
    scan_config: ScanConfig,
    scanner: Scanner,
    port_list: PortList,
}

struct CreatedDiscoveryTask {
    target: Target,
    task: Task,
}

async fn ready_session() -> Result<(E2eHarness, SessionResponse)> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;

    let session = harness.create_session().await?;
    eprintln!(
        "created session; gmpVersion={} expiresIn={}s",
        session.gmp_version, session.expires_in
    );

    Ok((harness, session))
}

async fn finish_session(
    harness: &E2eHarness,
    session: &SessionResponse,
    run: Result<()>,
) -> Result<()> {
    if let Err(error) = harness.delete_session(&session.token).await {
        eprintln!("best-effort session cleanup failed: {error:#}");
    }

    run
}

async fn select_discovery_resources(
    harness: &E2eHarness,
    token: &str,
) -> Result<DiscoveryResources> {
    let scan_configs = harness.list_scan_configs(token).await?;
    let scan_config = harness.select_discovery_scan_config(&scan_configs)?.clone();
    eprintln!(
        "selected discovery scan config {} ({})",
        scan_config.name, scan_config.id
    );

    let scanners = harness.list_scanners(token).await?;
    let scanner = harness.select_scanner(&scanners)?.clone();
    eprintln!("selected scanner {} ({})", scanner.name, scanner.id);

    // Real gvmd requires a target to carry a concrete port list before a task
    // can run, so the E2E suite proves the same contract real clients use.
    let port_lists = harness.list_port_lists(token).await?;
    let port_list = harness.select_port_list(&port_lists)?.clone();
    eprintln!("selected port list {} ({})", port_list.name, port_list.id);

    Ok(DiscoveryResources {
        scan_config,
        scanner,
        port_list,
    })
}

async fn create_discovery_task(
    harness: &E2eHarness,
    token: &str,
    resources: &DiscoveryResources,
) -> Result<CreatedDiscoveryTask> {
    let target_name = harness.unique_name("nightly-discovery-target");
    let target = harness
        .create_target(token, &target_name, &resources.port_list.id)
        .await?;
    eprintln!(
        "created target {} ({}) for host(s) {}",
        target.name,
        target.id,
        target.hosts.join(", ")
    );
    assert_created_target(harness, &target, &target_name, &resources.port_list);

    let task_name = harness.unique_name("nightly-discovery-task");
    let task = harness
        .create_task(
            token,
            &task_name,
            &target.id,
            &resources.scan_config.id,
            &resources.scanner.id,
        )
        .await?;
    eprintln!("created task {} ({})", task.name, task.id);
    assert_created_task(&task, &task_name, &target, resources);

    Ok(CreatedDiscoveryTask { target, task })
}

fn assert_created_target(
    harness: &E2eHarness,
    target: &Target,
    expected_name: &str,
    port_list: &PortList,
) {
    assert_eq!(target.name, expected_name);
    assert!(
        target
            .hosts
            .iter()
            .any(|host| host == &harness.config.target_host),
        "created target did not include configured host {}",
        harness.config.target_host
    );
    if let Some(actual_port_list) = target.port_list.as_ref() {
        assert_eq!(
            actual_port_list.id, port_list.id,
            "created target did not reference the selected port list"
        );
    }
}

fn assert_created_task(
    task: &Task,
    expected_name: &str,
    target: &Target,
    resources: &DiscoveryResources,
) {
    assert_eq!(task.name, expected_name);
    assert!(
        matches!(
            task.status.as_str(),
            "New" | "Requested" | "Running" | "Done"
        ),
        "created task returned unexpected lifecycle status {}",
        task.status
    );
    if let Some(actual_target) = task.target.as_ref() {
        assert_eq!(
            actual_target.id, target.id,
            "created task did not reference the created target"
        );
    }
    if let Some(actual_config) = task.scan_config.as_ref() {
        assert_eq!(
            actual_config.id, resources.scan_config.id,
            "created task did not reference the selected scan config"
        );
    }
    if let Some(actual_scanner) = task.scanner.as_ref() {
        assert_eq!(
            actual_scanner.id, resources.scanner.id,
            "created task did not reference the selected scanner"
        );
    }
}

fn assert_target_list_contains(targets: &ListResponse<Target>, target: &Target) {
    assert!(
        targets
            .data
            .iter()
            .any(|listed| listed.id == target.id && listed.name == target.name),
        "target list did not include created target {} ({})",
        target.name,
        target.id
    );
}

fn assert_task_list_contains(tasks: &ListResponse<Task>, task: &Task) {
    assert!(
        tasks
            .data
            .iter()
            .any(|listed| listed.id == task.id && listed.name == task.name),
        "task list did not include created task {} ({})",
        task.name,
        task.id
    );
}

fn assert_report_list_contains(reports: &ListResponse<Report>, report: &Report, task: &Task) {
    assert_pagination_shape("reports", reports);
    let listed = reports
        .data
        .iter()
        .find(|listed| listed.id == report.id)
        .unwrap_or_else(|| panic!("report list did not include completed report {}", report.id));
    assert_eq!(
        listed.task.as_ref().map(|task| task.id.as_str()),
        Some(task.id.as_str()),
        "listed report did not point back to the completed task"
    );
}

async fn assert_json_report_export_job(
    harness: &E2eHarness,
    token: &str,
    report: &Report,
) -> Result<()> {
    let created_job = harness
        .create_json_report_export_job(token, &report.id)
        .await?;
    assert_eq!(
        created_job.kind, "report_export",
        "JSON report export returned unexpected job kind"
    );
    assert_eq!(
        created_job.report.id, report.id,
        "JSON report export job points at a different report"
    );
    assert_eq!(
        created_job.format, "json",
        "JSON report export job returned unexpected format"
    );

    let completed_job = harness
        .wait_for_job_succeeded(token, &created_job.id)
        .await?;
    let expected_location = format!("/api/v1/jobs/{}/result", created_job.id);
    assert_eq!(
        completed_job.result_location.as_deref(),
        Some(expected_location.as_str()),
        "completed JSON report export job exposed unexpected result location"
    );
    assert!(
        completed_job.expires_at.is_some(),
        "completed JSON report export job did not expose expiresAt"
    );

    let result = completed_job
        .result
        .as_ref()
        .context("completed JSON export job did not include result metadata")?;
    assert_eq!(
        result.content_type.as_deref(),
        Some("application/json"),
        "completed JSON export job reported unexpected content type"
    );
    assert!(
        result.size.unwrap_or_default() > 0,
        "completed JSON export job reported an empty artifact"
    );

    let export = harness
        .download_json_report_export(token, &created_job.id)
        .await?;
    assert_eq!(
        export.report.id, report.id,
        "downloaded JSON export contains a different report"
    );
    assert!(
        export.generated_at.is_some(),
        "downloaded JSON export did not include generatedAt"
    );
    Ok(())
}

async fn assert_report_format_export_job(
    harness: &E2eHarness,
    token: &str,
    report: &Report,
    report_format_id: &str,
    expected_content_type: &str,
    expected_extension: &str,
) -> Result<()> {
    let created_job = harness
        .create_report_format_export_job(token, &report.id, report_format_id)
        .await?;
    assert_eq!(
        created_job.kind, "report_export",
        "report-format export returned unexpected job kind"
    );
    assert_eq!(
        created_job.report.id, report.id,
        "report-format export job points at a different report"
    );
    assert_eq!(
        created_job.format, "gvmd_report_format",
        "report-format export job returned unexpected format"
    );

    let completed_job = harness
        .wait_for_job_succeeded(token, &created_job.id)
        .await?;
    assert!(
        completed_job.expires_at.is_some(),
        "completed report-format export job did not expose expiresAt"
    );

    let response = harness
        .download_report_export_response(token, &created_job.id)
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.context("read report export body")?;

    assert_eq!(
        status,
        StatusCode::OK,
        "report export {expected_extension} returned unexpected status {status}"
    );
    assert!(
        !body.is_empty(),
        "report export {expected_extension} returned an empty payload"
    );

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with(expected_content_type),
        "report export {expected_extension} returned content type {content_type}, expected {expected_content_type}"
    );

    let content_disposition = headers
        .get(CONTENT_DISPOSITION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_disposition.contains(&report.id)
            && content_disposition.contains(&format!(".{expected_extension}")),
        "report export {expected_extension} returned unexpected content disposition {content_disposition}"
    );

    // Regression coverage for gvmd PDF exports that include metadata before the
    // base64 payload: the REST download contract must expose decoded PDF bytes.
    if expected_content_type == "application/pdf" {
        assert!(
            body.starts_with(b"%PDF"),
            "PDF report export returned non-PDF bytes; payload starts with {:?}",
            &body[..body.len().min(32)]
        );
    }

    Ok(())
}

async fn assert_report_format_round_trip(
    harness: &E2eHarness,
    token: &str,
    expected: &ReportFormat,
) -> Result<()> {
    let fetched = harness.get_report_format(token, &expected.id).await?;
    assert_eq!(fetched.id, expected.id, "report-format id changed on read");
    assert_eq!(
        fetched.name, expected.name,
        "report-format read did not preserve the name"
    );
    assert_eq!(
        fetched.extension, expected.extension,
        "report-format read did not preserve the extension"
    );
    Ok(())
}

fn assert_report_results_page_links_report(
    resource: &str,
    page: &ResultList,
    report: &Report,
    task: &Task,
    expected_per_page: Option<u32>,
) {
    assert_result_pagination_shape(resource, page, expected_per_page);

    for result in &page.data {
        assert_scan_result_links_report(resource, result, report, task);
    }
}

fn assert_report_vulnerabilities_page_links_report(
    page: &ResultList,
    report: &Report,
    task: &Task,
) {
    assert_report_results_page_links_report("report vulnerabilities", page, report, task, Some(25));

    if let Some(total) = report.result_count.as_ref().and_then(|count| count.total) {
        assert!(
            page.pagination.total <= total,
            "vulnerability total {} exceeded report total {}",
            page.pagination.total,
            total
        );
    }

    for result in &page.data {
        assert!(
            result.nvt.is_some() || result.severity.is_some() || !result.name.trim().is_empty(),
            "vulnerability result {} did not expose finding metadata",
            result.id
        );
    }
}

fn assert_tls_certificate_pagination_shape(
    resource: &str,
    response: &TlsCertificateList,
    expected_per_page: u32,
) {
    assert_eq!(
        response.pagination.page, 1,
        "{resource} list used an unexpected page"
    );
    assert_eq!(
        response.pagination.per_page, expected_per_page,
        "{resource} list used an unexpected page size"
    );
    if response.pagination.total == 0 {
        assert_eq!(
            response.pagination.total_pages, 0,
            "{resource} list returned totalPages for an empty result set"
        );
    } else {
        assert!(
            response.pagination.total_pages >= 1,
            "{resource} list returned no pages for a non-empty result set"
        );
    }
    assert!(
        response.data.len() <= response.pagination.per_page as usize,
        "{resource} list returned more items than its page size"
    );
    for certificate in &response.data {
        assert!(
            !certificate.subject.trim().is_empty(),
            "{resource} returned a certificate observation with an empty subject"
        );
    }
}

fn assert_scan_result_links_report(
    resource: &str,
    result: &ScanResult,
    report: &Report,
    task: &Task,
) {
    assert!(
        !result.id.trim().is_empty(),
        "{resource} returned a result with an empty id"
    );
    assert!(
        !result.name.trim().is_empty(),
        "{resource} returned result {} with an empty name",
        result.id
    );
    if let Some(result_report) = result.report.as_ref() {
        assert_eq!(
            result_report.id, report.id,
            "{resource} result {} did not point back to report {}",
            result.id, report.id
        );
    }
    if let Some(result_task) = result.task.as_ref() {
        assert_eq!(
            result_task.id, task.id,
            "{resource} result {} did not point back to task {}",
            result.id, task.id
        );
    }
}

fn assert_report_result_total_consistent(resource: &str, page: &ResultList, report: &Report) {
    if let Some(total) = report.result_count.as_ref().and_then(|count| count.total) {
        assert!(
            page.pagination.total >= total || page.data.len() as u32 >= total,
            "{resource} pagination under-reported total results"
        );
    }
}

fn assert_result_pagination_shape(
    resource: &str,
    response: &ResultList,
    expected_per_page: Option<u32>,
) {
    assert_eq!(
        response.pagination.page, 1,
        "{resource} list used an unexpected page"
    );
    if let Some(expected_per_page) = expected_per_page {
        assert_eq!(
            response.pagination.per_page, expected_per_page,
            "{resource} list used an unexpected page size"
        );
    } else {
        assert!(
            response.pagination.per_page > 0,
            "{resource} list returned a non-positive page size"
        );
    }
    if response.pagination.total == 0 {
        assert_eq!(
            response.pagination.total_pages, 0,
            "{resource} list returned totalPages for an empty result set"
        );
    } else {
        assert!(
            response.pagination.total_pages >= 1,
            "{resource} list returned no pages for a non-empty result set"
        );
    }
    assert!(
        response.data.len() <= response.pagination.per_page as usize,
        "{resource} list returned more items than its page size"
    );
}

fn assert_pagination_shape<T>(resource: &str, response: &ListResponse<T>) {
    assert_eq!(
        response.pagination.page, 1,
        "{resource} list used an unexpected default page"
    );
    assert!(
        response.pagination.per_page > 0,
        "{resource} list returned a non-positive page size"
    );
    if response.pagination.total == 0 {
        assert_eq!(
            response.pagination.total_pages, 0,
            "{resource} list returned totalPages for an empty result set"
        );
    } else {
        assert!(
            response.pagination.total_pages >= 1,
            "{resource} list returned no pages for a non-empty result set"
        );
    }
    assert!(
        response.data.len() <= response.pagination.per_page as usize,
        "{resource} list returned more items than its page size"
    );
}

async fn assert_target_not_listed(
    harness: &E2eHarness,
    token: &str,
    target_id: &str,
) -> Result<()> {
    let targets = harness
        .list_targets(token)
        .await
        .context("list targets after deleting target")?;
    assert!(
        targets.data.iter().all(|target| target.id != target_id),
        "deleted target {target_id} was still returned by list targets"
    );
    Ok(())
}

async fn assert_task_not_listed(harness: &E2eHarness, token: &str, task_id: &str) -> Result<()> {
    let tasks = harness
        .list_tasks(token)
        .await
        .context("list tasks after deleting task")?;
    assert!(
        tasks.data.iter().all(|task| task.id != task_id),
        "deleted task {task_id} was still returned by list tasks"
    );
    Ok(())
}

async fn assert_problem_response_status_in(
    response: Response,
    expected: &[StatusCode],
    action: &str,
) -> Result<()> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .text()
        .await
        .context("read problem response body")?;
    assert!(
        expected.contains(&status),
        "{action}: expected one of {:?} but received {status} with body {body}",
        expected
    );
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("application/problem+json"),
        "{action}: expected problem content type but received {content_type}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&body).with_context(|| format!("{action}: parse problem body"))?;
    assert_eq!(json["status"], serde_json::json!(status.as_u16()));
    for field in ["type", "code", "title", "detail"] {
        assert!(
            json[field].as_str().is_some_and(|value| !value.is_empty()),
            "{action}: problem response field {field} was missing or empty"
        );
    }
    Ok(())
}

async fn assert_idle_stop_response(response: Response) -> Result<()> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .text()
        .await
        .context("read idle stop response body")?;

    if status == StatusCode::OK {
        assert!(
            body.trim().is_empty(),
            "stop idle task: expected empty success body but received {body}"
        );
        return Ok(());
    }

    assert!(
        status == StatusCode::CONFLICT,
        "stop idle task: expected HTTP 200 OK or 409 Conflict but received {status} with body {body}"
    );
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("application/problem+json"),
        "stop idle task: expected problem content type but received {content_type}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&body).context("stop idle task: parse problem body")?;
    assert_eq!(json["status"], serde_json::json!(status.as_u16()));
    Ok(())
}

async fn best_effort_cleanup(
    harness: &E2eHarness,
    token: &str,
    task_id: Option<&str>,
    target_id: Option<&str>,
) {
    if let Some(task_id) = task_id {
        if let Err(error) = harness.delete_task(token, task_id).await {
            eprintln!("best-effort task cleanup failed for {task_id}: {error:#}");
        }
    }
    if let Some(target_id) = target_id {
        if let Err(error) = harness.delete_target(token, target_id).await {
            eprintln!("best-effort target cleanup failed for {target_id}: {error:#}");
        }
    }
}
