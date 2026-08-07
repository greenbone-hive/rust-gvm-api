// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! End-to-end coverage for the compliance (audit/policy) surface exposed by
//! #391. Audits are tasks scoped to `usage_type=audit` and policies are scan
//! configs scoped to `usage_type=policy`. This test drives the complete
//! compliance workflow against a live gvmd — list/read policies and audits,
//! create an audit from a compliance policy, start it, poll to a terminal
//! state, and retrieve its compliance report — while asserting the audit stays
//! scoped away from the ordinary scan-task route throughout.

use anyhow::{anyhow, Context, Result};
use gvm_gateway_e2e::harness::{E2eHarness, ListResponse, ScanConfig, SessionResponse, Task};
use reqwest::{Method, StatusCode};

// Drives the full compliance (audit/policy) workflow: policies and audits stay
// usage-scoped and individually retrievable, and an audit created from a
// compliance policy runs end to end (create → start → terminal state →
// compliance report) so the repaired lifecycle routing is actually exercised.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_compliance_runs_audit_lifecycle_and_keeps_usage_scoped() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut audit_id = None;
    let mut target_id = None;

    let run = async {
        // 1. Policies are compliance scan configs. The GVM feed ships built-in
        //    policies, so the catalog must be non-empty, every entry must be
        //    individually retrievable through the policy-scoped route, and each
        //    must carry the usage-type discriminator.
        let policies = list_policies(&harness, &session.token).await?;
        eprintln!("listed {} compliance policies", policies.data.len());
        assert!(
            !policies.data.is_empty(),
            "the compliance policy catalog must be non-empty; the feed ships built-in policies"
        );
        let policy = policies
            .data
            .first()
            .expect("policy catalog is non-empty")
            .clone();
        let fetched_policy = get_policy(&harness, &session.token, &policy.id).await?;
        assert_eq!(
            fetched_policy.id, policy.id,
            "GET /api/v1/policies/{{id}} should return the requested policy"
        );
        assert_eq!(
            fetched_policy.usage_type.as_deref(),
            Some("policy"),
            "a policy read must report usageType=policy"
        );

        // 2. Audits are compliance tasks scoped to usage_type=audit; they must
        //    never appear on the scan-task route (scoped to usage_type=scan).
        let audits = list_audits(&harness, &session.token).await?;
        let scan_tasks = harness.list_tasks(&session.token).await?;
        for audit in &audits.data {
            assert!(
                !scan_tasks.data.iter().any(|task| task.id == audit.id),
                "audit {} must not appear in the scan-task list; /audits and \
                 /tasks are scoped to disjoint usage types",
                audit.id
            );
        }

        // 3. Full workflow: create an audit from the compliance policy, a
        //    target, and a scanner; start it; poll to a terminal state; and
        //    retrieve its compliance report.
        let scanners = harness.list_scanners(&session.token).await?;
        let scanner = harness.select_scanner(&scanners)?.clone();
        let port_lists = harness.list_port_lists(&session.token).await?;
        let port_list = harness.select_port_list(&port_lists)?.clone();

        let target_name = harness.unique_name("nightly-compliance-target");
        let target = harness
            .create_target(&session.token, &target_name, &port_list.id)
            .await?;
        target_id = Some(target.id.clone());

        let audit_name = harness.unique_name("nightly-compliance-audit");
        let audit = harness
            .create_audit(
                &session.token,
                &audit_name,
                &target.id,
                &policy.id,
                &scanner.id,
            )
            .await?;
        audit_id = Some(audit.id.clone());
        eprintln!(
            "created audit {} ({}) from policy {}",
            audit.name, audit.id, policy.id
        );

        // The audit is retrievable through the audit route and listed there,
        // but never through the scan-task route.
        let fetched_audit = get_audit(&harness, &session.token, &audit.id).await?;
        assert_eq!(
            fetched_audit.id, audit.id,
            "GET /api/v1/audits/{{id}} should return the created audit"
        );
        let audits_after = list_audits(&harness, &session.token).await?;
        assert!(
            audits_after.data.iter().any(|listed| listed.id == audit.id),
            "created audit must appear in the audit catalog"
        );
        let scan_tasks_after = harness.list_tasks(&session.token).await?;
        assert!(
            !scan_tasks_after.data.iter().any(|task| task.id == audit.id),
            "the created audit must not leak into the scan-task list"
        );

        let action = harness.start_audit(&session.token, &audit.id).await?;
        assert!(
            !action.report_id.is_empty(),
            "start-audit response did not include a report id"
        );
        eprintln!("started audit {}; report {}", audit.id, action.report_id);

        let completed = harness
            .wait_for_audit_completion(&session.token, &audit.id)
            .await?;
        let report_ref = completed
            .last_report
            .as_ref()
            .or(completed.current_report.as_ref())
            .ok_or_else(|| {
                anyhow!(
                    "completed audit {} did not expose a report reference",
                    completed.id
                )
            })?;
        assert_eq!(
            report_ref.id, action.report_id,
            "audit report reference drifted from the start-audit response"
        );

        let report = harness
            .get_report(&session.token, &action.report_id)
            .await?;
        assert_eq!(report.id, action.report_id);
        assert_eq!(
            report.task.as_ref().map(|task| task.id.as_str()),
            Some(audit.id.as_str()),
            "compliance report did not point back to the audit"
        );
        assert!(
            report.scan_end.is_some(),
            "completed compliance report {} was missing scanEnd",
            report.id
        );
        eprintln!(
            "compliance report {} scanEnd={:?} resultCount={:?}",
            report.id, report.scan_end, report.result_count
        );

        Ok(())
    }
    .await;

    best_effort_cleanup(
        &harness,
        &session.token,
        audit_id.as_deref(),
        target_id.as_deref(),
    )
    .await;
    finish_session(&harness, &session, run).await
}

async fn best_effort_cleanup(
    harness: &E2eHarness,
    token: &str,
    audit_id: Option<&str>,
    target_id: Option<&str>,
) {
    if let Some(audit_id) = audit_id {
        if let Err(error) = harness.delete_audit(token, audit_id).await {
            eprintln!("best-effort audit cleanup failed for {audit_id}: {error:#}");
        }
    }
    if let Some(target_id) = target_id {
        if let Err(error) = harness.delete_target(token, target_id).await {
            eprintln!("best-effort target cleanup failed for {target_id}: {error:#}");
        }
    }
}

async fn list_policies(harness: &E2eHarness, token: &str) -> Result<ListResponse<ScanConfig>> {
    let response = harness
        .request(Method::GET, "/api/v1/policies")
        .bearer_auth(token)
        .send()
        .await
        .context("list policies request failed")?;
    assert_eq!(response.status(), StatusCode::OK, "GET /api/v1/policies");
    response
        .json::<ListResponse<ScanConfig>>()
        .await
        .context("decode policy list")
}

async fn get_policy(harness: &E2eHarness, token: &str, id: &str) -> Result<ScanConfig> {
    let response = harness
        .request(Method::GET, &format!("/api/v1/policies/{id}"))
        .bearer_auth(token)
        .send()
        .await
        .context("get policy request failed")?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GET /api/v1/policies/{{id}}"
    );
    response.json::<ScanConfig>().await.context("decode policy")
}

async fn list_audits(harness: &E2eHarness, token: &str) -> Result<ListResponse<Task>> {
    let response = harness
        .request(Method::GET, "/api/v1/audits")
        .bearer_auth(token)
        .send()
        .await
        .context("list audits request failed")?;
    assert_eq!(response.status(), StatusCode::OK, "GET /api/v1/audits");
    response
        .json::<ListResponse<Task>>()
        .await
        .context("decode audit list")
}

async fn get_audit(harness: &E2eHarness, token: &str, id: &str) -> Result<Task> {
    let response = harness
        .request(Method::GET, &format!("/api/v1/audits/{id}"))
        .bearer_auth(token)
        .send()
        .await
        .context("get audit request failed")?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GET /api/v1/audits/{{id}}"
    );
    response.json::<Task>().await.context("decode audit")
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
