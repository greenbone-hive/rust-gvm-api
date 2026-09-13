// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{Context, Result};
use gvm_gateway_e2e::harness::{
    CreatedResource, Credential, E2eHarness, ListResponse, NoteResource, NvtCatalogEntry,
    OverrideResource, PortList, ScanConfig, ScanResult, Scanner, SecInfoEntry, SessionResponse,
    Target, Task,
};

// Covers stable list/read contracts for supporting catalogs used by setup and discovery flows.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_supporting_catalogs_list_and_read_resources() -> Result<()> {
    let (harness, session) = ready_session().await?;

    let run = async {
        assert_generic_resource_catalogs(&harness, &session.token).await?;
        assert_scan_config_catalog(&harness, &session.token).await?;
        assert_scanner_catalog(&harness, &session.token).await?;
        assert_port_list_catalog(&harness, &session.token).await?;
        assert_feed_catalog(&harness, &session.token).await?;
        assert_credential_store_catalog(&harness, &session.token).await?;
        assert_credential_list_shape(&harness, &session.token).await?;
        assert_report_format_catalog(&harness, &session.token).await?;
        assert_cve_catalog(&harness, &session.token).await?;
        assert_cpe_catalog(&harness, &session.token).await?;
        assert_cert_bund_advisory_catalog(&harness, &session.token).await?;
        assert_dfn_cert_advisory_catalog(&harness, &session.token).await?;
        assert_filter_catalog(&harness, &session.token).await?;
        assert_tag_catalog(&harness, &session.token).await?;
        assert_ticket_catalog(&harness, &session.token).await?;
        assert_note_catalog(&harness, &session.token).await?;
        assert_override_catalog(&harness, &session.token).await?;
        assert_nvt_catalog(&harness, &session.token).await?;
        assert_nvt_family_catalog(&harness, &session.token).await?;
        assert_operating_system_catalog(&harness, &session.token).await?;
        Ok(())
    }
    .await;

    finish_session(&harness, &session, run).await
}

async fn assert_generic_resource_catalogs(harness: &E2eHarness, token: &str) -> Result<()> {
    // Compose-backed reads validate the generic routes against real gvmd. The
    // host asset catalog may legitimately be empty on a fresh stack, whereas
    // the scan-config catalog must provide a representative generic config.
    let assets = harness.list_generic_assets(token, "host").await?;
    assert_pagination_shape("generic host assets", &assets);
    if let Some(selected) = assets.data.first() {
        let fetched = harness
            .get_generic_asset(token, &selected.id, &selected.asset_type)
            .await?;
        assert_named_resource_matches(
            "generic asset",
            &fetched.id,
            &fetched.name,
            &selected.id,
            &selected.name,
        );
        assert_eq!(fetched.asset_type, selected.asset_type);
    }

    let configs = harness.list_generic_configs(token).await?;
    assert_pagination_shape("generic configs", &configs);
    let selected = configs
        .data
        .first()
        .context("generic config catalog returned no configs")?;
    let fetched = harness.get_generic_config(token, &selected.id).await?;
    assert_named_resource_matches(
        "generic config",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(fetched.usage_type, selected.usage_type);
    Ok(())
}

// Covers the triage-resource list/read contract in the context of a completed
// discovery scan, even when the stack does not auto-create notes/overrides.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_supporting_triage_resources_filter_on_completed_scan_context() -> Result<()> {
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
        let completed = harness
            .wait_for_task_completion(&session.token, &created.task.id)
            .await?;
        assert!(
            matches!(completed.status.as_str(), "Done" | "Stopped"),
            "completed discovery task ended in unexpected status {}",
            completed.status
        );

        assert_host_catalog_after_completed_scan(&harness, &session.token).await?;

        let notes = harness
            .list_notes_filtered(&session.token, &format!("task_id={}", created.task.id))
            .await?;
        assert_pagination_shape("filtered notes", &notes);
        if let Some(selected) = notes.data.first() {
            let fetched = harness.get_note(&session.token, &selected.id).await?;
            assert_note_matches_read("note", &fetched, selected, Some(&created.task.id));
        } else {
            eprintln!(
                "completed scan produced no note resources; deepest boundary reached is filtered list/read contract on task-scoped triage context"
            );
        }

        let overrides = harness
            .list_overrides_filtered(&session.token, &format!("task_id={}", created.task.id))
            .await?;
        assert_pagination_shape("filtered overrides", &overrides);
        if let Some(selected) = overrides.data.first() {
            let fetched = harness.get_override(&session.token, &selected.id).await?;
            assert_override_matches_read(
                "override",
                &fetched,
                selected,
                Some(&created.task.id),
            );
        } else {
            eprintln!(
                "completed scan produced no override resources; deepest boundary reached is filtered list/read contract on task-scoped triage context"
            );
        }

        Ok(())
    }
    .await;

    best_effort_delete_task(&harness, &session.token, task_id.as_deref()).await;
    best_effort_delete_target(&harness, &session.token, target_id.as_deref()).await;
    finish_session(&harness, &session, run).await
}

// Covers the note/override write workflow against a real completed scan result
// so external clients can perform REST-side triage without helper-specific flows.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_supporting_triage_resource_lifecycle_mutates_notes_and_overrides() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut task_id = None;
    let mut target_id = None;
    let mut note_id = None;
    let mut override_id = None;

    let run = async {
        let resources = select_discovery_resources(&harness, &session.token).await?;
        let created = create_discovery_task(&harness, &session.token, &resources).await?;
        task_id = Some(created.task.id.clone());
        target_id = Some(created.target.id.clone());

        let action = harness.start_task(&session.token, &created.task.id).await?;
        let completed = harness
            .wait_for_task_completion(&session.token, &created.task.id)
            .await?;
        assert!(
            matches!(completed.status.as_str(), "Done" | "Stopped"),
            "completed discovery task ended in unexpected status {}",
            completed.status
        );

        let result = select_triage_result(&harness, &session.token, &action.report_id).await?;
        let nvt_oid = result
            .nvt
            .as_ref()
            .and_then(|nvt| nvt.oid.as_deref())
            .with_context(|| format!("scan result {} did not expose an NVT oid", result.id))?;

        let created_note = harness
            .create_note(
                &session.token,
                nvt_oid,
                &created.task.id,
                &result.id,
                "created by compose-backed note triage coverage",
            )
            .await?;
        assert_created_location(&created_note, "/api/v1/notes");
        note_id = Some(created_note.id.clone());

        let created_note_resource = harness.get_note(&session.token, &created_note.id).await?;
        assert_eq!(
            created_note_resource
                .result
                .as_ref()
                .map(|reference| reference.id.as_str()),
            Some(result.id.as_str()),
            "created note did not preserve result linkage"
        );
        assert_eq!(
            created_note_resource.text.as_deref(),
            Some("created by compose-backed note triage coverage"),
            "created note did not preserve text"
        );

        let updated_note = harness
            .update_note(
                &session.token,
                &created_note.id,
                "updated by compose-backed note triage coverage",
                false,
            )
            .await?;
        assert_eq!(
            updated_note.text.as_deref(),
            Some("updated by compose-backed note triage coverage"),
            "updated note did not return changed text"
        );
        assert!(
            !updated_note.active,
            "updated note did not return changed active flag"
        );

        let created_override = harness
            .create_override(
                &session.token,
                nvt_oid,
                &created.task.id,
                &result.id,
                "created by compose-backed override triage coverage",
                "0.0",
            )
            .await?;
        assert_created_location(&created_override, "/api/v1/overrides");
        override_id = Some(created_override.id.clone());

        let created_override_resource = harness
            .get_override(&session.token, &created_override.id)
            .await?;
        assert_eq!(
            created_override_resource
                .result
                .as_ref()
                .map(|reference| reference.id.as_str()),
            Some(result.id.as_str()),
            "created override did not preserve result linkage"
        );
        assert_severity_value_matches(
            created_override_resource.new_severity.as_deref(),
            "0.0",
            "created override did not preserve replacement severity",
        );

        let updated_override = harness
            .update_override(
                &session.token,
                &created_override.id,
                "updated by compose-backed override triage coverage",
                "1.0",
                false,
            )
            .await?;
        assert_eq!(
            updated_override.text.as_deref(),
            Some("updated by compose-backed override triage coverage"),
            "updated override did not return changed text"
        );
        assert_severity_value_matches(
            updated_override.new_severity.as_deref(),
            "1.0",
            "updated override did not return changed replacement severity",
        );
        assert!(
            !updated_override.active,
            "updated override did not return changed active flag"
        );

        harness
            .delete_note(&session.token, &created_note.id, true)
            .await?;
        note_id = None;
        assert_note_not_listed(&harness, &session.token, &created.task.id, &created_note.id)
            .await?;

        harness
            .delete_override(&session.token, &created_override.id, true)
            .await?;
        override_id = None;
        assert_override_not_listed(
            &harness,
            &session.token,
            &created.task.id,
            &created_override.id,
        )
        .await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_delete_note(&harness, &session.token, note_id.as_deref()).await;
        best_effort_delete_override(&harness, &session.token, override_id.as_deref()).await;
    }
    best_effort_delete_task(&harness, &session.token, task_id.as_deref()).await;
    best_effort_delete_target(&harness, &session.token, target_id.as_deref()).await;
    finish_session(&harness, &session, run).await
}

// Covers scan-config copy/update/delete against gvmd because scan configs are
// created by copying an existing base config rather than by building one blank.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_supporting_scan_config_lifecycle_copies_updates_and_deletes() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut scan_config_id = None;

    let run = async {
        let scan_configs = harness.list_scan_configs(&session.token).await?;
        let base_config = harness.select_discovery_scan_config(&scan_configs)?;
        let scan_config_name = harness.unique_name("nightly-supporting-scan-config");
        let created_comment = "created by compose-backed E2E scan-config coverage";
        let created = harness
            .create_scan_config_from_base(
                &session.token,
                &scan_config_name,
                created_comment,
                &base_config.id,
            )
            .await?;
        assert_created_location(&created, "/api/v1/scan-configs");
        scan_config_id = Some(created.id.clone());

        let scan_config = harness.get_scan_config(&session.token, &created.id).await?;
        assert_scan_config_matches_created(&scan_config, &created.id, &scan_config_name);

        let updated_comment = "updated by compose-backed E2E scan-config coverage";
        let updated = harness
            .update_scan_config_comment(&session.token, &created.id, updated_comment)
            .await?;
        assert_eq!(
            updated.id, created.id,
            "scan-config id changed after update"
        );
        assert_eq!(
            updated.comment.as_deref(),
            Some(updated_comment),
            "scan-config update response did not expose changed comment"
        );
        let fetched = harness.get_scan_config(&session.token, &created.id).await?;
        assert_eq!(
            fetched.comment.as_deref(),
            Some(updated_comment),
            "scan-config read after update did not preserve changed comment"
        );

        harness
            .delete_scan_config(&session.token, &created.id)
            .await?;
        scan_config_id = None;
        assert_scan_config_not_listed(&harness, &session.token, &created.id).await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_delete_scan_config(&harness, &session.token, scan_config_id.as_deref()).await;
    }
    finish_session(&harness, &session, run).await
}

// Covers the port-list create/read/list/delete contract with a small repeatable payload.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_supporting_port_list_lifecycle_creates_reads_lists_and_deletes() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut port_list_id = None;

    let run = async {
        let port_list_name = harness.unique_name("nightly-supporting-port-list");
        let created = harness
            .create_port_list(&session.token, &port_list_name, "T:1")
            .await?;
        assert_created_location(&created, "/api/v1/port-lists");
        port_list_id = Some(created.id.clone());

        let port_list = harness.get_port_list(&session.token, &created.id).await?;
        assert_port_list_matches_created(&port_list, &created.id, &port_list_name);

        let port_lists = harness.list_port_lists(&session.token).await?;
        assert!(
            port_lists
                .iter()
                .any(|listed| listed.id == created.id && listed.name == port_list_name),
            "created port list {} ({}) was not returned by list port lists",
            port_list_name,
            created.id
        );

        harness
            .delete_port_list(&session.token, &created.id)
            .await?;
        port_list_id = None;
        assert_port_list_not_listed(&harness, &session.token, &created.id).await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_delete_port_list(&harness, &session.token, port_list_id.as_deref()).await;
    }
    finish_session(&harness, &session, run).await
}

// Covers the credential create/read/list/delete contract using the least environment-sensitive type.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_supporting_credential_lifecycle_creates_reads_lists_and_deletes() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut credential_id = None;

    let run = async {
        let credential_name = harness.unique_name("nightly-supporting-credential");
        let created = harness
            .create_username_password_credential(
                &session.token,
                &credential_name,
                "nightly-user",
                "nightly-password",
            )
            .await?;
        assert_created_location(&created, "/api/v1/credentials");
        credential_id = Some(created.id.clone());

        let credential = harness.get_credential(&session.token, &created.id).await?;
        assert_credential_matches_created(&credential, &created.id, &credential_name);

        let credentials = harness.list_credentials(&session.token).await?;
        assert!(
            credentials
                .data
                .iter()
                .any(|listed| listed.id == created.id && listed.name == credential_name),
            "created credential {} ({}) was not returned by list credentials",
            credential_name,
            created.id
        );

        harness
            .delete_credential(&session.token, &created.id)
            .await?;
        credential_id = None;
        assert_credential_not_listed(&harness, &session.token, &created.id).await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_delete_credential(&harness, &session.token, credential_id.as_deref()).await;
    }
    finish_session(&harness, &session, run).await
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

async fn assert_scan_config_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let scan_configs = harness.list_scan_configs(token).await?;
    let selected = harness.select_discovery_scan_config(&scan_configs)?;
    let fetched = harness.get_scan_config(token, &selected.id).await?;
    assert_named_resource_matches(
        "scan config",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    Ok(())
}

async fn assert_scanner_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let scanners = harness.list_scanners(token).await?;
    let selected = harness.select_scanner(&scanners)?;
    let fetched = harness.get_scanner(token, &selected.id).await?;
    assert_named_resource_matches(
        "scanner",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    Ok(())
}

async fn assert_port_list_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let port_lists = harness.list_port_lists(token).await?;
    let selected = harness.select_port_list(&port_lists)?;
    let fetched = harness.get_port_list(token, &selected.id).await?;
    assert_named_resource_matches(
        "port list",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    Ok(())
}

async fn assert_feed_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let catalog = harness.list_feeds(token, None).await?;
    assert!(
        !catalog.data.is_empty(),
        "feed status did not return any feed entries"
    );
    for feed in &catalog.data {
        assert!(
            !feed.feed_type.trim().is_empty(),
            "feed entry returned an empty type"
        );
        assert!(
            !feed.name.trim().is_empty(),
            "feed entry returned an empty name"
        );
    }

    if let Some(feed_type) = catalog
        .data
        .iter()
        .map(|feed| feed.feed_type.as_str())
        .find(|feed_type| matches!(*feed_type, "NVT" | "CERT" | "SCAP" | "GVMD_DATA"))
    {
        let filtered = harness.list_feeds(token, Some(feed_type)).await?;
        assert!(
            filtered.data.iter().all(|feed| feed.feed_type == feed_type),
            "feed type filter returned a different feed family"
        );
    }
    Ok(())
}

async fn assert_credential_store_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let Some(stores) = harness.list_credential_stores(token).await? else {
        eprintln!(
            "gvmd did not expose credential stores on 2026-08-28; covered documented 501 capability-absence contract instead of a concrete store list"
        );
        return Ok(());
    };

    for store in stores {
        if let Some(id) = store.id.as_deref() {
            assert!(
                !id.trim().is_empty(),
                "credential store returned an empty id"
            );
        }
        assert!(
            !store.name.trim().is_empty(),
            "credential store returned an empty name"
        );
    }
    Ok(())
}

async fn assert_credential_list_shape(harness: &E2eHarness, token: &str) -> Result<()> {
    let credentials = harness.list_credentials(token).await?;
    assert_pagination_shape("credentials", &credentials);
    for credential in credentials.data {
        assert!(
            !credential.id.trim().is_empty(),
            "credential list returned an empty id"
        );
        assert!(
            !credential.name.trim().is_empty(),
            "credential list returned an empty name"
        );
    }
    Ok(())
}

async fn assert_report_format_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let report_formats = harness.list_report_formats(token).await?;
    assert_pagination_shape("report formats", &report_formats);
    assert!(
        !report_formats.data.is_empty(),
        "report-format catalog did not return any entries"
    );
    let selected = harness.select_report_format_by_extension(
        &report_formats.data,
        "pdf",
        Some(&harness.config.pdf_report_format_id),
    )?;
    let fetched = harness.get_report_format(token, &selected.id).await?;
    assert_named_resource_matches(
        "report format",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(
        fetched.extension, selected.extension,
        "report format extension drifted on read"
    );
    Ok(())
}

async fn assert_cve_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let cves = harness.list_cves(token).await?;
    assert_secinfo_catalog(
        "cve",
        &cves,
        |id| async move { harness.get_cve(token, &id).await },
        "cve catalog is empty; deepest boundary reached is list/pagination contract",
    )
    .await
}

async fn assert_cpe_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let cpes = harness.list_cpes(token).await?;
    assert_secinfo_catalog(
        "cpe",
        &cpes,
        |id| async move { harness.get_cpe(token, &id).await },
        "cpe catalog is empty; deepest boundary reached is list/pagination contract",
    )
    .await
}

async fn assert_cert_bund_advisory_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let advisories = harness.list_cert_bund_advisories(token).await?;
    assert_secinfo_catalog(
        "cert-bund advisory",
        &advisories,
        |id| async move { harness.get_cert_bund_advisory(token, &id).await },
        "cert-bund advisory catalog is empty; deepest boundary reached is list/pagination contract",
    )
    .await
}

async fn assert_dfn_cert_advisory_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let advisories = harness.list_dfn_cert_advisories(token).await?;
    assert_secinfo_catalog(
        "dfn-cert advisory",
        &advisories,
        |id| async move { harness.get_dfn_cert_advisory(token, &id).await },
        "dfn-cert advisory catalog is empty; deepest boundary reached is list/pagination contract",
    )
    .await
}

async fn assert_host_catalog_after_completed_scan(harness: &E2eHarness, token: &str) -> Result<()> {
    let hosts = harness.list_hosts(token).await?;
    assert_pagination_shape("hosts", &hosts);
    let Some(selected) = hosts
        .data
        .iter()
        .find(|host| {
            host.hostname.as_deref() == Some(harness.config.target_host.as_str())
                || host.ip.as_deref() == Some(harness.config.target_host.as_str())
                || host.name == harness.config.target_host
        })
        .or_else(|| hosts.data.first())
    else {
        eprintln!("host catalog is empty even after a completed discovery scan; skipping item read assertion");
        return Ok(());
    };

    let fetched = harness.get_host(token, &selected.id).await?;
    assert_named_resource_matches(
        "host",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(fetched.ip, selected.ip, "host ip drifted on read");
    assert_eq!(
        fetched.hostname, selected.hostname,
        "host hostname drifted on read"
    );
    Ok(())
}

async fn assert_operating_system_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    // Compose-backed OS data depends on prior scans. The list contract is
    // always testable; item fidelity is checked when gvmd has an OS asset.
    let operating_systems = harness.list_operating_systems(token).await?;
    assert_pagination_shape("operating systems", &operating_systems);
    let Some(selected) = operating_systems.data.first() else {
        eprintln!("operating-system catalog is empty; skipping item read assertion");
        return Ok(());
    };
    let fetched = harness.get_operating_system(token, &selected.id).await?;
    assert_named_resource_matches(
        "operating system",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(fetched.title, selected.title, "OS title drifted on read");
    assert_eq!(
        fetched.all_installs, selected.all_installs,
        "OS all-installs count drifted on read"
    );
    assert_eq!(
        fetched.host_count, selected.host_count,
        "OS host count drifted on read"
    );
    Ok(())
}

async fn assert_filter_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let filters = harness.list_filters(token).await?;
    assert_pagination_shape("filters", &filters);
    let Some(selected) = filters.data.first() else {
        eprintln!("filter catalog is empty; skipping item read assertion");
        return Ok(());
    };

    let fetched = harness.get_filter(token, &selected.id).await?;
    assert_named_resource_matches(
        "filter",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(
        fetched.filter_type, selected.filter_type,
        "filter type drifted on read"
    );
    Ok(())
}

async fn assert_tag_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let tags = harness.list_tags(token).await?;
    assert_pagination_shape("tags", &tags);
    let Some(selected) = tags.data.first() else {
        eprintln!("tag catalog is empty; skipping item read assertion");
        return Ok(());
    };

    let fetched = harness.get_tag(token, &selected.id).await?;
    assert_named_resource_matches(
        "tag",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(fetched.value, selected.value, "tag value drifted on read");
    Ok(())
}

async fn assert_ticket_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let tickets = harness.list_tickets(token).await?;
    assert_pagination_shape("tickets", &tickets);
    let Some(selected) = tickets.data.first() else {
        eprintln!("ticket catalog is empty; skipping item read assertion");
        return Ok(());
    };

    let fetched = harness.get_ticket(token, &selected.id).await?;
    assert_named_resource_matches(
        "ticket",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(
        fetched.status, selected.status,
        "ticket status drifted on read"
    );
    Ok(())
}

async fn assert_note_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let notes = harness.list_notes(token).await?;
    assert_pagination_shape("notes", &notes);
    let Some(selected) = notes.data.first() else {
        eprintln!("note catalog is empty; skipping item read assertion");
        return Ok(());
    };

    let fetched = harness.get_note(token, &selected.id).await?;
    assert_note_matches_read("note", &fetched, selected, None);
    Ok(())
}

async fn assert_override_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let overrides = harness.list_overrides(token).await?;
    assert_pagination_shape("overrides", &overrides);
    let Some(selected) = overrides.data.first() else {
        eprintln!("override catalog is empty; skipping item read assertion");
        return Ok(());
    };

    let fetched = harness.get_override(token, &selected.id).await?;
    assert_override_matches_read("override", &fetched, selected, None);
    Ok(())
}

async fn assert_nvt_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let nvts = harness.list_nvts(token).await?;
    assert_pagination_shape("nvts", &nvts);
    let Some(selected) = nvts.data.first() else {
        eprintln!("nvt catalog is empty; skipping item read assertion");
        return Ok(());
    };

    assert_nvt_pagination_round_trip(harness, token, &nvts).await?;

    if let Some(family) = selected.family.as_deref() {
        let scan_configs = harness.list_scan_configs(token).await?;
        let config_id = &scan_configs
            .first()
            .context("scan config catalog returned no configs for typed NVT query")?
            .id;
        let selected_family = harness
            .list_nvts_with_typed_options(token, family, config_id)
            .await?;
        assert_pagination_shape("nvts with typed options", &selected_family);
        assert!(
            selected_family
                .data
                .iter()
                .all(|nvt| nvt.family.as_deref() == Some(family)),
            "typed family filter must not return NVTs from another family"
        );
    }

    let fetched = harness.get_nvt(token, &selected.oid).await?;
    assert_nvt_matches_read(&fetched, selected);
    Ok(())
}

async fn assert_nvt_family_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let families = harness.list_nvt_families(token).await?;
    assert_pagination_shape("nvt families", &families);
    if families.data.is_empty() {
        eprintln!("nvt family catalog is empty; skipping content assertions");
        return Ok(());
    }
    for family in &families.data {
        assert!(
            !family.name.trim().is_empty(),
            "nvt family catalog returned an empty name"
        );
    }
    Ok(())
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

async fn assert_secinfo_catalog<F, Fut>(
    resource: &str,
    response: &ListResponse<SecInfoEntry>,
    fetch: F,
    empty_message: &str,
) -> Result<()>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<SecInfoEntry>>,
{
    assert_pagination_shape(resource, response);
    let Some(selected) = response.data.first() else {
        eprintln!("{empty_message}");
        return Ok(());
    };

    let fetched = fetch(selected.id.clone()).await?;
    assert_named_resource_matches(
        resource,
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    Ok(())
}

async fn assert_nvt_pagination_round_trip(
    harness: &E2eHarness,
    token: &str,
    full_page: &ListResponse<NvtCatalogEntry>,
) -> Result<()> {
    if full_page.pagination.total < 2 {
        eprintln!("nvt catalog has fewer than two items; skipping page-2 assertion");
        return Ok(());
    }

    let first_page = harness.list_nvts_page(token, 1, 1).await?;
    let second_page = harness.list_nvts_page(token, 2, 1).await?;

    assert_eq!(first_page.pagination.page, 1, "nvt page 1 drifted");
    assert_eq!(second_page.pagination.page, 2, "nvt page 2 drifted");
    assert_eq!(first_page.pagination.per_page, 1, "nvt page 1 size drifted");
    assert_eq!(
        second_page.pagination.per_page, 1,
        "nvt page 2 size drifted"
    );
    assert_eq!(
        first_page.pagination.total, full_page.pagination.total,
        "nvt page 1 total drifted"
    );
    assert_eq!(
        second_page.pagination.total, full_page.pagination.total,
        "nvt page 2 total drifted"
    );
    assert_eq!(
        first_page.data.len(),
        1,
        "nvt page 1 should contain exactly one item"
    );
    assert_eq!(
        second_page.data.len(),
        1,
        "nvt page 2 should contain exactly one item"
    );
    assert_eq!(
        first_page.data[0].oid, full_page.data[0].oid,
        "nvt page 1 did not preserve the first item"
    );
    assert_eq!(
        second_page.data[0].oid, full_page.data[1].oid,
        "nvt page 2 did not preserve the second item"
    );

    Ok(())
}

fn assert_named_resource_matches(
    resource: &str,
    actual_id: &str,
    actual_name: &str,
    expected_id: &str,
    expected_name: &str,
) {
    assert_eq!(actual_id, expected_id, "{resource} id drifted on read");
    assert_eq!(
        actual_name, expected_name,
        "{resource} name drifted on read"
    );
}

fn assert_note_matches_read(
    resource: &str,
    fetched: &NoteResource,
    selected: &NoteResource,
    expected_task_id: Option<&str>,
) {
    assert_named_resource_matches(
        resource,
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(
        fetched.text, selected.text,
        "{resource} text drifted on read"
    );
    assert_eq!(
        fetched.severity, selected.severity,
        "{resource} severity drifted on read"
    );
    assert_eq!(
        fetched.active, selected.active,
        "{resource} active flag drifted on read"
    );
    if let Some(task_id) = expected_task_id {
        if let Some(task) = fetched.task.as_ref() {
            assert_eq!(
                task.id, task_id,
                "{resource} task reference drifted from filtered task context"
            );
        }
    }
}

fn assert_override_matches_read(
    resource: &str,
    fetched: &OverrideResource,
    selected: &OverrideResource,
    expected_task_id: Option<&str>,
) {
    assert_named_resource_matches(
        resource,
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(
        fetched.text, selected.text,
        "{resource} text drifted on read"
    );
    assert_eq!(
        fetched.severity, selected.severity,
        "{resource} severity drifted on read"
    );
    assert_eq!(
        fetched.new_severity, selected.new_severity,
        "{resource} replacement severity drifted on read"
    );
    assert_eq!(
        fetched.active, selected.active,
        "{resource} active flag drifted on read"
    );
    if let Some(task_id) = expected_task_id {
        if let Some(task) = fetched.task.as_ref() {
            assert_eq!(
                task.id, task_id,
                "{resource} task reference drifted from filtered task context"
            );
        }
    }
}

fn assert_nvt_matches_read(fetched: &NvtCatalogEntry, selected: &NvtCatalogEntry) {
    assert_eq!(fetched.oid, selected.oid, "nvt oid drifted on read");
    assert_eq!(fetched.name, selected.name, "nvt name drifted on read");
    assert_eq!(
        fetched.family, selected.family,
        "nvt family drifted on read"
    );
    assert_eq!(
        fetched.cvss_base, selected.cvss_base,
        "nvt cvss base drifted on read"
    );
    assert_eq!(
        fetched.solution_type, selected.solution_type,
        "nvt solution type drifted on read"
    );
}

#[derive(Clone, Debug)]
struct DiscoveryResources {
    scan_config: ScanConfig,
    scanner: Scanner,
    port_list: PortList,
}

#[derive(Clone, Debug)]
struct CreatedDiscoveryTask {
    target: Target,
    task: Task,
}

async fn select_discovery_resources(
    harness: &E2eHarness,
    token: &str,
) -> Result<DiscoveryResources> {
    let scan_configs = harness.list_scan_configs(token).await?;
    let scan_config = harness.select_discovery_scan_config(&scan_configs)?.clone();

    let scanners = harness.list_scanners(token).await?;
    let scanner = harness.select_scanner(&scanners)?.clone();

    let port_lists = harness.list_port_lists(token).await?;
    let port_list = harness.select_port_list(&port_lists)?.clone();

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
    let target_name = harness.unique_name("nightly-triage-target");
    let target = harness
        .create_target(token, &target_name, &resources.port_list.id)
        .await?;

    let task_name = harness.unique_name("nightly-triage-task");
    let task = harness
        .create_task(
            token,
            &task_name,
            &target.id,
            &resources.scan_config.id,
            &resources.scanner.id,
        )
        .await?;

    Ok(CreatedDiscoveryTask { target, task })
}

async fn select_triage_result(
    harness: &E2eHarness,
    token: &str,
    report_id: &str,
) -> Result<ScanResult> {
    let results = harness.get_report_results(token, report_id).await?;
    results
        .data
        .into_iter()
        .find(|result| {
            result
                .nvt
                .as_ref()
                .and_then(|nvt| nvt.oid.as_ref())
                .is_some()
        })
        .with_context(|| format!("report {report_id} did not expose a triageable result"))
}

async fn best_effort_delete_task(harness: &E2eHarness, token: &str, task_id: Option<&str>) {
    if let Some(task_id) = task_id {
        if let Err(error) = harness.delete_task(token, task_id).await {
            eprintln!("best-effort task cleanup failed for {task_id}: {error:#}");
        }
    }
}

async fn best_effort_delete_target(harness: &E2eHarness, token: &str, target_id: Option<&str>) {
    if let Some(target_id) = target_id {
        if let Err(error) = harness.delete_target(token, target_id).await {
            eprintln!("best-effort target cleanup failed for {target_id}: {error:#}");
        }
    }
}

fn assert_created_location(created: &CreatedResource, collection_path: &str) {
    assert!(
        created
            .location
            .ends_with(&format!("{collection_path}/{}", created.id)),
        "created resource Location {} did not point at returned id {}",
        created.location,
        created.id
    );
}

fn assert_port_list_matches_created(port_list: &PortList, expected_id: &str, expected_name: &str) {
    assert_eq!(port_list.id, expected_id);
    assert_eq!(port_list.name, expected_name);
}

fn assert_scan_config_matches_created(
    scan_config: &ScanConfig,
    expected_id: &str,
    expected_name: &str,
) {
    assert_eq!(scan_config.id, expected_id);
    assert_eq!(scan_config.name, expected_name);
}

fn assert_credential_matches_created(
    credential: &Credential,
    expected_id: &str,
    expected_name: &str,
) {
    assert_eq!(credential.id, expected_id);
    assert_eq!(credential.name, expected_name);
    assert_eq!(
        credential.credential_type.as_deref(),
        Some("up"),
        "created credential did not preserve username/password type"
    );
    assert_eq!(
        credential.login.as_deref(),
        Some("nightly-user"),
        "created credential did not preserve login"
    );
}

fn assert_severity_value_matches(actual: Option<&str>, expected: &str, message: &str) {
    // gvmd canonicalizes severity strings such as "0.0" to "0"; this assertion
    // covers value preservation without depending on backend decimal formatting.
    let Some(actual) = actual else {
        panic!("{message}: missing severity value");
    };
    match (actual.parse::<f64>(), expected.parse::<f64>()) {
        (Ok(actual), Ok(expected)) => assert!(
            (actual - expected).abs() < f64::EPSILON,
            "{message}: expected {expected}, got {actual}"
        ),
        _ => assert_eq!(actual, expected, "{message}"),
    }
}

async fn assert_scan_config_not_listed(
    harness: &E2eHarness,
    token: &str,
    scan_config_id: &str,
) -> Result<()> {
    let scan_configs = harness
        .list_scan_configs(token)
        .await
        .context("list scan configs after deleting scan config")?;
    assert!(
        scan_configs
            .iter()
            .all(|scan_config| scan_config.id != scan_config_id),
        "deleted scan config {scan_config_id} was still returned by list scan configs"
    );
    Ok(())
}

async fn assert_port_list_not_listed(
    harness: &E2eHarness,
    token: &str,
    port_list_id: &str,
) -> Result<()> {
    let port_lists = harness
        .list_port_lists(token)
        .await
        .context("list port lists after deleting port list")?;
    assert!(
        port_lists
            .iter()
            .all(|port_list| port_list.id != port_list_id),
        "deleted port list {port_list_id} was still returned by list port lists"
    );
    Ok(())
}

async fn assert_credential_not_listed(
    harness: &E2eHarness,
    token: &str,
    credential_id: &str,
) -> Result<()> {
    let credentials = harness
        .list_credentials(token)
        .await
        .context("list credentials after deleting credential")?;
    assert!(
        credentials
            .data
            .iter()
            .all(|credential| credential.id != credential_id),
        "deleted credential {credential_id} was still returned by list credentials"
    );
    Ok(())
}

async fn assert_note_not_listed(
    harness: &E2eHarness,
    token: &str,
    task_id: &str,
    note_id: &str,
) -> Result<()> {
    let notes = harness
        .list_notes_filtered(token, &format!("task_id={task_id}"))
        .await
        .context("list notes after deleting note")?;
    assert!(
        notes.data.iter().all(|note| note.id != note_id),
        "deleted note {note_id} was still returned by task-scoped note list"
    );
    Ok(())
}

async fn assert_override_not_listed(
    harness: &E2eHarness,
    token: &str,
    task_id: &str,
    override_id: &str,
) -> Result<()> {
    let overrides = harness
        .list_overrides_filtered(token, &format!("task_id={task_id}"))
        .await
        .context("list overrides after deleting override")?;
    assert!(
        overrides
            .data
            .iter()
            .all(|override_| override_.id != override_id),
        "deleted override {override_id} was still returned by task-scoped override list"
    );
    Ok(())
}

async fn best_effort_delete_scan_config(
    harness: &E2eHarness,
    token: &str,
    scan_config_id: Option<&str>,
) {
    if let Some(scan_config_id) = scan_config_id {
        if let Err(error) = harness.delete_scan_config(token, scan_config_id).await {
            eprintln!("best-effort scan-config cleanup failed for {scan_config_id}: {error:#}");
        }
    }
}

async fn best_effort_delete_port_list(
    harness: &E2eHarness,
    token: &str,
    port_list_id: Option<&str>,
) {
    if let Some(port_list_id) = port_list_id {
        if let Err(error) = harness.delete_port_list(token, port_list_id).await {
            eprintln!("best-effort port-list cleanup failed for {port_list_id}: {error:#}");
        }
    }
}

async fn best_effort_delete_credential(
    harness: &E2eHarness,
    token: &str,
    credential_id: Option<&str>,
) {
    if let Some(credential_id) = credential_id {
        if let Err(error) = harness.delete_credential(token, credential_id).await {
            eprintln!("best-effort credential cleanup failed for {credential_id}: {error:#}");
        }
    }
}

async fn best_effort_delete_note(harness: &E2eHarness, token: &str, note_id: Option<&str>) {
    if let Some(note_id) = note_id {
        if let Err(error) = harness.delete_note(token, note_id, true).await {
            eprintln!("best-effort note cleanup failed for {note_id}: {error:#}");
        }
    }
}

async fn best_effort_delete_override(harness: &E2eHarness, token: &str, override_id: Option<&str>) {
    if let Some(override_id) = override_id {
        if let Err(error) = harness.delete_override(token, override_id, true).await {
            eprintln!("best-effort override cleanup failed for {override_id}: {error:#}");
        }
    }
}
