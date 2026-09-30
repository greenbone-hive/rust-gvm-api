// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::Result;
use gvm_gateway_e2e::harness::{assert_problem_response, E2eHarness};
use reqwest::{Method, StatusCode};

// Proves the live gvmd import contract owns a stable report resource: a
// dedicated import task accepts one bounded envelope and the returned report is
// readable at Location. The current compose gvmd cannot delete imported
// reports, so that limitation is asserted explicitly while all independently
// removable resources are cleaned up; compose volume teardown removes the
// retained report. A capability regression is never silently skipped.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_report_import_lifecycle_creates_reads_and_cleans_up() -> Result<()> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;
    let session = harness.create_session().await?;

    let task = harness
        .create_import_task(
            &session.token,
            &harness.unique_name("nightly-report-import"),
        )
        .await?;
    assert_eq!(task.location, format!("/api/v1/tasks/{}", task.id));

    let report_xml = br#"<report><name>Compose imported report</name><comment>issue 570 lifecycle</comment></report>"#;
    let report = harness
        .import_report(&session.token, &task.id, Some(false), report_xml)
        .await?;
    assert_eq!(report.location, format!("/api/v1/reports/{}", report.id));

    let readback = harness.get_report(&session.token, &report.id).await?;
    assert_eq!(readback.id, report.id);
    assert_eq!(
        readback.task.as_ref().map(|task| task.id.as_str()),
        Some(task.id.as_str()),
        "imported report did not retain its import-task relationship"
    );

    let unsupported_report_cleanup = harness
        .request(Method::DELETE, &report.location)
        .bearer_auth(&session.token)
        .send()
        .await?;
    assert_problem_response(
        unsupported_report_cleanup,
        StatusCode::NOT_FOUND,
        "compose gvmd does not support deleting imported reports",
    )
    .await?;

    harness.delete_task(&session.token, &task.id).await?;
    let retained_report = harness.get_report(&session.token, &report.id).await?;
    assert_eq!(
        retained_report.id, report.id,
        "compose gvmd unexpectedly removed the imported report with its task"
    );
    harness.delete_session(&session.token).await?;

    Ok(())
}
