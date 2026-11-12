// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::Result;
use gvm_gateway_e2e::harness::{assert_problem_response, E2eHarness};
use reqwest::{Method, StatusCode};

// Proves the live gvmd import contract owns a stable report resource: a
// dedicated import task accepts one bounded envelope, the returned report is
// readable at Location and retains its task relationship. After gvmd's
// asynchronous import worker completes, DELETE returns 204 and a later
// authenticated GET returns RFC 9457 not_found. This prevents the required OSP
// lane from racing active-report cleanup or regressing to the obsolete
// undeletable-report behavior before it cleans up the import task and session.
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

    let completed_task = harness
        .wait_for_task_completion(&session.token, &task.id)
        .await?;
    assert_eq!(
        completed_task
            .last_report
            .as_ref()
            .or(completed_task.current_report.as_ref())
            .map(|report| report.id.as_str()),
        Some(report.id.as_str()),
        "completed import task did not retain the imported report"
    );

    let deleted_report = harness
        .request(Method::DELETE, &report.location)
        .bearer_auth(&session.token)
        .send()
        .await?;
    assert_eq!(
        deleted_report.status(),
        StatusCode::NO_CONTENT,
        "permanently delete imported report"
    );

    let deleted_report_readback = harness
        .request(Method::GET, &report.location)
        .bearer_auth(&session.token)
        .send()
        .await?;
    let problem = assert_problem_response(
        deleted_report_readback,
        StatusCode::NOT_FOUND,
        "read permanently deleted imported report",
    )
    .await?;
    assert_eq!(
        problem.code, "not_found",
        "deleted imported report must be permanently absent"
    );

    harness.delete_task(&session.token, &task.id).await?;
    harness.delete_session(&session.token).await?;

    Ok(())
}
