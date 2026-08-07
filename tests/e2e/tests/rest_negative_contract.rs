// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{Context, Result};
use gvm_gateway_e2e::harness::{assert_problem_response, E2eHarness, SessionResponse};
use reqwest::{header::CONTENT_TYPE, Method, StatusCode};

const MISSING_UUID: &str = "00000000-0000-0000-0000-000000000000";

// Covers live-stack negative REST contracts so malformed requests, unknown
// resources, and unsupported methods keep returning RFC 9457 problem responses.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_negative_contract_returns_problem_responses() -> Result<()> {
    let (harness, session) = ready_session().await?;

    let run = async {
        let unknown_route = harness
            .request(Method::GET, "/api/v1/does-not-exist")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send unknown-route request")?;
        assert_problem_response(unknown_route, StatusCode::NOT_FOUND, "unknown route").await?;

        let method_not_allowed = harness
            .request(Method::PATCH, "/api/v1/targets")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send unsupported-method request")?;
        assert_problem_response(
            method_not_allowed,
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported method",
        )
        .await?;

        let report_formats_patch = harness
            .request(Method::PATCH, "/api/v1/report-formats")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send report-format PATCH request")?;
        assert_problem_response(
            report_formats_patch,
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported report-format partial mutation",
        )
        .await?;

        let hosts_patch = harness
            .request(Method::PATCH, "/api/v1/hosts")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send hosts PATCH request")?;
        assert_problem_response(
            hosts_patch,
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported host partial mutation",
        )
        .await?;

        let notes_patch = harness
            .request(Method::PATCH, "/api/v1/notes")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send notes PATCH request")?;
        assert_problem_response(
            notes_patch,
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported note partial mutation",
        )
        .await?;

        let overrides_patch = harness
            .request(Method::PATCH, "/api/v1/overrides")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send overrides PATCH request")?;
        assert_problem_response(
            overrides_patch,
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported override partial mutation",
        )
        .await?;

        let nvts_post = harness
            .request(Method::POST, "/api/v1/nvts")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send nvts POST request")?;
        assert_problem_response(
            nvts_post,
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported nvt mutation",
        )
        .await?;

        let nvt_families_post = harness
            .request(Method::POST, "/api/v1/nvt-families")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send nvt-families POST request")?;
        assert_problem_response(
            nvt_families_post,
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported nvt-family mutation",
        )
        .await?;

        let invalid_uuid = harness
            .request(Method::GET, "/api/v1/targets/not-a-uuid")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send invalid UUID request")?;
        assert_problem_response(invalid_uuid, StatusCode::BAD_REQUEST, "invalid UUID").await?;

        let malformed_json = harness
            .request(Method::POST, "/api/v1/targets")
            .bearer_auth(&session.token)
            .header(CONTENT_TYPE, "application/json")
            .body("{")
            .send()
            .await
            .context("send malformed JSON request")?;
        assert_problem_response(malformed_json, StatusCode::BAD_REQUEST, "malformed JSON").await?;

        let missing_target = harness
            .request(Method::GET, &format!("/api/v1/targets/{MISSING_UUID}"))
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send missing-target request")?;
        assert_problem_response(missing_target, StatusCode::NOT_FOUND, "missing target").await?;

        Ok(())
    }
    .await;

    finish_session(&harness, &session, run).await
}

async fn ready_session() -> Result<(E2eHarness, SessionResponse)> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;
    let session = harness.create_session().await?;
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
