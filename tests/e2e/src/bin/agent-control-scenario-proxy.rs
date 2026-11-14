// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Test-only Agent Control scenario-selection boundary.
//!
//! gvmd does not expose a way to forward the emulator's scenario header. This
//! proxy selects one deterministic upstream profile scenario at a time by
//! adding `X-Emulator-Scenario`, while forwarding normal traffic without that
//! header. The upstream PR #50 profile remains the sole owner of all scenario
//! statuses, headers, and bodies. This proxy never observes or emits GMP and is
//! intentionally available only from the enterprise test image.

use std::{env, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::RwLock;

const MAX_PROXY_BODY_BYTES: usize = 16 * 1024 * 1024;
const EMULATOR_SCENARIO_HEADER: &str = "X-Emulator-Scenario";

#[derive(Clone)]
struct ProxyState {
    upstream: Arc<str>,
    control_token: Arc<str>,
    scenario: Arc<RwLock<Scenario>>,
    client: reqwest::Client,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Scenario {
    #[default]
    Normal,
    Authentication,
    Unavailable,
    Malformed,
    Conflict,
    RateLimit,
    Timeout,
}

impl Scenario {
    fn upstream_header(self) -> Option<&'static str> {
        match self {
            Self::Normal => None,
            Self::Authentication => Some("authentication"),
            Self::Unavailable => Some("unavailable"),
            Self::Malformed => Some("malformed"),
            Self::Conflict => Some("conflict"),
            Self::RateLimit => Some("rate-limit"),
            Self::Timeout => Some("timeout"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioSelection {
    scenario: Scenario,
}

#[tokio::main]
async fn main() -> Result<()> {
    let listen =
        env::var("AGENT_CONTROL_PROXY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8081".to_string());
    let upstream = required_env("AGENT_CONTROL_PROXY_UPSTREAM")?;
    let control_token = required_env("AGENT_CONTROL_PROXY_CONTROL_TOKEN")?;
    let upstream_timeout = env::var("AGENT_CONTROL_PROXY_UPSTREAM_TIMEOUT_SECONDS")
        .unwrap_or_else(|_| "30".to_string())
        .parse::<u64>()
        .context("AGENT_CONTROL_PROXY_UPSTREAM_TIMEOUT_SECONDS must be an integer")?;
    let state = ProxyState {
        upstream: upstream.trim_end_matches('/').to_string().into(),
        control_token: control_token.into(),
        scenario: Arc::new(RwLock::new(Scenario::Normal)),
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(upstream_timeout))
            .build()?,
    };
    let app = Router::new()
        .route("/health/ready", get(health))
        .route("/__control/scenario", get(get_scenario).put(set_scenario))
        .fallback(forward)
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("bind Agent Control scenario proxy to {listen}"))?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn required_env(name: &str) -> Result<String> {
    env::var(name)
        .with_context(|| format!("{name} is required"))
        .and_then(|value| {
            if value.is_empty() {
                anyhow::bail!("{name} must not be empty")
            }
            Ok(value)
        })
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ready"})))
}

async fn get_scenario(State(state): State<ProxyState>, headers: HeaderMap) -> Response {
    if !authorized(&headers, &state.control_token) {
        return failure(StatusCode::UNAUTHORIZED, "invalid proxy control token");
    }
    let scenario = *state.scenario.read().await;
    (StatusCode::OK, Json(json!({"scenario": scenario}))).into_response()
}

async fn set_scenario(
    State(state): State<ProxyState>,
    headers: HeaderMap,
    Json(selection): Json<ScenarioSelection>,
) -> Response {
    if !authorized(&headers, &state.control_token) {
        return failure(StatusCode::UNAUTHORIZED, "invalid proxy control token");
    }
    *state.scenario.write().await = selection.scenario;
    (
        StatusCode::OK,
        Json(json!({"scenario": selection.scenario, "status": "selected"})),
    )
        .into_response()
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {token}"))
}

async fn forward(State(state): State<ProxyState>, request: Request) -> Response {
    let scenario = *state.scenario.read().await;
    forward_upstream(&state, request, scenario).await
}

async fn forward_upstream(state: &ProxyState, request: Request, scenario: Scenario) -> Response {
    let (parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map_or_else(|| "/".to_string(), ToString::to_string);
    let bytes = match to_bytes(body, MAX_PROXY_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return failure(
                StatusCode::BAD_GATEWAY,
                &format!("request body rejected by scenario proxy: {error}"),
            )
        }
    };
    let mut upstream = state
        .client
        .request(parts.method, format!("{}{path}", state.upstream))
        .body(bytes);
    for (name, value) in &parts.headers {
        if name != header::HOST
            && name != header::CONTENT_LENGTH
            && !name.as_str().eq_ignore_ascii_case(EMULATOR_SCENARIO_HEADER)
        {
            upstream = upstream.header(name, value);
        }
    }
    if let Some(scenario) = scenario.upstream_header() {
        upstream = upstream.header(EMULATOR_SCENARIO_HEADER, scenario);
    }
    let response = match upstream.send().await {
        Ok(response) => response,
        Err(error) => {
            return failure(
                StatusCode::BAD_GATEWAY,
                &format!("Agent Control upstream request failed: {error}"),
            )
        }
    };
    let status = response.status();
    let headers = response.headers().clone();
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(error) => {
            return failure(
                StatusCode::BAD_GATEWAY,
                &format!("Agent Control upstream body failed: {error}"),
            )
        }
    };
    let mut forwarded = Response::new(Body::from(body));
    *forwarded.status_mut() = status;
    for (name, value) in headers {
        if let Some(name) = name {
            if name != header::TRANSFER_ENCODING && name != header::CONTENT_LENGTH {
                forwarded.headers_mut().insert(name, value);
            }
        }
    }
    forwarded
}

fn failure(status: StatusCode, detail: &str) -> Response {
    let document: Value = json!({
        "status": status.as_u16(),
        "detail": detail,
        "source": "issue-680-agent-control-scenario-proxy"
    });
    (status, Json(document)).into_response()
}
