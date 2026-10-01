// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! System endpoint DTOs, handlers, and OpenAPI transforms for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    extract::{Extension, OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    error::RestError,
    openapi::{ok_json, problem_response},
    router::bearer_token,
    shutdown::ShutdownRuntime,
};

// ============================================================================
// Response DTOs
// ============================================================================

/// Liveness state.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) enum HealthState {
    #[serde(rename = "ok")]
    Ok,
}

/// JSON body returned by `GET /health`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "HealthStatus")]
pub(crate) struct HealthStatusResponse {
    status: HealthState,
}

/// Readiness state.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) enum ReadinessState {
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "notReady")]
    NotReady,
}

/// JSON body returned by `GET /ready`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReadinessStatus")]
pub(crate) struct ReadinessStatusResponse {
    status: ReadinessState,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// JSON body returned by `GET /api/v1/version`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "VersionInfo")]
pub(crate) struct VersionInfoResponse {
    /// REST API contract version, aligned with the gateway package version.
    #[serde(rename = "apiVersion")]
    api_version: String,
    /// GMP protocol version reported by the proxied gvmd.
    #[serde(rename = "gmpVersion")]
    gmp_version: String,
}

/// JSON body returned for a single backend timezone.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Timezone")]
pub(crate) struct TimezoneResponse {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<String>,
}

impl From<gvm_gateway_domain::Timezone> for TimezoneResponse {
    fn from(timezone: gvm_gateway_domain::Timezone) -> Self {
        Self {
            name: timezone.name,
            offset: timezone.offset,
        }
    }
}

/// JSON body returned by `GET /api/v1/timezones`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TimezoneList")]
pub(crate) struct TimezoneListResponse {
    data: Vec<TimezoneResponse>,
}

// ============================================================================
// Handlers
// ============================================================================

pub(crate) async fn health(State(service): State<GatewayService>) -> Response {
    let _ = service.health();
    Json(HealthStatusResponse {
        status: HealthState::Ok,
    })
    .into_response()
}

pub(crate) async fn ready(
    State(service): State<GatewayService>,
    Extension(shutdown): Extension<std::sync::Arc<ShutdownRuntime>>,
) -> Response {
    if shutdown.is_shutting_down() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadinessStatusResponse {
                status: ReadinessState::NotReady,
                reason: Some("shutdown in progress".to_string()),
            }),
        )
            .into_response();
    }

    match service.ready().await {
        Ok(readiness) if readiness.status == "ready" => (
            StatusCode::OK,
            Json(ReadinessStatusResponse {
                status: ReadinessState::Ready,
                reason: readiness.reason,
            }),
        )
            .into_response(),
        Ok(readiness) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadinessStatusResponse {
                status: ReadinessState::NotReady,
                reason: readiness.reason,
            }),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, "/ready").into_response(),
    }
}

pub(crate) async fn version(State(service): State<GatewayService>) -> Response {
    match service.version().await {
        Ok(version) => (
            StatusCode::OK,
            Json(VersionInfoResponse {
                api_version: version.api_version,
                gmp_version: version.gmp_version,
            }),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, "/api/v1/version").into_response(),
    }
}

pub(crate) async fn list_timezones(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.list_timezones(&session).await {
        Ok(timezones) => (
            StatusCode::OK,
            Json(TimezoneListResponse {
                data: timezones.into_iter().map(TimezoneResponse::from).collect(),
            }),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `GET /health`.
pub(crate) fn health_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getHealth")
        .tag("System")
        .summary("Liveness probe")
        .description("Returns basic process liveness information.")
        .response_with::<200, Json<HealthStatusResponse>, _>(|response| {
            response.description("Service is alive")
        });

    problem_response::<400>(op, "Invalid request")
}

/// OpenAPI transform for `GET /ready`.
pub(crate) fn ready_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReadiness")
        .tag("System")
        .summary("Readiness probe")
        .description(
            "Indicates whether the service is ready to handle requests. Returns `503` while backend readiness is failing or graceful shutdown is draining in-flight requests.",
        )
        .response_with::<200, Json<ReadinessStatusResponse>, _>(|response| {
            response.description("Service is ready")
        })
        .response_with::<503, Json<ReadinessStatusResponse>, _>(|response| {
            response.description("Service is not ready")
        });

    problem_response::<400>(op, "Invalid request")
}

/// OpenAPI transform for `GET /api/v1/version`.
pub(crate) fn version_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getVersion")
        .tag("System")
        .summary("Get proxied gvmd version information")
        .description(
            "Returns the GMP protocol version reported by the proxied gvmd. The `apiVersion` field identifies the REST API contract version and is aligned with the gateway package version.",
        )
        .response_with::<200, Json<VersionInfoResponse>, _>(|response| {
            response.description("Proxied gvmd version information")
        });

    let op = problem_response::<400>(op, "Invalid request");

    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/timezones`.
pub(crate) fn list_timezones_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTimezones")
        .tag("System")
        .summary("List backend timezones")
        .description(
            "Returns the timezones known to the proxied gvmd backend. The catalog is sourced from the connected backend rather than the gateway host's local timezone database.",
        )
        .security_requirement("bearerAuth")
        .response_with::<200, Json<TimezoneListResponse>, _>(ok_json("Backend timezones"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<501>(
        op,
        "Connected backend does not support the GMP get_timezones command",
    );
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

#[cfg(test)]
#[path = "system_test.rs"]
mod system_test;
