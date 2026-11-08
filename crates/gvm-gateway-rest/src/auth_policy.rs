// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Shared REST route auth classification.

use axum::http::Method;

/// Auth policy for a REST route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestRouteAuthPolicy {
    /// Public endpoint with no auth requirement.
    Public,
    /// Basic-auth-only session creation endpoint.
    SessionCreate,
    /// Bearer-only current-session lifecycle endpoint.
    SessionCurrent,
    /// Protected endpoint that requires an existing bearer session.
    BearerOnly,
    /// Protected endpoint that accepts bearer auth or request-scoped Basic auth.
    Protected,
}

/// Classifies a runtime REST path into its auth policy bucket.
pub(crate) fn classify_runtime_route(method: &Method, path: &str) -> Option<RestRouteAuthPolicy> {
    if matches!(path, "/health" | "/ready") {
        return Some(RestRouteAuthPolicy::Public);
    }

    if matches!(
        path,
        "/api/v1/version"
            | "/api/v1/openapi.json"
            | "/api/v1/docs"
            | "/api/v1/docs/redoc.standalone.js"
    ) {
        return Some(RestRouteAuthPolicy::Public);
    }

    if path == "/api/v1/session" && *method == Method::POST {
        return Some(RestRouteAuthPolicy::SessionCreate);
    }

    if path == "/api/v1/session" {
        return Some(RestRouteAuthPolicy::SessionCurrent);
    }

    if *method == Method::POST && is_report_export_job_collection(path) {
        return Some(RestRouteAuthPolicy::BearerOnly);
    }

    if path.starts_with("/api/v1/") {
        return Some(RestRouteAuthPolicy::Protected);
    }

    None
}

fn is_report_export_job_collection(path: &str) -> bool {
    path.strip_prefix("/api/v1/reports/")
        .and_then(|path| path.strip_suffix("/exports"))
        .is_some_and(|report_id| !report_id.is_empty() && !report_id.contains('/'))
}

/// Maps a served OpenAPI path back to the runtime path used by the router.
pub(crate) fn runtime_path_from_openapi_path(path: &str) -> String {
    match path {
        "/health" | "/ready" => path.to_string(),
        "/version" => "/api/v1/version".to_string(),
        "/openapi.json" => "/api/v1/openapi.json".to_string(),
        _ => format!("/api/v1{path}"),
    }
}

#[cfg(test)]
#[path = "auth_policy_test.rs"]
mod auth_policy_test;
