// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::{classify_runtime_route, runtime_path_from_openapi_path, RestRouteAuthPolicy};
use axum::http::Method;

#[test]
fn classifies_public_routes() {
    assert_eq!(
        classify_runtime_route(&Method::GET, "/health"),
        Some(RestRouteAuthPolicy::Public)
    );
    assert_eq!(
        classify_runtime_route(&Method::GET, "/ready"),
        Some(RestRouteAuthPolicy::Public)
    );
    assert_eq!(
        classify_runtime_route(&Method::GET, "/api/v1/version"),
        Some(RestRouteAuthPolicy::Public)
    );
    assert_eq!(
        classify_runtime_route(&Method::GET, "/api/v1/openapi.json"),
        Some(RestRouteAuthPolicy::Public)
    );
    assert_eq!(
        classify_runtime_route(&Method::GET, "/api/v1/docs"),
        Some(RestRouteAuthPolicy::Public)
    );
    assert_eq!(
        classify_runtime_route(&Method::GET, "/api/v1/docs/redoc.standalone.js"),
        Some(RestRouteAuthPolicy::Public)
    );
}

#[test]
fn classifies_session_routes() {
    assert_eq!(
        classify_runtime_route(&Method::POST, "/api/v1/session"),
        Some(RestRouteAuthPolicy::SessionCreate)
    );
    assert_eq!(
        classify_runtime_route(&Method::GET, "/api/v1/session"),
        Some(RestRouteAuthPolicy::SessionCurrent)
    );
}

#[test]
fn classifies_only_report_export_job_creation_as_bearer_only() {
    // Export workers outlive the creating HTTP request, so their route must
    // retain a persistent bearer session instead of a request-scoped Basic
    // session that middleware tears down as soon as the response is returned.
    for path in [
        "/api/v1/reports/550e8400-e29b-41d4-a716-446655440000/exports",
        "/api/v1/reports/{id}/exports",
    ] {
        assert_eq!(
            classify_runtime_route(&Method::POST, path),
            Some(RestRouteAuthPolicy::BearerOnly)
        );
    }

    assert_eq!(
        classify_runtime_route(
            &Method::GET,
            "/api/v1/reports/550e8400-e29b-41d4-a716-446655440000/exports"
        ),
        Some(RestRouteAuthPolicy::Protected)
    );
    assert_eq!(
        classify_runtime_route(&Method::POST, "/api/v1/reports/exports"),
        Some(RestRouteAuthPolicy::Protected)
    );
}

#[test]
fn treats_non_session_api_routes_as_protected_by_default() {
    assert_eq!(
        classify_runtime_route(&Method::GET, "/api/v1/alerts"),
        Some(RestRouteAuthPolicy::Protected)
    );
    assert_eq!(
        classify_runtime_route(&Method::GET, "/api/v1/future-resource"),
        Some(RestRouteAuthPolicy::Protected)
    );
    assert_eq!(
        classify_runtime_route(&Method::POST, "/api/v1/reports"),
        Some(RestRouteAuthPolicy::Protected)
    );
}

#[test]
fn maps_openapi_paths_back_to_runtime_paths() {
    assert_eq!(runtime_path_from_openapi_path("/health"), "/health");
    assert_eq!(
        runtime_path_from_openapi_path("/version"),
        "/api/v1/version"
    );
    assert_eq!(
        runtime_path_from_openapi_path("/reports/{id}/exports"),
        "/api/v1/reports/{id}/exports"
    );
}
