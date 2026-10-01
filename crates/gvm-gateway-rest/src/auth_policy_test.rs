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
