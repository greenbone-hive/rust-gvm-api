// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    io,
    io::Write,
    sync::{Arc, Mutex, OnceLock},
};

use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Method, Request, StatusCode},
};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use tower::ServiceExt;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt};

use super::*;

#[derive(Clone)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn capture_tracing() -> Arc<Mutex<Vec<u8>>> {
    static BUFFER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    static INIT: OnceLock<()> = OnceLock::new();

    let buffer = BUFFER
        .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
        .clone();

    INIT.get_or_init(|| {
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .without_time()
                .with_span_events(FmtSpan::CLOSE)
                .with_writer(move || SharedWriter(writer.clone())),
        );
        let _ = tracing::subscriber::set_global_default(subscriber);
    });

    buffer.lock().unwrap().clear();
    buffer
}

async fn lock_tracing() -> AsyncMutexGuard<'static, ()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(())).lock().await
}

fn static_gateway_service() -> GatewayService {
    let adapter = Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7"));
    let system: Arc<dyn gvm_gateway_domain::SystemPort> = adapter.clone();
    let alerts: Arc<dyn gvm_gateway_domain::AlertPort> = adapter.clone();
    let schedules: Arc<dyn gvm_gateway_domain::SchedulePort> = adapter.clone();
    let credentials: Arc<dyn gvm_gateway_domain::CredentialPort> = adapter.clone();
    let port_lists: Arc<dyn gvm_gateway_domain::PortListPort> = adapter.clone();
    let feeds: Arc<dyn gvm_gateway_domain::FeedPort> = adapter.clone();
    let identity: Arc<dyn gvm_gateway_domain::IdentityPort> = adapter.clone();
    let targets: Arc<dyn gvm_gateway_domain::TargetPort> = adapter.clone();
    let tasks: Arc<dyn gvm_gateway_domain::TaskPort> = adapter.clone();
    let auth: Arc<dyn gvm_gateway_domain::AuthPort> = adapter.clone();
    let reports: Arc<dyn gvm_gateway_domain::ReportPort> = adapter.clone();
    let results: Arc<dyn gvm_gateway_domain::ResultPort> = adapter.clone();
    let scan_configs: Arc<dyn gvm_gateway_domain::ScanConfigPort> = adapter.clone();
    let scanners: Arc<dyn gvm_gateway_domain::ScannerPort> = adapter.clone();
    let agents: Arc<dyn gvm_gateway_domain::AgentPort> = adapter.clone();
    let supporting_resources: Arc<dyn gvm_gateway_domain::SupportingResourcePort> = adapter;

    GatewayService::new(
        gvm_gateway_app::GatewayPorts {
            system,
            alerts,
            schedules,
            credentials,
            port_lists,
            feeds,
            identity,
            targets,
            tasks,
            auth,
            reports,
            results,
            scan_configs,
            scanners,
            agents,
            supporting_resources,
        },
        Arc::new(gvm_gateway_domain::SessionManager::default()),
    )
}

#[tokio::test]
async fn draining_router_rejects_new_non_probe_requests() {
    let service = static_gateway_service();
    let shutdown = Arc::new(ShutdownRuntime::new());
    let app = build_router_with_runtime_and_security(
        service,
        Arc::clone(&shutdown),
        RestSecurityConfig::default(),
    );

    assert!(shutdown.begin_shutdown());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn draining_router_keeps_readiness_probe_available() {
    let service = static_gateway_service();
    let shutdown = Arc::new(ShutdownRuntime::new());
    let app = build_router_with_runtime_and_security(
        service,
        Arc::clone(&shutdown),
        RestSecurityConfig::default(),
    );

    assert!(shutdown.begin_shutdown());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn specialized_target_routes_require_authentication() {
    // Implemented current-GVMD target routes remain protected API surface,
    // rather than becoming public discovery endpoints.
    let app = build_router(static_gateway_service());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/oci-image-targets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn generic_resource_routes_dispatch_to_typed_services() {
    // Static typed ports return the sanitized backend-unavailable response.
    // Seeing 502 on every implemented generic route proves the router no
    // longer dispatches these methods to the 501 reservation handler.
    let app = build_router(static_gateway_service());
    let id = "123e4567-e89b-12d3-a456-426614174000";
    for (method, uri, body) in [
        (Method::GET, "/api/v1/assets?type=host".to_string(), ""),
        (Method::GET, format!("/api/v1/assets/{id}?type=host"), ""),
        (
            Method::PUT,
            format!("/api/v1/assets/{id}?type=host"),
            r#"{"comment":"updated"}"#,
        ),
        (Method::DELETE, format!("/api/v1/assets/{id}"), ""),
        (Method::GET, "/api/v1/configs".to_string(), ""),
        (Method::GET, format!("/api/v1/configs/{id}"), ""),
        (Method::DELETE, format!("/api/v1/configs/{id}"), ""),
        (Method::POST, format!("/api/v1/configs/{id}/clone"), ""),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(&uri)
                    .header(axum::http::header::AUTHORIZATION, "Basic YWRtaW46c2VjcmV0")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "{method} {uri} should reach the static typed port"
        );
    }

    // Unsupported generic creation/config modification methods are omitted
    // from the contract and use the normal known-path 405 response.
    for (method, uri) in [
        (Method::POST, "/api/v1/assets"),
        (Method::POST, "/api/v1/configs"),
        (
            Method::PUT,
            "/api/v1/configs/123e4567-e89b-12d3-a456-426614174000",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}

#[tokio::test]
async fn browser_docs_use_repository_bundled_redoc() {
    // The browser UI is public but outside the API contract. It must load the
    // generated contract and repository-bundled Redoc asset without a CDN.
    let app = build_router(static_gateway_service());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/docs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "text/html; charset=utf-8"
    );
    assert_eq!(
        response.headers().get("content-security-policy").unwrap(),
        "default-src 'none'; base-uri 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; img-src data: https:; font-src data:; frame-ancestors 'none'; form-action 'none'"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("spec-url=\"/api/v1/openapi.json\""));
    assert!(html.contains("src=\"/api/v1/docs/redoc.standalone.js\""));
    assert!(html.contains("integrity=\"sha512-"));
    assert!(!html.contains("cdn.redoc.ly"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/docs/redoc.standalone.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "text/javascript; charset=utf-8"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(body.len() > 1_000_000);
    assert!(body
        .windows(b"Redoc".len())
        .any(|window| window == b"Redoc"));
}

#[tokio::test]
async fn current_gvmd_report_and_operating_system_routes_dispatch_to_backend_boundary() {
    // These routes are no longer reserved placeholders. Even against the
    // static adapter they must route into the backend boundary and therefore
    // surface the shared backend-unavailable problem, not a router-level 501.
    let service = static_gateway_service();
    let token = service
        .session_manager()
        .create("router-test-user")
        .expect("test session")
        .token;
    let app = build_router(service);

    for path in [
        "/api/v1/reports/123e4567-e89b-12d3-a456-426614174000/hosts",
        "/api/v1/operating-systems",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "path={path}");
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/problem+json"),
            "path={path}"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            problem["code"],
            serde_json::json!("backend_unavailable"),
            "path={path}"
        );
        assert_eq!(problem["status"], serde_json::json!(502), "path={path}");
        assert_eq!(
            problem["detail"],
            serde_json::json!("The backend service is unavailable."),
            "path={path}"
        );
    }
}

#[tokio::test]
async fn request_trace_context_returns_trace_headers_without_echoing_baggage() {
    let _trace_lock = lock_tracing().await;
    let logs = capture_tracing();
    let service = static_gateway_service();
    let app = build_router(service);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header(
                    "traceparent",
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                )
                .header("tracestate", "vendor=value")
                .header("baggage", "secret=user-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("traceparent").unwrap(),
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    );
    assert_eq!(
        response.headers().get("tracestate").unwrap(),
        "vendor=value"
    );
    assert!(response.headers().get("baggage").is_none());

    let output = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(output.contains("http.request"));
    assert!(output.contains("http_method=GET"));
    assert!(output.contains("http_route=/health"));
    assert!(!output.contains("secret=user-token"));
}

#[tokio::test]
async fn session_trace_labels_do_not_include_bearer_tokens() {
    let _trace_lock = lock_tracing().await;
    let logs = capture_tracing();
    let service = static_gateway_service();
    let app = build_router(service);

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session")
                .header(axum::http::header::AUTHORIZATION, "Basic YWRtaW46c2VjcmV0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = created["sessionToken"].as_str().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let output = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(output.contains("http_route=/api/v1/session"));
    assert!(!output.contains(token));
}

#[tokio::test]
async fn unsupported_methods_on_known_paths_return_problem_responses() {
    let service = static_gateway_service();
    let app = build_router(service);

    // Covers the centralized 405 fallback so published paths cannot fall
    // through to the unknown-route fallback when a method is unsupported.
    for (method, uri) in [
        ("PATCH", "/api/v1/scan-configs"),
        (
            "PATCH",
            "/api/v1/scanners/123e4567-e89b-12d3-a456-426614174000",
        ),
        ("POST", "/api/v1/report-formats"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/problem+json")
        );
    }

    // A path that is not published must still use the 404 problem fallback.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
}

#[tokio::test]
async fn removed_ticket_routes_use_the_unknown_route_problem_contract() {
    // The removed routes must not be recognized as authenticated resources or
    // compatibility tombstones; both shapes use the ordinary 404 fallback.
    let app = build_router(static_gateway_service());

    for uri in [
        "/api/v1/tickets",
        "/api/v1/tickets/123e4567-e89b-12d3-a456-426614174000",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        "Bearer authenticated-session",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/problem+json")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["code"], serde_json::json!("not_found"));
        assert_eq!(problem["instance"], serde_json::json!(uri));
    }
}
