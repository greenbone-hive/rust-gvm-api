mod common;

use common::{
    assert_problem_status, assert_security_headers, target_harness, target_harness_with_security,
};
use gvm_gateway_rest::{
    peer_addr::TrustedProxyCidr,
    router::{RateLimitConfig, RestSecurityConfig},
};
use gvm_mock_server::Resource;
use http::StatusCode;

#[tokio::test]
async fn list_targets_accepts_request_scoped_basic_auth() {
    let harness = target_harness(|_| {}).await;
    let auth_count_before = harness
        .server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "authenticate")
        .count();

    let response = harness.get_targets_with_basic("admin", "admin").await;

    assert_eq!(response.status(), StatusCode::OK);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["data"], serde_json::json!([]));

    let history = harness.server.command_history();
    assert!(
        history
            .iter()
            .filter(|record| record.command_name() == "authenticate")
            .count()
            > auth_count_before
    );
    assert!(history
        .iter()
        .any(|record| record.command_name() == "get_targets"));

    let bearer_response = harness.get_targets().await;
    assert_eq!(bearer_response.status(), StatusCode::OK);

    harness.shutdown().await;
}

#[tokio::test]
async fn create_report_export_job_rejects_basic_without_side_effects() {
    let report_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let harness = target_harness(move |store| {
        store.create(Resource::with_id("report", "Basic rejection", report_id));
    })
    .await;
    harness.server.clear_history();

    // The bearer-only policy must run before temporary authentication and the
    // report preflight. Otherwise the accepted worker is immediately cancelled
    // when request-scoped Basic cleanup deletes its creating session.
    let response = harness
        .client
        .post(harness.url(&format!("/api/v1/reports/{report_id}/exports")))
        .basic_auth("admin", Some("admin"))
        .json(&serde_json::json!({ "format": "json" }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(response.status(), StatusCode::ACCEPTED);
    assert!(response.headers().get(reqwest::header::LOCATION).is_none());
    let problem = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(problem["code"], "unauthorized");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        harness.server.command_history().is_empty(),
        "rejected Basic auth must not authenticate, preflight, run, or cancel an export job"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn malformed_basic_auth_on_protected_route_returns_401() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .get(harness.url("/api/v1/targets"))
        .header("Authorization", "Basic not-base64")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["status"], 401);

    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_missing_bearer_rejected() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .get(harness.url("/api/v1/targets"))
        .send()
        .await
        .unwrap();

    assert_problem_status(response, StatusCode::UNAUTHORIZED).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_malformed_bearer_rejected() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .get(harness.url("/api/v1/targets"))
        .header("Authorization", "Bearer")
        .send()
        .await
        .unwrap();

    assert_problem_status(response, StatusCode::UNAUTHORIZED).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_unknown_session_rejected() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .get(harness.url("/api/v1/targets"))
        .bearer_auth("gvm_sess_unknown")
        .send()
        .await
        .unwrap();

    assert_problem_status(response, StatusCode::UNAUTHORIZED).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_expired_session_rejected() {
    let harness = target_harness(|_| {}).await;
    harness.sessions.expire(&harness.token).unwrap();

    let response = harness.get_targets().await;

    assert_problem_status(response, StatusCode::UNAUTHORIZED).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_invalidated_session_rejected() {
    let harness = target_harness(|_| {}).await;
    harness.sessions.remove(&harness.token).unwrap();

    let response = harness.get_targets().await;

    assert_problem_status(response, StatusCode::UNAUTHORIZED).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_valid_session_allowed() {
    let harness = target_harness(|_| {}).await;

    let response = harness.get_targets().await;

    assert_eq!(response.status(), StatusCode::OK);
    harness.shutdown().await;
}

#[tokio::test]
async fn cors_preflight_allowed_origin() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: vec!["https://ui.example".to_string()],
            rate_limit: RateLimitConfig::disabled(),
            trusted_proxy_cidrs: Vec::new(),
            native_tls_enabled: false,
        },
    )
    .await;

    let response = harness
        .client
        .request(reqwest::Method::OPTIONS, harness.url("/api/v1/targets"))
        .header("Origin", "https://ui.example")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://ui.example"
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn cors_preflight_denied_origin() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: vec!["https://ui.example".to_string()],
            rate_limit: RateLimitConfig::disabled(),
            trusted_proxy_cidrs: Vec::new(),
            native_tls_enabled: false,
        },
    )
    .await;

    let response = harness
        .client
        .request(reqwest::Method::OPTIONS, harness.url("/api/v1/targets"))
        .header("Origin", "https://evil.example")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
    harness.shutdown().await;
}

#[tokio::test]
async fn security_headers_present() {
    let harness = target_harness(|_| {}).await;

    let response = harness.get_targets().await;

    assert_security_headers(&response);
    harness.shutdown().await;
}

#[tokio::test]
async fn native_tls_security_config_emits_hsts() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig::disabled(),
            trusted_proxy_cidrs: Vec::new(),
            native_tls_enabled: true,
        },
    )
    .await;

    let response = harness.get_targets().await;

    assert_security_headers(&response);
    assert_eq!(
        response.headers().get("strict-transport-security").unwrap(),
        "max-age=31536000; includeSubDomains"
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn over_limit_returns_429() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(10),
                subject_per_window: Some(1),
            },
            trusted_proxy_cidrs: Vec::new(),
            native_tls_enabled: false,
        },
    )
    .await;

    let first = harness.get_targets().await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = harness.get_targets().await;

    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(second.headers().contains_key("retry-after"));
    let json = second.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["status"], 429);
    harness.shutdown().await;
}

#[tokio::test]
async fn retry_after_header_present() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(1),
                subject_per_window: Some(100),
            },
            trusted_proxy_cidrs: Vec::new(),
            native_tls_enabled: false,
        },
    )
    .await;

    let _ = harness.get_targets().await;
    let response = harness.get_targets().await;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0));
    harness.shutdown().await;
}

#[tokio::test]
async fn different_sessions_have_independent_subject_limits() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(10),
                subject_per_window: Some(1),
            },
            trusted_proxy_cidrs: Vec::new(),
            native_tls_enabled: false,
        },
    )
    .await;
    let second_token = harness.create_connected_session("admin", "admin").await;

    let first = harness.get_targets().await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = harness
        .client
        .get(harness.url("/api/v1/targets"))
        .bearer_auth(&second_token)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);

    let first_again = harness.get_targets().await;
    assert_eq!(first_again.status(), StatusCode::TOO_MANY_REQUESTS);

    harness.shutdown().await;
}

#[tokio::test]
async fn global_limit_applies_across_sessions() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(1),
                subject_per_window: Some(100),
            },
            trusted_proxy_cidrs: Vec::new(),
            native_tls_enabled: false,
        },
    )
    .await;
    let second_token = harness.create_connected_session("admin", "admin").await;

    let first = harness.get_targets().await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = harness
        .client
        .get(harness.url("/api/v1/targets"))
        .bearer_auth(&second_token)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    harness.shutdown().await;
}

#[tokio::test]
async fn session_creation_rate_limited_before_backend_work() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(10),
                subject_per_window: Some(1),
            },
            trusted_proxy_cidrs: Vec::new(),
            native_tls_enabled: false,
        },
    )
    .await;

    let first = harness.create_session_with_basic("admin", "admin").await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let auth_count_after_first = harness
        .server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "authenticate")
        .count();

    let second = harness.create_session_with_basic("admin", "admin").await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        harness
            .server
            .command_history()
            .iter()
            .filter(|record| record.command_name() == "authenticate")
            .count(),
        auth_count_after_first
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn session_creation_rate_limit_is_source_aware_before_authentication() {
    // A brute-force client can rotate Basic credentials on /session, so the
    // unauthenticated throttle must key by source before backend auth work.
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(10),
                subject_per_window: Some(1),
            },
            trusted_proxy_cidrs: Vec::new(),
            native_tls_enabled: false,
        },
    )
    .await;

    let first = harness.create_session_with_basic("admin", "admin").await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let auth_count_after_first = harness
        .server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "authenticate")
        .count();

    let second = harness
        .client
        .post(harness.url("/api/v1/session"))
        .basic_auth("admin", Some("different-password"))
        .send()
        .await
        .unwrap();

    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        harness
            .server
            .command_history()
            .iter()
            .filter(|record| record.command_name() == "authenticate")
            .count(),
        auth_count_after_first
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn trusted_forwarded_clients_have_independent_session_creation_limits() {
    // In the documented container shape, the direct peer can be the proxy.
    // Explicitly trusted proxy CIDRs let rate limiting use the forwarded client
    // IP so one login abuser does not exhaust the shared proxy bucket.
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(10),
                subject_per_window: Some(1),
            },
            trusted_proxy_cidrs: vec!["127.0.0.1/32".parse::<TrustedProxyCidr>().unwrap()],
            native_tls_enabled: false,
        },
    )
    .await;

    let first = harness
        .client
        .post(harness.url("/api/v1/session"))
        .header("X-Forwarded-For", "198.51.100.10")
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = harness
        .client
        .post(harness.url("/api/v1/session"))
        .header("X-Forwarded-For", "198.51.100.11")
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CREATED);

    let first_again = harness
        .client
        .post(harness.url("/api/v1/session"))
        .header("X-Forwarded-For", "198.51.100.10")
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(first_again.status(), StatusCode::TOO_MANY_REQUESTS);

    harness.shutdown().await;
}
