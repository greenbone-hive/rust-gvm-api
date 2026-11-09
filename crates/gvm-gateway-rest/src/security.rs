// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! REST security middleware and request-scoped auth helpers.

use std::sync::Arc;

use axum::{
    extract::Request,
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;
use serde::Deserialize;

use crate::{
    auth_policy::{classify_runtime_route, RestRouteAuthPolicy},
    error::RestError,
    peer_addr::TrustedProxyCidr,
    rate_limit::{is_rate_limited_path, too_many_requests_response, RateLimitConfig, RateLimiter},
};

/// REST security middleware configuration.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct RestSecurityConfig {
    /// Exact origins allowed for browser CORS requests. Empty means deny.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    /// Rate-limit and backpressure settings.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Trusted direct proxy CIDRs whose X-Forwarded-For client IP may be used.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<TrustedProxyCidr>,
    /// Whether this gateway process terminates HTTPS directly.
    #[serde(default)]
    pub native_tls_enabled: bool,
}

#[derive(Debug)]
pub(crate) struct SecurityRuntime {
    config: RestSecurityConfig,
    limiter: RateLimiter,
}

impl SecurityRuntime {
    pub(crate) fn new(config: RestSecurityConfig) -> Self {
        Self {
            limiter: RateLimiter::new(
                config.rate_limit.clone(),
                config.trusted_proxy_cidrs.clone(),
            ),
            config,
        }
    }
}

pub(crate) async fn security_middleware(
    security: axum::extract::State<Arc<SecurityRuntime>>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path().to_string();

    if is_cors_preflight(&request) {
        return cors_preflight_response(&security.config, request.headers(), &path);
    }

    if is_rate_limited_path(&path) {
        if let Some(retry_after) = security.limiter.check_request(&request) {
            let mut response = too_many_requests_response(&path, retry_after);
            apply_security_headers(
                response.headers_mut(),
                &path,
                security.config.native_tls_enabled,
            );
            apply_cors_headers(response.headers_mut(), &security.config, request.headers());
            tracing::warn!(
                target: "gvm_gateway_rest::security",
                security_event = "rate_limit.exceeded",
                path = %path,
                retry_after_secs = retry_after,
                "rate_limit_exceeded"
            );
            return response;
        }
    }

    let request_headers = request.headers().clone();
    let mut response = next.run(request).await;
    apply_security_headers(
        response.headers_mut(),
        &path,
        security.config.native_tls_enabled,
    );
    apply_cors_headers(response.headers_mut(), &security.config, &request_headers);
    response
}

pub(crate) async fn request_scoped_basic_auth_middleware(
    service: axum::extract::State<GatewayService>,
    mut request: Request,
    next: axum::middleware::Next,
) -> Response {
    if rejects_request_scoped_basic_auth(&request) {
        let instance = request.uri().path().to_string();
        return RestError::from_gateway_error(
            GatewayError::Unauthorized("bearer authentication required".to_string()),
            instance,
        )
        .into_response();
    }

    if !uses_request_scoped_basic_auth(&request) {
        return next.run(request).await;
    }

    let instance = request.uri().path().to_string();
    let (username, password) = match basic_credentials(request.headers()) {
        Ok(credentials) => credentials,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    let created = match service.create_session(&username, &password).await {
        Ok(created) => created,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let token = created.token;

    let bearer = match HeaderValue::from_str(&format!("Bearer {token}")) {
        Ok(value) => value,
        Err(_) => {
            let _ = service.delete_session(&token).await;
            return RestError::from_gateway_error(
                GatewayError::BackendUnavailable("failed to prepare request-scoped session".into()),
                instance,
            )
            .into_response();
        }
    };
    request.headers_mut().insert(header::AUTHORIZATION, bearer);

    let response = next.run(request).await;
    let response_was_successful = response.status().is_success();
    match service.delete_session(&token).await {
        Ok(()) => response,
        Err(error) if response_was_successful => {
            RestError::from_gateway_error(error, instance).into_response()
        }
        Err(_error) => response,
    }
}

fn is_cors_preflight(request: &Request) -> bool {
    request.method() == Method::OPTIONS
        && request.headers().contains_key(header::ORIGIN)
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
}

fn cors_preflight_response(
    config: &RestSecurityConfig,
    headers: &HeaderMap,
    instance: &str,
) -> Response {
    let Some(origin) = allowed_origin(config, headers) else {
        let mut response = RestError::from_gateway_error(
            GatewayError::Forbidden("CORS origin is not allowed".to_string()),
            instance.to_string(),
        )
        .into_response();
        apply_security_headers(response.headers_mut(), instance, config.native_tls_enabled);
        return response;
    };

    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET,POST,PUT,DELETE,OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Authorization,Content-Type,Traceparent,Tracestate,Baggage"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
    apply_security_headers(headers, instance, config.native_tls_enabled);
    response
}

fn allowed_origin(config: &RestSecurityConfig, headers: &HeaderMap) -> Option<HeaderValue> {
    let origin = headers.get(header::ORIGIN)?.to_str().ok()?;
    if config
        .cors_allowed_origins
        .iter()
        .any(|allowed| allowed == origin)
    {
        HeaderValue::from_str(origin).ok()
    } else {
        None
    }
}

fn apply_cors_headers(headers: &mut HeaderMap, config: &RestSecurityConfig, request: &HeaderMap) {
    if let Some(origin) = allowed_origin(config, request) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
}

pub(crate) fn apply_security_headers(
    headers: &mut HeaderMap,
    path: &str,
    native_tls_enabled: bool,
) {
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    if path == "/api/v1/docs" {
        headers.insert(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'none'; base-uri 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; img-src data: https:; font-src data:; frame-ancestors 'none'; form-action 'none'",
            ),
        );
    }
    if path.starts_with("/api/") {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    if native_tls_enabled {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
}

fn uses_request_scoped_basic_auth(request: &Request) -> bool {
    if is_basic_auth(request.headers()).is_none() {
        return false;
    }

    matches!(
        classify_runtime_route(request.method(), request.uri().path()),
        Some(RestRouteAuthPolicy::Protected)
    )
}

fn rejects_request_scoped_basic_auth(request: &Request) -> bool {
    if is_basic_auth(request.headers()).is_none() {
        return false;
    }

    // An asynchronous worker must keep using the caller's persistent backend
    // context after this middleware returns; tearing down a temporary Basic
    // session here would immediately cancel that worker's job.
    matches!(
        classify_runtime_route(request.method(), request.uri().path()),
        Some(RestRouteAuthPolicy::BearerOnly)
    )
}

fn is_basic_auth(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
}

fn basic_credentials(headers: &HeaderMap) -> Result<(String, String), GatewayError> {
    let encoded = is_basic_auth(headers)
        .ok_or_else(|| GatewayError::Unauthorized("expected Basic authentication".to_string()))?;

    let decoded = BASE64
        .decode(encoded)
        .map_err(|_| GatewayError::Unauthorized("invalid Base64 in credentials".to_string()))?;
    let decoded_str = String::from_utf8(decoded)
        .map_err(|_| GatewayError::Unauthorized("invalid UTF-8 in credentials".to_string()))?;
    let (username, password) = decoded_str
        .split_once(':')
        .ok_or_else(|| GatewayError::Unauthorized("malformed Basic credentials".to_string()))?;

    if username.is_empty() {
        return Err(GatewayError::Unauthorized(
            "username must not be empty".to_string(),
        ));
    }

    Ok((username.to_string(), password.to_string()))
}

#[cfg(test)]
#[path = "security_test.rs"]
mod security_test;
