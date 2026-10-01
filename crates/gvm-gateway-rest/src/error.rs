// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Error handling for the REST adapter.

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_domain::{GatewayError, GatewayErrorCode};
use serde::Serialize;

const PROBLEM_TYPE_BASE_URL: &str = "https://gvm-gateway.greenbone.net/errors";

/// RFC 9457 problem details payload.
#[derive(Debug, Serialize)]
pub struct ProblemDetails {
    /// Problem type URI.
    pub r#type: String,
    /// Stable machine-readable error identity.
    pub code: String,
    /// Human-readable summary.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Occurrence-specific detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Request-specific instance identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

/// REST adapter error mapped to RFC 9457 problem details.
pub struct RestError {
    status: StatusCode,
    problem: ProblemDetails,
}

impl RestError {
    /// Builds a REST error from a domain error.
    pub fn from_gateway_error(error: GatewayError, instance: impl Into<String>) -> Self {
        let instance = instance.into();
        let status = status_for_gateway_error(&error);
        let code = error.code();
        Self::from_parts(
            code,
            title_for_code(code),
            status,
            Some(public_detail_for_gateway_error(&error, status, &instance)),
            Some(instance),
        )
    }

    /// Builds a problem-details 404 for an unknown route.
    pub fn not_found(instance: impl Into<String>) -> Self {
        Self::from_parts(
            GatewayErrorCode::NotFound,
            title_for_code(GatewayErrorCode::NotFound),
            StatusCode::NOT_FOUND,
            Some("The requested route does not exist.".to_string()),
            Some(instance.into()),
        )
    }

    /// Builds a 405 problem details response.
    pub fn method_not_allowed(instance: impl Into<String>) -> Self {
        Self::from_custom_parts(
            "method-not-allowed",
            "method_not_allowed",
            "Method Not Allowed",
            StatusCode::METHOD_NOT_ALLOWED,
            Some("The requested HTTP method is not allowed for this route.".to_string()),
            Some(instance.into()),
        )
    }

    /// Builds a 403 problem details response.
    pub fn forbidden(detail: impl Into<String>, instance: impl Into<String>) -> Self {
        Self::from_parts(
            GatewayErrorCode::Forbidden,
            title_for_code(GatewayErrorCode::Forbidden),
            StatusCode::FORBIDDEN,
            Some(detail.into()),
            Some(instance.into()),
        )
    }

    /// Builds a 429 problem details response.
    pub fn too_many_requests(detail: impl Into<String>, instance: impl Into<String>) -> Self {
        Self::from_parts(
            GatewayErrorCode::TooManyRequests,
            title_for_code(GatewayErrorCode::TooManyRequests),
            StatusCode::TOO_MANY_REQUESTS,
            Some(detail.into()),
            Some(instance.into()),
        )
    }

    /// Builds a 413 problem details response for a bounded upload violation.
    pub fn payload_too_large(detail: impl Into<String>, instance: impl Into<String>) -> Self {
        Self::from_custom_parts(
            "payload-too-large",
            "payload_too_large",
            "Payload Too Large",
            StatusCode::PAYLOAD_TOO_LARGE,
            Some(detail.into()),
            Some(instance.into()),
        )
    }

    /// Builds a 415 problem details response for a disallowed request media type.
    pub fn unsupported_media_type(detail: impl Into<String>, instance: impl Into<String>) -> Self {
        Self::from_custom_parts(
            "unsupported-media-type",
            "unsupported_media_type",
            "Unsupported Media Type",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Some(detail.into()),
            Some(instance.into()),
        )
    }

    /// Builds a 503 problem details response.
    pub fn service_unavailable(detail: impl Into<String>, instance: impl Into<String>) -> Self {
        Self::from_custom_parts(
            "service-unavailable",
            "service_unavailable",
            "Service Unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
            Some(detail.into()),
            Some(instance.into()),
        )
    }

    fn from_parts(
        code: GatewayErrorCode,
        title: &'static str,
        status: StatusCode,
        detail: Option<String>,
        instance: Option<String>,
    ) -> Self {
        Self::from_custom_parts(
            code.problem_slug(),
            code.as_str(),
            title,
            status,
            detail,
            instance,
        )
    }

    fn from_custom_parts(
        slug: &str,
        code: &str,
        title: &'static str,
        status: StatusCode,
        detail: Option<String>,
        instance: Option<String>,
    ) -> Self {
        Self {
            status,
            problem: ProblemDetails {
                r#type: format!("{PROBLEM_TYPE_BASE_URL}/{slug}"),
                code: code.to_string(),
                title: title.to_string(),
                status: status.as_u16(),
                detail,
                instance,
            },
        }
    }
}

impl IntoResponse for RestError {
    fn into_response(self) -> Response {
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(self.problem),
        )
            .into_response()
    }
}

fn status_for_gateway_error(error: &GatewayError) -> StatusCode {
    match error {
        GatewayError::BackendUnavailable(_) => StatusCode::BAD_GATEWAY,
        GatewayError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
        GatewayError::NotFound(_) => StatusCode::NOT_FOUND,
        GatewayError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        GatewayError::Unauthorized(_)
        | GatewayError::SessionExpired(_)
        | GatewayError::SessionInvalidated(_) => StatusCode::UNAUTHORIZED,
        GatewayError::Forbidden(_) => StatusCode::FORBIDDEN,
        GatewayError::Conflict(_) => StatusCode::CONFLICT,
        GatewayError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
        GatewayError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        GatewayError::GatewayTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
    }
}

fn public_detail_for_gateway_error(
    error: &GatewayError,
    status: StatusCode,
    instance: &str,
) -> String {
    match error {
        GatewayError::BackendUnavailable(detail) => {
            log_private_gateway_error(error.code(), status, instance, detail);
            "The backend service is unavailable.".to_string()
        }
        GatewayError::Internal(detail) => {
            log_private_gateway_error(error.code(), status, instance, detail);
            "An internal server error occurred.".to_string()
        }
        _ => error.detail().to_string(),
    }
}

fn log_private_gateway_error(
    code: GatewayErrorCode,
    status: StatusCode,
    instance: &str,
    detail: &str,
) {
    tracing::error!(
        error_code = code.as_str(),
        http_status = status.as_u16(),
        instance,
        error_detail = %detail,
        "gateway error detail hidden from client response"
    );
}

fn title_for_code(code: GatewayErrorCode) -> &'static str {
    match code {
        GatewayErrorCode::BackendUnavailable => "Bad Gateway",
        GatewayErrorCode::NotImplemented => "Not Implemented",
        GatewayErrorCode::NotFound => "Not Found",
        GatewayErrorCode::BadRequest => "Bad Request",
        GatewayErrorCode::Unauthorized => "Unauthorized",
        GatewayErrorCode::SessionExpired => "Session Expired",
        GatewayErrorCode::SessionInvalidated => "Session Invalidated",
        GatewayErrorCode::Forbidden => "Forbidden",
        GatewayErrorCode::Conflict => "Conflict",
        GatewayErrorCode::TooManyRequests => "Too Many Requests",
        GatewayErrorCode::InternalServerError => "Internal Server Error",
        GatewayErrorCode::GatewayTimeout => "Gateway Timeout",
    }
}

#[cfg(test)]
#[path = "error_test.rs"]
mod error_test;
