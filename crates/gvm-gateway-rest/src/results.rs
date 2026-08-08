// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Result DTOs, request parsing, handlers, and response mapping for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;
use schemars::JsonSchema;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceRefResponse},
    error::RestError,
    open_enum::open_string_enum,
    openapi::{ok_json, problem_response, ResourceIdPathDoc, ResultListQueryDoc},
    query::parse_collection_query,
    router::bearer_token,
    targets::validate_uuid,
};

// ============================================================================
// Response DTOs
// ============================================================================

open_string_enum! {
    /// Threat level for a scan result.
    pub(crate) enum Threat {
        High => "High",
        Medium => "Medium",
        Low => "Low",
        Log => "Log",
        Alarm => "Alarm",
    }
}

/// NVT (Network Vulnerability Test) reference in a result.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "NvtRef")]
pub(crate) struct NvtRefResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    oid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    family: Option<String>,
    #[serde(rename = "cvssBase", skip_serializing_if = "Option::is_none")]
    cvss_base: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cves: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<String>,
}

impl From<gvm_gateway_domain::NvtRef> for NvtRefResponse {
    fn from(n: gvm_gateway_domain::NvtRef) -> Self {
        Self {
            oid: n.oid,
            name: n.name,
            family: n.family,
            cvss_base: n.cvss_base,
            cves: n.cves,
            tags: n.tags,
        }
    }
}

/// JSON body returned for a single scan result.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Result")]
pub(crate) struct ResultResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threat: Option<Threat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nvt: Option<NvtRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<ResourceRefResponse>,
    #[serde(rename = "hostsCount", skip_serializing_if = "Option::is_none")]
    hosts_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurrences: Option<u32>,
}

impl From<gvm_gateway_domain::ScanResult> for ResultResponse {
    fn from(r: gvm_gateway_domain::ScanResult) -> Self {
        Self {
            id: parse_uuid(&r.id),
            name: r.name,
            host: r.host,
            port: r.port,
            severity: r.severity,
            threat: r.threat.as_deref().map(Threat::parse),
            nvt: r.nvt.map(NvtRefResponse::from),
            description: r.description,
            task: r.task.map(ResourceRefResponse::from),
            report: r.report.map(ResourceRefResponse::from),
            hosts_count: r.hosts_count,
            occurrences: r.occurrences,
        }
    }
}

/// JSON body returned for a paginated list of results.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ResultList")]
pub(crate) struct ResultListResponse {
    #[schemars(length(max = 1000))]
    data: Vec<ResultResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::ResultPage> for ResultListResponse {
    fn from(page: gvm_gateway_domain::ResultPage) -> Self {
        Self {
            data: page.data.into_iter().map(ResultResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Parsed list-results query from HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultListQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl ResultListQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let parsed = parse_collection_query(query)?;

        Ok(Self {
            filter_string: parsed.filter_string,
            filter_id: parsed.filter_id,
            page: parsed.page,
            per_page: parsed.per_page,
        })
    }
}

/// List results handler.
pub async fn list_results(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match ResultListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_results(
            &session,
            gvm_gateway_domain::ResultQuery {
                filter_string: query.filter_string,
                filter_id: query.filter_id,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(results) => (StatusCode::OK, Json(ResultListResponse::from(results))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get result handler.
pub async fn get_result(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.get_result(&session, &id).await {
        Ok(result) => (StatusCode::OK, Json(ResultResponse::from(result))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `GET /api/v1/results`.
pub(crate) fn list_results_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getResults")
        .tag("Results")
        .summary("List results")
        .description("Returns a paginated list of results.")
        .security_requirement("bearerAuth")
        .input::<Query<ResultListQueryDoc>>()
        .response_with::<200, Json<ResultListResponse>, _>(ok_json("Paginated list of results"));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/results/{id}`.
pub(crate) fn get_result_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getResult")
        .tag("Results")
        .summary("Get a result")
        .description("Returns the details for a single result.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ResultResponse>, _>(ok_json("Result details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "results_test.rs"]
mod results_test;
