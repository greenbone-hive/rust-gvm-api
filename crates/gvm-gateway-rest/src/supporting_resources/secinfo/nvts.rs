// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::query::{nvt_query, NvtListQuery, NvtListQueryParams};
use crate::{
    dto::PaginationResponse,
    error::RestError,
    openapi::{ok_json, problem_response},
    router::bearer_token,
};

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub(crate) struct NvtOidPathDoc {
    id: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Nvt")]
pub(crate) struct NvtResponse {
    oid: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    family: Option<String>,
    #[serde(rename = "cvssBase", skip_serializing_if = "Option::is_none")]
    cvss_base: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<String>,
    #[serde(rename = "solutionType", skip_serializing_if = "Option::is_none")]
    solution_type: Option<String>,
}

impl From<gvm_gateway_domain::Nvt> for NvtResponse {
    fn from(nvt: gvm_gateway_domain::Nvt) -> Self {
        Self {
            oid: nvt.oid,
            name: nvt.name,
            family: nvt.family,
            cvss_base: nvt.cvss_base,
            severity: nvt.severity,
            tags: nvt.tags,
            solution_type: nvt.solution_type,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "NvtList")]
pub(crate) struct NvtListResponse {
    data: Vec<NvtResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::NvtPage> for NvtListResponse {
    fn from(page: gvm_gateway_domain::NvtPage) -> Self {
        Self {
            data: page.data.into_iter().map(NvtResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Lists NVTs visible to the authenticated session.
pub async fn list_nvts(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match NvtListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.list_nvts(&session, nvt_query(query)).await {
        Ok(page) => (StatusCode::OK, Json(NvtListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single NVT by OID.
pub async fn get_nvt(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.get_nvt(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(NvtResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub(crate) fn list_nvts_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getNvts")
        .tag("NVTs")
        .summary("List NVTs")
        .description(
            "Returns a paginated list of network vulnerability tests available in the feed catalog.",
        )
        .security_requirement("bearerAuth")
        .input::<Query<NvtListQueryParams>>()
        .response_with::<200, Json<NvtListResponse>, _>(ok_json("Paginated list of NVTs"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_nvt_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getNvt")
        .tag("NVTs")
        .summary("Get an NVT")
        .description("Returns the details for a single network vulnerability test by OID.")
        .security_requirement("bearerAuth")
        .input::<Path<NvtOidPathDoc>>()
        .response_with::<200, Json<NvtResponse>, _>(ok_json("NVT details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}
