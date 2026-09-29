// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    dto::PaginationResponse,
    error::RestError,
    openapi::{ok_json, problem_response},
    router::bearer_token,
    supporting_resources::common::{PaginationOnlyQuery, PaginationOnlyQueryParams},
};

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "NvtFamily")]
pub(crate) struct NvtFamilyResponse {
    name: String,
    #[serde(rename = "maxNvtCount", skip_serializing_if = "Option::is_none")]
    max_nvt_count: Option<u32>,
}

impl From<gvm_gateway_domain::NvtFamily> for NvtFamilyResponse {
    fn from(nvt_family: gvm_gateway_domain::NvtFamily) -> Self {
        Self {
            name: nvt_family.name,
            max_nvt_count: nvt_family.max_nvt_count,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "NvtFamilyList")]
pub(crate) struct NvtFamilyListResponse {
    data: Vec<NvtFamilyResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::NvtFamilyPage> for NvtFamilyListResponse {
    fn from(page: gvm_gateway_domain::NvtFamilyPage) -> Self {
        Self {
            data: page.data.into_iter().map(NvtFamilyResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Lists NVT families visible to the authenticated session.
pub async fn list_nvt_families(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match PaginationOnlyQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_nvt_families(&session, query.page, query.per_page)
        .await
    {
        Ok(page) => (StatusCode::OK, Json(NvtFamilyListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub(crate) fn list_nvt_families_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getNvtFamilies")
        .tag("NVT Families")
        .summary("List NVT families")
        .description(
            "Returns a paginated list of NVT families. This endpoint is collection-only and does not accept filter expressions.",
        )
        .security_requirement("bearerAuth")
        .input::<Query<PaginationOnlyQueryParams>>()
        .response_with::<200, Json<NvtFamilyListResponse>, _>(ok_json(
            "Paginated list of NVT families",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}
