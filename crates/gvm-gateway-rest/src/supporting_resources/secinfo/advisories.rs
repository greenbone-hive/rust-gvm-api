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
use serde::Serialize;

use super::inventory::SecInfoIdPathDoc;
use crate::{
    dto::PaginationResponse,
    error::RestError,
    handler::list_resource,
    openapi::{ok_json, problem_response},
    router::bearer_token,
    supporting_resources::common::{
        supporting_query, SupportingListQuery, SupportingResourceListQueryParams,
    },
};

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "CertBundAdvisory")]
pub(crate) struct CertBundAdvisoryResponse {
    id: String,
    name: String,
}

impl From<gvm_gateway_domain::CertBundAdvisory> for CertBundAdvisoryResponse {
    fn from(advisory: gvm_gateway_domain::CertBundAdvisory) -> Self {
        Self {
            id: advisory.id,
            name: advisory.name,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "CertBundAdvisoryList")]
pub(crate) struct CertBundAdvisoryListResponse {
    data: Vec<CertBundAdvisoryResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::CertBundAdvisoryPage> for CertBundAdvisoryListResponse {
    fn from(page: gvm_gateway_domain::CertBundAdvisoryPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(CertBundAdvisoryResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "DfnCertAdvisory")]
pub(crate) struct DfnCertAdvisoryResponse {
    id: String,
    name: String,
}

impl From<gvm_gateway_domain::DfnCertAdvisory> for DfnCertAdvisoryResponse {
    fn from(advisory: gvm_gateway_domain::DfnCertAdvisory) -> Self {
        Self {
            id: advisory.id,
            name: advisory.name,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "DfnCertAdvisoryList")]
pub(crate) struct DfnCertAdvisoryListResponse {
    data: Vec<DfnCertAdvisoryResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::DfnCertAdvisoryPage> for DfnCertAdvisoryListResponse {
    fn from(page: gvm_gateway_domain::DfnCertAdvisoryPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(DfnCertAdvisoryResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Lists CERT-Bund advisories visible to the authenticated session.
pub async fn list_cert_bund_advisories(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        SupportingListQuery::try_from_query_string,
        |service, session, query| async move {
            service
                .list_cert_bund_advisories(&session, supporting_query(query))
                .await
        },
        CertBundAdvisoryListResponse::from,
    )
    .await
}

/// Returns a single CERT-Bund advisory by identifier.
pub async fn get_cert_bund_advisory(
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

    match service.get_cert_bund_advisory(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(CertBundAdvisoryResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Lists DFN-CERT advisories visible to the authenticated session.
pub async fn list_dfn_cert_advisories(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        SupportingListQuery::try_from_query_string,
        |service, session, query| async move {
            service
                .list_dfn_cert_advisories(&session, supporting_query(query))
                .await
        },
        DfnCertAdvisoryListResponse::from,
    )
    .await
}

/// Returns a single DFN-CERT advisory by identifier.
pub async fn get_dfn_cert_advisory(
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

    match service.get_dfn_cert_advisory(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(DfnCertAdvisoryResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub(crate) fn list_cert_bund_advisories_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCertBundAdvisories")
        .tag("CERT-Bund Advisories")
        .summary("List CERT-Bund advisories")
        .description(
            "Returns a paginated list of CERT-Bund advisory entries from the SecInfo database.",
        )
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<CertBundAdvisoryListResponse>, _>(ok_json(
            "Paginated list of CERT-Bund advisories",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_cert_bund_advisory_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCertBundAdvisory")
        .tag("CERT-Bund Advisories")
        .summary("Get a CERT-Bund advisory")
        .description("Returns the details for a single CERT-Bund advisory entry.")
        .security_requirement("bearerAuth")
        .input::<Path<SecInfoIdPathDoc>>()
        .response_with::<200, Json<CertBundAdvisoryResponse>, _>(ok_json(
            "CERT-Bund advisory details",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_dfn_cert_advisories_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getDfnCertAdvisories")
        .tag("DFN-CERT Advisories")
        .summary("List DFN-CERT advisories")
        .description(
            "Returns a paginated list of DFN-CERT advisory entries from the SecInfo database.",
        )
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<DfnCertAdvisoryListResponse>, _>(ok_json(
            "Paginated list of DFN-CERT advisories",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_dfn_cert_advisory_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getDfnCertAdvisory")
        .tag("DFN-CERT Advisories")
        .summary("Get a DFN-CERT advisory")
        .description("Returns the details for a single DFN-CERT advisory entry.")
        .security_requirement("bearerAuth")
        .input::<Path<SecInfoIdPathDoc>>()
        .response_with::<200, Json<DfnCertAdvisoryResponse>, _>(ok_json(
            "DFN-CERT advisory details",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}
