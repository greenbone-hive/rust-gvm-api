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

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub(crate) struct SecInfoIdPathDoc {
    id: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Vulnerability")]
pub(crate) struct VulnerabilityResponse {
    id: String,
    name: String,
}

impl From<gvm_gateway_domain::Vulnerability> for VulnerabilityResponse {
    fn from(vuln: gvm_gateway_domain::Vulnerability) -> Self {
        Self {
            id: vuln.id,
            name: vuln.name,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "VulnerabilityList")]
pub(crate) struct VulnerabilityListResponse {
    data: Vec<VulnerabilityResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::VulnerabilityPage> for VulnerabilityListResponse {
    fn from(page: gvm_gateway_domain::VulnerabilityPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(VulnerabilityResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Cve")]
pub(crate) struct CveResponse {
    id: String,
    name: String,
}

impl From<gvm_gateway_domain::Cve> for CveResponse {
    fn from(cve: gvm_gateway_domain::Cve) -> Self {
        Self {
            id: cve.id,
            name: cve.name,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "CveList")]
pub(crate) struct CveListResponse {
    data: Vec<CveResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::CvePage> for CveListResponse {
    fn from(page: gvm_gateway_domain::CvePage) -> Self {
        Self {
            data: page.data.into_iter().map(CveResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Cpe")]
pub(crate) struct CpeResponse {
    id: String,
    name: String,
}

impl From<gvm_gateway_domain::Cpe> for CpeResponse {
    fn from(cpe: gvm_gateway_domain::Cpe) -> Self {
        Self {
            id: cpe.id,
            name: cpe.name,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "CpeList")]
pub(crate) struct CpeListResponse {
    data: Vec<CpeResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::CpePage> for CpeListResponse {
    fn from(page: gvm_gateway_domain::CpePage) -> Self {
        Self {
            data: page.data.into_iter().map(CpeResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Lists vulnerabilities (SecInfo) visible to the authenticated session.
pub async fn list_vulnerabilities(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match SupportingListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_vulnerabilities(&session, supporting_query(query))
        .await
    {
        Ok(page) => (StatusCode::OK, Json(VulnerabilityListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Lists CVEs visible to the authenticated session.
pub async fn list_cves(
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
            service.list_cves(&session, supporting_query(query)).await
        },
        CveListResponse::from,
    )
    .await
}

/// Returns a single CVE by identifier.
pub async fn get_cve(
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

    match service.get_cve(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(CveResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Lists CPEs visible to the authenticated session.
pub async fn list_cpes(
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
            service.list_cpes(&session, supporting_query(query)).await
        },
        CpeListResponse::from,
    )
    .await
}

/// Returns a single CPE by identifier.
pub async fn get_cpe(
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

    match service.get_cpe(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(CpeResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub(crate) fn list_vulnerabilities_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getVulnerabilities")
        .tag("Vulnerabilities")
        .summary("List vulnerabilities")
        .description("Returns a paginated list of vulnerabilities from the SecInfo database.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<VulnerabilityListResponse>, _>(ok_json(
            "Paginated list of vulnerabilities",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn list_cves_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCves")
        .tag("CVEs")
        .summary("List CVEs")
        .description("Returns a paginated list of CVE entries from the SecInfo database.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<CveListResponse>, _>(ok_json("Paginated list of CVEs"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_cve_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCve")
        .tag("CVEs")
        .summary("Get a CVE")
        .description("Returns the details for a single CVE entry.")
        .security_requirement("bearerAuth")
        .input::<Path<SecInfoIdPathDoc>>()
        .response_with::<200, Json<CveResponse>, _>(ok_json("CVE details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_cpes_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCpes")
        .tag("CPEs")
        .summary("List CPEs")
        .description("Returns a paginated list of CPE entries from the SecInfo database.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<CpeListResponse>, _>(ok_json("Paginated list of CPEs"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_cpe_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCpe")
        .tag("CPEs")
        .summary("Get a CPE")
        .description("Returns the details for a single CPE entry.")
        .security_requirement("bearerAuth")
        .input::<Path<SecInfoIdPathDoc>>()
        .response_with::<200, Json<CpeResponse>, _>(ok_json("CPE details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}
