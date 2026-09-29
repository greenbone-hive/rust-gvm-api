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

use super::common::{
    supporting_query, SupportingListQuery, SupportingResourceListQueryParams,
    SupportingResourceMetaResponse,
};
use crate::{
    dto::PaginationResponse,
    error::RestError,
    openapi::{ok_json, problem_response, ResourceIdPathDoc},
    router::bearer_token,
    targets::validate_uuid,
};

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportFormat")]
pub(crate) struct ReportFormatResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extension: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<String>,
    active: bool,
    predefined: bool,
}

impl From<gvm_gateway_domain::ReportFormat> for ReportFormatResponse {
    fn from(report_format: gvm_gateway_domain::ReportFormat) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(report_format.meta),
            content_type: report_format.content_type,
            extension: report_format.extension,
            summary: report_format.summary,
            trust: report_format.trust,
            active: report_format.active,
            predefined: report_format.predefined,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportFormatList")]
pub(crate) struct ReportFormatListResponse {
    data: Vec<ReportFormatResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::ReportFormatPage> for ReportFormatListResponse {
    fn from(page: gvm_gateway_domain::ReportFormatPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(ReportFormatResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Lists report formats available to the authenticated session.
pub async fn list_report_formats(
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
        .list_report_formats(&session, supporting_query(query))
        .await
    {
        Ok(page) => (StatusCode::OK, Json(ReportFormatListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single report format by id.
pub async fn get_report_format(
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

    match service.get_report_format(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(ReportFormatResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub(crate) fn list_report_formats_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportFormats")
        .tag("Report Formats")
        .summary("List report formats")
        .description("Returns a paginated list of report formats available for report export.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<ReportFormatListResponse>, _>(ok_json(
            "Paginated list of report formats",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_report_format_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportFormat")
        .tag("Report Formats")
        .summary("Get a report format")
        .description("Returns the details for a single report format.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ReportFormatResponse>, _>(ok_json("Report format details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}
