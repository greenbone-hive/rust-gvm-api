// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Report DTOs, request parsing, handlers, and response mapping for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    GatewayError, GetReportOpts, ReportApplication, ReportApplicationPage, ReportClosedCvePage,
    ReportCve, ReportCvePage, ReportErrorPage, ReportHost, ReportHostPage, ReportOperatingSystem,
    ReportOperatingSystemPage, ReportPortPage, ReportPortSummary, ReportQuery,
    ReportVulnerabilityPage, ResultQuery, TlsCertificate, TlsCertificatePage,
};
use schemars::JsonSchema;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    dto::{datetime_schema, parse_uuid, PaginationResponse, ResourceRefResponse},
    error::RestError,
    openapi::{
        ok_json, problem_response, GetReportQueryDoc, ReportListQueryDoc, ReportResultsQueryDoc,
        ResourceIdPathDoc,
    },
    query::{decoded_query_pairs, parse_collection_query},
    results::{NvtRefResponse, ResultListResponse, ResultResponse, Threat},
    router::bearer_token,
    targets::validate_uuid,
};

// ============================================================================
// Response DTOs
// ============================================================================

/// Result counts by severity category.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ResultCount")]
pub(crate) struct ResultCountResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    high: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    medium: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    low: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    debug: Option<u32>,
    #[serde(rename = "falsePositive", skip_serializing_if = "Option::is_none")]
    false_positive: Option<u32>,
}

impl From<gvm_gateway_domain::ResultCount> for ResultCountResponse {
    fn from(rc: gvm_gateway_domain::ResultCount) -> Self {
        Self {
            total: rc.total,
            high: rc.high,
            medium: rc.medium,
            low: rc.low,
            log: rc.log,
            debug: rc.debug,
            false_positive: rc.false_positive,
        }
    }
}

/// JSON body returned for a single report.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Report")]
pub(crate) struct ReportResponse {
    id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ResourceRefResponse>,
    #[serde(rename = "scanStart", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    scan_start: Option<String>,
    #[serde(rename = "scanEnd", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    scan_end: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<f64>,
    #[serde(rename = "resultCount", skip_serializing_if = "Option::is_none")]
    result_count: Option<ResultCountResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 1000))]
    results: Vec<ResultResponse>,
}

impl From<gvm_gateway_domain::Report> for ReportResponse {
    fn from(r: gvm_gateway_domain::Report) -> Self {
        Self {
            id: parse_uuid(&r.id),
            task: r.task.map(ResourceRefResponse::from),
            scan_start: r.scan_start,
            scan_end: r.scan_end,
            severity: r.severity,
            result_count: r.result_count.map(ResultCountResponse::from),
            results: r.results.into_iter().map(ResultResponse::from).collect(),
        }
    }
}

/// JSON body returned for a paginated list of reports.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportList")]
pub(crate) struct ReportListResponse {
    #[schemars(length(max = 1000))]
    data: Vec<ReportResponse>,
    pagination: PaginationResponse,
}

/// JSON body returned for a TLS certificate observation.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TlsCertificate")]
pub(crate) struct TlsCertificateResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<String>,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    not_before: Option<String>,
    #[serde(rename = "notAfter", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    not_after: Option<String>,
    #[serde(rename = "fingerprintSha256", skip_serializing_if = "Option::is_none")]
    fingerprint_sha256: Option<String>,
}

impl From<TlsCertificate> for TlsCertificateResponse {
    fn from(certificate: TlsCertificate) -> Self {
        Self {
            id: certificate.id,
            host: certificate.host,
            port: certificate.port,
            subject: certificate.subject,
            issuer: certificate.issuer,
            not_before: certificate.not_before,
            not_after: certificate.not_after,
            fingerprint_sha256: certificate.fingerprint_sha256,
        }
    }
}

/// JSON body returned for a paginated TLS certificate list.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TlsCertificateList")]
pub(crate) struct TlsCertificateListResponse {
    #[schemars(length(max = 1000))]
    data: Vec<TlsCertificateResponse>,
    pagination: PaginationResponse,
}

impl From<TlsCertificatePage> for TlsCertificateListResponse {
    fn from(page: TlsCertificatePage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(TlsCertificateResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// JSON body returned for a report host summary.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportHost")]
pub(crate) struct ReportHostResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
}

impl From<ReportHost> for ReportHostResponse {
    fn from(host: ReportHost) -> Self {
        Self {
            id: host.id,
            name: host.name,
            severity: host.severity,
        }
    }
}

/// JSON body returned for a paginated report-host list.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportHostList")]
pub(crate) struct ReportHostListResponse {
    #[schemars(length(max = 1000))]
    data: Vec<ReportHostResponse>,
    pagination: PaginationResponse,
}

impl From<ReportHostPage> for ReportHostListResponse {
    fn from(page: ReportHostPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(ReportHostResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// JSON body returned for a report port summary.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportPort")]
pub(crate) struct ReportPortResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
}

impl From<ReportPortSummary> for ReportPortResponse {
    fn from(port: ReportPortSummary) -> Self {
        Self {
            id: port.id,
            name: port.name,
            severity: port.severity,
        }
    }
}

/// JSON body returned for a paginated report-port list.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportPortList")]
pub(crate) struct ReportPortListResponse {
    #[schemars(length(max = 1000))]
    data: Vec<ReportPortResponse>,
    pagination: PaginationResponse,
}

impl From<ReportPortPage> for ReportPortListResponse {
    fn from(page: ReportPortPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(ReportPortResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// JSON body returned for a report application summary.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportApplication")]
pub(crate) struct ReportApplicationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
}

impl From<ReportApplication> for ReportApplicationResponse {
    fn from(application: ReportApplication) -> Self {
        Self {
            id: application.id,
            name: application.name,
            severity: application.severity,
        }
    }
}

/// JSON body returned for a paginated report-application list.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportApplicationList")]
pub(crate) struct ReportApplicationListResponse {
    #[schemars(length(max = 1000))]
    data: Vec<ReportApplicationResponse>,
    pagination: PaginationResponse,
}

impl From<ReportApplicationPage> for ReportApplicationListResponse {
    fn from(page: ReportApplicationPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(ReportApplicationResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// JSON body returned for a report operating-system summary.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportOperatingSystem")]
pub(crate) struct ReportOperatingSystemResponse {
    #[serde(rename = "bestOsCpe", skip_serializing_if = "Option::is_none")]
    best_os_cpe: Option<String>,
    #[serde(rename = "bestOsText", skip_serializing_if = "Option::is_none")]
    best_os_text: Option<String>,
    #[serde(rename = "hostsCount", skip_serializing_if = "Option::is_none")]
    hosts_count: Option<u32>,
}

impl From<ReportOperatingSystem> for ReportOperatingSystemResponse {
    fn from(operating_system: ReportOperatingSystem) -> Self {
        Self {
            best_os_cpe: operating_system.best_os_cpe,
            best_os_text: operating_system.best_os_text,
            hosts_count: operating_system.hosts_count,
        }
    }
}

/// JSON body returned for a paginated report-operating-system list.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportOperatingSystemList")]
pub(crate) struct ReportOperatingSystemListResponse {
    #[schemars(length(max = 1000))]
    data: Vec<ReportOperatingSystemResponse>,
    pagination: PaginationResponse,
}

impl From<ReportOperatingSystemPage> for ReportOperatingSystemListResponse {
    fn from(page: ReportOperatingSystemPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(ReportOperatingSystemResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// JSON body returned for a report CVE summary.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportCve")]
pub(crate) struct ReportCveResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
}

impl From<ReportCve> for ReportCveResponse {
    fn from(cve: ReportCve) -> Self {
        Self {
            id: cve.id,
            name: cve.name,
            severity: cve.severity,
        }
    }
}

/// JSON body returned for a paginated report-CVE list.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportCveList")]
pub(crate) struct ReportCveListResponse {
    #[schemars(length(max = 1000))]
    data: Vec<ReportCveResponse>,
    pagination: PaginationResponse,
}

impl From<ReportCvePage> for ReportCveListResponse {
    fn from(page: ReportCvePage) -> Self {
        Self {
            data: page.data.into_iter().map(ReportCveResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

impl From<gvm_gateway_domain::ReportPage> for ReportListResponse {
    fn from(page: gvm_gateway_domain::ReportPage) -> Self {
        Self {
            data: page.data.into_iter().map(ReportResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// JSON body returned for one aggregate report vulnerability.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportVulnerability")]
pub(crate) struct ReportVulnerabilityResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nvt: Option<NvtRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threat: Option<Threat>,
    #[serde(rename = "hostsCount", skip_serializing_if = "Option::is_none")]
    hosts_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurrences: Option<u32>,
}

impl From<gvm_gateway_domain::ReportVulnerability> for ReportVulnerabilityResponse {
    fn from(vulnerability: gvm_gateway_domain::ReportVulnerability) -> Self {
        Self {
            id: vulnerability.id,
            nvt: vulnerability.nvt.map(NvtRefResponse::from),
            host: vulnerability.host,
            port: vulnerability.port,
            severity: vulnerability.severity,
            threat: vulnerability.threat.as_deref().map(Threat::parse),
            hosts_count: vulnerability.hosts_count,
            occurrences: vulnerability.occurrences,
        }
    }
}

/// JSON body returned for a paginated report-vulnerability list.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportVulnerabilityList")]
pub(crate) struct ReportVulnerabilityListResponse {
    #[schemars(length(max = 1000))]
    data: Vec<ReportVulnerabilityResponse>,
    pagination: PaginationResponse,
}

impl From<ReportVulnerabilityPage> for ReportVulnerabilityListResponse {
    fn from(page: ReportVulnerabilityPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(ReportVulnerabilityResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// JSON body returned for one report error.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportError")]
pub(crate) struct ReportErrorResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "nvtName", skip_serializing_if = "Option::is_none")]
    nvt_name: Option<String>,
}

impl From<gvm_gateway_domain::ReportError> for ReportErrorResponse {
    fn from(error: gvm_gateway_domain::ReportError) -> Self {
        Self {
            id: error.id,
            name: error.name,
            host: error.host,
            port: error.port,
            description: error.description,
            nvt_name: error.nvt_name,
        }
    }
}

/// JSON body returned for a paginated report-error list.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportErrorList")]
pub(crate) struct ReportErrorListResponse {
    #[schemars(length(max = 1000))]
    data: Vec<ReportErrorResponse>,
    pagination: PaginationResponse,
}

impl From<ReportErrorPage> for ReportErrorListResponse {
    fn from(page: ReportErrorPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(ReportErrorResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// JSON body returned for one closed-CVE report finding.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportClosedCve")]
pub(crate) struct ReportClosedCveResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nvt: Option<NvtRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cve: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threat: Option<Threat>,
}

impl From<gvm_gateway_domain::ReportClosedCve> for ReportClosedCveResponse {
    fn from(closed_cve: gvm_gateway_domain::ReportClosedCve) -> Self {
        Self {
            id: closed_cve.id,
            nvt: closed_cve.nvt.map(NvtRefResponse::from),
            cve: closed_cve.cve,
            host: closed_cve.host,
            severity: closed_cve.severity,
            threat: closed_cve.threat.as_deref().map(Threat::parse),
        }
    }
}

/// JSON body returned for a paginated closed-CVE list.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportClosedCveList")]
pub(crate) struct ReportClosedCveListResponse {
    #[schemars(length(max = 1000))]
    data: Vec<ReportClosedCveResponse>,
    pagination: PaginationResponse,
}

impl From<ReportClosedCvePage> for ReportClosedCveListResponse {
    fn from(page: ReportClosedCvePage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(ReportClosedCveResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Parsed list-reports query from HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportListQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl ReportListQuery {
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

/// Parsed query parameters for GET /reports/{id} endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetReportQuery {
    /// Embedded-result page number.
    pub page: u32,
    /// Embedded-result page size.
    pub per_page: u32,
}

impl GetReportQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let parsed = parse_collection_query(query)?;

        Ok(Self {
            page: parsed.page,
            per_page: parsed.per_page,
        })
    }
}

/// Parsed query for report results sub-resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportResultsQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl ReportResultsQuery {
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

fn report_results_query(query: ReportResultsQuery) -> ResultQuery {
    ResultQuery {
        filter_string: query.filter_string,
        filter_id: query.filter_id,
        page: query.page,
        per_page: query.per_page,
    }
}

/// List reports handler.
pub async fn list_reports(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match ReportListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_reports(
            &session,
            ReportQuery {
                filter_string: query.filter_string,
                filter_id: query.filter_id,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(reports) => (StatusCode::OK, Json(ReportListResponse::from(reports))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report handler.
pub async fn get_report(
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
    let query = match GetReportQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report(
            &session,
            &id,
            GetReportOpts {
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(report) => (StatusCode::OK, Json(ReportResponse::from(report))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Reject the obsolete report-deletion permanence selector.
///
/// Report deletion is always permanent in gvmd. Accepting either value would
/// let legacy clients mistake a destructive operation for a trashcan move.
fn reject_report_ultimate_query(query: Option<&str>) -> Result<(), GatewayError> {
    if query
        .into_iter()
        .flat_map(decoded_query_pairs)
        .any(|(key, _)| key == "ultimate")
    {
        return Err(GatewayError::InvalidInput(
            "the `ultimate` query parameter is obsolete for report deletion; report deletion is always permanent"
                .to_string(),
        ));
    }
    Ok(())
}

/// Permanently delete a report.
pub async fn delete_report(
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

    match reject_report_ultimate_query(uri.query()) {
        Ok(()) => {}
        Err(GatewayError::InvalidInput(detail)) => {
            return RestError::from_gateway_error(GatewayError::InvalidInput(detail), instance)
                .into_response();
        }
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    }
    match service.delete_report(&session, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report results handler.
pub async fn get_report_results(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_results(&session, &id, report_results_query(query))
        .await
    {
        Ok(results) => (
            StatusCode::OK,
            Json(crate::results::ResultListResponse::from(results)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report vulnerabilities handler.
pub async fn get_report_vulnerabilities(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_vulnerabilities(&session, &id, report_results_query(query))
        .await
    {
        Ok(results) => (
            StatusCode::OK,
            Json(ReportVulnerabilityListResponse::from(results)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report TLS certificates handler.
pub async fn get_report_tls_certificates(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_tls_certificates(&session, &id, report_results_query(query))
        .await
    {
        Ok(certificates) => (
            StatusCode::OK,
            Json(TlsCertificateListResponse::from(certificates)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report errors handler.
pub async fn get_report_errors(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_errors(&session, &id, report_results_query(query))
        .await
    {
        Ok(results) => {
            (StatusCode::OK, Json(ReportErrorListResponse::from(results))).into_response()
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report closed CVEs handler.
pub async fn get_report_closed_cves(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_closed_cves(&session, &id, report_results_query(query))
        .await
    {
        Ok(results) => (
            StatusCode::OK,
            Json(ReportClosedCveListResponse::from(results)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report hosts handler.
pub async fn get_report_hosts(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_hosts(&session, &id, report_results_query(query))
        .await
    {
        Ok(hosts) => (StatusCode::OK, Json(ReportHostListResponse::from(hosts))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report ports handler.
pub async fn get_report_ports(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_ports(&session, &id, report_results_query(query))
        .await
    {
        Ok(ports) => (StatusCode::OK, Json(ReportPortListResponse::from(ports))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report applications handler.
pub async fn get_report_applications(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_applications(&session, &id, report_results_query(query))
        .await
    {
        Ok(applications) => (
            StatusCode::OK,
            Json(ReportApplicationListResponse::from(applications)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report operating systems handler.
pub async fn get_report_operating_systems(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_operating_systems(&session, &id, report_results_query(query))
        .await
    {
        Ok(operating_systems) => (
            StatusCode::OK,
            Json(ReportOperatingSystemListResponse::from(operating_systems)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report CVEs handler.
pub async fn get_report_cves(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_cves(&session, &id, report_results_query(query))
        .await
    {
        Ok(cves) => (StatusCode::OK, Json(ReportCveListResponse::from(cves))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `GET /api/v1/reports`.
pub(crate) fn list_reports_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReports")
        .tag("Reports")
        .summary("List reports")
        .description("Returns a paginated list of reports.")
        .security_requirement("bearerAuth")
        .input::<Query<ReportListQueryDoc>>()
        .response_with::<200, Json<ReportListResponse>, _>(ok_json("Paginated list of reports"));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}`.
pub(crate) fn get_report_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReport")
        .tag("Reports")
        .summary("Get a report")
        .description(
            "Returns the details for a single report with embedded results from the requested `page` and `perPage` window.",
        )
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<GetReportQueryDoc>)>()
        .response_with::<200, Json<ReportResponse>, _>(ok_json(
            "Report details with embedded results from the requested embedded-result window",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/reports/{id}`.
pub(crate) fn delete_report_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteReport")
        .tag("Reports")
        .summary("Delete a report")
        .description("Permanently deletes a report. Report deletion cannot be undone and has no trash or caller-selectable permanence mode. The obsolete `ultimate` query parameter is rejected with `400 bad_request`.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Report deleted"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/results`.
pub(crate) fn get_report_results_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportResults")
        .tag("Reports")
        .summary("Get paginated results for a report")
        .description("Returns a paginated list of results for a specific report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ResultListResponse>, _>(ok_json("Paginated list of results"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/vulnerabilities`.
pub(crate) fn get_report_vulnerabilities_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("getReportVulnerabilities")
        .tag("Reports")
        .summary("Get vulnerability findings for a report")
        .description("Returns purpose-shaped aggregate vulnerability findings. On gvmd versions before GMP 22.8 this returns 501; clients may fall back to `/reports/{id}/results`.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ReportVulnerabilityListResponse>, _>(ok_json(
            "Paginated list of vulnerability findings",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    );
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/tls-certificates`.
pub(crate) fn get_report_tls_certificates_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("getReportTlsCertificates")
        .tag("Reports")
        .summary("Get TLS certificates observed in a report")
        .description("Returns a paginated list of TLS certificate observations for a report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<TlsCertificateListResponse>, _>(ok_json(
            "Paginated list of TLS certificates",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    );
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/errors`.
pub(crate) fn get_report_errors_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportErrors")
        .tag("Reports")
        .summary("Get report error findings")
        .description("Returns purpose-shaped report errors without fabricated threat or severity values. On gvmd versions before GMP 22.8 this returns 501; clients may fall back to `/reports/{id}/results`.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ReportErrorListResponse>, _>(ok_json(
            "Paginated list of report errors",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    );
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/closed-cves`.
pub(crate) fn get_report_closed_cves_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportClosedCves")
        .tag("Reports")
        .summary("Get closed CVE findings for a report")
        .description("Returns purpose-shaped closed-CVE findings. On gvmd versions before GMP 22.8 this returns 501; clients may fall back to `/reports/{id}/results`.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ReportClosedCveListResponse>, _>(ok_json(
            "Paginated list of closed CVE findings",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    );
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/hosts`.
pub(crate) fn get_report_hosts_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportHosts")
        .tag("Reports")
        .summary("Get report hosts")
        .description("Returns a paginated list of host summaries for a report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ReportHostListResponse>, _>(ok_json(
            "Paginated list of report host summaries",
        ));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    )
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/ports`.
pub(crate) fn get_report_ports_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportPorts")
        .tag("Reports")
        .summary("Get report ports")
        .description("Returns a paginated list of port summaries for a report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ReportPortListResponse>, _>(ok_json(
            "Paginated list of report port summaries",
        ));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    )
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/applications`.
pub(crate) fn get_report_applications_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportApplications")
        .tag("Reports")
        .summary("Get report applications")
        .description("Returns a paginated list of application summaries for a report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ReportApplicationListResponse>, _>(ok_json(
            "Paginated list of report application summaries",
        ));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    )
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/operating-systems`.
pub(crate) fn get_report_operating_systems_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("getReportOperatingSystems")
        .tag("Reports")
        .summary("Get report operating systems")
        .description("Returns a paginated list of operating-system summaries for a report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ReportOperatingSystemListResponse>, _>(ok_json(
            "Paginated list of report operating-system summaries",
        ));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    )
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/cves`.
pub(crate) fn get_report_cves_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportCves")
        .tag("Reports")
        .summary("Get report CVEs")
        .description("Returns a paginated list of CVE summaries for a report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ReportCveListResponse>, _>(ok_json(
            "Paginated list of report CVE summaries",
        ));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    )
}

#[cfg(test)]
#[path = "reports_test.rs"]
mod reports_test;
