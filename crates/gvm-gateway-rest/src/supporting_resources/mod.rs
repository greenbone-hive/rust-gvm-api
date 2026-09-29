// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Supporting-resource REST modules and compatibility exports.

mod assets;
mod common;
mod filters;
mod notes;
mod overrides;
mod report_formats;
mod tags;
mod tls_certificates;

pub use assets::{
    create_host, delete_host, delete_operating_system, get_host, get_operating_system, list_hosts,
    list_operating_systems, update_host, update_operating_system,
};
// Preserve the pre-refactor crate-local DTO paths even when current consumers
// reach them only through the handlers and OpenAPI transforms below.
#[allow(unused_imports)]
pub(crate) use assets::{
    create_host_docs, delete_host_docs, delete_operating_system_docs, get_host_docs,
    get_operating_system_docs, list_hosts_docs, list_operating_systems_docs,
    modify_operating_system_docs, update_host_docs, CreateHostRequest, HostListResponse,
    HostResponse, ModifyHostRequest, ModifyOperatingSystemRequest, OperatingSystemHostResponse,
    OperatingSystemListResponse, OperatingSystemResponse,
};
pub use common::{PaginationOnlyQuery, SupportingListQuery};
pub(crate) use common::{
    PaginationOnlyQueryParams, SupportingResourceListQueryParams, SupportingResourceMetaResponse,
};
pub use filters::{
    clone_filter, create_filter, delete_filter, get_filter, list_filters, update_filter,
};
#[allow(unused_imports)]
pub(crate) use filters::{
    clone_filter_docs, create_filter_docs, delete_filter_docs, get_filter_docs, list_filters_docs,
    update_filter_docs, CreateFilterRequest, FilterListResponse, FilterResponse,
    ModifyFilterRequest,
};
pub use notes::{create_note, delete_note, get_note, list_notes, update_note};
#[allow(unused_imports)]
pub(crate) use notes::{
    create_note_docs, delete_note_docs, get_note_docs, list_notes_docs, update_note_docs,
    CreateNoteRequest, ModifyNoteRequest, NoteListResponse, NoteResponse,
};
pub use overrides::{
    create_override, delete_override, get_override, list_overrides, update_override,
};
#[allow(unused_imports)]
pub(crate) use overrides::{
    create_override_docs, delete_override_docs, get_override_docs, list_overrides_docs,
    update_override_docs, CreateOverrideRequest, ModifyOverrideRequest, OverrideListResponse,
    OverrideResponse,
};
pub use report_formats::{get_report_format, list_report_formats};
#[allow(unused_imports)]
pub(crate) use report_formats::{
    get_report_format_docs, list_report_formats_docs, ReportFormatListResponse,
    ReportFormatResponse,
};
pub use tags::{clone_tag, create_tag, delete_tag, get_tag, list_tags, update_tag};
#[allow(unused_imports)]
pub(crate) use tags::{
    clone_tag_docs, create_tag_docs, delete_tag_docs, get_tag_docs, list_tags_docs,
    update_tag_docs, CreateTagRequest, ModifyTagRequest, TagListResponse, TagResponse,
};
pub use tls_certificates::{get_tls_certificate, list_tls_certificates};
#[allow(unused_imports)]
pub(crate) use tls_certificates::{
    get_tls_certificate_docs, list_tls_certificates_docs, TlsCertificateAssetListResponse,
    TlsCertificateAssetResponse,
};

use common::{default_page, default_per_page, supporting_query};

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{GatewayError, NvtQuery};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::PaginationResponse,
    error::RestError,
    handler::list_resource,
    openapi::{ok_json, problem_response},
    query::{decoded_query_pairs, parse_collection_query},
    router::bearer_token,
    targets::validate_uuid,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NvtSortOrder {
    Ascending,
    Descending,
}

impl NvtSortOrder {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ascending => "ascending",
            Self::Descending => "descending",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct NvtListQueryParams {
    #[serde(default = "default_page")]
    #[schemars(default = "default_page", range(min = 1))]
    page: Option<u32>,
    #[serde(rename = "perPage", default = "default_per_page")]
    #[schemars(default = "default_per_page", range(min = 1, max = 1000))]
    per_page: Option<u32>,
    #[serde(rename = "configId")]
    config_id: Option<Uuid>,
    #[serde(rename = "preferencesConfigId")]
    preferences_config_id: Option<Uuid>,
    family: Option<String>,
    #[serde(rename = "includePreferences")]
    include_preferences: Option<bool>,
    #[serde(rename = "includePreferenceCount")]
    include_preference_count: Option<bool>,
    #[serde(rename = "includeTimeout")]
    include_timeout: Option<bool>,
    #[serde(rename = "sortOrder")]
    sort_order: Option<NvtSortOrder>,
    #[serde(rename = "sortField")]
    sort_field: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NvtListQuery {
    pub(crate) filter_string: Option<String>,
    pub(crate) filter_id: Option<String>,
    pub(crate) page: u32,
    pub(crate) per_page: u32,
    pub(crate) config_id: Option<String>,
    pub(crate) preferences_config_id: Option<String>,
    pub(crate) family: Option<String>,
    pub(crate) include_preferences: Option<bool>,
    pub(crate) include_preference_count: Option<bool>,
    pub(crate) include_timeout: Option<bool>,
    pub(crate) sort_order: Option<NvtSortOrder>,
    pub(crate) sort_field: Option<String>,
}

impl NvtListQuery {
    pub(crate) fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let common = parse_collection_query(query)?;
        let mut config_id = None;
        let mut preferences_config_id = None;
        let mut family = None;
        let mut include_preferences = None;
        let mut include_preference_count = None;
        let mut include_timeout = None;
        let mut sort_order = None;
        let mut sort_field = None;

        for (key, value) in decoded_query_pairs(query) {
            match key.as_ref() {
                "page" | "perPage" | "per_page" => {}
                "filter" | "filterId" => {
                    return Err(GatewayError::InvalidInput(format!(
                        "{key} is not supported for NVT queries"
                    )))
                }
                "configId" => {
                    validate_uuid("configId", &value)?;
                    config_id = Some(value.into_owned());
                }
                "preferencesConfigId" => {
                    validate_uuid("preferencesConfigId", &value)?;
                    preferences_config_id = Some(value.into_owned());
                }
                "family" => family = Some(nonempty_query_value("family", &value)?),
                "includePreferences" => {
                    include_preferences = Some(parse_query_bool("includePreferences", &value)?)
                }
                "includePreferenceCount" => {
                    include_preference_count =
                        Some(parse_query_bool("includePreferenceCount", &value)?)
                }
                "includeTimeout" => {
                    include_timeout = Some(parse_query_bool("includeTimeout", &value)?)
                }
                "sortOrder" => {
                    sort_order = Some(match value.as_ref() {
                        "ascending" => NvtSortOrder::Ascending,
                        "descending" => NvtSortOrder::Descending,
                        _ => {
                            return Err(GatewayError::InvalidInput(
                                "sortOrder must be ascending or descending".to_string(),
                            ))
                        }
                    })
                }
                "sortField" => sort_field = Some(nonempty_query_value("sortField", &value)?),
                _ => {
                    return Err(GatewayError::InvalidInput(format!(
                        "unsupported NVT query parameter: {key}"
                    )))
                }
            }
        }

        if include_timeout == Some(true) && config_id.is_none() {
            return Err(GatewayError::InvalidInput(
                "includeTimeout=true requires configId".to_string(),
            ));
        }

        Ok(Self {
            filter_string: common.filter_string,
            filter_id: common.filter_id,
            page: common.page,
            per_page: common.per_page,
            config_id,
            preferences_config_id,
            family,
            include_preferences,
            include_preference_count,
            include_timeout,
            sort_order,
            sort_field,
        })
    }
}

fn parse_query_bool(field: &str, value: &str) -> Result<bool, GatewayError> {
    value
        .parse::<bool>()
        .map_err(|_| GatewayError::InvalidInput(format!("{field} must be true or false")))
}

fn nonempty_query_value(field: &str, value: &str) -> Result<String, GatewayError> {
    let value = value.trim();
    if value.is_empty() {
        Err(GatewayError::InvalidInput(format!(
            "{field} must not be empty"
        )))
    } else {
        Ok(value.to_string())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub(crate) struct NvtOidPathDoc {
    id: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub(crate) struct SecInfoIdPathDoc {
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

fn nvt_query(query: NvtListQuery) -> NvtQuery {
    NvtQuery {
        filter_string: query.filter_string,
        filter_id: query.filter_id,
        page: query.page,
        per_page: query.per_page,
        config_id: query.config_id,
        preferences_config_id: query.preferences_config_id,
        family: query.family,
        include_preferences: query.include_preferences,
        include_preference_count: query.include_preference_count,
        include_timeout: query.include_timeout,
        sort_order: query.sort_order.map(|value| value.as_str().to_string()),
        sort_field: query.sort_field,
    }
}

fn require_nvt_oid(value: Option<String>) -> Result<String, GatewayError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| GatewayError::InvalidInput("nvtOid is required".to_string()))
}

fn validate_optional_uuid(field: &str, value: Option<&str>) -> Result<(), GatewayError> {
    if let Some(value) = value {
        validate_uuid(field, value)?;
    }
    Ok(())
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

#[cfg(test)]
#[path = "mod_test.rs"]
mod mod_test;
