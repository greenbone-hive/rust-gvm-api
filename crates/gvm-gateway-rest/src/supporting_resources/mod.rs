// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Host, report-format, triage, filter, tag, and NVT DTOs plus REST handlers.

mod assets;
mod common;
mod report_formats;
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
pub use report_formats::{get_report_format, list_report_formats};
#[allow(unused_imports)]
pub(crate) use report_formats::{
    get_report_format_docs, list_report_formats_docs, ReportFormatListResponse,
    ReportFormatResponse,
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
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    CreateFilterInput, CreateNoteInput, CreateOverrideInput, CreateTagInput, GatewayError,
    ModifyFilterInput, ModifyNoteInput, ModifyOverrideInput, ModifyTagInput, NvtQuery,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{PaginationResponse, ResourceCreatedResponse, ResourceRefResponse},
    error::RestError,
    handler::{
        create_resource, created_resource, delete_resource, gateway_error, get_resource,
        list_resource, update_resource, ValidateInto,
    },
    openapi::{created_json, ok_json, problem_response, ResourceIdPathDoc},
    query::{decoded_query_pairs, parse_collection_query, DeleteResourceQueryParams},
    results::NvtRefResponse,
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
#[schemars(rename = "Filter")]
pub(crate) struct FilterResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    filter_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    term: Option<String>,
}

impl From<gvm_gateway_domain::Filter> for FilterResponse {
    fn from(filter: gvm_gateway_domain::Filter) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(filter.meta),
            filter_type: filter.filter_type,
            term: filter.term,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "FilterList")]
pub(crate) struct FilterListResponse {
    data: Vec<FilterResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::FilterPage> for FilterListResponse {
    fn from(page: gvm_gateway_domain::FilterPage) -> Self {
        Self {
            data: page.data.into_iter().map(FilterResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TagResource")]
pub(crate) struct TagResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(rename = "resourceType", skip_serializing_if = "Option::is_none")]
    resource_type: Option<String>,
    #[serde(rename = "resourceCount", skip_serializing_if = "Option::is_none")]
    resource_count: Option<u32>,
    active: bool,
}

impl From<gvm_gateway_domain::Tag> for TagResponse {
    fn from(tag: gvm_gateway_domain::Tag) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(tag.meta),
            value: tag.value,
            resource_type: tag.resource_type,
            resource_count: tag.resource_count,
            active: tag.active,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TagList")]
pub(crate) struct TagListResponse {
    data: Vec<TagResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::TagPage> for TagListResponse {
    fn from(page: gvm_gateway_domain::TagPage) -> Self {
        Self {
            data: page.data.into_iter().map(TagResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateFilter")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateFilterRequest {
    #[schemars(required)]
    name: Option<String>,
    comment: Option<String>,
    term: Option<String>,
    #[serde(rename = "type")]
    filter_type: Option<String>,
}

impl CreateFilterRequest {
    fn validate(self) -> Result<CreateFilterInput, GatewayError> {
        let name = self
            .name
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))?;
        Ok(CreateFilterInput {
            name,
            comment: self.comment,
            term: self.term,
            filter_type: self.filter_type,
        })
    }
}

impl ValidateInto<CreateFilterInput> for CreateFilterRequest {
    fn validate_into(self) -> Result<CreateFilterInput, GatewayError> {
        self.validate()
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "UpdateFilter")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyFilterRequest {
    comment: Option<String>,
    term: Option<String>,
    #[serde(rename = "type")]
    filter_type: Option<String>,
}

impl ValidateInto<ModifyFilterInput> for ModifyFilterRequest {
    fn validate_into(self) -> Result<ModifyFilterInput, GatewayError> {
        Ok(ModifyFilterInput {
            comment: self.comment,
            term: self.term,
            filter_type: self.filter_type,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateTag")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateTagRequest {
    #[schemars(required)]
    name: Option<String>,
    comment: Option<String>,
    value: Option<String>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    #[serde(rename = "resourceId")]
    #[schemars(with = "Option<Uuid>")]
    resource_id: Option<String>,
    active: Option<bool>,
}

impl CreateTagRequest {
    fn validate(self) -> Result<CreateTagInput, GatewayError> {
        let name = self
            .name
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))?;
        validate_optional_uuid("resourceId", self.resource_id.as_deref())?;
        Ok(CreateTagInput {
            name,
            comment: self.comment,
            value: self.value,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            active: self.active,
        })
    }
}

impl ValidateInto<CreateTagInput> for CreateTagRequest {
    fn validate_into(self) -> Result<CreateTagInput, GatewayError> {
        self.validate()
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "UpdateTag")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyTagRequest {
    comment: Option<String>,
    value: Option<String>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    #[serde(rename = "resourceId")]
    #[schemars(with = "Option<Uuid>")]
    resource_id: Option<String>,
    active: Option<bool>,
}

impl ModifyTagRequest {
    fn validate(self) -> Result<ModifyTagInput, GatewayError> {
        validate_optional_uuid("resourceId", self.resource_id.as_deref())?;
        Ok(ModifyTagInput {
            comment: self.comment,
            value: self.value,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            active: self.active,
        })
    }
}

impl ValidateInto<ModifyTagInput> for ModifyTagRequest {
    fn validate_into(self) -> Result<ModifyTagInput, GatewayError> {
        self.validate()
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Note")]
pub(crate) struct NoteResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nvt: Option<NvtRefResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<ResourceRefResponse>,
    active: bool,
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    end_time: Option<String>,
}

impl From<gvm_gateway_domain::Note> for NoteResponse {
    fn from(note: gvm_gateway_domain::Note) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(note.meta),
            text: note.text,
            nvt: note.nvt.map(NvtRefResponse::from),
            hosts: note.hosts,
            port: note.port,
            severity: note.severity,
            task: note.task.map(ResourceRefResponse::from),
            result: note.result.map(ResourceRefResponse::from),
            active: note.active,
            end_time: note.end_time,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "NoteList")]
pub(crate) struct NoteListResponse {
    data: Vec<NoteResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::NotePage> for NoteListResponse {
    fn from(page: gvm_gateway_domain::NotePage) -> Self {
        Self {
            data: page.data.into_iter().map(NoteResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Override")]
pub(crate) struct OverrideResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nvt: Option<NvtRefResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(rename = "newSeverity", skip_serializing_if = "Option::is_none")]
    new_severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<ResourceRefResponse>,
    active: bool,
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    end_time: Option<String>,
}

impl From<gvm_gateway_domain::Override> for OverrideResponse {
    fn from(override_: gvm_gateway_domain::Override) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(override_.meta),
            text: override_.text,
            nvt: override_.nvt.map(NvtRefResponse::from),
            hosts: override_.hosts,
            port: override_.port,
            severity: override_.severity,
            new_severity: override_.new_severity,
            task: override_.task.map(ResourceRefResponse::from),
            result: override_.result.map(ResourceRefResponse::from),
            active: override_.active,
            end_time: override_.end_time,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "OverrideList")]
pub(crate) struct OverrideListResponse {
    data: Vec<OverrideResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::OverridePage> for OverrideListResponse {
    fn from(page: gvm_gateway_domain::OverridePage) -> Self {
        Self {
            data: page.data.into_iter().map(OverrideResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateNote")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateNoteRequest {
    #[serde(rename = "nvtOid")]
    #[schemars(required)]
    nvt_oid: Option<String>,
    text: Option<String>,
    #[serde(default)]
    hosts: Vec<String>,
    port: Option<String>,
    severity: Option<String>,
    #[serde(rename = "taskId")]
    #[schemars(with = "Option<Uuid>")]
    task_id: Option<String>,
    #[serde(rename = "resultId")]
    #[schemars(with = "Option<Uuid>")]
    result_id: Option<String>,
    active: Option<bool>,
    orphan: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "UpdateNote")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyNoteRequest {
    text: Option<String>,
    /// Host selector list. Omitted or null leaves existing selectors unchanged;
    /// an empty array clears all host selectors.
    hosts: Option<Vec<String>>,
    port: Option<String>,
    severity: Option<String>,
    #[serde(rename = "taskId")]
    #[schemars(with = "Option<Uuid>")]
    task_id: Option<String>,
    #[serde(rename = "resultId")]
    #[schemars(with = "Option<Uuid>")]
    result_id: Option<String>,
    active: Option<bool>,
    orphan: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateOverride")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateOverrideRequest {
    #[serde(rename = "nvtOid")]
    #[schemars(required)]
    nvt_oid: Option<String>,
    text: Option<String>,
    #[serde(default)]
    hosts: Vec<String>,
    port: Option<String>,
    severity: Option<String>,
    #[serde(rename = "newSeverity")]
    new_severity: Option<String>,
    #[serde(rename = "taskId")]
    #[schemars(with = "Option<Uuid>")]
    task_id: Option<String>,
    #[serde(rename = "resultId")]
    #[schemars(with = "Option<Uuid>")]
    result_id: Option<String>,
    active: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "UpdateOverride")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyOverrideRequest {
    text: Option<String>,
    /// Host selector list. Omitted or null leaves existing selectors unchanged;
    /// an empty array clears all host selectors.
    hosts: Option<Vec<String>>,
    port: Option<String>,
    severity: Option<String>,
    #[serde(rename = "newSeverity")]
    new_severity: Option<String>,
    #[serde(rename = "taskId")]
    #[schemars(with = "Option<Uuid>")]
    task_id: Option<String>,
    #[serde(rename = "resultId")]
    #[schemars(with = "Option<Uuid>")]
    result_id: Option<String>,
    active: Option<bool>,
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

impl CreateNoteRequest {
    fn validate(self) -> Result<CreateNoteInput, GatewayError> {
        validate_optional_uuid("taskId", self.task_id.as_deref())?;
        validate_optional_uuid("resultId", self.result_id.as_deref())?;

        Ok(CreateNoteInput {
            nvt_oid: require_nvt_oid(self.nvt_oid)?,
            text: self.text,
            hosts: self.hosts,
            port: self.port,
            severity: self.severity,
            task_id: self.task_id,
            result_id: self.result_id,
            active: self.active,
            orphan: self.orphan,
        })
    }
}

impl ValidateInto<CreateNoteInput> for CreateNoteRequest {
    fn validate_into(self) -> Result<CreateNoteInput, GatewayError> {
        self.validate()
    }
}

impl ModifyNoteRequest {
    fn validate(self) -> Result<ModifyNoteInput, GatewayError> {
        validate_optional_uuid("taskId", self.task_id.as_deref())?;
        validate_optional_uuid("resultId", self.result_id.as_deref())?;

        Ok(ModifyNoteInput {
            text: self.text,
            hosts: self.hosts,
            port: self.port,
            severity: self.severity,
            task_id: self.task_id,
            result_id: self.result_id,
            active: self.active,
            orphan: self.orphan,
        })
    }
}

impl ValidateInto<ModifyNoteInput> for ModifyNoteRequest {
    fn validate_into(self) -> Result<ModifyNoteInput, GatewayError> {
        self.validate()
    }
}

impl CreateOverrideRequest {
    fn validate(self) -> Result<CreateOverrideInput, GatewayError> {
        validate_optional_uuid("taskId", self.task_id.as_deref())?;
        validate_optional_uuid("resultId", self.result_id.as_deref())?;

        Ok(CreateOverrideInput {
            nvt_oid: require_nvt_oid(self.nvt_oid)?,
            text: self.text,
            hosts: self.hosts,
            port: self.port,
            severity: self.severity,
            new_severity: self.new_severity,
            task_id: self.task_id,
            result_id: self.result_id,
            active: self.active,
        })
    }
}

impl ValidateInto<CreateOverrideInput> for CreateOverrideRequest {
    fn validate_into(self) -> Result<CreateOverrideInput, GatewayError> {
        self.validate()
    }
}

impl ModifyOverrideRequest {
    fn validate(self) -> Result<ModifyOverrideInput, GatewayError> {
        validate_optional_uuid("taskId", self.task_id.as_deref())?;
        validate_optional_uuid("resultId", self.result_id.as_deref())?;

        Ok(ModifyOverrideInput {
            text: self.text,
            hosts: self.hosts,
            port: self.port,
            severity: self.severity,
            new_severity: self.new_severity,
            task_id: self.task_id,
            result_id: self.result_id,
            active: self.active,
        })
    }
}

impl ValidateInto<ModifyOverrideInput> for ModifyOverrideRequest {
    fn validate_into(self) -> Result<ModifyOverrideInput, GatewayError> {
        self.validate()
    }
}

/// Lists saved filters visible to the authenticated session.
pub async fn list_filters(
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
        .list_filters(&session, supporting_query(query))
        .await
    {
        Ok(page) => (StatusCode::OK, Json(FilterListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single saved filter by id.
pub async fn get_filter(
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

    match service.get_filter(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(FilterResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Creates a saved filter.
pub async fn create_filter(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateFilterInput, CreateFilterRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_filter(&session, input).await },
    )
    .await
}

/// Updates a saved filter.
pub async fn update_filter(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyFilterInput, ModifyFilterRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_filter(&session, &id, input).await
        },
        FilterResponse::from,
    )
    .await
}

/// Deletes a saved filter. Set `ultimate=true` to request permanent backend deletion.
pub async fn delete_filter(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id, ultimate| async move {
            service.delete_filter(&session, &id, ultimate).await
        },
    )
    .await
}

/// Clones a saved filter.
pub async fn clone_filter(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service.clone_filter(&session, &id).await {
        Ok(new_id) => created_resource("/api/v1/filters", &new_id),
        Err(error) => gateway_error(error, instance),
    }
}

/// Lists tags visible to the authenticated session.
pub async fn list_tags(
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

    match service.list_tags(&session, supporting_query(query)).await {
        Ok(page) => (StatusCode::OK, Json(TagListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single tag by id.
pub async fn get_tag(
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

    match service.get_tag(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(TagResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Creates a tag.
pub async fn create_tag(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateTagInput, CreateTagRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_tag(&session, input).await },
    )
    .await
}

/// Updates a tag.
pub async fn update_tag(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyTagInput, ModifyTagRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move { service.modify_tag(&session, &id, input).await },
        TagResponse::from,
    )
    .await
}

/// Deletes a tag. Set `ultimate=true` to request permanent backend deletion.
pub async fn delete_tag(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id, ultimate| async move {
            service.delete_tag(&session, &id, ultimate).await
        },
    )
    .await
}

/// Clones a tag.
pub async fn clone_tag(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service.clone_tag(&session, &id).await {
        Ok(new_id) => created_resource("/api/v1/tags", &new_id),
        Err(error) => gateway_error(error, instance),
    }
}

/// Lists notes visible to the authenticated session.
pub async fn list_notes(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        |query| SupportingListQuery::try_from_query_string(query).map(supporting_query),
        |service, session, query| async move { service.list_notes(&session, query).await },
        NoteListResponse::from,
    )
    .await
}

/// Returns a single note by id.
pub async fn get_note(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id| async move { service.get_note(&session, &id).await },
        NoteResponse::from,
    )
    .await
}

/// Creates a note for result triage.
pub async fn create_note(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateNoteInput, CreateNoteRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_note(&session, input).await },
    )
    .await
}

/// Updates a note used for result triage.
pub async fn update_note(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyNoteInput, ModifyNoteRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move { service.modify_note(&session, &id, input).await },
        NoteResponse::from,
    )
    .await
}

/// Deletes a note. Set `ultimate=true` to request permanent backend deletion.
pub async fn delete_note(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id, ultimate| async move {
            service.delete_note(&session, &id, ultimate).await
        },
    )
    .await
}

/// Lists overrides visible to the authenticated session.
pub async fn list_overrides(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        |query| SupportingListQuery::try_from_query_string(query).map(supporting_query),
        |service, session, query| async move { service.list_overrides(&session, query).await },
        OverrideListResponse::from,
    )
    .await
}

/// Returns a single override by id.
pub async fn get_override(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id| async move { service.get_override(&session, &id).await },
        OverrideResponse::from,
    )
    .await
}

/// Creates an override for result triage.
pub async fn create_override(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateOverrideInput, CreateOverrideRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_override(&session, input).await },
    )
    .await
}

/// Updates an override used for result triage.
pub async fn update_override(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyOverrideInput, ModifyOverrideRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_override(&session, &id, input).await
        },
        OverrideResponse::from,
    )
    .await
}

/// Deletes an override. Set `ultimate=true` to request permanent backend deletion.
pub async fn delete_override(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id, ultimate| async move {
            service.delete_override(&session, &id, ultimate).await
        },
    )
    .await
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

pub(crate) fn list_filters_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getFilters")
        .tag("Filters")
        .summary("List filters")
        .description("Returns a paginated list of saved filters.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<FilterListResponse>, _>(ok_json(
            "Paginated list of saved filters",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_filter_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getFilter")
        .tag("Filters")
        .summary("Get a filter")
        .description("Returns the details for a single saved filter.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<FilterResponse>, _>(ok_json("Filter details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn create_filter_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createFilter")
        .tag("Filters")
        .summary("Create a filter")
        .description("Creates a saved filter with an optional term, comment, and resource type.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateFilterRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Filter created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn update_filter_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyFilter")
        .tag("Filters")
        .summary("Modify a filter")
        .description("Updates a saved filter's term, comment, or resource type.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyFilterRequest>)>()
        .response_with::<200, Json<FilterResponse>, _>(ok_json("Filter updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_filter_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteFilter")
        .tag("Filters")
        .summary("Delete a filter")
        .description("Deletes a saved filter. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Filter deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn clone_filter_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("cloneFilter")
        .tag("Filters")
        .summary("Clone a filter")
        .description("Creates a copy of an existing saved filter.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Filter cloned"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_tags_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTags")
        .tag("Tags")
        .summary("List tags")
        .description("Returns a paginated list of tags.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<TagListResponse>, _>(ok_json("Paginated list of tags"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_tag_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTag")
        .tag("Tags")
        .summary("Get a tag")
        .description("Returns the details for a single tag.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TagResponse>, _>(ok_json("Tag details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn create_tag_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createTag")
        .tag("Tags")
        .summary("Create a tag")
        .description("Creates a tag, optionally attaching it to a related resource by type and id.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateTagRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Tag created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn update_tag_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyTag")
        .tag("Tags")
        .summary("Modify a tag")
        .description("Updates a tag's value, comment, resource attachment, or active state.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyTagRequest>)>()
        .response_with::<200, Json<TagResponse>, _>(ok_json("Tag updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_tag_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteTag")
        .tag("Tags")
        .summary("Delete a tag")
        .description("Deletes a tag. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Tag deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn clone_tag_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("cloneTag")
        .tag("Tags")
        .summary("Clone a tag")
        .description("Creates a copy of an existing tag.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Tag cloned"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_notes_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getNotes")
        .tag("Notes")
        .summary("List notes")
        .description(
            "Returns a paginated list of notes that annotate findings. Filter expressions can scope notes to the related task, result, NVT, host, or port selectors exposed by each note.",
        )
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<NoteListResponse>, _>(ok_json("Paginated list of notes"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_note_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getNote")
        .tag("Notes")
        .summary("Get a note")
        .description(
            "Returns the details for a single note, including any related task/result identifiers and the NVT/host/port selectors the note annotates.",
        )
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<NoteResponse>, _>(ok_json("Note details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn create_note_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createNote")
        .tag("Notes")
        .summary("Create a note")
        .description(
            "Creates a note that annotates findings selected by NVT, optional task/result scope, and optional host/port/severity selectors.",
        )
        .security_requirement("bearerAuth")
        .input::<Json<CreateNoteRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Note created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn update_note_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyNote")
        .tag("Notes")
        .summary("Modify a note")
        .description("Updates a note used for finding triage.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyNoteRequest>)>()
        .response_with::<200, Json<NoteResponse>, _>(ok_json("Note updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_note_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteNote")
        .tag("Notes")
        .summary("Delete a note")
        .description("Deletes a note. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Note deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_overrides_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getOverrides")
        .tag("Overrides")
        .summary("List overrides")
        .description(
            "Returns a paginated list of overrides that change finding interpretation. Filter expressions can scope overrides to the related task, result, NVT, host, or port selectors exposed by each override.",
        )
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<OverrideListResponse>, _>(ok_json(
            "Paginated list of overrides",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_override_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getOverride")
        .tag("Overrides")
        .summary("Get an override")
        .description(
            "Returns the details for a single override, including any related task/result identifiers, the annotated NVT/host/port selectors, and the replacement severity when one is set.",
        )
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<OverrideResponse>, _>(ok_json("Override details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn create_override_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createOverride")
        .tag("Overrides")
        .summary("Create an override")
        .description(
            "Creates an override that changes finding interpretation for the selected NVT and optional task/result/host/port/severity scope.",
        )
        .security_requirement("bearerAuth")
        .input::<Json<CreateOverrideRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Override created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn update_override_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyOverride")
        .tag("Overrides")
        .summary("Modify an override")
        .description("Updates an override used for finding triage.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyOverrideRequest>)>()
        .response_with::<200, Json<OverrideResponse>, _>(ok_json("Override updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_override_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteOverride")
        .tag("Overrides")
        .summary("Delete an override")
        .description("Deletes an override. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Override deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
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
