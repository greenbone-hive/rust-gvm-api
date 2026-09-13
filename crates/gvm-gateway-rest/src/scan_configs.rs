// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Scan config DTOs, request parsing, handlers, and response mapping for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    CreateScanConfigInput, GatewayError, ModifyScanConfigInput, ScanConfigFamilySelection,
    ScanConfigNvtQuery, ScanConfigPreference, ScanConfigPreferenceQuery, ScanConfigQuery,
    SetScanConfigFamilySelectionInput,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceCreatedResponse},
    handler::{
        create_resource, delete_resource, delete_resource_without_ultimate, gateway_error,
        get_resource, list_resource, no_content, ok_json as response_ok_json, parse_json_body_with,
        update_resource, ValidateInto,
    },
    open_enum::open_u32_enum,
    openapi::{created_json, ok_json, problem_response, ResourceIdPathDoc, ScanConfigListQueryDoc},
    query::{decoded_query_pairs, parse_collection_query, DeleteResourceQueryParams},
    router::bearer_token,
    supporting_resources::{NvtListResponse, NvtResponse},
    targets::validate_uuid,
};

// ============================================================================
// Response DTOs
// ============================================================================

open_u32_enum! {
    /// Scan config type.
    pub(crate) enum ScanConfigType {
        OpenVas => 0,
        Osp => 1,
    }
}

/// JSON body returned for a single scan config.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ScanConfig")]
pub(crate) struct ScanConfigResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "familyCount", skip_serializing_if = "Option::is_none")]
    family_count: Option<u32>,
    #[serde(rename = "nvtCount", skip_serializing_if = "Option::is_none")]
    nvt_count: Option<u32>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    config_type: Option<ScanConfigType>,
    /// Backend usage-type discriminator (`scan` or `policy`), so clients can
    /// tell compliance policies apart from scan configs in this collection.
    #[serde(rename = "usageType", skip_serializing_if = "Option::is_none")]
    usage_type: Option<String>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<gvm_gateway_domain::ScanConfig> for ScanConfigResponse {
    fn from(sc: gvm_gateway_domain::ScanConfig) -> Self {
        Self {
            id: parse_uuid(&sc.id),
            name: sc.name,
            comment: sc.comment,
            family_count: sc.family_count,
            nvt_count: sc.nvt_count,
            config_type: sc.config_type.map(ScanConfigType::parse),
            usage_type: sc.usage_type,
            in_use: sc.in_use,
            writable: sc.writable,
        }
    }
}

/// JSON body returned for a paginated list of scan configs.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ScanConfigList")]
pub(crate) struct ScanConfigListResponse {
    data: Vec<ScanConfigResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::ScanConfigPage> for ScanConfigListResponse {
    fn from(page: gvm_gateway_domain::ScanConfigPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(ScanConfigResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Parsed list-scan-configs query from HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanConfigListQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl ScanConfigListQuery {
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

/// Create-scan-config request payload.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[schemars(rename = "CreateScanConfig")]
#[serde(deny_unknown_fields)]
pub struct CreateScanConfigRequest {
    /// Optional name so validation can return RFC 9457 instead of extractor failures.
    #[schemars(required)]
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional base scan config identifier to copy from.
    #[serde(rename = "baseScanConfigId")]
    #[schemars(with = "Option<Uuid>")]
    pub base_scan_config_id: Option<String>,
}

impl CreateScanConfigRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<CreateScanConfigInput, GatewayError> {
        let name = self
            .name
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))?;
        if let Some(ref id) = self.base_scan_config_id {
            validate_uuid("baseScanConfigId", id)?;
        }

        Ok(CreateScanConfigInput {
            name,
            comment: self.comment,
            base_scan_config_id: self.base_scan_config_id,
        })
    }
}

impl ValidateInto<CreateScanConfigInput> for CreateScanConfigRequest {
    fn validate_into(self) -> Result<CreateScanConfigInput, GatewayError> {
        self.validate()
    }
}

/// Modify-scan-config request payload.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[schemars(rename = "ModifyScanConfig")]
#[serde(deny_unknown_fields)]
pub struct ModifyScanConfigRequest {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
}

impl ModifyScanConfigRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<ModifyScanConfigInput, GatewayError> {
        Ok(ModifyScanConfigInput {
            name: self.name,
            comment: self.comment,
        })
    }
}

impl ValidateInto<ModifyScanConfigInput> for ModifyScanConfigRequest {
    fn validate_into(self) -> Result<ModifyScanConfigInput, GatewayError> {
        self.validate()
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct ScanConfigNvtQueryDoc {
    family: Option<String>,
    #[serde(default = "default_page_doc")]
    #[schemars(default = "default_page_doc")]
    #[schemars(range(min = 1))]
    page: Option<u32>,
    #[serde(default = "default_per_page_doc")]
    #[schemars(default = "default_per_page_doc")]
    #[schemars(range(min = 1, max = 1000))]
    per_page: Option<u32>,
}

fn default_page_doc() -> Option<u32> {
    Some(1)
}

fn default_per_page_doc() -> Option<u32> {
    Some(25)
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct ScanConfigPreferenceQueryDoc {
    nvt_oid: Option<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[allow(dead_code)]
struct ScanConfigNvtPathDoc {
    id: Uuid,
    oid: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[allow(dead_code)]
struct ScanConfigPreferencePathDoc {
    id: Uuid,
    name: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[allow(dead_code)]
struct ScanConfigFamilyPathDoc {
    id: Uuid,
    family: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ScanConfigPreference")]
struct ScanConfigPreferenceResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    nvt: Option<ScanConfigPreferenceNvtResponse>,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    preference_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    alternatives: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct ScanConfigPreferenceNvtResponse {
    oid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

impl From<ScanConfigPreference> for ScanConfigPreferenceResponse {
    fn from(preference: ScanConfigPreference) -> Self {
        Self {
            nvt: preference.nvt.map(|nvt| ScanConfigPreferenceNvtResponse {
                oid: nvt.oid,
                name: nvt.name,
            }),
            name: preference.name,
            id: preference.id,
            preference_type: preference.preference_type,
            value: preference.value,
            alternatives: preference.alternatives,
            default: preference.default,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ScanConfigPreferenceList")]
struct ScanConfigPreferenceListResponse {
    data: Vec<ScanConfigPreferenceResponse>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SetNvtSelectionRequest {
    #[schemars(length(max = 10000))]
    nvt_oids: Vec<NvtOidRequest>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(transparent)]
struct NvtOidRequest(#[schemars(length(max = 255))] String);

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SetFamilySelectionRequest {
    #[schemars(length(max = 1000))]
    families: Vec<FamilySelectionRequest>,
    #[serde(default)]
    auto_add_new_families: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FamilySelectionRequest {
    #[schemars(length(max = 512))]
    name: String,
    growing: bool,
    all: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SetPreferenceRequest {
    #[schemars(length(max = 255))]
    nvt_oid: Option<String>,
    #[schemars(length(max = 65536))]
    value: Option<String>,
}

fn parse_scan_config_nvt_query(query: &str) -> Result<ScanConfigNvtQuery, GatewayError> {
    let mut family = None;
    let mut page = 1;
    let mut per_page = 25;
    for (key, value) in decoded_query_pairs(query) {
        match key.as_ref() {
            "family" => family = Some(require_bounded("family", value.into_owned(), 512)?),
            "page" => {
                page = value.parse().map_err(|_| {
                    GatewayError::InvalidInput("page must be a positive integer".to_string())
                })?;
            }
            "perPage" | "per_page" => {
                per_page = value.parse().map_err(|_| {
                    GatewayError::InvalidInput("perPage must be a positive integer".to_string())
                })?;
            }
            _ => {}
        }
    }
    if page == 0 || per_page == 0 || per_page > 1000 {
        return Err(GatewayError::InvalidInput(
            "page must be at least 1 and perPage between 1 and 1000".to_string(),
        ));
    }
    Ok(ScanConfigNvtQuery {
        family,
        page,
        per_page,
    })
}

fn parse_preference_query(query: &str) -> Result<ScanConfigPreferenceQuery, GatewayError> {
    let mut nvt_oid = None;
    for (key, value) in decoded_query_pairs(query) {
        if key == "nvtOid" {
            nvt_oid = Some(require_oid("nvtOid", value.into_owned())?);
        }
    }
    Ok(ScanConfigPreferenceQuery { nvt_oid })
}

fn require_bounded(field: &str, value: String, max: usize) -> Result<String, GatewayError> {
    if value.trim().is_empty() || value.len() > max {
        return Err(GatewayError::InvalidInput(format!(
            "{field} must contain between 1 and {max} bytes"
        )));
    }
    Ok(value)
}

fn require_oid(field: &str, value: String) -> Result<String, GatewayError> {
    if value.is_empty()
        || value.len() > 255
        || value.split('.').any(str::is_empty)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && byte != b'.')
    {
        return Err(GatewayError::InvalidInput(format!(
            "{field} must be a dotted numeric OID"
        )));
    }
    Ok(value)
}

/// List scan configs handler.
pub async fn list_scan_configs(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        ScanConfigListQuery::try_from_query_string,
        |service, session, query| async move {
            service
                .list_scan_configs(
                    &session,
                    ScanConfigQuery {
                        filter_string: query.filter_string,
                        filter_id: query.filter_id,
                        page: query.page,
                        per_page: query.per_page,
                    },
                )
                .await
        },
        ScanConfigListResponse::from,
    )
    .await
}

/// Create scan config handler.
pub async fn create_scan_config(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateScanConfigInput, CreateScanConfigRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_scan_config(&session, input).await },
    )
    .await
}

/// Get scan config handler.
pub async fn get_scan_config(
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
        |service, session, id| async move { service.get_scan_config(&session, &id).await },
        ScanConfigResponse::from,
    )
    .await
}

/// Update scan config handler.
pub async fn update_scan_config(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyScanConfigInput, ModifyScanConfigRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_scan_config(&session, &id, input).await
        },
        ScanConfigResponse::from,
    )
    .await
}

/// Delete scan config handler.
pub async fn delete_scan_config(
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
            service.delete_scan_config(&session, &id, ultimate).await
        },
    )
    .await
}

/// List NVTs selected by a scan configuration.
pub async fn list_scan_config_nvts(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let query = match parse_scan_config_nvt_query(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return gateway_error(error, instance),
    };
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service.list_scan_config_nvts(&session, &id, query).await {
        Ok(page) => response_ok_json(NvtListResponse::from(gvm_gateway_domain::NvtPage {
            data: page.data,
            pagination: page.pagination,
        })),
        Err(error) => gateway_error(error, instance),
    }
}

/// Fetch one NVT selected by a scan configuration.
pub async fn get_scan_config_nvt(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path((id, oid)): Path<(String, String)>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let oid = match require_oid("oid", oid) {
        Ok(oid) => oid,
        Err(error) => return gateway_error(error, instance),
    };
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service.get_scan_config_nvt(&session, &id, &oid).await {
        Ok(nvt) => response_ok_json(NvtResponse::from(nvt)),
        Err(error) => gateway_error(error, instance),
    }
}

/// List scanner or NVT preferences for a scan configuration.
pub async fn list_scan_config_preferences(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let query = match parse_preference_query(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return gateway_error(error, instance),
    };
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service
        .list_scan_config_preferences(&session, &id, query)
        .await
    {
        Ok(preferences) => response_ok_json(ScanConfigPreferenceListResponse {
            data: preferences
                .into_iter()
                .map(ScanConfigPreferenceResponse::from)
                .collect(),
        }),
        Err(error) => gateway_error(error, instance),
    }
}

/// Fetch one scanner or NVT preference for a scan configuration.
pub async fn get_scan_config_preference(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path((id, name)): Path<(String, String)>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let name = match require_bounded("name", name, 512) {
        Ok(name) => name,
        Err(error) => return gateway_error(error, instance),
    };
    let query = match parse_preference_query(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return gateway_error(error, instance),
    };
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service
        .get_scan_config_preference(&session, &id, &name, query)
        .await
    {
        Ok(preference) => response_ok_json(ScanConfigPreferenceResponse::from(preference)),
        Err(error) => gateway_error(error, instance),
    }
}

/// Replace one family's selected NVTs.
pub async fn set_scan_config_nvt_selection(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path((id, family)): Path<(String, String)>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let family = match require_bounded("family", family, 512) {
        Ok(family) => family,
        Err(error) => return gateway_error(error, instance),
    };
    let request = match parse_json_body_with::<SetNvtSelectionRequest, _>(&body, |_| {
        GatewayError::InvalidInput("request body must be a valid NVT selection".to_string())
    }) {
        Ok(request) => request,
        Err(error) => return gateway_error(error, instance),
    };
    if request.nvt_oids.len() > 10_000
        || request
            .nvt_oids
            .iter()
            .any(|oid| require_oid("nvtOids", oid.0.clone()).is_err())
    {
        return gateway_error(
            GatewayError::InvalidInput(
                "nvtOids must contain at most 10000 non-empty OIDs".to_string(),
            ),
            instance,
        );
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service
        .set_scan_config_nvt_selection(
            &session,
            &id,
            &family,
            request.nvt_oids.into_iter().map(|oid| oid.0).collect(),
        )
        .await
    {
        Ok(()) => no_content(),
        Err(error) => gateway_error(error, instance),
    }
}

/// Replace family selection atomically.
pub async fn set_scan_config_family_selection(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let request = match parse_json_body_with::<SetFamilySelectionRequest, _>(&body, |_| {
        GatewayError::InvalidInput("request body must be a valid family selection".to_string())
    }) {
        Ok(request) => request,
        Err(error) => return gateway_error(error, instance),
    };
    if request.families.len() > 1_000
        || request
            .families
            .iter()
            .any(|family| family.name.trim().is_empty() || family.name.len() > 512)
    {
        return gateway_error(
            GatewayError::InvalidInput(
                "families must contain at most 1000 non-empty family names".to_string(),
            ),
            instance,
        );
    }
    let input = SetScanConfigFamilySelectionInput {
        families: request
            .families
            .into_iter()
            .map(|family| ScanConfigFamilySelection {
                name: family.name,
                growing: family.growing,
                all: family.all,
            })
            .collect(),
        auto_add_new_families: request.auto_add_new_families,
    };
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service
        .set_scan_config_family_selection(&session, &id, input)
        .await
    {
        Ok(()) => no_content(),
        Err(error) => gateway_error(error, instance),
    }
}

/// Set or reset a scanner or NVT preference.
pub async fn set_scan_config_preference(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path((id, name)): Path<(String, String)>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let name = match require_bounded("name", name, 512) {
        Ok(name) => name,
        Err(error) => return gateway_error(error, instance),
    };
    let request = match parse_json_body_with::<SetPreferenceRequest, _>(&body, |_| {
        GatewayError::InvalidInput("request body must be a valid preference update".to_string())
    }) {
        Ok(request) => request,
        Err(error) => return gateway_error(error, instance),
    };
    if request
        .nvt_oid
        .as_ref()
        .is_some_and(|oid| require_oid("nvtOid", oid.clone()).is_err())
        || request
            .value
            .as_ref()
            .is_some_and(|value| value.len() > 65_536)
    {
        return gateway_error(
            GatewayError::InvalidInput(
                "nvtOid must be non-empty and preference values are limited to 65536 bytes"
                    .to_string(),
            ),
            instance,
        );
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service
        .set_scan_config_preference(&session, &id, &name, request.nvt_oid, request.value)
        .await
    {
        Ok(()) => no_content(),
        Err(error) => gateway_error(error, instance),
    }
}

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `GET /api/v1/scan-configs`.
pub(crate) fn list_scan_configs_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanConfigs")
        .tag("Scan Configs")
        .summary("List scan configurations")
        .description("Returns a paginated list of scan configurations.")
        .security_requirement("bearerAuth")
        .input::<Query<ScanConfigListQueryDoc>>()
        .response_with::<200, Json<ScanConfigListResponse>, _>(ok_json(
            "Paginated list of scan configs",
        ));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `POST /api/v1/scan-configs`.
pub(crate) fn create_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createScanConfig")
        .tag("Scan Configs")
        .summary("Create a scan configuration")
        .description("Creates a new scan configuration.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateScanConfigRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json(
            "Scan config created",
        ));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/scan-configs/{id}`.
pub(crate) fn get_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanConfig")
        .tag("Scan Configs")
        .summary("Get a scan configuration")
        .description("Returns the details for a single scan configuration.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ScanConfigResponse>, _>(ok_json("Scan config details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `PUT /api/v1/scan-configs/{id}`.
pub(crate) fn update_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyScanConfig")
        .tag("Scan Configs")
        .summary("Modify a scan configuration")
        .description("Updates an existing scan configuration.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyScanConfigRequest>)>()
        .response_with::<200, Json<ScanConfigResponse>, _>(ok_json("Scan config updated"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/scan-configs/{id}`.
pub(crate) fn delete_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteScanConfig")
        .tag("Scan Configs")
        .summary("Delete a scan configuration")
        .description("Deletes a scan configuration. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Scan config deleted"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_scan_config_nvts_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanConfigNvts")
        .tag("Scan Configs")
        .summary("List selected NVTs")
        .description("Returns NVTs selected by this scan configuration.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ScanConfigNvtQueryDoc>)>()
        .response_with::<200, Json<NvtListResponse>, _>(ok_json("Selected NVTs"));
    let op = problem_response::<400>(op, "Invalid query");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Scan config not found")
}

pub(crate) fn get_scan_config_nvt_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanConfigNvt")
        .tag("Scan Configs")
        .summary("Get a selected NVT")
        .security_requirement("bearerAuth")
        .input::<Path<ScanConfigNvtPathDoc>>()
        .response_with::<200, Json<NvtResponse>, _>(ok_json("Selected NVT"));
    let op = problem_response::<400>(op, "Invalid identifier");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "NVT is not selected")
}

pub(crate) fn list_scan_config_preferences_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("getScanConfigPreferences")
        .tag("Scan Configs")
        .summary("List configured preferences")
        .description("Lists scanner preferences, or NVT preferences when `nvtOid` is supplied.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ScanConfigPreferenceQueryDoc>)>()
        .response_with::<200, Json<ScanConfigPreferenceListResponse>, _>(ok_json(
            "Configured preferences",
        ));
    let op = problem_response::<400>(op, "Invalid query");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Scan config not found")
}

pub(crate) fn get_scan_config_preference_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("getScanConfigPreference")
        .tag("Scan Configs")
        .summary("Get a configured preference")
        .security_requirement("bearerAuth")
        .input::<(
            Path<ScanConfigPreferencePathDoc>,
            Query<ScanConfigPreferenceQueryDoc>,
        )>()
        .response_with::<200, Json<ScanConfigPreferenceResponse>, _>(ok_json(
            "Configured preference",
        ));
    let op = problem_response::<400>(op, "Invalid query or identifier");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Preference not found")
}

pub(crate) fn set_scan_config_nvt_selection_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("setScanConfigNvtSelection")
        .tag("Scan Configs")
        .summary("Replace a family's NVT selection")
        .security_requirement("bearerAuth")
        .input::<(Path<ScanConfigFamilyPathDoc>, Json<SetNvtSelectionRequest>)>()
        .response_with::<204, (), _>(|response| response.description("NVT selection replaced"));
    let op = problem_response::<400>(op, "Invalid selection");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Scan config not found")
}

pub(crate) fn set_scan_config_family_selection_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("setScanConfigFamilySelection")
        .tag("Scan Configs")
        .summary("Replace family selection")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<SetFamilySelectionRequest>)>()
        .response_with::<204, (), _>(|response| response.description("Family selection replaced"));
    let op = problem_response::<400>(op, "Invalid selection");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Scan config not found")
}

pub(crate) fn set_scan_config_preference_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("setScanConfigPreference")
        .tag("Scan Configs")
        .summary("Set or reset a configured preference")
        .description("Omit `value` to reset an NVT or scanner preference to its default.")
        .security_requirement("bearerAuth")
        .input::<(
            Path<ScanConfigPreferencePathDoc>,
            Json<SetPreferenceRequest>,
        )>()
        .response_with::<204, (), _>(|response| response.description("Preference updated"));
    let op = problem_response::<400>(op, "Invalid preference update");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Scan config not found")
}

// ============================================================================
// Policy handlers (compliance scan configs; reuse ScanConfig DTOs)
// ============================================================================

/// List policies handler.
pub async fn list_policies(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        ScanConfigListQuery::try_from_query_string,
        |service, session, query| async move {
            service
                .list_policies(
                    &session,
                    ScanConfigQuery {
                        filter_string: query.filter_string,
                        filter_id: query.filter_id,
                        page: query.page,
                        per_page: query.per_page,
                    },
                )
                .await
        },
        ScanConfigListResponse::from,
    )
    .await
}

/// Create policy handler.
pub async fn create_policy(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateScanConfigInput, CreateScanConfigRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_policy(&session, input).await },
    )
    .await
}

/// Get policy handler. Scoped to the policy usage type so a scan config is not
/// readable through this route.
pub async fn get_policy(
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
        |service, session, id| async move { service.get_policy(&session, &id).await },
        ScanConfigResponse::from,
    )
    .await
}

/// Update policy handler.
pub async fn update_policy(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyScanConfigInput, ModifyScanConfigRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_policy(&session, &id, input).await
        },
        ScanConfigResponse::from,
    )
    .await
}

/// Delete policy handler. Policies are always deleted non-ultimately by the backend.
pub async fn delete_policy(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource_without_ultimate(
        service,
        headers,
        id,
        uri,
        |service, session, id| async move { service.delete_policy(&session, &id).await },
    )
    .await
}

/// OpenAPI transform for `GET /api/v1/policies`.
pub(crate) fn list_policies_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getPolicies")
        .tag("Policies")
        .summary("List policies")
        .description("Returns a paginated list of compliance policies.")
        .security_requirement("bearerAuth")
        .input::<Query<ScanConfigListQueryDoc>>()
        .response_with::<200, Json<ScanConfigListResponse>, _>(ok_json(
            "Paginated list of policies",
        ));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `POST /api/v1/policies`.
pub(crate) fn create_policy_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createPolicy")
        .tag("Policies")
        .summary("Create a policy")
        .description("Creates a new compliance policy.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateScanConfigRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Policy created"));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/policies/{id}`.
pub(crate) fn get_policy_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getPolicy")
        .tag("Policies")
        .summary("Get a policy")
        .description("Returns the details for a single compliance policy.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ScanConfigResponse>, _>(ok_json("Policy details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `PUT /api/v1/policies/{id}`.
pub(crate) fn update_policy_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyPolicy")
        .tag("Policies")
        .summary("Modify a policy")
        .description("Updates an existing compliance policy.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyScanConfigRequest>)>()
        .response_with::<200, Json<ScanConfigResponse>, _>(ok_json("Policy updated"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/policies/{id}`.
pub(crate) fn delete_policy_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deletePolicy")
        .tag("Policies")
        .summary("Delete a policy")
        .description("Deletes a compliance policy.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Policy deleted"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "scan_configs_test.rs"]
mod scan_configs_test;
