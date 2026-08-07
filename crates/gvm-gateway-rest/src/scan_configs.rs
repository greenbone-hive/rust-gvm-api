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
    CreateScanConfigInput, GatewayError, ModifyScanConfigInput, ScanConfigQuery,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceCreatedResponse},
    handler::{
        create_resource, delete_resource, delete_resource_without_ultimate, get_resource,
        list_resource, update_resource, ValidateInto,
    },
    open_enum::open_u32_enum,
    openapi::{created_json, ok_json, problem_response, ResourceIdPathDoc, ScanConfigListQueryDoc},
    query::{parse_collection_query, DeleteResourceQueryParams},
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
