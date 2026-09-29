// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! REST resources for typed generic assets and configs.

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{AssetQuery, GatewayError, GenericConfigQuery, ModifyAssetInput};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceCreatedResponse},
    handler::{
        clone_resource, delete_resource, delete_resource_without_ultimate, get_resource,
        list_resource, update_resource, ValidateInto,
    },
    open_enum::open_string_enum,
    openapi::{created_json, ok_json, problem_response, ResourceIdPathDoc},
    query::{decoded_query_pairs, parse_collection_query, DeleteResourceQueryParams},
    supporting_resources::common::SupportingResourceMetaResponse,
};

fn default_page() -> Option<u32> {
    Some(1)
}

fn default_per_page() -> Option<u32> {
    Some(25)
}

open_string_enum! {
    /// Asset type returned by gvmd. Unknown future values remain intact.
    pub(crate) enum AssetType {
        Host => "host",
        OperatingSystem => "os",
        TlsCertificate => "tls_certificate",
    }
}

open_string_enum! {
    /// Config usage type returned by gvmd. Unknown future values remain intact.
    pub(crate) enum ConfigUsageType {
        Scan => "scan",
        Audit => "audit",
        Policy => "policy",
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
struct AssetListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    #[serde(rename = "type")]
    asset_type: AssetType,
    #[serde(default = "default_page")]
    #[schemars(default = "default_page")]
    #[schemars(range(min = 1))]
    page: Option<u32>,
    #[serde(rename = "perPage")]
    #[serde(default = "default_per_page")]
    #[schemars(default = "default_per_page")]
    #[schemars(range(min = 1, max = 1000))]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
struct AssetTypeQueryDoc {
    /// Required because typed gvmd asset reads must name the asset family.
    #[serde(rename = "type")]
    asset_type: AssetType,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct ConfigListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    #[serde(rename = "usageType")]
    usage_type: Option<ConfigUsageType>,
    #[serde(default = "default_page")]
    #[schemars(default = "default_page")]
    #[schemars(range(min = 1))]
    page: Option<u32>,
    #[serde(rename = "perPage")]
    #[serde(default = "default_per_page")]
    #[schemars(default = "default_per_page")]
    #[schemars(range(min = 1, max = 1000))]
    per_page: Option<u32>,
}

fn open_query_value(raw: &str, parameter: &str) -> Result<Option<String>, GatewayError> {
    let mut result = None;
    for (key, value) in decoded_query_pairs(raw) {
        if key == parameter {
            if value.trim().is_empty() {
                return Err(GatewayError::InvalidInput(format!(
                    "{parameter} must not be empty"
                )));
            }
            result = Some(value.into_owned());
        }
    }
    Ok(result)
}

fn parse_asset_query(raw: &str) -> Result<AssetQuery, GatewayError> {
    let common = parse_collection_query(raw)?;
    Ok(AssetQuery {
        filter_string: common.filter_string,
        filter_id: common.filter_id,
        page: common.page,
        per_page: common.per_page,
        asset_type: required_asset_type(raw)?,
    })
}

fn required_asset_type(raw: &str) -> Result<String, GatewayError> {
    open_query_value(raw, "type")?.ok_or_else(|| {
        GatewayError::InvalidInput(
            "type is required because typed gvmd asset reads are type-scoped".to_string(),
        )
    })
}

fn parse_config_query(raw: &str) -> Result<GenericConfigQuery, GatewayError> {
    let common = parse_collection_query(raw)?;
    Ok(GenericConfigQuery {
        filter_string: common.filter_string,
        filter_id: common.filter_id,
        page: common.page,
        per_page: common.per_page,
        usage_type: open_query_value(raw, "usageType")?,
    })
}

fn reject_asset_ultimate_query(query: Option<&str>) -> Result<(), GatewayError> {
    if query
        .into_iter()
        .flat_map(decoded_query_pairs)
        .any(|(key, _)| key == "ultimate")
    {
        return Err(GatewayError::InvalidInput(
            "ultimate is not supported for generic asset deletion".to_string(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AssetIdentifier")]
struct AssetIdentifierResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AssetHost")]
struct AssetHostResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "GenericAsset")]
struct GenericAssetResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(rename = "type")]
    asset_type: AssetType,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    identifiers: Vec<AssetIdentifierResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(rename = "hostsCount", skip_serializing_if = "Option::is_none")]
    hosts_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    installs: Option<u32>,
    #[serde(rename = "allInstalls", skip_serializing_if = "Option::is_none")]
    all_installs: Option<u32>,
    #[serde(rename = "latestSeverity", skip_serializing_if = "Option::is_none")]
    latest_severity: Option<String>,
    #[serde(rename = "highestSeverity", skip_serializing_if = "Option::is_none")]
    highest_severity: Option<String>,
    #[serde(rename = "averageSeverity", skip_serializing_if = "Option::is_none")]
    average_severity: Option<String>,
    #[serde(rename = "hostCount", skip_serializing_if = "Option::is_none")]
    host_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<AssetHostResponse>,
}

impl From<gvm_gateway_domain::GenericAsset> for GenericAssetResponse {
    fn from(asset: gvm_gateway_domain::GenericAsset) -> Self {
        Self {
            meta: asset.meta.into(),
            asset_type: AssetType::parse(&asset.asset_type),
            value: asset.value,
            identifiers: asset
                .identifiers
                .into_iter()
                .map(|identifier| AssetIdentifierResponse {
                    name: identifier.name,
                    value: identifier.value,
                    source: identifier.source,
                })
                .collect(),
            severity: asset.severity,
            ip: asset.ip,
            hostname: asset.hostname,
            os: asset.os,
            hosts_count: asset.hosts_count,
            title: asset.title,
            installs: asset.installs,
            all_installs: asset.all_installs,
            latest_severity: asset.latest_severity,
            highest_severity: asset.highest_severity,
            average_severity: asset.average_severity,
            host_count: asset.host_count,
            hosts: asset
                .hosts
                .into_iter()
                .map(|host| AssetHostResponse {
                    id: parse_uuid(&host.id),
                    name: host.name,
                    severity: host.severity,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "GenericAssetList")]
struct GenericAssetListResponse {
    data: Vec<GenericAssetResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::GenericAssetPage> for GenericAssetListResponse {
    fn from(page: gvm_gateway_domain::GenericAssetPage) -> Self {
        Self {
            data: page.data.into_iter().map(Into::into).collect(),
            pagination: page.pagination.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyGenericAsset")]
#[serde(deny_unknown_fields)]
struct ModifyGenericAssetRequest {
    /// Comment is the only generic asset field accepted by typed gvmd mutation.
    comment: Option<String>,
}

impl ValidateInto<ModifyAssetInput> for ModifyGenericAssetRequest {
    fn validate_into(self) -> Result<ModifyAssetInput, GatewayError> {
        Ok(ModifyAssetInput {
            comment: self.comment,
        })
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "GenericConfig")]
struct GenericConfigResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    config_type: Option<u32>,
    #[serde(rename = "usageType")]
    usage_type: ConfigUsageType,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<gvm_gateway_domain::GenericConfig> for GenericConfigResponse {
    fn from(config: gvm_gateway_domain::GenericConfig) -> Self {
        Self {
            id: parse_uuid(&config.id),
            name: config.name,
            comment: config.comment,
            config_type: config.config_type,
            usage_type: ConfigUsageType::parse(&config.usage_type),
            in_use: config.in_use,
            writable: config.writable,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "GenericConfigList")]
struct GenericConfigListResponse {
    data: Vec<GenericConfigResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::GenericConfigPage> for GenericConfigListResponse {
    fn from(page: gvm_gateway_domain::GenericConfigPage) -> Self {
        Self {
            data: page.data.into_iter().map(Into::into).collect(),
            pagination: page.pagination.into(),
        }
    }
}

/// List generic assets.
pub async fn list_assets(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        parse_asset_query,
        |service, token, query| async move { service.list_assets(&token, query).await },
        GenericAssetListResponse::from,
    )
    .await
}

/// Get a generic asset.
pub async fn get_asset(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let asset_type = match required_asset_type(uri.query().unwrap_or_default()) {
        Ok(asset_type) => asset_type,
        Err(error) => return crate::handler::gateway_error(error, uri.path().to_string()),
    };
    get_resource(
        service,
        headers,
        id,
        uri,
        |service, token, id| async move { service.get_asset(&token, &id, &asset_type).await },
        GenericAssetResponse::from,
    )
    .await
}

/// Update the comment of a generic asset.
pub async fn update_asset(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    let asset_type = match required_asset_type(uri.query().unwrap_or_default()) {
        Ok(asset_type) => asset_type,
        Err(error) => return crate::handler::gateway_error(error, uri.path().to_string()),
    };
    update_resource::<ModifyAssetInput, ModifyGenericAssetRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, token, id, input| async move {
            service.modify_asset(&token, &id, &asset_type, input).await
        },
        GenericAssetResponse::from,
    )
    .await
}

/// Delete a generic asset without unsupported permanent-delete semantics.
pub async fn delete_asset(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    if let Err(error) = reject_asset_ultimate_query(uri.query()) {
        return crate::handler::gateway_error(error, uri.path().to_string());
    }
    delete_resource_without_ultimate(service, headers, id, uri, |service, token, id| async move {
        service.delete_asset(&token, &id).await
    })
    .await
}

/// List generic configs.
pub async fn list_configs(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        parse_config_query,
        |service, token, query| async move { service.list_configs(&token, query).await },
        GenericConfigListResponse::from,
    )
    .await
}

/// Get a generic config.
pub async fn get_config(
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
        |service, token, id| async move { service.get_config(&token, &id).await },
        GenericConfigResponse::from,
    )
    .await
}

/// Delete a generic config with typed ultimate-delete forwarding.
pub async fn delete_config(
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
        |service, token, id, ultimate| async move {
            service.delete_config(&token, &id, ultimate).await
        },
    )
    .await
}

/// Clone a generic config.
pub async fn clone_config(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    clone_resource(
        service,
        headers,
        id,
        uri,
        "/api/v1/configs",
        |service, token, id| async move { service.clone_config(&token, &id).await },
    )
    .await
}

fn list_docs<'a, QueryDoc, ResponseDoc>(
    op: TransformOperation<'a>,
    operation_id: &'static str,
    tag: &'static str,
    summary: &'static str,
    description: &'static str,
) -> TransformOperation<'a>
where
    QueryDoc: JsonSchema + 'static,
    ResponseDoc: JsonSchema + 'static,
{
    let op = op
        .id(operation_id)
        .tag(tag)
        .summary(summary)
        .description(description)
        .security_requirement("bearerAuth")
        .input::<Query<QueryDoc>>()
        .response_with::<200, Json<ResponseDoc>, _>(ok_json(summary));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

fn item_docs<'a, ResponseDoc>(
    op: TransformOperation<'a>,
    operation_id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a>
where
    ResponseDoc: JsonSchema + 'static,
{
    let op = op
        .id(operation_id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ResponseDoc>, _>(ok_json(summary));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/assets`.
pub(crate) fn list_assets_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    list_docs::<AssetListQueryDoc, GenericAssetListResponse>(
        op,
        "getAssets",
        "Assets",
        "List generic assets",
        "Returns typed host, operating-system, TLS-certificate, and future asset variants with an open type discriminator.",
    )
}

/// OpenAPI transform for `GET /api/v1/assets/{id}`.
pub(crate) fn get_asset_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getAsset")
        .tag("Assets")
        .summary("Get a generic asset")
        .description(
            "The open type query is required because typed gvmd asset reads are type-scoped.",
        )
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<AssetTypeQueryDoc>)>()
        .response_with::<200, Json<GenericAssetResponse>, _>(ok_json("Get a generic asset"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `PUT /api/v1/assets/{id}`.
pub(crate) fn update_asset_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyAsset")
        .tag("Assets")
        .summary("Modify a generic asset")
        .description("Updates only the asset comment. The open type query is required to read back the type-scoped asset after mutation.")
        .security_requirement("bearerAuth")
        .input::<(
            Path<ResourceIdPathDoc>,
            Query<AssetTypeQueryDoc>,
            Json<ModifyGenericAssetRequest>,
        )>()
        .response_with::<200, Json<GenericAssetResponse>, _>(ok_json("Generic asset updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<409>(op, "Resource conflict");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `DELETE /api/v1/assets/{id}`.
pub(crate) fn delete_asset_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteAsset")
        .tag("Assets")
        .summary("Delete a generic asset")
        .description("Deletes an asset without an ultimate option because typed gvmd asset deletion does not support permanent-delete selection.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Generic asset deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<409>(op, "Resource conflict");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/configs`.
pub(crate) fn list_configs_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    list_docs::<ConfigListQueryDoc, GenericConfigListResponse>(
        op,
        "getConfigs",
        "Configs",
        "List generic configs",
        "Returns scan, audit, policy, and future config variants with an open usageType discriminator.",
    )
}

/// OpenAPI transform for `GET /api/v1/configs/{id}`.
pub(crate) fn get_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    item_docs::<GenericConfigResponse>(op, "getConfig", "Configs", "Get a generic config")
}

/// OpenAPI transform for `DELETE /api/v1/configs/{id}`.
pub(crate) fn delete_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteConfig")
        .tag("Configs")
        .summary("Delete a generic config")
        .description(
            "Deletes a config. Pass `ultimate=true` to request permanent backend deletion.",
        )
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Generic config deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<409>(op, "Resource conflict");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `POST /api/v1/configs/{id}/clone`.
pub(crate) fn clone_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("cloneConfig")
        .tag("Configs")
        .summary("Clone a generic config")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json(
            "Generic config cloned",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<409>(op, "Resource conflict");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

#[cfg(test)]
#[path = "generic_resources_test.rs"]
mod generic_resources_test;
