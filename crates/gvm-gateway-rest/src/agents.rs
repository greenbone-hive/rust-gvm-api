// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Agent and agent-group REST resources.

use aide::transform::{TransformOperation, TransformResponse};
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Uri},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    AgentConfig, AgentControlConfig, AgentGroupQuery, AgentInstallerInstructionQuery, AgentQuery,
    AgentRetryConfig, AgentScriptExecutorConfig, AgentSupportBundleQuery, CreateAgentGroupInput,
    GatewayError, ModifyAgentControlScanConfigInput, ModifyAgentGroupInput, ModifyAgentInput,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceCreatedResponse, ResourceRefResponse},
    handler::{
        clone_resource, create_resource, delete_resource, delete_resource_without_ultimate,
        gateway_error, get_resource, list_resource, no_content, ok_json, parse_json_body_with,
        update_resource, ValidateInto,
    },
    openapi::{created_json, ok_json as ok_json_docs, problem_response, ResourceIdPathDoc},
    query::{decoded_query_pairs, parse_collection_query, DeleteResourceQueryParams},
    router::bearer_token,
};

const DEFAULT_PER_PAGE: u32 = 25;

fn default_page() -> Option<u32> {
    Some(1)
}

fn default_per_page() -> Option<u32> {
    Some(DEFAULT_PER_PAGE)
}

fn default_trash() -> Option<bool> {
    Some(false)
}

fn default_language() -> String {
    "en".to_string()
}

fn uri_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type": "string", "format": "uri"})
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct AgentListQueryParams {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
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

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct AgentGroupListQueryParams {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    #[serde(default = "default_trash")]
    #[schemars(default = "default_trash")]
    trash: Option<bool>,
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

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct AgentSupportBundleQueryParams {
    /// Limit the support bundle to the most recent number of days.
    #[schemars(range(min = 1))]
    days: Option<u32>,
    /// Request backend support-bundle encryption. Omission preserves the backend default and is
    /// distinct from explicit false.
    encryption: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub(crate) struct AgentInstallerInstructionQueryParams {
    #[serde(rename = "originUrl")]
    #[schemars(schema_with = "uri_schema")]
    origin_url: String,
    #[serde(default = "default_language")]
    language: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AgentRetryConfig")]
struct AgentRetryConfigResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    attempts: Option<u32>,
    #[serde(rename = "delayInSeconds", skip_serializing_if = "Option::is_none")]
    delay_in_seconds: Option<u32>,
    #[serde(rename = "maxJitterInSeconds", skip_serializing_if = "Option::is_none")]
    max_jitter_in_seconds: Option<u32>,
}

impl From<gvm_gateway_domain::AgentRetryConfig> for AgentRetryConfigResponse {
    fn from(value: gvm_gateway_domain::AgentRetryConfig) -> Self {
        Self {
            attempts: value.attempts,
            delay_in_seconds: value.delay_in_seconds,
            max_jitter_in_seconds: value.max_jitter_in_seconds,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AgentControlConfig")]
struct AgentControlConfigResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    retry: Option<AgentRetryConfigResponse>,
}

impl From<gvm_gateway_domain::AgentControlConfig> for AgentControlConfigResponse {
    fn from(value: gvm_gateway_domain::AgentControlConfig) -> Self {
        Self {
            retry: value.retry.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AgentScriptExecutorConfig")]
struct AgentScriptExecutorConfigResponse {
    #[serde(rename = "bulkSize", skip_serializing_if = "Option::is_none")]
    bulk_size: Option<u32>,
    #[serde(
        rename = "bulkThrottleTimeInMs",
        skip_serializing_if = "Option::is_none"
    )]
    bulk_throttle_time_in_ms: Option<u32>,
    #[serde(rename = "indexerDirDepth", skip_serializing_if = "Option::is_none")]
    indexer_dir_depth: Option<u32>,
    #[serde(
        rename = "schedulerCronTime",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    scheduler_cron_time: Vec<String>,
}

impl From<gvm_gateway_domain::AgentScriptExecutorConfig> for AgentScriptExecutorConfigResponse {
    fn from(value: gvm_gateway_domain::AgentScriptExecutorConfig) -> Self {
        Self {
            bulk_size: value.bulk_size,
            bulk_throttle_time_in_ms: value.bulk_throttle_time_in_ms,
            indexer_dir_depth: value.indexer_dir_depth,
            scheduler_cron_time: value.scheduler_cron_time,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AgentHeartbeatConfig")]
struct AgentHeartbeatConfigResponse {
    #[serde(rename = "intervalInSeconds", skip_serializing_if = "Option::is_none")]
    interval_in_seconds: Option<u32>,
    #[serde(rename = "missUntilInactive", skip_serializing_if = "Option::is_none")]
    miss_until_inactive: Option<u32>,
}

impl From<gvm_gateway_domain::AgentHeartbeatConfig> for AgentHeartbeatConfigResponse {
    fn from(value: gvm_gateway_domain::AgentHeartbeatConfig) -> Self {
        Self {
            interval_in_seconds: value.interval_in_seconds,
            miss_until_inactive: value.miss_until_inactive,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AgentConfig")]
struct AgentConfigResponse {
    #[serde(rename = "agentControl", skip_serializing_if = "Option::is_none")]
    agent_control: Option<AgentControlConfigResponse>,
    #[serde(
        rename = "agentScriptExecutor",
        skip_serializing_if = "Option::is_none"
    )]
    agent_script_executor: Option<AgentScriptExecutorConfigResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    heartbeat: Option<AgentHeartbeatConfigResponse>,
}

impl From<gvm_gateway_domain::AgentConfig> for AgentConfigResponse {
    fn from(value: gvm_gateway_domain::AgentConfig) -> Self {
        Self {
            agent_control: value.agent_control.map(Into::into),
            agent_script_executor: value.agent_script_executor.map(Into::into),
            heartbeat: value.heartbeat.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Agent")]
struct AgentResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "creationTime", skip_serializing_if = "Option::is_none")]
    creation_time: Option<String>,
    #[serde(rename = "modificationTime", skip_serializing_if = "Option::is_none")]
    modification_time: Option<String>,
    writable: bool,
    #[serde(rename = "inUse")]
    in_use: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized: Option<bool>,
    #[serde(rename = "updateToLatest", skip_serializing_if = "Option::is_none")]
    update_to_latest: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(rename = "lastUpdateTime", skip_serializing_if = "Option::is_none")]
    last_update_time: Option<String>,
    #[serde(rename = "lastContactTime", skip_serializing_if = "Option::is_none")]
    last_contact_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scanner: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<AgentConfigResponse>,
}

impl From<gvm_gateway_domain::Agent> for AgentResponse {
    fn from(value: gvm_gateway_domain::Agent) -> Self {
        Self {
            id: parse_uuid(&value.meta.id),
            name: value.meta.name,
            comment: value.meta.comment,
            creation_time: value.meta.creation_time,
            modification_time: value.meta.modification_time,
            writable: value.meta.writable,
            in_use: value.meta.in_use,
            authorized: value.authorized,
            update_to_latest: value.update_to_latest,
            status: value.status,
            version: value.version,
            last_update_time: value.last_update_time,
            last_contact_time: value.last_contact_time,
            scanner: value.scanner.map(Into::into),
            config: value.config.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AgentList")]
struct AgentListResponse {
    data: Vec<AgentResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::AgentPage> for AgentListResponse {
    fn from(value: gvm_gateway_domain::AgentPage) -> Self {
        Self {
            data: value.data.into_iter().map(Into::into).collect(),
            pagination: value.pagination.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "ModifyAgent")]
struct ModifyAgentRequest {
    authorized: Option<bool>,
    #[serde(rename = "updateToLatest")]
    update_to_latest: Option<bool>,
    comment: Option<String>,
    config: Option<AgentConfigRequest>,
}

impl ValidateInto<ModifyAgentInput> for ModifyAgentRequest {
    fn validate_into(self) -> Result<ModifyAgentInput, GatewayError> {
        Ok(ModifyAgentInput {
            authorized: self.authorized,
            update_to_latest: self.update_to_latest,
            comment: self.comment,
            config: self.config.map(ValidateInto::validate_into).transpose()?,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "AgentConfigUpdate")]
struct AgentConfigRequest {
    #[serde(rename = "agentControl")]
    agent_control: Option<AgentControlConfigRequest>,
    #[serde(rename = "agentScriptExecutor")]
    agent_script_executor: Option<AgentScriptExecutorConfigRequest>,
    heartbeat: Option<AgentHeartbeatConfigRequest>,
}

impl ValidateInto<AgentConfig> for AgentConfigRequest {
    fn validate_into(self) -> Result<AgentConfig, GatewayError> {
        Ok(AgentConfig {
            agent_control: self
                .agent_control
                .map(ValidateInto::validate_into)
                .transpose()?,
            agent_script_executor: self
                .agent_script_executor
                .map(ValidateInto::validate_into)
                .transpose()?,
            heartbeat: self
                .heartbeat
                .map(ValidateInto::validate_into)
                .transpose()?,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "AgentControlConfigUpdate")]
struct AgentControlConfigRequest {
    retry: Option<AgentRetryConfigRequest>,
}

impl ValidateInto<AgentControlConfig> for AgentControlConfigRequest {
    fn validate_into(self) -> Result<AgentControlConfig, GatewayError> {
        Ok(AgentControlConfig {
            retry: self.retry.map(ValidateInto::validate_into).transpose()?,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "AgentRetryConfigUpdate")]
struct AgentRetryConfigRequest {
    attempts: Option<u32>,
    #[serde(rename = "delayInSeconds")]
    delay_in_seconds: Option<u32>,
    #[serde(rename = "maxJitterInSeconds")]
    max_jitter_in_seconds: Option<u32>,
}

impl ValidateInto<AgentRetryConfig> for AgentRetryConfigRequest {
    fn validate_into(self) -> Result<AgentRetryConfig, GatewayError> {
        Ok(AgentRetryConfig {
            attempts: self.attempts,
            delay_in_seconds: self.delay_in_seconds,
            max_jitter_in_seconds: self.max_jitter_in_seconds,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "AgentScriptExecutorConfigUpdate")]
struct AgentScriptExecutorConfigRequest {
    #[serde(rename = "bulkSize")]
    bulk_size: Option<u32>,
    #[serde(rename = "bulkThrottleTimeInMs")]
    bulk_throttle_time_in_ms: Option<u32>,
    #[serde(rename = "indexerDirDepth")]
    indexer_dir_depth: Option<u32>,
    #[serde(rename = "schedulerCronTime", default)]
    scheduler_cron_time: Vec<String>,
}

impl ValidateInto<AgentScriptExecutorConfig> for AgentScriptExecutorConfigRequest {
    fn validate_into(self) -> Result<AgentScriptExecutorConfig, GatewayError> {
        validate_cron_items("schedulerCronTime", &self.scheduler_cron_time)?;
        Ok(AgentScriptExecutorConfig {
            bulk_size: self.bulk_size,
            bulk_throttle_time_in_ms: self.bulk_throttle_time_in_ms,
            indexer_dir_depth: self.indexer_dir_depth,
            scheduler_cron_time: self.scheduler_cron_time,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "AgentHeartbeatConfigUpdate")]
struct AgentHeartbeatConfigRequest {
    #[serde(rename = "intervalInSeconds")]
    interval_in_seconds: Option<u32>,
    #[serde(rename = "missUntilInactive")]
    miss_until_inactive: Option<u32>,
}

impl ValidateInto<gvm_gateway_domain::AgentHeartbeatConfig> for AgentHeartbeatConfigRequest {
    fn validate_into(self) -> Result<gvm_gateway_domain::AgentHeartbeatConfig, GatewayError> {
        Ok(gvm_gateway_domain::AgentHeartbeatConfig {
            interval_in_seconds: self.interval_in_seconds,
            miss_until_inactive: self.miss_until_inactive,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "ModifyAgentControlScanConfig")]
struct ModifyAgentControlScanConfigRequest {
    #[serde(rename = "agentDefaults")]
    agent_defaults: Option<AgentConfigRequest>,
    #[serde(rename = "updateToLatest")]
    update_to_latest: Option<bool>,
}

impl ValidateInto<ModifyAgentControlScanConfigInput> for ModifyAgentControlScanConfigRequest {
    fn validate_into(self) -> Result<ModifyAgentControlScanConfigInput, GatewayError> {
        Ok(ModifyAgentControlScanConfigInput {
            agent_defaults: self
                .agent_defaults
                .map(ValidateInto::validate_into)
                .transpose()?,
            update_to_latest: self.update_to_latest,
        })
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AgentInstallerInstruction")]
struct AgentInstallerInstructionResponse {
    language: String,
    instruction: String,
}

impl From<gvm_gateway_domain::AgentInstallerInstruction> for AgentInstallerInstructionResponse {
    fn from(value: gvm_gateway_domain::AgentInstallerInstruction) -> Self {
        Self {
            language: value.language,
            instruction: value.instruction,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AgentGroup")]
struct AgentGroupResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "creationTime", skip_serializing_if = "Option::is_none")]
    creation_time: Option<String>,
    #[serde(rename = "modificationTime", skip_serializing_if = "Option::is_none")]
    modification_time: Option<String>,
    writable: bool,
    #[serde(rename = "inUse")]
    in_use: bool,
    #[serde(rename = "schedulerCronTime", skip_serializing_if = "Option::is_none")]
    scheduler_cron_time: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    agents: Vec<ResourceRefResponse>,
}

impl From<gvm_gateway_domain::AgentGroup> for AgentGroupResponse {
    fn from(value: gvm_gateway_domain::AgentGroup) -> Self {
        Self {
            id: parse_uuid(&value.meta.id),
            name: value.meta.name,
            comment: value.meta.comment,
            creation_time: value.meta.creation_time,
            modification_time: value.meta.modification_time,
            writable: value.meta.writable,
            in_use: value.meta.in_use,
            scheduler_cron_time: value.scheduler_cron_time,
            agents: value.agents.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AgentGroupList")]
struct AgentGroupListResponse {
    data: Vec<AgentGroupResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::AgentGroupPage> for AgentGroupListResponse {
    fn from(value: gvm_gateway_domain::AgentGroupPage) -> Self {
        Self {
            data: value.data.into_iter().map(Into::into).collect(),
            pagination: value.pagination.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "CreateAgentGroup")]
struct CreateAgentGroupRequest {
    #[schemars(required)]
    name: Option<String>,
    #[serde(rename = "schedulerCronTime")]
    #[schemars(required)]
    scheduler_cron_time: Option<String>,
    comment: Option<String>,
    #[serde(rename = "agentIds", default)]
    agent_ids: Vec<Uuid>,
}

impl ValidateInto<CreateAgentGroupInput> for CreateAgentGroupRequest {
    fn validate_into(self) -> Result<CreateAgentGroupInput, GatewayError> {
        Ok(CreateAgentGroupInput {
            name: required_trimmed("name", self.name)?,
            scheduler_cron_time: required_trimmed("schedulerCronTime", self.scheduler_cron_time)?,
            comment: self.comment,
            agent_ids: self
                .agent_ids
                .into_iter()
                .map(|value| value.to_string())
                .collect(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "ModifyAgentGroup")]
struct ModifyAgentGroupRequest {
    #[serde(rename = "schedulerCronTime")]
    #[schemars(required)]
    scheduler_cron_time: Option<String>,
    name: Option<String>,
    comment: Option<String>,
    #[serde(rename = "agentIds")]
    agent_ids: Option<Vec<Uuid>>,
}

impl ValidateInto<ModifyAgentGroupInput> for ModifyAgentGroupRequest {
    fn validate_into(self) -> Result<ModifyAgentGroupInput, GatewayError> {
        Ok(ModifyAgentGroupInput {
            scheduler_cron_time: required_trimmed("schedulerCronTime", self.scheduler_cron_time)?,
            name: self.name,
            comment: self.comment,
            agent_ids: self
                .agent_ids
                .map(|ids| ids.into_iter().map(|value| value.to_string()).collect()),
        })
    }
}

fn parse_agent_query(raw: &str) -> Result<AgentQuery, GatewayError> {
    let parsed = parse_collection_query(raw)?;
    Ok(AgentQuery {
        filter_string: parsed.filter_string,
        filter_id: parsed.filter_id,
        page: parsed.page,
        per_page: parsed.per_page,
    })
}

fn parse_agent_group_query(raw: &str) -> Result<AgentGroupQuery, GatewayError> {
    let parsed = parse_collection_query(raw)?;
    let mut trash = false;
    for (key, value) in decoded_query_pairs(raw) {
        if key == "trash" {
            trash = value.parse::<bool>().map_err(|_| {
                GatewayError::InvalidInput("trash must be true or false".to_string())
            })?;
        }
    }
    Ok(AgentGroupQuery {
        filter_string: parsed.filter_string,
        filter_id: parsed.filter_id,
        trash,
        page: parsed.page,
        per_page: parsed.per_page,
    })
}

fn parse_agent_support_bundle_query(raw: &str) -> Result<AgentSupportBundleQuery, GatewayError> {
    let mut days = None;
    let mut encryption = None;
    for (key, value) in decoded_query_pairs(raw) {
        match key.as_ref() {
            "days" => {
                let parsed_days = value.parse::<u32>().map_err(|_| {
                    GatewayError::InvalidInput("days must be a positive integer".to_string())
                })?;
                if parsed_days == 0 {
                    return Err(GatewayError::InvalidInput(
                        "days must be greater than or equal to 1".to_string(),
                    ));
                }
                days = Some(parsed_days);
            }
            "encryption" => {
                encryption = Some(value.parse::<bool>().map_err(|_| {
                    GatewayError::InvalidInput("encryption must be true or false".to_string())
                })?);
            }
            _ => {}
        }
    }
    Ok(AgentSupportBundleQuery { days, encryption })
}

fn parse_agent_installer_instruction_query(
    raw: &str,
) -> Result<AgentInstallerInstructionQuery, GatewayError> {
    let mut origin_url = None;
    let mut language = default_language();

    for (key, value) in decoded_query_pairs(raw) {
        match key.as_ref() {
            "originUrl" => origin_url = Some(value.into_owned()),
            "language" => language = value.into_owned(),
            _ => {}
        }
    }

    let origin_url = required_trimmed("originUrl", origin_url)?;
    let uri = origin_url
        .parse::<Uri>()
        .map_err(|_| GatewayError::InvalidInput("originUrl must be a valid URI".to_string()))?;
    if uri.scheme().is_none() || uri.authority().is_none() {
        return Err(GatewayError::InvalidInput(
            "originUrl must be an absolute URI".to_string(),
        ));
    }

    Ok(AgentInstallerInstructionQuery {
        language,
        origin_url,
    })
}

fn required_trimmed(field: &str, value: Option<String>) -> Result<String, GatewayError> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GatewayError::InvalidInput(format!("{field} is required")))
}

fn validate_cron_items(field: &str, values: &[String]) -> Result<(), GatewayError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(GatewayError::InvalidInput(format!(
            "{field} cannot contain empty entries"
        )));
    }
    Ok(())
}

fn safe_attachment_filename(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | '"' | '\r' | '\n' | '\t' => '_',
            ch if ch.is_control() => '_',
            _ => ch,
        })
        .collect::<String>()
        .trim()
        .trim_matches('.')
        .to_string();
    if sanitized.is_empty() {
        "agent-support-bundle.bin".to_string()
    } else {
        sanitized
    }
}

/// List agents.
pub async fn list_agents(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        parse_agent_query,
        |service, token, query| async move { service.list_agents(&token, query).await },
        AgentListResponse::from,
    )
    .await
}

/// Get an agent.
pub async fn get_agent(
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
        |service, token, id| async move { service.get_agent(&token, &id).await },
        AgentResponse::from,
    )
    .await
}

/// Update an agent.
pub async fn update_agent(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyAgentInput, ModifyAgentRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, token, id, input| async move { service.modify_agent(&token, &id, input).await },
        AgentResponse::from,
    )
    .await
}

/// Delete an agent.
pub async fn delete_agent(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource_without_ultimate(service, headers, id, uri, |service, token, id| async move {
        service.delete_agent(&token, &id).await
    })
    .await
}

/// Synchronize agents.
pub async fn sync_agents(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service.sync_agents(&session).await {
        Ok(()) => no_content(),
        Err(error) => gateway_error(error, instance),
    }
}

/// Download an agent support bundle.
pub async fn get_agent_support_bundle(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    let query = match parse_agent_support_bundle_query(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return gateway_error(error, instance),
    };

    match service.get_agent_support_bundle(&session, &id, query).await {
        Ok(bundle) => {
            let mut response = bundle.artifact.bytes.into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&bundle.artifact.content_type)
                    .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
            );
            let filename = safe_attachment_filename(&bundle.artifact.filename);
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            );
            response
        }
        Err(error) => gateway_error(error, instance),
    }
}

/// Update agent-control scan-config defaults.
pub async fn update_agent_control_scan_config(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    let request =
        match parse_json_body_with::<ModifyAgentControlScanConfigRequest, _>(&body, |error| {
            GatewayError::InvalidInput(format!("invalid JSON body: {error}"))
        }) {
            Ok(request) => request,
            Err(error) => return gateway_error(error, instance),
        };
    let input = match request.validate_into() {
        Ok(input) => input,
        Err(error) => return gateway_error(error, instance),
    };

    match service
        .modify_agent_control_scan_config(&session, &id, input)
        .await
    {
        Ok(()) => no_content(),
        Err(error) => gateway_error(error, instance),
    }
}

/// Get agent installer instructions.
pub async fn get_agent_installer_instruction(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    let query = match parse_agent_installer_instruction_query(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return gateway_error(error, instance),
    };

    match service
        .get_agent_installer_instruction(&session, &id, query)
        .await
    {
        Ok(instruction) => ok_json(AgentInstallerInstructionResponse::from(instruction)),
        Err(error) => gateway_error(error, instance),
    }
}

/// List agent groups.
pub async fn list_agent_groups(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        parse_agent_group_query,
        |service, token, query| async move { service.list_agent_groups(&token, query).await },
        AgentGroupListResponse::from,
    )
    .await
}

/// Create an agent group.
pub async fn create_agent_group(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateAgentGroupInput, CreateAgentGroupRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, token, input| async move { service.create_agent_group(&token, input).await },
    )
    .await
}

/// Get an agent group.
pub async fn get_agent_group(
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
        |service, token, id| async move { service.get_agent_group(&token, &id).await },
        AgentGroupResponse::from,
    )
    .await
}

/// Update an agent group.
pub async fn update_agent_group(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyAgentGroupInput, ModifyAgentGroupRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, token, id, input| async move {
            service.modify_agent_group(&token, &id, input).await
        },
        AgentGroupResponse::from,
    )
    .await
}

/// Delete an agent group.
pub async fn delete_agent_group(
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
            service.delete_agent_group(&token, &id, ultimate).await
        },
    )
    .await
}

/// Clone an agent group.
pub async fn clone_agent_group(
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
        "/api/v1/agent-groups",
        |service, token, id| async move { service.clone_agent_group(&token, &id).await },
    )
    .await
}

fn list_docs<'a, T: JsonSchema + 'static>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .response_with::<200, Json<T>, _>(ok_json_docs(summary));
    let op = problem_response::<401>(
        problem_response::<400>(op, "Invalid request"),
        "Authentication required or session expired",
    );
    let op = problem_response::<501>(op, "Backend does not support this GMP 22.8 operation");
    let op = problem_response::<502>(op, "Backend service unreachable or connection failed");
    problem_response::<504>(op, "Backend request timed out")
}

fn item_docs<'a, T: JsonSchema + 'static>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<T>, _>(ok_json_docs(summary));
    let op = problem_response::<404>(
        problem_response::<401>(
            problem_response::<400>(op, "Invalid request"),
            "Authentication required or session expired",
        ),
        "Resource not found",
    );
    let op = problem_response::<501>(op, "Backend does not support this GMP 22.8 operation");
    let op = problem_response::<502>(op, "Backend service unreachable or connection failed");
    problem_response::<504>(op, "Backend request timed out")
}

fn update_docs<'a, Req: JsonSchema + 'static, Resp: JsonSchema + 'static>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<Req>)>()
        .response_with::<200, Json<Resp>, _>(ok_json_docs(summary));
    let op = problem_response::<404>(
        problem_response::<401>(
            problem_response::<400>(op, "Invalid request"),
            "Authentication required or session expired",
        ),
        "Resource not found",
    );
    let op = problem_response::<409>(op, "Resource conflict");
    let op = problem_response::<501>(op, "Backend does not support this GMP 22.8 operation");
    let op = problem_response::<502>(op, "Backend service unreachable or connection failed");
    problem_response::<504>(op, "Backend request timed out")
}

fn create_docs<'a, Req: JsonSchema + 'static>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .input::<Json<Req>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json(summary));
    let op = problem_response::<401>(
        problem_response::<400>(op, "Invalid request"),
        "Authentication required or session expired",
    );
    let op = problem_response::<409>(op, "Resource conflict");
    let op = problem_response::<501>(op, "Backend does not support this GMP 22.8 operation");
    let op = problem_response::<502>(op, "Backend service unreachable or connection failed");
    problem_response::<504>(op, "Backend request timed out")
}

fn delete_docs<'a>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
    with_ultimate: bool,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description(summary));
    let op = if with_ultimate {
        op.input::<Query<DeleteResourceQueryParams>>()
    } else {
        op
    };
    let op = problem_response::<404>(
        problem_response::<401>(
            problem_response::<400>(op, "Invalid request"),
            "Authentication required or session expired",
        ),
        "Resource not found",
    );
    let op = problem_response::<403>(op, "Deletion is forbidden");
    let op = problem_response::<409>(op, "Resource conflict");
    let op = problem_response::<501>(op, "Backend does not support this GMP 22.8 operation");
    let op = problem_response::<502>(op, "Backend service unreachable or connection failed");
    problem_response::<504>(op, "Backend request timed out")
}

fn action_no_content_docs<'a>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .response_with::<204, (), _>(|response| response.description(summary));
    let op = problem_response::<401>(
        problem_response::<400>(op, "Invalid request"),
        "Authentication required or session expired",
    );
    let op = problem_response::<501>(op, "Backend does not support this GMP 22.8 operation");
    let op = problem_response::<502>(op, "Backend service unreachable or connection failed");
    problem_response::<504>(op, "Backend request timed out")
}

fn support_bundle_response<T>(mut response: TransformResponse<T>) -> TransformResponse<T> {
    *response.inner() = serde_json::from_value(json!({
        "description": "Agent support bundle download",
        "headers": {
            "Content-Disposition": {
                "description": "Attachment-style filename for the support bundle.",
                "schema": { "type": "string" }
            }
        },
        "content": {
            "application/octet-stream": { "schema": { "type": "string", "format": "binary" } },
            "application/gzip": { "schema": { "type": "string", "format": "binary" } },
            "application/zip": { "schema": { "type": "string", "format": "binary" } }
        }
    }))
    .expect("static support-bundle response is valid");
    response
}

/// OpenAPI transform for `GET /api/v1/agents`.
pub(crate) fn list_agents_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    list_docs::<AgentListResponse>(
        op.input::<Query<AgentListQueryParams>>(),
        "getAgents",
        "Agents",
        "Paginated list of agents",
    )
}

/// OpenAPI transform for `GET /api/v1/agents/{id}`.
pub(crate) fn get_agent_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    item_docs::<AgentResponse>(op, "getAgent", "Agents", "Agent details")
}

/// OpenAPI transform for `PUT /api/v1/agents/{id}`.
pub(crate) fn modify_agent_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    update_docs::<ModifyAgentRequest, AgentResponse>(op, "modifyAgent", "Agents", "Updated agent")
}

/// OpenAPI transform for `DELETE /api/v1/agents/{id}`.
pub(crate) fn delete_agent_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    delete_docs(op, "deleteAgent", "Agents", "Agent deleted", false)
}

/// OpenAPI transform for `POST /api/v1/agents/sync`.
pub(crate) fn sync_agents_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    action_no_content_docs(op, "syncAgents", "Agents", "Agent synchronization started")
}

/// OpenAPI transform for `GET /api/v1/agents/{id}/support-bundle`.
pub(crate) fn get_agent_support_bundle_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getAgentSupportBundle")
        .tag("Agents")
        .summary("Get an agent support bundle")
        .security_requirement("bearerAuth")
        .input::<(
            Path<ResourceIdPathDoc>,
            Query<AgentSupportBundleQueryParams>,
        )>()
        .response_with::<200, Json<ResourceCreatedResponse>, _>(support_bundle_response);
    let op = problem_response::<404>(
        problem_response::<401>(
            problem_response::<400>(op, "Invalid request"),
            "Authentication required or session expired",
        ),
        "Resource not found",
    );
    let op = problem_response::<501>(op, "Backend does not support this GMP 22.8 operation");
    let op = problem_response::<502>(op, "Backend service unreachable or connection failed");
    problem_response::<504>(op, "Backend request timed out")
}

/// OpenAPI transform for `PUT /api/v1/agent-control-scan-configs/{id}`.
pub(crate) fn modify_agent_control_scan_config_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("modifyAgentControlScanConfig")
        .tag("Agents")
        .summary("Modify agent-control scan config defaults")
        .security_requirement("bearerAuth")
        .input::<(
            Path<ResourceIdPathDoc>,
            Json<ModifyAgentControlScanConfigRequest>,
        )>()
        .response_with::<204, (), _>(|response| {
            response.description("Agent-control scan config defaults updated")
        });
    let op = problem_response::<404>(
        problem_response::<401>(
            problem_response::<400>(op, "Invalid request"),
            "Authentication required or session expired",
        ),
        "Resource not found",
    );
    let op = problem_response::<501>(op, "Backend does not support this GMP 22.8 operation");
    let op = problem_response::<502>(op, "Backend service unreachable or connection failed");
    problem_response::<504>(op, "Backend request timed out")
}

/// OpenAPI transform for `GET /api/v1/scanners/{id}/agent-installer-instruction`.
pub(crate) fn get_agent_installer_instruction_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("getAgentInstallerInstruction")
        .tag("Agents")
        .summary("Get agent installer instructions")
        .security_requirement("bearerAuth")
        .input::<(
            Path<ResourceIdPathDoc>,
            Query<AgentInstallerInstructionQueryParams>,
        )>()
        .response_with::<200, Json<AgentInstallerInstructionResponse>, _>(ok_json_docs(
            "Agent installer instructions",
        ));
    let op = problem_response::<404>(
        problem_response::<401>(
            problem_response::<400>(op, "Invalid request"),
            "Authentication required or session expired",
        ),
        "Resource not found",
    );
    let op = problem_response::<501>(op, "Backend does not support this GMP 22.8 operation");
    let op = problem_response::<502>(op, "Backend service unreachable or connection failed");
    problem_response::<504>(op, "Backend request timed out")
}

/// OpenAPI transform for `GET /api/v1/agent-groups`.
pub(crate) fn list_agent_groups_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    list_docs::<AgentGroupListResponse>(
        op.input::<Query<AgentGroupListQueryParams>>(),
        "getAgentGroups",
        "Agent Groups",
        "Paginated list of agent groups",
    )
}

/// OpenAPI transform for `POST /api/v1/agent-groups`.
pub(crate) fn create_agent_group_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    create_docs::<CreateAgentGroupRequest>(
        op,
        "createAgentGroup",
        "Agent Groups",
        "Agent group created",
    )
}

/// OpenAPI transform for `GET /api/v1/agent-groups/{id}`.
pub(crate) fn get_agent_group_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    item_docs::<AgentGroupResponse>(op, "getAgentGroup", "Agent Groups", "Agent group details")
}

/// OpenAPI transform for `PUT /api/v1/agent-groups/{id}`.
pub(crate) fn modify_agent_group_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    update_docs::<ModifyAgentGroupRequest, AgentGroupResponse>(
        op,
        "modifyAgentGroup",
        "Agent Groups",
        "Updated agent group",
    )
}

/// OpenAPI transform for `DELETE /api/v1/agent-groups/{id}`.
pub(crate) fn delete_agent_group_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    delete_docs(
        op,
        "deleteAgentGroup",
        "Agent Groups",
        "Agent group deleted",
        true,
    )
}

/// OpenAPI transform for `POST /api/v1/agent-groups/{id}/clone`.
pub(crate) fn clone_agent_group_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("cloneAgentGroup")
        .tag("Agent Groups")
        .summary("Clone an agent group")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json(
            "Agent group clone created",
        ));
    let op = problem_response::<404>(
        problem_response::<401>(
            problem_response::<400>(op, "Invalid request"),
            "Authentication required or session expired",
        ),
        "Resource not found",
    );
    let op = problem_response::<409>(op, "Resource conflict");
    let op = problem_response::<501>(op, "Backend does not support this GMP 22.8 operation");
    let op = problem_response::<502>(op, "Backend service unreachable or connection failed");
    problem_response::<504>(op, "Backend request timed out")
}

#[cfg(test)]
#[path = "agents_test.rs"]
mod agents_test;
