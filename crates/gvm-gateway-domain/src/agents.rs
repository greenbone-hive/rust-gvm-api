// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Agent and agent-group domain contracts.

use serde::{Deserialize, Serialize};

use crate::{JobArtifact, Pagination, ResourceRef, SupportingResourceMeta};

/// Query shared by agent collections.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentQuery {
    /// Optional inline GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Query shared by agent-group collections.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentGroupQuery {
    /// Optional inline GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Whether to list trashed agent groups.
    pub trash: bool,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Agent representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Agent {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: SupportingResourceMeta,
    /// Whether the agent is authorized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized: Option<bool>,
    /// Whether the agent should update to the latest version.
    #[serde(rename = "updateToLatest", skip_serializing_if = "Option::is_none")]
    pub update_to_latest: Option<bool>,
    /// Backend-reported status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Backend-reported version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Last update timestamp.
    #[serde(rename = "lastUpdateTime", skip_serializing_if = "Option::is_none")]
    pub last_update_time: Option<String>,
    /// Last contact timestamp.
    #[serde(rename = "lastContactTime", skip_serializing_if = "Option::is_none")]
    pub last_contact_time: Option<String>,
    /// Related scanner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner: Option<ResourceRef>,
    /// Optional nested configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<AgentConfig>,
}

/// Paginated agent list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentPage {
    /// Page items.
    pub data: Vec<Agent>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Agent configuration.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentConfig {
    /// Agent-control settings.
    #[serde(rename = "agentControl", skip_serializing_if = "Option::is_none")]
    pub agent_control: Option<AgentControlConfig>,
    /// Agent script executor settings.
    #[serde(
        rename = "agentScriptExecutor",
        skip_serializing_if = "Option::is_none"
    )]
    pub agent_script_executor: Option<AgentScriptExecutorConfig>,
    /// Heartbeat settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<AgentHeartbeatConfig>,
}

/// Agent-control settings.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentControlConfig {
    /// Retry settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<AgentRetryConfig>,
}

/// Agent retry settings.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentRetryConfig {
    /// Number of retry attempts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
    /// Delay between attempts.
    #[serde(rename = "delayInSeconds", skip_serializing_if = "Option::is_none")]
    pub delay_in_seconds: Option<u32>,
    /// Maximum jitter.
    #[serde(rename = "maxJitterInSeconds", skip_serializing_if = "Option::is_none")]
    pub max_jitter_in_seconds: Option<u32>,
}

/// Agent script-executor settings.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentScriptExecutorConfig {
    /// Bulk size.
    #[serde(rename = "bulkSize", skip_serializing_if = "Option::is_none")]
    pub bulk_size: Option<u32>,
    /// Bulk throttle time in milliseconds.
    #[serde(
        rename = "bulkThrottleTimeInMs",
        skip_serializing_if = "Option::is_none"
    )]
    pub bulk_throttle_time_in_ms: Option<u32>,
    /// Indexer directory depth.
    #[serde(rename = "indexerDirDepth", skip_serializing_if = "Option::is_none")]
    pub indexer_dir_depth: Option<u32>,
    /// Scheduler cron expressions.
    #[serde(
        rename = "schedulerCronTime",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub scheduler_cron_time: Vec<String>,
}

/// Agent heartbeat settings.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentHeartbeatConfig {
    /// Heartbeat interval in seconds.
    #[serde(rename = "intervalInSeconds", skip_serializing_if = "Option::is_none")]
    pub interval_in_seconds: Option<u32>,
    /// Missed heartbeat count before inactive.
    #[serde(rename = "missUntilInactive", skip_serializing_if = "Option::is_none")]
    pub miss_until_inactive: Option<u32>,
}

/// Agent modification input.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyAgentInput {
    /// Whether the agent is authorized.
    pub authorized: Option<bool>,
    /// Whether the agent should update to the latest version.
    pub update_to_latest: Option<bool>,
    /// Optional comment update.
    pub comment: Option<String>,
    /// Optional configuration update.
    pub config: Option<AgentConfig>,
}

/// Agent-control scan-config modification input.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyAgentControlScanConfigInput {
    /// Default agent settings.
    pub agent_defaults: Option<AgentConfig>,
    /// Default update-to-latest setting for controlled agents.
    pub update_to_latest: Option<bool>,
}

/// Agent installer instructions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentInstallerInstruction {
    /// Selected language.
    pub language: String,
    /// Installer instruction body.
    pub instruction: String,
}

/// Installer-instruction request query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentInstallerInstructionQuery {
    /// Selected language code.
    pub language: String,
    /// Manager origin URL embedded in the instruction text.
    pub origin_url: String,
}

/// Support-bundle request query.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentSupportBundleQuery {
    /// Optional day range requested from the backend.
    pub days: Option<u32>,
    /// Optional backend encryption selector; omission is distinct from false.
    pub encryption: Option<bool>,
}

/// Binary agent support bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentSupportBundle {
    /// Suggested download artifact.
    pub artifact: JobArtifact,
    /// Backend-reported size before download when present.
    pub size: Option<u64>,
    /// Backend-reported encoding metadata when present.
    pub encoding: Option<String>,
}

/// Agent group representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentGroup {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: SupportingResourceMeta,
    /// Scheduler cron time.
    #[serde(rename = "schedulerCronTime", skip_serializing_if = "Option::is_none")]
    pub scheduler_cron_time: Option<String>,
    /// Agents in the group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<ResourceRef>,
}

/// Paginated agent-group list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentGroupPage {
    /// Page items.
    pub data: Vec<AgentGroup>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Agent-group creation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateAgentGroupInput {
    /// Display name.
    pub name: String,
    /// Scheduler cron time.
    pub scheduler_cron_time: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Included agent identifiers.
    pub agent_ids: Vec<String>,
}

/// Agent-group modification input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifyAgentGroupInput {
    /// Scheduler cron time.
    pub scheduler_cron_time: String,
    /// Optional name replacement.
    pub name: Option<String>,
    /// Optional comment replacement.
    pub comment: Option<String>,
    /// Optional agent membership replacement.
    pub agent_ids: Option<Vec<String>>,
}
