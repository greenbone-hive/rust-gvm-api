// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Shared OpenAPI-only schema types.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

fn default_page() -> Option<u32> {
    Some(1)
}

fn default_per_page() -> Option<u32> {
    Some(25)
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ProblemDetail")]
pub(crate) struct ProblemDetailDoc {
    #[serde(rename = "type")]
    #[schemars(schema_with = "uri_schema")]
    r#type: String,
    code: String,
    title: String,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::dto::uri_reference_schema")]
    instance: Option<String>,
}

impl ProblemDetailDoc {
    pub(crate) fn example() -> Self {
        Self {
            r#type: "https://gvm-gateway.greenbone.net/errors/bad-request".to_string(),
            code: "bad_request".to_string(),
            title: "Bad Request".to_string(),
            status: 400,
            detail: Some("request validation failed".to_string()),
            instance: Some("/api/v1/targets".to_string()),
        }
    }
}

fn uri_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "format": "uri"
    })
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub(crate) struct ResourceIdPathDoc {
    id: Uuid,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct TargetListQueryDoc {
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

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateTarget")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateTargetDoc {
    name: String,
    comment: Option<String>,
    #[schemars(length(min = 1))]
    hosts: Vec<String>,
    #[serde(rename = "excludeHosts", default)]
    exclude_hosts: Vec<String>,
    #[serde(rename = "aliveTest")]
    alive_test: Option<AliveTestDoc>,
    #[serde(rename = "portListId")]
    port_list_id: Option<Uuid>,
    #[serde(rename = "reverseLookupOnly")]
    reverse_lookup_only: Option<bool>,
    #[serde(rename = "reverseLookupUnify")]
    reverse_lookup_unify: Option<bool>,
    #[serde(rename = "sshCredentialId")]
    ssh_credential_id: Option<Uuid>,
    #[serde(rename = "smbCredentialId")]
    smb_credential_id: Option<Uuid>,
    #[serde(rename = "esxiCredentialId")]
    esxi_credential_id: Option<Uuid>,
    #[serde(rename = "snmpCredentialId")]
    snmp_credential_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyTarget")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyTargetDoc {
    name: Option<String>,
    comment: Option<String>,
    hosts: Option<Vec<String>>,
    #[serde(rename = "excludeHosts")]
    exclude_hosts: Option<Vec<String>>,
    #[serde(rename = "aliveTest")]
    alive_test: Option<AliveTestDoc>,
    #[serde(rename = "portListId")]
    port_list_id: Option<Uuid>,
    #[serde(rename = "reverseLookupOnly")]
    reverse_lookup_only: Option<bool>,
    #[serde(rename = "reverseLookupUnify")]
    reverse_lookup_unify: Option<bool>,
    /// SSH credential binding. Omitted or null leaves the binding unchanged;
    /// clearing credential bindings is not supported by this request shape.
    #[serde(rename = "sshCredentialId")]
    ssh_credential_id: Option<Uuid>,
    /// SMB credential binding. Omitted or null leaves the binding unchanged;
    /// clearing credential bindings is not supported by this request shape.
    #[serde(rename = "smbCredentialId")]
    smb_credential_id: Option<Uuid>,
    /// ESXi credential binding. Omitted or null leaves the binding unchanged;
    /// clearing credential bindings is not supported by this request shape.
    #[serde(rename = "esxiCredentialId")]
    esxi_credential_id: Option<Uuid>,
    /// SNMP credential binding. Omitted or null leaves the binding unchanged;
    /// clearing credential bindings is not supported by this request shape.
    #[serde(rename = "snmpCredentialId")]
    snmp_credential_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub(crate) enum AliveTestDoc {
    #[serde(rename = "Scan Config Default")]
    ScanConfigDefault,
    #[serde(rename = "ICMP Ping")]
    IcmpPing,
    #[serde(rename = "TCP-ACK Service Ping")]
    TcpAckServicePing,
    #[serde(rename = "TCP-SYN Service Ping")]
    TcpSynServicePing,
    #[serde(rename = "ARP Ping")]
    ArpPing,
    #[serde(rename = "ICMP, TCP-ACK Service Ping")]
    IcmpTcpAckServicePing,
    #[serde(rename = "ICMP, ARP Ping")]
    IcmpArpPing,
    #[serde(rename = "TCP-ACK Service, ARP Ping")]
    TcpAckServiceArpPing,
    #[serde(rename = "ICMP, TCP-ACK Service, ARP Ping")]
    IcmpTcpAckServiceArpPing,
    #[serde(rename = "Consider Alive")]
    ConsiderAlive,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct TaskListQueryDoc {
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

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateTask")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateTaskDoc {
    name: String,
    comment: Option<String>,
    #[serde(rename = "type")]
    task_type: Option<TaskCreateTypeDoc>,
    #[serde(rename = "targetId")]
    target_id: Option<Uuid>,
    #[serde(rename = "agentGroupId")]
    agent_group_id: Option<Uuid>,
    #[serde(rename = "ociImageTargetId")]
    oci_image_target_id: Option<Uuid>,
    #[serde(rename = "webApplicationTargetId")]
    web_application_target_id: Option<Uuid>,
    #[serde(rename = "scanConfigId")]
    scan_config_id: Option<Uuid>,
    #[serde(rename = "scannerId")]
    scanner_id: Option<Uuid>,
    #[serde(rename = "scheduleId")]
    schedule_id: Option<Uuid>,
    #[serde(rename = "alertIds")]
    alert_ids: Option<Vec<Uuid>>,
    alterable: Option<bool>,
    observers: Option<Vec<String>>,
    #[serde(rename = "schedulePeriods")]
    schedule_periods: Option<u32>,
    preferences: Option<std::collections::HashMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub(crate) enum TaskCreateTypeDoc {
    #[serde(rename = "classic")]
    Classic,
    #[serde(rename = "agentGroup")]
    AgentGroup,
    #[serde(rename = "ociImage")]
    OciImage,
    #[serde(rename = "webApplication")]
    WebApplication,
    #[serde(rename = "import")]
    Import,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateAudit")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateAuditDoc {
    name: String,
    comment: Option<String>,
    #[serde(rename = "targetId")]
    target_id: Uuid,
    #[serde(rename = "scanConfigId")]
    scan_config_id: Uuid,
    #[serde(rename = "scannerId")]
    scanner_id: Uuid,
    #[serde(rename = "scheduleId")]
    schedule_id: Option<Uuid>,
    #[serde(rename = "alertIds")]
    alert_ids: Option<Vec<Uuid>>,
    alterable: Option<bool>,
    observers: Option<Vec<String>>,
    #[serde(rename = "schedulePeriods")]
    schedule_periods: Option<u32>,
    preferences: Option<std::collections::HashMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyTask")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyTaskDoc {
    name: Option<String>,
    comment: Option<String>,
    #[serde(rename = "targetId")]
    target_id: Option<Uuid>,
    #[serde(rename = "scanConfigId")]
    scan_config_id: Option<Uuid>,
    #[serde(rename = "scannerId")]
    scanner_id: Option<Uuid>,
    #[serde(rename = "scheduleId")]
    schedule_id: Option<Uuid>,
    #[serde(rename = "alertIds")]
    alert_ids: Option<Vec<Uuid>>,
    alterable: Option<bool>,
    observers: Option<Vec<String>>,
    #[serde(rename = "schedulePeriods")]
    schedule_periods: Option<u32>,
    /// Key-value scan preferences. Omitted or empty objects leave preferences
    /// unchanged; clearing preferences is not supported by this request shape.
    preferences: Option<std::collections::HashMap<String, String>>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct ReportListQueryDoc {
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
pub(crate) struct GetReportQueryDoc {
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
pub(crate) struct ReportResultsQueryDoc {
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
pub(crate) struct ResultListQueryDoc {
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
pub(crate) struct ScanConfigListQueryDoc {
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
