// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Task domain types and commands.

use serde::{Deserialize, Serialize};

use crate::{Pagination, ResourceRef};

/// Severity counts attached to a task's latest report reference.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskReportResultCount {
    /// Critical finding count.
    pub critical: Option<u32>,
    /// High finding count.
    pub high: Option<u32>,
    /// Medium finding count.
    pub medium: Option<u32>,
    /// Low finding count.
    pub low: Option<u32>,
    /// Log finding count.
    pub log: Option<u32>,
    /// False-positive count.
    #[serde(rename = "falsePositive")]
    pub false_positive: Option<u32>,
}

/// Compliance counts attached to an audit task's latest report reference.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskReportComplianceCount {
    /// Compliant result count.
    pub yes: Option<u32>,
    /// Non-compliant result count.
    pub no: Option<u32>,
    /// Incomplete result count.
    pub incomplete: Option<u32>,
}

/// Purpose-shaped task report reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskReportReference {
    /// Report identifier.
    pub id: String,
    /// Backend report timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Scan start timestamp.
    #[serde(rename = "scanStart", skip_serializing_if = "Option::is_none")]
    pub scan_start: Option<String>,
    /// Scan end timestamp.
    #[serde(rename = "scanEnd", skip_serializing_if = "Option::is_none")]
    pub scan_end: Option<String>,
    /// Latest report result counts when supplied for this reference.
    #[serde(rename = "resultCount", skip_serializing_if = "Option::is_none")]
    pub result_count: Option<TaskReportResultCount>,
    /// Latest report severity when supplied for this reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Latest audit compliance counts when supplied for this reference.
    #[serde(rename = "complianceCount", skip_serializing_if = "Option::is_none")]
    pub compliance_count: Option<TaskReportComplianceCount>,
}

/// Observer principals associated with a task.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskObservers {
    /// Observer user names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
    /// Observer group references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<ResourceRef>,
    /// Observer role references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<ResourceRef>,
}

impl TaskObservers {
    /// Whether no observer principals are present.
    pub fn is_empty(&self) -> bool {
        self.users.is_empty() && self.groups.is_empty() && self.roles.is_empty()
    }
}

/// Domain task representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Task {
    /// Task identifier.
    pub id: String,
    /// Task name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Task status.
    pub status: String,
    /// Task progress percentage reported by gvmd.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<i32>,
    /// Target reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<ResourceRef>,
    /// Agent group reference for agent-group scan tasks.
    #[serde(rename = "agentGroup", skip_serializing_if = "Option::is_none")]
    pub agent_group: Option<ResourceRef>,
    /// OCI image target reference for container-image scan tasks.
    #[serde(rename = "ociImageTarget", skip_serializing_if = "Option::is_none")]
    pub oci_image_target: Option<ResourceRef>,
    /// Web application target reference for web scan tasks.
    #[serde(
        rename = "webApplicationTarget",
        skip_serializing_if = "Option::is_none"
    )]
    pub web_application_target: Option<ResourceRef>,
    /// Scan configuration reference.
    #[serde(rename = "scanConfig", skip_serializing_if = "Option::is_none")]
    pub scan_config: Option<ResourceRef>,
    /// Scanner reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner: Option<ResourceRef>,
    /// Schedule reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<ResourceRef>,
    /// Alert references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alerts: Vec<ResourceRef>,
    /// Whether the task is alterable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alterable: Option<bool>,
    /// Hosts ordering strategy.
    #[serde(rename = "hostsOrdering", skip_serializing_if = "Option::is_none")]
    pub hosts_ordering: Option<String>,
    /// Observer principals.
    #[serde(default, skip_serializing_if = "TaskObservers::is_empty")]
    pub observers: TaskObservers,
    /// Number of schedule periods.
    #[serde(rename = "schedulePeriods", skip_serializing_if = "Option::is_none")]
    pub schedule_periods: Option<u32>,
    /// Last report reference.
    #[serde(rename = "lastReport", skip_serializing_if = "Option::is_none")]
    pub last_report: Option<TaskReportReference>,
    /// Current (in-progress) report reference.
    #[serde(rename = "currentReport", skip_serializing_if = "Option::is_none")]
    pub current_report: Option<TaskReportReference>,
    /// Number of reports associated with the task.
    #[serde(rename = "reportCount", skip_serializing_if = "Option::is_none")]
    pub report_count: Option<u32>,
    /// Backend task usage discriminator, such as `scan` or `audit`.
    #[serde(rename = "usageType", skip_serializing_if = "Option::is_none")]
    pub usage_type: Option<String>,
    /// Backend task trend value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trend: Option<String>,
    /// Whether the task is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the task is writable.
    pub writable: bool,
}

/// Paginated task list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskPage {
    /// Page items.
    pub data: Vec<Task>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Task list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Target selector for a task create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateTaskTarget {
    /// Classic target plus scan configuration and scanner.
    Classic {
        /// Classic target identifier.
        target_id: String,
        /// Scan configuration identifier.
        scan_config_id: String,
        /// Scanner identifier.
        scanner_id: String,
    },
    /// Agent-group scan task.
    AgentGroup {
        /// Agent-group identifier.
        agent_group_id: String,
        /// Scanner identifier.
        scanner_id: String,
    },
    /// OCI image scan task.
    OciImage {
        /// OCI image target identifier.
        oci_image_target_id: String,
        /// Scanner identifier.
        scanner_id: String,
    },
    /// Web application scan task.
    WebApplication {
        /// Web application target identifier.
        web_application_target_id: String,
        /// Scanner identifier.
        scanner_id: String,
    },
    /// Import-only task used as the owner for imported reports.
    Import,
}

/// Task create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateTaskInput {
    /// Task name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Exactly one validated task target variant.
    pub target: CreateTaskTarget,
    /// Optional schedule identifier.
    pub schedule_id: Option<String>,
    /// Optional alert identifiers.
    pub alert_ids: Vec<String>,
    /// Optional alterable flag.
    pub alterable: Option<bool>,
    /// Optional observers.
    pub observers: Vec<String>,
    /// Optional schedule periods.
    pub schedule_periods: Option<u32>,
    /// Optional key-value scan preferences.
    pub preferences: Vec<(String, String)>,
}

/// Task update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyTaskInput {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional target identifier.
    pub target_id: Option<String>,
    /// Optional scan config identifier.
    pub scan_config_id: Option<String>,
    /// Optional scanner identifier.
    pub scanner_id: Option<String>,
    /// Optional schedule identifier.
    pub schedule_id: Option<String>,
    /// Optional alert identifiers.
    pub alert_ids: Option<Vec<String>>,
    /// Optional alterable flag.
    pub alterable: Option<bool>,
    /// Optional observers.
    pub observers: Vec<String>,
    /// Optional schedule periods.
    pub schedule_periods: Option<u32>,
    /// Optional key-value scan preferences.
    pub preferences: Vec<(String, String)>,
}

/// Result from a start or resume task action containing the report identifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskAction {
    /// UUID of the report created by the action.
    #[serde(rename = "reportId")]
    pub report_id: String,
}
