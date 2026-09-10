// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Scan configuration domain types and commands.

use serde::{Deserialize, Serialize};

use crate::{Nvt, Pagination};

/// Domain scan configuration representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanConfig {
    /// Scan config identifier.
    pub id: String,
    /// Scan config name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Number of NVT families selected.
    #[serde(rename = "familyCount", skip_serializing_if = "Option::is_none")]
    pub family_count: Option<u32>,
    /// Number of NVTs selected.
    #[serde(rename = "nvtCount", skip_serializing_if = "Option::is_none")]
    pub nvt_count: Option<u32>,
    /// Config type (0 = standard OpenVAS config, 1 = OSP config).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub config_type: Option<u32>,
    /// Backend usage-type discriminator (`scan` or `policy`).
    ///
    /// Exposed so clients can distinguish compliance policies from ordinary
    /// scan configs in the combined `GET /scan-configs` collection, which lists
    /// both because gvmd's `get_configs` is not usage-scoped at the pinned
    /// revision.
    #[serde(rename = "usageType", skip_serializing_if = "Option::is_none")]
    pub usage_type: Option<String>,
    /// Whether the scan config is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the scan config is writable.
    pub writable: bool,
}

/// Paginated scan config list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanConfigPage {
    /// Page items.
    pub data: Vec<ScanConfig>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Scan config list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanConfigQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Scan config create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateScanConfigInput {
    /// Name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional base scan config identifier to copy from.
    pub base_scan_config_id: Option<String>,
}

/// Scan config update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyScanConfigInput {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
}

/// Query options for NVTs selected by a scan configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanConfigNvtQuery {
    /// Optional NVT family restriction.
    pub family: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// NVTs selected by a scan configuration.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ScanConfigNvtPage {
    /// Selected NVTs.
    pub data: Vec<Nvt>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// NVT reference attached to a scan-config preference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanConfigPreferenceNvt {
    /// NVT OID.
    pub oid: String,
    /// Optional NVT display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Scanner or NVT preference resolved for a scan configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanConfigPreference {
    /// Optional associated NVT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvt: Option<ScanConfigPreferenceNvt>,
    /// Preference name.
    pub name: String,
    /// Optional backend preference identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Optional preference type.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub preference_type: Option<String>,
    /// Configured value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Allowed alternative values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<String>,
    /// Optional default value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

/// Query options for scan-config preferences.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanConfigPreferenceQuery {
    /// Optional NVT OID restriction; omission selects scanner preferences.
    pub nvt_oid: Option<String>,
}

/// Family selection entry applied atomically to a scan configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanConfigFamilySelection {
    /// NVT family name.
    pub name: String,
    /// Whether new NVTs should be selected automatically.
    pub growing: bool,
    /// Whether all current NVTs in the family are selected.
    pub all: bool,
}

/// Atomic family-selection update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetScanConfigFamilySelectionInput {
    /// Family entries.
    pub families: Vec<ScanConfigFamilySelection>,
    /// Whether newly discovered families should be selected automatically.
    pub auto_add_new_families: bool,
}
