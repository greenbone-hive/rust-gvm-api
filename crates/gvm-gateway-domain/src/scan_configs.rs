// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Scan configuration domain types and commands.

use serde::{Deserialize, Serialize};

use crate::Pagination;

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
