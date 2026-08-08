// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Result domain types and query options.

use serde::{Deserialize, Serialize};

use crate::{Pagination, ResourceRef};

/// Domain scan result representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ScanResult {
    /// Result identifier.
    pub id: String,
    /// NVT name.
    pub name: String,
    /// Target host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Target port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// Severity score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<f64>,
    /// Threat level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    /// NVT reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvt: Option<NvtRef>,
    /// Result description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Associated task reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<ResourceRef>,
    /// Associated report reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ResourceRef>,
    /// Number of distinct hosts represented by an aggregate vulnerability.
    #[serde(rename = "hostsCount", skip_serializing_if = "Option::is_none")]
    pub hosts_count: Option<u32>,
    /// Number of result occurrences represented by an aggregate vulnerability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrences: Option<u32>,
}

/// NVT (Network Vulnerability Test) reference.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NvtRef {
    /// NVT OID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    /// NVT name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// NVT family.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// CVSS base score.
    #[serde(rename = "cvssBase", skip_serializing_if = "Option::is_none")]
    pub cvss_base: Option<f64>,
    /// CVE identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cves: Vec<String>,
    /// NVT tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
}

/// Paginated result list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResultPage {
    /// Page items.
    pub data: Vec<ScanResult>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Result list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResultQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}
