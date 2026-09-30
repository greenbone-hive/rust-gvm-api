// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Report domain types and query options.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Pagination, ResourceRef, ScanResult};

/// Request to import one opaque report envelope into an existing import task.
#[derive(Clone, Eq, PartialEq)]
pub struct ImportReportInput {
    /// Existing import-task identifier.
    pub task_id: String,
    /// Original report envelope bytes, interpreted only by the typed GMP layer.
    pub report_xml: Vec<u8>,
    /// Whether report hosts should be added to assets; omission preserves the
    /// backend default and is distinct from explicit `false`.
    pub in_assets: Option<bool>,
}

impl fmt::Debug for ImportReportInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportReportInput")
            .field("task_id", &self.task_id)
            .field("report_xml", &"<redacted>")
            .field("in_assets", &self.in_assets)
            .finish()
    }
}

/// Aggregate vulnerability finding returned by a report drill-down.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReportVulnerability {
    /// Backend row identifier when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// NVT identity and metadata emitted for the aggregate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvt: Option<crate::NvtRef>,
    /// Singular host when the backend returns one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Singular port when the backend returns one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// Backend threat classification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    /// Numeric severity emitted by the backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<f64>,
    /// Number of distinct hosts represented by the aggregate.
    #[serde(rename = "hostsCount", skip_serializing_if = "Option::is_none")]
    pub hosts_count: Option<u32>,
    /// Number of result occurrences represented by the aggregate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrences: Option<u32>,
}

/// Paginated aggregate vulnerability response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReportVulnerabilityPage {
    /// Page items.
    pub data: Vec<ReportVulnerability>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Error emitted while a report was being produced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportError {
    /// Backend row identifier when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Backend error label when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Host associated with the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Port associated with the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// Backend error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// NVT name reported as the source of the error.
    #[serde(rename = "nvtName", skip_serializing_if = "Option::is_none")]
    pub nvt_name: Option<String>,
}

/// Paginated report-error response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportErrorPage {
    /// Page items.
    pub data: Vec<ReportError>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Host summary returned by a report drill-down.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportHost {
    /// Backend row identifier when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Backend host label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Backend severity summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

/// Paginated report-host response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportHostPage {
    /// Page items.
    pub data: Vec<ReportHost>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Closed-CVE finding returned by a report drill-down.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReportClosedCve {
    /// Backend row identifier when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// NVT identity emitted for the closed CVE.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvt: Option<crate::NvtRef>,
    /// Closed CVE identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    /// Host associated with the closed CVE.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Numeric severity emitted by the backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<f64>,
    /// Backend threat classification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
}

/// Paginated closed-CVE response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReportClosedCvePage {
    /// Page items.
    pub data: Vec<ReportClosedCve>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Port summary returned by a report drill-down.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportPortSummary {
    /// Backend row identifier when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Backend port label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Backend severity summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

/// Paginated report-port response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportPortPage {
    /// Page items.
    pub data: Vec<ReportPortSummary>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Application summary returned by a report drill-down.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportApplication {
    /// Backend row identifier when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Backend application label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Backend severity summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

/// Paginated report-application response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportApplicationPage {
    /// Page items.
    pub data: Vec<ReportApplication>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Operating-system summary returned by a report drill-down.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportOperatingSystem {
    /// Best matching operating-system CPE reported by gvmd.
    #[serde(rename = "bestOsCpe", skip_serializing_if = "Option::is_none")]
    pub best_os_cpe: Option<String>,
    /// Human-readable best matching operating-system text reported by gvmd.
    #[serde(rename = "bestOsText", skip_serializing_if = "Option::is_none")]
    pub best_os_text: Option<String>,
    /// Number of report hosts with this best operating-system match.
    #[serde(rename = "hostsCount", skip_serializing_if = "Option::is_none")]
    pub hosts_count: Option<u32>,
}

/// Paginated report-operating-system response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportOperatingSystemPage {
    /// Page items.
    pub data: Vec<ReportOperatingSystem>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// CVE summary returned by a report drill-down.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportCve {
    /// Backend row identifier when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Backend CVE label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Backend severity summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

/// Paginated report-CVE response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportCvePage {
    /// Page items.
    pub data: Vec<ReportCve>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain report representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Report {
    /// Report identifier.
    pub id: String,
    /// Associated task reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<ResourceRef>,
    /// Scan start timestamp.
    #[serde(rename = "scanStart", skip_serializing_if = "Option::is_none")]
    pub scan_start: Option<String>,
    /// Scan end timestamp.
    #[serde(rename = "scanEnd", skip_serializing_if = "Option::is_none")]
    pub scan_end: Option<String>,
    /// Highest severity found in the report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<f64>,
    /// Result counts by severity category.
    #[serde(rename = "resultCount", skip_serializing_if = "Option::is_none")]
    pub result_count: Option<ResultCount>,
    /// Embedded results (when fetching a single report).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<ScanResult>,
}

/// Result counts by severity category for a report.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResultCount {
    /// Total number of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
    /// Number of high-severity results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high: Option<u32>,
    /// Number of medium-severity results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub medium: Option<u32>,
    /// Number of low-severity results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub low: Option<u32>,
    /// Number of log-level results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<u32>,
    /// Number of debug-level results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<u32>,
    /// Number of false-positive results.
    #[serde(rename = "falsePositive", skip_serializing_if = "Option::is_none")]
    pub false_positive: Option<u32>,
}

/// Paginated report list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReportPage {
    /// Page items.
    pub data: Vec<Report>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Exported report artifact for download-style responses.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportExport {
    /// Rendered report bytes in the selected report format.
    pub bytes: Vec<u8>,
    /// Content type reported by the backend when available.
    pub content_type: Option<String>,
    /// File extension reported by the backend when available.
    pub extension: Option<String>,
}

/// Options for exporting a report through a backend report format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportExportRequest {
    /// UUID of the report format used by gvmd.
    pub report_format_id: String,
    /// Optional report configuration identifier.
    pub report_config_id: Option<String>,
    /// Optional GMP result filter expression.
    pub filter: Option<String>,
    /// Optional saved result filter identifier.
    pub filter_id: Option<String>,
}

/// TLS certificate observation associated with a report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlsCertificate {
    /// Backend certificate or observation identifier when available.
    pub id: Option<String>,
    /// Host associated with the certificate.
    pub host: Option<String>,
    /// Port associated with the certificate.
    pub port: Option<String>,
    /// Subject distinguished name or other primary label.
    pub subject: String,
    /// Optional issuer distinguished name.
    pub issuer: Option<String>,
    /// Optional certificate activation timestamp.
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Optional certificate expiration timestamp.
    #[serde(rename = "notAfter", skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Optional SHA-256 fingerprint.
    #[serde(rename = "fingerprintSha256", skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<String>,
}

/// Paginated TLS certificate list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlsCertificatePage {
    /// Page items.
    pub data: Vec<TlsCertificate>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Report list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReportQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Options for fetching a single report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetReportOpts {
    /// Requested embedded-result page number.
    pub page: u32,
    /// Requested embedded-result page size.
    pub per_page: u32,
}

impl Default for GetReportOpts {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 25,
        }
    }
}

#[cfg(test)]
#[path = "reports_test.rs"]
mod reports_test;
