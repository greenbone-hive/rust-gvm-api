// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Supporting resource catalogs used by report export, finding triage, saved
//! filters, tags, asset inventory, and NVT discovery workflows.

use serde::{Deserialize, Serialize};

use crate::{NvtRef, Pagination, ResourceRef};

/// Common query options used by supporting-resource list endpoints.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SupportingResourceQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Typed NVT catalog query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NvtQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
    /// Optional scan-config identifier used to restrict the NVT catalog.
    pub config_id: Option<String>,
    /// Optional scan-config identifier used to resolve preference values.
    pub preferences_config_id: Option<String>,
    /// Optional NVT family restriction.
    pub family: Option<String>,
    /// Whether to include NVT preferences.
    pub include_preferences: Option<bool>,
    /// Whether to include the preference count.
    pub include_preference_count: Option<bool>,
    /// Whether to include the timeout preference.
    pub include_timeout: Option<bool>,
    /// Optional backend sort order (`ascending` or `descending`).
    pub sort_order: Option<String>,
    /// Optional backend NVT sort field.
    pub sort_field: Option<String>,
}

/// Note create command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CreateNoteInput {
    /// Required NVT OID selector.
    pub nvt_oid: String,
    /// Optional note text body.
    pub text: Option<String>,
    /// Optional host selectors.
    pub hosts: Vec<String>,
    /// Optional port selector.
    pub port: Option<String>,
    /// Optional severity selector.
    pub severity: Option<String>,
    /// Optional related task identifier.
    pub task_id: Option<String>,
    /// Optional related result identifier.
    pub result_id: Option<String>,
    /// Optional active flag.
    pub active: Option<bool>,
    /// Optional orphan flag.
    pub orphan: Option<bool>,
}

/// Note update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyNoteInput {
    /// Optional note text body.
    pub text: Option<String>,
    /// Optional host selectors.
    pub hosts: Option<Vec<String>>,
    /// Optional port selector.
    pub port: Option<String>,
    /// Optional severity selector.
    pub severity: Option<String>,
    /// Optional related task identifier.
    pub task_id: Option<String>,
    /// Optional related result identifier.
    pub result_id: Option<String>,
    /// Optional active flag.
    pub active: Option<bool>,
    /// Optional orphan flag.
    pub orphan: Option<bool>,
}

/// Override create command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CreateOverrideInput {
    /// Required NVT OID selector.
    pub nvt_oid: String,
    /// Optional override text body.
    pub text: Option<String>,
    /// Optional host selectors.
    pub hosts: Vec<String>,
    /// Optional port selector.
    pub port: Option<String>,
    /// Optional matching severity selector.
    pub severity: Option<String>,
    /// Optional replacement severity selector.
    pub new_severity: Option<String>,
    /// Optional related task identifier.
    pub task_id: Option<String>,
    /// Optional related result identifier.
    pub result_id: Option<String>,
    /// Optional active flag.
    pub active: Option<bool>,
}

/// Override update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyOverrideInput {
    /// Optional override text body.
    pub text: Option<String>,
    /// Optional host selectors.
    pub hosts: Option<Vec<String>>,
    /// Optional port selector.
    pub port: Option<String>,
    /// Optional matching severity selector.
    pub severity: Option<String>,
    /// Optional replacement severity selector.
    pub new_severity: Option<String>,
    /// Optional related task identifier.
    pub task_id: Option<String>,
    /// Optional related result identifier.
    pub result_id: Option<String>,
    /// Optional active flag.
    pub active: Option<bool>,
}

/// Common metadata shared by supporting resources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SupportingResourceMeta {
    /// Resource identifier.
    pub id: String,
    /// Resource name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Optional creation timestamp.
    #[serde(rename = "creationTime", skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<String>,
    /// Optional modification timestamp.
    #[serde(rename = "modificationTime", skip_serializing_if = "Option::is_none")]
    pub modification_time: Option<String>,
    /// Whether the resource is writable.
    pub writable: bool,
    /// Whether the resource is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
}

/// Domain host (asset) representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Host {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: SupportingResourceMeta,
    /// Optional IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Optional hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Optional severity summary exposed by gvmd.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Optional detected operating system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
}

/// Paginated host list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostPage {
    /// Page items.
    pub data: Vec<Host>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Host reference nested under an operating-system asset.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatingSystemHost {
    /// Host identifier.
    pub id: String,
    /// Host display name.
    pub name: String,
    /// Optional host severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

/// Domain operating-system asset representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatingSystem {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: SupportingResourceMeta,
    /// Optional backend OS value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Optional backend hosts count alias.
    #[serde(rename = "hostsCount", skip_serializing_if = "Option::is_none")]
    pub hosts_count: Option<u32>,
    /// Optional backend severity summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Backend title.
    pub title: String,
    /// Backend installs count.
    pub installs: u32,
    /// Backend all-installs count.
    #[serde(rename = "allInstalls")]
    pub all_installs: u32,
    /// Optional latest severity.
    #[serde(rename = "latestSeverity", skip_serializing_if = "Option::is_none")]
    pub latest_severity: Option<String>,
    /// Optional highest severity.
    #[serde(rename = "highestSeverity", skip_serializing_if = "Option::is_none")]
    pub highest_severity: Option<String>,
    /// Optional average severity.
    #[serde(rename = "averageSeverity", skip_serializing_if = "Option::is_none")]
    pub average_severity: Option<String>,
    /// Backend host count.
    #[serde(rename = "hostCount")]
    pub host_count: u32,
    /// Related hosts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<OperatingSystemHost>,
}

/// Paginated operating-system asset list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatingSystemPage {
    /// Page items.
    pub data: Vec<OperatingSystem>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain representation of a TLS certificate asset.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlsCertificateAsset {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: SupportingResourceMeta,
    /// Optional subject distinguished name.
    #[serde(rename = "subjectDn", skip_serializing_if = "Option::is_none")]
    pub subject_dn: Option<String>,
    /// Optional issuer distinguished name.
    #[serde(rename = "issuerDn", skip_serializing_if = "Option::is_none")]
    pub issuer_dn: Option<String>,
    /// Optional activation timestamp.
    #[serde(rename = "activationTime", skip_serializing_if = "Option::is_none")]
    pub activation_time: Option<String>,
    /// Optional expiration timestamp.
    #[serde(rename = "expirationTime", skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    /// Optional MD5 fingerprint.
    #[serde(rename = "md5Fingerprint", skip_serializing_if = "Option::is_none")]
    pub md5_fingerprint: Option<String>,
    /// Optional SHA-256 fingerprint.
    #[serde(rename = "sha256Fingerprint", skip_serializing_if = "Option::is_none")]
    pub sha256_fingerprint: Option<String>,
    /// Optional PEM-encoded certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// Whether the certificate is currently valid per gvmd.
    pub valid: bool,
}

/// Paginated TLS certificate asset list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlsCertificateAssetPage {
    /// Page items.
    pub data: Vec<TlsCertificateAsset>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain report-format representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportFormat {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: SupportingResourceMeta,
    /// MIME content type when known.
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// File extension when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    /// Optional human-readable summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Trust indicator when exposed by gvmd.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
    /// Whether the report format is active.
    pub active: bool,
    /// Whether the report format is predefined by the backend.
    pub predefined: bool,
}

/// Paginated report-format list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportFormatPage {
    /// Page items.
    pub data: Vec<ReportFormat>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain NVT representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Nvt {
    /// NVT OID.
    pub oid: String,
    /// NVT name.
    pub name: String,
    /// Optional NVT family.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Optional CVSS base score.
    #[serde(rename = "cvssBase", skip_serializing_if = "Option::is_none")]
    pub cvss_base: Option<f64>,
    /// Optional severity score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<f64>,
    /// Optional NVT tags payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    /// Optional solution type.
    #[serde(rename = "solutionType", skip_serializing_if = "Option::is_none")]
    pub solution_type: Option<String>,
}

/// Paginated NVT list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NvtPage {
    /// Page items.
    pub data: Vec<Nvt>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain vulnerability (SecInfo) summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Vulnerability {
    /// Vulnerability identifier (NVT OID).
    pub id: String,
    /// Vulnerability name.
    pub name: String,
}

/// Paginated vulnerability list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VulnerabilityPage {
    /// Page items.
    pub data: Vec<Vulnerability>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain CVE summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Cve {
    /// CVE identifier.
    pub id: String,
    /// CVE name.
    pub name: String,
}

/// Paginated CVE list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CvePage {
    /// Page items.
    pub data: Vec<Cve>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain CPE summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Cpe {
    /// CPE identifier.
    pub id: String,
    /// CPE name.
    pub name: String,
}

/// Paginated CPE list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CpePage {
    /// Page items.
    pub data: Vec<Cpe>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain CERT-Bund advisory summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertBundAdvisory {
    /// CERT-Bund advisory identifier.
    pub id: String,
    /// CERT-Bund advisory name.
    pub name: String,
}

/// Paginated CERT-Bund advisory list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertBundAdvisoryPage {
    /// Page items.
    pub data: Vec<CertBundAdvisory>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain DFN-CERT advisory summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DfnCertAdvisory {
    /// DFN-CERT advisory identifier.
    pub id: String,
    /// DFN-CERT advisory name.
    pub name: String,
}

/// Paginated DFN-CERT advisory list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DfnCertAdvisoryPage {
    /// Page items.
    pub data: Vec<DfnCertAdvisory>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain NVT family representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NvtFamily {
    /// Family name.
    pub name: String,
    /// Optional maximum NVT count exposed by gvmd.
    #[serde(rename = "maxNvtCount", skip_serializing_if = "Option::is_none")]
    pub max_nvt_count: Option<u32>,
}

/// Paginated NVT family list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NvtFamilyPage {
    /// Page items.
    pub data: Vec<NvtFamily>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain saved-filter representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Filter {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: SupportingResourceMeta,
    /// Optional resource type the filter targets.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub filter_type: Option<String>,
    /// Optional filter term.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
}

/// Paginated filter list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FilterPage {
    /// Page items.
    pub data: Vec<Filter>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain tag representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Tag {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: SupportingResourceMeta,
    /// Optional tag value payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Optional resource kind associated with the tag.
    #[serde(rename = "resourceType", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    /// Optional number of matching resources.
    #[serde(rename = "resourceCount", skip_serializing_if = "Option::is_none")]
    pub resource_count: Option<u32>,
    /// Whether the tag is active.
    pub active: bool,
}

/// Paginated tag list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TagPage {
    /// Page items.
    pub data: Vec<Tag>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Filter create command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CreateFilterInput {
    /// Required filter name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional GMP filter term expression.
    pub term: Option<String>,
    /// Optional resource type the filter applies to.
    pub filter_type: Option<String>,
}

/// Filter update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyFilterInput {
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional GMP filter term expression.
    pub term: Option<String>,
    /// Optional resource type the filter applies to.
    pub filter_type: Option<String>,
}

/// Tag create command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CreateTagInput {
    /// Required tag name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional free-form value payload.
    pub value: Option<String>,
    /// Optional related resource type.
    pub resource_type: Option<String>,
    /// Optional related resource identifier.
    pub resource_id: Option<String>,
    /// Whether the tag should be active.
    pub active: Option<bool>,
}

/// Tag update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyTagInput {
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional free-form value payload.
    pub value: Option<String>,
    /// Optional related resource type.
    pub resource_type: Option<String>,
    /// Optional related resource identifier.
    pub resource_id: Option<String>,
    /// Whether the tag should be active.
    pub active: Option<bool>,
}

/// Host asset create command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CreateHostInput {
    /// Host name or IP address.
    pub value: String,
    /// Optional comment.
    pub comment: Option<String>,
}

/// Host asset update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyHostInput {
    /// Optional comment.
    ///
    /// The gvmd `modify_asset` command does not update a host asset's name/IP
    /// value, so this input intentionally carries no `value`: a host's
    /// identity cannot be edited and callers must not be able to request it.
    pub comment: Option<String>,
}

/// Operating-system asset update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyOperatingSystemInput {
    /// Optional comment.
    ///
    /// The pinned gvmd operating-system asset update surface only accepts a
    /// comment payload, so this input intentionally carries no other fields.
    pub comment: Option<String>,
}

/// Domain note representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Note {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: SupportingResourceMeta,
    /// Optional note text body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Optional related NVT selector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvt: Option<NvtRef>,
    /// Optional host selectors associated with the note.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Optional port selector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// Optional matching severity selector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Optional related task reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<ResourceRef>,
    /// Optional related result reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResourceRef>,
    /// Whether the note is active.
    pub active: bool,
    /// Optional note expiry timestamp.
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
}

/// Paginated note list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NotePage {
    /// Page items.
    pub data: Vec<Note>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Domain override representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Override {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: SupportingResourceMeta,
    /// Optional override text body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Optional related NVT selector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvt: Option<NvtRef>,
    /// Optional host selectors associated with the override.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Optional port selector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// Optional matching severity selector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Optional replacement severity.
    #[serde(rename = "newSeverity", skip_serializing_if = "Option::is_none")]
    pub new_severity: Option<String>,
    /// Optional related task reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<ResourceRef>,
    /// Optional related result reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResourceRef>,
    /// Whether the override is active.
    pub active: bool,
    /// Optional override expiry timestamp.
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
}

/// Paginated override list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct OverridePage {
    /// Page items.
    pub data: Vec<Override>,
    /// Pagination metadata.
    pub pagination: Pagination,
}
