// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReadinessResponse {
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct VersionResponse {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    #[serde(rename = "gmpVersion")]
    pub gmp_version: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProblemResponse {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub code: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub instance: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SessionResponse {
    #[serde(rename = "sessionToken")]
    pub token: String,
    #[serde(rename = "expiresIn")]
    pub expires_in: u64,
    #[serde(rename = "gmpVersion")]
    pub gmp_version: String,
}

#[derive(Clone, Debug)]
pub struct CreatedSession {
    pub session: SessionResponse,
    pub location: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SessionInfo {
    pub user: String,
    pub state: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "lastUsedAt")]
    pub last_used_at: String,
    #[serde(rename = "expiresIn")]
    pub expires_in: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResourceRef {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResourceCreated {
    pub id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UnpaginatedListResponse<T> {
    pub data: Vec<T>,
}

#[derive(Clone, Debug)]
pub struct CreatedResource {
    pub id: String,
    pub location: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Pagination {
    pub page: u32,
    #[serde(rename = "perPage")]
    pub per_page: u32,
    pub total: u32,
    #[serde(rename = "totalPages")]
    pub total_pages: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListResponse<T> {
    pub data: Vec<T>,
    pub pagination: Pagination,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ScanConfig {
    pub id: String,
    pub name: String,
    pub comment: Option<String>,
    #[serde(rename = "usageType")]
    pub usage_type: Option<String>,
    #[serde(rename = "inUse")]
    pub in_use: Option<bool>,
    pub writable: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Scanner {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub scanner_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PortList {
    pub id: String,
    pub name: String,
    pub comment: Option<String>,
    #[serde(rename = "portCount")]
    pub port_count: Option<u32>,
    #[serde(rename = "tcpCount")]
    pub tcp_count: Option<u32>,
    #[serde(rename = "udpCount")]
    pub udp_count: Option<u32>,
    #[serde(rename = "inUse")]
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Feed {
    #[serde(rename = "type")]
    pub feed_type: String,
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "currentlySyncing")]
    pub currently_syncing: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReportFormat {
    pub id: String,
    pub name: String,
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    pub extension: Option<String>,
    pub summary: Option<String>,
    pub trust: Option<String>,
    pub active: bool,
    pub predefined: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FilterResource {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub filter_type: Option<String>,
    pub term: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HostResource {
    pub id: String,
    pub name: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub severity: Option<String>,
    pub os: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TagResource {
    pub id: String,
    pub name: String,
    pub value: Option<String>,
    #[serde(rename = "resourceType")]
    pub resource_type: Option<String>,
    #[serde(rename = "resourceCount")]
    pub resource_count: Option<u32>,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Ticket {
    pub id: String,
    pub name: String,
    pub status: Option<String>,
    #[serde(rename = "assignedTo")]
    pub assigned_to: Option<ResourceRef>,
    pub result: Option<ResourceRef>,
    pub task: Option<ResourceRef>,
    #[serde(rename = "openNote")]
    pub open_note: Option<String>,
    #[serde(rename = "fixedNote")]
    pub fixed_note: Option<String>,
    #[serde(rename = "closedNote")]
    pub closed_note: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NoteResource {
    pub id: String,
    pub name: String,
    pub text: Option<String>,
    pub nvt: Option<NvtRef>,
    #[serde(default)]
    pub hosts: Vec<String>,
    pub port: Option<String>,
    pub severity: Option<String>,
    pub task: Option<ResourceRef>,
    pub result: Option<ResourceRef>,
    pub active: bool,
    #[serde(rename = "endTime")]
    pub end_time: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OverrideResource {
    pub id: String,
    pub name: String,
    pub text: Option<String>,
    pub nvt: Option<NvtRef>,
    #[serde(default)]
    pub hosts: Vec<String>,
    pub port: Option<String>,
    pub severity: Option<String>,
    #[serde(rename = "newSeverity")]
    pub new_severity: Option<String>,
    pub task: Option<ResourceRef>,
    pub result: Option<ResourceRef>,
    pub active: bool,
    #[serde(rename = "endTime")]
    pub end_time: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NvtCatalogEntry {
    pub oid: String,
    pub name: String,
    pub family: Option<String>,
    #[serde(rename = "cvssBase")]
    pub cvss_base: Option<f64>,
    pub severity: Option<f64>,
    pub tags: Option<String>,
    #[serde(rename = "solutionType")]
    pub solution_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NvtFamily {
    pub name: String,
    #[serde(rename = "maxNvtCount")]
    pub max_nvt_count: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Schedule {
    pub id: String,
    pub name: String,
    pub comment: Option<String>,
    pub icalendar: Option<String>,
    pub timezone: Option<String>,
    #[serde(rename = "inUse")]
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Alert {
    pub id: String,
    pub name: String,
    pub comment: Option<String>,
    pub event: Option<String>,
    pub condition: Option<String>,
    pub method: Option<String>,
    #[serde(rename = "inUse")]
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CredentialStore {
    pub id: String,
    pub name: String,
    pub provider: Option<String>,
    pub default: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Credential {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub credential_type: Option<String>,
    pub login: Option<String>,
    #[serde(rename = "inUse")]
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IdentityResourceMeta {
    pub id: String,
    pub name: String,
    pub comment: Option<String>,
    pub owner: Option<ResourceRef>,
    #[serde(rename = "creationTime")]
    pub creation_time: Option<String>,
    #[serde(rename = "modificationTime")]
    pub modification_time: Option<String>,
    #[serde(rename = "inUse")]
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct User {
    #[serde(flatten)]
    pub meta: IdentityResourceMeta,
    pub roles: Vec<ResourceRef>,
    pub groups: Vec<ResourceRef>,
    #[serde(rename = "hostsAllow")]
    pub hosts_allow: Option<bool>,
    pub hosts: Option<String>,
    #[serde(rename = "authenticationType")]
    pub authentication_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Group {
    #[serde(flatten)]
    pub meta: IdentityResourceMeta,
    pub users: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Role {
    #[serde(flatten)]
    pub meta: IdentityResourceMeta,
    pub users: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Permission {
    #[serde(flatten)]
    pub meta: IdentityResourceMeta,
    #[serde(rename = "subjectType")]
    pub subject_type: Option<String>,
    pub subject: Option<ResourceRef>,
    #[serde(rename = "resourceType")]
    pub resource_type: Option<String>,
    pub resource: Option<ResourceRef>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UserSetting {
    pub id: String,
    pub name: String,
    pub value: Option<String>,
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Target {
    pub id: String,
    pub name: String,
    pub hosts: Vec<String>,
    #[serde(rename = "portList")]
    pub port_list: Option<ResourceRef>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Task {
    pub id: String,
    pub name: String,
    pub comment: Option<String>,
    pub status: String,
    pub target: Option<ResourceRef>,
    #[serde(rename = "scanConfig")]
    pub scan_config: Option<ResourceRef>,
    pub scanner: Option<ResourceRef>,
    pub progress: Option<i32>,
    #[serde(rename = "currentReport")]
    pub current_report: Option<ResourceRef>,
    #[serde(rename = "lastReport")]
    pub last_report: Option<ResourceRef>,
    #[serde(rename = "reportCount")]
    pub report_count: Option<u32>,
    pub observers: Option<TaskObservers>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TaskObservers {
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub groups: Vec<ResourceRef>,
    #[serde(default)]
    pub roles: Vec<ResourceRef>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TaskAction {
    #[serde(rename = "reportId")]
    pub report_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Report {
    pub id: String,
    pub task: Option<ResourceRef>,
    #[serde(rename = "scanEnd")]
    pub scan_end: Option<String>,
    #[serde(rename = "resultCount")]
    pub result_count: Option<ResultCount>,
    #[serde(default)]
    pub results: Vec<ScanResult>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReportExportJob {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub report: ResourceRef,
    pub format: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "resultLocation")]
    pub result_location: Option<String>,
    pub result: Option<JobResult>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct JobResult {
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    pub filename: Option<String>,
    pub size: Option<u64>,
    pub location: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReportJsonExport {
    pub report: Report,
    #[serde(default)]
    pub results: Vec<ScanResult>,
    #[serde(rename = "generatedAt")]
    pub generated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResultCount {
    pub total: Option<u32>,
    pub high: Option<u32>,
    pub medium: Option<u32>,
    pub low: Option<u32>,
    pub log: Option<u32>,
    pub debug: Option<u32>,
    #[serde(rename = "falsePositive")]
    pub false_positive: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResultList {
    pub data: Vec<ScanResult>,
    pub pagination: Pagination,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsCertificateList {
    pub data: Vec<TlsCertificate>,
    pub pagination: Pagination,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsCertificate {
    pub id: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub subject: String,
    pub issuer: Option<String>,
    #[serde(rename = "notBefore")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter")]
    pub not_after: Option<String>,
    #[serde(rename = "fingerprintSha256")]
    pub fingerprint_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub name: String,
    pub host: Option<String>,
    pub port: Option<String>,
    pub severity: Option<f64>,
    pub threat: Option<String>,
    pub task: Option<ResourceRef>,
    pub report: Option<ResourceRef>,
    pub nvt: Option<NvtRef>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NvtRef {
    pub oid: Option<String>,
    pub name: Option<String>,
    pub family: Option<String>,
    #[serde(rename = "cvssBase")]
    pub cvss_base: Option<f64>,
    pub cves: Option<Vec<String>>,
    pub tags: Option<String>,
}
