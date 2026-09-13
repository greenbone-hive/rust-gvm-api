// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![cfg(test)]

use crate::*;

// ------------------------------------------------------------------------
// GatewayError tests
// ------------------------------------------------------------------------

/// GatewayError variants remain distinguishable for callers that match on them.
#[test]
fn gateway_error_variants_distinguishable() {
    let backend = GatewayError::BackendUnavailable("down".to_string());
    let not_found = GatewayError::NotFound("missing".to_string());
    let invalid = GatewayError::InvalidInput("bad".to_string());
    let unauth = GatewayError::Unauthorized("denied".to_string());
    let expired = GatewayError::SessionExpired("expired".to_string());
    let invalidated = GatewayError::SessionInvalidated("missing".to_string());
    let forbidden = GatewayError::Forbidden("forbidden".to_string());
    let limited = GatewayError::TooManyRequests("slow down".to_string());
    let internal = GatewayError::Internal("boom".to_string());

    assert!(matches!(backend, GatewayError::BackendUnavailable(_)));
    assert!(matches!(not_found, GatewayError::NotFound(_)));
    assert!(matches!(invalid, GatewayError::InvalidInput(_)));
    assert!(matches!(unauth, GatewayError::Unauthorized(_)));
    assert!(matches!(expired, GatewayError::SessionExpired(_)));
    assert!(matches!(invalidated, GatewayError::SessionInvalidated(_)));
    assert!(matches!(forbidden, GatewayError::Forbidden(_)));
    assert!(matches!(limited, GatewayError::TooManyRequests(_)));
    assert!(matches!(internal, GatewayError::Internal(_)));
}

/// Shared errors expose stable public code and slug identity.
#[test]
fn gateway_error_identity_is_stable() {
    let error = GatewayError::SessionExpired("expired".to_string());

    assert_eq!(error.code().as_str(), "session_expired");
    assert_eq!(error.problem_slug(), "session-expired");
    assert_eq!(error.detail(), "expired");
}

// ------------------------------------------------------------------------
// Shared/system type tests
// ------------------------------------------------------------------------

/// HealthStatus serializes the expected `status` field from the system spec.
#[test]
fn health_status_serializes() {
    let status = HealthStatus { status: "ok" };
    let json = serde_json::to_string(&status).unwrap();
    assert!(json.contains("\"status\":\"ok\""));
}

/// ReadinessStatus omits `reason` so ready responses match the compact contract.
#[test]
fn readiness_status_omits_none_reason() {
    let status = ReadinessStatus {
        status: "ready",
        reason: None,
    };
    let json = serde_json::to_string(&status).unwrap();
    assert!(!json.contains("reason"));
}

/// ReadinessStatus includes `reason` for not-ready responses.
#[test]
fn readiness_status_includes_reason() {
    let status = ReadinessStatus {
        status: "notReady",
        reason: Some("gvmd offline".to_string()),
    };
    let json = serde_json::to_string(&status).unwrap();
    assert!(json.contains("\"reason\":\"gvmd offline\""));
}

/// VersionInfo retains the camelCase field names used by the REST contract.
#[test]
fn version_info_camel_case_fields() {
    let info = VersionInfo {
        api_version: "1.0.0".to_string(),
        gmp_version: "22.7".to_string(),
    };
    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains("\"apiVersion\""));
    assert!(json.contains("\"gmpVersion\""));
}

/// Backend timezone entries keep `offset` optional so gvmd can return bare
/// names like `UTC` without the gateway inventing extra normalization.
#[test]
fn timezone_omits_none_offset() {
    let timezone = Timezone {
        name: "UTC".to_string(),
        offset: None,
    };
    let json = serde_json::to_string(&timezone).unwrap();

    assert!(json.contains("\"name\":\"UTC\""));
    assert!(!json.contains("offset"));
}

/// Pagination keeps camelCase wire fields after the split.
#[test]
fn pagination_serializes_camel_case() {
    let pagination = Pagination {
        page: 1,
        per_page: 25,
        total: 100,
        total_pages: 4,
    };
    let json = serde_json::to_string(&pagination).unwrap();
    assert!(json.contains("\"perPage\""));
    assert!(json.contains("\"totalPages\""));
}

/// ResourceRef still omits the optional name when absent.
#[test]
fn resource_ref_name_optional() {
    let with_name = ResourceRef {
        id: "abc".to_string(),
        name: Some("Port List".to_string()),
    };
    let json = serde_json::to_string(&with_name).unwrap();
    assert!(json.contains("\"name\""));

    let without_name = ResourceRef {
        id: "abc".to_string(),
        name: None,
    };
    let json = serde_json::to_string(&without_name).unwrap();
    assert!(!json.contains("\"name\""));
}

/// Log-safety helpers expose only the shared marker and do not retain the
/// original value in Debug, Display, or optional Debug formatting.
#[test]
fn log_safety_helpers_hide_values() {
    let secret = "super-secret-value".to_string();
    let optional_secret = Some(secret.clone());
    let absent_secret: Option<String> = None;

    assert_eq!(format!("{}", hide_value(&secret)), "<redacted>");
    assert_eq!(format!("{:?}", hide_value(&secret)), "<redacted>");
    assert_eq!(
        format!("{:?}", hide_optional_value(&optional_secret)),
        "Some(<redacted>)"
    );
    assert_eq!(format!("{:?}", hide_optional_value(&absent_secret)), "None");
}

// ------------------------------------------------------------------------
// Target tests
// ------------------------------------------------------------------------

/// Credential command debug output must not expose write-only secret material
/// if inputs are ever included in diagnostic logs or panic messages.
#[test]
fn credential_command_debug_redacts_secrets() {
    let create = CreateCredentialInput {
        name: "Credential".to_string(),
        comment: Some("visible comment".to_string()),
        credential_type: "snmpv3".to_string(),
        login: Some("visible-login".to_string()),
        password: Some("create-password-secret".to_string()),
        private_key: Some("create-private-key-secret".to_string()),
        certificate: Some("public-certificate".to_string()),
        community: Some("create-community-secret".to_string()),
        auth_algorithm: Some("sha1".to_string()),
        privacy_algorithm: Some("aes".to_string()),
        privacy_password: Some("create-privacy-secret".to_string()),
        credential_store_id: None,
        vault_id: Some("create-vault-secret".to_string()),
        host_identifier: Some("create-host-secret".to_string()),
    };
    let modify = ModifyCredentialInput {
        name: Some("Credential".to_string()),
        comment: Some("visible comment".to_string()),
        login: Some("visible-login".to_string()),
        password: Some("modify-password-secret".to_string()),
        private_key: Some("modify-private-key-secret".to_string()),
        certificate: Some("public-certificate".to_string()),
        community: Some("modify-community-secret".to_string()),
        auth_algorithm: Some("sha1".to_string()),
        privacy_algorithm: Some("aes".to_string()),
        privacy_password: Some("modify-privacy-secret".to_string()),
        credential_store_id: None,
        vault_id: Some("modify-vault-secret".to_string()),
        host_identifier: Some("modify-host-secret".to_string()),
    };

    let debug = format!("{create:?}\n{modify:?}");

    assert!(debug.contains("visible-login"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("create-password-secret"));
    assert!(!debug.contains("create-private-key-secret"));
    assert!(!debug.contains("create-community-secret"));
    assert!(!debug.contains("create-privacy-secret"));
    assert!(!debug.contains("create-vault-secret"));
    assert!(!debug.contains("create-host-secret"));
    assert!(!debug.contains("modify-password-secret"));
    assert!(!debug.contains("modify-private-key-secret"));
    assert!(!debug.contains("modify-community-secret"));
    assert!(!debug.contains("modify-privacy-secret"));
    assert!(!debug.contains("modify-vault-secret"));
    assert!(!debug.contains("modify-host-secret"));
}

/// TargetQuery defaults preserve the existing zero-value pagination behavior.
#[test]
fn target_query_default() {
    let query = TargetQuery::default();
    assert_eq!(query.page, 0);
    assert_eq!(query.per_page, 0);
    assert!(query.filter_string.is_none());
    assert!(query.filter_id.is_none());
}

/// ModifyTargetInput defaults remain empty so partial updates are opt-in.
#[test]
fn modify_target_input_default() {
    let input = ModifyTargetInput::default();
    assert!(input.name.is_none());
    assert!(input.comment.is_none());
    assert!(input.hosts.is_none());
    assert!(input.reverse_lookup_only.is_none());
    assert!(input.reverse_lookup_unify.is_none());
    assert!(input.ssh_credential_id.is_none());
    assert!(input.smb_credential_id.is_none());
    assert!(input.esxi_credential_id.is_none());
    assert!(input.snmp_credential_id.is_none());
}

/// ModifyTaskInput defaults keep preferences empty so omitted updates do not
/// accidentally replace scanner-level settings.
#[test]
fn modify_task_input_default_keeps_preferences_empty() {
    let input = ModifyTaskInput::default();

    assert!(input.preferences.is_empty());
}

/// Target only emits `excludeHosts` when there are actual excluded hosts.
#[test]
fn target_serializes_exclude_hosts_only_when_nonempty() {
    let target_with_excludes = Target {
        id: "123".to_string(),
        name: "test".to_string(),
        comment: None,
        hosts: vec!["10.0.0.1".to_string()],
        exclude_hosts: vec!["10.0.0.2".to_string()],
        alive_test: None,
        port_list: None,
        reverse_lookup_only: false,
        reverse_lookup_unify: false,
        ssh_credential: None,
        smb_credential: None,
        esxi_credential: None,
        snmp_credential: None,
        in_use: false,
        writable: true,
    };
    let json_with = serde_json::to_string(&target_with_excludes).unwrap();
    assert!(json_with.contains("\"excludeHosts\""));

    let target_no_excludes = Target {
        exclude_hosts: vec![],
        ..target_with_excludes
    };
    let json_without = serde_json::to_string(&target_no_excludes).unwrap();
    assert!(!json_without.contains("excludeHosts"));
}

// ------------------------------------------------------------------------
// Report tests
// ------------------------------------------------------------------------

/// Report serializes camelCase fields and omits absent or empty fields.
#[test]
fn report_serializes_camel_case() {
    let report = Report {
        id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        task: Some(ResourceRef {
            id: "task-1".to_string(),
            name: Some("Scan".to_string()),
        }),
        scan_start: Some("2026-01-01T00:00:00Z".to_string()),
        scan_end: None,
        severity: Some(7.5),
        result_count: Some(ResultCount {
            total: Some(10),
            high: Some(2),
            medium: Some(3),
            low: Some(1),
            log: Some(4),
            debug: Some(6),
            false_positive: None,
        }),
        results: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"scanStart\""));
    assert!(!json.contains("\"scanEnd\""));
    assert!(json.contains("\"resultCount\""));
    assert!(json.contains("\"debug\""));
    assert!(!json.contains("\"falsePositive\""));
    assert!(!json.contains("\"results\""));
}

/// ResultCount omits absent severity buckets so payloads stay sparse.
#[test]
fn result_count_omits_none_fields() {
    let rc = ResultCount {
        total: Some(5),
        high: None,
        medium: None,
        low: None,
        log: None,
        debug: None,
        false_positive: None,
    };
    let json = serde_json::to_string(&rc).unwrap();
    assert!(json.contains("\"total\""));
    assert!(!json.contains("\"high\""));
    assert!(!json.contains("\"debug\""));
}

/// ReportQuery defaults preserve the existing zero-value pagination behavior.
#[test]
fn report_query_default() {
    let query = ReportQuery::default();
    assert_eq!(query.page, 0);
    assert_eq!(query.per_page, 0);
    assert!(query.filter_string.is_none());
}

/// Single-report fetch defaults expose the documented embedded-result window.
#[test]
fn get_report_opts_default_embeds_first_result_page() {
    let opts = GetReportOpts::default();
    assert_eq!(opts.page, 1);
    assert_eq!(opts.per_page, 25);
}

// ------------------------------------------------------------------------
// Task tests
// ------------------------------------------------------------------------

/// Task serializes progress and report-count semantics from gvmd task details.
#[test]
fn task_serializes_lifecycle_detail_fields() {
    let task = Task {
        id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        name: "Discovery Scan".to_string(),
        comment: None,
        status: "Processing".to_string(),
        progress: Some(42),
        target: None,
        agent_group: None,
        oci_image_target: None,
        web_application_target: None,
        scan_config: None,
        scanner: None,
        schedule: None,
        alerts: vec![],
        alterable: Some(true),
        hosts_ordering: None,
        observers: TaskObservers {
            users: vec!["alice".to_string()],
            groups: vec![ResourceRef {
                id: "11111111-1111-1111-1111-111111111111".to_string(),
                name: Some("Auditors".to_string()),
            }],
            roles: vec![ResourceRef {
                id: "22222222-2222-2222-2222-222222222222".to_string(),
                name: Some("Observers".to_string()),
            }],
        },
        schedule_periods: Some(3),
        last_report: None,
        current_report: Some(TaskReportReference {
            id: "33333333-3333-3333-3333-333333333333".to_string(),
            timestamp: None,
            scan_start: None,
            scan_end: None,
            result_count: None,
            severity: None,
            compliance_count: None,
        }),
        report_count: Some(7),
        usage_type: Some("scan".to_string()),
        trend: None,
        in_use: true,
        writable: true,
    };

    let json = serde_json::to_string(&task).unwrap();

    assert!(json.contains("\"progress\":42"));
    assert!(json.contains("\"reportCount\":7"));
    assert!(json.contains("\"currentReport\""));
    assert!(json.contains("\"observers\""));
    assert!(json.contains("\"groups\""));
    assert!(json.contains("\"roles\""));
    assert!(json.contains("\"schedulePeriods\":3"));
    assert!(!json.contains("\"resultCount\""));
}

// ------------------------------------------------------------------------
// Result tests
// ------------------------------------------------------------------------

/// ScanResult serializes camelCase nested fields and omits optional nulls.
#[test]
fn scan_result_serializes_camel_case() {
    let result = ScanResult {
        id: "result-1".to_string(),
        name: "Test NVT".to_string(),
        host: Some("192.168.1.1".to_string()),
        port: Some("443/tcp".to_string()),
        severity: Some(9.8),
        threat: Some("High".to_string()),
        nvt: Some(NvtRef {
            oid: Some("1.3.6.1.4.1.25623.1.0.12345".to_string()),
            name: Some("Test NVT".to_string()),
            family: Some("Test Family".to_string()),
            cvss_base: Some(9.8),
            cves: vec!["CVE-2024-1234".to_string()],
            tags: None,
        }),
        description: Some("A vulnerability was found.".to_string()),
        task: None,
        report: None,
        hosts_count: None,
        occurrences: None,
    };
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"cvssBase\""));
    assert!(!json.contains("\"tags\""));
    assert!(!json.contains("\"task\""));
    assert!(!json.contains("\"hostsCount\""));
    assert!(!json.contains("\"occurrences\""));
}

/// NvtRef omits the CVE list when it is empty.
#[test]
fn nvt_ref_omits_empty_cves() {
    let nvt = NvtRef {
        oid: Some("1.2.3".to_string()),
        name: None,
        family: None,
        cvss_base: None,
        cves: vec![],
        tags: None,
    };
    let json = serde_json::to_string(&nvt).unwrap();
    assert!(!json.contains("\"cves\""));
}

/// ResultQuery defaults preserve the existing zero-value pagination behavior.
#[test]
fn result_query_default() {
    let query = ResultQuery::default();
    assert_eq!(query.page, 0);
    assert_eq!(query.per_page, 0);
    assert!(query.filter_string.is_none());
}
