// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{
    parse_preference_query, parse_scan_config_nvt_query, ModifyScanConfigRequest,
    ScanConfigPreferenceResponse, ScanConfigResponse, ScanConfigType, SetFamilySelectionRequest,
    SetNvtSelectionRequest, SetPreferenceRequest,
};
use gvm_gateway_domain::{ScanConfig, ScanConfigPreference, ScanConfigPreferenceNvt};

fn scan_config_with_type(config_type: u32) -> ScanConfig {
    scan_config_with(config_type, None)
}

fn scan_config_with(config_type: u32, usage_type: Option<&str>) -> ScanConfig {
    ScanConfig {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Scan config".to_string(),
        comment: None,
        family_count: Some(2),
        nvt_count: Some(12),
        config_type: Some(config_type),
        usage_type: usage_type.map(str::to_string),
        in_use: false,
        writable: true,
    }
}

#[test]
fn scan_config_type_deserialization_preserves_unknown_values() {
    // The public REST contract uses numeric scan-config type values; new
    // backend values should round-trip as numbers, not be rejected.
    let parsed: ScanConfigType =
        serde_json::from_value(json!(42)).expect("scan config type should parse");

    assert_eq!(serde_json::to_value(parsed).unwrap(), json!(42));
}

#[test]
fn scan_config_response_preserves_known_and_unknown_types() {
    // Response conversion should preserve both documented numeric values
    // and future backend numeric values verbatim.
    let known = serde_json::to_value(ScanConfigResponse::from(scan_config_with_type(0)))
        .expect("scan config response should serialize");
    let unknown = serde_json::to_value(ScanConfigResponse::from(scan_config_with_type(42)))
        .expect("scan config response should serialize");

    assert_eq!(known["type"], json!(0));
    assert_eq!(unknown["type"], json!(42));
}

#[test]
fn scan_config_response_exposes_usage_type_discriminator() {
    // `GET /scan-configs` lists ordinary scan configs and compliance policies
    // together (gvmd `get_configs` is not usage-scoped at the pinned revision),
    // so the response must carry the usage-type discriminator for clients to
    // tell them apart. Absent usage types are omitted rather than serialized.
    let policy = serde_json::to_value(ScanConfigResponse::from(scan_config_with(
        0,
        Some("policy"),
    )))
    .expect("scan config response should serialize");
    let scan = serde_json::to_value(ScanConfigResponse::from(scan_config_with(0, Some("scan"))))
        .expect("scan config response should serialize");
    let unspecified = serde_json::to_value(ScanConfigResponse::from(scan_config_with(0, None)))
        .expect("scan config response should serialize");

    assert_eq!(policy["usageType"], json!("policy"));
    assert_eq!(scan["usageType"], json!("scan"));
    assert_eq!(unspecified.get("usageType"), None);
}

#[test]
fn modify_scan_config_request_preserves_rename() {
    // Regression coverage for #404: accepting a scan-config name on PUT is a
    // public promise, so conversion must keep it for the typed adapter.
    let input = ModifyScanConfigRequest {
        name: Some("renamed config".to_string()),
        comment: None,
    }
    .validate()
    .expect("rename-only scan config updates are valid");

    assert_eq!(input.name.as_deref(), Some("renamed config"));
}

#[test]
fn scan_config_subresource_queries_validate_bounds() {
    let nvts = parse_scan_config_nvt_query("family=Web+Servers&page=2&perPage=50")
        .expect("valid selected-NVT query");
    assert_eq!(nvts.family.as_deref(), Some("Web Servers"));
    assert_eq!((nvts.page, nvts.per_page), (2, 50));

    let preferences = parse_preference_query("nvtOid=1.3.6.1.4.1").expect("valid preference query");
    assert_eq!(preferences.nvt_oid.as_deref(), Some("1.3.6.1.4.1"));
    assert!(parse_scan_config_nvt_query("page=0").is_err());
    assert!(parse_scan_config_nvt_query("perPage=1001").is_err());
}

#[test]
fn scan_config_selection_requests_are_closed_camel_case_contracts() {
    let nvts: SetNvtSelectionRequest = serde_json::from_value(json!({
        "nvtOids": ["1.3.6.1"]
    }))
    .expect("valid NVT selection");
    assert_eq!(nvts.nvt_oids[0].0, "1.3.6.1");

    let families: SetFamilySelectionRequest = serde_json::from_value(json!({
        "families": [{"name": "Web Servers", "growing": true, "all": false}],
        "autoAddNewFamilies": true
    }))
    .expect("valid family selection");
    assert!(families.auto_add_new_families);

    let preference: SetPreferenceRequest = serde_json::from_value(json!({
        "nvtOid": "1.3.6.1"
    }))
    .expect("valid preference reset");
    assert_eq!(preference.value, None);
    assert!(serde_json::from_value::<SetPreferenceRequest>(json!({"secret": "no"})).is_err());
}

#[test]
fn scan_config_preference_response_preserves_typed_fields() {
    let response = serde_json::to_value(ScanConfigPreferenceResponse::from(ScanConfigPreference {
        nvt: Some(ScanConfigPreferenceNvt {
            oid: "1.3.6.1".to_string(),
            name: Some("Services".to_string()),
        }),
        name: "Timeout".to_string(),
        id: Some("7".to_string()),
        preference_type: Some("entry".to_string()),
        value: Some("10".to_string()),
        alternatives: vec!["5".to_string(), "10".to_string()],
        default: Some("5".to_string()),
    }))
    .expect("preference response serializes");

    assert_eq!(response["nvt"]["oid"], json!("1.3.6.1"));
    assert_eq!(response["type"], json!("entry"));
    assert_eq!(response["alternatives"], json!(["5", "10"]));
}
