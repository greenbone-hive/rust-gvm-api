// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{ScanConfigResponse, ScanConfigType};
use gvm_gateway_domain::ScanConfig;

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
