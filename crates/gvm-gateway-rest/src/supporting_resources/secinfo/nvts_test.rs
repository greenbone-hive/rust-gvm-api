// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::NvtResponse;
use gvm_gateway_domain::Nvt;

#[test]
fn nvt_response_preserves_discovery_false() {
    // Explicit false is backend information, not absence, and must remain in
    // the additive public response field.
    let response = NvtResponse::from(Nvt {
        oid: "1.3.6.1".to_string(),
        name: "Non-discovery check".to_string(),
        family: None,
        cvss_base: None,
        severity: None,
        tags: None,
        solution_type: None,
        discovery: Some(false),
    });

    let value = serde_json::to_value(response).expect("NVT response should serialize");
    assert_eq!(value["discovery"], false);
}

#[test]
fn nvt_response_omits_absent_discovery() {
    // Compatibility requires older backend responses to omit the new field
    // instead of adding a null value.
    let response = NvtResponse::from(Nvt {
        oid: "1.3.6.1".to_string(),
        name: "Unclassified check".to_string(),
        family: None,
        cvss_base: None,
        severity: None,
        tags: None,
        solution_type: None,
        discovery: None,
    });

    let value = serde_json::to_value(response).expect("NVT response should serialize");
    assert!(value.get("discovery").is_none());
}
