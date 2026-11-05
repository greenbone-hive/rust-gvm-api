// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::NvtResponse;
use gvm_gateway_domain::{Epss, EpssCve, EpssSelection, Nvt};

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
        epss: None,
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
        epss: None,
    });

    let value = serde_json::to_value(response).expect("NVT response should serialize");
    assert!(value.get("discovery").is_none());
    assert!(value.get("epss").is_none());
}

#[test]
fn nvt_response_exposes_optional_epss() {
    // Catalog list/detail DTOs expose both selections with their distinct CVEs
    // and retain optional severity exactly as represented by the domain model.
    let response = NvtResponse::from(Nvt {
        oid: "1.3.6.1".to_string(),
        name: "EPSS check".to_string(),
        family: None,
        cvss_base: None,
        severity: None,
        tags: None,
        solution_type: None,
        discovery: None,
        epss: Some(Epss {
            max_epss: EpssSelection {
                score: 0.8,
                percentile: 95.0,
                cve: EpssCve {
                    id: "CVE-2026-0002".to_string(),
                    severity: None,
                },
            },
            max_severity: EpssSelection {
                score: 0.2,
                percentile: 60.0,
                cve: EpssCve {
                    id: "CVE-2026-0001".to_string(),
                    severity: Some(10.0),
                },
            },
        }),
    });

    let value = serde_json::to_value(response).expect("NVT response should serialize");
    assert_eq!(value["epss"]["maxEpss"]["cve"], "CVE-2026-0002");
    assert_eq!(value["epss"]["maxSeverity"]["cve"], "CVE-2026-0001");
    assert_eq!(value["epss"]["maxSeverity"]["severity"], 10.0);
}
