// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::ResultResponse;
use gvm_gateway_domain::{NvtRef, ScanResult};

#[test]
fn result_response_preserves_critical_threat() {
    let response = ResultResponse::from(ScanResult {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Critical finding".to_string(),
        host: None,
        port: None,
        severity: Some(10.0),
        threat: Some("Critical".to_string()),
        nvt: None,
        description: None,
        task: None,
        report: None,
        hosts_count: None,
        occurrences: None,
    });

    let value = serde_json::to_value(response).expect("result response should serialize");
    assert_eq!(value["threat"], json!("Critical"));
}

#[test]
fn result_response_preserves_unknown_threat() {
    let response = ResultResponse::from(ScanResult {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Future finding".to_string(),
        host: None,
        port: None,
        severity: Some(7.5),
        threat: Some("FutureThreat".to_string()),
        nvt: None,
        description: None,
        task: None,
        report: None,
        hosts_count: None,
        occurrences: None,
    });

    let value = serde_json::to_value(response).expect("result response should serialize");
    assert_eq!(value["threat"], json!("FutureThreat"));
}

#[test]
fn result_response_preserves_source_shaped_type_metadata() {
    // `typeMetadata` is intentionally an opaque string so new upstream shapes
    // survive the gateway without lossy JSON parsing or schema narrowing.
    let response = ResultResponse::from(ScanResult {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Web finding".to_string(),
        host: None,
        port: None,
        severity: None,
        threat: None,
        nvt: Some(NvtRef {
            oid: Some("1.3.6.1".to_string()),
            name: None,
            family: None,
            cvss_base: None,
            cves: Vec::new(),
            tags: None,
            type_metadata: Some("{\"future\":[1,true]}".to_string()),
        }),
        description: None,
        task: None,
        report: None,
        hosts_count: None,
        occurrences: None,
    });

    let value = serde_json::to_value(response).expect("result response should serialize");
    assert_eq!(value["nvt"]["typeMetadata"], "{\"future\":[1,true]}");
}

#[test]
fn result_response_omits_absent_type_metadata() {
    // Additive response compatibility requires the field to disappear, not
    // serialize as null, when gvmd did not provide it.
    let nvt = super::NvtRefResponse::from(NvtRef {
        oid: Some("1.3.6.1".to_string()),
        name: None,
        family: None,
        cvss_base: None,
        cves: Vec::new(),
        tags: None,
        type_metadata: None,
    });

    let value = serde_json::to_value(nvt).expect("NVT reference should serialize");
    assert!(value.get("typeMetadata").is_none());
}
