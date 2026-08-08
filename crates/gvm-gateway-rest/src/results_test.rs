// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::ResultResponse;
use gvm_gateway_domain::ScanResult;

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
