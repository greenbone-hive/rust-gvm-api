// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::ResultResponse;
use gvm_gateway_domain::{Epss, EpssCve, EpssSelection, NvtRef, ScanResult};

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
            epss: None,
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
        epss: None,
    });

    let value = serde_json::to_value(nvt).expect("NVT reference should serialize");
    assert!(value.get("typeMetadata").is_none());
    assert!(value.get("epss").is_none());
}

#[test]
fn result_response_serializes_distinct_epss_selections() {
    // The shared result DTO must expose both maxima without normalizing the
    // backend-native percentile or fabricating an absent CVE severity.
    let nvt = super::NvtRefResponse::from(NvtRef {
        oid: Some("1.3.6.1".to_string()),
        name: None,
        family: None,
        cvss_base: None,
        cves: Vec::new(),
        tags: None,
        type_metadata: None,
        epss: Some(Epss {
            max_epss: EpssSelection {
                score: 0.54321,
                percentile: 99.5,
                cve: EpssCve {
                    id: "CVE-2026-0002".to_string(),
                    severity: None,
                },
            },
            max_severity: EpssSelection {
                score: 0.12345,
                percentile: 98.765,
                cve: EpssCve {
                    id: "CVE-2026-0001".to_string(),
                    severity: Some(9.8),
                },
            },
        }),
    });

    let value = serde_json::to_value(nvt).expect("NVT reference should serialize");
    assert_eq!(value["epss"]["maxEpss"]["score"], 0.54321);
    assert_eq!(value["epss"]["maxEpss"]["percentile"], 99.5);
    assert_eq!(value["epss"]["maxEpss"]["cve"], "CVE-2026-0002");
    assert!(value["epss"]["maxEpss"].get("severity").is_none());
    assert_eq!(value["epss"]["maxSeverity"]["score"], 0.12345);
    assert_eq!(value["epss"]["maxSeverity"]["percentile"], 98.765);
    assert_eq!(value["epss"]["maxSeverity"]["cve"], "CVE-2026-0001");
    assert_eq!(value["epss"]["maxSeverity"]["severity"], 9.8);
}

#[test]
fn summary_nvt_reference_does_not_expose_epss() {
    // Aggregate report vulnerabilities and other summary-only surfaces remain
    // outside issue #620 even if their shared domain value carries EPSS.
    let nvt = super::NvtRefSummaryResponse::from(NvtRef {
        oid: Some("1.3.6.1".to_string()),
        name: None,
        family: None,
        cvss_base: None,
        cves: Vec::new(),
        tags: None,
        type_metadata: None,
        epss: Some(Epss {
            max_epss: EpssSelection {
                score: 0.5,
                percentile: 50.0,
                cve: EpssCve {
                    id: "CVE-2026-0001".to_string(),
                    severity: None,
                },
            },
            max_severity: EpssSelection {
                score: 0.4,
                percentile: 40.0,
                cve: EpssCve {
                    id: "CVE-2026-0002".to_string(),
                    severity: Some(9.0),
                },
            },
        }),
    });

    let value = serde_json::to_value(nvt).expect("summary NVT reference should serialize");
    assert!(value.get("epss").is_none());
}
