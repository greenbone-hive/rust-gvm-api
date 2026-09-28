// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{
    reject_report_ultimate_query, GetReportQuery, ReportApplicationListResponse,
    ReportClosedCveListResponse, ReportCveListResponse, ReportErrorListResponse,
    ReportHostListResponse, ReportOperatingSystemListResponse, ReportPortListResponse,
    ReportResultsQuery, ReportVulnerabilityListResponse,
};

#[test]
fn report_delete_rejects_every_obsolete_ultimate_spelling_but_ignores_unrelated_queries() {
    // Report deletion is permanently destructive. Both boolean values, a
    // valueless key, and percent-encoded legacy input must fail closed so no
    // client can mistake the operation for a trashcan move.
    for query in [
        "ultimate=true",
        "ultimate=false",
        "ultimate",
        "reason=cleanup&ultimate=false",
        "ult%69mate=true",
    ] {
        let error = reject_report_ultimate_query(Some(query))
            .expect_err("obsolete report ultimate input must be rejected");
        assert!(
            matches!(
                error,
                gvm_gateway_domain::GatewayError::InvalidInput(ref detail)
                    if detail == "the `ultimate` query parameter is obsolete for report deletion; report deletion is always permanent"
            ),
            "unexpected error for {query}: {error:?}"
        );
    }

    // Unknown query behavior remains consistent with other repository
    // handlers: unrelated keys are ignored rather than globally rejected.
    reject_report_ultimate_query(None).expect("missing query should be accepted");
    reject_report_ultimate_query(Some("")).expect("empty query should be accepted");
    reject_report_ultimate_query(Some("reason=cleanup"))
        .expect("unrelated query should be accepted");
}
use gvm_gateway_domain::{
    Pagination, ReportApplication, ReportApplicationPage, ReportClosedCve, ReportClosedCvePage,
    ReportCve, ReportCvePage, ReportError, ReportErrorPage, ReportHost, ReportHostPage,
    ReportOperatingSystem, ReportOperatingSystemPage, ReportPortPage, ReportPortSummary,
    ReportVulnerability, ReportVulnerabilityPage,
};

#[test]
fn report_queries_decode_pagination_and_filter_values() {
    let report = GetReportQuery::try_from_query_string("page=2&perPage=30")
        .expect("encoded report query should parse");
    assert_eq!(report.page, 2);
    assert_eq!(report.per_page, 30);

    let results = ReportResultsQuery::try_from_query_string(
            "filter=severity%3E5+and+location~%22host%26port%3D443%22&filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000&page=2&perPage=10",
        )
        .expect("encoded filter should parse");
    assert_eq!(
        results.filter_string.as_deref(),
        Some("severity>5 and location~\"host&port=443\"")
    );
    assert_eq!(
        results.filter_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174000")
    );
    assert_eq!(results.page, 2);
    assert_eq!(results.per_page, 10);
}

#[test]
fn report_vulnerability_response_preserves_aggregate_fields() {
    // Vulnerability drill-downs are aggregate findings, not generic results;
    // the REST DTO must keep their count and NVT metadata shape intact.
    let json = serde_json::to_value(ReportVulnerabilityListResponse::from(
        ReportVulnerabilityPage {
            data: vec![ReportVulnerability {
                id: Some("row-1".to_string()),
                nvt: Some(gvm_gateway_domain::NvtRef {
                    oid: Some("1.3.6.1.4.1.25623.1.0.100000".to_string()),
                    name: Some("TLS finding".to_string()),
                    family: Some("General".to_string()),
                    cvss_base: None,
                    cves: vec!["CVE-2026-0001".to_string()],
                    tags: None,
                }),
                host: None,
                port: None,
                threat: Some("Medium".to_string()),
                severity: Some(5.0),
                hosts_count: Some(2),
                occurrences: Some(3),
            }],
            pagination: Pagination {
                page: 1,
                per_page: 25,
                total: 1,
                total_pages: 1,
            },
        },
    ))
    .expect("vulnerability response should serialize");

    assert_eq!(
        json["data"][0]["nvt"]["oid"],
        "1.3.6.1.4.1.25623.1.0.100000"
    );
    assert_eq!(json["data"][0]["threat"], "Medium");
    assert_eq!(json["data"][0]["hostsCount"], 2);
    assert_eq!(json["data"][0]["occurrences"], 3);
    assert!(json["data"][0].get("description").is_none());
}

#[test]
fn report_error_response_omits_fabricated_result_fields() {
    // Report-error rows must no longer inherit synthesized result threat or
    // severity fields from the generic result DTO.
    let json = serde_json::to_value(ReportErrorListResponse::from(ReportErrorPage {
        data: vec![ReportError {
            id: Some("row-2".to_string()),
            name: Some("VT error".to_string()),
            host: Some("192.0.2.10".to_string()),
            port: Some("443/tcp".to_string()),
            description: Some("scan failed".to_string()),
            nvt_name: Some("Broken VT".to_string()),
        }],
        pagination: Pagination {
            page: 1,
            per_page: 25,
            total: 1,
            total_pages: 1,
        },
    }))
    .expect("error response should serialize");

    assert_eq!(json["data"][0]["nvtName"], "Broken VT");
    assert!(json["data"][0].get("threat").is_none());
    assert!(json["data"][0].get("severity").is_none());
}

#[test]
fn report_closed_cve_response_preserves_closed_cve_fields() {
    // Closed-CVE drill-downs must expose the closed CVE id and backend threat
    // metadata without being coerced into the generic result `name` contract.
    let json = serde_json::to_value(ReportClosedCveListResponse::from(ReportClosedCvePage {
        data: vec![ReportClosedCve {
            id: Some("row-3".to_string()),
            nvt: Some(gvm_gateway_domain::NvtRef {
                oid: Some("1.3.6.1.4.1.25623.1.0.200000".to_string()),
                name: Some("Closed check".to_string()),
                family: None,
                cvss_base: None,
                cves: vec!["CVE-2025-9999".to_string()],
                tags: None,
            }),
            cve: Some("CVE-2025-9999".to_string()),
            host: Some("192.0.2.30".to_string()),
            severity: Some(5.0),
            threat: Some("Medium".to_string()),
        }],
        pagination: Pagination {
            page: 1,
            per_page: 25,
            total: 1,
            total_pages: 1,
        },
    }))
    .expect("closed-cve response should serialize");

    assert_eq!(json["data"][0]["cve"], "CVE-2025-9999");
    assert_eq!(json["data"][0]["threat"], "Medium");
    assert_eq!(json["data"][0]["nvt"]["name"], json!("Closed check"));
    assert!(json["data"][0].get("name").is_none());
}

#[test]
fn report_drill_downs_serialize_as_purpose_shaped_summaries() {
    // Issue #344 requires five distinct summary DTOs. Keeping this assertion at
    // the REST boundary prevents future reuse of generic result, asset, or
    // SecInfo response shapes for these report-scoped rows.
    let pagination = Pagination {
        page: 2,
        per_page: 10,
        total: 1,
        total_pages: 1,
    };
    let expected_pagination = json!({
        "page": 2,
        "perPage": 10,
        "total": 1,
        "totalPages": 1
    });

    let cases = [
        serde_json::to_value(ReportHostListResponse::from(ReportHostPage {
            data: vec![ReportHost {
                id: Some("host-row".to_string()),
                name: Some("192.0.2.10".to_string()),
                severity: Some("7.5".to_string()),
            }],
            pagination: pagination.clone(),
        }))
        .expect("host summary JSON"),
        serde_json::to_value(ReportPortListResponse::from(ReportPortPage {
            data: vec![ReportPortSummary {
                id: Some("port-row".to_string()),
                name: Some("443/tcp".to_string()),
                severity: Some("6.0".to_string()),
            }],
            pagination: pagination.clone(),
        }))
        .expect("port summary JSON"),
        serde_json::to_value(ReportApplicationListResponse::from(ReportApplicationPage {
            data: vec![ReportApplication {
                id: Some("application-row".to_string()),
                name: Some("nginx".to_string()),
                severity: Some("5.0".to_string()),
            }],
            pagination: pagination.clone(),
        }))
        .expect("application summary JSON"),
        serde_json::to_value(ReportOperatingSystemListResponse::from(
            ReportOperatingSystemPage {
                data: vec![ReportOperatingSystem {
                    id: Some("os-row".to_string()),
                    name: Some("Debian".to_string()),
                    severity: Some("4.0".to_string()),
                }],
                pagination: pagination.clone(),
            },
        ))
        .expect("operating-system summary JSON"),
        serde_json::to_value(ReportCveListResponse::from(ReportCvePage {
            data: vec![ReportCve {
                id: Some("cve-row".to_string()),
                name: Some("CVE-2026-0001".to_string()),
                severity: Some("8.0".to_string()),
            }],
            pagination,
        }))
        .expect("CVE summary JSON"),
    ];

    for value in cases {
        assert_eq!(value["pagination"], expected_pagination);
        let row = &value["data"][0];
        assert!(row.get("id").is_some());
        assert!(row.get("name").is_some());
        assert!(row.get("severity").is_some());
        assert_eq!(row.as_object().map(serde_json::Map::len), Some(3));
        assert!(row.get("results").is_none());
        assert!(row.get("hostsCount").is_none());
    }
}
