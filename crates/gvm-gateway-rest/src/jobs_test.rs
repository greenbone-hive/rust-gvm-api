// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_gateway_domain::{CreateReportExportRequest, GatewayError};

use super::CreateReportExportRequestBody;

/// JSON export requests parse into the JSON export variant.
#[test]
fn parses_json_export_request_body() {
    let body: CreateReportExportRequestBody =
        serde_json::from_str(r#"{"format":"json"}"#).expect("body should parse");

    assert!(matches!(body, CreateReportExportRequestBody::Json(_)));
}

/// `reportConfigId` is an export selector, so a valid UUID must survive REST
/// validation and reach the domain request unchanged.
#[test]
fn report_config_id_is_validated_and_forwarded_for_gvmd_exports() {
    let report_config_id = "123e4567-e89b-12d3-a456-426614174222";
    let body: CreateReportExportRequestBody = serde_json::from_str(&format!(
        r#"{{"reportFormatId":"123e4567-e89b-12d3-a456-426614174111","reportConfigId":"{report_config_id}"}}"#
    ))
    .expect("gvmd export body should parse");

    let request = body.into_domain().expect("valid UUIDs should map");
    let CreateReportExportRequest::GvmdReportFormat(request) = request else {
        panic!("report format selector must use the gvmd export variant");
    };
    assert_eq!(request.report_config_id.as_deref(), Some(report_config_id));
}

/// Invalid report-configuration selectors must retain the existing RFC 9457
/// invalid-input path instead of reaching the backend.
#[test]
fn invalid_report_config_id_is_rejected_before_export() {
    let body: CreateReportExportRequestBody = serde_json::from_str(
        r#"{"reportFormatId":"123e4567-e89b-12d3-a456-426614174111","reportConfigId":"not-a-uuid"}"#,
    )
    .expect("shape should parse before semantic validation");

    assert!(matches!(
        body.into_domain(),
        Err(GatewayError::InvalidInput(_))
    ));
}
