// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::ImportReportInput;

#[test]
fn import_report_input_keeps_opaque_bytes_but_redacts_debug_output() {
    // Report bytes must cross the domain unchanged while remaining unavailable
    // to ordinary debug/log formatting because report contents are sensitive.
    let private_xml = b"<report><name>private-report-marker</name></report>";
    let input = ImportReportInput {
        task_id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        report_xml: private_xml.to_vec(),
        in_assets: Some(false),
    };

    assert_eq!(input.report_xml, private_xml);
    let debug = format!("{input:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("private-report-marker"));
}
