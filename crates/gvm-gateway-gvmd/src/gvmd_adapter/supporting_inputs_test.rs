// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::*;
use gvm_gateway_domain::{Note, Override, ResourceRef, SupportingResourceMeta};

#[test]
fn active_flags_map_to_gvmd_activation_durations() {
    // Canonical note and override requests model gvmd's duration rather than
    // the removed boolean option-bag field: true means forever, false disabled.
    assert_eq!(active_days(true), -1);
    assert_eq!(active_days(false), 0);
}

#[test]
fn severity_text_is_converted_to_the_canonical_numeric_value() {
    // The REST/domain contract retains severity text, while canonical rust-gvm
    // requests validate a numeric value before any command is sent.
    assert_eq!(
        parse_optional_severity(Some("7.5".to_string()), "severity").unwrap(),
        Some(7.5)
    );
}

#[test]
fn invalid_severity_text_is_rejected_at_the_adapter_boundary() {
    // Invalid REST severity text must remain a client error and must never
    // reach rust-gvm's typed execution path as a fabricated wire value.
    assert!(matches!(
        parse_optional_severity(Some("high".to_string()), "severity"),
        Err(GatewayError::InvalidInput(_))
    ));
}

#[test]
fn omitted_note_modify_fields_preserve_existing_restrictions() {
    // The REST update contract is patch-shaped, while canonical note requests
    // replace restrictions. Rehydrate omitted fields so changing text alone
    // cannot erase host, port, severity, task, or result selectors.
    let request = note_request_from_modify_input(
        parse_entity_id("123e4567-e89b-12d3-a456-426614174000").expect("valid note id"),
        ModifyNoteInput {
            text: Some("updated text".to_string()),
            ..Default::default()
        },
        note_with_restrictions(),
    )
    .expect("complete request");

    assert_eq!(request.text, "updated text");
    assert_eq!(request.hosts, vec!["192.0.2.1".to_string()]);
    assert_eq!(request.port.as_deref(), Some("443/tcp"));
    assert_eq!(request.severity, Some(7.5));
    assert_eq!(
        request.task_id.expect("task").as_str(),
        "123e4567-e89b-12d3-a456-426614174001"
    );
    assert_eq!(
        request.result_id.expect("result").as_str(),
        "123e4567-e89b-12d3-a456-426614174002"
    );
}

#[test]
fn omitted_override_modify_fields_preserve_existing_restrictions() {
    // Overrides have required text and replacement severity in canonical GMP,
    // so an otherwise empty REST patch must rehydrate both and every selector.
    let request = override_request_from_modify_input(
        parse_entity_id("123e4567-e89b-12d3-a456-426614174000").expect("valid override id"),
        ModifyOverrideInput::default(),
        override_with_restrictions(),
    )
    .expect("complete request");

    assert_eq!(request.text, "existing override");
    assert_eq!(request.new_severity, 2.0);
    assert_eq!(request.hosts, vec!["192.0.2.1".to_string()]);
    assert_eq!(request.port.as_deref(), Some("443/tcp"));
    assert_eq!(request.severity, Some(7.5));
    assert_eq!(
        request.task_id.expect("task").as_str(),
        "123e4567-e89b-12d3-a456-426614174001"
    );
    assert_eq!(
        request.result_id.expect("result").as_str(),
        "123e4567-e89b-12d3-a456-426614174002"
    );
}

fn note_with_restrictions() -> Note {
    Note {
        meta: resource_meta(),
        text: Some("existing note".to_string()),
        nvt: None,
        hosts: vec!["192.0.2.1".to_string()],
        port: Some("443/tcp".to_string()),
        severity: Some("7.5".to_string()),
        task: Some(resource_ref("123e4567-e89b-12d3-a456-426614174001")),
        result: Some(resource_ref("123e4567-e89b-12d3-a456-426614174002")),
        active: true,
        end_time: None,
    }
}

fn override_with_restrictions() -> Override {
    Override {
        meta: resource_meta(),
        text: Some("existing override".to_string()),
        nvt: None,
        hosts: vec!["192.0.2.1".to_string()],
        port: Some("443/tcp".to_string()),
        severity: Some("7.5".to_string()),
        new_severity: Some("2.0".to_string()),
        task: Some(resource_ref("123e4567-e89b-12d3-a456-426614174001")),
        result: Some(resource_ref("123e4567-e89b-12d3-a456-426614174002")),
        active: true,
        end_time: None,
    }
}

fn resource_meta() -> SupportingResourceMeta {
    SupportingResourceMeta {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "resource".to_string(),
        comment: None,
        creation_time: None,
        modification_time: None,
        writable: true,
        in_use: false,
    }
}

fn resource_ref(id: &str) -> ResourceRef {
    ResourceRef {
        id: id.to_string(),
        name: None,
    }
}
