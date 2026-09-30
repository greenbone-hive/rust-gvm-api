// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{CreateNoteRequest, ModifyNoteRequest};
use crate::handler::ValidateInto;

#[test]
fn note_requests_preserve_nvt_and_host_selector_contracts() {
    // Extraction must retain the required camelCase NVT field and the semantic
    // difference between an omitted host selector and an explicit empty list.
    let create = serde_json::from_value::<CreateNoteRequest>(json!({
        "nvtOid": "1.3.6.1.4.1.25623.1.0.100000",
        "taskId": "550e8400-e29b-41d4-a716-446655440000"
    }))
    .expect("published note payload should deserialize");
    let create_input = create
        .validate_into()
        .expect("published note payload should validate");
    assert_eq!(create_input.nvt_oid, "1.3.6.1.4.1.25623.1.0.100000");
    assert!(create_input.hosts.is_empty());

    let omitted = serde_json::from_value::<ModifyNoteRequest>(json!({}))
        .expect("empty update payload should deserialize")
        .validate_into()
        .expect("empty update payload should validate");
    let cleared = serde_json::from_value::<ModifyNoteRequest>(json!({ "hosts": [] }))
        .expect("host-clearing payload should deserialize")
        .validate_into()
        .expect("host-clearing payload should validate");
    assert_eq!(omitted.hosts, None);
    assert_eq!(cleared.hosts, Some(Vec::new()));
}
