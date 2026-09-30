// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{CreateOverrideRequest, ModifyOverrideRequest};
use crate::handler::ValidateInto;

#[test]
fn override_requests_preserve_severity_and_host_selector_contracts() {
    // Extraction must retain the explicit `newSeverity` wire name and the
    // omitted-versus-empty host selector semantics used by modify operations.
    let create = serde_json::from_value::<CreateOverrideRequest>(json!({
        "nvtOid": "1.3.6.1.4.1.25623.1.0.100000",
        "newSeverity": "5.0"
    }))
    .expect("published override payload should deserialize");
    let create_input = create
        .validate_into()
        .expect("published override payload should validate");
    assert_eq!(create_input.new_severity.as_deref(), Some("5.0"));

    let omitted = serde_json::from_value::<ModifyOverrideRequest>(json!({}))
        .expect("empty update payload should deserialize")
        .validate_into()
        .expect("empty update payload should validate");
    let cleared = serde_json::from_value::<ModifyOverrideRequest>(json!({ "hosts": [] }))
        .expect("host-clearing payload should deserialize")
        .validate_into()
        .expect("host-clearing payload should validate");
    assert_eq!(omitted.hosts, None);
    assert_eq!(cleared.hosts, Some(Vec::new()));
}
