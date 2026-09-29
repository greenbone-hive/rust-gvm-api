// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::CreateFilterRequest;
use crate::handler::ValidateInto;

#[test]
fn create_filter_preserves_required_name_and_type_wire_name() {
    // The extracted DTO must keep the published `type` field and its existing
    // non-empty name validation contract.
    let request = serde_json::from_value::<CreateFilterRequest>(json!({
        "name": "Critical findings",
        "type": "result",
        "term": "severity>7"
    }))
    .expect("published filter payload should deserialize");
    let input = request
        .validate_into()
        .expect("published filter payload should validate");

    assert_eq!(input.name, "Critical findings");
    assert_eq!(input.filter_type.as_deref(), Some("result"));
    assert_eq!(input.term.as_deref(), Some("severity>7"));

    let missing_name = serde_json::from_value::<CreateFilterRequest>(json!({ "type": "result" }))
        .expect("missing required fields are rejected during validation");
    missing_name
        .validate_into()
        .expect_err("missing filter name should remain invalid");
}
