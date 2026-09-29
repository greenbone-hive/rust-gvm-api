// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::CreateTagRequest;
use crate::handler::ValidateInto;

#[test]
fn create_tag_preserves_resource_wire_names_and_uuid_validation() {
    // The extracted tag DTO must continue accepting camelCase attachment fields
    // and validating their UUID before dispatch.
    let request = serde_json::from_value::<CreateTagRequest>(json!({
        "name": "reviewed",
        "resourceType": "task",
        "resourceId": "550e8400-e29b-41d4-a716-446655440000",
        "active": true
    }))
    .expect("published tag payload should deserialize");
    let input = request
        .validate_into()
        .expect("valid tag attachment should validate");

    assert_eq!(input.resource_type.as_deref(), Some("task"));
    assert_eq!(
        input.resource_id.as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440000")
    );

    let invalid = serde_json::from_value::<CreateTagRequest>(json!({
        "name": "reviewed",
        "resourceId": "not-a-uuid"
    }))
    .expect("UUID shape is validated after deserialization");
    invalid
        .validate_into()
        .expect_err("invalid resourceId should remain rejected");
}
