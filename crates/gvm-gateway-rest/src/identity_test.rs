// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{
    AuthenticationType, IdentityListQuery, ModifyUserRequest, ModifyUserSettingRequest,
    UserResponse, UserSettingResponse, UserSettingsListQuery,
};
use gvm_gateway_domain::{IdentityOwner, IdentityResourceMeta, User, UserSetting};

#[test]
fn identity_queries_decode_filters_and_filter_ids() {
    let identity = IdentityListQuery::try_from_query_string(
            "filter=name~%22ops+team%22&filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000&page=3&perPage=5",
        )
        .expect("identity query should parse");
    assert_eq!(identity.filter_string.as_deref(), Some("name~\"ops team\""));
    assert_eq!(
        identity.filter_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174000")
    );
    assert_eq!(identity.page, 3);
    assert_eq!(identity.per_page, 5);

    let user_settings = UserSettingsListQuery::try_from_query_string(
        "filter=name~%22foo%20bar%22&filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000",
    )
    .expect("user settings query should parse");
    assert_eq!(
        user_settings.filter_string.as_deref(),
        Some("name~\"foo bar\"")
    );
    assert_eq!(
        user_settings.filter_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174000")
    );
}

fn user_with_auth_type(authentication_type: &str) -> User {
    User {
        meta: IdentityResourceMeta {
            id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            name: "user".to_string(),
            comment: None,
            owner: None,
            creation_time: None,
            modification_time: None,
            writable: true,
            in_use: false,
        },
        roles: vec![],
        groups: vec![],
        hosts_allow: None,
        hosts: None,
        authentication_type: Some(authentication_type.to_string()),
    }
}

#[test]
fn authentication_type_deserialization_preserves_unknown_values() {
    // User authentication backends can grow in gvmd. The response wrapper
    // must preserve that value even before request validation supports it.
    let parsed: AuthenticationType =
        serde_json::from_value(json!("oidc_connect")).expect("auth type should parse");

    assert_eq!(serde_json::to_value(parsed).unwrap(), json!("oidc_connect"));
}

#[test]
fn user_response_preserves_known_and_unknown_authentication_types() {
    // User response conversion should expose the exact backend
    // authenticationType value without coercing unknown future backends.
    let known = serde_json::to_value(UserResponse::from(user_with_auth_type("file")))
        .expect("user response should serialize");
    let unknown = serde_json::to_value(UserResponse::from(user_with_auth_type("oidc_connect")))
        .expect("user response should serialize");

    assert_eq!(known["authenticationType"], json!("file"));
    assert_eq!(unknown["authenticationType"], json!("oidc_connect"));
}

#[test]
fn modify_user_request_preserves_rename_and_explicit_role_clear() {
    // Regression coverage for #404 and #405: a user rename must be forwarded,
    // while [] remains distinguishable from an omitted roles property.
    let clear: ModifyUserRequest = serde_json::from_value(json!({
        "name": "renamed-user",
        "roles": []
    }))
    .expect("rename and empty roles should deserialize");
    let omitted: ModifyUserRequest =
        serde_json::from_value(json!({})).expect("omitted roles should deserialize");

    let clear = clear.validate().expect("empty roles are a valid clear");
    let omitted = omitted.validate().expect("omitted roles are valid");

    assert_eq!(clear.name.as_deref(), Some("renamed-user"));
    assert_eq!(clear.role_ids, Some(Vec::new()));
    assert_eq!(omitted.role_ids, None);
}

#[test]
fn modify_user_setting_requires_value_but_preserves_an_explicit_empty_clear() {
    // The PUT contract distinguishes a missing value (invalid) from an empty
    // string, which is the canonical request's explicit clear operation.
    let clear: ModifyUserSettingRequest =
        serde_json::from_value(json!({ "value": "" })).expect("empty clear should deserialize");
    assert_eq!(clear.validate().expect("empty clear is valid").value, "");

    let missing: ModifyUserSettingRequest =
        serde_json::from_value(json!({})).expect("missing value reaches validation");
    assert!(missing.validate().is_err());
}

#[test]
fn user_setting_rest_diagnostics_redact_values() {
    // REST request/response DTOs must not reintroduce values into debug output
    // after the upstream and domain layers have redacted them.
    let secret = "rest-user-setting-secret-529";
    let request: ModifyUserSettingRequest =
        serde_json::from_value(json!({ "value": secret })).expect("request should deserialize");
    let response = UserSettingResponse::from(UserSetting {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "confidential-setting".to_string(),
        value: Some(secret.to_string()),
        comment: None,
    });

    for diagnostic in [format!("{request:?}"), format!("{response:?}")] {
        assert!(diagnostic.contains("<redacted>"));
        assert!(!diagnostic.contains(secret));
    }
}

#[test]
fn user_response_preserves_name_only_owner_metadata() {
    // Typed identity responses only expose owner names today; the REST
    // contract must serialize that partial owner shape instead of faking an id.
    let user = User {
        meta: IdentityResourceMeta {
            owner: Some(IdentityOwner {
                name: "admin".to_string(),
            }),
            ..user_with_auth_type("file").meta
        },
        ..user_with_auth_type("file")
    };

    let json = serde_json::to_value(UserResponse::from(user)).expect("user response serializes");

    assert_eq!(json["owner"], json!({ "name": "admin" }));
    assert!(json["owner"].get("id").is_none());
}
