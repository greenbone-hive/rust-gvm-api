// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{
    reject_host_ultimate_query, reject_operating_system_ultimate_query, ModifyHostRequest,
    ModifyOperatingSystemRequest, NvtListQuery, NvtSortOrder, OperatingSystemResponse,
    PaginationOnlyQuery, SupportingListQuery,
};
use crate::query::parse_delete_resource_query;
use gvm_gateway_domain::{OperatingSystem, OperatingSystemHost, SupportingResourceMeta};

#[test]
fn supporting_query_decodes_percent_encoded_filter_values() {
    let parsed = SupportingListQuery::try_from_query_string(
        "filter=name~webserver%20and%20severity%3E5&perPage=10&page=2",
    )
    .expect("supporting-resource query should parse");

    assert_eq!(
        parsed.filter_string.as_deref(),
        Some("name~webserver and severity>5")
    );
    assert_eq!(parsed.page, 2);
    assert_eq!(parsed.per_page, 10);
}

#[test]
fn supporting_query_rejects_zero_page_after_decoding() {
    let error = SupportingListQuery::try_from_query_string("page=0")
        .expect_err("page=0 should remain invalid");

    match error {
        gvm_gateway_domain::GatewayError::InvalidInput(detail) => {
            assert_eq!(detail, "page must be greater than or equal to 1");
        }
        other => panic!("unexpected error variant: {:?}", other),
    }
}

#[test]
fn nvt_query_maps_all_typed_options_and_rejects_invalid_values() {
    let parsed = NvtListQuery::try_from_query_string(
        "filter=name~ssl&filterId=550e8400-e29b-41d4-a716-446655440000&page=2&perPage=50&configId=550e8400-e29b-41d4-a716-446655440001&preferencesConfigId=550e8400-e29b-41d4-a716-446655440002&family=General&includePreferences=true&includePreferenceCount=false&includeTimeout=true&sortOrder=ascending&sortField=name",
    )
    .expect("typed NVT query should parse");

    assert_eq!(parsed.page, 2);
    assert_eq!(parsed.per_page, 50);
    assert_eq!(parsed.family.as_deref(), Some("General"));
    assert_eq!(parsed.include_preferences, Some(true));
    assert_eq!(parsed.include_preference_count, Some(false));
    assert_eq!(parsed.include_timeout, Some(true));
    assert_eq!(parsed.sort_order, Some(NvtSortOrder::Ascending));
    assert_eq!(parsed.sort_field.as_deref(), Some("name"));

    for query in [
        "sortOrder=sideways",
        "includePreferences=1",
        "configId=not-a-uuid",
        "includeTimeout=true",
        "family=%20",
        "unknown=value",
    ] {
        NvtListQuery::try_from_query_string(query)
            .expect_err("invalid NVT query value should be rejected");
    }
}

#[test]
fn pagination_only_query_rejects_filter_params() {
    let error = PaginationOnlyQuery::try_from_query_string("filter=name~general")
        .expect_err("filter should be rejected");

    match error {
        gvm_gateway_domain::GatewayError::InvalidInput(detail) => {
            assert_eq!(detail, "filter is not supported on this endpoint");
        }
        other => panic!("unexpected error variant: {:?}", other),
    }
}

#[test]
fn delete_supporting_resource_query_rejects_invalid_bool() {
    let error = parse_delete_resource_query("ultimate=not-bool")
        .expect_err("invalid ultimate bool should be rejected");

    match error {
        gvm_gateway_domain::GatewayError::InvalidInput(detail) => {
            assert_eq!(detail, "ultimate must be true or false");
        }
        other => panic!("unexpected error variant: {:?}", other),
    }
}

#[test]
fn modify_host_request_rejects_unknown_value_field() {
    // gvmd cannot change a host asset's name/IP, so a `PUT /hosts/{id}` body
    // carrying `value` must be a 400 rather than a silently ignored mutation.
    let error = serde_json::from_value::<ModifyHostRequest>(json!({
        "comment": "lab host",
        "value": "192.0.2.10"
    }))
    .expect_err("unknown `value` field should be rejected");
    assert!(
        error.to_string().contains("value"),
        "error should name the rejected field: {error}"
    );

    // A comment-only body still parses.
    serde_json::from_value::<ModifyHostRequest>(json!({ "comment": "lab host" }))
        .expect("comment-only body should parse");
}

#[test]
fn host_delete_rejects_ultimate_query() {
    // gvmd's host-asset delete ignores `ultimate`, so any form of the flag is a
    // 400 rather than a silent ordinary delete reported as permanent.
    for query in [
        "ultimate=true",
        "ultimate=false",
        "ultimate",
        "comment=x&ultimate=true",
        // Percent-encoded query keys must not bypass the boundary check.
        "ult%69mate=true",
    ] {
        let error = reject_host_ultimate_query(Some(query))
            .expect_err("ultimate must be rejected for host deletion");
        match error {
            gvm_gateway_domain::GatewayError::InvalidInput(detail) => assert!(
                detail.contains("ultimate"),
                "detail should mention ultimate: {detail}"
            ),
            other => panic!("unexpected error variant: {:?}", other),
        }
    }

    // Absent, empty, and unrelated query strings are accepted.
    reject_host_ultimate_query(None).expect("no query is fine");
    reject_host_ultimate_query(Some("")).expect("empty query is fine");
    reject_host_ultimate_query(Some("foo=bar")).expect("unrelated params are fine");
}

#[test]
fn operating_system_update_rejects_backend_unsupported_fields() {
    // Only comment is accepted by rust-gvm's typed modify-OS builder. REST must
    // reject attempts to mutate display or aggregate fields instead of silently
    // reporting a successful no-op.
    serde_json::from_value::<ModifyOperatingSystemRequest>(json!({
        "comment": "reviewed"
    }))
    .expect("comment-only OS update should parse");

    for unsupported in [
        json!({ "name": "Renamed OS" }),
        json!({ "title": "Renamed OS" }),
        json!({ "value": "cpe:/o:example" }),
        json!({ "inUse": false }),
    ] {
        serde_json::from_value::<ModifyOperatingSystemRequest>(unsupported)
            .expect_err("unsupported OS mutation field must be rejected");
    }
}

#[test]
fn operating_system_delete_rejects_permanent_delete_query() {
    // rust-gvm's typed OS delete builder has no ultimate option. Every spelling
    // of that query must fail before dispatch so clients cannot mistake an
    // ordinary delete for a requested permanent-delete mode.
    for query in [
        "ultimate=true",
        "ultimate=false",
        "ultimate",
        "foo=bar&ultimate=true",
        "ult%69mate=true",
    ] {
        reject_operating_system_ultimate_query(Some(query))
            .expect_err("ultimate must be rejected for OS deletion");
    }
    reject_operating_system_ultimate_query(None).expect("no query is supported");
    reject_operating_system_ultimate_query(Some("foo=bar")).expect("unrelated query is supported");
}

#[test]
fn operating_system_response_preserves_typed_asset_view() {
    // The public OS resource must preserve typed asset metadata and aggregates,
    // including nested host observations, without collapsing to a generic asset.
    let value = serde_json::to_value(OperatingSystemResponse::from(OperatingSystem {
        meta: SupportingResourceMeta {
            id: "550e8400-e29b-41d4-a716-446655440131".to_string(),
            name: "cpe:/o:debian:debian_linux:12".to_string(),
            comment: Some("reviewed".to_string()),
            creation_time: Some("2026-08-29T00:00:00Z".to_string()),
            modification_time: Some("2026-08-29T01:00:00Z".to_string()),
            writable: false,
            in_use: true,
        },
        value: Some("cpe:/o:debian:debian_linux:12".to_string()),
        hosts_count: Some(1),
        severity: Some("7.5".to_string()),
        title: "Debian GNU/Linux 12".to_string(),
        installs: 1,
        all_installs: 3,
        latest_severity: Some("7.5".to_string()),
        highest_severity: Some("9.0".to_string()),
        average_severity: Some("6.2".to_string()),
        host_count: 1,
        hosts: vec![OperatingSystemHost {
            id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            name: "192.0.2.10".to_string(),
            severity: Some("7.5".to_string()),
        }],
    }))
    .expect("OS response JSON");

    assert_eq!(value["title"], json!("Debian GNU/Linux 12"));
    assert_eq!(value["inUse"], json!(true));
    assert_eq!(value["allInstalls"], json!(3));
    assert_eq!(value["hosts"][0]["name"], json!("192.0.2.10"));
    assert!(value.get("assetType").is_none());
}
