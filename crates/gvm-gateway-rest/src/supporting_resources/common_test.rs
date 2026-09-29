// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::{PaginationOnlyQuery, SupportingListQuery};
use crate::query::parse_delete_resource_query;

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
