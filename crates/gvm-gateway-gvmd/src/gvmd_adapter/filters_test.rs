// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_gateway_domain::GatewayError;

use super::filters::{
    gvmd_total, paged_pagination, paged_slice, paginated_filter,
    paginated_filter_with_reserved_terms,
};

#[test]
fn canonical_list_counts_drive_rest_pagination() {
    // Task and audit canonical responses expose filtered/full counts. The
    // adapter must prefer the filtered total and retain the existing REST page
    // arithmetic, falling back to decoded item count only when both are absent.
    assert_eq!(gvmd_total(Some(51), Some(80), 25), 51);
    assert_eq!(gvmd_total(None, Some(80), 25), 80);
    assert_eq!(gvmd_total(None, None, 25), 25);

    let pagination = paged_pagination(51, 3, 25);
    assert_eq!(pagination.page, 3);
    assert_eq!(pagination.per_page, 25);
    assert_eq!(pagination.total, 51);
    assert_eq!(pagination.total_pages, 3);
}

#[test]
fn paged_slice_treats_maximum_page_as_out_of_range() {
    // An extreme page must produce the normal empty out-of-range page instead
    // of overflowing the client-side fallback offset and wrapping to old data.
    assert!(paged_slice(vec!["first", "second"], u32::MAX, 1_000).is_empty());
}

#[test]
fn paginated_filter_appends_backend_paging_terms() {
    // GMP filter paging is one-based: page 3 with 25 rows starts at item 51.
    assert_eq!(
        paginated_filter(Some("report_id=abc"), Some("severity>5"), 3, 25),
        Ok(Some(
            "report_id=abc severity>5 first=51 rows=25".to_string()
        ))
    );
    assert_eq!(
        paginated_filter(None, Some("   "), 1, 10),
        Ok(Some("first=1 rows=10".to_string()))
    );
}

#[test]
fn paginated_filter_rejects_caller_pagination_terms() {
    // User filter fragments must not override backend pagination terms that
    // the gateway appends after validation.
    let result = paginated_filter(None, Some("severity>5 first=1"), 3, 25);

    assert!(matches!(
        result,
        Err(GatewayError::InvalidInput(detail))
            if detail == "filter contains reserved term 'first'"
    ));
}

#[test]
fn paginated_filter_rejects_endpoint_owned_scope_terms() {
    // Report-scoped endpoints add report_id themselves, so a caller filter
    // may not inject another report_id clause.
    let result = paginated_filter_with_reserved_terms(
        Some("report_id=abc"),
        Some("report_id=def severity>5"),
        1,
        25,
        &["report_id"],
    );

    assert!(matches!(
        result,
        Err(GatewayError::InvalidInput(detail))
            if detail == "filter contains reserved term 'report_id'"
    ));
}
