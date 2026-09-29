// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::{NvtListQuery, NvtSortOrder};

#[test]
fn nvt_query_maps_all_typed_options_and_rejects_invalid_values() {
    // Preserve the complete typed NVT query contract while the parser moves
    // behind the SecInfo module boundary.
    let parsed = NvtListQuery::try_from_query_string(
        "page=2&perPage=50&configId=550e8400-e29b-41d4-a716-446655440001&preferencesConfigId=550e8400-e29b-41d4-a716-446655440002&family=General&includePreferences=true&includePreferenceCount=false&includeTimeout=true&sortOrder=ascending&sortField=name",
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
        "filter=name~ssl",
        "filterId=550e8400-e29b-41d4-a716-446655440000",
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
