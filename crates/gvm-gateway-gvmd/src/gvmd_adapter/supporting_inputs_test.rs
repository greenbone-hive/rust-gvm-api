// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::*;

#[test]
fn omitted_modify_collections_leave_backend_values_unchanged() {
    // Target, note, and override modification paths share this conversion. An
    // absent REST field must not clear any of their backend collections.
    assert_eq!(collection_update(None), CollectionUpdate::Omitted);
}

#[test]
fn explicitly_empty_modify_collections_clear_backend_values() {
    // Target, note, and override modification paths share this conversion. An
    // explicit empty array must remain an intentional clear for each path.
    assert_eq!(collection_update(Some(Vec::new())), CollectionUpdate::Clear);
}

#[test]
fn nonempty_modify_collections_replace_backend_values() {
    // A populated REST hosts array replaces the backend collection exactly.
    assert_eq!(
        collection_update(Some(vec!["192.0.2.1".to_string()])),
        CollectionUpdate::Replace(vec!["192.0.2.1".to_string()])
    );
}
