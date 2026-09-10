// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Feed domain types.

use serde::{Deserialize, Serialize};

/// Domain feed status representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Feed {
    /// Feed type.
    #[serde(rename = "type")]
    pub feed_type: String,
    /// Feed display name.
    pub name: String,
    /// Feed version string.
    pub version: String,
    /// Optional description.
    pub description: Option<String>,
    /// Optional backend synchronization status.
    pub status: Option<String>,
    /// Optional synchronization-unavailable error.
    #[serde(rename = "syncError")]
    pub sync_error: Option<String>,
    /// Optional timestamp for the active synchronization.
    #[serde(rename = "syncTimestamp")]
    pub sync_timestamp: Option<String>,
    /// Whether a sync is currently running.
    #[serde(rename = "currentlySyncing")]
    pub currently_syncing: bool,
}

/// Feed-list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FeedQuery {
    /// Optional known backend feed type.
    pub feed_type: Option<String>,
}

/// Feed catalog plus backend access/configuration state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeedList {
    /// Feed entries.
    pub data: Vec<Feed>,
    /// Whether the backend feed owner is configured.
    #[serde(rename = "feedOwnerConfigured")]
    pub feed_owner_configured: bool,
    /// Whether the backend feed roles are configured.
    #[serde(rename = "feedRolesConfigured")]
    pub feed_roles_configured: bool,
    /// Whether the caller has access to feed resources.
    #[serde(rename = "feedResourcesAccess")]
    pub feed_resources_access: bool,
}
