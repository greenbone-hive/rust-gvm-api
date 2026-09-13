// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{FeedListQuery, FeedListResponse, FeedResponse, FeedType};
use gvm_gateway_domain::{Feed, FeedList, GatewayError};

fn feed_with_type(feed_type: &str) -> Feed {
    Feed {
        feed_type: feed_type.to_string(),
        name: "Feed".to_string(),
        version: "202606100000".to_string(),
        description: None,
        status: None,
        sync_error: None,
        sync_timestamp: None,
        currently_syncing: false,
    }
}

#[test]
fn feed_type_deserialization_preserves_unknown_values() {
    // Feed catalogs can gain new families; clients should still receive the
    // exact backend value through the open-enum wrapper.
    let parsed: FeedType =
        serde_json::from_value(json!("COMMUNITY_DATA")).expect("feed type should parse");

    assert_eq!(
        serde_json::to_value(parsed).unwrap(),
        json!("COMMUNITY_DATA")
    );
}

#[test]
fn feed_response_preserves_known_and_unknown_types() {
    // Response mapping keeps the public `type` value verbatim for both the
    // current rust-gvm enum set and backend-added feed families.
    let known = serde_json::to_value(FeedResponse::from(feed_with_type("NVT")))
        .expect("feed response should serialize");
    let unknown = serde_json::to_value(FeedResponse::from(feed_with_type("COMMUNITY_DATA")))
        .expect("feed response should serialize");

    assert_eq!(known["type"], json!("NVT"));
    assert_eq!(unknown["type"], json!("COMMUNITY_DATA"));
}

#[test]
fn feed_response_preserves_status_timestamp_error_and_access_state() {
    let response = FeedListResponse::from(FeedList {
        data: vec![Feed {
            status: Some("current".to_string()),
            sync_error: Some("lock unavailable".to_string()),
            sync_timestamp: Some("2026-08-30T19:00:00Z".to_string()),
            currently_syncing: true,
            ..feed_with_type("NVT")
        }],
        feed_owner_configured: true,
        feed_roles_configured: false,
        feed_resources_access: true,
    });

    let json = serde_json::to_value(response).unwrap();
    assert_eq!(json["data"][0]["status"], "current");
    assert_eq!(json["data"][0]["syncError"], "lock unavailable");
    assert_eq!(json["data"][0]["syncTimestamp"], "2026-08-30T19:00:00Z");
    assert_eq!(json["data"][0]["currentlySyncing"], true);
    assert_eq!(json["feedOwnerConfigured"], true);
    assert_eq!(json["feedRolesConfigured"], false);
    assert_eq!(json["feedResourcesAccess"], true);
}

#[test]
fn feed_query_accepts_one_known_type_and_rejects_unknown_inputs() {
    let query = FeedListQuery::try_from_query_string("type=GVMD_DATA").unwrap();
    assert_eq!(query.feed_type.unwrap().as_str(), "GVMD_DATA");

    for raw in ["type=FUTURE", "type=NVT&type=SCAP", "filter=name%3DFeed"] {
        assert!(matches!(
            FeedListQuery::try_from_query_string(raw),
            Err(GatewayError::InvalidInput(_))
        ));
    }
}
