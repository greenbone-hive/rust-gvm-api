// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

mod common;

use common::specialized_target_harness;
use gvm_mock_server::{Resource, ResourceStore};
use http::StatusCode;
use serde_json::Value;
use uuid::Uuid;

const USER_ID: &str = "550e8400-e29b-41d4-a716-446655440123";

fn seed_user(store: &ResourceStore) {
    store.create(Resource::with_id(
        "user",
        "delete-contract-user",
        Uuid::parse_str(USER_ID).expect("valid user id"),
    ));
}

#[tokio::test]
async fn user_delete_rejects_all_ultimate_forms_before_backend_dispatch() {
    // The HTTP contract exposes only plain DELETE. Every legacy query shape
    // must fail with the same problem response while leaving gvmd untouched.
    let harness = specialized_target_harness(seed_user).await;
    harness.server.clear_history();

    for query in [
        "ultimate=true",
        "ultimate=false",
        "ultimate=",
        "ultimate",
        "ultimate=true&ultimate=false",
        "ultimate=not-a-bool",
        "ult%69mate=true",
    ] {
        let response = harness
            .client
            .delete(harness.url(&format!("/api/v1/users/{USER_ID}?{query}")))
            .bearer_auth(&harness.token)
            .send()
            .await
            .expect("unsupported ultimate response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query={query}");
        let problem = response.json::<Value>().await.expect("problem JSON");
        assert_eq!(problem["code"], "bad_request", "query={query}");
    }

    assert!(
        harness
            .server
            .command_history()
            .iter()
            .all(|record| record.command_name() != "delete_user"),
        "unsupported queries must not dispatch user deletion"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn plain_user_delete_dispatches_one_canonical_typed_command() {
    // Plain DELETE remains supported and must emit exactly the rust-gvm typed
    // user-delete shape, with no invented permanence attribute.
    let harness = specialized_target_harness(seed_user).await;
    harness.server.clear_history();

    let response = harness
        .client
        .delete(harness.url(&format!("/api/v1/users/{USER_ID}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .expect("plain user delete response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let history = harness.server.command_history();
    let commands = history
        .iter()
        .filter(|record| record.command_name() == "delete_user")
        .collect::<Vec<_>>();
    assert_eq!(commands.len(), 1);
    let xml = String::from_utf8(commands[0].raw_xml().to_vec()).expect("delete XML");
    assert!(xml.contains(&format!("user_id=\"{USER_ID}\"")), "xml={xml}");
    assert!(!xml.contains("ultimate"), "xml={xml}");

    harness.shutdown().await;
}
