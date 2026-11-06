// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

mod common;

use common::specialized_target_harness;
use gvm_mock_server::Resource;
use http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

async fn assert_observer_update(
    collection: &str,
    usage_type: &str,
    update: Value,
    expected: Value,
    expected_status: StatusCode,
) {
    let id = Uuid::new_v4();
    let usage_type = usage_type.to_string();
    let harness = specialized_target_harness(move |store| {
        let target = Resource::new("target", "Scan target");
        let mut task = Resource::with_id("task", "Shared scan", id);
        task.set_attr("target_id", &target.id.to_string());
        store.create(target);
        task.set_attr("usage_type", &usage_type);
        task.set_attr("status", "New");
        task.set_attr("observers", "alice");
        store.create(task);
    })
    .await;
    let url = harness.url(&format!("/api/v1/{collection}/{id}"));
    let response = harness
        .client
        .put(&url)
        .bearer_auth(&harness.token)
        .json(&update)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let updated = response.json::<Value>().await.unwrap();
    assert_eq!(
        status, expected_status,
        "unexpected update response: {updated}"
    );
    if expected_status == StatusCode::BAD_REQUEST {
        assert_eq!(updated["code"], "bad_request");
        assert!(harness
            .server
            .command_history()
            .iter()
            .all(|record| record.command_name() != "modify_task"));
    } else {
        assert_eq!(updated["observers"]["users"], expected);
    }

    // A separate read proves backend state survived the round trip, rather
    // than relying only on the update handler's response.
    let response = harness
        .client
        .get(&url)
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let persisted = response.json::<Value>().await.unwrap();
    assert_eq!(persisted["observers"]["users"], expected);
    if expected_status == StatusCode::BAD_REQUEST {
        assert_eq!(persisted["name"], "Shared scan");
    }
    harness.shutdown().await;
}

#[tokio::test]
async fn task_and_audit_rename_preserves_omitted_observers() {
    // Regression #631: an unrelated name update must preserve existing users
    // across both REST resource families that share ModifyTaskRequest.
    for (collection, usage_type) in [("tasks", "scan"), ("audits", "audit")] {
        assert_observer_update(
            collection,
            usage_type,
            json!({"name": "Renamed"}),
            json!(["alice"]),
            StatusCode::OK,
        )
        .await;
    }
}

#[tokio::test]
async fn task_and_audit_explicit_observers_replace_existing_users() {
    // Preserving omission must not suppress an explicitly supplied replacement.
    for (collection, usage_type) in [("tasks", "scan"), ("audits", "audit")] {
        assert_observer_update(
            collection,
            usage_type,
            json!({"observers": ["bob"]}),
            json!(["bob"]),
            StatusCode::OK,
        )
        .await;
    }
}

#[tokio::test]
async fn task_and_audit_empty_observers_clear_existing_users() {
    // An explicit empty list means clear. Empty response collections are
    // omitted by the established REST DTO, so JSON indexing yields null.
    for (collection, usage_type) in [("tasks", "scan"), ("audits", "audit")] {
        assert_observer_update(
            collection,
            usage_type,
            json!({"observers": []}),
            Value::Null,
            StatusCode::OK,
        )
        .await;
    }
}

#[tokio::test]
async fn task_and_audit_null_observers_are_rejected_without_backend_mutation() {
    // Review regression #635: null is outside the array-only contract. Reject
    // the entire update before any mutation, preserving both access and name.
    for (collection, usage_type) in [("tasks", "scan"), ("audits", "audit")] {
        assert_observer_update(
            collection,
            usage_type,
            json!({"name": "Must not apply", "observers": null}),
            json!(["alice"]),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
}
