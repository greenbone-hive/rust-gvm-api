// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

mod common;

use common::specialized_target_harness;
use gvm_mock_server::{Resource, ResourceStore};
use http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

const SAVED_FILTER_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn seed_saved_filter(store: &ResourceStore) {
    let mut filter = Resource::with_id(
        "filter",
        "Updated specialized targets",
        Uuid::parse_str(SAVED_FILTER_ID).unwrap(),
    );
    filter.set_attr("term", "name=Updated");
    store.create(filter);
}

async fn created_id(response: reqwest::Response, collection: &str) -> String {
    assert_eq!(response.status(), StatusCode::CREATED);
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let id = response.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(location, format!("/api/v1/{collection}/{id}"));
    id
}

#[tokio::test]
async fn oci_image_target_rest_lifecycle_filter_trash_and_ultimate_delete() {
    // This contract test exercises every published OCI target operation and
    // verifies that list/delete query semantics reach the typed backend.
    let harness = specialized_target_harness(seed_saved_filter).await;
    let create = harness.client.post(harness.url("/api/v1/oci-image-targets")).bearer_auth(&harness.token).json(&json!({"name":"OCI Demo","imageReferences":["registry.example/app:1"],"comment":"initial"})).send().await.unwrap();
    let id = created_id(create, "oci-image-targets").await;

    let get = harness
        .client
        .get(harness.url(&format!("/api/v1/oci-image-targets/{id}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.json::<Value>().await.unwrap()["imageReferences"],
        json!(["registry.example/app:1"])
    );

    let update = harness
        .client
        .put(harness.url(&format!("/api/v1/oci-image-targets/{id}")))
        .bearer_auth(&harness.token)
        .json(&json!({"name":"Updated","imageReferences":["registry.example/app:2"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    assert_eq!(update.json::<Value>().await.unwrap()["name"], "Updated");

    let clone = harness
        .client
        .post(harness.url(&format!("/api/v1/oci-image-targets/{id}/clone")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    let clone_id = created_id(clone, "oci-image-targets").await;

    let list =
        harness
            .client
            .get(harness.url(
                "/api/v1/oci-image-targets?filter=name%3DUpdated&page=1&perPage=10&trash=false",
            ))
            .bearer_auth(&harness.token)
            .send()
            .await
            .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list = list.json::<Value>().await.unwrap();
    assert_eq!(list["pagination"]["perPage"], 10);
    assert!(
        list["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == id && item["name"] == "Updated"),
        "OCI inline filter commands: {:?}",
        harness
            .server
            .command_history()
            .iter()
            .filter(|record| record.command_name() == "get_oci_image_targets")
            .map(|record| String::from_utf8_lossy(record.raw_xml()).into_owned())
            .collect::<Vec<_>>()
    );

    let saved = harness
        .client
        .get(harness.url(&format!(
            "/api/v1/oci-image-targets?filterId={SAVED_FILTER_ID}"
        )))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), StatusCode::OK);
    assert!(saved.json::<Value>().await.unwrap()["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == id));

    let trash = harness
        .client
        .delete(harness.url(&format!("/api/v1/oci-image-targets/{clone_id}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(trash.status(), StatusCode::NO_CONTENT);
    let trash_list = harness
        .client
        .get(harness.url("/api/v1/oci-image-targets?trash=true"))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(trash_list.status(), StatusCode::OK);
    assert!(trash_list.json::<Value>().await.unwrap()["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == clone_id));

    let delete = harness
        .client
        .delete(harness.url(&format!("/api/v1/oci-image-targets/{id}?ultimate=true")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    assert!(harness
        .server
        .command_history()
        .iter()
        .any(|record| record.command_name() == "delete_oci_image_target"
            && String::from_utf8_lossy(record.raw_xml()).contains("ultimate=\"1\"")));
    harness.shutdown().await;
}

#[tokio::test]
async fn web_application_target_rest_lifecycle_filter_trash_and_ultimate_delete() {
    // Web application targets use a distinct DTO and command family; exercise
    // its full lifecycle independently to guard against classic-target reuse.
    let harness = specialized_target_harness(seed_saved_filter).await;
    let create = harness.client.post(harness.url("/api/v1/web-application-targets")).bearer_auth(&harness.token).json(&json!({"name":"Web Demo","urls":["https://example.com"],"excludeUrls":["https://example.com/logout"]})).send().await.unwrap();
    let id = created_id(create, "web-application-targets").await;

    let update = harness
        .client
        .put(harness.url(&format!("/api/v1/web-application-targets/{id}")))
        .bearer_auth(&harness.token)
        .json(&json!({"name":"Updated","urls":["https://example.org"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    assert_eq!(
        update.json::<Value>().await.unwrap()["urls"],
        json!(["https://example.org"])
    );

    let get = harness
        .client
        .get(harness.url(&format!("/api/v1/web-application-targets/{id}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);

    let clone = harness
        .client
        .post(harness.url(&format!("/api/v1/web-application-targets/{id}/clone")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    let clone_id = created_id(clone, "web-application-targets").await;

    let list = harness
        .client
        .get(harness.url("/api/v1/web-application-targets?filter=name%3DUpdated&trash=false"))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list = list.json::<Value>().await.unwrap();
    assert!(
        list["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == id && item["name"] == "Updated"),
        "web inline filter commands: {:?}",
        harness
            .server
            .command_history()
            .iter()
            .filter(|record| record.command_name() == "get_web_application_targets")
            .map(|record| String::from_utf8_lossy(record.raw_xml()).into_owned())
            .collect::<Vec<_>>()
    );

    let saved = harness
        .client
        .get(harness.url(&format!(
            "/api/v1/web-application-targets?filterId={SAVED_FILTER_ID}"
        )))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), StatusCode::OK);
    assert!(saved.json::<Value>().await.unwrap()["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == id));

    assert_eq!(
        harness
            .client
            .delete(harness.url(&format!("/api/v1/web-application-targets/{clone_id}")))
            .bearer_auth(&harness.token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let trash_list = harness
        .client
        .get(harness.url("/api/v1/web-application-targets?trash=true"))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(trash_list["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == clone_id));

    assert_eq!(
        harness
            .client
            .delete(harness.url(&format!(
                "/api/v1/web-application-targets/{id}?ultimate=true"
            )))
            .bearer_auth(&harness.token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(harness
        .server
        .command_history()
        .iter()
        .any(
            |record| record.command_name() == "delete_web_application_target"
                && String::from_utf8_lossy(record.raw_xml()).contains("ultimate=\"1\"")
        ));
    harness.shutdown().await;
}

#[tokio::test]
async fn web_application_target_update_preserves_replaces_and_rejects_clear_exclusions() {
    // Regression coverage for #645: omission preserves exclusions, a non-empty
    // list replaces them, and an unsupported clear fails before any gvmd call.
    let harness = specialized_target_harness(|_| {}).await;
    let create = harness
        .client
        .post(harness.url("/api/v1/web-application-targets"))
        .bearer_auth(&harness.token)
        .json(&json!({
            "name": "Exclusion semantics",
            "urls": ["https://example.com"],
            "excludeUrls": ["https://example.com/logout"]
        }))
        .send()
        .await
        .unwrap();
    let id = created_id(create, "web-application-targets").await;

    let omitted = harness
        .client
        .put(harness.url(&format!("/api/v1/web-application-targets/{id}")))
        .bearer_auth(&harness.token)
        .json(&json!({"name": "Renamed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(omitted.status(), StatusCode::OK);
    assert_eq!(
        omitted.json::<Value>().await.unwrap()["excludeUrls"],
        json!(["https://example.com/logout"])
    );

    let replaced = harness
        .client
        .put(harness.url(&format!("/api/v1/web-application-targets/{id}")))
        .bearer_auth(&harness.token)
        .json(&json!({"excludeUrls": ["https://example.com/private"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status(), StatusCode::OK);
    assert_eq!(
        replaced.json::<Value>().await.unwrap()["excludeUrls"],
        json!(["https://example.com/private"])
    );

    let commands_before_clear = harness.server.command_history().len();
    let clear = harness
        .client
        .put(harness.url(&format!("/api/v1/web-application-targets/{id}")))
        .bearer_auth(&harness.token)
        .json(&json!({"excludeUrls": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(clear.status(), StatusCode::BAD_REQUEST);
    assert_eq!(clear.json::<Value>().await.unwrap()["code"], "bad_request");
    assert_eq!(
        harness.server.command_history().len(),
        commands_before_clear,
        "an unsupported clear must be rejected before any gvmd command"
    );

    harness.shutdown().await;
}
