// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

mod common;

use common::specialized_target_harness;
use gvm_mock_server::{Resource, ResourceStore};
use http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

const HOST_ID: &str = "123e4567-e89b-12d3-a456-426614174010";
const FUTURE_CONFIG_ID: &str = "123e4567-e89b-12d3-a456-426614174020";

fn seed_generic_resources(store: &ResourceStore) {
    let mut host = Resource::with_id("asset", "192.0.2.42", Uuid::parse_str(HOST_ID).unwrap());
    host.comment = "initial generic host".to_string();
    host.set_attr("type", "host");
    host.set_attr("severity", "5.0");
    store.create(host);

    let mut config = Resource::with_id(
        "config",
        "Future config",
        Uuid::parse_str(FUTURE_CONFIG_ID).unwrap(),
    );
    config.comment = "open discriminator seed".to_string();
    config.set_attr("usage_type", "future_usage");
    config.set_attr("type", "42");
    store.create(config);
}

#[tokio::test]
async fn generic_asset_rest_contract_scopes_reads_and_limits_mutation() {
    // This stateful boundary proves REST pagination and the explicit type reach
    // typed get_assets calls, while mutation stays comment-only and deletion
    // never invents an unsupported ultimate GMP attribute.
    let harness = specialized_target_harness(seed_generic_resources).await;

    let list = harness
        .client
        .get(harness.url("/api/v1/assets?type=host&page=1&perPage=10"))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list = list.json::<Value>().await.unwrap();
    assert_eq!(list["pagination"]["perPage"], 10);
    assert!(list["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|asset| asset["id"] == HOST_ID && asset["type"] == "host"));

    let get = harness
        .client
        .get(harness.url(&format!("/api/v1/assets/{HOST_ID}?type=host")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get.json::<Value>().await.unwrap()["type"], "host");

    let update = harness
        .client
        .put(harness.url(&format!("/api/v1/assets/{HOST_ID}?type=host")))
        .bearer_auth(&harness.token)
        .json(&json!({"comment":"updated through generic REST"}))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    assert_eq!(
        update.json::<Value>().await.unwrap()["comment"],
        "updated through generic REST"
    );

    let unsupported = harness
        .client
        .delete(harness.url(&format!("/api/v1/assets/{HOST_ID}?ultimate=false")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);

    let delete = harness
        .client
        .delete(harness.url(&format!("/api/v1/assets/{HOST_ID}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let history = harness.server.command_history();
    assert!(history
        .iter()
        .filter(|record| record.command_name() == "get_assets")
        .all(|record| { String::from_utf8_lossy(record.raw_xml()).contains("type=\"host\"") }));
    let modify = history
        .iter()
        .find(|record| record.command_name() == "modify_asset")
        .expect("REST update should emit modify_asset");
    let modify_xml = String::from_utf8_lossy(modify.raw_xml());
    assert!(modify_xml.contains("<comment>updated through generic REST</comment>"));
    assert!(!modify_xml.contains("<value>"));
    let delete = history
        .iter()
        .find(|record| record.command_name() == "delete_asset")
        .expect("REST delete should emit delete_asset");
    assert!(!String::from_utf8_lossy(delete.raw_xml()).contains("ultimate"));

    harness.shutdown().await;
}

#[tokio::test]
async fn generic_config_rest_contract_preserves_open_usage_clone_and_ultimate() {
    // This contract covers an unknown usageType through list and single-resource
    // response parsing, then verifies clone Location and supported permanent
    // deletion.
    let harness = specialized_target_harness(seed_generic_resources).await;

    let list = harness
        .client
        .get(harness.url("/api/v1/configs?usageType=future_usage&page=1&perPage=10"))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list = list.json::<Value>().await.unwrap();
    assert_eq!(list["pagination"]["perPage"], 10);
    assert_eq!(list["data"].as_array().map(Vec::len), Some(1));
    assert_eq!(list["data"][0]["id"], FUTURE_CONFIG_ID);
    assert_eq!(list["data"][0]["usageType"], "future_usage");

    let get = harness
        .client
        .get(harness.url(&format!("/api/v1/configs/{FUTURE_CONFIG_ID}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.json::<Value>().await.unwrap()["usageType"],
        "future_usage"
    );

    let clone = harness
        .client
        .post(harness.url(&format!("/api/v1/configs/{FUTURE_CONFIG_ID}/clone")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(clone.status(), StatusCode::CREATED);
    let location = clone
        .headers()
        .get(reqwest::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let cloned_id = clone.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(location, format!("/api/v1/configs/{cloned_id}"));

    let delete = harness
        .client
        .delete(harness.url(&format!("/api/v1/configs/{cloned_id}?ultimate=true")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let history = harness.server.command_history();
    assert!(history.iter().any(|record| {
        record.command_name() == "get_configs"
            && String::from_utf8_lossy(record.raw_xml())
                .contains("filter=\"usage_type=future_usage")
    }));
    assert!(history.iter().any(|record| {
        record.command_name() == "create_config"
            && String::from_utf8_lossy(record.raw_xml())
                .contains(&format!("<copy>{FUTURE_CONFIG_ID}</copy>"))
    }));
    assert!(history.iter().any(|record| {
        record.command_name() == "delete_config"
            && String::from_utf8_lossy(record.raw_xml()).contains("ultimate=\"1\"")
    }));

    harness.shutdown().await;
}
