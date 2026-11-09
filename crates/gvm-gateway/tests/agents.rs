// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

mod common;

use common::{assert_problem_status, specialized_target_harness, target_harness};
use gvm_mock_server::{Resource, ResourceStore};
use http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

const AGENT_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const SAVED_FILTER_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const SCANNER_ID: &str = "08b69003-5fc2-4037-a479-93b440211c73";

fn seed_agent_group_filter(store: &ResourceStore) {
    let mut filter = Resource::with_id(
        "filter",
        "Updated agent groups",
        Uuid::parse_str(SAVED_FILTER_ID).unwrap(),
    );
    filter.set_attr("term", "name=Updated");
    store.create(filter);
}

fn seed_agent_resource(store: &ResourceStore) {
    let mut filter = Resource::with_id(
        "filter",
        "Managed agents",
        Uuid::parse_str(SAVED_FILTER_ID).unwrap(),
    );
    filter.set_attr("term", "name=Managed Agent");
    store.create(filter);

    let mut agent = Resource::with_id("agent", "Managed Agent", Uuid::parse_str(AGENT_ID).unwrap());
    agent.comment = "seeded agent".to_string();
    agent.set_attr("writable", "1");
    agent.set_attr("in_use", "0");
    agent.set_attr("authorized", "1");
    agent.set_attr("update_to_latest", "1");
    agent.set_attr("status", "active");
    agent.set_attr("version", "1.2.3");
    agent.set_attr("last_update_time", "2026-08-28T00:00:00Z");
    agent.set_attr("last_contact_time", "2026-08-28T00:05:00Z");
    store.create(agent);
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
async fn agent_rest_routes_cover_typed_actions_and_downloads() {
    // This black-box test exercises every published agent endpoint on a GMP
    // 22.8 backend and checks the command family rather than mock persistence.
    let harness = specialized_target_harness(seed_agent_resource).await;

    let list = harness
        .client
        .get(harness.url("/api/v1/agents?filter=name%3DManaged%20Agent&page=1&perPage=10"))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list = list.json::<Value>().await.unwrap();
    assert_eq!(list["pagination"]["perPage"], 10);

    let saved = harness
        .client
        .get(harness.url(&format!("/api/v1/agents?filterId={SAVED_FILTER_ID}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), StatusCode::OK);
    let _ = saved.json::<Value>().await.unwrap();

    let get = harness
        .client
        .get(harness.url(&format!("/api/v1/agents/{AGENT_ID}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get.json::<Value>().await.unwrap()["version"], "1.2.3");

    let update = harness
        .client
        .put(harness.url(&format!("/api/v1/agents/{AGENT_ID}")))
        .bearer_auth(&harness.token)
        .json(&json!({"authorized":false,"updateToLatest":false,"comment":"updated"}))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    assert_eq!(update.json::<Value>().await.unwrap()["id"], AGENT_ID);

    let sync = harness
        .client
        .post(harness.url("/api/v1/agents/sync"))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(sync.status(), StatusCode::NO_CONTENT);

    let bundle = harness
        .client
        .get(harness.url(&format!("/api/v1/agents/{AGENT_ID}/support-bundle?days=7")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(bundle.status(), StatusCode::OK);
    assert_eq!(
        bundle.headers().get(reqwest::header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(
        bundle
            .headers()
            .get(reqwest::header::CONTENT_DISPOSITION)
            .unwrap(),
        "attachment; filename=\"mock-agent-support-bundle.tar.gz\""
    );
    assert_eq!(bundle.bytes().await.unwrap().as_ref(), b"hello-mock");

    let control = harness
        .client
        .put(harness.url(&format!("/api/v1/agent-control-scan-configs/{SCANNER_ID}")))
        .bearer_auth(&harness.token)
        .json(&json!({"updateToLatest":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(control.status(), StatusCode::NO_CONTENT);

    let installer = harness
        .client
        .get(harness.url(&format!(
            "/api/v1/scanners/{SCANNER_ID}/agent-installer-instruction?originUrl=https%3A%2F%2Fmanager.example.invalid&language=de"
        )))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(installer.status(), StatusCode::OK);
    let installer = installer.json::<Value>().await.unwrap();
    assert_eq!(installer["language"], "de");
    assert!(installer["instruction"]
        .as_str()
        .unwrap()
        .contains("mock agent"));

    let delete = harness
        .client
        .delete(harness.url(&format!("/api/v1/agents/{AGENT_ID}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let history = harness.server.command_history();
    assert!(history.iter().any(|record| {
        record.command_name() == "get_agents"
            && String::from_utf8_lossy(record.raw_xml())
                .contains("filter=\"name=Managed Agent first=1 rows=10\"")
    }));
    assert!(history.iter().any(|record| {
        record.command_name() == "get_filters"
            && String::from_utf8_lossy(record.raw_xml()).contains(SAVED_FILTER_ID)
    }));
    assert!(history.iter().any(|record| {
        record.command_name() == "get_agents"
            && String::from_utf8_lossy(record.raw_xml())
                .contains(&format!("agent_id=\"{AGENT_ID}\""))
    }));
    assert!(history
        .iter()
        .any(|record| record.command_name() == "modify_agent"));
    assert!(history
        .iter()
        .any(|record| record.command_name() == "sync_agents"));
    assert!(history
        .iter()
        .any(|record| record.command_name() == "get_agent_support_bundle"));
    assert!(history.iter().any(|record| {
        record.command_name() == "modify_agent_control_scan_config"
            && String::from_utf8_lossy(record.raw_xml()).contains(SCANNER_ID)
    }));
    assert!(history.iter().any(|record| {
        record.command_name() == "get_agent_installer_instruction"
            && String::from_utf8_lossy(record.raw_xml()).contains("language=\"de\"")
    }));
    assert!(history
        .iter()
        .any(|record| record.command_name() == "delete_agent"));

    harness.shutdown().await;
}

#[tokio::test]
async fn agent_group_rest_lifecycle_filter_trash_and_ultimate_delete() {
    // Agent groups are fully stateful in the mock backend, so this covers the
    // complete published lifecycle including trash listing and permanent delete.
    let harness = specialized_target_harness(seed_agent_group_filter).await;

    let create = harness
        .client
        .post(harness.url("/api/v1/agent-groups"))
        .bearer_auth(&harness.token)
        .json(&json!({
            "name": "Blue Team",
            "schedulerCronTime": "0 */15 * * *",
            "comment": "initial",
            "agentIds": []
        }))
        .send()
        .await
        .unwrap();
    let id = created_id(create, "agent-groups").await;

    let get = harness
        .client
        .get(harness.url(&format!("/api/v1/agent-groups/{id}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get.json::<Value>().await.unwrap()["name"], "Blue Team");

    let update = harness
        .client
        .put(harness.url(&format!("/api/v1/agent-groups/{id}")))
        .bearer_auth(&harness.token)
        .json(&json!({
            "name": "Updated",
            "schedulerCronTime": "0 */30 * * *",
            "comment": "updated"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    let update = update.json::<Value>().await.unwrap();
    assert_eq!(update["name"], "Updated");
    assert_eq!(update["schedulerCronTime"], "0 */30 * * *");

    let clone = harness
        .client
        .post(harness.url(&format!("/api/v1/agent-groups/{id}/clone")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    let clone_id = created_id(clone, "agent-groups").await;

    let list = harness
        .client
        .get(
            harness.url("/api/v1/agent-groups?filter=name%3DUpdated&page=1&perPage=10&trash=false"),
        )
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list = list.json::<Value>().await.unwrap();
    assert_eq!(list["pagination"]["perPage"], 10);

    let saved = harness
        .client
        .get(harness.url(&format!("/api/v1/agent-groups?filterId={SAVED_FILTER_ID}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), StatusCode::OK);
    let _ = saved.json::<Value>().await.unwrap();

    let trash = harness
        .client
        .delete(harness.url(&format!("/api/v1/agent-groups/{clone_id}")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(trash.status(), StatusCode::NO_CONTENT);

    let trash_list = harness
        .client
        .get(harness.url("/api/v1/agent-groups?trash=true"))
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
        .delete(harness.url(&format!("/api/v1/agent-groups/{id}?ultimate=true")))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    assert!(harness.server.command_history().iter().any(|record| {
        record.command_name() == "get_agent_groups"
            && String::from_utf8_lossy(record.raw_xml())
                .contains("filter=\"name=Updated first=1 rows=10\"")
    }));
    assert!(harness.server.command_history().iter().any(|record| {
        record.command_name() == "get_filters"
            && String::from_utf8_lossy(record.raw_xml()).contains(SAVED_FILTER_ID)
    }));
    assert!(harness.server.command_history().iter().any(|record| {
        record.command_name() == "delete_agent_group"
            && String::from_utf8_lossy(record.raw_xml()).contains("ultimate=\"1\"")
    }));

    harness.shutdown().await;
}

#[tokio::test]
async fn agent_group_update_preserves_replaces_and_rejects_empty_agent_selection() {
    // Regression coverage for #649: omission emits no membership replacement,
    // a non-empty list does, and unsupported clearing fails before any gvmd call.
    let harness = specialized_target_harness(|_| {}).await;
    let create = harness
        .client
        .post(harness.url("/api/v1/agent-groups"))
        .bearer_auth(&harness.token)
        .json(&json!({
            "name": "Agent selection semantics",
            "schedulerCronTime": "0 */15 * * *",
            "agentIds": [AGENT_ID]
        }))
        .send()
        .await
        .unwrap();
    let id = created_id(create, "agent-groups").await;

    harness.server.clear_history();
    let omitted = harness
        .client
        .put(harness.url(&format!("/api/v1/agent-groups/{id}")))
        .bearer_auth(&harness.token)
        .json(&json!({
            "name": "Renamed without replacing agents",
            "schedulerCronTime": "0 */30 * * *"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(omitted.status(), StatusCode::OK);
    let omitted_history = harness.server.command_history();
    let omitted_modify = omitted_history
        .iter()
        .find(|record| record.command_name() == "modify_agent_group")
        .expect("omitted update should dispatch a modify command");
    assert!(
        !String::from_utf8_lossy(omitted_modify.raw_xml()).contains("<agents>"),
        "omission must not emit an agent replacement"
    );

    const REPLACEMENT_AGENT_ID: &str = "123e4567-e89b-12d3-a456-426614174001";
    harness.server.clear_history();
    let replaced = harness
        .client
        .put(harness.url(&format!("/api/v1/agent-groups/{id}")))
        .bearer_auth(&harness.token)
        .json(&json!({
            "schedulerCronTime": "0 */45 * * *",
            "agentIds": [REPLACEMENT_AGENT_ID]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status(), StatusCode::OK);
    let replaced_history = harness.server.command_history();
    let replaced_modify = replaced_history
        .iter()
        .find(|record| record.command_name() == "modify_agent_group")
        .expect("non-empty replacement should dispatch a modify command");
    let replaced_xml = String::from_utf8_lossy(replaced_modify.raw_xml());
    assert!(replaced_xml.contains("<agents>"), "xml={replaced_xml}");
    assert!(
        replaced_xml.contains(&format!("<agent id=\"{REPLACEMENT_AGENT_ID}\"")),
        "xml={replaced_xml}"
    );

    harness.server.clear_history();
    let clear = harness
        .client
        .put(harness.url(&format!("/api/v1/agent-groups/{id}")))
        .bearer_auth(&harness.token)
        .json(&json!({
            "schedulerCronTime": "0 0 * * *",
            "agentIds": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(clear.status(), StatusCode::BAD_REQUEST);
    assert_eq!(clear.json::<Value>().await.unwrap()["code"], "bad_request");
    assert!(
        harness.server.command_history().is_empty(),
        "an unsupported clear must be rejected before any gvmd command"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn agent_routes_return_not_implemented_on_gmp_22_7() {
    // Version-limited agent routes must surface backend 501 responses once the
    // reservation handler is removed, instead of regressing to 404 or 200.
    let harness = target_harness(seed_agent_resource).await;

    let response = harness
        .client
        .get(harness.url("/api/v1/agents"))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_problem_status(response, StatusCode::NOT_IMPLEMENTED).await;

    harness.shutdown().await;
}
