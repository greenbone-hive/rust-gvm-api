// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::env;

use anyhow::{bail, Context, Result};
use gvm_gateway_e2e::harness::{assert_problem_response_any, E2eHarness};
use reqwest::{header, Method, StatusCode};
use serde_json::{json, Value};

const AGENT_CONTROLLER_SCANNER_ID: &str = "3b4be213-281f-49ee-b457-5a5f34f71510";

// Covers the additive enterprise feature surface against a feature-enabled gvmd and the
// stateful Agent Control profile. The workflow runs the typed get_version/get_features
// preflight before selecting this test, so any route failure here is a contract failure rather
// than a feature/configuration mismatch. One serialized lifecycle makes the mutation/read-back,
// task correlation, and reverse-order cleanup guarantees explicit and repeatable.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the enterprise Agent Control compose profile and successful typed preflight"]
async fn rest_enterprise_agent_control_lifecycle_is_repeatable_and_fail_closed() -> Result<()> {
    // The universal OSP E2E runner deliberately includes ignored tests. Keep this
    // enterprise-only lifecycle inert unless the dedicated runner has completed
    // typed feature preflight and explicitly selected the Agent Control profile.
    if env::var("GVM_GATEWAY_E2E_ENTERPRISE_AGENT_CONTROL").as_deref() != Ok("1") {
        eprintln!("enterprise Agent Control profile not selected; contract not run");
        return Ok(());
    }
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;

    assert_route_auth_and_input_failures(&harness).await?;
    let session = harness.create_session().await?;
    let token = session.token.as_str();
    let mut report_id: Option<String> = None;
    let mut task_id: Option<String> = None;
    let mut clone_id: Option<String> = None;
    let mut group_id: Option<String> = None;
    let mut agent_restore: Option<(String, Value)> = None;

    let run = async {
        let agents = get_json(
            &harness,
            Method::GET,
            "/api/v1/agents?page=1&perPage=1",
            token,
            StatusCode::OK,
        )
        .await?;
        assert_eq!(agents["pagination"]["page"], 1, "agent page must echo page=1");
        assert_eq!(
            agents["pagination"]["perPage"], 1,
            "agent page must echo perPage=1"
        );
        let agent = agents["data"]
            .as_array()
            .and_then(|items| items.first())
            .context("stateful Agent Control profile must expose at least one agent after sync")?;
        let agent_id = required_string(agent, "id")?;
        let agent_target = required_string(agent, "name")?;

        let original = get_json(
            &harness,
            Method::GET,
            &format!("/api/v1/agents/{agent_id}"),
            token,
            StatusCode::OK,
        )
        .await?;
        let restoration = agent_restoration(&original)?;
        agent_restore = Some((agent_id.to_string(), restoration.clone()));
        assert_agent_control_failure_contracts(
            &harness,
            token,
            agent_id,
            &restoration,
            &original,
        )
        .await?;
        let unique = harness.unique_name("issue-680-agent");
        let mutation = json!({
            "authorized": true,
            "updateToLatest": true,
            "comment": unique,
            "config": {
                "agentControl": {"retry": {"attempts": 4, "delayInSeconds": 9, "maxJitterInSeconds": 2}},
                "heartbeat": {"intervalInSeconds": 45, "missUntilInactive": 3}
            }
        });
        let updated = send_json(
            &harness,
            Method::PUT,
            &format!("/api/v1/agents/{agent_id}"),
            token,
            &mutation,
            StatusCode::OK,
        )
        .await?;
        assert_agent_mutation(&updated, &unique);
        let read_back = get_json(
            &harness,
            Method::GET,
            &format!("/api/v1/agents/{agent_id}"),
            token,
            StatusCode::OK,
        )
        .await?;
        assert_agent_mutation(&read_back, &unique);

        let scan_config = json!({
            "agentDefaults": {
                "agentControl": {"retry": {"attempts": 5, "delayInSeconds": 10, "maxJitterInSeconds": 3}},
                "heartbeat": {"intervalInSeconds": 60, "missUntilInactive": 4}
            },
            "updateToLatest": true
        });
        assert_empty(
            harness
                .request(
                    Method::PUT,
                    &format!(
                        "/api/v1/agent-control-scan-configs/{AGENT_CONTROLLER_SCANNER_ID}"
                    ),
                )
                .bearer_auth(token)
                .json(&scan_config)
                .send()
                .await?,
            StatusCode::NO_CONTENT,
            "scan-agent configuration update",
        )
        .await?;

        assert_empty(
            harness
                .request(Method::POST, "/api/v1/agents/sync")
                .bearer_auth(token)
                .send()
                .await?,
            StatusCode::NO_CONTENT,
            "agent synchronization",
        )
        .await?;
        let synchronized = get_json(
            &harness,
            Method::GET,
            &format!("/api/v1/agents/{agent_id}"),
            token,
            StatusCode::OK,
        )
        .await?;
        assert_eq!(synchronized["updateToLatest"], true);
        assert_eq!(
            synchronized["config"]["agentControl"]["retry"]["attempts"],
            5,
            "scan-agent default retry configuration must be visible after synchronization"
        );
        assert_eq!(
            synchronized["config"]["heartbeat"]["intervalInSeconds"],
            60,
            "scan-agent default heartbeat configuration must be visible after synchronization"
        );
        assert!(
            synchronized.get("status").is_some(),
            "synchronized agent must retain update/synchronization state"
        );

        let support = harness
            .request(
                Method::GET,
                &format!("/api/v1/agents/{agent_id}/support-bundle?days=1&encryption=false"),
            )
            .bearer_auth(token)
            .send()
            .await?;
        assert_eq!(support.status(), StatusCode::OK);
        let content_type = support
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            ["application/octet-stream", "application/gzip", "application/zip"]
                .iter()
                .any(|expected| content_type.starts_with(expected)),
            "unexpected support-bundle content type: {content_type}"
        );
        assert!(
            support.headers().contains_key(header::CONTENT_DISPOSITION),
            "support bundle must include Content-Disposition"
        );
        assert!(!support.bytes().await?.is_empty(), "support bundle must not be empty");

        let instruction = get_json(
            &harness,
            Method::GET,
            &format!(
                "/api/v1/scanners/{AGENT_CONTROLLER_SCANNER_ID}/agent-installer-instruction?originUrl=https%3A%2F%2Fmanager.example&language=en"
            ),
            token,
            StatusCode::OK,
        )
        .await?;
        assert_eq!(instruction["language"], "en");
        assert!(
            instruction["instruction"].as_str().is_some_and(|value| !value.is_empty()),
            "installer instruction must contain a non-empty body"
        );

        let group_name = harness.unique_name("issue-680-agent-group");
        let created = send_json_with_location(
            &harness,
            Method::POST,
            "/api/v1/agent-groups",
            token,
            &json!({
                "name": group_name,
                "comment": "issue-680 initial",
                "schedulerCronTime": "0 3 * * *",
                "agentIds": [agent_id]
            }),
            StatusCode::CREATED,
            "/api/v1/agent-groups/",
        )
        .await?;
        let created_group_id = required_string(&created, "id")?.to_string();
        group_id = Some(created_group_id.clone());
        let modified_group_name = format!("{group_name}-updated");
        let modified_group = send_json(
            &harness,
            Method::PUT,
            &format!("/api/v1/agent-groups/{created_group_id}"),
            token,
            &json!({
                "name": modified_group_name,
                "comment": "issue-680 read-back",
                "schedulerCronTime": "15 4 * * *",
                "agentIds": [agent_id]
            }),
            StatusCode::OK,
        )
        .await?;
        assert_eq!(modified_group["name"], modified_group_name);
        let listed_groups = get_json(
            &harness,
            Method::GET,
            "/api/v1/agent-groups?page=1&perPage=100",
            token,
            StatusCode::OK,
        )
        .await?;
        assert!(listed_groups["data"].as_array().is_some_and(|items| items
            .iter()
            .any(|item| item["id"] == created_group_id && item["name"] == modified_group_name)));

        let cloned = send_json_with_location(
            &harness,
            Method::POST,
            &format!("/api/v1/agent-groups/{created_group_id}/clone"),
            token,
            &Value::Null,
            StatusCode::CREATED,
            "/api/v1/agent-groups/",
        )
        .await?;
        clone_id = Some(required_string(&cloned, "id")?.to_string());

        let task = send_json_with_location(
            &harness,
            Method::POST,
            "/api/v1/tasks",
            token,
            &json!({
                "name": harness.unique_name("issue-680-agent-backed-scan"),
                "comment": "same promoted community direct-OpenVASD substrate",
                "type": "agentGroup",
                "agentGroupId": created_group_id,
                "scannerId": AGENT_CONTROLLER_SCANNER_ID
            }),
            StatusCode::CREATED,
            "/api/v1/tasks/",
        )
        .await?;
        task_id = Some(required_string(&task, "id")?.to_string());
        let task_read = get_json(
            &harness,
            Method::GET,
            &format!("/api/v1/tasks/{}", task_id.as_deref().unwrap_or_default()),
            token,
            StatusCode::OK,
        )
        .await?;
        assert_eq!(task_read["agentGroup"]["id"], created_group_id);
        assert_eq!(task_read["scanner"]["id"], AGENT_CONTROLLER_SCANNER_ID);
        let started = get_json(
            &harness,
            Method::POST,
            &format!(
                "/api/v1/tasks/{}/start",
                task_id.as_deref().unwrap_or_default()
            ),
            token,
            StatusCode::OK,
        )
        .await?;
        assert!(
            started["reportId"]
                .as_str()
                .is_some_and(|report_id| !report_id.is_empty()),
            "agent-backed scan must return its correlated gvmd report"
        );
        report_id = Some(required_string(&started, "reportId")?.to_string());
        let completed = harness
            .wait_for_task_completion(token, task_id.as_deref().unwrap_or_default())
            .await?;
        let completed_report = completed
            .last_report
            .as_ref()
            .or(completed.current_report.as_ref())
            .context("completed agent-backed scan must reference a report")?;
        assert_eq!(
            Some(completed_report.id.as_str()),
            started["reportId"].as_str(),
            "agent-backed task and report correlation drifted"
        );
        assert_eq!(
            completed.scanner.as_ref().map(|scanner| scanner.id.as_str()),
            Some(AGENT_CONTROLLER_SCANNER_ID),
            "completed task must remain bound to the Agent Controller scanner"
        );
        assert_eq!(
            completed.agent_group.as_ref().map(|group| group.id.as_str()),
            Some(created_group_id.as_str()),
            "completed task must remain bound to the selected Agent Control group"
        );

        let report_path = format!(
            "/api/v1/reports/{}?page=1&perPage=100",
            report_id.as_deref().unwrap_or_default()
        );
        let report = get_json(&harness, Method::GET, &report_path, token, StatusCode::OK).await?;
        assert_eq!(report["id"], report_id.as_deref().unwrap_or_default());
        assert_eq!(
            report["task"]["id"],
            task_id.as_deref().unwrap_or_default(),
            "completed report must be bound to the created agent-group task"
        );
        assert_eq!(
            task_read["scanner"]["id"], AGENT_CONTROLLER_SCANNER_ID,
            "the report's owning task must retain the Agent Controller scanner"
        );

        let results_path = format!(
            "/api/v1/reports/{}/results?page=1&perPage=100",
            report_id.as_deref().unwrap_or_default()
        );
        let results = get_json(
            &harness,
            Method::GET,
            &results_path,
            token,
            StatusCode::OK,
        )
        .await?;
        assert_eq!(results["pagination"]["page"], 1);
        assert_eq!(results["pagination"]["perPage"], 100);
        let matching_result = results["data"]
            .as_array()
            .and_then(|items| {
                items.iter().find(|result| {
                    result_evidence(result).contains(agent_id)
                        && result["host"].as_str() == Some(agent_target)
                })
            })
            .with_context(|| {
                format!(
                    "completed report must contain the seeded Agent Control result for target \
                     {agent_target:?} with agent id {agent_id:?}: {}",
                    results["data"]
                )
            })?;
        assert_eq!(
            matching_result["task"]["id"],
            task_id.as_deref().unwrap_or_default(),
            "community-shaped result must reference the created task"
        );
        assert_eq!(
            matching_result["report"]["id"],
            report_id.as_deref().unwrap_or_default(),
            "community-shaped result must reference the completed report"
        );

        Ok(())
    }
    .await;

    // Reverse mutation order is intentional: report -> task -> clone -> group -> agent -> session.
    let report_cleanup = delete_report(&harness, token, report_id.as_deref()).await;
    let task_cleanup = delete_resource(&harness, token, "/api/v1/tasks", task_id.as_deref()).await;
    let clone_cleanup =
        delete_resource(&harness, token, "/api/v1/agent-groups", clone_id.as_deref()).await;
    let group_cleanup =
        delete_resource(&harness, token, "/api/v1/agent-groups", group_id.as_deref()).await;
    let agent_cleanup = match agent_restore {
        Some((agent_id, restoration)) => {
            restore_agent(&harness, token, &agent_id, &restoration).await
        }
        None => Ok(()),
    };
    let session_cleanup = harness.delete_session(token).await;

    if let Err(error) = run {
        for cleanup_error in [
            report_cleanup.err(),
            task_cleanup.err(),
            clone_cleanup.err(),
            group_cleanup.err(),
            agent_cleanup.err(),
            session_cleanup.err(),
        ]
        .into_iter()
        .flatten()
        {
            eprintln!("best-effort cleanup after contract failure also failed: {cleanup_error:#}");
        }
        return Err(error);
    }
    report_cleanup?;
    task_cleanup?;
    clone_cleanup?;
    group_cleanup?;
    agent_cleanup?;
    session_cleanup?;
    Ok(())
}

async fn assert_route_auth_and_input_failures(harness: &E2eHarness) -> Result<()> {
    assert_eq!(
        harness
            .request(Method::GET, "/api/v1/agents")
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED,
        "agents must reject missing authentication before backend access"
    );
    let invalid = harness
        .request(Method::GET, "/api/v1/agents?page=0")
        .basic_auth(&harness.config.username, Some(&harness.config.password))
        .send()
        .await?;
    assert_eq!(
        invalid.status(),
        StatusCode::BAD_REQUEST,
        "page=0 is a named input failure"
    );
    let unmatched = harness
        .request(
            Method::GET,
            "/api/v1/agents/00000000-0000-0000-0000-000000000000",
        )
        .basic_auth(&harness.config.username, Some(&harness.config.password))
        .send()
        .await?;
    assert_eq!(
        unmatched.status(),
        StatusCode::NOT_FOUND,
        "unknown agent must fail closed"
    );
    Ok(())
}

async fn assert_agent_control_failure_contracts(
    harness: &E2eHarness,
    token: &str,
    agent_id: &str,
    no_op_update: &Value,
    original: &Value,
) -> Result<()> {
    let control_url = env::var("GVM_GATEWAY_E2E_AGENT_CONTROL_PROXY_URL")
        .context("GVM_GATEWAY_E2E_AGENT_CONTROL_PROXY_URL is required")?;
    let control_token = env::var("GVM_GATEWAY_E2E_AGENT_CONTROL_PROXY_TOKEN")
        .context("GVM_GATEWAY_E2E_AGENT_CONTROL_PROXY_TOKEN is required")?;
    // PUT /agents/{id} is deliberately used here: the REST adapter maps it to
    // rust-gvm's typed ModifyAgentRequest and gvmd must perform the Agent Control
    // update before the adapter reads the agent back. Unlike installer/package
    // operations (explicitly out of scope in PR #50), every selected upstream
    // scenario therefore crosses the live gvmd-to-Agent-Control HTTP boundary.
    // The body repeats the observed state, so a normal request is a safe no-op.
    // The allowed pairs are the narrow intersection of emerging.yaml's PUT
    // responses and the adapter's deterministic GatewayError mappings. gvmd may
    // surface authentication as a typed auth failure or a generic server error;
    // its upstream timeout can likewise become a GMP transport timeout or a
    // generic server error. Exact observations remain in evidence.
    let expectations: &[(&str, &[(StatusCode, &str)])] = &[
        (
            "authentication",
            &[
                (StatusCode::UNAUTHORIZED, "unauthorized"),
                (StatusCode::BAD_GATEWAY, "backend_unavailable"),
            ],
        ),
        (
            "unavailable",
            &[(StatusCode::BAD_GATEWAY, "backend_unavailable")],
        ),
        (
            "malformed",
            &[(StatusCode::BAD_GATEWAY, "backend_unavailable")],
        ),
        (
            "conflict",
            &[(StatusCode::BAD_GATEWAY, "backend_unavailable")],
        ),
        (
            "rate-limit",
            &[(StatusCode::BAD_GATEWAY, "backend_unavailable")],
        ),
        (
            "timeout",
            &[
                (StatusCode::BAD_GATEWAY, "backend_unavailable"),
                (StatusCode::GATEWAY_TIMEOUT, "gateway_timeout"),
            ],
        ),
    ];
    for (scenario, allowed) in expectations {
        select_proxy_scenario(harness, &control_url, &control_token, scenario).await?;
        let response = harness
            .request(Method::PUT, &format!("/api/v1/agents/{agent_id}"))
            .bearer_auth(token)
            .json(no_op_update)
            .send()
            .await;
        // Reset before evaluating the route result so an assertion failure cannot
        // leak the selected fault into lifecycle or cleanup requests.
        select_proxy_scenario(harness, &control_url, &control_token, "normal").await?;
        let response = response?;
        let observed = response.status();
        let allowed_statuses = allowed
            .iter()
            .map(|(status, _)| *status)
            .collect::<Vec<_>>();
        let problem = assert_problem_response_any(
            response,
            &allowed_statuses,
            &format!("Agent Control {scenario} failure"),
        )
        .await?;
        assert!(
            allowed
                .iter()
                .any(|(status, classification)| *status == observed && *classification == problem.code),
            "Agent Control scenario {scenario:?} returned disallowed fail-closed pair ({observed}, {:?})",
            problem.code
        );
        let after_failure = get_json(
            harness,
            Method::GET,
            &format!("/api/v1/agents/{agent_id}"),
            token,
            StatusCode::OK,
        )
        .await?;
        assert_agent_state_matches(&after_failure, original);
        println!(
            "AGENT_CONTROL_FAILURE_EVIDENCE {}",
            json!({
                "scenario": scenario,
                "injectedAt": "upstream-agent-control-profile-selected-via-proxy",
                "allowedMappings": allowed.iter().map(|(status, classification)| json!({
                    "status": status.as_u16(),
                    "classification": classification
                })).collect::<Vec<_>>(),
                "observedStatus": observed.as_u16(),
                "classification": problem.code,
                "outcome": "pass"
            })
        );
    }
    Ok(())
}

async fn select_proxy_scenario(
    _harness: &E2eHarness,
    control_url: &str,
    control_token: &str,
    scenario: &str,
) -> Result<()> {
    let response = reqwest::Client::new()
        .put(format!(
            "{}/__control/scenario",
            control_url.trim_end_matches('/')
        ))
        .bearer_auth(control_token)
        .json(&json!({"scenario": scenario}))
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if status != StatusCode::OK {
        bail!("scenario proxy rejected {scenario:?} with {status}: {body}");
    }
    let selected: Value = serde_json::from_str(&body).context("decode proxy control response")?;
    if selected["scenario"] != scenario {
        bail!("scenario proxy did not select {scenario:?}: {selected}");
    }
    Ok(())
}

fn result_evidence(result: &Value) -> String {
    [
        result["name"].as_str(),
        result["description"].as_str(),
        result["nvt"]["name"].as_str(),
        result["nvt"]["tags"].as_str(),
        result["nvt"]["typeMetadata"].as_str(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("\n")
}

async fn get_json(
    harness: &E2eHarness,
    method: Method,
    path: &str,
    token: &str,
    expected: StatusCode,
) -> Result<Value> {
    let response = harness
        .request(method, path)
        .bearer_auth(token)
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await?;
    if status != expected {
        bail!("{path} returned {status}, expected {expected}: {text}");
    }
    serde_json::from_str(&text).with_context(|| format!("decode JSON response from {path}"))
}

async fn send_json(
    harness: &E2eHarness,
    method: Method,
    path: &str,
    token: &str,
    body: &Value,
    expected: StatusCode,
) -> Result<Value> {
    let mut request = harness.request(method, path).bearer_auth(token);
    if !body.is_null() {
        request = request.json(body);
    }
    let response = request.send().await?;
    let status = response.status();
    let text = response.text().await?;
    if status != expected {
        bail!("{path} returned {status}, expected {expected}: {text}");
    }
    serde_json::from_str(&text).with_context(|| format!("decode JSON response from {path}"))
}

async fn send_json_with_location(
    harness: &E2eHarness,
    method: Method,
    path: &str,
    token: &str,
    body: &Value,
    expected: StatusCode,
    location_prefix: &str,
) -> Result<Value> {
    let mut request = harness.request(method, path).bearer_auth(token);
    if !body.is_null() {
        request = request.json(body);
    }
    let response = request.send().await?;
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let text = response.text().await?;
    if status != expected {
        bail!("{path} returned {status}, expected {expected}: {text}");
    }
    if !location.starts_with(location_prefix) {
        bail!("{path} returned invalid Location {location:?}; expected prefix {location_prefix:?}");
    }
    serde_json::from_str(&text).with_context(|| format!("decode JSON response from {path}"))
}

async fn assert_empty(
    response: reqwest::Response,
    expected: StatusCode,
    context: &str,
) -> Result<()> {
    let status = response.status();
    let body = response.bytes().await?;
    if status != expected || !body.is_empty() {
        bail!("{context} returned {status} with {} bytes", body.len());
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|item| !item.is_empty())
        .with_context(|| format!("response field {key} must be a non-empty string"))
}

fn assert_agent_mutation(agent: &Value, comment: &str) {
    assert_eq!(agent["authorized"], true);
    assert_eq!(agent["updateToLatest"], true);
    assert_eq!(agent["comment"], comment);
    assert_eq!(agent["config"]["agentControl"]["retry"]["attempts"], 4);
    assert_eq!(agent["config"]["heartbeat"]["intervalInSeconds"], 45);
}

fn assert_agent_state_matches(actual: &Value, expected: &Value) {
    for field in ["authorized", "updateToLatest", "comment", "config"] {
        assert_eq!(
            actual[field], expected[field],
            "failed Agent Control scenario unexpectedly mutated {field}"
        );
    }
}

fn agent_restoration(original: &Value) -> Result<Value> {
    let authorized = original["authorized"]
        .as_bool()
        .context("fixture agent must expose restorable authorized state")?;
    let update_to_latest = original["updateToLatest"]
        .as_bool()
        .context("fixture agent must expose restorable updateToLatest state")?;
    let config = original["config"]
        .as_object()
        .context("fixture agent must expose restorable configuration")?;
    Ok(json!({
        "authorized": authorized,
        "updateToLatest": update_to_latest,
        "comment": original["comment"].as_str().unwrap_or_default(),
        "config": config
    }))
}

async fn restore_agent(
    harness: &E2eHarness,
    token: &str,
    id: &str,
    restoration: &Value,
) -> Result<()> {
    send_json(
        harness,
        Method::PUT,
        &format!("/api/v1/agents/{id}"),
        token,
        restoration,
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

async fn delete_resource(
    harness: &E2eHarness,
    token: &str,
    prefix: &str,
    id: Option<&str>,
) -> Result<()> {
    let Some(id) = id else { return Ok(()) };
    let path = format!("{prefix}/{id}?ultimate=true");
    let response = harness
        .request(Method::DELETE, &path)
        .bearer_auth(token)
        .send()
        .await?;
    if response.status() != StatusCode::NO_CONTENT {
        bail!("cleanup {path} returned {}", response.status());
    }
    Ok(())
}

async fn delete_report(harness: &E2eHarness, token: &str, id: Option<&str>) -> Result<()> {
    let Some(id) = id else { return Ok(()) };
    let path = format!("/api/v1/reports/{id}");
    let response = harness
        .request(Method::DELETE, &path)
        .bearer_auth(token)
        .send()
        .await?;
    if response.status() != StatusCode::NO_CONTENT {
        bail!("cleanup {path} returned {}", response.status());
    }
    Ok(())
}
