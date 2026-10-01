// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{fmt, time::Instant};

use cucumber::{given, then, when, World as _};
use gvm_gateway_e2e::harness::{
    assert_problem_response, E2eHarness, PortList, ScanConfig, Scanner,
};
use reqwest::StatusCode;

#[derive(Default, cucumber::World)]
struct GatewayWorld {
    harness: Option<E2eHarness>,
    session_token: Option<String>,
    invalidated_token: Option<String>,
    response: Option<reqwest::Response>,
    target_id: Option<String>,
    task_id: Option<String>,
    report_id: Option<String>,
}

impl fmt::Debug for GatewayWorld {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayWorld")
            .field("gateway_ready", &self.harness.is_some())
            .field("has_active_session", &self.session_token.is_some())
            .field("target_id", &self.target_id)
            .field("task_id", &self.task_id)
            .field("report_id", &self.report_id)
            .finish_non_exhaustive()
    }
}

impl GatewayWorld {
    fn harness(&self) -> &E2eHarness {
        self.harness
            .as_ref()
            .expect("the compose-backed gateway must be ready")
    }

    fn session_token(&self) -> &str {
        self.session_token
            .as_deref()
            .expect("the scenario must have an active gateway session")
    }

    async fn cleanup(&mut self) {
        let Some(harness) = self.harness.as_ref() else {
            return;
        };
        let Some(token) = self.session_token.as_deref() else {
            return;
        };

        if let Some(task_id) = self.task_id.take() {
            if let Err(error) = harness.delete_task(token, &task_id).await {
                eprintln!("BDD cleanup could not delete task {task_id}: {error:#}");
            }
        }
        if let Some(target_id) = self.target_id.take() {
            if let Err(error) = harness.delete_target(token, &target_id).await {
                eprintln!("BDD cleanup could not delete target {target_id}: {error:#}");
            }
        }
        if let Err(error) = harness.delete_session(token).await {
            eprintln!("BDD cleanup could not delete the gateway session: {error:#}");
        }
        self.session_token = None;
    }
}

#[given("the compose-backed gateway is ready")]
async fn compose_backed_gateway_is_ready(world: &mut GatewayWorld) {
    let harness = E2eHarness::from_env()
        .unwrap_or_else(|error| panic!("configure the BDD E2E harness: {error:#}"));
    harness
        .wait_until_ready()
        .await
        .unwrap_or_else(|error| panic!("wait for the compose-backed gateway: {error:#}"));
    world.harness = Some(harness);
}

#[when("a client requests protected targets without authentication")]
async fn request_targets_without_authentication(world: &mut GatewayWorld) {
    let response = world
        .harness()
        .get_targets_without_auth()
        .await
        .unwrap_or_else(|error| panic!("request protected targets without auth: {error:#}"));
    world.response = Some(response);
}

#[then("the response is an unauthorized problem document")]
async fn response_is_unauthorized_problem(world: &mut GatewayWorld) {
    let response = world
        .response
        .take()
        .expect("the unauthenticated request must produce a response");
    let problem = assert_problem_response(
        response,
        StatusCode::UNAUTHORIZED,
        "BDD unauthenticated protected access",
    )
    .await
    .unwrap_or_else(|error| panic!("validate unauthorized problem response: {error:#}"));
    assert_eq!(problem.code, "unauthorized");
}

#[when("a client creates a gateway session")]
#[given("an active gateway session")]
async fn create_gateway_session(world: &mut GatewayWorld) {
    let session = world
        .harness()
        .create_session()
        .await
        .unwrap_or_else(|error| panic!("create gateway session: {error:#}"));
    assert!(!session.token.trim().is_empty(), "session token was empty");
    world.session_token = Some(session.token);
}

#[then("the session grants protected access")]
async fn session_grants_protected_access(world: &mut GatewayWorld) {
    let targets = world
        .harness()
        .list_targets(world.session_token())
        .await
        .unwrap_or_else(|error| panic!("list targets with the gateway session: {error:#}"));
    assert!(
        targets.data.len() <= targets.pagination.per_page as usize,
        "target page exceeded its declared size"
    );
}

#[when("the client deletes the gateway session")]
async fn delete_gateway_session(world: &mut GatewayWorld) {
    let token = world.session_token().to_string();
    world
        .harness()
        .delete_session(&token)
        .await
        .unwrap_or_else(|error| panic!("delete gateway session: {error:#}"));
    world.session_token = None;
    world.invalidated_token = Some(token);
}

#[then("the deleted bearer token is rejected")]
async fn deleted_bearer_token_is_rejected(world: &mut GatewayWorld) {
    let token = world
        .invalidated_token
        .as_deref()
        .expect("the scenario must retain the deleted bearer token");
    let response = world
        .harness()
        .get_targets_with_bearer(token)
        .await
        .unwrap_or_else(|error| panic!("use the deleted bearer token: {error:#}"));
    assert_problem_response(
        response,
        StatusCode::UNAUTHORIZED,
        "BDD invalidated gateway session",
    )
    .await
    .unwrap_or_else(|error| panic!("validate invalidated-session problem response: {error:#}"));
}

#[when("the client creates a discovery target and task")]
async fn create_discovery_target_and_task(world: &mut GatewayWorld) {
    let token = world.session_token().to_string();
    let scan_configs = world
        .harness()
        .list_scan_configs(&token)
        .await
        .unwrap_or_else(|error| panic!("list discovery scan configs: {error:#}"));
    let scan_config: ScanConfig = world
        .harness()
        .select_discovery_scan_config(&scan_configs)
        .unwrap_or_else(|error| panic!("select a discovery scan config: {error:#}"))
        .clone();
    let scanners = world
        .harness()
        .list_scanners(&token)
        .await
        .unwrap_or_else(|error| panic!("list scanners: {error:#}"));
    let scanner: Scanner = world
        .harness()
        .select_scanner(&scanners)
        .unwrap_or_else(|error| panic!("select an OpenVAS scanner: {error:#}"))
        .clone();
    let port_lists = world
        .harness()
        .list_port_lists(&token)
        .await
        .unwrap_or_else(|error| panic!("list port lists: {error:#}"));
    let port_list: PortList = world
        .harness()
        .select_port_list(&port_lists)
        .unwrap_or_else(|error| panic!("select a discovery port list: {error:#}"))
        .clone();

    let target_name = world.harness().unique_name("bdd-discovery-target");
    let target = world
        .harness()
        .create_target(&token, &target_name, &port_list.id)
        .await
        .unwrap_or_else(|error| panic!("create the BDD discovery target: {error:#}"));
    world.target_id = Some(target.id.clone());

    let task_name = world.harness().unique_name("bdd-discovery-task");
    let task = world
        .harness()
        .create_task(&token, &task_name, &target.id, &scan_config.id, &scanner.id)
        .await
        .unwrap_or_else(|error| panic!("create the BDD discovery task: {error:#}"));
    world.task_id = Some(task.id);
}

#[when("starts the discovery task and waits for completion")]
async fn start_discovery_and_wait(world: &mut GatewayWorld) {
    let token = world.session_token().to_string();
    let task_id = world
        .task_id
        .as_deref()
        .expect("the discovery task must have been created")
        .to_string();
    let action = world
        .harness()
        .start_task(&token, &task_id)
        .await
        .unwrap_or_else(|error| panic!("start the BDD discovery task: {error:#}"));
    assert!(
        !action.report_id.is_empty(),
        "start response omitted reportId"
    );
    world.report_id = Some(action.report_id.clone());

    let completed = world
        .harness()
        .wait_for_task_completion(&token, &task_id)
        .await
        .unwrap_or_else(|error| panic!("wait for the BDD discovery task: {error:#}"));
    let completed_report_id = completed
        .last_report
        .as_ref()
        .or(completed.current_report.as_ref())
        .map(|report| report.id.as_str());
    assert_eq!(completed_report_id, Some(action.report_id.as_str()));
}

#[then("the resulting report is linked to the task")]
async fn resulting_report_is_linked(world: &mut GatewayWorld) {
    let report = world
        .harness()
        .get_report(
            world.session_token(),
            world
                .report_id
                .as_deref()
                .expect("the discovery task must expose a report id"),
        )
        .await
        .unwrap_or_else(|error| panic!("read the BDD discovery report: {error:#}"));
    assert_eq!(Some(report.id.as_str()), world.report_id.as_deref());
    assert_eq!(
        report.task.as_ref().map(|task| task.id.as_str()),
        world.task_id.as_deref()
    );
    assert!(
        report.scan_end.is_some(),
        "completed report omitted scanEnd"
    );
}

#[then("a JSON export of the report is observable")]
async fn json_export_is_observable(world: &mut GatewayWorld) {
    let token = world.session_token().to_string();
    let report_id = world
        .report_id
        .as_deref()
        .expect("the discovery task must expose a report id")
        .to_string();
    let created = world
        .harness()
        .create_json_report_export_job(&token, &report_id)
        .await
        .unwrap_or_else(|error| panic!("create the BDD JSON report export: {error:#}"));
    let completed = world
        .harness()
        .wait_for_job_succeeded(&token, &created.id)
        .await
        .unwrap_or_else(|error| panic!("wait for the BDD report export: {error:#}"));
    assert_eq!(completed.status, "succeeded");
    assert!(completed.result_location.is_some());

    let export = world
        .harness()
        .download_json_report_export(&token, &created.id)
        .await
        .unwrap_or_else(|error| panic!("download the BDD JSON report export: {error:#}"));
    assert_eq!(export.report.id, report_id);
}

// The pilot stays inside the existing E2E crate and runner. One ignored test
// owns all three scenarios, while Cucumber itself is restricted to one
// scenario at a time so the mutable gvmd backend remains serial.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn canonical_rest_behaviors_are_executable_specs() {
    let started = Instant::now();
    GatewayWorld::cucumber()
        .max_concurrent_scenarios(1)
        .fail_on_skipped()
        .with_default_cli()
        .after(|_, _, _, _, world| {
            Box::pin(async move {
                if let Some(world) = world {
                    world.cleanup().await;
                }
            })
        })
        .run_and_exit("features/canonical_rest.feature")
        .await;
    eprintln!("BDD pilot runtime: {:.2?}", started.elapsed());
}
