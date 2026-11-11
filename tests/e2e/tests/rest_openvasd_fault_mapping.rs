// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Test-only direct-OpenVASD fault mapping exercised once per named emulator
//! scenario by the shadow workflow. The ordinary all-contract pass leaves the
//! scenario unset; comparison evidence is completed from the five explicit
//! fault invocations rather than counting that discovery pass as coverage.

use std::{env, time::Instant};

use anyhow::{bail, Context, Result};
use gvm_gateway_e2e::harness::{E2eHarness, TaskAction};
use reqwest::StatusCode;
use serde_json::json;

// Proves scanner HTTP/protocol failures remain observable through gvmd and the
// public gateway as either the specified problem response or a terminal task.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the direct-OpenVASD Compose profile and a selected fault port"]
async fn rest_openvasd_faults_have_bounded_gateway_mappings() -> Result<()> {
    let Ok(scenario) = env::var("GVM_GATEWAY_E2E_OPENVASD_FAULT_SCENARIO") else {
        eprintln!(
            "fault scenario not selected; explicit shadow fault invocations own this contract"
        );
        return Ok(());
    };
    if !matches!(
        scenario.as_str(),
        "http-400" | "http-500" | "malformed-body" | "malformed-header" | "timeout"
    ) {
        bail!("unsupported direct-OpenVASD fault scenario {scenario:?}");
    }

    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;
    let session = harness.create_session().await?;
    let mut task_id = None;
    let mut target_id = None;

    let run = async {
        let scan_configs = harness.list_scan_configs(&session.token).await?;
        let scanners = harness.list_scanners(&session.token).await?;
        let port_lists = harness.list_port_lists(&session.token).await?;
        let scan_config = harness.select_discovery_scan_config(&scan_configs)?;
        let scanner = harness.select_scanner(&scanners)?;
        let port_list = harness.select_port_list(&port_lists)?;

        let target = harness
            .create_target(
                &session.token,
                &harness.unique_name("openvasd-fault-target"),
                &port_list.id,
            )
            .await?;
        target_id = Some(target.id.clone());
        let task = harness
            .create_task(
                &session.token,
                &harness.unique_name("openvasd-fault-task"),
                &target.id,
                &scan_config.id,
                &scanner.id,
            )
            .await?;
        task_id = Some(task.id.clone());

        let response = harness
            .start_task_response(&session.token, &task.id)
            .await?;
        let status = response.status();
        let mapping = if status == StatusCode::OK {
            let _: TaskAction = response
                .json()
                .await
                .context("parse successful fault start response")?;
            let deadline = Instant::now() + harness.config.scan_timeout;
            let terminal = loop {
                if Instant::now() >= deadline {
                    bail!("fault scenario {scenario} did not reach a terminal task state");
                }
                let observed = harness.get_task(&session.token, &task.id).await?;
                if matches!(observed.status.as_str(), "Interrupted" | "Error" | "Stopped") {
                    break observed.status;
                }
                if observed.status == "Done" {
                    bail!("fault scenario {scenario} unexpectedly completed successfully");
                }
                tokio::time::sleep(harness.config.poll_interval).await;
            };
            format!("task:{terminal}")
        } else {
            let expected = if scenario == "timeout" {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            if status != expected {
                let body = response.text().await.unwrap_or_default();
                bail!(
                    "fault scenario {scenario} mapped to HTTP {status}, expected {expected}; body={body}"
                );
            }
            format!("http:{}", status.as_u16())
        };

        println!(
            "FAULT_EVIDENCE {}",
            json!({
                "scenario": scenario,
                "injectedAt": "openvasd-http-boundary",
                "gatewayMapping": mapping,
                "target": harness.config.target_host,
                "outcome": "pass"
            })
        );
        Ok(())
    }
    .await;

    if let Some(id) = task_id.as_deref() {
        if let Err(error) = harness.delete_task(&session.token, id).await {
            eprintln!("fault cleanup could not delete task {id}: {error:#}");
        }
    }
    if let Some(id) = target_id.as_deref() {
        if let Err(error) = harness.delete_target(&session.token, id).await {
            eprintln!("fault cleanup could not delete target {id}: {error:#}");
        }
    }
    harness.delete_session(&session.token).await?;
    run
}
