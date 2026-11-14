// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Fail-closed typed GMP preflight for the advisory enterprise E2E lane.

use std::{env, process::ExitCode};

use anyhow::{Context, Result};
use gvm_client::GmpClient;
use gvm_connection::UnixSocketConnection;
use gvm_gmp::{
    commands::{
        authentication::AuthenticateRequest, features::GetFeaturesRequest,
        version::GetVersionRequest,
    },
    responses::{GetFeaturesResponse, GetVersionResponse},
    GmpRequestCodec, GmpResponse,
};
use gvm_protocol::Response;
use serde_json::{json, Value};

const REQUIRED_FEATURES: [&str; 2] = ["ENABLE_AGENTS", "ENABLE_OPENVASD"];

fn raw_response(response: &Response, command: &str) -> Result<String> {
    response
        .as_str()
        .map(ToOwned::to_owned)
        .with_context(|| format!("{command} response was not UTF-8"))
}

async fn preflight() -> Result<Value> {
    let socket = env::var("GVM_FEATURE_PREFLIGHT_SOCKET")
        .unwrap_or_else(|_| "/run/gvmd/gvmd.sock".to_string());
    let username = env::var("GVM_FEATURE_PREFLIGHT_USERNAME")
        .context("GVM_FEATURE_PREFLIGHT_USERNAME is required")?;
    let password = env::var("GVM_FEATURE_PREFLIGHT_PASSWORD")
        .context("GVM_FEATURE_PREFLIGHT_PASSWORD is required")?;

    let mut client = GmpClient::connect(UnixSocketConnection::with_path(&socket))
        .await
        .with_context(|| format!("connect to gvmd socket {socket}"))?;

    let version_request = GetVersionRequest::new()
        .encode(client.version())
        .context("encode typed get_version preflight")?;
    let version_raw = client
        .send(version_request)
        .await
        .context("execute typed get_version preflight")?;
    let version = GetVersionResponse::decode(&version_raw, client.version())
        .context("decode typed get_version response")?;

    client
        .execute(AuthenticateRequest::new(username, password))
        .await
        .context("authenticate typed enterprise feature preflight")?;

    let features_request = GetFeaturesRequest::new()
        .encode(client.version())
        .context("encode typed get_features preflight")?;
    let features_raw = client
        .send(features_request)
        .await
        .context("execute typed get_features preflight")?;
    let features = GetFeaturesResponse::decode(&features_raw, client.version())
        .context("decode typed get_features response")?;

    let required = REQUIRED_FEATURES
        .iter()
        .map(|name| {
            features
                .features
                .iter()
                .find(|feature| feature.name == *name)
                .map(|feature| {
                    json!({
                        "name": feature.name,
                        "compiledIn": feature.compiled_in,
                        "enabled": feature.enabled,
                    })
                })
                .unwrap_or_else(|| json!({"name": name, "missing": true}))
        })
        .collect::<Vec<_>>();

    let mismatches = required
        .iter()
        .filter(|feature| {
            feature.get("missing").and_then(Value::as_bool) == Some(true)
                || feature.get("compiledIn").and_then(Value::as_bool) != Some(true)
                || feature.get("enabled").and_then(Value::as_bool) != Some(true)
        })
        .cloned()
        .collect::<Vec<_>>();
    let version_document = json!({
        "gmp": version.version,
        "rawResponse": raw_response(&version_raw, "get_version")?,
    });
    let features_document = json!({
        "required": required,
        "rawResponse": raw_response(&features_raw, "get_features")?,
    });
    if !mismatches.is_empty() {
        return Ok(json!({
            "schemaVersion": 1,
            "status": "failed",
            "classification": "preflight-configuration",
            "detail": "required gvmd features are missing, not compiled in, or disabled",
            "mismatches": mismatches,
            "version": version_document,
            "features": features_document,
        }));
    }

    Ok(json!({
        "schemaVersion": 1,
        "status": "passed",
        "classification": "preflight",
        "version": version_document,
        "features": features_document,
    }))
}

#[tokio::main]
async fn main() -> ExitCode {
    match preflight().await {
        Ok(document) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&document).expect("JSON document")
            );
            if document.get("status").and_then(Value::as_str) == Some("passed") {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(78)
            }
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": 1,
                    "status": "failed",
                    "classification": "preflight-configuration",
                    "detail": format!("{error:#}"),
                }))
                .expect("JSON failure document")
            );
            ExitCode::from(78)
        }
    }
}
