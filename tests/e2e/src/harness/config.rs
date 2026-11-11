// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{env, fmt, time::Duration};

use anyhow::{bail, Context, Result};

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_USERNAME: &str = "admin";
const DEFAULT_PASSWORD: &str = "admin";
const DEFAULT_TARGET_HOST: &str = "openvasd";
const DEFAULT_READY_TIMEOUT_SECS: u64 = 1_200;
const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 900;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 10;
const DEFAULT_REPORT_FORMAT_PDF_ID: &str = "c402cc3e-b531-11e1-9163-406186ea4fc5";
const DEFAULT_REPORT_FORMAT_CSV_ID: &str = "c1645568-627a-11e3-a660-406186ea4fc5";

#[derive(Clone, Debug)]
pub struct E2eConfig {
    pub base_url: String,
    pub username: String,
    pub password: String,
    pub target_host: String,
    pub scanner_backend_identity: Option<String>,
    pub scanner_backend_url: Option<String>,
    pub expected_scanner_scenario: Option<String>,
    pub ready_timeout: Duration,
    pub scan_timeout: Duration,
    pub poll_interval: Duration,
    pub pdf_report_format_id: String,
    pub csv_report_format_id: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialStoreFixture {
    pub preferred_store_id: Option<String>,
    pub vault_id: String,
    pub host_identifier: String,
    pub credential_type: String,
    pub restore_comment: String,
}

impl CredentialStoreFixture {
    pub fn from_env() -> Result<Self> {
        let credential_type =
            env_or_default("GVM_GATEWAY_E2E_CREDENTIAL_STORE_CREDENTIAL_TYPE", "cs_up");
        if !matches!(
            credential_type.as_str(),
            "cs_cc" | "cs_pw" | "cs_pgp" | "cs_smime" | "cs_snmp" | "cs_up" | "cs_usk"
        ) {
            bail!("GVM_GATEWAY_E2E_CREDENTIAL_STORE_CREDENTIAL_TYPE must be a supported cs_* type");
        }
        Ok(Self {
            preferred_store_id: env::var("GVM_GATEWAY_E2E_CREDENTIAL_STORE_ID")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            vault_id: required_non_empty_env("GVM_GATEWAY_E2E_CREDENTIAL_STORE_VAULT_ID")?,
            host_identifier: required_non_empty_env(
                "GVM_GATEWAY_E2E_CREDENTIAL_STORE_HOST_IDENTIFIER",
            )?,
            credential_type,
            restore_comment: required_env("GVM_GATEWAY_E2E_CREDENTIAL_STORE_RESTORE_COMMENT")?,
        })
    }
}

impl fmt::Debug for CredentialStoreFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialStoreFixture")
            .field("preferred_store_id", &self.preferred_store_id)
            .field("vault_id", &"<redacted>")
            .field("host_identifier", &"<redacted>")
            .field("credential_type", &self.credential_type)
            .field("restore_comment", &"<redacted>")
            .finish()
    }
}

impl E2eConfig {
    pub fn from_env() -> Result<Self> {
        let target_host = env_or_default("GVM_GATEWAY_E2E_TARGET_HOST", DEFAULT_TARGET_HOST);
        let scanner_backend_identity =
            optional_non_empty_env("GVM_GATEWAY_E2E_SCANNER_BACKEND_IDENTITY");
        validate_shadow_identities(&target_host, scanner_backend_identity.as_deref())?;
        let scanner_backend_url = optional_non_empty_env("GVM_GATEWAY_E2E_SCANNER_BACKEND_URL");
        let expected_scanner_scenario =
            optional_non_empty_env("GVM_GATEWAY_E2E_EXPECTED_SCANNER_SCENARIO");
        if scanner_backend_url.is_some() != expected_scanner_scenario.is_some() {
            bail!(
                "GVM_GATEWAY_E2E_SCANNER_BACKEND_URL and \
                 GVM_GATEWAY_E2E_EXPECTED_SCANNER_SCENARIO must be set together"
            );
        }

        Ok(Self {
            base_url: env_or_default("GVM_GATEWAY_E2E_BASE_URL", DEFAULT_BASE_URL),
            username: env_or_default("GVM_GATEWAY_E2E_USERNAME", DEFAULT_USERNAME),
            password: env_or_default("GVM_GATEWAY_E2E_PASSWORD", DEFAULT_PASSWORD),
            target_host,
            scanner_backend_identity,
            scanner_backend_url,
            expected_scanner_scenario,
            ready_timeout: Duration::from_secs(env_u64_or_default(
                "GVM_GATEWAY_E2E_READY_TIMEOUT_SECS",
                DEFAULT_READY_TIMEOUT_SECS,
            )?),
            scan_timeout: Duration::from_secs(env_u64_or_default(
                "GVM_GATEWAY_E2E_SCAN_TIMEOUT_SECS",
                DEFAULT_SCAN_TIMEOUT_SECS,
            )?),
            poll_interval: Duration::from_secs(env_u64_or_default(
                "GVM_GATEWAY_E2E_POLL_INTERVAL_SECS",
                DEFAULT_POLL_INTERVAL_SECS,
            )?),
            pdf_report_format_id: env_or_default(
                "GVM_GATEWAY_E2E_REPORT_FORMAT_PDF_ID",
                DEFAULT_REPORT_FORMAT_PDF_ID,
            ),
            csv_report_format_id: env_or_default(
                "GVM_GATEWAY_E2E_REPORT_FORMAT_CSV_ID",
                DEFAULT_REPORT_FORMAT_CSV_ID,
            ),
        })
    }
}

fn env_or_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn optional_non_empty_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.trim().is_empty())
}

pub(super) fn validate_shadow_identities(
    target_host: &str,
    scanner_backend_identity: Option<&str>,
) -> Result<()> {
    if let Some(scanner_backend_identity) = scanner_backend_identity {
        if target_host.eq_ignore_ascii_case(scanner_backend_identity) {
            bail!(
                "scanner backend identity {scanner_backend_identity:?} must differ from \
                 synthetic target identity {target_host:?}"
            );
        }
    }
    Ok(())
}

fn env_u64_or_default(key: &str, default: u64) -> Result<u64> {
    match env::var(key) {
        Ok(raw) => raw
            .parse::<u64>()
            .with_context(|| format!("parse {key}={raw} as u64")),
        Err(_) => Ok(default),
    }
}

fn required_env(key: &str) -> Result<String> {
    env::var(key).with_context(|| {
        format!("credential-store capability is supported; set {key} to run the safe live fixture")
    })
}

fn required_non_empty_env(key: &str) -> Result<String> {
    let value = required_env(key)?;
    if value.is_empty() {
        bail!("credential-store capability is supported; {key} must not be empty");
    }
    Ok(value)
}
