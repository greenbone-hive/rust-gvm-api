// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl SystemPort for GvmdAdapter {
    async fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
        match self.probe_version().await {
            Ok(_) => Ok(ReadinessStatus {
                status: "ready",
                reason: None,
            }),
            Err(error) => Ok(ReadinessStatus {
                status: "notReady",
                reason: Some(error.detail().to_string()),
            }),
        }
    }

    async fn gmp_version(&self) -> Result<String, GatewayError> {
        self.probe_version().await
    }

    async fn list_timezones(&self, session_token: &str) -> Result<Vec<Timezone>, GatewayError> {
        let parsed = self
            .execute_with_session(session_token, "timezones.list", GetTimezonesRequest::new())
            .await?;

        Ok(parsed.items.into_iter().map(timezone_from_gmp).collect())
    }
}
