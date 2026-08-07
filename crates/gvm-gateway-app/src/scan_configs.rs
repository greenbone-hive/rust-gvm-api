// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Scan configuration use cases.

use gvm_gateway_domain::{
    CreateScanConfigInput, GatewayError, ModifyScanConfigInput, ScanConfig, ScanConfigPage,
    ScanConfigQuery,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists scan configs for an authenticated session.
    pub async fn list_scan_configs(
        &self,
        session_token: &str,
        query: ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        self.execute_with_resource(
            "scan_configs.list",
            session_token,
            "list",
            "scan_config",
            None,
            |session| async move {
                self.scan_configs
                    .list_scan_configs(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Creates a new scan config for an authenticated session.
    pub async fn create_scan_config(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "scan_configs.create",
            session_token,
            "create",
            "scan_config",
            None,
            |session| async move {
                self.scan_configs
                    .create_scan_config(&session.token, input)
                    .await
            },
        )
        .await
    }

    /// Fetches a scan config for an authenticated session.
    pub async fn get_scan_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanConfig, GatewayError> {
        self.execute_with_resource(
            "scan_configs.get",
            session_token,
            "read",
            "scan_config",
            Some(id),
            |session| async move { self.scan_configs.get_scan_config(&session.token, id).await },
        )
        .await
    }

    /// Modifies a scan config for an authenticated session.
    pub async fn modify_scan_config(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        self.execute_with_resource(
            "scan_configs.modify",
            session_token,
            "modify",
            "scan_config",
            Some(id),
            |session| async move {
                self.scan_configs
                    .modify_scan_config(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes a scan config for an authenticated session.
    pub async fn delete_scan_config(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "scan_configs.delete",
            session_token,
            "delete",
            "scan_config",
            Some(id),
            |session| async move {
                self.scan_configs
                    .delete_scan_config(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Lists policies (compliance scan configs) for an authenticated session.
    pub async fn list_policies(
        &self,
        session_token: &str,
        query: ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        self.execute_with_resource(
            "policies.list",
            session_token,
            "list",
            "policy",
            None,
            |session| async move {
                self.scan_configs
                    .list_policies(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches a policy for an authenticated session.
    pub async fn get_policy(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanConfig, GatewayError> {
        self.execute_with_resource(
            "policies.get",
            session_token,
            "read",
            "policy",
            Some(id),
            |session| async move { self.scan_configs.get_policy(&session.token, id).await },
        )
        .await
    }

    /// Creates a new policy (compliance scan config) for an authenticated session.
    pub async fn create_policy(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "policies.create",
            session_token,
            "create",
            "policy",
            None,
            |session| async move { self.scan_configs.create_policy(&session.token, input).await },
        )
        .await
    }

    /// Modifies a policy for an authenticated session.
    pub async fn modify_policy(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        self.execute_with_resource(
            "policies.modify",
            session_token,
            "modify",
            "policy",
            Some(id),
            |session| async move {
                self.scan_configs
                    .modify_policy(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes a policy for an authenticated session.
    pub async fn delete_policy(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "policies.delete",
            session_token,
            "delete",
            "policy",
            Some(id),
            |session| async move { self.scan_configs.delete_policy(&session.token, id).await },
        )
        .await
    }
}
