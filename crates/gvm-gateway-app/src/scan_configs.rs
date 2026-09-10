// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Scan configuration use cases.

use gvm_gateway_domain::{
    CreateScanConfigInput, GatewayError, GenericConfig, GenericConfigPage, GenericConfigQuery,
    ModifyScanConfigInput, Nvt, ScanConfig, ScanConfigNvtPage, ScanConfigNvtQuery, ScanConfigPage,
    ScanConfigPreference, ScanConfigPreferenceQuery, ScanConfigQuery,
    SetScanConfigFamilySelectionInput,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists generic configs for an authenticated session.
    pub async fn list_configs(
        &self,
        session_token: &str,
        query: GenericConfigQuery,
    ) -> Result<GenericConfigPage, GatewayError> {
        self.execute_with_resource(
            "configs.list",
            session_token,
            "list",
            "config",
            None,
            |session| async move { self.scan_configs.list_configs(&session.token, &query).await },
        )
        .await
    }

    /// Fetches a generic config for an authenticated session.
    pub async fn get_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<GenericConfig, GatewayError> {
        self.execute_with_resource(
            "configs.get",
            session_token,
            "read",
            "config",
            Some(id),
            |session| async move { self.scan_configs.get_config(&session.token, id).await },
        )
        .await
    }

    /// Deletes a generic config for an authenticated session.
    pub async fn delete_config(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "configs.delete",
            session_token,
            "delete",
            "config",
            Some(id),
            |session| async move {
                self.scan_configs
                    .delete_config(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Clones a generic config for an authenticated session.
    pub async fn clone_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "configs.clone",
            session_token,
            "create",
            "config",
            Some(id),
            |session| async move { self.scan_configs.clone_config(&session.token, id).await },
        )
        .await
    }

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

    /// Lists NVTs selected by a scan configuration.
    pub async fn list_scan_config_nvts(
        &self,
        session_token: &str,
        id: &str,
        query: ScanConfigNvtQuery,
    ) -> Result<ScanConfigNvtPage, GatewayError> {
        self.execute_with_resource(
            "scan_configs.nvts.list",
            session_token,
            "list",
            "scan_config_nvt",
            Some(id),
            |session| async move {
                self.scan_configs
                    .list_scan_config_nvts(&session.token, id, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches one NVT selected by a scan configuration.
    pub async fn get_scan_config_nvt(
        &self,
        session_token: &str,
        id: &str,
        oid: &str,
    ) -> Result<Nvt, GatewayError> {
        self.execute_with_resource(
            "scan_configs.nvts.get",
            session_token,
            "read",
            "scan_config_nvt",
            Some(id),
            |session| async move {
                self.scan_configs
                    .get_scan_config_nvt(&session.token, id, oid)
                    .await
            },
        )
        .await
    }

    /// Lists scanner or NVT preferences for a scan configuration.
    pub async fn list_scan_config_preferences(
        &self,
        session_token: &str,
        id: &str,
        query: ScanConfigPreferenceQuery,
    ) -> Result<Vec<ScanConfigPreference>, GatewayError> {
        self.execute_with_resource(
            "scan_configs.preferences.list",
            session_token,
            "list",
            "scan_config_preference",
            Some(id),
            |session| async move {
                self.scan_configs
                    .list_scan_config_preferences(&session.token, id, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches one scanner or NVT preference for a scan configuration.
    pub async fn get_scan_config_preference(
        &self,
        session_token: &str,
        id: &str,
        name: &str,
        query: ScanConfigPreferenceQuery,
    ) -> Result<ScanConfigPreference, GatewayError> {
        self.execute_with_resource(
            "scan_configs.preferences.get",
            session_token,
            "read",
            "scan_config_preference",
            Some(id),
            |session| async move {
                self.scan_configs
                    .get_scan_config_preference(&session.token, id, name, &query)
                    .await
            },
        )
        .await
    }

    /// Replaces one family's selected NVTs.
    pub async fn set_scan_config_nvt_selection(
        &self,
        session_token: &str,
        id: &str,
        family: &str,
        nvt_oids: Vec<String>,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "scan_configs.nvt_selection.set",
            session_token,
            "modify",
            "scan_config",
            Some(id),
            |session| async move {
                self.scan_configs
                    .set_scan_config_nvt_selection(&session.token, id, family, nvt_oids)
                    .await
            },
        )
        .await
    }

    /// Replaces family selection atomically.
    pub async fn set_scan_config_family_selection(
        &self,
        session_token: &str,
        id: &str,
        input: SetScanConfigFamilySelectionInput,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "scan_configs.family_selection.set",
            session_token,
            "modify",
            "scan_config",
            Some(id),
            |session| async move {
                self.scan_configs
                    .set_scan_config_family_selection(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Sets or resets a scanner or NVT preference.
    pub async fn set_scan_config_preference(
        &self,
        session_token: &str,
        id: &str,
        name: &str,
        nvt_oid: Option<String>,
        value: Option<String>,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "scan_configs.preferences.set",
            session_token,
            "modify",
            "scan_config_preference",
            Some(id),
            |session| async move {
                self.scan_configs
                    .set_scan_config_preference(&session.token, id, name, nvt_oid, value)
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
