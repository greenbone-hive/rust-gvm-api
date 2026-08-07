// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::super::*;

impl E2eHarness {
    pub async fn list_scan_configs(&self, token: &str) -> Result<Vec<ScanConfig>> {
        let response: ListResponse<ScanConfig> = self
            .send_json(
                self.authed(Method::GET, "/api/v1/scan-configs", token),
                StatusCode::OK,
                "list scan configs",
            )
            .await?;
        Ok(response.data)
    }

    pub async fn get_scan_config(&self, token: &str, scan_config_id: &str) -> Result<ScanConfig> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/scan-configs/{scan_config_id}"),
                token,
            ),
            StatusCode::OK,
            "get scan config",
        )
        .await
    }

    pub async fn create_scan_config_from_base(
        &self,
        token: &str,
        name: &str,
        comment: &str,
        base_scan_config_id: &str,
    ) -> Result<CreatedResource> {
        let body = json!({
            "name": name,
            "comment": comment,
            "baseScanConfigId": base_scan_config_id,
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/scan-configs", token)
                .json(&body),
            "create scan config",
        )
        .await
    }

    pub async fn update_scan_config_comment(
        &self,
        token: &str,
        scan_config_id: &str,
        comment: &str,
    ) -> Result<ScanConfig> {
        let body = json!({
            "comment": comment,
        });
        self.send_json(
            self.authed(
                Method::PUT,
                &format!("/api/v1/scan-configs/{scan_config_id}"),
                token,
            )
            .json(&body),
            StatusCode::OK,
            "update scan config",
        )
        .await
    }

    pub async fn delete_scan_config(&self, token: &str, scan_config_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::DELETE,
                &format!("/api/v1/scan-configs/{scan_config_id}"),
                token,
            ),
            StatusCode::NO_CONTENT,
            "delete scan config",
        )
        .await
    }

    pub async fn list_scanners(&self, token: &str) -> Result<Vec<Scanner>> {
        let response: ListResponse<Scanner> = self
            .send_json(
                self.authed(Method::GET, "/api/v1/scanners", token),
                StatusCode::OK,
                "list scanners",
            )
            .await?;
        Ok(response.data)
    }

    pub async fn get_scanner(&self, token: &str, scanner_id: &str) -> Result<Scanner> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/scanners/{scanner_id}"),
                token,
            ),
            StatusCode::OK,
            "get scanner",
        )
        .await
    }

    pub async fn create_target(
        &self,
        token: &str,
        name: &str,
        port_list_id: &str,
    ) -> Result<Target> {
        let body = json!({
            "name": name,
            "hosts": [self.config.target_host.clone()],
            "aliveTest": "Consider Alive",
            "portListId": port_list_id,
        });
        let created: ResourceCreated = self
            .send_json(
                self.authed(Method::POST, "/api/v1/targets", token)
                    .json(&body),
                StatusCode::CREATED,
                "create target",
            )
            .await?;
        self.get_target(token, &created.id).await
    }

    pub async fn list_targets(&self, token: &str) -> Result<ListResponse<Target>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/targets?perPage=1000", token),
            StatusCode::OK,
            "list targets",
        )
        .await
    }

    pub async fn get_target(&self, token: &str, target_id: &str) -> Result<Target> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/targets/{target_id}"), token),
            StatusCode::OK,
            "get target",
        )
        .await
    }

    pub async fn update_target_name(
        &self,
        token: &str,
        target_id: &str,
        name: &str,
    ) -> Result<Target> {
        let body = json!({
            "name": name,
        });
        self.send_json(
            self.authed(Method::PUT, &format!("/api/v1/targets/{target_id}"), token)
                .json(&body),
            StatusCode::OK,
            "update target",
        )
        .await
    }

    pub async fn delete_target(&self, token: &str, target_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::DELETE,
                &format!("/api/v1/targets/{target_id}"),
                token,
            ),
            StatusCode::NO_CONTENT,
            "delete target",
        )
        .await
    }

    pub async fn create_task(
        &self,
        token: &str,
        name: &str,
        target_id: &str,
        scan_config_id: &str,
        scanner_id: &str,
    ) -> Result<Task> {
        let body = json!({
            "name": name,
            "targetId": target_id,
            "scanConfigId": scan_config_id,
            "scannerId": scanner_id,
        });
        let created: ResourceCreated = self
            .send_json(
                self.authed(Method::POST, "/api/v1/tasks", token)
                    .json(&body),
                StatusCode::CREATED,
                "create task",
            )
            .await?;
        self.get_task(token, &created.id).await
    }

    pub async fn list_tasks(&self, token: &str) -> Result<ListResponse<Task>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/tasks?perPage=1000", token),
            StatusCode::OK,
            "list tasks",
        )
        .await
    }

    pub async fn start_task(&self, token: &str, task_id: &str) -> Result<TaskAction> {
        self.send_json(
            self.authed(
                Method::POST,
                &format!("/api/v1/tasks/{task_id}/start"),
                token,
            ),
            StatusCode::OK,
            "start task",
        )
        .await
    }

    pub async fn update_task_name(&self, token: &str, task_id: &str, name: &str) -> Result<Task> {
        let body = json!({
            "name": name,
        });
        self.send_json(
            self.authed(Method::PUT, &format!("/api/v1/tasks/{task_id}"), token)
                .json(&body),
            StatusCode::OK,
            "update task",
        )
        .await
    }

    pub async fn stop_task_response(
        &self,
        token: &str,
        task_id: &str,
    ) -> Result<reqwest::Response> {
        self.authed(
            Method::POST,
            &format!("/api/v1/tasks/{task_id}/stop"),
            token,
        )
        .send()
        .await
        .context("stop task")
    }

    pub async fn stop_task(&self, token: &str, task_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::POST,
                &format!("/api/v1/tasks/{task_id}/stop"),
                token,
            ),
            StatusCode::OK,
            "stop task",
        )
        .await
    }

    pub async fn resume_task_response(
        &self,
        token: &str,
        task_id: &str,
    ) -> Result<reqwest::Response> {
        self.authed(
            Method::POST,
            &format!("/api/v1/tasks/{task_id}/resume"),
            token,
        )
        .send()
        .await
        .context("resume task")
    }

    pub async fn delete_task(&self, token: &str, task_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(Method::DELETE, &format!("/api/v1/tasks/{task_id}"), token),
            StatusCode::NO_CONTENT,
            "delete task",
        )
        .await
    }

    pub async fn create_audit(
        &self,
        token: &str,
        name: &str,
        target_id: &str,
        policy_id: &str,
        scanner_id: &str,
    ) -> Result<Task> {
        // Audits reuse the task-create body shape; a compliance policy is a
        // scan config with `usage_type=policy`, so it is supplied via
        // `scanConfigId`.
        let body = json!({
            "name": name,
            "targetId": target_id,
            "scanConfigId": policy_id,
            "scannerId": scanner_id,
        });
        let created: ResourceCreated = self
            .send_json(
                self.authed(Method::POST, "/api/v1/audits", token)
                    .json(&body),
                StatusCode::CREATED,
                "create audit",
            )
            .await?;
        self.get_audit(token, &created.id).await
    }

    pub async fn get_audit(&self, token: &str, audit_id: &str) -> Result<Task> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/audits/{audit_id}"), token),
            StatusCode::OK,
            "get audit",
        )
        .await
    }

    pub async fn start_audit(&self, token: &str, audit_id: &str) -> Result<TaskAction> {
        self.send_json(
            self.authed(
                Method::POST,
                &format!("/api/v1/audits/{audit_id}/start"),
                token,
            ),
            StatusCode::OK,
            "start audit",
        )
        .await
    }

    pub async fn delete_audit(&self, token: &str, audit_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(Method::DELETE, &format!("/api/v1/audits/{audit_id}"), token),
            StatusCode::NO_CONTENT,
            "delete audit",
        )
        .await
    }

    pub async fn get_task(&self, token: &str, task_id: &str) -> Result<Task> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/tasks/{task_id}"), token),
            StatusCode::OK,
            "get task",
        )
        .await
    }

    pub async fn list_results_page(
        &self,
        token: &str,
        page: u32,
        per_page: u32,
    ) -> Result<ResultList> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/results?page={page}&perPage={per_page}"),
                token,
            ),
            StatusCode::OK,
            "list results page",
        )
        .await
    }

    pub async fn get_result(&self, token: &str, result_id: &str) -> Result<ScanResult> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/results/{result_id}"), token),
            StatusCode::OK,
            "get result",
        )
        .await
    }

    pub async fn get_report_results(&self, token: &str, report_id: &str) -> Result<ResultList> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/reports/{report_id}/results"),
                token,
            ),
            StatusCode::OK,
            "get report results",
        )
        .await
    }

    pub async fn get_report_results_page(
        &self,
        token: &str,
        report_id: &str,
        page: u32,
        per_page: u32,
    ) -> Result<ResultList> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/reports/{report_id}/results?page={page}&perPage={per_page}"),
                token,
            ),
            StatusCode::OK,
            "get report results page",
        )
        .await
    }

    pub fn select_discovery_scan_config<'a>(
        &self,
        scan_configs: &'a [ScanConfig],
    ) -> Result<&'a ScanConfig> {
        scan_configs
            .iter()
            .find(|config| lower(&config.name).contains("host discovery"))
            .or_else(|| {
                scan_configs
                    .iter()
                    .find(|config| lower(&config.name).contains("discovery"))
            })
            .with_context(|| {
                format!(
                    "no discovery scan config found; available configs: {}",
                    scan_configs
                        .iter()
                        .map(|config| config.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    pub fn select_scanner<'a>(&self, scanners: &'a [Scanner]) -> Result<&'a Scanner> {
        scanners
            .iter()
            .find(|scanner| {
                matches!(
                    scanner.scanner_type.as_deref(),
                    Some("OSP") | Some("OpenVAS")
                ) || lower(&scanner.name).contains("openvas")
            })
            .or_else(|| scanners.first())
            .with_context(|| "no scanners returned from REST API".to_string())
    }

    pub fn select_port_list<'a>(&self, port_lists: &'a [PortList]) -> Result<&'a PortList> {
        port_lists
            .iter()
            .find(|port_list| lower(&port_list.name).contains("all iana assigned tcp"))
            .or_else(|| {
                port_lists
                    .iter()
                    .find(|port_list| lower(&port_list.name).contains("all tcp"))
            })
            .or_else(|| port_lists.first())
            .with_context(|| "no port lists returned from REST API".to_string())
    }
}
