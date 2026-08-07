// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::sync::Arc;

use async_trait::async_trait;
use gvm_gateway_domain::{
    Alert, AlertPage, AlertPort, AlertQuery, AuthPort, CreateAlertInput, CreateCredentialInput,
    CreateGroupInput, CreateNoteInput, CreateOverrideInput, CreatePermissionInput,
    CreatePortListInput, CreateRoleInput, CreateScanConfigInput, CreateScheduleInput,
    CreateTargetInput, CreateTaskInput, CreateUserInput, Credential, CredentialPage,
    CredentialPort, CredentialQuery, CredentialStore, Feed, FeedPort, Filter, FilterPage,
    GatewayError, GetReportOpts, Group, GroupPage, Host, HostPage, IdentityPort, IdentityQuery,
    ModifyAlertInput, ModifyCredentialInput, ModifyGroupInput, ModifyNoteInput,
    ModifyOverrideInput, ModifyPermissionInput, ModifyPortListInput, ModifyRoleInput,
    ModifyScanConfigInput, ModifyScheduleInput, ModifyTargetInput, ModifyTaskInput,
    ModifyUserInput, ModifyUserSettingInput, Note, NotePage, Nvt, NvtFamilyPage, NvtPage, Override,
    OverridePage, Permission, PermissionPage, PortList, PortListPage, PortListPort, PortListQuery,
    ReadinessStatus, Report, ReportExport, ReportExportRequest, ReportFormat, ReportFormatPage,
    ReportPage, ReportPort, ReportQuery, ResultPage, ResultPort, ResultQuery, Role, RolePage,
    ScanConfig, ScanConfigPage, ScanConfigPort, ScanConfigQuery, ScanResult, Scanner, ScannerPage,
    ScannerPort, ScannerQuery, Schedule, SchedulePage, SchedulePort, ScheduleQuery,
    SupportingResourcePort, SupportingResourceQuery, SystemPort, Tag, TagPage, Target, TargetPage,
    TargetPort, TargetQuery, Task, TaskAction, TaskPage, TaskPort, TaskQuery, Ticket, TicketPage,
    TlsCertificateAsset, TlsCertificateAssetPage, TlsCertificatePage, User, UserPage, UserSetting,
    UserSettingList, UserSettingQuery, VulnerabilityPage,
};

/// Mock system port for tests that need deterministic readiness/version responses.
#[derive(Clone)]
pub(crate) struct MockSystemPort {
    pub(crate) ready: bool,
    pub(crate) gmp_version: String,
}

#[async_trait]
impl SystemPort for MockSystemPort {
    async fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
        if self.ready {
            Ok(ReadinessStatus {
                status: "ready",
                reason: None,
            })
        } else {
            Ok(ReadinessStatus {
                status: "notReady",
                reason: Some("mock not ready".to_string()),
            })
        }
    }

    async fn gmp_version(&self) -> Result<String, GatewayError> {
        Ok(self.gmp_version.clone())
    }
}

/// Mock alert port for tests that only need wiring.
#[derive(Clone, Default)]
pub(crate) struct MockAlertPort;

#[async_trait]
impl AlertPort for MockAlertPort {
    async fn list_alerts(&self, _: &str, query: &AlertQuery) -> Result<AlertPage, GatewayError> {
        Ok(AlertPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_alert(&self, _: &str, _: CreateAlertInput) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000011".to_string())
    }

    async fn get_alert(&self, _: &str, id: &str) -> Result<Alert, GatewayError> {
        Err(GatewayError::NotFound(format!("alert {id} not found")))
    }

    async fn modify_alert(
        &self,
        _: &str,
        id: &str,
        _: ModifyAlertInput,
    ) -> Result<Alert, GatewayError> {
        Err(GatewayError::NotFound(format!("alert {id} not found")))
    }

    async fn delete_alert(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("alert {id} not found")))
    }
}

/// Mock schedule port for tests that only need wiring.
#[derive(Clone, Default)]
pub(crate) struct MockSchedulePort;

#[async_trait]
impl SchedulePort for MockSchedulePort {
    async fn list_schedules(
        &self,
        _: &str,
        query: &ScheduleQuery,
    ) -> Result<SchedulePage, GatewayError> {
        Ok(SchedulePage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_schedule(
        &self,
        _: &str,
        _: CreateScheduleInput,
    ) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000012".to_string())
    }

    async fn get_schedule(&self, _: &str, id: &str) -> Result<Schedule, GatewayError> {
        Err(GatewayError::NotFound(format!("schedule {id} not found")))
    }

    async fn modify_schedule(
        &self,
        _: &str,
        id: &str,
        _: ModifyScheduleInput,
    ) -> Result<Schedule, GatewayError> {
        Err(GatewayError::NotFound(format!("schedule {id} not found")))
    }

    async fn delete_schedule(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("schedule {id} not found")))
    }
}

/// Mock credential port for tests that only need wiring.
#[derive(Clone, Default)]
pub(crate) struct MockCredentialPort;

#[async_trait]
impl CredentialPort for MockCredentialPort {
    async fn list_credential_stores(&self, _: &str) -> Result<Vec<CredentialStore>, GatewayError> {
        Ok(vec![CredentialStore {
            id: "default".to_string(),
            name: "Default".to_string(),
            provider: Some("gvmd".to_string()),
            default: true,
            writable: true,
        }])
    }

    async fn list_credentials(
        &self,
        _: &str,
        query: &CredentialQuery,
    ) -> Result<CredentialPage, GatewayError> {
        Ok(CredentialPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_credential(
        &self,
        _: &str,
        _: CreateCredentialInput,
    ) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000013".to_string())
    }

    async fn get_credential(&self, _: &str, id: &str) -> Result<Credential, GatewayError> {
        Err(GatewayError::NotFound(format!("credential {id} not found")))
    }

    async fn modify_credential(
        &self,
        _: &str,
        id: &str,
        _: ModifyCredentialInput,
    ) -> Result<Credential, GatewayError> {
        Err(GatewayError::NotFound(format!("credential {id} not found")))
    }

    async fn delete_credential(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("credential {id} not found")))
    }
}

/// Mock port-list port for tests that only need wiring.
#[derive(Clone, Default)]
pub(crate) struct MockPortListPort;

#[async_trait]
impl PortListPort for MockPortListPort {
    async fn list_port_lists(
        &self,
        _: &str,
        query: &PortListQuery,
    ) -> Result<PortListPage, GatewayError> {
        Ok(PortListPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_port_list(
        &self,
        _: &str,
        _: CreatePortListInput,
    ) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000014".to_string())
    }

    async fn get_port_list(&self, _: &str, id: &str) -> Result<PortList, GatewayError> {
        Err(GatewayError::NotFound(format!("port list {id} not found")))
    }

    async fn modify_port_list(
        &self,
        _: &str,
        id: &str,
        _: ModifyPortListInput,
    ) -> Result<PortList, GatewayError> {
        Err(GatewayError::NotFound(format!("port list {id} not found")))
    }

    async fn delete_port_list(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("port list {id} not found")))
    }
}

/// Mock feed port for tests that only need wiring.
#[derive(Clone, Default)]
pub(crate) struct MockFeedPort;

#[async_trait]
impl FeedPort for MockFeedPort {
    async fn list_feeds(&self, _: &str) -> Result<Vec<Feed>, GatewayError> {
        Ok(vec![])
    }
}

/// Mock identity port for tests that only need service wiring.
#[derive(Clone, Default)]
pub(crate) struct MockIdentityPort;

#[async_trait]
impl IdentityPort for MockIdentityPort {
    async fn list_users(&self, _: &str, query: &IdentityQuery) -> Result<UserPage, GatewayError> {
        Ok(UserPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_user(&self, _: &str, _: CreateUserInput) -> Result<String, GatewayError> {
        Ok("mock-user-id".to_string())
    }

    async fn get_user(&self, _: &str, id: &str) -> Result<User, GatewayError> {
        Err(GatewayError::NotFound(format!("user {id} not found")))
    }

    async fn modify_user(
        &self,
        _: &str,
        id: &str,
        _: ModifyUserInput,
    ) -> Result<User, GatewayError> {
        Err(GatewayError::NotFound(format!("user {id} not found")))
    }

    async fn delete_user(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("user {id} not found")))
    }

    async fn list_groups(&self, _: &str, query: &IdentityQuery) -> Result<GroupPage, GatewayError> {
        Ok(GroupPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_group(&self, _: &str, _: CreateGroupInput) -> Result<String, GatewayError> {
        Ok("mock-group-id".to_string())
    }

    async fn get_group(&self, _: &str, id: &str) -> Result<Group, GatewayError> {
        Err(GatewayError::NotFound(format!("group {id} not found")))
    }

    async fn modify_group(
        &self,
        _: &str,
        id: &str,
        _: ModifyGroupInput,
    ) -> Result<Group, GatewayError> {
        Err(GatewayError::NotFound(format!("group {id} not found")))
    }

    async fn delete_group(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("group {id} not found")))
    }

    async fn list_roles(&self, _: &str, query: &IdentityQuery) -> Result<RolePage, GatewayError> {
        Ok(RolePage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_role(&self, _: &str, _: CreateRoleInput) -> Result<String, GatewayError> {
        Ok("mock-role-id".to_string())
    }

    async fn get_role(&self, _: &str, id: &str) -> Result<Role, GatewayError> {
        Err(GatewayError::NotFound(format!("role {id} not found")))
    }

    async fn modify_role(
        &self,
        _: &str,
        id: &str,
        _: ModifyRoleInput,
    ) -> Result<Role, GatewayError> {
        Err(GatewayError::NotFound(format!("role {id} not found")))
    }

    async fn delete_role(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("role {id} not found")))
    }

    async fn list_permissions(
        &self,
        _: &str,
        query: &IdentityQuery,
    ) -> Result<PermissionPage, GatewayError> {
        Ok(PermissionPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_permission(
        &self,
        _: &str,
        _: CreatePermissionInput,
    ) -> Result<String, GatewayError> {
        Ok("mock-permission-id".to_string())
    }

    async fn get_permission(&self, _: &str, id: &str) -> Result<Permission, GatewayError> {
        Err(GatewayError::NotFound(format!("permission {id} not found")))
    }

    async fn modify_permission(
        &self,
        _: &str,
        id: &str,
        _: ModifyPermissionInput,
    ) -> Result<Permission, GatewayError> {
        Err(GatewayError::NotFound(format!("permission {id} not found")))
    }

    async fn delete_permission(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("permission {id} not found")))
    }

    async fn list_user_settings(
        &self,
        _: &str,
        _: &UserSettingQuery,
    ) -> Result<UserSettingList, GatewayError> {
        Ok(UserSettingList { data: vec![] })
    }

    async fn get_user_setting(&self, _: &str, id: &str) -> Result<UserSetting, GatewayError> {
        Err(GatewayError::NotFound(format!(
            "user setting {id} not found"
        )))
    }

    async fn modify_user_setting(
        &self,
        _: &str,
        id: &str,
        _: ModifyUserSettingInput,
    ) -> Result<UserSetting, GatewayError> {
        Err(GatewayError::NotFound(format!(
            "user setting {id} not found"
        )))
    }
}

/// Mock target port for tests that validate session gating and audit behavior.
#[derive(Clone, Default)]
pub(crate) struct MockTargetPort {
    pub(crate) should_fail: bool,
}

#[async_trait]
impl TargetPort for MockTargetPort {
    async fn list_targets(
        &self,
        _session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        if self.should_fail {
            return Err(GatewayError::BackendUnavailable("mock error".to_string()));
        }
        Ok(TargetPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_target(
        &self,
        _session_token: &str,
        _input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
        if self.should_fail {
            return Err(GatewayError::BackendUnavailable("mock error".to_string()));
        }
        Ok("mock-target-id".to_string())
    }

    async fn clone_target(&self, _session_token: &str, _id: &str) -> Result<String, GatewayError> {
        if self.should_fail {
            return Err(GatewayError::BackendUnavailable("mock error".to_string()));
        }
        Ok("mock-target-clone-id".to_string())
    }

    async fn get_target(&self, _session_token: &str, id: &str) -> Result<Target, GatewayError> {
        if self.should_fail {
            return Err(GatewayError::NotFound(format!("target {id} not found")));
        }
        Ok(Target {
            id: id.to_string(),
            name: "Mock Target".to_string(),
            comment: None,
            hosts: vec!["10.0.0.1".to_string()],
            exclude_hosts: vec![],
            alive_test: None,
            port_list: None,
            reverse_lookup_only: false,
            reverse_lookup_unify: false,
            ssh_credential: None,
            smb_credential: None,
            esxi_credential: None,
            snmp_credential: None,
            in_use: false,
            writable: true,
        })
    }

    async fn modify_target(
        &self,
        _session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        if self.should_fail {
            return Err(GatewayError::NotFound(format!("target {id} not found")));
        }
        Ok(Target {
            id: id.to_string(),
            name: input.name.unwrap_or_else(|| "Modified Target".to_string()),
            comment: input.comment,
            hosts: input.hosts.unwrap_or_else(|| vec!["10.0.0.1".to_string()]),
            exclude_hosts: input.exclude_hosts.unwrap_or_default(),
            alive_test: input.alive_test,
            port_list: None,
            reverse_lookup_only: false,
            reverse_lookup_unify: false,
            ssh_credential: None,
            smb_credential: None,
            esxi_credential: None,
            snmp_credential: None,
            in_use: false,
            writable: true,
        })
    }

    async fn delete_target(
        &self,
        _session_token: &str,
        id: &str,
        _: bool,
    ) -> Result<(), GatewayError> {
        if self.should_fail {
            return Err(GatewayError::NotFound(format!("target {id} not found")));
        }
        Ok(())
    }
}

/// Mock task port for tests that exercise task orchestration without backend state.
#[derive(Clone, Default)]
pub(crate) struct MockTaskPort;

#[async_trait]
impl TaskPort for MockTaskPort {
    async fn list_tasks(&self, _: &str, query: &TaskQuery) -> Result<TaskPage, GatewayError> {
        Ok(TaskPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_task(&self, _: &str, _: CreateTaskInput) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000001".to_string())
    }

    async fn clone_task(&self, _: &str, _: &str) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000002".to_string())
    }

    async fn get_task(&self, _: &str, id: &str) -> Result<Task, GatewayError> {
        Err(GatewayError::NotFound(format!("task {id} not found")))
    }

    async fn modify_task(
        &self,
        _: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        Ok(Task {
            id: id.to_string(),
            name: input.name.unwrap_or_else(|| "Modified Task".to_string()),
            comment: input.comment,
            status: "New".to_string(),
            progress: None,
            target: None,
            scan_config: None,
            scanner: None,
            schedule: None,
            alerts: vec![],
            alterable: None,
            hosts_ordering: input.hosts_ordering,
            observers: gvm_gateway_domain::TaskObservers {
                users: input.observers,
                groups: vec![],
                roles: vec![],
            },
            schedule_periods: input.schedule_periods,
            last_report: None,
            current_report: None,
            report_count: None,
            in_use: false,
            writable: true,
        })
    }

    async fn delete_task(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn start_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Ok(TaskAction {
            report_id: "00000000-0000-0000-0000-000000000002".to_string(),
        })
    }

    async fn stop_task(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn resume_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Ok(TaskAction {
            report_id: "00000000-0000-0000-0000-000000000003".to_string(),
        })
    }

    async fn list_audits(&self, _: &str, query: &TaskQuery) -> Result<TaskPage, GatewayError> {
        Ok(TaskPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_audit(&self, _: &str, _: CreateTaskInput) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000004".to_string())
    }

    async fn modify_audit(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        self.modify_task(session_token, id, input).await
    }

    async fn delete_audit(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn get_audit(&self, _: &str, id: &str) -> Result<Task, GatewayError> {
        Err(GatewayError::NotFound(format!("audit {id} not found")))
    }

    async fn start_audit(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Ok(TaskAction {
            report_id: "00000000-0000-0000-0000-000000000030".to_string(),
        })
    }

    async fn stop_audit(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn resume_audit(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Ok(TaskAction {
            report_id: "00000000-0000-0000-0000-000000000031".to_string(),
        })
    }
}

/// Mock auth port for tests that need controlled auth and disconnect outcomes.
#[derive(Clone)]
pub(crate) struct MockAuthPort {
    pub(crate) should_fail: bool,
    pub(crate) disconnect_should_fail: bool,
    pub(crate) gmp_version: String,
    pub(crate) disconnected: Arc<std::sync::Mutex<Vec<gvm_gateway_domain::SessionTokenDigest>>>,
}

impl Default for MockAuthPort {
    fn default() -> Self {
        Self {
            should_fail: false,
            disconnect_should_fail: false,
            gmp_version: "22.7".to_string(),
            disconnected: Arc::new(std::sync::Mutex::new(vec![])),
        }
    }
}

#[async_trait]
impl AuthPort for MockAuthPort {
    async fn authenticate_session(
        &self,
        _session_token: &str,
        _username: &str,
        _password: &str,
    ) -> Result<String, GatewayError> {
        if self.should_fail {
            return Err(GatewayError::Unauthorized(
                "invalid credentials".to_string(),
            ));
        }
        Ok(self.gmp_version.clone())
    }

    async fn disconnect_session(
        &self,
        session: &gvm_gateway_domain::SessionTokenDigest,
    ) -> Result<(), GatewayError> {
        if self.disconnect_should_fail {
            return Err(GatewayError::BackendUnavailable(
                "disconnect failed".to_string(),
            ));
        }
        self.disconnected.lock().unwrap().push(*session);
        Ok(())
    }
}

/// Mock report port for tests that validate report resource session flow.
#[derive(Clone, Default)]
pub(crate) struct MockReportPort;

#[async_trait]
impl ReportPort for MockReportPort {
    async fn list_reports(&self, _: &str, query: &ReportQuery) -> Result<ReportPage, GatewayError> {
        Ok(ReportPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_report(
        &self,
        _: &str,
        id: &str,
        _: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        Err(GatewayError::NotFound(format!("report {id} not found")))
    }

    async fn export_report(
        &self,
        _: &str,
        report_id: &str,
        _: &ReportExportRequest,
    ) -> Result<ReportExport, GatewayError> {
        Err(GatewayError::NotFound(format!(
            "report {report_id} not found"
        )))
    }

    async fn delete_report(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("report {id} not found")))
    }

    async fn get_report_results(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(ResultPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_report_vulnerabilities(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(ResultPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_report_tls_certificates(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        Ok(TlsCertificatePage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_report_errors(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(ResultPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_report_closed_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(ResultPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }
}

/// Mock result port for tests that validate result resource session flow.
#[derive(Clone, Default)]
pub(crate) struct MockResultPort;

#[async_trait]
impl ResultPort for MockResultPort {
    async fn list_results(&self, _: &str, query: &ResultQuery) -> Result<ResultPage, GatewayError> {
        Ok(ResultPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_result(&self, _: &str, id: &str) -> Result<ScanResult, GatewayError> {
        Err(GatewayError::NotFound(format!("result {id} not found")))
    }
}

/// Mock scan-config port for tests that validate scan-config session flow.
#[derive(Clone, Default)]
pub(crate) struct MockScanConfigPort;

#[async_trait]
impl ScanConfigPort for MockScanConfigPort {
    async fn list_scan_configs(
        &self,
        _: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        Ok(ScanConfigPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_scan_config(
        &self,
        _: &str,
        _: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        Ok("mock-scan-config-id".to_string())
    }

    async fn get_scan_config(&self, _: &str, id: &str) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::NotFound(format!(
            "scan config {id} not found"
        )))
    }

    async fn modify_scan_config(
        &self,
        _: &str,
        id: &str,
        _: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::NotFound(format!(
            "scan config {id} not found"
        )))
    }

    async fn delete_scan_config(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!(
            "scan config {id} not found"
        )))
    }

    async fn list_policies(
        &self,
        _: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        Ok(ScanConfigPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_policy(
        &self,
        _: &str,
        _: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        Ok("mock-policy-id".to_string())
    }

    async fn modify_policy(
        &self,
        _: &str,
        id: &str,
        _: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::NotFound(format!("policy {id} not found")))
    }

    async fn delete_policy(&self, _: &str, id: &str) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("policy {id} not found")))
    }

    async fn get_policy(&self, _: &str, id: &str) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::NotFound(format!("policy {id} not found")))
    }
}

/// Mock scanner port for tests that validate scanner read session flow.
#[derive(Clone, Default)]
pub(crate) struct MockScannerPort;

#[async_trait]
impl ScannerPort for MockScannerPort {
    async fn list_scanners(
        &self,
        _: &str,
        query: &ScannerQuery,
    ) -> Result<ScannerPage, GatewayError> {
        Ok(ScannerPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_scanner(&self, _: &str, id: &str) -> Result<Scanner, GatewayError> {
        Err(GatewayError::NotFound(format!("scanner {id} not found")))
    }
}

/// Mock supporting-resource port for tests that validate supporting catalog session flow.
#[derive(Clone, Default)]
pub(crate) struct MockSupportingResourcePort;

#[async_trait]
impl SupportingResourcePort for MockSupportingResourcePort {
    async fn list_hosts(
        &self,
        _: &str,
        query: &SupportingResourceQuery,
    ) -> Result<HostPage, GatewayError> {
        Ok(HostPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_host(&self, _: &str, id: &str) -> Result<Host, GatewayError> {
        Err(GatewayError::NotFound(format!("host {id} not found")))
    }

    async fn list_tls_certificates(
        &self,
        _: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TlsCertificateAssetPage, GatewayError> {
        Ok(TlsCertificateAssetPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_tls_certificate(
        &self,
        _: &str,
        id: &str,
    ) -> Result<TlsCertificateAsset, GatewayError> {
        Err(GatewayError::NotFound(format!(
            "tls certificate {id} not found"
        )))
    }

    async fn list_report_formats(
        &self,
        _: &str,
        query: &SupportingResourceQuery,
    ) -> Result<ReportFormatPage, GatewayError> {
        Ok(ReportFormatPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_report_format(&self, _: &str, id: &str) -> Result<ReportFormat, GatewayError> {
        Err(GatewayError::NotFound(format!(
            "report format {id} not found"
        )))
    }

    async fn list_filters(
        &self,
        _: &str,
        query: &SupportingResourceQuery,
    ) -> Result<FilterPage, GatewayError> {
        Ok(FilterPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_filter(&self, _: &str, id: &str) -> Result<Filter, GatewayError> {
        Err(GatewayError::NotFound(format!("filter {id} not found")))
    }

    async fn list_tags(
        &self,
        _: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TagPage, GatewayError> {
        Ok(TagPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_tag(&self, _: &str, id: &str) -> Result<Tag, GatewayError> {
        Err(GatewayError::NotFound(format!("tag {id} not found")))
    }

    async fn list_tickets(
        &self,
        _: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TicketPage, GatewayError> {
        Ok(TicketPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_ticket(&self, _: &str, id: &str) -> Result<Ticket, GatewayError> {
        Err(GatewayError::NotFound(format!("ticket {id} not found")))
    }

    async fn list_notes(
        &self,
        _: &str,
        query: &SupportingResourceQuery,
    ) -> Result<NotePage, GatewayError> {
        Ok(NotePage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_note(&self, _: &str, id: &str) -> Result<Note, GatewayError> {
        Err(GatewayError::NotFound(format!("note {id} not found")))
    }

    async fn create_note(&self, _: &str, _: CreateNoteInput) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000031".to_string())
    }

    async fn modify_note(
        &self,
        _: &str,
        id: &str,
        _: ModifyNoteInput,
    ) -> Result<Note, GatewayError> {
        Err(GatewayError::NotFound(format!("note {id} not found")))
    }

    async fn delete_note(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("note {id} not found")))
    }

    async fn list_overrides(
        &self,
        _: &str,
        query: &SupportingResourceQuery,
    ) -> Result<OverridePage, GatewayError> {
        Ok(OverridePage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_override(&self, _: &str, id: &str) -> Result<Override, GatewayError> {
        Err(GatewayError::NotFound(format!("override {id} not found")))
    }

    async fn create_override(
        &self,
        _: &str,
        _: CreateOverrideInput,
    ) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000032".to_string())
    }

    async fn modify_override(
        &self,
        _: &str,
        id: &str,
        _: ModifyOverrideInput,
    ) -> Result<Override, GatewayError> {
        Err(GatewayError::NotFound(format!("override {id} not found")))
    }

    async fn delete_override(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("override {id} not found")))
    }

    async fn list_nvts(
        &self,
        _: &str,
        query: &SupportingResourceQuery,
    ) -> Result<NvtPage, GatewayError> {
        Ok(NvtPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_nvt(&self, _: &str, oid: &str) -> Result<Nvt, GatewayError> {
        Err(GatewayError::NotFound(format!("nvt {oid} not found")))
    }

    async fn list_nvt_families(
        &self,
        _: &str,
        page: u32,
        per_page: u32,
    ) -> Result<NvtFamilyPage, GatewayError> {
        Ok(NvtFamilyPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page,
                per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn list_vulnerabilities(
        &self,
        _: &str,
        query: &SupportingResourceQuery,
    ) -> Result<VulnerabilityPage, GatewayError> {
        Ok(VulnerabilityPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }
}
