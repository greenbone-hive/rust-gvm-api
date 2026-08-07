// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Port traits describing backend-facing gateway operations.

use async_trait::async_trait;

use crate::{
    Alert, AlertPage, AlertQuery, CreateAlertInput, CreateCredentialInput, CreateGroupInput,
    CreateNoteInput, CreateOverrideInput, CreatePermissionInput, CreatePortListInput,
    CreateRoleInput, CreateScanConfigInput, CreateScheduleInput, CreateTargetInput,
    CreateTaskInput, CreateUserInput, Credential, CredentialPage, CredentialQuery, CredentialStore,
    Feed, Filter, FilterPage, GatewayError, GetReportOpts, Group, GroupPage, Host, HostPage,
    IdentityQuery, ModifyAlertInput, ModifyCredentialInput, ModifyGroupInput, ModifyNoteInput,
    ModifyOverrideInput, ModifyPermissionInput, ModifyPortListInput, ModifyRoleInput,
    ModifyScanConfigInput, ModifyScheduleInput, ModifyTargetInput, ModifyTaskInput,
    ModifyUserInput, ModifyUserSettingInput, Note, NotePage, Nvt, NvtFamilyPage, NvtPage, Override,
    OverridePage, Permission, PermissionPage, PortList, PortListPage, PortListQuery,
    ReadinessStatus, Report, ReportExport, ReportExportRequest, ReportFormat, ReportFormatPage,
    ReportPage, ReportQuery, ResultPage, ResultQuery, Role, RolePage, ScanConfig, ScanConfigPage,
    ScanConfigQuery, ScanResult, Scanner, ScannerPage, ScannerQuery, Schedule, SchedulePage,
    ScheduleQuery, SupportingResourceQuery, Tag, TagPage, Target, TargetPage, TargetQuery, Task,
    TaskAction, TaskPage, TaskQuery, Ticket, TicketPage, TlsCertificateAsset,
    TlsCertificateAssetPage, TlsCertificatePage, User, UserPage, UserSetting, UserSettingList,
    UserSettingQuery, VulnerabilityPage,
};

/// Port for system information needed by the gateway.
#[async_trait]
pub trait SystemPort: Send + Sync + 'static {
    /// Returns whether the backend is ready.
    async fn readiness(&self) -> Result<ReadinessStatus, GatewayError>;

    /// Returns the GMP version string for the connected backend.
    async fn gmp_version(&self) -> Result<String, GatewayError>;
}

/// Port for session authentication with the backend.
#[async_trait]
pub trait AuthPort: Send + Sync + 'static {
    /// Authenticate and establish a backend connection for the session.
    ///
    /// Returns the GMP version negotiated for the authenticated backend
    /// connection.
    async fn authenticate_session(
        &self,
        session_token: &str,
        username: &str,
        password: &str,
    ) -> Result<String, GatewayError>;

    /// Disconnect and clean up the backend connection for a session.
    async fn disconnect_session(
        &self,
        session: &crate::SessionTokenDigest,
    ) -> Result<(), GatewayError>;
}

/// Port for alert CRUD operations.
#[async_trait]
pub trait AlertPort: Send + Sync + 'static {
    /// List alerts for the session.
    async fn list_alerts(
        &self,
        session_token: &str,
        query: &AlertQuery,
    ) -> Result<AlertPage, GatewayError>;

    /// Create a new alert.
    async fn create_alert(
        &self,
        session_token: &str,
        input: CreateAlertInput,
    ) -> Result<String, GatewayError>;

    /// Fetch an alert by identifier.
    async fn get_alert(&self, session_token: &str, id: &str) -> Result<Alert, GatewayError>;

    /// Modify an alert by identifier.
    async fn modify_alert(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAlertInput,
    ) -> Result<Alert, GatewayError>;

    /// Delete an alert by identifier.
    async fn delete_alert(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;
}

/// Port for schedule CRUD operations.
#[async_trait]
pub trait SchedulePort: Send + Sync + 'static {
    /// List schedules for the session.
    async fn list_schedules(
        &self,
        session_token: &str,
        query: &ScheduleQuery,
    ) -> Result<SchedulePage, GatewayError>;

    /// Create a new schedule.
    async fn create_schedule(
        &self,
        session_token: &str,
        input: CreateScheduleInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a schedule by identifier.
    async fn get_schedule(&self, session_token: &str, id: &str) -> Result<Schedule, GatewayError>;

    /// Modify a schedule by identifier.
    async fn modify_schedule(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScheduleInput,
    ) -> Result<Schedule, GatewayError>;

    /// Delete a schedule by identifier.
    async fn delete_schedule(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;
}

/// Port for credential CRUD operations.
#[async_trait]
pub trait CredentialPort: Send + Sync + 'static {
    /// List credential stores available to the backend.
    async fn list_credential_stores(
        &self,
        session_token: &str,
    ) -> Result<Vec<CredentialStore>, GatewayError>;

    /// List credentials for the session.
    async fn list_credentials(
        &self,
        session_token: &str,
        query: &CredentialQuery,
    ) -> Result<CredentialPage, GatewayError>;

    /// Create a new credential.
    async fn create_credential(
        &self,
        session_token: &str,
        input: CreateCredentialInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a credential by identifier.
    async fn get_credential(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Credential, GatewayError>;

    /// Modify a credential by identifier.
    async fn modify_credential(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyCredentialInput,
    ) -> Result<Credential, GatewayError>;

    /// Delete a credential by identifier.
    async fn delete_credential(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;
}

/// Port for port-list CRUD operations.
#[async_trait]
pub trait PortListPort: Send + Sync + 'static {
    /// List port lists for the session.
    async fn list_port_lists(
        &self,
        session_token: &str,
        query: &PortListQuery,
    ) -> Result<PortListPage, GatewayError>;

    /// Create a new port list.
    async fn create_port_list(
        &self,
        session_token: &str,
        input: CreatePortListInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a port list by identifier.
    async fn get_port_list(&self, session_token: &str, id: &str) -> Result<PortList, GatewayError>;

    /// Modify a port list by identifier.
    async fn modify_port_list(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyPortListInput,
    ) -> Result<PortList, GatewayError>;

    /// Delete a port list by identifier.
    async fn delete_port_list(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;
}

/// Port for feed status.
#[async_trait]
pub trait FeedPort: Send + Sync + 'static {
    /// List feed status for the session.
    async fn list_feeds(&self, session_token: &str) -> Result<Vec<Feed>, GatewayError>;
}

/// Port for identity and access-control operations.
#[async_trait]
pub trait IdentityPort: Send + Sync + 'static {
    /// List users for the session.
    async fn list_users(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<UserPage, GatewayError>;

    /// Create a new user.
    async fn create_user(
        &self,
        session_token: &str,
        input: CreateUserInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a user by identifier.
    async fn get_user(&self, session_token: &str, id: &str) -> Result<User, GatewayError>;

    /// Modify a user by identifier.
    async fn modify_user(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyUserInput,
    ) -> Result<User, GatewayError>;

    /// Delete a user by identifier.
    async fn delete_user(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// List groups for the session.
    async fn list_groups(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<GroupPage, GatewayError>;

    /// Create a new group.
    async fn create_group(
        &self,
        session_token: &str,
        input: CreateGroupInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a group by identifier.
    async fn get_group(&self, session_token: &str, id: &str) -> Result<Group, GatewayError>;

    /// Modify a group by identifier.
    async fn modify_group(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyGroupInput,
    ) -> Result<Group, GatewayError>;

    /// Delete a group by identifier.
    async fn delete_group(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// List roles for the session.
    async fn list_roles(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<RolePage, GatewayError>;

    /// Create a new role.
    async fn create_role(
        &self,
        session_token: &str,
        input: CreateRoleInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a role by identifier.
    async fn get_role(&self, session_token: &str, id: &str) -> Result<Role, GatewayError>;

    /// Modify a role by identifier.
    async fn modify_role(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyRoleInput,
    ) -> Result<Role, GatewayError>;

    /// Delete a role by identifier.
    async fn delete_role(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// List permissions for the session.
    async fn list_permissions(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<PermissionPage, GatewayError>;

    /// Create a new permission.
    async fn create_permission(
        &self,
        session_token: &str,
        input: CreatePermissionInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a permission by identifier.
    async fn get_permission(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Permission, GatewayError>;

    /// Modify a permission by identifier.
    async fn modify_permission(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyPermissionInput,
    ) -> Result<Permission, GatewayError>;

    /// Delete a permission by identifier.
    async fn delete_permission(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// List current-user settings for the session.
    async fn list_user_settings(
        &self,
        session_token: &str,
        query: &UserSettingQuery,
    ) -> Result<UserSettingList, GatewayError>;

    /// Fetch one current-user setting by identifier.
    async fn get_user_setting(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<UserSetting, GatewayError>;

    /// Modify one current-user setting by identifier.
    async fn modify_user_setting(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyUserSettingInput,
    ) -> Result<UserSetting, GatewayError>;
}

/// Port for report operations.
#[async_trait]
pub trait ReportPort: Send + Sync + 'static {
    /// List reports for the session.
    async fn list_reports(
        &self,
        session_token: &str,
        query: &ReportQuery,
    ) -> Result<ReportPage, GatewayError>;

    /// Fetch a report by identifier, optionally with embedded results.
    async fn get_report(
        &self,
        session_token: &str,
        id: &str,
        opts: &GetReportOpts,
    ) -> Result<Report, GatewayError>;

    /// Export a report in the selected backend report format.
    async fn export_report(
        &self,
        session_token: &str,
        report_id: &str,
        request: &ReportExportRequest,
    ) -> Result<ReportExport, GatewayError>;

    /// Delete a report by identifier.
    async fn delete_report(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// List results for a specific report.
    async fn get_report_results(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError>;

    /// List vulnerability findings for a specific report.
    async fn get_report_vulnerabilities(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError>;

    /// List TLS certificate observations for a specific report.
    async fn get_report_tls_certificates(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError>;

    /// List report errors for a specific report.
    async fn get_report_errors(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError>;

    /// List closed-CVE findings for a specific report.
    async fn get_report_closed_cves(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError>;
}

/// Port for result operations.
#[async_trait]
pub trait ResultPort: Send + Sync + 'static {
    /// List results for the session.
    async fn list_results(
        &self,
        session_token: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError>;

    /// Fetch a result by identifier.
    async fn get_result(&self, session_token: &str, id: &str) -> Result<ScanResult, GatewayError>;
}

/// Port for scan config CRUD operations.
#[async_trait]
pub trait ScanConfigPort: Send + Sync + 'static {
    /// List scan configs for the session.
    async fn list_scan_configs(
        &self,
        session_token: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError>;

    /// Create a new scan config.
    async fn create_scan_config(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a scan config by identifier.
    async fn get_scan_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanConfig, GatewayError>;

    /// Modify a scan config by identifier.
    async fn modify_scan_config(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError>;

    /// Delete a scan config by identifier.
    async fn delete_scan_config(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// List policies (compliance scan configs) for the session.
    async fn list_policies(
        &self,
        session_token: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError>;

    /// Fetch a policy by identifier.
    async fn get_policy(&self, session_token: &str, id: &str) -> Result<ScanConfig, GatewayError>;

    /// Create a new policy (compliance scan config).
    async fn create_policy(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError>;

    /// Modify a policy by identifier.
    async fn modify_policy(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError>;

    /// Delete a policy by identifier.
    async fn delete_policy(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;
}

/// Port for scanner read operations.
#[async_trait]
pub trait ScannerPort: Send + Sync + 'static {
    /// List scanners for the session.
    async fn list_scanners(
        &self,
        session_token: &str,
        query: &ScannerQuery,
    ) -> Result<ScannerPage, GatewayError>;

    /// Fetch a scanner by identifier.
    async fn get_scanner(&self, session_token: &str, id: &str) -> Result<Scanner, GatewayError>;
}

/// Port for supporting report-format, triage, asset, and NVT catalogs.
#[async_trait]
pub trait SupportingResourcePort: Send + Sync + 'static {
    /// List hosts for the session.
    async fn list_hosts(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<HostPage, GatewayError>;

    /// Fetch a host by identifier.
    async fn get_host(&self, session_token: &str, id: &str) -> Result<Host, GatewayError>;

    /// List TLS certificate assets for the session.
    async fn list_tls_certificates(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TlsCertificateAssetPage, GatewayError>;

    /// Fetch a TLS certificate asset by identifier.
    async fn get_tls_certificate(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TlsCertificateAsset, GatewayError>;

    /// List report formats for the session.
    async fn list_report_formats(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<ReportFormatPage, GatewayError>;

    /// Fetch a report format by identifier.
    async fn get_report_format(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ReportFormat, GatewayError>;

    /// List saved filters for the session.
    async fn list_filters(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<FilterPage, GatewayError>;

    /// Fetch a saved filter by identifier.
    async fn get_filter(&self, session_token: &str, id: &str) -> Result<Filter, GatewayError>;

    /// List tags for the session.
    async fn list_tags(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TagPage, GatewayError>;

    /// Fetch a tag by identifier.
    async fn get_tag(&self, session_token: &str, id: &str) -> Result<Tag, GatewayError>;

    /// List tickets for the session.
    async fn list_tickets(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TicketPage, GatewayError>;

    /// Fetch a ticket by identifier.
    async fn get_ticket(&self, session_token: &str, id: &str) -> Result<Ticket, GatewayError>;

    /// List notes for the session.
    async fn list_notes(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<NotePage, GatewayError>;

    /// Fetch a note by identifier.
    async fn get_note(&self, session_token: &str, id: &str) -> Result<Note, GatewayError>;

    /// Create a note.
    async fn create_note(
        &self,
        session_token: &str,
        input: CreateNoteInput,
    ) -> Result<String, GatewayError>;

    /// Modify a note by identifier.
    async fn modify_note(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyNoteInput,
    ) -> Result<Note, GatewayError>;

    /// Delete a note by identifier.
    async fn delete_note(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// List overrides for the session.
    async fn list_overrides(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<OverridePage, GatewayError>;

    /// Fetch an override by identifier.
    async fn get_override(&self, session_token: &str, id: &str) -> Result<Override, GatewayError>;

    /// Create an override.
    async fn create_override(
        &self,
        session_token: &str,
        input: CreateOverrideInput,
    ) -> Result<String, GatewayError>;

    /// Modify an override by identifier.
    async fn modify_override(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyOverrideInput,
    ) -> Result<Override, GatewayError>;

    /// Delete an override by identifier.
    async fn delete_override(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// List NVTs for the session.
    async fn list_nvts(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<NvtPage, GatewayError>;

    /// Fetch an NVT by OID.
    async fn get_nvt(&self, session_token: &str, oid: &str) -> Result<Nvt, GatewayError>;

    /// List NVT families for the session.
    async fn list_nvt_families(
        &self,
        session_token: &str,
        page: u32,
        per_page: u32,
    ) -> Result<NvtFamilyPage, GatewayError>;

    /// List vulnerabilities (SecInfo) for the session.
    async fn list_vulnerabilities(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<VulnerabilityPage, GatewayError>;
}

/// Port for target CRUD operations.
#[async_trait]
pub trait TargetPort: Send + Sync + 'static {
    /// List targets for the session.
    async fn list_targets(
        &self,
        session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError>;

    /// Create a new target.
    async fn create_target(
        &self,
        session_token: &str,
        input: CreateTargetInput,
    ) -> Result<String, GatewayError>;

    /// Clone an existing target. Returns the identifier of the new target.
    async fn clone_target(&self, session_token: &str, id: &str) -> Result<String, GatewayError>;

    /// Fetch a target by identifier.
    async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError>;

    /// Modify a target by identifier.
    async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError>;

    /// Delete a target by identifier.
    async fn delete_target(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;
}

/// Port for task CRUD and lifecycle operations.
#[async_trait]
pub trait TaskPort: Send + Sync + 'static {
    /// List tasks for the session.
    async fn list_tasks(
        &self,
        session_token: &str,
        query: &TaskQuery,
    ) -> Result<TaskPage, GatewayError>;

    /// Create a new task.
    async fn create_task(
        &self,
        session_token: &str,
        input: CreateTaskInput,
    ) -> Result<String, GatewayError>;

    /// Clone an existing task. Returns the identifier of the new task.
    async fn clone_task(&self, session_token: &str, id: &str) -> Result<String, GatewayError>;

    /// Fetch a task by identifier.
    async fn get_task(&self, session_token: &str, id: &str) -> Result<Task, GatewayError>;

    /// Modify a task by identifier.
    async fn modify_task(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError>;

    /// Delete a task by identifier.
    async fn delete_task(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// Start a task. Returns the report identifier created by the action.
    async fn start_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError>;

    /// Stop a running task.
    async fn stop_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;

    /// Resume a stopped task. Returns the report identifier created by the action.
    async fn resume_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError>;

    /// List audits (compliance tasks) for the session.
    async fn list_audits(
        &self,
        session_token: &str,
        query: &TaskQuery,
    ) -> Result<TaskPage, GatewayError>;

    /// Fetch an audit by identifier.
    async fn get_audit(&self, session_token: &str, id: &str) -> Result<Task, GatewayError>;

    /// Create a new audit (compliance task).
    async fn create_audit(
        &self,
        session_token: &str,
        input: CreateTaskInput,
    ) -> Result<String, GatewayError>;

    /// Modify an audit by identifier.
    async fn modify_audit(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError>;

    /// Delete an audit by identifier.
    async fn delete_audit(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;

    /// Start an audit. Returns the report identifier created by the action.
    async fn start_audit(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError>;

    /// Stop a running audit.
    async fn stop_audit(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;

    /// Resume a stopped audit. Returns the report identifier created by the action.
    async fn resume_audit(&self, session_token: &str, id: &str)
        -> Result<TaskAction, GatewayError>;
}
