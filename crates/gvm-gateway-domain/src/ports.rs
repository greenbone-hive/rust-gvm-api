// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Port traits describing backend-facing gateway operations.

use async_trait::async_trait;

use crate::{
    Agent, AgentGroup, AgentGroupPage, AgentGroupQuery, AgentInstallerInstruction,
    AgentInstallerInstructionQuery, AgentPage, AgentQuery, AgentSupportBundle,
    AgentSupportBundleQuery, Alert, AlertPage, AlertQuery, AssetQuery, CertBundAdvisory,
    CertBundAdvisoryPage, Cpe, CpePage, CreateAgentGroupInput, CreateAlertInput,
    CreateCredentialInput, CreateFilterInput, CreateGroupInput, CreateHostInput, CreateNoteInput,
    CreateOciImageTargetInput, CreateOverrideInput, CreatePermissionInput, CreatePortListInput,
    CreateRoleInput, CreateScanConfigInput, CreateScheduleInput, CreateTagInput, CreateTargetInput,
    CreateTaskInput, CreateUserInput, CreateWebApplicationTargetInput, Credential, CredentialPage,
    CredentialQuery, CredentialStore, Cve, CvePage, DfnCertAdvisory, DfnCertAdvisoryPage, FeedList,
    FeedQuery, Filter, FilterPage, GatewayError, GenericAsset, GenericAssetPage, GenericConfig,
    GenericConfigPage, GenericConfigQuery, GetReportOpts, Group, GroupPage, Host, HostPage,
    IdentityQuery, ModifyAgentControlScanConfigInput, ModifyAgentGroupInput, ModifyAgentInput,
    ModifyAlertInput, ModifyAssetInput, ModifyCredentialInput, ModifyCredentialStoreInput,
    ModifyFilterInput, ModifyGroupInput, ModifyHostInput, ModifyNoteInput,
    ModifyOciImageTargetInput, ModifyOperatingSystemInput, ModifyOverrideInput,
    ModifyPermissionInput, ModifyPortListInput, ModifyRoleInput, ModifyScanConfigInput,
    ModifyScheduleInput, ModifyTagInput, ModifyTargetInput, ModifyTaskInput, ModifyUserInput,
    ModifyUserSettingInput, ModifyWebApplicationTargetInput, Note, NotePage, Nvt, NvtFamilyPage,
    NvtPage, NvtQuery, OciImageTarget, OciImageTargetPage, OperatingSystem, OperatingSystemPage,
    Override, OverridePage, Permission, PermissionPage, PortList, PortListPage, PortListQuery,
    ReadinessStatus, Report, ReportApplicationPage, ReportClosedCvePage, ReportCvePage,
    ReportErrorPage, ReportExport, ReportExportRequest, ReportFormat, ReportFormatPage,
    ReportHostPage, ReportOperatingSystemPage, ReportPage, ReportPortPage, ReportQuery,
    ReportVulnerabilityPage, ResultPage, ResultQuery, Role, RolePage, ScanConfig,
    ScanConfigNvtPage, ScanConfigNvtQuery, ScanConfigPage, ScanConfigPreference,
    ScanConfigPreferenceQuery, ScanConfigQuery, ScanResult, Scanner, ScannerPage, ScannerQuery,
    Schedule, SchedulePage, ScheduleQuery, SetScanConfigFamilySelectionInput,
    SpecializedTargetQuery, SupportingResourceQuery, Tag, TagPage, Target, TargetPage, TargetQuery,
    Task, TaskAction, TaskPage, TaskQuery, Ticket, TicketPage, Timezone, TlsCertificateAsset,
    TlsCertificateAssetPage, TlsCertificatePage, User, UserPage, UserSetting, UserSettingList,
    UserSettingQuery, VulnerabilityPage, WebApplicationTarget, WebApplicationTargetPage,
};

/// Port for system information needed by the gateway.
#[async_trait]
pub trait SystemPort: Send + Sync + 'static {
    /// Returns whether the backend is ready.
    async fn readiness(&self) -> Result<ReadinessStatus, GatewayError>;

    /// Returns the GMP version string for the connected backend.
    async fn gmp_version(&self) -> Result<String, GatewayError>;

    /// Lists backend timezones for the authenticated session.
    async fn list_timezones(&self, session_token: &str) -> Result<Vec<Timezone>, GatewayError>;
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

    /// Fetch one backend credential store.
    async fn get_credential_store(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<CredentialStore, GatewayError>;

    /// Modify one backend credential store.
    async fn modify_credential_store(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyCredentialStoreInput,
    ) -> Result<CredentialStore, GatewayError>;

    /// Verify one backend credential store connection.
    async fn verify_credential_store(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<(), GatewayError>;

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
    async fn list_feeds(
        &self,
        session_token: &str,
        query: &FeedQuery,
    ) -> Result<FeedList, GatewayError>;
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
    ) -> Result<ReportVulnerabilityPage, GatewayError>;

    /// List host summaries for a specific report.
    async fn get_report_hosts(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportHostPage, GatewayError>;

    /// List port summaries for a specific report.
    async fn get_report_ports(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportPortPage, GatewayError>;

    /// List application summaries for a specific report.
    async fn get_report_applications(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportApplicationPage, GatewayError>;

    /// List operating-system summaries for a specific report.
    async fn get_report_operating_systems(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportOperatingSystemPage, GatewayError>;

    /// List CVE summaries for a specific report.
    async fn get_report_cves(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportCvePage, GatewayError>;

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
    ) -> Result<ReportErrorPage, GatewayError>;

    /// List closed-CVE findings for a specific report.
    async fn get_report_closed_cves(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportClosedCvePage, GatewayError>;
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
    /// List generic configs for the session.
    async fn list_configs(
        &self,
        session_token: &str,
        query: &GenericConfigQuery,
    ) -> Result<GenericConfigPage, GatewayError>;

    /// Fetch a generic config by identifier.
    async fn get_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<GenericConfig, GatewayError>;

    /// Delete a generic config by identifier.
    async fn delete_config(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// Clone a generic config by identifier.
    async fn clone_config(&self, session_token: &str, id: &str) -> Result<String, GatewayError>;

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

    /// List NVTs selected by a scan configuration.
    async fn list_scan_config_nvts(
        &self,
        session_token: &str,
        id: &str,
        query: &ScanConfigNvtQuery,
    ) -> Result<ScanConfigNvtPage, GatewayError>;

    /// Fetch one selected NVT.
    async fn get_scan_config_nvt(
        &self,
        session_token: &str,
        id: &str,
        oid: &str,
    ) -> Result<Nvt, GatewayError>;

    /// List scanner or NVT preferences resolved for a scan configuration.
    async fn list_scan_config_preferences(
        &self,
        session_token: &str,
        id: &str,
        query: &ScanConfigPreferenceQuery,
    ) -> Result<Vec<ScanConfigPreference>, GatewayError>;

    /// Fetch one scanner or NVT preference.
    async fn get_scan_config_preference(
        &self,
        session_token: &str,
        id: &str,
        name: &str,
        query: &ScanConfigPreferenceQuery,
    ) -> Result<ScanConfigPreference, GatewayError>;

    /// Replace the selected NVTs for one family.
    async fn set_scan_config_nvt_selection(
        &self,
        session_token: &str,
        id: &str,
        family: &str,
        nvt_oids: Vec<String>,
    ) -> Result<(), GatewayError>;

    /// Replace scan-config family selection atomically.
    async fn set_scan_config_family_selection(
        &self,
        session_token: &str,
        id: &str,
        input: SetScanConfigFamilySelectionInput,
    ) -> Result<(), GatewayError>;

    /// Set or reset a scanner or NVT preference.
    async fn set_scan_config_preference(
        &self,
        session_token: &str,
        id: &str,
        name: &str,
        nvt_oid: Option<String>,
        value: Option<String>,
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

/// Port for agent and agent-group management operations.
#[async_trait]
pub trait AgentPort: Send + Sync + 'static {
    /// List agents for the session.
    async fn list_agents(
        &self,
        session_token: &str,
        query: &AgentQuery,
    ) -> Result<AgentPage, GatewayError>;

    /// Fetch an agent by identifier.
    async fn get_agent(&self, session_token: &str, id: &str) -> Result<Agent, GatewayError>;

    /// Modify an agent by identifier.
    async fn modify_agent(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAgentInput,
    ) -> Result<Agent, GatewayError>;

    /// Delete an agent by identifier.
    async fn delete_agent(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;

    /// Synchronize agents with the backend.
    async fn sync_agents(&self, session_token: &str) -> Result<(), GatewayError>;

    /// Download an agent support bundle.
    async fn get_agent_support_bundle(
        &self,
        session_token: &str,
        id: &str,
        query: &AgentSupportBundleQuery,
    ) -> Result<AgentSupportBundle, GatewayError>;

    /// Update agent-control scan-config defaults.
    async fn modify_agent_control_scan_config(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAgentControlScanConfigInput,
    ) -> Result<(), GatewayError>;

    /// Fetch agent installer instructions for a scanner.
    async fn get_agent_installer_instruction(
        &self,
        session_token: &str,
        scanner_id: &str,
        query: &AgentInstallerInstructionQuery,
    ) -> Result<AgentInstallerInstruction, GatewayError>;

    /// List agent groups for the session.
    async fn list_agent_groups(
        &self,
        session_token: &str,
        query: &AgentGroupQuery,
    ) -> Result<AgentGroupPage, GatewayError>;

    /// Create an agent group.
    async fn create_agent_group(
        &self,
        session_token: &str,
        input: CreateAgentGroupInput,
    ) -> Result<String, GatewayError>;

    /// Fetch an agent group by identifier.
    async fn get_agent_group(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<AgentGroup, GatewayError>;

    /// Modify an agent group by identifier.
    async fn modify_agent_group(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAgentGroupInput,
    ) -> Result<AgentGroup, GatewayError>;

    /// Delete an agent group by identifier.
    async fn delete_agent_group(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// Clone an agent group by identifier.
    async fn clone_agent_group(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<String, GatewayError>;
}

/// Port for supporting report-format, triage, asset, and NVT catalogs.
#[async_trait]
pub trait SupportingResourcePort: Send + Sync + 'static {
    /// List generic assets for the session.
    async fn list_assets(
        &self,
        session_token: &str,
        query: &AssetQuery,
    ) -> Result<GenericAssetPage, GatewayError>;

    /// Fetch a generic asset by identifier.
    async fn get_asset(
        &self,
        session_token: &str,
        id: &str,
        asset_type: &str,
    ) -> Result<GenericAsset, GatewayError>;

    /// Modify a generic asset by identifier.
    async fn modify_asset(
        &self,
        session_token: &str,
        id: &str,
        asset_type: &str,
        input: ModifyAssetInput,
    ) -> Result<GenericAsset, GatewayError>;

    /// Delete a generic asset by identifier.
    ///
    /// The gvmd generic asset delete command does not support the `ultimate`
    /// flag, so this method intentionally takes no `ultimate` argument.
    async fn delete_asset(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;

    /// List hosts for the session.
    async fn list_hosts(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<HostPage, GatewayError>;

    /// Fetch a host by identifier.
    async fn get_host(&self, session_token: &str, id: &str) -> Result<Host, GatewayError>;

    /// List operating-system assets for the session.
    async fn list_operating_systems(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<OperatingSystemPage, GatewayError>;

    /// Fetch an operating-system asset by identifier.
    async fn get_operating_system(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<OperatingSystem, GatewayError>;

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

    /// Create a host asset.
    async fn create_host(
        &self,
        session_token: &str,
        input: CreateHostInput,
    ) -> Result<String, GatewayError>;

    /// Modify a host asset by identifier.
    async fn modify_host(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyHostInput,
    ) -> Result<Host, GatewayError>;

    /// Modify an operating-system asset by identifier.
    async fn modify_operating_system(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyOperatingSystemInput,
    ) -> Result<OperatingSystem, GatewayError>;

    /// Delete a host asset by identifier.
    ///
    /// The gvmd host-asset delete command does not support the `ultimate`
    /// (permanent) flag, so this method intentionally takes no `ultimate`
    /// argument: callers cannot request a permanent delete the backend ignores.
    async fn delete_host(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;

    /// Delete an operating-system asset by identifier.
    ///
    /// The gvmd operating-system delete command does not support the
    /// `ultimate` (permanent) flag, so this method intentionally takes no
    /// `ultimate` argument.
    async fn delete_operating_system(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<(), GatewayError>;

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

    /// Create a saved filter.
    async fn create_filter(
        &self,
        session_token: &str,
        input: CreateFilterInput,
    ) -> Result<String, GatewayError>;

    /// Modify a saved filter by identifier.
    async fn modify_filter(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyFilterInput,
    ) -> Result<Filter, GatewayError>;

    /// Delete a saved filter by identifier.
    async fn delete_filter(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// Clone a saved filter by identifier.
    async fn clone_filter(&self, session_token: &str, id: &str) -> Result<String, GatewayError>;

    /// List tags for the session.
    async fn list_tags(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TagPage, GatewayError>;

    /// Fetch a tag by identifier.
    async fn get_tag(&self, session_token: &str, id: &str) -> Result<Tag, GatewayError>;

    /// Create a tag.
    async fn create_tag(
        &self,
        session_token: &str,
        input: CreateTagInput,
    ) -> Result<String, GatewayError>;

    /// Modify a tag by identifier.
    async fn modify_tag(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTagInput,
    ) -> Result<Tag, GatewayError>;

    /// Delete a tag by identifier.
    async fn delete_tag(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError>;

    /// Clone a tag by identifier.
    async fn clone_tag(&self, session_token: &str, id: &str) -> Result<String, GatewayError>;

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
        query: &NvtQuery,
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

    /// List CVEs for the session.
    async fn list_cves(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<CvePage, GatewayError>;

    /// Fetch a CVE by identifier.
    async fn get_cve(&self, session_token: &str, id: &str) -> Result<Cve, GatewayError>;

    /// List CPEs for the session.
    async fn list_cpes(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<CpePage, GatewayError>;

    /// Fetch a CPE by identifier.
    async fn get_cpe(&self, session_token: &str, id: &str) -> Result<Cpe, GatewayError>;

    /// List CERT-Bund advisories for the session.
    async fn list_cert_bund_advisories(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<CertBundAdvisoryPage, GatewayError>;

    /// Fetch a CERT-Bund advisory by identifier.
    async fn get_cert_bund_advisory(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<CertBundAdvisory, GatewayError>;

    /// List DFN-CERT advisories for the session.
    async fn list_dfn_cert_advisories(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<DfnCertAdvisoryPage, GatewayError>;

    /// Fetch a DFN-CERT advisory by identifier.
    async fn get_dfn_cert_advisory(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<DfnCertAdvisory, GatewayError>;
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

    /// List OCI image targets for the session.
    async fn list_oci_image_targets(
        &self,
        _: &str,
        _: &SpecializedTargetQuery,
    ) -> Result<OciImageTargetPage, GatewayError> {
        specialized_targets_not_implemented()
    }
    /// Create an OCI image target.
    async fn create_oci_image_target(
        &self,
        _: &str,
        _: CreateOciImageTargetInput,
    ) -> Result<String, GatewayError> {
        specialized_targets_not_implemented()
    }
    /// Clone an OCI image target.
    async fn clone_oci_image_target(&self, _: &str, _: &str) -> Result<String, GatewayError> {
        specialized_targets_not_implemented()
    }
    /// Fetch an OCI image target.
    async fn get_oci_image_target(&self, _: &str, _: &str) -> Result<OciImageTarget, GatewayError> {
        specialized_targets_not_implemented()
    }
    /// Modify an OCI image target.
    async fn modify_oci_image_target(
        &self,
        _: &str,
        _: &str,
        _: ModifyOciImageTargetInput,
    ) -> Result<OciImageTarget, GatewayError> {
        specialized_targets_not_implemented()
    }
    /// Delete an OCI image target.
    async fn delete_oci_image_target(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        specialized_targets_not_implemented()
    }

    /// List web application targets for the session.
    async fn list_web_application_targets(
        &self,
        _: &str,
        _: &SpecializedTargetQuery,
    ) -> Result<WebApplicationTargetPage, GatewayError> {
        specialized_targets_not_implemented()
    }
    /// Create a web application target.
    async fn create_web_application_target(
        &self,
        _: &str,
        _: CreateWebApplicationTargetInput,
    ) -> Result<String, GatewayError> {
        specialized_targets_not_implemented()
    }
    /// Clone a web application target.
    async fn clone_web_application_target(&self, _: &str, _: &str) -> Result<String, GatewayError> {
        specialized_targets_not_implemented()
    }
    /// Fetch a web application target.
    async fn get_web_application_target(
        &self,
        _: &str,
        _: &str,
    ) -> Result<WebApplicationTarget, GatewayError> {
        specialized_targets_not_implemented()
    }
    /// Modify a web application target.
    async fn modify_web_application_target(
        &self,
        _: &str,
        _: &str,
        _: ModifyWebApplicationTargetInput,
    ) -> Result<WebApplicationTarget, GatewayError> {
        specialized_targets_not_implemented()
    }
    /// Delete a web application target.
    async fn delete_web_application_target(
        &self,
        _: &str,
        _: &str,
        _: bool,
    ) -> Result<(), GatewayError> {
        specialized_targets_not_implemented()
    }
}

fn specialized_targets_not_implemented<T>() -> Result<T, GatewayError> {
    Err(GatewayError::NotImplemented(
        "specialized target resources are not implemented by this adapter".to_string(),
    ))
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
