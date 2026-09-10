// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Static (stub) adapter that reports system readiness but rejects all
//! operational queries. Used as a fallback when gvmd is unavailable.

use async_trait::async_trait;
use gvm_gateway_domain::{
    Agent, AgentGroup, AgentGroupPage, AgentGroupQuery, AgentInstallerInstruction,
    AgentInstallerInstructionQuery, AgentPage, AgentPort, AgentQuery, AgentSupportBundle,
    AgentSupportBundleQuery, Alert, AlertPage, AlertPort, AlertQuery, AssetQuery, AuthPort,
    CertBundAdvisory, CertBundAdvisoryPage, Cpe, CpePage, CreateAgentGroupInput, CreateAlertInput,
    CreateCredentialInput, CreateFilterInput, CreateGroupInput, CreateHostInput, CreateNoteInput,
    CreateOciImageTargetInput, CreateOverrideInput, CreatePermissionInput, CreatePortListInput,
    CreateRoleInput, CreateScanConfigInput, CreateScheduleInput, CreateTagInput, CreateTargetInput,
    CreateTaskInput, CreateUserInput, CreateWebApplicationTargetInput, Credential, CredentialPage,
    CredentialPort, CredentialQuery, CredentialStore, Cve, CvePage, DfnCertAdvisory,
    DfnCertAdvisoryPage, FeedList, FeedPort, FeedQuery, Filter, FilterPage, GatewayError,
    GenericAsset, GenericAssetPage, GenericConfig, GenericConfigPage, GenericConfigQuery,
    GetReportOpts, Group, GroupPage, Host, HostPage, IdentityPort, IdentityQuery,
    ModifyAgentControlScanConfigInput, ModifyAgentGroupInput, ModifyAgentInput, ModifyAlertInput,
    ModifyAssetInput, ModifyCredentialInput, ModifyCredentialStoreInput, ModifyFilterInput,
    ModifyGroupInput, ModifyHostInput, ModifyNoteInput, ModifyOciImageTargetInput,
    ModifyOperatingSystemInput, ModifyOverrideInput, ModifyPermissionInput, ModifyPortListInput,
    ModifyRoleInput, ModifyScanConfigInput, ModifyScheduleInput, ModifyTagInput, ModifyTargetInput,
    ModifyTaskInput, ModifyUserInput, ModifyUserSettingInput, ModifyWebApplicationTargetInput,
    Note, NotePage, Nvt, NvtFamilyPage, NvtPage, NvtQuery, OciImageTarget, OciImageTargetPage,
    OperatingSystem, OperatingSystemPage, Override, OverridePage, Permission, PermissionPage,
    PortList, PortListPage, PortListPort, PortListQuery, ReadinessStatus, Report,
    ReportApplicationPage, ReportClosedCvePage, ReportCvePage, ReportErrorPage, ReportExport,
    ReportExportRequest, ReportFormat, ReportFormatPage, ReportHostPage, ReportOperatingSystemPage,
    ReportPage, ReportPort, ReportPortPage, ReportQuery, ReportVulnerabilityPage, ResultPage,
    ResultPort, ResultQuery, Role, RolePage, ScanConfig, ScanConfigNvtPage, ScanConfigNvtQuery,
    ScanConfigPage, ScanConfigPort, ScanConfigPreference, ScanConfigPreferenceQuery,
    ScanConfigQuery, ScanResult, Scanner, ScannerPage, ScannerPort, ScannerQuery, Schedule,
    SchedulePage, SchedulePort, ScheduleQuery, SetScanConfigFamilySelectionInput,
    SpecializedTargetQuery, SupportingResourcePort, SupportingResourceQuery, SystemPort, Tag,
    TagPage, Target, TargetPage, TargetPort, TargetQuery, Task, TaskAction, TaskPage, TaskPort,
    TaskQuery, Ticket, TicketPage, Timezone, TlsCertificateAsset, TlsCertificateAssetPage,
    TlsCertificatePage, User, UserPage, UserSetting, UserSettingList, UserSettingQuery,
    VulnerabilityPage, WebApplicationTarget, WebApplicationTargetPage,
};

/// Static adapter for system readiness and version information.
#[derive(Clone, Debug)]
pub struct StaticGvmdAdapter {
    ready: bool,
    reason: Option<String>,
    gmp_version: String,
}

impl StaticGvmdAdapter {
    /// Creates a ready adapter with the provided GMP version.
    pub fn ready(gmp_version: impl Into<String>) -> Self {
        Self {
            ready: true,
            reason: None,
            gmp_version: gmp_version.into(),
        }
    }

    /// Creates an unready adapter with a reason and GMP version.
    pub fn not_ready(reason: impl Into<String>, gmp_version: impl Into<String>) -> Self {
        Self {
            ready: false,
            reason: Some(reason.into()),
            gmp_version: gmp_version.into(),
        }
    }
}

#[async_trait]
impl SystemPort for StaticGvmdAdapter {
    async fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
        if self.ready {
            Ok(ReadinessStatus {
                status: "ready",
                reason: None,
            })
        } else {
            Ok(ReadinessStatus {
                status: "notReady",
                reason: self.reason.clone(),
            })
        }
    }

    async fn gmp_version(&self) -> Result<String, GatewayError> {
        if self.ready {
            Ok(self.gmp_version.clone())
        } else {
            Err(GatewayError::BackendUnavailable(
                self.reason
                    .clone()
                    .unwrap_or_else(|| "gvmd unavailable".to_string()),
            ))
        }
    }

    async fn list_timezones(&self, _: &str) -> Result<Vec<Timezone>, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support timezones".to_string(),
        ))
    }
}

macro_rules! unsupported {
    ($message:literal) => {
        Err(GatewayError::BackendUnavailable($message.to_string()))
    };
}

#[async_trait]
impl AlertPort for StaticGvmdAdapter {
    async fn list_alerts(&self, _: &str, _: &AlertQuery) -> Result<AlertPage, GatewayError> {
        unsupported!("static adapter does not support alerts")
    }
    async fn create_alert(&self, _: &str, _: CreateAlertInput) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support alerts")
    }
    async fn get_alert(&self, _: &str, _: &str) -> Result<Alert, GatewayError> {
        unsupported!("static adapter does not support alerts")
    }
    async fn modify_alert(
        &self,
        _: &str,
        _: &str,
        _: ModifyAlertInput,
    ) -> Result<Alert, GatewayError> {
        unsupported!("static adapter does not support alerts")
    }
    async fn delete_alert(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support alerts")
    }
}

#[async_trait]
impl SchedulePort for StaticGvmdAdapter {
    async fn list_schedules(
        &self,
        _: &str,
        _: &ScheduleQuery,
    ) -> Result<SchedulePage, GatewayError> {
        unsupported!("static adapter does not support schedules")
    }
    async fn create_schedule(
        &self,
        _: &str,
        _: CreateScheduleInput,
    ) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support schedules")
    }
    async fn get_schedule(&self, _: &str, _: &str) -> Result<Schedule, GatewayError> {
        unsupported!("static adapter does not support schedules")
    }
    async fn modify_schedule(
        &self,
        _: &str,
        _: &str,
        _: ModifyScheduleInput,
    ) -> Result<Schedule, GatewayError> {
        unsupported!("static adapter does not support schedules")
    }
    async fn delete_schedule(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support schedules")
    }
}

#[async_trait]
impl CredentialPort for StaticGvmdAdapter {
    async fn list_credential_stores(&self, _: &str) -> Result<Vec<CredentialStore>, GatewayError> {
        Ok(vec![CredentialStore {
            id: Some("default".to_string()),
            name: "Default".to_string(),
            provider: Some("gvmd".to_string()),
            default: Some(true),
            writable: Some(true),
        }])
    }

    async fn get_credential_store(
        &self,
        _: &str,
        _: &str,
    ) -> Result<CredentialStore, GatewayError> {
        unsupported!("static adapter does not support credential stores")
    }

    async fn modify_credential_store(
        &self,
        _: &str,
        _: &str,
        _: ModifyCredentialStoreInput,
    ) -> Result<CredentialStore, GatewayError> {
        unsupported!("static adapter does not support credential stores")
    }

    async fn verify_credential_store(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support credential stores")
    }

    async fn list_credentials(
        &self,
        _: &str,
        _: &CredentialQuery,
    ) -> Result<CredentialPage, GatewayError> {
        unsupported!("static adapter does not support credentials")
    }
    async fn create_credential(
        &self,
        _: &str,
        _: CreateCredentialInput,
    ) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support credentials")
    }
    async fn get_credential(&self, _: &str, _: &str) -> Result<Credential, GatewayError> {
        unsupported!("static adapter does not support credentials")
    }
    async fn modify_credential(
        &self,
        _: &str,
        _: &str,
        _: ModifyCredentialInput,
    ) -> Result<Credential, GatewayError> {
        unsupported!("static adapter does not support credentials")
    }
    async fn delete_credential(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support credentials")
    }
}

#[async_trait]
impl PortListPort for StaticGvmdAdapter {
    async fn list_port_lists(
        &self,
        _: &str,
        _: &PortListQuery,
    ) -> Result<PortListPage, GatewayError> {
        unsupported!("static adapter does not support port lists")
    }
    async fn create_port_list(
        &self,
        _: &str,
        _: CreatePortListInput,
    ) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support port lists")
    }
    async fn get_port_list(&self, _: &str, _: &str) -> Result<PortList, GatewayError> {
        unsupported!("static adapter does not support port lists")
    }
    async fn modify_port_list(
        &self,
        _: &str,
        _: &str,
        _: ModifyPortListInput,
    ) -> Result<PortList, GatewayError> {
        unsupported!("static adapter does not support port lists")
    }
    async fn delete_port_list(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support port lists")
    }
}

#[async_trait]
impl FeedPort for StaticGvmdAdapter {
    async fn list_feeds(&self, _: &str, _: &FeedQuery) -> Result<FeedList, GatewayError> {
        unsupported!("static adapter does not support feeds")
    }
}

#[async_trait]
impl IdentityPort for StaticGvmdAdapter {
    async fn list_users(&self, _: &str, _: &IdentityQuery) -> Result<UserPage, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn create_user(&self, _: &str, _: CreateUserInput) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn get_user(&self, _: &str, _: &str) -> Result<User, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn modify_user(
        &self,
        _: &str,
        _: &str,
        _: ModifyUserInput,
    ) -> Result<User, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn delete_user(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn list_groups(&self, _: &str, _: &IdentityQuery) -> Result<GroupPage, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn create_group(&self, _: &str, _: CreateGroupInput) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn get_group(&self, _: &str, _: &str) -> Result<Group, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn modify_group(
        &self,
        _: &str,
        _: &str,
        _: ModifyGroupInput,
    ) -> Result<Group, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn delete_group(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn list_roles(&self, _: &str, _: &IdentityQuery) -> Result<RolePage, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn create_role(&self, _: &str, _: CreateRoleInput) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn get_role(&self, _: &str, _: &str) -> Result<Role, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn modify_role(
        &self,
        _: &str,
        _: &str,
        _: ModifyRoleInput,
    ) -> Result<Role, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn delete_role(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn list_permissions(
        &self,
        _: &str,
        _: &IdentityQuery,
    ) -> Result<PermissionPage, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn create_permission(
        &self,
        _: &str,
        _: CreatePermissionInput,
    ) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn get_permission(&self, _: &str, _: &str) -> Result<Permission, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn modify_permission(
        &self,
        _: &str,
        _: &str,
        _: ModifyPermissionInput,
    ) -> Result<Permission, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn delete_permission(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn list_user_settings(
        &self,
        _: &str,
        _: &UserSettingQuery,
    ) -> Result<UserSettingList, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn get_user_setting(&self, _: &str, _: &str) -> Result<UserSetting, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }

    async fn modify_user_setting(
        &self,
        _: &str,
        _: &str,
        _: ModifyUserSettingInput,
    ) -> Result<UserSetting, GatewayError> {
        unsupported!("static adapter does not support identity resources")
    }
}

#[async_trait]
impl TargetPort for StaticGvmdAdapter {
    async fn list_targets(&self, _: &str, _: &TargetQuery) -> Result<TargetPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn create_target(&self, _: &str, _: CreateTargetInput) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn clone_target(&self, _: &str, _: &str) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn get_target(&self, _: &str, _: &str) -> Result<Target, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn modify_target(
        &self,
        _: &str,
        _: &str,
        _: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn delete_target(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn list_oci_image_targets(
        &self,
        _: &str,
        _: &SpecializedTargetQuery,
    ) -> Result<OciImageTargetPage, GatewayError> {
        unsupported!("static adapter does not support OCI image targets")
    }
    async fn create_oci_image_target(
        &self,
        _: &str,
        _: CreateOciImageTargetInput,
    ) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support OCI image targets")
    }
    async fn clone_oci_image_target(&self, _: &str, _: &str) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support OCI image targets")
    }
    async fn get_oci_image_target(&self, _: &str, _: &str) -> Result<OciImageTarget, GatewayError> {
        unsupported!("static adapter does not support OCI image targets")
    }
    async fn modify_oci_image_target(
        &self,
        _: &str,
        _: &str,
        _: ModifyOciImageTargetInput,
    ) -> Result<OciImageTarget, GatewayError> {
        unsupported!("static adapter does not support OCI image targets")
    }
    async fn delete_oci_image_target(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support OCI image targets")
    }

    async fn list_web_application_targets(
        &self,
        _: &str,
        _: &SpecializedTargetQuery,
    ) -> Result<WebApplicationTargetPage, GatewayError> {
        unsupported!("static adapter does not support web application targets")
    }
    async fn create_web_application_target(
        &self,
        _: &str,
        _: CreateWebApplicationTargetInput,
    ) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support web application targets")
    }
    async fn clone_web_application_target(&self, _: &str, _: &str) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support web application targets")
    }
    async fn get_web_application_target(
        &self,
        _: &str,
        _: &str,
    ) -> Result<WebApplicationTarget, GatewayError> {
        unsupported!("static adapter does not support web application targets")
    }
    async fn modify_web_application_target(
        &self,
        _: &str,
        _: &str,
        _: ModifyWebApplicationTargetInput,
    ) -> Result<WebApplicationTarget, GatewayError> {
        unsupported!("static adapter does not support web application targets")
    }
    async fn delete_web_application_target(
        &self,
        _: &str,
        _: &str,
        _: bool,
    ) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support web application targets")
    }
}

#[async_trait]
impl TaskPort for StaticGvmdAdapter {
    async fn list_tasks(&self, _: &str, _: &TaskQuery) -> Result<TaskPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn create_task(&self, _: &str, _: CreateTaskInput) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn clone_task(&self, _: &str, _: &str) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn get_task(&self, _: &str, _: &str) -> Result<Task, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn modify_task(
        &self,
        _: &str,
        _: &str,
        _: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn delete_task(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn start_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn stop_task(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn resume_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn list_audits(&self, _: &str, _: &TaskQuery) -> Result<TaskPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support audits".to_string(),
        ))
    }

    async fn create_audit(&self, _: &str, _: CreateTaskInput) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support audits".to_string(),
        ))
    }

    async fn modify_audit(
        &self,
        _: &str,
        _: &str,
        _: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support audits".to_string(),
        ))
    }

    async fn delete_audit(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support audits".to_string(),
        ))
    }

    async fn get_audit(&self, _: &str, _: &str) -> Result<Task, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support audits".to_string(),
        ))
    }

    async fn start_audit(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support audits".to_string(),
        ))
    }

    async fn stop_audit(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support audits".to_string(),
        ))
    }

    async fn resume_audit(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support audits".to_string(),
        ))
    }
}

#[async_trait]
impl ReportPort for StaticGvmdAdapter {
    async fn list_reports(&self, _: &str, _: &ReportQuery) -> Result<ReportPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report(
        &self,
        _: &str,
        _: &str,
        _: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn export_report(
        &self,
        _: &str,
        _: &str,
        _: &ReportExportRequest,
    ) -> Result<ReportExport, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn delete_report(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report_results(
        &self,
        _: &str,
        _: &str,
        _: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report_vulnerabilities(
        &self,
        _: &str,
        _: &str,
        _: &ResultQuery,
    ) -> Result<ReportVulnerabilityPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report_hosts(
        &self,
        _: &str,
        _: &str,
        _: &ResultQuery,
    ) -> Result<ReportHostPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report_ports(
        &self,
        _: &str,
        _: &str,
        _: &ResultQuery,
    ) -> Result<ReportPortPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report_applications(
        &self,
        _: &str,
        _: &str,
        _: &ResultQuery,
    ) -> Result<ReportApplicationPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report_operating_systems(
        &self,
        _: &str,
        _: &str,
        _: &ResultQuery,
    ) -> Result<ReportOperatingSystemPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report_cves(
        &self,
        _: &str,
        _: &str,
        _: &ResultQuery,
    ) -> Result<ReportCvePage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report_tls_certificates(
        &self,
        _: &str,
        _: &str,
        _: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report_errors(
        &self,
        _: &str,
        _: &str,
        _: &ResultQuery,
    ) -> Result<ReportErrorPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report_closed_cves(
        &self,
        _: &str,
        _: &str,
        _: &ResultQuery,
    ) -> Result<ReportClosedCvePage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }
}

#[async_trait]
impl ResultPort for StaticGvmdAdapter {
    async fn list_results(&self, _: &str, _: &ResultQuery) -> Result<ResultPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support results".to_string(),
        ))
    }

    async fn get_result(&self, _: &str, _: &str) -> Result<ScanResult, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support results".to_string(),
        ))
    }
}

#[async_trait]
impl ScanConfigPort for StaticGvmdAdapter {
    async fn list_configs(
        &self,
        _: &str,
        _: &GenericConfigQuery,
    ) -> Result<GenericConfigPage, GatewayError> {
        unsupported!("static adapter does not support configs")
    }

    async fn get_config(&self, _: &str, _: &str) -> Result<GenericConfig, GatewayError> {
        unsupported!("static adapter does not support configs")
    }

    async fn delete_config(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support configs")
    }

    async fn clone_config(&self, _: &str, _: &str) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support configs")
    }

    async fn list_scan_configs(
        &self,
        _: &str,
        _: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scan configs".to_string(),
        ))
    }

    async fn create_scan_config(
        &self,
        _: &str,
        _: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scan configs".to_string(),
        ))
    }

    async fn get_scan_config(&self, _: &str, _: &str) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scan configs".to_string(),
        ))
    }

    async fn modify_scan_config(
        &self,
        _: &str,
        _: &str,
        _: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scan configs".to_string(),
        ))
    }

    async fn delete_scan_config(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scan configs".to_string(),
        ))
    }

    async fn list_scan_config_nvts(
        &self,
        _: &str,
        _: &str,
        _: &ScanConfigNvtQuery,
    ) -> Result<ScanConfigNvtPage, GatewayError> {
        unsupported!("static adapter does not support scan config NVTs")
    }

    async fn get_scan_config_nvt(&self, _: &str, _: &str, _: &str) -> Result<Nvt, GatewayError> {
        unsupported!("static adapter does not support scan config NVTs")
    }

    async fn list_scan_config_preferences(
        &self,
        _: &str,
        _: &str,
        _: &ScanConfigPreferenceQuery,
    ) -> Result<Vec<ScanConfigPreference>, GatewayError> {
        unsupported!("static adapter does not support scan config preferences")
    }

    async fn get_scan_config_preference(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &ScanConfigPreferenceQuery,
    ) -> Result<ScanConfigPreference, GatewayError> {
        unsupported!("static adapter does not support scan config preferences")
    }

    async fn set_scan_config_nvt_selection(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Vec<String>,
    ) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support scan config selection")
    }

    async fn set_scan_config_family_selection(
        &self,
        _: &str,
        _: &str,
        _: SetScanConfigFamilySelectionInput,
    ) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support scan config selection")
    }

    async fn set_scan_config_preference(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<String>,
        _: Option<String>,
    ) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support scan config preferences")
    }

    async fn list_policies(
        &self,
        _: &str,
        _: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support policies".to_string(),
        ))
    }

    async fn create_policy(
        &self,
        _: &str,
        _: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support policies".to_string(),
        ))
    }

    async fn modify_policy(
        &self,
        _: &str,
        _: &str,
        _: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support policies".to_string(),
        ))
    }

    async fn delete_policy(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support policies".to_string(),
        ))
    }

    async fn get_policy(&self, _: &str, _: &str) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support policies".to_string(),
        ))
    }
}

#[async_trait]
impl ScannerPort for StaticGvmdAdapter {
    async fn list_scanners(&self, _: &str, _: &ScannerQuery) -> Result<ScannerPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scanners".to_string(),
        ))
    }

    async fn get_scanner(&self, _: &str, _: &str) -> Result<Scanner, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scanners".to_string(),
        ))
    }
}

#[async_trait]
impl AgentPort for StaticGvmdAdapter {
    async fn list_agents(&self, _: &str, _: &AgentQuery) -> Result<AgentPage, GatewayError> {
        unsupported!("static adapter does not support agents")
    }

    async fn get_agent(&self, _: &str, _: &str) -> Result<Agent, GatewayError> {
        unsupported!("static adapter does not support agents")
    }

    async fn modify_agent(
        &self,
        _: &str,
        _: &str,
        _: ModifyAgentInput,
    ) -> Result<Agent, GatewayError> {
        unsupported!("static adapter does not support agents")
    }

    async fn delete_agent(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support agents")
    }

    async fn sync_agents(&self, _: &str) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support agents")
    }

    async fn get_agent_support_bundle(
        &self,
        _: &str,
        _: &str,
        _: &AgentSupportBundleQuery,
    ) -> Result<AgentSupportBundle, GatewayError> {
        unsupported!("static adapter does not support agents")
    }

    async fn modify_agent_control_scan_config(
        &self,
        _: &str,
        _: &str,
        _: ModifyAgentControlScanConfigInput,
    ) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support agents")
    }

    async fn get_agent_installer_instruction(
        &self,
        _: &str,
        _: &str,
        _: &AgentInstallerInstructionQuery,
    ) -> Result<AgentInstallerInstruction, GatewayError> {
        unsupported!("static adapter does not support agents")
    }

    async fn list_agent_groups(
        &self,
        _: &str,
        _: &AgentGroupQuery,
    ) -> Result<AgentGroupPage, GatewayError> {
        unsupported!("static adapter does not support agent groups")
    }

    async fn create_agent_group(
        &self,
        _: &str,
        _: CreateAgentGroupInput,
    ) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support agent groups")
    }

    async fn get_agent_group(&self, _: &str, _: &str) -> Result<AgentGroup, GatewayError> {
        unsupported!("static adapter does not support agent groups")
    }

    async fn modify_agent_group(
        &self,
        _: &str,
        _: &str,
        _: ModifyAgentGroupInput,
    ) -> Result<AgentGroup, GatewayError> {
        unsupported!("static adapter does not support agent groups")
    }

    async fn delete_agent_group(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support agent groups")
    }

    async fn clone_agent_group(&self, _: &str, _: &str) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support agent groups")
    }
}

#[async_trait]
impl SupportingResourcePort for StaticGvmdAdapter {
    async fn list_assets(&self, _: &str, _: &AssetQuery) -> Result<GenericAssetPage, GatewayError> {
        unsupported!("static adapter does not support assets")
    }

    async fn get_asset(&self, _: &str, _: &str, _: &str) -> Result<GenericAsset, GatewayError> {
        unsupported!("static adapter does not support assets")
    }

    async fn modify_asset(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: ModifyAssetInput,
    ) -> Result<GenericAsset, GatewayError> {
        unsupported!("static adapter does not support assets")
    }

    async fn delete_asset(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support assets")
    }

    async fn list_hosts(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<HostPage, GatewayError> {
        unsupported!("static adapter does not support hosts")
    }

    async fn get_host(&self, _: &str, _: &str) -> Result<Host, GatewayError> {
        unsupported!("static adapter does not support hosts")
    }

    async fn list_operating_systems(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<OperatingSystemPage, GatewayError> {
        unsupported!("static adapter does not support operating systems")
    }

    async fn get_operating_system(
        &self,
        _: &str,
        _: &str,
    ) -> Result<OperatingSystem, GatewayError> {
        unsupported!("static adapter does not support operating systems")
    }

    async fn list_tls_certificates(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<TlsCertificateAssetPage, GatewayError> {
        unsupported!("static adapter does not support tls certificates")
    }

    async fn get_tls_certificate(
        &self,
        _: &str,
        _: &str,
    ) -> Result<TlsCertificateAsset, GatewayError> {
        unsupported!("static adapter does not support tls certificates")
    }

    async fn create_host(&self, _: &str, _: CreateHostInput) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support hosts")
    }

    async fn modify_host(
        &self,
        _: &str,
        _: &str,
        _: ModifyHostInput,
    ) -> Result<Host, GatewayError> {
        unsupported!("static adapter does not support hosts")
    }

    async fn modify_operating_system(
        &self,
        _: &str,
        _: &str,
        _: ModifyOperatingSystemInput,
    ) -> Result<OperatingSystem, GatewayError> {
        unsupported!("static adapter does not support operating systems")
    }

    async fn delete_host(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support hosts")
    }

    async fn delete_operating_system(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support operating systems")
    }

    async fn list_report_formats(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<ReportFormatPage, GatewayError> {
        unsupported!("static adapter does not support report formats")
    }

    async fn get_report_format(&self, _: &str, _: &str) -> Result<ReportFormat, GatewayError> {
        unsupported!("static adapter does not support report formats")
    }

    async fn list_filters(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<FilterPage, GatewayError> {
        unsupported!("static adapter does not support filters")
    }

    async fn get_filter(&self, _: &str, _: &str) -> Result<Filter, GatewayError> {
        unsupported!("static adapter does not support filters")
    }

    async fn create_filter(&self, _: &str, _: CreateFilterInput) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support filters")
    }

    async fn modify_filter(
        &self,
        _: &str,
        _: &str,
        _: ModifyFilterInput,
    ) -> Result<Filter, GatewayError> {
        unsupported!("static adapter does not support filters")
    }

    async fn delete_filter(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support filters")
    }

    async fn clone_filter(&self, _: &str, _: &str) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support filters")
    }

    async fn list_tags(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<TagPage, GatewayError> {
        unsupported!("static adapter does not support tags")
    }

    async fn get_tag(&self, _: &str, _: &str) -> Result<Tag, GatewayError> {
        unsupported!("static adapter does not support tags")
    }

    async fn create_tag(&self, _: &str, _: CreateTagInput) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support tags")
    }

    async fn modify_tag(&self, _: &str, _: &str, _: ModifyTagInput) -> Result<Tag, GatewayError> {
        unsupported!("static adapter does not support tags")
    }

    async fn delete_tag(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support tags")
    }

    async fn clone_tag(&self, _: &str, _: &str) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support tags")
    }

    async fn list_tickets(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<TicketPage, GatewayError> {
        unsupported!("static adapter does not support tickets")
    }

    async fn get_ticket(&self, _: &str, _: &str) -> Result<Ticket, GatewayError> {
        unsupported!("static adapter does not support tickets")
    }

    async fn list_notes(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<NotePage, GatewayError> {
        unsupported!("static adapter does not support notes")
    }

    async fn get_note(&self, _: &str, _: &str) -> Result<Note, GatewayError> {
        unsupported!("static adapter does not support notes")
    }

    async fn create_note(&self, _: &str, _: CreateNoteInput) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support note mutations")
    }

    async fn modify_note(
        &self,
        _: &str,
        _: &str,
        _: ModifyNoteInput,
    ) -> Result<Note, GatewayError> {
        unsupported!("static adapter does not support note mutations")
    }

    async fn delete_note(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support note mutations")
    }

    async fn list_overrides(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<OverridePage, GatewayError> {
        unsupported!("static adapter does not support overrides")
    }

    async fn get_override(&self, _: &str, _: &str) -> Result<Override, GatewayError> {
        unsupported!("static adapter does not support overrides")
    }

    async fn create_override(
        &self,
        _: &str,
        _: CreateOverrideInput,
    ) -> Result<String, GatewayError> {
        unsupported!("static adapter does not support override mutations")
    }

    async fn modify_override(
        &self,
        _: &str,
        _: &str,
        _: ModifyOverrideInput,
    ) -> Result<Override, GatewayError> {
        unsupported!("static adapter does not support override mutations")
    }

    async fn delete_override(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        unsupported!("static adapter does not support override mutations")
    }

    async fn list_nvts(&self, _: &str, _: &NvtQuery) -> Result<NvtPage, GatewayError> {
        unsupported!("static adapter does not support nvts")
    }

    async fn get_nvt(&self, _: &str, _: &str) -> Result<Nvt, GatewayError> {
        unsupported!("static adapter does not support nvts")
    }

    async fn list_nvt_families(
        &self,
        _: &str,
        _: u32,
        _: u32,
    ) -> Result<NvtFamilyPage, GatewayError> {
        unsupported!("static adapter does not support nvt families")
    }

    async fn list_vulnerabilities(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<VulnerabilityPage, GatewayError> {
        unsupported!("static adapter does not support vulnerabilities")
    }

    async fn list_cves(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<CvePage, GatewayError> {
        unsupported!("static adapter does not support cves")
    }

    async fn get_cve(&self, _: &str, _: &str) -> Result<Cve, GatewayError> {
        unsupported!("static adapter does not support cves")
    }

    async fn list_cpes(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<CpePage, GatewayError> {
        unsupported!("static adapter does not support cpes")
    }

    async fn get_cpe(&self, _: &str, _: &str) -> Result<Cpe, GatewayError> {
        unsupported!("static adapter does not support cpes")
    }

    async fn list_cert_bund_advisories(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<CertBundAdvisoryPage, GatewayError> {
        unsupported!("static adapter does not support cert-bund advisories")
    }

    async fn get_cert_bund_advisory(
        &self,
        _: &str,
        _: &str,
    ) -> Result<CertBundAdvisory, GatewayError> {
        unsupported!("static adapter does not support cert-bund advisories")
    }

    async fn list_dfn_cert_advisories(
        &self,
        _: &str,
        _: &SupportingResourceQuery,
    ) -> Result<DfnCertAdvisoryPage, GatewayError> {
        unsupported!("static adapter does not support dfn-cert advisories")
    }

    async fn get_dfn_cert_advisory(
        &self,
        _: &str,
        _: &str,
    ) -> Result<DfnCertAdvisory, GatewayError> {
        unsupported!("static adapter does not support dfn-cert advisories")
    }
}

#[async_trait]
impl AuthPort for StaticGvmdAdapter {
    async fn authenticate_session(
        &self,
        _session_token: &str,
        _username: &str,
        _password: &str,
    ) -> Result<String, GatewayError> {
        if self.ready {
            Ok(self.gmp_version.clone())
        } else {
            Err(GatewayError::BackendUnavailable(
                "static adapter not ready".to_string(),
            ))
        }
    }

    async fn disconnect_session(
        &self,
        _session: &gvm_gateway_domain::SessionTokenDigest,
    ) -> Result<(), GatewayError> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "static_adapter_test.rs"]
mod static_adapter_test;
