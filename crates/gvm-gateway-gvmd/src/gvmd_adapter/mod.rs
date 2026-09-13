// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Live gvmd adapter backed by session-keyed GMP clients over Unix sockets.

use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use gvm_client::{GetReportDetailsOpts, GetReportExportOpts, GmpClient};
use gvm_connection::UnixSocketConnection;
use gvm_gateway_domain::{
    Alert, AlertPage, AlertPort, AlertQuery, AssetQuery, AuthPort, CertBundAdvisory,
    CertBundAdvisoryPage, Cpe, CpePage, CreateAlertInput, CreateCredentialInput, CreateFilterInput,
    CreateGroupInput, CreateHostInput, CreateNoteInput, CreateOciImageTargetInput,
    CreateOverrideInput, CreatePermissionInput, CreatePortListInput, CreateRoleInput,
    CreateScanConfigInput, CreateScheduleInput, CreateTagInput, CreateTargetInput, CreateTaskInput,
    CreateTaskTarget, CreateUserInput, CreateWebApplicationTargetInput, Credential, CredentialPage,
    CredentialPort, CredentialQuery, CredentialStore, Cve, CvePage, DfnCertAdvisory,
    DfnCertAdvisoryPage, FeedList, FeedPort, FeedQuery, Filter, FilterPage, GatewayError,
    GenericAsset, GenericAssetPage, GenericConfig, GenericConfigPage, GenericConfigQuery,
    GetReportOpts, Group, GroupPage, Host, HostPage, IdentityPort, IdentityQuery, ModifyAlertInput,
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
    ScanConfigPage, ScanConfigPort, ScanConfigPreference, ScanConfigPreferenceNvt,
    ScanConfigPreferenceQuery, ScanConfigQuery, ScanResult, Scanner, ScannerPage, ScannerPort,
    ScannerQuery, Schedule, SchedulePage, SchedulePort, ScheduleQuery, SessionTokenDigest,
    SetScanConfigFamilySelectionInput, SpecializedTargetQuery, SupportingResourcePort,
    SupportingResourceQuery, SystemPort, Tag, TagPage, Target, TargetPage, TargetPort, TargetQuery,
    Task, TaskAction, TaskPage, TaskPort, TaskQuery, Ticket, TicketPage, Timezone,
    TlsCertificateAsset, TlsCertificateAssetPage, TlsCertificatePage, User, UserPage, UserSetting,
    UserSettingList, UserSettingQuery, VulnerabilityPage, WebApplicationTarget,
    WebApplicationTargetPage,
};
use gvm_gmp::{
    commands::{
        alerts::{
            create_alert, delete_alert, get_alert, get_alerts, modify_alert, AlertData, AlertOpts,
            GetAlertsOpts,
        },
        assets::{
            delete_asset, get_assets, modify_asset, DeleteAssetOpts, GetAssetsOpts, ModifyAssetOpts,
        },
        configs::{
            clone_config, delete_config, get_config, get_configs,
            modify_config as modify_config_generic, CloneConfigOpts, ConfigUsageType,
            DeleteConfigOpts, GetConfigOpts, GetConfigsOpts, ModifyConfigOpts,
        },
        credentials::{
            create_credential, create_credential_store_credential, delete_credential,
            get_credential, get_credentials, modify_credential, modify_credential_store,
            modify_credential_store_credential, CredentialOpts, CredentialStoreCredentialOpts,
            CredentialStorePreference, GetCredentialsOpts, ModifyCredentialOpts,
            ModifyCredentialStoreCredentialOpts, ModifyCredentialStoreOpts,
        },
        feed::{get_feed, get_feeds},
        filters::{
            clone_filter, create_filter, delete_filter, get_filter, get_filters, modify_filter,
            GetFiltersOpts,
        },
        groups::{
            create_group, delete_group, get_group, get_groups, modify_group, GetGroupsOpts,
            GroupOpts,
        },
        hosts::{create_host, delete_host, get_host, get_hosts, modify_host, GetHostsOpts},
        notes::{create_note, delete_note, get_notes, modify_note, GetNotesOpts},
        nvts::{get_nvt, get_nvt_families, get_nvts, get_scan_config_nvts, GetNvtsOpts},
        oci_image_targets::{
            clone_oci_image_target, create_oci_image_target, delete_oci_image_target,
            get_oci_image_target, get_oci_image_targets, modify_oci_image_target,
            CreateOciImageTargetOpts, GetOciImageTargetsOpts, ModifyOciImageTargetOpts,
        },
        operating_systems::{
            delete_operating_system, get_operating_system, get_operating_systems,
            modify_operating_system, GetOperatingSystemsOpts,
        },
        overrides::{
            create_override, delete_override, get_overrides, modify_override, GetOverridesOpts,
        },
        permissions::{
            create_permission, delete_permission, get_permission, get_permissions,
            modify_permission, GetPermissionsOpts, PermissionOpts,
        },
        port_lists::{
            create_port_list, delete_port_list, get_port_list, get_port_lists, modify_port_list,
            GetPortListsOpts, ModifyPortListOpts, PortListOpts,
        },
        report_formats::{get_report_format, get_report_formats, GetReportFormatsOpts},
        reports::{delete_report, get_reports, GetReportsOpts},
        results::{get_result, get_results, GetResultsOpts},
        roles::{
            create_role, delete_role, get_role, get_roles, modify_role, GetRolesOpts, RoleOpts,
        },
        scan_configs::{
            create_policy, create_scan_config, delete_policy as delete_policy_cmd,
            delete_scan_config, get_policies, get_scan_config, get_scan_config_preference,
            get_scan_config_preferences, get_scan_configs, modify_scan_config_set_family_selection,
            modify_scan_config_set_nvt_preference, modify_scan_config_set_nvt_selection,
            modify_scan_config_set_scanner_preference, ConfigOpts, GetScanConfigPreferencesOpts,
            GetScanConfigsOpts, NvtFamilySelection,
        },
        scanners::{get_scanner, get_scanners, GetScannersOpts},
        schedules::{
            create_schedule, delete_schedule, get_schedule, get_schedules, modify_schedule,
            GetSchedulesOpts, ScheduleOpts,
        },
        secinfo::GetSecInfoOpts,
        system::{get_timezones, get_vulns, FilteredGetOpts},
        tags::{clone_tag, create_tag, delete_tag, get_tag, get_tags, modify_tag, GetTagsOpts},
        targets::{
            clone_target, create_target, delete_target, get_target, get_targets, modify_target,
            CreateTargetOpts, GetTargetsOpts, ModifyTargetOpts,
        },
        tasks::{
            clone_task, create_agent_group_task, create_audit, create_import_task,
            create_oci_image_target_task, create_task, create_web_application_task,
            delete_audit as delete_audit_cmd, delete_task as delete_task_cmd, get_audits,
            get_task as get_task_cmd, get_tasks, modify_audit as modify_audit_cmd,
            modify_task as modify_task_cmd, resume_audit as resume_audit_cmd,
            resume_task as resume_task_cmd, start_audit as start_audit_cmd,
            start_task as start_task_cmd, stop_audit as stop_audit_cmd, stop_task as stop_task_cmd,
            CreateAgentGroupTaskOpts, CreateOciImageTargetTaskOpts, CreateTaskOpts,
            CreateWebApplicationTaskOpts, GetTasksOpts, ModifyTaskOpts,
        },
        tickets::{get_ticket, get_tickets, GetTicketsOpts},
        tls_certificates::{get_tls_certificate, get_tls_certificates, GetTlsCertificatesOpts},
        user_settings::{
            get_user_setting, get_user_settings, modify_user_setting, GetUserSettingsOpts,
            ModifyUserSettingOpts,
        },
        users::{
            create_user, delete_user, get_user, get_users, modify_user, GetUsersOpts,
            ModifyUserOpts, UserHostAccess, UserOpts,
        },
        web_application_targets::{
            clone_web_application_target, create_web_application_target,
            delete_web_application_target, get_web_application_target, get_web_application_targets,
            modify_web_application_target, CreateWebApplicationTargetOpts,
            GetWebApplicationTargetsOpts, ModifyWebApplicationTargetOpts,
        },
    },
    responses::{
        ActionResponse, CreateAlertResponse, CreateConfigResponse, CreateCredentialResponse,
        CreateFilterResponse, CreateGroupResponse, CreateHostResponse, CreateNoteResponse,
        CreateOciImageTargetResponse, CreateOverrideResponse, CreatePermissionResponse,
        CreatePortListResponse, CreateRoleResponse, CreateScanConfigResponse,
        CreateScheduleResponse, CreateTagResponse, CreateTargetResponse, CreateTaskResponse,
        CreateUserResponse, CreateWebApplicationTargetResponse, GetAlertsResponse,
        GetAssetsResponse, GetConfigsResponse, GetCredentialsResponse, GetFeedsResponse,
        GetFiltersResponse, GetGroupsResponse, GetHostsResponse, GetNotesResponse,
        GetNvtFamiliesResponse, GetNvtsResponse, GetOciImageTargetsResponse,
        GetOperatingSystemAssetsResponse, GetOverridesResponse, GetPermissionsResponse,
        GetPortListsResponse, GetReportApplicationsResponse, GetReportCvesResponse,
        GetReportFormatsResponse, GetReportHostsResponse, GetReportOperatingSystemsResponse,
        GetReportPortsResponse, GetReportsResponse, GetResultsResponse, GetRolesResponse,
        GetScanConfigPreferencesResponse, GetScanConfigsResponse, GetScannersResponse,
        GetSchedulesResponse, GetTagsResponse, GetTargetsResponse, GetTasksResponse,
        GetTicketsResponse, GetTimezonesResponse, GetTlsCertificatesResponse,
        GetUserSettingsResponse, GetUsersResponse, GetVersionResponse, GetVulnerabilitiesResponse,
        GetWebApplicationTargetsResponse, ModifyUserSettingResponse, ResumeTaskResponse,
        StartTaskResponse, User as GmpUser,
    },
    CollectionUpdate, CredentialStoreCredentialType, EntityId, Pagination as GmpPagination,
    ScalarUpdate, TargetHost, TargetHosts, TargetPortRange, TargetPortSelection,
};
use gvm_protocol::{Request, Response};
use tracing::{field, info_span, Instrument};

mod filters;
mod ports;
mod session;
mod supporting_inputs;

#[cfg(test)]
mod filters_test;
#[cfg(test)]
#[path = "mod_test.rs"]
mod mod_test;

use crate::conversions::{
    alert_from_gmp, cert_bund_advisory_from_gmp, cpe_from_gmp, credential_from_gmp, cve_from_gmp,
    dfn_cert_advisory_from_gmp, feed_from_gmp, filter_from_gmp, generic_asset_from_gmp,
    generic_config_from_gmp, group_from_gmp, host_from_gmp, map_gvm_error, map_parse_error,
    note_from_gmp, nvt_family_from_gmp, nvt_from_gmp, oci_image_target_from_gmp,
    operating_system_from_gmp, override_from_gmp, parse_alert_condition, parse_alert_event,
    parse_alert_method, parse_alive_test, parse_asset_type, parse_config_usage_type,
    parse_credential_type, parse_entity_id, parse_hosts_ordering, parse_permission_subject_type,
    parse_snmp_auth_algorithm, parse_snmp_privacy_algorithm, parse_user_auth_type,
    permission_from_gmp, port_list_from_gmp, report_application_from_gmp,
    report_closed_cve_from_gmp, report_cve_from_gmp, report_error_from_gmp, report_format_from_gmp,
    report_from_gmp, report_host_from_gmp, report_operating_system_from_gmp, report_port_from_gmp,
    result_from_gmp, result_from_report_vulnerability, role_from_gmp, scan_config_from_gmp,
    scanner_from_gmp, schedule_from_gmp, tag_from_gmp, target_from_gmp, task_from_gmp,
    ticket_from_gmp, timezone_from_gmp, tls_certificate_asset_from_gmp,
    tls_certificate_from_report_tls_certificate, user_from_gmp, user_setting_from_gmp,
    vulnerability_from_gmp, web_application_target_from_gmp,
};
use filters::{
    backend_ignored_pagination, composed_filter, gvmd_total, needs_client_side_pagination_fallback,
    paged_pagination, paged_slice, paginated_filter,
};
use session::{
    connect_authenticated_client, CredentialStoreCapability, SessionClient, SharedClient,
};
use supporting_inputs::{
    filter_opts_from_create_input, filter_opts_from_modify_input, host_opts_from_create_input,
    host_opts_from_modify_input, note_opts_from_create_input, note_opts_from_modify_input,
    override_opts_from_create_input, override_opts_from_modify_input, tag_opts_from_create_input,
    tag_opts_from_modify_input,
};

/// gvmd adapter backed by session-keyed GMP clients.
#[derive(Clone)]
pub struct GvmdAdapter {
    socket_path: PathBuf,
    sessions: Arc<Mutex<HashMap<SessionTokenDigest, SharedClient>>>,
}

impl fmt::Debug for GvmdAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let session_count = self.sessions.lock().map(|guard| guard.len()).ok();
        formatter
            .debug_struct("GvmdAdapter")
            .field("socket_path", &self.socket_path)
            .field("session_count", &session_count)
            .finish()
    }
}

impl GvmdAdapter {
    /// Create a Unix-socket adapter.
    pub fn unix_socket(path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Probe the backend GMP version without creating a session-bound client.
    pub async fn probe_version(&self) -> Result<String, GatewayError> {
        let span = info_span!(
            "gvmd.probe_version",
            otel_name = "gvmd.probe_version",
            gvmd_endpoint = %self.socket_path.display()
        );

        async move {
            let connection = UnixSocketConnection::with_path(&self.socket_path);
            let mut client = GmpClient::connect(connection)
                .await
                .map_err(map_gvm_error)?;
            let negotiated = client.version().to_string();
            let response = client
                .call(gvm_gmp::commands::version::get_version())
                .await
                .map_err(map_gvm_error)?;
            let parsed = GetVersionResponse::from_response(&response).map_err(map_parse_error)?;

            if parsed.version.trim().is_empty() {
                Ok(negotiated)
            } else {
                Ok(parsed.version)
            }
        }
        .instrument(span)
        .await
    }

    /// Open and authenticate a session-bound GMP connection.
    pub async fn connect_session(
        &self,
        session_token: &str,
        username: &str,
        password: &str,
    ) -> Result<String, GatewayError> {
        let span = info_span!(
            "gvmd.session.connect",
            otel_name = "gvmd.session.connect",
            gvmd_username = %username,
            session_id = %safe_session_id(session_token),
            gvmd_endpoint = %self.socket_path.display()
        );

        async move {
            let mut client =
                connect_authenticated_client(&self.socket_path, username, password).await?;
            let negotiated = client.version().to_string();
            let credential_store_capability =
                match ports::credentials::probe_credential_store_capability(&mut client).await {
                    Ok(outcome) => {
                        if outcome.requires_reconnect {
                            client =
                                connect_authenticated_client(&self.socket_path, username, password)
                                    .await?;
                        }
                        outcome.capability
                    }
                    Err(error) => {
                        client =
                            connect_authenticated_client(&self.socket_path, username, password)
                                .await?;
                        tracing::debug!(
                            session_id = %safe_session_id(session_token),
                            gvmd_username = %username,
                            ?error,
                            "credential-store capability probe deferred after reconnect"
                        );
                        CredentialStoreCapability::Unknown
                    }
                };

            self.sessions
                .lock()
                .map_err(|_| {
                    GatewayError::BackendUnavailable("session store unavailable".to_string())
                })?
                .insert(
                    SessionTokenDigest::from_token(session_token),
                    Arc::new(SessionClient::new(client, credential_store_capability)),
                );

            Ok(negotiated)
        }
        .instrument(span)
        .await
    }

    fn session_client(&self, session_token: &str) -> Result<SharedClient, GatewayError> {
        self.sessions
            .lock()
            .map_err(|_| GatewayError::BackendUnavailable("session store unavailable".to_string()))?
            .get(&SessionTokenDigest::from_token(session_token))
            .cloned()
            .ok_or_else(|| GatewayError::SessionInvalidated("missing gvmd session".to_string()))
    }

    async fn call_with_session<R: Request>(
        &self,
        session_token: &str,
        operation: &'static str,
        request: R,
    ) -> Result<Response, GatewayError> {
        let client = self.session_client(session_token)?;
        let span = info_span!(
            "gvmd.request",
            otel_name = "gvmd.request",
            session_id = %safe_session_id(session_token),
            gvmd_operation = operation,
            gvmd_endpoint = %self.socket_path.display(),
            gvmd_status = field::Empty,
        );

        async move {
            let response = client
                .lock()
                .await?
                .call(request)
                .await
                .map_err(map_gvm_error)?;
            tracing::Span::current().record("gvmd_status", field::display("ok"));
            Ok(response)
        }
        .instrument(span)
        .await
    }

    async fn get_gmp_user(&self, session_token: &str, id: &str) -> Result<GmpUser, GatewayError> {
        let response = self
            .call_with_session(session_token, "users.get", get_user(&parse_entity_id(id)?))
            .await?;
        let parsed = GetUsersResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("user {id} not found")))
    }

    async fn saved_filter_term(
        &self,
        session_token: &str,
        filter_id: Option<&EntityId>,
    ) -> Result<Option<String>, GatewayError> {
        let Some(filter_id) = filter_id else {
            return Ok(None);
        };

        let response = self
            .call_with_session(session_token, "filters.get", get_filter(filter_id))
            .await?;
        let parsed = GetFiltersResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("filter {filter_id} not found")))
            .map(|filter| filter.term)
    }

    async fn paginated_filter_resolving_filter_id(
        &self,
        session_token: &str,
        prefix: Option<&str>,
        filter_string: Option<&str>,
        filter_id: Option<&EntityId>,
        page: u32,
        per_page: u32,
        reserved_terms: &[&str],
    ) -> Result<Option<String>, GatewayError> {
        let saved_filter = self.saved_filter_term(session_token, filter_id).await?;
        composed_filter(
            prefix,
            saved_filter.as_deref(),
            filter_string,
            Some(GmpPagination::new(page as usize, per_page as usize)),
            reserved_terms,
        )
    }

    async fn filter_resolving_filter_id(
        &self,
        session_token: &str,
        prefix: Option<&str>,
        filter_string: Option<&str>,
        filter_id: Option<&EntityId>,
        reserved_terms: &[&str],
    ) -> Result<Option<String>, GatewayError> {
        let saved_filter = self.saved_filter_term(session_token, filter_id).await?;
        composed_filter(
            prefix,
            saved_filter.as_deref(),
            filter_string,
            None,
            reserved_terms,
        )
    }
}

fn safe_session_id(token: &str) -> String {
    SessionTokenDigest::from_token(token).safe_id()
}
