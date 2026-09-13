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
use gvm_client::{GetReportDetailsOpts, GetReportExportOpts, GmpClient, GvmError};
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
            AlertData, AlertOpts, CreateAlertRequest, DeleteAlertRequest, GetAlertRequest,
            GetAlertsOpts, GetAlertsRequest, ModifyAlertRequest,
        },
        assets::{
            DeleteAssetOpts, DeleteAssetRequest, GetAssetRequest, GetAssetsOpts, GetAssetsRequest,
            ModifyAssetOpts, ModifyAssetRequest,
        },
        configs::{
            CloneConfigOpts, CloneConfigRequest, ConfigUsageType, DeleteConfigOpts,
            DeleteConfigRequest, GetConfigOpts, GetConfigRequest, GetConfigsOpts,
            GetConfigsRequest, ModifyConfigOpts, ModifyConfigRequest,
        },
        credentials::{
            CreateCredentialRequest, CreateCredentialStoreCredentialRequest, CredentialOpts,
            CredentialStoreCredentialOpts, CredentialStorePreference, DeleteCredentialRequest,
            GetCredentialRequest, GetCredentialStoreRequest, GetCredentialStoresOpts,
            GetCredentialStoresRequest, GetCredentialsOpts, GetCredentialsRequest,
            ModifyCredentialOpts, ModifyCredentialRequest, ModifyCredentialStoreCredentialOpts,
            ModifyCredentialStoreCredentialRequest, ModifyCredentialStoreOpts,
            ModifyCredentialStoreRequest, VerifyCredentialStoreRequest,
        },
        feed::{GetFeedRequest, GetFeedsRequest},
        filters::{
            CloneFilterRequest, CreateFilterRequest, DeleteFilterRequest, GetFilterRequest,
            GetFiltersOpts, GetFiltersRequest, ModifyFilterRequest,
        },
        groups::{
            CreateGroupRequest, DeleteGroupRequest, GetGroupRequest, GetGroupsOpts,
            GetGroupsRequest, GroupOpts, ModifyGroupRequest,
        },
        hosts::{
            CreateHostRequest, DeleteHostRequest, GetHostRequest, GetHostsOpts, GetHostsRequest,
            ModifyHostRequest,
        },
        notes::{
            CreateNoteRequest, DeleteNoteRequest, GetNotesOpts, GetNotesRequest, ModifyNoteRequest,
        },
        nvts::{
            GetNvtFamiliesRequest, GetNvtRequest, GetNvtsOpts, GetNvtsRequest,
            GetScanConfigNvtsRequest,
        },
        oci_image_targets::{
            CloneOciImageTargetRequest, CreateOciImageTargetOpts, CreateOciImageTargetRequest,
            DeleteOciImageTargetRequest, GetOciImageTargetRequest, GetOciImageTargetsOpts,
            GetOciImageTargetsRequest, ModifyOciImageTargetOpts, ModifyOciImageTargetRequest,
        },
        operating_systems::{
            DeleteOperatingSystemAssetRequest, GetOperatingSystemAssetRequest,
            GetOperatingSystemAssetsRequest, GetOperatingSystemsOpts,
            ModifyOperatingSystemAssetRequest,
        },
        overrides::{
            CreateOverrideRequest, DeleteOverrideRequest, GetOverridesOpts, GetOverridesRequest,
            ModifyOverrideRequest,
        },
        permissions::{
            CreatePermissionRequest, DeletePermissionRequest, GetPermissionRequest,
            GetPermissionsOpts, GetPermissionsRequest, ModifyPermissionRequest, PermissionOpts,
        },
        port_lists::{
            CreatePortListRequest, DeletePortListRequest, GetPortListRequest, GetPortListsOpts,
            GetPortListsRequest, ModifyPortListOpts, ModifyPortListRequest, PortListOpts,
        },
        report_formats::{GetReportFormatRequest, GetReportFormatsOpts, GetReportFormatsRequest},
        reports::{
            DeleteReportRequest, GetReportApplicationsRequest, GetReportClosedCvesRequest,
            GetReportCvesRequest, GetReportErrorsRequest,
            GetReportExportRequest as GmpGetReportExportRequest, GetReportHostsRequest,
            GetReportOperatingSystemsRequest, GetReportPortsRequest,
            GetReportTlsCertificatesRequest, GetReportVulnsRequest, GetReportsOpts,
            GetReportsRequest,
        },
        results::{GetResultRequest, GetResultsOpts, GetResultsRequest},
        roles::{
            CreateRoleRequest, DeleteRoleRequest, GetRoleRequest, GetRolesOpts, GetRolesRequest,
            ModifyRoleRequest, RoleOpts,
        },
        scan_configs::{
            ConfigOpts, CreatePolicyRequest, CreateScanConfigRequest, DeletePolicyRequest,
            DeleteScanConfigRequest, GetPoliciesRequest, GetScanConfigPreferenceRequest,
            GetScanConfigPreferencesOpts, GetScanConfigPreferencesRequest, GetScanConfigRequest,
            GetScanConfigsOpts, GetScanConfigsRequest, ModifyScanConfigSetFamilySelectionRequest,
            ModifyScanConfigSetNvtPreferenceRequest, ModifyScanConfigSetNvtSelectionRequest,
            ModifyScanConfigSetScannerPreferenceRequest, NvtFamilySelection,
        },
        scanners::{GetScannerRequest, GetScannersOpts, GetScannersRequest},
        schedules::{
            CreateScheduleRequest, DeleteScheduleRequest, GetScheduleRequest, GetSchedulesOpts,
            GetSchedulesRequest, ModifyScheduleRequest, ScheduleOpts,
        },
        secinfo::{
            GetCertBundAdvisoriesRequest, GetCertBundAdvisoryRequest, GetCpeRequest,
            GetCpesRequest, GetCveRequest, GetCvesRequest, GetDfnCertAdvisoriesRequest,
            GetDfnCertAdvisoryRequest, GetSecInfoOpts,
        },
        system::{FilteredGetOpts, GetTimezonesRequest, GetVulnsRequest},
        tags::{
            CloneTagRequest, CreateTagRequest, DeleteTagRequest, GetTagRequest, GetTagsOpts,
            GetTagsRequest, ModifyTagRequest,
        },
        targets::{
            CloneTargetRequest, CreateTargetOpts, CreateTargetRequest, DeleteTargetRequest,
            GetTargetRequest, GetTargetsOpts, GetTargetsRequest, ModifyTargetOpts,
            ModifyTargetRequest,
        },
        tasks::{
            CloneTaskRequest, CreateAgentGroupTaskOpts, CreateAgentGroupTaskRequest,
            CreateAuditRequest, CreateImportTaskRequest, CreateOciImageTargetTaskOpts,
            CreateOciImageTargetTaskRequest, CreateTaskOpts, CreateTaskRequest,
            CreateWebApplicationTaskOpts, CreateWebApplicationTaskRequest, DeleteAuditRequest,
            DeleteTaskRequest, GetAuditsRequest, GetTaskRequest, GetTasksOpts, GetTasksRequest,
            ModifyAuditRequest, ModifyTaskOpts, ModifyTaskRequest, ResumeAuditRequest,
            ResumeTaskRequest, StartAuditRequest, StartTaskRequest, StopAuditRequest,
            StopTaskRequest,
        },
        tickets::{get_ticket, get_tickets, GetTicketsOpts},
        tls_certificates::{
            GetTlsCertificateRequest, GetTlsCertificatesOpts, GetTlsCertificatesRequest,
        },
        user_settings::{
            GetUserSettingRequest, GetUserSettingsOpts, GetUserSettingsRequest,
            ModifyUserSettingOpts, ModifyUserSettingRequest,
        },
        users::{
            CreateUserRequest, DeleteUserRequest, GetUserRequest, GetUsersOpts, GetUsersRequest,
            ModifyUserOpts, ModifyUserRequest, UserHostAccess, UserOpts,
        },
        web_application_targets::{
            CloneWebApplicationTargetRequest, CreateWebApplicationTargetOpts,
            CreateWebApplicationTargetRequest, DeleteWebApplicationTargetRequest,
            GetWebApplicationTargetRequest, GetWebApplicationTargetsOpts,
            GetWebApplicationTargetsRequest, ModifyWebApplicationTargetOpts,
            ModifyWebApplicationTargetRequest,
        },
    },
    responses::{GetTicketsResponse, User as GmpUser},
    CollectionUpdate, CredentialStoreCredentialType, EntityId, GmpRequest,
    Pagination as GmpPagination, ScalarUpdate, TargetHost, TargetHosts, TargetPortRange,
    TargetPortSelection,
};
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
            let parsed = client
                .execute(gvm_gmp::commands::version::GetVersionRequest::new())
                .await
                .map_err(map_gvm_error)?;

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

    async fn execute_with_session<R: GmpRequest>(
        &self,
        session_token: &str,
        operation: &'static str,
        request: R,
    ) -> Result<R::Response, GatewayError> {
        self.execute_with_session_mapped(session_token, operation, request, map_gvm_error)
            .await
    }

    async fn execute_with_session_mapped<R, F>(
        &self,
        session_token: &str,
        operation: &'static str,
        request: R,
        map_error: F,
    ) -> Result<R::Response, GatewayError>
    where
        R: GmpRequest,
        F: FnOnce(GvmError) -> GatewayError,
    {
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
                .execute(request)
                .await
                .map_err(map_error)?;
            tracing::Span::current().record("gvmd_status", field::display("ok"));
            Ok(response)
        }
        .instrument(span)
        .await
    }

    async fn get_gmp_user(&self, session_token: &str, id: &str) -> Result<GmpUser, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "users.get",
                GetUserRequest::new(parse_entity_id(id)?),
            )
            .await?;
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

        let parsed = self
            .execute_with_session(
                session_token,
                "filters.get",
                GetFilterRequest::new(filter_id.clone()),
            )
            .await?;
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
