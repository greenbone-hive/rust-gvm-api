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
    SessionTokenDigest, SupportingResourcePort, SupportingResourceQuery, SystemPort, Tag, TagPage,
    Target, TargetPage, TargetPort, TargetQuery, Task, TaskAction, TaskPage, TaskPort, TaskQuery,
    Ticket, TicketPage, TlsCertificatePage, User, UserPage, UserSetting, UserSettingList,
    UserSettingQuery,
};
use gvm_gmp::{
    commands::{
        alerts::{
            create_alert, delete_alert, get_alert, get_alerts, modify_alert, AlertData, AlertOpts,
            GetAlertsOpts,
        },
        authentication::authenticate,
        credentials::{
            create_credential, delete_credential, get_credential, get_credentials,
            modify_credential, CredentialOpts, GetCredentialsOpts, ModifyCredentialOpts,
        },
        feed::get_feeds,
        filters::{get_filter, get_filters, GetFiltersOpts},
        groups::{
            create_group, delete_group, get_group, get_groups, modify_group, GetGroupsOpts,
            GroupOpts,
        },
        hosts::{get_host, get_hosts, GetHostsOpts},
        notes::{create_note, delete_note, get_notes, modify_note, GetNotesOpts},
        nvts::{get_nvt, get_nvt_families, get_nvts, GetNvtsOpts},
        overrides::{
            create_override, delete_override, get_overrides, modify_override, GetOverridesOpts,
        },
        permissions::{
            create_permission, delete_permission, get_permission, get_permissions,
            modify_permission, GetPermissionsOpts, PermissionOpts,
        },
        port_lists::{
            create_port_list, delete_port_list, get_port_list, get_port_lists, modify_port_list,
            GetPortListsOpts, PortListOpts,
        },
        report_formats::{get_report_format, get_report_formats, GetReportFormatsOpts},
        reports::{delete_report, get_reports, GetReportsOpts},
        results::{get_result, get_results, GetResultsOpts},
        roles::{
            create_role, delete_role, get_role, get_roles, modify_role, GetRolesOpts, RoleOpts,
        },
        scan_configs::{
            create_scan_config, delete_scan_config, get_scan_config, get_scan_configs,
            modify_scan_config, ConfigOpts, GetScanConfigsOpts,
        },
        scanners::{get_scanner, get_scanners, GetScannersOpts},
        schedules::{
            create_schedule, delete_schedule, get_schedule, get_schedules, modify_schedule,
            GetSchedulesOpts, ScheduleOpts,
        },
        tags::{get_tag, get_tags, GetTagsOpts},
        targets::{
            create_target, delete_target, get_target, get_targets, modify_target, CreateTargetOpts,
            GetTargetsOpts, ModifyTargetOpts,
        },
        tasks::{
            create_task, delete_task as delete_task_cmd, get_task as get_task_cmd, get_tasks,
            modify_task as modify_task_cmd, resume_task as resume_task_cmd,
            start_task as start_task_cmd, stop_task as stop_task_cmd, CreateTaskOpts, GetTasksOpts,
            ModifyTaskOpts,
        },
        tickets::{get_ticket, get_tickets, GetTicketsOpts},
        user_settings::{
            get_user_setting, get_user_settings, modify_user_setting, GetUserSettingsOpts,
            ModifyUserSettingOpts,
        },
        users::{
            create_user, delete_user, get_user, get_users, modify_user, GetUsersOpts,
            UserHostAccess, UserOpts,
        },
    },
    responses::{
        ActionResponse, AuthenticateResponse, CreateAlertResponse, CreateCredentialResponse,
        CreateGroupResponse, CreateNoteResponse, CreateOverrideResponse, CreatePermissionResponse,
        CreatePortListResponse, CreateRoleResponse, CreateScanConfigResponse,
        CreateScheduleResponse, CreateTargetResponse, CreateTaskResponse, CreateUserResponse,
        GetAlertsResponse, GetCredentialsResponse, GetFeedsResponse, GetFiltersResponse,
        GetGroupsResponse, GetHostsResponse, GetNotesResponse, GetNvtFamiliesResponse,
        GetNvtsResponse, GetOverridesResponse, GetPermissionsResponse, GetPortListsResponse,
        GetReportFormatsResponse, GetReportsResponse, GetResultsResponse, GetRolesResponse,
        GetScanConfigsResponse, GetScannersResponse, GetSchedulesResponse, GetTagsResponse,
        GetTargetsResponse, GetTasksResponse, GetTicketsResponse, GetUserSettingsResponse,
        GetUsersResponse, GetVersionResponse, ModifyUserSettingResponse, ResumeTaskResponse,
        StartTaskResponse, User as GmpUser,
    },
    EntityId, Pagination as GmpPagination,
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
    alert_from_gmp, credential_from_gmp, feed_from_gmp, filter_from_gmp, group_from_gmp,
    host_from_gmp, map_gvm_error, map_parse_error, note_from_gmp, nvt_family_from_gmp,
    nvt_from_gmp, override_from_gmp, parse_alert_condition, parse_alert_event, parse_alert_method,
    parse_alive_test, parse_credential_type, parse_entity_id, parse_hosts_ordering,
    parse_permission_subject_type, parse_snmp_auth_algorithm, parse_snmp_privacy_algorithm,
    parse_user_auth_type, permission_from_gmp, port_list_from_gmp, report_format_from_gmp,
    report_from_gmp, result_from_gmp, result_from_report_closed_cve, result_from_report_error,
    result_from_report_vulnerability, role_from_gmp, scan_config_from_gmp, scanner_from_gmp,
    schedule_from_gmp, tag_from_gmp, target_from_gmp, task_from_gmp, ticket_from_gmp,
    tls_certificate_from_report_tls_certificate, user_from_gmp, user_setting_from_gmp,
};
use filters::{
    backend_ignored_pagination, composed_filter, gvmd_total, needs_client_side_pagination_fallback,
    paged_pagination, paged_slice, paginated_filter,
};
use session::{SessionClient, SharedClient};
use supporting_inputs::{
    collection_update, note_opts_from_create_input, note_opts_from_modify_input,
    override_opts_from_create_input, override_opts_from_modify_input,
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
            let connection = UnixSocketConnection::with_path(&self.socket_path);
            let mut client = GmpClient::connect(connection)
                .await
                .map_err(map_gvm_error)?;
            let negotiated = client.version().to_string();
            let response = client
                .call(authenticate(username, password))
                .await
                .map_err(map_gvm_error)?;
            AuthenticateResponse::from_response(&response).map_err(map_parse_error)?;

            self.sessions
                .lock()
                .map_err(|_| {
                    GatewayError::BackendUnavailable("session store unavailable".to_string())
                })?
                .insert(
                    SessionTokenDigest::from_token(session_token),
                    Arc::new(SessionClient::new(client)),
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

    fn default_credential_stores(&self) -> Vec<CredentialStore> {
        vec![CredentialStore {
            id: "default".to_string(),
            name: "Default".to_string(),
            provider: Some("gvmd".to_string()),
            default: true,
            writable: true,
        }]
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
