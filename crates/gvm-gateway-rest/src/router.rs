// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Router construction for the REST adapter.

use std::sync::Arc;

use aide::{
    axum::{
        routing::{delete_with, get_with, post_with, put_with},
        ApiRouter,
    },
    openapi::OpenApi,
};
use axum::{
    extract::{Extension, OriginalUri, Request},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use gvm_gateway_app::GatewayService;
use opentelemetry::{
    propagation::{Extractor, Injector, TextMapPropagator},
    Context,
};
use opentelemetry_sdk::propagation::{BaggagePropagator, TraceContextPropagator};
use serde_json::Value;
use tracing::{field, Instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::{
    alerts::{
        create_alert, create_alert_docs, delete_alert, delete_alert_docs, get_alert,
        get_alert_docs, list_alerts, list_alerts_docs, update_alert, update_alert_docs,
    },
    credentials::{
        create_credential, create_credential_docs, delete_credential, delete_credential_docs,
        get_credential, get_credential_docs, list_credential_stores, list_credential_stores_docs,
        list_credentials, list_credentials_docs, update_credential, update_credential_docs,
    },
    docs::{api_docs, redoc_js},
    emerging::{
        clone_agent_group_docs, clone_config_docs, clone_oci_image_target_docs,
        clone_web_application_target_docs, create_agent_group_docs, create_asset_docs,
        create_config_docs, create_oci_image_target_docs, create_web_application_target_docs,
        delete_agent_docs, delete_agent_group_docs, delete_asset_docs, delete_config_docs,
        delete_oci_image_target_docs, delete_operating_system_docs,
        delete_web_application_target_docs, get_agent_docs, get_agent_group_docs,
        get_agent_installer_instruction_docs, get_agent_support_bundle_docs, get_asset_docs,
        get_config_docs, get_oci_image_target_docs, get_operating_system_docs,
        get_report_applications_docs, get_report_cves_docs, get_report_hosts_docs,
        get_report_operating_systems_docs, get_report_ports_docs, get_web_application_target_docs,
        list_agent_groups_docs, list_agents_docs, list_assets_docs, list_configs_docs,
        list_oci_image_targets_docs, list_operating_systems_docs,
        list_web_application_targets_docs, modify_agent_control_scan_config_docs,
        modify_agent_docs, modify_agent_group_docs, modify_asset_docs, modify_config_docs,
        modify_oci_image_target_docs, modify_operating_system_docs,
        modify_web_application_target_docs, not_implemented, sync_agents_docs,
    },
    error::RestError,
    feeds::{list_feeds, list_feeds_docs},
    identity::{
        create_group, create_group_docs, create_permission, create_permission_docs, create_role,
        create_role_docs, create_user, create_user_docs, delete_group, delete_group_docs,
        delete_permission, delete_permission_docs, delete_role, delete_role_docs, delete_user,
        delete_user_docs, get_group, get_group_docs, get_permission, get_permission_docs, get_role,
        get_role_docs, get_user, get_user_docs, get_user_setting, get_user_setting_docs,
        list_groups, list_groups_docs, list_permissions, list_permissions_docs, list_roles,
        list_roles_docs, list_user_settings, list_user_settings_docs, list_users, list_users_docs,
        update_group, update_group_docs, update_permission, update_permission_docs, update_role,
        update_role_docs, update_user, update_user_docs, update_user_setting,
        update_user_setting_docs,
    },
    jobs::{
        cancel_job, cancel_job_docs, create_report_export_job, create_report_export_job_docs,
        download_job_result, download_job_result_docs, get_job, get_job_docs,
    },
    openapi::{configure as configure_openapi, finalize_document},
    port_lists::{
        create_port_list, create_port_list_docs, delete_port_list, delete_port_list_docs,
        get_port_list, get_port_list_docs, list_port_lists, list_port_lists_docs, update_port_list,
        update_port_list_docs,
    },
    reports::{
        delete_report, delete_report_docs, get_report, get_report_closed_cves,
        get_report_closed_cves_docs, get_report_docs, get_report_errors, get_report_errors_docs,
        get_report_results, get_report_results_docs, get_report_tls_certificates,
        get_report_tls_certificates_docs, get_report_vulnerabilities,
        get_report_vulnerabilities_docs, list_reports, list_reports_docs,
    },
    results::{get_result, get_result_docs, list_results, list_results_docs},
    scan_configs::{
        create_policy, create_policy_docs, create_scan_config, create_scan_config_docs,
        delete_policy, delete_policy_docs, delete_scan_config, delete_scan_config_docs, get_policy,
        get_policy_docs, get_scan_config, get_scan_config_docs, list_policies, list_policies_docs,
        list_scan_configs, list_scan_configs_docs, update_policy, update_policy_docs,
        update_scan_config, update_scan_config_docs,
    },
    scanners::{get_scanner, get_scanner_docs, list_scanners, list_scanners_docs},
    schedules::{
        create_schedule, create_schedule_docs, delete_schedule, delete_schedule_docs, get_schedule,
        get_schedule_docs, list_schedules, list_schedules_docs, update_schedule,
        update_schedule_docs,
    },
    security::{request_scoped_basic_auth_middleware, security_middleware, SecurityRuntime},
    sessions::{
        create_session, create_session_docs, delete_session, delete_session_docs, get_session,
        get_session_docs,
    },
    shutdown::ShutdownRuntime,
    supporting_resources::{
        create_note, create_note_docs, create_override, create_override_docs, delete_note,
        delete_note_docs, delete_override, delete_override_docs, get_filter, get_filter_docs,
        get_host, get_host_docs, get_note, get_note_docs, get_nvt, get_nvt_docs, get_override,
        get_override_docs, get_report_format, get_report_format_docs, get_tag, get_tag_docs,
        get_ticket, get_ticket_docs, get_tls_certificate, get_tls_certificate_docs, list_filters,
        list_filters_docs, list_hosts, list_hosts_docs, list_notes, list_notes_docs,
        list_nvt_families, list_nvt_families_docs, list_nvts, list_nvts_docs, list_overrides,
        list_overrides_docs, list_report_formats, list_report_formats_docs, list_tags,
        list_tags_docs, list_tickets, list_tickets_docs, list_tls_certificates,
        list_tls_certificates_docs, list_vulnerabilities, list_vulnerabilities_docs, update_note,
        update_note_docs, update_override, update_override_docs,
    },
    system::{health, health_docs, ready, ready_docs, version, version_docs},
    targets::{
        clone_target, clone_target_docs, create_target, create_target_docs, delete_target,
        delete_target_docs, get_target, get_target_docs, list_targets, list_targets_docs,
        update_target, update_target_docs,
    },
    tasks::{
        clone_task, clone_task_docs, create_audit, create_audit_docs, create_task,
        create_task_docs, delete_audit, delete_audit_docs, delete_task, delete_task_docs,
        get_audit, get_audit_docs, get_task, get_task_docs, list_audits, list_audits_docs,
        list_tasks, list_tasks_docs, resume_audit, resume_audit_docs, resume_task,
        resume_task_docs, start_audit, start_audit_docs, start_task, start_task_docs, stop_audit,
        stop_audit_docs, stop_task, stop_task_docs, update_audit, update_audit_docs, update_task,
        update_task_docs,
    },
};

pub use crate::rate_limit::RateLimitConfig;
pub use crate::security::RestSecurityConfig;

/// Builds the gateway router.
pub fn build_router(state: GatewayService) -> Router {
    build_router_with_runtime_and_security(
        state,
        Arc::new(ShutdownRuntime::default()),
        RestSecurityConfig::default(),
    )
}

/// Builds the gateway router with explicit REST security middleware config.
pub fn build_router_with_security(state: GatewayService, security: RestSecurityConfig) -> Router {
    build_router_with_runtime_and_security(state, Arc::new(ShutdownRuntime::default()), security)
}

/// Builds the gateway router with explicit shutdown and REST security runtime.
pub fn build_router_with_runtime_and_security(
    state: GatewayService,
    shutdown: Arc<ShutdownRuntime>,
    security: RestSecurityConfig,
) -> Router {
    let openapi = build_openapi();
    let openapi_json =
        Arc::new(serde_json::to_string_pretty(&openapi).expect("generated OpenAPI must serialize"));
    let request_scoped_auth_state = state.clone();
    let security_state = Arc::new(SecurityRuntime::new(security));
    let router: Router<GatewayService> = documented_router()
        // Browser documentation is operational UI, not part of the REST API
        // contract generated from `ApiRouter`.
        .route("/api/v1/docs", get(api_docs))
        .route("/api/v1/docs/redoc.standalone.js", get(redoc_js))
        .route("/api/v1/openapi.json", get(serve_openapi))
        .fallback(not_found)
        .into();

    router
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(
            request_scoped_auth_state,
            request_scoped_basic_auth_middleware,
        ))
        .layer(middleware::from_fn(trace_context_middleware))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&shutdown),
            shutdown_gate_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            security_state,
            security_middleware,
        ))
        .with_state(state)
        .layer(Extension(shutdown))
        .layer(Extension(openapi_json))
}

/// Builds the generated OpenAPI document for the currently implemented routes.
pub(crate) fn build_openapi() -> Value {
    let mut api = OpenApi::default();
    aide::generate::extract_schemas(true);
    aide::generate::infer_responses(false);
    aide::generate::inferred_empty_response_status(204);

    let _ = documented_router().finish_api_with(&mut api, configure_openapi);
    finalize_document(serde_json::to_value(api).expect("generated OpenAPI must serialize"))
}

fn documented_router() -> ApiRouter<GatewayService> {
    ApiRouter::new()
        .api_route("/health", get_with(health, health_docs))
        .api_route("/ready", get_with(ready, ready_docs))
        .api_route("/api/v1/version", get_with(version, version_docs))
        // Session lifecycle
        .api_route(
            "/api/v1/session",
            post_with(create_session, create_session_docs),
        )
        .api_route("/api/v1/session", get_with(get_session, get_session_docs))
        .api_route(
            "/api/v1/session",
            delete_with(delete_session, delete_session_docs),
        )
        // Targets
        .api_route("/api/v1/targets", get_with(list_targets, list_targets_docs))
        .api_route(
            "/api/v1/targets",
            post_with(create_target, create_target_docs),
        )
        .api_route(
            "/api/v1/targets/{id}",
            get_with(get_target, get_target_docs),
        )
        .api_route(
            "/api/v1/targets/{id}",
            put_with(update_target, update_target_docs),
        )
        .api_route(
            "/api/v1/targets/{id}",
            delete_with(delete_target, delete_target_docs),
        )
        .api_route(
            "/api/v1/targets/{id}/clone",
            post_with(clone_target, clone_target_docs),
        )
        // Current-GVMD agent management reserved until rust-gvm exposes typed responses
        .api_route(
            "/api/v1/agents",
            get_with(not_implemented, list_agents_docs),
        )
        .api_route(
            "/api/v1/agents/{id}",
            get_with(not_implemented, get_agent_docs),
        )
        .api_route(
            "/api/v1/agents/{id}",
            put_with(not_implemented, modify_agent_docs),
        )
        .api_route(
            "/api/v1/agents/{id}",
            delete_with(not_implemented, delete_agent_docs),
        )
        .api_route(
            "/api/v1/agents/sync",
            post_with(not_implemented, sync_agents_docs),
        )
        .api_route(
            "/api/v1/agents/{id}/support-bundle",
            get_with(not_implemented, get_agent_support_bundle_docs),
        )
        .api_route(
            "/api/v1/agent-control-scan-configs/{id}",
            put_with(not_implemented, modify_agent_control_scan_config_docs),
        )
        .api_route(
            "/api/v1/scanners/{id}/agent-installer-instruction",
            get_with(not_implemented, get_agent_installer_instruction_docs),
        )
        .api_route(
            "/api/v1/agent-groups",
            get_with(not_implemented, list_agent_groups_docs),
        )
        .api_route(
            "/api/v1/agent-groups",
            post_with(not_implemented, create_agent_group_docs),
        )
        .api_route(
            "/api/v1/agent-groups/{id}",
            get_with(not_implemented, get_agent_group_docs),
        )
        .api_route(
            "/api/v1/agent-groups/{id}",
            put_with(not_implemented, modify_agent_group_docs),
        )
        .api_route(
            "/api/v1/agent-groups/{id}",
            delete_with(not_implemented, delete_agent_group_docs),
        )
        .api_route(
            "/api/v1/agent-groups/{id}/clone",
            post_with(not_implemented, clone_agent_group_docs),
        )
        // Generic assets/configs reserved without changing specific hosts/scan-configs contracts
        .api_route(
            "/api/v1/assets",
            get_with(not_implemented, list_assets_docs),
        )
        .api_route(
            "/api/v1/assets",
            post_with(not_implemented, create_asset_docs),
        )
        .api_route(
            "/api/v1/assets/{id}",
            get_with(not_implemented, get_asset_docs),
        )
        .api_route(
            "/api/v1/assets/{id}",
            put_with(not_implemented, modify_asset_docs),
        )
        .api_route(
            "/api/v1/assets/{id}",
            delete_with(not_implemented, delete_asset_docs),
        )
        .api_route(
            "/api/v1/configs",
            get_with(not_implemented, list_configs_docs),
        )
        .api_route(
            "/api/v1/configs",
            post_with(not_implemented, create_config_docs),
        )
        .api_route(
            "/api/v1/configs/{id}",
            get_with(not_implemented, get_config_docs),
        )
        .api_route(
            "/api/v1/configs/{id}",
            put_with(not_implemented, modify_config_docs),
        )
        .api_route(
            "/api/v1/configs/{id}",
            delete_with(not_implemented, delete_config_docs),
        )
        .api_route(
            "/api/v1/configs/{id}/clone",
            post_with(not_implemented, clone_config_docs),
        )
        // New target families from current GVMD
        .api_route(
            "/api/v1/oci-image-targets",
            get_with(not_implemented, list_oci_image_targets_docs),
        )
        .api_route(
            "/api/v1/oci-image-targets",
            post_with(not_implemented, create_oci_image_target_docs),
        )
        .api_route(
            "/api/v1/oci-image-targets/{id}",
            get_with(not_implemented, get_oci_image_target_docs),
        )
        .api_route(
            "/api/v1/oci-image-targets/{id}",
            put_with(not_implemented, modify_oci_image_target_docs),
        )
        .api_route(
            "/api/v1/oci-image-targets/{id}",
            delete_with(not_implemented, delete_oci_image_target_docs),
        )
        .api_route(
            "/api/v1/oci-image-targets/{id}/clone",
            post_with(not_implemented, clone_oci_image_target_docs),
        )
        .api_route(
            "/api/v1/web-application-targets",
            get_with(not_implemented, list_web_application_targets_docs),
        )
        .api_route(
            "/api/v1/web-application-targets",
            post_with(not_implemented, create_web_application_target_docs),
        )
        .api_route(
            "/api/v1/web-application-targets/{id}",
            get_with(not_implemented, get_web_application_target_docs),
        )
        .api_route(
            "/api/v1/web-application-targets/{id}",
            put_with(not_implemented, modify_web_application_target_docs),
        )
        .api_route(
            "/api/v1/web-application-targets/{id}",
            delete_with(not_implemented, delete_web_application_target_docs),
        )
        .api_route(
            "/api/v1/web-application-targets/{id}/clone",
            post_with(not_implemented, clone_web_application_target_docs),
        )
        // Alerts
        .api_route("/api/v1/alerts", get_with(list_alerts, list_alerts_docs))
        .api_route("/api/v1/alerts", post_with(create_alert, create_alert_docs))
        .api_route("/api/v1/alerts/{id}", get_with(get_alert, get_alert_docs))
        .api_route(
            "/api/v1/alerts/{id}",
            put_with(update_alert, update_alert_docs),
        )
        .api_route(
            "/api/v1/alerts/{id}",
            delete_with(delete_alert, delete_alert_docs),
        )
        // Schedules
        .api_route(
            "/api/v1/schedules",
            get_with(list_schedules, list_schedules_docs),
        )
        .api_route(
            "/api/v1/schedules",
            post_with(create_schedule, create_schedule_docs),
        )
        .api_route(
            "/api/v1/schedules/{id}",
            get_with(get_schedule, get_schedule_docs),
        )
        .api_route(
            "/api/v1/schedules/{id}",
            put_with(update_schedule, update_schedule_docs),
        )
        .api_route(
            "/api/v1/schedules/{id}",
            delete_with(delete_schedule, delete_schedule_docs),
        )
        // Credentials
        .api_route(
            "/api/v1/credential-stores",
            get_with(list_credential_stores, list_credential_stores_docs),
        )
        .api_route(
            "/api/v1/credentials",
            get_with(list_credentials, list_credentials_docs),
        )
        .api_route(
            "/api/v1/credentials",
            post_with(create_credential, create_credential_docs),
        )
        .api_route(
            "/api/v1/credentials/{id}",
            get_with(get_credential, get_credential_docs),
        )
        .api_route(
            "/api/v1/credentials/{id}",
            put_with(update_credential, update_credential_docs),
        )
        .api_route(
            "/api/v1/credentials/{id}",
            delete_with(delete_credential, delete_credential_docs),
        )
        // Port Lists
        .api_route(
            "/api/v1/port-lists",
            get_with(list_port_lists, list_port_lists_docs),
        )
        .api_route(
            "/api/v1/port-lists",
            post_with(create_port_list, create_port_list_docs),
        )
        .api_route(
            "/api/v1/port-lists/{id}",
            get_with(get_port_list, get_port_list_docs),
        )
        .api_route(
            "/api/v1/port-lists/{id}",
            put_with(update_port_list, update_port_list_docs),
        )
        .api_route(
            "/api/v1/port-lists/{id}",
            delete_with(delete_port_list, delete_port_list_docs),
        )
        // Feeds
        .api_route("/api/v1/feeds", get_with(list_feeds, list_feeds_docs))
        // Supporting resources
        .api_route("/api/v1/hosts", get_with(list_hosts, list_hosts_docs))
        .api_route("/api/v1/hosts/{id}", get_with(get_host, get_host_docs))
        .api_route(
            "/api/v1/tls-certificates",
            get_with(list_tls_certificates, list_tls_certificates_docs),
        )
        .api_route(
            "/api/v1/tls-certificates/{id}",
            get_with(get_tls_certificate, get_tls_certificate_docs),
        )
        .api_route(
            "/api/v1/report-formats",
            get_with(list_report_formats, list_report_formats_docs),
        )
        .api_route(
            "/api/v1/report-formats/{id}",
            get_with(get_report_format, get_report_format_docs),
        )
        .api_route("/api/v1/filters", get_with(list_filters, list_filters_docs))
        .api_route(
            "/api/v1/filters/{id}",
            get_with(get_filter, get_filter_docs),
        )
        .api_route("/api/v1/tags", get_with(list_tags, list_tags_docs))
        .api_route("/api/v1/tags/{id}", get_with(get_tag, get_tag_docs))
        .api_route("/api/v1/tickets", get_with(list_tickets, list_tickets_docs))
        .api_route(
            "/api/v1/tickets/{id}",
            get_with(get_ticket, get_ticket_docs),
        )
        .api_route("/api/v1/notes", get_with(list_notes, list_notes_docs))
        .api_route("/api/v1/notes", post_with(create_note, create_note_docs))
        .api_route("/api/v1/notes/{id}", get_with(get_note, get_note_docs))
        .api_route(
            "/api/v1/notes/{id}",
            put_with(update_note, update_note_docs),
        )
        .api_route(
            "/api/v1/notes/{id}",
            delete_with(delete_note, delete_note_docs),
        )
        .api_route(
            "/api/v1/overrides",
            get_with(list_overrides, list_overrides_docs),
        )
        .api_route(
            "/api/v1/overrides",
            post_with(create_override, create_override_docs),
        )
        .api_route(
            "/api/v1/overrides/{id}",
            get_with(get_override, get_override_docs),
        )
        .api_route(
            "/api/v1/overrides/{id}",
            put_with(update_override, update_override_docs),
        )
        .api_route(
            "/api/v1/overrides/{id}",
            delete_with(delete_override, delete_override_docs),
        )
        .api_route("/api/v1/nvts", get_with(list_nvts, list_nvts_docs))
        .api_route("/api/v1/nvts/{id}", get_with(get_nvt, get_nvt_docs))
        .api_route(
            "/api/v1/vulnerabilities",
            get_with(list_vulnerabilities, list_vulnerabilities_docs),
        )
        .api_route(
            "/api/v1/nvt-families",
            get_with(list_nvt_families, list_nvt_families_docs),
        )
        // Identity and access control
        .api_route("/api/v1/users", get_with(list_users, list_users_docs))
        .api_route("/api/v1/users", post_with(create_user, create_user_docs))
        .api_route("/api/v1/users/{id}", get_with(get_user, get_user_docs))
        .api_route(
            "/api/v1/users/{id}",
            put_with(update_user, update_user_docs),
        )
        .api_route(
            "/api/v1/users/{id}",
            delete_with(delete_user, delete_user_docs),
        )
        .api_route("/api/v1/groups", get_with(list_groups, list_groups_docs))
        .api_route("/api/v1/groups", post_with(create_group, create_group_docs))
        .api_route("/api/v1/groups/{id}", get_with(get_group, get_group_docs))
        .api_route(
            "/api/v1/groups/{id}",
            put_with(update_group, update_group_docs),
        )
        .api_route(
            "/api/v1/groups/{id}",
            delete_with(delete_group, delete_group_docs),
        )
        .api_route("/api/v1/roles", get_with(list_roles, list_roles_docs))
        .api_route("/api/v1/roles", post_with(create_role, create_role_docs))
        .api_route("/api/v1/roles/{id}", get_with(get_role, get_role_docs))
        .api_route(
            "/api/v1/roles/{id}",
            put_with(update_role, update_role_docs),
        )
        .api_route(
            "/api/v1/roles/{id}",
            delete_with(delete_role, delete_role_docs),
        )
        .api_route(
            "/api/v1/permissions",
            get_with(list_permissions, list_permissions_docs),
        )
        .api_route(
            "/api/v1/permissions",
            post_with(create_permission, create_permission_docs),
        )
        .api_route(
            "/api/v1/permissions/{id}",
            get_with(get_permission, get_permission_docs),
        )
        .api_route(
            "/api/v1/permissions/{id}",
            put_with(update_permission, update_permission_docs),
        )
        .api_route(
            "/api/v1/permissions/{id}",
            delete_with(delete_permission, delete_permission_docs),
        )
        .api_route(
            "/api/v1/user-settings",
            get_with(list_user_settings, list_user_settings_docs),
        )
        .api_route(
            "/api/v1/user-settings/{id}",
            get_with(get_user_setting, get_user_setting_docs),
        )
        .api_route(
            "/api/v1/user-settings/{id}",
            put_with(update_user_setting, update_user_setting_docs),
        )
        // Tasks
        .api_route("/api/v1/tasks", get_with(list_tasks, list_tasks_docs))
        .api_route("/api/v1/tasks", post_with(create_task, create_task_docs))
        .api_route("/api/v1/tasks/{id}", get_with(get_task, get_task_docs))
        .api_route(
            "/api/v1/tasks/{id}",
            put_with(update_task, update_task_docs),
        )
        .api_route(
            "/api/v1/tasks/{id}",
            delete_with(delete_task, delete_task_docs),
        )
        .api_route(
            "/api/v1/tasks/{id}/clone",
            post_with(clone_task, clone_task_docs),
        )
        .api_route(
            "/api/v1/tasks/{id}/start",
            post_with(start_task, start_task_docs),
        )
        .api_route(
            "/api/v1/tasks/{id}/stop",
            post_with(stop_task, stop_task_docs),
        )
        .api_route(
            "/api/v1/tasks/{id}/resume",
            post_with(resume_task, resume_task_docs),
        )
        // Audits (compliance tasks; get/start/stop/resume reuse task handlers)
        .api_route("/api/v1/audits", get_with(list_audits, list_audits_docs))
        .api_route("/api/v1/audits", post_with(create_audit, create_audit_docs))
        .api_route("/api/v1/audits/{id}", get_with(get_audit, get_audit_docs))
        .api_route(
            "/api/v1/audits/{id}",
            put_with(update_audit, update_audit_docs),
        )
        .api_route(
            "/api/v1/audits/{id}",
            delete_with(delete_audit, delete_audit_docs),
        )
        .api_route(
            "/api/v1/audits/{id}/start",
            post_with(start_audit, start_audit_docs),
        )
        .api_route(
            "/api/v1/audits/{id}/stop",
            post_with(stop_audit, stop_audit_docs),
        )
        .api_route(
            "/api/v1/audits/{id}/resume",
            post_with(resume_audit, resume_audit_docs),
        )
        // Reports
        .api_route("/api/v1/reports", get_with(list_reports, list_reports_docs))
        .api_route(
            "/api/v1/reports/{id}",
            get_with(get_report, get_report_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/exports",
            post_with(create_report_export_job, create_report_export_job_docs),
        )
        .api_route(
            "/api/v1/reports/{id}",
            delete_with(delete_report, delete_report_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/results",
            get_with(get_report_results, get_report_results_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/vulnerabilities",
            get_with(get_report_vulnerabilities, get_report_vulnerabilities_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/tls-certificates",
            get_with(
                get_report_tls_certificates,
                get_report_tls_certificates_docs,
            ),
        )
        .api_route(
            "/api/v1/reports/{id}/errors",
            get_with(get_report_errors, get_report_errors_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/closed-cves",
            get_with(get_report_closed_cves, get_report_closed_cves_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/hosts",
            get_with(not_implemented, get_report_hosts_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/ports",
            get_with(not_implemented, get_report_ports_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/applications",
            get_with(not_implemented, get_report_applications_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/operating-systems",
            get_with(not_implemented, get_report_operating_systems_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/cves",
            get_with(not_implemented, get_report_cves_docs),
        )
        // Jobs
        .api_route("/api/v1/jobs/{id}", get_with(get_job, get_job_docs))
        .api_route(
            "/api/v1/jobs/{id}",
            delete_with(cancel_job, cancel_job_docs),
        )
        .api_route(
            "/api/v1/jobs/{id}/result",
            get_with(download_job_result, download_job_result_docs),
        )
        // Results
        .api_route("/api/v1/results", get_with(list_results, list_results_docs))
        .api_route(
            "/api/v1/results/{id}",
            get_with(get_result, get_result_docs),
        )
        // Scan Configs
        .api_route(
            "/api/v1/scan-configs",
            get_with(list_scan_configs, list_scan_configs_docs),
        )
        .api_route(
            "/api/v1/scan-configs",
            post_with(create_scan_config, create_scan_config_docs),
        )
        .api_route(
            "/api/v1/scan-configs/{id}",
            get_with(get_scan_config, get_scan_config_docs),
        )
        .api_route(
            "/api/v1/scan-configs/{id}",
            put_with(update_scan_config, update_scan_config_docs),
        )
        .api_route(
            "/api/v1/scan-configs/{id}",
            delete_with(delete_scan_config, delete_scan_config_docs),
        )
        // Policies (compliance scan configs; get reuses the scan-config handler)
        .api_route(
            "/api/v1/policies",
            get_with(list_policies, list_policies_docs),
        )
        .api_route(
            "/api/v1/policies",
            post_with(create_policy, create_policy_docs),
        )
        .api_route(
            "/api/v1/policies/{id}",
            get_with(get_policy, get_policy_docs),
        )
        .api_route(
            "/api/v1/policies/{id}",
            put_with(update_policy, update_policy_docs),
        )
        .api_route(
            "/api/v1/policies/{id}",
            delete_with(delete_policy, delete_policy_docs),
        )
        // Scanners
        .api_route(
            "/api/v1/scanners",
            get_with(list_scanners, list_scanners_docs),
        )
        .api_route(
            "/api/v1/scanners/{id}",
            get_with(get_scanner, get_scanner_docs),
        )
        .api_route(
            "/api/v1/operating-systems",
            get_with(not_implemented, list_operating_systems_docs),
        )
        .api_route(
            "/api/v1/operating-systems/{id}",
            get_with(not_implemented, get_operating_system_docs),
        )
        .api_route(
            "/api/v1/operating-systems/{id}",
            put_with(not_implemented, modify_operating_system_docs),
        )
        .api_route(
            "/api/v1/operating-systems/{id}",
            delete_with(not_implemented, delete_operating_system_docs),
        )
}

async fn serve_openapi(Extension(openapi_json): Extension<Arc<String>>) -> Response {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        (*openapi_json).clone(),
    )
        .into_response()
}

pub(crate) async fn method_not_allowed(uri: OriginalUri) -> Response {
    RestError::method_not_allowed(uri.path()).into_response()
}

async fn not_found(request: Request) -> Response {
    RestError::not_found(request.uri().path()).into_response()
}

async fn trace_context_middleware(request: Request, next: Next) -> Response {
    let trace_headers = extract_trace_headers(request.headers());
    let request_path = request.uri().path().to_string();
    let request_method = request.method().clone();
    let parent_context = extract_trace_context(request.headers());
    let span = tracing::info_span!(
        "http.request",
        otel_name = field::Empty,
        http_method = %request_method,
        http_route = %request_path,
        http_status_code = field::Empty,
    );
    span.record(
        "otel_name",
        field::display(format!("{request_method} {request_path}")),
    );
    let _ = span.set_parent(parent_context);

    let span_for_response = span.clone();
    let mut response = async move { next.run(request).await }
        .instrument(span)
        .await;
    span_for_response.record(
        "http_status_code",
        field::display(response.status().as_u16()),
    );
    apply_trace_headers(
        response.headers_mut(),
        &trace_headers,
        &span_for_response.context(),
    );
    response
}

async fn shutdown_gate_middleware(
    axum::extract::State(shutdown): axum::extract::State<Arc<ShutdownRuntime>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    if should_bypass_shutdown_gate(&path) {
        return next.run(request).await;
    }

    let Some(_in_flight) = shutdown.try_track_request() else {
        tracing::info!(path, "shutdown: rejecting new request while draining");
        return RestError::service_unavailable(
            "The gateway is shutting down and no longer accepts new requests.",
            path,
        )
        .into_response();
    };

    next.run(request).await
}

fn should_bypass_shutdown_gate(path: &str) -> bool {
    matches!(path, "/health" | "/ready")
}

#[derive(Clone, Default)]
struct TraceHeaders {
    traceparent: Option<HeaderValue>,
    tracestate: Option<HeaderValue>,
}

fn extract_trace_headers(headers: &HeaderMap) -> TraceHeaders {
    TraceHeaders {
        traceparent: headers.get("traceparent").cloned(),
        tracestate: headers.get("tracestate").cloned(),
    }
}

fn apply_trace_headers(headers: &mut HeaderMap, trace_headers: &TraceHeaders, context: &Context) {
    trace_context_propagator().inject_context(context, &mut HeaderInjector(headers));

    if !headers.contains_key("traceparent") {
        if let Some(value) = trace_headers.traceparent.clone() {
            headers.insert(HeaderName::from_static("traceparent"), value);
        }
    }

    if !headers.contains_key("tracestate") {
        if let Some(value) = trace_headers.tracestate.clone() {
            headers.insert(HeaderName::from_static("tracestate"), value);
        }
    }
}

fn extract_trace_context(headers: &HeaderMap) -> Context {
    trace_propagator().extract(&HeaderExtractor(headers))
}

fn trace_propagator() -> opentelemetry::propagation::TextMapCompositePropagator {
    opentelemetry::propagation::TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ])
}

fn trace_context_propagator() -> TraceContextPropagator {
    TraceContextPropagator::new()
}

struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(HeaderName::as_str).collect()
    }
}

struct HeaderInjector<'a>(&'a mut HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        let Ok(name) = HeaderName::from_bytes(key.as_bytes()) else {
            return;
        };
        let Ok(value) = HeaderValue::from_str(&value) else {
            return;
        };
        self.0.insert(name, value);
    }
}

pub(crate) fn bearer_token(
    headers: &HeaderMap,
) -> Result<String, gvm_gateway_domain::GatewayError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            gvm_gateway_domain::GatewayError::Unauthorized("missing bearer token".to_string())
        })?;

    value
        .strip_prefix("Bearer ")
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            gvm_gateway_domain::GatewayError::Unauthorized("missing bearer token".to_string())
        })
}

#[cfg(test)]
#[path = "router_test.rs"]
mod router_test;
