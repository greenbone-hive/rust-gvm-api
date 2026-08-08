// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! GMP → domain type conversions, error mapping, and shared parsing helpers.
//!
//! Everything in this module is `pub(crate)` — it is an implementation detail
//! of the gvmd adapter and not part of the crate's public API.

use std::str::FromStr;

use gvm_gateway_domain::{
    Alert, Credential, Feed, Filter, GatewayError, Group, Host, IdentityResourceMeta, Note, Nvt,
    NvtFamily, NvtRef, Override, Permission, PortList, Report, ReportFormat, ResourceRef,
    ResultCount, Role, ScanConfig, ScanResult, Scanner, Schedule, SupportingResourceMeta, Tag,
    Target, Task, TaskObservers, Ticket, TlsCertificate, User, UserSetting,
};
use gvm_gmp::{
    AlertCondition, AlertEvent, AlertMethod, AliveTest, CredentialType, EntityId, HostsOrdering,
    PermissionSubjectType, SnmpAuthAlgorithm, SnmpPrivacyAlgorithm, UserAuthType,
};

// ============================================================================
// GMP → Domain Conversion Utilities
// ============================================================================

pub(crate) fn target_from_gmp(target: gvm_gmp::responses::Target) -> Target {
    Target {
        id: target.meta.id.to_string(),
        name: target.meta.name,
        comment: target.meta.comment,
        hosts: target.hosts,
        exclude_hosts: target.exclude_hosts,
        alive_test: target.alive_tests,
        port_list: target.port_list.map(resource_ref_from_named_entity),
        reverse_lookup_only: target.reverse_lookup_only,
        reverse_lookup_unify: target.reverse_lookup_unify,
        ssh_credential: target.ssh_credential.map(resource_ref_from_named_entity),
        smb_credential: target.smb_credential.map(resource_ref_from_named_entity),
        esxi_credential: target.esxi_credential.map(resource_ref_from_named_entity),
        snmp_credential: target.snmp_credential.map(resource_ref_from_named_entity),
        in_use: target.meta.in_use,
        writable: target.meta.writable,
    }
}

pub(crate) fn alert_from_gmp(alert: gvm_gmp::responses::Alert) -> Alert {
    Alert {
        id: alert.meta.id.to_string(),
        name: alert.meta.name,
        comment: alert.meta.comment,
        event: alert.event,
        condition: alert.condition,
        method: alert.method,
        event_data: alert.event_data,
        condition_data: alert.condition_data,
        method_data: alert.method_data,
        filter: alert.filter.map(|resource| ResourceRef {
            id: resource.id.to_string(),
            name: Some(resource.name),
        }),
        in_use: alert.meta.in_use,
        writable: alert.meta.writable,
    }
}

pub(crate) fn schedule_from_gmp(schedule: gvm_gmp::responses::Schedule) -> Schedule {
    Schedule {
        id: schedule.meta.id.to_string(),
        name: schedule.meta.name,
        comment: schedule.meta.comment,
        icalendar: schedule.icalendar,
        timezone: schedule.timezone,
        first_run: schedule.first_run,
        next_run: schedule.next_run,
        duration: schedule.duration,
        in_use: schedule.meta.in_use,
        writable: schedule.meta.writable,
    }
}

pub(crate) fn credential_from_gmp(credential: gvm_gmp::responses::Credential) -> Credential {
    Credential {
        id: credential.meta.id.to_string(),
        name: credential.meta.name,
        comment: credential.meta.comment,
        credential_type: credential.type_,
        login: credential.login,
        in_use: credential.meta.in_use,
        writable: credential.meta.writable,
    }
}

pub(crate) fn port_list_from_gmp(port_list: gvm_gmp::responses::PortList) -> PortList {
    PortList {
        id: port_list.meta.id.to_string(),
        name: port_list.meta.name,
        comment: port_list.meta.comment,
        port_count: port_list.port_count,
        tcp_count: port_list.tcp_count,
        udp_count: port_list.udp_count,
        port_range: port_list.port_range,
        in_use: port_list.meta.in_use,
        writable: port_list.meta.writable,
    }
}

pub(crate) fn feed_from_gmp(feed: gvm_gmp::responses::Feed) -> Feed {
    Feed {
        feed_type: feed.type_,
        name: feed.name,
        version: feed.version,
        description: feed.description,
        currently_syncing: feed
            .currently_syncing
            .as_deref()
            .is_some_and(|value| value != "0"),
    }
}

pub(crate) fn user_from_gmp(user: gvm_gmp::responses::User) -> User {
    User {
        meta: identity_meta_from_gmp(user.meta),
        roles: user
            .roles
            .into_iter()
            .map(resource_ref_from_named_entity)
            .collect(),
        groups: user
            .groups
            .into_iter()
            .map(resource_ref_from_named_entity)
            .collect(),
        hosts_allow: user.hosts_allow.as_deref().and_then(parse_bool_flag),
        hosts: user.hosts,
        authentication_type: user.authentication_type,
    }
}

pub(crate) fn group_from_gmp(group: gvm_gmp::responses::Group) -> Group {
    Group {
        meta: identity_meta_from_gmp(group.meta),
        users: group.users,
    }
}

pub(crate) fn role_from_gmp(role: gvm_gmp::responses::Role) -> Role {
    Role {
        meta: identity_meta_from_gmp(role.meta),
        users: role.users,
    }
}

pub(crate) fn permission_from_gmp(permission: gvm_gmp::responses::Permission) -> Permission {
    Permission {
        meta: identity_meta_from_gmp(permission.meta),
        subject_type: permission.subject_type,
        subject: permission.subject.map(resource_ref_from_named_entity),
        resource_type: permission.resource_type,
        resource: permission.resource.map(resource_ref_from_named_entity),
    }
}

pub(crate) fn user_setting_from_gmp(setting: gvm_gmp::responses::UserSetting) -> UserSetting {
    UserSetting {
        id: setting.id.to_string(),
        name: setting.name,
        value: setting.value,
        comment: setting.comment,
    }
}

pub(crate) fn task_from_gmp(task: gvm_gmp::responses::Task) -> Task {
    let named_entity_to_ref = |entity: gvm_gmp::responses::NamedEntity| -> ResourceRef {
        ResourceRef {
            id: entity.id.to_string(),
            name: if entity.name.is_empty() {
                None
            } else {
                Some(entity.name)
            },
        }
    };

    Task {
        id: task.meta.id.to_string(),
        name: task.meta.name,
        comment: task.meta.comment,
        status: task.status.unwrap_or_else(|| "New".to_string()),
        progress: task.progress,
        target: task.target.map(&named_entity_to_ref),
        scan_config: task.config.map(&named_entity_to_ref),
        scanner: task.scanner.map(&named_entity_to_ref),
        schedule: task.schedule.map(&named_entity_to_ref),
        alerts: task.alerts.into_iter().map(&named_entity_to_ref).collect(),
        alterable: task.alterable,
        hosts_ordering: task.hosts_ordering,
        observers: task
            .observers
            .map(|observers| TaskObservers {
                users: observers.users,
                groups: observers
                    .groups
                    .into_iter()
                    .map(&named_entity_to_ref)
                    .collect(),
                roles: observers
                    .roles
                    .into_iter()
                    .map(&named_entity_to_ref)
                    .collect(),
            })
            .unwrap_or_default(),
        schedule_periods: task.schedule_periods,
        last_report: task.last_report.map(|lr| ResourceRef {
            id: lr.id.to_string(),
            name: None,
        }),
        current_report: task.current_report.map(|report| ResourceRef {
            id: report.id.to_string(),
            name: None,
        }),
        report_count: task.report_count,
        in_use: task.meta.in_use,
        writable: task.meta.writable,
    }
}

pub(crate) fn report_from_gmp(report: gvm_gmp::responses::Report) -> Report {
    let severity = report
        .severity
        .as_ref()
        .and_then(|s| s.full.as_deref())
        .and_then(|v| v.parse::<f64>().ok());

    Report {
        id: report.meta.id.to_string(),
        task: report.task.map(resource_ref_from_named_entity),
        scan_start: report.scan_start,
        scan_end: report.scan_end,
        severity,
        result_count: report.result_count.map(|rc| ResultCount {
            total: rc.full,
            high: rc.high.and_then(|count| count.full),
            medium: rc.medium.and_then(|count| count.full),
            low: rc.low.and_then(|count| count.full),
            log: rc.log.and_then(|count| count.full),
            debug: rc.debug.and_then(|count| count.full),
            false_positive: rc.false_positive.and_then(|count| count.full),
        }),
        results: vec![],
    }
}

pub(crate) fn result_from_gmp(result: gvm_gmp::responses::ScanResult) -> ScanResult {
    let severity = result.severity_score();

    let nvt = result.nvt.map(|n| {
        let cvss_base = n.cvss_base_score();
        NvtRef {
            oid: Some(n.oid),
            name: n.name,
            family: n.family,
            cvss_base,
            cves: n.cves,
            tags: n.tags,
        }
    });

    ScanResult {
        id: result.meta.id.to_string(),
        name: result.meta.name,
        host: result.host,
        port: result.port,
        severity,
        threat: result.threat,
        nvt,
        description: result.description,
        task: result.task.map(resource_ref_from_named_entity),
        report: result.report.map(resource_ref_from_named_entity),
        hosts_count: None,
        occurrences: None,
    }
}

pub(crate) fn result_from_report_vulnerability(
    vulnerability: gvm_gmp::responses::ReportVulnerability,
) -> ScanResult {
    let name = vulnerability.name.unwrap_or_default();
    ScanResult {
        id: vulnerability.id.unwrap_or_default(),
        name: name.clone(),
        host: vulnerability.host,
        port: vulnerability.port,
        severity: vulnerability
            .severity
            .as_deref()
            .and_then(|value| value.parse::<f64>().ok()),
        threat: vulnerability.threat,
        nvt: Some(NvtRef {
            oid: vulnerability.nvt_oid,
            name: if name.is_empty() { None } else { Some(name) },
            family: vulnerability.family,
            cvss_base: None,
            cves: vulnerability.cves,
            tags: None,
        }),
        description: None,
        task: None,
        report: None,
        hosts_count: vulnerability.hosts_count,
        occurrences: vulnerability.occurrences,
    }
}

pub(crate) fn tls_certificate_from_report_tls_certificate(
    certificate: gvm_gmp::responses::ReportTlsCertificate,
) -> TlsCertificate {
    TlsCertificate {
        id: certificate.id,
        host: certificate.host,
        port: certificate.port,
        subject: certificate.subject.or(certificate.name).unwrap_or_default(),
        issuer: certificate.issuer,
        not_before: certificate.activation_time,
        not_after: certificate.expiration_time,
        fingerprint_sha256: None,
    }
}

pub(crate) fn result_from_report_error(error: gvm_gmp::responses::ReportError) -> ScanResult {
    ScanResult {
        id: error.id.unwrap_or_default(),
        name: error.name.unwrap_or_default(),
        host: error.host,
        port: error.port,
        severity: None,
        threat: Some("Alarm".to_string()),
        nvt: error.nvt_name.map(|name| NvtRef {
            oid: None,
            name: Some(name),
            family: None,
            cvss_base: None,
            cves: Vec::new(),
            tags: None,
        }),
        description: error.description,
        task: None,
        report: None,
        hosts_count: None,
        occurrences: None,
    }
}

pub(crate) fn result_from_report_closed_cve(
    closed_cve: gvm_gmp::responses::ReportClosedCve,
) -> ScanResult {
    let cve = closed_cve.cve.unwrap_or_default();
    ScanResult {
        id: closed_cve.id.unwrap_or_default(),
        name: cve.clone(),
        host: closed_cve.host,
        port: None,
        severity: closed_cve
            .severity
            .as_deref()
            .and_then(|value| value.parse::<f64>().ok()),
        threat: closed_cve.threat,
        nvt: Some(NvtRef {
            oid: closed_cve.nvt_oid,
            name: closed_cve.name,
            family: None,
            cvss_base: None,
            cves: if cve.is_empty() { vec![] } else { vec![cve] },
            tags: None,
        }),
        description: None,
        task: None,
        report: None,
        hosts_count: None,
        occurrences: None,
    }
}

pub(crate) fn scan_config_from_gmp(config: gvm_gmp::responses::ScanConfig) -> ScanConfig {
    ScanConfig {
        id: config.meta.id.to_string(),
        name: config.meta.name,
        comment: config.meta.comment,
        family_count: None,
        nvt_count: None,
        config_type: config.type_,
        in_use: config.meta.in_use,
        writable: config.meta.writable,
    }
}

pub(crate) fn scanner_from_gmp(scanner: gvm_gmp::responses::Scanner) -> Scanner {
    Scanner {
        id: scanner.meta.id.to_string(),
        name: scanner.meta.name,
        comment: scanner.meta.comment,
        host: scanner.host,
        port: scanner.port.map(|p| p as u32),
        scanner_type: scanner.scanner_type,
    }
}

pub(crate) fn report_format_from_gmp(
    report_format: gvm_gmp::responses::ReportFormat,
) -> ReportFormat {
    ReportFormat {
        meta: supporting_meta_from_gmp(report_format.meta),
        content_type: report_format.content_type,
        extension: report_format.extension,
        summary: report_format.summary,
        trust: report_format.trust,
        active: report_format.active,
        predefined: report_format.predefined,
    }
}

pub(crate) fn host_from_gmp(host: gvm_gmp::responses::Host) -> Host {
    Host {
        meta: supporting_meta_from_gmp(host.meta),
        ip: host.ip,
        hostname: host.hostname,
        severity: host.severity,
        os: host.os,
    }
}

pub(crate) fn filter_from_gmp(filter: gvm_gmp::responses::Filter) -> Filter {
    Filter {
        meta: supporting_meta_from_gmp(filter.meta),
        filter_type: filter.type_,
        term: filter.term,
    }
}

pub(crate) fn tag_from_gmp(tag: gvm_gmp::responses::Tag) -> Tag {
    Tag {
        meta: supporting_meta_from_gmp(tag.meta),
        value: tag.value,
        resource_type: tag.resource_type,
        resource_count: tag.resource_count,
        active: tag.active,
    }
}

pub(crate) fn ticket_from_gmp(ticket: gvm_gmp::responses::Ticket) -> Ticket {
    Ticket {
        meta: supporting_meta_from_gmp(ticket.meta),
        status: ticket.status,
        assigned_to: ticket.assigned_to.map(resource_ref_from_named_entity),
        result: ticket.result.map(resource_ref_from_named_entity),
        task: ticket.task.map(resource_ref_from_named_entity),
        open_note: ticket.open_note,
        fixed_note: ticket.fixed_note,
        closed_note: ticket.closed_note,
    }
}

pub(crate) fn note_from_gmp(note: gvm_gmp::responses::Note) -> Note {
    Note {
        meta: supporting_meta_from_gmp(note.meta),
        text: note.text,
        nvt: note.nvt_oid.map(nvt_ref_from_oid),
        hosts: note.hosts,
        port: note.port,
        severity: note.severity,
        task: note.task.map(resource_ref_from_named_entity),
        result: note.result.map(resource_ref_from_named_entity),
        active: note.active,
        end_time: note.end_time,
    }
}

pub(crate) fn override_from_gmp(override_: gvm_gmp::responses::Override) -> Override {
    Override {
        meta: supporting_meta_from_gmp(override_.meta),
        text: override_.text,
        nvt: override_.nvt_oid.map(nvt_ref_from_oid),
        hosts: override_.hosts,
        port: override_.port,
        severity: override_.severity,
        new_severity: override_.new_severity,
        task: override_.task.map(resource_ref_from_named_entity),
        result: override_.result.map(resource_ref_from_named_entity),
        active: override_.active,
        end_time: override_.end_time,
    }
}

pub(crate) fn nvt_from_gmp(nvt: gvm_gmp::responses::Nvt) -> Nvt {
    let cvss_base = nvt.cvss_base_score();
    let severity = nvt.severity_score();

    Nvt {
        oid: nvt.oid,
        name: nvt.name,
        family: nvt.family,
        cvss_base,
        severity,
        tags: nvt.tags,
        solution_type: nvt.solution_type,
    }
}

pub(crate) fn nvt_family_from_gmp(nvt_family: gvm_gmp::responses::NvtFamily) -> NvtFamily {
    NvtFamily {
        name: nvt_family.name,
        max_nvt_count: nvt_family.max_nvt_count,
    }
}

// ============================================================================
// Shared Parsing / Validation Helpers
// ============================================================================

pub(crate) fn parse_entity_id(value: &str) -> Result<EntityId, GatewayError> {
    EntityId::new(value).map_err(|_| GatewayError::InvalidInput(format!("invalid UUID: {value}")))
}

pub(crate) fn parse_alive_test(value: &str) -> Result<AliveTest, GatewayError> {
    AliveTest::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid aliveTest: {value}")))
}

pub(crate) fn parse_hosts_ordering(value: &str) -> Result<HostsOrdering, GatewayError> {
    match value {
        "sequential" => Ok(HostsOrdering::Sequential),
        "random" => Ok(HostsOrdering::Random),
        "reverse" => Ok(HostsOrdering::Reverse),
        _ => Err(GatewayError::InvalidInput(format!(
            "invalid hostsOrdering: {value}"
        ))),
    }
}

pub(crate) fn parse_alert_event(value: &str) -> Result<AlertEvent, GatewayError> {
    AlertEvent::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid event: {value}")))
}

pub(crate) fn parse_alert_condition(value: &str) -> Result<AlertCondition, GatewayError> {
    AlertCondition::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid condition: {value}")))
}

pub(crate) fn parse_alert_method(value: &str) -> Result<AlertMethod, GatewayError> {
    AlertMethod::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid method: {value}")))
}

pub(crate) fn parse_credential_type(value: &str) -> Result<CredentialType, GatewayError> {
    CredentialType::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid credential type: {value}")))
}

pub(crate) fn parse_snmp_auth_algorithm(value: &str) -> Result<SnmpAuthAlgorithm, GatewayError> {
    SnmpAuthAlgorithm::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid authAlgorithm: {value}")))
}

pub(crate) fn parse_snmp_privacy_algorithm(
    value: &str,
) -> Result<SnmpPrivacyAlgorithm, GatewayError> {
    SnmpPrivacyAlgorithm::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid privacyAlgorithm: {value}")))
}

pub(crate) fn parse_user_auth_type(value: &str) -> Result<UserAuthType, GatewayError> {
    UserAuthType::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid authenticationType: {value}")))
}

pub(crate) fn parse_permission_subject_type(
    value: &str,
) -> Result<PermissionSubjectType, GatewayError> {
    PermissionSubjectType::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid subjectType: {value}")))
}

// ============================================================================
// Error Mapping
// ============================================================================

pub(crate) fn map_gvm_error(error: gvm_client::GvmError) -> GatewayError {
    match error {
        gvm_client::GvmError::Parse(error) => map_parse_error(error),
        gvm_client::GvmError::UnsupportedCommand { .. } => {
            GatewayError::NotImplemented(error.to_string())
        }
        gvm_client::GvmError::Server {
            status: 400,
            message,
        } if is_authentication_failure(&message) => GatewayError::Unauthorized(message),
        gvm_client::GvmError::Server {
            status: 400,
            message,
        } => GatewayError::InvalidInput(message),
        gvm_client::GvmError::Server {
            status: 401,
            message,
        } => GatewayError::Unauthorized(message),
        gvm_client::GvmError::Server {
            status: 403,
            message,
        } => GatewayError::Forbidden(message),
        gvm_client::GvmError::Server {
            status: 404,
            message,
        } => GatewayError::NotFound(message),
        gvm_client::GvmError::Timeout(duration) => {
            GatewayError::GatewayTimeout(format!("gvmd timeout after {duration:?}"))
        }
        other => GatewayError::BackendUnavailable(other.to_string()),
    }
}

fn identity_meta_from_gmp(meta: gvm_gmp::responses::common::EntityMeta) -> IdentityResourceMeta {
    IdentityResourceMeta {
        id: meta.id.to_string(),
        name: meta.name,
        comment: meta.comment,
        owner: None,
        creation_time: meta.creation_time,
        modification_time: meta.modification_time,
        writable: meta.writable,
        in_use: meta.in_use,
    }
}

fn supporting_meta_from_gmp(
    meta: gvm_gmp::responses::common::EntityMeta,
) -> SupportingResourceMeta {
    SupportingResourceMeta {
        id: meta.id.to_string(),
        name: meta.name,
        comment: meta.comment,
        creation_time: meta.creation_time,
        modification_time: meta.modification_time,
        writable: meta.writable,
        in_use: meta.in_use,
    }
}

fn resource_ref_from_named_entity(entity: gvm_gmp::responses::NamedEntity) -> ResourceRef {
    ResourceRef {
        id: entity.id.to_string(),
        name: if entity.name.is_empty() {
            None
        } else {
            Some(entity.name)
        },
    }
}

fn nvt_ref_from_oid(oid: String) -> NvtRef {
    NvtRef {
        oid: Some(oid),
        name: None,
        family: None,
        cvss_base: None,
        cves: vec![],
        tags: None,
    }
}

fn parse_bool_flag(value: &str) -> Option<bool> {
    match value {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

pub(crate) fn map_parse_error(error: gvm_gmp::responses::ParseError) -> GatewayError {
    match error {
        gvm_gmp::responses::ParseError::ServerError {
            status: 404,
            message,
        } => GatewayError::NotFound(message),
        gvm_gmp::responses::ParseError::ServerError {
            status: 400,
            message,
        } if is_authentication_failure(&message) => GatewayError::Unauthorized(message),
        gvm_gmp::responses::ParseError::ServerError {
            status: 400,
            message,
        } => GatewayError::InvalidInput(message),
        gvm_gmp::responses::ParseError::ServerError {
            status: 401,
            message,
        } => GatewayError::Unauthorized(message),
        gvm_gmp::responses::ParseError::ServerError {
            status: 403,
            message,
        } => GatewayError::Forbidden(message),
        other => GatewayError::BackendUnavailable(other.to_string()),
    }
}

fn is_authentication_failure(message: &str) -> bool {
    message.eq_ignore_ascii_case("authentication failed")
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[path = "conversions_test.rs"]
mod conversions_test;
