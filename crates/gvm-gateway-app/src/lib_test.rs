// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![cfg(test)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use gvm_gateway_domain::{
    AssetQuery, CreateReportExportRequest, CreateTargetInput, GatewayError, GenericConfigQuery,
    GetReportOpts, GvmdReportFormatExportRequest, ImportReportInput, JobStatus,
    JsonReportExportRequest, ModifyAssetInput, ModifyTargetInput, Pagination, ReadinessStatus,
    Report, ReportApplicationPage, ReportClosedCvePage, ReportCvePage, ReportErrorPage,
    ReportExport, ReportExportJob, ReportExportRequest, ReportHostPage, ReportOperatingSystemPage,
    ReportPage, ReportPort, ReportPortPage, ReportQuery, ReportVulnerabilityPage, ResourceRef,
    ResultPage, ResultQuery, ScanResult, SessionLimits, SessionManager, SessionTokenDigest,
    SystemPort, TargetQuery, Timezone, TlsCertificatePage,
};
use tokio::sync::Notify;

use crate::{service::safe_session_id, test_support::*, GatewayService, SessionReaper};

/// Health always reports `ok` because liveness is process-local.
#[test]
fn service_health_always_returns_ok() {
    let service = create_test_service();
    let health = service.health();
    assert_eq!(health.status, "ok");
}

/// Raw-token observability paths use the shared digest-based safe ID without
/// exposing the complete bearer token or a raw token suffix.
#[test]
fn safe_session_id_uses_session_token_digest() {
    let token = "gvm_sess_1234567890abcdef";

    let session_id = safe_session_id(token);

    assert_eq!(session_id, SessionTokenDigest::from_token(token).safe_id());
    assert!(!session_id.contains(token));
    assert!(!session_id.contains("90abcdef"));
}

/// Ready forwards a healthy backend readiness response unchanged.
#[tokio::test]
async fn service_ready_returns_readiness() {
    let service = create_test_service();
    let ready = service.ready().await.unwrap();
    assert_eq!(ready.status, "ready");
    assert!(ready.reason.is_none());
}

/// Ready preserves a not-ready backend status and reason.
#[tokio::test]
async fn service_ready_returns_not_ready() {
    let mut ports = test_ports();
    ports.system = Arc::new(MockSystemPort {
        ready: false,
        gmp_version: "22.7".to_string(),
    });
    let service = GatewayService::new(ports, Arc::new(SessionManager::default()));
    let ready = service.ready().await.unwrap();
    assert_eq!(ready.status, "notReady");
    assert!(ready.reason.is_some());
}

/// Version includes both the crate version and the backend GMP version.
#[tokio::test]
async fn service_version_returns_api_and_gmp_version() {
    let service = create_test_service();
    let version = service.version().await.unwrap();
    assert_eq!(version.gmp_version, "22.7");
    assert!(!version.api_version.is_empty());
}

#[derive(Clone)]
struct FailingVersionSystemPort;

#[async_trait]
impl SystemPort for FailingVersionSystemPort {
    async fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
        Ok(ReadinessStatus {
            status: "ready",
            reason: None,
        })
    }

    async fn gmp_version(&self) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "version probe failed".to_string(),
        ))
    }

    async fn list_timezones(&self, _: &str) -> Result<Vec<Timezone>, GatewayError> {
        Ok(vec![])
    }
}

#[derive(Clone)]
struct FixedTimezoneSystemPort;

#[async_trait]
impl SystemPort for FixedTimezoneSystemPort {
    async fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
        Ok(ReadinessStatus {
            status: "ready",
            reason: None,
        })
    }

    async fn gmp_version(&self) -> Result<String, GatewayError> {
        Ok("22.8".to_string())
    }

    async fn list_timezones(&self, _: &str) -> Result<Vec<Timezone>, GatewayError> {
        Ok(vec![
            Timezone {
                name: "UTC".to_string(),
                offset: None,
            },
            Timezone {
                name: "Europe/Berlin".to_string(),
                offset: Some("+01:00".to_string()),
            },
        ])
    }
}

/// Session creation must use the version negotiated by the authenticated
/// backend connection instead of opening a second connection for a post-auth
/// version probe that can fail and orphan the newly created session.
#[tokio::test]
async fn service_create_session_uses_authenticated_version_without_extra_probe() {
    let sessions = Arc::new(SessionManager::with_limits(
        300,
        SessionLimits {
            max_global: Some(1),
            max_per_user: Some(1),
        },
    ));
    let auth = Arc::new(MockAuthPort {
        gmp_version: "22.9".to_string(),
        ..Default::default()
    });
    let disconnected = Arc::clone(&auth.disconnected);
    let mut ports = test_ports();
    ports.system = Arc::new(FailingVersionSystemPort);
    ports.auth = auth;
    let service = GatewayService::new(ports, Arc::clone(&sessions));

    let created = service.create_session("admin", "secret").await.unwrap();

    assert_eq!(created.gmp_version, "22.9");
    assert!(service.get_session(&created.token).is_ok());
    assert!(disconnected.lock().unwrap().is_empty());
}

/// Reaper startup clamps the derived default tick interval above Tokio's
/// zero-period panic while preserving short idle-timeout configurations.
#[tokio::test]
async fn session_reaper_spawn_uses_non_zero_default_interval_for_short_timeouts() {
    for timeout_secs in [0, 1] {
        let sessions = Arc::new(SessionManager::new(timeout_secs));
        let reaper = SessionReaper::new(sessions, Arc::new(MockAuthPort::default()));

        let handle = reaper.spawn();
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert!(
            !handle.is_finished(),
            "reaper task exited for idle timeout {timeout_secs}"
        );

        handle.abort();
        let result = handle.await;
        assert!(
            result.is_err_and(|err| err.is_cancelled()),
            "reaper task should stop through cancellation"
        );
    }
}

/// Target listing rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_list_targets_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .list_targets("invalid-token", TargetQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Target listing succeeds after a valid session is created.
#[tokio::test]
async fn service_list_targets_with_valid_session() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();
    let result = service
        .list_targets(&session.token, TargetQuery::default())
        .await;
    assert!(result.is_ok());
}

/// Timezone listing must remain session-scoped so the new system surface uses
/// the same authenticated execution path as the rest of the backend-backed API.
#[tokio::test]
async fn service_list_timezones_requires_valid_session() {
    let service = create_test_service();

    let result = service.list_timezones("invalid-token").await;

    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Backend timezone values should flow through the app layer unchanged once an
/// authenticated session exists.
#[tokio::test]
async fn service_list_timezones_returns_backend_values() {
    let sessions = Arc::new(SessionManager::default());
    let mut ports = test_ports();
    ports.system = Arc::new(FixedTimezoneSystemPort);
    let service = GatewayService::new(ports, Arc::clone(&sessions));
    let session = service.session_manager().create("admin").unwrap();

    let result = service.list_timezones(&session.token).await.unwrap();

    assert_eq!(
        result,
        vec![
            Timezone {
                name: "UTC".to_string(),
                offset: None,
            },
            Timezone {
                name: "Europe/Berlin".to_string(),
                offset: Some("+01:00".to_string()),
            },
        ]
    );
}

/// Generic resource operations share the normal authenticated service path and
/// preserve list pagination when forwarding to their dedicated ports.
#[tokio::test]
async fn service_generic_resource_operations_use_sessions_and_typed_ports() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();

    let assets = service
        .list_assets(
            &session.token,
            AssetQuery {
                page: 2,
                per_page: 10,
                asset_type: "tls_certificate".to_string(),
                ..Default::default()
            },
        )
        .await
        .expect("valid session should reach the asset port");
    let configs = service
        .list_configs(
            &session.token,
            GenericConfigQuery {
                page: 3,
                per_page: 5,
                usage_type: Some("future_usage".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("valid session should reach the config port");

    assert_eq!(
        (assets.pagination.page, assets.pagination.per_page),
        (2, 10)
    );
    assert_eq!(
        (configs.pagination.page, configs.pagination.per_page),
        (3, 5)
    );

    let error = service
        .modify_asset(
            "invalid-token",
            "123e4567-e89b-12d3-a456-426614174000",
            "host",
            ModifyAssetInput {
                comment: Some("blocked".to_string()),
            },
        )
        .await
        .expect_err("invalid sessions must fail before generic mutation");
    assert!(matches!(error, GatewayError::SessionInvalidated(_)));
}

/// Target creation rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_create_target_requires_valid_session() {
    let service = create_test_service();
    let input = CreateTargetInput {
        name: "test".to_string(),
        comment: None,
        hosts: vec!["127.0.0.1".to_string()],
        exclude_hosts: vec![],
        alive_test: None,
        port_list_id: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    };
    let result = service.create_target("invalid-token", input).await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Target fetch rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_get_target_requires_valid_session() {
    let service = create_test_service();
    let result = service.get_target("invalid-token", "some-id").await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Target modification rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_modify_target_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .modify_target("invalid-token", "some-id", ModifyTargetInput::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Target deletion rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_delete_target_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .delete_target("invalid-token", "some-id", false)
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Expired sessions are rejected consistently by target operations.
#[tokio::test]
async fn service_operations_fail_with_expired_session() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();
    service.session_manager().expire(&session.token).unwrap();

    let result = service
        .list_targets(&session.token, TargetQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionExpired(_))));
}

/// Report listing rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_list_reports_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .list_reports("invalid-token", ReportQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Report listing succeeds after a valid session is created.
#[tokio::test]
async fn service_list_reports_with_valid_session() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();
    let result = service
        .list_reports(&session.token, ReportQuery::default())
        .await;
    assert!(result.is_ok());
}

/// Report fetch rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_get_report_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .get_report("invalid-token", "some-id", GetReportOpts::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Report export rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_export_report_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .export_report("invalid-token", "some-report-id", "some-report-format-id")
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Creating an asynchronous report export job rejects unknown sessions before queuing work.
#[tokio::test]
async fn service_create_report_export_job_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .create_report_export_job(
            "invalid-token",
            "some-report-id",
            CreateReportExportRequest::Json(JsonReportExportRequest {
                filter: None,
                filter_id: None,
            }),
        )
        .await;

    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Created report export jobs are visible through the job-status use case.
#[tokio::test]
async fn service_create_report_export_job_returns_pollable_job() {
    let service = create_test_service_with_report_port(Arc::new(ExistingReportPort));
    let session = service.session_manager().create("admin").unwrap();

    let job = service
        .create_report_export_job(
            &session.token,
            "123e4567-e89b-12d3-a456-426614174000",
            CreateReportExportRequest::Json(JsonReportExportRequest {
                filter: None,
                filter_id: None,
            }),
        )
        .await
        .expect("job should be accepted");
    let fetched = service
        .get_job(&session.token, &job.id)
        .await
        .expect("created job should be pollable");

    assert_eq!(fetched.id, job.id);
    assert_eq!(fetched.report.id, "123e4567-e89b-12d3-a456-426614174000");
    assert!(matches!(
        fetched.status,
        JobStatus::Queued | JobStatus::Running | JobStatus::Failed
    ));
}

/// Gvmd report-format export jobs preserve report config and result filter
/// options so the gvmd adapter can render the documented request shape.
#[tokio::test]
async fn service_gvmd_report_export_job_forwards_export_options() {
    let captured = Arc::new(Mutex::new(None));
    let service = create_test_service_with_report_port(Arc::new(CapturingReportPort {
        captured: Arc::clone(&captured),
    }));
    let session = service.session_manager().create("admin").unwrap();

    let job = service
        .create_report_export_job(
            &session.token,
            "123e4567-e89b-12d3-a456-426614174000",
            CreateReportExportRequest::GvmdReportFormat(GvmdReportFormatExportRequest {
                report_format_id: "123e4567-e89b-12d3-a456-426614174111".to_string(),
                report_config_id: Some("123e4567-e89b-12d3-a456-426614174222".to_string()),
                filter: Some("severity>5".to_string()),
                filter_id: Some("123e4567-e89b-12d3-a456-426614174333".to_string()),
            }),
        )
        .await
        .expect("job should be accepted");
    wait_for_job_status(&service, &session.token, &job.id, JobStatus::Succeeded).await;

    let forwarded = captured
        .lock()
        .expect("captured export request mutex should not be poisoned")
        .clone()
        .expect("worker should call the report export port");
    assert_eq!(
        forwarded,
        ReportExportRequest {
            report_format_id: "123e4567-e89b-12d3-a456-426614174111".to_string(),
            report_config_id: Some("123e4567-e89b-12d3-a456-426614174222".to_string()),
            filter: Some("severity>5".to_string()),
            filter_id: Some("123e4567-e89b-12d3-a456-426614174333".to_string()),
        }
    );
}

/// Terminal jobs expose an expiry timestamp and are purged after retention.
#[tokio::test]
async fn service_report_export_jobs_expire_after_terminal_retention() {
    let service = create_test_service_with_report_port(Arc::new(ExistingReportPort));
    service.set_job_policy_for_tests(1000, 1);
    let session = service.session_manager().create("admin").unwrap();

    // The short retention locks the background cleanup contract without waiting
    // for the production 15-minute expiry window.
    let job = service
        .create_report_export_job(
            &session.token,
            "123e4567-e89b-12d3-a456-426614174000",
            CreateReportExportRequest::Json(JsonReportExportRequest {
                filter: None,
                filter_id: None,
            }),
        )
        .await
        .expect("job should be accepted");

    let mut terminal = None;
    for _ in 0..20 {
        let fetched = service
            .get_job(&session.token, &job.id)
            .await
            .expect("job should be visible before expiry");
        if fetched.status.is_terminal() {
            terminal = Some(fetched);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let terminal = terminal.expect("job should reach a terminal state");
    assert!(terminal.completed_at.is_some());
    assert!(terminal.expires_at.is_some());

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    service.job_reaper().sweep_once_for_test().await;
    assert_eq!(service.retained_job_count_for_tests(), 0);
    let expired = service.get_job(&session.token, &job.id).await;
    assert!(matches!(expired, Err(GatewayError::NotFound(_))));
}

/// Job creation fails with backpressure once the retained job cap is reached.
#[tokio::test]
async fn service_report_export_jobs_enforce_capacity_limit() {
    let service = create_test_service_with_report_port(Arc::new(ExistingReportPort));
    service.set_job_policy_for_tests(1, 900);
    let session = service.session_manager().create("admin").unwrap();

    let first = service
        .create_report_export_job(
            &session.token,
            "123e4567-e89b-12d3-a456-426614174000",
            CreateReportExportRequest::Json(JsonReportExportRequest {
                filter: None,
                filter_id: None,
            }),
        )
        .await;
    assert!(first.is_ok());

    let second = service
        .create_report_export_job(
            &session.token,
            "123e4567-e89b-12d3-a456-426614174000",
            CreateReportExportRequest::Json(JsonReportExportRequest {
                filter: None,
                filter_id: None,
            }),
        )
        .await;
    assert!(matches!(second, Err(GatewayError::TooManyRequests(_))));
}

/// Missing reports are rejected before a background export job is queued.
#[tokio::test]
async fn service_create_report_export_job_preflights_report_existence() {
    let service = create_test_service_with_report_port(Arc::new(MissingReportPort));
    let session = service.session_manager().create("admin").unwrap();

    let result = service
        .create_report_export_job(
            &session.token,
            "123e4567-e89b-12d3-a456-426614174000",
            CreateReportExportRequest::Json(JsonReportExportRequest {
                filter: None,
                filter_id: None,
            }),
        )
        .await;

    assert!(matches!(result, Err(GatewayError::NotFound(_))));
    assert_eq!(service.retained_job_count_for_tests(), 0);
}

/// Running export jobs hold their creating session so the idle reaper does not
/// remove the gvmd connection while background report retrieval is in progress.
#[tokio::test]
async fn service_report_export_job_holds_session_during_background_work() {
    let release = Arc::new(Notify::new());
    let service = create_test_service_with_report_port_and_sessions(
        Arc::new(BlockingReportPort {
            release: Arc::clone(&release),
        }),
        Arc::new(SessionManager::new(1)),
    );
    let session = service.session_manager().create("admin").unwrap();

    let job = service
        .create_report_export_job(
            &session.token,
            "123e4567-e89b-12d3-a456-426614174000",
            CreateReportExportRequest::Json(JsonReportExportRequest {
                filter: None,
                filter_id: None,
            }),
        )
        .await
        .expect("job should be accepted");
    wait_for_job_status(&service, &session.token, &job.id, JobStatus::Running).await;

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let drained = service.session_manager().drain_expired().unwrap();

    release.notify_waiters();
    assert!(drained.is_empty());
    assert!(service
        .session_manager()
        .get(&session.token)
        .unwrap()
        .is_some());
}

/// Deleting a session cancels non-terminal jobs that were started from that
/// session instead of leaving them to continue with an invalid backend login.
#[tokio::test]
async fn service_delete_session_cancels_running_report_export_job() {
    let release = Arc::new(Notify::new());
    let service = create_test_service_with_report_port(Arc::new(BlockingReportPort {
        release: Arc::clone(&release),
    }));
    let session = service.session_manager().create("admin").unwrap();

    let job = service
        .create_report_export_job(
            &session.token,
            "123e4567-e89b-12d3-a456-426614174000",
            CreateReportExportRequest::Json(JsonReportExportRequest {
                filter: None,
                filter_id: None,
            }),
        )
        .await
        .expect("job should be accepted");
    wait_for_job_status(&service, &session.token, &job.id, JobStatus::Running).await;

    service
        .delete_session(&session.token)
        .await
        .expect("session deletion should succeed");
    release.notify_waiters();

    let replacement_session = service.session_manager().create("admin").unwrap();
    let cancelled = service
        .get_job(&replacement_session.token, &job.id)
        .await
        .expect("same user should still see retained cancelled job");
    assert_eq!(cancelled.status, JobStatus::Cancelled);
}

/// A late abort-handle attachment must not resurrect cancellability after the
/// job has already reached a terminal state.
#[tokio::test]
async fn service_cancelled_report_export_job_rejects_late_abort_handle() {
    let release = Arc::new(Notify::new());
    let service = create_test_service_with_report_port(Arc::new(BlockingReportPort {
        release: Arc::clone(&release),
    }));
    let session = service.session_manager().create("admin").unwrap();

    let job = service
        .create_report_export_job(
            &session.token,
            "123e4567-e89b-12d3-a456-426614174000",
            CreateReportExportRequest::Json(JsonReportExportRequest {
                filter: None,
                filter_id: None,
            }),
        )
        .await
        .expect("job should be accepted");
    wait_for_job_status(&service, &session.token, &job.id, JobStatus::Running).await;

    service
        .cancel_job(&session.token, &job.id)
        .await
        .expect("job cancellation should succeed");

    let late_worker = tokio::spawn(async {
        std::future::pending::<()>().await;
    });
    service
        .attach_abort_handle_for_tests(&job.id, late_worker.abort_handle())
        .expect("late abort-handle attachment should be handled");
    let join_error = late_worker
        .await
        .expect_err("late worker should be aborted immediately");

    release.notify_waiters();
    assert!(join_error.is_cancelled());
    assert!(!service.job_has_abort_handle_for_tests(&job.id));
}

fn create_test_service_with_report_port(report_port: Arc<dyn ReportPort>) -> GatewayService {
    create_test_service_with_report_port_and_sessions(
        report_port,
        Arc::new(SessionManager::default()),
    )
}

fn create_test_service_with_report_port_and_sessions(
    report_port: Arc<dyn ReportPort>,
    sessions: Arc<SessionManager>,
) -> GatewayService {
    let mut ports = test_ports();
    ports.reports = report_port;
    GatewayService::new(ports, sessions)
}

async fn wait_for_job_status(
    service: &GatewayService,
    session_token: &str,
    job_id: &str,
    expected: JobStatus,
) -> ReportExportJob {
    for _ in 0..20 {
        let fetched = service
            .get_job(session_token, job_id)
            .await
            .expect("job should be visible while waiting for status");
        if fetched.status == expected {
            return fetched;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("job {job_id} did not reach status {expected:?}");
}

struct BlockingReportPort {
    release: Arc<Notify>,
}

#[async_trait]
impl ReportPort for BlockingReportPort {
    async fn import_report(&self, _: &str, _: ImportReportInput) -> Result<String, GatewayError> {
        Err(GatewayError::NotImplemented(
            "report import is outside this test port".to_string(),
        ))
    }

    async fn list_reports(&self, _: &str, query: &ReportQuery) -> Result<ReportPage, GatewayError> {
        Ok(ReportPage {
            data: vec![test_report("123e4567-e89b-12d3-a456-426614174000")],
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 1,
                total_pages: 1,
            },
        })
    }

    async fn get_report(
        &self,
        _: &str,
        id: &str,
        _: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        Ok(test_report(id))
    }

    async fn export_report(
        &self,
        _: &str,
        _: &str,
        _: &ReportExportRequest,
    ) -> Result<ReportExport, GatewayError> {
        self.release.notified().await;
        Ok(ReportExport {
            bytes: b"export".to_vec(),
            content_type: Some("text/plain".to_string()),
            extension: Some("txt".to_string()),
        })
    }

    async fn delete_report(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn get_report_results(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        self.release.notified().await;
        Ok(empty_result_page(query))
    }

    async fn get_report_vulnerabilities(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportVulnerabilityPage, GatewayError> {
        Ok(empty_report_vulnerability_page(query))
    }

    async fn get_report_hosts(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportHostPage, GatewayError> {
        Ok(empty_report_host_page(query))
    }

    async fn get_report_ports(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportPortPage, GatewayError> {
        Ok(empty_report_port_page(query))
    }

    async fn get_report_applications(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportApplicationPage, GatewayError> {
        Ok(empty_report_application_page(query))
    }

    async fn get_report_operating_systems(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportOperatingSystemPage, GatewayError> {
        Ok(empty_report_operating_system_page(query))
    }

    async fn get_report_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportCvePage, GatewayError> {
        Ok(empty_report_cve_page(query))
    }

    async fn get_report_tls_certificates(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        Ok(TlsCertificatePage {
            data: vec![],
            pagination: Pagination {
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
    ) -> Result<ReportErrorPage, GatewayError> {
        Ok(empty_report_error_page(query))
    }

    async fn get_report_closed_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportClosedCvePage, GatewayError> {
        Ok(empty_report_closed_cve_page(query))
    }
}

struct ExistingReportPort;

#[async_trait]
impl ReportPort for ExistingReportPort {
    async fn import_report(&self, _: &str, _: ImportReportInput) -> Result<String, GatewayError> {
        Err(GatewayError::NotImplemented(
            "report import is outside this test port".to_string(),
        ))
    }

    async fn list_reports(&self, _: &str, query: &ReportQuery) -> Result<ReportPage, GatewayError> {
        Ok(ReportPage {
            data: vec![test_report("123e4567-e89b-12d3-a456-426614174000")],
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 1,
                total_pages: 1,
            },
        })
    }

    async fn get_report(
        &self,
        _: &str,
        id: &str,
        _: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        Ok(test_report(id))
    }

    async fn export_report(
        &self,
        _: &str,
        _: &str,
        _: &ReportExportRequest,
    ) -> Result<ReportExport, GatewayError> {
        Ok(ReportExport {
            bytes: b"export".to_vec(),
            content_type: Some("text/plain".to_string()),
            extension: Some("txt".to_string()),
        })
    }

    async fn delete_report(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn get_report_results(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(empty_result_page(query))
    }

    async fn get_report_vulnerabilities(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportVulnerabilityPage, GatewayError> {
        Ok(empty_report_vulnerability_page(query))
    }

    async fn get_report_hosts(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportHostPage, GatewayError> {
        Ok(empty_report_host_page(query))
    }

    async fn get_report_ports(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportPortPage, GatewayError> {
        Ok(empty_report_port_page(query))
    }

    async fn get_report_applications(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportApplicationPage, GatewayError> {
        Ok(empty_report_application_page(query))
    }

    async fn get_report_operating_systems(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportOperatingSystemPage, GatewayError> {
        Ok(empty_report_operating_system_page(query))
    }

    async fn get_report_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportCvePage, GatewayError> {
        Ok(empty_report_cve_page(query))
    }

    async fn get_report_tls_certificates(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        Ok(TlsCertificatePage {
            data: vec![],
            pagination: Pagination {
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
    ) -> Result<ReportErrorPage, GatewayError> {
        Ok(empty_report_error_page(query))
    }

    async fn get_report_closed_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportClosedCvePage, GatewayError> {
        Ok(empty_report_closed_cve_page(query))
    }
}

struct CapturingReportPort {
    captured: Arc<Mutex<Option<ReportExportRequest>>>,
}

#[async_trait]
impl ReportPort for CapturingReportPort {
    async fn import_report(&self, _: &str, _: ImportReportInput) -> Result<String, GatewayError> {
        Err(GatewayError::NotImplemented(
            "report import is outside this test port".to_string(),
        ))
    }

    async fn list_reports(&self, _: &str, query: &ReportQuery) -> Result<ReportPage, GatewayError> {
        Ok(ReportPage {
            data: vec![test_report("123e4567-e89b-12d3-a456-426614174000")],
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 1,
                total_pages: 1,
            },
        })
    }

    async fn get_report(
        &self,
        _: &str,
        id: &str,
        _: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        Ok(test_report(id))
    }

    async fn export_report(
        &self,
        _: &str,
        _: &str,
        request: &ReportExportRequest,
    ) -> Result<ReportExport, GatewayError> {
        *self
            .captured
            .lock()
            .expect("captured export request mutex should not be poisoned") = Some(request.clone());
        Ok(ReportExport {
            bytes: b"export".to_vec(),
            content_type: Some("text/plain".to_string()),
            extension: Some("txt".to_string()),
        })
    }

    async fn delete_report(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn get_report_results(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(empty_result_page(query))
    }

    async fn get_report_vulnerabilities(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportVulnerabilityPage, GatewayError> {
        Ok(empty_report_vulnerability_page(query))
    }

    async fn get_report_hosts(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportHostPage, GatewayError> {
        Ok(empty_report_host_page(query))
    }

    async fn get_report_ports(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportPortPage, GatewayError> {
        Ok(empty_report_port_page(query))
    }

    async fn get_report_applications(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportApplicationPage, GatewayError> {
        Ok(empty_report_application_page(query))
    }

    async fn get_report_operating_systems(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportOperatingSystemPage, GatewayError> {
        Ok(empty_report_operating_system_page(query))
    }

    async fn get_report_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportCvePage, GatewayError> {
        Ok(empty_report_cve_page(query))
    }

    async fn get_report_tls_certificates(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        Ok(TlsCertificatePage {
            data: vec![],
            pagination: Pagination {
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
    ) -> Result<ReportErrorPage, GatewayError> {
        Ok(empty_report_error_page(query))
    }

    async fn get_report_closed_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportClosedCvePage, GatewayError> {
        Ok(empty_report_closed_cve_page(query))
    }
}

struct MissingReportPort;

#[async_trait]
impl ReportPort for MissingReportPort {
    async fn import_report(&self, _: &str, _: ImportReportInput) -> Result<String, GatewayError> {
        Err(GatewayError::NotFound("import task not found".to_string()))
    }

    async fn list_reports(&self, _: &str, query: &ReportQuery) -> Result<ReportPage, GatewayError> {
        Ok(ReportPage {
            data: vec![],
            pagination: Pagination {
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
        id: &str,
        _: &ReportExportRequest,
    ) -> Result<ReportExport, GatewayError> {
        Err(GatewayError::NotFound(format!("report {id} not found")))
    }

    async fn delete_report(&self, _: &str, id: &str) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("report {id} not found")))
    }

    async fn get_report_results(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(empty_result_page(query))
    }

    async fn get_report_vulnerabilities(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportVulnerabilityPage, GatewayError> {
        Ok(empty_report_vulnerability_page(query))
    }

    async fn get_report_hosts(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportHostPage, GatewayError> {
        Ok(empty_report_host_page(query))
    }

    async fn get_report_ports(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportPortPage, GatewayError> {
        Ok(empty_report_port_page(query))
    }

    async fn get_report_applications(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportApplicationPage, GatewayError> {
        Ok(empty_report_application_page(query))
    }

    async fn get_report_operating_systems(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportOperatingSystemPage, GatewayError> {
        Ok(empty_report_operating_system_page(query))
    }

    async fn get_report_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportCvePage, GatewayError> {
        Ok(empty_report_cve_page(query))
    }

    async fn get_report_tls_certificates(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        Ok(TlsCertificatePage {
            data: vec![],
            pagination: Pagination {
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
    ) -> Result<ReportErrorPage, GatewayError> {
        Ok(empty_report_error_page(query))
    }

    async fn get_report_closed_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportClosedCvePage, GatewayError> {
        Ok(empty_report_closed_cve_page(query))
    }
}

fn test_report(id: &str) -> Report {
    Report {
        id: id.to_string(),
        task: Some(ResourceRef {
            id: "223e4567-e89b-12d3-a456-426614174000".to_string(),
            name: Some("Task".to_string()),
        }),
        scan_start: None,
        scan_end: None,
        severity: Some(0.0),
        result_count: None,
        results: vec![],
    }
}

fn empty_result_page(query: &ResultQuery) -> ResultPage {
    ResultPage {
        data: Vec::<ScanResult>::new(),
        pagination: Pagination {
            page: query.page,
            per_page: query.per_page,
            total: 0,
            total_pages: 0,
        },
    }
}

fn empty_report_vulnerability_page(query: &ResultQuery) -> ReportVulnerabilityPage {
    ReportVulnerabilityPage {
        data: vec![],
        pagination: empty_result_page(query).pagination,
    }
}

fn empty_report_error_page(query: &ResultQuery) -> ReportErrorPage {
    ReportErrorPage {
        data: vec![],
        pagination: empty_result_page(query).pagination,
    }
}

fn empty_report_closed_cve_page(query: &ResultQuery) -> ReportClosedCvePage {
    ReportClosedCvePage {
        data: vec![],
        pagination: empty_result_page(query).pagination,
    }
}

fn empty_report_host_page(query: &ResultQuery) -> ReportHostPage {
    ReportHostPage {
        data: vec![],
        pagination: Pagination {
            page: query.page,
            per_page: query.per_page,
            total: 0,
            total_pages: 0,
        },
    }
}

fn empty_report_port_page(query: &ResultQuery) -> ReportPortPage {
    ReportPortPage {
        data: vec![],
        pagination: Pagination {
            page: query.page,
            per_page: query.per_page,
            total: 0,
            total_pages: 0,
        },
    }
}

fn empty_report_application_page(query: &ResultQuery) -> ReportApplicationPage {
    ReportApplicationPage {
        data: vec![],
        pagination: Pagination {
            page: query.page,
            per_page: query.per_page,
            total: 0,
            total_pages: 0,
        },
    }
}

fn empty_report_operating_system_page(query: &ResultQuery) -> ReportOperatingSystemPage {
    ReportOperatingSystemPage {
        data: vec![],
        pagination: Pagination {
            page: query.page,
            per_page: query.per_page,
            total: 0,
            total_pages: 0,
        },
    }
}

fn empty_report_cve_page(query: &ResultQuery) -> ReportCvePage {
    ReportCvePage {
        data: vec![],
        pagination: Pagination {
            page: query.page,
            per_page: query.per_page,
            total: 0,
            total_pages: 0,
        },
    }
}

/// Report deletion rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_delete_report_requires_valid_session() {
    let service = create_test_service();
    let result = service.delete_report("invalid-token", "some-id").await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Result listing rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_list_results_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .list_results("invalid-token", ResultQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Result listing succeeds after a valid session is created.
#[tokio::test]
async fn service_list_results_with_valid_session() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();
    let result = service
        .list_results(&session.token, ResultQuery::default())
        .await;
    assert!(result.is_ok());
}

/// Result fetch rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_get_result_requires_valid_session() {
    let service = create_test_service();
    let result = service.get_result("invalid-token", "some-id").await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Expired sessions are rejected consistently by report operations.
#[tokio::test]
async fn service_report_operations_fail_with_expired_session() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();
    service.session_manager().expire(&session.token).unwrap();

    let result = service
        .list_reports(&session.token, ReportQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionExpired(_))));
}

/// Audit logs record auth failures without leaking credentials or raw session tokens.
#[tokio::test]
async fn audit_logs_redact_sensitive_fields_and_record_session_creation_failure() {
    let _trace_lock = lock_tracing().await;
    let capture = capture_tracing();
    capture
        .run(async {
            let mut ports = test_ports();
            ports.auth = Arc::new(MockAuthPort {
                should_fail: true,
                ..Default::default()
            });
            let service = GatewayService::new(ports, Arc::new(SessionManager::default()));

            let _ = service
                .create_session("admin", "super-secret-password")
                .await;
        })
        .await;

    let output = capture.output();
    assert!(output.contains("audit_event=\"session.create\""));
    assert!(output.contains("audit_outcome=\"failure\""));
    assert!(output.contains("gvmd_username=admin"));
    assert!(output.contains("session_id=\"session:"));
    assert!(!output.contains("super-secret-password"));
    assert!(!output.contains("gvm_sess_"));
}

/// Audit logs tie command failures back to session expiry without exposing raw tokens.
#[tokio::test]
async fn audit_logs_command_execution_and_session_expiry_events() {
    let _trace_lock = lock_tracing().await;
    let capture = capture_tracing();
    capture
        .run(async {
            let service = create_test_service();
            let session = service.create_session("admin", "secret").await.unwrap();
            service.session_manager().expire(&session.token).unwrap();

            let _ = service
                .list_targets(&session.token, TargetQuery::default())
                .await;
        })
        .await;

    let output = capture.output();
    assert!(output.contains("audit_event=\"command.execution\""));
    assert!(output.contains("audit_outcome=\"start\""));
    assert!(output.contains("audit_event=\"session.expired\""));
    assert!(output.contains("error_category=\"session_expired\""));
}

/// Mutating resource workflows emit audit events with safe session context only.
#[tokio::test]
async fn audit_logs_target_mutation_without_raw_session_token() {
    let _trace_lock = lock_tracing().await;
    let capture = capture_tracing();
    let session_token = capture
        .run(async {
            let service = create_test_service();
            let session = service
                .create_session("admin", "super-secret-password")
                .await
                .unwrap();

            let result = service
                .create_target(
                    &session.token,
                    CreateTargetInput {
                        name: "target-a".to_string(),
                        comment: None,
                        hosts: vec!["192.0.2.10".to_string()],
                        exclude_hosts: vec![],
                        alive_test: None,
                        port_list_id: None,
                        reverse_lookup_only: None,
                        reverse_lookup_unify: None,
                        ssh_credential_id: None,
                        smb_credential_id: None,
                        esxi_credential_id: None,
                        snmp_credential_id: None,
                    },
                )
                .await;
            assert!(result.is_ok());

            session.token
        })
        .await;

    let output = capture.output();
    assert!(output.contains("audit_event=\"command.execution\""));
    assert!(output.contains("audit_outcome=\"start\""));
    assert!(output.contains("audit_outcome=\"success\""));
    assert!(output.contains("resource=\"target\""));
    assert!(output.contains("action=\"create\""));
    assert!(output.contains("session_id=\"session:"));
    assert!(!output.contains(&session_token));
    assert!(!output.contains("super-secret-password"));
}

/// Report export audit logs use a dedicated action separate from ordinary reads.
#[tokio::test]
async fn audit_logs_report_export_with_export_action() {
    let _trace_lock = lock_tracing().await;
    let capture = capture_tracing();
    let session_token = capture
        .run(async {
            let service = create_test_service();
            let session = service.create_session("admin", "secret").await.unwrap();

            let _ = service
                .export_report(
                    &session.token,
                    "550e8400-e29b-41d4-a716-446655440000",
                    "123e4567-e89b-12d3-a456-426614174000",
                )
                .await;

            session.token
        })
        .await;

    let output = capture.output();
    assert!(output.contains("audit_event=\"command.execution\""));
    assert!(output.contains("resource=\"report_export\""));
    assert!(output.contains("action=\"export\""));
    assert!(!output.contains("action=\"read\""));
    assert!(!output.contains(&session_token));
}

/// Report import preserves opaque bytes and omission-sensitive options across
/// the authenticated application boundary without adding payload observability.
#[tokio::test]
async fn service_import_report_propagates_the_opaque_domain_request() {
    let sessions = Arc::new(SessionManager::default());
    let report_port = Arc::new(MockReportPort::default());
    let imported = Arc::clone(&report_port.imported);
    let mut ports = test_ports();
    ports.reports = report_port;
    let service = GatewayService::new(ports, Arc::clone(&sessions));
    let session = sessions.create("admin").unwrap();
    let input = ImportReportInput {
        task_id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        report_xml: b"<report><name>opaque-marker</name></report>".to_vec(),
        in_assets: Some(false),
    };

    let id = service
        .import_report(&session.token, input.clone())
        .await
        .expect("report import should reach its port");

    assert_eq!(id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(*imported.lock().unwrap(), Some(input));
}

/// Spans are emitted for both session lifecycle and resource command execution.
#[tokio::test]
async fn spans_are_emitted_for_session_and_command_lifecycle() {
    let _trace_lock = lock_tracing().await;
    let capture = capture_tracing();
    capture
        .run(async {
            let mut ports = test_ports();
            ports.targets = Arc::new(MockTargetPort { should_fail: true });
            let service = GatewayService::new(ports, Arc::new(SessionManager::default()));

            let session = service.create_session("admin", "secret").await.unwrap();
            let _ = service.get_target(&session.token, "resource-123").await;
            let _ = service.delete_session(&session.token).await;
        })
        .await;

    let output = capture.output();
    assert!(output.contains("session.create"));
    assert!(output.contains("command.execution"));
    assert!(output.contains("targets.get"));
    assert!(output.contains("session.teardown"));
}
