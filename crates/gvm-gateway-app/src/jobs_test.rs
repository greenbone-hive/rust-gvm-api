// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use gvm_gateway_domain::*;
use tokio::sync::Semaphore;

use crate::{
    test_support::{test_ports, MockAuthPort},
    GatewayService,
};

const REPORT_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const FORMAT_ID: &str = "123e4567-e89b-12d3-a456-426614174111";
const EXPORT_ID: &str = "123e4567-e89b-12d3-a456-426614174222";

#[derive(Default)]
struct LifecycleState {
    calls: Vec<&'static str>,
    states: VecDeque<BackendReportExportState>,
    create_error: bool,
    poll_failures_remaining: usize,
    poll_error: Option<GatewayError>,
    download_error: bool,
    cancel_error: bool,
    cancel_calls: usize,
    bytes: Vec<u8>,
}

struct LifecycleReportPort {
    state: Arc<Mutex<LifecycleState>>,
    create_gate: Option<Arc<Semaphore>>,
    download_gate: Option<Arc<Semaphore>>,
    cancel_gate: Option<Arc<Semaphore>>,
}

impl LifecycleReportPort {
    fn new(states: impl IntoIterator<Item = BackendReportExportState>) -> Self {
        Self {
            state: Arc::new(Mutex::new(LifecycleState {
                states: states.into_iter().collect(),
                bytes: b"ok".to_vec(),
                ..LifecycleState::default()
            })),
            create_gate: None,
            download_gate: None,
            cancel_gate: None,
        }
    }

    fn with_create_gate(mut self, gate: Arc<Semaphore>) -> Self {
        self.create_gate = Some(gate);
        self
    }

    fn with_download_gate(mut self, gate: Arc<Semaphore>) -> Self {
        self.download_gate = Some(gate);
        self
    }

    fn with_cancel_gate(mut self, gate: Arc<Semaphore>) -> Self {
        self.cancel_gate = Some(gate);
        self
    }
}

#[async_trait]
impl ReportPort for LifecycleReportPort {
    async fn import_report(&self, _: &str, _: ImportReportInput) -> Result<String, GatewayError> {
        Err(GatewayError::NotImplemented(
            "not used by job tests".to_string(),
        ))
    }

    async fn list_reports(&self, _: &str, query: &ReportQuery) -> Result<ReportPage, GatewayError> {
        Ok(ReportPage {
            data: vec![report(REPORT_ID)],
            pagination: pagination(query.page, query.per_page, 1),
        })
    }

    async fn get_report(
        &self,
        _: &str,
        id: &str,
        _: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        Ok(report(id))
    }

    async fn create_report_export(
        &self,
        _: &str,
        _: &str,
        _: &ReportExportRequest,
    ) -> Result<BackendReportExport, GatewayError> {
        self.state.lock().unwrap().calls.push("create");
        if let Some(gate) = &self.create_gate {
            gate.acquire().await.unwrap().forget();
        }
        if self.state.lock().unwrap().create_error {
            return Err(GatewayError::InvalidInput(
                "invalid export request".to_string(),
            ));
        }
        Ok(BackendReportExport {
            id: EXPORT_ID.to_string(),
        })
    }

    async fn get_report_export(
        &self,
        _: &str,
        _: &str,
    ) -> Result<BackendReportExportState, GatewayError> {
        let mut state = self.state.lock().unwrap();
        state.calls.push("poll");
        if state.poll_failures_remaining > 0 {
            state.poll_failures_remaining -= 1;
            return Err(state.poll_error.clone().unwrap_or_else(|| {
                GatewayError::BackendUnavailable("private poll failure".to_string())
            }));
        }
        if state.cancel_calls > 0 && !state.cancel_error {
            return Ok(BackendReportExportState::Cancelled);
        }
        Ok(state
            .states
            .pop_front()
            .unwrap_or(BackendReportExportState::Running))
    }

    async fn download_report_export(&self, _: &str, _: &str) -> Result<ReportExport, GatewayError> {
        self.state.lock().unwrap().calls.push("download");
        if let Some(gate) = &self.download_gate {
            gate.acquire().await.unwrap().forget();
        }
        let state = self.state.lock().unwrap();
        if state.download_error {
            return Err(GatewayError::BackendUnavailable(
                "download failed".to_string(),
            ));
        }
        Ok(ReportExport {
            bytes: state.bytes.clone(),
            content_type: Some("application/pdf".to_string()),
            extension: Some("pdf".to_string()),
        })
    }

    async fn cancel_report_export(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        {
            let mut state = self.state.lock().unwrap();
            state.calls.push("cancel");
            state.cancel_calls += 1;
        }
        if let Some(gate) = &self.cancel_gate {
            gate.acquire().await.unwrap().forget();
        }
        if self.state.lock().unwrap().cancel_error {
            Err(GatewayError::BackendUnavailable(
                "cleanup cancel failed".to_string(),
            ))
        } else {
            Ok(())
        }
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
        Ok(ResultPage {
            data: vec![],
            pagination: pagination(query.page, query.per_page, 0),
        })
    }

    async fn get_report_vulnerabilities(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportVulnerabilityPage, GatewayError> {
        Ok(ReportVulnerabilityPage {
            data: vec![],
            pagination: pagination(query.page, query.per_page, 0),
        })
    }

    async fn get_report_hosts(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportHostPage, GatewayError> {
        Ok(ReportHostPage {
            data: vec![],
            pagination: pagination(query.page, query.per_page, 0),
        })
    }

    async fn get_report_ports(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportPortPage, GatewayError> {
        Ok(ReportPortPage {
            data: vec![],
            pagination: pagination(query.page, query.per_page, 0),
        })
    }

    async fn get_report_applications(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportApplicationPage, GatewayError> {
        Ok(ReportApplicationPage {
            data: vec![],
            pagination: pagination(query.page, query.per_page, 0),
        })
    }

    async fn get_report_operating_systems(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportOperatingSystemPage, GatewayError> {
        Ok(ReportOperatingSystemPage {
            data: vec![],
            pagination: pagination(query.page, query.per_page, 0),
        })
    }

    async fn get_report_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportCvePage, GatewayError> {
        Ok(ReportCvePage {
            data: vec![],
            pagination: pagination(query.page, query.per_page, 0),
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
            pagination: pagination(query.page, query.per_page, 0),
        })
    }

    async fn get_report_errors(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportErrorPage, GatewayError> {
        Ok(ReportErrorPage {
            data: vec![],
            pagination: pagination(query.page, query.per_page, 0),
        })
    }

    async fn get_report_closed_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ReportClosedCvePage, GatewayError> {
        Ok(ReportClosedCvePage {
            data: vec![],
            pagination: pagination(query.page, query.per_page, 0),
        })
    }
}

fn service(port: Arc<LifecycleReportPort>) -> GatewayService {
    let mut ports = test_ports();
    ports.reports = port;
    let service = GatewayService::new(ports, Arc::new(SessionManager::default()));
    service.set_report_export_policy_for_tests(Duration::from_millis(1), Duration::from_secs(1));
    service
}

async fn start_job(service: &GatewayService, token: &str) -> ReportExportJob {
    service
        .create_report_export_job(
            token,
            REPORT_ID,
            CreateReportExportRequest::GvmdReportFormat(GvmdReportFormatExportRequest {
                report_format_id: FORMAT_ID.to_string(),
                report_config_id: None,
                filter: None,
                filter_id: None,
            }),
        )
        .await
        .expect("job should be accepted")
}

async fn wait_for_terminal(service: &GatewayService, token: &str, job_id: &str) -> ReportExportJob {
    for _ in 0..1_000 {
        let job = service.get_job(token, job_id).await.unwrap();
        if job.status.is_terminal() {
            return job;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("job did not become terminal")
}

async fn wait_for_call(state: &Mutex<LifecycleState>, call: &str) {
    for _ in 0..1_000 {
        if state.lock().unwrap().calls.contains(&call) {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("lifecycle call {call} was not observed")
}

fn report(id: &str) -> Report {
    Report {
        id: id.to_string(),
        task: None,
        scan_start: None,
        scan_end: None,
        severity: None,
        result_count: None,
        results: vec![],
    }
}

fn pagination(page: u32, per_page: u32, total: u32) -> Pagination {
    Pagination {
        page,
        per_page,
        total,
        total_pages: u32::from(total > 0),
    }
}

#[tokio::test]
async fn backend_lifecycle_success_downloads_the_artifact() {
    // Locks the create -> poll -> download happy path and internal backend-ID retention.
    let port = Arc::new(LifecycleReportPort::new([BackendReportExportState::Ready]));
    let service = service(Arc::clone(&port));
    let session = service.session_manager().create("admin").unwrap();
    let job = start_job(&service, &session.token).await;

    let terminal = wait_for_terminal(&service, &session.token, &job.id).await;

    assert_eq!(terminal.status, JobStatus::Succeeded);
    assert_eq!(
        service.backend_export_id_for_tests(&job.id).as_deref(),
        Some(EXPORT_ID)
    );
    assert_eq!(
        service
            .download_job_result(&session.token, &job.id)
            .await
            .unwrap()
            .bytes,
        b"ok"
    );
    assert_eq!(
        port.state.lock().unwrap().calls,
        ["create", "poll", "download"]
    );
}

#[tokio::test]
async fn backend_lifecycle_polls_pending_and_running_until_ready() {
    // Proves non-terminal upstream states are polled rather than downloaded early.
    let port = Arc::new(LifecycleReportPort::new([
        BackendReportExportState::Pending,
        BackendReportExportState::Running,
        BackendReportExportState::Ready,
    ]));
    let service = service(Arc::clone(&port));
    let session = service.session_manager().create("admin").unwrap();
    let job = start_job(&service, &session.token).await;

    assert_eq!(
        wait_for_terminal(&service, &session.token, &job.id)
            .await
            .status,
        JobStatus::Succeeded
    );
    assert_eq!(
        port.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| **call == "poll")
            .count(),
        3
    );
}

#[tokio::test]
async fn backend_create_failure_fails_without_cleanup_for_an_unknown_id() {
    // A create validation error has no safe backend identifier to cancel.
    let port = Arc::new(LifecycleReportPort::new([]));
    port.state.lock().unwrap().create_error = true;
    let service = service(Arc::clone(&port));
    let session = service.session_manager().create("admin").unwrap();
    let job = start_job(&service, &session.token).await;

    let terminal = wait_for_terminal(&service, &session.token, &job.id).await;

    assert_eq!(terminal.status, JobStatus::Failed);
    let error = terminal.error.unwrap();
    assert_eq!(error.code, "bad_request");
    assert_eq!(
        error.detail.as_deref(),
        Some("The backend rejected the report export request.")
    );
    assert!(!serde_json::to_string(&error)
        .unwrap()
        .contains("invalid export request"));
    assert_eq!(port.state.lock().unwrap().cancel_calls, 0);
}

#[tokio::test]
async fn backend_poll_failure_triggers_cleanup_and_preserves_the_poll_error() {
    // Any failure after create must cancel the known backend export first.
    let port = Arc::new(LifecycleReportPort::new([]));
    port.state.lock().unwrap().poll_failures_remaining = 1;
    let service = service(Arc::clone(&port));
    let session = service.session_manager().create("admin").unwrap();
    let job = start_job(&service, &session.token).await;

    let terminal = wait_for_terminal(&service, &session.token, &job.id).await;

    assert_eq!(terminal.status, JobStatus::Failed);
    let error = terminal.error.unwrap();
    assert_eq!(error.code, "backend_unavailable");
    assert_eq!(
        error.detail.as_deref(),
        Some("The backend service is unavailable.")
    );
    let public_error = serde_json::to_string(&error).unwrap();
    assert!(!public_error.contains("private poll failure"));
    assert!(!public_error.contains(EXPORT_ID));
    assert_eq!(port.state.lock().unwrap().cancel_calls, 1);
}

#[tokio::test]
async fn backend_download_failure_triggers_cleanup() {
    // Download readiness does not make a subsequent download failure leak the export.
    let port = Arc::new(LifecycleReportPort::new([BackendReportExportState::Ready]));
    port.state.lock().unwrap().download_error = true;
    let service = service(Arc::clone(&port));
    let session = service.session_manager().create("admin").unwrap();
    let job = start_job(&service, &session.token).await;

    let terminal = wait_for_terminal(&service, &session.token, &job.id).await;

    assert_eq!(terminal.status, JobStatus::Failed);
    let error = terminal.error.unwrap();
    assert_eq!(error.code, "backend_unavailable");
    assert_eq!(
        error.detail.as_deref(),
        Some("The backend service is unavailable.")
    );
    assert!(!serde_json::to_string(&error)
        .unwrap()
        .contains("download failed"));
    assert_eq!(port.state.lock().unwrap().cancel_calls, 1);
}

#[tokio::test]
async fn cancellation_before_backend_id_registration_cleans_up_after_create_returns() {
    // Forces DELETE to win while create is in flight, before the backend ID is known.
    let gate = Arc::new(Semaphore::new(0));
    let port = Arc::new(LifecycleReportPort::new([]).with_create_gate(Arc::clone(&gate)));
    let service = service(Arc::clone(&port));
    let session = service.session_manager().create("admin").unwrap();
    let job = start_job(&service, &session.token).await;
    wait_for_call(&port.state, "create").await;

    service.cancel_job(&session.token, &job.id).await.unwrap();
    assert!(service.backend_export_id_for_tests(&job.id).is_none());
    gate.add_permits(1);

    assert_eq!(
        wait_for_terminal(&service, &session.token, &job.id)
            .await
            .status,
        JobStatus::Cancelled
    );
    assert_eq!(port.state.lock().unwrap().cancel_calls, 1);
}

#[tokio::test]
async fn cancellation_after_backend_id_registration_wakes_polling_and_cleans_up() {
    // A known pending export is cancelled by the worker without aborting that worker.
    let port = Arc::new(LifecycleReportPort::new([
        BackendReportExportState::Pending,
    ]));
    let service = service(Arc::clone(&port));
    let session = service.session_manager().create("admin").unwrap();
    let job = start_job(&service, &session.token).await;
    wait_for_call(&port.state, "poll").await;

    service.cancel_job(&session.token, &job.id).await.unwrap();

    assert_eq!(
        wait_for_terminal(&service, &session.token, &job.id)
            .await
            .status,
        JobStatus::Cancelled
    );
    assert_eq!(port.state.lock().unwrap().cancel_calls, 1);
}

#[tokio::test]
async fn running_jobs_are_not_purged_even_with_zero_terminal_retention() {
    // Retention starts only after a terminal commit; an in-flight worker must
    // remain addressable so cancellation and session teardown can find it.
    let gate = Arc::new(Semaphore::new(0));
    let port = Arc::new(LifecycleReportPort::new([]).with_create_gate(Arc::clone(&gate)));
    let service = service(Arc::clone(&port));
    service.set_job_policy_for_tests(10, 0);
    let session = service.session_manager().create("admin").unwrap();
    let job = start_job(&service, &session.token).await;
    wait_for_call(&port.state, "create").await;

    service.job_reaper().sweep_once_for_test().await;

    assert_eq!(service.retained_job_count_for_tests(), 1);
    assert_eq!(
        service
            .get_job(&session.token, &job.id)
            .await
            .unwrap()
            .status,
        JobStatus::Running
    );

    service.set_job_policy_for_tests(10, 900);
    service.cancel_job(&session.token, &job.id).await.unwrap();
    gate.add_permits(1);
    assert_eq!(
        wait_for_terminal(&service, &session.token, &job.id)
            .await
            .status,
        JobStatus::Cancelled
    );
}

#[tokio::test]
async fn completion_and_cancellation_race_commits_only_cancelled() {
    // Cancellation during download wins the single terminal commit and discards bytes.
    let gate = Arc::new(Semaphore::new(0));
    let port = Arc::new(
        LifecycleReportPort::new([BackendReportExportState::Ready])
            .with_download_gate(Arc::clone(&gate)),
    );
    let service = service(Arc::clone(&port));
    let session = service.session_manager().create("admin").unwrap();
    let job = start_job(&service, &session.token).await;
    wait_for_call(&port.state, "download").await;

    service.cancel_job(&session.token, &job.id).await.unwrap();
    gate.add_permits(1);

    assert_eq!(
        wait_for_terminal(&service, &session.token, &job.id)
            .await
            .status,
        JobStatus::Cancelled
    );
    assert!(matches!(
        service.download_job_result(&session.token, &job.id).await,
        Err(GatewayError::Conflict(_))
    ));
}

#[tokio::test]
async fn session_deletion_waits_for_backend_cancellation_before_disconnect() {
    // Session teardown must not remove the connection while its export cleanup is pending.
    let cancel_gate = Arc::new(Semaphore::new(0));
    let port = Arc::new(
        LifecycleReportPort::new([BackendReportExportState::Pending])
            .with_cancel_gate(Arc::clone(&cancel_gate)),
    );
    let auth = Arc::new(MockAuthPort::default());
    let disconnected = Arc::clone(&auth.disconnected);
    let mut ports = test_ports();
    ports.reports = port.clone();
    ports.auth = auth;
    let service = GatewayService::new(ports, Arc::new(SessionManager::default()));
    service.set_report_export_policy_for_tests(Duration::from_millis(1), Duration::from_secs(1));
    let session = service.session_manager().create("admin").unwrap();
    let job = start_job(&service, &session.token).await;
    wait_for_call(&port.state, "poll").await;

    let deletion_service = service.clone();
    let deleted_token = session.token.clone();
    let deletion =
        tokio::spawn(async move { deletion_service.delete_session(&deleted_token).await });
    wait_for_call(&port.state, "cancel").await;
    assert!(disconnected.lock().unwrap().is_empty());
    assert!(!deletion.is_finished());

    cancel_gate.add_permits(1);
    deletion.await.unwrap().unwrap();
    assert_eq!(disconnected.lock().unwrap().len(), 1);
    let replacement = service.session_manager().create("admin").unwrap();
    let terminal = service.get_job(&replacement.token, &job.id).await.unwrap();

    assert_eq!(terminal.status, JobStatus::Cancelled);
    assert_eq!(port.state.lock().unwrap().cancel_calls, 1);
}

#[tokio::test]
async fn cancel_failure_preserves_the_primary_error_and_consumes_a_ready_export() {
    // A cancel race with backend completion must consume the ready artifact so
    // no backend export is orphaned, without replacing the primary failure.
    let port = Arc::new(LifecycleReportPort::new([BackendReportExportState::Ready]));
    {
        let mut state = port.state.lock().unwrap();
        state.poll_failures_remaining = 1;
        state.poll_error = Some(GatewayError::GatewayTimeout(
            "private primary poll timeout".to_string(),
        ));
        state.cancel_error = true;
    }
    let service = service(Arc::clone(&port));
    let session = service.session_manager().create("admin").unwrap();
    let job = start_job(&service, &session.token).await;

    let terminal = wait_for_terminal(&service, &session.token, &job.id).await;

    assert_eq!(terminal.status, JobStatus::Failed);
    let error = terminal.error.unwrap();
    assert_eq!(error.code, "gateway_timeout");
    assert_eq!(
        error.detail.as_deref(),
        Some("The report export did not complete before the gateway timeout.")
    );
    let public_error = serde_json::to_string(&error).unwrap();
    assert!(!public_error.contains("private primary poll timeout"));
    assert!(!public_error.contains("cleanup cancel failed"));
    let state = port.state.lock().unwrap();
    assert_eq!(state.cancel_calls, 1);
    assert_eq!(
        state.calls,
        ["create", "poll", "cancel", "poll", "download"]
    );
}
