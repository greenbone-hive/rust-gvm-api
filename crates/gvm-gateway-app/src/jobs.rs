// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Asynchronous job use cases.

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use gvm_gateway_domain::{
    BackendReportExportState, CreateReportExportRequest, GatewayError, GetReportOpts, JobArtifact,
    JobCancelOutcome, JobProblem, JobProgress, JobResult, JobStatus, ReportExportFormat,
    ReportExportJob, ReportExportRequest, ReportJsonExport, ResourceRef, ResultQuery, Session,
    SessionHold, SessionTokenDigest,
};
use tokio::{sync::Notify, task::JoinHandle, time::Instant};
use uuid::Uuid;

use crate::GatewayService;

const JOB_KIND_REPORT_EXPORT: &str = "report_export";
const JSON_EXPORT_PAGE_SIZE: u32 = 1000;
const DEFAULT_MAX_JOBS_TOTAL: usize = 1000;
const DEFAULT_TERMINAL_JOB_RETENTION_SECS: u64 = 15 * 60;
const DEFAULT_JOB_REAPER_INTERVAL_SECS: u64 = 60;
const DEFAULT_REPORT_EXPORT_POLL_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_REPORT_EXPORT_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_REPORT_EXPORT_RECONCILIATION_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct JobRegistry {
    state: Mutex<JobRegistryState>,
}

struct JobRegistryState {
    jobs: HashMap<String, JobRecord>,
    policy: JobPolicy,
}

#[derive(Clone, Copy)]
struct JobPolicy {
    max_jobs_total: usize,
    terminal_retention_secs: u64,
    report_export_poll_interval: Duration,
    report_export_timeout: Duration,
}

struct JobRecord {
    owner_user: String,
    session_token_digest: SessionTokenDigest,
    job: ReportExportJob,
    artifact: Option<JobArtifact>,
    backend_export_id: Option<String>,
    cancellation_requested: bool,
    worker_finished: bool,
    state_changed: Arc<Notify>,
    worker_handle: Option<JoinHandle<()>>,
    purge_after_epoch_secs: Option<u64>,
}

struct JobWorkerCompletion {
    service: GatewayService,
    job_id: String,
}

impl Drop for JobWorkerCompletion {
    fn drop(&mut self) {
        self.service.mark_job_worker_finished(&self.job_id);
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self {
            state: Mutex::new(JobRegistryState {
                jobs: HashMap::new(),
                policy: JobPolicy::default(),
            }),
        }
    }
}

impl Default for JobPolicy {
    fn default() -> Self {
        Self {
            max_jobs_total: DEFAULT_MAX_JOBS_TOTAL,
            terminal_retention_secs: DEFAULT_TERMINAL_JOB_RETENTION_SECS,
            report_export_poll_interval: DEFAULT_REPORT_EXPORT_POLL_INTERVAL,
            report_export_timeout: DEFAULT_REPORT_EXPORT_TIMEOUT,
        }
    }
}

impl GatewayService {
    /// Creates a background reaper for expired asynchronous jobs.
    pub fn job_reaper(&self) -> JobReaper {
        JobReaper::new(Arc::clone(&self.jobs))
    }

    /// Starts an asynchronous report export job.
    pub async fn create_report_export_job(
        &self,
        session_token: &str,
        report_id: &str,
        request: CreateReportExportRequest,
    ) -> Result<ReportExportJob, GatewayError> {
        let report_id = report_id.to_string();
        let audit_report_id = report_id.clone();
        let service = self.clone();
        self.execute_with_resource(
            "reports.exports.create",
            session_token,
            "create",
            "report_export",
            Some(&audit_report_id),
            move |session| async move {
                service
                    .enqueue_report_export_job(session, report_id, request)
                    .await
            },
        )
        .await
    }

    /// Gets the status of an asynchronous job.
    pub async fn get_job(
        &self,
        session_token: &str,
        job_id: &str,
    ) -> Result<ReportExportJob, GatewayError> {
        let job_id = job_id.to_string();
        let audit_job_id = job_id.clone();
        let service = self.clone();
        self.execute_with_resource(
            "jobs.get",
            session_token,
            "read",
            "job",
            Some(&audit_job_id),
            move |session| async move { service.job_snapshot(&session.user, &job_id) },
        )
        .await
    }

    /// Requests cancellation of an asynchronous job.
    pub async fn cancel_job(
        &self,
        session_token: &str,
        job_id: &str,
    ) -> Result<JobCancelOutcome, GatewayError> {
        let job_id = job_id.to_string();
        let audit_job_id = job_id.clone();
        let service = self.clone();
        self.execute_with_resource(
            "jobs.cancel",
            session_token,
            "cancel",
            "job",
            Some(&audit_job_id),
            move |session| async move { service.cancel_job_record(&session.user, &job_id) },
        )
        .await
    }

    /// Downloads a completed asynchronous job result.
    pub async fn download_job_result(
        &self,
        session_token: &str,
        job_id: &str,
    ) -> Result<JobArtifact, GatewayError> {
        let job_id = job_id.to_string();
        let audit_job_id = job_id.clone();
        let service = self.clone();
        self.execute_with_resource(
            "jobs.result.download",
            session_token,
            "read",
            "job_result",
            Some(&audit_job_id),
            move |session| async move { service.job_artifact(&session.user, &job_id) },
        )
        .await
    }

    async fn enqueue_report_export_job(
        &self,
        session: Session,
        report_id: String,
        request: CreateReportExportRequest,
    ) -> Result<ReportExportJob, GatewayError> {
        self.reports
            .get_report(
                &session.token,
                &report_id,
                &GetReportOpts {
                    page: 1,
                    per_page: 1,
                },
            )
            .await?;

        let job_id = Uuid::new_v4().to_string();
        let job = report_export_job(&job_id, &report_id, &request);
        let session_hold = self.sessions.hold(&session.token)?;
        let session_token_digest = SessionTokenDigest::from_token(&session.token);
        let state_changed = Arc::new(Notify::new());
        self.insert_job(
            session.user,
            session_token_digest,
            job.clone(),
            Arc::clone(&state_changed),
        )?;

        let worker = self.clone();
        let worker_job_id = job_id.clone();
        let worker_report_id = report_id.clone();
        let worker_request = request.clone();
        let session_token = session.token;
        let completion = JobWorkerCompletion {
            service: worker.clone(),
            job_id: worker_job_id.clone(),
        };
        let handle = tokio::spawn(async move {
            let _completion = completion;
            worker
                .run_report_export_job(
                    worker_job_id,
                    session_token,
                    session_hold,
                    worker_report_id,
                    worker_request,
                    state_changed,
                )
                .await;
        });
        self.set_job_worker_handle(&job_id, handle)?;

        Ok(job)
    }

    async fn run_report_export_job(
        &self,
        job_id: String,
        session_token: String,
        _session_hold: SessionHold,
        report_id: String,
        request: CreateReportExportRequest,
        state_changed: Arc<Notify>,
    ) {
        if self.mark_job_running(&job_id).is_err() {
            if self.job_cancellation_requested(&job_id).unwrap_or(false) {
                let _ = self.mark_job_cancelled(&job_id);
            }
            return;
        }

        let result = match request {
            CreateReportExportRequest::GvmdReportFormat(request) => {
                let request = ReportExportRequest {
                    report_format_id: request.report_format_id,
                    report_config_id: request.report_config_id,
                    filter: request.filter,
                    filter_id: request.filter_id,
                };
                self.run_backend_report_export(
                    &job_id,
                    &session_token,
                    &report_id,
                    &request,
                    &state_changed,
                )
                .await
            }
            CreateReportExportRequest::Json(request) => {
                self.export_report_json(
                    &session_token,
                    &report_id,
                    request.filter,
                    request.filter_id,
                )
                .await
            }
        };

        match result {
            Ok(artifact) => {
                let _ = self.mark_job_succeeded(&job_id, artifact);
            }
            Err(error) => {
                if !self.job_cancellation_requested(&job_id).unwrap_or(true) {
                    let _ = self.mark_job_failed(&job_id, error);
                } else {
                    let _ = self.mark_job_cancelled(&job_id);
                }
            }
        }
    }

    async fn run_backend_report_export(
        &self,
        job_id: &str,
        session_token: &str,
        report_id: &str,
        request: &ReportExportRequest,
        state_changed: &Notify,
    ) -> Result<JobArtifact, GatewayError> {
        let (poll_interval, timeout) = self.report_export_policy()?;
        let deadline = Instant::now() + timeout;
        let created = await_report_export_operation(
            deadline,
            self.reports
                .create_report_export(session_token, report_id, request),
        )
        .await?;
        let export_id = created.id;
        let result = async {
            if self.register_backend_export_id(job_id, &export_id)? {
                return Err(GatewayError::Conflict(
                    "report export job was cancelled".to_string(),
                ));
            }

            loop {
                let cancellation_notified = state_changed.notified();
                if self.job_cancellation_requested(job_id)? {
                    return Err(report_export_cancelled_error());
                }

                let state = tokio::select! {
                    result = await_report_export_operation(
                        deadline,
                        self.reports.get_report_export(session_token, &export_id),
                    ) => result?,
                    () = cancellation_notified => continue,
                };
                match state {
                    BackendReportExportState::Ready => break,
                    BackendReportExportState::Failed => {
                        return Err(GatewayError::BackendUnavailable(
                            "backend report export failed".to_string(),
                        ));
                    }
                    BackendReportExportState::Cancelled => {
                        return Err(GatewayError::Conflict(
                            "backend report export was cancelled".to_string(),
                        ));
                    }
                    BackendReportExportState::Pending
                    | BackendReportExportState::Running
                    | BackendReportExportState::CancelRequested => {
                        let cancellation_notified = state_changed.notified();
                        if self.job_cancellation_requested(job_id)? {
                            continue;
                        }
                        let wake_at = deadline.min(Instant::now() + poll_interval);
                        tokio::select! {
                            () = tokio::time::sleep_until(wake_at) => {}
                            () = cancellation_notified => {}
                        }
                    }
                }
            }

            let cancellation_notified = state_changed.notified();
            if self.job_cancellation_requested(job_id)? {
                return Err(report_export_cancelled_error());
            }

            let export = tokio::select! {
                result = await_report_export_operation(
                    deadline,
                    self.reports.download_report_export(session_token, &export_id),
                ) => result?,
                () = cancellation_notified => return Err(report_export_cancelled_error()),
            };
            let extension = export.extension.unwrap_or_else(|| "bin".to_string());
            Ok(JobArtifact {
                bytes: export.bytes,
                content_type: export
                    .content_type
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                filename: format!("report-{report_id}.{extension}"),
            })
        }
        .await;

        if let Err(primary) = &result {
            self.reconcile_backend_export_best_effort(
                session_token,
                &export_id,
                timeout.min(MAX_REPORT_EXPORT_RECONCILIATION_TIMEOUT),
                primary,
            )
            .await;
        }
        result
    }

    async fn reconcile_backend_export_best_effort(
        &self,
        session_token: &str,
        export_id: &str,
        timeout: Duration,
        primary: &GatewayError,
    ) {
        let poll_interval = self
            .report_export_policy()
            .map(|(poll_interval, _)| poll_interval)
            .unwrap_or(DEFAULT_REPORT_EXPORT_POLL_INTERVAL);
        let deadline = Instant::now() + timeout;
        let state = match await_report_export_operation(
            deadline,
            self.reports.get_report_export(session_token, export_id),
        )
        .await
        {
            Ok(state) => state,
            Err(GatewayError::NotFound(_)) => return,
            Err(reconciliation_error) => {
                tracing::warn!(
                    primary_error_code = primary.code().as_str(),
                    reconciliation_error_code = reconciliation_error.code().as_str(),
                    "report export backend reconciliation polling failed"
                );
                return;
            }
        };

        match state {
            BackendReportExportState::Ready
            | BackendReportExportState::Failed
            | BackendReportExportState::Cancelled => return,
            BackendReportExportState::Pending | BackendReportExportState::Running => {
                if let Err(reconciliation_error) = await_report_export_operation(
                    deadline,
                    self.reports.cancel_report_export(session_token, export_id),
                )
                .await
                {
                    tracing::warn!(
                        primary_error_code = primary.code().as_str(),
                        reconciliation_error_code = reconciliation_error.code().as_str(),
                        "active report export backend cancellation failed"
                    );
                }
            }
            BackendReportExportState::CancelRequested => {}
        }

        loop {
            let state = match await_report_export_operation(
                deadline,
                self.reports.get_report_export(session_token, export_id),
            )
            .await
            {
                Ok(state) => state,
                Err(GatewayError::NotFound(_)) => return,
                Err(reconciliation_error) => {
                    tracing::warn!(
                        primary_error_code = primary.code().as_str(),
                        reconciliation_error_code = reconciliation_error.code().as_str(),
                        "report export backend reconciliation polling failed"
                    );
                    return;
                }
            };
            match state {
                BackendReportExportState::Ready
                | BackendReportExportState::Failed
                | BackendReportExportState::Cancelled => return,
                BackendReportExportState::Pending
                | BackendReportExportState::Running
                | BackendReportExportState::CancelRequested => {
                    let wake_at = deadline.min(Instant::now() + poll_interval);
                    tokio::time::sleep_until(wake_at).await;
                }
            }
        }
    }

    async fn export_report_json(
        &self,
        session_token: &str,
        report_id: &str,
        filter_string: Option<String>,
        filter_id: Option<String>,
    ) -> Result<JobArtifact, GatewayError> {
        let mut report = self
            .reports
            .get_report(
                session_token,
                report_id,
                &GetReportOpts {
                    page: 1,
                    per_page: 1,
                },
            )
            .await?;
        report.results.clear();

        let mut page = 1;
        let mut results = Vec::new();
        loop {
            let result_page = self
                .reports
                .get_report_results(
                    session_token,
                    report_id,
                    &ResultQuery {
                        filter_string: filter_string.clone(),
                        filter_id: filter_id.clone(),
                        page,
                        per_page: JSON_EXPORT_PAGE_SIZE,
                    },
                )
                .await?;

            let total_pages = result_page.pagination.total_pages;
            let item_count = result_page.data.len();
            results.extend(result_page.data);

            if item_count == 0 || page >= total_pages {
                break;
            }
            page += 1;
        }

        let export = ReportJsonExport {
            report,
            results,
            generated_at: Some(now_rfc3339()),
        };
        let bytes = serde_json::to_vec(&export).map_err(|err| {
            GatewayError::Internal(format!("failed to serialize JSON report export: {err}"))
        })?;

        Ok(JobArtifact {
            bytes,
            content_type: "application/json".to_string(),
            filename: format!("report-{report_id}.json"),
        })
    }

    fn insert_job(
        &self,
        owner_user: String,
        session_token_digest: SessionTokenDigest,
        job: ReportExportJob,
        state_changed: Arc<Notify>,
    ) -> Result<(), GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let now = now_epoch_secs();
        purge_expired_jobs(&mut state, now);
        if state.jobs.len() >= state.policy.max_jobs_total {
            return Err(GatewayError::TooManyRequests(format!(
                "job capacity exceeded; at most {} jobs are retained",
                state.policy.max_jobs_total
            )));
        }
        state.jobs.insert(
            job.id.clone(),
            JobRecord {
                owner_user,
                session_token_digest,
                job,
                artifact: None,
                backend_export_id: None,
                cancellation_requested: false,
                worker_finished: false,
                state_changed,
                worker_handle: None,
                purge_after_epoch_secs: None,
            },
        );
        Ok(())
    }

    fn set_job_worker_handle(
        &self,
        job_id: &str,
        worker_handle: JoinHandle<()>,
    ) -> Result<(), GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        record.worker_handle = Some(worker_handle);
        Ok(())
    }

    fn mark_job_running(&self, job_id: &str) -> Result<(), GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        if record.cancellation_requested || record.job.status.is_terminal() {
            return Err(GatewayError::Conflict(format!(
                "job {job_id} was cancelled"
            )));
        }
        record.job.status = JobStatus::Running;
        record.job.started_at = Some(now_rfc3339());
        record.job.progress = Some(JobProgress {
            percent: Some(0),
            message: Some("running".to_string()),
        });
        Ok(())
    }

    fn mark_job_succeeded(&self, job_id: &str, artifact: JobArtifact) -> Result<(), GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let now = now_epoch_secs();
        let retention_secs = state.policy.terminal_retention_secs;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        if record.job.status.is_terminal() {
            return Ok(());
        }
        if record.cancellation_requested {
            cancel_job_record_in_place(record, now, retention_secs);
            let state_changed = Arc::clone(&record.state_changed);
            drop(state);
            state_changed.notify_waiters();
            return Ok(());
        }
        let result_location = format!("/api/v1/jobs/{job_id}/result");
        record.job.status = JobStatus::Succeeded;
        record.job.completed_at = Some(format_epoch_secs(now));
        record.job.expires_at = Some(format_epoch_secs(now + retention_secs));
        record.job.result_location = Some(result_location.clone());
        record.job.progress = Some(JobProgress {
            percent: Some(100),
            message: Some("succeeded".to_string()),
        });
        record.job.result = Some(JobResult {
            content_type: Some(artifact.content_type.clone()),
            filename: Some(artifact.filename.clone()),
            size: Some(artifact.bytes.len() as u64),
            location: Some(result_location),
        });
        record.artifact = Some(artifact);
        record.purge_after_epoch_secs = Some(now + retention_secs);
        let state_changed = Arc::clone(&record.state_changed);
        drop(state);
        state_changed.notify_waiters();
        Ok(())
    }

    fn mark_job_failed(&self, job_id: &str, error: GatewayError) -> Result<(), GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let now = now_epoch_secs();
        let retention_secs = state.policy.terminal_retention_secs;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        if record.job.status.is_terminal() {
            return Ok(());
        }
        if record.cancellation_requested {
            cancel_job_record_in_place(record, now, retention_secs);
            let state_changed = Arc::clone(&record.state_changed);
            drop(state);
            state_changed.notify_waiters();
            return Ok(());
        }
        record.job.status = JobStatus::Failed;
        record.job.completed_at = Some(format_epoch_secs(now));
        record.job.expires_at = Some(format_epoch_secs(now + retention_secs));
        record.job.progress = Some(JobProgress {
            percent: Some(100),
            message: Some("failed".to_string()),
        });
        record.job.error = Some(report_export_job_problem(&error));
        record.purge_after_epoch_secs = Some(now + retention_secs);
        let state_changed = Arc::clone(&record.state_changed);
        drop(state);
        state_changed.notify_waiters();
        Ok(())
    }

    fn mark_job_cancelled(&self, job_id: &str) -> Result<(), GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let now = now_epoch_secs();
        let retention_secs = state.policy.terminal_retention_secs;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        if record.job.status.is_terminal() {
            return Ok(());
        }
        cancel_job_record_in_place(record, now, retention_secs);
        let state_changed = Arc::clone(&record.state_changed);
        drop(state);
        state_changed.notify_waiters();
        Ok(())
    }

    fn job_snapshot(
        &self,
        owner_user: &str,
        job_id: &str,
    ) -> Result<ReportExportJob, GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        purge_expired_jobs(&mut state, now_epoch_secs());
        let record = state
            .jobs
            .get(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        ensure_job_owner(record, owner_user, job_id)?;
        Ok(record.job.clone())
    }

    fn cancel_job_record(
        &self,
        owner_user: &str,
        job_id: &str,
    ) -> Result<JobCancelOutcome, GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        purge_expired_jobs(&mut state, now_epoch_secs());
        let retention_secs = state.policy.terminal_retention_secs;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        ensure_job_owner(record, owner_user, job_id)?;

        if record.job.status.is_terminal() {
            return Ok(JobCancelOutcome::AlreadyTerminal);
        }

        record.cancellation_requested = true;
        if record.job.format == ReportExportFormat::Json {
            if let Some(worker_handle) = &record.worker_handle {
                worker_handle.abort();
            }
            let now = now_epoch_secs();
            cancel_job_record_in_place(record, now, retention_secs);
        } else {
            record.job.status = JobStatus::Cancelling;
            record.job.progress = Some(JobProgress {
                percent: None,
                message: Some("cancelling".to_string()),
            });
        }
        let state_changed = Arc::clone(&record.state_changed);
        drop(state);
        state_changed.notify_waiters();

        Ok(JobCancelOutcome::CancellationRequested)
    }

    pub(crate) async fn cancel_jobs_for_session(
        &self,
        session_token_digest: &SessionTokenDigest,
    ) -> Result<usize, GatewayError> {
        let (workers, cancelled) = {
            let mut state =
                self.jobs.state.lock().map_err(|_| {
                    GatewayError::Internal("job registry lock poisoned".to_string())
                })?;
            purge_expired_jobs(&mut state, now_epoch_secs());
            let mut workers = Vec::new();
            let mut cancelled = 0;
            let now = now_epoch_secs();
            let retention_secs = state.policy.terminal_retention_secs;

            for (job_id, record) in &mut state.jobs {
                if record.session_token_digest != *session_token_digest {
                    continue;
                }
                if !record.job.status.is_terminal() {
                    record.cancellation_requested = true;
                    if record.job.format == ReportExportFormat::Json {
                        if let Some(worker_handle) = &record.worker_handle {
                            worker_handle.abort();
                        }
                        cancel_job_record_in_place(record, now, retention_secs);
                    } else {
                        record.job.status = JobStatus::Cancelling;
                        record.job.progress = Some(JobProgress {
                            percent: None,
                            message: Some("cancelling".to_string()),
                        });
                    }
                    cancelled += 1;
                }
                if !record.worker_finished {
                    workers.push((job_id.clone(), Arc::clone(&record.state_changed)));
                }
            }
            (workers, cancelled)
        };
        for (_, state_changed) in &workers {
            state_changed.notify_waiters();
        }
        for (job_id, state_changed) in workers {
            self.wait_for_job_worker(&job_id, &state_changed).await?;
        }

        Ok(cancelled)
    }

    fn job_artifact(&self, owner_user: &str, job_id: &str) -> Result<JobArtifact, GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        purge_expired_jobs(&mut state, now_epoch_secs());
        let record = state
            .jobs
            .get(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        ensure_job_owner(record, owner_user, job_id)?;

        if record.job.status != JobStatus::Succeeded {
            return Err(GatewayError::Conflict(format!(
                "job {job_id} has not produced a downloadable result"
            )));
        }

        record
            .artifact
            .clone()
            .ok_or_else(|| GatewayError::Internal(format!("job {job_id} artifact is missing")))
    }

    #[cfg(test)]
    pub(crate) fn set_job_policy_for_tests(
        &self,
        max_jobs_total: usize,
        terminal_retention_secs: u64,
    ) {
        let mut state = self.jobs.state.lock().unwrap();
        state.policy.max_jobs_total = max_jobs_total;
        state.policy.terminal_retention_secs = terminal_retention_secs;
    }

    #[cfg(test)]
    pub(crate) fn retained_job_count_for_tests(&self) -> usize {
        self.jobs.state.lock().unwrap().jobs.len()
    }

    async fn wait_for_job_worker(
        &self,
        job_id: &str,
        state_changed: &Notify,
    ) -> Result<(), GatewayError> {
        loop {
            let notified = state_changed.notified();
            let finished = {
                let state = self.jobs.state.lock().map_err(|_| {
                    GatewayError::Internal("job registry lock poisoned".to_string())
                })?;
                state
                    .jobs
                    .get(job_id)
                    .is_none_or(|record| record.worker_finished)
            };
            if finished {
                return Ok(());
            }
            notified.await;
        }
    }

    fn register_backend_export_id(
        &self,
        job_id: &str,
        export_id: &str,
    ) -> Result<bool, GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        record.backend_export_id = Some(export_id.to_string());
        Ok(record.cancellation_requested)
    }

    fn mark_job_worker_finished(&self, job_id: &str) {
        let state_changed = self.jobs.state.lock().ok().and_then(|mut state| {
            let record = state.jobs.get_mut(job_id)?;
            record.worker_finished = true;
            Some(Arc::clone(&record.state_changed))
        });
        if let Some(state_changed) = state_changed {
            state_changed.notify_waiters();
        }
    }

    fn job_cancellation_requested(&self, job_id: &str) -> Result<bool, GatewayError> {
        let state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let record = state
            .jobs
            .get(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        Ok(record.cancellation_requested)
    }

    fn report_export_policy(&self) -> Result<(Duration, Duration), GatewayError> {
        let state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        Ok((
            state.policy.report_export_poll_interval,
            state.policy.report_export_timeout,
        ))
    }

    #[cfg(test)]
    pub(crate) fn set_report_export_policy_for_tests(
        &self,
        poll_interval: Duration,
        timeout: Duration,
    ) {
        let mut state = self.jobs.state.lock().unwrap();
        state.policy.report_export_poll_interval = poll_interval;
        state.policy.report_export_timeout = timeout;
    }

    #[cfg(test)]
    pub(crate) fn backend_export_id_for_tests(&self, job_id: &str) -> Option<String> {
        self.jobs
            .state
            .lock()
            .unwrap()
            .jobs
            .get(job_id)
            .and_then(|record| record.backend_export_id.clone())
    }
}

fn cancel_job_record_in_place(record: &mut JobRecord, now: u64, retention_secs: u64) {
    record.cancellation_requested = true;
    record.job.status = JobStatus::Cancelled;
    record.job.completed_at = Some(format_epoch_secs(now));
    record.job.expires_at = Some(format_epoch_secs(now + retention_secs));
    record.job.progress = Some(JobProgress {
        percent: Some(100),
        message: Some("cancelled".to_string()),
    });
    record.artifact = None;
    record.purge_after_epoch_secs = Some(now + retention_secs);
}

/// Background task that periodically removes expired asynchronous jobs.
pub struct JobReaper {
    jobs: Arc<JobRegistry>,
}

impl JobReaper {
    /// Creates a new job reaper for the given registry.
    pub(crate) fn new(jobs: Arc<JobRegistry>) -> Self {
        Self { jobs }
    }

    /// Spawns the reaper with the default sweep interval.
    pub fn spawn(&self) -> JoinHandle<()> {
        self.spawn_with_interval(Duration::from_secs(DEFAULT_JOB_REAPER_INTERVAL_SECS))
    }

    /// Spawns the reaper with an explicit sweep interval.
    pub fn spawn_with_interval(&self, interval: Duration) -> JoinHandle<()> {
        let jobs = Arc::clone(&self.jobs);
        tokio::spawn(Self::run(jobs, interval))
    }

    async fn run(jobs: Arc<JobRegistry>, interval: Duration) {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            Self::sweep_once(Arc::clone(&jobs));
        }
    }

    fn sweep_once(jobs: Arc<JobRegistry>) {
        match jobs.sweep_expired_jobs() {
            Ok(0) => {}
            Ok(count) => {
                tracing::info!(count, "job reaper: removed expired jobs");
            }
            Err(err) => {
                tracing::warn!(?err, "job reaper: sweep failed");
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn sweep_once_for_test(&self) {
        Self::sweep_once(Arc::clone(&self.jobs));
    }
}

impl JobRegistry {
    fn sweep_expired_jobs(&self) -> Result<usize, GatewayError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        Ok(purge_expired_jobs(&mut state, now_epoch_secs()))
    }
}

fn report_export_job(
    job_id: &str,
    report_id: &str,
    request: &CreateReportExportRequest,
) -> ReportExportJob {
    let (format, report_format_id) = match request {
        CreateReportExportRequest::GvmdReportFormat(request) => (
            ReportExportFormat::GvmdReportFormat,
            Some(request.report_format_id.clone()),
        ),
        CreateReportExportRequest::Json(_) => (ReportExportFormat::Json, None),
    };

    ReportExportJob {
        id: job_id.to_string(),
        kind: JOB_KIND_REPORT_EXPORT.to_string(),
        status: JobStatus::Queued,
        progress: Some(JobProgress {
            percent: Some(0),
            message: Some("queued".to_string()),
        }),
        created_at: now_rfc3339(),
        started_at: None,
        completed_at: None,
        expires_at: None,
        result_location: None,
        error: None,
        report: ResourceRef {
            id: report_id.to_string(),
            name: None,
        },
        format,
        report_format_id,
        result: None,
    }
}

fn now_rfc3339() -> String {
    format_epoch_secs(now_epoch_secs())
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_epoch_secs(epoch_secs: u64) -> String {
    gvm_gateway_domain::format_rfc3339(epoch_secs)
}

fn purge_expired_jobs(state: &mut JobRegistryState, now_epoch_secs: u64) -> usize {
    let before = state.jobs.len();
    state.jobs.retain(|_, record| {
        !record.worker_finished
            || match record.purge_after_epoch_secs {
                Some(purge_after) => purge_after > now_epoch_secs,
                None => true,
            }
    });
    before - state.jobs.len()
}

fn ensure_job_owner(
    record: &JobRecord,
    owner_user: &str,
    job_id: &str,
) -> Result<(), GatewayError> {
    if record.owner_user == owner_user {
        Ok(())
    } else {
        Err(GatewayError::NotFound(format!("job {job_id} not found")))
    }
}

async fn await_report_export_operation<T>(
    deadline: Instant,
    operation: impl Future<Output = Result<T, GatewayError>>,
) -> Result<T, GatewayError> {
    if Instant::now() >= deadline {
        return Err(report_export_timeout_error());
    }

    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| report_export_timeout_error())?
}

fn report_export_timeout_error() -> GatewayError {
    GatewayError::GatewayTimeout(
        "backend report export did not complete before the gateway timeout".to_string(),
    )
}

fn report_export_cancelled_error() -> GatewayError {
    GatewayError::Conflict("report export job was cancelled".to_string())
}

fn report_export_job_problem(error: &GatewayError) -> JobProblem {
    let public_error = match error {
        GatewayError::BackendUnavailable(_) => {
            GatewayError::BackendUnavailable("The backend service is unavailable.".to_string())
        }
        GatewayError::NotImplemented(_) => GatewayError::NotImplemented(
            "The backend does not support asynchronous report export.".to_string(),
        ),
        GatewayError::NotFound(_) => {
            GatewayError::NotFound("The report export resource was not found.".to_string())
        }
        GatewayError::InvalidInput(_) => GatewayError::InvalidInput(
            "The backend rejected the report export request.".to_string(),
        ),
        GatewayError::Unauthorized(_) => GatewayError::Unauthorized(
            "Authentication is required to export the report.".to_string(),
        ),
        GatewayError::SessionExpired(_) => {
            GatewayError::SessionExpired("The report export session expired.".to_string())
        }
        GatewayError::SessionInvalidated(_) => GatewayError::SessionInvalidated(
            "The report export session is no longer valid.".to_string(),
        ),
        GatewayError::Forbidden(_) => {
            GatewayError::Forbidden("The report export operation is not permitted.".to_string())
        }
        GatewayError::Conflict(_) => {
            GatewayError::Conflict("The report export could not be completed.".to_string())
        }
        GatewayError::TooManyRequests(_) => GatewayError::TooManyRequests(
            "The report export backend is currently busy.".to_string(),
        ),
        GatewayError::Internal(_) => GatewayError::Internal(
            "An internal server error occurred while exporting the report.".to_string(),
        ),
        GatewayError::GatewayTimeout(_) => GatewayError::GatewayTimeout(
            "The report export did not complete before the gateway timeout.".to_string(),
        ),
    };
    JobProblem::from_gateway_error(&public_error)
}

pub(crate) fn new_job_registry() -> Arc<JobRegistry> {
    Arc::new(JobRegistry::default())
}

#[cfg(test)]
#[path = "jobs_test.rs"]
mod jobs_test;
