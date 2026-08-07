// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::time::Instant;

use anyhow::{bail, Context, Result};
use reqwest::StatusCode;

use super::{http::truncate, E2eHarness, ReadinessResponse, ReportExportJob, Task};

impl E2eHarness {
    pub async fn wait_until_ready(&self) -> Result<()> {
        let deadline = Instant::now() + self.config.ready_timeout;
        let mut last_observation = String::from("gateway readiness has not been queried yet");

        while Instant::now() < deadline {
            let response = self
                .client
                .get(self.endpoint("/ready"))
                .send()
                .await
                .context("query /ready")?;
            let status = response.status();
            let body = response.text().await.context("read /ready response body")?;

            if status == StatusCode::OK {
                let readiness: ReadinessResponse =
                    serde_json::from_str(&body).context("parse /ready success body")?;
                if readiness.status == "ready" {
                    eprintln!("gateway ready: {body}");
                    return Ok(());
                }
                last_observation = format!("readiness body reported non-ready state: {body}");
            } else {
                last_observation =
                    format!("readiness status {status} with body: {}", truncate(&body));
            }

            tokio::time::sleep(self.config.poll_interval).await;
        }

        bail!(
            "gateway did not become ready within {:?}: {last_observation}",
            self.config.ready_timeout
        );
    }
    pub async fn wait_for_task_completion(&self, token: &str, task_id: &str) -> Result<Task> {
        let deadline = Instant::now() + self.config.scan_timeout;
        let mut last_status = String::from("task status not yet observed");

        while Instant::now() < deadline {
            let task = self.get_task(token, task_id).await?;
            last_status = task.status.clone();
            eprintln!(
                "task {} status={} currentReport={:?} lastReport={:?}",
                task.id,
                task.status,
                task.current_report
                    .as_ref()
                    .map(|report| report.id.as_str()),
                task.last_report.as_ref().map(|report| report.id.as_str())
            );

            match task.status.as_str() {
                "Done" => return Ok(task),
                "Stopped" | "Interrupted" | "Delete Requested" | "Ultimate Delete Requested" => {
                    bail!(
                        "task {task_id} reached terminal failure status {}",
                        task.status
                    )
                }
                _ => tokio::time::sleep(self.config.poll_interval).await,
            }
        }

        bail!(
            "task {task_id} did not complete within {:?}; last status: {last_status}",
            self.config.scan_timeout
        );
    }

    pub async fn wait_for_audit_completion(&self, token: &str, audit_id: &str) -> Result<Task> {
        // Mirrors `wait_for_task_completion` but polls the audit-scoped route so
        // the compliance workflow observes the audit's own lifecycle rather than
        // the scan-task view (which excludes audits).
        let deadline = Instant::now() + self.config.scan_timeout;
        let mut last_status = String::from("audit status not yet observed");

        while Instant::now() < deadline {
            let audit = self.get_audit(token, audit_id).await?;
            last_status = audit.status.clone();
            eprintln!(
                "audit {} status={} currentReport={:?} lastReport={:?}",
                audit.id,
                audit.status,
                audit
                    .current_report
                    .as_ref()
                    .map(|report| report.id.as_str()),
                audit.last_report.as_ref().map(|report| report.id.as_str())
            );

            match audit.status.as_str() {
                "Done" => return Ok(audit),
                "Stopped" | "Interrupted" | "Delete Requested" | "Ultimate Delete Requested" => {
                    bail!(
                        "audit {audit_id} reached terminal failure status {}",
                        audit.status
                    )
                }
                _ => tokio::time::sleep(self.config.poll_interval).await,
            }
        }

        bail!(
            "audit {audit_id} did not complete within {:?}; last status: {last_status}",
            self.config.scan_timeout
        );
    }

    pub async fn wait_for_task_stopped(&self, token: &str, task_id: &str) -> Result<Task> {
        let deadline = Instant::now() + self.config.scan_timeout;
        let mut last_status = String::from("task status not yet observed");

        while Instant::now() < deadline {
            let task = self.get_task(token, task_id).await?;
            last_status = task.status.clone();
            eprintln!(
                "task {} status={} while waiting for stop",
                task.id, task.status
            );

            match task.status.as_str() {
                "Stopped" | "Interrupted" => return Ok(task),
                "Done" => bail!("task {task_id} completed before stop took effect"),
                _ => tokio::time::sleep(self.config.poll_interval).await,
            }
        }

        bail!(
            "task {task_id} did not stop within {:?}; last status: {last_status}",
            self.config.scan_timeout
        );
    }
    pub async fn wait_for_job_succeeded(
        &self,
        token: &str,
        job_id: &str,
    ) -> Result<ReportExportJob> {
        let deadline = Instant::now() + self.config.ready_timeout;
        let mut last_status = String::from("job status not yet observed");

        while Instant::now() < deadline {
            let job = self.get_job(token, job_id).await?;
            last_status = job.status.clone();
            if job.status == "succeeded" {
                return Ok(job);
            }
            if matches!(job.status.as_str(), "failed" | "cancelled" | "expired") {
                bail!("job {job_id} reached terminal status {}", job.status);
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }

        bail!(
            "job {job_id} did not succeed within {:?}; last status: {last_status}",
            self.config.ready_timeout
        )
    }
}
