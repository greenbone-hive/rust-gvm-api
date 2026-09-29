// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::super::*;

impl E2eHarness {
    pub async fn get_report_summary_page(
        &self,
        token: &str,
        report_id: &str,
        subresource: &str,
        page: u32,
        per_page: u32,
    ) -> Result<ListResponse<ReportSummaryRow>> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!(
                    "/api/v1/reports/{report_id}/{subresource}?page={page}&perPage={per_page}"
                ),
                token,
            ),
            StatusCode::OK,
            &format!("get report {subresource} summary page"),
        )
        .await
    }

    pub async fn get_report_operating_systems_page(
        &self,
        token: &str,
        report_id: &str,
        page: u32,
        per_page: u32,
    ) -> Result<ListResponse<ReportOperatingSystemSummary>> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!(
                    "/api/v1/reports/{report_id}/operating-systems?page={page}&perPage={per_page}"
                ),
                token,
            ),
            StatusCode::OK,
            "get report operating-system summary page",
        )
        .await
    }

    pub async fn get_report(&self, token: &str, report_id: &str) -> Result<Report> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/reports/{report_id}?perPage=1000"),
                token,
            ),
            StatusCode::OK,
            "get report",
        )
        .await
    }

    pub async fn list_reports(&self, token: &str) -> Result<ListResponse<Report>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/reports?perPage=1000", token),
            StatusCode::OK,
            "list reports",
        )
        .await
    }

    pub async fn create_json_report_export_job(
        &self,
        token: &str,
        report_id: &str,
    ) -> Result<ReportExportJob> {
        self.send_json(
            self.authed(
                Method::POST,
                &format!("/api/v1/reports/{report_id}/exports"),
                token,
            )
            .json(&serde_json::json!({ "format": "json" })),
            StatusCode::ACCEPTED,
            "create JSON report export job",
        )
        .await
    }

    pub async fn create_report_format_export_job(
        &self,
        token: &str,
        report_id: &str,
        report_format_id: &str,
    ) -> Result<ReportExportJob> {
        self.send_json(
            self.authed(
                Method::POST,
                &format!("/api/v1/reports/{report_id}/exports"),
                token,
            )
            .json(&serde_json::json!({ "reportFormatId": report_format_id })),
            StatusCode::ACCEPTED,
            "create report-format export job",
        )
        .await
    }

    pub async fn get_job(&self, token: &str, job_id: &str) -> Result<ReportExportJob> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/jobs/{job_id}"), token),
            StatusCode::OK,
            "get job",
        )
        .await
    }

    pub async fn download_json_report_export(
        &self,
        token: &str,
        job_id: &str,
    ) -> Result<ReportJsonExport> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/jobs/{job_id}/result"), token),
            StatusCode::OK,
            "download JSON report export",
        )
        .await
    }

    pub async fn download_report_export_response(
        &self,
        token: &str,
        job_id: &str,
    ) -> Result<reqwest::Response> {
        self.authed(Method::GET, &format!("/api/v1/jobs/{job_id}/result"), token)
            .send()
            .await
            .context("download report export")
    }

    pub async fn get_report_tls_certificates_page(
        &self,
        token: &str,
        report_id: &str,
        page: u32,
        per_page: u32,
    ) -> Result<TlsCertificateList> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!(
                    "/api/v1/reports/{report_id}/tls-certificates?page={page}&perPage={per_page}"
                ),
                token,
            ),
            StatusCode::OK,
            "get report TLS certificates page",
        )
        .await
    }

    pub async fn get_report_errors_page(
        &self,
        token: &str,
        report_id: &str,
        page: u32,
        per_page: u32,
    ) -> Result<ResultList> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/reports/{report_id}/errors?page={page}&perPage={per_page}"),
                token,
            ),
            StatusCode::OK,
            "get report errors page",
        )
        .await
    }

    pub async fn get_report_closed_cves_page(
        &self,
        token: &str,
        report_id: &str,
        page: u32,
        per_page: u32,
    ) -> Result<ResultList> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/reports/{report_id}/closed-cves?page={page}&perPage={per_page}"),
                token,
            ),
            StatusCode::OK,
            "get report closed CVEs page",
        )
        .await
    }

    pub async fn get_report_vulnerabilities_page(
        &self,
        token: &str,
        report_id: &str,
        page: u32,
        per_page: u32,
    ) -> Result<ResultList> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!(
                    "/api/v1/reports/{report_id}/vulnerabilities?page={page}&perPage={per_page}"
                ),
                token,
            ),
            StatusCode::OK,
            "get report vulnerabilities page",
        )
        .await
    }

    pub async fn get_report_vulnerabilities_problem(
        &self,
        token: &str,
        report_id: &str,
        page: u32,
        per_page: u32,
    ) -> Result<ProblemResponse> {
        let response = self
            .authed(
                Method::GET,
                &format!(
                    "/api/v1/reports/{report_id}/vulnerabilities?page={page}&perPage={per_page}"
                ),
                token,
            )
            .send()
            .await
            .context("get report vulnerabilities problem")?;

        assert_problem_response(
            response,
            StatusCode::NOT_IMPLEMENTED,
            "get report vulnerabilities problem",
        )
        .await
    }

    pub async fn report_detail_subresources_supported(
        &self,
        token: &str,
        report_id: &str,
    ) -> Result<bool> {
        let response = self
            .authed(
                Method::GET,
                &format!("/api/v1/reports/{report_id}/vulnerabilities?page=1&perPage=1"),
                token,
            )
            .send()
            .await
            .context("probe report-detail subresource support")?;
        let status = response.status();

        if status == StatusCode::OK {
            let _page: ResultList = response
                .json()
                .await
                .context("parse report-detail support probe response body as JSON")?;
            return Ok(true);
        }

        if status == StatusCode::NOT_IMPLEMENTED {
            let problem = assert_problem_response(
                response,
                StatusCode::NOT_IMPLEMENTED,
                "probe report-detail subresource support",
            )
            .await?;
            if problem.code == "not_implemented" {
                return Ok(false);
            }
            bail!(
                "probe report-detail subresource support: expected code not_implemented but received {} ({})",
                problem.code,
                problem.title
            );
        }

        let body = response
            .text()
            .await
            .context("read report-detail support probe response body")?;
        bail!(
            "probe report-detail subresource support: expected HTTP {} or {} but received {} with body {}",
            StatusCode::OK,
            StatusCode::NOT_IMPLEMENTED,
            status,
            truncate(&body)
        );
    }

    pub fn select_report_format_by_extension<'a>(
        &self,
        report_formats: &'a [ReportFormat],
        expected_extension: &str,
        preferred_id: Option<&str>,
    ) -> Result<&'a ReportFormat> {
        if let Some(preferred_id) = preferred_id {
            if let Some(report_format) = report_formats
                .iter()
                .find(|report_format| report_format.id == preferred_id)
            {
                return Ok(report_format);
            }
        }

        let expected_extension = lower(expected_extension);
        report_formats
            .iter()
            .find(|report_format| {
                report_format
                    .extension
                    .as_deref()
                    .is_some_and(|extension| lower(extension) == expected_extension)
            })
            .or_else(|| {
                report_formats.iter().find(|report_format| {
                    report_format
                        .name
                        .to_lowercase()
                        .contains(expected_extension.as_str())
                })
            })
            .with_context(|| {
                format!(
                    "no report format found for extension {}; available formats: {}",
                    expected_extension,
                    report_formats
                        .iter()
                        .map(|report_format| {
                            format!(
                                "{} ({}, ext={:?}, contentType={:?})",
                                report_format.name,
                                report_format.id,
                                report_format.extension,
                                report_format.content_type
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }
}
