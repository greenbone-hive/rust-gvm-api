// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Report use cases.

use gvm_gateway_domain::{
    GatewayError, GetReportOpts, ImportReportInput, Report, ReportApplicationPage,
    ReportClosedCvePage, ReportCvePage, ReportErrorPage, ReportExport, ReportExportRequest,
    ReportHostPage, ReportOperatingSystemPage, ReportPage, ReportPortPage, ReportQuery,
    ReportVulnerabilityPage, ResultPage, ResultQuery, TlsCertificatePage,
};

use crate::GatewayService;

impl GatewayService {
    /// Imports one opaque report envelope into an existing import task.
    pub async fn import_report(
        &self,
        session_token: &str,
        input: ImportReportInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "reports.create",
            session_token,
            "create",
            "report",
            None,
            |session| async move { self.reports.import_report(&session.token, input).await },
        )
        .await
    }

    /// Lists reports for an authenticated session.
    pub async fn list_reports(
        &self,
        session_token: &str,
        query: ReportQuery,
    ) -> Result<ReportPage, GatewayError> {
        self.execute_with_resource(
            "reports.list",
            session_token,
            "list",
            "report",
            None,
            |session| async move { self.reports.list_reports(&session.token, &query).await },
        )
        .await
    }

    /// Fetches a report for an authenticated session.
    pub async fn get_report(
        &self,
        session_token: &str,
        id: &str,
        opts: GetReportOpts,
    ) -> Result<Report, GatewayError> {
        self.execute_with_resource(
            "reports.get",
            session_token,
            "read",
            "report",
            Some(id),
            |session| async move { self.reports.get_report(&session.token, id, &opts).await },
        )
        .await
    }

    /// Exports a rendered report for an authenticated session.
    pub async fn export_report(
        &self,
        session_token: &str,
        report_id: &str,
        report_format_id: &str,
    ) -> Result<ReportExport, GatewayError> {
        self.execute_with_resource(
            "reports.export",
            session_token,
            "export",
            "report_export",
            Some(report_id),
            |session| async move {
                let request = ReportExportRequest {
                    report_format_id: report_format_id.to_string(),
                    report_config_id: None,
                    filter: None,
                    filter_id: None,
                };
                self.reports
                    .export_report(&session.token, report_id, &request)
                    .await
            },
        )
        .await
    }

    /// Permanently deletes a report for an authenticated session.
    pub async fn delete_report(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "reports.delete",
            session_token,
            "delete",
            "report",
            Some(id),
            |session| async move { self.reports.delete_report(&session.token, id).await },
        )
        .await
    }

    /// Lists results for a specific report.
    pub async fn get_report_results(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        self.execute_with_resource(
            "reports.results.list",
            session_token,
            "list",
            "report_result",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_results(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists vulnerability findings for a specific report.
    pub async fn get_report_vulnerabilities(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ReportVulnerabilityPage, GatewayError> {
        self.execute_with_resource(
            "reports.vulnerabilities.list",
            session_token,
            "list",
            "report_vulnerability",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_vulnerabilities(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists host summaries for a specific report.
    pub async fn get_report_hosts(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ReportHostPage, GatewayError> {
        self.execute_with_resource(
            "reports.hosts.list",
            session_token,
            "list",
            "report_host",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_hosts(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists port summaries for a specific report.
    pub async fn get_report_ports(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ReportPortPage, GatewayError> {
        self.execute_with_resource(
            "reports.ports.list",
            session_token,
            "list",
            "report_port",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_ports(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists application summaries for a specific report.
    pub async fn get_report_applications(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ReportApplicationPage, GatewayError> {
        self.execute_with_resource(
            "reports.applications.list",
            session_token,
            "list",
            "report_application",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_applications(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists operating-system summaries for a specific report.
    pub async fn get_report_operating_systems(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ReportOperatingSystemPage, GatewayError> {
        self.execute_with_resource(
            "reports.operating_systems.list",
            session_token,
            "list",
            "report_operating_system",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_operating_systems(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists CVE summaries for a specific report.
    pub async fn get_report_cves(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ReportCvePage, GatewayError> {
        self.execute_with_resource(
            "reports.cves.list",
            session_token,
            "list",
            "report_cve",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_cves(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists TLS certificate observations for a specific report.
    pub async fn get_report_tls_certificates(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        self.execute_with_resource(
            "reports.tls_certificates.list",
            session_token,
            "list",
            "report_tls_certificate",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_tls_certificates(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists report errors for a specific report.
    pub async fn get_report_errors(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ReportErrorPage, GatewayError> {
        self.execute_with_resource(
            "reports.errors.list",
            session_token,
            "list",
            "report_error",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_errors(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists closed-CVE findings for a specific report.
    pub async fn get_report_closed_cves(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ReportClosedCvePage, GatewayError> {
        self.execute_with_resource(
            "reports.closed_cves.list",
            session_token,
            "list",
            "report_closed_cve",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_closed_cves(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }
}
