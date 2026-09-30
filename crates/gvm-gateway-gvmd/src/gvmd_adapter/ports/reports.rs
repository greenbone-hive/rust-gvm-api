// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl ReportPort for GvmdAdapter {
    async fn list_reports(
        &self,
        session_token: &str,
        query: &ReportQuery,
    ) -> Result<ReportPage, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let parsed = self
            .execute_with_session(
                session_token,
                "reports.list",
                GetReportsRequest::new(GetReportsOpts {
                    report_id: None,
                    filter_string,
                    filter_id: None,
                    details: Some(false),
                    ignore_pagination: None,
                }),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(report_from_gmp)
            .collect::<Vec<_>>();

        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ReportPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report(
        &self,
        session_token: &str,
        id: &str,
        opts: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        let report_id = parse_entity_id(id)?;

        // Fetch only report metadata; embedded results are loaded below through
        // the explicit result-window request.
        let parsed = self
            .execute_with_session(
                session_token,
                "reports.get",
                GetReportsRequest::new(GetReportsOpts {
                    report_id: Some(report_id),
                    filter_string: None,
                    filter_id: None,
                    details: Some(false),
                    ignore_pagination: None,
                }),
            )
            .await?;
        let mut report = parsed
            .items
            .into_iter()
            .next()
            .map(report_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("report {id} not found")))?;

        // Fetch the explicitly requested embedded-result window for this report.
        let filter = paginated_filter(
            Some(&format!("report_id={id}")),
            None,
            opts.page,
            opts.per_page,
        )?;

        let results_parsed = self
            .execute_with_session(
                session_token,
                "reports.results",
                GetResultsRequest::new(GetResultsOpts {
                    filter_string: filter,
                    filter_id: None,
                    details: Some(true),
                }),
            )
            .await?;
        report.results = results_parsed
            .items
            .into_iter()
            .map(result_from_gmp)
            .collect();

        Ok(report)
    }

    async fn export_report(
        &self,
        session_token: &str,
        report_id: &str,
        request: &ReportExportRequest,
    ) -> Result<ReportExport, GatewayError> {
        let report_id = parse_entity_id(report_id)?;
        let mut opts = GetReportExportOpts::new(parse_entity_id(&request.report_format_id)?);
        opts.report_config_id = request
            .report_config_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        opts.filter_string = request.filter.clone();
        opts.filter_id = request
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;

        let export = self
            .execute_with_session(
                session_token,
                "reports.export",
                GmpGetReportExportRequest::new(report_id, opts),
            )
            .await?;

        Ok(ReportExport {
            bytes: export.bytes,
            content_type: export.content_type,
            extension: export.extension,
        })
    }

    async fn delete_report(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "reports.delete",
            DeleteReportRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn get_report_results(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        // Validate that the report_id is a valid UUID
        let _ = parse_entity_id(report_id)?;

        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let filter = self
            .paginated_filter_resolving_filter_id(
                session_token,
                Some(&format!("report_id={report_id}")),
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &["report_id"],
            )
            .await?;

        let parsed = self
            .execute_with_session(
                session_token,
                "reports.results",
                GetResultsRequest::new(GetResultsOpts {
                    filter_string: filter,
                    filter_id: None,
                    details: Some(true),
                }),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(result_from_gmp)
            .collect::<Vec<_>>();

        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ResultPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_vulnerabilities(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportVulnerabilityPage, GatewayError> {
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = self
            .execute_with_session_mapped(
                session_token,
                "reports.vulnerabilities",
                GetReportVulnsRequest::new(report_id, opts),
                |error| {
                    map_report_detail_error(error, "get_report_vulns", "report vulnerabilities")
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(result_from_report_vulnerability)
            .collect::<Result<Vec<_>, _>>()?;
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ReportVulnerabilityPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_hosts(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportHostPage, GatewayError> {
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = self
            .execute_with_session_mapped(
                session_token,
                "reports.hosts",
                GetReportHostsRequest::new(report_id, opts),
                |error| map_report_detail_error(error, "get_report_hosts", "report hosts"),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(report_host_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ReportHostPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_ports(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportPortPage, GatewayError> {
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = self
            .execute_with_session_mapped(
                session_token,
                "reports.ports",
                GetReportPortsRequest::new(report_id, opts),
                |error| map_report_detail_error(error, "get_report_ports", "report ports"),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(report_port_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ReportPortPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_applications(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportApplicationPage, GatewayError> {
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = self
            .execute_with_session_mapped(
                session_token,
                "reports.applications",
                GetReportApplicationsRequest::new(report_id, opts),
                |error| {
                    map_report_detail_error(error, "get_report_applications", "report applications")
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(report_application_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ReportApplicationPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_operating_systems(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportOperatingSystemPage, GatewayError> {
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = self
            .execute_with_session_mapped(
                session_token,
                "reports.operating_systems",
                GetReportOperatingSystemsRequest::new(report_id, opts),
                |error| {
                    map_report_detail_error(
                        error,
                        "get_report_operating_systems",
                        "report operating systems",
                    )
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(report_operating_system_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ReportOperatingSystemPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_cves(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportCvePage, GatewayError> {
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = self
            .execute_with_session_mapped(
                session_token,
                "reports.cves",
                GetReportCvesRequest::new(report_id, opts),
                |error| map_report_detail_error(error, "get_report_cves", "report CVEs"),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(report_cve_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ReportCvePage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_tls_certificates(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = self
            .execute_with_session_mapped(
                session_token,
                "reports.tls_certificates",
                GetReportTlsCertificatesRequest::new(report_id, opts),
                |error| {
                    map_report_detail_error(
                        error,
                        "get_report_tls_certificates",
                        "report TLS certificates",
                    )
                },
            )
            .await?;
        let certificates = parsed
            .items
            .into_iter()
            .map(tls_certificate_from_report_tls_certificate)
            .collect::<Vec<_>>();
        let total = gvmd_total(
            parsed.counts.filtered,
            parsed.counts.total,
            certificates.len(),
        );

        Ok(TlsCertificatePage {
            data: certificates,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_errors(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportErrorPage, GatewayError> {
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = self
            .execute_with_session_mapped(
                session_token,
                "reports.errors",
                GetReportErrorsRequest::new(report_id, opts),
                |error| map_report_detail_error(error, "get_report_errors", "report errors"),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(report_error_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ReportErrorPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_closed_cves(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ReportClosedCvePage, GatewayError> {
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = self
            .execute_with_session_mapped(
                session_token,
                "reports.closed_cves",
                GetReportClosedCvesRequest::new(report_id, opts),
                |error| {
                    map_report_detail_error(error, "get_report_closed_cves", "report closed CVEs")
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(report_closed_cve_from_gmp)
            .collect::<Result<Vec<_>, _>>()?;
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ReportClosedCvePage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }
}

async fn report_detail_query(
    adapter: &GvmdAdapter,
    session_token: &str,
    query: &ResultQuery,
) -> Result<GetReportDetailsOpts, GatewayError> {
    let filter_id = query
        .filter_id
        .as_deref()
        .map(parse_entity_id)
        .transpose()?;
    Ok(GetReportDetailsOpts {
        filter_string: adapter
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &["report_id"],
            )
            .await?,
        filter_id: None,
        ignore_pagination: None,
        details: Some(true),
    })
}

fn typed_report_detail_unsupported(error: &gvm_client::GvmError, command: &str) -> bool {
    matches!(
        error,
        gvm_client::GvmError::UnsupportedCommand { command: unsupported, .. }
            if unsupported == command
    )
}

fn map_report_detail_error(
    error: gvm_client::GvmError,
    command: &str,
    resource: &str,
) -> GatewayError {
    if typed_report_detail_unsupported(&error, command) {
        unsupported_typed_report_detail_error(command, resource)
    } else {
        map_gvm_error(error)
    }
}

// The gateway translates between REST/gRPC and GMP, but it does not emulate
// GMP functionality that the connected gvmd does not implement yet.
fn unsupported_typed_report_detail_error(command: &str, resource: &str) -> GatewayError {
    GatewayError::NotImplemented(format!(
        "{resource} are not available because gvmd does not implement `{command}` on this backend version; the proxy does not emulate unsupported GMP commands"
    ))
}
