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
        let client = self.session_client(session_token)?;
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
        let response = client
            .lock()
            .await?
            .call(get_reports(GetReportsOpts {
                report_id: None,
                filter_string,
                filter_id: None,
                details: Some(false),
                ignore_pagination: None,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetReportsResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(id)?;

        // Fetch only report metadata; embedded results are loaded below through
        // the explicit result-window request.
        let response = client
            .lock()
            .await?
            .call(get_reports(GetReportsOpts {
                report_id: Some(report_id),
                filter_string: None,
                filter_id: None,
                details: Some(false),
                ignore_pagination: None,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetReportsResponse::from_response(&response).map_err(map_parse_error)?;
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

        let results_response = client
            .lock()
            .await?
            .call(get_results(GetResultsOpts {
                filter_string: filter,
                filter_id: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let results_parsed =
            GetResultsResponse::from_response(&results_response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_report(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn get_report_results(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        let client = self.session_client(session_token)?;
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

        let response = client
            .lock()
            .await?
            .call(get_results(GetResultsOpts {
                filter_string: filter,
                filter_id: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetResultsResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = match client
            .lock()
            .await?
            .get_report_vulns(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error) if typed_report_detail_unsupported(&error, "get_report_vulns") => {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_vulns",
                    "report vulnerabilities",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
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
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let response = match client
            .lock()
            .await?
            .get_report_hosts(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error) if typed_report_detail_unsupported(&error, "get_report_hosts") => {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_hosts",
                    "report hosts",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
        let parsed = GetReportHostsResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let response = match client
            .lock()
            .await?
            .get_report_ports(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error) if typed_report_detail_unsupported(&error, "get_report_ports") => {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_ports",
                    "report ports",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
        let parsed = GetReportPortsResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let response = match client
            .lock()
            .await?
            .get_report_applications(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error) if typed_report_detail_unsupported(&error, "get_report_applications") => {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_applications",
                    "report applications",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
        let parsed =
            GetReportApplicationsResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let response = match client
            .lock()
            .await?
            .get_report_operating_systems(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error)
                if typed_report_detail_unsupported(&error, "get_report_operating_systems") =>
            {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_operating_systems",
                    "report operating systems",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
        let parsed =
            GetReportOperatingSystemsResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let response = match client.lock().await?.get_report_cves(&report_id, opts).await {
            Ok(parsed) => parsed,
            Err(error) if typed_report_detail_unsupported(&error, "get_report_cves") => {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_cves",
                    "report CVEs",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
        let parsed = GetReportCvesResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = match client
            .lock()
            .await?
            .get_report_tls_certificates(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error)
                if typed_report_detail_unsupported(&error, "get_report_tls_certificates") =>
            {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_tls_certificates",
                    "report TLS certificates",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
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
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = match client
            .lock()
            .await?
            .get_report_errors(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error) if typed_report_detail_unsupported(&error, "get_report_errors") => {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_errors",
                    "report errors",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
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
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = match client
            .lock()
            .await?
            .get_report_closed_cves(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error) if typed_report_detail_unsupported(&error, "get_report_closed_cves") => {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_closed_cves",
                    "report closed CVEs",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
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

// The gateway translates between REST/gRPC and GMP, but it does not emulate
// GMP functionality that the connected gvmd does not implement yet.
fn unsupported_typed_report_detail_error(command: &str, resource: &str) -> GatewayError {
    GatewayError::NotImplemented(format!(
        "{resource} are not available because gvmd does not implement `{command}` on this backend version; the proxy does not emulate unsupported GMP commands"
    ))
}
