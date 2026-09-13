// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

fn nvt_opts(query: &NvtQuery, filter_string: Option<String>) -> Result<GetNvtsOpts, GatewayError> {
    let entity_id = |field: &str, value: Option<&str>| {
        value
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput(format!("invalid {field}")))
            })
            .transpose()
    };
    if let Some(sort_order) = query.sort_order.as_deref() {
        if !matches!(sort_order, "ascending" | "descending") {
            return Err(GatewayError::InvalidInput(
                "sortOrder must be ascending or descending".to_string(),
            ));
        }
    }

    Ok(GetNvtsOpts {
        filter_string,
        filter_id: None,
        details: Some(true),
        preferences: query.include_preferences,
        preference_count: query.include_preference_count,
        timeout: query.include_timeout,
        config_id: entity_id("configId", query.config_id.as_deref())?,
        preferences_config_id: entity_id(
            "preferencesConfigId",
            query.preferences_config_id.as_deref(),
        )?,
        family: query.family.clone(),
        sort_order: query.sort_order.clone(),
        sort_field: query.sort_field.clone(),
    })
}

#[async_trait]
impl SupportingResourcePort for GvmdAdapter {
    async fn list_assets(
        &self,
        session_token: &str,
        query: &AssetQuery,
    ) -> Result<GenericAssetPage, GatewayError> {
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
                "assets.list",
                GetAssetsRequest::new(GetAssetsOpts {
                    asset_id: None,
                    asset_type: None,
                    type_: Some(parse_asset_type(&query.asset_type)),
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let mut items = parsed
            .items
            .into_iter()
            .map(generic_asset_from_gmp)
            .collect::<Result<Vec<_>, _>>()?;
        items.sort_by(|left, right| {
            left.asset_type
                .cmp(&right.asset_type)
                .then_with(|| left.meta.name.cmp(&right.meta.name))
                .then_with(|| left.value.cmp(&right.value))
                .then_with(|| left.meta.id.cmp(&right.meta.id))
        });
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(GenericAssetPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_asset(
        &self,
        session_token: &str,
        id: &str,
        asset_type: &str,
    ) -> Result<GenericAsset, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "assets.get",
                GetAssetRequest::new(parse_entity_id(id)?, parse_asset_type(asset_type)),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(generic_asset_from_gmp)
            .transpose()?
            .ok_or_else(|| GatewayError::NotFound(format!("asset {id} not found")))
    }

    async fn modify_asset(
        &self,
        session_token: &str,
        id: &str,
        asset_type: &str,
        input: ModifyAssetInput,
    ) -> Result<GenericAsset, GatewayError> {
        let asset_id = parse_entity_id(id)?;
        self.execute_with_session(
            session_token,
            "assets.modify",
            ModifyAssetRequest::new(
                asset_id,
                ModifyAssetOpts {
                    comment: input.comment,
                    value: None,
                },
            ),
        )
        .await?;
        self.get_asset(session_token, id, asset_type).await
    }

    async fn delete_asset(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "assets.delete",
            DeleteAssetRequest::new(parse_entity_id(id)?, DeleteAssetOpts::default()),
        )
        .await?;
        Ok(())
    }

    async fn list_hosts(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<HostPage, GatewayError> {
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
                "hosts.list",
                GetHostsRequest::new(GetHostsOpts {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let mut items = parsed
            .items
            .into_iter()
            .map(host_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            left.meta
                .name
                .cmp(&right.meta.name)
                .then_with(|| left.ip.cmp(&right.ip))
                .then_with(|| left.meta.id.cmp(&right.meta.id))
        });
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(HostPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_host(&self, session_token: &str, id: &str) -> Result<Host, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "hosts.get",
                GetHostRequest::new(parse_entity_id(id)?),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(host_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("host {id} not found")))
    }

    async fn list_operating_systems(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<OperatingSystemPage, GatewayError> {
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
                "operating_systems.list",
                GetOperatingSystemAssetsRequest::new(GetOperatingSystemsOpts {
                    filter_string,
                    filter_id: None,
                    details: Some(true),
                }),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(operating_system_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(OperatingSystemPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_operating_system(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<OperatingSystem, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "operating_systems.get",
                GetOperatingSystemAssetRequest::new(parse_entity_id(id)?, Some(true)),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(operating_system_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("operating system {id} not found")))
    }

    async fn list_tls_certificates(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TlsCertificateAssetPage, GatewayError> {
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
                "tls_certificates.list",
                GetTlsCertificatesRequest::new(GetTlsCertificatesOpts {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(tls_certificate_asset_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(TlsCertificateAssetPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_tls_certificate(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TlsCertificateAsset, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "tls_certificates.get",
                GetTlsCertificateRequest::new(parse_entity_id(id)?),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(tls_certificate_asset_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("tls certificate {id} not found")))
    }

    async fn create_host(
        &self,
        session_token: &str,
        input: CreateHostInput,
    ) -> Result<String, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "hosts.create",
                CreateHostRequest::new(host_opts_from_create_input(input)),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn modify_host(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyHostInput,
    ) -> Result<Host, GatewayError> {
        let host_id = parse_entity_id(id)?;
        self.execute_with_session(
            session_token,
            "hosts.modify",
            ModifyHostRequest::new(host_id, host_opts_from_modify_input(input)),
        )
        .await?;
        self.get_host(session_token, id).await
    }

    async fn modify_operating_system(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyOperatingSystemInput,
    ) -> Result<OperatingSystem, GatewayError> {
        let operating_system_id = parse_entity_id(id)?;
        self.execute_with_session(
            session_token,
            "operating_systems.modify",
            ModifyOperatingSystemAssetRequest::new(operating_system_id, input.comment),
        )
        .await?;
        self.get_operating_system(session_token, id).await
    }

    async fn delete_host(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        // The gvmd host-asset delete command ignores an ultimate flag, so a
        // plain delete is always issued.
        self.execute_with_session(
            session_token,
            "hosts.delete",
            DeleteHostRequest::new(parse_entity_id(id)?, false),
        )
        .await?;
        Ok(())
    }

    async fn delete_operating_system(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<(), GatewayError> {
        self.execute_with_session_mapped(
            session_token,
            "operating_systems.delete",
            DeleteOperatingSystemAssetRequest::new(parse_entity_id(id)?),
            |error| match error {
                // The typed OS delete command has no client-controlled option
                // beyond its already validated ID. gvmd uses status 400 when
                // the asset is still in use, which is a resource conflict at
                // the REST/domain boundary rather than malformed input.
                gvm_client::GvmError::Server {
                    status: 400,
                    message,
                }
                | gvm_client::GvmError::Parse(gvm_gmp::responses::ParseError::ServerError {
                    status: 400,
                    message,
                }) => GatewayError::Conflict(message),
                other => map_gvm_error(other),
            },
        )
        .await?;
        Ok(())
    }

    async fn list_report_formats(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<ReportFormatPage, GatewayError> {
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
                "report_formats.list",
                GetReportFormatsRequest::new(GetReportFormatsOpts {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(report_format_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(ReportFormatPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_format(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ReportFormat, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "report_formats.get",
                GetReportFormatRequest::new(parse_entity_id(id)?),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(report_format_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("report format {id} not found")))
    }

    async fn list_filters(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<FilterPage, GatewayError> {
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
                "filters.list",
                GetFiltersRequest::new(GetFiltersOpts {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(filter_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(FilterPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_filter(&self, session_token: &str, id: &str) -> Result<Filter, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "filters.get",
                GetFilterRequest::new(parse_entity_id(id)?),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(filter_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("filter {id} not found")))
    }

    async fn create_filter(
        &self,
        session_token: &str,
        input: CreateFilterInput,
    ) -> Result<String, GatewayError> {
        let name = input.name.clone();
        let opts = filter_opts_from_create_input(input)?;
        let parsed = self
            .execute_with_session(
                session_token,
                "filters.create",
                CreateFilterRequest::new(name, opts),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn modify_filter(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyFilterInput,
    ) -> Result<Filter, GatewayError> {
        let filter_id = parse_entity_id(id)?;
        self.execute_with_session(
            session_token,
            "filters.modify",
            ModifyFilterRequest::new(filter_id, filter_opts_from_modify_input(input)?),
        )
        .await?;
        self.get_filter(session_token, id).await
    }

    async fn delete_filter(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "filters.delete",
            DeleteFilterRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn clone_filter(&self, session_token: &str, id: &str) -> Result<String, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "filters.clone",
                CloneFilterRequest::new(parse_entity_id(id)?),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn list_tags(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TagPage, GatewayError> {
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
                "tags.list",
                GetTagsRequest::new(GetTagsOpts {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(tag_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(TagPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_tag(&self, session_token: &str, id: &str) -> Result<Tag, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "tags.get",
                GetTagRequest::new(parse_entity_id(id)?),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(tag_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("tag {id} not found")))
    }

    async fn create_tag(
        &self,
        session_token: &str,
        input: CreateTagInput,
    ) -> Result<String, GatewayError> {
        let name = input.name.clone();
        let opts = tag_opts_from_create_input(input)?;
        let parsed = self
            .execute_with_session(
                session_token,
                "tags.create",
                CreateTagRequest::new(name, opts),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn modify_tag(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTagInput,
    ) -> Result<Tag, GatewayError> {
        let tag_id = parse_entity_id(id)?;
        self.execute_with_session(
            session_token,
            "tags.modify",
            ModifyTagRequest::new(tag_id, tag_opts_from_modify_input(input)?),
        )
        .await?;
        self.get_tag(session_token, id).await
    }

    async fn delete_tag(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "tags.delete",
            DeleteTagRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn clone_tag(&self, session_token: &str, id: &str) -> Result<String, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "tags.clone",
                CloneTagRequest::new(parse_entity_id(id)?),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn list_tickets(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TicketPage, GatewayError> {
        // rust-gvm does not expose semantic ticket requests yet.
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
            .call(get_tickets(GetTicketsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTicketsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(ticket_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(TicketPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_ticket(&self, session_token: &str, id: &str) -> Result<Ticket, GatewayError> {
        // rust-gvm does not expose a semantic ticket detail request yet.
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_ticket(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTicketsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(ticket_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("ticket {id} not found")))
    }

    async fn list_notes(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<NotePage, GatewayError> {
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
                "notes.list",
                GetNotesRequest::new(GetNotesOpts {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                    result: Some(true),
                }),
            )
            .await?;
        let items = parsed.items;
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        let data = items.into_iter().map(note_from_gmp).collect();
        Ok(NotePage {
            data,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_note(&self, session_token: &str, id: &str) -> Result<Note, GatewayError> {
        let note_id = parse_entity_id(id)?;
        let uuid_filter = format!("uuid={}", note_id.as_str());
        let parsed = self
            .execute_with_session(
                session_token,
                "notes.get",
                GetNotesRequest::new(GetNotesOpts {
                    filter_string: paginated_filter(Some(&uuid_filter), None, 1, 1)?,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                    result: Some(true),
                }),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .find(|note| note.meta.id.as_str() == note_id.as_str())
            .map(note_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("note {id} not found")))
    }

    async fn create_note(
        &self,
        session_token: &str,
        input: CreateNoteInput,
    ) -> Result<String, GatewayError> {
        let nvt_oid = input.nvt_oid.clone();
        let opts = note_opts_from_create_input(input)?;
        let parsed = self
            .execute_with_session(
                session_token,
                "notes.create",
                CreateNoteRequest::new(nvt_oid, opts),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn modify_note(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyNoteInput,
    ) -> Result<Note, GatewayError> {
        let note_id = parse_entity_id(id)?;
        self.execute_with_session(
            session_token,
            "notes.modify",
            ModifyNoteRequest::new(note_id, note_opts_from_modify_input(input)?),
        )
        .await?;
        self.get_note(session_token, id).await
    }

    async fn delete_note(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "notes.delete",
            DeleteNoteRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn list_overrides(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<OverridePage, GatewayError> {
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
                "overrides.list",
                GetOverridesRequest::new(GetOverridesOpts {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                    result: Some(true),
                }),
            )
            .await?;
        let items = parsed.items;
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        let data = items.into_iter().map(override_from_gmp).collect();
        Ok(OverridePage {
            data,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_override(&self, session_token: &str, id: &str) -> Result<Override, GatewayError> {
        let override_id = parse_entity_id(id)?;
        let uuid_filter = format!("uuid={}", override_id.as_str());
        let parsed = self
            .execute_with_session(
                session_token,
                "overrides.get",
                GetOverridesRequest::new(GetOverridesOpts {
                    filter_string: paginated_filter(Some(&uuid_filter), None, 1, 1)?,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                    result: Some(true),
                }),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .find(|override_| override_.meta.id.as_str() == override_id.as_str())
            .map(override_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("override {id} not found")))
    }

    async fn create_override(
        &self,
        session_token: &str,
        input: CreateOverrideInput,
    ) -> Result<String, GatewayError> {
        let nvt_oid = input.nvt_oid.clone();
        let opts = override_opts_from_create_input(input)?;
        let parsed = self
            .execute_with_session(
                session_token,
                "overrides.create",
                CreateOverrideRequest::new(nvt_oid, opts),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn modify_override(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyOverrideInput,
    ) -> Result<Override, GatewayError> {
        let override_id = parse_entity_id(id)?;
        self.execute_with_session(
            session_token,
            "overrides.modify",
            ModifyOverrideRequest::new(override_id, override_opts_from_modify_input(input)?),
        )
        .await?;
        self.get_override(session_token, id).await
    }

    async fn delete_override(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "overrides.delete",
            DeleteOverrideRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn list_nvts(
        &self,
        session_token: &str,
        query: &NvtQuery,
    ) -> Result<NvtPage, GatewayError> {
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
                "nvts.list",
                GetNvtsRequest::new(nvt_opts(query, filter_string)?),
            )
            .await?;
        let mut items = parsed
            .items
            .into_iter()
            .map(nvt_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            left.oid
                .cmp(&right.oid)
                .then_with(|| left.name.cmp(&right.name))
        });
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        if needs_client_side_pagination_fallback(&items, total, query.page)
            || backend_ignored_pagination(&items, query.per_page)
        {
            let parsed = self
                .execute_with_session(
                    session_token,
                    "nvts.list",
                    GetNvtsRequest::new(nvt_opts(
                        query,
                        self.filter_resolving_filter_id(
                            session_token,
                            None,
                            query.filter_string.as_deref(),
                            filter_id.as_ref(),
                            &[],
                        )
                        .await?,
                    )?),
                )
                .await?;
            let mut items = parsed
                .items
                .into_iter()
                .map(nvt_from_gmp)
                .collect::<Vec<_>>();
            items.sort_by(|left, right| {
                left.oid
                    .cmp(&right.oid)
                    .then_with(|| left.name.cmp(&right.name))
            });
            let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

            return Ok(NvtPage {
                data: paged_slice(items, query.page, query.per_page),
                pagination: paged_pagination(total, query.page, query.per_page),
            });
        }

        Ok(NvtPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_nvt(&self, session_token: &str, oid: &str) -> Result<Nvt, GatewayError> {
        let parsed = self
            .execute_with_session(session_token, "nvts.get", GetNvtRequest::new(oid))
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(nvt_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("nvt {oid} not found")))
    }

    async fn list_nvt_families(
        &self,
        session_token: &str,
        page: u32,
        per_page: u32,
    ) -> Result<NvtFamilyPage, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "nvt_families.list",
                GetNvtFamiliesRequest::new(),
            )
            .await?;
        let mut items = parsed
            .items
            .into_iter()
            .map(nvt_family_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));
        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        Ok(NvtFamilyPage {
            data: paged_slice(items, page, per_page),
            pagination: paged_pagination(total, page, per_page),
        })
    }

    async fn list_vulnerabilities(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<VulnerabilityPage, GatewayError> {
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
                "vulnerabilities.list",
                GetVulnsRequest::new(FilteredGetOpts {
                    filter_string,
                    filter_id: None,
                }),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(vulnerability_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(VulnerabilityPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn list_cves(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<CvePage, GatewayError> {
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
                "cves.list",
                GetCvesRequest::new(GetSecInfoOpts {
                    filter: filter_string,
                    filter_id: None,
                    details: None,
                }),
            )
            .await?;
        let total = gvmd_total(
            parsed.counts.filtered,
            parsed.counts.total,
            parsed.items.len(),
        );
        Ok(CvePage {
            data: parsed.items.into_iter().map(cve_from_gmp).collect(),
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_cve(&self, session_token: &str, id: &str) -> Result<Cve, GatewayError> {
        let parsed = self
            .execute_with_session(session_token, "cves.get", GetCveRequest::new(id))
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(cve_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("cve {id} not found")))
    }

    async fn list_cpes(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<CpePage, GatewayError> {
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
                "cpes.list",
                GetCpesRequest::new(GetSecInfoOpts {
                    filter: filter_string,
                    filter_id: None,
                    details: None,
                }),
            )
            .await?;
        let total = gvmd_total(
            parsed.counts.filtered,
            parsed.counts.total,
            parsed.items.len(),
        );
        Ok(CpePage {
            data: parsed.items.into_iter().map(cpe_from_gmp).collect(),
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_cpe(&self, session_token: &str, id: &str) -> Result<Cpe, GatewayError> {
        let parsed = self
            .execute_with_session(session_token, "cpes.get", GetCpeRequest::new(id))
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(cpe_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("cpe {id} not found")))
    }

    async fn list_cert_bund_advisories(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<CertBundAdvisoryPage, GatewayError> {
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
                "cert_bund_advisories.list",
                GetCertBundAdvisoriesRequest::new(GetSecInfoOpts {
                    filter: filter_string,
                    filter_id: None,
                    details: None,
                }),
            )
            .await?;
        let total = gvmd_total(
            parsed.counts.filtered,
            parsed.counts.total,
            parsed.items.len(),
        );
        Ok(CertBundAdvisoryPage {
            data: parsed
                .items
                .into_iter()
                .map(cert_bund_advisory_from_gmp)
                .collect(),
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_cert_bund_advisory(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<CertBundAdvisory, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "cert_bund_advisories.get",
                GetCertBundAdvisoryRequest::new(id),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(cert_bund_advisory_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("cert bund advisory {id} not found")))
    }

    async fn list_dfn_cert_advisories(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<DfnCertAdvisoryPage, GatewayError> {
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
                "dfn_cert_advisories.list",
                GetDfnCertAdvisoriesRequest::new(GetSecInfoOpts {
                    filter: filter_string,
                    filter_id: None,
                    details: None,
                }),
            )
            .await?;
        let total = gvmd_total(
            parsed.counts.filtered,
            parsed.counts.total,
            parsed.items.len(),
        );
        Ok(DfnCertAdvisoryPage {
            data: parsed
                .items
                .into_iter()
                .map(dfn_cert_advisory_from_gmp)
                .collect(),
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_dfn_cert_advisory(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<DfnCertAdvisory, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "dfn_cert_advisories.get",
                GetDfnCertAdvisoryRequest::new(id),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(dfn_cert_advisory_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("dfn cert advisory {id} not found")))
    }
}
