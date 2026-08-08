// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl SupportingResourcePort for GvmdAdapter {
    async fn list_hosts(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<HostPage, GatewayError> {
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
            .call(get_hosts(GetHostsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetHostsResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_host(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetHostsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(host_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("host {id} not found")))
    }

    async fn list_report_formats(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<ReportFormatPage, GatewayError> {
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
            .call(get_report_formats(GetReportFormatsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetReportFormatsResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_report_format(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetReportFormatsResponse::from_response(&response).map_err(map_parse_error)?;
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
            .call(get_filters(GetFiltersOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetFiltersResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_filter(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetFiltersResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(filter_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("filter {id} not found")))
    }

    async fn list_tags(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TagPage, GatewayError> {
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
            .call(get_tags(GetTagsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTagsResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_tag(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTagsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(tag_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("tag {id} not found")))
    }

    async fn list_tickets(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TicketPage, GatewayError> {
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
            .call(get_notes(GetNotesOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
                result: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNotesResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed.items;
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        let data = items.into_iter().map(note_from_gmp).collect();
        Ok(NotePage {
            data,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_note(&self, session_token: &str, id: &str) -> Result<Note, GatewayError> {
        let client = self.session_client(session_token)?;
        let note_id = parse_entity_id(id)?;
        let uuid_filter = format!("uuid={}", note_id.as_str());
        let response = client
            .lock()
            .await?
            .call(get_notes(GetNotesOpts {
                filter_string: paginated_filter(Some(&uuid_filter), None, 1, 1)?,
                filter_id: None,
                trash: None,
                details: Some(true),
                result: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNotesResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let nvt_oid = input.nvt_oid.clone();
        let opts = note_opts_from_create_input(input)?;
        let response = client
            .lock()
            .await?
            .call(create_note(&nvt_oid, opts))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateNoteResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn modify_note(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyNoteInput,
    ) -> Result<Note, GatewayError> {
        let client = self.session_client(session_token)?;
        let note_id = parse_entity_id(id)?;
        let response = client
            .lock()
            .await?
            .call(modify_note(&note_id, note_opts_from_modify_input(input)?))
            .await
            .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_note(session_token, id).await
    }

    async fn delete_note(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_note(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_overrides(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<OverridePage, GatewayError> {
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
            .call(get_overrides(GetOverridesOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
                result: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetOverridesResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed.items;
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        let data = items.into_iter().map(override_from_gmp).collect();
        Ok(OverridePage {
            data,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_override(&self, session_token: &str, id: &str) -> Result<Override, GatewayError> {
        let client = self.session_client(session_token)?;
        let override_id = parse_entity_id(id)?;
        let uuid_filter = format!("uuid={}", override_id.as_str());
        let response = client
            .lock()
            .await?
            .call(get_overrides(GetOverridesOpts {
                filter_string: paginated_filter(Some(&uuid_filter), None, 1, 1)?,
                filter_id: None,
                trash: None,
                details: Some(true),
                result: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetOverridesResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let nvt_oid = input.nvt_oid.clone();
        let opts = override_opts_from_create_input(input)?;
        let response = client
            .lock()
            .await?
            .call(create_override(&nvt_oid, opts))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateOverrideResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn modify_override(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyOverrideInput,
    ) -> Result<Override, GatewayError> {
        let client = self.session_client(session_token)?;
        let override_id = parse_entity_id(id)?;
        let response = client
            .lock()
            .await?
            .call(modify_override(
                &override_id,
                override_opts_from_modify_input(input)?,
            ))
            .await
            .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_override(session_token, id).await
    }

    async fn delete_override(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_override(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_nvts(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<NvtPage, GatewayError> {
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
            .call(get_nvts(GetNvtsOpts {
                filter_string,
                filter_id: None,
                details: Some(true),
                ..Default::default()
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNvtsResponse::from_response(&response).map_err(map_parse_error)?;
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
            let fallback = self
                .call_with_session(
                    session_token,
                    "nvts.list",
                    get_nvts(GetNvtsOpts {
                        filter_string: self
                            .filter_resolving_filter_id(
                                session_token,
                                None,
                                query.filter_string.as_deref(),
                                filter_id.as_ref(),
                                &[],
                            )
                            .await?,
                        filter_id: None,
                        details: Some(true),
                        ..Default::default()
                    }),
                )
                .await?;
            let parsed = GetNvtsResponse::from_response(&fallback).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_nvt(oid))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNvtsResponse::from_response(&response).map_err(map_parse_error)?;
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
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_nvt_families())
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNvtFamiliesResponse::from_response(&response).map_err(map_parse_error)?;
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
}
