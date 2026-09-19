// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl TargetPort for GvmdAdapter {
    async fn list_targets(
        &self,
        session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let parsed = self
            .execute_with_session(
                session_token,
                "targets.list",
                GetTargetsRequest {
                    filter_string: self
                        .paginated_filter_resolving_filter_id(
                            session_token,
                            None,
                            query.filter_string.as_deref(),
                            filter_id.as_ref(),
                            query.page,
                            query.per_page,
                            &[],
                        )
                        .await?,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(target_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        // Compatibility for backends/mocks that accept pagination terms but do
        // not report totals for later pages; preserve the REST page contract.
        if needs_client_side_pagination_fallback(&items, total, query.page) {
            let parsed = self
                .execute_with_session(
                    session_token,
                    "targets.list",
                    GetTargetsRequest {
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
                        trash: None,
                        details: Some(true),
                    },
                )
                .await?;
            let items = parsed
                .items
                .into_iter()
                .map(target_from_gmp)
                .collect::<Vec<_>>();
            let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

            return Ok(TargetPage {
                data: paged_slice(items, query.page, query.per_page),
                pagination: paged_pagination(total, query.page, query.per_page),
            });
        }

        Ok(TargetPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_target(
        &self,
        session_token: &str,
        input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
        let hosts = target_hosts(input.hosts, input.exclude_hosts)?;
        let ports = input
            .port_list_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?
            .map(TargetPortSelection::PortList)
            .unwrap_or_else(default_target_ports);
        let mut request = CreateTargetRequest::new(input.name, hosts, ports);
        request.comment = input.comment;
        request.alive_test = input
            .alive_test
            .as_deref()
            .map(parse_alive_test)
            .transpose()?;
        request.ssh_credential_id = input
            .ssh_credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        request.smb_credential_id = input
            .smb_credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        request.esxi_credential_id = input
            .esxi_credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        request.snmp_credential_id = input
            .snmp_credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        request.reverse_lookup_only = input.reverse_lookup_only;
        request.reverse_lookup_unify = input.reverse_lookup_unify;
        let parsed = self
            .execute_with_session(session_token, "targets.create", request)
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn clone_target(&self, session_token: &str, id: &str) -> Result<String, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "targets.clone",
                CloneTargetRequest::new(parse_entity_id(id)?),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "targets.get",
                GetTargetRequest::new(parse_entity_id(id)?),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(target_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("target {id} not found")))
    }

    async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        let target_id = parse_entity_id(id)?;
        let hosts = match (input.hosts, input.exclude_hosts) {
            (None, None) => None,
            (Some(included), excluded) => {
                Some(target_hosts(included, excluded.unwrap_or_default())?)
            }
            (None, Some(_)) => {
                return Err(GatewayError::InvalidInput(
                    "excludeHosts requires hosts so both lists can be replaced atomically"
                        .to_string(),
                ));
            }
        };
        let mut request = ModifyTargetRequest::new(target_id);
        request.name = input.name;
        request.comment = input.comment;
        request.hosts = hosts;
        request.reverse_lookup_only = input.reverse_lookup_only;
        request.reverse_lookup_unify = input.reverse_lookup_unify;
        request.alive_test = input
            .alive_test
            .as_deref()
            .map(parse_alive_test)
            .transpose()?;
        request.port_list_id = input
            .port_list_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?
            .map(ScalarUpdate::Set)
            .unwrap_or_default();
        request.ssh_credential_id = input
            .ssh_credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?
            .map(ScalarUpdate::Set)
            .unwrap_or_default();
        request.smb_credential_id = input
            .smb_credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?
            .map(ScalarUpdate::Set)
            .unwrap_or_default();
        request.esxi_credential_id = input
            .esxi_credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?
            .map(ScalarUpdate::Set)
            .unwrap_or_default();
        request.snmp_credential_id = input
            .snmp_credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?
            .map(ScalarUpdate::Set)
            .unwrap_or_default();
        self.execute_with_session(session_token, "targets.modify", request)
            .await?;
        self.get_target(session_token, id).await
    }

    async fn delete_target(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "targets.delete",
            DeleteTargetRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn list_oci_image_targets(
        &self,
        session_token: &str,
        query: &SpecializedTargetQuery,
    ) -> Result<OciImageTargetPage, GatewayError> {
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
                "oci_image_targets.list",
                GetOciImageTargetsRequest {
                    filter_string,
                    filter_id: None,
                    trash: Some(query.trash),
                    tasks: Some(true),
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(oci_image_target_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        if items.is_empty() || needs_client_side_pagination_fallback(&items, total, query.page) {
            let filter_string = self
                .filter_resolving_filter_id(
                    session_token,
                    None,
                    query.filter_string.as_deref(),
                    filter_id.as_ref(),
                    &[],
                )
                .await?;
            let parsed = self
                .execute_with_session(
                    session_token,
                    "oci_image_targets.list",
                    GetOciImageTargetsRequest {
                        filter_string,
                        filter_id: None,
                        trash: Some(query.trash),
                        tasks: Some(true),
                    },
                )
                .await?;
            let items = parsed
                .items
                .into_iter()
                .map(oci_image_target_from_gmp)
                .collect::<Vec<_>>();
            let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
            return Ok(OciImageTargetPage {
                data: paged_slice(items, query.page, query.per_page),
                pagination: paged_pagination(total, query.page, query.per_page),
            });
        }
        Ok(OciImageTargetPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_oci_image_target(
        &self,
        session_token: &str,
        input: CreateOciImageTargetInput,
    ) -> Result<String, GatewayError> {
        let credential_id = input
            .credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let mut request = CreateOciImageTargetRequest::new(input.name, input.image_references);
        request.comment = input.comment;
        request.credential_id = credential_id;
        let parsed = self
            .execute_with_session(session_token, "oci_image_targets.create", request)
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn clone_oci_image_target(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<String, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "oci_image_targets.clone",
                CloneOciImageTargetRequest::new(parse_entity_id(id)?),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn get_oci_image_target(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<OciImageTarget, GatewayError> {
        let parsed = self
            .execute_with_session(session_token, "oci_image_targets.get", {
                let mut request = GetOciImageTargetRequest::new(parse_entity_id(id)?);
                request.tasks = Some(true);
                request
            })
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(oci_image_target_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("OCI image target {id} not found")))
    }

    async fn modify_oci_image_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyOciImageTargetInput,
    ) -> Result<OciImageTarget, GatewayError> {
        let target_id = parse_entity_id(id)?;
        let credential_id = input
            .credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let mut request = ModifyOciImageTargetRequest::new(target_id);
        request.name = input.name;
        request.comment = input.comment;
        request.image_references = input.image_references.unwrap_or_default();
        request.credential_id = credential_id;
        self.execute_with_session(session_token, "oci_image_targets.modify", request)
            .await?;
        self.get_oci_image_target(session_token, id).await
    }

    async fn delete_oci_image_target(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "oci_image_targets.delete",
            DeleteOciImageTargetRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn list_web_application_targets(
        &self,
        session_token: &str,
        query: &SpecializedTargetQuery,
    ) -> Result<WebApplicationTargetPage, GatewayError> {
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
                "web_application_targets.list",
                GetWebApplicationTargetsRequest {
                    filter_string,
                    filter_id: None,
                    trash: Some(query.trash),
                    tasks: Some(true),
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(web_application_target_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        if items.is_empty() || needs_client_side_pagination_fallback(&items, total, query.page) {
            let filter_string = self
                .filter_resolving_filter_id(
                    session_token,
                    None,
                    query.filter_string.as_deref(),
                    filter_id.as_ref(),
                    &[],
                )
                .await?;
            let parsed = self
                .execute_with_session(
                    session_token,
                    "web_application_targets.list",
                    GetWebApplicationTargetsRequest {
                        filter_string,
                        filter_id: None,
                        trash: Some(query.trash),
                        tasks: Some(true),
                    },
                )
                .await?;
            let items = parsed
                .items
                .into_iter()
                .map(web_application_target_from_gmp)
                .collect::<Vec<_>>();
            let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
            return Ok(WebApplicationTargetPage {
                data: paged_slice(items, query.page, query.per_page),
                pagination: paged_pagination(total, query.page, query.per_page),
            });
        }
        Ok(WebApplicationTargetPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_web_application_target(
        &self,
        session_token: &str,
        input: CreateWebApplicationTargetInput,
    ) -> Result<String, GatewayError> {
        let credential_id = input
            .credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let mut request = CreateWebApplicationTargetRequest::new(input.name, input.urls);
        request.comment = input.comment;
        request.exclude_urls = input.exclude_urls;
        request.credential_id = credential_id;
        let parsed = self
            .execute_with_session(session_token, "web_application_targets.create", request)
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn clone_web_application_target(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<String, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "web_application_targets.clone",
                CloneWebApplicationTargetRequest::new(parse_entity_id(id)?),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn get_web_application_target(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<WebApplicationTarget, GatewayError> {
        let parsed = self
            .execute_with_session(session_token, "web_application_targets.get", {
                let mut request = GetWebApplicationTargetRequest::new(parse_entity_id(id)?);
                request.tasks = Some(true);
                request
            })
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(web_application_target_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("web application target {id} not found")))
    }

    async fn modify_web_application_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyWebApplicationTargetInput,
    ) -> Result<WebApplicationTarget, GatewayError> {
        let target_id = parse_entity_id(id)?;
        let credential_id = input
            .credential_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let mut request = ModifyWebApplicationTargetRequest::new(target_id);
        request.name = input.name;
        request.comment = input.comment;
        request.urls = input.urls.unwrap_or_default();
        request.exclude_urls = input.exclude_urls.unwrap_or_default();
        request.credential_id = credential_id;
        self.execute_with_session(session_token, "web_application_targets.modify", request)
            .await?;
        self.get_web_application_target(session_token, id).await
    }

    async fn delete_web_application_target(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "web_application_targets.delete",
            DeleteWebApplicationTargetRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }
}

fn target_hosts(included: Vec<String>, excluded: Vec<String>) -> Result<TargetHosts, GatewayError> {
    let included = included
        .into_iter()
        .map(|host| host.parse::<TargetHost>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| GatewayError::InvalidInput(error.to_string()))?;
    let excluded = excluded
        .into_iter()
        .map(|host| host.parse::<TargetHost>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| GatewayError::InvalidInput(error.to_string()))?;
    TargetHosts::new(included, excluded)
        .map_err(|error| GatewayError::InvalidInput(error.to_string()))
}

fn default_target_ports() -> TargetPortSelection {
    TargetPortSelection::PortRange(
        "T:1-65535"
            .parse::<TargetPortRange>()
            .expect("the built-in full TCP port range is valid"),
    )
}
