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
        let response = self
            .call_with_session(
                session_token,
                "targets.list",
                get_targets(GetTargetsOpts {
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
                }),
            )
            .await?;
        let parsed = GetTargetsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(target_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        // Compatibility for backends/mocks that accept pagination terms but do
        // not report totals for later pages; preserve the REST page contract.
        if needs_client_side_pagination_fallback(&items, total, query.page) {
            let fallback = self
                .call_with_session(
                    session_token,
                    "targets.list",
                    get_targets(GetTargetsOpts {
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
                    }),
                )
                .await?;
            let parsed = GetTargetsResponse::from_response(&fallback).map_err(map_parse_error)?;
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
        let response = self
            .call_with_session(
                session_token,
                "targets.create",
                create_target(
                    &input.name,
                    CreateTargetOpts {
                        comment: input.comment,
                        hosts: input.hosts,
                        exclude_hosts: input.exclude_hosts,
                        alive_test: input
                            .alive_test
                            .as_deref()
                            .map(parse_alive_test)
                            .transpose()?,
                        port_list_id: input
                            .port_list_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        ssh_credential_id: input
                            .ssh_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        smb_credential_id: input
                            .smb_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        esxi_credential_id: input
                            .esxi_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        snmp_credential_id: input
                            .snmp_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        reverse_lookup_only: input.reverse_lookup_only,
                        reverse_lookup_unify: input.reverse_lookup_unify,
                    },
                ),
            )
            .await?;
        let parsed = CreateTargetResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "targets.get",
                get_target(&parse_entity_id(id)?),
            )
            .await?;
        let parsed = GetTargetsResponse::from_response(&response).map_err(map_parse_error)?;
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
        let response = self
            .call_with_session(
                session_token,
                "targets.modify",
                modify_target(
                    &target_id,
                    ModifyTargetOpts {
                        name: input.name,
                        comment: input.comment,
                        hosts: collection_update(input.hosts),
                        exclude_hosts: collection_update(input.exclude_hosts),
                        reverse_lookup_only: input.reverse_lookup_only,
                        reverse_lookup_unify: input.reverse_lookup_unify,
                        alive_test: input
                            .alive_test
                            .as_deref()
                            .map(parse_alive_test)
                            .transpose()?,
                        port_list_id: input
                            .port_list_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        ssh_credential_id: input
                            .ssh_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        smb_credential_id: input
                            .smb_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        esxi_credential_id: input
                            .esxi_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        snmp_credential_id: input
                            .snmp_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                    },
                ),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_target(session_token, id).await
    }

    async fn delete_target(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "targets.delete",
                delete_target(&parse_entity_id(id)?, ultimate),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}
