// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl PortListPort for GvmdAdapter {
    async fn list_port_lists(
        &self,
        session_token: &str,
        query: &PortListQuery,
    ) -> Result<PortListPage, GatewayError> {
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
                "port_lists.list",
                GetPortListsRequest::new(GetPortListsOpts {
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
            .map(port_list_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(PortListPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_port_list(
        &self,
        session_token: &str,
        input: CreatePortListInput,
    ) -> Result<String, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "port_lists.create",
                CreatePortListRequest::new(
                    input.name,
                    PortListOpts {
                        comment: input.comment,
                        port_range: input.port_range,
                    },
                ),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn get_port_list(&self, session_token: &str, id: &str) -> Result<PortList, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "port_lists.get",
                GetPortListRequest::new(parse_entity_id(id)?),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(port_list_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("port list {id} not found")))
    }

    async fn modify_port_list(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyPortListInput,
    ) -> Result<PortList, GatewayError> {
        if input.port_range.is_some() {
            return Err(GatewayError::InvalidInput(
                "portRange cannot be replaced atomically; update individual port ranges instead"
                    .to_string(),
            ));
        }
        self.execute_with_session(
            session_token,
            "port_lists.modify",
            ModifyPortListRequest::new(
                parse_entity_id(id)?,
                ModifyPortListOpts {
                    name: input.name,
                    comment: input.comment,
                },
            ),
        )
        .await?;
        self.get_port_list(session_token, id).await
    }

    async fn delete_port_list(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "port_lists.delete",
            DeletePortListRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }
}
