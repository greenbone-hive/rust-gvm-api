// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl ResultPort for GvmdAdapter {
    async fn list_results(
        &self,
        session_token: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
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
                "results.list",
                GetResultsRequest {
                    result_id: None,
                    task_id: None,
                    filter_string,
                    filter_id: None,
                    details: Some(true),
                    notes_details: None,
                    overrides_details: None,
                    get_counts: None,
                },
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

    async fn get_result(&self, session_token: &str, id: &str) -> Result<ScanResult, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "results.get",
                GetResultRequest::new(parse_entity_id(id)?),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(result_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("result {id} not found")))
    }
}
