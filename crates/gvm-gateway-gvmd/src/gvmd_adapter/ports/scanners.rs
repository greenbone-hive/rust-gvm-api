// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl ScannerPort for GvmdAdapter {
    async fn list_scanners(
        &self,
        session_token: &str,
        query: &ScannerQuery,
    ) -> Result<ScannerPage, GatewayError> {
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
                "scanners.list",
                GetScannersRequest {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(scanner_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ScannerPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_scanner(&self, session_token: &str, id: &str) -> Result<Scanner, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "scanners.get",
                GetScannerRequest::new(parse_entity_id(id)?),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(scanner_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("scanner {id} not found")))
    }
}
