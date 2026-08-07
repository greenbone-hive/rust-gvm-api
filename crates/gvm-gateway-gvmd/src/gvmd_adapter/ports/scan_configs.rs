// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl ScanConfigPort for GvmdAdapter {
    async fn list_scan_configs(
        &self,
        session_token: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
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
            .call(get_scan_configs(GetScanConfigsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScanConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(scan_config_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ScanConfigPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_scan_config(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let base_id = input
            .base_scan_config_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let response = client
            .lock()
            .await?
            .call(create_scan_config(
                &input.name,
                base_id.as_ref(),
                ConfigOpts {
                    comment: input.comment,
                    usage_type: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateScanConfigResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_scan_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanConfig, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_scan_config(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScanConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            // A policy shares the config resource family but must not be
            // readable through the scan-config route; treat it as absent so the
            // discriminator holds symmetrically with `get_policy`.
            .filter(|item| item.usage_type.as_deref() != Some("policy"))
            .map(scan_config_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("scan config {id} not found")))
    }

    async fn modify_scan_config(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        let client = self.session_client(session_token)?;
        let config_id = parse_entity_id(id)?;
        let response = client
            .lock()
            .await?
            .call(modify_scan_config(
                &config_id,
                ConfigOpts {
                    comment: input.comment,
                    usage_type: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_scan_config(session_token, id).await
    }

    async fn delete_scan_config(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_scan_config(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_policies(
        &self,
        session_token: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
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
            .call(get_policies(GetScanConfigsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScanConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(scan_config_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ScanConfigPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_policy(&self, session_token: &str, id: &str) -> Result<ScanConfig, GatewayError> {
        // Fetch through the policy-scoped `get_configs usage_type="policy"`
        // command filtered to this id, so a scan-config id is not readable as a
        // policy (and vice versa).
        let _ = parse_entity_id(id)?;
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_policies(GetScanConfigsOpts {
                filter_string: Some(format!("uuid={id}")),
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScanConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(scan_config_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("policy {id} not found")))
    }

    async fn create_policy(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(create_policy(
                &input.name,
                ConfigOpts {
                    comment: input.comment,
                    usage_type: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateScanConfigResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn modify_policy(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        let client = self.session_client(session_token)?;
        let config_id = parse_entity_id(id)?;
        let response = client
            .lock()
            .await?
            .call(modify_policy_cmd(
                &config_id,
                ConfigOpts {
                    comment: input.comment,
                    usage_type: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_policy(session_token, id).await
    }

    async fn delete_policy(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_policy_cmd(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}
