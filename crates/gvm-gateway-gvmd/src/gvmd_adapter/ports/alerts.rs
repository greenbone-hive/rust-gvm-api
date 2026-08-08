// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl AlertPort for GvmdAdapter {
    async fn list_alerts(
        &self,
        session_token: &str,
        query: &AlertQuery,
    ) -> Result<AlertPage, GatewayError> {
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
            .call(get_alerts(GetAlertsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetAlertsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(alert_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(AlertPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_alert(
        &self,
        session_token: &str,
        input: CreateAlertInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(create_alert(
                &input.name,
                AlertOpts {
                    name: None,
                    comment: input.comment,
                    event: input.event.as_deref().map(parse_alert_event).transpose()?,
                    event_data: alert_data(input.event_data),
                    condition: input
                        .condition
                        .as_deref()
                        .map(parse_alert_condition)
                        .transpose()?,
                    condition_data: alert_data(input.condition_data),
                    method: input
                        .method
                        .as_deref()
                        .map(parse_alert_method)
                        .transpose()?,
                    method_data: alert_data(input.method_data),
                    filter_id: input
                        .filter_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateAlertResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_alert(&self, session_token: &str, id: &str) -> Result<Alert, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_alert(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetAlertsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(alert_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("alert {id} not found")))
    }

    async fn modify_alert(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAlertInput,
    ) -> Result<Alert, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(modify_alert(
                &parse_entity_id(id)?,
                AlertOpts {
                    name: input.name,
                    comment: input.comment,
                    event: input.event.as_deref().map(parse_alert_event).transpose()?,
                    event_data: alert_data(input.event_data.unwrap_or_default()),
                    condition: input
                        .condition
                        .as_deref()
                        .map(parse_alert_condition)
                        .transpose()?,
                    condition_data: alert_data(input.condition_data.unwrap_or_default()),
                    method: input
                        .method
                        .as_deref()
                        .map(parse_alert_method)
                        .transpose()?,
                    method_data: alert_data(input.method_data.unwrap_or_default()),
                    filter_id: input
                        .filter_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_alert(session_token, id).await
    }

    async fn delete_alert(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_alert(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}

fn alert_data(values: HashMap<String, String>) -> Vec<AlertData> {
    let mut data = values
        .into_iter()
        .map(|(name, value)| AlertData::new(name, value))
        .collect::<Vec<_>>();
    data.sort_by(|left, right| left.name.cmp(&right.name));
    data
}
