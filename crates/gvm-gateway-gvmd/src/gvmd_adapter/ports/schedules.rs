// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl SchedulePort for GvmdAdapter {
    async fn list_schedules(
        &self,
        session_token: &str,
        query: &ScheduleQuery,
    ) -> Result<SchedulePage, GatewayError> {
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
                "schedules.list",
                GetSchedulesRequest::new(GetSchedulesOpts {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                    tasks: None,
                }),
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(schedule_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(SchedulePage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_schedule(
        &self,
        session_token: &str,
        input: CreateScheduleInput,
    ) -> Result<String, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "schedules.create",
                CreateScheduleRequest::new(
                    input.name,
                    ScheduleOpts {
                        comment: input.comment,
                        icalendar: Some(input.icalendar),
                        timezone: Some(input.timezone),
                        name: None,
                    },
                ),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn get_schedule(&self, session_token: &str, id: &str) -> Result<Schedule, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "schedules.get",
                GetScheduleRequest::new(parse_entity_id(id)?),
            )
            .await?;
        parsed
            .items
            .into_iter()
            .next()
            .map(schedule_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("schedule {id} not found")))
    }

    async fn modify_schedule(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScheduleInput,
    ) -> Result<Schedule, GatewayError> {
        self.execute_with_session(
            session_token,
            "schedules.modify",
            ModifyScheduleRequest::new(
                parse_entity_id(id)?,
                ScheduleOpts {
                    comment: input.comment,
                    icalendar: input.icalendar,
                    timezone: input.timezone,
                    name: input.name,
                },
            ),
        )
        .await?;
        self.get_schedule(session_token, id).await
    }

    async fn delete_schedule(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "schedules.delete",
            DeleteScheduleRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }
}
