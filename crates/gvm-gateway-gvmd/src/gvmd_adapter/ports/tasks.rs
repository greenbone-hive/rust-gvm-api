// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl TaskPort for GvmdAdapter {
    async fn list_tasks(
        &self,
        session_token: &str,
        query: &TaskQuery,
    ) -> Result<TaskPage, GatewayError> {
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
                "tasks.list",
                get_tasks(GetTasksOpts {
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
                    schedules_only: None,
                    ignore_pagination: None,
                }),
            )
            .await?;
        let parsed = GetTasksResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(task_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(TaskPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_task(
        &self,
        session_token: &str,
        input: CreateTaskInput,
    ) -> Result<String, GatewayError> {
        let config_id = parse_entity_id(&input.scan_config_id)?;
        let target_id = parse_entity_id(&input.target_id)?;
        let scanner_id = parse_entity_id(&input.scanner_id)?;
        let schedule_id = input
            .schedule_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let alert_ids = input
            .alert_ids
            .iter()
            .map(|id| parse_entity_id(id))
            .collect::<Result<Vec<_>, _>>()?;
        let hosts_ordering = input
            .hosts_ordering
            .as_deref()
            .map(parse_hosts_ordering)
            .transpose()?;

        let response = self
            .call_with_session(
                session_token,
                "tasks.create",
                create_task(
                    &input.name,
                    &config_id,
                    &target_id,
                    &scanner_id,
                    CreateTaskOpts {
                        alterable: input.alterable,
                        hosts_ordering,
                        schedule_id,
                        alert_ids,
                        comment: input.comment,
                        schedule_periods: input.schedule_periods,
                        observers: input.observers,
                        preferences: input.preferences,
                    },
                ),
            )
            .await?;
        let parsed = CreateTaskResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn clone_task(&self, session_token: &str, id: &str) -> Result<String, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.clone",
                clone_task(&parse_entity_id(id)?),
            )
            .await?;
        let parsed = CreateTaskResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_task(&self, session_token: &str, id: &str) -> Result<Task, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.get",
                get_task_cmd(&parse_entity_id(id)?),
            )
            .await?;
        let parsed = GetTasksResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(task_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("task {id} not found")))
    }

    async fn modify_task(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        let task_id = parse_entity_id(id)?;
        let target_id = input
            .target_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let config_id = input
            .scan_config_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let scanner_id = input
            .scanner_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let schedule_id = input
            .schedule_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let alert_ids = input
            .alert_ids
            .map(|ids| {
                ids.iter()
                    .map(|id| parse_entity_id(id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let hosts_ordering = input
            .hosts_ordering
            .as_deref()
            .map(parse_hosts_ordering)
            .transpose()?;

        let response = self
            .call_with_session(
                session_token,
                "tasks.modify",
                modify_task_cmd(
                    &task_id,
                    ModifyTaskOpts {
                        name: input.name,
                        comment: input.comment,
                        alterable: None,
                        hosts_ordering,
                        schedule_id,
                        schedule_periods: input.schedule_periods,
                        target_id,
                        config_id,
                        scanner_id,
                        alert_ids,
                        observers: input.observers,
                        preferences: input.preferences,
                    },
                ),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_task(session_token, id).await
    }

    async fn delete_task(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.delete",
                delete_task_cmd(&parse_entity_id(id)?, ultimate),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn start_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.start",
                start_task_cmd(&parse_entity_id(id)?),
            )
            .await?;
        let parsed = StartTaskResponse::from_response(&response).map_err(map_parse_error)?;
        let report_id = parsed.report_id.map(|id| id.to_string()).ok_or_else(|| {
            GatewayError::BackendUnavailable("start_task did not return a report_id".to_string())
        })?;
        Ok(TaskAction { report_id })
    }

    async fn stop_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.stop",
                stop_task_cmd(&parse_entity_id(id)?),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn resume_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.resume",
                resume_task_cmd(&parse_entity_id(id)?),
            )
            .await?;
        let parsed = ResumeTaskResponse::from_response(&response).map_err(map_parse_error)?;
        let report_id = parsed.report_id.map(|id| id.to_string()).ok_or_else(|| {
            GatewayError::BackendUnavailable("resume_task did not return a report_id".to_string())
        })?;
        Ok(TaskAction { report_id })
    }

    async fn list_audits(
        &self,
        session_token: &str,
        query: &TaskQuery,
    ) -> Result<TaskPage, GatewayError> {
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
                "audits.list",
                get_audits(GetTasksOpts {
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
                    schedules_only: None,
                    ignore_pagination: None,
                }),
            )
            .await?;
        let parsed = GetTasksResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(task_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(TaskPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_audit(
        &self,
        session_token: &str,
        input: CreateTaskInput,
    ) -> Result<String, GatewayError> {
        let config_id = parse_entity_id(&input.scan_config_id)?;
        let target_id = parse_entity_id(&input.target_id)?;
        let scanner_id = parse_entity_id(&input.scanner_id)?;
        let schedule_id = input
            .schedule_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let alert_ids = input
            .alert_ids
            .iter()
            .map(|id| parse_entity_id(id))
            .collect::<Result<Vec<_>, _>>()?;
        let hosts_ordering = input
            .hosts_ordering
            .as_deref()
            .map(parse_hosts_ordering)
            .transpose()?;

        let response = self
            .call_with_session(
                session_token,
                "audits.create",
                create_audit(
                    &input.name,
                    &config_id,
                    &target_id,
                    &scanner_id,
                    CreateTaskOpts {
                        alterable: input.alterable,
                        hosts_ordering,
                        schedule_id,
                        alert_ids,
                        comment: input.comment,
                        schedule_periods: input.schedule_periods,
                        observers: input.observers,
                        preferences: input.preferences,
                    },
                ),
            )
            .await?;
        let parsed = CreateTaskResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn modify_audit(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        let task_id = parse_entity_id(id)?;
        let target_id = input
            .target_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let config_id = input
            .scan_config_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let scanner_id = input
            .scanner_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let schedule_id = input
            .schedule_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let alert_ids = input
            .alert_ids
            .map(|ids| {
                ids.iter()
                    .map(|id| parse_entity_id(id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let hosts_ordering = input
            .hosts_ordering
            .as_deref()
            .map(parse_hosts_ordering)
            .transpose()?;

        let response = self
            .call_with_session(
                session_token,
                "audits.modify",
                modify_audit_cmd(
                    &task_id,
                    ModifyTaskOpts {
                        name: input.name,
                        comment: input.comment,
                        alterable: None,
                        hosts_ordering,
                        schedule_id,
                        schedule_periods: input.schedule_periods,
                        target_id,
                        config_id,
                        scanner_id,
                        alert_ids,
                        observers: input.observers,
                        preferences: input.preferences,
                    },
                ),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_audit(session_token, id).await
    }

    async fn delete_audit(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "audits.delete",
                delete_audit_cmd(&parse_entity_id(id)?),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn get_audit(&self, session_token: &str, id: &str) -> Result<Task, GatewayError> {
        // Fetch through the audit-scoped `get_tasks usage_type="audit"` command
        // filtered to this id, so a scan-task id is not readable as an audit.
        let _ = parse_entity_id(id)?;
        let response = self
            .call_with_session(
                session_token,
                "audits.get",
                get_audits(GetTasksOpts {
                    filter_string: Some(format!("uuid={id}")),
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                    schedules_only: None,
                    ignore_pagination: Some(true),
                }),
            )
            .await?;
        let parsed = GetTasksResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(task_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("audit {id} not found")))
    }

    async fn start_audit(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError> {
        // Enforce the audit discriminator before acting on the resource.
        self.get_audit(session_token, id).await?;
        let response = self
            .call_with_session(
                session_token,
                "audits.start",
                start_audit_cmd(&parse_entity_id(id)?),
            )
            .await?;
        let parsed = StartTaskResponse::from_response(&response).map_err(map_parse_error)?;
        let report_id = parsed.report_id.map(|id| id.to_string()).ok_or_else(|| {
            GatewayError::BackendUnavailable("start_audit did not return a report_id".to_string())
        })?;
        Ok(TaskAction { report_id })
    }

    async fn stop_audit(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.get_audit(session_token, id).await?;
        let response = self
            .call_with_session(
                session_token,
                "audits.stop",
                stop_audit_cmd(&parse_entity_id(id)?),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn resume_audit(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        self.get_audit(session_token, id).await?;
        let response = self
            .call_with_session(
                session_token,
                "audits.resume",
                resume_audit_cmd(&parse_entity_id(id)?),
            )
            .await?;
        let parsed = ResumeTaskResponse::from_response(&response).map_err(map_parse_error)?;
        let report_id = parsed.report_id.map(|id| id.to_string()).ok_or_else(|| {
            GatewayError::BackendUnavailable("resume_audit did not return a report_id".to_string())
        })?;
        Ok(TaskAction { report_id })
    }
}
