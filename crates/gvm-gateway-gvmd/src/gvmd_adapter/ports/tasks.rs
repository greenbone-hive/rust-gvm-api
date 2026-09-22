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
        let parsed = self
            .execute_with_session(
                session_token,
                "tasks.list",
                GetTasksRequest {
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
                },
            )
            .await?;
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
        let CreateTaskInput {
            name,
            comment,
            target,
            schedule_id,
            alert_ids,
            alterable,
            observers,
            schedule_periods,
            preferences,
        } = input;
        let schedule_id = schedule_id.as_deref().map(parse_entity_id).transpose()?;
        let alert_ids = alert_ids
            .iter()
            .map(|id| parse_entity_id(id))
            .collect::<Result<Vec<_>, _>>()?;

        let parsed = match target {
            CreateTaskTarget::Classic {
                target_id,
                scan_config_id,
                scanner_id,
            } => {
                let mut request = CreateTaskRequest::new(
                    name,
                    parse_entity_id(&scan_config_id)?,
                    parse_entity_id(&target_id)?,
                    parse_entity_id(&scanner_id)?,
                );
                request.comment = comment;
                request.alterable = alterable;
                request.schedule_id = schedule_id;
                request.alert_ids = alert_ids;
                request.schedule_periods = schedule_periods;
                request.observers = observers;
                request.preferences = preferences
                    .into_iter()
                    .map(|(name, value)| TaskPreference::new(name, value))
                    .collect();
                self.execute_with_session(session_token, "tasks.create", request)
                    .await?
            }
            CreateTaskTarget::AgentGroup {
                agent_group_id,
                scanner_id,
            } => {
                self.execute_with_session(
                    session_token,
                    "tasks.create",
                    CreateAgentGroupTaskRequest::new(
                        name,
                        parse_entity_id(&agent_group_id)?,
                        parse_entity_id(&scanner_id)?,
                        CreateAgentGroupTaskOpts {
                            comment,
                            alterable,
                            schedule_id,
                            alert_ids,
                            schedule_periods,
                            observers,
                            observer_group_ids: Vec::new(),
                            preferences,
                        },
                    ),
                )
                .await?
            }
            CreateTaskTarget::OciImage {
                oci_image_target_id,
                scanner_id,
            } => {
                self.execute_with_session(
                    session_token,
                    "tasks.create",
                    CreateOciImageTargetTaskRequest::new(
                        name,
                        parse_entity_id(&oci_image_target_id)?,
                        parse_entity_id(&scanner_id)?,
                        CreateOciImageTargetTaskOpts {
                            comment,
                            alterable,
                            schedule_id,
                            alert_ids,
                            schedule_periods,
                            observers,
                            observer_group_ids: Vec::new(),
                            preferences,
                        },
                    ),
                )
                .await?
            }
            CreateTaskTarget::WebApplication {
                web_application_target_id,
                scanner_id,
            } => {
                self.execute_with_session(
                    session_token,
                    "tasks.create",
                    CreateWebApplicationTaskRequest::new(
                        name,
                        parse_entity_id(&web_application_target_id)?,
                        parse_entity_id(&scanner_id)?,
                        CreateWebApplicationTaskOpts {
                            alterable,
                            schedule_id,
                            alert_ids,
                            comment,
                            schedule_periods,
                            observers,
                            observer_group_ids: Vec::new(),
                            preferences,
                        },
                    ),
                )
                .await?
            }
            CreateTaskTarget::Import => {
                if schedule_id.is_some()
                    || !alert_ids.is_empty()
                    || alterable.is_some()
                    || !observers.is_empty()
                    || schedule_periods.is_some()
                    || !preferences.is_empty()
                {
                    return Err(GatewayError::InvalidInput(
                        "import tasks accept only type, name, and comment".to_string(),
                    ));
                }
                self.execute_with_session(
                    session_token,
                    "tasks.create",
                    CreateImportTaskRequest::new(name, comment),
                )
                .await?
            }
        };
        Ok(parsed.id.to_string())
    }

    async fn clone_task(&self, session_token: &str, id: &str) -> Result<String, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "tasks.clone",
                CloneTaskRequest::new(parse_entity_id(id)?),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn get_task(&self, session_token: &str, id: &str) -> Result<Task, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "tasks.get",
                GetTaskRequest::new(parse_entity_id(id)?),
            )
            .await?;
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
            .transpose()?
            .map(ScalarUpdate::Set)
            .unwrap_or_default();
        let alert_ids = input
            .alert_ids
            .map(|ids| {
                ids.iter()
                    .map(|id| parse_entity_id(id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let mut request = ModifyTaskRequest::new(task_id);
        request.name = input.name;
        request.comment = input.comment;
        request.alterable = input.alterable;
        request.schedule_id = schedule_id;
        request.schedule_periods = input.schedule_periods;
        request.target_id = target_id;
        request.config_id = config_id;
        request.scanner_id = scanner_id;
        request.alert_ids = alert_ids.map(CollectionUpdate::Replace).unwrap_or_default();
        request.observers = CollectionUpdate::Replace(input.observers);
        request.preferences = input
            .preferences
            .into_iter()
            .map(|(name, value)| TaskPreference::new(name, value))
            .collect();
        self.execute_with_session(session_token, "tasks.modify", request)
            .await?;
        self.get_task(session_token, id).await
    }

    async fn delete_task(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "tasks.delete",
            DeleteTaskRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn start_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "tasks.start",
                StartTaskRequest::new(parse_entity_id(id)?),
            )
            .await?;
        let report_id = parsed.report_id.map(|id| id.to_string()).ok_or_else(|| {
            GatewayError::BackendUnavailable("start_task did not return a report_id".to_string())
        })?;
        Ok(TaskAction { report_id })
    }

    async fn stop_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "tasks.stop",
            StopTaskRequest::new(parse_entity_id(id)?),
        )
        .await?;
        Ok(())
    }

    async fn resume_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "tasks.resume",
                ResumeTaskRequest::new(parse_entity_id(id)?),
            )
            .await?;
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
        let parsed = self
            .execute_with_session(
                session_token,
                "audits.list",
                GetAuditsRequest::new(GetTasksOpts {
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
        let CreateTaskTarget::Classic {
            target_id,
            scan_config_id,
            scanner_id,
        } = input.target
        else {
            return Err(GatewayError::InvalidInput(
                "audits require targetId, scanConfigId, and scannerId".to_string(),
            ));
        };
        let config_id = parse_entity_id(&scan_config_id)?;
        let target_id = parse_entity_id(&target_id)?;
        let scanner_id = parse_entity_id(&scanner_id)?;
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
        let parsed = self
            .execute_with_session(
                session_token,
                "audits.create",
                CreateAuditRequest::new(
                    input.name,
                    config_id,
                    target_id,
                    scanner_id,
                    CreateTaskOpts {
                        alterable: input.alterable,
                        schedule_id,
                        alert_ids,
                        comment: input.comment,
                        schedule_periods: input.schedule_periods,
                        observers: input.observers,
                        observer_group_ids: Vec::new(),
                        preferences: input.preferences,
                    },
                ),
            )
            .await?;
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
            .transpose()?
            .map(ScalarUpdate::Set)
            .unwrap_or_default();
        let alert_ids = input
            .alert_ids
            .map(|ids| {
                ids.iter()
                    .map(|id| parse_entity_id(id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let request = ModifyAuditRequest::new(
            task_id,
            ModifyTaskOpts {
                name: input.name,
                comment: input.comment,
                alterable: input.alterable,
                schedule_id,
                schedule_periods: input.schedule_periods,
                target_id,
                config_id,
                scanner_id,
                alert_ids,
                observers: CollectionUpdate::Replace(input.observers),
                observer_group_ids: CollectionUpdate::Omitted,
                preferences: input.preferences,
            },
        )
        .map_err(|error| GatewayError::InvalidInput(error.to_string()))?;
        self.execute_with_session(session_token, "audits.modify", request)
            .await?;
        self.get_audit(session_token, id).await
    }

    async fn delete_audit(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "audits.delete",
            DeleteAuditRequest::new(parse_entity_id(id)?),
        )
        .await?;
        Ok(())
    }

    async fn get_audit(&self, session_token: &str, id: &str) -> Result<Task, GatewayError> {
        // Fetch through the audit-scoped `get_tasks usage_type="audit"` command
        // filtered to this id, so a scan-task id is not readable as an audit.
        let _ = parse_entity_id(id)?;
        let parsed = self
            .execute_with_session(
                session_token,
                "audits.get",
                GetAuditsRequest::new(GetTasksOpts {
                    filter_string: Some(format!("uuid={id}")),
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                    schedules_only: None,
                    ignore_pagination: Some(true),
                }),
            )
            .await?;
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
        let parsed = self
            .execute_with_session(
                session_token,
                "audits.start",
                StartAuditRequest::new(parse_entity_id(id)?),
            )
            .await?;
        let report_id = parsed.report_id.map(|id| id.to_string()).ok_or_else(|| {
            GatewayError::BackendUnavailable("start_audit did not return a report_id".to_string())
        })?;
        Ok(TaskAction { report_id })
    }

    async fn stop_audit(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.get_audit(session_token, id).await?;
        self.execute_with_session(
            session_token,
            "audits.stop",
            StopAuditRequest::new(parse_entity_id(id)?),
        )
        .await?;
        Ok(())
    }

    async fn resume_audit(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        self.get_audit(session_token, id).await?;
        let parsed = self
            .execute_with_session(
                session_token,
                "audits.resume",
                ResumeAuditRequest::new(parse_entity_id(id)?),
            )
            .await?;
        let report_id = parsed.report_id.map(|id| id.to_string()).ok_or_else(|| {
            GatewayError::BackendUnavailable("resume_audit did not return a report_id".to_string())
        })?;
        Ok(TaskAction { report_id })
    }
}
