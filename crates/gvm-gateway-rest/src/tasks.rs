// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Task DTOs, request parsing, handlers, and response mapping for the REST adapter.

use std::collections::HashMap;

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceCreatedResponse, ResourceRefResponse},
    error::RestError,
    handler::{
        clone_resource, create_resource, delete_resource, delete_resource_without_ultimate,
        get_resource, list_resource, update_resource, validate_uuid, ValidateInto,
    },
    open_enum::open_string_enum,
    openapi::{
        created_json, ok_json, problem_response, CreateTaskDoc, ModifyTaskDoc, ResourceIdPathDoc,
        TaskListQueryDoc,
    },
    query::{parse_collection_query, DeleteResourceQueryParams},
    router::bearer_token,
};

// Re-export domain types used by tests and other modules.
pub use gvm_gateway_domain::{
    CreateTaskInput, ModifyTaskInput, Task, TaskAction, TaskPage, TaskQuery,
};

// ============================================================================
// Response DTOs
// ============================================================================

open_string_enum! {
    /// Hosts ordering strategy.
    pub(crate) enum HostsOrdering {
        Sequential => "sequential",
        Random => "random",
        Reverse => "reverse",
    }
}

open_string_enum! {
    /// Task lifecycle status.
    pub(crate) enum TaskStatus {
        New => "New",
        Requested => "Requested",
        Queued => "Queued",
        Running => "Running",
        StopRequested => "Stop Requested",
        Stopping => "Stopping",
        Processing => "Processing",
        Done => "Done",
        Stopped => "Stopped",
        Error => "Error",
        DeleteRequested => "Delete Requested",
        UltimateDeleteRequested => "Ultimate Delete Requested",
        Container => "Container",
        Interrupted => "Interrupted",
    }
}

/// Observer principals returned for a task.
#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
#[schemars(rename = "TaskObservers")]
pub(crate) struct TaskObserversResponse {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    users: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    groups: Vec<ResourceRefResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    roles: Vec<ResourceRefResponse>,
}

impl TaskObserversResponse {
    fn is_empty(&self) -> bool {
        self.users.is_empty() && self.groups.is_empty() && self.roles.is_empty()
    }
}

impl From<gvm_gateway_domain::TaskObservers> for TaskObserversResponse {
    fn from(observers: gvm_gateway_domain::TaskObservers) -> Self {
        Self {
            users: observers.users,
            groups: observers
                .groups
                .into_iter()
                .map(ResourceRefResponse::from)
                .collect(),
            roles: observers
                .roles
                .into_iter()
                .map(ResourceRefResponse::from)
                .collect(),
        }
    }
}

/// JSON body returned for a single task.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Task")]
pub(crate) struct TaskResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<ResourceRefResponse>,
    #[serde(rename = "scanConfig", skip_serializing_if = "Option::is_none")]
    scan_config: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scanner: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schedule: Option<ResourceRefResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    alerts: Vec<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alterable: Option<bool>,
    #[serde(rename = "hostsOrdering", skip_serializing_if = "Option::is_none")]
    hosts_ordering: Option<HostsOrdering>,
    #[serde(skip_serializing_if = "TaskObserversResponse::is_empty")]
    observers: TaskObserversResponse,
    #[serde(rename = "schedulePeriods", skip_serializing_if = "Option::is_none")]
    schedule_periods: Option<u32>,
    #[serde(rename = "lastReport", skip_serializing_if = "Option::is_none")]
    last_report: Option<ResourceRefResponse>,
    #[serde(rename = "currentReport", skip_serializing_if = "Option::is_none")]
    current_report: Option<ResourceRefResponse>,
    #[serde(rename = "reportCount", skip_serializing_if = "Option::is_none")]
    report_count: Option<u32>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<gvm_gateway_domain::Task> for TaskResponse {
    fn from(t: gvm_gateway_domain::Task) -> Self {
        Self {
            id: parse_uuid(&t.id),
            name: t.name,
            comment: t.comment,
            status: TaskStatus::parse(&t.status),
            progress: t.progress,
            target: t.target.map(ResourceRefResponse::from),
            scan_config: t.scan_config.map(ResourceRefResponse::from),
            scanner: t.scanner.map(ResourceRefResponse::from),
            schedule: t.schedule.map(ResourceRefResponse::from),
            alerts: t
                .alerts
                .into_iter()
                .map(ResourceRefResponse::from)
                .collect(),
            alterable: t.alterable,
            hosts_ordering: t.hosts_ordering.as_deref().map(HostsOrdering::parse),
            observers: TaskObserversResponse::from(t.observers),
            schedule_periods: t.schedule_periods,
            last_report: t.last_report.map(ResourceRefResponse::from),
            current_report: t.current_report.map(ResourceRefResponse::from),
            report_count: t.report_count,
            in_use: t.in_use,
            writable: t.writable,
        }
    }
}

/// JSON body returned for a paginated list of tasks.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TaskList")]
pub(crate) struct TaskListResponse {
    data: Vec<TaskResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::TaskPage> for TaskListResponse {
    fn from(page: gvm_gateway_domain::TaskPage) -> Self {
        Self {
            data: page.data.into_iter().map(TaskResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// JSON body returned for a task start/resume action.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TaskAction")]
pub(crate) struct TaskActionResponse {
    #[serde(rename = "reportId")]
    report_id: Uuid,
}

impl From<gvm_gateway_domain::TaskAction> for TaskActionResponse {
    fn from(a: gvm_gateway_domain::TaskAction) -> Self {
        Self {
            report_id: parse_uuid(&a.report_id),
        }
    }
}

/// Parsed list-tasks query from HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskListQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl TaskListQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let parsed = parse_collection_query(query)?;

        Ok(Self {
            filter_string: parsed.filter_string,
            filter_id: parsed.filter_id,
            page: parsed.page,
            per_page: parsed.per_page,
        })
    }
}

/// Create-task request payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CreateTaskRequest {
    /// Task name (required).
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Target identifier (required).
    #[serde(rename = "targetId")]
    pub target_id: Option<String>,
    /// Scan config identifier (required).
    #[serde(rename = "scanConfigId")]
    pub scan_config_id: Option<String>,
    /// Scanner identifier (required).
    #[serde(rename = "scannerId")]
    pub scanner_id: Option<String>,
    /// Optional schedule identifier.
    #[serde(rename = "scheduleId")]
    pub schedule_id: Option<String>,
    /// Optional alert identifiers.
    #[serde(rename = "alertIds", default)]
    pub alert_ids: Vec<String>,
    /// Optional alterable flag.
    pub alterable: Option<bool>,
    /// Optional hosts ordering.
    #[serde(rename = "hostsOrdering")]
    pub hosts_ordering: Option<String>,
    /// Optional observers.
    #[serde(default)]
    pub observers: Vec<String>,
    /// Optional schedule periods.
    #[serde(rename = "schedulePeriods")]
    pub schedule_periods: Option<u32>,
    /// Optional key-value scan preferences. Omitted or empty objects leave preferences unchanged.
    #[serde(default)]
    pub preferences: HashMap<String, String>,
}

impl CreateTaskRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<CreateTaskInput, GatewayError> {
        let name = self
            .name
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))?;
        let target_id = self
            .target_id
            .ok_or_else(|| GatewayError::InvalidInput("targetId is required".to_string()))?;
        validate_uuid("targetId", &target_id)?;
        let scan_config_id = self
            .scan_config_id
            .ok_or_else(|| GatewayError::InvalidInput("scanConfigId is required".to_string()))?;
        validate_uuid("scanConfigId", &scan_config_id)?;
        let scanner_id = self
            .scanner_id
            .ok_or_else(|| GatewayError::InvalidInput("scannerId is required".to_string()))?;
        validate_uuid("scannerId", &scanner_id)?;
        validate_optional_uuid("scheduleId", self.schedule_id.as_deref())?;
        for (index, alert_id) in self.alert_ids.iter().enumerate() {
            validate_uuid(&format!("alertIds[{index}]"), alert_id)?;
        }

        Ok(CreateTaskInput {
            name,
            comment: self.comment,
            target_id,
            scan_config_id,
            scanner_id,
            schedule_id: self.schedule_id,
            alert_ids: self.alert_ids,
            alterable: self.alterable,
            hosts_ordering: self.hosts_ordering,
            observers: self.observers,
            schedule_periods: self.schedule_periods,
            preferences: self.preferences.into_iter().collect(),
        })
    }
}

impl ValidateInto<CreateTaskInput> for CreateTaskRequest {
    fn validate_into(self) -> Result<CreateTaskInput, GatewayError> {
        self.validate()
    }
}

/// Modify-task request payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ModifyTaskRequest {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional target identifier.
    #[serde(rename = "targetId")]
    pub target_id: Option<String>,
    /// Optional scan config identifier.
    #[serde(rename = "scanConfigId")]
    pub scan_config_id: Option<String>,
    /// Optional scanner identifier.
    #[serde(rename = "scannerId")]
    pub scanner_id: Option<String>,
    /// Optional schedule identifier.
    #[serde(rename = "scheduleId")]
    pub schedule_id: Option<String>,
    /// Optional alert identifiers.
    #[serde(rename = "alertIds")]
    pub alert_ids: Option<Vec<String>>,
    /// Optional hosts ordering.
    #[serde(rename = "hostsOrdering")]
    pub hosts_ordering: Option<String>,
    /// Optional observers.
    #[serde(default)]
    pub observers: Vec<String>,
    /// Optional schedule periods.
    #[serde(rename = "schedulePeriods")]
    pub schedule_periods: Option<u32>,
    /// Optional key-value scan preferences.
    #[serde(default)]
    pub preferences: HashMap<String, String>,
}

impl ModifyTaskRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<ModifyTaskInput, GatewayError> {
        validate_optional_uuid("targetId", self.target_id.as_deref())?;
        validate_optional_uuid("scanConfigId", self.scan_config_id.as_deref())?;
        validate_optional_uuid("scannerId", self.scanner_id.as_deref())?;
        validate_optional_uuid("scheduleId", self.schedule_id.as_deref())?;
        if let Some(ref alert_ids) = self.alert_ids {
            for (index, alert_id) in alert_ids.iter().enumerate() {
                validate_uuid(&format!("alertIds[{index}]"), alert_id)?;
            }
        }

        Ok(ModifyTaskInput {
            name: self.name,
            comment: self.comment,
            target_id: self.target_id,
            scan_config_id: self.scan_config_id,
            scanner_id: self.scanner_id,
            schedule_id: self.schedule_id,
            alert_ids: self.alert_ids,
            hosts_ordering: self.hosts_ordering,
            observers: self.observers,
            schedule_periods: self.schedule_periods,
            preferences: self.preferences.into_iter().collect(),
        })
    }
}

impl ValidateInto<ModifyTaskInput> for ModifyTaskRequest {
    fn validate_into(self) -> Result<ModifyTaskInput, GatewayError> {
        self.validate()
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// List tasks handler.
pub async fn list_tasks(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        TaskListQuery::try_from_query_string,
        |service, session, query| async move {
            service
                .list_tasks(
                    &session,
                    TaskQuery {
                        filter_string: query.filter_string,
                        filter_id: query.filter_id,
                        page: query.page,
                        per_page: query.per_page,
                    },
                )
                .await
        },
        TaskListResponse::from,
    )
    .await
}

/// Create task handler.
pub async fn create_task(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateTaskInput, CreateTaskRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_task(&session, input).await },
    )
    .await
}

/// Clone task handler.
pub async fn clone_task(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    clone_resource(
        service,
        headers,
        id,
        uri,
        "/api/v1/tasks",
        |service, session, id| async move { service.clone_task(&session, &id).await },
    )
    .await
}

/// Get task handler.
pub async fn get_task(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id| async move { service.get_task(&session, &id).await },
        TaskResponse::from,
    )
    .await
}

/// Update task handler.
pub async fn update_task(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyTaskInput, ModifyTaskRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move { service.modify_task(&session, &id, input).await },
        TaskResponse::from,
    )
    .await
}

/// Delete task handler.
pub async fn delete_task(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id, ultimate| async move {
            service.delete_task(&session, &id, ultimate).await
        },
    )
    .await
}

/// Start task handler.
pub async fn start_task(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.start_task(&session, &id).await {
        Ok(action) => (StatusCode::OK, Json(TaskActionResponse::from(action))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Stop task handler.
pub async fn stop_task(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.stop_task(&session, &id).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Resume task handler.
pub async fn resume_task(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.resume_task(&session, &id).await {
        Ok(action) => (StatusCode::OK, Json(TaskActionResponse::from(action))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

// ============================================================================
// Validation Helpers
// ============================================================================

fn validate_optional_uuid(field: &str, value: Option<&str>) -> Result<(), GatewayError> {
    if let Some(value) = value {
        validate_uuid(field, value)?;
    }
    Ok(())
}

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `GET /api/v1/tasks`.
pub(crate) fn list_tasks_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTasks")
        .tag("Tasks")
        .summary("List tasks")
        .description("Returns a paginated list of tasks.")
        .security_requirement("bearerAuth")
        .input::<Query<TaskListQueryDoc>>()
        .response_with::<200, Json<TaskListResponse>, _>(ok_json("Paginated list of tasks"));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `POST /api/v1/tasks`.
pub(crate) fn create_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createTask")
        .tag("Tasks")
        .summary("Create a task")
        .description("Creates a new scan task.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateTaskDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Task created"));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `POST /api/v1/tasks/{id}/clone`.
pub(crate) fn clone_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("cloneTask")
        .tag("Tasks")
        .summary("Clone a task")
        .description("Clones an existing task. Returns the identifier of the new task.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Task cloned"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `GET /api/v1/tasks/{id}`.
pub(crate) fn get_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTask")
        .tag("Tasks")
        .summary("Get a task")
        .description("Returns the details for a single task.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskResponse>, _>(ok_json("Task details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `PUT /api/v1/tasks/{id}`.
pub(crate) fn update_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyTask")
        .tag("Tasks")
        .summary("Modify a task")
        .description("Updates an existing task.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyTaskDoc>)>()
        .response_with::<200, Json<TaskResponse>, _>(ok_json("Task updated"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/tasks/{id}`.
pub(crate) fn delete_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteTask")
        .tag("Tasks")
        .summary("Delete a task")
        .description("Deletes a task. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Task deleted"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `POST /api/v1/tasks/{id}/start`.
pub(crate) fn start_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("startTask")
        .tag("Tasks")
        .summary("Start a task")
        .description("Starts a scan task. Returns the report identifier created by the action.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskActionResponse>, _>(ok_json("Task started"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<409>(op, "Resource state conflict");
    problem_response::<504>(op, "Backend service did not respond in time")
}

/// OpenAPI transform for `POST /api/v1/tasks/{id}/stop`.
pub(crate) fn stop_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("stopTask")
        .tag("Tasks")
        .summary("Stop a running task")
        .description("Stops a currently running scan task.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, (), _>(|response| response.description("Task stopped"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<409>(op, "Resource state conflict")
}

/// OpenAPI transform for `POST /api/v1/tasks/{id}/resume`.
pub(crate) fn resume_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("resumeTask")
        .tag("Tasks")
        .summary("Resume a stopped task")
        .description("Resumes a stopped scan task. Returns the report identifier.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskActionResponse>, _>(ok_json("Task resumed"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<409>(op, "Resource state conflict")
}

// ============================================================================
// Audit handlers (compliance tasks; reuse Task DTOs)
// ============================================================================

/// List audits handler.
pub async fn list_audits(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        TaskListQuery::try_from_query_string,
        |service, session, query| async move {
            service
                .list_audits(
                    &session,
                    TaskQuery {
                        filter_string: query.filter_string,
                        filter_id: query.filter_id,
                        page: query.page,
                        per_page: query.per_page,
                    },
                )
                .await
        },
        TaskListResponse::from,
    )
    .await
}

/// Create audit handler.
pub async fn create_audit(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateTaskInput, CreateTaskRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_audit(&session, input).await },
    )
    .await
}

/// Update audit handler.
pub async fn update_audit(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyTaskInput, ModifyTaskRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_audit(&session, &id, input).await
        },
        TaskResponse::from,
    )
    .await
}

/// Delete audit handler. Audits are always deleted non-ultimately by the backend.
pub async fn delete_audit(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource_without_ultimate(
        service,
        headers,
        id,
        uri,
        |service, session, id| async move { service.delete_audit(&session, &id).await },
    )
    .await
}

/// Get audit handler. Scoped to the audit usage type so a scan task is not
/// readable through this route.
pub async fn get_audit(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id| async move { service.get_audit(&session, &id).await },
        TaskResponse::from,
    )
    .await
}

/// Start audit handler.
pub async fn start_audit(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.start_audit(&session, &id).await {
        Ok(action) => (StatusCode::OK, Json(TaskActionResponse::from(action))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Stop audit handler.
pub async fn stop_audit(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.stop_audit(&session, &id).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Resume audit handler.
pub async fn resume_audit(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.resume_audit(&session, &id).await {
        Ok(action) => (StatusCode::OK, Json(TaskActionResponse::from(action))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// OpenAPI transform for `GET /api/v1/audits`.
pub(crate) fn list_audits_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getAudits")
        .tag("Audits")
        .summary("List audits")
        .description("Returns a paginated list of compliance audits.")
        .security_requirement("bearerAuth")
        .input::<Query<TaskListQueryDoc>>()
        .response_with::<200, Json<TaskListResponse>, _>(ok_json("Paginated list of audits"));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `POST /api/v1/audits`.
pub(crate) fn create_audit_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createAudit")
        .tag("Audits")
        .summary("Create an audit")
        .description("Creates a new compliance audit.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateTaskDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Audit created"));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/audits/{id}`.
pub(crate) fn get_audit_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getAudit")
        .tag("Audits")
        .summary("Get an audit")
        .description("Returns the details for a single compliance audit.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskResponse>, _>(ok_json("Audit details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `PUT /api/v1/audits/{id}`.
pub(crate) fn update_audit_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyAudit")
        .tag("Audits")
        .summary("Modify an audit")
        .description("Updates an existing compliance audit.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyTaskDoc>)>()
        .response_with::<200, Json<TaskResponse>, _>(ok_json("Audit updated"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/audits/{id}`.
pub(crate) fn delete_audit_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteAudit")
        .tag("Audits")
        .summary("Delete an audit")
        .description("Deletes a compliance audit.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Audit deleted"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `POST /api/v1/audits/{id}/start`.
pub(crate) fn start_audit_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("startAudit")
        .tag("Audits")
        .summary("Start an audit")
        .description(
            "Starts a compliance audit. Returns the report identifier created by the action.",
        )
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskActionResponse>, _>(ok_json("Audit started"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<409>(op, "Resource state conflict");
    problem_response::<504>(op, "Backend service did not respond in time")
}

/// OpenAPI transform for `POST /api/v1/audits/{id}/stop`.
pub(crate) fn stop_audit_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("stopAudit")
        .tag("Audits")
        .summary("Stop a running audit")
        .description("Stops a currently running compliance audit.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, (), _>(|response| response.description("Audit stopped"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<409>(op, "Resource state conflict")
}

/// OpenAPI transform for `POST /api/v1/audits/{id}/resume`.
pub(crate) fn resume_audit_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("resumeAudit")
        .tag("Audits")
        .summary("Resume a stopped audit")
        .description("Resumes a stopped compliance audit. Returns the report identifier.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskActionResponse>, _>(ok_json("Audit resumed"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<409>(op, "Resource state conflict")
}

#[cfg(test)]
#[path = "tasks_test.rs"]
mod tasks_test;
