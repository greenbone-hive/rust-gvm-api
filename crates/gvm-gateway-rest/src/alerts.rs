// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Alert DTOs and handlers for the REST adapter.

#![allow(missing_docs)]

use std::collections::HashMap;

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceCreatedResponse, ResourceRefResponse},
    handler::{
        create_resource, delete_resource, get_resource, list_resource, update_resource,
        ValidateInto,
    },
    open_enum::{closed_string_enum_schema, open_string_enum, open_string_enum_schema},
    openapi::{created_json, ok_json, problem_response, ResourceIdPathDoc, TargetListQueryDoc},
    query::{CollectionListQuery, DeleteResourceQueryParams},
    targets::validate_uuid,
};

pub use gvm_gateway_domain::{Alert, AlertPage, AlertQuery, CreateAlertInput, ModifyAlertInput};

fn alert_event_request_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    closed_string_enum_schema("AlertEventRequest", AlertEvent::known_values())
}

fn alert_condition_request_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    closed_string_enum_schema("AlertConditionRequest", AlertCondition::known_values())
}

fn alert_method_request_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    closed_string_enum_schema("AlertMethodRequest", AlertMethod::known_values())
}

fn alert_event_response_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    open_string_enum_schema("AlertEventResponse", AlertEvent::known_values())
}

fn alert_condition_response_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    open_string_enum_schema("AlertConditionResponse", AlertCondition::known_values())
}

fn alert_method_response_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    open_string_enum_schema("AlertMethodResponse", AlertMethod::known_values())
}

open_string_enum! {
    /// Alert event selector.
    pub(crate) enum AlertEvent {
        TaskRunStatusChanged => "task_run_status_changed",
        UpdatedSecInfo => "updated_secinfo",
        NewSecInfo => "new_secinfo",
    }
}

open_string_enum! {
    /// Alert condition selector.
    pub(crate) enum AlertCondition {
        Always => "always",
        FilterCountAtLeast => "filter_count_at_least",
        FilterCountChanged => "filter_count_changed",
        SeverityAtLeast => "severity_at_least",
        SeverityChanged => "severity_changed",
    }
}

open_string_enum! {
    /// Alert delivery method.
    pub(crate) enum AlertMethod {
        Email => "email",
        HttpGet => "http_get",
        Scp => "scp",
        SendEmail => "send_email",
        Smb => "smb",
        Snmp => "snmp",
        SourcefireConnector => "sourcefire_connector",
        StartTask => "start_task",
        Syslog => "syslog",
        Tippingpoint => "tippingpoint",
        VeriniceCe => "verinice_ce",
        VeriniceNet => "verinice_net",
        Alemba => "alemba",
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Alert")]
pub(crate) struct AlertResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(required)]
    #[schemars(schema_with = "alert_event_response_schema")]
    event: Option<AlertEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(required)]
    #[schemars(schema_with = "alert_condition_response_schema")]
    condition: Option<AlertCondition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(required)]
    #[schemars(schema_with = "alert_method_response_schema")]
    method: Option<AlertMethod>,
    #[serde(
        rename = "eventData",
        default,
        skip_serializing_if = "HashMap::is_empty"
    )]
    event_data: HashMap<String, String>,
    #[serde(
        rename = "conditionData",
        default,
        skip_serializing_if = "HashMap::is_empty"
    )]
    condition_data: HashMap<String, String>,
    #[serde(
        rename = "methodData",
        default,
        skip_serializing_if = "HashMap::is_empty"
    )]
    method_data: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<ResourceRefResponse>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<Alert> for AlertResponse {
    fn from(alert: Alert) -> Self {
        Self {
            id: parse_uuid(&alert.id),
            name: alert.name,
            comment: alert.comment,
            event: alert.event.as_deref().map(AlertEvent::parse),
            condition: alert.condition.as_deref().map(AlertCondition::parse),
            method: alert.method.as_deref().map(AlertMethod::parse),
            event_data: alert.event_data,
            condition_data: alert.condition_data,
            method_data: alert.method_data,
            filter: alert.filter.map(ResourceRefResponse::from),
            in_use: alert.in_use,
            writable: alert.writable,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AlertList")]
pub(crate) struct AlertListResponse {
    data: Vec<AlertResponse>,
    pagination: PaginationResponse,
}

impl From<AlertPage> for AlertListResponse {
    fn from(page: AlertPage) -> Self {
        Self {
            data: page.data.into_iter().map(AlertResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[schemars(rename = "CreateAlert")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateAlertRequest {
    name: String,
    comment: Option<String>,
    #[schemars(required)]
    #[schemars(schema_with = "alert_event_request_schema")]
    event: Option<AlertEvent>,
    #[schemars(required)]
    #[schemars(schema_with = "alert_condition_request_schema")]
    condition: Option<AlertCondition>,
    #[schemars(required)]
    #[schemars(schema_with = "alert_method_request_schema")]
    method: Option<AlertMethod>,
    #[serde(rename = "eventData", default)]
    event_data: HashMap<String, String>,
    #[serde(rename = "conditionData", default)]
    condition_data: HashMap<String, String>,
    #[serde(rename = "methodData", default)]
    method_data: HashMap<String, String>,
    #[serde(rename = "filterId")]
    #[schemars(with = "Option<Uuid>")]
    filter_id: Option<String>,
}

impl CreateAlertRequest {
    fn validate(self) -> Result<CreateAlertInput, GatewayError> {
        if self.name.trim().is_empty() {
            return Err(GatewayError::InvalidInput("name is required".to_string()));
        }
        if let Some(filter_id) = self.filter_id.as_deref() {
            validate_uuid("filterId", filter_id)?;
        }
        Ok(CreateAlertInput {
            name: self.name,
            comment: self.comment,
            event: self.event.map(|event| event.as_str().to_string()),
            condition: self
                .condition
                .map(|condition| condition.as_str().to_string()),
            method: self.method.map(|method| method.as_str().to_string()),
            event_data: self.event_data,
            condition_data: self.condition_data,
            method_data: self.method_data,
            filter_id: self.filter_id,
        })
    }
}

impl ValidateInto<CreateAlertInput> for CreateAlertRequest {
    fn validate_into(self) -> Result<CreateAlertInput, GatewayError> {
        self.validate()
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "ModifyAlert")]
#[serde(deny_unknown_fields)]
pub struct ModifyAlertRequest {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub event: Option<String>,
    pub condition: Option<String>,
    pub method: Option<String>,
    #[serde(rename = "eventData")]
    pub event_data: Option<HashMap<String, String>>,
    #[serde(rename = "conditionData")]
    pub condition_data: Option<HashMap<String, String>>,
    #[serde(rename = "methodData")]
    pub method_data: Option<HashMap<String, String>>,
    #[serde(rename = "filterId")]
    #[schemars(with = "Option<Uuid>")]
    pub filter_id: Option<String>,
}

impl ModifyAlertRequest {
    fn validate(self) -> Result<ModifyAlertInput, GatewayError> {
        if let Some(filter_id) = self.filter_id.as_deref() {
            validate_uuid("filterId", filter_id)?;
        }
        Ok(ModifyAlertInput {
            name: self.name,
            comment: self.comment,
            event: self.event,
            condition: self.condition,
            method: self.method,
            event_data: self.event_data,
            condition_data: self.condition_data,
            method_data: self.method_data,
            filter_id: self.filter_id,
        })
    }
}

impl ValidateInto<ModifyAlertInput> for ModifyAlertRequest {
    fn validate_into(self) -> Result<ModifyAlertInput, GatewayError> {
        self.validate()
    }
}

pub async fn list_alerts(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        CollectionListQuery::try_from_query_string,
        |service, session, query| async move {
            service
                .list_alerts(
                    &session,
                    AlertQuery {
                        filter_string: query.filter_string,
                        filter_id: query.filter_id,
                        page: query.page,
                        per_page: query.per_page,
                    },
                )
                .await
        },
        AlertListResponse::from,
    )
    .await
}

pub async fn create_alert(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateAlertInput, CreateAlertRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_alert(&session, input).await },
    )
    .await
}

pub async fn get_alert(
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
        |service, session, id| async move { service.get_alert(&session, &id).await },
        AlertResponse::from,
    )
    .await
}

pub async fn update_alert(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyAlertInput, ModifyAlertRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_alert(&session, &id, input).await
        },
        AlertResponse::from,
    )
    .await
}

pub async fn delete_alert(
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
            service.delete_alert(&session, &id, ultimate).await
        },
    )
    .await
}

pub(crate) fn list_alerts_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getAlerts")
        .tag("Alerts")
        .summary("List alerts")
        .description("Returns a paginated list of alerts.")
        .security_requirement("bearerAuth")
        .input::<Query<TargetListQueryDoc>>()
        .response_with::<200, Json<AlertListResponse>, _>(ok_json("Paginated list of alerts"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn create_alert_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createAlert")
        .tag("Alerts")
        .summary("Create an alert")
        .description("Creates a new alert.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateAlertRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Alert created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_alert_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getAlert")
        .tag("Alerts")
        .summary("Get an alert")
        .description("Returns a single alert.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<AlertResponse>, _>(ok_json("Alert details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn update_alert_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyAlert")
        .tag("Alerts")
        .summary("Modify an alert")
        .description("Updates an existing alert.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyAlertRequest>)>()
        .response_with::<200, Json<AlertResponse>, _>(ok_json("Alert updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_alert_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteAlert")
        .tag("Alerts")
        .summary("Delete an alert")
        .description("Deletes an alert. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Alert deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "alerts_test.rs"]
mod alerts_test;
