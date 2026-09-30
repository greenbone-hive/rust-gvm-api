// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{CreateOverrideInput, GatewayError, ModifyOverrideInput};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::{
    require_nvt_oid, supporting_query, validate_optional_uuid, SupportingListQuery,
    SupportingResourceListQueryParams, SupportingResourceMetaResponse,
};
use crate::{
    dto::{PaginationResponse, ResourceCreatedResponse, ResourceRefResponse},
    handler::{
        create_resource, delete_resource, get_resource, list_resource, update_resource,
        ValidateInto,
    },
    openapi::{created_json, ok_json, problem_response, ResourceIdPathDoc},
    query::DeleteResourceQueryParams,
    results::NvtRefResponse,
};

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Override")]
pub(crate) struct OverrideResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nvt: Option<NvtRefResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(rename = "newSeverity", skip_serializing_if = "Option::is_none")]
    new_severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<ResourceRefResponse>,
    active: bool,
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    end_time: Option<String>,
}

impl From<gvm_gateway_domain::Override> for OverrideResponse {
    fn from(override_: gvm_gateway_domain::Override) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(override_.meta),
            text: override_.text,
            nvt: override_.nvt.map(NvtRefResponse::from),
            hosts: override_.hosts,
            port: override_.port,
            severity: override_.severity,
            new_severity: override_.new_severity,
            task: override_.task.map(ResourceRefResponse::from),
            result: override_.result.map(ResourceRefResponse::from),
            active: override_.active,
            end_time: override_.end_time,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "OverrideList")]
pub(crate) struct OverrideListResponse {
    data: Vec<OverrideResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::OverridePage> for OverrideListResponse {
    fn from(page: gvm_gateway_domain::OverridePage) -> Self {
        Self {
            data: page.data.into_iter().map(OverrideResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateOverride")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateOverrideRequest {
    #[serde(rename = "nvtOid")]
    #[schemars(required)]
    nvt_oid: Option<String>,
    text: Option<String>,
    #[serde(default)]
    hosts: Vec<String>,
    port: Option<String>,
    severity: Option<String>,
    #[serde(rename = "newSeverity")]
    new_severity: Option<String>,
    #[serde(rename = "taskId")]
    #[schemars(with = "Option<Uuid>")]
    task_id: Option<String>,
    #[serde(rename = "resultId")]
    #[schemars(with = "Option<Uuid>")]
    result_id: Option<String>,
    active: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "UpdateOverride")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyOverrideRequest {
    text: Option<String>,
    /// Host selector list. Omitted or null leaves existing selectors unchanged;
    /// an empty array clears all host selectors.
    hosts: Option<Vec<String>>,
    port: Option<String>,
    severity: Option<String>,
    #[serde(rename = "newSeverity")]
    new_severity: Option<String>,
    #[serde(rename = "taskId")]
    #[schemars(with = "Option<Uuid>")]
    task_id: Option<String>,
    #[serde(rename = "resultId")]
    #[schemars(with = "Option<Uuid>")]
    result_id: Option<String>,
    active: Option<bool>,
}

impl CreateOverrideRequest {
    fn validate(self) -> Result<CreateOverrideInput, GatewayError> {
        validate_optional_uuid("taskId", self.task_id.as_deref())?;
        validate_optional_uuid("resultId", self.result_id.as_deref())?;

        Ok(CreateOverrideInput {
            nvt_oid: require_nvt_oid(self.nvt_oid)?,
            text: self.text,
            hosts: self.hosts,
            port: self.port,
            severity: self.severity,
            new_severity: self.new_severity,
            task_id: self.task_id,
            result_id: self.result_id,
            active: self.active,
        })
    }
}

impl ValidateInto<CreateOverrideInput> for CreateOverrideRequest {
    fn validate_into(self) -> Result<CreateOverrideInput, GatewayError> {
        self.validate()
    }
}

impl ModifyOverrideRequest {
    fn validate(self) -> Result<ModifyOverrideInput, GatewayError> {
        validate_optional_uuid("taskId", self.task_id.as_deref())?;
        validate_optional_uuid("resultId", self.result_id.as_deref())?;

        Ok(ModifyOverrideInput {
            text: self.text,
            hosts: self.hosts,
            port: self.port,
            severity: self.severity,
            new_severity: self.new_severity,
            task_id: self.task_id,
            result_id: self.result_id,
            active: self.active,
        })
    }
}

impl ValidateInto<ModifyOverrideInput> for ModifyOverrideRequest {
    fn validate_into(self) -> Result<ModifyOverrideInput, GatewayError> {
        self.validate()
    }
}

/// Lists overrides visible to the authenticated session.
pub async fn list_overrides(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        |query| SupportingListQuery::try_from_query_string(query).map(supporting_query),
        |service, session, query| async move { service.list_overrides(&session, query).await },
        OverrideListResponse::from,
    )
    .await
}

/// Returns a single override by id.
pub async fn get_override(
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
        |service, session, id| async move { service.get_override(&session, &id).await },
        OverrideResponse::from,
    )
    .await
}

/// Creates an override for result triage.
pub async fn create_override(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateOverrideInput, CreateOverrideRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_override(&session, input).await },
    )
    .await
}

/// Updates an override used for result triage.
pub async fn update_override(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyOverrideInput, ModifyOverrideRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_override(&session, &id, input).await
        },
        OverrideResponse::from,
    )
    .await
}

/// Deletes an override. Set `ultimate=true` to request permanent backend deletion.
pub async fn delete_override(
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
            service.delete_override(&session, &id, ultimate).await
        },
    )
    .await
}

pub(crate) fn list_overrides_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getOverrides")
        .tag("Overrides")
        .summary("List overrides")
        .description(
            "Returns a paginated list of overrides that change finding interpretation. Filter expressions can scope overrides to the related task, result, NVT, host, or port selectors exposed by each override.",
        )
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<OverrideListResponse>, _>(ok_json(
            "Paginated list of overrides",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_override_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getOverride")
        .tag("Overrides")
        .summary("Get an override")
        .description(
            "Returns the details for a single override, including any related task/result identifiers, the annotated NVT/host/port selectors, and the replacement severity when one is set.",
        )
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<OverrideResponse>, _>(ok_json("Override details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn create_override_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createOverride")
        .tag("Overrides")
        .summary("Create an override")
        .description(
            "Creates an override that changes finding interpretation for the selected NVT and optional task/result/host/port/severity scope.",
        )
        .security_requirement("bearerAuth")
        .input::<Json<CreateOverrideRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Override created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn update_override_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyOverride")
        .tag("Overrides")
        .summary("Modify an override")
        .description("Updates an override used for finding triage.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyOverrideRequest>)>()
        .response_with::<200, Json<OverrideResponse>, _>(ok_json("Override updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_override_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteOverride")
        .tag("Overrides")
        .summary("Delete an override")
        .description("Deletes an override. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Override deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "overrides_test.rs"]
mod overrides_test;
