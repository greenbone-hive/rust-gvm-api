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
use gvm_gateway_domain::{CreateNoteInput, GatewayError, ModifyNoteInput};
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
#[schemars(rename = "Note")]
pub(crate) struct NoteResponse {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<ResourceRefResponse>,
    active: bool,
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    end_time: Option<String>,
}

impl From<gvm_gateway_domain::Note> for NoteResponse {
    fn from(note: gvm_gateway_domain::Note) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(note.meta),
            text: note.text,
            nvt: note.nvt.map(NvtRefResponse::from),
            hosts: note.hosts,
            port: note.port,
            severity: note.severity,
            task: note.task.map(ResourceRefResponse::from),
            result: note.result.map(ResourceRefResponse::from),
            active: note.active,
            end_time: note.end_time,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "NoteList")]
pub(crate) struct NoteListResponse {
    data: Vec<NoteResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::NotePage> for NoteListResponse {
    fn from(page: gvm_gateway_domain::NotePage) -> Self {
        Self {
            data: page.data.into_iter().map(NoteResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateNote")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateNoteRequest {
    #[serde(rename = "nvtOid")]
    #[schemars(required)]
    nvt_oid: Option<String>,
    text: Option<String>,
    #[serde(default)]
    hosts: Vec<String>,
    port: Option<String>,
    severity: Option<String>,
    #[serde(rename = "taskId")]
    #[schemars(with = "Option<Uuid>")]
    task_id: Option<String>,
    #[serde(rename = "resultId")]
    #[schemars(with = "Option<Uuid>")]
    result_id: Option<String>,
    active: Option<bool>,
    orphan: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "UpdateNote")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyNoteRequest {
    text: Option<String>,
    /// Host selector list. Omitted or null leaves existing selectors unchanged;
    /// an empty array clears all host selectors.
    hosts: Option<Vec<String>>,
    port: Option<String>,
    severity: Option<String>,
    #[serde(rename = "taskId")]
    #[schemars(with = "Option<Uuid>")]
    task_id: Option<String>,
    #[serde(rename = "resultId")]
    #[schemars(with = "Option<Uuid>")]
    result_id: Option<String>,
    active: Option<bool>,
    orphan: Option<bool>,
}

impl CreateNoteRequest {
    fn validate(self) -> Result<CreateNoteInput, GatewayError> {
        validate_optional_uuid("taskId", self.task_id.as_deref())?;
        validate_optional_uuid("resultId", self.result_id.as_deref())?;

        Ok(CreateNoteInput {
            nvt_oid: require_nvt_oid(self.nvt_oid)?,
            text: self.text,
            hosts: self.hosts,
            port: self.port,
            severity: self.severity,
            task_id: self.task_id,
            result_id: self.result_id,
            active: self.active,
            orphan: self.orphan,
        })
    }
}

impl ValidateInto<CreateNoteInput> for CreateNoteRequest {
    fn validate_into(self) -> Result<CreateNoteInput, GatewayError> {
        self.validate()
    }
}

impl ModifyNoteRequest {
    fn validate(self) -> Result<ModifyNoteInput, GatewayError> {
        validate_optional_uuid("taskId", self.task_id.as_deref())?;
        validate_optional_uuid("resultId", self.result_id.as_deref())?;

        Ok(ModifyNoteInput {
            text: self.text,
            hosts: self.hosts,
            port: self.port,
            severity: self.severity,
            task_id: self.task_id,
            result_id: self.result_id,
            active: self.active,
            orphan: self.orphan,
        })
    }
}

impl ValidateInto<ModifyNoteInput> for ModifyNoteRequest {
    fn validate_into(self) -> Result<ModifyNoteInput, GatewayError> {
        self.validate()
    }
}

/// Lists notes visible to the authenticated session.
pub async fn list_notes(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        |query| SupportingListQuery::try_from_query_string(query).map(supporting_query),
        |service, session, query| async move { service.list_notes(&session, query).await },
        NoteListResponse::from,
    )
    .await
}

/// Returns a single note by id.
pub async fn get_note(
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
        |service, session, id| async move { service.get_note(&session, &id).await },
        NoteResponse::from,
    )
    .await
}

/// Creates a note for result triage.
pub async fn create_note(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateNoteInput, CreateNoteRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_note(&session, input).await },
    )
    .await
}

/// Updates a note used for result triage.
pub async fn update_note(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyNoteInput, ModifyNoteRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move { service.modify_note(&session, &id, input).await },
        NoteResponse::from,
    )
    .await
}

/// Deletes a note. Set `ultimate=true` to request permanent backend deletion.
pub async fn delete_note(
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
            service.delete_note(&session, &id, ultimate).await
        },
    )
    .await
}

pub(crate) fn list_notes_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getNotes")
        .tag("Notes")
        .summary("List notes")
        .description(
            "Returns a paginated list of notes that annotate findings. Filter expressions can scope notes to the related task, result, NVT, host, or port selectors exposed by each note.",
        )
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<NoteListResponse>, _>(ok_json("Paginated list of notes"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_note_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getNote")
        .tag("Notes")
        .summary("Get a note")
        .description(
            "Returns the details for a single note, including any related task/result identifiers and the NVT/host/port selectors the note annotates.",
        )
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<NoteResponse>, _>(ok_json("Note details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn create_note_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createNote")
        .tag("Notes")
        .summary("Create a note")
        .description(
            "Creates a note that annotates findings selected by NVT, optional task/result scope, and optional host/port/severity selectors.",
        )
        .security_requirement("bearerAuth")
        .input::<Json<CreateNoteRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Note created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn update_note_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyNote")
        .tag("Notes")
        .summary("Modify a note")
        .description("Updates a note used for finding triage.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyNoteRequest>)>()
        .response_with::<200, Json<NoteResponse>, _>(ok_json("Note updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_note_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteNote")
        .tag("Notes")
        .summary("Delete a note")
        .description("Deletes a note. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Note deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "notes_test.rs"]
mod notes_test;
