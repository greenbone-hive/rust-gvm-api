// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{CreateTagInput, GatewayError, ModifyTagInput};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::{
    supporting_query, validate_optional_uuid, SupportingListQuery,
    SupportingResourceListQueryParams, SupportingResourceMetaResponse,
};
use crate::{
    dto::{PaginationResponse, ResourceCreatedResponse},
    error::RestError,
    handler::{
        create_resource, created_resource, delete_resource, gateway_error, update_resource,
        ValidateInto,
    },
    openapi::{created_json, ok_json, problem_response, ResourceIdPathDoc},
    query::DeleteResourceQueryParams,
    router::bearer_token,
    targets::validate_uuid,
};

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TagResource")]
pub(crate) struct TagResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(rename = "resourceType", skip_serializing_if = "Option::is_none")]
    resource_type: Option<String>,
    #[serde(rename = "resourceCount", skip_serializing_if = "Option::is_none")]
    resource_count: Option<u32>,
    active: bool,
}

impl From<gvm_gateway_domain::Tag> for TagResponse {
    fn from(tag: gvm_gateway_domain::Tag) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(tag.meta),
            value: tag.value,
            resource_type: tag.resource_type,
            resource_count: tag.resource_count,
            active: tag.active,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TagList")]
pub(crate) struct TagListResponse {
    data: Vec<TagResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::TagPage> for TagListResponse {
    fn from(page: gvm_gateway_domain::TagPage) -> Self {
        Self {
            data: page.data.into_iter().map(TagResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateTag")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateTagRequest {
    #[schemars(required)]
    name: Option<String>,
    comment: Option<String>,
    value: Option<String>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    #[serde(rename = "resourceId")]
    #[schemars(with = "Option<Uuid>")]
    resource_id: Option<String>,
    active: Option<bool>,
}

impl CreateTagRequest {
    fn validate(self) -> Result<CreateTagInput, GatewayError> {
        let name = self
            .name
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))?;
        validate_optional_uuid("resourceId", self.resource_id.as_deref())?;
        Ok(CreateTagInput {
            name,
            comment: self.comment,
            value: self.value,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            active: self.active,
        })
    }
}

impl ValidateInto<CreateTagInput> for CreateTagRequest {
    fn validate_into(self) -> Result<CreateTagInput, GatewayError> {
        self.validate()
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "UpdateTag")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyTagRequest {
    comment: Option<String>,
    value: Option<String>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    #[serde(rename = "resourceId")]
    #[schemars(with = "Option<Uuid>")]
    resource_id: Option<String>,
    active: Option<bool>,
}

impl ModifyTagRequest {
    fn validate(self) -> Result<ModifyTagInput, GatewayError> {
        validate_optional_uuid("resourceId", self.resource_id.as_deref())?;
        Ok(ModifyTagInput {
            comment: self.comment,
            value: self.value,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            active: self.active,
        })
    }
}

impl ValidateInto<ModifyTagInput> for ModifyTagRequest {
    fn validate_into(self) -> Result<ModifyTagInput, GatewayError> {
        self.validate()
    }
}

/// Lists tags visible to the authenticated session.
pub async fn list_tags(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match SupportingListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.list_tags(&session, supporting_query(query)).await {
        Ok(page) => (StatusCode::OK, Json(TagListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single tag by id.
pub async fn get_tag(
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

    match service.get_tag(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(TagResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Creates a tag.
pub async fn create_tag(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateTagInput, CreateTagRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_tag(&session, input).await },
    )
    .await
}

/// Updates a tag.
pub async fn update_tag(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyTagInput, ModifyTagRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move { service.modify_tag(&session, &id, input).await },
        TagResponse::from,
    )
    .await
}

/// Deletes a tag. Set `ultimate=true` to request permanent backend deletion.
pub async fn delete_tag(
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
            service.delete_tag(&session, &id, ultimate).await
        },
    )
    .await
}

/// Clones a tag.
pub async fn clone_tag(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service.clone_tag(&session, &id).await {
        Ok(new_id) => created_resource("/api/v1/tags", &new_id),
        Err(error) => gateway_error(error, instance),
    }
}

pub(crate) fn list_tags_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTags")
        .tag("Tags")
        .summary("List tags")
        .description("Returns a paginated list of tags.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<TagListResponse>, _>(ok_json("Paginated list of tags"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_tag_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTag")
        .tag("Tags")
        .summary("Get a tag")
        .description("Returns the details for a single tag.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TagResponse>, _>(ok_json("Tag details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn create_tag_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createTag")
        .tag("Tags")
        .summary("Create a tag")
        .description("Creates a tag, optionally attaching it to a related resource by type and id.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateTagRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Tag created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn update_tag_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyTag")
        .tag("Tags")
        .summary("Modify a tag")
        .description("Updates a tag's value, comment, resource attachment, or active state.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyTagRequest>)>()
        .response_with::<200, Json<TagResponse>, _>(ok_json("Tag updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_tag_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteTag")
        .tag("Tags")
        .summary("Delete a tag")
        .description("Deletes a tag. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Tag deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn clone_tag_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("cloneTag")
        .tag("Tags")
        .summary("Clone a tag")
        .description("Creates a copy of an existing tag.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Tag cloned"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "tags_test.rs"]
mod tags_test;
