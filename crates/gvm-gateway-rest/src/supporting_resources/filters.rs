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
use gvm_gateway_domain::{CreateFilterInput, GatewayError, ModifyFilterInput};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::common::{
    supporting_query, SupportingListQuery, SupportingResourceListQueryParams,
    SupportingResourceMetaResponse,
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
#[schemars(rename = "Filter")]
pub(crate) struct FilterResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    filter_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    term: Option<String>,
}

impl From<gvm_gateway_domain::Filter> for FilterResponse {
    fn from(filter: gvm_gateway_domain::Filter) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(filter.meta),
            filter_type: filter.filter_type,
            term: filter.term,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "FilterList")]
pub(crate) struct FilterListResponse {
    data: Vec<FilterResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::FilterPage> for FilterListResponse {
    fn from(page: gvm_gateway_domain::FilterPage) -> Self {
        Self {
            data: page.data.into_iter().map(FilterResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateFilter")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateFilterRequest {
    #[schemars(required)]
    name: Option<String>,
    comment: Option<String>,
    term: Option<String>,
    #[serde(rename = "type")]
    filter_type: Option<String>,
}

impl CreateFilterRequest {
    fn validate(self) -> Result<CreateFilterInput, GatewayError> {
        let name = self
            .name
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))?;
        Ok(CreateFilterInput {
            name,
            comment: self.comment,
            term: self.term,
            filter_type: self.filter_type,
        })
    }
}

impl ValidateInto<CreateFilterInput> for CreateFilterRequest {
    fn validate_into(self) -> Result<CreateFilterInput, GatewayError> {
        self.validate()
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "UpdateFilter")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyFilterRequest {
    comment: Option<String>,
    term: Option<String>,
    #[serde(rename = "type")]
    filter_type: Option<String>,
}

impl ValidateInto<ModifyFilterInput> for ModifyFilterRequest {
    fn validate_into(self) -> Result<ModifyFilterInput, GatewayError> {
        Ok(ModifyFilterInput {
            comment: self.comment,
            term: self.term,
            filter_type: self.filter_type,
        })
    }
}

/// Lists saved filters visible to the authenticated session.
pub async fn list_filters(
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

    match service
        .list_filters(&session, supporting_query(query))
        .await
    {
        Ok(page) => (StatusCode::OK, Json(FilterListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single saved filter by id.
pub async fn get_filter(
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

    match service.get_filter(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(FilterResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Creates a saved filter.
pub async fn create_filter(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateFilterInput, CreateFilterRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_filter(&session, input).await },
    )
    .await
}

/// Updates a saved filter.
pub async fn update_filter(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyFilterInput, ModifyFilterRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_filter(&session, &id, input).await
        },
        FilterResponse::from,
    )
    .await
}

/// Deletes a saved filter. Set `ultimate=true` to request permanent backend deletion.
pub async fn delete_filter(
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
            service.delete_filter(&session, &id, ultimate).await
        },
    )
    .await
}

/// Clones a saved filter.
pub async fn clone_filter(
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
    match service.clone_filter(&session, &id).await {
        Ok(new_id) => created_resource("/api/v1/filters", &new_id),
        Err(error) => gateway_error(error, instance),
    }
}

pub(crate) fn list_filters_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getFilters")
        .tag("Filters")
        .summary("List filters")
        .description("Returns a paginated list of saved filters.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<FilterListResponse>, _>(ok_json(
            "Paginated list of saved filters",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_filter_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getFilter")
        .tag("Filters")
        .summary("Get a filter")
        .description("Returns the details for a single saved filter.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<FilterResponse>, _>(ok_json("Filter details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn create_filter_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createFilter")
        .tag("Filters")
        .summary("Create a filter")
        .description("Creates a saved filter with an optional term, comment, and resource type.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateFilterRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Filter created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn update_filter_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyFilter")
        .tag("Filters")
        .summary("Modify a filter")
        .description("Updates a saved filter's term, comment, or resource type.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyFilterRequest>)>()
        .response_with::<200, Json<FilterResponse>, _>(ok_json("Filter updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_filter_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteFilter")
        .tag("Filters")
        .summary("Delete a filter")
        .description("Deletes a saved filter. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Filter deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn clone_filter_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("cloneFilter")
        .tag("Filters")
        .summary("Clone a filter")
        .description("Creates a copy of an existing saved filter.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Filter cloned"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "filters_test.rs"]
mod filters_test;
