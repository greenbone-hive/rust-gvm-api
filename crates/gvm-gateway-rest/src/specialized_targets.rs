// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! REST resources for OCI image and web application targets.

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    CreateOciImageTargetInput, CreateWebApplicationTargetInput, GatewayError,
    ModifyOciImageTargetInput, ModifyWebApplicationTargetInput, SpecializedTargetQuery,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceCreatedResponse, ResourceRefResponse},
    handler::{
        clone_resource, create_resource, delete_resource, get_resource, list_resource,
        update_resource, ValidateInto,
    },
    openapi::{created_json, ok_json, problem_response, ResourceIdPathDoc},
    query::{decoded_query_pairs, parse_collection_query, DeleteResourceQueryParams},
};

fn default_page() -> Option<u32> {
    Some(1)
}

fn default_per_page() -> Option<u32> {
    Some(25)
}

fn default_trash() -> Option<bool> {
    Some(false)
}

#[derive(JsonSchema)]
#[schemars(transparent)]
#[allow(dead_code)] // OpenAPI-only marker used through `schemars(with = ...)`.
struct UrlDoc(#[schemars(schema_with = "uri_schema")] String);

fn uri_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type": "string", "format": "uri"})
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct SpecializedTargetListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    #[serde(default = "default_trash")]
    #[schemars(default = "default_trash")]
    trash: Option<bool>,
    #[serde(default = "default_page")]
    #[schemars(default = "default_page")]
    #[schemars(range(min = 1))]
    page: Option<u32>,
    #[serde(rename = "perPage")]
    #[serde(default = "default_per_page")]
    #[schemars(default = "default_per_page")]
    #[schemars(range(min = 1, max = 1000))]
    per_page: Option<u32>,
}

fn parse_query(raw: &str) -> Result<SpecializedTargetQuery, GatewayError> {
    let common = parse_collection_query(raw)?;
    let mut trash = false;
    for (key, value) in decoded_query_pairs(raw) {
        if key == "trash" {
            trash = value.parse::<bool>().map_err(|_| {
                GatewayError::InvalidInput("trash must be true or false".to_string())
            })?;
        }
    }
    Ok(SpecializedTargetQuery {
        filter_string: common.filter_string,
        filter_id: common.filter_id,
        trash,
        page: common.page,
        per_page: common.per_page,
    })
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "OciImageTarget")]
struct OciImageTargetResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "imageReferences")]
    image_references: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<ResourceRefResponse>,
    tasks: Vec<ResourceRefResponse>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<gvm_gateway_domain::OciImageTarget> for OciImageTargetResponse {
    fn from(value: gvm_gateway_domain::OciImageTarget) -> Self {
        Self {
            id: parse_uuid(&value.id),
            name: value.name,
            comment: value.comment,
            image_references: value.image_references,
            credential: value.credential.map(Into::into),
            tasks: value.tasks.into_iter().map(Into::into).collect(),
            in_use: value.in_use,
            writable: value.writable,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "OciImageTargetList")]
struct OciImageTargetListResponse {
    data: Vec<OciImageTargetResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::OciImageTargetPage> for OciImageTargetListResponse {
    fn from(value: gvm_gateway_domain::OciImageTargetPage) -> Self {
        Self {
            data: value.data.into_iter().map(Into::into).collect(),
            pagination: value.pagination.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[schemars(rename = "CreateOciImageTarget")]
#[serde(deny_unknown_fields)]
struct CreateOciImageTargetRequest {
    name: String,
    comment: Option<String>,
    #[serde(rename = "imageReferences")]
    #[schemars(length(min = 1))]
    image_references: Vec<String>,
    #[serde(rename = "credentialId")]
    credential_id: Option<Uuid>,
}

impl ValidateInto<CreateOciImageTargetInput> for CreateOciImageTargetRequest {
    fn validate_into(self) -> Result<CreateOciImageTargetInput, GatewayError> {
        let name = required_name(Some(self.name))?;
        required_values("imageReferences", &self.image_references)?;
        Ok(CreateOciImageTargetInput {
            name,
            comment: self.comment,
            image_references: self.image_references,
            credential_id: self.credential_id.map(|value| value.to_string()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[schemars(rename = "ModifyOciImageTarget")]
#[serde(deny_unknown_fields)]
struct ModifyOciImageTargetRequest {
    name: Option<String>,
    comment: Option<String>,
    #[serde(rename = "imageReferences")]
    #[schemars(length(min = 1))]
    image_references: Option<Vec<String>>,
    #[serde(rename = "credentialId")]
    credential_id: Option<Uuid>,
}

impl ValidateInto<ModifyOciImageTargetInput> for ModifyOciImageTargetRequest {
    fn validate_into(self) -> Result<ModifyOciImageTargetInput, GatewayError> {
        if let Some(values) = &self.image_references {
            required_values("imageReferences", values)?;
        }
        Ok(ModifyOciImageTargetInput {
            name: self.name,
            comment: self.comment,
            image_references: self.image_references,
            credential_id: self.credential_id.map(|value| value.to_string()),
        })
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "WebApplicationTarget")]
struct WebApplicationTargetResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[schemars(with = "Vec<UrlDoc>")]
    urls: Vec<String>,
    #[serde(rename = "excludeUrls")]
    #[schemars(with = "Vec<UrlDoc>")]
    exclude_urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<ResourceRefResponse>,
    tasks: Vec<ResourceRefResponse>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<gvm_gateway_domain::WebApplicationTarget> for WebApplicationTargetResponse {
    fn from(value: gvm_gateway_domain::WebApplicationTarget) -> Self {
        Self {
            id: parse_uuid(&value.id),
            name: value.name,
            comment: value.comment,
            urls: value.urls,
            exclude_urls: value.exclude_urls,
            credential: value.credential.map(Into::into),
            tasks: value.tasks.into_iter().map(Into::into).collect(),
            in_use: value.in_use,
            writable: value.writable,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "WebApplicationTargetList")]
struct WebApplicationTargetListResponse {
    data: Vec<WebApplicationTargetResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::WebApplicationTargetPage> for WebApplicationTargetListResponse {
    fn from(value: gvm_gateway_domain::WebApplicationTargetPage) -> Self {
        Self {
            data: value.data.into_iter().map(Into::into).collect(),
            pagination: value.pagination.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[schemars(rename = "CreateWebApplicationTarget")]
#[serde(deny_unknown_fields)]
struct CreateWebApplicationTargetRequest {
    name: String,
    comment: Option<String>,
    #[schemars(length(min = 1))]
    #[schemars(with = "Vec<UrlDoc>")]
    urls: Vec<String>,
    #[serde(rename = "excludeUrls", default)]
    #[schemars(with = "Vec<UrlDoc>")]
    exclude_urls: Vec<String>,
    #[serde(rename = "credentialId")]
    credential_id: Option<Uuid>,
}

impl ValidateInto<CreateWebApplicationTargetInput> for CreateWebApplicationTargetRequest {
    fn validate_into(self) -> Result<CreateWebApplicationTargetInput, GatewayError> {
        let name = required_name(Some(self.name))?;
        required_values("urls", &self.urls)?;
        Ok(CreateWebApplicationTargetInput {
            name,
            comment: self.comment,
            urls: self.urls,
            exclude_urls: self.exclude_urls,
            credential_id: self.credential_id.map(|value| value.to_string()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[schemars(rename = "ModifyWebApplicationTarget")]
#[serde(deny_unknown_fields)]
struct ModifyWebApplicationTargetRequest {
    name: Option<String>,
    comment: Option<String>,
    #[schemars(length(min = 1))]
    #[schemars(with = "Option<Vec<UrlDoc>>")]
    urls: Option<Vec<String>>,
    #[serde(rename = "excludeUrls")]
    /// Omit to preserve current exclusions. A non-empty array replaces them;
    /// clearing exclusions is not supported until rust-gvm provides a typed operation.
    #[schemars(length(min = 1))]
    #[schemars(with = "Option<Vec<UrlDoc>>")]
    exclude_urls: Option<Vec<String>>,
    #[serde(rename = "credentialId")]
    credential_id: Option<Uuid>,
}

impl ValidateInto<ModifyWebApplicationTargetInput> for ModifyWebApplicationTargetRequest {
    fn validate_into(self) -> Result<ModifyWebApplicationTargetInput, GatewayError> {
        if let Some(values) = &self.urls {
            required_values("urls", values)?;
        }
        if let Some(values) = &self.exclude_urls {
            required_values("excludeUrls", values)?;
        }
        Ok(ModifyWebApplicationTargetInput {
            name: self.name,
            comment: self.comment,
            urls: self.urls,
            exclude_urls: self.exclude_urls,
            credential_id: self.credential_id.map(|value| value.to_string()),
        })
    }
}

fn required_name(value: Option<String>) -> Result<String, GatewayError> {
    value
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))
}
fn required_values(field: &str, values: &[String]) -> Result<(), GatewayError> {
    if values.is_empty() || values.iter().any(|v| v.trim().is_empty()) {
        Err(GatewayError::InvalidInput(format!(
            "{field} must contain at least one non-empty entry"
        )))
    } else {
        Ok(())
    }
}
/// List OCI image targets.
pub async fn list_oci_image_targets(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        parse_query,
        |s, token, q| async move { s.list_oci_image_targets(&token, q).await },
        OciImageTargetListResponse::from,
    )
    .await
}
/// Create an OCI image target.
pub async fn create_oci_image_target(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateOciImageTargetInput, CreateOciImageTargetRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |s, token, input| async move { s.create_oci_image_target(&token, input).await },
    )
    .await
}
/// Clone an OCI image target.
pub async fn clone_oci_image_target(
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
        "/api/v1/oci-image-targets",
        |s, token, id| async move { s.clone_oci_image_target(&token, &id).await },
    )
    .await
}
/// Get an OCI image target.
pub async fn get_oci_image_target(
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
        |s, token, id| async move { s.get_oci_image_target(&token, &id).await },
        OciImageTargetResponse::from,
    )
    .await
}
/// Update an OCI image target.
pub async fn update_oci_image_target(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyOciImageTargetInput, ModifyOciImageTargetRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |s, token, id, input| async move { s.modify_oci_image_target(&token, &id, input).await },
        OciImageTargetResponse::from,
    )
    .await
}
/// Delete an OCI image target.
pub async fn delete_oci_image_target(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(service, headers, id, uri, |s, token, id, ultimate| async move { s.delete_oci_image_target(&token, &id, ultimate).await }).await
}

/// List web application targets.
pub async fn list_web_application_targets(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        parse_query,
        |s, token, q| async move { s.list_web_application_targets(&token, q).await },
        WebApplicationTargetListResponse::from,
    )
    .await
}
/// Create a web application target.
pub async fn create_web_application_target(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateWebApplicationTargetInput, CreateWebApplicationTargetRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |s, token, input| async move { s.create_web_application_target(&token, input).await },
    )
    .await
}
/// Clone a web application target.
pub async fn clone_web_application_target(
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
        "/api/v1/web-application-targets",
        |s, token, id| async move { s.clone_web_application_target(&token, &id).await },
    )
    .await
}
/// Get a web application target.
pub async fn get_web_application_target(
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
        |s, token, id| async move { s.get_web_application_target(&token, &id).await },
        WebApplicationTargetResponse::from,
    )
    .await
}
/// Update a web application target.
pub async fn update_web_application_target(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyWebApplicationTargetInput, ModifyWebApplicationTargetRequest, _, _, _, _>(service, headers, id, uri, body, |s, token, id, input| async move { s.modify_web_application_target(&token, &id, input).await }, WebApplicationTargetResponse::from).await
}
/// Delete a web application target.
pub async fn delete_web_application_target(
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
        |s, token, id, ultimate| async move {
            s.delete_web_application_target(&token, &id, ultimate).await
        },
    )
    .await
}

fn collection_docs<'a, T: JsonSchema + 'static>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .input::<Query<SpecializedTargetListQueryDoc>>()
        .response_with::<200, Json<T>, _>(ok_json(summary));
    let op = problem_response::<401>(
        problem_response::<400>(op, "Invalid request"),
        "Authentication required or session expired",
    );
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}
fn create_docs<'a, T: JsonSchema + 'static>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .input::<Json<T>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json(summary));
    let op = problem_response::<401>(
        problem_response::<400>(op, "Invalid request"),
        "Authentication required or session expired",
    );
    let op = problem_response::<409>(op, "Resource conflict");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}
fn item_docs<'a, T: JsonSchema + 'static>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<T>, _>(ok_json(summary));
    let op = problem_response::<404>(
        problem_response::<401>(
            problem_response::<400>(op, "Invalid request"),
            "Authentication required or session expired",
        ),
        "Resource not found",
    );
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}
fn update_docs<'a, Req: JsonSchema + 'static, Resp: JsonSchema + 'static>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<Req>)>()
        .response_with::<200, Json<Resp>, _>(ok_json(summary));
    let op = problem_response::<404>(
        problem_response::<401>(
            problem_response::<400>(op, "Invalid request"),
            "Authentication required or session expired",
        ),
        "Resource not found",
    );
    let op = problem_response::<409>(op, "Resource conflict");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}
fn clone_docs<'a>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json(summary));
    let op = problem_response::<404>(
        problem_response::<401>(
            problem_response::<400>(op, "Invalid request"),
            "Authentication required or session expired",
        ),
        "Resource not found",
    );
    let op = problem_response::<409>(op, "Resource conflict");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}
fn delete_docs<'a>(
    op: TransformOperation<'a>,
    id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(id)
        .tag(tag)
        .summary(summary)
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|r| r.description(summary));
    let op = problem_response::<404>(
        problem_response::<403>(
            problem_response::<401>(
                problem_response::<400>(op, "Invalid request"),
                "Authentication required or session expired",
            ),
            "Forbidden",
        ),
        "Resource not found",
    );
    let op = problem_response::<409>(op, "Resource conflict");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

pub(crate) fn list_oci_image_targets_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    collection_docs::<OciImageTargetListResponse>(
        op,
        "getOciImageTargets",
        "OCI Image Targets",
        "List OCI image targets",
    )
}
pub(crate) fn create_oci_image_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    create_docs::<CreateOciImageTargetRequest>(
        op,
        "createOciImageTarget",
        "OCI Image Targets",
        "Create an OCI image target",
    )
}
pub(crate) fn get_oci_image_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    item_docs::<OciImageTargetResponse>(
        op,
        "getOciImageTarget",
        "OCI Image Targets",
        "Get an OCI image target",
    )
}
pub(crate) fn update_oci_image_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    update_docs::<ModifyOciImageTargetRequest, OciImageTargetResponse>(
        op,
        "modifyOciImageTarget",
        "OCI Image Targets",
        "Modify an OCI image target",
    )
}
pub(crate) fn delete_oci_image_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    delete_docs(
        op,
        "deleteOciImageTarget",
        "OCI Image Targets",
        "Delete an OCI image target",
    )
}
pub(crate) fn clone_oci_image_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    clone_docs(
        op,
        "cloneOciImageTarget",
        "OCI Image Targets",
        "Clone an OCI image target",
    )
}

pub(crate) fn list_web_application_targets_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    collection_docs::<WebApplicationTargetListResponse>(
        op,
        "getWebApplicationTargets",
        "Web Application Targets",
        "List web application targets",
    )
}
pub(crate) fn create_web_application_target_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    create_docs::<CreateWebApplicationTargetRequest>(
        op,
        "createWebApplicationTarget",
        "Web Application Targets",
        "Create a web application target",
    )
}
pub(crate) fn get_web_application_target_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    item_docs::<WebApplicationTargetResponse>(
        op,
        "getWebApplicationTarget",
        "Web Application Targets",
        "Get a web application target",
    )
}
pub(crate) fn update_web_application_target_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    update_docs::<ModifyWebApplicationTargetRequest, WebApplicationTargetResponse>(
        op,
        "modifyWebApplicationTarget",
        "Web Application Targets",
        "Modify a web application target",
    )
}
pub(crate) fn delete_web_application_target_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    delete_docs(
        op,
        "deleteWebApplicationTarget",
        "Web Application Targets",
        "Delete a web application target",
    )
}
pub(crate) fn clone_web_application_target_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    clone_docs(
        op,
        "cloneWebApplicationTarget",
        "Web Application Targets",
        "Clone a web application target",
    )
}

#[cfg(test)]
#[path = "specialized_targets_test.rs"]
mod specialized_targets_test;
