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
use gvm_gateway_domain::{
    CreateHostInput, GatewayError, ModifyHostInput, ModifyOperatingSystemInput, OperatingSystem,
    OperatingSystemHost,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::{
    supporting_query, SupportingListQuery, SupportingResourceListQueryParams,
    SupportingResourceMetaResponse,
};
use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceCreatedResponse},
    error::RestError,
    handler::{create_resource, gateway_error, update_resource, ValidateInto},
    openapi::{created_json, ok_json, problem_response, ResourceIdPathDoc},
    query::decoded_query_pairs,
    router::bearer_token,
    targets::validate_uuid,
};

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Host")]
pub(crate) struct HostResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
}

impl From<gvm_gateway_domain::Host> for HostResponse {
    fn from(host: gvm_gateway_domain::Host) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(host.meta),
            ip: host.ip,
            hostname: host.hostname,
            severity: host.severity,
            os: host.os,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "HostList")]
pub(crate) struct HostListResponse {
    data: Vec<HostResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::HostPage> for HostListResponse {
    fn from(page: gvm_gateway_domain::HostPage) -> Self {
        Self {
            data: page.data.into_iter().map(HostResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "OperatingSystemHost")]
pub(crate) struct OperatingSystemHostResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
}

impl From<OperatingSystemHost> for OperatingSystemHostResponse {
    fn from(host: OperatingSystemHost) -> Self {
        Self {
            id: parse_uuid(&host.id),
            name: host.name,
            severity: host.severity,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "OperatingSystem")]
pub(crate) struct OperatingSystemResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(rename = "hostsCount", skip_serializing_if = "Option::is_none")]
    hosts_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    title: String,
    installs: u32,
    #[serde(rename = "allInstalls")]
    all_installs: u32,
    #[serde(rename = "latestSeverity", skip_serializing_if = "Option::is_none")]
    latest_severity: Option<String>,
    #[serde(rename = "highestSeverity", skip_serializing_if = "Option::is_none")]
    highest_severity: Option<String>,
    #[serde(rename = "averageSeverity", skip_serializing_if = "Option::is_none")]
    average_severity: Option<String>,
    #[serde(rename = "hostCount")]
    host_count: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<OperatingSystemHostResponse>,
}

impl From<OperatingSystem> for OperatingSystemResponse {
    fn from(operating_system: OperatingSystem) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(operating_system.meta),
            value: operating_system.value,
            hosts_count: operating_system.hosts_count,
            severity: operating_system.severity,
            title: operating_system.title,
            installs: operating_system.installs,
            all_installs: operating_system.all_installs,
            latest_severity: operating_system.latest_severity,
            highest_severity: operating_system.highest_severity,
            average_severity: operating_system.average_severity,
            host_count: operating_system.host_count,
            hosts: operating_system
                .hosts
                .into_iter()
                .map(OperatingSystemHostResponse::from)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "OperatingSystemList")]
pub(crate) struct OperatingSystemListResponse {
    data: Vec<OperatingSystemResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::OperatingSystemPage> for OperatingSystemListResponse {
    fn from(page: gvm_gateway_domain::OperatingSystemPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(OperatingSystemResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateHost")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateHostRequest {
    /// Host name or IP address.
    #[schemars(required)]
    value: Option<String>,
    comment: Option<String>,
}

impl CreateHostRequest {
    fn validate(self) -> Result<CreateHostInput, GatewayError> {
        let value = self
            .value
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GatewayError::InvalidInput("value is required".to_string()))?;
        Ok(CreateHostInput {
            value,
            comment: self.comment,
        })
    }
}

impl ValidateInto<CreateHostInput> for CreateHostRequest {
    fn validate_into(self) -> Result<CreateHostInput, GatewayError> {
        self.validate()
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "UpdateHost")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyHostRequest {
    // The gvmd `modify_asset` command does not update a host asset's name/IP
    // value, so this endpoint only edits the comment. `deny_unknown_fields`
    // makes a body carrying `value` (or any other unsupported field) a `400`
    // rather than silently dropping it and reporting success.
    comment: Option<String>,
}

impl ValidateInto<ModifyHostInput> for ModifyHostRequest {
    fn validate_into(self) -> Result<ModifyHostInput, GatewayError> {
        Ok(ModifyHostInput {
            comment: self.comment,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "UpdateOperatingSystem")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyOperatingSystemRequest {
    // The typed gvmd `modify_operating_system` command only supports comment
    // updates. Rejecting unknown fields keeps the REST contract aligned with
    // the backend instead of silently dropping unsupported mutations.
    comment: Option<String>,
}

impl ValidateInto<ModifyOperatingSystemInput> for ModifyOperatingSystemRequest {
    fn validate_into(self) -> Result<ModifyOperatingSystemInput, GatewayError> {
        Ok(ModifyOperatingSystemInput {
            comment: self.comment,
        })
    }
}

/// Lists hosts visible to the authenticated session.
pub async fn list_hosts(
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

    match service.list_hosts(&session, supporting_query(query)).await {
        Ok(page) => (StatusCode::OK, Json(HostListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single host by id.
pub async fn get_host(
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

    match service.get_host(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(HostResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Rejects the `ultimate` query parameter on host deletion.
///
/// gvmd's host-asset delete command does not support permanent (`ultimate`)
/// deletion, so accepting the flag and silently performing an ordinary delete
/// would misrepresent the outcome. Any `ultimate` key is a `400` instead.
fn reject_host_ultimate_query(query: Option<&str>) -> Result<(), GatewayError> {
    let has_ultimate = query
        .into_iter()
        .flat_map(decoded_query_pairs)
        .any(|(key, _)| key == "ultimate");
    if has_ultimate {
        return Err(GatewayError::InvalidInput(
            "the `ultimate` query parameter is not supported for host deletion".to_string(),
        ));
    }
    Ok(())
}

fn reject_operating_system_ultimate_query(query: Option<&str>) -> Result<(), GatewayError> {
    let has_ultimate = query
        .into_iter()
        .flat_map(decoded_query_pairs)
        .any(|(key, _)| key == "ultimate");
    if has_ultimate {
        return Err(GatewayError::InvalidInput(
            "the `ultimate` query parameter is not supported for operating-system deletion"
                .to_string(),
        ));
    }
    Ok(())
}

/// Creates a host asset.
pub async fn create_host(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateHostInput, CreateHostRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_host(&session, input).await },
    )
    .await
}

/// Lists operating-system assets visible to the authenticated session.
pub async fn list_operating_systems(
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
        .list_operating_systems(&session, supporting_query(query))
        .await
    {
        Ok(page) => (
            StatusCode::OK,
            Json(OperatingSystemListResponse::from(page)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single operating-system asset by id.
pub async fn get_operating_system(
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

    match service.get_operating_system(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(OperatingSystemResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Updates a host asset.
pub async fn update_host(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyHostInput, ModifyHostRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move { service.modify_host(&session, &id, input).await },
        HostResponse::from,
    )
    .await
}

/// Updates an operating-system asset.
pub async fn update_operating_system(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyOperatingSystemInput, ModifyOperatingSystemRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_operating_system(&session, &id, input).await
        },
        OperatingSystemResponse::from,
    )
    .await
}

/// Deletes a host asset.
///
/// The gvmd host-asset delete command does not support the `ultimate`
/// (permanent) flag, so this endpoint performs a single delete without an
/// `ultimate` query parameter rather than advertising a flag the backend
/// ignores.
pub async fn delete_host(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    // gvmd's host-asset delete does not support the `ultimate` (permanent)
    // flag; reject it at the boundary instead of silently performing an
    // ordinary delete and reporting success.
    if let Err(error) = reject_host_ultimate_query(uri.query()) {
        return gateway_error(error, instance);
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service.delete_host(&session, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => gateway_error(error, instance),
    }
}

/// Deletes an operating-system asset.
///
/// The typed gvmd delete command does not expose an `ultimate` flag for
/// operating-system assets, so this endpoint rejects that parameter instead of
/// advertising permanent deletion semantics the backend cannot honor.
pub async fn delete_operating_system(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    if let Err(error) = reject_operating_system_ultimate_query(uri.query()) {
        return gateway_error(error, instance);
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service.delete_operating_system(&session, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => gateway_error(error, instance),
    }
}

pub(crate) fn list_hosts_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getHosts")
        .tag("Hosts")
        .summary("List hosts")
        .description("Returns a paginated list of discovered hosts/assets.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<HostListResponse>, _>(ok_json(
            "Paginated list of discovered hosts",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_host_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getHost")
        .tag("Hosts")
        .summary("Get a host")
        .description("Returns the details for a single discovered host/asset.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<HostResponse>, _>(ok_json("Host details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn create_host_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createHost")
        .tag("Hosts")
        .summary("Create a host")
        .description("Creates a host asset identified by a name or IP address.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateHostRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Host created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn update_host_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyHost")
        .tag("Hosts")
        .summary("Modify a host")
        .description(
            "Updates a host asset's comment. The gvmd `modify_asset` command does not change a host asset's name/IP value, so only the comment can be edited here.",
        )
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyHostRequest>)>()
        .response_with::<200, Json<HostResponse>, _>(ok_json("Host updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_host_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteHost")
        .tag("Hosts")
        .summary("Delete a host")
        .description(
            "Deletes a host asset. The gvmd host-asset delete command does not support the `ultimate` (permanent) flag, so this endpoint always performs a single delete.",
        )
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Host deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_operating_systems_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getOperatingSystems")
        .tag("Operating Systems")
        .summary("List operating systems")
        .description("Returns a paginated list of operating-system assets.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<OperatingSystemListResponse>, _>(ok_json(
            "Paginated list of operating-system assets",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_operating_system_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getOperatingSystem")
        .tag("Operating Systems")
        .summary("Get an operating system")
        .description("Returns the details for a single operating-system asset.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<OperatingSystemResponse>, _>(ok_json(
            "Operating-system details",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn modify_operating_system_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyOperatingSystem")
        .tag("Operating Systems")
        .summary("Modify an operating system")
        .description(
            "Updates an operating-system asset's comment. The typed gvmd command only supports comment updates for this resource.",
        )
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyOperatingSystemRequest>)>()
        .response_with::<200, Json<OperatingSystemResponse>, _>(ok_json(
            "Operating-system updated",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_operating_system_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteOperatingSystem")
        .tag("Operating Systems")
        .summary("Delete an operating system")
        .description(
            "Deletes an operating-system asset. The typed gvmd delete command does not support the `ultimate` flag for this resource, so this endpoint always performs a single delete. Deleting an asset that is still in use returns `409 Conflict`.",
        )
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Operating-system deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<409>(op, "Operating-system asset is in use")
}

#[cfg(test)]
#[path = "assets_test.rs"]
mod assets_test;
