// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Shared runtime handler helpers for standard REST resource endpoints.

use std::future::Future;

use axum::{
    body::Bytes,
    extract::OriginalUri,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

use crate::{
    dto::{created_resource_location, parse_uuid, ResourceCreatedResponse},
    error::RestError,
    query::parse_delete_resource_query,
    router::bearer_token,
};

/// Convert a validated REST request DTO into an application input type.
pub(crate) trait ValidateInto<T> {
    /// Validate the request and return the corresponding application input.
    fn validate_into(self) -> Result<T, GatewayError>;
}

/// Validate a UUID-like REST resource identifier.
pub fn validate_uuid(field: &str, value: &str) -> Result<(), GatewayError> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| GatewayError::InvalidInput(format!("{field} must be a valid UUID")))
}

pub(crate) fn gateway_error(error: GatewayError, instance: String) -> Response {
    RestError::from_gateway_error(error, instance).into_response()
}

pub(crate) fn ok_json<T>(value: T) -> Response
where
    T: Serialize,
{
    (StatusCode::OK, Json(value)).into_response()
}

pub(crate) fn created_resource(collection_path: &str, id: &str) -> Response {
    (
        StatusCode::CREATED,
        [(
            header::LOCATION,
            created_resource_location(collection_path, id),
        )],
        Json(ResourceCreatedResponse { id: parse_uuid(id) }),
    )
        .into_response()
}

pub(crate) fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) fn parse_json_body_with<Req, M>(body: &Bytes, map_error: M) -> Result<Req, GatewayError>
where
    Req: DeserializeOwned,
    M: FnOnce(serde_json::Error) -> GatewayError,
{
    serde_json::from_slice::<Req>(body).map_err(map_error)
}

pub(crate) async fn list_resource<Q, T, R, Parse, F, Fut>(
    service: GatewayService,
    headers: HeaderMap,
    uri: OriginalUri,
    parse_query: Parse,
    operation: F,
    map: fn(T) -> R,
) -> Response
where
    R: Serialize,
    Parse: FnOnce(&str) -> Result<Q, GatewayError>,
    F: FnOnce(GatewayService, String, Q) -> Fut,
    Fut: Future<Output = Result<T, GatewayError>>,
{
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    let query = match parse_query(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return gateway_error(error, instance),
    };
    match operation(service, session, query).await {
        Ok(resource) => ok_json(map(resource)),
        Err(error) => gateway_error(error, instance),
    }
}

pub(crate) async fn authenticated_resource<T, R, F, Fut>(
    service: GatewayService,
    headers: HeaderMap,
    uri: OriginalUri,
    operation: F,
    map: fn(T) -> R,
) -> Response
where
    R: Serialize,
    F: FnOnce(GatewayService, String) -> Fut,
    Fut: Future<Output = Result<T, GatewayError>>,
{
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match operation(service, session).await {
        Ok(resource) => ok_json(map(resource)),
        Err(error) => gateway_error(error, instance),
    }
}

pub(crate) async fn create_resource<I, Req, F, Fut>(
    service: GatewayService,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
    operation: F,
) -> Response
where
    Req: DeserializeOwned + ValidateInto<I>,
    F: FnOnce(GatewayService, String, I) -> Fut,
    Fut: Future<Output = Result<String, GatewayError>>,
{
    create_resource_with_json_error::<I, Req, F, Fut, _>(
        service,
        headers,
        uri,
        body,
        operation,
        |error| GatewayError::InvalidInput(format!("invalid JSON body: {error}")),
    )
    .await
}

pub(crate) async fn create_resource_with_json_error<I, Req, F, Fut, M>(
    service: GatewayService,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
    operation: F,
    map_json_error: M,
) -> Response
where
    Req: DeserializeOwned + ValidateInto<I>,
    F: FnOnce(GatewayService, String, I) -> Fut,
    Fut: Future<Output = Result<String, GatewayError>>,
    M: FnOnce(serde_json::Error) -> GatewayError,
{
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    let request = match parse_json_body_with::<Req, _>(&body, map_json_error) {
        Ok(request) => request,
        Err(error) => return gateway_error(error, instance),
    };
    let input = match request.validate_into() {
        Ok(input) => input,
        Err(error) => return gateway_error(error, instance),
    };
    match operation(service, session, input).await {
        Ok(id) => created_resource(&instance, &id),
        Err(error) => gateway_error(error, instance),
    }
}

pub(crate) async fn clone_resource<F, Fut>(
    service: GatewayService,
    headers: HeaderMap,
    id: String,
    uri: OriginalUri,
    collection_path: &'static str,
    operation: F,
) -> Response
where
    F: FnOnce(GatewayService, String, String) -> Fut,
    Fut: Future<Output = Result<String, GatewayError>>,
{
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match operation(service, session, id).await {
        Ok(new_id) => created_resource(collection_path, &new_id),
        Err(error) => gateway_error(error, instance),
    }
}

pub(crate) async fn get_resource<T, R, F, Fut>(
    service: GatewayService,
    headers: HeaderMap,
    id: String,
    uri: OriginalUri,
    operation: F,
    map: fn(T) -> R,
) -> Response
where
    R: Serialize,
    F: FnOnce(GatewayService, String, String) -> Fut,
    Fut: Future<Output = Result<T, GatewayError>>,
{
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match operation(service, session, id).await {
        Ok(resource) => ok_json(map(resource)),
        Err(error) => gateway_error(error, instance),
    }
}

pub(crate) async fn update_resource<I, Req, T, R, F, Fut>(
    service: GatewayService,
    headers: HeaderMap,
    id: String,
    uri: OriginalUri,
    body: Bytes,
    operation: F,
    map: fn(T) -> R,
) -> Response
where
    Req: DeserializeOwned + ValidateInto<I>,
    R: Serialize,
    F: FnOnce(GatewayService, String, String, I) -> Fut,
    Fut: Future<Output = Result<T, GatewayError>>,
{
    update_resource_with_json_error::<I, Req, T, R, F, Fut, _>(
        service,
        headers,
        id,
        uri,
        body,
        operation,
        map,
        |error| GatewayError::InvalidInput(format!("invalid JSON body: {error}")),
    )
    .await
}

pub(crate) async fn update_resource_with_json_error<I, Req, T, R, F, Fut, M>(
    service: GatewayService,
    headers: HeaderMap,
    id: String,
    uri: OriginalUri,
    body: Bytes,
    operation: F,
    map: fn(T) -> R,
    map_json_error: M,
) -> Response
where
    Req: DeserializeOwned + ValidateInto<I>,
    R: Serialize,
    F: FnOnce(GatewayService, String, String, I) -> Fut,
    Fut: Future<Output = Result<T, GatewayError>>,
    M: FnOnce(serde_json::Error) -> GatewayError,
{
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    let request = match parse_json_body_with::<Req, _>(&body, map_json_error) {
        Ok(request) => request,
        Err(error) => return gateway_error(error, instance),
    };
    let input = match request.validate_into() {
        Ok(input) => input,
        Err(error) => return gateway_error(error, instance),
    };
    match operation(service, session, id, input).await {
        Ok(resource) => ok_json(map(resource)),
        Err(error) => gateway_error(error, instance),
    }
}

pub(crate) async fn delete_resource<F, Fut>(
    service: GatewayService,
    headers: HeaderMap,
    id: String,
    uri: OriginalUri,
    operation: F,
) -> Response
where
    F: FnOnce(GatewayService, String, String, bool) -> Fut,
    Fut: Future<Output = Result<(), GatewayError>>,
{
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    let ultimate = match parse_delete_resource_query(uri.query().unwrap_or("")) {
        Ok(ultimate) => ultimate,
        Err(error) => return gateway_error(error, instance),
    };
    match operation(service, session, id, ultimate).await {
        Ok(()) => no_content(),
        Err(error) => gateway_error(error, instance),
    }
}

/// Delete handler for resources whose backend delete has no `ultimate` toggle.
pub(crate) async fn delete_resource_without_ultimate<F, Fut>(
    service: GatewayService,
    headers: HeaderMap,
    id: String,
    uri: OriginalUri,
    operation: F,
) -> Response
where
    F: FnOnce(GatewayService, String, String) -> Fut,
    Fut: Future<Output = Result<(), GatewayError>>,
{
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return gateway_error(error, instance);
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match operation(service, session, id).await {
        Ok(()) => no_content(),
        Err(error) => gateway_error(error, instance),
    }
}
