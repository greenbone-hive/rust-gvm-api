// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! OpenAPI generation helpers for the REST adapter.

use aide::{
    openapi::{Header, License, ReferenceOr, SecurityScheme, Server, StatusCode},
    transform::{TransformOpenApi, TransformOperation, TransformResponse},
};
use axum::http::Method;
use axum::Json;
use serde_json::{json, Map, Value};

// Runtime DTO imports are no longer needed centrally — OpenAPI transforms
// now live alongside their handlers in each module.
use crate::auth_policy::{
    classify_runtime_route, runtime_path_from_openapi_path, RestRouteAuthPolicy,
};

mod doc;

pub(crate) use doc::{
    CreateTargetDoc, CreateTaskDoc, GetReportQueryDoc, ModifyTargetDoc, ModifyTaskDoc,
    ProblemDetailDoc, ReportListQueryDoc, ReportResultsQueryDoc, ResourceIdPathDoc,
    ResultListQueryDoc, ScanConfigListQueryDoc, TargetListQueryDoc, TaskListQueryDoc,
};

pub(crate) fn ok_json<T>(
    description: &'static str,
) -> impl FnOnce(TransformResponse<T>) -> TransformResponse<T> {
    move |response| response.description(description)
}

pub(crate) fn created_json<T>(
    description: &'static str,
) -> impl FnOnce(TransformResponse<T>) -> TransformResponse<T> {
    move |mut response| {
        add_location_header(response.inner());
        response.description(description)
    }
}

pub(crate) fn accepted_job_json<T>(
    description: &'static str,
) -> impl FnOnce(TransformResponse<T>) -> TransformResponse<T> {
    move |mut response| {
        add_location_header(response.inner());
        add_retry_after_header(
            response.inner(),
            "Suggested seconds to wait before polling the job.",
        );
        response.description(description)
    }
}

pub(crate) fn problem_response<'a, const N: u16>(
    op: TransformOperation<'a>,
    description: &'static str,
) -> TransformOperation<'a> {
    op.response_with::<N, Json<ProblemDetailDoc>, _>(|mut response| {
        response = response
            .description(description)
            .example(ProblemDetailDoc::example());
        if let Some(problem_json) = response.inner().content.shift_remove("application/json") {
            response
                .inner()
                .content
                .insert("application/problem+json".to_string(), problem_json);
        }
        response
    })
}

pub(crate) fn response_with_retry_after<'a, const N: u16>(
    mut op: TransformOperation<'a>,
    description: &'static str,
) -> TransformOperation<'a> {
    if let Some(response) = op
        .inner_mut()
        .responses
        .as_mut()
        .and_then(|responses| responses.responses.get_mut(&StatusCode::Code(N)))
        .and_then(ReferenceOr::as_item_mut)
    {
        add_retry_after_header(response, description);
    }
    op
}

fn add_location_header(response: &mut aide::openapi::Response) {
    response
        .headers
        .insert("Location".to_string(), location_header());
}

fn add_retry_after_header(response: &mut aide::openapi::Response, description: &'static str) {
    response
        .headers
        .insert("Retry-After".to_string(), retry_after_header(description));
}

fn location_header() -> ReferenceOr<Header> {
    serde_json::from_value(json!({
        "description": "Canonical URI of the created resource.",
        "schema": {
            "type": "string",
            "format": "uri-reference"
        }
    }))
    .expect("static Location header schema is valid")
}

fn retry_after_header(description: &'static str) -> ReferenceOr<Header> {
    serde_json::from_value(json!({
        "description": description,
        "schema": {
            "type": "integer",
            "minimum": 1
        }
    }))
    .expect("static Retry-After header schema is valid")
}

/// Finalize the generated OpenAPI document so its served contract shape matches
/// the curated repository spec for the implemented REST surface.
pub(crate) fn finalize_document(mut document: Value) -> Value {
    document["servers"] = json!([
        {
            "url": "/api/v1",
            "description": "Base path for versioned API endpoints"
        }
    ]);
    document["security"] = json!([
        {
            "bearerAuth": []
        },
        {
            "basicAuth": []
        }
    ]);
    document["tags"] = openapi_tags();

    let source_paths = document["paths"].as_object().cloned().unwrap_or_default();
    let mut normalized_paths = normalize_paths(&source_paths);
    add_probe_server_overrides(&mut normalized_paths);
    normalized_paths.insert(
        "/openapi.json".to_string(),
        json!({
            "get": {
                "operationId": "getOpenApiDocument",
                "tags": ["System"],
                "summary": "Get generated OpenAPI document",
                "description": "Returns the generated OpenAPI document for the implemented REST surface.",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Generated OpenAPI document",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object"
                                }
                            }
                        }
                    }
                }
            }
        }),
    );

    document_backend_unavailable_responses(&mut normalized_paths);

    document["paths"] = Value::Object(normalized_paths);

    apply_route_auth_security(&mut document);

    strip_nullable_types(&mut document);
    document
}

fn openapi_tags() -> Value {
    json!([
        {
            "name": "Sessions",
            "description": "Session lifecycle"
        },
        {
            "name": "Targets",
            "description": "Scan target management"
        },
        {
            "name": "Agents",
            "description": "Current GVMD agent management"
        },
        {
            "name": "Agent Groups",
            "description": "Current GVMD agent-group management"
        },
        {
            "name": "Assets",
            "description": "Generic current GVMD asset management"
        },
        {
            "name": "Configs",
            "description": "Generic current GVMD config management"
        },
        {
            "name": "OCI Image Targets",
            "description": "OCI image target management"
        },
        {
            "name": "Web Application Targets",
            "description": "Web application target management"
        },
        {
            "name": "Alerts",
            "description": "Alert management"
        },
        {
            "name": "Schedules",
            "description": "Schedule management"
        },
        {
            "name": "Credentials",
            "description": "Credential management"
        },
        {
            "name": "Port Lists",
            "description": "Port list management"
        },
        {
            "name": "Feeds",
            "description": "Feed status"
        },
        {
            "name": "Hosts",
            "description": "Discovered host inventory"
        },
        {
            "name": "TLS Certificates",
            "description": "TLS certificate assets"
        },
        {
            "name": "Report Formats",
            "description": "Report export format discovery"
        },
        {
            "name": "Filters",
            "description": "Saved filter discovery"
        },
        {
            "name": "Tags",
            "description": "Tag discovery"
        },
        {
            "name": "Tickets",
            "description": "Ticket discovery"
        },
        {
            "name": "Notes",
            "description": "Note discovery"
        },
        {
            "name": "Overrides",
            "description": "Override discovery"
        },
        {
            "name": "NVTs",
            "description": "NVT catalog discovery"
        },
        {
            "name": "Vulnerabilities",
            "description": "SecInfo vulnerability discovery"
        },
        {
            "name": "NVT Families",
            "description": "NVT family discovery"
        },
        {
            "name": "Users",
            "description": "User management"
        },
        {
            "name": "Groups",
            "description": "Group management"
        },
        {
            "name": "Roles",
            "description": "Role management"
        },
        {
            "name": "Permissions",
            "description": "Permission management"
        },
        {
            "name": "User Settings",
            "description": "Current-user settings"
        },
        {
            "name": "Jobs",
            "description": "Asynchronous job management"
        },
        {
            "name": "Tasks",
            "description": "Scan task management"
        },
        {
            "name": "Audits",
            "description": "Compliance audit management"
        },
        {
            "name": "Reports",
            "description": "Scan report management"
        },
        {
            "name": "Report Exports",
            "description": "Asynchronous report artifact exports"
        },
        {
            "name": "Results",
            "description": "Scan result management"
        },
        {
            "name": "Policies",
            "description": "Compliance policy management"
        },
        {
            "name": "Scan Configs",
            "description": "Scan configuration management"
        },
        {
            "name": "Scanners",
            "description": "Scanner information"
        },
        {
            "name": "Operating Systems",
            "description": "Operating-system asset management"
        },
        {
            "name": "System",
            "description": "System and health endpoints"
        }
    ])
}

fn apply_route_auth_security(document: &mut Value) {
    let Some(paths) = document["paths"].as_object_mut() else {
        return;
    };

    for (openapi_path, methods) in paths {
        let runtime_path = runtime_path_from_openapi_path(openapi_path);
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };

        for (method_name, operation) in methods {
            let Some(operation) = operation.as_object_mut() else {
                continue;
            };
            let Some(method) = openapi_method(method_name) else {
                continue;
            };
            let Some(policy) = classify_runtime_route(&method, &runtime_path) else {
                continue;
            };

            match policy {
                RestRouteAuthPolicy::Protected => {
                    operation.remove("security");
                }
                RestRouteAuthPolicy::Public => {
                    operation.insert("security".to_string(), json!([]));
                }
                RestRouteAuthPolicy::SessionCreate => {
                    operation.insert("security".to_string(), json!([{"basicAuth": []}]));
                }
                RestRouteAuthPolicy::SessionCurrent => {
                    operation.insert("security".to_string(), json!([{"bearerAuth": []}]));
                }
            }
        }
    }
}

fn openapi_method(method_name: &str) -> Option<Method> {
    Some(match method_name {
        "get" => Method::GET,
        "post" => Method::POST,
        "put" => Method::PUT,
        "delete" => Method::DELETE,
        "patch" => Method::PATCH,
        "options" => Method::OPTIONS,
        "head" => Method::HEAD,
        _ => return None,
    })
}

fn document_backend_unavailable_responses(paths: &mut Map<String, Value>) {
    for (path, methods) in paths {
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };
        for (method_name, operation) in methods {
            if openapi_method(method_name).is_none() {
                continue;
            }
            if !operation_can_proxy_to_backend(path, method_name) {
                continue;
            }
            let Some(responses) = operation["responses"].as_object_mut() else {
                continue;
            };
            responses
                .entry("502".to_string())
                .or_insert_with(bad_gateway_response);
        }
    }
}

fn operation_can_proxy_to_backend(path: &str, method_name: &str) -> bool {
    let Some(method) = openapi_method(method_name) else {
        return false;
    };
    let runtime_path = runtime_path_from_openapi_path(path);

    match classify_runtime_route(&method, &runtime_path) {
        Some(RestRouteAuthPolicy::Protected | RestRouteAuthPolicy::SessionCreate) => true,
        Some(RestRouteAuthPolicy::Public) => {
            matches!(runtime_path.as_str(), "/ready" | "/api/v1/version")
        }
        Some(RestRouteAuthPolicy::SessionCurrent) | None => false,
    }
}

fn bad_gateway_response() -> Value {
    json!({
        "description": "Backend service unreachable or connection failed",
        "content": {
            "application/problem+json": {
                "schema": {
                    "$ref": "#/components/schemas/ProblemDetail"
                },
                "example": ProblemDetailDoc::example()
            }
        }
    })
}

fn strip_nullable_types(value: &mut Value) {
    *value = normalize_nullable_schema(std::mem::take(value));
}

fn normalize_nullable_schema(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut object = object
                .into_iter()
                .map(|(key, value)| (key, normalize_nullable_schema(value)))
                .collect::<Map<String, Value>>();

            if let Some(Value::Array(types)) = object.get_mut("type") {
                let mut filtered = types
                    .iter()
                    .filter(|ty| ty.as_str() != Some("null"))
                    .cloned()
                    .collect::<Vec<_>>();
                if filtered.len() == 1 {
                    object.insert("type".to_string(), filtered.remove(0));
                } else if filtered.len() != types.len() {
                    *types = filtered;
                }
            }

            collapse_nullable_combinator(&object, "anyOf")
                .or_else(|| collapse_nullable_combinator(&object, "oneOf"))
                .unwrap_or(Value::Object(object))
        }
        Value::Array(array) => Value::Array(
            array
                .into_iter()
                .map(normalize_nullable_schema)
                .collect::<Vec<_>>(),
        ),
        other => other,
    }
}

fn collapse_nullable_combinator(object: &Map<String, Value>, key: &str) -> Option<Value> {
    let Value::Array(options) = object.get(key)? else {
        return None;
    };

    let filtered = options
        .iter()
        .filter(|option| !is_null_schema(option))
        .cloned()
        .collect::<Vec<_>>();

    if filtered.len() == options.len() {
        return None;
    }

    if filtered.len() == 1 {
        let mut remaining = filtered.into_iter().next().unwrap();
        if let Value::Object(ref mut remaining_object) = remaining {
            for (other_key, other_value) in object {
                if other_key != key && !remaining_object.contains_key(other_key) {
                    remaining_object.insert(other_key.clone(), other_value.clone());
                }
            }
        }
        Some(remaining)
    } else {
        let mut normalized = object.clone();
        normalized.insert(key.to_string(), Value::Array(filtered));
        Some(Value::Object(normalized))
    }
}

fn is_null_schema(value: &Value) -> bool {
    matches!(value, Value::Object(object) if object.get("type").and_then(Value::as_str) == Some("null"))
}

fn normalize_paths(source_paths: &Map<String, Value>) -> Map<String, Value> {
    source_paths
        .iter()
        .map(|(source_path, path_item)| {
            let normalized_path = source_path.strip_prefix("/api/v1").map_or_else(
                || source_path.clone(),
                |suffix| {
                    if suffix.is_empty() {
                        "/".to_string()
                    } else {
                        suffix.to_string()
                    }
                },
            );
            (normalized_path, path_item.clone())
        })
        .collect()
}

fn add_probe_server_overrides(normalized_paths: &mut Map<String, Value>) {
    let servers = json!([
        {
            "url": "/",
            "description": "Root path for unversioned liveness and readiness probes"
        }
    ]);

    for path in ["/health", "/ready"] {
        if let Some(path_item) = normalized_paths
            .get_mut(path)
            .and_then(Value::as_object_mut)
        {
            path_item.insert("servers".to_string(), servers.clone());
        }
    }
}

/// Configure the top-level generated OpenAPI document.
pub(crate) fn configure(api: TransformOpenApi<'_>) -> TransformOpenApi<'_> {
    api.title("GVM REST API")
        .description("Generated OpenAPI for the currently implemented REST adapter surface.")
        .version(env!("CARGO_PKG_VERSION"))
        .license(License {
            name: "AGPL-3.0-or-later".to_string(),
            identifier: Some("AGPL-3.0-or-later".to_string()),
            url: None,
            extensions: Default::default(),
        })
        .server(Server {
            url: "/".to_string(),
            description: Some("Runtime-served REST endpoints".to_string()),
            variables: Default::default(),
            extensions: Default::default(),
        })
        .security_scheme(
            "bearerAuth",
            SecurityScheme::Http {
                scheme: "bearer".to_string(),
                bearer_format: None,
                description: Some(
                    "Opaque session token returned by the session lifecycle API.".to_string(),
                ),
                extensions: Default::default(),
            },
        )
        .security_scheme(
            "basicAuth",
            SecurityScheme::Http {
                scheme: "basic".to_string(),
                bearer_format: None,
                description: Some(
                    "HTTP Basic credentials used either to create a persistent session or to authenticate one protected request with request-scoped backend cleanup.".to_string(),
                ),
                extensions: Default::default(),
            },
        )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "openapi_test.rs"]
mod openapi_test;
