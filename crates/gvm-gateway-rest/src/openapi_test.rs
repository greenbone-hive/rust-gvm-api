// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use serde_json::{json, Map, Value};

use super::{normalize_paths, openapi_method};
use crate::auth_policy::{
    classify_runtime_route, runtime_path_from_openapi_path, RestRouteAuthPolicy,
};
use crate::router::build_openapi;

#[test]
fn generated_openapi_matches_curated_spec() {
    let generated = build_openapi();
    let curated = root_spec();
    let generated_routes = route_methods(&generated);
    let curated_routes = curated_route_methods(&curated);

    assert_route_methods_match(
        &generated_routes,
        &curated_routes,
        "generated OpenAPI route/method set must match the complete curated spec",
    );

    for (generated_path, method) in curated_routes {
        let generated_path_item = &generated["paths"][&generated_path];
        let curated_path_item = resolve_curated_path_item(&curated["paths"][&generated_path]);
        assert_eq!(
            generated_path_item.get("servers"),
            curated_path_item.get("servers"),
            "path-level servers drift for {generated_path}"
        );

        let generated_op = op(&generated, &generated_path, &method);
        let curated_op = &curated_path_item[&method];
        assert_eq!(
            generated_op["operationId"], curated_op["operationId"],
            "operationId drift for {method} {generated_path}"
        );

        let generated_statuses = response_statuses(generated_op);
        let curated_statuses = response_statuses(curated_op);
        assert_string_sets_match(
            &generated_statuses,
            &curated_statuses,
            &format!("generated response status drift for {method} {generated_path}"),
        );
    }
}

#[test]
fn generated_openapi_preserves_key_schema_fields() {
    let generated = build_openapi();

    let target_props = &generated["components"]["schemas"]["Target"]["properties"];
    assert!(target_props.get("excludeHosts").is_some());
    assert!(target_props.get("aliveTest").is_some());
    assert!(target_props.get("portList").is_some());
    assert_eq!(target_props["id"]["format"], "uuid");

    let pagination_props = &generated["components"]["schemas"]["Pagination"]["properties"];
    assert!(pagination_props.get("perPage").is_some());
    assert!(pagination_props.get("totalPages").is_some());

    let create_target_required = generated["components"]["schemas"]["CreateTarget"]["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert!(create_target_required.contains("name"));
    assert!(create_target_required.contains("hosts"));

    let modify_target_props = &generated["components"]["schemas"]["ModifyTarget"]["properties"];
    assert!(modify_target_props.get("reverseLookupOnly").is_some());
    assert!(modify_target_props.get("reverseLookupUnify").is_some());
    assert!(modify_target_props.get("sshCredentialId").is_some());
    assert!(modify_target_props.get("smbCredentialId").is_some());
    assert!(modify_target_props.get("esxiCredentialId").is_some());
    assert!(modify_target_props.get("snmpCredentialId").is_some());

    let modify_task_props = &generated["components"]["schemas"]["ModifyTask"]["properties"];
    assert!(modify_task_props.get("alterable").is_some());
    assert!(modify_task_props.get("preferences").is_some());
    let preferences_description = modify_task_props["preferences"]["description"]
        .as_str()
        .expect("ModifyTask.preferences should document update semantics");
    assert!(preferences_description.contains("Omitted or empty objects"));
    assert!(preferences_description.contains("clearing preferences is not supported"));

    let create_agent_group_required = generated["components"]["schemas"]["CreateAgentGroup"]
        ["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert!(create_agent_group_required.contains("name"));
    assert!(create_agent_group_required.contains("schedulerCronTime"));

    let modify_agent_group_required = generated["components"]["schemas"]["ModifyAgentGroup"]
        ["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert!(modify_agent_group_required.contains("schedulerCronTime"));

    let scanner_instruction_parameters = generated["paths"]
        ["/scanners/{id}/agent-installer-instruction"]["get"]["parameters"]
        .as_array()
        .unwrap();
    let origin_url_parameter = scanner_instruction_parameters
        .iter()
        .find(|parameter| parameter["name"] == "originUrl")
        .expect("agent installer instruction must document originUrl");
    assert_eq!(origin_url_parameter["schema"]["format"], "uri");

    let schemas = &generated["components"]["schemas"];
    let create_alert_props = &schemas["CreateAlert"]["properties"];
    assert!(create_alert_props.get("eventData").is_some());
    assert!(create_alert_props.get("conditionData").is_some());
    assert!(create_alert_props.get("methodData").is_some());
    let modify_alert_props = &schemas["ModifyAlert"]["properties"];
    assert!(modify_alert_props.get("name").is_some());
    assert!(modify_alert_props.get("eventData").is_some());
    assert!(modify_alert_props.get("conditionData").is_some());
    assert!(modify_alert_props.get("methodData").is_some());
    let create_credential_props = &schemas["CreateCredential"]["properties"];
    assert!(create_credential_props.get("privateKey").is_some());
    assert!(create_credential_props.get("certificate").is_some());
    assert!(create_credential_props.get("community").is_some());
    assert!(create_credential_props.get("privacyPassword").is_some());
    let modify_credential_props = &schemas["ModifyCredential"]["properties"];
    assert!(modify_credential_props.get("privateKey").is_some());
    assert!(modify_credential_props.get("certificate").is_some());
    assert!(modify_credential_props.get("community").is_some());
    assert!(modify_credential_props.get("privacyPassword").is_some());
    assert_empty_array_clear_contract(
        &schemas["UpdateNote"]["properties"]["hosts"],
        "UpdateNote.hosts",
        "empty array clears",
    );
    assert_empty_array_clear_contract(
        &schemas["UpdateOverride"]["properties"]["hosts"],
        "UpdateOverride.hosts",
        "empty array clears",
    );
    assert_empty_array_clear_contract(
        &schemas["ModifyUser"]["properties"]["roles"],
        "ModifyUser.roles",
        "empty array clears",
    );
    assert!(schemas["ModifyPortList"]["properties"]
        .get("name")
        .is_some());
    assert!(schemas["ModifyUser"]["properties"].get("name").is_some());

    let credential_store_responses = &generated["paths"]["/credential-stores"]["get"]["responses"];
    assert!(credential_store_responses.get("501").is_some());

    let report_vulnerability_props = &schemas["ReportVulnerability"]["properties"];
    assert!(report_vulnerability_props.get("hostsCount").is_some());
    assert!(report_vulnerability_props.get("occurrences").is_some());

    let report_error_props = &schemas["ReportError"]["properties"];
    assert!(report_error_props.get("nvtName").is_some());
    assert!(report_error_props.get("threat").is_none());

    let report_closed_cve_props = &schemas["ReportClosedCve"]["properties"];
    assert!(report_closed_cve_props.get("cve").is_some());
    assert!(report_closed_cve_props.get("name").is_none());

    let task_props = &schemas["Task"]["properties"];
    assert_eq!(
        task_props["lastReport"]["$ref"],
        json!("#/components/schemas/TaskReportReference")
    );
    assert!(task_props.get("usageType").is_some());
    assert!(task_props.get("trend").is_some());

    let scanner_props = &schemas["Scanner"]["properties"];
    assert!(scanner_props.get("credential").is_some());
    assert!(scanner_props.get("caPub").is_some());

    let port_list_props = &schemas["PortList"]["properties"];
    assert!(port_list_props.get("portRange").is_some());

    // Generic resources are additive DTOs: their discriminators and variant
    // fields must not leak into the established specialized schemas.
    assert!(schemas["GenericAsset"]["properties"].get("type").is_some());
    assert!(schemas["GenericAsset"]["properties"]
        .get("identifiers")
        .is_some());
    assert!(schemas["Host"]["properties"].get("type").is_none());
    assert!(schemas["Host"]["properties"].get("identifiers").is_none());
    assert!(schemas["GenericConfig"]["properties"]
        .get("usageType")
        .is_some());
    assert!(schemas["ScanConfig"]["properties"]
        .get("familyCount")
        .is_some());
}

#[test]
fn generated_openapi_closes_every_request_object_without_closing_extension_maps() {
    let generated = build_openapi();
    let schemas = &generated["components"]["schemas"];

    // Keep an explicit inventory of every current request-body object so the
    // strictness audit covers less prominent and newly added write endpoints,
    // including doc-only identity schemas. Policies and audits intentionally
    // reuse the scan-config and task schemas listed here.
    for schema_name in [
        "CreateTarget",
        "ModifyTarget",
        "CreateOciImageTarget",
        "ModifyOciImageTarget",
        "CreateWebApplicationTarget",
        "ModifyWebApplicationTarget",
        "CreateTask",
        "ModifyTask",
        "CreateAlert",
        "ModifyAlert",
        "CreateCredential",
        "ModifyCredential",
        "CreateSchedule",
        "ModifySchedule",
        "CreatePortList",
        "ModifyPortList",
        "CreateScanConfig",
        "ModifyScanConfig",
        "CreateUser",
        "ModifyUser",
        "CreateGroup",
        "ModifyGroup",
        "CreateRole",
        "ModifyRole",
        "CreatePermission",
        "ModifyPermission",
        "ModifyUserSetting",
        "CreateHost",
        "UpdateHost",
        "CreateFilter",
        "UpdateFilter",
        "CreateTag",
        "UpdateTag",
        "CreateNote",
        "UpdateNote",
        "CreateOverride",
        "UpdateOverride",
        "GvmdReportFormatExportRequest",
        "JsonReportExportRequest",
    ] {
        assert_eq!(
            schemas[schema_name]["additionalProperties"],
            json!(false),
            "{schema_name} should reject unknown top-level fields"
        );
    }

    // Open map fields remain extensible for backend-defined keys.
    assert!(
        schemas["CreateTask"]["properties"]["preferences"]["additionalProperties"].is_object(),
        "CreateTask.preferences should remain an open string map"
    );
    assert!(
        schemas["ModifyTask"]["properties"]["preferences"]["additionalProperties"].is_object(),
        "ModifyTask.preferences should remain an open string map"
    );
    assert!(
        schemas["CreateAlert"]["properties"]["eventData"]["additionalProperties"].is_object(),
        "CreateAlert.eventData should remain an open string map"
    );
    assert!(
        schemas["CreateAlert"]["properties"]["conditionData"]["additionalProperties"].is_object(),
        "CreateAlert.conditionData should remain an open string map"
    );
    assert!(
        schemas["CreateAlert"]["properties"]["methodData"]["additionalProperties"].is_object(),
        "CreateAlert.methodData should remain an open string map"
    );
    assert!(
        schemas["ModifyAlert"]["properties"]["eventData"]["additionalProperties"].is_object(),
        "ModifyAlert.eventData should remain an open string map"
    );
    assert!(
        schemas["ModifyAlert"]["properties"]["conditionData"]["additionalProperties"].is_object(),
        "ModifyAlert.conditionData should remain an open string map"
    );
    assert!(
        schemas["ModifyAlert"]["properties"]["methodData"]["additionalProperties"].is_object(),
        "ModifyAlert.methodData should remain an open string map"
    );
}

#[test]
fn generated_openapi_feed_version_matches_required_runtime_contract() {
    let generated = build_openapi();
    let required = generated["components"]["schemas"]["Feed"]["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();

    assert!(required.contains("type"));
    assert!(required.contains("name"));
    assert!(required.contains("version"));
}

#[test]
fn generated_openapi_secinfo_ids_remain_plain_strings() {
    let generated = build_openapi();
    let schemas = &generated["components"]["schemas"];

    // SecInfo item ids are backend-defined names like CVE and advisory ids, so
    // these contracts must remain plain strings instead of UUID-formatted ids.
    assert_eq!(schemas["Cve"]["properties"]["id"]["type"], "string");
    assert!(schemas["Cve"]["properties"]["id"].get("format").is_none());
    assert_eq!(schemas["Cpe"]["properties"]["id"]["type"], "string");
    assert!(schemas["Cpe"]["properties"]["id"].get("format").is_none());
    assert_eq!(
        schemas["CertBundAdvisory"]["properties"]["id"]["type"],
        "string"
    );
    assert!(schemas["CertBundAdvisory"]["properties"]["id"]
        .get("format")
        .is_none());
    assert_eq!(
        schemas["DfnCertAdvisory"]["properties"]["id"]["type"],
        "string"
    );
    assert!(schemas["DfnCertAdvisory"]["properties"]["id"]
        .get("format")
        .is_none());
}

#[test]
fn generated_openapi_documents_open_enum_fields_as_non_exhaustive() {
    let generated = build_openapi();
    let schemas = &generated["components"]["schemas"];

    // Open enums deliberately keep OpenAPI enum lists for docs/codegen while
    // their descriptions define the non-exhaustive runtime contract.
    assert_open_enum_schema(
        schemas,
        &schemas["CredentialType"],
        json!([
            "cc", "pw", "snmp", "snmpv3", "up", "usk", "cs_cc", "cs_pw", "cs_pgp", "cs_smime",
            "cs_snmp", "cs_up", "cs_usk"
        ]),
        "CredentialType",
    );
    assert_open_enum_schema(
        schemas,
        &schemas["FeedType"],
        json!(["NVT", "CERT", "SCAP", "GVMD_DATA"]),
        "FeedType",
    );
    assert_open_enum_schema(
        schemas,
        &schemas["AuthenticationType"],
        json!(["file", "ldap_connect", "radius_connect"]),
        "AuthenticationType",
    );
    assert_open_enum_schema(
        schemas,
        &schemas["ScanConfigType"],
        json!([0, 1]),
        "ScanConfigType",
    );
    assert_open_enum_schema(
        schemas,
        &schemas["TicketStatus"],
        json!(["Open", "Fixed", "Closed"]),
        "TicketStatus",
    );
    assert_open_enum_schema(
        schemas,
        &schemas["AssetType"],
        json!(["host", "os", "tls_certificate"]),
        "AssetType",
    );
    assert_open_enum_schema(
        schemas,
        &schemas["ConfigUsageType"],
        json!(["scan", "audit", "policy"]),
        "ConfigUsageType",
    );

    let alert_props = &schemas["Alert"]["properties"];
    assert_open_enum_schema(
        schemas,
        &alert_props["event"],
        json!(["task_run_status_changed", "updated_secinfo", "new_secinfo"]),
        "Alert.event",
    );
    assert_open_enum_schema(
        schemas,
        &alert_props["condition"],
        json!([
            "always",
            "filter_count_at_least",
            "filter_count_changed",
            "severity_at_least",
            "severity_changed"
        ]),
        "Alert.condition",
    );
    assert_open_enum_schema(
        schemas,
        &alert_props["method"],
        json!([
            "email",
            "http_get",
            "scp",
            "send_email",
            "smb",
            "snmp",
            "sourcefire_connector",
            "start_task",
            "syslog",
            "tippingpoint",
            "verinice_ce",
            "verinice_net",
            "alemba"
        ]),
        "Alert.method",
    );

    let create_alert_props = &schemas["CreateAlert"]["properties"];
    assert_open_enum_schema(
        schemas,
        &create_alert_props["event"],
        json!(["task_run_status_changed", "updated_secinfo", "new_secinfo"]),
        "CreateAlert.event",
    );
    assert_open_enum_schema(
        schemas,
        &create_alert_props["condition"],
        json!([
            "always",
            "filter_count_at_least",
            "filter_count_changed",
            "severity_at_least",
            "severity_changed"
        ]),
        "CreateAlert.condition",
    );
    assert_open_enum_schema(
        schemas,
        &create_alert_props["method"],
        json!([
            "email",
            "http_get",
            "scp",
            "send_email",
            "smb",
            "snmp",
            "sourcefire_connector",
            "start_task",
            "syslog",
            "tippingpoint",
            "verinice_ce",
            "verinice_net",
            "alemba"
        ]),
        "CreateAlert.method",
    );

    assert_open_enum_schema(
        schemas,
        &schemas["Credential"]["properties"]["type"],
        json!([
            "cc", "pw", "snmp", "snmpv3", "up", "usk", "cs_cc", "cs_pw", "cs_pgp", "cs_smime",
            "cs_snmp", "cs_up", "cs_usk"
        ]),
        "Credential.type",
    );
    assert_open_enum_schema(
        schemas,
        &schemas["CreateCredential"]["properties"]["type"],
        json!([
            "cc", "pw", "snmp", "snmpv3", "up", "usk", "cs_cc", "cs_pw", "cs_pgp", "cs_smime",
            "cs_snmp", "cs_up", "cs_usk"
        ]),
        "CreateCredential.type",
    );
    assert_open_enum_schema(
        schemas,
        &schemas["Feed"]["properties"]["type"],
        json!(["NVT", "CERT", "SCAP", "GVMD_DATA"]),
        "Feed.type",
    );
    assert_open_enum_schema(
        schemas,
        &schemas["User"]["allOf"][1]["properties"]["authenticationType"],
        json!(["file", "ldap_connect", "radius_connect"]),
        "User.authenticationType",
    );
}

#[test]
fn generated_and_curated_generic_resource_contracts_match_semantics() {
    // Route parity checks operation IDs/statuses globally. This focused guard
    // additionally covers the open enums and asymmetric delete semantics that
    // are central to the generic asset/config contract.
    let generated = build_openapi();
    let generated_schemas = &generated["components"]["schemas"];
    let emerging_path = root_spec_path()
        .parent()
        .expect("root spec should have a directory")
        .join("emerging.yaml");
    let curated = read_yaml(&emerging_path);

    for name in ["AssetType", "ConfigUsageType"] {
        assert_eq!(
            generated_schemas[name]["enum"], curated["components"]["schemas"][name]["enum"],
            "generated and curated {name} known values must match"
        );
        assert_eq!(
            generated_schemas[name]["description"],
            curated["components"]["schemas"][name]["description"],
            "generated and curated {name} openness text must match"
        );
    }

    for (path, method) in [
        ("/assets", "get"),
        ("/assets/{id}", "get"),
        ("/assets/{id}", "put"),
    ] {
        let generated_type = op(&generated, path, method)["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "type")
            .unwrap_or_else(|| panic!("generated {method} {path} must document type"));
        let curated_type = curated["paths"][path][method]["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "type")
            .unwrap_or_else(|| panic!("curated {method} {path} must document type"));
        assert_eq!(generated_type["required"], json!(true));
        assert_eq!(curated_type["required"], json!(true));
    }

    let asset_delete = op(&generated, "/assets/{id}", "delete");
    let asset_parameters = asset_delete["parameters"].as_array().unwrap();
    assert!(asset_parameters
        .iter()
        .all(|parameter| parameter["name"] != "ultimate"));
    let config_delete = op(&generated, "/configs/{id}", "delete");
    assert!(config_delete["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .any(|parameter| parameter["name"] == "ultimate"));

    assert!(generated["paths"]["/assets"].get("post").is_none());
    assert!(generated["paths"]["/configs"].get("post").is_none());
    assert!(generated["paths"]["/configs/{id}"].get("put").is_none());
}

#[test]
fn generated_openapi_declares_every_operation_tag() {
    let generated = build_openapi();
    let declared_tags = generated["tags"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tag| tag["name"].as_str())
        .collect::<BTreeSet<_>>();

    for (path, methods) in generated["paths"].as_object().unwrap() {
        for (method, operation) in methods.as_object().unwrap() {
            if openapi_method(method).is_none() {
                continue;
            }
            for tag in operation["tags"].as_array().into_iter().flatten() {
                let tag = tag.as_str().unwrap();
                assert!(
                    declared_tags.contains(tag),
                    "missing top-level tag declaration for {tag} used by {method} {path}"
                );
            }
        }
    }
}

#[test]
fn generated_openapi_includes_session_schemas() {
    let generated = build_openapi();
    let schemas = generated["components"]["schemas"].as_object().unwrap();

    assert!(
        schemas.contains_key("SessionCreated"),
        "missing SessionCreated schema"
    );
    assert!(
        schemas.contains_key("SessionInfo"),
        "missing SessionInfo schema"
    );
}

#[test]
fn generated_openapi_session_state_matches_inspectable_contract() {
    let generated = build_openapi();
    let schemas = &generated["components"]["schemas"];

    assert_eq!(
        schemas["SessionInfo"]["properties"]["state"]["$ref"],
        json!("#/components/schemas/SessionState")
    );
    assert_eq!(
        schemas["SessionState"]["enum"],
        json!(["active", "expired"]),
        "SessionInfo state must only document states returned by GET /session"
    );
}

#[test]
fn generated_openapi_includes_task_schemas() {
    let generated = build_openapi();
    let schemas = generated["components"]["schemas"].as_object().unwrap();

    assert!(schemas.contains_key("Task"), "missing Task schema");
    assert!(schemas.contains_key("TaskList"), "missing TaskList schema");
    assert!(
        schemas.contains_key("CreateTask"),
        "missing CreateTask schema"
    );
    assert!(
        schemas.contains_key("ModifyTask"),
        "missing ModifyTask schema"
    );
    assert!(
        schemas.contains_key("TaskAction"),
        "missing TaskAction schema"
    );
}

#[test]
fn generated_openapi_applies_route_auth_policy_consistently() {
    let generated = build_openapi();

    for (path, method_name) in route_methods(&generated) {
        let method =
            openapi_method(&method_name).expect("route_methods returns valid HTTP methods");
        let runtime_path = runtime_path_from_openapi_path(&path);
        let operation = op(&generated, &path, &method_name);
        let policy = classify_runtime_route(&method, &runtime_path)
            .unwrap_or_else(|| panic!("missing auth policy for {method_name} {path}"));

        match policy {
            RestRouteAuthPolicy::Public => {
                assert_eq!(
                    operation["security"],
                    json!([]),
                    "{method_name} {path} should explicitly disable auth"
                );
            }
            RestRouteAuthPolicy::SessionCreate => {
                assert_eq!(
                    operation["security"],
                    json!([{"basicAuth": []}]),
                    "{method_name} {path} should require Basic auth"
                );
            }
            RestRouteAuthPolicy::SessionCurrent => {
                assert_eq!(
                    operation["security"],
                    json!([{"bearerAuth": []}]),
                    "{method_name} {path} should require Bearer auth"
                );
            }
            RestRouteAuthPolicy::Protected => {
                assert!(
                    operation.get("security").is_none(),
                    "{method_name} {path} should inherit dual protected-route auth"
                );
            }
        }
    }
}

#[test]
fn generated_openapi_documents_backend_timezone_contract() {
    let generated = build_openapi();
    let operation = op(&generated, "/timezones", "get");
    let schemas = &generated["components"]["schemas"];

    assert_eq!(operation["operationId"], json!("getTimezones"));
    assert_eq!(
        response_statuses(operation),
        BTreeSet::from(["200", "401", "501", "502"])
    );
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        json!("#/components/schemas/TimezoneList")
    );
    assert_eq!(
        schemas["Timezone"]["required"],
        json!(["name"]),
        "timezone items must only require the backend-provided timezone name"
    );
}

#[test]
fn generated_openapi_excludes_the_browser_docs_ui() {
    // The browser UI is an operational convenience, not part of the client API
    // contract, so generating the contract must never publish it as an API path.
    let generated = build_openapi();

    assert!(generated["paths"].get("/docs").is_none());
    assert!(generated["paths"]
        .get("/docs/redoc.standalone.js")
        .is_none());
}

#[test]
fn normalize_paths_strips_runtime_api_prefix() {
    let source_paths = serde_json::from_value::<Map<String, Value>>(serde_json::json!({
        "/health": { "get": {} },
        "/ready": { "get": {} },
        "/api/v1/version": { "get": {} },
        "/api/v1/reports/{id}/exports": { "post": {} }
    }))
    .unwrap();

    let normalized = normalize_paths(&source_paths);

    assert!(normalized.contains_key("/health"));
    assert!(normalized.contains_key("/ready"));
    assert!(normalized.contains_key("/version"));
    assert!(normalized.contains_key("/reports/{id}/exports"));
    assert!(!normalized.contains_key("/api/v1/version"));
    assert!(!normalized.contains_key("/api/v1/reports/{id}/exports"));
}

fn root_spec() -> Value {
    read_yaml(&root_spec_path())
}

fn curated_route_methods(root_spec: &Value) -> BTreeSet<(String, String)> {
    root_spec["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(path, path_item_ref)| {
            operation_methods(&resolve_curated_path_item(path_item_ref))
                .into_iter()
                .map(move |method| (path.clone(), method))
        })
        .collect()
}

fn route_methods(doc: &Value) -> BTreeSet<(String, String)> {
    doc["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(path, path_item)| {
            operation_methods(path_item)
                .into_iter()
                .map(move |method| (path.clone(), method))
        })
        .collect()
}

fn assert_route_methods_match(
    generated: &BTreeSet<(String, String)>,
    curated: &BTreeSet<(String, String)>,
    context: &str,
) {
    let generated_only = generated.difference(curated).collect::<Vec<_>>();
    let curated_only = curated.difference(generated).collect::<Vec<_>>();

    assert!(
        generated_only.is_empty() && curated_only.is_empty(),
        "{context}: generated_only={generated_only:?}, curated_only={curated_only:?}"
    );
}

fn assert_string_sets_match(generated: &BTreeSet<&str>, curated: &BTreeSet<&str>, context: &str) {
    let generated_only = generated.difference(curated).collect::<Vec<_>>();
    let curated_only = curated.difference(generated).collect::<Vec<_>>();

    assert!(
        generated_only.is_empty() && curated_only.is_empty(),
        "{context}: generated_only={generated_only:?}, curated_only={curated_only:?}"
    );
}

fn operation_methods(path_item: &Value) -> Vec<String> {
    path_item
        .as_object()
        .unwrap()
        .keys()
        .filter(|method| openapi_method(method).is_some())
        .cloned()
        .collect()
}

fn resolve_curated_path_item(path_item_ref: &Value) -> Value {
    let reference = path_item_ref["$ref"]
        .as_str()
        .expect("root spec path items should use file refs");

    resolve_spec_ref(&root_spec_path(), reference)
}

fn resolve_spec_ref(current_doc_path: &Path, reference: &str) -> Value {
    let (doc_ref, pointer) = reference
        .split_once('#')
        .unwrap_or_else(|| panic!("path item ref `{reference}` should include a JSON pointer"));
    let doc_path = if doc_ref.is_empty() {
        current_doc_path.to_path_buf()
    } else {
        current_doc_path
            .parent()
            .expect("spec document should have a parent directory")
            .join(doc_ref)
    };

    read_yaml(&doc_path)
        .pointer(pointer)
        .unwrap_or_else(|| panic!("missing path item ref target `{reference}`"))
        .clone()
}

fn root_spec_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/rest-api/openapi.yaml")
}

fn read_yaml(path: &Path) -> Value {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read `{}`: {error}", path.display()));
    serde_yaml::from_str(&source)
        .unwrap_or_else(|error| panic!("failed to parse `{}`: {error}", path.display()))
}

fn op<'a>(doc: &'a Value, path: &str, method: &str) -> &'a Value {
    &doc["paths"][path][method]
}

fn response_statuses(operation: &Value) -> BTreeSet<&str> {
    operation["responses"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

fn assert_open_enum_schema(schemas: &Value, schema: &Value, expected_values: Value, context: &str) {
    let schema = resolve_local_schema_ref(schemas, schema);

    assert_eq!(
        schema["enum"], expected_values,
        "{context} should list known values for OpenAPI docs and client generation"
    );

    let description = schema["description"]
        .as_str()
        .unwrap_or_else(|| panic!("{context} should describe the open-enum contract"));
    assert!(
        description.contains("This list is not exhaustive"),
        "{context} should document that known enum values are non-exhaustive"
    );
    assert!(
        description.contains("unknown future values"),
        "{context} should document future backend values"
    );
    assert!(
        description.contains("clients must preserve them"),
        "{context} should document client preservation of unknown values"
    );
}

fn resolve_local_schema_ref<'a>(schemas: &'a Value, schema: &'a Value) -> &'a Value {
    let Some(reference) = schema["$ref"].as_str() else {
        return schema;
    };
    let Some(name) = reference.strip_prefix("#/components/schemas/") else {
        return schema;
    };
    &schemas[name]
}

fn assert_empty_array_clear_contract(schema: &Value, context: &str, clear_phrase: &str) {
    let description = schema["description"]
        .as_str()
        .unwrap_or_else(|| panic!("{context} should document empty-array update semantics"));
    for phrase in ["Omitted", "null", "unchanged", clear_phrase] {
        assert!(
            description.contains(phrase),
            "{context} description should mention {phrase:?}; description={description:?}"
        );
    }
}
