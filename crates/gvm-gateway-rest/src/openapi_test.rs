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
fn epss_schema_is_bounded_and_excludes_report_vulnerabilities() {
    // Issue #620 adds EPSS only to catalog NVTs and ordinary-result NVT refs;
    // generated and curated contracts must agree on ranges and the #624 boundary.
    let generated = build_openapi();
    let schemas = &generated["components"]["schemas"];
    assert!(schemas["Nvt"]["properties"].get("epss").is_some());
    assert!(schemas["NvtRef"]["properties"].get("epss").is_some());
    assert_eq!(
        schemas["EpssSelection"]["properties"]["score"]["minimum"],
        0.0
    );
    assert_eq!(
        schemas["EpssSelection"]["properties"]["score"]["maximum"],
        1.0
    );
    assert_eq!(
        schemas["EpssSelection"]["properties"]["percentile"]["minimum"],
        0.0
    );
    assert_eq!(
        schemas["EpssSelection"]["properties"]["percentile"]["maximum"],
        100.0
    );
    assert_eq!(
        schemas["EpssSelection"]["properties"]["severity"]["maximum"],
        10.0
    );
    assert_eq!(
        schemas["EpssSelection"]["properties"]["severity"]["minimum"],
        0.0
    );
    assert_eq!(
        schemas["EpssSelection"]["properties"]["cve"]["type"],
        "string"
    );
    assert!(schemas.get("EpssCve").is_none());
    assert_eq!(
        schemas["ReportVulnerability"]["properties"]["nvt"]["$ref"],
        "#/components/schemas/NvtRefSummary"
    );
    assert!(schemas["NvtRefSummary"]["properties"].get("epss").is_none());

    let spec_dir = root_spec_path()
        .parent()
        .expect("REST spec directory")
        .to_path_buf();
    let results = read_yaml(&spec_dir.join("results.yaml"));
    let supporting = read_yaml(&spec_dir.join("supporting-resources.yaml"));
    let reports = read_yaml(&spec_dir.join("reports.yaml"));
    assert!(results["components"]["schemas"]["NvtRef"]["properties"]
        .get("epss")
        .is_some());
    assert_eq!(
        results["components"]["schemas"]["EpssSelection"]["properties"]["percentile"]["maximum"],
        100
    );
    assert_eq!(
        results["components"]["schemas"]["EpssSelection"]["properties"]["cve"]["type"],
        "string"
    );
    assert!(results["components"]["schemas"].get("EpssCve").is_none());
    assert!(supporting["components"]["schemas"]["Nvt"]["properties"]
        .get("epss")
        .is_some());
    assert_eq!(
        reports["components"]["schemas"]["ReportVulnerability"]["properties"]["nvt"]["$ref"],
        "./results.yaml#/components/schemas/NvtRefSummary"
    );
}

#[test]
fn qod_schema_matches_gmp_optionality_semantics_and_range() {
    // Issue #623 exposes the one shared result schema across list, detail,
    // report, and embedded-report surfaces. Generated and curated OpenAPI must
    // both retain GMP's optional children and 0..=100 percentage semantics.
    let generated = build_openapi();
    let schemas = &generated["components"]["schemas"];
    assert_eq!(
        schemas["Result"]["properties"]["qod"]["$ref"],
        "#/components/schemas/Qod"
    );
    assert_eq!(schemas["Qod"]["properties"]["value"]["minimum"], 0);
    assert_eq!(schemas["Qod"]["properties"]["value"]["maximum"], 100);
    assert_eq!(schemas["Qod"]["properties"]["type"]["type"], "string");
    assert!(schemas["Qod"]["properties"]["type"]["description"]
        .as_str()
        .is_some_and(|description| description.contains("Backend-defined GMP detection method")));
    assert!(schemas["Qod"]["required"]
        .as_array()
        .is_none_or(|required| required.is_empty()));

    let spec_dir = root_spec_path()
        .parent()
        .expect("REST spec directory")
        .to_path_buf();
    let results = read_yaml(&spec_dir.join("results.yaml"));
    let reports = read_yaml(&spec_dir.join("reports.yaml"));
    assert_eq!(
        results["components"]["schemas"]["Result"]["properties"]["qod"]["$ref"],
        "#/components/schemas/Qod"
    );
    assert_eq!(
        results["components"]["schemas"]["Qod"]["properties"]["value"]["minimum"],
        0
    );
    assert_eq!(
        results["components"]["schemas"]["Qod"]["properties"]["value"]["maximum"],
        100
    );
    assert_eq!(
        reports["components"]["schemas"]["Report"]["properties"]["results"]["items"]["$ref"],
        "./results.yaml#/components/schemas/Result"
    );
}

#[test]
fn generated_and_curated_metadata_describe_the_current_typed_contract() {
    // Top-level metadata is what runtime Redoc and release-shipped clients see.
    // Keep it tied to the compiled API version and implemented authentication
    // modes instead of allowing route-level parity to hide stale guidance.
    let generated = build_openapi();
    let curated = root_spec();
    let version = env!("CARGO_PKG_VERSION");

    assert_eq!(generated["info"]["version"], json!(version));
    assert_eq!(curated["info"]["version"], json!(version));

    for (name, document) in [("generated", &generated), ("curated", &curated)] {
        let description = document["info"]["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} OpenAPI must have an info description"));
        assert!(
            description.contains("typed rust-gvm"),
            "{name} OpenAPI must describe the typed rust-gvm ownership boundary"
        );
        assert!(
            description.contains("request-scoped HTTP Basic"),
            "{name} OpenAPI must describe implemented request-scoped Basic authentication"
        );
        assert!(
            !description.contains("future version"),
            "{name} OpenAPI must not describe implemented authentication as future work"
        );
    }

    for file_name in ["audits.yaml", "policies.yaml"] {
        let document = read_yaml(
            &root_spec_path()
                .parent()
                .expect("spec directory")
                .join(file_name),
        );
        assert_eq!(
            document["info"]["version"],
            json!(version),
            "standalone OpenAPI fragment {file_name} has stale version metadata"
        );
    }

    let system = read_yaml(
        &root_spec_path()
            .parent()
            .expect("spec directory")
            .join("system.yaml"),
    );
    for (name, description) in [
        (
            "generated version operation",
            generated["paths"]["/version"]["get"]["description"].as_str(),
        ),
        (
            "generated apiVersion schema",
            generated["components"]["schemas"]["VersionInfo"]["properties"]["apiVersion"]
                ["description"]
                .as_str(),
        ),
        (
            "curated version operation",
            system["paths"]["/version"]["get"]["description"].as_str(),
        ),
        (
            "curated apiVersion schema",
            system["components"]["schemas"]["VersionInfo"]["properties"]["apiVersion"]
                ["description"]
                .as_str(),
        ),
    ] {
        assert!(
            description
                .unwrap_or_else(|| panic!("{name} must have a description"))
                .contains("gateway package version"),
            "{name} must describe the implemented version alignment"
        );
    }
    assert_eq!(
        system["components"]["schemas"]["VersionInfo"]["properties"]["apiVersion"]["examples"],
        json!([version]),
        "VersionInfo.apiVersion example must match the compiled API version"
    );
}

#[test]
fn generated_and_curated_openapi_exclude_the_removed_ticket_surface() {
    // Issue #500 removes the contract instead of retaining a compatibility
    // operation, so paths, operation ids, tags, and schemas must all disappear.
    for (name, document) in [("generated", build_openapi()), ("curated", root_spec())] {
        assert!(
            document["paths"].get("/tickets").is_none(),
            "{name} ticket list path remains"
        );
        assert!(
            document["paths"].get("/tickets/{id}").is_none(),
            "{name} ticket detail path remains"
        );

        let serialized = serde_json::to_string(&document).expect("serialize OpenAPI document");
        for removed in ["getTickets", "getTicket", "TicketStatus", "TicketList"] {
            assert!(
                !serialized.contains(removed),
                "{name} OpenAPI still contains removed ticket symbol {removed}"
            );
        }
        assert!(
            document["components"]["schemas"].get("Ticket").is_none(),
            "{name} Ticket schema remains"
        );
        assert!(
            document["tags"]
                .as_array()
                .expect("OpenAPI tags array")
                .iter()
                .all(|tag| tag["name"] != "Tickets"),
            "{name} Tickets tag remains"
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

    // Web application exclusions cannot be cleared until rust-gvm exposes a
    // typed clear operation, so both generated and curated contracts must
    // distinguish omission from a supported non-empty replacement.
    let curated_emerging = read_yaml(&root_spec_path().parent().unwrap().join("emerging.yaml"));
    for (name, field) in [
        (
            "generated",
            &generated["components"]["schemas"]["ModifyWebApplicationTarget"]["properties"]
                ["excludeUrls"],
        ),
        (
            "curated",
            &curated_emerging["components"]["schemas"]["ModifyWebApplicationTarget"]["properties"]
                ["excludeUrls"],
        ),
    ] {
        assert_eq!(field["minItems"], 1, "{name} excludeUrls minimum");
        let description = field["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} excludeUrls omission semantics"));
        assert!(description.contains("Omit to preserve current exclusions"));
        assert!(description.contains("non-empty array replaces"));
        assert!(description.contains("not supported") || description.contains("rejected"));
    }

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

    // Clearing agent-group membership cannot be encoded by the pinned typed
    // rust-gvm request, so both contracts must reject an explicit empty list.
    for (name, field) in [
        (
            "generated",
            &generated["components"]["schemas"]["ModifyAgentGroup"]["properties"]["agentIds"],
        ),
        (
            "curated",
            &curated_emerging["components"]["schemas"]["ModifyAgentGroup"]["properties"]
                ["agentIds"],
        ),
    ] {
        assert_eq!(field["minItems"], 1, "{name} agentIds minimum");
        let description = field["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} agentIds update semantics"));
        assert!(description.contains("Omit to preserve"));
        assert!(description.contains("non-empty array replaces"));
        assert!(description.contains("#812"));
    }

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

    let report_import = &generated["paths"]["/reports"]["post"];
    assert_eq!(report_import["operationId"], "importReport");
    assert_eq!(
        report_import["requestBody"]["content"]["application/xml"]["schema"]["maxLength"],
        10 * 1024 * 1024
    );
    assert_eq!(
        report_import["responses"]["201"]["headers"]["Location"]["schema"]["format"],
        "uri-reference"
    );
    for status in ["400", "401", "404", "413", "415", "501", "502", "504"] {
        assert!(
            report_import["responses"].get(status).is_some(),
            "report import is missing documented {status} response"
        );
    }

    let report_operating_system_props = &schemas["ReportOperatingSystem"]["properties"];
    for property in ["bestOsCpe", "bestOsText", "hostsCount"] {
        assert!(
            report_operating_system_props.get(property).is_some(),
            "generated report operating-system schema is missing {property}"
        );
    }
    for removed_property in ["id", "name", "severity"] {
        assert!(
            report_operating_system_props
                .get(removed_property)
                .is_none(),
            "generated report operating-system schema retains false {removed_property} field"
        );
    }

    // The curated OpenAPI source must publish the identical real gvmd row
    // shape, rather than only verifying the generated endpoint contract.
    let curated_reports = read_yaml(&root_spec_path().parent().unwrap().join("reports.yaml"));
    let curated_report_operating_system_props =
        &curated_reports["components"]["schemas"]["ReportOperatingSystem"]["properties"];
    for property in ["bestOsCpe", "bestOsText", "hostsCount"] {
        assert!(
            curated_report_operating_system_props
                .get(property)
                .is_some(),
            "curated report operating-system schema is missing {property}"
        );
    }
    for removed_property in ["id", "name", "severity"] {
        assert!(
            curated_report_operating_system_props
                .get(removed_property)
                .is_none(),
            "curated report operating-system schema retains false {removed_property} field"
        );
    }

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
fn optional_custom_schema_request_fields_remain_omittable() {
    // Regression for #640: `schema_with` replaces `Option<T>` inference, so
    // optional request fields with custom schemas must explicitly remain out
    // of generated `required` arrays. This also audits the credential request
    // fields that use the same derivation pattern.
    let generated = build_openapi();
    let generated_schemas = &generated["components"]["schemas"];
    let root_spec_path = root_spec_path();
    let spec_dir = root_spec_path.parent().expect("REST spec directory");
    let identity = read_yaml(&spec_dir.join("identity.yaml"));
    let credentials = read_yaml(&spec_dir.join("credentials.yaml"));

    for (context, schema, expected) in [
        (
            "generated CreateUser",
            &generated_schemas["CreateUser"],
            BTreeSet::from(["name"]),
        ),
        (
            "curated CreateUser",
            &identity["components"]["schemas"]["CreateUser"],
            BTreeSet::from(["name"]),
        ),
        (
            "generated ModifyUser",
            &generated_schemas["ModifyUser"],
            BTreeSet::new(),
        ),
        (
            "curated ModifyUser",
            &identity["components"]["schemas"]["ModifyUser"],
            BTreeSet::new(),
        ),
        (
            "generated CreateCredential",
            &generated_schemas["CreateCredential"],
            BTreeSet::from(["name", "type"]),
        ),
        (
            "curated CreateCredential",
            &credentials["components"]["schemas"]["CreateCredential"],
            BTreeSet::from(["name", "type"]),
        ),
        (
            "generated ModifyCredential",
            &generated_schemas["ModifyCredential"],
            BTreeSet::new(),
        ),
        (
            "curated ModifyCredential",
            &credentials["components"]["schemas"]["ModifyCredential"],
            BTreeSet::new(),
        ),
    ] {
        assert_eq!(required_fields(schema), expected, "{context} required set");
    }

    for (context, schema, instance) in [
        (
            "generated CreateUser",
            &generated_schemas["CreateUser"],
            json!({"name": "alice"}),
        ),
        (
            "curated CreateUser",
            &identity["components"]["schemas"]["CreateUser"],
            json!({"name": "alice"}),
        ),
        (
            "generated ModifyUser",
            &generated_schemas["ModifyUser"],
            json!({"comment": "unchanged authentication"}),
        ),
        (
            "curated ModifyUser",
            &identity["components"]["schemas"]["ModifyUser"],
            json!({"comment": "unchanged authentication"}),
        ),
        (
            "generated CreateCredential",
            &generated_schemas["CreateCredential"],
            json!({"name": "scanner login", "type": "up"}),
        ),
        (
            "curated CreateCredential",
            &credentials["components"]["schemas"]["CreateCredential"],
            json!({"name": "scanner login", "type": "up"}),
        ),
        (
            "generated ModifyCredential",
            &generated_schemas["ModifyCredential"],
            json!({"comment": "unchanged secrets"}),
        ),
        (
            "curated ModifyCredential",
            &credentials["components"]["schemas"]["ModifyCredential"],
            json!({"comment": "unchanged secrets"}),
        ),
    ] {
        assert!(
            schema_accepts_instance(schema, &instance),
            "{context} rejects a valid request that omits optional custom-schema fields"
        );
    }

    for (context, schema) in [
        (
            "generated CreateUser.authenticationType",
            &generated_schemas["CreateUser"]["properties"]["authenticationType"],
        ),
        (
            "generated ModifyUser.authenticationType",
            &generated_schemas["ModifyUser"]["properties"]["authenticationType"],
        ),
        (
            "curated CreateUser.authenticationType",
            &identity["components"]["schemas"]["CreateUser"]["properties"]["authenticationType"],
        ),
        (
            "curated ModifyUser.authenticationType",
            &identity["components"]["schemas"]["ModifyUser"]["properties"]["authenticationType"],
        ),
    ] {
        assert!(schema_accepts_instance(schema, &json!("file")));
        assert!(
            !schema_accepts_instance(schema, &json!("future_auth")),
            "{context} must remain closed to undocumented values"
        );
    }
}

#[test]
fn user_setting_modify_requires_value_allows_empty_and_exposes_no_create_or_delete() {
    // A missing value is invalid, while an explicit empty string is the
    // supported clear operation. The existing surface remains GET/GET/PUT.
    let generated = build_openapi();
    let generated_modify = &generated["components"]["schemas"]["ModifyUserSetting"];
    assert_eq!(generated_modify["required"], json!(["value"]));
    assert_eq!(generated_modify["properties"]["value"]["type"], "string");
    assert!(generated_modify["properties"]["value"]
        .get("minLength")
        .is_none());
    assert!(generated["paths"]["/user-settings"].get("post").is_none());
    assert!(generated["paths"]["/user-settings"].get("delete").is_none());
    assert!(generated["paths"]["/user-settings/{id}"]
        .get("post")
        .is_none());
    assert!(generated["paths"]["/user-settings/{id}"]
        .get("delete")
        .is_none());

    let identity = read_yaml(
        root_spec_path()
            .parent()
            .expect("spec directory")
            .join("identity.yaml")
            .as_path(),
    );
    let curated_modify = &identity["components"]["schemas"]["ModifyUserSetting"];
    assert_eq!(curated_modify["required"], json!(["value"]));
    assert_eq!(curated_modify["properties"]["value"]["type"], "string");
    assert!(curated_modify["properties"]["value"]
        .get("minLength")
        .is_none());
    assert!(identity["paths"]["/user-settings"].get("post").is_none());
    assert!(identity["paths"]["/user-settings"].get("delete").is_none());
    assert!(identity["paths"]["/user-settings/{id}"]
        .get("post")
        .is_none());
    assert!(identity["paths"]["/user-settings/{id}"]
        .get("delete")
        .is_none());
}

#[test]
fn generated_openapi_keeps_administration_and_cleanup_operations_non_public() {
    // Canonical upstream requests for system administration and cleanup do
    // not create a REST product decision. Scanner administration also remains
    // read-only while its typed requests are available upstream.
    let generated = build_openapi();
    for absent_path in [
        "/auth-config",
        "/license",
        "/settings",
        "/wizards",
        "/trashcan",
        "/restore",
    ] {
        assert!(
            generated["paths"].get(absent_path).is_none(),
            "administration/cleanup path must stay absent: {absent_path}"
        );
    }
    for (path, forbidden_methods) in [
        ("/scanners", ["post", "put", "delete"]),
        ("/scanners/{id}", ["post", "put", "delete"]),
    ] {
        assert!(generated["paths"][path].get("get").is_some());
        for method in forbidden_methods {
            assert!(
                generated["paths"][path].get(method).is_none(),
                "scanner administration must stay absent: {method} {path}"
            );
        }
    }

    let operation_ids = generated["paths"]
        .as_object()
        .expect("paths object")
        .values()
        .flat_map(|path_item| {
            path_item
                .as_object()
                .into_iter()
                .flatten()
                .map(|(_, value)| value)
        })
        .filter_map(|operation| operation["operationId"].as_str())
        .collect::<BTreeSet<_>>();
    for omitted in [
        "describeAuth",
        "modifyAuth",
        "getLicense",
        "modifyLicense",
        "getSettings",
        "modifySetting",
        "runWizard",
        "emptyTrashcan",
        "restore",
        "createScanner",
        "cloneScanner",
        "modifyScanner",
        "deleteScanner",
        "verifyScanner",
    ] {
        assert!(
            !operation_ids.contains(omitted),
            "administration/cleanup operation must stay absent: {omitted}"
        );
    }
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
fn generated_openapi_feed_contract_matches_required_runtime_booleans() {
    // Canonical GMP feed metadata may be absent, but the gateway compatibility
    // mapping keeps all three downstream access flags required booleans.
    let generated = build_openapi();
    let feed_required = generated["components"]["schemas"]["Feed"]["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();

    assert!(feed_required.contains("type"));
    assert!(feed_required.contains("name"));
    assert!(feed_required.contains("version"));

    let feed_list_required = generated["components"]["schemas"]["FeedList"]["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    for field in [
        "data",
        "feedOwnerConfigured",
        "feedRolesConfigured",
        "feedResourcesAccess",
    ] {
        assert!(
            feed_list_required.contains(field),
            "FeedList must keep {field} required"
        );
    }
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
fn generated_and_curated_response_enums_accept_known_and_unknown_values_of_the_right_type() {
    // Issue #633 is a validation contract, not a prose convention: every open
    // response enum must accept known and future values while rejecting a
    // value of the wrong JSON primitive type in both published schemas.
    let generated = build_openapi();
    let schemas = &generated["components"]["schemas"];
    let root_spec_path = root_spec_path();
    let spec_dir = root_spec_path.parent().expect("REST spec directory");
    let common = read_yaml(&spec_dir.join("common.yaml"));
    let tasks = read_yaml(&spec_dir.join("tasks.yaml"));
    let feeds = read_yaml(&spec_dir.join("feeds.yaml"));
    let scanners = read_yaml(&spec_dir.join("scanners.yaml"));
    let scan_configs = read_yaml(&spec_dir.join("scan-configs.yaml"));
    let alerts = read_yaml(&spec_dir.join("alerts.yaml"));
    let results = read_yaml(&spec_dir.join("results.yaml"));
    let reports = read_yaml(&spec_dir.join("reports.yaml"));
    let identity = read_yaml(&spec_dir.join("identity.yaml"));
    let emerging = read_yaml(&spec_dir.join("emerging.yaml"));

    for (context, schema, known, unknown, wrong_type, known_values) in [
        (
            "generated AliveTest",
            &schemas["AliveTest"],
            json!("ICMP Ping"),
            json!("Passive DNS"),
            json!(1),
            json!([
                "Scan Config Default",
                "ICMP Ping",
                "TCP-ACK Service Ping",
                "TCP-SYN Service Ping",
                "ARP Ping",
                "ICMP, TCP-ACK Service Ping",
                "ICMP, ARP Ping",
                "TCP-ACK Service, ARP Ping",
                "ICMP, TCP-ACK Service, ARP Ping",
                "Consider Alive"
            ]),
        ),
        (
            "generated HostsOrdering",
            &schemas["HostsOrdering"],
            json!("sequential"),
            json!("by-latency"),
            json!(1),
            json!(["sequential", "random", "reverse"]),
        ),
        (
            "generated TaskStatus",
            &schemas["TaskStatus"],
            json!("Running"),
            json!("Future State"),
            json!(1),
            json!([
                "New",
                "Requested",
                "Queued",
                "Running",
                "Stop Requested",
                "Stopping",
                "Processing",
                "Done",
                "Stopped",
                "Error",
                "Delete Requested",
                "Ultimate Delete Requested",
                "Container",
                "Interrupted"
            ]),
        ),
        (
            "generated CredentialType",
            &schemas["Credential"]["properties"]["type"],
            json!("up"),
            json!("future_credential"),
            json!(1),
            json!([
                "cc", "krb5", "pw", "pgp", "smime", "snmp", "up", "usk", "cs_krb5", "cs_pw",
                "cs_pgp", "cs_smime", "cs_snmp", "cs_up", "cs_usk"
            ]),
        ),
        (
            "generated FeedType",
            &schemas["FeedType"],
            json!("NVT"),
            json!("COMMUNITY_DATA"),
            json!(1),
            json!(["NVT", "CERT", "SCAP", "GVMD_DATA"]),
        ),
        (
            "generated ScannerType",
            &schemas["ScannerType"],
            json!("OpenVAS"),
            json!("Sensor"),
            json!(1),
            json!(["OpenVAS", "CVE", "OSP"]),
        ),
        (
            "generated AlertEvent",
            &schemas["Alert"]["properties"]["event"],
            json!("task_run_status_changed"),
            json!("future_event"),
            json!(1),
            json!(["task_run_status_changed", "updated_secinfo", "new_secinfo"]),
        ),
        (
            "generated AlertCondition",
            &schemas["Alert"]["properties"]["condition"],
            json!("always"),
            json!("future_condition"),
            json!(1),
            json!([
                "always",
                "filter_count_at_least",
                "filter_count_changed",
                "severity_at_least",
                "severity_changed"
            ]),
        ),
        (
            "generated AlertMethod",
            &schemas["Alert"]["properties"]["method"],
            json!("email"),
            json!("future_method"),
            json!(1),
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
        ),
        (
            "generated Threat",
            &schemas["Threat"],
            json!("High"),
            json!("FutureThreat"),
            json!(1),
            json!(["High", "Medium", "Low", "Log", "Alarm"]),
        ),
        (
            "generated AuthenticationType",
            &schemas["User"]["allOf"][1]["properties"]["authenticationType"],
            json!("file"),
            json!("future_auth"),
            json!(1),
            json!(["file", "ldap_connect", "radius_connect"]),
        ),
        (
            "generated AssetType",
            &schemas["AssetType"],
            json!("host"),
            json!("future_asset"),
            json!(1),
            json!(["host", "os", "tls_certificate"]),
        ),
        (
            "generated ConfigUsageType",
            &schemas["ConfigUsageType"],
            json!("scan"),
            json!("future_usage"),
            json!(1),
            json!(["scan", "audit", "policy"]),
        ),
    ] {
        assert_open_enum_schema(
            schema,
            &known,
            &unknown,
            &wrong_type,
            &known_values,
            context,
        );
    }

    assert_open_enum_schema(
        &schemas["ScanConfigType"],
        &json!(0),
        &json!(42),
        &json!("0"),
        &json!([0, 1]),
        "generated ScanConfigType",
    );

    for (context, schema, known, unknown, wrong_type, known_values) in [
        (
            "curated AliveTestResponse",
            &common["components"]["schemas"]["AliveTestResponse"],
            json!("ICMP Ping"),
            json!("Passive DNS"),
            json!(1),
            json!([
                "Scan Config Default",
                "ICMP Ping",
                "TCP-ACK Service Ping",
                "TCP-SYN Service Ping",
                "ARP Ping",
                "ICMP, TCP-ACK Service Ping",
                "ICMP, ARP Ping",
                "TCP-ACK Service, ARP Ping",
                "ICMP, TCP-ACK Service, ARP Ping",
                "Consider Alive"
            ]),
        ),
        (
            "curated HostsOrdering",
            &common["components"]["schemas"]["HostsOrdering"],
            json!("sequential"),
            json!("by-latency"),
            json!(1),
            json!(["sequential", "random", "reverse"]),
        ),
        (
            "curated Task.status",
            &tasks["components"]["schemas"]["Task"]["properties"]["status"],
            json!("Running"),
            json!("Future State"),
            json!(1),
            schemas["TaskStatus"]["anyOf"][0]["enum"].clone(),
        ),
        (
            "curated Credential.type",
            &common["components"]["schemas"]["CredentialTypeResponse"],
            json!("up"),
            json!("future_credential"),
            json!(1),
            json!([
                "cc", "krb5", "pw", "pgp", "smime", "snmp", "up", "usk", "cs_krb5", "cs_pw",
                "cs_pgp", "cs_smime", "cs_snmp", "cs_up", "cs_usk"
            ]),
        ),
        (
            "curated Feed.type",
            &feeds["components"]["schemas"]["Feed"]["properties"]["type"],
            json!("NVT"),
            json!("COMMUNITY_DATA"),
            json!(1),
            json!(["NVT", "CERT", "SCAP", "GVMD_DATA"]),
        ),
        (
            "curated Scanner.type",
            &scanners["components"]["schemas"]["Scanner"]["properties"]["type"],
            json!("OpenVAS"),
            json!("Sensor"),
            json!(1),
            json!(["OpenVAS", "CVE", "OSP"]),
        ),
        (
            "curated Alert.event",
            &alerts["components"]["schemas"]["Alert"]["properties"]["event"],
            json!("task_run_status_changed"),
            json!("future_event"),
            json!(1),
            json!(["task_run_status_changed", "updated_secinfo", "new_secinfo"]),
        ),
        (
            "curated Alert.condition",
            &alerts["components"]["schemas"]["Alert"]["properties"]["condition"],
            json!("always"),
            json!("future_condition"),
            json!(1),
            json!([
                "always",
                "filter_count_at_least",
                "filter_count_changed",
                "severity_at_least",
                "severity_changed"
            ]),
        ),
        (
            "curated Alert.method",
            &alerts["components"]["schemas"]["Alert"]["properties"]["method"],
            json!("email"),
            json!("future_method"),
            json!(1),
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
        ),
        (
            "curated Result.threat",
            &results["components"]["schemas"]["Result"]["properties"]["threat"],
            json!("High"),
            json!("FutureThreat"),
            json!(1),
            json!(["High", "Medium", "Low", "Log", "Alarm"]),
        ),
        (
            "curated ReportVulnerability.threat",
            &reports["components"]["schemas"]["ReportVulnerability"]["properties"]["threat"],
            json!("High"),
            json!("FutureThreat"),
            json!(1),
            json!(["High", "Medium", "Low", "Log", "Alarm"]),
        ),
        (
            "curated ReportClosedCve.threat",
            &reports["components"]["schemas"]["ReportClosedCve"]["properties"]["threat"],
            json!("High"),
            json!("FutureThreat"),
            json!(1),
            json!(["High", "Medium", "Low", "Log", "Alarm"]),
        ),
        (
            "curated User.authenticationType",
            &identity["components"]["schemas"]["User"]["allOf"][1]["properties"]
                ["authenticationType"],
            json!("file"),
            json!("future_auth"),
            json!(1),
            json!(["file", "ldap_connect", "radius_connect"]),
        ),
        (
            "curated AssetType",
            &emerging["components"]["schemas"]["AssetType"],
            json!("host"),
            json!("future_asset"),
            json!(1),
            json!(["host", "os", "tls_certificate"]),
        ),
        (
            "curated ConfigUsageType",
            &emerging["components"]["schemas"]["ConfigUsageType"],
            json!("scan"),
            json!("future_usage"),
            json!(1),
            json!(["scan", "audit", "policy"]),
        ),
    ] {
        assert_open_enum_schema(
            schema,
            &known,
            &unknown,
            &wrong_type,
            &known_values,
            context,
        );
    }

    assert_open_enum_schema(
        &scan_configs["components"]["schemas"]["ScanConfig"]["properties"]["type"],
        &json!(0),
        &json!(42),
        &json!("0"),
        &json!([0, 1]),
        "curated ScanConfig.type",
    );
}

#[test]
fn representative_serialized_responses_validate_against_generated_and_curated_enum_contracts() {
    // Validate actual DTO serialization for the string and integer open-enum
    // families. Mutating only the enum field to the wrong primitive proves
    // that openness does not degrade into accepting arbitrary JSON values.
    let generated = build_openapi();
    let schemas = &generated["components"]["schemas"];
    let root_spec_path = root_spec_path();
    let spec_dir = root_spec_path.parent().expect("REST spec directory");
    let tasks = read_yaml(&spec_dir.join("tasks.yaml"));
    let scan_configs = read_yaml(&spec_dir.join("scan-configs.yaml"));

    let known_task = serialized_task_response("Running");
    let unknown_task = serialized_task_response("Future State");
    let mut wrong_task = unknown_task.clone();
    wrong_task["status"] = json!(7);
    for (context, schema) in [
        (
            "generated Task.status response",
            &schemas["Task"]["properties"]["status"],
        ),
        (
            "curated Task.status response",
            &tasks["components"]["schemas"]["Task"]["properties"]["status"],
        ),
    ] {
        assert_response_field_contract(
            schemas,
            "status",
            schema,
            &known_task,
            &unknown_task,
            &wrong_task,
            context,
        );
    }

    let known_config = serialized_scan_config_response(0);
    let unknown_config = serialized_scan_config_response(42);
    let mut wrong_config = unknown_config.clone();
    wrong_config["type"] = json!("42");
    for (context, schema) in [
        (
            "generated ScanConfig.type response",
            &schemas["ScanConfig"]["properties"]["type"],
        ),
        (
            "curated ScanConfig.type response",
            &scan_configs["components"]["schemas"]["ScanConfig"]["properties"]["type"],
        ),
    ] {
        assert_response_field_contract(
            schemas,
            "type",
            schema,
            &known_config,
            &unknown_config,
            &wrong_config,
            context,
        );
    }
}

#[test]
fn request_only_closed_enums_remain_restrictive() {
    // Opening response enums must not broaden request selectors whose curated
    // contracts intentionally enumerate the only accepted input values.
    let generated = build_openapi();
    let schemas = &generated["components"]["schemas"];
    let root_spec_path = root_spec_path();
    let spec_dir = root_spec_path.parent().expect("REST spec directory");
    let common = read_yaml(&spec_dir.join("common.yaml"));
    let feeds = read_yaml(&spec_dir.join("feeds.yaml"));
    let tasks = read_yaml(&spec_dir.join("tasks.yaml"));
    let alerts = read_yaml(&spec_dir.join("alerts.yaml"));
    let identity = read_yaml(&spec_dir.join("identity.yaml"));

    let generated_feed_type = generated["paths"]["/feeds"]["get"]["parameters"]
        .as_array()
        .expect("generated feed parameters")
        .iter()
        .find(|parameter| parameter["name"] == "type")
        .map(|parameter| &parameter["schema"])
        .expect("generated feed type parameter");
    let curated_feed_type = &feeds["paths"]["/feeds"]["get"]["parameters"][0]["schema"];
    let generated_task_type = &schemas["CreateTask"]["properties"]["type"];
    let curated_task_type = &tasks["components"]["schemas"]["CreateTask"]["properties"]["type"];
    let credential_request_types = json!([
        "cc", "pw", "smime", "snmp", "snmpv3", "up", "usk", "cs_pw", "cs_pgp", "cs_smime",
        "cs_snmp", "cs_up", "cs_usk"
    ]);

    // Credential request types are a closed construction contract. Keep both
    // generated and curated schemas tied to the exact typed-adapter inventory.
    assert_eq!(
        resolve_local_schema_ref(schemas, &schemas["CreateCredential"]["properties"]["type"])
            ["enum"],
        credential_request_types
    );
    assert_eq!(
        common["components"]["schemas"]["CredentialType"]["enum"],
        credential_request_types
    );

    for (context, schema, known, unknown) in [
        (
            "generated feed type request",
            generated_feed_type,
            json!("NVT"),
            json!("FUTURE"),
        ),
        (
            "curated feed type request",
            curated_feed_type,
            json!("NVT"),
            json!("FUTURE"),
        ),
        (
            "generated task type request",
            generated_task_type,
            json!("classic"),
            json!("future"),
        ),
        (
            "curated task type request",
            curated_task_type,
            json!("classic"),
            json!("future"),
        ),
        (
            "generated alert event request",
            &schemas["CreateAlert"]["properties"]["event"],
            json!("task_run_status_changed"),
            json!("future_event"),
        ),
        (
            "curated alert event request",
            &alerts["components"]["schemas"]["CreateAlert"]["properties"]["event"],
            json!("task_run_status_changed"),
            json!("future_event"),
        ),
        (
            "generated credential type request",
            &schemas["CreateCredential"]["properties"]["type"],
            json!("up"),
            json!("future_credential"),
        ),
        (
            "curated credential type request",
            &common["components"]["schemas"]["CredentialType"],
            json!("up"),
            json!("future_credential"),
        ),
        (
            "generated authentication type request",
            &schemas["CreateUser"]["properties"]["authenticationType"],
            json!("file"),
            json!("future_auth"),
        ),
        (
            "curated authentication type request",
            &identity["components"]["schemas"]["CreateUser"]["properties"]["authenticationType"],
            json!("file"),
            json!("future_auth"),
        ),
    ] {
        let schema = resolve_local_schema_ref(schemas, schema);
        assert!(
            schema_accepts_instance(schema, &known),
            "{context} rejects known value"
        );
        assert!(
            !schema_accepts_instance(schema, &unknown),
            "{context} accepts unknown value"
        );
        assert!(
            !schema_accepts_instance(schema, &json!(1)),
            "{context} accepts wrong primitive type"
        );
    }
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
            generated_schemas[name]["anyOf"][0]["enum"],
            curated["components"]["schemas"][name]["anyOf"][0]["enum"],
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
fn generated_and_curated_report_delete_contract_is_permanent_without_selector() {
    // Report deletion cannot be downgraded to trash semantics. Keep both
    // published contracts free of `ultimate`, explicit about permanence, and
    // honest about the 400 returned for obsolete legacy input.
    let generated = build_openapi();
    let generated_delete = op(&generated, "/reports/{id}", "delete");
    assert!(generated_delete["parameters"]
        .as_array()
        .expect("generated report delete parameters")
        .iter()
        .all(|parameter| parameter["name"] != "ultimate"));
    assert!(generated_delete["description"]
        .as_str()
        .is_some_and(|description| description.contains("Permanently deletes")
            && description.contains("400 bad_request")));
    assert!(generated_delete["responses"].get("400").is_some());

    let reports_path = root_spec_path()
        .parent()
        .expect("root spec should have a directory")
        .join("reports.yaml");
    let curated = read_yaml(&reports_path);
    let curated_delete = &curated["paths"]["/reports/{id}"]["delete"];
    assert!(curated_delete.get("parameters").is_none());
    assert!(curated_delete["description"]
        .as_str()
        .is_some_and(|description| description.contains("Permanently deletes")
            && description.contains("400 bad_request")));
    assert!(curated_delete["responses"].get("400").is_some());
}

#[test]
fn generated_and_curated_user_delete_contract_has_no_permanence_selector() {
    // Typed user deletion has one canonical command shape. Keep both OpenAPI
    // surfaces free of a permanence control and explicit about rejecting it.
    let generated = build_openapi();
    let generated_delete = op(&generated, "/users/{id}", "delete");
    assert!(generated_delete["parameters"]
        .as_array()
        .expect("generated user delete parameters")
        .iter()
        .all(|parameter| parameter["name"] != "ultimate"));
    assert!(generated_delete["description"]
        .as_str()
        .is_some_and(
            |description| description.contains("no caller-selectable permanence mode")
                && description.contains("400 bad_request")
        ));
    assert!(generated_delete["responses"].get("400").is_some());

    let identity_path = root_spec_path()
        .parent()
        .expect("root spec should have a directory")
        .join("identity.yaml");
    let curated = read_yaml(&identity_path);
    let curated_delete = &curated["paths"]["/users/{id}"]["delete"];
    assert!(curated_delete.get("parameters").is_none());
    assert!(curated_delete["description"]
        .as_str()
        .is_some_and(
            |description| description.contains("no caller-selectable permanence mode")
                && description.contains("400 bad_request")
        ));
    assert!(curated_delete["responses"].get("400").is_some());
}

#[test]
fn generated_and_curated_config_create_contracts_require_family_specific_bases() {
    // Issue #518 intentionally corrects the Technology Preview create schema;
    // keep generated docs and both curated component documents exact here.
    let generated = build_openapi();
    let generated_schemas = &generated["components"]["schemas"];
    assert_eq!(
        generated_schemas["CreateScanConfig"]["required"],
        json!(["name", "baseScanConfigId"])
    );
    assert_eq!(
        generated_schemas["CreatePolicy"]["required"],
        json!(["name", "basePolicyId"])
    );

    let root_spec = root_spec_path();
    let spec_dir = root_spec
        .parent()
        .expect("root spec should have a directory");
    let scan_configs = read_yaml(&spec_dir.join("scan-configs.yaml"));
    let policies = read_yaml(&spec_dir.join("policies.yaml"));
    assert_eq!(
        scan_configs["components"]["schemas"]["CreateScanConfig"]["required"],
        json!(["name", "baseScanConfigId"])
    );
    assert_eq!(
        policies["components"]["schemas"]["CreatePolicy"]["required"],
        json!(["name", "basePolicyId"])
    );
    assert_eq!(
        policies["paths"]["/policies"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["$ref"],
        json!("#/components/schemas/CreatePolicy")
    );
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
            RestRouteAuthPolicy::BearerOnly => {
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
fn report_export_job_creation_is_bearer_only_in_generated_and_curated_openapi() {
    // This assertion protects both published contracts from silently falling
    // back to the root dual-auth policy while the runtime rejects Basic.
    let generated = build_openapi();
    let curated = read_yaml(
        &root_spec_path()
            .parent()
            .unwrap()
            .join("report-exports.yaml"),
    );
    let expected = json!([{"bearerAuth": []}]);

    assert_eq!(
        generated["paths"]["/reports/{id}/exports"]["post"]["security"],
        expected
    );
    assert_eq!(
        curated["paths"]["/reports/{id}/exports"]["post"]["security"],
        expected
    );
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

fn required_fields(schema: &Value) -> BTreeSet<&str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
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

fn assert_open_enum_schema(
    schema: &Value,
    known: &Value,
    unknown: &Value,
    wrong_type: &Value,
    expected_values: &Value,
    context: &str,
) {
    assert_eq!(
        &schema["anyOf"][0]["enum"], expected_values,
        "{context} should list known values for OpenAPI docs and client generation"
    );
    assert!(
        schema_accepts_instance(schema, known),
        "{context} rejects a documented value: {known}"
    );
    assert!(
        schema_accepts_instance(schema, unknown),
        "{context} rejects an unknown future value: {unknown}"
    );
    assert!(
        !schema_accepts_instance(schema, wrong_type),
        "{context} accepts a value of the wrong primitive type: {wrong_type}"
    );
}

fn assert_response_field_contract(
    generated_schemas: &Value,
    field: &str,
    field_schema: &Value,
    known_response: &Value,
    unknown_response: &Value,
    wrong_response: &Value,
    context: &str,
) {
    let field_schema = resolve_local_schema_ref(generated_schemas, field_schema);
    let mut properties = Map::new();
    properties.insert(field.to_string(), field_schema.clone());
    let response_projection = json!({
        "type": "object",
        "required": [field],
        "properties": properties
    });

    assert!(
        schema_accepts_instance(&response_projection, known_response),
        "{context} rejects a serialized response containing a known value"
    );
    assert!(
        schema_accepts_instance(&response_projection, unknown_response),
        "{context} rejects a serialized response containing an unknown value"
    );
    assert!(
        !schema_accepts_instance(&response_projection, wrong_response),
        "{context} accepts a response containing the wrong primitive type"
    );
}

/// Evaluate the JSON Schema assertions used by the enum contract tests.
///
/// Keeping this focused evaluator in the test module avoids adding a large
/// validator dependency solely for primitive enum projections while still
/// exercising the emitted `type`, `enum`, `anyOf`, `required`, and
/// `properties` semantics against serialized response instances.
fn schema_accepts_instance(schema: &Value, instance: &Value) -> bool {
    if let Some(branches) = schema.get("anyOf").and_then(Value::as_array) {
        if !branches
            .iter()
            .any(|branch| schema_accepts_instance(branch, instance))
        {
            return false;
        }
    }

    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.contains(instance) {
            return false;
        }
    }

    if let Some(schema_type) = schema.get("type").and_then(Value::as_str) {
        let type_matches = match schema_type {
            "array" => instance.is_array(),
            "boolean" => instance.is_boolean(),
            "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
            "null" => instance.is_null(),
            "number" => instance.is_number(),
            "object" => instance.is_object(),
            "string" => instance.is_string(),
            _ => false,
        };
        if !type_matches {
            return false;
        }
    }

    if let Some(object) = instance.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            if required
                .iter()
                .filter_map(Value::as_str)
                .any(|field| !object.contains_key(field))
            {
                return false;
            }
        }

        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            if properties.iter().any(|(field, field_schema)| {
                object
                    .get(field)
                    .is_some_and(|value| !schema_accepts_instance(field_schema, value))
            }) {
                return false;
            }
        }
    }

    true
}

fn serialized_task_response(status: &str) -> Value {
    use gvm_gateway_domain::{Task, TaskObservers};

    serde_json::to_value(crate::tasks::TaskResponse::from(Task {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Contract task".to_string(),
        comment: None,
        status: status.to_string(),
        progress: Some(42),
        target: None,
        agent_group: None,
        oci_image_target: None,
        web_application_target: None,
        scan_config: None,
        scanner: None,
        schedule: None,
        alerts: vec![],
        alterable: None,
        hosts_ordering: None,
        observers: TaskObservers::default(),
        schedule_periods: None,
        last_report: None,
        current_report: None,
        report_count: Some(3),
        usage_type: None,
        trend: None,
        in_use: false,
        writable: true,
    }))
    .expect("task response should serialize")
}

fn serialized_scan_config_response(config_type: u32) -> Value {
    serde_json::to_value(crate::scan_configs::ScanConfigResponse::from(
        gvm_gateway_domain::ScanConfig {
            id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            name: "Contract scan config".to_string(),
            comment: None,
            family_count: Some(2),
            nvt_count: Some(12),
            config_type: Some(config_type),
            usage_type: Some("scan".to_string()),
            in_use: false,
            writable: true,
        },
    ))
    .expect("scan-config response should serialize")
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

#[test]
fn task_observer_update_schemas_allow_omission_and_reject_null() {
    // Review #635: runtime omission/clear/replace semantics must agree with
    // both published array-only schemas used by task and audit update routes.
    let generated = build_openapi();
    let spec_dir = root_spec_path().parent().unwrap().to_path_buf();
    let curated = read_yaml(&spec_dir.join("tasks.yaml"));
    let generated_task = &generated["components"]["schemas"]["ModifyTask"];
    let curated_task = &curated["components"]["schemas"]["ModifyTask"];
    for task in [generated_task, curated_task] {
        let observers = &task["properties"]["observers"];
        assert_eq!(observers["type"], "array");
        assert_eq!(observers["items"]["type"], "string");
        assert!(!task["required"]
            .as_array()
            .is_some_and(|required| required.contains(&json!("observers"))));
        let description = observers["description"].as_str().unwrap();
        for intent in [
            "Omit to leave unchanged",
            "an empty array clears users",
            "a nonempty array replaces users",
            "Explicit null is invalid",
        ] {
            assert!(description.contains(intent), "missing intent: {intent}");
        }
    }
    assert_eq!(
        generated_task["properties"]["observers"]["description"],
        curated_task["properties"]["observers"]["description"]
    );
}
