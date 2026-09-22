// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const RUST_GVM_COMPONENTS: &[&str] = &[
    "gvm-client",
    "gvm-connection",
    "gvm-gmp",
    "gvm-mock-server",
    "gvm-protocol",
];
const RUST_GVM_BASELINE: &str = "034d0ce29ad54d93b328e83b85f6a29f2ba6daa5";

const REMOVED_CANONICAL_TRANSITION_TYPES: &[&str] = &[
    "CreateTargetOpts",
    "GetTargetsOpts",
    "ModifyTargetOpts",
    "CreateOciImageTargetOpts",
    "GetOciImageTargetsOpts",
    "ModifyOciImageTargetOpts",
    "CreateWebApplicationTargetOpts",
    "GetWebApplicationTargetsOpts",
    "ModifyWebApplicationTargetOpts",
    "CreateAgentGroupOpts",
    "GetAgentGroupsOpts",
    "ModifyAgentGroupOpts",
    "GetAgentsOpts",
    "ModifyAgentOpts",
    "ModifyAgentControlScanConfigOpts",
    "GetIntegrationConfigsOpts",
    "ModifyIntegrationConfigOpts",
    "PortListOpts",
    "ModifyPortListOpts",
    "GetPortListsOpts",
    "CredentialOpts",
    "ModifyCredentialOpts",
    "GetCredentialsOpts",
    "GetCredentialStoresOpts",
    "CredentialStoreCredentialOpts",
    "ModifyCredentialStoreOpts",
    "ModifyCredentialStoreCredentialOpts",
    "FilterOpts",
    "GetFiltersOpts",
    "TagOpts",
    "GetTagsOpts",
    "AlertOpts",
    "GetAlertsOpts",
    "TriggerAlertOpts",
    "ScheduleOpts",
    "GetSchedulesOpts",
    "CreateTypedScheduleRequest",
    "ModifyTypedScheduleRequest",
    "ScannerOpts",
    "GetScannersOpts",
    "NoteOpts",
    "ModifyNoteOpts",
    "GetNotesOpts",
    "OverrideOpts",
    "ModifyOverrideOpts",
    "GetOverridesOpts",
    "UserOpts",
    "ModifyUserOpts",
    "GetUsersOpts",
    "GroupOpts",
    "GetGroupsOpts",
    "RoleOpts",
    "GetRolesOpts",
    "PermissionOpts",
    "GetPermissionsOpts",
    "CreateAssetOpts",
    "DeleteAssetOpts",
    "GetAssetsOpts",
    "ModifyAssetOpts",
    "HostOpts",
    "GetHostsOpts",
    "GetOperatingSystemsOpts",
    "ModifyOperatingSystemAssetRequest",
    "GetResultsOpts",
    "CreateReportConfigOpts",
    "CreateReportConfigWithOptsRequest",
    "DeleteReportConfigOpts",
    "GetReportConfigsOpts",
    "ModifyReportConfigOpts",
    "GetNvtsOpts",
    "GetSecInfoOpts",
];

#[derive(Debug, Eq, PartialEq)]
struct Finding {
    path: String,
    line: usize,
    marker: &'static str,
    text: String,
}

const FORBIDDEN_MARKERS: &[(&str, &str)] = &[
    (
        "quick_xml::",
        "raw GMP XML parsing belongs in greenbone-hive/rust-gvm",
    ),
    (
        "roxmltree::",
        "raw GMP XML parsing belongs in greenbone-hive/rust-gvm",
    ),
    (
        "xmltree::",
        "raw GMP XML parsing belongs in greenbone-hive/rust-gvm",
    ),
    (
        "serde_xml_rs::",
        "raw GMP XML parsing belongs in greenbone-hive/rust-gvm",
    ),
    (
        "Response::from(",
        "raw GMP XML response fixture parsing belongs in greenbone-hive/rust-gvm tests",
    ),
    (
        "XmlCommand",
        "local GMP XML command construction belongs in greenbone-hive/rust-gvm",
    ),
    (
        ".to_bytes()",
        "GMP command serialization assertions belong in greenbone-hive/rust-gvm",
    ),
    (
        "_gvmd_name",
        "GMP wire/display-name translation belongs in greenbone-hive/rust-gvm",
    ),
    (
        "normalize_alert_",
        "GMP response value normalization belongs in greenbone-hive/rust-gvm",
    ),
    (
        "same XML structure",
        "GMP response shape aliases belong in greenbone-hive/rust-gvm",
    ),
    (
        "Task run status changed",
        "gvmd alert display names belong in greenbone-hive/rust-gvm",
    ),
    (
        "Updated SecInfo arrived",
        "gvmd alert display names belong in greenbone-hive/rust-gvm",
    ),
    (
        "New SecInfo arrived",
        "gvmd alert display names belong in greenbone-hive/rust-gvm",
    ),
    (
        "SysLog",
        "gvmd alert display names belong in greenbone-hive/rust-gvm",
    ),
    (
        "Syslog",
        "gvmd alert display names belong in greenbone-hive/rust-gvm",
    ),
];

const FORBIDDEN_DIRECT_DEPS: &[(&str, &str)] = &[
    (
        "quick-xml",
        "direct XML parser dependencies belong in greenbone-hive/rust-gvm",
    ),
    (
        "roxmltree",
        "direct XML parser dependencies belong in greenbone-hive/rust-gvm",
    ),
    (
        "xmltree",
        "direct XML parser dependencies belong in greenbone-hive/rust-gvm",
    ),
    (
        "serde-xml-rs",
        "direct XML parser dependencies belong in greenbone-hive/rust-gvm",
    ),
];

#[test]
fn gmp_wire_handling_stays_in_rust_gvm() {
    // This is an architecture boundary test, not a style lint. The gateway may
    // orchestrate typed rust-gvm APIs, but GMP XML command construction and GMP
    // response parsing, protocol-shape aliases, and wire/display-name parsing
    // must be fixed upstream in greenbone-hive/rust-gvm. Unit-test sidecar fixtures
    // may still contain raw XML; this test intentionally scans production
    // source.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    let mut findings = find_forbidden_gmp_wire_handling(&manifest_dir, &src_dir);
    findings.extend(find_forbidden_direct_dependencies(&manifest_dir));
    findings.extend(find_mismatched_response_parsers(
        &manifest_dir,
        &src_dir.join("gvmd_adapter"),
    ));

    assert!(
        findings.is_empty(),
        "GMP command/response wire handling must be implemented in \
         greenbone-hive/rust-gvm, not rust-gvm-api. Stop this change and report an \
         upstream issue using docs/rust-gvm-gmp-boundary-issue-template.md.\n\n{}",
        format_findings(&findings.iter().collect::<Vec<_>>())
    );
}

#[test]
fn rust_gvm_components_resolve_to_one_revision() {
    // These five crates share one upstream workspace and typed protocol
    // contract. A partial lockfile update can compile against incompatible
    // command, response, and transport revisions, so the resolved SHAs must
    // remain atomic.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lockfile = fs::read_to_string(manifest_dir.join("../../Cargo.lock"))
        .expect("read workspace Cargo.lock");
    let mut revisions = BTreeMap::new();

    for package in lockfile.split("[[package]]") {
        let name = package.lines().find_map(|line| {
            line.trim()
                .strip_prefix("name = \"")
                .and_then(|value| value.strip_suffix('"'))
        });
        let Some(name) = name.filter(|name| RUST_GVM_COMPONENTS.contains(name)) else {
            continue;
        };
        let source = package
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("source = \"")
                    .and_then(|value| value.strip_suffix('"'))
            })
            .unwrap_or_else(|| panic!("{name} must have a git source"));
        let revision = source
            .rsplit_once('#')
            .map(|(_, revision)| revision)
            .unwrap_or_else(|| panic!("{name} git source must record a revision"));
        assert!(
            revisions.insert(name, revision).is_none(),
            "{name} must resolve exactly once"
        );
    }

    assert_eq!(
        revisions.len(),
        RUST_GVM_COMPONENTS.len(),
        "all five rust-gvm components must be present in Cargo.lock"
    );
    let expected = revisions
        .values()
        .next()
        .expect("at least one rust-gvm revision");
    assert!(
        revisions.values().all(|revision| revision == expected),
        "rust-gvm components resolved to different revisions: {revisions:?}"
    );
    assert_eq!(
        *expected, RUST_GVM_BASELINE,
        "rust-gvm components must remain on the reviewed issue #517 NVT/SecInfo baseline"
    );

    let workspace_manifest =
        fs::read_to_string(manifest_dir.join("../../Cargo.toml")).expect("read workspace manifest");
    for component in RUST_GVM_COMPONENTS {
        let dependency = workspace_manifest
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("{component} =")))
            .unwrap_or_else(|| panic!("{component} must be declared in workspace dependencies"));
        assert!(
            dependency.contains(&format!("rev = \"{RUST_GVM_BASELINE}\"")),
            "{component} must pin the reviewed issue #517 baseline in Cargo.toml: {dependency}"
        );
        assert!(
            !dependency.contains("branch ="),
            "{component} must not use a moving branch dependency: {dependency}"
        );
    }
}

#[test]
fn removed_pre_result_transition_types_stay_absent() {
    // Issue #512 adopts every canonical complete-request family through the
    // asset baseline. Scanning adapter production and sidecar tests prevents a
    // future upstream compatibility shim from silently restoring option bags
    // or the removed operating-system-specific transition request downstream.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut findings = Vec::new();
    for root in [manifest_dir.join("src"), manifest_dir.join("tests")] {
        for file in rust_files(&root) {
            if file.ends_with("tests/architecture.rs") {
                continue;
            }
            let contents = fs::read_to_string(&file).expect("read adapter Rust source");
            for removed in REMOVED_CANONICAL_TRANSITION_TYPES {
                if contents.contains(removed) {
                    findings.push(format!("{} uses {removed}", file.display()));
                }
            }
        }
    }
    assert!(
        findings.is_empty(),
        "removed pre-result canonical transition APIs must stay absent:\n{}",
        findings.join("\n")
    );
}

#[test]
fn report_configuration_administration_stays_omitted() {
    // Issue #514 distinguishes the supported report-export selector from the
    // intentionally omitted report-configuration administration surface in
    // issue #381. Canonical upstream availability must not add those methods.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let production = fs::read_to_string(manifest_dir.join("src/gvmd_adapter/mod.rs"))
        .expect("read gvmd adapter imports");
    for request in [
        "GetReportConfigsRequest",
        "GetReportConfigRequest",
        "CreateReportConfigRequest",
        "CloneReportConfigRequest",
        "ModifyReportConfigRequest",
        "DeleteReportConfigRequest",
    ] {
        assert!(
            !production.contains(request),
            "report-configuration administration is omitted under issue #381: {request}"
        );
    }

    let reports = fs::read_to_string(manifest_dir.join("src/gvmd_adapter/ports/reports.rs"))
        .expect("read report adapter");
    assert!(
        reports.contains("opts.report_config_id = request"),
        "reportConfigId must remain an export selector"
    );
}

#[test]
fn nvt_secinfo_migration_dispositions_stay_bounded() {
    // Issue #517 migrates existing reads only. Generic SecInfo/vulnerability
    // endpoints remain omitted, while preference and selection mutations keep
    // their existing implementation until the separately reviewed #523 work.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let production = fs::read_to_string(manifest_dir.join("src/gvmd_adapter/mod.rs"))
        .expect("read gvmd adapter imports");
    for request in [
        "GetInfoListRequest",
        "GetInfoRequest",
        "GetVulnerabilityRequest",
        "GetNvtPreferencesRequest",
        "GetNvtPreferenceRequest",
    ] {
        assert!(
            !production.contains(request),
            "issue #517 must not widen the public surface through {request}"
        );
    }

    let scan_configs =
        fs::read_to_string(manifest_dir.join("src/gvmd_adapter/ports/scan_configs.rs"))
            .expect("read scan-config adapter");
    for deferred_mutation in [
        "ModifyScanConfigSetNvtSelectionRequest::new",
        "ModifyScanConfigSetNvtPreferenceRequest::new",
    ] {
        assert!(
            scan_configs.contains(deferred_mutation),
            "preference/selection mutation must remain unchanged pending #523: {deferred_mutation}"
        );
    }

    let dispositions =
        fs::read_to_string(manifest_dir.join("../../docs/upstream-surface-dispositions.md"))
            .expect("read upstream surface dispositions");
    assert!(dispositions.contains("Deferred to #523"));
    assert!(dispositions.contains("Generic SecInfo dispatch"));
}

#[test]
fn initial_adapter_slice_stays_on_typed_execution() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let adapter_dir = manifest_dir.join("src/gvmd_adapter");

    let adapter = fs::read_to_string(adapter_dir.join("mod.rs")).expect("read adapter module");
    let version_probe = section_between(
        &adapter,
        "pub async fn probe_version",
        "/// Open and authenticate a session-bound GMP connection.",
    );
    assert_typed_section(
        version_probe,
        "GetVersionRequest::new()",
        "backend version probe",
    );

    let session = fs::read_to_string(adapter_dir.join("session.rs")).expect("read session module");
    let authentication = section_between(
        &session,
        "pub(super) async fn connect_authenticated_client",
        "pub(super) type SharedClient",
    );
    assert_typed_section(
        authentication,
        "AuthenticateRequest::new(username, password)",
        "session authentication",
    );

    let targets = fs::read_to_string(adapter_dir.join("ports/targets.rs"))
        .expect("read target adapter module");
    let standard_targets = section_between(
        &targets,
        "impl TargetPort for GvmdAdapter",
        "async fn list_oci_image_targets",
    );
    for request in [
        "GetTargetsRequest",
        "GetTargetRequest::new",
        "CreateTargetRequest::new",
        "ModifyTargetRequest::new",
        "DeleteTargetRequest::new",
        "CloneTargetRequest::new",
    ] {
        assert!(
            standard_targets.contains(request),
            "standard target operations must use semantic request {request}"
        );
    }
    assert_typed_section(
        standard_targets,
        "execute_with_session",
        "standard target operations",
    );

    let reports = fs::read_to_string(adapter_dir.join("ports/reports.rs"))
        .expect("read report adapter module");
    let report_export =
        section_between(&reports, "async fn export_report", "async fn delete_report");
    assert_typed_section(
        report_export,
        "GmpGetReportExportRequest::new",
        "report export",
    );
}

#[test]
fn migrated_task_and_report_families_stay_on_typed_execution() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ports_dir = manifest_dir.join("src/gvmd_adapter/ports");

    let tasks = fs::read_to_string(ports_dir.join("tasks.rs")).expect("read task adapter module");
    assert_typed_section(&tasks, "GetTasksRequest {", "standard task family");

    let reports =
        fs::read_to_string(ports_dir.join("reports.rs")).expect("read report adapter module");
    assert_typed_section(&reports, "GetReportsRequest::new", "report family");
}

#[test]
fn migrated_security_and_config_families_stay_on_typed_execution() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ports_dir = manifest_dir.join("src/gvmd_adapter/ports");

    for (file, request, description) in [
        (
            "credentials.rs",
            "GetCredentialsRequest",
            "credential family",
        ),
        ("scanners.rs", "GetScannersRequest", "scanner family"),
        (
            "scan_configs.rs",
            "GetScanConfigsRequest::new",
            "config and policy family",
        ),
        ("port_lists.rs", "GetPortListsRequest", "port-list family"),
    ] {
        let contents = fs::read_to_string(ports_dir.join(file))
            .unwrap_or_else(|error| panic!("read {description} adapter module: {error}"));
        assert_typed_section(&contents, request, description);
    }
}

#[test]
fn migrated_automation_families_stay_on_typed_execution() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ports_dir = manifest_dir.join("src/gvmd_adapter/ports");

    for (file, request, description) in [
        ("alerts.rs", "GetAlertsRequest", "alert family"),
        ("schedules.rs", "GetSchedulesRequest", "schedule family"),
    ] {
        let contents = fs::read_to_string(ports_dir.join(file))
            .unwrap_or_else(|error| panic!("read {description} adapter module: {error}"));
        assert_typed_section(&contents, request, description);
    }
}

#[test]
fn migrated_identity_families_stay_on_typed_execution() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let identity = fs::read_to_string(manifest_dir.join("src/gvmd_adapter/ports/identity.rs"))
        .expect("read identity adapter module");

    for request in [
        "GetUsersRequest",
        "GetGroupsRequest",
        "GetRolesRequest",
        "GetPermissionsRequest",
        "GetUserSettingsRequest::new",
    ] {
        assert!(
            identity.contains(request),
            "identity operations must use semantic request {request}"
        );
    }
    assert_typed_section(&identity, "execute_with_session", "identity families");
}

#[test]
fn remaining_adapter_families_and_raw_call_inventory_stay_typed() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let adapter_dir = manifest_dir.join("src/gvmd_adapter");
    let ports_dir = adapter_dir.join("ports");

    for (file, request, description) in [
        ("feeds.rs", "GetFeedsRequest::new", "feed family"),
        ("system.rs", "GetTimezonesRequest::new", "system family"),
        ("agents.rs", "GetAgentsRequest", "agent family"),
    ] {
        let contents = fs::read_to_string(ports_dir.join(file))
            .unwrap_or_else(|error| panic!("read {description} adapter module: {error}"));
        assert_typed_section(&contents, request, description);
    }

    let targets =
        fs::read_to_string(ports_dir.join("targets.rs")).expect("read target adapter module");
    assert!(
        targets.contains("GetOciImageTargetsRequest")
            && targets.contains("GetWebApplicationTargetsRequest"),
        "specialized target families must construct semantic requests"
    );
    assert_typed_section(&targets, "execute_with_session", "all target families");

    let mut raw_calls = 0;
    let mut manual_parsers = 0;
    let mut raw_helpers = 0;
    for file in rust_files(&adapter_dir) {
        let contents = fs::read_to_string(file).expect("read production adapter source");
        raw_calls += contents.matches(".call(").count();
        manual_parsers += contents.matches("::from_response(").count();
        raw_helpers += contents.matches("call_with_session").count();
    }
    assert_eq!(raw_calls, 0, "production adapters must stay fully typed");
    assert_eq!(
        manual_parsers, 0,
        "production adapters must not manually parse GMP responses"
    );
    assert_eq!(
        raw_helpers, 0,
        "the obsolete raw session helper must stay removed"
    );
}

#[test]
fn migrated_supporting_resource_families_stay_on_typed_execution() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ports_dir = manifest_dir.join("src/gvmd_adapter/ports");
    let supporting = fs::read_to_string(ports_dir.join("supporting_resources.rs"))
        .expect("read supporting-resource adapter module");

    assert!(
        !supporting.contains("GetReportFormatsOpts"),
        "report-format adapters must not restore the removed option bag"
    );
    assert!(
        !supporting.contains("GetTlsCertificatesOpts"),
        "TLS-certificate adapters must not restore the removed option bag"
    );
    assert!(
        !supporting.contains("GetNvtsOpts") && !supporting.contains("GetSecInfoOpts"),
        "NVT and SecInfo adapters must not restore removed option bags"
    );

    for request in [
        "GetAssetsRequest::new",
        "GetHostsRequest",
        "GetOperatingSystemAssetsRequest",
        "GetTlsCertificatesRequest {",
        "GetReportFormatsRequest {",
        "GetFiltersRequest",
        "GetTagsRequest",
        "GetNotesRequest",
        "GetOverridesRequest",
        "GetNvtsRequest {",
        "GetNvtRequest::new",
        "GetNvtFamiliesRequest::new",
        "GetVulnsRequest {",
        "GetCvesRequest {",
        "GetCveRequest::new",
        "GetCpesRequest {",
        "GetCpeRequest::new",
        "GetCertBundAdvisoriesRequest {",
        "GetCertBundAdvisoryRequest::new",
        "GetDfnCertAdvisoriesRequest {",
        "GetDfnCertAdvisoryRequest::new",
    ] {
        assert!(
            supporting.contains(request),
            "supporting-resource operations must use semantic request {request}"
        );
    }
    assert!(
        !supporting.contains("call_with_session"),
        "supporting resources must not use the raw session helper"
    );
    assert_eq!(
        supporting.matches(".call(").count(),
        0,
        "supporting resources must not bypass typed execution with raw calls"
    );
    assert_eq!(
        supporting.matches("::from_response").count(),
        0,
        "supporting resources must not parse GMP responses manually"
    );

    let results =
        fs::read_to_string(ports_dir.join("results.rs")).expect("read result adapter module");
    assert_typed_section(&results, "GetResultsRequest {", "result family");

    let scan_configs = fs::read_to_string(ports_dir.join("scan_configs.rs"))
        .expect("read scan-config adapter module");
    assert!(
        !scan_configs.contains("GetNvtsOpts"),
        "scan-config NVT reads must not restore the removed option bag"
    );
    for request in [
        "GetScanConfigNvtsRequest::new",
        "GetScanConfigNvtRequest::new",
    ] {
        assert!(
            scan_configs.contains(request),
            "scan-config NVT reads must use canonical request {request}"
        );
    }
}

fn section_between<'a>(contents: &'a str, start: &str, end: &str) -> &'a str {
    contents
        .split_once(start)
        .unwrap_or_else(|| panic!("missing section start: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing section end: {end}"))
        .0
}

fn assert_typed_section(section: &str, semantic_request: &str, description: &str) {
    assert!(
        section.contains(semantic_request),
        "{description} must construct {semantic_request}"
    );
    assert!(
        section.contains(".execute(") || section.contains("execute_with_session"),
        "{description} must use typed execution"
    );
    assert!(
        !section.contains(".call(") && !section.contains("call_with_session"),
        "{description} must not use the raw call boundary"
    );
    assert!(
        !section.contains("::from_response("),
        "{description} must not manually pair a response parser"
    );
}

fn find_forbidden_gmp_wire_handling(manifest_dir: &Path, dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in rust_files(dir) {
        let relative = file
            .strip_prefix(manifest_dir)
            .expect("source file should be below manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        let contents = fs::read_to_string(&file).expect("read Rust source file");
        let mut cfg_test_pending = false;
        let mut test_module_depth: Option<isize> = None;

        for (line_index, line) in contents.lines().enumerate() {
            if let Some(depth) = test_module_depth.as_mut() {
                *depth += brace_delta(line);
                if *depth <= 0 {
                    test_module_depth = None;
                }
                continue;
            }

            if line.trim() == "#[cfg(test)]" {
                cfg_test_pending = true;
                continue;
            }

            if cfg_test_pending && line.contains("mod tests") {
                test_module_depth = Some(brace_delta(line));
                cfg_test_pending = false;
                continue;
            }
            cfg_test_pending = false;

            for (needle, marker) in FORBIDDEN_MARKERS {
                if line.contains(needle) {
                    findings.push(Finding {
                        path: relative.clone(),
                        line: line_index + 1,
                        marker,
                        text: line.trim().to_string(),
                    });
                }
            }
        }
    }
    findings
}

fn brace_delta(line: &str) -> isize {
    line.chars().filter(|character| *character == '{').count() as isize
        - line.chars().filter(|character| *character == '}').count() as isize
}

fn find_forbidden_direct_dependencies(manifest_dir: &Path) -> Vec<Finding> {
    let cargo_toml = manifest_dir.join("Cargo.toml");
    let contents = fs::read_to_string(&cargo_toml).expect("read Cargo.toml");
    let mut findings = Vec::new();

    for (line_index, line) in contents.lines().enumerate() {
        let trimmed = line.trim_start();
        for (dependency, marker) in FORBIDDEN_DIRECT_DEPS {
            if trimmed.starts_with(&format!("{dependency} "))
                || trimmed.starts_with(&format!("{dependency}="))
                || trimmed.starts_with(&format!("{dependency}."))
            {
                findings.push(Finding {
                    path: "Cargo.toml".to_string(),
                    line: line_index + 1,
                    marker,
                    text: line.trim().to_string(),
                });
            }
        }
    }

    findings
}

fn find_mismatched_response_parsers(manifest_dir: &Path, dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for file in rust_files(dir) {
        let relative = file
            .strip_prefix(manifest_dir)
            .expect("source file should be below manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        let contents = fs::read_to_string(file).expect("read gvmd adapter source file");
        let mut last_operation: Option<(&'static str, usize)> = None;

        for (line_index, line) in contents.lines().enumerate() {
            if line.contains("\"tasks.start\"") {
                last_operation = Some(("tasks.start", line_index + 1));
            } else if line.contains("\"tasks.resume\"") {
                last_operation = Some(("tasks.resume", line_index + 1));
            } else if line.contains("StartTaskResponse::from_response(&response)") {
                if let Some(("tasks.resume", operation_line)) = last_operation {
                    findings.push(Finding {
                        path: relative.clone(),
                        line: line_index + 1,
                        marker: "resume_task must use a typed rust-gvm resume response parser",
                        text: format!(
                            "operation declared at line {operation_line}; parser: {}",
                            line.trim()
                        ),
                    });
                }
                last_operation = None;
            } else if line.contains("ActionResponse::from_response(&response)")
                || line.contains("GetTasksResponse::from_response(&response)")
                || line.contains("CreateTaskResponse::from_response(&response)")
            {
                last_operation = None;
            }
        }
    }

    findings
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).expect("read source directory") {
        let path = entry.expect("read directory entry").path();
        if path.is_dir() {
            files.extend(rust_files(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && !path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with("_test.rs"))
        {
            files.push(path);
        }
    }
    files.sort();
    files
}

fn format_findings(findings: &[&Finding]) -> String {
    if findings.is_empty() {
        return "no unexpected findings".to_string();
    }

    findings
        .iter()
        .map(|finding| {
            format!(
                "{}:{}: {}\n    {}\n    {}",
                finding.path, finding.line, finding.marker, finding.text, finding.marker
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
