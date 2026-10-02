// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    collections::{BTreeMap, BTreeSet},
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
// The published v0.7.0 release contains the complete reviewed canonical-request
// baseline and must remain immutable across all five workspace dependencies.
const RUST_GVM_RELEASE_TAG: &str = "v0.7.0";
const RUST_GVM_RELEASE_REVISION: &str = "acdabf5a039d78df82e86b69ee8a374df8575c7a";
const RUST_GVM_TYPED_FACADE_METHOD_COUNT: usize = 261;
const RUST_GVM_TYPED_FACADE_SNAPSHOT: &str = "tests/fixtures/rust-gvm-v0.7.0-typed-facade.tsv";
const RUST_GVM_DISPOSITION_LEDGER: &str = "../../docs/upstream-surface-dispositions.tsv";
const ALLOWED_DISPOSITIONS: &[&str] = &[
    "exposed", "mapped", "internal", "blocked", "deferred", "omitted",
];

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
    "GetReportsOpts",
    "GetReportDetailsOpts",
    "GetReportExportOpts",
    "CreateAgentGroupTaskOpts",
    "CreateOciImageTargetTaskOpts",
    "CreateWebApplicationTaskOpts",
    "CreateTaskOpts",
    "GetTasksOpts",
    "ModifyTaskOpts",
    "GetUserSettingsOpts",
    "ModifyUserSettingOpts",
];

#[derive(Debug, Eq, PartialEq)]
struct Finding {
    path: String,
    line: usize,
    marker: &'static str,
    text: String,
}

#[derive(Debug, Eq, PartialEq)]
struct PinnedMethodInventory {
    tag: String,
    revision: String,
    methods: BTreeSet<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct DispositionLedger {
    tag: String,
    revision: String,
    methods: BTreeSet<String>,
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
        *expected, RUST_GVM_RELEASE_REVISION,
        "rust-gvm components must remain on the exact published v0.7.0 revision"
    );

    let workspace_manifest =
        fs::read_to_string(manifest_dir.join("../../Cargo.toml")).expect("read workspace manifest");
    for component in RUST_GVM_COMPONENTS {
        let dependency = workspace_manifest
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("{component} =")))
            .unwrap_or_else(|| panic!("{component} must be declared in workspace dependencies"));
        assert!(
            dependency.contains(&format!("tag = \"{RUST_GVM_RELEASE_TAG}\"")),
            "{component} must pin the immutable v0.7.0 release tag in Cargo.toml: {dependency}"
        );
        assert!(
            !dependency.contains("branch ="),
            "{component} must not use a moving branch dependency: {dependency}"
        );
    }
}

#[test]
fn rust_gvm_typed_facade_dispositions_are_complete_and_pinned() {
    // Issue #573 closes the downstream review for every public async helper in
    // the pinned facade. The checked-in source snapshot keeps this test fully
    // offline, while shared tag/revision constants couple reconciliation to the
    // immutable dependency-pin guard above.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let snapshot_source = fs::read_to_string(manifest_dir.join(RUST_GVM_TYPED_FACADE_SNAPSHOT))
        .expect("read checked-in rust-gvm typed-facade snapshot");
    let ledger_source = fs::read_to_string(manifest_dir.join(RUST_GVM_DISPOSITION_LEDGER))
        .expect("read downstream disposition ledger");
    let snapshot = parse_pinned_method_inventory(&snapshot_source).unwrap_or_else(|errors| {
        panic!(
            "invalid checked-in rust-gvm typed-facade snapshot:\n- {}",
            errors.join("\n- ")
        )
    });
    let ledger = parse_disposition_ledger(&ledger_source).unwrap_or_else(|errors| {
        panic!(
            "invalid downstream disposition ledger:\n- {}",
            errors.join("\n- ")
        )
    });

    let mut errors = pinned_metadata_errors("upstream snapshot", &snapshot.tag, &snapshot.revision);
    errors.extend(pinned_metadata_errors(
        "disposition ledger",
        &ledger.tag,
        &ledger.revision,
    ));
    if snapshot.methods.len() != RUST_GVM_TYPED_FACADE_METHOD_COUNT {
        errors.push(format!(
            "upstream snapshot has {} methods, expected {RUST_GVM_TYPED_FACADE_METHOD_COUNT}; regenerate it from rust-gvm {RUST_GVM_RELEASE_TAG} at {RUST_GVM_RELEASE_REVISION}",
            snapshot.methods.len()
        ));
    }
    errors.extend(reconcile_disposition_ledger(&snapshot, &ledger));

    assert!(
        errors.is_empty(),
        "rust-gvm typed-facade disposition drift requires explicit ledger reconciliation:\n- {}",
        errors.join("\n- ")
    );
}

#[test]
fn disposition_ledger_rejects_malformed_rows_and_blank_required_fields() {
    // Malformed TSV and blank review evidence must fail closed instead of
    // silently turning an incomplete row into an accepted classification.
    let errors = parse_disposition_ledger(concat!(
        "# rust-gvm-tag\tv0.7.0\n",
        "# rust-gvm-revision\tacdabf5a039d78df82e86b69ee8a374df8575c7a\n",
        "method\tdisposition\trationale\tevidence\n",
        "get_version\texposed\tonly three columns\n",
        "get_targets\texposed\t\tspec/rest-api/targets.yaml\n",
        "get_tasks\texposed\tdirect task read\t\n",
    ))
    .expect_err("malformed and blank required fields must be rejected");

    assert!(errors
        .iter()
        .any(|error| error.contains("expected 4 columns")));
    assert!(errors.iter().any(|error| error.contains("blank rationale")));
    assert!(errors.iter().any(|error| error.contains("blank evidence")));
}

#[test]
fn disposition_ledger_rejects_duplicate_methods() {
    // One upstream method must have one and only one downstream decision so a
    // later row cannot shadow a reviewed classification.
    let errors = parse_disposition_ledger(concat!(
        "# rust-gvm-tag\tv0.7.0\n",
        "# rust-gvm-revision\tacdabf5a039d78df82e86b69ee8a374df8575c7a\n",
        "method\tdisposition\trationale\tevidence\n",
        "get_version\texposed\tpublic version\tspec/rest-api/system.yaml\n",
        "get_version\tinternal\tprobe only\tcrates/gvm-gateway-gvmd/src\n",
    ))
    .expect_err("duplicate ledger methods must be rejected");

    assert!(errors.iter().any(|error| {
        error.contains("duplicate method get_version") && error.contains("first declared on line 4")
    }));
}

#[test]
fn disposition_ledger_rejects_unknown_dispositions() {
    // The six reviewed disposition values are a closed vocabulary; spelling
    // drift must not create an accidental seventh classification.
    let errors = parse_disposition_ledger(concat!(
        "# rust-gvm-tag\tv0.7.0\n",
        "# rust-gvm-revision\tacdabf5a039d78df82e86b69ee8a374df8575c7a\n",
        "method\tdisposition\trationale\tevidence\n",
        "get_version\tadopted\tpublic version\tspec/rest-api/system.yaml\n",
    ))
    .expect_err("unknown dispositions must be rejected");

    assert!(errors.iter().any(|error| {
        error.contains("unknown disposition adopted") && error.contains("allowed values")
    }));
}

#[test]
fn disposition_reconciliation_reports_added_removed_and_renamed_methods() {
    // A changed upstream inventory must identify both new/unclassified helpers
    // and stale ledger rows, which together make method renames actionable.
    let snapshot = parse_pinned_method_inventory(concat!(
        "# rust-gvm-tag\tv0.7.0\n",
        "# rust-gvm-revision\tacdabf5a039d78df82e86b69ee8a374df8575c7a\n",
        "module\tmethod\n",
        "core\tget_version\n",
        "core\tnew_upstream_method\n",
    ))
    .expect("valid test inventory");
    let ledger = parse_disposition_ledger(concat!(
        "# rust-gvm-tag\tv0.7.0\n",
        "# rust-gvm-revision\tacdabf5a039d78df82e86b69ee8a374df8575c7a\n",
        "method\tdisposition\trationale\tevidence\n",
        "get_version\texposed\tpublic version\tspec/rest-api/system.yaml\n",
        "removed_upstream_method\tomitted\tretired helper\tparent #381\n",
    ))
    .expect("valid test ledger");

    let errors = reconcile_disposition_ledger(&snapshot, &ledger);
    assert!(errors.iter().any(|error| {
        error.contains("unclassified upstream methods (added or renamed)")
            && error.contains("new_upstream_method")
    }));
    assert!(errors.iter().any(|error| {
        error.contains("ledger methods absent from upstream snapshot (removed or renamed)")
            && error.contains("removed_upstream_method")
    }));
}

#[test]
fn removed_canonical_transition_types_stay_absent() {
    // The ordered canonical migrations through issue #529 remove transitional
    // request and option APIs. Scanning all workspace production prevents a
    // future upstream compatibility shim from silently restoring them.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut findings = Vec::new();
    for file in rust_files(&manifest_dir.join("../../crates")) {
        if file.ends_with("tests/architecture.rs") {
            continue;
        }
        let contents = fs::read_to_string(&file).expect("read workspace Rust source");
        for removed in REMOVED_CANONICAL_TRANSITION_TYPES {
            if contents.contains(removed) {
                findings.push(format!("{} uses {removed}", file.display()));
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
fn canonical_user_setting_requests_stay_complete_and_source_faithful() {
    // Issue #529 adopts the canonical #671 request and response surface. Keep
    // all query controls explicit, consume the source-faithful items field,
    // and prevent compatibility option bags from returning.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let identity = fs::read_to_string(manifest_dir.join("src/gvmd_adapter/ports/identity.rs"))
        .expect("read identity adapter");
    let list = section_between(
        &identity,
        "async fn list_user_settings",
        "async fn get_user_setting",
    );
    for assignment in [
        "request.filter_string = filter;",
        "request.first = Some(1);",
        "request.max = Some(-1);",
        "request.sort_field = Some(\"name\".to_string());",
        "request.sort_order = Some(SortOrder::Ascending);",
    ] {
        assert!(
            list.contains(assignment),
            "user-setting list must populate canonical field: {assignment}"
        );
    }
    assert!(list.contains(".items"));
    assert!(!list.contains(".settings"));

    let detail = section_between(
        &identity,
        "async fn get_user_setting",
        "async fn modify_user_setting",
    );
    assert!(detail.contains("GetUserSettingRequest::new"));
    assert!(detail.contains(".items"));
    assert!(detail.contains("GatewayError::NotFound"));
    assert!(!detail.contains(".settings"));

    let modify = identity
        .split("async fn modify_user_setting")
        .nth(1)
        .expect("modify user-setting section");
    assert!(modify.contains("ModifyUserSettingRequest::new(parse_entity_id(id)?, input.value)"));
    assert!(!identity.contains("GetUserSettingsOpts"));
    assert!(!identity.contains("ModifyUserSettingOpts"));

    let conversions =
        fs::read_to_string(manifest_dir.join("src/conversions.rs")).expect("read conversions");
    assert!(conversions.contains("user_setting_from_gmp(setting: gvm_gmp::responses::Setting)"));
    assert!(!conversions.contains("gvm_gmp::responses::UserSetting"));
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
        reports.contains("export_request.report_config_id = request"),
        "reportConfigId must remain an export selector"
    );
}

#[test]
fn nvt_secinfo_migration_dispositions_stay_bounded() {
    // Issue #517 migrated existing reads only. Generic SecInfo/vulnerability
    // endpoints remain omitted. Issue #523 later moved the existing preference
    // and selection mutations to canonical typed requests without adding routes.
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
    for canonical_mutation in [
        "ModifyScanConfigSetNvtSelectionRequest::new",
        "ModifyScanConfigSetNvtPreferenceRequest::new",
    ] {
        assert!(
            scan_configs.contains(canonical_mutation),
            "preference/selection mutation must stay on its canonical #523 request: {canonical_mutation}"
        );
    }

    let dispositions =
        fs::read_to_string(manifest_dir.join("../../docs/upstream-surface-dispositions.md"))
            .expect("read upstream surface dispositions");
    assert!(dispositions.contains("Adopted through completed #523"));
    assert!(dispositions.contains("Generic SecInfo dispatch"));
}

#[test]
fn system_discovery_migration_dispositions_stay_bounded() {
    // Issue #528 adopts canonical typed discovery only for the pre-existing
    // version, authentication, timezone, and feed operations. The other
    // upstream system-discovery requests remain deliberately non-public under
    // the #381/#401 surface inventory; their availability must not add routes.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let production = fs::read_to_string(manifest_dir.join("src/gvmd_adapter/mod.rs"))
        .expect("read gvmd adapter imports");
    for request in [
        "GetSettingsRequest",
        "GetAggregatesRequest",
        "GetFeaturesRequest",
        "GetLicenseRequest",
        "HelpRequest",
        "GetResourceNamesRequest",
        "GetResourceNameRequest",
        "GetSystemReportsRequest",
        "DescribeAuthRequest",
    ] {
        assert!(
            !production.contains(request),
            "system discovery is not a new public surface under #381/#401: {request}"
        );
    }

    let feeds = fs::read_to_string(manifest_dir.join("src/gvmd_adapter/ports/feeds.rs"))
        .expect("read feed adapter");
    for mapping in [
        "parsed.feed_owner_set.unwrap_or(false)",
        "parsed.feed_roles_set.unwrap_or(false)",
        "parsed.feed_resources_access.unwrap_or(false)",
    ] {
        assert!(
            feeds.contains(mapping),
            "optional canonical feed access metadata must preserve required REST booleans: {mapping}"
        );
    }

    let dispositions =
        fs::read_to_string(manifest_dir.join("../../docs/upstream-surface-dispositions.md"))
            .expect("read upstream surface dispositions");
    for disposition in [
        "System discovery additions",
        "#381/#401",
        "feed-sync",
        "auth-description",
    ] {
        assert!(
            dispositions.contains(disposition),
            "system-discovery disposition must remain documented: {disposition}"
        );
    }
}

#[test]
fn administration_and_cleanup_dispositions_stay_explicit_and_non_public() {
    // Reviewed upstream availability does not authorize new downstream
    // administration routes. Every remaining #664 family must retain its
    // #381/#401 disposition and stay absent from production adapter imports.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let production = fs::read_to_string(manifest_dir.join("src/gvmd_adapter/mod.rs"))
        .expect("read gvmd adapter imports");
    for omitted_request in [
        "DescribeAuthRequest",
        "ModifyAuthRequest",
        "GetLicenseRequest",
        "ModifyLicenseRequest",
        "GetSettingsRequest",
        "ModifySettingRequest",
        "RunWizardRequest",
        "EmptyTrashcanRequest",
        "RestoreRequest",
        "CreateScannerRequest",
        "CloneScannerRequest",
        "ModifyScannerRequest",
        "DeleteScannerRequest",
        "VerifyScannerRequest",
    ] {
        assert!(
            !production.contains(omitted_request),
            "administration/cleanup request must stay non-public: {omitted_request}"
        );
    }

    let dispositions =
        fs::read_to_string(manifest_dir.join("../../docs/upstream-surface-dispositions.md"))
            .expect("read upstream surface dispositions");
    for documented in [
        "Authentication configuration",
        "License administration",
        "Global settings administration",
        "Wizard execution",
        "Trash cleanup and recovery",
        "Scanner administration",
        "Removed #664 compatibility surfaces",
        "#381/#401",
    ] {
        assert!(
            dispositions.contains(documented),
            "administration/cleanup disposition must remain documented: {documented}"
        );
    }

    let router = fs::read_to_string(manifest_dir.join("../gvm-gateway-rest/src/router.rs"))
        .expect("read REST router");
    let scanner_routes = section_between(&router, "// Scanners", "\"/api/v1/operating-systems\"");
    assert_eq!(scanner_routes.matches("/api/v1/scanners").count(), 2);
    assert_eq!(scanner_routes.matches("get_with(").count(), 2);
    for mutating_route in ["post_with(", "put_with(", "delete_with("] {
        assert!(
            !scanner_routes.contains(mutating_route),
            "scanner administration route must stay absent: {mutating_route}"
        );
    }
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
        "GetReportExportRequest::new",
        "report export",
    );
    assert!(
        !report_export.contains("GmpGetReportExportRequest"),
        "report export must retain the canonical upstream request spelling"
    );
}

#[test]
fn migrated_task_and_report_families_stay_on_typed_execution() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ports_dir = manifest_dir.join("src/gvmd_adapter/ports");

    let tasks = fs::read_to_string(ports_dir.join("tasks.rs")).expect("read task adapter module");
    for (request, description) in [
        ("GetTasksRequest {", "standard task family"),
        (
            "CreateAgentGroupTaskRequest::new",
            "agent-group task creation",
        ),
        (
            "CreateOciImageTargetTaskRequest::new",
            "OCI-image task creation",
        ),
        (
            "CreateWebApplicationTaskRequest::new",
            "web-application task creation",
        ),
        ("CreateImportTaskRequest::new", "import task creation"),
        ("GetAuditsRequest {", "audit listing"),
        ("GetAuditRequest::new", "audit detail"),
        ("CreateAuditRequest::new", "audit creation"),
        ("ModifyAuditRequest::new", "audit modification"),
        ("DeleteAuditRequest::new", "audit deletion"),
        ("StartAuditRequest::new", "audit start"),
        ("StopAuditRequest::new", "audit stop"),
        ("ResumeAuditRequest::new", "audit resume"),
    ] {
        assert_typed_section(&tasks, request, description);
    }

    let reports =
        fs::read_to_string(ports_dir.join("reports.rs")).expect("read report adapter module");
    let import_report =
        section_between(&reports, "async fn import_report", "async fn list_reports");
    assert_typed_section(
        import_report,
        "ImportReportRequest::new",
        "bounded report import",
    );
    assert!(
        import_report.contains("request.in_assets = input.in_assets"),
        "report import must preserve omitted versus explicit false inAssets"
    );
    let list_reports = section_between(&reports, "async fn list_reports", "async fn get_report");
    assert_typed_section(list_reports, "GetReportsRequest {", "report listing");
    assert!(
        !list_reports.contains("GetReportsRequest::new"),
        "report listing must use the canonical complete request value"
    );

    let get_report = section_between(&reports, "async fn get_report", "async fn export_report");
    assert_typed_section(get_report, "GetReportRequest::new", "report detail");
    assert!(
        get_report.contains("request.details = Some(false)"),
        "report detail must suppress canonical default details because results use a separate window"
    );

    let delete_report = section_between(
        &reports,
        "async fn delete_report",
        "async fn get_report_results",
    );
    assert_typed_section(
        delete_report,
        "DeleteReportRequest::new",
        "permanent report deletion",
    );

    // Issue #527 adopts the canonical complete request values for all nine
    // existing projection endpoints. Their constructors carry identity only;
    // gateway-resolved filters and explicit detail semantics are assigned here.
    for (function, next_function, request, description) in [
        (
            "async fn get_report_vulnerabilities",
            "async fn get_report_hosts",
            "GetReportVulnsRequest",
            "report vulnerabilities",
        ),
        (
            "async fn get_report_hosts",
            "async fn get_report_ports",
            "GetReportHostsRequest",
            "report hosts",
        ),
        (
            "async fn get_report_ports",
            "async fn get_report_applications",
            "GetReportPortsRequest",
            "report ports",
        ),
        (
            "async fn get_report_applications",
            "async fn get_report_operating_systems",
            "GetReportApplicationsRequest",
            "report applications",
        ),
        (
            "async fn get_report_operating_systems",
            "async fn get_report_cves",
            "GetReportOperatingSystemsRequest",
            "report operating systems",
        ),
        (
            "async fn get_report_cves",
            "async fn get_report_tls_certificates",
            "GetReportCvesRequest",
            "report CVEs",
        ),
        (
            "async fn get_report_tls_certificates",
            "async fn get_report_errors",
            "GetReportTlsCertificatesRequest",
            "report TLS certificates",
        ),
        (
            "async fn get_report_errors",
            "async fn get_report_closed_cves",
            "GetReportErrorsRequest",
            "report errors",
        ),
        (
            "async fn get_report_closed_cves",
            "async fn report_projection_filter",
            "GetReportClosedCvesRequest",
            "report closed CVEs",
        ),
    ] {
        let projection = section_between(&reports, function, next_function);
        assert_typed_section(
            projection,
            &format!("{request}::new(report_id);"),
            description,
        );
        assert!(
            !projection.contains(&format!("{request}::new(report_id,")),
            "{description} must not restore the removed two-argument constructor"
        );
        for assignment in [
            "request.filter_string = filter_string;",
            "request.filter_id = None;",
            "request.ignore_pagination = None;",
            "request.details = Some(true);",
        ] {
            assert!(
                projection.contains(assignment),
                "{description} must populate the canonical complete request field: {assignment}"
            );
        }
    }

    let hosts = section_between(
        &reports,
        "async fn get_report_hosts",
        "async fn get_report_ports",
    );
    assert!(
        hosts.contains("request.lean = None;"),
        "report-host projection must preserve lean omission"
    );

    assert!(
        reports.contains("async fn report_projection_filter(")
            && reports.contains(") -> Result<Option<String>, GatewayError>"),
        "gateway-owned report filter resolution must return only the resolved inline filter"
    );
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
            "GetScanConfigsRequest {",
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

fn parse_pinned_method_inventory(contents: &str) -> Result<PinnedMethodInventory, Vec<String>> {
    let lines = contents.lines().collect::<Vec<_>>();
    let mut errors = Vec::new();
    let tag = parse_metadata_value(&lines, 0, "rust-gvm-tag", "upstream snapshot", &mut errors);
    let revision = parse_metadata_value(
        &lines,
        1,
        "rust-gvm-revision",
        "upstream snapshot",
        &mut errors,
    );
    if lines.get(2) != Some(&"module\tmethod") {
        errors.push(
            "upstream snapshot line 3 must be the exact header module<TAB>method".to_string(),
        );
    }

    let mut methods = BTreeSet::new();
    let mut first_lines = BTreeMap::new();
    for (index, line) in lines.iter().enumerate().skip(3) {
        let line_number = index + 1;
        let columns = line.split('\t').collect::<Vec<_>>();
        if columns.len() != 2 {
            errors.push(format!(
                "upstream snapshot line {line_number} expected 2 columns, found {}",
                columns.len()
            ));
            continue;
        }
        let module = columns[0];
        let method = columns[1];
        if !is_snake_case_identifier(module) {
            errors.push(format!(
                "upstream snapshot line {line_number} has invalid or blank module {module:?}"
            ));
        }
        if !is_snake_case_identifier(method) {
            errors.push(format!(
                "upstream snapshot line {line_number} has invalid or blank method {method:?}"
            ));
            continue;
        }
        if let Some(first_line) = first_lines.insert(method.to_string(), line_number) {
            errors.push(format!(
                "upstream snapshot line {line_number} duplicates method {method} first declared on line {first_line}"
            ));
        } else {
            methods.insert(method.to_string());
        }
    }

    if errors.is_empty() {
        Ok(PinnedMethodInventory {
            tag,
            revision,
            methods,
        })
    } else {
        Err(errors)
    }
}

fn parse_disposition_ledger(contents: &str) -> Result<DispositionLedger, Vec<String>> {
    let lines = contents.lines().collect::<Vec<_>>();
    let mut errors = Vec::new();
    let tag = parse_metadata_value(&lines, 0, "rust-gvm-tag", "ledger", &mut errors);
    let revision = parse_metadata_value(&lines, 1, "rust-gvm-revision", "ledger", &mut errors);
    if lines.get(2) != Some(&"method\tdisposition\trationale\tevidence") {
        errors.push(
            "ledger line 3 must be the exact header method<TAB>disposition<TAB>rationale<TAB>evidence"
                .to_string(),
        );
    }

    let mut methods = BTreeSet::new();
    let mut first_lines = BTreeMap::new();
    for (index, line) in lines.iter().enumerate().skip(3) {
        let line_number = index + 1;
        let columns = line.split('\t').collect::<Vec<_>>();
        if columns.len() != 4 {
            errors.push(format!(
                "ledger line {line_number} expected 4 columns, found {}",
                columns.len()
            ));
            continue;
        }
        let method = columns[0];
        let disposition = columns[1];
        let rationale = columns[2];
        let evidence = columns[3];
        if !is_snake_case_identifier(method) {
            errors.push(format!(
                "ledger line {line_number} has invalid or blank method {method:?}"
            ));
            continue;
        }
        if !ALLOWED_DISPOSITIONS.contains(&disposition) {
            errors.push(format!(
                "ledger line {line_number} has unknown disposition {disposition}; allowed values: {}",
                ALLOWED_DISPOSITIONS.join(", ")
            ));
        }
        if rationale.trim().is_empty() {
            errors.push(format!(
                "ledger line {line_number} for {method} has blank rationale"
            ));
        }
        if evidence.trim().is_empty() {
            errors.push(format!(
                "ledger line {line_number} for {method} has blank evidence"
            ));
        }
        if let Some(first_line) = first_lines.insert(method.to_string(), line_number) {
            errors.push(format!(
                "ledger line {line_number} has duplicate method {method}, first declared on line {first_line}"
            ));
        } else {
            methods.insert(method.to_string());
        }
    }

    if errors.is_empty() {
        Ok(DispositionLedger {
            tag,
            revision,
            methods,
        })
    } else {
        Err(errors)
    }
}

fn parse_metadata_value(
    lines: &[&str],
    index: usize,
    key: &str,
    source: &str,
    errors: &mut Vec<String>,
) -> String {
    let line_number = index + 1;
    let prefix = format!("# {key}\t");
    let Some(line) = lines.get(index) else {
        errors.push(format!(
            "{source} is missing required metadata line {line_number}: {key}"
        ));
        return String::new();
    };
    let Some(value) = line.strip_prefix(&prefix) else {
        errors.push(format!(
            "{source} line {line_number} must start with {prefix:?}"
        ));
        return String::new();
    };
    if value.trim().is_empty() || value.contains('\t') {
        errors.push(format!(
            "{source} line {line_number} has invalid or blank {key} metadata"
        ));
        return String::new();
    }
    value.to_string()
}

fn is_snake_case_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn pinned_metadata_errors(label: &str, tag: &str, revision: &str) -> Vec<String> {
    let mut errors = Vec::new();
    if tag != RUST_GVM_RELEASE_TAG {
        errors.push(format!(
            "{label} tag is {tag:?}, expected {RUST_GVM_RELEASE_TAG:?}; regenerate the upstream snapshot and reconcile every ledger row with the dependency pin"
        ));
    }
    if revision != RUST_GVM_RELEASE_REVISION {
        errors.push(format!(
            "{label} revision is {revision:?}, expected {RUST_GVM_RELEASE_REVISION:?}; regenerate the upstream snapshot and reconcile every ledger row with the dependency pin"
        ));
    }
    errors
}

fn reconcile_disposition_ledger(
    snapshot: &PinnedMethodInventory,
    ledger: &DispositionLedger,
) -> Vec<String> {
    let mut errors = Vec::new();
    let unclassified = snapshot
        .methods
        .difference(&ledger.methods)
        .cloned()
        .collect::<Vec<_>>();
    if !unclassified.is_empty() {
        errors.push(format!(
            "unclassified upstream methods (added or renamed): {}",
            unclassified.join(", ")
        ));
    }
    let stale = ledger
        .methods
        .difference(&snapshot.methods)
        .cloned()
        .collect::<Vec<_>>();
    if !stale.is_empty() {
        errors.push(format!(
            "ledger methods absent from upstream snapshot (removed or renamed): {}",
            stale.join(", ")
        ));
    }
    errors
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
