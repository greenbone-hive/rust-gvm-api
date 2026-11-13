#!/usr/bin/env python3
"""Fail-closed validation for Phase 0 E2E inventory and evidence artifacts."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = REPOSITORY_ROOT / "tests" / "e2e" / "evidence"
INVENTORY_PATH = EVIDENCE_ROOT / "contract-inventory.json"
OWNERS_PATH = EVIDENCE_ROOT / "owners.json"
BASELINE_PATH = EVIDENCE_ROOT / "baselines" / "osp-required.json"
DIRECT_PINS_PATH = EVIDENCE_ROOT / "direct-openvasd-pins.json"

FAILURE_CLASSES = {
    "setup",
    "readiness",
    "application",
    "assertion",
    "cleanup",
    "runner",
    "unexplained-flake",
    "unclassified",
}
OSP_DISPOSITIONS = {"keep", "migrate", "replace", "retire", "not-applicable"}
SCANNER_PORTABILITY = {
    "scanner-independent",
    "direct-openvasd-compatible",
    "osp-specific",
}
CONTRACT_PREFIXES = {"rest", "gmp", "scanner"}
DEPENDENCY_KINDS = {"component", "data-feed", "fixture", "environment", "feature-flag"}
TEST_KINDS = {"helper", "live"}
SETUP_KINDS = {
    "fixture-only",
    "public-readiness",
    "authenticated-session",
    "mutable-resources",
    "completed-scan",
}
ISOLATION_KINDS = {
    "process-local",
    "serial-shared-gvmd",
    "global-lock-shared-gvmd",
}
CLEANUP_KINDS = {"none", "session", "reverse-delete", "best-effort-reverse-delete"}
DIRECT_RUNTIME_IMAGE_SERVICES = {
    "gvmd": ("gvmd", "configure-direct-openvasd"),
    "vulnerability-tests": ("vulnerability-tests",),
    "data-objects": ("data-objects",),
    "report-formats": ("report-formats",),
    "gpg-data": ("gpg-data",),
    "notus-data": ("notus-data",),
    "pg-gvm-migrator": ("pg-gvm-migrator",),
    "pg-gvm": ("pg-gvm",),
    "scenario-proxy": ("openvasd-scenario-proxy",),
    "e2e-target": ("e2e-target",),
}
REAL_RUNTIME_IMAGE_SERVICES = {
    "real-openvasd": ("configure-openvas", "openvasd-backend"),
}


class EvidenceError(ValueError):
    """Raised when checked-in E2E evidence violates its versioned contract."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot load {path.relative_to(REPOSITORY_ROOT)}: {error}") from error


def expect_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{context} must be an object")
    return value


def expect_keys(
    value: dict[str, Any],
    required: set[str],
    context: str,
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise EvidenceError(f"{context} is missing keys: {sorted(missing)}")
    if unknown:
        raise EvidenceError(f"{context} has unknown keys: {sorted(unknown)}")


def expect_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{context} must be a non-empty string")
    return value


def expect_string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise EvidenceError(f"{context} must be a non-empty array")
    result = [expect_string(item, f"{context}[]") for item in value]
    if len(result) != len(set(result)):
        raise EvidenceError(f"{context} must not contain duplicates")
    return result


def compose_service_images(path: Path) -> dict[str, str]:
    """Read the image assigned to each service without accepting unstructured drift."""

    images: dict[str, str] = {}
    current_service: str | None = None
    in_services = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "services:":
            in_services = True
            continue
        if not in_services:
            continue
        service = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
        if service:
            current_service = service.group(1)
            continue
        image = re.fullmatch(r"    image: (\S+)", line)
        if image and current_service:
            if current_service in images:
                raise EvidenceError(f"Compose service {current_service!r} declares multiple images")
            images[current_service] = image.group(1)
    return images


def validate_compose_runtime_images(
    runtime_images: dict[str, str],
    emulator_image: str,
    direct_compose_path: Path = REPOSITORY_ROOT / "tests" / "e2e" / "compose.direct-openvasd.yaml",
    real_compose_path: Path = REPOSITORY_ROOT / "tests" / "e2e" / "compose.real-openvasd.yaml",
) -> None:
    """Keep every runtime service's immutable Compose reference equal to its manifest pin."""

    direct_images = compose_service_images(direct_compose_path)
    real_images = compose_service_images(real_compose_path)
    direct_expected = {
        **{
            service: runtime_images[name]
            for name, services in DIRECT_RUNTIME_IMAGE_SERVICES.items()
            for service in services
        },
        "openvasd-backend": emulator_image,
    }
    real_expected = {
        **{
            service: runtime_images[name]
            for name, services in REAL_RUNTIME_IMAGE_SERVICES.items()
            for service in services
        },
    }
    for compose_name, declared, expected in (
        ("direct", direct_images, direct_expected),
        ("real", real_images, real_expected),
    ):
        for service, image in expected.items():
            if declared.get(service) != image:
                raise EvidenceError(
                    f"{compose_name} Compose service {service!r} image does not match its "
                    "pinned runtime manifest entry"
                )


def discover_rust_tests(repository_root: Path = REPOSITORY_ROOT) -> dict[str, dict[str, Any]]:
    """Discover Rust tests from attributes so inventory drift fails closed."""

    crate_root = repository_root / "tests" / "e2e"
    discovered: dict[str, dict[str, Any]] = {}
    function_pattern = re.compile(r"(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")

    for source_path in sorted(crate_root.rglob("*.rs")):
        attributes: list[str] = []
        for line_number, line in enumerate(source_path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#["):
                attributes.append(stripped)
                continue

            match = function_pattern.match(stripped)
            if match:
                is_test = any(
                    attribute == "#[test]" or attribute.startswith("#[tokio::test")
                    for attribute in attributes
                )
                if is_test:
                    relative = source_path.relative_to(repository_root).as_posix()
                    test_id = f"{relative}::{match.group(1)}"
                    if test_id in discovered:
                        raise EvidenceError(f"duplicate discovered Rust test: {test_id}")
                    discovered[test_id] = {
                        "source": relative,
                        "name": match.group(1),
                        "ignored": any(attribute.startswith("#[ignore") for attribute in attributes),
                        "line": line_number,
                    }
                attributes = []
            elif stripped and not stripped.startswith("//"):
                attributes = []

    return discovered


def validate_owners(document: Any) -> dict[str, dict[str, Any]]:
    root = expect_object(document, "owners")
    expect_keys(root, {"schemaVersion", "roles"}, "owners")
    if root["schemaVersion"] != 1:
        raise EvidenceError("owners.schemaVersion must equal 1")
    roles = expect_object(root["roles"], "owners.roles")
    if not roles:
        raise EvidenceError("owners.roles must not be empty")

    for name, raw_role in roles.items():
        expect_string(name, "owners.roles key")
        role = expect_object(raw_role, f"owners.roles.{name}")
        expect_keys(role, {"accountable", "consulted", "responsibilities", "escalation"}, f"owners.roles.{name}")
        accountable = expect_string(role["accountable"], f"owners.roles.{name}.accountable")
        if not accountable.startswith("@greenbone/"):
            raise EvidenceError(f"owners.roles.{name}.accountable must name a Greenbone team")
        consulted = role["consulted"]
        if not isinstance(consulted, list) or any(
            not isinstance(team, str) or not team.startswith("@greenbone/") for team in consulted
        ):
            raise EvidenceError(f"owners.roles.{name}.consulted must contain Greenbone teams")
        expect_string_list(role["responsibilities"], f"owners.roles.{name}.responsibilities")
        expect_string(role["escalation"], f"owners.roles.{name}.escalation")
    return roles


def validate_inventory(
    document: Any,
    owners: dict[str, dict[str, Any]],
    repository_root: Path = REPOSITORY_ROOT,
) -> set[str]:
    root = expect_object(document, "contract inventory")
    expect_keys(
        root,
        {
            "schemaVersion",
            "generatedFrom",
            "ownerRoles",
            "contractOwners",
            "dependencyOwners",
            "dependencyKinds",
            "tests",
        },
        "contract inventory",
    )
    if root["schemaVersion"] != 1:
        raise EvidenceError("contract inventory schemaVersion must equal 1")

    generated_from = expect_object(root["generatedFrom"], "contract inventory.generatedFrom")
    expect_keys(generated_from, {"crate", "sourceRoots", "discovery"}, "contract inventory.generatedFrom")
    if generated_from["crate"] != "gvm-gateway-e2e":
        raise EvidenceError("contract inventory must describe gvm-gateway-e2e")
    source_roots = expect_string_list(generated_from["sourceRoots"], "contract inventory.generatedFrom.sourceRoots")
    if set(source_roots) != {"tests/e2e/src", "tests/e2e/tests"}:
        raise EvidenceError("contract inventory sourceRoots must cover helper and live test roots")
    expect_string(generated_from["discovery"], "contract inventory.generatedFrom.discovery")

    owner_roles = expect_string_list(root["ownerRoles"], "contract inventory.ownerRoles")
    if set(owner_roles) != set(owners):
        raise EvidenceError("contract inventory ownerRoles must exactly match owners.json")

    ownership_registries: dict[str, dict[str, str]] = {}
    for registry_name in ("contractOwners", "dependencyOwners"):
        registry = expect_object(root[registry_name], f"contract inventory.{registry_name}")
        if not registry:
            raise EvidenceError(f"contract inventory.{registry_name} must not be empty")
        for item_name, owner_role in registry.items():
            expect_string(item_name, f"contract inventory.{registry_name} key")
            if owner_role not in owners:
                raise EvidenceError(
                    f"contract inventory.{registry_name}.{item_name} is not defined in owners.json"
                )
        ownership_registries[registry_name] = registry

    dependency_kinds = expect_object(
        root["dependencyKinds"], "contract inventory.dependencyKinds"
    )
    for dependency_name, dependency_kind in dependency_kinds.items():
        expect_string(dependency_name, "contract inventory.dependencyKinds key")
        if dependency_kind not in DEPENDENCY_KINDS:
            raise EvidenceError(
                f"contract inventory.dependencyKinds.{dependency_name} is invalid"
            )

    raw_tests = root["tests"]
    if not isinstance(raw_tests, list) or not raw_tests:
        raise EvidenceError("contract inventory.tests must be a non-empty array")
    inventory: dict[str, dict[str, Any]] = {}
    for index, raw_test in enumerate(raw_tests):
        context = f"contract inventory.tests[{index}]"
        test = expect_object(raw_test, context)
        expect_keys(
            test,
            {
                "id",
                "source",
                "kind",
                "ignored",
                "contracts",
                "dependencies",
                "featureFlags",
                "scannerPortability",
                "ospDisposition",
                "state",
                "artifacts",
                "ownerRole",
            },
            context,
        )
        test_id = expect_string(test["id"], f"{context}.id")
        if test_id in inventory:
            raise EvidenceError(f"duplicate inventory test id: {test_id}")
        inventory[test_id] = test
        source = expect_string(test["source"], f"{context}.source")
        if not (repository_root / source).is_file():
            raise EvidenceError(f"{context}.source does not exist: {source}")
        if test["kind"] not in TEST_KINDS:
            raise EvidenceError(f"{context}.kind is invalid")
        if not isinstance(test["ignored"], bool):
            raise EvidenceError(f"{context}.ignored must be boolean")
        contracts = expect_string_list(test["contracts"], f"{context}.contracts")
        for contract in contracts:
            prefix = contract.split(".", 1)[0]
            if prefix not in CONTRACT_PREFIXES:
                raise EvidenceError(f"{context}.contracts contains an unknown contract layer")
        dependencies = expect_string_list(test["dependencies"], f"{context}.dependencies")
        feature_flags = test["featureFlags"]
        if not isinstance(feature_flags, list) or any(
            not isinstance(flag, str) or not flag.strip() for flag in feature_flags
        ):
            raise EvidenceError(f"{context}.featureFlags must be a string array")
        if len(feature_flags) != len(set(feature_flags)):
            raise EvidenceError(f"{context}.featureFlags must not contain duplicates")
        if "gvmd" in dependencies and not any(contract.startswith("gmp.") for contract in contracts):
            raise EvidenceError(f"{context} must name the GMP contract exercised through gvmd")
        if "osp-scanner-path" in dependencies and not any(
            contract.startswith("scanner.") for contract in contracts
        ):
            raise EvidenceError(f"{context} must name the scanner contract exercised through OSP")
        if test["scannerPortability"] not in SCANNER_PORTABILITY:
            raise EvidenceError(f"{context}.scannerPortability is invalid")
        if test["ospDisposition"] not in OSP_DISPOSITIONS:
            raise EvidenceError(f"{context}.ospDisposition is invalid")
        if test["scannerPortability"] == "osp-specific" and test["ospDisposition"] == "not-applicable":
            raise EvidenceError(f"{context} must disposition an OSP-specific contract")
        if "osp-scanner-path" in dependencies and test["ospDisposition"] == "not-applicable":
            raise EvidenceError(f"{context} must disposition its OSP scanner dependency")
        state = expect_object(test["state"], f"{context}.state")
        expect_keys(state, {"setup", "isolation", "cleanup"}, f"{context}.state")
        if state["setup"] not in SETUP_KINDS:
            raise EvidenceError(f"{context}.state.setup is invalid")
        if state["isolation"] not in ISOLATION_KINDS:
            raise EvidenceError(f"{context}.state.isolation is invalid")
        if state["cleanup"] not in CLEANUP_KINDS:
            raise EvidenceError(f"{context}.state.cleanup is invalid")
        expect_string_list(test["artifacts"], f"{context}.artifacts")
        if test["ownerRole"] not in owners:
            raise EvidenceError(f"{context}.ownerRole is not defined in owners.json")

    discovered = discover_rust_tests(repository_root)
    missing = discovered.keys() - inventory.keys()
    stale = inventory.keys() - discovered.keys()
    if missing or stale:
        raise EvidenceError(
            "contract inventory/source mismatch: "
            f"missing={sorted(missing)} stale={sorted(stale)}"
        )
    for test_id, source_test in discovered.items():
        entry = inventory[test_id]
        if entry["source"] != source_test["source"]:
            raise EvidenceError(f"{test_id} source path does not match discovery")
        if entry["ignored"] != source_test["ignored"]:
            raise EvidenceError(f"{test_id} ignored state does not match source")
        # The integration-test targets also contain four non-live helper tests;
        # ignored state, not file placement alone, identifies compose-backed cases.
        expected_kind = "live" if source_test["ignored"] else "helper"
        if entry["kind"] != expected_kind:
            raise EvidenceError(f"{test_id} kind must be {expected_kind}")

    referenced_contracts = {name for test in inventory.values() for name in test["contracts"]}
    referenced_dependencies = {name for test in inventory.values() for name in test["dependencies"]}
    referenced_feature_flags = {name for test in inventory.values() for name in test["featureFlags"]}
    referenced_owned_dependencies = referenced_dependencies | referenced_feature_flags
    for registry_name, referenced in (
        ("contractOwners", referenced_contracts),
        ("dependencyOwners", referenced_owned_dependencies),
    ):
        registered = set(ownership_registries[registry_name])
        if registered != referenced:
            raise EvidenceError(
                f"contract inventory.{registry_name} must exactly cover referenced names: "
                f"missing={sorted(referenced - registered)} stale={sorted(registered - referenced)}"
            )
    registered_dependency_kinds = set(dependency_kinds)
    if registered_dependency_kinds != referenced_owned_dependencies:
        raise EvidenceError(
            "contract inventory.dependencyKinds must exactly cover referenced names: "
            f"missing={sorted(referenced_owned_dependencies - registered_dependency_kinds)} "
            f"stale={sorted(registered_dependency_kinds - referenced_owned_dependencies)}"
        )
    for flag in referenced_feature_flags:
        if dependency_kinds[flag] != "feature-flag":
            raise EvidenceError(f"contract inventory.dependencyKinds.{flag} must be feature-flag")
    return referenced_contracts


def validate_provenance(document: Any, context: str = "provenance") -> None:
    root = expect_object(document, context)
    expect_keys(
        root,
        {
            "schemaVersion",
            "gateway",
            "gvmd",
            "scanner",
            "feedData",
            "fixtures",
            "apiContract",
            "composeSha256",
            "runner",
            "harnessRevision",
        },
        context,
    )
    if root["schemaVersion"] != 1:
        raise EvidenceError(f"{context}.schemaVersion must equal 1")
    for component_name in ("gateway", "gvmd", "scanner"):
        component = expect_object(root[component_name], f"{context}.{component_name}")
        expect_keys(component, {"sourceRevision", "image", "imageDigest"}, f"{context}.{component_name}")
        for field in component:
            expect_string(component[field], f"{context}.{component_name}.{field}")
    for collection_name in ("feedData", "fixtures"):
        collection = root[collection_name]
        if not isinstance(collection, list) or not collection:
            raise EvidenceError(f"{context}.{collection_name} must be a non-empty array")
        for index, raw_item in enumerate(collection):
            item = expect_object(raw_item, f"{context}.{collection_name}[{index}]")
            expect_keys(item, {"name", "revision"}, f"{context}.{collection_name}[{index}]")
            expect_string(item["name"], f"{context}.{collection_name}[{index}].name")
            expect_string(item["revision"], f"{context}.{collection_name}[{index}].revision")
    api_contract = expect_object(root["apiContract"], f"{context}.apiContract")
    expect_keys(api_contract, {"name", "revision"}, f"{context}.apiContract")
    if api_contract["name"] != "spec/rest-api/openapi.yaml":
        raise EvidenceError(f"{context}.apiContract.name must identify the curated OpenAPI document")
    expect_string(api_contract["revision"], f"{context}.apiContract.revision")
    expect_string(root["composeSha256"], f"{context}.composeSha256")
    runner = expect_object(root["runner"], f"{context}.runner")
    expect_keys(runner, {"os", "architecture", "image"}, f"{context}.runner")
    for field in runner:
        expect_string(runner[field], f"{context}.runner.{field}")
    expect_string(root["harnessRevision"], f"{context}.harnessRevision")


def validate_comparison(
    document: Any,
    owners: dict[str, dict[str, Any]],
    known_contracts: set[str],
) -> None:
    root = expect_object(document, "comparison")
    expect_keys(root, {"schemaVersion", "baselineLane", "candidateLane", "contracts"}, "comparison")
    if root["schemaVersion"] != 1:
        raise EvidenceError("comparison.schemaVersion must equal 1")
    expect_string(root["baselineLane"], "comparison.baselineLane")
    expect_string(root["candidateLane"], "comparison.candidateLane")
    contracts = root["contracts"]
    if not isinstance(contracts, list) or not contracts:
        raise EvidenceError("comparison.contracts must be a non-empty array")
    seen: set[str] = set()
    for index, raw_contract in enumerate(contracts):
        context = f"comparison.contracts[{index}]"
        contract = expect_object(raw_contract, context)
        expect_keys(contract, {"contract", "baseline", "candidate", "disposition", "ownerRole"}, context)
        name = expect_string(contract["contract"], f"{context}.contract")
        if name in seen:
            raise EvidenceError(f"duplicate comparison contract: {name}")
        seen.add(name)
        if name not in known_contracts:
            raise EvidenceError(f"{context}.contract is not present in the contract inventory")
        if contract["baseline"] not in {"pass", "fail", "not-run"}:
            raise EvidenceError(f"{context}.baseline is invalid")
        if contract["candidate"] not in {"pass", "fail", "not-run"}:
            raise EvidenceError(f"{context}.candidate is invalid")
        if contract["disposition"] not in {"equivalent", "backend-specific", "gap", "approved-exclusion"}:
            raise EvidenceError(f"{context}.disposition is invalid")
        owner_role = expect_string(contract["ownerRole"], f"{context}.ownerRole")
        if owner_role not in owners:
            raise EvidenceError(f"{context}.ownerRole is not defined in owners.json")


def validate_fault_mappings(document: Any, require_complete: bool = True) -> None:
    root = expect_object(document, "fault mappings")
    expect_keys(root, {"schemaVersion", "lane", "scenarios"}, "fault mappings")
    if root["schemaVersion"] != 1:
        raise EvidenceError("fault mappings.schemaVersion must equal 1")
    if root["lane"] != "community-direct-openvasd-shadow":
        raise EvidenceError("fault mappings.lane must identify the advisory shadow lane")
    scenarios = root["scenarios"]
    if not isinstance(scenarios, list):
        raise EvidenceError("fault mappings.scenarios must be an array")
    expected = {"http-400", "http-500", "malformed-body", "malformed-header", "timeout"}
    seen: set[str] = set()
    for index, raw_scenario in enumerate(scenarios):
        context = f"fault mappings.scenarios[{index}]"
        scenario = expect_object(raw_scenario, context)
        expect_keys(
            scenario,
            {"scenario", "injectedAt", "gatewayMapping", "target", "outcome"},
            context,
        )
        name = expect_string(scenario["scenario"], f"{context}.scenario")
        if name not in expected or name in seen:
            raise EvidenceError(f"{context}.scenario is unknown or duplicated")
        seen.add(name)
        if scenario["injectedAt"] != "openvasd-http-boundary":
            raise EvidenceError(f"{context}.injectedAt must identify the scanner HTTP boundary")
        expect_string(scenario["gatewayMapping"], f"{context}.gatewayMapping")
        expect_string(scenario["target"], f"{context}.target")
        if scenario["outcome"] not in {"pass", "fail"}:
            raise EvidenceError(f"{context}.outcome is invalid")
    if require_complete and seen != expected:
        raise EvidenceError(f"fault mappings must cover every named scenario: missing={sorted(expected - seen)}")


def validate_direct_pins(document: Any) -> None:
    root = expect_object(document, "direct OpenVASD pins")
    expect_keys(root, {"schemaVersion", "emulator", "runtimeImages", "identities", "runner"}, "direct OpenVASD pins")
    if root["schemaVersion"] != 1:
        raise EvidenceError("direct OpenVASD pins.schemaVersion must equal 1")
    emulator = expect_object(root["emulator"], "direct OpenVASD pins.emulator")
    expect_keys(
        emulator,
        {
            "sourceRepository",
            "sourceRevision",
            "image",
            "openapiRevision",
            "openapiSha256",
            "fixtureRevision",
            "files",
        },
        "direct OpenVASD pins.emulator",
    )
    for field in ("sourceRepository", "sourceRevision", "image", "openapiRevision", "openapiSha256", "fixtureRevision"):
        expect_string(emulator[field], f"direct OpenVASD pins.emulator.{field}")
    if emulator["sourceRepository"] != "greenbone/gvm-openapi-emulator":
        raise EvidenceError("emulator sourceRepository must identify the upstream Phase 1 repository")
    if not re.fullmatch(r"[0-9a-f]{40}", emulator["sourceRevision"]):
        raise EvidenceError("emulator sourceRevision must be a full commit SHA")
    if not re.fullmatch(r"[0-9a-f]{40}", emulator["openapiRevision"]):
        raise EvidenceError("emulator openapiRevision must be a full commit SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", emulator["openapiSha256"]):
        raise EvidenceError("emulator openapiSha256 must be an exact SHA-256")
    if not re.search(r"@sha256:[0-9a-f]{64}$", emulator["image"]):
        raise EvidenceError("emulator image must be pinned by digest")
    files = expect_object(emulator["files"], "direct OpenVASD pins.emulator.files")
    expected_files = {
        "sample/scans/GET.json",
        "sample/scans/POST.json",
        "sample/scans/preferences/GET.json",
        "sample/scans/{id}/results/GET.json",
        "sample/scans/{id}/status/GET.requested.json",
        "sample/scans/{id}/status/GET.running.1.json",
        "sample/scans/{id}/status/GET.running.2.json",
        "sample/scans/{id}/status/GET.running.3.json",
        "sample/scans/{id}/status/GET.running.4.json",
        "sample/scans/{id}/status/GET.succeeded.json",
        "sample/scans/{id}/status/scenario.json",
        "sample/scans/{id}/status/scenario.time.json",
        "sample/vts/GET.json",
        "swagger.json",
    }
    if set(files) != expected_files:
        raise EvidenceError("emulator files must exactly cover the Phase 1 OpenVASD fixture set")
    if files.get("swagger.json") != emulator["openapiSha256"]:
        raise EvidenceError("pinned swagger.json must match openapiSha256")
    for name, digest in files.items():
        if name.startswith("/") or ".." in Path(name).parts:
            raise EvidenceError(f"unsafe emulator fixture path: {name}")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise EvidenceError(f"emulator fixture {name} must have an exact SHA-256")

    runtime_images = expect_object(root["runtimeImages"], "direct OpenVASD pins.runtimeImages")
    expected_images = {
        "gvmd",
        "vulnerability-tests",
        "data-objects",
        "report-formats",
        "gpg-data",
        "notus-data",
        "pg-gvm-migrator",
        "pg-gvm",
        "scenario-proxy",
        "e2e-target",
        "real-openvasd",
    }
    if set(runtime_images) != expected_images:
        raise EvidenceError("direct OpenVASD runtimeImages must exactly cover the lane topology")
    for name, image in runtime_images.items():
        expect_string(name, "direct OpenVASD runtimeImages key")
        if not isinstance(image, str) or not re.search(r"@sha256:[0-9a-f]{64}$", image):
            raise EvidenceError(f"runtime image {name} must be pinned by digest")

    identities = expect_object(root["identities"], "direct OpenVASD pins.identities")
    expect_keys(identities, {"scannerBackend", "syntheticTarget"}, "direct OpenVASD pins.identities")
    backend = expect_string(identities["scannerBackend"], "direct OpenVASD pins.identities.scannerBackend")
    target = expect_string(identities["syntheticTarget"], "direct OpenVASD pins.identities.syntheticTarget")
    if backend == target:
        raise EvidenceError("scanner backend and synthetic target identities must differ")
    runner = expect_object(root["runner"], "direct OpenVASD pins.runner")
    expect_keys(runner, {"label", "rust"}, "direct OpenVASD pins.runner")
    expect_string(runner["label"], "direct OpenVASD pins.runner.label")
    expect_string(runner["rust"], "direct OpenVASD pins.runner.rust")

    compose_text = (REPOSITORY_ROOT / "tests" / "e2e" / "compose.direct-openvasd.yaml").read_text(encoding="utf-8")
    validate_compose_runtime_images(runtime_images, emulator["image"])
    for identity in (backend, target):
        if f"  {identity}:" not in compose_text:
            raise EvidenceError(f"pinned identity {identity} is not a Compose service")
    if f"--scanner-host={backend}" not in compose_text:
        raise EvidenceError("direct Compose scanner configuration does not use the pinned backend identity")

    workflows = (
        (REPOSITORY_ROOT / ".github" / "workflows" / "nightly-e2e.yml").read_text(encoding="utf-8"),
        (REPOSITORY_ROOT / ".github" / "workflows" / "real-openvasd-compatibility.yml").read_text(encoding="utf-8"),
    )
    for workflow in workflows:
        if f"runs-on: {runner['label']}" not in workflow:
            raise EvidenceError("an OpenVASD workflow does not use the pinned runner label")
        if f'rust-version: "{runner["rust"]}"' not in workflow:
            raise EvidenceError("an OpenVASD workflow does not use the pinned Rust toolchain")


def nearest_rank(values: list[float], percentile: float) -> float:
    if not values:
        raise EvidenceError("cannot calculate a percentile for an empty list")
    ordered = sorted(values)
    return ordered[math.ceil(percentile * len(ordered)) - 1]


def validate_run(raw_run: Any, index: int) -> dict[str, Any]:
    context = f"baseline.runs[{index}]"
    run = expect_object(raw_run, context)
    expect_keys(
        run,
        {
            "runId",
            "runAttempt",
            "runNumber",
            "event",
            "headBranch",
            "headSha",
            "createdAt",
            "runUrl",
            "jobId",
            "jobUrl",
            "conclusion",
            "timingsSeconds",
            "retried",
            "artifacts",
            "failureClassification",
            "failureOwnerRole",
        },
        context,
    )
    for field in ("runId", "runAttempt", "runNumber", "jobId"):
        if not isinstance(run[field], int) or run[field] < 1:
            raise EvidenceError(f"{context}.{field} must be a positive integer")
    for field in ("event", "headBranch", "headSha", "createdAt", "runUrl", "jobUrl", "conclusion"):
        expect_string(run[field], f"{context}.{field}")
    if run["conclusion"] not in {"success", "failure", "timed_out"}:
        raise EvidenceError(f"{context}.conclusion is not eligible")
    timings = expect_object(run["timingsSeconds"], f"{context}.timingsSeconds")
    expect_keys(timings, {"startup", "tests", "total"}, f"{context}.timingsSeconds")
    for field, value in timings.items():
        if not isinstance(value, (int, float)) or value < 0:
            raise EvidenceError(f"{context}.timingsSeconds.{field} must be non-negative")
    if timings["total"] < timings["startup"] or timings["total"] < timings["tests"]:
        raise EvidenceError(f"{context}.timingsSeconds.total cannot be shorter than a measured step")
    if not isinstance(run["retried"], bool) or run["retried"] != (run["runAttempt"] > 1):
        raise EvidenceError(f"{context}.retried must match runAttempt")
    artifacts = expect_object(run["artifacts"], f"{context}.artifacts")
    expect_keys(artifacts, {"expected", "present", "complete"}, f"{context}.artifacts")
    expected = expect_string_list(artifacts["expected"], f"{context}.artifacts.expected")
    present = artifacts["present"]
    if not isinstance(present, list) or any(not isinstance(item, str) for item in present):
        raise EvidenceError(f"{context}.artifacts.present must be a string array")
    if len(present) != len(set(present)):
        raise EvidenceError(f"{context}.artifacts.present must not contain duplicates")
    if artifacts["complete"] != set(expected).issubset(present):
        raise EvidenceError(f"{context}.artifacts.complete does not match artifact names")
    failure = run["failureClassification"]
    if run["conclusion"] == "success":
        if failure is not None or run["failureOwnerRole"] is not None:
            raise EvidenceError(
                f"{context}.failureClassification and failureOwnerRole must be null on success"
            )
    elif failure not in FAILURE_CLASSES:
        raise EvidenceError(f"{context}.failureClassification is invalid")
    elif run["failureOwnerRole"] not in {
        "community-contract-lane",
        "promotion-rollback-incident",
    }:
        raise EvidenceError(f"{context}.failureOwnerRole must name a triage owner")
    return run


def validate_baseline(document: Any) -> None:
    root = expect_object(document, "baseline")
    expect_keys(
        root,
        {"schemaVersion", "generatedAt", "repository", "workflow", "job", "eligibility", "summary", "runs"},
        "baseline",
    )
    if root["schemaVersion"] != 1:
        raise EvidenceError("baseline.schemaVersion must equal 1")
    for field in ("generatedAt", "repository", "workflow", "job"):
        expect_string(root[field], f"baseline.{field}")
    if root["repository"] != "greenbone/rust-gvm-api":
        raise EvidenceError("baseline.repository must be greenbone/rust-gvm-api")
    if root["workflow"] != ".github/workflows/nightly-e2e.yml":
        raise EvidenceError("baseline.workflow must identify the current E2E workflow")
    if root["job"] != "REST Discovery Scan E2E":
        raise EvidenceError("baseline.job must identify the existing OSP job")

    eligibility = expect_object(root["eligibility"], "baseline.eligibility")
    expect_keys(eligibility, {"requiredRuns", "selection", "includedConclusions", "excluded", "window"}, "baseline.eligibility")
    if not isinstance(eligibility["requiredRuns"], int) or eligibility["requiredRuns"] < 30:
        raise EvidenceError("baseline.eligibility.requiredRuns must be at least 30")
    expect_string(eligibility["selection"], "baseline.eligibility.selection")
    conclusions = expect_string_list(eligibility["includedConclusions"], "baseline.eligibility.includedConclusions")
    if set(conclusions) != {"success", "failure", "timed_out"}:
        raise EvidenceError("baseline eligibility must include terminal executed conclusions")
    expect_string_list(eligibility["excluded"], "baseline.eligibility.excluded")
    window = expect_object(eligibility["window"], "baseline.eligibility.window")
    expect_keys(window, {"oldestCreatedAt", "newestCreatedAt"}, "baseline.eligibility.window")
    expect_string(window["oldestCreatedAt"], "baseline.eligibility.window.oldestCreatedAt")
    expect_string(window["newestCreatedAt"], "baseline.eligibility.window.newestCreatedAt")

    raw_runs = root["runs"]
    if not isinstance(raw_runs, list) or len(raw_runs) < eligibility["requiredRuns"]:
        raise EvidenceError("baseline.runs does not meet requiredRuns")
    runs = [validate_run(raw_run, index) for index, raw_run in enumerate(raw_runs)]
    run_ids = [run["runId"] for run in runs]
    if len(run_ids) != len(set(run_ids)):
        raise EvidenceError("baseline.runs contains duplicate run IDs")

    summary = expect_object(root["summary"], "baseline.summary")
    expect_keys(
        summary,
        {
            "eligibleRuns",
            "passedRuns",
            "failedRuns",
            "timedOutRuns",
            "passRate",
            "failureRate",
            "retryRate",
            "unexplainedFlakeRate",
            "artifactCompletenessRate",
            "startupSeconds",
            "testSeconds",
            "totalSeconds",
        },
        "baseline.summary",
    )
    count = len(runs)
    passed = sum(run["conclusion"] == "success" for run in runs)
    failed = sum(run["conclusion"] == "failure" for run in runs)
    timed_out = sum(run["conclusion"] == "timed_out" for run in runs)
    retried = sum(run["retried"] for run in runs)
    flakes = sum(run["failureClassification"] == "unexplained-flake" for run in runs)
    complete = sum(run["artifacts"]["complete"] for run in runs)
    exact_counts = {
        "eligibleRuns": count,
        "passedRuns": passed,
        "failedRuns": failed,
        "timedOutRuns": timed_out,
    }
    for field, expected in exact_counts.items():
        if summary[field] != expected:
            raise EvidenceError(f"baseline.summary.{field} must equal {expected}")
    exact_rates = {
        "passRate": passed / count,
        "failureRate": (failed + timed_out) / count,
        "retryRate": retried / count,
        "unexplainedFlakeRate": flakes / count,
        "artifactCompletenessRate": complete / count,
    }
    for field, expected in exact_rates.items():
        if summary[field] != expected:
            raise EvidenceError(f"baseline.summary.{field} must equal {expected}")

    for field, run_field in (
        ("startupSeconds", "startup"),
        ("testSeconds", "tests"),
        ("totalSeconds", "total"),
    ):
        metric = expect_object(summary[field], f"baseline.summary.{field}")
        expect_keys(metric, {"p50", "p95", "min", "max"}, f"baseline.summary.{field}")
        values = [float(run["timingsSeconds"][run_field]) for run in runs]
        expected_metric = {
            "p50": statistics.median(values),
            "p95": nearest_rank(values, 0.95),
            "min": min(values),
            "max": max(values),
        }
        if metric != expected_metric:
            raise EvidenceError(f"baseline.summary.{field} does not match run evidence")


def validate_schema_documents() -> None:
    required_schemas = {
        "contract-inventory.schema.json",
        "fault-mappings.schema.json",
        "provenance.schema.json",
        "comparison.schema.json",
        "run-evidence.schema.json",
        "shadow-observation.schema.json",
    }
    found = {path.name for path in (EVIDENCE_ROOT / "schemas").glob("*.json")}
    if found != required_schemas:
        raise EvidenceError(f"schema set mismatch: expected={sorted(required_schemas)} found={sorted(found)}")
    for name in sorted(required_schemas):
        schema = expect_object(load_json(EVIDENCE_ROOT / "schemas" / name), f"schema {name}")
        expect_keys(
            schema,
            {"$schema", "$id", "title", "type", "additionalProperties", "required", "properties"},
            f"schema {name}",
            optional={"$defs"},
        )
        if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema":
            raise EvidenceError(f"schema {name} must use JSON Schema 2020-12")
        if schema["type"] != "object" or schema["additionalProperties"] is not False:
            raise EvidenceError(f"schema {name} must be a closed object")


def validate_all(repository_root: Path = REPOSITORY_ROOT) -> None:
    validate_schema_documents()
    owners = validate_owners(load_json(OWNERS_PATH))
    validate_direct_pins(load_json(DIRECT_PINS_PATH))
    known_contracts = validate_inventory(load_json(INVENTORY_PATH), owners, repository_root)
    validate_provenance(load_json(EVIDENCE_ROOT / "examples" / "provenance.json"))
    validate_comparison(
        load_json(EVIDENCE_ROOT / "examples" / "comparison.json"),
        owners,
        known_contracts,
    )
    validate_baseline(load_json(BASELINE_PATH))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        validate_all()
    except EvidenceError as error:
        parser.error(str(error))
    discovered = discover_rust_tests()
    print(f"validated E2E evidence and {len(discovered)} inventoried Rust tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
