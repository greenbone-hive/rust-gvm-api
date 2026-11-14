#!/usr/bin/env python3
"""Reject incomplete or drifting exact-source Agent Control inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / "tests" / "e2e" / "evidence" / "enterprise-agent-control-pins.json"


def fail(message: str) -> None:
    raise SystemExit(f"enterprise Agent Control input validation failed: {message}")


def source_archive_sha256(source: Path) -> str:
    result = subprocess.run(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=source,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return hashlib.sha256(result.stdout).hexdigest()


def tree_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        digest.update(item.relative_to(path).as_posix().encode())
        digest.update(b"\0")
        digest.update(item.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def git_output(source: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=source, check=True, text=True, capture_output=True
    ).stdout.strip()


def validate_source(source: Path, pins: dict[str, object]) -> dict[str, str]:
    expected_source = pins["sourceBuildWorkaround"]
    expected_agent = pins["agentControl"]
    revision = git_output(source, "rev-parse", "HEAD")
    if revision != expected_source["revision"]:
        fail(f"source revision drifted: expected {expected_source['revision']}, got {revision}")
    if git_output(source, "status", "--porcelain"):
        fail("source checkout is not clean")
    dockerfile = source / expected_source["dockerfile"]
    fixture_root = source / expected_agent["fixtureDirectory"]
    swagger = fixture_root / "swagger.json"
    if not dockerfile.is_file() or not swagger.is_file():
        fail("pinned Dockerfile or examples/agent-folder/swagger.json is absent")
    identities = {
        "gitTree": git_output(source, "rev-parse", "HEAD^{tree}"),
        "sourceArchiveSha256": source_archive_sha256(source),
        "dockerfileSha256": hashlib.sha256(dockerfile.read_bytes()).hexdigest(),
        "fixtureTreeSha256": tree_sha256(fixture_root),
        "swaggerSha256": hashlib.sha256(swagger.read_bytes()).hexdigest(),
    }
    for key in ("gitTree", "sourceArchiveSha256", "dockerfileSha256"):
        if identities[key] != expected_source[key]:
            fail(f"source {key} differs from the checked-in exact pin")
    for key in ("fixtureTreeSha256", "swaggerSha256"):
        if identities[key] != expected_agent[key]:
            fail(f"Agent Control {key} differs from the checked-in exact pin")
    api_input = subprocess.run(
        ["git", "cat-file", "blob", expected_agent["apiRevision"]],
        cwd=source,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    identities["apiInputSha256"] = hashlib.sha256(api_input).hexdigest()
    if identities["apiInputSha256"] != expected_agent["apiInputSha256"]:
        fail("upstream Agent Control API input object SHA-256 differs from the exact pin")
    swagger_document = json.loads(swagger.read_text(encoding="utf-8"))
    info = swagger_document.get("info", {})
    if info.get("x-upstream-openapi-revision") != expected_agent["apiRevision"]:
        fail("swagger API revision differs from the checked-in exact pin")
    if info.get("x-emulator-fixture-revision") != expected_agent["fixtureRevision"]:
        fail("swagger fixture revision differs from the checked-in exact pin")
    contract = pins.get("realCompatibilityContract")
    if not isinstance(contract, dict):
        fail("real compatibility wire-contract pin is absent")
    paths = swagger_document.get("paths", {})
    inventory_path = contract.get("inventoryPath")
    inventory_schema = (
        paths.get(inventory_path, {})
        .get("get", {})
        .get("responses", {})
        .get("200", {})
        .get("schema", {})
    )
    if contract.get("inventoryResponseShape") != "raw-array" or inventory_schema.get("type") != "array":
        fail("pinned inventory path is not a raw-array response in the exact Swagger")
    installer_path = contract.get("installerInstructionsPath")
    installer_parameters = (
        paths.get(installer_path, {}).get("get", {}).get("parameters", [])
    )
    installer_query_names = {
        item.get("name")
        for item in installer_parameters
        if isinstance(item, dict) and item.get("in") == "query"
    }
    if installer_query_names != {
        contract.get("installerLanguageParameter"),
        contract.get("installerOriginParameter"),
    } or "language" in installer_query_names:
        fail("installer query pins differ from the exact Swagger")
    profile_document = (source / "docs/AGENT_CONTROL_PROFILE.md").read_text(encoding="utf-8")
    backend_source = (source / "internal/agentcontrol/backend.go").read_text(encoding="utf-8")
    expected_pagination = {
        "paginationQuery": {"page": "page", "perPage": "per_page"},
        "paginationHeaders": {
            "totalCount": "x-total-count",
            "page": "x-page",
            "perPage": "x-per-page",
        },
    }
    for key, expected in expected_pagination.items():
        if contract.get(key) != expected:
            fail(f"real compatibility {key} pin drifted")
    for token in ("x-total-count", "x-page", "x-per-page", '"per_page"'):
        if token not in profile_document and token not in backend_source:
            fail(f"exact source does not implement pinned pagination token {token}")
    return identities


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="validate the exact checkout and fixture identities without Docker inputs",
    )
    args = parser.parse_args()
    pins = json.loads(PINS.read_text(encoding="utf-8"))
    source = (args.source or Path(os.environ["GVM_GATEWAY_E2E_AGENT_CONTROL_SOURCE"])).resolve()
    identities = validate_source(source, pins)
    if args.source_only:
        print(json.dumps({"status": "passed", "source": str(source), **identities}, sort_keys=True))
        return 0
    manifest_path = Path(os.environ["GVM_GATEWAY_E2E_AGENT_CONTROL_BUILD_MANIFEST"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_source = pins["sourceBuildWorkaround"]
    expected_agent = pins["agentControl"]
    if manifest.get("schemaVersion") != 1:
        fail("build manifest schemaVersion must be 1")
    manifest_source = manifest.get("source", {})
    if (
        manifest_source.get("repository") != expected_source["repository"]
        or manifest_source.get("revision") != expected_source["revision"]
    ):
        fail("source repository or commit does not match the checked-in pin")
    if manifest.get("profile") != expected_agent["profile"]:
        fail("profile does not match the checked-in pin")
    if manifest.get("apiRevision") != expected_agent["apiRevision"]:
        fail("API revision does not match the checked-in pin")
    if manifest.get("fixtureRevision") != expected_agent["fixtureRevision"]:
        fail("fixture revision does not match the checked-in pin")
    if manifest.get("build", {}).get("dockerfileSha256") != identities["dockerfileSha256"]:
        fail("Dockerfile SHA-256 differs from the exact build manifest")
    image = os.environ["GVM_GATEWAY_E2E_AGENT_CONTROL_IMAGE"]
    if manifest.get("image", {}).get("reference") != image or not re.fullmatch(
        r".+@sha256:[0-9a-f]{64}", image
    ):
        fail("runtime image is not the manifest's immutable repository digest")
    if manifest_source.get("gitTree") != identities["gitTree"]:
        fail("source Git tree differs from the exact build manifest")
    if manifest_source.get("archiveSha256") != identities["sourceArchiveSha256"]:
        fail("source archive SHA-256 differs from the exact build manifest")
    if manifest.get("fixtureTreeSha256") != identities["fixtureTreeSha256"]:
        fail("fixture tree SHA-256 differs from the exact build manifest")
    if manifest.get("swaggerSha256") != identities["swaggerSha256"]:
        fail("swagger SHA-256 differs from the exact build manifest")
    if manifest.get("apiInputSha256") != identities["apiInputSha256"]:
        fail("upstream API input SHA-256 differs from the exact build manifest")
    print("validated exact-source Agent Control emulator inputs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
