#!/usr/bin/env python3
"""Capture exact independent provenance for the additive enterprise emulator lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DIRECT_PINS = ROOT / "tests/e2e/evidence/direct-openvasd-pins.json"
ENTERPRISE_PINS = ROOT / "tests/e2e/evidence/enterprise-agent-control-pins.json"
COMPOSE = [
    ROOT / "tests/e2e/compose.direct-openvasd.yaml",
    ROOT / "tests/e2e/compose.enterprise-agent-control.yaml",
]
FEEDS = ("vulnerability-tests", "data-objects", "report-formats", "gpg-data", "notus-data")


class ProvenanceError(RuntimeError):
    """Runtime evidence is missing or does not match the immutable inputs."""


def output(command: list[str]) -> str:
    result = subprocess.run(
        command, cwd=ROOT, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    if result.returncode:
        raise ProvenanceError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result.stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_archive_sha256(path: Path) -> str:
    result = subprocess.run(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=path,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise ProvenanceError(
            f"git archive failed ({result.returncode}): {result.stderr.decode(errors='replace')}"
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


def combined_sha256(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def runtime_records(compose: Path) -> dict[str, dict[str, str]]:
    ids = output([str(compose), "ps", "-a", "-q"]).split()
    if not ids:
        raise ProvenanceError("enterprise Compose project has no containers")
    inspected = json.loads(output(["docker", "inspect", *ids]))
    records: dict[str, dict[str, str]] = {}
    for item in inspected:
        config = item.get("Config") or {}
        labels = config.get("Labels") or {}
        service = labels.get("com.docker.compose.service")
        if service:
            records[service] = {
                "sourceRevision": labels.get("org.opencontainers.image.revision")
                or f"image-id:{item['Image']}",
                "image": config["Image"],
                "imageDigest": item["Image"],
            }
    return records


def require(records: dict[str, dict[str, str]], service: str) -> dict[str, str]:
    if service not in records:
        raise ProvenanceError(f"runtime service {service!r} is absent")
    return records[service]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-manifest", type=Path, required=True)
    parser.add_argument("--agent-control-source", type=Path, required=True)
    parser.add_argument("--compose", type=Path, default=ROOT / "scripts/compose-enterprise-agent-control.sh")
    args = parser.parse_args()

    direct = json.loads(DIRECT_PINS.read_text())
    enterprise = json.loads(ENTERPRISE_PINS.read_text())
    build = json.loads(args.build_manifest.read_text())
    records = runtime_records(args.compose.resolve())
    source_revision = output(["git", "-C", str(args.agent_control_source), "rev-parse", "HEAD"])
    source_git_tree = output(
        ["git", "-C", str(args.agent_control_source), "rev-parse", "HEAD^{tree}"]
    )
    source_archive = source_archive_sha256(args.agent_control_source)
    repository_revision = output(["git", "rev-parse", "HEAD"])
    expected_source = enterprise["sourceBuildWorkaround"]["revision"]
    if source_revision != expected_source or build["source"]["revision"] != expected_source:
        raise ProvenanceError("Agent Control source/build revision drifted")
    if (
        source_git_tree != enterprise["sourceBuildWorkaround"]["gitTree"]
        or source_archive != enterprise["sourceBuildWorkaround"]["sourceArchiveSha256"]
        or build["source"].get("gitTree") != source_git_tree
        or build["source"].get("archiveSha256") != source_archive
    ):
        raise ProvenanceError("Agent Control source tree/archive hash drifted")
    dockerfile = (
        args.agent_control_source
        / enterprise["sourceBuildWorkaround"]["dockerfile"]
    )
    if (
        sha256(dockerfile) != enterprise["sourceBuildWorkaround"]["dockerfileSha256"]
        or build["build"].get("dockerfileSha256") != sha256(dockerfile)
    ):
        raise ProvenanceError("Agent Control Dockerfile hash drifted")
    agent_runtime = require(records, "agent-control-backend")
    if agent_runtime["image"] != build["image"]["reference"]:
        raise ProvenanceError("Agent Control runtime did not use the built immutable digest")
    openvasd_runtime = require(records, "openvasd-backend")
    if openvasd_runtime["image"] != direct["emulator"]["image"]:
        raise ProvenanceError("community OpenVASD emulator runtime drifted")

    fixture_root = args.agent_control_source / enterprise["agentControl"]["fixtureDirectory"]
    fixture_tree = tree_sha256(fixture_root)
    if fixture_tree != enterprise["agentControl"]["fixtureTreeSha256"]:
        raise ProvenanceError("Agent Control fixture tree hash drifted")
    if sha256(fixture_root / "swagger.json") != enterprise["agentControl"]["swaggerSha256"]:
        raise ProvenanceError("Agent Control swagger hash drifted")
    if build.get("apiInputSha256") != enterprise["agentControl"]["apiInputSha256"]:
        raise ProvenanceError("Agent Control upstream API input hash drifted")
    document: dict[str, Any] = {
        "schemaVersion": 1,
        "lane": "enterprise-agent-control-emulator-advisory",
        "rustGvmApi": {**require(records, "gvm-gateway"), "sourceRevision": repository_revision},
        "featureEnabledGvmd": require(records, "gvmd"),
        "openvasd": {
            "runtime": openvasd_runtime,
            "sourceRevision": direct["emulator"]["sourceRevision"],
            "apiRevision": direct["emulator"]["openapiRevision"],
            "fixtureRevision": direct["emulator"]["fixtureRevision"],
            "fixtureTreeSha256": tree_sha256(ROOT / "dist/e2e-openvasd/fixtures"),
            "pinsSha256": sha256(DIRECT_PINS),
        },
        "agentControl": {
            "runtime": agent_runtime,
            "sourceRepository": enterprise["sourceBuildWorkaround"]["repository"],
            "sourceRevision": source_revision,
            "sourceGitTree": source_git_tree,
            "sourceArchiveSha256": source_archive,
            "dockerfileSha256": build["build"]["dockerfileSha256"],
            "buildManifestSha256": sha256(args.build_manifest),
            "profile": build["profile"],
            "apiRevision": build["apiRevision"],
            "apiInputSha256": build["apiInputSha256"],
            "swaggerSha256": build["swaggerSha256"],
            "fixtureRevision": build["fixtureRevision"],
            "fixtureTreeSha256": fixture_tree,
        },
        "agentControlScenarioSelection": {
            "name": "issue-680-agent-control-scenario-proxy",
            "runtime": require(records, "agent-control-scenario-proxy"),
            "sourceSha256": sha256(
                ROOT / "tests/e2e/src/bin/agent-control-scenario-proxy.rs"
            ),
            "control": "bearer-authenticated-and-loopback-published",
            "role": "selects-upstream-profile-with-x-emulator-scenario",
            "upstreamService": "agent-control-backend",
        },
        "databases": [
            {"name": service, **require(records, service)}
            for service in ("pg-gvm-migrator", "pg-gvm")
        ],
        "feedData": [
            {"name": service, "revision": require(records, service)["imageDigest"]}
            for service in FEEDS
        ],
        "composeHarness": {
            "composeSha256": combined_sha256(COMPOSE),
            "harnessSha256": tree_sha256(ROOT / "tests/e2e"),
            "runnerScriptSha256": sha256(ROOT / "scripts/run-enterprise-agent-control-contracts.sh"),
        },
        "runner": {
            "os": os.environ.get("RUNNER_OS", os.uname().sysname),
            "architecture": os.environ.get("RUNNER_ARCH", os.uname().machine),
            "image": "-".join(filter(None, [os.environ.get("ImageOS"), os.environ.get("ImageVersion")]))
            or "local-or-self-hosted",
            "rust": enterprise["runner"]["rust"],
        },
        "realCompatibilityInput": {
            "configured": False,
            "reason": "emulator evidence is isolated from the separately bounded real-service workflow",
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
