#!/usr/bin/env python3
"""Build and publish the exact temporary Agent Control emulator source."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PINS_PATH = ROOT / "tests" / "e2e" / "evidence" / "enterprise-agent-control-pins.json"


class BuildError(RuntimeError):
    """The exact-source image could not be built or identified."""


def run(command: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd or ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise BuildError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result.stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_archive_sha256(source: Path) -> str:
    result = subprocess.run(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=source,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise BuildError(
            f"git archive failed ({result.returncode}): {result.stderr.decode(errors='replace')}"
        )
    return hashlib.sha256(result.stdout).hexdigest()


def git_blob_sha256(source: Path, object_id: str) -> str:
    result = subprocess.run(
        ["git", "cat-file", "blob", object_id],
        cwd=source,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise BuildError(
            f"git cat-file failed ({result.returncode}): {result.stderr.decode(errors='replace')}"
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


def load_pins() -> dict[str, Any]:
    document = json.loads(PINS_PATH.read_text(encoding="utf-8"))
    if document.get("schemaVersion") != 1:
        raise BuildError("enterprise Agent Control pins must use schemaVersion 1")
    return document


def build(source: Path, output: Path, github_env: Path | None, registry: str) -> dict[str, Any]:
    pins = load_pins()
    source_pin = pins["sourceBuildWorkaround"]
    expected_revision = source_pin["revision"]
    actual_revision = run(["git", "rev-parse", "HEAD"], cwd=source)
    if actual_revision != expected_revision:
        raise BuildError(
            f"Agent Control emulator source drifted: expected {expected_revision}, got {actual_revision}"
        )
    if run(["git", "status", "--porcelain"], cwd=source):
        raise BuildError("Agent Control emulator source checkout is not clean")

    dockerfile = source / source_pin["dockerfile"]
    fixture_root = source / pins["agentControl"]["fixtureDirectory"]
    if not dockerfile.is_file():
        raise BuildError(f"pinned Dockerfile is missing: {dockerfile}")
    if not (fixture_root / "swagger.json").is_file():
        raise BuildError(f"pinned Agent Control API fixture is missing: {fixture_root / 'swagger.json'}")
    actual_tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=source)
    actual_archive = source_archive_sha256(source)
    actual_dockerfile = sha256(dockerfile)
    actual_fixture_tree = tree_sha256(fixture_root)
    actual_swagger = sha256(fixture_root / "swagger.json")
    exact_inputs = {
        "gitTree": actual_tree,
        "sourceArchiveSha256": actual_archive,
        "dockerfileSha256": actual_dockerfile,
    }
    for key, actual in exact_inputs.items():
        if source_pin.get(key) != actual:
            raise BuildError(f"Agent Control source {key} drifted: expected {source_pin.get(key)}, got {actual}")
    if pins["agentControl"].get("fixtureTreeSha256") != actual_fixture_tree:
        raise BuildError("Agent Control fixture tree SHA-256 drifted")
    if pins["agentControl"].get("swaggerSha256") != actual_swagger:
        raise BuildError("Agent Control swagger.json SHA-256 drifted")
    api_input_hash = git_blob_sha256(source, pins["agentControl"]["apiRevision"])
    if pins["agentControl"].get("apiInputSha256") != api_input_hash:
        raise BuildError("Agent Control upstream API input SHA-256 drifted")

    staging = f"{registry}/greenbone/gvm-openapi-emulator:issue-680-{expected_revision[:12]}"
    run(
        [
            "docker",
            "build",
            "--pull",
            "--label",
            f"org.opencontainers.image.revision={expected_revision}",
            "--label",
            "org.opencontainers.image.source=https://github.com/greenbone/gvm-openapi-emulator",
            "-f",
            str(dockerfile),
            "-t",
            staging,
            str(source),
        ]
    )
    run(["docker", "push", staging])
    repo_digests = json.loads(run(["docker", "image", "inspect", staging, "--format", "{{json .RepoDigests}}"] ))
    matches = [item for item in repo_digests if item.startswith(f"{registry}/greenbone/gvm-openapi-emulator@sha256:")]
    if len(matches) != 1:
        raise BuildError(f"expected one immutable repository digest for {staging}, got {repo_digests}")
    image_reference = matches[0]
    image_id = run(["docker", "image", "inspect", staging, "--format", "{{.Id}}"])

    document = {
        "schemaVersion": 1,
        "workaround": "greenbone/gvm-openapi-emulator#50 exact-source build",
        "replacementCondition": source_pin["replacementCondition"],
        "source": {
            "repository": source_pin["repository"],
            "revision": expected_revision,
            "gitTree": actual_tree,
            "archiveSha256": actual_archive,
        },
        "build": {
            "dockerfile": source_pin["dockerfile"],
            "dockerfileSha256": actual_dockerfile,
            "platform": run(["docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"]),
        },
        "image": {"reference": image_reference, "imageId": image_id},
        "profile": pins["agentControl"]["profile"],
        "apiRevision": pins["agentControl"]["apiRevision"],
        "fixtureRevision": pins["agentControl"]["fixtureRevision"],
        "fixtureDirectory": pins["agentControl"]["fixtureDirectory"],
        "fixtureTreeSha256": actual_fixture_tree,
        "swaggerSha256": actual_swagger,
        "apiInputSha256": api_input_hash,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    if github_env is not None:
        with github_env.open("a", encoding="utf-8") as stream:
            stream.write(f"GVM_GATEWAY_E2E_AGENT_CONTROL_IMAGE={image_reference}\n")
            stream.write(f"GVM_GATEWAY_E2E_AGENT_CONTROL_SOURCE={source.resolve()}\n")
            stream.write(f"GVM_GATEWAY_E2E_AGENT_CONTROL_BUILD_MANIFEST={output.resolve()}\n")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-env", type=Path)
    parser.add_argument("--registry", default="127.0.0.1:5001")
    args = parser.parse_args()
    document = build(args.source.resolve(), args.output, args.github_env, args.registry)
    print(f"built exact Agent Control emulator {document['image']['reference']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
