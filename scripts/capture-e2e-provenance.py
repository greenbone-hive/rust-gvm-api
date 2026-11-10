#!/usr/bin/env python3
"""Capture exact runtime component and fixture provenance for E2E diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FEED_SERVICES = ("vulnerability-tests", "data-objects", "report-formats", "gpg-data")


def command_output(command: list[str], cwd: Path = REPOSITORY_ROOT) -> str:
    return subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True).stdout


def compose_runtime() -> str:
    if shutil.which("docker"):
        result = subprocess.run(["docker", "compose", "version"], capture_output=True)
        if result.returncode == 0:
            return "docker"
    if shutil.which("podman"):
        return "podman"
    raise RuntimeError("no Docker or Podman runtime is available for provenance capture")


def container_inspects(runtime: str) -> list[dict[str, Any]]:
    # Include completed one-shot feed containers; their exact images are part
    # of the reproducibility contract even though they are no longer running.
    container_ids = command_output(["./scripts/compose-dev.sh", "ps", "-a", "-q"]).split()
    if not container_ids:
        raise RuntimeError("compose returned no containers")
    return json.loads(command_output([runtime, "inspect", *container_ids]))


def service_records(inspects: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    records: dict[str, dict[str, str]] = {}
    for inspect in inspects:
        config = inspect.get("Config") or {}
        labels = config.get("Labels") or {}
        service = labels.get("com.docker.compose.service") or labels.get("io.podman.compose.service")
        if not service:
            continue
        image_id = inspect.get("Image")
        image_ref = config.get("Image")
        if not image_id or not image_ref:
            raise RuntimeError(f"container for {service} is missing exact image identity")
        source_revision = labels.get("org.opencontainers.image.revision") or f"image-id:{image_id}"
        records[service] = {
            "sourceRevision": source_revision,
            "image": image_ref,
            "imageDigest": image_id,
        }
    return records


def require_service(records: dict[str, dict[str, str]], service: str) -> dict[str, str]:
    try:
        return records[service]
    except KeyError as error:
        raise RuntimeError(f"compose service {service!r} is missing from runtime provenance") from error


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_document(
    records: dict[str, dict[str, str]],
    repository_revision: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    gateway = dict(require_service(records, "gvm-gateway"))
    gateway["sourceRevision"] = repository_revision
    compose_hash = sha256(REPOSITORY_ROOT / "compose.yaml")
    api_hash = sha256(REPOSITORY_ROOT / "spec" / "rest-api" / "openapi.yaml")
    return {
        "schemaVersion": 1,
        "gateway": gateway,
        "gvmd": require_service(records, "gvmd"),
        "scanner": require_service(records, "ospd-openvas"),
        "feedData": [
            {"name": service, "revision": require_service(records, service)["imageDigest"]}
            for service in FEED_SERVICES
        ],
        "fixtures": [
            {"name": "compose.yaml", "revision": f"sha256:{compose_hash}"},
            {
                "name": "GVM_GATEWAY_E2E_TARGET_HOST",
                "revision": environment.get("GVM_GATEWAY_E2E_TARGET_HOST", "openvasd"),
            },
        ],
        "apiContract": {
            "name": "spec/rest-api/openapi.yaml",
            "revision": f"sha256:{api_hash}",
        },
        "composeSha256": compose_hash,
        "runner": {
            "os": environment.get("RUNNER_OS", os.uname().sysname),
            "architecture": environment.get("RUNNER_ARCH", os.uname().machine),
            "image": ":".join(
                filter(
                    None,
                    [
                        environment.get("ImageOS"),
                        environment.get("ImageVersion"),
                    ],
                )
            )
            or "local-or-self-hosted",
        },
        "harnessRevision": repository_revision,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runtime = compose_runtime()
    records = service_records(container_inspects(runtime))
    revision = command_output(["git", "rev-parse", "HEAD"]).strip()
    document = build_document(records, revision, dict(os.environ))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote exact E2E runtime provenance to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
