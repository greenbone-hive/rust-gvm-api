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

from build_temporary_openvas_scanner import (
    SOURCE_REVISION as TEMPORARY_SCANNER_SOURCE_REVISION,
    load_manifest as load_temporary_scanner_build_manifest,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FEED_SERVICES = ("vulnerability-tests", "data-objects", "report-formats", "gpg-data")
DIRECT_FEED_SERVICES = (*FEED_SERVICES, "notus-data")
DIRECT_COMPOSE_PATH = REPOSITORY_ROOT / "tests" / "e2e" / "compose.direct-openvasd.yaml"
REAL_COMPOSE_PATH = REPOSITORY_ROOT / "tests" / "e2e" / "compose.real-openvasd.yaml"
PINS_PATH = REPOSITORY_ROOT / "tests" / "e2e" / "evidence" / "direct-openvasd-pins.json"


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


def container_inspects(runtime: str, compose_script: str = "./scripts/compose-dev.sh") -> list[dict[str, Any]]:
    # Include completed one-shot feed containers; their exact images are part
    # of the reproducibility contract even though they are no longer running.
    container_ids = command_output([compose_script, "ps", "-a", "-q"]).split()
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


def assert_pinned_runtime(
    records: dict[str, dict[str, str]],
    pins: dict[str, Any],
    lane: str,
    temporary_scanner_build: dict[str, Any] | None = None,
) -> None:
    runtime_images = pins["runtimeImages"]
    service_pins = {
        "gvmd": runtime_images["gvmd"],
        "configure-direct-openvasd": runtime_images["gvmd"],
        "vulnerability-tests": runtime_images["vulnerability-tests"],
        "data-objects": runtime_images["data-objects"],
        "report-formats": runtime_images["report-formats"],
        "gpg-data": runtime_images["gpg-data"],
        "notus-data": runtime_images["notus-data"],
        "pg-gvm-migrator": runtime_images["pg-gvm-migrator"],
        "pg-gvm": runtime_images["pg-gvm"],
        "openvasd-scenario-proxy": runtime_images["scenario-proxy"],
        "e2e-target": runtime_images["e2e-target"],
    }
    if lane == "real-openvasd":
        real_openvasd_image = (
            temporary_scanner_build["image"]["reference"]
            if temporary_scanner_build is not None
            else runtime_images["real-openvasd"]
        )
        service_pins["openvasd-backend"] = real_openvasd_image
        service_pins["configure-openvas"] = real_openvasd_image
    else:
        service_pins["openvasd-backend"] = pins["emulator"]["image"]

    for service, expected_image in service_pins.items():
        actual_image = require_service(records, service)["image"]
        if actual_image != expected_image:
            raise RuntimeError(
                f"compose service {service!r} image drifted: expected {expected_image}, "
                f"got {actual_image}"
            )
    if lane == "direct-openvasd":
        source_revision = records["openvasd-backend"]["sourceRevision"]
        if source_revision != pins["emulator"]["sourceRevision"]:
            raise RuntimeError(
                "emulator OCI source revision does not match the pinned Phase 1 source commit: "
                f"expected {pins['emulator']['sourceRevision']}, got {source_revision}"
            )
    if lane == "real-openvasd" and temporary_scanner_build is not None:
        configure = records["configure-openvas"]
        backend = records["openvasd-backend"]
        for service, record in (
            ("configure-openvas", configure),
            ("openvasd-backend", backend),
        ):
            if record["sourceRevision"] != TEMPORARY_SCANNER_SOURCE_REVISION:
                raise RuntimeError(
                    f"compose service {service!r} source revision drifted: expected "
                    f"{TEMPORARY_SCANNER_SOURCE_REVISION}, got {record['sourceRevision']}"
                )
        if (
            configure["image"] != backend["image"]
            or configure["imageDigest"] != backend["imageDigest"]
        ):
            raise RuntimeError(
                "configure-openvas and openvasd-backend must use one identical temporary image"
            )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def combined_sha256(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def directory_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        if item.name == "fixture-tree.sha256":
            continue
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(item.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def assert_distinct_identities(
    inspects: list[dict[str, Any]], backend_service: str, target_service: str
) -> None:
    """Fail if Compose made the scanner backend and requested target the same identity."""

    identities: dict[str, tuple[str, set[str]]] = {}
    for inspect in inspects:
        labels = (inspect.get("Config") or {}).get("Labels") or {}
        service = labels.get("com.docker.compose.service") or labels.get(
            "io.podman.compose.service"
        )
        if service not in {backend_service, target_service}:
            continue
        container_id = inspect.get("Id")
        networks = (inspect.get("NetworkSettings") or {}).get("Networks") or {}
        addresses = {
            network.get("IPAddress")
            for network in networks.values()
            if network.get("IPAddress")
        }
        if not container_id or not addresses:
            raise RuntimeError(f"compose service {service!r} has no exact container/network identity")
        identities[service] = (container_id, addresses)

    missing = {backend_service, target_service} - identities.keys()
    if missing:
        raise RuntimeError(f"identity assertion is missing compose services: {sorted(missing)}")
    backend_id, backend_addresses = identities[backend_service]
    target_id, target_addresses = identities[target_service]
    if backend_service == target_service or backend_id == target_id:
        raise RuntimeError("scanner backend and synthetic target container identities are conflated")
    overlap = backend_addresses & target_addresses
    if overlap:
        raise RuntimeError(
            f"scanner backend and synthetic target network identities overlap: {sorted(overlap)}"
        )


def build_document(
    records: dict[str, dict[str, str]],
    repository_revision: str,
    environment: dict[str, str],
    *,
    scanner_service: str = "ospd-openvas",
    feed_services: tuple[str, ...] = FEED_SERVICES,
    compose_paths: list[Path] | None = None,
    target_service: str | None = None,
    fixture_root: Path | None = None,
    temporary_scanner_build_path: Path | None = None,
    temporary_scanner_build: dict[str, Any] | None = None,
) -> dict[str, Any]:
    gateway = dict(require_service(records, "gvm-gateway"))
    gateway["sourceRevision"] = repository_revision
    compose_paths = compose_paths or [REPOSITORY_ROOT / "compose.yaml"]
    compose_hash = (
        sha256(compose_paths[0]) if len(compose_paths) == 1 else combined_sha256(compose_paths)
    )
    api_hash = sha256(REPOSITORY_ROOT / "spec" / "rest-api" / "openapi.yaml")
    fixtures = [
        {
            "name": path.relative_to(REPOSITORY_ROOT).as_posix(),
            "revision": f"sha256:{sha256(path)}",
        }
        for path in compose_paths
    ]
    fixtures.append(
        {
            "name": "GVM_GATEWAY_E2E_TARGET_HOST",
            "revision": environment.get("GVM_GATEWAY_E2E_TARGET_HOST", "openvasd"),
        }
    )
    if target_service:
        target = require_service(records, target_service)
        fixtures.extend(
            [
                {"name": "scanner-backend-identity", "revision": scanner_service},
                {"name": "synthetic-target-identity", "revision": target_service},
                {"name": "synthetic-target-image", "revision": target["imageDigest"]},
                {"name": PINS_PATH.relative_to(REPOSITORY_ROOT).as_posix(), "revision": f"sha256:{sha256(PINS_PATH)}"},
            ]
        )
    if fixture_root:
        fixtures.extend(
            [
                {
                    "name": "gvm-openapi-emulator/examples/openvasd/swagger.json",
                    "revision": f"sha256:{sha256(fixture_root / 'swagger.json')}",
                },
                {
                    "name": "gvm-openapi-emulator/examples/openvasd",
                    "revision": f"sha256:{directory_sha256(fixture_root)}",
                },
            ]
        )
    if temporary_scanner_build_path is not None and temporary_scanner_build is not None:
        build = temporary_scanner_build["build"]
        source = temporary_scanner_build["source"]
        image = temporary_scanner_build["image"]
        fixtures.extend(
            [
                {
                    "name": "temporary-openvas-scanner-source",
                    "revision": f"{source['repository']}@{source['revision']}",
                },
                {
                    "name": f"{source['repository']}/{build['dockerfile']}",
                    "revision": f"sha256:{build['dockerfileSha256']}",
                },
                {
                    "name": "temporary-openvas-scanner-build-inputs",
                    "revision": "sha256:"
                    + hashlib.sha256(
                        json.dumps(build, sort_keys=True, separators=(",", ":")).encode(
                            "utf-8"
                        )
                    ).hexdigest(),
                },
                {
                    "name": "temporary-openvas-scanner-image",
                    "revision": image["reference"],
                },
                {
                    "name": "temporary-openvas-scanner-build-manifest",
                    "revision": f"sha256:{sha256(temporary_scanner_build_path)}",
                },
            ]
        )
    fixtures.append(
        {
            "name": "tests/e2e-harness",
            "revision": f"sha256:{directory_sha256(REPOSITORY_ROOT / 'tests' / 'e2e')}",
        }
    )
    return {
        "schemaVersion": 1,
        "gateway": gateway,
        "gvmd": require_service(records, "gvmd"),
        "scanner": require_service(records, scanner_service),
        "feedData": [
            {"name": service, "revision": require_service(records, service)["imageDigest"]}
            for service in feed_services
        ],
        "fixtures": fixtures,
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
    parser.add_argument(
        "--lane",
        choices=("osp", "direct-openvasd", "real-openvasd"),
        default="osp",
    )
    temporary_manifest_environment = os.environ.get(
        "GVM_GATEWAY_E2E_TEMPORARY_SCANNER_BUILD_MANIFEST"
    )
    parser.add_argument(
        "--temporary-scanner-build-manifest",
        type=Path,
        default=(
            Path(temporary_manifest_environment)
            if temporary_manifest_environment
            else None
        ),
    )
    args = parser.parse_args()
    if args.temporary_scanner_build_manifest is not None and args.lane != "real-openvasd":
        raise RuntimeError(
            "a temporary scanner build manifest is valid only for the real-openvasd lane"
        )
    runtime = compose_runtime()
    if args.lane == "osp":
        compose_script = "./scripts/compose-dev.sh"
        scanner_service = "ospd-openvas"
        feed_services = FEED_SERVICES
        compose_paths = [REPOSITORY_ROOT / "compose.yaml"]
        target_service = None
        fixture_root = None
    else:
        compose_script = "./scripts/compose-direct-openvasd.sh"
        scanner_service = "openvasd-backend"
        feed_services = DIRECT_FEED_SERVICES
        compose_paths = [DIRECT_COMPOSE_PATH]
        if args.lane == "real-openvasd":
            compose_paths.append(REAL_COMPOSE_PATH)
        target_service = "e2e-target"
        fixture_root = REPOSITORY_ROOT / "dist" / "e2e-openvasd" / "fixtures"

    inspects = container_inspects(runtime, compose_script)
    if target_service:
        assert_distinct_identities(inspects, scanner_service, target_service)
    records = service_records(inspects)
    temporary_scanner_build = None
    if args.temporary_scanner_build_manifest is not None:
        temporary_scanner_build = load_temporary_scanner_build_manifest(
            args.temporary_scanner_build_manifest
        )
    if args.lane != "osp":
        pins = json.loads(PINS_PATH.read_text(encoding="utf-8"))
        assert_pinned_runtime(records, pins, args.lane, temporary_scanner_build)
    revision = command_output(["git", "rev-parse", "HEAD"]).strip()
    document = build_document(
        records,
        revision,
        dict(os.environ),
        scanner_service=scanner_service,
        feed_services=feed_services,
        compose_paths=compose_paths,
        target_service=target_service,
        fixture_root=fixture_root,
        temporary_scanner_build_path=args.temporary_scanner_build_manifest,
        temporary_scanner_build=temporary_scanner_build,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote exact E2E runtime provenance to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
