#!/usr/bin/env python3
"""Build the issue #695 scanner source and publish one immutable local-registry image."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any


SOURCE_REPOSITORY = "greenbone/openvas-scanner"
SOURCE_URL = f"https://github.com/{SOURCE_REPOSITORY}"
SOURCE_REVISION = "d6e3cbe74ca6f1f4ff1a9d9fcafca59732a32b81"
DOCKERFILE = ".docker/prod.Dockerfile"
DOCKERFILE_SHA256 = "86c23e2f9660b56c2b73a7f6cdf8a94b6138bdd85b09294f089f1763e2d6baed"
PLATFORM = "linux/amd64"
BUILD_ARGUMENTS = {
    "VERSION": "latest",
    "GVM_LIBS": "ghcr.io/greenbone/gvm-libs",
    "RUST_IMAGE": "rust",
    "OPENVAS_SMB_IMAGE": "greenbone/openvas-smb",
    "BUILD_IMAGE": "ghcr.io/greenbone/gvm-libs:latest",
    "FINAL_IMAGE": "ghcr.io/greenbone/gvm-libs:latest",
    "FINAL_PACKAGE_SET": "latest",
    "KRB5_VERSION": "1.22.2",
    "LIBPCAP_VERSION": "1.10.6",
    "BIN_VERSION": "",
    "PYPSRP_CLI_VERSION": "v0.1.0",
}
BUILD_LABELS = {
    "org.opencontainers.image.source": SOURCE_URL,
    "org.opencontainers.image.revision": SOURCE_REVISION,
}
REGISTRY_IMAGE = (
    "docker.io/library/registry:2@sha256:"
    "a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
)
IMAGE_REPOSITORY = "localhost:5000/rust-gvm-api/openvas-scanner"
REMOVAL_TRIGGER = (
    "Remove this temporary build after greenbone/openvas-scanner PR #2454 is merged "
    "and an official community scanner image containing the fix is published."
)
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IMAGE_REFERENCE_PATTERN = re.compile(
    rf"{re.escape(IMAGE_REPOSITORY)}@(sha256:[0-9a-f]{{64}})"
)


class TemporaryScannerBuildError(RuntimeError):
    """The temporary scanner cannot be built or identified without provenance drift."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command_output(command: list[str], *, cwd: Path | None = None) -> str:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
    except FileNotFoundError as error:
        raise TemporaryScannerBuildError(
            f"required command is unavailable: {command[0]}"
        ) from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or error.stdout.strip() or f"exit status {error.returncode}"
        raise TemporaryScannerBuildError(
            f"command failed ({' '.join(command)}): {detail}"
        ) from error


def run_command(command: list[str]) -> None:
    """Run a long Docker operation with live output for Actions diagnostics."""

    try:
        subprocess.run(command, check=True)
    except FileNotFoundError as error:
        raise TemporaryScannerBuildError(
            f"required command is unavailable: {command[0]}"
        ) from error
    except subprocess.CalledProcessError as error:
        raise TemporaryScannerBuildError(
            f"command failed ({' '.join(command)}): exit status {error.returncode}"
        ) from error


def image_exists(reference: str) -> bool:
    """Distinguish an absent local image from a Docker inspection failure."""

    try:
        result = subprocess.run(
            ["docker", "image", "inspect", reference],
            check=False,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError as error:
        raise TemporaryScannerBuildError("required command is unavailable: docker") from error
    if result.returncode == 0:
        return True
    detail = result.stderr.strip() or result.stdout.strip()
    if "No such image" in detail:
        return False
    raise TemporaryScannerBuildError(
        f"cannot verify local scanner image cleanup for {reference}: "
        f"{detail or f'exit status {result.returncode}'}"
    )


def cleanup_local_build_state(
    staging_reference: str,
    image_id: str,
    *,
    command_runner: Callable[[list[str]], None] = run_command,
    image_inspector: Callable[[str], bool] = image_exists,
) -> None:
    """Remove the built local image and all build cache while preserving the registry copy."""

    print(
        f"removing local temporary scanner staging image {staging_reference} ({image_id})",
        flush=True,
    )
    command_runner(["docker", "image", "rm", "--force", image_id])
    retained = [
        reference
        for reference in (staging_reference, image_id)
        if image_inspector(reference)
    ]
    if retained:
        raise TemporaryScannerBuildError(
            f"local temporary scanner image cleanup retained: {', '.join(retained)}"
        )
    print("local temporary scanner image and staging tag removed", flush=True)

    print("pruning Docker build cache on the ephemeral compatibility runner", flush=True)
    command_runner(["docker", "builder", "prune", "--all", "--force"])
    print("Docker build cache prune completed", flush=True)


def verify_source(source: Path) -> None:
    """Require the pristine, exact PR commit and its supported production Dockerfile."""

    if not source.is_dir():
        raise TemporaryScannerBuildError(f"scanner source checkout does not exist: {source}")
    revision = command_output(["git", "rev-parse", "HEAD"], cwd=source)
    if revision != SOURCE_REVISION:
        raise TemporaryScannerBuildError(
            f"scanner source revision drifted: expected {SOURCE_REVISION}, got {revision}"
        )
    status = command_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=source
    )
    if status:
        raise TemporaryScannerBuildError("scanner source checkout contains uncommitted inputs")
    dockerfile = source / DOCKERFILE
    if not dockerfile.is_file():
        raise TemporaryScannerBuildError(f"supported scanner Dockerfile is missing: {DOCKERFILE}")
    dockerfile_sha256 = sha256(dockerfile)
    if dockerfile_sha256 != DOCKERFILE_SHA256:
        raise TemporaryScannerBuildError(
            "scanner production Dockerfile drifted: "
            f"expected {DOCKERFILE_SHA256}, got {dockerfile_sha256}"
        )


def expect_exact_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TemporaryScannerBuildError(f"{context} must be an object")
    if set(value) != expected:
        raise TemporaryScannerBuildError(
            f"{context} keys drifted: expected {sorted(expected)}, got {sorted(value)}"
        )
    return value


def validate_manifest(document: Any) -> str:
    """Validate the closed build manifest and return its immutable image reference."""

    root = expect_exact_keys(
        document,
        {"schemaVersion", "temporaryUntil", "source", "build", "registry", "image"},
        "temporary scanner build manifest",
    )
    if root["schemaVersion"] != 1:
        raise TemporaryScannerBuildError("temporary scanner build schemaVersion must equal 1")
    if root["temporaryUntil"] != REMOVAL_TRIGGER:
        raise TemporaryScannerBuildError("temporary scanner build removal trigger drifted")

    source = expect_exact_keys(root["source"], {"repository", "revision"}, "source")
    if source != {"repository": SOURCE_REPOSITORY, "revision": SOURCE_REVISION}:
        raise TemporaryScannerBuildError("temporary scanner source identity drifted")

    build = expect_exact_keys(
        root["build"],
        {
            "contextRevision",
            "dockerfile",
            "dockerfileSha256",
            "platform",
            "arguments",
            "labels",
        },
        "build",
    )
    expected_build = {
        "contextRevision": SOURCE_REVISION,
        "dockerfile": DOCKERFILE,
        "dockerfileSha256": DOCKERFILE_SHA256,
        "platform": PLATFORM,
        "arguments": BUILD_ARGUMENTS,
        "labels": BUILD_LABELS,
    }
    if build != expected_build:
        raise TemporaryScannerBuildError("temporary scanner build inputs drifted")

    registry = expect_exact_keys(root["registry"], {"image", "repository"}, "registry")
    if registry != {"image": REGISTRY_IMAGE, "repository": IMAGE_REPOSITORY}:
        raise TemporaryScannerBuildError("temporary scanner registry identity drifted")

    image = expect_exact_keys(root["image"], {"reference", "digest"}, "image")
    reference = image["reference"]
    digest = image["digest"]
    if not isinstance(reference, str) or not isinstance(digest, str):
        raise TemporaryScannerBuildError("temporary scanner image identity must contain strings")
    match = IMAGE_REFERENCE_PATTERN.fullmatch(reference)
    if not match or not SHA256_PATTERN.fullmatch(digest) or match.group(1) != digest:
        raise TemporaryScannerBuildError(
            "temporary scanner image must use its matching immutable local-registry digest"
        )
    return reference


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TemporaryScannerBuildError(
            f"cannot load temporary scanner build manifest {path}: {error}"
        ) from error
    validate_manifest(document)
    return document


def build_manifest(reference: str) -> dict[str, Any]:
    match = IMAGE_REFERENCE_PATTERN.fullmatch(reference)
    if not match:
        raise TemporaryScannerBuildError(
            f"Docker did not return the expected immutable image repository: {reference}"
        )
    document = {
        "schemaVersion": 1,
        "temporaryUntil": REMOVAL_TRIGGER,
        "source": {"repository": SOURCE_REPOSITORY, "revision": SOURCE_REVISION},
        "build": {
            "contextRevision": SOURCE_REVISION,
            "dockerfile": DOCKERFILE,
            "dockerfileSha256": DOCKERFILE_SHA256,
            "platform": PLATFORM,
            "arguments": dict(BUILD_ARGUMENTS),
            "labels": dict(BUILD_LABELS),
        },
        "registry": {"image": REGISTRY_IMAGE, "repository": IMAGE_REPOSITORY},
        "image": {"reference": reference, "digest": match.group(1)},
    }
    validate_manifest(document)
    return document


def build_and_publish(source: Path) -> tuple[dict[str, Any], str, str]:
    verify_source(source)
    staging_reference = f"{IMAGE_REPOSITORY}:{SOURCE_REVISION}"
    build_command = [
        "docker",
        "build",
        "--file",
        str(source / DOCKERFILE),
        "--platform",
        PLATFORM,
    ]
    for name, value in BUILD_ARGUMENTS.items():
        build_command.extend(["--build-arg", f"{name}={value}"])
    for name, value in BUILD_LABELS.items():
        build_command.extend(["--label", f"{name}={value}"])
    build_command.extend(["--tag", staging_reference, str(source)])
    run_command(build_command)

    image_id = command_output(
        ["docker", "image", "inspect", staging_reference, "--format", "{{.Id}}"]
    )
    if not SHA256_PATTERN.fullmatch(image_id):
        raise TemporaryScannerBuildError(
            f"Docker returned an invalid local scanner image ID: {image_id}"
        )

    labels_raw = command_output(
        ["docker", "image", "inspect", staging_reference, "--format", "{{json .Config.Labels}}"]
    )
    try:
        labels = json.loads(labels_raw)
    except json.JSONDecodeError as error:
        raise TemporaryScannerBuildError("Docker returned invalid scanner image labels") from error
    if not isinstance(labels, dict) or any(
        labels.get(name) != value for name, value in BUILD_LABELS.items()
    ):
        raise TemporaryScannerBuildError(
            "built scanner image source labels do not match the exact inputs"
        )

    run_command(["docker", "push", staging_reference])
    repo_digests_raw = command_output(
        ["docker", "image", "inspect", staging_reference, "--format", "{{json .RepoDigests}}"]
    )
    try:
        repo_digests = json.loads(repo_digests_raw)
    except json.JSONDecodeError as error:
        raise TemporaryScannerBuildError("Docker returned invalid repository digests") from error
    matching = (
        sorted(
            reference
            for reference in repo_digests
            if isinstance(reference, str)
            and reference.startswith(f"{IMAGE_REPOSITORY}@")
        )
        if isinstance(repo_digests, list)
        else []
    )
    if len(matching) != 1:
        raise TemporaryScannerBuildError(
            "Docker must resolve exactly one repository digest for the temporary scanner image"
        )
    reference = matching[0]
    document = build_manifest(reference)
    command_output(["docker", "manifest", "inspect", "--insecure", reference])
    print(f"verified immutable scanner manifest in the job-local registry: {reference}")
    return document, staging_reference, image_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    args = parser.parse_args()

    document, staging_reference, image_id = build_and_publish(args.source.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    image_reference = validate_manifest(document)
    print(f"wrote fail-closed temporary scanner build evidence to {args.output}")
    cleanup_local_build_state(staging_reference, image_id)
    with args.github_env.open("a", encoding="utf-8") as environment:
        environment.write(f"GVM_GATEWAY_E2E_REAL_OPENVASD_IMAGE={image_reference}\n")
        environment.write(
            "GVM_GATEWAY_E2E_TEMPORARY_SCANNER_BUILD_MANIFEST="
            f"{args.output.resolve()}\n"
        )
    print(f"published exact temporary scanner image {image_reference}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TemporaryScannerBuildError as error:
        raise SystemExit(f"temporary scanner build failed: {error}") from error
