#!/usr/bin/env python3
"""Verify every immutable direct-OpenVASD runtime image before Compose starts."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from build_temporary_openvas_scanner import load_manifest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PINS_PATH = REPOSITORY_ROOT / "tests" / "e2e" / "evidence" / "direct-openvasd-pins.json"
IMAGE_DIGEST_PATTERN = re.compile(r".+@sha256:[0-9a-f]{64}$")


class RuntimeImageManifestError(RuntimeError):
    """A runtime image pin cannot be used safely for a Compose launch."""


def runtime_images(
    path: Path = PINS_PATH,
    temporary_scanner_build_manifest: Path | None = None,
    real_openvasd_image: str | None = None,
) -> dict[str, str]:
    """Load every valid immutable runtime image reference from the pin manifest."""

    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeImageManifestError(f"cannot load runtime image manifest {path}: {error}") from error
    images = document.get("runtimeImages") if isinstance(document, dict) else None
    if not isinstance(images, dict) or not images:
        raise RuntimeImageManifestError("runtime image manifest must contain a non-empty runtimeImages object")

    emulator = document.get("emulator")
    emulator_image = emulator.get("image") if isinstance(emulator, dict) else None
    if not isinstance(emulator_image, str):
        raise RuntimeImageManifestError("runtime image manifest must contain an emulator image")

    validated: dict[str, str] = {"emulator": emulator_image}
    for name, image in images.items():
        if not isinstance(name, str) or not name or not isinstance(image, str):
            raise RuntimeImageManifestError("runtime image manifest contains an invalid image entry")
        if name == "emulator":
            raise RuntimeImageManifestError("runtimeImages must not redefine the emulator image")
        validated[name] = image

    for name, image in validated.items():
        if not IMAGE_DIGEST_PATTERN.fullmatch(image):
            raise RuntimeImageManifestError(
                f"runtime image {name!r} is not pinned to an immutable SHA-256 digest: {image!r}"
            )
    if temporary_scanner_build_manifest is not None:
        try:
            temporary_build = load_manifest(temporary_scanner_build_manifest)
        except RuntimeError as error:
            raise RuntimeImageManifestError(str(error)) from error
        temporary_image = temporary_build["image"]["reference"]
        if real_openvasd_image != temporary_image:
            raise RuntimeImageManifestError(
                "real OpenVASD Compose override does not match the temporary build manifest"
            )
        validated["real-openvasd"] = temporary_image
    elif real_openvasd_image is not None:
        raise RuntimeImageManifestError(
            "a real OpenVASD image override requires a temporary build manifest"
        )
    return validated


def digest_reference(image: str) -> str:
    """Drop the mutable tag so Docker resolves the retained digest directly."""

    repository_and_tag, separator, digest = image.rpartition("@")
    if not separator:
        raise RuntimeImageManifestError(f"runtime image is missing a digest: {image!r}")
    last_slash = repository_and_tag.rfind("/")
    last_colon = repository_and_tag.rfind(":")
    repository = (
        repository_and_tag[:last_colon]
        if last_colon > last_slash
        else repository_and_tag
    )
    return f"{repository}@{digest}"


def inspect_manifest(image: str) -> None:
    """Ask the registry for the exact pinned manifest without pulling or starting an image."""

    try:
        reference = digest_reference(image)
        command = ["docker", "manifest", "inspect"]
        if reference.startswith("localhost:"):
            command.append("--insecure")
        command.append(reference)
        result = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=60,
        )
    except FileNotFoundError as error:
        raise RuntimeImageManifestError("Docker CLI is required to validate runtime image manifests") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeImageManifestError("registry manifest lookup timed out") from error
    except OSError as error:
        raise RuntimeImageManifestError(f"registry manifest lookup could not start: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "registry did not return a manifest"
        raise RuntimeImageManifestError(detail)


def validate_runtime_images(
    images: dict[str, str], manifest_inspector: Callable[[str], None] = inspect_manifest
) -> None:
    """Fail before Compose if any declared runtime image manifest is unavailable."""

    for name in sorted(images):
        image = images[name]
        try:
            manifest_inspector(image)
        except RuntimeImageManifestError as error:
            raise RuntimeImageManifestError(
                f"unavailable runtime image {name!r}: {image}; {error}"
            ) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pins", type=Path, default=PINS_PATH)
    parser.add_argument("--temporary-scanner-build-manifest", type=Path)
    parser.add_argument("--real-openvasd-image")
    args = parser.parse_args()
    images = runtime_images(
        args.pins,
        args.temporary_scanner_build_manifest,
        args.real_openvasd_image,
    )
    validate_runtime_images(images)
    print(f"validated {len(images)} immutable direct-OpenVASD runtime image manifests")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeImageManifestError as error:
        raise SystemExit(f"runtime image manifest validation failed: {error}") from error
