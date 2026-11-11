#!/usr/bin/env python3
"""Fetch and verify the exact OpenVASD emulator contract fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Callable
from urllib.parse import urlsplit


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from secure_https import HttpsTransportError, https_get


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PINS_PATH = REPOSITORY_ROOT / "tests" / "e2e" / "evidence" / "direct-openvasd-pins.json"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "dist" / "e2e-openvasd" / "fixtures"
RAW_GITHUB_HOST = "raw.githubusercontent.com"


class FixtureError(RuntimeError):
    """The pinned fixture could not be reproduced exactly."""


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def checked_relative_path(raw_path: str) -> Path:
    path = PurePosixPath(raw_path)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise FixtureError(f"unsafe fixture path: {raw_path!r}")
    return Path(*path.parts)


def fixture_tree_sha256(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(files[name])
        digest.update(b"\0")
    return digest.hexdigest()


def fetch_fixtures(
    pins: dict[str, object],
    fetch: Callable[[str], bytes],
) -> dict[str, bytes]:
    emulator = pins.get("emulator")
    if not isinstance(emulator, dict):
        raise FixtureError("pins.emulator must be an object")
    repository = emulator.get("sourceRepository")
    revision = emulator.get("sourceRevision")
    expected_files = emulator.get("files")
    if not isinstance(repository, str) or not repository:
        raise FixtureError("pins.emulator.sourceRepository must be set")
    if not isinstance(revision, str) or len(revision) != 40:
        raise FixtureError("pins.emulator.sourceRevision must be a full commit SHA")
    if not isinstance(expected_files, dict) or not expected_files:
        raise FixtureError("pins.emulator.files must not be empty")

    files: dict[str, bytes] = {}
    for raw_name, expected_sha in sorted(expected_files.items()):
        if not isinstance(raw_name, str) or not isinstance(expected_sha, str):
            raise FixtureError("fixture names and hashes must be strings")
        checked_relative_path(raw_name)
        url = (
            f"https://raw.githubusercontent.com/{repository}/{revision}/"
            f"examples/openvasd/{raw_name}"
        )
        content = fetch(url)
        actual_sha = sha256(content)
        if actual_sha != expected_sha:
            raise FixtureError(
                f"fixture {raw_name} SHA-256 mismatch: expected {expected_sha}, got {actual_sha}"
            )
        files[raw_name] = content

    openapi_sha = emulator.get("openapiSha256")
    if openapi_sha != expected_files.get("swagger.json"):
        raise FixtureError("the OpenAPI pin must equal the verified swagger.json hash")
    return files


def download(url: str) -> bytes:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != RAW_GITHUB_HOST
        or parsed.port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise FixtureError(f"refusing untrusted fixture URL: {url!r}")
    target = parsed.path
    if parsed.query:
        target += f"?{parsed.query}"
    try:
        status, _headers, content = https_get(
            f"https://{RAW_GITHUB_HOST}{target}",
            {"User-Agent": "rust-gvm-api-e2e"},
        )
    except HttpsTransportError as error:
        raise FixtureError(str(error)) from error
    if status != 200:
        raise FixtureError(f"fixture download failed with HTTP {status}")
    return content


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    pins = json.loads(PINS_PATH.read_text(encoding="utf-8"))
    files = fetch_fixtures(pins, download)
    args.output.mkdir(parents=True, exist_ok=True)
    existing = {
        path.relative_to(args.output).as_posix()
        for path in args.output.rglob("*")
        if path.is_file() and path.name != "fixture-tree.sha256"
    }
    unexpected = existing - files.keys()
    if unexpected:
        raise FixtureError(
            f"fixture output contains unpinned files; remove them before retrying: {sorted(unexpected)}"
        )
    for name, content in files.items():
        destination = args.output / checked_relative_path(name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    tree_sha = fixture_tree_sha256(files)
    (args.output / "fixture-tree.sha256").write_text(tree_sha + "\n", encoding="utf-8")
    print(
        f"verified {len(files)} OpenVASD fixture files at "
        f"{pins['emulator']['sourceRevision']} (tree sha256:{tree_sha})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
