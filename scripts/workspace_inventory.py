#!/usr/bin/env python3
"""Load and validate the explicit first-party Cargo workspace inventory."""

from __future__ import annotations

import json
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT / "supply-chain" / "workspace-packages.toml"


@dataclass(frozen=True, order=True)
class WorkspacePackage:
    name: str
    manifest: Path


def load_inventory(path: Path = DEFAULT_INVENTORY) -> tuple[WorkspacePackage, ...]:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != 1:
        raise ValueError("workspace inventory schema must be 1")

    raw_packages = document.get("packages")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise ValueError("workspace inventory must contain packages")

    packages: list[WorkspacePackage] = []
    for index, raw in enumerate(raw_packages):
        if not isinstance(raw, dict):
            raise ValueError(f"packages[{index}] must be a table")
        name = raw.get("name")
        manifest_text = raw.get("manifest")
        if not isinstance(name, str) or not name:
            raise ValueError(f"packages[{index}].name must be non-empty")
        if not isinstance(manifest_text, str) or not manifest_text:
            raise ValueError(f"packages[{index}].manifest must be non-empty")
        manifest = Path(manifest_text)
        if manifest.is_absolute() or ".." in manifest.parts:
            raise ValueError(f"unsafe manifest path for {name}: {manifest_text}")
        packages.append(WorkspacePackage(name=name, manifest=manifest))

    if len({package.name for package in packages}) != len(packages):
        raise ValueError("workspace inventory contains duplicate package names")
    if len({package.manifest for package in packages}) != len(packages):
        raise ValueError("workspace inventory contains duplicate manifests")
    return tuple(packages)


def cargo_metadata(root: Path = ROOT) -> dict[str, Any]:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise ValueError("cargo metadata did not return a JSON object")
    return payload


def metadata_packages(metadata: dict[str, Any], root: Path = ROOT) -> set[WorkspacePackage]:
    members = set(metadata.get("workspace_members", []))
    packages: set[WorkspacePackage] = set()
    for package in metadata.get("packages", []):
        if not isinstance(package, dict) or package.get("id") not in members:
            continue
        manifest = Path(str(package.get("manifest_path", ""))).resolve()
        try:
            relative = manifest.relative_to(root.resolve())
        except ValueError as error:
            raise ValueError(f"workspace manifest is outside repository: {manifest}") from error
        packages.add(WorkspacePackage(str(package.get("name", "")), relative))
    return packages


def validate_inventory(
    inventory: tuple[WorkspacePackage, ...],
    metadata: dict[str, Any],
    root: Path = ROOT,
) -> None:
    configured = set(inventory)
    discovered = metadata_packages(metadata, root)
    if configured == discovered:
        return

    missing = sorted(discovered - configured)
    stale = sorted(configured - discovered)
    details = []
    if missing:
        details.append(
            "missing: " + ", ".join(f"{item.name} ({item.manifest})" for item in missing)
        )
    if stale:
        details.append(
            "stale: " + ", ".join(f"{item.name} ({item.manifest})" for item in stale)
        )
    raise ValueError("workspace inventory mismatch; " + "; ".join(details))


def validated_inventory(root: Path = ROOT) -> tuple[WorkspacePackage, ...]:
    inventory = load_inventory(root / "supply-chain" / "workspace-packages.toml")
    validate_inventory(inventory, cargo_metadata(root), root)
    for package in inventory:
        if not (root / package.manifest).is_file():
            raise ValueError(f"workspace manifest does not exist: {package.manifest}")
    return inventory
