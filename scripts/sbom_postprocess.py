#!/usr/bin/env python3
"""Deterministically enrich generated CycloneDX JSON for quality scoring."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


CC0_LICENSE = {"license": {"id": "CC0-1.0"}}
BUILD_LIFECYCLE = {"phase": "build"}
SUPPLIER_FALLBACK = "greenbone-hive"


def workspace_metadata(cargo_toml: Path) -> tuple[str, str, list[Any]]:
    workspace = tomllib.loads(cargo_toml.read_text(encoding="utf-8")).get("workspace", {})
    package = workspace.get("package", {}) if isinstance(workspace, dict) else {}
    repository = str(package.get("repository", ""))
    match = re.search(r"github\.com/([^/]+)/", repository)
    supplier = match.group(1) if match else SUPPLIER_FALLBACK
    license_value = package.get("license")
    licenses = [{"expression": license_value}] if isinstance(license_value, str) else []
    return supplier, repository, licenses


def normalize_spec_version(value: Any) -> str:
    try:
        major, minor = [int(part) for part in str(value).split(".")[:2]]
    except (TypeError, ValueError):
        return "1.5"
    return "1.5" if (major, minor) < (1, 5) else f"{major}.{minor}"


def ensure_list_entry(container: dict[str, Any], key: str, value: dict[str, Any]) -> None:
    current = container.get(key)
    if not isinstance(current, list):
        container[key] = [value]
    elif value not in current:
        current.append(value)


def iter_components(document: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def visit(values: Any) -> None:
        if not isinstance(values, list):
            return
        for component in values:
            if not isinstance(component, dict):
                continue
            found.append(component)
            visit(component.get("components"))

    metadata = document.get("metadata", {})
    primary = metadata.get("component") if isinstance(metadata, dict) else None
    if isinstance(primary, dict):
        found.append(primary)
        visit(primary.get("components"))
    visit(document.get("components"))
    return found


def is_first_party(component: dict[str, Any], repository: str) -> bool:
    bom_ref = str(component.get("bom-ref", ""))
    purl = str(component.get("purl", ""))
    if bom_ref.startswith("path+file://") or "download_url=file://" in purl:
        return True
    references = component.get("externalReferences", [])
    return any(
        isinstance(item, dict)
        and item.get("type") == "vcs"
        and item.get("url") == repository
        for item in references
    )


def enrich_component(
    component: dict[str, Any], supplier: str, repository: str, licenses: list[Any]
) -> None:
    first_party = is_first_party(component, repository)
    if not component.get("supplier"):
        purl = str(component.get("purl", ""))
        if first_party:
            component["supplier"] = {"name": supplier}
        elif purl.startswith("pkg:cargo/"):
            component["supplier"] = {"name": "crates.io"}
    if not first_party:
        return
    if licenses and not component.get("licenses"):
        component["licenses"] = copy.deepcopy(licenses)
    references = component.get("externalReferences")
    if not isinstance(references, list):
        references = []
        component["externalReferences"] = references
    vcs = {"type": "vcs", "url": repository}
    if repository and vcs not in references:
        references.append(vcs)


def declare_complete(document: dict[str, Any]) -> None:
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        return
    refs = list(
        dict.fromkeys(
            str(item.get("ref"))
            for item in dependencies
            if isinstance(item, dict)
            and item.get("ref")
            and isinstance(item.get("dependsOn"), list)
        )
    )
    if not refs:
        return
    compositions = document.setdefault("compositions", [])
    if not isinstance(compositions, list):
        raise ValueError("SBOM compositions must be a JSON array")
    complete = next(
        (
            item
            for item in compositions
            if isinstance(item, dict) and item.get("aggregate") == "complete"
        ),
        None,
    )
    if complete is None:
        compositions.append({"aggregate": "complete", "dependencies": refs})
    else:
        existing = complete.get("dependencies", [])
        complete["dependencies"] = list(
            dict.fromkeys([item for item in existing if isinstance(item, str)] + refs)
        )


def transform(
    document: dict[str, Any], cargo_toml: Path, dependency_complete: bool
) -> dict[str, Any]:
    supplier, repository, licenses = workspace_metadata(cargo_toml)
    document["specVersion"] = normalize_spec_version(document.get("specVersion"))
    metadata = document.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("SBOM metadata must be a JSON object")
    ensure_list_entry(metadata, "licenses", CC0_LICENSE)
    ensure_list_entry(metadata, "lifecycles", BUILD_LIFECYCLE)
    if not metadata.get("authors"):
        metadata["authors"] = [{"name": supplier}]
    if not metadata.get("supplier"):
        metadata["supplier"] = {"name": supplier}
    for component in iter_components(document):
        enrich_component(component, supplier, repository, licenses)
    if dependency_complete:
        declare_complete(document)
    return document


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", nargs="+", type=Path)
    parser.add_argument("--cargo-toml", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("--declare-dependency-complete", action="store_true")
    args = parser.parse_args(argv)
    for path in args.sbom:
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError(f"SBOM must be a JSON object: {path}")
        transformed = transform(document, args.cargo_toml, args.declare_dependency_complete)
        path.write_text(json.dumps(transformed, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
