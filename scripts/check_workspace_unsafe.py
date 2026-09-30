#!/usr/bin/env python3
"""Generate Cargo Geiger evidence and optionally reject first-party unsafe use."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from scripts.workspace_inventory import ROOT, WorkspacePackage, validated_inventory
except ModuleNotFoundError:  # Direct script execution adds scripts/ to sys.path.
    from workspace_inventory import ROOT, WorkspacePackage, validated_inventory


DEFAULT_REPORT_DIR = ROOT / "target" / "geiger"


def unsafe_total(used: dict[str, Any]) -> int:
    total = 0
    for section in used.values():
        if not isinstance(section, dict):
            continue
        value = section.get("unsafe_", 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("Cargo Geiger unsafe counts must be non-negative integers")
        total += value
    return total


def first_party_unsafe(payload: dict[str, Any], package: WorkspacePackage) -> int:
    matches = [
        item
        for item in payload.get("packages", [])
        if isinstance(item, dict)
        and item.get("package", {}).get("id", {}).get("name") == package.name
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected one first-party package named {package.name}, found {len(matches)}"
        )
    unsafety = matches[0].get("unsafety", {})
    if not isinstance(unsafety, dict) or not isinstance(unsafety.get("used", {}), dict):
        raise ValueError(f"invalid Cargo Geiger unsafety payload for {package.name}")
    return unsafe_total(unsafety.get("used", {}))


def generate_report(package: WorkspacePackage, report_dir: Path) -> int:
    report_dir.mkdir(parents=True, exist_ok=True)
    output = report_dir / f"{package.name}.json"
    result = subprocess.run(
        [
            "cargo",
            "geiger",
            "--manifest-path",
            str(ROOT / package.manifest),
            "--all-features",
            "--all-dependencies",
            "--output-format",
            "Json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"cargo geiger failed for {package.name} (exit {result.returncode}): "
            f"{result.stderr.strip()}"
        )
    output.write_text(result.stdout, encoding="utf-8")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid Cargo Geiger JSON for {package.name}: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError(f"Cargo Geiger report for {package.name} must be an object")
    return first_party_unsafe(payload, package)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="generate evidence without making unsafe counts fail the command",
    )
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        packages = validated_inventory()
        violations = []
        for package in packages:
            count = generate_report(package, args.report_dir)
            print(f"{package.name}: used_unsafe={count}")
            if count:
                violations.append((package.name, count))
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if violations and not args.report_only:
        print("Unsafe usage detected in first-party workspace packages:", file=sys.stderr)
        for name, count in violations:
            print(f"  - {name}: {count}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
