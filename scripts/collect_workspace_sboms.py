#!/usr/bin/env python3
"""Collect exactly one generated CycloneDX JSON document per workspace member."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

try:
    from scripts.workspace_inventory import ROOT, validated_inventory
except ModuleNotFoundError:  # Direct script execution adds scripts/ to sys.path.
    from workspace_inventory import ROOT, validated_inventory


def collect(destination: Path) -> list[Path]:
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    collected = []
    for package in validated_inventory():
        package_dir = (ROOT / package.manifest).parent
        candidates = [
            path
            for path in package_dir.glob("*.cdx.json")
            if path.resolve().parent != destination
            and path.name == f"{package.name}.cdx.json"
        ]
        if len(candidates) != 1:
            raise ValueError(
                f"expected one SBOM for {package.name} beside {package.manifest}, "
                f"found {len(candidates)}"
            )
        target = destination / candidates[0].name
        shutil.copyfile(candidates[0], target)
        collected.append(target)
    return collected


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    try:
        collected = collect(args.destination)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for path in collected:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
