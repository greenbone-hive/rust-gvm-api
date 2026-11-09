#!/usr/bin/env python3
"""Collect generated CycloneDX documents for exactly the workspace members."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

try:
    from scripts.workspace_inventory import ROOT, validated_inventory
except ModuleNotFoundError:  # Direct script execution adds scripts/ to sys.path.
    from workspace_inventory import ROOT, validated_inventory


SUPPORTED_FORMATS = ("json", "xml")


def collect(destination: Path, formats: tuple[str, ...] = ("json",)) -> list[Path]:
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    collected = []
    for package in validated_inventory():
        package_dir = (ROOT / package.manifest).parent
        for document_format in formats:
            source = package_dir / f"{package.name}.cdx.{document_format}"
            if not source.is_file():
                raise ValueError(
                    f"expected one {document_format.upper()} SBOM for {package.name} "
                    f"beside {package.manifest}"
                )
            target = destination / source.name
            shutil.copyfile(source, target)
            collected.append(target)
    return collected


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--format",
        action="append",
        choices=SUPPORTED_FORMATS,
        dest="formats",
        help="document format to collect; repeat for multiple formats (default: json)",
    )
    parser.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    try:
        formats = tuple(dict.fromkeys(args.formats or ("json",)))
        collected = collect(args.destination, formats)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for path in collected:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
