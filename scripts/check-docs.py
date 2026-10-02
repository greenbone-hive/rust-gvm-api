#!/usr/bin/env python3
"""Validate documentation navigation and the human REST route reference."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


def curated_routes() -> dict[str, set[str]]:
    """Read the path/method inventory from the curated split OpenAPI files."""

    spec_root = REPOSITORY_ROOT / "spec" / "rest-api"
    root_lines = (spec_root / "openapi.yaml").read_text().splitlines()
    routes: dict[str, set[str]] = {}
    in_paths = False

    for index, line in enumerate(root_lines):
        if line == "paths:":
            in_paths = True
            continue
        if in_paths and line == "components:":
            break
        match = re.match(r"^  (/[^:]*):$", line)
        if not in_paths or match is None:
            continue

        path = match.group(1)
        if index + 1 >= len(root_lines):
            raise ValueError(f"missing OpenAPI reference for {path}")
        reference_match = re.match(
            r"^    \$ref: ['\"](\./[^#]+)#",
            root_lines[index + 1],
        )
        if reference_match is None:
            raise ValueError(f"expected a split-file OpenAPI reference for {path}")

        referenced_lines = (spec_root / reference_match.group(1)).read_text().splitlines()
        try:
            start = referenced_lines.index(f"  {path}:") + 1
        except ValueError as error:
            raise ValueError(f"referenced OpenAPI path is missing: {path}") from error

        methods: set[str] = set()
        for referenced_line in referenced_lines[start:]:
            if re.match(r"^  /", referenced_line):
                break
            method_match = re.match(r"^    ([a-z]+):$", referenced_line)
            if method_match and method_match.group(1) in HTTP_METHODS:
                methods.add(method_match.group(1).upper())
        if not methods:
            raise ValueError(f"no operations found for curated path {path}")
        routes[path] = methods

    return routes


def documented_routes() -> tuple[dict[str, set[str]], tuple[int, int]]:
    """Read the route table and stated inventory from the user API reference."""

    reference = (
        REPOSITORY_ROOT / "docs" / "user" / "api-reference.md"
    ).read_text()
    route_pattern = re.compile(r"^\| ([^|]+) \| `(/[^`]+)` \|", re.MULTILINE)
    routes: dict[str, set[str]] = {}

    for method_cell, path in route_pattern.findall(reference):
        if path in routes:
            raise ValueError(f"duplicate API-reference route row: {path}")
        routes[path] = set(
            re.findall(r"`(GET|POST|PUT|PATCH|DELETE)`", method_cell)
        )

    count_match = re.search(
        r"current contract contains (\d+) paths and (\d+) operations",
        reference,
    )
    if count_match is None:
        raise ValueError("API reference does not state its path/operation inventory")
    return routes, (int(count_match.group(1)), int(count_match.group(2)))


def check_api_reference() -> list[str]:
    """Require the human route matrix to match the curated contract exactly."""

    expected = curated_routes()
    documented, stated_counts = documented_routes()
    failures: list[str] = []

    for path in sorted(expected.keys() - documented.keys()):
        failures.append(f"API reference is missing route {path}")
    for path in sorted(documented.keys() - expected.keys()):
        failures.append(f"API reference has unknown route {path}")
    for path in sorted(expected.keys() & documented.keys()):
        if expected[path] != documented[path]:
            failures.append(
                f"API reference methods for {path} are {sorted(documented[path])}; "
                f"expected {sorted(expected[path])}"
            )

    actual_counts = (len(expected), sum(len(methods) for methods in expected.values()))
    if stated_counts != actual_counts:
        failures.append(
            f"API reference states {stated_counts[0]} paths/{stated_counts[1]} "
            f"operations; expected {actual_counts[0]}/{actual_counts[1]}"
        )
    return failures


def check_relative_links() -> list[str]:
    """Reject broken repository-relative Markdown links in active and archived docs."""

    markdown_files = [REPOSITORY_ROOT / "README.md"]
    markdown_files.extend((REPOSITORY_ROOT / "docs").rglob("*.md"))
    markdown_files.extend((REPOSITORY_ROOT / "spec").rglob("*.md"))
    link_pattern = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)", re.DOTALL)
    failures: list[str] = []

    for markdown_file in markdown_files:
        contents = markdown_file.read_text()
        for match in link_pattern.finditer(contents):
            raw_target = match.group(1)
            target = raw_target.split()[0].strip("<>")
            if not target or target.startswith(
                ("#", "http://", "https://", "mailto:")
            ):
                continue
            target_path = target.split("#", 1)[0]
            resolved = (markdown_file.parent / target_path).resolve()
            if resolved.exists():
                continue
            line = contents.count("\n", 0, match.start()) + 1
            relative_file = markdown_file.relative_to(REPOSITORY_ROOT)
            failures.append(
                f"broken relative link at {relative_file}:{line}: {raw_target}"
            )
    return failures


def main() -> int:
    """Run all deterministic documentation checks."""

    try:
        failures = check_api_reference() + check_relative_links()
    except (OSError, ValueError) as error:
        print(f"documentation validation failed: {error}", file=sys.stderr)
        return 1

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    routes = curated_routes()
    operations = sum(len(methods) for methods in routes.values())
    print(
        f"documentation validation passed: {len(routes)} paths, "
        f"{operations} operations, relative links intact"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
