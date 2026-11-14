#!/usr/bin/env python3
"""Run a bounded, read-only real Agent Control compatibility probe with exact inputs."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PINS_PATH = ROOT / "tests/e2e/evidence/enterprise-agent-control-pins.json"
DEPENDENCY_FAILURE_CLASSIFICATIONS = (
    "connectivity",
    "health",
    "authentication",
    "signing",
    "authenticated-signed-access",
    "inventory",
    "pagination",
    "scan-agent-configuration",
    "installer-instructions",
)

REQUIRED_INPUTS = (
    "REAL_AGENT_CONTROL_URL",
    "REAL_AGENT_CONTROL_HEALTH_PATH",
    "REAL_AGENT_CONTROL_AUTH_HEADER_NAME",
    "REAL_AGENT_CONTROL_AUTH_HEADER_VALUE",
    "REAL_AGENT_CONTROL_SIGNING_HEADER_NAME",
    "REAL_AGENT_CONTROL_SIGNING_HEADER_VALUE",
    "REAL_AGENT_CONTROL_SERVICE_REVISION",
    "REAL_AGENT_CONTROL_API_REVISION",
    "REAL_AGENT_CONTROL_FIXTURE_REVISION",
)


class CompatibilityFailure(RuntimeError):
    def __init__(self, classification: str, detail: str):
        super().__init__(detail)
        self.classification = classification


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def load_wire_contract() -> tuple[dict[str, Any], dict[str, Any]]:
    """Load the direct-service contract bound to the exact PR #50 source identities."""

    pins = json.loads(PINS_PATH.read_text(encoding="utf-8"))
    contract = pins.get("realCompatibilityContract")
    agent_control = pins.get("agentControl")
    if not isinstance(contract, dict) or not isinstance(agent_control, dict):
        raise CompatibilityFailure(
            "incomplete-operator-input", "checked-in Agent Control contract pins are incomplete"
        )
    return contract, agent_control


def validated_inputs() -> dict[str, str]:
    values = {key: os.environ.get(key, "").strip() for key in REQUIRED_INPUTS}
    missing = sorted(key for key, value in values.items() if not value)
    if missing:
        raise CompatibilityFailure(
            "incomplete-operator-input", f"required real Agent Control inputs are missing: {missing}"
        )
    parsed = urllib.parse.urlsplit(values["REAL_AGENT_CONTROL_URL"])
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise CompatibilityFailure(
            "incomplete-operator-input",
            "REAL_AGENT_CONTROL_URL must be an HTTPS origin without credentials, path, query, or fragment",
        )
    for key in ("REAL_AGENT_CONTROL_AUTH_HEADER_NAME", "REAL_AGENT_CONTROL_SIGNING_HEADER_NAME"):
        if any(character in values[key] for character in "\r\n:"):
            raise CompatibilityFailure("incomplete-operator-input", f"{key} is not a safe HTTP header name")
    if values["REAL_AGENT_CONTROL_AUTH_HEADER_NAME"].lower() == values[
        "REAL_AGENT_CONTROL_SIGNING_HEADER_NAME"
    ].lower():
        raise CompatibilityFailure(
            "incomplete-operator-input", "authentication and signing header names must be distinct"
        )
    mutable_identities = {"latest", "main", "master", "head", "unknown", "unversioned"}
    for key in (
        "REAL_AGENT_CONTROL_SERVICE_REVISION",
        "REAL_AGENT_CONTROL_API_REVISION",
        "REAL_AGENT_CONTROL_FIXTURE_REVISION",
    ):
        if values[key].lower() in mutable_identities:
            raise CompatibilityFailure(
                "incomplete-operator-input", f"{key} must identify an exact immutable input"
            )
    return values


def request(
    origin: str,
    path: str,
    headers: dict[str, str],
    *,
    timeout: int,
) -> tuple[int, dict[str, list[str]], bytes]:
    if not path.startswith("/") or "\r" in path or "\n" in path:
        raise CompatibilityFailure("incomplete-operator-input", f"unsafe request path: {path!r}")
    req = urllib.request.Request(
        f"{origin.rstrip('/')}{path}", headers={"Accept": "application/json", **headers}
    )
    try:
        with urllib.request.urlopen(
            req, timeout=timeout, context=ssl.create_default_context()
        ) as response:
            return response.status, preserve_headers(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, preserve_headers(error.headers), error.read()
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise CompatibilityFailure("connectivity", str(error)) from error


def preserve_headers(message: Any) -> dict[str, list[str]]:
    """Retain every response-header field value so duplicates cannot be hidden by a dict."""

    preserved: dict[str, list[str]] = {}
    if message is None:
        return preserved
    for name in message.keys():
        normalized = name.lower()
        if normalized not in preserved:
            preserved[normalized] = list(message.get_all(name, []))
    return preserved


def display_header(headers: dict[str, list[str]], name: str) -> str:
    return ", ".join(headers.get(name.lower(), []))


def checked_json(
    origin: str,
    path: str,
    headers: dict[str, str],
    expected: set[int],
    classification: str,
    timeout: int,
) -> tuple[Any, dict[str, object], dict[str, list[str]]]:
    status, response_headers, body = request(origin, path, headers, timeout=timeout)
    observation = {
        "path": path,
        "status": status,
        "contentType": display_header(response_headers, "content-type"),
        "bodySha256": sha256(body),
        "bodyBytes": len(body),
    }
    if status not in expected:
        raise CompatibilityFailure(classification, f"{path} returned HTTP {status}")
    try:
        return json.loads(body) if body else None, observation, response_headers
    except json.JSONDecodeError as error:
        raise CompatibilityFailure(classification, f"{path} returned invalid JSON: {error}") from error


def exact_nonnegative_integer_header(
    headers: dict[str, list[str]], name: str
) -> tuple[int, list[str]]:
    values = headers.get(name.lower(), [])
    if len(values) != 1:
        raise CompatibilityFailure(
            "pagination", f"inventory requires exactly one {name} header; got {values!r}"
        )
    raw = values[0]
    if not raw.isascii() or not raw.isdecimal() or len(raw) > 10:
        raise CompatibilityFailure("pagination", f"inventory {name} is not an integer: {raw!r}")
    parsed = int(raw)
    if str(parsed) != raw:
        raise CompatibilityFailure("pagination", f"inventory {name} is not canonical: {raw!r}")
    return parsed, values


def empty_inventory_page(
    value: Any,
    headers: dict[str, list[str]],
    contract: dict[str, Any],
) -> dict[str, Any]:
    """Validate PR #50's raw-array body and header-carried pagination contract."""

    if contract.get("inventoryResponseShape") != "raw-array" or not isinstance(value, list):
        raise CompatibilityFailure("inventory", "agent inventory is not the pinned raw JSON array")
    if value:
        raise CompatibilityFailure(
            "inventory", "bounded compatibility input must expose an empty non-production inventory"
        )
    names = contract.get("paginationHeaders")
    if not isinstance(names, dict):
        raise CompatibilityFailure("pagination", "pinned pagination-header contract is incomplete")
    parsed: dict[str, int] = {}
    raw_headers: dict[str, list[str]] = {}
    for field in ("totalCount", "page", "perPage"):
        name = names.get(field)
        if not isinstance(name, str) or not name:
            raise CompatibilityFailure("pagination", f"pinned {field} header name is incomplete")
        parsed[field], raw_headers[name] = exact_nonnegative_integer_header(headers, name)
    if parsed != {"totalCount": 0, "page": 1, "perPage": 1}:
        raise CompatibilityFailure(
            "pagination", f"empty page pagination metadata is inconsistent: {parsed}"
        )
    return {**parsed, "rawHeaders": raw_headers}


def run(values: dict[str, str], timeout: int) -> dict[str, object]:
    contract, _agent_control_pin = load_wire_contract()
    origin = values["REAL_AGENT_CONTROL_URL"]
    authenticated = {
        values["REAL_AGENT_CONTROL_AUTH_HEADER_NAME"]: values["REAL_AGENT_CONTROL_AUTH_HEADER_VALUE"],
        values["REAL_AGENT_CONTROL_SIGNING_HEADER_NAME"]: values["REAL_AGENT_CONTROL_SIGNING_HEADER_VALUE"],
    }
    observations: list[dict[str, object]] = []

    health, health_observation, _health_headers = checked_json(
        origin, values["REAL_AGENT_CONTROL_HEALTH_PATH"], {}, {200}, "health", timeout
    )
    observations.append(health_observation)

    inventory_query = contract["paginationQuery"]
    inventory_path = contract["inventoryPath"] + "?" + urllib.parse.urlencode(
        {inventory_query["page"]: 1, inventory_query["perPage"]: 1}
    )
    unauth_status, _unauth_headers, unauth_body = request(origin, inventory_path, {}, timeout=timeout)
    observations.append(
        {
            "path": inventory_path,
            "status": unauth_status,
            "mode": "unauthenticated",
            "bodySha256": sha256(unauth_body),
            "bodyBytes": len(unauth_body),
        }
    )
    if unauth_status not in {401, 403}:
        raise CompatibilityFailure(
            "authentication", f"unauthenticated inventory did not fail closed: HTTP {unauth_status}"
        )

    auth_only = {
        values["REAL_AGENT_CONTROL_AUTH_HEADER_NAME"]: values[
            "REAL_AGENT_CONTROL_AUTH_HEADER_VALUE"
        ]
    }
    unsigned_status, _unsigned_headers, unsigned_body = request(
        origin,
        inventory_path,
        auth_only,
        timeout=timeout,
    )
    observations.append(
        {
            "path": inventory_path,
            "status": unsigned_status,
            "mode": "authenticated-unsigned",
            "bodySha256": sha256(unsigned_body),
            "bodyBytes": len(unsigned_body),
        }
    )
    if unsigned_status not in {401, 403}:
        raise CompatibilityFailure(
            "signing",
            f"authenticated but unsigned inventory did not fail closed: HTTP {unsigned_status}",
        )

    inventory, inventory_observation, inventory_headers = checked_json(
        origin,
        inventory_path,
        authenticated,
        {200},
        "authenticated-signed-access",
        timeout,
    )
    pagination = empty_inventory_page(inventory, inventory_headers, contract)
    inventory_observation["paginationHeaders"] = pagination["rawHeaders"]
    observations.append(inventory_observation)

    scan_config, scan_observation, _scan_headers = checked_json(
        origin,
        "/api/v1/admin/scan-agent-config",
        authenticated,
        {200},
        "scan-agent-configuration",
        timeout,
    )
    observations.append(scan_observation)
    if not isinstance(scan_config, dict):
        raise CompatibilityFailure("scan-agent-configuration", "scan-agent config is not an object")

    installer_path = contract["installerInstructionsPath"] + "?" + urllib.parse.urlencode(
        {
            contract["installerLanguageParameter"]: "en",
            contract["installerOriginParameter"]: "https://manager.example",
        }
    )
    installer, installer_observation, _installer_headers = checked_json(
        origin, installer_path, authenticated, {200}, "installer-instructions", timeout
    )
    observations.append(installer_observation)
    if not isinstance(installer, (dict, list)):
        raise CompatibilityFailure("installer-instructions", "installer instructions have an unexpected shape")

    return {
        "healthShape": type(health).__name__,
        "emptyInventory": True,
        "pagination": pagination,
        "scanAgentConfigSha256": scan_observation["bodySha256"],
        "installerInstructionsSha256": installer_observation["bodySha256"],
        "dependencyFailureClassifications": list(DEPENDENCY_FAILURE_CLASSIFICATIONS),
        "observations": observations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()
    document: dict[str, object] = {
        "schemaVersion": 1,
        "lane": "real-agent-control-compatibility-advisory",
        "advisory": True,
        "completedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "failed",
        "failureClassification": None,
        "provenance": None,
        "checks": None,
    }
    exit_code = 1
    try:
        values = validated_inputs()
        _contract, agent_control_pin = load_wire_contract()
        document["provenance"] = {
            "serviceOrigin": values["REAL_AGENT_CONTROL_URL"],
            "serviceRevision": values["REAL_AGENT_CONTROL_SERVICE_REVISION"],
            "apiRevision": values["REAL_AGENT_CONTROL_API_REVISION"],
            "fixtureRevision": values["REAL_AGENT_CONTROL_FIXTURE_REVISION"],
            "authHeaderName": values["REAL_AGENT_CONTROL_AUTH_HEADER_NAME"],
            "signingHeaderName": values["REAL_AGENT_CONTROL_SIGNING_HEADER_NAME"],
            "contractSourceRevision": json.loads(PINS_PATH.read_text(encoding="utf-8"))[
                "sourceBuildWorkaround"
            ]["revision"],
            "contractApiRevision": agent_control_pin["apiRevision"],
            "contractFixtureRevision": agent_control_pin["fixtureRevision"],
            "contractSwaggerSha256": agent_control_pin["swaggerSha256"],
        }
        document["checks"] = run(values, args.timeout)
        document["status"] = "passed"
        exit_code = 0
    except CompatibilityFailure as error:
        document["failureClassification"] = error.classification
        document["detail"] = str(error)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n")
    print(json.dumps(document, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
