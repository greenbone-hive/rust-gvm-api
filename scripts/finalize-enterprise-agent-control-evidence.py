#!/usr/bin/env python3
"""Finalize only the advisory enterprise emulator evidence bundle."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path


PASS = re.compile(
    r"test rest_enterprise_agent_control_lifecycle_is_repeatable_and_fail_closed .*?\bok\b",
    re.DOTALL,
)
FAILURE_EVIDENCE = re.compile(r"AGENT_CONTROL_FAILURE_EVIDENCE (\{[^\r\n]*\})")
FAILURE_EXPECTATIONS = {
    "authentication": [(401, "unauthorized"), (502, "backend_unavailable")],
    "unavailable": [(502, "backend_unavailable")],
    "malformed": [(502, "backend_unavailable")],
    "conflict": [(502, "backend_unavailable")],
    "rate-limit": [(502, "backend_unavailable")],
    "timeout": [(502, "backend_unavailable"), (504, "gateway_timeout")],
}


class FinalizationError(RuntimeError):
    """Enterprise evidence is incomplete or internally inconsistent."""


def load(path: Path) -> dict[str, object]:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise FinalizationError(f"cannot load {path}: {error}") from error


def load_optional(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    return load(path)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence_dir
    preflight = load_optional(root / "preflight.json")
    provenance = load_optional(root / "provenance.json")
    reset = load_optional(root / "reset-last.json")
    configuration = load_optional(root / "fixture-configuration.json")
    repetitions = []
    failure_scenarios = []
    for number in (1, 2):
        path = root / f"contracts-{number}.log"
        text = path.read_text() if path.is_file() else ""
        for match in FAILURE_EVIDENCE.finditer(text):
            try:
                scenario = json.loads(match.group(1))
            except json.JSONDecodeError as error:
                raise FinalizationError(
                    f"invalid failure-scenario evidence in {path}: {error}"
                ) from error
            scenario["repetition"] = number
            failure_scenarios.append(scenario)
        repetitions.append(
            {
                "number": number,
                "outcome": (
                    "pass" if PASS.search(text) else "fail" if path.is_file() else "not-run"
                ),
                "sha256": digest(path) if path.is_file() else None,
            }
        )
    failures_complete = True
    for number in (1, 2):
        observed = [
            item for item in failure_scenarios if item.get("repetition") == number
        ]
        if len(observed) != len(FAILURE_EXPECTATIONS):
            failures_complete = False
            continue
        for item in observed:
            expected = FAILURE_EXPECTATIONS.get(item.get("scenario"))
            allowed = [
                (entry.get("status"), entry.get("classification"))
                for entry in item.get("allowedMappings", [])
                if isinstance(entry, dict)
            ]
            observed_mapping = (item.get("observedStatus"), item.get("classification"))
            if (
                expected is None
                or allowed != expected
                or observed_mapping not in expected
                or item.get("injectedAt")
                != "upstream-agent-control-profile-selected-via-proxy"
                or item.get("outcome") != "pass"
            ):
                failures_complete = False
    passed = (
        preflight is not None
        and preflight.get("status") == "passed"
        and provenance is not None
        and provenance.get("lane") == "enterprise-agent-control-emulator-advisory"
        and reset is not None
        and reset.get("status") == "passed"
        and configuration is not None
        and configuration.get("status") == "passed"
        and all(item["outcome"] == "pass" for item in repetitions)
        and failures_complete
    )
    classification = None
    if preflight is None:
        classification = "setup"
    elif preflight.get("status") != "passed":
        classification = "preflight-configuration"
    elif not passed:
        classification = "enterprise-contract"
    document = {
        "schemaVersion": 1,
        "lane": "enterprise-agent-control-emulator-advisory",
        "advisory": True,
        "status": "passed" if passed else "failed",
        "failureClassification": classification,
        "promotionEligible": False,
        "universalCommunityGateChanged": False,
        "completedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "preflight": {
            "outcome": preflight.get("status") if preflight is not None else "not-run",
            "classification": preflight.get("classification") if preflight is not None else None,
            "rawResponsesRetained": preflight is not None and all(
                isinstance(preflight.get(key), dict) and "rawResponse" in preflight[key]
                for key in ("version", "features")
            ),
        },
        "contracts": [
            "auth-and-named-failures",
            "pagination",
            "agent-mutation-read-back",
            "scan-agent-configuration",
            "update-and-synchronization-state",
            "support-bundle-status-and-headers",
            "installer-instructions",
            "agent-group-lifecycle",
            "agent-backed-scan-correlation",
            "agent-backed-public-report-results",
            "agent-control-http-failure-mapping",
            "deterministic-reset-and-unmatched-fail-closed",
        ],
        "failureScenarios": failure_scenarios,
        "repeatability": repetitions,
        "provenanceSha256": digest(root / "provenance.json") if provenance is not None else None,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n")
    if not passed:
        raise FinalizationError(f"enterprise evidence failed: {classification}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
