#!/usr/bin/env python3
"""Evaluate Phase 3 direct-HTTP promotion and rollback readiness, fail closed."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

from shadow_evidence_ledger import LedgerError, observation_from_ledger, validate_ledger


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "tests" / "e2e" / "evidence"
DEFAULT_BASELINE = EVIDENCE_ROOT / "baselines" / "osp-required.json"
DEFAULT_INVENTORY = EVIDENCE_ROOT / "contract-inventory.json"
DEFAULT_DECISION = EVIDENCE_ROOT / "promotion-decision.json"
DEFAULT_ROLLBACK_EVENTS = EVIDENCE_ROOT / "rollback-events.json"
EXPECTED_DIAGNOSTICS = {
    "compose-ps.txt",
    "compose.log",
    "runner-container-runtime.txt",
}
EXISTING_REQUIRED_STATUSES = {
    "REST Discovery Scan E2E (main)",
    "REST Discovery Scan E2E (devel)",
}
CANDIDATE_STATUSES = {
    "Direct OpenVASD E2E (main candidate, advisory)",
    "Direct OpenVASD E2E (devel candidate, advisory)",
}


class EvaluationError(ValueError):
    """An input is incomplete, malformed, or inconsistent."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvaluationError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{path} must contain a JSON object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise EvaluationError(
            f"{context} keys differ: missing={sorted(expected - value.keys())} "
            f"unknown={sorted(value.keys() - expected)}"
        )


def timestamp(value: Any, context: str) -> dt.datetime:
    if not isinstance(value, str):
        raise EvaluationError(f"{context} must be a timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvaluationError(f"{context} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise EvaluationError(f"{context} must include a timezone")
    return parsed


def nearest_rank(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[math.ceil(percentile * len(ordered)) - 1]


def provenance_fingerprint(provenance: dict[str, Any]) -> str:
    required = {
        "schemaVersion",
        "gvmd",
        "scanner",
        "feedData",
        "fixtures",
        "apiContract",
        "composeSha256",
        "runner",
    }
    if provenance.get("schemaVersion") != 1 or not required <= provenance.keys():
        raise EvaluationError("retained provenance is incomplete")
    fixtures = provenance.get("fixtures")
    if not isinstance(fixtures, list):
        raise EvaluationError("retained provenance fixtures must be an array")
    fixture_revisions = {
        item.get("name"): item.get("revision")
        for item in fixtures
        if isinstance(item, dict)
    }
    required_inputs = {
        "tests/e2e/compose.direct-openvasd.yaml",
        "synthetic-target-image",
        "tests/e2e/evidence/direct-openvasd-pins.json",
        "gvm-openapi-emulator/examples/openvasd/swagger.json",
        "gvm-openapi-emulator/examples/openvasd",
        "tests/e2e-harness",
    }
    for name in required_inputs:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(fixture_revisions.get(name))):
            raise EvaluationError(f"retained provenance input {name!r} is not exact")
    identities = {
        "GVM_GATEWAY_E2E_TARGET_HOST": "e2e-target",
        "scanner-backend-identity": "openvasd-backend",
        "synthetic-target-identity": "e2e-target",
    }
    for name, expected in identities.items():
        if fixture_revisions.get(name) != expected:
            raise EvaluationError(f"retained provenance identity {name!r} is invalid")
    comparable = {
        name: provenance[name] for name in sorted(required - {"runner"})
    }
    encoded = json.dumps(comparable, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_observation(document: dict[str, Any]) -> list[dict[str, Any]]:
    exact_keys(
        document,
        {
            "schemaVersion",
            "generatedAt",
            "repository",
            "workflow",
            "job",
            "comparisonFingerprint",
            "gate",
            "runs",
        },
        "observation",
    )
    if document["schemaVersion"] != 1:
        raise EvaluationError("observation schemaVersion must equal 1")
    if (
        document["repository"] != "greenbone-hive/rust-gvm-api"
        or document["workflow"] != ".github/workflows/nightly-e2e.yml"
        or document["job"] != "Direct OpenVASD Shadow E2E (advisory)"
        or not (
            re.fullmatch(r"[0-9a-f]{64}", document["comparisonFingerprint"])
            or (document["comparisonFingerprint"] == "unavailable" and not document["runs"])
        )
    ):
        raise EvaluationError("observation source or fingerprint is invalid")
    timestamp(document["generatedAt"], "observation.generatedAt")
    runs = document["runs"]
    if not isinstance(runs, list):
        raise EvaluationError("observation.runs must be an array")
    ids: set[tuple[int, int]] = set()
    for run in runs:
        if not isinstance(run, dict):
            raise EvaluationError("every observation run must be an object")
        exact_keys(
            run,
            {
                "runId",
                "runAttempt",
                "event",
                "headSha",
                "createdAt",
                "runUrl",
                "jobId",
                "jobUrl",
                "conclusion",
                "evidenceArtifactId",
                "provenanceSha256",
            },
            "observation run",
        )
        identity = (run.get("runId"), run.get("runAttempt"))
        if not all(isinstance(item, int) and item > 0 for item in identity):
            raise EvaluationError("observation run identity is invalid")
        if identity in ids:
            raise EvaluationError("observation contains a duplicate run attempt")
        ids.add(identity)
        timestamp(run.get("createdAt"), "observation run createdAt")
    gate = document.get("gate")
    if not isinstance(gate, dict):
        raise EvaluationError("observation.gate must be an object")
    exact_keys(
        gate,
        {"requiredRuns", "requiredDays", "observedRuns", "spanDays", "satisfied"},
        "observation.gate",
    )
    if gate.get("requiredRuns", 0) < 30 or gate.get("requiredDays", 0) < 14:
        raise EvaluationError("observation gate weakens the 30-run/14-day minimum")
    return runs


def validate_decision(document: dict[str, Any]) -> None:
    exact_keys(
        document,
        {
            "schemaVersion",
            "status",
            "evidenceRange",
            "exclusions",
            "approver",
            "effectiveStatusNames",
            "incidentContact",
            "effectiveAt",
            "rollbackWindow",
        },
        "decision",
    )
    if document["schemaVersion"] != 1 or document["status"] not in {
        "observing",
        "approved",
    }:
        raise EvaluationError("decision version or status is invalid")
    statuses = document.get("effectiveStatusNames")
    if not isinstance(statuses, dict) or set(statuses) != {
        "existingRequired",
        "candidate",
    }:
        raise EvaluationError("decision effectiveStatusNames is incomplete")
    if set(statuses["existingRequired"]) != EXISTING_REQUIRED_STATUSES:
        raise EvaluationError("decision must preserve the existing OSP required statuses")
    if set(statuses["candidate"]) != CANDIDATE_STATUSES:
        raise EvaluationError("decision candidate status names do not match the workflows")
    incident = document.get("incidentContact")
    if (
        not isinstance(incident, dict)
        or incident.get("ownerRole") != "promotion-rollback-incident"
        or not isinstance(incident.get("handle"), str)
        or not incident["handle"]
    ):
        raise EvaluationError("decision incident contact is incomplete")
    window = document.get("rollbackWindow")
    if (
        not isinstance(window, dict)
        or window.get("minimumDays", 0) < 14
        or window.get("minimumEligibleRequiredRuns", 0) < 30
    ):
        raise EvaluationError("decision rollback window weakens its minimum")
    if not isinstance(document.get("exclusions"), list):
        raise EvaluationError("decision exclusions must be an array")


def evidence_packages(root: Path) -> dict[tuple[int, int], dict[str, Any]]:
    packages: dict[tuple[int, int], dict[str, Any]] = {}
    for run_path in sorted(root.rglob("run-evidence.json")):
        directory = run_path.parent
        required = {
            "comparison": directory / "comparison.json",
            "faults": directory / "fault-mappings.json",
            "provenance": directory / "provenance.json",
            "run": run_path,
        }
        if any(not path.is_file() for path in required.values()):
            continue
        package = {name: load_json(path) for name, path in required.items()}
        diagnostics_path = directory / "diagnostic-evidence.json"
        package["diagnostics"] = (
            load_json(diagnostics_path) if diagnostics_path.is_file() else None
        )
        run = package["run"]
        identity = (run.get("runId"), run.get("runAttempt"))
        if not all(isinstance(item, int) and item > 0 for item in identity):
            raise EvaluationError(f"invalid run identity in {run_path}")
        if identity in packages:
            raise EvaluationError(f"duplicate retained evidence for run {identity}")
        package["directory"] = str(directory)
        package["provenanceBytes"] = required["provenance"].read_bytes()
        packages[identity] = package
    return packages


def decision_range(
    runs: list[dict[str, Any]], fingerprint: str, ledger_head: str | None = None
) -> dict[str, Any]:
    if not runs:
        return {
            "comparisonFingerprint": fingerprint,
            "ledgerHeadSha256": ledger_head,
            "oldestRunId": None,
            "newestRunId": None,
            "oldestCreatedAt": None,
            "newestCreatedAt": None,
        }
    ordered = sorted(runs, key=lambda run: timestamp(run["createdAt"], "createdAt"))
    return {
        "comparisonFingerprint": fingerprint,
        "ledgerHeadSha256": ledger_head,
        "oldestRunId": ordered[0]["runId"],
        "newestRunId": ordered[-1]["runId"],
        "oldestCreatedAt": ordered[0]["createdAt"],
        "newestCreatedAt": ordered[-1]["createdAt"],
    }


def add_check(
    checks: list[dict[str, Any]],
    name: str,
    passed: bool,
    actual: Any,
    threshold: str,
    reasons: list[str] | None = None,
) -> None:
    checks.append(
        {
            "name": name,
            "passed": bool(passed),
            "actual": actual,
            "threshold": threshold,
            "reasons": reasons or [],
        }
    )


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    try:
        ledger = validate_ledger(args.ledger_root)
        observation = observation_from_ledger(args.ledger_root)
    except LedgerError as error:
        raise EvaluationError(f"durable evidence ledger is invalid: {error}") from error
    observed_runs = validate_observation(observation)
    decision = load_json(args.decision)
    validate_decision(decision)
    inventory = load_json(args.inventory)
    baseline = load_json(args.baseline)
    if (
        inventory.get("schemaVersion") != 1
        or not isinstance(inventory.get("contractOwners"), dict)
        or not inventory["contractOwners"]
        or not isinstance(inventory.get("tests"), list)
    ):
        raise EvaluationError("contract inventory is incomplete")
    if (
        baseline.get("schemaVersion") != 1
        or baseline.get("repository") != "greenbone/rust-gvm-api"
        or baseline.get("job") != "REST Discovery Scan E2E"
        or baseline.get("eligibility", {}).get("requiredRuns", 0) < 30
        or len(baseline.get("runs", [])) < 30
    ):
        raise EvaluationError("Phase 0 OSP baseline is incomplete or misidentified")
    events = load_json(args.rollback_events)
    if set(events) != {"schemaVersion", "events"} or events["schemaVersion"] != 1:
        raise EvaluationError("rollback event manifest is invalid")
    if not isinstance(events["events"], list):
        raise EvaluationError("rollback events must be an array")

    packages = evidence_packages(args.ledger_root / "runs")
    checks: list[dict[str, Any]] = []
    matched: list[tuple[dict[str, Any], dict[str, Any]]] = []
    raw_reasons: list[str] = []
    fingerprint = observation["comparisonFingerprint"]
    for observed in observed_runs:
        identity = (observed["runId"], observed["runAttempt"])
        package = packages.get(identity)
        if package is None:
            raw_reasons.append(f"missing retained finalized evidence for run {identity}")
            continue
        run = package["run"]
        for field in ("runId", "runAttempt", "runUrl", "jobId", "jobUrl", "conclusion"):
            if run.get(field) != observed.get(field):
                raw_reasons.append(f"run {identity} retained {field} does not match observation")
        provenance_sha = hashlib.sha256(package["provenanceBytes"]).hexdigest()
        if provenance_sha != observed.get("provenanceSha256"):
            raw_reasons.append(f"run {identity} provenance hash does not match observation")
        if provenance_fingerprint(package["provenance"]) != fingerprint:
            raw_reasons.append(f"run {identity} provenance fingerprint is not comparable")
        rows = package["comparison"].get("contracts")
        names = [row.get("contract") for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
        if (
            len(names) != len(set(names))
            or set(names) != set(inventory["contractOwners"])
        ):
            raw_reasons.append(f"run {identity} comparison does not exactly cover the inventory")
        elif any(
            set(row)
            != {"contract", "baseline", "candidate", "disposition", "ownerRole"}
            or row.get("baseline") not in {"pass", "fail", "not-run"}
            or row.get("candidate") not in {"pass", "fail", "not-run"}
            or row.get("ownerRole") != inventory["contractOwners"][row["contract"]]
            for row in rows
        ):
            raw_reasons.append(f"run {identity} comparison row is malformed or unowned")
        matched.append((observed, package))
    add_check(
        checks,
        "retained-raw-evidence-and-provenance",
        not raw_reasons and len(matched) == len(observed_runs) and bool(matched),
        {"observedRuns": len(observed_runs), "matchedPackages": len(matched)},
        "every observed run has identity- and hash-matched finalized raw evidence",
        raw_reasons,
    )

    exclusions_by_run: dict[int, dict[str, Any]] = {}
    exclusion_reasons: list[str] = []
    matched_by_run = {observed["runId"]: package for observed, package in matched}
    for exclusion in decision["exclusions"]:
        if not isinstance(exclusion, dict) or set(exclusion) != {
            "runId",
            "jobUrl",
            "classification",
            "reason",
            "ownerRole",
            "incidentUrl",
        }:
            exclusion_reasons.append("an exclusion has incomplete or unknown fields")
            continue
        run_id = exclusion.get("runId")
        package = matched_by_run.get(run_id)
        if run_id in exclusions_by_run:
            exclusion_reasons.append(f"run {run_id} is excluded more than once")
        elif (
            package is None
            or exclusion.get("classification") != "external-runner-outage"
            or exclusion.get("ownerRole") != "promotion-rollback-incident"
            or package["run"].get("failureClassification") != "runner"
            or package["run"].get("jobUrl") != exclusion.get("jobUrl")
            or not all(
                isinstance(exclusion.get(field), str) and exclusion[field]
                for field in ("reason", "incidentUrl")
            )
        ):
            exclusion_reasons.append(f"run {run_id} is not a documented external runner outage")
        else:
            exclusions_by_run[run_id] = exclusion
    add_check(
        checks,
        "documented-exclusions-only",
        not exclusion_reasons,
        {"documentedExternalRunnerOutages": len(exclusions_by_run)},
        "only raw runner failures with reason, owner, job URL, and incident URL may be excluded",
        exclusion_reasons,
    )

    eligible = [item for item in matched if item[0]["runId"] not in exclusions_by_run]
    gate = observation["gate"]
    timestamps = [timestamp(run["createdAt"], "createdAt") for run, _ in eligible]
    span_days = (
        (max(timestamps) - min(timestamps)).total_seconds() / 86400
        if len(timestamps) > 1
        else 0.0
    )
    add_check(
        checks,
        "observation-window",
        len(eligible) >= 30 and span_days >= 14 and gate.get("satisfied") is True,
        {"eligibleRuns": len(eligible), "spanDays": span_days},
        ">=30 eligible comparable runs spanning >=14 days",
    )

    tests_by_contract: dict[str, list[dict[str, Any]]] = {
        name: [] for name in inventory.get("contractOwners", {})
    }
    for test in inventory.get("tests", []):
        for contract in test.get("contracts", []):
            tests_by_contract.setdefault(contract, []).append(test)
    osp_specific = {
        contract
        for contract, tests in tests_by_contract.items()
        if tests and all(test.get("scannerPortability") == "osp-specific" for test in tests)
    }
    named_contracts = set(inventory.get("contractOwners", {})) - osp_specific
    cells = 0
    executed_cells = 0
    regressions: list[dict[str, Any]] = []
    run_passes = 0
    run_pass_by_id: dict[int, bool] = {}
    for observed, package in eligible:
        rows = package["comparison"].get("contracts", [])
        by_name = {row.get("contract"): row for row in rows if isinstance(row, dict)}
        run_pass = package["run"].get("conclusion") == "success"
        for contract in named_contracts:
            cells += 1
            row = by_name.get(contract)
            if row and row.get("candidate") != "not-run":
                executed_cells += 1
            if not row or row.get("candidate") != "pass":
                run_pass = False
            if row and row.get("baseline") == "pass" and row.get("candidate") == "fail":
                regressions.append({"runId": observed["runId"], "contract": contract})
        if run_pass:
            run_passes += 1
        run_pass_by_id[observed["runId"]] = run_pass
    coverage = executed_cells / cells if cells else 0.0
    add_check(
        checks,
        "named-non-osp-contract-coverage",
        coverage == 1.0 and bool(named_contracts),
        {"coverage": coverage, "namedContracts": len(named_contracts), "cells": cells},
        "100%",
    )
    pass_rate = run_passes / len(eligible) if eligible else 0.0
    add_check(
        checks,
        "eligible-pass-rate",
        pass_rate >= 0.99,
        {"passRate": pass_rate, "passedRuns": run_passes, "eligibleRuns": len(eligible)},
        ">=99% after documented external runner outages only",
    )

    latest_twenty = sorted(
        eligible,
        key=lambda item: timestamp(item[0]["createdAt"], "createdAt"),
        reverse=True,
    )[:20]
    flakes = [
        observed["runId"]
        for observed, package in latest_twenty
        if package["run"].get("failureClassification") == "unexplained-flake"
    ]
    add_check(
        checks,
        "latest-20-unexplained-flakes",
        len(latest_twenty) == 20 and not flakes,
        {"windowRuns": len(latest_twenty), "unexplainedFlakes": flakes},
        "20 eligible runs and zero unexplained flakes",
    )

    retries = sum(bool(package["run"].get("retried")) for _, package in eligible)
    retry_rate = retries / len(eligible) if eligible else 0.0
    add_check(
        checks,
        "infrastructure-retry-rate",
        bool(eligible) and retry_rate <= 0.01,
        {"retryRate": retry_rate, "retriedRuns": retries},
        "<=1%",
    )
    total_times = [float(package["run"]["timingsSeconds"]["total"]) for _, package in eligible]
    shadow_p95 = nearest_rank(total_times, 0.95)
    baseline_p95 = float(baseline.get("summary", {}).get("totalSeconds", {}).get("p95", 0))
    runtime_limit = baseline_p95 * 1.2
    add_check(
        checks,
        "shadow-p95-runtime",
        shadow_p95 is not None and baseline_p95 > 0 and shadow_p95 <= runtime_limit,
        {"shadowP95Seconds": shadow_p95, "ospBaselineP95Seconds": baseline_p95},
        f"<={runtime_limit:g} seconds (120% of Phase 0 OSP P95)",
    )

    diagnostic_missing: list[int] = []
    failed_missing: list[int] = []
    for observed, package in eligible:
        diagnostics = package["diagnostics"]
        complete = (
            isinstance(diagnostics, dict)
            and diagnostics.get("runId") == observed["runId"]
            and diagnostics.get("runAttempt") == observed["runAttempt"]
            and set(diagnostics.get("expected", [])) == EXPECTED_DIAGNOSTICS
            and set(diagnostics.get("present", [])) == EXPECTED_DIAGNOSTICS
            and diagnostics.get("complete") is True
        )
        if not complete:
            diagnostic_missing.append(observed["runId"])
            if package["run"].get("conclusion") in {"failure", "timed_out"}:
                failed_missing.append(observed["runId"])
    completeness = (
        (len(eligible) - len(diagnostic_missing)) / len(eligible) if eligible else 0.0
    )
    add_check(
        checks,
        "diagnostic-completeness",
        completeness == 1.0,
        {"rate": completeness, "missingRunIds": diagnostic_missing},
        "100% bounded diagnostic documents and files",
    )

    compatibility_reasons: list[str] = []
    compatibility: dict[str, Any] | None = None
    if args.compatibility is None or args.compatibility_provenance is None:
        compatibility_reasons.append("no real-OpenVASD compatibility result was supplied")
    else:
        compatibility = load_json(args.compatibility)
        expected_compatibility = {
            "schemaVersion", "repository", "workflow", "job", "runId", "runAttempt",
            "runUrl", "headSha", "completedAt", "conclusion", "provenanceSha256",
            "unresolvedReleaseBlockingDrift",
        }
        if set(compatibility) != expected_compatibility:
            compatibility_reasons.append("compatibility result fields are incomplete or unknown")
        elif (
            compatibility.get("schemaVersion") != 1
            or compatibility.get("workflow") != ".github/workflows/real-openvasd-compatibility.yml"
            or compatibility.get("job") != "Real OpenVASD Direct-HTTP Compatibility (advisory)"
            or compatibility.get("repository") != "greenbone-hive/rust-gvm-api"
            or compatibility.get("conclusion") != "success"
            or compatibility.get("unresolvedReleaseBlockingDrift") != []
            or not re.fullmatch(r"[0-9a-f]{40}", str(compatibility.get("headSha")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(compatibility.get("provenanceSha256")))
        ):
            compatibility_reasons.append("compatibility did not pass with complete provenance and zero drift")
        else:
            timestamp(compatibility["completedAt"], "compatibility.completedAt")
            expected_run_url = (
                "https://github.com/greenbone-hive/rust-gvm-api/actions/runs/"
                f"{compatibility['runId']}"
            )
            if compatibility.get("runUrl") != expected_run_url:
                compatibility_reasons.append("compatibility run URL does not match its identity")
            try:
                compatibility_provenance = args.compatibility_provenance.read_bytes()
                parsed_provenance = json.loads(compatibility_provenance)
            except (OSError, json.JSONDecodeError) as error:
                compatibility_reasons.append(f"cannot load compatibility provenance: {error}")
            else:
                if (
                    not isinstance(parsed_provenance, dict)
                    or parsed_provenance.get("schemaVersion") != 1
                    or hashlib.sha256(compatibility_provenance).hexdigest()
                    != compatibility["provenanceSha256"]
                ):
                    compatibility_reasons.append("compatibility provenance hash or version does not match")
    add_check(
        checks,
        "latest-real-openvasd-compatibility",
        not compatibility_reasons,
        compatibility,
        "successful supplied latest result with exact provenance and no release-blocking drift",
        compatibility_reasons,
    )

    ledger_head = ledger["entries"][-1]["entrySha256"] if ledger["entries"] else None
    observed_range = decision_range(observed_runs, fingerprint, ledger_head)
    approval_reasons: list[str] = []
    if decision["status"] != "approved":
        approval_reasons.append("decision status remains observing")
    if decision.get("evidenceRange") != observed_range:
        approval_reasons.append("recorded evidence range does not exactly match the observation")
    approver = decision.get("approver")
    if not isinstance(approver, dict) or set(approver) != {
        "identity", "approvedAt", "recordUrl"
    }:
        approval_reasons.append("recorded approver, approval time, and approval URL are required")
    else:
        approved_at = timestamp(approver["approvedAt"], "decision.approver.approvedAt")
        if observed_runs:
            newest_evidence = max(
                timestamp(run["createdAt"], "createdAt") for run in observed_runs
            )
            if approved_at < newest_evidence:
                approval_reasons.append("approval predates the recorded evidence range")
    if decision.get("effectiveAt") is None:
        approval_reasons.append("effectiveAt is not recorded")
    else:
        effective_time = timestamp(decision["effectiveAt"], "decision.effectiveAt")
        if isinstance(approver, dict) and effective_time < timestamp(
            approver["approvedAt"], "decision.approver.approvedAt"
        ):
            approval_reasons.append("effectiveAt predates approval")
    add_check(
        checks,
        "recorded-approval",
        not approval_reasons,
        {"status": decision["status"], "approver": approver, "effectiveAt": decision.get("effectiveAt")},
        "explicit approved decision bound to the exact evidence range",
        approval_reasons,
    )

    generated_at = timestamp(observation["generatedAt"], "observation.generatedAt")
    false_gate_events: list[dict[str, Any]] = []
    event_reasons: list[str] = []
    event_run_ids: set[int] = set()
    for event in events["events"]:
        expected_event = {"kind", "runId", "jobUrl", "occurredAt", "reproducedAt", "issueUrl", "ownerRole"}
        if not isinstance(event, dict) or set(event) != expected_event:
            event_reasons.append("rollback event has incomplete or unknown fields")
            continue
        occurred = timestamp(event["occurredAt"], "rollback event occurredAt")
        reproduced = timestamp(event["reproducedAt"], "rollback event reproducedAt")
        if (
            event["kind"] != "emulator-false-gate-failure"
            or event["ownerRole"] != "promotion-rollback-incident"
            or reproduced < occurred
            or event["runId"] in event_run_ids
        ):
            event_reasons.append(f"rollback event for run {event.get('runId')} is invalid")
            continue
        event_run_ids.add(event["runId"])
        if dt.timedelta(0) <= generated_at - occurred <= dt.timedelta(days=7):
            false_gate_events.append(event)

    add_check(
        checks,
        "classified-rollback-events",
        not event_reasons,
        {"events": len(events["events"]), "validEvents": len(event_run_ids)},
        "every rollback event is complete, uniquely identified, and reproducible",
        event_reasons,
    )

    latest_twenty_passes = sum(
        run_pass_by_id.get(observed["runId"], False)
        for observed, _package in latest_twenty
    )
    latest_twenty_pass_rate = (
        latest_twenty_passes / len(latest_twenty) if latest_twenty else 0.0
    )
    rollback_indicators = [
        {
            "trigger": "named-regression-missed-vs-osp",
            "fired": bool(regressions),
            "count": len(regressions),
            "evidence": regressions,
        },
        {
            "trigger": "two-reproducible-emulator-false-gate-failures-in-7-days",
            "fired": len(false_gate_events) >= 2,
            "count": len(false_gate_events),
            "evidence": false_gate_events,
            "inputErrors": event_reasons,
        },
        {
            "trigger": "latest-20-pass-rate-or-flake-regression",
            "fired": len(latest_twenty) == 20 and (latest_twenty_pass_rate < 0.99 or bool(flakes)),
            "count": len(flakes),
            "evidence": {"windowRuns": len(latest_twenty), "passRate": latest_twenty_pass_rate, "unexplainedFlakes": flakes},
        },
        {
            "trigger": "missing-diagnostics-for-two-completed-failures",
            "fired": len(failed_missing) >= 2,
            "count": len(failed_missing),
            "evidence": failed_missing,
        },
    ]

    effective_at = decision.get("effectiveAt")
    rollback_runs = 0
    rollback_days = 0.0
    if effective_at is not None:
        effective_time = timestamp(effective_at, "decision.effectiveAt")
        after_effective = [
            run for run, _ in eligible
            if timestamp(run["createdAt"], "createdAt") >= effective_time
        ]
        rollback_runs = len(after_effective)
        rollback_days = max(0.0, (generated_at - effective_time).total_seconds() / 86400)
    window = decision["rollbackWindow"]
    rollback_complete = (
        effective_at is not None
        and rollback_days >= window["minimumDays"]
        and rollback_runs >= window["minimumEligibleRequiredRuns"]
    )
    promotion_ready = all(check["passed"] for check in checks)
    return {
        "schemaVersion": 1,
        "generatedAt": observation["generatedAt"],
        "mode": "approved" if promotion_ready else "observing",
        "promotionReady": promotion_ready,
        "evidenceRange": observed_range,
        "exclusions": decision["exclusions"],
        "approver": decision["approver"],
        "effectiveStatusNames": decision["effectiveStatusNames"],
        "incidentContact": decision["incidentContact"],
        "effectiveAt": decision["effectiveAt"],
        "checks": checks,
        "rollbackWindow": {
            "minimumDays": window["minimumDays"],
            "minimumEligibleRequiredRuns": window["minimumEligibleRequiredRuns"],
            "observedDays": rollback_days,
            "observedEligibleRequiredRuns": rollback_runs,
            "closureEligible": rollback_complete,
        },
        "rollbackIndicators": rollback_indicators,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger-root", required=True, type=Path)
    parser.add_argument("--compatibility", type=Path)
    parser.add_argument("--compatibility-provenance", type=Path)
    parser.add_argument("--decision", default=DEFAULT_DECISION, type=Path)
    parser.add_argument("--rollback-events", default=DEFAULT_ROLLBACK_EVENTS, type=Path)
    parser.add_argument("--baseline", default=DEFAULT_BASELINE, type=Path)
    parser.add_argument("--inventory", default=DEFAULT_INVENTORY, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--allow-observing",
        action="store_true",
        help="write an unmet advisory report without returning a failing status",
    )
    args = parser.parse_args()
    try:
        report = evaluate(args)
    except EvaluationError as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"Phase 3 mode={report['mode']} promotionReady="
        f"{str(report['promotionReady']).lower()}"
    )
    if not report["promotionReady"] and not args.allow_observing:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
