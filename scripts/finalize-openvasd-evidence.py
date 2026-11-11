#!/usr/bin/env python3
"""Finalize per-contract, fault, and run evidence for an OpenVASD E2E job."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from secure_https import HttpsTransportError, https_get


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = REPOSITORY_ROOT / "tests" / "e2e" / "evidence" / "contract-inventory.json"
EXPECTED_FAULTS = {
    "http-400",
    "http-500",
    "malformed-body",
    "malformed-header",
    "timeout",
}
TEST_RESULT = re.compile(r"\btest (?P<name>\S+) \.\.\. (?P<result>ok|FAILED|ignored)\s*$")
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
FAULT_PREFIX = "FAULT_EVIDENCE "
GITHUB_API_HOST = "api.github.com"
LOG_REDIRECT_HOST_SUFFIXES = (
    ".actions.githubusercontent.com",
    ".blob.core.windows.net",
)


class FinalizationError(RuntimeError):
    """Evidence inputs are incomplete or internally inconsistent."""


def parse_test_results(text: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for line in text.splitlines():
        match = TEST_RESULT.search(ANSI_ESCAPE.sub("", line).strip())
        if not match:
            continue
        name = match.group("name").split("::")[-1]
        result = match.group("result")
        normalized = "pass" if result == "ok" else "fail" if result == "FAILED" else "not-run"
        previous = results.get(name)
        if previous is not None and previous != normalized:
            raise FinalizationError(f"conflicting cargo outcomes for test {name}")
        results[name] = normalized
    return results


def parse_fault_evidence(text: str) -> dict[str, Any]:
    scenarios: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        if FAULT_PREFIX not in line:
            continue
        payload = line.split(FAULT_PREFIX, 1)[1]
        try:
            item = json.loads(payload)
        except json.JSONDecodeError as error:
            raise FinalizationError(f"invalid fault evidence JSON: {error}") from error
        scenario = item.get("scenario")
        if scenario not in EXPECTED_FAULTS:
            raise FinalizationError(f"unknown fault scenario in evidence: {scenario!r}")
        if scenario in scenarios:
            raise FinalizationError(f"duplicate fault scenario in evidence: {scenario}")
        expected_keys = {"scenario", "injectedAt", "gatewayMapping", "target", "outcome"}
        if set(item) != expected_keys:
            raise FinalizationError(f"fault scenario {scenario} has incomplete fields")
        scenarios[scenario] = item
    for missing in EXPECTED_FAULTS - scenarios.keys():
        scenarios[missing] = {
            "scenario": missing,
            "injectedAt": "openvasd-http-boundary",
            "gatewayMapping": "not-run: shadow job did not produce scenario evidence",
            "target": "e2e-target",
            "outcome": "fail",
        }
    ordered = [scenarios[name] for name in sorted(scenarios)]
    return {
        "schemaVersion": 1,
        "lane": "community-direct-openvasd-shadow",
        "scenarios": ordered,
    }


def aggregate_outcomes(
    inventory: dict[str, Any],
    test_results: dict[str, str],
    fault_document: dict[str, Any],
) -> dict[str, str]:
    by_contract: dict[str, list[str]] = {
        contract: [] for contract in inventory["contractOwners"]
    }
    for test in inventory["tests"]:
        name = test["id"].rsplit("::", 1)[1]
        outcome = test_results.get(name, "not-run")
        for contract in test["contracts"]:
            by_contract[contract].append(outcome)

    fault_outcomes = {item["outcome"] for item in fault_document["scenarios"]}
    if len(fault_document["scenarios"]) == len(EXPECTED_FAULTS) and fault_outcomes == {"pass"}:
        by_contract["scanner.direct-openvasd-error-mapping"] = ["pass"]
    elif "fail" in fault_outcomes:
        by_contract["scanner.direct-openvasd-error-mapping"] = ["fail"]
    else:
        by_contract["scanner.direct-openvasd-error-mapping"] = ["not-run"]

    aggregated: dict[str, str] = {}
    for contract, outcomes in by_contract.items():
        if "fail" in outcomes:
            aggregated[contract] = "fail"
        elif outcomes and all(outcome == "pass" for outcome in outcomes):
            aggregated[contract] = "pass"
        else:
            aggregated[contract] = "not-run"
    return aggregated


def build_comparison(
    inventory: dict[str, Any],
    candidate_outcomes: dict[str, str],
    baseline_outcomes: dict[str, str],
) -> dict[str, Any]:
    contract_tests: dict[str, list[dict[str, Any]]] = {
        contract: [] for contract in inventory["contractOwners"]
    }
    for test in inventory["tests"]:
        for contract in test["contracts"]:
            contract_tests[contract].append(test)

    contracts = []
    for contract in sorted(inventory["contractOwners"]):
        tests = contract_tests[contract]
        osp_specific = bool(tests) and all(
            test["scannerPortability"] == "osp-specific" for test in tests
        )
        direct_only = bool(tests) and all(
            test["ospDisposition"] in {"replace", "retire"} for test in tests
        )
        candidate = candidate_outcomes[contract]
        if osp_specific:
            baseline = baseline_outcomes[contract]
            candidate = "not-run"
            disposition = "approved-exclusion"
        elif direct_only:
            baseline = "not-run"
            disposition = "backend-specific" if candidate == "pass" else "gap"
        else:
            baseline = baseline_outcomes[contract]
            disposition = "equivalent" if baseline == candidate == "pass" else "gap"
        contracts.append(
            {
                "contract": contract,
                "baseline": baseline,
                "candidate": candidate,
                "disposition": disposition,
                "ownerRole": inventory["contractOwners"][contract],
            }
        )
    return {
        "schemaVersion": 1,
        "baselineLane": "community-osp",
        "candidateLane": "community-direct-openvasd-shadow",
        "contracts": contracts,
    }


def https_response(
    host: str, target: str, headers: dict[str, str]
) -> tuple[int, dict[str, str], bytes]:
    if not target.startswith("/") or "\r" in target or "\n" in target:
        raise FinalizationError("refusing an invalid HTTPS request target")
    trusted_log_host = any(host.endswith(suffix) for suffix in LOG_REDIRECT_HOST_SUFFIXES)
    if host != GITHUB_API_HOST and not trusted_log_host:
        raise FinalizationError("refusing an HTTPS request to an untrusted host")
    if host == GITHUB_API_HOST and not target.startswith("/repos/"):
        raise FinalizationError("refusing a GitHub API path outside /repos")
    if host != GITHUB_API_HOST and any(name.lower() == "authorization" for name in headers):
        raise FinalizationError("refusing to forward GitHub authorization to a redirect host")
    try:
        return https_get(f"https://{host}{target}", headers)
    except HttpsTransportError as error:
        raise FinalizationError(str(error)) from error


def github_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "rust-gvm-api-e2e-evidence",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def github_json(path: str, token: str) -> dict[str, Any]:
    if not path.startswith("/repos/"):
        raise FinalizationError("refusing a GitHub API path outside /repos")
    status, _headers, body = https_response(
        GITHUB_API_HOST, path, github_headers(token)
    )
    if not 200 <= status < 300:
        raise FinalizationError(f"GitHub API request failed with HTTP {status}")
    return json.loads(body)


def github_text(path: str, token: str) -> str:
    if not path.startswith("/repos/"):
        raise FinalizationError("refusing a GitHub API path outside /repos")
    status, headers, body = https_response(GITHUB_API_HOST, path, github_headers(token))
    if status in {301, 302, 303, 307, 308}:
        location = headers.get("location", "")
        parsed = urlsplit(location)
        hostname = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or not any(hostname.endswith(suffix) for suffix in LOG_REDIRECT_HOST_SUFFIXES)
            or parsed.port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise FinalizationError("GitHub job log redirected to an untrusted URL")
        target = parsed.path or "/"
        if parsed.query:
            target += f"?{parsed.query}"
        # Signed Actions log URLs authenticate through their query string. Do
        # not forward the GitHub bearer token to the redirected storage host.
        status, _headers, body = https_response(
            hostname,
            target,
            {"User-Agent": "rust-gvm-api-e2e-evidence"},
        )
    if not 200 <= status < 300:
        raise FinalizationError(f"GitHub job log request failed with HTTP {status}")
    return body.decode("utf-8", errors="replace")


def parse_timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def elapsed(start: str | None, end: str | None) -> float:
    if not start or not end:
        return 0
    return max(0.0, (parse_timestamp(end) - parse_timestamp(start)).total_seconds())


def classify_failure(job: dict[str, Any], raw_dir: Path) -> str | None:
    if job.get("conclusion") == "success":
        return None
    marker = raw_dir / "application-failure"
    if marker.exists():
        return "application"
    phase_by_step = {
        "Fetch pinned OpenVASD fixtures": "setup",
        "Start direct-OpenVASD shadow runtime": "setup",
        "Verify direct-OpenVASD readiness and identities": "readiness",
        "Capture exact direct-OpenVASD provenance": "readiness",
        "Run all named community contracts": "assertion",
        "Exercise scanner failure mappings": "assertion",
        "Capture bounded direct-OpenVASD diagnostics": "application",
        "Tear down direct-OpenVASD shadow runtime": "cleanup",
    }
    for step in job.get("steps", []):
        if step.get("conclusion") in {"failure", "cancelled", "timed_out"}:
            return phase_by_step.get(step.get("name"), "runner")
    return "runner"


def build_run_evidence(
    job: dict[str, Any],
    artifacts: set[str],
    environment: dict[str, str],
    expected_artifact: str,
    raw_dir: Path,
) -> dict[str, Any]:
    conclusion = job.get("conclusion")
    if conclusion not in {"success", "failure", "timed_out"}:
        conclusion = "failure"
    steps = {step["name"]: step for step in job.get("steps", [])}
    startup_step = steps.get("Start direct-OpenVASD shadow runtime", {})
    test_steps = [
        steps.get("Run all named community contracts", {}),
        steps.get("Exercise scanner failure mappings", {}),
    ]
    classification = classify_failure(job, raw_dir)
    return {
        "runId": int(environment["GITHUB_RUN_ID"]),
        "runAttempt": int(environment["GITHUB_RUN_ATTEMPT"]),
        "runNumber": int(environment["GITHUB_RUN_NUMBER"]),
        "event": environment["GITHUB_EVENT_NAME"],
        "headBranch": environment.get("GITHUB_HEAD_REF")
        or environment.get("GITHUB_REF_NAME")
        or "detached",
        "headSha": environment["GITHUB_SHA"],
        "createdAt": job["started_at"],
        "runUrl": (
            f"https://github.com/{environment['GITHUB_REPOSITORY']}/actions/runs/"
            f"{environment['GITHUB_RUN_ID']}"
        ),
        "jobId": int(job["id"]),
        "jobUrl": job["html_url"],
        "conclusion": conclusion,
        "timingsSeconds": {
            "startup": elapsed(startup_step.get("started_at"), startup_step.get("completed_at")),
            "tests": sum(
                elapsed(step.get("started_at"), step.get("completed_at")) for step in test_steps
            ),
            "total": elapsed(job.get("started_at"), job.get("completed_at")),
        },
        "retried": int(environment["GITHUB_RUN_ATTEMPT"]) > 1,
        "artifacts": {
            "expected": [expected_artifact],
            "present": [expected_artifact] if expected_artifact in artifacts else [],
            "complete": expected_artifact in artifacts,
        },
        "failureClassification": classification,
        "failureOwnerRole": "community-contract-lane" if classification else None,
    }


def resolve_job_and_artifacts(
    repository: str,
    run_id: str,
    run_attempt: str,
    job_name: str,
    osp_job_name: str,
    token: str,
) -> tuple[dict[str, Any], dict[str, Any], set[str]]:
    base = f"/repos/{repository}/actions/runs/{run_id}"
    jobs = github_json(
        f"{base}/attempts/{run_attempt}/jobs?per_page=100", token
    ).get("jobs", [])
    matches = [job for job in jobs if job.get("name") == job_name]
    if len(matches) != 1:
        raise FinalizationError(f"expected one completed job named {job_name!r}, found {len(matches)}")
    osp_matches = [job for job in jobs if job.get("name") == osp_job_name]
    if len(osp_matches) != 1:
        raise FinalizationError(
            f"expected one completed job named {osp_job_name!r}, found {len(osp_matches)}"
        )
    artifacts = set()
    for artifact in github_json(f"{base}/artifacts?per_page=100", token).get(
        "artifacts", []
    ):
        if artifact.get("expired"):
            continue
        created_at = artifact.get("created_at")
        if created_at and parse_timestamp(created_at) >= parse_timestamp(matches[0]["started_at"]):
            artifacts.add(artifact["name"])
    return matches[0], osp_matches[0], artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--job-name", required=True)
    parser.add_argument("--osp-job-name", required=True)
    parser.add_argument("--raw-artifact", required=True)
    args = parser.parse_args()

    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    cargo_log = (args.raw_dir / "cargo.log").read_text(encoding="utf-8") if (args.raw_dir / "cargo.log").exists() else ""
    fault_log = (args.raw_dir / "faults.log").read_text(encoding="utf-8") if (args.raw_dir / "faults.log").exists() else ""
    fault_document = parse_fault_evidence(fault_log)
    outcomes = aggregate_outcomes(inventory, parse_test_results(cargo_log), fault_document)

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise FinalizationError("GITHUB_TOKEN is required to resolve exact job/artifact evidence")
    job, osp_job, artifacts = resolve_job_and_artifacts(
        os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_RUN_ID"],
        os.environ["GITHUB_RUN_ATTEMPT"],
        args.job_name,
        args.osp_job_name,
        token,
    )
    osp_log = github_text(
        f"/repos/{os.environ['GITHUB_REPOSITORY']}/actions/jobs/"
        f"{osp_job['id']}/logs",
        token,
    )
    baseline_outcomes = aggregate_outcomes(
        inventory,
        parse_test_results(osp_log),
        parse_fault_evidence(""),
    )
    comparison = build_comparison(inventory, outcomes, baseline_outcomes)
    run_evidence = build_run_evidence(job, artifacts, dict(os.environ), args.raw_artifact, args.raw_dir)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, document in (
        ("comparison.json", comparison),
        ("fault-mappings.json", fault_document),
        ("run-evidence.json", run_evidence),
    ):
        (args.output_dir / name).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"finalized direct-OpenVASD evidence for job {job['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
