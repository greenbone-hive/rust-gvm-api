#!/usr/bin/env python3
"""Collect a reproducible baseline of executed E2E jobs from GitHub Actions."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import statistics
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


ELIGIBLE_CONCLUSIONS = {"success", "failure", "timed_out"}
WORKFLOW = "nightly-e2e.yml"
WORKFLOW_PATH = ".github/workflows/nightly-e2e.yml"
JOB_NAME = "REST Discovery Scan E2E"
STARTUP_STEP = "Start compose-backed runtime"
TEST_STEP = "Run REST discovery-scan E2E suite"
EXPECTED_ARTIFACTS = ["e2e-compose-diagnostics"]


def gh_api(endpoint: str) -> Any:
    completed = subprocess.run(
        ["gh", "api", endpoint],
        check=True,
        text=True,
        capture_output=True,
    )
    return json.loads(completed.stdout)


def parse_timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def duration_seconds(started_at: str, completed_at: str) -> int:
    return int((parse_timestamp(completed_at) - parse_timestamp(started_at)).total_seconds())


def step_duration_seconds(step: dict[str, Any]) -> int:
    if not step.get("started_at") or not step.get("completed_at"):
        return 0
    return duration_seconds(step["started_at"], step["completed_at"])


def failure_classification(conclusion: str, startup_step: dict[str, Any]) -> str | None:
    if conclusion == "success":
        return None
    if startup_step.get("conclusion") in {"failure", "timed_out"}:
        return "setup"
    return "unclassified"


def nearest_rank(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    return ordered[math.ceil(percentile * len(ordered)) - 1]


def summarize(values: list[int]) -> dict[str, float | int]:
    return {
        "p50": statistics.median(values),
        "p95": nearest_rank(values, 0.95),
        "min": min(values),
        "max": max(values),
    }


def fetch_completed_runs(repository: str, page: int) -> list[dict[str, Any]]:
    response = gh_api(
        f"repos/{repository}/actions/workflows/{WORKFLOW}/runs"
        f"?status=completed&per_page=100&page={page}"
    )
    return response["workflow_runs"]


def normalize_run(repository: str, run: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    jobs = gh_api(f"repos/{repository}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")["jobs"]
    matching_jobs = [job for job in jobs if job["name"] == JOB_NAME]
    if not matching_jobs:
        return None, "missing-job"
    if len(matching_jobs) != 1:
        return None, "ambiguous-job"
    job = matching_jobs[0]
    if job.get("conclusion") == "skipped":
        return None, "docs-only-or-policy-skip"
    if job.get("conclusion") == "cancelled":
        return None, "concurrency-or-manual-cancellation"
    if job.get("conclusion") not in ELIGIBLE_CONCLUSIONS:
        return None, "non-executed-or-unsupported-conclusion"
    if not job.get("started_at") or not job.get("completed_at"):
        return None, "missing-job-timestamps"

    steps = {step["name"]: step for step in job.get("steps", [])}
    for step_name in (STARTUP_STEP, TEST_STEP):
        if step_name not in steps:
            return None, "missing-required-step-evidence"

    conclusion = job["conclusion"]
    if conclusion == "success" and any(
        not steps[step_name].get("started_at") or not steps[step_name].get("completed_at")
        for step_name in (STARTUP_STEP, TEST_STEP)
    ):
        return None, "missing-required-step-evidence"

    artifacts = gh_api(f"repos/{repository}/actions/runs/{run['id']}/artifacts?per_page=100")["artifacts"]
    artifact_names = sorted({artifact["name"] for artifact in artifacts})
    return {
        "runId": run["id"],
        "runAttempt": run["run_attempt"],
        "runNumber": run["run_number"],
        "event": run["event"],
        "headBranch": run["head_branch"],
        "headSha": run["head_sha"],
        "createdAt": run["created_at"],
        "runUrl": run["html_url"],
        "jobId": job["id"],
        "jobUrl": job["html_url"],
        "conclusion": conclusion,
        "timingsSeconds": {
            "startup": step_duration_seconds(steps[STARTUP_STEP]),
            "tests": step_duration_seconds(steps[TEST_STEP]),
            "total": duration_seconds(job["started_at"], job["completed_at"]),
        },
        "retried": run["run_attempt"] > 1,
        "artifacts": {
            "expected": EXPECTED_ARTIFACTS,
            "present": artifact_names,
            "complete": set(EXPECTED_ARTIFACTS).issubset(artifact_names),
        },
        "failureClassification": failure_classification(conclusion, steps[STARTUP_STEP]),
        "failureOwnerRole": None if conclusion == "success" else "promotion-rollback-incident",
    }, None


def collect(repository: str, required_runs: int) -> dict[str, Any]:
    selected: list[dict[str, Any]] = []
    exclusions: Counter[str] = Counter()
    page = 1
    while len(selected) < required_runs:
        candidates = fetch_completed_runs(repository, page)
        if not candidates:
            break
        for candidate in candidates:
            normalized, exclusion = normalize_run(repository, candidate)
            if normalized is not None:
                selected.append(normalized)
                if len(selected) == required_runs:
                    break
            elif exclusion is not None:
                exclusions[exclusion] += 1
        page += 1
    if len(selected) < required_runs:
        raise RuntimeError(f"found only {len(selected)} eligible runs; required {required_runs}")

    startup = [run["timingsSeconds"]["startup"] for run in selected]
    tests = [run["timingsSeconds"]["tests"] for run in selected]
    total = [run["timingsSeconds"]["total"] for run in selected]
    passed = sum(run["conclusion"] == "success" for run in selected)
    failed = sum(run["conclusion"] == "failure" for run in selected)
    timed_out = sum(run["conclusion"] == "timed_out" for run in selected)
    retried = sum(run["retried"] for run in selected)
    flakes = sum(run["failureClassification"] == "unexplained-flake" for run in selected)
    complete = sum(run["artifacts"]["complete"] for run in selected)
    count = len(selected)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "schemaVersion": 1,
        "generatedAt": now,
        "repository": repository,
        "workflow": WORKFLOW_PATH,
        "job": JOB_NAME,
        "eligibility": {
            "requiredRuns": required_runs,
            "selection": "most recent completed runs with one executed OSP job and required timing steps",
            "includedConclusions": sorted(ELIGIBLE_CONCLUSIONS),
            "excluded": [
                "docs-only or policy-skipped jobs",
                "concurrency or manually cancelled jobs",
                "runs without the REST Discovery Scan E2E job",
                "successful jobs without required timestamps or jobs without named steps",
                "unsupported non-terminal conclusions",
            ],
            "window": {
                "oldestCreatedAt": selected[-1]["createdAt"],
                "newestCreatedAt": selected[0]["createdAt"],
            },
        },
        "summary": {
            "eligibleRuns": count,
            "passedRuns": passed,
            "failedRuns": failed,
            "timedOutRuns": timed_out,
            "passRate": passed / count,
            "failureRate": (failed + timed_out) / count,
            "retryRate": retried / count,
            "unexplainedFlakeRate": flakes / count,
            "artifactCompletenessRate": complete / count,
            "startupSeconds": summarize(startup),
            "testSeconds": summarize(tests),
            "totalSeconds": summarize(total),
        },
        "runs": selected,
        "collectionExclusions": dict(sorted(exclusions.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default="greenbone/rust-gvm-api")
    parser.add_argument("--required-runs", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.required_runs < 30:
        parser.error("--required-runs must be at least 30")
    document = collect(args.repository, args.required_runs)
    # Collection exclusions are diagnostic, not part of the stable checked-in schema.
    exclusions = document.pop("collectionExclusions")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(document['runs'])} eligible runs to {args.output}")
    if exclusions:
        print("excluded candidates: " + ", ".join(f"{key}={value}" for key, value in exclusions.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
