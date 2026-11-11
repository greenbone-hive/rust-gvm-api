#!/usr/bin/env python3
"""Identify comparable direct-OpenVASD shadow runs across the observation gate."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import re
import subprocess
import zipfile
from pathlib import Path
from typing import Any


WORKFLOW = "nightly-e2e.yml"
WORKFLOW_PATH = ".github/workflows/nightly-e2e.yml"
JOB_NAME = "Direct OpenVASD Shadow E2E (advisory)"
EVIDENCE_ARTIFACT = "e2e-direct-openvasd-shadow-evidence"
ELIGIBLE_CONCLUSIONS = {"success", "failure", "timed_out"}


def gh_api(endpoint: str) -> Any:
    completed = subprocess.run(
        ["gh", "api", endpoint], check=True, text=True, capture_output=True
    )
    return json.loads(completed.stdout)


def gh_api_bytes(endpoint: str) -> bytes:
    completed = subprocess.run(
        ["gh", "api", endpoint], check=True, capture_output=True
    )
    return completed.stdout


def artifact_provenance(
    repository: str, artifact_id: int
) -> tuple[dict[str, Any], str]:
    archive = gh_api_bytes(f"repos/{repository}/actions/artifacts/{artifact_id}/zip")
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        candidates = [name for name in bundle.namelist() if Path(name).name == "provenance.json"]
        if len(candidates) != 1:
            raise ValueError(
                f"evidence artifact {artifact_id} must contain exactly one provenance.json"
            )
        content = bundle.read(candidates[0])
    return json.loads(content), hashlib.sha256(content).hexdigest()


def comparison_fingerprint(provenance: dict[str, Any]) -> str:
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
    if not isinstance(provenance, dict):
        raise ValueError("direct-lane provenance must be an object")
    if provenance.get("schemaVersion") != 1 or not required <= provenance.keys():
        raise ValueError("direct-lane provenance is incomplete")
    fixtures = provenance["fixtures"]
    if not isinstance(fixtures, list):
        raise ValueError("direct-lane provenance fixtures must be a list")
    fixture_revisions = {
        item.get("name"): item.get("revision")
        for item in fixtures
        if isinstance(item, dict)
    }
    expected_identities = {
        "GVM_GATEWAY_E2E_TARGET_HOST": "e2e-target",
        "scanner-backend-identity": "openvasd-backend",
        "synthetic-target-identity": "e2e-target",
    }
    for name, expected in expected_identities.items():
        if fixture_revisions.get(name) != expected:
            raise ValueError(
                f"direct-lane provenance identity {name!r} must be {expected!r}"
            )
    pinned_inputs = {
        "tests/e2e/compose.direct-openvasd.yaml",
        "synthetic-target-image",
        "tests/e2e/evidence/direct-openvasd-pins.json",
        "gvm-openapi-emulator/examples/openvasd/swagger.json",
        "gvm-openapi-emulator/examples/openvasd",
        "tests/e2e-harness",
    }
    for name in pinned_inputs:
        revision = fixture_revisions.get(name)
        if not isinstance(revision, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", revision):
            raise ValueError(
                f"direct-lane provenance input {name!r} must have an exact SHA-256"
            )
    # GitHub records the resolved hosted-runner image for triage, but that
    # image version is not a repository-controlled pin and rotates over time.
    # The fixture list contains the exact pin-manifest hash, including runner
    # label and Rust toolchain; compare that stable contract rather than
    # splitting a 14-day window on hosted image maintenance.
    comparable_fields = required - {"runner"}
    comparable_inputs = {
        name: provenance[name] for name in sorted(comparable_fields)
    }
    canonical = json.dumps(
        comparable_inputs, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def parse_timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def observation_span_days(runs: list[dict[str, Any]]) -> float:
    if len(runs) < 2:
        return 0.0
    timestamps = [parse_timestamp(run["createdAt"]) for run in runs]
    return (max(timestamps) - min(timestamps)).total_seconds() / 86400


def gate_satisfied(
    runs: list[dict[str, Any]], required_runs: int = 30, required_days: int = 14
) -> bool:
    return len(runs) >= required_runs and observation_span_days(runs) >= required_days


def normalize_run(
    repository: str, run: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    jobs = gh_api(
        f"repos/{repository}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100"
    )["jobs"]
    matching_jobs = [job for job in jobs if job["name"] == JOB_NAME]
    if len(matching_jobs) != 1:
        return None, None
    job = matching_jobs[0]
    if job.get("conclusion") not in ELIGIBLE_CONCLUSIONS:
        return None, None
    artifacts = gh_api(
        f"repos/{repository}/actions/runs/{run['id']}/artifacts?per_page=100"
    )["artifacts"]
    matching_artifacts = [
        artifact
        for artifact in artifacts
        if artifact["name"] == EVIDENCE_ARTIFACT
        and not artifact.get("expired")
        and artifact.get("created_at")
        and parse_timestamp(artifact["created_at"])
        >= parse_timestamp(job["started_at"])
    ]
    if not matching_artifacts:
        return None, None
    artifact_id = max(matching_artifacts, key=lambda item: item["created_at"])["id"]
    try:
        provenance, provenance_sha = artifact_provenance(repository, artifact_id)
        fingerprint = comparison_fingerprint(provenance)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError, zipfile.BadZipFile):
        return None, None
    return {
        "runId": run["id"],
        "runAttempt": run["run_attempt"],
        "event": run["event"],
        "headSha": run["head_sha"],
        "createdAt": run["created_at"],
        "runUrl": run["html_url"],
        "jobId": job["id"],
        "jobUrl": job["html_url"],
        "conclusion": job["conclusion"],
        "evidenceArtifactId": artifact_id,
        "provenanceSha256": provenance_sha,
    }, fingerprint


def collect(
    repository: str, required_runs: int = 30, required_days: int = 14
) -> dict[str, Any]:
    selected: list[dict[str, Any]] = []
    comparison_identity: str | None = None
    page = 1
    while not gate_satisfied(selected, required_runs, required_days):
        response = gh_api(
            f"repos/{repository}/actions/workflows/{WORKFLOW}/runs"
            f"?status=completed&per_page=100&page={page}"
        )
        candidates = response["workflow_runs"]
        if not candidates:
            break
        for candidate in candidates:
            normalized, fingerprint = normalize_run(repository, candidate)
            if normalized is not None and fingerprint is not None:
                if comparison_identity is None:
                    comparison_identity = fingerprint
                if fingerprint != comparison_identity:
                    continue
                selected.append(normalized)
                if gate_satisfied(selected, required_runs, required_days):
                    break
        page += 1

    span_days = observation_span_days(selected)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "schemaVersion": 1,
        "generatedAt": now,
        "repository": repository,
        "workflow": WORKFLOW_PATH,
        "job": JOB_NAME,
        "comparisonFingerprint": comparison_identity or "unavailable",
        "gate": {
            "requiredRuns": required_runs,
            "requiredDays": required_days,
            "observedRuns": len(selected),
            "spanDays": span_days,
            "satisfied": gate_satisfied(selected, required_runs, required_days),
        },
        "runs": selected,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default="greenbone/rust-gvm-api")
    parser.add_argument("--required-runs", type=int, default=30)
    parser.add_argument("--required-days", type=int, default=14)
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.required_runs < 30 or args.required_days < 14:
        parser.error("the observation gate cannot be lower than 30 runs across 14 days")
    document = collect(args.repository, args.required_runs, args.required_days)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    if not document["gate"]["satisfied"] and not args.allow_incomplete:
        parser.error(
            f"observation gate is not met: {document['gate']['observedRuns']} runs across "
            f"{document['gate']['spanDays']:.2f} days"
        )
    print(
        f"identified {document['gate']['observedRuns']} comparable shadow runs across "
        f"{document['gate']['spanDays']:.2f} days"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
