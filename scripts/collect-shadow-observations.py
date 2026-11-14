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

from shadow_evidence_ledger import LedgerError, observation_from_ledger


WORKFLOW = "nightly-e2e.yml"
WORKFLOW_PATH = ".github/workflows/nightly-e2e.yml"
DEFAULT_REPOSITORY = "greenbone-hive/rust-gvm-api"
JOB_NAME = "Direct OpenVASD Shadow E2E (advisory)"
EVIDENCE_ARTIFACT = "e2e-direct-openvasd-shadow-evidence"
RAW_EVIDENCE_ARTIFACT = "e2e-direct-openvasd-shadow-raw"
ELIGIBLE_CONCLUSIONS = {"success", "failure", "timed_out"}
FINALIZED_DOCUMENTS = {
    "comparison.json",
    "fault-mappings.json",
    "provenance.json",
    "run-evidence.json",
}
OPTIONAL_FINALIZED_DOCUMENTS = {"diagnostic-evidence.json"}
EXPECTED_DIAGNOSTICS = {
    "compose-ps.txt",
    "compose.log",
    "runner-container-runtime.txt",
}


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


def artifact_documents(
    repository: str, artifact_id: int
) -> tuple[dict[str, dict[str, Any]], str]:
    archive = gh_api_bytes(f"repos/{repository}/actions/artifacts/{artifact_id}/zip")
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        candidates = {
            filename: [
                name for name in bundle.namelist() if Path(name).name == filename
            ]
            for filename in FINALIZED_DOCUMENTS
        }
        invalid = {
            filename: len(paths)
            for filename, paths in candidates.items()
            if len(paths) != 1
        }
        if invalid:
            raise ValueError(
                f"evidence artifact {artifact_id} must contain exactly one of every "
                f"finalized document; invalid counts: {invalid}"
            )
        contents = {
            filename: bundle.read(paths[0])
            for filename, paths in candidates.items()
        }
        for filename in OPTIONAL_FINALIZED_DOCUMENTS:
            paths = [name for name in bundle.namelist() if Path(name).name == filename]
            if len(paths) > 1:
                raise ValueError(
                    f"evidence artifact {artifact_id} contains duplicate {filename} documents"
                )
            if paths:
                contents[filename] = bundle.read(paths[0])
    documents = {
        filename: json.loads(content) for filename, content in contents.items()
    }
    if any(not isinstance(document, dict) for document in documents.values()):
        raise ValueError(f"evidence artifact {artifact_id} documents must be objects")
    provenance_content = contents["provenance.json"]
    return documents, hashlib.sha256(provenance_content).hexdigest()


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


def validate_finalized_documents(
    documents: dict[str, dict[str, Any]],
    run: dict[str, Any],
    job: dict[str, Any],
) -> None:
    comparison = documents["comparison.json"]
    if (
        comparison.get("schemaVersion") != 1
        or comparison.get("baselineLane") != "community-osp"
        or comparison.get("candidateLane") != "community-direct-openvasd-shadow"
        or not isinstance(comparison.get("contracts"), list)
        or not comparison["contracts"]
    ):
        raise ValueError("finalized comparison does not identify both evidence lanes")

    faults = documents["fault-mappings.json"]
    if (
        faults.get("schemaVersion") != 1
        or faults.get("lane") != "community-direct-openvasd-shadow"
        or not isinstance(faults.get("scenarios"), list)
        or not faults["scenarios"]
    ):
        raise ValueError("finalized fault mappings do not identify the shadow lane")

    evidence = documents["run-evidence.json"]
    expected_identity = {
        "runId": run["id"],
        "runAttempt": run["run_attempt"],
        "event": run["event"],
        "headSha": run["head_sha"],
        "runUrl": run["html_url"],
        "jobId": job["id"],
        "jobUrl": job["html_url"],
        "conclusion": job["conclusion"],
    }
    for field, expected_value in expected_identity.items():
        if evidence[field] != expected_value:
            raise ValueError(
                f"finalized run evidence {field} does not match GitHub metadata"
            )
    if evidence["createdAt"] != job["started_at"]:
        raise ValueError(
            "finalized run evidence createdAt does not match the shadow job start"
        )
    if evidence["retried"] != (run["run_attempt"] > 1):
        raise ValueError("finalized run evidence retried does not match runAttempt")
    artifacts = evidence["artifacts"]
    if not isinstance(artifacts, dict):
        raise ValueError("finalized run evidence artifacts must be an object")
    expected_artifacts = artifacts.get("expected")
    present_artifacts = artifacts.get("present")
    if (
        not isinstance(expected_artifacts, list)
        or not expected_artifacts
        or not isinstance(present_artifacts, list)
        or artifacts.get("complete") is not True
        or not set(expected_artifacts).issubset(set(present_artifacts))
    ):
        raise ValueError("finalized run evidence must retain its complete raw artifact")


def normalize_artifact(
    repository: str,
    artifact: dict[str, Any],
    expected_workflow_id: int,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        workflow_run = artifact["workflow_run"]
        run_id = workflow_run["id"]
        artifact_id = artifact["id"]
        artifact_created_at = artifact["created_at"]
        if (
            artifact.get("name") != EVIDENCE_ARTIFACT
            or artifact.get("expired")
            or not isinstance(run_id, int)
            or not isinstance(artifact_id, int)
        ):
            return None, None
        parse_timestamp(artifact_created_at)
    except (KeyError, TypeError, ValueError):
        return None, None

    run = gh_api(f"repos/{repository}/actions/runs/{run_id}")
    if (
        run.get("id") != run_id
        or run.get("workflow_id") != expected_workflow_id
        or run.get("status") != "completed"
        or not isinstance(run.get("run_attempt"), int)
    ):
        return None, None
    jobs = gh_api(
        f"repos/{repository}/actions/runs/{run_id}/attempts/"
        f"{run['run_attempt']}/jobs?per_page=100"
    )["jobs"]
    matching_jobs = [job for job in jobs if job["name"] == JOB_NAME]
    if len(matching_jobs) != 1:
        return None, None
    job = matching_jobs[0]
    if job.get("conclusion") not in ELIGIBLE_CONCLUSIONS:
        return None, None
    if (
        not job.get("started_at")
        or not job.get("completed_at")
        or parse_timestamp(artifact_created_at) < parse_timestamp(job["started_at"])
    ):
        return None, None
    try:
        documents, provenance_sha = artifact_documents(repository, artifact_id)
        validate_finalized_documents(documents, run, job)
        provenance = documents["provenance.json"]
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
    workflow = gh_api(f"repos/{repository}/actions/workflows/{WORKFLOW}")
    expected_workflow_id = workflow.get("id")
    if not isinstance(expected_workflow_id, int) or expected_workflow_id < 1:
        raise RuntimeError(f"could not resolve workflow identity for {WORKFLOW}")

    artifacts_by_run: dict[int, dict[str, Any]] = {}
    page = 1
    while True:
        response = gh_api(
            f"repos/{repository}/actions/artifacts?name={EVIDENCE_ARTIFACT}"
            f"&per_page=100&page={page}"
        )
        candidates = response["artifacts"]
        if not candidates:
            break
        for artifact in candidates:
            try:
                run_id = artifact["workflow_run"]["id"]
                created_at = artifact["created_at"]
                if (
                    artifact.get("name") != EVIDENCE_ARTIFACT
                    or artifact.get("expired")
                    or not isinstance(run_id, int)
                ):
                    continue
                created = parse_timestamp(created_at)
            except (KeyError, TypeError, ValueError):
                continue
            current = artifacts_by_run.get(run_id)
            if current is None or created > parse_timestamp(current["created_at"]):
                artifacts_by_run[run_id] = artifact
        page += 1

    selected: list[dict[str, Any]] = []
    comparison_identity: str | None = None
    candidates = sorted(
        artifacts_by_run.values(),
        key=lambda item: parse_timestamp(item["created_at"]),
        reverse=True,
    )
    for candidate in candidates:
        normalized, fingerprint = normalize_artifact(
            repository, candidate, expected_workflow_id
        )
        if normalized is not None and fingerprint is not None:
            if comparison_identity is None:
                comparison_identity = fingerprint
            if fingerprint != comparison_identity:
                continue
            selected.append(normalized)
            if gate_satisfied(selected, required_runs, required_days):
                break

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


def retain_finalized_evidence(
    repository: str, observation: dict[str, Any], output_dir: Path
) -> None:
    """Materialize the already-selected finalized documents for offline review."""

    output_dir.mkdir(parents=True, exist_ok=True)
    for run in observation["runs"]:
        documents, _provenance_sha = artifact_documents(
            repository, run["evidenceArtifactId"]
        )
        if "diagnostic-evidence.json" not in documents:
            documents["diagnostic-evidence.json"] = diagnostic_evidence_from_raw_artifact(
                repository, run, documents["run-evidence.json"]
            )
        run_dir = output_dir / f"run-{run['runId']}-attempt-{run['runAttempt']}"
        run_dir.mkdir(parents=True, exist_ok=True)
        for filename, document in documents.items():
            (run_dir / filename).write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8"
            )


def diagnostic_evidence_from_raw_artifact(
    repository: str, observed_run: dict[str, Any], run_evidence: dict[str, Any]
) -> dict[str, Any]:
    """Recover pre-Phase-3 diagnostic presence from the retained raw ZIP."""

    response = gh_api(
        f"repos/{repository}/actions/runs/{observed_run['runId']}/artifacts?per_page=100"
    )
    started_at = parse_timestamp(run_evidence["createdAt"])
    candidates = []
    for artifact in response.get("artifacts", []):
        try:
            created_at = parse_timestamp(artifact["created_at"])
        except (KeyError, TypeError, ValueError):
            continue
        if (
            artifact.get("name") == RAW_EVIDENCE_ARTIFACT
            and not artifact.get("expired")
            and created_at >= started_at
            and isinstance(artifact.get("id"), int)
        ):
            candidates.append(artifact)
    present: set[str] = set()
    if len(candidates) == 1:
        archive = gh_api_bytes(
            f"repos/{repository}/actions/artifacts/{candidates[0]['id']}/zip"
        )
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                present = {
                    Path(name).name
                    for name in bundle.namelist()
                    if Path(name).name in EXPECTED_DIAGNOSTICS
                }
        except zipfile.BadZipFile:
            present = set()
    expected = sorted(EXPECTED_DIAGNOSTICS)
    retained = sorted(present)
    return {
        "schemaVersion": 1,
        "runId": observed_run["runId"],
        "runAttempt": observed_run["runAttempt"],
        "expected": expected,
        "present": retained,
        "complete": retained == expected,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--required-runs", type=int, default=30)
    parser.add_argument("--required-days", type=int, default=14)
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument(
        "--ledger-root",
        type=Path,
        help="collect only from a validated durable evidence-branch checkout",
    )
    parser.add_argument(
        "--retain-finalized-dir",
        type=Path,
        help="write the selected finalized documents for offline Phase 3 evaluation",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.required_runs < 30 or args.required_days < 14:
        parser.error("the observation gate cannot be lower than 30 runs across 14 days")
    if args.ledger_root is not None and args.retain_finalized_dir is not None:
        parser.error("--retain-finalized-dir is only valid while inspecting live artifacts")
    if args.ledger_root is not None:
        try:
            document = observation_from_ledger(
                args.ledger_root,
                required_runs=args.required_runs,
                required_days=args.required_days,
            )
        except LedgerError as error:
            parser.error(str(error))
    else:
        document = collect(args.repository, args.required_runs, args.required_days)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    if args.retain_finalized_dir is not None:
        retain_finalized_evidence(
            args.repository, document, args.retain_finalized_dir
        )
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
