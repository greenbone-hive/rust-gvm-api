#!/usr/bin/env python3
"""Append one trusted finalized shadow run to the durable evidence branch."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from shadow_evidence_ledger import (
    JOB,
    REPOSITORY,
    WORKFLOW,
    LedgerError,
    append_entry,
    empty_ledger,
    validate_append_only,
    validate_ledger,
)


RAW_ARTIFACT = "e2e-direct-openvasd-shadow-raw"
FINAL_ARTIFACT = "e2e-direct-openvasd-shadow-evidence"
EVIDENCE_JOB = "Direct OpenVASD Shadow Evidence (advisory)"
TRUSTED_EVENTS = {"push", "schedule", "workflow_dispatch"}
TRUSTED_REFS = {"refs/heads/main", "refs/heads/devel"}
MAX_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
FINAL_DOCUMENTS = {
    "comparison.json",
    "fault-mappings.json",
    "provenance.json",
    "run-evidence.json",
    "diagnostic-evidence.json",
}


class PersistenceError(RuntimeError):
    """The current workflow execution is not safe to archive."""


def gh_json(endpoint: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["gh", "api", endpoint], check=True, text=True, capture_output=True
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise PersistenceError(f"GitHub API endpoint {endpoint} did not return an object")
    return value


def gh_bytes(endpoint: str) -> bytes:
    completed = subprocess.run(["gh", "api", endpoint], check=True, capture_output=True)
    return completed.stdout


def archive_files(repository: str, artifact_id: int) -> dict[str, bytes]:
    archive = gh_bytes(f"repos/{repository}/actions/artifacts/{artifact_id}/zip")
    try:
        bundle = zipfile.ZipFile(io.BytesIO(archive))
    except zipfile.BadZipFile as error:
        raise PersistenceError(f"artifact {artifact_id} is not a ZIP archive") from error
    with bundle:
        infos = [item for item in bundle.infolist() if not item.is_dir()]
        if sum(item.file_size for item in infos) > MAX_UNCOMPRESSED_BYTES:
            raise PersistenceError(f"artifact {artifact_id} exceeds the bounded evidence size")
        result: dict[str, bytes] = {}
        for info in infos:
            path = PurePosixPath(info.filename)
            if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
                raise PersistenceError(f"artifact {artifact_id} contains an unsafe path")
            name = path.as_posix()
            if name in result:
                raise PersistenceError(f"artifact {artifact_id} contains duplicate path {name}")
            result[name] = bundle.read(info)
    return result


def one_by_basename(files: dict[str, bytes], basename: str, context: str) -> bytes:
    matches = [content for name, content in files.items() if PurePosixPath(name).name == basename]
    if len(matches) != 1:
        raise PersistenceError(f"{context} must contain exactly one {basename}")
    return matches[0]


def parse_json(content: bytes, context: str) -> dict[str, Any]:
    try:
        value = json.loads(content)
    except json.JSONDecodeError as error:
        raise PersistenceError(f"{context} is not valid JSON") from error
    if not isinstance(value, dict):
        raise PersistenceError(f"{context} must be an object")
    return value


def provenance_fingerprint(provenance: dict[str, Any]) -> str:
    required = {
        "schemaVersion", "gvmd", "scanner", "feedData", "fixtures",
        "apiContract", "composeSha256", "runner",
    }
    if provenance.get("schemaVersion") != 1 or not required <= provenance.keys():
        raise PersistenceError("finalized provenance is incomplete")
    fixtures = provenance.get("fixtures")
    if not isinstance(fixtures, list):
        raise PersistenceError("finalized provenance fixtures are incomplete")
    revisions = {
        item.get("name"): item.get("revision") for item in fixtures if isinstance(item, dict)
    }
    identities = {
        "GVM_GATEWAY_E2E_TARGET_HOST": "e2e-target",
        "scanner-backend-identity": "openvasd-backend",
        "synthetic-target-identity": "e2e-target",
    }
    for name, expected in identities.items():
        if revisions.get(name) != expected:
            raise PersistenceError(f"finalized provenance identity {name} is invalid")
    exact_inputs = {
        "tests/e2e/compose.direct-openvasd.yaml",
        "synthetic-target-image",
        "tests/e2e/evidence/direct-openvasd-pins.json",
        "gvm-openapi-emulator/examples/openvasd/swagger.json",
        "gvm-openapi-emulator/examples/openvasd",
        "tests/e2e-harness",
    }
    for name in exact_inputs:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(revisions.get(name))):
            raise PersistenceError(f"finalized provenance input {name} is not exact")
    comparable = {name: provenance[name] for name in sorted(required - {"runner"})}
    encoded = json.dumps(comparable, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def trusted_environment() -> dict[str, str]:
    required = {
        "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA",
    }
    missing = sorted(name for name in required if not os.environ.get(name))
    if missing:
        raise PersistenceError(f"missing workflow identity: {', '.join(missing)}")
    environment = dict(os.environ)
    if (
        environment["GITHUB_REPOSITORY"] != REPOSITORY
        or environment["GITHUB_EVENT_NAME"] not in TRUSTED_EVENTS
        or environment["GITHUB_REF"] not in TRUSTED_REFS
    ):
        raise PersistenceError("fork, pull-request, merge-queue, or non-protected-ref evidence is untrusted")
    return environment


def resolve_source(environment: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    repository = environment["GITHUB_REPOSITORY"]
    run_id = int(environment["GITHUB_RUN_ID"])
    attempt = int(environment["GITHUB_RUN_ATTEMPT"])
    run = gh_json(f"repos/{repository}/actions/runs/{run_id}")
    workflow = gh_json(f"repos/{repository}/actions/workflows/nightly-e2e.yml")
    if (
        run.get("id") != run_id
        or run.get("run_attempt") != attempt
        or run.get("workflow_id") != workflow.get("id")
        or run.get("event") != environment["GITHUB_EVENT_NAME"]
        or run.get("head_sha") != environment["GITHUB_SHA"]
    ):
        raise PersistenceError("workflow run identity does not match the trusted execution")
    jobs = gh_json(
        f"repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100"
    ).get("jobs", [])
    shadow = [job for job in jobs if job.get("name") == JOB]
    evidence = [job for job in jobs if job.get("name") == EVIDENCE_JOB]
    if len(shadow) != 1 or len(evidence) != 1 or evidence[0].get("conclusion") != "success":
        raise PersistenceError("exactly one successful finalized evidence job is required")
    if shadow[0].get("conclusion") not in {"success", "failure", "timed_out"}:
        raise PersistenceError("shadow job did not complete with an eligible conclusion")
    return run, shadow[0], evidence[0]


def resolve_artifacts(
    environment: dict[str, str], shadow_job: dict[str, Any], evidence_job: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    repository = environment["GITHUB_REPOSITORY"]
    run_id = environment["GITHUB_RUN_ID"]
    artifacts = gh_json(f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100").get(
        "artifacts", []
    )
    raw = [
        item for item in artifacts
        if item.get("name") == RAW_ARTIFACT
        and not item.get("expired")
        and item.get("created_at", "") >= shadow_job.get("started_at", "")
    ]
    final = [
        item for item in artifacts
        if item.get("name") == FINAL_ARTIFACT
        and not item.get("expired")
        and item.get("created_at", "") >= evidence_job.get("started_at", "")
    ]
    if len(raw) != 1 or len(final) != 1:
        raise PersistenceError("one non-expired raw and finalized artifact are required; no backfill is allowed")
    if not isinstance(raw[0].get("id"), int) or not isinstance(final[0].get("id"), int):
        raise PersistenceError("artifact identity is incomplete")
    return raw[0], final[0]


def persist(ledger_root: Path) -> dict[str, Any]:
    environment = trusted_environment()
    run, shadow_job, evidence_job = resolve_source(environment)
    raw_artifact, final_artifact = resolve_artifacts(environment, shadow_job, evidence_job)
    repository = environment["GITHUB_REPOSITORY"]
    raw_files = archive_files(repository, raw_artifact["id"])
    final_files = archive_files(repository, final_artifact["id"])

    final_bytes = {
        name: one_by_basename(final_files, name, "finalized artifact")
        for name in FINAL_DOCUMENTS
    }
    documents = {name: parse_json(content, name) for name, content in final_bytes.items()}
    run_evidence = documents["run-evidence.json"]
    diagnostics = documents["diagnostic-evidence.json"]
    expected_identity = {
        "runId": run["id"],
        "runAttempt": run["run_attempt"],
        "event": run["event"],
        "headSha": run["head_sha"],
        "runUrl": run["html_url"],
        "jobId": shadow_job["id"],
        "jobUrl": shadow_job["html_url"],
        "conclusion": shadow_job["conclusion"],
    }
    if any(run_evidence.get(name) != value for name, value in expected_identity.items()):
        raise PersistenceError("finalized run evidence does not match GitHub run/job identity")
    if diagnostics.get("runId") != run["id"] or diagnostics.get("runAttempt") != run["run_attempt"]:
        raise PersistenceError("diagnostic evidence does not match the run attempt")
    comparison = documents["comparison.json"]
    faults = documents["fault-mappings.json"]
    if (
        comparison.get("schemaVersion") != 1
        or comparison.get("baselineLane") != "community-osp"
        or comparison.get("candidateLane") != "community-direct-openvasd-shadow"
        or not comparison.get("contracts")
        or faults.get("schemaVersion") != 1
        or faults.get("lane") != "community-direct-openvasd-shadow"
        or not faults.get("scenarios")
    ):
        raise PersistenceError("finalized comparison or fault documents are partial")
    provenance_bytes = final_bytes["provenance.json"]
    provenance = documents["provenance.json"]
    raw_provenance = one_by_basename(raw_files, "provenance.json", "raw artifact")
    if raw_provenance != provenance_bytes:
        raise PersistenceError("raw and finalized provenance bytes differ")
    fingerprint = provenance_fingerprint(provenance)
    provenance_sha = hashlib.sha256(provenance_bytes).hexdigest()

    payload = {f"final/{name}": content for name, content in final_bytes.items()}
    for name, content in raw_files.items():
        safe = PurePosixPath(name)
        relative = safe.as_posix()
        payload[f"raw/{relative}"] = content
    metadata = {
        "runId": run["id"],
        "runAttempt": run["run_attempt"],
        "createdAt": run["created_at"],
        "comparisonFingerprint": fingerprint,
        "evidenceArtifactId": final_artifact["id"],
        "rawArtifactId": raw_artifact["id"],
        "provenanceSha256": provenance_sha,
    }
    try:
        before = validate_ledger(ledger_root) if (ledger_root / "ledger.json").exists() else empty_ledger()
        entry = append_entry(ledger_root, metadata, payload)
        after = validate_ledger(ledger_root)
        validate_append_only(before, after)
        return entry
    except LedgerError as error:
        raise PersistenceError(str(error)) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        entry = persist(args.ledger_root)
    except (PersistenceError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    print(
        f"sealed durable evidence sequence={entry['sequence']} "
        f"run={entry['runId']} attempt={entry['runAttempt']} "
        f"entrySha256={entry['entrySha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
