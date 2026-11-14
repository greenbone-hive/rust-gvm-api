"""Hash-chained durable storage for direct-OpenVASD shadow evidence."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA_VERSION = 1
ZERO_HASH = "0" * 64
REPOSITORY = "greenbone-hive/rust-gvm-api"
WORKFLOW = ".github/workflows/nightly-e2e.yml"
JOB = "Direct OpenVASD Shadow E2E (advisory)"
REQUIRED_FINAL_DOCUMENTS = {
    "comparison.json",
    "fault-mappings.json",
    "provenance.json",
    "run-evidence.json",
    "diagnostic-evidence.json",
}
TRUSTED_EVENTS = {"push", "schedule", "workflow_dispatch"}
TRUSTED_BRANCHES = {"main", "devel"}


class LedgerError(ValueError):
    """The durable evidence ledger is incomplete or has been modified."""


def parse_timestamp(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise LedgerError(f"invalid ledger timestamp: {value!r}") from error
    if parsed.tzinfo is None:
        raise LedgerError("ledger timestamps must include a timezone")
    return parsed


def safe_relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise LedgerError(f"unsafe ledger payload path: {value!r}")
    return path.as_posix()


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_manifest(files: dict[str, bytes]) -> list[dict[str, Any]]:
    return [
        {
            "path": safe_relative_path(name),
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for name, content in sorted(files.items())
    ]


def payload_sha256(manifest: list[dict[str, Any]]) -> str:
    return canonical_sha256(manifest)


def entry_sha256(entry: dict[str, Any]) -> str:
    unsigned = {name: value for name, value in entry.items() if name != "entrySha256"}
    return canonical_sha256(unsigned)


def exact_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise LedgerError(f"{context} has incomplete or unknown fields")
    return value


def json_document(content: bytes, context: str) -> dict[str, Any]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LedgerError(f"{context} is not valid JSON") from error
    if not isinstance(value, dict):
        raise LedgerError(f"{context} must be an object")
    return value


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
        raise LedgerError("finalized provenance is incomplete")
    fixtures = provenance.get("fixtures")
    if not isinstance(fixtures, list):
        raise LedgerError("finalized provenance fixtures are incomplete")
    revisions = {
        item.get("name"): item.get("revision")
        for item in fixtures
        if isinstance(item, dict)
    }
    identities = {
        "GVM_GATEWAY_E2E_TARGET_HOST": "e2e-target",
        "scanner-backend-identity": "openvasd-backend",
        "synthetic-target-identity": "e2e-target",
    }
    for name, expected in identities.items():
        if revisions.get(name) != expected:
            raise LedgerError(f"finalized provenance identity {name} is invalid")
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
            raise LedgerError(f"finalized provenance input {name} is not exact")
    comparable = {name: provenance[name] for name in sorted(required - {"runner"})}
    return canonical_sha256(comparable)


def validate_finalized_payload(entry: dict[str, Any], files: dict[str, bytes]) -> None:
    """Reject partial or structurally invalid finalizer output before retention."""

    required_paths = {f"final/{name}" for name in REQUIRED_FINAL_DOCUMENTS}
    if required_paths - files.keys():
        raise LedgerError("ledger payload lacks required finalized documents")
    raw_paths = {name for name in files if name.startswith("raw/")}
    if not raw_paths:
        raise LedgerError("ledger payload lacks retained raw evidence")

    provenance_bytes = files["final/provenance.json"]
    raw_provenance = [
        content
        for name, content in files.items()
        if name.startswith("raw/") and PurePosixPath(name).name == "provenance.json"
    ]
    if len(raw_provenance) != 1 or raw_provenance[0] != provenance_bytes:
        raise LedgerError("raw/final provenance differs")
    provenance = json_document(provenance_bytes, "finalized provenance")
    exact_keys(
        provenance,
        {
            "schemaVersion",
            "gateway",
            "gvmd",
            "scanner",
            "feedData",
            "fixtures",
            "apiContract",
            "composeSha256",
            "runner",
            "harnessRevision",
        },
        "finalized provenance",
    )
    if provenance.get("schemaVersion") != 1:
        raise LedgerError("finalized provenance version is invalid")
    for name in ("gateway", "gvmd", "scanner"):
        component = exact_keys(
            provenance.get(name), {"sourceRevision", "image", "imageDigest"}, f"{name} provenance"
        )
        if any(not isinstance(value, str) or not value for value in component.values()):
            raise LedgerError(f"{name} provenance is incomplete")
    for name in ("feedData", "fixtures"):
        revisions = provenance.get(name)
        if not isinstance(revisions, list) or not revisions:
            raise LedgerError(f"{name} provenance is incomplete")
        revision_names: set[str] = set()
        for item in revisions:
            revision = exact_keys(item, {"name", "revision"}, f"{name} revision")
            if (
                not all(isinstance(value, str) and value for value in revision.values())
                or revision["name"] in revision_names
            ):
                raise LedgerError(f"{name} provenance has an invalid or duplicate revision")
            revision_names.add(revision["name"])
    api_contract = exact_keys(
        provenance.get("apiContract"), {"name", "revision"}, "API contract provenance"
    )
    runner = exact_keys(
        provenance.get("runner"), {"os", "architecture", "image"}, "runner provenance"
    )
    if (
        any(not isinstance(value, str) or not value for value in api_contract.values())
        or any(not isinstance(value, str) or not value for value in runner.values())
        or not isinstance(provenance.get("composeSha256"), str)
        or not provenance["composeSha256"]
        or not isinstance(provenance.get("harnessRevision"), str)
        or not provenance["harnessRevision"]
    ):
        raise LedgerError("finalized provenance is incomplete")
    if hashlib.sha256(provenance_bytes).hexdigest() != entry["provenanceSha256"]:
        raise LedgerError("provenance seal is invalid")
    if provenance_fingerprint(provenance) != entry["comparisonFingerprint"]:
        raise LedgerError("comparison fingerprint is invalid")

    comparison = json_document(files["final/comparison.json"], "finalized comparison")
    exact_keys(
        comparison,
        {"schemaVersion", "baselineLane", "candidateLane", "contracts"},
        "finalized comparison",
    )
    rows = comparison.get("contracts")
    if (
        comparison.get("schemaVersion") != 1
        or comparison.get("baselineLane") != "community-osp"
        or comparison.get("candidateLane") != "community-direct-openvasd-shadow"
        or not isinstance(rows, list)
        or not rows
    ):
        raise LedgerError("finalized comparison is partial")
    contracts: set[str] = set()
    for row in rows:
        exact_keys(
            row,
            {"contract", "baseline", "candidate", "disposition", "ownerRole"},
            "finalized comparison row",
        )
        contract = row.get("contract")
        if (
            not isinstance(contract, str)
            or not contract
            or contract in contracts
            or row.get("baseline") not in {"pass", "fail", "not-run"}
            or row.get("candidate") not in {"pass", "fail", "not-run"}
            or row.get("disposition")
            not in {"equivalent", "backend-specific", "gap", "approved-exclusion"}
            or not isinstance(row.get("ownerRole"), str)
            or not row["ownerRole"]
        ):
            raise LedgerError("finalized comparison row is invalid or duplicated")
        contracts.add(contract)

    faults = json_document(files["final/fault-mappings.json"], "finalized fault mappings")
    exact_keys(faults, {"schemaVersion", "lane", "scenarios"}, "finalized fault mappings")
    scenarios = faults.get("scenarios")
    expected_faults = {"http-400", "http-500", "malformed-body", "malformed-header", "timeout"}
    if (
        faults.get("schemaVersion") != 1
        or faults.get("lane") != "community-direct-openvasd-shadow"
        or not isinstance(scenarios, list)
        or len(scenarios) != len(expected_faults)
    ):
        raise LedgerError("finalized fault mappings are partial")
    scenario_names: set[str] = set()
    for scenario in scenarios:
        exact_keys(
            scenario,
            {"scenario", "injectedAt", "gatewayMapping", "target", "outcome"},
            "finalized fault scenario",
        )
        name = scenario.get("scenario")
        if (
            not isinstance(name, str)
            or name not in expected_faults
            or name in scenario_names
            or scenario.get("injectedAt") != "openvasd-http-boundary"
            or not isinstance(scenario.get("gatewayMapping"), str)
            or not scenario["gatewayMapping"]
            or not isinstance(scenario.get("target"), str)
            or not scenario["target"]
            or scenario.get("outcome") not in {"pass", "fail"}
        ):
            raise LedgerError("finalized fault scenario is invalid or duplicated")
        scenario_names.add(name)

    run = json_document(files["final/run-evidence.json"], "finalized run evidence")
    exact_keys(
        run,
        {
            "runId", "runAttempt", "runNumber", "event", "headBranch", "headSha",
            "createdAt", "runUrl", "jobId", "jobUrl", "conclusion", "timingsSeconds",
            "retried", "artifacts", "failureClassification", "failureOwnerRole",
        },
        "finalized run evidence",
    )
    identity = (entry["runId"], entry["runAttempt"])
    expected_run_url = f"https://github.com/{REPOSITORY}/actions/runs/{identity[0]}"
    if (
        run.get("runId") != identity[0]
        or run.get("runAttempt") != identity[1]
        or not isinstance(run.get("runNumber"), int)
        or isinstance(run.get("runNumber"), bool)
        or run["runNumber"] < 1
        or run.get("event") not in TRUSTED_EVENTS
        or run.get("headBranch") not in TRUSTED_BRANCHES
        or not isinstance(run.get("headSha"), str)
        or not run["headSha"]
        or run.get("runUrl") != expected_run_url
        or not isinstance(run.get("jobId"), int)
        or isinstance(run.get("jobId"), bool)
        or run["jobId"] < 1
        or run.get("jobUrl") != f"{expected_run_url}/job/{run['jobId']}"
        or run.get("conclusion") not in {"success", "failure", "timed_out"}
        or not isinstance(run.get("retried"), bool)
        or run["retried"] != (identity[1] > 1)
    ):
        raise LedgerError("finalized run/job identity is invalid or untrusted")
    run_created = parse_timestamp(run.get("createdAt"))
    if parse_timestamp(entry["createdAt"]) > run_created:
        raise LedgerError("ledger workflow time is later than the finalized job start")
    timings = exact_keys(
        run.get("timingsSeconds"), {"startup", "tests", "total"}, "run timings"
    )
    if any(
        isinstance(timings[name], bool)
        or not isinstance(timings[name], (int, float))
        or timings[name] < 0
        for name in timings
    ):
        raise LedgerError("finalized run timings are invalid")
    artifacts = exact_keys(
        run.get("artifacts"), {"expected", "present", "complete"}, "run artifacts"
    )
    expected_artifacts = artifacts.get("expected")
    present_artifacts = artifacts.get("present")
    if (
        not isinstance(expected_artifacts, list)
        or expected_artifacts != ["e2e-direct-openvasd-shadow-raw"]
        or not isinstance(present_artifacts, list)
        or any(not isinstance(name, str) for name in present_artifacts)
        or len(present_artifacts) != len(set(present_artifacts))
        or set(expected_artifacts) - set(present_artifacts)
        or artifacts.get("complete") is not True
    ):
        raise LedgerError("finalized run did not retain its exact raw source artifact")
    classifications = {
        None, "setup", "readiness", "application", "assertion", "cleanup", "runner",
        "unexplained-flake", "unclassified",
    }
    failure_classification = run.get("failureClassification")
    failure_owner = run.get("failureOwnerRole")
    if (
        not isinstance(failure_classification, (str, type(None)))
        or failure_classification not in classifications
        or not isinstance(failure_owner, (str, type(None)))
        or failure_owner
        not in {None, "community-contract-lane", "promotion-rollback-incident"}
    ):
        raise LedgerError("finalized failure classification is invalid")
    if (run["conclusion"] == "success") != (run["failureClassification"] is None):
        raise LedgerError("finalized conclusion and failure classification disagree")

    diagnostics = json_document(
        files["final/diagnostic-evidence.json"], "finalized diagnostic evidence"
    )
    exact_keys(
        diagnostics,
        {"schemaVersion", "runId", "runAttempt", "expected", "present", "complete"},
        "finalized diagnostic evidence",
    )
    expected = diagnostics.get("expected")
    present = diagnostics.get("present")
    required_diagnostics = {"compose-ps.txt", "compose.log", "runner-container-runtime.txt"}
    if (
        diagnostics.get("schemaVersion") != 1
        or diagnostics.get("runId") != identity[0]
        or diagnostics.get("runAttempt") != identity[1]
        or not isinstance(expected, list)
        or any(not isinstance(name, str) for name in expected)
        or set(expected) != required_diagnostics
        or len(expected) != len(set(expected))
        or not isinstance(present, list)
        or any(not isinstance(name, str) for name in present)
        or not set(present) <= required_diagnostics
        or len(present) != len(set(present))
        or diagnostics.get("complete") is not (set(present) == required_diagnostics)
    ):
        raise LedgerError("finalized diagnostic evidence is inconsistent")
    raw_basenames = {PurePosixPath(path).name for path in raw_paths}
    if not set(present) <= raw_basenames:
        raise LedgerError("finalized diagnostics claim files absent from raw evidence")


def empty_ledger() -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "workflow": WORKFLOW,
        "job": JOB,
        "entries": [],
    }


def load_ledger(root: Path) -> dict[str, Any]:
    path = root / "ledger.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LedgerError(f"cannot load durable ledger {path}: {error}") from error
    if not isinstance(document, dict):
        raise LedgerError("durable ledger must be an object")
    return document


def validate_ledger(root: Path) -> dict[str, Any]:
    ledger = load_ledger(root)
    if set(ledger) != {"schemaVersion", "repository", "workflow", "job", "entries"}:
        raise LedgerError("durable ledger has incomplete or unknown top-level fields")
    if (
        ledger["schemaVersion"] != SCHEMA_VERSION
        or ledger["repository"] != REPOSITORY
        or ledger["workflow"] != WORKFLOW
        or ledger["job"] != JOB
        or not isinstance(ledger["entries"], list)
    ):
        raise LedgerError("durable ledger identity or version is invalid")

    previous = ZERO_HASH
    identities: set[tuple[int, int]] = set()
    expected_entry_keys = {
        "sequence",
        "runId",
        "runAttempt",
        "createdAt",
        "comparisonFingerprint",
        "evidenceArtifactId",
        "rawArtifactId",
        "provenanceSha256",
        "payloadSha256",
        "previousEntrySha256",
        "files",
        "entrySha256",
    }
    for index, entry in enumerate(ledger["entries"], start=1):
        if not isinstance(entry, dict) or set(entry) != expected_entry_keys:
            raise LedgerError(f"ledger entry {index} has incomplete or unknown fields")
        identity = (entry["runId"], entry["runAttempt"])
        if (
            not isinstance(entry["sequence"], int)
            or isinstance(entry["sequence"], bool)
            or entry["sequence"] != index
            or not all(
                isinstance(value, int) and not isinstance(value, bool) and value > 0
                for value in identity
            )
            or identity in identities
            or entry["previousEntrySha256"] != previous
            or not all(
                isinstance(entry[name], int)
                and not isinstance(entry[name], bool)
                and entry[name] > 0
                for name in ("evidenceArtifactId", "rawArtifactId")
            )
            or not all(
                isinstance(entry[name], str)
                and re.fullmatch(r"[0-9a-f]{64}", entry[name])
                for name in (
                    "comparisonFingerprint",
                    "provenanceSha256",
                    "payloadSha256",
                    "previousEntrySha256",
                    "entrySha256",
                )
            )
        ):
            raise LedgerError(f"ledger entry {index} identity or chain is invalid")
        parse_timestamp(entry["createdAt"])
        identities.add(identity)

        run_dir = root / "runs" / f"{entry['runId']}-{entry['runAttempt']}"
        manifest = entry["files"]
        if not isinstance(manifest, list) or not manifest:
            raise LedgerError(f"ledger entry {index} has no payload manifest")
        declared_paths: set[str] = set()
        for item in manifest:
            if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
                raise LedgerError(f"ledger entry {index} has a malformed file record")
            if (
                not isinstance(item["path"], str)
                or not isinstance(item["size"], int)
                or isinstance(item["size"], bool)
                or item["size"] < 0
                or not isinstance(item["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
            ):
                raise LedgerError(f"ledger entry {index} has an invalid file record")
            relative = safe_relative_path(item["path"])
            if relative in declared_paths:
                raise LedgerError(f"ledger entry {index} declares a file twice")
            declared_paths.add(relative)
            path = run_dir / relative
            if path.is_symlink():
                raise LedgerError(f"ledger entry {index} payload cannot be a symbolic link")
            try:
                content = path.read_bytes()
            except OSError as error:
                raise LedgerError(f"ledger entry {index} payload is missing: {relative}") from error
            if len(content) != item["size"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
                raise LedgerError(f"ledger entry {index} payload was modified: {relative}")
        discovered = list(run_dir.rglob("*"))
        if any(path.is_symlink() for path in discovered):
            raise LedgerError(f"ledger entry {index} payload cannot contain symbolic links")
        actual_paths = {
            path.relative_to(run_dir).as_posix() for path in discovered if path.is_file()
        }
        if actual_paths != declared_paths:
            raise LedgerError(f"ledger entry {index} contains undeclared or missing files")
        if {f"final/{name}" for name in REQUIRED_FINAL_DOCUMENTS} - declared_paths:
            raise LedgerError(f"ledger entry {index} lacks required finalized documents")
        if not any(path.startswith("raw/") for path in declared_paths):
            raise LedgerError(f"ledger entry {index} lacks retained raw evidence")
        if payload_sha256(manifest) != entry["payloadSha256"]:
            raise LedgerError(f"ledger entry {index} payload seal is invalid")

        payload = {path: (run_dir / path).read_bytes() for path in declared_paths}
        try:
            validate_finalized_payload(entry, payload)
        except LedgerError as error:
            raise LedgerError(f"ledger entry {index}: {error}") from error
        if entry_sha256(entry) != entry["entrySha256"]:
            raise LedgerError(f"ledger entry {index} seal is invalid")
        previous = entry["entrySha256"]
    return ledger


def validate_append_only(previous: dict[str, Any], current: dict[str, Any]) -> None:
    """Reject mutation, deletion, or reordering of an already-reviewed prefix."""

    for field in ("schemaVersion", "repository", "workflow", "job"):
        if previous.get(field) != current.get(field):
            raise LedgerError(f"durable ledger changed immutable field {field}")
    prior_entries = previous.get("entries")
    current_entries = current.get("entries")
    if not isinstance(prior_entries, list) or not isinstance(current_entries, list):
        raise LedgerError("append-only comparison requires entry arrays")
    if len(current_entries) < len(prior_entries) or current_entries[: len(prior_entries)] != prior_entries:
        raise LedgerError("durable ledger history was modified instead of appended")


def append_entry(root: Path, metadata: dict[str, Any], files: dict[str, bytes]) -> dict[str, Any]:
    expected_metadata = {
        "runId",
        "runAttempt",
        "createdAt",
        "comparisonFingerprint",
        "evidenceArtifactId",
        "rawArtifactId",
        "provenanceSha256",
    }
    if set(metadata) != expected_metadata or not files:
        raise LedgerError("new ledger entry metadata or payload is incomplete")
    if (
        any(
            not isinstance(metadata[name], int)
            or isinstance(metadata[name], bool)
            or metadata[name] < 1
            for name in ("runId", "runAttempt", "evidenceArtifactId", "rawArtifactId")
        )
        or any(
            not isinstance(metadata[name], str)
            or not re.fullmatch(r"[0-9a-f]{64}", metadata[name])
            for name in ("comparisonFingerprint", "provenanceSha256")
        )
    ):
        raise LedgerError("new ledger entry identity or hashes are invalid")
    parse_timestamp(metadata["createdAt"])
    if any(
        not isinstance(name, str) or not isinstance(content, bytes)
        for name, content in files.items()
    ):
        raise LedgerError("new ledger payload paths and contents must be bytes-backed")
    root.mkdir(parents=True, exist_ok=True)
    ledger_path = root / "ledger.json"
    if ledger_path.exists():
        ledger = validate_ledger(root)
    else:
        ledger = empty_ledger()
    identity = (metadata["runId"], metadata["runAttempt"])
    existing = [
        entry for entry in ledger["entries"]
        if (entry["runId"], entry["runAttempt"]) == identity
    ]
    if existing:
        proposed_manifest = file_manifest(files)
        immutable = {
            "runId": metadata["runId"],
            "runAttempt": metadata["runAttempt"],
            "createdAt": metadata["createdAt"],
            "comparisonFingerprint": metadata["comparisonFingerprint"],
            "evidenceArtifactId": metadata["evidenceArtifactId"],
            "rawArtifactId": metadata["rawArtifactId"],
            "provenanceSha256": metadata["provenanceSha256"],
            "payloadSha256": payload_sha256(proposed_manifest),
            "files": proposed_manifest,
        }
        if any(existing[0][name] != value for name, value in immutable.items()):
            raise LedgerError(
                f"run {identity[0]} attempt {identity[1]} already exists with different content"
            )
        return existing[0]

    manifest = file_manifest(files)
    previous = ledger["entries"][-1]["entrySha256"] if ledger["entries"] else ZERO_HASH
    entry = {
        "sequence": len(ledger["entries"]) + 1,
        "runId": metadata["runId"],
        "runAttempt": metadata["runAttempt"],
        "createdAt": metadata["createdAt"],
        "comparisonFingerprint": metadata["comparisonFingerprint"],
        "evidenceArtifactId": metadata["evidenceArtifactId"],
        "rawArtifactId": metadata["rawArtifactId"],
        "provenanceSha256": metadata["provenanceSha256"],
        "payloadSha256": payload_sha256(manifest),
        "previousEntrySha256": previous,
        "files": manifest,
        "entrySha256": "",
    }
    entry["entrySha256"] = entry_sha256(entry)
    run_dir = root / "runs" / f"{identity[0]}-{identity[1]}"
    if run_dir.exists():
        raise LedgerError("new ledger run directory already exists without a matching entry")
    validate_finalized_payload(entry, files)
    for relative, content in files.items():
        path = run_dir / safe_relative_path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    ledger["entries"].append(entry)
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
    validate_ledger(root)
    return entry


def observation_from_ledger(
    root: Path,
    *,
    required_runs: int = 30,
    required_days: int = 14,
    generated_at: dt.datetime | None = None,
) -> dict[str, Any]:
    """Build the Phase 2 observation shape solely from durable sealed entries."""

    if required_runs < 30 or required_days < 14:
        raise LedgerError("the durable observation gate cannot weaken 30 runs/14 days")
    ledger = validate_ledger(root)
    latest_attempt_by_run: dict[int, dict[str, Any]] = {}
    for entry in ledger["entries"]:
        current = latest_attempt_by_run.get(entry["runId"])
        if current is None or entry["runAttempt"] > current["runAttempt"]:
            latest_attempt_by_run[entry["runId"]] = entry
    ordered = sorted(
        latest_attempt_by_run.values(),
        key=lambda entry: (parse_timestamp(entry["createdAt"]), entry["runId"]),
        reverse=True,
    )
    selected: list[dict[str, Any]] = []
    fingerprint: str | None = None
    for entry in ordered:
        if fingerprint is None:
            fingerprint = entry["comparisonFingerprint"]
        if entry["comparisonFingerprint"] != fingerprint:
            continue
        run_dir = root / "runs" / f"{entry['runId']}-{entry['runAttempt']}" / "final"
        run_evidence = json.loads((run_dir / "run-evidence.json").read_text(encoding="utf-8"))
        selected.append(
            {
                "runId": entry["runId"],
                "runAttempt": entry["runAttempt"],
                "event": run_evidence["event"],
                "headSha": run_evidence["headSha"],
                "createdAt": entry["createdAt"],
                "runUrl": run_evidence["runUrl"],
                "jobId": run_evidence["jobId"],
                "jobUrl": run_evidence["jobUrl"],
                "conclusion": run_evidence["conclusion"],
                "evidenceArtifactId": entry["evidenceArtifactId"],
                "provenanceSha256": entry["provenanceSha256"],
            }
        )
        timestamps = [parse_timestamp(run["createdAt"]) for run in selected]
        span = (
            (max(timestamps) - min(timestamps)).total_seconds() / 86400
            if len(timestamps) > 1
            else 0.0
        )
        if len(selected) >= required_runs and span >= required_days:
            break
    timestamps = [parse_timestamp(run["createdAt"]) for run in selected]
    span_days = (
        (max(timestamps) - min(timestamps)).total_seconds() / 86400
        if len(timestamps) > 1
        else 0.0
    )
    now = generated_at or dt.datetime.now(dt.timezone.utc)
    generated = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "schemaVersion": 1,
        "generatedAt": generated,
        "repository": REPOSITORY,
        "workflow": WORKFLOW,
        "job": JOB,
        "comparisonFingerprint": fingerprint or "unavailable",
        "gate": {
            "requiredRuns": required_runs,
            "requiredDays": required_days,
            "observedRuns": len(selected),
            "spanDays": span_days,
            "satisfied": len(selected) >= required_runs and span_days >= required_days,
        },
        "runs": selected,
    }
