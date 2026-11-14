#!/usr/bin/env python3
"""Record a successful real-OpenVASD compatibility execution for Phase 3 review."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path


WORKFLOW = ".github/workflows/real-openvasd-compatibility.yml"
JOB = "Real OpenVASD Direct-HTTP Compatibility (advisory)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    provenance = args.provenance.read_bytes()
    # Parse before hashing so a byte-preserved but malformed document cannot be
    # presented later as compatibility provenance.
    document = json.loads(provenance)
    if not isinstance(document, dict) or document.get("schemaVersion") != 1:
        parser.error("real-OpenVASD provenance is missing or unsupported")

    required_environment = (
        "GITHUB_REPOSITORY",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_SHA",
    )
    missing = [name for name in required_environment if not os.environ.get(name)]
    if missing:
        parser.error(f"missing GitHub execution identity: {', '.join(missing)}")

    now = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    repository = os.environ["GITHUB_REPOSITORY"]
    run_id = int(os.environ["GITHUB_RUN_ID"])
    result = {
        "schemaVersion": 1,
        "repository": repository,
        "workflow": WORKFLOW,
        "job": JOB,
        "runId": run_id,
        "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "runUrl": f"https://github.com/{repository}/actions/runs/{run_id}",
        "headSha": os.environ["GITHUB_SHA"],
        "completedAt": now,
        "conclusion": "success",
        "provenanceSha256": hashlib.sha256(provenance).hexdigest(),
        "unresolvedReleaseBlockingDrift": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"recorded successful real-OpenVASD compatibility run {run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
