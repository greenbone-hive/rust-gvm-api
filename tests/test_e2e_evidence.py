#!/usr/bin/env python3
"""Tests that keep Phase 0 E2E evidence complete and fail closed on drift."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {relative_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CHECKER = load_script("check_e2e_evidence", "scripts/check-e2e-evidence.py")
COLLECTOR = load_script("collect_e2e_baseline", "scripts/collect-e2e-baseline.py")
PROVENANCE = load_script("capture_e2e_provenance", "scripts/capture-e2e-provenance.py")


class E2eEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        evidence_root = ROOT / "tests" / "e2e" / "evidence"
        self.owners = json.loads((evidence_root / "owners.json").read_text(encoding="utf-8"))["roles"]
        self.inventory = json.loads(
            (evidence_root / "contract-inventory.json").read_text(encoding="utf-8")
        )
        self.baseline = json.loads(
            (evidence_root / "baselines" / "osp-required.json").read_text(encoding="utf-8")
        )

    def test_checked_in_evidence_satisfies_all_versioned_contracts(self) -> None:
        """The repository must remain usable as the canonical Phase 0 evidence source."""

        CHECKER.validate_all(ROOT)

    def test_inventory_matches_every_rust_test_exactly_once(self) -> None:
        """Adding or removing a Rust E2E test without inventory maintenance must fail."""

        discovered = set(CHECKER.discover_rust_tests(ROOT))
        inventoried = {test["id"] for test in self.inventory["tests"]}
        self.assertEqual(discovered, inventoried)
        self.assertEqual(len(inventoried), len(self.inventory["tests"]))

    def test_inventory_rejects_unknown_fields(self) -> None:
        """Evidence extensions need an explicit schema/version change, not silent acceptance."""

        changed = copy.deepcopy(self.inventory)
        changed["tests"][0]["unexpected"] = True
        with self.assertRaisesRegex(CHECKER.EvidenceError, "unknown keys"):
            CHECKER.validate_inventory(changed, self.owners, ROOT)

    def test_inventory_rejects_missing_source_test(self) -> None:
        """The contract matrix cannot claim completeness after an entry is dropped."""

        changed = copy.deepcopy(self.inventory)
        changed["tests"].pop()
        with self.assertRaisesRegex(CHECKER.EvidenceError, "source mismatch"):
            CHECKER.validate_inventory(changed, self.owners, ROOT)

    def test_inventory_rejects_an_unowned_contract(self) -> None:
        """Every named contract must retain an accountable role as the matrix evolves."""

        changed = copy.deepcopy(self.inventory)
        contract = changed["tests"][0]["contracts"][0]
        del changed["contractOwners"][contract]
        with self.assertRaisesRegex(CHECKER.EvidenceError, "contractOwners must exactly cover"):
            CHECKER.validate_inventory(changed, self.owners, ROOT)

    def test_osp_dependency_requires_an_explicit_disposition(self) -> None:
        """OSP-bound coverage cannot disappear from migration planning implicitly."""

        changed = copy.deepcopy(self.inventory)
        entry = next(
            test for test in changed["tests"] if "osp-scanner-path" in test["dependencies"]
        )
        entry["ospDisposition"] = "not-applicable"
        with self.assertRaisesRegex(CHECKER.EvidenceError, "OSP scanner dependency"):
            CHECKER.validate_inventory(changed, self.owners, ROOT)

    def test_baseline_rejects_summary_drift(self) -> None:
        """Published promotion metrics must be reproducible from their raw run rows."""

        changed = copy.deepcopy(self.baseline)
        changed["summary"]["passRate"] = 0.5
        with self.assertRaisesRegex(CHECKER.EvidenceError, "passRate"):
            CHECKER.validate_baseline(changed)

    def test_collector_excludes_a_skipped_job(self) -> None:
        """Docs-only workflow runs must never dilute the measured OSP baseline."""

        run = {"id": 42}
        jobs = {"jobs": [{"name": COLLECTOR.JOB_NAME, "conclusion": "skipped"}]}
        with patch.object(COLLECTOR, "gh_api", return_value=jobs):
            normalized, exclusion = COLLECTOR.normalize_run("greenbone/rust-gvm-api", run)
        self.assertIsNone(normalized)
        self.assertEqual(exclusion, "docs-only-or-policy-skip")

    def test_collector_retains_a_setup_failure_without_test_timestamps(self) -> None:
        """Executed setup failures must affect the baseline instead of being filtered out."""

        run = {
            "id": 42,
            "run_attempt": 1,
            "run_number": 7,
            "event": "push",
            "head_branch": "main",
            "head_sha": "0123456789abcdef",
            "created_at": "2026-11-10T00:00:00Z",
            "html_url": "https://github.com/greenbone/rust-gvm-api/actions/runs/42",
        }
        job = {
            "id": 84,
            "name": COLLECTOR.JOB_NAME,
            "conclusion": "failure",
            "started_at": "2026-11-10T00:00:01Z",
            "completed_at": "2026-11-10T00:00:11Z",
            "html_url": "https://github.com/greenbone/rust-gvm-api/actions/runs/42/job/84",
            "steps": [
                {
                    "name": COLLECTOR.STARTUP_STEP,
                    "conclusion": "failure",
                    "started_at": "2026-11-10T00:00:02Z",
                    "completed_at": "2026-11-10T00:00:10Z",
                },
                {
                    "name": COLLECTOR.TEST_STEP,
                    "conclusion": "skipped",
                    "started_at": None,
                    "completed_at": None,
                },
            ],
        }
        responses = [{"jobs": [job]}, {"artifacts": []}]
        with patch.object(COLLECTOR, "gh_api", side_effect=responses):
            normalized, exclusion = COLLECTOR.normalize_run("greenbone/rust-gvm-api", run)
        self.assertIsNone(exclusion)
        self.assertEqual(normalized["failureClassification"], "setup")
        self.assertEqual(normalized["timingsSeconds"]["tests"], 0)

    def test_runtime_provenance_uses_exact_container_image_ids(self) -> None:
        """A failed live job must identify immutable component and feed images."""

        def image(service: str) -> dict[str, str]:
            return {
                "sourceRevision": f"image-id:sha256:{service}",
                "image": f"example.invalid/{service}:stable",
                "imageDigest": f"sha256:{service}",
            }

        records = {
            "gvm-gateway": image("gvm-gateway"),
            "gvmd": image("gvmd"),
            "ospd-openvas": image("ospd-openvas"),
            **{service: image(service) for service in PROVENANCE.FEED_SERVICES},
        }
        document = PROVENANCE.build_document(
            records,
            "0123456789abcdef",
            {
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "ImageOS": "ubuntu",
                "ImageVersion": "24.04",
            },
        )
        CHECKER.validate_provenance(document)
        self.assertEqual(document["apiContract"]["name"], "spec/rest-api/openapi.yaml")
        self.assertTrue(document["apiContract"]["revision"].startswith("sha256:"))
        self.assertEqual(document["scanner"]["imageDigest"], "sha256:ospd-openvas")
        self.assertTrue(all(item["revision"].startswith("sha256:") for item in document["feedData"]))


if __name__ == "__main__":
    unittest.main()
