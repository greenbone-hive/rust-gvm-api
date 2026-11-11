#!/usr/bin/env python3
"""Tests that keep Phase 0 E2E evidence complete and fail closed on drift."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
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
FINALIZER = load_script("finalize_openvasd_evidence", "scripts/finalize-openvasd-evidence.py")
FIXTURES = load_script("fetch_openvasd_fixtures", "scripts/fetch-openvasd-emulator-fixtures.py")
OBSERVATIONS = load_script("collect_shadow_observations", "scripts/collect-shadow-observations.py")


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

    def test_direct_runtime_rejects_conflated_container_identity(self) -> None:
        """Backend and target aliases must never hide one shared container."""

        def inspect(service: str, container_id: str, address: str) -> dict[str, object]:
            return {
                "Id": container_id,
                "Config": {"Labels": {"com.docker.compose.service": service}},
                "NetworkSettings": {"Networks": {"default": {"IPAddress": address}}},
            }

        conflated = [
            inspect("openvasd-backend", "same", "172.20.0.2"),
            inspect("e2e-target", "same", "172.20.0.2"),
        ]
        with self.assertRaisesRegex(RuntimeError, "conflated"):
            PROVENANCE.assert_distinct_identities(
                conflated, "openvasd-backend", "e2e-target"
            )

        PROVENANCE.assert_distinct_identities(
            [
                inspect("openvasd-backend", "backend", "172.20.0.2"),
                inspect("e2e-target", "target", "172.20.0.3"),
            ],
            "openvasd-backend",
            "e2e-target",
        )

    def test_direct_runtime_provenance_rejects_an_image_pin_mismatch(self) -> None:
        """A live service cannot substitute a mutable or unexpected image after static checks."""

        pins = json.loads(
            (ROOT / "tests/e2e/evidence/direct-openvasd-pins.json").read_text(
                encoding="utf-8"
            )
        )
        service_to_pin = {
            "gvmd": "gvmd",
            "configure-direct-openvasd": "gvmd",
            "vulnerability-tests": "vulnerability-tests",
            "data-objects": "data-objects",
            "report-formats": "report-formats",
            "gpg-data": "gpg-data",
            "notus-data": "notus-data",
            "pg-gvm-migrator": "pg-gvm-migrator",
            "pg-gvm": "pg-gvm",
            "openvasd-scenario-proxy": "scenario-proxy",
            "e2e-target": "e2e-target",
        }
        records = {
            service: {
                "image": pins["runtimeImages"][pin],
                "sourceRevision": "unused",
                "imageDigest": "sha256:runtime",
            }
            for service, pin in service_to_pin.items()
        }
        records["openvasd-backend"] = {
            "image": pins["emulator"]["image"],
            "sourceRevision": pins["emulator"]["sourceRevision"],
            "imageDigest": "sha256:emulator",
        }
        PROVENANCE.assert_pinned_runtime(records, pins, "direct-openvasd")

        records["e2e-target"]["image"] = "example.invalid/mutable:latest"
        with self.assertRaisesRegex(RuntimeError, "image drifted"):
            PROVENANCE.assert_pinned_runtime(records, pins, "direct-openvasd")

    def test_fixture_fetch_fails_closed_on_hash_drift(self) -> None:
        """An upstream file change cannot silently alter the pinned test backend."""

        pins = {
            "emulator": {
                "sourceRepository": "greenbone/gvm-openapi-emulator",
                "sourceRevision": "d85f0bf9101398738cf73abd2725540e38dd355e",
                "openapiSha256": "0" * 64,
                "files": {"swagger.json": "0" * 64},
            }
        }
        with self.assertRaisesRegex(FIXTURES.FixtureError, "SHA-256 mismatch"):
            FIXTURES.fetch_fixtures(pins, lambda _url: b"changed")

    def test_fixture_download_rejects_non_github_transport(self) -> None:
        """Pinned fixture retrieval must not permit urllib-style local file access."""

        with self.assertRaisesRegex(FIXTURES.FixtureError, "untrusted fixture URL"):
            FIXTURES.download("file:///etc/passwd")

    def test_job_log_redirect_drops_github_authorization(self) -> None:
        """Actions signed log redirects must not receive the GitHub bearer token."""

        responses = [
            (
                302,
                {
                    "location": (
                        "https://productionresultssa9.blob.core.windows.net/"
                        "actions-results/job.log?sig=signed"
                    )
                },
                b"",
            ),
            (200, {}, b"test portable_contract ... ok\n"),
        ]
        with patch.object(FINALIZER, "https_response", side_effect=responses) as request:
            output = FINALIZER.github_text(
                "/repos/greenbone/rust-gvm-api/actions/jobs/42/logs", "secret-token"
            )
        self.assertIn("portable_contract", output)
        self.assertIn("Authorization", request.call_args_list[0].args[2])
        self.assertNotIn("Authorization", request.call_args_list[1].args[2])

    def test_direct_manifest_rejects_a_missing_runtime_pin(self) -> None:
        """Every service in the shadow/real topology must retain an immutable image input."""

        pins = json.loads(
            (ROOT / "tests/e2e/evidence/direct-openvasd-pins.json").read_text(
                encoding="utf-8"
            )
        )
        del pins["runtimeImages"]["e2e-target"]
        with self.assertRaisesRegex(CHECKER.EvidenceError, "exactly cover"):
            CHECKER.validate_direct_pins(pins)

    def test_shadow_comparison_covers_every_named_contract_and_fault(self) -> None:
        """The advisory lane may not report success while omitting a named contract."""

        test_results = {
            test["id"].rsplit("::", 1)[1]: "pass" for test in self.inventory["tests"]
        }
        fault_document = {
            "schemaVersion": 1,
            "lane": "community-direct-openvasd-shadow",
            "scenarios": [
                {
                    "scenario": scenario,
                    "injectedAt": "openvasd-http-boundary",
                    "gatewayMapping": "task:Interrupted",
                    "target": "e2e-target",
                    "outcome": "pass",
                }
                for scenario in sorted(FINALIZER.EXPECTED_FAULTS)
            ],
        }
        CHECKER.validate_fault_mappings(fault_document)
        outcomes = FINALIZER.aggregate_outcomes(
            self.inventory, test_results, fault_document
        )
        comparison = FINALIZER.build_comparison(self.inventory, outcomes, outcomes)
        CHECKER.validate_comparison(
            comparison, self.owners, set(self.inventory["contractOwners"])
        )
        self.assertEqual(
            set(self.inventory["contractOwners"]),
            {row["contract"] for row in comparison["contracts"]},
        )
        fault_row = next(
            row
            for row in comparison["contracts"]
            if row["contract"] == "scanner.direct-openvasd-error-mapping"
        )
        self.assertEqual(fault_row["candidate"], "pass")
        self.assertEqual(fault_row["disposition"], "backend-specific")

    def test_cargo_result_parser_handles_actions_timestamps_and_color(self) -> None:
        """Per-contract OSP evidence must survive the exact formatting of Actions logs."""

        output = (
            "2026-11-11T12:00:00Z test portable_contract ... \x1b[32mok\x1b[0m\n"
            "2026-11-11T12:00:01Z test failed_contract ... \x1b[31mFAILED\x1b[0m\n"
        )
        self.assertEqual(
            FINALIZER.parse_test_results(output),
            {"portable_contract": "pass", "failed_contract": "fail"},
        )

    def test_failure_classification_distinguishes_all_operational_phases(self) -> None:
        """One failed run must retain enough step evidence to triage without rerunning."""

        cases = {
            "Fetch pinned OpenVASD fixtures": "setup",
            "Verify direct-OpenVASD readiness and identities": "readiness",
            "Run all named community contracts": "assertion",
            "Tear down direct-OpenVASD shadow runtime": "cleanup",
            "Set up Rust": "runner",
        }
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory)
            for step_name, expected in cases.items():
                job = {
                    "conclusion": "failure",
                    "steps": [{"name": step_name, "conclusion": "failure"}],
                }
                self.assertEqual(FINALIZER.classify_failure(job, raw), expected)
            (raw / "application-failure").touch()
            job = {
                "conclusion": "failure",
                "steps": [
                    {"name": "Run all named community contracts", "conclusion": "failure"}
                ],
            }
            self.assertEqual(FINALIZER.classify_failure(job, raw), "application")

    def test_shadow_observation_gate_requires_runs_and_elapsed_days(self) -> None:
        """Synthetic unit data may test the gate, but checked-in evidence cannot claim elapsed time."""

        def runs(count: int, days: int) -> list[dict[str, str]]:
            start = OBSERVATIONS.parse_timestamp("2026-01-01T00:00:00Z")
            return [
                {"createdAt": (start + OBSERVATIONS.dt.timedelta(days=days * index / max(1, count - 1))).isoformat()}
                for index in range(count)
            ]

        self.assertFalse(OBSERVATIONS.gate_satisfied(runs(30, 13)))
        self.assertFalse(OBSERVATIONS.gate_satisfied(runs(29, 14)))
        self.assertTrue(OBSERVATIONS.gate_satisfied(runs(30, 14)))

    def test_shadow_observations_require_one_pinned_input_fingerprint(self) -> None:
        """The elapsed gate cannot combine runs whose lane topology or harness inputs differ."""

        digest = "sha256:" + "a" * 64
        provenance = {
            "schemaVersion": 1,
            "gvmd": {"imageDigest": "sha256:gvmd"},
            "scanner": {"imageDigest": "sha256:scanner"},
            "feedData": [{"name": "feed", "revision": "sha256:feed"}],
            "fixtures": [
                {"name": "GVM_GATEWAY_E2E_TARGET_HOST", "revision": "e2e-target"},
                {"name": "scanner-backend-identity", "revision": "openvasd-backend"},
                {"name": "synthetic-target-identity", "revision": "e2e-target"},
                {"name": "tests/e2e/compose.direct-openvasd.yaml", "revision": digest},
                {"name": "synthetic-target-image", "revision": digest},
                {
                    "name": "tests/e2e/evidence/direct-openvasd-pins.json",
                    "revision": digest,
                },
                {
                    "name": "gvm-openapi-emulator/examples/openvasd/swagger.json",
                    "revision": digest,
                },
                {
                    "name": "gvm-openapi-emulator/examples/openvasd",
                    "revision": digest,
                },
                {"name": "tests/e2e-harness", "revision": digest},
            ],
            "apiContract": {"revision": "sha256:api"},
            "composeSha256": "compose-a",
            "runner": {"image": "ubuntu-24.04"},
        }
        first = OBSERVATIONS.comparison_fingerprint(provenance)
        changed = copy.deepcopy(provenance)
        changed["fixtures"][-1]["revision"] = "sha256:" + "b" * 64
        self.assertNotEqual(first, OBSERVATIONS.comparison_fingerprint(changed))

        rotated_runner = copy.deepcopy(provenance)
        rotated_runner["runner"]["image"] = "ubuntu-24.04-next"
        self.assertEqual(first, OBSERVATIONS.comparison_fingerprint(rotated_runner))

        conflated = copy.deepcopy(provenance)
        conflated["fixtures"][2]["revision"] = "openvasd-backend"
        with self.assertRaisesRegex(ValueError, "synthetic-target-identity"):
            OBSERVATIONS.comparison_fingerprint(conflated)

    def test_workflows_preserve_osp_gate_and_keep_new_lanes_advisory(self) -> None:
        """Shadow coverage follows OSP triggers without changing required status policy."""

        e2e = (ROOT / ".github/workflows/nightly-e2e.yml").read_text(encoding="utf-8")
        real = (ROOT / ".github/workflows/real-openvasd-compatibility.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("name: REST Discovery Scan E2E\n", e2e)
        self.assertIn("name: REST Discovery Scan E2E (main)\n", e2e)
        self.assertIn("name: REST Discovery Scan E2E (devel)\n", e2e)
        self.assertIn("name: Direct OpenVASD Shadow E2E (advisory)\n", e2e)
        self.assertIn("if: needs.classify-changes.outputs.e2e_required == 'true'", e2e)
        main_gate = e2e.split("  rest-discovery-scan-main-gate:", 1)[1].split(
            "  rest-discovery-scan-devel-gate:", 1
        )[0]
        devel_gate = e2e.split("  rest-discovery-scan-devel-gate:", 1)[1]
        self.assertNotIn("direct-openvasd-shadow", main_gate)
        self.assertNotIn("direct-openvasd-shadow", devel_gate)
        self.assertNotIn("pull_request_target:", e2e)
        self.assertIn("workflow_dispatch:", real)
        self.assertIn("schedule:", real)
        self.assertNotIn("pull_request:", real)
        self.assertIn("Real OpenVASD Direct-HTTP Compatibility (advisory)", real)

    def test_direct_compose_uses_pinned_separate_topology(self) -> None:
        """The profile must wire a real target beside, never as, its scanner backend."""

        compose = (ROOT / "tests/e2e/compose.direct-openvasd.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("profiles: [direct-openvasd]", compose)
        self.assertIn("  openvasd-backend:", compose)
        self.assertIn("  e2e-target:", compose)
        self.assertIn("--scanner-host=openvasd-backend", compose)
        self.assertNotIn("--scanner-host=e2e-target", compose)
        self.assertEqual(compose.count('GVMD_ENABLE_OPENVASD: "true"'), 2)
        pins = json.loads(
            (ROOT / "tests/e2e/evidence/direct-openvasd-pins.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn(pins["emulator"]["image"], compose)
        for image in pins["runtimeImages"].values():
            self.assertIn("@sha256:", image)


if __name__ == "__main__":
    unittest.main()
