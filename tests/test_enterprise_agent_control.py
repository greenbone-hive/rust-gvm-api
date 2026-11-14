#!/usr/bin/env python3
"""Regression tests for the isolated Phase 4 Agent Control workflows."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


REAL = load("real_agent_control_compatibility", "scripts/run-real-agent-control-compatibility.py")
RESET = load("reset_enterprise_agent_control", "scripts/reset-enterprise-agent-control.py")
FINALIZER = load(
    "finalize_enterprise_agent_control_evidence",
    "scripts/finalize-enterprise-agent-control-evidence.py",
)


class EnterpriseAgentControlTests(unittest.TestCase):
    def test_real_probe_rejects_incomplete_operator_inputs_before_network_access(self) -> None:
        """Credentials and provenance must never be guessed for the advisory real lane."""

        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(REAL.CompatibilityFailure) as caught:
                REAL.validated_inputs()
        self.assertEqual(caught.exception.classification, "incomplete-operator-input")

    def test_real_probe_rejects_credential_bearing_or_non_https_origins(self) -> None:
        """The real probe must keep secrets in explicit headers and require TLS."""

        inputs = {key: "pinned" for key in REAL.REQUIRED_INPUTS}
        inputs["REAL_AGENT_CONTROL_URL"] = "http://user:secret@example.test"
        with patch.dict(os.environ, inputs, clear=True):
            with self.assertRaises(REAL.CompatibilityFailure) as caught:
                REAL.validated_inputs()
        self.assertEqual(caught.exception.classification, "incomplete-operator-input")

    def test_real_probe_uses_exact_raw_array_header_pagination_and_swagger_lang(self) -> None:
        """The direct-service probe must stay bound to PR #50, not the gateway page model."""

        contract, agent_control = REAL.load_wire_contract()
        self.assertEqual(contract["inventoryResponseShape"], "raw-array")
        self.assertEqual(contract["paginationQuery"], {"page": "page", "perPage": "per_page"})
        self.assertEqual(
            contract["paginationHeaders"],
            {"totalCount": "x-total-count", "page": "x-page", "perPage": "x-per-page"},
        )
        self.assertEqual(
            contract["installerInstructionsPath"],
            "/agent-control/public/v2/api/installers/instructions",
        )
        self.assertEqual(contract["installerLanguageParameter"], "lang")
        self.assertNotEqual(contract["installerLanguageParameter"], "language")
        self.assertEqual(
            agent_control["swaggerSha256"],
            "902715531919d1ebea417a4b2a453dd39ac02b411be2434e441498b0ccfad24d",
        )

    def test_real_probe_preserves_and_accepts_exact_empty_inventory_headers(self) -> None:
        """The bounded empty inventory must retain exact integer pagination evidence."""

        contract, _agent_control = REAL.load_wire_contract()
        headers = {
            "x-total-count": ["0"],
            "x-page": ["1"],
            "x-per-page": ["1"],
        }
        self.assertEqual(
            REAL.empty_inventory_page([], headers, contract),
            {
                "totalCount": 0,
                "page": 1,
                "perPage": 1,
                "rawHeaders": headers,
            },
        )

    def test_real_probe_rejects_missing_duplicate_invalid_or_inconsistent_pagination(self) -> None:
        """No malformed direct-service pagination metadata may collapse into a passing page."""

        contract, _agent_control = REAL.load_wire_contract()
        message = Message()
        message.add_header("X-Total-Count", "0")
        message.add_header("X-Page", "1")
        message.add_header("X-Page", "2")
        message.add_header("X-Per-Page", "1")
        duplicate_headers = REAL.preserve_headers(message)
        cases = {
            "missing": {"x-total-count": ["0"], "x-page": ["1"]},
            "duplicate": duplicate_headers,
            "invalid": {
                "x-total-count": ["0"],
                "x-page": ["one"],
                "x-per-page": ["1"],
            },
            "inconsistent": {
                "x-total-count": ["1"],
                "x-page": ["1"],
                "x-per-page": ["1"],
            },
        }
        for name, headers in cases.items():
            with self.subTest(name=name), self.assertRaises(REAL.CompatibilityFailure) as caught:
                REAL.empty_inventory_page([], headers, contract)
            self.assertEqual(caught.exception.classification, "pagination")

    def test_real_probe_rejects_gateway_page_shape_for_direct_inventory(self) -> None:
        """A gateway data/pagination object cannot masquerade as the direct raw-array response."""

        contract, _agent_control = REAL.load_wire_contract()
        with self.assertRaises(REAL.CompatibilityFailure) as caught:
            REAL.empty_inventory_page(
                {"data": [], "pagination": {"page": 1, "perPage": 1}},
                {"x-total-count": ["0"], "x-page": ["1"], "x-per-page": ["1"]},
                contract,
            )
        self.assertEqual(caught.exception.classification, "inventory")

    def test_real_probe_names_every_bounded_dependency_failure(self) -> None:
        """Successful evidence must retain the issue #680 dependency-failure taxonomy."""

        self.assertEqual(
            set(REAL.DEPENDENCY_FAILURE_CLASSIFICATIONS),
            {
                "connectivity",
                "health",
                "authentication",
                "signing",
                "authenticated-signed-access",
                "inventory",
                "pagination",
                "scan-agent-configuration",
                "installer-instructions",
            },
        )

    def test_real_probe_runs_bounded_read_only_contract_with_exact_paths(self) -> None:
        """The smoke must use PR #50 query names and retain raw pagination evidence end to end."""

        values = {key: "pinned" for key in REAL.REQUIRED_INPUTS}
        values.update(
            {
                "REAL_AGENT_CONTROL_URL": "https://agent-control.example.test",
                "REAL_AGENT_CONTROL_HEALTH_PATH": "/health/ready",
                "REAL_AGENT_CONTROL_AUTH_HEADER_NAME": "Authorization",
                "REAL_AGENT_CONTROL_AUTH_HEADER_VALUE": "Bearer test",
                "REAL_AGENT_CONTROL_SIGNING_HEADER_NAME": "X-Signature",
                "REAL_AGENT_CONTROL_SIGNING_HEADER_VALUE": "signed",
            }
        )
        pagination_headers = {
            "content-type": ["application/json"],
            "x-total-count": ["0"],
            "x-page": ["1"],
            "x-per-page": ["1"],
        }
        responses = [
            (200, {"content-type": ["application/json"]}, b'{"status":"ready"}'),
            (401, {"content-type": ["application/json"]}, b'{"error":"unauthorized"}'),
            (403, {"content-type": ["application/json"]}, b'{"error":"unsigned"}'),
            (200, pagination_headers, b"[]"),
            (200, {"content-type": ["application/json"]}, b"{}"),
            (200, {"content-type": ["application/json"]}, b"{}"),
        ]
        with patch.object(REAL, "request", side_effect=responses) as mocked_request:
            evidence = REAL.run(values, timeout=5)
        paths = [call.args[1] for call in mocked_request.call_args_list]
        self.assertEqual(paths.count("/api/v1/admin/agents?page=1&per_page=1"), 3)
        self.assertIn(
            "/agent-control/public/v2/api/installers/instructions?lang=en&origin_url=https%3A%2F%2Fmanager.example",
            paths,
        )
        self.assertFalse(any("language=" in path for path in paths))
        self.assertEqual(evidence["pagination"]["rawHeaders"]["x-page"], ["1"])
        self.assertTrue(evidence["emptyInventory"])

    def test_real_probe_rejects_mutable_service_provenance(self) -> None:
        """A reachable endpoint cannot pass without exact service/API/fixture identities."""

        inputs = {key: "pinned" for key in REAL.REQUIRED_INPUTS}
        inputs.update(
            {
                "REAL_AGENT_CONTROL_URL": "https://agent-control.example.test",
                "REAL_AGENT_CONTROL_AUTH_HEADER_NAME": "Authorization",
                "REAL_AGENT_CONTROL_SIGNING_HEADER_NAME": "X-Signature",
                "REAL_AGENT_CONTROL_SERVICE_REVISION": "latest",
            }
        )
        with patch.dict(os.environ, inputs, clear=True):
            with self.assertRaises(REAL.CompatibilityFailure) as caught:
                REAL.validated_inputs()
        self.assertEqual(caught.exception.classification, "incomplete-operator-input")

    def test_reset_rejects_non_success_status_instead_of_hiding_state_drift(self) -> None:
        """Repeatability depends on an acknowledged reset from each stateful emulator."""

        with patch.object(RESET, "request", return_value=(401, b"denied")):
            with self.assertRaises(RESET.ResetError):
                RESET.reset("http://127.0.0.1:8090", "wrong", "agent-control")

    def test_checked_in_enterprise_pin_is_an_exact_commit_not_a_branch(self) -> None:
        """The temporary PR #50 workaround must remain immutable and self-identifying."""

        pins = json.loads(
            (ROOT / "tests/e2e/evidence/enterprise-agent-control-pins.json").read_text()
        )
        self.assertEqual(
            pins["sourceBuildWorkaround"]["revision"],
            "82c03f6cf190942764f99ac799efc539cc57b4ca",
        )
        self.assertEqual(pins["agentControl"]["fixtureDirectory"], "examples/agent-folder")
        self.assertEqual(
            pins["sourceBuildWorkaround"]["dockerfileSha256"],
            "833c06bb50137c10f08600af23757d0bc7d21a36e5d8092f48a8b088d97a647a",
        )
        self.assertEqual(
            pins["agentControl"]["fixtureTreeSha256"],
            "489b0ca2a6704bf8687a191a400ca6029851719a4c8904a5ac365ea53719f3da",
        )
        self.assertNotIn("feat/49-stateful-agent-control-profile", json.dumps(pins))

    def test_production_image_excludes_enterprise_e2e_tools(self) -> None:
        """The default image must remain production-only while Compose opts into test tools."""

        containerfile = (ROOT / "Containerfile").read_text()
        test_stage = containerfile.split("FROM builder AS enterprise-test-tools", 1)[1]
        production_stage = test_stage.split("FROM debian:trixie-slim AS runtime", 1)[1]
        self.assertIn("--bin enterprise-feature-preflight", test_stage)
        self.assertIn("--bin agent-control-scenario-proxy", test_stage)
        self.assertNotIn("enterprise-feature-preflight", production_stage)
        self.assertNotIn("agent-control-scenario-proxy", production_stage)

        compose = (ROOT / "tests/e2e/compose.enterprise-agent-control.yaml").read_text()
        self.assertGreaterEqual(compose.count("target: enterprise-test-tools"), 2)
        self.assertIn("--scanner-host=agent-control-scenario-proxy", compose)
        self.assertIn("127.0.0.1:8091:8081", compose)

    def test_phase3_promotion_is_a_checked_in_prerequisite(self) -> None:
        """A clean checkout must keep Phase 4 advisory until Phase 3 is promoted."""

        policy = json.loads(
            (ROOT / "tests/e2e/evidence/enterprise-promotion-policy.json").read_text()
        )
        self.assertFalse(policy["promotionAllowed"])
        self.assertIn(
            "Phase 3 direct-OpenVASD is approved and promoted",
            policy["promotionPrerequisites"],
        )

    def test_failure_proxy_control_is_authenticated_and_loopback_published(self) -> None:
        """Failure selection must not become an unauthenticated runtime control surface."""

        compose = (ROOT / "tests/e2e/compose.enterprise-agent-control.yaml").read_text()
        proxy = (
            ROOT / "tests/e2e/src/bin/agent-control-scenario-proxy.rs"
        ).read_text()
        self.assertIn("127.0.0.1:8091:8081", compose)
        self.assertIn("AGENT_CONTROL_PROXY_CONTROL_TOKEN", compose)
        self.assertIn("header::AUTHORIZATION", proxy)
        self.assertIn("invalid proxy control token", proxy)

    def test_scenario_proxy_selects_upstream_failures_without_fabricating_them(self) -> None:
        """PR #50 must remain the sole owner of scenario status, headers, body, and delay."""

        proxy = (
            ROOT / "tests/e2e/src/bin/agent-control-scenario-proxy.rs"
        ).read_text()
        self.assertIn('const EMULATOR_SCENARIO_HEADER: &str = "X-Emulator-Scenario"', proxy)
        self.assertIn("upstream.header(EMULATOR_SCENARIO_HEADER, scenario)", proxy)
        self.assertIn("headers = response.headers().clone()", proxy)
        for fabricated_logic in (
            "StatusCode::SERVICE_UNAVAILABLE",
            "StatusCode::TOO_MANY_REQUESTS",
            "StatusCode::GATEWAY_TIMEOUT",
            "tokio::time::sleep",
            "malformed-agent-control-response",
            "injected authentication",
            "injected conflict",
        ):
            self.assertNotIn(fabricated_logic, proxy)

    def test_preflight_failure_finalizes_routes_as_not_run_with_raw_responses(self) -> None:
        """Feature mismatches must be classified before any route result is inferred."""

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            (directory / "preflight.json").write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "classification": "preflight-configuration",
                        "version": {"rawResponse": "<get_version_response/>"},
                        "features": {"rawResponse": "<get_features_response/>"},
                    }
                )
            )
            (directory / "provenance.json").write_text(
                json.dumps({"lane": "enterprise-agent-control-emulator-advisory"})
            )
            (directory / "reset-last.json").write_text(json.dumps({"status": "passed"}))
            result = directory / "result.json"
            with patch.object(
                sys,
                "argv",
                [
                    "finalize-enterprise-agent-control-evidence.py",
                    "--evidence-dir",
                    str(directory),
                    "--output",
                    str(result),
                ],
            ):
                with self.assertRaises(FINALIZER.FinalizationError):
                    FINALIZER.main()
            evidence = json.loads(result.read_text())
            self.assertEqual(evidence["failureClassification"], "preflight-configuration")
            self.assertTrue(evidence["preflight"]["rawResponsesRetained"])
            self.assertEqual(
                [item["outcome"] for item in evidence["repeatability"]],
                ["not-run", "not-run"],
            )

    def test_finalizer_requires_all_named_failure_scenarios_in_each_repetition(self) -> None:
        """A lifecycle pass cannot hide missing gvmd-to-Agent-Control failure coverage."""

        scenarios = {
            "authentication": ([(401, "unauthorized"), (502, "backend_unavailable")], 401),
            "unavailable": ([(502, "backend_unavailable")], 502),
            "malformed": ([(502, "backend_unavailable")], 502),
            "conflict": ([(502, "backend_unavailable")], 502),
            "rate-limit": ([(502, "backend_unavailable")], 502),
            "timeout": ([(502, "backend_unavailable"), (504, "gateway_timeout")], 504),
        }
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            (directory / "preflight.json").write_text(
                json.dumps(
                    {
                        "status": "passed",
                        "classification": None,
                        "version": {"rawResponse": "<get_version_response/>"},
                        "features": {"rawResponse": "<get_features_response/>"},
                    }
                )
            )
            (directory / "provenance.json").write_text(
                json.dumps({"lane": "enterprise-agent-control-emulator-advisory"})
            )
            (directory / "reset-last.json").write_text(json.dumps({"status": "passed"}))
            (directory / "fixture-configuration.json").write_text(
                json.dumps({"status": "passed"})
            )
            evidence_lines = [
                "AGENT_CONTROL_FAILURE_EVIDENCE "
                + json.dumps(
                    {
                        "scenario": scenario,
                        "injectedAt": "upstream-agent-control-profile-selected-via-proxy",
                        "allowedMappings": [
                            {"status": status, "classification": classification}
                            for status, classification in allowed
                        ],
                        "observedStatus": status,
                        "classification": (
                            "unauthorized"
                            if status == 401
                            else "gateway_timeout"
                            if status == 504
                            else "backend_unavailable"
                        ),
                        "outcome": "pass",
                    }
                )
                for scenario, (allowed, status) in scenarios.items()
            ]
            for repetition in (1, 2):
                (directory / f"contracts-{repetition}.log").write_text(
                    "\n".join(
                        [
                            *evidence_lines,
                            "test rest_enterprise_agent_control_lifecycle_is_repeatable_and_fail_closed ... ok",
                        ]
                    )
                )
            result = directory / "result.json"
            with patch.object(
                sys,
                "argv",
                [
                    "finalize-enterprise-agent-control-evidence.py",
                    "--evidence-dir",
                    str(directory),
                    "--output",
                    str(result),
                ],
            ):
                self.assertEqual(FINALIZER.main(), 0)
            evidence = json.loads(result.read_text())
            self.assertEqual(evidence["status"], "passed")
            self.assertEqual(len(evidence["failureScenarios"]), 12)


if __name__ == "__main__":
    unittest.main()
