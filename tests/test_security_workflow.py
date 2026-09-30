"""Policy tests keep the required Security aggregate deterministic and fail closed."""

import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-publish.yml"
REQUIRED_JOBS = (
    "cargo-audit",
    "cargo-machete",
    "cargo-vet",
    "security-policy",
    "sbom-quality",
    "cargo-geiger-report",
    "cargo-geiger-workspace-gate",
    "semgrep",
)


def source() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def aggregate_needs(workflow: str) -> tuple[str, ...]:
    match = re.search(
        r"(?ms)^  security:\n.*?^    needs:\n(?P<needs>(?:      - .+\n)+).*?^    runs-on:",
        workflow,
    )
    if match is None:
        raise AssertionError("Security aggregate needs block not found")
    return tuple(re.findall(r"(?m)^      - ([a-z0-9-]+)$", match.group("needs")))


class SecurityWorkflowTests(unittest.TestCase):
    def test_all_protected_lane_and_manual_triggers_are_present(self) -> None:
        workflow = source()
        self.assertIn("merge_group:", workflow)
        self.assertEqual(workflow.count("branches: [main, next]"), 2)
        self.assertIn("schedule:", workflow)
        self.assertIn("workflow_dispatch:", workflow)

    def test_every_required_job_is_fail_closed_in_aggregate(self) -> None:
        workflow = source()
        self.assertEqual(aggregate_needs(workflow), REQUIRED_JOBS)
        for job in REQUIRED_JOBS:
            variable = job.upper().replace("-", "_")
            with self.subTest(job=job):
                self.assertIn(f'test "${variable}_RESULT" = success', workflow)

    def test_external_actions_and_security_tools_are_pinned(self) -> None:
        workflow = source()
        uses = re.findall(r"(?m)^\s+- uses: ([^\s]+)", workflow)
        self.assertTrue(uses)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"@[0-9a-f]{40}$")
        for value in (
            'CARGO_AUDIT_VERSION: "0.22.2"',
            'CARGO_CYCLONEDX_VERSION: "0.5.9"',
            'CARGO_GEIGER_VERSION: "0.13.0"',
            'CARGO_MACHETE_VERSION: "0.9.2"',
            'CARGO_VET_VERSION: "0.10.2"',
            'SBOMQS_VERSION: "v2.0.5"',
            "semgrep/semgrep:1.176.1@sha256:",
        ):
            self.assertIn(value, workflow)
        self.assertNotRegex(workflow, r"cargo install [^\n]+(?!@\d)")

        release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CARGO_CYCLONEDX_VERSION: "0.5.9"', release)
        self.assertIn("tool: cargo-cyclonedx@${{ env.CARGO_CYCLONEDX_VERSION }}", release)
        self.assertNotIn("cargo install cargo-cyclonedx", release)

    def test_networked_jobs_use_hardened_runner_and_evidence_is_retained(self) -> None:
        workflow = source()
        self.assertEqual(workflow.count("step-security/harden-runner@"), len(REQUIRED_JOBS))
        self.assertEqual(workflow.count("egress-policy: audit"), len(REQUIRED_JOBS))
        self.assertIn("name: sbom-quality-evidence", workflow)
        self.assertIn("name: cargo-geiger-report", workflow)
        self.assertGreaterEqual(workflow.count("if-no-files-found: error"), 2)

    def test_vet_baseline_uses_exact_versions_and_review_imports(self) -> None:
        config = tomllib.loads(
            (ROOT / "supply-chain" / "config.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(set(config["imports"]), {"google", "mozilla", "rust-gvm"})
        exemptions = config.get("exemptions", {})
        self.assertTrue(exemptions)
        for crate, entries in exemptions.items():
            for entry in entries:
                with self.subTest(crate=crate, entry=entry):
                    self.assertIsInstance(entry.get("version"), str)
                    self.assertNotIn("*", entry["version"])
                    self.assertIn(entry.get("criteria"), {"safe-to-run", "safe-to-deploy"})


if __name__ == "__main__":
    unittest.main()
