"""Policy tests keep the required Security aggregate deterministic and fail closed."""

import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-publish.yml"
SETUP_RUST_ACTION = (
    "greenbone/actions/setup-rust@d6d4c9500cb4e83f8a516ec1d40b04bcc720bd22"
)
BLOCKED_ACTIONS = (
    "dtolnay/rust-toolchain@",
    "Swatinem/rust-cache@",
    "EmbarkStudios/cargo-deny-action@",
    "taiki-e/install-action@",
)
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


def workflow_sources() -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(WORKFLOW_DIR.glob("*.yml"))
    }


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

    def test_release_token_is_confined_to_release_write_workflows(self) -> None:
        workflows = workflow_sources()
        token_users = {
            name
            for name, workflow in workflows.items()
            if "secrets.RELEASE_TOKEN" in workflow
        }

        self.assertEqual(token_users, {"release-prepare.yml", "release-tag.yml"})
        for name, workflow in workflows.items():
            with self.subTest(workflow=name):
                self.assertNotIn(
                    "Configure git credentials for private deps", workflow
                )
                self.assertNotIn("git config --global url.", workflow)

    def test_external_actions_and_cargo_tools_are_pinned(self) -> None:
        workflows = workflow_sources()
        all_workflows = "\n".join(workflows.values())
        uses = re.findall(r"(?m)^\s+uses: ([^\s]+)|^\s+- uses: ([^\s]+)", all_workflows)
        uses = [direct or named for direct, named in uses]
        self.assertTrue(uses)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"@[0-9a-f]{40}$")
        for blocked in BLOCKED_ACTIONS:
            with self.subTest(blocked=blocked):
                self.assertNotIn(blocked, all_workflows)

        setup_count = all_workflows.count(f"uses: {SETUP_RUST_ACTION}")
        cache_keys = re.findall(r"(?m)^\s+cache-key: (.+)$", all_workflows)
        self.assertGreater(setup_count, 0)
        self.assertEqual(len(cache_keys), setup_count)
        self.assertEqual(len(cache_keys), len(set(cache_keys)))
        for cache_key in cache_keys:
            with self.subTest(cache_key=cache_key):
                self.assertIn("${{ runner.os }}", cache_key)
                self.assertIn("${{ runner.arch }}", cache_key)
                self.assertIn("${{ hashFiles('**/Cargo.lock') }}", cache_key)

        expected_installs = (
            'cargo install cargo-deny --version "${CARGO_DENY_VERSION}" --locked',
            'cargo install cargo-llvm-cov --version "${CARGO_LLVM_COV_VERSION}" --locked',
            'cargo install cargo-audit --version "${CARGO_AUDIT_VERSION}" --locked',
            'cargo install cargo-machete --version "${CARGO_MACHETE_VERSION}" --locked',
            'cargo install cargo-vet --version "${CARGO_VET_VERSION}" --locked',
            'cargo install cargo-cyclonedx --version "${CARGO_CYCLONEDX_VERSION}" --locked',
            'cargo install cargo-geiger --version "${CARGO_GEIGER_VERSION}" --locked',
            'cargo install cargo-geiger --version "${CARGO_GEIGER_VERSION}" --locked',
            'cargo install cargo-cyclonedx --version "${CARGO_CYCLONEDX_VERSION}" --locked',
        )
        installs = re.findall(r"(?m)^\s+run: (cargo install .+)$", all_workflows)
        self.assertCountEqual(installs, expected_installs)
        for install in installs:
            with self.subTest(install=install):
                self.assertRegex(
                    install,
                    r'^cargo install cargo-[a-z0-9-]+ --version "\$\{CARGO_[A-Z0-9_]+_VERSION\}" --locked$',
                )

        workflow = source()
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

        ci = workflows["ci.yml"]
        self.assertIn('CARGO_DENY_VERSION: "0.20.2"', ci)
        self.assertIn('CARGO_LLVM_COV_VERSION: "0.9.1"', ci)
        self.assertIn("RUSTUP_TOOLCHAIN: ${{ matrix.rust }}", ci)
        self.assertIn('RUSTUP_TOOLCHAIN: "1.89.0"', ci)
        release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CARGO_CYCLONEDX_VERSION: "0.5.9"', release)
        self.assertIn(
            'cargo install cargo-cyclonedx --version "${CARGO_CYCLONEDX_VERSION}" --locked',
            release,
        )

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
