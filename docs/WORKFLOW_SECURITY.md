# Workflow Security Policy

The required `Security` check is a fail-closed aggregate over Cargo Audit,
Cargo Machete, Cargo Vet, security-policy regression tests, SBOM quality,
Cargo Geiger evidence, the first-party unsafe-code gate, and direct Semgrep.
Every dependency must finish with `success`; failure, cancellation, or an
unexpected skip makes the aggregate fail without changing its branch-protection
context name.

## Deterministic tooling and workflow actions

External actions are pinned by full commit SHA. Security tools are installed at
the versions declared in `.github/workflows/security.yml`; do not replace those
versions with tags such as `latest`. Networked jobs use least-privilege
permissions and StepSecurity Harden-Runner in audited-egress mode. Move to an
egress allowlist only after observed Cargo, crates.io, GitHub, Go, Semgrep, and
SARIF endpoints have been reviewed across scheduled, pull-request, and
merge-queue runs.

## Updating Cargo Vet evidence

The repository-owned Vet store is `supply-chain/` and applies to Cargo's locked,
all-feature workspace graph. `config.toml` contains exact-version bootstrap
exemptions plus the Google, Mozilla, and rust-gvm review imports; it contains no
wildcard exemptions. `imports.lock` freezes the imported evidence used by CI.

For a dependency update:

1. Run `cargo vet --locked` to identify missing evidence.
2. Prefer a qualifying imported audit. Refresh deliberately with
   `cargo vet regenerate imports`, inspect the diff, and commit the resulting
   `imports.lock` change.
3. If no suitable review exists, inspect the crate or version delta and record
   it with `cargo vet certify` using the narrowest applicable criterion.
4. Use a new exact-version exemption only to record an explicitly reviewed
   bootstrap decision. Explain that decision in the PR; never add wildcard,
   open-ended, or undocumented broad exemptions.
5. Run `cargo vet --locked` again before pushing.

## SBOM policy

Security installs the pinned `cargo-cyclonedx` release, verifies `Cargo.lock`
through `cargo metadata --locked --all-features`, and generates CycloneDX 1.5
JSON for every member of `supply-chain/workspace-packages.toml`.
`collect_workspace_sboms.py` fails unless exactly one generated document exists
for every inventoried package. `sbom_postprocess.py` adds deterministic document
licensing, build-lifecycle, supplier, repository, and completeness metadata;
`check_sbom_quality.py` fails if the machine-readable `sbomqs` result is absent,
malformed, or below 8.3 for any file. The generated SBOMs and score report are
uploaded as workflow evidence.

When updating `cargo-cyclonedx` or `sbomqs`, review release notes, update the
pinned version in Security (and the matching release-workflow pin for
`cargo-cyclonedx`), run the helper unit tests, generate the complete workspace
SBOM set, and confirm every score remains at least 8.3.

## First-party unsafe-code policy

`supply-chain/workspace-packages.toml` is the explicit first-party inventory.
The security helper compares it with locked Cargo metadata before producing one
Cargo Geiger JSON report per member. Adding, removing, or renaming any workspace
member without updating the inventory therefore fails both Geiger jobs.

All inventoried packages currently have a zero-unsafe policy. Transitive
dependency unsafe counts remain visible in the uploaded reports but do not
become false first-party violations. A future exception requires a separately
reviewed issue and PR that documents the exact package, code boundary, safety
invariants, owner, and removal trigger; it must also add a narrow machine-
checked allowance rather than weakening or skipping the workspace gate.

## Local policy verification

Run the deterministic helper suite with:

```bash
python3 -B -m unittest \
  tests.test_sbom_postprocess \
  tests.test_sbom_quality \
  tests.test_workspace_security \
  tests.test_security_workflow -q
cargo vet --locked
```

The normal Rust format, test, strict Clippy, Cargo Deny, Cargo Audit, Cargo
Machete, and live REST Discovery Scan E2E gates remain unchanged.
