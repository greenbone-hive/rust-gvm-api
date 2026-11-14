# E2E contract and baseline evidence

This directory is the machine-readable Phase 0 record for migrating the
required community E2E scanner boundary from OSP to direct OpenVASD HTTP. It
does not change the current required OSP job or authorize promotion.

## Inventory and ownership

[`contract-inventory.json`](contract-inventory.json) covers all 44 Rust tests
in the `gvm-gateway-e2e` package:

- 15 local helper/fixture tests;
- 29 ignored compose-backed live tests;
- 32 scanner-independent tests; and
- 8 contracts that currently use the OSP scanner path but are expected to
  migrate to the direct-OpenVASD lane.

There is no intentionally OSP-specific public contract in the current suite.
Every test that declares the `osp-scanner-path` dependency therefore has an
explicit `migrate` disposition. The validator compares Rust test attributes
with inventory IDs, source paths, ignored state, and kind. A new or removed
test makes validation fail until the inventory changes with it.

The inventory also contains closed owner registries for all 49 named contracts
and all 9 named dependencies. Validation rejects an unowned reference and a
stale registry entry, so ownership cannot drift independently from the test
matrix. REST, typed-GMP, and scanner contracts are first-class names; dependency
kinds distinguish components, feed/data, fixtures, and environment inputs.
Every test also declares its feature-flag set explicitly (currently empty).

[`owners.json`](owners.json) assigns accountable Greenbone teams to the
community lane, emulator parity, real-service compatibility, enterprise
coverage, product qualification, and promotion/rollback response. Repository
ownership is the evidence for the first two assignments:
`@greenbone/rust-gvm` owns rust-gvm-api and `@greenbone/gea` owns
gvm-openapi-emulator. Product qualification is separately accountable to
`@greenbone/product-department-developers`; source-lane ownership does not
silently absorb packaged-product responsibility.

## Versioned formats

The closed JSON Schema 2020-12 documents under [`schemas/`](schemas/) define:

- the test-to-contract inventory;
- exact component, feed/data, fixture, runner, and harness provenance;
- OSP/direct-OpenVASD per-contract comparisons; and
- per-run timing, retry, artifact, and failure evidence.

Unknown keys, versions, enum values, owners, tests, and state transitions fail
validation. [`examples/provenance.json`](examples/provenance.json) records the
current stack shape and makes unresolved mutable image tags visible rather than
pretending they are reproducible. The live E2E workflow now captures resolved
container image IDs plus the exact OpenAPI, Compose, and harness revisions into
`e2e-compose-diagnostics/provenance.json` after startup, so future failures can
be tied to immutable runtime inputs.

Failure classification uses exactly these categories: `setup`, `readiness`,
`application`, `assertion`, `cleanup`, `runner`, `unexplained-flake`, and
`unclassified`. An executed failure is never excluded or called a flake merely
because a later run passed. `unexplained-flake` requires explicit evidence from
attempt history; otherwise the collector records `unclassified`. Failed and
timed-out rows also require a triage owner role; successful rows require both
failure fields to be null.

[`direct-openvasd-pins.json`](direct-openvasd-pins.json) is the fail-closed
input manifest for the advisory lanes. It pins emulator source/image, its
OpenAPI and every mounted fixture, gvmd, feed/data images, the target, the
test-only fault proxy, real OpenVASD, runner label, and Rust toolchain.
`scripts/fetch-openvasd-emulator-fixtures.py` downloads only listed files from
the full source commit and rejects any hash mismatch.
Before the shared direct-OpenVASD Compose launcher starts either advisory lane,
`scripts/validate-direct-openvasd-pins.py` resolves every digest-pinned runtime
image in this manifest. An unavailable manifest names the exact immutable image
and stops the launch; no mutable-tag fallback is permitted.

## Advisory direct-OpenVASD shadow lane

The required `REST Discovery Scan E2E` job and its main/devel gate jobs remain
unchanged. `Direct OpenVASD Shadow E2E (advisory)` uses the same change
classification and triggers, read-only permissions, and no secrets. It is
deliberately absent from both required gate jobs.

The test-owned [`../compose.direct-openvasd.yaml`](../compose.direct-openvasd.yaml)
connects gateway to gvmd to the pinned emulator over direct OpenVASD HTTP. A
separate pinned `e2e-target` container is the requested scan host. Configuration
loading and runtime provenance reject equal backend/target names, containers,
or network addresses. While each happy-path scan is active, the Rust harness
also proves report/scan ID, requested target, result host, and emulator scenario
correlation.

All inventoried tests run with Cargo `--no-fail-fast`, so one failure cannot
hide later contract outcomes. The finalizer emits one comparison row for every
named contract and reads the completed required job's log through the
read-only Actions API for actual per-contract OSP outcomes. A pre-test OSP
failure is therefore `not-run`, not an inferred pass or failure. Any future
`osp-specific` entry remains an owned
`approved-exclusion` with its explicit inventory disposition.

The happy path connects gvmd straight to the emulator. During fault coverage,
gvmd temporarily selects a pinned test-only proxy port which injects one of the
upstream emulator's `http-400`, `http-500`, `malformed-body`,
`malformed-header`, or `timeout` scenario headers. Each case starts a task via
the public gateway and requires its 502/504 or terminal gvmd task mapping. A
trap restores the direct scanner and resets emulator state.

Every shadow execution uploads a 30-day raw artifact containing exact
provenance, Cargo/fault output, Compose state, runtime details, and logs bounded
to 2 MiB and 2,000 lines per service. An always-running evidence job resolves
exact job/artifact identity through GitHub's read-only API and records timings,
retry state, artifact completeness, comparisons, faults, and failure class. A
runtime-health marker separates application from assertion failures; named
steps distinguish setup, readiness, cleanup, and runner failures.

Local reproduction uses a run-scoped Compose project:

```bash
export GVM_GATEWAY_E2E_RUN_SCOPE="local-$(id -u)"
export GVM_GATEWAY_E2E_TARGET_HOST=e2e-target
export GVM_GATEWAY_E2E_SCANNER_BACKEND_IDENTITY=openvasd-backend
export GVM_GATEWAY_E2E_SCANNER_BACKEND_URL=http://127.0.0.1:8086
export GVM_GATEWAY_E2E_EXPECTED_SCANNER_SCENARIO=success
python3 scripts/fetch-openvasd-emulator-fixtures.py
./scripts/compose-direct-openvasd.sh up -d --build
./scripts/run-e2e-tests.sh --wait-only
./scripts/run-direct-openvasd-contracts.sh
./scripts/run-openvasd-fault-mappings.sh
./scripts/compose-direct-openvasd.sh down -v
```

## Real-OpenVASD compatibility

`Real OpenVASD Compatibility` runs weekly or manually, never on ordinary PRs.
Manual `release_ref` selects the exact release commit/tag, so the stable
`Real OpenVASD Direct-HTTP Compatibility (advisory)` result and 90-day artifact
can be cited as a release prerequisite. The override
[`../compose.real-openvasd.yaml`](../compose.real-openvasd.yaml) swaps only the
backend implementation and scanner/feed mounts; gvmd, gateway, direct-HTTP
happy path, and distinct target remain the same. Its provenance records exact
scanner/feed/image, gateway, gvmd, target, Compose, harness, and runner inputs.

Issue #695 temporarily makes only this manual/weekly workflow check out
`greenbone/openvas-scanner` commit
`d6e3cbe74ca6f1f4ff1a9d9fcafca59732a32b81`, verify the supported
`.docker/prod.Dockerfile`, and build it into a digest-pinned job-local registry.
The generated immutable repository-digest reference overrides the official
scanner default for both `configure-openvas` and `openvasd-backend`. The shared
preflight resolves that digest before startup, and runtime provenance rejects a
source label, image reference, image ID, Dockerfile hash, build-input, or
between-service mismatch. The artifact includes
`temporary-scanner-build.json`, whose closed fields record the upstream source
SHA, Dockerfile SHA-256, build arguments and platform, pinned registry image,
and resulting repository digest. After that registry manifest is verified, the
helper writes the evidence manifest, removes the local staging tag and image,
verifies both are absent, and prunes all Docker build cache. Cleanup output is
visible and any removal, verification, or prune failure stops the job. The
registry service and evidence manifest are retained, so Compose must pull the
exact recorded digest rather than reuse the locally built image while avoiding
holding the full scanner build cache beside the complete GVM runtime stack.
Ordinary pull-request CI, the direct emulator lane, and local real-lane runs
without the override continue to use their existing images; the official
scanner digest remains the Compose default.

This workaround must be removed after upstream
`greenbone/openvas-scanner` PR #2454 is merged **and** an official community
scanner image containing that fix is published. At that point, update the
official digest pin and remove the temporary upstream checkout, local registry,
build helper, manifest override, and temporary provenance assertions together.

Automating release policy or branch protection remains outside this phase.

## Shadow observation gate

Phase 3 requires at least 30 comparable finalized shadow runs spanning at
least 14 days. No elapsed shadow evidence is checked in by this implementation.
After runs exist, collect the auditable window with:

```bash
python3 scripts/collect-shadow-observations.py \
  --repository greenbone-hive/rust-gvm-api \
  --required-runs 30 \
  --required-days 14 \
  --output shadow-observations.json
```

Only executed jobs with a non-expired finalized evidence artifact and valid
direct-lane provenance qualify. The collector fingerprints the pinned
gvmd/scanner/feed images, Compose, OpenAPI, fixtures, runner, target identity,
and test-harness input; it counts only runs matching the newest qualifying
fingerprint. Collection starts from the repository's exact-name finalized
artifact inventory rather than scanning workflow history from before the
shadow lane existed. For each counted artifact it resolves the originating
workflow and exact run attempt, requires all four finalizer documents, and
cross-checks the run/job identity recorded in the archive. Missing, expired,
partial, malformed, cross-workflow, or provenance-incomparable artifacts do
not qualify.

The output is the machine-readable Phase 2 readiness record: `observedRuns`
and `spanDays` report the two independent observations, while `satisfied` is
true only when both reach their unchanged minimum. To inspect progress before
14 days have elapsed, add `--allow-incomplete`; the collector stops after the
finite finalized-artifact inventory and writes an explicitly unsatisfied
snapshot. It does not waive the gate.

## OSP baseline

[`baselines/osp-required.json`](baselines/osp-required.json) contains the 30
most recent eligible executions at collection time. Eligibility requires one
completed `REST Discovery Scan E2E` job with the named startup and test steps
and a `success`, `failure`, or `timed_out` conclusion. It excludes:

- docs-only or policy-skipped jobs;
- concurrency or manually cancelled jobs;
- workflow runs without the actual OSP job;
- successful jobs without required timestamps, or jobs without the named
  startup/test steps; and
- unsupported non-terminal conclusions.

Executed setup failures remain eligible even when the test step was skipped;
their unexecuted test duration is recorded as zero. Executed runner failures
also remain eligible and must be classified as `runner` with evidence; the
collector does not silently remove them. Promotion policy
may exclude a documented external runner outage only after its raw run/job URL,
classification, and owner are retained.

The checked-in window is 2026-11-09 03:06 UTC through 2026-11-10 18:28 UTC.
It contains 13 pull-request, 9 merge-group, 7 push, and 1 scheduled execution.
All 30 passed on their first attempt and all 30 retained the expected compose
diagnostic artifact. The measured baseline is:

| Metric | P50 | P95 | Minimum | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Compose startup | 529.5 s | 805 s | 330 s | 808 s |
| E2E tests | 129 s | 160 s | 117 s | 186 s |
| Whole job | 710 s | 978 s | 515 s | 997 s |

Pass rate and artifact completeness are `1.0`; failure, retry, and
unexplained-flake rates are `0.0`. These are measurements, not permanent
thresholds. Each run
entry retains its run/job URLs, head SHA, event, attempt, timings, conclusion,
and artifact names so the aggregate can be audited without reconstructing it.

## Reproduction and Phase 2 use

Validate all checked-in contracts and completeness locally:

```bash
make e2e-evidence-check
```

Regenerate the point-in-time baseline with authenticated GitHub CLI access:

```bash
python3 scripts/collect-e2e-baseline.py \
  --repository greenbone/rust-gvm-api \
  --required-runs 30 \
  --output tests/e2e/evidence/baselines/osp-required.json
make e2e-evidence-check
```

Phase 2 must populate the comparison format with the same named contracts,
record both lane outcomes without silently omitting backend-specific checks,
and compare runtime/reliability/artifact metrics with this baseline. The
emulator dependency is tracked in
[gvm-openapi-emulator #41](https://github.com/greenbone/gvm-openapi-emulator/issues/41).
Secret-bearing product or release credentials remain outside untrusted pull
request execution; the Phase 0 tooling uses only read-only GitHub metadata and
public workflow artifacts.

## Limitations

- The 30-run window is short because recent repository activity supplied the
  sample quickly; a longer observation period is still required for promotion.
- All selected runs passed, so the failure taxonomy is validated structurally
  but has no observed failure example in this snapshot.
- Older runs predate runtime provenance capture; their head SHA and workflow
  evidence are exact, while full resolved component/feed image identity starts
  with runs containing `provenance.json`.
- The current stack uses mutable community feed/scanner tags. The new manifest
  records their resolved image IDs but does not turn them into source revisions.
- The advisory profiles use digest pins; the existing required OSP stack is
  intentionally unchanged.
- The direct shadow 30-run/14-day window begins only after this workflow lands
  and remains outstanding at implementation handoff.
