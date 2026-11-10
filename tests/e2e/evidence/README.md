# E2E contract and baseline evidence

This directory is the machine-readable Phase 0 record for migrating the
required community E2E scanner boundary from OSP to direct OpenVASD HTTP. It
does not change the current required OSP job or authorize promotion.

## Inventory and ownership

[`contract-inventory.json`](contract-inventory.json) covers all 39 Rust tests
in the `gvm-gateway-e2e` package:

- 11 local helper/fixture tests;
- 28 ignored compose-backed live tests;
- 31 scanner-independent tests; and
- 8 contracts that currently use the OSP scanner path but are expected to
  migrate to the direct-OpenVASD lane.

There is no intentionally OSP-specific public contract in the current suite.
Every test that declares the `osp-scanner-path` dependency therefore has an
explicit `migrate` disposition. The validator compares Rust test attributes
with inventory IDs, source paths, ignored state, and kind. A new or removed
test makes validation fail until the inventory changes with it.

The inventory also contains closed owner registries for all 47 named contracts
and all 7 named dependencies. Validation rejects an unowned reference and a
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
