# Formal BDD Pilot

Issue [#458](https://github.com/greenbone-hive/rust-gvm-api/issues/458)
adds a deliberately small executable-specification layer for three canonical
REST journeys:

- unauthenticated protected access returns the documented problem response;
- a gateway session is created, used, deleted, and then rejected;
- a discovery target and task produce a linked report and downloadable JSON
  report export.

The scenarios live in
[`tests/e2e/features/canonical_rest.feature`](../tests/e2e/features/canonical_rest.feature).
Their step adapter is an ignored integration test in the existing
`gvm-gateway-e2e` crate. It calls `E2eHarness` for HTTP requests, readiness,
resource selection, polling, typed response handling, and cleanup; it does not
create another transport client or compose environment.

## Running the pilot

Start the normal compose-backed environment, then use the same runner as every
other E2E test:

```bash
./scripts/compose-dev.sh up -d --build
./scripts/run-e2e-tests.sh
./scripts/compose-dev.sh down -v
```

The repository runner sets `RUST_TEST_THREADS=1`, and the Cucumber runner also
limits itself to one scenario. This preserves serial ownership of mutable gvmd
resources. Cucumber output names the feature, scenario, and failed step, while
the reused harness includes HTTP status/body or backend polling context in the
failure. Compose logs remain captured by the existing E2E workflow.

To iterate on only the pilot after the compose stack is ready:

```bash
cargo test -p gvm-gateway-e2e --test bdd \
  canonical_rest_behaviors_are_executable_specs -- \
  --ignored --nocapture --test-threads=1
```

Add new feature text only for stable public behavior. Prefer existing harness
methods, and extend the harness once when a genuinely shared lifecycle helper
is missing. Do not put handler, adapter, or GMP XML details in feature files.

## Pilot measurements and decision

The pilot adds one feature file and one narrow step adapter. It adds no second
HTTP client, compose stack, readiness loop, resource polling loop, or export
implementation. It intentionally overlaps three existing direct Rust E2E
journeys so diagnostic quality can be compared; those primary tests remain in
place during the evaluation.

The first isolated live run on the project's validation host, against the
compose-backed gvmd stack with a warm Rust build, completed all three scenarios
and 14 steps in **53.76 seconds**; the complete `cargo test` command took
**60.16 seconds** wall-clock time. This is the pilot's measured additive runtime
delta on that host. The first exact-head GitHub E2E run completed the same
three scenarios and 14 steps in **30.83 seconds**. CI can vary with scanner and
feed readiness, so the test prints `BDD pilot runtime` on every run for later
comparison.

The duplication delta is one 23-line feature file and a 325-line step adapter.
The adapter adds scenario state, domain-language bindings, assertions, and
best-effort teardown, but duplicates **zero** HTTP clients, compose stacks,
readiness loops, resource-selection helpers, scan polling loops, or report
export implementations. The three journeys deliberately overlap existing
direct Rust E2E coverage; those tests remain the primary diagnostic layer.

**Decision: retain only the three-scenario pilot.** Do not convert the endpoint
matrix or add more feature files until non-Rust reviewers confirm that the
feature text improves reviewability enough to justify the dependency and step
maintenance. If that evidence does not materialize, remove the pilot rather
than establishing a parallel acceptance-test architecture.
