# MCP Implementation Roadmap

> **Archived:** This July 2026 phase plan predates the completed REST and gvmd
> adapter refactors and contains stale issue and module sequencing. MCP is still
> unimplemented. Use [`gateway-architecture.md`](../gateway-architecture.md)
> for the peer-adapter boundary and create a current ADR/roadmap before starting
> MCP implementation.

Last updated: 2026-07-15 (rewritten against the shipped REST baseline; supersedes and
folds in the earlier MCP surface analysis that assumed a catalog-first core).

## 1. Goal

Ship `MCP` as a native public surface of the `rust-gvm-api` gateway, alongside the
already-shipped `REST` surface and ahead of the planned `gRPC` and `CLI` surfaces —
all backed by the same shared application core, the same session/auth model, the same
error taxonomy, and the same audit trail.

Target shape:

```text
Clients
  ├─ REST            (shipped)
  ├─ MCP             (this roadmap)
  ├─ gRPC            (planned, phase 8)
  └─ CLI             (planned, follows the same adapter rule)
         │
         ▼
Incoming adapters      gvm-gateway-rest │ gvm-gateway-mcp │ gvm-gateway-grpc │ ...
         │
         ▼
Application core       gvm-gateway-app   (GatewayService, SessionManager, JobRegistry, audit)
         │
         ▼
Domain                 gvm-gateway-domain (ports, session rules, error model)
         │
         ▼
Outgoing adapter       gvm-gateway-gvmd → rust-gvm → gvmd
```

The contract to preserve: **no surface implements business logic.** Adapters translate
transport syntax to `GatewayService` calls and translate `GatewayError` back. Auth,
session lifecycle, policy, audit, and gvmd execution stay below the adapters.

## 2. Current State (what already exists)

This roadmap is written against the code on `main`, not against a greenfield design:

- `gvm-gateway-app::GatewayService` is the shared execution core. It bundles typed
  resource ports (`SystemPort`, `TargetPort`, `TaskPort`, `AuthPort`, `ReportPort`, ...),
  the domain `SessionManager`, and the `JobRegistry` for asynchronous report export
  jobs.
- `gvm-gateway-rest` is a thin adapter: DTO mapping, auth-policy extraction, error
  mapping, rate limiting, OpenAPI. It contains no gvmd or business logic.
- `gvm-gateway` is the composition root: config loading, TLS modes
  (`disabled` / `terminated_by_proxy` / `native`), telemetry (tracing + OTLP),
  graceful shutdown with bounded drain.
- Session model: explicit bootstrap (`POST /api/v1/session`) returns an opaque bearer
  token; one gateway token binds to one authenticated gvmd connection; per-session
  serial execution with backpressure; expiry/revocation centralized in the domain.
- Test infrastructure: unit tests co-located per crate (`*_test.rs`), app-private mock
  ports in `gvm-gateway-app/src/test_support/`, workspace e2e harness in `tests/e2e`
  (REST flows against a real or mock backend), `tests/performance` smoke benchmarks.
- CI (`ci.yml`): fmt, clippy (`-D warnings`), test matrix (stable + MSRV 1.88.0),
  all-features test, rustdoc (`-D warnings`), user-docs package verification,
  cargo-deny, coverage (llvm-cov → Codecov), MSRV check, deb/arch packaging with
  smoke install, container build with smoke run. Plus `nightly-e2e.yml`,
  `weekly-performance.yml`, `security.yml`, and the PR-gated release flow
  (`release-prepare` → `release` label → `release-tag` → `release-publish`).

### 2.1 Deviation from the original analysis (recorded decision)

The earlier draft of this roadmap prescribed a *canonical operation catalog* with a
generic `execute(operation_id, request, session)` core. The implemented core instead
uses **typed port traits and typed service methods**. This roadmap keeps the typed
approach:

- typed ports already deliver the "one shared core" property the catalog was for
- a catalog rewrite now would be a high-regression-risk refactor of a shipped surface
  with no customer-visible benefit
- parity across surfaces is enforced with a lightweight **surface inventory + parity
  test** (phase 6) instead of catalog metadata

The catalog idea is retired, not deferred. If a future surface genuinely needs
runtime operation dispatch, that is a new ADR.

### 2.2 Consolidated MCP surface analysis

This is the single authoritative MCP planning document. The earlier separate MCP
surface-analysis note has been folded into this roadmap and retired.

The carried-forward architectural rule is intentionally small:

- MCP is a native incoming adapter, not a downstream REST/gRPC client.
- MCP shares the existing gateway session, policy, error, audit, and gvmd execution
  path with REST.
- Capability parity is required, but identical wire shape is not. REST can expose an
  HTTP route, MCP can expose a tool, and gRPC can later expose a streaming method if
  all three represent the same gateway capability.
- MCP v1 exposes tools. MCP resources, notifications, stdio, and richer streaming
  ergonomics are optional follow-up work only after tool parity exists.
- Tool invocations never call GMP directly; they call typed `GatewayService` methods
  through the same domain ports REST already uses.

Anti-over-engineering guardrails:

- no generic operation-catalog rewrite
- no new `gvm-api-core` extraction as an MCP prerequisite
- no separate MCP sidecar service that calls the REST API
- no hidden MCP credential vault or invisible session bootstrap
- no raw GMP/XML passthrough tool
- no code generation unless the phase-6 parity manifest becomes painful by hand
- no gRPC, CLI, resources, notifications, or multi-transport work blocking the first
  MCP vertical slice

## 3. Architectural Decisions

| # | Decision | Rationale |
| --- | --- | --- |
| D1 | MCP is a native adapter crate `gvm-gateway-mcp` inside this workspace | Reuses domain/app/gvmd seam directly; avoids proxy-on-proxy topologies; keeps session, policy, audit correct in one runtime |
| D2 | SDK: official Rust MCP SDK (`rmcp`) | Maintained by the MCP project, tool macros, stdio + HTTP transports; pin a compatible minor before scaffold so MSRV/licensing drift is deliberate |
| D3 | Transport v1: Streamable HTTP, mounted as one endpoint on the existing axum/tokio listener | Fits the shipped server bootstrap (TLS modes, graceful shutdown, peer-addr, tracing) without a parallel network stack; stdio can be added later for local use without touching tool logic |
| D4 | Auth: reuse the existing gateway session model unchanged; do not confuse it with MCP transport sessions | `sessions_create` tool → existing `SessionManager` token; `Mcp-Session-Id` tracks JSON-RPC transport lifecycle only; no credential storage inside the MCP adapter, no hidden bootstrap |
| D5 | MCP is **off by default** (`[mcp] enabled = false`) | Existing deployments see zero behavior change; enabling is an explicit operator action |
| D6 | No raw GMP passthrough tool | Passthrough would bypass the domain model, error taxonomy, and audit; capability gaps are fixed in the core first |
| D7 | Tool naming: canonical operation id `targets.list` ↔ MCP tool `targets_list` | Some MCP clients restrict tool names to `[a-zA-Z0-9_-]`; the underscore form is the wire name, the dotted form remains the documentation/parity id |
| D8 | Existing job-backed work goes through `JobRegistry`; scan task lifecycle follows the current task/report model | Report exports use the same job/polling capability on REST and MCP; `tasks_start` keeps returning the domain `reportId` and must not invent separate task state |

## 4. Testing and Regression Strategy (read before any phase)

This section is deliberately placed **before** the phase plan: every phase below
inherits these rules, and each phase lists its own regression risks explicitly.

### 4.1 Test layers (matching the existing pyramid)

| Layer | Location | What it must cover for MCP |
| --- | --- | --- |
| Unit (domain/app) | co-located `*_test.rs`, mocks in `gvm-gateway-app/src/test_support/` | Any shared-core change (e.g. audit `surface` field) tested here first, independent of MCP |
| Adapter unit | `gvm-gateway-mcp/src/*_test.rs` | Tool registration, schema generation, DTO mapping, error mapping (`GatewayError` → MCP error codes), token extraction |
| Adapter integration | `gvm-gateway-mcp` tests against `GatewayService` built from adapter-visible fixtures (`StaticGvmdAdapter`, local port fakes, or an explicitly exported test-support feature) | Full tool-call round trip in-process, no network |
| Composition | `gvm-gateway` tests | Config parsing (`[mcp]` section), enabled/disabled wiring, shutdown drain covers the MCP endpoint |
| E2E | `tests/e2e/tests/mcp_*.rs` (new, same harness style as `rest_*.rs`) | Real MCP client session against a running gateway backed by `gvm-mock-server`: bootstrap, tool listing, first-slice flows, negative contract |
| Parity | `tests/e2e` or a dedicated workspace test | REST↔MCP surface inventory comparison (phase 6) |
| Performance | `tests/performance` | MCP smoke benchmark alongside `rest_smoke_performance.rs` once the vertical slice ships |

### 4.2 Regression risk register

The MCP work touches a **shipped product surface's shared core**. These are the ways
it can break REST, ranked by likelihood, with the standing mitigation:

| Risk | Where it bites | Mitigation (mandatory) |
| --- | --- | --- |
| R1: shared-core edits (audit `surface` field, session helpers) change REST behavior | `gvm-gateway-app`, `gvm-gateway-domain` | Core changes land in their **own PRs before** any MCP adapter code, with unit tests asserting REST-visible behavior is unchanged (audit event shape is additive-only; existing REST tests must pass untouched) |
| R2: new workspace dependencies (`rmcp` and its tree) shift feature unification, MSRV, or licensing | whole workspace | `cargo check` at MSRV 1.88.0 and `cargo deny check` locally before the scaffold PR; pin `rmcp` minor version; deny.toml updated deliberately, never loosened silently |
| R3: `SessionManager` concurrency assumptions violated by MCP call patterns (parallel tool calls on one token) | domain | Reuse `touch_session_with_audit` and per-session serial execution as-is; add a unit test simulating concurrent MCP calls on one session asserting serialization and backpressure |
| R4: config schema changes break existing deployments' TOML files | `gvm-gateway` config | `[mcp]` section is additive and optional with `enabled = false` default; config tests include a fixture of the pre-MCP example file parsing unchanged |
| R5: composition-root/server changes (second endpoint, shutdown paths) destabilize REST serving | `gvm-gateway/src/server.rs` | Shutdown/drain tests extended, not replaced; nightly e2e REST suite is the canary — it must stay green with MCP disabled *and* enabled |
| R6: packaging/container drift (new config keys, docs package contents) | `packaging/`, `Containerfile`, docs-package CI job | Packaging smoke tests updated in the same PR that adds config keys; docs-package verification list extended explicitly |
| R7: audit/observability format changes break downstream log consumers | tracing/audit events | `surface` is a new field, existing fields keep names and semantics; documented in the ADR |

Rule of thumb enforced in review: **a PR that touches `gvm-gateway-domain` or
`gvm-gateway-app` must be green on the full existing REST test suite without editing
any existing assertion.** Editing an existing REST test in an MCP PR is a red flag
that the change is not additive.

### 4.3 Definition of done (every phase)

- `make ci` passes locally (fmt-check, clippy `-D warnings`, all-features tests,
  rustdoc `-D warnings`, cargo-deny) — this mirrors the `ci.yml` aggregator gate
- new public items documented (`missing_docs` is warn→deny via rustdoc flags)
- coverage does not drop on touched crates (Codecov diff)
- docs listed in §6 for that phase are updated **in the same PR**, not later
- a `journal/` entry records the phase completion (existing repo convention)

## 5. CI / Pipeline Integration

The pipeline principle: **MCP rides the existing workspace-wide jobs; only
deliberately-scoped additions are made.** No parallel pipeline.

What is automatic (because jobs run `--workspace`):

- fmt, clippy, test (stable + MSRV), all-features test, doc, deny, coverage, msrv —
  `gvm-gateway-mcp` is picked up the moment it joins `[workspace] members`

What must be explicitly extended, each in the phase that introduces the artifact:

| Pipeline piece | Change | Phase |
| --- | --- | --- |
| `ci.yml` → docs-package verification | assert `api/mcp/tools.json` (tool manifest) and MCP usage doc are in the archive | 5 |
| `ci.yml` → package/container smoke | package smoke greps the installed example config for a commented `[mcp]` block; container smoke keeps proving the binary starts and compose config is valid | 3 |
| `nightly-e2e.yml` | add `mcp_*` e2e suite next to the REST suite, gated on the same mock-backend bring-up | 5 |
| parity gate | workspace test failing when a parity-required operation is exposed on one surface only; runs in the normal `test` job (no new CI job needed) | 6 |
| `weekly-performance.yml` | MCP smoke benchmark | 7 |
| `security.yml` | nothing new — already scans workspace deps; verify `rmcp` tree is in scope after the scaffold lands | 2 |
| release flow (`release-prepare/tag/publish`) | no structural change; publish picks up the extended docs package and packages automatically | — |

## 6. Documentation Obligations

Docs are updated in the same PR as the code they describe. Concretely:

| Doc | Update | Phase |
| --- | --- | --- |
| `docs/adr/` (new) or design note | ADR-000X: MCP surface decisions D1–D8, catalog retirement (§2.1) | 0 |
| `README.md` | MCP moves from "planned" to "implemented" in the crate table and architecture diagram; quick-start snippet for enabling MCP | 3 (skeleton) / 5 (final) |
| `docs/gateway-architecture.md` | MCP adapter in the authoritative architecture description; session/auth flow diagram gains the MCP path | 3 |
| `spec/mcp-api/` (new, mirrors `spec/rest-api/`) | `openspec.md` (surface contract, naming rule D7, error mapping table), `tools.json` manifest per domain, `test-spec.md` | 1, then per domain |
| `docs/user/usage.md` + `docs/user/examples.md` | Enabling `[mcp]`, connecting an MCP client (Claude Code/Desktop example), session bootstrap walkthrough, one end-to-end scan example | 5 |
| `packaging/` source examples (`gvm-gateway.container.toml`, `gvm-gateway.toml`; packaged as `container-config.example.toml`, `package-config.example.toml` in the docs archive) | commented `[mcp]` section | 3 |
| `docs/mcp-implementation-roadmap.md` | single MCP planning source, including folded surface analysis, anti-over-engineering guardrails, and open-issue alignment | 0 |
| `RELEASING.md` | only if MCP adds release artifacts beyond the docs package (not expected) | — |

## 7. Phase Plan

Phases are sequential; each is independently shippable and leaves `main` releasable.
Every phase states **tests first** and **regression exposure** before deliverables,
per §4.

### Phase 0 — Decision Closure (ADR)

Purpose: freeze scope so adapter code never starts ahead of recorded decisions.

Tests first: none (docs only). Regression exposure: none.

Deliverables:

- ADR recording D1–D8, the catalog retirement (§2.1), the parity rule
  ("a capability shipped on one surface must ship on the other shipped surfaces in
  the same capability area, or carry a documented exception"), and the v1 domain
  scope: `system`, `sessions`, `targets`, `tasks`, `reports`
- retired separate MCP surface-analysis document removed and inbound links updated
  to this roadmap

Exit: ADR merged; this roadmap and the ADR agree.

### Phase 1 — MCP Surface Contract Spec

Purpose: write the wire contract before the wire exists (same discipline as
`spec/rest-api/` before REST handlers).

Tests first: `spec/mcp-api/test-spec.md` drafted alongside the contract — every
contract statement gets a planned test id, so later phases implement against a list.

Regression exposure: none (docs only).

Deliverables in `spec/mcp-api/`:

- `openspec.md`: transport (single streamable HTTP endpoint path, TLS modes inherited
  from gateway config, `Origin` validation for streamable HTTP), initialization/capability
  handshake expectations, auth contract (gateway token parameter vs `Authorization`
  header precedence, and explicit separation from `Mcp-Session-Id`), tool naming rule
  (D7), pagination/large-result conventions, long-running job conventions (D8)
- error mapping table: every `GatewayError` variant → MCP error code + message shape,
  asserted to be category-identical with the REST mapping in `gvm-gateway-rest/src/error.rs`
- `tools.json` seed manifest for the first slice: canonical ids `sessions.create`,
  `sessions.delete`, `system.get_version`; REST references `POST /api/v1/session`,
  `DELETE /api/v1/session`, and `GET /api/v1/version`; MCP wire tools
  `sessions_create`, `sessions_delete`, `system_get_version` with full input/output
  JSON schemas

Exit: spec reviewed; first-slice schemas frozen.

### Phase 2 — Shared-Core Preparation (highest regression sensitivity)

Purpose: make the *small* core changes MCP needs, isolated from adapter code, so
REST regressions are caught here and not inside a large MCP PR.

Tests first:

- unit tests in `gvm-gateway-app` asserting audit events carry `surface="rest"`
  today and that the field is additive (existing event fields unchanged)
- concurrency test: N parallel calls on one session token serialize and hit
  backpressure exactly as REST does (guards R3)

Regression exposure: **R1, R3, R7** — this is the only phase that edits
`gvm-gateway-app`/`gvm-gateway-domain`. Mitigation per §4.2: standalone PR, zero
edits to existing REST test assertions, full `make ci` green.

Deliverables:

- `surface` dimension in the audit path (`AUDIT_TARGET` events) with `rest` stamped
  by the REST adapter; mechanism generic so MCP/gRPC stamp their own
- any session-helper visibility changes MCP needs (e.g. exposing
  `touch_session_with_audit`-equivalent flow to a second adapter) — no semantic changes
- confirmation (test, not assumption) that `GatewayService: Send + Sync` sharing
  across two adapters is sound

Exit: REST behaves identically (nightly e2e green); core is adapter-count-agnostic.

### Phase 3 — Crate Scaffold + First Slice (`gvm-gateway-mcp`)

Purpose: stand up the adapter with the three bootstrap tools; prove the
adapter→core seam.

Tests first (written against the phase-1 spec before/with the implementation):

- tool registration test: served tool list matches `spec/mcp-api/tools.json` exactly
- per-tool round-trip tests against a `GatewayService` built from adapter-visible
  fixtures: happy path + every error-mapping row exercised at least once. If the app
  crate's current private mocks are needed, first extract them behind an explicit
  test-support feature instead of reaching across crate privacy.
- auth tests: missing token, expired token, invalidated token → correct MCP error
  category, audit event with `surface="mcp"` and the same reason codes REST emits
- MSRV + deny gate locally before the PR (guards R2)

Regression exposure: **R2** (new dependency tree), **R4** (config), **R5**
(composition root), **R6** (packaging/config examples).
Mitigation: `rmcp` pinned; `cargo deny check` and MSRV check in the same PR;
composition-root wiring lands behind `enabled = false` default (D5) so a released
binary with this code behaves identically unless opted in.

Deliverables:

- `crates/gvm-gateway-mcp`: lib structure mirroring `gvm-gateway-rest` conventions
  (`error.rs` mapping, `dto.rs`, per-domain modules, co-located `*_test.rs`,
  `#![deny(unsafe_code)]` / `#![warn(missing_docs)]` headers, SPDX headers)
- tools: `sessions_create`, `sessions_delete`, `system_get_version`
- streamable-HTTP service constructed from the shared `Arc<GatewayService>`
- `[mcp]` config section in `gvm-gateway` (enabled flag, endpoint path, allowed
  origins if different from REST policy), mounted on the existing gateway listener and
  wired through `server.rs` with graceful-shutdown drain covering MCP connections. A
  separate MCP port is a later ADR, not a phase-3 default.
- config fixture test: pre-MCP TOML parses unchanged (guards R4)
- `packaging/gvm-gateway.toml` and `packaging/gvm-gateway.container.toml` gain the
  commented `[mcp]` block; package/container smoke updated (guards R6)
- README + `gateway-architecture.md` updated to "MCP: first slice implemented"

Exit: with `enabled = true`, an MCP client can initialize, list three tools, create
a session, read the version, delete the session — against `gvm-mock-server`; with the
flag off, REST-facing runtime behavior is unchanged from the pre-MCP binary.

### Phase 4 — Vertical Slice: Real Scan Workflow

Purpose: prove the architecture on workflow-bearing capabilities, including scan
status polling and report retrieval. `JobRegistry` remains reserved for the existing
report-export job model until the report-export tools land.

Tests first:

- extend `spec/mcp-api/tools.json` + `test-spec.md` for the slice before coding
- adapter tests per tool (happy + error rows), reusing REST test scenarios as the
  behavioral oracle: same input conditions must yield the same error categories
- scan-lifecycle test: `tasks_start` returns the same `reportId` shape as REST, then
  task/report polling behaves identically to the REST discovery-scan flow. Do not
  introduce `JobRegistry` state for task start.

Regression exposure: low on REST (adapter-only crate churn). No `gvm-gateway-app`
edits expected; if a gap in a port surfaces, it goes through a phase-2-style
standalone core PR first.

Deliverables:

- tools: `targets_list`, `targets_create`, `tasks_list`, `tasks_get`,
  `tasks_create`, `tasks_start`, `tasks_stop`, `reports_list`, `reports_get`
- large-result convention implemented per spec (pagination parameters mirroring the
  REST query model; summary-plus-detail shape for reports where responses would
  exceed sane MCP message sizes)
Exit: one end-to-end discovery-scan workflow (create target → create task → start →
poll → fetch report) runs through MCP against the mock backend, mirroring
`tests/e2e/tests/rest_discovery_scan.rs`.

### Phase 5 — E2E, Docs Package, and User Documentation

Purpose: make MCP a supported, documented, nightly-verified surface.

Tests first: the e2e suite *is* the deliverable —

- `tests/e2e/tests/mcp_bootstrap.rs`, `mcp_auth.rs`, `mcp_discovery_scan.rs`,
  `mcp_negative_contract.rs`, built on the existing harness (`tests/e2e/src/harness`)
  with an MCP client module added
- nightly-e2e workflow runs REST and MCP suites; REST suite acts as the standing
  regression canary with MCP enabled (guards R5 permanently)

Regression exposure: CI/docs only; code frozen except fixes the e2e suite surfaces.

Deliverables:

- e2e suites above; `nightly-e2e.yml` extended
- docs package: `api/mcp/tools.json` + MCP usage doc included;
  `ci.yml` docs-package verification list extended
- `docs/user/usage.md` + `examples.md`: enabling MCP, connecting Claude Code /
  Claude Desktop as a client, scripted example mirroring `scan-target.sh`
- README final state for the MCP section

Exit: nightly green on both surfaces two consecutive runs; a new user can enable and
use MCP from the shipped docs package alone.

### Phase 6 — Parity Enforcement (drift prevention)

Purpose: turn parity from a review habit into a CI failure.

Tests first: this phase is a test.

Regression exposure: none at runtime; CI-only. Deliberately *after* the vertical
slice so the inventory format is derived from real, stable code rather than guessed.

Deliverables:

- machine-readable surface inventories: REST derives from the OpenAPI/router,
  MCP derives from the served tool list (which is already tested against
  `spec/mcp-api/tools.json`)
- parity map keyed by canonical operation id (`targets.list` ↔ REST route ↔ MCP tool)
  with an explicit, documented exception list (e.g. REST-only operational endpoints
  like health/readiness probes)
- workspace test: parity-required operation present on exactly the declared
  surfaces, else fail — runs inside the normal `test` job
- contribution rule documented: adding an endpoint or tool without updating the
  parity map fails CI, which forces the "rollout obligation" conversation in-PR

Exit: seeding a deliberate parity hole fails CI; removing it passes.

### Phase 7 — Domain Expansion + Performance

Purpose: widen MCP coverage to the remaining shipped REST domains and watch cost.

Tests first: per-domain spec + adapter tests (phase-4 template), parity map updated
first so CI *demands* each domain's tools.

Regression exposure: low; adapter-only, pattern established. Performance risk is the
new dimension: MCP JSON-RPC framing overhead on report-heavy operations.

Deliverables:

- domains: `alerts`, `schedules`, `credentials`, `port_lists`, `scan_configs`,
  `scanners`, `feeds`, `results`, `supporting_resources`, `identity`,
  `report_exports`, `jobs` — expanded domain-by-domain, each domain's REST parity
  entry flipped on in the same PR
- `tests/performance`: MCP smoke benchmark next to `rest_smoke_performance.rs`;
  `weekly-performance.yml` extended
- report/export ergonomics for MCP finalized: `reports_export`, `jobs_get`,
  `jobs_cancel`, and `jobs_download_result` mirror the existing REST job contract
  rather than returning megabyte tool results inline

Exit: parity map shows full coverage of shipped REST domains minus documented
exceptions; weekly performance job tracks both surfaces.

### Phase 8 — gRPC (and CLI) Follow the Same Rails

Purpose: keep the later surfaces honest; nothing here blocks MCP.

- `gvm-gateway-grpc` follows the phase 1→7 template: spec first
  (`spec/grpc-api/` already drafted), core untouched, adapter-only crate, parity map
  extended, e2e + nightly, off by default
- a CLI is either a fourth in-process adapter or a thin REST client — decided by ADR
  when scheduled; either way it may not bypass `GatewayService`
- streaming (gRPC) and any MCP resource/notification affordances are modeled as
  transport ergonomics over existing core capabilities, never as new core state

## 8. Cross-Cutting Requirements (day one, not post-MVP)

- observability: every MCP tool call traced and audited with
  `surface="mcp"`, same span/field conventions as REST (`info_span` + audit target)
- secret handling: credentials appear only in `sessions_create` input, are never
  logged (existing `log_safety` rules apply), never persisted by the adapter
- session hygiene: explicit create/delete tools; expiry and revocation behavior
  identical to REST because it *is* the same `SessionManager`; `Mcp-Session-Id` is
  never accepted as a gateway bearer token
- streamable-HTTP security: validate `Origin`, inherit or explicitly configure
  allowed origins, and keep localhost-oriented defaults when MCP is enabled for local
  agent clients
- backpressure: per-session serial execution and queue-saturation errors surface as
  a distinct, documented MCP error category
- versioning: `tools.json` schemas are versioned with the workspace; breaking a tool
  schema follows the same release discipline as breaking a REST DTO
- supply chain: `rmcp` tree covered by cargo-deny, `security.yml`, and SBOM output
  like every other dependency

## 9. Standing Risks

| Risk | Position |
| --- | --- |
| Surface drift | Phase 6 parity gate; exception list is documented, never implicit |
| Session leakage via MCP convenience | D4/D6: explicit bootstrap only; no adapter-held credentials; audit distinguishes surfaces |
| Raw passthrough pressure | D6: capability gaps are core work items, not passthrough justifications |
| Topology lock-in | MCP endpoint path is config-addressed; the phase-3 same-listener default is a deployment choice, not an architectural assumption |
| Long-running ergonomics | Report exports are modeled once in `JobRegistry`; scan task execution keeps the current task/report polling contract |
| Over-design | Catalog retired (§2.1); parity is a test, not a metadata platform; codegen only if the manifest test proves painful by hand |
| Shared-core regression into REST | §4.2 register + phase 2 isolation + nightly REST canary with MCP enabled |

## 10. Open Issue Alignment (2026-07-15)

Open GitHub issues were reviewed against this roadmap. There is no open issue that
already owns MCP implementation, so this roadmap is not duplicating an active MCP
tracking issue. The issues below are the ones most likely to overlap with or pull
against the roadmap if they are implemented without reconciliation.

| Issue | Relationship to this roadmap | Required handling |
| --- | --- | --- |
| [#27](https://github.com/greenbone-hive/rust-gvm-api/issues/27) `feat: Connection Pooling and Session Handling for gRPC and REST API` | Overlaps Phase 2 session/concurrency work, but still names historical `POST /api/v1/sessions` / `DELETE /api/v1/sessions/{token}` routes and assumes TLS-only gateway acceptance. Current REST is singular `POST/DELETE /api/v1/session`, and transport security is mode-based (`disabled`, `terminated_by_proxy`, `native`). | Treat as partially superseded before MCP Phase 2. Split or rewrite the remaining useful work (pool limits, backpressure, telemetry) without reintroducing plural session routes or a blanket TLS-only assumption. |
| [#18](https://github.com/greenbone-hive/rust-gvm-api/issues/18) `feat: Shared GMP connection pool + error types across REST and gRPC` | Proposes an older shared-core/pool shape that conflicts with this roadmap's typed `GatewayService`/port boundary and adapter-only MCP approach. | Mark superseded or rewrite around the current `gvm-gateway-app` domain/port model. Do not make a `gvm-api-core` extraction or pool rewrite an MCP prerequisite. |
| [#2](https://github.com/greenbone-hive/rust-gvm-api/issues/2), [#11](https://github.com/greenbone-hive/rust-gvm-api/issues/11)-[#17](https://github.com/greenbone-hive/rust-gvm-api/issues/17) gRPC program | Still useful as gRPC intent, but it predates the MCP-first sequencing and current architecture. Several items imply gRPC-specific services, auth, streaming, packaging, and SDK work that should now live behind Phase 8. | Keep deferred until Phase 8. Before implementing, reconcile each issue with `spec/grpc-api/`, the parity gate, current auth/session behavior, and the "adapter only, core untouched" rule. |
| [#203](https://github.com/greenbone-hive/rust-gvm-api/issues/203) `feat(reports): implement report export/download via rust-gvm` | Overlaps D8 and Phase 7 report ergonomics, but describes older export/download assumptions. The current gateway exposes asynchronous report export jobs through `JobRegistry`. | Update or close as superseded by the async export job contract. MCP must mirror `reports_export`, `jobs_get`, `jobs_cancel`, and `jobs_download_result`; it must not return large report bodies inline. |
| [#239](https://github.com/greenbone-hive/rust-gvm-api/issues/239) `refactor(gvmd): split monolithic gvmd_adapter.rs by port-family boundaries` | High merge-conflict risk for Phase 7 domain expansion and adapter tests, even though early MCP phases should only consume typed ports. | Prefer landing before broad MCP domain expansion, or freeze adapter module boundaries before Phase 7 begins. |
| [#250](https://github.com/greenbone-hive/rust-gvm-api/issues/250) `refactor(rest): split and refine supporting_resources.rs` | Overlaps Phase 6/7 inventory and parity work for supporting resources. | Land before Phase 6 if possible. Otherwise make REST inventory derive from OpenAPI/router output rather than fragile module paths. |
| [#341](https://github.com/greenbone-hive/rust-gvm-api/issues/341)-[#344](https://github.com/greenbone-hive/rust-gvm-api/issues/344) new REST/resource families | These add or reshape REST domains (agent management, assets/configs, OCI/web targets, report subresources, operating systems). They can expand the parity scope after this roadmap's first MCP slice. | Any new REST route merged before Phase 6 needs a parity-map entry in the same PR or an explicit documented exception. Phase 4 remains classic targets only; new target/resource families belong in Phase 7 unless deliberately pulled forward. |
| [#308](https://github.com/greenbone-hive/rust-gvm-api/issues/308) `fix(gvmd): harden client-side pagination fallback against large page overflow` | Not MCP-specific, but it affects every paginated MCP tool once list operations are exposed. | Fix before Phase 4 list tools or before any parity-required paginated MCP domain lands. |
| [#297](https://github.com/greenbone-hive/rust-gvm-api/issues/297) CI action hardening | Low runtime conflict; relevant because this roadmap adds `rmcp` supply-chain and security workflow coverage. | Coordinate dependency/security workflow changes, but do not block MCP implementation on it. |
| [#161](https://github.com/greenbone-hive/rust-gvm-api/issues/161) OCI distroless/signing | Intersects Phase 3 packaged config examples and Phase 5 container smoke tests. | If it lands first, MCP package/container smoke must use the distroless, non-root, signed-image contract. |

Rule for all future open issues: if a REST endpoint or gateway capability lands before
Phase 6, the same PR must either add it to the parity map or document why the
capability is intentionally REST-only.

## 11. Immediate Next Steps

1. Triage open-issue drift: update, split, or mark superseded issues #27, #18, #203, and the gRPC issue set so they cannot steer MCP back to older route/core assumptions
2. Phase 0: write the ADR (D1–D8 + catalog retirement) and keep this roadmap as the single MCP planning document
3. Phase 1: author `spec/mcp-api/` for the first slice (contract + error table + `tools.json`)
4. Phase 2: land the shared-core preparation PR (audit `surface` field + concurrency test) and watch the REST suite
5. Phase 3: scaffold `gvm-gateway-mcp` with `rmcp`, ship the three-tool slice behind `enabled = false`, and update packaged config examples
6. Phase 5's e2e harness work can be prepared in parallel with phase 4 by one contributor without contention

The sequencing rule that protects the shipped product: **spec before adapter, core
changes in isolation before adapter changes, parity as CI before expansion.**
