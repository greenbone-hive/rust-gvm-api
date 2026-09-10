# OpenSpec: GVM REST API

## 1. Overview

The REST surface of the `gvm-gateway`, exposing Greenbone Vulnerability Management (GVM) operations over HTTP/JSON. Built on [axum](https://github.com/tokio-rs/axum) and [rust-gvm](https://github.com/greenbone-hive/rust-gvm), providing a standards-compliant alternative to GMP's raw XML protocol.

### Goals

- **Standards-first**: OpenAPI 3.1 specification, JSON:API-inspired resource design, proper HTTP semantics
- **Security-first**: Session-token authentication, deny-by-default CORS, security headers, rate limiting, audit logging
- **Observable**: Structured logging and OpenTelemetry (OTel) traces via OTLP
- **Performant**: Async throughout, connection pooling to gvmd, streaming for large responses

### Non-Goals

- Full GMP protocol parity in v0.1 (start with the most-used operations)
- Built-in user management (delegates to gvmd's user/role system via GMP)
- Web UI (API only — UIs are separate consumers)

### rust-gvm typed response policy

For GMP-backed endpoints, adapter/application conversion must use the structured response models provided by `rust-gvm`.

**Hard requirement:** `rust-gvm-api` must not parse or process raw GMP XML responses directly.
All GMP XML processing and protocol-shape handling belong in `rust-gvm`.

Current mandatory coverage (from `rust-gvm` PR #68):
- tasks (`GetTasksResponse`, `CreateTaskResponse`, `StartTaskResponse` + action aliases)
- reports (`GetReportsResponse`, `DeleteReportResponse`)
- results (`GetResultsResponse`)

When a structured model exists upstream, use it as the source for API mapping.


## 2. Architecture

The REST adapter follows the shared gateway architecture defined in [docs/gateway-architecture.md](../../docs/gateway-architecture.md).
For REST specifically, that means the crate layering from issue `#26` plus the shared session/connection execution model from issue `#27`.

Current responsibilities inside the architecture:

- `gvm-gateway-rest` is the REST incoming adapter.
- `gvm-gateway-app` is the shared application/use-case layer.
- `gvm-gateway-domain` owns session rules, invariants, and port traits.
- `gvm-gateway-gvmd` is the gvmd outgoing adapter built on `rust-gvm`.
- `gvm-gateway` is the composition root and runtime bootstrap.

```text
HTTP clients
    │
    ▼
gvm-gateway-rest
    │
    ▼
gvm-gateway-app
    │
    ▼
gvm-gateway-domain
    │
    ▼
gvm-gateway-gvmd
    │
    ▼
rust-gvm -> gvmd
```

### Crate Structure

```text
crates/
├── gvm-gateway-domain/   # Session model, lifecycle rules, port traits
├── gvm-gateway-app/      # Shared use cases and orchestration
├── gvm-gateway-rest/     # REST router, handlers, middleware, OpenAPI exposure
├── gvm-gateway-gvmd/     # gvmd adapter over rust-gvm
└── gvm-gateway/          # Composition root, config, listeners, shutdown, tracing
```

## 3. API Design

### Base URL

```
/api/v1
```

### Versioning Strategy

URL-based versioning (`/api/v1/`, `/api/v2/`). Major breaking changes increment version. Minor additions are non-breaking.

### REST Design Constraints

The public REST surface intentionally targets **Richardson Maturity Model Level 2**.
That is a design constraint for new endpoints and spec reviews, not just an after-the-fact assessment.

What Level 2 means in this repo:

- Model public resources as collections and items by default.
- Use HTTP methods for their normal semantics:
  - `GET` is safe and read-only.
  - `POST` creates resources or performs an explicitly documented state transition.
  - `PUT` is idempotent replacement/update.
  - `DELETE` removes or closes a resource and returns `204 No Content` when no body is needed.
- Use meaningful success and failure status codes rather than tunneling everything through `200`.
- Use RFC 9457 `application/problem+json` responses for failures.
- When a canonical URI exists for a created resource, return `201 Created` with a `Location` header that points at that resource.

This repo does **not** target Richardson Maturity Model Level 3 for the public REST surface.
Hypermedia controls are optional and not required for API completeness or review acceptance.

### Proxy Responsibility Boundary

This proxy translates between REST/gRPC and GMP while providing an idiomatic interface for clients.

That translation boundary is intentionally limited:

- The proxy may normalize transport, authentication, status codes, problem shapes, pagination/query handling, and resource modeling.
- The proxy must **not** reimplement GMP/GVMD commands that are unavailable or unsupported on the connected backend.
- The proxy must **not** compensate for, extend, or fill functional gaps in GMP/GVMD by fabricating equivalent higher-level behavior locally.

If a capability exists in the abstract API surface but the connected gvmd backend does not implement the required GMP command or semantic support, the proxy should return an explicit capability/implementation failure instead of emulating the missing backend behavior.

Missing functionality should be addressed in GMP/GVMD or in reusable `rust-gvm` capability support, not recreated ad hoc inside the proxy layer.

### Action-Style Endpoint Rule

Collection/item resource modeling is the default. Action-style routes are allowed only when the operation is a state transition or controller-style command with no stable child resource to expose cleanly.

Accepted action-style exceptions:

- `POST /api/v1/tasks/{id}/start`
- `POST /api/v1/tasks/{id}/stop`
- `POST /api/v1/tasks/{id}/resume`

Rules for these exceptions:

- They must be documented explicitly in the REST spec instead of appearing as ad hoc RPC drift.
- They must stay on `POST`.
- They must use status codes that reflect the transition outcome (`200`, `202`, `404`, `409`, `504`, etc.).
- If a future action can be modeled more clearly as a real resource, that design should be preferred during review.

### Resource Endpoints

#### Targets

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/targets` | List targets (paginated, filterable) |
| `POST` | `/api/v1/targets` | Create a target (`201 Created` + `Location`) |
| `GET` | `/api/v1/targets/{id}` | Get target by ID |
| `PUT` | `/api/v1/targets/{id}` | Update target |
| `DELETE` | `/api/v1/targets/{id}` | Delete target |

#### Tasks

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/tasks` | List tasks |
| `POST` | `/api/v1/tasks` | Create task (`201 Created` + `Location`) |
| `GET` | `/api/v1/tasks/{id}` | Get task |
| `PUT` | `/api/v1/tasks/{id}` | Update task |
| `DELETE` | `/api/v1/tasks/{id}` | Delete task |
| `POST` | `/api/v1/tasks/{id}/start` | Start task |
| `POST` | `/api/v1/tasks/{id}/stop` | Stop task |
| `POST` | `/api/v1/tasks/{id}/resume` | Resume task |

#### Reports

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/reports` | List reports |
| `GET` | `/api/v1/reports/{id}` | Get report with an embedded result page |
| `POST` | `/api/v1/reports/{id}/exports` | Start an asynchronous report export job (`202 Accepted` + `Location`) |
| `GET` | `/api/v1/reports/{id}/results` | Get report results (paginated) |
| `GET` | `/api/v1/reports/{id}/vulnerabilities` | Get report vulnerability findings (paginated) |
| `GET` | `/api/v1/reports/{id}/tls-certificates` | Get TLS certificates observed in a report (paginated) |
| `GET` | `/api/v1/reports/{id}/errors` | Get report error findings (paginated) |
| `GET` | `/api/v1/reports/{id}/closed-cves` | Get closed CVE findings for a report (paginated) |
| `DELETE` | `/api/v1/reports/{id}` | Delete report |

Report export is intentionally modeled as a job because gvmd may need to
materialize the full report and run report-format generation scripts before an
artifact exists. `POST /api/v1/reports/{id}/exports` returns `202 Accepted` with
`Location: /api/v1/jobs/{jobId}`. Clients poll `GET /api/v1/jobs/{jobId}` and
download completed artifacts from `GET /api/v1/jobs/{jobId}/result`.
Export requests either reference a gvmd report format with `reportFormatId` or
select the API JSON export with `format: "json"`.

Report reads and result subresources use `page` and `perPage`.

#### Jobs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/jobs/{id}` | Get asynchronous job status |
| `DELETE` | `/api/v1/jobs/{id}` | Request job cancellation |
| `GET` | `/api/v1/jobs/{id}/result` | Download a completed job artifact |

#### Results

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/results` | List results (paginated, filterable) |
| `GET` | `/api/v1/results/{id}` | Get individual result |

#### Scan Configs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/scan-configs` | List scan configurations |
| `POST` | `/api/v1/scan-configs` | Create scan config (`201 Created` + `Location`) |
| `GET` | `/api/v1/scan-configs/{id}` | Get scan config |
| `PUT` | `/api/v1/scan-configs/{id}` | Update scan config |
| `DELETE` | `/api/v1/scan-configs/{id}` | Delete scan config |

#### Scanners

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/scanners` | List scanners |
| `GET` | `/api/v1/scanners/{id}` | Get scanner |

#### Alerts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/alerts` | List alerts |
| `POST` | `/api/v1/alerts` | Create alert |
| `GET` | `/api/v1/alerts/{id}` | Get alert |
| `PUT` | `/api/v1/alerts/{id}` | Update alert |
| `DELETE` | `/api/v1/alerts/{id}` | Delete alert |

#### Schedules

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/schedules` | List schedules |
| `POST` | `/api/v1/schedules` | Create schedule |
| `GET` | `/api/v1/schedules/{id}` | Get schedule |
| `PUT` | `/api/v1/schedules/{id}` | Update schedule |
| `DELETE` | `/api/v1/schedules/{id}` | Delete schedule |

#### Credentials

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/credential-stores` | List available credential stores |
| `GET` | `/api/v1/credential-stores/{id}` | Get a credential store without exposing preference values |
| `PUT` | `/api/v1/credential-stores/{id}` | Update credential-store connection settings and write-only preferences |
| `POST` | `/api/v1/credential-stores/{id}/actions/verify` | Verify the credential-store connection |
| `GET` | `/api/v1/credentials` | List credentials |
| `POST` | `/api/v1/credentials` | Create credential |
| `GET` | `/api/v1/credentials/{id}` | Get credential |
| `PUT` | `/api/v1/credentials/{id}` | Update credential |
| `DELETE` | `/api/v1/credentials/{id}` | Delete credential |

#### Port Lists

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/port-lists` | List port lists |
| `POST` | `/api/v1/port-lists` | Create port list |
| `GET` | `/api/v1/port-lists/{id}` | Get port list |
| `PUT` | `/api/v1/port-lists/{id}` | Update port list |
| `DELETE` | `/api/v1/port-lists/{id}` | Delete port list |

#### Identity & Access Control

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/users` | List users |
| `POST` | `/api/v1/users` | Create user |
| `GET` | `/api/v1/users/{id}` | Get user |
| `PUT` | `/api/v1/users/{id}` | Update user |
| `DELETE` | `/api/v1/users/{id}` | Delete user |
| `GET` | `/api/v1/groups` | List groups |
| `POST` | `/api/v1/groups` | Create group |
| `GET` | `/api/v1/groups/{id}` | Get group |
| `PUT` | `/api/v1/groups/{id}` | Update group |
| `DELETE` | `/api/v1/groups/{id}` | Delete group |
| `GET` | `/api/v1/roles` | List roles |
| `POST` | `/api/v1/roles` | Create role |
| `GET` | `/api/v1/roles/{id}` | Get role |
| `PUT` | `/api/v1/roles/{id}` | Update role |
| `DELETE` | `/api/v1/roles/{id}` | Delete role |
| `GET` | `/api/v1/permissions` | List permission grants |
| `POST` | `/api/v1/permissions` | Create permission grant |
| `GET` | `/api/v1/permissions/{id}` | Get permission grant |
| `PUT` | `/api/v1/permissions/{id}` | Update permission grant |
| `DELETE` | `/api/v1/permissions/{id}` | Delete permission grant |
| `GET` | `/api/v1/user-settings` | List current-user settings |
| `GET` | `/api/v1/user-settings/{id}` | Get one current-user setting |
| `PUT` | `/api/v1/user-settings/{id}` | Update one current-user setting |

#### Sessions & Auth

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/session` | Authenticate with HTTP Basic credentials and create a session (`201 Created` + `Location`) |
| `GET` | `/api/v1/session` | Inspect current session state |
| `DELETE` | `/api/v1/session` | Close and destroy a session |

Protected routes accept either an existing Bearer session token or request-scoped HTTP Basic credentials. `POST /api/v1/session` remains the persistent-session creation path.

#### Feeds

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/feeds` | List feed status |

#### System

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe (checks gvmd connectivity) |
| `GET` | `/api/v1/version` | GMP protocol version reported by the proxied gvmd; `apiVersion` is the REST API contract version, not the proxy binary version |
| `GET` | `/api/v1/timezones` | Authenticated backend-sourced timezone catalog from gvmd; returns `501` on backends that do not support `get_timezones` |
| `GET` | `/api/v1/openapi.json` | OpenAPI 3.1 spec |

The gateway also serves a browser documentation UI backed by
`/api/v1/openapi.json`. That operational UI is intentionally outside the API
contract.

### Request/Response Conventions

#### Pagination

```http
GET /api/v1/targets?page=1&perPage=25&sort=name&order=asc
```

Response includes pagination metadata:

```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "perPage": 25,
    "total": 142,
    "totalPages": 6
  }
}
```

`perPage` / `totalPages` are the canonical public JSON field names.
For request compatibility, the gateway may continue to accept legacy snake_case query aliases such as `per_page`, but published examples and generated SDKs should use camelCase.
The maximum published `perPage` value is 1000. Servers may reject or clamp larger
values.

#### Filtering

GMP filter strings exposed as query parameters:

```http
GET /api/v1/results?severity_min=7.0&host=192.168.1.0/24&task_id=<uuid>
```

#### Error Responses

RFC 9457 Problem Details:

```json
{
  "type": "https://gvm-gateway.greenbone.net/errors/not-found",
  "code": "not_found",
  "title": "Not Found",
  "status": 404,
  "detail": "Target with ID '550e8400-e29b-41d4-a716-446655440000' not found.",
  "instance": "/api/v1/targets/550e8400-e29b-41d4-a716-446655440000"
}
```

#### Distributed tracing

The API accepts W3C Trace Context (`traceparent`, `tracestate`, optional `baggage`) for OpenTelemetry correlation. REST responses return `traceparent` and `tracestate` for correlation, but do not echo `baggage`. The gvmd backend transport is GMP over a Unix socket, so trace headers are not forwarded downstream; internal correlation is represented by nested request/app/gvmd spans.

#### Create semantics

When a create operation returns a canonical resource identifier, the response must include:

- `201 Created`
- a response body containing the created identifier or resource representation
- a `Location` header pointing at the canonical resource URI

Current required coverage:

- `POST /api/v1/session` → `Location: /api/v1/session`
- `POST /api/v1/targets` → `Location: /api/v1/targets/{id}`
- `POST /api/v1/tasks` → `Location: /api/v1/tasks/{id}`
- `POST /api/v1/scan-configs` → `Location: /api/v1/scan-configs/{id}`

### Authentication & Authorization

1. **Session token flow** — Persistent auth model
   - `POST /api/v1/session` with Basic credentials
   - API returns an opaque session token
   - Subsequent requests use `Authorization: Bearer <sessionToken>`

2. **Request-scoped Basic auth** — Single-call auth model
   - Protected resource routes may use `Authorization: Basic <base64(username:password)>`
   - The gateway authenticates those credentials, creates a backend execution context for exactly one request, then tears it down before returning
   - Bearer authentication takes precedence whenever the `Authorization` scheme is `Bearer`; malformed Basic credentials fail with `401 Unauthorized`

3. **Session lifecycle controls**
   - `GET /api/v1/session` to inspect session state
   - `DELETE /api/v1/session` for explicit teardown
   - Session creation and use flow through the shared `SessionManager` / gvmd connection-store model.
   - One active session token maps to one authenticated backend execution context.
   - Requests that reuse the same session token must serialize against that backend context; queue saturation/timeouts are surfaced as backpressure errors rather than hidden retries.

4. **Authorization**
   - Authorization behavior follows gvmd user permissions
   - API adapters map domain permission errors to protocol-specific status codes

### Rate Limiting

Fixed-window rate limiting per global API surface and authenticated subject, aligned with the session model in #27:
- Defaults are conservative and configurable (`rate_limit_*` config keys)
- Subject keys are derived from Bearer tokens or request-scoped Basic credentials without logging raw secrets
- Session-creation and unauthenticated source keys use the direct TCP peer by default, or the first `X-Forwarded-For` client IP only when the direct peer matches an explicit `trusted_proxy_cidrs` entry
- `429 Too Many Requests` includes a `Retry-After` header
- Capacity/backpressure composes with global/per-user session limits and protects session creation from unauthenticated pressure

## 4. Configuration

```toml
# gvm-gateway.toml

bind = "0.0.0.0:8080"
transport_security_mode = "terminated_by_proxy" # "disabled" | "terminated_by_proxy" | "native"
# tls_certificate_path = "/etc/gvm-gateway/tls/cert.pem"
# tls_private_key_path = "/etc/gvm-gateway/tls/key.pem"
gvmd_endpoint = "unix:///run/gvmd/gvmd.sock"
shutdown_drain_timeout_secs = 30

cors_allowed_origins = ["https://ui.example"]
rate_limit_window_secs = 60
rate_limit_global_per_window = 1000
rate_limit_subject_per_window = 500
trusted_proxy_cidrs = ["127.0.0.1/32", "::1/128"]

otlp_endpoint = "http://localhost:4317"
local_log_output = "stdout" # "stdout" | "journald"
telemetry_service_name = "gvm-gateway"
telemetry_service_namespace = "greenbone"
telemetry_deployment_environment = "staging"
telemetry_service_instance_id = "gateway-01"
```

CLI flags override config file values; environment variables override both.

Transport-security notes:
- `disabled` means intentional plain HTTP.
- `terminated_by_proxy` means plain HTTP behind a trusted TLS-terminating proxy and does not require local TLS files.
- `native` means the gateway itself serves HTTPS and must fail startup unless both the certificate and private-key files are configured and loadable.
- Proxy mode does not implicitly enable trust for forwarded headers.
- Forwarded client IPs are trusted only when the direct TCP peer matches `trusted_proxy_cidrs`; otherwise `X-Forwarded-For` is ignored for rate-limit source attribution.

Logging notes:
- `local_log_output = "stdout"` preserves the default local formatter path.
- `local_log_output = "journald"` targets `systemd-journald` directly for systemd deployments and must fail startup clearly when journald is unavailable.

This explicit mode contract supersedes the earlier TLS-only ingress assumption from issue `#27` while preserving its shared session/connection model.

## 5. Implementation Phases (REST-first, aligned with #26 and #27)

This plan is aligned with:

- General architecture proposal: https://github.com/greenbone-hive/rust-gvm-api/issues/26
- Connection pooling + session handling proposal: https://github.com/greenbone-hive/rust-gvm-api/issues/27

Scope of this plan is **REST API only** (implementation of the proposed OpenAPI spec under `spec/rest-api/`).
**gRPC is explicitly deferred to a later iteration.**

### Delivery approach: acceptance-test first (mandatory)

For every use case and endpoint, development follows this loop:

1. Write or extend an **acceptance test** for the behavior.
2. Run the test and confirm it **fails** (red) for the expected reason.
3. Implement the minimal code to satisfy the behavior.
4. Re-run and confirm the acceptance test is **green**.
5. Refactor while keeping the acceptance test green.

No implementation work should start without an acceptance test that defines the expected behavior.

### Phase 1: Architecture skeleton (hexagonal baseline)

- Create crate boundaries per #26:
  - `gvm-gateway-domain` (session model, domain services, port traits)
  - `gvm-gateway-app` (use cases: session lifecycle + GMP execution)
  - `gvm-gateway-rest` (REST incoming adapter)
  - `gvm-gateway-gvmd` (outgoing adapter)
  - `gvm-gateway` (composition root)
- Keep domain free from framework/I/O dependencies.
- Wire REST adapter to application use cases only.
- Keep gRPC crate/work out of scope for this iteration.

### Phase 2: Session and connection core (from #27)

- Implement domain `SessionManager` with `create/get/touch/expire/remove`.
- Enforce atomic limits:
  - global max sessions
  - per-user max sessions
- Implement gvmd adapter connection store keyed by session token.
- Add one in-flight GMP command serialization per session (single-flight queue).
- Implement backpressure behavior for queue saturation/timeouts.
- Implement idle-expiry cleanup and explicit teardown.

### Phase 3: REST adapter foundation (spec-first)

- Generate REST server stubs/types from the OpenAPI 3.1 spec in `spec/rest-api/`.
- Implement session endpoints first (acceptance-test first for each endpoint):
  - `POST /session`
  - `GET /session`
  - `DELETE /session`
- Implement bearer-token extraction and session resolution middleware.
- Map domain errors to HTTP status/problem responses consistently.

### Phase 4: Resource endpoint implementation (proposed spec)

Implement REST resources against the shared application execution path (`execute(token, command)`):

- Targets
- Tasks (+ start/stop/resume) — use `rust-gvm` structured task responses
- Reports (+ report results) — use `rust-gvm` structured report responses
- Results — use `rust-gvm` structured result responses
- Scan configs
- Scanners
- Alerts
- Schedules
- Credentials
- Port lists
- Feeds
- Version/System

For each resource (acceptance-test first):
- preserve API contract from OpenAPI spec
- ensure token-scoped execution and per-session GMP serialization
- keep adapter thin (translation only, no business logic, no raw GMP XML handling)

### Phase 5: REST hardening and release readiness

- Add structured observability for REST flow (logs, OTel tracing).
- Implement OTel tracer setup with OTLP exporter and explicit service/resource attributes.
- Ensure W3C Trace Context propagation across incoming HTTP, application use cases, and gvmd adapter calls.
- Add resilience checks for session expiry, backend disconnects, and queue backpressure.
- Implement graceful shutdown and connection draining for the REST gateway:
  - handle `SIGTERM`/shutdown signals explicitly
  - stop accepting new application requests once drain mode begins
  - keep `/health` live but degrade `/ready` to `503 notReady` while draining
  - allow in-flight requests to complete up to a bounded drain timeout
  - after the timeout, return from the serve loop so the process can exit even if blocked handlers remain
- Emit structured shutdown telemetry for state transitions, rejected requests, and drain-timeout exits.
- Build OCI image artifacts for the REST gateway and verify they run under both Podman and Docker.
- Document the local container/dev workflow in terms of Compose-compatible stacks rather than Docker-only assumptions.
- Add/maintain integration and E2E tests focused on REST behavior (written first, fail-first):
  - session lifecycle
  - concurrent calls on same token serialize correctly
  - limit enforcement and teardown behavior
  - graceful shutdown drain completion and bounded-timeout behavior
- Prepare first REST-focused release cut.

### Deferred to next iteration

- gRPC adapter implementation and `.proto` contract integration.
- Cross-adapter parity tests (REST vs gRPC).

## 6. Error Handling

### GMP → HTTP Status Mapping

| GMP Condition | HTTP Status |
|---------------|-------------|
| Success | `200 OK` / `201 Created` |
| Resource not found | `404 Not Found` |
| Authentication failed | `401 Unauthorized` |
| Permission denied | `403 Forbidden` |
| Invalid request | `400 Bad Request` |
| Resource conflict | `409 Conflict` |
| GMP connection failure | `502 Bad Gateway` |
| GMP timeout | `504 Gateway Timeout` |
| Internal error | `500 Internal Server Error` |

## 7. Dependencies

### Runtime

| Dependency | Purpose |
|------------|---------|
| `gvm-client` / `gvm-gmp` | GMP protocol client + structured response models (tasks/reports/results from rust-gvm PR #68) |
| `axum` | HTTP framework |
| `tower` / `tower-http` | Middleware (CORS, compression, auth, trace context propagation) |
| `tokio` | Async runtime |
| `utoipa` | OpenAPI spec generation |
| `serde` / `serde_json` | Serialization |
| `uuid` | Opaque session-token / resource identifier support |
| `clap` | CLI argument parsing |
| `tracing` + `tracing-opentelemetry` + `opentelemetry` + `opentelemetry-otlp` | Structured logging + OTel export |
| `prometheus` | Metrics |

### Dev/Test

| Dependency | Purpose |
|------------|---------|
| `rstest` | Parameterized tests |
| `wiremock` | HTTP mock server (for downstream tests) |
| `assert_json_diff` | JSON response assertion |

## 8. Security Considerations

- **No credential storage**: GMP credentials are used only to establish a session; bearer session tokens must be treated as secrets and redacted from logs
- **Transport security**: REST TLS / termination-mode configuration is deferred to #130 and is not part of Phase 3 until explicitly re-scoped
- **Input validation**: All request bodies validated before GMP translation
- **No unsafe code**: `#[deny(unsafe_code)]` crate-wide
- **CORS**: Configurable origin allowlist (deny by default)
- **Headers**: Security headers are applied by REST middleware (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control` for API responses)
- **Audit taxonomy**: Session lifecycle emits `session.create`, `session.delete`, `session.expired`, and `session.disconnect`; resource workflows emit `command.execution` with `start`/`success`/`failure` outcomes plus resource/action metadata.
- **Token-safe observability**: Logs and spans use safe session identifiers (`session:<suffix>`). Raw bearer tokens, Basic credentials, and passwords must not be written to audit fields, tracing fields, problem details, or rate-limit/security events.

## 9. Open Questions

- [ ] Should we support GMP filter syntax passthrough or only structured query params?
- [ ] WebSocket vs SSE for real-time task status updates?
- [ ] Should request-scoped Basic auth remain a compatibility path long-term, or should clients be encouraged to use explicit sessions for all workflows?
