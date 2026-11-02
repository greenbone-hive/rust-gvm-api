# Gateway Architecture

This document is the repository-local architecture reference for `rust-gvm-api`.
It describes the implemented component boundaries, session/connection model,
and current repository shape on `main`.

## Core Rules

- The gateway follows a ports-and-adapters (hexagonal) architecture.
- `rust-gvm-api` must not parse raw GMP XML directly.
  All GMP XML parsing and protocol-shape handling belong in `rust-gvm`; the gateway consumes typed models and protocol APIs from `rust-gvm`.
- `rust-gvm-api` must not locally construct GMP command XML or normalize GMP wire/display values.
  If a gateway change needs that behavior, the implementation stops and the missing typed support is reported against [`greenbone-hive/rust-gvm`](https://github.com/greenbone-hive/rust-gvm) instead.
- REST is the implemented incoming adapter. Future MCP work is planned to use
  the same execution core rather than duplicate gateway domain or gvmd logic.
- `rust-gvm-api` intentionally exposes no GMP ticket surface. Ticket discovery
  and lifecycle operations are excluded by the
  [GMP ticket surface decision](ticket-surface-scope.md).
- The domain layer owns session lifecycle rules and invariants, but does not hold live I/O handles.
- The gvmd outgoing adapter owns live backend connections, session-bound command serialization, and transport concerns.
- The current deployment target is a single gateway instance with in-memory session and connection state.
- Transport security must be explicit: plain HTTP (`disabled`), proxy-terminated HTTP (`terminated_by_proxy`), or native HTTPS (`native`).
- Trace correlation uses OpenTelemetry plus W3C Trace Context at the public adapter boundary.

## Current Workspace Shape

The authoritative workspace members are defined in the root `Cargo.toml`:

```text
crates/gvm-gateway-domain
crates/gvm-gateway-app
crates/gvm-gateway-rest
crates/gvm-gateway-gvmd
crates/gvm-gateway
```

Their responsibilities are:

- `gvm-gateway-domain`: session entities, lifecycle/state rules, port traits, domain errors.
- `gvm-gateway-app`: shared use cases and orchestration over the domain and ports.
- `gvm-gateway-rest`: REST incoming adapter, HTTP translation, security middleware, request/response mapping.
- `gvm-gateway-gvmd`: gvmd outgoing adapter built on `rust-gvm`.
- `gvm-gateway`: composition root, config loading, listener/bootstrap, tracing init, shutdown wiring.

## Adapter Status

- REST is the implemented public adapter on `main`.
- MCP is planned as another peer adapter over the same application core; it is not yet implemented.

## High-Level Structure

```text
Clients
  ├─ REST
  └─ MCP  (planned)
         │
         ▼
Incoming adapters
  ├─ gvm-gateway-rest
  └─ gvm-gateway-mcp  (planned)
         │
         ▼
Application core
  └─ gvm-gateway-app
         │
         ▼
Domain
  └─ gvm-gateway-domain
         │
         ▼
Outgoing adapter
  └─ gvm-gateway-gvmd
         │
         ▼
rust-gvm -> gvmd
```

## Session and Backend Ownership

- Incoming adapters authenticate/translate requests but do not own backend sessions.
- The domain layer owns session identity, limits, expiry, and lifecycle decisions.
- The gvmd adapter owns authenticated backend connections and per-session execution serialization.
- Shared use cases in `gvm-gateway-app` coordinate those responsibilities without leaking transport/framework concerns into the domain.

## Shared Session Execution Model

- Persistent sessions are the execution model for multi-request REST workflows.
- A successful session bootstrap yields an opaque bearer token that identifies one authenticated gateway session.
- The domain `SessionManager` owns:
  - token generation and lookup
  - per-user and global session limits
  - idle-expiry rules
  - explicit teardown and invalidation
- The gvmd adapter owns:
  - the live authenticated backend connection bound to a session token
  - single-flight execution on that connection
  - backend disconnect detection and cleanup
- Requests that resolve to the same session token must execute serially against gvmd.
- Queue saturation and per-request timeouts are backpressure events, not silent retries or reordering.

## Session Lifecycle Shape

1. The client authenticates and creates a gateway session.
2. The gateway authenticates against gvmd and binds the resulting backend connection to a new opaque session token.
3. Subsequent adapter calls resolve that token through the same shared application/domain path.
4. Every successful command dispatch refreshes the session's idle-expiry window.
5. Explicit teardown, idle expiry, or backend disconnect invalidates the token and closes the bound connection.

## Transport-Security Model

The gateway implements an explicit transport-security contract:

- `disabled` for intentional plain HTTP
- `terminated_by_proxy` for HTTP behind a trusted TLS-terminating proxy
- `native` for direct HTTPS from the gateway process

These modes do not change session ownership: the domain owns session lifecycle,
and the gvmd adapter owns the authenticated backend connection bound to each
session.

## Development Implications

- Architecture changes should update this document together with the relevant
  implementation and specifications.
- The GMP boundary architecture test is an executable guard for the `rust-gvm` ownership rule.
  New local GMP command construction, response parsing, or wire/display-name normalization in `gvm-gateway-gvmd` is a stop-and-report event, not a reason to add another gateway workaround.
- Shared session/connection behavior changes should stay aligned across the
  domain, application, gvmd adapter, REST adapter, and composition root.
- Coverage audits and adapter-parity plans should treat all GMP ticket operations
  as a deliberate exclusion, not as missing endpoints.
- Specs under `spec/rest-api/` should treat this document as the architectural source of truth.
- Repo docs must distinguish clearly between:
  - implemented gateway surfaces on `main`
  - planned adapter surfaces
  - exploratory or legacy artifacts that are not part of the current workspace composition root
