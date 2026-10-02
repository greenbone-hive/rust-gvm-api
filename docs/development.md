# Developer guide

This guide is the practical code map for contributors to `rust-gvm-api`. It
describes the current 0.5.0 workspace on `main`, where behavior belongs, and
the shortest reliable validation path for each kind of change.

## What this repository owns

`rust-gvm-api` is a gateway in front of gvmd. The shipped public surface is
REST. The gateway owns HTTP contracts, application workflows, domain types,
session lifecycle, runtime configuration, and translation between domain
values and typed `rust-gvm` requests and responses.

It does **not** own GMP XML. Command construction, response parsing, protocol
version rules, and GMP wire/display-name normalization belong in
[`greenbone-hive/rust-gvm`](https://github.com/greenbone-hive/rust-gvm).

```text
HTTP client
    -> gvm-gateway-rest
    -> gvm-gateway-app
    -> gvm-gateway-domain ports and models
    -> gvm-gateway-gvmd
    -> typed rust-gvm request/response
    -> gvmd
```

If a gateway change appears to require hand-written GMP XML, local response
parsing, or string normalization for a GMP wire value, stop. Use the
[GMP boundary issue template](rust-gvm-gmp-boundary-issue-template.md) to
describe the missing typed support upstream.

## Sources of truth

Use the following order when locating or changing behavior:

1. [`spec/rest-api/`](../spec/rest-api/) defines externally observable REST
   behavior: routes, methods, parameters, schemas, status codes, headers, and
   semantics.
2. `crates/gvm-gateway-rest/src/router.rs` is the runtime route inventory.
   Its generated OpenAPI is served at `/api/v1/openapi.json` and contract-tested
   against the curated specification.
3. [`gateway-architecture.md`](gateway-architecture.md) defines component,
   session, and connection ownership.
4. Domain and application contracts live in `gvm-gateway-domain` and
   `gvm-gateway-app`.
5. Historical documents under [`archive/`](archive/README.md) are context only.

Do not change a specification solely to make a disagreement disappear. Decide
whether the runtime or the contract is wrong, then change the correct owner and
add a regression test.

## Workspace map

| Location | Responsibility | Start here |
| --- | --- | --- |
| `crates/gvm-gateway-domain` | Framework-independent models, errors, session rules, and outgoing port traits | `src/lib.rs`, `src/ports.rs`, resource-family modules |
| `crates/gvm-gateway-app` | Use cases and orchestration over domain ports | `src/service.rs`, the matching resource-family module |
| `crates/gvm-gateway-rest` | Axum routes, HTTP DTOs, validation, auth policy, Problem Details, generated OpenAPI | `src/router.rs`, `src/error.rs`, `src/openapi.rs`, the matching handler module |
| `crates/gvm-gateway-gvmd` | Domain-to-typed-GMP mapping, typed response projection, session-bound backend execution | `src/gvmd_adapter/mod.rs`, `src/gvmd_adapter/ports/`, `src/conversions.rs` |
| `crates/gvm-gateway` | Composition root, config, listener/TLS, telemetry, shutdown | `src/main.rs`, `src/config.rs`, `src/server.rs` |
| `spec/rest-api` | Curated OpenAPI and behavioral design/test specifications | `openapi.yaml`, `openspec.md`, the resource-family YAML file |
| `tests/e2e` | Live HTTP client and compose-backed REST lifecycles | `tests/rest_discovery_scan.rs` and other `rest_*.rs` files |
| `tests/performance` | Ignored performance scenarios run by the weekly wrapper | `tests/` and `README.md` |
| `packaging`, `compose.yaml`, `Containerfile` | Package/container runtime contract | matching example config and build scripts |
| `docs/user` | Release-shipped user guidance and examples | `index.md` |

REST supporting resources are split by family under
`crates/gvm-gateway-rest/src/supporting_resources/`. The gvmd adapter follows
the same ownership pattern under `crates/gvm-gateway-gvmd/src/gvmd_adapter/ports/`.
Keep new work in the module that owns the resource family; do not rebuild a
monolithic catch-all module.

## Local setup

The workspace uses Rust 1.88.0 as its minimum supported version. The checked-in
toolchain file selects the normal development toolchain.

```bash
cargo build --workspace --all-features
cargo test --workspace
```

Install optional repository tools and hooks with:

```bash
make setup-tools
make setup-hooks
```

The local compose stack requires Docker Compose or Podman Compose:

```bash
./scripts/compose-dev.sh up -d --build
./scripts/run-e2e-tests.sh
./scripts/compose-dev.sh down
```

The first start can take several minutes while Greenbone data is initialized.
Readiness of the TCP/GMP process alone does not mean scan configurations,
scanners, and port lists are ready for an end-to-end scan.

## How to change a REST capability

Follow the request from the public contract inward, then follow the response
back out:

1. Read the relevant YAML file in `spec/rest-api/` and the shared schemas in
   `common.yaml`.
2. Find the route in `gvm-gateway-rest/src/router.rs` and its handler/DTO module.
3. Find the application method in the matching `gvm-gateway-app` module.
4. Find the domain model and port method in `gvm-gateway-domain`.
5. Find the outgoing implementation under
   `gvm-gateway-gvmd/src/gvmd_adapter/ports/`.
6. Confirm the operation uses a typed `rust-gvm` request and typed response.
7. Update tests at each changed boundary and, for externally visible behavior,
   the curated OpenAPI and user documentation.

Changing a command usually requires checking all of these concerns:

- request DTO validation and unknown-field rejection;
- domain input/output and error identity;
- typed request construction and typed response projection;
- backend version or help-discovery gates;
- `404`, `409`, `501`, `502`, and `504` mapping where applicable;
- mock-server and real-gvmd behavior;
- generated-versus-curated OpenAPI parity;
- user-visible examples and migration notes.

The current API is a Technology Preview, but compatibility changes must still
be explicit. Do not rename public fields or routes merely to resemble another
client library.

## Sessions and authentication

Persistent sessions and request-scoped Basic authentication share the same
backend execution path:

- `POST /api/v1/session` authenticates with Basic credentials and returns an
  opaque bearer token.
- `GET` and `DELETE /api/v1/session` operate on the current bearer session.
- Protected resource routes also accept Basic credentials for one request;
  the temporary backend context is removed before the response completes.
- One persistent token owns one authenticated gvmd connection. Operations on
  that connection are serialized.

Session identity and limits belong to the domain. Live connections and
single-flight execution belong to the gvmd adapter. HTTP credential extraction
and route auth policy belong to the REST adapter. Preserve those boundaries
when changing authentication or backpressure behavior.

## Errors and backend capability gaps

The public error format is RFC 9457 `application/problem+json`. Stable client
logic should use the `code` field rather than parsing `detail` text.

The gvmd adapter maps typed `rust-gvm` errors into `GatewayError`; the REST
adapter maps `GatewayError` into HTTP status and Problem Details. A command that
is unavailable because of backend version or advertised capability maps to
`501 Not Implemented`. An unreachable or failed backend maps to `502`, and a
timeout maps to `504`. Do not infer those categories from endpoint-specific
message strings.

## Tests by change type

Run focused tests while iterating:

```bash
# Domain or session rules
cargo test -p gvm-gateway-domain

# Application workflows and job behavior
cargo test -p gvm-gateway-app

# REST DTOs, handlers, auth, errors, and generated OpenAPI
cargo test -p gvm-gateway-rest

# Typed GMP mapping, adapter integration, and architecture guards
cargo test -p gvm-gateway-gvmd

# Runtime config, composition, TLS, and full HTTP contract tests
cargo test -p gvm-gateway

# Compile the external E2E and performance clients
cargo test -p gvm-gateway-e2e
cargo test -p gvm-gateway-performance
```

Before handing off code changes, run:

```bash
cargo fmt --all -- --check
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-Dwarnings' cargo doc --locked --workspace --all-features --no-deps
cargo deny check
```

`make ci` provides the repository's normal local aggregate. Security-policy,
package/container, MSRV, coverage, and live compose-backed checks also run in
GitHub Actions; use their dedicated scripts when the changed area requires
them.

For a docs-only change, do not run the full Rust test suite unless the docs
contain checked code/examples or packaging/contract logic changed. Always
validate relative links and build the user docs package when `docs/user`,
`spec/rest-api`, or `scripts/build-docs-package.sh` changes.

```bash
make docs-check
```

## Documentation workflow

Keep each kind of information in its owner:

- Public API behavior: `spec/rest-api/`.
- Human route and behavior overview: `docs/user/api-reference.md`.
- Installation and configuration: `docs/user/usage.md`.
- End-to-end calls: `docs/user/examples.md` and executable examples.
- Breaking Technology Preview changes: `docs/user/migration.md`.
- Architecture and ownership: `docs/gateway-architecture.md`.
- Historical analysis or completed migrations: `docs/archive/`.

The release documentation archive is built by
`scripts/build-docs-package.sh`. Its OpenAPI version must equal the requested
package version. Build and inspect it with:

```bash
version="$(./scripts/workspace-version.sh)"
./scripts/build-docs-package.sh --version "${version}" --output-dir dist/docs
tar tzf "dist/docs/rust-gvm-api-docs-${version}.tar.gz"
```

## Pull-request checklist

- The change is in the owning crate and respects the typed GMP boundary.
- Public behavior and the curated/runtime OpenAPI remain aligned.
- New or changed tests explain the behavior or regression they protect.
- User-facing changes update the user docs in the same PR.
- Focused tests and the risk-appropriate workspace checks pass.
- The branch is rebased onto its target branch before push.
- Commit and PR metadata follow the repository's signing and attribution rules.
