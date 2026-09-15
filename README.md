# rust-gvm-api

[![CI](https://github.com/greenbone-hive/rust-gvm-api/actions/workflows/ci.yml/badge.svg)](https://github.com/greenbone-hive/rust-gvm-api/actions/workflows/ci.yml)
[![Security](https://github.com/greenbone-hive/rust-gvm-api/actions/workflows/security.yml/badge.svg)](https://github.com/greenbone-hive/rust-gvm-api/actions/workflows/security.yml)

> [!WARNING]
> **Technology Preview:** This code is provided as a Technology Preview only.
> All APIs are still subject to change and must not be considered stable.

> [!IMPORTANT]
> **Breaking Technology Preview change:** GMP ticket discovery is not exposed by
> `rust-gvm-api`; the former `/api/v1/tickets` routes were removed under
> [issue #500](https://github.com/greenbone-hive/rust-gvm-api/issues/500).
> Direct GMP consumers may continue using `rust-gvm`, while gateway integrations
> should manage tickets through their external ticketing system.

> [!NOTE]
> **Releases** use a PR-gated GitHub Actions flow. Run the "Prepare Release"
> workflow with the target version, label the generated PR `release`, and merge
> it. The tag workflow creates `v<version>` from the merge commit, and the
> publish workflow builds Debian, Arch Linux, OCI, user-documentation, and SBOM
> release artifacts.

Gateway API surfaces for [Greenbone Vulnerability Management (GVM)](https://greenbone.github.io/docs/latest/), built on top of [rust-gvm](https://github.com/greenbone-hive/rust-gvm). REST is implemented on `main`; gRPC and MCP remain planned peer adapters over the same shared core.

## Overview

This project provides a modern gateway on top of the Greenbone Management Protocol (GMP). Instead of speaking GMP's raw XML over Unix sockets or SSH, consumers interact through higher-level gateway surfaces while the gateway keeps XML parsing and protocol-shape handling inside `rust-gvm`.

### Crates

| Crate | Description |
|-------|-------------|
| `gvm-gateway-domain` | Domain model, session lifecycle rules, port traits |
| `gvm-gateway-app` | Shared gateway use cases and orchestration |
| `gvm-gateway-rest` | REST incoming adapter |
| `gvm-gateway-gvmd` | gvmd outgoing adapter built on `rust-gvm` |
| `gvm-gateway` | Composition root and runtime bootstrap |

### Architecture

```
Clients
  ├─ REST
  ├─ gRPC (planned)
  └─ MCP  (planned)
         │
         ▼
Incoming adapters
  ├─ gvm-gateway-rest
  ├─ gvm-gateway-grpc (planned)
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

See [Gateway Architecture](docs/gateway-architecture.md) for the authoritative architecture description derived from issues `#26` and `#27`.

## Status

The repository now contains a working REST gateway baseline in the `gvm-gateway*` workspace crates, including container/runtime packaging, shutdown control, transport-security modes, and tracing. gRPC and MCP remain planned surfaces; their specs and roadmap should be read as forward-looking design material rather than shipped runtime behavior.

## Shared Session Model

The gateway's multi-request execution model is session-backed rather than stateless:

- clients create a session and receive an opaque bearer token
- the domain `SessionManager` owns token lifecycle, expiry, and session limits
- the gvmd adapter owns the live authenticated backend connection bound to that session
- commands for one session execute serially against gvmd, with explicit backpressure on queue saturation

That session/connection model is shared architecture for REST today and planned gRPC later, even though the exact transport-security deployment mode is now configurable (`disabled`, `terminated_by_proxy`, `native`).

## Getting Started

### Prerequisites

- Rust 1.88.0+ (see `rust-toolchain.toml`)
- A running GVM/gvmd instance (for integration testing)
- [rust-gvm](https://github.com/greenbone-hive/rust-gvm) (pulled as a git dependency)

### Build

```bash
cargo build --workspace
```

### Test

```bash
cargo test --workspace
```

### Development

```bash
# Install dev tools
make setup-tools

# Install pre-commit hooks
make setup-hooks

# Run full CI locally
make ci
```

### OCI Image Build

Build the gateway image with either Docker or Podman:

```bash
./scripts/oci-build.sh --tag local/gvm-gateway:dev
```

The image is built from [Containerfile](./Containerfile) as a multi-stage OCI-compatible runtime image for the `gvm-gateway` binary. Release workflows also export the result as an OCI archive artifact.

### Compose Dev Stack

Start a local gateway + gvmd stack with either Docker Compose or Podman Compose:

```bash
./scripts/compose-dev.sh up -d --build
```

The stack definition in [compose.yaml](./compose.yaml) is based on the official Greenbone Community container topology, but trims it to the services needed for `gvmd` plus the gateway. On the first boot, feed and data initialization can take several minutes before `gvmd` is ready.

Run the compose-backed REST end-to-end tests through the wrapper script:

```bash
./scripts/run-e2e-tests.sh
```

The wrapper waits for `/ready`, prints feed status for diagnostics, then polls the REST resources required by the discovery scan test: discovery scan configs, OpenVAS scanner availability, and usable port lists. This is stricter than feed status alone because gvmd can accept GMP connections before first-boot data imports have populated REST-visible scan configs.

Run the weekly-scope performance slice through its dedicated wrapper:

```bash
./scripts/run-performance-tests.sh
```

That wrapper reuses the compose readiness/seed checks from the E2E lane, then runs the ignored `tests/performance` scenarios single-threaded and writes JSON result artifacts to `dist/performance/`. CI uses the same contract in the dedicated weekly Sunday-night workflow.

Useful follow-up commands:

```bash
./scripts/compose-dev.sh logs -f gvmd gvm-gateway
./scripts/compose-dev.sh down
```

### Container Runtime Contract

- Default container config: [packaging/gvm-gateway.container.toml](./packaging/gvm-gateway.container.toml)
- Listener: `0.0.0.0:8080`
- Default transport mode: `terminated_by_proxy`
- Default trusted proxy CIDRs for forwarded client IPs: `127.0.0.1/32`, `::1/128`
- gvmd socket mount: `/run/gvmd`
- Required backend endpoint: `GVM_GATEWAY_GVMD_ENDPOINT=unix:///run/gvmd/gvmd.sock`
- Required transport-security mode: `GVM_GATEWAY_TRANSPORT_SECURITY_MODE`
- Native TLS certificate path when `GVM_GATEWAY_TRANSPORT_SECURITY_MODE=native`: `GVM_GATEWAY_TLS_CERTIFICATE_PATH`
- Native TLS private-key path when `GVM_GATEWAY_TRANSPORT_SECURITY_MODE=native`: `GVM_GATEWAY_TLS_PRIVATE_KEY_PATH`
- Optional local log sink: `GVM_GATEWAY_LOCAL_LOG_OUTPUT` (`stdout` by default, `journald` for systemd deployments)
- Optional telemetry endpoint: `GVM_GATEWAY_OTLP_ENDPOINT`
- Optional telemetry resource attributes:
  - `GVM_GATEWAY_TELEMETRY_SERVICE_NAME`
  - `GVM_GATEWAY_TELEMETRY_SERVICE_NAMESPACE`
  - `GVM_GATEWAY_TELEMETRY_DEPLOYMENT_ENVIRONMENT`
  - `GVM_GATEWAY_TELEMETRY_SERVICE_INSTANCE_ID`
- Optional shutdown tuning: `GVM_GATEWAY_SHUTDOWN_DRAIN_TIMEOUT_SECS`
- Optional session tuning:
  - `GVM_GATEWAY_SESSION_IDLE_TIMEOUT_SECS`
  - `GVM_GATEWAY_SESSION_MAX_GLOBAL`
  - `GVM_GATEWAY_SESSION_MAX_PER_USER`
- Optional REST security overrides:
  - `GVM_GATEWAY_CORS_ALLOWED_ORIGINS`
  - `GVM_GATEWAY_RATE_LIMIT_WINDOW_SECS`
  - `GVM_GATEWAY_RATE_LIMIT_GLOBAL_PER_WINDOW`
  - `GVM_GATEWAY_RATE_LIMIT_SUBJECT_PER_WINDOW`
  - `GVM_GATEWAY_TRUSTED_PROXY_CIDRS`

### OS Package Runtime Contract

- Example package config: [packaging/gvm-gateway.toml](./packaging/gvm-gateway.toml), installed at `/etc/gvm-gateway/gvm-gateway.toml.example`
- Canonical package config path: `/etc/gvm-gateway/gvm-gateway.toml`; copy the example there to activate file-based settings
- Config directory: `/etc/gvm-gateway`, created by package installation
- Default backend endpoint: `unix:///run/gvmd/gvmd.sock`
- Package installation does not create a live canonical config file automatically; administrators opt into file-based settings by copying the example to `/etc/gvm-gateway/gvm-gateway.toml`.

### Transport Security Contract

- `transport_security_mode = "disabled"` serves plain HTTP intentionally.
- `transport_security_mode = "terminated_by_proxy"` serves plain HTTP behind a trusted TLS-terminating proxy.
- `transport_security_mode = "native"` serves HTTPS directly from the gateway process.
- Native TLS requires both `tls_certificate_path` and `tls_private_key_path`; startup fails if either path is missing or the PEM material cannot be loaded.
- Proxy mode does not require local TLS files.
- Forwarded headers are not trusted implicitly in proxy mode. Configure `trusted_proxy_cidrs` or `GVM_GATEWAY_TRUSTED_PROXY_CIDRS` with the direct proxy CIDRs whose `X-Forwarded-For` client IPs may be used for unauthenticated rate-limit buckets.

### Telemetry Contract

- Logs are always emitted locally through the gateway tracing subscriber.
- `local_log_output = "stdout"` keeps the current local formatter behavior and remains the default.
- `local_log_output = "journald"` sends local logs directly to `systemd-journald`; startup fails clearly if journald is unavailable in the selected runtime.
- OTLP trace export is enabled only when `otlp_endpoint` or `GVM_GATEWAY_OTLP_ENDPOINT` is set.
- The current exporter path is OTLP over gRPC (for example `http://otel-collector:4317`).
- Stable resource attributes are `service.name`, `service.namespace`, and `service.version`; `deployment.environment` and `service.instance.id` are emitted only when configured.
- Incoming REST requests accept W3C Trace Context headers (`traceparent`, optional `tracestate`, optional `baggage`).
- REST responses return correlation headers for `traceparent` and `tracestate`; `baggage` is consumed for parent context but is not echoed back.
- The gvmd backend runs over GMP on a Unix socket, so trace headers are not forwarded downstream; correlation across the internal boundary is represented by nested gateway/gvmd spans instead.

## Documentation

- Release-shipped user docs source:
  - [docs/user/index.md](docs/user/index.md)
  - [docs/user/overview.md](docs/user/overview.md)
  - [docs/user/usage.md](docs/user/usage.md)
  - [docs/user/examples.md](docs/user/examples.md)
- [REST API OpenSpec](spec/rest-api/openspec.md)
- [gRPC API OpenSpec](spec/grpc-api/openspec.md)
- [Gateway Architecture](docs/gateway-architecture.md)
- [GMP to REST Translation Model](docs/gmp-rest-translation.md)
- [GMP API Proxy Analysis](docs/gmp-api-proxy-analysis.md)
- [Proxy Access Control Analysis](docs/proxy-access-control-analysis.md)
- [MCP Implementation Roadmap](docs/mcp-implementation-roadmap.md)

## License

Licensed under [AGPL-3.0-or-later](LICENSE).
