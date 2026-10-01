# Installation And Configuration

## Release artifacts

Current releases publish Debian packages, Arch Linux packages, an OCI image
archive, and this user documentation package with the matching OpenAPI
specification.

Choose the package or container form that matches your environment.

## What an installation needs

A working installation needs:

- a reachable gvmd instance
- a gateway configuration that points to the gvmd socket
- valid gvmd user credentials for the people or systems calling the API

The gateway is a separate service in front of gvmd. It does not replace gvmd.

## Package installation

Packaged installs use:

- example config: `/etc/gvm-gateway/gvm-gateway.toml.example`
- active config: `/etc/gvm-gateway/gvm-gateway.toml`
- shipped example in this documentation package: `package-config.example.toml`

The package does not create the active config automatically. Copy the example
file to the active path and then adjust the values for your deployment.

## Container installation

Container-oriented deployments can start from the settings shown in the shipped
container example config:

- `container-config.example.toml`

In a normal container setup the gateway listens on `0.0.0.0:8080` and assumes
it is running behind a TLS-terminating proxy.

## Configuration reference

### Core listener and backend

- `bind`
  HTTP listener address for the gateway, for example `127.0.0.1:8080`.
- `gvmd_endpoint`
  Unix socket endpoint for gvmd. Current releases expect a Unix socket path such
  as `unix:///run/gvmd/gvmd.sock`.

### Transport security

- `transport_security_mode`
  One of:
  - `disabled`: serve plain HTTP intentionally
  - `terminated_by_proxy`: serve plain HTTP behind a TLS-terminating proxy
  - `native`: serve HTTPS directly from the gateway
- `tls_certificate_path`
  Required when `transport_security_mode = "native"`.
- `tls_private_key_path`
  Required when `transport_security_mode = "native"`.

If `transport_security_mode` is `disabled` or `terminated_by_proxy`, TLS file
paths must not be set.

### Session handling

- `session_idle_timeout_secs`
  Maximum idle time for a gateway session before it expires.
- `session_max_global`
  Maximum number of active sessions across all users. Set to `0` to disable the
  limit.
- `session_max_per_user`
  Maximum number of active sessions for one user. Set to `0` to disable the
  limit.

### Logging and telemetry

- `local_log_output`
  Local log sink. Supported values:
  - `stdout`
  - `journald`
- `otlp_endpoint`
  Optional OTLP trace export endpoint.
- `telemetry_service_name`
  OpenTelemetry `service.name`.
- `telemetry_service_namespace`
  OpenTelemetry `service.namespace`.
- `telemetry_deployment_environment`
  OpenTelemetry `deployment.environment`.
- `telemetry_service_instance_id`
  OpenTelemetry `service.instance.id`.

### REST security settings

- `cors_allowed_origins`
  Allowed browser origins for CORS.
- `rate_limit_window_secs`
  Window size for REST rate limiting.
- `rate_limit_global_per_window`
  Total request budget per window. Set to `0` to disable that limit.
- `rate_limit_subject_per_window`
  Per-subject request budget per window. Set to `0` to disable that limit.
- `trusted_proxy_cidrs`
  Proxy source CIDRs whose forwarded client IPs may be trusted.

## Authentication options

The gateway supports two practical authentication patterns:

- session-based access:
  - create a session with `POST /api/v1/session` using HTTP Basic auth
  - reuse the returned bearer token on later requests
- request-scoped HTTP Basic auth:
  - for endpoints that allow it, the gateway can authenticate the request
    directly from Basic credentials instead of reusing a previously created
    session

For scripts, automation, and multi-step workflows, session-based access is the
normal choice because it avoids sending the username and password on every
request.

## Connection points

Operational probes:

- `/health`
- `/ready`

Versioned REST API:

- `/api/v1/...`

OpenAPI document exposed by the running service:

- `GET /api/v1/openapi.json`

Browser documentation:

- `GET /api/v1/docs`

This operational UI is outside the REST API contract. It uses the generated
`/api/v1/openapi.json` document as its source of truth and loads the
repository-bundled Redoc 2.5.3 asset from the gateway. The route's Content
Security Policy permits scripts and contract requests only from the gateway
itself, so browsers do not need outbound network access to render it.

## API contract and version

The running gateway derives `/api/v1/openapi.json` from its instrumented Axum
router. Release documentation packages contain the matching curated OpenAPI
files under `api/rest/`. Contract tests compare the generated and curated
documents so their paths, operations, parameters, request bodies, responses,
headers, media types, and schemas stay aligned.

`GET /api/v1/version` reports two distinct values:

- `apiVersion` is the REST contract and package version. It matches the
  top-level OpenAPI `info.version` for that release.
- `gmpVersion` is the protocol version reported by the connected gvmd backend.

The REST representation is backed by typed rust-gvm requests and responses.
GMP XML is an internal backend protocol and is never part of the public HTTP
contract.
