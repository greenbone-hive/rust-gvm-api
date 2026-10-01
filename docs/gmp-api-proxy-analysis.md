# GMP API Proxy Analysis

Status: architecture analysis. REST is implemented; gRPC and MCP are
forward-looking. The current REST contract is defined by
[`spec/rest-api/openapi.yaml`](../spec/rest-api/openapi.yaml), and current
runtime ownership is defined by
[`gateway-architecture.md`](gateway-architecture.md).

## 1. Scope

This document explains how `rust-gvm-api` should expose a gateway in front of `gvmd`.

The backend execution path remains:

`rust-gvm-api -> rust-gvm -> GMP/XML -> gvmd`

This analysis focuses on the public gateway surfaces that sit above that execution layer.

## 2. Why a Gateway Exists

`gvmd` exposes GMP as a raw XML stream over a persistent Unix socket or TLS connection. It does not offer a native REST, gRPC, or MCP surface.

That creates a clear gateway opportunity for consumers that want:

- standard API contracts
- typed client generation
- browser and script-friendly access
- simpler integration than raw GMP XML
- agent-facing tool access without re-implementing GMP session handling

## 3. Gateway Built on `rust-gvm`

Rather than waiting for `gvmd` itself to grow new public surfaces, the project can build them on top of `rust-gvm`:

- `rust-gvm-api` owns the customer-facing gateway surfaces
- `rust-gvm` stays the execution substrate for transport, protocol, parsing, and typed GMP builders

```text
┌──────────────┐   REST / gRPC / MCP      ┌──────────────────┐      GMP/XML       ┌────────┐
│ Web UI       │◄────────────────────────►│   rust-gvm-api   │◄──────────────────►│ gvmd   │
│ Scripts      │ HTTP/JSON, Protobuf,     │  gateway layer   │                    │        │
│ Automation   │ and MCP tools/resources  │                  │                    │        │
│ Agents       │                          │                  │                    │        │
└──────────────┘                          └────────┬─────────┘                    └────────┘
                                                   │
                                            ┌──────┴──────┐
                                            │  rust-gvm   │
                                            │ execution   │
                                            │ substrate   │
                                            └─────────────┘
```

The gateway stays relatively thin if all public surfaces share one execution core:

1. Accept REST, gRPC, or MCP requests.
2. Map them into one canonical operation catalog.
3. Execute them through `rust-gvm`.
4. Normalize the result into the calling surface.

## 4. Frontend Options

### Option A: REST/JSON

REST is the easiest surface for human-operated tooling, browser flows, `curl`, and lightweight automation.

Typical characteristics:

- `axum` or similar HTTP framework
- OpenAPI-backed contracts
- token-based gateway sessions
- predictable request/response semantics

### Option B: gRPC

gRPC is the strongest fit for:

- typed service-to-service integrations
- generated clients
- streaming-heavy operations such as large reports

It brings more schema work up front, but gives the cleanest typed machine interface once the core contracts settle.

### Option C: Hybrid REST + gRPC + MCP

This is the intended long-term shape:

- `REST` for browser/script-friendly access
- `gRPC` for typed service integration and streaming workloads
- `MCP` for agent- and tool-driven workflows

The important architectural point is that `MCP` is not a downstream REST client bolted on later. It is a peer adapter over the same gateway core.

## 5. Recommended Gateway Architecture

The gateway should have five layers:

1. REST adapter
2. gRPC adapter
3. MCP adapter
4. shared application core
5. `rust-gvm` execution layer

The shared core owns:

- canonical operation ids
- request validation
- auth/session handling
- policy enforcement hooks
- endpoint routing
- error normalization
- audit events

See [MCP Implementation Roadmap](mcp-implementation-roadmap.md) for the explicit MCP parity rule and implementation sequence.

## 6. Session and Connection Model

This design is constrained by how `gvmd` behaves:

- backend connections carry authentication state
- work must be serialized per authenticated backend session where required
- idle/revoked sessions need cleanup

That means the gateway should expose an explicit session bootstrap flow:

1. client authenticates to the gateway
2. gateway opens/authenticates the `gvmd` session through `rust-gvm`
3. gateway returns a session token
4. subsequent REST/gRPC/MCP operations reuse that gateway session

This model should be shared across all public surfaces. MCP should not invent a second hidden auth stack unless there is a deliberate local-only deployment mode.

## 7. Why MCP Must Be Native

Treating MCP as "just another REST client" would create the wrong layering:

- an extra request-mapping hop
- weaker parity guarantees
- drift between agent-facing behavior and the canonical operation model

The better model is:

- one canonical operation catalog
- three peer public surfaces
- one shared auth, routing, policy, and audit core

Examples:

| Canonical operation | REST | gRPC | MCP |
| --- | --- | --- | --- |
| `sessions.create` | `POST /api/v1/session` | `CreateSession` | `sessions.create` |
| `system.get_version` | `GET /api/v1/version` | `GetVersion` | `system.get_version` |
| `tasks.start` | `POST /api/v1/tasks/{id}/start` | `StartTask` | `tasks.start` |

Wire shapes differ. Capability must not.

## 8. Recommended Delivery Order

The safest sequence is:

1. define the canonical operation catalog
2. stand up the shared gateway core
3. ship a narrow `REST + MCP` slice first
4. expand parity across higher-value domains
5. add or expand `gRPC` once the contracts are stable

That keeps the first useful agent-facing surface inside the real architecture instead of in a sidecar.

## 9. Practical Consequences

For downstream consumers:

| Consumer | Preferred gateway shape |
| --- | --- |
| browser/admin tools | REST |
| service integrations | gRPC or REST |
| agent/tool workflows | native MCP tools backed by the same session model |

For project boundaries:

- `rust-gvm-api` owns public gateway surfaces and their contracts
- `rust-gvm` owns the backend execution substrate
- MCP planning and parity rules therefore belong in `rust-gvm-api`

## 10. Summary

The gateway should not be designed as "REST first, maybe MCP later." It should be designed as one shared gateway core with three peer adapters:

- REST
- gRPC
- MCP

That preserves a clean repo boundary, keeps customer-facing behavior in the API-layer repo, and prevents the agent-facing surface from drifting away from the real gateway contract.
