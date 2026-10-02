# Proxy Access Control Analysis

> **Archived:** This is an unimplemented early multi-endpoint/RBAC exploration,
> not a description of the current gateway. See
> [`gateway-architecture.md`](../gateway-architecture.md) and the current
> [REST specification](../../spec/rest-api/openspec.md).

## 1. Scope

This document describes how `rust-gvm-api` should enforce access control when one gateway fronts one or more `gvmd` endpoints.

It extends the basic gateway model with:

- client authentication
- endpoint authorization
- operation-level policy
- auditability across REST, gRPC, and MCP

## 2. Core Design

The gateway is not only a protocol translator. It is also the access-control plane in front of the scanner estate.

```text
Client Identity
    │
    ▼
┌──────────────┐
│ Auth Layer   │  API keys / OIDC / mTLS / service identity
└──────┬───────┘
       ▼
┌──────────────┐
│ Policy Engine│  endpoint binding + operation permissions + limits
└──────┬───────┘
       ▼
┌──────────────┐
│ Gateway Core │  canonical operation catalog + audit + routing
└──────┬───────┘
       ▼
┌──────────────┐
│ rust-gvm     │  authenticated gvmd sessions / endpoint pools
└──────────────┘
```

## 3. Why MCP Matters Here

MCP changes the public surface shape, but it should not change the underlying security model.

The same policy engine should govern:

- REST endpoints
- gRPC methods
- MCP tools/resources

That means:

- a capability allowed through REST must carry the same authorization semantics through MCP
- audit logs must record which surface invoked the operation
- rate limits and endpoint bindings must apply uniformly

If MCP is treated as a sidecar REST client instead of a native gateway surface, policy parity becomes accidental. That is the failure mode this design avoids.

## 4. Entity Model

The gateway needs three first-class entities:

### Client identity

- id
- auth method
- roles
- team or tenant metadata

### Managed endpoint

- endpoint id
- transport configuration
- credential reference
- connection-pool settings
- tags such as `production`, `staging`, `customer-a`

### Policy rule

- subject selector
- endpoint selector
- allowed operations
- denied operations
- optional schedule/limit constraints

## 5. Authorization Model

Start with RBAC, not ABAC.

Example operation categories:

| Category | Meaning |
| --- | --- |
| `read` | view tasks, targets, reports, version, configs |
| `scan` | create/start/stop scan workflows |
| `manage` | create/modify/delete managed resources |
| `admin` | user/settings/auth administration |
| `report` | read potentially sensitive report/result payloads |

Example role mapping:

| Role | Endpoint scope | Allowed categories |
| --- | --- | --- |
| `soc-analyst` | production scanners | `read`, `scan`, `report` |
| `devsecops` | staging scanners | `*` |
| `auditor` | all assigned scanners | `read`, `report` |
| `tenant-admin` | tenant-scoped scanners only | `*` within tenant |

Fine-grained command or operation-id permissions can sit beneath these categories when needed.

## 6. Request Flow

1. client authenticates to the gateway
2. gateway resolves identity and roles
3. client invokes a canonical operation through REST, gRPC, or MCP
4. policy engine evaluates endpoint access, operation permission, and any limits
5. gateway routes the operation to the correct authenticated backend session
6. audit event records actor, endpoint, operation, surface, and result

The surface-specific adapter should be thin. Authorization belongs below the adapter boundary.

## 7. Multi-Surface Parity Rule

Every shipped public surface must respect the same policy semantics.

Examples:

| Canonical operation | REST surface | gRPC surface | MCP surface | Policy category |
| --- | --- | --- | --- | --- |
| `targets.list` | `GET /api/v1/targets` | `ListTargets` | `targets.list` | `read` |
| `tasks.start` | `POST /api/v1/tasks/{id}/start` | `StartTask` | `tasks.start` | `scan` |
| `reports.get` | `GET /api/v1/reports/{id}` | `GetReport` | `reports.get` | `report` |

If a role may start tasks through REST, it should not be silently denied through MCP for the same canonical operation.

## 8. Audit Requirements

Every operation should emit an audit event that includes:

- actor identity
- target endpoint
- canonical operation id
- public surface: `rest`, `grpc`, or `mcp`
- allow/deny outcome
- backend result status

This matters especially for MCP because agent activity needs to be distinguishable from browser or service activity without changing the underlying authorization rules.

## 9. Delivery Phases

### Phase 1

- single-endpoint gateway
- REST adapter
- MCP adapter for the same initial operation set
- API-key or equivalent simple auth
- operation-level RBAC
- audit logging

### Phase 2

- multiple managed endpoints
- endpoint registry and routing
- tenant or environment segmentation
- per-endpoint pools and health checks

### Phase 3

- OIDC/enterprise identity integration
- richer policy model if needed
- gRPC surface expansion
- conformance tests that verify policy parity across REST/gRPC/MCP

## 10. Summary

The access-control design should treat MCP as a native public surface, not a downstream client exception.

That keeps the system coherent:

- one identity model
- one authorization model
- one audit model
- three peer public surfaces

With that structure, `rust-gvm-api` can own gateway security semantics cleanly while `rust-gvm` remains focused on backend execution.
