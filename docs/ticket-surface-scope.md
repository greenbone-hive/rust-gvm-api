# GMP Ticket Surface Scope

Status: Accepted; supersedes the discovery-only boundary
Decision date: 2026-09-13
Previous decision: 2026-08-03 (recorded 2026-08-27)

## Context

[`rust-gvm-api` PR #417](https://github.com/greenbone-hive/rust-gvm-api/pull/417)
proposed ticket create, update, and delete operations. Product review rejected
that expansion because GVM tickets are rarely used and the additional public and
protocol surface is not worth its ongoing implementation, compatibility, and test
cost.

The original decision retained ticket discovery in `rust-gvm-api` while
rejecting lifecycle operations. Keeping those two reads still imposed public
contract, domain, adapter, compatibility, and test costs in every gateway layer.
Issue [#500](https://github.com/greenbone-hive/rust-gvm-api/issues/500)
therefore removes the remaining gateway surface. `rust-gvm` continues to own
its existing ticket command and response support for direct GMP consumers.

## Decision

`rust-gvm-api` exposes no GMP ticket support:

- `GET /api/v1/tickets` and `GET /api/v1/tickets/{id}` are not published routes.
- Ticket-specific contracts, domain types, application ports, outgoing-adapter
  behavior, and positive gateway tests are not maintained.
- `rust-gvm-api` will not add ticket discovery, create, clone, update, or delete
  operations to REST, gRPC, MCP, CLI, or another public adapter.
- `rust-gvm` keeps its existing ticket command builders, response models, typed
  client integration, and mock behavior, but will not expand them with new
  ticket-specific commands, fields, helpers, mock behavior, or conformance work.
- Lower-level raw GMP request paths remain available under their existing
  forward-compatibility contract; they do not create a supported ticket-specific
  gateway API commitment.

Coverage audits and parity plans must treat all GMP ticket functionality as a
deliberate gateway exclusion rather than an implementation gap.

## Reconsideration

Reintroducing this surface requires a new explicit product decision backed by a
concrete consumer need and an identified maintenance owner. Protocol availability
or parity with another GMP client is not sufficient by itself.

## Consequences

- [`rust-gvm-api` issue #393](https://github.com/greenbone-hive/rust-gvm-api/issues/393)
  is not planned.
- The former ticket routes use the ordinary unknown-route `404` response; no
  tombstone, redirect, `410`, or `501` compatibility route is retained.
- Future GMP schema-drift audits may report ticket additions, but those additions
  do not become rust-gvm or gateway roadmap items automatically.
- Integrations that manage tickets in an external system should continue using
  that system's API directly; the repository's OTOBO example already follows this
  boundary.
