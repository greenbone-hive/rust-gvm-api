# Documentation

This directory separates current guidance from design history. Start with the
document that matches the work you are doing; do not treat every Markdown file
as an equally authoritative description of the running service.

## Start here

- [Developer guide](development.md) — repository map, source-of-truth rules,
  local workflow, and validation by change type.
- [User documentation](user/index.md) — installation, configuration, API
  reference, migration notes, and executable examples shipped with releases.
- [Human-readable REST API reference](user/api-reference.md) — authentication,
  common semantics, and a complete route-family map for the current REST API.
- [Runtime API documentation](http://127.0.0.1:8080/api/v1/docs) — Redoc served
  by a locally running gateway.
- [Curated OpenAPI root](../spec/rest-api/openapi.yaml) — the normative,
  release-aligned REST contract.

## Current architecture and policy

- [Gateway architecture](gateway-architecture.md) — authoritative component,
  session, connection, and adapter ownership.
- [GMP-to-REST translation](gmp-rest-translation.md) — how GMP commands become
  REST resources without leaking XML into the gateway.
- [GMP boundary issue template](rust-gvm-gmp-boundary-issue-template.md) — use
  when the gateway needs typed protocol support that belongs in `rust-gvm`.
- [Workflow security policy](WORKFLOW_SECURITY.md) — supply-chain and workflow
  gates.

## Product decisions and compatibility records

- [Ticket surface decision](ticket-surface-scope.md) — accepted decision that
  tickets are not part of the gateway API.
- [Upstream surface dispositions](upstream-surface-dispositions.md) — readable
  summary of the completed rust-gvm v0.7 method disposition.
- [Machine-readable disposition ledger](upstream-surface-dispositions.tsv) —
  exhaustive, test-checked method-level record.

## Specifications

- [`spec/rest-api/`](../spec/rest-api/) is normative for public REST behavior.
- [`spec/grpc-api/`](../spec/grpc-api/) is forward-looking; gRPC is not part of
  the current runtime.

## Historical material

Completed migrations and superseded design analyses live under
[`archive/`](archive/README.md). They explain how the project arrived at the
current design, but they are not implementation instructions or API contracts.

## Authority order

When documents disagree, use this order:

1. executable runtime behavior and contract tests;
2. `spec/rest-api/` and the runtime-generated `/api/v1/openapi.json` document;
3. `gateway-architecture.md` and accepted decision records;
4. developer and user guides;
5. archived material.

Surface disagreements deliberately. Do not update a specification merely to
hide a runtime mismatch.
