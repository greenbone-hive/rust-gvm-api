# Documentation archive

These documents are preserved for design history. They describe completed
migrations or plans that predate the current 0.5.0 workspace and must not be
used as the API contract or as implementation instructions.

| Document | Why it is archived | Current replacement |
| --- | --- | --- |
| [GMP API proxy analysis](gmp-api-proxy-analysis.md) | Early gateway-surface analysis built around a generic operation catalog; the shipped core uses typed ports and services. | [Gateway architecture](../gateway-architecture.md), [developer guide](../development.md) |
| [Proxy access-control analysis](proxy-access-control-analysis.md) | Exploratory multi-endpoint/RBAC design that was not implemented by the current single-endpoint gateway. | Current security and session behavior in [gateway architecture](../gateway-architecture.md) and the [REST specification](../../spec/rest-api/openspec.md) |
| [MCP implementation roadmap](mcp-implementation-roadmap.md) | July 2026 phase plan whose issue map, module assumptions, and delivery sequence were overtaken by later REST and adapter refactors. MCP remains unimplemented; future work needs a current ADR and roadmap. | [Gateway architecture](../gateway-architecture.md) for the peer-adapter boundary; live GitHub issues for future scheduling |
| [Typed GMP execution adoption](typed-gmp-execution-adoption.md) | Completed migration baseline and closure record for the move to typed `rust-gvm` execution. | [Developer guide](../development.md), [GMP-to-REST translation](../gmp-rest-translation.md), and the executable architecture tests |

Moving a document here does not revoke decisions that were carried into active
architecture or tests. Those decisions have been restated in the linked current
sources.
