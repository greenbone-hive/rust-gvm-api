# Typed GMP Execution Adoption

Issue [#457](https://github.com/greenbone-hive/rust-gvm-api/issues/457) tracks the
migration of the gvmd adapter from manually paired command builders and response
parsers to rust-gvm's semantic requests and `GmpClient::execute` boundary.

## Synchronized `next` baseline

The baseline was recorded after synchronizing `main` into `next` and before the
first typed-execution migration:

- generated REST OpenAPI: 123 paths and 200 operations;
- direct `.call(...)` sites in `crates/gvm-gateway-gvmd/src`: 122;
- `call_with_session(...)` declarations and invocations: 66;
- manual `::from_response(...)` invocations: 215;
- direct `.execute(...)` sites: 0.

These source counts are migration indicators, not permanent API contracts. The
OpenAPI path and operation counts are the compatibility baseline and must not
change solely because of this internal boundary migration.

## Migration rules

Each migrated operation must:

1. construct a semantic request implementing `GmpRequest`;
2. execute it through the session-aware typed helper, preserving session queue
   limits, per-session serialization, tracing fields, and gateway error mapping;
3. consume the associated typed response directly, without a downstream
   `from_response` pairing;
4. preserve REST behavior, including pagination fallbacks, not-found mapping,
   and lookup-after-modify behavior.

Authentication and backend version probing use `GmpClient::execute` directly
because they run before a session-bound client exists. The first session-bound
slice covers standard target CRUD/clone/list operations and synchronous report
export.

The subsequent bounded families cover tasks and audits; reports and their
drill-downs; credentials and credential stores; scanners; generic configs,
scan configs, and policies; port lists; supporting resources and SecInfo;
alerts and schedules; identity administration; feeds and system discovery;
agents and agent groups; and specialized targets. Architecture tests prevent
these migrated modules from reintroducing the raw call/parser boundary.

After those migrations, production code under `src/gvmd_adapter` contains two
direct `.call(...)` sites, no `call_with_session(...)` helper, and two manual
`::from_response(...)` pairings. All four remaining markers belong to the two
ticket reads described below. The generated REST OpenAPI remains at the
123-path, 200-operation baseline.

## Intentional raw exceptions

The two ticket reads remain on the raw compatibility path. The public ticket
surface is intentionally discovery-only, and its lower-level compatibility
scope is documented in `docs/ticket-surface-scope.md`. An architecture test
keeps the production raw-call and manual-parser inventory fixed at those two
operations.
