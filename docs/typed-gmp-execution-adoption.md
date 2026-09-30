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
change solely because of this internal boundary migration. Issue
[#500](https://github.com/greenbone-hive/rust-gvm-api/issues/500) deliberately
contracts the Technology Preview ticket surface to 121 paths and 198 operations.

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

After those migrations and the ticket-surface removal, production code under
`src/gvmd_adapter` contains no direct `.call(...)` sites, no
`call_with_session(...)` helper, and no manual `::from_response(...)` pairings.
The generated REST OpenAPI contains 121 paths and 198 operations.

## Raw compatibility exceptions

There are no raw execution or manual response-parsing exceptions in the
gvmd adapter. Issue #500 removed the ticket discovery surface that previously
accounted for its final two exceptions. Architecture tests require zero
`.call(...)` and `::from_response(...)` sites in production adapter modules;
any future exception requires an explicit, reviewed architectural decision.
