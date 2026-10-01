# Technology Preview API migration notes

## Authentication modes

Protected resource operations accept either a persistent bearer session or
request-scoped HTTP Basic credentials. Create a persistent session with
`POST /api/v1/session`; inspect or delete that session with bearer-authenticated
`GET` or `DELETE /api/v1/session`. When Basic credentials are sent directly to
a protected resource operation, the gateway creates a backend context for that
request and tears it down before returning.

## Removed ticket surface

The former `GET /api/v1/tickets` and `GET /api/v1/tickets/{id}` Technology
Preview routes have been removed. They now behave like other unknown routes and
return the standard `404` problem response. Integrations should manage tickets
through their external ticketing system rather than through this gateway.

## Report import

`POST /api/v1/reports` imports one XML report into an existing import task. It
requires `taskId`, accepts optional `inAssets`, enforces a 10 MiB body limit,
and returns `201 Created` with the canonical report `Location`. The XML body is
opaque to the gateway; typed rust-gvm code validates and constructs the GMP
request.

## Explicit scan-configuration and policy bases

The Technology Preview create contract now matches gvmd's copy-based
configuration lifecycle. `POST /api/v1/scan-configs` requires
`baseScanConfigId`, identifying an active scan configuration, and
`POST /api/v1/policies` requires `basePolicyId`, identifying an active policy.

The gateway no longer accepts name-only creation and never chooses a base
automatically. A missing or malformed selector, a nonexistent or trashed base,
or a base from the other configuration family returns the standard `400`
RFC 9457 invalid-input response.

Scan-configuration request example:

```json
{
  "name": "Custom full and fast",
  "comment": "Local copy",
  "baseScanConfigId": "daba56c8-73ec-11df-a475-002264764cea"
}
```

Policy request example:

```json
{
  "name": "Custom compliance policy",
  "comment": "Local copy",
  "basePolicyId": "085569ce-73ed-11df-83c3-002264764cea"
}
```

## Task host ordering

`hostsOrdering` is no longer accepted by task or audit create/modify requests.
Pinned gvmd versions do not parse a request-side host-ordering field, so the
previous Technology Preview input was misleading. Response-side
`hostsOrdering` remains unchanged when gvmd reports it.
