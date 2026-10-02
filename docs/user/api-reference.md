# REST API reference

This is the human-readable map of the REST API shipped by `rust-gvm-api`
0.5.0. It explains common behavior and shows every current route family. For
exact request and response schemas, use the OpenAPI document shipped with the
same release or the running gateway's `GET /api/v1/openapi.json` endpoint.

The normative contract is
[`spec/rest-api`](https://github.com/greenbone-hive/rust-gvm-api/tree/main/spec/rest-api)
in the source repository and `api/rest/openapi.yaml` in the release docs
archive. The curated contract and runtime-generated contract are tested for
alignment. The current contract contains 121 paths and 199 operations.

## Base paths and documentation

- Versioned API: `/api/v1`
- Liveness: `GET /health`
- Readiness: `GET /ready`
- Runtime OpenAPI: `GET /api/v1/openapi.json`
- Browser documentation: `GET /api/v1/docs`

`/health` and `/ready` are intentionally unversioned. The browser documentation
route is an operational UI and is not itself part of the OpenAPI contract.

## Authentication

The gateway supports two authentication modes:

1. Create a persistent session with Basic credentials:

   ```http
   POST /api/v1/session
   Authorization: Basic <base64(username:password)>
   ```

   Reuse the returned `sessionToken`:

   ```http
   Authorization: Bearer <sessionToken>
   ```

2. Send Basic credentials directly to a protected resource operation. The
   gateway creates a backend context for that request and removes it before
   returning.

`GET /api/v1/session` and `DELETE /api/v1/session` operate on an existing
bearer session. Health, readiness, version, OpenAPI, and browser documentation
are public. Unless a route is explicitly public, assume that it requires
Bearer or request-scoped Basic authentication.

Authorization is enforced by gvmd for the authenticated user. The gateway does
not add an independent user-permission database.

## Common request behavior

### JSON and identifiers

Normal request and response bodies use `application/json`. Resource IDs are
UUIDs unless a route documents another identifier, such as an NVT OID,
preference name, or family name. Request objects reject unknown fields.

Report import is the main non-JSON exception:

```http
POST /api/v1/reports?taskId=<uuid>&inAssets=true
Content-Type: application/xml
```

It accepts one opaque XML report body up to 10 MiB. The selected task must be an
existing import task.

### Collections

Most collection routes support:

- `page`: one-based page number, default `1`;
- `perPage`: page size from `1` to `1000`, default `25`;
- `filter`: inline GMP filter expression;
- `filterId`: UUID of a saved filter.

Resource-specific selectors vary. Consult OpenAPI rather than assuming that a
query parameter accepted by one collection is accepted by another. Published
JSON and query names use camel case; some legacy snake-case aliases may remain
accepted during the Technology Preview.

Paginated responses use:

```json
{
  "data": [],
  "pagination": {
    "page": 1,
    "perPage": 25,
    "total": 0,
    "totalPages": 0
  }
}
```

### Creation, updates, and deletion

Resource creation normally returns `201 Created`, an identifier or resource
body, and a canonical `Location` header. Controller-style operations such as
task start/stop/resume and credential-store verification use `POST` action
routes.

Many current `PUT` operations are sparse Technology Preview updates rather
than full replacements. Omission, empty collection, and clear/detach behavior
is resource-specific; follow the exact schema and description for that route.

For delete operations that publish the `ultimate` query parameter, the default
uses gvmd's normal non-ultimate deletion behavior. `ultimate=true` requests
permanent deletion. Do not add that parameter to routes that do not document it.

### Errors

Errors use RFC 9457 `application/problem+json`:

```json
{
  "type": "https://gvm-gateway.greenbone.net/errors/not-found",
  "code": "not_found",
  "title": "Resource Not Found",
  "status": 404,
  "detail": "The requested resource was not found.",
  "instance": "/api/v1/targets/550e8400-e29b-41d4-a716-446655440000"
}
```

Use `code` for program logic. `detail` is human-readable and may include
occurrence-specific context.

Common statuses are:

| Status | Meaning |
| --- | --- |
| `400` | Invalid parameter, identifier, request body, or state-independent validation |
| `401` | Missing/invalid credentials or expired session |
| `403` | gvmd denied the authenticated user |
| `404` | Resource or job not found |
| `409` | Resource/job state conflict |
| `413` | Request body exceeds the route limit |
| `415` | Unsupported request media type |
| `429` | Rate, session, queue, or capacity limit; inspect `Retry-After` when present |
| `501` | The connected gvmd version/build does not expose the capability |
| `502` | Backend connection or execution failure |
| `504` | Backend execution timeout |

### Trace correlation

Requests may include W3C `traceparent`, `tracestate`, and `baggage`. Responses
return `traceparent` and, when present, `tracestate`; `baggage` is not echoed.

## Route map

Methods below are the methods currently published for each path. All paths in
the tables are relative to `/api/v1` except `/health` and `/ready`.

### System and sessions

| Methods | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Unversioned process liveness |
| `GET` | `/ready` | Unversioned backend readiness |
| `GET` | `/version` | REST package/API version and backend GMP version |
| `GET` | `/timezones` | Backend timezone catalog |
| `GET` | `/openapi.json` | Runtime-generated OpenAPI contract |
| `POST`, `GET`, `DELETE` | `/session` | Create, inspect, or destroy the current session |

### Targets, agents, and generic current-GVMD resources

| Methods | Path | Purpose |
| --- | --- | --- |
| `GET`, `POST` | `/targets` | List or create classic scan targets |
| `GET`, `PUT`, `DELETE` | `/targets/{id}` | Read, update, or delete a target |
| `POST` | `/targets/{id}/clone` | Clone a target |
| `GET` | `/agents` | List agents |
| `GET`, `PUT`, `DELETE` | `/agents/{id}` | Read, update, or delete an agent |
| `POST` | `/agents/sync` | Synchronize agent state |
| `GET` | `/agents/{id}/support-bundle` | Download an agent support bundle |
| `PUT` | `/agent-control-scan-configs/{id}` | Update an agent-control scan configuration |
| `GET` | `/scanners/{id}/agent-installer-instruction` | Read the installer instruction for a scanner |
| `GET`, `POST` | `/agent-groups` | List or create agent groups |
| `GET`, `PUT`, `DELETE` | `/agent-groups/{id}` | Read, update, or delete an agent group |
| `POST` | `/agent-groups/{id}/clone` | Clone an agent group |
| `GET` | `/assets` | List generic current-GVMD assets |
| `GET`, `PUT`, `DELETE` | `/assets/{id}` | Read, update, or delete a generic asset |
| `GET` | `/configs` | List generic current-GVMD configs |
| `GET`, `DELETE` | `/configs/{id}` | Read or delete a generic config |
| `POST` | `/configs/{id}/clone` | Clone a generic config |
| `GET`, `POST` | `/oci-image-targets` | List or create OCI-image targets |
| `GET`, `PUT`, `DELETE` | `/oci-image-targets/{id}` | Read, update, or delete an OCI-image target |
| `POST` | `/oci-image-targets/{id}/clone` | Clone an OCI-image target |
| `GET`, `POST` | `/web-application-targets` | List or create web-application targets |
| `GET`, `PUT`, `DELETE` | `/web-application-targets/{id}` | Read, update, or delete a web-application target |
| `POST` | `/web-application-targets/{id}/clone` | Clone a web-application target |

### Tasks and audits

| Methods | Path | Purpose |
| --- | --- | --- |
| `GET`, `POST` | `/tasks` | List or create scan tasks |
| `GET`, `PUT`, `DELETE` | `/tasks/{id}` | Read, update, or delete a task |
| `POST` | `/tasks/{id}/clone` | Clone a task |
| `POST` | `/tasks/{id}/start` | Start a task and return its report ID |
| `POST` | `/tasks/{id}/stop` | Stop a task |
| `POST` | `/tasks/{id}/resume` | Resume a task |
| `GET`, `POST` | `/audits` | List or create compliance audits |
| `GET`, `PUT`, `DELETE` | `/audits/{id}` | Read, update, or delete an audit |
| `POST` | `/audits/{id}/start` | Start an audit |
| `POST` | `/audits/{id}/stop` | Stop an audit |
| `POST` | `/audits/{id}/resume` | Resume an audit |

### Reports, results, and export jobs

| Methods | Path | Purpose |
| --- | --- | --- |
| `GET`, `POST` | `/reports` | List reports or import one report |
| `GET`, `DELETE` | `/reports/{id}` | Read or delete a report |
| `POST` | `/reports/{id}/exports` | Create an asynchronous export job |
| `GET` | `/reports/{id}/results` | List report results |
| `GET` | `/reports/{id}/vulnerabilities` | List report vulnerability projections |
| `GET` | `/reports/{id}/tls-certificates` | List report TLS-certificate projections |
| `GET` | `/reports/{id}/errors` | List report errors |
| `GET` | `/reports/{id}/closed-cves` | List report closed-CVE projections |
| `GET` | `/reports/{id}/hosts` | List report hosts |
| `GET` | `/reports/{id}/ports` | List report ports |
| `GET` | `/reports/{id}/applications` | List report applications |
| `GET` | `/reports/{id}/operating-systems` | List report operating systems |
| `GET` | `/reports/{id}/cves` | List report CVEs |
| `GET` | `/results` | List visible scan results |
| `GET` | `/results/{id}` | Read one scan result |
| `GET`, `DELETE` | `/jobs/{id}` | Inspect or cancel a job |
| `GET` | `/jobs/{id}/result` | Download a successful job result |

Creating an export returns `202 Accepted`, `Location`, `Retry-After`, and a job
representation. Jobs and artifacts are visible only to the creating user.
Deleting the creating session cancels its non-terminal jobs. The gateway keeps
at most 1000 jobs and removes terminal job metadata/artifacts 15 minutes after
completion.

### Scan configuration and supporting management resources

| Methods | Path | Purpose |
| --- | --- | --- |
| `GET`, `POST` | `/scan-configs` | List or create scan configurations |
| `GET`, `PUT`, `DELETE` | `/scan-configs/{id}` | Read, update, or delete a scan configuration |
| `GET` | `/scan-configs/{id}/nvts` | List selected NVTs |
| `GET` | `/scan-configs/{id}/nvts/{oid}` | Read one selected NVT |
| `GET` | `/scan-configs/{id}/preferences` | List scan-config preferences |
| `GET`, `PUT` | `/scan-configs/{id}/preferences/{name}` | Read, set, or reset a preference as documented by the request |
| `PUT` | `/scan-configs/{id}/families/{family}/nvts` | Replace a family's selected NVTs |
| `PUT` | `/scan-configs/{id}/family-selection` | Replace family selection |
| `GET`, `POST` | `/policies` | List or create compliance policies |
| `GET`, `PUT`, `DELETE` | `/policies/{id}` | Read, update, or delete a policy |
| `GET` | `/scanners` | List scanners |
| `GET` | `/scanners/{id}` | Read one scanner |
| `GET`, `POST` | `/alerts` | List or create alerts |
| `GET`, `PUT`, `DELETE` | `/alerts/{id}` | Read, update, or delete an alert |
| `GET`, `POST` | `/schedules` | List or create schedules |
| `GET`, `PUT`, `DELETE` | `/schedules/{id}` | Read, update, or delete a schedule |
| `GET` | `/credential-stores` | List credential stores when supported by gvmd |
| `GET`, `PUT` | `/credential-stores/{id}` | Read or update a credential store |
| `POST` | `/credential-stores/{id}/actions/verify` | Verify a credential store |
| `GET`, `POST` | `/credentials` | List or create credentials |
| `GET`, `PUT`, `DELETE` | `/credentials/{id}` | Read, update, or delete a credential |
| `GET`, `POST` | `/port-lists` | List or create port lists |
| `GET`, `PUT`, `DELETE` | `/port-lists/{id}` | Read, update, or delete a port list |

### Identity and current-user settings

| Methods | Path | Purpose |
| --- | --- | --- |
| `GET`, `POST` | `/users` | List or create users |
| `GET`, `PUT`, `DELETE` | `/users/{id}` | Read, update, or delete a user |
| `GET`, `POST` | `/groups` | List or create groups |
| `GET`, `PUT`, `DELETE` | `/groups/{id}` | Read, update, or delete a group |
| `GET`, `POST` | `/roles` | List or create roles |
| `GET`, `PUT`, `DELETE` | `/roles/{id}` | Read, update, or delete a role |
| `GET`, `POST` | `/permissions` | List or create permissions |
| `GET`, `PUT`, `DELETE` | `/permissions/{id}` | Read, update, or delete a permission |
| `GET` | `/user-settings` | List settings for the authenticated user |
| `GET`, `PUT` | `/user-settings/{id}` | Read or update one current-user setting |

The gateway does not expose global auth configuration, global settings,
license administration, wizard execution, trashcan-wide cleanup/restore, or
scanner administration. Typed upstream support does not automatically create a
public REST operation.

### Inventory, saved resources, and SecInfo

| Methods | Path | Purpose |
| --- | --- | --- |
| `GET` | `/feeds` | List backend feed status |
| `GET`, `POST` | `/hosts` | List or create host assets |
| `GET`, `PUT`, `DELETE` | `/hosts/{id}` | Read, update, or delete a host |
| `GET` | `/operating-systems` | List operating-system assets |
| `GET`, `PUT`, `DELETE` | `/operating-systems/{id}` | Read, update, or delete an operating-system asset |
| `GET` | `/tls-certificates` | List TLS-certificate assets |
| `GET` | `/tls-certificates/{id}` | Read one TLS certificate |
| `GET` | `/report-formats` | List report formats |
| `GET` | `/report-formats/{id}` | Read one report format |
| `GET`, `POST` | `/filters` | List or create saved filters |
| `GET`, `PUT`, `DELETE` | `/filters/{id}` | Read, update, or delete a filter |
| `POST` | `/filters/{id}/clone` | Clone a filter |
| `GET`, `POST` | `/tags` | List or create tags |
| `GET`, `PUT`, `DELETE` | `/tags/{id}` | Read, update, or delete a tag |
| `POST` | `/tags/{id}/clone` | Clone a tag |
| `GET`, `POST` | `/notes` | List or create notes |
| `GET`, `PUT`, `DELETE` | `/notes/{id}` | Read, update, or delete a note |
| `GET`, `POST` | `/overrides` | List or create overrides |
| `GET`, `PUT`, `DELETE` | `/overrides/{id}` | Read, update, or delete an override |
| `GET` | `/vulnerabilities` | List SecInfo vulnerabilities |
| `GET` | `/cves` | List CVEs |
| `GET` | `/cves/{id}` | Read one CVE |
| `GET` | `/cpes` | List CPEs |
| `GET` | `/cpes/{id}` | Read one CPE |
| `GET` | `/cert-bund-advisories` | List CERT-Bund advisories |
| `GET` | `/cert-bund-advisories/{id}` | Read one CERT-Bund advisory |
| `GET` | `/dfn-cert-advisories` | List DFN-CERT advisories |
| `GET` | `/dfn-cert-advisories/{id}` | Read one DFN-CERT advisory |
| `GET` | `/nvts` | List NVTs |
| `GET` | `/nvts/{id}` | Read one NVT |
| `GET` | `/nvt-families` | List NVT families |

## Deliberate exclusions and backend-dependent operations

The public API is selected, not a mechanical one-to-one mirror of every GMP
command. GMP tickets are deliberately excluded. Several current-GVMD features
are present only on compatible versions/builds; those routes remain part of
the REST contract but return `501` when the connected backend cannot perform
them.

For the complete method-level upstream disposition, see the repository's
[`upstream-surface-dispositions.tsv`](https://github.com/greenbone-hive/rust-gvm-api/blob/main/docs/upstream-surface-dispositions.tsv).
