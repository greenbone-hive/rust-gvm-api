# GMP to REST Translation Model

Status: explanatory architecture note

Reviewed: 2026-09-15

This document explains the Greenbone Management Protocol (GMP) boundary and
compares two ways of exposing it to HTTP clients:

- the command-oriented HTTP bridge implemented by GSA and GSAD; and
- the resource-oriented REST translation implemented by `rust-gvm-api`.

It is an implementation guide, not a public API contract. The normative REST
contract remains the files under [`spec/rest-api`](../spec/rest-api/), and the
repository ownership rules remain in
[`gateway-architecture.md`](gateway-architecture.md).

## Review Basis

The analysis is based on these repository snapshots:

- [`greenbone/gsa` at `4ba9551`](https://github.com/greenbone/gsa/tree/4ba9551bcd82bc53e22684ab5bb0eacc73419729)
- [`greenbone/gsad` at `b98497f`](https://github.com/greenbone/gsad/tree/b98497f2cad94888b594aa6af1c84719d3c36a03)
- `greenbone-hive/rust-gvm-api` `main` at `0ff45e7`
- [`greenbone-hive/rust-gvm` at the API-pinned `5a43e1e`](https://github.com/greenbone-hive/rust-gvm/tree/5a43e1e90a0645202a79c10d47bef15b6684aeab)

GSA and GSAD are valuable behavioral references, but they are not the
normative GMP specification. Their bridge is tailored to the needs of the GSA
web application and includes presentation and session concerns that do not
belong in a general-purpose REST contract.

## Executive Summary

GMP is a command protocol. A client sends an XML command such as
`<get_targets/>` or `<start_task task_id="..."/>` over an authenticated gvmd
connection and receives an XML response such as `get_targets_response` or
`start_task_response`. The response carries a GMP `status` and `status_text`;
GMP itself has no HTTP method, URL, media type, or HTTP status semantics.

GSA and GSAD put HTTP around this command protocol:

```text
GSA command object
    -> GET or POST /gmp with cmd=<command> and flattened parameters
    -> GSAD validates and dispatches cmd
    -> GSAD constructs GMP XML and authenticates to gvmd
    -> gvmd returns GMP XML
    -> GSAD maps selected failures to HTTP status and adds an XML envelope
    -> GSA parses the XML into JavaScript models
```

This is an HTTP command facade, not a REST API. Almost every operation uses the
same `/gmp` URL, the `cmd` parameter selects behavior, mutations use form data,
and successful bodies remain XML shaped around GMP responses.

`rust-gvm-api` deliberately performs a deeper semantic translation:

```text
HTTP resource or action
    -> REST request DTO and validation
    -> application/domain operation
    -> gvmd port adapter
    -> typed rust-gvm request
    -> GMP XML over an authenticated gvmd connection
    -> typed rust-gvm response
    -> domain model
    -> JSON resource, HTTP status, headers, or Problem Details
```

The key design rule is that the REST surface models GVM resources and
workflows, while `rust-gvm` owns GMP wire construction, parsing, version rules,
and protocol-specific representations.

## 1. GMP as Observed at the gvmd Boundary

### 1.1 Command/response protocol

GMP requests are XML elements named after operations. Read operations commonly
use `get_*`; writes and transitions use verbs such as `create_*`, `modify_*`,
`delete_*`, `start_*`, `stop_*`, and `resume_*`.

Representative exchanges are:

```xml
<get_targets filter="rows=25 first=1" details="1"/>
```

```xml
<get_targets_response status="200" status_text="OK">
  <target id="...">...</target>
</get_targets_response>
```

and:

```xml
<start_task task_id="..."/>
```

```xml
<start_task_response status="202" status_text="OK, request submitted">
  <report_id>...</report_id>
</start_task_response>
```

The exact elements and supported attributes depend on the negotiated GMP/gvmd
version. A leading `2` in the response `status` denotes success in GSAD's GMP
handling. Other values are protocol outcomes that a higher-level adapter must
classify; they are not automatically equivalent to the same-numbered HTTP
status.

### 1.2 Connection and session behavior

Authentication is itself a GMP exchange on a live connection. Commands after
authentication execute in that connection's user context. The protocol is
therefore not naturally equivalent to independent, stateless HTTP requests.

Any HTTP gateway must decide whether to:

- reconnect and authenticate for each HTTP request;
- keep a backend connection bound to a gateway session; or
- support both a persistent session path and request-scoped authentication.

That decision affects serialization, expiry, backpressure, disconnect recovery,
and the cost of each public request.

### 1.3 Protocol data shapes

GMP uses several shapes that need explicit translation:

- UUIDs appear as attributes, element text, or nested resource references.
- Optional update fields can mean omitted, set, clear, or reset; those meanings
  must not collapse accidentally.
- Collections carry filter and count metadata in the XML response.
- Filters are a GMP expression language rather than ordinary URL query
  semantics.
- Some successful operations return only status and an identifier, while
  others return complete resource trees or binary/report content.
- Deletion may mean moving a resource to the trashcan or removing it
  permanently.

These are semantic translation concerns, not merely XML-to-JSON serialization.

## 2. How GSA and GSAD Expose GMP over HTTP

### 2.1 GSA's browser-side abstraction

GSA presents JavaScript command objects such as `gmp.targets`, `gmp.target`,
`gmp.tasks`, and `gmp.task`. The generic collection and entity classes supply
common list, get, clone, delete, export, filter, and aggregate behavior. This is
a useful resource-like programming facade inside GSA.

On the wire, however, GSA's HTTP client sends requests to `/gmp`:

- query parameters on `GET`;
- `FormData` on `POST`;
- `cmd` as the operation selector;
- a session token in the query/form data when present;
- cookies via `withCredentials`; and
- `Authorization: Bearer <jwt>` when JWT mode is active.

The relevant implementation is in GSA's
[`Http`](https://github.com/greenbone/gsa/blob/4ba9551bcd82bc53e22684ab5bb0eacc73419729/src/gmp/http/http.ts),
[`HttpCommand`](https://github.com/greenbone/gsa/blob/4ba9551bcd82bc53e22684ab5bb0eacc73419729/src/gmp/commands/http.ts),
[`EntityCommand`](https://github.com/greenbone/gsa/blob/4ba9551bcd82bc53e22684ab5bb0eacc73419729/src/gmp/commands/entity.ts),
and
[`EntitiesCommand`](https://github.com/greenbone/gsa/blob/4ba9551bcd82bc53e22684ab5bb0eacc73419729/src/gmp/commands/entities.ts).

### 2.2 GSAD's route surface

The reviewed GSAD snapshot exposes these management routes:

- `POST /login`
- `GET /logout`
- `GET /gmp`
- `POST /gmp`
- a separate system-report download route

All other GSA browser routes are static content or client-side routing. The
`/gmp` handlers are selected only by HTTP method; the `cmd` parameter drives the
large command dispatch in `exec_gmp_get` and `exec_gmp_post`. See GSAD's
[`gsad_http_handle_request.c`](https://github.com/greenbone/gsad/blob/b98497f2cad94888b594aa6af1c84719d3c36a03/src/gsad_http_handle_request.c)
and
[`gsad_gmp.c`](https://github.com/greenbone/gsad/blob/b98497f2cad94888b594aa6af1c84719d3c36a03/src/gsad_gmp.c).

GET is used mainly for reads and downloads, while POST is used mainly for
mutations. That separation is useful, but it does not make the interface
resource-oriented: the URL does not identify the target collection or item,
the form/query payload still names the command, and logout is a state-changing
`GET`.

### 2.3 Request transformation

GSA flattens a method call into form or query fields. GSAD validates those
fields and reconstructs the GMP XML. Simple commands can be generated as a
self-closing element with escaped attributes; complex commands are assembled
with nested elements.

For example, a GSA target creation resembles:

```http
POST /gmp
Content-Type: multipart/form-data

cmd=create_target
name=example
hosts=192.0.2.10
port_list_id=<uuid>
alive_tests:=ICMP Ping
```

GSAD translates it into a shape like:

```xml
<create_target>
  <name>example</name>
  <hosts>192.0.2.10</hosts>
  <exclude_hosts></exclude_hosts>
  <port_list id="..."/>
  <alive_tests>
    <alive_test>ICMP Ping</alive_test>
  </alive_tests>
  ...
</create_target>
```

This illustrates why GSA/GSAD field names are not a suitable public REST
schema. Repeated fields such as `alive_tests:`, indexed keys, sentinel values,
and keys such as `bulk_selected:<uuid>` are bridge encodings for nested GMP
data, not stable resource properties.

The concrete target mapping is visible in GSA's
[`target.ts`](https://github.com/greenbone/gsa/blob/4ba9551bcd82bc53e22684ab5bb0eacc73419729/src/gmp/commands/target.ts)
and GSAD's `create_target_gmp` implementation in
[`gsad_gmp.c`](https://github.com/greenbone/gsad/blob/b98497f2cad94888b594aa6af1c84719d3c36a03/src/gsad_gmp.c).

### 2.4 Response transformation

For ordinary reads, GSAD largely preserves the GMP response and places it
inside two wrappers:

```xml
<envelope>
  <client_address>...</client_address>
  <i18n>...</i18n>
  <timezone>...</timezone>
  <token>...</token>
  <version>...</version>
  <get_targets>
    <get_targets_response status="200" status_text="OK">
      ...
    </get_targets_response>
  </get_targets>
</envelope>
```

The outer envelope carries GSAD/session context. The command wrapper lets GSA
locate the enclosed GMP response. GSA then parses the XML and converts response
elements into browser-side models and collection metadata.

Mutation responses are often reduced to an `action_result` containing an
action label, GMP `status_text`, optional details, and an optional created
identifier. Downloads are exceptions and may return binary or raw report
content with a content type and content disposition. The envelope construction
is implemented in GSAD's
[`gsad_http.c`](https://github.com/greenbone/gsad/blob/b98497f2cad94888b594aa6af1c84719d3c36a03/src/gsad_http.c).

### 2.5 Error mapping

GSAD maps selected conditions into HTTP status codes:

- authentication/session failures to `401`;
- a GMP `404` status to HTTP `404`;
- `Permission denied` to HTTP `403`;
- a GMP `503` status to HTTP `503`;
- other unsuccessful GMP responses commonly to HTTP `400`;
- backend connection failures to `500` or `503`.

The body remains an XML envelope, either with an `action_result`, the original
GMP response, or a `gsad_response` message. GSA's XML rejection transform
extracts those messages for UI errors. This mapping is pragmatic but narrower
than a stable, typed REST error taxonomy.

### 2.6 Authentication model

In the default GSAD mode, `POST /login` authenticates against gvmd and creates
GSAD-managed user/session state. GSA subsequently sends both the session cookie
and the returned token. GSAD recovers the stored credentials, opens and
authenticates a gvmd connection for a `/gmp` request, executes the selected
command, and closes the connection after the response.

In JWT mode, the login response returns a JWT and GSA uses it as a bearer token.
GSAD uses that token to authenticate a new gvmd connection for the request. The
mode changes the credential carrier, but `/gmp` remains a command tunnel. The
backend connection and authentication paths are visible in
[`gsad_manager.c`](https://github.com/greenbone/gsad/blob/b98497f2cad94888b594aa6af1c84719d3c36a03/src/gsad_manager.c),
while GSA's browser session handling is in
[`gmp.ts`](https://github.com/greenbone/gsa/blob/4ba9551bcd82bc53e22684ab5bb0eacc73419729/src/gmp/gmp.ts).

### 2.7 What to reuse from GSA/GSAD

GSA and GSAD are useful as:

- a catalog of real UI operations and combinations;
- evidence of the parameters gvmd features require;
- examples of irregular commands, downloads, filters, and version-dependent
  behavior;
- a reference for user-visible model fields; and
- a source of compatibility scenarios and test cases.

They should not be copied as:

- a single `/gmp` endpoint;
- public `cmd` parameters;
- flattened multipart field conventions;
- XML envelopes exposed to clients;
- UI-specific action labels or error messages; or
- a second local implementation of GMP XML construction and parsing.

## 3. The `rust-gvm-api` REST Translation

### 3.1 Boundary placement

The translation is split across explicit layers:

```text
gvm-gateway-rest
  HTTP routes, request/response DTOs, public validation, status and headers
        |
        v
gvm-gateway-app + gvm-gateway-domain
  use cases, resource semantics, session rules, ports, canonical errors
        |
        v
gvm-gateway-gvmd
  domain-to-rust-gvm request mapping and typed response projection
        |
        v
rust-gvm
  GMP requests/responses, XML codecs, protocol versions, transport behavior
        |
        v
gvmd
```

This keeps the public REST contract independent of GSA/GSAD bridge encodings
and prevents GMP wire details from leaking into the gateway's domain or REST
crates. Representative implementation entry points are the
[`REST router`](../crates/gvm-gateway-rest/src/router.rs),
[`target handlers`](../crates/gvm-gateway-rest/src/targets.rs),
[`gvmd target adapter`](../crates/gvm-gateway-gvmd/src/gvmd_adapter/ports/targets.rs),
and
[`session-bound gvmd client`](../crates/gvm-gateway-gvmd/src/gvmd_adapter/session.rs).

### 3.2 Representative mappings

| REST operation | GMP operation | REST result |
| --- | --- | --- |
| `GET /api/v1/targets` | `get_targets` | `200` JSON page with normalized targets and pagination |
| `POST /api/v1/targets` | `create_target` | `201` JSON containing the new ID plus `Location` |
| `GET /api/v1/targets/{id}` | filtered/single `get_targets` | `200` JSON target or `404` Problem Details |
| `PUT /api/v1/targets/{id}` | `modify_target`, then a read-back when needed | `200` JSON representation |
| `DELETE /api/v1/targets/{id}` | `delete_target` with trash/permanent semantics | `204` on success |
| `POST /api/v1/tasks/{id}/start` | `start_task` | `200` JSON action result containing `reportId` |
| `POST /api/v1/reports/{id}/exports` | report retrieval/export operations | `202` plus a pollable job URI |

The table describes translation intent; the OpenAPI files remain authoritative
for exact request fields, responses, and supported operations.

### 3.3 Resource operations and action exceptions

Collections and items use stable paths and normal HTTP methods. A GMP command
verb does not automatically become an action route:

- `create_target` becomes `POST /targets`;
- `modify_target` becomes `PUT /targets/{id}`;
- `delete_target` becomes `DELETE /targets/{id}`; and
- `get_targets` becomes `GET /targets` or `GET /targets/{id}`.

Controller-style state transitions such as starting, stopping, and resuming a
task remain explicit POST actions because there is no clearer stable child
resource. These are bounded exceptions documented in the REST specification,
not a general license to expose GMP command names as URLs.

### 3.4 JSON model translation

The REST request is first validated as a public DTO and converted into a domain
input. The gvmd adapter then maps that input into typed `rust-gvm` values. This
is where protocol distinctions such as entity IDs, collection updates, scalar
set/clear/omitted states, target host sets, and filter pagination are made
explicit.

On the return path, `rust-gvm` parses GMP XML into typed response models. The
gvmd adapter projects those models into the gateway domain, and the REST adapter
serializes domain values into the public JSON representation.

Raw XML must not cross into `rust-gvm-api`. If the required typed request or
response support is absent, it belongs upstream in `rust-gvm`; use
[`rust-gvm-gmp-boundary-issue-template.md`](rust-gvm-gmp-boundary-issue-template.md)
rather than adding a local parser or command string.

### 3.5 HTTP and error semantics

`rust-gvm-api` owns the HTTP interpretation:

- resource-oriented methods and paths;
- `201 Created` and `Location` for resource creation;
- `202 Accepted` and jobs for long-running artifact generation;
- `204 No Content` for successful deletion without a representation;
- media types and JSON naming;
- UUID and request-shape validation;
- RFC 9457 `application/problem+json` errors; and
- stable distinctions among bad input, authentication, authorization, missing
  resources, conflict, backend unavailability, and timeout.

GMP status values are inputs to this classification, not HTTP statuses copied
mechanically. Internal/backend details can be logged while public error bodies
remain bounded and safe.

### 3.6 Session translation

The REST gateway exposes a resource lifecycle for sessions:

- `POST /api/v1/session` authenticates with HTTP Basic credentials and returns
  an opaque bearer token;
- `GET /api/v1/session` inspects the current gateway session; and
- `DELETE /api/v1/session` tears it down.

Unlike GSAD's default per-request gvmd reconnection, a persistent gateway
session owns a live authenticated backend client. Requests sharing that session
are serialized against the client. Idle expiry, explicit deletion, backend
disconnect, queue saturation, and timeouts are gateway lifecycle events with
defined public errors. Protected resource routes may also use request-scoped
Basic authentication, in which case the backend execution context is limited
to that request.

## 4. Why the Translation Is Not One-to-One

A reliable REST facade cannot be generated by renaming GMP commands alone.
Examples include:

- An update can require a second GMP read to return the REST representation.
- A saved-filter ID may require a GMP lookup before the requested list command.
- Pagination compatibility can require a fallback query and local page slice
  when a backend omits usable totals.
- One detailed GMP report tree can be exposed as multiple REST subresources.
- Report generation is represented as an asynchronous REST job even when the
  backend interaction is a blocking GMP exchange.
- A REST field can map to a GMP attribute, nested element, sentinel, or a
  version-specific omission rule.
- A capability absent on the connected gvmd version must become an explicit
  unsupported/not-implemented result, not locally emulated behavior.

Conversely, not every GMP command needs a public REST operation. Public surface
area is a product decision with long-term compatibility and security cost. The
deliberate exclusion of GMP tickets is documented in
[`ticket-surface-scope.md`](ticket-surface-scope.md).

## 5. Translation Ownership Matrix

| Concern | Owner |
| --- | --- |
| Public paths, methods, JSON schemas, HTTP headers and status codes | `gvm-gateway-rest` and `spec/rest-api` |
| Use cases, resource semantics, session invariants and canonical errors | `gvm-gateway-app` / `gvm-gateway-domain` |
| Domain-to-protocol mapping and typed response projection | `gvm-gateway-gvmd` |
| GMP XML construction, parsing, protocol types, version gates and wire normalization | `rust-gvm` |
| Authorization decisions, supported commands and managed resource state | `gvmd` |
| UI workflows and presentation models | GSA; reference only for the reviewed bridge |

The most important negative rule is: `rust-gvm-api` does not become a second
GSAD. It must not grow a command dispatch table that builds XML from HTTP form
fields.

## 6. Checklist for Translating Another GMP Capability

1. Confirm a concrete consumer need; GMP availability alone does not require a
   public endpoint.
2. Decide whether the capability is a collection, item, subresource,
   asynchronous job, or a justified state-transition action.
3. Define externally observable behavior in `spec/rest-api`: method, path,
   parameters, JSON schema, headers, statuses, and error semantics.
4. Define or reuse domain inputs, outputs, errors, and a port operation without
   GMP wire names where a stable domain term exists.
5. Find the typed `rust-gvm` request and response. If either is missing, stop
   and address the gap in `rust-gvm`.
6. Map omitted, clear, default, trash, filter, pagination, and version behavior
   explicitly.
7. Decide whether one GMP exchange is sufficient or whether read-back,
   capability probing, fallback pagination, or job orchestration is required.
8. Map backend failures into the stable domain error taxonomy, then into RFC
   9457 responses; do not expose raw XML or credentials.
9. Test the REST contract, domain/adapter mapping, typed GMP behavior, session
   serialization, and a real-gvmd lifecycle where the operation is mutable or
   version-sensitive.

## 7. Recommendations from the GSA/GSAD Comparison

The current resource-oriented paths, bounded action routes, asynchronous report
export jobs, Problem Details responses, and typed `rust-gvm` boundary are the
right foundation. The comparison does not justify a command tunnel or automatic
endpoint parity with GSA. It does identify the following adjustments and
follow-up work.

| Priority | Recommendation | Primary owner |
| --- | --- | --- |
| 1 | Make partial-update, clear, detach, and reset semantics explicit | `rust-gvm-api`, supported by `rust-gvm` update types |
| 1 | Model actionable command-support states and map unsupported backends consistently | `rust-gvm`, then `rust-gvm-api` |
| 2 | Complete update support for specialized task variants | both repositories |
| 2 | Add delta/comparison report export to the existing export-job workflow | both repositories |
| 2 | Stabilize the collection query and GMP-filter compatibility contract | both repositories |
| 3 | Apply one bounded artifact contract to downloads and future uploads | `rust-gvm-api` |
| Continuous | Maintain an operation disposition ledger and compatibility scenario suite | both repositories |

### 7.1 Make update semantics explicit

GSA and GSAD's save flows show that GMP updates frequently distinguish omitted,
set, clear, detach, and reset-to-default states. They sometimes encode those
states with empty elements or sentinel identifiers. The REST contract must not
collapse those states accidentally.

Many current `PUT` request schemas are sparse updates in which every property is
optional. Some request DTOs also use default empty collections, making an
omitted field indistinguishable from an explicit clear. For example, task
updates cannot detach a schedule through the public JSON shape, and omitted and
empty observer or preference collections do not have a uniform contract.

Before the mutable surface grows further:

- define one JSON rule across resources: omitted means unchanged, a value means
  set or replace, and an explicit `null` or documented empty collection means
  detach or clear;
- prefer `PATCH` for this partial-update behavior before the API becomes stable;
  retain `PUT` only for full replacement or as a documented compatibility alias;
- preserve the distinction in domain inputs instead of converting early to
  `Option<T>` or a default empty collection; and
- carry it into `rust-gvm` with types such as `ScalarUpdate<T>` and
  `CollectionUpdate<T>`, including exact XML tests for every state.

This is more important than matching the names of GSA's save commands: it
prevents a harmless-looking REST omission from clearing backend state.

### 7.2 Complete the specialized-task lifecycle

`POST /api/v1/tasks` and task responses already recognize classic,
agent-group, OCI-image, web-application, and import tasks. `PUT
/api/v1/tasks/{id}`, however, exposes only the classic target, scan-config, and
scanner relationships. GSA and GSAD contain separate save flows for the other
task variants, all implemented as variant-specific `modify_task` payloads.

The REST update shape should therefore accept the relevant relationship and
preference fields for the task's existing variant, while rejecting mixed
selectors and attempts to change a task from one variant to another. Task
responses should also expose a stable variant discriminator; the existing
known relationship fields can remain for compatibility, while future backend
target kinds should not be silently discarded.

The prerequisite in `rust-gvm` is a typed modify-task model that can encode
`agent_group`, `oci_image_target`, and `web_application_target` relationships
plus their variant-specific preferences. Validation must operate on the final
typed request and enforce that fields are valid for that variant. The gateway
can then map the REST discriminator and fields without constructing XML or
reproducing GSAD's sentinel conventions.

### 7.3 Add delta report export to the existing job resource

GSA can render a report relative to another report by passing
`delta_report_id` to `get_reports`. The reviewed GSAD snapshot also exposes the
newer `export_delta_scan_report` command. The current
`POST /api/v1/reports/{id}/exports` job request supports report formats,
report configs, and filters, but it has no comparison-report input. The pinned
`rust-gvm` `GetReportExportOpts` and `ExportScanReportOpts` omit that input and
there is no typed `export_delta_scan_report` request.

Add an optional `deltaReportId` to the existing report-export request rather
than adding an RPC-style route. The resulting resource remains a
`report_export` job and should record both report references. Validate UUIDs,
reject identical report identifiers, enforce access to both reports, and use
the existing job polling, cancellation, retention, and result-download
semantics.

In `rust-gvm`, first add typed support for the `get_reports` delta attribute and
a distinct help-discovery-gated `ExportDeltaScanReportRequest`. Exact request
and response fixtures should cover filters, report formats, report configs,
unknown command discovery, and server failure. `rust-gvm-api` should select the
appropriate typed request according to backend support; it must not assemble a
delta command locally.

### 7.4 Stabilize collection queries and the filter escape hatch

The public `filter` query parameter is the main deliberate GMP-shaped escape
hatch in the REST API. It is useful because GSA demonstrates many real filter,
sort, aggregate, and resource-specific combinations, but it also exposes a
backend expression language whose accepted fields vary by resource and gvmd
version.

Define and test one collection-query contract across endpoints:

- specify how `filterId`, inline `filter`, typed resource selectors, sorting,
  `page`, and `perPage` are combined and which one wins on conflict;
- keep `first`, `rows`, and endpoint-owned scope terms reserved so clients
  cannot override gateway pagination or escape a parent resource;
- reject unknown query parameters instead of silently ignoring misspellings;
- bound filter length and complexity before sending it to gvmd; and
- add common `sortBy` and `sortOrder` parameters, plus high-value typed
  selectors, when they remove the need for clients to embed routine behavior in
  a GMP expression.

Extend `rust-gvm`'s filter composition types to perform the backend-safe
serialization and reserved-term validation shared by callers. Do not implement
a second, divergent GMP filter grammar in the REST handler. The OpenAPI
description should continue to label raw `filter` as an advanced,
backend-dependent compatibility surface rather than implying that every gvmd
filter field is part of the stable REST model.

Generic `get_aggregates` parity is not recommended. Add a resource-specific
analytics endpoint only when a concrete consumer needs a stable metric and
shape; otherwise GSA's aggregate calls remain test and requirements evidence,
not public-contract requirements.

### 7.5 Make capability and server outcomes actionable

Version numbers alone do not describe all observed behavior. Commands may be
version-gated, advertised only through XML help discovery, compiled out, or
present but unauthorized. `rust-gvm` should replace the ambiguous
`supports_command() -> Option<bool>` result with actionable states such as
supported, discovery required, insufficient version, not advertised, and
unknown to the library. This work is tracked in
[`rust-gvm` issue #600](https://github.com/greenbone-hive/rust-gvm/issues/600).

`rust-gvm-api` should explicitly perform and cache required discovery in the
authenticated backend-session context, then map insufficient-version and
not-advertised outcomes to the documented `501 Not Implemented` problem. An
unknown library command indicates an adapter/programming defect and must not be
reported as an ordinary backend capability absence.

Similarly, `rust-gvm` should preserve non-success GMP status and status text as
structured server outcomes for every typed execution path. The gateway remains
the owner of HTTP classification, but it should use one central mapping instead
of endpoint-specific message matching. Tests should cover bad input,
authentication, authorization, missing resources, conflicts, unavailable
backends, and timeouts. This does not require a public capability-discovery
endpoint; callers can rely on the documented operation and its `501` behavior.

### 7.6 Use one bounded artifact contract

GSA/GSAD have several exceptional binary and upload flows: report rendering,
agent installers and support bundles, credential downloads, report imports,
and report-format imports. The existing asynchronous report job and bounded
agent support-bundle endpoint are better patterns than exposing each GMP
download command directly.

Factor their guarantees into a common artifact policy:

- per-artifact and aggregate storage limits, with limits enforced before an
  unbounded in-memory buffer is accepted;
- allowlisted or normalized media types and sanitized attachment filenames;
- authenticated ownership, authorization checks, expiry, cancellation, and
  cleanup;
- bounded upload media types and sizes for any future import workflow; and
- streaming or disk-backed spooling when the maximum artifact is too large for
  predictable in-memory handling.

Future report and report-format imports should be modeled as bounded resources
or jobs with these rules. Credential private-material export should remain
omitted unless a concrete product requirement and a stricter secret-delivery
contract justify it.

### 7.7 Convert the reference catalog into governance and tests

Maintain a disposition ledger for the GSA/GSAD operation catalog and the public
typed `rust-gvm` surface. Each operation should be classified as exposed,
mapped to another REST workflow, internal, upstream-blocked, deferred, or
deliberately omitted. A new GSA operation or public typed request should require
a disposition, not necessarily a new endpoint. The broader parity ledger is
tracked in
[`rust-gvm-api` issue #381](https://github.com/greenbone-hive/rust-gvm-api/issues/381).

For every accepted mapping, derive tests at the layer that owns the behavior:

- exact XML request/response and version/help gates in `rust-gvm`;
- domain projection, filter composition, and error mapping in the gvmd adapter;
- OpenAPI and HTTP contract tests in the REST adapter; and
- representative real-gvmd lifecycles for mutable, version-sensitive, upload,
  and download workflows.

The scenario set should include unknown future enum values and optional model
fields, missing or inconsistent collection counts, saved filters with their own
pagination or sorting, explicit clear/detach updates, permission failures,
binary metadata, oversized artifacts, and backend disconnects. This reuses the
most valuable part of GSA/GSAD—their accumulated compatibility knowledge—without
making their bridge the public contract.

## 8. Related Documentation

- [`gateway-architecture.md`](gateway-architecture.md) defines the authoritative
  repository layering and session ownership.
- [`gmp-api-proxy-analysis.md`](gmp-api-proxy-analysis.md) explains why the
  gateway exists and how REST, gRPC, and MCP fit as peer adapters.
- [`spec/rest-api/openspec.md`](../spec/rest-api/openspec.md) defines REST design
  constraints, including resource modeling and bounded action routes.
- [`rust-gvm-gmp-boundary-issue-template.md`](rust-gvm-gmp-boundary-issue-template.md)
  defines the escalation path for missing typed GMP support.
