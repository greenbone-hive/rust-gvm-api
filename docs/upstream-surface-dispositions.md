# rust-gvm upstream surface dispositions

This document records the deliberate product-surface decisions completed while
`main` adopted canonical typed requests from `rust-gvm`. Upstream request
availability does not by itself authorize a REST route, domain port, or OpenAPI
operation. Completed issue #381 is the closure record for the v0.7.0 baseline;
new upstream methods require a new, explicit disposition review.

Issue #588 accepts rust-gvm v0.8.0. All five workspace dependencies use that
immutable release tag, which resolves to revision
`f20a01f7297060f02b6f577bba7261cacb585fc3`. The tag, resolved revision,
fixture, and method ledger are coupled fail-closed by the architecture guard.

The complete method-level closure record is the machine-readable
[`upstream-surface-dispositions.tsv`](upstream-surface-dispositions.tsv). It
classifies every public async method in the pinned `rust-gvm` typed facade as
exactly one of `exposed`, `mapped`, `internal`, `blocked`, `deferred`, or
`omitted`, with a review rationale and repository evidence. The offline drift
guard reconciles that ledger against the checked-in
[`rust-gvm-v0.8.0-typed-facade.tsv`](../crates/gvm-gateway-gvmd/tests/fixtures/rust-gvm-v0.8.0-typed-facade.tsv)
snapshot at the accepted release and the workspace's immutable dependency tag.
This table remains the family-level product narrative; the TSV is the
exhaustive per-method source of truth.

Disposition meanings are deliberately closed:

- `exposed`: a public REST operation directly represents the upstream method;
- `mapped`: another documented REST workflow or mode represents it;
- `internal`: the gateway uses the capability without exposing raw GMP
  semantics;
- `blocked`: exposure requires missing typed upstream support;
- `deferred`: a future contract needs separate product or security review; and
- `omitted`: the operation is deliberately outside the gateway surface.

| Upstream family | Downstream disposition | Existing supported distinction |
| --- | --- | --- |
| Agent integration configuration | Deferred under #381/#401; integration endpoints and mutable connection details need an explicit ownership and secret-handling contract. | Existing agent, agent-group, installer-instruction, support-bundle, and synchronization routes remain supported. |
| Alert clone, test, and trigger controller commands | Omitted under #381; the bounded alert resource exposes list, detail, create, update, and delete without adding controller-style actions. | Existing alert CRUD behavior remains unchanged. |
| Report import: `ImportReportRequest` / `import_report` | Adopted by #570 as bounded `POST /reports` collection creation. The body is opaque outside rust-gvm, limited to 10 MiB while reading, and allowlisted to `application/xml`. | Existing import-task creation supplies the required task relationship; optional `inAssets` preserves omission versus explicit `false`, and success returns the canonical report readback location. |
| Report-export lifecycle: `export_scan_report`, `get_report_exports`, `download_report_export`, and `cancel_report_export` | Adopted internally by the existing asynchronous REST report-export job contract. The worker retains the opaque backend export ID, polls typed lifecycle states with bounded timing, downloads into the existing in-memory artifact model, and reconciles active backend cancellation for job and session cancellation. Terminal exports remain subject to gvmd retention. | Existing `/reports/{id}/exports`, `/jobs/{id}`, and `/jobs/{id}/result` paths remain unchanged. |
| Audit/scan-specific report reads and export helpers, including `export_audit_report`, `export_delta_audit_report`, and `export_delta_scan_report` | Existing type-neutral reads and supported export selection map to report resources and the asynchronous job workflow. The three new audit/delta helpers are omitted because no existing public contract selects those specialized operations. | Report IDs use the existing `/reports/{id}` family; this layer adds no audit-specific or delta-export route. |
| Report-configuration list, detail, create, clone, modify, and delete | Omitted under #381; no administration REST surface is planned in this migration. | `reportConfigId` remains an optional, validated selector on synchronous and job-backed report export. |
| Report-format create/import, clone, modify, delete, and verify | Omitted or deferred under #381; canonical upstream mutation requests do not authorize new administration routes. | Existing report-format list/detail and report export selection remain supported. |
| TLS-certificate create/import, clone, modify, and delete | Omitted under #381; this migration does not add certificate administration or transport TLS/mTLS controls. | Existing global TLS-certificate list/detail and report-scoped projections remain supported. |
| NVT and result projections | The release's optional catalog-NVT `discovery` flag and source-shaped result-NVT `type_metadata` string are adopted additively on existing resources. | `discovery` and `typeMetadata` are optional and omitted when gvmd does not provide them; `typeMetadata` is not parsed or narrowed by the gateway. |
| NVT preference and scan-config NVT/family selection mutations | Adopted through completed #523 using canonical typed requests; the migration added no routes and did not alter the existing public contract. | Existing NVT, NVT-family, scan-config NVT, preference, and selection routes keep their current REST/OpenAPI surface. |
| Generic SecInfo dispatch and observed-vulnerability detail | Omitted under #381; the gateway keeps the existing specialized CVE, CPE, CERT-Bund, DFN-CERT, and vulnerability list/detail disposition and does not expose the upstream generic command as a new endpoint. Additional detailed NVT `tech_info.description_md` and the `web_application_vt` subtype remain unconsumed with that generic get-info surface. | SecInfo identifiers remain opaque strings, and existing list filters, pagination, conversions, and error mapping remain supported. |
| Agent support-bundle encryption selector | Adopted as the optional `encryption` query on the existing support-bundle download route. | Omission, explicit `false`, and explicit `true` remain distinct through REST, domain, and the typed request; no new route is added. |
| System discovery additions: public settings, aggregates, features, license, help/schema, resource-name lookup, system reports, feed-sync, auth-description, and related administrative operations | Omitted or internal/deferred under #381/#401; issue #528 consumes canonical typed support only for existing version, authentication, timezone, and feed reads and adds no routes. | The existing read-only system-discovery surface remains limited to public version fallback, authenticated backend timezone discovery, and filtered feed status. Canonical optional feed access metadata maps missing values to `false` so the established required REST booleans remain non-null. |
| Current-user settings: `GetUserSettingsRequest`, `GetUserSettingRequest`, and `ModifyUserSettingRequest` | Adopted by #529 for the existing #381 current-user settings surface; this is not generic global-setting administration. | Existing `GET /user-settings`, `GET /user-settings/{id}`, and `PUT /user-settings/{id}` routes remain unchanged. `POST` and `DELETE` stay omitted. |
| Authentication configuration: `DescribeAuthRequest` and `ModifyAuthRequest` | Internal/deferred under #401. Authentication-configuration discovery and mutation require a separately reviewed administration and secret-handling contract. | Session authentication and existing user authentication-type fields remain supported; no auth-configuration route is added. |
| License administration: `GetLicenseRequest` and `ModifyLicenseRequest` | Omitted under #381/#401. License content and replacement/clear operations are appliance administration, not part of the current gateway resource surface. | Existing version and feed-status discovery remain supported; no license route is added. |
| Global settings administration: `GetSettingsRequest` and `ModifySettingRequest` | Omitted under #381/#401. Global settings must not be confused with the authenticated principal's existing user-setting resources. | Only the three current-user setting operations listed above are public. |
| Wizard execution: `RunWizardRequest` | Omitted under #381. Wizard execution is an open-ended controller command with confidential parameters and needs an explicit product/API design before exposure. | Existing concrete task, target, and scan-config workflows remain supported; no wizard action route is added. |
| Trash cleanup and recovery: `EmptyTrashcanRequest` and `RestoreRequest` | Deferred under #381. Bulk permanent cleanup and cross-resource restoration need resource-specific authorization, destructive-operation, and HTTP-semantics review. | Existing resource-specific delete behavior remains unchanged; no trashcan or restore route is added. |
| Scanner administration: `CreateScannerRequest`, `CloneScannerRequest`, `ModifyScannerRequest`, `DeleteScannerRequest`, and `VerifyScannerRequest` | Deferred under #401. Connection credentials, verification side effects, and appliance ownership require a dedicated administration contract. | Existing scanner list/detail and agent installer-instruction reads remain supported; scanner mutation/action routes stay absent. |
| Removed #664 compatibility surfaces: `ModifyLicenseWithOptsRequest`, `RunWizardWithOptsRequest`, `RestoreFromTrashcanRequest`, the former user-setting option bags, and their free builders/facade forwarding forms | Omitted as upstream cleanup artifacts, not downstream operations. Their canonical replacements inherit the explicit adopted, omitted, internal, or deferred dispositions above. | No compatibility endpoint, local GMP builder, or alias is introduced. |
