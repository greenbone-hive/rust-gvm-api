# rust-gvm upstream surface dispositions

This document records deliberate product-surface decisions while the `next`
branch adopts canonical typed requests from `rust-gvm`. Upstream request
availability does not by itself authorize a REST route, domain port, or OpenAPI
operation. Issue #381 remains the owning inventory for omitted or deferred GMP
surface.

| Upstream family | Downstream disposition | Existing supported distinction |
| --- | --- | --- |
| Report-configuration list, detail, create, clone, modify, and delete | Omitted under #381; no administration REST surface is planned in this migration. | `reportConfigId` remains an optional, validated selector on synchronous and job-backed report export. |
| Report-format create/import, clone, modify, delete, and verify | Omitted or deferred under #381; canonical upstream mutation requests do not authorize new administration routes. | Existing report-format list/detail and report export selection remain supported. |
| TLS-certificate create/import, clone, modify, and delete | Omitted under #381; this migration does not add certificate administration or transport TLS/mTLS controls. | Existing global TLS-certificate list/detail and report-scoped projections remain supported. |
