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
| NVT preference and scan-config NVT/family selection mutations | Deferred to #523; canonical read migration does not authorize new endpoints or alter the existing mutation contract. | Existing NVT, NVT-family, scan-config NVT, preference, and selection routes keep their current REST/OpenAPI surface. |
| Generic SecInfo dispatch and observed-vulnerability detail | Omitted under #381; the gateway keeps the existing specialized CVE, CPE, CERT-Bund, DFN-CERT, and vulnerability list/detail disposition and does not expose the upstream generic command as a new endpoint. | SecInfo identifiers remain opaque strings, and existing list filters, pagination, conversions, and error mapping remain supported. |
