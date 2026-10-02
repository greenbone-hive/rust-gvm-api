# rust-gvm-api User Documentation

This package is the release-aligned user documentation for `rust-gvm-api`.

`rust-gvm-api` provides a REST API for gvmd through GMP. It is intended to make
integration with gvmd easier, including automated management of targets,
schedules, and tasks, as well as access to scan results and reports.

## Contents

- [Installation and configuration](./usage.md)
- [REST API reference](./api-reference.md)
- [Workflow examples](./examples.md)
- [Technology Preview API migration notes](./migration.md)
- Example config files in the release archive:
  - `package-config.example.toml`
  - `container-config.example.toml`
- Curated OpenAPI specification for this release (contract-tested against the
  runtime-generated `/api/v1/openapi.json` document):
  - `api/rest/openapi.yaml`

## Version alignment

Use the documentation package that shipped with the same release version as the
gateway you are running. Its OpenAPI `info.version` matches the gateway's
`apiVersion`.

For interactive documentation from the running service, open
`/api/v1/docs`. For machine-readable schemas, use
`/api/v1/openapi.json` or the release package's `api/rest/openapi.yaml`.
