# rust-gvm-api User Documentation

This package is the release-aligned user documentation for `rust-gvm-api`.

`rust-gvm-api` provides a REST API for gvmd through GMP. It is intended to make
integration with gvmd easier, including automated management of targets,
schedules, and tasks, as well as access to scan results and reports.

## Contents

- [Installation and configuration](./usage.md)
- [Workflow examples](./examples.md)
- [Technology Preview API migration notes](./migration.md)
- Example config files:
  - [package-config.example.toml](./package-config.example.toml)
  - [container-config.example.toml](./container-config.example.toml)
- OpenAPI specification for this release:
  - [openapi.yaml](./api/rest/openapi.yaml)

## Version alignment

Use the documentation package that shipped with the same release version as the
gateway you are running.
