# `next` Development Branch

The long-lived `next` branch is the downstream integration lane for
[rust-gvm-api issue #457](https://github.com/greenbone-hive/rust-gvm-api/issues/457)
and the typed request/associated-response work owned by
[rust-gvm issue #523](https://github.com/greenbone-hive/rust-gvm/issues/523).

## Branch roles

- `main` remains the release integration branch and continues to use reviewed,
  explicitly pinned rust-gvm revisions.
- `next` consumes the paired rust-gvm `next` branch and carries incremental
  gvmd-adapter adoption without changing REST, OpenAPI, application, or domain
  contracts merely for the migration.
- Short-lived migration branches target `next` through pull requests.
- Unrelated endpoint, bug-fix, and release work continues to target `main`.
- The pre-existing `devel` branch is a separate legacy lane and is not part of
  the #457/#523 migration.

## Dependency and integration rules

The workspace manifests select the rust-gvm `next` branch. `Cargo.lock` records
the exact resolved commit so every build remains reproducible. Refreshing that
lock after rust-gvm `next` advances is an explicit, reviewed integration change.

- Require `CI`, `Security`, and `REST Discovery Scan E2E (next)` for changes to
  this branch.
- Rebase short-lived branches onto the latest `next` before pushing them for
  review; do not rewrite the shared `next` branch.
- Bring applicable `main` changes into `next` through a reviewed synchronization
  pull request.
- Keep raw GMP execution where the upstream typed contract is incomplete, and
  report focused gaps upstream instead of changing the gateway boundary.
- Move mature work to `main` through bounded reviewed pull requests rather than
  merging the entire development branch.

## Intentional contract changes

Issue [#500](https://github.com/greenbone-hive/rust-gvm-api/issues/500) removes
the Technology Preview GMP ticket discovery endpoints from `next`. The REST and
OpenAPI surface therefore contains neither `/api/v1/tickets` nor
`/api/v1/tickets/{id}`. Direct GMP consumers remain unaffected because ticket
support in `greenbone-hive/rust-gvm` is unchanged.
