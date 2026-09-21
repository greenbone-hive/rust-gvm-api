# `next` Development Branch

The long-lived `next` branch is the downstream integration lane for
[rust-gvm-api issue #457](https://github.com/greenbone-hive/rust-gvm-api/issues/457)
and the typed request/associated-response work owned by
[rust-gvm issue #523](https://github.com/greenbone-hive/rust-gvm/issues/523).

## Branch roles

- `main` remains the release integration branch and continues to use reviewed,
  explicitly pinned rust-gvm revisions.
- `next` consumes reviewed, exact rust-gvm revisions and carries incremental
  gvmd-adapter adoption without changing REST, OpenAPI, application, or domain
  contracts merely for the migration.
- Short-lived migration branches target `next` through pull requests.
- Unrelated endpoint, bug-fix, and release work continues to target `main`.
- The pre-existing `devel` branch is a separate legacy lane and is not part of
  the #457/#523 migration.

## Dependency and integration rules

The workspace manifest and `Cargo.lock` pin all five rust-gvm crates to one exact
reviewed commit so every build remains reproducible. Refreshing that revision is
an explicit, atomic integration change.

Issue [#512](https://github.com/greenbone-hive/rust-gvm-api/issues/512) sets the
canonical complete-request baseline to rust-gvm commit
`ebfdb93dab53f1748d68df5d4e831d89fbf2b71d`, the merge of rust-gvm PR #644.
This is the last reviewed slice before result canonicalization. Follow-up issue
[#513](https://github.com/greenbone-hive/rust-gvm-api/issues/513) must start from
this exact five-crate baseline and advance the result family in upstream order.

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
