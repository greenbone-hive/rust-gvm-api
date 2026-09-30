# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | ✅ Current |

We support the latest minor release with security patches. Once a new minor or major version is published, prior versions receive patches only for critical vulnerabilities at maintainer discretion.

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Instead, use **GitHub Private Vulnerability Reporting**:

1. Go to the [Security Advisories](https://github.com/greenbone-hive/rust-gvm-api/security/advisories) tab
2. Click **"Report a vulnerability"**
3. Fill in the details — affected crate(s), reproduction steps, and impact assessment

### What to expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Patch timeline** depends on severity:
  - **Critical / High**: Target fix within 7 days
  - **Medium**: Target fix within 30 days
  - **Low**: Next scheduled release
- We will coordinate disclosure timing with you. We follow [responsible disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure) practices.

### What qualifies

- Authentication/authorization bypass in REST or gRPC APIs
- Credential exposure in API responses, logs, or headers
- Injection vulnerabilities (SQL, XML, command)
- Improper input validation leading to resource exhaustion (DoS)
- TLS/transport layer vulnerabilities
- Dependency vulnerabilities with a viable attack path through our code

### What doesn't qualify

- Issues in upstream dependencies without a demonstrated attack path through rust-gvm-api
- Rate limiting or brute-force concerns (expected to be handled by deployment infrastructure)

## Security Measures

### Dependency Auditing

- **[cargo-audit](https://github.com/rustsec/rustsec)** runs on relevant protected-branch pushes and pull requests, merge queues, manual dispatch, and the weekly Security schedule
- **[cargo-deny](https://github.com/EmbarkStudios/cargo-deny)** enforces license compliance, bans, and source restrictions (see [`deny.toml`](deny.toml))
- **[Dependabot](https://docs.github.com/en/code-security/dependabot)** monitors Cargo and GitHub Actions dependencies with weekly update PRs
- **[cargo-machete](https://github.com/bnjbvr/cargo-machete)** checks for unused dependencies in CI
- **[cargo-vet](https://mozilla.github.io/cargo-vet/)** requires committed review evidence for the complete locked, all-feature dependency graph
- **Cargo Geiger** produces per-package machine-readable reports; a separate gate rejects unsafe Rust in every explicitly inventoried first-party workspace member
- **CycloneDX SBOM quality** is checked for every workspace member and blocks if any `sbomqs` score is below 8.3
- **Semgrep** runs directly from an immutable container digest and uploads normalized SARIF

Contributor procedures for Vet evidence, pinned SBOM tooling, the workspace
inventory, and reviewed unsafe-policy exceptions are documented in
[`docs/WORKFLOW_SECURITY.md`](docs/WORKFLOW_SECURITY.md).

### Code Quality

- `cargo clippy` with `-D warnings` in CI
- `#[deny(unsafe_code)]` — no unsafe blocks in any crate, reinforced by the independent workspace-inventory/Geiger gate
- MSRV tested (currently Rust 1.88.0)
- SBOM (CycloneDX) generated for releases and continuously quality-gated by Security

## Changelog

| Date | Change |
|------|--------|
| 2026-03-20 | Initial security policy |
| 2026-09-30 | Added blocking Vet, SBOM quality, Geiger evidence, explicit workspace unsafe-code policy, deterministic tool pins, and protected `main`/`next` coverage |
