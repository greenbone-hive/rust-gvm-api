// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{
    CredentialStore, IdentityOwner, IdentityResourceMeta, ReportOperatingSystemSummary, User,
};

#[test]
fn report_operating_system_summary_deserializes_the_live_gvmd_shape() {
    // The compose E2E harness must model the purpose-shaped OS row directly;
    // requiring generic summary fields would allow the #527 empty-object
    // regression to escape live coverage.
    let operating_system: ReportOperatingSystemSummary = serde_json::from_value(json!({
        "bestOsCpe": "cpe:/o:debian:debian_linux:12",
        "bestOsText": "Debian GNU/Linux 12 (bookworm)",
        "hostsCount": 2
    }))
    .expect("live report operating-system row should deserialize");

    assert_eq!(
        operating_system.best_os_cpe.as_deref(),
        Some("cpe:/o:debian:debian_linux:12")
    );
    assert_eq!(
        operating_system.best_os_text.as_deref(),
        Some("Debian GNU/Linux 12 (bookworm)")
    );
    assert_eq!(operating_system.hosts_count, Some(2));
}

#[test]
fn identity_meta_deserializes_name_only_owner_shape() {
    // Regression coverage for PR #463 live E2E: identity owner payloads are
    // purpose-shaped and may expose only the backend-provided owner name.
    let user: User = serde_json::from_value(json!({
        "id": "f6342b5f-2223-42c9-826d-54e1108073c3",
        "name": "admin",
        "owner": { "name": "" },
        "creationTime": "2026-08-28T22:58:20Z",
        "modificationTime": "2026-08-28T22:58:20Z",
        "writable": true,
        "inUse": false,
        "roles": [{ "id": "7a8cb5b4-b74d-11e2-8187-406186ea4fc5", "name": "Admin" }],
        "groups": [],
        "hostsAllow": false,
        "hosts": "",
        "authenticationType": "file"
    }))
    .expect("user response should deserialize with a name-only owner");

    assert_eq!(user.meta.id, "f6342b5f-2223-42c9-826d-54e1108073c3");
    assert_eq!(
        user.meta.owner.as_ref().map(|owner| owner.name.as_str()),
        Some("")
    );
}

#[test]
fn identity_owner_remains_distinct_from_generic_resource_refs() {
    // This test locks the E2E harness boundary to the public identity-owner
    // schema so future changes do not quietly revert to requiring owner ids.
    let owner: IdentityOwner =
        serde_json::from_value(json!({ "name": "admin" })).expect("owner should deserialize");

    assert_eq!(owner.name, "admin");
    let meta: IdentityResourceMeta = serde_json::from_value(json!({
        "id": "99447d0c-5ae4-419a-896f-335fc18509da",
        "name": "nightly-identity-group",
        "comment": "created by compose-backed E2E identity/admin coverage",
        "owner": { "name": "admin" },
        "creationTime": "2026-08-28T22:59:56Z",
        "modificationTime": "2026-08-28T22:59:56Z",
        "writable": true,
        "inUse": false
    }))
    .expect("identity metadata should deserialize without owner ids");

    assert_eq!(
        meta.owner.as_ref().map(|value| value.name.as_str()),
        Some("admin")
    );
}

#[test]
fn credential_store_deserializes_optional_capability_fields() {
    // Credential stores are purpose-shaped supporting resources. Live gvmd
    // responses may omit id/default/writable when the typed backend surface
    // does not expose those values, and the harness must not require them.
    let store: CredentialStore = serde_json::from_value(json!({
        "name": "CyberArk",
        "provider": "cyberark"
    }))
    .expect("credential store should deserialize with optional fields omitted");

    assert_eq!(store.id, None);
    assert_eq!(store.name, "CyberArk");
    assert_eq!(store.provider.as_deref(), Some("cyberark"));
    assert_eq!(store.default, None);
    assert_eq!(store.writable, None);
}
