// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, ensure, Context, Result};
use gvm_gateway_e2e::harness::{
    CreatedResource, CredentialStore, CredentialStoreCapability, CredentialStoreFixture,
    E2eHarness, NvtCatalogEntry, ScanConfig, ScanConfigFamilySelection, ScanConfigPreference,
    SessionResponse, SetScanConfigFamilySelection, SetScanConfigNvtSelection,
    SetScanConfigPreference, StoreBackedCredentialRequest,
};

const UNSUPPORTED_FIXTURE_UUID: &str = "57500000-0000-4000-8000-000000000575";

// Qualifies the public scan-config selection/preference mutation contract against
// real gvmd data while confining every change to a disposable copied config.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_scan_config_live_mutations_replace_read_back_restore_and_delete() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut scan_config_id = None;

    let run = async {
        let fixture = discover_scan_config_fixture(&harness, &session.token).await?;
        let name = harness.unique_name("issue-575-scan-config");
        let created = harness
            .create_scan_config_from_base(
                &session.token,
                &name,
                "disposable issue #575 live mutation qualification",
                &fixture.base.id,
            )
            .await?;
        scan_config_id = Some(created.id.clone());
        require_created_location(&created, "/api/v1/scan-configs")?;

        let copied = harness.get_scan_config(&session.token, &created.id).await?;
        ensure!(copied.name == name, "copied scan-config name drifted");
        let snapshot = harness
            .list_all_scan_config_nvts(&session.token, &created.id, None)
            .await?;
        require_oid_sets_equal(
            "copied scan config did not preserve the base selection",
            &snapshot,
            &fixture.selected_nvts,
        )?;
        let copied_preference = read_scan_config_preference(
            &harness,
            &session.token,
            &created.id,
            &fixture.preference.name,
            fixture.preference_nvt_oid.as_deref(),
        )
        .await?;
        ensure!(
            copied_preference == fixture.preference,
            "copied scan config did not preserve the preference snapshot"
        );

        harness
            .set_scan_config_family_selection(
                &session.token,
                &created.id,
                &SetScanConfigFamilySelection {
                    families: vec![ScanConfigFamilySelection {
                        name: fixture.family.clone(),
                        growing: false,
                        all: true,
                    }],
                    auto_add_new_families: false,
                },
            )
            .await?;
        let family_replacement = harness
            .list_all_scan_config_nvts(&session.token, &created.id, None)
            .await?;
        require_oid_sets_equal(
            "family-selection replacement was not persisted by gvmd",
            &family_replacement,
            &fixture.feed_family_nvts,
        )?;

        harness
            .set_scan_config_nvt_selection(
                &session.token,
                &created.id,
                &fixture.family,
                vec![fixture.selected_nvt.oid.clone()],
            )
            .await?;
        let nvt_replacement = harness
            .list_all_scan_config_nvts(&session.token, &created.id, Some(&fixture.family))
            .await?;
        ensure!(
            nvt_replacement
                .iter()
                .map(|nvt| nvt.oid.as_str())
                .collect::<Vec<_>>()
                == vec![fixture.selected_nvt.oid.as_str()],
            "per-family NVT replacement was not persisted by gvmd"
        );

        exercise_preference_mutation(&harness, &session.token, &created.id, &fixture).await?;
        restore_scan_config_selection(&harness, &session.token, &created.id, &snapshot).await?;
        let restored = harness
            .list_all_scan_config_nvts(&session.token, &created.id, None)
            .await?;
        require_oid_sets_equal(
            "observable scan-config selection was not restored",
            &restored,
            &snapshot,
        )?;

        harness
            .delete_scan_config_permanently(&session.token, &created.id)
            .await?;
        require_scan_config_absent(&harness, &session.token, &created.id).await?;
        scan_config_id = None;
        Ok(())
    }
    .await;

    if let Some(id) = scan_config_id.as_deref() {
        if let Err(error) = harness
            .delete_scan_config_permanently(&session.token, id)
            .await
        {
            eprintln!("best-effort disposable scan-config cleanup failed: {error:#}");
        }
    }
    finish_session(&harness, &session, run).await
}

// Qualifies both sides of the credential-store capability contract. A supported
// backend must receive explicit safe fixture inputs; unsupported backends must
// reject every store-specific workflow consistently without breaking credentials.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_credential_store_live_mutations_follow_capability_matrix() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut credential_id = None;
    let mut store_restore = None;

    let run = async {
        match harness
            .probe_credential_store_capability(&session.token)
            .await?
        {
            CredentialStoreCapability::Unsupported => {
                let request = unsupported_store_credential_request();
                harness
                    .assert_credential_store_unsupported_matrix(
                        &session.token,
                        UNSUPPORTED_FIXTURE_UUID,
                        &request,
                    )
                    .await?;
                let credentials = harness.list_credentials(&session.token).await?;
                ensure!(
                    credentials.pagination.page == 1,
                    "ordinary credential listing returned an invalid first page"
                );
                eprintln!("credential-store capability branch: exact HTTP 501 not_implemented");
            }
            CredentialStoreCapability::Supported(stores) => {
                let fixture = CredentialStoreFixture::from_env()?;
                let store = select_stable_store(&stores, fixture.preferred_store_id.as_deref())?;
                let store_id = store.id.as_deref().context(
                    "selected credential store did not expose the stable id required by item routes",
                )?;
                let fetched = harness
                    .get_credential_store(&session.token, store_id)
                    .await?;
                require_same_store_metadata("credential-store get", store, &fetched)?;

                store_restore = Some((store_id.to_string(), fixture.restore_comment.clone()));
                let mutation_comment = harness.unique_name("issue-575-store-update");
                let updated = harness
                    .update_credential_store_comment(
                        &session.token,
                        store_id,
                        &mutation_comment,
                    )
                    .await?;
                let update_readback = harness
                    .get_credential_store(&session.token, store_id)
                    .await?;
                require_same_store_metadata("credential-store update response", store, &updated)?;
                require_same_store_metadata(
                    "credential-store update readback",
                    &updated,
                    &update_readback,
                )?;

                harness
                    .update_credential_store_comment(
                        &session.token,
                        store_id,
                        &fixture.restore_comment,
                    )
                    .await?;
                let restored = harness
                    .get_credential_store(&session.token, store_id)
                    .await?;
                require_same_store_metadata(
                    "credential-store restore readback",
                    store,
                    &restored,
                )?;
                store_restore = None;

                harness
                    .verify_credential_store(&session.token, store_id)
                    .await?;

                let credential_name = harness.unique_name("issue-575-store-credential");
                let request = StoreBackedCredentialRequest {
                    name: credential_name.clone(),
                    comment: "disposable issue #575 store-backed credential".to_string(),
                    credential_type: fixture.credential_type.clone(),
                    credential_store_id: store_id.to_string(),
                    vault_id: fixture.vault_id.clone(),
                    host_identifier: fixture.host_identifier.clone(),
                };
                let created = harness
                    .create_store_backed_credential(&session.token, &request)
                    .await?;
                credential_id = Some(created.id.clone());
                require_created_location(&created, "/api/v1/credentials")?;
                let credential = harness
                    .get_credential(&session.token, &created.id)
                    .await?;
                ensure!(credential.id == created.id, "credential id drifted on readback");
                ensure!(
                    credential.name == credential_name,
                    "credential name drifted on readback"
                );
                ensure!(
                    credential.credential_type.as_deref()
                        == Some(fixture.credential_type.as_str()),
                    "store-backed credential type drifted on readback"
                );

                harness
                    .delete_credential_permanently(&session.token, &created.id)
                    .await?;
                require_credential_absent(&harness, &session.token, &created.id).await?;
                credential_id = None;
                eprintln!("credential-store capability branch: supported");
            }
        }
        Ok(())
    }
    .await;

    if let Some(id) = credential_id.as_deref() {
        if let Err(error) = harness
            .delete_credential_permanently(&session.token, id)
            .await
        {
            eprintln!("best-effort store-backed credential cleanup failed: {error:#}");
        }
    }
    if let Some((store_id, restore_comment)) = store_restore.as_ref() {
        if let Err(error) = harness
            .update_credential_store_comment(&session.token, store_id, restore_comment)
            .await
        {
            eprintln!("best-effort credential-store state restoration failed: {error:#}");
        }
    }
    finish_session(&harness, &session, run).await
}

#[derive(Clone, Debug)]
struct ScanConfigFixture {
    base: ScanConfig,
    selected_nvts: Vec<NvtCatalogEntry>,
    family: String,
    selected_nvt: NvtCatalogEntry,
    feed_family_nvts: Vec<NvtCatalogEntry>,
    preference: ScanConfigPreference,
    preference_nvt_oid: Option<String>,
    preference_mutation: String,
}

async fn discover_scan_config_fixture(
    harness: &E2eHarness,
    token: &str,
) -> Result<ScanConfigFixture> {
    let feed_families = harness
        .list_nvt_families(token)
        .await?
        .data
        .into_iter()
        .map(|family| family.name)
        .collect::<BTreeSet<_>>();
    let scan_configs = harness.list_scan_configs(token).await?;
    // Fresh gvmd stacks expose feed-owned bases as read-only. The copy route
    // accepts those bases and creates the writable disposable config that this
    // test mutates, so base writability is not a valid discovery requirement.
    let candidates = scan_configs.into_iter().filter(|config| {
        config
            .usage_type
            .as_deref()
            .is_none_or(|value| value == "scan")
    });

    for base in candidates {
        let selected_nvts = harness
            .list_all_scan_config_nvts(token, &base.id, None)
            .await?;
        if selected_nvts.is_empty()
            || selected_nvts.iter().any(|nvt| {
                nvt.family
                    .as_ref()
                    .is_none_or(|family| !feed_families.contains(family))
            })
        {
            continue;
        }

        if let Some((preference, mutation)) = find_mutable_preference(
            harness
                .list_scan_config_preferences(token, &base.id, None)
                .await?,
        ) {
            let selected_nvt = selected_nvts[0].clone();
            let family = selected_nvt
                .family
                .clone()
                .context("selected feed NVT did not expose its family")?;
            let feed_family_nvts = harness
                .list_all_feed_nvts_for_family(token, &family)
                .await?;
            if !feed_family_nvts.is_empty() {
                return Ok(ScanConfigFixture {
                    base,
                    selected_nvts,
                    family,
                    selected_nvt,
                    feed_family_nvts,
                    preference,
                    preference_nvt_oid: None,
                    preference_mutation: mutation,
                });
            }
        }

        // Scanner preferences are fetched first because a broad config can
        // select tens of thousands of NVTs. The bounded fallback still finds
        // a representative feed preference without making the live gate
        // proportional to the full feed size.
        for selected_nvt in selected_nvts.clone().into_iter().take(256) {
            let family = selected_nvt
                .family
                .as_ref()
                .context("selected feed NVT did not expose its family")?;
            if let Some((preference, mutation)) = find_mutable_preference(
                harness
                    .list_scan_config_preferences(token, &base.id, Some(&selected_nvt.oid))
                    .await?,
            ) {
                let feed_family_nvts = harness.list_all_feed_nvts_for_family(token, family).await?;
                if !feed_family_nvts.is_empty() {
                    let preference_nvt_oid = selected_nvt.oid.clone();
                    return Ok(ScanConfigFixture {
                        base,
                        selected_nvts,
                        family: family.clone(),
                        selected_nvt,
                        feed_family_nvts,
                        preference,
                        preference_nvt_oid: Some(preference_nvt_oid),
                        preference_mutation: mutation,
                    });
                }
            }
        }
    }

    bail!(
        "no scan-config base exposed a restorable feed-backed selection and a safely mutable preference"
    )
}

fn find_mutable_preference(
    preferences: Vec<ScanConfigPreference>,
) -> Option<(ScanConfigPreference, String)> {
    preferences.into_iter().find_map(|preference| {
        let mutation = derive_preference_mutation(&preference)?;
        Some((preference, mutation))
    })
}

fn derive_preference_mutation(preference: &ScanConfigPreference) -> Option<String> {
    let current = preference.value.as_deref()?;
    if preference
        .preference_type
        .as_deref()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("password"))
    {
        return None;
    }

    if let Some(alternative) = preference.alternatives.iter().find(|alternative| {
        alternative.as_str() != current
            && preference.default.as_deref() != Some(alternative.as_str())
    }) {
        return Some(alternative.clone());
    }

    let candidate = match current {
        "0" => "1".to_string(),
        "1" => "0".to_string(),
        _ => current
            .parse::<i64>()
            .ok()
            .and_then(|value| value.checked_add(1))
            .map(|value| value.to_string())?,
    };
    (candidate != current && preference.default.as_deref() != Some(candidate.as_str()))
        .then_some(candidate)
}

async fn exercise_preference_mutation(
    harness: &E2eHarness,
    token: &str,
    scan_config_id: &str,
    fixture: &ScanConfigFixture,
) -> Result<()> {
    let nvt_oid = fixture.preference_nvt_oid.as_deref();
    let original = fixture
        .preference
        .value
        .as_deref()
        .context("selected preference lost its snapshot value")?;
    harness
        .set_scan_config_preference(
            token,
            scan_config_id,
            &fixture.preference.name,
            nvt_oid,
            Some(&fixture.preference_mutation),
        )
        .await?;
    let mutated = read_scan_config_preference(
        harness,
        token,
        scan_config_id,
        &fixture.preference.name,
        nvt_oid,
    )
    .await?;
    ensure!(
        mutated.value.as_deref() == Some(fixture.preference_mutation.as_str()),
        "preference mutation was not persisted by gvmd"
    );

    harness
        .set_scan_config_preference(
            token,
            scan_config_id,
            &fixture.preference.name,
            nvt_oid,
            None,
        )
        .await?;
    let reset = read_scan_config_preference(
        harness,
        token,
        scan_config_id,
        &fixture.preference.name,
        nvt_oid,
    )
    .await?;
    ensure!(
        reset.value.as_deref() != Some(fixture.preference_mutation.as_str()),
        "preference reset retained the explicitly mutated value"
    );

    harness
        .set_scan_config_preference(
            token,
            scan_config_id,
            &fixture.preference.name,
            nvt_oid,
            Some(original),
        )
        .await?;
    let restored = read_scan_config_preference(
        harness,
        token,
        scan_config_id,
        &fixture.preference.name,
        nvt_oid,
    )
    .await?;
    ensure!(
        restored.value.as_deref() == Some(original),
        "preference snapshot was not restored"
    );
    Ok(())
}

async fn read_scan_config_preference(
    harness: &E2eHarness,
    token: &str,
    scan_config_id: &str,
    name: &str,
    nvt_oid: Option<&str>,
) -> Result<ScanConfigPreference> {
    harness
        .list_scan_config_preferences(token, scan_config_id, nvt_oid)
        .await?
        .into_iter()
        .find(|preference| preference.name == name)
        .with_context(|| format!("scan-config preference {name} disappeared from readback"))
}

async fn restore_scan_config_selection(
    harness: &E2eHarness,
    token: &str,
    scan_config_id: &str,
    snapshot: &[NvtCatalogEntry],
) -> Result<()> {
    let mut families = BTreeMap::<String, Vec<String>>::new();
    for nvt in snapshot {
        let family = nvt
            .family
            .as_ref()
            .with_context(|| format!("selected NVT {} did not expose its family", nvt.oid))?;
        families
            .entry(family.clone())
            .or_default()
            .push(nvt.oid.clone());
    }
    harness
        .set_scan_config_family_selection(
            token,
            scan_config_id,
            &SetScanConfigFamilySelection {
                families: families
                    .keys()
                    .map(|name| ScanConfigFamilySelection {
                        name: name.clone(),
                        growing: false,
                        all: false,
                    })
                    .collect(),
                auto_add_new_families: false,
            },
        )
        .await?;
    for (family, nvt_oids) in families {
        harness
            .set_scan_config_nvt_selection(token, scan_config_id, &family, nvt_oids)
            .await?;
    }
    Ok(())
}

fn select_stable_store<'a>(
    stores: &'a [CredentialStore],
    preferred_id: Option<&str>,
) -> Result<&'a CredentialStore> {
    if let Some(preferred_id) = preferred_id {
        if !is_uuid_shaped(preferred_id) {
            bail!("configured credential-store id must be a UUID accepted by item routes");
        }
        return stores
            .iter()
            .find(|store| {
                store.id.as_deref() == Some(preferred_id) && store.writable != Some(false)
            })
            .context(
                "configured credential-store id was not returned as a writable store by the capability probe",
            );
    }
    stores
        .iter()
        .find(|store| {
            store.writable != Some(false)
                && store
                    .id
                    .as_deref()
                    .is_some_and(is_uuid_shaped)
        })
        .context(
            "credential-store capability is supported but no writable store with a stable UUID id was returned; set GVM_GATEWAY_E2E_CREDENTIAL_STORE_ID",
        )
}

fn is_uuid_shaped(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn unsupported_store_credential_request() -> StoreBackedCredentialRequest {
    StoreBackedCredentialRequest {
        name: "issue-575-unsupported-capability-probe".to_string(),
        comment: "syntactically valid unsupported-capability probe".to_string(),
        credential_type: "cs_up".to_string(),
        credential_store_id: UNSUPPORTED_FIXTURE_UUID.to_string(),
        vault_id: "redacted-probe-vault-reference".to_string(),
        host_identifier: "redacted-probe-host-reference".to_string(),
    }
}

fn require_same_store_metadata(
    action: &str,
    expected: &CredentialStore,
    actual: &CredentialStore,
) -> Result<()> {
    if let Some(expected_id) = expected.id.as_deref() {
        ensure!(
            actual.id.as_deref() == Some(expected_id),
            "{action}: id drifted"
        );
    }
    ensure!(actual.name == expected.name, "{action}: name drifted");
    ensure!(
        actual.provider == expected.provider,
        "{action}: provider drifted"
    );
    ensure!(
        actual.default == expected.default,
        "{action}: default drifted"
    );
    ensure!(
        actual.writable == expected.writable,
        "{action}: writable drifted"
    );
    Ok(())
}

fn require_oid_sets_equal(
    message: &str,
    actual: &[NvtCatalogEntry],
    expected: &[NvtCatalogEntry],
) -> Result<()> {
    let actual = actual
        .iter()
        .map(|nvt| nvt.oid.as_str())
        .collect::<BTreeSet<_>>();
    let expected = expected
        .iter()
        .map(|nvt| nvt.oid.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(actual == expected, "{message}");
    Ok(())
}

async fn require_scan_config_absent(harness: &E2eHarness, token: &str, id: &str) -> Result<()> {
    let configs = harness.list_scan_configs(token).await?;
    ensure!(
        configs.iter().all(|config| config.id != id),
        "permanently deleted scan config remained visible"
    );
    Ok(())
}

async fn require_credential_absent(harness: &E2eHarness, token: &str, id: &str) -> Result<()> {
    let credentials = harness.list_credentials(token).await?;
    ensure!(
        credentials
            .data
            .iter()
            .all(|credential| credential.id != id),
        "permanently deleted credential remained visible"
    );
    Ok(())
}

fn require_created_location(created: &CreatedResource, collection: &str) -> Result<()> {
    ensure!(
        created
            .location
            .ends_with(&format!("{collection}/{}", created.id)),
        "created resource Location did not identify the returned resource"
    );
    Ok(())
}

#[test]
fn live_mutation_requests_use_public_camel_case_shapes_and_redact_external_references() {
    // The live suite sends these DTOs directly. This locks their public JSON
    // shape and ensures failures cannot reveal vault/host fixture references.
    let family = SetScanConfigFamilySelection {
        families: vec![ScanConfigFamilySelection {
            name: "feed family".to_string(),
            growing: false,
            all: true,
        }],
        auto_add_new_families: false,
    };
    assert_eq!(
        serde_json::to_value(family).expect("family selection should serialize"),
        serde_json::json!({
            "families": [{"name": "feed family", "growing": false, "all": true}],
            "autoAddNewFamilies": false
        })
    );
    assert_eq!(
        serde_json::to_value(SetScanConfigNvtSelection {
            nvt_oids: vec!["1.3.6.1.4.1.25623.1.0.1".to_string()],
        })
        .expect("NVT selection should serialize"),
        serde_json::json!({"nvtOids": ["1.3.6.1.4.1.25623.1.0.1"]})
    );
    assert_eq!(
        serde_json::to_value(SetScanConfigPreference {
            nvt_oid: Some("1.3.6.1.4.1.25623.1.0.1".to_string()),
            value: None,
        })
        .expect("preference reset should serialize"),
        serde_json::json!({"nvtOid": "1.3.6.1.4.1.25623.1.0.1"})
    );

    let credential = StoreBackedCredentialRequest {
        name: "fixture".to_string(),
        comment: "fixture".to_string(),
        credential_type: "cs_up".to_string(),
        credential_store_id: UNSUPPORTED_FIXTURE_UUID.to_string(),
        vault_id: "vault-value-must-not-leak".to_string(),
        host_identifier: "host-value-must-not-leak".to_string(),
    };
    let debug = format!("{credential:?}");
    assert!(!debug.contains("vault-value-must-not-leak"));
    assert!(!debug.contains("host-value-must-not-leak"));
    assert_eq!(debug.matches("<redacted>").count(), 2);

    let fixture = CredentialStoreFixture {
        preferred_store_id: None,
        vault_id: "fixture-vault-value".to_string(),
        host_identifier: "fixture-host-value".to_string(),
        credential_type: "cs_up".to_string(),
        restore_comment: "fixture-restore-value".to_string(),
    };
    let fixture_debug = format!("{fixture:?}");
    for secret in [
        "fixture-vault-value",
        "fixture-host-value",
        "fixture-restore-value",
    ] {
        assert!(!fixture_debug.contains(secret));
    }
}

#[test]
fn stable_store_selection_honors_fixture_id_and_rejects_unaddressable_entries() {
    // Supported live qualification must use a concrete UUID item route, never
    // silently pick an omitted or display-only backend identifier.
    let stable_id = "57500000-0000-4000-8000-000000000001";
    let stores = vec![
        CredentialStore {
            id: None,
            name: "no id".to_string(),
            provider: None,
            default: None,
            writable: Some(true),
        },
        CredentialStore {
            id: Some("display-only".to_string()),
            name: "not addressable".to_string(),
            provider: None,
            default: None,
            writable: Some(true),
        },
        CredentialStore {
            id: Some(stable_id.to_string()),
            name: "stable".to_string(),
            provider: None,
            default: Some(true),
            writable: Some(true),
        },
    ];
    assert_eq!(
        select_stable_store(&stores, None)
            .expect("stable store should be selected")
            .id
            .as_deref(),
        Some(stable_id)
    );
    assert_eq!(
        select_stable_store(&stores, Some(stable_id))
            .expect("configured store should be selected")
            .name,
        "stable"
    );
    assert!(select_stable_store(&stores[..2], None).is_err());
}

#[test]
fn preference_mutation_prefers_alternatives_and_derives_safe_entry_values() {
    let mut preference = ScanConfigPreference {
        nvt: None,
        name: "fixture".to_string(),
        id: None,
        preference_type: Some("entry".to_string()),
        value: Some("5".to_string()),
        alternatives: Vec::new(),
        default: Some("5".to_string()),
    };
    assert_eq!(
        derive_preference_mutation(&preference).as_deref(),
        Some("6")
    );

    preference.alternatives = vec!["5".to_string(), "10".to_string()];
    assert_eq!(
        derive_preference_mutation(&preference).as_deref(),
        Some("10")
    );

    preference.preference_type = Some("password".to_string());
    assert!(derive_preference_mutation(&preference).is_none());

    preference.preference_type = Some("entry".to_string());
    preference.value = Some("80,443".to_string());
    preference.alternatives.clear();
    assert!(derive_preference_mutation(&preference).is_none());
}

async fn ready_session() -> Result<(E2eHarness, SessionResponse)> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;
    let session = harness.create_session().await?;
    eprintln!(
        "created session; gmpVersion={} expiresIn={}s",
        session.gmp_version, session.expires_in
    );
    Ok((harness, session))
}

async fn finish_session(
    harness: &E2eHarness,
    session: &SessionResponse,
    run: Result<()>,
) -> Result<()> {
    if let Err(error) = harness.delete_session(&session.token).await {
        eprintln!("best-effort session cleanup failed: {error:#}");
    }
    run
}
