// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{
    credential_json_body_error, CreateCredentialRequest, CredentialResponse,
    CredentialStorePreferenceRequest, CredentialStoreResponse, CredentialType,
    ModifyCredentialRequest, ModifyCredentialStoreRequest,
};
use crate::handler::ValidateInto;
use gvm_gateway_domain::{Credential, CredentialStore, GatewayError, ModifyCredentialStoreInput};

fn credential_with_type(credential_type: &str) -> Credential {
    Credential {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Credential".to_string(),
        comment: None,
        credential_type: Some(credential_type.to_string()),
        login: Some("user".to_string()),
        in_use: false,
        writable: true,
    }
}

#[test]
fn credential_type_deserialization_preserves_unknown_values() {
    // Backend-added credential types must survive deserialization instead
    // of being rejected by the open-enum wrapper.
    let parsed: CredentialType =
        serde_json::from_value(json!("future_credential")).expect("type should parse");

    assert_eq!(
        serde_json::to_value(parsed).unwrap(),
        json!("future_credential")
    );
}

#[test]
fn credential_response_preserves_known_and_unknown_types() {
    // Response conversion should expose both known rust-gvm type values and
    // future backend values without collapsing the public `type` field.
    let known = serde_json::to_value(CredentialResponse::from(credential_with_type("up")))
        .expect("credential response should serialize");
    let unknown = serde_json::to_value(CredentialResponse::from(credential_with_type(
        "future_credential",
    )))
    .expect("credential response should serialize");

    assert_eq!(known["type"], json!("up"));
    assert_eq!(unknown["type"], json!("future_credential"));
}

#[test]
fn credential_request_debug_redacts_secrets() {
    // Request DTOs carry write-only credential secrets; debug output must
    // only expose their presence, never their submitted values.
    let create = CreateCredentialRequest {
        name: "Credential".to_string(),
        comment: Some("visible comment".to_string()),
        credential_type: serde_json::from_value(json!("snmpv3"))
            .expect("known credential type should parse"),
        login: Some("visible-login".to_string()),
        password: Some("create-password-secret".to_string()),
        private_key: Some("create-private-key-secret".to_string()),
        certificate: Some("public-certificate".to_string()),
        community: Some("create-community-secret".to_string()),
        auth_algorithm: Some("sha1".to_string()),
        privacy_algorithm: Some("aes".to_string()),
        privacy_password: Some("create-privacy-secret".to_string()),
        credential_store_id: None,
        vault_id: Some("create-vault-secret".to_string()),
        host_identifier: Some("create-host-secret".to_string()),
    };
    let modify = ModifyCredentialRequest {
        name: Some("Credential".to_string()),
        comment: Some("visible comment".to_string()),
        login: Some("visible-login".to_string()),
        password: Some("modify-password-secret".to_string()),
        private_key: Some("modify-private-key-secret".to_string()),
        certificate: Some("public-certificate".to_string()),
        community: Some("modify-community-secret".to_string()),
        auth_algorithm: Some("sha1".to_string()),
        privacy_algorithm: Some("aes".to_string()),
        privacy_password: Some("modify-privacy-secret".to_string()),
        credential_store_id: None,
        vault_id: Some("modify-vault-secret".to_string()),
        host_identifier: Some("modify-host-secret".to_string()),
    };

    let debug = format!("{create:?}\n{modify:?}");

    assert!(debug.contains("visible-login"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("create-password-secret"));
    assert!(!debug.contains("create-private-key-secret"));
    assert!(!debug.contains("create-community-secret"));
    assert!(!debug.contains("create-privacy-secret"));
    assert!(!debug.contains("create-vault-secret"));
    assert!(!debug.contains("create-host-secret"));
    assert!(!debug.contains("modify-password-secret"));
    assert!(!debug.contains("modify-private-key-secret"));
    assert!(!debug.contains("modify-community-secret"));
    assert!(!debug.contains("modify-privacy-secret"));
    assert!(!debug.contains("modify-vault-secret"));
    assert!(!debug.contains("modify-host-secret"));
}

#[test]
fn credential_json_parse_error_detail_omits_submitted_values() {
    // Credential parse failures become client-visible problem details, so
    // the detail string must not reuse serde's value-bearing error text.
    let error = serde_json::from_value::<CreateCredentialRequest>(json!({
        "name": "Credential",
        "type": "up",
        "password": 123456789,
        "privateKey": 987654321,
        "community": 111222333,
        "privacyPassword": 444555666
    }))
    .expect_err("numeric secret fields should fail string deserialization");

    let GatewayError::InvalidInput(detail) = credential_json_body_error(error) else {
        panic!("credential parse errors should map to invalid input");
    };

    assert!(detail.starts_with("invalid JSON body at line "));
    assert!(!detail.contains("123456789"));
    assert!(!detail.contains("987654321"));
    assert!(!detail.contains("111222333"));
    assert!(!detail.contains("444555666"));
}

#[test]
fn credential_requests_preserve_supported_secret_and_type_fields() {
    // Regression coverage for #403: REST credential requests must keep the
    // supported secret-bearing fields and public type values for the typed
    // gvmd adapter instead of rejecting or collapsing them locally.
    let create = CreateCredentialRequest {
        name: "Credential".to_string(),
        comment: None,
        credential_type: serde_json::from_value(json!("snmpv3"))
            .expect("known credential type should parse"),
        login: Some("snmp-user".to_string()),
        password: Some("auth-secret".to_string()),
        private_key: Some("PRIVATE KEY".to_string()),
        certificate: Some("CERTIFICATE".to_string()),
        community: Some("public".to_string()),
        auth_algorithm: Some("sha1".to_string()),
        privacy_algorithm: Some("aes".to_string()),
        privacy_password: Some("privacy-secret".to_string()),
        credential_store_id: None,
        vault_id: None,
        host_identifier: None,
    }
    .validate()
    .expect("credential create request should preserve supported secrets");
    let modify = ModifyCredentialRequest {
        name: Some("Renamed Credential".to_string()),
        comment: None,
        login: Some("snmp-user".to_string()),
        password: Some("auth-secret".to_string()),
        private_key: Some("PRIVATE KEY".to_string()),
        certificate: Some("CERTIFICATE".to_string()),
        community: Some("public".to_string()),
        auth_algorithm: Some("sha1".to_string()),
        privacy_algorithm: Some("aes".to_string()),
        privacy_password: Some("privacy-secret".to_string()),
        credential_store_id: None,
        vault_id: None,
        host_identifier: None,
    }
    .validate();

    assert_eq!(create.credential_type, "snmpv3");
    assert_eq!(create.private_key.as_deref(), Some("PRIVATE KEY"));
    assert_eq!(create.certificate.as_deref(), Some("CERTIFICATE"));
    assert_eq!(create.community.as_deref(), Some("public"));
    assert_eq!(create.privacy_password.as_deref(), Some("privacy-secret"));
    assert_eq!(modify.name.as_deref(), Some("Renamed Credential"));
    assert_eq!(modify.private_key.as_deref(), Some("PRIVATE KEY"));
    assert_eq!(modify.certificate.as_deref(), Some("CERTIFICATE"));
    assert_eq!(modify.community.as_deref(), Some("public"));
    assert_eq!(modify.privacy_password.as_deref(), Some("privacy-secret"));
}

#[test]
fn credential_store_response_omits_unknown_backend_metadata() {
    // Backends before the typed credential-store surface only expose the
    // fields they actually return; the REST DTO must not synthesize defaults.
    let value = serde_json::to_value(CredentialStoreResponse::from(CredentialStore {
        id: None,
        name: "Vault".to_string(),
        provider: Some("hashicorp".to_string()),
        default: None,
        writable: None,
    }))
    .expect("credential store response should serialize");

    assert_eq!(value["name"], "Vault");
    assert_eq!(value["provider"], "hashicorp");
    assert!(value.get("id").is_none());
    assert!(value.get("default").is_none());
    assert!(value.get("writable").is_none());
}

#[test]
fn store_backed_credential_create_requires_vault_references_and_rejects_local_secrets() {
    let accepted: CreateCredentialRequest = serde_json::from_value(json!({
        "name": "Vault credential",
        "type": "cs_up",
        "credentialStoreId": "123e4567-e89b-12d3-a456-426614174000",
        "vaultId": "secret/data/service",
        "hostIdentifier": "production"
    }))
    .expect("store-backed request should deserialize");
    let input = accepted
        .validate()
        .expect("complete vault references should validate");
    assert_eq!(input.credential_type, "cs_up");
    assert_eq!(input.vault_id.as_deref(), Some("secret/data/service"));

    let mixed: CreateCredentialRequest = serde_json::from_value(json!({
        "name": "Unsafe mixed credential",
        "type": "cs_up",
        "vaultId": "secret/data/service",
        "hostIdentifier": "production",
        "password": "must-not-be-forwarded"
    }))
    .expect("mixed request should deserialize before semantic validation");
    assert!(matches!(
        mixed.validate(),
        Err(GatewayError::InvalidInput(_))
    ));
}

#[test]
fn credential_store_preference_debug_and_domain_input_redact_values() {
    let request = ModifyCredentialStoreRequest {
        active: Some(true),
        host: Some("vault.internal".to_string()),
        path: Some("/v1".to_string()),
        port: Some(8200),
        comment: Some("Vault".to_string()),
        preferences: vec![CredentialStorePreferenceRequest {
            name: "token".to_string(),
            value: "preference-secret".to_string(),
        }],
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains("preference-secret"));

    let input: ModifyCredentialStoreInput = request
        .validate_into()
        .expect("bounded preference should validate");
    let debug = format!("{input:?}");
    assert!(!debug.contains("preference-secret"));
    assert_eq!(input.preferences[0].name, "token");
}
