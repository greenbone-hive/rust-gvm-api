// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Credential domain types and commands.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{hide_optional_value, Pagination};

/// Domain credential representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Credential {
    /// Credential identifier.
    pub id: String,
    /// Credential name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional type code.
    #[serde(rename = "type")]
    pub credential_type: Option<String>,
    /// Optional login value.
    pub login: Option<String>,
    /// Whether the credential is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the credential is writable.
    pub writable: bool,
}

/// Paginated credential list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialPage {
    /// Page items.
    pub data: Vec<Credential>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Backend credential store available for new credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialStore {
    /// Stable backend identifier.
    pub id: Option<String>,
    /// Human-friendly store name.
    pub name: String,
    /// Optional provider label.
    pub provider: Option<String>,
    /// Whether this is the default store for new credentials.
    pub default: Option<bool>,
    /// Whether clients may write to this store.
    pub writable: Option<bool>,
}

/// Write-only credential-store preference update.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialStorePreferenceInput {
    /// Preference name.
    pub name: String,
    /// Preference value. Never returned by the public API or debug output.
    pub value: String,
}

impl fmt::Debug for CredentialStorePreferenceInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialStorePreferenceInput")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Credential-store update command.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ModifyCredentialStoreInput {
    /// Whether the store is active.
    pub active: Option<bool>,
    /// Backend host.
    pub host: Option<String>,
    /// Backend path.
    pub path: Option<String>,
    /// Backend port.
    pub port: Option<u16>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Write-only preference updates.
    pub preferences: Vec<CredentialStorePreferenceInput>,
}

impl fmt::Debug for ModifyCredentialStoreInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModifyCredentialStoreInput")
            .field("active", &self.active)
            .field("host", &self.host)
            .field("path", &self.path)
            .field("port", &self.port)
            .field("comment", &self.comment)
            .field("preferences", &self.preferences)
            .finish()
    }
}

/// Credential list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CredentialQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Credential create command.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct CreateCredentialInput {
    /// Credential name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Credential type code.
    pub credential_type: String,
    /// Optional login value.
    pub login: Option<String>,
    /// Optional password value.
    pub password: Option<String>,
    /// Optional private key.
    pub private_key: Option<String>,
    /// Optional certificate data.
    pub certificate: Option<String>,
    /// Optional SNMP community.
    pub community: Option<String>,
    /// Optional SNMP auth algorithm.
    pub auth_algorithm: Option<String>,
    /// Optional SNMP privacy algorithm.
    pub privacy_algorithm: Option<String>,
    /// Optional SNMP privacy password.
    pub privacy_password: Option<String>,
    /// Optional credential-store identifier for store-backed credentials.
    pub credential_store_id: Option<String>,
    /// Optional external vault identifier for store-backed credentials.
    pub vault_id: Option<String>,
    /// Optional external host identifier for store-backed credentials.
    pub host_identifier: Option<String>,
}

/// Credential update command.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ModifyCredentialInput {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional login value.
    pub login: Option<String>,
    /// Optional password value.
    pub password: Option<String>,
    /// Optional private key.
    pub private_key: Option<String>,
    /// Optional certificate data.
    pub certificate: Option<String>,
    /// Optional SNMP community.
    pub community: Option<String>,
    /// Optional SNMP auth algorithm.
    pub auth_algorithm: Option<String>,
    /// Optional SNMP privacy algorithm.
    pub privacy_algorithm: Option<String>,
    /// Optional SNMP privacy password.
    pub privacy_password: Option<String>,
    /// Optional credential-store identifier for store-backed credentials.
    pub credential_store_id: Option<String>,
    /// Optional external vault identifier for store-backed credentials.
    pub vault_id: Option<String>,
    /// Optional external host identifier for store-backed credentials.
    pub host_identifier: Option<String>,
}

impl fmt::Debug for CreateCredentialInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateCredentialInput")
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("credential_type", &self.credential_type)
            .field("login", &self.login)
            .field("password", &hide_optional_value(&self.password))
            .field("private_key", &hide_optional_value(&self.private_key))
            .field("certificate", &self.certificate)
            .field("community", &hide_optional_value(&self.community))
            .field("auth_algorithm", &self.auth_algorithm)
            .field("privacy_algorithm", &self.privacy_algorithm)
            .field(
                "privacy_password",
                &hide_optional_value(&self.privacy_password),
            )
            .field("credential_store_id", &self.credential_store_id)
            .field("vault_id", &hide_optional_value(&self.vault_id))
            .field(
                "host_identifier",
                &hide_optional_value(&self.host_identifier),
            )
            .finish()
    }
}

impl fmt::Debug for ModifyCredentialInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModifyCredentialInput")
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("login", &self.login)
            .field("password", &hide_optional_value(&self.password))
            .field("private_key", &hide_optional_value(&self.private_key))
            .field("certificate", &self.certificate)
            .field("community", &hide_optional_value(&self.community))
            .field("auth_algorithm", &self.auth_algorithm)
            .field("privacy_algorithm", &self.privacy_algorithm)
            .field(
                "privacy_password",
                &hide_optional_value(&self.privacy_password),
            )
            .field("credential_store_id", &self.credential_store_id)
            .field("vault_id", &hide_optional_value(&self.vault_id))
            .field(
                "host_identifier",
                &hide_optional_value(&self.host_identifier),
            )
            .finish()
    }
}
