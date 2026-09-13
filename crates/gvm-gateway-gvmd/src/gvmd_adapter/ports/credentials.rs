// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;
use crate::gvmd_adapter::session::CredentialStoreCapability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::gvmd_adapter) struct CredentialStoreProbeOutcome {
    pub(in crate::gvmd_adapter) capability: CredentialStoreCapability,
    pub(in crate::gvmd_adapter) requires_reconnect: bool,
}

#[async_trait]
impl CredentialPort for GvmdAdapter {
    async fn list_credential_stores(
        &self,
        session_token: &str,
    ) -> Result<Vec<CredentialStore>, GatewayError> {
        let client = self.session_client(session_token)?;
        if client.credential_store_capability() == CredentialStoreCapability::Unsupported {
            return Err(unsupported_credential_store_error());
        }

        let mut guard = client.lock().await?;
        let parsed = match guard.get_credential_stores().await {
            Ok(parsed) => parsed,
            Err(error) if credential_store_capability_unavailable(&error) => {
                return Err(unsupported_credential_store_error());
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
        drop(guard);

        Ok(parsed
            .items
            .into_iter()
            .map(credential_store_from_gmp)
            .collect())
    }

    async fn get_credential_store(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<CredentialStore, GatewayError> {
        let client = self.session_client(session_token)?;
        ensure_credential_stores_supported(&client)?;
        let mut guard = client.lock().await?;
        let parsed = guard
            .get_credential_store(&parse_entity_id(id)?, Some(true))
            .await
            .map_err(map_credential_store_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(credential_store_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("credential store {id} not found")))
    }

    async fn modify_credential_store(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyCredentialStoreInput,
    ) -> Result<CredentialStore, GatewayError> {
        let client = self.session_client(session_token)?;
        ensure_credential_stores_supported(&client)?;
        let response = client
            .lock()
            .await?
            .call(modify_credential_store(
                &parse_entity_id(id)?,
                ModifyCredentialStoreOpts {
                    active: input.active,
                    host: input.host,
                    path: input.path,
                    port: input.port,
                    comment: input.comment,
                    preferences: input
                        .preferences
                        .into_iter()
                        .map(|preference| CredentialStorePreference {
                            name: preference.name,
                            value: preference.value,
                        })
                        .collect(),
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_credential_store(session_token, id).await
    }

    async fn verify_credential_store(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        ensure_credential_stores_supported(&client)?;
        client
            .lock()
            .await?
            .verify_credential_store(&parse_entity_id(id)?)
            .await
            .map_err(map_credential_store_error)?;
        Ok(())
    }

    async fn list_credentials(
        &self,
        session_token: &str,
        query: &CredentialQuery,
    ) -> Result<CredentialPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_credentials(GetCredentialsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetCredentialsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(credential_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(CredentialPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_credential(
        &self,
        session_token: &str,
        input: CreateCredentialInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let store_type = parse_credential_store_type(&input.credential_type);
        if store_type.is_none()
            && (input.credential_store_id.is_some()
                || input.vault_id.is_some()
                || input.host_identifier.is_some())
        {
            return Err(GatewayError::InvalidInput(
                "credential-store fields require a credential type with the `cs_` prefix"
                    .to_string(),
            ));
        }
        if let Some(credential_type) = store_type {
            ensure_credential_stores_supported(&client)?;
            ensure_no_local_secret_fields(
                input.login.as_ref(),
                input.password.as_ref(),
                input.private_key.as_ref(),
                input.certificate.as_ref(),
                input.community.as_ref(),
                input.auth_algorithm.as_ref(),
                input.privacy_algorithm.as_ref(),
                input.privacy_password.as_ref(),
            )?;
            let vault_id = input.vault_id.as_deref().ok_or_else(|| {
                GatewayError::InvalidInput(
                    "vaultId is required for a credential-store-backed credential".to_string(),
                )
            })?;
            let host_identifier = input.host_identifier.as_deref().ok_or_else(|| {
                GatewayError::InvalidInput(
                    "hostIdentifier is required for a credential-store-backed credential"
                        .to_string(),
                )
            })?;
            let response = client
                .lock()
                .await?
                .call(create_credential_store_credential(
                    &input.name,
                    credential_type,
                    vault_id,
                    host_identifier,
                    CredentialStoreCredentialOpts {
                        comment: input.comment,
                        credential_store_id: input
                            .credential_store_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                    },
                ))
                .await
                .map_err(map_gvm_error)?;
            let parsed =
                CreateCredentialResponse::from_response(&response).map_err(map_parse_error)?;
            return Ok(parsed.id.to_string());
        }
        let response = client
            .lock()
            .await?
            .call(create_credential(
                &input.name,
                CredentialOpts {
                    comment: input.comment,
                    credential_type: Some(parse_credential_type(&input.credential_type)?),
                    login: input.login,
                    password: input.password,
                    private_key: input.private_key,
                    key_phrase: None,
                    public_key: None,
                    certificate: input.certificate,
                    community: input.community,
                    auth_algorithm: input
                        .auth_algorithm
                        .as_deref()
                        .map(parse_snmp_auth_algorithm)
                        .transpose()?,
                    privacy_password: input.privacy_password,
                    privacy_algorithm: input
                        .privacy_algorithm
                        .as_deref()
                        .map(parse_snmp_privacy_algorithm)
                        .transpose()?,
                    allow_insecure: None,
                    kdc: None,
                    kdcs: vec![],
                    realm: None,
                    ..Default::default()
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateCredentialResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_credential(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Credential, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_credential(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetCredentialsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(credential_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("credential {id} not found")))
    }

    async fn modify_credential(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyCredentialInput,
    ) -> Result<Credential, GatewayError> {
        let client = self.session_client(session_token)?;
        let modifies_store_reference = input.credential_store_id.is_some()
            || input.vault_id.is_some()
            || input.host_identifier.is_some();
        if modifies_store_reference {
            ensure_credential_stores_supported(&client)?;
            ensure_no_local_secret_fields(
                input.login.as_ref(),
                input.password.as_ref(),
                input.private_key.as_ref(),
                input.certificate.as_ref(),
                input.community.as_ref(),
                input.auth_algorithm.as_ref(),
                input.privacy_algorithm.as_ref(),
                input.privacy_password.as_ref(),
            )?;
            let response = client
                .lock()
                .await?
                .call(modify_credential_store_credential(
                    &parse_entity_id(id)?,
                    ModifyCredentialStoreCredentialOpts {
                        name: input.name,
                        comment: input.comment,
                        credential_store_id: input
                            .credential_store_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        vault_id: input.vault_id,
                        host_identifier: input.host_identifier,
                    },
                ))
                .await
                .map_err(map_gvm_error)?;
            let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
            drop(client);
            return self.get_credential(session_token, id).await;
        }
        let response = client
            .lock()
            .await?
            .call(modify_credential(
                &parse_entity_id(id)?,
                ModifyCredentialOpts {
                    name: input.name,
                    comment: input.comment,
                    login: input.login,
                    password: input.password,
                    private_key: input.private_key,
                    key_phrase: None,
                    public_key: None,
                    certificate: input.certificate,
                    community: input.community,
                    auth_algorithm: input
                        .auth_algorithm
                        .as_deref()
                        .map(parse_snmp_auth_algorithm)
                        .transpose()?,
                    privacy_password: input.privacy_password,
                    privacy_algorithm: input
                        .privacy_algorithm
                        .as_deref()
                        .map(parse_snmp_privacy_algorithm)
                        .transpose()?,
                    allow_insecure: None,
                    kdc: None,
                    kdcs: vec![],
                    realm: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_credential(session_token, id).await
    }

    async fn delete_credential(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_credential(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}

fn credential_store_from_gmp(store: gvm_gmp::responses::CredentialStore) -> CredentialStore {
    CredentialStore {
        id: store.id,
        name: store.name,
        provider: store.type_,
        default: None,
        writable: None,
    }
}

fn ensure_credential_stores_supported(
    client: &crate::gvmd_adapter::session::SessionClient,
) -> Result<(), GatewayError> {
    if client.credential_store_capability() == CredentialStoreCapability::Unsupported {
        return Err(unsupported_credential_store_error());
    }
    Ok(())
}

fn map_credential_store_error(error: gvm_client::GvmError) -> GatewayError {
    if credential_store_capability_unavailable(&error) {
        unsupported_credential_store_error()
    } else {
        map_gvm_error(error)
    }
}

fn parse_credential_store_type(value: &str) -> Option<CredentialStoreCredentialType> {
    match value {
        "cs_cc" => Some(CredentialStoreCredentialType::ClientCertificate),
        "cs_pw" => Some(CredentialStoreCredentialType::PasswordOnly),
        "cs_pgp" => Some(CredentialStoreCredentialType::PgpEncryptionKey),
        "cs_smime" => Some(CredentialStoreCredentialType::SmimeCertificate),
        "cs_snmp" => Some(CredentialStoreCredentialType::Snmp),
        "cs_up" => Some(CredentialStoreCredentialType::UsernamePassword),
        "cs_usk" => Some(CredentialStoreCredentialType::UsernameSshKey),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn ensure_no_local_secret_fields(
    login: Option<&String>,
    password: Option<&String>,
    private_key: Option<&String>,
    certificate: Option<&String>,
    community: Option<&String>,
    auth_algorithm: Option<&String>,
    privacy_algorithm: Option<&String>,
    privacy_password: Option<&String>,
) -> Result<(), GatewayError> {
    if login.is_some()
        || password.is_some()
        || private_key.is_some()
        || certificate.is_some()
        || community.is_some()
        || auth_algorithm.is_some()
        || privacy_algorithm.is_some()
        || privacy_password.is_some()
    {
        return Err(GatewayError::InvalidInput(
            "credential-store references cannot be combined with local credential values"
                .to_string(),
        ));
    }
    Ok(())
}

pub(in crate::gvmd_adapter) async fn probe_credential_store_capability(
    client: &mut GmpClient<UnixSocketConnection>,
) -> Result<CredentialStoreProbeOutcome, gvm_client::GvmError> {
    match client.get_credential_stores().await {
        Ok(_) => Ok(CredentialStoreProbeOutcome {
            capability: CredentialStoreCapability::Supported,
            requires_reconnect: false,
        }),
        Err(gvm_client::GvmError::UnsupportedCommand { command, .. })
            if command == "get_credential_stores" =>
        {
            Ok(CredentialStoreProbeOutcome {
                capability: CredentialStoreCapability::Unsupported,
                requires_reconnect: false,
            })
        }
        Err(error) if credential_store_capability_unavailable(&error) => {
            Ok(CredentialStoreProbeOutcome {
                capability: CredentialStoreCapability::Unsupported,
                requires_reconnect: true,
            })
        }
        Err(error) => Err(error),
    }
}

pub(super) fn credential_store_capability_unavailable(error: &gvm_client::GvmError) -> bool {
    match error {
        gvm_client::GvmError::UnsupportedCommand { command, .. } => {
            command == "get_credential_stores"
        }
        gvm_client::GvmError::Server {
            status: 503,
            message,
        }
        | gvm_client::GvmError::Parse(gvm_gmp::responses::ParseError::ServerError {
            status: 503,
            message,
        }) => credential_store_command_disabled(message),
        _ => false,
    }
}

fn credential_store_command_disabled(message: &str) -> bool {
    message.to_ascii_lowercase().contains("command disabled")
}

pub(super) fn unsupported_credential_store_error() -> GatewayError {
    GatewayError::NotImplemented(
        "credential stores are not available because gvmd does not expose `get_credential_stores` on this backend instance; the proxy does not synthesize credential store entries".to_string(),
    )
}
