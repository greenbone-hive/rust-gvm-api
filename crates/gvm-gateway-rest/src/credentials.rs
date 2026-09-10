// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Credential DTOs and handlers for the REST adapter.

#![allow(missing_docs)]

use std::fmt;

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{hide_optional_value, GatewayError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, password_schema, PaginationResponse, ResourceCreatedResponse},
    handler::{
        authenticated_resource, create_resource_with_json_error, delete_resource, gateway_error,
        get_resource, list_resource, no_content, update_resource_with_json_error, ValidateInto,
    },
    open_enum::open_string_enum,
    openapi::{created_json, ok_json, problem_response, ResourceIdPathDoc, TargetListQueryDoc},
    query::{CollectionListQuery, DeleteResourceQueryParams},
    router::bearer_token,
};

pub use gvm_gateway_domain::{
    CreateCredentialInput, Credential, CredentialPage, CredentialQuery, CredentialStore,
    CredentialStorePreferenceInput, ModifyCredentialInput, ModifyCredentialStoreInput,
};

open_string_enum! {
    /// Credential type code.
    pub(crate) enum CredentialType {
        ClientCertificate => "cc",
        PasswordOnly => "pw",
        SnmpV1Or2c => "snmp",
        SnmpV3 => "snmpv3",
        UsernamePassword => "up",
        UsernameSshKey => "usk",
        CredentialStoreClientCertificate => "cs_cc",
        CredentialStorePasswordOnly => "cs_pw",
        CredentialStorePgpEncryptionKey => "cs_pgp",
        CredentialStoreSmimeCertificate => "cs_smime",
        CredentialStoreSnmp => "cs_snmp",
        CredentialStoreUsernamePassword => "cs_up",
        CredentialStoreUsernameSshKey => "cs_usk",
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Credential")]
pub(crate) struct CredentialResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    #[schemars(required)]
    credential_type: Option<CredentialType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<String>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<Credential> for CredentialResponse {
    fn from(credential: Credential) -> Self {
        Self {
            id: parse_uuid(&credential.id),
            name: credential.name,
            comment: credential.comment,
            credential_type: credential
                .credential_type
                .as_deref()
                .map(CredentialType::parse),
            login: credential.login,
            in_use: credential.in_use,
            writable: credential.writable,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "CredentialList")]
pub(crate) struct CredentialListResponse {
    data: Vec<CredentialResponse>,
    pagination: PaginationResponse,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "CredentialStore")]
pub(crate) struct CredentialStoreResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    writable: Option<bool>,
}

impl From<CredentialStore> for CredentialStoreResponse {
    fn from(store: CredentialStore) -> Self {
        Self {
            id: store.id,
            name: store.name,
            provider: store.provider,
            default: store.default,
            writable: store.writable,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "CredentialStoreList")]
pub(crate) struct CredentialStoreListResponse {
    data: Vec<CredentialStoreResponse>,
}

#[derive(Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CredentialStorePreferenceRequest {
    #[schemars(length(max = 1024))]
    name: String,
    #[schemars(schema_with = "credential_store_preference_value_schema")]
    value: String,
}

fn credential_store_preference_value_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "format": "password",
        "maxLength": 65536
    })
}

impl fmt::Debug for CredentialStorePreferenceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialStorePreferenceRequest")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Default, Deserialize, JsonSchema)]
#[schemars(rename = "ModifyCredentialStore")]
#[serde(deny_unknown_fields)]
pub(crate) struct ModifyCredentialStoreRequest {
    active: Option<bool>,
    host: Option<String>,
    path: Option<String>,
    port: Option<u16>,
    comment: Option<String>,
    #[serde(default)]
    #[schemars(length(max = 256))]
    preferences: Vec<CredentialStorePreferenceRequest>,
}

impl fmt::Debug for ModifyCredentialStoreRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModifyCredentialStoreRequest")
            .field("active", &self.active)
            .field("host", &self.host)
            .field("path", &self.path)
            .field("port", &self.port)
            .field("comment", &self.comment)
            .field("preferences", &self.preferences)
            .finish()
    }
}

impl ValidateInto<ModifyCredentialStoreInput> for ModifyCredentialStoreRequest {
    fn validate_into(self) -> Result<ModifyCredentialStoreInput, GatewayError> {
        if self.preferences.len() > 256 {
            return Err(GatewayError::InvalidInput(
                "preferences must contain at most 256 entries".to_string(),
            ));
        }
        let preferences = self
            .preferences
            .into_iter()
            .map(|preference| {
                if preference.name.trim().is_empty() {
                    return Err(GatewayError::InvalidInput(
                        "preference name is required".to_string(),
                    ));
                }
                if preference.name.len() > 1024 || preference.value.len() > 65_536 {
                    return Err(GatewayError::InvalidInput(
                        "credential-store preference exceeds the supported size".to_string(),
                    ));
                }
                Ok(CredentialStorePreferenceInput {
                    name: preference.name,
                    value: preference.value,
                })
            })
            .collect::<Result<Vec<_>, GatewayError>>()?;
        Ok(ModifyCredentialStoreInput {
            active: self.active,
            host: self.host,
            path: self.path,
            port: self.port,
            comment: self.comment,
            preferences,
        })
    }
}

impl From<Vec<CredentialStore>> for CredentialStoreListResponse {
    fn from(stores: Vec<CredentialStore>) -> Self {
        Self {
            data: stores
                .into_iter()
                .map(CredentialStoreResponse::from)
                .collect(),
        }
    }
}

impl From<CredentialPage> for CredentialListResponse {
    fn from(page: CredentialPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(CredentialResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Deserialize, JsonSchema)]
#[schemars(rename = "CreateCredential")]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateCredentialRequest {
    name: String,
    comment: Option<String>,
    #[serde(rename = "type")]
    credential_type: CredentialType,
    login: Option<String>,
    #[schemars(schema_with = "password_schema")]
    password: Option<String>,
    #[serde(rename = "privateKey")]
    private_key: Option<String>,
    certificate: Option<String>,
    community: Option<String>,
    #[serde(rename = "authAlgorithm")]
    #[schemars(schema_with = "auth_algorithm_schema")]
    auth_algorithm: Option<String>,
    #[serde(rename = "privacyAlgorithm")]
    #[schemars(schema_with = "privacy_algorithm_schema")]
    privacy_algorithm: Option<String>,
    #[serde(rename = "privacyPassword")]
    #[schemars(schema_with = "password_schema")]
    privacy_password: Option<String>,
    #[serde(rename = "credentialStoreId")]
    credential_store_id: Option<Uuid>,
    #[serde(rename = "vaultId")]
    vault_id: Option<String>,
    #[serde(rename = "hostIdentifier")]
    host_identifier: Option<String>,
}

impl fmt::Debug for CreateCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateCredentialRequest")
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

impl CreateCredentialRequest {
    fn validate(self) -> Result<CreateCredentialInput, GatewayError> {
        if self.name.trim().is_empty() {
            return Err(GatewayError::InvalidInput("name is required".to_string()));
        }
        if self.credential_type.as_str().trim().is_empty() {
            return Err(GatewayError::InvalidInput("type is required".to_string()));
        }
        let store_backed = self.credential_type.as_str().starts_with("cs_");
        let has_store_fields = self.credential_store_id.is_some()
            || self.vault_id.is_some()
            || self.host_identifier.is_some();
        if store_backed {
            if self.vault_id.as_deref().is_none_or(str::is_empty)
                || self.host_identifier.as_deref().is_none_or(str::is_empty)
            {
                return Err(GatewayError::InvalidInput(
                    "vaultId and hostIdentifier are required for credential-store-backed credentials"
                        .to_string(),
                ));
            }
            if self.login.is_some()
                || self.password.is_some()
                || self.private_key.is_some()
                || self.certificate.is_some()
                || self.community.is_some()
                || self.auth_algorithm.is_some()
                || self.privacy_algorithm.is_some()
                || self.privacy_password.is_some()
            {
                return Err(GatewayError::InvalidInput(
                    "credential-store references cannot be combined with local credential values"
                        .to_string(),
                ));
            }
        } else if has_store_fields {
            return Err(GatewayError::InvalidInput(
                "credential-store fields require a credential type with the `cs_` prefix"
                    .to_string(),
            ));
        }
        Ok(CreateCredentialInput {
            name: self.name,
            comment: self.comment,
            credential_type: self.credential_type.as_str().to_string(),
            login: self.login,
            password: self.password,
            private_key: self.private_key,
            certificate: self.certificate,
            community: self.community,
            auth_algorithm: self.auth_algorithm,
            privacy_algorithm: self.privacy_algorithm,
            privacy_password: self.privacy_password,
            credential_store_id: self.credential_store_id.map(|id| id.to_string()),
            vault_id: self.vault_id,
            host_identifier: self.host_identifier,
        })
    }
}

impl ValidateInto<CreateCredentialInput> for CreateCredentialRequest {
    fn validate_into(self) -> Result<CreateCredentialInput, GatewayError> {
        self.validate()
    }
}

#[derive(Clone, Default, Deserialize, JsonSchema)]
#[schemars(rename = "ModifyCredential")]
#[serde(deny_unknown_fields)]
pub struct ModifyCredentialRequest {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub login: Option<String>,
    #[schemars(schema_with = "password_schema")]
    pub password: Option<String>,
    #[serde(rename = "privateKey")]
    pub private_key: Option<String>,
    pub certificate: Option<String>,
    pub community: Option<String>,
    #[serde(rename = "authAlgorithm")]
    #[schemars(schema_with = "auth_algorithm_schema")]
    pub auth_algorithm: Option<String>,
    #[serde(rename = "privacyAlgorithm")]
    #[schemars(schema_with = "privacy_algorithm_schema")]
    pub privacy_algorithm: Option<String>,
    #[serde(rename = "privacyPassword")]
    #[schemars(schema_with = "password_schema")]
    pub privacy_password: Option<String>,
    #[serde(rename = "credentialStoreId")]
    pub credential_store_id: Option<Uuid>,
    #[serde(rename = "vaultId")]
    pub vault_id: Option<String>,
    #[serde(rename = "hostIdentifier")]
    pub host_identifier: Option<String>,
}

fn auth_algorithm_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "enum": ["md5", "sha1"]
    })
}

fn privacy_algorithm_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "enum": ["aes", "des"]
    })
}

impl fmt::Debug for ModifyCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModifyCredentialRequest")
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

impl ModifyCredentialRequest {
    fn validate(self) -> ModifyCredentialInput {
        ModifyCredentialInput {
            name: self.name,
            comment: self.comment,
            login: self.login,
            password: self.password,
            private_key: self.private_key,
            certificate: self.certificate,
            community: self.community,
            auth_algorithm: self.auth_algorithm,
            privacy_algorithm: self.privacy_algorithm,
            privacy_password: self.privacy_password,
            credential_store_id: self.credential_store_id.map(|id| id.to_string()),
            vault_id: self.vault_id,
            host_identifier: self.host_identifier,
        }
    }
}

impl ValidateInto<ModifyCredentialInput> for ModifyCredentialRequest {
    fn validate_into(self) -> Result<ModifyCredentialInput, GatewayError> {
        Ok(self.validate())
    }
}

fn credential_json_body_error(error: serde_json::Error) -> GatewayError {
    GatewayError::InvalidInput(format!(
        "invalid JSON body at line {}, column {}",
        error.line(),
        error.column()
    ))
}

pub async fn list_credentials(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        CollectionListQuery::try_from_query_string,
        |service, session, query| async move {
            service
                .list_credentials(
                    &session,
                    CredentialQuery {
                        filter_string: query.filter_string,
                        filter_id: query.filter_id,
                        page: query.page,
                        per_page: query.per_page,
                    },
                )
                .await
        },
        CredentialListResponse::from,
    )
    .await
}

pub async fn list_credential_stores(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    authenticated_resource(
        service,
        headers,
        uri,
        |service, session| async move { service.list_credential_stores(&session).await },
        CredentialStoreListResponse::from,
    )
    .await
}

pub async fn get_credential_store(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id| async move { service.get_credential_store(&session, &id).await },
        CredentialStoreResponse::from,
    )
    .await
}

pub async fn update_credential_store(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource_with_json_error::<
        ModifyCredentialStoreInput,
        ModifyCredentialStoreRequest,
        _,
        _,
        _,
        _,
        _,
    >(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_credential_store(&session, &id, input).await
        },
        CredentialStoreResponse::from,
        credential_json_body_error,
    )
    .await
}

pub async fn verify_credential_store(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if Uuid::parse_str(&id).is_err() {
        return gateway_error(
            GatewayError::InvalidInput("id must be a valid UUID".to_string()),
            instance,
        );
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return gateway_error(error, instance),
    };
    match service.verify_credential_store(&session, &id).await {
        Ok(()) => no_content(),
        Err(error) => gateway_error(error, instance),
    }
}

pub async fn create_credential(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource_with_json_error::<CreateCredentialInput, CreateCredentialRequest, _, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_credential(&session, input).await },
        credential_json_body_error,
    )
    .await
}

pub async fn get_credential(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id| async move { service.get_credential(&session, &id).await },
        CredentialResponse::from,
    )
    .await
}

pub async fn update_credential(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource_with_json_error::<
        ModifyCredentialInput,
        ModifyCredentialRequest,
        _,
        _,
        _,
        _,
        _,
    >(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_credential(&session, &id, input).await
        },
        CredentialResponse::from,
        credential_json_body_error,
    )
    .await
}

pub async fn delete_credential(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id, ultimate| async move {
            service.delete_credential(&session, &id, ultimate).await
        },
    )
    .await
}

pub(crate) fn list_credentials_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCredentials")
        .tag("Credentials")
        .summary("List credentials")
        .description("Returns a paginated list of credentials.")
        .security_requirement("bearerAuth")
        .input::<Query<TargetListQueryDoc>>()
        .response_with::<200, Json<CredentialListResponse>, _>(ok_json(
            "Paginated list of credentials",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/credential-stores`.
pub(crate) fn list_credential_stores_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCredentialStores")
        .tag("Credentials")
        .summary("List available credential stores")
        .description("Returns credential stores reported by gvmd. Backends that do not expose this capability, including versions before GMP 22.8 and instances where gvmd disables `get_credential_stores`, return 501 because the gateway does not synthesize default store entries.")
        .security_requirement("bearerAuth")
        .response_with::<200, Json<CredentialStoreListResponse>, _>(ok_json(
            "Available credential stores",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<501>(
        op,
        "The connected gvmd backend does not expose credential stores",
    );
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

pub(crate) fn get_credential_store_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCredentialStore")
        .tag("Credentials")
        .summary("Get a credential store")
        .description("Returns one credential store without exposing backend preference values.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<CredentialStoreResponse>, _>(ok_json(
            "Credential store details",
        ));
    credential_store_problem_responses(op, true)
}

pub(crate) fn update_credential_store_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyCredentialStore")
        .tag("Credentials")
        .summary("Modify a credential store")
        .description("Updates credential-store connection settings. Preference values are write-only and never returned.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyCredentialStoreRequest>)>()
        .response_with::<200, Json<CredentialStoreResponse>, _>(ok_json(
            "Credential store updated",
        ));
    credential_store_problem_responses(op, true)
}

pub(crate) fn verify_credential_store_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("verifyCredentialStore")
        .tag("Credentials")
        .summary("Verify a credential store")
        .description("Asks gvmd to verify the credential-store connection.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Credential store verified"));
    credential_store_problem_responses(op, true)
}

fn credential_store_problem_responses(
    op: TransformOperation<'_>,
    include_not_found: bool,
) -> TransformOperation<'_> {
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = if include_not_found {
        problem_response::<404>(op, "Credential store not found")
    } else {
        op
    };
    let op = problem_response::<501>(op, "Backend does not expose credential stores");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

pub(crate) fn create_credential_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createCredential")
        .tag("Credentials")
        .summary("Create a credential")
        .description("Creates a new credential.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateCredentialRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Credential created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_credential_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCredential")
        .tag("Credentials")
        .summary("Get a credential")
        .description("Returns a single credential.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<CredentialResponse>, _>(ok_json("Credential details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn update_credential_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyCredential")
        .tag("Credentials")
        .summary("Modify a credential")
        .description("Updates an existing credential.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyCredentialRequest>)>()
        .response_with::<200, Json<CredentialResponse>, _>(ok_json("Credential updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_credential_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteCredential")
        .tag("Credentials")
        .summary("Delete a credential")
        .description("Deletes a credential. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Credential deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "credentials_test.rs"]
mod credentials_test;
