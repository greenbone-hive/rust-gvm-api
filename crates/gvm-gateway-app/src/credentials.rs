// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Credential use cases.

use gvm_gateway_domain::{
    CreateCredentialInput, Credential, CredentialPage, CredentialQuery, CredentialStore,
    GatewayError, ModifyCredentialInput, ModifyCredentialStoreInput,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists backend credential stores for an authenticated session.
    pub async fn list_credential_stores(
        &self,
        session_token: &str,
    ) -> Result<Vec<gvm_gateway_domain::CredentialStore>, GatewayError> {
        self.execute_with_resource(
            "credentials.stores.list",
            session_token,
            "list",
            "credential_store",
            None,
            |session| async move {
                self.credentials
                    .list_credential_stores(&session.token)
                    .await
            },
        )
        .await
    }

    /// Fetches one backend credential store for an authenticated session.
    pub async fn get_credential_store(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<CredentialStore, GatewayError> {
        self.execute_with_resource(
            "credentials.stores.get",
            session_token,
            "read",
            "credential_store",
            Some(id),
            |session| async move {
                self.credentials
                    .get_credential_store(&session.token, id)
                    .await
            },
        )
        .await
    }

    /// Modifies one backend credential store for an authenticated session.
    pub async fn modify_credential_store(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyCredentialStoreInput,
    ) -> Result<CredentialStore, GatewayError> {
        self.execute_with_resource(
            "credentials.stores.modify",
            session_token,
            "modify",
            "credential_store",
            Some(id),
            |session| async move {
                self.credentials
                    .modify_credential_store(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Verifies one backend credential store for an authenticated session.
    pub async fn verify_credential_store(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "credentials.stores.verify",
            session_token,
            "verify",
            "credential_store",
            Some(id),
            |session| async move {
                self.credentials
                    .verify_credential_store(&session.token, id)
                    .await
            },
        )
        .await
    }

    /// Lists credentials for an authenticated session.
    pub async fn list_credentials(
        &self,
        session_token: &str,
        query: CredentialQuery,
    ) -> Result<CredentialPage, GatewayError> {
        self.execute_with_resource(
            "credentials.list",
            session_token,
            "list",
            "credential",
            None,
            |session| async move {
                self.credentials
                    .list_credentials(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Creates a new credential for an authenticated session.
    pub async fn create_credential(
        &self,
        session_token: &str,
        input: CreateCredentialInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "credentials.create",
            session_token,
            "create",
            "credential",
            None,
            |session| async move {
                self.credentials
                    .create_credential(&session.token, input)
                    .await
            },
        )
        .await
    }

    /// Fetches a credential for an authenticated session.
    pub async fn get_credential(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Credential, GatewayError> {
        self.execute_with_resource(
            "credentials.get",
            session_token,
            "read",
            "credential",
            Some(id),
            |session| async move { self.credentials.get_credential(&session.token, id).await },
        )
        .await
    }

    /// Modifies a credential for an authenticated session.
    pub async fn modify_credential(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyCredentialInput,
    ) -> Result<Credential, GatewayError> {
        self.execute_with_resource(
            "credentials.modify",
            session_token,
            "modify",
            "credential",
            Some(id),
            |session| async move {
                self.credentials
                    .modify_credential(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes a credential for an authenticated session.
    pub async fn delete_credential(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "credentials.delete",
            session_token,
            "delete",
            "credential",
            Some(id),
            |session| async move {
                self.credentials
                    .delete_credential(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }
}
