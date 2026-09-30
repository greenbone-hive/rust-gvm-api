// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_gmp::commands::credentials::GetCredentialsRequest;
use gvm_mock_server::{Fault, FaultKind, GmpVersion as MockVersion, MockGmpServer, ServerMode};

use super::{connect_authenticated_client, CredentialStoreCapability, SessionClient};

#[test]
fn session_client_only_caches_capability_state_after_connect() {
    // Security regression coverage for PR #463: the cached session client must
    // not retain plaintext gvmd credentials after connect_session returns.
    fn assert_shape(
        SessionClient {
            client: _,
            command_slots: _,
            credential_store_capability: _,
        }: SessionClient,
    ) {
    }

    let _ = assert_shape as fn(SessionClient);
}

#[tokio::test]
async fn connect_authenticated_client_restores_authenticated_socket_after_disconnect() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .inject_fault(Fault::after_commands(3, FaultKind::Disconnect))
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let client = connect_authenticated_client(server.socket_path().unwrap(), "admin", "admin")
        .await
        .expect("initial authentication");
    let session_client = SessionClient::new(client, CredentialStoreCapability::Supported);
    let mut guard = session_client.lock().await.expect("session lock");

    guard
        .get_credentials(GetCredentialsRequest::default())
        .await
        .expect("first credential read should succeed before the injected disconnect");
    guard
        .get_credentials(GetCredentialsRequest::default())
        .await
        .expect_err("second credential read should observe the injected disconnect");

    // The connect-time capability probe may need to discard a stale GMP
    // socket before the session is published. The reconnect helper must
    // restore a usable authenticated client without storing the password.
    *guard = connect_authenticated_client(server.socket_path().unwrap(), "admin", "admin")
        .await
        .expect("reconnect should replace the stale GMP client");
    guard
        .get_credentials(GetCredentialsRequest::default())
        .await
        .expect("credential reads should succeed after reconnect");

    server.shutdown().await;
}
