use std::{
    collections::HashMap,
    io,
    io::Write,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use gvm_gateway_domain::*;
use gvm_gateway_gvmd::GvmdAdapter;
use gvm_mock_server::{
    response_gen::{REPORT_EXPORT_BINARY_FORMAT_ID, REPORT_EXPORT_XML_FORMAT_ID},
    Fault, FaultKind, GmpVersion as MockVersion, MockGmpServer, Resource, ServerMode,
};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt};

#[derive(Clone)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn capture_tracing() -> Arc<Mutex<Vec<u8>>> {
    static BUFFER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    static INIT: OnceLock<()> = OnceLock::new();

    let buffer = BUFFER
        .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
        .clone();

    INIT.get_or_init(|| {
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .without_time()
                .with_span_events(FmtSpan::CLOSE)
                .with_writer(move || SharedWriter(writer.clone())),
        );
        let _ = tracing::subscriber::set_global_default(subscriber);
    });

    buffer.lock().unwrap().clear();
    buffer
}

async fn lock_tracing() -> AsyncMutexGuard<'static, ()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(())).lock().await
}

#[tokio::test]
async fn gvmd_adapter_probe_version_reports_mock_version() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let version = adapter.probe_version().await.unwrap();
    assert_eq!(version, "22.7");

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_readiness_reports_ready_when_probe_succeeds() {
    // Covers the production `/ready` contract: a reachable GMP backend must
    // be reported as ready instead of relying on startup-only state.
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let status = adapter.readiness().await.unwrap();
    assert_eq!(status.status, "ready");
    assert!(status.reason.is_none());

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_readiness_reports_not_ready_when_socket_is_missing() {
    // Regression coverage for compose startup races: `/ready` must degrade
    // while gvmd has not created its Unix socket yet.
    let adapter = GvmdAdapter::unix_socket("/tmp/nonexistent-gvmd-readiness.sock");
    let status = adapter.readiness().await.unwrap();
    assert_eq!(status.status, "notReady");
    assert!(
        status
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("socket not found")),
        "readiness reason should explain the missing socket: {:?}",
        status.reason
    );
}
async fn create_mock_adapter() -> (GvmdAdapter, MockGmpServer, String) {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();

    (adapter, server, token.to_string())
}

async fn create_mock_adapter_v22_8() -> (GvmdAdapter, MockGmpServer, String) {
    let report_id =
        uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid report id");
    let filter_id =
        uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").expect("valid filter id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .seed(move |store| {
            store.create(Resource::with_id("report", "Typed report", report_id));
            let mut filter = Resource::with_id("filter", "Saved alarm filter", filter_id);
            filter.set_attr("term", "threat=Alarm");
            store.create(filter);
        })
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();

    (adapter, server, token.to_string())
}

async fn create_mock_adapter_v22_8_with_credential_store_error(
    message: &str,
) -> (GvmdAdapter, MockGmpServer, String) {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .inject_fault(Fault::on_command(
            "get_credential_stores",
            FaultKind::ErrorStatus {
                code: 503,
                message: message.to_string(),
            },
        ))
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();

    (adapter, server, token.to_string())
}

async fn create_mock_adapter_v22_8_with_disabled_credential_stores_followed_by_disconnect(
) -> (GvmdAdapter, MockGmpServer, String) {
    let credential_id =
        uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174009").expect("valid credential id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .seed(move |store| {
            let mut credential =
                Resource::with_id("credential", "Reconnect-safe credential", credential_id);
            credential.set_attr("type", "up");
            credential.set_attr("login", "admin");
            store.create(credential);
        })
        .inject_fault(Fault::on_command(
            "get_credential_stores",
            FaultKind::ErrorStatus {
                code: 503,
                message: "Service unavailable: Command disabled".to_string(),
            },
        ))
        .inject_fault(Fault::after_commands(3, FaultKind::Disconnect))
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();

    (adapter, server, token.to_string())
}

async fn create_mock_adapter_v22_8_with_unknown_credential_store_probe_followed_by_disconnect(
) -> (GvmdAdapter, MockGmpServer, String) {
    let credential_id =
        uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174010").expect("valid credential id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .seed(move |store| {
            let mut credential = Resource::with_id(
                "credential",
                "Reconnect-safe unknown probe credential",
                credential_id,
            );
            credential.set_attr("type", "up");
            credential.set_attr("login", "admin");
            store.create(credential);
        })
        .inject_fault(Fault::on_command(
            "get_credential_stores",
            FaultKind::ErrorStatus {
                code: 503,
                message: "Service unavailable: database offline".to_string(),
            },
        ))
        .inject_fault(Fault::after_commands(3, FaultKind::Disconnect))
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();

    (adapter, server, token.to_string())
}

fn assert_paginated_commands(
    server: &MockGmpServer,
    command_name: &str,
    expected_filter: &str,
    expected_count: usize,
) {
    let matching_commands = server
        .command_history()
        .into_iter()
        .filter(|record| record.command_name() == command_name)
        .collect::<Vec<_>>();

    assert_eq!(
        matching_commands.len(),
        expected_count,
        "{command_name} should be called {expected_count} time(s) for this paginated list request"
    );
    let first_xml = String::from_utf8(matching_commands[0].raw_xml().to_vec())
        .expect("xml command should be UTF-8");
    assert!(
            first_xml.contains(expected_filter),
            "{command_name} should include backend pagination filter {expected_filter:?}; xml={first_xml}"
        );
}

macro_rules! assert_backend_pagination {
    ($adapter:expr, $server:expr, $call:expr, $command_name:literal, $expected_filter:literal) => {{
        $server.clear_history();

        let result = $call.await;
        assert!(
            result.is_ok(),
            "{} should accept the paginated query: {:?}",
            $command_name,
            result
        );
        assert_paginated_commands(&$server, $command_name, $expected_filter, 1);
    }};
    ($adapter:expr, $server:expr, $call:expr, $command_name:literal, $expected_filter:literal, $expected_count:literal) => {{
        $server.clear_history();

        let result = $call.await;
        assert!(
            result.is_ok(),
            "{} should accept the paginated query: {:?}",
            $command_name,
            result
        );
        assert_paginated_commands(&$server, $command_name, $expected_filter, $expected_count);
    }};
}

#[tokio::test]
async fn gvmd_adapter_connect_session_success() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "gvm_sess_adapter_debug_secret";
    let result = adapter.connect_session(token, "admin", "admin").await;

    assert_eq!(result.unwrap(), "22.7");
    let debug = format!("{adapter:?}");
    assert!(debug.contains("session_count"));
    assert!(!debug.contains(token));
    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_connect_session_auth_failure_returns_unauthorized() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let result = adapter.connect_session("token", "admin", "wrong").await;

    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    let session_digest = SessionTokenDigest::from_token("token");
    let disconnect_result = adapter.disconnect_session(&session_digest).await;
    assert!(disconnect_result.is_ok());
    let follow_up = adapter
        .list_targets(
            "token",
            &TargetQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await;
    assert!(matches!(
        follow_up,
        Err(GatewayError::SessionInvalidated(_))
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_targets_empty() {
    let (adapter, server, token) = create_mock_adapter().await;

    let result = adapter
        .list_targets(
            &token,
            &TargetQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await;

    assert!(result.is_ok());
    let page = result.unwrap();
    assert!(page.data.is_empty());
    assert_eq!(page.pagination.total, 0);

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_emits_backend_boundary_spans_without_raw_session_token() {
    let _trace_lock = lock_tracing().await;
    let logs = capture_tracing();
    let (adapter, server, token) = create_mock_adapter().await;

    let result = adapter
        .list_targets(
            &token,
            &TargetQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await;

    assert!(result.is_ok());

    let output = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(output.contains("gvmd.session.connect"));
    assert!(output.contains("gvmd.request"));
    assert!(output.contains("targets.list"));
    assert!(output.contains("session:"));
    assert!(!output.contains(&token));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_create_target() {
    let (adapter, server, token) = create_mock_adapter().await;

    let input = CreateTargetInput {
        name: "Test Target".to_string(),
        comment: Some("Integration test".to_string()),
        hosts: vec!["192.168.1.1".to_string()],
        exclude_hosts: vec![],
        alive_test: None,
        port_list_id: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    };

    let result = adapter.create_target(&token, input).await;

    assert!(result.is_ok());
    let id = result.unwrap();
    assert!(!id.is_empty());

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_target() {
    let (adapter, server, token) = create_mock_adapter().await;

    // Create a target first so get can read an existing target path.
    let input = CreateTargetInput {
        name: "Get Me".to_string(),
        comment: None,
        hosts: vec!["10.0.0.1".to_string()],
        exclude_hosts: vec![],
        alive_test: None,
        port_list_id: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    };
    let id = adapter.create_target(&token, input).await.unwrap();

    // Fetch the target
    let result = adapter.get_target(&token, &id).await;

    assert!(result.is_ok());
    let target = result.unwrap();
    assert_eq!(target.name, "Get Me");

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_target_not_found() {
    let (adapter, server, token) = create_mock_adapter().await;

    let result = adapter
        .get_target(&token, "550e8400-e29b-41d4-a716-446655440000")
        .await;

    assert!(matches!(result, Err(GatewayError::NotFound(_))));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_modify_target() {
    let (adapter, server, token) = create_mock_adapter().await;

    // Create a target first
    let input = CreateTargetInput {
        name: "Before Modify".to_string(),
        comment: None,
        hosts: vec!["10.0.0.1".to_string()],
        exclude_hosts: vec![],
        alive_test: None,
        port_list_id: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    };
    let id = adapter.create_target(&token, input).await.unwrap();
    server.clear_history();

    // Regression coverage for issue #309: reverse lookup flags supplied on
    // modify must reach rust-gvm's typed modify_target builder.
    let modify_input = ModifyTargetInput {
        name: Some("After Modify".to_string()),
        comment: Some("Updated".to_string()),
        hosts: Some(vec!["10.0.0.2".to_string(), "10.0.0.3".to_string()]),
        exclude_hosts: None,
        alive_test: None,
        port_list_id: None,
        reverse_lookup_only: Some(true),
        reverse_lookup_unify: Some(false),
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    };
    let result = adapter.modify_target(&token, &id, modify_input).await;

    assert!(result.is_ok());
    let target = result.unwrap();
    assert_eq!(target.name, "After Modify");
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_target")
        .expect("modify_target command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<reverse_lookup_only>1</reverse_lookup_only>"));
    assert!(xml.contains("<reverse_lookup_unify>0</reverse_lookup_unify>"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_modify_task_forwards_preferences() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    // Regression coverage for issue #228: task preferences supplied on
    // modify must reach the typed rust-gvm command instead of being
    // dropped by the gvmd adapter.
    let result = adapter
        .modify_task(
            &token,
            "550e8400-e29b-41d4-a716-446655440010",
            ModifyTaskInput {
                preferences: vec![("scanner.max_hosts".to_string(), "64".to_string())],
                ..Default::default()
            },
        )
        .await;

    assert!(
        result.is_err(),
        "mock backend may reject the unknown task, but the command should still be emitted"
    );
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_task")
        .expect("modify_task command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<scanner_name>scanner.max_hosts</scanner_name>"));
    assert!(xml.contains("<value>64</value>"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_create_alert_forwards_selector_data_maps() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    // Regression coverage for #402: advertised alert selector data maps must
    // reach the typed GMP request instead of being rejected locally.
    let alert_id = adapter
        .create_alert(
            &token,
            CreateAlertInput {
                name: "Selector Alert".to_string(),
                comment: Some("notify".to_string()),
                event: Some("task_run_status_changed".to_string()),
                condition: Some("severity_at_least".to_string()),
                method: Some("email".to_string()),
                event_data: HashMap::from([("status".to_string(), "Done".to_string())]),
                condition_data: HashMap::from([("severity".to_string(), "7.5".to_string())]),
                method_data: HashMap::from([(
                    "to_address".to_string(),
                    "ops@example.com".to_string(),
                )]),
                filter_id: None,
            },
        )
        .await
        .expect("alert create should succeed with non-empty selector data");
    let alert = adapter
        .get_alert(&token, &alert_id)
        .await
        .expect("created alert should remain readable");

    assert_eq!(
        alert.event_data.get("status").map(String::as_str),
        Some("Done")
    );
    assert_eq!(
        alert.condition_data.get("severity").map(String::as_str),
        Some("7.5")
    );
    assert_eq!(
        alert.method_data.get("to_address").map(String::as_str),
        Some("ops@example.com")
    );

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "create_alert")
        .expect("create_alert command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<event>Task run status changed"));
    assert!(xml.contains("<data>Done<name>status</name></data>"));
    assert!(xml.contains("<condition>Severity at least"));
    assert!(xml.contains("<data>7.5<name>severity</name></data>"));
    assert!(xml.contains("<method>Email"));
    assert!(xml.contains("<data>ops@example.com<name>to_address</name></data>"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_modify_alert_forwards_rename_and_selector_data_maps() {
    let alert_id =
        uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440120").expect("valid alert id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .seed(move |store| {
            store.create(Resource::with_id("alert", "Existing Alert", alert_id));
        })
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();
    server.clear_history();

    // Regression coverage for #402 and #404: alert modify must keep the
    // replacement name and advertised selector data maps.
    let alert = adapter
        .modify_alert(
            token,
            &alert_id.to_string(),
            ModifyAlertInput {
                name: Some("Renamed Alert".to_string()),
                event: Some("task_run_status_changed".to_string()),
                condition: Some("severity_at_least".to_string()),
                method: Some("email".to_string()),
                event_data: Some(HashMap::from([(
                    "status".to_string(),
                    "Stopped".to_string(),
                )])),
                condition_data: Some(HashMap::from([("severity".to_string(), "8.0".to_string())])),
                method_data: Some(HashMap::from([(
                    "to_address".to_string(),
                    "soc@example.com".to_string(),
                )])),
                ..Default::default()
            },
        )
        .await
        .expect("alert modify should succeed with rename and selector data");

    assert_eq!(alert.name, "Renamed Alert");
    assert_eq!(
        alert.event_data.get("status").map(String::as_str),
        Some("Stopped")
    );
    assert_eq!(
        alert.condition_data.get("severity").map(String::as_str),
        Some("8.0")
    );
    assert_eq!(
        alert.method_data.get("to_address").map(String::as_str),
        Some("soc@example.com")
    );

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_alert")
        .expect("modify_alert command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<name>Renamed Alert</name>"));
    assert!(xml.contains("<data>Stopped<name>status</name></data>"));
    assert!(xml.contains("<data>8.0<name>severity</name></data>"));
    assert!(xml.contains("<data>soc@example.com<name>to_address</name></data>"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_create_credential_forwards_certificate_and_community_fields() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    // Regression coverage for #403: a complete client-certificate request must
    // keep both required key material and unrelated supported secret fields.
    let result = adapter
        .create_credential(
            &token,
            CreateCredentialInput {
                name: "Credential".to_string(),
                comment: None,
                credential_type: "cc".to_string(),
                login: None,
                password: None,
                private_key: Some("PRIVATE KEY".to_string()),
                certificate: Some("CERTIFICATE".to_string()),
                community: Some("public".to_string()),
                auth_algorithm: None,
                privacy_algorithm: None,
                privacy_password: None,
                ..Default::default()
            },
        )
        .await;

    assert!(
        result.is_ok(),
        "credential create should accept supported secret-bearing fields: {result:?}"
    );
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "create_credential")
        .expect("create_credential command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<type>cc</type>"));
    assert!(xml.contains("<key><private>PRIVATE KEY</private>"));
    assert!(xml.contains("<certificate>CERTIFICATE</certificate>"));
    assert!(xml.contains("<community>public</community>"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_modify_credential_forwards_private_key_and_privacy_fields() {
    let credential_id =
        uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440121").expect("valid credential id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .seed(move |store| {
            store.create(Resource::with_id(
                "credential",
                "Existing Credential",
                credential_id,
            ));
        })
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();
    server.clear_history();

    // Regression coverage for #403: modify must keep supported nested secret
    // values instead of dropping them for typed credential updates.
    let result = adapter
        .modify_credential(
            token,
            &credential_id.to_string(),
            ModifyCredentialInput {
                name: Some("Renamed Credential".to_string()),
                private_key: Some("PRIVATE".to_string()),
                community: Some("public".to_string()),
                privacy_algorithm: Some("des".to_string()),
                privacy_password: Some("privacy-secret".to_string()),
                ..Default::default()
            },
        )
        .await;

    assert!(
        result.is_ok(),
        "credential modify should accept supported secret-bearing fields: {result:?}"
    );
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_credential")
        .expect("modify_credential command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<name>Renamed Credential</name>"));
    assert!(xml.contains("<private>PRIVATE</private>"));
    assert!(xml.contains("<community>public</community>"));
    assert!(xml.contains("<algorithm>des</algorithm>"));
    assert!(xml.contains("<password>privacy-secret</password>"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_modify_task_forwards_alterable() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    // Regression coverage for #406: task modify must preserve explicit false
    // instead of hardcoding alterable to omitted.
    let result = adapter
        .modify_task(
            &token,
            "550e8400-e29b-41d4-a716-446655440010",
            ModifyTaskInput {
                alterable: Some(false),
                ..Default::default()
            },
        )
        .await;

    assert!(
        result.is_err(),
        "mock backend may reject the unknown task, but the command should still be emitted"
    );
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_task")
        .expect("modify_task command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<alterable>0</alterable>"));
    assert!(xml.contains("task_id=\"550e8400-e29b-41d4-a716-446655440010\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_modify_audit_forwards_alterable() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    // Shared audit updates reuse ModifyTaskInput, so the adapter must not drop
    // alterable there either.
    let result = adapter
        .modify_audit(
            &token,
            "550e8400-e29b-41d4-a716-446655440011",
            ModifyTaskInput {
                alterable: Some(false),
                ..Default::default()
            },
        )
        .await;

    assert!(
        result.is_err(),
        "mock backend may reject the unknown audit, but the command should still be emitted"
    );
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_task")
        .expect("modify_task command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<alterable>0</alterable>"));
    assert!(xml.contains("<usage_type>audit</usage_type>"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_modify_user_forwards_rename_and_explicit_role_clear() {
    let user_id =
        uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440122").expect("valid user id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .seed(move |store| {
            let mut user = Resource::with_id("user", "existing-user", user_id);
            user.set_attr("hosts_allow", "1");
            user.set_attr("hosts", "192.0.2.0/24");
            store.create(user);
        })
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();
    server.clear_history();

    // Regression coverage for #404 and #405: user modify must keep both
    // explicit rename and explicit role clearing in the typed request.
    let result = adapter
        .modify_user(
            token,
            &user_id.to_string(),
            ModifyUserInput {
                name: Some("renamed-user".to_string()),
                role_ids: Some(Vec::new()),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok(), "modify_user should succeed: {result:?}");
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_user")
        .expect("modify_user command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<new_name>renamed-user</new_name>"));
    assert!(xml.contains("<role id=\"0\"/>"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_modify_scan_config_forwards_rename() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    // Regression coverage for #404: scan-config PUT now promises rename
    // support, so the typed modify_config request must emit the new name.
    let result = adapter
        .modify_scan_config(
            &token,
            "550e8400-e29b-41d4-a716-446655440123",
            ModifyScanConfigInput {
                name: Some("Renamed Config".to_string()),
                ..Default::default()
            },
        )
        .await;

    assert!(
        result.is_err(),
        "mock backend may reject the unknown config, but the command should still be emitted"
    );
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_config")
        .expect("modify_config command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<name>Renamed Config</name>"));
    assert!(!xml.contains("usage_type"), "xml={xml}");

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_scan_config_preference_reads_use_complete_requests() {
    let (adapter, server, token) = create_mock_adapter().await;
    let config_id = "550e8400-e29b-41d4-a716-446655440123";
    let nvt_oid = "1.3.6.1.4.1.25623.1.0.100000";
    server.clear_history();

    let query = ScanConfigPreferenceQuery {
        nvt_oid: Some(nvt_oid.to_string()),
    };
    let _ = adapter
        .list_scan_config_preferences(&token, config_id, &query)
        .await;
    let _ = adapter
        .get_scan_config_preference(&token, config_id, "Timeout", &query)
        .await;

    let history = server.command_history();
    assert!(history.iter().any(|record| {
        let xml = String::from_utf8_lossy(record.raw_xml());
        record.command_name() == "get_preferences"
            && xml.contains(&format!("config_id=\"{config_id}\""))
            && xml.contains(&format!("nvt_oid=\"{nvt_oid}\""))
            && !xml.contains("preference=")
    }));
    assert!(history.iter().any(|record| {
        let xml = String::from_utf8_lossy(record.raw_xml());
        record.command_name() == "get_preferences"
            && xml.contains(&format!("config_id=\"{config_id}\""))
            && xml.contains(&format!("nvt_oid=\"{nvt_oid}\""))
            && xml.contains("preference=\"Timeout\"")
    }));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_scan_config_selection_uses_typed_modify_shapes() {
    let (adapter, server, token) = create_mock_adapter().await;
    let config_id = "550e8400-e29b-41d4-a716-446655440123";

    let _ = adapter
        .set_scan_config_nvt_selection(
            &token,
            config_id,
            "Web Servers",
            vec!["1.3.6.1.4.1".to_string()],
        )
        .await;
    let _ = adapter
        .set_scan_config_family_selection(
            &token,
            config_id,
            SetScanConfigFamilySelectionInput {
                families: vec![ScanConfigFamilySelection {
                    name: "Web Servers".to_string(),
                    growing: true,
                    all: false,
                }],
                auto_add_new_families: true,
            },
        )
        .await;
    let _ = adapter
        .set_scan_config_preference(
            &token,
            config_id,
            "Timeout",
            Some("1.3.6.1.4.1".to_string()),
            Some("10".to_string()),
        )
        .await;

    let commands = server
        .command_history()
        .into_iter()
        .filter(|record| record.command_name() == "modify_config")
        .map(|record| String::from_utf8(record.raw_xml().to_vec()).expect("XML command"))
        .collect::<Vec<_>>();
    assert!(commands.iter().any(|xml| {
        xml.contains("<nvt_selection>")
            && xml.contains("<family>Web Servers</family>")
            && xml.contains("oid=\"1.3.6.1.4.1\"")
    }));
    assert!(commands.iter().any(|xml| {
        xml.contains("<family_selection>")
            && xml.contains("<growing>1</growing>")
            && xml.contains("<all>0</all>")
    }));
    assert!(commands.iter().any(|xml| {
        xml.contains("<preference>")
            && xml.contains("<nvt oid=\"1.3.6.1.4.1\"")
            && xml.contains("<value>MTA=</value>")
    }));
    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_modify_port_list_forwards_rename() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    // Regression coverage for #404: port-list PUT must forward the replacement
    // name through the typed modify_port_list request.
    let result = adapter
        .modify_port_list(
            &token,
            "550e8400-e29b-41d4-a716-446655440124",
            ModifyPortListInput {
                name: Some("Renamed Ports".to_string()),
                ..Default::default()
            },
        )
        .await;

    assert!(
        result.is_err(),
        "mock backend may reject the unknown port list, but the command should still be emitted"
    );
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_port_list")
        .expect("modify_port_list command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<name>Renamed Ports</name>"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_rejects_unsupported_atomic_port_range_replacement() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let result = adapter
        .modify_port_list(
            &token,
            "550e8400-e29b-41d4-a716-446655440124",
            ModifyPortListInput {
                port_range: Some("T:22".to_string()),
                ..Default::default()
            },
        )
        .await;

    assert!(matches!(result, Err(GatewayError::InvalidInput(_))));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_validates_atomic_target_host_replacements() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let result = adapter
        .modify_target(
            &token,
            "550e8400-e29b-41d4-a716-446655440001",
            ModifyTargetInput {
                exclude_hosts: Some(vec!["192.0.2.1".to_string()]),
                ..Default::default()
            },
        )
        .await;

    assert!(matches!(result, Err(GatewayError::InvalidInput(_))));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_modify_user_preserves_hosts_when_request_omits_hosts() {
    let user_id =
        uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440099").expect("valid user id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .seed(move |store| {
            let mut user = Resource::with_id("user", "restricted-user", user_id);
            user.set_attr("hosts_allow", "1");
            user.set_attr("hosts", "192.0.2.0/24");
            store.create(user);
        })
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();
    server.clear_history();

    // Regression coverage for #274: gvmd treats an absent <hosts>
    // element on modify_user as "allow all", so unrelated updates must
    // echo the current host restriction through the typed rust-gvm
    // command when the request did not explicitly change hosts.
    let result = adapter
        .modify_user(
            token,
            &user_id.to_string(),
            ModifyUserInput {
                comment: Some("updated comment".to_string()),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok(), "modify_user should succeed: {result:?}");
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_user")
        .expect("modify_user command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<comment>updated comment</comment>"));
    assert!(
        xml.contains("<hosts allow=\"1\">192.0.2.0/24</hosts>"),
        "modify_user should preserve existing host restrictions; xml={xml}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_modify_user_preserves_deny_hosts_when_request_omits_hosts() {
    let user_id =
        uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440100").expect("valid user id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .seed(move |store| {
            let mut user = Resource::with_id("user", "restricted-user", user_id);
            user.set_attr("hosts_allow", "0");
            user.set_attr("hosts", "198.51.100.0/24");
            store.create(user);
        })
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();
    server.clear_history();

    // Regression coverage for #274: preserving only the host string is
    // not enough. Deny-mode restrictions must keep allow="0" when an
    // unrelated user update omits hosts.
    let result = adapter
        .modify_user(
            token,
            &user_id.to_string(),
            ModifyUserInput {
                comment: Some("updated comment".to_string()),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok(), "modify_user should succeed: {result:?}");
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_user")
        .expect("modify_user command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<comment>updated comment</comment>"));
    assert!(
        xml.contains("<hosts allow=\"0\">198.51.100.0/24</hosts>"),
        "modify_user should preserve deny-mode host restrictions; xml={xml}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_delete_target() {
    let (adapter, server, token) = create_mock_adapter().await;

    // Create a target first
    let input = CreateTargetInput {
        name: "Delete Me".to_string(),
        comment: None,
        hosts: vec!["10.0.0.1".to_string()],
        exclude_hosts: vec![],
        alive_test: None,
        port_list_id: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    };
    let id = adapter.create_target(&token, input).await.unwrap();

    // Delete the target
    let result = adapter.delete_target(&token, &id, false).await;

    assert!(result.is_ok());

    // Verify it's gone
    let get_result = adapter.get_target(&token, &id).await;
    assert!(matches!(get_result, Err(GatewayError::NotFound(_))));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_direct_lists_emit_backend_pagination_filter() {
    let (adapter, server, token) = create_mock_adapter().await;

    // Regression coverage for issue #210: directly backed gvmd
    // collections must push REST pagination through GMP filters instead
    // of fetching full collections and slicing locally.
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_alerts(
            &token,
            &AlertQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_alerts",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_schedules(
            &token,
            &ScheduleQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_schedules",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_credentials(
            &token,
            &CredentialQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_credentials",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_port_lists(
            &token,
            &PortListQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_port_lists",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_users(
            &token,
            &IdentityQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_users",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_groups(
            &token,
            &IdentityQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_groups",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_roles(
            &token,
            &IdentityQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_roles",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_permissions(
            &token,
            &IdentityQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_permissions",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_targets(
            &token,
            &TargetQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_targets",
        "filter=\"name~Target first=11 rows=10\"",
        2
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_tasks(
            &token,
            &TaskQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_tasks",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_reports(
            &token,
            &ReportQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_reports",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_results(
            &token,
            &ResultQuery {
                filter_string: Some("name=Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_results",
        "filter=\"name=Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.get_report_results(
            &token,
            "550e8400-e29b-41d4-a716-446655440000",
            &ResultQuery {
                filter_string: Some("name=Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_results",
        "filter=\"report_id=550e8400-e29b-41d4-a716-446655440000 name=Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_scan_configs(
            &token,
            &ScanConfigQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_configs",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_scanners(
            &token,
            &ScannerQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_scanners",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_report_formats(
            &token,
            &SupportingResourceQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_report_formats",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_filters(
            &token,
            &SupportingResourceQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_filters",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_tags(
            &token,
            &SupportingResourceQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_tags",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_notes(
            &token,
            &SupportingResourceQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_notes",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_overrides(
            &token,
            &SupportingResourceQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_overrides",
        "filter=\"name~Target first=11 rows=10\""
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_targets_resolves_filter_id_before_paginating() {
    let filter_id =
        uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").expect("valid filter id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .seed(move |store| {
            let mut filter = Resource::with_id("filter", "Saved target filter", filter_id);
            filter.set_attr("term", "name~Saved");
            store.create(filter);
        })
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();
    server.clear_history();

    // Regression coverage for issue #272: real gvmd ignores the
    // inline filter when filter_id is set, so pagination must be
    // composed into the inline filter after resolving the saved term.
    let result = adapter
        .list_targets(
            token,
            &TargetQuery {
                filter_string: Some("comment~web".to_string()),
                filter_id: Some(filter_id.to_string()),
                page: 2,
                per_page: 10,
            },
        )
        .await;

    assert!(result.is_ok(), "target list should succeed: {result:?}");
    let history = server.command_history();
    let target_command = history
        .iter()
        .find(|record| record.command_name() == "get_targets")
        .expect("get_targets command should be recorded");
    let xml = String::from_utf8(target_command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("filter=\"name~Saved comment~web first=11 rows=10\""));
    assert!(!xml.contains("filter_id"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_agents_uses_typed_pagination_and_version_gate() {
    // Agent list parity depends on GMP 22.8-only typed commands. Keep both the
    // pagination filter shape and the unsupported-backend mapping explicit.
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    assert_backend_pagination!(
        adapter,
        server,
        adapter.list_agents(
            &token,
            &AgentQuery {
                filter_string: Some("name~Agent".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_agents",
        "filter=\"name~Agent first=11 rows=10\"",
        2
    );
    server.shutdown().await;

    let (adapter, server, token) = create_mock_adapter().await;
    let error = adapter
        .list_agents(
            &token,
            &AgentQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await
        .expect_err("GMP 22.7 should reject typed agent commands");
    assert!(
        matches!(error, GatewayError::NotImplemented(ref detail) if detail.contains("get_agents")),
        "unsupported command should surface as NotImplemented: {error:?}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_agent_group_list_preserves_trash_query() {
    // Agent-group trash browsing is a public lifecycle contract, so the gvmd
    // adapter must carry the trash selector into the typed backend command.
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    server.clear_history();

    let result = adapter
        .list_agent_groups(
            &token,
            &AgentGroupQuery {
                filter_string: Some("name~Group".to_string()),
                filter_id: None,
                trash: true,
                page: 1,
                per_page: 10,
            },
        )
        .await;

    assert!(
        result.is_ok(),
        "agent-group list should succeed: {result:?}"
    );
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_agent_groups")
        .expect("get_agent_groups command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(
        xml.contains("filter=\"name~Group first=1 rows=10\""),
        "xml={xml}"
    );
    assert!(xml.contains("trash=\"1\""), "xml={xml}");

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_agent_download_helpers_map_typed_payloads() {
    // The agent download endpoints are the most shape-sensitive part of issue
    // #341 because they are not plain JSON CRUD resources.
    let (adapter, server, token) = create_mock_adapter_v22_8().await;

    let instruction = adapter
        .get_agent_installer_instruction(
            &token,
            "08b69003-5fc2-4037-a479-93b440211c73",
            &AgentInstallerInstructionQuery {
                language: "de".to_string(),
                origin_url: "https://manager.example.invalid".to_string(),
            },
        )
        .await
        .expect("installer instruction should succeed");
    assert_eq!(instruction.language, "de");
    assert!(instruction.instruction.contains("mock agent"));

    let bundle = adapter
        .get_agent_support_bundle(
            &token,
            "550e8400-e29b-41d4-a716-446655440000",
            &AgentSupportBundleQuery { days: Some(7) },
        )
        .await
        .expect("support bundle should succeed");
    assert_eq!(bundle.artifact.filename, "mock-agent-support-bundle.tar.gz");
    assert_eq!(bundle.artifact.content_type, "application/octet-stream");
    assert_eq!(&bundle.artifact.bytes[..], b"hello-mock");

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_alerts_filter_id_resolution_does_not_deadlock() {
    let filter_id =
        uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").expect("valid filter id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .seed(move |store| {
            let mut filter = Resource::with_id("filter", "Saved alert filter", filter_id);
            filter.set_attr("term", "name~Saved");
            store.create(filter);
        })
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();
    server.clear_history();

    // Regression coverage for the direct-lock list paths: resolving a
    // saved filter must happen before the session client is locked, or
    // the nested get_filter request waits forever on the same mutex.
    let result = tokio::time::timeout(
        Duration::from_millis(250),
        adapter.list_alerts(
            token,
            &AlertQuery {
                filter_string: Some("comment~web".to_string()),
                filter_id: Some(filter_id.to_string()),
                page: 2,
                per_page: 10,
            },
        ),
    )
    .await;

    let history = server.command_history();
    server.shutdown().await;

    let page = result
        .expect("list_alerts with filterId should not deadlock")
        .expect("list_alerts with filterId should succeed");
    assert_eq!(page.pagination.page, 2);
    assert_eq!(page.pagination.per_page, 10);

    let alert_command = history
        .iter()
        .find(|record| record.command_name() == "get_alerts")
        .expect("get_alerts command should be recorded");
    let xml = String::from_utf8(alert_command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("filter=\"name~Saved comment~web first=11 rows=10\""));
    assert!(!xml.contains("filter_id"));
}

#[tokio::test]
async fn gvmd_adapter_list_reports_requests_summary_metadata_only() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    // Regression coverage for issue #273: report listing maps only
    // report summary metadata, so it must not ask gvmd to embed full
    // report bodies or rely on unsupported report-suppression attrs.
    let result = adapter
        .list_reports(
            &token,
            &ReportQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await;

    assert!(result.is_ok(), "list reports should succeed: {result:?}");
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_reports")
        .expect("get_reports command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("details=\"0\""), "xml={xml}");
    assert!(!xml.contains("details=\"1\""), "xml={xml}");
    assert!(!xml.contains("no_report"), "xml={xml}");

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_hosts_emits_backend_pagination_filter() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let result = adapter
        .list_hosts(
            &token,
            &SupportingResourceQuery {
                filter_string: Some("name~host".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            },
        )
        .await;

    assert!(result.is_ok());
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_assets")
        .expect("get_assets command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<get_assets"));
    assert!(xml.contains("type=\"host\""));
    assert!(xml.contains("filter=\"name~host first=11 rows=10\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_assets_forwards_open_type_and_shared_pagination() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    // Generic asset filters must use rust-gvm's canonical `type` attribute,
    // including known values represented through its forward-compatible type.
    let error = adapter
        .list_assets(
            &token,
            &AssetQuery {
                filter_string: Some("name~certificate".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
                asset_type: "tls_certificate".to_string(),
            },
        )
        .await
        .expect_err("the pinned mock deliberately rejects unsupported asset families");
    assert!(matches!(error, GatewayError::NotFound(_)));

    let command = server
        .command_history()
        .into_iter()
        .find(|record| record.command_name() == "get_assets")
        .expect("get_assets command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("type=\"tls_certificate\""), "xml={xml}");
    assert!(!xml.contains("asset_type="), "xml={xml}");
    assert!(
        xml.contains("filter=\"name~certificate first=11 rows=10\""),
        "xml={xml}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_asset_mutations_emit_comment_only_and_no_ultimate() {
    let (adapter, server, token) = create_mock_adapter().await;
    let id = adapter
        .create_host(
            &token,
            CreateHostInput {
                value: "192.0.2.42".to_string(),
                comment: Some("initial".to_string()),
            },
        )
        .await
        .expect("host seed should be created through typed rust-gvm");
    server.clear_history();

    // The generic surface promises only comment mutation and a single asset
    // delete mode, matching the exact typed command options supported upstream.
    let updated = adapter
        .modify_asset(
            &token,
            &id,
            "host",
            ModifyAssetInput {
                comment: Some("updated".to_string()),
            },
        )
        .await
        .expect("generic asset comment should update");
    assert_eq!(updated.meta.comment.as_deref(), Some("updated"));
    server.clear_history();

    // Complete canonical requests must not turn an omitted patch field into
    // an accidental comment clear; the adapter supplies the stored value.
    let preserved = adapter
        .modify_asset(&token, &id, "host", ModifyAssetInput { comment: None })
        .await
        .expect("omitted generic asset comment should be preserved");
    assert_eq!(preserved.meta.comment.as_deref(), Some("updated"));
    adapter
        .delete_asset(&token, &id)
        .await
        .expect("generic asset should delete");

    let history = server.command_history();
    let modify = history
        .iter()
        .find(|record| record.command_name() == "modify_asset")
        .expect("modify_asset command should be recorded");
    let modify_xml = String::from_utf8(modify.raw_xml().to_vec()).expect("xml command");
    assert!(modify_xml.contains("<comment>updated</comment>"));
    assert!(!modify_xml.contains("<value>"), "xml={modify_xml}");
    let get = history
        .iter()
        .find(|record| record.command_name() == "get_assets")
        .expect("the mutation response read must emit get_assets");
    let get_xml = String::from_utf8(get.raw_xml().to_vec()).expect("xml command");
    assert!(get_xml.contains("type=\"host\""), "xml={get_xml}");
    let delete = history
        .iter()
        .find(|record| record.command_name() == "delete_asset")
        .expect("delete_asset command should be recorded");
    let delete_xml = String::from_utf8(delete.raw_xml().to_vec()).expect("xml command");
    assert!(!delete_xml.contains("ultimate"), "xml={delete_xml}");

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_generic_configs_forward_open_usage_clone_and_ultimate_delete() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    // List usage is open and forwarded by the typed get_configs builder; the
    // cloned identifier and ultimate delete then exercise typed write fidelity.
    let configs = adapter
        .list_configs(
            &token,
            &GenericConfigQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 25,
                usage_type: Some("future_usage".to_string()),
            },
        )
        .await
        .expect("open config usage query should be accepted");
    assert!(configs.data.is_empty());

    // Fetch the mock's canonical config directly because its generic list
    // fixture interprets pagination directives as resource predicates.
    let source_id = "daba56c8-73ec-11df-a475-002264764cea";
    let source = adapter
        .get_config(&token, source_id)
        .await
        .expect("stateful mock should expose its seeded config by id");
    assert_eq!(source.usage_type, "scan");
    let cloned_id = adapter
        .clone_config(&token, source_id)
        .await
        .expect("typed config clone should return an id");
    adapter
        .delete_config(&token, &cloned_id, true)
        .await
        .expect("typed config ultimate delete should succeed");

    let history = server.command_history();
    assert!(history.iter().any(|record| {
        record.command_name() == "get_configs"
            && String::from_utf8_lossy(record.raw_xml())
                .contains("filter=\"usage_type=future_usage")
    }));
    assert!(history.iter().any(|record| {
        record.command_name() == "create_config"
            && String::from_utf8_lossy(record.raw_xml()).contains("<copy>")
    }));
    assert!(history.iter().any(|record| {
        record.command_name() == "delete_config"
            && String::from_utf8_lossy(record.raw_xml()).contains("ultimate=\"1\"")
    }));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_config_create_requires_active_same_usage_bases() {
    // Issue #518 requires deterministic validation before create_config: a
    // scan config can copy only an active scan config, and a policy can copy
    // only an active policy. Exercise valid, wrong-usage, missing, and trashed
    // sources against the canonical stateful lifecycle implementation.
    let (adapter, server, token) = create_mock_adapter().await;
    let scan_base = "daba56c8-73ec-11df-a475-002264764cea";
    let policy_base = "00000000-0000-0000-0000-000000000301";
    let missing_base = "00000000-0000-0000-0000-000000009999";
    server.clear_history();

    let scan_id = adapter
        .create_scan_config(
            &token,
            CreateScanConfigInput {
                name: "Issue 518 scan copy".to_string(),
                comment: Some("scan metadata".to_string()),
                base_scan_config_id: scan_base.to_string(),
            },
        )
        .await
        .expect("active scan base should be copied");
    let policy_id = adapter
        .create_policy(
            &token,
            CreatePolicyInput {
                name: "Issue 518 policy copy".to_string(),
                comment: Some("policy metadata".to_string()),
                base_policy_id: policy_base.to_string(),
            },
        )
        .await
        .expect("active policy base should be copied");

    for error in [
        adapter
            .create_scan_config(
                &token,
                CreateScanConfigInput {
                    name: "Wrong usage scan".to_string(),
                    comment: None,
                    base_scan_config_id: policy_base.to_string(),
                },
            )
            .await
            .expect_err("policy base must be rejected for scan creation"),
        adapter
            .create_scan_config(
                &token,
                CreateScanConfigInput {
                    name: "Missing scan".to_string(),
                    comment: None,
                    base_scan_config_id: missing_base.to_string(),
                },
            )
            .await
            .expect_err("missing scan base must be rejected"),
    ] {
        assert_eq!(
            error,
            GatewayError::InvalidInput(
                "baseScanConfigId must identify an active scan config".to_string()
            )
        );
    }

    for error in [
        adapter
            .create_policy(
                &token,
                CreatePolicyInput {
                    name: "Wrong usage policy".to_string(),
                    comment: None,
                    base_policy_id: scan_base.to_string(),
                },
            )
            .await
            .expect_err("scan base must be rejected for policy creation"),
        adapter
            .create_policy(
                &token,
                CreatePolicyInput {
                    name: "Missing policy".to_string(),
                    comment: None,
                    base_policy_id: missing_base.to_string(),
                },
            )
            .await
            .expect_err("missing policy base must be rejected"),
    ] {
        assert_eq!(
            error,
            GatewayError::InvalidInput("basePolicyId must identify an active policy".to_string())
        );
    }

    adapter
        .delete_scan_config(&token, &scan_id, false)
        .await
        .expect("created scan should move to trash");
    let trashed_scan = adapter
        .create_scan_config(
            &token,
            CreateScanConfigInput {
                name: "Trashed scan source".to_string(),
                comment: None,
                base_scan_config_id: scan_id,
            },
        )
        .await
        .expect_err("trashed scan base must be rejected");
    assert!(matches!(trashed_scan, GatewayError::InvalidInput(_)));

    adapter
        .delete_policy(&token, &policy_id)
        .await
        .expect("created policy should move to trash");
    let trashed_policy = adapter
        .create_policy(
            &token,
            CreatePolicyInput {
                name: "Trashed policy source".to_string(),
                comment: None,
                base_policy_id: policy_id,
            },
        )
        .await
        .expect_err("trashed policy base must be rejected");
    assert!(matches!(trashed_policy, GatewayError::InvalidInput(_)));

    let create_commands = server
        .command_history()
        .into_iter()
        .filter(|record| record.command_name() == "create_config")
        .collect::<Vec<_>>();
    assert_eq!(
        create_commands.len(),
        2,
        "invalid bases must be rejected before create_config"
    );
    let scan_xml = String::from_utf8_lossy(create_commands[0].raw_xml());
    assert!(scan_xml.contains(&format!("<copy>{scan_base}</copy>")));
    assert!(scan_xml.contains("<name>Issue 518 scan copy</name>"));
    assert!(!scan_xml.contains("<usage_type>"));
    let policy_xml = String::from_utf8_lossy(create_commands[1].raw_xml());
    assert!(policy_xml.contains(&format!("<copy>{policy_base}</copy>")));
    assert!(policy_xml.contains("<usage_type>policy</usage_type>"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_config_modify_is_metadata_only_and_reads_back() {
    // Canonical scan/policy modifies must emit metadata only and then perform
    // the existing typed read-back without touching selectors/preferences.
    let (adapter, server, token) = create_mock_adapter().await;
    let scan_id = "00000000-0000-0000-0000-000000000300";
    let policy_id = "00000000-0000-0000-0000-000000000302";
    server.clear_history();

    let scan = adapter
        .modify_scan_config(
            &token,
            scan_id,
            ModifyScanConfigInput {
                name: Some("Renamed discovery scan".to_string()),
                comment: Some("updated scan".to_string()),
            },
        )
        .await
        .expect("scan metadata update should read back");
    assert_eq!(scan.name, "Renamed discovery scan");

    let policy = adapter
        .modify_policy(
            &token,
            policy_id,
            ModifyScanConfigInput {
                name: Some("Renamed empty policy".to_string()),
                comment: Some("updated policy".to_string()),
            },
        )
        .await
        .expect("policy metadata update should read back");
    assert_eq!(policy.name, "Renamed empty policy");

    let history = server.command_history();
    let modifies = history
        .iter()
        .filter(|record| record.command_name() == "modify_config")
        .collect::<Vec<_>>();
    assert_eq!(modifies.len(), 2);
    for modify in modifies {
        let xml = String::from_utf8_lossy(modify.raw_xml());
        assert!(xml.contains("<name>"));
        assert!(xml.contains("<comment>"));
        assert!(
            !xml.contains("usage_type"),
            "metadata modify changed usage: {xml}"
        );
        assert!(
            !xml.contains("preference"),
            "metadata modify touched preferences: {xml}"
        );
        assert!(
            !xml.contains("selection"),
            "metadata modify touched selections: {xml}"
        );
    }
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "get_configs")
            .count(),
        2,
        "each metadata update must retain read-back behavior"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_vulnerabilities_emits_get_vulns() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let _ = adapter
        .list_vulnerabilities(
            &token,
            &SupportingResourceQuery {
                filter_string: Some("name~ssl".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            },
        )
        .await;

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_vulns")
        .expect("list_vulnerabilities should emit a get_vulns command");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<get_vulns"));
    assert!(xml.contains("filter=\"name~ssl first=11 rows=10\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_tls_certificates_emits_backend_pagination_filter() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let result = adapter
        .list_tls_certificates(
            &token,
            &SupportingResourceQuery {
                filter_string: Some("subject_dn~example".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            },
        )
        .await;

    assert!(result.is_ok());
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_tls_certificates")
        .expect("get_tls_certificates command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<get_tls_certificates"));
    assert!(xml.contains("filter=\"subject_dn~example first=11 rows=10\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_audits_scopes_usage_type_audit() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let _ = adapter
        .list_audits(
            &token,
            &TaskQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await;

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_tasks")
        .expect("list_audits should emit a get_tasks command");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("usage_type=\"audit\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_policies_scopes_usage_type_policy() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let _ = adapter
        .list_policies(
            &token,
            &ScanConfigQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await;

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_configs")
        .expect("list_policies should emit a get_configs command");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("usage_type=\"policy\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_audit_scopes_usage_type_audit() {
    let (adapter, server, token) = create_mock_adapter().await;
    let audit_id = uuid::Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0a01).to_string();
    server.clear_history();

    let _ = adapter.get_audit(&token, &audit_id).await;

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_tasks")
        .expect("get_audit should emit an audit-scoped get_tasks command");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("usage_type=\"audit\""), "xml={xml}");
    assert!(
        xml.contains(&format!("uuid={audit_id}")),
        "get_audit must filter to the requested id; xml={xml}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_policy_scopes_usage_type_policy() {
    let (adapter, server, token) = create_mock_adapter().await;
    let policy_id = uuid::Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0b01).to_string();
    server.clear_history();

    let _ = adapter.get_policy(&token, &policy_id).await;

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_configs")
        .expect("get_policy should emit a policy-scoped get_configs command");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("usage_type=\"policy\""), "xml={xml}");
    assert!(
        xml.contains(&format!("uuid={policy_id}")),
        "get_policy must filter to the requested id; xml={xml}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_start_audit_verifies_audit_scope_before_acting() {
    let (adapter, server, token) = create_mock_adapter().await;
    let audit_id = uuid::Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0a02).to_string();
    server.clear_history();

    let _ = adapter.start_audit(&token, &audit_id).await;

    // The audit discriminator is enforced by fetching the audit-scoped task
    // before the lifecycle command would be sent, so a scan task cannot be
    // started through the audit route.
    let history = server.command_history();
    let verify = history
        .iter()
        .find(|record| record.command_name() == "get_tasks")
        .expect("start_audit should verify the audit scope with a get_tasks command");
    let xml = String::from_utf8(verify.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("usage_type=\"audit\""), "xml={xml}");
    assert!(
        xml.contains(&format!("uuid={audit_id}")),
        "start_audit must verify the requested audit id; xml={xml}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_nvts_emits_complete_canonical_context() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let result = adapter
        .list_nvts(
            &token,
            &NvtQuery {
                // Dedicated get_nvts does not accept generic filter attributes;
                // this still exercises public filter validation without
                // fabricating unsupported wire fields.
                filter_string: Some("family=General".to_string()),
                filter_id: None,
                page: 1,
                per_page: 25,
                config_id: Some("daba56c8-73ec-11df-a475-002264764cea".to_string()),
                preferences_config_id: None,
                family: Some("General".to_string()),
                include_preferences: Some(true),
                include_preference_count: Some(false),
                include_timeout: Some(true),
                sort_order: Some("ascending".to_string()),
                sort_field: Some("name".to_string()),
            },
        )
        .await;

    assert!(result.is_ok());
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_nvts")
        .expect("get_nvts command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<get_nvts"));
    assert!(xml.contains("config_id=\"daba56c8-73ec-11df-a475-002264764cea\""));
    assert!(xml.contains("family=\"General\""));
    assert!(
        !xml.contains(" filter="),
        "get_nvts must not regain ignored filters: {xml}"
    );
    assert!(
        !xml.contains("filt_id="),
        "get_nvts must not regain ignored filters: {xml}"
    );
    assert!(!xml.contains("preferences_config_id="));
    assert!(xml.contains("details=\"1\""));
    assert!(xml.contains("preferences=\"1\""));
    assert!(xml.contains("preference_count=\"0\""));
    assert!(xml.contains("timeout=\"1\""));
    assert!(xml.contains("sort_order=\"ascending\""));
    assert!(xml.contains("sort_field=\"name\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_scan_config_nvt_reads_keep_family_and_detail_context() {
    // Config-scoped lists require a family in reviewed gvmd. This regression
    // test protects the adapter's family decomposition and the distinct
    // preference-expanded detail request without changing the REST query.
    let (adapter, server, token) = create_mock_adapter().await;
    let config_id = "daba56c8-73ec-11df-a475-002264764cea";
    let nvt_oid = "1.3.6.1.4.1.25623.1";
    server.clear_history();

    let page = adapter
        .list_scan_config_nvts(
            &token,
            config_id,
            &ScanConfigNvtQuery {
                family: None,
                page: 1,
                per_page: 25,
            },
        )
        .await
        .expect("config-only NVT list should decompose through canonical families");
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.pagination.total, 1);
    assert!(server
        .command_history()
        .iter()
        .any(|record| record.command_name() == "get_nvt_families"));
    let list_xml = recorded_xml(&server, "get_nvts");
    assert!(list_xml.contains(&format!("config_id=\"{config_id}\"")));
    assert!(list_xml.contains("family=\"General\""));
    assert!(list_xml.contains("details=\"1\""));
    assert!(list_xml.contains("preferences=\"1\""));
    assert!(list_xml.contains("preference_count=\"1\""));
    assert!(list_xml.contains("timeout=\"1\""));
    assert!(list_xml.contains("sort_field=\"name\""));

    server.clear_history();
    let nvt = adapter
        .get_scan_config_nvt(&token, config_id, nvt_oid)
        .await
        .expect("scan-config NVT detail should preserve preference context");
    assert_eq!(nvt.oid, nvt_oid);
    let detail_xml = recorded_xml(&server, "get_nvts");
    assert!(detail_xml.contains(&format!("nvt_oid=\"{nvt_oid}\"")));
    assert!(detail_xml.contains(&format!("config_id=\"{config_id}\"")));
    assert!(!detail_xml.contains("family="));
    assert!(detail_xml.contains("details=\"1\""));
    assert!(detail_xml.contains("preferences=\"1\""));
    assert!(detail_xml.contains("preference_count=\"1\""));
    assert!(detail_xml.contains("timeout=\"1\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_report_vulnerabilities_uses_typed_command() {
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    server.clear_history();

    let page = adapter
        .get_report_vulnerabilities(
            &token,
            "550e8400-e29b-41d4-a716-446655440000",
            &ResultQuery {
                filter_string: Some("severity>5".to_string()),
                filter_id: Some("123e4567-e89b-12d3-a456-426614174000".to_string()),
                page: 2,
                per_page: 10,
            },
        )
        .await
        .expect("typed report vulnerabilities");

    assert_eq!(page.pagination.page, 2);
    assert_eq!(page.pagination.per_page, 10);
    assert_eq!(page.pagination.total, 1);
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.data[0].host, None);
    assert_eq!(page.data[0].port, None);
    assert_eq!(page.data[0].severity, Some(5.0));
    assert_eq!(page.data[0].threat.as_deref(), Some("Medium"));
    assert_eq!(page.data[0].hosts_count, Some(2));
    assert_eq!(page.data[0].occurrences, Some(3));
    assert_eq!(
        page.data[0].nvt.as_ref().and_then(|nvt| nvt.oid.as_deref()),
        Some("1.3.6.1.4.1.25623.1.0.117761")
    );
    assert_eq!(
        page.data[0]
            .nvt
            .as_ref()
            .and_then(|nvt| nvt.name.as_deref()),
        Some("SSL/TLS Renegotiation Vulnerability")
    );
    assert_eq!(
        page.data[0]
            .nvt
            .as_ref()
            .map(|nvt| nvt.cves.clone())
            .unwrap_or_default(),
        vec!["CVE-2011-1473".to_string(), "CVE-2011-5094".to_string()]
    );

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_report_vulns")
        .expect("get_report_vulns command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("report_id=\"550e8400-e29b-41d4-a716-446655440000\""));
    assert!(xml.contains("filter=\"threat=Alarm severity&gt;5 first=11 rows=10\""));
    assert!(!xml.contains("filter_id"));
    assert!(xml.contains("details=\"1\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_report_vulnerabilities_returns_not_implemented_on_v22_7() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let error = adapter
        .get_report_vulnerabilities(
            &token,
            "550e8400-e29b-41d4-a716-446655440000",
            &ResultQuery {
                filter_string: Some("severity>5".to_string()),
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await
        .expect_err("v22.7 should return not implemented");

    assert!(
        matches!(error, GatewayError::NotImplemented(detail) if detail.contains("get_report_vulns"))
    );

    let history = server.command_history();
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "get_results")
            .count(),
        0
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_credential_stores_uses_typed_backend_response() {
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    server.clear_history();

    let stores = adapter
        .list_credential_stores(&token)
        .await
        .expect("typed credential stores");

    assert_eq!(stores.len(), 1);
    assert_eq!(stores[0].id.as_deref(), Some("local"));
    assert_eq!(stores[0].name, "Local credential store");
    assert_eq!(stores[0].provider.as_deref(), Some("local"));
    assert_eq!(stores[0].default, None);
    assert_eq!(stores[0].writable, None);

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_credential_stores")
        .expect("get_credential_stores command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<get_credential_stores"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_credential_store_item_update_and_verify_use_typed_commands() {
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    server.clear_history();
    let id = "123e4567-e89b-12d3-a456-426614174000";

    let store = adapter
        .get_credential_store(&token, id)
        .await
        .expect("credential store item response");
    assert_eq!(store.name, "Local credential store");

    adapter
        .modify_credential_store(
            &token,
            id,
            ModifyCredentialStoreInput {
                active: Some(true),
                host: Some("vault.internal".to_string()),
                path: Some("/v1".to_string()),
                port: Some(8200),
                comment: Some("Vault".to_string()),
                preferences: vec![CredentialStorePreferenceInput {
                    name: "token".to_string(),
                    value: "write-only-token".to_string(),
                }],
            },
        )
        .await
        .expect("credential store update");
    adapter
        .verify_credential_store(&token, id)
        .await
        .expect("credential store verification");

    let history = server.command_history();
    let modify = history
        .iter()
        .find(|record| record.command_name() == "modify_credential_store")
        .expect("modify command should be recorded");
    let xml = String::from_utf8(modify.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("credential_store_id=\"123e4567-e89b-12d3-a456-426614174000\""));
    assert!(xml.contains("<host>vault.internal</host>"));
    assert!(xml.contains("<name>token</name>"));
    assert!(xml.contains("<value>write-only-token</value>"));
    assert!(history
        .iter()
        .any(|record| record.command_name() == "verify_credential_store"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_store_backed_credential_create_and_update_forward_vault_references() {
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    server.clear_history();

    let credential_id = adapter
        .create_credential(
            &token,
            CreateCredentialInput {
                name: "Vault credential".to_string(),
                credential_type: "cs_up".to_string(),
                credential_store_id: Some("123e4567-e89b-12d3-a456-426614174000".to_string()),
                vault_id: Some("secret/data/service".to_string()),
                host_identifier: Some("production".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("store-backed credential create");
    adapter
        .modify_credential(
            &token,
            &credential_id,
            ModifyCredentialInput {
                vault_id: Some("secret/data/service-v2".to_string()),
                host_identifier: Some("staging".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("store-backed credential update");

    let history = server.command_history();
    let create = history
        .iter()
        .find(|record| record.command_name() == "create_credential")
        .expect("create command should be recorded");
    let create_xml = String::from_utf8(create.raw_xml().to_vec()).expect("xml command");
    assert!(create_xml.contains("<type>cs_up</type>"));
    assert!(create_xml.contains("<vault_id>secret/data/service</vault_id>"));
    assert!(create_xml.contains("<host_identifier>production</host_identifier>"));
    let modify = history
        .iter()
        .find(|record| record.command_name() == "modify_credential")
        .expect("modify command should be recorded");
    let modify_xml = String::from_utf8(modify.raw_xml().to_vec()).expect("xml command");
    assert!(modify_xml.contains("<vault_id>secret/data/service-v2</vault_id>"));
    assert!(modify_xml.contains("<host_identifier>staging</host_identifier>"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_credential_stores_returns_not_implemented_on_v22_7() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let error = adapter
        .list_credential_stores(&token)
        .await
        .expect_err("v22.7 should return not implemented");

    assert!(matches!(
        error,
        GatewayError::NotImplemented(detail) if detail.contains("get_credential_stores")
    ));
    assert_eq!(
        server
            .command_history()
            .into_iter()
            .filter(|record| record.command_name() == "get_credential_stores")
            .count(),
        0,
        "unsupported backends should return the cached 501 capability result without probing again"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_credential_stores_returns_not_implemented_when_gvmd_disables_command() {
    let (adapter, server, token) = create_mock_adapter_v22_8_with_credential_store_error(
        "Service unavailable: Command disabled",
    )
    .await;
    server.clear_history();

    // Regression coverage for PR #463 live E2E: gvmd 22.8 may advertise the
    // command by version but disable it at runtime, returning a typed 503
    // parse-status response instead of an UnsupportedCommand client error.
    let error = adapter
        .list_credential_stores(&token)
        .await
        .expect_err("disabled credential-store command should return not implemented");

    assert!(matches!(
        error,
        GatewayError::NotImplemented(detail) if detail.contains("get_credential_stores")
    ));
    assert_eq!(
        server
            .command_history()
            .into_iter()
            .filter(|record| record.command_name() == "get_credential_stores")
            .count(),
        0,
        "disabled-command capability absence should be cached after connect_session"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_credential_stores_keeps_unrelated_503_as_backend_unavailable() {
    let (adapter, server, token) = create_mock_adapter_v22_8_with_credential_store_error(
        "Service unavailable: database offline",
    )
    .await;
    server.clear_history();

    // A same-endpoint backend outage without the disabled-command reason must
    // keep the generic 502 REST behavior through GatewayError::BackendUnavailable.
    let error = adapter
        .list_credential_stores(&token)
        .await
        .expect_err("unrelated backend 503 should remain backend unavailable");

    assert!(matches!(
        error,
        GatewayError::BackendUnavailable(detail) if detail.contains("database offline")
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_refreshes_cached_session_after_disabled_credential_store_response() {
    let (adapter, server, token) =
        create_mock_adapter_v22_8_with_disabled_credential_stores_followed_by_disconnect().await;
    server.clear_history();

    // Regression coverage for GitHub E2E run 33263885269 on 2026-08-29:
    // connect_session must consume the disabled-command capability probe,
    // restore the authenticated socket before publishing the session, and let
    // later routes observe 501 plus a healthy credentials list.
    let error = adapter
        .list_credential_stores(&token)
        .await
        .expect_err("disabled credential-store command should still return not implemented");
    assert!(
        matches!(
            error,
            GatewayError::NotImplemented(ref detail) if detail.contains("get_credential_stores")
        ),
        "unexpected credential-store error: {error:?}"
    );

    let page = adapter
        .list_credentials(
            &token,
            &CredentialQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 1000,
            },
        )
        .await
        .expect("credentials should succeed after the cached session reconnects");

    assert_eq!(page.pagination.page, 1);
    assert_eq!(page.pagination.per_page, 1000);

    let history = server.command_history();
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "authenticate")
            .count(),
        0,
        "the reconnect should happen during connect_session, before history is cleared"
    );
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "get_credential_stores")
            .count(),
        0,
        "list_credential_stores should use the cached unsupported capability state"
    );
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "get_credentials")
            .count(),
        1,
        "credential listing should use the refreshed session instead of failing on a stale socket"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_reconnects_before_caching_unknown_credential_store_capability() {
    let (adapter, server, token) =
        create_mock_adapter_v22_8_with_unknown_credential_store_probe_followed_by_disconnect()
            .await;
    server.clear_history();

    // If the connect-time capability probe fails for a non-capability reason,
    // the adapter must still reconnect before publishing the session. That
    // keeps subsequent commands off a potentially poisoned socket even though
    // `/credential-stores` must keep probing live and may still fail later.
    let page = adapter
        .list_credentials(
            &token,
            &CredentialQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 1000,
            },
        )
        .await
        .expect("credentials should succeed after the unknown probe reconnects");

    assert_eq!(page.pagination.page, 1);
    assert_eq!(page.pagination.per_page, 1000);

    let error = adapter
        .list_credential_stores(&token)
        .await
        .expect_err("unknown credential-store failures should stay backend unavailable");
    assert!(
        matches!(error, GatewayError::BackendUnavailable(_)),
        "unexpected credential-store error: {error:?}"
    );

    let history = server.command_history();
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "authenticate")
            .count(),
        0,
        "the reconnect should happen during connect_session, before history is cleared"
    );
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "get_credential_stores")
            .count(),
        1,
        "unknown capability state must keep probing `/credential-stores` live"
    );
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "get_credentials")
            .count(),
        1,
        "credentials should use the refreshed session instead of failing on the stale connect-time probe socket"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_report_tls_certificates_uses_typed_command() {
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    server.clear_history();

    let page = adapter
        .get_report_tls_certificates(
            &token,
            "550e8400-e29b-41d4-a716-446655440000",
            &ResultQuery {
                filter_string: Some("subject~example".to_string()),
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await
        .expect("typed report tls certificates");

    assert_eq!(page.pagination.total, 1);
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.data[0].subject, "CN=example.com");
    assert_eq!(page.data[0].issuer.as_deref(), Some("CN=Example CA"));
    assert_eq!(
        page.data[0].not_after.as_deref(),
        Some("2027-01-01T00:00:00Z")
    );

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_report_tls_certificates")
        .expect("get_report_tls_certificates command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("report_id=\"550e8400-e29b-41d4-a716-446655440000\""));
    assert!(xml.contains("filter=\"subject~example first=1 rows=25\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_report_results_resolves_filter_id_into_inline_filter() {
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    server.clear_history();

    // Regression coverage for issue #272: gvmd ignores inline filter
    // and pagination attributes when filter_id is set, so the adapter
    // must resolve saved filters and send one composed inline filter.
    let _ = adapter
        .get_report_results(
            &token,
            "550e8400-e29b-41d4-a716-446655440000",
            &ResultQuery {
                filter_string: Some("severity>5".to_string()),
                filter_id: Some("123e4567-e89b-12d3-a456-426614174000".to_string()),
                page: 1,
                per_page: 25,
            },
        )
        .await
        .expect("results with filter id");

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_results")
        .expect("get_results command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains(
            "filter=\"threat=Alarm report_id=550e8400-e29b-41d4-a716-446655440000 severity&gt;5 first=1 rows=25\""
        ));
    assert!(!xml.contains("filter_id"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_report_embeds_requested_result_window_larger_than_25() {
    let report_id =
        uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid report id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .seed(move |store| {
            store.create(Resource::with_id(
                "report",
                "Large embedded report",
                report_id,
            ));

            // Regression coverage for issue #230: the single-report
            // path must honor the requested embedded-result window
            // instead of silently forcing the old 25-row window.
            for index in 0..30 {
                let result_id = uuid::Uuid::new_v5(&report_id, &[index]);
                let mut result =
                    Resource::with_id("result", &format!("Embedded result {index}"), result_id);
                result.set_attr("report_id", &report_id.to_string());
                result.set_attr("first", "1");
                result.set_attr("rows", "30");
                result.set_attr("host", "192.0.2.10");
                result.set_attr("port", "443/tcp");
                result.set_attr("severity", "5.0");
                store.create(result);
            }
        })
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();
    server.clear_history();

    let report = adapter
        .get_report(
            token,
            &report_id.to_string(),
            &GetReportOpts {
                page: 1,
                per_page: 30,
            },
        )
        .await
        .expect("report with embedded result window");

    assert_eq!(report.results.len(), 30);

    let history = server.command_history();
    let report_command = history
        .iter()
        .find(|record| record.command_name() == "get_reports")
        .expect("get_reports command should be recorded");
    let report_xml = String::from_utf8(report_command.raw_xml().to_vec()).expect("xml command");
    assert!(
        report_xml.contains("report_id=\"550e8400-e29b-41d4-a716-446655440000\""),
        "xml={report_xml}"
    );
    assert!(report_xml.contains("details=\"0\""), "xml={report_xml}");
    assert!(!report_xml.contains("details=\"1\""), "xml={report_xml}");

    let command = history
        .iter()
        .find(|record| record.command_name() == "get_results")
        .expect("get_results command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("report_id=550e8400-e29b-41d4-a716-446655440000"));
    assert!(xml.contains("first=1 rows=30"));
    assert!(!xml.contains("first=25 rows=25"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_report_errors_uses_typed_command() {
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    server.clear_history();

    let page = adapter
        .get_report_errors(
            &token,
            "550e8400-e29b-41d4-a716-446655440000",
            &ResultQuery {
                filter_string: Some("threat=Alarm".to_string()),
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await
        .expect("typed report errors");

    assert_eq!(page.pagination.total, 1);
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.data[0].name.as_deref(), Some("Host dead"));
    assert_eq!(
        page.data[0].description.as_deref(),
        Some("Could not reach host.")
    );
    assert_eq!(page.data[0].nvt_name.as_deref(), Some("Ping Host"));
    assert_eq!(page.data[0].host.as_deref(), Some("192.0.2.20"));

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_report_errors")
        .expect("get_report_errors command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("filter=\"threat=Alarm first=1 rows=25\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_report_closed_cves_uses_typed_command() {
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    server.clear_history();

    let page = adapter
        .get_report_closed_cves(
            &token,
            "550e8400-e29b-41d4-a716-446655440000",
            &ResultQuery {
                filter_string: Some("severity>4".to_string()),
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await
        .expect("typed report closed cves");

    assert_eq!(page.pagination.total, 1);
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.data[0].cve.as_deref(), Some("CVE-2025-9999"));
    assert_eq!(page.data[0].severity, Some(5.0));
    assert_eq!(page.data[0].threat.as_deref(), Some("Medium"));
    assert_eq!(
        page.data[0]
            .nvt
            .as_ref()
            .map(|nvt| nvt.cves.clone())
            .unwrap_or_default(),
        vec!["CVE-2025-9999".to_string()]
    );

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_report_closed_cves")
        .expect("get_report_closed_cves command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("filter=\"severity&gt;4 first=1 rows=25\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_report_summary_drill_downs_use_typed_commands() {
    // Issue #344 requires five distinct report-summary contracts. This test
    // guards both their typed response mapping and their shared backend
    // filter/pagination command shape without coercing them into generic assets.
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    server.clear_history();
    let report_id = "550e8400-e29b-41d4-a716-446655440000";
    let query = ResultQuery {
        filter_string: Some("severity>3".to_string()),
        filter_id: None,
        page: 1,
        per_page: 10,
    };

    let hosts = adapter
        .get_report_hosts(&token, report_id, &query)
        .await
        .expect("typed report hosts");
    let ports = adapter
        .get_report_ports(&token, report_id, &query)
        .await
        .expect("typed report ports");
    let applications = adapter
        .get_report_applications(&token, report_id, &query)
        .await
        .expect("typed report applications");
    let operating_systems = adapter
        .get_report_operating_systems(&token, report_id, &query)
        .await
        .expect("typed report operating systems");
    let cves = adapter
        .get_report_cves(&token, report_id, &query)
        .await
        .expect("typed report CVEs");

    assert_eq!(hosts.data[0].name.as_deref(), Some("192.0.2.10"));
    assert_eq!(ports.data[0].name.as_deref(), Some("22/tcp"));
    assert_eq!(applications.data[0].name.as_deref(), Some("OpenSSH"));
    assert_eq!(operating_systems.data[0].name.as_deref(), Some("Debian"));
    assert_eq!(cves.data[0].name.as_deref(), Some("CVE-2026-0001"));

    for command_name in [
        "get_report_hosts",
        "get_report_ports",
        "get_report_applications",
        "get_report_operating_systems",
        "get_report_cves",
    ] {
        let xml = recorded_xml(&server, command_name);
        assert!(
            xml.contains(&format!("report_id=\"{report_id}\"")),
            "xml={xml}"
        );
        assert!(
            xml.contains("filter=\"severity&gt;3 first=1 rows=10\""),
            "xml={xml}"
        );
        assert!(xml.contains("details=\"1\""), "xml={xml}");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_report_summary_drill_down_maps_unsupported_version() {
    // gvmd 22.7 predates these report-detail commands. The adapter must expose
    // the negotiated capability failure instead of falling back to generic
    // results or attempting local GMP parsing.
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let error = adapter
        .get_report_hosts(
            &token,
            "550e8400-e29b-41d4-a716-446655440000",
            &ResultQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await
        .expect_err("gvmd 22.7 must not claim report-host support");

    assert!(
        matches!(error, GatewayError::NotImplemented(detail) if detail.contains("get_report_hosts"))
    );
    assert!(server.command_history().is_empty());

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_operating_system_reads_preserve_typed_asset_fields() {
    // OS resources use the typed asset view, including backend ownership flags
    // and severity/install aggregates, rather than the generic asset schema.
    let os_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440131")
        .expect("valid operating-system id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .seed(move |store| {
            let mut operating_system =
                Resource::with_id("asset", "cpe:/o:debian:debian_linux:12", os_id);
            operating_system.comment = "discovered OS".to_string();
            operating_system.set_attr("type", "os");
            operating_system.set_attr("title", "Debian GNU/Linux 12");
            operating_system.set_attr("installs", "0");
            operating_system.set_attr("all_installs", "4");
            operating_system.set_attr("latest_severity", "4.2");
            operating_system.set_attr("highest_severity", "8.1");
            operating_system.set_attr("average_severity", "5.3");
            store.create(operating_system);
        })
        .unix_socket_auto()
        .build()
        .await
        .unwrap();
    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();
    server.clear_history();

    let page = adapter
        .list_operating_systems(
            token,
            &SupportingResourceQuery {
                filter_string: Some("name=cpe:/o:debian:debian_linux:12".to_string()),
                filter_id: None,
                page: 1,
                per_page: 10,
            },
        )
        .await
        .expect("typed OS list");
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.data[0].title, "Debian GNU/Linux 12");
    assert_eq!(page.data[0].all_installs, 4);
    assert_eq!(page.data[0].highest_severity.as_deref(), Some("8.1"));
    assert!(!page.data[0].meta.writable);
    // The canonical OS parser derives in-use state from all installations,
    // even when the filtered/current installation count is zero.
    assert!(page.data[0].meta.in_use);

    let fetched = adapter
        .get_operating_system(token, &os_id.to_string())
        .await
        .expect("typed OS get");
    assert_eq!(fetched.meta.id, os_id.to_string());
    assert_eq!(fetched.meta.comment.as_deref(), Some("discovered OS"));

    let history = server.command_history();
    let list_xml = history
        .iter()
        .find(|record| {
            record.command_name() == "get_assets"
                && String::from_utf8_lossy(record.raw_xml()).contains("filter=")
        })
        .map(|record| String::from_utf8_lossy(record.raw_xml()).into_owned())
        .expect("OS list command should be recorded");
    assert!(list_xml.contains("type=\"os\""), "xml={list_xml}");
    assert!(
        list_xml.contains("filter=\"name=cpe:/o:debian:debian_linux:12 first=1 rows=10\""),
        "xml={list_xml}"
    );
    let get_xml = history
        .iter()
        .find(|record| {
            record.command_name() == "get_assets"
                && String::from_utf8_lossy(record.raw_xml()).contains("asset_id=")
        })
        .map(|record| String::from_utf8_lossy(record.raw_xml()).into_owned())
        .expect("OS get command should be recorded");
    assert!(
        get_xml.contains(&format!("asset_id=\"{os_id}\"")),
        "xml={get_xml}"
    );
    assert!(get_xml.contains("type=\"os\""), "xml={get_xml}");

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_operating_system_mutations_use_canonical_asset_requests() {
    // The removed OS-specific transition request must be replaced by the
    // canonical complete asset request without changing this domain route.
    // The mock rejects the mutation, but its history proves the typed shape.
    let removable_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440132")
        .expect("valid operating-system id");
    let in_use_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440133")
        .expect("valid operating-system id");
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .seed(move |store| {
            for (id, installs) in [(removable_id, "0"), (in_use_id, "2")] {
                let mut operating_system = Resource::with_id("asset", "Debian", id);
                operating_system.set_attr("type", "os");
                operating_system.set_attr("title", "Debian GNU/Linux");
                operating_system.set_attr("installs", installs);
                store.create(operating_system);
            }
        })
        .unix_socket_auto()
        .build()
        .await
        .unwrap();
    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();
    server.clear_history();

    let modify_error = adapter
        .modify_operating_system(
            token,
            &removable_id.to_string(),
            ModifyOperatingSystemInput {
                comment: Some("reviewed".to_string()),
            },
        )
        .await
        .expect_err("stateful mock does not mutate OS comments yet");
    assert!(matches!(modify_error, GatewayError::NotFound(_)));
    let modify_xml = recorded_xml(&server, "modify_asset");
    assert!(modify_xml.contains(&format!("asset_id=\"{removable_id}\"")));
    assert!(modify_xml.contains("<comment>reviewed</comment>"));
    assert!(!modify_xml.contains("<name>"));
    assert!(!modify_xml.contains("<value>"));

    let conflict = adapter
        .delete_operating_system(token, &in_use_id.to_string())
        .await
        .expect_err("an installed OS asset must be protected");
    assert!(matches!(conflict, GatewayError::Conflict(_)));

    adapter
        .delete_operating_system(token, &removable_id.to_string())
        .await
        .expect("unused OS asset should be deleted");
    let delete_commands = server
        .command_history()
        .into_iter()
        .filter(|record| record.command_name() == "delete_asset")
        .collect::<Vec<_>>();
    assert_eq!(delete_commands.len(), 2);
    for command in delete_commands {
        let xml = String::from_utf8(command.raw_xml().to_vec()).expect("delete XML");
        assert!(!xml.contains("ultimate="), "xml={xml}");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_targets_unauthorized() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    // Don't authenticate

    let result = adapter
        .list_targets(
            "unauthed-token",
            &TargetQuery {
                filter_string: None,
                filter_id: None,
                page: 1,
                per_page: 25,
            },
        )
        .await;

    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_export_report_binary_payload() {
    let report_id = uuid::Uuid::from_u128(0x11111111_1111_1111_1111_111111111111);
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .seed(move |store| {
            store.create(Resource::with_id(
                "report",
                "Binary export report",
                report_id,
            ));
        })
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();

    let export = adapter
        .export_report(
            token,
            &report_id.to_string(),
            &ReportExportRequest {
                report_format_id: REPORT_EXPORT_BINARY_FORMAT_ID.to_string(),
                report_config_id: None,
                filter: None,
                filter_id: None,
            },
        )
        .await
        .expect("binary export");

    assert_eq!(export.bytes, b"Hello PDF");
    assert_eq!(export.content_type.as_deref(), Some("application/pdf"));
    assert_eq!(export.extension.as_deref(), Some("pdf"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_export_report_emits_config_and_filter_options() {
    let report_id = uuid::Uuid::from_u128(0x33333333_3333_3333_3333_333333333333);
    let report_config_id =
        uuid::Uuid::from_u128(0x44444444_4444_4444_4444_444444444444).to_string();
    let filter_id = uuid::Uuid::from_u128(0x55555555_5555_5555_5555_555555555555).to_string();
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .seed(move |store| {
            store.create(Resource::with_id(
                "report",
                "Filtered export report",
                report_id,
            ));
        })
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();
    server.clear_history();

    // The mock backend may reject unknown report configs, but command
    // history still verifies that the adapter delegates all supported
    // export options to rust-gvm's typed command builder.
    let _ = adapter
        .export_report(
            token,
            &report_id.to_string(),
            &ReportExportRequest {
                report_format_id: REPORT_EXPORT_BINARY_FORMAT_ID.to_string(),
                report_config_id: Some(report_config_id.clone()),
                filter: Some("severity>5".to_string()),
                filter_id: Some(filter_id.clone()),
            },
        )
        .await;

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "get_reports")
        .expect("get_reports command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains(&format!("format_id=\"{REPORT_EXPORT_BINARY_FORMAT_ID}\"")));
    assert!(xml.contains(&format!("config_id=\"{report_config_id}\"")));
    assert!(xml.contains("filter=\"severity&gt;5\""));
    assert!(xml.contains(&format!("filt_id=\"{filter_id}\"")));
    assert!(xml.contains(&format!("report_id=\"{report_id}\"")));
    assert!(xml.contains("details=\"1\""));
    assert!(xml.contains("ignore_pagination=\"1\""));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_export_report_xml_payload() {
    let report_id = uuid::Uuid::from_u128(0x22222222_2222_2222_2222_222222222222);
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .seed(move |store| {
            store.create(Resource::with_id("report", "XML export report", report_id));
        })
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let token = "test-session-token";
    adapter
        .connect_session(token, "admin", "admin")
        .await
        .unwrap();

    let export = adapter
        .export_report(
            token,
            &report_id.to_string(),
            &ReportExportRequest {
                report_format_id: REPORT_EXPORT_XML_FORMAT_ID.to_string(),
                report_config_id: None,
                filter: None,
                filter_id: None,
            },
        )
        .await
        .expect("xml export");

    let xml = String::from_utf8(export.bytes).expect("utf8 xml");
    assert_eq!(export.content_type.as_deref(), Some("text/xml"));
    assert_eq!(export.extension.as_deref(), Some("xml"));
    assert!(xml.contains("<report id="));
    assert!(xml.contains(r#"<result id="result-1"/>"#));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_clone_target() {
    let (adapter, server, token) = create_mock_adapter().await;

    let input = CreateTargetInput {
        name: "Clone Source".to_string(),
        comment: None,
        hosts: vec!["10.0.0.5".to_string()],
        exclude_hosts: vec![],
        alive_test: None,
        port_list_id: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    };
    let source_id = adapter.create_target(&token, input).await.unwrap();

    let clone_id = adapter.clone_target(&token, &source_id).await.unwrap();

    assert!(!clone_id.is_empty());
    assert_ne!(clone_id, source_id);
    // The clone is an independent, retrievable target.
    assert!(adapter.get_target(&token, &clone_id).await.is_ok());

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_clone_task_emits_copy_command() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    // The task need not exist in the mock: cloning must emit a create_task
    // command carrying the source id in a <copy> element.
    let source_id = "550e8400-e29b-41d4-a716-446655440030";
    let _ = adapter.clone_task(&token, source_id).await;

    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "create_task")
        .expect("clone_task should emit a create_task command");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains(&format!("<copy>{source_id}</copy>")));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_create_task_emits_each_typed_target_variant() {
    let (adapter, server, token) = create_mock_adapter_v22_8().await;
    let scanner_id = "11111111-1111-1111-1111-111111111111";
    let target_id = "22222222-2222-2222-2222-222222222222";
    let config_id = "33333333-3333-3333-3333-333333333333";
    let input = |name: &str, target| CreateTaskInput {
        name: name.to_string(),
        comment: Some("typed selector".to_string()),
        target,
        schedule_id: None,
        alert_ids: vec![],
        alterable: Some(true),
        hosts_ordering: None,
        observers: vec![],
        schedule_periods: None,
        preferences: vec![],
    };

    server.clear_history();
    let _ = adapter
        .create_task(
            &token,
            input(
                "Classic",
                CreateTaskTarget::Classic {
                    target_id: target_id.to_string(),
                    scan_config_id: config_id.to_string(),
                    scanner_id: scanner_id.to_string(),
                },
            ),
        )
        .await;
    let xml = recorded_xml(&server, "create_task");
    assert!(xml.contains(&format!("<target id=\"{target_id}\"")));
    assert!(xml.contains(&format!("<config id=\"{config_id}\"")));

    server.clear_history();
    let _ = adapter
        .create_task(
            &token,
            input(
                "Agents",
                CreateTaskTarget::AgentGroup {
                    agent_group_id: target_id.to_string(),
                    scanner_id: scanner_id.to_string(),
                },
            ),
        )
        .await;
    assert!(
        recorded_xml(&server, "create_task").contains(&format!("<agent_group id=\"{target_id}\""))
    );

    server.clear_history();
    let _ = adapter
        .create_task(
            &token,
            input(
                "Container",
                CreateTaskTarget::OciImage {
                    oci_image_target_id: target_id.to_string(),
                    scanner_id: scanner_id.to_string(),
                },
            ),
        )
        .await;
    assert!(recorded_xml(&server, "create_task")
        .contains(&format!("<oci_image_target id=\"{target_id}\"")));

    server.clear_history();
    let _ = adapter
        .create_task(
            &token,
            input(
                "Web",
                CreateTaskTarget::WebApplication {
                    web_application_target_id: target_id.to_string(),
                    scanner_id: scanner_id.to_string(),
                },
            ),
        )
        .await;
    assert!(recorded_xml(&server, "create_task")
        .contains(&format!("<web_application_target id=\"{target_id}\"")));

    server.clear_history();
    let import = CreateTaskInput {
        name: "Import".to_string(),
        comment: Some("report owner".to_string()),
        target: CreateTaskTarget::Import,
        schedule_id: None,
        alert_ids: vec![],
        alterable: None,
        hosts_ordering: None,
        observers: vec![],
        schedule_periods: None,
        preferences: vec![],
    };
    let _ = adapter.create_task(&token, import).await;
    let xml = recorded_xml(&server, "create_task");
    assert!(xml.contains("<target id=\"0\""));
    assert!(!xml.contains("<scanner"));

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_feed_filter_uses_typed_command_and_preserves_access_flags() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let feeds = adapter
        .list_feeds(
            &token,
            &FeedQuery {
                feed_type: Some("NVT".to_string()),
            },
        )
        .await
        .expect("filtered feed list");

    let xml = recorded_xml(&server, "get_feeds");
    assert!(xml.contains("type=\"NVT\""));
    assert!(feeds.data.iter().all(|feed| feed.feed_type == "NVT"));

    let error = adapter
        .list_feeds(
            &token,
            &FeedQuery {
                feed_type: Some("FUTURE".to_string()),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, GatewayError::InvalidInput(message) if message.contains("FUTURE")));

    server.shutdown().await;
}

fn recorded_xml(server: &MockGmpServer, command_name: &str) -> String {
    let history = server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == command_name)
        .unwrap_or_else(|| panic!("{command_name} command should be recorded"));
    String::from_utf8(command.raw_xml().to_vec()).expect("xml command should be UTF-8")
}

#[tokio::test]
async fn gvmd_adapter_list_cves_uses_typed_secinfo_request_with_pagination_filter() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let page = adapter
        .list_cves(
            &token,
            &SupportingResourceQuery {
                // The reviewed mock deliberately rejects its old permissive
                // `~` fixture syntax. Use a supported inline sort term while
                // still verifying filter and pagination forwarding.
                filter_string: Some("sort=name".to_string()),
                filter_id: None,
                page: 2,
                per_page: 1,
            },
        )
        .await
        .expect("list_cves should succeed against the mock backend");

    assert_eq!(page.data.len(), 1);
    assert_eq!(page.pagination.page, 2);
    assert_eq!(page.pagination.per_page, 1);
    assert_eq!(page.pagination.total, 2);
    assert_eq!(page.pagination.total_pages, 2);
    let xml = recorded_xml(&server, "get_info");
    assert!(xml.contains("type=\"CVE\""), "xml={xml}");
    assert!(
        xml.contains("filter=\"sort=name first=2 rows=1\""),
        "xml={xml}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_get_cert_bund_advisory_uses_typed_secinfo_item_lookup() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let advisory = adapter
        .get_cert_bund_advisory(&token, "CB-K26/001")
        .await
        .expect("get_cert_bund_advisory should succeed against the mock backend");

    assert_eq!(advisory.id, "CB-K26/001");
    assert_eq!(advisory.name, "CERT-Bund advisory one");
    let xml = recorded_xml(&server, "get_info");
    assert!(xml.contains("type=\"CERT_BUND_ADV\""), "xml={xml}");
    assert!(xml.contains("details=\"1\""), "xml={xml}");
    assert!(xml.contains("info_id=\"CB-K26/001\""), "xml={xml}");

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_create_filter_emits_name_and_term() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let _ = adapter
        .create_filter(
            &token,
            CreateFilterInput {
                name: "High severity".to_string(),
                comment: Some("saved".to_string()),
                term: Some("severity>7".to_string()),
                filter_type: Some("result".to_string()),
            },
        )
        .await;

    let xml = recorded_xml(&server, "create_filter");
    assert!(xml.contains("<name>High severity</name>"), "xml={xml}");
    assert!(xml.contains("<term>severity&gt;7</term>"), "xml={xml}");
    assert!(xml.contains("<type>result</type>"), "xml={xml}");

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_clone_filter_emits_copy() {
    let (adapter, server, token) = create_mock_adapter().await;
    let filter_id = uuid::Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_00f1).to_string();
    server.clear_history();

    let _ = adapter.clone_filter(&token, &filter_id).await;

    let xml = recorded_xml(&server, "create_filter");
    assert!(
        xml.contains(&format!("<copy>{filter_id}</copy>")),
        "clone should copy the source filter id; xml={xml}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_create_tag_emits_name_and_resource() {
    let (adapter, server, token) = create_mock_adapter().await;
    let resource_id = uuid::Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_00a1).to_string();
    server.clear_history();

    let _ = adapter
        .create_tag(
            &token,
            CreateTagInput {
                name: "owner:alice".to_string(),
                comment: None,
                value: Some("alice".to_string()),
                resource_type: Some("task".to_string()),
                resource_id: Some(resource_id.clone()),
                active: Some(true),
            },
        )
        .await;

    let xml = recorded_xml(&server, "create_tag");
    assert!(xml.contains("<name>owner:alice</name>"), "xml={xml}");
    assert!(xml.contains("<type>task</type>"), "xml={xml}");
    assert!(
        xml.contains(&format!("id=\"{resource_id}\"")),
        "tag should reference the resource id; xml={xml}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_create_host_emits_asset() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let _ = adapter
        .create_host(
            &token,
            CreateHostInput {
                value: "192.0.2.10".to_string(),
                comment: Some("lab host".to_string()),
            },
        )
        .await;

    let xml = recorded_xml(&server, "create_asset");
    assert!(xml.contains("<type>host</type>"), "xml={xml}");
    assert!(xml.contains("<name>192.0.2.10</name>"), "xml={xml}");

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_timezones_returns_backend_catalog_on_v22_8() {
    // The timezone catalog must come from gvmd itself so the gateway does not
    // reintroduce the proxy-local zoneinfo divergence removed in PR #312.
    let (adapter, server, token) = create_mock_adapter_v22_8().await;

    let timezones = adapter.list_timezones(&token).await.unwrap();

    assert_eq!(
        timezones,
        vec![
            Timezone {
                name: "UTC".to_string(),
                offset: None,
            },
            Timezone {
                name: "Europe/Berlin".to_string(),
                offset: Some("+01:00".to_string()),
            },
        ]
    );
    assert!(
        server
            .command_history()
            .iter()
            .any(|record| record.command_name() == "get_timezones"),
        "list_timezones should emit get_timezones"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn gvmd_adapter_list_timezones_returns_not_implemented_on_v22_7() {
    // Regression coverage for the exact review blocker from PR #425: older
    // supported backends must surface a typed unsupported-command error as 501,
    // not as a generic backend outage.
    let (adapter, server, token) = create_mock_adapter().await;

    let error = adapter.list_timezones(&token).await.unwrap_err();

    assert!(
        matches!(error, GatewayError::NotImplemented(ref detail) if detail.contains("get_timezones")),
        "expected unsupported 22.7 backend to map to NotImplemented, got {error:?}"
    );

    server.shutdown().await;
}
