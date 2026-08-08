use std::{
    io,
    io::Write,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use gvm_gateway_domain::*;
use gvm_gateway_gvmd::GvmdAdapter;
use gvm_mock_server::{
    response_gen::{REPORT_EXPORT_BINARY_FORMAT_ID, REPORT_EXPORT_XML_FORMAT_ID},
    GmpVersion as MockVersion, MockGmpServer, Resource, ServerMode,
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
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_results",
        "filter=\"name~Target first=11 rows=10\""
    );
    assert_backend_pagination!(
        adapter,
        server,
        adapter.get_report_results(
            &token,
            "550e8400-e29b-41d4-a716-446655440000",
            &ResultQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_results",
        "filter=\"report_id=550e8400-e29b-41d4-a716-446655440000 name~Target first=11 rows=10\""
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
        adapter.list_tickets(
            &token,
            &SupportingResourceQuery {
                filter_string: Some("name~Target".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            }
        ),
        "get_tickets",
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
async fn gvmd_adapter_list_nvts_emits_backend_pagination_filter() {
    let (adapter, server, token) = create_mock_adapter().await;
    server.clear_history();

    let result = adapter
        .list_nvts(
            &token,
            &SupportingResourceQuery {
                filter_string: Some("family=Databases".to_string()),
                filter_id: None,
                page: 3,
                per_page: 25,
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
    assert!(xml.contains("filter=\"family=Databases first=51 rows=25\""));

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
    assert_eq!(page.data[0].name, "SSL/TLS Renegotiation Vulnerability");
    assert_eq!(page.data[0].host, None);
    assert_eq!(page.data[0].port, None);
    assert_eq!(page.data[0].severity, Some(5.0));
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
    assert_eq!(
        page.data[0].description.as_deref(),
        Some("Could not reach host.")
    );
    assert_eq!(page.data[0].threat.as_deref(), Some("Alarm"));
    assert_eq!(
        page.data[0]
            .nvt
            .as_ref()
            .and_then(|nvt| nvt.name.as_deref()),
        Some("Ping Host")
    );

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
    assert_eq!(page.data[0].name, "CVE-2025-9999");
    assert_eq!(page.data[0].severity, Some(5.0));
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
