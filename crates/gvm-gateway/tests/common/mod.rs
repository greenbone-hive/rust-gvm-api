#![allow(dead_code)]

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gvm_gateway::server;
use gvm_gateway_app::{GatewayPorts, GatewayService, SessionReaper};
use gvm_gateway_domain::{
    AuthPort, CreateTargetInput, GatewayError, ModifyTargetInput, Pagination, SessionManager,
    Target, TargetPage, TargetPort, TargetQuery,
};
use gvm_gateway_gvmd::{GvmdAdapter, StaticGvmdAdapter};
use gvm_gateway_rest::peer_addr::ClientPeerAddr;
use gvm_gateway_rest::router::{
    build_router, build_router_with_runtime_and_security, build_router_with_security,
    RestSecurityConfig,
};
use gvm_gateway_rest::shutdown::ShutdownRuntime;
use gvm_mock_server::{Fault, GmpVersion as MockVersion, MockGmpServer, ResourceStore, ServerMode};
use http::StatusCode;
use reqwest::{Client, Response};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::Notify;

fn static_gateway_service(
    system_adapter: StaticGvmdAdapter,
    target_adapter: StaticGvmdAdapter,
    sessions: Arc<SessionManager>,
) -> GatewayService {
    GatewayService::new(
        GatewayPorts {
            system: Arc::new(system_adapter),
            alerts: Arc::new(target_adapter.clone()),
            schedules: Arc::new(target_adapter.clone()),
            credentials: Arc::new(target_adapter.clone()),
            port_lists: Arc::new(target_adapter.clone()),
            feeds: Arc::new(target_adapter.clone()),
            identity: Arc::new(target_adapter.clone()),
            targets: Arc::new(target_adapter),
            tasks: Arc::new(StaticGvmdAdapter::ready("22.7")),
            auth: Arc::new(StaticGvmdAdapter::ready("22.7")),
            reports: Arc::new(StaticGvmdAdapter::ready("22.7")),
            results: Arc::new(StaticGvmdAdapter::ready("22.7")),
            scan_configs: Arc::new(StaticGvmdAdapter::ready("22.7")),
            scanners: Arc::new(StaticGvmdAdapter::ready("22.7")),
            agents: Arc::new(StaticGvmdAdapter::ready("22.7")),
            supporting_resources: Arc::new(StaticGvmdAdapter::ready("22.7")),
        },
        sessions,
    )
}

fn live_gateway_service(
    target_adapter: GvmdAdapter,
    sessions: Arc<SessionManager>,
) -> GatewayService {
    GatewayService::new(
        GatewayPorts {
            system: Arc::new(target_adapter.clone()),
            alerts: Arc::new(target_adapter.clone()),
            schedules: Arc::new(target_adapter.clone()),
            credentials: Arc::new(target_adapter.clone()),
            port_lists: Arc::new(target_adapter.clone()),
            feeds: Arc::new(target_adapter.clone()),
            identity: Arc::new(target_adapter.clone()),
            targets: Arc::new(target_adapter.clone()),
            tasks: Arc::new(target_adapter.clone()),
            auth: Arc::new(target_adapter.clone()),
            reports: Arc::new(target_adapter.clone()),
            results: Arc::new(target_adapter.clone()),
            scan_configs: Arc::new(target_adapter.clone()),
            scanners: Arc::new(target_adapter.clone()),
            agents: Arc::new(target_adapter.clone()),
            supporting_resources: Arc::new(target_adapter),
        },
        sessions,
    )
}

fn target_port_gateway_service(
    target_adapter: Arc<dyn TargetPort>,
    sessions: Arc<SessionManager>,
) -> GatewayService {
    GatewayService::new(
        GatewayPorts {
            system: Arc::new(StaticGvmdAdapter::ready("22.7")),
            alerts: Arc::new(StaticGvmdAdapter::ready("22.7")),
            schedules: Arc::new(StaticGvmdAdapter::ready("22.7")),
            credentials: Arc::new(StaticGvmdAdapter::ready("22.7")),
            port_lists: Arc::new(StaticGvmdAdapter::ready("22.7")),
            feeds: Arc::new(StaticGvmdAdapter::ready("22.7")),
            identity: Arc::new(StaticGvmdAdapter::ready("22.7")),
            targets: target_adapter,
            tasks: Arc::new(StaticGvmdAdapter::ready("22.7")),
            auth: Arc::new(StaticGvmdAdapter::ready("22.7")),
            reports: Arc::new(StaticGvmdAdapter::ready("22.7")),
            results: Arc::new(StaticGvmdAdapter::ready("22.7")),
            scan_configs: Arc::new(StaticGvmdAdapter::ready("22.7")),
            scanners: Arc::new(StaticGvmdAdapter::ready("22.7")),
            agents: Arc::new(StaticGvmdAdapter::ready("22.7")),
            supporting_resources: Arc::new(StaticGvmdAdapter::ready("22.7")),
        },
        sessions,
    )
}

pub async fn spawn_server(
    system_adapter: StaticGvmdAdapter,
    target_adapter: StaticGvmdAdapter,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_server_with_sessions(
        system_adapter,
        target_adapter,
        Arc::new(SessionManager::default()),
    )
    .await
}

pub async fn spawn_server_with_sessions(
    system_adapter: StaticGvmdAdapter,
    target_adapter: StaticGvmdAdapter,
    sessions: Arc<SessionManager>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = static_gateway_service(system_adapter, target_adapter, sessions);
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<ClientPeerAddr>(),
        )
        .await
        .unwrap();
    });

    (addr, handle)
}

pub fn static_gateway_service_for_reaper(
    adapter: StaticGvmdAdapter,
    sessions: Arc<SessionManager>,
) -> (GatewayService, SessionReaper, Arc<StaticGvmdAdapter>) {
    let adapter = Arc::new(adapter);
    let service = static_gateway_service(
        adapter.as_ref().clone(),
        adapter.as_ref().clone(),
        Arc::clone(&sessions),
    );
    let reaper = SessionReaper::new(
        Arc::clone(&sessions),
        Arc::new(adapter.as_ref().clone()) as Arc<dyn AuthPort>,
    );

    (service, reaper, adapter)
}

pub struct GracefulShutdownHarness {
    pub addr: SocketAddr,
    pub client: Client,
    pub token: String,
    pub shutdown: Arc<ShutdownRuntime>,
    pub handle: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl GracefulShutdownHarness {
    pub fn begin_shutdown(&self) {
        self.shutdown.begin_shutdown();
    }
}

pub struct ControlledTargetAdapter {
    started: Arc<Notify>,
    release: Arc<Notify>,
}

impl ControlledTargetAdapter {
    pub fn new(started: Arc<Notify>, release: Arc<Notify>) -> Self {
        Self { started, release }
    }
}

#[async_trait]
impl TargetPort for ControlledTargetAdapter {
    async fn list_targets(
        &self,
        _session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        self.started.notify_waiters();
        self.release.notified().await;
        Ok(TargetPage {
            data: Vec::<Target>::new(),
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_target(
        &self,
        _session_token: &str,
        _input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
        Err(GatewayError::Internal(
            "not implemented in test adapter".to_string(),
        ))
    }

    async fn clone_target(&self, _session_token: &str, _id: &str) -> Result<String, GatewayError> {
        Err(GatewayError::Internal(
            "not implemented in test adapter".to_string(),
        ))
    }

    async fn get_target(&self, _session_token: &str, _id: &str) -> Result<Target, GatewayError> {
        Err(GatewayError::Internal(
            "not implemented in test adapter".to_string(),
        ))
    }

    async fn modify_target(
        &self,
        _session_token: &str,
        _id: &str,
        _input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        Err(GatewayError::Internal(
            "not implemented in test adapter".to_string(),
        ))
    }

    async fn delete_target(
        &self,
        _session_token: &str,
        _id: &str,
        _ultimate: bool,
    ) -> Result<(), GatewayError> {
        Err(GatewayError::Internal(
            "not implemented in test adapter".to_string(),
        ))
    }
}

pub async fn graceful_shutdown_harness(
    target_adapter: Arc<dyn TargetPort>,
    drain_timeout: Duration,
) -> GracefulShutdownHarness {
    let sessions = Arc::new(SessionManager::default());
    let token = sessions.create("admin").unwrap().token;
    let service = target_port_gateway_service(target_adapter, sessions);
    let shutdown = Arc::new(ShutdownRuntime::new());
    let app = build_router_with_runtime_and_security(
        service,
        Arc::clone(&shutdown),
        RestSecurityConfig::default(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(server::serve(
        listener,
        app,
        Arc::clone(&shutdown),
        drain_timeout,
        None,
    ));

    GracefulShutdownHarness {
        addr,
        client: Client::new(),
        token,
        shutdown,
        handle,
    }
}

pub struct TargetHarness {
    pub addr: SocketAddr,
    pub client: Client,
    pub token: String,
    pub sessions: Arc<SessionManager>,
    pub target_adapter: GvmdAdapter,
    pub server: MockGmpServer,
    handle: tokio::task::JoinHandle<()>,
}

impl TargetHarness {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub async fn create_connected_session(&self, user: &str, password: &str) -> String {
        let token = self.sessions.create(user).unwrap().token;
        self.target_adapter
            .connect_session(&token, user, password)
            .await
            .unwrap();
        token
    }

    pub async fn get_targets(&self) -> Response {
        self.client
            .get(self.url("/api/v1/targets"))
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap()
    }

    pub async fn get_targets_with_query(&self, query: &str) -> Response {
        self.client
            .get(self.url(&format!("/api/v1/targets?{query}")))
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap()
    }

    pub async fn get_targets_with_basic(&self, user: &str, password: &str) -> Response {
        self.client
            .get(self.url("/api/v1/targets"))
            .basic_auth(user, Some(password))
            .send()
            .await
            .unwrap()
    }

    pub async fn create_target(&self, payload: Value) -> Response {
        self.client
            .post(self.url("/api/v1/targets"))
            .bearer_auth(&self.token)
            .json(&payload)
            .send()
            .await
            .unwrap()
    }

    pub async fn get_target(&self, id: &str) -> Response {
        self.client
            .get(self.url(&format!("/api/v1/targets/{id}")))
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap()
    }

    pub async fn update_target(&self, id: &str, payload: Value) -> Response {
        self.client
            .put(self.url(&format!("/api/v1/targets/{id}")))
            .bearer_auth(&self.token)
            .json(&payload)
            .send()
            .await
            .unwrap()
    }

    pub async fn delete_target(&self, id: &str) -> Response {
        self.client
            .delete(self.url(&format!("/api/v1/targets/{id}")))
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap()
    }

    pub async fn create_session_with_basic(&self, user: &str, password: &str) -> Response {
        self.client
            .post(self.url("/api/v1/session"))
            .basic_auth(user, Some(password))
            .send()
            .await
            .unwrap()
    }

    pub async fn shutdown(self) {
        self.handle.abort();
        self.server.shutdown().await;
    }
}

pub async fn target_harness(seed: impl FnOnce(&ResourceStore) + Send + 'static) -> TargetHarness {
    target_harness_with_security(seed, RestSecurityConfig::default()).await
}

pub async fn specialized_target_harness(
    seed: impl FnOnce(&ResourceStore) + Send + 'static,
) -> TargetHarness {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .seed(seed)
        .build()
        .await
        .unwrap();

    specialized_target_harness_from_server(server).await
}

pub async fn specialized_target_harness_with_fault(
    seed: impl FnOnce(&ResourceStore) + Send + 'static,
    fault: Fault,
) -> TargetHarness {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .inject_fault(fault)
        .unix_socket_auto()
        .seed(seed)
        .build()
        .await
        .unwrap();

    specialized_target_harness_from_server(server).await
}

async fn specialized_target_harness_from_server(server: MockGmpServer) -> TargetHarness {
    let target_adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let sessions = Arc::new(SessionManager::default());
    let service = live_gateway_service(target_adapter.clone(), Arc::clone(&sessions));
    let token = service.session_manager().create("admin").unwrap().token;
    target_adapter
        .connect_session(&token, "admin", "admin")
        .await
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<ClientPeerAddr>(),
        )
        .await
        .unwrap();
    });

    TargetHarness {
        addr,
        client: Client::new(),
        token,
        sessions,
        target_adapter,
        server,
        handle,
    }
}

pub async fn target_harness_with_security(
    seed: impl FnOnce(&ResourceStore) + Send + 'static,
    security: RestSecurityConfig,
) -> TargetHarness {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .unix_socket_auto()
        .seed(seed)
        .build()
        .await
        .unwrap();

    let target_adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let sessions = Arc::new(SessionManager::default());
    let service = live_gateway_service(target_adapter.clone(), Arc::clone(&sessions));
    let token = service.session_manager().create("admin").unwrap().token;
    target_adapter
        .connect_session(&token, "admin", "admin")
        .await
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router_with_security(service, security);
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<ClientPeerAddr>(),
        )
        .await
        .unwrap();
    });

    TargetHarness {
        addr,
        client: Client::new(),
        token,
        sessions,
        target_adapter,
        server,
        handle,
    }
}

pub async fn assert_problem_status(response: Response, status: StatusCode) {
    assert_eq!(response.status(), status);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap(),
        "application/problem+json"
    );
    let json = response.json::<Value>().await.unwrap();
    assert_eq!(json["status"], serde_json::json!(status.as_u16()));
    assert!(json["code"].as_str().is_some());
    assert!(json["type"]
        .as_str()
        .unwrap()
        .starts_with("https://gvm-gateway.greenbone.net/errors/"));
}

pub fn assert_security_headers(response: &Response) {
    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        response.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
}
