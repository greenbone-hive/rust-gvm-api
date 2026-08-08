mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use common::{spawn_server, spawn_server_with_sessions};
use gvm_gateway_app::{GatewayPorts, GatewayService};
use gvm_gateway_domain::{
    CreateTaskInput, GatewayError, GetReportOpts, ModifyTaskInput, Pagination, Report,
    ReportExport, ReportExportRequest, ReportPage, ReportPort, ReportQuery, ResourceRef,
    ResultPage, ResultQuery, ScanResult, SessionLimits, SessionManager, Task, TaskAction,
    TaskObservers, TaskPage, TaskPort, TaskQuery, TlsCertificatePage,
};
use gvm_gateway_gvmd::StaticGvmdAdapter;
use gvm_gateway_rest::{
    router::build_router,
    targets::{build_gmp_filter, CreateTargetRequest, ModifyTargetRequest, TargetListQuery},
};
use http::{Method, StatusCode};
use reqwest::Client;
use serde_json::Value;
use tokio::net::TcpListener;

#[tokio::test]
async fn generated_openapi_endpoint_exposes_implemented_contract() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/api/v1/openapi.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap(),
        "application/json"
    );

    let json = response.json::<Value>().await.unwrap();
    let docs = SpecDocs::load(&json);
    let root_spec = docs.root_spec();

    assert_eq!(json["servers"], root_spec["servers"]);
    assert_eq!(json["security"], root_spec["security"]);
    let routes = route_contracts(&docs);
    assert_route_methods_match(
        &generated_route_methods(&json),
        &expected_route_methods(&routes),
        "generated OpenAPI route/method set drifted from the root spec path refs",
    );

    for route in &routes {
        for method in &route.methods {
            assert_operation_contract(
                &docs,
                &route.spec_path,
                method,
                &route.curated_doc,
                &route.curated_path,
            );
        }
    }

    handle.abort();
}

#[tokio::test]
async fn documented_route_inventory_matches_live_router_dispatch() {
    // This test guards the effective runtime URLs documented by OpenAPI, not
    // just the path keys. A root or path-level `servers` change must therefore
    // still map to an implemented router path.
    let adapter = StaticGvmdAdapter::ready("22.7");
    let sessions = Arc::new(SessionManager::with_limits(
        300,
        SessionLimits {
            max_global: None,
            max_per_user: None,
        },
    ));
    let (addr, handle) = spawn_server_with_sessions(adapter.clone(), adapter, sessions).await;
    let client = Client::new();
    let unused_generated = Value::Null;
    let docs = SpecDocs::load(&unused_generated);
    let routes = route_contracts(&docs);

    for route in &routes {
        for method in &route.methods {
            let session_token = create_route_probe_session(&client, addr).await;
            let response = build_route_probe_request(&client, addr, route, method, &session_token)
                .send()
                .await
                .unwrap();

            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "router did not expose {} {}",
                method,
                route.probe_path()
            );
            assert_ne!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "router rejected documented method {} {}",
                method,
                route.probe_path()
            );
        }
    }

    handle.abort();
}

#[tokio::test]
async fn update_task_preserves_preferences_through_handler() {
    let captured = Arc::new(Mutex::new(None));
    let task_port = Arc::new(CapturingTaskPort {
        captured: Arc::clone(&captured),
    });
    let (addr, token, handle) = spawn_task_server(task_port).await;

    // Regression coverage for issue #228: task preferences must survive the
    // full REST route path, not just direct request validation or gvmd emission.
    let response = Client::new()
        .put(format!(
            "http://{addr}/api/v1/tasks/550e8400-e29b-41d4-a716-446655440000"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "preferences": {
                "scanner.max_hosts": "64"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let input = captured
        .lock()
        .unwrap()
        .clone()
        .expect("modify_task input should be captured");
    assert_eq!(
        input.preferences,
        vec![("scanner.max_hosts".to_string(), "64".to_string())]
    );

    handle.abort();
}

#[tokio::test]
async fn report_export_job_api_downloads_json_result() {
    let (addr, token, handle) = spawn_report_server(Arc::new(JsonExportReportPort)).await;
    let report_id = "550e8400-e29b-41d4-a716-446655440000";
    let client = Client::new();

    // This covers the asynchronous export contract: creation returns 202 with a
    // job location, job polling reaches success, and the result endpoint returns
    // the gateway JSON report artifact.
    let create_response = client
        .post(format!("http://{addr}/api/v1/reports/{report_id}/exports"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "format": "json" }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_response.status(), StatusCode::ACCEPTED);
    let location = create_response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("job creation should return Location")
        .to_string();
    let created = create_response.json::<Value>().await.unwrap();
    assert_eq!(created["kind"], "report_export");
    assert_eq!(created["format"], "json");
    assert_eq!(created["report"]["id"], report_id);

    let job_id = created["id"].as_str().unwrap();
    assert_eq!(location, format!("/api/v1/jobs/{job_id}"));

    let mut completed = None;
    for _ in 0..20 {
        let job = client
            .get(format!("http://{addr}/api/v1/jobs/{job_id}"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        if job["status"] == "succeeded" {
            completed = Some(job);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let completed = completed.expect("report export job should succeed");
    assert_eq!(
        completed["resultLocation"],
        format!("/api/v1/jobs/{job_id}/result")
    );
    assert_eq!(completed["result"]["contentType"], "application/json");
    assert!(completed["expiresAt"].as_str().is_some());

    let result_response = client
        .get(format!("http://{addr}/api/v1/jobs/{job_id}/result"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(result_response.status(), StatusCode::OK);
    let content_type = result_response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(content_type.starts_with("application/json"));
    let export = result_response.json::<Value>().await.unwrap();
    assert_eq!(export["report"]["id"], report_id);
    assert_eq!(export["results"].as_array().unwrap().len(), 1);

    handle.abort();
}

#[tokio::test]
async fn report_export_jobs_are_hidden_from_other_users() {
    let (addr, owner_token, other_token, handle) =
        spawn_report_server_with_users(Arc::new(JsonExportReportPort)).await;
    let report_id = "550e8400-e29b-41d4-a716-446655440000";
    let client = Client::new();

    // Job artifacts are cached in the gateway, so this test locks the access
    // contract: a different authenticated gvmd user must not be able to infer,
    // cancel, or download another user's export job.
    let created = client
        .post(format!("http://{addr}/api/v1/reports/{report_id}/exports"))
        .bearer_auth(&owner_token)
        .json(&serde_json::json!({ "format": "json" }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let job_id = created["id"].as_str().unwrap();

    let status_response = client
        .get(format!("http://{addr}/api/v1/jobs/{job_id}"))
        .bearer_auth(&other_token)
        .send()
        .await
        .unwrap();
    assert_eq!(status_response.status(), StatusCode::NOT_FOUND);

    let cancel_response = client
        .delete(format!("http://{addr}/api/v1/jobs/{job_id}"))
        .bearer_auth(&other_token)
        .send()
        .await
        .unwrap();
    assert_eq!(cancel_response.status(), StatusCode::NOT_FOUND);

    let result_response = client
        .get(format!("http://{addr}/api/v1/jobs/{job_id}/result"))
        .bearer_auth(&other_token)
        .send()
        .await
        .unwrap();
    assert_eq!(result_response.status(), StatusCode::NOT_FOUND);

    let owner_response = client
        .get(format!("http://{addr}/api/v1/jobs/{job_id}"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_ne!(owner_response.status(), StatusCode::NOT_FOUND);

    handle.abort();
}

#[tokio::test]
async fn report_export_job_create_returns_not_found_for_missing_report() {
    let (addr, token, handle) = spawn_report_server(Arc::new(MissingReportPort)).await;
    let report_id = "550e8400-e29b-41d4-a716-446655440999";

    // The create endpoint documents 404 for a missing report. This locks that
    // contract at job creation time instead of hiding the failure in a later
    // background status poll.
    let response = Client::new()
        .post(format!("http://{addr}/api/v1/reports/{report_id}/exports"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "format": "json" }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    handle.abort();
}

async fn spawn_task_server(
    task_port: Arc<dyn TaskPort>,
) -> (std::net::SocketAddr, String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sessions = Arc::new(SessionManager::default());
    let token = sessions.create("admin").unwrap().token;
    let adapter = Arc::new(StaticGvmdAdapter::ready("22.7"));
    let service = GatewayService::new(
        GatewayPorts {
            system: adapter.clone(),
            alerts: adapter.clone(),
            schedules: adapter.clone(),
            credentials: adapter.clone(),
            port_lists: adapter.clone(),
            feeds: adapter.clone(),
            identity: adapter.clone(),
            targets: adapter.clone(),
            tasks: task_port,
            auth: adapter.clone(),
            reports: adapter.clone(),
            results: adapter.clone(),
            scan_configs: adapter.clone(),
            scanners: adapter.clone(),
            supporting_resources: adapter,
        },
        sessions,
    );
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, token, handle)
}

async fn spawn_report_server(
    report_port: Arc<dyn ReportPort>,
) -> (std::net::SocketAddr, String, tokio::task::JoinHandle<()>) {
    let (addr, token, _, handle) = spawn_report_server_with_users(report_port).await;
    (addr, token, handle)
}

async fn spawn_report_server_with_users(
    report_port: Arc<dyn ReportPort>,
) -> (
    std::net::SocketAddr,
    String,
    String,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sessions = Arc::new(SessionManager::default());
    let token = sessions.create("admin").unwrap().token;
    let other_token = sessions.create("auditor").unwrap().token;
    let adapter = Arc::new(StaticGvmdAdapter::ready("22.7"));
    let service = GatewayService::new(
        GatewayPorts {
            system: adapter.clone(),
            alerts: adapter.clone(),
            schedules: adapter.clone(),
            credentials: adapter.clone(),
            port_lists: adapter.clone(),
            feeds: adapter.clone(),
            identity: adapter.clone(),
            targets: adapter.clone(),
            tasks: adapter.clone(),
            auth: adapter.clone(),
            reports: report_port,
            results: adapter.clone(),
            scan_configs: adapter.clone(),
            scanners: adapter.clone(),
            supporting_resources: adapter,
        },
        sessions,
    );
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, token, other_token, handle)
}

struct JsonExportReportPort;

#[async_trait]
impl ReportPort for JsonExportReportPort {
    async fn list_reports(&self, _: &str, query: &ReportQuery) -> Result<ReportPage, GatewayError> {
        Ok(ReportPage {
            data: vec![report_response("550e8400-e29b-41d4-a716-446655440000")],
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 1,
                total_pages: 1,
            },
        })
    }

    async fn get_report(
        &self,
        _: &str,
        id: &str,
        _: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        Ok(report_response(id))
    }

    async fn export_report(
        &self,
        _: &str,
        _: &str,
        _: &ReportExportRequest,
    ) -> Result<ReportExport, GatewayError> {
        Err(GatewayError::NotImplemented(
            "gvmd report-format export is not used by this test port".to_string(),
        ))
    }

    async fn delete_report(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn get_report_results(
        &self,
        _: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        let data = if query.page == 1 {
            vec![scan_result_response(report_id)]
        } else {
            vec![]
        };
        Ok(ResultPage {
            data,
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 1,
                total_pages: 1,
            },
        })
    }

    async fn get_report_vulnerabilities(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(empty_result_page(query))
    }

    async fn get_report_tls_certificates(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        Ok(TlsCertificatePage {
            data: vec![],
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_report_errors(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(empty_result_page(query))
    }

    async fn get_report_closed_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(empty_result_page(query))
    }
}

struct MissingReportPort;

#[async_trait]
impl ReportPort for MissingReportPort {
    async fn list_reports(&self, _: &str, query: &ReportQuery) -> Result<ReportPage, GatewayError> {
        Ok(ReportPage {
            data: vec![],
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_report(
        &self,
        _: &str,
        id: &str,
        _: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        Err(GatewayError::NotFound(format!("report {id} not found")))
    }

    async fn export_report(
        &self,
        _: &str,
        id: &str,
        _: &ReportExportRequest,
    ) -> Result<ReportExport, GatewayError> {
        Err(GatewayError::NotFound(format!("report {id} not found")))
    }

    async fn delete_report(&self, _: &str, id: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("report {id} not found")))
    }

    async fn get_report_results(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(empty_result_page(query))
    }

    async fn get_report_vulnerabilities(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(empty_result_page(query))
    }

    async fn get_report_tls_certificates(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        Ok(TlsCertificatePage {
            data: vec![],
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_report_errors(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(empty_result_page(query))
    }

    async fn get_report_closed_cves(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(empty_result_page(query))
    }
}

fn report_response(id: &str) -> Report {
    Report {
        id: id.to_string(),
        task: Some(ResourceRef {
            id: "660e8400-e29b-41d4-a716-446655440000".to_string(),
            name: Some("Task".to_string()),
        }),
        scan_start: None,
        scan_end: None,
        severity: Some(5.0),
        result_count: None,
        results: vec![],
    }
}

fn scan_result_response(report_id: &str) -> ScanResult {
    ScanResult {
        id: "770e8400-e29b-41d4-a716-446655440000".to_string(),
        name: "Result".to_string(),
        host: Some("127.0.0.1".to_string()),
        port: None,
        severity: Some(5.0),
        threat: Some("Medium".to_string()),
        nvt: None,
        description: None,
        task: None,
        report: Some(ResourceRef {
            id: report_id.to_string(),
            name: None,
        }),
        hosts_count: None,
        occurrences: None,
    }
}

fn empty_result_page(query: &ResultQuery) -> ResultPage {
    ResultPage {
        data: vec![],
        pagination: Pagination {
            page: query.page,
            per_page: query.per_page,
            total: 0,
            total_pages: 0,
        },
    }
}

struct CapturingTaskPort {
    captured: Arc<Mutex<Option<ModifyTaskInput>>>,
}

#[async_trait]
impl TaskPort for CapturingTaskPort {
    async fn list_tasks(&self, _: &str, query: &TaskQuery) -> Result<TaskPage, GatewayError> {
        Ok(TaskPage {
            data: vec![],
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_task(&self, _: &str, _: CreateTaskInput) -> Result<String, GatewayError> {
        Err(GatewayError::Internal(
            "create_task is not used by this test port".to_string(),
        ))
    }

    async fn get_task(&self, _: &str, id: &str) -> Result<Task, GatewayError> {
        Ok(task_response(id, "Captured Task"))
    }

    async fn modify_task(
        &self,
        _: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        *self.captured.lock().unwrap() = Some(input);
        Ok(task_response(id, "Captured Task"))
    }

    async fn delete_task(&self, _: &str, _: &str, _: bool) -> Result<(), GatewayError> {
        Err(GatewayError::Internal(
            "delete_task is not used by this test port".to_string(),
        ))
    }

    async fn start_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Err(GatewayError::Internal(
            "start_task is not used by this test port".to_string(),
        ))
    }

    async fn stop_task(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::Internal(
            "stop_task is not used by this test port".to_string(),
        ))
    }

    async fn resume_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Err(GatewayError::Internal(
            "resume_task is not used by this test port".to_string(),
        ))
    }
}

fn task_response(id: &str, name: &str) -> Task {
    Task {
        id: id.to_string(),
        name: name.to_string(),
        comment: None,
        status: "New".to_string(),
        progress: None,
        target: None,
        scan_config: None,
        scanner: None,
        schedule: None,
        alerts: vec![],
        alterable: None,
        hosts_ordering: None,
        observers: TaskObservers::default(),
        schedule_periods: None,
        last_report: None,
        current_report: None,
        report_count: None,
        in_use: false,
        writable: true,
    }
}

#[tokio::test]
async fn trace_context_headers_propagated_without_baggage_echo() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/health"))
        .header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
        )
        .header("tracestate", "vendor=value")
        .header("baggage", "user_id=123")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("traceparent").unwrap(),
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
    );
    assert_eq!(
        response.headers().get("tracestate").unwrap(),
        "vendor=value"
    );
    assert!(response.headers().get("baggage").is_none());

    handle.abort();
}

#[tokio::test]
async fn problem_details_shape_on_error() {
    let adapter = StaticGvmdAdapter::not_ready("backend offline", "22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/api/v1/version"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        json["type"],
        serde_json::json!("https://gvm-gateway.greenbone.net/errors/bad-gateway")
    );
    assert_eq!(json["code"], serde_json::json!("backend_unavailable"));
    assert_eq!(json["title"], serde_json::json!("Bad Gateway"));
    assert_eq!(json["status"], serde_json::json!(502));
    // Backend diagnostics must not leak into public RFC 9457 problem details.
    assert_eq!(
        json["detail"],
        serde_json::json!("The backend service is unavailable.")
    );
    assert_ne!(json["detail"], serde_json::json!("backend offline"));
    assert_eq!(json["instance"], serde_json::json!("/api/v1/version"));

    handle.abort();
}

#[tokio::test]
async fn not_found_route_returns_404_problem() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/does-not-exist"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        json["type"],
        serde_json::json!("https://gvm-gateway.greenbone.net/errors/not-found")
    );
    assert_eq!(json["code"], serde_json::json!("not_found"));
    assert_eq!(json["title"], serde_json::json!("Not Found"));
    assert_eq!(json["status"], serde_json::json!(404));
    assert_eq!(json["instance"], serde_json::json!("/does-not-exist"));

    handle.abort();
}

#[test]
fn pagination_defaults() {
    let query = TargetListQuery::try_from_query_string("").unwrap();

    assert_eq!(query.page, 1);
    assert_eq!(query.per_page, 25);
}

#[test]
fn pagination_bounds() {
    let error = TargetListQuery::try_from_query_string("perPage=5000")
        .expect_err("perPage above the API maximum should fail");

    assert_eq!(
        error,
        GatewayError::InvalidInput("perPage must be between 1 and 1000".to_string())
    );
}

#[test]
fn filter_to_gmp_string() {
    let filter = build_gmp_filter(Some("name=Target-7".to_string()), None);

    assert_eq!(filter.as_deref(), Some("name=Target-7"));
}

#[test]
fn uuid_validation() {
    assert!(TargetListQuery::try_from_query_string("filterId=not-a-uuid").is_err());
    assert!(CreateTargetRequest {
        name: Some("target".to_string()),
        comment: None,
        hosts: vec!["127.0.0.1".to_string()],
        exclude_hosts: vec![],
        alive_test: None,
        port_list_id: Some("not-a-uuid".to_string()),
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    }
    .validate()
    .is_err());
    // Modify-target credential IDs use the same UUID validation contract as
    // create-target credential IDs, preserving symmetry between both paths.
    assert!(ModifyTargetRequest {
        name: None,
        comment: None,
        hosts: None,
        exclude_hosts: None,
        alive_test: None,
        port_list_id: Some("still-not-a-uuid".to_string()),
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    }
    .validate()
    .is_err());
    assert!(ModifyTargetRequest {
        name: None,
        comment: None,
        hosts: None,
        exclude_hosts: None,
        alive_test: None,
        port_list_id: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: Some("not-a-uuid".to_string()),
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    }
    .validate()
    .is_err());
}

#[test]
fn modify_requests_map_mutable_fields() {
    let target_input = ModifyTargetRequest {
        name: None,
        comment: None,
        hosts: None,
        exclude_hosts: None,
        alive_test: None,
        port_list_id: None,
        reverse_lookup_only: Some(true),
        reverse_lookup_unify: Some(false),
        ssh_credential_id: Some("550e8400-e29b-41d4-a716-446655440001".to_string()),
        smb_credential_id: Some("550e8400-e29b-41d4-a716-446655440002".to_string()),
        esxi_credential_id: Some("550e8400-e29b-41d4-a716-446655440003".to_string()),
        snmp_credential_id: Some("550e8400-e29b-41d4-a716-446655440004".to_string()),
    }
    .validate()
    .expect("valid credential IDs should map into modify-target input");
    assert_eq!(
        target_input.ssh_credential_id.as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440001")
    );
    assert_eq!(
        target_input.smb_credential_id.as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440002")
    );
    assert_eq!(
        target_input.esxi_credential_id.as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440003")
    );
    assert_eq!(
        target_input.snmp_credential_id.as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440004")
    );
    assert_eq!(target_input.reverse_lookup_only, Some(true));
    assert_eq!(target_input.reverse_lookup_unify, Some(false));

    let task_input =
        serde_json::from_value::<gvm_gateway_rest::tasks::ModifyTaskRequest>(serde_json::json!({
            "preferences": {
                "scanner.max_hosts": "64"
            }
        }))
        .expect("modify-task preferences should deserialize");
    let task_input = task_input
        .validate()
        .expect("preferences do not affect ID validation");

    assert_eq!(
        task_input.preferences,
        vec![("scanner.max_hosts".to_string(), "64".to_string())]
    );
}

const ROOT_SPEC_FILE: &str = "openapi.yaml";

#[derive(Clone, Debug, Eq, PartialEq)]
enum SpecDocRef {
    Generated,
    File(PathBuf),
}

struct SpecDocs<'a> {
    generated: &'a Value,
    spec_files: BTreeMap<PathBuf, Value>,
}

impl<'a> SpecDocs<'a> {
    fn load(generated: &'a Value) -> Self {
        let spec_files = read_spec_files(&rest_spec_dir());
        assert!(
            spec_files.contains_key(Path::new(ROOT_SPEC_FILE)),
            "REST spec directory should contain {ROOT_SPEC_FILE}"
        );

        Self {
            generated,
            spec_files,
        }
    }

    fn root_spec(&self) -> &Value {
        self.spec_file(Path::new(ROOT_SPEC_FILE))
    }

    fn doc(&self, name: &SpecDocRef) -> &Value {
        match name {
            SpecDocRef::Generated => self.generated,
            SpecDocRef::File(name) => self.spec_file(name),
        }
    }

    fn spec_file(&self, name: &Path) -> &Value {
        self.spec_files
            .get(name)
            .unwrap_or_else(|| panic!("missing REST spec document `{}`", name.display()))
    }
}

struct RouteContract {
    spec_path: String,
    runtime_path: String,
    methods: Vec<String>,
    curated_doc: SpecDocRef,
    curated_path: String,
}

impl RouteContract {
    fn probe_path(&self) -> String {
        self.runtime_path.replace("{id}", "not-a-uuid")
    }
}

fn route_contracts(docs: &SpecDocs<'_>) -> Vec<RouteContract> {
    docs.root_spec()["paths"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(spec_path, path_item_ref)| {
            let reference = path_item_ref["$ref"]
                .as_str()
                .expect("root spec path items should use file refs");
            let (curated_doc, pointer) =
                parse_ref(&SpecDocRef::File(PathBuf::from(ROOT_SPEC_FILE)), reference);
            let curated_path = path_from_ref_pointer(&pointer);
            let path_item = docs
                .doc(&curated_doc)
                .pointer(&pointer)
                .unwrap_or_else(|| panic!("missing path item ref target `{reference}`"))
                .clone();
            let runtime_path = effective_runtime_path(docs.root_spec(), &path_item, spec_path);

            RouteContract {
                spec_path: spec_path.clone(),
                runtime_path,
                methods: operation_methods(&path_item),
                curated_doc,
                curated_path,
            }
        })
        .collect()
}

fn expected_route_methods(routes: &[RouteContract]) -> BTreeSet<(String, String)> {
    routes
        .iter()
        .flat_map(|route| {
            route
                .methods
                .iter()
                .map(move |method| (route.spec_path.clone(), method.clone()))
        })
        .collect()
}

fn generated_route_methods(doc: &Value) -> BTreeSet<(String, String)> {
    doc["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(path, methods)| {
            operation_methods(methods)
                .into_iter()
                .map(move |method| (path.clone(), method.clone()))
        })
        .collect()
}

fn effective_runtime_path(root_spec: &Value, path_item: &Value, spec_path: &str) -> String {
    let server_url = path_item
        .get("servers")
        .unwrap_or(&root_spec["servers"])
        .as_array()
        .and_then(|servers| servers.first())
        .and_then(|server| server["url"].as_str())
        .unwrap_or_else(|| panic!("missing OpenAPI server URL for path `{spec_path}`"));

    join_openapi_server_path(server_url, spec_path)
}

fn join_openapi_server_path(server_url: &str, spec_path: &str) -> String {
    let server = server_url.trim_end_matches('/');
    let path = spec_path.trim_start_matches('/');

    match (server.is_empty(), path.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{path}"),
        (false, true) => server.to_string(),
        (false, false) => format!("{server}/{path}"),
    }
}

fn assert_route_methods_match(
    generated: &BTreeSet<(String, String)>,
    curated: &BTreeSet<(String, String)>,
    context: &str,
) {
    let generated_only = generated.difference(curated).collect::<Vec<_>>();
    let curated_only = curated.difference(generated).collect::<Vec<_>>();

    assert!(
        generated_only.is_empty() && curated_only.is_empty(),
        "{context}: generated_only={generated_only:?}, curated_only={curated_only:?}"
    );
}

fn operation_methods(path_item: &Value) -> Vec<String> {
    path_item
        .as_object()
        .unwrap()
        .keys()
        .filter(|method| is_openapi_operation_method(method))
        .cloned()
        .collect()
}

fn is_openapi_operation_method(method: &str) -> bool {
    matches!(
        method,
        "get" | "post" | "put" | "delete" | "patch" | "options" | "head"
    )
}

fn path_from_ref_pointer(pointer: &str) -> String {
    decode_json_pointer_token(
        pointer
            .rsplit('/')
            .next()
            .unwrap_or_else(|| panic!("invalid path item JSON pointer `{pointer}`")),
    )
}

fn decode_json_pointer_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

fn read_spec_files(spec_dir: &Path) -> BTreeMap<PathBuf, Value> {
    let mut files = BTreeMap::new();
    read_spec_files_in_dir(spec_dir, spec_dir, &mut files);
    files
}

fn read_spec_files_in_dir(spec_root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, Value>) {
    for entry in fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read `{}`: {error}", dir.display()))
    {
        let path = entry
            .unwrap_or_else(|error| panic!("failed to read entry in `{}`: {error}", dir.display()))
            .path();

        if path.is_dir() {
            read_spec_files_in_dir(spec_root, &path, files);
            continue;
        }

        if !is_yaml_file(&path) {
            continue;
        }

        let relative_path = path
            .strip_prefix(spec_root)
            .unwrap_or_else(|error| {
                panic!(
                    "failed to strip spec root `{}` from `{}`: {error}",
                    spec_root.display(),
                    path.display()
                )
            })
            .to_path_buf();
        files.insert(relative_path, read_yaml(&path));
    }
}

fn is_yaml_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("yaml" | "yml")
    )
}

fn rest_spec_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/rest-api")
}

fn read_yaml(path: &Path) -> Value {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read `{}`: {error}", path.display()));
    serde_yaml::from_str(&source)
        .unwrap_or_else(|error| panic!("failed to parse `{}`: {error}", path.display()))
}

fn build_route_probe_request(
    client: &Client,
    addr: std::net::SocketAddr,
    route: &RouteContract,
    method: &str,
    session_token: &str,
) -> reqwest::RequestBuilder {
    let runtime_path = route.probe_path();
    let wire_method = method.to_ascii_uppercase();
    let request = client.request(
        Method::from_bytes(wire_method.as_bytes()).expect("documented methods must be valid"),
        format!("http://{addr}{runtime_path}"),
    );

    match runtime_path.as_str() {
        "/health" | "/ready" | "/api/v1/version" | "/api/v1/openapi.json" => request,
        "/api/v1/session" if method == "post" => {
            request.header("Authorization", "Basic YWRtaW46c2VjcmV0")
        }
        _ => request.bearer_auth(session_token),
    }
}

async fn create_route_probe_session(client: &Client, addr: std::net::SocketAddr) -> String {
    client
        .post(format!("http://{addr}/api/v1/session"))
        .header("Authorization", "Basic YWRtaW46c2VjcmV0")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap()["sessionToken"]
        .as_str()
        .unwrap()
        .to_string()
}

fn assert_operation_contract(
    docs: &SpecDocs<'_>,
    generated_path: &str,
    method: &str,
    curated_doc: &SpecDocRef,
    curated_path: &str,
) {
    let generated_doc = SpecDocRef::Generated;
    let generated_op = effective_operation(docs.doc(&generated_doc), generated_path, method);
    let curated_op = effective_operation(docs.doc(curated_doc), curated_path, method);
    let context = format!("{method} {generated_path}");

    assert_eq!(
        generated_op["operationId"], curated_op["operationId"],
        "operationId drift for {context}"
    );
    assert_eq!(
        generated_op["tags"], curated_op["tags"],
        "tags drift for {context}"
    );
    assert_eq!(
        generated_op["summary"], curated_op["summary"],
        "summary drift for {context}"
    );

    compare_parameters(
        docs,
        &generated_doc,
        &generated_op,
        curated_doc,
        &curated_op,
        &context,
    );
    compare_request_body(
        docs,
        &generated_doc,
        &generated_op,
        curated_doc,
        &curated_op,
        &context,
    );
    compare_responses(
        docs,
        &generated_doc,
        &generated_op,
        curated_doc,
        &curated_op,
        &context,
    );
}

fn compare_parameters(
    docs: &SpecDocs<'_>,
    generated_doc: &SpecDocRef,
    generated_op: &Value,
    curated_doc: &SpecDocRef,
    curated_op: &Value,
    context: &str,
) {
    let generated_params = generated_op["parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let curated_params = curated_op["parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let generated_keys = generated_params
        .iter()
        .map(|parameter| parameter_key(docs, generated_doc, parameter))
        .collect::<BTreeSet<_>>();
    let curated_keys = curated_params
        .iter()
        .map(|parameter| parameter_key(docs, curated_doc, parameter))
        .collect::<BTreeSet<_>>();

    assert_eq!(
        generated_keys, curated_keys,
        "parameter set drift for {context}"
    );

    for key in generated_keys {
        let generated_parameter = generated_params
            .iter()
            .find(|parameter| parameter_key(docs, generated_doc, parameter) == key)
            .unwrap();
        let curated_parameter = curated_params
            .iter()
            .find(|parameter| parameter_key(docs, curated_doc, parameter) == key)
            .unwrap();

        let (generated_parameter_doc, generated_parameter) =
            resolve_ref(docs, generated_doc, generated_parameter);
        let (curated_parameter_doc, curated_parameter) =
            resolve_ref(docs, curated_doc, curated_parameter);

        assert_required_flag(
            generated_parameter.get("required"),
            curated_parameter.get("required"),
            &format!("{context} parameter {key} required"),
        );

        compare_schema_like(
            docs,
            &generated_parameter_doc,
            generated_parameter.get("schema").unwrap_or(&Value::Null),
            &curated_parameter_doc,
            curated_parameter.get("schema").unwrap_or(&Value::Null),
            &format!("{context} parameter {key} schema"),
        );
    }
}

fn compare_request_body(
    docs: &SpecDocs<'_>,
    generated_doc: &SpecDocRef,
    generated_op: &Value,
    curated_doc: &SpecDocRef,
    curated_op: &Value,
    context: &str,
) {
    let generated_body = generated_op
        .get("requestBody")
        .filter(|value| !value.is_null());
    let curated_body = curated_op
        .get("requestBody")
        .filter(|value| !value.is_null());

    match (generated_body, curated_body) {
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            panic!("requestBody presence drift for {context}");
        }
        (Some(generated_body), Some(curated_body)) => {
            let (generated_body_doc, generated_body) =
                resolve_ref(docs, generated_doc, generated_body);
            let (curated_body_doc, curated_body) = resolve_ref(docs, curated_doc, curated_body);

            assert_required_flag(
                generated_body.get("required"),
                curated_body.get("required"),
                &format!("{context} requestBody required"),
            );

            let generated_content = generated_body["content"].as_object().unwrap();
            let curated_content = curated_body["content"].as_object().unwrap();
            assert_eq!(
                generated_content.keys().collect::<BTreeSet<_>>(),
                curated_content.keys().collect::<BTreeSet<_>>(),
                "requestBody content types drift for {context}"
            );

            for media_type in generated_content.keys() {
                compare_schema_like(
                    docs,
                    &generated_body_doc,
                    &generated_content[media_type]["schema"],
                    &curated_body_doc,
                    &curated_content[media_type]["schema"],
                    &format!("{context} requestBody {media_type} schema"),
                );
            }
        }
    }
}

fn compare_responses(
    docs: &SpecDocs<'_>,
    generated_doc: &SpecDocRef,
    generated_op: &Value,
    curated_doc: &SpecDocRef,
    curated_op: &Value,
    context: &str,
) {
    let generated_responses = generated_op["responses"].as_object().unwrap();
    let curated_responses = curated_op["responses"].as_object().unwrap();
    let generated_statuses = generated_responses
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let curated_statuses = curated_responses
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    assert_string_sets_match(
        &generated_statuses,
        &curated_statuses,
        &format!("response status drift for {context}"),
    );

    for status in generated_statuses {
        let (generated_response_doc, generated_response) =
            resolve_ref(docs, generated_doc, &generated_responses[status]);
        let (curated_response_doc, curated_response) =
            resolve_ref(docs, curated_doc, &curated_responses[status]);

        let generated_content = generated_response
            .get("content")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let curated_content = curated_response
            .get("content")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let generated_media_types = generated_content
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let curated_media_types = curated_content
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_string_sets_match(
            &generated_media_types,
            &curated_media_types,
            &format!("response content type drift for {context} {status}"),
        );
        compare_headers(
            docs,
            &generated_response_doc,
            generated_response.get("headers"),
            &curated_response_doc,
            curated_response.get("headers"),
            &format!("{context} response {status} headers"),
        );

        for media_type in generated_media_types {
            compare_schema_like(
                docs,
                &generated_response_doc,
                &generated_content[media_type]["schema"],
                &curated_response_doc,
                &curated_content[media_type]["schema"],
                &format!("{context} response {status} {media_type} schema"),
            );
        }
    }
}

fn assert_string_sets_match(generated: &BTreeSet<&str>, curated: &BTreeSet<&str>, context: &str) {
    let generated_only = generated.difference(curated).collect::<Vec<_>>();
    let curated_only = curated.difference(generated).collect::<Vec<_>>();

    assert!(
        generated_only.is_empty() && curated_only.is_empty(),
        "{context}: generated_only={generated_only:?}, curated_only={curated_only:?}"
    );
}

fn compare_headers(
    docs: &SpecDocs<'_>,
    generated_doc: &SpecDocRef,
    generated_headers: Option<&Value>,
    curated_doc: &SpecDocRef,
    curated_headers: Option<&Value>,
    context: &str,
) {
    let generated_headers = generated_headers
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let curated_headers = curated_headers
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let generated_keys = generated_headers
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let curated_keys = curated_headers
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    assert!(
        generated_keys.is_subset(&curated_keys),
        "response header drift for {context}: generated={generated_keys:?}, curated={curated_keys:?}"
    );

    for key in generated_keys {
        let (generated_header_doc, generated_header) =
            resolve_ref(docs, generated_doc, &generated_headers[key]);
        let (curated_header_doc, curated_header) =
            resolve_ref(docs, curated_doc, &curated_headers[key]);

        assert_required_flag(
            generated_header.get("required"),
            curated_header.get("required"),
            &format!("{context} {key} required"),
        );
        compare_schema_like(
            docs,
            &generated_header_doc,
            generated_header.get("schema").unwrap_or(&Value::Null),
            &curated_header_doc,
            curated_header.get("schema").unwrap_or(&Value::Null),
            &format!("{context} {key} schema"),
        );
    }
}

fn compare_schema_like(
    docs: &SpecDocs<'_>,
    generated_doc: &SpecDocRef,
    generated: &Value,
    curated_doc: &SpecDocRef,
    curated: &Value,
    context: &str,
) {
    let (generated_doc, generated) = resolve_ref(docs, generated_doc, generated);
    let (curated_doc, curated) = resolve_ref(docs, curated_doc, curated);

    match (generated, curated) {
        (Value::Null, Value::Null) => {}
        (_, Value::Null) | (Value::Null, _) => panic!("schema presence drift for {context}"),
        (Value::Object(generated), Value::Object(curated)) => {
            for (key, curated_value) in curated {
                if matches!(
                    key.as_str(),
                    "description" | "example" | "examples" | "title"
                ) {
                    continue;
                }

                let generated_value = generated
                    .get(key)
                    .unwrap_or_else(|| panic!("missing `{key}` in {context}"));

                match key.as_str() {
                    "required" if curated_value.is_boolean() => assert_required_flag(
                        Some(generated_value),
                        Some(curated_value),
                        &format!("{context} required"),
                    ),
                    "required" => assert_required_items(
                        generated_value,
                        curated_value,
                        &format!("{context} required"),
                    ),
                    "enum" => assert_enum_subset(
                        generated_value,
                        curated_value,
                        &format!("{context} enum"),
                    ),
                    "minimum" | "exclusiveMinimum" | "minLength" | "minItems" | "minProperties" => {
                        assert_numeric_at_least(
                            generated_value,
                            curated_value,
                            &format!("{context} {key}"),
                        )
                    }
                    "maximum" | "exclusiveMaximum" | "maxLength" | "maxItems" | "maxProperties" => {
                        assert_numeric_at_most(
                            generated_value,
                            curated_value,
                            &format!("{context} {key}"),
                        )
                    }
                    _ => compare_schema_like(
                        docs,
                        &generated_doc,
                        generated_value,
                        &curated_doc,
                        curated_value,
                        &format!("{context}.{key}"),
                    ),
                }
            }
        }
        (Value::Array(generated), Value::Array(curated)) => {
            assert_eq!(
                generated.len(),
                curated.len(),
                "array length drift for {context}"
            );
            for (index, (generated_value, curated_value)) in
                generated.iter().zip(curated).enumerate()
            {
                compare_schema_like(
                    docs,
                    &generated_doc,
                    generated_value,
                    &curated_doc,
                    curated_value,
                    &format!("{context}[{index}]"),
                );
            }
        }
        _ => assert_eq!(generated, curated, "value drift for {context}"),
    }
}

fn assert_required_flag(generated: Option<&Value>, curated: Option<&Value>, context: &str) {
    let generated = generated.and_then(Value::as_bool).unwrap_or(false);
    let curated = curated.and_then(Value::as_bool).unwrap_or(false);
    assert!(generated || !curated, "required-flag drift for {context}");
}

fn assert_required_items(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let curated = curated
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert!(
        generated.is_superset(&curated),
        "required items drift for {context}: generated={generated:?}, curated={curated:?}"
    );
}

fn assert_enum_subset(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_array()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect::<BTreeSet<_>>();
    let curated = curated
        .as_array()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect::<BTreeSet<_>>();
    assert!(
        generated.is_subset(&curated),
        "enum drift for {context}: generated={generated:?}, curated={curated:?}"
    );
}

fn assert_numeric_at_least(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric generated value for {context}"));
    let curated = curated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric curated value for {context}"));
    assert!(generated >= curated, "numeric drift for {context}");
}

fn assert_numeric_at_most(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric generated value for {context}"));
    let curated = curated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric curated value for {context}"));
    assert!(generated <= curated, "numeric drift for {context}");
}

fn parameter_key(docs: &SpecDocs<'_>, current_doc: &SpecDocRef, parameter: &Value) -> String {
    let (_, parameter) = resolve_ref(docs, current_doc, parameter);
    format!(
        "{}:{}",
        parameter["in"].as_str().unwrap(),
        parameter["name"].as_str().unwrap()
    )
}

fn effective_operation(doc: &Value, path: &str, method: &str) -> Value {
    let mut operation = op(doc, path, method).clone();
    let mut parameters = Vec::new();

    if let Some(path_parameters) = doc["paths"][path]["parameters"].as_array() {
        parameters.extend(path_parameters.iter().cloned());
    }
    if let Some(operation_parameters) = operation["parameters"].as_array() {
        parameters.extend(operation_parameters.iter().cloned());
    }
    if !parameters.is_empty() {
        operation["parameters"] = Value::Array(parameters);
    }

    operation
}

fn resolve_ref<'a>(
    docs: &'a SpecDocs<'_>,
    current_doc: &SpecDocRef,
    mut value: &'a Value,
) -> (SpecDocRef, &'a Value) {
    let mut current_doc = current_doc.clone();
    while let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        let (next_doc, pointer) = parse_ref(&current_doc, reference);
        current_doc = next_doc;
        value = docs
            .doc(&current_doc)
            .pointer(&pointer)
            .unwrap_or_else(|| panic!("missing ref target `{reference}`"));
    }

    (current_doc, value)
}

fn parse_ref(current_doc: &SpecDocRef, reference: &str) -> (SpecDocRef, String) {
    let (doc_name, pointer) = reference.split_once('#').unwrap_or((reference, ""));
    let doc = if doc_name.is_empty() {
        current_doc.clone()
    } else {
        let current_file = match current_doc {
            SpecDocRef::File(path) => path,
            SpecDocRef::Generated => {
                panic!("generated OpenAPI refs must not target external spec document `{doc_name}`")
            }
        };
        SpecDocRef::File(resolve_relative_ref_doc(current_file, doc_name))
    };

    (doc, pointer.to_string())
}

fn resolve_relative_ref_doc(current_file: &Path, doc_name: &str) -> PathBuf {
    normalize_relative_path(
        current_file
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(doc_name),
    )
}

fn normalize_relative_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                assert!(
                    normalized.pop(),
                    "spec ref path `{}` escapes the spec root",
                    path.display()
                );
            }
            std::path::Component::Normal(component) => normalized.push(component),
            other => panic!(
                "unsupported spec ref path component `{other:?}` in `{}`",
                path.display()
            ),
        }
    }

    normalized
}

fn op<'a>(doc: &'a Value, path: &str, method: &str) -> &'a Value {
    &doc["paths"][path][method]
}
