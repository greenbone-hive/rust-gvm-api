# Test Spec: GVM REST Gateway (`gvm-gateway-rest` / `gvm-gateway`)

## 1. Test Strategy

### Test Pyramid

```
         ┌──────────┐
         │   E2E    │  Against real gvmd (Compose stack via Podman or Docker)
        ┌┴──────────┴┐
        │ Integration │  axum test client + mock GMP pool
       ┌┴────────────┴┐
       │    Unit       │  Individual functions, no I/O
      └────────────────┘
```

### Test Categories

| Category | Scope | Dependencies | Speed |
|----------|-------|-------------|-------|
| Unit | Individual functions, conversions, validation | None | < 1s each |
| Integration | Route handlers with mock GMP | axum `TestServer` | < 5s each |
| E2E | Full server against gvmd | Compose-compatible stack (Podman or Docker) | < 30s each |
| Contract | OpenAPI spec compliance | Generated spec | < 2s each |

## 2. Unit Tests

### 2.1 Error Mapping (`error.rs`)

| Test | Input | Expected |
|------|-------|----------|
| `gmp_not_found_maps_to_404` | GMP "resource not found" | 404 + RFC 9457 body |
| `gmp_auth_failure_maps_to_401` | GMP "authentication failed" | 401 |
| `gmp_permission_denied_maps_to_403` | GMP "permission denied" | 403 |
| `gmp_connection_failure_maps_to_502` | GMP connection error | 502 |
| `gmp_timeout_maps_to_504` | GMP timeout | 504 |
| `error_response_follows_rfc9457` | Any error | Has `type`, `code`, `title`, `status`, `detail` fields |
| `error_response_includes_instance` | Error with path context | `instance` matches request path |

### 2.2 Model Conversion (`models/`)

| Test | Scope |
|------|-------|
| `target_from_gmp_roundtrip` | GMP Target XML → API Target JSON → validate all fields |
| `task_status_mapping` | Every GMP task status string → API enum variant |
| `report_summary_counts` | GMP report severity counts → ResultSummary |
| `task_from_structured_response` | Map `rust-gvm` task response models to REST Task schema |
| `report_from_structured_response` | Map `rust-gvm` report response models to REST Report schema |
| `result_from_structured_response` | Map `rust-gvm` result response models to REST Result schema |
| `pagination_defaults` | Missing page/perPage → defaults (1, 25) |
| `pagination_bounds` | perPage > 1000 → rejected or clamped to 1000 |
| `filter_to_gmp_string` | Structured filter params → GMP filter expression |
| `uuid_validation` | Invalid UUID → 400 error |
| `severity_range_validation` | severity_min=-1 or >10 → 400 |

### 2.3 Authentication (`auth/`)

| Test | Scope |
|------|-------|
| `basic_auth_session_create_valid_credentials` | Valid HTTP Basic credentials → 201 + session token |
| `basic_auth_session_create_invalid_credentials` | Bad credentials → 401 |
| `missing_auth_header_rejected` | No Authorization header on protected endpoint → 401 |
| `malformed_bearer_header_rejected` | Invalid bearer header syntax → 401 |
| `unknown_session_token_rejected` | Unknown bearer token → 401 |
| `expired_session_token_rejected` | Expired token → 401 |
| `invalidated_session_token_rejected` | Deleted or invalidated token → 401 |
| `valid_session_token_allows_request` | Active token → request proceeds |
| `request_scoped_basic_auth_allows_request` | Basic credentials on protected endpoint → request proceeds without explicit session management |
| `request_scoped_basic_auth_cleans_up` | Request-scoped Basic execution tears down backend/session state after success or failure |

### 2.4 Rate Limiting (`middleware/rate_limit.rs`)

| Test | Scope |
|------|-------|
| `under_limit_passes` | Requests below configured fixed-window limits → all 200 |
| `over_limit_returns_429` | Requests above subject/global window → 429 after threshold |
| `retry_after_header_present` | 429 response → has `Retry-After` header |
| `different_sessions_independent` | Two active session tokens → separate subject limits |
| `session_creation_rate_limited` | Unauthenticated session creation pressure is limited before backend work |
| `trusted_forwarded_clients_have_independent_session_creation_limits` | Trusted proxy CIDR + different `X-Forwarded-For` client IPs → independent session-creation buckets |
| `untrusted_forwarded_client_ip_ignored` | Untrusted direct peer with spoofed `X-Forwarded-For` → rate-limit source remains the TCP peer |

### 2.5 Configuration (`config.rs`)

| Test | Scope |
|------|-------|
| `default_config_valid` | No config file → sensible defaults |
| `env_var_override` | `GVM_API_BIND=0.0.0.0:9090` overrides config |
| `cli_arg_override` | `--bind 0.0.0.0:9090` overrides config + env |
| `security_config_override` | CORS/rate-limit/trusted-proxy file config and env overrides map into REST security config |
| `invalid_trusted_proxy_cidr_rejected` | Invalid trusted proxy CIDR config → startup/config load fails clearly |
| `invalid_config_rejected` | Bad TOML → clear error message |

## 3. Integration Tests

### 3.1 Test Infrastructure

```rust
// Current crate-local harness lives under crates/gvm-gateway/tests/common/mod.rs.
use axum::Router;
use axum_test::TestServer;

/// Creates a test server with a mock GMP connection pool.
async fn test_server() -> TestServer {
    let mock_pool = MockGmpPool::new();
    let app = build_router(mock_pool);
    TestServer::new(app).unwrap()
}
```

### 3.2 Health Endpoints

| Test | Request | Expected |
|------|---------|----------|
| `health_returns_200` | `GET /health` | 200, `{"status": "ok"}` |
| `ready_healthy` | `GET /ready` (GMP connected) | 200 |
| `ready_unhealthy` | `GET /ready` (GMP disconnected) | 503 |
| `version_returns_info` | `GET /api/v1/version` | 200, includes proxied gvmd GMP version and REST API contract version |
| `timezones_return_backend_catalog` | `GET /api/v1/timezones` (authenticated, GMP 22.8 backend) | 200, backend-sourced timezone list |
| `timezones_return_not_implemented_on_older_backend` | `GET /api/v1/timezones` (authenticated, GMP 22.7 backend) | 501 problem response |

### 3.3 Targets CRUD

| Test | Request | Setup | Expected |
|------|---------|-------|----------|
| `list_targets_empty` | `GET /api/v1/targets` | No targets | 200, empty `data[]`, pagination |
| `list_targets_paginated` | `GET /api/v1/targets?page=2&perPage=10` | 25 targets | 200, 10 items, correct pagination |
| `create_target` | `POST /api/v1/targets` + body | — | 201, target with ID |
| `create_target_location_header` | `POST /api/v1/targets` + body | — | 201 + `Location: /api/v1/targets/{id}` |
| `create_target_missing_name` | `POST /api/v1/targets` (no name) | — | 400, RFC 9457 |
| `get_target` | `GET /api/v1/targets/{id}` | Target exists | 200, full target |
| `get_target_not_found` | `GET /api/v1/targets/{bad-id}` | — | 404 |
| `update_target` | `PUT /api/v1/targets/{id}` + body | Target exists | 200, updated fields |
| `delete_target` | `DELETE /api/v1/targets/{id}` | Target exists | 204 |
| `delete_target_not_found` | `DELETE /api/v1/targets/{bad-id}` | — | 404 |

### 3.4 Tasks Lifecycle

| Test | Request | Setup | Expected |
|------|---------|-------|----------|
| `create_task` | `POST /api/v1/tasks` | Target + config exist | 201 |
| `create_task_location_header` | `POST /api/v1/tasks` | Target + config exist | 201 + `Location: /api/v1/tasks/{id}` |
| `start_task` | `POST /api/v1/tasks/{id}/start` | Task exists | 200, report_id |
| `stop_running_task` | `POST /api/v1/tasks/{id}/stop` | Task running | 200 |
| `stop_idle_task` | `POST /api/v1/tasks/{id}/stop` | Task not running | 409 |
| `resume_stopped_task` | `POST /api/v1/tasks/{id}/resume` | Task stopped | 200 |

### 3.5 Reports

| Test | Request | Setup | Expected |
|------|---------|-------|----------|
| `list_reports` | `GET /api/v1/reports` | Reports exist | 200, summaries |
| `get_report_with_results` | `GET /api/v1/reports/{id}` | Report exists | 200, includes requested result page |
| `get_report_results_paginated` | `GET /api/v1/reports/{id}/results?page=1&perPage=50` | Large report | 200, 50 results |
| `get_report_vulnerabilities_paginated` | `GET /api/v1/reports/{id}/vulnerabilities?page=1&perPage=50` | Report exists | 200, paginated vulnerability findings |
| `get_report_tls_certificates_paginated` | `GET /api/v1/reports/{id}/tls-certificates?page=1&perPage=50` | Report exists | 200, paginated TLS certificate observations |
| `get_report_errors_paginated` | `GET /api/v1/reports/{id}/errors?page=1&perPage=50` | Report exists | 200, paginated report errors |
| `get_report_closed_cves_paginated` | `GET /api/v1/reports/{id}/closed-cves?page=1&perPage=50` | Report exists | 200, paginated closed CVE findings |
| `create_report_export_job_pdf` | `POST /api/v1/reports/{id}/exports` + PDF `reportFormatId` | Report exists + PDF report format exists | 202 + `Location: /api/v1/jobs/{jobId}` |
| `create_report_export_job_csv` | `POST /api/v1/reports/{id}/exports` + CSV `reportFormatId` | Report exists + CSV report format exists | 202 + `Location: /api/v1/jobs/{jobId}` |
| `create_report_export_job_json` | `POST /api/v1/reports/{id}/exports` + `format=json` | Report exists | 202 + `Location: /api/v1/jobs/{jobId}` |
| `create_report_export_job_unknown_format` | `POST /api/v1/reports/{id}/exports` + bad `reportFormatId` | Report exists | 404 |
| `get_report_export_job` | `GET /api/v1/jobs/{jobId}` | Export job exists | 200, job status |
| `download_report_export_job_result` | `GET /api/v1/jobs/{jobId}/result` | Export job succeeded | 200, rendered artifact content type |

### 3.5a Discovery Helpers

| Test | Request | Setup | Expected |
|------|---------|-------|----------|
| `list_credential_stores` | `GET /api/v1/credential-stores` | Backend exposes credential store catalog | 200, credential store list |
| `get_credential_store` | `GET /api/v1/credential-stores/{id}` | Existing store id | 200, store metadata with no preference values |
| `modify_credential_store` | `PUT /api/v1/credential-stores/{id}` | Bounded connection/preference update | 200, updated metadata; write-only values omitted |
| `verify_credential_store` | `POST /api/v1/credential-stores/{id}/actions/verify` | Existing configured store | 204 |
| `create_store_backed_credential` | `POST /api/v1/credentials` | `cs_*` type with vault and host references | 201; no local secret values mixed into command |
| `modify_store_backed_credential` | `PUT /api/v1/credentials/{id}` | Store reference update | 200; semantic store-backed command used |

### 3.5b Identity & Access Control

| Test | Request | Setup | Expected |
|------|---------|-------|----------|
| `list_users_as_admin` | `GET /api/v1/users` | Admin-capable principal | 200, paginated users |
| `list_users_without_admin_scope` | `GET /api/v1/users` | Authenticated non-admin principal | 403 |
| `create_user_as_admin` | `POST /api/v1/users` | Admin-capable principal | 201 + `Location` |
| `get_user_not_found` | `GET /api/v1/users/{bad-id}` | Admin-capable principal | 404 |
| `modify_user_as_admin` | `PUT /api/v1/users/{id}` | Existing user + admin principal | 200 |
| `delete_user_as_admin` | `DELETE /api/v1/users/{id}` | Existing user + admin principal | 204 |
| `list_groups_as_admin` | `GET /api/v1/groups` | Admin-capable principal | 200, paginated groups |
| `create_group_as_admin` | `POST /api/v1/groups` | Admin-capable principal | 201 + `Location` |
| `modify_group_as_admin` | `PUT /api/v1/groups/{id}` | Existing group + admin principal | 200 |
| `delete_group_as_admin` | `DELETE /api/v1/groups/{id}` | Existing group + admin principal | 204 |
| `list_roles_as_admin` | `GET /api/v1/roles` | Admin-capable principal | 200, paginated roles |
| `create_role_as_admin` | `POST /api/v1/roles` | Admin-capable principal | 201 + `Location` |
| `modify_role_as_admin` | `PUT /api/v1/roles/{id}` | Existing role + admin principal | 200 |
| `delete_role_as_admin` | `DELETE /api/v1/roles/{id}` | Existing role + admin principal | 204 |
| `list_permissions_as_admin` | `GET /api/v1/permissions` | Admin-capable principal | 200, paginated permissions |
| `create_permission_as_admin` | `POST /api/v1/permissions` | Admin-capable principal | 201 + `Location` |
| `modify_permission_as_admin` | `PUT /api/v1/permissions/{id}` | Existing permission + admin principal | 200 |
| `delete_permission_as_admin` | `DELETE /api/v1/permissions/{id}` | Existing permission + admin principal | 204 |
| `list_user_settings_for_current_user` | `GET /api/v1/user-settings` | Authenticated principal | 200, unpaginated setting list |
| `get_user_setting_for_current_user` | `GET /api/v1/user-settings/{id}` | Setting belongs to caller | 200 |
| `modify_user_setting_for_current_user` | `PUT /api/v1/user-settings/{id}` | Setting belongs to caller | 200 |
| `create_user_setting_not_allowed` | `POST /api/v1/user-settings` | Authenticated principal | 405 |
| `delete_user_setting_not_allowed` | `DELETE /api/v1/user-settings/{id}` | Authenticated principal | 405 |

### 3.6 Authentication Flow

| Test | Request | Expected |
|------|---------|----------|
| `create_session_valid_credentials` | `POST /api/v1/session` + valid Basic auth | 201, session token + metadata |
| `create_session_location_header` | `POST /api/v1/session` + valid Basic auth | 201 + `Location: /api/v1/session` |
| `create_session_invalid_credentials` | `POST /api/v1/session` + bad Basic auth | 401 |
| `get_session_valid_token` | `GET /api/v1/session` + `Authorization: Bearer <sessionToken>` | 200, session details |
| `delete_session_valid_token` | `DELETE /api/v1/session` + `Authorization: Bearer <sessionToken>` | 204 |
| `protected_endpoint_no_auth` | `GET /api/v1/targets` (no token) | 401 |
| `protected_endpoint_unknown_token` | `GET /api/v1/targets` + unknown token | 401 |
| `protected_endpoint_valid_auth` | `GET /api/v1/targets` + valid session token | 200 |
| `protected_endpoint_request_scoped_basic_auth` | `GET /api/v1/targets` + valid Basic credentials | 200, backend context cleaned up after response |
| `protected_endpoint_malformed_basic_auth` | `GET /api/v1/targets` + malformed Basic credentials | 401 |

### 3.7 OpenAPI Compliance

| Test | Scope |
|------|-------|
| `openapi_spec_valid` | `GET /api/v1/openapi.json` validates against OpenAPI 3.1 schema |
| `all_routes_documented` | Every registered route appears in the spec |
| `response_matches_schema` | Actual responses validate against declared schemas |

### 3.8 REST Level 2 Conformance

| Test | Scope |
|------|-------|
| `create_target_location_header` | Resource creation returns `201 Created` + canonical `Location` |
| `create_task_location_header` | Resource creation returns `201 Created` + canonical `Location` |
| `create_scan_config_location_header` | Resource creation returns `201 Created` + canonical `Location` |
| `create_session_location_header` | Session creation returns `201 Created` + canonical `Location` |
| `method_not_allowed` | Unsupported method on a published resource returns `405` |
| `not_found_route` | Unknown route returns `404` |
| `stop_idle_task` | Illegal action transition returns `409` |
| `content_type_problem_json` | Problem responses use `application/problem+json` |
| `generated_openapi_endpoint_exposes_implemented_contract` | Generated OpenAPI stays aligned with curated path/method/response/header contract |

### 3.9 Cross-Cutting

| Test | Scope |
|------|-------|
| `trace_context_headers_propagated` | W3C trace context is accepted; responses return `traceparent`/`tracestate` but do not echo `baggage` |
| `cors_preflight_allowed_origin` | OPTIONS request with allowed origin → 204 + allow headers |
| `cors_preflight_denied_origin` | OPTIONS with unknown origin → 403 and no CORS allow-origin header |
| `gzip_compression` | `Accept-Encoding: gzip` → compressed response |
| `content_type_json` | Success responses → `Content-Type: application/json` |
| `content_type_problem_json` | Problem responses → `Content-Type: application/problem+json` |
| `security_headers_present` | API success and problem responses include baseline security headers |
| `browser_docs_use_bundled_redoc_with_same_origin_csp` | Documentation UI outside the API contract serves the repository-bundled Redoc asset with same-origin-only script and contract loading |
| `audit_log_redacts_session_token` | Audit/log capture contains safe session IDs but no raw tokens or passwords |
| `method_not_allowed` | `PATCH /api/v1/targets` → 405 |
| `not_found_route` | `GET /api/v1/nonexistent` → 404 |

## 4. E2E Tests (Compose stack via Podman or Docker)

### Test Environment

```yaml
# Current repository stack lives in compose.yaml.
# Compatible with Docker Compose and Podman Compose.
services:
  gvmd:
    image: greenbone/gvmd:latest
    # ... (Greenbone Community stack)

  gvm-gateway:
    build: ../..
    environment:
      GVM_GATEWAY_GVMD_ENDPOINT: unix:///run/gvmd/gvmd.sock
    depends_on:
      gvmd:
        condition: service_healthy
```

### E2E Test Suite

| Test | Scenario |
|------|----------|
| `e2e_full_scan_lifecycle` | Create target → create task → start → poll until done → get report |
| `e2e_concurrent_requests` | 50 parallel target creates → all succeed |
| `e2e_large_report_pagination` | Report with 10k+ results → paginate through all pages |
| `e2e_auth_flow` | Create session → use token → close session → confirm token is rejected |
| `e2e_graceful_shutdown` | Begin shutdown during active requests → in-flight complete before timeout, readiness degrades, new work is shed |

## 5. Performance Tests

| Test | Metric | Target |
|------|--------|--------|
| `throughput_list_targets` | Requests/sec for `GET /targets` | > 1000 rps |
| `latency_p99_get_target` | p99 latency for `GET /targets/{id}` | < 50ms |
| `latency_large_report` | Time to first byte for large report | < 500ms |
| `connection_pool_saturation` | Behavior when pool exhausted | Queues, doesn't crash |
| `memory_large_report` | Peak memory during 100MB report | < 200MB |

## 6. Test Data & Fixtures

```
Target future top-level test fixture layout:

```
tests/
├── fixtures/
│   ├── targets/
│   │   ├── create_target.json         # Valid create request
│   │   ├── create_target_minimal.json # Minimum required fields
│   │   └── create_target_invalid.json # Missing required fields
│   ├── tasks/
│   │   └── ...
│   └── gmp_responses/
│       ├── get_targets.xml            # Mock GMP response
│       ├── get_report_large.xml       # Large report for streaming tests
│       └── error_not_found.xml        # GMP error response
```

## 7. CI Integration

All unit and integration tests run in the CI workflow. E2E tests are gated behind a feature flag:

```bash
# CI (fast)
cargo test --workspace

# E2E (requires Podman or Docker)
cargo test --workspace --features e2e-tests
```

Coverage target: **80%** line coverage for route handlers and service layer.
