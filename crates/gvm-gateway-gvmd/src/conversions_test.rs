// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::*;
use gvm_gmp::responses::{
    GetAlertsResponse, GetCredentialsResponse, GetFeedsResponse, GetPortListsResponse,
    GetReportClosedCvesResponse, GetReportVulnsResponse, GetReportsResponse, GetResultsResponse,
    GetScanConfigsResponse, GetSchedulesResponse, GetTargetsResponse, GetTasksResponse,
    GetTicketsResponse, GetUsersResponse,
};
use gvm_protocol::Response as GmpResponse;

#[test]
fn parse_entity_id_valid() {
    let result = parse_entity_id("550e8400-e29b-41d4-a716-446655440000");
    assert!(result.is_ok());
}

#[test]
fn parse_entity_id_invalid_empty() {
    let result = parse_entity_id("");
    assert!(matches!(result, Err(GatewayError::InvalidInput(_))));
}

#[test]
fn parse_entity_id_invalid_special_chars() {
    let result = parse_entity_id("invalid@id");
    assert!(matches!(result, Err(GatewayError::InvalidInput(_))));
}

#[test]
fn parse_alive_test_valid() {
    let result = parse_alive_test("ICMP Ping");
    assert!(result.is_ok());
}

#[test]
fn parse_alive_test_invalid() {
    let result = parse_alive_test("InvalidTest");
    assert!(matches!(result, Err(GatewayError::InvalidInput(_))));
}

#[test]
fn map_gvm_error_400_to_invalid_input() {
    let error = gvm_client::GvmError::Server {
        status: 400,
        message: "bad request".to_string(),
    };
    let mapped = map_gvm_error(error);
    assert!(matches!(mapped, GatewayError::InvalidInput(_)));
}

#[test]
fn map_gvm_error_400_authentication_failed_to_unauthorized() {
    // gvmd may report failed login as a 400 server error; the REST
    // contract still exposes credential failure as 401 Unauthorized.
    let error = gvm_client::GvmError::Server {
        status: 400,
        message: "Authentication failed".to_string(),
    };
    let mapped = map_gvm_error(error);
    assert!(matches!(mapped, GatewayError::Unauthorized(_)));
}

#[test]
fn map_gvm_error_unsupported_command_to_not_implemented() {
    let error = gvm_client::GvmError::UnsupportedCommand {
        command: "get_report_vulns".to_string(),
        version: gvm_gmp::types::GmpVersion(22, 7),
        required: "22.8",
    };

    let mapped = map_gvm_error(error);

    assert!(
        matches!(mapped, GatewayError::NotImplemented(detail) if detail.contains("get_report_vulns"))
    );
}

#[test]
fn map_gvm_error_401_to_unauthorized() {
    let error = gvm_client::GvmError::Server {
        status: 401,
        message: "unauthorized".to_string(),
    };
    let mapped = map_gvm_error(error);
    assert!(matches!(mapped, GatewayError::Unauthorized(_)));
}

#[test]
fn map_gvm_error_403_to_forbidden() {
    let error = gvm_client::GvmError::Server {
        status: 403,
        message: "forbidden".to_string(),
    };
    let mapped = map_gvm_error(error);
    assert!(matches!(mapped, GatewayError::Forbidden(_)));
}

#[test]
fn map_gvm_error_404_to_not_found() {
    let error = gvm_client::GvmError::Server {
        status: 404,
        message: "not found".to_string(),
    };
    let mapped = map_gvm_error(error);
    assert!(matches!(mapped, GatewayError::NotFound(_)));
}

#[test]
fn map_gvm_error_timeout_to_gateway_timeout() {
    let error = gvm_client::GvmError::Timeout(std::time::Duration::from_secs(5));
    let mapped = map_gvm_error(error);
    assert!(matches!(mapped, GatewayError::GatewayTimeout(_)));
}

#[test]
fn map_gvm_error_parse_server_error_uses_parse_mapping() {
    let error = gvm_client::GvmError::Parse(gvm_gmp::responses::ParseError::ServerError {
        status: 400,
        message: "bad request".to_string(),
    });
    let mapped = map_gvm_error(error);
    assert!(matches!(mapped, GatewayError::InvalidInput(detail) if detail == "bad request"));
}

#[test]
fn map_parse_error_404_to_not_found() {
    let error = gvm_gmp::responses::ParseError::ServerError {
        status: 404,
        message: "not found".to_string(),
    };
    let mapped = map_parse_error(error);
    assert!(matches!(mapped, GatewayError::NotFound(_)));
}

#[test]
fn map_parse_error_400_to_invalid_input() {
    let error = gvm_gmp::responses::ParseError::ServerError {
        status: 400,
        message: "bad request".to_string(),
    };
    let mapped = map_parse_error(error);
    assert!(matches!(mapped, GatewayError::InvalidInput(_)));
}

#[test]
fn map_parse_error_400_authentication_failed_to_unauthorized() {
    // Keep structured response parsing aligned with direct client errors
    // when gvmd encodes authentication failure as a 400 response.
    let error = gvm_gmp::responses::ParseError::ServerError {
        status: 400,
        message: "Authentication failed".to_string(),
    };
    let mapped = map_parse_error(error);
    assert!(matches!(mapped, GatewayError::Unauthorized(_)));
}

#[test]
fn map_parse_error_403_to_forbidden() {
    let error = gvm_gmp::responses::ParseError::ServerError {
        status: 403,
        message: "forbidden".to_string(),
    };
    let mapped = map_parse_error(error);
    assert!(matches!(mapped, GatewayError::Forbidden(_)));
}

#[test]
fn target_from_gmp_roundtrip() {
    let response = GmpResponse::from(
        r#"<get_targets_response status="200" status_text="OK">
            <target id="550e8400-e29b-41d4-a716-446655440000">
                <owner><name>admin</name></owner>
                <name>Example Target</name>
                <comment>demo</comment>
                <creation_time>2026-03-27T00:00:00Z</creation_time>
                <modification_time>2026-03-27T00:00:00Z</modification_time>
                <writable>1</writable>
                <in_use>0</in_use>
                <hosts>10.0.0.1,10.0.0.2</hosts>
                <exclude_hosts>10.0.0.3</exclude_hosts>
                <alive_tests>ICMP Ping</alive_tests>
                <reverse_lookup_only>1</reverse_lookup_only>
                <reverse_lookup_unify>0</reverse_lookup_unify>
                <port_list id="11111111-1111-1111-1111-111111111111"><name>All TCP</name></port_list>
                <ssh_credential id="22222222-2222-2222-2222-222222222222"><name>SSH Login</name></ssh_credential>
                <smb_credential id="33333333-3333-3333-3333-333333333333"><name>SMB Login</name></smb_credential>
                <esxi_credential id="44444444-4444-4444-4444-444444444444"><name>ESXi Login</name></esxi_credential>
                <snmp_credential id="55555555-5555-5555-5555-555555555555"><name>SNMP Login</name></snmp_credential>
            </target>
        </get_targets_response>"#,
    );
    let parsed = GetTargetsResponse::from_response(&response).unwrap();

    let target = target_from_gmp(parsed.items.into_iter().next().unwrap());

    assert_eq!(target.id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(target.name, "Example Target");
    assert_eq!(target.comment.as_deref(), Some("demo"));
    assert_eq!(target.hosts, vec!["10.0.0.1", "10.0.0.2"]);
    assert_eq!(target.exclude_hosts, vec!["10.0.0.3"]);
    assert_eq!(target.alive_test.as_deref(), Some("ICMP Ping"));
    assert!(target.reverse_lookup_only);
    assert!(!target.reverse_lookup_unify);
    assert_eq!(target.port_list.unwrap().name.as_deref(), Some("All TCP"));
    assert_eq!(
        target.ssh_credential.unwrap(),
        ResourceRef {
            id: "22222222-2222-2222-2222-222222222222".to_string(),
            name: Some("SSH Login".to_string()),
        }
    );
    assert_eq!(
        target.smb_credential.unwrap(),
        ResourceRef {
            id: "33333333-3333-3333-3333-333333333333".to_string(),
            name: Some("SMB Login".to_string()),
        }
    );
    assert_eq!(
        target.esxi_credential.unwrap(),
        ResourceRef {
            id: "44444444-4444-4444-4444-444444444444".to_string(),
            name: Some("ESXi Login".to_string()),
        }
    );
    assert_eq!(
        target.snmp_credential.unwrap(),
        ResourceRef {
            id: "55555555-5555-5555-5555-555555555555".to_string(),
            name: Some("SNMP Login".to_string()),
        }
    );
}

#[test]
fn report_from_gmp_omits_missing_task_reference_name() {
    // Report task refs follow the shared ResourceRef contract: empty typed
    // names from gvmd refs should keep the id and omit the optional name.
    let response = GmpResponse::from(
        r#"<get_reports_response status="200" status_text="OK">
            <report id="550e8400-e29b-41d4-a716-446655440000">
                <name>Id-only Task Report</name>
                <task id="11111111-1111-1111-1111-111111111111"><name></name></task>
                <report id="550e8400-e29b-41d4-a716-446655440000">
                    <result_count><full>1</full><filtered>1</filtered></result_count>
                </report>
            </report>
        </get_reports_response>"#,
    );
    let parsed = GetReportsResponse::from_response(&response).unwrap();

    let report = report_from_gmp(parsed.items.into_iter().next().unwrap());

    assert_eq!(
        report.task.as_ref().map(|task| task.id.as_str()),
        Some("11111111-1111-1111-1111-111111111111")
    );
    assert_eq!(
        report.task.as_ref().and_then(|task| task.name.as_ref()),
        None
    );
}

#[test]
fn report_from_gmp_preserves_result_count_severity_buckets() {
    // Report summary reads must preserve structured gvmd severity buckets
    // instead of collapsing the typed response to total-only counts.
    let response = GmpResponse::from(
        r#"<get_reports_response status="200" status_text="OK">
            <report id="550e8400-e29b-41d4-a716-446655440000">
                <name>Bucketed Report</name>
                <report id="550e8400-e29b-41d4-a716-446655440000">
                    <result_count>
                        <full>11</full>
                        <hole><full>2</full><filtered>1</filtered></hole>
                        <warning><full>3</full><filtered>2</filtered></warning>
                        <info><full>4</full><filtered>3</filtered></info>
                        <log><full>1</full><filtered>1</filtered></log>
                        <debug><full>2</full><filtered>2</filtered></debug>
                        <false_positive><full>1</full><filtered>1</filtered></false_positive>
                    </result_count>
                </report>
            </report>
        </get_reports_response>"#,
    );
    let parsed = GetReportsResponse::from_response(&response).unwrap();

    let report = report_from_gmp(parsed.items.into_iter().next().unwrap());
    let result_count = report.result_count.expect("result count should map");

    assert_eq!(result_count.total, Some(11));
    assert_eq!(result_count.high, Some(2));
    assert_eq!(result_count.medium, Some(3));
    assert_eq!(result_count.low, Some(4));
    assert_eq!(result_count.log, Some(1));
    assert_eq!(result_count.debug, Some(2));
    assert_eq!(result_count.false_positive, Some(1));
}

#[test]
fn result_from_gmp_preserves_references_and_nvt_metadata() {
    // Result reads must not fabricate empty NVT metadata or drop typed
    // task/report references returned by rust-gvm.
    let response = GmpResponse::from(
        r#"<get_results_response status="200" status_text="OK">
            <result id="550e8400-e29b-41d4-a716-446655440000">
                <name>HTTP Server Detection</name>
                <host>192.168.1.1</host>
                <port>80/tcp</port>
                <task id="11111111-1111-1111-1111-111111111111"><name>Discovery Scan</name></task>
                <report id="22222222-2222-2222-2222-222222222222"><name>Daily Report</name></report>
                <nvt oid="1.3.6.1.4.1.25623.1.0.100315">
                    <name>HTTP Server Detection</name>
                    <family>Service detection</family>
                    <cvss_base>0.0</cvss_base>
                    <cve>CVE-2026-0001</cve>
                    <refs><ref type="cve" id="CVE-2026-0002"/></refs>
                    <tags>summary=Detects HTTP server</tags>
                </nvt>
                <threat>Log</threat>
                <severity>0.0</severity>
                <description>An HTTP server was detected on the target.</description>
            </result>
            <result_count>1<filtered>1</filtered></result_count>
        </get_results_response>"#,
    );
    let parsed = GetResultsResponse::from_response(&response).unwrap();

    let result = result_from_gmp(parsed.items.into_iter().next().unwrap());
    let nvt = result.nvt.expect("nvt should map");

    assert_eq!(
        result.task.as_ref().map(|task| task.id.as_str()),
        Some("11111111-1111-1111-1111-111111111111")
    );
    assert_eq!(
        result.task.as_ref().and_then(|task| task.name.as_deref()),
        Some("Discovery Scan")
    );
    assert_eq!(
        result.report.as_ref().map(|report| report.id.as_str()),
        Some("22222222-2222-2222-2222-222222222222")
    );
    assert_eq!(
        result
            .report
            .as_ref()
            .and_then(|report| report.name.as_deref()),
        Some("Daily Report")
    );
    assert_eq!(
        nvt.cves,
        vec!["CVE-2026-0001".to_string(), "CVE-2026-0002".to_string()]
    );
    assert_eq!(nvt.tags.as_deref(), Some("summary=Detects HTTP server"));
}

#[test]
fn result_from_gmp_omits_missing_reference_names() {
    // Id-only task/report refs from gvmd arrive as empty typed names; the
    // REST contract treats that as an absent optional name, not an empty one.
    let response = GmpResponse::from(
        r#"<get_results_response status="200" status_text="OK">
            <result id="550e8400-e29b-41d4-a716-446655440000">
                <name>HTTP Server Detection</name>
                <task id="11111111-1111-1111-1111-111111111111"/>
                <report id="22222222-2222-2222-2222-222222222222"/>
                <threat>Log</threat>
                <severity>0.0</severity>
            </result>
            <result_count>1<filtered>1</filtered></result_count>
        </get_results_response>"#,
    );
    let parsed = GetResultsResponse::from_response(&response).unwrap();

    let result = result_from_gmp(parsed.items.into_iter().next().unwrap());

    assert_eq!(
        result.task.as_ref().map(|task| task.id.as_str()),
        Some("11111111-1111-1111-1111-111111111111")
    );
    assert_eq!(
        result.task.as_ref().and_then(|task| task.name.as_ref()),
        None
    );
    assert_eq!(
        result.report.as_ref().map(|report| report.id.as_str()),
        Some("22222222-2222-2222-2222-222222222222")
    );
    assert_eq!(
        result
            .report
            .as_ref()
            .and_then(|report| report.name.as_ref()),
        None
    );
}

#[test]
fn port_list_from_gmp_uses_structured_protocol_counts() {
    // Mixed-protocol port lists need the typed TCP/UDP counts; inferring
    // counts from the first port_range character loses UDP data.
    let response = GmpResponse::from(
        r#"<get_port_lists_response status="200" status_text="OK">
            <port_list id="550e8400-e29b-41d4-a716-446655440000">
                <name>Mixed TCP UDP</name>
                <port_count>
                    <all>3</all>
                    <tcp>2</tcp>
                    <udp>1</udp>
                </port_count>
                <port_range>T:22,80,U:53</port_range>
            </port_list>
            <port_list_count>1<filtered>1</filtered></port_list_count>
        </get_port_lists_response>"#,
    );
    let parsed = GetPortListsResponse::from_response(&response).unwrap();

    let port_list = port_list_from_gmp(parsed.items.into_iter().next().unwrap());

    assert_eq!(port_list.port_count, Some(3));
    assert_eq!(port_list.tcp_count, Some(2));
    assert_eq!(port_list.udp_count, Some(1));
}

#[test]
fn remaining_open_enum_conversions_preserve_backend_values() {
    // These fields are typed at the REST boundary, but gvmd conversion
    // should still pass through the exact values provided by rust-gvm.
    let credentials = GetCredentialsResponse::from_response(&GmpResponse::from(
        r#"<get_credentials_response status="200" status_text="OK">
                <credential id="123e4567-e89b-12d3-a456-426614174001">
                    <name>Credential</name>
                    <type>future_credential</type>
                    <login>user</login>
                </credential>
            </get_credentials_response>"#,
    ))
    .expect("credentials parse");
    let credential = credential_from_gmp(credentials.items.into_iter().next().unwrap());
    assert_eq!(
        credential.credential_type.as_deref(),
        Some("future_credential")
    );

    let feeds = GetFeedsResponse::from_response(&GmpResponse::from(
        r#"<get_feeds_response status="200" status_text="OK">
                <feed>
                    <type>COMMUNITY_DATA</type>
                    <name>Community Feed</name>
                    <version>202606100000</version>
                </feed>
            </get_feeds_response>"#,
    ))
    .expect("feeds parse");
    let feed = feed_from_gmp(feeds.items.into_iter().next().unwrap());
    assert_eq!(feed.feed_type, "COMMUNITY_DATA");

    let alerts = GetAlertsResponse::from_response(&GmpResponse::from(
        r#"<get_alerts_response status="200" status_text="OK">
                <alert id="123e4567-e89b-12d3-a456-426614174002">
                    <name>Alert</name>
                    <event>future_event</event>
                    <condition>future_condition</condition>
                    <method>future_method</method>
                </alert>
            </get_alerts_response>"#,
    ))
    .expect("alerts parse");
    let alert = alert_from_gmp(alerts.items.into_iter().next().unwrap());
    assert_eq!(alert.event.as_deref(), Some("future_event"));
    assert_eq!(alert.condition.as_deref(), Some("future_condition"));
    assert_eq!(alert.method.as_deref(), Some("future_method"));

    let tickets = GetTicketsResponse::from_response(&GmpResponse::from(
        r#"<get_tickets_response status="200" status_text="OK">
                <ticket id="123e4567-e89b-12d3-a456-426614174003">
                    <name>Ticket</name>
                    <status>Deferred</status>
                </ticket>
            </get_tickets_response>"#,
    ))
    .expect("tickets parse");
    let ticket = ticket_from_gmp(tickets.items.into_iter().next().unwrap());
    assert_eq!(ticket.status.as_deref(), Some("Deferred"));
}

#[test]
fn alert_from_gmp_preserves_data_maps() {
    // Alert reads expose event/condition/method data in the REST contract;
    // the gateway must forward the typed maps parsed from gvmd responses.
    let alerts = GetAlertsResponse::from_response(&GmpResponse::from(
        r#"<get_alerts_response status="200" status_text="OK">
                <alert id="123e4567-e89b-12d3-a456-426614174006">
                    <name>Data Alert</name>
                    <event>
                        <name>Task run status changed</name>
                        <data><name>status</name>Done</data>
                    </event>
                    <condition>
                        Severity at least
                        <data><name>severity</name>5.0</data>
                    </condition>
                    <method>
                        Email
                        <data><name>to_address</name>ops@example.com</data>
                    </method>
                </alert>
            </get_alerts_response>"#,
    ))
    .expect("alerts parse");

    let alert = alert_from_gmp(alerts.items.into_iter().next().unwrap());

    assert_eq!(
        alert.event_data.get("status").map(String::as_str),
        Some("Done")
    );
    assert_eq!(
        alert.condition_data.get("severity").map(String::as_str),
        Some("5.0")
    );
    assert_eq!(
        alert.method_data.get("to_address").map(String::as_str),
        Some("ops@example.com")
    );
}

#[test]
fn schedule_from_gmp_preserves_run_times() {
    // Schedule reads expose firstRun/nextRun in the REST contract; these
    // timestamps should not be replaced with null once rust-gvm parses them.
    let schedules = GetSchedulesResponse::from_response(&GmpResponse::from(
        r#"<get_schedules_response status="200" status_text="OK">
                <schedule id="123e4567-e89b-12d3-a456-426614174007">
                    <name>Timed Schedule</name>
                    <icalendar>BEGIN:VCALENDAR&#10;END:VCALENDAR</icalendar>
                    <timezone>UTC</timezone>
                    <first_run>2026-01-03T00:00:00Z</first_run>
                    <next_run>2026-01-04T00:00:00Z</next_run>
                    <duration>3600</duration>
                </schedule>
            </get_schedules_response>"#,
    ))
    .expect("schedules parse");

    let schedule = schedule_from_gmp(schedules.items.into_iter().next().unwrap());

    assert_eq!(schedule.first_run.as_deref(), Some("2026-01-03T00:00:00Z"));
    assert_eq!(schedule.next_run.as_deref(), Some("2026-01-04T00:00:00Z"));
}

#[test]
fn aggregate_vulnerability_preserves_counts_and_nested_nvt_identity() {
    // Report vulnerability rows are aggregates, so they expose counts and NVT
    // identity while intentionally leaving singular host and port absent.
    let response = GmpResponse::from(
        r#"<get_report_vulns_response status="200" status_text="OK">
            <vulns><vuln>
                <nvt oid="1.3.6.1.4.1.25623.1.0.117761"><name>TLS finding</name></nvt>
                <cves><cve>CVE-2026-0001</cve></cves>
                <hosts_count>2</hosts_count><occurrences>3</occurrences>
                <severity>5.0</severity><threat>Medium</threat>
            </vuln></vulns>
            <report_vuln_count>1<filtered>1</filtered></report_vuln_count>
        </get_report_vulns_response>"#,
    );
    let parsed = GetReportVulnsResponse::from_response(&response).expect("vulnerabilities parse");

    let result = result_from_report_vulnerability(parsed.items.into_iter().next().unwrap());

    assert_eq!(result.name, "TLS finding");
    assert_eq!(result.host, None);
    assert_eq!(result.port, None);
    assert_eq!(result.hosts_count, Some(2));
    assert_eq!(result.occurrences, Some(3));
    assert_eq!(
        result.nvt.as_ref().and_then(|nvt| nvt.oid.as_deref()),
        Some("1.3.6.1.4.1.25623.1.0.117761")
    );
    assert_eq!(
        result.nvt.as_ref().and_then(|nvt| nvt.name.as_deref()),
        Some("TLS finding")
    );
}

#[test]
fn closed_cve_keeps_cve_name_and_maps_nested_nvt_identity() {
    // The public result name is the closed CVE identifier; the nested NVT
    // name and OID remain available separately instead of replacing it.
    let response = GmpResponse::from(
        r#"<get_report_closed_cves_response status="200" status_text="OK">
            <closed_cves><closed_cve>
                <host>192.0.2.30</host><cve>CVE-2025-9999</cve>
                <nvt oid="1.3.6.1.4.1.25623.1.0.100000"><name>Closed check</name></nvt>
                <severity>5.0</severity><threat>Medium</threat>
            </closed_cve></closed_cves>
            <report_closed_cve_count>1<filtered>1</filtered></report_closed_cve_count>
        </get_report_closed_cves_response>"#,
    );
    let parsed = GetReportClosedCvesResponse::from_response(&response).expect("closed CVEs parse");

    let result = result_from_report_closed_cve(parsed.items.into_iter().next().unwrap());

    assert_eq!(result.name, "CVE-2025-9999");
    assert_eq!(result.threat.as_deref(), Some("Medium"));
    assert_eq!(
        result.nvt.as_ref().and_then(|nvt| nvt.oid.as_deref()),
        Some("1.3.6.1.4.1.25623.1.0.100000")
    );
    assert_eq!(
        result.nvt.as_ref().and_then(|nvt| nvt.name.as_deref()),
        Some("Closed check")
    );
}

#[test]
fn remaining_open_enum_conversions_use_typed_upstream_fields() {
    // These fields are now parsed by rust-gvm. The gateway maps the typed
    // values directly and still preserves future backend values verbatim.
    let configs = GetScanConfigsResponse::from_response(&GmpResponse::from(
        r#"<get_configs_response status="200" status_text="OK">
                <config id="123e4567-e89b-12d3-a456-426614174004">
                    <name>Config</name>
                    <usage_type>scan</usage_type>
                    <type>42</type>
                </config>
            </get_configs_response>"#,
    ))
    .expect("scan configs parse");
    let config = scan_config_from_gmp(configs.items.into_iter().next().unwrap());
    assert_eq!(config.config_type, Some(42));

    let users = GetUsersResponse::from_response(&GmpResponse::from(
        r#"<get_users_response status="200" status_text="OK">
                <user id="123e4567-e89b-12d3-a456-426614174005">
                    <name>User</name>
                    <hosts_allow>1</hosts_allow>
                    <sources><source>oidc_connect</source></sources>
                </user>
            </get_users_response>"#,
    ))
    .expect("users parse");
    let user = user_from_gmp(users.items.into_iter().next().unwrap());
    assert_eq!(user.authentication_type.as_deref(), Some("oidc_connect"));
}

#[test]
fn task_from_gmp_preserves_typed_detail_fields() {
    // Detailed task reads must map typed rust-gvm fields instead of
    // dropping gvmd lifecycle data at the gateway boundary.
    let response = GmpResponse::from(
        r#"<get_tasks_response status="200" status_text="OK">
            <task id="550e8400-e29b-41d4-a716-446655440000">
                <owner><name>admin</name></owner>
                <name>Discovery Scan</name>
                <comment>demo</comment>
                <creation_time>2026-06-01T00:00:00Z</creation_time>
                <modification_time>2026-06-02T00:00:00Z</modification_time>
                <writable>1</writable>
                <in_use>1</in_use>
                <status>Processing</status>
                <progress>42</progress>
                <alterable>1</alterable>
                <observers>
                    <group id="11111111-1111-1111-1111-111111111111"><name>Auditors</name></group>
                    <role id="22222222-2222-2222-2222-222222222222"><name>Observers</name></role>
                </observers>
                <current_report>
                    <report id="33333333-3333-3333-3333-333333333333">
                        <timestamp>2026-06-02T00:00:00Z</timestamp>
                    </report>
                </current_report>
                <last_report>
                    <report id="44444444-4444-4444-4444-444444444444">
                        <timestamp>2026-06-01T00:00:00Z</timestamp>
                    </report>
                </last_report>
                <report_count>7</report_count>
                <schedule_periods>3</schedule_periods>
            </task>
            <task_count>1<filtered>1</filtered></task_count>
        </get_tasks_response>"#,
    );
    let parsed = GetTasksResponse::from_response(&response).unwrap();

    let task = task_from_gmp(parsed.items.into_iter().next().unwrap());

    assert_eq!(task.status, "Processing");
    assert_eq!(task.progress, Some(42));
    assert_eq!(task.alterable, Some(true));
    assert!(task.observers.users.is_empty());
    assert_eq!(
        task.observers.groups[0].id,
        "11111111-1111-1111-1111-111111111111"
    );
    assert_eq!(task.observers.groups[0].name.as_deref(), Some("Auditors"));
    assert_eq!(
        task.observers.roles[0].id,
        "22222222-2222-2222-2222-222222222222"
    );
    assert_eq!(task.observers.roles[0].name.as_deref(), Some("Observers"));
    assert_eq!(
        task.current_report
            .as_ref()
            .map(|report| report.id.as_str()),
        Some("33333333-3333-3333-3333-333333333333")
    );
    assert_eq!(
        task.last_report.as_ref().map(|report| report.id.as_str()),
        Some("44444444-4444-4444-4444-444444444444")
    );
    assert_eq!(task.report_count, Some(7));
    assert_eq!(task.schedule_periods, Some(3));
    assert!(task.in_use);
    assert!(task.writable);
}
