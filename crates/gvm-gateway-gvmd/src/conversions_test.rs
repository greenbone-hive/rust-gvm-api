// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::*;
use gvm_gmp::responses::{
    GetAgentGroupsResponse, GetAgentInstallerInstructionResponse, GetAgentSupportBundleResponse,
    GetAgentsResponse, GetAlertsResponse, GetAssetsResponse, GetConfigsResponse,
    GetCredentialsResponse, GetFeedsResponse, GetNotesResponse, GetOverridesResponse,
    GetPortListsResponse, GetReportClosedCvesResponse, GetReportTlsCertificatesResponse,
    GetReportVulnsResponse, GetReportsResponse, GetResultsResponse, GetScanConfigsResponse,
    GetScannersResponse, GetSchedulesResponse, GetTargetsResponse, GetTasksResponse,
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
fn agent_from_gmp_maps_nested_runtime_configuration() {
    // Agent parity depends on preserving typed nested config values instead of
    // flattening or dropping them at the gateway/domain boundary.
    let parsed = GetAgentsResponse::from_response(&GmpResponse::from(
        r#"<get_agents_response status="200" status_text="OK">
            <agent id="550e8400-e29b-41d4-a716-446655440000">
                <owner><name>admin</name></owner>
                <name>Managed Agent</name>
                <comment>demo</comment>
                <creation_time>2026-08-01T00:00:00Z</creation_time>
                <modification_time>2026-08-02T00:00:00Z</modification_time>
                <writable>1</writable>
                <in_use>1</in_use>
                <authorized>1</authorized>
                <update_to_latest>0</update_to_latest>
                <status>active</status>
                <version>1.2.3</version>
                <last_update_time>2026-08-03T00:00:00Z</last_update_time>
                <last_contact_time>2026-08-04T00:00:00Z</last_contact_time>
                <scanner id="08b69003-5fc2-4037-a479-93b440211c73"><name>Controller</name></scanner>
                <config>
                    <agent_control>
                        <retry>
                            <attempts>5</attempts>
                            <delay_in_seconds>30</delay_in_seconds>
                            <max_jitter_in_seconds>3</max_jitter_in_seconds>
                        </retry>
                    </agent_control>
                    <agent_script_executor>
                        <bulk_size>20</bulk_size>
                        <bulk_throttle_time_in_ms>100</bulk_throttle_time_in_ms>
                        <indexer_dir_depth>4</indexer_dir_depth>
                        <scheduler_cron_time>
                            <item>0 */5 * * *</item>
                            <item>15 */5 * * *</item>
                        </scheduler_cron_time>
                    </agent_script_executor>
                    <heartbeat>
                        <interval_in_seconds>60</interval_in_seconds>
                        <miss_until_inactive>3</miss_until_inactive>
                    </heartbeat>
                </config>
            </agent>
            <agent_count>1<filtered>1</filtered></agent_count>
        </get_agents_response>"#,
    ))
    .expect("agents parse");

    let agent = agent_from_gmp(parsed.items.into_iter().next().unwrap());

    assert_eq!(agent.meta.name, "Managed Agent");
    assert_eq!(agent.authorized, Some(true));
    assert_eq!(agent.update_to_latest, Some(false));
    assert_eq!(agent.status.as_deref(), Some("active"));
    assert_eq!(agent.version.as_deref(), Some("1.2.3"));
    assert_eq!(
        agent
            .scanner
            .as_ref()
            .map(|scanner| scanner.name.as_deref()),
        Some(Some("Controller"))
    );
    let config = agent.config.expect("config");
    assert_eq!(
        config
            .agent_control
            .and_then(|control| control.retry)
            .and_then(|retry| retry.attempts),
        Some(5)
    );
    assert_eq!(
        config
            .agent_script_executor
            .as_ref()
            .map(|executor| executor.scheduler_cron_time.clone()),
        Some(vec!["0 */5 * * *".to_string(), "15 */5 * * *".to_string()])
    );
    assert_eq!(
        config
            .heartbeat
            .and_then(|heartbeat| heartbeat.interval_in_seconds),
        Some(60)
    );
}

#[test]
fn agent_group_from_gmp_maps_members_and_schedule() {
    // Agent groups carry both scheduling data and member references, and both
    // are part of the public REST contract for issue #341.
    let parsed = GetAgentGroupsResponse::from_response(&GmpResponse::from(
        r#"<get_agent_groups_response status="200" status_text="OK">
            <agent_group id="123e4567-e89b-12d3-a456-426614174000">
                <owner><name>admin</name></owner>
                <name>Blue Team Agents</name>
                <comment>demo</comment>
                <creation_time>2026-08-01T00:00:00Z</creation_time>
                <modification_time>2026-08-02T00:00:00Z</modification_time>
                <writable>1</writable>
                <in_use>0</in_use>
                <scheduler_cron_time>0 */10 * * *</scheduler_cron_time>
                <agents>
                    <agent id="550e8400-e29b-41d4-a716-446655440000"><name>Agent One</name></agent>
                    <agent id="550e8400-e29b-41d4-a716-446655440001"><name>Agent Two</name></agent>
                </agents>
            </agent_group>
            <agent_group_count>1<filtered>1</filtered></agent_group_count>
        </get_agent_groups_response>"#,
    ))
    .expect("agent groups parse");

    let group = agent_group_from_gmp(parsed.items.into_iter().next().unwrap());

    assert_eq!(group.meta.name, "Blue Team Agents");
    assert_eq!(group.scheduler_cron_time.as_deref(), Some("0 */10 * * *"));
    assert_eq!(group.agents.len(), 2);
    assert_eq!(group.agents[0].name.as_deref(), Some("Agent One"));
}

#[test]
fn agent_download_conversions_preserve_instruction_and_binary_bundle() {
    // Download-style responses should keep their typed metadata and decoded
    // bytes intact instead of being reinterpreted by the REST layer.
    let instruction = GetAgentInstallerInstructionResponse::from_response(&GmpResponse::from(
        r#"<get_agent_installer_instruction_response status="200" status_text="OK">
            <language>en</language>
            <instruction>Install me</instruction>
        </get_agent_installer_instruction_response>"#,
    ))
    .expect("instruction parses");
    let instruction = agent_installer_instruction_from_gmp(instruction);
    assert_eq!(instruction.language, "en");
    assert_eq!(instruction.instruction, "Install me");

    let bundle = GetAgentSupportBundleResponse::from_response(&GmpResponse::from(
        r#"<get_agent_support_bundle_response status="200" status_text="OK">
            <file>
                <name>bundle.tar.gz</name>
                <content_type>application/gzip</content_type>
                <size>5</size>
                <content encoding="base64">aGVsbG8=</content>
            </file>
        </get_agent_support_bundle_response>"#,
    ))
    .expect("support bundle parses");
    let bundle = agent_support_bundle_from_gmp(bundle);
    assert_eq!(bundle.artifact.filename, "bundle.tar.gz");
    assert_eq!(bundle.artifact.content_type, "application/gzip");
    assert_eq!(&bundle.artifact.bytes[..], b"hello");
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
                    <status>current</status>
                    <sync_not_available><error>Feed lock unavailable</error></sync_not_available>
                    <currently_syncing><timestamp>2026-08-30T19:00:00Z</timestamp></currently_syncing>
                </feed>
            </get_feeds_response>"#,
    ))
    .expect("feeds parse");
    let feed = feed_from_gmp(feeds.items.into_iter().next().unwrap());
    assert_eq!(feed.feed_type, "COMMUNITY_DATA");
    assert_eq!(feed.status.as_deref(), Some("current"));
    assert_eq!(feed.sync_error.as_deref(), Some("Feed lock unavailable"));
    assert_eq!(feed.sync_timestamp.as_deref(), Some("2026-08-30T19:00:00Z"));
    assert!(feed.currently_syncing);

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
fn generic_asset_conversion_preserves_typed_known_and_custom_variants() {
    // The gateway consumes rust-gvm's typed response parser and must retain
    // both the canonical TLS certificate spelling and future asset strings.
    let parsed = GetAssetsResponse::from_response(&GmpResponse::from(
        r#"<get_assets_response status="200" status_text="OK">
            <asset id="123e4567-e89b-12d3-a456-426614174010">
                <name>TLS asset</name><type>tls_certificate</type><value>fingerprint</value>
            </asset>
            <asset id="123e4567-e89b-12d3-a456-426614174011">
                <name>Firmware asset</name><type>firmware</type><value>1.2.3</value>
            </asset>
            <asset_count>2<filtered>2</filtered></asset_count>
        </get_assets_response>"#,
    ))
    .expect("typed asset response should parse");
    let assets = parsed
        .items
        .into_iter()
        .map(generic_asset_from_gmp)
        .collect::<Result<Vec<_>, _>>()
        .expect("typed asset variants should convert");

    assert_eq!(assets[0].asset_type, "tls_certificate");
    assert_eq!(assets[0].value.as_deref(), Some("fingerprint"));
    assert_eq!(assets[1].asset_type, "firmware");
    assert_eq!(assets[1].value.as_deref(), Some("1.2.3"));
}

#[test]
fn generic_config_conversion_preserves_audit_and_future_usage_types() {
    // Config usage is an open typed rust-gvm value; converting it must not
    // collapse audit or a backend value introduced after this client release.
    let parsed = GetConfigsResponse::from_response(&GmpResponse::from(
        r#"<get_configs_response status="200" status_text="OK">
            <config id="123e4567-e89b-12d3-a456-426614174020">
                <name>Audit</name><usage_type>audit</usage_type><type>1</type>
            </config>
            <config id="123e4567-e89b-12d3-a456-426614174021">
                <name>Future</name><usage_type>future_usage</usage_type><type>42</type>
            </config>
            <config_count>2<filtered>2</filtered></config_count>
        </get_configs_response>"#,
    ))
    .expect("typed config response should parse");
    let configs = parsed
        .items
        .into_iter()
        .map(generic_config_from_gmp)
        .collect::<Vec<_>>();

    assert_eq!(configs[0].usage_type, "audit");
    assert_eq!(configs[1].usage_type, "future_usage");
    assert_eq!(configs[1].config_type, Some(42));
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
                    <icalendar>BEGIN:VCALENDAR&#10;VERSION:2.0&#10;BEGIN:VEVENT&#10;DTSTART:20260103T000000Z&#10;RRULE:FREQ=DAILY&#10;END:VEVENT&#10;END:VCALENDAR</icalendar>
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

    let result =
        result_from_report_vulnerability(parsed.items.into_iter().next().unwrap()).expect("maps");

    assert_eq!(result.host, None);
    assert_eq!(result.port, None);
    assert_eq!(result.hosts_count, Some(2));
    assert_eq!(result.occurrences, Some(3));
    assert_eq!(result.threat.as_deref(), Some("Medium"));
    assert_eq!(result.severity, Some(5.0));
    assert_eq!(
        result.nvt.as_ref().and_then(|nvt| nvt.oid.as_deref()),
        Some("1.3.6.1.4.1.25623.1.0.117761")
    );
    assert_eq!(
        result.nvt.as_ref().and_then(|nvt| nvt.name.as_deref()),
        Some("TLS finding")
    );
    assert_eq!(
        result.nvt.as_ref().map(|nvt| nvt.cves.clone()),
        Some(vec!["CVE-2026-0001".to_string()])
    );
}

#[test]
fn closed_cve_preserves_closed_cve_identity_and_nested_nvt_identity() {
    // Closed-CVE drill-downs need their dedicated cve and threat fields
    // instead of being coerced into the generic result `name` shape.
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

    let result =
        report_closed_cve_from_gmp(parsed.items.into_iter().next().unwrap()).expect("maps");

    assert_eq!(result.cve.as_deref(), Some("CVE-2025-9999"));
    assert_eq!(result.host.as_deref(), Some("192.0.2.30"));
    assert_eq!(result.severity, Some(5.0));
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
fn scan_config_from_gmp_preserves_counts_exposed_by_typed_responses() {
    // Issue #407: config family and NVT counts now arrive as typed fields
    // and must not be hardcoded to null in the gateway response model.
    let parsed = GetScanConfigsResponse::from_response(&GmpResponse::from(
        r#"<get_configs_response status="200" status_text="OK">
                <config id="123e4567-e89b-12d3-a456-426614174004">
                    <name>Config</name>
                    <family_count>12</family_count>
                    <nvt_count>345</nvt_count>
                </config>
            </get_configs_response>"#,
    ))
    .expect("scan configs parse");

    let config = scan_config_from_gmp(parsed.items.into_iter().next().unwrap());

    assert_eq!(config.family_count, Some(12));
    assert_eq!(config.nvt_count, Some(345));
}

#[test]
fn tls_certificate_from_gmp_preserves_sha256_fingerprint() {
    // Issue #407: report TLS certificate reads must surface the typed
    // SHA-256 fingerprint instead of leaving the REST field null.
    let parsed = GetReportTlsCertificatesResponse::from_response(&GmpResponse::from(
        r#"<get_report_tls_certificates_response status="200" status_text="OK">
                <tls_certificates><tls_certificate id="tls-1">
                    <name>TLS certificate</name>
                    <host>192.0.2.55</host>
                    <port>443/tcp</port>
                    <subject>CN=example</subject>
                    <issuer>CN=issuer</issuer>
                    <sha256_fingerprint>ABCD1234</sha256_fingerprint>
                </tls_certificate></tls_certificates>
                <report_tls_certificate_count>1<filtered>1</filtered></report_tls_certificate_count>
            </get_report_tls_certificates_response>"#,
    ))
    .expect("tls certificates parse");

    let certificate =
        tls_certificate_from_report_tls_certificate(parsed.items.into_iter().next().unwrap());

    assert_eq!(certificate.fingerprint_sha256.as_deref(), Some("ABCD1234"));
}

#[test]
fn user_from_gmp_preserves_typed_owner_and_hosts_allow_fields() {
    // Issues #407 and #410: typed identity metadata now exposes owner names
    // and host-access booleans directly; the gateway must not discard them.
    let parsed = GetUsersResponse::from_response(&GmpResponse::from(
        r#"<get_users_response status="200" status_text="OK">
                <user id="123e4567-e89b-12d3-a456-426614174005">
                    <owner><name>admin</name></owner>
                    <name>User</name>
                    <hosts allow="0">192.0.2.0/24</hosts>
                </user>
            </get_users_response>"#,
    ))
    .expect("users parse");

    let user = user_from_gmp(parsed.items.into_iter().next().unwrap());

    assert_eq!(
        user.meta.owner.as_ref().map(|owner| owner.name.as_str()),
        Some("admin")
    );
    assert_eq!(user.hosts_allow, Some(false));
}

#[test]
fn note_and_override_from_gmp_preserve_typed_nvt_name_and_family() {
    // Issue #410: typed note/override NVT references carry more than an OID,
    // and the gateway must preserve the emitted name and family metadata.
    let notes = GetNotesResponse::from_response(&GmpResponse::from(
        r#"<get_notes_response status="200" status_text="OK">
                <note id="note-1">
                    <name>Note</name>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.100001">
                        <name>Named NVT</name>
                        <type>Product detection</type>
                    </nvt>
                </note>
            </get_notes_response>"#,
    ))
    .expect("notes parse");
    let overrides = GetOverridesResponse::from_response(&GmpResponse::from(
        r#"<get_overrides_response status="200" status_text="OK">
                <override id="override-1">
                    <name>Override</name>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.100002">
                        <name>Override NVT</name>
                        <type>General</type>
                    </nvt>
                </override>
            </get_overrides_response>"#,
    ))
    .expect("overrides parse");

    let note = note_from_gmp(notes.items.into_iter().next().unwrap());
    let override_ = override_from_gmp(overrides.items.into_iter().next().unwrap());

    assert_eq!(
        note.nvt.as_ref().and_then(|nvt| nvt.name.as_deref()),
        Some("Named NVT")
    );
    assert_eq!(
        note.nvt.as_ref().and_then(|nvt| nvt.family.as_deref()),
        Some("Product detection")
    );
    assert_eq!(
        override_.nvt.as_ref().and_then(|nvt| nvt.name.as_deref()),
        Some("Override NVT")
    );
    assert_eq!(
        override_.nvt.as_ref().and_then(|nvt| nvt.family.as_deref()),
        Some("General")
    );
}

#[test]
fn scanner_from_gmp_preserves_credential_and_write_state_fields() {
    // Issue #410: typed scanner responses include credential references and
    // write-state flags that must survive gateway conversion.
    let parsed = GetScannersResponse::from_response(&GmpResponse::from(
        r#"<get_scanners_response status="200" status_text="OK">
                <scanner id="scanner-1">
                    <name>Default Scanner</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <type>OpenVAS</type>
                    <host>127.0.0.1</host>
                    <port>9390</port>
                    <ca_pub>CA certificate</ca_pub>
                    <credential id="cred-1"><name>OSP Credential</name></credential>
                </scanner>
            </get_scanners_response>"#,
    ))
    .expect("scanners parse");

    let scanner = scanner_from_gmp(parsed.items.into_iter().next().unwrap());

    assert_eq!(
        scanner
            .credential
            .as_ref()
            .map(|credential| credential.id.as_str()),
        Some("cred-1")
    );
    assert_eq!(scanner.ca_pub.as_deref(), Some("CA certificate"));
    assert!(scanner.in_use);
    assert!(!scanner.writable);
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
