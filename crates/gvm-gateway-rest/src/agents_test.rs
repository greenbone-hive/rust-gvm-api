// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::*;

const RESOURCE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

#[test]
fn agent_query_decodes_filter_filter_id_and_pagination() {
    // Agent collection requests must preserve the shared list contract exactly
    // so REST-level filtering and paging reach the typed gvmd adapter intact.
    let query = parse_agent_query(
        "filter=status%3Dactive+and+name~demo&filterId=550e8400-e29b-41d4-a716-446655440000&page=2&perPage=50",
    )
    .expect("query should parse");

    assert_eq!(
        query.filter_string.as_deref(),
        Some("status=active and name~demo")
    );
    assert_eq!(query.filter_id.as_deref(), Some(RESOURCE_ID));
    assert_eq!(query.page, 2);
    assert_eq!(query.per_page, 50);
}

#[test]
fn agent_group_query_preserves_trash_flag() {
    // Trash listing is part of the public agent-group lifecycle and must not
    // be dropped when translating REST query strings into domain inputs.
    let query =
        parse_agent_group_query("trash=true&page=3&perPage=10").expect("query should parse");

    assert!(query.trash);
    assert_eq!(query.page, 3);
    assert_eq!(query.per_page, 10);
}

#[test]
fn support_bundle_query_rejects_zero_days() {
    // The REST boundary should reject nonsensical bundle windows before the
    // request reaches gvmd, keeping the contract precise and predictable.
    let error = parse_agent_support_bundle_query("days=0").expect_err("days=0 must fail");

    assert!(
        matches!(error, GatewayError::InvalidInput(message) if message.contains("greater than or equal to 1"))
    );
}

#[test]
fn support_bundle_query_preserves_encryption_tristate() {
    // The backend distinguishes an omitted encryption selector from explicit
    // false and true, so REST parsing must not apply a boolean default.
    let omitted = parse_agent_support_bundle_query("").expect("empty query should parse");
    let disabled =
        parse_agent_support_bundle_query("encryption=false").expect("false should parse");
    let enabled = parse_agent_support_bundle_query("encryption=true").expect("true should parse");

    assert_eq!(omitted.encryption, None);
    assert_eq!(disabled.encryption, Some(false));
    assert_eq!(enabled.encryption, Some(true));
}

#[test]
fn support_bundle_query_rejects_invalid_encryption() {
    // Invalid boolean text must fail at the public boundary instead of being
    // silently treated as omission or a backend default.
    let error = parse_agent_support_bundle_query("encryption=1")
        .expect_err("non-boolean encryption must fail");

    assert!(
        matches!(error, GatewayError::InvalidInput(message) if message.contains("encryption must be true or false"))
    );
}

#[test]
fn installer_instruction_query_defaults_language_and_requires_absolute_uri() {
    // Installer instructions must default language consistently, but they also
    // require an absolute origin URL because gvmd uses it to render the output.
    let parsed =
        parse_agent_installer_instruction_query("originUrl=https%3A%2F%2Fexample.com%2Fconsole")
            .expect("absolute origin URL should parse");
    assert_eq!(parsed.language, "en");
    assert_eq!(parsed.origin_url, "https://example.com/console");

    let error = parse_agent_installer_instruction_query("originUrl=%2Frelative%2Fpath")
        .expect_err("relative origin URL must fail");
    assert!(
        matches!(error, GatewayError::InvalidInput(message) if message.contains("absolute URI"))
    );
}

#[test]
fn create_agent_group_requires_trimmed_name_and_scheduler_cron_time() {
    // Agent-group creation should fail fast on empty required strings so the
    // API does not emit create commands that gvmd will reject later anyway.
    let error = CreateAgentGroupRequest {
        name: Some("  ".to_string()),
        scheduler_cron_time: Some(" ".to_string()),
        comment: None,
        agent_ids: Vec::new(),
    }
    .validate_into()
    .expect_err("blank required fields must fail");

    assert!(
        matches!(error, GatewayError::InvalidInput(message) if message.contains("name is required"))
    );
}

#[test]
fn modify_agent_group_requires_scheduler_cron_time() {
    // The typed modify-agent-group builder requires a scheduler cron value, so
    // REST must enforce that contract instead of silently sending omissions.
    let error = ModifyAgentGroupRequest {
        scheduler_cron_time: None,
        name: Some("renamed".to_string()),
        comment: None,
        agent_ids: None,
    }
    .validate_into()
    .expect_err("missing schedulerCronTime must fail");

    assert!(
        matches!(error, GatewayError::InvalidInput(message) if message.contains("schedulerCronTime is required"))
    );
}

#[test]
fn attachment_filename_sanitizes_path_and_control_characters() {
    // Support-bundle downloads expose a backend-derived filename; sanitizing it
    // here prevents header injection and path-like values from leaking through.
    assert_eq!(
        safe_attachment_filename("../bundle\r\nname.zip"),
        "_bundle__name.zip"
    );
    assert_eq!(safe_attachment_filename("..."), "agent-support-bundle.bin");
}
