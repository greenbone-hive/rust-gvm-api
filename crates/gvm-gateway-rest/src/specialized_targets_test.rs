// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::*;

const CREDENTIAL_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

#[test]
fn specialized_target_query_preserves_filter_trash_and_pagination() {
    // Specialized collections must carry the complete public query contract
    // into the domain request rather than silently dropping trash or filters.
    let query = parse_query(&format!(
        "filter=name%3Ddemo&filterId={CREDENTIAL_ID}&trash=true&page=2&perPage=10"
    ))
    .expect("query is valid");
    assert_eq!(query.filter_string.as_deref(), Some("name=demo"));
    assert_eq!(query.filter_id.as_deref(), Some(CREDENTIAL_ID));
    assert!(query.trash);
    assert_eq!((query.page, query.per_page), (2, 10));
}

#[test]
fn create_requests_require_the_family_specific_collection() {
    // Empty image/URL collections cannot be represented as meaningful create
    // commands and must fail before reaching gvmd.
    let oci = CreateOciImageTargetRequest {
        name: "OCI".into(),
        comment: None,
        image_references: vec![],
        credential_id: None,
    };
    assert!(matches!(
        oci.validate_into(),
        Err(GatewayError::InvalidInput(_))
    ));

    let web = CreateWebApplicationTargetRequest {
        name: "Web".into(),
        comment: None,
        urls: vec![],
        exclude_urls: vec![],
        credential_id: None,
    };
    assert!(matches!(
        web.validate_into(),
        Err(GatewayError::InvalidInput(_))
    ));
}

#[test]
fn modify_requests_preserve_omitted_collections() {
    // Omitted collections mean "leave unchanged". This distinction prevents
    // accidental replacement when rust-gvm omits empty list elements.
    let oci = ModifyOciImageTargetRequest {
        name: Some("renamed".into()),
        comment: None,
        image_references: None,
        credential_id: None,
    }
    .validate_into()
    .expect("valid input");
    assert_eq!(oci.image_references, None);

    let web = ModifyWebApplicationTargetRequest {
        name: Some("renamed".into()),
        comment: None,
        urls: None,
        exclude_urls: None,
        credential_id: None,
    }
    .validate_into()
    .expect("valid input");
    assert_eq!(web.urls, None);
    assert_eq!(web.exclude_urls, None);
}

#[test]
fn modify_web_application_target_accepts_only_supported_exclusion_updates() {
    // A non-empty exclusion list is a supported replacement, while an explicit
    // empty list must be rejected until rust-gvm can represent a typed clear.
    let replacement = vec!["https://example.com/private".to_string()];
    let web = ModifyWebApplicationTargetRequest {
        name: None,
        comment: None,
        urls: None,
        exclude_urls: Some(replacement.clone()),
        credential_id: None,
    }
    .validate_into()
    .expect("non-empty exclusions are a supported replacement");
    assert_eq!(web.exclude_urls, Some(replacement));

    let clear = ModifyWebApplicationTargetRequest {
        name: None,
        comment: None,
        urls: None,
        exclude_urls: Some(vec![]),
        credential_id: None,
    };
    assert!(matches!(
        clear.validate_into(),
        Err(GatewayError::InvalidInput(detail))
            if detail.contains("excludeUrls must contain at least one non-empty entry")
    ));
}
