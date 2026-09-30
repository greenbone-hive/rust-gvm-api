// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use schemars::JsonSchema;
use serde::Serialize;

use super::common::{
    supporting_query, SupportingListQuery, SupportingResourceListQueryParams,
    SupportingResourceMetaResponse,
};
use crate::{
    dto::PaginationResponse,
    error::RestError,
    openapi::{ok_json, problem_response, ResourceIdPathDoc},
    router::bearer_token,
    targets::validate_uuid,
};

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TlsCertificateAsset")]
pub(crate) struct TlsCertificateAssetResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(rename = "subjectDn", skip_serializing_if = "Option::is_none")]
    subject_dn: Option<String>,
    #[serde(rename = "issuerDn", skip_serializing_if = "Option::is_none")]
    issuer_dn: Option<String>,
    #[serde(rename = "activationTime", skip_serializing_if = "Option::is_none")]
    activation_time: Option<String>,
    #[serde(rename = "expirationTime", skip_serializing_if = "Option::is_none")]
    expiration_time: Option<String>,
    #[serde(rename = "md5Fingerprint", skip_serializing_if = "Option::is_none")]
    md5_fingerprint: Option<String>,
    #[serde(rename = "sha256Fingerprint", skip_serializing_if = "Option::is_none")]
    sha256_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
    valid: bool,
}

impl From<gvm_gateway_domain::TlsCertificateAsset> for TlsCertificateAssetResponse {
    fn from(cert: gvm_gateway_domain::TlsCertificateAsset) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(cert.meta),
            subject_dn: cert.subject_dn,
            issuer_dn: cert.issuer_dn,
            activation_time: cert.activation_time,
            expiration_time: cert.expiration_time,
            md5_fingerprint: cert.md5_fingerprint,
            sha256_fingerprint: cert.sha256_fingerprint,
            certificate: cert.certificate,
            valid: cert.valid,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TlsCertificateAssetList")]
pub(crate) struct TlsCertificateAssetListResponse {
    data: Vec<TlsCertificateAssetResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::TlsCertificateAssetPage> for TlsCertificateAssetListResponse {
    fn from(page: gvm_gateway_domain::TlsCertificateAssetPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(TlsCertificateAssetResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Lists TLS certificate assets visible to the authenticated session.
pub async fn list_tls_certificates(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match SupportingListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_tls_certificates(&session, supporting_query(query))
        .await
    {
        Ok(page) => (
            StatusCode::OK,
            Json(TlsCertificateAssetListResponse::from(page)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single TLS certificate asset by id.
pub async fn get_tls_certificate(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.get_tls_certificate(&session, &id).await {
        Ok(item) => (
            StatusCode::OK,
            Json(TlsCertificateAssetResponse::from(item)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub(crate) fn list_tls_certificates_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTlsCertificates")
        .tag("TLS Certificates")
        .summary("List TLS certificates")
        .description("Returns a paginated list of TLS certificate assets.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<TlsCertificateAssetListResponse>, _>(ok_json(
            "Paginated list of TLS certificate assets",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_tls_certificate_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTlsCertificate")
        .tag("TLS Certificates")
        .summary("Get a TLS certificate")
        .description("Returns the details for a single TLS certificate asset.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TlsCertificateAssetResponse>, _>(ok_json(
            "TLS certificate details",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}
