// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_gateway_domain::{GatewayError, SupportingResourceQuery};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{dto::parse_uuid, query::parse_collection_query, targets::validate_uuid};

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct SupportingResourceListQueryParams {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    #[serde(default = "default_page")]
    #[schemars(default = "default_page")]
    #[schemars(range(min = 1))]
    page: Option<u32>,
    #[serde(rename = "perPage")]
    #[serde(default = "default_per_page")]
    #[schemars(default = "default_per_page")]
    #[schemars(range(min = 1, max = 1000))]
    per_page: Option<u32>,
}

/// Normalized query parameters for supporting-resource list endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportingListQuery {
    /// Optional raw GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// One-based page number.
    pub page: u32,
    /// Requested page size, clamped server-side.
    pub per_page: u32,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct PaginationOnlyQueryParams {
    #[serde(default = "default_page")]
    #[schemars(default = "default_page")]
    #[schemars(range(min = 1))]
    page: Option<u32>,
    #[serde(rename = "perPage")]
    #[serde(default = "default_per_page")]
    #[schemars(default = "default_per_page")]
    #[schemars(range(min = 1, max = 1000))]
    per_page: Option<u32>,
}

/// Normalized query parameters for pagination-only collection endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaginationOnlyQuery {
    /// One-based page number.
    pub page: u32,
    /// Requested page size, clamped server-side.
    pub per_page: u32,
}

impl SupportingListQuery {
    /// Parses a raw query string into a normalized supporting-resource query.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let parsed = parse_collection_query(query)?;

        Ok(Self {
            filter_string: parsed.filter_string,
            filter_id: parsed.filter_id,
            page: parsed.page,
            per_page: parsed.per_page,
        })
    }
}

impl PaginationOnlyQuery {
    /// Parses a raw query string into a normalized pagination-only query.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let mut page = None;
        let mut per_page = None;

        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "filter" | "filterId" => {
                    return Err(GatewayError::InvalidInput(format!(
                        "{} is not supported on this endpoint",
                        key.as_ref()
                    )))
                }
                "page" => {
                    page = Some(value.parse::<u32>().map_err(|_| {
                        GatewayError::InvalidInput("page must be a positive integer".to_string())
                    })?);
                }
                "perPage" | "per_page" => {
                    let parsed_per_page = value.parse::<u32>().map_err(|_| {
                        GatewayError::InvalidInput("perPage must be a positive integer".to_string())
                    })?;
                    if parsed_per_page == 0 || parsed_per_page > 1000 {
                        return Err(GatewayError::InvalidInput(
                            "perPage must be between 1 and 1000".to_string(),
                        ));
                    }
                    per_page = Some(parsed_per_page);
                }
                _ => {}
            }
        }

        let page = page.unwrap_or(1);
        if page == 0 {
            return Err(GatewayError::InvalidInput(
                "page must be greater than or equal to 1".to_string(),
            ));
        }
        let per_page = per_page.unwrap_or(25);

        Ok(Self { page, per_page })
    }
}

pub(super) fn default_page() -> Option<u32> {
    Some(1)
}

pub(super) fn default_per_page() -> Option<u32> {
    Some(25)
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "SupportingResourceMeta")]
pub(crate) struct SupportingResourceMetaResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "creationTime", skip_serializing_if = "Option::is_none")]
    creation_time: Option<String>,
    #[serde(rename = "modificationTime", skip_serializing_if = "Option::is_none")]
    modification_time: Option<String>,
    writable: bool,
    #[serde(rename = "inUse")]
    in_use: bool,
}

impl From<gvm_gateway_domain::SupportingResourceMeta> for SupportingResourceMetaResponse {
    fn from(meta: gvm_gateway_domain::SupportingResourceMeta) -> Self {
        Self {
            id: parse_uuid(&meta.id),
            name: meta.name,
            comment: meta.comment,
            creation_time: meta.creation_time,
            modification_time: meta.modification_time,
            writable: meta.writable,
            in_use: meta.in_use,
        }
    }
}

pub(super) fn supporting_query(query: SupportingListQuery) -> SupportingResourceQuery {
    SupportingResourceQuery {
        filter_string: query.filter_string,
        filter_id: query.filter_id,
        page: query.page,
        per_page: query.per_page,
    }
}

pub(super) fn require_nvt_oid(value: Option<String>) -> Result<String, GatewayError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| GatewayError::InvalidInput("nvtOid is required".to_string()))
}

pub(super) fn validate_optional_uuid(field: &str, value: Option<&str>) -> Result<(), GatewayError> {
    if let Some(value) = value {
        validate_uuid(field, value)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "common_test.rs"]
mod common_test;
