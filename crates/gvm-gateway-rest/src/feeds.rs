// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Feed DTOs and handlers for the REST adapter.

#![allow(missing_docs)]

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    dto::datetime_schema,
    error::RestError,
    open_enum::open_string_enum,
    openapi::{ok_json, problem_response},
    router::bearer_token,
};

pub use gvm_gateway_domain::{Feed, FeedList, FeedQuery};

open_string_enum! {
    /// Feed catalog type.
    pub(crate) enum FeedType {
        Nvt => "NVT",
        Cert => "CERT",
        Scap => "SCAP",
        GvmdData => "GVMD_DATA",
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Feed")]
pub(crate) struct FeedResponse {
    #[serde(rename = "type")]
    feed_type: FeedType,
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(rename = "syncError", skip_serializing_if = "Option::is_none")]
    sync_error: Option<String>,
    #[serde(rename = "syncTimestamp", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    sync_timestamp: Option<String>,
    #[serde(rename = "currentlySyncing")]
    currently_syncing: bool,
}

impl From<Feed> for FeedResponse {
    fn from(feed: Feed) -> Self {
        Self {
            feed_type: FeedType::parse(&feed.feed_type),
            name: feed.name,
            version: feed.version,
            description: feed.description,
            status: feed.status,
            sync_error: feed.sync_error,
            sync_timestamp: feed.sync_timestamp,
            currently_syncing: feed.currently_syncing,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "FeedList")]
pub(crate) struct FeedListResponse {
    data: Vec<FeedResponse>,
    #[serde(rename = "feedOwnerConfigured")]
    feed_owner_configured: bool,
    #[serde(rename = "feedRolesConfigured")]
    feed_roles_configured: bool,
    #[serde(rename = "feedResourcesAccess")]
    feed_resources_access: bool,
}

impl From<FeedList> for FeedListResponse {
    fn from(feeds: FeedList) -> Self {
        Self {
            data: feeds.data.into_iter().map(FeedResponse::from).collect(),
            feed_owner_configured: feeds.feed_owner_configured,
            feed_roles_configured: feeds.feed_roles_configured,
            feed_resources_access: feeds.feed_resources_access,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
enum FeedTypeFilter {
    #[serde(rename = "NVT")]
    Nvt,
    #[serde(rename = "CERT")]
    Cert,
    #[serde(rename = "SCAP")]
    Scap,
    #[serde(rename = "GVMD_DATA")]
    GvmdData,
}

impl FeedTypeFilter {
    fn parse(value: &str) -> Result<Self, GatewayError> {
        match value {
            "NVT" => Ok(Self::Nvt),
            "CERT" => Ok(Self::Cert),
            "SCAP" => Ok(Self::Scap),
            "GVMD_DATA" => Ok(Self::GvmdData),
            _ => Err(GatewayError::InvalidInput(format!(
                "unsupported feed type: {value}"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Nvt => "NVT",
            Self::Cert => "CERT",
            Self::Scap => "SCAP",
            Self::GvmdData => "GVMD_DATA",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FeedListQuery {
    #[serde(rename = "type")]
    feed_type: Option<FeedTypeFilter>,
}

impl FeedListQuery {
    fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let mut feed_type = None;
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            if key != "type" {
                return Err(GatewayError::InvalidInput(format!(
                    "unsupported feed query parameter: {key}"
                )));
            }
            if feed_type.is_some() {
                return Err(GatewayError::InvalidInput(
                    "type may be supplied only once".to_string(),
                ));
            }
            feed_type = Some(FeedTypeFilter::parse(&value)?);
        }
        Ok(Self { feed_type })
    }
}

pub async fn list_feeds(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let query = match FeedListQuery::try_from_query_string(uri.0.query().unwrap_or_default()) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service
        .list_feeds(
            &session,
            FeedQuery {
                feed_type: query.feed_type.map(|value| value.as_str().to_string()),
            },
        )
        .await
    {
        Ok(feeds) => (StatusCode::OK, Json(FeedListResponse::from(feeds))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub(crate) fn list_feeds_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getFeeds")
        .tag("Feeds")
        .summary("Get feed status")
        .description("Returns feed status, optionally filtered by feed type.")
        .security_requirement("bearerAuth")
        .input::<Query<FeedListQuery>>()
        .response_with::<200, Json<FeedListResponse>, _>(ok_json("Feed status"));
    let op = problem_response::<400>(op, "Invalid feed type or query parameter");
    problem_response::<401>(op, "Authentication required or session expired")
}

#[cfg(test)]
#[path = "feeds_test.rs"]
mod feeds_test;
