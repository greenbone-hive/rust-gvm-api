// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_gateway_domain::{GatewayError, NvtQuery};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    query::{decoded_query_pairs, parse_collection_query},
    supporting_resources::common::{default_page, default_per_page},
    targets::validate_uuid,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NvtSortOrder {
    Ascending,
    Descending,
}

impl NvtSortOrder {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ascending => "ascending",
            Self::Descending => "descending",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct NvtListQueryParams {
    #[serde(default = "default_page")]
    #[schemars(default = "default_page", range(min = 1))]
    page: Option<u32>,
    #[serde(rename = "perPage", default = "default_per_page")]
    #[schemars(default = "default_per_page", range(min = 1, max = 1000))]
    per_page: Option<u32>,
    #[serde(rename = "configId")]
    config_id: Option<Uuid>,
    #[serde(rename = "preferencesConfigId")]
    preferences_config_id: Option<Uuid>,
    family: Option<String>,
    #[serde(rename = "includePreferences")]
    include_preferences: Option<bool>,
    #[serde(rename = "includePreferenceCount")]
    include_preference_count: Option<bool>,
    #[serde(rename = "includeTimeout")]
    include_timeout: Option<bool>,
    #[serde(rename = "sortOrder")]
    sort_order: Option<NvtSortOrder>,
    #[serde(rename = "sortField")]
    sort_field: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NvtListQuery {
    pub(crate) filter_string: Option<String>,
    pub(crate) filter_id: Option<String>,
    pub(crate) page: u32,
    pub(crate) per_page: u32,
    pub(crate) config_id: Option<String>,
    pub(crate) preferences_config_id: Option<String>,
    pub(crate) family: Option<String>,
    pub(crate) include_preferences: Option<bool>,
    pub(crate) include_preference_count: Option<bool>,
    pub(crate) include_timeout: Option<bool>,
    pub(crate) sort_order: Option<NvtSortOrder>,
    pub(crate) sort_field: Option<String>,
}

impl NvtListQuery {
    pub(crate) fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let common = parse_collection_query(query)?;
        let mut config_id = None;
        let mut preferences_config_id = None;
        let mut family = None;
        let mut include_preferences = None;
        let mut include_preference_count = None;
        let mut include_timeout = None;
        let mut sort_order = None;
        let mut sort_field = None;

        for (key, value) in decoded_query_pairs(query) {
            match key.as_ref() {
                "page" | "perPage" | "per_page" => {}
                "filter" | "filterId" => {
                    return Err(GatewayError::InvalidInput(format!(
                        "{key} is not supported for NVT queries"
                    )))
                }
                "configId" => {
                    validate_uuid("configId", &value)?;
                    config_id = Some(value.into_owned());
                }
                "preferencesConfigId" => {
                    validate_uuid("preferencesConfigId", &value)?;
                    preferences_config_id = Some(value.into_owned());
                }
                "family" => family = Some(nonempty_query_value("family", &value)?),
                "includePreferences" => {
                    include_preferences = Some(parse_query_bool("includePreferences", &value)?)
                }
                "includePreferenceCount" => {
                    include_preference_count =
                        Some(parse_query_bool("includePreferenceCount", &value)?)
                }
                "includeTimeout" => {
                    include_timeout = Some(parse_query_bool("includeTimeout", &value)?)
                }
                "sortOrder" => {
                    sort_order = Some(match value.as_ref() {
                        "ascending" => NvtSortOrder::Ascending,
                        "descending" => NvtSortOrder::Descending,
                        _ => {
                            return Err(GatewayError::InvalidInput(
                                "sortOrder must be ascending or descending".to_string(),
                            ))
                        }
                    })
                }
                "sortField" => sort_field = Some(nonempty_query_value("sortField", &value)?),
                _ => {
                    return Err(GatewayError::InvalidInput(format!(
                        "unsupported NVT query parameter: {key}"
                    )))
                }
            }
        }

        if include_timeout == Some(true) && config_id.is_none() {
            return Err(GatewayError::InvalidInput(
                "includeTimeout=true requires configId".to_string(),
            ));
        }

        Ok(Self {
            filter_string: common.filter_string,
            filter_id: common.filter_id,
            page: common.page,
            per_page: common.per_page,
            config_id,
            preferences_config_id,
            family,
            include_preferences,
            include_preference_count,
            include_timeout,
            sort_order,
            sort_field,
        })
    }
}

pub(super) fn nvt_query(query: NvtListQuery) -> NvtQuery {
    NvtQuery {
        filter_string: query.filter_string,
        filter_id: query.filter_id,
        page: query.page,
        per_page: query.per_page,
        config_id: query.config_id,
        preferences_config_id: query.preferences_config_id,
        family: query.family,
        include_preferences: query.include_preferences,
        include_preference_count: query.include_preference_count,
        include_timeout: query.include_timeout,
        sort_order: query.sort_order.map(|value| value.as_str().to_string()),
        sort_field: query.sort_field,
    }
}

fn parse_query_bool(field: &str, value: &str) -> Result<bool, GatewayError> {
    value
        .parse::<bool>()
        .map_err(|_| GatewayError::InvalidInput(format!("{field} must be true or false")))
}

fn nonempty_query_value(field: &str, value: &str) -> Result<String, GatewayError> {
    let value = value.trim();
    if value.is_empty() {
        Err(GatewayError::InvalidInput(format!(
            "{field} must not be empty"
        )))
    } else {
        Ok(value.to_string())
    }
}

#[cfg(test)]
#[path = "query_test.rs"]
mod query_test;
