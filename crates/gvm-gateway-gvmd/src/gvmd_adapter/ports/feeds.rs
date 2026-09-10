// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl FeedPort for GvmdAdapter {
    async fn list_feeds(
        &self,
        session_token: &str,
        query: &FeedQuery,
    ) -> Result<FeedList, GatewayError> {
        let client = self.session_client(session_token)?;
        let mut client = client.lock().await?;
        let response = if let Some(feed_type) = query.feed_type.as_deref() {
            let feed_type = feed_type.parse::<gvm_gmp::FeedType>().map_err(|_| {
                GatewayError::InvalidInput(format!("unsupported feed type: {feed_type}"))
            })?;
            client.call(get_feed(feed_type)).await
        } else {
            client.call(get_feeds()).await
        }
        .map_err(map_gvm_error)?;
        let parsed = GetFeedsResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(FeedList {
            data: parsed.items.into_iter().map(feed_from_gmp).collect(),
            feed_owner_configured: parsed.feed_owner_set,
            feed_roles_configured: parsed.feed_roles_set,
            feed_resources_access: parsed.feed_resources_access,
        })
    }
}
