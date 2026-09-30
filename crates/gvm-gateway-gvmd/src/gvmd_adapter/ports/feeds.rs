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
        let parsed = if let Some(feed_type) = query.feed_type.as_deref() {
            let feed_type = feed_type.parse::<gvm_gmp::FeedType>().map_err(|_| {
                GatewayError::InvalidInput(format!("unsupported feed type: {feed_type}"))
            })?;
            self.execute_with_session(session_token, "feeds.get", GetFeedRequest::new(feed_type))
                .await?
        } else {
            self.execute_with_session(session_token, "feeds.list", GetFeedsRequest::new())
                .await?
        };
        Ok(FeedList {
            data: parsed.items.into_iter().map(feed_from_gmp).collect(),
            feed_owner_configured: parsed.feed_owner_set,
            feed_roles_configured: parsed.feed_roles_set,
            feed_resources_access: parsed.feed_resources_access,
        })
    }
}
