// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Feed-status use cases.

use gvm_gateway_domain::{FeedList, FeedQuery, GatewayError};

use crate::GatewayService;

impl GatewayService {
    /// Lists feed status for an authenticated session.
    pub async fn list_feeds(
        &self,
        session_token: &str,
        query: FeedQuery,
    ) -> Result<FeedList, GatewayError> {
        self.execute_with_resource(
            "feeds.list",
            session_token,
            "list",
            "feed",
            None,
            |session| async move { self.feeds.list_feeds(&session.token, &query).await },
        )
        .await
    }
}
