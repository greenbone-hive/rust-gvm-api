// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Session lifecycle use cases and the background session reaper.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{field, info_span, Instrument};

use gvm_gateway_domain::{
    AuthPort, GatewayError, SessionCreated, SessionInfo, SessionManager, SessionTokenDigest,
};

use crate::{
    service::{emit_audit_event, emit_audit_event_with_session_id, safe_session_id},
    GatewayService,
};

// ============================================================================
// Session lifecycle use cases
// ============================================================================

impl GatewayService {
    /// Borrow the shared session manager.
    pub fn session_manager(&self) -> Arc<SessionManager> {
        Arc::clone(&self.sessions)
    }

    /// Authenticates with the supplied credentials, creates a domain session,
    /// and establishes a backend connection bound to the new token.
    pub async fn create_session(
        &self,
        username: &str,
        password: &str,
    ) -> Result<SessionCreated, GatewayError> {
        let span = info_span!(
            "session.create",
            otel_name = "session.create",
            gvmd_username = %username,
            session_id = field::Empty,
            audit_action = "create",
            audit_resource = "session"
        );

        async move {
            let (session, expired_session_digests) =
                self.sessions.create_draining_expired(username)?;
            disconnect_expired_sessions(
                Arc::clone(&self.auth),
                username,
                expired_session_digests,
                "session.create",
            )
            .await;
            tracing::Span::current().record(
                "session_id",
                field::display(safe_session_id(&session.token)),
            );

            let gmp_version = match self
                .auth
                .authenticate_session(&session.token, username, password)
                .await
            {
                Ok(version) => version,
                Err(err) => {
                    let _ = self.sessions.remove(&session.token);
                    emit_audit_event(
                        "session.create",
                        "failure",
                        username,
                        Some(&session.token),
                        None,
                        None,
                        Some(&err),
                    );
                    return Err(err);
                }
            };

            emit_audit_event(
                "session.create",
                "success",
                username,
                Some(&session.token),
                None,
                None,
                None,
            );

            Ok(SessionCreated {
                token: session.token,
                expires_in: self.sessions.idle_timeout_secs(),
                gmp_version,
            })
        }
        .instrument(span)
        .await
    }

    /// Returns detailed session information without extending the idle timer.
    pub fn get_session(&self, token: &str) -> Result<SessionInfo, GatewayError> {
        let _span = info_span!(
            "session.lookup",
            otel_name = "session.lookup",
            session_id = %safe_session_id(token),
            audit_action = "lookup",
            audit_resource = "session"
        )
        .entered();
        self.sessions.get_info(token)
    }

    /// Closes and destroys a session, disconnecting the backend connection.
    pub async fn delete_session(&self, token: &str) -> Result<(), GatewayError> {
        let span = info_span!(
            "session.teardown",
            otel_name = "session.teardown",
            session_id = %safe_session_id(token),
            audit_action = "delete",
            audit_resource = "session"
        );

        async move {
            let removed = self.sessions.remove(token)?;
            if removed.is_none() {
                let err = GatewayError::NotFound("session not found".to_string());
                emit_audit_event(
                    "session.delete",
                    "failure",
                    "unknown",
                    Some(token),
                    None,
                    None,
                    Some(&err),
                );
                return Err(err);
            }

            let removed = removed.expect("checked is_some");
            let session_digest = SessionTokenDigest::from_token(token);
            match self.cancel_jobs_for_session(&session_digest).await {
                Ok(0) => {}
                Ok(count) => {
                    tracing::info!(count, "session.delete: cancelled session-bound jobs");
                }
                Err(err) => {
                    emit_audit_event(
                        "session.delete",
                        "job_cancel_failed",
                        &removed.user,
                        Some(token),
                        None,
                        None,
                        Some(&err),
                    );
                    return Err(err);
                }
            }
            if let Err(err) = self.auth.disconnect_session(&session_digest).await {
                emit_audit_event(
                    "session.delete",
                    "backend_disconnect_failed",
                    &removed.user,
                    Some(token),
                    None,
                    None,
                    Some(&err),
                );
            }

            emit_audit_event(
                "session.delete",
                "success",
                &removed.user,
                Some(token),
                None,
                None,
                None,
            );

            Ok(())
        }
        .instrument(span)
        .await
    }
}

async fn disconnect_expired_sessions(
    auth: Arc<dyn AuthPort>,
    username: &str,
    session_digests: Vec<SessionTokenDigest>,
    event: &'static str,
) {
    for session_digest in &session_digests {
        let session_id = session_digest.safe_id();
        emit_audit_event_with_session_id(
            "session.expired",
            "cleanup",
            username,
            &session_id,
            None,
            Some("expire"),
            None,
        );
        if let Err(err) = auth.disconnect_session(session_digest).await {
            emit_audit_event_with_session_id(
                "session.disconnect",
                "failure",
                username,
                &session_id,
                None,
                Some("disconnect"),
                Some(&err),
            );
            tracing::warn!(session_id = %session_id, ?err, "{event}: disconnect_session failed");
        }
    }
}

// ============================================================================
// Session Reaper
// ============================================================================

/// Background task that periodically drains idle-expired sessions and
/// disconnects their backend connections.
///
/// This is a dedicated type that encapsulates the reaper lifecycle.
/// Construct it with [`SessionReaper::new`] and spawn it with
/// [`SessionReaper::spawn`].
pub struct SessionReaper {
    sessions: Arc<SessionManager>,
    auth: Arc<dyn AuthPort>,
}

impl SessionReaper {
    /// Create a new session reaper that will drain expired sessions from the
    /// given manager and disconnect them via the given auth port.
    pub fn new(sessions: Arc<SessionManager>, auth: Arc<dyn AuthPort>) -> Self {
        Self { sessions, auth }
    }

    /// Spawn the reaper as a background Tokio task.
    ///
    /// The default sweep interval is half the idle timeout so that expired
    /// sessions are reaped within one full timeout period.  The returned
    /// [`JoinHandle`] can be aborted to stop the reaper (e.g. on server
    /// shutdown).
    pub fn spawn(&self) -> JoinHandle<()> {
        let interval = Duration::from_secs((self.sessions.idle_timeout_secs() / 2).max(1));
        self.spawn_with_interval(interval)
    }

    /// Like [`spawn`](Self::spawn) but with an explicit sweep interval
    /// (useful for testing).
    pub fn spawn_with_interval(&self, interval: Duration) -> JoinHandle<()> {
        let sessions = Arc::clone(&self.sessions);
        let auth = Arc::clone(&self.auth);
        tokio::spawn(Self::run(sessions, auth, interval))
    }

    async fn run(sessions: Arc<SessionManager>, auth: Arc<dyn AuthPort>, interval: Duration) {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            Self::sweep_once(Arc::clone(&sessions), Arc::clone(&auth)).await;
        }
    }

    async fn sweep_once(sessions: Arc<SessionManager>, auth: Arc<dyn AuthPort>) {
        let session_digests = match sessions.drain_expired() {
            Ok(t) => t,
            Err(err) => {
                tracing::warn!(?err, "session reaper: drain_expired failed");
                return;
            }
        };
        let cleaned_count = session_digests.len();
        disconnect_expired_sessions(auth, "unknown", session_digests, "session reaper").await;
        if cleaned_count > 0 {
            tracing::info!(
                count = cleaned_count,
                "session reaper: cleaned up expired sessions"
            );
        }
    }

    #[cfg(test)]
    async fn sweep_once_for_test(&self) {
        Self::sweep_once(Arc::clone(&self.sessions), Arc::clone(&self.auth)).await;
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[path = "session_test.rs"]
mod session_test;
