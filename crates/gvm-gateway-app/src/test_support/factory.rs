// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    future::Future,
    io,
    sync::{Arc, Mutex, OnceLock},
};

use gvm_gateway_domain::SessionManager;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    prelude::*,
};

use crate::{test_support::mocks::*, GatewayPorts, GatewayService};

/// Builds a service with permissive mocks for tests that only care about service wiring.
pub(crate) fn create_test_service() -> GatewayService {
    GatewayService::new(test_ports(), Arc::new(SessionManager::default()))
}

/// Builds the default mock port bundle for app-layer tests.
pub(crate) fn test_ports() -> GatewayPorts {
    GatewayPorts {
        system: Arc::new(MockSystemPort {
            ready: true,
            gmp_version: "22.7".to_string(),
        }),
        alerts: Arc::new(MockAlertPort),
        schedules: Arc::new(MockSchedulePort),
        credentials: Arc::new(MockCredentialPort),
        port_lists: Arc::new(MockPortListPort),
        feeds: Arc::new(MockFeedPort),
        identity: Arc::new(MockIdentityPort),
        targets: Arc::new(MockTargetPort::default()),
        tasks: Arc::new(MockTaskPort),
        auth: Arc::new(MockAuthPort::default()),
        reports: Arc::new(MockReportPort::default()),
        results: Arc::new(MockResultPort),
        scan_configs: Arc::new(MockScanConfigPort),
        scanners: Arc::new(MockScannerPort),
        agents: Arc::new(MockAgentPort),
        supporting_resources: Arc::new(MockSupportingResourcePort),
    }
}

#[derive(Clone, Default)]
struct TestWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl<'a> fmt::MakeWriter<'a> for TestWriter {
    type Writer = TestWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        TestWriterGuard {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

struct TestWriterGuard {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for TestWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Captures tracing output so tests can assert on audit and span behavior.
pub(crate) struct TraceCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
    subscriber: tracing::Dispatch,
}

impl TraceCapture {
    /// Runs a future with this capture's subscriber as the scoped default.
    pub(crate) async fn run<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        // Audit callsite interest is process-global, while these captures are
        // scoped per future. Rebuild so parallel tests cannot leave audit
        // events disabled before this subscriber runs.
        tracing::dispatcher::with_default(
            &self.subscriber,
            tracing::callsite::rebuild_interest_cache,
        );
        let output = future.with_subscriber(self.subscriber.clone()).await;
        tracing::callsite::rebuild_interest_cache();
        output
    }

    /// Returns captured trace output as UTF-8 text.
    pub(crate) fn output(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap()
    }
}

/// Creates an isolated tracing capture for one test.
pub(crate) fn capture_tracing() -> TraceCapture {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = TestWriter {
        buffer: buffer.clone(),
    };
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
            .with_span_events(FmtSpan::CLOSE),
    );

    TraceCapture {
        buffer,
        subscriber: tracing::Dispatch::new(subscriber),
    }
}

/// Serializes tests that assert on tracing output.
///
/// `tracing` callsite interest is process-global enough that several scoped
/// subscribers running in parallel can make target-specific assertions flaky.
pub(crate) async fn lock_tracing() -> AsyncMutexGuard<'static, ()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    ensure_tracing_callsites_stay_enabled();

    LOCK.get_or_init(|| AsyncMutex::new(())).lock().await
}

fn ensure_tracing_callsites_stay_enabled() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(io::sink)
                .with_ansi(false)
                .with_span_events(FmtSpan::CLOSE),
        );

        // These tests assert captured audit and span output. A sink global
        // subscriber keeps callsite interest enabled even while other tests
        // exercise the same callsites without a scoped capture subscriber.
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}
