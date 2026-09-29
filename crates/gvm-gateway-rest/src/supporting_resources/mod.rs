// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Supporting-resource REST modules.

/// Host and operating-system resources.
pub mod assets;
/// Shared supporting-resource DTOs and query handling.
pub mod common;
/// Filter resources.
pub mod filters;
/// Note resources.
pub mod notes;
/// Override resources.
pub mod overrides;
/// Report-format resources.
pub mod report_formats;
/// Security-information resources.
pub mod secinfo;
/// Tag resources.
pub mod tags;
/// TLS-certificate resources.
pub mod tls_certificates;
