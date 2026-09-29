// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Security-information resources.

/// CERT-Bund and DFN-CERT advisory resources.
pub mod advisories;
/// NVT-family resources.
pub mod families;
/// Vulnerability, CVE, and CPE resources.
pub mod inventory;
/// Network vulnerability test resources.
pub mod nvts;
mod query;
