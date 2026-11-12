// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::super::dto::ScanConfig;
use super::discovery::select_discovery_scan_config_for_backend;

fn scan_config(name: &str) -> ScanConfig {
    ScanConfig {
        id: name.to_owned(),
        name: name.to_owned(),
        comment: None,
        usage_type: Some("scan".to_owned()),
        in_use: None,
        writable: Some(false),
    }
}

#[test]
fn direct_openvasd_prefers_the_populated_exact_discovery_config() {
    // Regression for the severity-metadata fixture: gvmd exposes an empty
    // "Host Discovery" config beside the fixture-backed "Discovery" config.
    // The direct lane must select the latter so a scan includes imported VTs.
    let configs = vec![scan_config("Host Discovery"), scan_config("Discovery")];

    let selected = select_discovery_scan_config_for_backend(&configs, true)
        .expect("direct OpenVASD needs a discovery config");

    assert_eq!(selected.name, "Discovery");
}

#[test]
fn osp_selection_preserves_the_host_discovery_preference() {
    // The direct-lane preference must not perturb the established OSP setup,
    // where Host Discovery remains the most purpose-specific base config.
    let configs = vec![scan_config("Host Discovery"), scan_config("Discovery")];

    let selected = select_discovery_scan_config_for_backend(&configs, false)
        .expect("OSP needs a discovery config");

    assert_eq!(selected.name, "Host Discovery");
}
