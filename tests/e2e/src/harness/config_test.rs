// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::config::validate_shadow_identities;

#[test]
fn shadow_identity_guard_rejects_backend_target_conflation() {
    // Regression contract for issue #678: a typo must not turn the scanner
    // backend into the synthetic host that the scan request is meant to target.
    let error = validate_shadow_identities("e2e-target", Some("E2E-TARGET"))
        .expect_err("equal identities must fail closed");
    assert!(error.to_string().contains("must differ"));
}

#[test]
fn shadow_identity_guard_accepts_separate_services_and_the_osp_default() {
    // The explicit direct lane is separated, while the legacy OSP lane remains
    // valid because it does not configure a direct-backend identity.
    validate_shadow_identities("e2e-target", Some("openvasd-backend"))
        .expect("separate identities should be accepted");
    validate_shadow_identities("openvasd", None).expect("OSP defaults should remain unchanged");
}
