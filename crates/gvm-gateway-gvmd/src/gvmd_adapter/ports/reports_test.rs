// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_gateway_domain::GatewayError;

use super::reports::map_report_export_state;

#[test]
fn unknown_report_export_status_fails_closed() {
    // A newly introduced gvmd state must never be guessed as ready or otherwise
    // allow downloading an artifact before the lifecycle mapping is reviewed.
    let error = map_report_export_state("new_backend_state").unwrap_err();

    assert!(matches!(
        error,
        GatewayError::BackendUnavailable(detail)
            if detail == "backend returned an unsupported report export lifecycle state"
    ));
}
