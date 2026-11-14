#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_DIR="${GVM_GATEWAY_E2E_ENTERPRISE_EVIDENCE_DIR:-${ROOT_DIR}/dist/e2e-enterprise}"
mkdir -p "${EVIDENCE_DIR}"

reset() {
  python3 "${ROOT_DIR}/scripts/reset-enterprise-agent-control.py" \
    >"${EVIDENCE_DIR}/reset-last.json"
}
trap 'reset || true' EXIT

reset

# A feature mismatch exits 78 and stops this script before any REST assertion.
"${ROOT_DIR}/scripts/compose-enterprise-agent-control.sh" run --rm \
  enterprise-feature-preflight >"${EVIDENCE_DIR}/preflight.json"

python3 "${ROOT_DIR}/scripts/configure-enterprise-agent-owner.py" \
  >"${EVIDENCE_DIR}/fixture-configuration.json"

export RUST_TEST_THREADS=1
export GVM_GATEWAY_E2E_ENTERPRISE_AGENT_CONTROL=1
for repetition in 1 2; do
  cargo test -p gvm-gateway-e2e --test rest_enterprise_agent_control \
    rest_enterprise_agent_control_lifecycle_is_repeatable_and_fail_closed -- \
    --ignored --exact --nocapture 2>&1 | tee "${EVIDENCE_DIR}/contracts-${repetition}.log"
  reset
  if [[ "${repetition}" -lt 2 ]]; then
    python3 "${ROOT_DIR}/scripts/configure-enterprise-agent-owner.py" \
      >"${EVIDENCE_DIR}/fixture-configuration-${repetition}.json"
  fi
done
