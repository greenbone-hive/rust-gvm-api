#!/usr/bin/env bash
set -euo pipefail

SCANNER_UUID="08b69003-5fc2-4037-a479-93b440211c73"
RESET_URL="http://127.0.0.1:8086/_emulator/reset"

configure_scanner() {
  local host="$1"
  local port="$2"
  ./scripts/compose-direct-openvasd.sh exec -T --user gvmd gvmd \
    gvmd "--modify-scanner=${SCANNER_UUID}" \
    "--scanner-host=${host}" "--scanner-port=${port}" --scanner-type=openvasd
}

reset_emulator() {
  curl --fail --silent --show-error -X POST \
    -H 'X-Emulator-Reset-Token: issue-678-shadow-reset' \
    -H 'Content-Type: application/json' \
    --data '{"not_ready_responses":0}' "${RESET_URL}"
}

restore_happy_path() {
  configure_scanner openvasd-backend 8086 || true
  reset_emulator || true
}
trap restore_happy_path EXIT

scenarios=(http-400 http-500 malformed-body malformed-header timeout)
ports=(8400 8500 8600 8700 8800)

for index in "${!scenarios[@]}"; do
  scenario="${scenarios[${index}]}"
  port="${ports[${index}]}"
  echo "exercising direct-OpenVASD fault scenario ${scenario} through gvmd/gateway"
  reset_emulator
  configure_scanner openvasd-scenario-proxy "${port}"
  GVM_GATEWAY_E2E_SCANNER_BACKEND_URL= \
  GVM_GATEWAY_E2E_EXPECTED_SCANNER_SCENARIO= \
  GVM_GATEWAY_E2E_OPENVASD_FAULT_SCENARIO="${scenario}" \
  GVM_GATEWAY_E2E_SCAN_TIMEOUT_SECS=120 \
  GVM_GATEWAY_E2E_POLL_INTERVAL_SECS=2 \
    cargo test -p gvm-gateway-e2e --test rest_openvasd_fault_mapping \
      rest_openvasd_faults_have_bounded_gateway_mappings -- \
      --ignored --exact --nocapture
done

restore_happy_path
trap - EXIT
