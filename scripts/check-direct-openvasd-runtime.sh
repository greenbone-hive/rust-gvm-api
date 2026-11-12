#!/usr/bin/env bash
set -euo pipefail

EVIDENCE_DIR="${1:-dist/e2e-openvasd/raw}"
mkdir -p "${EVIDENCE_DIR}"
running="$(./scripts/compose-direct-openvasd.sh ps --status running --services)"
required=(
  gvm-gateway
  gvmd
  pg-gvm
  openvasd-backend
  openvasd-scenario-proxy
  e2e-target
)

for service in "${required[@]}"; do
  if ! grep -Fxq "${service}" <<<"${running}"; then
    printf 'required service %s was not running\n' "${service}" >&2
    touch "${EVIDENCE_DIR}/application-failure"
    exit 1
  fi
done

printf '%s\n' "${running}" > "${EVIDENCE_DIR}/running-services.txt"
