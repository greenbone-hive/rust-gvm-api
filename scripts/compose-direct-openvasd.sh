#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
COMPOSE_ARGS=(-f "${ROOT_DIR}/tests/e2e/compose.direct-openvasd.yaml")
if [[ "${GVM_GATEWAY_E2E_OPENVASD_KIND:-emulator}" == "real" ]]; then
  COMPOSE_ARGS+=(-f "${ROOT_DIR}/tests/e2e/compose.real-openvasd.yaml")
fi

RUN_SCOPE="${GVM_GATEWAY_E2E_RUN_SCOPE:-local-${UID}}"
RUN_SCOPE="$(printf '%s' "${RUN_SCOPE}" | tr -c 'a-zA-Z0-9_-' '-')"
PROJECT_NAME="rust-gvm-api-openvasd-${RUN_SCOPE}"

if [[ $# -eq 0 ]]; then
  echo "Usage: scripts/compose-direct-openvasd.sh <compose-args...>" >&2
  exit 1
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  exec docker compose --project-name "${PROJECT_NAME}" "${COMPOSE_ARGS[@]}" \
    --profile direct-openvasd "$@"
fi

echo "The direct-OpenVASD lane requires Docker Compose." >&2
exit 1
