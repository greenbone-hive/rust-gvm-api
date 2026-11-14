#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_ARGS=(
  -f "${ROOT_DIR}/tests/e2e/compose.direct-openvasd.yaml"
  -f "${ROOT_DIR}/tests/e2e/compose.enterprise-agent-control.yaml"
)

if [[ -z "${GVM_GATEWAY_E2E_RUN_SCOPE:-}" ]]; then
  echo "GVM_GATEWAY_E2E_RUN_SCOPE is required for isolated enterprise Compose state" >&2
  exit 2
fi
if [[ ! "${GVM_GATEWAY_E2E_RUN_SCOPE}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
  echo "GVM_GATEWAY_E2E_RUN_SCOPE contains unsupported characters" >&2
  exit 2
fi
export COMPOSE_PROJECT_NAME="rust-gvm-api-enterprise-${GVM_GATEWAY_E2E_RUN_SCOPE}"

if [[ "${1:-}" == "up" || "${1:-}" == "run" ]]; then
  : "${GVM_GATEWAY_E2E_AGENT_CONTROL_IMAGE:?exact Agent Control image digest is required}"
  : "${GVM_GATEWAY_E2E_AGENT_CONTROL_SOURCE:?exact Agent Control source checkout is required}"
  : "${GVM_GATEWAY_E2E_AGENT_CONTROL_BUILD_MANIFEST:?exact Agent Control build manifest is required}"
  [[ "${GVM_GATEWAY_E2E_AGENT_CONTROL_IMAGE}" =~ @sha256:[0-9a-f]{64}$ ]] || {
    echo "Agent Control image must be an immutable repository digest" >&2
    exit 2
  }
  python3 "${ROOT_DIR}/scripts/validate-direct-openvasd-pins.py"
  python3 "${ROOT_DIR}/scripts/validate-enterprise-agent-control-inputs.py"
fi

if docker compose version >/dev/null 2>&1; then
  exec docker compose "${COMPOSE_ARGS[@]}" --profile direct-openvasd --profile enterprise-agent-control "$@"
fi
if command -v podman-compose >/dev/null 2>&1; then
  exec podman-compose "${COMPOSE_ARGS[@]}" --profile direct-openvasd --profile enterprise-agent-control "$@"
fi
echo "Neither docker compose nor podman-compose is available" >&2
exit 1
