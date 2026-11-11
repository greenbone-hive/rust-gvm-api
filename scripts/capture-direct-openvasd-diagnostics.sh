#!/usr/bin/env bash
set -euo pipefail

EVIDENCE_DIR="${1:-dist/e2e-openvasd/raw}"
mkdir -p "${EVIDENCE_DIR}"

./scripts/compose-direct-openvasd.sh ps -a > "${EVIDENCE_DIR}/compose-ps.txt" 2>&1 || true
./scripts/compose-direct-openvasd.sh logs --no-color --timestamps --tail 2000 \
  > "${EVIDENCE_DIR}/compose.log.unbounded" 2>&1 || true
# Bound the aggregate even when a component emitted very large individual lines.
tail -c 2097152 "${EVIDENCE_DIR}/compose.log.unbounded" \
  > "${EVIDENCE_DIR}/compose.log" || true
rm -f "${EVIDENCE_DIR}/compose.log.unbounded"

{
  docker version
  docker compose version
} > "${EVIDENCE_DIR}/runner-container-runtime.txt" 2>&1 || true
