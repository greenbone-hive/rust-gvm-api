#!/usr/bin/env bash
set -euo pipefail

# Keep the existing OSP harness untouched while ensuring one failure does not
# prevent later named community contracts from producing comparison evidence.
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
exec cargo test -p gvm-gateway-e2e --tests --no-fail-fast -- \
  --include-ignored --nocapture "$@"
