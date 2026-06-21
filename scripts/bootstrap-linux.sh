#!/usr/bin/env bash
# bootstrap-linux.sh — Install and start a CHP node on Linux (Pi/Ubuntu).
#
# Usage (fresh machine — installs from PyPI):
#   curl -sSL https://raw.githubusercontent.com/capabilityhostprotocol/chp-core/main/scripts/bootstrap-linux.sh | bash -s -- [ROLE]
#
# Or from a local clone:
#   bash scripts/bootstrap-linux.sh [ROLE] [--dev]
#
# ROLE: auto-detected (raspi on aarch64, linux-worker on x86_64) or pass explicitly.
# --dev: use local editable installs instead of PyPI (for contributors)

set -euo pipefail

ARCH="$(uname -m)"
DEV_MODE=false
for arg in "$@"; do [[ "$arg" == "--dev" ]] && DEV_MODE=true; done

if [[ -z "${1:-}" || "${1:-}" == "--dev" ]]; then
  if [[ "${ARCH}" == "aarch64" || "${ARCH}" == "arm64" ]]; then
    ROLE="raspi"
  else
    ROLE="linux-worker"
  fi
else
  ROLE="$1"
fi

echo "==> CHP bootstrap: Linux (${ARCH}) — role=${ROLE}${DEV_MODE:+ (dev/editable mode)}"

COMMON_ADAPTERS=(
  chp-adapter-http
  chp-adapter-filesystem
  chp-adapter-process
  chp-adapter-audit
  chp-adapter-jobs
  chp-adapter-secrets
  chp-adapter-mcp
)

if [[ "$DEV_MODE" == true ]]; then
  REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
  echo "==> Dev mode: installing from ${REPO_ROOT}"
  pip install -e "${REPO_ROOT}/packages/python" "${REPO_ROOT}/packages/chp-host"
  for pkg in "${COMMON_ADAPTERS[@]}"; do
    pip install -e "${REPO_ROOT}/packages/${pkg}"
  done
else
  echo "==> Installing chp-core + chp-host from PyPI..."
  pip install "chp-core>=0.7.0" "chp-host>=0.7.0"
  echo "==> Installing common adapters..."
  pip install "${COMMON_ADAPTERS[@]}"
fi

echo "==> Running chp-host init --role ${ROLE} --yes"
chp-host init --role "${ROLE}" --yes

echo ""
echo "==> Bootstrap complete."
echo "    Service started via systemd (see output above)."
echo "    Then on your PRIMARY mac:"
echo "      chp-host mesh add http://<this-ip>:8803"
