#!/usr/bin/env bash
# bootstrap-mac.sh — Install and start a CHP node on macOS.
#
# Usage (fresh machine — installs from PyPI):
#   curl -sSL https://raw.githubusercontent.com/capabilityhostprotocol/chp-core/main/scripts/bootstrap-mac.sh | bash -s -- [ROLE]
#
# Or from a local clone:
#   bash scripts/bootstrap-mac.sh [ROLE] [--dev]
#
# ROLE: primary (default) | worker
# --dev: use local editable installs instead of PyPI (for chp-dev contributors)
#
# On success: chp-host init --role ROLE --yes

set -euo pipefail

ROLE="${1:-primary}"
DEV_MODE=false
for arg in "$@"; do [[ "$arg" == "--dev" ]] && DEV_MODE=true; done

echo "==> CHP bootstrap: macOS — role=${ROLE}${DEV_MODE:+ (dev/editable mode)}"

# Require Python 3.10+
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" || {
  echo "Error: Python 3.10+ required. Install via: brew install python@3.12" >&2
  exit 1
}

# Adapters common to all roles
COMMON_ADAPTERS=(
  chp-adapter-http
  chp-adapter-filesystem
  chp-adapter-process
  chp-adapter-audit
  chp-adapter-jobs
  chp-adapter-tailscale
  chp-adapter-secrets
  chp-adapter-mcp
)

# Primary-only adapters
PRIMARY_ADAPTERS=(
  chp-adapter-git
  chp-adapter-github
  chp-adapter-radicle
  chp-adapter-planning
  chp-adapter-delegation
  chp-adapter-safety
  chp-adapter-conformance
  chp-adapter-ci
  chp-adapter-huggingface
  chp-adapter-tei
  chp-adapter-vllm
  chp-adapter-scout
  chp-adapter-smolagents
  chp-adapter-launchd
  chp-adapter-messages
  chp-adapter-composition
  chp-adapter-local-llm
  chp-adapter-registry
)

if [[ "$DEV_MODE" == true ]]; then
  # Editable installs from local repo (for contributors)
  REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
  echo "==> Dev mode: installing from ${REPO_ROOT}"
  pip install -e "${REPO_ROOT}/packages/python" "${REPO_ROOT}/packages/chp-host"
  for pkg in "${COMMON_ADAPTERS[@]}"; do
    pip install -e "${REPO_ROOT}/packages/${pkg}"
  done
  if [[ "${ROLE}" == "primary" ]]; then
    for pkg in "${PRIMARY_ADAPTERS[@]}"; do
      pip install -e "${REPO_ROOT}/packages/${pkg}"
    done
  fi
else
  # PyPI + GitHub Releases fallback.
  # New packages appear on PyPI gradually (4/day limit on new project creation).
  # --find-links covers the gap: pip prefers PyPI when the version is there,
  # falls back to the release asset if not.
  GH_RELEASE_LINKS="https://github.com/capabilityhostprotocol/chp-core/releases/expanded_assets/v0.8.0"
  PIP_INSTALL="pip install --find-links ${GH_RELEASE_LINKS}"

  echo "==> Installing chp-core + chp-host..."
  ${PIP_INSTALL} "chp-core>=0.8.0" "chp-host>=0.8.0"

  echo "==> Installing common adapters..."
  ${PIP_INSTALL} "${COMMON_ADAPTERS[@]}"

  if [[ "${ROLE}" == "primary" ]]; then
    echo "==> Installing primary-role adapters..."
    ${PIP_INSTALL} "${PRIMARY_ADAPTERS[@]}"
  fi
fi

echo "==> Running chp-host init --role ${ROLE} --yes"
chp-host init --role "${ROLE}" --yes
