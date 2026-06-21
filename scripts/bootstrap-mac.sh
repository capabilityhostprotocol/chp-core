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

# Find Python 3.11+ — prefer brew's explicit binaries over pyenv shims,
# which may intercept 'python3' with an older version from .python-version.
PYTHON=""
for candidate in python3.13 python3.12 python3.11; do
  if bin=$(command -v "$candidate" 2>/dev/null); then
    if "$bin" -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null; then
      PYTHON="$bin"
      break
    fi
  fi
done

# Fall back to 'python3' only if it's new enough (handles non-pyenv setups)
if [[ -z "$PYTHON" ]]; then
  if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null; then
    PYTHON="python3"
  fi
fi

if [[ -z "$PYTHON" ]]; then
  echo "" >&2
  echo "Error: Python 3.11+ not found." >&2
  echo "" >&2
  echo "If you have pyenv with an older version pinned, install a newer Python:" >&2
  echo "  brew install python@3.12" >&2
  echo "Then re-run this script — it will find brew's python3.12 automatically." >&2
  exit 1
fi

echo "==> Using $PYTHON ($("$PYTHON" --version))"

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
  "$PYTHON" -m pip install -e "${REPO_ROOT}/packages/python" "${REPO_ROOT}/packages/chp-host"
  for pkg in "${COMMON_ADAPTERS[@]}"; do
    "$PYTHON" -m pip install -e "${REPO_ROOT}/packages/${pkg}"
  done
  if [[ "${ROLE}" == "primary" ]]; then
    for pkg in "${PRIMARY_ADAPTERS[@]}"; do
      "$PYTHON" -m pip install -e "${REPO_ROOT}/packages/${pkg}"
    done
  fi
else
  # PyPI + GitHub Releases fallback.
  # New packages appear on PyPI gradually (4/day limit on new project creation).
  # --find-links covers the gap: pip prefers PyPI when the version is there,
  # falls back to the release asset if not.
  GH_RELEASE_LINKS="https://github.com/capabilityhostprotocol/chp-core/releases/expanded_assets/v0.8.0"
  PIP_INSTALL="$PYTHON -m pip install --find-links ${GH_RELEASE_LINKS}"

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
# Add this Python's scripts dir to PATH so the installed chp-host binary is found
# even when pyenv shims shadow the system PATH.
PY_SCRIPTS="$("$PYTHON" -c "import sysconfig; print(sysconfig.get_path('scripts'))")"
export PATH="${PY_SCRIPTS}:${PATH}"
chp-host init --role "${ROLE}" --yes
