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

# Find Python 3.11+ — prefer explicit binaries over a pyenv shim, which may
# intercept 'python3' with an older version from a pinned .python-version.
PYTHON=""
for candidate in python3.13 python3.12 python3.11; do
  if bin=$(command -v "$candidate" 2>/dev/null); then
    if "$bin" -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null; then
      PYTHON="$bin"
      break
    fi
  fi
done

# Fall back to 'python3' only if it's new enough (handles non-pyenv setups).
if [[ -z "$PYTHON" ]]; then
  if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null; then
    PYTHON="python3"
  fi
fi

if [[ -z "$PYTHON" ]]; then
  echo "" >&2
  echo "Error: Python 3.11+ not found." >&2
  echo "" >&2
  echo "Install a newer Python, then re-run this script:" >&2
  echo "  Debian/Ubuntu: sudo apt-get install -y python3.12 python3.12-venv" >&2
  echo "  Fedora:        sudo dnf install -y python3.12" >&2
  echo "If you use pyenv: pyenv install 3.12 && pyenv local 3.12" >&2
  exit 1
fi

echo "==> Using $PYTHON ($("$PYTHON" --version))"

COMMON_ADAPTERS=(
  chp-adapter-http
  chp-adapter-filesystem
  chp-adapter-process
  chp-adapter-audit
  chp-adapter-jobs
  chp-adapter-secrets
  chp-adapter-mcp
  chp-adapter-host
)

if [[ "$DEV_MODE" == true ]]; then
  REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
  echo "==> Dev mode: installing from ${REPO_ROOT}"
  "$PYTHON" -m pip install -e "${REPO_ROOT}/packages/python" "${REPO_ROOT}/packages/chp-host"
  for pkg in "${COMMON_ADAPTERS[@]}"; do
    "$PYTHON" -m pip install -e "${REPO_ROOT}/packages/${pkg}"
  done
else
  GH_RELEASE_LINKS="https://github.com/capabilityhostprotocol/chp-core/releases/expanded_assets/v0.8.0"
  PIP_INSTALL="$PYTHON -m pip install --find-links ${GH_RELEASE_LINKS}"

  echo "==> Installing chp-core + chp-host..."
  ${PIP_INSTALL} "chp-core>=0.8.0" "chp-host>=0.8.0"
  echo "==> Installing common adapters..."
  ${PIP_INSTALL} "${COMMON_ADAPTERS[@]}"
fi

echo "==> Running chp-host init --role ${ROLE} --yes"
# Add this Python's scripts dir to PATH so the installed chp-host binary is
# found even when a pyenv shim shadows the system PATH.
PY_SCRIPTS="$("$PYTHON" -c "import sysconfig; print(sysconfig.get_path('scripts'))")"
export PATH="${PY_SCRIPTS}:${PATH}"
chp-host init --role "${ROLE}" --yes

echo ""
echo "==> Bootstrap complete."
echo "    Service started via systemd (see output above)."
echo "    Then on your PRIMARY mac:"
echo "      chp-host mesh add http://<this-ip>:8803"
