"""Self-provision the ollama runtime for the local_llm adapter.

Adapter-first: the adapter owns its runtime, so *pushing the adapter* makes a node
inference-ready — even a sudo-less headless box where the official `install.sh` (root:
/usr/local/bin + systemd) can't run. On Linux we fetch the official release bundle into a
node-local dir (no root, no systemd) and start `ollama serve`. macOS/Windows keep their own
installers, so we only auto-install on Linux.

Downloads use `curl` (not the http/transport adapter): this is a one-time infra bootstrap of
a ~1.5 GB binary bundle, not a governed request/response cap — the same tool + source
(`ollama-linux-<arch>.tar.zst`, zstd) the official install.sh uses. Best-effort throughout:
any failure returns False and the caller falls through to its normal "no backend" handling.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

# Root-free install root (matches the node agent's state dir convention).
_OLLAMA_HOME = Path.home() / ".chp-home-node" / "ollama-bin"


def _locate() -> str | None:
    for p in ("/opt/homebrew/bin/ollama", "/usr/local/bin/ollama", "/usr/bin/ollama",
              str(_OLLAMA_HOME / "bin" / "ollama")):
        if os.path.exists(p):
            return p
    return shutil.which("ollama")


def _install_unprivileged() -> str:
    """Fetch the official ollama release bundle and extract it into a node-local dir — no root,
    no systemd. Bundle: ``ollama-linux-<arch>.tar.zst`` from GitHub releases (the ollama.com
    redirect points at a dead un-versioned .tgz); zstd-compressed, so extract with ``tar --zstd``
    (GNU tar on modern Linux). The binary finds its runners (``lib/ollama``) relative to itself."""
    arch = {"x86_64": "amd64", "aarch64": "arm64",
            "arm64": "arm64"}.get(platform.machine(), "amd64")
    url = (f"https://github.com/ollama/ollama/releases/latest/download/"
           f"ollama-linux-{arch}.tar.zst")
    _OLLAMA_HOME.mkdir(parents=True, exist_ok=True)
    archive = _OLLAMA_HOME / "ollama.tar.zst"
    subprocess.run(["curl", "-fsSL", "-o", str(archive), url], check=True, timeout=1800)
    subprocess.run(["tar", "--zstd", "-xf", str(archive), "-C", str(_OLLAMA_HOME)],
                   check=True)                       # -> bin/ollama, lib/ollama/*
    archive.unlink(missing_ok=True)
    binp = _OLLAMA_HOME / "bin" / "ollama"
    if not binp.exists():
        raise RuntimeError(f"ollama bundle extracted but {binp} is missing")
    binp.chmod(0o755)
    return str(binp)


def _serving(url: str) -> bool:
    return subprocess.run(
        ["curl", "-fsS", "-m", "2", f"{url.rstrip('/')}/api/tags"],
        capture_output=True).returncode == 0


def ensure_ollama(url: str, *, models_dir: str | None = None) -> bool:
    """Ensure ollama is serving at ``url`` — locate/install (Linux, unprivileged) + serve.

    Returns True iff ollama is serving afterward. Only auto-installs on Linux (macOS/Windows
    have their own installers). Best-effort: install/serve failures return False.
    """
    if _serving(url):
        return True
    if platform.system() != "Linux":
        return False
    binp = _locate() or _install_unprivileged()
    env = {**os.environ}
    if models_dir:
        Path(models_dir).mkdir(parents=True, exist_ok=True)
        env["OLLAMA_MODELS"] = models_dir
    u = urlparse(url if "://" in url else "http://" + url)
    env["OLLAMA_HOST"] = f"{u.hostname or '127.0.0.1'}:{u.port or 11434}"
    subprocess.Popen([binp, "serve"], env=env, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    for _ in range(30):                              # ~30s for cold serve to bind
        time.sleep(1)
        if _serving(url):
            return True
    return False
