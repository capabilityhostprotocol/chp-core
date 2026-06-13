"""Standalone CHP host that registers the chp-adapter-* packages.

Depends only on ``chp-core`` and the ``chp-adapter-*`` packages — never on
chp-agent. This is the reference for hosting these adapters in your own app: each
is registered via ``register_adapter`` and gated, fail-soft, on its own
env/config, so the host comes up with whatever you have configured.

Config (see .env.example):
  GITHUB_TOKEN                GitHub PAT (optional; public reads work without)
  DATABASE_URL / POSTGRES_DSN Postgres DSN (enables the postgres adapter)
  SLACK_BOT_TOKEN             Slack bot token (enables outbound Slack)
  SLACK_SIGNING_SECRET        Slack signing secret (enables inbound Slack)
  CHP_MCP_CONFIG              path to an mcp.json (default: ./mcp.json)
  CHP_WEBHOOK_SECRETS         path to webhook secrets json (default: ./webhook.secrets.json)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

HERE = Path(__file__).resolve().parent
DEFAULT_STORE = ".chp/local-adapter-host.sqlite"


def build_local_adapter_host(store_path: str = DEFAULT_STORE) -> LocalCapabilityHost:
    host = LocalCapabilityHost(
        "chp-local-adapter-host",
        store=SQLiteEvidenceStore(str(store_path)),
        metadata={"description": "Standalone host for local chp-adapter-* testing."},
    )

    summary: list[tuple[str, str]] = []
    summary.append(("github", _register_github(host)))
    summary.append(("postgres", _register_postgres(host)))
    summary.append(("webhook", _register_webhook(host)))
    summary.append(("slack", _register_slack(host)))
    summary.append(("mcp", _register_mcp(host)))

    print("Adapter registration:")
    for name, status in summary:
        print(f"  {name:<9} {status}")
    return host


def _register_github(host: LocalCapabilityHost) -> str:
    try:
        from chp_adapter_github import GitHubAdapter, GitHubConfig
    except ImportError:
        return "skipped (chp-adapter-github not installed)"
    register_adapter(host, GitHubAdapter(GitHubConfig()))
    authed = bool(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
    return f"registered ({'authenticated' if authed else 'unauthenticated reads'})"


def _register_postgres(host: LocalCapabilityHost) -> str:
    if not (os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_DSN")):
        return "skipped (no DATABASE_URL/POSTGRES_DSN)"
    try:
        from chp_adapter_postgres import PostgresAdapter, PostgresConfig
    except ImportError:
        return "skipped (chp-adapter-postgres not installed)"
    register_adapter(host, PostgresAdapter(PostgresConfig()))
    return "registered"


def _register_webhook(host: LocalCapabilityHost) -> str:
    path = Path(os.environ.get("CHP_WEBHOOK_SECRETS") or (HERE / "webhook.secrets.json"))
    if not path.is_file():
        return f"skipped (no secrets file at {path})"
    try:
        from chp_adapter_webhook import WebhookAdapter, WebhookConfig
    except ImportError:
        return "skipped (chp-adapter-webhook not installed)"
    raw = json.loads(path.read_text())
    secrets = raw.get("secrets", raw) if isinstance(raw, dict) else {}
    register_adapter(host, WebhookAdapter(WebhookConfig(
        secrets={k: str(v) for k, v in secrets.items() if not isinstance(v, dict)},
        default_secret=raw.get("default_secret") if isinstance(raw, dict) else None,
    )))
    return f"registered ({len(secrets)} provider secrets)"


def _register_slack(host: LocalCapabilityHost) -> str:
    if not (os.environ.get("SLACK_BOT_TOKEN") or os.environ.get("SLACK_SIGNING_SECRET")):
        return "skipped (no SLACK_BOT_TOKEN/SLACK_SIGNING_SECRET)"
    try:
        from chp_adapter_slack import SlackAdapter, SlackConfig
    except ImportError:
        return "skipped (chp-adapter-slack not installed)"
    register_adapter(host, SlackAdapter(SlackConfig()))
    out = "outbound" if os.environ.get("SLACK_BOT_TOKEN") else ""
    inb = "inbound" if os.environ.get("SLACK_SIGNING_SECRET") else ""
    return f"registered ({'+'.join(x for x in (out, inb) if x)})"


def _register_mcp(host: LocalCapabilityHost) -> str:
    path = Path(os.environ.get("CHP_MCP_CONFIG") or (HERE / "mcp.json"))
    if not path.is_file():
        return f"skipped (no config at {path})"
    try:
        from chp_adapter_mcp import MCPAdapter, MCPServerConfig
    except ImportError:
        return "skipped (chp-adapter-mcp not installed)"
    try:
        servers = json.loads(path.read_text()).get("mcpServers", {})
    except (OSError, ValueError) as exc:
        return f"error reading config: {exc}"
    count = 0
    for name, spec in servers.items():
        try:
            register_adapter(host, MCPAdapter(MCPServerConfig(
                name=name,
                command=spec.get("command"),
                args=spec.get("args", []),
                env=spec.get("env"),
                url=spec.get("url"),
            )))
            count += 1
        except Exception as exc:  # a broken server must not break host startup
            print(f"  mcp[{name}] failed: {exc}")
    return f"registered ({count} server(s))" if count else "skipped (no servers connected)"
