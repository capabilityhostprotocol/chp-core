"""MessagesAdapter — conversation transcript storage as CHP capabilities."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from dataclasses import dataclass

from chp_core import BaseAdapter, capability

from .backends import CHPFilesystemBackend, JSONLBackend


@dataclass
class MessagesConfig:
    local_base_dir: str = "~/.chp-agent/messages"
    include_content_in_evidence: bool = False  # True for private chp-agent use
    remote_host_url: str | None = None          # env: CHP_MESSAGE_REMOTE_HOST
    remote_host_key: str | None = None          # env: CHP_MESSAGE_REMOTE_KEY
    remote_path_template: str = "/volume1/homes/chp/messages/{session_id}.jsonl"


class MessagesAdapter(BaseAdapter):
    """Conversation transcript storage across JSONL and remote CHP backends."""

    adapter_id = "chp.adapters.messages"
    adapter_name = "Messages"
    adapter_description = "Stores conversation turns in local JSONL and optionally archives to a remote CHP host."
    adapter_category = "storage"
    adapter_tags = ["messages", "transcript", "conversation", "storage"]

    def __init__(self, config: MessagesConfig | None = None) -> None:
        import os
        cfg = config or MessagesConfig()
        # Allow env-var overrides when instantiated without explicit config
        if config is None:
            if os.environ.get("CHP_MESSAGES_BASE_DIR"):
                cfg.local_base_dir = os.environ["CHP_MESSAGES_BASE_DIR"]
            if os.environ.get("CHP_MESSAGES_INCLUDE_CONTENT", "").lower() in ("1", "true", "yes"):
                cfg.include_content_in_evidence = True
            if os.environ.get("CHP_MESSAGE_REMOTE_HOST"):
                cfg.remote_host_url = os.environ["CHP_MESSAGE_REMOTE_HOST"]
            if os.environ.get("CHP_MESSAGE_REMOTE_KEY"):
                cfg.remote_host_key = os.environ["CHP_MESSAGE_REMOTE_KEY"]
        self._config = cfg
        self._jsonl = JSONLBackend(self._config.local_base_dir)
        self._remote: CHPFilesystemBackend | None = (
            CHPFilesystemBackend(
                remote_host_url=self._config.remote_host_url,
                remote_host_key=self._config.remote_host_key,
                path_template=self._config.remote_path_template,
            )
            if self._config.remote_host_url
            else None
        )

    @capability(
        id="chp.adapters.messages.record_turn",
        emits=['message_turn_recorded'],
        version="1.0.0",
        description="Record a conversation turn (user/assistant/system) into the evidence chain and JSONL store.",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "role": {"type": "string", "enum": ["user", "assistant", "system"]},
                "content": {},
                "agent": {"type": "string"},
            },
            "required": ["session_id", "role", "content"],
        },
    )
    async def record_turn(self, ctx, payload: dict) -> dict:
        session_id = payload["session_id"]
        role = payload["role"]
        content = payload["content"]
        agent = payload.get("agent", "")

        content_hash = hashlib.sha256(
            json.dumps(content, sort_keys=True, default=str).encode()
        ).hexdigest()

        word_count = _word_count(content)

        turn: dict = {
            "session_id": session_id,
            "role": role,
            "agent": agent,
            "word_count": word_count,
            "content_hash": content_hash,
            "ts": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        }
        if self._config.include_content_in_evidence:
            turn["content"] = content

        await self._jsonl.append(session_id, turn)

        # Also record as ConversationEvent in the chp-core evidence chain
        ctx.host.record_turn(
            ctx.correlation_id,
            role=role,
            content=content,
            agent=agent,
            include_content=self._config.include_content_in_evidence,
        )

        evidence_payload: dict = {
            "session_id": session_id,
            "role": role,
            "word_count": word_count,
            "content_hash": content_hash,
        }
        if self._config.include_content_in_evidence:
            evidence_payload["content"] = content

        ctx.emit("message_turn_recorded", evidence_payload, redacted=False)
        return {"ok": True, "session_id": session_id, "role": role, "content_hash": content_hash}

    @capability(
        id="chp.adapters.messages.load_session",
        emits=['session_loaded'],
        version="1.0.0",
        description="Load all conversation turns for a session from the local JSONL store.",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    )
    async def load_session(self, ctx, payload: dict) -> dict:
        session_id = payload["session_id"]
        turns = await self._jsonl.load(session_id)
        ctx.emit(
            "session_loaded",
            {"session_id": session_id, "turn_count": len(turns)},
            redacted=False,
        )
        return {"session_id": session_id, "turns": turns, "count": len(turns)}

    @capability(
        id="chp.adapters.messages.list_sessions",
        emits=['sessions_listed'],
        version="1.0.0",
        description="List session IDs that have stored conversation transcripts.",
        input_schema={"type": "object", "properties": {}},
    )
    async def list_sessions(self, ctx, payload: dict) -> dict:
        sessions = await self._jsonl.list_sessions()
        ctx.emit("sessions_listed", {"count": len(sessions)}, redacted=False)
        return {"sessions": sessions, "count": len(sessions)}

    @capability(
        id="chp.adapters.messages.backfill_session",
        emits=['session_backfilled'],
        version="1.0.0",
        description="Parse a Claude Code JSONL transcript and backfill human-typed turns into the evidence chain.",
        input_schema={
            "type": "object",
            "properties": {
                "transcript_path": {"type": "string", "description": "Absolute path to the Claude Code session .jsonl file"},
                "session_id": {"type": "string", "description": "Session ID to use (defaults to transcript filename stem)"},
                "agent": {"type": "string", "description": "Agent name to tag turns with (default: claude-code)"},
            },
            "required": ["transcript_path"],
        },
    )
    async def backfill_session(self, ctx, payload: dict) -> dict:
        transcript_path = os.path.expanduser(payload["transcript_path"])
        agent = payload.get("agent", "claude-code")
        session_id = payload.get("session_id") or os.path.splitext(os.path.basename(transcript_path))[0]

        # Load existing turns to avoid duplicates
        existing = await self._jsonl.load(session_id)
        existing_hashes = {t["content_hash"] for t in existing}

        # Tags that mark hook outputs / system injections — skip these
        _SKIP_TAGS = (
            "<local-command", "<command-name", "<command-stdout", "<command-stderr",
            "<system-reminder", "<user-prompt-submit", "<antml-function", "<tool-",
        )

        read_result = await ctx.ainvoke(
            "chp.adapters.filesystem.read_file",
            {"path": transcript_path},
        )
        if not read_result.success:
            raise RuntimeError(f"Cannot read transcript: {read_result.error}")

        turns_added = []
        for raw in read_result.data["content"].splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                line = json.loads(raw)
            except Exception:
                continue
            msg = line.get("message", {})
            if msg.get("role") != "user":
                continue
            content = msg.get("content", "")

            # Extract text blocks
            texts: list[str] = []
            if isinstance(content, str):
                texts = [content]
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        texts.append(block.get("text", ""))

            for text in texts:
                text = text.strip()
                if not text:
                    continue
                if any(tag in text for tag in _SKIP_TAGS):
                    continue
                if len(text) > 2000:
                    # Overly long texts are likely system context injections
                    continue

                content_hash = hashlib.sha256(
                    json.dumps(text, sort_keys=True, default=str).encode()
                ).hexdigest()

                if content_hash in existing_hashes:
                    continue  # Already recorded

                turn: dict = {
                    "session_id": session_id,
                    "role": "user",
                    "agent": agent,
                    "word_count": _word_count(text),
                    "content_hash": content_hash,
                    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "backfill": True,
                }
                if self._config.include_content_in_evidence:
                    turn["content"] = text

                await self._jsonl.append(session_id, turn)
                ctx.host.record_turn(
                    ctx.correlation_id,
                    role="user",
                    content=text,
                    agent=agent,
                    include_content=self._config.include_content_in_evidence,
                    subject={"backfill": True, "session_id": session_id},
                )
                existing_hashes.add(content_hash)
                turns_added.append({"content_hash": content_hash, "word_count": _word_count(text)})

        ctx.emit(
            "session_backfilled",
            {"session_id": session_id, "turns_added": len(turns_added), "transcript_path": transcript_path},
            redacted=False,
        )
        return {
            "ok": True,
            "session_id": session_id,
            "turns_added": len(turns_added),
            "turns": turns_added,
        }

    @capability(
        id="chp.adapters.messages.archive_to_remote",
        version="1.0.0",
        description="Archive a session's local JSONL transcript to the configured remote CHP host.",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    )
    async def archive_to_remote(self, ctx, payload: dict) -> dict:
        if self._remote is None:
            return {"ok": False, "error": "No remote host configured (set remote_host_url in MessagesConfig)"}

        session_id = payload["session_id"]
        turns = await self._jsonl.load(session_id)
        remote_path = await self._remote.write_session(session_id, turns)

        archive_hash = hashlib.sha256(
            json.dumps(turns, sort_keys=True).encode()
        ).hexdigest()

        ctx.emit(
            "session_archived",
            {"session_id": session_id, "remote_path": remote_path, "content_hash": archive_hash},
            redacted=False,
        )
        return {"ok": True, "session_id": session_id, "remote_path": remote_path, "content_hash": archive_hash}


def _word_count(content) -> int:
    if isinstance(content, str):
        return len(content.split())
    if isinstance(content, list):
        return sum(_word_count(item) for item in content)
    if isinstance(content, dict):
        return _word_count(content.get("text", ""))
    return 0
