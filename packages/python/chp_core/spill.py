"""chp.spill.chat — GOVERNED cloud-spill (proposal 0006).

Cloud-spill used to be a raw urlopen byte pump around the pipeline: no gates,
no evidence, no token accounting — and it fired silently as the local-failure
fallback. This capability replaces it: spill traffic now runs the full gate
pipeline, brackets in ``execution_*`` evidence, and emits the same
``http_response`` usage events the http adapter does — so token accounting
works with zero metrics changes. It is an async generator (modes
``["sync","stream"]``): the arc's real end-to-end streaming path.
"""

from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen

from .types import JSON, CapabilityDescriptor, StreamResult

SPILL_CAPABILITY_ID = "chp.spill.chat"
_TIMEOUT = 180


def spill_endpoint() -> tuple[str, str] | None:
    """(base_url, api_key) for the configured cloud endpoint, or None."""
    base = os.environ.get("CHP_SPILL_BASE_URL")
    return (base.rstrip("/"), os.environ.get("CHP_SPILL_API_KEY", "")) if base else None


def _clean(payload: JSON) -> JSON:
    return {k: v for k, v in payload.items() if not k.startswith("chp_")}


def _usage_fields(usage: JSON, model) -> JSON:
    return {
        "prompt_tokens": int(usage.get("prompt_tokens") or 0),
        "completion_tokens": int(usage.get("completion_tokens") or 0),
        "total_tokens": int(usage.get("total_tokens")
                            or (usage.get("prompt_tokens") or 0)
                            + (usage.get("completion_tokens") or 0)),
        "model": model,
    }


async def _spill_chat(ctx, payload: JSON):
    """Async-generator handler. Stream mode yields the upstream's OpenAI chunk
    objects as deltas; sync mode goes straight to the terminal StreamResult
    (whose ``response`` carries the raw OpenAI response for the shim). Both
    modes emit an ``http_response`` usage event — the token-accounting shape
    the metrics already read."""
    endpoint = spill_endpoint()
    if endpoint is None:
        raise RuntimeError("no spill endpoint configured (CHP_SPILL_BASE_URL)")
    base, key = endpoint
    body = _clean(payload)
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {key}"}

    if ctx.envelope.mode == "stream":
        body["stream"] = True
        req = Request(f"{base}/chat/completions", data=json.dumps(body).encode(),
                      headers=headers, method="POST")
        content_parts: list[str] = []
        usage: JSON = {}
        model = body.get("model")
        with urlopen(req, timeout=_TIMEOUT) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8").strip()
                if not line.startswith("data: "):
                    continue
                data_str = line[len("data: "):]
                if data_str == "[DONE]":
                    break
                chunk = json.loads(data_str)
                usage = chunk.get("usage") or usage
                model = chunk.get("model") or model
                delta = ((chunk.get("choices") or [{}])[0].get("delta")) or {}
                if isinstance(delta.get("content"), str):
                    content_parts.append(delta["content"])
                yield chunk
        fields = _usage_fields(usage, model)
        ctx.emit("http_response", {"url": f"{base}/chat/completions",
                                   "status": 200, **fields}, redacted=False)
        yield StreamResult({
            "message": {"role": "assistant", "content": "".join(content_parts)},
            "finish_reason": "stop",
            "spilled_to": base,
            **fields,
        })
    else:
        req = Request(f"{base}/chat/completions", data=json.dumps(body).encode(),
                      headers=headers, method="POST")
        with urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        fields = _usage_fields(data.get("usage") or {}, data.get("model") or body.get("model"))
        ctx.emit("http_response", {"url": f"{base}/chat/completions",
                                   "status": 200, **fields}, redacted=False)
        message = ((data.get("choices") or [{}])[0].get("message")) or {}
        yield StreamResult({
            "message": message,
            "finish_reason": ((data.get("choices") or [{}])[0].get("finish_reason")) or "stop",
            "response": data,
            "spilled_to": base,
            **fields,
        })


def register_spill_capability(host) -> None:
    """Register chp.spill.chat on *host* (idempotent). Risk tier ``high`` on
    purpose: spill sends conversation data to an external cloud — if a
    deployment's policy caps risk below that, the spill being BLOCKED is the
    policy working, not a bug (it used to bypass policy entirely)."""
    if SPILL_CAPABILITY_ID in getattr(host, "_capabilities", {}):
        return
    host.register(
        CapabilityDescriptor(
            id=SPILL_CAPABILITY_ID,
            version="1.0.0",
            description="Governed cloud-spill chat: OpenAI-compatible completion "
                        "against the configured CHP_SPILL_BASE_URL endpoint, with "
                        "evidence + token accounting (proposal 0006).",
            modes=["sync", "stream"],
            risk="high",
            tags=["inference", "spill"],
            emits=["http_response"],
        ),
        _spill_chat,
    )
