"""Shared agent primitives: role→model tiering, portable Skills, and tool-RAG.

Domain- and product-neutral. Every CHP product that provisions an agent needs the same three things:
pick a model for a profile's *role* from the models a node actually has, carry a portable/signed
*skill* (an instruction + a scoped tool set), and rank capabilities against a task so the agent gets
the few relevant tools rather than an overflowing set (which degrades small local models).

This is the single home for logic that had forked across chp-home (``assistant.py``/``skills.py``),
chp-platform (``agent_routing.py``/``agent.py``), and chp-agent (``host.py``). The tiering here
reproduces **chp-home's mesh-grounded semantics** — coder-family models win the tool/code tiers at the
*smallest* sufficient size (they emit clean tool-call JSON; a bigger coder just costs VRAM), and the
reason/agent tiers take the largest model *that can call tools* (an agent tier that can't tool-call is
useless). A product that wants a different policy (e.g. a cloud tier where bigger is strictly better)
passes its own ``rules=`` — the default is conservative because a wrong pick on a real node either
fails to fit or can't call a tool.

Pure stdlib; sits alongside :mod:`chp_core.agent_interface` (capability→tool-schema projection),
:class:`chp_core.types.Actor`, and :class:`chp_core.types.AutonomyProfile`.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Sequence

__all__ = [
    "ModelCard",
    "ModelCatalog",
    "resolve_model",
    "DEFAULT_ROLE_RULES",
    "Skill",
    "rank_by_cosine",
]

# ── model tiering ─────────────────────────────────────────────────────────────

_SIZE_RE = re.compile(r"(\d+(?:\.\d+)?)\s*b\b", re.IGNORECASE)


@dataclass
class ModelCard:
    """A model available to serve a role. ``params_b`` (billions) is the size proxy the tiers sort on.
    ``coder``/``tools``/``embedding`` are first-class traits (the tool tier needs ``tools``); ``has()``
    keeps tag/family/name-substring compatibility. Populate from a node's model list or a static
    catalog and refresh when the fleet changes."""

    name: str
    params_b: float = 0.0
    family: str = ""
    backend: str = ""              # ollama | mlx | colibri | openai_server | …
    context: int = 0               # max context window (0 = unknown)
    coder: bool = False
    tools: bool = False
    embedding: bool = False
    tags: list[str] = field(default_factory=list)

    def has(self, trait: str) -> bool:
        """True if the model carries a trait — by explicit flag/tag, family, or name substring."""
        t = trait.lower()
        if t == "coder":
            return self.coder or "coder" in self.name.lower()
        if t == "tools":
            return self.tools
        if t == "embedding":
            return self.embedding
        return (t in {x.lower() for x in self.tags} or t in self.family.lower()
                or t in self.name.lower())

    @classmethod
    def from_name(cls, name: str, **over: Any) -> "ModelCard":
        """Infer a card from a model name like ``qwen2.5-coder:14b`` (size 14, coder trait)."""
        m = _SIZE_RE.search(name)
        card = cls(name=name, params_b=float(m.group(1)) if m else 0.0,
                   coder="coder" in name.lower())
        for k, v in over.items():
            setattr(card, k, v)
        return card


def _smallest(items: list[ModelCard]) -> ModelCard | None:
    # min() returns the first item on a tie — insertion-order tie-breaking (chp-home parity).
    return min(items, key=lambda c: c.params_b) if items else None


def _coder(items: list[ModelCard]) -> ModelCard | None:
    # A coder model emits the cleanest tool-call JSON; the coder trait already guarantees that, so take
    # the SMALLEST coder (speed + fits tight nodes). Fall back coder → tools-capable → any.
    pool = [c for c in items if c.has("coder")] or [c for c in items if c.has("tools")] or items
    return _smallest(pool)


def _largest(items: list[ModelCard]) -> ModelCard | None:
    # The hardest tiers want the biggest model that can still CALL TOOLS — a non-tool-calling model is
    # useless for agent work. Fall back to any only when nothing advertises tools.
    pool = [c for c in items if c.has("tools")] or items
    return max(pool, key=lambda c: c.params_b) if pool else None


# Role → selection rule. Products may override this map (e.g. a cloud tier where bigger always wins).
DEFAULT_ROLE_RULES: dict[str, Callable[[list[ModelCard]], "ModelCard | None"]] = {
    "route": _smallest,      # cheap routing / classification
    "chat": _smallest,
    "tool": _coder,          # tool-calling — coder models are the most reliable
    "code": _coder,
    "reason": _largest,      # hardest reasoning
    "agent": _largest,
    "frontier": _largest,
}


class ModelCatalog:
    """A set of available models, queryable by role. Preserves insertion order (tie-breaking is
    first-encountered); build it from a node's model list or static config and refresh on fleet change."""

    def __init__(self, cards: Iterable[ModelCard] | None = None,
                 rules: dict[str, Callable[[list[ModelCard]], "ModelCard | None"]] | None = None) -> None:
        self._cards: list[ModelCard] = list(cards or [])
        self._rules = dict(rules or DEFAULT_ROLE_RULES)

    def __len__(self) -> int:
        return len(self._cards)

    @property
    def cards(self) -> list[ModelCard]:
        return list(self._cards)

    def resolve(self, role: str, *, pin: str | None = None) -> str | None:
        """The model name for a role. A pin (explicit config) always wins; else the role's rule picks
        from the non-embedding models; unknown roles fall back to the largest. None if empty."""
        if pin:
            return pin
        items = [c for c in self._cards if not c.embedding]
        if not items:
            return None
        chosen = self._rules.get(role, _largest)(items)
        return chosen.name if chosen else None


def resolve_model(role: str, catalog: "ModelCatalog | Iterable[ModelCard]", *,
                  pin: str | None = None,
                  rules: dict[str, Callable[[list[ModelCard]], "ModelCard | None"]] | None = None) -> str | None:
    """Convenience: resolve a role to a model name against a catalog (or a raw card iterable)."""
    if not isinstance(catalog, ModelCatalog):
        catalog = ModelCatalog(catalog, rules=rules)
    return catalog.resolve(role, pin=pin)


# ── Skill (signed, portable) ──────────────────────────────────────────────────


@dataclass
class Skill:
    """A portable, signable agent skill: an instruction plus a scoped set of capability ids and the
    agent shape to run them in. ``canonical()`` is the exact byte serialization a provenance signature
    binds to — its field set and encoding are a compatibility surface (changing them invalidates every
    already-signed skill), so extend an *agent profile* around a Skill rather than the Skill itself."""

    name: str
    description: str = ""
    instructions: str = ""
    tools: list[str] = field(default_factory=list)   # capability ids the skill's agent may call
    agent_type: str = "tool"                         # chat | tool | code
    role: str = ""                                   # model tier (route|tool|code|reason|…)
    model: str | None = None                         # explicit pin, overrides role
    version: str = "1"

    def canonical(self) -> bytes:
        """The exact bytes a signature binds to (sorted keys, compact separators)."""
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Skill":
        return cls(**{k: d[k] for k in d if k in cls.__dataclass_fields__})


# ── tool-RAG ──────────────────────────────────────────────────────────────────


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def rank_by_cosine(task_vec: list[float], spec_vecs: list[list[float]], ids: list[str],
                   k: int) -> list[str]:
    """Top-k capability ids by cosine(task, capability-description) — Tool-RAG's core: give the agent
    the relevant tools, not all of them. Stable: ties keep input order."""
    scored = sorted(zip(ids, spec_vecs), key=lambda t: _cosine(task_vec, t[1]), reverse=True)
    return [i for i, _ in scored[:max(0, k)]]
