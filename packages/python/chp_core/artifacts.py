"""Artifact data plane — content-addressed refs + local store (slice 1).

Large data stays OUT of the control plane: invocation payloads/results carry an
``ArtifactRef`` while the bytes flow through the ``/artifacts`` data-plane
endpoints. Identity IS the content digest — a substituted artifact simply does
not match its ref (the negative-catalog artifact-substitution refusal), and the
store re-verifies the digest on every read so silent corruption surfaces as an
integrity error, never as wrong bytes.

Transfer is bounded by the binding's body cap in this slice.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .types import JSON, utc_now

_PREFIX = "sha256:"


def artifact_id_for(data: bytes) -> str:
    return _PREFIX + hashlib.sha256(data).hexdigest()


class ArtifactIntegrityError(RuntimeError):
    """Stored bytes no longer match their content address."""


@dataclass(slots=True)
class ArtifactRef:
    """Control-plane reference to data-plane content (schemas/artifact-ref.schema.json)."""

    artifact_id: str  # "sha256:<hex>" — the content digest, nothing else
    media_type: str = "application/octet-stream"
    size_bytes: int = 0
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.artifact_id.startswith(_PREFIX) or len(self.artifact_id) != len(_PREFIX) + 64:
            raise ValueError(f"artifact_id must be '{_PREFIX}<64-hex>', got {self.artifact_id!r}")

    def to_dict(self) -> JSON:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: JSON) -> "ArtifactRef":
        return cls(artifact_id=data["artifact_id"],
                   media_type=data.get("media_type", "application/octet-stream"),
                   size_bytes=int(data.get("size_bytes", 0)),
                   created_at=data.get("created_at") or utc_now())


class ArtifactStore:
    """Content-addressed local artifact store (default ``.chp/artifacts``).

    ``put`` is idempotent by construction (same bytes -> same address); ``get``
    re-verifies the digest so a tampered file raises ArtifactIntegrityError
    instead of returning wrong bytes. Media types ride a ``.meta`` sidecar.
    """

    def __init__(self, root: str | Path = ".chp/artifacts") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, artifact_id: str) -> Path:
        if not artifact_id.startswith(_PREFIX):
            raise ValueError(f"not an artifact id: {artifact_id!r}")
        digest = artifact_id.removeprefix(_PREFIX)
        if not (len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)):
            raise ValueError(f"malformed artifact digest: {artifact_id!r}")
        return self.root / digest

    def _read_meta(self, path: Path) -> tuple[str, list[str] | None, str | None]:
        # .meta is JSON {media_type, created_at, audience?}; a bare media-type
        # string is the legacy slice-1 form (read-compat, no created_at).
        meta = path.with_suffix(".meta")
        if not meta.exists():
            return "application/octet-stream", None, None
        raw = meta.read_text()
        if raw.startswith("{"):
            import json
            d = json.loads(raw)
            return (d.get("media_type", "application/octet-stream"),
                    d.get("audience"), d.get("created_at"))
        return raw, None, None

    def put(self, data: bytes, media_type: str = "application/octet-stream",
            audience: list[str] | None = None) -> ArtifactRef:
        """Store bytes content-addressed. *audience* (optional) is the access
        allowlist — caller-id patterns (exact or trailing-``*``) that may fetch
        this artifact; absent = open to any authorized caller. Content-addressing
        means audience + created_at ride the meta, not the id (same bytes keep
        their address); created_at is persisted so retention is deterministic."""
        import json
        ref = ArtifactRef(artifact_id=artifact_id_for(data), media_type=media_type,
                          size_bytes=len(data))
        path = self._path(ref.artifact_id)
        if not path.exists():
            path.write_bytes(data)
            meta: dict[str, object] = {"media_type": media_type, "created_at": ref.created_at}
            if audience:
                meta["audience"] = list(audience)
            path.with_suffix(".meta").write_text(json.dumps(meta))
        return ref

    def access_of(self, artifact_id: str) -> list[str] | None:
        """The artifact's audience allowlist, or None when unbounded. Reads only
        the meta sidecar — the access check runs BEFORE the bytes are served.
        Raises FileNotFoundError for an unknown id (existence precedes access)."""
        path = self._path(artifact_id)
        if not path.exists():
            raise FileNotFoundError(artifact_id)
        return self._read_meta(path)[1]

    def apply_retention(self, max_age_days: int, now: str | None = None) -> list[str]:
        """Delete artifacts older than *max_age_days* (by persisted created_at;
        file-mtime fallback for legacy artifacts) and return the ids removed.

        This is the retention MECHANISM (DATA-006). Deletion is a governed
        operation — a product invokes this through a capability / scheduled
        sweep so the removal is evidenced; the transport path never deletes."""
        import datetime as _dt

        def _parse(ts: str) -> _dt.datetime:  # tolerant of Z + fractional seconds
            return _dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)

        cutoff = _parse(now or utc_now()) - _dt.timedelta(days=max_age_days)
        removed: list[str] = []
        for f in self.root.iterdir():
            if f.suffix == ".meta" or not (len(f.name) == 64
                                           and all(c in "0123456789abcdef" for c in f.name)):
                continue
            _mt, _aud, created_at = self._read_meta(f)
            created_dt = (_parse(created_at) if created_at is not None
                          else _dt.datetime.utcfromtimestamp(f.stat().st_mtime))
            if created_dt < cutoff:
                f.unlink()
                f.with_suffix(".meta").unlink(missing_ok=True)
                removed.append(_PREFIX + f.name)
        return removed

    def get(self, artifact_id: str) -> tuple[bytes, str]:
        """(bytes, media_type). Raises FileNotFoundError for an unknown id and
        ArtifactIntegrityError when stored bytes fail digest re-verification."""
        path = self._path(artifact_id)
        data = path.read_bytes()
        if artifact_id_for(data) != artifact_id:
            raise ArtifactIntegrityError(
                f"artifact {artifact_id} failed integrity re-verification")
        media_type, _, _ = self._read_meta(path)
        return data, media_type

    def exists(self, artifact_id: str) -> bool:
        try:
            return self._path(artifact_id).exists()
        except ValueError:
            return False
