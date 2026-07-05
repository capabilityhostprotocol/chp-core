"""Governed data transformation capability for CHP v0.4.2."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    TransformationRecord,
    TransformationResult,
)

if TYPE_CHECKING:
    pass

_TRANSFORMATION_EMITS = [
    "execution_started",
    "execution_completed",
    "execution_failed",
    "transformation_started",
    "transformation_completed",
    "transformation_failed",
]


class TransformationCapability:
    capability_id: str = "transformation.transform"
    capability_version: str = "0.1.0"
    description: str = "Governed transformation capability."

    def transform(
        self,
        content: str,
        *,
        transform_type: str = "normalize",
        params: dict | None = None,
    ) -> TransformationResult:
        raise NotImplementedError

    def as_capability_descriptor(self) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            id=self.capability_id,
            version=self.capability_version,
            description=self.description,
            category=CapabilityCategory.DATA_KNOWLEDGE,
            tags=["transformation"],
            emits=list(_TRANSFORMATION_EMITS),
        )


class InMemoryTextTransformationCapability(TransformationCapability):
    SUPPORTED_TRANSFORMS = {"normalize", "chunk", "redact"}

    _DEFAULT_REDACT_PATTERNS = [
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]"),
        (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "[REDACTED_PHONE]"),
    ]

    def __init__(
        self,
        *,
        capability_id: str = "transformation.transform",
        capability_version: str = "0.1.0",
        description: str = "In-memory text transformation.",
    ) -> None:
        self.capability_id = capability_id
        self.capability_version = capability_version
        self.description = description

    def transform(
        self,
        content: str,
        *,
        transform_type: str = "normalize",
        params: dict | None = None,
    ) -> TransformationResult:
        import hashlib
        import time

        params = params or {}
        t0 = time.perf_counter()
        input_hash = "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()
        input_byte_count = len(content.encode("utf-8"))

        if transform_type == "normalize":
            output = self._normalize(content)
        elif transform_type == "chunk":
            output = self._chunk(content, params)
        elif transform_type == "redact":
            output = self._redact(content, params)
        else:
            raise ValueError(f"unsupported transform_type: {transform_type!r}")

        output_hash = "sha256:" + hashlib.sha256(output.encode("utf-8")).hexdigest()
        output_byte_count = len(output.encode("utf-8"))
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        record = TransformationRecord(
            transform_type=transform_type,
            input_hash=input_hash,
            output_hash=output_hash,
            input_byte_count=input_byte_count,
            output_byte_count=output_byte_count,
            params=params,
        )
        return TransformationResult(
            content=output,
            transform_type=transform_type,
            record=record,
            latency_ms=latency_ms,
        )

    def _normalize(self, content: str) -> str:
        import re
        return re.sub(r"\s+", " ", content.strip()).lower()

    def _chunk(self, content: str, params: dict) -> str:
        import json
        max_chars: int = params.get("max_chars", 512)
        separator: str = params.get("separator", "\n\n")
        chunks: list[str] = []
        parts = content.split(separator) if separator else [content]
        for part in parts:
            while len(part) > max_chars:
                chunks.append(part[:max_chars])
                part = part[max_chars:]
            if part:
                chunks.append(part)
        return json.dumps(chunks)

    def _redact(self, content: str, params: dict) -> str:
        import re
        raw_patterns = params.get("patterns")
        if raw_patterns is not None:
            patterns = [(p[0], p[1]) for p in raw_patterns]
        else:
            patterns = self._DEFAULT_REDACT_PATTERNS
        result = content
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result)
        return result


def register_transformation_capability(host: Any, cap: TransformationCapability) -> None:
    import time

    async def _transform(ctx, payload) -> dict:
        content: str = payload.get("content", "")
        transform_type: str = payload.get("transform_type", "normalize")
        params: dict = payload.get("params") or {}

        ctx.emit(
            "transformation_started",
            {"transform_type": transform_type, "input_byte_count": len(content.encode("utf-8"))},
            redacted=False,
        )

        t0 = time.perf_counter()
        try:
            result = cap.transform(content, transform_type=transform_type, params=params)
        except Exception as exc:
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            ctx.emit(
                "transformation_failed",
                {"error": str(exc), "latency_ms": latency_ms},
                redacted=False,
            )
            raise

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        ctx.emit(
            "transformation_completed",
            {
                "transform_type": result.transform_type,
                "input_hash": result.record.input_hash,
                "output_hash": result.record.output_hash,
                "input_byte_count": result.record.input_byte_count,
                "output_byte_count": result.record.output_byte_count,
                "latency_ms": latency_ms,
            },
            redacted=False,
        )
        return result.to_dict()

    host.register(cap.as_capability_descriptor(), _transform)
