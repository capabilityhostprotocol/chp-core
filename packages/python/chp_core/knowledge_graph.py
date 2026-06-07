"""Governed knowledge graph capability for CHP v0.4.3."""

from __future__ import annotations

from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    EntityRecord,
    GraphQueryResult,
    RelationRecord,
    new_id,
)

_BASE_EMITS = ["execution_started", "execution_completed", "execution_failed"]

_ADD_ENTITY_EMITS = _BASE_EMITS + ["graph_entity_added", "graph_operation_failed"]
_ADD_RELATION_EMITS = _BASE_EMITS + ["graph_relation_added", "graph_operation_failed"]
_QUERY_EMITS = _BASE_EMITS + ["graph_queried", "graph_operation_failed"]
_TRAVERSE_EMITS = _BASE_EMITS + ["graph_traversed", "graph_operation_failed"]


class KnowledgeGraphCapability:
    capability_id_prefix: str = "graph"
    capability_version: str = "0.1.0"
    description: str = "Governed knowledge graph capability."

    def add_entity(
        self,
        entity_id: str,
        entity_type: str,
        *,
        label: str | None = None,
        properties: dict | None = None,
    ) -> EntityRecord:
        raise NotImplementedError

    def add_relation(
        self,
        from_id: str,
        to_id: str,
        relation_type: str,
        *,
        properties: dict | None = None,
    ) -> RelationRecord:
        raise NotImplementedError

    def query_entities(
        self,
        *,
        entity_type: str | None = None,
        limit: int | None = None,
    ) -> GraphQueryResult:
        raise NotImplementedError

    def traverse(
        self,
        start_id: str,
        *,
        relation_type: str | None = None,
        direction: str = "outgoing",
        depth: int = 1,
    ) -> GraphQueryResult:
        raise NotImplementedError


class InMemoryKnowledgeGraph(KnowledgeGraphCapability):
    def __init__(
        self,
        *,
        capability_id_prefix: str = "graph",
        capability_version: str = "0.1.0",
        description: str = "In-memory knowledge graph.",
    ) -> None:
        self.capability_id_prefix = capability_id_prefix
        self.capability_version = capability_version
        self.description = description
        self._entities: dict[str, EntityRecord] = {}
        self._relations: list[RelationRecord] = []

    def add_entity(
        self,
        entity_id: str,
        entity_type: str,
        *,
        label: str | None = None,
        properties: dict | None = None,
    ) -> EntityRecord:
        record = EntityRecord(
            entity_id=entity_id,
            entity_type=entity_type,
            label=label,
            properties=dict(properties or {}),
        )
        self._entities[entity_id] = record
        return record

    def add_relation(
        self,
        from_id: str,
        to_id: str,
        relation_type: str,
        *,
        properties: dict | None = None,
    ) -> RelationRecord:
        if from_id not in self._entities:
            raise ValueError(f"entity not found: {from_id!r}")
        if to_id not in self._entities:
            raise ValueError(f"entity not found: {to_id!r}")
        record = RelationRecord(
            from_entity_id=from_id,
            to_entity_id=to_id,
            relation_type=relation_type,
            properties=dict(properties or {}),
        )
        self._relations.append(record)
        return record

    def query_entities(
        self,
        *,
        entity_type: str | None = None,
        limit: int | None = None,
    ) -> GraphQueryResult:
        import time
        t0 = time.perf_counter()
        entities = list(self._entities.values())
        if entity_type is not None:
            entities = [e for e in entities if e.entity_type == entity_type]
        if limit is not None:
            entities = entities[:limit]
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return GraphQueryResult(
            entities=entities,
            entity_count=len(entities),
            query_type="query_entities",
            latency_ms=latency_ms,
        )

    def traverse(
        self,
        start_id: str,
        *,
        relation_type: str | None = None,
        direction: str = "outgoing",
        depth: int = 1,
    ) -> GraphQueryResult:
        import time
        t0 = time.perf_counter()
        # BFS: visited tracks all reached nodes (including start); current_level drives expansion
        visited: set[str] = {start_id}
        current_level: set[str] = {start_id}

        for _ in range(depth):
            next_level: set[str] = set()
            for node_id in current_level:
                for rel in self._relations:
                    if direction in ("outgoing", "both") and rel.from_entity_id == node_id:
                        if relation_type is None or rel.relation_type == relation_type:
                            if rel.to_entity_id not in visited:
                                next_level.add(rel.to_entity_id)
                    if direction in ("incoming", "both") and rel.to_entity_id == node_id:
                        if relation_type is None or rel.relation_type == relation_type:
                            if rel.from_entity_id not in visited:
                                next_level.add(rel.from_entity_id)
            visited.update(next_level)
            current_level = next_level

        result_entities = [
            self._entities[eid]
            for eid in visited
            if eid != start_id and eid in self._entities
        ]
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return GraphQueryResult(
            entities=result_entities,
            entity_count=len(result_entities),
            query_type="traverse",
            latency_ms=latency_ms,
        )


def register_knowledge_graph_capability(host: object, kg: KnowledgeGraphCapability) -> None:
    prefix = kg.capability_id_prefix
    version = kg.capability_version

    # ── add_entity ────────────────────────────────────────────────────────────

    add_entity_desc = CapabilityDescriptor(
        id=f"{prefix}.add_entity",
        version=version,
        description="Add or upsert an entity in the knowledge graph.",
        category=CapabilityCategory.DATA_KNOWLEDGE,
        tags=["graph"],
        emits=list(_ADD_ENTITY_EMITS),
    )

    async def _add_entity(ctx, payload) -> dict:
        entity_id: str = payload.get("entity_id") or new_id("ent")
        entity_type: str = payload.get("entity_type", "unknown")
        label: str | None = payload.get("label")
        properties: dict = payload.get("properties") or {}

        ctx.emit("execution_started", {"capability_id": add_entity_desc.id, "capability_version": version}, redacted=False)
        try:
            record = kg.add_entity(entity_id, entity_type, label=label, properties=properties)
        except Exception as exc:
            ctx.emit("graph_operation_failed", {"error": str(exc), "operation": "add_entity"}, redacted=False)
            ctx.emit("execution_failed", {"error": str(exc)}, redacted=False)
            raise
        ctx.emit("graph_entity_added", {
            "entity_id": record.entity_id,
            "entity_type": record.entity_type,
            "label": record.label,
        }, redacted=False)
        ctx.emit("execution_completed", {"capability_id": add_entity_desc.id, "outcome": "success"}, redacted=False)
        return record.to_dict()

    host.register(add_entity_desc, _add_entity)

    # ── add_relation ──────────────────────────────────────────────────────────

    add_relation_desc = CapabilityDescriptor(
        id=f"{prefix}.add_relation",
        version=version,
        description="Add a directed relation between two entities.",
        category=CapabilityCategory.DATA_KNOWLEDGE,
        tags=["graph"],
        emits=list(_ADD_RELATION_EMITS),
    )

    async def _add_relation(ctx, payload) -> dict:
        from_id: str = payload.get("from_entity_id", "")
        to_id: str = payload.get("to_entity_id", "")
        relation_type: str = payload.get("relation_type", "related_to")
        properties: dict = payload.get("properties") or {}

        ctx.emit("execution_started", {"capability_id": add_relation_desc.id, "capability_version": version}, redacted=False)
        try:
            record = kg.add_relation(from_id, to_id, relation_type, properties=properties)
        except Exception as exc:
            ctx.emit("graph_operation_failed", {"error": str(exc), "operation": "add_relation"}, redacted=False)
            ctx.emit("execution_failed", {"error": str(exc)}, redacted=False)
            raise
        ctx.emit("graph_relation_added", {
            "from_entity_id": record.from_entity_id,
            "to_entity_id": record.to_entity_id,
            "relation_type": record.relation_type,
        }, redacted=False)
        ctx.emit("execution_completed", {"capability_id": add_relation_desc.id, "outcome": "success"}, redacted=False)
        return record.to_dict()

    host.register(add_relation_desc, _add_relation)

    # ── query_entities ────────────────────────────────────────────────────────

    query_desc = CapabilityDescriptor(
        id=f"{prefix}.query_entities",
        version=version,
        description="Query entities from the knowledge graph.",
        category=CapabilityCategory.DATA_KNOWLEDGE,
        tags=["graph"],
        emits=list(_QUERY_EMITS),
    )

    async def _query_entities(ctx, payload) -> dict:
        entity_type: str | None = payload.get("entity_type")
        limit: int | None = payload.get("limit")

        ctx.emit("execution_started", {"capability_id": query_desc.id, "capability_version": version}, redacted=False)
        try:
            result = kg.query_entities(entity_type=entity_type, limit=limit)
        except Exception as exc:
            ctx.emit("graph_operation_failed", {"error": str(exc), "operation": "query_entities"}, redacted=False)
            ctx.emit("execution_failed", {"error": str(exc)}, redacted=False)
            raise
        ctx.emit("graph_queried", {
            "entity_type": entity_type,
            "entity_count": result.entity_count,
            "latency_ms": result.latency_ms,
        }, redacted=False)
        ctx.emit("execution_completed", {"capability_id": query_desc.id, "outcome": "success"}, redacted=False)
        return result.to_dict()

    host.register(query_desc, _query_entities)

    # ── traverse ──────────────────────────────────────────────────────────────

    traverse_desc = CapabilityDescriptor(
        id=f"{prefix}.traverse",
        version=version,
        description="Traverse the knowledge graph from a starting entity.",
        category=CapabilityCategory.DATA_KNOWLEDGE,
        tags=["graph"],
        emits=list(_TRAVERSE_EMITS),
    )

    async def _traverse(ctx, payload) -> dict:
        start_id: str = payload.get("start_id", "")
        relation_type: str | None = payload.get("relation_type")
        direction: str = payload.get("direction", "outgoing")
        depth: int = int(payload.get("depth", 1))

        ctx.emit("execution_started", {"capability_id": traverse_desc.id, "capability_version": version}, redacted=False)
        try:
            result = kg.traverse(start_id, relation_type=relation_type, direction=direction, depth=depth)
        except Exception as exc:
            ctx.emit("graph_operation_failed", {"error": str(exc), "operation": "traverse"}, redacted=False)
            ctx.emit("execution_failed", {"error": str(exc)}, redacted=False)
            raise
        ctx.emit("graph_traversed", {
            "start_id": start_id,
            "depth": depth,
            "direction": direction,
            "entity_count": result.entity_count,
            "latency_ms": result.latency_ms,
        }, redacted=False)
        ctx.emit("execution_completed", {"capability_id": traverse_desc.id, "outcome": "success"}, redacted=False)
        return result.to_dict()

    host.register(traverse_desc, _traverse)
