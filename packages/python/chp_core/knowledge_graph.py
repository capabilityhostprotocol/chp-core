"""Governed knowledge graph capability for CHP v0.4.3."""

from __future__ import annotations

from typing import Any

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


class SQLiteKnowledgeGraph(KnowledgeGraphCapability):
    """SQLite-backed knowledge graph — entities and relations survive restarts."""

    def __init__(
        self,
        store_path: str = ".chp/graph.sqlite",
        *,
        capability_id_prefix: str = "graph",
        capability_version: str = "0.1.0",
        description: str = "SQLite-backed knowledge graph.",
    ) -> None:
        import sqlite3
        from pathlib import Path

        self.capability_id_prefix = capability_id_prefix
        self.capability_version = capability_version
        self.description = description
        p = Path(store_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(p), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS entities (
                entity_id       TEXT PRIMARY KEY,
                entity_type     TEXT NOT NULL,
                label           TEXT,
                properties_json TEXT NOT NULL DEFAULT '{}'
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS relations (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                from_entity     TEXT NOT NULL,
                to_entity       TEXT NOT NULL,
                relation_type   TEXT NOT NULL,
                properties_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(from_entity) REFERENCES entities(entity_id),
                FOREIGN KEY(to_entity)   REFERENCES entities(entity_id)
            )
        """)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rel_from ON relations(from_entity)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rel_to ON relations(to_entity)"
        )
        self._conn.commit()

    def _row_to_entity(self, row: tuple) -> EntityRecord:
        import json

        entity_id, entity_type, label, props_json = row
        return EntityRecord(
            entity_id=entity_id,
            entity_type=entity_type,
            label=label,
            properties=json.loads(props_json),
        )

    def add_entity(
        self,
        entity_id: str,
        entity_type: str,
        *,
        label: str | None = None,
        properties: dict | None = None,
    ) -> EntityRecord:
        import json

        props = dict(properties or {})
        self._conn.execute(
            """INSERT OR REPLACE INTO entities (entity_id, entity_type, label, properties_json)
               VALUES (?, ?, ?, ?)""",
            (entity_id, entity_type, label, json.dumps(props)),
        )
        self._conn.commit()
        return EntityRecord(
            entity_id=entity_id, entity_type=entity_type, label=label, properties=props
        )

    def add_relation(
        self,
        from_id: str,
        to_id: str,
        relation_type: str,
        *,
        properties: dict | None = None,
    ) -> RelationRecord:
        import json

        row = self._conn.execute(
            "SELECT entity_id FROM entities WHERE entity_id = ?", (from_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"entity not found: {from_id!r}")
        row = self._conn.execute(
            "SELECT entity_id FROM entities WHERE entity_id = ?", (to_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"entity not found: {to_id!r}")
        props = dict(properties or {})
        self._conn.execute(
            """INSERT INTO relations (from_entity, to_entity, relation_type, properties_json)
               VALUES (?, ?, ?, ?)""",
            (from_id, to_id, relation_type, json.dumps(props)),
        )
        self._conn.commit()
        return RelationRecord(
            from_entity_id=from_id,
            to_entity_id=to_id,
            relation_type=relation_type,
            properties=props,
        )

    def query_entities(
        self,
        *,
        entity_type: str | None = None,
        limit: int | None = None,
    ) -> GraphQueryResult:
        import time

        t0 = time.perf_counter()
        if entity_type is not None:
            rows = self._conn.execute(
                "SELECT * FROM entities WHERE entity_type = ?", (entity_type,)
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM entities").fetchall()
        entities = [self._row_to_entity(r) for r in rows]
        if limit is not None:
            entities = entities[:limit]
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return GraphQueryResult(
            entities=entities, entity_count=len(entities),
            query_type="query_entities", latency_ms=latency_ms,
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
        visited: set[str] = {start_id}
        current_level: set[str] = {start_id}

        for _ in range(depth):
            next_level: set[str] = set()
            for node_id in current_level:
                if direction in ("outgoing", "both"):
                    q = "SELECT to_entity FROM relations WHERE from_entity = ?"
                    p: list = [node_id]
                    if relation_type is not None:
                        q += " AND relation_type = ?"
                        p.append(relation_type)
                    for (neighbor,) in self._conn.execute(q, p).fetchall():
                        if neighbor not in visited:
                            next_level.add(neighbor)
                if direction in ("incoming", "both"):
                    q = "SELECT from_entity FROM relations WHERE to_entity = ?"
                    p = [node_id]
                    if relation_type is not None:
                        q += " AND relation_type = ?"
                        p.append(relation_type)
                    for (neighbor,) in self._conn.execute(q, p).fetchall():
                        if neighbor not in visited:
                            next_level.add(neighbor)
            visited.update(next_level)
            current_level = next_level

        result_entities = []
        for eid in visited:
            if eid == start_id:
                continue
            row = self._conn.execute(
                "SELECT * FROM entities WHERE entity_id = ?", (eid,)
            ).fetchone()
            if row:
                result_entities.append(self._row_to_entity(row))
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return GraphQueryResult(
            entities=result_entities, entity_count=len(result_entities),
            query_type="traverse", latency_ms=latency_ms,
        )

    def close(self) -> None:
        self._conn.close()


def register_knowledge_graph_capability(host: Any, kg: KnowledgeGraphCapability) -> None:
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

        try:
            record = kg.add_entity(entity_id, entity_type, label=label, properties=properties)
        except Exception as exc:
            ctx.emit("graph_operation_failed", {"error": str(exc), "operation": "add_entity"}, redacted=False)
            raise
        ctx.emit("graph_entity_added", {
            "entity_id": record.entity_id,
            "entity_type": record.entity_type,
            "label": record.label,
        }, redacted=False)
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

        try:
            record = kg.add_relation(from_id, to_id, relation_type, properties=properties)
        except Exception as exc:
            ctx.emit("graph_operation_failed", {"error": str(exc), "operation": "add_relation"}, redacted=False)
            raise
        ctx.emit("graph_relation_added", {
            "from_entity_id": record.from_entity_id,
            "to_entity_id": record.to_entity_id,
            "relation_type": record.relation_type,
        }, redacted=False)
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

        try:
            result = kg.query_entities(entity_type=entity_type, limit=limit)
        except Exception as exc:
            ctx.emit("graph_operation_failed", {"error": str(exc), "operation": "query_entities"}, redacted=False)
            raise
        ctx.emit("graph_queried", {
            "entity_type": entity_type,
            "entity_count": result.entity_count,
            "latency_ms": result.latency_ms,
        }, redacted=False)
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

        try:
            result = kg.traverse(start_id, relation_type=relation_type, direction=direction, depth=depth)
        except Exception as exc:
            ctx.emit("graph_operation_failed", {"error": str(exc), "operation": "traverse"}, redacted=False)
            raise
        ctx.emit("graph_traversed", {
            "start_id": start_id,
            "depth": depth,
            "direction": direction,
            "entity_count": result.entity_count,
            "latency_ms": result.latency_ms,
        }, redacted=False)
        return result.to_dict()

    host.register(traverse_desc, _traverse)
