"""CHP CLI adapter registry management commands."""

from __future__ import annotations

import argparse
import json
import sys


def cmd_registry_list(args: argparse.Namespace) -> int:
    from ..registry import load_registry
    entries = load_registry(args.registry)
    print(json.dumps([e.to_dict() for e in entries], indent=2))
    return 0


def cmd_registry_add(args: argparse.Namespace) -> int:
    from ..registry import RegistryEntry, add_entry
    entry = RegistryEntry(
        id=args.adapter_id,
        package=args.package,
        version=args.version,
        enabled=not args.disabled,
        tags=args.tags or [],
    )
    add_entry(entry, args.registry)
    print(json.dumps(entry.to_dict(), indent=2))
    return 0


def cmd_registry_remove(args: argparse.Namespace) -> int:
    import sys
    from ..registry import remove_entry
    removed = remove_entry(args.adapter_id, args.registry)
    if removed:
        print(f"Removed adapter: {args.adapter_id}")
        return 0
    print(f"Adapter not found: {args.adapter_id}", file=sys.stderr)
    return 1


def cmd_registry_assess_maturity(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore
    from ..registry import load_registry, add_entry, RegistryEntry, default_registry_path
    from ..certification import assess_maturity

    # Resolve store path (same logic as session commands)
    import os
    store_env = os.environ.get("CHP_STORE_FILE")
    store_path = getattr(args, "store", None) or store_env or os.path.join(
        os.environ.get("HOME", "."), ".chp", "evidence.sqlite"
    )

    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.query(capability_id=args.capability_id)
    except Exception:
        events = []
    finally:
        store.close()

    # Try to get registry entry for descriptor metadata
    registry_path = getattr(args, "registry", None)
    entries = load_registry(registry_path)
    entry = next((e for e in entries if e.id == args.capability_id), None)

    # Attempt descriptor reconstruction from first execution_started payload
    descriptor = None
    for e in events:
        if e.get("event_type") == "execution_started":
            p = e.get("payload") or {}
            cap_id = p.get("capability_id", args.capability_id)
            cap_ver = p.get("capability_version", "")
            if cap_id:
                from ..types import CapabilityDescriptor
                descriptor = CapabilityDescriptor(
                    id=cap_id,
                    version=cap_ver or "unknown",
                    description=p.get("description", ""),
                    category=p.get("category"),
                    tags=list(p.get("tags") or []),
                    emits=list(p.get("emits") or [
                        "execution_started", "execution_completed",
                        "execution_failed", "execution_denied",
                    ]),
                )
                break

    assessment = assess_maturity(
        args.capability_id,
        descriptor=descriptor,
        events=events,
        registry_entry=entry,
    )

    # Persist assessed level back to registry
    if entry is None:
        entry = RegistryEntry(id=args.capability_id)
    entry.maturity_level = assessment.level
    add_entry(entry, registry_path)

    print(json.dumps(assessment.to_dict(), indent=2))
    return 0


def cmd_registry_certify(args: argparse.Namespace) -> int:
    from ..registry import load_registry, add_entry, RegistryEntry
    from ..types import CertificationRecord, utc_now

    registry_path = getattr(args, "registry", None)
    entries = load_registry(registry_path)
    entry = next((e for e in entries if e.id == args.capability_id), None)
    if entry is None:
        entry = RegistryEntry(id=args.capability_id)

    level = int(args.level)
    if not 1 <= level <= 7:
        print(f"Error: --level must be 1–7, got {level}", file=sys.stderr)
        return 1

    granted_by = getattr(args, "by", None) or "anonymous"
    notes = getattr(args, "notes", None)
    certified_at = utc_now()

    entry.certification_level = level
    entry.certified_by = granted_by
    entry.certified_at = certified_at
    entry.certification_notes = notes
    if entry.maturity_level is None or entry.maturity_level < level:
        entry.maturity_level = level

    add_entry(entry, registry_path)

    record = CertificationRecord(
        capability_id=args.capability_id,
        level=level,
        granted_by=granted_by,
        certified_at=certified_at,
        notes=notes,
    )
    print(json.dumps(record.to_dict(), indent=2))
    return 0


def cmd_registry_status(args: argparse.Namespace) -> int:
    from ..registry import load_registry
    from ..adapters import auto_register_adapters
    from ..host import LocalCapabilityHost

    entries = load_registry(args.registry)
    if not entries:
        print("No adapters registered. Use: chp registry add <id>")
        return 0

    host = LocalCapabilityHost("registry-status-host")
    try:
        auto_register_adapters(host)
    except Exception:  # noqa: BLE001
        pass

    caps_by_adapter: dict[str, list[dict]] = {}
    for cap in host.discover().get("capabilities", []):
        prefix = cap["id"].split(".")[0]
        caps_by_adapter.setdefault(prefix, []).append(cap)

    result = []
    for entry in entries:
        adapter_caps = caps_by_adapter.get(entry.id, [])
        statuses = {c.get("status", "draft") for c in adapter_caps}
        result.append({
            "id": entry.id,
            "enabled": entry.enabled,
            "package": entry.package,
            "capability_count": len(adapter_caps),
            "statuses": sorted(statuses),
        })

    print(json.dumps(result, indent=2))
    return 0
