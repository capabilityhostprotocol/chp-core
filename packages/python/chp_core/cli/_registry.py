"""CHP CLI adapter registry management commands."""

from __future__ import annotations

import argparse
import json


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
