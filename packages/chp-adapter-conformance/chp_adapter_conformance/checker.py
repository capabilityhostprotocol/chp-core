"""Static (AST) and runtime capability violation checker."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Violation model
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    rule: str          # e.g. "raw_io", "missing_emit", "issue_policy"
    severity: str      # "error" | "warning"
    message: str
    location: str = ""  # "line N" or "capability_id"

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "location": self.location,
        }


# ---------------------------------------------------------------------------
# Static checker (AST)
# ---------------------------------------------------------------------------

_RAW_IO_CALLS = {"open", "read", "write"}
# Top-level packages that are forbidden HTTP transports.
# urllib.parse is NOT included — it is URL string manipulation, not a transport.
_FORBIDDEN_TOP = {"httpx", "requests", "aiohttp"}
# Specific urllib sub-packages that ARE HTTP transports.
_FORBIDDEN_URLLIB = {"urllib.request", "urllib.error", "urllib.response"}
_ISSUE_RE = re.compile(r"rad:[0-9a-f]{7,40}")
_MERGE_RE = re.compile(r"^Merge ")
_REVERT_RE = re.compile(r"^Revert ")


class _CapabilityVisitor(ast.NodeVisitor):
    """Walk a capability method body and collect violations."""

    def __init__(self, method_name: str) -> None:
        self.method_name = method_name
        self.violations: list[Violation] = []
        self._has_emit = False
        self._in_capability = False

    def _loc(self, node: ast.AST) -> str:
        return f"line {node.lineno}" if hasattr(node, "lineno") else ""

    def visit_Call(self, node: ast.Call) -> None:
        # open() / read() / write() direct calls
        if isinstance(node.func, ast.Name) and node.func.id in _RAW_IO_CALLS:
            self.violations.append(Violation(
                rule="raw_io",
                severity="error",
                message=f"Direct `{node.func.id}()` call — use filesystem adapter instead",
                location=self._loc(node),
            ))

        # ctx.emit() — mark as found
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "emit"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "ctx"
        ):
            self._has_emit = True

        # self._helper(ctx, ...) — private helper delegation counts as an emit
        # (helpers receive ctx and are responsible for emitting on behalf of the capability)
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "self"
            and node.func.attr.startswith("_")
        ):
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id == "ctx":
                    self._has_emit = True
                    break

        # ctx.host.<anything except sanctioned> direct access
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "host"
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "ctx"
        ):
            method = node.func.attr
            if method not in {"record_turn"}:
                self.violations.append(Violation(
                    rule="direct_host_call",
                    severity="warning",
                    message=f"ctx.host.{method}() bypasses invocation chain — use ctx.invoke() instead",
                    location=self._loc(node),
                ))
        # No generic_visit: outer ast.walk already visits children

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        # Detect bare `except: pass` or `except Exception: pass`
        if node.body and all(isinstance(s, ast.Pass) for s in node.body):
            self.violations.append(Violation(
                rule="silent_error",
                severity="warning",
                message="Silent exception handler (except: pass) swallows errors",
                location=self._loc(node),
            ))

    def generic_visit(self, node: ast.AST) -> None:
        # Suppress default recursion: outer ast.walk handles all traversal.
        # Without this, nodes lacking a specific visit_* method recurse into
        # children via the default generic_visit, causing N+1 visits per node.
        pass


_LIFECYCLE_EVENTS = {
    "execution_started", "execution_completed", "execution_failed",
    "execution_denied", "execution_skipped",
}


def _module_string_lists(tree: ast.Module) -> dict[str, set[str]]:
    """Module-level `NAME = ["a", "b"]` string-list assignments (the `_EMITS`
    sharing pattern) so a declared `emits=_EMITS` resolves statically."""
    out: dict[str, set[str]] = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, (ast.List, ast.Tuple, ast.Set))
                and all(isinstance(e, ast.Constant) and isinstance(e.value, str)
                        for e in node.value.elts)):
            out[node.targets[0].id] = {e.value for e in node.value.elts}
    return out


def _declared_emits(node: ast.AST, module_lists: dict[str, set[str]]) -> set[str] | None:
    """The literal `emits=` set declared on a @capability decorator, or None when
    absent/unresolvable (no declaration → no contract to enforce)."""
    for d in getattr(node, "decorator_list", []):
        if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
                and d.func.id == "capability"):
            continue
        for kw in d.keywords:
            if kw.arg != "emits":
                continue
            v = kw.value
            if isinstance(v, (ast.List, ast.Tuple, ast.Set)) and all(
                    isinstance(e, ast.Constant) and isinstance(e.value, str)
                    for e in v.elts):
                return {e.value for e in v.elts}
            if isinstance(v, ast.Name) and v.id in module_lists:
                return module_lists[v.id]
            return None  # computed expression — can't resolve statically
    return None


def _emitted_literals(node: ast.AST) -> list[tuple[str, int]]:
    """Every `ctx.emit("literal", ...)` first-arg string inside the body."""
    found: list[tuple[str, int]] = []
    for child in ast.walk(node):
        if (isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                and child.func.attr == "emit"
                and isinstance(child.func.value, ast.Name)
                and child.func.value.id == "ctx"
                and child.args
                and isinstance(child.args[0], ast.Constant)
                and isinstance(child.args[0].value, str)):
            found.append((child.args[0].value, child.lineno))
    return found


def check_source_file(path: str | Path) -> list[Violation]:
    """Parse a Python source file and return capability violations."""
    source = Path(path).read_text()
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [Violation(rule="parse_error", severity="error", message=str(exc))]

    violations: list[Violation] = []
    module_lists = _module_string_lists(tree)

    # File-level: check all imports regardless of context
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                full = alias.name
                if top in _FORBIDDEN_TOP or full in _FORBIDDEN_URLLIB:
                    violations.append(Violation(
                        rule="raw_http",
                        severity="error",
                        message=f"Direct import of `{alias.name}` — use http/transport adapter instead",
                        location=f"line {node.lineno}",
                    ))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            top = module.split(".")[0]
            if top in _FORBIDDEN_TOP or module in _FORBIDDEN_URLLIB:
                violations.append(Violation(
                    rule="raw_http",
                    severity="error",
                    message=f"Direct import from `{module}` — use http/transport adapter instead",
                    location=f"line {node.lineno}",
                ))

    # Capability-level: check each @capability-decorated method
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        decorators = [
            (d.func.id if isinstance(d, ast.Call) and isinstance(d.func, ast.Name) else
             d.id if isinstance(d, ast.Name) else "")
            for d in node.decorator_list
        ]
        if "capability" not in decorators:
            continue

        visitor = _CapabilityVisitor(node.name)
        for child in ast.walk(node):
            visitor.visit(child)

        if not visitor._has_emit:
            violations.append(Violation(
                rule="missing_emit",
                severity="error",
                message=f"Capability `{node.name}` never calls ctx.emit() — evidence chain incomplete",
                location=f"line {node.lineno}",
            ))

        # Declared emits is a CONTRACT (governance §4.4): a statically visible
        # ctx.emit of a bare event type outside the declared set is a violation.
        declared = _declared_emits(node, module_lists)
        if declared is not None:
            for event_type, lineno in _emitted_literals(node):
                if (event_type not in declared
                        and event_type not in _LIFECYCLE_EVENTS
                        and "." not in event_type):
                    violations.append(Violation(
                        rule="undeclared_emit",
                        severity="error",
                        message=(f"Capability `{node.name}` emits `{event_type}` which is not "
                                 "in its declared emits set (governance §4.4 — declared emits "
                                 "is a contract; declare it or reverse-DNS namespace it)"),
                        location=f"line {lineno}",
                    ))

        violations.extend(visitor.violations)

    return violations


# ---------------------------------------------------------------------------
# Runtime checker (introspection)
# ---------------------------------------------------------------------------

def check_registered_adapter(adapter: object) -> list[Violation]:
    """Inspect a registered adapter instance for schema violations."""
    violations: list[Violation] = []

    if not getattr(adapter, "adapter_id", None):
        violations.append(Violation(
            rule="missing_adapter_id",
            severity="error",
            message=f"{type(adapter).__name__} has no adapter_id",
        ))

    if not getattr(adapter, "adapter_category", None):
        violations.append(Violation(
            rule="missing_category",
            severity="warning",
            message=f"{type(adapter).__name__} has no adapter_category",
        ))

    # Walk registered capabilities from the class
    for attr_name in dir(type(adapter)):
        method = getattr(type(adapter), attr_name, None)
        if method is None:
            continue
        cap_meta = getattr(method, "_chp_capability", None)
        if cap_meta is None:
            continue
        cap_id = getattr(cap_meta, "id", attr_name)

        if not getattr(cap_meta, "input_schema", None):
            violations.append(Violation(
                rule="missing_schema",
                severity="error",
                message="No input_schema defined",
                location=cap_id,
            ))
        else:
            schema = cap_meta.input_schema
            if not isinstance(schema, dict) or schema.get("type") != "object":
                violations.append(Violation(
                    rule="invalid_schema",
                    severity="warning",
                    message="input_schema should be an object schema",
                    location=cap_id,
                ))

        if not getattr(cap_meta, "version", None):
            violations.append(Violation(
                rule="missing_version",
                severity="warning",
                message="No version declared on capability",
                location=cap_id,
            ))

    return violations


# ---------------------------------------------------------------------------
# Issue policy check
# ---------------------------------------------------------------------------

def check_commit_message(msg: str) -> list[Violation]:
    clean = "\n".join(l for l in msg.splitlines() if not l.startswith("#"))
    if _ISSUE_RE.search(clean):
        return []
    if _MERGE_RE.match(clean.strip()):
        return []
    if _REVERT_RE.match(clean.strip()):
        return []
    return [Violation(
        rule="issue_policy",
        severity="error",
        message="Commit message missing Radicle issue reference (rad:XXXXXXX)",
    )]


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------

def score(violations: list[Violation]) -> int:
    """0–100 conformance score. 100 = no violations."""
    errors = sum(1 for v in violations if v.severity == "error")
    warnings = sum(1 for v in violations if v.severity == "warning")
    deductions = errors * 15 + warnings * 5
    return max(0, 100 - deductions)
