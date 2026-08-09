"""Dependency-aware diagnostics for hybrid reconstruction blockers.

This module deliberately has no dependency on the static completeness gate.  It
accepts content-addressed blocker records, validates their dependency graph, and
separates root repair work from diagnostics that are only consequences of that
work.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any


HYBRID_DIAGNOSTICS_V2_FORMAT = "stage-b-hybrid-diagnostics-v2"
HYBRID_BLOCKER_V2_ID_PREFIX = "hybrid-blocker-v2:"
_INTEGRITY_ID_PREFIX = "hybrid-diagnostics-integrity-v2:"
_BLOCKER_STATUSES = frozenset({"incomplete", "violated"})
_FRONTIER_KINDS = ("scc", "environment", "isa")


class HybridDiagnosticsV2Error(ValueError):
    """A submitted blocker record is not a deterministic JSON record."""


def make_blocker_record(
    *,
    status: str,
    category: str,
    message: str,
    next_action: str,
    blocked_by: Sequence[str] = (),
    frontiers: Mapping[str, Sequence[Mapping[str, Any] | str]] | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one deterministic, content-addressed blocker record.

    ``status`` is ``incomplete`` for missing evidence and ``violated`` for a
    contradiction or corrupt evidence.  Frontier entries are objects with an
    ``id`` field; a string is accepted as shorthand for ``{"id": value}``.
    """

    dependencies = _dependency_ids(blocked_by, "blocker dependencies")
    if len(dependencies) != len(set(dependencies)):
        raise HybridDiagnosticsV2Error("blocker dependencies must be unique")
    body: dict[str, Any] = {
        "status": _status(status, "blocker status"),
        "category": _nonempty(category, "blocker category"),
        "message": _nonempty(message, "blocker message"),
        "next_action": _nonempty(next_action, "blocker next action"),
        "blocked_by": sorted(dependencies),
        "frontiers": _frontiers(frontiers or {}, "blocker frontiers"),
        "details": _json_clone(details or {}, "blocker details"),
    }
    body["id"] = blocker_record_id(body)
    return body


def blocker_record_id(record: Mapping[str, Any]) -> str:
    """Return the deterministic ID expected for ``record``.

    The supplied ``id`` is excluded.  Dependency order and frontier entry order
    are normalized because both collections have set semantics.
    """

    body = _identity_body(record)
    return HYBRID_BLOCKER_V2_ID_PREFIX + _canonical_sha256(body)


def build_hybrid_diagnostics_v2(
    blockers: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate and summarize a dependency-aware blocker inventory.

    Missing evidence remains an ``incomplete`` blocker.  A blocker marked
    ``violated`` or any graph/content corruption makes the overall result
    ``violated``.  Dependent consequences remain in ``blockers`` with all of
    their details, but only primary blocker IDs become repair tasks.
    """

    records = [_validated_record(item, index) for index, item in enumerate(blockers)]
    integrity: list[dict[str, Any]] = []
    for record in records:
        dependencies = record["blocked_by"]
        if len(dependencies) != len(set(dependencies)):
            integrity.append(_integrity_violation(
                code="duplicate_dependency",
                message="a blocker repeats a dependency ID",
                details={"blocker_id": record["id"]},
            ))
        record["blocked_by"] = sorted(set(dependencies))
    records.sort(key=_record_sort_key)

    records_by_id: dict[str, dict[str, Any]] = {}
    records_for_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        record_id = record["id"]
        records_for_id[record_id].append(record)
        records_by_id.setdefault(record_id, record)
        expected_id = blocker_record_id(record)
        if record_id != expected_id:
            integrity.append(_integrity_violation(
                code="blocker_id_mismatch",
                message="a blocker ID does not bind its canonical record content",
                details={"observed_id": record_id, "expected_id": expected_id},
            ))
    for record_id, duplicates in sorted(records_for_id.items()):
        if len(duplicates) > 1:
            integrity.append(_integrity_violation(
                code="duplicate_blocker_id",
                message="more than one blocker record has the same ID",
                details={"blocker_id": record_id, "records": len(duplicates)},
            ))

    known_ids = set(records_by_id)
    graph: dict[str, tuple[str, ...]] = {}
    for record_id, record in sorted(records_by_id.items()):
        dependencies = tuple(sorted(set(record["blocked_by"])))
        graph[record_id] = tuple(
            dependency for dependency in dependencies if dependency in known_ids
        )
        for dependency in dependencies:
            if dependency not in known_ids:
                integrity.append(_integrity_violation(
                    code="missing_dependency",
                    message="a blocker references an absent dependency ID",
                    details={
                        "blocker_id": record_id,
                        "missing_dependency_id": dependency,
                    },
                ))

    dependency_sccs = _strong_components(graph)
    cyclic_sccs = [
        component
        for component in dependency_sccs
        if len(component) > 1 or component[0] in graph[component[0]]
    ]
    for component in cyclic_sccs:
        integrity.append(_integrity_violation(
            code="dependency_cycle",
            message="blocker dependencies contain a cycle",
            details={"blocker_ids": list(component)},
        ))

    primary_ids = sorted(
        record_id
        for record_id, record in records_by_id.items()
        if not record["blocked_by"]
    )
    dependent_ids = sorted(known_ids - set(primary_ids))
    root_ids = _primary_dependency_closure(
        records_by_id=records_by_id,
        primary_ids=primary_ids,
    )

    frontier_summary, frontier_integrity = _primary_frontier_summary(
        records=records,
        primary_ids=set(primary_ids),
    )
    integrity.extend(frontier_integrity)
    integrity = _deduplicate_integrity(integrity)

    category_ids: dict[str, list[str]] = defaultdict(list)
    for record_id in primary_ids:
        category_ids[records_by_id[record_id]["category"]].append(record_id)
    primary_categories = [
        {
            "category": category,
            "repair_tasks": len(blocker_ids),
            "blocker_ids": blocker_ids,
        }
        for category, blocker_ids in sorted(category_ids.items())
    ]

    status_counts = Counter(record["status"] for record in records)
    status = (
        "violated"
        if integrity or status_counts["violated"]
        else "incomplete"
        if records
        else "complete"
    )
    report: dict[str, Any] = {
        "format": HYBRID_DIAGNOSTICS_V2_FORMAT,
        "status": status,
        "counts": {
            "blockers": len(records),
            "incomplete_blockers": status_counts["incomplete"],
            "violated_blockers": status_counts["violated"],
            "primary_blockers": len(primary_ids),
            "dependent_consequences": len(dependent_ids),
            "repair_tasks": len(primary_ids),
            "integrity_violations": len(integrity),
        },
        "blockers": records,
        "primary_blocker_ids": primary_ids,
        "dependent_consequence_ids": dependent_ids,
        "repair_task_ids": primary_ids,
        "dependency_closure": [
            {
                "blocker_id": record_id,
                "primary_blocker_ids": sorted(root_ids[record_id]),
            }
            for record_id in dependent_ids
        ],
        "primary_categories": primary_categories,
        "frontiers": frontier_summary,
        "integrity_violations": integrity,
    }
    report["diagnostics_sha256"] = _canonical_sha256(report)
    return report


def _identity_body(record: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise HybridDiagnosticsV2Error("blocker record must be an object")
    body = _json_clone(dict(record), "blocker record")
    body.pop("id", None)
    if "blocked_by" in body:
        body["blocked_by"] = sorted(set(_dependency_ids(
            body["blocked_by"], "blocker dependencies"
        )))
    body["frontiers"] = _frontiers(
        body.get("frontiers", {}), "blocker frontiers"
    )
    return body


def _validated_record(record: Mapping[str, Any], index: int) -> dict[str, Any]:
    context = f"blocker {index}"
    if not isinstance(record, Mapping):
        raise HybridDiagnosticsV2Error(f"{context} must be an object")
    result = _json_clone(dict(record), context)
    result["id"] = _nonempty(result.get("id"), f"{context} ID")
    result["status"] = _status(result.get("status"), f"{context} status")
    result["category"] = _nonempty(
        result.get("category"), f"{context} category"
    )
    result["message"] = _nonempty(
        result.get("message"), f"{context} message"
    )
    result["next_action"] = _nonempty(
        result.get("next_action"), f"{context} next action"
    )
    result["blocked_by"] = _dependency_ids(
        result.get("blocked_by"), f"{context} dependencies"
    )
    result["frontiers"] = _frontiers(
        result.get("frontiers", {}), f"{context} frontiers"
    )
    return result


def _primary_dependency_closure(
    *,
    records_by_id: Mapping[str, Mapping[str, Any]],
    primary_ids: Sequence[str],
) -> dict[str, set[str]]:
    roots = {record_id: set() for record_id in records_by_id}
    for record_id in primary_ids:
        roots[record_id].add(record_id)

    # Monotone propagation terminates after at most one new root per node/pass.
    for _ in range(max(1, len(records_by_id))):
        changed = False
        for record_id, record in sorted(records_by_id.items()):
            inherited: set[str] = set()
            for dependency in record["blocked_by"]:
                inherited.update(roots.get(dependency, ()))
            if not inherited.issubset(roots[record_id]):
                roots[record_id].update(inherited)
                changed = True
        if not changed:
            break
    return roots


def _strong_components(
    graph: Mapping[str, Sequence[str]],
) -> list[tuple[str, ...]]:
    """Return deterministic SCCs using iterative Kosaraju traversal."""

    visited: set[str] = set()
    finish_order: list[str] = []
    for start in sorted(graph):
        if start in visited:
            continue
        visited.add(start)
        stack: list[tuple[str, Iterator[str]]] = [
            (start, iter(sorted(graph[start])))
        ]
        while stack:
            node, targets = stack[-1]
            try:
                target = next(targets)
            except StopIteration:
                finish_order.append(node)
                stack.pop()
                continue
            if target not in visited:
                visited.add(target)
                stack.append((target, iter(sorted(graph[target]))))

    reverse: dict[str, list[str]] = {node: [] for node in graph}
    for source, targets in graph.items():
        for target in targets:
            reverse[target].append(source)
    for targets in reverse.values():
        targets.sort(reverse=True)

    assigned: set[str] = set()
    components: list[tuple[str, ...]] = []
    for start in reversed(finish_order):
        if start in assigned:
            continue
        assigned.add(start)
        members: list[str] = []
        stack = [start]
        while stack:
            node = stack.pop()
            members.append(node)
            for target in reverse[node]:
                if target not in assigned:
                    assigned.add(target)
                    stack.append(target)
        components.append(tuple(sorted(members)))
    return sorted(components)


def _primary_frontier_summary(
    *,
    records: Sequence[Mapping[str, Any]],
    primary_ids: set[str],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    definitions: dict[tuple[str, str], dict[str, Any]] = {}
    repair_ids: dict[tuple[str, str], set[str]] = defaultdict(set)
    integrity: list[dict[str, Any]] = []
    for record in records:
        blocker_id = str(record["id"])
        for kind in _FRONTIER_KINDS:
            for frontier in record["frontiers"].get(kind, []):
                key = (kind, frontier["id"])
                previous = definitions.get(key)
                if previous is None:
                    definitions[key] = frontier
                elif previous != frontier:
                    integrity.append(_integrity_violation(
                        code="frontier_definition_conflict",
                        message="one frontier ID has contradictory definitions",
                        details={"kind": kind, "frontier_id": frontier["id"]},
                    ))
                if blocker_id in primary_ids:
                    repair_ids[key].add(blocker_id)

    result = {kind: [] for kind in _FRONTIER_KINDS}
    for key in sorted(repair_ids):
        kind, _ = key
        result[kind].append({
            "frontier": copy.deepcopy(definitions[key]),
            "repair_task_ids": sorted(repair_ids[key]),
        })
    return result, integrity


def _frontiers(value: Any, context: str) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(value, Mapping):
        raise HybridDiagnosticsV2Error(f"{context} must be an object")
    unknown = sorted(set(value) - set(_FRONTIER_KINDS))
    if unknown:
        raise HybridDiagnosticsV2Error(
            f"{context} has unsupported kinds: {unknown}"
        )
    result: dict[str, list[dict[str, Any]]] = {}
    for kind in _FRONTIER_KINDS:
        raw_entries = value.get(kind, [])
        if not isinstance(raw_entries, (list, tuple)):
            raise HybridDiagnosticsV2Error(
                f"{context}.{kind} must be an array"
            )
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for index, raw_entry in enumerate(raw_entries):
            entry = {"id": raw_entry} if isinstance(raw_entry, str) else raw_entry
            if not isinstance(entry, Mapping):
                raise HybridDiagnosticsV2Error(
                    f"{context}.{kind}[{index}] must be an object"
                )
            item = _json_clone(dict(entry), f"{context}.{kind}[{index}]")
            frontier_id = _nonempty(
                item.get("id"), f"{context}.{kind}[{index}] ID"
            )
            if frontier_id in seen:
                raise HybridDiagnosticsV2Error(
                    f"{context}.{kind} repeats frontier ID {frontier_id!r}"
                )
            seen.add(frontier_id)
            item["id"] = frontier_id
            entries.append(item)
        if entries:
            result[kind] = sorted(entries, key=lambda item: (
                item["id"], _canonical_json(item)
            ))
    return result


def _dependency_ids(value: Any, context: str) -> list[str]:
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise HybridDiagnosticsV2Error(f"{context} must be an array of IDs")
    return [
        _nonempty(item, f"{context}[{index}]")
        for index, item in enumerate(value)
    ]


def _status(value: Any, context: str) -> str:
    result = _nonempty(value, context)
    if result not in _BLOCKER_STATUSES:
        raise HybridDiagnosticsV2Error(
            f"{context} must be incomplete or violated"
        )
    return result


def _nonempty(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HybridDiagnosticsV2Error(f"{context} must be a non-empty string")
    return value


def _json_clone(value: Any, context: str) -> Any:
    try:
        return json.loads(_canonical_json(value))
    except (TypeError, ValueError) as exc:
        raise HybridDiagnosticsV2Error(
            f"{context} must contain only finite JSON values"
        ) from exc


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("ascii")).hexdigest()


def _record_sort_key(record: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(record["category"]),
        str(record["id"]),
        _canonical_json(record),
    )


def _integrity_violation(
    *, code: str, message: str, details: Mapping[str, Any]
) -> dict[str, Any]:
    body = {
        "status": "violated",
        "code": code,
        "message": message,
        "details": _json_clone(details, f"{code} details"),
    }
    body["id"] = _INTEGRITY_ID_PREFIX + _canonical_sha256(body)
    return body


def _deduplicate_integrity(
    violations: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    by_id = {str(item["id"]): dict(item) for item in violations}
    return sorted(
        by_id.values(), key=lambda item: (str(item["code"]), str(item["id"]))
    )


__all__ = [
    "HYBRID_BLOCKER_V2_ID_PREFIX",
    "HYBRID_DIAGNOSTICS_V2_FORMAT",
    "HybridDiagnosticsV2Error",
    "blocker_record_id",
    "build_hybrid_diagnostics_v2",
    "make_blocker_record",
]
