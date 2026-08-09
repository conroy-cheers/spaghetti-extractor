"""Exact rooted-control extraction and cold-replayed closure for v2."""

from __future__ import annotations

import copy
import json
from typing import Any, Mapping, Sequence

from .analysis_schema_v2 import ROOTED_CONTROL_GRAPH_V2_FORMAT
from .artifact_identity_v2 import canonical_sha256
from .authority_bindings_v2 import indirect_exit_id_v2

# Root discovery and rooted closure are phases over one canonical graph schema.
# Keep the old exported name as a source-compatibility alias while removing the
# second wire format.
ROOTED_CONTROL_CLOSURE_V2_FORMAT = ROOTED_CONTROL_GRAPH_V2_FORMAT

def derive_rooted_control_graph_v2(
    *,
    rows: Sequence[Mapping[str, Any]],
    manifest: Mapping[str, Any],
    behavioral_roots: Mapping[str, Any],
) -> dict[str, Any]:
    # The v1 manifest may contain useful recovery proposals, but base graph
    # authority comes only from exact unit semantics and declared PE roots.
    _object(manifest.get("control"), "machine-IR control")
    by_id = {str(row.get("id")): row for row in rows}
    by_rva = {
        int(row["source"]["original"]["rva_start"]): str(row["id"])
        for row in rows
    }
    issues: list[dict[str, Any]] = []
    roots: list[dict[str, str]] = []
    for root in behavioral_roots.get("roots", []):
        if isinstance(root, Mapping) and isinstance(root.get("rva"), int):
            unit_id = by_rva.get(int(root["rva"]))
            if unit_id is not None:
                roots.append({
                    "unit_id": unit_id,
                    "kind": str(root.get("kind", "pe")),
                })
            else:
                issues.append({
                    "status": "incomplete",
                    "code": "root_unit_missing",
                    "rva": int(root["rva"]),
                })
    exact = _exact_control_inventory(rows)
    direct_edges = [
        *exact["direct_edges"],
        *(
            {
                "source_unit_id": edge["source_unit_id"],
                "target_unit_id": edge["target_unit_id"],
            }
            for edge in exact["internal_call_edges"]
        ),
    ]
    successors: dict[str, set[str]] = {unit_id: set() for unit_id in by_id}
    for edge in direct_edges:
        successors[str(edge["source_unit_id"])].add(str(edge["target_unit_id"]))
    reachable: set[str] = set()
    pending = [str(root["unit_id"]) for root in reversed(roots)]
    while pending:
        unit_id = pending.pop()
        if unit_id in reachable:
            continue
        reachable.add(unit_id)
        pending.extend(sorted(successors.get(unit_id, ()), reverse=True))
    issues.extend(
        issue
        for issue in exact["issues"]
        if issue.get("source_unit_id") in reachable
    )
    indirect = [
        {
            "id": raw["id"],
            "source_unit_id": raw["source_unit_id"],
            "status": "incomplete",
            "target_unit_ids": [],
            "external_targets": [],
            "failure": {"code": "awaiting_interprocedural_certificate"},
        }
        for raw in exact["indirect_exits"]
        if raw["source_unit_id"] in reachable
    ]
    if indirect:
        issues.extend({
            "status": "incomplete",
            "code": "indirect_exit_certificate_incomplete",
            "exit_id": raw["id"],
            "source_unit_id": raw["source_unit_id"],
        } for raw in indirect)
    graph_status = (
        "violated"
        if any(issue["status"] == "violated" for issue in issues)
        else "incomplete" if issues else "complete"
    )
    body = {
        "format": ROOTED_CONTROL_GRAPH_V2_FORMAT,
        "status": graph_status,
        "roots": sorted(
            {json.dumps(row, sort_keys=True): row for row in roots}.values(),
            key=lambda row: (row["unit_id"], row["kind"]),
        ),
        "direct_edges": sorted(
            {json.dumps(row, sort_keys=True): row for row in direct_edges}.values(),
            key=lambda row: (row["source_unit_id"], row["target_unit_id"]),
        ),
        "indirect_exits": sorted(indirect, key=lambda row: str(row["id"])),
        "reachable_units": sorted(reachable),
        "issues": sorted(
            issues,
            key=lambda row: (
                str(row.get("status")),
                str(row.get("code")),
                str(row.get("source_unit_id", "")),
            ),
        ),
    }
    return {
        **body,
        "id": "rooted-control-graph-v2:" + canonical_sha256(body),
    }


def _exact_control_inventory(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Extract direct/call edges and indirect sites from exact unit semantics."""

    by_rva = {
        int(row["source"]["original"]["rva_start"]): str(row["id"])
        for row in rows
    }
    direct_edges: list[dict[str, Any]] = []
    internal_call_edges: list[dict[str, Any]] = []
    indirect_exits: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for row in rows:
        unit_id = str(row["id"])
        source_rva = int(row["source"]["original"]["rva_start"])
        control = row.get("control")
        semantics = row.get("semantics")
        if not isinstance(control, Mapping) or not isinstance(semantics, Mapping):
            issues.append({
                "status": "violated",
                "code": "unit_control_semantics_malformed",
                "source_unit_id": unit_id,
            })
            continue
        direct_targets = control.get("direct_targets")
        if not isinstance(direct_targets, list):
            issues.append({
                "status": "violated",
                "code": "direct_target_inventory_malformed",
                "source_unit_id": unit_id,
            })
            direct_targets = []
        for target_rva in direct_targets:
            target = by_rva.get(target_rva) if isinstance(target_rva, int) else None
            if target is None:
                issues.append({
                    "status": "incomplete",
                    "code": "direct_edge_unresolved",
                    "source_unit_id": unit_id,
                    "target_rva": target_rva,
                })
            else:
                edge = {
                    "source_unit_id": unit_id,
                    "target_unit_id": target,
                }
                guard = _normalized_edge_guard(semantics, target_rva)
                if guard is not None:
                    edge["guard"] = guard
                direct_edges.append(edge)
        if control.get("has_indirect_target") is True:
            outcome = semantics.get("outcome")
            item = {
                "source_unit_id": unit_id,
                "source_rva": source_rva,
                "kind": control.get("kind"),
                "target_expression": (
                    outcome.get("target") if isinstance(outcome, Mapping) else None
                ),
            }
            item["id"] = indirect_exit_id_v2(item)
            indirect_exits.append(item)
        events = semantics.get("external_events")
        if not isinstance(events, list):
            issues.append({
                "status": "violated",
                "code": "external_event_inventory_malformed",
                "source_unit_id": unit_id,
            })
            continue
        for event_index, event in enumerate(events):
            if not isinstance(event, Mapping):
                issues.append({
                    "status": "violated",
                    "code": "external_event_malformed",
                    "source_unit_id": unit_id,
                    "event_index": event_index,
                })
                continue
            kind = event.get("kind")
            if kind == "internal_call":
                target_rva = event.get("target_rva")
                target = by_rva.get(target_rva) if isinstance(target_rva, int) else None
                if target is None:
                    issues.append({
                        "status": "incomplete",
                        "code": "internal_call_target_unresolved",
                        "source_unit_id": unit_id,
                        "event_index": event_index,
                        "target_rva": target_rva,
                    })
                else:
                    edge = {
                        "source_unit_id": unit_id,
                        "target_unit_id": target,
                        "source_event_index": event_index,
                    }
                    internal_call_edges.append(edge)
            elif kind in {"indirect_call", "indirect_jump"}:
                item = {
                    "source_unit_id": unit_id,
                    "source_rva": source_rva,
                    "source_event_index": event_index,
                    "kind": kind,
                    "target_expression": event.get("target"),
                }
                item["id"] = indirect_exit_id_v2(item)
                indirect_exits.append(item)
    return {
        "direct_edges": sorted(
            {json.dumps(row, sort_keys=True): row for row in direct_edges}.values(),
            key=lambda row: (str(row["source_unit_id"]), str(row["target_unit_id"])),
        ),
        "internal_call_edges": sorted(
            internal_call_edges,
            key=lambda row: (
                str(row["source_unit_id"]),
                int(row["source_event_index"]),
                str(row["target_unit_id"]),
            ),
        ),
        "indirect_exits": sorted(indirect_exits, key=lambda row: str(row["id"])),
        "issues": issues,
    }


def _normalized_edge_guard(
    semantics: Mapping[str, Any], target_rva: Any
) -> dict[str, Any] | None:
    """Retain a target's exact path guard in value-provenance form.

    Aggregate symbolic semantics already substitute most flag-producing
    instructions into edge predicates.  Some x86 idioms, notably ``test
    eax,eax``, retain the register's defining expression instead of its name.
    Replace only non-trivial expressions that exactly match one register output
    from the same unit, then apply small bitvector identities.  This preserves
    the checked predicate while allowing downstream facts for that register to
    be refined on the selected edge.
    """

    if not isinstance(target_rva, int) or isinstance(target_rva, bool):
        return None
    raw_conditions = semantics.get("edge_conditions")
    if not isinstance(raw_conditions, list):
        return None
    matches = [
        row.get("condition")
        for row in raw_conditions
        if isinstance(row, Mapping) and row.get("target_rva") == target_rva
    ]
    if len(matches) != 1 or not isinstance(matches[0], Mapping):
        return None

    aliases: list[tuple[Mapping[str, Any], dict[str, Any]]] = []
    writes = semantics.get("register_writes")
    if isinstance(writes, list):
        for raw in writes:
            if not isinstance(raw, Mapping):
                continue
            register = raw.get("register")
            expression = raw.get("value")
            if (
                not isinstance(register, str)
                or not isinstance(expression, Mapping)
                or not _guard_alias_expression(expression)
            ):
                continue
            aliases.append((
                expression,
                {"op": "reg", "name": register.lower(), "width": 32},
            ))
    aliases.sort(key=lambda item: str(item[1]["name"]))
    normalized = _normalize_guard_expression(matches[0], aliases)
    return normalized if isinstance(normalized, dict) else None


def _guard_alias_expression(expression: Mapping[str, Any]) -> bool:
    return str(expression.get("op") or "").lower() not in {
        "",
        "const",
        "constant",
        "reg",
        "register",
        "input_reg",
        "flag",
        "true",
        "false",
        "call_response",
        "call_flag",
    }


def _normalize_guard_expression(
    value: Any,
    aliases: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> Any:
    if isinstance(value, Mapping):
        for expression, replacement in aliases:
            if value == expression:
                return copy.deepcopy(dict(replacement))
        result = {
            str(key): _normalize_guard_expression(item, aliases)
            for key, item in value.items()
        }
        op = str(result.get("op") or "").lower()
        args = result.get("args")
        if (
            op in {"and", "and32", "bit_and"}
            and isinstance(args, list)
            and len(args) == 2
            and args[0] == args[1]
        ):
            return args[0]
        return result
    if isinstance(value, list):
        return [_normalize_guard_expression(item, aliases) for item in value]
    return copy.deepcopy(value)


def derive_rooted_control_closure_v2(
    *,
    rows: Sequence[Mapping[str, Any]],
    base_graph: Mapping[str, Any],
    interprocedural: Mapping[str, Any],
) -> dict[str, Any]:
    """Close exact control under cold-replayed targets and callback roots."""

    by_id = {str(row["id"]): row for row in rows}
    exact = _exact_control_inventory(rows)
    fixed = _object(interprocedural.get("fixed_point"), "interprocedural fixed point")
    root_ids = fixed.get("root_unit_ids")
    if not isinstance(root_ids, list):
        root_ids = [
            root.get("unit_id")
            for root in base_graph.get("roots", ())
            if isinstance(root, Mapping)
        ]
    roots = sorted({str(root) for root in root_ids if str(root) in by_id})
    recoveries = {
        str(row.get("id")): row
        for row in interprocedural.get("recovered_targets", ())
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    successors: dict[str, set[str]] = {unit_id: set() for unit_id in by_id}
    for edge in (*exact["direct_edges"], *exact["internal_call_edges"]):
        successors[str(edge["source_unit_id"])].add(str(edge["target_unit_id"]))
    for recovery in recoveries.values():
        if recovery.get("status") != "recovered":
            continue
        source = recovery.get("source_unit_id")
        if not isinstance(source, str) or source not in by_id:
            continue
        successors[source].update(
            target
            for target in recovery.get("target_unit_ids", ())
            if isinstance(target, str) and target in by_id
        )
    reachable: set[str] = set()
    pending = list(reversed(roots))
    while pending:
        unit_id = pending.pop()
        if unit_id in reachable:
            continue
        reachable.add(unit_id)
        pending.extend(sorted(successors.get(unit_id, ()), reverse=True))
    frontiers: list[dict[str, Any]] = []
    for exit_row in exact["indirect_exits"]:
        if exit_row["source_unit_id"] not in reachable:
            continue
        recovery = recoveries.get(str(exit_row["id"]))
        targets = recovery.get("target_unit_ids", ()) if recovery else ()
        external = recovery.get("external_targets", ()) if recovery else ()
        complete = (
            isinstance(recovery, Mapping)
            and recovery.get("status") == "recovered"
            and isinstance(targets, list)
            and isinstance(external, list)
            and bool(targets or external)
            and all(isinstance(target, str) and target in by_id for target in targets)
        )
        if not complete:
            frontiers.append({
                "id": exit_row["id"],
                "source_unit_id": exit_row["source_unit_id"],
                "failure": (
                    {"code": "interprocedural_recovery_missing"}
                    if recovery is None
                    else recovery.get("failure", {"code": "recovery_incomplete"})
                ),
            })
    issues = [
        issue
        for issue in exact["issues"]
        if issue.get("source_unit_id") in reachable
    ]
    issues.extend({
        "status": "incomplete",
        "code": "reachable_indirect_frontier",
        "exit_id": frontier["id"],
        "source_unit_id": frontier["source_unit_id"],
    } for frontier in frontiers)
    status = (
        "violated"
        if any(issue.get("status") == "violated" for issue in issues)
        else "incomplete" if issues else "complete"
    )
    root_kinds = {
        str(root.get("unit_id")): str(root.get("kind", "checked_root"))
        for root in base_graph.get("roots", ())
        if isinstance(root, Mapping) and isinstance(root.get("unit_id"), str)
    }
    indirect_certificates = []
    for exit_row in exact["indirect_exits"]:
        if exit_row["source_unit_id"] not in reachable:
            continue
        recovery = recoveries.get(str(exit_row["id"]))
        targets = recovery.get("target_unit_ids", []) if recovery else []
        external = recovery.get("external_targets", []) if recovery else []
        indirect_certificates.append({
            "id": exit_row["id"],
            "source_unit_id": exit_row["source_unit_id"],
            "status": (
                "complete"
                if isinstance(recovery, Mapping)
                and recovery.get("status") == "recovered"
                and bool(targets or external)
                else "incomplete"
            ),
            "target_unit_ids": list(targets) if isinstance(targets, list) else [],
            "external_targets": list(external) if isinstance(external, list) else [],
        })
    reachable_edges = [
        {"source_unit_id": source, "target_unit_id": target}
        for source in sorted(reachable)
        for target in sorted(successors.get(source, ()))
        if target in reachable
    ]
    body = {
        "format": ROOTED_CONTROL_CLOSURE_V2_FORMAT,
        "status": status,
        "roots": [
            {
                "unit_id": unit_id,
                "kind": root_kinds.get(unit_id, "registered_callback"),
            }
            for unit_id in roots
        ],
        "reachable_units": sorted(reachable),
        "direct_edges": reachable_edges,
        "indirect_exits": sorted(
            indirect_certificates, key=lambda row: str(row["id"])
        ),
        "frontiers": sorted(frontiers, key=lambda row: str(row["id"])),
        "issues": sorted(
            issues,
            key=lambda row: (
                str(row.get("status")),
                str(row.get("code")),
                str(row.get("source_unit_id", "")),
            ),
        ),
    }
    return {**body, "id": "rooted-control-graph-v2:" + canonical_sha256(body)}




def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    return value


exact_control_inventory_v2 = _exact_control_inventory
exact_indirect_exit_id_v2 = indirect_exit_id_v2


__all__ = [
    "ROOTED_CONTROL_CLOSURE_V2_FORMAT",
    "derive_rooted_control_closure_v2",
    "derive_rooted_control_graph_v2",
    "exact_control_inventory_v2",
    "exact_indirect_exit_id_v2",
]
