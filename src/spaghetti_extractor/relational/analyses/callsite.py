from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from ..schema import REGISTERS
from ...util import sha256_bytes


CALLSITE_PRESERVATION_ANALYSIS_FORMAT = (
    "stage-a-callsite-preservation-analysis-v1"
)
CALLSITE_PRESERVATION_CERTIFICATE_FORMAT = (
    "stage-a-callsite-preserved-register-summary-v1"
)
NORMALIZED_BEHAVIOR_FORMAT = "stage-a-normalized-behavior-v1"


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _certificate_hash(value: Mapping[str, Any]) -> str:
    return sha256_bytes(_canonical_json(value).encode())


def _issue(
    code: str,
    *,
    node_id: int | None = None,
    field: str | None = None,
    reference: Any = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"code": code}
    if node_id is not None:
        result["node_id"] = node_id
    if field is not None:
        result["field"] = field
    if reference is not None:
        result["reference"] = reference
    return result


def _sorted_issues(issues: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {_canonical_json(issue): issue for issue in issues}
    return [unique[key] for key in sorted(unique)]


def _incomplete(
    callsite_id: Any, issues: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    ordered = _sorted_issues(issues)
    return {
        "format": CALLSITE_PRESERVATION_ANALYSIS_FORMAT,
        "status": "incomplete",
        "callsite_id": callsite_id,
        "reason_codes": sorted({str(issue["code"]) for issue in ordered}),
        "issues": ordered,
        "certificate": None,
    }


def _rows_by_node(
    rows: Any,
    *,
    invalid_code: str,
    duplicate_code: str,
) -> tuple[dict[int, Mapping[str, Any]], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    by_node: dict[int, Mapping[str, Any]] = {}
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return {}, [_issue(invalid_code)]
    for row in rows:
        if not isinstance(row, Mapping) or not _is_integer(row.get("node_id")):
            issues.append(_issue(invalid_code))
            continue
        node_id = int(row["node_id"])
        if node_id in by_node:
            issues.append(_issue(duplicate_code, node_id=node_id))
            continue
        by_node[node_id] = row
    return by_node, issues


def _normalize_relations(
    relations: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    normalized: list[dict[str, Any]] = []
    if not isinstance(relations, Sequence) or isinstance(relations, (str, bytes)):
        return [], [_issue("requested_relation_inventory_invalid")]
    seen: set[str] = set()
    original_owners: dict[str, str] = {}
    candidate_owners: dict[str, str] = {}
    for relation in relations:
        if not isinstance(relation, Mapping):
            issues.append(_issue("requested_relation_invalid"))
            continue
        original = relation.get("original")
        candidate = relation.get("candidate")
        imported = relation.get("import")
        if (
            original not in REGISTERS
            or candidate not in REGISTERS
            or not isinstance(imported, Mapping)
            or not imported
        ):
            issues.append(_issue("requested_relation_invalid"))
            continue
        try:
            canonical_import = json.loads(_canonical_json(imported))
        except (TypeError, ValueError):
            issues.append(_issue("requested_relation_invalid"))
            continue
        normalized_relation = {
            "original": str(original),
            "candidate": str(candidate),
            "import": canonical_import,
        }
        key = _canonical_json(normalized_relation)
        if key in seen:
            issues.append(_issue("requested_relation_duplicate"))
            continue
        seen.add(key)
        if original in original_owners and original_owners[str(original)] != key:
            issues.append(_issue(
                "requested_relation_ambiguous",
                field="original",
                reference=str(original),
            ))
        if candidate in candidate_owners and candidate_owners[str(candidate)] != key:
            issues.append(_issue(
                "requested_relation_ambiguous",
                field="candidate",
                reference=str(candidate),
            ))
        original_owners[str(original)] = key
        candidate_owners[str(candidate)] = key
        normalized.append(normalized_relation)
    if not normalized:
        issues.append(_issue("requested_relation_inventory_empty"))
    return sorted(normalized, key=_canonical_json), issues


def _normalize_return_inventory(
    inventory: Any,
) -> tuple[dict[int, dict[str, int]], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    result: dict[int, dict[str, int]] = {}
    if not isinstance(inventory, Sequence) or isinstance(inventory, (str, bytes)):
        return {}, [_issue("return_inventory_invalid")]
    for row in inventory:
        if not isinstance(row, Mapping):
            issues.append(_issue("return_inventory_invalid"))
            continue
        return_node_id = row.get("return_node_id")
        continuation_id = row.get("continuation_id")
        if not _is_integer(return_node_id) or not _is_integer(continuation_id):
            issues.append(_issue("return_inventory_invalid"))
            continue
        return_node_id = int(return_node_id)
        continuation_id = int(continuation_id)
        if return_node_id in result:
            issues.append(_issue(
                "return_inventory_duplicate", node_id=return_node_id,
            ))
            if result[return_node_id]["continuation_id"] != continuation_id:
                issues.append(_issue(
                    "return_continuation_ambiguous", node_id=return_node_id,
                ))
            continue
        result[return_node_id] = {
            "return_node_id": return_node_id,
            "continuation_id": continuation_id,
        }
    if not result:
        issues.append(_issue("return_inventory_empty"))
    return result, issues


def _normalize_nested_summaries(
    summaries: Any,
) -> tuple[dict[str, Mapping[str, Any]], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    result: dict[str, Mapping[str, Any]] = {}
    if summaries is None:
        summaries = []
    if not isinstance(summaries, Sequence) or isinstance(summaries, (str, bytes)):
        return {}, [_issue("nested_summary_inventory_invalid")]
    for supplied in summaries:
        certificate = supplied
        if (
            isinstance(supplied, Mapping)
            and supplied.get("format") == CALLSITE_PRESERVATION_ANALYSIS_FORMAT
        ):
            certificate = supplied.get("certificate")
        if not isinstance(certificate, Mapping):
            issues.append(_issue("nested_summary_invalid"))
            continue
        summary_id = certificate.get("id")
        if (
            certificate.get("format") != CALLSITE_PRESERVATION_CERTIFICATE_FORMAT
            or not isinstance(summary_id, str)
            or not summary_id
        ):
            issues.append(_issue("nested_summary_invalid"))
            continue
        unsigned = dict(certificate)
        supplied_hash = unsigned.pop("certificate_hash", None)
        if supplied_hash != _certificate_hash(unsigned):
            issues.append(_issue(
                "nested_summary_hash_invalid", reference=summary_id,
            ))
            continue
        if summary_id in result:
            issues.append(_issue(
                "nested_summary_duplicate", reference=summary_id,
            ))
            continue
        result[summary_id] = certificate
    return result, issues


def _behavior_successors(
    outcome: Mapping[str, Any], *, nested: bool,
) -> tuple[list[int] | None, str | None]:
    operation = outcome.get("op")
    if operation == "jump" and _is_integer(outcome.get("target")):
        return [int(outcome["target"])], None
    if (
        operation == "branch"
        and _is_integer(outcome.get("taken"))
        and _is_integer(outcome.get("fallthrough"))
    ):
        return [int(outcome["taken"]), int(outcome["fallthrough"])], None
    if operation == "returned":
        return [], "return"
    if (
        nested
        and operation == "call"
        and _is_integer(outcome.get("target"))
        and _is_integer(outcome.get("continuation"))
    ):
        return [int(outcome["continuation"])], "nested_call"
    if operation in {"indirect_call", "indirect_jump"}:
        return None, "unresolved_indirect_control"
    return None, "unsupported_behavior"


def _cyclic_nodes(
    nodes: Sequence[int], adjacency: Mapping[int, Sequence[int]],
) -> list[int]:
    """Return nodes in nontrivial SCCs or with self edges, deterministically."""
    index = 0
    indices: dict[int, int] = {}
    lowlinks: dict[int, int] = {}
    stack: list[int] = []
    on_stack: set[int] = set()
    cyclic: set[int] = set()

    def visit(node_id: int) -> None:
        nonlocal index
        indices[node_id] = index
        lowlinks[node_id] = index
        index += 1
        stack.append(node_id)
        on_stack.add(node_id)
        for successor in sorted(adjacency.get(node_id, [])):
            if successor not in indices:
                visit(successor)
                lowlinks[node_id] = min(lowlinks[node_id], lowlinks[successor])
            elif successor in on_stack:
                lowlinks[node_id] = min(lowlinks[node_id], indices[successor])
        if lowlinks[node_id] != indices[node_id]:
            return
        component: list[int] = []
        while stack:
            member = stack.pop()
            on_stack.remove(member)
            component.append(member)
            if member == node_id:
                break
        if len(component) > 1 or node_id in adjacency.get(node_id, []):
            cyclic.update(component)

    for node_id in sorted(nodes):
        if node_id not in indices:
            visit(node_id)
    return sorted(cyclic)


def propose_callsite_preserved_register_summary(
    *,
    callsite_id: int,
    callee_entry: int,
    return_inventory: Sequence[Mapping[str, Any]],
    requested_relations: Sequence[Mapping[str, Any]],
    behaviors: Sequence[Mapping[str, Any]],
    control: Sequence[Mapping[str, Any]],
    nested_summaries: Sequence[Mapping[str, Any]] = (),
    max_nodes: int = 4096,
    max_edges: int = 16384,
) -> dict[str, Any]:
    """Propose a checked callsite-local preserved-import-register summary.

    This is untrusted proposal analysis. It accepts only a finite, explicitly
    paired control graph whose reachable normalized blocks preserve every
    requested register by syntactic identity. A later Lean checker must replay
    the emitted node, edge, return, behavior, and nested-certificate inventory.
    """
    issues: list[dict[str, Any]] = []
    if not _is_integer(callsite_id):
        issues.append(_issue("callsite_id_invalid"))
    if not _is_integer(callee_entry):
        issues.append(_issue("callee_entry_invalid"))
    if (
        not _is_integer(max_nodes)
        or not _is_integer(max_edges)
        or max_nodes <= 0
        or max_edges <= 0
    ):
        issues.append(_issue("analysis_budget_invalid"))

    behavior_by_node, behavior_issues = _rows_by_node(
        behaviors,
        invalid_code="behavior_inventory_invalid",
        duplicate_code="behavior_node_duplicate",
    )
    control_by_node, control_issues = _rows_by_node(
        control,
        invalid_code="control_inventory_invalid",
        duplicate_code="control_node_duplicate",
    )
    relations, relation_issues = _normalize_relations(requested_relations)
    returns, return_issues = _normalize_return_inventory(return_inventory)
    nested_by_id, nested_issues = _normalize_nested_summaries(nested_summaries)
    issues.extend(behavior_issues)
    issues.extend(control_issues)
    issues.extend(relation_issues)
    issues.extend(return_issues)
    issues.extend(nested_issues)
    if issues:
        return _incomplete(callsite_id, issues)

    entry = int(callee_entry)
    if entry not in control_by_node:
        return _incomplete(callsite_id, [
            _issue("callee_entry_missing", node_id=entry),
        ])

    pending = [entry]
    reachable: set[int] = set()
    adjacency: dict[int, list[int]] = {}
    matched_return_nodes: set[int] = set()
    nested_dependencies: list[dict[str, Any]] = []
    edge_count = 0
    while pending:
        node_id = pending.pop()
        if node_id in reachable:
            continue
        if len(reachable) >= max_nodes:
            issues.append(_issue("node_budget_overflow", node_id=node_id))
            break
        reachable.add(node_id)
        control_row = control_by_node.get(node_id)
        behavior_row = behavior_by_node.get(node_id)
        if control_row is None:
            issues.append(_issue("reachable_control_node_missing", node_id=node_id))
            continue
        if behavior_row is None:
            issues.append(_issue("reachable_behavior_missing", node_id=node_id))
            continue

        successors = control_row.get("successors")
        exit_row = control_row.get("exit")
        if (
            not isinstance(successors, Sequence)
            or isinstance(successors, (str, bytes))
            or not isinstance(exit_row, Mapping)
        ):
            issues.append(_issue("control_inventory_invalid", node_id=node_id))
            continue
        if any(not _is_integer(successor) for successor in successors):
            issues.append(_issue("successor_inventory_invalid", node_id=node_id))
            continue
        successor_ids = [int(successor) for successor in successors]
        if len(set(successor_ids)) != len(successor_ids):
            issues.append(_issue("successor_duplicate", node_id=node_id))
            continue
        edge_count += len(successor_ids)
        if edge_count > max_edges:
            issues.append(_issue("edge_budget_overflow", node_id=node_id))
            break
        adjacency[node_id] = successor_ids

        original = behavior_row.get("original_ir")
        candidate = behavior_row.get("candidate_ir")
        if (
            not isinstance(original, Mapping)
            or not isinstance(candidate, Mapping)
            or original.get("format") != NORMALIZED_BEHAVIOR_FORMAT
            or candidate.get("format") != NORMALIZED_BEHAVIOR_FORMAT
        ):
            issues.append(_issue("unsupported_behavior", node_id=node_id))
            continue
        original_registers = original.get("registers")
        candidate_registers = candidate.get("registers")
        if not isinstance(original_registers, Mapping) or not isinstance(
            candidate_registers, Mapping
        ):
            issues.append(_issue("unsupported_behavior", node_id=node_id))
            continue
        for relation in relations:
            original_register = relation["original"]
            candidate_register = relation["candidate"]
            expected_original = {
                "op": "input_reg", "reg": original_register,
            }
            expected_candidate = {
                "op": "input_reg", "reg": candidate_register,
            }
            if original_register not in original_registers:
                issues.append(_issue(
                    "register_output_missing",
                    node_id=node_id,
                    field=f"original.{original_register}",
                ))
            elif original_registers[original_register] != expected_original:
                issues.append(_issue(
                    "register_clobbered",
                    node_id=node_id,
                    field=f"original.{original_register}",
                ))
            if candidate_register not in candidate_registers:
                issues.append(_issue(
                    "register_output_missing",
                    node_id=node_id,
                    field=f"candidate.{candidate_register}",
                ))
            elif candidate_registers[candidate_register] != expected_candidate:
                issues.append(_issue(
                    "register_clobbered",
                    node_id=node_id,
                    field=f"candidate.{candidate_register}",
                ))

        exit_kind = exit_row.get("kind")
        nested = exit_kind == "nested_call"
        original_successors, original_terminal = _behavior_successors(
            original.get("outcome") or {}, nested=nested,
        )
        candidate_successors, candidate_terminal = _behavior_successors(
            candidate.get("outcome") or {}, nested=nested,
        )
        if (
            original_terminal == "unresolved_indirect_control"
            or candidate_terminal == "unresolved_indirect_control"
            or exit_kind == "unresolved_indirect"
        ):
            issues.append(_issue(
                "unresolved_indirect_control", node_id=node_id,
            ))
            continue
        if (
            original_terminal == "unsupported_behavior"
            or candidate_terminal == "unsupported_behavior"
            or exit_kind == "unsupported"
        ):
            issues.append(_issue("unsupported_behavior", node_id=node_id))
            continue
        if original_terminal != candidate_terminal:
            issues.append(_issue("mismatched_return", node_id=node_id))
            continue
        if original_successors != candidate_successors:
            issues.append(_issue("paired_successor_mismatch", node_id=node_id))
            continue
        if (
            nested
            and (original.get("outcome") or {}).get("target")
                != (candidate.get("outcome") or {}).get("target")
        ):
            issues.append(_issue(
                "paired_nested_target_mismatch", node_id=node_id,
            ))
            continue
        if original_successors != successor_ids:
            issues.append(_issue("control_behavior_mismatch", node_id=node_id))
            continue

        if exit_kind == "return":
            if original_terminal != "return":
                issues.append(_issue("mismatched_return", node_id=node_id))
                continue
            if successor_ids:
                issues.append(_issue("return_has_successor", node_id=node_id))
                continue
            if node_id not in returns:
                issues.append(_issue("return_inventory_missing", node_id=node_id))
                continue
            matched_return_nodes.add(node_id)
        elif exit_kind == "direct":
            if original_terminal is not None:
                issues.append(_issue("control_behavior_mismatch", node_id=node_id))
                continue
            if not successor_ids:
                issues.append(_issue("unmatched_reachable_exit", node_id=node_id))
                continue
        elif exit_kind == "nested_call":
            if original_terminal != "nested_call":
                issues.append(_issue("control_behavior_mismatch", node_id=node_id))
                continue
            summary_id = exit_row.get("summary_id")
            if not isinstance(summary_id, str) or not summary_id:
                issues.append(_issue("nested_summary_missing", node_id=node_id))
                continue
            summary = nested_by_id.get(summary_id)
            if summary is None:
                issues.append(_issue(
                    "nested_summary_missing", node_id=node_id,
                    reference=summary_id,
                ))
                continue
            target = (original.get("outcome") or {}).get("target")
            if summary.get("callee_entry") != target:
                issues.append(_issue(
                    "nested_summary_target_mismatch", node_id=node_id,
                    reference=summary_id,
                ))
            if summary.get("callsite_id") != node_id:
                issues.append(_issue(
                    "nested_summary_callsite_mismatch", node_id=node_id,
                    reference=summary_id,
                ))
            summary_relations = {
                _canonical_json(relation)
                for relation in summary.get("requested_relations", [])
                if isinstance(relation, Mapping)
            }
            missing_relations = [
                relation for relation in relations
                if _canonical_json(relation) not in summary_relations
            ]
            if missing_relations:
                issues.append(_issue(
                    "nested_summary_relation_missing", node_id=node_id,
                    reference=summary_id,
                ))
            continuations = {
                row.get("continuation_id")
                for row in summary.get("return_inventory", [])
                if isinstance(row, Mapping)
            }
            if continuations != set(successor_ids):
                issues.append(_issue(
                    "nested_summary_continuation_mismatch", node_id=node_id,
                    reference=summary_id,
                ))
            nested_dependencies.append({
                "node_id": node_id,
                "summary_id": summary_id,
                "certificate_hash": summary["certificate_hash"],
            })
        else:
            issues.append(_issue(
                "control_exit_kind_unsupported",
                node_id=node_id,
                reference=exit_kind,
            ))
            continue

        for successor in reversed(successor_ids):
            if successor not in control_by_node:
                issues.append(_issue(
                    "successor_node_missing",
                    node_id=node_id,
                    reference=successor,
                ))
                continue
            pending.append(successor)

    unmatched_inventory = sorted(set(returns) - matched_return_nodes)
    for node_id in unmatched_inventory:
        issues.append(_issue("return_inventory_unreachable", node_id=node_id))
    if not matched_return_nodes:
        issues.append(_issue("no_matched_return"))

    if reachable:
        predecessors: dict[int, list[int]] = {node_id: [] for node_id in reachable}
        for source, successors in adjacency.items():
            for target in successors:
                if target in predecessors:
                    predecessors[target].append(source)
        can_return = set(matched_return_nodes)
        pending_reverse = list(sorted(matched_return_nodes, reverse=True))
        while pending_reverse:
            node_id = pending_reverse.pop()
            for predecessor in sorted(predecessors.get(node_id, []), reverse=True):
                if predecessor not in can_return:
                    can_return.add(predecessor)
                    pending_reverse.append(predecessor)
        for node_id in sorted(reachable - can_return):
            issues.append(_issue(
                "cycle_without_return_closure", node_id=node_id,
            ))

    if issues:
        return _incomplete(callsite_id, issues)

    reachable_nodes = sorted(reachable)
    edges = [
        {"source": source, "target": target}
        for source in reachable_nodes
        for target in adjacency.get(source, [])
    ]
    behavior_hashes = [{
        "node_id": node_id,
        "original": _certificate_hash(behavior_by_node[node_id]["original_ir"]),
        "candidate": _certificate_hash(behavior_by_node[node_id]["candidate_ir"]),
    } for node_id in reachable_nodes]
    certificate: dict[str, Any] = {
        "format": CALLSITE_PRESERVATION_CERTIFICATE_FORMAT,
        "callsite_id": int(callsite_id),
        "callee_entry": entry,
        "requested_relations": relations,
        "reachable_node_ids": reachable_nodes,
        "reachable_edges": edges,
        "return_inventory": [returns[node_id] for node_id in sorted(returns)],
        "behavior_hashes": behavior_hashes,
        "nested_dependencies": sorted(
            nested_dependencies,
            key=lambda row: (row["node_id"], row["summary_id"]),
        ),
        "cyclic_node_ids": _cyclic_nodes(reachable_nodes, adjacency),
        "closure": {
            "finite": True,
            "all_reachable_exits_matched": True,
            "all_nodes_can_reach_return": True,
            "all_requested_registers_identity_preserved": True,
        },
    }
    identity_hash = _certificate_hash(certificate)
    certificate["id"] = (
        f"callsite-preservation:{int(callsite_id)}:{entry}:"
        f"{identity_hash[:16]}"
    )
    certificate["certificate_hash"] = _certificate_hash(certificate)
    return {
        "format": CALLSITE_PRESERVATION_ANALYSIS_FORMAT,
        "status": "satisfied",
        "callsite_id": int(callsite_id),
        "reason_codes": [],
        "issues": [],
        "certificate": certificate,
    }
