"""Fail-closed frame summaries for PE32 calls and behavioral roots.

The summaries are proposal evidence, not acceptance authority.  They traverse
the exported machine IR, retain only values whose origins survive every
returning path, and abandon claims at unresolved control or bounded-analysis
frontiers.  Lean must replay any summary used by a final proof.
"""

from __future__ import annotations

import copy
import hashlib
import heapq
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .import_abi import SelectedImportABI
from .machine_abi import resolve_machine_call_abi
from .machine_import_profiles import MachineImportIdentity


INTERNAL_CALL_SUMMARY_FORMAT = "stage-a-internal-call-preservation-v1"
_REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")
_SUMMARY_REGISTERS = frozenset({"ebp", "ebx", "edi", "esi"})
_CALL_KINDS = frozenset({"external_call", "indirect_call", "internal_call"})
_TERMINAL_KINDS = frozenset({"fault", "terminate", "terminated", "halt"})
_TERMINATING_DISPOSITION = {
    "kind": "terminates_after_external_event",
    "authority": "external_profile_machine_import_contract",
}


@dataclass(frozen=True)
class _RegisterOrigin:
    register: str


@dataclass(frozen=True)
class _StackAddress:
    offset: int
    register_terms: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class _StackTransform:
    constant: int
    register_terms: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class _Exact:
    value: int


@dataclass(frozen=True)
class _ExternalResult:
    producer_unit_id: str
    event_index: int
    dll: str
    identity_kind: str
    identity_value: str | int
    relation: str
    nullable: bool


@dataclass(frozen=True)
class _InternalContractResult:
    contract_id: str
    relation: str
    nullable: bool


_Value = (
    _RegisterOrigin
    | _StackAddress
    | _Exact
    | _ExternalResult
    | _InternalContractResult
    | None
)


@dataclass
class _State:
    registers: dict[str, _Value]
    stack_words: dict[int, _Value]


@dataclass(frozen=True)
class _CallFrame:
    behavior_complete: bool
    may_return: bool | None
    may_not_return: bool | None
    preserved_registers: frozenset[str]
    stack_cleanup: _StackTransform | None
    result_registers: Mapping[str, _Value]
    blocker_codes: frozenset[str] = frozenset()


def derive_internal_call_preservation_summaries(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Iterable[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recovered_indirect_targets: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    declared_summaries: Mapping[str, Mapping[str, Any]] | None = None,
    max_units_per_summary: int = 4096,
    max_stack_words: int = 256,
    max_fixed_point_rounds: int = 64,
) -> dict[str, Any]:
    """Propose frame/return facts for reachable callees and behavioral roots."""

    if min(max_units_per_summary, max_stack_words, max_fixed_point_rounds) <= 0:
        raise ValueError("internal call summary budgets must be positive")
    by_id = {str(unit["id"]): unit for unit in units}
    if len(by_id) != len(units):
        raise ValueError("internal call summaries require unique unit IDs")
    declarations = declared_summaries or {}
    unknown_declarations = sorted(set(declarations) - set(by_id))
    if unknown_declarations:
        raise ValueError(
            "declared internal summaries name unknown units: "
            + ", ".join(unknown_declarations)
        )

    normal_edges: dict[str, set[str]] = defaultdict(set)
    unresolved_direct_sources: set[str] = set()
    for edge in direct_edges:
        source = edge.get("source_unit_id")
        target = edge.get("target_unit_id", edge.get("resolved_unit_id"))
        if not isinstance(source, str) or source not in by_id:
            continue
        if (
            edge.get("status") in {None, "resolved"}
            and isinstance(target, str)
            and target in by_id
        ):
            normal_edges[source].add(target)
        else:
            unresolved_direct_sources.add(source)

    explicit_direct_calls: dict[tuple[str, int], str] = {}
    for edge in internal_call_edges:
        source = edge.get("source_unit_id")
        target = edge.get("target_unit_id", edge.get("resolved_unit_id"))
        event_index = _integer(edge.get("source_event_index"))
        if (
            edge.get("status") in {None, "resolved"}
            and isinstance(source, str)
            and isinstance(target, str)
            and event_index is not None
            and source in by_id
            and target in by_id
        ):
            explicit_direct_calls[(source, event_index)] = target
    direct_calls = _canonical_direct_calls(
        by_id=by_id,
        explicit_calls=explicit_direct_calls,
    )

    exits_by_site = {
        (str(row.get("source_unit_id") or ""), _integer(row.get("source_event_index"))): row
        for row in indirect_exits
    }
    recoveries_by_id = {
        str(row.get("id")): row
        for row in recovered_indirect_targets
        if row.get("status") == "recovered"
    }
    unresolved_jump_sources: set[str] = set()
    recovered_calls: dict[tuple[str, int], Mapping[str, Any]] = {}
    recovered_call_targets: dict[str, set[str]] = defaultdict(set)
    for site, exit_record in exits_by_site.items():
        recovery = recoveries_by_id.get(str(exit_record.get("id")))
        source, event_index = site
        if exit_record.get("kind") == "indirect_jump":
            if recovery is None or recovery.get("external_targets"):
                unresolved_jump_sources.add(source)
                continue
            targets = recovery.get("target_unit_ids")
            if not isinstance(targets, Sequence) or isinstance(targets, (str, bytes)):
                unresolved_jump_sources.add(source)
                continue
            valid = {
                str(target)
                for target in targets
                if isinstance(target, str) and target in by_id
            }
            if len(valid) != len(targets) or not valid:
                unresolved_jump_sources.add(source)
                continue
            normal_edges[source].update(valid)
        elif (
            exit_record.get("kind") == "indirect_call"
            and event_index is not None
            and recovery is not None
        ):
            recovered_calls[(source, event_index)] = recovery
            for target in recovery.get("target_unit_ids", []):
                if isinstance(target, str) and target in by_id:
                    recovered_call_targets[source].add(target)

    behavioral_roots = {str(root) for root in roots if str(root) in by_id}
    eligible_units, callee_roots = _reachable_call_roots(
        roots=behavioral_roots,
        normal_edges=normal_edges,
        direct_calls=direct_calls,
        recovered_call_targets=recovered_call_targets,
    )
    summary_roots = behavioral_roots | callee_roots
    (
        ordered_components,
        recursive_roots,
        dependency_inventory_incomplete,
    ) = _summary_dependency_order(
        summary_roots=summary_roots,
        normal_edges=normal_edges,
        direct_calls=direct_calls,
        recovered_calls=recovered_calls,
        max_units=max_units_per_summary,
        opaque_roots=frozenset(declarations),
    )
    summaries: dict[str, dict[str, Any]] = {
        root: copy.deepcopy(dict(summary))
        for root, summary in declarations.items()
        if root in summary_roots
    }
    rounds = 1 if summary_roots else 0
    fixed_point_complete = True
    for component in ordered_components:
        if all(root in summaries for root in component):
            continue
        recursive_component = any(root in recursive_roots for root in component)
        if recursive_component:
            component_summaries, component_rounds, converged = (
                _analyze_recursive_component(
                    component=component,
                    by_id=by_id,
                    normal_edges=normal_edges,
                    unresolved_direct_sources=unresolved_direct_sources,
                    unresolved_jump_sources=unresolved_jump_sources,
                    direct_calls=direct_calls,
                    recovered_calls=recovered_calls,
                    completed_summaries=summaries,
                    import_abis=import_abis,
                    max_units=max_units_per_summary,
                    max_stack_words=max_stack_words,
                    max_rounds=max_fixed_point_rounds,
                )
            )
            rounds = max(rounds, component_rounds)
            fixed_point_complete = fixed_point_complete and converged
            summaries.update(component_summaries)
            continue

        root = component[0]
        proposed = _analyze_callee(
            root=root,
            by_id=by_id,
            normal_edges=normal_edges,
            unresolved_direct_sources=unresolved_direct_sources,
            unresolved_jump_sources=unresolved_jump_sources,
            direct_calls=direct_calls,
            recovered_calls=recovered_calls,
            summaries=summaries,
            import_abis=import_abis,
            max_units=max_units_per_summary,
            max_stack_words=max_stack_words,
        )
        forced_blockers = (
            {"call_dependency_inventory_budget_exceeded"}
            if root in dependency_inventory_incomplete
            else set()
        )
        summaries[root] = _force_incomplete(proposed, forced_blockers)

    for root in dependency_inventory_incomplete:
        if root in summaries:
            summaries[root] = _force_incomplete(
                summaries[root],
                {"call_dependency_inventory_budget_exceeded"},
            )
    fixed_point_complete = (
        fixed_point_complete and len(summaries) == len(summary_roots)
    )

    rows: list[dict[str, Any]] = []
    for root in sorted(summary_roots):
        source = _mapping(_mapping(by_id[root].get("source")).get("original"))
        is_behavioral_root = root in behavioral_roots
        is_callee = root in callee_roots
        return_instruction_cleanup = _derive_return_instruction_cleanup(
            root=root,
            by_id=by_id,
            normal_edges=normal_edges,
            unresolved_direct_sources=unresolved_direct_sources,
            unresolved_jump_sources=unresolved_jump_sources,
            max_units=max_units_per_summary,
        )
        rows.append(
            {
                "target_unit_id": root,
                "target_rva": _integer(source.get("rva_start")),
                "root_kind": (
                    "behavioral_root_and_callee"
                    if is_behavioral_root and is_callee
                    else "behavioral_root"
                    if is_behavioral_root
                    else "callee"
                ),
                **summaries[root],
                # This family depends only on represented intraprocedural
                # control and exact return instructions.  It remains usable
                # when register, memory, or external behavior is incomplete.
                "return_instruction_cleanup": return_instruction_cleanup,
            }
        )
    complete = [row for row in rows if row["status"] == "complete"]
    stack_complete = [
        row
        for row in complete
        if _mapping(row.get("stack_cleanup")).get("status") == "complete"
    ]
    return_instruction_complete = [
        row
        for row in rows
        if _mapping(row.get("return_instruction_cleanup")).get("status")
        == "complete"
    ]
    return {
        "format": INTERNAL_CALL_SUMMARY_FORMAT,
        "status": (
            "complete"
            if fixed_point_complete and len(complete) == len(rows)
            else "incomplete"
        ),
        "proof_authority": False,
        "required_replay": "Lean must replay CFG closure and every preserved origin",
        "budgets": {
            "max_units_per_summary": max_units_per_summary,
            "max_stack_words": max_stack_words,
            "max_fixed_point_rounds": max_fixed_point_rounds,
        },
        "fixed_point_rounds": rounds,
        "fixed_point_complete": fixed_point_complete,
        "recursive_summary_roots": sorted(recursive_roots),
        "dependency_inventory_incomplete_roots": sorted(
            dependency_inventory_incomplete
        ),
        "eligible_units": sorted(eligible_units),
        "summaries": rows,
        "counts": {
            "eligible_units": len(eligible_units),
            "call_targets": len(callee_roots),
            "behavioral_roots": len(behavioral_roots),
            "summary_roots": len(rows),
            "recursive_summary_roots": len(recursive_roots),
            "dependency_inventory_incomplete_roots": len(
                dependency_inventory_incomplete
            ),
            "complete_summaries": len(complete),
            "incomplete_summaries": len(rows) - len(complete),
            "preserved_register_claims": sum(
                len(row["preserved_registers"]) for row in complete
            ),
            "complete_stack_cleanup_claims": len(stack_complete),
            "complete_return_instruction_cleanup_claims": len(
                return_instruction_complete
            ),
        },
    }


def _derive_return_instruction_cleanup(
    *,
    root: str,
    by_id: Mapping[str, Mapping[str, Any]],
    normal_edges: Mapping[str, set[str]],
    unresolved_direct_sources: set[str],
    unresolved_jump_sources: set[str],
    max_units: int,
) -> dict[str, Any]:
    """Check the caller-visible cleanup encoded by every reachable ``ret``.

    Callee cleanup is a property of return instructions, not of prologue stack
    motion or unrelated register and memory summaries.  Keeping this as an
    independent family lets stack analysis cross a call while other families
    truthfully remain incomplete.
    """

    pending = deque([root])
    reached: set[str] = set()
    returns: dict[str, int] = {}
    blockers: set[str] = set()
    while pending:
        unit_id = pending.popleft()
        if unit_id in reached:
            continue
        if len(reached) >= max_units:
            blockers.add("return_instruction_cleanup_unit_budget_exceeded")
            break
        unit = by_id.get(unit_id)
        if unit is None:
            blockers.add("return_instruction_cleanup_unit_missing")
            break
        reached.add(unit_id)
        outcome = _mapping(_mapping(unit.get("semantics")).get("outcome"))
        kind = outcome.get("kind")
        if kind == "return":
            cleanup = _return_instruction_cleanup_bytes(unit)
            if cleanup is None:
                blockers.add("return_instruction_form_unsupported")
            else:
                returns[unit_id] = cleanup
            continue
        if unit_id in unresolved_direct_sources:
            blockers.add("return_instruction_direct_frontier_open")
        if unit_id in unresolved_jump_sources:
            blockers.add("return_instruction_indirect_frontier_open")
        successors = normal_edges.get(unit_id, set())
        if successors:
            pending.extend(sorted(successors))
        elif kind not in _TERMINAL_KINDS and not _has_checked_terminating_disposition(
            unit
        ):
            blockers.add("return_instruction_control_frontier_open")

    cleanup_values = sorted(set(returns.values()))
    if not returns:
        blockers.add("return_instruction_inventory_empty")
    if len(cleanup_values) > 1:
        blockers.add("return_instruction_cleanup_ambiguous")
    status = "complete" if not blockers and len(cleanup_values) == 1 else "incomplete"
    return {
        "status": status,
        "cleanup_bytes": cleanup_values[0] if status == "complete" else None,
        "return_unit_ids": sorted(returns),
        "reached_units": len(reached),
        "blocker_codes": sorted(blockers),
    }


def _return_instruction_cleanup_bytes(unit: Mapping[str, Any]) -> int | None:
    instructions = unit.get("instructions")
    if not isinstance(instructions, list) or not instructions:
        return None
    returns = [
        _mapping(raw)
        for raw in instructions
        if str(_mapping(raw).get("mnemonic") or "").lower().startswith("ret")
    ]
    if len(returns) != 1:
        return None
    operands = returns[0].get("operands")
    if not isinstance(operands, list):
        return None
    if not operands:
        return 0
    if len(operands) != 1:
        return None
    operand = _mapping(operands[0])
    if operand.get("kind") not in {"immediate", None}:
        return None
    value = _integer(operand.get("value"))
    return value if value is not None and 0 <= value <= 0xFFFF else None


def _reachable_call_roots(
    *,
    roots: set[str],
    normal_edges: Mapping[str, set[str]],
    direct_calls: Mapping[tuple[str, int], str],
    recovered_call_targets: Mapping[str, set[str]],
) -> tuple[set[str], set[str]]:
    callees_by_source: dict[str, set[str]] = defaultdict(set)
    for (source, _), target in direct_calls.items():
        callees_by_source[source].add(target)
    for source, targets in recovered_call_targets.items():
        callees_by_source[source].update(targets)
    reached = set(roots)
    callees: set[str] = set()
    work = deque(sorted(roots))
    while work:
        source = work.popleft()
        call_targets = callees_by_source.get(source, set())
        callees.update(call_targets)
        for target in sorted(normal_edges.get(source, set()) | call_targets):
            if target not in reached:
                reached.add(target)
                work.append(target)
    return reached, callees


def _canonical_direct_calls(
    *,
    by_id: Mapping[str, Mapping[str, Any]],
    explicit_calls: Mapping[tuple[str, int], str],
) -> dict[tuple[str, int], str]:
    """Bind direct-call events to one exact decoded unit.

    The event's decoded target is authoritative.  A separately generated edge
    may confirm that binding, but cannot redirect it or make an ambiguous RVA
    usable.  This keeps summary discovery independent of redundant edge
    inventories while failing closed on disagreements.
    """

    units_by_rva: dict[int, list[str]] = defaultdict(list)
    for unit_id, unit in by_id.items():
        source = _mapping(_mapping(unit.get("source")).get("original"))
        rva = _integer(source.get("rva_start"))
        if rva is not None:
            units_by_rva[rva].append(unit_id)

    resolved: dict[tuple[str, int], str] = {}
    semantic_sites: set[tuple[str, int]] = set()
    for unit_id, unit in by_id.items():
        for event_index, event in enumerate(_events(unit)):
            if event.get("kind") != "internal_call":
                continue
            site = (unit_id, event_index)
            semantic_sites.add(site)
            target_rva = _integer(event.get("target_rva"))
            targets = units_by_rva.get(target_rva, []) if target_rva is not None else []
            if len(targets) != 1:
                continue
            target = targets[0]
            explicit = explicit_calls.get(site)
            if explicit is not None and explicit != target:
                continue
            resolved[site] = target

    # An edge without an exact internal-call event is not call authority.
    return {
        site: target
        for site, target in resolved.items()
        if site in semantic_sites
    }


def _summary_dependency_order(
    *,
    summary_roots: set[str],
    normal_edges: Mapping[str, set[str]],
    direct_calls: Mapping[tuple[str, int], str],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    max_units: int,
    opaque_roots: frozenset[str] = frozenset(),
) -> tuple[list[list[str]], set[str], set[str]]:
    """Return callee-first SCC order and explicit recursive frontiers."""

    opaque = set(opaque_roots) & summary_roots
    active_roots = summary_roots - opaque
    calls_by_source: dict[str, set[str]] = defaultdict(set)
    for (source, _), target in direct_calls.items():
        if target in active_roots:
            calls_by_source[source].add(target)
    for (source, _), recovery in recovered_calls.items():
        for target in recovery.get("target_unit_ids", []):
            if isinstance(target, str) and target in active_roots:
                calls_by_source[source].add(target)

    dependencies: dict[str, set[str]] = {
        root: set() for root in active_roots
    }
    inventory_incomplete: set[str] = set()
    for root in sorted(active_roots):
        reached = {root}
        work = deque([root])
        while work:
            source = work.popleft()
            dependencies[root].update(calls_by_source.get(source, set()))
            if len(reached) > max_units:
                inventory_incomplete.add(root)
                break
            for target in sorted(normal_edges.get(source, set())):
                if target not in reached:
                    reached.add(target)
                    work.append(target)

    components = _strongly_connected_components(dependencies)
    component_by_root = {
        root: index
        for index, component in enumerate(components)
        for root in component
    }
    component_dependencies: dict[int, set[int]] = defaultdict(set)
    recursive_roots: set[str] = set()
    for index, component in enumerate(components):
        if len(component) > 1 or any(
            root in dependencies[root] for root in component
        ):
            recursive_roots.update(component)
        for root in component:
            for dependency in dependencies[root]:
                dependency_index = component_by_root[dependency]
                if dependency_index != index:
                    component_dependencies[index].add(dependency_index)

    pending_dependencies = {
        index: len(component_dependencies.get(index, set()))
        for index in range(len(components))
    }
    dependents: dict[int, set[int]] = defaultdict(set)
    for index, dependencies_for_component in component_dependencies.items():
        for dependency in dependencies_for_component:
            dependents[dependency].add(index)
    ready = [
        index for index, count in pending_dependencies.items() if count == 0
    ]
    heapq.heapify(ready)
    ordered_indices: list[int] = []
    while ready:
        index = heapq.heappop(ready)
        ordered_indices.append(index)
        for dependent in sorted(dependents.get(index, set())):
            pending_dependencies[dependent] -= 1
            if pending_dependencies[dependent] == 0:
                heapq.heappush(ready, dependent)
    if len(ordered_indices) != len(components):
        raise AssertionError("SCC condensation graph must be acyclic")
    return (
        [[root] for root in sorted(opaque)]
        + [sorted(components[index]) for index in ordered_indices],
        recursive_roots,
        inventory_incomplete,
    )


def _strongly_connected_components(
    graph: Mapping[str, set[str]],
) -> list[list[str]]:
    visited: set[str] = set()
    finish_order: list[str] = []
    for node in sorted(graph):
        if node in visited:
            continue
        visited.add(node)
        stack: list[tuple[str, Iterable[str]]] = [
            (node, iter(sorted(graph.get(node, set()))))
        ]
        while stack:
            current, targets = stack[-1]
            try:
                target = next(targets)
            except StopIteration:
                stack.pop()
                finish_order.append(current)
                continue
            if target in visited:
                continue
            visited.add(target)
            stack.append((target, iter(sorted(graph.get(target, set())))))

    reverse_graph: dict[str, set[str]] = defaultdict(set)
    for source, targets in graph.items():
        for target in targets:
            reverse_graph[target].add(source)
    components: list[list[str]] = []
    assigned: set[str] = set()
    for node in reversed(finish_order):
        if node in assigned:
            continue
        component: list[str] = []
        assigned.add(node)
        stack = [(node, False)]
        while stack:
            current, _ = stack.pop()
            component.append(current)
            for source in sorted(reverse_graph.get(current, set()), reverse=True):
                if source not in assigned:
                    assigned.add(source)
                    stack.append((source, False))
        components.append(component)
    return components


def _force_incomplete(
    summary: dict[str, Any], blocker_codes: set[str]
) -> dict[str, Any]:
    if not blocker_codes:
        return summary
    result = copy.deepcopy(summary)
    result["status"] = "incomplete"
    result["preserved_registers"] = []
    result["register_preservation"] = {"status": "incomplete"}
    result["result_register_origins"] = {
        "status": "incomplete",
        "registers": {},
    }
    result["return_behavior"] = {
        "status": "incomplete",
        "may_return": None,
        "may_not_return": None,
    }
    for family in ("memory_effects", "callback_effects", "world_effects"):
        existing = _mapping(result.get(family))
        result[family] = {**dict(existing), "status": "incomplete"}
    result["blocker_codes"] = sorted(
        set(result.get("blocker_codes", [])) | blocker_codes
    )
    return result


def _recursive_seed_summary() -> dict[str, Any]:
    """Initial inductive hypothesis for one recursive summary root.

    A recursive edge is conservatively considered capable of nontermination.
    Returning behavior starts false and can only be discovered from concrete
    base paths.  Register and stack facts are therefore never assumed on a
    returning path before such a path exists.
    """

    return {
        "status": "complete",
        "preserved_registers": [],
        "register_preservation": {"status": "complete"},
        "result_register_origins": {"status": "complete", "registers": {}},
        "stack_cleanup": {"status": "not_applicable", "stack_delta": None},
        "return_behavior": {
            "status": "complete",
            "may_return": False,
            "may_not_return": True,
        },
        "memory_effects": {"status": "incomplete", "local_sites": []},
        "callback_effects": {"status": "incomplete", "sites": []},
        "world_effects": {"status": "incomplete", "external_sites": []},
        "target_dependencies": [],
        "reached_units": 0,
        "transfer_evaluations": 0,
        "return_nodes": 0,
        "return_unit_ids": [],
        "nonreturning_nodes": 1,
        "blocker_codes": [],
    }


def _analyze_recursive_component(
    *,
    component: Sequence[str],
    by_id: Mapping[str, Mapping[str, Any]],
    normal_edges: Mapping[str, set[str]],
    unresolved_direct_sources: set[str],
    unresolved_jump_sources: set[str],
    direct_calls: Mapping[tuple[str, int], str],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    completed_summaries: Mapping[str, Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    max_units: int,
    max_stack_words: int,
    max_rounds: int,
) -> tuple[dict[str, dict[str, Any]], int, bool]:
    """Establish one simultaneous inductive summary for a recursive SCC."""

    current = {root: _recursive_seed_summary() for root in component}
    for round_index in range(1, max_rounds + 1):
        assumptions = {**completed_summaries, **current}
        proposed: dict[str, dict[str, Any]] = {}
        for root in sorted(component):
            summary = _analyze_callee(
                root=root,
                by_id=by_id,
                normal_edges=normal_edges,
                unresolved_direct_sources=unresolved_direct_sources,
                unresolved_jump_sources=unresolved_jump_sources,
                direct_calls=direct_calls,
                recovered_calls=recovered_calls,
                summaries=assumptions,
                import_abis=import_abis,
                max_units=max_units,
                max_stack_words=max_stack_words,
            )
            summary["recursive_induction"] = {
                "status": "checked_fixed_point_candidate",
                "component_roots": sorted(component),
                "round": round_index,
                "base_returns": list(summary.get("return_unit_ids", [])),
            }
            proposed[root] = summary
        if _recursive_summary_projection(proposed) == _recursive_summary_projection(current):
            for summary in proposed.values():
                summary["recursive_induction"]["status"] = "complete"
                summary["recursive_induction"]["rounds"] = round_index
            return proposed, round_index, True
        current = proposed

    return (
        {
            root: _force_incomplete(
                summary,
                {"recursive_summary_fixed_point_incomplete"},
            )
            for root, summary in current.items()
        },
        max_rounds,
        False,
    )


def _recursive_summary_projection(
    summaries: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Return exactly the facts consumed across a recursive call boundary."""

    return {
        root: {
            "status": summary.get("status"),
            "preserved_registers": summary.get("preserved_registers"),
            "register_preservation": summary.get("register_preservation"),
            "result_register_origins": summary.get("result_register_origins"),
            "stack_cleanup": summary.get("stack_cleanup"),
            "return_behavior": summary.get("return_behavior"),
            "memory_effects": summary.get("memory_effects"),
            "callback_effects": summary.get("callback_effects"),
            "world_effects": summary.get("world_effects"),
            "target_dependencies": summary.get("target_dependencies"),
            "blocker_codes": summary.get("blocker_codes"),
        }
        for root, summary in sorted(summaries.items())
    }


def _analyze_callee(
    *,
    root: str,
    by_id: Mapping[str, Mapping[str, Any]],
    normal_edges: Mapping[str, set[str]],
    unresolved_direct_sources: set[str],
    unresolved_jump_sources: set[str],
    direct_calls: Mapping[tuple[str, int], str],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    summaries: Mapping[str, Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    max_units: int,
    max_stack_words: int,
) -> dict[str, Any]:
    initial = _State(
        registers={
            register: (
                _StackAddress(0)
                if register == "esp"
                else _RegisterOrigin(register)
            )
            for register in _REGISTERS
        },
        stack_words={},
    )
    states = {root: initial}
    work = deque([root])
    return_states: list[_State] = []
    return_unit_ids: set[str] = set()
    nonreturning_nodes: set[str] = set()
    blockers: set[str] = set()
    evaluations = 0
    while work:
        unit_id = work.popleft()
        evaluations += 1
        if len(states) > max_units or evaluations > max_units * 16:
            blockers.add("callee_summary_budget_exceeded")
            break
        unit = by_id[unit_id]
        successors = normal_edges.get(unit_id, set())
        if _has_checked_terminating_disposition(unit):
            if successors:
                blockers.add("terminating_control_has_successors")
            else:
                nonreturning_nodes.add(unit_id)
            continue
        call_frame = _unit_call_frame(
            unit_id=unit_id,
            unit=unit,
            direct_calls=direct_calls,
            recovered_calls=recovered_calls,
            summaries=summaries,
            import_abis=import_abis,
        )
        if call_frame is not None:
            blockers.update(call_frame.blocker_codes)
            if call_frame.may_not_return is True:
                nonreturning_nodes.add(unit_id)
            if not call_frame.behavior_complete:
                blockers.add("call_return_behavior_incomplete")
            elif call_frame.may_return is False:
                continue
        output, transfer_blockers = _transfer(
            unit_id=unit_id,
            unit=unit,
            state=states[unit_id],
            direct_calls=direct_calls,
            recovered_calls=recovered_calls,
            summaries=summaries,
            import_abis=import_abis,
            max_stack_words=max_stack_words,
        )
        blockers.update(transfer_blockers)
        kind = _mapping(_mapping(unit.get("semantics")).get("outcome")).get("kind")
        if kind == "return":
            return_states.append(output)
            return_unit_ids.add(unit_id)
            continue
        if unit_id in unresolved_direct_sources:
            blockers.add("unresolved_direct_control")
        if unit_id in unresolved_jump_sources:
            blockers.add("unresolved_indirect_jump")
        if not successors:
            tail_return = _external_tail_return_state(
                unit=unit,
                output=output,
                import_abis=import_abis,
            )
            if tail_return is not None:
                return_states.append(tail_return)
                return_unit_ids.add(unit_id)
            elif kind in _TERMINAL_KINDS:
                nonreturning_nodes.add(unit_id)
            else:
                blockers.add("unterminated_control_path")
            continue
        for target in sorted(successors):
            prior = states.get(target)
            joined = copy.deepcopy(output) if prior is None else _join_states(prior, output)
            if prior != joined:
                states[target] = joined
                work.append(target)

    if not return_states and not nonreturning_nodes:
        blockers.add("return_inventory_empty")
    preserved = sorted(
        register
        for register in _SUMMARY_REGISTERS
        if return_states
        and all(
            state.registers.get(register) == _RegisterOrigin(register)
            for state in return_states
        )
    )
    control_complete = not {
        "callee_summary_budget_exceeded",
        "call_return_behavior_incomplete",
        "internal_call_target_unresolved",
        "nested_call_return_behavior_incomplete",
        "indirect_call_target_unresolved",
        "indirect_call_target_inventory_invalid",
        "indirect_call_return_behavior_incomplete",
        "external_call_abi_unresolved",
        "unresolved_direct_control",
        "unresolved_indirect_jump",
        "unterminated_control_path",
        "return_inventory_empty",
        "terminating_control_has_successors",
        "multiple_calls_in_unit",
        "register_write_inventory_invalid",
    } & blockers
    return_esp_values = {state.registers.get("esp") for state in return_states}
    exact_return_esp = (
        next(iter(return_esp_values)) if len(return_esp_values) == 1 else None
    )
    return_stack_offsets = sorted(
        value.offset
        for value in return_esp_values
        if isinstance(value, _StackAddress)
    )
    if not return_states:
        stack_cleanup = {"status": "not_applicable", "stack_delta": None}
        stack_complete = True
    elif (
        isinstance(exact_return_esp, _StackAddress)
        and exact_return_esp.offset >= 4
    ):
        transform = _StackTransform(
            exact_return_esp.offset - 4,
            exact_return_esp.register_terms,
        )
        stack_cleanup = {
            "status": "complete",
            "stack_delta": (
                transform.constant if not transform.register_terms else None
            ),
            "return_stack_offset": (
                exact_return_esp.offset
                if not exact_return_esp.register_terms
                else None
            ),
        }
        if transform.register_terms:
            stack_cleanup["transform"] = _stack_transform_json(transform)
        stack_complete = True
    else:
        if len(return_stack_offsets) > 1:
            blockers.add("inconsistent_return_stack_delta")
        elif return_stack_offsets and return_stack_offsets[0] < 4:
            blockers.add("invalid_return_stack_delta")
        else:
            blockers.add("return_stack_delta_unknown")
        stack_cleanup = {
            "status": "incomplete",
            "stack_delta": None,
            "return_stack_offsets": return_stack_offsets,
        }
        stack_complete = False
    summary_complete = control_complete and stack_complete
    result_registers: dict[str, dict[str, Any]] = {}
    if control_complete and return_states:
        for register in _REGISTERS:
            values = {state.registers.get(register) for state in return_states}
            if len(values) != 1:
                continue
            value = next(iter(values))
            serialized = _serialize_summary_value(value)
            if serialized is not None:
                result_registers[register] = serialized
    effect_families = _summary_effect_families(
        reached_unit_ids=states,
        by_id=by_id,
        direct_calls=direct_calls,
        recovered_calls=recovered_calls,
        complete=control_complete,
    )
    return {
        "status": "complete" if summary_complete else "incomplete",
        "preserved_registers": preserved if control_complete else [],
        "register_preservation": {
            "status": "complete" if control_complete else "incomplete",
        },
        "result_register_origins": {
            "status": "complete" if control_complete else "incomplete",
            "registers": result_registers if control_complete else {},
        },
        "stack_cleanup": stack_cleanup,
        "return_behavior": {
            "status": "complete" if control_complete else "incomplete",
            "may_return": bool(return_states) if control_complete else None,
            "may_not_return": (
                bool(nonreturning_nodes) if control_complete else None
            ),
        },
        "reached_units": len(states),
        "transfer_evaluations": evaluations,
        "return_nodes": len(return_states),
        "return_unit_ids": sorted(return_unit_ids),
        "nonreturning_nodes": len(nonreturning_nodes),
        **effect_families,
        "blocker_codes": sorted(blockers),
    }


def _summary_effect_families(
    *,
    reached_unit_ids: Mapping[str, _State],
    by_id: Mapping[str, Mapping[str, Any]],
    direct_calls: Mapping[tuple[str, int], str],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    complete: bool,
) -> dict[str, Any]:
    """Inventory local effects and delegated call dependencies exactly once."""

    memory_sites: list[dict[str, Any]] = []
    external_sites: list[dict[str, Any]] = []
    callback_sites: list[dict[str, Any]] = []
    dependencies: set[str] = set()
    for unit_id in sorted(reached_unit_ids):
        semantics = _mapping(by_id[unit_id].get("semantics"))
        memory = semantics.get("memory_events", ())
        if isinstance(memory, Sequence) and not isinstance(memory, (str, bytes)):
            for event_index, event in enumerate(memory):
                if not isinstance(event, Mapping):
                    continue
                memory_sites.append({
                    "unit_id": unit_id,
                    "event_index": event_index,
                    "kind": event.get("kind"),
                    "width": event.get("width"),
                    "event_sha256": _summary_event_sha256(event),
                })
        for event_index, event in enumerate(_events(by_id[unit_id])):
            kind = event.get("kind")
            if kind == "internal_call":
                target = direct_calls.get((unit_id, event_index))
                if isinstance(target, str):
                    dependencies.add(f"call-summary:{target}")
            elif kind == "indirect_call":
                recovery = recovered_calls.get((unit_id, event_index))
                if isinstance(recovery, Mapping):
                    identity = recovery.get("id")
                    if isinstance(identity, str):
                        dependencies.add(identity)
                    dependencies.update(
                        f"call-summary:{target}"
                        for target in recovery.get("target_unit_ids", ())
                        if isinstance(target, str)
                    )
            if kind in {"external_call", "indirect_call"}:
                site = {
                    "unit_id": unit_id,
                    "event_index": event_index,
                    "kind": kind,
                    "event_sha256": _summary_event_sha256(event),
                }
                external_sites.append(site)
                if any(
                    key in event
                    for key in (
                        "callback_contract",
                        "callback_adapter",
                        "callback_registration",
                    )
                ):
                    callback_sites.append(site)
    status = "complete" if complete else "incomplete"
    return {
        "memory_effects": {
            "status": status,
            "local_sites": memory_sites,
            "delegated_dependencies": sorted(dependencies),
        },
        "callback_effects": {
            "status": status,
            "sites": callback_sites,
            "delegated_dependencies": sorted(dependencies),
        },
        "world_effects": {
            "status": status,
            "external_sites": external_sites,
            "delegated_dependencies": sorted(dependencies),
        },
        "target_dependencies": sorted(dependencies),
    }


def _summary_event_sha256(event: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _has_checked_terminating_disposition(unit: Mapping[str, Any]) -> bool:
    disposition = _mapping(_mapping(unit.get("control")).get("disposition"))
    return disposition == _TERMINATING_DISPOSITION and any(
        event.get("kind") == "external_call" for event in _events(unit)
    )


def _unit_call_frame(
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    direct_calls: Mapping[tuple[str, int], str],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    summaries: Mapping[str, Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    input_registers: Mapping[str, _Value] | None = None,
) -> _CallFrame | None:
    events = _events(unit)
    calls = [
        (index, event)
        for index, event in enumerate(events)
        if event.get("kind") in _CALL_KINDS
    ]
    if not calls:
        return None
    if len(calls) != 1:
        return _CallFrame(
            behavior_complete=False,
            may_return=None,
            may_not_return=None,
            preserved_registers=frozenset(),
            stack_cleanup=None,
            result_registers={},
            blocker_codes=frozenset({"multiple_calls_in_unit"}),
        )
    event_index, event = calls[0]
    kind = event.get("kind")
    if kind == "external_call":
        identity = _event_import_identity(event)
        selected = import_abis.get(identity) if identity is not None else None
        if selected is None:
            return _incomplete_call_frame("external_call_abi_unresolved")
        return _returning_abi_frame(
            preserved_registers=selected.abi.preserved_registers,
            stack_cleanup=_selected_import_stack_cleanup(selected),
            result_registers=_selected_import_result_registers(
                selected, unit_id=unit_id, event_index=event_index
            ),
        )
    if kind == "internal_call":
        target = direct_calls.get((unit_id, event_index))
        if target is None:
            return _incomplete_call_frame("internal_call_target_unresolved")
        return _summary_call_frame(
            summaries.get(target), input_registers=input_registers
        )
    if kind != "indirect_call":
        return _incomplete_call_frame("call_kind_unsupported")
    recovery = recovered_calls.get((unit_id, event_index))
    if recovery is None:
        return _incomplete_call_frame("indirect_call_target_unresolved")
    return _recovered_indirect_call_frame(
        recovery=recovery,
        summaries=summaries,
        import_abis=import_abis,
        input_registers=input_registers,
    )


def _summary_call_frame(
    summary: Mapping[str, Any] | None,
    *,
    input_registers: Mapping[str, _Value] | None = None,
) -> _CallFrame:
    if summary is None:
        return _incomplete_call_frame("nested_call_summary_unavailable")
    behavior = _mapping(summary.get("return_behavior"))
    may_return = behavior.get("may_return")
    may_not_return = behavior.get("may_not_return")
    if (
        behavior.get("status") != "complete"
        or not isinstance(may_return, bool)
        or not isinstance(may_not_return, bool)
        or not (may_return or may_not_return)
    ):
        return _incomplete_call_frame("nested_call_return_behavior_incomplete")
    stack_cleanup = _summary_stack_cleanup(summary) if may_return else None
    return _CallFrame(
        behavior_complete=True,
        may_return=may_return,
        may_not_return=may_not_return,
        preserved_registers=_summary_preserved(summary) if may_return else frozenset(),
        stack_cleanup=stack_cleanup,
        result_registers=(
            _summary_result_registers(
                summary, input_registers=input_registers
            )
            if may_return
            else {}
        ),
    )


def _recovered_indirect_call_frame(
    *,
    recovery: Mapping[str, Any],
    summaries: Mapping[str, Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    input_registers: Mapping[str, _Value] | None = None,
) -> _CallFrame:
    raw_external = recovery.get("external_targets", [])
    raw_internal = recovery.get("target_unit_ids", [])
    if (
        not isinstance(raw_external, Sequence)
        or isinstance(raw_external, (str, bytes))
        or not isinstance(raw_internal, Sequence)
        or isinstance(raw_internal, (str, bytes))
    ):
        return _incomplete_call_frame("indirect_call_target_inventory_invalid")

    alternatives: list[_CallFrame] = []
    for raw in raw_external:
        external = _mapping(raw)
        protocol = _mapping(external.get("external_protocol"))
        if protocol:
            raw_abi = _mapping(external.get("abi"))
            abi = resolve_machine_call_abi(raw_abi.get("template"))
            words = _integer(external.get("argument_words"))
            if (
                abi is None
                or raw_abi != abi.as_json()
                or words is None
                or words < 0
            ):
                alternatives.append(
                    _incomplete_call_frame("indirect_call_external_abi_incomplete")
                )
            else:
                alternatives.append(_returning_abi_frame(
                    preserved_registers=abi.preserved_registers,
                    stack_cleanup=words * 4 if abi.callee_cleanup else 0,
                ))
            continue
        identity = _event_import_identity(_mapping(external.get("import")))
        selected = import_abis.get(identity) if identity is not None else None
        if selected is None:
            alternatives.append(
                _incomplete_call_frame("indirect_call_external_abi_incomplete")
            )
        else:
            alternatives.append(_returning_abi_frame(
                preserved_registers=selected.abi.preserved_registers,
                stack_cleanup=_selected_import_stack_cleanup(selected),
            ))
    for raw_target in raw_internal:
        if not isinstance(raw_target, str):
            alternatives.append(
                _incomplete_call_frame("indirect_call_target_inventory_invalid")
            )
        else:
            alternatives.append(_summary_call_frame(
                summaries.get(raw_target), input_registers=input_registers
            ))
    if not alternatives:
        return _incomplete_call_frame("indirect_call_target_inventory_invalid")

    blockers = frozenset().union(
        *(alternative.blocker_codes for alternative in alternatives)
    )
    if not all(alternative.behavior_complete for alternative in alternatives):
        return _CallFrame(
            behavior_complete=False,
            may_return=None,
            may_not_return=None,
            preserved_registers=frozenset(),
            stack_cleanup=None,
            result_registers={},
            blocker_codes=blockers | {"indirect_call_return_behavior_incomplete"},
        )
    returning = [
        alternative for alternative in alternatives
        if alternative.may_return is True
    ]
    preserved = set(returning[0].preserved_registers) if returning else set()
    for alternative in returning[1:]:
        preserved &= alternative.preserved_registers
    cleanups = {alternative.stack_cleanup for alternative in returning}
    stack_cleanup = next(iter(cleanups)) if len(cleanups) == 1 else None
    result_registers = _common_call_results(returning)
    return _CallFrame(
        behavior_complete=True,
        may_return=bool(returning),
        may_not_return=any(
            alternative.may_not_return is True for alternative in alternatives
        ),
        preserved_registers=frozenset(preserved),
        stack_cleanup=stack_cleanup,
        result_registers=result_registers,
        blocker_codes=blockers,
    )


def _returning_abi_frame(
    *,
    preserved_registers: Iterable[str],
    stack_cleanup: int | None,
    result_registers: Mapping[str, _Value] | None = None,
) -> _CallFrame:
    return _CallFrame(
        behavior_complete=True,
        may_return=True,
        may_not_return=False,
        preserved_registers=frozenset(
            register for register in preserved_registers if register in _REGISTERS
        ),
        stack_cleanup=(
            None if stack_cleanup is None else _StackTransform(stack_cleanup)
        ),
        result_registers=dict(result_registers or {}),
    )


def _incomplete_call_frame(code: str) -> _CallFrame:
    return _CallFrame(
        behavior_complete=False,
        may_return=None,
        may_not_return=None,
        preserved_registers=frozenset(),
        stack_cleanup=None,
        result_registers={},
        blocker_codes=frozenset({code}),
    )


def _external_tail_return_state(
    *,
    unit: Mapping[str, Any],
    output: _State,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
) -> _State | None:
    outcome = _mapping(_mapping(unit.get("semantics")).get("outcome"))
    if outcome.get("kind") != "external_jump":
        return None
    events = _events(unit)
    if len(events) != 1 or events[0].get("kind") != "external_call":
        return None
    event_identity = _event_import_identity(events[0])
    if (
        event_identity is None
        or event_identity != _event_import_identity(outcome)
        or event_identity not in import_abis
    ):
        return None
    registers = dict(output.registers)
    registers["esp"] = _add_stack_cleanup(
        registers.get("esp"), _StackTransform(4), registers
    )
    return _State(registers=registers, stack_words=dict(output.stack_words))


def _transfer(
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    state: _State,
    direct_calls: Mapping[tuple[str, int], str],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    summaries: Mapping[str, Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    max_stack_words: int,
) -> tuple[_State, set[str]]:
    events = _events(unit)
    calls = [
        (index, event)
        for index, event in enumerate(events)
        if event.get("kind") in _CALL_KINDS
    ]
    if calls:
        event_index, event = calls[0]
        pre_call = _event_state(event, state)
        frame = _unit_call_frame(
            unit_id=unit_id,
            unit=unit,
            direct_calls=direct_calls,
            recovered_calls=recovered_calls,
            summaries=summaries,
            import_abis=import_abis,
            input_registers=pre_call.registers,
        )
        if frame is None:
            return _unknown_state(), {"call_inventory_missing"}
        output_registers = {
            register: (
                pre_call.registers.get(register)
                if register in frame.preserved_registers
                else None
            )
            for register in _REGISTERS
        }
        output_registers.update(frame.result_registers)
        output_registers["esp"] = _add_stack_cleanup(
            pre_call.registers.get("esp"),
            frame.stack_cleanup,
            pre_call.registers,
        )
        output_registers["esp"], stack_blockers = _compose_semantic_stack_delta(
            input_esp=state.registers.get("esp"),
            evaluated_esp=output_registers["esp"],
            semantics=_mapping(unit.get("semantics")),
        )
        return (
            _State(
                registers=output_registers,
                stack_words=_stack_words_preserved_across_call(
                    event=event,
                    pre_call=pre_call,
                ),
            ),
            set(frame.blocker_codes) | stack_blockers,
        )

    semantics = _mapping(unit.get("semantics"))
    writes = semantics.get("register_writes")
    if not isinstance(writes, list):
        return _unknown_state(), {"register_write_inventory_invalid"}
    registers = dict(state.registers)
    for raw in writes:
        write = _mapping(raw)
        register = write.get("register")
        if isinstance(register, str) and register in registers:
            registers[register] = _evaluate(write.get("value"), state)
    registers["esp"], stack_blockers = _compose_semantic_stack_delta(
        input_esp=state.registers.get("esp"),
        evaluated_esp=registers.get("esp"),
        semantics=semantics,
    )

    stack_words = dict(state.stack_words)
    memory_events = semantics.get("memory_events")
    if not isinstance(memory_events, list):
        stack_words.clear()
    else:
        for raw in memory_events:
            event = _mapping(raw)
            if event.get("kind") != "write":
                continue
            address = _evaluate(event.get("address"), state)
            width = _integer(event.get("width"))
            if (
                isinstance(address, _StackAddress)
                and not address.register_terms
                and width is not None
            ):
                _invalidate_overlapping(stack_words, address.offset, width)
                value = _evaluate(event.get("value"), state)
                if width == 4 and value is not None:
                    stack_words[address.offset] = value
            elif not isinstance(address, _Exact):
                stack_words.clear()
    schedule = _mapping(semantics.get("instruction_effect_schedule"))
    blockers = schedule.get("blockers")
    if isinstance(blockers, list):
        instructions = unit.get("instructions")
        for raw in blockers:
            blocker = _mapping(raw)
            index = _integer(blocker.get("index"))
            if (
                index is None
                or not isinstance(instructions, list)
                or not 0 <= index < len(instructions)
            ):
                registers = {register: None for register in _REGISTERS}
                stack_words.clear()
                continue
            instruction = _mapping(instructions[index])
            written = instruction.get("registers_written")
            if isinstance(written, list):
                for register in written:
                    if isinstance(register, str) and register in registers:
                        registers[register] = None
            operands = instruction.get("operands")
            if isinstance(operands, list) and any(
                isinstance(operand, Mapping)
                and operand.get("kind") == "memory"
                and operand.get("access") in {"write", "read_write"}
                for operand in operands
            ):
                stack_words.clear()
    if len(stack_words) > max_stack_words:
        stack_words.clear()
    return _State(registers=registers, stack_words=stack_words), stack_blockers


def _summary_preserved(summary: Mapping[str, Any] | None) -> frozenset[str]:
    if summary is None:
        return frozenset()
    preservation = _mapping(summary.get("register_preservation"))
    if preservation:
        if preservation.get("status") != "complete":
            return frozenset()
    elif summary.get("status") != "complete":
        return frozenset()
    raw = summary.get("preserved_registers")
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(str(register) for register in raw if register in _SUMMARY_REGISTERS)


def _selected_import_stack_cleanup(selected: SelectedImportABI | None) -> int | None:
    if selected is None:
        return None
    if not selected.abi.callee_cleanup:
        return 0
    if selected.argument_words is None:
        return None
    return selected.argument_words * 4


def _summary_stack_cleanup(
    summary: Mapping[str, Any] | None,
) -> _StackTransform | None:
    if summary is None:
        return None
    cleanup = _mapping(summary.get("stack_cleanup"))
    if cleanup.get("status") != "complete":
        return None
    transform = _mapping(cleanup.get("transform"))
    if transform:
        constant = _integer(transform.get("constant"))
        raw_terms = transform.get("register_terms")
        if constant is None or not isinstance(raw_terms, list):
            return None
        terms: list[tuple[str, int]] = []
        for raw in raw_terms:
            row = _mapping(raw)
            register = row.get("register")
            coefficient = _integer(row.get("coefficient"))
            if (
                register not in _REGISTERS
                or coefficient is None
                or coefficient == 0
            ):
                return None
            terms.append((str(register), coefficient))
        return _StackTransform(constant, _normalize_register_terms(terms))
    value = _integer(cleanup.get("stack_delta"))
    return None if value is None else _StackTransform(value)


def _selected_import_result_registers(
    selected: SelectedImportABI,
    *,
    unit_id: str,
    event_index: int,
) -> dict[str, _Value]:
    contract = selected.contract
    if not isinstance(contract, Mapping):
        return {}
    raw_relations = contract.get("result_register_relations")
    if not isinstance(raw_relations, list):
        return {}
    result: dict[str, _Value] = {}
    for raw in raw_relations:
        relation = _mapping(raw)
        register = relation.get("register")
        kind = relation.get("relation")
        if (
            register not in _REGISTERS
            or kind != "dynamic_range_base"
            or not isinstance(relation.get("nullable"), bool)
        ):
            continue
        result[str(register)] = _ExternalResult(
            producer_unit_id=unit_id,
            event_index=event_index,
            dll=selected.identity.dll,
            identity_kind=selected.identity.kind,
            identity_value=selected.identity.value,
            relation=str(kind),
            nullable=bool(relation["nullable"]),
        )
    return result


def _serialize_summary_value(value: _Value) -> dict[str, Any] | None:
    if isinstance(value, _RegisterOrigin):
        return {"kind": "input_register", "register": value.register}
    if isinstance(value, _StackAddress):
        return {
            "kind": "stack_address",
            "offset": value.offset,
            "register_terms": _register_terms_json(value.register_terms),
        }
    if isinstance(value, _Exact):
        return {"kind": "exact", "value": value.value & 0xFFFFFFFF}
    if isinstance(value, _ExternalResult):
        return {
            "kind": "external_result",
            "producer_unit_id": value.producer_unit_id,
            "event_index": value.event_index,
            "import": {
                "dll": value.dll,
                value.identity_kind: value.identity_value,
            },
            "relation": value.relation,
            "nullable": value.nullable,
        }
    if isinstance(value, _InternalContractResult):
        return {
            "kind": "internal_contract_result",
            "contract_id": value.contract_id,
            "relation": value.relation,
            "nullable": value.nullable,
        }
    return None


def _parse_summary_value(value: Any) -> _Value:
    row = _mapping(value)
    kind = row.get("kind")
    if kind == "input_register" and row.get("register") in _REGISTERS:
        return _RegisterOrigin(str(row["register"]))
    if kind == "stack_address":
        offset = _integer(row.get("offset"))
        raw_terms = row.get("register_terms", [])
        if offset is None or not isinstance(raw_terms, list):
            return None
        terms: list[tuple[str, int]] = []
        for raw in raw_terms:
            term = _mapping(raw)
            register = term.get("register")
            coefficient = _integer(term.get("coefficient"))
            if register not in _REGISTERS or coefficient in {None, 0}:
                return None
            terms.append((str(register), int(coefficient)))
        return _StackAddress(offset, _normalize_register_terms(terms))
    if kind == "exact":
        exact = _integer(row.get("value"))
        return None if exact is None else _Exact(exact & 0xFFFFFFFF)
    if kind == "internal_contract_result":
        contract_id = row.get("contract_id")
        relation = row.get("relation")
        nullable = row.get("nullable")
        if (
            not isinstance(contract_id, str)
            or not contract_id
            or relation != "dynamic_range_base"
            or not isinstance(nullable, bool)
        ):
            return None
        return _InternalContractResult(contract_id, str(relation), nullable)
    if kind != "external_result":
        return None
    imported = _mapping(row.get("import"))
    identity = MachineImportIdentity.from_mapping(
        imported, context="internal result origin"
    )
    event_index = _integer(row.get("event_index"))
    producer = row.get("producer_unit_id")
    relation = row.get("relation")
    nullable = row.get("nullable")
    if (
        event_index is None
        or not isinstance(producer, str)
        or relation != "dynamic_range_base"
        or not isinstance(nullable, bool)
    ):
        return None
    return _ExternalResult(
        producer_unit_id=producer,
        event_index=event_index,
        dll=identity.dll,
        identity_kind=identity.kind,
        identity_value=identity.value,
        relation=str(relation),
        nullable=nullable,
    )


def _summary_result_registers(
    summary: Mapping[str, Any] | None,
    *,
    input_registers: Mapping[str, _Value] | None = None,
) -> dict[str, _Value]:
    if summary is None:
        return {}
    inventory = _mapping(summary.get("result_register_origins"))
    if inventory.get("status") != "complete":
        return {}
    registers = _mapping(inventory.get("registers"))
    result: dict[str, _Value] = {}
    for register, raw in registers.items():
        if register not in _REGISTERS:
            continue
        value = _instantiate_summary_value(
            raw, input_registers=input_registers
        )
        if value is not None:
            result[register] = value
    return result


def _instantiate_summary_value(
    raw: Any,
    *,
    input_registers: Mapping[str, _Value] | None,
) -> _Value:
    """Instantiate one callee-input-relative result at a concrete call site."""

    row = _mapping(raw)
    kind = row.get("kind")
    if kind == "input_register":
        source = row.get("register")
        return (
            input_registers.get(str(source))
            if input_registers is not None and source in _REGISTERS
            else None
        )
    if kind == "stack_address":
        if input_registers is None:
            return None
        offset = _integer(row.get("offset"))
        raw_terms = row.get("register_terms", [])
        if offset is None or not isinstance(raw_terms, list):
            return None
        terms: list[tuple[str, int]] = []
        for raw_term in raw_terms:
            term = _mapping(raw_term)
            register = term.get("register")
            coefficient = _integer(term.get("coefficient"))
            if register not in _REGISTERS or coefficient in {None, 0}:
                return None
            terms.append((str(register), int(coefficient)))
        # A machine CALL pushes a four-byte return address after the event's
        # pre-call register state.  Summary offset zero denotes callee-entry
        # ESP, hence the caller-relative constant is offset - 4.
        return _add_stack_cleanup(
            input_registers.get("esp"),
            _StackTransform(offset - 4, _normalize_register_terms(terms)),
            input_registers,
        )
    return _parse_summary_value(raw)


def _common_call_results(alternatives: Sequence[_CallFrame]) -> dict[str, _Value]:
    if not alternatives:
        return {}
    common = dict(alternatives[0].result_registers)
    for alternative in alternatives[1:]:
        common = {
            register: value
            for register, value in common.items()
            if alternative.result_registers.get(register) == value
        }
    return common


def _add_stack_cleanup(
    value: _Value,
    cleanup: _StackTransform | None,
    registers: Mapping[str, _Value],
) -> _Value:
    if not isinstance(value, _StackAddress) or cleanup is None:
        return None
    constant = value.offset + cleanup.constant
    terms = list(value.register_terms)
    for register, coefficient in cleanup.register_terms:
        register_value = registers.get(register)
        if isinstance(register_value, _Exact):
            constant += coefficient * register_value.value
        elif isinstance(register_value, _RegisterOrigin):
            terms.append((register_value.register, coefficient))
        else:
            return None
    return _StackAddress(constant, _normalize_register_terms(terms))


def _compose_semantic_stack_delta(
    *,
    input_esp: _Value,
    evaluated_esp: _Value,
    semantics: Mapping[str, Any],
) -> tuple[_Value, set[str]]:
    stack_delta = _mapping(semantics.get("stack_delta"))
    net_bytes = _integer(stack_delta.get("net_bytes"))
    if stack_delta.get("status") != "derived" or net_bytes is None:
        return evaluated_esp, set()

    composed_esp = _add_stack_cleanup(
        input_esp,
        _StackTransform(net_bytes),
        {},
    )
    if composed_esp is None:
        return evaluated_esp, set()
    if evaluated_esp is not None and evaluated_esp != composed_esp:
        return None, {"stack_delta_evidence_inconsistent"}
    return composed_esp, set()


def _event_state(event: Mapping[str, Any], state: _State) -> _State:
    raw = event.get("register_inputs")
    registers = (
        {
            register: _evaluate(raw.get(register), state)
            for register in _REGISTERS
        }
        if isinstance(raw, Mapping)
        else dict(state.registers)
    )
    return _State(registers=registers, stack_words=dict(state.stack_words))


def _stack_words_preserved_across_call(
    *, event: Mapping[str, Any], pre_call: _State
) -> dict[int, _Value]:
    """Retain caller spills outside the declared call argument frame.

    The summary remains fail-closed when a stack-derived pointer is exposed to
    the callee or when the call's stack inventory is malformed.  Ordinary
    calls may use their own lower stack frame and declared argument words, but
    cannot invalidate unrelated caller spills merely by crossing the boundary.
    """

    esp = pre_call.registers.get("esp")
    raw_stack_inputs = event.get("stack_inputs", [])
    if (
        not isinstance(esp, _StackAddress)
        or esp.register_terms
        or not isinstance(raw_stack_inputs, list)
    ):
        return {}

    argument_end = 0
    for raw in raw_stack_inputs:
        if not isinstance(raw, Mapping):
            return {}
        offset = _integer(raw.get("offset"))
        width = _integer(raw.get("width"))
        if offset is None or width is None or offset < 0 or width <= 0:
            return {}
        argument_end = max(argument_end, offset + width)
        evaluated = _evaluate(raw.get("value"), pre_call)
        if isinstance(evaluated, _StackAddress):
            return {}

    raw_registers = event.get("register_inputs")
    if isinstance(raw_registers, Mapping):
        for register, expression in raw_registers.items():
            if str(register).lower() == "esp":
                continue
            if isinstance(_evaluate(expression, pre_call), _StackAddress):
                return {}
    elif raw_registers is not None:
        return {}

    protected_floor = esp.offset + argument_end
    return {
        offset: value
        for offset, value in pre_call.stack_words.items()
        if offset >= protected_floor
    }


def _evaluate(expression: Any, state: _State) -> _Value:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op") or "").lower()
    if op in {"reg", "input_reg", "register"}:
        name = expression.get("name", expression.get("reg"))
        return state.registers.get(str(name).lower()) if name is not None else None
    if op in {"const", "constant"}:
        value = _integer(expression.get("value"))
        return _Exact(value & 0xFFFFFFFF) if value is not None else None
    if op in {"add", "add32", "sub", "sub32"}:
        operands = _binary_operands(expression)
        if operands is None:
            return None
        left = _evaluate(operands[0], state)
        right = _evaluate(operands[1], state)
        subtract = op in {"sub", "sub32"}
        if isinstance(left, _Exact) and isinstance(right, _Exact):
            value = left.value - right.value if subtract else left.value + right.value
            return _Exact(value & 0xFFFFFFFF)
        if isinstance(left, _StackAddress) and isinstance(right, _Exact):
            offset = left.offset - right.value if subtract else left.offset + right.value
            return _StackAddress(offset, left.register_terms)
        if isinstance(left, _StackAddress) and isinstance(right, _RegisterOrigin):
            coefficient = -1 if subtract else 1
            return _StackAddress(
                left.offset,
                _normalize_register_terms(
                    (*left.register_terms, (right.register, coefficient))
                ),
            )
        if not subtract and isinstance(left, _Exact) and isinstance(right, _StackAddress):
            return _StackAddress(
                left.value + right.offset,
                right.register_terms,
            )
        return None
    if op in {"load", "read32", "mem32"}:
        width = expression.get("width", expression.get("width_bits", 4))
        if width not in {4, 32, None}:
            return None
        address = _evaluate(expression.get("address"), state)
        return (
            state.stack_words.get(address.offset)
            if isinstance(address, _StackAddress) and not address.register_terms
            else None
        )
    return None


def _normalize_register_terms(
    terms: Iterable[tuple[str, int]],
) -> tuple[tuple[str, int], ...]:
    combined: dict[str, int] = defaultdict(int)
    for register, coefficient in terms:
        combined[register] += coefficient
    return tuple(
        (register, coefficient)
        for register, coefficient in sorted(combined.items())
        if coefficient
    )


def _register_terms_json(
    terms: Iterable[tuple[str, int]],
) -> list[dict[str, Any]]:
    return [
        {"register": register, "coefficient": coefficient}
        for register, coefficient in terms
    ]


def _stack_transform_json(transform: _StackTransform) -> dict[str, Any]:
    return {
        "format": "stage-a-affine-stack-transform-v1",
        "constant": transform.constant,
        "register_terms": _register_terms_json(transform.register_terms),
    }


def _join_states(left: _State, right: _State) -> _State:
    registers = {
        register: (
            left.registers.get(register)
            if left.registers.get(register) == right.registers.get(register)
            else None
        )
        for register in _REGISTERS
    }
    stack_words = {
        offset: value
        for offset, value in left.stack_words.items()
        if value is not None and right.stack_words.get(offset) == value
    }
    return _State(registers=registers, stack_words=stack_words)


def _unknown_state() -> _State:
    return _State(
        registers={register: None for register in _REGISTERS},
        stack_words={},
    )


def _invalidate_overlapping(
    stack_words: dict[int, _Value], start: int, width: int
) -> None:
    end = start + max(width, 0)
    for offset in list(stack_words):
        if offset < end and start < offset + 4:
            del stack_words[offset]


def _events(unit: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = _mapping(unit.get("semantics")).get("external_events")
    return [value for value in raw if isinstance(value, Mapping)] if isinstance(raw, list) else []


def _event_import_identity(event: Mapping[str, Any]) -> MachineImportIdentity | None:
    dll = event.get("dll")
    symbol = event.get("symbol")
    ordinal = _integer(event.get("ordinal"))
    if not isinstance(dll, str):
        return None
    if isinstance(symbol, str) and symbol:
        return MachineImportIdentity(dll.lower(), "symbol", symbol)
    if ordinal is not None:
        return MachineImportIdentity(dll.lower(), "ordinal", ordinal)
    return None


def _binary_operands(expression: Mapping[str, Any]) -> tuple[Any, Any] | None:
    arguments = expression.get("args")
    if (
        isinstance(arguments, Sequence)
        and not isinstance(arguments, (str, bytes))
        and len(arguments) == 2
    ):
        return arguments[0], arguments[1]
    if "left" in expression and "right" in expression:
        return expression["left"], expression["right"]
    return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


__all__ = [
    "INTERNAL_CALL_SUMMARY_FORMAT",
    "derive_internal_call_preservation_summaries",
]
