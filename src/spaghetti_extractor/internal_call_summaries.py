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
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Mapping, Sequence

from .call_site_effects import (
    CallSiteEffect,
    CallSiteId,
    CallWriteSpan,
    parse_call_site_effects,
)
from .authority_bindings_v2 import BinaryBinding
from .checked_memory_access_v2 import (
    PreparedMemoryAccessFact,
    validate_prepared_memory_access_facts_v2,
)
from .import_abi import SelectedImportABI
from .machine_abi import resolve_machine_call_abi
from .machine_import_profiles import MachineImportIdentity
from .provenance_domain import (
    ValueOrigin,
    origin_concrete_value,
    parse_value_origin,
)


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
class _InputStackWord:
    """One four-byte word from the callee-entry stack frame."""

    offset: int


@dataclass(frozen=True, order=True)
class _ParametricTerm:
    """One coefficient over a callee-entry input value."""

    source_kind: str
    source: str | int
    coefficient: int


@dataclass(frozen=True)
class _ParametricWord:
    """A 32-bit affine word over input registers and stack words."""

    constant: int
    terms: tuple[_ParametricTerm, ...]


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
    extent_lower_bound: int | None = None


@dataclass(frozen=True)
class _InternalContractResult:
    contract_id: str
    relation: str
    nullable: bool


@dataclass(frozen=True)
class _TypedOrigins:
    origins: tuple[ValueOrigin, ...]


_Value = (
    _RegisterOrigin
    | _InputStackWord
    | _ParametricWord
    | _StackAddress
    | _Exact
    | _ExternalResult
    | _InternalContractResult
    | _TypedOrigins
    | None
)


@dataclass
class _State:
    registers: dict[str, _Value]
    stack_words: dict[int, _Value]
    memory_words: dict[ValueOrigin, _Value] = field(default_factory=dict)
    input_stack_valid: bool = True
    input_stack_kills: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class _CallFrame:
    behavior_complete: bool
    may_return: bool | None
    may_not_return: bool | None
    register_frame_complete: bool
    preserved_registers: frozenset[str]
    stack_frame_complete: bool
    stack_cleanup: _StackTransform | None
    result_frame_complete: bool
    result_registers: Mapping[str, _Value]
    blocker_codes: frozenset[str] = frozenset()
    result_memory: Mapping[ValueOrigin, _Value] = field(default_factory=dict)
    memory_frame_complete: bool = False
    memory_preserved: bool = False
    memory_writes: tuple[CallWriteSpan, ...] = ()


@dataclass(frozen=True)
class _MemoryWriteFootprint:
    fact_id: str
    stack_offsets: tuple[int, ...]
    has_non_stack_alternative: bool


def derive_internal_call_preservation_summaries(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Iterable[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recovered_indirect_targets: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    call_site_effects: Sequence[Mapping[str, Any]] = (),
    prepared_memory_access_facts: Sequence[Mapping[str, Any]] = (),
    binary_binding: BinaryBinding | None = None,
    image_base: int | None = None,
    image_size: int | None = None,
    declared_summaries: Mapping[str, Mapping[str, Any]] | None = None,
    max_units_per_summary: int = 4096,
    max_stack_words: int = 256,
    max_memory_words: int = 256,
    max_fixed_point_rounds: int = 64,
    max_value_alternatives: int = 32,
) -> dict[str, Any]:
    """Propose frame/return facts for reachable callees and behavioral roots."""

    if min(
        max_units_per_summary,
        max_stack_words,
        max_memory_words,
        max_fixed_point_rounds,
        max_value_alternatives,
    ) <= 0:
        raise ValueError("internal call summary budgets must be positive")
    by_id = {str(unit["id"]): unit for unit in units}
    if len(by_id) != len(units):
        raise ValueError("internal call summaries require unique unit IDs")
    effects_by_site = parse_call_site_effects(
        call_site_effects,
        finite_value_budget=max_value_alternatives,
    )
    for site, effect in effects_by_site.items():
        unit = by_id.get(site.unit_id)
        events = _events(unit or {})
        if (
            unit is None
            or not 0 <= site.event_index < len(events)
            or events[site.event_index].get("kind") != effect.transfer_kind
        ):
            raise ValueError(
                "call-site effect does not bind an exact machine-IR call: "
                f"{site.unit_id}:{site.event_index}"
            )
    if prepared_memory_access_facts and binary_binding is None:
        raise ValueError(
            "prepared memory-access facts require an exact binary binding"
        )
    if prepared_memory_access_facts and (
        image_base is None
        or image_size is None
        or not _valid_image_range(image_base, image_size)
    ):
        raise ValueError(
            "prepared memory-access facts require a bounded PE image range"
        )
    prepared_by_event = (
        {}
        if binary_binding is None
        else validate_prepared_memory_access_facts_v2(
            prepared_memory_access_facts,
            units=units,
            binary=binary_binding,
        )
    )
    recovered_external_calls = _recovered_external_call_sites(
        recovered_indirect_targets,
        indirect_exits=indirect_exits,
        by_id=by_id,
    )
    write_footprints = _memory_write_footprints(
        prepared_by_event,
        by_id=by_id,
        recovered_external_calls=recovered_external_calls,
        import_abis=import_abis,
        image_base=image_base,
        image_size=image_size,
    )
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
    return_instruction_cleanups = {
        root: _derive_return_instruction_cleanup(
            root=root,
            by_id=by_id,
            normal_edges=normal_edges,
            unresolved_direct_sources=unresolved_direct_sources,
            unresolved_jump_sources=unresolved_jump_sources,
            max_units=max_units_per_summary,
        )
        for root in summary_roots
    }
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
        root: {
            **copy.deepcopy(dict(summary)),
            "return_instruction_cleanup": copy.deepcopy(
                return_instruction_cleanups[root]
            ),
        }
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
                    call_site_effects=effects_by_site,
                    memory_write_footprints=write_footprints,
                    return_instruction_cleanups=return_instruction_cleanups,
                    max_units=max_units_per_summary,
                    max_stack_words=max_stack_words,
                    max_memory_words=max_memory_words,
                    max_rounds=max_fixed_point_rounds,
                    max_value_alternatives=max_value_alternatives,
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
            call_site_effects=effects_by_site,
            memory_write_footprints=write_footprints,
            max_units=max_units_per_summary,
            max_stack_words=max_stack_words,
            max_memory_words=max_memory_words,
            max_value_alternatives=max_value_alternatives,
        )
        proposed["return_instruction_cleanup"] = copy.deepcopy(
            return_instruction_cleanups[root]
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
                "return_instruction_cleanup": copy.deepcopy(
                    return_instruction_cleanups[root]
                ),
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
            "max_memory_words": max_memory_words,
            "max_fixed_point_rounds": max_fixed_point_rounds,
            "max_value_alternatives": max_value_alternatives,
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
        dfs_stack: list[tuple[str, Iterator[str]]] = [
            (node, iter(sorted(graph.get(node, set()))))
        ]
        while dfs_stack:
            current, targets = dfs_stack[-1]
            try:
                target = next(targets)
            except StopIteration:
                dfs_stack.pop()
                finish_order.append(current)
                continue
            if target in visited:
                continue
            visited.add(target)
            dfs_stack.append((target, iter(sorted(graph.get(target, set())))))

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
        component_stack = [node]
        while component_stack:
            current = component_stack.pop()
            component.append(current)
            for source in sorted(reverse_graph.get(current, set()), reverse=True):
                if source not in assigned:
                    assigned.add(source)
                    component_stack.append(source)
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
    result["result_memory_origins"] = {
        "status": "incomplete",
        "locations": [],
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
        "result_memory_origins": {"status": "complete", "locations": []},
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
    call_site_effects: Mapping[CallSiteId, CallSiteEffect],
    memory_write_footprints: Mapping[
        tuple[str, int], _MemoryWriteFootprint
    ],
    return_instruction_cleanups: Mapping[str, Mapping[str, Any]],
    max_units: int,
    max_stack_words: int,
    max_memory_words: int,
    max_rounds: int,
    max_value_alternatives: int,
) -> tuple[dict[str, dict[str, Any]], int, bool]:
    """Establish one simultaneous inductive summary for a recursive SCC."""

    current = {
        root: {
            **_recursive_seed_summary(),
            "return_instruction_cleanup": copy.deepcopy(
                return_instruction_cleanups[root]
            ),
        }
        for root in component
    }
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
                call_site_effects=call_site_effects,
                memory_write_footprints=memory_write_footprints,
                max_units=max_units,
                max_stack_words=max_stack_words,
                max_memory_words=max_memory_words,
                max_value_alternatives=max_value_alternatives,
            )
            summary["return_instruction_cleanup"] = copy.deepcopy(
                return_instruction_cleanups[root]
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
            "result_memory_origins": summary.get("result_memory_origins"),
            "stack_cleanup": summary.get("stack_cleanup"),
            "return_instruction_cleanup": summary.get(
                "return_instruction_cleanup"
            ),
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
    call_site_effects: Mapping[CallSiteId, CallSiteEffect],
    memory_write_footprints: Mapping[
        tuple[str, int], _MemoryWriteFootprint
    ],
    max_units: int,
    max_stack_words: int,
    max_memory_words: int,
    max_value_alternatives: int,
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
    register_frames_complete = True
    memory_fact_dependencies: set[str] = set()
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
            call_site_effects=call_site_effects,
        )
        if call_frame is not None:
            blockers.update(call_frame.blocker_codes)
            register_frames_complete = (
                register_frames_complete
                and call_frame.register_frame_complete
            )
            if call_frame.may_not_return is True:
                nonreturning_nodes.add(unit_id)
            if not call_frame.behavior_complete:
                blockers.add("call_return_behavior_incomplete")
            elif call_frame.may_return is False:
                continue
        output, transfer_blockers, transfer_dependencies = _transfer(
            unit_id=unit_id,
            unit=unit,
            state=states[unit_id],
            direct_calls=direct_calls,
            recovered_calls=recovered_calls,
            summaries=summaries,
            import_abis=import_abis,
            call_site_effects=call_site_effects,
            memory_write_footprints=memory_write_footprints,
            max_stack_words=max_stack_words,
            max_memory_words=max_memory_words,
        )
        blockers.update(transfer_blockers)
        memory_fact_dependencies.update(transfer_dependencies)
        if "register_write_inventory_invalid" in transfer_blockers:
            register_frames_complete = False
        kind = _mapping(_mapping(unit.get("semantics")).get("outcome")).get("kind")
        if kind == "return":
            return_states.append(output)
            return_unit_ids.add(unit_id)
            continue
        if unit_id in unresolved_direct_sources:
            blockers.add("unresolved_direct_control")
            register_frames_complete = False
        if unit_id in unresolved_jump_sources:
            blockers.add("unresolved_indirect_jump")
            register_frames_complete = False
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
                register_frames_complete = False
            continue
        for target in sorted(successors):
            prior = states.get(target)
            joined = (
                copy.deepcopy(output)
                if prior is None
                else _join_states(
                    prior,
                    output,
                    max_value_alternatives=max_value_alternatives,
                )
            )
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
    register_control_complete = register_frames_complete and not {
        "callee_summary_budget_exceeded",
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
    result_memory: list[dict[str, Any]] = []
    if control_complete and return_states:
        for register in _REGISTERS:
            values = {state.registers.get(register) for state in return_states}
            if len(values) != 1:
                continue
            value = next(iter(values))
            serialized = _serialize_summary_value(value)
            if serialized is not None:
                result_registers[register] = serialized
        for location, value in _common_return_memory(
            return_states,
            maximum=max_value_alternatives,
        ).items():
            serialized = _serialize_summary_value(value)
            if serialized is not None:
                result_memory.append({
                    "location": location.as_json(),
                    "value": serialized,
                })
    effect_families = _summary_effect_families(
        reached_unit_ids=states,
        by_id=by_id,
        direct_calls=direct_calls,
        recovered_calls=recovered_calls,
        call_site_effects=call_site_effects,
        memory_fact_dependencies=memory_fact_dependencies,
        complete=control_complete,
    )
    return {
        "status": "complete" if summary_complete else "incomplete",
        "preserved_registers": (
            preserved if register_control_complete else []
        ),
        "register_preservation": {
            "status": (
                "complete" if register_control_complete else "incomplete"
            ),
        },
        "result_register_origins": {
            "status": "complete" if control_complete else "incomplete",
            "registers": result_registers if control_complete else {},
        },
        "result_memory_origins": {
            "status": "complete" if control_complete else "incomplete",
            "locations": (
                sorted(
                    result_memory,
                    key=lambda row: json.dumps(
                        row["location"],
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                )
                if control_complete
                else []
            ),
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
    call_site_effects: Mapping[CallSiteId, CallSiteEffect],
    memory_fact_dependencies: Iterable[str],
    complete: bool,
) -> dict[str, Any]:
    """Inventory local effects and delegated call dependencies exactly once."""

    memory_sites: list[dict[str, Any]] = []
    external_sites: list[dict[str, Any]] = []
    callback_sites: list[dict[str, Any]] = []
    dependencies: set[str] = set(memory_fact_dependencies)
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
            effect = call_site_effects.get(CallSiteId(unit_id, event_index))
            if effect is not None:
                dependencies.update(effect.dependencies)
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
    call_site_effects: Mapping[CallSiteId, CallSiteEffect],
    input_state: _State | None = None,
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
            register_frame_complete=False,
            preserved_registers=frozenset(),
            stack_frame_complete=False,
            stack_cleanup=None,
            result_frame_complete=False,
            result_registers={},
            blocker_codes=frozenset({"multiple_calls_in_unit"}),
        )
    event_index, event = calls[0]
    kind = event.get("kind")
    effect = call_site_effects.get(CallSiteId(unit_id, event_index))
    if kind == "external_call":
        identity = _event_import_identity(event)
        selected = import_abis.get(identity) if identity is not None else None
        if selected is None:
            frame = _incomplete_call_frame("external_call_abi_unresolved")
        else:
            frame = _returning_abi_frame(
                preserved_registers=selected.abi.preserved_registers,
                stack_cleanup=_selected_import_stack_cleanup(selected),
                result_registers=_selected_import_result_registers(
                    selected,
                    unit_id=unit_id,
                    event_index=event_index,
                    input_state=input_state,
                ),
            )
        return _overlay_call_site_effect(
            frame,
            effect,
            may_establish_return_behavior=True,
        )
    if kind == "internal_call":
        target = direct_calls.get((unit_id, event_index))
        if target is None:
            frame = _incomplete_call_frame("internal_call_target_unresolved")
        else:
            frame = _summary_call_frame(
                summaries.get(target), input_state=input_state
            )
        return _overlay_call_site_effect(
            frame,
            effect,
            may_establish_return_behavior=False,
        )
    if kind != "indirect_call":
        return _incomplete_call_frame("call_kind_unsupported")
    recovery = recovered_calls.get((unit_id, event_index))
    if recovery is None:
        frame = _incomplete_call_frame("indirect_call_target_unresolved")
    else:
        frame = _recovered_indirect_call_frame(
            recovery=recovery,
            summaries=summaries,
            import_abis=import_abis,
            input_state=input_state,
        )
    return _overlay_call_site_effect(
        frame,
        effect,
        may_establish_return_behavior=True,
    )


def _summary_call_frame(
    summary: Mapping[str, Any] | None,
    *,
    input_state: _State | None = None,
) -> _CallFrame:
    if summary is None:
        return _incomplete_call_frame("nested_call_summary_unavailable")
    behavior = _mapping(summary.get("return_behavior"))
    may_return = behavior.get("may_return")
    may_not_return = behavior.get("may_not_return")
    behavior_complete = behavior.get("status") == "complete" and (
        isinstance(may_return, bool)
        and isinstance(may_not_return, bool)
        and (may_return or may_not_return)
    )
    if not behavior_complete:
        may_return = None
        may_not_return = None
    preservation = _mapping(summary.get("register_preservation"))
    register_frame_complete = preservation.get("status") == "complete"
    stack_cleanup = _summary_stack_cleanup(summary)
    stack_frame_complete = stack_cleanup is not None
    register_results = _mapping(summary.get("result_register_origins"))
    memory_results = _mapping(summary.get("result_memory_origins"))
    result_frame_complete = (
        register_results.get("status") == "complete"
        and memory_results.get("status") == "complete"
    )
    return _CallFrame(
        behavior_complete=behavior_complete,
        may_return=may_return,
        may_not_return=may_not_return,
        register_frame_complete=register_frame_complete,
        preserved_registers=(
            _summary_preserved(summary) if register_frame_complete else frozenset()
        ),
        stack_frame_complete=stack_frame_complete,
        stack_cleanup=stack_cleanup,
        result_frame_complete=result_frame_complete,
        result_registers=(
            _summary_result_registers(
                summary, input_state=input_state
            )
            if result_frame_complete
            else {}
        ),
        result_memory=(
            _summary_result_memory(
                summary,
                input_state=input_state,
            )
            if result_frame_complete
            else {}
        ),
        blocker_codes=(
            frozenset()
            if behavior_complete
            else frozenset({"nested_call_return_behavior_incomplete"})
        ),
    )


def _recovered_indirect_call_frame(
    *,
    recovery: Mapping[str, Any],
    summaries: Mapping[str, Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    input_state: _State | None = None,
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
                summaries.get(raw_target), input_state=input_state
            ))
    if not alternatives:
        return _incomplete_call_frame("indirect_call_target_inventory_invalid")

    blockers = frozenset().union(
        *(alternative.blocker_codes for alternative in alternatives)
    )
    behavior_complete = all(
        alternative.behavior_complete for alternative in alternatives
    )
    if not behavior_complete:
        blockers |= {"indirect_call_return_behavior_incomplete"}
    possible_returning = [
        alternative
        for alternative in alternatives
        if alternative.may_return is not False
    ]
    register_frame_complete = bool(possible_returning) and all(
        alternative.register_frame_complete
        for alternative in possible_returning
    )
    preserved = (
        set(possible_returning[0].preserved_registers)
        if register_frame_complete
        else set()
    )
    for alternative in possible_returning[1:]:
        preserved &= alternative.preserved_registers
    stack_frame_complete = bool(possible_returning) and all(
        alternative.stack_frame_complete
        for alternative in possible_returning
    )
    cleanups = {
        alternative.stack_cleanup for alternative in possible_returning
    }
    if len(cleanups) != 1:
        stack_frame_complete = False
    stack_cleanup = (
        next(iter(cleanups)) if stack_frame_complete else None
    )
    result_frame_complete = bool(possible_returning) and all(
        alternative.result_frame_complete
        for alternative in possible_returning
    )
    result_registers = (
        _common_call_results(possible_returning)
        if result_frame_complete
        else {}
    )
    result_memory = (
        _common_call_memory(possible_returning)
        if result_frame_complete
        else {}
    )
    memory_frame_complete = bool(possible_returning) and all(
        alternative.memory_frame_complete for alternative in possible_returning
    )
    return _CallFrame(
        behavior_complete=behavior_complete,
        may_return=(
            any(alternative.may_return is True for alternative in alternatives)
            if behavior_complete
            else None
        ),
        may_not_return=(
            any(
                alternative.may_not_return is True
                for alternative in alternatives
            )
            if behavior_complete
            else None
        ),
        register_frame_complete=register_frame_complete,
        preserved_registers=frozenset(preserved),
        stack_frame_complete=stack_frame_complete,
        stack_cleanup=stack_cleanup,
        result_frame_complete=result_frame_complete,
        result_registers=result_registers,
        blocker_codes=blockers,
        result_memory=result_memory,
        memory_frame_complete=memory_frame_complete,
        memory_preserved=(
            memory_frame_complete
            and all(
                alternative.memory_preserved
                for alternative in possible_returning
            )
        ),
        memory_writes=(
            tuple(sorted(
                {
                    span
                    for alternative in possible_returning
                    for span in alternative.memory_writes
                },
                key=lambda span: (
                    _typed_origin_sort_key(span.base),
                    -1 if span.size is None else span.size,
                ),
            ))
            if memory_frame_complete
            else ()
        ),
    )


def _returning_abi_frame(
    *,
    preserved_registers: Iterable[str],
    stack_cleanup: int | None,
    result_registers: Mapping[str, _Value] | None = None,
    result_memory: Mapping[ValueOrigin, _Value] | None = None,
    memory_frame_complete: bool = False,
    memory_preserved: bool = False,
    memory_writes: tuple[CallWriteSpan, ...] = (),
) -> _CallFrame:
    return _CallFrame(
        behavior_complete=True,
        may_return=True,
        may_not_return=False,
        register_frame_complete=True,
        preserved_registers=frozenset(
            register for register in preserved_registers if register in _REGISTERS
        ),
        stack_frame_complete=stack_cleanup is not None,
        stack_cleanup=(
            None if stack_cleanup is None else _StackTransform(stack_cleanup)
        ),
        result_frame_complete=True,
        result_registers=dict(result_registers or {}),
        result_memory=dict(result_memory or {}),
        memory_frame_complete=memory_frame_complete,
        memory_preserved=memory_preserved,
        memory_writes=memory_writes,
    )


def _call_site_effect_frame(effect: CallSiteEffect) -> _CallFrame:
    result_registers: dict[str, _Value] = {}
    result_memory: dict[ValueOrigin, _Value] = {}
    for output in effect.outputs:
        typed = (
            None
            if output.value is None
            else _TypedOrigins(
                tuple(sorted(output.value, key=_typed_origin_sort_key))
            )
        )
        if typed is None:
            continue
        if (
            output.location.kind == "register_location"
            and len(output.location.key) == 1
            and output.location.key[0] in _REGISTERS
        ):
            result_registers[str(output.location.key[0])] = typed
            continue
        result_memory[output.location] = typed
    return _returning_abi_frame(
        preserved_registers=effect.preserved_registers,
        stack_cleanup=effect.stack_cleanup_bytes,
        result_registers=result_registers,
        result_memory=result_memory,
        memory_frame_complete=effect.memory_frame_status == "complete",
        memory_preserved=effect.memory_preserved,
        memory_writes=effect.memory_writes,
    )


def _overlay_call_site_effect(
    frame: _CallFrame,
    effect: CallSiteEffect | None,
    *,
    may_establish_return_behavior: bool,
) -> _CallFrame:
    """Compose independently checked site families with target-derived facts."""

    if effect is None:
        return frame
    behavior_from_effect = bool(
        may_establish_return_behavior
        and effect.abi is not None
        and effect.status == "complete"
    )
    register_complete = effect.register_frame_status == "complete"
    stack_complete = effect.stack_frame_status == "complete"
    result_complete = effect.result_status == "complete"
    memory_complete = effect.memory_frame_status == "complete"
    effect_frame = _call_site_effect_frame(effect)
    return _CallFrame(
        behavior_complete=(
            True if behavior_from_effect else frame.behavior_complete
        ),
        may_return=True if behavior_from_effect else frame.may_return,
        may_not_return=False if behavior_from_effect else frame.may_not_return,
        register_frame_complete=(
            True if register_complete else frame.register_frame_complete
        ),
        preserved_registers=(
            effect_frame.preserved_registers
            if register_complete
            else frame.preserved_registers
        ),
        stack_frame_complete=(
            True if stack_complete else frame.stack_frame_complete
        ),
        stack_cleanup=(
            effect_frame.stack_cleanup
            if stack_complete
            else frame.stack_cleanup
        ),
        result_frame_complete=(
            True if result_complete else frame.result_frame_complete
        ),
        result_registers=(
            effect_frame.result_registers
            if result_complete
            else frame.result_registers
        ),
        blocker_codes=(
            frozenset(effect.failure_codes)
            if behavior_from_effect
            else frame.blocker_codes | frozenset(effect.failure_codes)
        ),
        result_memory=(
            effect_frame.result_memory
            if result_complete
            else frame.result_memory
        ),
        memory_frame_complete=(
            True if memory_complete else frame.memory_frame_complete
        ),
        memory_preserved=(
            effect_frame.memory_preserved
            if memory_complete
            else frame.memory_preserved
        ),
        memory_writes=(
            effect_frame.memory_writes
            if memory_complete
            else frame.memory_writes
        ),
    )


def _incomplete_call_frame(code: str) -> _CallFrame:
    return _CallFrame(
        behavior_complete=False,
        may_return=None,
        may_not_return=None,
        register_frame_complete=False,
        preserved_registers=frozenset(),
        stack_frame_complete=False,
        stack_cleanup=None,
        result_frame_complete=False,
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
    return _State(
        registers=registers,
        stack_words=dict(output.stack_words),
        memory_words=dict(output.memory_words),
        input_stack_valid=output.input_stack_valid,
        input_stack_kills=output.input_stack_kills,
    )


def _recovered_external_call_sites(
    recoveries: Sequence[Mapping[str, Any]],
    *,
    indirect_exits: Sequence[Mapping[str, Any]],
    by_id: Mapping[str, Mapping[str, Any]],
) -> dict[tuple[str, int], Mapping[str, Any]]:
    """Bind recovered external alternatives to exact indirect-call events."""

    by_recovery_id = {
        str(row["id"]): row
        for row in recoveries
        if row.get("status") == "recovered"
        and isinstance(row.get("id"), str)
    }
    result: dict[tuple[str, int], Mapping[str, Any]] = {}
    for exit_record in indirect_exits:
        if exit_record.get("kind") != "indirect_call":
            continue
        source = exit_record.get("source_unit_id")
        event_index = _integer(exit_record.get("source_event_index"))
        recovery = by_recovery_id.get(str(exit_record.get("id") or ""))
        if (
            not isinstance(source, str)
            or event_index is None
            or recovery is None
            or recovery.get("source_unit_id") != source
            or _integer(recovery.get("source_event_index")) != event_index
            or not recovery.get("external_targets")
        ):
            continue
        events = _events(by_id.get(source, {}))
        if (
            not 0 <= event_index < len(events)
            or events[event_index].get("kind") != "indirect_call"
        ):
            continue
        result[(source, event_index)] = recovery
    return result


def _recovered_external_identities(
    recovery: Mapping[str, Any] | None,
) -> frozenset[MachineImportIdentity]:
    result: set[MachineImportIdentity] = set()
    targets = recovery.get("external_targets") if recovery else None
    for raw in targets if isinstance(targets, list) else ():
        target = _mapping(raw)
        imported = _mapping(target.get("import"))
        dll = imported.get("dll")
        symbol = imported.get("symbol")
        ordinal = _integer(imported.get("ordinal"))
        if not isinstance(dll, str):
            continue
        if isinstance(symbol, str) and symbol:
            result.add(MachineImportIdentity(dll.lower(), "symbol", symbol))
        elif ordinal is not None:
            result.add(MachineImportIdentity(dll.lower(), "ordinal", ordinal))
    return frozenset(result)


def _memory_write_footprints(
    facts: Mapping[str, PreparedMemoryAccessFact],
    *,
    by_id: Mapping[str, Mapping[str, Any]],
    recovered_external_calls: Mapping[
        tuple[str, int], Mapping[str, Any]
    ],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    image_base: int | None,
    image_size: int | None,
) -> dict[tuple[str, int], _MemoryWriteFootprint]:
    """Classify exact write facts that cannot silently alias stack spills.

    Dynamic origins are accepted only when their producer is the exact import
    event selected by a reviewed ``dynamic_range_base`` contract. Such ranges
    are relational-world allocations and are disjoint from the launch stack.
    Concrete origins must lie wholly inside the PE image, whose launch mapping
    is likewise disjoint from that stack. Any other alternative prevents the
    fact from becoming a usable footprint.
    """

    if not facts:
        return {}
    assert image_base is not None and image_size is not None
    result: dict[tuple[str, int], _MemoryWriteFootprint] = {}
    for fact in facts.values():
        if fact.memory_kind not in {"write", "read_write"}:
            continue
        stack_offsets: set[int] = set()
        has_non_stack = False
        complete = True
        for raw in fact.address_origins:
            try:
                origin = parse_value_origin(
                    raw.to_value(), context="prepared write-footprint origin"
                )
            except ValueError:
                complete = False
                break
            stack_offset = _stack_origin_offset(origin)
            if stack_offset is not None:
                stack_offsets.add(stack_offset)
                continue
            if _origin_is_checked_non_stack(
                origin,
                width=fact.width_bytes,
                by_id=by_id,
                recovered_external_calls=recovered_external_calls,
                import_abis=import_abis,
                image_base=image_base,
                image_size=image_size,
            ):
                has_non_stack = True
                continue
            complete = False
            break
        if not complete or not (stack_offsets or has_non_stack):
            continue
        key = (fact.binding.unit.unit_id, fact.binding.event_index)
        if key in result:
            raise ValueError("prepared write footprints duplicate an exact event")
        result[key] = _MemoryWriteFootprint(
            fact_id=fact.fact_id,
            stack_offsets=tuple(sorted(stack_offsets)),
            has_non_stack_alternative=has_non_stack,
        )
    return result


def _stack_origin_offset(origin: ValueOrigin) -> int | None:
    if origin.kind != "stack_location" or len(origin.key) != 1:
        return None
    offset = origin.key[0]
    return (
        int(offset)
        if isinstance(offset, int)
        and not isinstance(offset, bool)
        and -(1 << 31) <= offset < (1 << 31)
        else None
    )


def _origin_is_checked_non_stack(
    origin: ValueOrigin,
    *,
    width: int,
    by_id: Mapping[str, Mapping[str, Any]],
    recovered_external_calls: Mapping[
        tuple[str, int], Mapping[str, Any]
    ],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    image_base: int,
    image_size: int,
) -> bool:
    concrete = origin_concrete_value(origin)
    if concrete is not None:
        return _span_inside_image(
            concrete,
            width,
            image_base=image_base,
            image_size=image_size,
        )
    if origin.kind == "absolute_span" and len(origin.key) == 2:
        minimum, maximum_start = origin.key
        return (
            isinstance(minimum, int)
            and not isinstance(minimum, bool)
            and isinstance(maximum_start, int)
            and not isinstance(maximum_start, bool)
            and 0 <= minimum <= maximum_start < (1 << 32)
            and maximum_start + width <= (1 << 32)
            and _span_inside_image(
                minimum,
                maximum_start - minimum + width,
                image_base=image_base,
                image_size=image_size,
            )
        )
    if origin.kind not in {
        "dynamic_range",
        "dynamic_location",
        "dynamic_span",
    }:
        return False
    key = origin.key
    if origin.kind == "dynamic_range" and len(key) in {5, 6}:
        extent_lower_bound = key[5] if len(key) == 6 else None
        minimum_offset = maximum_offset = 0
    elif origin.kind == "dynamic_location" and len(key) in {6, 7}:
        extent_lower_bound = key[5] if len(key) == 7 else None
        minimum_offset = maximum_offset = key[-1]
    elif origin.kind == "dynamic_span" and len(key) == 8:
        extent_lower_bound = key[5]
        minimum_offset, maximum_offset = key[6:]
    else:
        return False
    producer, event_index, dll, identity_kind, identity_value = key[:5]
    if (
        not isinstance(producer, str)
        or not isinstance(event_index, int)
        or isinstance(event_index, bool)
        or not isinstance(dll, str)
        or identity_kind not in {"symbol", "ordinal"}
        or (identity_kind == "symbol" and not isinstance(identity_value, str))
        or (identity_kind == "ordinal" and not isinstance(identity_value, int))
        or not isinstance(minimum_offset, int)
        or isinstance(minimum_offset, bool)
        or not isinstance(maximum_offset, int)
        or isinstance(maximum_offset, bool)
        or minimum_offset < 0
        or maximum_offset < minimum_offset
        or maximum_offset + width > (1 << 32)
        or (
            extent_lower_bound is not None
            and (
                not isinstance(extent_lower_bound, int)
                or isinstance(extent_lower_bound, bool)
                or not 0 < extent_lower_bound <= 0xFFFFFFFF
            )
        )
    ):
        return False
    unit = by_id.get(producer)
    events = _events(unit or {})
    if not 0 <= event_index < len(events):
        return False
    identity = _event_import_identity(events[event_index])
    expected_identity = MachineImportIdentity(
        str(dll).lower(), str(identity_kind), identity_value
    )
    if identity is None:
        identities = _recovered_external_identities(
            recovered_external_calls.get((producer, event_index))
        )
        if identities == frozenset({expected_identity}):
            identity = expected_identity
    selected = import_abis.get(expected_identity)
    if identity != expected_identity or selected is None:
        return False
    contract = selected.contract
    relations = (
        contract.get("result_register_relations")
        if isinstance(contract, Mapping)
        else None
    )
    if not isinstance(relations, list):
        return False
    reviewed_bounds = [
        int(relation.get("minimum_size"))
        for relation in relations
        if isinstance(relation, Mapping)
        and relation.get("relation") == "dynamic_range_base"
        and isinstance(relation.get("minimum_size"), int)
        and not isinstance(relation.get("minimum_size"), bool)
        and 0 <= int(relation["minimum_size"]) <= 0xFFFFFFFF
    ]
    reviewed_minimum = min(reviewed_bounds) if reviewed_bounds else 0
    effective_extent = max(
        reviewed_minimum,
        0 if extent_lower_bound is None else int(extent_lower_bound),
    )
    return maximum_offset + width <= effective_extent


def _valid_image_range(image_base: int, image_size: int) -> bool:
    return (
        isinstance(image_base, int)
        and not isinstance(image_base, bool)
        and isinstance(image_size, int)
        and not isinstance(image_size, bool)
        and 0 <= image_base < (1 << 32)
        and 0 < image_size <= (1 << 32) - image_base
    )


def _span_inside_image(
    address: int,
    width: int,
    *,
    image_base: int,
    image_size: int,
) -> bool:
    return (
        0 < width <= image_size
        and image_base <= address
        and address + width <= image_base + image_size
    )


def _transfer(
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    state: _State,
    direct_calls: Mapping[tuple[str, int], str],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    summaries: Mapping[str, Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    call_site_effects: Mapping[CallSiteId, CallSiteEffect],
    memory_write_footprints: Mapping[
        tuple[str, int], _MemoryWriteFootprint
    ],
    max_stack_words: int,
    max_memory_words: int,
) -> tuple[_State, set[str], set[str]]:
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
            call_site_effects=call_site_effects,
            input_state=pre_call,
        )
        if frame is None:
            return _unknown_state(), {"call_inventory_missing"}, set()
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
        (
            output_stack,
            output_memory,
            input_stack_valid,
            input_stack_kills,
        ) = _apply_call_memory_frame(
            event=event,
            pre_call=pre_call,
            frame=frame,
            maximum_stack_ranges=max_stack_words,
        )
        return (
            _State(
                registers=output_registers,
                stack_words=output_stack,
                memory_words=output_memory,
                input_stack_valid=input_stack_valid,
                input_stack_kills=input_stack_kills,
            ),
            set(frame.blocker_codes) | stack_blockers,
            set(),
        )

    semantics = _mapping(unit.get("semantics"))
    writes = semantics.get("register_writes")
    if not isinstance(writes, list):
        return _unknown_state(), {"register_write_inventory_invalid"}, set()
    registers: dict[str, _Value] = dict(state.registers)
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
    memory_words = dict(state.memory_words)
    input_stack_valid = state.input_stack_valid
    input_stack_kills = state.input_stack_kills
    memory_fact_dependencies: set[str] = set()
    memory_events = semantics.get("memory_events")
    if not isinstance(memory_events, list):
        stack_words.clear()
        memory_words.clear()
        input_stack_valid = False
        input_stack_kills = ()
    else:
        for event_index, raw in enumerate(memory_events):
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
                input_stack_kills = _add_killed_stack_range(
                    input_stack_kills,
                    address.offset,
                    width,
                    maximum=max_stack_words,
                )
                if input_stack_kills is None:
                    input_stack_valid = False
                    input_stack_kills = ()
                value = _evaluate(event.get("value"), state)
                if width == 4 and value is not None:
                    stack_words[address.offset] = value
            elif (
                (location := _summary_memory_location(address)) is not None
                and width is not None
                and (
                    location.kind != "parametric_location"
                    or (unit_id, event_index) not in memory_write_footprints
                )
            ):
                if location.kind == "parametric_location":
                    # The address relation is useful as a returned memory
                    # effect, but by itself does not prove separation from the
                    # callee's stack. Preserve no stack-frame evidence unless a
                    # checked spatial footprint selected the branch below.
                    stack_words.clear()
                    input_stack_valid = False
                    input_stack_kills = ()
                memory_words = {
                    existing: value
                    for existing, value in memory_words.items()
                    if _locations_provably_disjoint(
                        existing,
                        CallWriteSpan(location, width),
                    )
                }
                value = _evaluate(event.get("value"), state)
                if width == 4 and value is not None:
                    memory_words[location] = value
            else:
                footprint = memory_write_footprints.get(
                    (unit_id, event_index)
                )
                if footprint is None or width is None:
                    stack_words.clear()
                    memory_words.clear()
                    input_stack_valid = False
                    input_stack_kills = ()
                    continue
                memory_fact_dependencies.add(footprint.fact_id)
                for offset in footprint.stack_offsets:
                    _invalidate_overlapping(stack_words, offset, width)
                    updated_kills = _add_killed_stack_range(
                        input_stack_kills,
                        offset,
                        width,
                        maximum=max_stack_words,
                    )
                    if updated_kills is None:
                        input_stack_valid = False
                        input_stack_kills = ()
                    else:
                        input_stack_kills = updated_kills
                # The fact proves separation from protected stack cells, not
                # the identity of every non-stack location. Keep stack frame
                # evidence but conservatively discard ordinary memory facts.
                if footprint.has_non_stack_alternative:
                    memory_words.clear()
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
                memory_words.clear()
                input_stack_valid = False
                input_stack_kills = ()
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
                memory_words.clear()
                input_stack_valid = False
                input_stack_kills = ()
    if len(stack_words) > max_stack_words:
        stack_words.clear()
    if len(memory_words) > max_memory_words:
        memory_words.clear()
    return _State(
        registers=registers,
        stack_words=stack_words,
        memory_words=memory_words,
        input_stack_valid=input_stack_valid,
        input_stack_kills=input_stack_kills,
    ), stack_blockers, memory_fact_dependencies


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
    if cleanup.get("status") == "complete":
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
            return _StackTransform(
                constant, _normalize_register_terms(terms)
            )
        value = _integer(cleanup.get("stack_delta"))
        return None if value is None else _StackTransform(value)
    instruction_cleanup = _mapping(
        summary.get("return_instruction_cleanup")
    )
    value = _integer(instruction_cleanup.get("cleanup_bytes"))
    if instruction_cleanup.get("status") == "complete" and value is not None:
        return _StackTransform(value)
    return None


def _selected_import_result_registers(
    selected: SelectedImportABI,
    *,
    unit_id: str,
    event_index: int,
    input_state: _State | None,
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
            extent_lower_bound=_dynamic_result_extent_lower_bound(
                selected,
                relation,
                input_state=input_state,
            ),
        )
    return result


def _dynamic_result_extent_lower_bound(
    selected: SelectedImportABI,
    relation: Mapping[str, Any],
    *,
    input_state: _State | None,
) -> int | None:
    """Recover a checked lower bound for one allocation-like result.

    The reviewed import contract supplies the extent rule.  A dynamic argument
    contributes only when the exact call-frame state reduces it to one
    concrete unsigned word; otherwise the declared minimum remains the only
    usable bound.
    """

    minimum = _integer(relation.get("minimum_size"))
    if minimum is None or minimum < 0 or minimum > 0xFFFFFFFF:
        minimum = 0
    size = _mapping(relation.get("size"))
    kind = size.get("kind")
    if kind == "fixed":
        fixed = _integer(size.get("bytes"))
        if fixed is not None and 0 <= fixed <= 0xFFFFFFFF:
            minimum = max(minimum, fixed)
    elif kind == "argument" and input_state is not None:
        argument = _integer(size.get("argument"))
        scale = _integer(size.get("scale"))
        esp = input_state.registers.get("esp")
        if (
            argument is not None
            and selected.argument_words is not None
            and 0 <= argument < selected.argument_words
            and scale is not None
            and 0 < scale <= 0xFFFFFFFF
            and isinstance(esp, _StackAddress)
            and not esp.register_terms
        ):
            value = _read_stack_word(
                input_state, esp.offset + argument * 4
            )
            if isinstance(value, _Exact) and value.value <= 0xFFFFFFFF // scale:
                minimum = max(minimum, value.value * scale)
    return minimum if minimum > 0 else None


def _serialize_summary_value(value: _Value) -> dict[str, Any] | None:
    if isinstance(value, _RegisterOrigin):
        return {"kind": "input_register", "register": value.register}
    if isinstance(value, _InputStackWord):
        return {"kind": "input_stack_word", "offset": value.offset}
    if isinstance(value, _ParametricWord):
        return {
            "kind": "parametric_word",
            "constant": value.constant,
            "terms": [_parametric_term_json(term) for term in value.terms],
        }
    if isinstance(value, _StackAddress):
        return {
            "kind": "stack_address",
            "offset": value.offset,
            "register_terms": _register_terms_json(value.register_terms),
        }
    if isinstance(value, _Exact):
        return {"kind": "exact", "value": value.value & 0xFFFFFFFF}
    if isinstance(value, _ExternalResult):
        result = {
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
        if value.extent_lower_bound is not None:
            result["extent_lower_bound"] = value.extent_lower_bound
        return result
    if isinstance(value, _InternalContractResult):
        return {
            "kind": "internal_contract_result",
            "contract_id": value.contract_id,
            "relation": value.relation,
            "nullable": value.nullable,
        }
    if isinstance(value, _TypedOrigins):
        return {
            "kind": "typed_origins",
            "origins": [origin.as_json() for origin in value.origins],
        }
    return None


def _parse_summary_value(value: Any) -> _Value:
    row = _mapping(value)
    kind = row.get("kind")
    if kind == "input_register" and row.get("register") in _REGISTERS:
        return _RegisterOrigin(str(row["register"]))
    if kind == "input_stack_word":
        offset = _integer(row.get("offset"))
        return (
            _InputStackWord(offset)
            if set(row) == {"kind", "offset"}
            and offset is not None
            and 4 <= offset <= 0xFFFFFFFF
            else None
        )
    if kind == "parametric_word":
        return _parse_parametric_word(row)
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
            if register not in _REGISTERS or coefficient is None or coefficient == 0:
                return None
            terms.append((str(register), coefficient))
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
    if kind == "typed_origins":
        raw_origins = row.get("origins")
        if not isinstance(raw_origins, list) or not raw_origins:
            return None
        try:
            origins = tuple(
                sorted(
                    (_parse_typed_origin(raw) for raw in raw_origins),
                    key=_typed_origin_sort_key,
                )
            )
        except ValueError:
            return None
        if len(set(origins)) != len(origins):
            return None
        return _TypedOrigins(origins)
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
    extent_lower_bound = _integer(row.get("extent_lower_bound"))
    if (
        event_index is None
        or not isinstance(producer, str)
        or relation != "dynamic_range_base"
        or not isinstance(nullable, bool)
        or (
            "extent_lower_bound" in row
            and (
                extent_lower_bound is None
                or not 0 < extent_lower_bound <= 0xFFFFFFFF
            )
        )
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
        extent_lower_bound=extent_lower_bound,
    )


def _parse_typed_origin(raw: Any) -> ValueOrigin:
    return parse_value_origin(raw, context="typed summary origin")


def _typed_origin_sort_key(origin: ValueOrigin) -> tuple[str, str, tuple[str, ...]]:
    return (origin.kind, repr(origin.key), origin.dependencies)


def _summary_result_registers(
    summary: Mapping[str, Any] | None,
    *,
    input_state: _State | None = None,
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
            raw, input_state=input_state
        )
        if value is not None:
            result[register] = value
    return result


def _summary_result_memory(
    summary: Mapping[str, Any] | None,
    *,
    input_state: _State | None = None,
) -> dict[ValueOrigin, _Value]:
    if summary is None:
        return {}
    inventory = _mapping(summary.get("result_memory_origins"))
    raw_locations = inventory.get("locations")
    if inventory.get("status") != "complete" or not isinstance(
        raw_locations, list
    ):
        return {}
    result: dict[ValueOrigin, _Value] = {}
    for raw in raw_locations:
        row = _mapping(raw)
        if set(row) != {"location", "value"}:
            return {}
        try:
            location = _parse_typed_origin(row.get("location"))
        except ValueError:
            return {}
        instantiated_location = _instantiate_summary_location(
            location,
            input_state=input_state,
        )
        value = _instantiate_summary_value(
            row.get("value"),
            input_state=input_state,
        )
        if instantiated_location is None or value is None:
            return {}
        if instantiated_location in result:
            return {}
        result[instantiated_location] = value
    return result


def _instantiate_summary_location(
    location: ValueOrigin,
    *,
    input_state: _State | None,
) -> ValueOrigin | None:
    if location.kind == "parametric_location":
        parametric = _parametric_word_from_location(location)
        if parametric is None or input_state is None:
            return None
        return _summary_memory_location(
            _instantiate_parametric_word(parametric, input_state=input_state)
        )
    if location.kind != "stack_location":
        return location
    if len(location.key) != 1 or input_state is None:
        return None
    offset = _integer(location.key[0])
    if offset is None:
        return None
    instantiated = _add_stack_cleanup(
        input_state.registers.get("esp"),
        _StackTransform(offset - 4),
        input_state.registers,
    )
    if not isinstance(instantiated, _StackAddress) or instantiated.register_terms:
        return None
    return ValueOrigin(
        "stack_location",
        (instantiated.offset,),
        location.dependencies,
    )


def _instantiate_summary_value(
    raw: Any,
    *,
    input_state: _State | None,
) -> _Value:
    """Instantiate one callee-input-relative result at a concrete call site."""

    row = _mapping(raw)
    kind = row.get("kind")
    if kind == "input_register":
        source = row.get("register")
        return (
            input_state.registers.get(str(source))
            if input_state is not None and source in _REGISTERS
            else None
        )
    if kind == "input_stack_word":
        offset = _integer(row.get("offset"))
        if (
            input_state is None
            or offset is None
            or not 4 <= offset <= 0xFFFFFFFF
        ):
            return None
        address = _add_stack_cleanup(
            input_state.registers.get("esp"),
            _StackTransform(offset - 4),
            input_state.registers,
        )
        if not isinstance(address, _StackAddress) or address.register_terms:
            return None
        return _read_stack_word(input_state, address.offset)
    if kind == "stack_address":
        if input_state is None:
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
            if register not in _REGISTERS or coefficient is None or coefficient == 0:
                return None
            terms.append((str(register), coefficient))
        # A machine CALL pushes a four-byte return address after the event's
        # pre-call register state.  Summary offset zero denotes callee-entry
        # ESP, hence the caller-relative constant is offset - 4.
        return _add_stack_cleanup(
            input_state.registers.get("esp"),
            _StackTransform(offset - 4, _normalize_register_terms(terms)),
            input_state.registers,
        )
    if kind == "parametric_word":
        parsed = _parse_parametric_word(row)
        return (
            None
            if parsed is None or input_state is None
            else _instantiate_parametric_word(parsed, input_state=input_state)
        )
    if kind == "typed_origins":
        parsed = _parse_summary_value(raw)
        if not isinstance(parsed, _TypedOrigins):
            return None
        origins: list[ValueOrigin] = []
        for origin in parsed.origins:
            instantiated = _instantiate_summary_location(
                origin,
                input_state=input_state,
            )
            if instantiated is None:
                return None
            origins.append(instantiated)
        return _TypedOrigins(tuple(sorted(origins, key=_typed_origin_sort_key)))
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


def _common_call_memory(
    alternatives: Sequence[_CallFrame],
) -> dict[ValueOrigin, _Value]:
    if not alternatives:
        return {}
    common = dict(alternatives[0].result_memory)
    for alternative in alternatives[1:]:
        common = {
            location: value
            for location, value in common.items()
            if alternative.result_memory.get(location) == value
        }
    return common


def _common_return_memory(
    states: Sequence[_State], *, maximum: int
) -> dict[ValueOrigin, _Value]:
    if not states:
        return {}
    common: dict[ValueOrigin, _Value] = dict(states[0].memory_words)
    for state in states[1:]:
        joined_memory: dict[ValueOrigin, _Value] = {}
        for location, value in common.items():
            joined = _join_summary_value(
                value,
                state.memory_words.get(location),
                maximum=maximum,
            )
            if joined is not None:
                joined_memory[location] = joined
        common = joined_memory
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
    return _State(
        registers=registers,
        stack_words=dict(state.stack_words),
        memory_words=dict(state.memory_words),
        input_stack_valid=state.input_stack_valid,
        input_stack_kills=state.input_stack_kills,
    )


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


def _apply_call_memory_frame(
    *,
    event: Mapping[str, Any],
    pre_call: _State,
    frame: _CallFrame,
    maximum_stack_ranges: int,
) -> tuple[
    dict[int, _Value],
    dict[ValueOrigin, _Value],
    bool,
    tuple[tuple[int, int], ...],
]:
    stack_words = _stack_words_preserved_across_call(
        event=event,
        pre_call=pre_call,
    )
    if not frame.memory_frame_complete:
        memory_words: dict[ValueOrigin, _Value] = {}
        input_stack_valid = False
        input_stack_kills: tuple[tuple[int, int], ...] = ()
    elif frame.memory_preserved:
        memory_words = dict(pre_call.memory_words)
        input_stack_valid = pre_call.input_stack_valid
        input_stack_kills = pre_call.input_stack_kills
    else:
        memory_words = {
            location: value
            for location, value in pre_call.memory_words.items()
            if all(
                _locations_provably_disjoint(location, span)
                for span in frame.memory_writes
            )
        }
        input_stack_valid = pre_call.input_stack_valid
        input_stack_kills = pre_call.input_stack_kills
        for span in frame.memory_writes:
            if span.base.kind != "stack_location" or len(span.base.key) != 1:
                continue
            offset = _integer(span.base.key[0])
            if offset is None or span.size is None:
                stack_words.clear()
                input_stack_valid = False
                input_stack_kills = ()
            else:
                _invalidate_overlapping(stack_words, offset, span.size)
                updated_kills = _add_killed_stack_range(
                    input_stack_kills,
                    offset,
                    span.size,
                    maximum=maximum_stack_ranges,
                )
                if updated_kills is None:
                    input_stack_valid = False
                    input_stack_kills = ()
                else:
                    input_stack_kills = updated_kills

    for location, value in frame.result_memory.items():
        if value is None:
            continue
        if location.kind == "stack_location" and len(location.key) == 1:
            offset = _integer(location.key[0])
            if offset is not None:
                stack_words[offset] = value
            continue
        memory_words[location] = value
    return stack_words, memory_words, input_stack_valid, input_stack_kills


def _locations_provably_disjoint(
    location: ValueOrigin, span: CallWriteSpan
) -> bool:
    if span.size is None:
        return False
    if (
        location.kind == span.base.kind == "exact"
        and len(location.key) == len(span.base.key) == 1
    ):
        left = _integer(location.key[0])
        right = _integer(span.base.key[0])
        return (
            left is not None
            and right is not None
            and not _ranges_overlap_u32(left, 4, right, span.size)
        )
    if (
        location.kind == span.base.kind == "stack_location"
        and len(location.key) == len(span.base.key) == 1
    ):
        left = _integer(location.key[0])
        right = _integer(span.base.key[0])
        return bool(
            left is not None
            and right is not None
            and (left + 4 <= right or right + span.size <= left)
        )
    if location.kind == span.base.kind == "parametric_location":
        left = _parametric_word_from_location(location)
        right = _parametric_word_from_location(span.base)
        if left is None or right is None or left.terms != right.terms:
            return False
        return not _ranges_overlap_u32(
            left.constant,
            4,
            right.constant,
            span.size,
        )
    return False


def _ranges_overlap_u32(
    left_start: int,
    left_size: int,
    right_start: int,
    right_size: int,
) -> bool:
    if min(left_size, right_size) <= 0:
        return False
    modulus = 1 << 32
    if left_size >= modulus or right_size >= modulus:
        return True

    def intervals(start: int, size: int) -> tuple[tuple[int, int], ...]:
        start &= 0xFFFFFFFF
        end = start + size
        if end <= modulus:
            return ((start, end),)
        return ((start, modulus), (0, end - modulus))

    return any(
        left < right_end and right < left_end
        for left, left_end in intervals(left_start, left_size)
        for right, right_end in intervals(right_start, right_size)
    )


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
        return _combine_parametric_words(left, right, subtract=subtract)
    if op in {"mul", "mul32"}:
        operands = _binary_operands(expression)
        if operands is None:
            return None
        return _multiply_parametric_words(
            _evaluate(operands[0], state),
            _evaluate(operands[1], state),
        )
    if op in {"load", "read32", "mem32"}:
        width = expression.get("width", expression.get("width_bits", 4))
        if width not in {4, 32, None}:
            return None
        address = _evaluate(expression.get("address"), state)
        if isinstance(address, _StackAddress) and not address.register_terms:
            return _read_stack_word(state, address.offset)
        if isinstance(address, _Exact):
            return state.memory_words.get(
                ValueOrigin("exact", (address.value & 0xFFFFFFFF,))
            )
        location = _summary_memory_location(address)
        if location is not None:
            return state.memory_words.get(location)
        return None
    return None


def _summary_memory_location(value: _Value) -> ValueOrigin | None:
    """Normalize one summary word into a serializable memory location."""

    if isinstance(value, _Exact):
        return ValueOrigin("exact", (value.value & 0xFFFFFFFF,))
    parametric = _as_parametric_word(value)
    if parametric is not None:
        if not parametric.terms:
            return ValueOrigin("exact", (parametric.constant,))
        return ValueOrigin(
            "parametric_location",
            (
                parametric.constant,
                tuple(
                    (
                        term.source_kind,
                        term.source,
                        term.coefficient,
                    )
                    for term in parametric.terms
                ),
            ),
        )
    if isinstance(value, _ExternalResult):
        key: tuple[Any, ...] = (
            value.producer_unit_id,
            value.event_index,
            value.dll,
            value.identity_kind,
            value.identity_value,
        )
        if value.extent_lower_bound is not None:
            key = (*key, value.extent_lower_bound)
        return ValueOrigin("dynamic_location", (*key, 0))
    if isinstance(value, _TypedOrigins) and len(value.origins) == 1:
        origin = value.origins[0]
        if origin.kind == "dynamic_range":
            return ValueOrigin(
                "dynamic_location", (*origin.key, 0), origin.dependencies
            )
        if origin.kind in {"exact", "dynamic_location", "stack_location"}:
            return origin
    return None


def _as_parametric_word(value: _Value) -> _ParametricWord | None:
    if isinstance(value, _ParametricWord):
        return value
    if isinstance(value, _RegisterOrigin):
        return _make_parametric_word(
            0, (_ParametricTerm("input_register", value.register, 1),)
        )
    if isinstance(value, _InputStackWord):
        return _make_parametric_word(
            0, (_ParametricTerm("input_stack_word", value.offset, 1),)
        )
    if isinstance(value, _Exact):
        return _ParametricWord(value.value & 0xFFFFFFFF, ())
    return None


def _make_parametric_word(
    constant: int, terms: Iterable[_ParametricTerm]
) -> _ParametricWord:
    combined: dict[tuple[str, str | int], int] = defaultdict(int)
    for term in terms:
        identity = (term.source_kind, term.source)
        combined[identity] = (
            combined[identity] + term.coefficient
        ) & 0xFFFFFFFF
    normalized = tuple(
        _ParametricTerm(kind, source, coefficient)
        for (kind, source), coefficient in sorted(
            combined.items(), key=lambda item: (item[0][0], str(item[0][1]))
        )
        if coefficient
    )
    return _ParametricWord(constant & 0xFFFFFFFF, normalized)


def _combine_parametric_words(
    left: _Value, right: _Value, *, subtract: bool
) -> _Value:
    lhs = _as_parametric_word(left)
    rhs = _as_parametric_word(right)
    if lhs is None or rhs is None:
        return None
    sign = -1 if subtract else 1
    result = _make_parametric_word(
        lhs.constant + sign * rhs.constant,
        (
            *lhs.terms,
            *(
                _ParametricTerm(
                    term.source_kind,
                    term.source,
                    sign * term.coefficient,
                )
                for term in rhs.terms
            ),
        ),
    )
    return _Exact(result.constant) if not result.terms else result


def _multiply_parametric_words(left: _Value, right: _Value) -> _Value:
    if isinstance(left, _Exact):
        factor = left.value
        parametric = _as_parametric_word(right)
    elif isinstance(right, _Exact):
        factor = right.value
        parametric = _as_parametric_word(left)
    else:
        return None
    if parametric is None:
        return None
    result = _make_parametric_word(
        parametric.constant * factor,
        (
            _ParametricTerm(
                term.source_kind,
                term.source,
                term.coefficient * factor,
            )
            for term in parametric.terms
        ),
    )
    return _Exact(result.constant) if not result.terms else result


def _parametric_term_json(term: _ParametricTerm) -> dict[str, Any]:
    return {
        "source_kind": term.source_kind,
        "source": term.source,
        "coefficient": term.coefficient,
    }


def _parse_parametric_word(row: Mapping[str, Any]) -> _ParametricWord | None:
    if set(row) != {"kind", "constant", "terms"}:
        return None
    constant = _integer(row.get("constant"))
    raw_terms = row.get("terms")
    if constant is None or not isinstance(raw_terms, list) or not raw_terms:
        return None
    terms: list[_ParametricTerm] = []
    for raw in raw_terms:
        term = _mapping(raw)
        if set(term) != {"source_kind", "source", "coefficient"}:
            return None
        source_kind = term.get("source_kind")
        source = term.get("source")
        coefficient = _integer(term.get("coefficient"))
        if (
            source_kind == "input_register"
            and source not in _REGISTERS
        ) or (
            source_kind == "input_stack_word"
            and (
                not isinstance(source, int)
                or isinstance(source, bool)
                or source < 4
            )
        ) or source_kind not in {"input_register", "input_stack_word"} or (
            coefficient is None or coefficient == 0
        ):
            return None
        terms.append(_ParametricTerm(str(source_kind), source, coefficient))
    result = _make_parametric_word(constant, terms)
    return result if result.terms and len(result.terms) == len(terms) else None


def _parametric_word_from_location(
    location: ValueOrigin,
) -> _ParametricWord | None:
    if location.kind != "parametric_location" or len(location.key) != 2:
        return None
    constant = _integer(location.key[0])
    raw_terms = location.key[1]
    if constant is None or not isinstance(raw_terms, tuple) or not raw_terms:
        return None
    terms = []
    for raw in raw_terms:
        if not isinstance(raw, tuple) or len(raw) != 3:
            return None
        terms.append({
            "source_kind": raw[0],
            "source": raw[1],
            "coefficient": raw[2],
        })
    return _parse_parametric_word({
        "kind": "parametric_word",
        "constant": constant,
        "terms": terms,
    })


def _instantiate_parametric_word(
    value: _ParametricWord, *, input_state: _State
) -> _Value:
    result: _Value = _Exact(value.constant)
    for term in value.terms:
        if term.source_kind == "input_register":
            source = input_state.registers.get(str(term.source))
        else:
            source = _instantiate_summary_value(
                {"kind": "input_stack_word", "offset": int(term.source)},
                input_state=input_state,
            )
        scaled = _multiply_parametric_words(source, _Exact(term.coefficient))
        result = _combine_parametric_words(result, scaled, subtract=False)
        if result is None:
            return None
    return result


def _read_stack_word(state: _State, offset: int) -> _Value:
    if offset in state.stack_words:
        return state.stack_words[offset]
    if (
        not state.input_stack_valid
        or offset < 4
        or any(
            start < offset + 4 and offset < end
            for start, end in state.input_stack_kills
        )
    ):
        return None
    return _InputStackWord(offset)


def _add_killed_stack_range(
    ranges: tuple[tuple[int, int], ...],
    start: int,
    width: int,
    *,
    maximum: int,
) -> tuple[tuple[int, int], ...] | None:
    """Add one known stack overwrite to the entry-word invalidation set."""

    if width <= 0:
        return ranges
    pending_start = start
    pending_end = start + width
    merged: list[tuple[int, int]] = []
    inserted = False
    for old_start, old_end in ranges:
        if old_end < pending_start:
            merged.append((old_start, old_end))
        elif pending_end < old_start:
            if not inserted:
                merged.append((pending_start, pending_end))
                inserted = True
            merged.append((old_start, old_end))
        else:
            pending_start = min(pending_start, old_start)
            pending_end = max(pending_end, old_end)
    if not inserted:
        merged.append((pending_start, pending_end))
    return tuple(merged) if len(merged) <= maximum else None


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


def _join_states(
    left: _State,
    right: _State,
    *,
    max_value_alternatives: int,
) -> _State:
    registers = {
        register: _join_summary_value(
            left.registers.get(register),
            right.registers.get(register),
            maximum=max_value_alternatives,
        )
        for register in _REGISTERS
    }
    stack_words: dict[int, _Value] = {}
    for offset, value in left.stack_words.items():
        joined = _join_summary_value(
            value,
            right.stack_words.get(offset),
            maximum=max_value_alternatives,
        )
        if joined is not None:
            stack_words[offset] = joined
    memory_words: dict[ValueOrigin, _Value] = {}
    for location, value in left.memory_words.items():
        joined = _join_summary_value(
            value,
            right.memory_words.get(location),
            maximum=max_value_alternatives,
        )
        if joined is not None:
            memory_words[location] = joined
    input_stack_valid = left.input_stack_valid and right.input_stack_valid
    input_stack_kills: tuple[tuple[int, int], ...] = ()
    if input_stack_valid:
        for start, end in (*left.input_stack_kills, *right.input_stack_kills):
            updated = _add_killed_stack_range(
                input_stack_kills,
                start,
                end - start,
                maximum=max_value_alternatives,
            )
            if updated is None:
                input_stack_valid = False
                input_stack_kills = ()
                break
            input_stack_kills = updated
    return _State(
        registers=registers,
        stack_words=stack_words,
        memory_words=memory_words,
        input_stack_valid=input_stack_valid,
        input_stack_kills=input_stack_kills,
    )


def _join_summary_value(
    left: _Value, right: _Value, *, maximum: int
) -> _Value:
    if left == right:
        return left
    if isinstance(left, _TypedOrigins) and isinstance(right, _TypedOrigins):
        joined = set(left.origins) | set(right.origins)
        if len(joined) <= maximum:
            return _TypedOrigins(tuple(sorted(joined, key=_typed_origin_sort_key)))
    return None


def _unknown_state() -> _State:
    return _State(
        registers={register: None for register in _REGISTERS},
        stack_words={},
        input_stack_valid=False,
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
