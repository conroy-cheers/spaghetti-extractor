"""Cold-replayed stack provenance for mutable-memory alias exclusion.

The result is deliberately narrower than a general stack model.  It proves
only that the entry ESP for a machine-IR unit remains within the private stack
range declared by the launch profile, and that a represented ESP-relative
memory access stays inside that range.  Such accesses cannot alias the PE
image.  Unknown call frames, non-affine ESP transitions, and finite-domain
overflow stop propagation instead of widening to an arbitrary address.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import defaultdict, deque
from typing import Any, Mapping, Sequence

from .analysis_schema_v2 import CHECKED_MEMORY_RANGE_FACT_V2_FORMAT
from .address_expression_v2 import affine_register_offset
from .artifact_identity_v2 import canonical_sha256
from .authority_bindings_v2 import BinaryBinding
from .call_site_effects import CallSiteEffect, CallSiteId, parse_call_site_effects
from .checked_memory_access_v2 import (
    CheckedMemoryAccessFact,
    validate_checked_memory_access_facts_v2,
)
from .control_analysis_v2 import exact_control_inventory_v2
from .internal_call_summaries import checked_summary_preserved_registers


STACK_RANGE_ANALYSIS_V2_FORMAT = "spaghetti-extractor-stack-range-analysis-v2"
CHECKED_STACK_SPATIAL_FACT_V2_FORMAT = (
    "stage-a-checked-stack-spatial-fact-v2"
)
CHECKED_STACK_ORIGIN_SPATIAL_FACT_V2_FORMAT = (
    "stage-a-checked-stack-origin-spatial-fact-v2"
)
CHECKED_CALL_STACK_WRITE_SPATIAL_FACT_V2_FORMAT = (
    "stage-a-checked-call-stack-write-spatial-fact-v2"
)
_STACK_BASE = {"op": "reg", "name": "esp", "width": 32}
_UINT32 = 1 << 32
_StackState = tuple[int, int, int | None]
# (launch-relative ESP, active call-frame base, launch-relative EBP)


def derive_stack_range_analysis_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    graph: Mapping[str, Any],
    launch_assumptions: Mapping[str, Any],
    pe_sha256: str,
    machine_ir_sha256: str,
    image_base: int,
    size_of_image: int,
    call_summaries: Mapping[str, Any] | None = None,
    indirect_recoveries: Sequence[Mapping[str, Any]] = (),
    call_site_effects: Sequence[Mapping[str, Any]] = (),
    checked_memory_access_facts: Sequence[Mapping[str, Any]] = (),
    interprocedural_authority_sha256: str | None = None,
    finite_offset_budget: int = 256,
) -> dict[str, Any]:
    """Derive checked ESP-relative ranges and reproduce them from empty state."""

    if not 0 < finite_offset_budget <= 4096:
        raise ValueError("finite stack-offset budget must be between 1 and 4096")
    normalized_units = _normalize_units(units)
    roots = _root_ids(graph, normalized_units)
    stack_contract = _stack_contract(launch_assumptions)
    summaries = _complete_summary_index(call_summaries or {})
    effects = _checked_call_site_effects(
        call_site_effects,
        units=normalized_units,
        finite_value_budget=finite_offset_budget,
    )
    effects_sha256 = canonical_sha256([
        effect.as_json() for effect in effects.values()
    ])
    access_facts = _checked_memory_access_facts(
        checked_memory_access_facts,
        units=normalized_units,
        pe_sha256=pe_sha256,
        machine_ir_sha256=machine_ir_sha256,
        interprocedural_authority_sha256=interprocedural_authority_sha256,
    )
    exact = exact_control_inventory_v2(tuple(normalized_units.values()))
    first = _run(
        units=normalized_units,
        roots=roots,
        exact=exact,
        stack_contract=stack_contract,
        summaries=summaries,
        call_site_effects=effects,
        indirect_recoveries=indirect_recoveries,
        finite_offset_budget=finite_offset_budget,
    )
    second = _run(
        units=normalized_units,
        roots=roots,
        exact=exact,
        stack_contract=stack_contract,
        summaries=summaries,
        call_site_effects=effects,
        indirect_recoveries=indirect_recoveries,
        finite_offset_budget=finite_offset_budget,
    )
    first_sha = canonical_sha256(first)
    second_sha = canonical_sha256(second)
    cold_valid = first_sha == second_sha
    issues = list(first["issues"])
    if not cold_valid:
        issues.append({"status": "violated", "code": "cold_replay_mismatch"})
    graph_id = graph.get("id")
    if not isinstance(graph_id, str) or not graph_id:
        issues.append({"status": "violated", "code": "rooted_graph_binding_invalid"})
        graph_id = "invalid-rooted-graph"
    binding = {
        "pe_sha256": _digest(pe_sha256, "PE SHA-256"),
        "machine_ir_sha256": _digest(machine_ir_sha256, "machine-IR SHA-256"),
        "rooted_graph_id": graph_id,
        "launch_assumptions_sha256": canonical_sha256(launch_assumptions),
        "image_base": _u32(image_base, "image base"),
        "size_of_image": _positive_u32(size_of_image, "image size"),
        "call_site_effects_sha256": effects_sha256,
    }
    if binding["image_base"] + binding["size_of_image"] > _UINT32:
        raise ValueError("PE image range wraps the 32-bit address space")
    facts = [
        _range_fact(
            unit_id=unit_id,
            span=span,
            binding=binding,
            image_base=image_base,
            size_of_image=size_of_image,
        )
        for unit_id, span in sorted(first["access_spans"].items())
    ]
    spatial_facts = _spatial_facts(
        units=normalized_units,
        entry_offsets=first["entry_offsets"],
        frame_base_offsets=first["frame_base_offsets"],
        call_site_effects=effects,
        checked_memory_access_facts=access_facts,
        binding=binding,
        stack_contract=stack_contract,
        image_base=image_base,
        size_of_image=size_of_image,
    )
    statuses = [
        str(issue["status"])
        for issue in (*issues, *first["frontiers"])
    ]
    status = (
        "violated"
        if "violated" in statuses
        else "incomplete" if statuses else "complete"
    )
    body = {
        "format": STACK_RANGE_ANALYSIS_V2_FORMAT,
        "status": status,
        "binding": binding,
        "counts": {
            "units": len(normalized_units),
            "root_units": len(roots),
            "stack_entry_units": len(first["entry_offsets"]),
            "checked_range_facts": len(facts),
            "checked_spatial_facts": len(spatial_facts),
            "frontiers": len(first["frontiers"]),
        },
        "entry_offsets": first["entry_offsets"],
        "frame_base_offsets": first["frame_base_offsets"],
        "checked_range_facts": facts,
        "checked_spatial_facts": spatial_facts,
        "frontiers": first["frontiers"],
        "issues": sorted(
            _deduplicate(issues),
            key=lambda row: (
                str(row.get("status")),
                str(row.get("code")),
                str(row.get("unit_id", "")),
            ),
        ),
        "cold_replay": {
            "status": "complete" if cold_valid else "violated",
            "deterministic": cold_valid,
            "empty_initial_state": True,
            "target_proposals_used": bool(indirect_recoveries),
            "unseeded": not bool(indirect_recoveries),
            "first_sha256": first_sha,
            "replay_sha256": second_sha,
        },
    }
    return {**body, "analysis_sha256": canonical_sha256(body)}


def _run(
    *,
    units: Mapping[str, Mapping[str, Any]],
    roots: Sequence[str],
    exact: Mapping[str, Sequence[Mapping[str, Any]]],
    stack_contract: Mapping[str, int],
    summaries: Mapping[int, Mapping[str, Any]],
    call_site_effects: Mapping[CallSiteId, CallSiteEffect],
    indirect_recoveries: Sequence[Mapping[str, Any]],
    finite_offset_budget: int,
) -> dict[str, Any]:
    by_rva = {
        int(unit["source"]["original"]["rva_start"]): unit_id
        for unit_id, unit in units.items()
    }
    normal: dict[str, set[str]] = defaultdict(set)
    for edge in exact["direct_edges"]:
        normal[str(edge["source_unit_id"])].add(str(edge["target_unit_id"]))
    calls: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for edge in exact["internal_call_edges"]:
        calls[str(edge["source_unit_id"])].append(edge)
    recoveries = {
        str(row.get("id")): row
        for row in indirect_recoveries
        if isinstance(row, Mapping)
        and isinstance(row.get("id"), str)
        and row.get("status") == "recovered"
    }
    exit_by_source = {
        str(row["source_unit_id"]): row
        for row in exact["indirect_exits"]
        if isinstance(row.get("source_unit_id"), str)
    }

    entry: dict[str, frozenset[_StackState]] = {
        root: frozenset({(0, 0, None)}) for root in roots if root in units
    }
    pending = deque(sorted(entry))
    queued = set(pending)
    incomplete_entry_units: set[str] = set()
    frontiers: list[dict[str, Any]] = []
    evaluations = 0
    maximum_evaluations = max(
        8, len(units) * (finite_offset_budget + 2)
    )
    while pending and evaluations < maximum_evaluations:
        unit_id = pending.popleft()
        queued.discard(unit_id)
        evaluations += 1
        unit = units[unit_id]
        states = entry[unit_id]
        transitions, transition_frontiers = _successor_offsets(
            unit_id=unit_id,
            unit=unit,
            states=states,
            normal_targets=normal.get(unit_id, set()),
            call_edges=calls.get(unit_id, ()),
            by_rva=by_rva,
            summaries=summaries,
            call_site_effects=call_site_effects,
            recovery=(
                recoveries.get(str(exit_by_source[unit_id]["id"]))
                if unit_id in exit_by_source
                else None
            ),
        )
        frontiers.extend(transition_frontiers)
        for target, values in sorted(transitions.items()):
            target_was_incomplete = target in incomplete_entry_units
            bounded = {
                state
                for state in values
                if (
                    -stack_contract["bytes_below"]
                    <= state[0]
                    <= stack_contract["bytes_above"]
                    and -stack_contract["bytes_below"]
                    <= state[1]
                    <= stack_contract["bytes_above"]
                    and (
                        state[2] is None
                        or -stack_contract["bytes_below"]
                        <= state[2]
                        <= stack_contract["bytes_above"]
                    )
                )
            }
            if len(bounded) != len(values):
                frontiers.append({
                    "status": "incomplete",
                    "code": "stack_offset_outside_launch_window",
                    "unit_id": unit_id,
                    "target_unit_id": target,
                })
                incomplete_entry_units.add(target)
            prior = entry.get(target, frozenset())
            joined = prior | frozenset(bounded)
            if len(joined) > finite_offset_budget:
                frontiers.append({
                    "status": "incomplete",
                    "code": "stack_offset_alternative_budget_exceeded",
                    "unit_id": target,
                    "budget": finite_offset_budget,
                })
                incomplete_entry_units.add(target)
                joined = frozenset(
                    sorted(joined, key=_stack_state_sort_key)[
                        :finite_offset_budget
                    ]
                )
            if unit_id in incomplete_entry_units:
                incomplete_entry_units.add(target)
            target_became_incomplete = (
                target in incomplete_entry_units and not target_was_incomplete
            )
            if joined != prior:
                entry[target] = joined
                if target not in queued:
                    pending.append(target)
                    queued.add(target)
            elif target_became_incomplete and target not in queued:
                pending.append(target)
                queued.add(target)
    if pending:
        frontiers.append({
            "status": "incomplete",
            "code": "stack_provenance_worklist_budget_exceeded",
            "evaluations": evaluations,
        })

    checked_entry = {
        unit_id: states
        for unit_id, states in entry.items()
        if unit_id not in incomplete_entry_units
    }
    entry_offsets = {
        unit_id: sorted({state[0] for state in states})
        for unit_id, states in checked_entry.items()
    }
    frame_base_offsets = {
        unit_id: sorted({state[1] for state in states})
        for unit_id, states in checked_entry.items()
    }
    access_spans: dict[str, tuple[int, int]] = {}
    for unit_id in sorted(checked_entry):
        span = _esp_access_span(units[unit_id])
        if span is None:
            continue
        lower, upper = span
        if all(
            -stack_contract["bytes_below"] <= base + lower
            and base + upper <= stack_contract["bytes_above"]
            for base in entry_offsets[unit_id]
        ):
            access_spans[unit_id] = span
        else:
            frontiers.append({
                "status": "incomplete",
                "code": "stack_access_outside_launch_window",
                "unit_id": unit_id,
                "offset_start": lower,
                "offset_end": upper,
            })
    issues = [
        copy.deepcopy(dict(issue))
        for issue in exact.get("issues", ())
        if issue.get("status") == "violated"
    ]
    return {
        "entry_offsets": dict(sorted(entry_offsets.items())),
        "frame_base_offsets": dict(sorted(frame_base_offsets.items())),
        "access_spans": access_spans,
        "frontiers": sorted(
            _deduplicate(frontiers),
            key=lambda row: (
                str(row.get("code")),
                str(row.get("unit_id", "")),
                str(row.get("target_unit_id", "")),
            ),
        ),
        "issues": issues,
    }


def _successor_offsets(
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    states: frozenset[_StackState],
    normal_targets: set[str],
    call_edges: Sequence[Mapping[str, Any]],
    by_rva: Mapping[int, str],
    summaries: Mapping[int, Mapping[str, Any]],
    call_site_effects: Mapping[CallSiteId, CallSiteEffect],
    recovery: Mapping[str, Any] | None,
) -> tuple[dict[str, set[_StackState]], list[dict[str, Any]]]:
    semantics = unit["semantics"]
    events = semantics.get("external_events", [])
    call_events = [
        (index, event)
        for index, event in enumerate(events)
        if isinstance(event, Mapping)
        and event.get("kind") in {"internal_call", "external_call", "indirect_call"}
    ] if isinstance(events, list) else []
    transitions: dict[str, set[_StackState]] = defaultdict(set)
    frontiers: list[dict[str, Any]] = []

    if not call_events:
        successor_states = _ordinary_successor_states(semantics, states)
        if successor_states is None and normal_targets:
            frontiers.append({
                "status": "incomplete",
                "code": "non_affine_stack_transition",
                "unit_id": unit_id,
            })
        elif successor_states is not None:
            for target in normal_targets:
                transitions[target].update(successor_states)
            if recovery is not None and recovery.get("kind") == "indirect_jump":
                for target in recovery.get("target_unit_ids", ()):
                    if isinstance(target, str):
                        transitions[target].update(successor_states)
        return transitions, frontiers

    if len(call_events) != 1:
        frontiers.append({
            "status": "incomplete",
            "code": "multiple_call_frames_in_unit",
            "unit_id": unit_id,
        })
        return transitions, frontiers
    event_index, event = call_events[0]
    effect = call_site_effects.get(CallSiteId(unit_id, event_index))
    event_esp = _affine_esp_offset(
        _mapping(event.get("register_inputs")).get("esp")
    )
    if event_esp is None:
        frontiers.append({
            "status": "incomplete",
            "code": "call_stack_input_non_affine",
            "unit_id": unit_id,
            "event_index": event_index,
        })
        return transitions, frontiers
    event_ebp_expression = _mapping(event.get("register_inputs")).get("ebp")
    event_states = [
        (
            esp + event_esp,
            frame_base,
            _evaluate_stack_expression(
                event_ebp_expression,
                esp=esp,
                ebp=ebp,
            ),
        )
        for esp, frame_base, ebp in states
    ]

    kind = event.get("kind")
    if kind == "internal_call":
        target_rva = event.get("target_rva")
        target = by_rva.get(target_rva) if isinstance(target_rva, int) else None
        if target is not None:
            transitions[target].update(
                (event_esp_value - 4, event_esp_value - 4, event_ebp)
                for event_esp_value, _frame_base, event_ebp in event_states
            )
        cleanup = _call_effect_cleanup(effect)
        if effect is None:
            cleanup = _internal_cleanup(target_rva, summaries)
        if cleanup is None:
            frontiers.append({
                "status": "incomplete",
                "code": "internal_call_frame_incomplete",
                "unit_id": unit_id,
                "event_index": event_index,
                "target_rva": target_rva,
            })
        else:
            ebp_preserved = _call_effect_preserves(effect, "ebp")
            if effect is None:
                ebp_preserved = _internal_preserves(
                    target_rva, summaries, "ebp"
                )
            for target_id in normal_targets:
                transitions[target_id].update(
                    (
                        event_esp_value + cleanup,
                        frame_base,
                        event_ebp if ebp_preserved else None,
                    )
                    for event_esp_value, frame_base, event_ebp in event_states
                )
        return transitions, frontiers

    if kind == "external_call":
        # A terminal external transfer has no local continuation whose stack
        # state must be reconstructed.  Its external-site contract remains
        # responsible for the transfer itself, but stack closure must not
        # invent a returning frame obligation for a tail jump.
        if not normal_targets:
            return transitions, frontiers
        cleanup = _call_effect_cleanup(effect)
        checked_effect = effect is not None
        if effect is None:
            cleanup = _external_cleanup(event)
        disposition = _mapping(event.get("abi_contract")).get("disposition")
        if cleanup is None or (
            not checked_effect
            and disposition not in {"returns", "may_return"}
        ):
            if disposition not in {"terminates", "noreturn"}:
                frontiers.append({
                    "status": "incomplete",
                    "code": "external_call_frame_incomplete",
                    "unit_id": unit_id,
                    "event_index": event_index,
                })
        else:
            ebp_preserved = _call_effect_preserves(effect, "ebp")
            if effect is None:
                ebp_preserved = _external_preserves(event, "ebp")
            for target_id in normal_targets:
                transitions[target_id].update(
                    (
                        event_esp_value + cleanup,
                        frame_base,
                        event_ebp if ebp_preserved else None,
                    )
                    for event_esp_value, frame_base, event_ebp in event_states
                )
        return transitions, frontiers

    recovery_cleanup, target_units, recovery_preserves_ebp = _indirect_cleanup(
        recovery, summaries=summaries
    )
    cleanup = _call_effect_cleanup(effect)
    if effect is None:
        cleanup = recovery_cleanup
    for target in target_units:
        transitions[target].update(
            (event_esp_value - 4, event_esp_value - 4, event_ebp)
            for event_esp_value, _frame_base, event_ebp in event_states
        )
    if cleanup is None:
        frontiers.append({
            "status": "incomplete",
            "code": "indirect_call_frame_unresolved",
            "unit_id": unit_id,
            "event_index": event_index,
        })
    else:
        ebp_preserved = _call_effect_preserves(effect, "ebp")
        if effect is None:
            ebp_preserved = recovery_preserves_ebp
        for target_id in normal_targets:
            transitions[target_id].update(
                (
                    event_esp_value + cleanup,
                    frame_base,
                    event_ebp if ebp_preserved else None,
                )
                for event_esp_value, frame_base, event_ebp in event_states
            )
    return transitions, frontiers


def _range_fact(
    *,
    unit_id: str,
    span: tuple[int, int],
    binding: Mapping[str, Any],
    image_base: int,
    size_of_image: int,
) -> dict[str, Any]:
    core = {
        "format": CHECKED_MEMORY_RANGE_FACT_V2_FORMAT,
        "status": "complete",
        "source_kind": "entry",
        "range_kind": "stack",
        "base_expression": _STACK_BASE,
        "offset_start": span[0],
        "offset_end": span[1],
        "applies_to_unit_ids": [unit_id],
        "disjoint_from_image": {
            "image_base": image_base,
            "size_of_image": size_of_image,
        },
        "authority_binding": copy.deepcopy(dict(binding)),
    }
    return {**core, "id": "checked-stack-range-v2:" + canonical_sha256(core)}


def _spatial_facts(
    *,
    units: Mapping[str, Mapping[str, Any]],
    entry_offsets: Mapping[str, Sequence[int]],
    frame_base_offsets: Mapping[str, Sequence[int]],
    call_site_effects: Mapping[CallSiteId, CallSiteEffect],
    checked_memory_access_facts: Mapping[str, CheckedMemoryAccessFact],
    binding: Mapping[str, Any],
    stack_contract: Mapping[str, int],
    image_base: int,
    size_of_image: int,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    lower_bound = -int(stack_contract["bytes_below"])
    upper_bound = int(stack_contract["bytes_above"])
    for unit_id, offsets in sorted(entry_offsets.items()):
        if unit_id not in units or not offsets:
            continue
        events = units[unit_id]["semantics"].get("memory_events")
        if not isinstance(events, list):
            continue
        for event_index, raw in enumerate(events):
            if not isinstance(raw, Mapping):
                continue
            memory_kind = raw.get("kind")
            width = raw.get("width")
            if (
                memory_kind not in {"read", "write", "read_write"}
                or not isinstance(width, int)
                or isinstance(width, bool)
                or not 0 < width <= 4096
            ):
                continue
            address_offset = _affine_esp_offset(raw.get("address"))
            if address_offset is not None:
                starts = [int(base) + address_offset for base in offsets]
                if not starts or any(
                    start < lower_bound or start + width > upper_bound
                    for start in starts
                ):
                    continue
                core = {
                    "format": CHECKED_STACK_SPATIAL_FACT_V2_FORMAT,
                    "status": "complete",
                    "unit_id": unit_id,
                    "event_index": event_index,
                    "memory_kind": memory_kind,
                    "width_bytes": width,
                    "address_expression": copy.deepcopy(raw.get("address")),
                    "entry_esp_offsets": sorted(
                        set(int(value) for value in offsets)
                    ),
                    "address_esp_offset": address_offset,
                    "minimum_start_offset": min(starts),
                    "maximum_start_offset": max(starts),
                    "stack_contract": {
                        "lower_bound": lower_bound,
                        "upper_bound_exclusive": upper_bound,
                    },
                    "disjoint_from_image": {
                        "image_base": image_base,
                        "size_of_image": size_of_image,
                    },
                    "authority_binding": copy.deepcopy(dict(binding)),
                }
                result.append(_seal_spatial_fact(
                    core, prefix="checked-stack-spatial-v2:"
                ))
                continue

            event_node = f"event:{unit_id}:{event_index}"
            access_fact = checked_memory_access_facts.get(event_node)
            origin_offsets = (
                None
                if access_fact is None
                else _stack_origin_offsets(access_fact)
            )
            frame_offsets = frame_base_offsets.get(unit_id, ())
            if origin_offsets is None or not frame_offsets:
                continue
            starts = [
                int(frame_base) + int(origin_offset)
                for frame_base in frame_offsets
                for origin_offset in origin_offsets
            ]
            if not starts or any(
                start < lower_bound or start + width > upper_bound
                for start in starts
            ):
                continue
            core = {
                "format": CHECKED_STACK_ORIGIN_SPATIAL_FACT_V2_FORMAT,
                "status": "complete",
                "unit_id": unit_id,
                "event_index": event_index,
                "memory_kind": memory_kind,
                "width_bytes": width,
                "address_expression": copy.deepcopy(raw.get("address")),
                "memory_access_fact_id": access_fact.fact_id,
                "memory_access_fact_sha256": access_fact.to_payload()[
                    "fact_sha256"
                ],
                "address_origins": [
                    origin.to_value() for origin in access_fact.address_origins
                ],
                "frame_base_offsets": sorted(
                    set(int(value) for value in frame_offsets)
                ),
                "minimum_start_offset": min(starts),
                "maximum_start_offset": max(starts),
                "stack_contract": {
                    "lower_bound": lower_bound,
                    "upper_bound_exclusive": upper_bound,
                },
                "disjoint_from_image": {
                    "image_base": image_base,
                    "size_of_image": size_of_image,
                },
                "authority_binding": copy.deepcopy(dict(binding)),
            }
            result.append(_seal_spatial_fact(
                core, prefix="checked-stack-origin-spatial-v2:"
            ))
    result.extend(_call_stack_write_spatial_facts(
        frame_base_offsets=frame_base_offsets,
        call_site_effects=call_site_effects,
        binding=binding,
        stack_contract=stack_contract,
        image_base=image_base,
        size_of_image=size_of_image,
    ))
    return sorted(
        result,
        key=lambda row: (
            str(row["unit_id"]),
            int(row["event_index"]),
            int(row.get("write_index", -1)),
            str(row["id"]),
        ),
    )


def _call_stack_write_spatial_facts(
    *,
    frame_base_offsets: Mapping[str, Sequence[int]],
    call_site_effects: Mapping[CallSiteId, CallSiteEffect],
    binding: Mapping[str, Any],
    stack_contract: Mapping[str, int],
    image_base: int,
    size_of_image: int,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    lower_bound = -int(stack_contract["bytes_below"])
    upper_bound = int(stack_contract["bytes_above"])
    for site, effect in sorted(
        call_site_effects.items(),
        key=lambda item: (item[0].unit_id, item[0].event_index),
    ):
        frame_offsets = frame_base_offsets.get(site.unit_id, ())
        if effect.memory_frame_status != "complete" or not frame_offsets:
            continue
        effect_payload = effect.as_json()
        effect_sha256 = canonical_sha256(effect_payload)
        for write_index, span in enumerate(effect.memory_writes):
            offset = _signed_stack_origin_offset(span.base)
            width = span.size
            if (
                offset is None
                or not isinstance(width, int)
                or isinstance(width, bool)
                or not 0 < width <= 4096
            ):
                continue
            starts = [int(frame_base) + offset for frame_base in frame_offsets]
            if not starts or any(
                start < lower_bound or start + width > upper_bound
                for start in starts
            ):
                continue
            core = {
                "format": CHECKED_CALL_STACK_WRITE_SPATIAL_FACT_V2_FORMAT,
                "status": "complete",
                "unit_id": site.unit_id,
                "event_index": site.event_index,
                "write_index": write_index,
                "memory_kind": "write",
                "width_bytes": width,
                "address_origin": span.base.as_json(),
                "call_site_effect_sha256": effect_sha256,
                "frame_base_offsets": sorted(
                    set(int(value) for value in frame_offsets)
                ),
                "address_frame_offset": offset,
                "minimum_start_offset": min(starts),
                "maximum_start_offset": max(starts),
                "stack_contract": {
                    "lower_bound": lower_bound,
                    "upper_bound_exclusive": upper_bound,
                },
                "disjoint_from_image": {
                    "image_base": image_base,
                    "size_of_image": size_of_image,
                },
                "authority_binding": copy.deepcopy(dict(binding)),
            }
            result.append(_seal_spatial_fact(
                core, prefix="checked-call-stack-write-spatial-v2:"
            ))
    return result


def _signed_stack_origin_offset(origin: Any) -> int | None:
    if origin.kind != "stack_location" or len(origin.key) != 1:
        return None
    raw = origin.key[0]
    if (
        not isinstance(raw, int)
        or isinstance(raw, bool)
        or not 0 <= raw < _UINT32
    ):
        return None
    return raw if raw < (1 << 31) else raw - _UINT32


def _seal_spatial_fact(
    core: Mapping[str, Any], *, prefix: str
) -> dict[str, Any]:
    identity = prefix + canonical_sha256(core)
    payload = {**copy.deepcopy(dict(core)), "id": identity}
    return {**payload, "fact_sha256": canonical_sha256(payload)}


def _stack_origin_offsets(
    fact: CheckedMemoryAccessFact,
) -> tuple[int, ...] | None:
    offsets: set[int] = set()
    for raw in fact.address_origins:
        origin = raw.to_value()
        key = origin.get("key") if isinstance(origin, Mapping) else None
        if (
            not isinstance(origin, Mapping)
            or origin.get("kind") != "stack_location"
            or not isinstance(key, list)
            or len(key) != 1
            or not isinstance(key[0], int)
            or isinstance(key[0], bool)
        ):
            return None
        offsets.add(int(key[0]))
    return tuple(sorted(offsets)) if offsets else None


def validate_checked_stack_range_facts_v2(
    facts: Sequence[Mapping[str, Any]],
    *,
    units: Sequence[Mapping[str, Any]],
    pe_sha256: str,
    machine_ir_sha256: str,
    rooted_graph_id: str,
    launch_assumptions_sha256: str,
    image_base: int,
    size_of_image: int,
    call_site_effects_sha256: str | None = None,
) -> frozenset[str]:
    """Replay exact stack facts and return their authorized unit IDs."""

    by_id = _normalize_units(units)
    accepted: set[str] = set()
    for raw in facts:
        if not isinstance(raw, Mapping):
            raise ValueError("checked stack-range fact must be an object")
        binding = raw.get("authority_binding")
        unit_ids = raw.get("applies_to_unit_ids")
        if (
            not isinstance(binding, Mapping)
            or not isinstance(unit_ids, list)
            or len(unit_ids) != 1
            or not isinstance(unit_ids[0], str)
            or unit_ids[0] not in by_id
        ):
            raise ValueError("checked stack-range fact binding is malformed")
        unit_id = unit_ids[0]
        if unit_id in accepted:
            raise ValueError("checked stack-range unit is duplicated")
        span = _esp_access_span(by_id[unit_id])
        if span is None:
            raise ValueError("checked stack-range unit has no ESP-relative access")
        expected_binding = {
            "pe_sha256": pe_sha256,
            "machine_ir_sha256": machine_ir_sha256,
            "rooted_graph_id": rooted_graph_id,
            "launch_assumptions_sha256": launch_assumptions_sha256,
            "image_base": image_base,
            "size_of_image": size_of_image,
            "call_site_effects_sha256": (
                _digest(
                    call_site_effects_sha256,
                    "call-site effects SHA-256",
                )
                if call_site_effects_sha256 is not None
                else canonical_sha256([])
            ),
        }
        if dict(binding) != expected_binding:
            raise ValueError("checked stack-range fact authority binding is stale")
        expected = _range_fact(
            unit_id=unit_id,
            span=span,
            binding=expected_binding,
            image_base=image_base,
            size_of_image=size_of_image,
        )
        if dict(raw) != expected:
            raise ValueError("checked stack-range fact does not replay exactly")
        accepted.add(unit_id)
    return frozenset(accepted)


def validate_stack_range_analysis_v2(
    analysis: Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]],
    graph: Mapping[str, Any],
    launch_assumptions: Mapping[str, Any],
    pe_sha256: str,
    machine_ir_sha256: str,
    image_base: int,
    size_of_image: int,
    call_summaries: Mapping[str, Any] | None = None,
    indirect_recoveries: Sequence[Mapping[str, Any]] = (),
    call_site_effects: Sequence[Mapping[str, Any]] = (),
    checked_memory_access_facts: Sequence[Mapping[str, Any]] = (),
    interprocedural_authority_sha256: str | None = None,
    finite_offset_budget: int = 256,
) -> dict[str, Mapping[str, Any]]:
    """Replay the complete stack analysis and index exact spatial facts.

    Consumers must not authorize a submitted range merely because its shape
    and hashes are self-consistent.  Re-deriving the analysis checks the rooted
    call/return propagation that justifies every entry-ESP alternative.
    """

    expected = derive_stack_range_analysis_v2(
        units=units,
        graph=graph,
        launch_assumptions=launch_assumptions,
        pe_sha256=pe_sha256,
        machine_ir_sha256=machine_ir_sha256,
        image_base=image_base,
        size_of_image=size_of_image,
        call_summaries=call_summaries,
        indirect_recoveries=indirect_recoveries,
        call_site_effects=call_site_effects,
        checked_memory_access_facts=checked_memory_access_facts,
        interprocedural_authority_sha256=(
            interprocedural_authority_sha256
        ),
        finite_offset_budget=finite_offset_budget,
    )
    if dict(analysis) != expected:
        raise ValueError("stack-range analysis does not replay exactly")
    result: dict[str, Mapping[str, Any]] = {}
    for row in expected["checked_spatial_facts"]:
        event_id = _spatial_fact_event_id(row)
        if event_id in result:
            raise ValueError("stack spatial facts duplicate an exact event")
        result[event_id] = row
    return dict(sorted(result.items()))


def _spatial_fact_event_id(row: Mapping[str, Any]) -> str:
    if row.get("format") == CHECKED_CALL_STACK_WRITE_SPATIAL_FACT_V2_FORMAT:
        return (
            f"call-memory-write:{row['unit_id']}:{row['event_index']}:"
            f"{row['write_index']}"
        )
    return f"event:{row['unit_id']}:{row['event_index']}"


def _normalize_units(
    units: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for raw in units:
        if not isinstance(raw, Mapping):
            raise ValueError("machine-IR unit must be an object")
        unit_id = raw.get("id")
        semantics = raw.get("semantics")
        source = raw.get("source")
        original = source.get("original") if isinstance(source, Mapping) else None
        if (
            not isinstance(unit_id, str)
            or not unit_id
            or unit_id in result
            or not isinstance(semantics, Mapping)
            or not isinstance(original, Mapping)
            or not isinstance(original.get("rva_start"), int)
        ):
            raise ValueError("machine-IR unit binding is invalid")
        result[unit_id] = copy.deepcopy(dict(raw))
    return dict(sorted(result.items()))


def _root_ids(
    graph: Mapping[str, Any], units: Mapping[str, Mapping[str, Any]]
) -> list[str]:
    roots: list[str] = []
    for raw in graph.get("roots", ()):
        unit_id = raw if isinstance(raw, str) else raw.get("unit_id") if isinstance(raw, Mapping) else None
        kind = "pe" if isinstance(raw, str) else raw.get("kind") if isinstance(raw, Mapping) else None
        if isinstance(unit_id, str) and unit_id in units and kind in {
            "pe", "pe_entrypoint", "pe_export", "pe_tls_callback", "event_callback", "registered_callback"
        }:
            roots.append(unit_id)
    if not roots:
        raise ValueError("stack provenance requires an exact behavioral root")
    return sorted(set(roots))


def _stack_contract(value: Mapping[str, Any]) -> dict[str, int]:
    assumptions = value.get("assumptions")
    if not isinstance(assumptions, Mapping):
        raise ValueError("launch assumptions are missing")
    raw = assumptions.get("initial_stack")
    if not isinstance(raw, Mapping):
        raise ValueError("initial-stack launch assumption is missing")
    if (
        raw.get("contract") != "private-non-image-stack-range-v2"
        or raw.get("mapped_separately_from_image") is not True
    ):
        raise ValueError("initial-stack launch assumption is not range-qualified")
    below = raw.get("minimum_accessible_bytes_below")
    above = raw.get("minimum_accessible_bytes_above")
    if (
        not isinstance(below, int)
        or isinstance(below, bool)
        or not 0 < below < _UINT32
        or not isinstance(above, int)
        or isinstance(above, bool)
        or not 0 < above < _UINT32
    ):
        raise ValueError("initial-stack launch window is invalid")
    return {"bytes_below": below, "bytes_above": above}


def _complete_summary_index(value: Mapping[str, Any]) -> dict[int, Mapping[str, Any]]:
    result: dict[int, Mapping[str, Any]] = {}
    rows = value.get("summaries", ())
    if not isinstance(rows, list):
        return result
    for raw in rows:
        if not isinstance(raw, Mapping):
            continue
        if _summary_cleanup(raw) is None:
            continue
        rva = raw.get("target_rva")
        if isinstance(rva, int) and not isinstance(rva, bool):
            result[rva] = raw
    return result


def _checked_call_site_effects(
    rows: Sequence[Mapping[str, Any]],
    *,
    units: Mapping[str, Mapping[str, Any]],
    finite_value_budget: int,
) -> dict[CallSiteId, CallSiteEffect]:
    effects = parse_call_site_effects(
        rows,
        finite_value_budget=finite_value_budget,
    )
    for site, effect in effects.items():
        unit = units.get(site.unit_id)
        semantics = unit.get("semantics") if isinstance(unit, Mapping) else None
        events = (
            semantics.get("external_events")
            if isinstance(semantics, Mapping)
            else None
        )
        if (
            not isinstance(events, list)
            or not 0 <= site.event_index < len(events)
            or not isinstance(events[site.event_index], Mapping)
            or events[site.event_index].get("kind") != effect.transfer_kind
        ):
            raise ValueError(
                "call-site effect does not bind an exact stack transition"
            )
    return dict(sorted(
        effects.items(),
        key=lambda item: (item[0].unit_id, item[0].event_index),
    ))


def _checked_memory_access_facts(
    rows: Sequence[Mapping[str, Any]],
    *,
    units: Mapping[str, Mapping[str, Any]],
    pe_sha256: str,
    machine_ir_sha256: str,
    interprocedural_authority_sha256: str | None,
) -> dict[str, CheckedMemoryAccessFact]:
    if not rows:
        return {}
    if interprocedural_authority_sha256 is None:
        raise ValueError(
            "checked memory-access facts require interprocedural authority"
        )
    return validate_checked_memory_access_facts_v2(
        rows,
        units=list(units.values()),
        binary=BinaryBinding(
            pe_sha256=pe_sha256,
            machine_ir_sha256=machine_ir_sha256,
        ),
        interprocedural_authority_sha256=interprocedural_authority_sha256,
    )


def _call_effect_cleanup(effect: CallSiteEffect | None) -> int | None:
    if effect is None or effect.stack_frame_status != "complete":
        return None
    return effect.stack_cleanup_bytes


def _call_effect_preserves(
    effect: CallSiteEffect | None, register: str
) -> bool:
    return bool(
        effect is not None
        and effect.register_frame_status == "complete"
        and register in effect.preserved_registers
    )


def _internal_cleanup(
    target_rva: Any, summaries: Mapping[int, Mapping[str, Any]]
) -> int | None:
    summary = summaries.get(target_rva) if isinstance(target_rva, int) else None
    return _summary_cleanup(summary) if isinstance(summary, Mapping) else None


def _internal_preserves(
    target_rva: Any,
    summaries: Mapping[int, Mapping[str, Any]],
    register: str,
) -> bool:
    summary = summaries.get(target_rva) if isinstance(target_rva, int) else None
    return bool(
        isinstance(summary, Mapping)
        and register in checked_summary_preserved_registers(summary)
    )


def _summary_cleanup(summary: Mapping[str, Any]) -> int | None:
    stack = summary.get("stack_cleanup")
    stack_delta = (
        stack.get("stack_delta")
        if isinstance(stack, Mapping) and stack.get("status") == "complete"
        else None
    )
    instruction = summary.get("return_instruction_cleanup")
    instruction_delta = (
        instruction.get("cleanup_bytes")
        if isinstance(instruction, Mapping)
        and instruction.get("status") == "complete"
        else None
    )
    values = {
        value
        for value in (stack_delta, instruction_delta)
        if isinstance(value, int) and not isinstance(value, bool)
    }
    return next(iter(values)) if len(values) == 1 else None


def _external_cleanup(event: Mapping[str, Any]) -> int | None:
    abi = event.get("abi_contract")
    if not isinstance(abi, Mapping):
        return None
    if abi.get("disposition") != "returns":
        return None
    words = abi.get("argument_words")
    template = abi.get("template")
    if not isinstance(words, int) or isinstance(words, bool) or words < 0:
        return None
    if template in {"pe32-stdcall-v1", "pe32-thiscall-v1"}:
        return words * 4
    if template in {"pe32-cdecl-v1", "pe32-cdecl-varargs-v1"}:
        return 0
    return None


def _external_preserves(event: Mapping[str, Any], register: str) -> bool:
    abi = event.get("abi_contract")
    if not isinstance(abi, Mapping):
        return False
    raw = abi.get("preserved_registers")
    if isinstance(raw, list):
        return register in raw
    return bool(
        register in {"ebp", "ebx", "edi", "esi"}
        and abi.get("template") in {
            "pe32-cdecl-v1",
            "pe32-cdecl-varargs-v1",
            "pe32-stdcall-v1",
            "pe32-thiscall-v1",
        }
    )


def _indirect_cleanup(
    recovery: Mapping[str, Any] | None,
    *,
    summaries: Mapping[int, Mapping[str, Any]],
) -> tuple[int | None, tuple[str, ...], bool]:
    if recovery is None or recovery.get("status") != "recovered":
        return None, (), False
    cleanups: set[int] = set()
    preserves_ebp = True
    target_units = tuple(
        sorted(
            target
            for target in recovery.get("target_unit_ids", ())
            if isinstance(target, str)
        )
    )
    for target_rva in recovery.get("target_rvas", ()):
        cleanup = _internal_cleanup(target_rva, summaries)
        if cleanup is None:
            return None, target_units, False
        cleanups.add(cleanup)
        preserves_ebp = preserves_ebp and _internal_preserves(
            target_rva, summaries, "ebp"
        )
    for target in recovery.get("external_targets", ()):
        if not isinstance(target, Mapping):
            return None, target_units, False
        if target.get("disposition") != "returns":
            return None, target_units, False
        abi = target.get("abi")
        words = target.get("argument_words")
        if not isinstance(abi, Mapping) or not isinstance(words, int) or isinstance(words, bool):
            return None, target_units, False
        template = abi.get("template")
        callee_cleanup = abi.get("callee_cleanup")
        if template in {"pe32-stdcall-v1", "pe32-thiscall-v1"} and callee_cleanup is True:
            cleanups.add(words * 4)
        elif template in {"pe32-cdecl-v1", "pe32-cdecl-varargs-v1"} and callee_cleanup is False:
            cleanups.add(0)
        else:
            return None, target_units, False
        raw_preserved = abi.get("preserved_registers")
        preserves_ebp = preserves_ebp and (
            "ebp" in raw_preserved
            if isinstance(raw_preserved, list)
            else template in {
                "pe32-cdecl-v1",
                "pe32-cdecl-varargs-v1",
                "pe32-stdcall-v1",
                "pe32-thiscall-v1",
            }
        )
    return (
        (next(iter(cleanups)), target_units, preserves_ebp)
        if len(cleanups) == 1
        else (None, target_units, False)
    )


def _derived_stack_delta(semantics: Mapping[str, Any]) -> int | None:
    raw = semantics.get("stack_delta")
    delta = raw.get("net_bytes") if isinstance(raw, Mapping) and raw.get("status") == "derived" else None
    return delta if isinstance(delta, int) and not isinstance(delta, bool) else None


def _ordinary_successor_states(
    semantics: Mapping[str, Any], states: frozenset[_StackState]
) -> set[_StackState] | None:
    raw_stack = semantics.get("stack_delta")
    stack_expression = (
        raw_stack.get("expression") if isinstance(raw_stack, Mapping) else None
    )
    delta = _derived_stack_delta(semantics)
    ebp_expression, ebp_written = _register_output_expression(
        semantics, "ebp"
    )
    result: set[_StackState] = set()
    for esp, frame_base, ebp in states:
        next_esp = (
            esp + delta
            if delta is not None
            else _evaluate_stack_expression(
                stack_expression,
                esp=esp,
                ebp=ebp,
            )
        )
        if next_esp is None:
            return None
        next_ebp = (
            ebp
            if not ebp_written
            else _evaluate_stack_expression(
                ebp_expression,
                esp=esp,
                ebp=ebp,
            )
        )
        result.add((next_esp, frame_base, next_ebp))
    return result


def _register_output_expression(
    semantics: Mapping[str, Any], register: str
) -> tuple[Any, bool]:
    writes = semantics.get("register_writes")
    if not isinstance(writes, list):
        return None, False
    matching = [
        row.get("value")
        for row in writes
        if isinstance(row, Mapping) and row.get("register") == register
    ]
    return (matching[-1], True) if matching else (None, False)


def _evaluate_stack_expression(
    expression: Any, *, esp: int, ebp: int | None
) -> int | None:
    esp_offset = affine_register_offset(expression, "esp")
    if esp_offset is not None:
        return esp + esp_offset
    ebp_offset = affine_register_offset(expression, "ebp")
    if ebp is not None and ebp_offset is not None:
        return ebp + ebp_offset
    return None


def _stack_state_sort_key(state: _StackState) -> tuple[int, int, int, int]:
    esp, frame_base, ebp = state
    return (esp, frame_base, ebp is None, 0 if ebp is None else ebp)


def _esp_access_span(unit: Mapping[str, Any]) -> tuple[int, int] | None:
    events = unit["semantics"].get("memory_events", ())
    spans: list[tuple[int, int]] = []
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, Mapping):
            continue
        offset = _affine_esp_offset(event.get("address"))
        width = event.get("width")
        if offset is None or not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            continue
        spans.append((offset, offset + width))
    return (
        (min(start for start, _end in spans), max(end for _start, end in spans))
        if spans else None
    )


def _affine_esp_offset(expression: Any) -> int | None:
    return affine_register_offset(expression, "esp")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{context} is invalid")
    return value


def _u32(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < _UINT32:
        raise ValueError(f"{context} is invalid")
    return value


def _positive_u32(value: Any, context: str) -> int:
    value = _u32(value, context)
    if value == 0:
        raise ValueError(f"{context} is invalid")
    return value


def _deduplicate(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return list({
        json.dumps(row, sort_keys=True, separators=(",", ":")): copy.deepcopy(dict(row))
        for row in rows
    }.values())


__all__ = [
    "CHECKED_CALL_STACK_WRITE_SPATIAL_FACT_V2_FORMAT",
    "CHECKED_STACK_ORIGIN_SPATIAL_FACT_V2_FORMAT",
    "CHECKED_STACK_SPATIAL_FACT_V2_FORMAT",
    "STACK_RANGE_ANALYSIS_V2_FORMAT",
    "derive_stack_range_analysis_v2",
    "validate_checked_stack_range_facts_v2",
    "validate_stack_range_analysis_v2",
]
