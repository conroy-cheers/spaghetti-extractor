"""Independent reconstruction and replay for mutable-slot v2 authority."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .authority_bindings_v2 import canonical_json_bytes
from .global_slot_analysis_v2 import analyze_global_slots_v2
from .global_slot_authority_v2 import (
    _violated_replay_authority,
    _with_replay_violation,
    build_global_slot_authority_v2,
)
from .global_slot_image_v2 import GlobalSlotImageV2Error, loader_initial_bytes_v2
from .launch_memory_ranges_v2 import derive_launch_memory_range_analysis_v2
from .mutable_slot_candidates_v2 import derive_dependency_scoped_slot_inventory_v2
from .stage_binary import StageABinary


def replay_global_slot_authority_v2(
    *,
    submitted_analysis: Mapping[str, Any],
    provenance: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]],
    graph: Mapping[str, Any],
    interprocedural: Mapping[str, Any],
    stack_range_analysis: Mapping[str, Any],
    launch_assumptions: Mapping[str, Any],
    memory_range_invariant_analysis: Mapping[str, Any] | None,
    original_binary: StageABinary,
    machine_ir_sha256: str,
    finite_value_budget: int = 32,
    stack_finite_offset_budget: int | None = None,
    proposal_slot_dependencies: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Reconstruct slot inputs, replay analysis, then promote safe evidence."""

    recoveries = interprocedural.get("recovered_targets")
    if not isinstance(recoveries, list) or any(
        not isinstance(row, Mapping) for row in recoveries
    ):
        return _violated_replay_authority(
            "global_slot_replay_recovery_inventory_invalid"
        )
    try:
        slot_rvas, relevant_reads = derive_dependency_scoped_slot_inventory_v2(
            original_binary,
            recoveries,
            proposal_dependencies=proposal_slot_dependencies,
        )
    except (TypeError, ValueError) as exc:
        return _violated_replay_authority(
            "global_slot_replay_recovery_inventory_invalid",
            detail=str(exc),
        )
    candidate_slots = [
        original_binary.image_base + slot_rva for slot_rva in slot_rvas
    ]
    launch_initial_values: dict[int, int] = {}
    for address in candidate_slots:
        try:
            data, _kind = loader_initial_bytes_v2(
                original_binary,
                rva_start=address - original_binary.image_base,
                width_bytes=4,
            )
        except GlobalSlotImageV2Error:
            continue
        launch_initial_values[address] = int.from_bytes(data, "little")
    operation = interprocedural.get("operation_provenance")
    access_facts = (
        operation.get("checked_memory_access_facts", [])
        if isinstance(operation, Mapping)
        else []
    )
    address_domains = (
        operation.get("checked_memory_address_domains", [])
        if isinstance(operation, Mapping)
        else []
    )
    call_site_effects = (
        operation.get("call_site_effects", [])
        if isinstance(operation, Mapping)
        else []
    )
    fixed = interprocedural.get("fixed_point")
    interprocedural_sha256 = (
        fixed.get("authority_artifact_sha256")
        if isinstance(fixed, Mapping)
        else None
    )
    call_summaries = interprocedural.get("call_summaries")
    if not isinstance(call_summaries, Mapping):
        call_summaries = {}
    launch_memory_ranges = derive_launch_memory_range_analysis_v2(
        units=units,
        launch_assumptions=launch_assumptions,
        pe_sha256=original_binary.sha256,
        machine_ir_sha256=machine_ir_sha256,
        image_base=original_binary.image_base,
        size_of_image=original_binary.size_of_image,
    )
    expected = analyze_global_slots_v2(
        units=units,
        graph=graph,
        candidate_slot_addresses=candidate_slots,
        image_base=original_binary.image_base,
        size_of_image=original_binary.size_of_image,
        checked_memory_spatial_facts=stack_range_analysis.get(
            "checked_spatial_facts", []
        ),
        launch_memory_range_analysis=launch_memory_ranges,
        launch_assumptions=launch_assumptions,
        range_authority_binding=stack_range_analysis.get("binding"),
        relevant_read_dependencies=relevant_reads,
        launch_initial_values=launch_initial_values,
        checked_memory_access_facts=access_facts,
        checked_memory_address_domains=address_domains,
        call_site_effects=call_site_effects,
        memory_range_invariant_analysis=memory_range_invariant_analysis,
        pe_sha256=original_binary.sha256,
        machine_ir_sha256=machine_ir_sha256,
        interprocedural_authority_sha256=interprocedural_sha256,
        alternative_budget=finite_value_budget,
    )
    authority = build_global_slot_authority_v2(
        provenance=provenance,
        global_slot_analysis=expected,
        units=units,
        pe_sha256=original_binary.sha256,
        machine_ir_sha256=machine_ir_sha256,
        image_base=original_binary.image_base,
        size_of_image=original_binary.size_of_image,
        original_binary=original_binary,
        stack_range_analysis=stack_range_analysis,
        stack_graph=graph,
        stack_launch_assumptions=launch_assumptions,
        stack_call_summaries=call_summaries,
        stack_indirect_recoveries=recoveries,
        stack_call_site_effects=call_site_effects,
        stack_finite_offset_budget=(
            finite_value_budget
            if stack_finite_offset_budget is None
            else stack_finite_offset_budget
        ),
        launch_memory_range_analysis=launch_memory_ranges,
        launch_memory_assumptions=launch_assumptions,
    )
    if canonical_json_bytes(submitted_analysis) == canonical_json_bytes(expected):
        return authority
    return _with_replay_violation(
        authority,
        code="global_slot_analysis_replay_mismatch",
        details={
            "submitted_analysis_sha256": submitted_analysis.get(
                "analysis_sha256"
            ),
            "expected_analysis_sha256": expected["analysis_sha256"],
        },
    )


__all__ = ["replay_global_slot_authority_v2"]
