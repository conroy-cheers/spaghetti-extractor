"""Derive required semantic assertions independently of solver discovery."""

from __future__ import annotations
from typing import Mapping, Sequence
from .bisimulation_exact_frame import MACHINE_STATE_DESCRIPTION, CUT_MACHINE_STATE_DESCRIPTION
from .bisimulation_mutable_machine_frame import SPECS as MUTABLE_MACHINE_FRAMES
from .bisimulation_clobber_frame import clobber_specs, result_registers
from .bisimulation import BisimulationOperationV1
from .bisimulation_continuation import continuation_assertions
from .bisimulation_exact import (
    _compact_exact_temporaries as _compact_exact_temporaries,
    _specialize_exact_function_source as _specialize_exact_function_source,
    _specialize_machine_overlay_for_proof as _specialize_machine_overlay_for_proof,
)
from .bisimulation_harness import (
    _cut_view_domain,
    _captured_parameter_view,
    _exit_comparisons as _exit_comparisons,
    _private_stack_high_offset as _private_stack_high_offset,
    _render_source_expression as _render_source_expression,
)
from .bisimulation_support import (
    PROOF_PRIVATE_STACK_ABOVE as PROOF_PRIVATE_STACK_ABOVE,
)
from .bisimulation_typed_services import (
    build_typed_proof_service_thunk_renderer as build_typed_proof_service_thunk_renderer,
)
from .bisimulation_world import _world_source as _world_source
from .bisimulation_projection import machine_fact_read_descriptions


def _required_assertion_descriptions(
    *,
    authored: BisimulationOperationV1,
    proof_function: str,
    active_start_sync_id: str | None,
    next_sync_ids: set[str],
    logical_projection: Mapping[str, object],
    continuous_acyclic: bool,
    typed_call_positions: Sequence[int],
    connected_summary_ids: Sequence[int] = (),
    connected_entry_assertions: Sequence[str] = (),
    readable_machine_state: bool = False,
    mutable_machine_state: bool = False,
    continuation: Mapping[str, object] | None = None,
    readable_range_assertions: Sequence[str] = (),
) -> list[str]:
    """Derive semantic goals independently of CBMC's property inventory."""

    from .bisimulation_local_views import byte_read_checks, input_owner_description
    from .bisimulation_memory_facts import description as memory_fact_description, coordinate_phases as memory_fact_coordinate_phases
    from .bisimulation_projection_frames import configuration as projection_frame, description as projection_frame_description
    descriptions = {
        *(projection_frame_description(projection_frame(sync)) for sync in authored.syncs
          if sync.identity == active_start_sync_id and projection_frame(sync)),
        *readable_range_assertions,
        *(memory_fact_description(sync, fact, phase)
          for sync in authored.syncs if sync.identity == active_start_sync_id or sync.identity in next_sync_ids
          for fact in sync.memory_facts for phase in memory_fact_coordinate_phases(sync, fact)),
        *(memory_fact_description(sync, fact, phase)
          for sync in authored.syncs for fact in sync.memory_facts
          for phase in (("construction-order", "input-domain") if sync.identity == active_start_sync_id else ())
              + (("output-domain", "contents") if sync.identity in next_sync_ids else ())),
        *(f"spx-bisimulation-allocation-entry-{kind}:{authored.operation_id}"
          for kind in ("input", "admission")
          if active_start_sync_id is None and authored.entry_allocation_history is not None),
        *(description for sync in authored.syncs
          if sync.identity == active_start_sync_id or sync.identity in next_sync_ids
          for description in byte_read_checks(sync)),
        *(f"spx-bisimulation-native-view-input:{sync.identity}:{capture.identity}"
          for sync in authored.syncs if sync.identity == active_start_sync_id
          for capture in sync.captures if capture.mode == "native_view"),
        *(input_owner_description(sync.identity, capture.identity)
          for sync in authored.syncs if sync.identity == active_start_sync_id
          for capture in sync.captures if capture.mode == "native_view"),
        *(f"spx-bisimulation-capture-reference-memory:{sync.identity}:{capture.identity}"
          for sync in authored.syncs if sync.identity in next_sync_ids
          for capture in sync.captures if capture.mode == 'native_view' and capture.kind == 'parameter'),
        *(f"spx-bisimulation-allocation-history-input:{sync.identity}"
          for sync in authored.syncs if sync.identity == active_start_sync_id and sync.allocation_history is not None),
        *(f"spx-bisimulation-private-stack-scope:{sync.identity}"
          for sync in authored.syncs if sync.identity in next_sync_ids
          and any(item.private_stack_scope is not None for item in authored.syncs)),
        *(f"spx-bisimulation-private-stack-scope-input:{sync.identity}"
          for sync in authored.syncs if sync.identity == active_start_sync_id and sync.private_stack_scope is not None),
        *(description for sync in authored.syncs
          for direction, active in (("input", sync.identity == active_start_sync_id),
                                    ("output", sync.identity in next_sync_ids)) if active
          for description in machine_fact_read_descriptions(sync, direction)),
        *connected_entry_assertions,
        *([MACHINE_STATE_DESCRIPTION, CUT_MACHINE_STATE_DESCRIPTION] if readable_machine_state else []),
        *([spec.description for spec in MUTABLE_MACHINE_FRAMES] if mutable_machine_state else []),
        *(continuation_assertions(authored.operation_id, proof_function) if continuation is not None else []),
        f"spx-bisimulation-shared-view-inputs:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-source-frame-preservation:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-control:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-target:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-value:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-continuation-state:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-world-calls:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-world-atomics:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-world-memory:{authored.operation_id}:{proof_function}",
        *(
            f"spx-bisimulation-exit-observable:{authored.operation_id}:{row['id']}"
            for row in _exit_comparisons(logical_projection)
        ),
        *(
            f"spx-bisimulation-typed-call-fields:{position}"
            for position in typed_call_positions
        ),
        *(
            f"spx-bisimulation-typed-call-public-memory:{position}"
            for position in typed_call_positions
        ),
        *(
            f"spx-bisimulation-connected-summary-input:{summary_id}"
            for summary_id in connected_summary_ids
        ),
        *(
            f"spx-bisimulation-connected-summary-prefix:{summary_id}"
            for summary_id in connected_summary_ids
        ),
        *(
            f"spx-bisimulation-connected-summary-memory:{summary_id}"
            for summary_id in connected_summary_ids
        ),
    }
    if connected_summary_ids:
        descriptions.add(
            "spx-bisimulation-connected-summary-cardinality:"
            f"{authored.operation_id}:{proof_function}"
        )
    if authored.machine_clobbers:
        descriptions.update(spec.description for spec in clobber_specs(
            authored.machine_clobbers, result_registers(logical_projection)))
    if authored.private_stack_writes:
        from .bisimulation_private_frame import specs
        descriptions.update(spec.description for spec in specs(authored.private_stack_writes))
    if continuous_acyclic:
        descriptions.add(
            "spx-bisimulation-continuous-exact-internal-transfer:"
            f"{authored.operation_id}:{proof_function}"
        )
    for sync in authored.syncs:
        if sync.identity != active_start_sync_id and sync.identity not in next_sync_ids:
            descriptions.add(f"spx-bisimulation-unexpected-sync:{sync.identity}")
        if sync.identity not in next_sync_ids:
            continue
        descriptions.update(
            {
                f"spx-bisimulation-invariant:{sync.identity}",
                f"spx-bisimulation-world-calls:{sync.identity}",
                f"spx-bisimulation-world-atomics:{sync.identity}",
                f"spx-bisimulation-world-memory:{sync.identity}",
                f"spx-bisimulation-allocation-cut-admission:{sync.identity}",
                f"spx-bisimulation-world-connected-calls:{sync.identity}",
                f"spx-bisimulation-sync-alignment:{sync.identity}",
                *(
                    f"spx-bisimulation-capture:{sync.identity}:{capture.identity}"
                    for capture in sync.captures
                ),
                *(
                    f"spx-bisimulation-capture-roundtrip:{sync.identity}:{capture.identity}"
                    for capture in sync.captures
                    if capture.kind == "source_state" and capture.mode == "machine_codec"
                ),
                *(
                    f"spx-bisimulation-resumed-view-admission:{sync.identity}:{capture.identity}"
                    for capture in sync.captures
                    if _cut_view_domain(capture, state="spx_proof_exact_output",
                                        read="spx_proof_exact_output_read") is not None
                ),
                *(
                    f"spx-bisimulation-capture-{kind}:{sync.identity}:{capture.identity}"
                    for capture in sync.captures
                    if _captured_parameter_view(capture) is not None
                    for kind in ("reference-memory", "methods", "metadata", "context", "extent")
                ),
                *(
                    f"spx-bisimulation-derived:{sync.identity}:{derived.identity}"
                    for derived in sync.derived
                ),
            }
        )
    return sorted(descriptions)
