"""Direct-C bisimulation harness and relation projection rendering."""

from __future__ import annotations

import hashlib
import re
from typing import Mapping, Sequence

from .bisimulation_connected import (
    _connected_replay_source,
    _connected_summary_source,
)

from ..artifacts.artifact_set import canonical_sha256_v3
from ..transfer.runtime_abi import _base_runtime_header
from .bisimulation import BisimulationOperationV1, BisimulationSyncV1
from .bisimulation_continuation import render_continuation
from .bisimulation_support import (
    BisimulationRefinementError,
    PROOF_PRIVATE_STACK_ABOVE,
    PROOF_PRIVATE_STACK_BELOW,
    PROOF_RELATION_WITNESS,
    PROOF_SOURCE_SYNC_STACK_BIAS,
    mapping as _mapping,
    rows as _rows,
    strings as _strings,
)
from .bisimulation_typed_services import (
    _checked_reference_result_origins,
    _proof_private_ranges,
    _proof_call_specs,
)
from .bisimulation_call_ranges import call_range_write_capacity
from .bisimulation_projection import _captured_parameter_view, _projection_expression, exact_stack_address_expression, incoming_machine_relations
from .bisimulation_reference_transport import view_address_expression

COVER_OBSERVER = "void __CPROVER_cover(__CPROVER_bool condition) { (void)condition; }"
from .bisimulation_native_views import native_view_specs
from .bisimulation_view_extent import shared_view_admission_source, shared_view_initialization, source_frame_preservation, stack_admission_expression, view_parameter_ids
from .bisimulation_view_extent import _VIEW_ADMISSION_SOURCE, _cut_view_domain
from .bisimulation_stack_scope import scope_expression
from .bisimulation_projection import machine_fact_stack
from .bisimulation_world import _world_source
from .bisimulation_runtime_dispatch import runtime_dispatch_source
from . import bisimulation_completion as completion
from . import bisimulation_local_views as local_views
from .bisimulation_support import typed_call_focus_source
from .bisimulation_allocation_cuts import allocation_cut_sources, maximum_history, entry_history_initialization
from .bisimulation_reference_authority import checked_reference_authority
from . import bisimulation_memory_facts as memory_facts
from .bisimulation_mutable_frame import authored_frame_configuration, mutable_frame_views, mutable_frame_initialization, mutable_frame_probe_source
from . import bisimulation_image_frame as image_frame
from .bisimulation_mutable_machine_frame import CUT as MUTABLE_MACHINE_CUT, EXIT as MUTABLE_MACHINE_EXIT, CUT_CHECK
from . import bisimulation_clobber_frame as clobber_frame
from . import bisimulation_private_frame as private_frame
from .bisimulation_shared_composition import shared_current_memory_summaries
from .interface_ir import ProofKernelComponentInterface
from .local_cell_transducers import checked_initial_words
from .machine_storage import reconstruct_register_address, scalar_storage_address
from .bisimulation_exact_frame import wide_entry_condition, frame_candidate, frame_probe_source, GUARD as EXACT_FRAME_GUARD, ACTIVE as EXACT_FRAME_ACTIVE, MACHINE_STATE_GUARD, CUT_MACHINE_STATE_GUARD, CUT_MACHINE_STATE_DESCRIPTION



from .bisimulation_source_expressions import (
    _incoming_scalar_invariant, _render_decoding, _replace_projected_value,
    _render_source_expression, memory_projection_readers,
)

def _validate_static_slot_rvas(
    value: object,
    *,
    image_size: int,
    context: str = "logical operation projection",
) -> None:
    """Reject absolute image addresses mislabeled as image-relative offsets."""

    if isinstance(value, Mapping):
        if value.get("kind") == "static_slot":
            rva = value.get("rva")
            width = value.get("width")
            if (
                not isinstance(rva, int)
                or isinstance(rva, bool)
                or not isinstance(width, int)
                or isinstance(width, bool)
                or width <= 0
                or width % 8 != 0
                or rva < 0
                or rva + width // 8 > image_size
            ):
                raise BisimulationRefinementError(
                    f"{context} static-slot RVA is outside the proof image"
                )
        for key, nested in value.items():
            _validate_static_slot_rvas(
                nested,
                image_size=image_size,
                context=f"{context}.{key}",
            )
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _validate_static_slot_rvas(
                nested,
                image_size=image_size,
                context=f"{context}[{index}]",
            )


def _render_harness(
    *,
    interface: ProofKernelComponentInterface,
    authored: BisimulationOperationV1,
    machine_image: Mapping[str, object],
    operation_projection: Mapping[str, object],
    overlay_entry: Mapping[str, object],
    functions: Sequence[Mapping[str, object]],
    max_writes: int,
    max_private_writes: int,
    max_calls: int,
    max_atomics: int,
    max_shadow_bytes: int,
    max_nul_views: int,
    service_bindings: Sequence[Mapping[str, object]],
    connected_summaries: Sequence[Mapping[str, object]],
    include_finite_control: bool,
    exact_stack_accesses: Sequence[tuple[int, int]] = (),
    call_completion_lemmas: Sequence[Mapping[str, object]] = (),
    continuous_acyclic: bool = False,
    continuous_exact_unit_rvas: Sequence[int] = (),
    unexpected_sync_ids: Sequence[str] = (),
    relation_evidence: Sequence[Mapping[str, object]] = (),
    reference_service_bindings: Sequence[Mapping[str, object]] | None = None,
    continuation: Mapping[str, object] | None = None,
    reference_authority: Mapping[str, object] | None = None,
    reference_allocation_requirements: list[Mapping[str, object]] | None = None,
    cut_unsigned_words: Mapping[str, Sequence[str]] | None = None,
    runtime_assurance: Mapping[str, object] | None = None,
) -> str:
    if any(binding.get("target_sampling") == "operation_entry" for binding in service_bindings) and any(
        function.get("sync_id") is not None for function in functions
    ):
        raise BisimulationRefinementError(
            "proof_service_entry_target_cut_transport_unsupported: a resumed region must transport the original capture"
        )
    overlay_symbol = str(overlay_entry.get("symbol", ""))
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", overlay_symbol) is None:
        raise BisimulationRefinementError("machine-overlay symbol is malformed")
    logical_projection = _mapping(
        operation_projection.get("operation"), "logical operation projection"
    )
    image = _mapping(machine_image, "proof machine image")
    preferred_base = int(image.get("preferred_base", -1))
    image_size = int(image.get("image_size", 0))
    if (
        preferred_base < 0
        or image_size <= 0
        or preferred_base + image_size > 0x100000000
    ):
        raise BisimulationRefinementError("proof machine image is malformed")
    _validate_static_slot_rvas(logical_projection, image_size=image_size)
    _validate_static_slot_rvas(authored.to_payload(), image_size=image_size, context="cut relation")
    probe_empty_frame = frame_candidate(interface, authored.operation_id, connected_summaries)
    mutable_views = mutable_frame_views(interface, authored.operation_id, connected_summaries)
    from .bisimulation_projection_frames import configuration as projection_frame_configuration
    projection_frames = [projection_frame_configuration(sync) for function in functions
                         for sync in authored.syncs if sync.identity == function.get("sync_id")]
    projection_frame = next((frame for frame in projection_frames if frame), None)
    if projection_frame and (len(functions) != 1 or any(
            row.get("summary_strategy") != "scalar-body-free-v1" or row.get("entry_contract") is not None
            for row in connected_summaries)):
        raise BisimulationRefinementError("parameter slot frames require one region with unconditional scalar dependencies")
    probe_image_frame = image_frame.candidate(interface=interface, mutable_views=mutable_views,
        connected=connected_summaries, authority=reference_authority, allocations=reference_allocation_requirements)
    clobbers, clobber_results, private_writes = authored_frame_configuration(
        authored, logical_projection, mutable_views=mutable_views, image_frame=probe_image_frame)
    stack_minimum = (f"({wide_entry_condition(probe_empty_frame, bool(mutable_views))} ? UINT32_C(4) : UINT32_C({PROOF_PRIVATE_STACK_BELOW}))"
                     if probe_empty_frame or mutable_views else f"UINT32_C({PROOF_PRIVATE_STACK_BELOW})")
    stack_image_assumptions = ["  __CPROVER_assume(" + stack_admission_expression(
        stack_pointer="initial_state.esp", high_offset="private_high_offset",
        image_base=preferred_base, image_size=image_size, readable_entry=probe_empty_frame, mutable_entry=bool(mutable_views)) + ");"]
    comparisons = _exit_comparisons(logical_projection)
    finite_control_model = (
        _finite_control_proof_model(
            logical_projection,
            machine_image=image,
        )
        if include_finite_control
        else None
    )
    immutable_bytes = (
        []
        if finite_control_model is None
        else [
            (int(row["address"]), int(row["value"]))
            for row in _rows(
                finite_control_model["immutable_bytes"],
                "finite-control immutable bytes",
            )
        ]
    )
    private_high_offset = _private_stack_high_offset(
        operation_projection=logical_projection,
    )
    parameter_specs = native_view_specs(interface, authored.operation_id, overlay_entry,
                                        reference_authority, logical_projection)
    nullable_parameters = {name for name, spec in (parameter_specs or {}).items()
                           if spec.get('nullable_input')}
    for sync in authored.syncs:
        captured = {capture.identity for capture in sync.captures
                    if capture.kind == 'parameter' and capture.mode == 'native_view'}
        if nullable_parameters - captured:
            raise BisimulationRefinementError('nullable input cuts require canonical native parameter transport')
    shared_view_count = len(view_parameter_ids(interface, authored.operation_id, logical_projection,
                                               native_specs=parameter_specs))
    private_ranges = _proof_private_ranges(logical_projection, image_base=preferred_base)
    reference_result_relations = _checked_reference_result_origins(
        interface=interface,
        relation_evidence=relation_evidence,
    )
    lines = [
        '#include "state-machine-runtime.h"',
        '#include "behavioral-c.h"',
        "#include <stdint.h>",
        f"#define SPX_PROOF_IMAGE_BASE UINT32_C({preferred_base})",
        "",
        _world_source(
            max_writes=max_writes,
            max_private_writes=max_private_writes,
            max_calls=max_calls,
            max_atomics=max_atomics,
            max_shadow_bytes=max_shadow_bytes,
            max_nul_views=max_nul_views,
            service_bindings=service_bindings,
            private_ranges=private_ranges,
            max_exposed_stack_views=shared_view_count,
            immutable_bytes=immutable_bytes,
            exact_stack_accesses=exact_stack_accesses,
            reference_result_relations=reference_result_relations,
            reference_service_bindings=reference_service_bindings,
            typed_exact_recording=bool(connected_summaries),
            summary_ranges=any(row.get('summary_strategy') in {'image-shared-body-free-v1', 'image-shared-framed-body-free-v1'} for row in connected_summaries),
            summary_current_zero=shared_current_memory_summaries(connected_summaries),
            framed_shared_summaries=any(row.get('summary_strategy') == 'image-shared-framed-body-free-v1' for row in connected_summaries),
            reference_authority=reference_authority,
            reference_allocation_requirements=reference_allocation_requirements,
            image_size=image_size,
            probe_empty_frame=probe_empty_frame, mutable_frame_views=mutable_views,
            private_stack_writes=private_writes,
            probe_image_frame=probe_image_frame,
            private_stack_accesses=authored.private_stack_accesses,
            reference_origin_capacity=authored.reference_origin_capacity,
            maximum_input_allocations=maximum_history([authored]),
            memory_fact_capacity=memory_facts.capacity(authored),
            runtime_assurance=runtime_assurance,
            projection_frame=projection_frame,
        ),
        "",
        f"const uint32_t spx_proof_private_high_offset = UINT32_C({private_high_offset});",
        local_views.runtime_source() if local_views.has_local_views(authored) else "",
        runtime_dispatch_source(runtime_assurance),
        allocation_cut_sources(authored, specs=_proof_call_specs(service_bindings,
            allow_lifetime_effects=reference_allocation_requirements is not None),
            authority=checked_reference_authority(reference_authority), inventory=None,
            requirements=reference_allocation_requirements, image_base=preferred_base,
            image_size=image_size, readable_entry=probe_empty_frame, mutable_entry=bool(mutable_views)),
        *([memory_facts.source(authored, local_views.local_view_specs(authored,
            component_id=interface.identity, overlay_entry=overlay_entry, authority=reference_authority,
            parameter_specs=native_view_specs(interface, authored.operation_id, overlay_entry, reference_authority, logical_projection)),
            reference_authority, runtime_assurance=runtime_assurance)] if memory_facts.capacity(authored) else []),
        (shared_view_admission_source(private_ranges=private_ranges,
            image_base=preferred_base, image_size=image_size, readable_entry=probe_empty_frame, mutable_entry=bool(mutable_views)) if shared_view_count else _VIEW_ADMISSION_SOURCE),
        "const spx_region_override *spx_proof_exact_region_override_lookup(",
        "    uint32_t entry_rva) {",
        "  (void)entry_rva;",
        "  return (const spx_region_override *)0;",
        "}",
        "uint32_t spx_proof_exact_native_machine_fallback_allowed(",
        "    uint32_t source_rva) {",
        "  (void)source_rva;",
        "  return UINT32_C(1);",
        "}",
        "",
        f"extern spx_step_result {overlay_symbol}(spx_runtime *, spx_machine_state *);",
        "extern spx_step_result spx_behavioral_step(",
        "    spx_runtime *, spx_machine_state *, uint32_t);",
        "",
        "uint32_t spx_proof_start;",
        "uint32_t spx_proof_resumed;",
        "uint32_t spx_proof_relation_probe;",
        "uint32_t spx_proof_relation_selector;",
        "spx_machine_state spx_proof_exact_input;",
        "spx_machine_state spx_proof_exact_output;",
        "spx_step_result spx_proof_exact_result;",
        *(_readable_cut_machine_state_source() if probe_empty_frame else []),
        *clobber_frame.declarations(clobbers, clobber_results),
        *(_mutable_cut_machine_state_source(clobbers, clobber_results, private_writes) if mutable_views else []),
        "",
        *(
            line
            for sync_id in unexpected_sync_ids
            for line in (
                f"void spx_proof_unexpected_sync_{sync_id}(uint32_t aligned) {{",
                f'  __CPROVER_assert(aligned, "spx-bisimulation-unexpected-sync:{sync_id}");',
                "}",
            )
        ),
        *_connected_replay_source(
            connected_summaries,
            runtime_assurance=runtime_assurance,
            max_writes=max_writes,
            max_calls=max_calls,
            max_atomics=max_atomics,
            call_range_writes_per_call=call_range_write_capacity(_proof_call_specs(
                service_bindings, allow_lifetime_effects=reference_allocation_requirements is not None)),
        ),
        *_connected_summary_source(connected_summaries),
        "spx_call_status spx_dispatch_external_call(",
        "    spx_runtime *rt, const spx_call_event *event,",
        "    const spx_machine_state *input, spx_machine_state *output) {",
        "  if (rt == 0 || rt->external_call_fallback == 0 ||",
        "      event == 0 || input == 0 || output == 0)",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  return rt->external_call_fallback(rt, event, input, output);",
        "}",
        "",
        *memory_projection_readers(stack_facts=any(machine_fact_stack(relation)
            for sync in authored.syncs for relation in sync.derived)),
        "uint32_t spx_proof_world_calls_equal(void) {",
        "  return spx_source_world.call_count == spx_exact_world.call_count;",
        "}",
        "uint32_t spx_proof_world_atomics_equal(void) {",
        "  return spx_source_world.atomic_count == spx_exact_world.atomic_count;",
        "}",
        "uint32_t spx_proof_world_connected_calls_equal(void) {",
        (
            "  return spx_proof_connected_summaries_equal();"
            if connected_summaries else "  return UINT32_C(1);"
        ),
        "}",
        # Coverage instrumentation consumes these calls in --cover mode. The
        # same model also supports ordinary entry safety/assertion queries,
        # where the observer has no state effect. Use CBMC's logical Boolean:
        # a C _Bool parameter becomes c_bool and breaks coverage instrumentation.
        COVER_OBSERVER,
        *(
            []
            if finite_control_model is None
            else _strings(
                finite_control_model["witness_definitions"],
                "finite-control witness definitions",
            )
        ),
        f"void {PROOF_RELATION_WITNESS}(void) {{",
        *(
            [
                f"  {witness}(spx_proof_relation_selector);"
                for witness in _strings(
                    finite_control_model["witness_functions"],
                    "finite-control witness functions",
                )
            ]
            if finite_control_model is not None
            else ["  __CPROVER_cover(1);"]
        ),
        "}",
        "",
    ]
    # The proof and its relation witness share this assertion site. Duplicating
    # it in both entry bodies makes CBMC's model-wide inventory ambiguous even
    # when one body is unreachable from the selected property entry.
    for sync in authored.syncs:
        if sync.private_stack_scope is not None and any(
            function.get("sync_id") == sync.identity for function in functions
        ):
            lines.extend([
                f"void spx_proof_private_scope_input_{sync.identity}(int64_t anchor) {{",
                "  __CPROVER_assert(spx_proof_private_scope_matches(anchor),",
                f'      "spx-bisimulation-private-stack-scope-input:{sync.identity}");',
                "}",
                "",
            ])
    lines.extend(completion.declarations(call_completion_lemmas))
    for function in functions:
        name = str(function["symbol"])
        sync_id = function.get("sync_id")
        sync = (
            None
            if sync_id is None
            else next(item for item in authored.syncs if item.identity == sync_id)
        )
        scope_anchor = scope_expression(sync, "initial_state")
        scope_domain = [line.replace("initial_state.esp", scope_anchor) for line in stack_image_assumptions]
        reset_scope = (["  spx_proof_reset_worlds(initial_state.esp, private_high_offset);"]
                       if sync is None or sync.private_stack_scope is None else [
                           "  spx_proof_reset_worlds_in_scope(initial_state.esp,",
                           f"      (uint32_t)({scope_anchor}), private_high_offset);",
                           f"  spx_proof_private_scope_input_{sync.identity}({scope_anchor});"])
        preconditions = (
            _entry_preconditions(interface, authored.operation_id, logical_projection, shared_views=bool(shared_view_count))
            if sync is None
            else _sync_preconditions(interface, authored.operation_id, sync)
        )
        source_initialization = (
            []
            if sync is None
            else _sync_source_initialization(
                authored=authored,
                sync_identity=sync.identity,
                operation_projection=logical_projection,
                service_bindings=list(
                    _rows(
                        overlay_entry.get("service_bindings", []),
                        "machine-overlay service bindings",
                    )
                ),
            )
        )
        scalar_invariant = _incoming_scalar_invariant(
            sync, unsigned_words=(cut_unsigned_words or {}).get(sync_id, ()))
        view_registrations = _nul_view_registrations(
            interface=interface,
            operation_id=authored.operation_id,
            operation_projection=logical_projection,
            sync=sync, shared_views=bool(shared_view_count),
        )
        native_specs = native_view_specs(interface, authored.operation_id, overlay_entry, reference_authority, logical_projection)
        shared_views = shared_view_initialization(interface=interface, operation_id=authored.operation_id,
            operation_projection=logical_projection, sync=sync, proof_function=name, native_specs=native_specs)
        frame_guard = source_frame_preservation(authored.operation_id, name)
        relation_shared_views = shared_view_initialization(interface=interface, operation_id=authored.operation_id,
            operation_projection=logical_projection, sync=sync, proof_function=f"{name}_relation", native_specs=native_specs)
        finite_control_assumptions = (
            []
            if finite_control_model is None
            else _strings(
                finite_control_model["preconditions"],
                "finite-control preconditions",
            )
        )
        exact_execution = [
            f"  spx_proof_exact_output.original_rva = UINT32_C({int(function['start_rva'])});",
            "  spx_proof_exact_result = spx_behavioral_step(",
            f"      &exact_runtime, &spx_proof_exact_output, UINT32_C({int(function['start_rva'])}));",
        ]
        exact_execution.extend(f"  {completion.symbol(row)}();" for row in call_completion_lemmas
                               if row["start_sync"] == sync_id)
        if continuous_acyclic:
            internal_targets = sorted(set(continuous_exact_unit_rvas))
            if not internal_targets:
                raise BisimulationRefinementError(
                    "continuous exact execution requires selected unit RVAs"
                )
            target_is_internal = " ||\n          ".join(
                f"spx_proof_exact_result.target_rva == UINT32_C({rva})"
                for rva in internal_targets
            )
            exact_execution.extend(
                [
                    "  __CPROVER_assert(!(",
                    "      spx_proof_exact_result.kind <= SPX_BRANCH && (",
                    f"          {target_is_internal})),",
                    f'      "spx-bisimulation-continuous-exact-internal-transfer:{authored.operation_id}:{name}");',
                ]
            )
        lines.extend(
            [
                f"void {name}(void) {{",
                *([f"  {EXACT_FRAME_GUARD}(UINT32_C(1));"] if probe_empty_frame else []),
                "  spx_machine_state initial_state;",
                "  spx_machine_state source_state;",
                "  spx_step_result source_result;",
                "  spx_runtime exact_runtime = spx_proof_runtime(&spx_exact_world);",
                "  spx_runtime source_runtime = spx_proof_runtime(&spx_source_world);",
                *local_views.runtime_binding(authored),
                # Keep one inventory entry even if resuming skips the entire
                # lexical block containing an unexpected marker. Real marker
                # visits call the same assertion with their alignment predicate.
                *(f"  spx_proof_unexpected_sync_{sync_id}(UINT32_C(1));"
                  for sync_id in unexpected_sync_ids),
                f"  __CPROVER_assume({scope_anchor} >= {stack_minimum});",
                f"  __CPROVER_assume({scope_anchor} <= UINT32_MAX - "
                f"UINT32_C({PROOF_PRIVATE_STACK_ABOVE}));",
                f"  const uint32_t private_high_offset = UINT32_C({private_high_offset});",
                *scope_domain,
                *([f"  __CPROVER_assume({private_frame.ACTIVE} == 0U || " + private_frame.admission(private_writes,
                    stack="initial_state.esp", image_base=preferred_base, image_size=image_size, high="private_high_offset") + ");"] if private_writes else []),
                *reset_scope,
                *(entry_history_initialization(authored) if sync is None else []),
                *(
                    ["  spx_proof_reset_connected_summaries();"]
                    if connected_summaries
                    else []
                ),
                *([f"  spx_proof_initialize_allocation_history_{sync.identity}();"]
                  if sync is not None and sync.allocation_history is not None else []),
                *memory_facts.initialization(sync),
                *shared_views,
                *preconditions,
                *view_registrations,
                *finite_control_assumptions,
                *mutable_frame_initialization(mutable_views, logical_projection, sync),
                *private_frame.initialization(private_writes),
                "  spx_proof_exact_input = initial_state;",
                "  spx_proof_exact_output = initial_state;",
                *scalar_invariant,
                *([f"  {CUT_MACHINE_STATE_GUARD}();"] if probe_empty_frame else []),
                *([f"  {CUT_CHECK}();"] if mutable_views else []),
                "  source_state = initial_state;",
                *source_initialization,
                f"  spx_proof_start = UINT32_C({int(function['start_code'])});",
                "  spx_proof_resumed = UINT32_C(0);",
                "  spx_proof_relation_probe = UINT32_C(0);",
                *exact_execution,
                *(
                    [
                        "  if (spx_proof_exact_result.kind == SPX_RETURN) {",
                        "    spx_proof_initialize_source(",
                        "        source_state.esp, UINT32_C(4),",
                        "        spx_proof_exact_result.value);",
                        "  }",
                    ]
                    if sync is not None
                    else []
                ),
                *frame_guard,
                f"  source_result = {overlay_symbol}(&source_runtime, &source_state);",
                *(
                    [
                        "  __CPROVER_assert(spx_proof_connected_summaries_equal(),",
                        f'      "spx-bisimulation-connected-summary-cardinality:{authored.operation_id}:{name}");',
                        "  __CPROVER_assume(spx_proof_connected_summaries_equal());",
                    ]
                    if connected_summaries
                    else []
                ),
                "  __CPROVER_assert(source_result.kind == spx_proof_exact_result.kind,",
                f'      "spx-bisimulation-exit-control:{authored.operation_id}:{name}");',
                "  __CPROVER_assert(source_result.target_rva == spx_proof_exact_result.target_rva,",
                f'      "spx-bisimulation-exit-target:{authored.operation_id}:{name}");',
                "  __CPROVER_assert(source_result.value == spx_proof_exact_result.value,",
                f'      "spx-bisimulation-exit-value:{authored.operation_id}:{name}");',
                *(
                    f"  __CPROVER_assert({item['condition']} || "
                    f"({item['left']} == {item['right']}), "
                    f'"spx-bisimulation-exit-observable:{authored.operation_id}:{item["id"]}");'
                    for item in comparisons
                ),
                "  __CPROVER_assert(spx_proof_world_calls_equal(),",
                f'      "spx-bisimulation-exit-world-calls:{authored.operation_id}:{name}");',
                "  __CPROVER_assert(spx_proof_world_atomics_equal(),",
                f'      "spx-bisimulation-exit-world-atomics:{authored.operation_id}:{name}");',
                "  __CPROVER_assert(spx_proof_world_public_memory_equal(),",
                f'      "spx-bisimulation-exit-world-memory:{authored.operation_id}:{name}");',
                # These pure scalar equalities were asserted above. Every
                # prefix assertion remains mandatory in the complete inventory;
                # only that complete proof can discharge their use here. Do not
                # repeat memory predicates that introduce fresh symbolic probes.
                *([
                    "  __CPROVER_assume(source_result.kind == spx_proof_exact_result.kind);",
                    "  __CPROVER_assume(source_result.target_rva == spx_proof_exact_result.target_rva);",
                    "  __CPROVER_assume(source_result.value == spx_proof_exact_result.value);",
                ] if continuation is not None else []),
                *(render_continuation(continuation, operation_id=authored.operation_id, proof_function=name)
                  if continuation is not None else []),
                *_continuation_state_checks(authored.operation_id, name, common_context=continuation is not None, readable_machine_state=probe_empty_frame, mutable_machine_state=bool(mutable_views), clobbers=clobbers, clobber_results=clobber_results),
                "}",
                "",
                f"void {name}_relation(void) {{",
                "  spx_machine_state initial_state;",
                "  spx_machine_state source_state;",
                "  spx_step_result source_result;",
                "  spx_runtime source_runtime = spx_proof_runtime(&spx_source_world);",
                *local_views.runtime_binding(authored),
                f"  __CPROVER_assume({scope_anchor} >= {stack_minimum});",
                f"  __CPROVER_assume({scope_anchor} <= UINT32_MAX - "
                f"UINT32_C({PROOF_PRIVATE_STACK_ABOVE}));",
                f"  const uint32_t private_high_offset = UINT32_C({private_high_offset});",
                *scope_domain,
                *reset_scope,
                *(entry_history_initialization(authored) if sync is None else []),
                *(
                    ["  spx_proof_reset_connected_summaries();"]
                    if connected_summaries
                    else []
                ),
                *([f"  spx_proof_initialize_allocation_history_{sync.identity}();"]
                  if sync is not None and sync.allocation_history is not None else []),
                *memory_facts.initialization(sync),
                *relation_shared_views,
                *preconditions,
                *view_registrations,
                *finite_control_assumptions,
                "  spx_proof_exact_input = initial_state;",
                "  spx_proof_exact_output = initial_state;",
                *scalar_invariant,
                "  source_state = initial_state;",
                *source_initialization,
                *source_frame_preservation(authored.operation_id, f"{name}_relation"),
                *(
                    [
                        "  spx_proof_relation_selector =",
                        f"      {finite_control_model['selector_expression']};",
                    ]
                    if finite_control_model is not None
                    else []
                ),
                f"  spx_proof_start = UINT32_C({int(function['start_code'])});",
                "  spx_proof_resumed = UINT32_C(0);",
                "  spx_proof_relation_probe = UINT32_C(1);",
                *(
                    [f"  {PROOF_RELATION_WITNESS}();", "  __CPROVER_assume(0);"]
                    if sync is None
                    else [
                        f"  source_result = {overlay_symbol}(&source_runtime, &source_state);",
                        "  (void)source_result;",
                        "  __CPROVER_assume(0);",
                    ]
                ),
                "}",
                "",
            ]
        )
        lines.extend(typed_call_focus_source(name, max_calls))
        if probe_empty_frame:
            lines.append(frame_probe_source(name))
        if mutable_views:
            lines.append(mutable_frame_probe_source(name, private_writes))
            lines.append(clobber_frame.probe_source(name, clobbers, clobber_results, private_writes))
            lines.append(private_frame.probe_source(name, private_writes))
            if probe_image_frame:
                lines.append(image_frame.probe_source(True, name, private_writes))
    return "\n".join(lines)


def _source_projection_storage(value: object) -> Mapping[str, object]:
    row = _mapping(getattr(value, "payload", value), "source entry projection")
    kind = row.get("kind")
    if kind in {"view", "bytes_view"}:
        return _source_projection_storage(row.get("base"))
    if kind in {"reference", "resource", "callback_handle", "atomic_object"}:
        return _source_projection_storage(row.get("source"))
    if kind == "service_output":
        return _source_projection_storage(row.get("fallback"))
    return row


def _nul_view_count(interface: ProofKernelComponentInterface, operation_id: str) -> int:
    operation = interface.operation_index()[operation_id]
    types = interface.type_index()
    return max(
        1,
        sum(
            1
            for parameter in operation.parameters
            if types[parameter.type_id].nul_terminated
            or types[parameter.type_id].extent_kind == "nul_terminated"
        ),
    )


def _nul_view_registrations(
    *,
    interface: ProofKernelComponentInterface,
    operation_id: str,
    operation_projection: Mapping[str, object],
    sync: BisimulationSyncV1 | None,
    shared_views: bool = False,
) -> list[str]:
    operation = interface.operation_index()[operation_id]
    types = interface.type_index()
    parameter_projections = {
        str(row.get("id")): row.get("projection")
        for row in _rows(
            operation_projection.get("parameters"), "parameter projections"
        )
    }
    captures = {} if sync is None else {item.identity: item for item in sync.captures}
    projection_rows = {
        str(row.get("id")): row.get("projection")
        for row in _rows(
            operation_projection.get("parameters"), "parameter projections"
        )
    }
    lines: list[str] = []
    for parameter in operation.parameters:
        logical_type = types[parameter.type_id]
        raw_projection = parameter_projections.get(parameter.identity)
        projection_payload = getattr(raw_projection, "payload", raw_projection)
        projection_row = (
            projection_payload if isinstance(projection_payload, Mapping) else {}
        )
        extent_id = projection_row.get("extent_id")
        if extent_id is not None:
            if sync is None:
                base_projection = raw_projection
                extent_projection = projection_rows.get(str(extent_id))
            else:
                base_capture = captures.get(parameter.identity)
                extent_capture = captures.get(str(extent_id))
                base_projection = (
                    None
                    if base_capture is None or base_capture.mode != "machine_codec"
                    else base_capture.projection
                )
                extent_projection = (
                    None
                    if extent_capture is None or extent_capture.mode != "machine_codec"
                    else extent_capture.projection
                )
            base_expression = _projection_expression(
                base_projection,
                state="initial_state",
                read="spx_proof_exact_input_read",
            )
            extent_expression = _projection_expression(
                extent_projection,
                state="initial_state",
                read="spx_proof_exact_input_read",
            )
            if base_expression is None or extent_expression is None:
                raise BisimulationRefinementError(
                    f"bounded view {parameter.identity!r} has no reconstructible extent"
                )
            if shared_views:
                lines.extend([
                    f"  __CPROVER_assume(spx_proof_range_is_public(&spx_source_world, {base_expression}, {extent_expression}));",
                    f"  __CPROVER_assume(spx_proof_range_is_public(&spx_exact_world, {base_expression}, {extent_expression}));",
                ])
            else:
                lines.extend(
                    [
                        f"  __CPROVER_assume((uint64_t)({base_expression}) +",
                        f"      (uint64_t)({extent_expression}) <= UINT64_C(4294967296));",
                        f"  __CPROVER_assume(({extent_expression}) == UINT32_C(0) ||",
                        f"      (uint64_t)({base_expression}) + (uint64_t)({extent_expression}) <=",
                        "          (uint64_t)spx_source_world.private_low ||",
                        f"      (uint64_t)({base_expression}) >=",
                        "          (uint64_t)spx_source_world.private_high);",
                        f"  __CPROVER_assume(({extent_expression}) == UINT32_C(0) ||",
                        f"      (uint64_t)({base_expression}) + (uint64_t)({extent_expression}) <=",
                        "          (uint64_t)spx_exact_world.private_low ||",
                        f"      (uint64_t)({base_expression}) >=",
                        "          (uint64_t)spx_exact_world.private_high);",
                    ]
                )
        if not (
            logical_type.nul_terminated or logical_type.extent_kind == "nul_terminated"
        ):
            continue
        if sync is None:
            projection = parameter_projections.get(parameter.identity)
        else:
            capture = captures.get(parameter.identity)
            projection = (
                None
                if capture is None or capture.mode != "machine_codec"
                else capture.projection
            )
        expression = _projection_expression(
            projection,
            state="initial_state",
            read="spx_proof_exact_input_read",
        )
        if expression is None:
            raise BisimulationRefinementError(
                f"NUL view {parameter.identity!r} has no reconstructible projection"
            )
        registered_payload = getattr(projection, "payload", projection)
        registered_row = (
            registered_payload
            if isinstance(registered_payload, Mapping)
            else projection_row
        )
        requested = _projection_expression(
            registered_row.get(
                "requested_extent",
                projection_row.get(
                    "requested_extent",
                    {"kind": "constant", "value": 1, "width": 32},
                ),
            ),
            state="initial_state",
            read="spx_proof_exact_input_read",
        )
        if requested is None:
            raise BisimulationRefinementError(
                f"NUL view {parameter.identity!r} has no reconstructible minimum extent"
            )
        lines.append(f"  spx_proof_register_nul_view({expression}, {requested});")
    return lines


def _source_shadow_bytes(projection: Mapping[str, object]) -> int:
    def projected_bytes(value: object) -> int:
        row = _mapping(getattr(value, "payload", value), "source shadow projection")
        if row.get("kind") == "record_view":
            return sum(
                projected_bytes(field.get("projection"))
                for field in _rows(row.get("fields"), "record shadow fields")
            )
        storage = _source_projection_storage(row)
        return (
            int(storage.get("width", 32)) // 8 if storage.get("kind") == "stack" else 0
        )

    total = 0
    for raw in _rows(projection.get("parameters"), "parameter projections"):
        total += projected_bytes(raw.get("projection"))
    for raw in _rows(projection.get("state"), "state projections"):
        total += projected_bytes(raw.get("entry"))
    return max(1, total)


def _private_stack_high_offset(
    *,
    operation_projection: Mapping[str, object],
) -> int:
    """Return the end of stack storage private to the modeled activation.

    By-value ABI arguments, compiler locals captured at proof barriers, call
    staging, and nested return addresses are not shared-memory observations.
    The generated overlay cannot mutate the caller's argument area, while
    reference parameters are separately constrained not to alias this range.
    """

    projections: list[object] = [
        raw.get("projection")
        for raw in _rows(
            operation_projection.get("parameters"), "parameter projections"
        )
    ] + [
        raw.get("entry")
        for raw in _rows(operation_projection.get("state"), "state projections")
    ]
    intervals: list[tuple[int, int]] = []

    def collect(projection: object) -> None:
        if projection is None:
            return
        row = _mapping(
            getattr(projection, "payload", projection),
            "private stack boundary projection",
        )
        if row.get("kind") == "record_view":
            fields = _rows(row.get("fields"), "private stack record fields")
            if not fields:
                raise BisimulationRefinementError(
                    "private stack record projection has no fields"
                )
            for field in fields:
                collect(field.get("projection"))
            return
        storage = _source_projection_storage(projection)
        if storage.get("kind") != "stack":
            return
        offset = int(storage.get("offset", -1))
        width = int(storage.get("width", 32))
        if offset < 0 or offset > 4096:
            raise BisimulationRefinementError(
                "private stack boundary projection is malformed"
            )
        if width not in {8, 16, 32} or offset + width // 8 > 4096:
            raise BisimulationRefinementError(
                "private stack boundary projection width is malformed"
            )
        intervals.append((offset, width // 8))

    for projection in projections:
        collect(projection)
    declared_high = max((offset + width for offset, width in intervals), default=0)
    # Checked view exposure and admission preserve caller-visible frame bytes.
    return max(declared_high, PROOF_PRIVATE_STACK_ABOVE)


def _source_storage_initialization(
    storage: Mapping[str, object], value: str
) -> list[str]:
    kind = storage.get("kind")
    width = int(storage.get("width", 32))
    if not 8 <= width <= 32 or width % 8 != 0:
        raise BisimulationRefinementError(
            "source entry projection has an unsupported width"
        )
    if kind == "register":
        register = str(storage.get("register", ""))
        if register not in {
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
        }:
            raise BisimulationRefinementError(
                "source entry register projection is malformed"
            )
        mask = "" if width == 32 else f" & UINT32_C({(1 << width) - 1})"
        return [f"  source_state.{register} = ({value}){mask};"]
    if kind == "offset":
        return ["  " + reconstruct_register_address(storage, state="source_state", address=value)]
    if kind == "stack":
        offset = int(storage.get("offset", -1))
        if offset < 0 or offset > 4092:
            raise BisimulationRefinementError(
                "source entry stack projection is malformed"
            )
        return [
            "  spx_proof_initialize_source(",
            f"      source_state.esp + UINT32_C({offset}), UINT32_C({width // 8}), {value});",
        ]
    if kind == "constant":
        constant = int(storage.get("value", -1))
        if constant < 0 or constant > 0xFFFFFFFF:
            raise BisimulationRefinementError(
                "source entry constant projection is malformed"
            )
        return [f"  __CPROVER_assume(({value}) == UINT32_C({constant}));"]
    if kind == "static_slot":
        # Both sides already read the same arbitrary initial byte function at
        # an absolute slot.  The cutpoint relation constrains that shared
        # value, so no proof-only initialization is needed.
        return []
    if kind == "memory":
        source_address, storage_width = scalar_storage_address(storage, state="source_state",
                                                               image_base="SPX_PROOF_IMAGE_BASE", phase="entry")
        exact_address, _ = scalar_storage_address(storage, state="initial_state",
                                                  image_base="SPX_PROOF_IMAGE_BASE", phase="entry")
        # Reuse the shared initial bytes only after checking that parameter
        # reconstruction and the synthetic stack frame preserve their address.
        # Do not write a proof-only copy that could hide aliases or new effects.
        return [f"  __CPROVER_assert(({source_address}) == ({exact_address}),",
                '      "spx-bisimulation-source-state-address-preserved");',
                f"  __CPROVER_assert(spx_proof_source_output_read({source_address},",
                f"      UINT32_C({storage_width // 8})) == ({value}),",
                '      "spx-bisimulation-source-state-memory-preserved");']
    raise BisimulationRefinementError(
        f"source entry projection kind {kind!r} cannot be reconstructed"
    )


def _sync_source_initialization(
    *,
    authored: BisimulationOperationV1,
    sync_identity: str,
    operation_projection: Mapping[str, object],
    service_bindings: Sequence[Mapping[str, object]],
) -> list[str]:
    sync = next(item for item in authored.syncs if item.identity == sync_identity)
    captures = {item.identity: item for item in sync.captures}
    def needs_stack_frame(value):
        if isinstance(value, Mapping):
            return value.get("kind") == "stack" or any(needs_stack_frame(item) for item in value.values())
        return isinstance(value, (list, tuple)) and any(needs_stack_frame(item) for item in value)

    lines = [
        # A sync machine frame is not an operation-entry frame.  Reconstruct a
        # private entry frame solely to let the checked production overlay
        # decode the logical parameters before SPX_PROOF_BEGIN resumes at the
        # requested source cutpoint.
        "  source_state.esp = initial_state.esp - "
        f"UINT32_C({PROOF_SOURCE_SYNC_STACK_BIAS});",
    ] if needs_stack_frame((operation_projection, service_bindings)) else []
    # Register-only decoders do not need a synthetic frame. Preserve their real
    # ESP so the unchanged continuation-state theorem can compose at the exit.
    # Checked local-cell recipes are expressed in the exact call site's entry
    # frame.  A resumed Portable-C shard uses a private synthetic entry frame,
    # so mirror every referenced stack word explicitly.  This keeps the
    # production thunk unchanged while preventing a proof-only stack bias from
    # changing service arguments (for example DirectDraw GetCaps fields).
    service_stack_offsets: set[int] = set()
    for raw_binding in service_bindings:
        binding = _mapping(raw_binding, "sync service binding")
        raw_transducers = binding.get("argument_transducers")
        if raw_transducers is None:
            continue
        for raw_transducer in _rows(
            raw_transducers,
            "sync service argument transducers",
        ):
            transducer = _mapping(raw_transducer, "sync service transducer")
            if transducer.get("kind") != "local_cell":
                continue
            for word in checked_initial_words(
                transducer.get("initial_words"), context="sync service local cell"
            ):
                if not isinstance(word, Mapping):
                    continue
                projection = _mapping(
                    word.get("projection"), "sync service entry projection"
                )
                if projection.get("kind") == "stack":
                    service_stack_offsets.add(int(projection.get("offset", -1)))
    for offset in sorted(service_stack_offsets):
        if offset < 0 or offset > 4092:
            raise BisimulationRefinementError(
                "sync service stack projection is outside its private frame"
            )
        lines.extend(
            [
                "  spx_proof_initialize_source(",
                f"      source_state.esp + UINT32_C({offset}), UINT32_C(4),",
                "      spx_proof_exact_input_read(",
                f"          initial_state.esp + UINT32_C({offset}), UINT32_C(4)));",
            ]
        )
    for raw in _rows(operation_projection.get("parameters"), "parameter projections"):
        identity = str(raw.get("id", ""))
        capture = captures.get(identity)
        operation_parameter_projection = _mapping(
            raw.get("projection"), "operation parameter projection"
        )
        if (capture is None and operation_parameter_projection.get("kind") in {"register", "stack"}
                and operation_parameter_projection.get("width") in {8, 16, 32}):
            # Compiler inventory admits only integer C arguments here. The
            # resumed source havocs their actual storage, including immutable
            # arguments, before restoring captures. No old argument is assumed.
            continue
        if (
            capture is None
            and operation_parameter_projection.get("kind") == "record_view"
        ):
            fields = _rows(
                operation_parameter_projection.get("fields"),
                "operation record parameter fields",
            )
            if not fields:
                raise BisimulationRefinementError(
                    f"sync {sync_identity!r} record parameter {identity!r} has no fields"
                )
            for field in fields:
                field_projection = field.get("projection")
                value = _projection_expression(
                    field_projection,
                    state="initial_state",
                    read="spx_proof_exact_input_read",
                )
                if value is None:
                    raise BisimulationRefinementError(
                        f"sync {sync_identity!r} record parameter {identity!r} "
                        "has an unsupported field projection"
                    )
                lines.extend(
                    _source_storage_initialization(
                        _source_projection_storage(field_projection), value
                    )
                )
            continue
        if (
            capture is None
            or capture.kind != "parameter"
            or capture.mode not in {"machine_codec", "native_view"}
        ):
            raise BisimulationRefinementError(
                f"sync {sync_identity!r} cannot reconstruct parameter {identity!r}"
            )
        value = _projection_expression(
            capture.projection,
            state="initial_state",
            read="spx_proof_exact_input_read",
        )
        if value is None:
            raise BisimulationRefinementError(
                f"sync {sync_identity!r} parameter {identity!r} lacks a machine projection"
            )
        lines.extend(
            _source_storage_initialization(
                _source_projection_storage(operation_parameter_projection), value
            )
        )
    for raw in _rows(operation_projection.get("state"), "state projections"):
        identity = str(raw.get("id", ""))
        capture = captures.get(identity)
        if capture is None:
            raise BisimulationRefinementError(
                f"sync {sync_identity!r} cannot reconstruct state {identity!r}"
            )
        if capture.mode != "machine_codec":
            continue
        value = _projection_expression(
            capture.projection,
            state="initial_state",
            read="spx_proof_exact_input_read",
        )
        if value is None:
            raise BisimulationRefinementError(
                f"sync {sync_identity!r} state {identity!r} lacks a machine projection"
            )
        lines.extend(
            _source_storage_initialization(
                _source_projection_storage(raw.get("entry")), value
            )
        )
    return lines


def _sync_preconditions(
    interface: ProofKernelComponentInterface,
    operation_id: str,
    sync: BisimulationSyncV1,
) -> list[str]:
    logical = interface.operation_index()[operation_id]
    types = interface.type_index()
    captures = {item.identity: item for item in sync.captures}
    lines = incoming_machine_relations(sync, state="initial_state")
    for parameter in logical.parameters:
        logical_type = types[parameter.type_id]
        if logical_type.kind not in {"bytes", "reference", "view", "resource"}:
            continue
        if logical_type.nullable is True:
            continue
        capture = captures.get(parameter.identity)
        if capture is None or capture.mode != "machine_codec":
            raise BisimulationRefinementError(
                f"sync {sync.identity!r} omits non-null parameter {parameter.identity!r}"
            )
        expression = _projection_expression(
            capture.projection,
            state="initial_state",
            read="spx_proof_exact_input_read",
        )
        if expression is not None:
            lines.append(f"  __CPROVER_assume(({expression}) != UINT32_C(0));")
    for capture in sync.captures:
        domain = _cut_view_domain(capture, sync=sync, state="initial_state", read="spx_proof_exact_input_read")
        if domain is not None:
            lines.append(f"  __CPROVER_assume({domain});")
    return lines



def _entry_preconditions(
    interface: ProofKernelComponentInterface,
    operation_id: str,
    projection: Mapping[str, object],
    *, shared_views: bool = False,
) -> list[str]:
    logical = interface.operation_index()[operation_id]
    types = interface.type_index()
    parameter_projections = {
        str(row.get("id")): _mapping(row.get("projection"), "parameter projection")
        for row in _rows(projection.get("parameters"), "parameter projections")
    }
    state_projections = {
        str(row.get("id")): _mapping(row.get("entry"), "entry state projection")
        for row in _rows(projection.get("state", []), "state projections")
    }
    state_types = {field.identity: field.type_id for field in interface.state}
    typed_inputs = [
        (parameter.identity, types[parameter.type_id], parameter_projections)
        for parameter in logical.parameters
    ] + [
        (identity, types[type_id], state_projections)
        for identity, type_id in sorted(state_types.items())
        if identity in state_projections
    ]
    lines: list[str] = []
    for identity, logical_type, projections in typed_inputs:
        if logical_type.kind not in {"bytes", "reference", "view", "resource"}:
            continue
        raw = projections[identity]
        if raw.get("kind") in {"view", "bytes_view"}:
            source = _mapping(raw.get("base"), "view base")
        elif raw.get("kind") == "resource":
            source = _mapping(raw.get("source"), "resource source")
        else:
            source = raw
        expression = _projection_expression(
            source,
            state="initial_state",
            read="spx_proof_exact_input_read",
        )
        if expression is not None and logical_type.nullable is not True:
            lines.append(f"  __CPROVER_assume(({expression}) != UINT32_C(0));")
        if raw.get("kind") in {"view", "reference"}:
            requested = _projection_expression(
                raw.get("requested_extent", raw.get("extent")),
                state="initial_state",
                read="spx_proof_exact_input_read",
            )
            if expression is None or requested is None:
                raise BisimulationRefinementError(
                    f"typed input {identity!r} lacks a checked extent"
                )
            if shared_views and projections is parameter_projections and raw.get("kind") == "view":
                nullable = f"({expression}) == UINT32_C(0) || " if logical_type.nullable else ""
                lines.append(f"  __CPROVER_assume({nullable}spx_proof_view_admitted({expression}, {requested}, initial_state.esp));")
                continue
            lines.extend(
                [
                    "  __CPROVER_assume((" + expression + ") == UINT32_C(0) ||",
                    "      (uint64_t)(" + expression + ") +",
                    "      (uint64_t)(" + requested + ") <= UINT64_C(4294967296));",
                    "  __CPROVER_assume((" + expression + ") == UINT32_C(0) ||",
                    "      (" + requested + ") == UINT32_C(0) ||",
                    "      (uint64_t)("
                    + expression
                    + ") + (uint64_t)("
                    + requested
                    + ") <=",
                    "          (uint64_t)spx_source_world.private_low ||",
                    "      (uint64_t)(" + expression + ") >=",
                    "          (uint64_t)spx_source_world.private_high);",
                    "  __CPROVER_assume((" + expression + ") == UINT32_C(0) ||",
                    "      (" + requested + ") == UINT32_C(0) ||",
                    "      (uint64_t)("
                    + expression
                    + ") + (uint64_t)("
                    + requested
                    + ") <=",
                    "          (uint64_t)spx_exact_world.private_low ||",
                    "      (uint64_t)(" + expression + ") >=",
                    "          (uint64_t)spx_exact_world.private_high);",
                ]
            )
    return lines


def _finite_control_proof_model(
    projection: Mapping[str, object],
    *,
    machine_image: Mapping[str, object],
) -> dict[str, object] | None:
    """Materialize checked selector-domain and immutable image-byte evidence.

    The exact execution remains unconstrained after it runs.  Before execution,
    the caller-visible selector is restricted to the recovery-proven finite
    domain and the exact table bytes are installed in the shared initial world.
    One cover site per selector proves that no admitted domain member is hidden
    by contradictory operation preconditions.
    """

    results = [
        _mapping(row.get("projection"), "finite-control result projection")
        for row in _rows(projection.get("results"), "result projections")
        if _mapping(row.get("projection"), "result projection").get("kind")
        == "finite_control_target"
    ]
    if not results:
        return None
    if len(results) != 1:
        raise BisimulationRefinementError(
            "an operation may expose only one finite-control result"
        )
    result = results[0]
    routes = _rows(result.get("routes"), "checked finite-control routes")
    evidence = _mapping(result.get("proof_evidence"), "finite-control proof evidence")
    evidence_core = dict(evidence)
    evidence_digest = evidence_core.pop("route_inventory_sha256", None)
    if (
        not routes
        or evidence_digest != canonical_sha256_v3(evidence_core)
        or evidence_digest != result.get("target_inventory_sha256")
        or evidence.get("unit_id") != result.get("unit_id")
    ):
        raise BisimulationRefinementError(
            "finite-control proof lacks its canonical route authority"
        )
    index_provenance = _mapping(
        evidence.get("index_provenance"),
        "finite-control index provenance",
    )
    if index_provenance.get("kind") != "direct_index":
        raise BisimulationRefinementError(
            "remapped finite-control selectors lack a proof model"
        )
    image_base = int(machine_image.get("preferred_base", -1))
    image_size = int(machine_image.get("image_size", -1))
    if (
        evidence.get("pe_sha256") != machine_image.get("pe_sha256")
        or evidence.get("image_base") != image_base
        or evidence.get("image_size") != image_size
        or image_base < 0
        or image_size <= 0
        or image_base + image_size > 0x100000000
    ):
        raise BisimulationRefinementError(
            "finite-control proof authority names another machine image"
        )
    selector_id = str(result.get("selector_parameter_id", ""))
    parameters = {
        str(row.get("id", "")): _mapping(
            row.get("projection"), "finite-control selector projection"
        )
        for row in _rows(projection.get("parameters"), "parameter projections")
    }
    selector = _projection_expression(
        parameters.get(selector_id),
        state="initial_state",
        read="spx_proof_exact_input_read",
    )
    if not selector_id or selector is None:
        raise BisimulationRefinementError(
            "finite-control proof lacks its selector projection"
        )
    parsed: list[tuple[int, int, int]] = []
    for route in routes:
        selector_value = int(route.get("selector_value", -1))
        target_rva = int(route.get("target_rva", -1))
        target_address = int(route.get("target_address", -1))
        if selector_value < 0 or target_rva < 0 or target_address < 0:
            raise BisimulationRefinementError(
                "finite-control route inventory is malformed"
            )
        parsed.append((selector_value, target_rva, target_address))
    if parsed != sorted(set(parsed)) or len({row[0] for row in parsed}) != len(parsed):
        raise BisimulationRefinementError(
            "finite-control route inventory is duplicated or noncanonical"
        )
    table = _mapping(evidence.get("table"), "finite-control table evidence")
    table_address = int(table.get("address", -1))
    table_rva_start = int(table.get("rva_start", -1))
    table_rva_end = int(table.get("rva_end", -1))
    evidence_routes = _rows(evidence.get("routes"), "finite-control proof routes")
    evidence_projection: list[tuple[int, int, int]] = []
    immutable_bytes: list[dict[str, int]] = []
    table_rows: list[tuple[int, bytes]] = []
    inventory_bytes = bytearray()
    for route in evidence_routes:
        selector_value = int(route.get("selector_value", -1))
        entry_address = int(route.get("entry_address", -1))
        entry_rva = int(route.get("entry_rva", -1))
        target_rva = int(route.get("target_rva", -1))
        target_address = int(route.get("target_address", -1))
        raw_bytes = route.get("bytes_le")
        if (
            min(
                selector_value,
                entry_address,
                entry_rva,
                target_rva,
                target_address,
            )
            < 0
            or not isinstance(raw_bytes, list)
            or len(raw_bytes) != 4
            or any(
                not isinstance(byte, int)
                or isinstance(byte, bool)
                or byte < 0
                or byte > 255
                for byte in raw_bytes
            )
        ):
            raise BisimulationRefinementError(
                "finite-control proof route evidence is malformed"
            )
        encoded = bytes(raw_bytes)
        if (
            entry_address != ((table_address + selector_value * 4) & 0xFFFFFFFF)
            or entry_address != image_base + entry_rva
            or target_address != image_base + target_rva
            or entry_rva + 4 > image_size
            or target_rva >= image_size
            or int.from_bytes(encoded, "little") != target_address
        ):
            raise BisimulationRefinementError(
                "finite-control proof route disagrees with its image/table"
            )
        evidence_projection.append((selector_value, target_rva, target_address))
        table_rows.append((entry_rva, encoded))
        inventory_bytes.extend(selector_value.to_bytes(4, "little"))
        inventory_bytes.extend(encoded)
        immutable_bytes.extend(
            {"address": entry_address + offset, "value": byte}
            for offset, byte in enumerate(raw_bytes)
        )
    table_bytes = b"".join(encoded for _rva, encoded in sorted(table_rows))
    if (
        evidence_projection != parsed
        or table.get("entry_width") != 4
        or table_rva_start != min(rva for rva, _encoded in table_rows)
        or table_rva_end != max(rva for rva, _encoded in table_rows) + 4
        or table.get("bytes_sha256") != hashlib.sha256(table_bytes).hexdigest()
        or table.get("inventory_sha256")
        != hashlib.sha256(bytes(inventory_bytes)).hexdigest()
    ):
        raise BisimulationRefinementError(
            "finite-control table evidence is stale or incomplete"
        )
    selector_u32 = f"((uint32_t)({selector}))"
    precondition = (
        "  __CPROVER_assume("
        + " || ".join(
            f"{selector_u32} == UINT32_C({selector_value})"
            for selector_value, _target_rva, _target_address in parsed
        )
        + ");"
    )
    witness_functions: list[str] = []
    witness_definitions: list[str] = []
    witness_calls: list[str] = []
    for ordinal, (selector_value, _target_rva, _target_address) in enumerate(parsed):
        name = f"spx_finite_control_route_{ordinal:04d}"
        witness_functions.append(name)
        witness_definitions.extend(
            [
                f"void {name}(uint32_t selector) {{",
                f"  __CPROVER_cover(selector == UINT32_C({selector_value}));",
                "}",
                "",
            ]
        )
        witness_calls.append(f"  {name}({selector_u32});")
    return {
        "preconditions": [precondition],
        "immutable_bytes": immutable_bytes,
        "selector_projection": dict(parameters[selector_id]),
        "selector_expression": selector_u32,
        "witness_functions": witness_functions,
        "witness_definitions": witness_definitions,
        "witness_calls": witness_calls,
        "route_inventory_sha256": evidence_digest,
    }


def _architectural_state_equalities(left: str, right: str) -> list[str]:
    header = _base_runtime_header()
    x87 = re.search(r"typedef struct spx_x87_value \{(.*?)\} spx_x87_value;", header, re.S)
    if x87 is None or re.sub(r"\s+", "", x87[1]) != "uint8_tvalue_bytes[10];uint32_tempty;uint8_ttag;":
        raise BisimulationRefinementError("continuation x87 ABI contains unsupported storage")
    match = re.search(r"typedef struct spx_machine_state \{(.*?)\} spx_machine_state;", header, re.S)
    if match is None:
        raise BisimulationRefinementError("continuation state ABI is unavailable")
    fields = []
    for declaration in match[1].split(";"):
        declaration = declaration.strip()
        if not declaration or declaration == "spx_x87_value x87_stack[8]":
            continue
        scalar = re.fullmatch(r"uint(?:8|16|32|64)_t ([a-z0-9_, ]+)", declaration)
        if scalar is None:
            raise BisimulationRefinementError("continuation state ABI contains unsupported storage")
        fields.extend(name.strip() for name in scalar[1].split(",") if name.strip() != "original_rva")
    equalities = [f"{left}.{field} == {right}.{field}" for field in fields]
    # Universal indices compare payload bytes without struct padding or loops.
    equalities.extend(f"{left}.x87_stack[continuation_slot].{field} == {right}.x87_stack[continuation_slot].{field}"
                      for field in ("value_bytes[continuation_byte]", "empty", "tag"))
    return equalities


def _readable_cut_machine_state_source() -> list[str]:
    equalities = _architectural_state_equalities("spx_proof_exact_input", "spx_proof_exact_output")
    return [
        f"void {CUT_MACHINE_STATE_GUARD}(void) {{",
        "  uint32_t continuation_slot = spx_nondet_u32(), continuation_byte = spx_nondet_u32();",
        "  __CPROVER_assume(continuation_slot < 8U && continuation_byte < 10U);",
        f"  __CPROVER_assert({EXACT_FRAME_ACTIVE} != UINT32_C(2) || (" + " &&\n      ".join(equalities) + "),",
        f'      "{CUT_MACHINE_STATE_DESCRIPTION}");',
        "}", "",
    ]


def _mutable_cut_machine_state_source(clobbers=(), results=(), private_writes=()) -> list[str]:
    equalities = _architectural_state_equalities("spx_proof_exact_input", "spx_proof_exact_output")
    return [f"void {CUT_CHECK}(void) {{", *private_frame.cut_check(private_writes),
        "  uint32_t continuation_slot = spx_nondet_u32(), continuation_byte = spx_nondet_u32();",
        "  __CPROVER_assume(continuation_slot < 8U && continuation_byte < 10U);",
        f"  {MUTABLE_MACHINE_CUT.guard}(" + " &&\n      ".join(equalities) + ");",
        *([f"  {clobber_frame.clobber_specs(clobbers, results)[0].guard}(" + " &&\n      ".join(
            clobber_frame.frame_equalities(equalities, (*clobbers, *results))) + ");"] if clobbers else []), "}", ""]


def _continuation_state_checks(operation_id: str, proof_function: str, *, common_context: bool = False, readable_machine_state: bool = False, mutable_machine_state: bool = False, clobbers=(), clobber_results=()) -> list[str]:
    """Use equality until a checked context relation can admit a difference.

    An intrafunction continuation can observe every architectural state field.
    original_rva is diagnostic instruction provenance; control kind and target
    are checked separately. Return and exceptional boundary contracts have
    their own observations and are not intrafunction continuation exits.
    """
    equalities = _architectural_state_equalities("spx_proof_exact_output", "source_state")
    condition = " || ".join(f"source_result.kind == {kind}" for kind in
                             ("SPX_FALLTHROUGH", "SPX_JUMP", "SPX_BRANCH", "SPX_INDIRECT_JUMP"))
    if common_context:
        condition = f"continuation_active || ({condition})"
        equalities.append("(!continuation_active || spx_proof_exact_output.original_rva == source_state.original_rva)")
    return [
        "  uint32_t continuation_slot = spx_nondet_u32(), continuation_byte = spx_nondet_u32();",
        "  __CPROVER_assume(continuation_slot < 8U && continuation_byte < 10U);",
        f"  __CPROVER_assert(!({condition}) || (" + " &&\n      ".join(equalities) + "),",
        f'      "spx-bisimulation-exit-continuation-state:{operation_id}:{proof_function}");',
        *([
            f"  {MACHINE_STATE_GUARD}(" + " &&\n      ".join(equalities) + ");",
        ] if readable_machine_state else []),
        *([f"  {MUTABLE_MACHINE_EXIT.guard}(" + " &&\n      ".join(equalities) + ");"] if mutable_machine_state else []),
        *([f"  {clobber_frame.clobber_specs(clobbers, clobber_results)[1].guard}(" + " &&\n      ".join(
            clobber_frame.frame_equalities(equalities, clobbers)) + ");"] if clobbers else []),
    ]


def _exit_comparisons(projection: Mapping[str, object]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    from .machine_overlay_result_views import parameter_exit_projections
    projected_outputs = [('result', row) for row in _rows(projection.get('results'), 'result projections')]
    projected_outputs.extend(('parameter', row) for row in parameter_exit_projections(projection))
    for category, row in projected_outputs:
        identity = str(row.get("id"))
        item = _mapping(row.get("projection"), "result projection")
        if item.get("kind") in {"control_condition", "finite_control_target"}:
            # These logical results are encoded wholly in the adapter's
            # spx_step_result.  The harness compares kind, target_rva, and
            # value directly; there is no second machine storage projection.
            continue
        left = _projection_expression(
            item,
            state="spx_proof_exact_output",
            read="spx_proof_exact_output_read",
        )
        right = _projection_expression(
            item,
            state="source_state",
            read="spx_proof_source_output_read",
        )
        if left is None or right is None:
            raise BisimulationRefinementError("result projection is unsupported")
        result.append(
            {
                "id": f"{category}:{identity}",
                "left": left,
                "right": right,
                # A C operation can return a logical value while its machine
                # region continues through fallthrough, jump, or branch.
                # Fault/nonlocal outcomes do not define that ordinary result.
                "condition": "!(" + " || ".join(
                    f"source_result.kind == {kind}" for kind in (
                        "SPX_FALLTHROUGH", "SPX_JUMP", "SPX_BRANCH", "SPX_RETURN",
                        "SPX_INDIRECT_JUMP",
                    )) + ")",
            }
        )
    for row in _rows(projection.get("state"), "state projections"):
        identity = str(row.get("id"))
        item = _mapping(row.get("exit"), "state exit projection")
        if item.get("kind") == "memory":
            exact_address, storage_width = scalar_storage_address(item, state="spx_proof_exact_output",
                                                                  image_base="SPX_PROOF_IMAGE_BASE", phase="exit")
            source_address, _ = scalar_storage_address(item, state="source_state",
                                                       image_base="SPX_PROOF_IMAGE_BASE", phase="exit")
            result.append({"id": f"state-address:{identity}", "left": exact_address,
                           "right": source_address, "condition": "UINT32_C(0)"})
            # Compare the total byte snapshots even after a fault. Reissuing a
            # runtime word read here would itself fault for an address crossing
            # UINT32_MAX and reject two correctly matching memory-fault exits.
            snapshots = ["(" + " | ".join(
                f"((uint32_t)spx_proof_{side}_byte((uint32_t)(({address}) + UINT32_C({index}))) << {index * 8}U)"
                for index in range(storage_width // 8)) + ")"
                for side, address in (("exact", exact_address), ("source", source_address))]
            result.append({"id": f"state:{identity}", "left": snapshots[0],
                           "right": snapshots[1], "condition": "UINT32_C(0)"})
            continue
        left = _projection_expression(
            item,
            state="spx_proof_exact_output",
            read="spx_proof_exact_output_read",
        )
        right = _projection_expression(
            item,
            state="source_state",
            read="spx_proof_source_output_read",
        )
        if left is None or right is None:
            raise BisimulationRefinementError("state projection is unsupported")
        result.append(
            {
                "id": f"state:{identity}",
                "left": left,
                "right": right,
                "condition": "UINT32_C(0)",
            }
        )
    return result
