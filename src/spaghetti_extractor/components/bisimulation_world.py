"""Sparse shared proof-world renderer for direct C bisimulation."""

from __future__ import annotations

from typing import Mapping, Sequence

from .bisimulation_support import (
    BisimulationRefinementError,
    PROOF_PRIVATE_STACK_ABOVE,
    mapping as _mapping,
)
from .bisimulation_world_memory import exposed_stack_fragments, memory_fragments, fixed_index_stores
from .bisimulation_typed_services import _proof_call_specs
from .bisimulation_call_memory import call_memory_fragments, event_stack_input_cases
from .bisimulation_call_ranges import call_range_fragments
from .bisimulation_terminated_reads import with_terminated_reads
from .bisimulation_allocation_lifetime import allocation_configuration
from .bisimulation_reference_origins import origin_declarations, reference_source, logical_argument_physical_index
from .bisimulation_reference_authority import checked_reference_authority
from .bisimulation_exact_frame import frame_declarations, frame_write_check, frame_private_low
from .bisimulation_mutable_frame import mutable_frame_declarations, mutable_frame_write_check
from . import bisimulation_private_frame as private_frame
from . import bisimulation_image_frame as image_frame
from . import bisimulation_native_admission as native_admission


def _world_source(
    *,
    max_writes: int,
    max_private_writes: int,
    max_calls: int,
    max_atomics: int,
    max_shadow_bytes: int,
    max_nul_views: int,
    service_bindings: Sequence[Mapping[str, object]],
    private_ranges: Sequence[tuple[int, int]],
    immutable_bytes: Sequence[tuple[int, int]] = (),
    exact_stack_accesses: Sequence[tuple[int, int]] = (),
    reference_result_relations: Mapping[str, Mapping[str, object]] | None = None,
    reference_service_bindings: Sequence[Mapping[str, object]] | None = None,
    typed_exact_recording: bool = False,
    max_exposed_stack_views: int = 0,
    reference_authority: Mapping[str, object] | None = None,
    reference_runtime_inventory: Mapping[str, object] | None = None,
    reference_allocation_requirements: list[Mapping[str, object]] | None = None,
    reference_origin_capacity: int | None = None,
    image_size: int | None = None,
    probe_empty_frame: bool = False,
    mutable_frame_views: tuple = (),
    private_stack_writes: tuple = (),
    summary_ranges: bool = False,
    summary_current_zero: bool = False,
    probe_image_frame: bool = False,
    private_stack_accesses: tuple[tuple[int, int], ...] | None = None,
    framed_shared_summaries: bool = False,
    maximum_input_allocations: int = 0,
    memory_fact_capacity: int = 0,
    runtime_assurance: Mapping[str, object] | None = None,
    projection_frame: Mapping[str, object] | None = None,
) -> str:
    """Render paired sparse memories and a shared call/atomic oracle."""

    from .bisimulation_assurance import runtime_contract_selected
    byte_projection = runtime_contract_selected(runtime_assurance, "allocation-byte-projection")
    native_access = runtime_contract_selected(runtime_assurance, "native-memory-admission")
    from .bisimulation_memory_facts import world_fragments
    memory_facts = world_fragments(memory_fact_capacity)
    from .bisimulation_projection_frames import world_fragments as projection_frame_fragments
    parameter_frame = projection_frame_fragments(projection_frame)
    if projection_frame and (maximum_input_allocations or memory_fact_capacity
            or reference_allocation_requirements is not None or reference_runtime_inventory is not None
            or runtime_assurance is not None or summary_ranges or mutable_frame_views
            or any(row.get("provider_kind") != "component_operation"
                   for row in (*service_bindings, *(reference_service_bindings or ())))):
        raise BisimulationRefinementError("parameter slot frames do not yet support allocation, service-memory or conditional runtime effects")

    call_specs = _proof_call_specs(service_bindings,
                                  allow_lifetime_effects=reference_runtime_inventory is not None or reference_allocation_requirements is not None)
    authority = checked_reference_authority(reference_authority)
    call_memory = call_memory_fragments()
    lifetime_calls, authority_source, allocations, reference_capacity, allocation_capacity = allocation_configuration(
        specs=call_specs, max_calls=max_calls, maximum_inputs=maximum_input_allocations,
        max_nul_views=max_nul_views, reference_capacity=reference_origin_capacity,
        authority_payload=reference_authority, inventory=reference_runtime_inventory,
        requirements=reference_allocation_requirements, private_ranges=private_ranges,
        immutable_bytes=immutable_bytes, image_size=image_size,
        runtime_assurance=runtime_assurance)
    call_ranges = call_range_fragments(specs=call_specs,
        authority=checked_reference_authority(reference_authority), image_size=image_size, private_ranges=private_ranges,
        frame_check=frame_write_check(probe_empty_frame) + mutable_frame_write_check(mutable_frame_views) +
        private_frame.write_check(private_stack_writes) + image_frame.access_check(probe_image_frame),
        summary_ranges=summary_ranges, reference_capacity=reference_capacity)
    # Static store bounds omit external effects. Reserve one event per writable
    # footprint at each bounded call, independently of the footprint's byte size.
    max_writes += max_calls * call_ranges["writes_per_call"]
    exposed = exposed_stack_fragments(capacity=max_exposed_stack_views, private_ranges=private_ranges)
    reference_private_check = (
        "  if (!spx_proof_range_is_public(world, address, extent))"
        if max_exposed_stack_views else """
  if (world != 0 && extent != UINT64_C(0) &&
      !((uint64_t)address + extent <= (uint64_t)world->private_low ||
        (uint64_t)address >= (uint64_t)world->private_high))"""
    )
    nul_range_admission = (
        "  __CPROVER_assume(spx_proof_range_is_public(&spx_source_world, address, extent));\n"
        "  __CPROVER_assume(spx_proof_range_is_public(&spx_exact_world, address, extent));"
        if max_exposed_stack_views else """
  __CPROVER_assume((uint64_t)address + (uint64_t)extent <=
          (uint64_t)spx_source_world.private_low ||
      (uint64_t)address >= (uint64_t)spx_source_world.private_high);
  __CPROVER_assume((uint64_t)address + (uint64_t)extent <=
          (uint64_t)spx_exact_world.private_low ||
      (uint64_t)address >= (uint64_t)spx_exact_world.private_high);""")
    frame_preservation = """
  if (spx_proof_address_exposed(address)) {
    uint32_t fault = 0U;
    uint32_t previous = spx_proof_source_read(0, address, 1U, &fault);
    __CPROVER_spx_source_frame_preserved &= fault == 0U && previous == byte;
  }
""" if max_exposed_stack_views else ""
    call_ranges = with_terminated_reads(call_ranges, specs=call_specs,
        reference_capacity=reference_capacity, max_nul_views=max_nul_views, max_calls=max_calls,
        max_zero_writes=max_writes if summary_current_zero else 0,
        access_check=f'  {image_frame.FRAME.guard}(0U);' if probe_image_frame else '')
    reference_result_relations = reference_result_relations or {}
    reference_call_spec_ids = {
        int(spec["spec_id"])
        for spec in _proof_call_specs(
            service_bindings
            if reference_service_bindings is None
            else reference_service_bindings,
            allow_lifetime_effects=reference_runtime_inventory is not None or reference_allocation_requirements is not None,
        )
    }
    behavior_specs_by_id: dict[int, Mapping[str, object]] = {}
    for spec in call_specs:
        behavior_specs_by_id.setdefault(int(spec["spec_id"]), spec)
    behavior_specs = list(behavior_specs_by_id.values())
    max_arguments = max(
        (len(spec["raw_indices"]) for spec in behavior_specs), default=0
    )
    max_cell_inputs = max(
        (len(spec["cell_inputs"]) for spec in behavior_specs), default=0
    )
    max_outputs = max((len(spec["outputs"]) for spec in behavior_specs), default=0)
    max_stack_inputs = max(
        (len(spec["offsets"]) for spec in behavior_specs), default=0
    )
    event_spec_cases = "\n".join(
        "  if (event->kind == {kind} && "
        "event->instruction_rva == UINT32_C({instruction}) && "
        "event->call_index == UINT32_C({index}) && "
        "event->return_rva == UINT32_C({returned})) "
        "return UINT32_C({spec_id});".format(
            kind=spec["event_kind"],
            instruction=spec["instruction_rva"],
            index=spec["event_index"],
            returned=spec["return_rva"],
            spec_id=spec["spec_id"],
        )
        for spec in call_specs
    )
    record_cases: list[str] = []
    replay_cases: list[str] = []
    apply_output_cases: list[str] = []
    apply_response_cases: list[str] = []
    typed_origin_constraints: dict[
        int, tuple[int, Mapping[str, object], int | None]
    ] = {}
    for spec in behavior_specs:
        spec_id = int(spec["spec_id"])
        offsets = list(spec["offsets"])
        raw_indices = list(spec["raw_indices"])
        cell_inputs = list(spec["cell_inputs"])
        outputs = list(spec["outputs"])
        origin_raw_position: int | None = None
        origin_constraint = (
            reference_result_relations.get(str(spec["service_id"]))
            if spec_id in reference_call_spec_ids
            else None
        )
        conditional_raw_position: int | None = None
        if origin_constraint is not None:
            origin_physical_index = logical_argument_physical_index(
                str(spec["service_id"]),
                origin_constraint.get("input_argument_index"),
                service_bindings=service_bindings if reference_service_bindings is None else reference_service_bindings,
            )
            matching_positions = [
                position
                for position, physical_index in enumerate(raw_indices)
                if int(physical_index) == origin_physical_index
            ]
            if len(matching_positions) != 1:
                raise BisimulationRefinementError(
                    "proof-world reference-result origin is absent or duplicated"
                )
            origin_raw_position = matching_positions[0]
            remaining = origin_constraint.get("nonnull_min_remaining")
            if isinstance(remaining, Mapping):
                conditional_physical_index = logical_argument_physical_index(
                    str(spec["service_id"]),
                    remaining.get("nonzero_argument_index"),
                    service_bindings=service_bindings if reference_service_bindings is None else reference_service_bindings,
                )
                conditional_positions = [
                    position
                    for position, physical_index in enumerate(raw_indices)
                    if int(physical_index) == conditional_physical_index
                ]
                if len(conditional_positions) != 1:
                    raise BisimulationRefinementError(
                        "proof-world reference-result condition is absent or duplicated"
                    )
                conditional_raw_position = conditional_positions[0]
            typed_origin_constraints[spec_id] = (
                origin_raw_position,
                origin_constraint,
                conditional_raw_position,
            )
        record = [
            f"  if (spec == UINT32_C({spec_id})) {{",
            f"    call->argument_count = UINT32_C({len(raw_indices)});",
            f"    call->cell_input_count = UINT32_C({len(cell_inputs)});",
            f"    call->output_count = UINT32_C({len(outputs)});",
        ]
        replay = [
            f"  if (spec == UINT32_C({spec_id})) {{",
            f"    __CPROVER_assert(call->argument_count == UINT32_C({len(raw_indices)}),",
            f'        "spx-bisimulation-call-argument-count:{spec_id}");',
            f"    __CPROVER_assert(call->cell_input_count == UINT32_C({len(cell_inputs)}),",
            f'        "spx-bisimulation-call-cell-count:{spec_id}");',
            f"    __CPROVER_assert(call->output_count == UINT32_C({len(outputs)}),",
            f'        "spx-bisimulation-call-output-count:{spec_id}");',
            f"    __CPROVER_assume(call->argument_count == UINT32_C({len(raw_indices)}));",
            f"    __CPROVER_assume(call->cell_input_count == UINT32_C({len(cell_inputs)}));",
            f"    __CPROVER_assume(call->output_count == UINT32_C({len(outputs)}));",
        ]
        if bool(spec["compare_target"]):
            record.extend(
                [
                    "    __CPROVER_assert(event->target_rva != UINT32_C(0),",
                    f'        "spx-bisimulation-call-target-valid:{spec_id}");',
                    "    __CPROVER_assume(event->target_rva != UINT32_C(0));",
                ]
            )
            replay.extend(
                [
                    "    __CPROVER_assert(call->target_rva != UINT32_C(0) &&",
                    "        call->target_rva == event->target_rva,",
                    f'        "spx-bisimulation-call-target:{spec_id}");',
                    "    __CPROVER_assume(call->target_rva != UINT32_C(0) &&",
                    "        call->target_rva == event->target_rva);",
                ]
            )
        for position, physical_index in enumerate(raw_indices):
            offset = offsets[int(physical_index)]
            expression = (
                "spx_proof_call_argument(world, event, input, "
                f"UINT32_C({offset}), &fault)"
            )
            record.append(f"    call->arguments[{position}] = {expression};")
            replay.extend(
                [
                    f"    __CPROVER_assert(call->arguments[{position}] == {expression},",
                    f'        "spx-bisimulation-call-argument:{spec_id}:{position}");',
                    f"    __CPROVER_assume(call->arguments[{position}] == {expression});",
                ]
            )
        for position, raw_cell in enumerate(cell_inputs):
            physical_index = int(raw_cell["physical_index"])
            word_index = int(raw_cell["word_index"])
            expression = (
                "spx_proof_call_event_cell(world, event, input, "
                f"UINT32_C({offsets[physical_index]}), "
                f"UINT32_C({word_index}), &fault)"
            )
            record.append(f"    call->cell_inputs[{position}] = {expression};")
            replay.extend(
                [
                    f"    __CPROVER_assert(call->cell_inputs[{position}] == {expression},",
                    f'        "spx-bisimulation-call-cell-input:{spec_id}:{position}");',
                    f"    __CPROVER_assume(call->cell_inputs[{position}] == {expression});",
                ]
            )
        record.extend(
            [
                "    __CPROVER_assert(fault == UINT32_C(0),",
                f'        "spx-bisimulation-call-input-readable:{spec_id}");',
                "    __CPROVER_assume(fault == UINT32_C(0));",
                "    call->response_eax = spx_nondet_u32();",
                "    call->response_ecx = spx_nondet_u32();",
                "    call->response_edx = spx_nondet_u32();",
                "    call->response_cf = spx_nondet_u32() & UINT32_C(1);",
                "    call->response_zf = spx_nondet_u32() & UINT32_C(1);",
                "    call->response_sf = spx_nondet_u32() & UINT32_C(1);",
                "    call->response_of = spx_nondet_u32() & UINT32_C(1);",
                "    call->response_pf = spx_nondet_u32() & UINT32_C(1);",
                "    call->status = SPX_CALL_OK;",
            ]
        )
        if origin_raw_position is not None:
            origin_type = _mapping(
                origin_constraint.get("origin_type"),
                "proof-world reference-result origin type",
            )
            record.extend(
                [
                    "    if (call->response_eax != UINT32_C(0)) {",
                    "      __CPROVER_assume(call->response_eax >=",
                    f"          call->arguments[{origin_raw_position}]);",
                ]
            )
            if (
                origin_type.get("kind") == "view"
                and origin_type.get("nul_terminated") is True
            ):
                minimum = origin_constraint.get("nonnull_min_remaining")
                record.extend(
                    [
                        "      uint64_t spx_response_origin_extent =",
                        "          (uint64_t)__CPROVER_uninterpreted_spx_nul_extent(",
                        f"              call->arguments[{origin_raw_position}]);",
                        "      uint64_t spx_response_minimum_remaining = UINT64_C(1);",
                    ]
                )
                if isinstance(minimum, Mapping):
                    record.extend(
                        [
                            f"      if (call->arguments[{conditional_raw_position}] != UINT32_C(0))",
                            "        spx_response_minimum_remaining = "
                            f"UINT64_C({int(minimum['minimum'])});",
                        ]
                    )
                record.extend(
                    [
                        "      __CPROVER_assume(spx_response_origin_extent >=",
                        "          spx_response_minimum_remaining);",
                        "      __CPROVER_assume((uint64_t)call->arguments[",
                        f"          {origin_raw_position}] + spx_response_origin_extent <=",
                        "          UINT64_C(4294967296));",
                        "      __CPROVER_assume(",
                        "          (uint64_t)call->response_eax -",
                        f"              (uint64_t)call->arguments[{origin_raw_position}] <=",
                        "          spx_response_origin_extent -",
                        "              spx_response_minimum_remaining);",
                    ]
                )
            record.append("    }")
        for position, raw_output in enumerate(outputs):
            condition = str(raw_output["condition"])
            active = {
                "always": "UINT32_C(1)",
                "success": (
                    "((call->response_eax & UINT32_C(2147483648)) == UINT32_C(0))"
                ),
                "failure": (
                    "((call->response_eax & UINT32_C(2147483648)) != UINT32_C(0))"
                ),
            }[condition]
            record.extend(
                [
                    f"    call->output_active[{position}] = {active};",
                    f"    call->output_values[{position}] = call->output_active[{position}]",
                    (
                        "        ? spx_nondet_nonzero_u32() : UINT32_C(0);"
                        if bool(raw_output["nonnull"])
                        else "        ? spx_nondet_u32() : UINT32_C(0);"
                    ),
                ]
            )
        record.extend(["    return;", "  }"])
        replay.extend(
            [
                "    __CPROVER_assert(fault == UINT32_C(0),",
                f'        "spx-bisimulation-call-replay-input-readable:{spec_id}");',
                "    __CPROVER_assume(fault == UINT32_C(0));",
                "    return;",
                "  }",
            ]
        )
        record_cases.extend(record)
        replay_cases.extend(replay)
        output_case = [f"  if (spec == UINT32_C({spec_id})) {{"]
        for position, raw_output in enumerate(outputs):
            physical_index = int(raw_output["physical_index"])
            word_index = int(raw_output["word_index"])
            output_case.extend(
                [
                    f"    if (call->output_active[{position}] != UINT32_C(0))",
                    "      spx_proof_write_call_cell(world, input, "
                    f"UINT32_C({offsets[physical_index]}), UINT32_C({word_index}),",
                    f"          call->output_values[{position}], &fault);",
                ]
            )
        output_case.extend(
            [
                "    __CPROVER_assert(fault == UINT32_C(0),",
                f'        "spx-bisimulation-call-output-writable:{spec_id}");',
                "    __CPROVER_assume(fault == UINT32_C(0));",
                "    return;",
                "  }",
            ]
        )
        apply_output_cases.extend(output_case)
        apply_response_cases.extend(
            [
                f"  if (spec == UINT32_C({spec_id})) {{",
                "    *output = *input;",
                "    output->eax = call->response_eax;",
                "    output->ecx = call->response_ecx;",
                "    output->edx = call->response_edx;",
                "    output->cf = call->response_cf;",
                "    output->zf = call->response_zf;",
                "    output->sf = call->response_sf;",
                "    output->of = call->response_of;",
                "    output->pf = call->response_pf;",
                f"    output->esp = input->esp + UINT32_C({spec['callee_cleanup']});",
                "    return;",
                "  }",
            ]
        )
    record_call_cases = "\n".join(record_cases)
    replay_call_cases = "\n".join(replay_cases)
    apply_call_output_cases = "\n".join(apply_output_cases)
    apply_call_response_cases = "\n".join(apply_response_cases)
    stack_input_cases = event_stack_input_cases(max_stack_inputs)
    call_proof_fields = (
        "  uint32_t spec, target_rva;\n"
        f"  uint32_t argument_count, arguments[{max(1, max_arguments)}];\n"
        f"  uint32_t cell_input_count, cell_inputs[{max(1, max_cell_inputs)}];\n"
    )
    atomic_proof_fields = "  uint32_t kind, address, width, expected, desired;\n"
    record_call_identity = (
        "  call->spec = spec;\n  call->target_rva = event->target_rva;\n"
    )
    replay_call_identity = (
        "    __CPROVER_assert(call->spec == spec,\n"
        '        "spx-bisimulation-call-identity");\n'
        "    __CPROVER_assume(call->spec == spec);\n"
    )
    atomic_record_identity = (
        "    event->kind = kind;\n"
        "    event->address = address;\n"
        "    event->width = width;\n"
        "    event->expected = expected;\n"
        "    event->desired = desired;\n"
    )
    atomic_replay_checks = (
        "    __CPROVER_assert(exact_position < spx_exact_world.atomic_count &&\n"
        "        exact_position < SPX_PROOF_MAX_ATOMICS &&\n"
        "        event->kind == kind && event->address == address &&\n"
        "        event->width == width && event->expected == expected &&\n"
        '        event->desired == desired, "spx-bisimulation-atomic-event");\n'
        "    __CPROVER_assume(exact_position < spx_exact_world.atomic_count &&\n"
        "        exact_position < SPX_PROOF_MAX_ATOMICS &&\n"
        "        event->kind == kind && event->address == address &&\n"
        "        event->width == width && event->expected == expected &&\n"
        "        event->desired == desired);\n"
    )
    memory = memory_fragments(
        max_writes=max_writes,
        max_private_writes=max_private_writes,
        max_shadow_bytes=max_shadow_bytes,
        max_nul_views=max_nul_views,
        private_ranges=private_ranges,
        immutable_bytes=immutable_bytes,
        exact_stack_accesses=exact_stack_accesses,
        defer_initial_reads=memory_fact_capacity > 0,
        summary_ranges=summary_ranges,
        allocation_byte_projection=byte_projection,
    )
    exact_byte_cases = memory["exact_byte_cases"]
    exact_private_byte_cases = memory["exact_private_byte_cases"]
    exact_private_read_cases = memory["exact_private_read_cases"]
    exact_shadow_cases = memory["exact_shadow_cases"]
    private_byte_count = memory["private_byte_count"]
    exact_stack_declarations = memory["exact_stack_declarations"]
    exact_stack_read_cases = memory["exact_stack_read_cases"]
    exact_stack_reset = memory["exact_stack_reset"]
    exact_stack_updates = memory["exact_stack_updates"]
    immutable_byte_cases = memory["immutable_byte_cases"]
    nul_extent_cases = memory["nul_extent_cases"]
    private_index_cases = memory["private_index_cases"]
    source_byte_cases = memory["source_byte_cases"]
    source_private_byte_cases = memory["source_private_byte_cases"]
    source_private_read_cases = memory["source_private_read_cases"]
    source_shadow_cases = memory["source_shadow_cases"]
    typed_begin_cases = "\n".join(
        f"  if (position == UINT32_C({position})) {{\n"
        f"    __CPROVER_assert(spx_proof_replay_call_memory(&spx_exact_world.calls[{position}]),\n"
        f'        "spx-bisimulation-typed-call-public-memory:{position}");\n'
        "    spx_proof_typed_call_matches =\n"
        f"        spx_exact_world.calls[{position}].spec == spec &&\n"
        f"        spx_exact_world.calls[{position}].status == SPX_CALL_OK &&\n"
        f"        spx_proof_replay_call_memory(&spx_exact_world.calls[{position}]);\n"
        f"    spx_proof_typed_call_position = UINT32_C({position});\n"
        "    return;\n"
        "  }"
        for position in range(max_calls)
    )
    typed_record_begin_rows: list[str] = []
    for spec in behavior_specs:
        spec_id = int(spec["spec_id"])
        outputs = list(spec["outputs"])
        rows = [
            f"    if (spec == UINT32_C({spec_id})) {{",
            "      spx_proof_call *call = &spx_exact_world.calls[position];",
            "      spx_proof_record_call_memory(call);",
            "      call->spec = spec;",
            "      call->target_rva = UINT32_C(0);",
            f"      call->argument_count = UINT32_C({len(spec['raw_indices'])});",
            f"      call->cell_input_count = UINT32_C({len(spec['cell_inputs'])});",
            f"      call->output_count = UINT32_C({len(outputs)});",
            "      call->response_eax = spx_nondet_u32();",
            "      call->response_ecx = spx_nondet_u32();",
            "      call->response_edx = spx_nondet_u32();",
            "      call->response_cf = spx_nondet_u32() & UINT32_C(1);",
            "      call->response_zf = spx_nondet_u32() & UINT32_C(1);",
            "      call->response_sf = spx_nondet_u32() & UINT32_C(1);",
            "      call->response_of = spx_nondet_u32() & UINT32_C(1);",
            "      call->response_pf = spx_nondet_u32() & UINT32_C(1);",
            "      call->status = SPX_CALL_OK;",
        ]
        for position, raw_output in enumerate(outputs):
            condition = str(raw_output["condition"])
            active = {
                "always": "UINT32_C(1)",
                "success": (
                    "((call->response_eax & UINT32_C(2147483648)) == UINT32_C(0))"
                ),
                "failure": (
                    "((call->response_eax & UINT32_C(2147483648)) != UINT32_C(0))"
                ),
            }[condition]
            rows.extend(
                [
                    f"      call->output_active[{position}] = {active};",
                    f"      call->output_values[{position}] = call->output_active[{position}]",
                    (
                        "          ? spx_nondet_nonzero_u32() : UINT32_C(0);"
                        if bool(raw_output["nonnull"])
                        else "          ? spx_nondet_u32() : UINT32_C(0);"
                    ),
                ]
            )
        rows.extend(
            [
                "      spx_proof_typed_call_position = position;",
                "      spx_proof_typed_recording = UINT32_C(1);",
                "      return;",
                "    }",
            ]
        )
        typed_record_begin_rows.extend(rows)
    typed_record_begin_cases = "\n".join(typed_record_begin_rows)

    typed_result_constraint_rows: list[str] = []
    for spec in behavior_specs:
        spec_id = int(spec["spec_id"])
        rows = [f"  if (call->spec == UINT32_C({spec_id})) {{"]
        constraint = typed_origin_constraints.get(spec_id)
        if constraint is not None:
            origin_position, origin, conditional_position = constraint
            origin_type = _mapping(
                origin.get("origin_type"),
                "typed proof-world reference-result origin type",
            )
            rows.extend(
                [
                    "    if (call->response_eax != UINT32_C(0)) {",
                    "      __CPROVER_assume(call->response_eax >=",
                    f"          call->arguments[{origin_position}]);",
                ]
            )
            if (
                origin_type.get("kind") == "view"
                and origin_type.get("nul_terminated") is True
            ):
                minimum = origin.get("nonnull_min_remaining")
                rows.extend(
                    [
                        "      uint64_t spx_response_origin_extent =",
                        "          (uint64_t)__CPROVER_uninterpreted_spx_nul_extent(",
                        f"              call->arguments[{origin_position}]);",
                        "      uint64_t spx_response_minimum_remaining = UINT64_C(1);",
                    ]
                )
                if isinstance(minimum, Mapping):
                    rows.extend(
                        [
                            f"      if (call->arguments[{conditional_position}] != UINT32_C(0))",
                            "        spx_response_minimum_remaining = "
                            f"UINT64_C({int(minimum['minimum'])});",
                        ]
                    )
                rows.extend(
                    [
                        "      __CPROVER_assume(spx_response_origin_extent >=",
                        "          spx_response_minimum_remaining);",
                        "      __CPROVER_assume((uint64_t)call->arguments[",
                        f"          {origin_position}] + spx_response_origin_extent <=",
                        "          UINT64_C(4294967296));",
                        "      __CPROVER_assume(",
                        "          (uint64_t)call->response_eax -",
                        f"              (uint64_t)call->arguments[{origin_position}] <=",
                        "          spx_response_origin_extent -",
                        "              spx_response_minimum_remaining);",
                    ]
                )
            rows.append("    }")
        rows.extend(["    return;", "  }"])
        typed_result_constraint_rows.extend(rows)
    typed_result_constraint_cases = "\n".join(typed_result_constraint_rows)

    typed_target_cases = "\n".join(
        f"  if (spx_proof_typed_call_position == UINT32_C({position})) {{\n"
        "    spx_proof_typed_call_matches = spx_proof_typed_call_matches &&\n"
        "        value != UINT32_C(0) &&\n"
        f"        spx_exact_world.calls[{position}].target_rva == value;\n"
        "    return;\n"
        "  }"
        for position in range(max_calls)
    )
    typed_argument_cases = "\n".join(
        f"  if (spx_proof_typed_call_position == UINT32_C({position}) &&\n"
        f"      index == UINT32_C({index})) {{\n"
        "    spx_proof_typed_call_matches = spx_proof_typed_call_matches &&\n"
        f"        index < spx_exact_world.calls[{position}].argument_count &&\n"
        f"        spx_exact_world.calls[{position}].arguments[{index}] == value;\n"
        "    return;\n"
        "  }"
        for position in range(max_calls)
        for index in range(max_arguments)
    )
    typed_cell_input_cases = "\n".join(
        f"  if (spx_proof_typed_call_position == UINT32_C({position}) &&\n"
        f"      index == UINT32_C({index})) {{\n"
        "    spx_proof_typed_call_matches = spx_proof_typed_call_matches &&\n"
        f"        index < spx_exact_world.calls[{position}].cell_input_count &&\n"
        f"        spx_exact_world.calls[{position}].cell_inputs[{index}] == value;\n"
        "    return;\n"
        "  }"
        for position in range(max_calls)
        for index in range(max_cell_inputs)
    )
    typed_output_active_cases = "\n".join(
        f"  if (spx_proof_typed_call_position == UINT32_C({position}) &&\n"
        f"      index == UINT32_C({index})) {{\n"
        "    spx_proof_typed_call_matches = spx_proof_typed_call_matches &&\n"
        f"        index < spx_exact_world.calls[{position}].output_count;\n"
        f"    return spx_exact_world.calls[{position}].output_active[{index}];\n"
        "  }"
        for position in range(max_calls)
        for index in range(max_outputs)
    )
    typed_output_cases = "\n".join(
        f"  if (spx_proof_typed_call_position == UINT32_C({position}) &&\n"
        f"      index == UINT32_C({index})) {{\n"
        "    spx_proof_typed_call_matches = spx_proof_typed_call_matches &&\n"
        f"        index < spx_exact_world.calls[{position}].output_count &&\n"
        f"        spx_exact_world.calls[{position}].output_active[{index}] != UINT32_C(0);\n"
        f"    return spx_exact_world.calls[{position}].output_values[{index}];\n"
        "  }"
        for position in range(max_calls)
        for index in range(max_outputs)
    )
    typed_result_cases = "\n".join(
        f"  if (spx_proof_typed_call_position == UINT32_C({position}))\n"
        f"    return spx_exact_world.calls[{position}].response_eax;"
        for position in range(max_calls)
    )
    typed_finish_cases = "\n".join(
        f"  if (spx_proof_typed_call_position == UINT32_C({position})) {{\n"
        "    __CPROVER_assert(spx_proof_typed_call_matches != UINT32_C(0),\n"
        f'        "spx-bisimulation-typed-call-fields:{position}");\n'
        "    __CPROVER_assume(spx_proof_typed_call_matches != UINT32_C(0));\n"
        "    if (spx_proof_property_focus_kind == UINT32_C(1) &&\n"
        f"        spx_proof_property_focus_position == UINT32_C({position}))\n"
        "      __CPROVER_assume(0);\n"
        "  }"
        for position in range(max_calls)
    )
    apply_recorded_outputs = (
        "    spx_proof_apply_call_outputs(\n"
        "        &spx_exact_world, input, call, spec);\n"
    )
    apply_replayed_outputs = (
        "    spx_proof_apply_call_outputs(\n"
        "        &spx_source_world, input, call, spec);\n"
    )
    typed_exact_begin = (
        "  if (context == &spx_exact_world) {\n"
        "    position = spx_exact_world.call_count++;\n"
        "    __CPROVER_assert(position < SPX_PROOF_MAX_CALLS,\n"
        '        "spx-bisimulation-typed-exact-call-capacity");\n'
        "    __CPROVER_assume(position < SPX_PROOF_MAX_CALLS);\n"
        f"{typed_record_begin_cases}\n"
        "    __CPROVER_assert(UINT32_C(0),\n"
        '        "spx-bisimulation-typed-exact-service-spec");\n'
        "    __CPROVER_assume(UINT32_C(0));\n"
        "  }\n"
        if typed_exact_recording
        else ""
    )
    typed_exact_target = (
        "  if (spx_proof_typed_recording != UINT32_C(0)) {\n"
        "    __CPROVER_assert(value != UINT32_C(0),\n"
        '        "spx-bisimulation-typed-exact-call-target");\n'
        "    __CPROVER_assume(value != UINT32_C(0));\n"
        "    spx_exact_world.calls[spx_proof_typed_call_position].target_rva = value;\n"
        "    return;\n"
        "  }\n"
        if typed_exact_recording
        else ""
    )
    typed_exact_argument = (
        "  if (spx_proof_typed_recording != UINT32_C(0)) {\n"
        "    spx_proof_call *call =\n"
        "        &spx_exact_world.calls[spx_proof_typed_call_position];\n"
        "    __CPROVER_assert(index < call->argument_count &&\n"
        "        index < SPX_PROOF_MAX_ARGUMENTS,\n"
        '        "spx-bisimulation-typed-exact-call-argument-index");\n'
        "    __CPROVER_assume(index < call->argument_count &&\n"
        "        index < SPX_PROOF_MAX_ARGUMENTS);\n"
        "    call->arguments[index] = value;\n"
        "    return;\n"
        "  }\n"
        if typed_exact_recording
        else ""
    )
    typed_exact_cell_input = (
        "  if (spx_proof_typed_recording != UINT32_C(0)) {\n"
        "    spx_proof_call *call =\n"
        "        &spx_exact_world.calls[spx_proof_typed_call_position];\n"
        "    __CPROVER_assert(index < call->cell_input_count &&\n"
        "        index < SPX_PROOF_MAX_CELL_INPUTS,\n"
        '        "spx-bisimulation-typed-exact-call-cell-index");\n'
        "    __CPROVER_assume(index < call->cell_input_count &&\n"
        "        index < SPX_PROOF_MAX_CELL_INPUTS);\n"
        "    call->cell_inputs[index] = value;\n"
        "    return;\n"
        "  }\n"
        if typed_exact_recording
        else ""
    )
    typed_exact_result = (
        "  if (spx_proof_typed_recording != UINT32_C(0))\n"
        "    spx_proof_typed_constrain_result(\n"
        "        &spx_exact_world.calls[spx_proof_typed_call_position]);\n"
        if typed_exact_recording
        else ""
    )
    return f"""
#define SPX_PROOF_MAX_WRITES UINT32_C({max_writes})
#define SPX_PROOF_MAX_PRIVATE_WRITES UINT32_C({max_private_writes})
#define SPX_PROOF_MAX_CALLS UINT32_C({max_calls})
#define SPX_PROOF_MAX_ATOMICS UINT32_C({max_atomics})
#define SPX_PROOF_MAX_SHADOW_BYTES UINT32_C({max_shadow_bytes})
#define SPX_PROOF_MAX_NUL_VIEWS UINT32_C({max_nul_views})
{'#define SPX_PROOF_SUMMARY_RANGES 1' + chr(10) if summary_ranges else ''}#define SPX_PROOF_MAX_ARGUMENTS UINT32_C({max(1, max_arguments)})
#define SPX_PROOF_MAX_CELL_INPUTS UINT32_C({max(1, max_cell_inputs)})
#define SPX_PROOF_MAX_CALL_OUTPUTS UINT32_C({max(1, max_outputs)})

typedef struct spx_proof_write_event {{
  uint32_t address, width, value, call_range;
}} spx_proof_write_event;

typedef struct spx_proof_byte_event {{
  uint32_t address;
  uint8_t value;
}} spx_proof_byte_event;

{allocations["declarations"]}
typedef struct spx_proof_call {{
{call_proof_fields.rstrip()}
{call_memory["fields"]}
{lifetime_calls["fields"]}
  uint32_t output_count, output_active[{max(1, max_outputs)}];
  uint32_t output_values[{max(1, max_outputs)}];
  uint32_t response_eax, response_ecx, response_edx;
  uint32_t response_cf, response_zf, response_sf, response_of, response_pf;
  spx_call_status status;
}} spx_proof_call;

typedef struct spx_proof_atomic {{
{atomic_proof_fields.rstrip()}
  uint32_t observed, exchanged, fault;
}} spx_proof_atomic;

typedef struct spx_proof_world {{
{allocations["world_fields"]}
  uint32_t replay, write_count, private_write_count;
  uint32_t call_count, atomic_count, shadow_count, private_low, private_high;
  uint32_t private_anchor;
  uint32_t private_scope_anchor;
  uint32_t nul_view_count, nul_view_bases[{max_nul_views}], nul_view_extents[{max_nul_views}];
  spx_proof_write_event private_writes[{max_private_writes}];
  spx_proof_write_event writes[{max_writes}];
  spx_proof_byte_event shadow[{max_shadow_bytes}];
  spx_proof_call calls[{max_calls}];
  spx_proof_atomic atomics[{max_atomics}];
}} spx_proof_world;

static spx_proof_world spx_exact_world, spx_source_world;
{lifetime_calls["declarations"]}
{call_ranges["declarations"]}
uint32_t __CPROVER_spx_source_frame_preserved;
{exposed["declarations"]}
{origin_declarations(reference_capacity)}
static spx_proof_origins spx_exact_origins, spx_source_origins;
static spx_proof_origins *spx_proof_origins_for(void *world) {{
  if (world == &spx_exact_world) return &spx_exact_origins;
  if (world == &spx_source_world) return &spx_source_origins;
  return 0;
}}
{allocations["helpers"]}
{native_admission.source() if native_access else ''}{exact_stack_declarations}
static uint32_t spx_proof_typed_call_position = UINT32_MAX;
static uint32_t spx_proof_typed_recording;
static uint32_t spx_proof_typed_call_matches;
static uint32_t spx_proof_property_focus_kind;
static uint32_t spx_proof_property_focus_position;
uint8_t __CPROVER_uninterpreted_spx_initial_byte(uint32_t address);
uint8_t __CPROVER_uninterpreted_spx_call_byte(uint32_t position, uint32_t address);
{'uint8_t __CPROVER_uninterpreted_spx_summary_byte(uint32_t token, uint32_t address);' + chr(10) if summary_ranges else ''}uint32_t __CPROVER_uninterpreted_spx_nul_extent(uint32_t address);
{call_memory["declarations"]}
static uint32_t spx_nondet_u32(void) {{ uint32_t value; return value; }}
static uint32_t spx_nondet_nonzero_u32(void) {{
  uint32_t value = spx_nondet_u32();
  return value == UINT32_C(0) ? UINT32_C(1) : value;
}}

void spx_proof_typed_service_begin(void *context, uint32_t spec) {{
  uint32_t position;
  __CPROVER_assert(spx_proof_typed_call_position == UINT32_MAX,
      "spx-bisimulation-typed-service-not-nested");
  __CPROVER_assume(spx_proof_typed_call_position == UINT32_MAX);
{lifetime_calls["typed_reset"]}
{call_ranges["typed_reset"]}
{typed_exact_begin.rstrip()}
  __CPROVER_assert(context == &spx_source_world,
      "spx-bisimulation-typed-service-context");
  __CPROVER_assume(context == &spx_source_world);
  position = spx_source_world.call_count++;
  __CPROVER_assert(position < SPX_PROOF_MAX_CALLS,
      "spx-bisimulation-typed-call-capacity");
  __CPROVER_assume(position < SPX_PROOF_MAX_CALLS);
  __CPROVER_assert(position < spx_exact_world.call_count,
      "spx-bisimulation-typed-call-count");
  __CPROVER_assume(position < spx_exact_world.call_count);
{typed_begin_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-typed-service-position");
  __CPROVER_assume(UINT32_C(0));
}}

void spx_proof_typed_service_target(uint32_t value) {{
  __CPROVER_assert(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS,
      "spx-bisimulation-typed-service-target-active");
  __CPROVER_assume(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS);
{typed_exact_target.rstrip()}
{typed_target_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-typed-service-target-position");
  __CPROVER_assume(UINT32_C(0));
}}

void spx_proof_typed_service_argument(uint32_t index, uint32_t value) {{
  __CPROVER_assert(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS,
      "spx-bisimulation-typed-service-argument-active");
  __CPROVER_assume(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS);
{typed_exact_argument.rstrip()}
{typed_argument_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-typed-service-argument-position");
  __CPROVER_assume(UINT32_C(0));
}}

void spx_proof_typed_service_cell_input(uint32_t index, uint32_t value) {{
  __CPROVER_assert(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS,
      "spx-bisimulation-typed-service-cell-active");
  __CPROVER_assume(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS);
{typed_exact_cell_input.rstrip()}
{typed_cell_input_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-typed-service-cell-position");
  __CPROVER_assume(UINT32_C(0));
}}

static void spx_proof_typed_constrain_result(
    const spx_proof_call *call) {{
  __CPROVER_assert(call != 0,
      "spx-bisimulation-typed-exact-result-call");
  __CPROVER_assume(call != 0);
{typed_result_constraint_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-typed-exact-result-spec");
  __CPROVER_assume(UINT32_C(0));
}}

uint32_t spx_proof_typed_service_result(void) {{
  __CPROVER_assert(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS,
      "spx-bisimulation-typed-service-result-active");
  __CPROVER_assume(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS);
{typed_exact_result.rstrip()}
{lifetime_calls["typed_apply"]}
{call_ranges["typed_apply"]}
{typed_result_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-typed-service-result-position");
  __CPROVER_assume(UINT32_C(0));
  return UINT32_C(0);
}}

uint32_t spx_proof_typed_service_output_active(uint32_t index) {{
  __CPROVER_assert(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS,
      "spx-bisimulation-typed-service-output-active-call");
  __CPROVER_assume(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS);
{typed_output_active_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-typed-service-output-active-index");
  __CPROVER_assume(UINT32_C(0));
  return UINT32_C(0);
}}

uint32_t spx_proof_typed_service_output(uint32_t index) {{
  __CPROVER_assert(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS,
      "spx-bisimulation-typed-service-output-call");
  __CPROVER_assume(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS);
{typed_output_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-typed-service-output-index");
  __CPROVER_assume(UINT32_C(0));
  return UINT32_C(0);
}}

uint32_t spx_proof_exact_call_output(uint32_t call_index, uint32_t output_index) {{
  __CPROVER_assert(call_index < spx_exact_world.call_count &&
      call_index < SPX_PROOF_MAX_CALLS,
      "spx-bisimulation-service-output-call");
  __CPROVER_assume(call_index < spx_exact_world.call_count &&
      call_index < SPX_PROOF_MAX_CALLS);
  __CPROVER_assert(
      output_index < spx_exact_world.calls[call_index].output_count &&
      output_index < SPX_PROOF_MAX_CALL_OUTPUTS &&
      spx_exact_world.calls[call_index].output_active[output_index] != UINT32_C(0),
      "spx-bisimulation-service-output-index");
  __CPROVER_assume(
      output_index < spx_exact_world.calls[call_index].output_count &&
      output_index < SPX_PROOF_MAX_CALL_OUTPUTS &&
      spx_exact_world.calls[call_index].output_active[output_index] != UINT32_C(0));
  return spx_exact_world.calls[call_index].output_values[output_index];
}}

void spx_proof_typed_service_finish(void) {{
  __CPROVER_assert(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS,
      "spx-bisimulation-typed-service-finish-active");
  __CPROVER_assume(spx_proof_typed_call_position < SPX_PROOF_MAX_CALLS);
{lifetime_calls["typed_apply"]}
{call_ranges["typed_apply"]}
  if (spx_proof_typed_recording == UINT32_C(0)) {{
{typed_finish_cases}
  }}
  spx_proof_typed_call_position = UINT32_MAX;
  spx_proof_typed_recording = UINT32_C(0);
}}

static uint32_t spx_proof_is_private(
    const spx_proof_world *world, uint32_t address) {{
{exposed["private"]}
  if (world != 0 && address >= world->private_low &&
      address < world->private_high) {{
    return UINT32_C(1);
  }}
{private_index_cases}
  return UINT32_C(0);
}}

{private_byte_count}
{exposed["helpers"]}
uint32_t spx_proof_typed_service_public_range(
    uint32_t address, uint32_t width) {{
  if (width == UINT32_C(0) || width > UINT32_C(4) ||
      address > UINT32_MAX - width + UINT32_C(1))
    return UINT32_C(0);
  return spx_proof_private_bytes(&spx_exact_world, address, width) == UINT32_C(0) &&
      spx_proof_private_bytes(&spx_source_world, address, width) == UINT32_C(0);
}}

{memory_facts['declarations']}static uint8_t spx_proof_initial_byte(uint32_t address) {{
{memory_facts['read']}{immutable_byte_cases}
  return __CPROVER_uninterpreted_spx_initial_byte(address);
}}

static uint32_t spx_proof_initial_read(
    uint32_t address, uint32_t width, uint32_t *fault) {{
  uint32_t result = UINT32_C(0);
  if (fault == 0 || width == 0U || width > 4U ||
      address > UINT32_MAX - width + 1U) {{
    if (fault != 0) *fault = UINT32_C(1);
    return UINT32_C(0);
  }}
  *fault = UINT32_C(0);
  result = (uint32_t)spx_proof_initial_byte(address);
  if (width > 1U)
    result |= ((uint32_t)spx_proof_initial_byte(address + 1U)) << 8U;
  if (width > 2U)
    result |= ((uint32_t)spx_proof_initial_byte(address + 2U)) << 16U;
  if (width > 3U)
    result |= ((uint32_t)spx_proof_initial_byte(address + 3U)) << 24U;
  return result;
}}

static uint32_t spx_proof_word_suffix(
    uint32_t value, uint32_t byte_offset) {{
  if (byte_offset == UINT32_C(0)) return value;
  if (byte_offset == UINT32_C(1)) return value >> 8U;
  if (byte_offset == UINT32_C(2)) return value >> 16U;
  if (byte_offset == UINT32_C(3)) return value >> 24U;
  return UINT32_C(0);
}}

static uint8_t spx_proof_exact_byte(uint32_t address) {{
{memory['exact_byte_prefix']}  if (spx_proof_is_private(&spx_exact_world, address)) {{
{exact_private_byte_cases}
  }} else {{
{exact_byte_cases}
  }}
{exact_shadow_cases}
{memory['exact_byte_initial']}
}}

static uint8_t spx_proof_source_byte(uint32_t address) {{
{memory['source_byte_prefix']}  if (spx_proof_is_private(&spx_source_world, address)) {{
{source_private_byte_cases}
  }} else {{
{source_byte_cases}
  }}
{source_shadow_cases}
{memory['source_byte_initial']}
}}

uint32_t spx_proof_world_public_memory_equal(void) {{
  if (!spx_proof_allocation_states_equal()) return UINT32_C(0);
  /* The proof assertion quantifies over this fresh, otherwise unused address.
     Compare effective bytes, independent of write order, width, or count. */
  uint32_t address = spx_nondet_u32();
  if (spx_proof_is_private(&spx_exact_world, address) != UINT32_C(0) ||
      spx_proof_is_private(&spx_source_world, address) != UINT32_C(0))
    return UINT32_C(1);
  return spx_proof_exact_byte(address) == spx_proof_source_byte(address);
}}

{call_memory["helpers"]}

uint32_t spx_proof_world_memory_range_equal(uint32_t base, uint64_t extent) {{
  uint32_t address = spx_nondet_u32();
  if (extent > UINT64_C(4294967296) - base) return UINT32_C(0);
  if (address < base || (uint64_t)address - base >= extent) return UINT32_C(1);
  /* Check effective bytes even while this range is still private. Changing
     visibility first could hide values in the preceding private histories. */
  return spx_proof_exact_byte(address) == spx_proof_source_byte(address);
}}

static uint32_t spx_proof_exact_private_read(
    uint32_t address, uint32_t width, uint32_t *matched) {{
  *matched = UINT32_C(0);
{exact_stack_read_cases}
{exact_private_read_cases}
  return UINT32_C(0);
}}

static uint32_t spx_proof_source_private_read(
    uint32_t address, uint32_t width, uint32_t *matched) {{
  *matched = UINT32_C(0);
{source_private_read_cases}
  return UINT32_C(0);
}}

{image_frame.allocation_frame_source(allocation_capacity) if framed_shared_summaries else ''}{image_frame.declarations(probe_image_frame, image_size, private_stack_accesses)}static uint32_t spx_proof_exact_read(
    void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {{
  uint32_t result = UINT32_C(0), matched = UINT32_C(0);
  (void)opaque;
  if (fault == 0 || width == 0U || width > 4U ||
      address > UINT32_MAX - width + 1U) {{
    if (fault != 0) *fault = UINT32_C(1);
    return UINT32_C(0);
  }}
  *fault = UINT32_C(0);
{image_frame.access_check(probe_image_frame, world='&spx_exact_world')}  if (!{native_admission.access_expression(native_access, '&spx_exact_world', False)}) {{
    *fault = UINT32_C(1); return UINT32_C(0);
  }}
  if (spx_proof_private_bytes(&spx_exact_world, address, width) == width) {{
    result = spx_proof_exact_private_read(address, width, &matched);
    if (matched != UINT32_C(0)) return result;
  }}
  result = (uint32_t)spx_proof_exact_byte(address);
  if (width > 1U)
    result |= ((uint32_t)spx_proof_exact_byte(address + 1U)) << 8U;
  if (width > 2U)
    result |= ((uint32_t)spx_proof_exact_byte(address + 2U)) << 16U;
  if (width > 3U)
    result |= ((uint32_t)spx_proof_exact_byte(address + 3U)) << 24U;
  return result;
}}

static uint32_t spx_proof_source_read(
    void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {{
  uint32_t result = UINT32_C(0), matched = UINT32_C(0);
  (void)opaque;
  if (fault == 0 || width == 0U || width > 4U ||
      address > UINT32_MAX - width + 1U) {{
    if (fault != 0) *fault = UINT32_C(1);
    return UINT32_C(0);
  }}
  *fault = UINT32_C(0);
{image_frame.access_check(probe_image_frame, world='&spx_source_world')}  if (!{native_admission.access_expression(native_access, '&spx_source_world', False)}) {{
    *fault = UINT32_C(1); return UINT32_C(0);
  }}
  if (spx_proof_private_bytes(&spx_source_world, address, width) == width) {{
    result = spx_proof_source_private_read(address, width, &matched);
    if (matched != UINT32_C(0)) return result;
  }}
  result = (uint32_t)spx_proof_source_byte(address);
  if (width > 1U)
    result |= ((uint32_t)spx_proof_source_byte(address + 1U)) << 8U;
  if (width > 2U)
    result |= ((uint32_t)spx_proof_source_byte(address + 2U)) << 16U;
  if (width > 3U)
    result |= ((uint32_t)spx_proof_source_byte(address + 3U)) << 24U;
  return result;
}}

static uint32_t spx_proof_read(
    spx_proof_world *world, uint32_t address, uint32_t width, uint32_t *fault) {{
  if (world == &spx_exact_world)
    return spx_proof_exact_read(0, address, width, fault);
  if (world == &spx_source_world)
    return spx_proof_source_read(0, address, width, fault);
  if (fault != 0) *fault = UINT32_C(1);
  return UINT32_C(0);
}}

static void spx_proof_append_write(
    spx_proof_world *world, uint32_t address, uint32_t width,
    uint32_t value) {{
  uint32_t position;
  position = world->write_count++;
  __CPROVER_assert(position < SPX_PROOF_MAX_WRITES,
      "spx-bisimulation-public-write-capacity");
  __CPROVER_assume(position < SPX_PROOF_MAX_WRITES);
{fixed_index_stores('world->writes', max_writes, (('address', 'address'), ('width', 'width'), ('value', 'value'), ('call_range', 'UINT32_C(0)')))}
}}

static void spx_proof_append_private_write(
    spx_proof_world *world, uint32_t address, uint32_t width,
    uint32_t value) {{
  uint32_t position = world->private_write_count++;
  __CPROVER_assert(position < SPX_PROOF_MAX_PRIVATE_WRITES,
      "spx-bisimulation-private-write-capacity");
  __CPROVER_assume(position < SPX_PROOF_MAX_PRIVATE_WRITES);
{fixed_index_stores('world->private_writes', max_private_writes, (('address', 'address'), ('width', 'width'), ('value', 'value')))}
}}

static void spx_proof_initialize_source_byte(
    uint32_t address, uint8_t byte) {{
{frame_preservation}  uint32_t position = spx_source_world.shadow_count++;
  __CPROVER_assert(position < SPX_PROOF_MAX_SHADOW_BYTES,
      "spx-bisimulation-shadow-entry-frame");
  __CPROVER_assume(position < SPX_PROOF_MAX_SHADOW_BYTES);
{fixed_index_stores('spx_source_world.shadow', max_shadow_bytes, (('address', 'address'), ('value', 'byte')))}
}}

static void spx_proof_initialize_source(
    uint32_t address, uint32_t width, uint32_t value) {{
  spx_proof_initialize_source_byte(address, (uint8_t)(value & UINT32_C(255)));
  if (width > 1U)
    spx_proof_initialize_source_byte(address + 1U,
        (uint8_t)((value >> 8U) & UINT32_C(255)));
  if (width > 2U)
    spx_proof_initialize_source_byte(address + 2U,
        (uint8_t)((value >> 16U) & UINT32_C(255)));
  if (width > 3U)
    spx_proof_initialize_source_byte(address + 3U,
        (uint8_t)((value >> 24U) & UINT32_C(255)));
}}

static void spx_proof_register_nul_view(
    uint32_t address, uint32_t minimum_extent) {{
  uint32_t position = spx_source_world.nul_view_count++;
  uint32_t extent = __CPROVER_uninterpreted_spx_nul_extent(address);
  uint32_t terminator_fault = UINT32_C(0);
  __CPROVER_assert(position < SPX_PROOF_MAX_NUL_VIEWS,
      "spx-bisimulation-nul-view-count");
  __CPROVER_assume(position < SPX_PROOF_MAX_NUL_VIEWS);
  __CPROVER_assume(extent != UINT32_C(0));
  __CPROVER_assume(extent >= minimum_extent);
  __CPROVER_assume((uint64_t)address + (uint64_t)extent <=
      UINT64_C(4294967296));
{nul_range_admission}
  __CPROVER_assume(spx_proof_source_read(
      0, address + extent - UINT32_C(1), UINT32_C(1),
      &terminator_fault) == UINT32_C(0));
  __CPROVER_assume(terminator_fault == UINT32_C(0));
  spx_source_world.nul_view_bases[position] = address;
  spx_source_world.nul_view_extents[position] = extent;
  spx_exact_world.nul_view_count = position + UINT32_C(1);
  spx_exact_world.nul_view_bases[position] = address;
  spx_exact_world.nul_view_extents[position] = extent;
}}

{parameter_frame['declarations']}{frame_declarations(probe_empty_frame)}{private_frame.declarations(private_stack_writes)}{mutable_frame_declarations(mutable_frame_views, private_stack_writes)}static void spx_proof_write_world(
    void *opaque, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {{
  spx_proof_world *world = (spx_proof_world *)opaque;
  uint32_t private_bytes;
  if (world == 0 || fault == 0 || width == 0U || width > 4U ||
      address > UINT32_MAX - width + 1U) {{
    if (fault != 0) *fault = UINT32_C(1);
    return;
  }}
  *fault = UINT32_C(0);
{image_frame.access_check(probe_image_frame)}  if (!{native_admission.access_expression(native_access, 'world', True)}) {{
    *fault = UINT32_C(1); return;
  }}
{parameter_frame['write']}{frame_write_check(probe_empty_frame)}{mutable_frame_write_check(mutable_frame_views)}{private_frame.write_check(private_stack_writes)}  private_bytes = spx_proof_private_bytes(world, address, width);
  if (world == &spx_exact_world) {{
{exact_stack_updates}
  }}
  /* Mirror a crossing store into both histories. Each byte consults only its
     own partition, preserving order across later mixed and unmixed stores. */
  if (private_bytes != UINT32_C(0))
    spx_proof_append_private_write(world, address, width, value);
  if (private_bytes != width)
    spx_proof_append_write(world, address, width, value);
}}

static void spx_proof_exact_write(
    void *opaque, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {{
  (void)opaque;
  spx_proof_write_world(&spx_exact_world, address, width, value, fault);
}}

static void spx_proof_source_write(
    void *opaque, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {{
  (void)opaque;
  spx_proof_write_world(&spx_source_world, address, width, value, fault);
}}

static uint32_t spx_proof_call_spec(const spx_call_event *event) {{
  if (event == 0) return UINT32_C(0);
{event_spec_cases}
  return UINT32_C(0);
}}

static uint32_t spx_proof_call_word(
    spx_proof_world *world, const spx_machine_state *input,
    uint32_t offset, uint32_t *fault) {{
  if (input == 0 || input->esp > UINT32_MAX - offset) {{
    *fault = UINT32_C(1);
    return UINT32_C(0);
  }}
  return spx_proof_read(world, input->esp + offset, UINT32_C(4), fault);
}}

static uint32_t spx_proof_call_argument(
    spx_proof_world *world, const spx_call_event *event,
    const spx_machine_state *input, uint32_t offset, uint32_t *fault) {{
  if (fault == 0) return UINT32_C(0);
  *fault = UINT32_C(0);
{stack_input_cases}
  return spx_proof_call_word(world, input, offset, fault);
}}

static uint32_t spx_proof_call_event_cell(
    spx_proof_world *world, const spx_call_event *event,
    const spx_machine_state *input, uint32_t argument_offset,
    uint32_t word_index, uint32_t *fault) {{
  uint32_t base = spx_proof_call_argument(
      world, event, input, argument_offset, fault);
  uint32_t byte_offset;
  if (*fault != UINT32_C(0) || word_index > UINT32_MAX / UINT32_C(4)) {{
    *fault = UINT32_C(1);
    return UINT32_C(0);
  }}
  byte_offset = word_index * UINT32_C(4);
  if (base > UINT32_MAX - byte_offset) {{
    *fault = UINT32_C(1);
    return UINT32_C(0);
  }}
  return spx_proof_read(world, base + byte_offset, UINT32_C(4), fault);
}}

static void spx_proof_write_call_cell(
    spx_proof_world *world, const spx_machine_state *input,
    uint32_t argument_offset, uint32_t word_index, uint32_t value,
    uint32_t *fault) {{
  uint32_t base = spx_proof_call_word(world, input, argument_offset, fault);
  uint32_t byte_offset;
  if (*fault != UINT32_C(0) || word_index > UINT32_MAX / UINT32_C(4)) {{
    *fault = UINT32_C(1);
    return;
  }}
  byte_offset = word_index * UINT32_C(4);
  if (base > UINT32_MAX - byte_offset) {{
    *fault = UINT32_C(1);
    return;
  }}
  spx_proof_write_world(
      world, base + byte_offset, UINT32_C(4), value, fault);
}}

static void spx_proof_record_call(
    spx_proof_world *world, const spx_call_event *event,
    const spx_machine_state *input, spx_proof_call *call,
    uint32_t spec) {{
  uint32_t fault = UINT32_C(0);
{record_call_identity.rstrip()}
  spx_proof_record_call_memory(call);
{record_call_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-call-record-spec");
  __CPROVER_assume(UINT32_C(0));
}}

static void spx_proof_replay_call(
    spx_proof_world *world, const spx_call_event *event,
    const spx_machine_state *input,
    const spx_proof_call *call, uint32_t spec) {{
  uint32_t fault = UINT32_C(0);
  __CPROVER_assert(spx_proof_replay_call_memory(call),
      "spx-bisimulation-call-public-memory");
{replay_call_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-call-replay-spec");
  __CPROVER_assume(UINT32_C(0));
}}

static void spx_proof_apply_call_outputs(
    spx_proof_world *world, const spx_machine_state *input,
    const spx_proof_call *call, uint32_t spec) {{
  uint32_t fault = UINT32_C(0);
{apply_call_output_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-call-output-spec");
  __CPROVER_assume(UINT32_C(0));
}}

static void spx_proof_apply_call_response(
    spx_proof_world *world, const spx_machine_state *input,
    spx_machine_state *output, const spx_proof_call *call, uint32_t spec) {{
{apply_call_response_cases}
  __CPROVER_assert(UINT32_C(0),
      "spx-bisimulation-call-response-spec");
  __CPROVER_assume(UINT32_C(0));
  *output = *input;
}}

{call_ranges["helpers"]}
static spx_call_status spx_proof_exact_external_call(
    spx_runtime *runtime, const spx_call_event *event,
    const spx_machine_state *input, spx_machine_state *output) {{
  uint32_t position = spx_exact_world.call_count++;
  uint32_t spec = spx_proof_call_spec(event);
  (void)runtime;
  __CPROVER_assert(position < SPX_PROOF_MAX_CALLS,
      "spx-bisimulation-exact-call-capacity");
  __CPROVER_assume(position < SPX_PROOF_MAX_CALLS);
  __CPROVER_assert(spec != UINT32_C(0),
      "spx-bisimulation-exact-call-spec");
  __CPROVER_assume(spec != UINT32_C(0));
  {{
    spx_proof_call *call = &spx_exact_world.calls[position];
    spx_proof_record_call(&spx_exact_world, event, input, call, spec);
{lifetime_calls["exact_apply"]}
{call_ranges["exact_apply"]}
{apply_recorded_outputs.rstrip()}
    spx_proof_apply_call_response(
        &spx_exact_world, input, output, call, spec);
    return call->status;
  }}
}}

static spx_call_status spx_proof_source_external_call(
    spx_runtime *runtime, const spx_call_event *event,
    const spx_machine_state *input, spx_machine_state *output) {{
  uint32_t position = spx_source_world.call_count++;
  uint32_t spec = spx_proof_call_spec(event);
  (void)runtime;
  __CPROVER_assert(position < SPX_PROOF_MAX_CALLS,
      "spx-bisimulation-source-call-capacity");
  __CPROVER_assume(position < SPX_PROOF_MAX_CALLS);
  __CPROVER_assert(spec != UINT32_C(0),
      "spx-bisimulation-source-call-spec");
  __CPROVER_assume(spec != UINT32_C(0));
  {{
    uint32_t exact_position = position;
    __CPROVER_assert(exact_position < spx_exact_world.call_count &&
        exact_position < SPX_PROOF_MAX_CALLS,
        "spx-bisimulation-call-count");
    __CPROVER_assume(exact_position < spx_exact_world.call_count &&
        exact_position < SPX_PROOF_MAX_CALLS);
    spx_proof_call *call = &spx_exact_world.calls[exact_position];
{replay_call_identity.rstrip()}
    spx_proof_replay_call(&spx_source_world, event, input, call, spec);
{lifetime_calls["source_apply"]}
{call_ranges["source_apply"]}
{apply_replayed_outputs.rstrip()}
    spx_proof_apply_call_response(
        &spx_source_world, input, output, call, spec);
    return call->status;
  }}
}}

static void spx_proof_atomic_common(
    void *opaque, uint32_t kind, uint32_t address, uint32_t width,
    uint32_t expected, uint32_t desired, uint32_t *observed,
    uint32_t *exchanged, uint32_t *fault) {{
  spx_proof_world *world = (spx_proof_world *)opaque;
  uint32_t position = world->atomic_count++;
  __CPROVER_assert(position < SPX_PROOF_MAX_ATOMICS,
      "spx-bisimulation-atomic-capacity");
  __CPROVER_assume(position < SPX_PROOF_MAX_ATOMICS);
  if (world->replay == 0U) {{
    spx_proof_atomic *event = &world->atomics[position];
{atomic_record_identity.rstrip()}
    event->observed = spx_nondet_u32();
    event->fault = spx_nondet_u32() & UINT32_C(1);
    event->exchanged = kind == 0U ? event->observed == expected : 1U;
    *observed = event->observed;
    *exchanged = event->exchanged;
    *fault = event->fault;
    return;
  }}
  {{
    uint32_t exact_position = position;
    __CPROVER_assert(exact_position < spx_exact_world.atomic_count,
        "spx-bisimulation-atomic-count");
    __CPROVER_assume(exact_position < spx_exact_world.atomic_count);
    const spx_proof_atomic *event = &spx_exact_world.atomics[exact_position];
{atomic_replay_checks.rstrip()}
    *observed = event->observed;
    *exchanged = event->exchanged;
    *fault = event->fault;
  }}
}}

static void spx_proof_compare_exchange(
    void *opaque, uint32_t address, uint32_t width, uint32_t expected,
    uint32_t desired, uint32_t *observed, uint32_t *exchanged,
    uint32_t *fault) {{
  spx_proof_atomic_common(opaque, 0U, address, width, expected, desired,
      observed, exchanged, fault);
}}

static void spx_proof_exchange(
    void *opaque, uint32_t address, uint32_t width, uint32_t desired,
    uint32_t *observed, uint32_t *fault) {{
  uint32_t exchanged = UINT32_C(0);
  spx_proof_atomic_common(opaque, 1U, address, width, 0U, desired,
      observed, &exchanged, fault);
}}

{reference_source(reference_capacity=reference_capacity, nul_extent_cases=nul_extent_cases, reference_private_check=reference_private_check, capacity_claim=reference_origin_capacity)}
{authority_source}
{lifetime_calls["helpers"]}
static spx_boundary_status spx_proof_resolve_resource(
    void *opaque, const char *profile, const char *interface_id,
    uint32_t word, uint32_t nullable, spx_machine_resource_v1 *result) {{
  (void)opaque; (void)profile; (void)interface_id;
  if (result == 0 || (word == 0U && nullable == 0U))
    return SPX_BOUNDARY_TYPE_MISMATCH;
  *result = (spx_machine_resource_v1){{
    UINT32_C(1), word == 0U ? UINT32_C(0) : UINT32_C(1), word
  }};
  return SPX_BOUNDARY_OK;
}}

static spx_boundary_status spx_proof_realize_resource(
    void *opaque, const char *profile, const char *interface_id,
    const spx_machine_resource_v1 *resource, uint32_t nullable,
    uint32_t *word) {{
  (void)opaque; (void)profile; (void)interface_id;
  if (resource == 0 || word == 0 ||
      (resource->identity == 0U && nullable == 0U) ||
      resource->identity > UINT32_MAX)
    return SPX_BOUNDARY_TYPE_MISMATCH;
  *word = (uint32_t)resource->identity;
  return SPX_BOUNDARY_OK;
}}

static uint32_t spx_proof_undefined(
    void *opaque, uint32_t slot, const spx_machine_state *input,
    uint32_t defined_value) {{
  (void)opaque; (void)input;
  return defined_value ^ slot;
}}

static uint32_t spx_proof_resolve_code(
    spx_runtime *runtime, spx_code_site_kind kind, uint32_t source,
    uint32_t instruction, uint32_t index, uint32_t target, uint32_t *rva) {{
  (void)runtime; (void)kind; (void)source; (void)instruction;
  (void)index; (void)target; (void)rva;
  return UINT32_C(1);
}}

static uint32_t spx_proof_access_violation(
    void *opaque, uint32_t operation, uint32_t address) {{
  (void)opaque; (void)operation; (void)address;
  return UINT32_C(1);
}}

static spx_runtime spx_proof_runtime(spx_proof_world *world) {{
  spx_runtime result = {{0}};
  result.context = world;
  result.image_base = SPX_PROOF_IMAGE_BASE;
  result.read = world == &spx_source_world
      ? spx_proof_source_read : spx_proof_exact_read;
  result.write = world == &spx_source_world
      ? spx_proof_source_write : spx_proof_exact_write;
  result.atomic_compare_exchange = spx_proof_compare_exchange;
  result.atomic_exchange = spx_proof_exchange;
  result.resolve_reference = {"spx_proof_authority_runtime_resolve" if authority is not None else "spx_proof_resolve_reference"};
  result.realize_reference = {"spx_proof_authority_runtime_realize" if authority is not None else "spx_proof_realize_reference"};
  result.resolve_interface_resource = spx_proof_resolve_resource;
  result.realize_interface_resource = spx_proof_realize_resource;
  result.undefined_value = spx_proof_undefined;
  result.external_call_fallback = world == &spx_source_world
      ? spx_proof_source_external_call : spx_proof_exact_external_call;
  result.resolve_code_target = spx_proof_resolve_code;
  result.record_access_violation = spx_proof_access_violation;
  return result;
}}

static void spx_proof_reset_worlds_in_scope(
    uint32_t entry_esp, uint32_t scope_anchor, uint32_t private_high_offset) {{
{memory_facts['reset']}  __CPROVER_spx_source_frame_preserved = UINT32_C(1);
{exposed["reset"]}
  spx_proof_typed_call_position = UINT32_MAX;
  spx_proof_typed_recording = UINT32_C(0);
  spx_proof_typed_call_matches = UINT32_C(0);
  spx_exact_world.allocation_count = UINT32_C(0);
  spx_exact_world.input_allocation_count = UINT32_C(0);
  spx_exact_world.replay = UINT32_C(0);
  spx_exact_world.write_count = UINT32_C(0);
  spx_exact_world.private_write_count = UINT32_C(0);
  spx_exact_world.call_count = UINT32_C(0);
  spx_exact_world.atomic_count = UINT32_C(0);
  spx_exact_world.shadow_count = UINT32_C(0);
  spx_exact_world.nul_view_count = UINT32_C(0);
  spx_exact_origins.count = UINT32_C(0);
  spx_exact_world.private_low = {frame_private_low(probe_empty_frame, bool(mutable_frame_views)).replace("entry_esp", "scope_anchor")};
  spx_exact_world.private_high = scope_anchor + private_high_offset;
  spx_exact_world.private_anchor = entry_esp;
{parameter_frame['reset']}
  spx_exact_world.private_scope_anchor = scope_anchor;
{exact_stack_reset}
  spx_source_world.allocation_count = UINT32_C(0);
  spx_source_world.input_allocation_count = UINT32_C(0);
  spx_source_world.replay = UINT32_C(1);
  spx_source_world.write_count = UINT32_C(0);
  spx_source_world.private_write_count = UINT32_C(0);
  spx_source_world.call_count = UINT32_C(0);
  spx_source_world.atomic_count = UINT32_C(0);
  spx_source_world.shadow_count = UINT32_C(0);
  spx_source_world.nul_view_count = UINT32_C(0);
  spx_source_origins.count = UINT32_C(0);
  spx_source_world.private_low = {frame_private_low(probe_empty_frame, bool(mutable_frame_views)).replace("entry_esp", "scope_anchor")};
  spx_source_world.private_high = scope_anchor + private_high_offset;
  spx_source_world.private_anchor = entry_esp;
  spx_source_world.private_scope_anchor = scope_anchor;
}}

static void spx_proof_reset_worlds(uint32_t entry_esp, uint32_t private_high_offset) {{
  spx_proof_reset_worlds_in_scope(entry_esp, entry_esp, private_high_offset);
}}

uint32_t spx_proof_private_scope_matches(int64_t scope_anchor) {{
  return scope_anchor >= INT64_C(0) && scope_anchor <= UINT32_MAX &&
      scope_anchor == spx_exact_world.private_scope_anchor &&
      scope_anchor == spx_source_world.private_scope_anchor &&
      spx_exact_world.private_low == spx_source_world.private_low &&
      spx_exact_world.private_high == spx_source_world.private_high;
}}
""".strip()
