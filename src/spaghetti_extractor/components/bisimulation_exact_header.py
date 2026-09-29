"""Render the exact-C proof header from the existing checked relations."""

from __future__ import annotations
import re
from typing import Mapping, Sequence
from .bisimulation_exact_frame import CUT_MACHINE_STATE_GUARD
from .bisimulation_mutable_frame import CUT_FRAME, mutable_cut_frame_checks
from .bisimulation_mutable_machine_frame import CUT_CHECK
from . import bisimulation_memory_facts as memory_facts
from .bisimulation import BisimulationOperationV1, BisimulationSyncV1
from .bisimulation_support import (
    BisimulationRefinementError,
    PROOF_RELATION_WITNESS,
    unit_rva as _unit_rva,
)
from .bisimulation_harness import (
    _cut_view_domain,
    _captured_parameter_view,
    _projection_expression,
    _render_decoding,
)
from .bisimulation_view_context import view_context_proof_source
from .bisimulation_reference_transport import (
    machine_reference_expression, specialize_view_address_checks, view_address_expression,
)
from .bisimulation_stack_scope import scope_expression
from .bisimulation_projection import machine_fact_expression, machine_fact_stack
from .bisimulation_view_extent import cut_view_extent_relation, view_extent_expressions, validate_nul_invariant
from .bisimulation_native_views import native_view_decoder_source, native_view_metadata_relation


def _render_proof_header(
    *,
    authored: BisimulationOperationV1,
    image_base: int,
    unit_rvas: Mapping[str, int] | None = None,
    active_start_sync_id: str | None = None,
    active_target_sync_ids: set[str] | None = None,
    local_havoc: Mapping[str, Sequence[str]] | None = None,
    nul_view_ids: frozenset[str] = frozenset(),
    native_specs: Mapping[str, object] | None = None,
    readable_machine_state: bool = False,
    mutable_views: tuple = (),
    operation_projection: Mapping[str, object] | None = None,
    local_view_specs: Mapping[str, object] | None = None,
) -> str:
    if not 0 <= image_base <= 0xFFFFFFFF:
        raise BisimulationRefinementError(
            "proof-header machine image base is malformed"
        )
    from . import bisimulation_local_views as local_views
    for sync in authored.syncs:
        validate_nul_invariant(sync, nul_view_ids)
    continuation = " " + chr(92)
    specialized = active_target_sync_ids is not None
    active_targets = (
        {sync.identity for sync in authored.syncs}
        if active_target_sync_ids is None
        else set(active_target_sync_ids)
    )
    known_sync_ids = {sync.identity for sync in authored.syncs}
    if (
        active_start_sync_id is not None
        and active_start_sync_id not in known_sync_ids
    ) or not active_targets <= known_sync_ids:
        raise BisimulationRefinementError(
            "proof-header shard specialization names an unknown sync"
        )
    source_codes = {
        sync.identity: index + 1 for index, sync in enumerate(authored.syncs)
    }
    from . import bisimulation_projection_frames as projection_frames
    active_start_sync = next((sync for sync in authored.syncs if sync.identity == active_start_sync_id), None)
    projection_frame = projection_frames.configuration(active_start_sync)
    view_arguments: dict[str, str] = {}
    for sync in authored.syncs:
        for capture, argument in zip(sync.captures, sync.source_arguments(), strict=True):
            if _captured_parameter_view(capture) is None:
                continue
            if (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", argument) is None
                    or view_arguments.get(capture.identity, argument) != argument):
                raise BisimulationRefinementError("view snapshots require one bound C argument across cuts")
            view_arguments[capture.identity] = argument
    resolved_unit_rvas = unit_rvas or {}

    def sync_rva(sync: BisimulationSyncV1) -> int:
        return (
            resolved_unit_rvas[sync.exact_unit_id]
            if sync.exact_unit_id in resolved_unit_rvas
            else _unit_rva(sync.exact_unit_id)
        )

    lines = [
        "#ifndef SPX_COMPONENT_BISIMULATION_H",
        "#define SPX_COMPONENT_BISIMULATION_H",
        '#include "state-machine-runtime.h"',
        "#include <stdint.h>",
        *local_views.header_source(local_view_specs),
        *view_context_proof_source().splitlines(),
        *native_view_decoder_source().splitlines(),
        f"#define SPX_PROOF_IMAGE_BASE UINT32_C({image_base})",
        "extern uint32_t spx_proof_start;",
        "extern uint32_t spx_proof_resumed;",
        "extern uint32_t spx_proof_relation_probe;",
        "extern spx_machine_state spx_proof_exact_input;",
        "extern spx_machine_state spx_proof_exact_output;",
        "extern spx_step_result spx_proof_exact_result;",
        "uint32_t spx_proof_view_admitted(uint32_t address, uint32_t extent, uint32_t stack_pointer);",
        "uint32_t spx_proof_world_memory_range_equal(uint32_t base, uint64_t extent);",
        "uint32_t __CPROVER_uninterpreted_spx_nul_extent(uint32_t address);",
        "uint32_t spx_proof_exact_input_read(uint32_t address, uint32_t width);",
        "uint32_t spx_proof_exact_output_read(uint32_t address, uint32_t width);",
        *projection_frames.header_reader(projection_frame),
        *([f"uint32_t spx_proof_exact_{direction}_stack_read(uint32_t stack, int64_t offset, uint32_t width);"
           for direction in ('input', 'output')] if any(machine_fact_stack(relation)
            for sync in authored.syncs for relation in sync.derived) else []),
        "uint32_t spx_proof_exact_call_output(uint32_t call_index, uint32_t output_index);",
        "uint32_t spx_proof_source_output_read(uint32_t address, uint32_t width);",
        "uint32_t spx_proof_world_calls_equal(void);",
        "uint32_t spx_proof_world_atomics_equal(void);",
        "uint32_t spx_proof_world_public_memory_equal(void);",
        "uint32_t spx_proof_world_allocation_cut_admitted(void);",
        *(["uint32_t spx_proof_private_scope_matches(int64_t scope_anchor);"]
          if any(sync.private_stack_scope is not None for sync in authored.syncs) else []),
        *(f"uint32_t spx_proof_allocation_history_admitted_{sync.identity}(uint32_t stack_pointer);"
          for sync in authored.syncs if sync.allocation_history is not None),
        *memory_facts.declarations(authored),
        "uint32_t spx_proof_world_connected_calls_equal(void);",
        f"void {PROOF_RELATION_WITNESS}(void);",
        *([f"void {CUT_MACHINE_STATE_GUARD}(void);"] if readable_machine_state else []),
        *([f"void {CUT_FRAME.guard}(uint32_t, uint64_t, uint64_t, uint64_t);"] if mutable_views else []),
        *([f"void {CUT_CHECK}(void);"] if mutable_views else []),
        "#define SPX_PROOF_BEGIN(operation_id) SPX_PROOF_BEGIN_I(operation_id)",
        "#define SPX_PROOF_BEGIN_I(operation_id) SPX_PROOF_BEGIN_##operation_id",
        f"#define SPX_PROOF_BEGIN_{authored.operation_id}{continuation}",
        # Declare generated owner storage at the common BEGIN, so extracting a
        # nested cut does not change its compiler identity. Each use assigns it
        # after descriptor validation; no pointer value is carried across cuts.
        *([f"  void *__CPROVER_spx_cut_owner;{continuation}"]
          if any(capture.mode == "native_view" and capture.kind == "source_state"
                 for sync in authored.syncs for capture in sync.captures) else []),
        *(f"  const spx_view_v1 __CPROVER_spx_local_view_{identity} = *({argument});{continuation}"
          for identity, argument in sorted(view_arguments.items())),
        *(f"  const __CPROVER_spx_view_context_snapshot __CPROVER_spx_local_context_{identity} = "
          f"__CPROVER_spx_snapshot_view_context(({argument})->context);{continuation}"
          for identity, argument in sorted(view_arguments.items())),
        f"do {{{continuation}",
        *(
            (
                f"  goto spx_proof_sync_{sync.identity};{continuation}"
                if specialized
                else (
                    f"  if (spx_proof_start == UINT32_C({source_codes[sync.identity]})) "
                    f"goto spx_proof_sync_{sync.identity};{continuation}"
                )
            )
            for sync in authored.syncs
            if sync.identity == active_start_sync_id or not specialized
        ),
        "} while (0)",
        f"#define SPX_PROOF_SYNC(sync_id, invariant, ...){continuation}",
        "  SPX_PROOF_SYNC_I(sync_id, invariant, __VA_ARGS__)",
        f"#define SPX_PROOF_SYNC_I(sync_id, invariant, ...){continuation}",
        "  SPX_PROOF_SYNC_##sync_id(invariant, __VA_ARGS__)",
    ]
    for sync in authored.syncs:
        captures = [item.identity for item in sync.captures]
        framed_target = projection_frames.transports_anchor(active_start_sync, sync)
        output_read = projection_frames.READER if framed_target else "spx_proof_exact_output_read"
        checked_output_addresses: dict[str, str] = {}
        def render_source(value, *, memory):
            return local_views.render_expression(sync, value, memory=memory,
                checked_view_addresses=checked_output_addresses if memory == "output" else None)
        code = source_codes[sync.identity]
        active_start = sync.identity == active_start_sync_id
        active_target = sync.identity in active_targets
        havoc_names = list((local_havoc or {}).get(sync.identity, []))
        for capture, argument in zip(sync.captures, sync.source_arguments(), strict=True):
            if capture.mode == 'native_view' and capture.kind == 'parameter' and (
                    re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', argument) is None or argument in havoc_names):
                raise BisimulationRefinementError('native parameter view requires a stable canonical argument binding')
        if havoc_names != sorted(set(havoc_names)) or any(
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None for name in havoc_names
        ):
            raise BisimulationRefinementError("source cut local havoc inventory is malformed")
        lines.append(
            f"#define SPX_PROOF_HAVOC_LOCALS_{sync.identity}() do {{ "
            + " ".join(f"__CPROVER_havoc_object(&{name});" for name in havoc_names)
            + " } while (0)"
        )
        if specialized and not active_start and not active_target:
            # A real visit cannot match any outcome of this region. Keep the
            # shared assertion callable with true only for inventory retention.
            lines.extend(
                [
                    f"void spx_proof_unexpected_sync_{sync.identity}(uint32_t aligned);",
                    f"#define SPX_PROOF_SYNC_{sync.identity}(invariant, {', '.join(captures)})"
                    + continuation,
                    "do {" + continuation,
                    f"  spx_proof_unexpected_sync_{sync.identity}(UINT32_C(0));{continuation}",
                    "  __CPROVER_assume(0);" + continuation,
                    "} while (0)",
                ]
            )
            continue
        start_lines: list[str] = []
        local_view_input_checks: list[str] = []
        logical_start_lines: list[str] = []
        target_lines: list[str] = []
        for capture in sorted(sync.captures, key=lambda capture: capture.mode != "native_view"):
            domain = _cut_view_domain(capture, sync=sync, state="spx_proof_exact_output", read=output_read)
            if domain is not None:
                target_lines.append(
                    f'    __CPROVER_assert({domain}, "spx-bisimulation-resumed-view-admission:{sync.identity}:{capture.identity}");'
                    + continuation)
            if capture.mode == "native_view":
                incoming, outgoing = local_views.cut_fragments(sync, capture, local_view_specs)
                start_lines.append(incoming[0] + continuation)
                local_view_input_checks.extend(line + continuation for line in incoming[1:])
                target_lines.extend(line + continuation for line in outgoing)
                continue
            if _captured_parameter_view(capture) is not None:
                for incoming, state, read in (
                    (True, "spx_proof_exact_input", "spx_proof_exact_input_read"),
                    (False, "spx_proof_exact_output", output_read),
                ):
                    extent_relation = cut_view_extent_relation(
                        sync=sync, capture=capture, nul_view_ids=nul_view_ids, state=state, read=read, native=native_specs is not None)
                    if native_specs is not None:
                        extents = view_extent_expressions(
                            projections={c.identity: c.projection for c in sync.captures if c.mode == "machine_codec"},
                            identity=capture.identity, nul_view_ids=nul_view_ids, state=state, read=read, native=True)
                        metadata = native_view_metadata_relation(capture, native_specs[capture.identity], extents)
                        if incoming:
                            start_lines.append(f"    __CPROVER_assume({metadata});" + continuation)
                        else:
                            target_lines.append(
                                f'    __CPROVER_assert({metadata}, "spx-bisimulation-capture-metadata:{sync.identity}:{capture.identity}");'
                                + continuation)
                    if incoming:
                        start_lines.append(f"    __CPROVER_assume({extent_relation});" + continuation)
                    else:
                        target_lines.append(
                            f'    __CPROVER_assert({extent_relation}, "spx-bisimulation-capture-extent:{sync.identity}:{capture.identity}");'
                            + continuation)
                # Native metadata is decoded at the reached machine address.
                # Direct flat diagnostics retain their fixed metadata snapshots.
                # Method pointers and access contexts have separate relations.
                for kind, fields in (
                    ("methods", ("read_u8", "write_u8", "read", "write")),
                    ("metadata", ("base.domain", "base.generation", "base.offset",
                                  "base.permissions", "element_width")),
                ):
                    if kind == "metadata" and native_specs is not None:
                        continue
                    relation = " && ".join(
                        f"({capture.identity})->{field} == __CPROVER_spx_local_view_{capture.identity}.{field}"
                        for field in fields)
                    start_lines.append(f"    __CPROVER_assume({relation});" + continuation)
                    target_lines.append(
                        f'    __CPROVER_assert({relation}, "spx-bisimulation-capture-{kind}:{sync.identity}:{capture.identity}");'
                        + continuation)
                view_base = _projection_expression(capture.projection, state="spx_proof_exact_output",
                                                   read=output_read)
                if view_base is None:
                    raise BisimulationRefinementError("captured view lacks a reconstructible machine address")
                input_base = _projection_expression(capture.projection, state="spx_proof_exact_input",
                                                    read="spx_proof_exact_input_read")
                if input_base is None:
                    raise BisimulationRefinementError("captured view lacks a reconstructible input address")
                for incoming, base in ((True, input_base), (False, view_base)):
                    context_relation = (
                        f"({capture.identity})->context == ({capture.identity})->access_context && "
                        f"__CPROVER_spx_view_context_matches(&__CPROVER_spx_local_context_{capture.identity}, "
                        f"({capture.identity})->context, {base}, ({capture.identity})->extent) && "
                        f"__CPROVER_spx_view_reference_matches(({capture.identity})->context, "
                        f"{machine_reference_expression(f'({capture.identity})->base')}, "
                        f"({capture.identity})->extent, {base})")
                    if incoming:
                        start_lines.append(f"    __CPROVER_assume({context_relation});" + continuation)
                    else:
                        # Realization may record an issued origin. Consume the
                        # result we checked rather than invoking that stateful
                        # validator again in the assumption. A failed first
                        # evaluation remains an ordinary mandatory assertion.
                        context_valid = f"__CPROVER_spx_output_context_{capture.identity}"
                        target_lines.append(
                            f"    const uint32_t {context_valid} = ({context_relation});" + continuation)
                        target_lines.append(
                            f'    __CPROVER_assert({context_valid}, "spx-bisimulation-capture-context:{sync.identity}:{capture.identity}");'
                            + continuation)
                        target_lines.append(f"    __CPROVER_assume({context_valid});" + continuation)
                        if native_specs is not None:
                            # The native context relation just checked the current
                            # reference, lifetime, span and physical address. The
                            # remaining outgoing checks only observe this state.
                            # Keep the established address local to this barrier;
                            # incoming restoration may write aliased descriptors,
                            # and a later barrier must check its own current state.
                            address = f"__CPROVER_spx_checked_output_address_{capture.identity}"
                            checked_output_addresses[capture.identity] = address
                            target_lines.append(f"    const uint32_t {address} = (uint32_t)({base});" + continuation)
                object_base = (
                    f"(uint32_t)((uint64_t){checked_output_addresses[capture.identity]} - ({capture.identity})->base.offset)"
                    if capture.identity in checked_output_addresses
                    else view_address_expression(capture.identity, object_start=True))
                target_lines.append(
                    f'    __CPROVER_assert(spx_proof_world_memory_range_equal({object_base}, ({capture.identity})->base.extent), '
                    f'"spx-bisimulation-capture-reference-memory:{sync.identity}:{capture.identity}");' + continuation)
            if capture.mode == "logical_definition":
                encoded_start = render_source(
                    capture.encoding, memory="input"
                )
                encoded_target = render_source(
                    capture.encoding, memory="output"
                )
                if capture.kind == "source_state":
                    logical_start_lines.append(
                        f"    {capture.identity} = ({encoded_start});{continuation}"
                    )
                target_lines.append(
                    f"    __CPROVER_assert(({capture.identity}) == ({encoded_target}), "
                    f'"spx-bisimulation-capture:{sync.identity}:{capture.identity}");'
                    + continuation
                )
                continue
            input_projection = _projection_expression(
                capture.projection,
                state="spx_proof_exact_input",
                read="spx_proof_exact_input_read",
            )
            output_projection = _projection_expression(
                capture.projection,
                state="spx_proof_exact_output",
                read=output_read,
            )
            if input_projection is None or output_projection is None:
                raise BisimulationRefinementError(
                    f"sync {sync.identity!r} machine capture lacks a projection"
                )
            decoded = _render_decoding(
                capture.decoding, input_projection, memory="input"
            )
            if capture.kind == "source_state":
                start_lines.append(
                    f"    {capture.identity} = ({decoded});{continuation}"
                )
            start_encoding = render_source(
                capture.encoding, memory="input"
            )
            target_encoding = render_source(
                capture.encoding, memory="output"
            )
            start_lines.append(
                f"    __CPROVER_assume(({input_projection}) == ({start_encoding}));"
                + continuation
            )
            target_lines.append(
                f"    __CPROVER_assert(({output_projection}) == ({target_encoding}), "
                f'"spx-bisimulation-capture:{sync.identity}:{capture.identity}");'
                + continuation
            )
            if capture.kind == "source_state":
                # Use the same checked addresses as the outgoing encoding.
                # Incoming restoration deliberately keeps its ordinary reads:
                # restoring other captures can still change aliased state.
                target_decoding = _render_decoding(capture.decoding, output_projection,
                                                  memory="output", renderer=render_source)
                target_lines.append(
                    f"    __CPROVER_assert(({capture.identity}) == ({target_decoding}), "
                    f'"spx-bisimulation-capture-roundtrip:{sync.identity}:{capture.identity}");'
                    + continuation
                )
        # Machine codecs establish the source variables that logical
        # definitions may reference.  Capture identifiers are canonically
        # sorted for stable artifacts, so dependency order cannot come from
        # their lexical order.
        start_lines.extend(logical_start_lines)
        # Other captures can alias descriptor members through distinct C paths.
        # Check the complete descriptor after every restoration has finished.
        start_lines.extend(local_view_input_checks)
        for derived in sync.derived:
            input_projection = _projection_expression(
                derived.projection,
                state="spx_proof_exact_input",
                read="spx_proof_exact_input_read",
            )
            output_projection = _projection_expression(
                derived.projection,
                state="spx_proof_exact_output",
                read=output_read,
            )
            if input_projection is None or output_projection is None:
                raise BisimulationRefinementError(
                    "derived sync relation lacks a projection"
                )
            start_expression = render_source(
                derived.expression, memory="input"
            )
            target_expression = render_source(
                derived.expression, memory="output"
            )
            if derived.expression.get('op') == 'exact_projection':
                input_projection = machine_fact_expression(derived.projection,
                    state='spx_proof_exact_input', direction='input')
                output_projection = machine_fact_expression(derived.projection,
                    state='spx_proof_exact_output', direction='output')
                start_expression = machine_fact_expression(derived.expression['projection'],
                    state='spx_proof_exact_input', direction='input')
                target_expression = machine_fact_expression(derived.expression['projection'],
                    state='spx_proof_exact_output', direction='output')
            start_lines.append(
                f"    __CPROVER_assume(({input_projection}) == ({start_expression}));"
                + continuation
            )
            target_lines.append(
                f"    __CPROVER_assert(({output_projection}) == ({target_expression}), "
                f'"spx-bisimulation-derived:{sync.identity}:{derived.identity}");'
                + continuation
            )
        invariant_start = render_source(sync.invariant, memory="input")
        invariant_target = render_source(sync.invariant, memory="output")
        invariant_target_check = (
            f"    __CPROVER_assert({invariant_target}, "
            f'"spx-bisimulation-invariant:{sync.identity}");' + continuation)
        rva = sync_rva(sync)
        # A regional proof fixes its incoming cut and outgoing barriers. Do not
        # emit reconstruction or observation branches belonging to other phases.
        # A revisit of a start-only cut still reaches the alignment failure.
        has_start = not specialized or active_start
        has_target = not specialized or active_target
        scope_checks = []
        if any(item.private_stack_scope is not None for item in authored.syncs):
            scope = f"spx_proof_private_scope_matches({scope_expression(sync, 'spx_proof_exact_output')})"
            if framed_target:
                # Equal nonwrapping ESP-relative scopes at the same cut imply
                # equal ESPs. Consume this checked fact before framed reads.
                scope_checks.append(f"    const uint32_t __CPROVER_spx_slot_scope = {scope};" + continuation)
                scope = "__CPROVER_spx_slot_scope"
            scope_checks.append(f'    __CPROVER_assert({scope}, "spx-bisimulation-private-stack-scope:{sync.identity}");' + continuation)
            if framed_target:
                scope_checks.append(f"    __CPROVER_assume({scope});" + continuation)
        lines.extend(
            [
                f"#define SPX_PROOF_SYNC_{sync.identity}(invariant, {', '.join(captures)})"
                + continuation,
                f"spx_proof_sync_{sync.identity}: do {{{continuation}",
                *([
                f"  if (spx_proof_start == UINT32_C({code}) && "
                f"spx_proof_resumed == UINT32_C(0)) {{{continuation}",
                f"    SPX_PROOF_HAVOC_LOCALS_{sync.identity}();{continuation}",
                *start_lines,
                "    spx_proof_resumed = UINT32_C(1);" + continuation,
                f"    __CPROVER_assume({invariant_start});{continuation}",
                f"    if (spx_proof_relation_probe != UINT32_C(0)) {{{continuation}",
                f"      {PROOF_RELATION_WITNESS}();{continuation}",
                "      __CPROVER_assume(0);" + continuation,
                "    }" + continuation,
                ] if has_start else []),
                *([
                ("  } else if (spx_proof_exact_result.kind <= SPX_BRANCH &&"
                 if has_start else "  if (spx_proof_exact_result.kind <= SPX_BRANCH &&")
                + continuation,
                f"      spx_proof_exact_result.target_rva == UINT32_C({rva})) {{"
                + continuation,
                *([] if checked_output_addresses else [invariant_target_check]),
                *scope_checks,
                *target_lines,
                *([invariant_target_check] if checked_output_addresses else []),
                *(line + continuation for line in memory_facts.outgoing(sync)),
                *(line + continuation for line in mutable_cut_frame_checks(mutable_views, sync, operation_projection)),
                *([f"    {CUT_CHECK}();" + continuation] if mutable_views else []),
                *([f"    {CUT_MACHINE_STATE_GUARD}();" + continuation] if readable_machine_state else []),
                "    __CPROVER_assert(spx_proof_world_calls_equal(),"
                + continuation,
                f'        "spx-bisimulation-world-calls:{sync.identity}");'
                + continuation,
                "    __CPROVER_assert(spx_proof_world_atomics_equal(),"
                + continuation,
                f'        "spx-bisimulation-world-atomics:{sync.identity}");'
                + continuation,
                "    __CPROVER_assert(spx_proof_world_public_memory_equal(),"
                + continuation,
                f'        "spx-bisimulation-world-memory:{sync.identity}");'
                + continuation,
                (f"    __CPROVER_assert(spx_proof_allocation_history_admitted_{sync.identity}((uint32_t)({scope_expression(sync, 'spx_proof_exact_output')})),"
                 if sync.allocation_history is not None else
                 "    __CPROVER_assert(spx_proof_world_allocation_cut_admitted(),")
                + continuation,
                f'        "spx-bisimulation-allocation-cut-admission:{sync.identity}");'
                + continuation,
                "    __CPROVER_assert(spx_proof_world_connected_calls_equal(),"
                + continuation,
                f'        "spx-bisimulation-world-connected-calls:{sync.identity}");'
                + continuation,
                "    __CPROVER_assume(0);" + continuation,
                ] if has_target else []),
                "  } else {" + continuation,
                # Unmatched markers are failures even when the exact side
                # returned or faulted. They must not expose a later source
                # region to this obligation's bounded execution.
                f'    __CPROVER_assert(0, "spx-bisimulation-sync-alignment:{sync.identity}");'
                + continuation,
                "    __CPROVER_assume(0);" + continuation,
                "  }" + continuation,
                "} while (0)",
            ]
        )
    lines.extend(["#endif", ""])
    return specialize_view_address_checks("\n".join(lines))
