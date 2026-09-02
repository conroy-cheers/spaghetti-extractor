# ruff: noqa: E402, F401, F402
"""Deterministic execution closure over canonical transfer-v2 semantics."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import heapq
from pathlib import Path
import resource
import time
from typing import Any, Iterable, Mapping, MutableMapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .exception_projection import (
    exception_record_projection_paths_v1,
)
from ..boundary import BoundarySchemaV1, TargetDataLayoutV1
from ..calls.frame import PhysicalCallFrameV3
from ..semantic_objects.object_authority import MachineObjectAuthorityV2
from ..external.formats import RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
from ..pe32.behavioral_roots import load_behavioral_roots
from ..pe32.module_interface import Pe32ModuleInterfaceV2
from ..util import sha256_file, write_json
from .formats import MODULE_EXECUTION_CLOSURE_FORMAT
from .exception_semantics import (
    CheckedExceptionTransitionV1,
    X87_EXCEPTION_PROJECTION_FIELDS_V1,
)
from .closure_validation import validate_checked_exception_targets_v1
from .model import TransferPlanError, _Call, _REGISTERS, _Transfer
from .operations import NATIVE_EXCEPTION_EFFECTS_V2
from .plan import load_executable_transfer_plan
from .provenance import (
    BOUNDED_SCALAR_ALTERNATIVE_LIMIT_V1,
    BOTTOM_REFERENCE_V1,
    CONFLICT_REFERENCE_V1,
    ExternalCallbackRuleV1,
    ExternalCallRuleV1,
    ExternalMemoryWriteV1,
    ExternalOutPointerV1,
    ObjectRangeV1,
    ReferenceAtomV1,
    UNKNOWN_SCALAR_REFERENCE_V1,
    ReferenceCatalogV1,
    ReferenceStateV1,
    ReferenceValueV1,
    STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
    adjust_reference_by_constant_v1,
    apply_reference_effects_v1,
    call_parameter_owner_v1,
    captured_stack_owner_v1,
    call_argument_values_v1,
    finite_reference_value_v1,
    is_call_parameter_object_v1,
    instantiate_call_parameter_identity_v1,
    join_reference_values_v1,
    refine_reference_state_for_branch_v1,
)


_OBSERVATIONAL_CLOSURE_METRICS_V1 = frozenset({
    "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
})

# This is a qualification bound rather than a semantic promise. Reachable
# checked state beyond it produces an explicit fail-closed blocker below.
OUTGOING_STACK_PROJECTION_BYTE_LIMIT_V1 = 4096

_EXCEPTION_STATE_PROJECTION_FIELDS_V1 = (
    "registers", "flags", "x87", "stack", "exception_record", "context",
)


from .closure_exception_occurrences import (
    _checked_exception_v1,
    _transfer_exception_occurrences_v1,
)


def _exception_projection_state_v1(
    source: ReferenceStateV1,
    projection: Mapping[str, Any],
    *,
    catalog: ReferenceCatalogV1,
    transition: CheckedExceptionTransitionV1,
    action_values: tuple[ReferenceValueV1, ...],
    function_context_identity: str,
) -> tuple[ReferenceStateV1, tuple[str, ...]]:
    """Project the exact pre-fault state into a checked handler entry state."""

    selected = {
        projection_field: {
            str(value).lower()
            for value in projection.get(projection_field, ())
        }
        for projection_field in _EXCEPTION_STATE_PROJECTION_FIELDS_V1
    }
    issues: set[str] = set()
    register_names = set(_REGISTERS)
    flag_names = {"cf", "zf", "sf", "of", "pf", "df"}
    unsupported_registers = selected["registers"] - register_names
    if unsupported_registers:
        issues.update(
            f"unsupported_register:{name}" for name in unsupported_registers
        )
    unsupported_flags = selected["flags"] - flag_names - {"eflags"}
    if unsupported_flags:
        issues.update(f"unsupported_flag:{name}" for name in unsupported_flags)
    unsupported_stack = selected["stack"] - {"esp"}
    if unsupported_stack:
        issues.update(f"unsupported_stack:{name}" for name in unsupported_stack)
    unsupported_x87 = (
        selected["x87"] - X87_EXCEPTION_PROJECTION_FIELDS_V1
    )
    if unsupported_x87:
        issues.update(f"unsupported_x87:{name}" for name in unsupported_x87)
    (
        exception_record_paths,
        malformed_exception_record,
        bounded_exception_record,
    ) = exception_record_projection_paths_v1(
        frozenset(selected["exception_record"])
    )
    if malformed_exception_record:
        issues.update(
            f"unsupported_exception_record:{name}"
            for name in malformed_exception_record
        )
    if bounded_exception_record:
        issues.update(
            f"unsupported_exception_record_depth:{name}"
            for name in bounded_exception_record
        )
    if any(
        path.depth != 0 and path.field == "exceptionaddress"
        for path in exception_record_paths
    ):
        issues.add("nested_numeric_exception_address_unsupported")
    if any(path.depth != 0 for path in exception_record_paths) and (
        transition.occurrence_kind != "call"
    ):
        issues.add("nested_exception_record_source_unavailable")
    # Numeric code-address fields are valid semantic projections here.  The
    # native ingress realization separately requires pinned layout authority
    # before materializing original numeric values in a candidate image.
    context_registers = selected["context"] & register_names
    context_flags = bool(selected["context"] & {"eflags"})
    unsupported_context = selected["context"] - register_names - {
        "eflags", "eip", "contextflags",
    }
    if unsupported_context:
        issues.update(
            f"unsupported_context:{name}" for name in unsupported_context
        )
    kept_registers = selected["registers"] | context_registers
    if "esp" in selected["stack"]:
        kept_registers.add("esp")
    registers = tuple(
        value if name in kept_registers else UNKNOWN_SCALAR_REFERENCE_V1
        for name, value in zip(_REGISTERS, source.registers, strict=True)
    )
    preserve_all_flags = "eflags" in selected["flags"] or context_flags
    flags = tuple(
        value
        if preserve_all_flags or (index < 6 and (
            "cf", "zf", "sf", "of", "pf", "df"
        )[index] in selected["flags"])
        else UNKNOWN_SCALAR_REFERENCE_V1
        for index, value in enumerate(source.flags)
    )
    flag_relations = tuple(
        relation
        if preserve_all_flags or (index < 6 and (
            "cf", "zf", "sf", "of", "pf", "df"
        )[index] in selected["flags"])
        else None
        for index, relation in enumerate(source.flag_relations)
    )
    kept_register_indexes = {
        _REGISTERS.index(name) for name in kept_registers
    }
    projected = ReferenceStateV1(
        registers=registers,
        flags=flags,
        memory=source.memory,
        call_registers=registers,
        call_flags=flags,
        invalidated_memory_ranges=source.invalidated_memory_ranges,
        all_memory_invalidated=source.all_memory_invalidated,
        callback_registry=source.callback_registry,
        flag_relations=flag_relations,
        scalar_constraints={
            key: values for key, values in source.scalar_constraints.items()
            if key[0] in kept_register_indexes
        },
        preserves_inherited_memory=source.preserves_inherited_memory,
        relational_object_bindings=source.relational_object_bindings,
        written_memory_keys=source.written_memory_keys,
        effect_invalidated_memory_ranges=(
            source.effect_invalidated_memory_ranges
        ),
        effect_all_memory_invalidated=source.effect_all_memory_invalidated,
        possible_allocation_identities=source.possible_allocation_identities,
    )
    materialized_fields = (
        selected["exception_record"] or selected["context"]
    )
    if materialized_fields and any(
        value is None
        for value in (
            transition.native_exception_code,
            transition.native_exception_flags,
            transition.native_exception_parameter_count,
            transition.native_exception_continuable,
        )
    ):
        issues.add("native_exception_metadata_unavailable")
    if issues or not materialized_fields:
        return projected, tuple(sorted(issues))
    assert transition.transition_id is not None
    record_depth = max(
        (path.depth for path in exception_record_paths), default=0
    )
    primary_record_identity = (
        f"exception_record:{transition.transition_id}:"
        f"{function_context_identity}"
    )
    record_identities = (primary_record_identity,) + tuple(
        f"{primary_record_identity}:{depth}"
        for depth in range(1, record_depth + 1)
    )
    record_identity = record_identities[0]
    context_identity = (
        f"exception_context:{transition.transition_id}:"
        f"{function_context_identity}"
    )
    frame_identity = (
        f"exception_handler_frame:{transition.transition_id}:"
        f"{function_context_identity}"
    )
    memory = dict(projected.memory)

    def scalar(value: int) -> ReferenceValueV1:
        return finite_reference_value_v1(scalars=(value,))

    def pointer(identity: str) -> ReferenceValueV1:
        return finite_reference_value_v1(references=(
            ReferenceAtomV1("object", identity, 0),
        ))

    exception_address = (
        transition.source_rva
        if catalog.guest_image_base == 0
        else (catalog.guest_image_base + transition.source_rva) & 0xFFFF_FFFF
    )
    record_values = {
        "exceptioncode": scalar(int(transition.native_exception_code)),
        "exceptionflags": scalar(int(transition.native_exception_flags)),
        "exceptionrecord": (
            pointer(record_identities[1])
            if record_depth != 0
            else scalar(0)
        ),
        "exceptionaddress": catalog.classify_scalar(exception_address),
        "numberparameters": scalar(
            int(transition.native_exception_parameter_count)
        ),
    }
    access_violation = transition.native_exception_access_violation
    if access_violation is not None and len(action_values) >= 3:
        record_values.update({
            f"exceptioninformation[{access_violation[0]}]": action_values[1],
            f"exceptioninformation[{access_violation[1]}]": action_values[2],
        })
    record_offsets = {
        "exceptioncode": 0,
        "exceptionflags": 4,
        "exceptionrecord": 8,
        "exceptionaddress": 12,
        "numberparameters": 16,
        **{
            f"exceptioninformation[{index}]": 20 + index * 4
            for index in range(15)
        },
    }
    for depth in range(record_depth):
        memory[("object", record_identities[depth], 8, 4)] = pointer(
            record_identities[depth + 1]
        )
    for path in exception_record_paths:
        projected_field = path.field
        if path.depth == 0:
            value = record_values.get(projected_field)
        elif projected_field == "exceptionrecord":
            value = (
                pointer(record_identities[path.depth + 1])
                if path.depth < record_depth
                else scalar(0)
            )
        else:
            value = UNKNOWN_SCALAR_REFERENCE_V1
        if value is None:
            issues.add(
                f"exception_record_value_unavailable:{projected_field}"
            )
            continue
        memory[(
            "object",
            record_identities[path.depth],
            record_offsets[projected_field],
            4,
        )] = value

    context_offsets = {
        "edi": 156, "esi": 160, "ebx": 164, "edx": 168,
        "ecx": 172, "eax": 176, "ebp": 180, "eflags": 192,
        "esp": 196,
    }
    for field in selected["context"]:
        if field == "contextflags":
            memory[("object", context_identity, 0, 4)] = scalar(0x10003)
        elif field == "eflags":
            memory[("object", context_identity, 192, 4)] = source.flags[-1]
        elif field == "eip":
            memory[("object", context_identity, 184, 4)] = (
                catalog.classify_scalar(exception_address)
            )
        else:
            memory[("object", context_identity, context_offsets[field], 4)] = (
                source.registers[_REGISTERS.index(field)]
            )

    # IA-32 EXCEPTION_ROUTINE entry frame: return address, exception record,
    # establisher frame, CONTEXT, dispatcher context.  The latter two opaque
    # values stay unknown until their own checked authority exists.
    memory[("object", frame_identity, 0, 4)] = UNKNOWN_SCALAR_REFERENCE_V1
    memory[("object", frame_identity, 4, 4)] = pointer(record_identity)
    memory[("object", frame_identity, 8, 4)] = UNKNOWN_SCALAR_REFERENCE_V1
    memory[("object", frame_identity, 12, 4)] = pointer(context_identity)
    memory[("object", frame_identity, 16, 4)] = UNKNOWN_SCALAR_REFERENCE_V1
    handler_stack = pointer(frame_identity)
    handler_registers = list(projected.registers)
    handler_registers[7] = handler_stack
    return replace(
        projected,
        registers=tuple(handler_registers),
        call_registers=tuple(handler_registers),
        memory=memory,
    ), tuple(sorted(issues))


from .closure_model import (
    ExecutionClosureContextV1,
    ExecutionFunctionContextV1,
    execution_closure_context_with_roots_v1,
    _reference_state_kernel_payload_v1,
    _execution_closure_kernel_context_payload_v1,
    _boundary_reference_state_v1,
    _effect_summary_state_v1,
    _state_object_identities_v1,
    _implicit_memory_value_v1,
    _normalize_reference_memory_v1,
    _reference_states_equal_v1,
    join_reference_states_v1,
)
from .closure_calls import (
    _direct_successors,
    _reference_targets,
    _external_reference_targets,
    _reference_target_resolution_v1,
    _external_tail_return_state_v1,
    _call_targets,
    _external_call_targets,
    _call_target_resolution,
    _call_argument_values,
    _callback_targets,
    _callback_root_state,
    _stack_frame_identity_v1,
    _expire_stack_frame_value_v1,
    _call_parameter_identity_v1,
    _parameterizable_call_value_v1,
    _explicit_outgoing_stack_cells_v1,
    _outgoing_stack_projection_exceeds_limit_v1,
    _raw_outgoing_stack_projection_v1,
    _parameterized_call_inputs_v1,
    _conservative_return_state_for_caller_v1,
    _instantiate_parameter_value_v1,
    _instantiate_parameter_key_v1,
    _instantiate_parameter_range_v1,
    _return_state_for_caller_v1,
    _callee_state,
    _transfer_rpo_priorities_v1,
)
@dataclass(frozen=True, slots=True)
class _ActiveCallFrameV1:
    """One exact abstract call frame used by return and nonlocal control.

    This is analysis-local state, not a second authority artifact.  Every
    field is already computed for the ordinary return-summary composition;
    retaining it lets a declared nonlocal terminator prove that its target is
    an actually active ancestor and reuse the same stack-object expiration.
    """

    caller_key: tuple[int, ExecutionFunctionContextV1]
    callee_context: ExecutionFunctionContextV1
    call: _Call
    caller_state: ReferenceStateV1
    caller_esp: ReferenceValueV1
    parameter_bindings: Mapping[str, ReferenceValueV1]


def _exact_nonlocal_target_v1(value: ReferenceValueV1) -> int | None:
    """Resolve a declared nonlocal target without inventing code authority."""

    if value.kind != "finite":
        return None
    if len(value.scalars) == 1 and not value.references:
        return next(iter(value.scalars))
    targets = _reference_targets(value)
    if targets is None or len(targets) != 1:
        return None
    return targets[0]


def _resolve_nonlocal_transition_v1(
    *,
    source_key: tuple[int, ExecutionFunctionContextV1],
    source_unit_id: str,
    output: ReferenceStateV1,
    target_value: ReferenceValueV1,
    result_value: ReferenceValueV1,
    active_frames: Mapping[
        ExecutionFunctionContextV1,
        Mapping[tuple[tuple[int, ExecutionFunctionContextV1], int], _ActiveCallFrameV1],
    ],
    by_rva: Mapping[int, _Transfer],
    catalog: ReferenceCatalogV1,
    diagnostic_failures: list[dict[str, Any]] | None,
) -> tuple[dict[str, Any] | None, ReferenceStateV1 | None, str | None]:
    """Resolve one nonlocal transfer to one active ancestor continuation."""

    target_rva = _exact_nonlocal_target_v1(target_value)
    if target_rva is None:
        return None, None, "target_not_exact"
    target_transfer = by_rva.get(target_rva)
    if target_transfer is None:
        return None, None, "target_outside_exact_universe"

    candidates: list[
        tuple[
            _ActiveCallFrameV1,
            ReferenceStateV1,
            tuple[str, ...],
        ]
    ] = []
    instantiation_failed = False

    def walk(
        context: ExecutionFunctionContextV1,
        state: ReferenceStateV1,
        abandoned: tuple[str, ...],
        visited: frozenset[ExecutionFunctionContextV1],
    ) -> None:
        nonlocal instantiation_failed
        if context in visited:
            return
        for _edge_key, frame in sorted(
            active_frames.get(context, {}).items()
        ):
            restored, _escaped = _return_state_for_caller_v1(
                state,
                callee_context=frame.callee_context,
                caller_state=frame.caller_state,
                caller_esp=frame.caller_esp,
                parameter_bindings=frame.parameter_bindings,
                catalog=catalog,
                diagnostic_failures=diagnostic_failures,
            )
            if restored is None:
                instantiation_failed = True
                continue
            abandoned_frames = (*abandoned, _stack_frame_identity_v1(context))
            if frame.call.return_rva == target_rva:
                candidates.append((frame, restored, abandoned_frames))
                continue
            walk(
                frame.caller_key[1],
                restored,
                abandoned_frames,
                visited | {context},
            )

    walk(source_key[1], output, (), frozenset())
    if len(candidates) != 1:
        reason = (
            "state_instantiation_unavailable"
            if not candidates and instantiation_failed
            else "active_ancestor_missing"
            if not candidates
            else "active_ancestor_ambiguous"
        )
        return None, None, reason
    frame, resumed, abandoned_frames = candidates[0]
    target_context = frame.caller_key[1]
    core: dict[str, Any] = {
        "source_unit_id": source_unit_id,
        "source_rva": source_key[0],
        "source_context_id": source_key[1].identity,
        "root_rva": source_key[1].root_rva,
        "target_unit_id": target_transfer.identity,
        "target_rva": target_rva,
        "target_context_id": target_context.identity,
        "target_function_entry_rva": target_context.function_entry_rva,
        "abandoned_frame_ids": list(abandoned_frames),
        "value": result_value.payload(),
        "cleanup": {
            "kind": "expire_abandoned_stack_frames",
            "unwind_unit_ids": [],
        },
    }
    transition = {
        "id": "checked-nonlocal-transition-v1:"
        + canonical_sha256_v3(core),
        **core,
    }
    return transition, resumed, None

def build_module_execution_closure_v1(
    *,
    transfer_plan_sha256: str,
    transfers: Iterable[_Transfer],
    context: ExecutionClosureContextV1,
    diagnostic_states: MutableMapping[
        tuple[int, ExecutionFunctionContextV1], ReferenceStateV1
    ] | None = None,
    diagnostic_visits: MutableMapping[
        tuple[int, ExecutionFunctionContextV1], int
    ] | None = None,
    diagnostic_parameter_failures: list[dict[str, Any]] | None = None,
    diagnostic_edge_roots: MutableMapping[
        tuple[int, int, str], set[int]
    ] | None = None,
    dynamic_scheduling: bool = True,
) -> dict[str, Any]:
    """Compute one bounded closure; finite results may authorize downstream use."""

    started = time.monotonic()
    rows = tuple(sorted(transfers, key=lambda row: row.rva_start))
    by_rva = {row.rva_start: row for row in rows}
    rva_by_identity = {row.identity: row.rva_start for row in rows}
    blockers: list[dict[str, Any]] = [dict(row) for row in context.preexisting_blockers]
    if len(by_rva) != len(rows):
        raise ValueError("execution closure transfer RVAs are not unique")
    if len(rva_by_identity) != len(rows):
        raise ValueError("execution closure transfer identities are not unique")
    validate_checked_exception_targets_v1(context, rva_by_identity)
    for root in context.roots:
        if root not in by_rva:
            blockers.append({
                "code": "execution_root_outside_exact_universe",
                "root_rva": root,
            })

    states: dict[
        tuple[int, ExecutionFunctionContextV1], ReferenceStateV1
    ] = {
        (root, ExecutionFunctionContextV1(root, root)):
        context.initial_states.get(root, ReferenceStateV1())
        for root in context.roots if root in by_rva
    }
    priorities = _transfer_rpo_priorities_v1(rows, context.roots)
    pending = [
        (priorities[rva], key) for key in sorted(states) for rva in (key[0],)
    ]
    heapq.heapify(pending)
    queued = set(states)
    reachable_edges: set[tuple[int, int, str]] = set()
    indirect_contexts: dict[
        tuple[int, str, ExecutionFunctionContextV1],
        tuple[tuple[int, ...], tuple[tuple[str, str], ...]] | None,
    ] = {}
    indirect_provenance: dict[
        tuple[int, str, ExecutionFunctionContextV1], ReferenceValueV1
    ] = {}
    external_contracts: set[tuple[str, str]] = set()
    terminal_external_outcomes: set[tuple[int, str, str]] = set()
    callback_escapes: dict[
        tuple[int, str, str, str], tuple[int, ...] | None
    ] = {}
    callback_metadata: dict[
        tuple[int, str, str, str], ExternalCallbackRuleV1
    ] = {}
    external_write_failures: dict[
        tuple[int, int, ExecutionFunctionContextV1],
        tuple[_Call, tuple[ReferenceValueV1, ...], tuple[tuple[str, str], ...]],
    ] = {}
    return_instantiation_failures: dict[
        tuple[
            int, int, ExecutionFunctionContextV1,
            ExecutionFunctionContextV1,
        ],
        _Call,
    ] = {}
    stack_frame_reuse_sites: set[tuple[int, int, str]] = set()
    stack_projection_failures: set[
        tuple[int, int, int, str, int, tuple[int, ...]]
    ] = set()
    return_summaries: dict[ExecutionFunctionContextV1, ReferenceStateV1] = {}
    return_dependents: dict[
        ExecutionFunctionContextV1,
        set[tuple[int, ExecutionFunctionContextV1]],
    ] = {}
    active_call_frames: dict[
        ExecutionFunctionContextV1,
        dict[
            tuple[tuple[int, ExecutionFunctionContextV1], int],
            _ActiveCallFrameV1,
        ],
    ] = {}
    track_nonlocal_call_frames = any(
        transfer.actions[-1].op == "outcome_nonlocal"
        for transfer in by_rva.values()
    )
    nonlocal_contexts: dict[
        tuple[int, ExecutionFunctionContextV1], dict[str, Any] | None
    ] = {}
    nonlocal_failures: dict[
        tuple[int, ExecutionFunctionContextV1], dict[str, Any]
    ] = {}
    checked_exceptions = {
        (row.unit_id, row.effect_index, row.operation): row
        for row in context.checked_exception_transitions
    }
    exception_projection_issues: dict[
        tuple[int, int, str], tuple[str, ...]
    ] = {}
    exception_continuation_failures: dict[
        tuple[int, int, str], tuple[str, ...]
    ] = {}
    steps = 0
    scheduling_edges: set[tuple[int, int]] = set()
    deferred_direct_edges: dict[
        tuple[int, ExecutionFunctionContextV1],
        dict[int, ReferenceStateV1],
    ] = {}
    mutable_baseline_invalidation_index: dict[
        tuple[str, str], list[tuple[str, str, int, int]]
    ] = {}
    immutable_baseline_owners = {
        ("object", row.identity)
        for row in context.catalog.objects if not row.writable
    }
    for baseline_key, baseline_value in context.catalog.initial_memory.items():
        if baseline_key[:2] in immutable_baseline_owners:
            # Unknown guest-write fallbacks cannot mutate loader-protected
            # objects.  Do not materialize their baseline cells as
            # baseline-vs-unknown conflicts when invalidation metadata joins.
            continue
        if join_reference_values_v1(
            baseline_value,
            UNKNOWN_SCALAR_REFERENCE_V1,
            alternative_limit=context.catalog.alternative_limit,
        ) == UNKNOWN_SCALAR_REFERENCE_V1:
            continue
        mutable_baseline_invalidation_index.setdefault(
            baseline_key[:2], []
        ).append(baseline_key)
    baseline_invalidation_index = {
        owner: tuple(sorted(keys))
        for owner, keys in mutable_baseline_invalidation_index.items()
    }
    def discover_dynamic_scheduling_edges(
        source: int, targets: Iterable[int],
    ) -> None:
        """Refresh RPO only for newly closed indirect edges."""

        if not dynamic_scheduling:
            return
        nonlocal priorities, pending
        additions = {
            (source, target) for target in targets
            if target in by_rva and (source, target) not in scheduling_edges
        }
        if not additions:
            return
        scheduling_edges.update(additions)
        priorities = _transfer_rpo_priorities_v1(
            rows, context.roots, frozenset(scheduling_edges)
        )
        pending = [(priorities[key[0]], key) for key in queued]
        heapq.heapify(pending)
    def queue(key: tuple[int, ExecutionFunctionContextV1]) -> None:
        if key not in queued:
            heapq.heappush(pending, (priorities[key[0]], key))
            queued.add(key)

    def enqueue(
        source: tuple[int, ExecutionFunctionContextV1],
        target: int,
        kind: str,
        state: ReferenceStateV1,
        *, target_context: ExecutionFunctionContextV1 | None = None,
    ) -> None:
        state = _boundary_reference_state_v1(state)
        if target not in by_rva:
            blockers.append({
                "code": "execution_edge_outside_exact_universe",
                "source_rva": source[0],
                "target_rva": target,
                "edge_kind": kind,
            })
            return
        resolved_target_context = (
            source[1] if target_context is None else target_context
        )
        edge = (source[0], target, kind)
        reachable_edges.add(edge)
        if diagnostic_edge_roots is not None:
            diagnostic_edge_roots.setdefault(edge, set()).add(
                resolved_target_context.root_rva
            )
        key = (target, resolved_target_context)
        previous = states.get(key)
        joined = (
            _normalize_reference_memory_v1(
                state, context.catalog.initial_memory
            )
            if previous is None else join_reference_states_v1(
                previous, state,
                alternative_limit=context.catalog.alternative_limit,
                baseline_memory=context.catalog.initial_memory,
                baseline_invalidation_index=baseline_invalidation_index,
            )
        )
        # join_reference_states_v1 canonicalizes an unchanged result to the
        # exact left input.  Identity is therefore the authoritative change
        # test here and avoids repeating a full structural/map comparison.
        if previous is not joined:
            states[key] = joined
            queue(key)

    def record_return_summary(
        function_context: ExecutionFunctionContextV1,
        state: ReferenceStateV1,
    ) -> None:
        state = _effect_summary_state_v1(
            _boundary_reference_state_v1(state)
        )
        previous = return_summaries.get(function_context)
        summary = (
            state
            if previous is None else join_reference_states_v1(
                previous,
                state,
                alternative_limit=context.catalog.alternative_limit,
                baseline_memory=context.catalog.initial_memory,
                baseline_invalidation_index=baseline_invalidation_index,
            )
        )
        if previous is not summary:
            return_summaries[function_context] = summary
            for dependent in sorted(
                return_dependents.get(function_context, ())
            ):
                queue(dependent)

    while steps < context.maximum_worklist_steps:
        if not pending:
            if not deferred_direct_edges:
                break
            additions = tuple(
                (source_key, target, successor_state)
                for source_key, targets in sorted(
                    deferred_direct_edges.items()
                )
                for target, successor_state in sorted(targets.items())
            )
            deferred_direct_edges.clear()
            for source_key, target, successor_state in additions:
                enqueue(
                    source_key,
                    target,
                    "direct_control",
                    successor_state,
                )
            if not pending:
                break
        _priority, key = heapq.heappop(pending)
        queued.remove(key)
        rva, function_context = key
        steps += 1
        transfer = by_rva[rva]
        if diagnostic_visits is not None:
            diagnostic_visits[key] = diagnostic_visits.get(key, 0) + 1
        if diagnostic_states is not None:
            diagnostic_states[key] = states[key]
        call_input_states: dict[int, ReferenceStateV1] = {}
        exception_action_states: dict[int, ReferenceStateV1] = {}
        unresolved_external_writes: dict[
            int, tuple[ReferenceValueV1, ...]
        ] = {}
        output, values = apply_reference_effects_v1(
            transfer,
            states[key],
            context.catalog,
            call_input_states=call_input_states,
            unresolved_external_writes=unresolved_external_writes,
            action_input_states=exception_action_states,
        )
        overrides: dict[int, ReferenceStateV1] = {}
        parameterized_call_inputs: dict[
            tuple[int, ExecutionFunctionContextV1],
            tuple[
                tuple[ReferenceValueV1, ...],
                dict[tuple[str, str, int, int], ReferenceValueV1],
                tuple[ReferenceAtomV1, ...],
                dict[str, ReferenceValueV1],
                bool,
            ],
        ] = {}
        waiting_for_return = False
        for call in transfer.calls:
            resolution = _call_target_resolution(
                call, values, context.catalog
            )
            if resolution is None:
                # An unresolved indirect callee has no sound return summary.
                # Propagating the generic clobber state through its
                # continuation can feed that loss back around a loop and erase
                # a target that becomes finite on a later fixed-point step.
                # The site remains a blocker, and its continuation is resumed
                # only once a checked guest or external target is available.
                if call.kind != "external_call":
                    waiting_for_return = True
                continue
            if resolution[1]:
                continue
            targets = resolution[0]
            if targets:
                summary: ReferenceStateV1 | None = None
                missing_summary = False
                for target in targets:
                    callee_context = function_context.child(
                        target_rva=target,
                        instruction_rva=call.instruction_rva,
                        limit=context.call_string_limit,
                    )
                    return_dependents.setdefault(callee_context, set()).add(key)
                    candidate = return_summaries.get(callee_context)
                    if candidate is not None:
                        derived_inputs = _parameterized_call_inputs_v1(
                            call,
                            values,
                            call_input_states[call.call_index],
                            context.catalog,
                            callee_context,
                        )
                        parameterized_call_inputs[
                            (call.call_index, callee_context)
                        ] = derived_inputs
                        (
                            _parameterized_registers,
                            _parameterized_stack,
                            _caller_stack_atoms,
                            parameter_bindings,
                            projection_exceeded,
                        ) = derived_inputs
                        if projection_exceeded:
                            stack_projection_failures.add((
                                rva,
                                call.instruction_rva,
                                call.call_index,
                                function_context.identity,
                                function_context.function_entry_rva,
                                function_context.call_string,
                            ))
                        candidate, _frame_expired = _return_state_for_caller_v1(
                            candidate,
                            callee_context=callee_context,
                            caller_state=call_input_states[call.call_index],
                            caller_esp=values[call.register_nodes[7]],
                            parameter_bindings=parameter_bindings,
                            catalog=context.catalog,
                            diagnostic_failures=diagnostic_parameter_failures,
                        )
                        failure_key = (
                            rva,
                            call.call_index,
                            function_context,
                            callee_context,
                        )
                        if candidate is None:
                            return_instantiation_failures[failure_key] = call
                            candidate = _conservative_return_state_for_caller_v1(
                                return_summaries[callee_context],
                                callee_context=callee_context,
                                caller_state=call_input_states[call.call_index],
                                caller_esp=values[call.register_nodes[7]],
                                parameter_bindings=parameter_bindings,
                                catalog=context.catalog,
                            )
                        else:
                            return_instantiation_failures.pop(failure_key, None)
                        summary = (
                            candidate if summary is None
                            else join_reference_states_v1(
                                summary,
                                candidate,
                                alternative_limit=context.catalog.alternative_limit,
                                baseline_memory=context.catalog.initial_memory,
                                baseline_invalidation_index=(
                                    baseline_invalidation_index
                                ),
                            )
                        )
                    else:
                        missing_summary = True
                if summary is not None and not missing_summary:
                    overrides[call.call_index] = summary
                else:
                    waiting_for_return = True
        if overrides:
            first_call_index = (
                transfer.calls[0].call_index if transfer.calls else -1
            )
            parameterized_call_inputs = {
                cache_key: cached
                for cache_key, cached in parameterized_call_inputs.items()
                if cache_key[0] == first_call_index
            }
            call_input_states.clear()
            unresolved_external_writes.clear()
            exception_action_states.clear()
            output, values = apply_reference_effects_v1(
                transfer,
                states[key],
                context.catalog,
                overrides,
                call_input_states,
                unresolved_external_writes,
                exception_action_states,
            )
        for effect_index, operation, call in _transfer_exception_occurrences_v1(
            transfer
        ):
            effect = transfer.actions[effect_index]
            transition = _checked_exception_v1(
                checked_exceptions,
                unit_id=transfer.identity,
                effect_index=effect_index,
                operation=operation,
            )
            if (
                transition is None
                or not transition.authorizing
                or transition.disposition != "handled"
                or transition.state_projection is None
                or transition.handler_rva is None
            ):
                continue
            projected, projection_issues = _exception_projection_state_v1(
                exception_action_states[effect_index],
                transition.state_projection,
                catalog=context.catalog,
                transition=transition,
                action_values=(
                    ()
                    if call is not None
                    else tuple(values[index] for index in effect.args)
                ),
                function_context_identity=function_context.identity,
            )
            issue_key = (rva, effect_index, function_context.identity)
            if projection_issues:
                exception_projection_issues[issue_key] = projection_issues
                continue
            exception_projection_issues.pop(issue_key, None)
            continuation_state = projected
            continuation_source = key
            continuation_failures: list[str] = []
            for unwind_index, unwind_unit_id in enumerate(
                transition.unwind_unit_ids
            ):
                unwind_rva = rva_by_identity[unwind_unit_id]
                unwind_context = ExecutionFunctionContextV1(
                    root_rva=function_context.root_rva,
                    function_entry_rva=unwind_rva,
                    call_string=((
                        transition.source_rva
                        + transition.effect_index
                        + unwind_index
                    ) & 0xFFFF_FFFF,),
                )
                return_dependents.setdefault(unwind_context, set()).add(key)
                enqueue(
                    continuation_source,
                    unwind_rva,
                    "exception_unwind",
                    continuation_state,
                    target_context=unwind_context,
                )
                summary = return_summaries.get(unwind_context)
                if summary is None:
                    continuation_failures.append(
                        f"unwind_return_summary_unavailable:{unwind_unit_id}"
                    )
                    break
                composed, _escaped = _return_state_for_caller_v1(
                    summary,
                    callee_context=unwind_context,
                    caller_state=continuation_state,
                    caller_esp=continuation_state.registers[7],
                    catalog=context.catalog,
                    diagnostic_failures=diagnostic_parameter_failures,
                )
                if composed is None:
                    continuation_failures.append(
                        "unwind_return_state_instantiation_unavailable:"
                        + unwind_unit_id
                    )
                    break
                continuation_state = composed
                continuation_source = (unwind_rva, unwind_context)
            if continuation_failures:
                exception_continuation_failures[issue_key] = tuple(
                    continuation_failures
                )
                continue
            exception_continuation_failures.pop(issue_key, None)
            handler_context = ExecutionFunctionContextV1(
                root_rva=function_context.root_rva,
                function_entry_rva=transition.handler_rva,
            )
            if transition.resumption_rva is not None:
                return_dependents.setdefault(handler_context, set()).add(key)
            enqueue(
                continuation_source,
                transition.handler_rva,
                "exception_handler",
                continuation_state,
                target_context=handler_context,
            )
            if transition.resumption_rva is None:
                exception_continuation_failures.pop(issue_key, None)
                continue
            handler_summary = return_summaries.get(handler_context)
            if handler_summary is None:
                exception_continuation_failures[issue_key] = (
                    "handler_return_summary_unavailable:"
                    + str(transition.handler_unit_id),
                )
                continue
            resumed, _escaped = _return_state_for_caller_v1(
                handler_summary,
                callee_context=handler_context,
                caller_state=continuation_state,
                caller_esp=continuation_state.registers[7],
                catalog=context.catalog,
                diagnostic_failures=diagnostic_parameter_failures,
            )
            if resumed is None:
                exception_continuation_failures[issue_key] = (
                    "handler_return_state_instantiation_unavailable:"
                    + str(transition.handler_unit_id),
                )
                continue
            exception_continuation_failures.pop(issue_key, None)
            enqueue(
                (transition.handler_rva, handler_context),
                transition.resumption_rva,
                "exception_resumption",
                resumed,
                target_context=ExecutionFunctionContextV1(
                    root_rva=function_context.root_rva,
                    function_entry_rva=transition.resumption_rva,
                ),
            )
        if transfer.actions[-1].op == "outcome_nonlocal":
            target_node, value_node = transfer.actions[-1].args
            transition, resumed, failure = _resolve_nonlocal_transition_v1(
                source_key=key,
                source_unit_id=transfer.identity,
                output=output,
                target_value=values[target_node],
                result_value=values[value_node],
                active_frames=active_call_frames,
                by_rva=by_rva,
                catalog=context.catalog,
                diagnostic_failures=diagnostic_parameter_failures,
            )
            if transition is None or resumed is None:
                nonlocal_contexts[key] = None
                nonlocal_failures[key] = {
                "code": "reachable_nonlocal_outcome_authority_missing",
                "source_rva": rva,
                "unit_id": transfer.identity,
                "function_context": function_context.identity,
                "reason": failure,
                "target": values[target_node].payload(),
                "value": values[value_node].payload(),
                }
            else:
                nonlocal_contexts[key] = transition
                nonlocal_failures.pop(key, None)
                enqueue(
                    key,
                    int(transition["target_rva"]),
                    "nonlocal_control",
                    resumed,
                    target_context=next(
                        frame.caller_key[1]
                        for frames in active_call_frames.values()
                        for frame in frames.values()
                        if frame.caller_key[1].identity
                        == transition["target_context_id"]
                    ),
                )
        for call in transfer.calls:
            failure_key = (rva, call.call_index, function_context)
            external_write_failures.pop(failure_key, None)
            arguments = unresolved_external_writes.get(call.call_index)
            if arguments is None:
                continue
            resolution = _call_target_resolution(
                call, values, context.catalog
            )
            external_write_failures[failure_key] = (
                call,
                arguments,
                () if resolution is None else resolution[1],
            )
        terminal_external_call = False
        tail_external_resolutions = 0
        tail_external_returns = transfer.actions[-1].op == "outcome_external"
        for call in transfer.calls:
            resolution = _call_target_resolution(
                call, values, context.catalog
            )
            if resolution is None:
                continue
            external_targets = resolution[1]
            if external_targets:
                if transfer.actions[-1].op == "outcome_external":
                    tail_external_resolutions += 1
                external_contracts.update(external_targets)
                rules = [
                    context.catalog.external_calls.get(target)
                    for target in external_targets
                ]
                if transfer.actions[-1].op == "outcome_external" and not all(
                    rule is not None and rule.disposition == "returns"
                    for rule in rules
                ):
                    tail_external_returns = False
                if rules and all(
                    rule is not None and rule.disposition == "terminates"
                    for rule in rules
                ):
                    terminal_external_call = True
                    terminal_external_outcomes.update(
                        (rva, dll, identity)
                        for dll, identity in external_targets
                    )
                for dll, identity in external_targets:
                    rule = context.catalog.external_calls.get((dll, identity))
                    if rule is None or rule.callback is None:
                        continue
                    arguments = _call_argument_values(
                        transfer,
                        call,
                        values,
                        call_input_states[call.call_index],
                        context.catalog,
                        rule,
                    )
                    callback = rule.callback
                    escape_key = (
                        call.instruction_rva, dll, identity,
                        callback.protocol_id,
                    )
                    targets = _callback_targets(
                        callback,
                        arguments,
                        call_input_states[call.call_index],
                        context.catalog,
                    )
                    previous = callback_escapes.get(escape_key)
                    if escape_key not in callback_escapes:
                        callback_escapes[escape_key] = targets
                    elif previous is None or targets is None:
                        callback_escapes[escape_key] = None
                    else:
                        callback_escapes[escape_key] = tuple(sorted(
                            set(previous) | set(targets)
                        ))
                    callback_metadata[escape_key] = callback
                    if targets is not None:
                        for target in targets:
                            callback_context = ExecutionFunctionContextV1(
                                target, target
                            )
                            enqueue(
                                key,
                                target,
                                "callback_escape",
                                _callback_root_state(target, output),
                                target_context=callback_context,
                            )
        terminator = transfer.actions[-1]
        if terminator.op == "outcome_branch":
            deferred_direct_edges.pop(key, None)
        if (
            not waiting_for_return
            and not terminal_external_call
            and rva not in context.boundary_exit_rvas
        ):
            direct_successors = _direct_successors(
                transfer,
                values,
                output,
                alternative_limit=context.catalog.alternative_limit,
            )
            for target, successor_state in direct_successors:
                edge = (rva, target, "direct_control")
                if (
                    terminator.op != "outcome_branch"
                    or edge in reachable_edges
                ):
                    enqueue(
                        key, target, "direct_control", successor_state
                    )
                else:
                    deferred_direct_edges.setdefault(key, {})[
                        target
                    ] = successor_state
        inferred_resolution = (
            _reference_target_resolution_v1(
                values[transfer.actions[-1].args[0]], context.catalog
            )
            if transfer.actions[-1].op == "outcome_indirect"
            else None
        )
        if transfer.actions[-1].op == "outcome_indirect" and not waiting_for_return:
            authorized_targets = context.finite_control_targets.get(rva)
            resolution = inferred_resolution
            if authorized_targets is not None:
                if inferred_resolution is None:
                    resolution = (authorized_targets, ())
                elif (
                    not inferred_resolution[1]
                    and set(inferred_resolution[0]) <= set(authorized_targets)
                ):
                    resolution = inferred_resolution
                else:
                    blockers.append({
                        "code": "finite_control_route_conflict",
                        "source_rva": rva,
                    })
                    resolution = None
            site_key = (rva, "terminator", function_context)
            indirect_contexts[site_key] = resolution
            indirect_provenance[site_key] = values[
                transfer.actions[-1].args[0]
            ]
            if resolution is not None:
                targets, external_targets = resolution
                external_contracts.update(external_targets)
                external_return = _external_tail_return_state_v1(
                    transfer=transfer,
                    state=output,
                    targets=external_targets,
                    catalog=context.catalog,
                )
                if external_return is not None:
                    record_return_summary(function_context, external_return)
                if rva not in context.boundary_exit_rvas:
                    discover_dynamic_scheduling_edges(rva, targets)
                    for target in targets:
                        enqueue(key, target, "indirect_control", output)

        for call in transfer.calls:
            resolution = _call_target_resolution(
                call, values, context.catalog
            )
            if call.kind == "external_call":
                continue
            call_targets = None if resolution is None else resolution[0]
            external_targets = () if resolution is None else resolution[1]
            site = f"call:{call.instruction_rva:08x}:{call.call_index}"
            if call.target_node is not None:
                site_key = (rva, site, function_context)
                indirect_contexts[site_key] = resolution
                indirect_provenance[site_key] = values[call.target_node]
            if resolution is None:
                continue
            external_contracts.update(external_targets)
            if call.target_node is not None:
                discover_dynamic_scheduling_edges(rva, call_targets)
            for target in call_targets:
                callee_context = function_context.child(
                    target_rva=target,
                    instruction_rva=call.instruction_rva,
                    limit=context.call_string_limit,
                )
                return_dependents.setdefault(callee_context, set()).add(key)
                (
                    callee_state,
                    frame_reused,
                    parameter_bindings,
                    projection_exceeded,
                ) = _callee_state(
                    call,
                    values,
                    call_input_states[call.call_index],
                    context.catalog,
                    callee_context,
                    parameterized_call_inputs.get((
                        call.call_index, callee_context
                    )),
                )
                if track_nonlocal_call_frames:
                    active_call_frames.setdefault(callee_context, {})[
                        (key, call.call_index)
                    ] = _ActiveCallFrameV1(
                        caller_key=key,
                        callee_context=callee_context,
                        call=call,
                        caller_state=call_input_states[call.call_index],
                        caller_esp=values[call.register_nodes[7]],
                        parameter_bindings=parameter_bindings,
                    )
                if frame_reused:
                    stack_frame_reuse_sites.add((
                        rva,
                        call.instruction_rva,
                        callee_context.identity,
                    ))
                if projection_exceeded:
                    stack_projection_failures.add((
                        rva,
                        call.instruction_rva,
                        call.call_index,
                        function_context.identity,
                        function_context.function_entry_rva,
                        function_context.call_string,
                    ))
                enqueue(
                    key, target, "internal_call",
                    callee_state,
                    target_context=callee_context,
                )

        if transfer.actions[-1].op == "outcome_return":
            record_return_summary(function_context, output)
        elif tail_external_returns and tail_external_resolutions == 1:
            registers = list(output.call_registers)
            registers[7] = adjust_reference_by_constant_v1(
                registers[7], 4, context.catalog
            )
            record_return_summary(
                function_context,
                ReferenceStateV1(
                    registers=tuple(registers),
                    flags=output.call_flags,
                    memory=output.memory,
                    call_registers=output.call_registers,
                    call_flags=output.call_flags,
                    invalidated_memory_ranges=output.invalidated_memory_ranges,
                    all_memory_invalidated=output.all_memory_invalidated,
                    callback_registry=output.callback_registry,
                    flag_relations=(None,) * len(output.flag_relations),
                    scalar_constraints={},
                    preserves_inherited_memory=(
                        output.preserves_inherited_memory
                    ),
                    relational_object_bindings=(
                        output.relational_object_bindings
                    ),
                    written_memory_keys=output.written_memory_keys,
                    effect_invalidated_memory_ranges=(
                        output.effect_invalidated_memory_ranges
                    ),
                    effect_all_memory_invalidated=(
                        output.effect_all_memory_invalidated
                    ),
                    possible_allocation_identities=(
                        output.possible_allocation_identities
                    ),
                ),
            )

    if pending or deferred_direct_edges:
        blockers.append({
            "code": "execution_closure_worklist_bound_exceeded",
            "maximum_steps": context.maximum_worklist_steps,
        })
    blockers.extend(nonlocal_failures.values())
    indirect_sites: dict[
        tuple[int, str],
        tuple[tuple[int, ...], tuple[tuple[str, str], ...]] | None,
    ] = {}
    site_provenance: dict[
        tuple[int, str], dict[str, dict[str, object]]
    ] = {}
    for (rva, site, function_context), resolution in sorted(
        indirect_contexts.items()
    ):
        aggregate_key = (rva, site)
        if aggregate_key not in indirect_sites:
            indirect_sites[aggregate_key] = resolution
        elif indirect_sites[aggregate_key] is None or resolution is None:
            indirect_sites[aggregate_key] = None
        else:
            previous = indirect_sites[aggregate_key]
            assert previous is not None
            indirect_sites[aggregate_key] = (
                tuple(sorted(set(previous[0]) | set(resolution[0]))),
                tuple(sorted(set(previous[1]) | set(resolution[1]))),
            )
        provenance_payload = indirect_provenance[
            (rva, site, function_context)
        ].payload()
        site_provenance.setdefault(aggregate_key, {})[
            canonical_sha256_v3(provenance_payload)
        ] = provenance_payload
    blockers.extend(
        {
            "code": "unresolved_reachable_indirect_target",
            "source_rva": rva,
            "site": site,
            "provenance": [
                payload for _digest, payload in sorted(
                    site_provenance[(rva, site)].items()
                )
            ],
        }
        for (rva, site), resolution in indirect_sites.items()
        if resolution is None
    )
    blockers.extend({
        "code": "unresolved_reachable_callback_target",
        "instruction_rva": instruction_rva,
        "dll": dll,
        "identity": identity,
        "protocol_id": protocol_id,
    } for (
        instruction_rva, dll, identity, protocol_id
    ), targets in callback_escapes.items() if targets is None)
    blockers.extend({
        "code": "unresolved_external_memory_write_footprint",
        "source_rva": rva,
        "instruction_rva": call.instruction_rva,
        "call_index": call_index,
        "function_context": function_context.identity,
        "function_entry_rva": function_context.function_entry_rva,
        "call_string": list(function_context.call_string),
        "external_targets": [
            {"dll": dll, "identity": identity}
            for dll, identity in targets
        ],
        "arguments": [argument.payload() for argument in arguments],
    } for (
        rva, call_index, function_context
    ), (call, arguments, targets) in sorted(external_write_failures.items()))
    blockers.extend({
        "code": "unresolved_callee_effect_instantiation",
        "source_rva": rva,
        "instruction_rva": call.instruction_rva,
        "call_index": call_index,
        "caller_context": caller_context.identity,
        "caller_function_rva": caller_context.function_entry_rva,
        "caller_call_string": list(caller_context.call_string),
        "callee_context": callee_context.identity,
        "callee_function_rva": callee_context.function_entry_rva,
        "callee_call_string": list(callee_context.call_string),
    } for (
        rva, call_index, caller_context, callee_context
    ), call in sorted(return_instantiation_failures.items()))
    blockers.extend({
        "code": "recursive_stack_frame_context_reused",
        "source_rva": source_rva,
        "instruction_rva": instruction_rva,
        "callee_context": callee_context,
    } for source_rva, instruction_rva, callee_context in sorted(
        stack_frame_reuse_sites
    ))
    blockers.extend({
        "code": "outgoing_stack_projection_bound_exceeded",
        "source_rva": source_rva,
        "instruction_rva": instruction_rva,
        "call_index": call_index,
        "caller_context": caller_context,
        "caller_function_rva": caller_function_rva,
        "caller_call_string": list(caller_call_string),
        "qualified_byte_limit": OUTGOING_STACK_PROJECTION_BYTE_LIMIT_V1,
    } for (
        source_rva,
        instruction_rva,
        call_index,
        caller_context,
        caller_function_rva,
        caller_call_string,
    ) in sorted(stack_projection_failures))
    for (
        source_rva,
        effect_index,
        instruction_rva,
        call_index,
        call_kind,
        operations,
    ) in sorted({
        (
            source_rva,
            effect_index,
            call.instruction_rva,
            call.call_index,
            call.kind,
            call.native_exception_operations,
        )
        for source_rva, _function_context in states
        for effect_index, _operation, call
        in _transfer_exception_occurrences_v1(by_rva[source_rva])
        if call is not None
    }):
        unresolved = [
            operation
            for operation in operations
            if not (
                (
                    transition := _checked_exception_v1(
                        checked_exceptions,
                        unit_id=by_rva[source_rva].identity,
                        effect_index=effect_index,
                        operation=operation,
                    )
                ) is not None
                and transition.authorizing
            )
        ]
        if unresolved:
            blockers.append({
                "code": "reachable_call_exception_authority_missing",
                "unit_id": by_rva[source_rva].identity,
                "source_rva": source_rva,
                "instruction_rva": instruction_rva,
                "call_index": call_index,
                "call_kind": call_kind,
                "native_exception_operations": unresolved,
            })
    exception_continuations: list[dict[str, Any]] = []
    for source_rva in sorted({rva for rva, _context in states}):
        transfer = by_rva[source_rva]
        causal_roots = sorted({
            function_context.root_rva
            for rva, function_context in states
            if rva == source_rva
        })
        for effect_index, operation, call in _transfer_exception_occurrences_v1(
            transfer
        ):
            transition = _checked_exception_v1(
                checked_exceptions,
                unit_id=transfer.identity,
                effect_index=effect_index,
                operation=operation,
            )
            if transition is None or not transition.authorizing:
                if call is not None:
                    # The call-site blocker above owns this fail-closed case.
                    continue
                blocker = {
                    "code": "reachable_exception_outcome_unresolved",
                    "source_rva": source_rva,
                    "effect_index": effect_index,
                    "operation": operation,
                }
                if transition is not None:
                    blocker["authority_blocker"] = transition.blocker_code
                blockers.append(blocker)
                continue
            exception_continuations.append({
                "unit_id": transition.unit_id,
                "source_rva": transition.source_rva,
                "effect_index": transition.effect_index,
                "fault_index": transition.fault_index,
                "fault_sha256": transition.fault_sha256,
                "transition_id": transition.transition_id,
                "transition_sha256": transition.transition_sha256,
                "occurrence_kind": transition.occurrence_kind,
                "call_index": transition.call_index,
                "operation": operation,
                "disposition": transition.disposition,
                "handler_unit_id": transition.handler_unit_id,
                "handler_rva": transition.handler_rva,
                "resumption_unit_id": transition.resumption_unit_id,
                "resumption_rva": transition.resumption_rva,
                "unwind_unit_ids": list(transition.unwind_unit_ids),
                "state_projection": transition.state_projection,
                "guard": transition.guard,
                "root_rvas": causal_roots,
            })
            if transition.disposition == "handled":
                projection_issue_rows = sorted({
                    issue
                    for (issue_rva, issue_index, _context), issues
                    in exception_projection_issues.items()
                    if issue_rva == source_rva and issue_index == effect_index
                    for issue in issues
                })
                continuation_failure_rows = sorted({
                    issue
                    for (issue_rva, issue_index, _context), issues
                    in exception_continuation_failures.items()
                    if issue_rva == source_rva and issue_index == effect_index
                    for issue in issues
                })
                if transition.state_projection is None:
                    code = "checked_exception_handler_state_projection_unavailable"
                elif projection_issue_rows:
                    code = "checked_exception_handler_state_projection_unsupported"
                elif continuation_failure_rows:
                    code = "checked_exception_unwind_state_composition_unavailable"
                else:
                    continue
                blockers.append({
                    "code": code,
                    "source_rva": source_rva,
                    "effect_index": effect_index,
                    "transition_id": transition.transition_id,
                    "handler_unit_id": transition.handler_unit_id,
                    "handler_rva": transition.handler_rva,
                    "resumption_unit_id": transition.resumption_unit_id,
                    "resumption_rva": transition.resumption_rva,
                    "unwind_unit_ids": list(transition.unwind_unit_ids),
                    "state_projection": transition.state_projection,
                    "projection_issues": projection_issue_rows,
                    "continuation_failures": continuation_failure_rows,
                })
    nonlocal_transitions = sorted(
        {
            canonical_sha256_v3(transition): transition
            for transition in nonlocal_contexts.values()
            if transition is not None
        }.values(),
        key=canonical_sha256_v3,
    )
    unique_blockers = sorted(
        {canonical_sha256_v3(row): row for row in blockers}.values(),
        key=lambda row: canonical_sha256_v3(row),
    )
    reachable = sorted({rva for rva, _function_context in states})
    core: dict[str, Any] = {
        "format": MODULE_EXECUTION_CLOSURE_FORMAT,
        "status": "complete" if not unique_blockers else "incomplete",
        "authorizes_execution": not unique_blockers,
        "bindings": {
            "executable_transfer_plan_sha256": transfer_plan_sha256,
            **dict(sorted(context.authority_bindings.items())),
        },
        "roots": list(context.roots),
        "reachable_units": [
            {"unit_id": by_rva[rva].identity, "rva": rva} for rva in reachable
        ],
        "reachable_edges": [
            {"source_rva": source, "target_rva": target, "kind": kind}
            for source, target, kind in sorted(reachable_edges)
        ],
        "indirect_targets": [
            {
                "source_rva": rva,
                "site": site,
                "targets": (
                    None if resolution is None else list(resolution[0])
                ),
                "external_targets": (
                    None if resolution is None else [
                        {"dll": dll, "identity": identity}
                        for dll, identity in resolution[1]
                    ]
                ),
                "provenance": [
                    payload for _digest, payload in sorted(
                        site_provenance[(rva, site)].items()
                    )
                ],
            }
            for (rva, site), resolution in sorted(indirect_sites.items())
        ],
        "external_contracts": [
            {"dll": dll, "identity": identity}
            for dll, identity in sorted(external_contracts)
        ],
        "runtime_providers": list(context.runtime_provider_requirements),
        "callback_escapes": [
            {
                "instruction_rva": instruction_rva,
                "dll": dll,
                "identity": identity,
                "protocol_id": protocol_id,
                "targets": None if targets is None else list(targets),
                "action": callback_metadata[key].action,
                "lifetime": callback_metadata[key].lifetime,
                "delivery": {
                    "thread": callback_metadata[key].delivery_thread,
                    "timing": callback_metadata[key].delivery_timing,
                },
            }
            for key, targets in sorted(callback_escapes.items())
            for instruction_rva, dll, identity, protocol_id in (key,)
        ],
        "exception_continuations": exception_continuations,
        "nonlocal_transitions": nonlocal_transitions,
        "lifecycle_effects": [
            {
                "kind": "external_termination",
                "source_rva": rva,
                "dll": dll,
                "identity": identity,
            }
            for rva, dll, identity in sorted(terminal_external_outcomes)
        ],
        "witnesses": [
            {
                "unit_id": by_rva[rva].identity,
                "rva": rva,
                "context_id": function_context.identity,
                "root_rva": function_context.root_rva,
                "function_entry_rva": function_context.function_entry_rva,
                "call_string": list(function_context.call_string),
            }
            for rva, function_context in sorted(states)
        ],
        "blockers": unique_blockers,
        "metrics": {
            "elapsed_milliseconds": (
                int((time.monotonic() - started) * 1000)
            ),
            "worklist_steps": steps,
            "reachable_units": len(reachable),
            "reachable_edges": len(reachable_edges),
            "reachable_expression_nodes": sum(
                len(by_rva[rva].nodes) for rva in reachable
            ),
            "indirect_sites": len(indirect_sites),
            "function_contexts": len({entry for _rva, entry in states}),
            "return_summaries": len(return_summaries),
            "relational_object_bindings": len({
                identity
                for state in states.values()
                for identity in state.relational_object_bindings
            }),
            "peak_rss_kib": int(
                resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            ),
        },
        "analysis_policy": {
            "reference_alternative_limit": context.catalog.alternative_limit,
            "call_string_limit": context.call_string_limit,
            "maximum_worklist_steps": context.maximum_worklist_steps,
            "boundary_exit_rvas": list(context.boundary_exit_rvas),
        },
        "authority": (
            "derived exact execution closure; diagnostics and tests remain veto-only"
        ),
    }
    # Timing is observational and excluded from the semantic identity.
    semantic_core = {
        **core,
        "metrics": {
            key: value for key, value in core["metrics"].items()
            if key not in _OBSERVATIONAL_CLOSURE_METRICS_V1
        },
    }
    core["closure_sha256"] = canonical_sha256_v3(semantic_core)
    return core
