# ruff: noqa: F401
"""Deterministic execution closure over canonical transfer-v2 semantics."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import heapq
import json
from pathlib import Path
import resource
import time
from typing import Any, Iterable, Mapping, MutableMapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary import BoundarySchemaV1, TargetDataLayoutV1
from ..calls.frame import PhysicalCallFrameV3
from ..semantic_objects.object_authority import MachineObjectAuthorityV2
from ..external.formats import RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
from ..pe32.behavioral_roots import load_behavioral_roots
from ..pe32.module_interface import Pe32ModuleInterfaceV2
from ..util import sha256_file, write_json
from .formats import MODULE_EXECUTION_CLOSURE_FORMAT
from .exception_semantics import CheckedExceptionTransitionV1
from .model import TransferPlanError, _Call, _REGISTERS, _Transfer
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


@dataclass(frozen=True, slots=True)

class ExecutionClosureContextV1:
    roots: tuple[int, ...]
    catalog: ReferenceCatalogV1
    authority_bindings: Mapping[str, str]
    initial_states: Mapping[int, ReferenceStateV1] = field(default_factory=dict)
    runtime_provider_requirements: tuple[str, ...] = ()
    preexisting_blockers: tuple[Mapping[str, Any], ...] = ()
    maximum_worklist_steps: int = 1_000_000
    call_string_limit: int = 1
    boundary_exit_rvas: tuple[int, ...] = ()
    checked_exception_transitions: tuple[
        CheckedExceptionTransitionV1, ...
    ] = ()
    finite_control_targets: Mapping[int, tuple[int, ...]] = field(
        default_factory=dict
    )
    external_declaration_contracts: Mapping[
        tuple[str, str], tuple[str, str | None]
    ] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.roots or len(set(self.roots)) != len(self.roots):
            raise ValueError("execution closure roots must be nonempty and unique")
        if not self.authority_bindings or any(
            not key or len(value) != 64
            for key, value in self.authority_bindings.items()
        ):
            raise ValueError("execution closure requires exact authority bindings")
        if self.maximum_worklist_steps <= 0:
            raise ValueError("execution closure worklist bound must be positive")
        if self.call_string_limit <= 0:
            raise ValueError("execution closure call-string bound must be positive")
        if tuple(sorted(set(self.boundary_exit_rvas))) != self.boundary_exit_rvas:
            raise ValueError("execution closure boundary exits must be canonical")
        if any(value < 0 for value in self.boundary_exit_rvas):
            raise ValueError("execution closure boundary exits must be nonnegative")
        if tuple(sorted(set(self.runtime_provider_requirements))) != (
            self.runtime_provider_requirements
        ):
            raise ValueError("execution closure runtime providers must be canonical")
        if any(
            not isinstance(source_rva, int)
            or isinstance(source_rva, bool)
            or source_rva < 0
            or not targets
            or tuple(sorted(set(targets))) != targets
            or any(
                not isinstance(target, int)
                or isinstance(target, bool)
                or target < 0
                for target in targets
            )
            for source_rva, targets in self.finite_control_targets.items()
        ):
            raise ValueError(
                "execution closure finite-control targets must be canonical"
            )
        if any(
            not dll or dll != dll.lower() or not identity
            or len(contract_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in contract_sha256
            )
            or (
                loader_sha256 is not None
                and (
                    len(loader_sha256) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in loader_sha256
                    )
                )
            )
            for (dll, identity), (
                contract_sha256, loader_sha256,
            ) in self.external_declaration_contracts.items()
        ):
            raise ValueError(
                "execution closure external declarations must be canonical"
            )
        exception_keys = [
            (row.unit_id, row.effect_index, row.operation or "")
            for row in self.checked_exception_transitions
        ]
        if exception_keys != sorted(set(exception_keys)):
            raise ValueError(
                "execution closure exception transitions must be canonical"
            )


@dataclass(frozen=True, order=True, slots=True)
class ExecutionFunctionContextV1:
    root_rva: int
    function_entry_rva: int
    call_string: tuple[int, ...] = ()
    _identity: str = field(init=False, repr=False, compare=False)
    _frame_identity: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        identity = "execution-context:" + canonical_sha256_v3({
            "root_rva": self.root_rva,
            "function_entry_rva": self.function_entry_rva,
            "call_string": list(self.call_string),
        })
        object.__setattr__(self, "_identity", identity)
        object.__setattr__(
            self, "_frame_identity", f"captured_stack_frame:{identity}"
        )

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def frame_identity(self) -> str:
        return self._frame_identity

    def child(
        self, *, target_rva: int, instruction_rva: int, limit: int,
    ) -> "ExecutionFunctionContextV1":
        return ExecutionFunctionContextV1(
            root_rva=self.root_rva,
            function_entry_rva=target_rva,
            call_string=(*self.call_string, instruction_rva)[-limit:],
        )


def _root_reference_state_v1(root_rva: int) -> ReferenceStateV1:
    registers = list(ReferenceStateV1().registers)
    registers[7] = finite_reference_value_v1(references=(
        ReferenceAtomV1(
            "object", f"captured_stack:root:{root_rva:08x}", 0
        ),
    ))
    return ReferenceStateV1(registers=tuple(registers))


def _callback_root_state(
    target: int, shared: ReferenceStateV1,
) -> ReferenceStateV1:
    root = _root_reference_state_v1(target)
    return ReferenceStateV1(
        registers=root.registers,
        flags=root.flags,
        memory=shared.memory,
        invalidated_memory_ranges=shared.invalidated_memory_ranges,
        all_memory_invalidated=shared.all_memory_invalidated,
        callback_registry=shared.callback_registry,
        relational_object_bindings=shared.relational_object_bindings,
        possible_allocation_identities=shared.possible_allocation_identities,
    )


def execution_closure_context_with_roots_v1(
    context: ExecutionClosureContextV1,
    roots: Iterable[int],
    *,
    boundary_exit_rvas: Iterable[int] = (),
) -> ExecutionClosureContextV1:
    """Retarget one checked environment context without changing semantics.

    Component refinement needs the same object/environment universe as module
    execution, but begins at component operation entries.  Re-rooting retains
    the shared mapped-memory and callback state while creating the canonical
    entry register state for each new root.
    """

    normalized = tuple(sorted(set(int(value) for value in roots)))
    if not normalized or any(value < 0 for value in normalized):
        raise ValueError("execution closure root override is empty or invalid")
    shared = (
        context.initial_states[min(context.initial_states)]
        if context.initial_states
        else None
    )
    initial_states = (
        {}
        if shared is None
        else {
            root: _callback_root_state(root, shared)
            for root in normalized
        }
    )
    return replace(
        context,
        roots=normalized,
        initial_states=initial_states,
        boundary_exit_rvas=tuple(sorted(set(
            int(value) for value in boundary_exit_rvas
        ))),
    )


def _reference_state_kernel_payload_v1(
    state: ReferenceStateV1,
) -> dict[str, Any]:
    """Project one reference state into the private native-kernel transport.

    This transport is deliberately analysis-local: it is neither registered
    as an artifact nor accepted by any authority or deployment check.  Keeping
    the projection here prevents the native accelerator from acquiring a
    second semantic input model.
    """

    def key_payload(key: tuple[str, str, int, int]) -> dict[str, Any]:
        return {
            "kind": key[0], "identity": key[1],
            "offset": key[2], "width": key[3],
        }

    def range_payload(row: tuple[str, str, int, int]) -> dict[str, Any]:
        return {
            "kind": row[0], "identity": row[1],
            "start": row[2], "end": row[3],
        }

    return {
        "registers": [value.payload() for value in state.registers],
        "flags": [value.payload() for value in state.flags],
        "memory": [
            {**key_payload(key), "value": value.payload()}
            for key, value in sorted(state.memory.items())
        ],
        "call_registers": [
            value.payload() for value in state.call_registers
        ],
        "call_flags": [value.payload() for value in state.call_flags],
        "invalidated_memory_ranges": [
            range_payload(row)
            for row in sorted(state.invalidated_memory_ranges)
        ],
        "all_memory_invalidated": state.all_memory_invalidated,
        "callback_registry": [
            {"identity": identity, "value": value.payload()}
            for identity, value in sorted(state.callback_registry.items())
        ],
        "flag_relations": [
            None if relation is None else {
                "register_index": relation.register_index,
                "mask": relation.mask,
                "relation": relation.relation,
                "constant": relation.constant,
            }
            for relation in state.flag_relations
        ],
        "scalar_constraints": [
            {
                "register_index": register,
                "mask": mask,
                "values": sorted(values),
            }
            for (register, mask), values in sorted(
                state.scalar_constraints.items()
            )
        ],
        "preserves_inherited_memory": state.preserves_inherited_memory,
        "relational_object_bindings": [
            {"identity": identity, "value": value.payload()}
            for identity, value in sorted(
                state.relational_object_bindings.items()
            )
        ],
        "written_memory_keys": [
            key_payload(key) for key in sorted(state.written_memory_keys)
        ],
        "effect_invalidated_memory_ranges": [
            range_payload(row)
            for row in sorted(state.effect_invalidated_memory_ranges)
        ],
        "effect_all_memory_invalidated": state.effect_all_memory_invalidated,
        "possible_allocation_identities": sorted(
            state.possible_allocation_identities
        ),
    }


def _execution_closure_kernel_context_payload_v1(
    context: ExecutionClosureContextV1,
) -> dict[str, Any]:
    """Encode the already checked closure context for one native invocation."""

    def callback_payload(rule: ExternalCallbackRuleV1) -> dict[str, Any]:
        return {
            "protocol_id": rule.protocol_id,
            "source_argument": rule.source_argument,
            "source_kind": rule.source_kind,
            "source_offset": rule.source_offset,
            "sentinels": sorted(rule.sentinels),
            "action": rule.action,
            "lifetime": rule.lifetime,
            "delivery_thread": rule.delivery_thread,
            "delivery_timing": rule.delivery_timing,
            "instance_kind": rule.instance_kind,
            "instance_argument": rule.instance_argument,
            "previous_result_register": rule.previous_result_register,
            "previous_sentinels": sorted(rule.previous_sentinels),
        }

    def external_rule_payload(
        key: tuple[str, str], rule: ExternalCallRuleV1,
    ) -> dict[str, Any]:
        return {
            "dll": key[0],
            "identity": key[1],
            "contract_sha256": rule.contract_sha256,
            "loader_service_contract_sha256": (
                rule.loader_service_contract_sha256
            ),
            "preserved_registers": sorted(rule.preserved_registers),
            "argument_words": rule.argument_words,
            "stack_cleanup_bytes": rule.stack_cleanup_bytes,
            "disposition": rule.disposition,
            "allocation_result_register": rule.allocation_result_register,
            "allocation_nullable": rule.allocation_nullable,
            "write_footprints": [{
                "base_argument": row.base_argument,
                "offset": row.offset,
                "fixed_bytes": row.fixed_bytes,
                "size_argument": row.size_argument,
                "scale": row.scale,
                "authority_selector": row.authority_selector,
            } for row in rule.write_footprints],
            "memory_copies": [{
                "destination_argument": row.destination_argument,
                "source_argument": row.source_argument,
                "size_argument": row.size_argument,
                "scale": row.scale,
            } for row in rule.memory_copies],
            "out_pointers": [{
                "argument": row.argument,
                "offset": row.offset,
                "nullable": row.nullable,
                "max_elements": row.max_elements,
                "element_unit_bytes": row.element_unit_bytes,
                "element_max_units": row.element_max_units,
            } for row in rule.out_pointers],
            "unknown_guest_memory_write": rule.unknown_guest_memory_write,
            "callback": (
                None if rule.callback is None
                else callback_payload(rule.callback)
            ),
            "module_handle_name_argument": rule.module_handle_name_argument,
            "module_handle_nullable_name": rule.module_handle_nullable_name,
            "module_handle_wide_name": rule.module_handle_wide_name,
            "dynamic_export_handle_argument": (
                rule.dynamic_export_handle_argument
            ),
            "dynamic_export_name_argument": rule.dynamic_export_name_argument,
            "dynamic_export_results": [{
                "dll": dynamic_key[0],
                "identity": dynamic_key[1],
                "target": target,
            } for dynamic_key, target in sorted(
                rule.dynamic_export_results.items()
            )],
        }

    catalog = context.catalog
    return {
        "version": 1,
        "roots": list(context.roots),
        "catalog": {
            "guest_code_rvas": sorted(catalog.guest_code_rvas),
            "guest_image_base": catalog.guest_image_base,
            "external_functions": [{
                "address": address, "identity": identity,
            } for address, identity in sorted(
                catalog.external_functions.items()
            )],
            "external_function_contracts": [{
                "function_identity": identity,
                "dll": contract[0],
                "identity": contract[1],
            } for identity, contract in sorted(
                catalog.external_function_contracts.items()
            )],
            "objects": [{
                "identity": row.identity,
                "address": row.address,
                "extent": row.extent,
                "writable": row.writable,
            } for row in catalog.objects],
            "external_calls": [
                external_rule_payload(key, rule)
                for key, rule in sorted(catalog.external_calls.items())
            ],
            "initial_memory": _reference_state_kernel_payload_v1(
                ReferenceStateV1(
                    memory=catalog.initial_memory,
                    possible_allocation_identities=frozenset(),
                )
            )["memory"],
            "object_bytes": [{
                "identity": identity,
                "hex": value.hex(),
            } for identity, value in sorted(catalog.object_bytes.items())],
            "alternative_limit": catalog.alternative_limit,
        },
        "authority_bindings": dict(sorted(context.authority_bindings.items())),
        "initial_states": [{
            "rva": rva,
            "state": _reference_state_kernel_payload_v1(state),
        } for rva, state in sorted(context.initial_states.items())],
        "runtime_provider_requirements": list(
            context.runtime_provider_requirements
        ),
        "external_declarations": [{
            "dll": key[0],
            "identity": key[1],
            "contract_sha256": value[0],
            "loader_service_contract_sha256": value[1],
        } for key, value in sorted(
            context.external_declaration_contracts.items()
        )],
        "preexisting_blockers": [
            dict(row) for row in context.preexisting_blockers
        ],
        "maximum_worklist_steps": context.maximum_worklist_steps,
        "call_string_limit": context.call_string_limit,
        "boundary_exit_rvas": list(context.boundary_exit_rvas),
        "checked_exception_transitions": [
            row.payload() for row in sorted(
                context.checked_exception_transitions,
                key=lambda value: (
                    value.unit_id,
                    value.effect_index,
                    value.operation or "",
                ),
            )
        ],
    }


def _boundary_reference_state_v1(state: ReferenceStateV1) -> ReferenceStateV1:
    """Drop call-response temporaries that cannot cross a transfer boundary."""

    empty = ReferenceStateV1()
    if (
        state.call_registers == empty.call_registers
        and state.call_flags == empty.call_flags
    ):
        return state
    return replace(
        state,
        call_registers=empty.call_registers,
        call_flags=empty.call_flags,
    )


def _effect_summary_state_v1(state: ReferenceStateV1) -> ReferenceStateV1:
    """Project one function state to its monotone memory effects."""

    return replace(
        state,
        memory={
            key: value for key, value in state.memory.items()
            if key in state.written_memory_keys
        },
        invalidated_memory_ranges=state.effect_invalidated_memory_ranges,
        all_memory_invalidated=state.effect_all_memory_invalidated,
    )


def _state_object_identities_v1(state: ReferenceStateV1) -> frozenset[str]:
    values = (
        *state.registers,
        *state.memory.values(),
        *state.callback_registry.values(),
        *state.relational_object_bindings.values(),
    )
    return frozenset(
        atom.identity
        for value in values for atom in value.references
        if atom.kind in {"object", "object_view"}
    )


def _implicit_memory_value_v1(
    state: ReferenceStateV1,
    key: tuple[str, str, int, int],
    baseline: Mapping[tuple[str, str, int, int], ReferenceValueV1],
    invalidated: Mapping[
        tuple[str, str], tuple[tuple[int, int], ...]
    ] | None = None,
) -> ReferenceValueV1:
    kind, identity, offset, width = key
    if state.all_memory_invalidated:
        return UNKNOWN_SCALAR_REFERENCE_V1
    ranges = (
        tuple(
            (start, end)
            for range_kind, range_identity, start, end
            in state.invalidated_memory_ranges
            if range_kind == kind and range_identity == identity
        )
        if invalidated is None else invalidated.get((kind, identity), ())
    )
    for start, end in ranges:
        if offset < end and start < offset + width:
            return UNKNOWN_SCALAR_REFERENCE_V1
    if (
        kind == "object"
        and identity.startswith("allocation:")
        and identity not in state.possible_allocation_identities
    ):
        return BOTTOM_REFERENCE_V1
    inherited = baseline.get(key)
    if inherited is not None:
        return inherited
    if kind == "object" and is_call_parameter_object_v1(identity):
        return CONFLICT_REFERENCE_V1
    return UNKNOWN_SCALAR_REFERENCE_V1


def _normalize_reference_memory_v1(
    state: ReferenceStateV1,
    baseline: Mapping[tuple[str, str, int, int], ReferenceValueV1],
) -> ReferenceStateV1:
    if not state.memory:
        return state
    if (
        len(state.written_memory_keys) >= len(state.memory)
        and state.memory.keys() <= state.written_memory_keys
    ):
        return state
    invalidated: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for kind, identity, start, end in state.invalidated_memory_ranges:
        invalidated.setdefault((kind, identity), []).append((start, end))
    invalidated_index = {
        key: tuple(sorted(ranges)) for key, ranges in invalidated.items()
    }
    memory = {
        key: value for key, value in state.memory.items()
        if key in state.written_memory_keys or value != (
            _implicit_memory_value_v1(
                state, key, baseline, invalidated_index
            )
        )
    }
    normalized = state.memory if len(memory) == len(state.memory) else memory
    return state if normalized is state.memory else replace(
        state, memory=normalized
    )


def _reference_states_equal_v1(
    left: ReferenceStateV1, right: ReferenceStateV1,
) -> bool:
    """Compare cheap scalar metadata before potentially large memory maps."""

    return left is right or (
        left.registers == right.registers
        and left.flags == right.flags
        and left.call_registers == right.call_registers
        and left.call_flags == right.call_flags
        and left.invalidated_memory_ranges == right.invalidated_memory_ranges
        and left.all_memory_invalidated == right.all_memory_invalidated
        and left.callback_registry == right.callback_registry
        and left.flag_relations == right.flag_relations
        and left.scalar_constraints == right.scalar_constraints
        and left.preserves_inherited_memory == right.preserves_inherited_memory
        and left.relational_object_bindings == right.relational_object_bindings
        and left.written_memory_keys == right.written_memory_keys
        and left.effect_invalidated_memory_ranges
        == right.effect_invalidated_memory_ranges
        and left.effect_all_memory_invalidated
        == right.effect_all_memory_invalidated
        and left.possible_allocation_identities
        == right.possible_allocation_identities
        and (left.memory is right.memory or left.memory == right.memory)
    )


def join_reference_states_v1(
    left: ReferenceStateV1,
    right: ReferenceStateV1,
    *, alternative_limit: int,
    baseline_memory: Mapping[
        tuple[str, str, int, int], ReferenceValueV1
    ] | None = None,
    baseline_invalidation_index: Mapping[
        tuple[str, str],
        tuple[tuple[str, str, int, int], ...],
    ] | None = None,
) -> ReferenceStateV1:
    if _reference_states_equal_v1(left, right):
        return left
    baseline = {} if baseline_memory is None else baseline_memory
    if baseline_invalidation_index is None:
        mutable_baseline_index: dict[
            tuple[str, str], list[tuple[str, str, int, int]]
        ] = {}
        for key, value in baseline.items():
            # Scalar-only baseline values are subsumed by an invalidated
            # unknown scalar and normalize away.  Reference-bearing or
            # conflicting cells must remain explicit to prevent an
            # invalidation from erasing a possible code/object identity.
            if join_reference_values_v1(
                value,
                UNKNOWN_SCALAR_REFERENCE_V1,
                alternative_limit=alternative_limit,
            ) == UNKNOWN_SCALAR_REFERENCE_V1:
                continue
            mutable_baseline_index.setdefault(key[:2], []).append(key)
        baseline_invalidation_index = {
            owner: tuple(sorted(keys))
            for owner, keys in mutable_baseline_index.items()
        }
    left_invalidated: dict[tuple[str, str], list[tuple[int, int]]] = {}
    right_invalidated: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for kind, identity, start, end in left.invalidated_memory_ranges:
        left_invalidated.setdefault((kind, identity), []).append((start, end))
    for kind, identity, start, end in right.invalidated_memory_ranges:
        right_invalidated.setdefault((kind, identity), []).append((start, end))
    left_invalidated_index = {
        key: tuple(sorted(ranges)) for key, ranges in left_invalidated.items()
    }
    right_invalidated_index = {
        key: tuple(sorted(ranges)) for key, ranges in right_invalidated.items()
    }
    def memory_value(
        state: ReferenceStateV1,
        key: tuple[str, str, int, int],
        invalidated: Mapping[
            tuple[str, str], tuple[tuple[int, int], ...]
        ],
    ) -> ReferenceValueV1:
        explicit = state.memory.get(key)
        if explicit is not None:
            return explicit
        return _implicit_memory_value_v1(
            state, key, baseline, invalidated,
        )

    def join_values(
        lhs: tuple[ReferenceValueV1, ...], rhs: tuple[ReferenceValueV1, ...],
        *, stack_pointer: bool = False,
    ) -> tuple[ReferenceValueV1, ...]:
        if lhs == rhs:
            return lhs
        return tuple(
            one if one == two else join_reference_values_v1(
                one,
                two,
                alternative_limit=(
                    max(
                        alternative_limit,
                        STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
                    )
                    if stack_pointer and index == 7
                    else alternative_limit
                ),
            )
            for index, (one, two) in enumerate(zip(lhs, rhs, strict=True))
        )

    memory_maps_unchanged = (
        left.memory is right.memory or left.memory == right.memory
    )
    invalidation_metadata_unchanged = (
        left.invalidated_memory_ranges == right.invalidated_memory_ranges
        and left.all_memory_invalidated == right.all_memory_invalidated
    )
    baseline_keys: set[tuple[str, str, int, int]] = set()
    # An invalidation changes an otherwise implicit baseline cell.  Such a
    # cell must be materialized at the join even when neither input has an
    # explicit memory entry; otherwise `(baseline ⊔ baseline) ⊔ invalidated`
    # can differ from `baseline ⊔ (baseline ⊔ invalidated)`.
    if not invalidation_metadata_unchanged:
        affected_owners = (
            set(baseline_invalidation_index)
            if left.all_memory_invalidated != right.all_memory_invalidated
            else {
                (kind, identity)
                for kind, identity, _start, _end in (
                    *left.invalidated_memory_ranges,
                    *right.invalidated_memory_ranges,
                )
            }
        )
        baseline_keys.update(
            key
            for owner in affected_owners
            for key in baseline_invalidation_index.get(owner, ())
            if key not in left.memory
            and memory_value(left, key, left_invalidated_index)
            != memory_value(right, key, right_invalidated_index)
        )
    memory_keys = (
        baseline_keys
        if memory_maps_unchanged
        else set(left.memory) | set(right.memory) | baseline_keys
    )

    if not memory_keys:
        memory = left.memory
    else:
        memory = dict(left.memory) if memory_maps_unchanged else {}
        for key in memory_keys:
            left_value = memory_value(
                left, key, left_invalidated_index
            )
            right_value = memory_value(
                right, key, right_invalidated_index
            )
            memory[key] = (
                left_value if left_value == right_value
                else join_reference_values_v1(
                    left_value,
                    right_value,
                    alternative_limit=alternative_limit,
                )
            )
    if left.callback_registry == right.callback_registry:
        callback_registry = left.callback_registry
    else:
        callback_registry = {}
        for key in set(left.callback_registry) | set(right.callback_registry):
            left_value = left.callback_registry.get(
                key, UNKNOWN_SCALAR_REFERENCE_V1
            )
            right_value = right.callback_registry.get(
                key, UNKNOWN_SCALAR_REFERENCE_V1
            )
            callback_registry[key] = (
                left_value if left_value == right_value
                else join_reference_values_v1(
                    left_value,
                    right_value,
                    alternative_limit=alternative_limit,
                )
            )
    flag_relations = tuple(
        left_relation if left_relation == right_relation else None
        for left_relation, right_relation in zip(
            left.flag_relations, right.flag_relations, strict=True
        )
    )
    scalar_constraints: dict[tuple[int, int], frozenset[int]] = {}
    for key in set(left.scalar_constraints) & set(right.scalar_constraints):
        joined = left.scalar_constraints[key] | right.scalar_constraints[key]
        if len(joined) <= BOUNDED_SCALAR_ALTERNATIVE_LIMIT_V1:
            scalar_constraints[key] = joined
    relational_object_bindings: dict[str, ReferenceValueV1] = {}
    for identity in (
        set(left.relational_object_bindings)
        | set(right.relational_object_bindings)
    ):
        left_value = left.relational_object_bindings.get(identity)
        right_value = right.relational_object_bindings.get(identity)
        if left_value is None:
            assert right_value is not None
            relational_object_bindings[identity] = right_value
        elif right_value is None:
            relational_object_bindings[identity] = left_value
        else:
            relational_object_bindings[identity] = (
                left_value if left_value == right_value
                else join_reference_values_v1(
                    left_value,
                    right_value,
                    alternative_limit=max(
                        alternative_limit,
                        STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
                    ),
                )
            )
    result = ReferenceStateV1(
        registers=join_values(
            left.registers, right.registers, stack_pointer=True
        ),
        flags=join_values(left.flags, right.flags),
        memory=memory,
        call_registers=join_values(
            left.call_registers, right.call_registers, stack_pointer=True
        ),
        call_flags=join_values(left.call_flags, right.call_flags),
        invalidated_memory_ranges=(
            left.invalidated_memory_ranges | right.invalidated_memory_ranges
        ),
        all_memory_invalidated=(
            left.all_memory_invalidated or right.all_memory_invalidated
        ),
        callback_registry=callback_registry,
        flag_relations=flag_relations,
        scalar_constraints=scalar_constraints,
        preserves_inherited_memory=(
            left.preserves_inherited_memory and right.preserves_inherited_memory
        ),
        relational_object_bindings=relational_object_bindings,
        written_memory_keys=(
            left.written_memory_keys | right.written_memory_keys
        ),
        effect_invalidated_memory_ranges=(
            left.effect_invalidated_memory_ranges
            | right.effect_invalidated_memory_ranges
        ),
        effect_all_memory_invalidated=(
            left.effect_all_memory_invalidated
            or right.effect_all_memory_invalidated
        ),
        possible_allocation_identities=(
            left.possible_allocation_identities
            | right.possible_allocation_identities
        ),
    )
    # Both inputs are normalized at worklist boundaries.  A shared explicit
    # map remains canonical when only invalidation metadata changes; explicit
    # cells dominate invalidations on both inputs.  Only newly materialized
    # implicit baseline cells require another normalization pass.
    if not (memory_maps_unchanged and not memory_keys):
        result = _normalize_reference_memory_v1(result, baseline)

    # Fixed-point joins overwhelmingly land on one of their immutable input
    # states.  Preserve that exact object (and, critically, its shared memory
    # map) instead of retaining an equivalent freshly allocated state.  The
    # equality checks are also the comparison the caller would otherwise make
    # against its previous value, so this does not add a second semantic test.
    # Canonical endpoint reuse is non-authorizing: equality remains the full
    # structural ReferenceStateV1 equality, never a hash or heuristic.
    if _reference_states_equal_v1(result, left):
        return left
    if _reference_states_equal_v1(result, right):
        return right
    return result
