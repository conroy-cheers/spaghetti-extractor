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
    _callback_source_value_v1,
    refine_reference_state_for_branch_v1,
)


_OBSERVATIONAL_CLOSURE_METRICS_V1 = frozenset({
    "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
})

# This is a qualification bound rather than a semantic promise. Reachable
# checked state beyond it produces an explicit fail-closed blocker below.
OUTGOING_STACK_PROJECTION_BYTE_LIMIT_V1 = 4096


from .closure_model import (
    ExecutionClosureContextV1,
    ExecutionFunctionContextV1,
    _root_reference_state_v1,
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

def _direct_successors(
    transfer: _Transfer,
    values: tuple[ReferenceValueV1, ...],
    state: ReferenceStateV1,
    *,
    alternative_limit: int,
) -> tuple[tuple[int, ReferenceStateV1], ...]:
    terminator = transfer.actions[-1]
    if terminator.op in {"outcome_fallthrough", "outcome_jump"}:
        return ((terminator.args[0], state),)
    if terminator.op == "outcome_branch":
        condition = values[terminator.args[0]]
        outcomes = (
            tuple(sorted(bool(value) for value in condition.scalars))
            if condition.kind == "finite" and not condition.references
            else (False, True)
        )
        successors: dict[int, ReferenceStateV1] = {}
        for taken in outcomes:
            target = terminator.args[1] if taken else terminator.args[2]
            refined = refine_reference_state_for_branch_v1(
                transfer,
                state,
                values,
                taken=taken,
                alternative_limit=alternative_limit,
            )
            if refined is None:
                continue
            previous = successors.get(target)
            successors[target] = (
                refined if previous is None else join_reference_states_v1(
                    previous,
                    refined,
                    alternative_limit=alternative_limit,
                )
            )
        return tuple(sorted(successors.items()))
    return ()


def _reference_targets(value: ReferenceValueV1) -> tuple[int, ...] | None:
    if value.kind != "finite" or value.scalars:
        return None
    targets = []
    for atom in value.references:
        if atom.kind != "guest_code" or atom.offset != 0:
            return None
        prefix = "rva:"
        if not atom.identity.startswith(prefix):
            return None
        targets.append(int(atom.identity[len(prefix):], 16))
    return tuple(sorted(set(targets)))


def _external_reference_targets(
    value: ReferenceValueV1, catalog: ReferenceCatalogV1,
) -> tuple[tuple[str, str], ...] | None:
    if value.kind != "finite" or value.scalars or not value.references:
        return None
    targets: list[tuple[str, str]] = []
    for atom in value.references:
        if atom.kind != "external_function" or atom.offset != 0:
            return None
        target = catalog.external_function_contracts.get(atom.identity)
        if target is None:
            return None
        targets.append(target)
    return tuple(sorted(set(targets)))


def _reference_target_resolution_v1(
    value: ReferenceValueV1,
    catalog: ReferenceCatalogV1,
) -> tuple[tuple[int, ...], tuple[tuple[str, str], ...]] | None:
    """Resolve a code capability set without imposing one registry kind."""

    if value.kind != "finite" or value.scalars or not value.references:
        return None
    guest: set[int] = set()
    external: set[tuple[str, str]] = set()
    for atom in value.references:
        if atom.offset != 0:
            return None
        if atom.kind == "guest_code" and atom.identity.startswith("rva:"):
            guest.add(int(atom.identity.removeprefix("rva:"), 16))
            continue
        if atom.kind == "external_function":
            target = catalog.external_function_contracts.get(atom.identity)
            if target is not None:
                external.add(target)
                continue
        return None
    return tuple(sorted(guest)), tuple(sorted(external))


def _external_tail_return_state_v1(
    *,
    transfer: _Transfer,
    state: ReferenceStateV1,
    targets: tuple[tuple[str, str], ...],
    catalog: ReferenceCatalogV1,
) -> ReferenceStateV1 | None:
    """Summarize a checked returning provider reached by a tail jump."""

    rules = tuple(catalog.external_calls.get(target) for target in targets)
    if (
        not rules
        or any(rule is None for rule in rules)
        or any(rule != rules[0] for rule in rules[1:])
    ):
        return None
    rule = rules[0]
    assert rule is not None
    if (
        rule.disposition != "returns"
        or rule.write_footprints
        or rule.memory_copies
        or rule.out_pointers
        or rule.unknown_guest_memory_write
        or rule.callback is not None
        or rule.module_handle_name_argument is not None
        or rule.dynamic_export_handle_argument is not None
        or 7 not in rule.preserved_registers
    ):
        return None
    registers = [UNKNOWN_SCALAR_REFERENCE_V1] * len(_REGISTERS)
    for register_index in rule.preserved_registers:
        registers[register_index] = state.registers[register_index]
    if 7 in rule.preserved_registers:
        registers[7] = adjust_reference_by_constant_v1(
            registers[7],
            rule.stack_cleanup_bytes + 4,
            catalog,
            alternative_limit=STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
        )
    if rule.allocation_result_register is not None:
        dll, identity = targets[0]
        registers[rule.allocation_result_register] = finite_reference_value_v1(
            scalars=(0,) if rule.allocation_nullable else (),
            references=(ReferenceAtomV1(
                "object",
                f"external-object:{dll}!{identity}:{transfer.identity}",
            ),),
            alternative_limit=catalog.alternative_limit,
        )
    return ReferenceStateV1(
        registers=tuple(registers),
        flags=(UNKNOWN_SCALAR_REFERENCE_V1,) * len(state.flags),
        memory=state.memory,
        invalidated_memory_ranges=state.invalidated_memory_ranges,
        all_memory_invalidated=state.all_memory_invalidated,
        callback_registry=state.callback_registry,
        preserves_inherited_memory=state.preserves_inherited_memory,
        relational_object_bindings=state.relational_object_bindings,
        written_memory_keys=state.written_memory_keys,
        effect_invalidated_memory_ranges=(
            state.effect_invalidated_memory_ranges
        ),
        effect_all_memory_invalidated=state.effect_all_memory_invalidated,
        possible_allocation_identities=(
            state.possible_allocation_identities
        ),
    )


def _call_targets(
    call: _Call, values: tuple[ReferenceValueV1, ...]
) -> tuple[int, ...] | None:
    if call.target_node is not None:
        return _reference_targets(values[call.target_node])
    if call.target_rva:
        return (call.target_rva,)
    return () if call.kind == "external_call" else None


def _external_call_targets(
    call: _Call,
    values: tuple[ReferenceValueV1, ...],
    catalog: ReferenceCatalogV1,
) -> tuple[tuple[str, str], ...] | None:
    if call.kind == "external_call":
        identity = (
            call.symbol if call.symbol is not None
            else f"ordinal:{call.ordinal}"
        )
        return (((call.dll or "").lower(), identity),)
    if call.target_node is not None:
        return _external_reference_targets(values[call.target_node], catalog)
    return ()


def _call_target_resolution(
    call: _Call,
    values: tuple[ReferenceValueV1, ...],
    catalog: ReferenceCatalogV1,
) -> tuple[tuple[int, ...], tuple[tuple[str, str], ...]] | None:
    guest = _call_targets(call, values)
    external = _external_call_targets(call, values, catalog)
    if call.kind == "external_call":
        return ((), external or ())
    if call.target_node is None:
        return None if guest is None else (guest, ())
    # One physical call site may not ambiguously select between the guest code
    # registry and loader-owned external code.  That ambiguity is a blocker,
    # not a reason to invent a combined dispatch convention.
    if guest is not None:
        return (guest, ())
    if external is not None:
        return ((), external)
    return None


def _call_argument_values(
    transfer: _Transfer,
    call: _Call,
    values: tuple[ReferenceValueV1, ...],
    state: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
    rule: ExternalCallRuleV1,
) -> tuple[ReferenceValueV1, ...]:
    return call_argument_values_v1(
        call,
        lambda index: values[index],
        state,
        catalog,
        argument_words=rule.argument_words,
        base_offset=(
            4 if transfer.actions[-1].op == "outcome_external" else 0
        ),
    )


def _callback_targets(
    rule: ExternalCallbackRuleV1,
    arguments: tuple[ReferenceValueV1, ...],
    state: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
) -> tuple[int, ...] | None:
    value = _callback_source_value_v1(rule, arguments, state, catalog)
    if value.kind != "finite":
        return None
    if any(scalar not in rule.sentinels for scalar in value.scalars):
        return None
    targets: list[int] = []
    for atom in value.references:
        if (
            atom.kind != "guest_code"
            or atom.offset != 0
            or not atom.identity.startswith("rva:")
        ):
            return None
        targets.append(int(atom.identity.removeprefix("rva:"), 16))
    return tuple(sorted(set(targets)))


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
        possible_allocation_identities=(
            shared.possible_allocation_identities
        ),
    )


def _stack_frame_identity_v1(
    context: ExecutionFunctionContextV1,
) -> str:
    return context.frame_identity


def _expire_stack_frame_value_v1(
    value: ReferenceValueV1, frame_identity: str,
) -> tuple[ReferenceValueV1, bool]:
    escaped = any(
        atom.kind in {"object", "object_view"}
        and captured_stack_owner_v1(atom.identity) == frame_identity
        for atom in value.references
    )
    return (
        (CONFLICT_REFERENCE_V1 if escaped else value),
        escaped,
    )


def _call_parameter_identity_v1(
    context: ExecutionFunctionContextV1, coordinate: str,
) -> str:
    return f"call_parameter_object:{context.identity}:{coordinate}"


def _parameterizable_call_value_v1(value: ReferenceValueV1) -> bool:
    """Whether one exact transient pointer can become a relational input."""

    return (
        value.kind == "finite"
        and not value.scalars
        and bool(value.references)
        and all(
            atom.kind == "object"
            and (
                captured_stack_owner_v1(atom.identity) is not None
                or is_call_parameter_object_v1(atom.identity)
            )
            for atom in value.references
        )
    )


def _explicit_outgoing_stack_cells_v1(
    call: _Call,
    values: tuple[ReferenceValueV1, ...],
    caller: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
) -> dict[tuple[int, int], ReferenceValueV1]:
    """Return qualified contiguous PE32 argument words above caller ESP."""

    stack_atoms = tuple(
        atom for atom in values[call.register_nodes[7]].references
        if atom.kind == "object"
        and captured_stack_owner_v1(atom.identity) is not None
    )
    cells: dict[tuple[int, int], ReferenceValueV1] = {}
    for offset in range(0, OUTGOING_STACK_PROJECTION_BYTE_LIMIT_V1, 4):
        alternatives = tuple(
            caller.memory.get((
                "object", atom.identity, atom.offset + offset, 4,
            ))
            for atom in stack_atoms
        )
        if not alternatives or all(value is None for value in alternatives):
            break
        value = BOTTOM_REFERENCE_V1
        for alternative in alternatives:
            value = join_reference_values_v1(
                value,
                (
                    UNKNOWN_SCALAR_REFERENCE_V1
                    if alternative is None else alternative
                ),
                alternative_limit=catalog.alternative_limit,
            )
        cells[(offset, 4)] = value
    return cells


def _outgoing_stack_projection_exceeds_limit_v1(
    call: _Call,
    values: tuple[ReferenceValueV1, ...],
    caller: ReferenceStateV1,
) -> bool:
    """Whether checked stack state exceeds the qualified projection window."""

    return any(
        key[0] == "object"
        and key[1] == atom.identity
        and key[2] - atom.offset >= OUTGOING_STACK_PROJECTION_BYTE_LIMIT_V1
        for atom in values[call.register_nodes[7]].references
        if atom.kind == "object"
        and captured_stack_owner_v1(atom.identity) is not None
        for key in caller.memory
    )


def _raw_outgoing_stack_projection_v1(
    call: _Call,
    values: tuple[ReferenceValueV1, ...],
    caller: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
) -> tuple[
    dict[tuple[str, str, int, int], ReferenceValueV1],
    tuple[ReferenceAtomV1, ...],
]:
    """Project all physical outgoing stack cells into callee coordinates."""

    projected: dict[tuple[str, str, int, int], ReferenceValueV1] = {}
    caller_stack_atoms = tuple(
        atom for atom in values[call.register_nodes[7]].references
        if atom.kind == "object"
        and captured_stack_owner_v1(atom.identity) is not None
    )
    for offset, width, node_index in call.stack_inputs:
        if offset < 0:
            continue
        key = ("object", "", offset + 4, width)
        value = values[node_index]
        previous = projected.get(key)
        projected[key] = (
            value if previous is None or previous == value
            else join_reference_values_v1(
                previous,
                value,
                alternative_limit=catalog.alternative_limit,
            )
        )
    for (offset, width), value in _explicit_outgoing_stack_cells_v1(
        call, values, caller, catalog
    ).items():
        key = ("object", "", offset + 4, width)
        # The transfer call-frame inventory is the checked value at this
        # physical boundary.  The broader caller-memory projection only fills
        # coordinates absent from that inventory; joining a stale or widened
        # memory cell over an exact stack input destroys code capabilities.
        projected.setdefault(key, value)
    return projected, caller_stack_atoms


def _parameterized_call_inputs_v1(
    call: _Call,
    values: tuple[ReferenceValueV1, ...],
    caller: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
    callee_context: ExecutionFunctionContextV1,
) -> tuple[
    tuple[ReferenceValueV1, ...],
    dict[tuple[str, str, int, int], ReferenceValueV1],
    tuple[ReferenceAtomV1, ...],
    dict[str, ReferenceValueV1],
    bool,
]:
    """Give transient pointer inputs stable relational identities.

    Bindings are deliberately transient.  They are used to instantiate a
    canonical callee summary at this call site and are never serialized as an
    authority-bearing object model.
    """

    frame_identity = _stack_frame_identity_v1(callee_context)
    caller_memory = {
        key: value for key, value in caller.memory.items()
        if not (
            key[0] == "object"
            and captured_stack_owner_v1(key[1]) == frame_identity
        )
    }
    raw_projected, caller_stack_atoms = _raw_outgoing_stack_projection_v1(
        call, values, caller, catalog
    )
    bindings: dict[str, ReferenceValueV1] = {}

    def parameterize(
        coordinate: str,
        value: ReferenceValueV1,
        *,
        relational_word: bool = False,
    ) -> ReferenceValueV1:
        identity = _call_parameter_identity_v1(callee_context, coordinate)
        if value.kind == "bottom" or (
            not relational_word and not _parameterizable_call_value_v1(value)
        ):
            return value
        bindings[identity] = value
        # Callee-saved registers are relational inputs even when their current
        # value is not a pointer.  The placeholder records caller correlation;
        # it does not assert ABI preservation or grant object authority.  A
        # callee that changes the word naturally destroys the placeholder.
        if relational_word:
            return finite_reference_value_v1(references=(
                ReferenceAtomV1("object", identity),
            ))
        # Keep a binding even when the most precise callee representation is
        # its physical frame coordinate.  A context summary may also contain
        # the same coordinate's parameter form from an ancestor-stack caller;
        # every exact caller can therefore instantiate that joined summary.
        # A pointer into the caller's current outgoing stack already has an
        # exact physical alias in the callee frame: CALL maps caller offset N
        # to callee offset N+4.  Use that coordinate directly so reads and
        # writes have one memory identity rather than two aliases.
        stack_bases = {
            atom.identity: atom.offset for atom in caller_stack_atoms
        }
        if all(atom.identity in stack_bases for atom in value.references):
            offsets = tuple(
                atom.offset - stack_bases[atom.identity] + 4
                for atom in value.references
            )
            if all(offset >= 4 for offset in offsets):
                return finite_reference_value_v1(
                    references=(
                        ReferenceAtomV1("object", frame_identity, offset)
                        for offset in offsets
                    ),
                    alternative_limit=max(
                        catalog.alternative_limit,
                        STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
                    ),
                )
        return finite_reference_value_v1(references=(
            ReferenceAtomV1("object", identity),
        ))

    registers = tuple(
        parameterize(
            f"register:{index}",
            values[node_index],
            relational_word=index in {1, 4, 5, 6},
        )
        if index != 7 else values[node_index]
        for index, node_index in enumerate(call.register_nodes)
    )
    projected = {
        (kind, frame_identity, offset, width): parameterize(
            f"stack:{offset}:{width}",
            value,
        )
        for (kind, _identity, offset, width), value
        in raw_projected.items()
    }
    return (
        registers,
        projected,
        caller_stack_atoms,
        bindings,
        _outgoing_stack_projection_exceeds_limit_v1(
            call, values, caller
        ),
    )
def _instantiate_parameter_value_v1(
    value: ReferenceValueV1,
    bindings: Mapping[str, ReferenceValueV1],
    catalog: ReferenceCatalogV1,
    callee_context: ExecutionFunctionContextV1,
) -> ReferenceValueV1:
    if value.kind != "finite" or not value.references:
        return value
    scalars = set(value.scalars)
    references: set[ReferenceAtomV1] = set()
    direct_bindings: list[ReferenceValueV1] = []
    for atom in value.references:
        parameter_owner = call_parameter_owner_v1(atom.identity)
        binding = (
            None if parameter_owner is None
            else bindings.get(parameter_owner)
        )
        if binding is None:
            if (
                parameter_owner is not None
                and parameter_owner.startswith(
                    f"call_parameter_object:{callee_context.identity}:"
                )
            ):
                return CONFLICT_REFERENCE_V1
            references.add(atom)
            continue
        if (
            atom.kind == "object"
            and atom.identity == parameter_owner
            and atom.offset == 0
        ):
            # A direct relational word placeholder can stand for any abstract
            # word, including scalar, unknown, or conflict.  Derived pointer
            # identities below still require an exact object binding.
            direct_bindings.append(binding)
            continue
        if binding.kind != "finite" or binding.scalars:
            return CONFLICT_REFERENCE_V1
        for actual in binding.references:
            instantiated = instantiate_call_parameter_identity_v1(
                atom.identity, actual
            )
            if instantiated is None:
                return CONFLICT_REFERENCE_V1
            references.add(ReferenceAtomV1(
                "object_view" if atom.kind == "object_view" else "object",
                instantiated.identity,
                0 if atom.kind == "object_view" else (
                    instantiated.offset + atom.offset
                ),
            ))
    result = finite_reference_value_v1(
        scalars=scalars,
        references=references,
        alternative_limit=max(
            catalog.alternative_limit, STACK_REFERENCE_ALTERNATIVE_LIMIT_V1
        ),
    )
    for binding in direct_bindings:
        result = join_reference_values_v1(
            result,
            binding,
            alternative_limit=max(
                catalog.alternative_limit,
                STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
            ),
        )
    return result


def _instantiate_parameter_key_v1(
    key: tuple[str, str, int, int],
    bindings: Mapping[str, ReferenceValueV1],
    callee_context: ExecutionFunctionContextV1,
) -> tuple[tuple[str, str, int, int], ...] | None:
    kind, identity, offset, width = key
    parameter_owner = call_parameter_owner_v1(identity)
    binding = None if parameter_owner is None else bindings.get(parameter_owner)
    if binding is None:
        return (
            None
            if parameter_owner is not None and parameter_owner.startswith(
                f"call_parameter_object:{callee_context.identity}:"
            )
            else (key,)
        )
    if kind != "object" or binding.kind != "finite" or binding.scalars:
        return None
    rows = []
    for atom in binding.references:
        instantiated = instantiate_call_parameter_identity_v1(identity, atom)
        if instantiated is None:
            return None
        rows.append((
            "object", instantiated.identity,
            instantiated.offset + offset, width,
        ))
    return tuple(rows)


def _instantiate_parameter_range_v1(
    row: tuple[str, str, int, int],
    bindings: Mapping[str, ReferenceValueV1],
    callee_context: ExecutionFunctionContextV1,
) -> tuple[tuple[str, str, int, int], ...] | None:
    kind, identity, start, end = row
    parameter_owner = call_parameter_owner_v1(identity)
    binding = None if parameter_owner is None else bindings.get(parameter_owner)
    if binding is None:
        return (
            None
            if parameter_owner is not None and parameter_owner.startswith(
                f"call_parameter_object:{callee_context.identity}:"
            )
            else (row,)
        )
    if kind != "object" or binding.kind != "finite" or binding.scalars:
        return None
    rows = []
    for atom in binding.references:
        instantiated = instantiate_call_parameter_identity_v1(identity, atom)
        if instantiated is None:
            return None
        rows.append((
            "object", instantiated.identity,
            instantiated.offset + start, instantiated.offset + end,
        ))
    return tuple(rows)


def _return_state_for_caller_v1(
    summary: ReferenceStateV1,
    *,
    callee_context: ExecutionFunctionContextV1,
    caller_state: ReferenceStateV1,
    caller_esp: ReferenceValueV1,
    parameter_bindings: Mapping[str, ReferenceValueV1] = {},
    catalog: ReferenceCatalogV1 = ReferenceCatalogV1(),
    diagnostic_failures: list[dict[str, Any]] | None = None,
) -> tuple[ReferenceStateV1 | None, bool]:
    """Instantiate one callee summary and restore the caller coordinate."""

    frame_identity = _stack_frame_identity_v1(callee_context)
    caller_stack_frames = frozenset(
        owner for identity in _state_object_identities_v1(caller_state)
        if (owner := captured_stack_owner_v1(identity)) is not None
    )
    escaped = False

    def expire(value: ReferenceValueV1) -> ReferenceValueV1:
        nonlocal escaped
        value = _instantiate_parameter_value_v1(
            value, parameter_bindings, catalog, callee_context
        )
        if value.kind == "finite" and any(
            atom.kind == "object"
            and atom.identity == frame_identity
            and atom.offset >= 4
            for atom in value.references
        ):
            restored: set[ReferenceAtomV1] = set()
            for atom in value.references:
                if not (
                    atom.kind == "object"
                    and atom.identity == frame_identity
                    and atom.offset >= 4
                ):
                    restored.add(atom)
                    continue
                if (
                    caller_esp.kind != "finite"
                    or caller_esp.scalars
                    or any(
                        base.kind != "object"
                        for base in caller_esp.references
                    )
                ):
                    value = CONFLICT_REFERENCE_V1
                    break
                restored.update(
                    ReferenceAtomV1(
                        "object", base.identity,
                        base.offset + atom.offset - 4,
                    )
                    for base in caller_esp.references
                )
            else:
                value = finite_reference_value_v1(
                    scalars=value.scalars,
                    references=restored,
                    alternative_limit=max(
                        catalog.alternative_limit,
                        STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
                    ),
                )
        result, did_escape = _expire_stack_frame_value_v1(
            value, frame_identity
        )
        escaped = escaped or did_escape
        return result

    registers = [
        value if index == 7 else expire(value)
        for index, value in enumerate(summary.registers)
    ]
    registers[7] = caller_esp
    instantiated_ranges: set[tuple[str, str, int, int]] = set()
    instantiation_failed = False

    def caller_stack_ranges(
        start: int, end: int,
    ) -> tuple[tuple[str, str, int, int], ...] | None:
        # The physical CALL puts its return address at callee offset zero.
        # Positive callee offsets therefore alias caller offsets offset-4.
        if end <= 4:
            return ()
        clipped_start = max(start, 4) - 4
        clipped_end = end - 4
        if (
            caller_esp.kind != "finite"
            or caller_esp.scalars
            or any(atom.kind != "object" for atom in caller_esp.references)
        ):
            return None
        return tuple(
            (
                "object", atom.identity,
                atom.offset + clipped_start, atom.offset + clipped_end,
            )
            for atom in caller_esp.references
        )

    for row in summary.invalidated_memory_ranges:
        row_owner = (
            captured_stack_owner_v1(row[1])
            if row[0] == "object" else None
        )
        if row_owner == frame_identity and row[1] != frame_identity:
            # A variable-size stack region is local to the callee.  Its
            # invalidations die with that region just like ordinary negative
            # frame offsets; escaped references are rejected separately.
            continue
        if row[0] == "object" and row[1] == frame_identity:
            instantiated = caller_stack_ranges(row[2], row[3])
        else:
            instantiated = _instantiate_parameter_range_v1(
                row, parameter_bindings, callee_context
            )
        if instantiated is None:
            instantiation_failed = True
            if diagnostic_failures is not None:
                diagnostic_failures.append({
                    "kind": "invalidated_range",
                    "row": row,
                    "callee_context": callee_context.identity,
                    "binding_present": row[1] in parameter_bindings,
                })
        else:
            instantiated_ranges.update(instantiated)

    # A missing relational binding is absence of a checked return
    # instantiation, not evidence that the callee wrote every guest byte.
    # Defer the caller continuation until its input and summary fixed points
    # provide the binding; the closure emits an explicit final blocker if that
    # never happens.
    if instantiation_failed:
        return None, escaped

    all_memory_invalidated = (
        caller_state.all_memory_invalidated
        or summary.all_memory_invalidated
    )
    memory: dict[
        tuple[str, str, int, int], ReferenceValueV1
    ] = {} if all_memory_invalidated else dict(caller_state.memory)
    if not all_memory_invalidated:
        memory = {
            key: value for key, value in memory.items()
            if not any(
                range_kind == key[0]
                and range_identity == key[1]
                and key[2] < end
                and start < key[2] + key[3]
                for range_kind, range_identity, start, end
                in instantiated_ranges
            )
        }
    instantiated_written_keys: set[tuple[str, str, int, int]] = set()
    for key, value in summary.memory.items():
        if key[0] == "object" and key[1] == frame_identity:
            if key[2] < 4:
                continue
            stack_rows = caller_stack_ranges(key[2], key[2] + key[3])
            if stack_rows is None:
                if diagnostic_failures is not None:
                    diagnostic_failures.append({
                        "kind": "callee_stack_key",
                        "key": key,
                        "callee_context": callee_context.identity,
                    })
                return None, escaped
            instantiated_keys = tuple(
                (kind, identity, start, key[3])
                for kind, identity, start, _end in stack_rows
            )
        else:
            instantiated_keys = _instantiate_parameter_key_v1(
                key, parameter_bindings, callee_context
            )
        if instantiated_keys is None:
            if diagnostic_failures is not None:
                diagnostic_failures.append({
                    "kind": "memory_key",
                    "key": key,
                    "callee_context": callee_context.identity,
                    "binding_present": key[1] in parameter_bindings,
                })
            return None, escaped
        instantiated_value = expire(value)
        for instantiated_key in instantiated_keys:
            owner = (
                captured_stack_owner_v1(instantiated_key[1])
                if instantiated_key[0] == "object" else None
            )
            if owner is not None and owner not in caller_stack_frames:
                continue
            previous = memory.get(instantiated_key)
            memory[instantiated_key] = (
                instantiated_value
                if previous is None or previous == instantiated_value
                else join_reference_values_v1(
                    previous,
                    instantiated_value,
                    alternative_limit=catalog.alternative_limit,
                )
            )
            instantiated_written_keys.add(instantiated_key)
    callbacks = {
        key: expire(value)
        for key, value in summary.callback_registry.items()
    }
    return ReferenceStateV1(
        registers=tuple(registers),
        flags=summary.flags,
        memory=memory,
        call_registers=summary.call_registers,
        call_flags=summary.call_flags,
        invalidated_memory_ranges=frozenset(
            set(caller_state.invalidated_memory_ranges) | instantiated_ranges
        ),
        all_memory_invalidated=all_memory_invalidated,
        callback_registry=callbacks,
        flag_relations=tuple(
            None if (
                relation is not None and relation.register_index == 7
            ) else relation
            for relation in summary.flag_relations
        ),
        scalar_constraints={
            key: value for key, value in summary.scalar_constraints.items()
            if key[0] != 7
        },
        preserves_inherited_memory=(
            caller_state.preserves_inherited_memory
            and summary.preserves_inherited_memory
        ),
        relational_object_bindings=caller_state.relational_object_bindings,
        written_memory_keys=frozenset(
            set(caller_state.written_memory_keys) | instantiated_written_keys
        ),
        effect_invalidated_memory_ranges=frozenset(
            set(caller_state.effect_invalidated_memory_ranges)
            | instantiated_ranges
        ),
        effect_all_memory_invalidated=(
            caller_state.effect_all_memory_invalidated
            or summary.effect_all_memory_invalidated
        ),
        possible_allocation_identities=(
            caller_state.possible_allocation_identities
            | summary.possible_allocation_identities
        ),
    ), escaped


def _conservative_return_state_for_caller_v1(
    summary: ReferenceStateV1,
    *,
    callee_context: ExecutionFunctionContextV1,
    caller_state: ReferenceStateV1,
    caller_esp: ReferenceValueV1,
    parameter_bindings: Mapping[str, ReferenceValueV1] = {},
    catalog: ReferenceCatalogV1 = ReferenceCatalogV1(),
) -> ReferenceStateV1:
    """Keep control reachable when a checked summary cannot be rebound.

    Failure to instantiate a relational write says that the callee may have
    changed any guest byte; it does not say that the callee cannot return.
    Preserve only register/callback facts that can be restored independently,
    invalidate all memory, and leave the original instantiation blocker in
    place.  This is an analysis-local fallback in the same fixed point, not an
    alternative authority path.
    """

    frame_identity = _stack_frame_identity_v1(callee_context)

    def restore(value: ReferenceValueV1) -> ReferenceValueV1:
        value = _instantiate_parameter_value_v1(
            value, parameter_bindings, catalog, callee_context
        )
        if value.kind == "finite" and any(
            atom.kind == "object"
            and atom.identity == frame_identity
            and atom.offset >= 4
            for atom in value.references
        ):
            restored: set[ReferenceAtomV1] = set()
            for atom in value.references:
                if not (
                    atom.kind == "object"
                    and atom.identity == frame_identity
                    and atom.offset >= 4
                ):
                    restored.add(atom)
                    continue
                if (
                    caller_esp.kind != "finite"
                    or caller_esp.scalars
                    or any(base.kind != "object" for base in caller_esp.references)
                ):
                    return CONFLICT_REFERENCE_V1
                restored.update(
                    ReferenceAtomV1(
                        "object", base.identity,
                        base.offset + atom.offset - 4,
                    )
                    for base in caller_esp.references
                )
            value = finite_reference_value_v1(
                scalars=value.scalars,
                references=restored,
                alternative_limit=max(
                    catalog.alternative_limit,
                    STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
                ),
            )
        return _expire_stack_frame_value_v1(value, frame_identity)[0]

    registers = [restore(value) for value in summary.registers]
    registers[7] = caller_esp
    return ReferenceStateV1(
        registers=tuple(registers),
        flags=summary.flags,
        memory={},
        call_registers=summary.call_registers,
        call_flags=summary.call_flags,
        all_memory_invalidated=True,
        callback_registry={
            key: restore(value)
            for key, value in summary.callback_registry.items()
        },
        preserves_inherited_memory=False,
        relational_object_bindings=caller_state.relational_object_bindings,
        effect_all_memory_invalidated=True,
        possible_allocation_identities=(
            caller_state.possible_allocation_identities
            | summary.possible_allocation_identities
        ),
    )


def _callee_state(
    call: _Call,
    values: tuple[ReferenceValueV1, ...],
    caller: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
    callee_context: ExecutionFunctionContextV1,
    parameterized_inputs: tuple[
        tuple[ReferenceValueV1, ...],
        dict[tuple[str, str, int, int], ReferenceValueV1],
        tuple[ReferenceAtomV1, ...],
        dict[str, ReferenceValueV1],
        bool,
    ] | None = None,
) -> tuple[
    ReferenceStateV1, bool, Mapping[str, ReferenceValueV1], bool,
]:
    frame_identity = _stack_frame_identity_v1(callee_context)
    frame_reused = any(
        key[0] == "object"
        and captured_stack_owner_v1(key[1]) == frame_identity
        for key in caller.memory
    )
    derived_inputs = (
        _parameterized_call_inputs_v1(
            call, values, caller, catalog, callee_context
        )
        if parameterized_inputs is None else parameterized_inputs
    )
    (
        parameterized_registers,
        projected,
        caller_stack_atoms,
        parameter_bindings,
        projection_exceeded,
    ) = derived_inputs
    active_parameter_bindings = parameter_bindings
    frame_binding = finite_reference_value_v1(
        references=(
            ReferenceAtomV1("object", atom.identity, atom.offset - 4)
            for atom in caller_stack_atoms
        ),
        alternative_limit=STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
    )
    registers = list(parameterized_registers)
    registers[7] = finite_reference_value_v1(references=(
        ReferenceAtomV1("object", frame_identity, 0),
    ))
    caller_memory = {
        key: value for key, value in caller.memory.items()
        if not (
            key[0] == "object"
            and captured_stack_owner_v1(key[1]) == frame_identity
        )
    }
    # A physical CALL aliases the caller's outgoing stack area into the
    # callee-entry coordinate.  The transfer compiler's stack_inputs inventory
    # is intentionally sparse (it contains checked live inputs, not a second
    # memory model), so project every explicit outgoing stack cell from the
    # canonical pre-call memory state.  Otherwise ordinary argument stores
    # that are not in that sparse inventory disappear at the function
    # boundary.
    parameter_invalidations: set[tuple[str, str, int, int]] = set()
    for parameter_identity, binding in parameter_bindings.items():
        for atom in binding.references:
            for kind, identity, start, end in caller.invalidated_memory_ranges:
                if kind == "object" and identity == atom.identity:
                    parameter_invalidations.add((
                        "object", parameter_identity,
                        start - atom.offset, end - atom.offset,
                    ))
    # Do not carry every ancestral stack frame into every nested call.  A
    # frame remains observable only when a call input, shared-memory cell, or
    # callback value references it (transitively).  This is reachability GC of
    # the same canonical memory graph, not a semantic widening.
    def transient_owner(identity: str) -> str | None:
        frame = captured_stack_owner_v1(identity)
        if frame is not None:
            return frame
        return call_parameter_owner_v1(identity)

    root_values = [
        *registers[:7],
        *projected.values(),
        *active_parameter_bindings.values(),
        frame_binding,
        *caller.callback_registry.values(),
        *(
            value for key, value in caller_memory.items()
            if transient_owner(key[1]) is None
        ),
    ]
    live_transients = {
        owner
        for value in root_values
        for atom in value.references
        if atom.kind in {"object", "object_view"}
        if (owner := transient_owner(atom.identity)) is not None
    }
    changed = True
    while changed:
        changed = False
        for key, value in caller_memory.items():
            owner = transient_owner(key[1])
            if owner is None or owner not in live_transients:
                continue
            for atom in value.references:
                referenced = (
                    transient_owner(atom.identity)
                    if atom.kind in {"object", "object_view"} else None
                )
                if (
                    referenced is not None
                    and referenced not in live_transients
                ):
                    live_transients.add(referenced)
                    changed = True
        for identity, value in caller.relational_object_bindings.items():
            if identity not in live_transients:
                continue
            for atom in value.references:
                referenced = (
                    transient_owner(atom.identity)
                    if atom.kind in {"object", "object_view"} else None
                )
                if (
                    referenced is not None
                    and referenced not in live_transients
                ):
                    live_transients.add(referenced)
                    changed = True
    memory = {
        key: value for key, value in caller_memory.items()
        if (
            (owner := transient_owner(key[1])) is None
            or owner in live_transients
        )
    }
    memory.update(projected)
    # Physical call inputs contain the six serialized architectural flags.
    # The provenance state also reserves one slot for AF, which is derived by
    # the transfer language but is not part of a checked call input frame.
    flags = (
        *(values[index] for index in call.flag_nodes),
        UNKNOWN_SCALAR_REFERENCE_V1,
    )
    invalidated_memory_ranges = {
        row for row in caller.invalidated_memory_ranges
        if (
            (owner := transient_owner(row[1])) is None
            or owner in live_transients
        )
    }
    invalidated_memory_ranges.update(parameter_invalidations)
    for atom in caller_stack_atoms:
        for kind, identity, start, end in caller.invalidated_memory_ranges:
            if kind != "object" or identity != atom.identity or end <= atom.offset:
                continue
            invalidated_memory_ranges.add((
                "object",
                frame_identity,
                max(start, atom.offset) - atom.offset + 4,
                end - atom.offset + 4,
            ))
    return ReferenceStateV1(
        registers=tuple(registers),
        flags=flags,
        memory=memory,
        invalidated_memory_ranges=frozenset(invalidated_memory_ranges),
        all_memory_invalidated=caller.all_memory_invalidated,
        callback_registry=caller.callback_registry,
        flag_relations=caller.flag_relations,
        scalar_constraints=caller.scalar_constraints,
        relational_object_bindings={
            **{
                identity: value
                for identity, value
                in caller.relational_object_bindings.items()
                if identity in live_transients
            },
            **active_parameter_bindings,
            frame_identity: frame_binding,
        },
        possible_allocation_identities=(
            caller.possible_allocation_identities
        ),
    ), frame_reused, parameter_bindings, projection_exceeded


def _transfer_rpo_priorities_v1(
    transfers: tuple[_Transfer, ...],
    roots: tuple[int, ...],
    discovered_edges: frozenset[tuple[int, int]] = frozenset(),
) -> dict[int, int]:
    """Return deterministic reverse-postorder priorities for static edges."""

    rvas = {transfer.rva_start for transfer in transfers}
    adjacency: dict[int, tuple[int, ...]] = {}
    for transfer in transfers:
        targets: set[int] = set()
        terminator = transfer.actions[-1]
        if terminator.op in {"outcome_fallthrough", "outcome_jump"}:
            targets.add(terminator.args[0])
        elif terminator.op == "outcome_branch":
            targets.update(terminator.args[1:3])
        targets.update(
            call.target_rva for call in transfer.calls
            if call.target_rva and call.target_rva in rvas
        )
        targets.update(
            target for source, target in discovered_edges
            if source == transfer.rva_start and target in rvas
        )
        adjacency[transfer.rva_start] = tuple(sorted(targets & rvas))

    visited: set[int] = set()
    postorder: list[int] = []
    seeds = (*roots, *(transfer.rva_start for transfer in transfers))
    for seed in seeds:
        if seed not in rvas or seed in visited:
            continue
        visited.add(seed)
        stack: list[tuple[int, bool]] = [(seed, False)]
        while stack:
            rva, exiting = stack.pop()
            if exiting:
                postorder.append(rva)
                continue
            stack.append((rva, True))
            for target in reversed(adjacency[rva]):
                if target not in visited:
                    visited.add(target)
                    stack.append((target, False))
    return {
        rva: priority
        for priority, rva in enumerate(reversed(postorder))
    }
