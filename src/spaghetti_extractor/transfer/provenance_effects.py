# ruff: noqa: F401
"""Bounded reference provenance over executable-transfer-plan-v2.

This is a semantic interpretation of the canonical plan, not another machine
IR adapter.  Loss of a finite reference becomes an explicit value and later a
closure blocker; it never grants an indirect target.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from functools import cache
from typing import Callable, Iterable, Mapping, MutableMapping

from .interpretation import DomainOperationCoverageV2, total_domain_coverage_v2
from .model import _Call, _FLAGS, _REGISTERS, _Node, _Transfer
from .operations import (
    EFFECT_OPERATIONS_V2,
    EXPRESSION_OPERATIONS_V2,
    expression_operation_v2,
)
from .x87 import typed_x87_operation_writes_memory


REFERENCE_ALTERNATIVE_LIMIT_V1 = 16
STACK_REFERENCE_ALTERNATIVE_LIMIT_V1 = 256
BOUNDED_SCALAR_ALTERNATIVE_LIMIT_V1 = 256
CALL_PARAMETER_OBJECT_PREFIX_V1 = "call_parameter_object:"


from .provenance_model import (
    ReferenceAtomV1,
    captured_stack_owner_v1,
    is_call_parameter_object_v1,
    _aligned_object_identity_v1,
    call_parameter_owner_v1,
    instantiate_call_parameter_identity_v1,
    ReferenceValueV1,
    finite_reference_value_v1,
    _interned_finite_reference_value_v1,
    join_reference_values_v1,
    ObjectRangeV1,
    ExternalMemoryCopyV1,
    ExternalMemoryWriteV1,
    ExternalOutPointerV1,
    ExternalCallbackRuleV1,
    ExternalCallRuleV1,
    ReferenceCatalogV1,
    ScalarFlagRelationV1,
    _normalized_memory_ranges_v1,
    ReferenceStateV1,
    _MutableReferenceStateViewV1,
    BOTTOM_REFERENCE_V1,
    UNKNOWN_SCALAR_REFERENCE_V1,
    CONFLICT_REFERENCE_V1,
)
from .provenance_branch import (
    reference_operation_coverage_v2,
    _scalar_product,
    _adjust_reference,
    _aligned_object_reference_v1,
    adjust_reference_by_constant_v1,
    _dynamic_stack_region_v1,
    _predicate_value_v1,
    _branch_predicate_node_v1,
    _branch_equality_subject_v1,
    _masked_register_subject_v1,
    _scalar_flag_relation_v1,
    _branch_flag_relation_v1,
    _branch_scalar_constraint_v1,
    _filter_reference_equality_v1,
    _drop_narrowed_allocation_alternatives_v1,
    refine_reference_state_for_branch_v1,
)
from .provenance_memory import (
    _memory_keys,
    _ranges_overlap,
    _memory_key_invalidated_v1,
    _memory_value_v1,
    _external_memory_copy_words_v1,
    call_argument_values_v1,
    _static_loader_name_v1,
    _module_handle_result_v1,
    _dynamic_export_result_v1,
    _write_range_v1,
    _callback_source_value_v1,
    _callback_instance_keys_v1,
    _interpret_reference_node_v1,
    interpret_reference_expressions_v1,
)

def apply_reference_effects_v1(
    transfer: _Transfer,
    state: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
    call_result_overrides: Mapping[int, ReferenceStateV1] | None = None,
    call_input_states: MutableMapping[int, ReferenceStateV1] | None = None,
    unresolved_external_writes: MutableMapping[
        int, tuple[ReferenceValueV1, ...]
    ] | None = None,
    action_input_states: MutableMapping[int, ReferenceStateV1] | None = None,
) -> tuple[ReferenceStateV1, tuple[ReferenceValueV1, ...]]:
    values: list[ReferenceValueV1 | None] = [None] * len(transfer.nodes)
    stack_nodes: set[int] = set()
    stack_pending = [
        action.args[0] for action in transfer.actions[:-1]
        if action.op == "set_reg" and action.aux == 7
    ]
    while stack_pending:
        node_index = stack_pending.pop()
        if node_index in stack_nodes:
            continue
        stack_nodes.add(node_index)
        stack_pending.extend(transfer.nodes[node_index].args)
    target_nodes: set[int] = set()
    target_pending = [
        transfer.actions[-1].args[0]
        for _unit in (0,)
        if transfer.actions[-1].op in {
            "outcome_indirect", "outcome_nonlocal",
        }
    ]
    target_pending.extend(
        call.target_node for call in transfer.calls
        if call.target_node is not None
    )
    while target_pending:
        node_index = target_pending.pop()
        if node_index in target_nodes:
            continue
        target_nodes.add(node_index)
        target_pending.extend(transfer.nodes[node_index].args)
    registers = list(state.registers)
    flags = list(state.flags)
    # Most machine transfers do not mutate memory.  Preserve the incoming map
    # by identity until the first write so closure joins can recognize an
    # unchanged shared-memory version without copying or rescanning it.
    memory: Mapping[
        tuple[str, str, int, int], ReferenceValueV1
    ] = state.memory
    memory_owned = False
    invalidated_memory_ranges = set(state.invalidated_memory_ranges)
    all_memory_invalidated = state.all_memory_invalidated
    callback_registry = dict(state.callback_registry)
    flag_relations = list(state.flag_relations)
    scalar_constraints = dict(state.scalar_constraints)
    call_registers = list(state.call_registers)
    call_flags = list(state.call_flags)
    preserves_inherited_memory = state.preserves_inherited_memory
    written_memory_keys = set(state.written_memory_keys)
    effect_invalidated_memory_ranges = set(
        state.effect_invalidated_memory_ranges
    )
    effect_all_memory_invalidated = state.effect_all_memory_invalidated
    possible_allocation_identities = set(
        state.possible_allocation_identities
    )
    current_view = _MutableReferenceStateViewV1(
        registers=registers,
        flags=flags,
        memory=memory,
        call_registers=call_registers,
        call_flags=call_flags,
        invalidated_memory_ranges=invalidated_memory_ranges,
        all_memory_invalidated=all_memory_invalidated,
        relational_object_bindings=state.relational_object_bindings,
    )

    def writable_memory() -> dict[
        tuple[str, str, int, int], ReferenceValueV1
    ]:
        nonlocal memory, memory_owned
        if not memory_owned:
            memory = dict(memory)
            memory_owned = True
            current_view.memory = memory
        assert isinstance(memory, dict)
        return memory

    def current_state() -> ReferenceStateV1:
        return ReferenceStateV1(
            registers=tuple(registers),
            flags=tuple(flags),
            memory=memory,
            call_registers=tuple(call_registers),
            call_flags=tuple(call_flags),
            invalidated_memory_ranges=frozenset(invalidated_memory_ranges),
            all_memory_invalidated=all_memory_invalidated,
            # The mutable registry continues through the remainder of this
            # transfer.  Captured action/call inputs are pre-effect snapshots:
            # sharing the dict lets a later internal-call return override or
            # callback registration rewrite the state that was supplied to
            # the callee, feeding post-call facts backwards around the fixed
            # point.  Memory is copy-on-write; snapshot this small map for the
            # same value semantics.
            callback_registry=dict(callback_registry),
            flag_relations=tuple(flag_relations),
            scalar_constraints=scalar_constraints,
            preserves_inherited_memory=preserves_inherited_memory,
            relational_object_bindings=state.relational_object_bindings,
            written_memory_keys=frozenset(written_memory_keys),
            effect_invalidated_memory_ranges=frozenset(
                effect_invalidated_memory_ranges
            ),
            effect_all_memory_invalidated=effect_all_memory_invalidated,
            possible_allocation_identities=frozenset(
                possible_allocation_identities
            ),
        )

    def writes_outside_current_frame(
        keys: Iterable[tuple[str, str, int, int]] | None,
    ) -> bool:
        if keys is None:
            return True
        current_frames = {
            owner
            for atom in registers[7].references
            if atom.kind in {"object", "object_view"}
            if (owner := captured_stack_owner_v1(atom.identity)) is not None
        }
        return any(
            kind != "object"
            or captured_stack_owner_v1(identity) not in current_frames
            for kind, identity, _start, _end in keys
        )

    def invalidate_write_ranges(
        ranges: Iterable[tuple[str, str, int, int]],
    ) -> None:
        nonlocal memory, memory_owned
        rows = tuple(ranges)
        if not rows:
            return
        invalidated_memory_ranges.update(rows)
        effect_invalidated_memory_ranges.update(rows)
        memory = {
            key: value for key, value in memory.items()
            if not any(
                range_kind == key[0]
                and range_identity == key[1]
                and _ranges_overlap(
                    key[2], key[2] + key[3], start, end
                )
                for range_kind, range_identity, start, end in rows
            )
        }
        memory_owned = True
        current_view.memory = memory

    def invalidate_unknown_write() -> None:
        nonlocal all_memory_invalidated, memory, memory_owned
        nonlocal effect_all_memory_invalidated
        all_memory_invalidated = True
        current_view.all_memory_invalidated = True
        invalidated_memory_ranges.clear()
        effect_all_memory_invalidated = True
        effect_invalidated_memory_ranges.clear()
        written_memory_keys.clear()
        memory = {}
        memory_owned = True
        current_view.memory = memory

    def repeated_write_ranges(
        destination: ReferenceValueV1,
        count: ReferenceValueV1,
        direction: ReferenceValueV1,
        width: int,
    ) -> tuple[tuple[str, str, int, int], ...] | None:
        keys = _memory_keys(destination, width)
        if (
            keys is None
            or count.kind != "finite"
            or count.references
            or direction.kind != "finite"
            or direction.references
        ):
            return None
        ranges: set[tuple[str, str, int, int]] = set()
        for kind, identity, offset, _key_width in keys:
            for repetitions in count.scalars:
                repetitions &= 0xFFFF_FFFF
                if repetitions == 0:
                    continue
                for backwards in direction.scalars:
                    if backwards & 1:
                        start = offset - (repetitions - 1) * width
                        end = offset + width
                    else:
                        start = offset
                        end = offset + repetitions * width
                    ranges.add((kind, identity, start, end))
        return tuple(sorted(ranges))

    def object_scoped_repeat_write_ranges(
        destination: ReferenceValueV1,
        direction: ReferenceValueV1,
        width: int,
    ) -> tuple[tuple[str, str, int, int], ...] | None:
        """Bound an otherwise unknown repeat write to known objects.

        An unknown count prevents an exact footprint, but it does not erase
        an exact destination object's identity.  Keep the conservative
        unbounded prefix/suffix (or whole-object) invalidation local to every
        possible destination object.  Scalar and non-object alternatives
        still require the all-memory fallback.
        """
        if (
            destination.kind != "finite"
            or destination.scalars
            or not destination.references
            or any(
                atom.kind not in {"object", "object_view"}
                for atom in destination.references
            )
        ):
            return None
        directions = (
            tuple(bool(value & 1) for value in direction.scalars)
            if direction.kind == "finite"
            and not direction.references
            and direction.scalars
            else None
        )
        ranges: set[tuple[str, str, int, int]] = set()
        for atom in destination.references:
            if atom.kind == "object_view" or directions is None:
                ranges.add((
                    "object", atom.identity, -(1 << 63), 1 << 63,
                ))
                continue
            for backwards in directions:
                ranges.add((
                    "object",
                    atom.identity,
                    -(1 << 63) if backwards else atom.offset,
                    atom.offset + width if backwards else 1 << 63,
                ))
        return tuple(sorted(ranges))

    def exact_repeat_shape(
        address: ReferenceValueV1,
        count: ReferenceValueV1,
        direction: ReferenceValueV1,
        width: int,
    ) -> tuple[tuple[str, str, int, int], int, bool] | None:
        keys = _memory_keys(address, width)
        if (
            keys is None
            or len(keys) != 1
            or count.kind != "finite"
            or count.references
            or len(count.scalars) != 1
            or direction.kind != "finite"
            or direction.references
            or len(direction.scalars) != 1
        ):
            return None
        repetitions = next(iter(count.scalars)) & 0xFFFF_FFFF
        if repetitions > 256:
            return None
        return keys[0], repetitions, bool(next(iter(direction.scalars)) & 1)

    def typed_x87_memory_address(action_index: int) -> ReferenceValueV1:
        program = transfer.x87_operations[action_index]
        operand = program.operation.operand
        if operand.image_rva is not None:
            return catalog.classify_scalar(
                program.image_base + operand.image_rva
            )
        address = finite_reference_value_v1(scalars=(0,))
        if operand.base is not None:
            address = registers[_REGISTERS.index(operand.base)]
        if operand.index is not None:
            index = _scalar_product(
                (
                    registers[_REGISTERS.index(operand.index)],
                    finite_reference_value_v1(scalars=(operand.scale,)),
                ),
                "mul32",
                catalog.alternative_limit,
            )
            address = _adjust_reference(address, index, False, catalog)
        return adjust_reference_by_constant_v1(
            address, operand.displacement, catalog
        )

    def word(index: int) -> ReferenceValueV1:
        cached = values[index]
        if cached is not None:
            return cached
        node = transfer.nodes[index]
        subject = (
            _masked_register_subject_v1(transfer, index)
            if node.op in {"and32", "reg"} else None
        )
        constrained = (
            None if subject is None
            else scalar_constraints.get(subject)
        )
        if constrained is not None:
            value = finite_reference_value_v1(
                scalars=constrained,
                alternative_limit=BOUNDED_SCALAR_ALTERNATIVE_LIMIT_V1,
            )
        else:
            value = _interpret_reference_node_v1(
                node,
                tuple(word(argument) for argument in node.args),
                state,
                current_view,
                catalog,
                alternative_limit=(
                    max(
                        catalog.alternative_limit,
                        BOUNDED_SCALAR_ALTERNATIVE_LIMIT_V1,
                    )
                    if index in target_nodes else (
                        STACK_REFERENCE_ALTERNATIVE_LIMIT_V1
                        if index in stack_nodes else catalog.alternative_limit
                    )
                ),
            )
        values[index] = value
        return value

    for action_index, action in enumerate(transfer.actions[:-1]):
        if action_input_states is not None:
            action_input_states[action_index] = current_state()
        operation = action.op
        if operation == "eval_word":
            # Evaluation actions are semantic sequence points.  Nodes that
            # read the current machine state must be cached here, before a
            # later call or effect mutates that state.
            word(action.args[0])
        elif operation == "set_reg":
            scalar_constraints = {
                key: value for key, value in scalar_constraints.items()
                if key[0] != action.aux
            }
            flag_relations = [
                None if (
                    relation is not None
                    and relation.register_index == action.aux
                ) else relation
                for relation in flag_relations
            ]
            assigned = word(action.args[0])
            assigned_node = transfer.nodes[action.args[0]]
            if (
                action.aux == 7
                and assigned.kind in {"unknown_scalar", "conflict"}
                and assigned_node.op == "sub32"
            ):
                dynamic_region = _dynamic_stack_region_v1(
                    transfer,
                    action.args[0],
                    word(assigned_node.args[0]),
                    catalog,
                )
                if dynamic_region is not None:
                    assigned = dynamic_region
            registers[action.aux] = assigned
        elif operation == "set_flag":
            flags[action.aux] = word(action.args[0])
            flag_relations[action.aux] = _scalar_flag_relation_v1(
                transfer, action.args[0]
            )
        elif operation == "memory_write":
            keys = _memory_keys(word(action.args[0]), action.aux)
            if writes_outside_current_frame(keys):
                preserves_inherited_memory = False
            if keys is not None:
                for key in keys:
                    writable_memory()[key] = word(action.args[1])
                    written_memory_keys.add(key)
        elif operation == "atomic_exchange":
            keys = _memory_keys(word(action.args[0]), action.aux)
            if writes_outside_current_frame(keys):
                preserves_inherited_memory = False
            if keys is not None:
                for key in keys:
                    writable_memory()[key] = word(action.args[1])
                    written_memory_keys.add(key)
        elif operation == "atomic_compare_exchange":
            keys = _memory_keys(word(action.args[0]), action.aux)
            if writes_outside_current_frame(keys):
                preserves_inherited_memory = False
            if keys is not None:
                for key in keys:
                    writable_memory()[key] = join_reference_values_v1(
                        _memory_value_v1(current_view, key, catalog),
                        word(action.args[2]),
                        alternative_limit=catalog.alternative_limit,
                    )
                    written_memory_keys.add(key)
        elif operation in {"rep_movsd", "rep_movs", "rep_stosd", "rep_stos"}:
            width = 4 if operation in {"rep_movsd", "rep_stosd"} else action.aux
            destination_index = 1 if operation in {"rep_movsd", "rep_movs"} else 0
            destination_shape = exact_repeat_shape(
                word(action.args[destination_index]),
                word(action.args[2]),
                word(action.args[3]),
                width,
            )
            ranges = repeated_write_ranges(
                word(action.args[destination_index]),
                word(action.args[2]),
                word(action.args[3]),
                width,
            )
            source_shape = (
                exact_repeat_shape(
                    word(action.args[0]),
                    word(action.args[2]),
                    word(action.args[3]),
                    width,
                )
                if operation in {"rep_movsd", "rep_movs"} else None
            )
            exact = destination_shape is not None and (
                source_shape is not None
                if operation in {"rep_movsd", "rep_movs"} else True
            )
            if exact:
                assert destination_shape is not None
                destination_key, repetitions, backwards = destination_shape
                if ranges and writes_outside_current_frame(ranges):
                    preserves_inherited_memory = False
                # Keep the exact footprint receipt even though word-sized
                # cells are materialized below.  Explicit cells take
                # precedence on reads; the range still invalidates overlapping
                # widths and survives interprocedural effect summarization.
                invalidated_memory_ranges.update(ranges or ())
                effect_invalidated_memory_ranges.update(ranges or ())
                for index in range(repetitions):
                    delta = (-index if backwards else index) * width
                    write_key = (
                        destination_key[0], destination_key[1],
                        destination_key[2] + delta, width,
                    )
                    copied = (
                        word(action.args[1])
                        if source_shape is None else _memory_value_v1(
                            current_view,
                            (
                                source_shape[0][0], source_shape[0][1],
                                source_shape[0][2] + delta, width,
                            ),
                            catalog,
                        )
                    )
                    writable_memory()[write_key] = copied
                    written_memory_keys.add(write_key)
            elif ranges is None:
                ranges = object_scoped_repeat_write_ranges(
                    word(action.args[destination_index]),
                    word(action.args[3]),
                    width,
                )
                if ranges is None:
                    preserves_inherited_memory = False
                    invalidate_unknown_write()
                else:
                    if writes_outside_current_frame(ranges):
                        preserves_inherited_memory = False
                    invalidate_write_ranges(ranges)
            elif ranges:
                if writes_outside_current_frame(ranges):
                    preserves_inherited_memory = False
                invalidate_write_ranges(ranges)
        elif operation == "typed_x87":
            program = transfer.x87_operations[action.args[0]]
            typed = program.operation
            if typed.operand.kind == "ax":
                registers[0] = UNKNOWN_SCALAR_REFERENCE_V1
            if typed.mnemonic in {
                "fcomi", "fcomip", "fcompi", "fucomi", "fucomip", "fucompi",
            }:
                for flag_index in (0, 1, 4):
                    flags[flag_index] = UNKNOWN_SCALAR_REFERENCE_V1
                    flag_relations[flag_index] = None
            if typed_x87_operation_writes_memory(typed):
                keys = _memory_keys(
                    typed_x87_memory_address(action.args[0]),
                    typed.operand.width,
                )
                ranges = None if keys is None else tuple(
                    (kind, identity, offset, offset + width)
                    for kind, identity, offset, width in keys
                )
                if ranges is None:
                    preserves_inherited_memory = False
                    invalidate_unknown_write()
                elif ranges:
                    if writes_outside_current_frame(ranges):
                        preserves_inherited_memory = False
                    invalidate_write_ranges(ranges)
        elif operation == "call":
            call = transfer.calls[action.args[0]]
            if call_input_states is not None:
                call_input_states[call.call_index] = current_state()
            override = (
                None if call_result_overrides is None
                else call_result_overrides.get(call.call_index)
            )
            if override is not None:
                call_registers[:] = override.registers
                call_flags[:] = override.flags
                memory = override.memory
                memory_owned = False
                current_view.memory = memory
                invalidated_memory_ranges.clear()
                invalidated_memory_ranges.update(
                    override.invalidated_memory_ranges
                )
                all_memory_invalidated = override.all_memory_invalidated
                current_view.all_memory_invalidated = all_memory_invalidated
                callback_registry.clear()
                callback_registry.update(override.callback_registry)
                preserves_inherited_memory = (
                    override.preserves_inherited_memory
                )
                written_memory_keys.clear()
                written_memory_keys.update(override.written_memory_keys)
                effect_invalidated_memory_ranges.clear()
                effect_invalidated_memory_ranges.update(
                    override.effect_invalidated_memory_ranges
                )
                effect_all_memory_invalidated = (
                    override.effect_all_memory_invalidated
                )
                possible_allocation_identities.clear()
                possible_allocation_identities.update(
                    override.possible_allocation_identities
                )
                continue
            # A call without a checked return override is reachable but has an
            # unknown result. Bottom means no reachable information and would
            # incorrectly prune the continuation after an unresolved indirect
            # call. Known internal calls are replayed with summaries before
            # their continuation is enqueued by the closure engine.
            default = UNKNOWN_SCALAR_REFERENCE_V1
            call_registers[:] = [default] * len(_REGISTERS)
            call_flags[:] = [default] * (len(_FLAGS) + 1)
            rules: list[ExternalCallRuleV1] = []
            if call.kind == "external_call":
                identity = (
                    call.symbol if call.symbol is not None
                    else f"ordinal:{call.ordinal}"
                )
                rule = catalog.external_calls.get(
                    ((call.dll or "").lower(), identity)
                )
                if rule is not None:
                    rules.append(rule)
            elif call.target_node is not None:
                target = word(call.target_node)
                if target.kind == "finite" and not target.scalars:
                    for atom in target.references:
                        if atom.kind != "external_function" or atom.offset != 0:
                            rules = []
                            break
                        key = catalog.external_function_contracts.get(atom.identity)
                        rule = (
                            None if key is None else catalog.external_calls.get(key)
                        )
                        if rule is None:
                            rules = []
                            break
                        rules.append(rule)
            rule = _merge_external_call_rules_v1(rules)
            if rule is not None:
                for register_index in rule.preserved_registers:
                    call_registers[register_index] = word(
                        call.register_nodes[register_index]
                    )
                if 7 in rule.preserved_registers and rule.stack_cleanup_bytes:
                    call_registers[7] = adjust_reference_by_constant_v1(
                        call_registers[7],
                        rule.stack_cleanup_bytes,
                        catalog,
                        alternative_limit=STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
                    )
                arguments = call_argument_values_v1(
                    call,
                    word,
                    current_view,
                    catalog,
                    argument_words=rule.argument_words,
                    base_offset=(
                        4
                        if transfer.actions[-1].op == "outcome_external"
                        else 0
                    ),
                )
                if rule.module_handle_name_argument is not None:
                    call_registers[0] = _module_handle_result_v1(
                        rule, arguments, catalog
                    )
                if rule.dynamic_export_handle_argument is not None:
                    call_registers[0] = _dynamic_export_result_v1(
                        rule, arguments, catalog
                    )
                write_ranges: set[tuple[str, str, int, int]] = set()
                copy_writes: list[
                    tuple[
                        tuple[str, str, int, int], ReferenceValueV1,
                    ]
                ] = []
                out_pointer_writes: list[
                    tuple[
                        tuple[tuple[str, str, int, int], ...],
                        ReferenceValueV1,
                    ]
                ] = []
                precise_writes = not rule.unknown_guest_memory_write
                for footprint in rule.write_footprints:
                    ranges = _write_range_v1(footprint, arguments)
                    if ranges is None:
                        precise_writes = False
                        break
                    write_ranges.update(ranges)
                if precise_writes:
                    for relation in rule.memory_copies:
                        copied = _external_memory_copy_words_v1(
                            relation, arguments, current_view, catalog
                        )
                        if copied is not None:
                            copy_writes.extend(copied)
                if precise_writes:
                    for relation_index, relation in enumerate(
                        rule.out_pointers
                    ):
                        if relation.argument >= len(arguments):
                            precise_writes = False
                            break
                        destination = adjust_reference_by_constant_v1(
                            arguments[relation.argument],
                            relation.offset,
                            catalog,
                        )
                        keys = _memory_keys(destination, 4)
                        if keys is None:
                            precise_writes = False
                            break
                        write_ranges.update(
                            (kind, identity, offset, offset + width)
                            for kind, identity, offset, width in keys
                        )
                        out_pointer_writes.append((
                            keys,
                            finite_reference_value_v1(
                                scalars=(0,) if relation.nullable else (),
                                references=(ReferenceAtomV1(
                                    "object",
                                    "external-out-pointer:"
                                    f"{transfer.identity}:"
                                    f"{call.instruction_rva:08x}:"
                                    f"{call.call_index}:{relation_index}",
                                ),),
                                alternative_limit=catalog.alternative_limit,
                            ),
                        ))
                if not precise_writes:
                    preserves_inherited_memory = False
                    if unresolved_external_writes is not None:
                        unresolved_external_writes[call.call_index] = arguments
                    invalidate_unknown_write()
                elif write_ranges:
                    if writes_outside_current_frame(write_ranges):
                        preserves_inherited_memory = False
                    invalidate_write_ranges(write_ranges)
                    for key, copied in copy_writes:
                        writable_memory()[key] = copied
                        written_memory_keys.add(key)
                    for keys, pointer in out_pointer_writes:
                        for key in keys:
                            writable_memory()[key] = pointer
                            written_memory_keys.add(key)
                if rule.callback is not None:
                    callback = rule.callback
                    instance_keys = _callback_instance_keys_v1(
                        callback, arguments
                    )
                    source = _callback_source_value_v1(
                        callback, arguments, current_view, catalog
                    )
                    if (
                        callback.action == "replace"
                        and callback.previous_result_register is not None
                    ):
                        previous = BOTTOM_REFERENCE_V1
                        defaults = finite_reference_value_v1(
                            scalars=callback.previous_sentinels,
                            alternative_limit=catalog.alternative_limit,
                        )
                        if instance_keys is None:
                            previous = UNKNOWN_SCALAR_REFERENCE_V1
                        else:
                            for instance_key in instance_keys:
                                previous = join_reference_values_v1(
                                    previous,
                                    callback_registry.get(instance_key, defaults),
                                    alternative_limit=catalog.alternative_limit,
                                )
                        call_registers[
                            callback.previous_result_register
                        ] = previous
                    if instance_keys is None:
                        callback_registry[
                            f"{callback.protocol_id}:unknown-instance"
                        ] = UNKNOWN_SCALAR_REFERENCE_V1
                    else:
                        for instance_key in instance_keys:
                            callback_registry[instance_key] = source
            if rule is not None and rule.allocation_result_register is not None:
                allocation_id = (
                    f"allocation:{transfer.identity}:"
                    f"{call.instruction_rva:08x}:{call.call_index}"
                )
                call_registers[rule.allocation_result_register] = (
                    finite_reference_value_v1(
                        scalars=(0,) if rule.allocation_nullable else (),
                        references=(
                            ReferenceAtomV1("object", allocation_id, 0),
                        ),
                        alternative_limit=catalog.alternative_limit,
                    )
                )
                possible_allocation_identities.add(allocation_id)
        elif operation in EFFECT_OPERATIONS_V2:
            # Calls, repeats, x87, and scalar-only effects cannot safely create
            # a finite code target here. Unknown memory remains a later veto.
            continue
        else:
            raise AssertionError(f"reference effect handler absent for {operation!r}")
    terminator = transfer.actions[-1]
    for index in terminator.args[:1] if terminator.op == "outcome_branch" else (
        terminator.args
        if terminator.op in {
            "outcome_return", "outcome_indirect", "outcome_nonlocal",
        }
        else ()
    ):
        word(index)
    for index in range(len(values)):
        word(index)
    return (
        ReferenceStateV1(
            registers=tuple(registers),
            flags=tuple(flags),
            memory=memory,
            call_registers=tuple(call_registers),
            call_flags=tuple(call_flags),
            invalidated_memory_ranges=frozenset(invalidated_memory_ranges),
            all_memory_invalidated=all_memory_invalidated,
            callback_registry=callback_registry,
            flag_relations=tuple(flag_relations),
            scalar_constraints=scalar_constraints,
            preserves_inherited_memory=preserves_inherited_memory,
            relational_object_bindings=state.relational_object_bindings,
            written_memory_keys=frozenset(written_memory_keys),
            effect_invalidated_memory_ranges=frozenset(
                effect_invalidated_memory_ranges
            ),
            effect_all_memory_invalidated=effect_all_memory_invalidated,
            possible_allocation_identities=frozenset(
                possible_allocation_identities
            ),
        ),
        tuple(value for value in values if value is not None),
    )


def _merge_external_call_rules_v1(
    rules: Iterable[ExternalCallRuleV1],
) -> ExternalCallRuleV1 | None:
    rows = tuple(rules)
    if not rows:
        return None
    cleanup = {row.stack_cleanup_bytes for row in rows}
    argument_counts = {row.argument_words for row in rows}
    dispositions = {row.disposition for row in rows}
    allocation_registers = {row.allocation_result_register for row in rows}
    allocation_nullable = {row.allocation_nullable for row in rows}
    memory_copies = {row.memory_copies for row in rows}
    callbacks = {row.callback for row in rows}

    def shared(attribute: str) -> object | None:
        first = getattr(rows[0], attribute)
        return first if all(
            getattr(row, attribute) == first for row in rows[1:]
        ) else None

    preserved = frozenset.intersection(
        *(row.preserved_registers for row in rows)
    )
    if len(cleanup) != 1:
        preserved = preserved - {7}
    return ExternalCallRuleV1(
        preserved_registers=preserved,
        argument_words=(
            argument_counts.pop() if len(argument_counts) == 1 else 0
        ),
        stack_cleanup_bytes=(cleanup.pop() if len(cleanup) == 1 else 0),
        disposition=(
            dispositions.pop() if len(dispositions) == 1 else "returns"
        ),
        allocation_result_register=(
            allocation_registers.pop()
            if len(allocation_registers) == 1 else None
        ),
        allocation_nullable=(
            allocation_nullable.pop() if len(allocation_nullable) == 1 else True
        ),
        write_footprints=tuple(sorted({
            footprint for row in rows for footprint in row.write_footprints
        }, key=lambda footprint: (
            footprint.base_argument,
            footprint.offset,
            footprint.fixed_bytes if footprint.fixed_bytes is not None else -1,
            footprint.size_argument if footprint.size_argument is not None else -1,
            footprint.scale,
            footprint.authority_selector or "",
        ))),
        memory_copies=(
            memory_copies.pop() if len(memory_copies) == 1 else ()
        ),
        out_pointers=tuple(sorted({
            relation for row in rows for relation in row.out_pointers
        }, key=lambda relation: (
            relation.argument,
            relation.offset,
            relation.nullable,
            relation.max_elements,
            relation.element_unit_bytes,
            relation.element_max_units,
        ))),
        unknown_guest_memory_write=any(
            row.unknown_guest_memory_write for row in rows
        ),
        callback=callbacks.pop() if len(callbacks) == 1 else None,
        module_handle_name_argument=shared(
            "module_handle_name_argument"
        ),
        module_handle_nullable_name=bool(shared(
            "module_handle_nullable_name"
        )),
        module_handle_wide_name=bool(shared(
            "module_handle_wide_name"
        )),
        dynamic_export_handle_argument=shared(
            "dynamic_export_handle_argument"
        ),
        dynamic_export_name_argument=shared(
            "dynamic_export_name_argument"
        ),
        dynamic_export_results=(
            rows[0].dynamic_export_results
            if all(
                row.dynamic_export_results == rows[0].dynamic_export_results
                for row in rows[1:]
            )
            else {}
        ),
    )


def indirect_targets_v1(
    transfer: _Transfer, values: tuple[ReferenceValueV1, ...]
) -> tuple[int, ...] | None:
    terminator = transfer.actions[-1]
    if terminator.op != "outcome_indirect":
        return ()
    value = values[terminator.args[0]]
    if value.kind != "finite" or value.scalars:
        return None
    targets = []
    for atom in value.references:
        if atom.kind != "guest_code" or atom.offset != 0:
            return None
        targets.append(int(atom.identity.removeprefix("rva:"), 16))
    return tuple(sorted(set(targets)))
