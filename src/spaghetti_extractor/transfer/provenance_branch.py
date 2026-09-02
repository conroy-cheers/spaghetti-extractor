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

from .model import _Call, _FLAGS, _REGISTERS, _Node, _Transfer
from .operations import (
    EFFECT_OPERATIONS_V2,
    EXPRESSION_OPERATIONS_V2,
    expression_operation_v2,
)
from .x87 import typed_x87_operation_writes_memory
from .provenance_coverage import reference_operation_coverage_v2


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



_PREDICATE_RESULTS_V1 = frozenset({
    name for name, spec in EXPRESSION_OPERATIONS_V2.items()
    if spec.result_sort == "predicate"
})
_REFERENCE_PRESERVING_BINARY_V1 = frozenset({"add32", "sub32"})
_EXACT_SCALAR_OPERATIONS_V1 = frozenset({
    "mul32", "xor32", "and32", "or32", "not32", "neg32", "shl32",
    "lshr32", "sar", "sign_extend", "bool_to_bit", "imul_low32",
    "mul_low32", "imul_high32", "mul_high32", "udiv_quot32",
    "udiv_rem32", "bsr_index", "tzcnt", "fpu_control_load",
    "fpu_control_word", "fpu_status_word",
})
_UNKNOWN_WORD_OPERATIONS_V1 = frozenset({
    name for name, spec in EXPRESSION_OPERATIONS_V2.items()
    if spec.result_sort == "bitvector"
}) - {
    "const", "reg", "fs_base", "undefined_bv", "call_response", "load",
    "ite", *_REFERENCE_PRESERVING_BINARY_V1, *_EXACT_SCALAR_OPERATIONS_V1,
}


def _scalar_product(
    values: tuple[ReferenceValueV1, ...], operation: str, limit: int,
) -> ReferenceValueV1:
    if any(value.kind == "conflict" or value.references for value in values):
        return CONFLICT_REFERENCE_V1
    if any(value.kind != "finite" for value in values):
        return UNKNOWN_SCALAR_REFERENCE_V1
    products: set[int] = set()
    rows: list[tuple[int, ...]] = [()]
    for value in values:
        rows = [prefix + (item,) for prefix in rows for item in value.scalars]
        if len(rows) > limit:
            return CONFLICT_REFERENCE_V1
    for row in rows:
        if operation == "mul32":
            result = 1
            for item in row:
                result *= item
        elif operation == "xor32":
            result = 0
            for item in row:
                result ^= item
        elif operation == "and32":
            result = 0xFFFF_FFFF
            for item in row:
                result &= item
        elif operation == "or32":
            result = 0
            for item in row:
                result |= item
        elif operation == "not32":
            result = ~row[0]
        elif operation == "neg32":
            result = -row[0]
        elif operation == "shl32":
            result = row[0] << (row[1] & 31)
        elif operation == "lshr32":
            result = row[0] >> (row[1] & 31)
        elif operation == "bool_to_bit":
            result = int(bool(row[0]))
        elif operation in {"imul_low32", "mul_low32"}:
            result = row[0] * row[1]
        else:
            return UNKNOWN_SCALAR_REFERENCE_V1
        products.add(result & 0xFFFF_FFFF)
        if len(products) > limit:
            return CONFLICT_REFERENCE_V1
    return finite_reference_value_v1(scalars=products, alternative_limit=limit)


def _adjust_reference(
    left: ReferenceValueV1, right: ReferenceValueV1, subtract: bool,
    catalog: ReferenceCatalogV1,
    *,
    alternative_limit: int | None = None,
) -> ReferenceValueV1:
    limit = (
        catalog.alternative_limit
        if alternative_limit is None else alternative_limit
    )
    if left.kind != "finite" or right.kind != "finite":
        if "conflict" in {left.kind, right.kind}:
            return CONFLICT_REFERENCE_V1
        return UNKNOWN_SCALAR_REFERENCE_V1
    scalars = {
        (lhs - rhs if subtract else lhs + rhs) & 0xFFFF_FFFF
        for lhs in left.scalars for rhs in right.scalars
    }
    references: set[ReferenceAtomV1] = set()
    invalid = bool(subtract and left.scalars and right.references)
    for atom in left.references:
        for delta in right.scalars:
            signed_delta = delta if delta < 0x8000_0000 else delta - 0x1_0000_0000
            if atom.kind == "object_view":
                references.add(atom)
                continue
            if atom.kind != "object" and signed_delta != 0:
                invalid = True
                continue
            references.add(replace(
                atom,
                offset=atom.offset + (
                    -signed_delta if subtract else signed_delta
                ),
            ))
        for other in right.references:
            if (
                subtract
                and atom.kind in {"object", "object_view"}
                and other.kind in {"object", "object_view"}
                and atom.identity == other.identity
                and "object_view" in {atom.kind, other.kind}
            ):
                return UNKNOWN_SCALAR_REFERENCE_V1
            if (
                subtract
                and atom.kind == other.kind
                and atom.identity == other.identity
            ):
                scalars.add((atom.offset - other.offset) & 0xFFFF_FFFF)
            else:
                invalid = True
    if not subtract:
        for atom in right.references:
            for delta in left.scalars:
                signed_delta = (
                    delta if delta < 0x8000_0000 else delta - 0x1_0000_0000
                )
                if atom.kind == "object_view":
                    references.add(atom)
                    continue
                if atom.kind != "object" and signed_delta != 0:
                    invalid = True
                    continue
                references.add(replace(
                    atom,
                    offset=atom.offset + signed_delta,
                ))
    if invalid:
        return CONFLICT_REFERENCE_V1
    return finite_reference_value_v1(
        scalars=scalars, references=references,
        alternative_limit=limit,
    )


def _aligned_object_reference_v1(
    arguments: tuple[ReferenceValueV1, ...],
    catalog: ReferenceCatalogV1,
    *,
    alternative_limit: int | None = None,
) -> ReferenceValueV1 | None:
    limit = (
        catalog.alternative_limit
        if alternative_limit is None else alternative_limit
    )
    if len(arguments) != 2:
        return None
    for reference, mask_value in (arguments, arguments[::-1]):
        if (
            reference.kind != "finite"
            or reference.scalars
            or not reference.references
            or any(
                atom.kind not in {"object", "object_view"}
                for atom in reference.references
            )
            or mask_value.kind != "finite"
            or mask_value.references
            or len(mask_value.scalars) != 1
        ):
            continue
        mask = next(iter(mask_value.scalars))
        cleared = (~mask) & 0xFFFF_FFFF
        if cleared == 0 or cleared & (cleared + 1):
            continue
        prefix = f"aligned:{mask:08x}:"
        alignment = cleared + 1
        return finite_reference_value_v1(
            references=(
                (
                    atom
                    if atom.kind == "object_view" else
                    replace(
                        atom,
                        offset=atom.offset - (atom.offset % alignment),
                    )
                    if atom.identity.startswith(prefix)
                    else ReferenceAtomV1(
                        "object",
                        f"{prefix}{atom.identity}:{atom.offset}",
                        0,
                    )
                )
                for atom in reference.references
            ),
            alternative_limit=limit,
        )
    return None


def adjust_reference_by_constant_v1(
    value: ReferenceValueV1,
    delta: int,
    catalog: ReferenceCatalogV1,
    *,
    alternative_limit: int | None = None,
) -> ReferenceValueV1:
    limit = (
        catalog.alternative_limit
        if alternative_limit is None else alternative_limit
    )
    constant = finite_reference_value_v1(
        scalars=(abs(delta),), alternative_limit=limit
    )
    return _adjust_reference(
        value,
        constant,
        delta < 0,
        catalog,
        alternative_limit=limit,
    )


def _dynamic_stack_region_v1(
    transfer: _Transfer,
    node_index: int,
    base: ReferenceValueV1,
    catalog: ReferenceCatalogV1,
) -> ReferenceValueV1 | None:
    """Create the allocation-site object for a variable `sub esp, size`.

    The previous coordinate must not enter the object identity.  A loop would
    otherwise manufacture a recursively longer identity on every visit, so
    the alleged fixed point depended on worklist scheduling.  One object per
    captured-frame owner and transfer site is the conservative allocation-site
    abstraction: repeated executions may alias, but no possible alias is lost.
    """

    if (
        base.kind != "finite"
        or base.scalars
        or not base.references
        or any(
            atom.kind != "object"
            or captured_stack_owner_v1(atom.identity) is None
            for atom in base.references
        )
    ):
        return None
    return finite_reference_value_v1(
        references=(
            ReferenceAtomV1(
                "object",
                "dynamic_stack_region:"
                f"{captured_stack_owner_v1(atom.identity)}|"
                f"{transfer.identity}:{node_index}",
                0,
            )
            for atom in base.references
        ),
        alternative_limit=max(
            catalog.alternative_limit,
            STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
        ),
    )


def _predicate_value_v1(
    operation: str,
    arguments: tuple[ReferenceValueV1, ...],
    limit: int,
) -> ReferenceValueV1:
    if operation in {"eq", "eq_bool"} and len(arguments) == 2:
        left, right = arguments
        if left.kind == "finite" and right.kind == "finite":
            left_atoms = {("scalar", value) for value in left.scalars} | {
                ("reference", value) for value in left.references
            }
            right_atoms = {("scalar", value) for value in right.scalars} | {
                ("reference", value) for value in right.references
            }
            possibilities: set[int] = set()
            for lhs in left_atoms:
                for rhs in right_atoms:
                    left_value = lhs[1]
                    right_value = rhs[1]
                    if (
                        lhs[0] == rhs[0] == "reference"
                        and isinstance(left_value, ReferenceAtomV1)
                        and isinstance(right_value, ReferenceAtomV1)
                        and (
                            (
                                left_value.identity == right_value.identity
                                and "object_view" in {
                                    left_value.kind, right_value.kind
                                }
                            )
                            or (
                                left_value.identity != right_value.identity
                                and is_call_parameter_object_v1(
                                    left_value.identity
                                )
                                and is_call_parameter_object_v1(
                                    right_value.identity
                                )
                            )
                        )
                    ):
                        possibilities.update((0, 1))
                    else:
                        possibilities.add(int(lhs == rhs))
            return finite_reference_value_v1(
                scalars=possibilities, alternative_limit=limit
            )
    if operation == "ult32" and len(arguments) == 2 and all(
        value.kind == "finite" and not value.references for value in arguments
    ):
        return finite_reference_value_v1(
            scalars={
                int(left < right)
                for left in arguments[0].scalars
                for right in arguments[1].scalars
            },
            alternative_limit=limit,
        )
    if operation == "ult32" and len(arguments) == 2 and all(
        value.kind == "finite" and not value.scalars and value.references
        for value in arguments
    ):
        pairs = [
            (left, right)
            for left in arguments[0].references
            for right in arguments[1].references
        ]
        if all(
            left.kind in {"object", "object_view"}
            and right.kind in {"object", "object_view"}
            and left.identity == right.identity
            for left, right in pairs
        ):
            return finite_reference_value_v1(
                scalars=(
                    (0, 1)
                    if any(
                        "object_view" in {left.kind, right.kind}
                        for left, right in pairs
                    ) else {
                        int(left.offset < right.offset)
                        for left, right in pairs
                    }
                ),
                alternative_limit=limit,
            )
    if operation == "not" and len(arguments) == 1:
        value = arguments[0]
        if value.kind == "finite" and not value.references:
            return finite_reference_value_v1(
                scalars={int(not item) for item in value.scalars},
                alternative_limit=limit,
            )
    return finite_reference_value_v1(scalars=(0, 1))


def _branch_predicate_node_v1(
    transfer: _Transfer, node_index: int, desired: bool,
) -> tuple[int, bool]:
    """Resolve local flag/not forwarding to the predicate that produced it."""

    seen: set[int] = set()
    while node_index not in seen:
        seen.add(node_index)
        node = transfer.nodes[node_index]
        if node.op == "not" and len(node.args) == 1:
            node_index = node.args[0]
            desired = not desired
            continue
        if node.op == "flag" and node.immediate:
            setter = next((
                action for action in reversed(transfer.actions[:-1])
                if action.op == "set_flag" and action.aux == node.aux
            ), None)
            if setter is not None:
                node_index = setter.args[0]
                continue
        break
    return node_index, desired


def _branch_equality_subject_v1(
    transfer: _Transfer,
    values: tuple[ReferenceValueV1, ...],
    node_index: int,
) -> tuple[int, ReferenceValueV1] | None:
    """Recognize the canonical compare/test forms emitted for x86 equality."""

    node = transfer.nodes[node_index]
    if node.op not in {"eq", "eq_bool"} or len(node.args) != 2:
        return None
    left_index, right_index = node.args
    left = transfer.nodes[left_index]
    right = transfer.nodes[right_index]

    def register(index: int) -> int | None:
        candidate = transfer.nodes[index]
        return (
            candidate.aux
            if candidate.op == "reg" and candidate.immediate else None
        )

    def constant(index: int) -> ReferenceValueV1 | None:
        return values[index] if transfer.nodes[index].op == "const" else None

    # Direct equality, including comparisons against callback sentinels.
    for register_index, constant_index in (
        (left_index, right_index), (right_index, left_index),
    ):
        register_id = register(register_index)
        expected = constant(constant_index)
        if register_id is not None and expected is not None:
            return register_id, expected

    # x86 CMP is represented as eq(sub32(lhs, rhs), 0).
    for difference_index, zero_index in (
        (left_index, right_index), (right_index, left_index),
    ):
        zero = constant(zero_index)
        difference = transfer.nodes[difference_index]
        if (
            zero is None
            or zero.kind != "finite"
            or zero.references
            or zero.scalars != frozenset({0})
            or difference.op != "sub32"
            or len(difference.args) != 2
        ):
            continue
        lhs, rhs = difference.args
        for register_index, constant_index in ((lhs, rhs), (rhs, lhs)):
            register_id = register(register_index)
            expected = constant(constant_index)
            if register_id is not None and expected is not None:
                return register_id, expected

    # x86 TEST reg,reg is represented as eq(and32(reg, reg), 0).
    for mask_index, zero_index in (
        (left_index, right_index), (right_index, left_index),
    ):
        zero = constant(zero_index)
        mask = transfer.nodes[mask_index]
        if (
            zero is None
            or zero.kind != "finite"
            or zero.references
            or zero.scalars != frozenset({0})
            or mask.op != "and32"
            or len(mask.args) != 2
            or mask.args[0] != mask.args[1]
        ):
            continue
        register_id = register(mask.args[0])
        if register_id is not None:
            return register_id, zero
    return None


def _masked_register_subject_v1(
    transfer: _Transfer, node_index: int,
) -> tuple[int, int] | None:
    node = transfer.nodes[node_index]
    if node.op == "reg" and node.immediate:
        return node.aux, 0xFFFF_FFFF
    if node.op != "and32" or len(node.args) != 2:
        return None
    if node.args[0] == node.args[1]:
        register = transfer.nodes[node.args[0]]
        if register.op == "reg" and register.immediate:
            return register.aux, 0xFFFF_FFFF
    for register_index, mask_index in (
        (node.args[0], node.args[1]), (node.args[1], node.args[0]),
    ):
        register = transfer.nodes[register_index]
        mask = transfer.nodes[mask_index]
        if (
            register.op == "reg" and register.immediate
            and mask.op == "const"
        ):
            return register.aux, mask.immediate & 0xFFFF_FFFF
    return None


def _scalar_flag_relation_v1(
    transfer: _Transfer, node_index: int,
) -> ScalarFlagRelationV1 | None:
    node = transfer.nodes[node_index]
    if node.op == "ult32" and len(node.args) == 2:
        subject = _masked_register_subject_v1(transfer, node.args[0])
        constant = transfer.nodes[node.args[1]]
        if subject is not None and constant.op == "const":
            return ScalarFlagRelationV1(
                *subject, "ult", constant.immediate & 0xFFFF_FFFF
            )
    if node.op != "eq" or len(node.args) != 2:
        return None
    for masked_index, zero_index in (
        (node.args[0], node.args[1]), (node.args[1], node.args[0]),
    ):
        subject = _masked_register_subject_v1(transfer, masked_index)
        zero = transfer.nodes[zero_index]
        if subject is not None and zero.op == "const" and zero.immediate == 0:
            return ScalarFlagRelationV1(*subject, "eq", 0)
    for difference_index, zero_index in (
        (node.args[0], node.args[1]), (node.args[1], node.args[0]),
    ):
        difference = transfer.nodes[difference_index]
        zero = transfer.nodes[zero_index]
        if difference.op == "and32" and len(difference.args) == 2:
            masked_difference = next((
                transfer.nodes[index]
                for index in difference.args
                if transfer.nodes[index].op == "sub32"
            ), None)
            mask = next((
                transfer.nodes[index]
                for index in difference.args
                if transfer.nodes[index].op == "const"
            ), None)
            if masked_difference is not None and mask is not None:
                difference = masked_difference
        if (
            difference.op != "sub32" or len(difference.args) != 2
            or zero.op != "const" or zero.immediate != 0
        ):
            continue
        subject = _masked_register_subject_v1(
            transfer, difference.args[0]
        )
        constant = transfer.nodes[difference.args[1]]
        if subject is not None and constant.op == "const":
            return ScalarFlagRelationV1(
                *subject, "eq", constant.immediate & 0xFFFF_FFFF
            )
    return None


def _branch_flag_relation_v1(
    transfer: _Transfer,
    state: ReferenceStateV1,
    node_index: int,
    desired: bool,
) -> tuple[ScalarFlagRelationV1, bool] | None:
    candidate = transfer.nodes[node_index]
    if candidate.op == "not" and len(candidate.args) == 1:
        return _branch_flag_relation_v1(
            transfer, state, candidate.args[0], not desired
        )
    if candidate.op != "flag" or not candidate.immediate:
        return None
    relation = state.flag_relations[candidate.aux]
    return None if relation is None else (relation, desired)


def _branch_scalar_constraint_v1(
    transfer: _Transfer,
    state: ReferenceStateV1,
    node_index: int,
    desired: bool,
) -> tuple[tuple[int, int], frozenset[int]] | None:
    """Recover a bounded scalar meet from checked x86 flag relations."""

    node = transfer.nodes[node_index]

    simple = _branch_flag_relation_v1(
        transfer, state, node_index, desired
    )
    if simple is not None:
        relation, expected = simple
        if (
            relation.relation == "eq"
            and expected
            and relation.constant < BOUNDED_SCALAR_ALTERNATIVE_LIMIT_V1
        ):
            allowed = frozenset({relation.constant & relation.mask})
        elif (
            relation.relation == "ult" and expected
            and relation.constant <= BOUNDED_SCALAR_ALTERNATIVE_LIMIT_V1
        ):
            allowed = frozenset(range(relation.constant))
        else:
            return None
        return (relation.register_index, relation.mask), allowed

    # Unsigned-above is serialized as !CF && !ZF.  Its false successor is the
    # bounded <= side used by compiler-generated switch tables.
    if node.op == "and_bool" and len(node.args) == 2 and not desired:
        relations = [
            _branch_flag_relation_v1(transfer, state, index, True)
            for index in node.args
        ]
        if any(relation is None for relation in relations):
            return None
        assert all(relation is not None for relation in relations)
        decoded_pairs = [relation for relation in relations if relation is not None]
        if any(expected for _relation, expected in decoded_pairs):
            return None
        decoded = [relation for relation, _expected in decoded_pairs]
        less = next((row for row in decoded if row.relation == "ult"), None)
        equal = next((row for row in decoded if row.relation == "eq"), None)
        if (
            less is None or equal is None
            or less.register_index != equal.register_index
            or less.mask != equal.mask
            or less.constant != equal.constant
            or less.constant >= BOUNDED_SCALAR_ALTERNATIVE_LIMIT_V1
        ):
            return None
        return (
            (less.register_index, less.mask),
            frozenset(range(less.constant + 1)),
        )
    return None


def _filter_reference_equality_v1(
    value: ReferenceValueV1,
    expected: ReferenceValueV1,
    *, equal: bool,
    alternative_limit: int,
) -> ReferenceValueV1 | None:
    if value.kind != "finite" or expected.kind != "finite":
        return value
    expected_scalars = expected.scalars
    expected_references = expected.references
    scalars = frozenset(
        item for item in value.scalars
        if ((item in expected_scalars) == equal)
    )
    references: set[ReferenceAtomV1] = set()
    for item in value.references:
        matching_expected = {
            candidate for candidate in expected_references
            if (
                item.kind == "object_view"
                and candidate.kind in {"object", "object_view"}
                and item.identity == candidate.identity
            )
        }
        if matching_expected:
            references.update(matching_expected if equal else (item,))
        elif ((item in expected_references) == equal):
            references.add(item)
    if not scalars and not references:
        return None
    return finite_reference_value_v1(
        scalars=scalars,
        references=frozenset(references),
        alternative_limit=alternative_limit,
    )


def _drop_narrowed_allocation_alternatives_v1(
    state: ReferenceStateV1,
    removed: frozenset[str],
) -> ReferenceStateV1:
    """Forget nullable allocation alternatives disproved by a branch meet."""

    if not removed:
        return state
    values = (
        *state.registers,
        *state.call_registers,
        *state.memory.values(),
        *state.callback_registry.values(),
        *state.relational_object_bindings.values(),
    )
    materialized = (
        *state.memory.keys(),
        *state.written_memory_keys,
        *state.invalidated_memory_ranges,
        *state.effect_invalidated_memory_ranges,
    )
    disproved = {
        identity for identity in removed
        if not any(
            atom.kind in {"object", "object_view"}
            and atom.identity == identity
            for value in values
            for atom in value.references
        )
        and not any(
            kind == "object" and owner == identity
            for kind, owner, _start, _extent in materialized
        )
    }
    if not disproved:
        return state
    return replace(
        state,
        possible_allocation_identities=(
            state.possible_allocation_identities - disproved
        ),
    )


def refine_reference_state_for_branch_v1(
    transfer: _Transfer,
    state: ReferenceStateV1,
    values: tuple[ReferenceValueV1, ...],
    *,
    taken: bool,
    alternative_limit: int = REFERENCE_ALTERNATIVE_LIMIT_V1,
) -> ReferenceStateV1 | None:
    """Meet a successor with an exact local equality branch constraint.

    This is deliberately limited to relations present in the serialized
    transfer.  It neither consults disassembly nor invents target-specific
    facts, and an unrecognized predicate simply leaves the state unchanged.
    """

    terminator = transfer.actions[-1]
    if terminator.op != "outcome_branch":
        return state
    constraint = _branch_scalar_constraint_v1(
        transfer, state, terminator.args[0], taken
    )
    constrained_state = state
    if constraint is not None:
        key, allowed = constraint
        previous = state.scalar_constraints.get(key)
        allowed = allowed if previous is None else previous & allowed
        if not allowed:
            return None
        constraints = dict(state.scalar_constraints)
        constraints[key] = allowed
        constrained_state = replace(state, scalar_constraints=constraints)

    carried = _branch_flag_relation_v1(
        transfer, state, terminator.args[0], taken
    )
    if carried is not None:
        relation, equal = carried
        if (
            relation.relation == "eq"
            and relation.mask == 0xFFFF_FFFF
            and relation.constant == 0
        ):
            narrowed = _filter_reference_equality_v1(
                constrained_state.registers[relation.register_index],
                finite_reference_value_v1(
                    scalars=(relation.constant,),
                    alternative_limit=alternative_limit,
                ),
                equal=equal,
                alternative_limit=alternative_limit,
            )
            if narrowed is None:
                return None
            registers = list(constrained_state.registers)
            removed_allocations = frozenset(
                atom.identity
                for atom in registers[relation.register_index].references
                if atom.kind in {"object", "object_view"}
                and atom.identity.startswith("allocation:")
                and atom not in narrowed.references
            )
            registers[relation.register_index] = narrowed
            constrained_state = replace(
                constrained_state, registers=tuple(registers)
            )
            constrained_state = _drop_narrowed_allocation_alternatives_v1(
                constrained_state, removed_allocations
            )

    predicate_index, desired = _branch_predicate_node_v1(
        transfer, terminator.args[0], taken
    )
    subject = _branch_equality_subject_v1(
        transfer, values, predicate_index
    )
    if subject is None:
        return constrained_state
    register_index, expected = subject
    narrowed = _filter_reference_equality_v1(
        constrained_state.registers[register_index],
        expected,
        equal=desired,
        alternative_limit=alternative_limit,
    )
    if narrowed is None:
        return None
    registers = list(constrained_state.registers)
    removed_allocations = frozenset(
        atom.identity
        for atom in registers[register_index].references
        if atom.kind in {"object", "object_view"}
        and atom.identity.startswith("allocation:")
        and atom not in narrowed.references
    )
    registers[register_index] = narrowed
    return _drop_narrowed_allocation_alternatives_v1(
        replace(constrained_state, registers=tuple(registers)),
        removed_allocations,
    )
