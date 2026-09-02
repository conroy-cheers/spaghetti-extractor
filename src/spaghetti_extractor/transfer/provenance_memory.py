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
    _EXACT_SCALAR_OPERATIONS_V1,
    _PREDICATE_RESULTS_V1,
    _REFERENCE_PRESERVING_BINARY_V1,
    _UNKNOWN_WORD_OPERATIONS_V1,
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

def _memory_keys(
    value: ReferenceValueV1, width: int,
) -> tuple[tuple[str, str, int, int], ...] | None:
    if value.kind != "finite":
        return None
    keys = [
        ("object", atom.identity, atom.offset, width)
        for atom in value.references if atom.kind == "object"
    ]
    keys.extend(("absolute", "", scalar, width) for scalar in value.scalars)
    return tuple(keys) if len(keys) == len(value.references) + len(value.scalars) else None


def _ranges_overlap(left_start: int, left_end: int, right_start: int, right_end: int) -> bool:
    return left_start < right_end and right_start < left_end


def _memory_key_invalidated_v1(
    state: ReferenceStateV1,
    key: tuple[str, str, int, int],
    catalog: ReferenceCatalogV1,
) -> bool:
    if key[0] == "object" and catalog.object_is_immutable(key[1]):
        return False
    if state.all_memory_invalidated:
        return True
    kind, identity, offset, width = key
    return any(
        range_kind == kind
        and range_identity == identity
        and _ranges_overlap(offset, offset + width, start, end)
        for range_kind, range_identity, start, end
        in state.invalidated_memory_ranges
    )


def _memory_value_v1(
    state: ReferenceStateV1,
    key: tuple[str, str, int, int],
    catalog: ReferenceCatalogV1,
    _resolving: frozenset[tuple[str, str, int, int]] = frozenset(),
) -> ReferenceValueV1:
    explicit = state.memory.get(key)
    if explicit is not None:
        return explicit
    if _memory_key_invalidated_v1(state, key, catalog):
        return UNKNOWN_SCALAR_REFERENCE_V1
    parameter_owner = (
        call_parameter_owner_v1(key[1]) if key[0] == "object" else None
    )
    frame_backed = (
        key[0] == "object"
        and key[2] >= 4
        and captured_stack_owner_v1(key[1]) == key[1]
        and key[1] in state.relational_object_bindings
    )
    if parameter_owner is not None or frame_backed:
        # Resolve a sparse relational cell through the caller objects carried
        # by this exact abstract state.  Self-references are rebased to the
        # parameter identity so the resulting function summary remains
        # independent of a particular caller frame.
        if key in _resolving:
            return CONFLICT_REFERENCE_V1
        binding_identity = key[1] if parameter_owner is None else parameter_owner
        binding = state.relational_object_bindings.get(binding_identity)
        if (
            binding is None
            or binding.kind != "finite"
            or binding.scalars
            or not binding.references
            or any(atom.kind != "object" for atom in binding.references)
        ):
            return CONFLICT_REFERENCE_V1
        values: list[ReferenceValueV1] = []
        for atom in binding.references:
            actual = (
                atom if parameter_owner is None
                else instantiate_call_parameter_identity_v1(key[1], atom)
            )
            if actual is None:
                return CONFLICT_REFERENCE_V1
            actual_key = (
                "object", actual.identity, actual.offset + key[2], key[3]
            )
            value = _memory_value_v1(
                state, actual_key, catalog, _resolving | {key}
            )
            if value.kind == "finite":
                value = finite_reference_value_v1(
                    scalars=value.scalars,
                    references=(
                        ReferenceAtomV1(
                            "object", key[1], reference.offset - actual.offset
                        )
                        if reference.kind == "object"
                        and reference.identity == actual.identity
                        else reference
                        for reference in value.references
                    ),
                    alternative_limit=max(
                        catalog.alternative_limit,
                        STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
                    ),
                )
            values.append(value)
        result = values[0]
        for value in values[1:]:
            result = join_reference_values_v1(
                result, value,
                alternative_limit=catalog.alternative_limit,
            )
        return result
    return catalog.initial_memory.get(key, UNKNOWN_SCALAR_REFERENCE_V1)


def _external_memory_copy_words_v1(
    relation: ExternalMemoryCopyV1,
    arguments: tuple[ReferenceValueV1, ...],
    state: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
) -> tuple[
    tuple[tuple[str, str, int, int], ReferenceValueV1], ...
] | None:
    """Project exact reference cells through one checked byte copy.

    The write footprint remains the authority for the destination mutation.
    This helper adds precision only when destination, source, and extent each
    have one exact value.  Unknown shapes simply retain the ordinary
    invalidation semantics.
    """

    indexes = (
        relation.destination_argument,
        relation.source_argument,
        relation.size_argument,
    )
    if any(index >= len(arguments) for index in indexes):
        return None
    destination, source, size = (arguments[index] for index in indexes)
    if (
        destination.kind != "finite"
        or destination.scalars
        or len(destination.references) != 1
        or next(iter(destination.references)).kind != "object"
        or source.kind != "finite"
        or source.scalars
        or len(source.references) != 1
        or next(iter(source.references)).kind != "object"
        or size.kind != "finite"
        or size.references
        or len(size.scalars) != 1
    ):
        return None
    extent = next(iter(size.scalars)) * relation.scale
    destination_atom = next(iter(destination.references))
    source_atom = next(iter(source.references))
    available = set(state.memory) | set(catalog.initial_memory)
    copied: list[tuple[tuple[str, str, int, int], ReferenceValueV1]] = []
    for key in sorted(available):
        kind, identity, offset, width = key
        relative = offset - source_atom.offset
        if (
            kind != "object"
            or identity != source_atom.identity
            or relative < 0
            or relative + width > extent
        ):
            continue
        value = _memory_value_v1(state, key, catalog)
        if value.kind != "finite":
            continue
        copied.append((
            (
                "object",
                destination_atom.identity,
                destination_atom.offset + relative,
                width,
            ),
            value,
        ))
    return tuple(copied)


def _callback_source_value_v1(
    callback: ExternalCallbackRuleV1,
    arguments: tuple[ReferenceValueV1, ...],
    state: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
) -> ReferenceValueV1:
    if callback.source_argument >= len(arguments):
        return UNKNOWN_SCALAR_REFERENCE_V1
    source = arguments[callback.source_argument]
    if callback.source_kind == "argument_word":
        return source
    address = adjust_reference_by_constant_v1(
        source, callback.source_offset, catalog
    )
    keys = _memory_keys(address, 4)
    if keys is None:
        return UNKNOWN_SCALAR_REFERENCE_V1
    result = BOTTOM_REFERENCE_V1
    for key in keys:
        result = join_reference_values_v1(
            result,
            _memory_value_v1(state, key, catalog),
            alternative_limit=catalog.alternative_limit,
        )
    return result


def call_argument_values_v1(
    call: _Call,
    word: Callable[[int], ReferenceValueV1],
    state: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
    *,
    argument_words: int,
    base_offset: int = 0,
) -> tuple[ReferenceValueV1, ...]:
    if call.argument_nodes:
        return tuple(word(index) for index in call.argument_nodes)
    if argument_words < 0 or base_offset < 0 or base_offset % 4:
        raise ValueError("external-call argument frame is invalid")
    maximum = max(
        (offset - base_offset) // 4
        for offset, _width, _node in call.stack_inputs
        if offset >= base_offset and (offset - base_offset) % 4 == 0
    ) if any(
        offset >= base_offset and (offset - base_offset) % 4 == 0
        for offset, _width, _node in call.stack_inputs
    ) else -1
    count = max(argument_words, maximum + 1)
    if count == 0:
        return ()
    values: list[ReferenceValueV1 | None] = [None] * count
    for offset, width, node in call.stack_inputs:
        relative = offset - base_offset
        if width != 4 or relative < 0 or relative % 4:
            continue
        index = relative // 4
        if index < count:
            values[index] = word(node)
    stack = word(call.register_nodes[7])
    for index, value in enumerate(values):
        if value is not None:
            continue
        address = adjust_reference_by_constant_v1(
            stack, base_offset + index * 4, catalog
        )
        keys = _memory_keys(address, 4)
        if keys is None:
            values[index] = UNKNOWN_SCALAR_REFERENCE_V1
            continue
        result = BOTTOM_REFERENCE_V1
        for key in keys:
            result = join_reference_values_v1(
                result,
                _memory_value_v1(state, key, catalog),
                alternative_limit=catalog.alternative_limit,
            )
        values[index] = result
    return tuple(
        value if value is not None else UNKNOWN_SCALAR_REFERENCE_V1
        for value in values
    )


def _static_loader_name_v1(
    value: ReferenceValueV1,
    catalog: ReferenceCatalogV1,
    *,
    wide: bool = False,
) -> str | None:
    """Decode one exact loader-observed name from immutable image bytes."""

    if value.kind != "finite" or value.scalars or not value.references:
        return None
    names: set[str] = set()
    terminator = b"\0\0" if wide else b"\0"
    alignment = 2 if wide else 1
    for atom in value.references:
        if atom.kind != "object" or atom.offset < 0:
            return None
        data = catalog.object_bytes.get(atom.identity)
        if data is None or atom.offset >= len(data):
            return None
        suffix = data[atom.offset:atom.offset + 4096]
        if wide:
            end = next(
                (
                    index for index in range(0, len(suffix) - 1, alignment)
                    if suffix[index:index + 2] == terminator
                ),
                -1,
            )
            encoding = "utf-16-le"
        else:
            end = suffix.find(terminator)
            encoding = "ascii"
        if end < 0:
            return None
        try:
            names.add(suffix[:end].decode(encoding))
        except UnicodeDecodeError:
            return None
    return next(iter(names)) if len(names) == 1 else None


def _module_handle_result_v1(
    rule: ExternalCallRuleV1,
    arguments: tuple[ReferenceValueV1, ...],
    catalog: ReferenceCatalogV1,
) -> ReferenceValueV1:
    argument_index = rule.module_handle_name_argument
    if argument_index is None or argument_index >= len(arguments):
        return UNKNOWN_SCALAR_REFERENCE_V1
    argument = arguments[argument_index]
    if (
        rule.module_handle_nullable_name
        and argument.kind == "finite"
        and argument.scalars == frozenset({0})
        and not argument.references
    ):
        module_name = "<process-image>"
    else:
        module_name = _static_loader_name_v1(
            argument, catalog, wide=rule.module_handle_wide_name
        )
        if module_name is None:
            return UNKNOWN_SCALAR_REFERENCE_V1
        module_name = module_name.lower()
    return finite_reference_value_v1(
        scalars=(0,),
        references=(ReferenceAtomV1("loader_module", module_name),),
        alternative_limit=catalog.alternative_limit,
    )


def _dynamic_export_result_v1(
    rule: ExternalCallRuleV1,
    arguments: tuple[ReferenceValueV1, ...],
    catalog: ReferenceCatalogV1,
) -> ReferenceValueV1:
    handle_index = rule.dynamic_export_handle_argument
    name_index = rule.dynamic_export_name_argument
    if (
        handle_index is None
        or name_index is None
        or handle_index >= len(arguments)
        or name_index >= len(arguments)
    ):
        return UNKNOWN_SCALAR_REFERENCE_V1
    handles = arguments[handle_index]
    if (
        handles.kind != "finite"
        or handles.scalars
        or not handles.references
        or any(
            atom.kind != "loader_module" or atom.offset != 0
            for atom in handles.references
        )
    ):
        return UNKNOWN_SCALAR_REFERENCE_V1
    name_value = arguments[name_index]
    export_identity: str | None
    if (
        name_value.kind == "finite"
        and not name_value.references
        and len(name_value.scalars) == 1
        and 0 < next(iter(name_value.scalars)) <= 0xFFFF
    ):
        export_identity = f"ordinal:{next(iter(name_value.scalars))}"
    else:
        export_identity = _static_loader_name_v1(name_value, catalog)
    if export_identity is None:
        return UNKNOWN_SCALAR_REFERENCE_V1
    targets: set[ReferenceAtomV1] = set()
    for handle in handles.references:
        target = rule.dynamic_export_results.get(
            (handle.identity, export_identity)
        )
        if target is None:
            return UNKNOWN_SCALAR_REFERENCE_V1
        targets.add(ReferenceAtomV1("external_function", target))
    return finite_reference_value_v1(
        scalars=(0,), references=targets,
        alternative_limit=catalog.alternative_limit,
    )


def _write_range_v1(
    footprint: ExternalMemoryWriteV1,
    arguments: tuple[ReferenceValueV1, ...],
) -> frozenset[tuple[str, str, int, int]] | None:
    if footprint.base_argument >= len(arguments):
        return None
    base = arguments[footprint.base_argument]
    if base.kind != "finite":
        return None
    extent: int | None
    if footprint.fixed_bytes is not None:
        extent = footprint.fixed_bytes
    else:
        assert footprint.size_argument is not None
        if footprint.size_argument >= len(arguments):
            extent = None
        else:
            size = arguments[footprint.size_argument]
            extent = (
                max(size.scalars) * footprint.scale
                if size.kind == "finite"
                and not size.references
                and size.scalars
                else None
            )
    if extent is not None and (extent < 0 or extent > 0xFFFF_FFFF):
        return None
    ranges: set[tuple[str, str, int, int]] = set()
    for atom in base.references:
        if atom.kind not in {"object", "object_view"}:
            return None
        if (
            footprint.authority_selector is not None
            and atom.identity != footprint.authority_selector
        ):
            return None
        if atom.kind == "object_view":
            ranges.add((
                "object", atom.identity, -(1 << 63), (1 << 63)
            ))
            continue
        start = atom.offset + footprint.offset
        # If only the extent is unknown, object identity remains authoritative.
        # Conservatively invalidate the entire suffix of that object without
        # destroying provenance for unrelated objects.
        ranges.add((
            "object",
            atom.identity,
            start,
            (1 << 63) if extent is None else start + extent,
        ))
    for scalar in base.scalars:
        if scalar == 0:
            continue
        if extent is None:
            return None
        start = scalar + footprint.offset
        ranges.add(("absolute", "", start, start + extent))
    return frozenset(ranges)


def _callback_instance_keys_v1(
    callback: ExternalCallbackRuleV1,
    arguments: tuple[ReferenceValueV1, ...],
) -> tuple[str, ...] | None:
    if callback.instance_kind in {"singleton", "registration_sequence"}:
        return (callback.protocol_id,)
    if callback.instance_argument is None:
        return None
    if callback.instance_argument >= len(arguments):
        return None
    instance = arguments[callback.instance_argument]
    if instance.kind != "finite":
        return None
    if callback.instance_kind == "provider_resource":
        keys = [
            f"{callback.protocol_id}:provider-resource:scalar:{value:08x}"
            for value in sorted(instance.scalars)
        ]
        keys.extend(
            f"{callback.protocol_id}:provider-resource:"
            f"{atom.kind}:{atom.identity}:{atom.offset}"
            for atom in sorted(instance.references)
        )
        return tuple(keys) if keys else None
    if instance.references:
        return None
    return tuple(
        f"{callback.protocol_id}:argument:{value:08x}"
        for value in sorted(instance.scalars)
    )


def _interpret_reference_node_v1(
    node: _Node,
    arguments: tuple[ReferenceValueV1, ...],
    initial: ReferenceStateV1,
    current: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
    *,
    alternative_limit: int | None = None,
) -> ReferenceValueV1:
    limit = (
        catalog.alternative_limit
        if alternative_limit is None else alternative_limit
    )
    expression_operation_v2(node)
    operation = node.op
    if operation == "const":
        result = catalog.classify_scalar(node.immediate)
    elif operation == "reg":
        result = (current if node.immediate else initial).registers[node.aux]
    elif operation == "flag":
        result = (current if node.immediate else initial).flags[node.aux]
    elif operation == "fs_base":
        result = UNKNOWN_SCALAR_REFERENCE_V1
    elif operation == "undefined_bv":
        result = UNKNOWN_SCALAR_REFERENCE_V1
    elif operation == "call_response":
        result = current.call_registers[node.aux]
    elif operation == "undefined_flag":
        result = finite_reference_value_v1(scalars=(0, 1))
    elif operation == "call_flag":
        result = current.call_flags[node.aux]
    elif operation in {"true", "false"}:
        result = finite_reference_value_v1(scalars=(operation == "true",))
    elif operation == "load":
        keys = _memory_keys(arguments[0], node.aux)
        result = UNKNOWN_SCALAR_REFERENCE_V1
        if keys is not None:
            result = BOTTOM_REFERENCE_V1
            for key in keys:
                result = join_reference_values_v1(
                    result,
                    _memory_value_v1(current, key, catalog),
                    alternative_limit=limit,
                )
    elif operation in _REFERENCE_PRESERVING_BINARY_V1:
        result = _adjust_reference(
            arguments[0],
            arguments[1],
            operation == "sub32",
            catalog,
            alternative_limit=limit,
        )
    elif operation == "ite":
        result = join_reference_values_v1(
            arguments[1], arguments[2],
            alternative_limit=limit,
        )
    elif operation in _PREDICATE_RESULTS_V1:
        result = _predicate_value_v1(
            operation, arguments, limit
        )
    elif operation in _EXACT_SCALAR_OPERATIONS_V1:
        aligned = (
            _aligned_object_reference_v1(
                arguments, catalog, alternative_limit=limit
            )
            if operation == "and32" else None
        )
        result = aligned or _scalar_product(
            arguments, operation, limit
        )
    elif operation in _UNKNOWN_WORD_OPERATIONS_V1:
        result = UNKNOWN_SCALAR_REFERENCE_V1
    else:  # Registry and these sets must stay total together.
        raise AssertionError(f"reference handler absent for {operation!r}")
    return result


def interpret_reference_expressions_v1(
    transfer: _Transfer,
    state: ReferenceStateV1,
    catalog: ReferenceCatalogV1,
) -> tuple[ReferenceValueV1, ...]:
    values: list[ReferenceValueV1] = []
    for node in transfer.nodes:
        values.append(_interpret_reference_node_v1(
            node,
            tuple(values[index] for index in node.args),
            state,
            state,
            catalog,
        ))
    return tuple(values)
