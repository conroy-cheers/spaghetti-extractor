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


@dataclass(frozen=True, order=True, slots=True)

class ReferenceAtomV1:
    kind: str
    identity: str
    offset: int = 0

    def __post_init__(self) -> None:
        if self.kind not in {
            "object", "object_view", "guest_code", "external_function",
            "loader_module",
        }:
            raise ValueError(f"unknown reference atom kind {self.kind!r}")
        if self.kind == "object_view" and self.offset != 0:
            raise ValueError("unknown-interior object views use zero offset")


@cache
def captured_stack_owner_v1(identity: str) -> str | None:
    """Return the canonical captured frame owning a derived object."""

    if identity.startswith("captured_stack_frame:"):
        return identity
    if identity.startswith("aligned:"):
        _kind, _mask, derived = identity.split(":", 2)
        base_identity, _offset = derived.rsplit(":", 1)
        return captured_stack_owner_v1(base_identity)
    if identity.startswith("dynamic_stack_region:"):
        encoded_owner, separator, _allocation = identity.removeprefix(
            "dynamic_stack_region:"
        ).partition("|")
        if not separator:
            return None
        return captured_stack_owner_v1(encoded_owner)
    return None


@cache
def is_call_parameter_object_v1(identity: str) -> bool:
    """Recognize an analysis-local, relational call-parameter object."""

    return call_parameter_owner_v1(identity) is not None


@cache
def _aligned_object_identity_v1(
    identity: str,
) -> tuple[str, str, int] | None:
    if not identity.startswith("aligned:"):
        return None
    _aligned, mask, derived = identity.split(":", 2)
    base_identity, offset = derived.rsplit(":", 1)
    return mask, base_identity, int(offset)


@cache
def call_parameter_owner_v1(identity: str) -> str | None:
    """Return the relational parameter underlying a derived object."""

    if identity.startswith(CALL_PARAMETER_OBJECT_PREFIX_V1):
        return identity
    aligned = _aligned_object_identity_v1(identity)
    return None if aligned is None else call_parameter_owner_v1(aligned[1])


@cache
def instantiate_call_parameter_identity_v1(
    identity: str, actual: ReferenceAtomV1,
) -> ReferenceAtomV1 | None:
    """Substitute one exact object into a parameter-derived identity."""

    owner = call_parameter_owner_v1(identity)
    if owner is None or actual.kind != "object":
        return None

    def instantiate(value: str) -> tuple[str, int] | None:
        if value == owner:
            return actual.identity, actual.offset
        aligned = _aligned_object_identity_v1(value)
        if aligned is None:
            return None
        mask, base_identity, base_offset = aligned
        base = instantiate(base_identity)
        if base is None:
            return None
        return f"aligned:{mask}:{base[0]}:{base[1] + base_offset}", 0

    result = instantiate(identity)
    return None if result is None else ReferenceAtomV1(
        "object", result[0], result[1]
    )


@dataclass(frozen=True, slots=True)
class ReferenceValueV1:
    kind: str
    scalars: frozenset[int] = frozenset()
    references: frozenset[ReferenceAtomV1] = frozenset()

    def __post_init__(self) -> None:
        if self.kind not in {
            "bottom", "finite", "unknown_scalar", "conflict",
        }:
            raise ValueError(f"unknown reference value kind {self.kind!r}")
        if self.kind != "finite" and (self.scalars or self.references):
            raise ValueError("only finite reference values may carry alternatives")

    def payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "scalars": sorted(self.scalars),
            "references": [
                {"kind": row.kind, "identity": row.identity, "offset": row.offset}
                for row in sorted(self.references)
            ],
        }


BOTTOM_REFERENCE_V1 = ReferenceValueV1("bottom")
UNKNOWN_SCALAR_REFERENCE_V1 = ReferenceValueV1("unknown_scalar")
CONFLICT_REFERENCE_V1 = ReferenceValueV1("conflict")


def finite_reference_value_v1(
    *, scalars: Iterable[int] = (), references: Iterable[ReferenceAtomV1] = (),
    alternative_limit: int = REFERENCE_ALTERNATIVE_LIMIT_V1,
) -> ReferenceValueV1:
    exact_scalars = frozenset(value & 0xFFFF_FFFF for value in scalars)
    exact_references = frozenset(references)
    return _interned_finite_reference_value_v1(
        exact_scalars, exact_references, alternative_limit
    )


@cache
def _interned_finite_reference_value_v1(
    exact_scalars: frozenset[int],
    exact_references: frozenset[ReferenceAtomV1],
    alternative_limit: int,
) -> ReferenceValueV1:
    """Return one immutable representative for a canonical finite value."""

    existing_views = {
        reference.identity for reference in exact_references
        if reference.kind == "object_view"
    }
    if existing_views:
        exact_references = frozenset({
            reference for reference in exact_references
            if reference.kind not in {"object", "object_view"}
        } | {
            ReferenceAtomV1("object_view", reference.identity)
            for reference in exact_references
            if reference.kind in {"object", "object_view"}
        })
    if not exact_scalars and not exact_references:
        return BOTTOM_REFERENCE_V1
    if len(exact_scalars) + len(exact_references) > alternative_limit:
        collapsed = {
            reference for reference in exact_references
            if reference.kind not in {"object", "object_view"}
        }
        collapsed.update(
            ReferenceAtomV1("object_view", identity)
            for identity in {
                reference.identity for reference in exact_references
                if reference.kind in {"object", "object_view"}
            }
        )
        if len(exact_scalars) + len(collapsed) > alternative_limit:
            return CONFLICT_REFERENCE_V1
        exact_references = frozenset(collapsed)
    return ReferenceValueV1("finite", exact_scalars, exact_references)


def join_reference_values_v1(
    left: ReferenceValueV1,
    right: ReferenceValueV1,
    *, alternative_limit: int = REFERENCE_ALTERNATIVE_LIMIT_V1,
) -> ReferenceValueV1:
    if left.kind == "bottom":
        return right
    if right.kind == "bottom":
        return left
    if left.kind == "conflict" or right.kind == "conflict":
        return CONFLICT_REFERENCE_V1
    if left.kind == "unknown_scalar" or right.kind == "unknown_scalar":
        other = right if left.kind == "unknown_scalar" else left
        return (
            UNKNOWN_SCALAR_REFERENCE_V1
            if other.kind == "unknown_scalar"
            or (other.kind == "finite" and not other.references)
            else CONFLICT_REFERENCE_V1
        )
    return finite_reference_value_v1(
        scalars=left.scalars | right.scalars,
        references=left.references | right.references,
        alternative_limit=alternative_limit,
    )


@dataclass(frozen=True, order=True, slots=True)
class ObjectRangeV1:
    identity: str
    address: int
    extent: int
    writable: bool = True

    def contains(self, address: int) -> bool:
        return self.address <= address < self.address + self.extent


@dataclass(frozen=True, slots=True)
class ExternalMemoryWriteV1:
    base_argument: int
    offset: int
    fixed_bytes: int | None = None
    size_argument: int | None = None
    scale: int = 1
    authority_selector: str | None = None

    def __post_init__(self) -> None:
        if self.base_argument < 0:
            raise ValueError("external write footprint arguments are invalid")
        if (self.fixed_bytes is None) == (self.size_argument is None):
            raise ValueError("external write footprint size is ambiguous")
        if self.fixed_bytes is not None and self.fixed_bytes < 0:
            raise ValueError("external fixed write extent is invalid")
        if self.size_argument is not None and self.size_argument < 0:
            raise ValueError("external write size argument is invalid")
        if self.scale <= 0:
            raise ValueError("external write scale is invalid")
        if self.authority_selector is not None and (
            not isinstance(self.authority_selector, str)
            or not self.authority_selector
        ):
            raise ValueError("external write authority selector is invalid")


@dataclass(frozen=True, slots=True)
class ExternalMemoryCopyV1:
    """Checked byte-for-byte relation between two call-frame arguments."""

    destination_argument: int
    source_argument: int
    size_argument: int
    scale: int = 1

    def __post_init__(self) -> None:
        if min(
            self.destination_argument,
            self.source_argument,
            self.size_argument,
        ) < 0:
            raise ValueError("external memory-copy argument is invalid")
        if self.destination_argument == self.source_argument:
            raise ValueError("external memory-copy endpoints must be distinct")
        if self.scale <= 0:
            raise ValueError("external memory-copy scale is invalid")


@dataclass(frozen=True, slots=True)
class ExternalOutPointerV1:
    argument: int
    offset: int
    nullable: bool
    max_elements: int
    element_unit_bytes: int
    element_max_units: int

    def __post_init__(self) -> None:
        if self.argument < 0 or self.offset < 0:
            raise ValueError("external out-pointer location is invalid")
        if self.max_elements <= 0:
            raise ValueError("external out-pointer vector is empty")
        if self.element_unit_bytes not in {1, 2, 4}:
            raise ValueError("external out-pointer element width is invalid")
        if self.element_max_units <= 0:
            raise ValueError("external out-pointer element bound is invalid")


@dataclass(frozen=True, slots=True)
class ExternalCallbackRuleV1:
    protocol_id: str
    source_argument: int
    source_kind: str = "argument_word"
    source_offset: int = 0
    sentinels: frozenset[int] = frozenset()
    action: str = "register"
    lifetime: str = "invocation"
    delivery_thread: str = "same_thread"
    delivery_timing: str = "synchronous"
    instance_kind: str = "singleton"
    instance_argument: int | None = None
    previous_result_register: int | None = None
    previous_sentinels: frozenset[int] = frozenset()

    def __post_init__(self) -> None:
        if not self.protocol_id or self.source_argument < 0:
            raise ValueError("external callback rule identity is invalid")
        if self.source_kind not in {"argument_word", "argument_pointee"}:
            raise ValueError("external callback source kind is invalid")
        if self.source_offset < 0 or (
            self.source_kind == "argument_word" and self.source_offset != 0
        ):
            raise ValueError("external callback source offset is invalid")
        if self.action not in {"register", "replace", "invoke"}:
            raise ValueError("external callback action is invalid")
        if self.instance_kind not in {
            "singleton", "registration_sequence", "argument",
            "provider_resource",
        }:
            raise ValueError("external callback instance kind is invalid")
        if (
            self.instance_kind in {"argument", "provider_resource"}
            and self.instance_argument is None
        ):
            raise ValueError("external callback instance argument is missing")
        if self.instance_argument is not None and self.instance_argument < 0:
            raise ValueError("external callback instance argument is invalid")
        if (
            self.previous_result_register is not None
            and not 0 <= self.previous_result_register < len(_REGISTERS)
        ):
            raise ValueError("external callback previous-result register is invalid")


@dataclass(frozen=True, slots=True)
class ExternalCallRuleV1:
    contract_sha256: str | None = None
    loader_service_contract_sha256: str | None = None
    preserved_registers: frozenset[int] = frozenset()
    argument_words: int = 0
    stack_cleanup_bytes: int = 0
    disposition: str = "returns"
    allocation_result_register: int | None = None
    allocation_nullable: bool = False
    write_footprints: tuple[ExternalMemoryWriteV1, ...] = ()
    memory_copies: tuple[ExternalMemoryCopyV1, ...] = ()
    out_pointers: tuple[ExternalOutPointerV1, ...] = ()
    unknown_guest_memory_write: bool = False
    callback: ExternalCallbackRuleV1 | None = None
    module_handle_name_argument: int | None = None
    module_handle_nullable_name: bool = False
    module_handle_wide_name: bool = False
    dynamic_export_handle_argument: int | None = None
    dynamic_export_name_argument: int | None = None
    dynamic_export_results: Mapping[tuple[str, str], str] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if self.contract_sha256 is not None and (
            len(self.contract_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.contract_sha256
            )
        ):
            raise ValueError("external-call contract digest is invalid")
        if self.loader_service_contract_sha256 is not None and (
            len(self.loader_service_contract_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.loader_service_contract_sha256
            )
        ):
            raise ValueError("loader-service contract digest is invalid")
        if any(index < 0 or index >= len(_REGISTERS) for index in self.preserved_registers):
            raise ValueError("external-call preserved register is invalid")
        if self.argument_words < 0:
            raise ValueError("external-call argument count is invalid")
        if self.stack_cleanup_bytes < 0 or self.stack_cleanup_bytes % 4:
            raise ValueError("external-call stack cleanup must be word aligned")
        if self.disposition not in {"returns", "terminates"}:
            raise ValueError("external-call disposition is invalid")
        if (
            self.allocation_result_register is not None
            and not 0 <= self.allocation_result_register < len(_REGISTERS)
        ):
            raise ValueError("external-call allocation register is invalid")
        if any(
            argument >= self.argument_words
            for relation in self.memory_copies
            for argument in (
                relation.destination_argument,
                relation.source_argument,
                relation.size_argument,
            )
        ):
            raise ValueError("external memory-copy argument is out of bounds")
        if (
            self.module_handle_name_argument is not None
            and not 0 <= self.module_handle_name_argument < self.argument_words
        ):
            raise ValueError("module-handle name argument is invalid")
        if self.module_handle_name_argument is None and (
            self.module_handle_nullable_name or self.module_handle_wide_name
        ):
            raise ValueError("module-handle options require a loader service")
        dynamic_arguments = (
            self.dynamic_export_handle_argument,
            self.dynamic_export_name_argument,
        )
        if (dynamic_arguments[0] is None) != (dynamic_arguments[1] is None):
            raise ValueError("dynamic-export arguments are incomplete")
        if any(
            argument is not None
            and not 0 <= argument < self.argument_words
            for argument in dynamic_arguments
        ):
            raise ValueError("dynamic-export argument is invalid")
        if self.dynamic_export_results and dynamic_arguments[0] is None:
            raise ValueError("dynamic-export catalog has no loader service")
        if any(
            not dll or dll != dll.lower() or not identity or not target
            for (dll, identity), target in self.dynamic_export_results.items()
        ):
            raise ValueError("dynamic-export result catalog is not canonical")


@dataclass(frozen=True, slots=True)
class ReferenceCatalogV1:
    guest_code_rvas: frozenset[int] = frozenset()
    guest_image_base: int = 0
    external_functions: Mapping[int, str] = field(default_factory=dict)
    external_function_contracts: Mapping[str, tuple[str, str]] = field(
        default_factory=dict
    )
    objects: tuple[ObjectRangeV1, ...] = ()
    external_calls: Mapping[tuple[str, str], ExternalCallRuleV1] = field(
        default_factory=dict
    )
    initial_memory: Mapping[
        tuple[str, str, int, int], ReferenceValueV1
    ] = field(default_factory=dict)
    object_bytes: Mapping[str, bytes] = field(default_factory=dict)
    alternative_limit: int = REFERENCE_ALTERNATIVE_LIMIT_V1

    def object_is_immutable(self, identity: str) -> bool:
        """Return whether checked object authority forbids writes.

        Coarse unknown-write fallbacks describe possible guest writes, not
        loader-protected image mutation.  Keeping this property on the
        existing object range avoids inventing a second memory registry while
        letting read-only jump tables remain exact after an unrelated write
        loses its destination provenance.
        """

        return any(
            row.identity == identity and not row.writable
            for row in self.objects
        )

    def classify_scalar(self, value: int) -> ReferenceValueV1:
        value &= 0xFFFF_FFFF
        alternatives = [
            ReferenceAtomV1("object", row.identity, value - row.address)
            for row in self.objects if row.contains(value)
        ]
        guest_rva = value
        if (
            self.guest_image_base
            and value >= self.guest_image_base
            and value - self.guest_image_base in self.guest_code_rvas
        ):
            guest_rva = value - self.guest_image_base
        if guest_rva in self.guest_code_rvas:
            alternatives.append(
                ReferenceAtomV1("guest_code", f"rva:{guest_rva:08x}")
            )
        if value in self.external_functions:
            alternatives.append(ReferenceAtomV1(
                "external_function", self.external_functions[value]
            ))
        if len(alternatives) > 1:
            return CONFLICT_REFERENCE_V1
        if alternatives:
            return finite_reference_value_v1(
                references=alternatives, alternative_limit=self.alternative_limit
            )
        return finite_reference_value_v1(
            scalars=(value,), alternative_limit=self.alternative_limit
        )


@dataclass(frozen=True, slots=True)
class ScalarFlagRelationV1:
    register_index: int
    mask: int
    relation: str
    constant: int

    def __post_init__(self) -> None:
        if not 0 <= self.register_index < len(_REGISTERS):
            raise ValueError("scalar flag relation register is invalid")
        if not 0 <= self.mask <= 0xFFFF_FFFF:
            raise ValueError("scalar flag relation mask is invalid")
        if self.relation not in {"eq", "ult"}:
            raise ValueError("scalar flag relation kind is invalid")
        if not 0 <= self.constant <= 0xFFFF_FFFF:
            raise ValueError("scalar flag relation constant is invalid")


def _normalized_memory_ranges_v1(
    rows: frozenset[tuple[str, str, int, int]],
) -> frozenset[tuple[str, str, int, int]]:
    """Canonicalize a byte-set as disjoint owner-local intervals."""

    if len(rows) < 2:
        return rows
    grouped: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for kind, identity, start, end in rows:
        grouped.setdefault((kind, identity), []).append((start, end))
    normalized: set[tuple[str, str, int, int]] = set()
    for (kind, identity), intervals in grouped.items():
        current_start: int | None = None
        current_end = 0
        for start, end in sorted(intervals):
            if current_start is None:
                current_start, current_end = start, end
            elif start <= current_end:
                current_end = max(current_end, end)
            else:
                normalized.add((
                    kind, identity, current_start, current_end,
                ))
                current_start, current_end = start, end
        assert current_start is not None
        normalized.add((kind, identity, current_start, current_end))
    result = frozenset(normalized)
    return rows if result == rows else result


@dataclass(frozen=True, slots=True)
class ReferenceStateV1:
    registers: tuple[ReferenceValueV1, ...] = field(default_factory=lambda: (
        UNKNOWN_SCALAR_REFERENCE_V1,
    ) * len(_REGISTERS))
    flags: tuple[ReferenceValueV1, ...] = field(default_factory=lambda: (
        UNKNOWN_SCALAR_REFERENCE_V1,
    ) * (len(_FLAGS) + 1))
    memory: Mapping[tuple[str, str, int, int], ReferenceValueV1] = field(
        default_factory=dict
    )
    call_registers: tuple[ReferenceValueV1, ...] = field(default_factory=lambda: (
        UNKNOWN_SCALAR_REFERENCE_V1,
    ) * len(_REGISTERS))
    call_flags: tuple[ReferenceValueV1, ...] = field(default_factory=lambda: (
        UNKNOWN_SCALAR_REFERENCE_V1,
    ) * (len(_FLAGS) + 1))
    invalidated_memory_ranges: frozenset[
        tuple[str, str, int, int]
    ] = frozenset()
    all_memory_invalidated: bool = False
    callback_registry: Mapping[str, ReferenceValueV1] = field(
        default_factory=dict
    )
    flag_relations: tuple[ScalarFlagRelationV1 | None, ...] = field(
        default_factory=lambda: (None,) * (len(_FLAGS) + 1)
    )
    scalar_constraints: Mapping[
        tuple[int, int], frozenset[int]
    ] = field(default_factory=dict)
    preserves_inherited_memory: bool = True
    # Analysis-local aliases for relational call parameters.  The mapping is
    # part of the closure state (rather than a mutable side table) so sparse
    # memory loads can follow an exact caller object without restarting the
    # whole-program fixed point.  It is never serialized as an independent
    # authority artifact.
    relational_object_bindings: Mapping[str, ReferenceValueV1] = field(
        default_factory=dict
    )
    written_memory_keys: frozenset[
        tuple[str, str, int, int]
    ] = frozenset()
    effect_invalidated_memory_ranges: frozenset[
        tuple[str, str, int, int]
    ] = frozenset()
    effect_all_memory_invalidated: bool = False
    # Allocation existence is an explicit monotone fact.  Inferring it only
    # from the currently materialized register and memory values is unsound:
    # a join can abstract the last precise pointer and thereby make a later
    # missing allocation cell change from "unknown" to "absent".  Retaining
    # the may-exist set makes the state lattice independent of join grouping.
    possible_allocation_identities: frozenset[str] | None = None

    def __post_init__(self) -> None:
        if len(self.registers) != len(_REGISTERS):
            raise ValueError("reference register state has invalid cardinality")
        if len(self.flags) != len(_FLAGS) + 1:
            raise ValueError("reference flag state has invalid cardinality")
        if len(self.call_registers) != len(_REGISTERS):
            raise ValueError("reference call register state has invalid cardinality")
        if len(self.call_flags) != len(_FLAGS) + 1:
            raise ValueError("reference call flag state has invalid cardinality")
        if len(self.flag_relations) != len(_FLAGS) + 1:
            raise ValueError("reference flag relations have invalid cardinality")
        if any(
            not 0 <= register < len(_REGISTERS)
            or not 0 <= mask <= 0xFFFF_FFFF
            or not values
            or len(values) > BOUNDED_SCALAR_ALTERNATIVE_LIMIT_V1
            or any(not 0 <= value <= mask for value in values)
            for (register, mask), values in self.scalar_constraints.items()
        ):
            raise ValueError("reference scalar constraint is malformed")
        allocation_identities = set(
            () if self.possible_allocation_identities is None
            else self.possible_allocation_identities
        )
        # Production transitions explicitly propagate this monotone set and
        # add each newly created allocation.  Derive it only for boundary and
        # hand-constructed states that do not yet carry the explicit fact;
        # rescanning a large memory map for every temporary expression state
        # is otherwise the dominant whole-program cost.
        if self.possible_allocation_identities is None:
            values = (
                *self.registers,
                *self.call_registers,
                *self.memory.values(),
                *self.callback_registry.values(),
                *self.relational_object_bindings.values(),
            )
            allocation_identities.update(
                atom.identity
                for value in values
                for atom in value.references
                if atom.kind in {"object", "object_view"}
                and atom.identity.startswith("allocation:")
            )
            allocation_identities.update(
                identity
                for kind, identity, _offset, _width in (
                    *self.memory.keys(), *self.written_memory_keys,
                )
                if kind == "object" and identity.startswith("allocation:")
            )
            allocation_identities.update(
                identity
                for kind, identity, _start, _end in (
                    *self.invalidated_memory_ranges,
                    *self.effect_invalidated_memory_ranges,
                )
                if kind == "object" and identity.startswith("allocation:")
            )
        if any(
            not identity.startswith("allocation:")
            for identity in allocation_identities
        ):
            raise ValueError("possible allocation identity is malformed")
        normalized_allocations = frozenset(allocation_identities)
        if normalized_allocations != self.possible_allocation_identities:
            object.__setattr__(
                self,
                "possible_allocation_identities",
                normalized_allocations,
            )
        if any(
            end < start
            for _kind, _identity, start, end in self.invalidated_memory_ranges
        ):
            raise ValueError("reference invalidated memory range is malformed")
        if any(
            end < start
            for _kind, _identity, start, end
            in self.effect_invalidated_memory_ranges
        ):
            raise ValueError("reference effect invalidation is malformed")
        normalized_invalidations = _normalized_memory_ranges_v1(
            self.invalidated_memory_ranges
        )
        if normalized_invalidations is not self.invalidated_memory_ranges:
            object.__setattr__(
                self,
                "invalidated_memory_ranges",
                normalized_invalidations,
            )
        normalized_effect_invalidations = _normalized_memory_ranges_v1(
            self.effect_invalidated_memory_ranges
        )
        if (
            normalized_effect_invalidations
            is not self.effect_invalidated_memory_ranges
        ):
            object.__setattr__(
                self,
                "effect_invalidated_memory_ranges",
                normalized_effect_invalidations,
            )


@dataclass(slots=True)
class _MutableReferenceStateViewV1:
    """Zero-copy state view while interpreting one transfer."""

    registers: list[ReferenceValueV1]
    flags: list[ReferenceValueV1]
    memory: Mapping[tuple[str, str, int, int], ReferenceValueV1]
    call_registers: list[ReferenceValueV1]
    call_flags: list[ReferenceValueV1]
    invalidated_memory_ranges: set[tuple[str, str, int, int]]
    all_memory_invalidated: bool
    relational_object_bindings: Mapping[str, ReferenceValueV1]
