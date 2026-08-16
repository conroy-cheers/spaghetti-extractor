"""Typed records for root-independent parametric interprocedural summaries.

The proposal codec is deliberately non-authorizing.  A proposal describes a
finite abstract interpretation result and its witnesses; the companion
checker reconstructs the call SCC and validates each admitted equation against
checked local authority artifacts.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ..artifacts.artifact_set import RecordDependencyV3
from ..artifacts.phases import RecordCodecV3
from ._schema import (
    canonical_strings,
    fail,
    require_stable_id,
    sequence,
    stable_id,
    strict_object,
    text,
    uint,
)
from .authority_common import (
    PrimaryBlockerV3,
    canonical_dependencies_v3,
    decode_dependencies_v3,
    encode_dependencies_v3,
    validate_authority_decision_v3,
)


PARAMETRIC_SUMMARY_PROPOSAL_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-parametric-summary-proposal-record-v3"
)
PARAMETRIC_SUMMARY_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-parametric-scc-summary-record-v3"
)
PARAMETRIC_SUMMARY_PROPOSALS_ARTIFACT_KIND_V3 = (
    "interprocedural-summary-proposals-v3"
)
PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3 = "parametric-scc-summaries-v3"

VALUE_ORIGIN_KINDS_V3 = frozenset(
    {
        "exact_bits",
        "entry_register",
        "entry_stack_word",
        "static_code_target",
        "static_data_location",
        "import_target",
        "stack_frame_location",
        "dynamic_range_location",
        "opaque_resource",
        "call_result",
    }
)
VALUE_LATTICE_KINDS_V3 = frozenset({"bottom", "finite", "top"})
REGISTER_RELATION_KINDS_V3 = frozenset(
    {"preserved", "constant", "finite", "call_result", "clobbered"}
)
MEMORY_EFFECT_KINDS_V3 = frozenset({"preserved", "write", "unknown_kill"})
CALL_EFFECT_KINDS_V3 = frozenset(
    {"direct_internal", "finite_internal", "external_profile"}
)
PE32_GENERAL_REGISTERS_V3 = frozenset(
    {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
)
PE32_CALLEE_PRESERVED_REGISTERS_V3 = (
    "ebp",
    "ebx",
    "edi",
    "esi",
)


def _canonical_rows(values: Iterable[Any], *, key: str, context: str) -> tuple[Any, ...]:
    result = tuple(sorted(values, key=lambda row: getattr(row, key)))
    identifiers = tuple(getattr(row, key) for row in result)
    if len(identifiers) != len(set(identifiers)):
        fail(
            "duplicate_record_id",
            f"{context} contain duplicate stable IDs",
            f"deduplicate {context} by {key}",
        )
    return result


def _require_canonical_rows(
    values: tuple[Any, ...], *, key: str, context: str
) -> None:
    if values != _canonical_rows(values, key=key, context=context):
        fail(
            "noncanonical_record_order",
            f"{context} are not ordered by {key}",
            f"sort {context} by {key}",
        )


def partition_call_graph_sccs_v3(
    nodes: Iterable[str], edges: Mapping[str, Iterable[str]]
) -> tuple[tuple[str, ...], ...]:
    """Return a deterministic root-independent call-graph SCC partition."""

    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    result: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in sorted(set(edges.get(node, ()))):
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])
        if lowlinks[node] != indices[node]:
            return
        members: list[str] = []
        while True:
            member = stack.pop()
            on_stack.remove(member)
            members.append(member)
            if member == node:
                break
        result.append(tuple(sorted(members)))

    for node in sorted(set(nodes)):
        if node not in indices:
            visit(node)
    return tuple(sorted(result))


def parametric_scc_id_v3(
    member_unit_ids: Iterable[str], call_edges: Iterable[tuple[str, str]]
) -> str:
    members = tuple(sorted(set(member_unit_ids)))
    edges = tuple(sorted(set(call_edges)))
    return stable_id(
        "parametric-call-scc-v3",
        {
            "root_independent": True,
            "member_unit_ids": list(members),
            "internal_call_edges": [list(row) for row in edges],
        },
    )


@dataclass(frozen=True, order=True)
class ValueOriginV3:
    kind: str
    subject_id: str | None = None
    offset: int | None = None
    exact_bits: int | None = None

    def __post_init__(self) -> None:
        if self.kind not in VALUE_ORIGIN_KINDS_V3:
            fail(
                "record_schema_mismatch",
                f"unsupported value origin {self.kind!r}",
                "use a bounded parametric-summary value origin",
            )
        if self.subject_id is not None:
            text(self.subject_id, "value-origin subject", maximum=512)
        if (
            self.offset is not None
            and (
                not isinstance(self.offset, int)
                or isinstance(self.offset, bool)
                or not -(1 << 31) <= self.offset < 1 << 31
            )
        ):
            fail(
                "record_schema_mismatch",
                "value-origin offset is outside signed PE32 range",
                "emit a signed frame/object-relative byte offset",
            )
        if self.exact_bits is not None:
            uint(self.exact_bits, "value-origin exact bits")
        if self.kind == "exact_bits":
            if self.exact_bits is None or self.subject_id is not None or self.offset is not None:
                fail(
                    "record_schema_mismatch",
                    "exact-bits origin carries non-exact fields",
                    "supply only exact_bits for an exact value",
                )
        elif self.subject_id is None or self.exact_bits is not None:
            fail(
                "record_schema_mismatch",
                f"{self.kind} origin lacks an exact subject binding",
                "bind the source record/register/slot/call result",
            )
        if self.kind == "entry_register" and self.subject_id not in PE32_GENERAL_REGISTERS_V3:
            fail(
                "record_schema_mismatch",
                f"entry-register origin names non-PE32 register {self.subject_id!r}",
                "use a canonical PE32 general register",
            )
        if self.kind in {"entry_stack_word", "stack_frame_location"} and self.offset is None:
            fail(
                "record_schema_mismatch",
                "stack origin lacks its signed ESP/frame-relative offset",
                "supply the signed byte offset explicitly",
            )

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "subject_id": self.subject_id,
            "offset": self.offset,
            "exact_bits": self.exact_bits,
        }

    @classmethod
    def parse(cls, value: Any) -> "ValueOriginV3":
        row = strict_object(
            value,
            {"kind", "subject_id", "offset", "exact_bits"},
            "parametric value origin",
        )
        return cls(
            text(row["kind"], "value-origin kind"),
            None if row["subject_id"] is None else text(row["subject_id"], "value-origin subject"),
            (
                None
                if row["offset"] is None
                else row["offset"]
                if isinstance(row["offset"], int) and not isinstance(row["offset"], bool)
                else fail(
                    "record_schema_mismatch",
                    "value-origin offset is not an integer",
                    "emit a signed byte offset",
                )
            ),
            None if row["exact_bits"] is None else uint(row["exact_bits"], "value-origin exact bits"),
        )


@dataclass(frozen=True, order=True)
class ValueFactV3:
    fact_id: str
    lattice: str
    origins: tuple[ValueOriginV3, ...]

    def __post_init__(self) -> None:
        text(self.fact_id, "parametric value-fact ID", maximum=512)
        if self.lattice not in VALUE_LATTICE_KINDS_V3:
            fail(
                "record_schema_mismatch",
                f"unsupported value lattice element {self.lattice!r}",
                "use bottom, finite, or top",
            )
        if self.origins != tuple(sorted(set(self.origins))):
            fail(
                "noncanonical_record_order",
                "value origins are duplicated or unsorted",
                "sort and deduplicate value origins",
            )
        if (self.lattice == "finite") != bool(self.origins):
            fail(
                "record_schema_mismatch",
                "value lattice and finite origin inventory disagree",
                "supply origins exactly for finite facts",
            )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.fact_id,
            "lattice": self.lattice,
            "origins": [row.to_payload() for row in self.origins],
        }

    @classmethod
    def parse(cls, value: Any) -> "ValueFactV3":
        row = strict_object(value, {"id", "lattice", "origins"}, "parametric value fact")
        return cls(
            text(row["id"], "parametric value-fact ID"),
            text(row["lattice"], "parametric value lattice"),
            tuple(ValueOriginV3.parse(item) for item in sequence(row["origins"], "value origins")),
        )


@dataclass(frozen=True, order=True)
class RegisterRelationV3:
    relation_id: str
    unit_id: str
    register: str
    kind: str
    value_fact_id: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.relation_id, "register-relation ID"),
            (self.unit_id, "register-relation unit"),
            (self.register, "register-relation register"),
            (self.value_fact_id, "register-relation value fact"),
        ):
            text(value, label, maximum=512)
        if self.kind not in REGISTER_RELATION_KINDS_V3:
            fail(
                "record_schema_mismatch",
                f"unsupported register relation {self.kind!r}",
                "use a checked parametric register relation",
            )
        if self.register not in PE32_GENERAL_REGISTERS_V3:
            fail(
                "record_schema_mismatch",
                f"register relation names non-PE32 register {self.register!r}",
                "use a canonical PE32 general register",
            )

    def to_payload(self) -> dict[str, str]:
        return {
            "id": self.relation_id,
            "unit_id": self.unit_id,
            "register": self.register,
            "kind": self.kind,
            "value_fact_id": self.value_fact_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "RegisterRelationV3":
        row = strict_object(
            value,
            {"id", "unit_id", "register", "kind", "value_fact_id"},
            "parametric register relation",
        )
        return cls(*(text(row[name], f"register relation {name}") for name in (
            "id", "unit_id", "register", "kind", "value_fact_id"
        )))


@dataclass(frozen=True, order=True)
class StackAccessV3:
    access_id: str
    unit_id: str
    kind: str
    entry_esp_offset: int
    width_bytes: int
    value_fact_id: str | None

    def __post_init__(self) -> None:
        text(self.access_id, "stack-access ID")
        text(self.unit_id, "stack-access unit")
        if self.kind not in {"read", "write", "read_write"}:
            fail("record_schema_mismatch", "invalid stack access kind", "use read, write, or read_write")
        if not isinstance(self.entry_esp_offset, int) or isinstance(self.entry_esp_offset, bool):
            fail("record_schema_mismatch", "stack offset is not an integer", "emit an entry-ESP-relative offset")
        uint(self.width_bytes, "stack-access width", maximum=4096)
        if self.width_bytes == 0:
            fail("record_schema_mismatch", "stack access has zero width", "emit its exact positive width")
        if self.value_fact_id is not None:
            text(self.value_fact_id, "stack-access value fact")

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.access_id,
            "unit_id": self.unit_id,
            "kind": self.kind,
            "entry_esp_offset": self.entry_esp_offset,
            "width_bytes": self.width_bytes,
            "value_fact_id": self.value_fact_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "StackAccessV3":
        row = strict_object(
            value,
            {"id", "unit_id", "kind", "entry_esp_offset", "width_bytes", "value_fact_id"},
            "parametric stack access",
        )
        offset = row["entry_esp_offset"]
        if not isinstance(offset, int) or isinstance(offset, bool):
            fail("record_schema_mismatch", "stack offset is not an integer", "emit an exact signed offset")
        return cls(
            text(row["id"], "stack-access ID"),
            text(row["unit_id"], "stack-access unit"),
            text(row["kind"], "stack-access kind"),
            offset,
            uint(row["width_bytes"], "stack-access width"),
            None if row["value_fact_id"] is None else text(row["value_fact_id"], "stack-access value fact"),
        )


@dataclass(frozen=True, order=True)
class StaticMemoryEffectV3:
    effect_id: str
    unit_id: str
    alias_component_id: str
    kind: str
    input_fact_id: str | None
    output_fact_id: str | None

    def __post_init__(self) -> None:
        text(self.effect_id, "static-memory effect ID")
        text(self.unit_id, "static-memory effect unit")
        text(self.alias_component_id, "static-memory alias component")
        if self.kind not in MEMORY_EFFECT_KINDS_V3:
            fail("record_schema_mismatch", "invalid static-memory effect", "use preserved, write, or unknown_kill")
        for value in (self.input_fact_id, self.output_fact_id):
            if value is not None:
                text(value, "static-memory value fact")
        if self.kind == "unknown_kill" and self.output_fact_id is not None:
            fail("record_schema_mismatch", "unknown write retains an output fact", "clear the killed output fact")

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.effect_id,
            "unit_id": self.unit_id,
            "alias_component_id": self.alias_component_id,
            "kind": self.kind,
            "input_fact_id": self.input_fact_id,
            "output_fact_id": self.output_fact_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "StaticMemoryEffectV3":
        row = strict_object(
            value,
            {"id", "unit_id", "alias_component_id", "kind", "input_fact_id", "output_fact_id"},
            "parametric static-memory effect",
        )
        return cls(
            text(row["id"], "static-memory effect ID"),
            text(row["unit_id"], "static-memory effect unit"),
            text(row["alias_component_id"], "static-memory alias component"),
            text(row["kind"], "static-memory effect kind"),
            None if row["input_fact_id"] is None else text(row["input_fact_id"], "static-memory input fact"),
            None if row["output_fact_id"] is None else text(row["output_fact_id"], "static-memory output fact"),
        )


@dataclass(frozen=True, order=True)
class CallEffectV3:
    call_id: str
    source_unit_id: str
    event_index: int
    kind: str
    target_unit_ids: tuple[str, ...]
    external_profile_record_id: str | None
    argument_fact_ids: tuple[str, ...]
    result_fact_id: str | None
    preserved_registers: tuple[str, ...] | None

    def __post_init__(self) -> None:
        text(self.call_id, "parametric call ID")
        text(self.source_unit_id, "parametric call source")
        uint(self.event_index, "parametric call event index")
        if self.kind not in CALL_EFFECT_KINDS_V3:
            fail("record_schema_mismatch", "invalid parametric call kind", "use direct_internal, finite_internal, or external_profile")
        if self.target_unit_ids != tuple(sorted(set(self.target_unit_ids))):
            fail("noncanonical_record_order", "call targets are duplicated or unsorted", "sort and deduplicate call targets")
        if self.kind == "direct_internal" and len(self.target_unit_ids) != 1:
            fail("record_schema_mismatch", "direct call lacks one target", "bind exactly one internal target")
        if self.kind == "finite_internal" and not self.target_unit_ids:
            fail("record_schema_mismatch", "finite call has no targets", "bind its finite internal target set")
        if self.kind == "external_profile":
            if self.target_unit_ids or self.external_profile_record_id is None:
                fail("record_schema_mismatch", "external call binding is incomplete", "bind one exact external profile and no internal targets")
        elif self.external_profile_record_id is not None:
            fail("record_schema_mismatch", "internal call carries an external profile", "clear the external profile binding")
        if self.external_profile_record_id is not None:
            text(self.external_profile_record_id, "external profile record ID")
        if self.argument_fact_ids != tuple(sorted(set(self.argument_fact_ids))):
            fail("noncanonical_record_order", "call argument facts are duplicated or unsorted", "sort and deduplicate argument fact IDs")
        if self.result_fact_id is not None:
            text(self.result_fact_id, "call result fact ID")
        if self.preserved_registers is not None:
            if self.preserved_registers != tuple(
                sorted(set(self.preserved_registers))
            ):
                fail(
                    "noncanonical_record_order",
                    "call preserved registers are duplicated or unsorted",
                    "sort and deduplicate the exact preserved-register inventory",
                )
            unsupported = set(self.preserved_registers) - set(
                PE32_CALLEE_PRESERVED_REGISTERS_V3
            )
            if unsupported:
                fail(
                    "record_schema_mismatch",
                    f"call preservation claims unsupported registers {sorted(unsupported)!r}",
                    "claim only checked PE32 nonvolatile general registers",
                )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.call_id,
            "source_unit_id": self.source_unit_id,
            "event_index": self.event_index,
            "kind": self.kind,
            "target_unit_ids": list(self.target_unit_ids),
            "external_profile_record_id": self.external_profile_record_id,
            "argument_fact_ids": list(self.argument_fact_ids),
            "result_fact_id": self.result_fact_id,
            "preserved_registers": (
                None
                if self.preserved_registers is None
                else list(self.preserved_registers)
            ),
        }

    @classmethod
    def parse(cls, value: Any) -> "CallEffectV3":
        row = strict_object(
            value,
            {"id", "source_unit_id", "event_index", "kind", "target_unit_ids", "external_profile_record_id", "argument_fact_ids", "result_fact_id", "preserved_registers"},
            "parametric call effect",
        )
        return cls(
            text(row["id"], "parametric call ID"),
            text(row["source_unit_id"], "parametric call source"),
            uint(row["event_index"], "parametric call event index"),
            text(row["kind"], "parametric call kind"),
            canonical_strings(row["target_unit_ids"], "parametric call targets"),
            None if row["external_profile_record_id"] is None else text(row["external_profile_record_id"], "external profile record ID"),
            canonical_strings(row["argument_fact_ids"], "parametric call argument facts"),
            None if row["result_fact_id"] is None else text(row["result_fact_id"], "parametric call result fact"),
            (
                None
                if row["preserved_registers"] is None
                else canonical_strings(
                    row["preserved_registers"],
                    "parametric call preserved registers",
                )
            ),
        )


@dataclass(frozen=True, order=True)
class ReturnBehaviorV3:
    unit_id: str
    may_return: bool
    may_not_return: bool
    cleanup_bytes: int | None
    return_address_preserved: bool

    def __post_init__(self) -> None:
        text(self.unit_id, "return-behavior unit")
        if self.cleanup_bytes is not None:
            uint(self.cleanup_bytes, "return cleanup", maximum=(1 << 16) - 1)
        if not self.may_return and not self.may_not_return:
            fail(
                "record_schema_mismatch",
                "return behavior describes neither return nor non-return",
                "set at least one exact behavior flag",
            )
        if not self.may_return and self.cleanup_bytes is not None:
            fail("record_schema_mismatch", "non-returning path carries cleanup", "clear return cleanup for a no-return path")
        if self.may_return and not self.return_address_preserved:
            fail("record_schema_mismatch", "return path does not preserve its return address", "prove return-address preservation or mark the SCC incomplete")

    def to_payload(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "may_return": self.may_return,
            "may_not_return": self.may_not_return,
            "cleanup_bytes": self.cleanup_bytes,
            "return_address_preserved": self.return_address_preserved,
        }

    @classmethod
    def parse(cls, value: Any) -> "ReturnBehaviorV3":
        row = strict_object(value, {"unit_id", "may_return", "may_not_return", "cleanup_bytes", "return_address_preserved"}, "parametric return behavior")
        for name in ("may_return", "may_not_return", "return_address_preserved"):
            if not isinstance(row[name], bool):
                fail("record_schema_mismatch", f"return field {name} is not Boolean", "emit an exact Boolean")
        return cls(
            text(row["unit_id"], "return-behavior unit"),
            row["may_return"],
            row["may_not_return"],
            None if row["cleanup_bytes"] is None else uint(row["cleanup_bytes"], "return cleanup"),
            row["return_address_preserved"],
        )


@dataclass(frozen=True, order=True)
class ParametricIndirectExitV3:
    exit_id: str
    source_unit_id: str
    expression_sha256: str
    value_fact_id: str
    target_unit_ids: tuple[str, ...]
    external_profile_record_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        text(self.exit_id, "parametric indirect-exit ID")
        text(self.source_unit_id, "parametric indirect-exit source")
        if len(self.expression_sha256) != 64 or any(character not in "0123456789abcdef" for character in self.expression_sha256):
            fail("record_schema_mismatch", "invalid indirect-exit expression digest", "bind the exact expression SHA-256")
        text(self.value_fact_id, "parametric indirect-exit fact")
        for values, label in (
            (self.target_unit_ids, "indirect-exit unit targets"),
            (self.external_profile_record_ids, "indirect-exit external profiles"),
        ):
            if values != tuple(sorted(set(values))):
                fail("noncanonical_record_order", f"{label} are duplicated or unsorted", f"sort and deduplicate {label}")
        if not (self.target_unit_ids or self.external_profile_record_ids):
            fail("record_schema_mismatch", "parametric indirect exit has no finite targets", "supply every finite target alternative")

    def to_payload(self) -> dict[str, Any]:
        return {
            "exit_id": self.exit_id,
            "source_unit_id": self.source_unit_id,
            "expression_sha256": self.expression_sha256,
            "value_fact_id": self.value_fact_id,
            "target_unit_ids": list(self.target_unit_ids),
            "external_profile_record_ids": list(self.external_profile_record_ids),
        }

    @classmethod
    def parse(cls, value: Any) -> "ParametricIndirectExitV3":
        row = strict_object(value, {"exit_id", "source_unit_id", "expression_sha256", "value_fact_id", "target_unit_ids", "external_profile_record_ids"}, "parametric indirect exit")
        return cls(
            text(row["exit_id"], "parametric indirect-exit ID"),
            text(row["source_unit_id"], "parametric indirect-exit source"),
            text(row["expression_sha256"], "indirect-exit expression digest"),
            text(row["value_fact_id"], "parametric indirect-exit fact"),
            canonical_strings(row["target_unit_ids"], "parametric indirect-exit targets"),
            canonical_strings(row["external_profile_record_ids"], "parametric indirect-exit profiles"),
        )


def _validate_cross_references(
    *,
    member_unit_ids: tuple[str, ...],
    value_facts: tuple[ValueFactV3, ...],
    register_relations: tuple[RegisterRelationV3, ...],
    stack_accesses: tuple[StackAccessV3, ...],
    memory_effects: tuple[StaticMemoryEffectV3, ...],
    call_effects: tuple[CallEffectV3, ...],
    returns: tuple[ReturnBehaviorV3, ...],
    indirect_exits: tuple[ParametricIndirectExitV3, ...],
) -> None:
    """Enforce internal closure before checker-specific semantic validation."""

    member_set = set(member_unit_ids)
    fact_ids = tuple(row.fact_id for row in value_facts)
    if len(fact_ids) != len(set(fact_ids)):
        fail("duplicate_record_id", "value facts contain duplicate IDs", "deduplicate value facts")
    for rows, attribute, context in (
        (register_relations, "relation_id", "register relations"),
        (stack_accesses, "access_id", "stack accesses"),
        (memory_effects, "effect_id", "memory effects"),
        (call_effects, "call_id", "call effects"),
        (indirect_exits, "exit_id", "indirect exits"),
    ):
        identifiers = tuple(getattr(row, attribute) for row in rows)
        if len(identifiers) != len(set(identifiers)):
            fail("duplicate_record_id", f"{context} contain duplicate IDs", f"deduplicate {context}")
    return_units = tuple(row.unit_id for row in returns)
    if len(return_units) != len(set(return_units)):
        fail("duplicate_record_id", "return behaviors duplicate a unit", "emit one return behavior per member unit")
    owned_rows = (
        *((row.unit_id, "register relation") for row in register_relations),
        *((row.unit_id, "stack access") for row in stack_accesses),
        *((row.unit_id, "memory effect") for row in memory_effects),
        *((row.source_unit_id, "call effect") for row in call_effects),
        *((row.unit_id, "return behavior") for row in returns),
        *((row.source_unit_id, "indirect exit") for row in indirect_exits),
    )
    for unit_id, context in owned_rows:
        if unit_id not in member_set:
            fail(
                "record_schema_mismatch",
                f"{context} belongs to non-member unit {unit_id!r}",
                "bind every row to a checked SCC member",
            )
    referenced_facts = {
        *(row.value_fact_id for row in register_relations),
        *(row.value_fact_id for row in stack_accesses if row.value_fact_id is not None),
        *(row.input_fact_id for row in memory_effects if row.input_fact_id is not None),
        *(row.output_fact_id for row in memory_effects if row.output_fact_id is not None),
        *(fact_id for row in call_effects for fact_id in row.argument_fact_ids),
        *(row.result_fact_id for row in call_effects if row.result_fact_id is not None),
        *(row.value_fact_id for row in indirect_exits),
    }
    if referenced_facts - set(fact_ids):
        fail(
            "record_schema_mismatch",
            "parametric summary references unknown value facts",
            "include every referenced fact in the same SCC record",
        )


@dataclass(frozen=True)
class ParametricSccProposalV3:
    proposal_id: str
    scc_id: str
    member_unit_ids: tuple[str, ...]
    base_path_unit_ids: tuple[str, ...]
    value_budget: int
    value_facts: tuple[ValueFactV3, ...]
    register_relations: tuple[RegisterRelationV3, ...]
    stack_accesses: tuple[StackAccessV3, ...]
    stack_cleanup_bytes: int | None
    return_address_preserved: bool
    memory_effects: tuple[StaticMemoryEffectV3, ...]
    call_effects: tuple[CallEffectV3, ...]
    returns: tuple[ReturnBehaviorV3, ...]
    indirect_exits: tuple[ParametricIndirectExitV3, ...]
    dependencies: tuple[RecordDependencyV3, ...]

    def __post_init__(self) -> None:
        text(self.scc_id, "parametric proposal SCC ID")
        if self.member_unit_ids != tuple(sorted(set(self.member_unit_ids))) or not self.member_unit_ids:
            fail("noncanonical_record_order", "proposal SCC members are empty, duplicated, or unsorted", "emit sorted unique SCC members")
        if self.base_path_unit_ids != tuple(sorted(set(self.base_path_unit_ids))):
            fail("noncanonical_record_order", "proposal base paths are duplicated or unsorted", "sort and deduplicate base-path units")
        if set(self.base_path_unit_ids) - set(self.member_unit_ids):
            fail("record_schema_mismatch", "proposal base path is outside its SCC", "bind base paths to SCC members")
        uint(self.value_budget, "parametric value budget", maximum=4096)
        if self.value_budget == 0:
            fail("record_schema_mismatch", "parametric value budget is zero", "use a positive finite-alternative budget")
        if self.stack_cleanup_bytes is not None:
            uint(self.stack_cleanup_bytes, "SCC stack cleanup", maximum=(1 << 16) - 1)
        if not isinstance(self.return_address_preserved, bool):
            fail("record_schema_mismatch", "return-address preservation is not Boolean", "emit an exact Boolean")
        canonical_dependencies_v3(self.dependencies)
        if self.dependencies != canonical_dependencies_v3(self.dependencies):
            fail("noncanonical_record_order", "proposal dependencies are duplicated or unsorted", "sort and deduplicate proposal dependencies")
        for rows, key, context in (
            (self.value_facts, "fact_id", "value facts"),
            (self.register_relations, "relation_id", "register relations"),
            (self.stack_accesses, "access_id", "stack accesses"),
            (self.memory_effects, "effect_id", "memory effects"),
            (self.call_effects, "call_id", "call effects"),
            (self.returns, "unit_id", "return behaviors"),
            (self.indirect_exits, "exit_id", "indirect exits"),
        ):
            _require_canonical_rows(rows, key=key, context=context)
        _validate_cross_references(
            member_unit_ids=self.member_unit_ids,
            value_facts=self.value_facts,
            register_relations=self.register_relations,
            stack_accesses=self.stack_accesses,
            memory_effects=self.memory_effects,
            call_effects=self.call_effects,
            returns=self.returns,
            indirect_exits=self.indirect_exits,
        )
        require_stable_id(self.proposal_id, "parametric-summary-proposal-v3", self.identity_payload, "parametric summary proposal")

    def value_fact(self, fact_id: str) -> ValueFactV3 | None:
        """Return one typed proposal fact without exposing its wire payload."""

        return next((row for row in self.value_facts if row.fact_id == fact_id), None)

    def register_relation(
        self, unit_id: str, register: str
    ) -> RegisterRelationV3 | None:
        return next(
            (
                row
                for row in self.register_relations
                if row.unit_id == unit_id and row.register == register
            ),
            None,
        )

    def call_effect(self, source_unit_id: str, event_index: int) -> CallEffectV3 | None:
        return next(
            (
                row
                for row in self.call_effects
                if row.source_unit_id == source_unit_id
                and row.event_index == event_index
            ),
            None,
        )

    def call_preserves_register(
        self, source_unit_id: str, event_index: int, register: str
    ) -> bool:
        call = self.call_effect(source_unit_id, event_index)
        return (
            call is not None
            and call.preserved_registers is not None
            and register in call.preserved_registers
        )

    def indirect_exit(self, exit_id: str) -> ParametricIndirectExitV3 | None:
        return next((row for row in self.indirect_exits if row.exit_id == exit_id), None)

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "root_independent": True,
            "scc_id": self.scc_id,
            "member_unit_ids": list(self.member_unit_ids),
            "base_path_unit_ids": list(self.base_path_unit_ids),
            "value_budget": self.value_budget,
            "value_facts": [row.to_payload() for row in self.value_facts],
            "register_relations": [row.to_payload() for row in self.register_relations],
            "stack": {
                "accesses": [row.to_payload() for row in self.stack_accesses],
                "cleanup_bytes": self.stack_cleanup_bytes,
                "return_address_preserved": self.return_address_preserved,
            },
            "memory_effects": [row.to_payload() for row in self.memory_effects],
            "call_effects": [row.to_payload() for row in self.call_effects],
            "returns": [row.to_payload() for row in self.returns],
            "indirect_exits": [row.to_payload() for row in self.indirect_exits],
            "dependencies": encode_dependencies_v3(self.dependencies),
        }

    @classmethod
    def create(cls, **fields: Any) -> "ParametricSccProposalV3":
        normalized = {
            **fields,
            "member_unit_ids": tuple(sorted(set(fields["member_unit_ids"]))),
            "base_path_unit_ids": tuple(sorted(set(fields.get("base_path_unit_ids", ())))),
            "value_facts": _canonical_rows(fields.get("value_facts", ()), key="fact_id", context="value facts"),
            "register_relations": _canonical_rows(fields.get("register_relations", ()), key="relation_id", context="register relations"),
            "stack_accesses": _canonical_rows(fields.get("stack_accesses", ()), key="access_id", context="stack accesses"),
            "memory_effects": _canonical_rows(fields.get("memory_effects", ()), key="effect_id", context="memory effects"),
            "call_effects": _canonical_rows(fields.get("call_effects", ()), key="call_id", context="call effects"),
            "returns": tuple(sorted(fields.get("returns", ()), key=lambda row: row.unit_id)),
            "indirect_exits": tuple(sorted(fields.get("indirect_exits", ()), key=lambda row: row.exit_id)),
            "dependencies": canonical_dependencies_v3(fields.get("dependencies", ())),
        }
        payload = {
            "root_independent": True,
            "scc_id": normalized["scc_id"],
            "member_unit_ids": list(normalized["member_unit_ids"]),
            "base_path_unit_ids": list(normalized["base_path_unit_ids"]),
            "value_budget": normalized["value_budget"],
            "value_facts": [row.to_payload() for row in normalized["value_facts"]],
            "register_relations": [row.to_payload() for row in normalized["register_relations"]],
            "stack": {
                "accesses": [row.to_payload() for row in normalized["stack_accesses"]],
                "cleanup_bytes": normalized["stack_cleanup_bytes"],
                "return_address_preserved": normalized["return_address_preserved"],
            },
            "memory_effects": [row.to_payload() for row in normalized["memory_effects"]],
            "call_effects": [row.to_payload() for row in normalized["call_effects"]],
            "returns": [row.to_payload() for row in normalized["returns"]],
            "indirect_exits": [row.to_payload() for row in normalized["indirect_exits"]],
            "dependencies": encode_dependencies_v3(normalized["dependencies"]),
        }
        normalized["proposal_id"] = stable_id("parametric-summary-proposal-v3", payload)
        return cls(**normalized)

    def to_payload(self) -> dict[str, Any]:
        return {"schema": PARAMETRIC_SUMMARY_PROPOSAL_RECORD_V3_SCHEMA, "id": self.proposal_id, **self.identity_payload}

    @classmethod
    def parse(cls, value: Any) -> "ParametricSccProposalV3":
        row = strict_object(
            value,
            {"schema", "id", "root_independent", "scc_id", "member_unit_ids", "base_path_unit_ids", "value_budget", "value_facts", "register_relations", "stack", "memory_effects", "call_effects", "returns", "indirect_exits", "dependencies"},
            "parametric summary proposal",
        )
        if row["schema"] != PARAMETRIC_SUMMARY_PROPOSAL_RECORD_V3_SCHEMA or row["root_independent"] is not True:
            fail("wrong_record_schema", "record is not a root-independent parametric proposal", "use the v3 proposal codec")
        stack = strict_object(row["stack"], {"accesses", "cleanup_bytes", "return_address_preserved"}, "parametric stack proposal")
        if not isinstance(stack["return_address_preserved"], bool):
            fail("record_schema_mismatch", "stack return-address flag is not Boolean", "emit an exact Boolean")
        return cls(
            proposal_id=text(row["id"], "parametric proposal ID"),
            scc_id=text(row["scc_id"], "parametric proposal SCC ID"),
            member_unit_ids=canonical_strings(row["member_unit_ids"], "proposal SCC members"),
            base_path_unit_ids=canonical_strings(row["base_path_unit_ids"], "proposal base paths"),
            value_budget=uint(row["value_budget"], "parametric value budget"),
            value_facts=tuple(ValueFactV3.parse(item) for item in sequence(row["value_facts"], "parametric value facts")),
            register_relations=tuple(RegisterRelationV3.parse(item) for item in sequence(row["register_relations"], "parametric register relations")),
            stack_accesses=tuple(StackAccessV3.parse(item) for item in sequence(stack["accesses"], "parametric stack accesses")),
            stack_cleanup_bytes=None if stack["cleanup_bytes"] is None else uint(stack["cleanup_bytes"], "SCC stack cleanup"),
            return_address_preserved=stack["return_address_preserved"],
            memory_effects=tuple(StaticMemoryEffectV3.parse(item) for item in sequence(row["memory_effects"], "parametric memory effects")),
            call_effects=tuple(CallEffectV3.parse(item) for item in sequence(row["call_effects"], "parametric call effects")),
            returns=tuple(ReturnBehaviorV3.parse(item) for item in sequence(row["returns"], "parametric returns")),
            indirect_exits=tuple(ParametricIndirectExitV3.parse(item) for item in sequence(row["indirect_exits"], "parametric indirect exits")),
            dependencies=decode_dependencies_v3(row["dependencies"]),
        )


@dataclass(frozen=True)
class ParametricSccSummaryV3:
    record_id: str
    scc_id: str
    status: str
    authorizing: bool
    proposal_id: str | None
    member_unit_ids: tuple[str, ...]
    recursive: bool
    checked_base_path_unit_ids: tuple[str, ...]
    value_facts: tuple[ValueFactV3, ...]
    register_relations: tuple[RegisterRelationV3, ...]
    stack_accesses: tuple[StackAccessV3, ...]
    stack_cleanup_bytes: int | None
    return_address_preserved: bool
    memory_effects: tuple[StaticMemoryEffectV3, ...]
    call_effects: tuple[CallEffectV3, ...]
    returns: tuple[ReturnBehaviorV3, ...]
    indirect_exits: tuple[ParametricIndirectExitV3, ...]
    primary_blocker: PrimaryBlockerV3 | None
    dependencies: tuple[RecordDependencyV3, ...]

    def __post_init__(self) -> None:
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=self.dependencies,
            context="parametric SCC summary",
        )
        text(self.scc_id, "parametric summary SCC ID")
        if self.record_id != self.scc_id:
            fail("stale_record_id", "parametric summary record ID differs from its SCC ID", "use the checked call-SCC ID")
        if self.proposal_id is not None:
            text(self.proposal_id, "parametric proposal ID")
        if self.member_unit_ids != tuple(sorted(set(self.member_unit_ids))) or not self.member_unit_ids:
            fail("noncanonical_record_order", "checked SCC members are empty, duplicated, or unsorted", "emit the checked SCC partition")
        if self.checked_base_path_unit_ids != tuple(sorted(set(self.checked_base_path_unit_ids))):
            fail("noncanonical_record_order", "checked recursive base paths are duplicated or unsorted", "sort and deduplicate checked base-path units")
        if set(self.checked_base_path_unit_ids) - set(self.member_unit_ids):
            fail("record_schema_mismatch", "checked base path lies outside its SCC", "bind base paths to checked SCC members")
        if self.dependencies != canonical_dependencies_v3(self.dependencies):
            fail("noncanonical_record_order", "checked summary dependencies are duplicated or unsorted", "sort and deduplicate dependencies")
        for rows, key, context in (
            (self.value_facts, "fact_id", "checked value facts"),
            (self.register_relations, "relation_id", "checked register relations"),
            (self.stack_accesses, "access_id", "checked stack accesses"),
            (self.memory_effects, "effect_id", "checked memory effects"),
            (self.call_effects, "call_id", "checked call effects"),
            (self.returns, "unit_id", "checked return behaviors"),
            (self.indirect_exits, "exit_id", "checked indirect exits"),
        ):
            _require_canonical_rows(rows, key=key, context=context)
        if self.status != "complete" and any((self.value_facts, self.register_relations, self.stack_accesses, self.memory_effects, self.call_effects, self.returns, self.indirect_exits)):
            fail("fail_open_parametric_summary", "non-authorizing summary retains semantic facts", "clear all facts unless the SCC is complete")
        if self.status != "complete" and self.checked_base_path_unit_ids:
            fail("fail_open_parametric_summary", "non-authorizing summary retains a checked recursive base path", "clear base paths unless the SCC is complete")
        if self.status == "complete":
            if self.recursive and not self.checked_base_path_unit_ids:
                fail("fail_open_parametric_summary", "recursive complete summary has no checked base path", "include a checked returning base path")
            _validate_cross_references(
                member_unit_ids=self.member_unit_ids,
                value_facts=self.value_facts,
                register_relations=self.register_relations,
                stack_accesses=self.stack_accesses,
                memory_effects=self.memory_effects,
                call_effects=self.call_effects,
                returns=self.returns,
                indirect_exits=self.indirect_exits,
            )

    def value_fact(self, fact_id: str) -> ValueFactV3 | None:
        return next((row for row in self.value_facts if row.fact_id == fact_id), None)

    def covers_unit(self, unit_id: str) -> bool:
        return unit_id in self.member_unit_ids

    def register_relation(
        self, unit_id: str, register: str
    ) -> RegisterRelationV3 | None:
        return next(
            (
                row
                for row in self.register_relations
                if row.unit_id == unit_id and row.register == register
            ),
            None,
        )

    def preserves_register(self, unit_id: str, register: str) -> bool:
        relation = self.register_relation(unit_id, register)
        return relation is not None and relation.kind == "preserved"

    def call_effect(self, source_unit_id: str, event_index: int) -> CallEffectV3 | None:
        return next(
            (
                row
                for row in self.call_effects
                if row.source_unit_id == source_unit_id
                and row.event_index == event_index
            ),
            None,
        )

    def call_preserves_register(
        self, source_unit_id: str, event_index: int, register: str
    ) -> bool:
        call = self.call_effect(source_unit_id, event_index)
        return (
            call is not None
            and call.preserved_registers is not None
            and register in call.preserved_registers
        )

    def indirect_exit(self, exit_id: str) -> ParametricIndirectExitV3 | None:
        return next((row for row in self.indirect_exits if row.exit_id == exit_id), None)

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema": PARAMETRIC_SUMMARY_RECORD_V3_SCHEMA,
            "id": self.record_id,
            "root_independent": True,
            "scc_id": self.scc_id,
            "status": self.status,
            "authorizing": self.authorizing,
            "proposal_id": self.proposal_id,
            "member_unit_ids": list(self.member_unit_ids),
            "recursive": self.recursive,
            "checked_base_path_unit_ids": list(self.checked_base_path_unit_ids),
            "value_facts": [row.to_payload() for row in self.value_facts],
            "register_relations": [row.to_payload() for row in self.register_relations],
            "stack": {"accesses": [row.to_payload() for row in self.stack_accesses], "cleanup_bytes": self.stack_cleanup_bytes, "return_address_preserved": self.return_address_preserved},
            "memory_effects": [row.to_payload() for row in self.memory_effects],
            "call_effects": [row.to_payload() for row in self.call_effects],
            "returns": [row.to_payload() for row in self.returns],
            "indirect_exits": [row.to_payload() for row in self.indirect_exits],
            "primary_blocker": None if self.primary_blocker is None else self.primary_blocker.to_payload(),
            "dependencies": encode_dependencies_v3(self.dependencies),
        }

    @classmethod
    def parse(cls, value: Any) -> "ParametricSccSummaryV3":
        row = strict_object(value, {"schema", "id", "root_independent", "scc_id", "status", "authorizing", "proposal_id", "member_unit_ids", "recursive", "checked_base_path_unit_ids", "value_facts", "register_relations", "stack", "memory_effects", "call_effects", "returns", "indirect_exits", "primary_blocker", "dependencies"}, "parametric SCC summary")
        if row["schema"] != PARAMETRIC_SUMMARY_RECORD_V3_SCHEMA or row["root_independent"] is not True:
            fail("wrong_record_schema", "record is not a root-independent checked summary", "use the v3 checked-summary codec")
        for name in ("authorizing", "recursive"):
            if not isinstance(row[name], bool):
                fail("record_schema_mismatch", f"checked summary {name} is not Boolean", "emit an exact Boolean")
        stack = strict_object(row["stack"], {"accesses", "cleanup_bytes", "return_address_preserved"}, "checked parametric stack")
        if not isinstance(stack["return_address_preserved"], bool):
            fail("record_schema_mismatch", "checked return-address flag is not Boolean", "emit an exact Boolean")
        return cls(
            record_id=text(row["id"], "parametric summary record ID"),
            scc_id=text(row["scc_id"], "parametric summary SCC ID"),
            status=text(row["status"], "parametric summary status"),
            authorizing=row["authorizing"],
            proposal_id=None if row["proposal_id"] is None else text(row["proposal_id"], "parametric proposal ID"),
            member_unit_ids=canonical_strings(row["member_unit_ids"], "checked SCC members"),
            recursive=row["recursive"],
            checked_base_path_unit_ids=canonical_strings(row["checked_base_path_unit_ids"], "checked recursive base paths"),
            value_facts=tuple(ValueFactV3.parse(item) for item in sequence(row["value_facts"], "checked value facts")),
            register_relations=tuple(RegisterRelationV3.parse(item) for item in sequence(row["register_relations"], "checked register relations")),
            stack_accesses=tuple(StackAccessV3.parse(item) for item in sequence(stack["accesses"], "checked stack accesses")),
            stack_cleanup_bytes=None if stack["cleanup_bytes"] is None else uint(stack["cleanup_bytes"], "checked stack cleanup"),
            return_address_preserved=stack["return_address_preserved"],
            memory_effects=tuple(StaticMemoryEffectV3.parse(item) for item in sequence(row["memory_effects"], "checked memory effects")),
            call_effects=tuple(CallEffectV3.parse(item) for item in sequence(row["call_effects"], "checked call effects")),
            returns=tuple(ReturnBehaviorV3.parse(item) for item in sequence(row["returns"], "checked returns")),
            indirect_exits=tuple(ParametricIndirectExitV3.parse(item) for item in sequence(row["indirect_exits"], "checked indirect exits")),
            primary_blocker=None if row["primary_blocker"] is None else PrimaryBlockerV3.parse(row["primary_blocker"]),
            dependencies=decode_dependencies_v3(row["dependencies"]),
        )


PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3 = RecordCodecV3[ParametricSccProposalV3](
    decode=ParametricSccProposalV3.parse,
    encode=ParametricSccProposalV3.to_payload,
)
PARAMETRIC_SCC_SUMMARY_CODEC_V3 = RecordCodecV3[ParametricSccSummaryV3](
    decode=ParametricSccSummaryV3.parse,
    encode=ParametricSccSummaryV3.to_payload,
)


__all__ = [
    "CALL_EFFECT_KINDS_V3",
    "MEMORY_EFFECT_KINDS_V3",
    "PE32_CALLEE_PRESERVED_REGISTERS_V3",
    "PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3",
    "PARAMETRIC_SCC_SUMMARY_CODEC_V3",
    "PARAMETRIC_SUMMARY_PROPOSALS_ARTIFACT_KIND_V3",
    "PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3",
    "PARAMETRIC_SUMMARY_PROPOSAL_RECORD_V3_SCHEMA",
    "PARAMETRIC_SUMMARY_RECORD_V3_SCHEMA",
    "CallEffectV3",
    "ParametricIndirectExitV3",
    "ParametricSccProposalV3",
    "ParametricSccSummaryV3",
    "RegisterRelationV3",
    "ReturnBehaviorV3",
    "StackAccessV3",
    "StaticMemoryEffectV3",
    "ValueFactV3",
    "ValueOriginV3",
    "parametric_scc_id_v3",
    "partition_call_graph_sccs_v3",
]
