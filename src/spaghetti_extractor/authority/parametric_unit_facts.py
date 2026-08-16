"""Checked compact inputs for root-independent interprocedural analysis.

The semantic index and transition summary remain authoritative.  This phase
projects only the fields consumed by parametric value/provenance analysis so
global fixed-point passes do not repeatedly decode large local artifacts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..artifacts.artifact_set import ArtifactRecordV3, CanonicalValueV3
from ..artifacts.io import ArtifactSetReaderV3
from ..artifacts.phases import PhaseContextV3, RecordCodecV3, map_units
from ._schema import (
    boolean,
    digest,
    fail,
    mapping,
    require_record_ids,
    sequence,
    sorted_records,
    strict_object,
    text,
    uint,
)
from .semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    SemanticIndexRecordV3,
)
from .transition_records import (
    TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)


PARAMETRIC_UNIT_FACT_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-parametric-unit-fact-record-v3"
)
PARAMETRIC_UNIT_FACTS_ARTIFACT_KIND_V3 = "parametric-unit-facts-v3"

_GENERAL_REGISTERS = frozenset(
    {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
)


def _signed(value: Any, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not -(1 << 31) <= value < (1 << 31)
    ):
        fail(
            "record_schema_mismatch",
            f"{context} must be a signed 32-bit integer",
            "emit the exact normalized stack offset",
        )
    return value


def _optional_signed(value: Any, context: str) -> int | None:
    return None if value is None else _signed(value, context)


def _optional_uint(value: Any, context: str) -> int | None:
    return None if value is None else uint(value, context)


def _canonical_registers(values: Any, context: str) -> tuple[str, ...]:
    result = tuple(text(row, context, maximum=8) for row in sequence(values, context))
    if result != tuple(sorted(set(result))) or any(
        row not in _GENERAL_REGISTERS for row in result
    ):
        fail(
            "record_schema_mismatch",
            f"{context} must be sorted unique PE32 general registers",
            "emit only canonical general-register names",
        )
    return result


@dataclass(frozen=True, order=True)
class CompactInternalCallV3:
    event_index: int
    target_rva: int | None

    def to_payload(self) -> dict[str, Any]:
        return {"event_index": self.event_index, "target_rva": self.target_rva}

    @classmethod
    def parse(cls, value: Any) -> "CompactInternalCallV3":
        row = strict_object(value, {"event_index", "target_rva"}, "compact internal call")
        return cls(
            uint(row["event_index"], "compact internal-call event index"),
            _optional_uint(row["target_rva"], "compact internal-call target RVA"),
        )


@dataclass(frozen=True)
class CompactExternalCallV3:
    event_index: int
    transfer_kind: str
    identity: CanonicalValueV3

    def to_payload(self) -> dict[str, Any]:
        return {
            "event_index": self.event_index,
            "transfer_kind": self.transfer_kind,
            "identity": self.identity.to_value(),
        }

    @classmethod
    def parse(cls, value: Any) -> "CompactExternalCallV3":
        row = strict_object(
            value,
            {"event_index", "transfer_kind", "identity"},
            "compact external call",
        )
        transfer = text(row["transfer_kind"], "compact external transfer", maximum=16)
        if transfer not in {"call", "jump"}:
            fail(
                "record_schema_mismatch",
                f"unsupported compact external transfer {transfer!r}",
                "normalize the transfer to call or jump",
            )
        return cls(
            uint(row["event_index"], "compact external-call event index"),
            transfer,
            CanonicalValueV3.of(row["identity"]),
        )


@dataclass(frozen=True)
class CompactIndirectExitV3:
    exit_id: str
    event_index: int | None
    transfer_kind: str
    expression: CanonicalValueV3

    def to_payload(self) -> dict[str, Any]:
        return {
            "exit_id": self.exit_id,
            "event_index": self.event_index,
            "transfer_kind": self.transfer_kind,
            "expression": self.expression.to_value(),
        }

    @classmethod
    def parse(cls, value: Any) -> "CompactIndirectExitV3":
        row = strict_object(
            value,
            {"exit_id", "event_index", "transfer_kind", "expression"},
            "compact indirect exit",
        )
        return cls(
            text(row["exit_id"], "compact indirect-exit ID"),
            _optional_uint(row["event_index"], "compact indirect event index"),
            text(row["transfer_kind"], "compact indirect transfer", maximum=32),
            CanonicalValueV3.of(row["expression"]),
        )


@dataclass(frozen=True, order=True)
class CompactStackAccessV3:
    access_id: str
    kind: str
    entry_esp_offset: int
    width_bytes: int
    value: CanonicalValueV3 | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "access_id": self.access_id,
            "kind": self.kind,
            "entry_esp_offset": self.entry_esp_offset,
            "width_bytes": self.width_bytes,
            "value": None if self.value is None else self.value.to_value(),
        }

    @classmethod
    def parse(cls, value: Any) -> "CompactStackAccessV3":
        row = strict_object(
            value,
            {"access_id", "kind", "entry_esp_offset", "width_bytes", "value"},
            "compact stack access",
        )
        return cls(
            text(row["access_id"], "compact stack-access ID"),
            text(row["kind"], "compact stack-access kind", maximum=16),
            _signed(row["entry_esp_offset"], "compact stack offset"),
            uint(row["width_bytes"], "compact stack-access width", maximum=64),
            None if row["value"] is None else CanonicalValueV3.of(row["value"]),
        )


@dataclass(frozen=True, order=True)
class CompactMemoryAccessV3:
    access_id: str
    kind: str

    def to_payload(self) -> dict[str, str]:
        return {"access_id": self.access_id, "kind": self.kind}

    @classmethod
    def parse(cls, value: Any) -> "CompactMemoryAccessV3":
        row = strict_object(value, {"access_id", "kind"}, "compact memory access")
        return cls(
            text(row["access_id"], "compact memory-access ID"),
            text(row["kind"], "compact memory-access kind", maximum=16),
        )


@dataclass(frozen=True)
class ParametricUnitFactV3:
    record_id: str
    pe_sha256: str
    transition_summary_id: str
    rva_start: int
    input_registers: tuple[str, ...]
    register_outputs: tuple[tuple[str, CanonicalValueV3], ...]
    stack_net_bytes: int | None
    returns: bool
    successor_rvas: tuple[int, ...] | None
    external_calls: tuple[CompactExternalCallV3, ...]
    internal_calls: tuple[CompactInternalCallV3, ...]
    indirect_exits: tuple[CompactIndirectExitV3, ...]
    event_register_inputs: tuple[
        tuple[int, tuple[tuple[str, CanonicalValueV3], ...]], ...
    ]
    stack_accesses: tuple[CompactStackAccessV3, ...]
    nonstack_accesses: tuple[CompactMemoryAccessV3, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "parametric unit ID", maximum=512)
        digest(self.pe_sha256, "parametric unit PE SHA-256")
        text(self.transition_summary_id, "parametric transition-summary ID", maximum=512)
        uint(self.rva_start, "parametric unit start RVA")
        if self.input_registers != tuple(sorted(set(self.input_registers))):
            fail(
                "noncanonical_record_order",
                "parametric input registers are not sorted and unique",
                "sort and deduplicate input registers",
            )
        if self.successor_rvas is not None and self.successor_rvas != tuple(
            sorted(set(self.successor_rvas))
        ):
            fail(
                "noncanonical_record_order",
                "parametric successor RVAs are not sorted and unique",
                "sort and deduplicate successor RVAs",
            )
        for rows, key, label in (
            (self.register_outputs, lambda row: row[0], "register outputs"),
            (self.external_calls, lambda row: row.event_index, "external calls"),
            (self.internal_calls, lambda row: row.event_index, "internal calls"),
            (self.indirect_exits, lambda row: row.exit_id, "indirect exits"),
            (self.event_register_inputs, lambda row: row[0], "event inputs"),
            (self.stack_accesses, lambda row: row.access_id, "stack accesses"),
            (self.nonstack_accesses, lambda row: row.access_id, "nonstack accesses"),
        ):
            if rows != tuple(sorted(rows, key=key)) or len({key(row) for row in rows}) != len(rows):
                fail(
                    "noncanonical_record_order",
                    f"parametric {label} are duplicated or unsorted",
                    f"sort and deduplicate {label}",
                )

    def output(self, register: str) -> Any | None:
        return next(
            (value.to_value() for name, value in self.register_outputs if name == register),
            None,
        )

    def event_register_input(self, event_index: int, register: str) -> Any | None:
        return next(
            (
                value.to_value()
                for index, inputs in self.event_register_inputs
                if index == event_index
                for name, value in inputs
                if name == register
            ),
            None,
        )


def _encode(value: ParametricUnitFactV3) -> dict[str, Any]:
    return {
        "schema": PARAMETRIC_UNIT_FACT_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "pe_sha256": value.pe_sha256,
        "transition_summary_id": value.transition_summary_id,
        "rva_start": value.rva_start,
        "input_registers": list(value.input_registers),
        "register_outputs": [
            {"register": register, "expression": expression.to_value()}
            for register, expression in value.register_outputs
        ],
        "stack_net_bytes": value.stack_net_bytes,
        "returns": value.returns,
        "successor_rvas": (
            None if value.successor_rvas is None else list(value.successor_rvas)
        ),
        "external_calls": [row.to_payload() for row in value.external_calls],
        "internal_calls": [row.to_payload() for row in value.internal_calls],
        "indirect_exits": [row.to_payload() for row in value.indirect_exits],
        "event_register_inputs": [
            {
                "event_index": event_index,
                "registers": [
                    {"register": register, "expression": expression.to_value()}
                    for register, expression in inputs
                ],
            }
            for event_index, inputs in value.event_register_inputs
        ],
        "stack_accesses": [row.to_payload() for row in value.stack_accesses],
        "nonstack_accesses": [row.to_payload() for row in value.nonstack_accesses],
    }


def _decode(value: Any) -> ParametricUnitFactV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "pe_sha256",
            "transition_summary_id",
            "rva_start",
            "input_registers",
            "register_outputs",
            "stack_net_bytes",
            "returns",
            "successor_rvas",
            "external_calls",
            "internal_calls",
            "indirect_exits",
            "event_register_inputs",
            "stack_accesses",
            "nonstack_accesses",
        },
        "parametric unit fact",
    )
    if row["schema"] != PARAMETRIC_UNIT_FACT_RECORD_V3_SCHEMA:
        fail(
            "record_schema_mismatch",
            "parametric unit fact has the wrong schema",
            "use the parametric-unit-fact-v3 codec",
        )
    register_outputs = tuple(
        (
            text(
                strict_object(item, {"register", "expression"}, "compact register output")["register"],
                "compact output register",
                maximum=8,
            ),
            CanonicalValueV3.of(mapping(item, "compact register output")["expression"]),
        )
        for item in sequence(row["register_outputs"], "compact register outputs")
    )
    event_inputs = []
    for item in sequence(row["event_register_inputs"], "compact event inputs"):
        event = strict_object(item, {"event_index", "registers"}, "compact event input")
        registers = tuple(
            (
                text(
                    strict_object(register, {"register", "expression"}, "compact event register")["register"],
                    "compact event-input register",
                    maximum=8,
                ),
                CanonicalValueV3.of(mapping(register, "compact event register")["expression"]),
            )
            for register in sequence(event["registers"], "compact event registers")
        )
        event_inputs.append(
            (uint(event["event_index"], "compact event-input index"), registers)
        )
    successor_rows = row["successor_rvas"]
    return ParametricUnitFactV3(
        record_id=text(row["id"], "parametric unit ID", maximum=512),
        pe_sha256=digest(row["pe_sha256"], "parametric unit PE SHA-256"),
        transition_summary_id=text(
            row["transition_summary_id"], "parametric transition-summary ID", maximum=512
        ),
        rva_start=uint(row["rva_start"], "parametric unit start RVA"),
        input_registers=_canonical_registers(
            row["input_registers"], "parametric input registers"
        ),
        register_outputs=register_outputs,
        stack_net_bytes=_optional_signed(row["stack_net_bytes"], "parametric stack delta"),
        returns=boolean(row["returns"], "parametric return flag"),
        successor_rvas=(
            None
            if successor_rows is None
            else tuple(
                uint(item, "parametric successor RVA")
                for item in sequence(successor_rows, "parametric successor RVAs")
            )
        ),
        external_calls=tuple(
            CompactExternalCallV3.parse(item)
            for item in sequence(row["external_calls"], "compact external calls")
        ),
        internal_calls=tuple(
            CompactInternalCallV3.parse(item)
            for item in sequence(row["internal_calls"], "compact internal calls")
        ),
        indirect_exits=tuple(
            CompactIndirectExitV3.parse(item)
            for item in sequence(row["indirect_exits"], "compact indirect exits")
        ),
        event_register_inputs=tuple(event_inputs),
        stack_accesses=tuple(
            CompactStackAccessV3.parse(item)
            for item in sequence(row["stack_accesses"], "compact stack accesses")
        ),
        nonstack_accesses=tuple(
            CompactMemoryAccessV3.parse(item)
            for item in sequence(row["nonstack_accesses"], "compact nonstack accesses")
        ),
    )


PARAMETRIC_UNIT_FACT_CODEC_V3 = RecordCodecV3[ParametricUnitFactV3](
    decode=_decode, encode=_encode
)


def _expression_register(value: Any) -> str | None:
    if not isinstance(value, Mapping) or value.get("op") != "reg":
        return None
    register = value.get("name")
    return register if register in _GENERAL_REGISTERS else None


def _expression_constant(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return None
    result = value.get("value")
    return result if isinstance(result, int) and not isinstance(result, bool) else None


def _signed_u32(value: int) -> int:
    return value - (1 << 32) if value & (1 << 31) else value


def _esp_offset(value: Any) -> int | None:
    if _expression_register(value) == "esp":
        return 0
    if not isinstance(value, Mapping) or value.get("op") not in {"add", "add32"}:
        return None
    arguments = value.get("args")
    if not isinstance(arguments, list) or len(arguments) != 2:
        return None
    for register, constant in (arguments, tuple(reversed(arguments))):
        exact = _expression_constant(constant)
        if _expression_register(register) == "esp" and exact is not None:
            return _signed_u32(exact & 0xFFFFFFFF)
    return None


def _external_identity(value: Any) -> CanonicalValueV3:
    exact = mapping(value, "exact external-call record")
    imported = exact.get("import")
    source = imported if isinstance(imported, Mapping) else exact
    dll = source.get("dll")
    symbol = source.get("symbol")
    ordinal = source.get("ordinal")
    if isinstance(dll, str) and dll and (
        (isinstance(symbol, str) and bool(symbol))
        != (isinstance(ordinal, int) and not isinstance(ordinal, bool))
    ):
        return CanonicalValueV3.of(
            {
                "kind": "import",
                "dll": dll.lower(),
                "symbol": symbol if isinstance(symbol, str) and symbol else None,
                "ordinal": ordinal if isinstance(ordinal, int) and not isinstance(ordinal, bool) else None,
            }
        )
    protocol = source.get("external_protocol")
    if isinstance(protocol, Mapping) and protocol:
        return CanonicalValueV3.of({"kind": "protocol", "protocol": dict(protocol)})
    return CanonicalValueV3.of({})


def _successor_rvas(summary: TransitionSummaryRecordV3) -> tuple[int, ...] | None:
    outcomes = tuple(row for row in summary.exits if row.source_kind == "outcome")
    if len(outcomes) != 1:
        return None
    exact = outcomes[0].exact_record.to_value()
    if not isinstance(exact, Mapping):
        return None
    kind = exact.get("kind")
    if kind in {"fallthrough", "jump"}:
        target = exact.get("target_rva")
        return (target,) if isinstance(target, int) and not isinstance(target, bool) else None
    if kind == "branch":
        targets = (exact.get("false_target_rva"), exact.get("true_target_rva"))
        if any(not isinstance(target, int) or isinstance(target, bool) for target in targets):
            return None
        return tuple(sorted(set(targets)))
    if kind in {
        "return",
        "external_jump",
        "indirect_jump",
        "noreturn",
        "terminate",
        "fault",
    }:
        return ()
    return None


def _checked_successor_rvas(
    semantic: SemanticIndexRecordV3,
    transition: TransitionSummaryRecordV3,
    *,
    has_external_transfer: bool,
) -> tuple[int, ...] | None:
    # Exact control reconciliation incorporates checked external dispositions,
    # including non-returning calls whose instruction-level outcome still has
    # a syntactic fallthrough address.  Ordinary internal control continues to
    # use the transition summary's explicit outcome inventory.
    if has_external_transfer:
        return semantic.direct_target_rvas
    return _successor_rvas(transition)


def derive_parametric_unit_fact_v3(
    semantic: SemanticIndexRecordV3,
    transition: TransitionSummaryRecordV3,
) -> ParametricUnitFactV3:
    if (
        semantic.record_id != transition.record_id
        or semantic.pe_sha256 != transition.pe_sha256
        or semantic.unit_sha256 != transition.unit_sha256
        or semantic.unit_ir_sha256 != transition.unit_ir_sha256
        or semantic.rva_start != transition.rva_start
        or semantic.rva_end != transition.rva_end
    ):
        fail(
            "parametric_unit_binding_contradiction",
            f"semantic and transition records for {semantic.record_id!r} disagree",
            "rebuild both local authority artifacts from the same exact unit",
        )
    outputs = tuple(
        sorted(
            (
                row.destination,
                row.value,
            )
            for row in transition.outputs
            if row.category == "register"
        )
    )
    stack_delta_rows = tuple(
        row for row in transition.outputs if row.category == "stack" and row.destination == "esp"
    )
    stack_delta = None
    if stack_delta_rows:
        payload = stack_delta_rows[-1].value.to_value()
        raw_delta = payload.get("net_bytes") if isinstance(payload, Mapping) else None
        if isinstance(raw_delta, int) and not isinstance(raw_delta, bool):
            stack_delta = raw_delta
    external_calls = []
    event_inputs = []
    for row in transition.exits:
        if row.source_kind != "external_event" or row.source_index is None:
            continue
        exact = row.exact_record.to_value()
        raw_inputs = exact.get("register_inputs") if isinstance(exact, Mapping) else None
        inputs = tuple(
            sorted(
                (name, CanonicalValueV3.of(expression))
                for name, expression in raw_inputs.items()
                if name in _GENERAL_REGISTERS
            )
        ) if isinstance(raw_inputs, Mapping) else ()
        event_inputs.append((row.source_index, inputs))
        if row.category in {"external", "callback"}:
            external_calls.append(
                CompactExternalCallV3(
                    row.source_index,
                    "jump" if "jump" in row.transfer_kind else "call",
                    _external_identity(exact),
                )
            )
    stack_accesses = []
    nonstack_accesses = []
    for access in transition.memory_accesses:
        offset = _esp_offset(access.address.to_value())
        if offset is None:
            nonstack_accesses.append(
                CompactMemoryAccessV3(access.access_id, access.memory_kind)
            )
        else:
            stack_accesses.append(
                CompactStackAccessV3(
                    access.access_id,
                    access.memory_kind,
                    offset,
                    access.width_bytes,
                    access.value,
                )
            )
    return ParametricUnitFactV3(
        record_id=semantic.record_id,
        pe_sha256=semantic.pe_sha256,
        transition_summary_id=transition.summary_id,
        rva_start=semantic.rva_start,
        input_registers=tuple(
            sorted(
                row.name
                for row in transition.inputs
                if row.category == "register" and row.name in _GENERAL_REGISTERS
            )
        ),
        register_outputs=outputs,
        stack_net_bytes=stack_delta,
        returns=any(
            row.category == "outcome" and row.transfer_kind == "return"
            for row in transition.exits
        ),
        successor_rvas=_checked_successor_rvas(
            semantic,
            transition,
            has_external_transfer=bool(external_calls),
        ),
        external_calls=tuple(sorted(external_calls, key=lambda row: row.event_index)),
        internal_calls=tuple(
            CompactInternalCallV3(row.event_index, row.target_rva)
            for row in semantic.internal_calls
        ),
        indirect_exits=tuple(
            CompactIndirectExitV3(
                row.exit_id,
                row.event_index,
                row.transfer_kind,
                row.target_expression,
            )
            for row in semantic.indirect_exits
        ),
        event_register_inputs=tuple(sorted(event_inputs)),
        stack_accesses=tuple(sorted(stack_accesses)),
        nonstack_accesses=tuple(sorted(nonstack_accesses)),
    )


def _transform(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    semantic = context.typed_record(
        "semantic_index", source, SEMANTIC_INDEX_CODEC_V3
    ).value
    transition = context.typed_record(
        "transition_summaries", source.record_id, TRANSITION_SUMMARY_CODEC_V3
    ).value
    return PARAMETRIC_UNIT_FACT_CODEC_V3.write(
        source.record_id,
        derive_parametric_unit_fact_v3(semantic, transition),
    )


def check_parametric_unit_facts_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    semantic_records = sorted_records(context.records("semantic_index"))
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in semantic_records),
        "parametric unit facts",
    )
    for semantic_record, output in zip(semantic_records, outputs, strict=True):
        semantic = context.typed_record(
            "semantic_index", semantic_record, SEMANTIC_INDEX_CODEC_V3
        ).value
        transition = context.typed_record(
            "transition_summaries", semantic_record.record_id, TRANSITION_SUMMARY_CODEC_V3
        ).value
        submitted = PARAMETRIC_UNIT_FACT_CODEC_V3.read(output).value
        if submitted != derive_parametric_unit_fact_v3(semantic, transition):
            fail(
                "parametric_unit_fact_contradiction",
                f"parametric unit fact {output.record_id!r} is stale",
                "rebuild it from checked semantic and transition authority",
            )


PARAMETRIC_UNIT_FACTS_PHASE_V3 = map_units(
    name="parametric-unit-facts-v3",
    version="1",
    source_input="semantic_index",
    input_artifact_kinds={
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        "transition_summaries": TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=PARAMETRIC_UNIT_FACTS_ARTIFACT_KIND_V3,
    transform=_transform,
    completeness=check_parametric_unit_facts_completeness_v3,
    unit_aligned_inputs=("transition_summaries",),
    output_value_codec="plain-json-v1",
)


__all__ = [
    "CompactExternalCallV3",
    "CompactIndirectExitV3",
    "CompactInternalCallV3",
    "CompactMemoryAccessV3",
    "CompactStackAccessV3",
    "PARAMETRIC_UNIT_FACT_CODEC_V3",
    "PARAMETRIC_UNIT_FACT_RECORD_V3_SCHEMA",
    "PARAMETRIC_UNIT_FACTS_ARTIFACT_KIND_V3",
    "PARAMETRIC_UNIT_FACTS_PHASE_V3",
    "ParametricUnitFactV3",
    "check_parametric_unit_facts_completeness_v3",
    "derive_parametric_unit_fact_v3",
]
