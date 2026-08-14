"""Native v3 models and codecs for checked transition-summary records."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, ClassVar

from ..artifact_set_v3 import CanonicalValueV3, canonical_json_bytes_v3
from ..phase_framework_v3 import RecordCodecV3
from ._schema import digest, fail, sequence, strict_object, text, uint


TRANSITION_SUMMARY_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-transition-summary-record-v3"
)
TRANSITION_SUMMARIES_ARTIFACT_KIND_V3 = "transition-summaries-v3"

_EVENT_KIND_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_INPUT_CATEGORIES = frozenset({"register", "flag", "memory", "state"})
_OUTPUT_CATEGORIES = frozenset({"register", "flag", "stack", "state"})
_MEMORY_KINDS = frozenset({"read", "write", "read_write"})
_EXIT_CATEGORIES = frozenset({"outcome", "call", "external", "callback"})


def _node_id(prefix: str, payload: Any) -> str:
    return f"{prefix}:{hashlib.sha256(canonical_json_bytes_v3(payload)).hexdigest()[:24]}"


def _require_node_id(value: str, prefix: str, payload: Any, context: str) -> None:
    expected = _node_id(prefix, payload)
    if value != expected:
        fail(
            "stale_record_id",
            f"{context} ID {value!r} does not bind its identity payload",
            f"recreate it as {expected!r}",
        )


def _canonical(value: Any) -> CanonicalValueV3:
    return CanonicalValueV3.of(value)


def _require_canonical(value: Any, context: str) -> None:
    if not isinstance(value, CanonicalValueV3):
        fail(
            "record_schema_mismatch",
            f"{context} is not canonical v3 JSON",
            "construct nested transition records through the native v3 codec",
        )


def _unique(values: tuple[Any, ...], attribute: str, context: str) -> None:
    identifiers = tuple(getattr(value, attribute) for value in values)
    if len(set(identifiers)) != len(identifiers):
        fail(
            "duplicate_record_id",
            f"{context} contain duplicate stable IDs",
            "regenerate the transition record from exact-unit authority",
        )


def _contiguous(values: tuple[Any, ...], attribute: str, context: str) -> None:
    observed = tuple(getattr(value, attribute) for value in values)
    expected = tuple(range(len(values)))
    if observed != expected:
        fail(
            "noncanonical_record_order",
            f"{context} indices are not contiguous: {observed!r}",
            "sort the rows by their zero-based source index",
        )


@dataclass(frozen=True, order=True)
class TransitionBinaryBindingV3:
    pe_sha256: str
    unit_ir_sha256: str

    def __post_init__(self) -> None:
        digest(self.pe_sha256, "transition PE SHA-256")
        digest(self.unit_ir_sha256, "transition unit-IR SHA-256")

    def to_payload(self) -> dict[str, str]:
        return {
            "pe_sha256": self.pe_sha256,
            "machine_ir_sha256": self.unit_ir_sha256,
        }


@dataclass(frozen=True, order=True)
class TransitionUnitBindingV3:
    binary: TransitionBinaryBindingV3
    unit_id: str
    rva_start: int
    rva_end: int
    unit_sha256: str
    instruction_bytes_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.binary, TransitionBinaryBindingV3):
            fail(
                "record_schema_mismatch",
                "transition unit has no native v3 binary binding",
                "construct the unit header through the native v3 codec",
            )
        text(self.unit_id, "transition unit ID", maximum=256)
        uint(self.rva_start, "transition unit start RVA")
        uint(self.rva_end, "transition unit end RVA")
        if self.rva_end <= self.rva_start:
            fail(
                "record_schema_mismatch",
                "transition unit has an empty or reversed span",
                "regenerate it from exact-unit authority",
            )
        digest(self.unit_sha256, "transition unit SHA-256")
        digest(
            self.instruction_bytes_sha256,
            "transition instruction-bytes SHA-256",
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": "unit",
            "binary": self.binary.to_payload(),
            "unit_id": self.unit_id,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "unit_sha256": self.unit_sha256,
            "instruction_bytes_sha256": self.instruction_bytes_sha256,
        }


@dataclass(frozen=True, order=True)
class TransitionEventBindingV3:
    """Compact event binding whose unit is supplied by its record header."""

    unit: TransitionUnitBindingV3
    event_index: int
    event_kind: str
    instruction_rva: int
    event_sha256: str

    _FIELDS: ClassVar[set[str]] = {
        "event_index",
        "event_kind",
        "instruction_rva",
        "event_sha256",
    }

    def __post_init__(self) -> None:
        if not isinstance(self.unit, TransitionUnitBindingV3):
            fail(
                "record_schema_mismatch",
                "transition event has no native v3 unit binding",
                "derive the event binding from its transition record header",
            )
        uint(self.event_index, "transition event index")
        if (
            not isinstance(self.event_kind, str)
            or _EVENT_KIND_RE.fullmatch(self.event_kind) is None
        ):
            fail(
                "record_schema_mismatch",
                "transition event kind is not a lowercase identifier",
                "emit the exact event kind from machine-IR semantics",
            )
        uint(self.instruction_rva, "transition event instruction RVA")
        if not self.unit.rva_start <= self.instruction_rva < self.unit.rva_end:
            fail(
                "record_schema_mismatch",
                "transition event instruction RVA is outside its exact unit",
                "bind the event to the instruction that emitted it",
            )
        digest(self.event_sha256, "transition event SHA-256")

    def to_payload(self) -> dict[str, Any]:
        return {
            "event_index": self.event_index,
            "event_kind": self.event_kind,
            "instruction_rva": self.instruction_rva,
            "event_sha256": self.event_sha256,
        }

    def to_full_payload(self) -> dict[str, Any]:
        return {"kind": "event", "unit": self.unit.to_payload(), **self.to_payload()}

    @classmethod
    def parse(
        cls, value: Any, *, unit: TransitionUnitBindingV3
    ) -> "TransitionEventBindingV3":
        row = strict_object(value, cls._FIELDS, "transition event binding")
        return cls(
            unit=unit,
            event_index=uint(row["event_index"], "transition event index"),
            event_kind=text(row["event_kind"], "transition event kind", maximum=64),
            instruction_rva=uint(
                row["instruction_rva"], "transition event instruction RVA"
            ),
            event_sha256=digest(row["event_sha256"], "transition event SHA-256"),
        )


@dataclass(frozen=True, order=True)
class TransitionInputV3:
    input_id: str
    category: str
    name: str
    value: CanonicalValueV3

    def __post_init__(self) -> None:
        if self.category not in _INPUT_CATEGORIES:
            fail(
                "record_schema_mismatch",
                f"transition input has invalid category {self.category!r}",
                "use register, flag, memory, or state",
            )
        text(self.name, "transition input name", maximum=512)
        _require_canonical(self.value, "transition input value")
        _require_node_id(
            self.input_id, "transition-input", self.identity_payload(), "transition input"
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "name": self.name,
            "value": self.value.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.input_id, **self.identity_payload()}

    @classmethod
    def parse(cls, value: Any) -> "TransitionInputV3":
        row = strict_object(
            value, {"id", "category", "name", "value"}, "transition input"
        )
        return cls(
            text(row["id"], "transition input ID"),
            text(row["category"], "transition input category"),
            text(row["name"], "transition input name", maximum=512),
            _canonical(row["value"]),
        )


@dataclass(frozen=True, order=True)
class TransitionOutputV3:
    output_id: str
    category: str
    source_index: int
    destination: str
    value: CanonicalValueV3
    exact_record: CanonicalValueV3

    def __post_init__(self) -> None:
        if self.category not in _OUTPUT_CATEGORIES:
            fail(
                "record_schema_mismatch",
                f"transition output has invalid category {self.category!r}",
                "use register, flag, stack, or state",
            )
        uint(self.source_index, "transition output index")
        text(self.destination, "transition output destination", maximum=512)
        _require_canonical(self.value, "transition output value")
        _require_canonical(self.exact_record, "transition output exact record")
        _require_node_id(
            self.output_id,
            "transition-output",
            self.identity_payload(),
            "transition output",
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "source_index": self.source_index,
            "destination": self.destination,
            "value": self.value.to_value(),
            "exact_record": self.exact_record.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.output_id, **self.identity_payload()}

    @classmethod
    def parse(cls, value: Any) -> "TransitionOutputV3":
        row = strict_object(
            value,
            {"id", "category", "source_index", "destination", "value", "exact_record"},
            "transition output",
        )
        return cls(
            text(row["id"], "transition output ID"),
            text(row["category"], "transition output category"),
            uint(row["source_index"], "transition output index"),
            text(row["destination"], "transition output destination", maximum=512),
            _canonical(row["value"]),
            _canonical(row["exact_record"]),
        )


@dataclass(frozen=True, order=True)
class TransitionMemoryAccessV3:
    access_id: str
    binding: TransitionEventBindingV3
    memory_kind: str
    width_bytes: int
    address: CanonicalValueV3
    value: CanonicalValueV3 | None
    exact_record: CanonicalValueV3

    def __post_init__(self) -> None:
        if not isinstance(self.binding, TransitionEventBindingV3):
            fail(
                "record_schema_mismatch",
                "transition memory access has no native v3 event binding",
                "construct it through the native v3 codec",
            )
        if self.memory_kind not in _MEMORY_KINDS:
            fail(
                "record_schema_mismatch",
                f"transition memory access has invalid kind {self.memory_kind!r}",
                "use read, write, or read_write",
            )
        uint(self.width_bytes, "transition memory width", maximum=4096)
        if self.width_bytes == 0:
            fail(
                "record_schema_mismatch",
                "transition memory width must be positive",
                "emit the exact access width",
            )
        if self.memory_kind in {"write", "read_write"} and self.value is None:
            fail(
                "record_schema_mismatch",
                "transition memory write has no value",
                "include the exact write expression",
            )
        _require_canonical(self.address, "transition memory address")
        if self.value is not None:
            _require_canonical(self.value, "transition memory value")
        _require_canonical(self.exact_record, "transition memory exact record")
        _require_node_id(
            self.access_id,
            "transition-memory",
            self.identity_payload(),
            "transition memory access",
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_full_payload(),
            "memory_kind": self.memory_kind,
            "width_bytes": self.width_bytes,
            "address": self.address.to_value(),
            "value": None if self.value is None else self.value.to_value(),
            "exact_record": self.exact_record.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        payload = self.identity_payload()
        payload["binding"] = self.binding.to_payload()
        return {"id": self.access_id, **payload}

    def to_full_payload(self) -> dict[str, Any]:
        return {"id": self.access_id, **self.identity_payload()}

    @classmethod
    def parse(
        cls, value: Any, *, unit: TransitionUnitBindingV3
    ) -> "TransitionMemoryAccessV3":
        row = strict_object(
            value,
            {"id", "binding", "memory_kind", "width_bytes", "address", "value", "exact_record"},
            "transition memory access",
        )
        return cls(
            text(row["id"], "transition memory access ID"),
            TransitionEventBindingV3.parse(row["binding"], unit=unit),
            text(row["memory_kind"], "transition memory kind"),
            uint(row["width_bytes"], "transition memory width", maximum=4096),
            _canonical(row["address"]),
            None if row["value"] is None else _canonical(row["value"]),
            _canonical(row["exact_record"]),
        )


@dataclass(frozen=True, order=True)
class IndexedTransitionRecordV3:
    record_id: str
    family: str
    source_index: int
    exact_record: CanonicalValueV3

    def __post_init__(self) -> None:
        text(self.family, "transition record family", maximum=512)
        uint(self.source_index, "transition record index")
        _require_canonical(self.exact_record, "indexed transition exact record")
        _require_node_id(
            self.record_id,
            "transition-record",
            self.identity_payload(),
            "indexed transition record",
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "source_index": self.source_index,
            "exact_record": self.exact_record.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.record_id, **self.identity_payload()}

    @classmethod
    def parse(cls, value: Any) -> "IndexedTransitionRecordV3":
        row = strict_object(
            value, {"id", "family", "source_index", "exact_record"}, "transition record"
        )
        return cls(
            text(row["id"], "transition record ID"),
            text(row["family"], "transition record family", maximum=512),
            uint(row["source_index"], "transition record index"),
            _canonical(row["exact_record"]),
        )


@dataclass(frozen=True, order=True)
class TransitionExitV3:
    exit_id: str
    category: str
    source_kind: str
    source_index: int | None
    transfer_kind: str
    binding: TransitionEventBindingV3 | None
    exact_record: CanonicalValueV3

    def __post_init__(self) -> None:
        if self.category not in _EXIT_CATEGORIES:
            fail(
                "record_schema_mismatch",
                f"transition exit has invalid category {self.category!r}",
                "use outcome, call, external, or callback",
            )
        if self.source_kind not in {"outcome", "external_event"}:
            fail(
                "record_schema_mismatch",
                f"transition exit has invalid source kind {self.source_kind!r}",
                "use outcome or external_event",
            )
        if self.source_kind == "outcome":
            if self.source_index is not None or self.binding is not None:
                fail(
                    "record_schema_mismatch",
                    "outcome exit unexpectedly has an event binding",
                    "remove event-only fields from the terminal outcome",
                )
        elif self.source_index is None or self.binding is None:
            fail(
                "record_schema_mismatch",
                "external-event exit lacks its exact event binding",
                "bind the exit to its exact external event",
            )
        if self.binding is not None and not isinstance(
            self.binding, TransitionEventBindingV3
        ):
            fail(
                "record_schema_mismatch",
                "transition exit has no native v3 event binding",
                "construct it through the native v3 codec",
            )
        if (
            self.binding is not None
            and self.binding.event_index != self.source_index
        ):
            fail(
                "record_schema_mismatch",
                "transition exit event index is inconsistent",
                "use the same source index in the exit and event binding",
            )
        text(self.transfer_kind, "transition transfer kind", maximum=512)
        _require_canonical(self.exact_record, "transition exit exact record")
        _require_node_id(
            self.exit_id, "transition-exit", self.identity_payload(), "transition exit"
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "source_kind": self.source_kind,
            "source_index": self.source_index,
            "transfer_kind": self.transfer_kind,
            "binding": None if self.binding is None else self.binding.to_full_payload(),
            "exact_record": self.exact_record.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        payload = self.identity_payload()
        if self.binding is not None:
            payload["binding"] = self.binding.to_payload()
        return {"id": self.exit_id, **payload}

    def to_full_payload(self) -> dict[str, Any]:
        return {"id": self.exit_id, **self.identity_payload()}

    @classmethod
    def parse(
        cls, value: Any, *, unit: TransitionUnitBindingV3
    ) -> "TransitionExitV3":
        row = strict_object(
            value,
            {
                "id",
                "category",
                "source_kind",
                "source_index",
                "transfer_kind",
                "binding",
                "exact_record",
            },
            "transition exit",
        )
        source_index = row["source_index"]
        if source_index is not None:
            source_index = uint(source_index, "transition exit index")
        return cls(
            text(row["id"], "transition exit ID"),
            text(row["category"], "transition exit category"),
            text(row["source_kind"], "transition exit source kind"),
            source_index,
            text(row["transfer_kind"], "transition transfer kind", maximum=512),
            None
            if row["binding"] is None
            else TransitionEventBindingV3.parse(row["binding"], unit=unit),
            _canonical(row["exact_record"]),
        )


@dataclass(frozen=True, order=True)
class TransitionFaultV3:
    fault_id: str
    binding: TransitionEventBindingV3
    exact_record: CanonicalValueV3

    def __post_init__(self) -> None:
        if not isinstance(self.binding, TransitionEventBindingV3):
            fail(
                "record_schema_mismatch",
                "transition fault has no native v3 event binding",
                "construct it through the native v3 codec",
            )
        if self.binding.event_kind != "fault":
            fail(
                "record_schema_mismatch",
                "transition fault has a non-fault binding",
                "bind the record to an exact fault event",
            )
        _require_canonical(self.exact_record, "transition fault exact record")
        _require_node_id(
            self.fault_id, "transition-fault", self.identity_payload(), "transition fault"
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_full_payload(),
            "exact_record": self.exact_record.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.fault_id,
            "binding": self.binding.to_payload(),
            "exact_record": self.exact_record.to_value(),
        }

    def to_full_payload(self) -> dict[str, Any]:
        return {"id": self.fault_id, **self.identity_payload()}

    @classmethod
    def parse(
        cls, value: Any, *, unit: TransitionUnitBindingV3
    ) -> "TransitionFaultV3":
        row = strict_object(
            value, {"id", "binding", "exact_record"}, "transition fault"
        )
        return cls(
            text(row["id"], "transition fault ID"),
            TransitionEventBindingV3.parse(row["binding"], unit=unit),
            _canonical(row["exact_record"]),
        )


@dataclass(frozen=True, order=True)
class UnsupportedTransitionEffectV3:
    effect_id: str
    code: str
    location: str
    detail: CanonicalValueV3

    def __post_init__(self) -> None:
        text(self.code, "unsupported-effect code", maximum=128)
        text(self.location, "unsupported-effect location", maximum=512)
        _require_canonical(self.detail, "unsupported transition-effect detail")
        _require_node_id(
            self.effect_id,
            "unsupported-effect",
            self.identity_payload(),
            "unsupported transition effect",
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "location": self.location,
            "detail": self.detail.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.effect_id, **self.identity_payload()}

    @classmethod
    def parse(cls, value: Any) -> "UnsupportedTransitionEffectV3":
        row = strict_object(
            value, {"id", "code", "location", "detail"}, "unsupported transition effect"
        )
        return cls(
            text(row["id"], "unsupported-effect ID"),
            text(row["code"], "unsupported-effect code", maximum=128),
            text(row["location"], "unsupported-effect location", maximum=512),
            _canonical(row["detail"]),
        )


@dataclass(frozen=True)
class TransitionSummaryRecordV3:
    """Compact, root-independent v3 transition authority for one exact unit."""

    record_id: str
    summary_id: str
    unit_id: str
    unit_sha256: str
    pe_sha256: str
    unit_ir_sha256: str
    instruction_bytes_sha256: str
    rva_start: int
    rva_end: int
    status: str
    expression_model: str
    semantics_sha256: str
    inputs: tuple[TransitionInputV3, ...]
    outputs: tuple[TransitionOutputV3, ...]
    memory_accesses: tuple[TransitionMemoryAccessV3, ...]
    exits: tuple[TransitionExitV3, ...]
    guards: tuple[IndexedTransitionRecordV3, ...]
    faults: tuple[TransitionFaultV3, ...]
    ordered_events: tuple[IndexedTransitionRecordV3, ...]
    unsupported_effects: tuple[UnsupportedTransitionEffectV3, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "transition-summary record ID")
        text(self.summary_id, "transition-summary content ID")
        if self.record_id != self.unit_id:
            fail(
                "stale_record_id",
                f"transition-summary record {self.record_id!r} does not use "
                f"unit ID {self.unit_id!r}",
                "preserve the exact-unit record ID in the map_units phase",
            )
        if self.status not in {"complete", "incomplete"}:
            fail(
                "record_schema_mismatch",
                f"transition summary has unsupported status {self.status!r}",
                "use complete or incomplete",
            )
        text(self.expression_model, "transition-summary expression model", maximum=512)
        digest(self.semantics_sha256, "transition-summary semantics SHA-256")
        unit = self.unit
        for binding in (
            *(row.binding for row in self.memory_accesses),
            *(row.binding for row in self.exits if row.binding is not None),
            *(row.binding for row in self.faults),
        ):
            if binding.unit != unit:
                fail(
                    "transition_binding_mismatch",
                    f"transition summary {self.summary_id!r} contains a foreign event binding",
                    "derive all nested event bindings from the record header",
                )
        for rows, attribute, label in (
            (self.inputs, "input_id", "transition inputs"),
            (self.outputs, "output_id", "transition outputs"),
            (self.memory_accesses, "access_id", "memory accesses"),
            (self.exits, "exit_id", "transition exits"),
            (self.guards, "record_id", "transition guards"),
            (self.faults, "fault_id", "transition faults"),
            (self.ordered_events, "record_id", "ordered events"),
            (self.unsupported_effects, "effect_id", "unsupported effects"),
        ):
            _unique(rows, attribute, label)
        if self.inputs != tuple(sorted(self.inputs, key=lambda row: (row.category, row.name))):
            fail(
                "noncanonical_record_order",
                "transition inputs are not canonically ordered",
                "sort inputs by category and name",
            )
        output_order = {"flag": 0, "register": 1, "stack": 2, "state": 3}
        if self.outputs != tuple(
            sorted(
                self.outputs,
                key=lambda row: (
                    output_order[row.category],
                    row.source_index,
                    row.destination,
                ),
            )
        ):
            fail(
                "noncanonical_record_order",
                "transition outputs are not canonically ordered",
                "sort outputs by category, source index, and destination",
            )
        self.validate_collections()
    @property
    def unit(self) -> TransitionUnitBindingV3:
        return TransitionUnitBindingV3(
            TransitionBinaryBindingV3(self.pe_sha256, self.unit_ir_sha256),
            self.unit_id,
            self.rva_start,
            self.rva_end,
            self.unit_sha256,
            self.instruction_bytes_sha256,
        )

    @property
    def parsed_summary(self) -> "TransitionSummaryRecordV3":
        """Compatibility view for consumers not yet renamed to native records."""

        return self

    def identity_payload(self) -> dict[str, Any]:
        return {
            "root_independent": True,
            "status": self.status,
            "unit": self.unit.to_payload(),
            "expression_model": self.expression_model,
            "semantics_sha256": self.semantics_sha256,
            "inputs": [row.to_payload() for row in self.inputs],
            "outputs": [row.to_payload() for row in self.outputs],
            "memory_accesses": [row.to_full_payload() for row in self.memory_accesses],
            "exits": [row.to_full_payload() for row in self.exits],
            "guards": [row.to_payload() for row in self.guards],
            "faults": [row.to_full_payload() for row in self.faults],
            "ordered_events": [row.to_payload() for row in self.ordered_events],
            "unsupported_effects": [row.to_payload() for row in self.unsupported_effects],
        }

    def validate_collections(self) -> None:
        _contiguous_bindings(self.memory_accesses, "memory accesses")
        _contiguous(self.guards, "source_index", "transition guards")
        _contiguous_bindings(self.faults, "transition faults")
        families: dict[str, list[int]] = {}
        for row in self.ordered_events:
            families.setdefault(row.family, []).append(row.source_index)
        for family, indices in families.items():
            if indices != list(range(len(indices))):
                fail(
                    "noncanonical_record_order",
                    f"ordered-event family {family!r} is not contiguous",
                    "sort each family by zero-based source index",
                )
        if self.ordered_events != tuple(
            sorted(self.ordered_events, key=lambda row: (row.family, row.source_index))
        ):
            fail(
                "noncanonical_record_order",
                "ordered events are not canonically ordered",
                "sort ordered events by family and source index",
            )
        event_exits = tuple(
            row for row in self.exits if row.source_kind == "external_event"
        )
        outcomes = tuple(row for row in self.exits if row.source_kind == "outcome")
        if tuple(row.source_index for row in event_exits) != tuple(range(len(event_exits))):
            fail(
                "noncanonical_record_order",
                "external exits are not contiguous",
                "sort external exits by zero-based source index",
            )
        if len(outcomes) != 1:
            fail(
                "record_schema_mismatch",
                "transition summary must contain one exact outcome",
                "emit all external exits followed by one terminal outcome",
            )
        if self.exits != (*event_exits, *outcomes):
            fail(
                "noncanonical_record_order",
                "transition exits are not canonically ordered",
                "emit all external exits followed by the terminal outcome",
            )
        if self.unsupported_effects != tuple(
            sorted(self.unsupported_effects, key=lambda row: row.effect_id)
        ):
            fail(
                "noncanonical_record_order",
                "unsupported effects are not canonically ordered",
                "sort unsupported effects by stable ID",
            )
        if (self.status == "complete") != (not self.unsupported_effects):
            fail(
                "record_schema_mismatch",
                "transition summary status does not match unsupported effects",
                "mark records incomplete exactly when unsupported effects exist",
            )
        _require_node_id(
            self.summary_id,
            "transition-summary",
            self.identity_payload(),
            "transition summary",
        )


def _contiguous_bindings(values: tuple[Any, ...], context: str) -> None:
    observed = tuple(value.binding.event_index for value in values)
    if observed != tuple(range(len(values))):
        fail(
            "noncanonical_record_order",
            f"{context} event indices are not contiguous: {observed!r}",
            "sort the rows by their zero-based event index",
        )


def _encode_transition_summary(value: TransitionSummaryRecordV3) -> dict[str, Any]:
    return {
        "schema": TRANSITION_SUMMARY_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "summary_id": value.summary_id,
        "unit_id": value.unit_id,
        "unit_sha256": value.unit_sha256,
        "pe_sha256": value.pe_sha256,
        "unit_ir_sha256": value.unit_ir_sha256,
        "instruction_bytes_sha256": value.instruction_bytes_sha256,
        "rva_start": value.rva_start,
        "rva_end": value.rva_end,
        "status": value.status,
        "expression_model": value.expression_model,
        "semantics_sha256": value.semantics_sha256,
        "inputs": [row.to_payload() for row in value.inputs],
        "outputs": [row.to_payload() for row in value.outputs],
        "memory_accesses": [row.to_payload() for row in value.memory_accesses],
        "exits": [row.to_payload() for row in value.exits],
        "guards": [row.to_payload() for row in value.guards],
        "faults": [row.to_payload() for row in value.faults],
        "ordered_events": [row.to_payload() for row in value.ordered_events],
        "unsupported_effects": [row.to_payload() for row in value.unsupported_effects],
    }


def _decode_transition_summary(value: Any) -> TransitionSummaryRecordV3:
    fields = {
        "schema", "id", "summary_id", "unit_id", "unit_sha256", "pe_sha256",
        "unit_ir_sha256", "instruction_bytes_sha256", "rva_start", "rva_end",
        "status", "expression_model", "semantics_sha256", "inputs", "outputs",
        "memory_accesses", "exits", "guards", "faults", "ordered_events",
        "unsupported_effects",
    }
    row = strict_object(value, fields, "transition-summary record")
    if row["schema"] != TRANSITION_SUMMARY_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not a transition-summary-record-v3",
            "use TRANSITION_SUMMARY_CODEC_V3 with transition-summaries-v3",
        )
    unit = TransitionUnitBindingV3(
        TransitionBinaryBindingV3(
            digest(row["pe_sha256"], "transition-summary PE SHA-256"),
            digest(row["unit_ir_sha256"], "transition-summary unit-IR SHA-256"),
        ),
        text(row["unit_id"], "transition-summary unit ID", maximum=256),
        uint(row["rva_start"], "transition-summary start RVA"),
        uint(row["rva_end"], "transition-summary end RVA"),
        digest(row["unit_sha256"], "transition-summary unit SHA-256"),
        digest(
            row["instruction_bytes_sha256"],
            "transition-summary instruction-bytes SHA-256",
        ),
    )
    result = TransitionSummaryRecordV3(
        record_id=text(row["id"], "transition-summary record ID"),
        summary_id=text(row["summary_id"], "transition-summary content ID"),
        unit_id=unit.unit_id,
        unit_sha256=unit.unit_sha256,
        pe_sha256=unit.binary.pe_sha256,
        unit_ir_sha256=unit.binary.unit_ir_sha256,
        instruction_bytes_sha256=unit.instruction_bytes_sha256,
        rva_start=unit.rva_start,
        rva_end=unit.rva_end,
        status=text(row["status"], "transition-summary status"),
        expression_model=text(
            row["expression_model"], "transition-summary expression model", maximum=512
        ),
        semantics_sha256=digest(
            row["semantics_sha256"], "transition-summary semantics SHA-256"
        ),
        inputs=tuple(
            TransitionInputV3.parse(item)
            for item in sequence(row["inputs"], "transition inputs")
        ),
        outputs=tuple(
            TransitionOutputV3.parse(item)
            for item in sequence(row["outputs"], "transition outputs")
        ),
        memory_accesses=tuple(
            TransitionMemoryAccessV3.parse(item, unit=unit)
            for item in sequence(row["memory_accesses"], "transition memory accesses")
        ),
        exits=tuple(
            TransitionExitV3.parse(item, unit=unit)
            for item in sequence(row["exits"], "transition exits")
        ),
        guards=tuple(
            IndexedTransitionRecordV3.parse(item)
            for item in sequence(row["guards"], "transition guards")
        ),
        faults=tuple(
            TransitionFaultV3.parse(item, unit=unit)
            for item in sequence(row["faults"], "transition faults")
        ),
        ordered_events=tuple(
            IndexedTransitionRecordV3.parse(item)
            for item in sequence(row["ordered_events"], "transition ordered events")
        ),
        unsupported_effects=tuple(
            UnsupportedTransitionEffectV3.parse(item)
            for item in sequence(
                row["unsupported_effects"], "transition unsupported effects"
            )
        ),
    )
    return result


TRANSITION_SUMMARY_CODEC_V3 = RecordCodecV3[TransitionSummaryRecordV3](
    decode=_decode_transition_summary,
    encode=_encode_transition_summary,
)


__all__ = [
    "IndexedTransitionRecordV3",
    "TRANSITION_SUMMARIES_ARTIFACT_KIND_V3",
    "TRANSITION_SUMMARY_CODEC_V3",
    "TRANSITION_SUMMARY_RECORD_V3_SCHEMA",
    "TransitionBinaryBindingV3",
    "TransitionEventBindingV3",
    "TransitionExitV3",
    "TransitionFaultV3",
    "TransitionInputV3",
    "TransitionMemoryAccessV3",
    "TransitionOutputV3",
    "TransitionSummaryRecordV3",
    "TransitionUnitBindingV3",
    "UnsupportedTransitionEffectV3",
]
