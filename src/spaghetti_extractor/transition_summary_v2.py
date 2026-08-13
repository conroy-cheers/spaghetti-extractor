"""Root-independent exact transition summaries for canonical machine IR.

The summary is a compact, typed projection of one exact machine-IR unit.  It
does not contain rooted facts, inferred targets, or promoted invariants.  A
consumer can therefore cache it by exact unit identity and independently
recheck every projected field against the canonical unit record.
"""

from __future__ import annotations

import hashlib
from dataclasses import InitVar, dataclass
from typing import Any, Mapping, Sequence

from .authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
    CanonicalJson,
    EventBinding,
    UnitBinding,
    canonical_json_bytes,
)
from .machine_ir_authority_v2 import (
    MachineIRAuthorityV2Error,
    recompute_event_binding,
    recompute_unit_binding,
)


TRANSITION_SUMMARY_V2_FORMAT = "spaghetti-extractor-transition-summary-v2"
MACHINE_IR_V2_FORMAT = "stage-a-machine-ir-v2"

_STATUS_VALUES = frozenset({"complete", "incomplete"})
_INPUT_CATEGORIES = frozenset({"register", "flag", "memory", "state"})
_OUTPUT_CATEGORIES = frozenset({"register", "flag", "stack", "state"})
_MEMORY_KINDS = frozenset({"read", "write", "read_write"})
_EXIT_CATEGORIES = frozenset({"outcome", "call", "external", "callback"})
_SEMANTIC_ARRAYS = (
    "register_writes",
    "flag_writes",
    "memory_events",
    "external_events",
    "faults",
    "ordered_events",
    "edge_conditions",
)


class TransitionSummaryV2Error(ValueError):
    """A transition summary or its exact machine-IR subject is invalid."""


@dataclass(frozen=True, order=True)
class TransitionInputV2:
    input_id: str
    category: str
    name: str
    value: CanonicalJson
    _identity_checked: InitVar[bool] = False

    def __post_init__(self, _identity_checked: bool) -> None:
        if self.category not in _INPUT_CATEGORIES:
            raise AuthorityDataError("transition input has an invalid category")
        _text(self.name, "transition input name")
        if not isinstance(self.value, CanonicalJson):
            raise AuthorityDataError("transition input value is not canonical JSON")
        if not _identity_checked:
            _check_id(self.input_id, "transition-input", self.identity_payload())

    def identity_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "name": self.name,
            "value": self.value.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.input_id, **self.identity_payload()}

    @classmethod
    def create(cls, *, category: str, name: str, value: Any) -> "TransitionInputV2":
        canonical = CanonicalJson.of(value)
        identity = {"category": category, "name": name, "value": canonical.to_value()}
        return cls(_node_id("transition-input", identity), category, name, canonical, True)

    @classmethod
    def parse(cls, value: Any) -> "TransitionInputV2":
        row = _object(value, {"id", "category", "name", "value"}, "transition input")
        return cls(
            input_id=_text(row["id"], "transition input ID"),
            category=_text(row["category"], "transition input category"),
            name=_text(row["name"], "transition input name"),
            value=CanonicalJson.of(row["value"]),
        )


@dataclass(frozen=True, order=True)
class TransitionOutputV2:
    output_id: str
    category: str
    source_index: int
    destination: str
    value: CanonicalJson
    exact_record: CanonicalJson
    _identity_checked: InitVar[bool] = False

    def __post_init__(self, _identity_checked: bool) -> None:
        if self.category not in _OUTPUT_CATEGORIES:
            raise AuthorityDataError("transition output has an invalid category")
        _uint(self.source_index, "transition output index")
        _text(self.destination, "transition output destination")
        if not isinstance(self.value, CanonicalJson) or not isinstance(
            self.exact_record, CanonicalJson
        ):
            raise AuthorityDataError("transition output data is not canonical JSON")
        if not _identity_checked:
            _check_id(self.output_id, "transition-output", self.identity_payload())

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
    def create(
        cls,
        *,
        category: str,
        source_index: int,
        destination: str,
        value: Any,
        exact_record: Any,
    ) -> "TransitionOutputV2":
        canonical_value = CanonicalJson.of(value)
        canonical_record = CanonicalJson.of(exact_record)
        identity = {
            "category": category,
            "source_index": source_index,
            "destination": destination,
            "value": canonical_value.to_value(),
            "exact_record": canonical_record.to_value(),
        }
        return cls(
            _node_id("transition-output", identity),
            category,
            source_index,
            destination,
            canonical_value,
            canonical_record,
            True,
        )

    @classmethod
    def parse(cls, value: Any) -> "TransitionOutputV2":
        row = _object(
            value,
            {"id", "category", "source_index", "destination", "value", "exact_record"},
            "transition output",
        )
        return cls(
            output_id=_text(row["id"], "transition output ID"),
            category=_text(row["category"], "transition output category"),
            source_index=_uint(row["source_index"], "transition output index"),
            destination=_text(row["destination"], "transition output destination"),
            value=CanonicalJson.of(row["value"]),
            exact_record=CanonicalJson.of(row["exact_record"]),
        )


@dataclass(frozen=True, order=True)
class TransitionMemoryAccessV2:
    access_id: str
    binding: EventBinding
    memory_kind: str
    width_bytes: int
    address: CanonicalJson
    value: CanonicalJson | None
    exact_record: CanonicalJson
    _identity_checked: InitVar[bool] = False

    def __post_init__(self, _identity_checked: bool) -> None:
        if self.memory_kind not in _MEMORY_KINDS:
            raise AuthorityDataError("transition memory access has an invalid kind")
        if not 0 < self.width_bytes <= 4096:
            raise AuthorityDataError("transition memory width is invalid")
        if not isinstance(self.address, CanonicalJson) or not isinstance(
            self.exact_record, CanonicalJson
        ):
            raise AuthorityDataError("transition memory data is not canonical JSON")
        if self.memory_kind in {"write", "read_write"} and self.value is None:
            raise AuthorityDataError("transition memory write has no value")
        if self.value is not None and not isinstance(self.value, CanonicalJson):
            raise AuthorityDataError("transition memory value is not canonical JSON")
        if not _identity_checked:
            _check_id(self.access_id, "transition-memory", self.identity_payload())

    def identity_payload(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_payload(),
            "memory_kind": self.memory_kind,
            "width_bytes": self.width_bytes,
            "address": self.address.to_value(),
            "value": None if self.value is None else self.value.to_value(),
            "exact_record": self.exact_record.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.access_id, **self.identity_payload()}

    @classmethod
    def create(
        cls,
        *,
        binding: EventBinding,
        memory_kind: str,
        width_bytes: int,
        address: Any,
        value: Any | None,
        exact_record: Any,
    ) -> "TransitionMemoryAccessV2":
        canonical_address = CanonicalJson.of(address)
        canonical_value = None if value is None else CanonicalJson.of(value)
        canonical_record = CanonicalJson.of(exact_record)
        identity = {
            "binding": binding.to_payload(),
            "memory_kind": memory_kind,
            "width_bytes": width_bytes,
            "address": canonical_address.to_value(),
            "value": None if canonical_value is None else canonical_value.to_value(),
            "exact_record": canonical_record.to_value(),
        }
        return cls(
            _node_id("transition-memory", identity),
            binding,
            memory_kind,
            width_bytes,
            canonical_address,
            canonical_value,
            canonical_record,
            True,
        )

    @classmethod
    def parse(cls, value: Any) -> "TransitionMemoryAccessV2":
        row = _object(
            value,
            {"id", "binding", "memory_kind", "width_bytes", "address", "value", "exact_record"},
            "transition memory access",
        )
        return cls(
            access_id=_text(row["id"], "transition memory access ID"),
            binding=EventBinding.parse(row["binding"]),
            memory_kind=_text(row["memory_kind"], "transition memory kind"),
            width_bytes=_uint(row["width_bytes"], "transition memory width", maximum=4096),
            address=CanonicalJson.of(row["address"]),
            value=None if row["value"] is None else CanonicalJson.of(row["value"]),
            exact_record=CanonicalJson.of(row["exact_record"]),
        )


@dataclass(frozen=True, order=True)
class IndexedSemanticRecordV2:
    record_id: str
    family: str
    source_index: int
    exact_record: CanonicalJson
    _identity_checked: InitVar[bool] = False

    def __post_init__(self, _identity_checked: bool) -> None:
        _text(self.family, "semantic record family")
        _uint(self.source_index, "semantic record index")
        if not isinstance(self.exact_record, CanonicalJson):
            raise AuthorityDataError("semantic record is not canonical JSON")
        if not _identity_checked:
            _check_id(self.record_id, "transition-record", self.identity_payload())

    def identity_payload(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "source_index": self.source_index,
            "exact_record": self.exact_record.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.record_id, **self.identity_payload()}

    @classmethod
    def create(
        cls, *, family: str, source_index: int, exact_record: Any
    ) -> "IndexedSemanticRecordV2":
        canonical = CanonicalJson.of(exact_record)
        identity = {
            "family": family,
            "source_index": source_index,
            "exact_record": canonical.to_value(),
        }
        return cls(
            _node_id("transition-record", identity),
            family,
            source_index,
            canonical,
            True,
        )

    @classmethod
    def parse(cls, value: Any) -> "IndexedSemanticRecordV2":
        row = _object(value, {"id", "family", "source_index", "exact_record"}, "semantic record")
        return cls(
            record_id=_text(row["id"], "semantic record ID"),
            family=_text(row["family"], "semantic record family"),
            source_index=_uint(row["source_index"], "semantic record index"),
            exact_record=CanonicalJson.of(row["exact_record"]),
        )


@dataclass(frozen=True, order=True)
class TransitionExitV2:
    exit_id: str
    category: str
    source_kind: str
    source_index: int | None
    transfer_kind: str
    binding: EventBinding | None
    exact_record: CanonicalJson
    _identity_checked: InitVar[bool] = False

    def __post_init__(self, _identity_checked: bool) -> None:
        if self.category not in _EXIT_CATEGORIES:
            raise AuthorityDataError("transition exit has an invalid category")
        if self.source_kind not in {"outcome", "external_event"}:
            raise AuthorityDataError("transition exit has an invalid source kind")
        if self.source_kind == "outcome":
            if self.source_index is not None or self.binding is not None:
                raise AuthorityDataError("outcome exit unexpectedly has an event binding")
        else:
            if self.source_index is None or self.binding is None:
                raise AuthorityDataError("event exit lacks its exact event binding")
            _uint(self.source_index, "transition exit index")
            if self.binding.event_index != self.source_index:
                raise AuthorityDataError("transition exit event index is inconsistent")
        _text(self.transfer_kind, "transition transfer kind")
        if not isinstance(self.exact_record, CanonicalJson):
            raise AuthorityDataError("transition exit record is not canonical JSON")
        if not _identity_checked:
            _check_id(self.exit_id, "transition-exit", self.identity_payload())

    def identity_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "source_kind": self.source_kind,
            "source_index": self.source_index,
            "transfer_kind": self.transfer_kind,
            "binding": None if self.binding is None else self.binding.to_payload(),
            "exact_record": self.exact_record.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.exit_id, **self.identity_payload()}

    @classmethod
    def create(
        cls,
        *,
        category: str,
        source_kind: str,
        source_index: int | None,
        transfer_kind: str,
        binding: EventBinding | None,
        exact_record: Any,
    ) -> "TransitionExitV2":
        canonical = CanonicalJson.of(exact_record)
        identity = {
            "category": category,
            "source_kind": source_kind,
            "source_index": source_index,
            "transfer_kind": transfer_kind,
            "binding": None if binding is None else binding.to_payload(),
            "exact_record": canonical.to_value(),
        }
        return cls(
            _node_id("transition-exit", identity),
            category,
            source_kind,
            source_index,
            transfer_kind,
            binding,
            canonical,
            True,
        )

    @classmethod
    def parse(cls, value: Any) -> "TransitionExitV2":
        row = _object(
            value,
            {"id", "category", "source_kind", "source_index", "transfer_kind", "binding", "exact_record"},
            "transition exit",
        )
        index = row["source_index"]
        if index is not None:
            index = _uint(index, "transition exit index")
        return cls(
            exit_id=_text(row["id"], "transition exit ID"),
            category=_text(row["category"], "transition exit category"),
            source_kind=_text(row["source_kind"], "transition exit source kind"),
            source_index=index,
            transfer_kind=_text(row["transfer_kind"], "transition transfer kind"),
            binding=None if row["binding"] is None else EventBinding.parse(row["binding"]),
            exact_record=CanonicalJson.of(row["exact_record"]),
        )


@dataclass(frozen=True, order=True)
class TransitionFaultV2:
    fault_id: str
    binding: EventBinding
    exact_record: CanonicalJson
    _identity_checked: InitVar[bool] = False

    def __post_init__(self, _identity_checked: bool) -> None:
        if self.binding.event_kind != "fault":
            raise AuthorityDataError("transition fault has a non-fault binding")
        if not isinstance(self.exact_record, CanonicalJson):
            raise AuthorityDataError("transition fault record is not canonical JSON")
        if not _identity_checked:
            _check_id(self.fault_id, "transition-fault", self.identity_payload())

    def identity_payload(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_payload(),
            "exact_record": self.exact_record.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.fault_id, **self.identity_payload()}

    @classmethod
    def create(cls, *, binding: EventBinding, exact_record: Any) -> "TransitionFaultV2":
        canonical = CanonicalJson.of(exact_record)
        identity = {"binding": binding.to_payload(), "exact_record": canonical.to_value()}
        return cls(_node_id("transition-fault", identity), binding, canonical, True)

    @classmethod
    def parse(cls, value: Any) -> "TransitionFaultV2":
        row = _object(value, {"id", "binding", "exact_record"}, "transition fault")
        return cls(
            fault_id=_text(row["id"], "transition fault ID"),
            binding=EventBinding.parse(row["binding"]),
            exact_record=CanonicalJson.of(row["exact_record"]),
        )


@dataclass(frozen=True, order=True)
class UnsupportedTransitionEffectV2:
    effect_id: str
    code: str
    location: str
    detail: CanonicalJson
    _identity_checked: InitVar[bool] = False

    def __post_init__(self, _identity_checked: bool) -> None:
        _text(self.code, "unsupported-effect code", maximum=128)
        _text(self.location, "unsupported-effect location")
        if not isinstance(self.detail, CanonicalJson):
            raise AuthorityDataError("unsupported-effect detail is not canonical JSON")
        if not _identity_checked:
            _check_id(self.effect_id, "unsupported-effect", self.identity_payload())

    def identity_payload(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "location": self.location,
            "detail": self.detail.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.effect_id, **self.identity_payload()}

    @classmethod
    def create(cls, *, code: str, location: str, detail: Any) -> "UnsupportedTransitionEffectV2":
        canonical = CanonicalJson.of(detail)
        identity = {"code": code, "location": location, "detail": canonical.to_value()}
        return cls(
            _node_id("unsupported-effect", identity),
            code,
            location,
            canonical,
            True,
        )

    @classmethod
    def parse(cls, value: Any) -> "UnsupportedTransitionEffectV2":
        row = _object(value, {"id", "code", "location", "detail"}, "unsupported effect")
        return cls(
            effect_id=_text(row["id"], "unsupported-effect ID"),
            code=_text(row["code"], "unsupported-effect code", maximum=128),
            location=_text(row["location"], "unsupported-effect location"),
            detail=CanonicalJson.of(row["detail"]),
        )


@dataclass(frozen=True)
class TransitionSummaryV2:
    summary_id: str
    status: str
    unit: UnitBinding
    expression_model: str
    semantics_sha256: str
    inputs: tuple[TransitionInputV2, ...]
    outputs: tuple[TransitionOutputV2, ...]
    memory_accesses: tuple[TransitionMemoryAccessV2, ...]
    exits: tuple[TransitionExitV2, ...]
    guards: tuple[IndexedSemanticRecordV2, ...]
    faults: tuple[TransitionFaultV2, ...]
    ordered_events: tuple[IndexedSemanticRecordV2, ...]
    unsupported_effects: tuple[UnsupportedTransitionEffectV2, ...]
    _identity_checked: InitVar[bool] = False

    def __post_init__(self, _identity_checked: bool) -> None:
        if self.status not in _STATUS_VALUES:
            raise AuthorityDataError("transition summary has an invalid status")
        if not isinstance(self.unit, UnitBinding):
            raise AuthorityDataError("transition summary has no exact unit binding")
        _text(self.expression_model, "transition expression model")
        _digest(self.semantics_sha256, "transition semantics SHA-256")
        _unique_ids(self.inputs, "input_id", "transition inputs")
        _unique_ids(self.outputs, "output_id", "transition outputs")
        _unique_ids(self.memory_accesses, "access_id", "memory accesses")
        _unique_ids(self.exits, "exit_id", "transition exits")
        _unique_ids(self.guards, "record_id", "transition guards")
        _unique_ids(self.faults, "fault_id", "transition faults")
        _unique_ids(self.ordered_events, "record_id", "ordered events")
        _unique_ids(self.unsupported_effects, "effect_id", "unsupported effects")
        if tuple(sorted(self.inputs, key=lambda row: (row.category, row.name))) != self.inputs:
            raise AuthorityDataError("transition inputs are not canonically ordered")
        output_order = {"flag": 0, "register": 1, "stack": 2, "state": 3}
        if tuple(sorted(
            self.outputs,
            key=lambda row: (
                output_order[row.category],
                row.source_index,
                row.destination,
            ),
        )) != self.outputs:
            raise AuthorityDataError("transition outputs are not canonically ordered")
        _contiguous(self.memory_accesses, lambda row: row.binding.event_index, "memory accesses")
        _contiguous(self.guards, lambda row: row.source_index, "transition guards")
        _contiguous(self.faults, lambda row: row.binding.event_index, "transition faults")
        _contiguous_by_family(self.ordered_events, "ordered events")
        event_exits = tuple(row for row in self.exits if row.source_kind == "external_event")
        outcome_exits = tuple(row for row in self.exits if row.source_kind == "outcome")
        _contiguous(event_exits, lambda row: int(row.source_index), "external exits")
        if len(outcome_exits) != 1:
            raise AuthorityDataError("transition summary must contain one exact outcome")
        if self.exits != (*event_exits, *outcome_exits):
            raise AuthorityDataError("transition exits are not canonically ordered")
        if tuple(sorted(
            self.unsupported_effects, key=lambda row: row.effect_id
        )) != self.unsupported_effects:
            raise AuthorityDataError("unsupported effects are not canonically ordered")
        if (self.status == "complete") != (not self.unsupported_effects):
            raise AuthorityDataError("transition summary status does not match unsupported effects")
        if not _identity_checked:
            _check_id(self.summary_id, "transition-summary", self.identity_payload())

    def identity_payload(self) -> dict[str, Any]:
        return _summary_identity_payload(
            status=self.status,
            unit=self.unit,
            expression_model=self.expression_model,
            semantics_sha256=self.semantics_sha256,
            inputs=self.inputs,
            outputs=self.outputs,
            memory_accesses=self.memory_accesses,
            exits=self.exits,
            guards=self.guards,
            faults=self.faults,
            ordered_events=self.ordered_events,
            unsupported_effects=self.unsupported_effects,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": TRANSITION_SUMMARY_V2_FORMAT,
            "id": self.summary_id,
            **self.identity_payload(),
        }

    @classmethod
    def parse(cls, value: Any) -> "TransitionSummaryV2":
        row = _object(
            value,
            {
                "format",
                "id",
                "root_independent",
                "status",
                "unit",
                "expression_model",
                "semantics_sha256",
                "inputs",
                "outputs",
                "memory_accesses",
                "exits",
                "guards",
                "faults",
                "ordered_events",
                "unsupported_effects",
            },
            "transition summary",
        )
        if row["format"] != TRANSITION_SUMMARY_V2_FORMAT or row["root_independent"] is not True:
            raise AuthorityDataError("transition summary has invalid format or authority scope")
        return cls(
            summary_id=_text(row["id"], "transition summary ID"),
            status=_text(row["status"], "transition summary status"),
            unit=UnitBinding.parse(row["unit"]),
            expression_model=_text(row["expression_model"], "transition expression model"),
            semantics_sha256=_digest(row["semantics_sha256"], "transition semantics SHA-256"),
            inputs=tuple(TransitionInputV2.parse(item) for item in _array(row["inputs"], "transition inputs")),
            outputs=tuple(TransitionOutputV2.parse(item) for item in _array(row["outputs"], "transition outputs")),
            memory_accesses=tuple(TransitionMemoryAccessV2.parse(item) for item in _array(row["memory_accesses"], "memory accesses")),
            exits=tuple(TransitionExitV2.parse(item) for item in _array(row["exits"], "transition exits")),
            guards=tuple(IndexedSemanticRecordV2.parse(item) for item in _array(row["guards"], "transition guards")),
            faults=tuple(TransitionFaultV2.parse(item) for item in _array(row["faults"], "transition faults")),
            ordered_events=tuple(IndexedSemanticRecordV2.parse(item) for item in _array(row["ordered_events"], "ordered events")),
            unsupported_effects=tuple(UnsupportedTransitionEffectV2.parse(item) for item in _array(row["unsupported_effects"], "unsupported effects")),
        )


def derive_transition_summary_v2(
    unit_row: Mapping[str, Any], *, binary: BinaryBinding
) -> TransitionSummaryV2:
    """Derive one deterministic summary from an exact canonical unit."""

    try:
        _validate_canonical_unit(unit_row)
        unit = recompute_unit_binding(unit_row, binary=binary)
        semantics = _mapping(unit_row["semantics"], "machine-IR semantics")
        inputs = _derive_inputs(_mapping(semantics["pre_state"], "machine-IR pre-state"))
        outputs = _derive_outputs(semantics)
        accesses = _derive_memory_accesses(unit, _array(semantics["memory_events"], "memory events"))
        exits = _derive_exits(unit, semantics)
        guards = tuple(
            IndexedSemanticRecordV2.create(family="guard", source_index=index, exact_record=raw)
            for index, raw in enumerate(_mapping_array(semantics["edge_conditions"], "edge conditions"))
        )
        faults = tuple(
            TransitionFaultV2.create(
                binding=recompute_event_binding(unit, raw, event_index=index, event_kind="fault"),
                exact_record=raw,
            )
            for index, raw in enumerate(_mapping_array(semantics["faults"], "faults"))
        )
        ordered = tuple(
            IndexedSemanticRecordV2.create(family="ordered_event", source_index=index, exact_record=raw)
            for index, raw in enumerate(_mapping_array(semantics["ordered_events"], "ordered events"))
        ) + tuple(
            IndexedSemanticRecordV2.create(
                family="instruction_effect",
                source_index=index,
                exact_record=raw,
            )
            for index, raw in enumerate(
                _instruction_effect_rows(
                    semantics.get("instruction_effect_schedule")
                )
            )
        )
        ordered = tuple(
            sorted(ordered, key=lambda row: (row.family, row.source_index))
        )
        unsupported = _unsupported_effects(unit_row, semantics)
        status = "complete" if not unsupported else "incomplete"
        fields = {
            "status": status,
            "unit": unit,
            "expression_model": _text(unit_row["expression_model"], "machine-IR expression model"),
            "semantics_sha256": hashlib.sha256(canonical_json_bytes(semantics)).hexdigest(),
            "inputs": inputs,
            "outputs": outputs,
            "memory_accesses": accesses,
            "exits": exits,
            "guards": guards,
            "faults": faults,
            "ordered_events": ordered,
            "unsupported_effects": unsupported,
        }
        return TransitionSummaryV2(
            summary_id=_node_id(
                "transition-summary", _summary_identity_payload(**fields)
            ),
            _identity_checked=True,
            **fields,
        )
    except (AuthorityDataError, MachineIRAuthorityV2Error, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, TransitionSummaryV2Error):
            raise
        raise TransitionSummaryV2Error(f"cannot derive exact transition summary: {exc}") from exc


def check_transition_summary_v2(
    value: TransitionSummaryV2 | Mapping[str, Any],
    *,
    unit_row: Mapping[str, Any],
    binary: BinaryBinding,
) -> TransitionSummaryV2:
    """Parse and rederive a summary, rejecting stale or omitted semantics."""

    try:
        submitted = value if isinstance(value, TransitionSummaryV2) else TransitionSummaryV2.parse(value)
        expected = derive_transition_summary_v2(unit_row, binary=binary)
        if submitted != expected:
            raise TransitionSummaryV2Error(
                "transition summary contradicts its exact machine-IR unit"
            )
        return submitted
    except AuthorityDataError as exc:
        raise TransitionSummaryV2Error(f"transition summary is malformed: {exc}") from exc


validate_transition_summary_v2 = check_transition_summary_v2


def rebind_checked_transition_summary_v2(
    summary: TransitionSummaryV2,
    *,
    binary: BinaryBinding,
) -> TransitionSummaryV2:
    """Rebind already checked local semantics without deriving them again.

    Aggregate legacy consumers historically included a whole-inventory digest
    in every unit and event identity.  The v3 pipeline checks each summary at
    its exact-unit boundary, then uses this adapter only to satisfy that legacy
    identity shape.  No semantic proposal or machine-IR traversal occurs here.
    """

    unit = UnitBinding(
        binary=binary,
        unit_id=summary.unit.unit_id,
        rva_start=summary.unit.rva_start,
        rva_end=summary.unit.rva_end,
        unit_sha256=summary.unit.unit_sha256,
        instruction_bytes_sha256=summary.unit.instruction_bytes_sha256,
    )

    def event(binding: EventBinding) -> EventBinding:
        return EventBinding(
            unit=unit,
            event_index=binding.event_index,
            event_kind=binding.event_kind,
            instruction_rva=binding.instruction_rva,
            event_sha256=binding.event_sha256,
        )

    memory_accesses = tuple(
        TransitionMemoryAccessV2.create(
            binding=event(row.binding),
            memory_kind=row.memory_kind,
            width_bytes=row.width_bytes,
            address=row.address.to_value(),
            value=None if row.value is None else row.value.to_value(),
            exact_record=row.exact_record.to_value(),
        )
        for row in summary.memory_accesses
    )
    exits = tuple(
        TransitionExitV2.create(
            category=row.category,
            source_kind=row.source_kind,
            source_index=row.source_index,
            transfer_kind=row.transfer_kind,
            binding=None if row.binding is None else event(row.binding),
            exact_record=row.exact_record.to_value(),
        )
        for row in summary.exits
    )
    faults = tuple(
        TransitionFaultV2.create(
            binding=event(row.binding),
            exact_record=row.exact_record.to_value(),
        )
        for row in summary.faults
    )
    fields = {
        "status": summary.status,
        "unit": unit,
        "expression_model": summary.expression_model,
        "semantics_sha256": summary.semantics_sha256,
        "inputs": summary.inputs,
        "outputs": summary.outputs,
        "memory_accesses": memory_accesses,
        "exits": exits,
        "guards": summary.guards,
        "faults": faults,
        "ordered_events": summary.ordered_events,
        "unsupported_effects": summary.unsupported_effects,
    }
    return TransitionSummaryV2(
        summary_id=_node_id(
            "transition-summary", _summary_identity_payload(**fields)
        ),
        _identity_checked=True,
        **fields,
    )


def _validate_canonical_unit(row: Mapping[str, Any]) -> None:
    if not isinstance(row, Mapping):
        raise TransitionSummaryV2Error("machine-IR unit must be an object")
    if row.get("format") != MACHINE_IR_V2_FORMAT or row.get("record_kind") != "unit":
        raise TransitionSummaryV2Error("machine-IR unit is not a canonical v2 unit record")
    if row.get("status") not in {"qualified", "incomplete"}:
        raise TransitionSummaryV2Error("machine-IR unit has an invalid status")
    _text(row.get("expression_model"), "machine-IR expression model")
    semantics = _mapping(row.get("semantics"), "machine-IR semantics")
    required = {"pre_state", *_SEMANTIC_ARRAYS, "outcome", "stack_delta", "counts"}
    if not required <= set(semantics):
        raise TransitionSummaryV2Error("machine-IR semantics omit required canonical fields")
    _mapping(semantics["pre_state"], "machine-IR pre-state")
    for name in _SEMANTIC_ARRAYS:
        _mapping_array(semantics[name], f"machine-IR {name}")
    outcome = _mapping(semantics["outcome"], "machine-IR outcome")
    _text(outcome.get("kind"), "machine-IR outcome kind")
    if semantics["stack_delta"] is not None:
        _mapping(semantics["stack_delta"], "machine-IR stack delta")
    if semantics["counts"] is not None:
        counts = _mapping(semantics["counts"], "machine-IR semantic counts")
        for name in _SEMANTIC_ARRAYS:
            if name in counts and counts[name] != len(semantics[name]):
                raise TransitionSummaryV2Error(
                    f"machine-IR semantic count for {name} is stale"
                )
    # Force exact canonical-JSON validation before hashing the unit.
    canonical_json_bytes(row)


def _derive_inputs(pre_state: Mapping[str, Any]) -> tuple[TransitionInputV2, ...]:
    result: list[TransitionInputV2] = []
    for category, field in (("register", "registers"), ("flag", "flags")):
        values = pre_state.get(field)
        if values is None:
            continue
        for name, value in sorted(_mapping(values, f"pre-state {field}").items()):
            result.append(TransitionInputV2.create(category=category, name=_text(name, f"pre-state {field} name"), value=value))
    if "memory" in pre_state:
        result.append(TransitionInputV2.create(category="memory", name="memory", value=pre_state["memory"]))
    for name in sorted(set(pre_state) - {"registers", "flags", "memory"}):
        result.append(TransitionInputV2.create(category="state", name=_text(name, "pre-state field"), value=pre_state[name]))
    return tuple(sorted(result, key=lambda row: (row.category, row.name)))


def _derive_outputs(semantics: Mapping[str, Any]) -> tuple[TransitionOutputV2, ...]:
    result: list[TransitionOutputV2] = []
    for category, field, destination_field in (
        ("register", "register_writes", "register"),
        ("flag", "flag_writes", "flag"),
    ):
        for index, raw in enumerate(_mapping_array(semantics[field], field)):
            if destination_field not in raw or "value" not in raw:
                raise TransitionSummaryV2Error(f"{field} record omits destination or value")
            result.append(TransitionOutputV2.create(
                category=category,
                source_index=index,
                destination=_text(raw[destination_field], f"{field} destination"),
                value=raw["value"],
                exact_record=raw,
            ))
    stack_delta = semantics["stack_delta"]
    if stack_delta is not None:
        result.append(TransitionOutputV2.create(
            category="stack",
            source_index=0,
            destination="esp",
            value=stack_delta,
            exact_record=stack_delta,
        ))
    if semantics.get("fpu_state") is not None:
        result.append(TransitionOutputV2.create(
            category="state",
            source_index=0,
            destination="fpu_state",
            value=semantics["fpu_state"],
            exact_record=semantics["fpu_state"],
        ))
    order = {"flag": 0, "register": 1, "stack": 2, "state": 3}
    return tuple(sorted(result, key=lambda row: (order[row.category], row.source_index, row.destination)))


def _derive_memory_accesses(
    unit: UnitBinding, rows: Sequence[Mapping[str, Any]]
) -> tuple[TransitionMemoryAccessV2, ...]:
    result: list[TransitionMemoryAccessV2] = []
    for index, raw in enumerate(rows):
        kind = _text(raw.get("kind"), "memory-event kind")
        if kind not in _MEMORY_KINDS:
            raise TransitionSummaryV2Error("memory event has an unsupported access kind")
        width = _uint(raw.get("width"), "memory-event width", maximum=4096)
        if width == 0 or "address" not in raw:
            raise TransitionSummaryV2Error("memory event lacks width or address")
        if kind in {"write", "read_write"} and "value" not in raw:
            raise TransitionSummaryV2Error("memory write lacks an exact value")
        result.append(TransitionMemoryAccessV2.create(
            binding=recompute_event_binding(unit, raw, event_index=index),
            memory_kind=kind,
            width_bytes=width,
            address=raw["address"],
            value=raw.get("value"),
            exact_record=raw,
        ))
    return tuple(result)


def _instruction_effect_rows(value: Any) -> list[Mapping[str, Any]]:
    """Return exact schedule records from the canonical nullable wrapper."""

    if value is None:
        return []
    schedule = _mapping(value, "instruction effect schedule")
    return _mapping_array(
        schedule.get("records"), "instruction effect schedule records"
    )


def _derive_exits(unit: UnitBinding, semantics: Mapping[str, Any]) -> tuple[TransitionExitV2, ...]:
    result: list[TransitionExitV2] = []
    for index, raw in enumerate(_mapping_array(semantics["external_events"], "external events")):
        kind = _text(raw.get("kind"), "external-event kind")
        binding = recompute_event_binding(unit, raw, event_index=index)
        result.append(TransitionExitV2.create(
            category=_external_category(raw),
            source_kind="external_event",
            source_index=index,
            transfer_kind=kind,
            binding=binding,
            exact_record=raw,
        ))
    outcome = _mapping(semantics["outcome"], "machine-IR outcome")
    kind = _text(outcome.get("kind"), "machine-IR outcome kind")
    result.append(TransitionExitV2.create(
        category="call" if kind in {"internal_call", "indirect_call"} else "outcome",
        source_kind="outcome",
        source_index=None,
        transfer_kind=kind,
        binding=None,
        exact_record=outcome,
    ))
    return tuple(result)


def _external_category(row: Mapping[str, Any]) -> str:
    kind = str(row.get("kind", ""))
    abi = row.get("abi_contract")
    if "callback" in kind.lower() or (
        isinstance(abi, Mapping)
        and ("callback_source" in abi or "callback_abi" in abi)
    ):
        return "callback"
    if kind in {"internal_call", "indirect_call"}:
        return "call"
    return "external"


def _unsupported_effects(
    unit: Mapping[str, Any], semantics: Mapping[str, Any]
) -> tuple[UnsupportedTransitionEffectV2, ...]:
    result: list[UnsupportedTransitionEffectV2] = []
    if unit.get("status") != "qualified":
        result.append(UnsupportedTransitionEffectV2.create(
            code="unit_not_semantically_qualified",
            location="status",
            detail={"status": unit.get("status")},
        ))
    known_fields = {
        "pre_state",
        *_SEMANTIC_ARRAYS,
        "outcome",
        "stack_delta",
        "counts",
        "fpu_state",
        "instruction_effect_schedule",
    }
    for name in sorted(set(semantics) - known_fields):
        result.append(UnsupportedTransitionEffectV2.create(
            code="unknown_semantic_field",
            location=f"semantics.{name}",
            detail={"field": name, "value": semantics[name]},
        ))

    def visit(value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            if value.get("op") == "unsupported":
                result.append(UnsupportedTransitionEffectV2.create(
                    code="unsupported_expression",
                    location=path,
                    detail=value,
                ))
            for key in sorted(value):
                visit(value[key], f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}[{index}]")

    visit(semantics, "semantics")
    unique = {row.effect_id: row for row in result}
    return tuple(sorted(unique.values(), key=lambda row: row.effect_id))


def _node_id(prefix: str, payload: Any) -> str:
    digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()[:24]
    return f"{prefix}:{digest}"


def _summary_identity_payload(**fields: Any) -> dict[str, Any]:
    return {
        "root_independent": True,
        "status": fields["status"],
        "unit": fields["unit"].to_payload(),
        "expression_model": fields["expression_model"],
        "semantics_sha256": fields["semantics_sha256"],
        "inputs": [row.to_payload() for row in fields["inputs"]],
        "outputs": [row.to_payload() for row in fields["outputs"]],
        "memory_accesses": [row.to_payload() for row in fields["memory_accesses"]],
        "exits": [row.to_payload() for row in fields["exits"]],
        "guards": [row.to_payload() for row in fields["guards"]],
        "faults": [row.to_payload() for row in fields["faults"]],
        "ordered_events": [row.to_payload() for row in fields["ordered_events"]],
        "unsupported_effects": [row.to_payload() for row in fields["unsupported_effects"]],
    }


def _check_id(value: str, prefix: str, payload: Any) -> None:
    if value != _node_id(prefix, payload):
        raise AuthorityDataError(f"{prefix} ID is stale")


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise AuthorityDataError(f"{context} must be a lowercase SHA-256 digest")
    return value


def _text(value: Any, context: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise AuthorityDataError(f"{context} must be bounded nonempty text")
    return value


def _uint(value: Any, context: str, *, maximum: int = 0xFFFFFFFF) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise AuthorityDataError(f"{context} must be an unsigned integer")
    return value


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise AuthorityDataError(f"{context} must be an object with string keys")
    return value


def _object(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    row = _mapping(value, context)
    if set(row) != fields:
        raise AuthorityDataError(f"{context} has noncanonical fields")
    return row


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise AuthorityDataError(f"{context} must be an array")
    return value


def _mapping_array(value: Any, context: str) -> list[Mapping[str, Any]]:
    return [_mapping(item, f"{context}[{index}]") for index, item in enumerate(_array(value, context))]


def _unique_ids(rows: Sequence[Any], attribute: str, context: str) -> None:
    values = [getattr(row, attribute) for row in rows]
    if len(values) != len(set(values)):
        raise AuthorityDataError(f"{context} contain duplicate identities")


def _contiguous(rows: Sequence[Any], index_of: Any, context: str) -> None:
    if tuple(index_of(row) for row in rows) != tuple(range(len(rows))):
        raise AuthorityDataError(f"{context} are not in exact source order")


def _contiguous_by_family(
    rows: Sequence[IndexedSemanticRecordV2], context: str
) -> None:
    if tuple(sorted(rows, key=lambda row: (row.family, row.source_index))) != tuple(rows):
        raise AuthorityDataError(f"{context} are not canonically ordered")
    families: dict[str, list[int]] = {}
    for row in rows:
        families.setdefault(row.family, []).append(row.source_index)
    if any(values != list(range(len(values))) for values in families.values()):
        raise AuthorityDataError(f"{context} are not in exact source order")


__all__ = [
    "MACHINE_IR_V2_FORMAT",
    "TRANSITION_SUMMARY_V2_FORMAT",
    "IndexedSemanticRecordV2",
    "TransitionExitV2",
    "TransitionFaultV2",
    "TransitionInputV2",
    "TransitionMemoryAccessV2",
    "TransitionOutputV2",
    "TransitionSummaryV2",
    "TransitionSummaryV2Error",
    "UnsupportedTransitionEffectV2",
    "check_transition_summary_v2",
    "derive_transition_summary_v2",
    "rebind_checked_transition_summary_v2",
    "validate_transition_summary_v2",
]
