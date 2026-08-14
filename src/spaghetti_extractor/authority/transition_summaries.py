"""Derive and check native v3 transition records against exact units."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    CanonicalValueV3,
    canonical_json_bytes_v3,
)
from ..phase_framework_v3 import PhaseContextV3, map_units
from ._schema import (
    fail,
    mapping,
    require_record_ids,
    sequence,
    sorted_records,
    text,
    uint,
)
from .exact_units import EXACT_UNIT_CODEC_V3, ExactUnitV3
from .transition_records import (
    IndexedTransitionRecordV3,
    TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    TRANSITION_SUMMARY_CODEC_V3,
    TRANSITION_SUMMARY_RECORD_V3_SCHEMA,
    TransitionBinaryBindingV3,
    TransitionEventBindingV3,
    TransitionExitV3,
    TransitionFaultV3,
    TransitionInputV3,
    TransitionMemoryAccessV3,
    TransitionOutputV3,
    TransitionSummaryRecordV3,
    TransitionUnitBindingV3,
    UnsupportedTransitionEffectV3,
)


_MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"
_SEMANTIC_ARRAYS = (
    "register_writes",
    "flag_writes",
    "memory_events",
    "external_events",
    "faults",
    "ordered_events",
    "edge_conditions",
)


def _canonical(value: Any) -> bytes:
    return canonical_json_bytes_v3(value)


def _node_id(prefix: str, payload: Any) -> str:
    digest = hashlib.sha256(_canonical(payload)).hexdigest()[:24]
    return f"{prefix}:{digest}"


def _canonical_value(value: Any) -> CanonicalValueV3:
    return CanonicalValueV3.of(value)


def _input(category: str, name: str, value: Any) -> TransitionInputV3:
    canonical = _canonical_value(value)
    identity = {
        "category": category,
        "name": name,
        "value": canonical.to_value(),
    }
    return TransitionInputV3(
        input_id=_node_id("transition-input", identity),
        category=category,
        name=name,
        value=canonical,
    )


def _output(
    category: str,
    source_index: int,
    destination: str,
    value: Any,
    exact_record: Any,
) -> TransitionOutputV3:
    canonical_value = _canonical_value(value)
    canonical_record = _canonical_value(exact_record)
    identity = {
        "category": category,
        "source_index": source_index,
        "destination": destination,
        "value": canonical_value.to_value(),
        "exact_record": canonical_record.to_value(),
    }
    return TransitionOutputV3(
        output_id=_node_id("transition-output", identity),
        category=category,
        source_index=source_index,
        destination=destination,
        value=canonical_value,
        exact_record=canonical_record,
    )


def _event_binding(
    unit: TransitionUnitBindingV3,
    raw: Mapping[str, Any],
    index: int,
    *,
    event_kind: str | None = None,
) -> TransitionEventBindingV3:
    kind = text(
        raw.get("kind") if event_kind is None else event_kind,
        "transition event kind",
        maximum=64,
    )
    return TransitionEventBindingV3(
        unit=unit,
        event_index=index,
        event_kind=kind,
        instruction_rva=uint(
            raw.get("instruction_rva", unit.rva_start),
            "transition event instruction RVA",
        ),
        event_sha256=hashlib.sha256(_canonical(raw)).hexdigest(),
    )


def _memory_access(
    unit: TransitionUnitBindingV3,
    raw: Mapping[str, Any],
    index: int,
) -> TransitionMemoryAccessV3:
    if "address" not in raw:
        fail(
            "record_schema_mismatch",
            "exact memory event omits its address",
            "regenerate the exact-unit artifact with a complete memory event",
        )
    binding = _event_binding(unit, raw, index)
    width = uint(raw.get("width"), "transition memory width", maximum=4096)
    address = _canonical_value(raw["address"])
    value = None if raw.get("value") is None else _canonical_value(raw["value"])
    exact_record = _canonical_value(raw)
    identity = {
        "binding": binding.to_full_payload(),
        "memory_kind": binding.event_kind,
        "width_bytes": width,
        "address": address.to_value(),
        "value": None if value is None else value.to_value(),
        "exact_record": exact_record.to_value(),
    }
    return TransitionMemoryAccessV3(
        access_id=_node_id("transition-memory", identity),
        binding=binding,
        memory_kind=binding.event_kind,
        width_bytes=width,
        address=address,
        value=value,
        exact_record=exact_record,
    )


def _indexed_record(
    family: str, source_index: int, exact_record: Mapping[str, Any]
) -> IndexedTransitionRecordV3:
    canonical = _canonical_value(exact_record)
    identity = {
        "family": family,
        "source_index": source_index,
        "exact_record": canonical.to_value(),
    }
    return IndexedTransitionRecordV3(
        record_id=_node_id("transition-record", identity),
        family=family,
        source_index=source_index,
        exact_record=canonical,
    )


def _exit(
    *,
    category: str,
    source_kind: str,
    source_index: int | None,
    transfer_kind: str,
    binding: TransitionEventBindingV3 | None,
    exact_record: Mapping[str, Any],
) -> TransitionExitV3:
    canonical = _canonical_value(exact_record)
    identity = {
        "category": category,
        "source_kind": source_kind,
        "source_index": source_index,
        "transfer_kind": transfer_kind,
        "binding": None if binding is None else binding.to_full_payload(),
        "exact_record": canonical.to_value(),
    }
    return TransitionExitV3(
        exit_id=_node_id("transition-exit", identity),
        category=category,
        source_kind=source_kind,
        source_index=source_index,
        transfer_kind=transfer_kind,
        binding=binding,
        exact_record=canonical,
    )


def _fault(
    unit: TransitionUnitBindingV3,
    raw: Mapping[str, Any],
    index: int,
) -> TransitionFaultV3:
    binding = _event_binding(unit, raw, index, event_kind="fault")
    exact_record = _canonical_value(raw)
    identity = {
        "binding": binding.to_full_payload(),
        "exact_record": exact_record.to_value(),
    }
    return TransitionFaultV3(
        fault_id=_node_id("transition-fault", identity),
        binding=binding,
        exact_record=exact_record,
    )


def _unsupported_effect(
    code: str, location: str, detail: bytes
) -> UnsupportedTransitionEffectV3:
    canonical = CanonicalValueV3(detail)
    identity = {
        "code": code,
        "location": location,
        "detail": canonical.to_value(),
    }
    return UnsupportedTransitionEffectV3(
        effect_id=_node_id("unsupported-effect", identity),
        code=code,
        location=location,
        detail=canonical,
    )


def _expected_unit_binding(exact: ExactUnitV3) -> TransitionUnitBindingV3:
    return TransitionUnitBindingV3(
        binary=TransitionBinaryBindingV3(exact.pe_sha256, exact.unit_ir_sha256),
        unit_id=exact.unit_id,
        rva_start=exact.rva_start,
        rva_end=exact.rva_end,
        unit_sha256=exact.unit_sha256,
        instruction_bytes_sha256=exact.instruction_bytes_sha256,
    )


def _external_category(raw: Mapping[str, Any]) -> str:
    kind = str(raw.get("kind", ""))
    abi = raw.get("abi_contract")
    if "callback" in kind.lower() or (
        isinstance(abi, Mapping)
        and ("callback_source" in abi or "callback_abi" in abi)
    ):
        return "callback"
    if kind in {"internal_call", "indirect_call"}:
        return "call"
    return "external"


def _expected_unsupported(
    unit: Mapping[str, Any], semantics: Mapping[str, Any]
) -> set[tuple[str, str, bytes]]:
    result: set[tuple[str, str, bytes]] = set()
    if unit.get("status") != "qualified":
        result.add(
            (
                "unit_not_semantically_qualified",
                "status",
                _canonical({"status": unit.get("status")}),
            )
        )
    known_fields = {
        "pre_state",
        "register_writes",
        "flag_writes",
        "memory_events",
        "external_events",
        "edge_conditions",
        "faults",
        "ordered_events",
        "outcome",
        "stack_delta",
        "counts",
        "fpu_state",
        "instruction_effect_schedule",
    }
    for name in sorted(set(semantics) - known_fields):
        result.add(
            (
                "unknown_semantic_field",
                f"semantics.{name}",
                _canonical({"field": name, "value": semantics[name]}),
            )
        )

    def visit(value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            if value.get("op") == "unsupported":
                result.add(("unsupported_expression", path, _canonical(value)))
            for key in sorted(value):
                visit(value[key], f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}[{index}]")

    visit(semantics, "semantics")
    return result


def _validated_semantics(
    exact: ExactUnitV3,
) -> tuple[Mapping[str, Any], Mapping[str, Any], str]:
    unit = mapping(exact.unit.to_value(), "exact machine-IR unit")
    if (
        unit.get("format") != _MACHINE_IR_FORMAT
        or unit.get("record_kind") != "unit"
    ):
        fail(
            "record_schema_mismatch",
            f"exact unit {exact.unit_id!r} is not a canonical machine-IR unit",
            "regenerate the exact-unit artifact from canonical machine IR",
        )
    if unit.get("status") not in {"qualified", "incomplete"}:
        fail(
            "record_schema_mismatch",
            f"exact unit {exact.unit_id!r} has an invalid semantic status",
            "qualify the unit or mark it incomplete before transition projection",
        )
    expression_model = text(
        unit.get("expression_model"),
        "exact machine-IR expression model",
        maximum=512,
    )
    semantics = mapping(unit.get("semantics"), "exact machine-IR semantics")
    required = {
        "pre_state",
        *_SEMANTIC_ARRAYS,
        "outcome",
        "stack_delta",
        "counts",
    }
    if not required <= set(semantics):
        fail(
            "record_schema_mismatch",
            f"exact unit {exact.unit_id!r} omits required semantic fields",
            "regenerate the exact-unit artifact with complete canonical semantics",
        )
    mapping(semantics["pre_state"], "exact machine-IR pre-state")
    for name in _SEMANTIC_ARRAYS:
        for index, value in enumerate(sequence(semantics[name], f"exact {name}")):
            mapping(value, f"exact {name}[{index}]")
    outcome = mapping(semantics["outcome"], "exact transition outcome")
    text(outcome.get("kind"), "exact transition outcome kind")
    if semantics["stack_delta"] is not None:
        mapping(semantics["stack_delta"], "exact stack delta")
    if semantics["counts"] is not None:
        counts = mapping(semantics["counts"], "exact semantic counts")
        for name in _SEMANTIC_ARRAYS:
            if name in counts and counts[name] != len(semantics[name]):
                fail(
                    "record_schema_mismatch",
                    f"exact semantic count for {name!r} is stale",
                    "regenerate the exact-unit artifact with current semantic counts",
                )
    return unit, semantics, expression_model


def _derive_summary(exact: ExactUnitV3) -> TransitionSummaryRecordV3:
    unit, semantics, expression_model = _validated_semantics(exact)
    unit_binding = _expected_unit_binding(exact)

    pre_state = mapping(semantics["pre_state"], "exact machine-IR pre-state")
    inputs: list[TransitionInputV3] = []
    for category, source_name in (("register", "registers"), ("flag", "flags")):
        values = pre_state.get(source_name)
        if values is None:
            continue
        for name, value in sorted(
            mapping(values, f"exact pre-state {source_name}").items()
        ):
            inputs.append(
                _input(
                    category,
                    text(name, f"exact pre-state {source_name} name", maximum=512),
                    value,
                )
            )
    if "memory" in pre_state:
        inputs.append(_input("memory", "memory", pre_state["memory"]))
    for name in sorted(set(pre_state) - {"registers", "flags", "memory"}):
        inputs.append(
            _input(
                "state",
                text(name, "exact pre-state field", maximum=512),
                pre_state[name],
            )
        )
    native_inputs = tuple(sorted(inputs, key=lambda row: (row.category, row.name)))

    outputs: list[TransitionOutputV3] = []
    for category, source_name, destination_name in (
        ("register", "register_writes", "register"),
        ("flag", "flag_writes", "flag"),
    ):
        for index, value in enumerate(semantics[source_name]):
            raw = mapping(value, f"exact {source_name}[{index}]")
            if destination_name not in raw or "value" not in raw:
                fail(
                    "record_schema_mismatch",
                    f"exact {source_name} record omits its destination or value",
                    "regenerate the exact-unit artifact with complete write records",
                )
            outputs.append(
                _output(
                    category,
                    index,
                    text(
                        raw[destination_name],
                        f"exact {source_name} destination",
                        maximum=512,
                    ),
                    raw["value"],
                    raw,
                )
            )
    stack_delta = semantics["stack_delta"]
    if stack_delta is not None:
        outputs.append(_output("stack", 0, "esp", stack_delta, stack_delta))
    fpu_state = semantics.get("fpu_state")
    if fpu_state is not None:
        outputs.append(_output("state", 0, "fpu_state", fpu_state, fpu_state))
    output_order = {"flag": 0, "register": 1, "stack": 2, "state": 3}
    native_outputs = tuple(
        sorted(
            outputs,
            key=lambda row: (
                output_order[row.category],
                row.source_index,
                row.destination,
            ),
        )
    )

    memory_accesses = tuple(
        _memory_access(
            unit_binding,
            mapping(value, f"exact memory event {index}"),
            index,
        )
        for index, value in enumerate(semantics["memory_events"])
    )

    exits: list[TransitionExitV3] = []
    for index, value in enumerate(semantics["external_events"]):
        raw = mapping(value, f"exact external event {index}")
        kind = text(raw.get("kind"), "exact external-event kind")
        exits.append(
            _exit(
                category=_external_category(raw),
                source_kind="external_event",
                source_index=index,
                transfer_kind=kind,
                binding=_event_binding(unit_binding, raw, index),
                exact_record=raw,
            )
        )
    outcome = mapping(semantics["outcome"], "exact transition outcome")
    outcome_kind = text(outcome.get("kind"), "exact transition outcome kind")
    exits.append(
        _exit(
            category=(
                "call"
                if outcome_kind in {"internal_call", "indirect_call"}
                else "outcome"
            ),
            source_kind="outcome",
            source_index=None,
            transfer_kind=outcome_kind,
            binding=None,
            exact_record=outcome,
        )
    )

    guards = tuple(
        _indexed_record(
            "guard",
            index,
            mapping(value, f"exact guard {index}"),
        )
        for index, value in enumerate(semantics["edge_conditions"])
    )
    faults = tuple(
        _fault(
            unit_binding,
            mapping(value, f"exact fault {index}"),
            index,
        )
        for index, value in enumerate(semantics["faults"])
    )
    ordered_events = [
        _indexed_record(
            "ordered_event",
            index,
            mapping(value, f"exact ordered event {index}"),
        )
        for index, value in enumerate(semantics["ordered_events"])
    ]
    schedule = semantics.get("instruction_effect_schedule")
    if schedule is not None:
        schedule_row = mapping(schedule, "exact instruction effect schedule")
        for index, value in enumerate(
            sequence(
                schedule_row.get("records"),
                "exact instruction effect schedule records",
            )
        ):
            ordered_events.append(
                _indexed_record(
                    "instruction_effect",
                    index,
                    mapping(value, f"exact instruction effect {index}"),
                )
            )
    native_ordered_events = tuple(
        sorted(ordered_events, key=lambda row: (row.family, row.source_index))
    )
    unsupported_effects = tuple(
        sorted(
            (
                _unsupported_effect(code, location, detail)
                for code, location, detail in _expected_unsupported(unit, semantics)
            ),
            key=lambda row: row.effect_id,
        )
    )
    status = "complete" if not unsupported_effects else "incomplete"
    semantics_sha256 = hashlib.sha256(_canonical(semantics)).hexdigest()
    identity = {
        "root_independent": True,
        "status": status,
        "unit": unit_binding.to_payload(),
        "expression_model": expression_model,
        "semantics_sha256": semantics_sha256,
        "inputs": [row.to_payload() for row in native_inputs],
        "outputs": [row.to_payload() for row in native_outputs],
        "memory_accesses": [row.to_full_payload() for row in memory_accesses],
        "exits": [row.to_full_payload() for row in exits],
        "guards": [row.to_payload() for row in guards],
        "faults": [row.to_full_payload() for row in faults],
        "ordered_events": [row.to_payload() for row in native_ordered_events],
        "unsupported_effects": [row.to_payload() for row in unsupported_effects],
    }
    result = TransitionSummaryRecordV3(
        record_id=exact.record_id,
        summary_id=_node_id("transition-summary", identity),
        unit_id=exact.unit_id,
        unit_sha256=exact.unit_sha256,
        pe_sha256=exact.pe_sha256,
        unit_ir_sha256=exact.unit_ir_sha256,
        instruction_bytes_sha256=exact.instruction_bytes_sha256,
        rva_start=exact.rva_start,
        rva_end=exact.rva_end,
        status=status,
        expression_model=expression_model,
        semantics_sha256=semantics_sha256,
        inputs=native_inputs,
        outputs=native_outputs,
        memory_accesses=memory_accesses,
        exits=tuple(exits),
        guards=guards,
        faults=faults,
        ordered_events=native_ordered_events,
        unsupported_effects=unsupported_effects,
    )
    _check_summary_against_exact(result, exact)
    return result


def _check_summary_against_exact(
    submitted: TransitionSummaryRecordV3, exact: ExactUnitV3
) -> None:
    """Check the summary projection without rerunning the proposal generator."""

    unit = mapping(exact.unit.to_value(), "exact machine-IR unit")
    semantics = mapping(unit.get("semantics"), "exact machine-IR semantics")
    expected_unit = _expected_unit_binding(exact)
    if submitted.unit != expected_unit:
        fail(
            "transition_unit_contradiction",
            f"transition summary {submitted.summary_id!r} has a stale unit binding",
            "regenerate the summary from the exact-unit artifact",
        )
    if submitted.expression_model != unit.get("expression_model"):
        fail(
            "transition_projection_mismatch",
            f"transition summary {submitted.summary_id!r} has a stale expression model",
            "regenerate the summary from the exact-unit artifact",
        )
    expected_semantics_sha256 = hashlib.sha256(_canonical(semantics)).hexdigest()
    if submitted.semantics_sha256 != expected_semantics_sha256:
        fail(
            "transition_projection_mismatch",
            f"transition summary {submitted.summary_id!r} has a stale semantics digest",
            "regenerate the summary from the exact-unit artifact",
        )

    pre_state = mapping(semantics.get("pre_state"), "exact pre-state")
    expected_inputs: list[tuple[str, str, bytes]] = []
    for category, source_name in (("register", "registers"), ("flag", "flags")):
        values = pre_state.get(source_name)
        if values is None:
            continue
        for name, value in sorted(mapping(values, f"pre-state {source_name}").items()):
            expected_inputs.append((category, name, _canonical(value)))
    if "memory" in pre_state:
        expected_inputs.append(("memory", "memory", _canonical(pre_state["memory"])))
    for name in sorted(set(pre_state) - {"registers", "flags", "memory"}):
        expected_inputs.append(("state", name, _canonical(pre_state[name])))
    expected_inputs.sort(key=lambda row: (row[0], row[1]))
    observed_inputs = [
        (row.category, row.name, row.value.data) for row in submitted.inputs
    ]
    if observed_inputs != expected_inputs:
        fail(
            "transition_projection_mismatch",
            f"transition summary {submitted.summary_id!r} does not exactly project its inputs",
            "regenerate the summary from the exact-unit artifact",
        )

    expected_outputs: list[tuple[str, int, str, bytes, bytes]] = []
    for category, source_name, destination_name in (
        ("register", "register_writes", "register"),
        ("flag", "flag_writes", "flag"),
    ):
        raw_rows = semantics.get(source_name)
        if not isinstance(raw_rows, list):
            fail(
                "record_schema_mismatch",
                f"exact semantics field {source_name!r} is not an array",
                "regenerate the exact-unit artifact",
            )
        for index, raw_value in enumerate(raw_rows):
            raw = mapping(raw_value, f"exact {source_name} record")
            expected_outputs.append(
                (
                    category,
                    index,
                    text(raw.get(destination_name), f"{source_name} destination"),
                    _canonical(raw.get("value")),
                    _canonical(raw),
                )
            )
    stack_delta = semantics.get("stack_delta")
    if stack_delta is not None:
        expected_outputs.append(
            ("stack", 0, "esp", _canonical(stack_delta), _canonical(stack_delta))
        )
    fpu_state = semantics.get("fpu_state")
    if fpu_state is not None:
        expected_outputs.append(
            ("state", 0, "fpu_state", _canonical(fpu_state), _canonical(fpu_state))
        )
    output_order = {"flag": 0, "register": 1, "stack": 2, "state": 3}
    expected_outputs.sort(
        key=lambda row: (output_order[row[0]], row[1], row[2])
    )
    observed_outputs = [
        (
            row.category,
            row.source_index,
            row.destination,
            row.value.data,
            row.exact_record.data,
        )
        for row in submitted.outputs
    ]
    if observed_outputs != expected_outputs:
        fail(
            "transition_projection_mismatch",
            f"transition summary {submitted.summary_id!r} does not exactly project its outputs",
            "regenerate the summary from the exact-unit artifact",
        )

    memory_rows = semantics.get("memory_events")
    if not isinstance(memory_rows, list) or len(memory_rows) != len(
        submitted.memory_accesses
    ):
        fail(
            "transition_projection_mismatch",
            f"transition summary {submitted.summary_id!r} has a stale memory-event inventory",
            "regenerate the summary from the exact-unit artifact",
        )
    for index, (raw_value, observed) in enumerate(
        zip(memory_rows, submitted.memory_accesses, strict=True)
    ):
        raw = mapping(raw_value, "exact memory event")
        kind = text(raw.get("kind"), "memory-event kind")
        event_sha256 = hashlib.sha256(_canonical(raw)).hexdigest()
        expected_value = None if raw.get("value") is None else _canonical(raw["value"])
        if (
            observed.binding.unit != expected_unit
            or observed.binding.event_index != index
            or observed.binding.event_kind != kind
            or observed.binding.event_sha256 != event_sha256
            or observed.binding.instruction_rva
            != raw.get("instruction_rva", exact.rva_start)
            or observed.memory_kind != kind
            or observed.width_bytes != raw.get("width")
            or observed.address.data != _canonical(raw.get("address"))
            or (None if observed.value is None else observed.value.data)
            != expected_value
            or observed.exact_record.data != _canonical(raw)
        ):
            fail(
                "transition_projection_mismatch",
                f"transition summary {submitted.summary_id!r} has a stale memory event at index {index}",
                "regenerate the summary from the exact-unit artifact",
            )

    external_rows = semantics.get("external_events")
    if not isinstance(external_rows, list):
        fail(
            "record_schema_mismatch",
            "exact external-events field is not an array",
            "regenerate the exact-unit artifact",
        )
    if len(submitted.exits) != len(external_rows) + 1:
        fail(
            "transition_projection_mismatch",
            f"transition summary {submitted.summary_id!r} has a stale exit inventory",
            "regenerate the summary from the exact-unit artifact",
        )
    for index, (raw_value, observed) in enumerate(
        zip(external_rows, submitted.exits[:-1], strict=True)
    ):
        raw = mapping(raw_value, "exact external event")
        kind = text(raw.get("kind"), "external-event kind")
        event_sha256 = hashlib.sha256(_canonical(raw)).hexdigest()
        binding = observed.binding
        if (
            observed.category != _external_category(raw)
            or observed.source_kind != "external_event"
            or observed.source_index != index
            or observed.transfer_kind != kind
            or binding is None
            or binding.unit != expected_unit
            or binding.event_index != index
            or binding.event_kind != kind
            or binding.event_sha256 != event_sha256
            or binding.instruction_rva != raw.get("instruction_rva", exact.rva_start)
            or observed.exact_record.data != _canonical(raw)
        ):
            fail(
                "transition_projection_mismatch",
                f"transition summary {submitted.summary_id!r} has a stale "
                f"external event at index {index}",
                "regenerate the summary from the exact-unit artifact",
            )
    outcome = mapping(semantics.get("outcome"), "exact transition outcome")
    outcome_kind = text(outcome.get("kind"), "transition outcome kind")
    observed_outcome = submitted.exits[-1]
    if (
        observed_outcome.category
        != ("call" if outcome_kind in {"internal_call", "indirect_call"} else "outcome")
        or observed_outcome.source_kind != "outcome"
        or observed_outcome.source_index is not None
        or observed_outcome.binding is not None
        or observed_outcome.transfer_kind != outcome_kind
        or observed_outcome.exact_record.data != _canonical(outcome)
    ):
        fail(
            "transition_projection_mismatch",
            f"transition summary {submitted.summary_id!r} has a stale terminal outcome",
            "regenerate the summary from the exact-unit artifact",
        )

    def check_indexed(
        observed_rows: tuple[Any, ...],
        expected_rows: list[tuple[str, int, Mapping[str, Any]]],
        label: str,
    ) -> None:
        observed = [
            (row.family, row.source_index, row.exact_record.data)
            for row in observed_rows
        ]
        expected = [
            (family, index, _canonical(raw))
            for family, index, raw in expected_rows
        ]
        if observed != expected:
            fail(
                "transition_projection_mismatch",
                f"transition summary {submitted.summary_id!r} has stale {label}",
                "regenerate the summary from the exact-unit artifact",
            )

    guard_rows = semantics.get("edge_conditions")
    if not isinstance(guard_rows, list):
        fail(
            "record_schema_mismatch",
            "exact edge-conditions field is not an array",
            "regenerate the exact-unit artifact",
        )
    check_indexed(
        submitted.guards,
        [
            ("guard", index, mapping(raw, "exact guard"))
            for index, raw in enumerate(guard_rows)
        ],
        "guard inventory",
    )

    fault_rows = semantics.get("faults")
    if not isinstance(fault_rows, list) or len(fault_rows) != len(submitted.faults):
        fail(
            "transition_projection_mismatch",
            f"transition summary {submitted.summary_id!r} has a stale fault inventory",
            "regenerate the summary from the exact-unit artifact",
        )
    for index, (raw_value, observed) in enumerate(
        zip(fault_rows, submitted.faults, strict=True)
    ):
        raw = mapping(raw_value, "exact fault")
        event_sha256 = hashlib.sha256(_canonical(raw)).hexdigest()
        if (
            observed.binding.unit != expected_unit
            or observed.binding.event_index != index
            or observed.binding.event_kind != "fault"
            or observed.binding.event_sha256 != event_sha256
            or observed.binding.instruction_rva
            != raw.get("instruction_rva", exact.rva_start)
            or observed.exact_record.data != _canonical(raw)
        ):
            fail(
                "transition_projection_mismatch",
                f"transition summary {submitted.summary_id!r} has a stale fault at index {index}",
                "regenerate the summary from the exact-unit artifact",
            )

    ordered_rows = semantics.get("ordered_events")
    if not isinstance(ordered_rows, list):
        fail(
            "record_schema_mismatch",
            "exact ordered-events field is not an array",
            "regenerate the exact-unit artifact",
        )
    schedule = semantics.get("instruction_effect_schedule")
    schedule_rows: list[Any] = []
    if schedule is not None:
        schedule_mapping = mapping(schedule, "instruction effect schedule")
        raw_schedule_rows = schedule_mapping.get("records")
        if not isinstance(raw_schedule_rows, list):
            fail(
                "record_schema_mismatch",
                "instruction effect schedule records are not an array",
                "regenerate the exact-unit artifact",
            )
        schedule_rows = raw_schedule_rows
    expected_ordered = [
        ("ordered_event", index, mapping(raw, "exact ordered event"))
        for index, raw in enumerate(ordered_rows)
    ] + [
        ("instruction_effect", index, mapping(raw, "exact instruction effect"))
        for index, raw in enumerate(schedule_rows)
    ]
    expected_ordered.sort(key=lambda row: (row[0], row[1]))
    check_indexed(submitted.ordered_events, expected_ordered, "ordered-event inventory")

    expected_unsupported = _expected_unsupported(unit, semantics)
    observed_unsupported = {
        (row.code, row.location, row.detail.data)
        for row in submitted.unsupported_effects
    }
    if observed_unsupported != expected_unsupported or submitted.status != (
        "complete" if not expected_unsupported else "incomplete"
    ):
        fail(
            "transition_projection_mismatch",
            f"transition summary {submitted.summary_id!r} has stale unsupported-effect authority",
            "regenerate the summary from the exact-unit artifact",
        )


def _transform_transition_summary(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    exact = context.typed_record("exact_units", source, EXACT_UNIT_CODEC_V3).value
    if exact.record_id != source.record_id:
        fail(
            "exact_unit_record_id_mismatch",
            f"exact-unit record {source.record_id!r} contains unit ID {exact.record_id!r}",
            "preserve the same unit ID through the exact-unit artifact",
        )
    summary = _derive_summary(exact)
    return TRANSITION_SUMMARY_CODEC_V3.write(source.record_id, summary)


def check_transition_summaries_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    exact_records = sorted_records(context.records("exact_units"))
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (record.record_id for record in exact_records),
        "transition summaries",
    )
    exact_by_id: dict[str, ExactUnitV3] = {}
    for record in exact_records:
        exact = context.typed_record(
            "exact_units", record.record_id, EXACT_UNIT_CODEC_V3
        ).value
        if exact.record_id != record.record_id:
            fail(
                "exact_unit_record_id_mismatch",
                f"exact-unit record {record.record_id!r} contains unit ID {exact.record_id!r}",
                "preserve the same unit ID through the exact-unit artifact",
            )
        exact_by_id[record.record_id] = exact
    for output in outputs:
        submitted = TRANSITION_SUMMARY_CODEC_V3.read(output).value
        if submitted.record_id != output.record_id:
            fail(
                "transition_record_id_mismatch",
                f"transition-summary record {output.record_id!r} contains "
                f"unit ID {submitted.record_id!r}",
                "preserve the exact-unit ID in the transition-summary envelope",
            )
        _check_summary_against_exact(
            submitted, exact_by_id[output.record_id]
        )
        if (
            len(output.dependencies) != 1
            or output.dependencies[0].input_name != "exact_units"
            or output.dependencies[0].record_id != output.record_id
        ):
            fail(
                "incomplete_record_dependencies",
                f"transition-summary record {output.record_id!r} lacks its exact-unit dependency",
                "let the map_units runner attach the source dependency",
            )


TRANSITION_SUMMARIES_PHASE_V3 = map_units(
    name="transition-summaries-v3",
    version="2",
    source_input="exact_units",
    input_artifact_kinds={"exact_units": "exact-units-v3"},
    output_artifact_kind=TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    transform=_transform_transition_summary,
    completeness=check_transition_summaries_completeness_v3,
)


__all__ = [
    "TRANSITION_SUMMARIES_ARTIFACT_KIND_V3",
    "TRANSITION_SUMMARIES_PHASE_V3",
    "TRANSITION_SUMMARY_CODEC_V3",
    "TRANSITION_SUMMARY_RECORD_V3_SCHEMA",
    "TransitionSummaryRecordV3",
    "check_transition_summaries_completeness_v3",
]
