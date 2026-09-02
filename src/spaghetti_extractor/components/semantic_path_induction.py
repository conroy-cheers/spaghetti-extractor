# ruff: noqa: F401
"""Machine-derived finite path models for portable component refinement.

This module contains no target knowledge and accepts no expected behavior.  It
symbolically executes exact machine-IR summaries, replacing only explicitly
bound service events with shared symbolic responses.  The resulting path set
is consumed by CBMC to compare portable C against every represented machine
path.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .inductive_receipts import CheckedInductiveMachineReceiptV1
from .inductive_relation import InductiveCutpointRelationV1
from .inductive_source import InductiveSourcePlanV1
from .interface_ir import ProofKernelComponentInterface
from .machine_binding import MachineProjectionV1
from .semantic_arithmetic import (
    byte_view_offset as _byte_view_offset,
    simplify_logical_arithmetic as _simplify_logical_arithmetic,
)
from .semantic_path_errors import SemanticPathError, SemanticPathViolation
from .semantic_services import (
    BoundServiceEvent as _BoundServiceEvent,
    service_event_index as _service_event_index,
)


_TRANSFER_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_TRANSFER_FLAGS = ("cf", "zf", "sf", "of", "pf", "df", "af")

from .semantic_path_model import (
    _State,
    _ExecutedUnit,
)
from .semantic_path_values import (
    _unit_rva,
    _stack_address,
    _private_stack_offset,
    _expression_key,
    _collect_ops,
    _object,
    _rows,
    _array,
    _strings,
    _text,
    _uint,
    _uint_rows,
)
from .semantic_path_projection import (
    _logical_input_expression,
    _replace_target_state_inputs,
    _replace_projected_value,
    _result_binding,
    _decode_result_value,
    _derived_relation_equality,
    _projection,
    _write_projection,
    _projection_memory_location,
    _read_projection,
    _read_call_projection,
    _service_argument_load_expressions,
    _read_result_projection,
    _bind_call_result,
    _substitute,
    _logical_byte_read,
    _memory_value,
    _normalize_machine_event,
    _normalize_outcome,
    _require_logical_expression,
    _logical_load_is_authorized,
)
from .semantic_path_atomics import (
    _atomic_action_models,
)
from .semantic_path_execution import (
    _execute_semantic_unit,
    _execute_transfer_v2_unit,
)
from .semantic_path_operations import (
    build_operation_path_model,
    _parameter_machine_word,
    _checked_interaction_reference_constraints,
    _nullable_same_origin_input,
    _nonnull_minimum_remaining,
    _trace_reference_constraints,
    _constant_callback_word,
)

def build_inductive_segment_models(
    operation: Mapping[str, object],
    interface: ProofKernelComponentInterface,
    source_plan: InductiveSourcePlanV1,
    machine_receipt: CheckedInductiveMachineReceiptV1,
    relation: InductiveCutpointRelationV1,
    service_bindings: object,
    *,
    max_events_per_segment: int = 64,
) -> dict[str, object]:
    """Symbolically execute every exact finite segment between cutpoints."""

    relation.validate_for(interface, source_plan, machine_receipt)
    operation_id = _text(operation.get("operation_id"), "operation id")
    if operation_id != source_plan.operation_id:
        raise SemanticPathError("inductive operation identity differs")
    logical = interface.operation_index()[operation_id]
    types = interface.type_index()
    if any(
        types[value.type_id].kind not in {"scalar", "enum", "resource", "bytes"}
        for value in logical.parameters
    ):
        raise SemanticPathError(
            "inductive segments require scalar, resource, or byte-view parameters"
        )
    if any(
        types[value.type_id].kind not in {"scalar", "enum", "resource"}
        for value in logical.results
    ):
        raise SemanticPathError(
            "inductive segments require scalar or resource results"
        )

    parameters = {
        str(row["id"]): _projection(
            row.get("projection"), "parameter projection"
        )
        for row in _rows(operation.get("parameters"), "operation parameters")
    }
    results = {
        str(row["id"]): _result_binding(row, "inductive result")
        for row in _rows(operation.get("results"), "operation results")
    }
    if set(parameters) != {row.identity for row in logical.parameters}:
        raise SemanticPathError("inductive parameter projection inventory differs")
    if set(results) != {row.identity for row in logical.results}:
        raise SemanticPathError("inductive result projection inventory differs")

    units = {
        _text(row.get("id"), "semantic unit id"): row
        for row in _rows(operation.get("units"), "semantic operation units")
    }
    receipt_shape = machine_receipt.shape.to_value()
    assert isinstance(receipt_shape, dict)
    expected_unit_hashes = {
        str(row["unit_id"]): str(row["semantics_sha256"])
        for row in receipt_shape["semantic_units"]
        if isinstance(row, Mapping)
    }
    observed_unit_hashes = {
        unit_id: canonical_sha256_v3(
            _object(unit.get("semantics"), "semantic unit semantics")
        )
        for unit_id, unit in units.items()
    }
    if observed_unit_hashes != expected_unit_hashes:
        raise SemanticPathError(
            "inductive semantic operation differs from its exact machine receipt"
        )

    service_index = {row.identity: row for row in interface.services}
    event_index = _service_event_index(service_bindings, service_index)
    relation_index = {item.unit_id: item for item in relation.cutpoints}
    completion_index = {
        item.segment_id: item.completion_id
        for item in relation.completion_segments
    }
    inventory = machine_receipt.segment_inventory.to_value()
    assert isinstance(inventory, dict)
    models: list[dict[str, object]] = []
    for raw_segment in _rows(inventory.get("segments"), "inductive segments"):
        segment_id = _text(raw_segment.get("segment_id"), "segment id")
        source = _object(raw_segment.get("source"), "segment source")
        target = _object(raw_segment.get("target"), "segment target")
        env = {
            name: {
                "op": "symbol",
                "name": f"machine_{name}",
                "width": 32,
            }
            for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        flags = {
            name: {
                "op": "symbol",
                "name": f"machine_{name}",
                "width": 1,
            }
            for name in ("cf", "zf", "sf", "of", "pf", "df")
        }
        state = _State(
            env,
            flags,
            {},
            copy.deepcopy(env),
            copy.deepcopy(flags),
            {},
            [],
            [],
            set(),
            set(),
            set(),
            set(),
        )
        source_kind = _text(source.get("kind"), "segment source kind")
        source_id = _text(source.get("id"), "segment source id")
        if source_kind == "operation_entry":
            for parameter in logical.parameters:
                _write_projection(
                    parameters[parameter.identity],
                    _logical_input_expression(
                        parameter.identity, types[parameter.type_id].kind
                    ),
                    state.env,
                    state.memory,
                )
            source_phase = None
        elif source_kind == "cutpoint":
            cutpoint = relation_index.get(source_id)
            if cutpoint is None:
                raise SemanticPathError("segment source cutpoint is not related")
            for value in cutpoint.values:
                if value.mode in {"logical_carry", "logical_definition"}:
                    continue
                assert value.projection is not None
                assert value.encoding is not None
                _write_projection(
                    value.projection,
                    copy.deepcopy(dict(value.encoding)),
                    state.env,
                    state.memory,
                )
            for derived in cutpoint.derived:
                _write_projection(
                    derived.projection,
                    copy.deepcopy(dict(derived.expression)),
                    state.env,
                    state.memory,
                )
            source_phase = cutpoint.phase_id
        else:
            raise SemanticPathError("segment source kind is unsupported")

        edges = _rows(raw_segment.get("edges"), "segment edges")
        edge_by_source: dict[str, Mapping[str, object]] = {}
        for edge in edges:
            edge_source = _text(edge.get("source_unit_id"), "segment edge source")
            if edge_source in edge_by_source:
                raise SemanticPathError(
                    "one exact segment contains multiple selected edges from a unit"
                )
            edge_by_source[edge_source] = edge
        last_execution: _ExecutedUnit | None = None
        unit_ids = _strings(raw_segment.get("unit_ids"), "segment units")
        for unit_id in unit_ids:
            if unit_id in state.visited or unit_id not in units:
                raise SemanticPathError("segment unit path is cyclic or stale")
            state.visited.add(unit_id)
            last_execution = _execute_semantic_unit(
                unit_id=unit_id,
                unit=units[unit_id],
                state=state,
                event_index=event_index,
                state_write_locations={},
                max_events=max_events_per_segment,
            )
            selected_edge = edge_by_source.get(unit_id)
            if selected_edge is not None:
                target_unit_id = _text(
                    selected_edge.get("target_unit_id"), "segment edge target"
                )
                if target_unit_id not in units:
                    raise SemanticPathError(
                        "segment edge target is absent from the operation"
                    )
                target_rva = _unit_rva(units[target_unit_id])
                guard = last_execution.edge_guards.get(target_rva)
                if guard is None:
                    raise SemanticPathError(
                        "segment edge is absent from the executed unit control summary"
                    )
                state.guards.append(copy.deepcopy(guard))
        if last_execution is None:
            raise SemanticPathError("exact segment contains no machine units")
        if state.pending_service_stack_writes:
            raise SemanticPathError(
                "machine stack write crosses an inductive cutpoint without a frame relation"
            )
        if set(edge_by_source) - set(unit_ids):
            raise SemanticPathError("segment edge source is absent from its unit path")

        target_kind = _text(target.get("kind"), "segment target kind")
        target_id = _text(target.get("id"), "segment target id")
        target_values: dict[str, dict[str, object]] = {}
        relation_checks: list[dict[str, object]] = []
        target_phase: str | None = None
        expected_results: dict[str, dict[str, object]] = {}
        completion_id: str | None = None
        if target_kind == "cutpoint":
            cutpoint = relation_index.get(target_id)
            if cutpoint is None:
                raise SemanticPathError("segment target cutpoint is not related")
            target_phase = cutpoint.phase_id
            observed_values: dict[tuple[str, str], dict[str, object]] = {}
            for value in cutpoint.values:
                if value.mode == "logical_carry":
                    target_values[f"source_state:{value.identity}"] = {
                        "op": "state_input",
                        "name": value.identity,
                    }
                    continue
                if value.mode == "logical_definition":
                    assert value.encoding is not None
                    target_values[f"source_state:{value.identity}"] = (
                        copy.deepcopy(dict(value.encoding))
                    )
                    continue
                assert value.projection is not None
                try:
                    observed = _read_projection(
                        value.projection,
                        state.env,
                        state.memory,
                        state.flags,
                        last_execution.call_results,
                    )
                except SemanticPathError as exc:
                    raise SemanticPathError(
                        f"segment {segment_id} cannot read target cutpoint "
                        f"value {value.kind}:{value.identity}: {exc}"
                    ) from exc
                observed_values[(value.kind, value.identity)] = observed
                if value.kind == "parameter":
                    logical_type = types[
                        next(
                            item.type_id
                            for item in logical.parameters
                            if item.identity == value.identity
                        )
                    ]
                    target_values[f"parameter:{value.identity}"] = (
                        _logical_input_expression(
                            value.identity, logical_type.kind
                        )
                    )
                else:
                    assert value.decoding is not None
                    target_values[f"source_state:{value.identity}"] = (
                        _simplify_logical_arithmetic(
                            _replace_projected_value(value.decoding, observed)
                        )
                    )
            for value in cutpoint.values:
                if value.mode in {"logical_carry", "logical_definition"}:
                    continue
                assert value.encoding is not None
                expected = _replace_target_state_inputs(
                    value.encoding, target_values
                )
                try:
                    relation_checks.append(
                        _derived_relation_equality(
                            observed_values[(value.kind, value.identity)],
                            expected,
                            f"value:{value.kind}:{value.identity}",
                        )
                    )
                except SemanticPathError as exc:
                    raise SemanticPathError(
                        f"segment {segment_id} target relation failed: {exc}"
                    ) from exc
            for derived in cutpoint.derived:
                observed = _read_projection(
                    derived.projection,
                    state.env,
                    state.memory,
                    state.flags,
                    last_execution.call_results,
                )
                expected = _replace_target_state_inputs(
                    derived.expression, target_values
                )
                relation_checks.append(
                    _derived_relation_equality(observed, expected, derived.identity)
                )
        elif target_kind == "operation_exit":
            completion_id = completion_index.get(segment_id)
            if completion_id is None:
                raise SemanticPathError("operation-exit segment has no completion relation")
            expected_results = {
                result.identity: _decode_result_value(
                    results[result.identity],
                    _read_result_projection(
                        results[result.identity]["projection"],
                        last_execution,
                        state.env,
                        state.flags,
                        state.memory,
                        last_execution.call_results,
                    ),
                )
                for result in logical.results
            }
        else:
            raise SemanticPathError("segment target kind is unsupported")
        for index, expression in enumerate(state.guards):
            _require_logical_expression(
                expression,
                f"inductive segment {segment_id} guard {index}",
            )
        for index, expression in enumerate(relation_checks):
            _require_logical_expression(
                expression,
                f"inductive segment {segment_id} relation check {index}",
            )
        for value_id, expression in target_values.items():
            _require_logical_expression(
                expression,
                f"inductive segment {segment_id} target value {value_id}",
            )
        for result_id, expression in expected_results.items():
            _require_logical_expression(
                expression,
                f"inductive segment {segment_id} result {result_id}",
            )
        models.append(
            {
                "segment_id": segment_id,
                "source": {
                    "kind": source_kind,
                    "id": source_id,
                    "phase_id": source_phase,
                },
                "target": {
                    "kind": target_kind,
                    "id": target_id,
                    "phase_id": target_phase,
                    "completion_id": completion_id,
                },
                "guards": copy.deepcopy(state.guards),
                "relation_checks": relation_checks,
                "target_values": target_values,
                "results": expected_results,
                "trace": copy.deepcopy(state.trace),
                "private_stack_writes": [
                    {"offset": offset, "width": width}
                    for offset, width in sorted(state.private_stack_writes)
                ],
                "service_argument_stack_writes": [
                    {"offset": offset, "width": width}
                    for offset, width in sorted(
                        state.service_argument_stack_writes
                    )
                ],
            }
        )
    return {
        "operation_id": operation_id,
        "machine_receipt_sha256": machine_receipt.receipt_sha256,
        "relation_sha256": relation.relation_sha256,
        "segments": sorted(models, key=lambda item: str(item["segment_id"])),
        "model_sha256": canonical_sha256_v3(
            sorted(models, key=lambda item: str(item["segment_id"]))
        ),
    }
