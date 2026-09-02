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

def _atomic_action_models(
    *,
    operation: Mapping[str, object],
    interface: ProofKernelComponentInterface,
    logical: object,
    parameter_projections: Mapping[str, MachineProjectionV1],
    units: Mapping[str, Mapping[str, object]],
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
) -> list[dict[str, object]]:
    """Project exact authoritative RMW actions into the logical world model."""

    service_effect_ids = {
        effect_id
        for service in interface.services
        if service.identity in set(getattr(logical, "allowed_service_ids"))
        for effect_id in service.effect_ids
    }
    direct_effect_ids = set(getattr(logical, "effect_ids")) - service_effect_ids
    logical_effects = {
        row.identity: row
        for row in interface.effects
        if row.identity in direct_effect_ids
    }
    bound_effects = _rows(operation.get("effects", []), "operation effects")
    if not logical_effects and not bound_effects:
        if any(item.kind == "atomic_object" for item in parameter_projections.values()):
            raise SemanticPathError("atomic-object parameter has no direct atomic effect")
        return []
    if set(logical_effects) != direct_effect_ids:
        raise SemanticPathError("operation effect inventory is stale")
    by_effect: dict[str, list[Mapping[str, object]]] = {
        effect_id: [] for effect_id in logical_effects
    }
    for row in bound_effects:
        effect_id = _text(row.get("effect_id"), "bound effect id")
        if effect_id not in by_effect:
            raise SemanticPathError("machine binding contains an unknown direct effect")
        by_effect[effect_id].append(row)

    models: list[dict[str, object]] = []
    seen_parameters: set[str] = set()
    for effect_id, effect in logical_effects.items():
        parameter_id = effect.target_id
        if (
            effect.kind != "memory"
            or effect.operation not in {"compare_exchange", "exchange"}
            or parameter_id is None
            or parameter_id not in parameter_projections
        ):
            raise SemanticPathError(
                "direct effects require a checked atomic RMW world model"
            )
        projection = parameter_projections[parameter_id]
        if projection.kind != "atomic_object" or parameter_id in seen_parameters:
            raise SemanticPathError("atomic effect target projection is invalid")
        seen_parameters.add(parameter_id)
        payload = projection.payload
        unit_id = _text(payload.get("unit_id"), "atomic projection unit")
        unit = units.get(unit_id)
        if unit is None:
            raise SemanticPathError("atomic projection unit is outside the operation")
        semantics = _object(unit.get("semantics"), "atomic unit semantics")
        canonical_transfer = "transfer_v2" in semantics
        if canonical_transfer:
            matches = [
                row
                for row in _rows(
                    semantics.get("transfer_atomic_effects"),
                    "canonical transfer atomic effects",
                )
                if row.get("action_id") == payload.get("action_id")
            ]
            profile_id = matches[0].get("profile_id") if len(matches) == 1 else None
        else:
            # Compatibility for the mature proof-kernel unit tests. Production
            # V5 refinement always enters through the canonical transfer view.
            graph = _object(semantics.get("memory_actions"), "memory-action graph")
            authority = _object(graph.get("authority"), "memory-action authority")
            if (
                graph.get("status") != "complete"
                or authority.get("authoritative") is not True
            ):
                raise SemanticPathError("atomic projection graph is not authoritative")
            matches = [
                row
                for row in _rows(graph.get("actions"), "memory actions")
                if row.get("id") == payload.get("action_id")
            ]
            profile_id = graph.get("profile_id")
        if len(matches) != 1:
            raise SemanticPathError("atomic projection action is stale")
        action = matches[0]
        operation_kind = action.get("operation")
        if (
            operation_kind not in {"compare_exchange", "exchange"}
            or (
                action.get("width_bytes") != payload.get("width")
                and action.get("width") != payload.get("width")
            )
            or profile_id != payload.get("profile_id")
        ):
            raise SemanticPathError("atomic projection action shape is stale")
        raw_source_indices = action.get("source_memory_event_indices")
        if not isinstance(raw_source_indices, list) or any(
            not isinstance(index, int) or isinstance(index, bool) or index < 0
            for index in raw_source_indices
        ):
            raise SemanticPathError("atomic source event indices are malformed")
        expected_refs = {(unit_id, index) for index in raw_source_indices}
        observed_refs = {
            (
                _text(row.get("unit_id"), "atomic effect unit"),
                int(row.get("index", -1)),
            )
            for row in by_effect[effect_id]
            if row.get("family") == "memory_event"
        }
        if observed_refs != expected_refs or len(observed_refs) != len(by_effect[effect_id]):
            raise SemanticPathError("atomic effect does not bind the exact RMW events")
        if operation_kind == "compare_exchange":
            if "transfer_v2" in semantics:
                expected_raw = action.get("expected")
                desired_raw = action.get("desired")
            else:
                transition = _object(action.get("compare"), "compare/exchange operands")
                expected_raw = transition.get("expected")
                desired_raw = transition.get("desired")
            expected = _substitute(expected_raw, env, flags, memory, {})
            desired = _substitute(desired_raw, env, flags, memory, {})
            _require_logical_expression(expected, "atomic expected value")
        else:
            expected = None
            desired_raw = (
                action.get("desired")
                if "transfer_v2" in semantics
                else _object(
                    action.get("transition"), "exchange transition"
                ).get("written")
            )
            desired = _substitute(desired_raw, env, flags, memory, {})
        _require_logical_expression(desired, "atomic desired value")
        models.append(
            {
                "effect_id": effect_id,
                "parameter_id": parameter_id,
                "action_id": (
                    action["action_id"] if canonical_transfer else action["id"]
                ),
                "profile_id": profile_id,
                "width": (
                    action["width"]
                    if canonical_transfer
                    else action["width_bytes"]
                ),
                "operation": operation_kind,
                "expected": expected,
                "desired": desired,
            }
        )
    return sorted(models, key=canonical_sha256_v3)
