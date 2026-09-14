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


def _projection(value: object, context: str) -> MachineProjectionV1:
    return MachineProjectionV1.parse(value, context)


def _write_projection(
    projection: MachineProjectionV1,
    value: dict[str, object],
    env: dict[str, dict[str, object]],
    memory: dict[str, dict[str, object]],
) -> None:
    payload = projection.payload
    if projection.kind == "register":
        register = _text(payload.get("register"), "projection register")
        width = int(payload.get("width", 32))
        if width == 32:
            env[register] = copy.deepcopy(value)
        else:
            mask = (1 << width) - 1
            env[register] = _simplify_logical_arithmetic(
                {
                    "op": "or32",
                    "args": [
                        {
                            "op": "and32",
                            "args": [
                                env[register],
                                {
                                    "op": "const",
                                    "value": (~mask) & 0xFFFFFFFF,
                                    "width": 32,
                                },
                            ],
                        },
                        {
                            "op": "and32",
                            "args": [
                                value,
                                {"op": "const", "value": mask, "width": 32},
                            ],
                        },
                    ],
                }
            )
        return
    if projection.kind == "stack":
        address = _stack_address(env["esp"], int(payload.get("offset", 0)))
        memory[_expression_key(address)] = copy.deepcopy(value)
        return
    if projection.kind == "static_slot":
        address = {"op": "const", "value": int(payload["rva"]), "width": 32}
        memory[_expression_key(address)] = copy.deepcopy(value)
        return
    if projection.kind == "resource":
        _write_projection(
            _projection(payload.get("source"), "resource source"), value, env, memory
        )
        return
    if projection.kind == "atomic_object":
        return
    if projection.kind == "callback_handle":
        _write_projection(
            _projection(payload.get("source"), "callback-handle source"),
            value,
            env,
            memory,
        )
        return
    if projection.kind == "reference":
        _write_projection(
            _projection(payload.get("source"), "reference source"),
            value,
            env,
            memory,
        )
        return
    if projection.kind == "view":
        _write_projection(
            _projection(payload.get("base"), "view base"),
            value,
            env,
            memory,
        )
        return
    if projection.kind == "bytes_view":
        _write_projection(
            _projection(payload.get("base"), "byte-view base"), value, env, memory
        )
        return
    if projection.kind == "constant":
        return
    raise SemanticPathError(f"entry projection {projection.kind!r} is unsupported")


def _projection_memory_location(
    projection: MachineProjectionV1,
    env: Mapping[str, dict[str, object]],
) -> tuple[str, int] | None:
    """Return the exact memory cell owned by a projection, when it has one."""

    payload = projection.payload
    if projection.kind == "stack":
        address = _stack_address(env["esp"], int(payload.get("offset", 0)))
        return _expression_key(address), int(payload.get("width", 32)) // 8
    if projection.kind == "static_slot":
        address = {"op": "const", "value": int(payload["rva"]), "width": 32}
        return _expression_key(address), int(payload.get("width", 32)) // 8
    if projection.kind == "resource":
        return _projection_memory_location(
            _projection(payload.get("source"), "resource source"), env
        )
    if projection.kind == "atomic_object":
        source = _projection(payload.get("source"), "atomic-object source")
        if source.kind != "constant":
            return None
        address = {
            "op": "const",
            "value": int(source.payload["value"]),
            "width": int(source.payload["width"]),
        }
        return _expression_key(address), int(payload.get("width", 0))
    if projection.kind == "callback_handle":
        return _projection_memory_location(
            _projection(payload.get("source"), "callback-handle source"), env
        )
    if projection.kind == "reference":
        return _projection_memory_location(
            _projection(payload.get("source"), "reference source"), env
        )
    if projection.kind == "view":
        return _projection_memory_location(
            _projection(payload.get("base"), "view base"), env
        )
    return None


def _read_projection(
    projection: MachineProjectionV1,
    env: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]] | None = None,
    call_results: Mapping[tuple[int, str], dict[str, object]] | None = None,
) -> dict[str, object]:
    payload = projection.payload
    if projection.kind == "register":
        register = _text(payload.get("register"), "projection register")
        width = int(payload.get("width", 32))
        value = copy.deepcopy(env[register])
        if width == 32:
            return value
        return _simplify_logical_arithmetic(
            {
                "op": "and32",
                "args": [
                    value,
                    {"op": "const", "value": (1 << width) - 1, "width": 32},
                ],
            }
        )
    if projection.kind == "stack":
        address = _stack_address(env["esp"], int(payload.get("offset", 0)))
        return _memory_value(memory, address)
    if projection.kind == "static_slot":
        address = {"op": "const", "value": int(payload["rva"]), "width": 32}
        return _memory_value(memory, address)
    if projection.kind == "constant":
        return {
            "op": "const",
            "value": int(payload.get("value", 0)),
            "width": int(payload.get("width", 32)),
        }
    if projection.kind == "resource":
        return _read_projection(
            _projection(payload.get("source"), "resource source"),
            env,
            memory,
            flags,
            call_results,
        )
    if projection.kind == "callback_handle":
        return _read_projection(
            _projection(payload.get("source"), "callback-handle source"),
            env,
            memory,
            flags,
            call_results,
        )
    if projection.kind == "reference":
        return _read_projection(
            _projection(payload.get("source"), "reference source"),
            env,
            memory,
            flags,
            call_results,
        )
    if projection.kind == "view":
        return _read_projection(
            _projection(payload.get("base"), "view base"),
            env,
            memory,
            flags,
            call_results,
        )
    if projection.kind == "bytes_view":
        return _read_projection(
            _projection(payload.get("base"), "byte-view base"),
            env,
            memory,
            flags,
            call_results,
        )
    raise SemanticPathError(f"exit projection {projection.kind!r} is unsupported")


def _read_call_projection(
    projection: MachineProjectionV1,
    event: Mapping[str, object],
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    call_results: Mapping[tuple[int, str], dict[str, object]],
) -> dict[str, object]:
    payload = projection.payload
    if projection.kind == "register":
        register = _text(payload.get("register"), "call projection register")
        inputs = _object(event.get("register_inputs"), "external register inputs")
        if register not in inputs:
            raise SemanticPathError(f"external event has no {register} input")
        return _substitute(inputs[register], env, flags, memory, call_results)
    if projection.kind == "stack":
        offset = int(payload.get("offset", 0))
        matches = [
            row
            for row in _rows(event.get("stack_inputs", []), "external stack inputs")
            if row.get("offset") == offset
        ]
        if len(matches) > 1:
            raise SemanticPathError(
                f"external event stack offset {offset} is ambiguous"
            )
        if matches:
            return _substitute(
                matches[0].get("value"), env, flags, memory, call_results
            )
        # Machine events intentionally carry only the stack words observed by
        # the unit that contains the call.  Call arguments are commonly
        # prepared by preceding units, so a checked service projection may
        # name a call-time stack word that is absent from that local capture.
        # Reconstruct it from the event's exact call-time ESP and the
        # persistent symbolic memory instead of treating unit boundaries as
        # argument-lifetime boundaries.
        inputs = _object(event.get("register_inputs"), "external register inputs")
        if "esp" not in inputs:
            raise SemanticPathError(
                f"external event stack offset {offset} has no call-time ESP"
            )
        call_esp = _substitute(inputs["esp"], env, flags, memory, call_results)
        return _memory_value(memory, _stack_address(call_esp, offset))
    if projection.kind in {"constant", "static_slot", "resource", "reference", "view"}:
        return _read_projection(projection, env, memory, flags, call_results)
    if projection.kind == "offset":
        base = _read_call_projection(
            _projection(payload.get("base"), "call projection offset base"),
            event,
            env,
            flags,
            memory,
            call_results,
        )
        return _stack_address(base, int(payload.get("offset_bytes", 0)))
    raise SemanticPathError(
        f"service argument projection {projection.kind!r} is unsupported"
    )


def _service_argument_load_expressions(
    binding: _BoundServiceEvent,
    event: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    """Return exact expressions whose loads supply a bound service argument."""

    if binding.physical_argument_expressions:
        return binding.physical_argument_expressions
    if binding.argument_expressions:
        return binding.argument_expressions
    result: list[Mapping[str, object]] = []
    stack_inputs = _rows(event.get("stack_inputs", []), "external stack inputs")
    register_inputs = _object(event.get("register_inputs"), "external register inputs")
    for projection in binding.argument_projections:
        if projection.kind != "stack":
            continue
        offset = int(projection.payload.get("offset", 0))
        matches = [row for row in stack_inputs if row.get("offset") == offset]
        if len(matches) > 1:
            raise SemanticPathError(
                f"external event stack offset {offset} is ambiguous"
            )
        if matches:
            result.append(_object(matches[0].get("value"), "external stack input"))
            continue
        call_esp = register_inputs.get("esp")
        if not isinstance(call_esp, Mapping):
            raise SemanticPathError(
                f"external event stack offset {offset} has no call-time ESP"
            )
        result.append(
            {
                "op": "load",
                "address": _stack_address(
                    _object(call_esp, "external call-time ESP"), offset
                ),
                "width": int(projection.payload.get("width", 32)) // 8,
            }
        )
    return tuple(result)


def _read_result_projection(
    projection: MachineProjectionV1,
    execution: _ExecutedUnit,
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    call_results: Mapping[tuple[int, str], dict[str, object]],
) -> dict[str, object]:
    if projection.kind != "control_condition":
        return _read_projection(projection, env, memory, flags, call_results)
    outcome = execution.outcome
    if outcome.get("kind") != "branch" or not isinstance(
        outcome.get("condition"), Mapping
    ):
        raise SemanticPathViolation(
            "control-condition result does not project a machine branch"
        )
    return copy.deepcopy(dict(outcome["condition"]))


def _bind_call_result(
    projection: MachineProjectionV1,
    event_index: int,
    value: dict[str, object],
    call_results: dict[tuple[int, str], dict[str, object]],
    memory: dict[str, dict[str, object]],
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    old_memory: Mapping[str, dict[str, object]],
    event: Mapping[str, object] | None = None,
) -> None:
    payload = projection.payload
    if projection.kind == "register":
        call_results[
            (event_index, _text(payload.get("register"), "result register"))
        ] = value
        return
    if projection.kind == "static_slot":
        address = {"op": "const", "value": int(payload["rva"]), "width": 32}
        memory[_expression_key(address)] = value
        return
    if projection.kind == "memory":
        address_projection = _projection(payload.get("address"), "result address")
        address = (
            _read_call_projection(
                address_projection,
                event,
                env,
                flags,
                old_memory,
                call_results,
            )
            if payload.get("at") == "call" and event is not None
            else _read_projection(
                address_projection, env, old_memory, flags, call_results
            )
        )
        memory[_expression_key(address)] = value
        return
    if projection.kind == "resource":
        _bind_call_result(
            _projection(payload.get("source"), "resource result source"),
            event_index,
            value,
            call_results,
            memory,
            env,
            flags,
            old_memory,
            event,
        )
        return
    if projection.kind in {"callback_handle", "reference", "view"}:
        source_field = "base" if projection.kind == "view" else "source"
        _bind_call_result(
            _projection(payload.get(source_field), f"{projection.kind} result source"),
            event_index,
            value,
            call_results,
            memory,
            env,
            flags,
            old_memory,
            event,
        )
        return
    raise SemanticPathError(
        f"service result projection {projection.kind!r} is unsupported"
    )


def _bind_service_writebacks(
    binding: _BoundServiceEvent,
    event: Mapping[str, object],
    trace_index: int,
    machine_event_index: int,
    call_results: dict[tuple[int, str], dict[str, object]],
    memory: dict[str, dict[str, object]],
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    old_memory: Mapping[str, dict[str, object]],
) -> None:
    for writeback in binding.writebacks:
        if writeback.success_condition != "hresult_succeeded_eax":
            raise SemanticPathError(
                "service writeback success condition is unsupported"
            )
        status = {
            "op": "service_result",
            "index": trace_index,
            "width": 32,
        }
        value = {
            "op": "ite",
            "args": [
                {
                    "op": "eq",
                    "args": [
                        {
                            "op": "and32",
                            "args": [
                                status,
                                {
                                    "op": "const",
                                    "value": 0x80000000,
                                    "width": 32,
                                },
                            ],
                        },
                        {"op": "const", "value": 0, "width": 32},
                    ],
                },
                {
                    "op": "service_writeback",
                    "index": trace_index,
                    "parameter_index": writeback.parameter_index,
                    "width": 64,
                },
                {"op": "const", "value": 0, "width": 64},
            ],
        }
        _bind_call_result(
            writeback.projection,
            machine_event_index,
            value,
            call_results,
            memory,
            env,
            flags,
            old_memory,
            event,
        )


def _substitute(
    value: object,
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    call_results: Mapping[tuple[int, str], dict[str, object]],
) -> dict[str, object]:
    row = _object(value, "machine expression")
    op = row.get("op")
    if op == "reg":
        return copy.deepcopy(env[_text(row.get("name"), "register expression")])
    if op == "flag":
        return copy.deepcopy(flags[_text(row.get("name"), "flag expression")])
    if op == "load":
        address = _substitute(row.get("address"), env, flags, memory, call_results)
        known = memory.get(_expression_key(address))
        if known is not None:
            return copy.deepcopy(known)
        width = int(row.get("width", 4))
        byte_read = _logical_byte_read(address, width)
        if byte_read is not None:
            return byte_read
        return {
            "op": "load",
            "address": address,
            "width": width,
        }
    if op == "call_response":
        call_index = row.get("call_index")
        register = _text(row.get("register"), "call-response register")
        if not isinstance(call_index, int) or isinstance(call_index, bool):
            raise SemanticPathError("call-response index is invalid")
        return copy.deepcopy(
            call_results.get(
                (call_index, register),
                {
                    "op": "symbol",
                    "name": f"machine_call_{call_index}_{register}",
                    "width": int(row.get("width", 32)),
                },
            )
        )
    if op == "call_flag":
        call_index = row.get("call_index")
        flag = _text(row.get("flag"), "call-response flag")
        if not isinstance(call_index, int) or isinstance(call_index, bool):
            raise SemanticPathError("call-response flag index is invalid")
        return copy.deepcopy(
            call_results.get(
                (call_index, f"flag:{flag}"),
                {
                    "op": "symbol",
                    "name": f"machine_call_{call_index}_{flag}",
                    "width": 1,
                },
            )
        )
    result = {key: copy.deepcopy(item) for key, item in row.items() if key != "args"}
    if "args" in row:
        if not isinstance(row["args"], list):
            raise SemanticPathError("machine expression arguments are malformed")
        result["args"] = [
            _substitute(item, env, flags, memory, call_results)
            if isinstance(item, Mapping)
            else item
            for item in row["args"]
        ]
    return _simplify_logical_arithmetic(result)


def _resolve_entry_projections(
    value: object,
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
) -> object:
    """Resolve explicit entry snapshots before call-time substitution."""

    if isinstance(value, Mapping):
        if value.get("op") == "entry_projection":
            if set(value) != {"op", "projection"}:
                raise SemanticPathError("entry-projection expression fields differ")
            return _read_projection(
                _projection(value.get("projection"), "entry-projection expression"),
                env,
                memory,
                flags,
                {},
            )
        return {
            str(key): _resolve_entry_projections(item, env, flags, memory)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_resolve_entry_projections(item, env, flags, memory) for item in value]
    return copy.deepcopy(value)


def _logical_byte_read(
    address: Mapping[str, object], width: int
) -> dict[str, object] | None:
    if width != 1:
        return None
    resolved = _byte_view_offset(address)
    if resolved is None:
        return None
    name, index = resolved
    return {
        "op": "byte_read",
        "name": name,
        "index": index,
    }


def _memory_value(
    memory: Mapping[str, dict[str, object]], address: dict[str, object]
) -> dict[str, object]:
    known = memory.get(_expression_key(address))
    if known is None:
        raise SemanticPathError("observable expression reads unmapped memory")
    return copy.deepcopy(known)


def _normalize_machine_event(
    event: Mapping[str, object],
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    call_results: Mapping[tuple[int, str], dict[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {
        key: copy.deepcopy(value)
        for key, value in event.items()
        if key
        not in {"arguments", "stack_inputs", "register_inputs", "flag_inputs", "target"}
    }
    for field in ("register_inputs", "flag_inputs"):
        raw = _object(event.get(field, {}), f"external {field}")
        result[field] = {
            str(name): _substitute(value, env, flags, memory, call_results)
            for name, value in raw.items()
        }
    arguments = _rows(event.get("arguments", []), "external arguments")
    result["arguments"] = [
        _substitute(value, env, flags, memory, call_results) for value in arguments
    ]
    stack_inputs: list[dict[str, object]] = []
    for raw in _rows(event.get("stack_inputs", []), "external stack inputs"):
        row = dict(raw)
        row["value"] = _substitute(raw.get("value"), env, flags, memory, call_results)
        stack_inputs.append(row)
    result["stack_inputs"] = stack_inputs
    if isinstance(event.get("target"), Mapping):
        result["target"] = _substitute(
            event.get("target"), env, flags, memory, call_results
        )
    unresolved_responses = [
        row
        for row in _collect_ops(result, "symbol")
        if str(row.get("name", "")).startswith("machine_call_")
    ]
    if unresolved_responses:
        raise SemanticPathError(
            "external event input depends on an unavailable call response"
        )
    return result


def _normalize_outcome(
    value: object,
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    call_results: Mapping[tuple[int, str], dict[str, object]],
) -> dict[str, object]:
    raw = _object(value, "machine outcome")
    result = copy.deepcopy(dict(raw))
    for field in ("value", "target", "condition"):
        if isinstance(raw.get(field), Mapping):
            result[field] = _substitute(raw[field], env, flags, memory, call_results)
    return result


def _require_logical_expression(
    value: object,
    context: str,
    *,
    memory_authority: Mapping[str, object] | None = None,
) -> None:
    for unsupported in (
        "symbol",
        "call_response",
        "call_flag",
        "service_machine_result",
        "service_machine_flag",
        "machine_undefined",
        "reg",
        "flag",
    ):
        matches = _collect_ops(value, unsupported)
        if matches:
            names = sorted(
                {
                    str(row.get("name") or row.get("register") or unsupported)
                    for row in matches
                }
            )
            raise SemanticPathError(
                f"{context} depends on unmapped machine values: {', '.join(names)}"
            )
    for load in _collect_ops(value, "load"):
        if not _logical_load_is_authorized(load, memory_authority):
            raise SemanticPathError(
                f"{context} depends on unmapped machine values: load"
            )


def _logical_load_is_authorized(
    load: Mapping[str, object], memory_authority: Mapping[str, object] | None
) -> bool:
    if memory_authority is None:
        return False
    width = load.get("width")
    address = load.get("address")
    if width not in {1, 2, 4, 8} or not isinstance(address, Mapping):
        return False
    if any(
        _collect_ops(address, op)
        for op in (
            "load",
            "symbol",
            "call_response",
            "call_flag",
            "service_machine_result",
            "service_machine_flag",
            "reg",
            "flag",
        )
    ):
        return False
    parameters = {str(item) for item in memory_authority.get("parameters", [])}
    service_results = {
        int(item)
        for item in memory_authority.get("service_results", [])
        if isinstance(item, int) and not isinstance(item, bool)
    }
    parameter_anchors = {
        str(item.get("name"))
        for item in _collect_ops(address, "parameter")
        if isinstance(item.get("name"), str)
    }
    service_anchors = {
        int(item.get("index"))
        for item in _collect_ops(address, "service_result")
        if isinstance(item.get("index"), int)
        and not isinstance(item.get("index"), bool)
    }
    return bool(
        (parameter_anchors and parameter_anchors <= parameters)
        or (service_anchors and service_anchors <= service_results)
    )


def _result_binding(value: Mapping[str, object], context: str) -> dict[str, object]:
    if set(value) not in (
        {"id", "projection"},
        {"id", "projection", "decoding"},
        {"id", "projection", "encoding"},
        {"id", "projection", "decoding", "encoding"},
    ):
        raise SemanticPathError(f"{context} fields differ")
    decoding = value.get("decoding")
    if decoding is not None and not isinstance(decoding, Mapping):
        raise SemanticPathError(f"{context} decoding is malformed")
    return {
        "projection": _projection(value.get("projection"), f"{context} projection"),
        "decoding": None if decoding is None else copy.deepcopy(dict(decoding)),
    }


def _decode_result_value(
    binding: Mapping[str, object], observed: Mapping[str, object]
) -> dict[str, object]:
    decoding = binding.get("decoding")
    if decoding is None:
        return copy.deepcopy(dict(observed))
    if not isinstance(decoding, Mapping):
        raise SemanticPathError("result decoding is malformed")
    return _simplify_logical_arithmetic(_replace_projected_value(decoding, observed))


def _derived_relation_equality(
    observed: Mapping[str, object],
    expected: Mapping[str, object],
    identity: str,
) -> dict[str, object]:
    observed_view = _byte_view_offset(observed)
    expected_view = _byte_view_offset(expected)
    if observed_view is not None or expected_view is not None:
        if (
            observed_view is None
            or expected_view is None
            or observed_view[0] != expected_view[0]
        ):
            raise SemanticPathError(
                f"derived relation {identity!r} compares incompatible byte views"
            )
        left, right = observed_view[1], expected_view[1]
    else:
        left = copy.deepcopy(dict(observed))
        right = copy.deepcopy(dict(expected))
    return {"op": "eq", "args": [left, right]}


def _logical_input_expression(identity: str, kind: str) -> dict[str, object]:
    if kind == "bytes":
        return {"op": "bytes_address", "name": identity}
    return {"op": "parameter", "name": identity}


def _replace_target_state_inputs(
    value: Mapping[str, object],
    target_values: Mapping[str, dict[str, object]],
) -> dict[str, object]:
    if value.get("op") == "state_input":
        name = _text(value.get("name"), "derived state-input name")
        replacement = target_values.get(f"source_state:{name}")
        if replacement is None:
            raise SemanticPathError(
                f"derived relation references unavailable source state {name!r}"
            )
        return copy.deepcopy(replacement)
    result: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(item, Mapping):
            result[str(key)] = _replace_target_state_inputs(item, target_values)
        elif isinstance(item, list):
            result[str(key)] = [
                _replace_target_state_inputs(child, target_values)
                if isinstance(child, Mapping)
                else copy.deepcopy(child)
                for child in item
            ]
        else:
            result[str(key)] = copy.deepcopy(item)
    return _simplify_logical_arithmetic(result)


def _replace_projected_value(
    value: Mapping[str, object], projected: Mapping[str, object]
) -> dict[str, object]:
    if value.get("op") == "projected_value":
        return copy.deepcopy(dict(projected))
    result: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(item, Mapping):
            result[str(key)] = _replace_projected_value(item, projected)
        elif isinstance(item, list):
            result[str(key)] = [
                _replace_projected_value(child, projected)
                if isinstance(child, Mapping)
                else copy.deepcopy(child)
                for child in item
            ]
        else:
            result[str(key)] = copy.deepcopy(item)
    return result
