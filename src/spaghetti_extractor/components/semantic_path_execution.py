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


def _write_owned_memory(
    memory: dict[str, dict[str, object]],
    state_write_locations: Mapping[str, tuple[str, int]],
    owner: tuple[str, int],
    value: dict[str, object],
) -> None:
    """Update every loader-relative/original-VA alias for one owned cell."""

    for key, candidate in state_write_locations.items():
        if candidate == owner:
            memory[key] = copy.deepcopy(value)


def _constant_predicate(value: Mapping[str, object]) -> bool | None:
    if value.get("op") == "true":
        return True
    if value.get("op") == "false":
        return False
    if value.get("op") == "const" and value.get("width") == 1:
        observed = value.get("value")
        if observed in {0, 1}:
            return bool(observed)
    return None


def _bound_service_result_expression(
    binding: _BoundServiceEvent,
    trace_index: int,
) -> dict[str, object]:
    projection = binding.result
    width = 64
    while projection is not None:
        if projection.kind in {"register", "memory"}:
            candidate = projection.payload.get("width")
            if isinstance(candidate, int) and not isinstance(candidate, bool):
                width = candidate
            break
        if projection.kind == "view":
            projection = _projection(
                projection.payload.get("base"), "service result view base"
            )
            continue
        if projection.kind in {"resource", "callback_handle", "reference"}:
            projection = _projection(
                projection.payload.get("source"),
                f"service {projection.kind} result source",
            )
            continue
        break
    return {
        "op": "service_result",
        "index": trace_index,
        "width": width,
    }


def _bind_service_result_rule(
    *,
    state: "_State",
    binding: _BoundServiceEvent,
    trace_index: int,
    status: Mapping[str, object],
) -> None:
    rule = binding.result_rule
    if rule is None:
        return
    if rule.get("kind") != "hresult_success_or_preserved_initial":
        raise SemanticPathError("service result rule is unsupported")
    failure_value = _resolve_entry_projections(
        rule.get("failure_value"),
        state.entry_env,
        state.entry_flags,
        state.entry_memory,
    )
    if not isinstance(failure_value, Mapping):
        raise SemanticPathError("service failure value is malformed")
    state.guards.append(
        {
            "op": "ite",
            "args": [
                {
                    "op": "eq",
                    "args": [
                        {
                            "op": "and32",
                            "args": [
                                copy.deepcopy(dict(status)),
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
                {"op": "const", "value": 1, "width": 1},
                {
                    "op": "eq",
                    "args": [
                        _bound_service_result_expression(binding, trace_index),
                        copy.deepcopy(dict(failure_value)),
                    ],
                },
            ],
        }
    )


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
    _bind_service_writebacks,
    _substitute,
    _resolve_entry_projections,
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


def _execute_semantic_unit(
    *,
    unit_id: str,
    unit: Mapping[str, object],
    state: _State,
    event_index: Mapping[tuple[str, int], _BoundServiceEvent],
    state_write_locations: Mapping[str, tuple[str, int]],
    max_events: int,
) -> _ExecutedUnit:
    """Apply one exact unit to symbolic state exactly once."""

    semantics = _object(unit.get("semantics"), "machine unit semantics")
    transfer = semantics.get("transfer_v2")
    if isinstance(transfer, Mapping):
        return _execute_transfer_v2_unit(
            unit_id=unit_id,
            transfer=transfer,
            external_events=_rows(
                semantics.get("external_events", []),
                "transfer external events",
            ),
            state=state,
            event_index=event_index,
            state_write_locations=state_write_locations,
            max_events=max_events,
        )
    if semantics.get("faults"):
        raise SemanticPathError("machine faults require explicit operation outcomes")
    old_env = copy.deepcopy(state.env)
    old_flags = copy.deepcopy(state.flags)
    old_memory = copy.deepcopy(state.memory)
    call_results: dict[tuple[int, str], dict[str, object]] = {}
    external_events = _rows(
        semantics.get("external_events", []), "machine external events"
    )
    event_memory = copy.deepcopy(old_memory)
    ordered_service_writes: set[tuple[int, int]] = set()
    consumed_service_writes: set[tuple[int, int]] = set()

    def process_external_event(machine_event_index: int) -> None:
        machine_event = external_events[machine_event_index]
        bound = event_index.get((unit_id, machine_event_index))
        if bound is None:
            raise SemanticPathError(
                f"external event {unit_id}:{machine_event_index} has no logical service binding"
            )
        if len(state.trace) >= max_events:
            raise SemanticPathError("service-event budget exceeded")
        register_inputs = _object(
            machine_event.get("register_inputs"), "external register inputs"
        )
        # Argument transducers are expressed in the callee's physical frame.
        # Rebase register-relative loads onto the event's exact call-time
        # capture before resolving them against the ordered memory state.
        call_env = copy.deepcopy(old_env)
        call_env.update(
            {
                register: _substitute(
                    value, old_env, old_flags, event_memory, call_results
                )
                for register, value in register_inputs.items()
            }
        )
        for expression in _service_argument_load_expressions(bound, machine_event):
            for load in _collect_ops(expression, "load"):
                address = _substitute(
                    load.get("address"),
                    call_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                width = load.get("width")
                offset = _private_stack_offset(address)
                if (
                    isinstance(width, int)
                    and not isinstance(width, bool)
                    and offset is not None
                    and 0 <= offset <= 65536 - width
                    and (offset, width) in state.pending_service_stack_writes
                ):
                    state.pending_service_stack_writes.remove((offset, width))
                    state.service_argument_stack_writes.add((offset, width))
                    consumed_service_writes.add((offset, width))
        arguments = (
            [
                _substitute(
                    expression,
                    call_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                for expression in bound.argument_expressions
            ]
            if bound.argument_expressions
            else [
                _read_call_projection(
                    projection,
                    machine_event,
                    old_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                for projection in bound.argument_projections
            ]
        )
        state.guards.extend(
            _substitute(
                _resolve_entry_projections(
                    guard,
                    state.entry_env,
                    state.entry_flags,
                    state.entry_memory,
                ),
                call_env,
                old_flags,
                event_memory,
                call_results,
            )
            for guard in bound.argument_guards
        )
        trace_index = len(state.trace)
        normalized_event = _normalize_machine_event(
            machine_event,
            old_env,
            old_flags,
            event_memory,
            call_results,
        )
        if bound.argument_expressions:
            normalized_event["arguments"] = copy.deepcopy(arguments)
        for register in (
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
        ):
            if register in bound.preserved_registers or (
                register == "esp" and bound.stack_pointer_adjustment is not None
            ):
                preserved_value = _substitute(
                    register_inputs[register],
                    old_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                if register == "esp" and bound.stack_pointer_adjustment:
                    preserved_value = _simplify_logical_arithmetic(
                        {
                            "op": "add32",
                            "args": [
                                preserved_value,
                                {
                                    "op": "const",
                                    "value": bound.stack_pointer_adjustment,
                                    "width": 32,
                                },
                            ],
                        }
                    )
                call_results[(machine_event_index, register)] = preserved_value
            else:
                call_results[(machine_event_index, register)] = {
                    "op": "service_machine_result",
                    "index": trace_index,
                    "register": register,
                    "width": 32,
                }
        for flag in ("cf", "zf", "sf", "of", "pf", "df"):
            call_results[(machine_event_index, f"flag:{flag}")] = {
                "op": "service_machine_flag",
                "index": trace_index,
                "flag": flag,
                "width": 1,
            }
        _bind_service_result_rule(
            state=state,
            binding=bound,
            trace_index=trace_index,
            status=call_results[(machine_event_index, "eax")],
        )
        state.trace.append(
            {
                "service_id": bound.service_id,
                "arguments": arguments,
                "guards": copy.deepcopy(state.guards),
                "machine_event": normalized_event,
                "unit_id": unit_id,
                "event_index": machine_event_index,
                "event_sha256": bound.event_sha256,
            }
        )
        if bound.result is not None:
            response = _bound_service_result_expression(bound, trace_index)
            _bind_call_result(
                bound.result,
                machine_event_index,
                response,
                call_results,
                event_memory,
                old_env,
                old_flags,
                event_memory,
                machine_event,
            )
        _bind_service_writebacks(
            bound,
            machine_event,
            trace_index,
            machine_event_index,
            call_results,
            event_memory,
            old_env,
            old_flags,
            event_memory,
        )

    ordered_events = _rows(
        semantics.get("ordered_events", []), "ordered machine events"
    )
    if ordered_events:
        external_cursor = 0
        for ordered_event in ordered_events:
            family = ordered_event.get("family")
            if family == "memory" and ordered_event.get("kind") == "write":
                address = _substitute(
                    ordered_event.get("address"),
                    old_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                value = _substitute(
                    ordered_event.get("value"),
                    old_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                width = ordered_event.get("width")
                offset = _private_stack_offset(address)
                key = _expression_key(address)
                owner = state_write_locations.get(key)
                if (
                    owner is not None
                    and isinstance(width, int)
                    and not isinstance(width, bool)
                    and owner[1] == width
                ):
                    _write_owned_memory(
                        event_memory,
                        state_write_locations,
                        owner,
                        value,
                    )
                else:
                    event_memory[key] = value
                if (
                    owner is None
                    and isinstance(width, int)
                    and not isinstance(width, bool)
                    and offset is not None
                    and 0 <= offset <= 65536 - width
                ):
                    state.pending_service_stack_writes.add((offset, width))
                    ordered_service_writes.add((offset, width))
            elif family == "external":
                if external_cursor >= len(external_events):
                    raise SemanticPathError(
                        "ordered external-event inventory exceeds machine events"
                    )
                process_external_event(external_cursor)
                external_cursor += 1
        if external_cursor != len(external_events):
            raise SemanticPathError(
                "ordered external-event inventory differs from machine events"
            )
    else:
        for machine_event_index in range(len(external_events)):
            process_external_event(machine_event_index)

    state.memory.update(event_memory)

    # Validate every summarized write against component ownership.  Without
    # an ordered-event inventory the summary writes also define the final
    # unit state.  With ordered events, ``event_memory`` above already carries
    # the temporal final state (including external-call writebacks); replaying
    # an earlier initialization write here would incorrectly erase a later
    # service writeback.
    expression_memory = copy.deepcopy(old_memory)
    for raw in _rows(semantics.get("memory_events", []), "memory events"):
        if raw.get("kind") != "write":
            continue
        address = _substitute(
            raw.get("address"),
            old_env,
            old_flags,
            expression_memory,
            call_results,
        )
        value = _substitute(
            raw.get("value"),
            old_env,
            old_flags,
            expression_memory,
            call_results,
        )
        width = raw.get("width")
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            raise SemanticPathError("machine memory write width is invalid")
        key = _expression_key(address)
        owner = state_write_locations.get(key)
        if owner is not None and owner[1] == width:
            if not ordered_events:
                _write_owned_memory(
                    state.memory,
                    state_write_locations,
                    owner,
                    value,
                )
            continue
        private_offset = _private_stack_offset(address)
        if private_offset is not None and -65536 <= private_offset < 0:
            if private_offset + width > 0:
                raise SemanticPathError(
                    "machine memory write crosses the component stack-frame boundary"
                )
            state.private_stack_writes.add((private_offset, width))
            if not ordered_events:
                state.memory[key] = value
            continue
        stack_write = (private_offset, width)
        if (
            private_offset is not None
            and 0 <= private_offset <= 65536 - width
            and stack_write in ordered_service_writes
            and (
                stack_write in state.pending_service_stack_writes
                or stack_write in consumed_service_writes
            )
        ):
            if not ordered_events:
                state.memory[key] = value
            continue
        if private_offset is None or private_offset < -65536:
            raise SemanticPathError(
                "machine memory write is outside the checked component-state frame"
            )
        raise SemanticPathError(
            "machine stack write is not ordered as a checked service argument"
        )

    normalized_edge_guards: dict[int, dict[str, object]] = {}
    raw_edges = _rows(semantics.get("edge_conditions", []), "edge conditions")
    if not raw_edges:
        raw_outcome = _object(semantics.get("outcome"), "machine outcome")
        target = raw_outcome.get("target_rva")
        if isinstance(target, int):
            raw_edges = [{"condition": {"op": "true"}, "target_rva": target}]
    for raw_edge in raw_edges:
        target = raw_edge.get("target_rva")
        if not isinstance(target, int) or isinstance(target, bool):
            raise SemanticPathError("machine edge target is invalid")
        guard = _substitute(
            raw_edge.get("condition"),
            old_env,
            old_flags,
            old_memory,
            call_results,
        )
        prior = normalized_edge_guards.get(target)
        normalized_edge_guards[target] = (
            guard
            if prior is None
            else {
                "op": "or_bool",
                "args": [prior, guard],
            }
        )
    normalized_outcome = _normalize_outcome(
        semantics.get("outcome"),
        old_env,
        old_flags,
        old_memory,
        call_results,
    )

    state.env.update(
        {
            _text(raw.get("register"), "written register"): _substitute(
                raw.get("value"),
                old_env,
                old_flags,
                expression_memory,
                call_results,
            )
            for raw in _rows(semantics.get("register_writes", []), "register writes")
        }
    )
    state.flags.update(
        {
            _text(raw.get("flag"), "written flag"): _substitute(
                raw.get("value"),
                old_env,
                old_flags,
                expression_memory,
                call_results,
            )
            for raw in _rows(semantics.get("flag_writes", []), "flag writes")
        }
    )
    return _ExecutedUnit(
        semantics=semantics,
        call_results=call_results,
        edge_guards=normalized_edge_guards,
        outcome=normalized_outcome,
    )


def _execute_transfer_v2_unit(
    *,
    unit_id: str,
    transfer: Mapping[str, object],
    external_events: list[Mapping[str, object]],
    state: _State,
    event_index: Mapping[tuple[str, int], _BoundServiceEvent],
    state_write_locations: Mapping[str, tuple[str, int]],
    max_events: int,
) -> _ExecutedUnit:
    """Symbolically execute the canonical transfer language for refinement."""

    expressions = _rows(transfer.get("expressions"), "transfer expressions")
    effects = _rows(transfer.get("effects"), "transfer effects")
    calls = _rows(transfer.get("calls"), "transfer calls")
    terminator = _object(transfer.get("terminator"), "transfer terminator")
    expression_index = {
        _uint(row.get("id"), "transfer expression id"): row for row in expressions
    }
    call_index = {_uint(row.get("id"), "transfer call id"): row for row in calls}
    if sorted(expression_index) != list(range(len(expressions))) or sorted(
        call_index
    ) != list(range(len(calls))):
        raise SemanticPathError("canonical transfer IDs are not dense")
    initial_env = copy.deepcopy(state.env)
    initial_flags = copy.deepcopy(state.flags)
    values: dict[int, dict[str, object]] = {}
    call_results: dict[tuple[int, str], dict[str, object]] = {}

    def word(identity: int, active: set[int] | None = None) -> dict[str, object]:
        if identity in values:
            return copy.deepcopy(values[identity])
        if identity not in expression_index:
            raise SemanticPathError("transfer expression reference is stale")
        active = set() if active is None else set(active)
        if identity in active:
            raise SemanticPathError("transfer expression graph is cyclic")
        active.add(identity)
        row = expression_index[identity]
        op = _text(row.get("op"), "transfer expression operation")
        operands = _uint_rows(row.get("operands"), "transfer expression operands")
        parameters = _object(row.get("parameters"), "transfer expression parameters")
        aux = _uint(parameters.get("aux", 0), "transfer expression auxiliary")
        immediate = _uint(
            parameters.get("immediate", 0), "transfer expression immediate"
        )
        if op == "ite":
            if len(operands) != 3:
                raise SemanticPathError("canonical conditional expression is malformed")
            condition = word(operands[0], active)
            truth = _constant_predicate(condition)
            if truth is not None:
                result = word(operands[1 if truth else 2], active)
                values[identity] = copy.deepcopy(result)
                return result
            arguments = [
                condition,
                word(operands[1], active),
                word(operands[2], active),
            ]
        else:
            arguments = [word(item, active) for item in operands]
        if op == "const":
            result = {"op": "const", "value": immediate, "width": 32}
        elif op == "reg":
            result = copy.deepcopy(
                (state.env if immediate else initial_env)[_TRANSFER_REGISTERS[aux]]
            )
        elif op == "flag":
            name = _TRANSFER_FLAGS[aux]
            if name == "af":
                raise SemanticPathError(
                    "auxiliary-flag refinement requires an explicit logical projection"
                )
            result = copy.deepcopy((state.flags if immediate else initial_flags)[name])
        elif op == "fs_base":
            raise SemanticPathError("FS-base refinement is not yet supported")
        elif op in {"true", "false"}:
            result = {"op": op}
        elif op in {"undefined_bv", "undefined_flag"}:
            if arguments:
                # Some qualified undefined results are related to a captured
                # machine input (for example the destination-preserving BSR
                # case).  Retain that exact relation when the canonical node
                # carries one.
                result = arguments[0]
            else:
                undefined_identity = parameters.get("identity")
                if not isinstance(undefined_identity, str) or not undefined_identity:
                    raise SemanticPathError(
                        "canonical undefined transfer input lacks a stable identity"
                    )
                # An architecturally undefined result is an arbitrary machine
                # value, not zero and not an immediate proof failure.  Keep it
                # symbolic so instruction-local dead values can be overwritten.
                # The logical-expression gate below rejects this node if it
                # reaches a guard, service interaction, state field, or result.
                result = {
                    "op": "machine_undefined",
                    "identity": undefined_identity,
                    "slot": immediate,
                    "width": 1 if op == "undefined_flag" else 32,
                }
        elif op == "call_response":
            result = copy.deepcopy(
                call_results.get(
                    (immediate, _TRANSFER_REGISTERS[aux]),
                    {
                        "op": "symbol",
                        "name": f"machine_call_{immediate}_{_TRANSFER_REGISTERS[aux]}",
                        "width": 32,
                    },
                )
            )
        elif op == "call_flag":
            name = _TRANSFER_FLAGS[aux]
            result = copy.deepcopy(
                call_results.get(
                    (immediate, f"flag:{name}"),
                    {
                        "op": "symbol",
                        "name": f"machine_call_{immediate}_{name}",
                        "width": 1,
                    },
                )
            )
        elif op == "load":
            result = _substitute(
                {"op": "load", "address": arguments[0], "width": aux},
                {},
                {},
                state.memory,
                call_results,
            )
        elif op in {"shift_cf", "shift_of"}:
            kind = {0: "shl", 1: "shr", 2: "sar"}.get(aux >> 8)
            if kind is None:
                raise SemanticPathError("transfer shift kind is unsupported")
            result = _substitute(
                {"op": op, "args": [kind, aux & 0xFF, *arguments]},
                {},
                {},
                state.memory,
                call_results,
            )
        elif op == "sign_extend":
            if len(arguments) != 2:
                raise SemanticPathError(
                    "canonical sign-extension expression has invalid arity"
                )
            width_expression = arguments[0]
            width = width_expression.get("value")
            if (
                width_expression.get("op") != "const"
                or width_expression.get("width") != 32
                or not isinstance(width, int)
                or isinstance(width, bool)
                or not 0 < width <= 32
            ):
                raise SemanticPathError(
                    "canonical sign-extension width is not a checked constant"
                )
            result = _substitute(
                {"op": op, "args": [width, arguments[1]]},
                {},
                {},
                state.memory,
                call_results,
            )
        elif op.startswith("fpu_"):
            raise SemanticPathError(
                "typed x87 component refinement is not yet supported"
            )
        else:
            result = _substitute(
                {"op": op, "args": arguments},
                {},
                {},
                state.memory,
                call_results,
            )
        values[identity] = copy.deepcopy(result)
        return result

    def cached(identity: int) -> dict[str, object]:
        if identity not in values:
            raise SemanticPathError(
                "transfer effect uses an expression before its scheduled evaluation"
            )
        return copy.deepcopy(values[identity])

    def process_call(row: Mapping[str, object]) -> None:
        dense_id = _uint(row.get("id"), "transfer call id")
        machine_event_index = _uint(row.get("event_index"), "transfer call event index")
        if machine_event_index >= len(external_events):
            raise SemanticPathError("transfer call lacks its proof event projection")
        machine_event = external_events[machine_event_index]
        if machine_event.get("kind") not in {
            "external_call",
            "internal_call",
            "indirect_call",
        }:
            raise SemanticPathError("transfer call proof event has another identity")
        bound = event_index.get((unit_id, machine_event_index))
        if bound is None:
            raise SemanticPathError(
                f"external event {unit_id}:{machine_event_index} has no logical service binding"
            )
        if len(state.trace) >= max_events:
            raise SemanticPathError("service-event budget exceeded")
        register_nodes = _uint_rows(
            row.get("register_nodes"), "transfer call register nodes"
        )
        flag_nodes = _uint_rows(row.get("flag_nodes"), "transfer call flag nodes")
        argument_nodes = _uint_rows(
            row.get("argument_nodes"), "transfer call argument nodes"
        )
        if len(register_nodes) != len(_TRANSFER_REGISTERS) or len(flag_nodes) != 6:
            raise SemanticPathError("transfer call physical state is malformed")
        register_inputs = {
            name: cached(node)
            for name, node in zip(_TRANSFER_REGISTERS, register_nodes, strict=True)
        }
        flag_inputs = {
            name: cached(node)
            for name, node in zip(_TRANSFER_FLAGS[:6], flag_nodes, strict=True)
        }
        for expression in _service_argument_load_expressions(bound, machine_event):
            for load in _collect_ops(expression, "load"):
                address = _substitute(
                    load.get("address"),
                    register_inputs,
                    state.flags,
                    state.memory,
                    call_results,
                )
                width = load.get("width")
                offset = _private_stack_offset(address)
                if (
                    isinstance(width, int)
                    and not isinstance(width, bool)
                    and offset is not None
                    and 0 <= offset <= 65536 - width
                    and (offset, width) in state.pending_service_stack_writes
                ):
                    state.pending_service_stack_writes.remove((offset, width))
                    state.service_argument_stack_writes.add((offset, width))
        arguments = (
            [
                _substitute(
                    expression,
                    register_inputs,
                    state.flags,
                    state.memory,
                    call_results,
                )
                for expression in bound.argument_expressions
            ]
            if bound.argument_expressions
            else [
                _read_call_projection(
                    projection,
                    machine_event,
                    state.env,
                    state.flags,
                    state.memory,
                    call_results,
                )
                for projection in bound.argument_projections
            ]
        )
        state.guards.extend(
            _substitute(
                _resolve_entry_projections(
                    guard,
                    state.entry_env,
                    state.entry_flags,
                    state.entry_memory,
                ),
                register_inputs,
                state.flags,
                state.memory,
                call_results,
            )
            for guard in bound.argument_guards
        )
        trace_index = len(state.trace)
        for name in _TRANSFER_REGISTERS:
            if name in bound.preserved_registers or (
                name == "esp" and bound.stack_pointer_adjustment is not None
            ):
                result = copy.deepcopy(register_inputs[name])
                if name == "esp" and bound.stack_pointer_adjustment:
                    result = _simplify_logical_arithmetic(
                        {
                            "op": "add32",
                            "args": [
                                result,
                                {
                                    "op": "const",
                                    "value": bound.stack_pointer_adjustment,
                                    "width": 32,
                                },
                            ],
                        }
                    )
            else:
                result = {
                    "op": "service_machine_result",
                    "index": trace_index,
                    "register": name,
                    "width": 32,
                }
            call_results[(machine_event_index, name)] = result
            state.env[name] = copy.deepcopy(result)
        for name in _TRANSFER_FLAGS[:6]:
            result = {
                "op": "service_machine_flag",
                "index": trace_index,
                "flag": name,
                "width": 1,
            }
            call_results[(machine_event_index, f"flag:{name}")] = result
            state.flags[name] = copy.deepcopy(result)
        _bind_service_result_rule(
            state=state,
            binding=bound,
            trace_index=trace_index,
            status=call_results[(machine_event_index, "eax")],
        )
        state.trace.append(
            {
                "service_id": bound.service_id,
                "arguments": arguments,
                "guards": copy.deepcopy(state.guards),
                "machine_event": {
                    **{
                        key: copy.deepcopy(value)
                        for key, value in machine_event.items()
                        if key
                        not in {
                            "register_inputs",
                            "flag_inputs",
                            "arguments",
                            "stack_inputs",
                            "target",
                        }
                    },
                    "register_inputs": register_inputs,
                    "flag_inputs": flag_inputs,
                    "arguments": copy.deepcopy(arguments),
                    "stack_inputs": copy.deepcopy(
                        machine_event.get("stack_inputs", [])
                    ),
                },
                "unit_id": unit_id,
                "event_index": machine_event_index,
                "event_sha256": bound.event_sha256,
            }
        )
        if bound.result is not None:
            # Result and writeback projections are explicitly call-time views.
            # ``state.env`` already contains the callee's clobbers and stdcall
            # stack cleanup, so resolve them against the captured pre-call
            # physical inputs even when a stack word was prepared by an
            # earlier transfer effect and is absent from the local capture.
            _bind_call_result(
                bound.result,
                machine_event_index,
                _bound_service_result_expression(bound, trace_index),
                call_results,
                state.memory,
                register_inputs,
                flag_inputs,
                state.memory,
                machine_event,
            )
        _bind_service_writebacks(
            bound,
            machine_event,
            trace_index,
            machine_event_index,
            call_results,
            state.memory,
            register_inputs,
            flag_inputs,
            state.memory,
        )

    for effect in effects:
        op = _text(effect.get("op"), "transfer effect operation")
        operands = _uint_rows(effect.get("operands"), "transfer effect operands")
        parameters = _object(effect.get("parameters"), "transfer effect parameters")
        aux = _uint(parameters.get("aux", 0), "transfer effect auxiliary")
        if op == "eval_word":
            word(operands[0])
        elif op == "memory_write":
            address, value = cached(operands[0]), cached(operands[1])
            key = _expression_key(address)
            owner = state_write_locations.get(key)
            private_offset = _private_stack_offset(address)
            if owner is not None and owner[1] == aux:
                _write_owned_memory(
                    state.memory,
                    state_write_locations,
                    owner,
                    value,
                )
            elif private_offset is not None and -65536 <= private_offset < 0:
                if private_offset + aux > 0:
                    raise SemanticPathError(
                        "transfer write crosses the component stack-frame boundary"
                    )
                state.private_stack_writes.add((private_offset, aux))
                state.memory[key] = value
            elif private_offset is not None and 0 <= private_offset <= 65536 - aux:
                state.pending_service_stack_writes.add((private_offset, aux))
                state.memory[key] = value
            else:
                raise SemanticPathError(
                    "transfer write is outside the checked component-state frame: "
                    f"unit={unit_id!r}, width={aux}, address={address!r}"
                )
        elif op in {"atomic_compare_exchange", "atomic_exchange"}:
            expected_count = 4 if op == "atomic_compare_exchange" else 3
            if len(operands) != expected_count:
                raise SemanticPathError(
                    "canonical atomic effect operands are malformed"
                )
            address = cached(operands[0])
            key = _expression_key(address)
            owner = state_write_locations.get(key)
            if owner is None or not owner[0].startswith("atomic:") or owner[1] != aux:
                raise SemanticPathError(
                    "canonical atomic effect is outside its checked atomic object"
                )
            if op == "atomic_compare_exchange":
                expected = cached(operands[1])
                desired = cached(operands[2])
                observed_node = operands[3]
            else:
                expected = None
                desired = cached(operands[1])
                observed_node = operands[2]
            observed = word(observed_node)
            values[observed_node] = copy.deepcopy(observed)
            state.memory[key] = (
                desired
                if expected is None
                else {
                    "op": "ite",
                    "args": [
                        {"op": "eq", "args": [expected, observed]},
                        desired,
                        observed,
                    ],
                }
            )
        elif op == "call":
            process_call(call_index[operands[0]])
        elif op == "set_reg":
            state.env[_TRANSFER_REGISTERS[aux]] = cached(operands[0])
        elif op == "set_flag":
            name = _TRANSFER_FLAGS[aux]
            if name == "af":
                raise SemanticPathError("auxiliary-flag refinement is unsupported")
            state.flags[name] = cached(operands[0])
        elif op == "sync_eflags":
            continue
        else:
            raise SemanticPathError(
                f"canonical transfer effect {op!r} is unsupported by component refinement"
            )

    op = _text(terminator.get("op"), "transfer terminator operation")
    operands = _uint_rows(terminator.get("operands"), "transfer terminator operands")
    if op in {"outcome_fallthrough", "outcome_jump"}:
        kind = "fallthrough" if op.endswith("fallthrough") else "jump"
        outcome = {"kind": kind, "target_rva": operands[0]}
        edges = {operands[0]: {"op": "true"}}
    elif op == "outcome_branch":
        condition = cached(operands[0])
        outcome = {
            "kind": "branch",
            "condition": condition,
            "true_target_rva": operands[1],
            "false_target_rva": operands[2],
        }
        edges = {
            operands[1]: condition,
            operands[2]: {"op": "not", "args": [condition]},
        }
    elif op == "outcome_return":
        outcome = {"kind": "return", "value": cached(operands[0])}
        edges = {}
    elif op == "outcome_indirect":
        outcome = {"kind": "indirect_jump", "target": cached(operands[0])}
        edges = {}
    elif op == "outcome_nonlocal":
        outcome = {
            "kind": "nonlocal",
            "target": cached(operands[0]),
            "value": cached(operands[1]),
        }
        edges = {}
    elif op == "outcome_external":
        outcome = {"kind": "external_jump"}
        edges = {}
    else:
        raise SemanticPathError(f"canonical transfer terminator {op!r} is unsupported")
    return _ExecutedUnit(
        semantics={"transfer_v2": transfer},
        call_results=call_results,
        edge_guards=edges,
        outcome=outcome,
    )
