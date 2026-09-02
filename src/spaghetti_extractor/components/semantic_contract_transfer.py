"""Exact transfer and checked-service projections for component contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.machine_abi import resolve_machine_call_abi
from ..external.resolved import ResolvedExternalEnvironmentV1
from .semantic_external_transducers import (
    ComponentSemanticContractError,
    checked_external_argument_transducers as _checked_external_argument_transducers,
    checked_external_stack_arguments as _checked_external_stack_arguments,
    checked_local_cell_result_projection as _checked_local_cell_result_projection,
)


_TRANSFER_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_TRANSFER_FLAGS = ("cf", "zf", "sf", "of", "pf", "df", "af")


def _checked_machine_image(
    value: Mapping[str, object] | None, *, pe_sha256: str
) -> dict[str, object] | None:
    """Bind loader-relative component projections to original machine words."""

    if value is None:
        return None
    row = _object(value, "component machine image")
    required = {
        "image_size",
        "module_interface_sha256",
        "pe_sha256",
        "preferred_base",
    }
    preferred_base = row.get("preferred_base")
    image_size = row.get("image_size")
    module_interface_sha256 = row.get("module_interface_sha256")
    if (
        set(row) != required
        or row.get("pe_sha256") != pe_sha256
        or not isinstance(preferred_base, int)
        or isinstance(preferred_base, bool)
        or not isinstance(image_size, int)
        or isinstance(image_size, bool)
        or preferred_base < 0
        or image_size <= 0
        or preferred_base + image_size > 0x100000000
        or not isinstance(module_interface_sha256, str)
        or len(module_interface_sha256) != 64
        or any(
            character not in "0123456789abcdef" for character in module_interface_sha256
        )
    ):
        raise ComponentSemanticContractError(
            "component machine-image mapping is malformed or stale"
        )
    return {
        "image_size": image_size,
        "module_interface_sha256": module_interface_sha256,
        "pe_sha256": pe_sha256,
        "preferred_base": preferred_base,
    }

def _operation_units(
    operation: object, selected: Mapping[str, Mapping[str, object]]
) -> tuple[Mapping[str, object], ...] | None:
    entries = tuple(getattr(operation, "entry_unit_ids"))
    exits = set(getattr(operation, "exit_unit_ids"))
    if any(item not in selected for item in entries) or any(
        item not in selected for item in exits
    ):
        return None
    by_rva = {
        int(
            _object(row.get("source"), "machine unit source")
            .get("original", {})
            .get("rva_start", -1)
        ): unit_id
        for unit_id, row in selected.items()
    }
    visited: set[str] = set()
    pending = list(entries)
    while pending:
        unit_id = pending.pop()
        if unit_id in visited:
            continue
        visited.add(unit_id)
        if unit_id in exits:
            continue
        semantics = _object(selected[unit_id].get("semantics"), "machine semantics")
        targets = []
        transfer = semantics.get("transfer_v2")
        if isinstance(transfer, Mapping):
            terminator = transfer.get("terminator")
            if not isinstance(terminator, Mapping):
                return None
            operation_name = terminator.get("op")
            operands = terminator.get("operands")
            if not isinstance(operands, list):
                return None
            if operation_name in {"outcome_fallthrough", "outcome_jump"}:
                targets.extend(operands[:1])
            elif operation_name == "outcome_branch":
                targets.extend(operands[1:3])
            elif operation_name not in {
                "outcome_return",
                "outcome_indirect",
                "outcome_nonlocal",
                "outcome_external",
            }:
                return None
        else:
            for edge in semantics.get("edge_conditions", []):
                if isinstance(edge, Mapping) and isinstance(
                    edge.get("target_rva"), int
                ):
                    targets.append(int(edge["target_rva"]))
            outcome = semantics.get("outcome")
            if isinstance(outcome, Mapping):
                for field in ("target_rva", "true_target_rva", "false_target_rva"):
                    if isinstance(outcome.get(field), int):
                        targets.append(int(outcome[field]))
        for target in targets:
            if not isinstance(target, int) or isinstance(target, bool):
                return None
            target_id = by_rva.get(target)
            if target_id is None:
                return None
            pending.append(target_id)
    if not exits <= visited:
        return None
    return tuple(
        selected[item]
        for item in sorted(
            visited,
            key=lambda item: int(
                _object(selected[item].get("source"), "machine unit source")
                .get("original", {})
                .get("rva_start", 0)
            ),
        )
    )

def _service_event_selectors(
    provider: Mapping[str, object],
) -> tuple[tuple[str, int], ...]:
    selectors: list[tuple[str, int]] = []
    for index, raw in enumerate(_array(provider.get("events"), "bound service events")):
        event = _object(raw, f"bound service event {index}")
        if set(event) != {"unit_id", "event_index"}:
            raise ComponentSemanticContractError("bound service event fields differ")
        unit_id = event.get("unit_id")
        event_index = event.get("event_index")
        if (
            not isinstance(unit_id, str)
            or not unit_id
            or not isinstance(event_index, int)
            or isinstance(event_index, bool)
            or event_index < 0
        ):
            raise ComponentSemanticContractError(
                "bound service event selector is malformed"
            )
        selectors.append((unit_id, event_index))
    if not selectors or selectors != sorted(set(selectors)):
        raise ComponentSemanticContractError(
            "bound service event selectors are empty, duplicated, or noncanonical"
        )
    return tuple(selectors)

def _external_machine_event_matches_provider(
    event: Mapping[str, object],
    *,
    identity: Mapping[str, object],
    captured_target: bool,
) -> bool:
    if captured_target:
        return event.get("kind") == "indirect_call" and isinstance(
            event.get("target"), Mapping
        )
    return (
        event.get("kind") == "external_call"
        and isinstance(identity.get("dll"), str)
        and isinstance(event.get("dll"), str)
        and str(identity["dll"]).lower() == str(event["dll"]).lower()
        and identity.get("symbol") == event.get("symbol")
        and identity.get("ordinal") == event.get("ordinal")
    )

def _external_identity_key(
    identity: Mapping[str, object],
) -> tuple[str, str, int | None]:
    dll = identity.get("dll")
    symbol = identity.get("symbol")
    ordinal = identity.get("ordinal")
    if (
        not isinstance(dll, str)
        or not dll
        or (symbol is None) == (ordinal is None)
        or (symbol is not None and (not isinstance(symbol, str) or not symbol))
        or (
            ordinal is not None
            and (
                not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 0
            )
        )
    ):
        raise ComponentSemanticContractError("external-call identity is malformed")
    return (dll.lower(), "" if symbol is None else symbol, ordinal)

def _resolved_external_contract_index(
    environment: ResolvedExternalEnvironmentV1,
) -> dict[tuple[str, str, int | None], Mapping[str, object]]:
    result: dict[tuple[str, str, int | None], Mapping[str, object]] = {}
    for index, raw in enumerate(environment.payload["machine_import_contracts"]):
        row = _object(raw, f"resolved machine-import contract {index}")
        key = _external_identity_key(
            _object(row.get("identity"), "resolved import identity")
        )
        if (
            key in result
            or not isinstance(row.get("contract"), Mapping)
            or not isinstance(row.get("boundary"), Mapping)
        ):
            raise ComponentSemanticContractError(
                "resolved machine-import contracts are incomplete or duplicated"
            )
        result[key] = row
    return result

def _checked_interface_method_service_v1(
    *,
    service_id: str,
    logical: object,
    logical_types: Mapping[str, object],
    target: Mapping[str, object],
    method_contract_sha256: str,
    unit_id: str,
    event_index: int,
    machine_event: Mapping[str, object],
    argument_transducers: object = None,
    result_projection: object = None,
) -> dict[str, object]:
    """Materialize an interface call through the existing service-event path.

    Interface methods are checked external calls with a live resource receiver,
    not a second component execution model.  The event retains its method and
    receiver identity while using the same ABI/path machinery as imports.
    """

    method = _object(target.get("method"), "resolved interface method")
    protocol = _object(method.get("external_protocol"), "interface-method protocol")
    receiver = _object(method.get("receiver_resource"), "interface-method receiver")
    abi_row = _object(method.get("abi"), "interface-method ABI")
    argument_words = method.get("argument_words")
    slot = protocol.get("slot")
    receiver_argument = receiver.get("argument_index")
    if (
        not isinstance(argument_words, int)
        or isinstance(argument_words, bool)
        or not 1 <= argument_words <= 256
        or not isinstance(slot, int)
        or isinstance(slot, bool)
        or slot < 0
        or protocol.get("kind") != "pe32-interface-method"
        or protocol.get("profile_id") != target.get("profile_id")
        or protocol.get("profile_sha256") != target.get("profile_sha256")
        or protocol.get("interface_id") != target.get("interface_id")
        or protocol.get("offset") != slot * 4
        or receiver.get("dispatch_slot") != slot
        or receiver.get("required_state") != "live"
        or not isinstance(receiver_argument, int)
        or isinstance(receiver_argument, bool)
        or not 0 <= receiver_argument < argument_words
        or method.get("callback_effect") != "none"
    ):
        raise ComponentSemanticContractError(
            "interface-method protocol, receiver, or arity is incomplete"
        )
    if logical is None:
        raise ComponentSemanticContractError(
            f"interface-method service {service_id!r} has no logical signature"
        )
    parameter_type_ids = tuple(getattr(logical, "parameter_type_ids", ()))
    if argument_transducers is None and len(parameter_type_ids) != argument_words:
        raise ComponentSemanticContractError(
            "interface-method logical and physical arities differ"
        )
    receiver_parameter = receiver_argument
    if argument_transducers is not None:
        transducer_rows = _array(
            argument_transducers, "interface-method argument transducers"
        )
        if len(transducer_rows) != argument_words:
            raise ComponentSemanticContractError(
                "interface-method argument transducers disagree with its ABI"
            )
        receiver_transducer = _object(
            transducer_rows[receiver_argument],
            "interface-method receiver transducer",
        )
        receiver_parameter = receiver_transducer.get("parameter_index")
        if (
            receiver_transducer.get("kind") != "logical_argument"
            or not isinstance(receiver_parameter, int)
            or isinstance(receiver_parameter, bool)
        ):
            raise ComponentSemanticContractError(
                "interface-method receiver requires a logical resource transducer"
            )
    if not 0 <= receiver_parameter < len(parameter_type_ids):
        raise ComponentSemanticContractError(
            "interface-method receiver names an unknown logical parameter"
        )
    receiver_type = logical_types.get(parameter_type_ids[receiver_parameter])
    if receiver_type is None or getattr(receiver_type, "kind", None) != "resource":
        raise ComponentSemanticContractError(
            "interface-method receiver is not a logical resource"
        )
    if machine_event.get("kind") != "indirect_call":
        raise ComponentSemanticContractError(
            "interface-method binding does not select an indirect call"
        )
    target_expression = _object(
        machine_event.get("target"), "interface-method call target"
    )
    local_slot = _interface_method_slot_offset(target_expression)
    if local_slot is not None and local_slot != slot * 4:
        raise ComponentSemanticContractError(
            "interface-method call target does not use the checked vtable slot"
        )
    machine_arguments = [
        _object(row, "interface-method argument")
        for row in _array(
            machine_event.get("arguments", []),
            "interface-method arguments",
        )
    ]
    if machine_arguments and len(machine_arguments) != argument_words:
        raise ComponentSemanticContractError(
            "interface-method logical argument projection is partial"
        )
    stack_inputs = [
        _object(row, "machine interface-method stack input")
        for row in _array(
            machine_event.get("stack_inputs", []),
            "machine interface-method stack inputs",
        )
    ]
    contract_arguments = _checked_external_stack_arguments(
        stack_inputs, argument_words=argument_words
    )
    for stack_input in stack_inputs:
        argument_index = int(stack_input["offset"]) // 4
        if (
            machine_arguments
            and stack_input["value"] != machine_arguments[argument_index]
        ):
            raise ComponentSemanticContractError(
                "interface-method logical argument projection disagrees with its stack frame"
            )
    expected_target: dict[str, object] = {
        "op": "load",
        "address": {
            "op": "add32",
            "args": [
                {
                    "op": "load",
                    "address": json.loads(
                        json.dumps(contract_arguments[receiver_argument])
                    ),
                    "width": 4,
                },
                {"op": "const", "value": slot * 4, "width": 32},
            ],
        },
        "width": 4,
    }
    argument_guards = [
        {
            "op": "eq",
            "args": [
                json.loads(json.dumps(contract_arguments[index])),
                json.loads(json.dumps(machine_argument)),
            ],
        }
        for index, machine_argument in enumerate(machine_arguments)
    ]
    arguments = contract_arguments
    physical_arguments = [
        {
            "index": index,
            "machine": json.loads(json.dumps(argument)),
            "transducer": {
                "kind": "interface_method_argument",
                "parameter_index": index,
            },
        }
        for index, argument in enumerate(contract_arguments)
    ]
    writebacks: list[dict[str, object]] = []
    if argument_transducers is not None:
        (
            arguments,
            physical_arguments,
            transducer_guards,
            writebacks,
        ) = _checked_external_argument_transducers(
            argument_transducers,
            logical=logical,
            logical_types=logical_types,
            contract={"profile_sha256": target.get("profile_sha256")},
            contract_payload={
                "out_interface_relations": method.get("out_interfaces", []),
                "caller_memory_frame": method.get("caller_memory_frame"),
                "local_cells": method.get("local_cells", []),
            },
            contract_arguments=contract_arguments,
        )
        argument_guards.extend(transducer_guards)
    argument_guards.append(
        {
            "op": "eq",
            "args": [
                json.loads(json.dumps(target_expression)),
                expected_target,
            ],
        }
    )
    abi = resolve_machine_call_abi(abi_row.get("template"))
    if abi is None or abi_row != abi.as_json():
        raise ComponentSemanticContractError(
            "interface-method ABI differs from the canonical machine ABI"
        )
    result: dict[str, object] | None = None
    result_rule: dict[str, object] | None = None
    result_type_id = getattr(logical, "result_type_id", None)
    if result_type_id is not None:
        logical_result = logical_types.get(result_type_id)
        logical_kind = getattr(logical_result, "kind", None)
        if logical_kind not in {"scalar", "enum"}:
            raise ComponentSemanticContractError(
                "interface-method resource results require a checked out-interface transducer"
            )
        if result_projection is None:
            result = {
                "kind": "register",
                "register": "eax",
                "width": 32,
                "at": "call",
            }
        else:
            result, result_rule = _checked_local_cell_result_projection(
                result_projection,
                logical_kind=logical_kind,
                transducers=argument_transducers,
                contract_payload={
                    "caller_memory_frame": method.get("caller_memory_frame"),
                    "local_cells": method.get("local_cells", []),
                },
                argument_words=argument_words,
            )
    elif result_projection is not None:
        raise ComponentSemanticContractError(
            "void interface-method service has a result projection"
        )
    identity = {
        "kind": "interface_method",
        "method_contract_sha256": method_contract_sha256,
        "profile_sha256": target.get("profile_sha256"),
        "interface_id": target.get("interface_id"),
        "method": protocol.get("method"),
        "slot": slot,
        "receiver_resource": json.loads(json.dumps(receiver)),
    }
    return {
        "kind": "checked_external_call_events",
        "call_boundary": {
            "contract_id": f"interface-method:{method_contract_sha256}",
            "abi_template": abi.template,
            "preserved_registers": list(abi.preserved_registers),
            "stack_pointer_adjustment": (
                argument_words * 4 if abi.callee_cleanup else 0
            ),
        },
        "events": [
            {
                "unit_id": unit_id,
                "event_index": event_index,
                "event_sha256": canonical_sha256_v3(dict(machine_event)),
                "identity": identity,
                "arguments": arguments,
                "result": result,
                **({"result_rule": result_rule} if result_rule is not None else {}),
                "physical_arguments": physical_arguments,
                "argument_guards": argument_guards,
                "writebacks": writebacks,
            }
        ],
    }

def _interface_method_slot_offset(
    target: Mapping[str, object],
) -> int | None:
    if target.get("op") != "load":
        return None
    address = target.get("address")
    if not isinstance(address, Mapping) or address.get("op") != "add32":
        return None
    arguments = address.get("args")
    if not isinstance(arguments, list) or len(arguments) != 2:
        return None
    constants = [
        row
        for row in arguments
        if isinstance(row, Mapping) and row.get("op") == "const"
    ]
    bases = [
        row
        for row in arguments
        if isinstance(row, Mapping) and row.get("op") != "const"
    ]
    if len(constants) != 1 or len(bases) != 1:
        return None
    if bases[0].get("op") not in {"reg", "load"}:
        return None
    value = constants[0].get("value")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value % 4:
        return None
    return value

def _contract_unit(unit: Mapping[str, object]) -> dict[str, object]:
    source = _object(unit.get("source"), "machine unit source")
    return {
        "id": unit.get("id"),
        "status": unit.get("status"),
        "source": json.loads(json.dumps(source)),
        "semantics": json.loads(
            json.dumps(_object(unit.get("semantics"), "machine semantics"))
        ),
    }

def _read_units(data: bytes) -> dict[str, Mapping[str, object]]:
    result: dict[str, Mapping[str, object]] = {}
    for line_number, raw in enumerate(data.decode("utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        value = json.loads(raw)
        row = _object(value, f"machine-IR line {line_number}")
        identity = row.get("id")
        if not isinstance(identity, str) or not identity or identity in result:
            raise ComponentSemanticContractError("machine-IR unit identity is invalid")
        result[identity] = row
    return result

def _expression_index(
    rows: list[object],
) -> dict[int, Mapping[str, object]]:
    result: dict[int, Mapping[str, object]] = {}
    for raw in rows:
        row = _object(raw, "canonical transfer expression")
        identity = row.get("id")
        if (
            not isinstance(identity, int)
            or isinstance(identity, bool)
            or identity in result
        ):
            raise ComponentSemanticContractError(
                "canonical transfer expression IDs are ambiguous"
            )
        result[identity] = row
    if sorted(result) != list(range(len(result))):
        raise ComponentSemanticContractError(
            "canonical transfer expression IDs are not dense"
        )
    return result

def _transfer_expression(
    identity: int,
    rows: Mapping[int, Mapping[str, object]],
    active: set[int] | None = None,
) -> dict[str, object]:
    active = set() if active is None else set(active)
    if identity in active or identity not in rows:
        raise ComponentSemanticContractError(
            "canonical transfer expression graph is cyclic or stale"
        )
    active.add(identity)
    row = rows[identity]
    op = str(row.get("op", ""))
    operands = _array(row.get("operands"), "canonical expression operands")
    parameters = _object(row.get("parameters"), "canonical expression parameters")
    aux = int(parameters.get("aux", 0))
    immediate = int(parameters.get("immediate", 0))
    if op == "const":
        return {"op": "const", "value": immediate, "width": 32}
    if op == "reg":
        return {"op": "reg", "name": _TRANSFER_REGISTERS[aux], "width": 32}
    if op == "flag":
        return {"op": "flag", "name": _TRANSFER_FLAGS[aux], "width": 1}
    if op == "fs_base":
        return {"op": "fs_base", "width": 32}
    if op in {"true", "false"}:
        return {"op": op}
    if op == "sign_extend":
        if len(operands) != 2:
            raise ComponentSemanticContractError(
                "canonical sign-extension expression has invalid arity"
            )
        width_row = rows.get(int(operands[0]))
        width_parameters = (
            width_row.get("parameters") if isinstance(width_row, Mapping) else None
        )
        if (
            not isinstance(width_row, Mapping)
            or width_row.get("op") != "const"
            or not isinstance(width_parameters, Mapping)
        ):
            raise ComponentSemanticContractError(
                "canonical sign-extension width is not constant"
            )
        width = width_parameters.get("immediate")
        if width not in {8, 16, 32}:
            raise ComponentSemanticContractError(
                "canonical sign-extension width is unsupported by refinement"
            )
        return {
            "op": op,
            "args": [
                width,
                _transfer_expression(int(operands[1]), rows, active),
            ],
        }
    args = [_transfer_expression(int(item), rows, active) for item in operands]
    if op in {"undefined_bv", "undefined_flag"}:
        result: dict[str, object] = {
            "op": op,
            "id": parameters.get("identity") or f"slot:{immediate}",
        }
        if args:
            result["defined_value"] = args[0]
        return result
    if op == "call_response":
        return {
            "op": op,
            "call_index": immediate,
            "register": _TRANSFER_REGISTERS[aux],
        }
    if op == "call_flag":
        return {
            "op": op,
            "call_index": immediate,
            "flag": _TRANSFER_FLAGS[aux],
        }
    if op == "load":
        return {"op": op, "address": args[0], "width": aux}
    if op in {"shift_cf", "shift_of"}:
        kind = {0: "shl", 1: "shr", 2: "sar"}[aux >> 8]
        return {"op": op, "args": [kind, aux & 0xFF, *args]}
    return {"op": op, "args": args}

def transfer_expression_view_v2(
    transfer: Mapping[str, object], identity: int
) -> dict[str, object]:
    """Decode one checked transfer expression for a logical boundary view."""

    expressions = _expression_index(
        _array(transfer.get("expressions"), "canonical transfer expressions")
    )
    return _transfer_expression(identity, expressions)

def _call_event(
    call: Mapping[str, object],
    expressions: Mapping[int, Mapping[str, object]],
) -> dict[str, object]:
    register_nodes = _array(call.get("register_nodes"), "canonical call register nodes")
    flag_nodes = _array(call.get("flag_nodes"), "canonical call flag nodes")
    argument_nodes = _array(call.get("argument_nodes"), "canonical call argument nodes")
    stack_inputs = _array(call.get("stack_inputs"), "canonical call stack inputs")
    if len(register_nodes) != len(_TRANSFER_REGISTERS) or len(flag_nodes) != 6:
        raise ComponentSemanticContractError(
            "canonical transfer call physical frame is malformed"
        )
    event: dict[str, object] = {
        "kind": call.get("kind"),
        "dll": call.get("dll"),
        "symbol": call.get("symbol"),
        "ordinal": call.get("ordinal"),
        "instruction_rva": call.get("instruction_rva"),
        "return_rva": call.get("return_rva"),
        "target_rva": call.get("target_rva"),
        "register_inputs": {
            name: _transfer_expression(int(node), expressions)
            for name, node in zip(_TRANSFER_REGISTERS, register_nodes, strict=True)
        },
        "flag_inputs": {
            name: _transfer_expression(int(node), expressions)
            for name, node in zip(_TRANSFER_FLAGS[:6], flag_nodes, strict=True)
        },
        "arguments": [
            _transfer_expression(int(node), expressions) for node in argument_nodes
        ],
        "stack_inputs": [
            {
                "offset": int(_array(row, "canonical call stack row")[0]),
                "width": int(_array(row, "canonical call stack row")[1]),
                "value": _transfer_expression(
                    int(_array(row, "canonical call stack row")[2]),
                    expressions,
                ),
            }
            for row in stack_inputs
        ],
    }
    target = call.get("target_node")
    if target is not None:
        event["target"] = _transfer_expression(int(target), expressions)
    return event

def _external_event_inventory(
    calls: list[object],
    expressions: Mapping[int, Mapping[str, object]],
) -> list[dict[str, object]]:
    indexed: dict[int, dict[str, object]] = {}
    for raw in calls:
        call = _object(raw, "canonical transfer call")
        event_index = call.get("event_index")
        if (
            not isinstance(event_index, int)
            or isinstance(event_index, bool)
            or event_index < 0
            or event_index in indexed
        ):
            raise ComponentSemanticContractError(
                "canonical transfer call event indices are ambiguous"
            )
        indexed[event_index] = _call_event(call, expressions)
    if not indexed:
        return []
    return [
        indexed.get(
            index,
            {
                "kind": "non_call_transfer_event",
                "event_index": index,
            },
        )
        for index in range(max(indexed) + 1)
    ]

def _atomic_effect_inventory(
    transfer: Mapping[str, object],
    expressions: Mapping[int, Mapping[str, object]],
    authority_rows: list[Mapping[str, object]],
) -> list[dict[str, object]]:
    effects = _array(transfer.get("effects"), "canonical transfer effects")
    result: list[dict[str, object]] = []
    for authority in authority_rows:
        effect_index = authority.get("effect_index")
        if (
            not isinstance(effect_index, int)
            or isinstance(effect_index, bool)
            or effect_index < 0
            or effect_index >= len(effects)
        ):
            raise ComponentSemanticContractError(
                "canonical atomic-effect index is stale"
            )
        effect = _object(effects[effect_index], "canonical atomic effect")
        operands = _array(effect.get("operands"), "canonical atomic operands")
        operation = authority.get("operation")
        expected_op = {
            "compare_exchange": "atomic_compare_exchange",
            "exchange": "atomic_exchange",
        }.get(operation)
        if effect.get("op") != expected_op:
            raise ComponentSemanticContractError(
                "canonical atomic-effect operation is stale"
            )
        row: dict[str, object] = {
            "effect_index": effect_index,
            "action_id": authority.get("action_id"),
            "profile_id": authority.get("profile_id"),
            "instruction_rva": authority.get("instruction_rva"),
            "source_memory_event_indices": authority.get("source_memory_event_indices"),
            "operation": operation,
            "width": authority.get("width_bytes"),
        }
        if operation == "compare_exchange" and len(operands) == 4:
            row["expected"] = _transfer_expression(int(operands[1]), expressions)
            row["desired"] = _transfer_expression(int(operands[2]), expressions)
        elif operation == "exchange" and len(operands) == 3:
            row["expected"] = None
            row["desired"] = _transfer_expression(int(operands[1]), expressions)
        else:
            raise ComponentSemanticContractError(
                "canonical atomic-effect operands are malformed"
            )
        result.append(row)
    return sorted(result, key=lambda row: int(row["effect_index"]))

def _load(value: Path | str | Mapping[str, object], context: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    try:
        result = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentSemanticContractError(f"cannot read {context}: {exc}") from exc
    return dict(_object(result, context))

def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentSemanticContractError(f"{context} must be an object")
    return value

def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentSemanticContractError(f"{context} must be an array")
    return value
