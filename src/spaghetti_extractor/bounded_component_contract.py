"""Checked machine-shape contracts for guarded bounded components.

The checker in this module recognizes a normalized, call-free PE32 ``strnlen``
loop.  It deliberately accepts a semantic shape rather than a symbol name or
fixed RVA.  The emitted invariant is consumed by Stage B source and adapter
generation; states outside the configured finite domain remain on the
canonical machine-IR interpreter path.  The pairwise-byte profile recognizes a
lexicographic loop whose normalization operation is supplied by a separately
qualified scalar component.  This makes procedure calls compositional proof
dependencies instead of profile-specific waivers.
"""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from typing import Any, Mapping, Sequence

from .artifact_formats import (
    BOUNDED_PAIRWISE_BYTE_CONTRACT_FORMAT,
    FINITE_COMPONENT_CONTRACT_FORMAT,
)
from .stage_binary import StageAInputError


BOUNDED_STRING_CONTRACT_FORMAT = "stage-b-bounded-string-contract-v1"


def derive_bounded_pairwise_byte_compare_contract(
    *,
    component: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]],
    machine_ir_sha256: str,
    max_bytes: int,
    component_dependency: Mapping[str, Any],
) -> dict[str, Any]:
    """Recognize a guarded lexicographic byte loop with one scalar service.

    The recognized code compares two byte strings after applying the same
    total scalar component to each byte.  The contract is complete when the
    pointers are equal or a return decision is reached within ``max_bytes``.
    Other states remain on the canonical machine-IR path.
    """

    if max_bytes <= 0 or max_bytes > 4096:
        raise StageAInputError("bounded pairwise comparison has an invalid byte budget")
    member_ids = [
        str(value) for value in component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in units}
    if len(by_id) != len(units) or set(by_id) != set(member_ids):
        raise StageAInputError(
            "bounded pairwise units do not match exact component membership"
        )
    ordered = sorted(units, key=_unit_rva)
    if len(ordered) != 12:
        raise StageAInputError(
            "bounded pairwise profile requires the canonical twelve-unit loop"
        )

    dependency = _checked_scalar_dependency(component_dependency)
    target_rva = int(dependency["target_rva"])
    target_unit_id = str(dependency["target_unit_id"])
    calls = _array(component.get("component_calls"), "component calls")
    if len(calls) != 1:
        raise StageAInputError(
            "bounded pairwise profile requires one selected component dependency"
        )
    declared_call = _object(calls[0], "selected component call")
    if (
        declared_call.get("target_component_id")
        != dependency["target_component_id"]
        or declared_call.get("target_rva") != target_rva
        or declared_call.get("target_unit_id") != target_unit_id
    ):
        raise StageAInputError(
            "bounded pairwise dependency disagrees with selected component calls"
        )

    boundary = _object(component.get("machine_boundary"), "component boundary")
    counts = _object(boundary.get("counts"), "component boundary counts")
    exits = _array(boundary.get("exits"), "component exits")
    call_exits = [item for item in exits if item.get("kind") == "internal_call"]
    return_exits = [item for item in exits if item.get("kind") == "return"]
    if (
        counts.get("entries") != 1
        or counts.get("faults") != 0
        or len(call_exits) != 2
        or len(return_exits) != 1
        or _object(boundary.get("call_closure"), "component call closure").get(
            "status"
        )
        != "complete"
    ):
        raise StageAInputError(
            "bounded pairwise profile requires two checked component calls and one return"
        )
    if any(
        item.get("target_rva") != target_rva
        or item.get("target_unit_id") != target_unit_id
        for item in call_exits
    ):
        raise StageAInputError(
            "bounded pairwise boundary contains an unexpected call target"
        )

    expected_instructions = (
        (
            ("push", (_reg("edi"),)),
            ("xor", (_reg("eax"), _reg("eax"))),
            ("push", (_reg("esi"),)),
            ("push", (_reg("ebx"),)),
        ),
        (
            ("sub", (_reg("esp"), _imm(16))),
            ("mov", (_reg("edi"), _mem("esp", 32, 32))),
            ("mov", (_reg("esi"), _mem("esp", 36, 32))),
            ("cmp", (_reg("edi"), _reg("esi"))),
        ),
        (("jne", (_imm(None),)),),
        (("jmp", (_imm(None),)),),
        (
            ("add", (_reg("edi"), _imm(1))),
            ("add", (_reg("esi"), _imm(1))),
        ),
        (
            ("movzx", (_reg("eax"), _mem("edi", 0, 8))),
            ("mov", (_mem("esp", 0, 32), _reg("eax"))),
            ("call", (_imm(None),)),
        ),
        (
            ("mov", (_reg("ebx"), _reg("eax"))),
            ("movzx", (_reg("eax"), _mem("esi", 0, 8))),
            ("mov", (_mem("esp", 0, 32), _reg("eax"))),
            ("call", (_imm(None),)),
        ),
        (
            ("test", (_reg("bl"), _reg("bl"))),
            ("je", (_imm(None),)),
        ),
        (
            ("cmp", (_reg("bl"), _reg("al"))),
            ("je", (_imm(None),)),
        ),
        (
            ("movzx", (_reg("edx"), _reg("al"))),
            ("movzx", (_reg("eax"), _reg("bl"))),
            ("sub", (_reg("eax"), _reg("edx"))),
        ),
        (
            ("add", (_reg("esp"), _imm(16))),
            ("pop", (_reg("ebx"),)),
            ("pop", (_reg("esi"),)),
            ("pop", (_reg("edi"),)),
        ),
        (
            ("xor", (_reg("edx"), _reg("edx"))),
            ("xor", (_reg("ecx"), _reg("ecx"))),
            ("ret", ()),
        ),
    )
    for index, (unit, expected) in enumerate(zip(ordered, expected_instructions)):
        observed = tuple(
            (
                str(instruction.get("mnemonic")),
                tuple(
                    _operand(item)
                    for item in _array(
                        instruction.get("operands"), "instruction operands"
                    )
                ),
            )
            for instruction in _array(unit.get("instructions"), "unit instructions")
        )
        if not _instruction_sequences_match(observed, expected):
            raise StageAInputError(
                f"bounded pairwise unit {index} does not match the normalized loop shape"
            )

    rvas = [_unit_rva(unit) for unit in ordered]
    _require_control(ordered[0], "fallthrough", (rvas[1],))
    _require_control(ordered[1], "fallthrough", (rvas[2],))
    _require_branch(ordered[2], true_target=rvas[5], false_target=rvas[3])
    _require_control(ordered[3], "jump", (rvas[10],))
    _require_control(ordered[4], "fallthrough", (rvas[5],))
    _require_control(ordered[5], "fallthrough", (rvas[6],))
    _require_control(ordered[6], "fallthrough", (rvas[7],))
    _require_branch(ordered[7], true_target=rvas[9], false_target=rvas[8])
    _require_branch(ordered[8], true_target=rvas[4], false_target=rvas[9])
    _require_control(ordered[9], "fallthrough", (rvas[10],))
    _require_control(ordered[10], "fallthrough", (rvas[11],))
    _require_control(ordered[11], "return", ())
    _require_scalar_call(
        ordered[5],
        pointer_register="edi",
        target_rva=target_rva,
        return_rva=rvas[6],
    )
    _require_scalar_call(
        ordered[6],
        pointer_register="esi",
        target_rva=target_rva,
        return_rva=rvas[7],
    )
    callsite_ids = {
        str(item.get("source_unit_id"))
        for item in _array(declared_call.get("callsites"), "component callsites")
    }
    if callsite_ids != {str(ordered[5]["id"]), str(ordered[6]["id"])}:
        raise StageAInputError(
            "bounded pairwise dependency does not bind both machine callsites"
        )

    unit_bindings = [
        {
            "unit_id": str(unit["id"]),
            "rva_start": _unit_rva(unit),
            "rva_end": int(unit["source"]["original"]["rva_end"]),
            "instruction_bytes_sha256": str(
                unit["source"]["instruction_bytes_sha256"]
            ),
            "semantic_transfer_sha256": str(
                unit["source"]["semantic_export"]["semantic_transfer_sha256"]
            ),
        }
        for unit in ordered
    ]
    core = {
        "format": BOUNDED_PAIRWISE_BYTE_CONTRACT_FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "bounded_pairwise_byte_compare_v1",
        "component": {
            "id": str(component["id"]),
            "sha256": str(component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": machine_ir_sha256,
            "units": unit_bindings,
            "component_dependency_sha256": dependency["binding_sha256"],
        },
        "domain": {
            "kind": "guarded_partial",
            "max_bytes": max_bytes,
            "predicate": (
                "pointers equal, or the first zero-left/folded-byte mismatch "
                "occurs below max_bytes"
            ),
            "outside_domain": "canonical_machine_ir",
        },
        "component_call": copy.deepcopy(dict(dependency)),
        "logical_interface": {
            "parameters": [
                {
                    "id": "left",
                    "type": "const uint8_t *",
                    "machine": "stack_argument_0",
                },
                {
                    "id": "right",
                    "type": "const uint8_t *",
                    "machine": "stack_argument_1",
                },
            ],
            "result": {"id": "ordering", "type": "int32_t", "machine": "eax"},
        },
        "loop": {
            "body_entry_unit_id": str(ordered[5]["id"]),
            "back_edge_unit_id": str(ordered[8]["id"]),
            "invariant": [
                "left and right point at the same compared byte index",
                "all earlier normalized byte pairs were equal and nonzero",
                "callee-saved registers retain their entry values in saved frame slots",
            ],
            "variant": "max_bytes - compared_bytes",
        },
        "result": {
            "definition": (
                "normalize(left[i]) - normalize(right[i]) at the first i where "
                "normalize(left[i]) is zero or the normalized bytes differ"
            ),
            "pointer_identity_fast_path": 0,
            "memory_effect": "read_only_outside_private_call_frame",
        },
        "machine_projection": {
            "registers_written": ["eax", "ecx", "edx", "esp"],
            "flags_written": ["cf", "of", "pf", "sf", "zf"],
            "preserved_registers": ["ebx", "esi", "edi", "ebp"],
            "constant_outputs": {
                "ecx": 0,
                "edx": 0,
                "cf": 0,
                "of": 0,
                "pf": 1,
                "sf": 0,
                "zf": 1,
            },
            "stack_delta": 4,
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def derive_bounded_string_length_contract(
    *,
    component: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]],
    machine_ir_sha256: str,
    max_bytes: int,
) -> dict[str, Any]:
    """Recognize and bind a guarded ``strnlen`` machine component."""

    if max_bytes <= 0 or max_bytes > 4096:
        raise StageAInputError("bounded string length has an invalid byte budget")
    member_ids = [
        str(value) for value in component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in units}
    if len(by_id) != len(units) or set(by_id) != set(member_ids):
        raise StageAInputError(
            "bounded string units do not match exact component membership"
        )
    ordered = sorted(units, key=_unit_rva)
    if len(ordered) != 8:
        raise StageAInputError(
            "bounded string profile requires the canonical eight-unit loop"
        )

    boundary = _object(component.get("machine_boundary"), "component boundary")
    counts = _object(boundary.get("counts"), "component boundary counts")
    if (
        counts.get("entries") != 1
        or counts.get("exits") != 1
        or counts.get("external_events") != 0
        or counts.get("faults") != 0
        or _object(boundary.get("call_closure"), "component call closure").get(
            "status"
        )
        != "complete"
        or _array(boundary.get("internal_calls", []), "component internal calls")
    ):
        raise StageAInputError(
            "bounded string profile requires one closed, internal-only return region"
        )
    exits = _array(boundary.get("exits"), "component exits")
    if exits[0].get("kind") != "return":
        raise StageAInputError("bounded string profile requires a return exit")

    expected_instructions = (
        (("push", (_reg("ebx"),)),
         ("mov", (_reg("ebx"), _mem("esp", 8, 32))),
         ("xor", (_reg("edx"), _reg("edx"))),
         ("mov", (_reg("ecx"), _mem("esp", 12, 32)))),
        (("mov", (_reg("eax"), _reg("ebx"))),
         ("test", (_reg("ecx"), _reg("ecx"))),
         ("jne", (_imm(None),))),
        (("jmp", (_imm(None),)),),
        (("add", (_reg("eax"), _imm(1))),
         ("mov", (_reg("edx"), _reg("eax"))),
         ("sub", (_reg("edx"), _reg("ebx"))),
         ("cmp", (_reg("edx"), _reg("ecx")))),
        (("jae", (_imm(None),)),),
        (("cmp", (_mem("eax", 0, 8), _imm(0))),
         ("jne", (_imm(None),))),
        (("mov", (_reg("eax"), _reg("edx"))),
         ("pop", (_reg("ebx"),)),
         ("xor", (_reg("edx"), _reg("edx"))),
         ("xor", (_reg("ecx"), _reg("ecx")))),
        (("ret", ()),),
    )
    for index, (unit, expected) in enumerate(zip(ordered, expected_instructions)):
        observed = tuple(
            (str(instruction.get("mnemonic")), tuple(_operand(item) for item in _array(
                instruction.get("operands"), "instruction operands"
            )))
            for instruction in _array(unit.get("instructions"), "unit instructions")
        )
        if not _instruction_sequences_match(observed, expected):
            raise StageAInputError(
                f"bounded string unit {index} does not match the normalized loop shape"
            )
        semantics = _object(unit.get("semantics"), "unit semantics")
        if _array(semantics.get("external_events", []), "unit external events"):
            raise StageAInputError("bounded string loop contains an external event")
        schedule = semantics.get("instruction_effect_schedule")
        if schedule is not None:
            for record in _array(
                _object(schedule, "instruction effect schedule").get("records"),
                "instruction effect records",
            ):
                effects = _object(record.get("effects"), "instruction effects")
                if _array(effects.get("call_effects", []), "instruction call effects"):
                    raise StageAInputError("bounded string loop contains a call")

    rvas = [_unit_rva(unit) for unit in ordered]
    _require_control(ordered[0], "fallthrough", (rvas[1],))
    _require_branch(ordered[1], true_target=rvas[5], false_target=rvas[2])
    _require_control(ordered[2], "jump", (rvas[6],))
    _require_control(ordered[3], "fallthrough", (rvas[4],))
    _require_branch(ordered[4], true_target=rvas[6], false_target=rvas[5])
    _require_branch(ordered[5], true_target=rvas[3], false_target=rvas[6])
    _require_control(ordered[6], "fallthrough", (rvas[7],))
    _require_control(ordered[7], "return", ())

    unit_bindings = [
        {
            "unit_id": str(unit["id"]),
            "rva_start": _unit_rva(unit),
            "rva_end": int(unit["source"]["original"]["rva_end"]),
            "instruction_bytes_sha256": str(
                unit["source"]["instruction_bytes_sha256"]
            ),
            "semantic_transfer_sha256": str(
                unit["source"]["semantic_export"]["semantic_transfer_sha256"]
            ),
        }
        for unit in ordered
    ]
    core = {
        "format": BOUNDED_STRING_CONTRACT_FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "bounded_string_length_v1",
        "component": {
            "id": str(component["id"]),
            "sha256": str(component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": machine_ir_sha256,
            "units": unit_bindings,
        },
        "domain": {
            "kind": "guarded_partial",
            "max_bytes": max_bytes,
            "outside_domain": "canonical_machine_ir",
        },
        "logical_interface": {
            "parameters": [
                {"id": "bytes", "type": "const uint8_t *", "machine": "stack_argument_0"},
                {"id": "limit", "type": "uint32_t", "machine": "stack_argument_1"},
            ],
            "result": {"id": "length", "type": "uint32_t", "machine": "eax"},
        },
        "loop": {
            "entry_unit_id": str(ordered[3]["id"]),
            "test_unit_id": str(ordered[5]["id"]),
            "invariant": [
                "0 <= index <= limit",
                "eax == bytes + index modulo 2^32",
                "edx == index",
                "all bytes before index are nonzero",
            ],
            "variant": "limit - index",
            "step": "read bytes[index]; return index on zero, otherwise increment index",
        },
        "result": {
            "definition": "least zero byte index below limit, or limit",
            "memory_effect": "read_only",
            "preserved_registers": ["ebx", "esi", "edi", "ebp"],
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _checked_scalar_dependency(value: Mapping[str, Any]) -> Mapping[str, Any]:
    dependency = _object(value, "bounded pairwise component dependency")
    expected = dependency.get("binding_sha256")
    core = copy.deepcopy(dict(dependency))
    core.pop("binding_sha256", None)
    if expected != _canonical_sha256(core):
        raise StageAInputError("bounded pairwise component dependency is stale")
    required_strings = (
        "target_component_id",
        "target_unit_id",
        "qualification_sha256",
        "refinement_sha256",
    )
    if any(
        not isinstance(dependency.get(field), str) or not dependency.get(field)
        for field in required_strings
    ) or not isinstance(dependency.get("target_rva"), int):
        raise StageAInputError("bounded pairwise component dependency is malformed")
    activation = _object(
        dependency.get("activation"), "bounded pairwise dependency activation"
    )
    if activation.get("authorized") is not True or activation.get("kind") != "total":
        raise StageAInputError(
            "bounded pairwise component dependency is not totally qualified"
        )
    contract = _object(
        dependency.get("finite_component_contract"),
        "bounded pairwise scalar component contract",
    )
    if (
        contract.get("format") != FINITE_COMPONENT_CONTRACT_FORMAT
        or contract.get("profile") != "finite_acyclic_scalar_v1"
        or contract.get("status") != "derived"
        or contract.get("executes_original_binary") is not False
    ):
        raise StageAInputError(
            "bounded pairwise dependency lacks a checked finite scalar contract"
        )
    contract_core = copy.deepcopy(dict(contract))
    contract_expected = contract_core.pop("contract_sha256", None)
    if contract_expected != _canonical_sha256(contract_core):
        raise StageAInputError("bounded pairwise scalar contract is stale")
    contract_component_id = contract.get("component_id")
    if contract_component_id is None:
        contract_component_id = contract.get("component", {}).get("id")
    if contract_component_id != dependency.get("target_component_id"):
        raise StageAInputError(
            "bounded pairwise scalar contract has the wrong component identity"
        )
    return dependency


def _require_scalar_call(
    unit: Mapping[str, Any], *, pointer_register: str, target_rva: int, return_rva: int
) -> None:
    events = _array(
        _object(unit.get("semantics"), "unit semantics").get("external_events"),
        "unit call events",
    )
    if len(events) != 1:
        raise StageAInputError("bounded pairwise callsite has an invalid event count")
    event = _object(events[0], "bounded pairwise call event")
    if (
        event.get("kind") != "internal_call"
        or event.get("target_rva") != target_rva
        or event.get("return_rva") != return_rva
    ):
        raise StageAInputError("bounded pairwise callsite has an unexpected target")
    stack_inputs = _array(event.get("stack_inputs"), "bounded pairwise stack inputs")
    if len(stack_inputs) != 1:
        raise StageAInputError("bounded pairwise scalar call requires one argument")
    argument = _object(stack_inputs[0], "bounded pairwise scalar argument")
    if argument.get("offset") != 0 or argument.get("width") != 4:
        raise StageAInputError("bounded pairwise scalar argument has the wrong ABI slot")
    value = _object(argument.get("value"), "bounded pairwise scalar value")
    args = value.get("args")
    if value.get("op") != "and32" or not isinstance(args, list) or len(args) != 2:
        raise StageAInputError("bounded pairwise scalar argument is not a byte load")
    constant, loaded = args
    if not (
        isinstance(constant, Mapping)
        and constant.get("op") == "const"
        and constant.get("value") == 255
        and isinstance(loaded, Mapping)
        and loaded.get("op") == "load"
        and loaded.get("width") == 1
        and loaded.get("address")
        == {"op": "reg", "name": pointer_register, "width": 32}
    ):
        raise StageAInputError(
            "bounded pairwise scalar argument does not read the expected byte"
        )


def _require_control(
    unit: Mapping[str, Any], kind: str, expected_targets: tuple[int, ...]
) -> None:
    control = _object(unit.get("control"), "unit control")
    targets = tuple(int(value) for value in control.get("direct_targets", []))
    if control.get("kind") != kind or targets != expected_targets:
        raise StageAInputError(
            f"bounded string {kind} control does not match the loop graph"
        )


def _require_branch(
    unit: Mapping[str, Any], *, true_target: int, false_target: int
) -> None:
    outcome = _object(unit.get("semantics", {}).get("outcome"), "branch outcome")
    if (
        unit.get("control", {}).get("kind") != "branch"
        or outcome.get("kind") != "branch"
        or outcome.get("true_target_rva") != true_target
        or outcome.get("false_target_rva") != false_target
    ):
        raise StageAInputError("bounded string branch does not match the loop graph")


def _instruction_sequences_match(
    observed: tuple[tuple[str, tuple[tuple[Any, ...], ...]], ...],
    expected: tuple[tuple[str, tuple[tuple[Any, ...], ...]], ...],
) -> bool:
    if len(observed) != len(expected):
        return False
    for observed_instruction, expected_instruction in zip(observed, expected):
        if observed_instruction[0] != expected_instruction[0]:
            return False
        if len(observed_instruction[1]) != len(expected_instruction[1]):
            return False
        for observed_operand, expected_operand in zip(
            observed_instruction[1], expected_instruction[1]
        ):
            if expected_operand[0] == "imm" and expected_operand[1] is None:
                if observed_operand[0] != "imm":
                    return False
            elif observed_operand != expected_operand:
                return False
    return True


def _operand(value: Any) -> tuple[Any, ...]:
    item = _object(value, "instruction operand")
    kind = item.get("kind")
    if kind == "register":
        return _reg(str(item.get("name")))
    if kind == "immediate":
        return _imm(int(item.get("value")))
    if kind == "memory":
        return _mem(
            str(item.get("base")),
            int(item.get("displacement", 0)),
            int(item.get("width_bits")),
            index=item.get("index"),
            scale=int(item.get("scale", 1)),
        )
    return (str(kind),)


def _reg(name: str) -> tuple[Any, ...]:
    return ("reg", name)


def _imm(value: int | None) -> tuple[Any, ...]:
    return ("imm", value)


def _mem(
    base: str,
    displacement: int,
    width_bits: int,
    *,
    index: Any = None,
    scale: int = 1,
) -> tuple[Any, ...]:
    return ("mem", base, displacement, width_bits, index, scale)


def _unit_rva(unit: Mapping[str, Any]) -> int:
    return int(_object(unit.get("source"), "unit source")["original"]["rva_start"])


def _object(value: Any, description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{description} must be an object")
    return value


def _array(value: Any, description: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{description} must be an array")
    return value


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate_bounded_string_contract(payload: Mapping[str, Any]) -> None:
    """Fail closed when a persisted bounded contract is malformed or stale."""

    if payload.get("format") != BOUNDED_STRING_CONTRACT_FORMAT:
        raise StageAInputError("bounded string contract has an unsupported format")
    core = copy.deepcopy(dict(payload))
    expected = core.pop("contract_sha256", None)
    if expected != _canonical_sha256(core):
        raise StageAInputError("bounded string contract self-hash is stale")
    if payload.get("status") != "checked" or payload.get("executes_original_binary") is not False:
        raise StageAInputError("bounded string contract has invalid authority")


def validate_bounded_pairwise_byte_contract(payload: Mapping[str, Any]) -> None:
    """Fail closed when a persisted pairwise-byte contract is malformed."""

    if payload.get("format") != BOUNDED_PAIRWISE_BYTE_CONTRACT_FORMAT:
        raise StageAInputError(
            "bounded pairwise byte contract has an unsupported format"
        )
    core = copy.deepcopy(dict(payload))
    expected = core.pop("contract_sha256", None)
    if expected != _canonical_sha256(core):
        raise StageAInputError("bounded pairwise byte contract self-hash is stale")
    if (
        payload.get("status") != "checked"
        or payload.get("executes_original_binary") is not False
    ):
        raise StageAInputError("bounded pairwise byte contract has invalid authority")
    _checked_scalar_dependency(
        _object(payload.get("component_call"), "bounded pairwise component call")
    )


__all__ = [
    "derive_bounded_pairwise_byte_compare_contract",
    "derive_bounded_string_length_contract",
    "validate_bounded_pairwise_byte_contract",
    "validate_bounded_string_contract",
]
