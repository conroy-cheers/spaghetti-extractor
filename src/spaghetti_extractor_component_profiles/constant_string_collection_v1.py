"""Lift an exact constant-string collection pipeline into portable C."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

import pefile

from spaghetti_extractor.component_profile import (
    ComponentProfileContext,
    PreparedComponentProfile,
    array_value,
    machine_eflags_sync_lines,
    object_value,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file, write_json


_FORMAT = "stage-b-constant-string-collection-contract-v1"
_CALL_UNITS = (2, 3, 4, 5, 9, 14, 19)


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    return sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()


def _rva(unit: Mapping[str, Any]) -> int:
    return int(object_value(unit.get("source"), "unit source")["original"]["rva_start"])


def _operand(value: Any) -> tuple[Any, ...]:
    operand = object_value(value, "instruction operand")
    kind = operand.get("kind")
    if kind == "register":
        return ("r", str(operand.get("name")), int(operand.get("width_bits", 0)))
    if kind == "immediate":
        return ("i", int(operand.get("value", 0)), int(operand.get("width_bits", 0)))
    if kind == "memory":
        return (
            "m",
            operand.get("base"),
            operand.get("index"),
            int(operand.get("scale", 1)),
            int(operand.get("displacement", 0)),
            int(operand.get("width_bits", 0)),
        )
    raise StageAInputError(f"unsupported collection operand kind: {kind!r}")


def _shape(unit: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        (
            str(instruction.get("mnemonic")),
            tuple(
                _operand(value)
                for value in array_value(
                    instruction.get("operands"), "instruction operands"
                )
            ),
        )
        for instruction in array_value(unit.get("instructions"), "unit instructions")
    )


def _r(name: str) -> tuple[Any, ...]:
    return ("r", name, 32)


def _i(value: int) -> tuple[Any, ...]:
    return ("i", value, 32)


def _m(displacement: int) -> tuple[Any, ...]:
    return ("m", "esp", None, 1, displacement, 32)


def _rep() -> tuple[Any, ...]:
    return (
        "rep movsd",
        (
            ("m", "edi", None, 1, 0, 32),
            ("m", "esi", None, 1, 0, 32),
        ),
    )


def _require_call(shape: tuple[Any, ...], prefix: tuple[Any, ...], label: str) -> None:
    if (
        len(shape) != len(prefix) + 1
        or shape[:-1] != prefix
        or shape[-1][0] != "call"
        or len(shape[-1][1]) != 1
        or shape[-1][1][0][0] != "i"
    ):
        raise StageAInputError(f"constant-string collection {label} shape is invalid")


def _read_ascii_c_string(image: Path, address: int) -> tuple[int, str, bytes]:
    try:
        data = image.read_bytes()
        pe = pefile.PE(data=data, fast_load=True)
    except (OSError, pefile.PEFormatError) as error:
        raise StageAInputError(f"cannot inspect collection PE image: {error}") from error
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    if address < image_base:
        raise StageAInputError("collection string address precedes the image")
    rva = address - image_base
    matches: list[int] = []
    for section in pe.sections:
        start = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        if start <= rva < start + raw_size:
            matches.append(int(section.PointerToRawData) + rva - start)
    if len(matches) != 1:
        raise StageAInputError("collection string is not in one raw PE section")
    offset = matches[0]
    end_limit = min(len(data), offset + 257)
    end = data.find(b"\0", offset, end_limit)
    if end < 0 or end == offset:
        raise StageAInputError("collection string is empty or exceeds 256 bytes")
    raw = data[offset:end]
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise StageAInputError("collection string is not portable ASCII") from error
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in text):
        raise StageAInputError("collection string contains non-printable bytes")
    return image_base, text, raw + b"\0"


def _event(unit: Mapping[str, Any], expected_offsets: Sequence[int]) -> dict[str, Any]:
    semantics = object_value(unit.get("semantics"), "collection call semantics")
    events = array_value(semantics.get("external_events"), "collection call events")
    if len(events) != 1:
        raise StageAInputError("collection call must emit exactly one external event")
    event = object_value(events[0], "collection external event")
    stack_inputs = array_value(event.get("stack_inputs"), "collection stack inputs")
    offsets = [int(value.get("offset", -1)) for value in stack_inputs]
    outcome = object_value(semantics.get("outcome"), "collection call outcome")
    instructions = array_value(unit.get("instructions"), "collection instructions")
    if (
        event.get("kind") != "external_call"
        or not isinstance(event.get("dll"), str)
        or not event.get("dll")
        or not isinstance(event.get("symbol"), str)
        or not event.get("symbol")
        or event.get("ordinal") is not None
        or event.get("arguments") != []
        or offsets != list(expected_offsets)
        or any(value.get("width") != 4 for value in stack_inputs)
        or event.get("return_rva") != outcome.get("target_rva")
        or instructions[-1].get("mnemonic") != "call"
    ):
        raise StageAInputError("collection external event is outside the profile")
    return {
        "dll": str(event["dll"]),
        "symbol": str(event["symbol"]),
        "call_rva": int(instructions[-1]["rva_start"]),
        "call_unit_rva": _rva(unit),
        "return_rva": int(event["return_rva"]),
        "reported_stack_inputs": offsets,
    }


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("constant-string collection has no component dependencies")
    if context.static_image is None:
        raise StageAInputError("constant-string collection requires the exact PE image")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("collection units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 21:
        raise StageAInputError("constant-string collection requires 21 machine units")
    shapes = [_shape(unit) for unit in ordered]

    gate = shapes[0]
    if (
        len(gate) != 2
        or gate[0][0] != "cmp"
        or gate[0][1][0] != _r("eax")
        or gate[0][1][1][0] != "i"
        or gate[1][0] != "je"
        or len(gate[1][1]) != 1
        or gate[1][1][0][0] != "i"
    ):
        raise StageAInputError("constant-string collection gate is invalid")
    selector = int(gate[0][1][1][1])

    first = shapes[1]
    if (
        len(first) != 4
        or first[0][0] != "lea"
        or first[0][1][0] != _r("eax")
        or first[0][1][1][0:4] != ("m", "esp", None, 1)
        or first[1][0] != "mov"
        or first[1][1][0] != _m(4)
        or first[1][1][1][0] != "i"
        or first[2][0] != "lea"
        or first[2][1][0] != _r("edi")
        or first[2][1][1] != _m(20)
        or first[3] != ("mov", (_m(0), _r("eax")))
    ):
        raise StageAInputError("constant-string collection first constructor is invalid")
    string_slots = [int(first[0][1][1][4])]
    string_addresses = [int(first[1][1][1][1])]

    second_setup = shapes[2]
    _require_call(
        second_setup,
        (
            ("lea", (_r("esi"), second_setup[0][1][1])),
            ("lea", (_r("ebx"), second_setup[1][1][1])),
        ),
        "first constructor call",
    )
    if second_setup[0][1][1][0:4] != ("m", "esp", None, 1) or second_setup[1][1][1][0:4] != ("m", "esp", None, 1):
        raise StageAInputError("collection constructor slots are not ESP-relative")
    string_slots.append(int(second_setup[0][1][1][4]))
    array_slot = int(second_setup[1][1][1][4])

    third = shapes[3]
    if (
        len(third) != 4
        or third[0][0] != "lea"
        or third[0][1][0] != _r("eax")
        or third[0][1][1][0:4] != ("m", "esp", None, 1)
        or third[1][0] != "mov"
        or third[1][1][0] != _m(4)
        or third[1][1][1][0] != "i"
        or third[2] != ("mov", (_m(0), _r("eax")))
    ):
        raise StageAInputError("constant-string collection second constructor is invalid")
    _require_call(third, third[:-1], "second constructor call")
    string_slots.insert(1, int(third[0][1][1][4]))
    string_addresses.append(int(third[1][1][1][1]))

    fourth = shapes[4]
    if (
        len(fourth) != 3
        or fourth[0] != ("mov", (_m(0), _r("esi")))
        or fourth[1][0] != "mov"
        or fourth[1][1][0] != _m(4)
        or fourth[1][1][1][0] != "i"
    ):
        raise StageAInputError("constant-string collection third constructor is invalid")
    _require_call(fourth, fourth[:-1], "third constructor call")
    string_addresses.append(int(fourth[1][1][1][1]))

    _require_call(shapes[5], (("mov", (_m(0), _r("ebx"))),), "empty collection call")
    append_one_slot = int(shapes[6][1][1][1][4]) if len(shapes[6]) == 3 else -1
    append_two_slot = int(shapes[8][2][1][1][4]) if len(shapes[8]) == 4 else -1
    if (
        shapes[6] != (
            ("mov", (_r("ecx"), _i(4))),
            ("lea", (_r("edx"), _m(append_one_slot))),
            _rep(),
        )
        or shapes[7] != (("lea", (_r("edi"), _m(4))),)
        or shapes[8] != (
            ("mov", (_r("esi"), _r("ebx"))),
            ("mov", (_r("ecx"), _i(4))),
            ("lea", (_r("ebx"), _m(append_two_slot))),
            _rep(),
        )
    ):
        raise StageAInputError("constant-string collection first append setup is invalid")
    _require_call(
        shapes[9],
        (
            ("mov", (_m(0), _r("edx"))),
            ("lea", (_r("edi"), _m(20))),
            ("lea", (_r("esi"), _m(string_slots[1]))),
        ),
        "first append call",
    )
    if (
        shapes[10] != (("mov", (_r("ecx"), _i(4))), _rep())
        or shapes[11] != (
            ("lea", (_r("edi"), _m(4))),
            ("lea", (_r("esi"), _m(append_one_slot))),
        )
        or shapes[12] != (("mov", (_r("ecx"), _i(4))), _rep())
        or shapes[13] != (
            ("mov", (_m(0), _r("ebx"))),
            ("lea", (_r("edi"), _m(20))),
        )
    ):
        raise StageAInputError("constant-string collection second append setup is invalid")
    _require_call(
        shapes[14],
        (("lea", (_r("esi"), _m(string_slots[0]))),),
        "second append call",
    )
    if (
        shapes[15] != (("mov", (_r("ecx"), _i(4))), _rep())
        or shapes[16] != (
            ("lea", (_r("edi"), _m(4))),
            ("mov", (_r("esi"), _r("ebx"))),
        )
        or shapes[17] != (("mov", (_r("ecx"), _i(4))), _rep())
    ):
        raise StageAInputError("constant-string collection final append setup is invalid")
    final_setup = shapes[18]
    if (
        len(final_setup) != 2
        or final_setup[0][0] != "mov"
        or final_setup[0][1][0] != _r("eax")
        or final_setup[0][1][1][0:4] != ("m", "esp", None, 1)
        or final_setup[1] != ("mov", (_m(0), _r("eax")))
    ):
        raise StageAInputError("constant-string collection final output is invalid")
    final_pointer_slot = int(final_setup[0][1][1][4])
    _require_call(shapes[19], (), "final append call")
    if len(shapes[20]) != 1 or shapes[20][0][0] != "jmp":
        raise StageAInputError("constant-string collection continuation is not a jump")

    if (
        len(set(string_slots + [array_slot, append_one_slot, append_two_slot])) != 6
        or any(value < 36 or value % 4 for value in string_slots + [array_slot, append_one_slot, append_two_slot])
        or sorted(string_slots + [array_slot, append_one_slot, append_two_slot])
        != list(range(min(string_slots), min(string_slots) + 96, 16))
        or final_pointer_slot < 36
        or final_pointer_slot % 4
    ):
        raise StageAInputError("constant-string collection stack layout is not canonical")

    starts = [_rva(unit) for unit in ordered]
    gate_fallthrough = int(ordered[0]["source"]["original"]["rva_end"])
    gate_control = object_value(ordered[0].get("control"), "collection gate control")
    if (
        gate_control.get("kind") != "branch"
        or set(gate_control.get("direct_targets", []))
        != {starts[1], gate_fallthrough}
    ):
        raise StageAInputError("constant-string collection gate CFG is invalid")
    exit_rva = next(
        int(value)
        for value in gate_control["direct_targets"]
        if int(value) != starts[1]
    )
    for index, unit in enumerate(ordered[1:-1], start=1):
        control = object_value(unit.get("control"), "collection body control")
        if control.get("kind") != "fallthrough" or control.get("direct_targets") != [starts[index + 1]]:
            raise StageAInputError(f"collection CFG mismatch at RVA 0x{starts[index]:x}")
    final_control = object_value(ordered[-1].get("control"), "collection final control")
    if final_control.get("kind") != "jump" or final_control.get("direct_targets") != [exit_rva]:
        raise StageAInputError("constant-string collection exits do not reconverge")

    expected_offsets = ((), (0, 4), (0, 4), (0,), (0,), (), ())
    events = [
        _event(ordered[unit_index], offsets)
        for unit_index, offsets in zip(_CALL_UNITS, expected_offsets, strict=True)
    ]
    identities = [(value["dll"], value["symbol"]) for value in events]
    if (
        len(set(identities[:3])) != 1
        or len(set(identities[4:])) != 1
        or len({value["dll"] for value in events}) != 1
        or identities[0] == identities[3]
        or identities[0] == identities[4]
        or identities[3] == identities[4]
    ):
        raise StageAInputError("constant-string collection service protocol is invalid")

    strings = []
    image_bases = set()
    for address in string_addresses:
        image_base, text, raw = _read_ascii_c_string(context.static_image, address)
        image_bases.add(image_base)
        strings.append(
            {
                "virtual_address": address,
                "rva": address - image_base,
                "text": text,
                "nul_terminated_bytes_sha256": sha256(raw).hexdigest(),
            }
        )
    if len(image_bases) != 1 or len({value["text"] for value in strings}) != 3:
        raise StageAInputError("constant-string collection literals are ambiguous")
    image_base = next(iter(image_bases))
    manifest_binary = object_value(
        context.machine_ir_manifest.get("binary"), "machine IR binary"
    )
    if manifest_binary.get("image_base") != image_base:
        raise StageAInputError("constant-string collection PE image is stale")

    bindings = [
        {
            "unit_id": str(unit["id"]),
            "rva_start": _rva(unit),
            "rva_end": int(unit["source"]["original"]["rva_end"]),
            "instruction_bytes_sha256": str(unit["source"]["instruction_bytes_sha256"]),
            "semantic_transfer_sha256": str(unit["source"]["semantic_export"]["semantic_transfer_sha256"]),
        }
        for unit in ordered
    ]
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "constant_string_collection_v1",
        "component": {
            "id": str(context.component["id"]),
            "sha256": str(context.component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "static_image_sha256": sha256_file(context.static_image),
            "units": bindings,
        },
        "domain": {
            "kind": "guarded_partial",
            "requires_direction_flag_clear": True,
            "requires_readable_stack_pointer_slot": final_pointer_slot,
            "requires_writable_stack_and_result": True,
            "fallback": "canonical_machine_ir",
            "decline_before_guest_writes": True,
            "decline_before_observable_effects": True,
        },
        "selector": selector,
        "strings": strings,
        "stack": {
            "string_slots": string_slots,
            "array_slot": array_slot,
            "append_one_slot": append_one_slot,
            "append_two_slot": append_two_slot,
            "argument_zero_slot": 4,
            "argument_one_slot": 20,
            "final_pointer_slot": final_pointer_slot,
        },
        "events": events,
        "control": {
            "entry_rva": starts[0],
            "body_rva": starts[1],
            "exit_rva": exit_rva,
            "final_jump_rva": starts[-1],
        },
        "behavior": {
            "service_calls_when_selected": 7,
            "service_order": [value["symbol"] for value in events],
            "append_value_order": [2, 1, 0],
            "unselected_service_calls": 0,
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("constant_string_collection_contract"),
        "constant-string collection contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("constant-string collection contract is stale")
    return contract


def _adapter_parts(
    *, root: Path, backend_workspace: Mapping[str, Any]
) -> tuple[Mapping[str, Any], Path, str]:
    files = object_value(backend_workspace.get("files"), "backend workspace files")
    adapter = root / str(files["machine_adapter_source"])
    matches = re.findall(
        r"stage_b_step_result\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        adapter.read_text(encoding="ascii"),
    )
    if len(matches) != 1:
        raise StageAInputError("collection adapter does not have one entry")
    return files, adapter, matches[0]


def _c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


class ConstantStringCollectionProfile:
    name = "constant_string_collection_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        contract = _contract(interface_refinement)
        stack = object_value(contract["stack"], "collection stack contract")
        value_slots = [
            *array_value(stack["string_slots"], "collection string slots"),
            stack["array_slot"],
            stack["append_one_slot"],
            stack["append_two_slot"],
            stack["final_pointer_slot"],
        ]
        stack_span = max(int(value) for value in value_slots) + 32
        return (
            {
                "semantic_expression": {"op": "reg", "name": "esp", "width": 32},
                "width": stack_span,
                "access": "read_write",
            },
        )

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="collect_constant_strings",
            contract_field="constant_string_collection_contract",
            contract_filename="constant-string-collection-contract.json",
            contract_hash_binding="constant_string_collection_contract_sha256",
            contract=contract,
            activation_domain={
                "kind": "guarded_partial",
                "requires_direction_flag_clear": True,
                "fallback": "canonical_machine_ir",
                "decline_before_guest_writes": True,
                "decline_before_observable_effects": True,
            },
        )

    def install_sources(
        self,
        *,
        root: Path,
        backend_workspace: Mapping[str, Any],
        entry_rva: int,
        prepared: PreparedComponentProfile,
    ) -> None:
        contract = prepared.contract
        stack = object_value(contract["stack"], "collection stack contract")
        control = object_value(contract["control"], "collection control contract")
        events = array_value(contract["events"], "collection events")
        strings = array_value(contract["strings"], "collection strings")
        string_slots = [int(value) for value in stack["string_slots"]]
        array_slot = int(stack["array_slot"])
        append_one_slot = int(stack["append_one_slot"])
        append_two_slot = int(stack["append_two_slot"])
        final_pointer_slot = int(stack["final_pointer_slot"])
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

typedef struct opaque_value4 {
  uint32_t words[4];
} opaque_value4;

typedef struct constant_string_collection_services {
  void *context;
  void (*make_string)(void *context, opaque_value4 *result, const char *text);
  void (*make_collection)(void *context, opaque_value4 *result);
  void (*append)(void *context, opaque_value4 *result,
                 opaque_value4 collection, opaque_value4 value);
} constant_string_collection_services;

uint32_t collect_constant_strings(constant_string_collection_services *services,
                                  uint32_t selector,
                                  opaque_value4 *result);

#endif
"""
        portable = f'''#include "implementation.h"

uint32_t collect_constant_strings(constant_string_collection_services *services,
                                  uint32_t selector,
                                  opaque_value4 *result) {{
  opaque_value4 strings[3], collection, next;
  if (selector != UINT32_C({int(contract["selector"])})) return 0U;
  services->make_string(services->context, &strings[0], {_c_string(str(strings[0]["text"]))});
  services->make_string(services->context, &strings[1], {_c_string(str(strings[1]["text"]))});
  services->make_string(services->context, &strings[2], {_c_string(str(strings[2]["text"]))});
  services->make_collection(services->context, &collection);
  services->append(services->context, &next, collection, strings[2]);
  collection = next;
  services->append(services->context, &next, collection, strings[1]);
  collection = next;
  services->append(services->context, result, collection, strings[0]);
  return 1U;
}}
'''
        event_cases = []
        for index, event in enumerate(events):
            offsets = [int(value) for value in event["reported_stack_inputs"]]
            stack_lines = [
                f"      stack_inputs[{slot}].offset = {offset}U; stack_inputs[{slot}].width = 4U;"
                f" stack_inputs[{slot}].value = read_word(context, context->esp + {offset}U);"
                for slot, offset in enumerate(offsets)
            ]
            event_cases.extend(
                [
                    f"    case {index}U:",
                    *stack_lines,
                    "      event = (stage_b_call_event){",
                    f"        STAGE_B_CALL_EXTERNAL_IMPORT, UINT32_C(0x{int(event['call_rva']):08x}), 0U, 0U, UINT32_C(0x{int(event['return_rva']):08x}),",
                    f"        {_c_string(str(event['dll']))}, {_c_string(str(event['symbol']))}, 0U, 0U, 0, 0U, stack_inputs, {len(offsets)}U",
                    "      };",
                    f"      context->state->original_rva = UINT32_C(0x{int(event['call_unit_rva']):08x});",
                    "      break;",
                ]
            )
        literals = [str(value["text"]) for value in strings]
        addresses = [int(value["virtual_address"]) for value in strings]
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "#include <string.h>",
            "",
            "typedef struct collection_context {",
            "  stage_b_runtime *runtime;",
            "  stage_b_machine_state *state;",
            "  stage_b_call_status status;",
            "  uint32_t esp, next_call;",
            "} collection_context;",
            "",
            "static uint32_t byte_parity(uint32_t value) {",
            "  value ^= value >> 4; value &= UINT32_C(0x0f);",
            "  return (UINT32_C(0x9669) >> value) & UINT32_C(1);",
            "}",
            "",
            "static void subtraction_flags(stage_b_machine_state *state, uint32_t left, uint32_t right, uint32_t result) {",
            "  state->cf = left < right;",
            "  state->of = (((left ^ right) & (left ^ result)) >> 31) & UINT32_C(1);",
            "  state->pf = byte_parity(result); state->sf = result >> 31; state->zf = result == 0U;",
            "}",
            "",
            "static uint32_t read_word(collection_context *context, uint32_t address) {",
            "  uint32_t fault = 0U, value = context->runtime->read(context->runtime->context, address, 4U, &fault);",
            "  if (fault) context->status = STAGE_B_CALL_MEMORY_FAULT;",
            "  return value;",
            "}",
            "",
            "static void write_word(collection_context *context, uint32_t address, uint32_t value) {",
            "  uint32_t fault = 0U;",
            "  context->runtime->write(context->runtime->context, address, 4U, value, &fault);",
            "  if (fault) context->status = STAGE_B_CALL_MEMORY_FAULT;",
            "}",
            "",
            "static opaque_value4 read_value(collection_context *context, uint32_t address) {",
            "  opaque_value4 value;",
            "  value.words[0] = read_word(context, address);",
            "  value.words[1] = read_word(context, address + 4U);",
            "  value.words[2] = read_word(context, address + 8U);",
            "  value.words[3] = read_word(context, address + 12U);",
            "  return value;",
            "}",
            "",
            "static int same_value(opaque_value4 left, opaque_value4 right) {",
            "  return left.words[0] == right.words[0] && left.words[1] == right.words[1] &&",
            "      left.words[2] == right.words[2] && left.words[3] == right.words[3];",
            "}",
            "",
            "static void copy_value(collection_context *context, uint32_t source, uint32_t destination) {",
            "  uint32_t index;",
            "  context->state->esi = source; context->state->edi = destination; context->state->ecx = 4U;",
            "  for (index = 0U; index < 4U && context->status == STAGE_B_CALL_OK; ++index) {",
            "    uint32_t value = read_word(context, context->state->esi);",
            "    write_word(context, context->state->edi, value);",
            "    context->state->esi += 4U; context->state->edi += 4U; context->state->ecx -= 1U;",
            "  }",
            "}",
            "",
            "static void invoke_next(collection_context *context) {",
            "  stage_b_stack_input stack_inputs[2]; stage_b_call_event event;",
            "  stage_b_machine_state output = *context->state;",
            "  if (context->status != STAGE_B_CALL_OK) return;",
            "  switch (context->next_call) {",
            *event_cases,
            "    default: context->status = STAGE_B_CALL_UNIMPLEMENTED; return;",
            "  }",
            "  if (context->status != STAGE_B_CALL_OK) return;",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status == STAGE_B_CALL_OK) *context->state = output;",
            "  context->next_call += 1U;",
            "}",
            "",
            "static void make_string(void *opaque, opaque_value4 *result, const char *text) {",
            "  collection_context *context = (collection_context *)opaque; uint32_t slot, address;",
            "  if (context->status != STAGE_B_CALL_OK || result == 0 || text == 0) return;",
            f"  if (context->next_call == 0U && strcmp(text, {_c_string(literals[0])}) == 0) {{ slot = {string_slots[0]}U; address = UINT32_C(0x{addresses[0]:08x});",
            f"    context->state->eax = context->esp + {string_slots[0]}U; write_word(context, context->esp + 4U, address);",
            "    context->state->edi = context->esp + 20U; write_word(context, context->esp, context->state->eax);",
            f"    context->state->esi = context->esp + {string_slots[2]}U; context->state->ebx = context->esp + {array_slot}U; }}",
            f"  else if (context->next_call == 1U && strcmp(text, {_c_string(literals[1])}) == 0) {{ slot = {string_slots[1]}U; address = UINT32_C(0x{addresses[1]:08x});",
            "    context->state->eax = context->esp + slot; write_word(context, context->esp + 4U, address); write_word(context, context->esp, context->state->eax); }",
            f"  else if (context->next_call == 2U && strcmp(text, {_c_string(literals[2])}) == 0) {{ slot = {string_slots[2]}U; address = UINT32_C(0x{addresses[2]:08x});",
            "    write_word(context, context->esp, context->state->esi); write_word(context, context->esp + 4U, address); }",
            "  else { context->status = STAGE_B_CALL_UNIMPLEMENTED; return; }",
            "  invoke_next(context); *result = read_value(context, context->esp + slot);",
            "}",
            "",
            "static void make_collection(void *opaque, opaque_value4 *result) {",
            "  collection_context *context = (collection_context *)opaque;",
            "  if (context->status != STAGE_B_CALL_OK || result == 0 || context->next_call != 3U) return;",
            "  write_word(context, context->esp, context->state->ebx);",
            "  invoke_next(context); *result = read_value(context, context->esp + " + str(array_slot) + "U);",
            "}",
            "",
            "static void append_value(void *opaque, opaque_value4 *result, opaque_value4 collection, opaque_value4 value) {",
            "  collection_context *context = (collection_context *)opaque; uint32_t source_collection, source_value, destination;",
            "  if (context->status != STAGE_B_CALL_OK || result == 0) return;",
            f"  if (context->next_call == 4U) {{ source_collection = context->esp + {array_slot}U; source_value = context->esp + {string_slots[2]}U; destination = context->esp + {append_one_slot}U;",
            "    if (!same_value(collection, read_value(context, source_collection)) || !same_value(value, read_value(context, source_value))) { context->status = STAGE_B_CALL_UNIMPLEMENTED; return; }",
            "    context->state->edx = destination; copy_value(context, source_value, context->esp + 20U); context->state->edi = context->esp + 4U;",
            f"    context->state->esi = context->state->ebx; context->state->ecx = 4U; context->state->ebx = context->esp + {append_two_slot}U; copy_value(context, source_collection, context->esp + 4U);",
            "    write_word(context, context->esp, context->state->edx); context->state->edi = context->esp + 20U; context->state->esi = context->esp + " + str(string_slots[1]) + "U; }",
            f"  else if (context->next_call == 5U) {{ source_collection = context->esp + {append_one_slot}U; source_value = context->esp + {string_slots[1]}U; destination = context->esp + {append_two_slot}U;",
            "    if (!same_value(collection, read_value(context, source_collection)) || !same_value(value, read_value(context, source_value))) { context->status = STAGE_B_CALL_UNIMPLEMENTED; return; }",
            "    copy_value(context, source_value, context->esp + 20U); context->state->edi = context->esp + 4U; context->state->esi = source_collection; copy_value(context, source_collection, context->esp + 4U);",
            "    write_word(context, context->esp, context->state->ebx); context->state->edi = context->esp + 20U; context->state->esi = context->esp + " + str(string_slots[0]) + "U; }",
            f"  else if (context->next_call == 6U) {{ source_collection = context->esp + {append_two_slot}U; source_value = context->esp + {string_slots[0]}U; destination = read_word(context, context->esp + {final_pointer_slot}U);",
            "    if (!same_value(collection, read_value(context, source_collection)) || !same_value(value, read_value(context, source_value))) { context->status = STAGE_B_CALL_UNIMPLEMENTED; return; }",
            "    copy_value(context, source_value, context->esp + 20U); context->state->edi = context->esp + 4U; context->state->esi = context->state->ebx; copy_value(context, source_collection, context->esp + 4U);",
            "    context->state->eax = destination; write_word(context, context->esp, destination); }",
            "  else { context->status = STAGE_B_CALL_UNIMPLEMENTED; return; }",
            "  invoke_next(context); *result = read_value(context, destination);",
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  collection_context context; constant_string_collection_services services; opaque_value4 result; uint32_t selected, compared;",
            "  if (rt == 0 || rt->read == 0 || rt->write == 0) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            f"  compared = state->eax - UINT32_C({int(contract['selector'])}); subtraction_flags(state, state->eax, UINT32_C({int(contract['selector'])}), compared);",
            *machine_eflags_sync_lines("  "),
            f"  if (state->eax != UINT32_C({int(contract['selector'])})) {{ state->original_rva = UINT32_C(0x{entry_rva:08x}); return (stage_b_step_result){{ STAGE_B_BRANCH, UINT32_C(0x{int(control['exit_rva']):08x}), 0U }}; }}",
            "  if (state->df != 0U) return (stage_b_step_result){ STAGE_B_UNIMPLEMENTED, state->original_rva, 0U };",
            "  context = (collection_context){ rt, state, STAGE_B_CALL_OK, state->esp, 0U };",
            "  services = (constant_string_collection_services){ &context, make_string, make_collection, append_value };",
            "  selected = collect_constant_strings(&services, state->eax, &result);",
            "  if (context.status != STAGE_B_CALL_OK) return (stage_b_step_result){ context.status == STAGE_B_CALL_MEMORY_FAULT ? STAGE_B_MEMORY_FAULT : STAGE_B_UNIMPLEMENTED, state->original_rva, 0U };",
            "  if (selected != 1U || context.next_call != 7U) return (stage_b_step_result){ STAGE_B_UNIMPLEMENTED, state->original_rva, 0U };",
            f"  state->original_rva = UINT32_C(0x{int(control['final_jump_rva']):08x});",
            f"  return (stage_b_step_result){{ STAGE_B_JUMP, UINT32_C(0x{int(control['exit_rva']):08x}), 0U }};",
            "}",
            "",
        ]
        (root / str(files["portable_header"])).write_text(header, encoding="ascii")
        (root / str(files["portable_source"])).write_text(portable, encoding="ascii")
        adapter_path.write_text("\n".join(adapter_lines), encoding="ascii")

    def install_cases(
        self,
        *,
        root: Path,
        backend_workspace: Mapping[str, Any],
        cluster: Mapping[str, Any],
        prepared: PreparedComponentProfile,
    ) -> None:
        contract = _contract(
            {"constant_string_collection_contract": prepared.contract}
        )
        stack = object_value(contract["stack"], "collection stack contract")
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        selectors = (0, 2, 0xFFFFFFFF, 1, 1, 1, 1, 1, 1, 1)
        rows = []
        for index, selector in enumerate(selectors):
            esp = 0x70001000 + index * 0x1000
            destination = 0x71000000 + index * 0x100
            responses = []
            if selector == int(contract["selector"]):
                for call_index in range(7):
                    words = tuple(
                        (0x10000000 * (word + 1) + index * 0x100 + call_index)
                        & 0xFFFFFFFF
                        for word in range(4)
                    )
                    responses.append(
                        {
                            "eax": (0xA0000000 + index * 0x10 + call_index) & 0xFFFFFFFF,
                            "memory_writes": [
                                {
                                    "stack_pointer_offset": 0,
                                    "offset": 0,
                                    "bytes": b"".join(
                                        value.to_bytes(4, "little") for value in words
                                    ).hex(),
                                }
                            ],
                        }
                    )
            rows.append(
                {
                    "id": f"case:constant-string-collection-{index}",
                    "registers": {
                        "eax": selector,
                        "ebx": 0x11110000 + index,
                        "ecx": 0x22220000 + index,
                        "edx": 0x33330000 + index,
                        "esi": 0x44440000 + index,
                        "edi": 0x55550000 + index,
                        "ebp": 0x72000000 + index * 0x100,
                        "esp": esp,
                    },
                    "flags": {
                        "cf": index & 1,
                        "zf": (index >> 1) & 1,
                        "sf": (index >> 2) & 1,
                        "of": (index >> 3) & 1,
                        "pf": (index + 1) & 1,
                        "df": 0,
                    },
                    "memory": [
                        {
                            "address": esp + int(stack["final_pointer_slot"]),
                            "bytes": destination.to_bytes(4, "little").hex(),
                        }
                    ],
                    "external_responses": responses,
                    "external_response_seed": f"constant-string-collection-{index}",
                }
            )
        payload = {
            "format": "stage-b-reconstruction-cases-v1",
            "cluster_id": cluster["id"],
            "entry_unit_id": cluster["entry_unit_id"],
            "entry_rva": cluster["entry_rva"],
            "cases": rows,
        }
        payload["cases_sha256"] = _canonical_sha256(payload)
        write_json(root / str(files["cases"]), payload)

    def render_cbmc_harness(self, refinement: Mapping[str, Any]) -> str:
        contract = _contract(refinement)
        symbol = str(refinement.get("portable_symbol") or "")
        strings = [str(value["text"]) for value in contract["strings"]]
        selector = int(contract["selector"])
        return f'''#include "implementation.h"
#include <stdint.h>
#include <string.h>

extern uint32_t nondet_u32(void);
typedef struct model {{
  uint32_t calls, kinds[7];
  const char *texts[3];
  opaque_value4 responses[7], append_collections[3], append_values[3];
}} model;
static void make_string(void *opaque, opaque_value4 *result, const char *text) {{
  model *m = (model *)opaque; uint32_t index = m->calls++;
  m->kinds[index] = 1U; m->texts[index] = text; *result = m->responses[index];
}}
static void make_collection(void *opaque, opaque_value4 *result) {{
  model *m = (model *)opaque; uint32_t index = m->calls++;
  m->kinds[index] = 2U; *result = m->responses[index];
}}
static void append(void *opaque, opaque_value4 *result, opaque_value4 collection, opaque_value4 value) {{
  model *m = (model *)opaque; uint32_t index = m->calls++, append_index = index - 4U;
  m->kinds[index] = 3U; m->append_collections[append_index] = collection;
  m->append_values[append_index] = value; *result = m->responses[index];
}}
static int equal_value(opaque_value4 a, opaque_value4 b) {{
  return a.words[0] == b.words[0] && a.words[1] == b.words[1] &&
      a.words[2] == b.words[2] && a.words[3] == b.words[3];
}}
int main(void) {{
  model m; constant_string_collection_services services = {{ &m, make_string, make_collection, append }};
  opaque_value4 result = {{{{ nondet_u32(), nondet_u32(), nondet_u32(), nondet_u32() }}}};
  opaque_value4 before = result; uint32_t selector = nondet_u32(), index, word;
  m.calls = 0U;
  for (index = 0U; index < 7U; ++index)
    for (word = 0U; word < 4U; ++word) m.responses[index].words[word] = nondet_u32();
  uint32_t selected = {symbol}(&services, selector, &result);
  if (selector != UINT32_C({selector})) {{
    __CPROVER_assert(selected == 0U, "unselected result");
    __CPROVER_assert(m.calls == 0U, "unselected calls");
    __CPROVER_assert(equal_value(result, before), "unselected output preserved");
  }} else {{
    __CPROVER_assert(selected == 1U, "selected result");
    __CPROVER_assert(m.calls == 7U, "seven service calls");
    __CPROVER_assert(m.kinds[0] == 1U && m.kinds[1] == 1U && m.kinds[2] == 1U, "string calls");
    __CPROVER_assert(strcmp(m.texts[0], {_c_string(strings[0])}) == 0, "first string");
    __CPROVER_assert(strcmp(m.texts[1], {_c_string(strings[1])}) == 0, "second string");
    __CPROVER_assert(strcmp(m.texts[2], {_c_string(strings[2])}) == 0, "third string");
    __CPROVER_assert(m.kinds[3] == 2U, "collection call");
    __CPROVER_assert(m.kinds[4] == 3U && m.kinds[5] == 3U && m.kinds[6] == 3U, "append calls");
    __CPROVER_assert(equal_value(m.append_collections[0], m.responses[3]), "first append collection");
    __CPROVER_assert(equal_value(m.append_values[0], m.responses[2]), "first append value");
    __CPROVER_assert(equal_value(m.append_collections[1], m.responses[4]), "second append collection");
    __CPROVER_assert(equal_value(m.append_values[1], m.responses[1]), "second append value");
    __CPROVER_assert(equal_value(m.append_collections[2], m.responses[5]), "third append collection");
    __CPROVER_assert(equal_value(m.append_values[2], m.responses[0]), "third append value");
    __CPROVER_assert(equal_value(result, m.responses[6]), "final output");
  }}
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 24

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {
            "complete_for_all_selectors_and_service_values_with_df_clear": True,
            "service_calls": 7,
            "outside_domain": "decline_to_canonical_machine_ir",
        }

    def activation_scope_matches(
        self,
        *,
        activation_domain: Mapping[str, Any],
        evidence_scope: Mapping[str, Any],
    ) -> bool:
        return (
            activation_domain.get("kind") == "guarded_partial"
            and activation_domain.get("requires_direction_flag_clear") is True
            and evidence_scope.get(
                "complete_for_all_selectors_and_service_values_with_df_clear"
            )
            is True
        )


PROFILE = ConstantStringCollectionProfile()
