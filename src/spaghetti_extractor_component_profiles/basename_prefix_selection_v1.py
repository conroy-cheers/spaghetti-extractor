"""Portable basename selection with a checked imported-predicate child."""

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


_FORMAT = "stage-b-basename-prefix-selection-contract-v1"


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
    raise StageAInputError(f"unsupported basename-selector operand kind: {kind!r}")


def _shape(unit: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        (
            str(instruction.get("mnemonic")),
            tuple(_operand(value) for value in array_value(instruction.get("operands"), "instruction operands")),
        )
        for instruction in array_value(unit.get("instructions"), "unit instructions")
    )


def _r(name: str, width: int = 32) -> tuple[Any, ...]:
    return ("r", name, width)


def _i(value: int, width: int = 32) -> tuple[Any, ...]:
    return ("i", value, width)


def _m(base: str | None, displacement: int, width: int = 32) -> tuple[Any, ...]:
    return ("m", base, None, 1, displacement, width)


def _event(unit: Mapping[str, Any]) -> Mapping[str, Any]:
    events = array_value(
        object_value(unit.get("semantics"), "unit semantics").get("external_events"),
        "unit external events",
    )
    if len(events) != 1:
        raise StageAInputError(f"expected one call event at RVA 0x{_rva(unit):x}")
    return object_value(events[0], "unit call event")


def _read_image_bytes(
    context: ComponentProfileContext, address: int, count: int
) -> dict[str, Any]:
    if context.static_image is None:
        raise StageAInputError("basename selector requires the exact static PE image")
    image = Path(context.static_image)
    binary = object_value(context.machine_ir_manifest.get("binary"), "machine IR binary")
    if sha256_file(image) != binary.get("sha256"):
        raise StageAInputError("basename selector static image does not match machine IR")
    image_base = int(binary["image_base"])
    pe = pefile.PE(data=image.read_bytes(), fast_load=True)
    raw = bytes(pe.get_data(address - image_base, count))
    if len(raw) != count:
        raise StageAInputError("basename selector static pattern is outside the PE image")
    return {
        "va": address,
        "rva": address - image_base,
        "length": count,
        "bytes_hex": raw.hex(),
        "bytes_sha256": sha256(raw).hexdigest(),
        "image_sha256": str(binary["sha256"]),
    }


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    member_ids = [str(value) for value in context.component["membership"]["resolved_unit_ids"]]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("basename selector units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 16:
        raise StageAInputError("basename selector requires the reviewed sixteen-unit region")
    starts = [_rva(unit) for unit in ordered]
    image_base = int(
        object_value(context.machine_ir_manifest.get("binary"), "machine IR binary")[
            "image_base"
        ]
    )
    frame_bytes = 40
    first = _shape(ordered[0])
    if first != (
        ("push", (_r("ebx"),)),
        ("sub", (_r("esp"), _i(frame_bytes))),
        ("mov", (_r("ebx"), _m("esp", frame_bytes + 8))),
        ("mov", (_m("esp", 4), _i(47))),
    ):
        raise StageAInputError("basename selector prologue is not the reviewed shape")
    if (
        len(_shape(ordered[1])) != 2
        or _shape(ordered[1])[0] != ("mov", (_m("esp", 0), _r("ebx")))
        or _shape(ordered[1])[1][0] != "call"
    ):
        raise StageAInputError("basename selector imported-search call is malformed")
    expected_shapes = {
        2: (("test", (_r("eax"), _r("eax"))), ("je", (_i(image_base + starts[12]),))),
        3: (("lea", (_r("ecx"), _m("eax", 1))), ("mov", (_r("edx"), _r("eax"))), ("mov", (_r("eax"), _r("ecx"))), ("sub", (_r("eax"), _r("ebx")))),
        4: (("cmp", (_r("eax"), _i(6))), ("jle", (_i(image_base + starts[12]),))),
        7: (("test", (_r("al", 8), _r("al", 8))), ("je", (_i(image_base + starts[12]),))),
        8: (("mov", (_r("edx"), _m("esp", 24))), ("mov", (_r("ecx"), _m("esp", 28))), ("cmp", (_m("edx", 1, 8), _i(108, 8))), ("jne", (_i(image_base + starts[14]),))),
        9: (("cmp", (_m("ecx", 1, 8), _i(116, 8))), ("jne", (_i(image_base + starts[14]),))),
        10: (("cmp", (_m("ecx", 2, 8), _i(45, 8))), ("jne", (_i(image_base + starts[14]),))),
        11: (("lea", (_r("ebx"), _m("edx", 4))),),
        13: (("xor", (_r("edx"), _r("edx"))), ("xor", (_r("ecx"), _r("ecx"))), ("ret", ())),
        15: (("xor", (_r("eax"), _r("eax"))), ("xor", (_r("edx"), _r("edx"))), ("xor", (_r("ecx"), _r("ecx"))), ("ret", ())),
    }
    for index, expected in expected_shapes.items():
        if _shape(ordered[index]) != expected:
            raise StageAInputError(f"basename selector unit {index} has an unexpected shape")
    prefix_unit = _shape(ordered[5])
    if (
        len(prefix_unit) != 4
        or prefix_unit[0] != ("lea", (_r("eax"), _m("edx", -6)))
        or prefix_unit[1] != ("mov", (_m("esp", 8), _i(7)))
        or prefix_unit[2][0] != "mov"
        or prefix_unit[2][1][0] != _m("esp", 4)
        or prefix_unit[2][1][1][0] != "i"
        or prefix_unit[3] != ("mov", (_m("esp", 0), _r("eax")))
    ):
        raise StageAInputError("basename selector prefix-call arguments are malformed")
    prefix_address = int(prefix_unit[2][1][1][1])
    child_shape = _shape(ordered[6])
    if (
        len(child_shape) != 3
        or child_shape[:2]
        != (("mov", (_m("esp", 24), _r("edx"))), ("mov", (_m("esp", 28), _r("ecx"))))
        or child_shape[2][0] != "call"
    ):
        raise StageAInputError("basename selector child call is malformed")
    stores = [_shape(ordered[index]) for index in (12, 14)]
    if (
        stores[0] != (("mov", (_m(None, stores[0][0][1][0][4]), _r("ebx"))), ("add", (_r("esp"), _i(frame_bytes))), ("pop", (_r("ebx"),)), ("xor", (_r("eax"), _r("eax"))))
        or stores[1] != (("mov", (_r("ebx"), _r("ecx"))), ("mov", (_m(None, stores[1][1][1][0][4]), _r("ebx"))), ("add", (_r("esp"), _i(frame_bytes))), ("pop", (_r("ebx"),)))
    ):
        raise StageAInputError("basename selector static-store epilogues are malformed")
    global_address = int(stores[0][0][1][0][4])
    if int(stores[1][1][1][0][4]) != global_address:
        raise StageAInputError("basename selector epilogues disagree on the static slot")

    controls = [
        ("fallthrough", [starts[1]]), ("fallthrough", [starts[2]]),
        ("branch", [starts[3], starts[12]]), ("fallthrough", [starts[4]]),
        ("branch", [starts[5], starts[12]]), ("fallthrough", [starts[6]]),
        ("fallthrough", [starts[7]]), ("branch", [starts[8], starts[12]]),
        ("branch", [starts[9], starts[14]]), ("branch", [starts[10], starts[14]]),
        ("branch", [starts[11], starts[14]]), ("fallthrough", [starts[12]]),
        ("fallthrough", [starts[13]]), ("return", []),
        ("fallthrough", [starts[15]]), ("return", []),
    ]
    for unit, (kind, targets) in zip(ordered, controls, strict=True):
        control = object_value(unit.get("control"), "basename selector control")
        if control.get("kind") != kind or set(control.get("direct_targets", [])) != set(targets):
            raise StageAInputError(f"basename selector CFG mismatch at RVA 0x{_rva(unit):x}")

    search_event = _event(ordered[1])
    search_abi = object_value(search_event.get("abi_contract"), "search ABI")
    if (
        search_event.get("kind") != "external_call"
        or len(search_event.get("arguments", [])) != 2
        or search_event.get("return_rva") != starts[2]
        or search_abi.get("template") != "pe32-cdecl-v1"
        or search_abi.get("argument_words") != 2
        or search_abi.get("disposition") != "returns"
    ):
        raise StageAInputError("basename selector search event is outside the cdecl profile")
    child_event = _event(ordered[6])
    if child_event.get("kind") != "internal_call" or child_event.get("return_rva") != starts[7]:
        raise StageAInputError("basename selector child event is malformed")
    if len(context.component_dependencies) != 1:
        raise StageAInputError("basename selector requires exactly one qualified child")
    dependency = object_value(context.component_dependencies[0], "basename selector child")
    child_contract_binding = object_value(dependency.get("component_contract"), "child contract binding")
    child_contract = object_value(child_contract_binding.get("payload"), "child contract")
    child_event_binding = object_value(
        object_value(child_contract.get("bindings"), "child bindings").get("external_event"),
        "child external event",
    )
    if (
        dependency.get("target_rva") != child_event.get("target_rva")
        or dependency.get("activation", {}).get("kind") != "total"
        or child_contract.get("profile") != "external_zero_predicate_v1"
        or dependency.get("external_trace")
        != [{"kind": "external_call", "identity": f"{child_event_binding['dll']}!{child_event_binding['symbol']}"}]
    ):
        raise StageAInputError("basename selector child is not the checked zero-predicate service")

    pattern = _read_image_bytes(context, prefix_address, 7)
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
        "profile": "basename_prefix_selection_v1",
        "component": {
            "id": str(context.component["id"]),
            "sha256": str(context.component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "units": bindings,
            "static_pattern": pattern,
            "child": dependency,
        },
        "domain": {"kind": "total", "requires": "declared call and readable-memory contracts"},
        "search_event": {
            "dll": str(search_event["dll"]),
            "symbol": str(search_event["symbol"]),
            "call_rva": int(ordered[1]["instructions"][-1]["rva_start"]),
            "return_rva": starts[2],
            "separator": 47,
        },
        "child_event": {
            "call_rva": int(ordered[6]["instructions"][-1]["rva_start"]),
            "return_rva": starts[7],
            "target_rva": int(child_event["target_rva"]),
            "external": child_event_binding,
            "frame_bytes": int(child_contract["stack_frame_bytes"]),
        },
        "selection": {
            "minimum_distance_exclusive": 6,
            "prefix_length": 7,
            "marker_bytes": [108, 116, 45],
            "marker_skip": 3,
            "global_address": global_address,
        },
        "machine_projection": {
            "eax": 0, "ecx": 0, "edx": 0, "esp_delta": 4,
            "ebx": "preserved", "flags": {"cf": 0, "of": 0, "pf": 1, "sf": 0, "zf": 1, "df": "latest_external"},
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(refinement.get("basename_prefix_selection_contract"), "basename selector contract")
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("basename selector contract is stale or malformed")
    return contract


def _adapter_parts(*, root: Path, backend_workspace: Mapping[str, Any]) -> tuple[Mapping[str, Any], Path, str]:
    files = object_value(backend_workspace.get("files"), "backend workspace files")
    adapter = root / str(files["machine_adapter_source"])
    matches = re.findall(r"stage_b_step_result\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", adapter.read_text(encoding="ascii"))
    if len(matches) != 1:
        raise StageAInputError("basename selector adapter does not have one entry")
    return files, adapter, matches[0]


def _c_string(value: str) -> str:
    if "\x00" in value:
        raise StageAInputError("import identity contains NUL")
    value.encode("ascii")
    return json.dumps(value, ensure_ascii=True)


class BasenamePrefixSelectionProfile:
    name = "basename_prefix_selection_v1"

    def observable_memory(self, interface_refinement: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        logical = object_value(interface_refinement.get("logical_interface"), "logical interface")
        addresses = {
            int(base["value"])
            for item in array_value(logical.get("objects"), "logical objects")
            if isinstance(item, Mapping)
            and isinstance((base := item.get("base")), Mapping)
            and base.get("op") == "const"
            and isinstance(base.get("value"), int)
            and any(
                isinstance(field, Mapping)
                and "write" in field.get("permissions", [])
                and field.get("width") == 4
                for field in item.get("fields", [])
            )
        }
        if len(addresses) != 1:
            return ()
        address = next(iter(addresses))
        return ({"semantic_expression": {"op": "const", "value": address, "width": 32}, "width": 4, "access": "read_write"},)

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="select_program_name",
            contract_field="basename_prefix_selection_contract",
            contract_filename="basename-prefix-selection-contract.json",
            contract_hash_binding="basename_prefix_selection_contract_sha256",
            contract=contract,
            activation_domain={"kind": "total"},
        )

    def install_sources(self, *, root: Path, backend_workspace: Mapping[str, Any], entry_rva: int, prepared: PreparedComponentProfile) -> None:
        contract = prepared.contract
        search = object_value(contract["search_event"], "search event")
        child = object_value(contract["child_event"], "child event")
        child_external = object_value(child["external"], "child external event")
        selection = object_value(contract["selection"], "selection constants")
        pattern = object_value(contract["bindings"]["static_pattern"], "static pattern")
        child_binding = object_value(contract["bindings"]["child"], "child binding")
        child_symbol = str(child_binding.get("portable_symbol"))
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", child_symbol) is None:
            raise StageAInputError("basename selector child symbol is malformed")
        parent_frame = 40
        child_frame = int(child["frame_bytes"])
        static_address = int(pattern["va"])
        global_address = int(selection["global_address"])
        marker = [int(value) for value in selection["marker_bytes"]]
        files, adapter_path, adapter_symbol = _adapter_parts(root=root, backend_workspace=backend_workspace)
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

typedef struct program_name_services {
  void *context;
  uint32_t (*find_last)(void *context, uint32_t string_address, uint32_t byte_value);
  int (*prefix_matches)(void *context, uint32_t candidate_address);
  uint8_t (*read_byte)(void *context, uint32_t address);
} program_name_services;

uint32_t select_program_name(program_name_services *services, uint32_t argv0);

#endif
"""
        portable = f'''#include "implementation.h"

static int signed_distance_exceeds(uint32_t distance, uint32_t threshold) {{
  return (distance & UINT32_C(0x80000000)) == 0U && distance > threshold;
}}

uint32_t select_program_name(program_name_services *services, uint32_t argv0) {{
  uint32_t separator = services->find_last(services->context, argv0, UINT32_C({int(search['separator'])}));
  uint32_t basename;
  if (separator == 0U ||
      !signed_distance_exceeds(separator + UINT32_C(1) - argv0,
                               UINT32_C({int(selection['minimum_distance_exclusive'])})))
    return argv0;
  if (!services->prefix_matches(services->context,
                                separator - UINT32_C({int(selection['minimum_distance_exclusive'])})))
    return argv0;
  basename = separator + UINT32_C(1);
  if (services->read_byte(services->context, basename) == UINT8_C(0x{marker[0]:02x}) &&
      services->read_byte(services->context, basename + UINT32_C(1)) == UINT8_C(0x{marker[1]:02x}) &&
      services->read_byte(services->context, basename + UINT32_C(2)) == UINT8_C(0x{marker[2]:02x}))
    return basename + UINT32_C({int(selection['marker_skip'])});
  return basename;
}}
'''
        adapter_lines = [
            '#include "state-machine-runtime.h"', '#include "implementation.h"', '',
            'typedef struct reconstructed_compare_service {',
            '  void *context;',
            '  int32_t (*compare)(void *context, const uint8_t *left,',
            '                     const uint8_t *right, uint32_t length);',
            '} reconstructed_compare_service;',
            f'extern int {child_symbol}(reconstructed_compare_service *service,',
            '    const uint8_t *left, const uint8_t *right, uint32_t length);', '',
            'typedef struct selector_context {',
            '  stage_b_runtime *runtime;', '  stage_b_machine_state *state;',
            '  stage_b_call_status status;', '  uint32_t memory_fault;',
            '  uint32_t argv0;', '  uint32_t separator;', '  uint32_t parent_frame_esp;',
            '} selector_context;', '',
            'static uint32_t byte_parity(uint32_t value) {',
            '  value ^= value >> 4; value &= UINT32_C(0x0f);',
            '  return (UINT32_C(0x9669) >> value) & UINT32_C(1);', '}', '',
            'static void subtraction_flags(stage_b_machine_state *state, uint32_t left, uint32_t right, uint32_t result) {',
            '  state->cf = left < right;',
            '  state->of = (((left ^ right) & (left ^ result)) >> 31) & UINT32_C(1);',
            '  state->pf = byte_parity(result); state->sf = result >> 31; state->zf = result == 0U;', '}', '',
            'static uint32_t find_last(void *opaque, uint32_t string_address, uint32_t byte_value) {',
            '  selector_context *context = (selector_context *)opaque;',
            '  stage_b_machine_state output = *context->state;',
            '  const uint32_t arguments[] = { string_address, byte_value };',
            '  const stage_b_stack_input stack_inputs[] = { { 0U, 4U, string_address } };',
            '  const stage_b_call_event event = {',
            f'    STAGE_B_CALL_EXTERNAL_IMPORT, UINT32_C(0x{int(search["call_rva"]):08x}), 0U, 0U, UINT32_C(0x{int(search["return_rva"]):08x}),',
            f'    {_c_string(str(search["dll"]))}, {_c_string(str(search["symbol"]))}, 0U, 0U, arguments, 2U, stack_inputs, 1U',
            '  };',
            '  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);',
            '  if (context->status == STAGE_B_CALL_OK) *context->state = output;',
            '  context->separator = output.eax; return output.eax;', '}', '',
            'static int32_t invoke_child_compare(void *opaque, const uint8_t *left,',
            '                                    const uint8_t *right, uint32_t length) {',
            '  selector_context *context = (selector_context *)opaque;',
            '  stage_b_machine_state output = *context->state;',
            '  const uint32_t arguments[] = {',
            '    (uint32_t)(uintptr_t)left, (uint32_t)(uintptr_t)right, length',
            '  };',
            '  const stage_b_stack_input stack_inputs[] = {',
            '    { 0U, 4U, (uint32_t)(uintptr_t)left },',
            '    { 4U, 4U, (uint32_t)(uintptr_t)right }',
            '  };',
            '  const stage_b_call_event event = {',
            f'    STAGE_B_CALL_EXTERNAL_IMPORT, UINT32_C(0x{int(child_external["call_rva"]):08x}), 0U, 0U, UINT32_C(0x{int(child_external["return_rva"]):08x}),',
            f'    {_c_string(str(child_external["dll"]))}, {_c_string(str(child_external["symbol"]))}, 0U, 0U, arguments, 3U, stack_inputs, 2U',
            '  };',
            '  context->status = stage_b_invoke_call(',
            '      context->runtime, &event, context->state, &output);',
            '  if (context->status == STAGE_B_CALL_OK) *context->state = output;',
            '  return (int32_t)output.eax;', '}', '',
            'static int prefix_matches(void *opaque, uint32_t candidate_address) {',
            '  selector_context *context = (selector_context *)opaque;',
            '  uint32_t fault = 0U, child_entry_esp, child_frame_esp, raw, predicate, added;',
            '  reconstructed_compare_service child_service = { context, invoke_child_compare };',
            '  context->state->edx = context->separator; context->state->ecx = context->separator + UINT32_C(1);',
            '  context->state->eax = context->state->ecx - context->argv0;',
            '  subtraction_flags(context->state, context->state->eax, UINT32_C(6), context->state->eax - UINT32_C(6));',
            '  context->state->eax = candidate_address;',
            '  context->runtime->write(context->runtime->context, context->parent_frame_esp + UINT32_C(8), 4U, UINT32_C(7), &fault);',
            f'  context->runtime->write(context->runtime->context, context->parent_frame_esp + UINT32_C(4), 4U, UINT32_C(0x{static_address:08x}), &fault);',
            '  context->runtime->write(context->runtime->context, context->parent_frame_esp, 4U, candidate_address, &fault);',
            '  context->runtime->write(context->runtime->context, context->parent_frame_esp + UINT32_C(24), 4U, context->separator, &fault);',
            '  context->runtime->write(context->runtime->context, context->parent_frame_esp + UINT32_C(28), 4U, context->separator + UINT32_C(1), &fault);',
            '  if (fault) { context->memory_fault = 1U; return 0; }',
            '  child_entry_esp = context->parent_frame_esp - UINT32_C(4);',
            f'  child_frame_esp = child_entry_esp - UINT32_C({child_frame});',
            f'  context->runtime->write(context->runtime->context, child_entry_esp, 4U, UINT32_C(0x{int(child["return_rva"]):08x}), &fault);',
            f'  context->runtime->write(context->runtime->context, child_frame_esp + UINT32_C(8), 4U, UINT32_C({int(selection["prefix_length"])}), &fault);',
            f'  context->runtime->write(context->runtime->context, child_frame_esp + UINT32_C(4), 4U, UINT32_C(0x{static_address:08x}), &fault);',
            '  context->runtime->write(context->runtime->context, child_frame_esp, 4U, candidate_address, &fault);',
            '  if (fault) { context->memory_fault = 1U; return 0; }',
            '  context->state->esp = child_frame_esp; context->state->eax = candidate_address;',
            '  subtraction_flags(context->state, child_entry_esp, UINT32_C(' + str(child_frame) + '), child_frame_esp);',
            f'  predicate = (uint32_t){child_symbol}(&child_service,',
            '      (const uint8_t *)(uintptr_t)candidate_address,',
            f'      (const uint8_t *)(uintptr_t)UINT32_C(0x{static_address:08x}),',
            f'      UINT32_C({int(selection["prefix_length"])}));',
            '  if (context->status != STAGE_B_CALL_OK) return 0;',
            '  raw = context->state->eax;',
            '  context->state->eax = (raw & UINT32_C(0xffffff00)) | predicate;',
            f'  added = context->state->esp + UINT32_C({child_frame});',
            f'  context->state->cf = added < context->state->esp; context->state->of = (((~(context->state->esp ^ UINT32_C({child_frame}))) & (context->state->esp ^ added)) >> 31) & 1U;',
            '  context->state->pf = byte_parity(added); context->state->sf = added >> 31; context->state->zf = added == 0U;',
            '  context->state->esp = added + UINT32_C(4); return (int)predicate;', '}', '',
            'static uint8_t read_byte(void *opaque, uint32_t address) {',
            '  selector_context *context = (selector_context *)opaque; uint32_t fault = 0U;',
            '  context->state->edx = context->separator; context->state->ecx = context->separator + UINT32_C(1);',
            '  { uint32_t value = context->runtime->read(context->runtime->context, address, 1U, &fault);',
            '    if (fault) context->memory_fault = 1U;',
            '    return (uint8_t)value;',
            '  }', '}', '',
            f'stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{',
            '  uint32_t fault = 0U, entry_esp, pushed_esp, frame_esp, argv0, selected, return_target;',
            '  selector_context context; program_name_services services;',
            '  if (rt == 0 || rt->read == 0 || rt->write == 0) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
            '  entry_esp = state->esp; pushed_esp = entry_esp - UINT32_C(4);',
            f'  frame_esp = pushed_esp - UINT32_C({parent_frame});',
            '  rt->write(rt->context, pushed_esp, 4U, state->ebx, &fault);',
            '  argv0 = rt->read(rt->context, entry_esp + UINT32_C(4), 4U, &fault);',
            '  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
            '  state->esp = frame_esp; state->ebx = argv0;',
            f'  subtraction_flags(state, pushed_esp, UINT32_C({parent_frame}), frame_esp);',
            f'  state->original_rva = UINT32_C(0x{entry_rva:08x});',
            f'  rt->write(rt->context, frame_esp + UINT32_C(4), 4U, UINT32_C({int(search["separator"])}), &fault);',
            '  rt->write(rt->context, frame_esp, 4U, argv0, &fault);',
            '  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
            '  context = (selector_context){ rt, state, STAGE_B_CALL_OK, 0U, argv0, 0U, frame_esp };',
            '  services = (program_name_services){ &context, find_last, prefix_matches, read_byte };',
            '  selected = select_program_name(&services, argv0);',
            '  if (context.memory_fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };',
            '  if (context.status != STAGE_B_CALL_OK) return (stage_b_step_result){ STAGE_B_EXTERNAL_FAULT, state->original_rva, 0U };',
            f'  rt->write(rt->context, UINT32_C(0x{global_address:08x}), 4U, selected, &fault);',
            '  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };',
            f'  state->esp = frame_esp + UINT32_C({parent_frame});',
            '  state->ebx = rt->read(rt->context, state->esp, 4U, &fault); state->esp += UINT32_C(4);',
            '  return_target = rt->read(rt->context, state->esp, 4U, &fault); state->esp += UINT32_C(4);',
            '  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };',
            '  state->eax = 0U; state->ecx = 0U; state->edx = 0U;',
            '  state->cf = 0U; state->of = 0U; state->pf = 1U; state->sf = 0U; state->zf = 1U;',
            *machine_eflags_sync_lines('  '),
            '  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };', '}', '',
        ]
        (root / str(files["portable_header"])).write_text(header, encoding="ascii")
        (root / str(files["portable_source"])).write_text(portable, encoding="ascii")
        adapter_path.write_text("\n".join(adapter_lines), encoding="ascii")

    def install_cases(self, *, root: Path, backend_workspace: Mapping[str, Any], cluster: Mapping[str, Any], prepared: PreparedComponentProfile) -> None:
        contract = prepared.contract
        global_address = int(contract["selection"]["global_address"])
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        esp, base = 0x70001000, 0x70002000
        probes = [
            ("no-separator", b"hello\0", 0, None),
            ("short-distance", b"12345/x\0", base + 5, None),
            ("child-false", b"123456/x\0", base + 6, 1),
            ("marker-first-mismatch", b"123456/xoo\0", base + 6, 0),
            ("marker-second-mismatch", b"123456/lx-foo\0", base + 6, 0),
            ("marker-third-mismatch", b"123456/ltxfoo\0", base + 6, 0),
            ("marker-match", b"123456/lt-hello\0", base + 6, 0),
            ("wrapped-distance", b"abcdef/lt-name\0", base + 6, 0),
            ("late-separator", b"prefix/lt-tool\0", base + 6, 0),
            ("child-negative", b"123456/lt-tool\0", base + 6, 0xFFFFFFFF),
        ]
        rows = []
        for index, (label, data, separator, compare_result) in enumerate(probes):
            responses = [{"eax": separator}]
            if compare_result is not None:
                responses.append({"eax": compare_result})
            rows.append({
                "id": f"case:basename-prefix-{label}",
                "registers": {"eax": 0x10203040 + index, "ebx": 0x11223344, "ecx": 0x55667788, "edx": 0x89ABCDEF, "esi": 0x12345678, "edi": 0x87654321, "ebp": 0x70004000, "esp": esp},
                "flags": {"cf": index & 1, "zf": (index >> 1) & 1, "sf": (index >> 2) & 1, "of": (index >> 3) & 1, "pf": 0, "df": index & 1},
                "memory": [
                    {"address": esp, "bytes": "78563412"},
                    {"address": esp + 4, "bytes": base.to_bytes(4, "little").hex()},
                    {"address": base, "bytes": data.hex()},
                    {"address": global_address, "bytes": (0xDEADBEEF).to_bytes(4, "little").hex()},
                ],
                "external_responses": responses,
                "external_response_seed": f"basename-prefix-{label}",
            })
        payload = {"format": "stage-b-reconstruction-cases-v1", "cluster_id": cluster["id"], "entry_unit_id": cluster["entry_unit_id"], "entry_rva": cluster["entry_rva"], "cases": rows}
        payload["cases_sha256"] = _canonical_sha256(payload)
        write_json(root / str(files["cases"]), payload)

    def render_cbmc_harness(self, refinement: Mapping[str, Any]) -> str:
        symbol = str(refinement.get("portable_symbol") or "")
        contract = _contract(refinement)
        selection = contract["selection"]
        marker = selection["marker_bytes"]
        return f'''#include "implementation.h"
#include <stdint.h>

extern uint32_t nondet_u32(void);
typedef struct model {{ uint32_t argv0, separator, candidate, find_calls, match_calls, read_calls; int match; uint8_t bytes[3]; }} model;
static uint32_t find_last(void *opaque, uint32_t address, uint32_t byte) {{ model *m=opaque; m->find_calls++; __CPROVER_assert(address==m->argv0, "search address"); __CPROVER_assert(byte==UINT32_C({contract['search_event']['separator']}), "search byte"); return m->separator; }}
static int prefix_matches(void *opaque, uint32_t candidate) {{ model *m=opaque; m->match_calls++; m->candidate=candidate; return m->match; }}
static uint8_t read_byte(void *opaque, uint32_t address) {{ model *m=opaque; uint32_t offset=address-(m->separator+1U); __CPROVER_assert(offset<3U, "marker read range"); m->read_calls++; return m->bytes[offset]; }}
int main(void) {{
  model m={{0}}; program_name_services services={{&m,find_last,prefix_matches,read_byte}}; uint32_t actual, expected, distance;
  m.argv0=nondet_u32(); m.separator=nondet_u32(); m.match=(int)(nondet_u32()&1U); m.bytes[0]=(uint8_t)nondet_u32(); m.bytes[1]=(uint8_t)nondet_u32(); m.bytes[2]=(uint8_t)nondet_u32();
  actual={symbol}(&services,m.argv0); expected=m.argv0; distance=m.separator+1U-m.argv0;
  if (m.separator!=0U && (distance&UINT32_C(0x80000000))==0U && distance>UINT32_C({selection['minimum_distance_exclusive']}) && m.match) {{ expected=m.separator+1U; if (m.bytes[0]==UINT8_C({marker[0]}) && m.bytes[1]==UINT8_C({marker[1]}) && m.bytes[2]==UINT8_C({marker[2]})) expected+=UINT32_C({selection['marker_skip']}); }}
  __CPROVER_assert(actual==expected,"selected program name"); __CPROVER_assert(m.find_calls==1U,"one search call");
  __CPROVER_assert(m.match_calls==((m.separator!=0U && (distance&UINT32_C(0x80000000))==0U && distance>UINT32_C({selection['minimum_distance_exclusive']}))?1U:0U),"conditional child call");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement); return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement); return {"complete_for_all_32_bit_inputs_and_service_results": True, "loops": 0}

    def activation_scope_matches(self, *, activation_domain: Mapping[str, Any], evidence_scope: Mapping[str, Any]) -> bool:
        return activation_domain.get("kind") == "total" and evidence_scope.get("complete_for_all_32_bit_inputs_and_service_results") is True


PROFILE = BasenamePrefixSelectionProfile()
