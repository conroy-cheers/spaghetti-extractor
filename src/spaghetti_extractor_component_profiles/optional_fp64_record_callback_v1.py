"""Lift an optional callback over a two-word and three-FP64 record."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from spaghetti_extractor.component_profile import (
    ComponentProfileContext,
    PreparedComponentProfile,
    array_value,
    machine_eflags_sync_lines,
    object_value,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import write_json


_FORMAT = "stage-b-optional-fp64-record-callback-contract-v1"


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
    raise StageAInputError(f"unsupported optional-callback operand: {kind!r}")


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


def _r(name: str, width: int = 32) -> tuple[Any, ...]:
    return ("r", name, width)


def _i(value: int) -> tuple[Any, ...]:
    return ("i", value, 32)


def _m(base: str | None, displacement: int, width: int = 32) -> tuple[Any, ...]:
    return ("m", base, None, 1, displacement, width)


def _require_edge(unit: Mapping[str, Any], kind: str, targets: Sequence[int]) -> None:
    control = object_value(unit.get("control"), "optional-callback control")
    if control.get("kind") != kind or set(control.get("direct_targets", [])) != set(targets):
        raise StageAInputError(
            f"optional-callback CFG mismatch at RVA 0x{_rva(unit):x}"
        )


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("optional record callback has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("optional-callback units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) == 19 and all(
        mnemonic == "nop" for mnemonic, _operands in _shape(ordered[0])
    ):
        padding = ordered.pop(0)
    else:
        padding = None
    if len(ordered) != 18:
        raise StageAInputError("optional FP64 record callback requires eighteen code units")

    first = _shape(ordered[0])
    if (
        len(first) != 2
        or first[0][0] != "sub"
        or first[0][1][0] != _r("esp")
        or first[0][1][1][0] != "i"
        or first[1][0] != "mov"
        or first[1][1][0] != _r("eax")
        or first[1][1][1][:4] != ("m", None, None, 1)
        or first[1][1][1][5] != 32
    ):
        raise StageAInputError("optional-callback prologue is outside the reviewed shape")
    frame_bytes = int(first[0][1][1][1])
    callback_slot = int(first[1][1][1][4])
    if frame_bytes < 48 or frame_bytes % 4:
        raise StageAInputError("optional-callback frame is too small or unaligned")

    fp_offsets = (frame_bytes + 12, frame_bytes + 20, frame_bytes + 28)
    if tuple(_shape(ordered[index]) for index in range(1, 4)) != tuple(
        (("fld", (_m("esp", offset, 64),)),) for offset in fp_offsets
    ):
        raise StageAInputError("optional-callback FP64 arguments are not exact stack loads")
    if _shape(ordered[4]) != (
        ("test", (_r("eax"), _r("eax"))),
        ("je", (_i(_rva(ordered[14]) + int(context.machine_ir_manifest["binary"]["image_base"])),)),
    ):
        raise StageAInputError("optional-callback null-target branch is malformed")
    if _shape(ordered[5]) != (("fxch", (_r("st(0)", 80), _r("st(2)", 80))),):
        raise StageAInputError("optional-callback FP64 reorder is malformed")
    if _shape(ordered[6]) != (("mov", (_r("edx"), _m("esp", frame_bytes + 4))),):
        raise StageAInputError("optional-callback first scalar load is malformed")
    if _shape(ordered[7]) != (("fstp", (_m("esp", 24, 64),)),):
        raise StageAInputError("optional-callback first FP64 record field is malformed")
    if _shape(ordered[8]) != (("fstp", (_m("esp", 32, 64),)),):
        raise StageAInputError("optional-callback second FP64 record field is malformed")
    if _shape(ordered[9]) != (
        ("mov", (_m("esp", 16), _r("edx"))),
        ("mov", (_r("edx"), _m("esp", frame_bytes + 8))),
    ):
        raise StageAInputError("optional-callback scalar record prefix is malformed")
    if _shape(ordered[10]) != (("fstp", (_m("esp", 40, 64),)),):
        raise StageAInputError("optional-callback third FP64 record field is malformed")
    if _shape(ordered[11]) != (("mov", (_m("esp", 20), _r("edx"))),):
        raise StageAInputError("optional-callback second scalar field is malformed")
    call_shape = _shape(ordered[12])
    if call_shape != (
        ("lea", (_r("edx"), _m("esp", 16))),
        ("mov", (_m("esp", 0), _r("edx"))),
        ("call", (_r("eax"),)),
    ):
        raise StageAInputError("optional-callback indirect call is malformed")
    if _shape(ordered[13]) != (("jmp", (_i(_rva(ordered[17]) + int(context.machine_ir_manifest["binary"]["image_base"])),)),):
        raise StageAInputError("optional-callback continuation jump is malformed")
    for index in range(14, 17):
        if _shape(ordered[index]) != (("fstp", (_r("st(0)", 80),)),):
            raise StageAInputError("optional-callback null path does not balance x87")
    if _shape(ordered[17]) != (
        ("add", (_r("esp"), _i(frame_bytes))),
        ("xor", (_r("eax"), _r("eax"))),
        ("xor", (_r("edx"), _r("edx"))),
        ("ret", ()),
    ):
        raise StageAInputError("optional-callback epilogue is malformed")

    starts = [_rva(unit) for unit in ordered]
    if padding is not None:
        _require_edge(padding, "fallthrough", [starts[0]])
    for index in range(0, 4):
        _require_edge(ordered[index], "fallthrough", [starts[index + 1]])
    _require_edge(ordered[4], "branch", [starts[5], starts[14]])
    for index in range(5, 13):
        _require_edge(ordered[index], "fallthrough", [starts[index + 1]])
    _require_edge(ordered[13], "jump", [starts[17]])
    _require_edge(ordered[14], "fallthrough", [starts[15]])
    _require_edge(ordered[15], "fallthrough", [starts[16]])
    _require_edge(ordered[16], "fallthrough", [starts[17]])
    _require_edge(ordered[17], "return", [])

    events = array_value(
        object_value(ordered[12].get("semantics"), "call semantics").get(
            "external_events"
        ),
        "optional-callback events",
    )
    if len(events) != 1:
        raise StageAInputError("optional-callback call must emit one event")
    event = object_value(events[0], "optional-callback event")
    stack_inputs = array_value(event.get("stack_inputs"), "callback stack inputs")
    if (
        event.get("kind") != "indirect_call"
        or event.get("target") != {"name": "eax", "op": "reg", "width": 32}
        or event.get("return_rva") != starts[13]
        or len(stack_inputs) != 1
        or stack_inputs[0].get("offset") != 0
        or stack_inputs[0].get("width") != 4
    ):
        raise StageAInputError("optional-callback event ABI is malformed")

    all_units = ([padding] if padding is not None else []) + ordered
    bindings = [
        {
            "unit_id": str(unit["id"]),
            "rva_start": _rva(unit),
            "rva_end": int(unit["source"]["original"]["rva_end"]),
            "instruction_bytes_sha256": str(unit["source"]["instruction_bytes_sha256"]),
            "semantic_transfer_sha256": (
                None
                if unit["source"].get("semantic_export") is None
                else str(
                    unit["source"]["semantic_export"]["semantic_transfer_sha256"]
                )
            ),
        }
        for unit in all_units
    ]
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "units": bindings,
            "units_sha256": _canonical_sha256({"units": bindings}),
            "callback_event_sha256": _canonical_sha256(event),
        },
        "abi": {
            "stack_frame_bytes": frame_bytes,
            "callback_slot": callback_slot,
            "argument_offsets": {
                "code": frame_bytes + 4,
                "name": frame_bytes + 8,
                "first_fp64": frame_bytes + 12,
                "second_fp64": frame_bytes + 20,
                "result_fp64": frame_bytes + 28,
            },
            "record_offset": 16,
            "record_field_offsets": [0, 4, 8, 16, 24],
        },
        "control": {
            "call_rva": int(ordered[12]["instructions"][-1]["rva_start"]),
            "return_rva": starts[13],
        },
        "semantics": {
            "callback_is_optional": True,
            "callback_receives_one_record_pointer": True,
            "record_preserves_all_input_bits": True,
            "return_value": 0,
            "x87_stack_depth_delta": 0,
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("optional_fp64_record_callback_contract"),
        "optional FP64 record callback contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("optional FP64 record callback contract is stale")
    return contract


def _adapter_parts(
    *, root: Path, backend_workspace: Mapping[str, Any]
) -> tuple[Mapping[str, Any], Path, str]:
    files = object_value(backend_workspace.get("files"), "backend workspace files")
    adapter = root / str(files["machine_adapter_source"])
    symbols = re.findall(
        r"stage_b_step_result\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        adapter.read_text(encoding="ascii"),
    )
    if len(symbols) != 1:
        raise StageAInputError("optional-callback adapter does not have one entry")
    return files, adapter, symbols[0]


_HEADER = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

typedef struct optional_fp64_record {
  uint32_t code;
  uint32_t name;
  uint64_t first_bits;
  uint64_t second_bits;
  uint64_t result_bits;
} optional_fp64_record;

typedef struct optional_fp64_record_callback {
  void *context;
  uint32_t target;
  void (*invoke)(void *context, uint32_t target,
                 const optional_fp64_record *record);
} optional_fp64_record_callback;

uint32_t dispatch_optional_fp64_record(
    optional_fp64_record_callback *callback,
    optional_fp64_record record);

#endif
"""


_PORTABLE = """#include "implementation.h"

uint32_t dispatch_optional_fp64_record(
    optional_fp64_record_callback *callback,
    optional_fp64_record record) {
  if (callback->target != 0U)
    callback->invoke(callback->context, callback->target, &record);
  return 0U;
}
"""


class OptionalFp64RecordCallbackProfile:
    name = "optional_fp64_record_callback_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        _contract(interface_refinement)
        return ()

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="dispatch_optional_fp64_record",
            contract_field="optional_fp64_record_callback_contract",
            contract_filename="optional-fp64-record-callback-contract.json",
            contract_hash_binding="optional_fp64_record_callback_contract_sha256",
            contract=contract,
            activation_domain={
                "kind": "guarded_partial",
                "requires_masked_x87_exceptions": True,
                "requires_no_pending_x87_exception": True,
                "requires_three_free_x87_slots": True,
                "rejects_signaling_nan_inputs": True,
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
        abi = object_value(contract["abi"], "optional-callback ABI")
        control = object_value(contract["control"], "optional-callback control")
        frame_bytes = int(abi["stack_frame_bytes"])
        callback_slot = int(abi["callback_slot"])
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        sync = machine_eflags_sync_lines("  ")
        context_sync = [line.replace("state->", "context->state->") for line in sync]
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            "typedef struct callback_context {",
            "  stage_b_runtime *runtime; stage_b_machine_state *state;",
            "  stage_b_call_status status; uint32_t frame_esp;",
            "} callback_context;",
            "",
            "static uint32_t byte_parity(uint32_t value) {",
            "  value ^= value >> 4; value &= UINT32_C(0x0f);",
            "  return (UINT32_C(0x9669) >> value) & UINT32_C(1);",
            "}",
            "",
            "static void logical_flags(stage_b_machine_state *state, uint32_t value) {",
            "  state->cf = 0U; state->of = 0U; state->pf = byte_parity(value);",
            "  state->sf = value >> 31; state->zf = value == 0U;",
            "}",
            "",
            "static uint32_t fp64_is_signaling_nan(uint64_t bits) {",
            "  uint64_t exponent = bits & UINT64_C(0x7ff0000000000000);",
            "  uint64_t fraction = bits & UINT64_C(0x000fffffffffffff);",
            "  return exponent == UINT64_C(0x7ff0000000000000) && fraction != 0U &&",
            "      (fraction & UINT64_C(0x0008000000000000)) == 0U;",
            "}",
            "",
            "static uint32_t x87_activation_guard(const stage_b_machine_state *state,",
            "    const optional_fp64_record *record) {",
            "  return (state->x87_control & UINT16_C(0x003f)) == UINT16_C(0x003f) &&",
            "      state->x87_pending_exception == 0U &&",
            "      (state->x87_status & UINT16_C(0x0080)) == 0U &&",
            "      state->x87_stack[5].empty != 0U && state->x87_stack[5].tag == 3U &&",
            "      state->x87_stack[6].empty != 0U && state->x87_stack[6].tag == 3U &&",
            "      state->x87_stack[7].empty != 0U && state->x87_stack[7].tag == 3U &&",
            "      !fp64_is_signaling_nan(record->first_bits) &&",
            "      !fp64_is_signaling_nan(record->second_bits) &&",
            "      !fp64_is_signaling_nan(record->result_bits);",
            "}",
            "",
            "static void invoke_callback(void *opaque, uint32_t target,",
            "                            const optional_fp64_record *record) {",
            "  callback_context *context = (callback_context *)opaque;",
            "  stage_b_machine_state output; stage_b_stack_input stack_input;",
            "  stage_b_call_event event = {0}; uint32_t fault = 0U;",
            "  uint32_t record_address = context->frame_esp + UINT32_C(16);",
            "  if (context->status != STAGE_B_CALL_OK) return;",
            "  context->runtime->write(context->runtime->context, record_address + 0U, 4U, record->code, &fault);",
            "  context->runtime->write(context->runtime->context, record_address + 4U, 4U, record->name, &fault);",
            "  context->runtime->write(context->runtime->context, record_address + 8U, 4U, (uint32_t)record->first_bits, &fault);",
            "  context->runtime->write(context->runtime->context, record_address + 12U, 4U, (uint32_t)(record->first_bits >> 32), &fault);",
            "  context->runtime->write(context->runtime->context, record_address + 16U, 4U, (uint32_t)record->second_bits, &fault);",
            "  context->runtime->write(context->runtime->context, record_address + 20U, 4U, (uint32_t)(record->second_bits >> 32), &fault);",
            "  context->runtime->write(context->runtime->context, record_address + 24U, 4U, (uint32_t)record->result_bits, &fault);",
            "  context->runtime->write(context->runtime->context, record_address + 28U, 4U, (uint32_t)(record->result_bits >> 32), &fault);",
            "  context->runtime->write(context->runtime->context, context->frame_esp, 4U, record_address, &fault);",
            "  if (fault) { context->status = STAGE_B_CALL_MEMORY_FAULT; return; }",
            "  context->state->eax = target; context->state->edx = record_address;",
            "  logical_flags(context->state, target);",
            "  stack_input = (stage_b_stack_input){ 0U, 4U, record_address };",
            "  event.kind = STAGE_B_CALL_INDIRECT; event.target_rva = target;",
            f"  event.instruction_rva = UINT32_C(0x{int(control['call_rva']):08x});",
            f"  event.return_rva = UINT32_C(0x{int(control['return_rva']):08x});",
            "  event.stack_inputs = &stack_input; event.stack_input_count = 1U;",
            *context_sync,
            "  output = *context->state;",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status == STAGE_B_CALL_OK) *context->state = output;",
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  uint32_t entry_esp, frame_esp, target, return_target, fault = 0U;",
            "  optional_fp64_record record; optional_fp64_record_callback callback;",
            "  callback_context context;",
            "  if (rt == 0 || rt->read == 0 || rt->write == 0)",
            "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  entry_esp = state->esp;",
            f"  frame_esp = entry_esp - UINT32_C({frame_bytes});",
            f"  target = rt->read(rt->context, UINT32_C(0x{callback_slot:08x}), 4U, &fault);",
            f"  record.code = rt->read(rt->context, entry_esp + UINT32_C(4), 4U, &fault);",
            f"  record.name = rt->read(rt->context, entry_esp + UINT32_C(8), 4U, &fault);",
            "  record.first_bits = rt->read(rt->context, entry_esp + UINT32_C(12), 4U, &fault);",
            "  record.first_bits |= (uint64_t)rt->read(rt->context, entry_esp + UINT32_C(16), 4U, &fault) << 32;",
            "  record.second_bits = rt->read(rt->context, entry_esp + UINT32_C(20), 4U, &fault);",
            "  record.second_bits |= (uint64_t)rt->read(rt->context, entry_esp + UINT32_C(24), 4U, &fault) << 32;",
            "  record.result_bits = rt->read(rt->context, entry_esp + UINT32_C(28), 4U, &fault);",
            "  record.result_bits |= (uint64_t)rt->read(rt->context, entry_esp + UINT32_C(32), 4U, &fault) << 32;",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  if (!x87_activation_guard(state, &record))",
            "    return (stage_b_step_result){ STAGE_B_UNIMPLEMENTED, state->original_rva, 0U };",
            "  state->esp = frame_esp;",
            f"  state->original_rva = UINT32_C(0x{entry_rva:08x}); state->eax = target;",
            "  context = (callback_context){ rt, state, STAGE_B_CALL_OK, frame_esp };",
            "  callback = (optional_fp64_record_callback){ &context, target, invoke_callback };",
            "  (void)dispatch_optional_fp64_record(&callback, record);",
            "  if (context.status != STAGE_B_CALL_OK)",
            "    return (stage_b_step_result){ context.status == STAGE_B_CALL_MEMORY_FAULT ? STAGE_B_MEMORY_FAULT : STAGE_B_EXTERNAL_FAULT, state->original_rva, 0U };",
            f"  state->esp += UINT32_C({frame_bytes}); state->eax = 0U; state->edx = 0U;",
            "  logical_flags(state, 0U);",
            "  return_target = rt->read(rt->context, state->esp, 4U, &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  state->esp += UINT32_C(4);",
            *sync,
            "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };",
            "}",
            "",
        ]
        (root / str(files["portable_header"])).write_text(_HEADER, encoding="ascii")
        (root / str(files["portable_source"])).write_text(_PORTABLE, encoding="ascii")
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
            {"optional_fp64_record_callback_contract": prepared.contract}
        )
        abi = object_value(contract["abi"], "optional-callback ABI")
        files = object_value(backend_workspace.get("files"), "backend files")
        rows = []
        for index in range(10):
            esp = 0x70002000 + index * 0x100
            target = 0 if index % 2 == 0 else 0x00406000 + index * 0x20
            values = (
                0x10203040 + index,
                0x71000000 + index * 0x100,
                0x3FF0000000000000 ^ index,
                0xC004000000000000 ^ (index << 8),
                0x7FF8000000000000 | index,
            )
            memory = [
                {"address": esp, "bytes": (0x12345678 + index).to_bytes(4, "little").hex()},
                {"address": esp + 4, "bytes": values[0].to_bytes(4, "little").hex()},
                {"address": esp + 8, "bytes": values[1].to_bytes(4, "little").hex()},
                {"address": esp + 12, "bytes": values[2].to_bytes(8, "little").hex()},
                {"address": esp + 20, "bytes": values[3].to_bytes(8, "little").hex()},
                {"address": esp + 28, "bytes": values[4].to_bytes(8, "little").hex()},
                {"address": int(abi["callback_slot"]), "bytes": target.to_bytes(4, "little").hex()},
            ]
            row = {
                "id": f"case:optional-fp64-record-{index}",
                "registers": {
                    "eax": 0x11110000 + index,
                    "ebx": 0x22220000 + index,
                    "ecx": 0x33330000 + index,
                    "edx": 0x44440000 + index,
                    "esi": 0x55550000 + index,
                    "edi": 0x66660000 + index,
                    "ebp": 0x77770000 + index,
                    "esp": esp,
                },
                "flags": {
                    "cf": index & 1,
                    "zf": (index >> 1) & 1,
                    "sf": (index >> 2) & 1,
                    "of": (index >> 3) & 1,
                    "pf": (index + 1) & 1,
                    "df": index & 1,
                },
                "memory": memory,
                "external_response_seed": f"optional-fp64-record-{index}",
            }
            if target:
                row["external_responses"] = [
                    {
                        "eax": 0xABC00000 + index,
                        "registers": {
                            "esp": (esp - int(abi["stack_frame_bytes"])) & 0xFFFFFFFF
                        },
                    }
                ]
            rows.append(row)
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
        symbol = str(refinement.get("portable_symbol") or "")
        _contract(refinement)
        return f'''#include "implementation.h"
#include <stdint.h>

extern uint32_t nondet_u32(void);
extern uint64_t nondet_u64(void);
typedef struct observation {{
  uint32_t calls, target; optional_fp64_record record;
}} observation;
static void invoke(void *opaque, uint32_t target,
                   const optional_fp64_record *record) {{
  observation *seen = (observation *)opaque;
  __CPROVER_assert(seen->calls == 0U, "callback invoked at most once");
  seen->calls = 1U; seen->target = target; seen->record = *record;
}}
int main(void) {{
  observation seen = {{0}}; optional_fp64_record record;
  optional_fp64_record_callback callback;
  record.code = nondet_u32(); record.name = nondet_u32();
  record.first_bits = nondet_u64(); record.second_bits = nondet_u64();
  record.result_bits = nondet_u64();
  callback = (optional_fp64_record_callback){{&seen, nondet_u32(), invoke}};
  uint32_t result = {symbol}(&callback, record);
  __CPROVER_assert(result == 0U, "dispatcher always returns zero");
  __CPROVER_assert(seen.calls == (callback.target != 0U), "callback is optional by target");
  if (callback.target != 0U) {{
    __CPROVER_assert(seen.target == callback.target, "callback target preserved");
    __CPROVER_assert(seen.record.code == record.code && seen.record.name == record.name,
                     "scalar record fields preserved");
    __CPROVER_assert(seen.record.first_bits == record.first_bits &&
                     seen.record.second_bits == record.second_bits &&
                     seen.record.result_bits == record.result_bits,
                     "FP64 record bits preserved");
  }}
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {
            "complete_for_all_safe_x87_record_bits_and_callback_targets": True,
            "loops": 0,
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
            and activation_domain.get("requires_masked_x87_exceptions") is True
            and activation_domain.get("requires_no_pending_x87_exception") is True
            and activation_domain.get("requires_three_free_x87_slots") is True
            and activation_domain.get("rejects_signaling_nan_inputs") is True
            and evidence_scope.get(
                "complete_for_all_safe_x87_record_bits_and_callback_targets"
            )
            is True
        )


PROFILE = OptionalFp64RecordCallbackProfile()
