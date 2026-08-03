"""Lift an opaque value, stream callback, and static label construction prefix."""

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
from spaghetti_extractor.stage_binary import StageAInputError, _parse_stage_a_pe
from spaghetti_extractor.util import sha256_file, write_json


_FORMAT = "stage-b-opaque-value-label-prefix-contract-v1"


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    return sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()


def _rva(unit: Mapping[str, Any]) -> int:
    return int(object_value(unit.get("source"), "unit source")["original"]["rva_start"])


def _operand(value: Any) -> tuple[Any, ...]:
    operand = object_value(value, "label-prefix operand")
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
    raise StageAInputError(f"unsupported label-prefix operand kind: {kind!r}")


def _shape(unit: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        (
            str(instruction.get("mnemonic")),
            tuple(
                _operand(value)
                for value in array_value(
                    instruction.get("operands"), "label-prefix instruction operands"
                )
            ),
        )
        for instruction in array_value(unit.get("instructions"), "label-prefix instructions")
    )


def _r(name: str) -> tuple[Any, ...]:
    return ("r", name, 32)


def _i(value: int) -> tuple[Any, ...]:
    return ("i", value, 32)


def _m(base: str | None, displacement: int) -> tuple[Any, ...]:
    return ("m", base, None, 1, displacement, 32)


def _event(unit: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    semantics = object_value(unit.get("semantics"), "label-prefix semantics")
    events = array_value(semantics.get("external_events"), "label-prefix events")
    instructions = array_value(unit.get("instructions"), "label-prefix instructions")
    outcome = object_value(semantics.get("outcome"), "label-prefix outcome")
    if (
        len(events) != 1
        or not instructions
        or instructions[-1].get("mnemonic") != "call"
    ):
        raise StageAInputError("label-prefix service unit is not one exact call")
    event = object_value(events[0], "label-prefix event")
    if (
        event.get("kind") != kind
        or event.get("return_rva") != outcome.get("target_rva")
    ):
        raise StageAInputError("label-prefix event identity or continuation is malformed")
    return event


def _static_c_string(context: ComponentProfileContext, address: int) -> tuple[bytes, str]:
    if context.static_image is None:
        raise StageAInputError("opaque value label prefix requires the exact static image")
    binary = _parse_stage_a_pe(context.static_image)
    rva = address - binary.image_base
    if rva < 0:
        raise StageAInputError("label-prefix string address precedes the image base")
    raw = bytes(binary.pe.get_data(rva, 256))
    terminator = raw.find(b"\0")
    if terminator < 0:
        raise StageAInputError("label-prefix string is not NUL terminated within 256 bytes")
    value = raw[:terminator]
    if not value or any(byte < 0x20 or byte > 0x7E for byte in value):
        raise StageAInputError("label-prefix string is not nonempty printable ASCII")
    return value, sha256_file(context.static_image)


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("opaque value label prefix has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("label-prefix units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 7:
        raise StageAInputError("opaque value label prefix requires seven machine units")
    shapes = [_shape(unit) for unit in ordered]

    if (
        len(shapes[0]) != 4
        or shapes[0][:3]
        != (
            ("push", (_r("edi"),)),
            ("push", (_r("esi"),)),
            ("push", (_r("ebx"),)),
        )
        or shapes[0][3][0] not in {"add", "sub"}
        or shapes[0][3][1][0] != _r("esp")
        or shapes[0][3][1][1][0] != "i"
    ):
        raise StageAInputError("label-prefix entry frame is malformed")
    frame_immediate = int(shapes[0][3][1][1][1])
    local_frame_bytes = (
        -frame_immediate if shapes[0][3][0] == "add" else frame_immediate
    )
    if local_frame_bytes < 64 or local_frame_bytes % 4:
        raise StageAInputError("label-prefix local frame is invalid")
    frame_delta = local_frame_bytes + 12
    value_entry_offset = frame_delta + 8
    context_entry_offset = frame_delta + 4

    callback_load = shapes[1][0] if shapes[1] else ()
    if (
        len(callback_load) != 2
        or callback_load[0] != "mov"
        or callback_load[1][0] != _r("esi")
        or callback_load[1][1][:4] != ("m", None, None, 1)
        or callback_load[1][1][5] != 32
    ):
        raise StageAInputError("label-prefix callback is not one absolute slot")
    callback_slot = int(callback_load[1][1][4])

    if shapes[1] != (
        ("mov", (_r("esi"), _m(None, callback_slot))),
        ("mov", (_r("eax"), _m("esp", value_entry_offset))),
        ("mov", (_m("esp", 48), _r("eax"))),
        ("mov", (_r("eax"), _m("esp", value_entry_offset + 4))),
    ) or shapes[2] != (
        ("mov", (_m("esp", 52), _r("eax"))),
        ("mov", (_r("eax"), _m("esp", value_entry_offset + 8))),
        ("mov", (_m("esp", 56), _r("eax"))),
        ("mov", (_r("eax"), _m("esp", value_entry_offset + 12))),
    ):
        raise StageAInputError("label-prefix opaque-value copy is malformed")

    if (
        len(shapes[3]) != 4
        or shapes[3][:3]
        != (
            ("mov", (_m("esp", 60), _r("eax"))),
            ("mov", (_r("eax"), _m("esp", context_entry_offset))),
            ("mov", (_r("ebx"), _m("eax", 0))),
        )
        or shapes[3][3][0] != "mov"
        or shapes[3][3][1][0] != _m("esp", 0)
        or shapes[3][3][1][1][0] != "i"
    ):
        raise StageAInputError("label-prefix stream setup is malformed")
    mode = int(shapes[3][3][1][1][1]) & 0xFFFFFFFF
    if shapes[4] != (("call", (_r("esi"),)),):
        raise StageAInputError("label-prefix callback call is malformed")

    if (
        len(shapes[5]) != 4
        or shapes[5][0][0] != "mov"
        or shapes[5][0][1][0] != _m("esp", 4)
        or shapes[5][0][1][1][0] != "i"
        or shapes[5][1] != ("mov", (_r("edi"), _r("eax")))
        or shapes[5][2][0] != "lea"
        or shapes[5][2][1][0] != _r("eax")
        or shapes[5][2][1][1][:4] != ("m", "esp", None, 1)
        or shapes[5][3][0] != "and"
        or shapes[5][3][1][0] != _r("ebx")
        or shapes[5][3][1][1][0] != "i"
    ):
        raise StageAInputError("label-prefix static-label setup is malformed")
    label_address = int(shapes[5][0][1][1][1]) & 0xFFFFFFFF
    hidden_result_offset = int(shapes[5][2][1][1][4])
    context_mask = int(shapes[5][3][1][1][1]) & 0xFFFFFFFF
    if hidden_result_offset < 16 or hidden_result_offset + 16 > local_frame_bytes:
        raise StageAInputError("label-prefix hidden result is outside the local frame")
    if shapes[6][0] != ("mov", (_m("esp", 0), _r("eax"))) or shapes[6][1][0] != "call":
        raise StageAInputError("label-prefix string call frame is malformed")

    starts = [_rva(unit) for unit in ordered]
    for index, unit in enumerate(ordered):
        control = object_value(unit.get("control"), "label-prefix control")
        target = starts[index + 1] if index + 1 < len(starts) else int(
            object_value(unit["semantics"]["outcome"], "label-prefix outcome")[
                "target_rva"
            ]
        )
        if control.get("kind") != "fallthrough" or control.get("direct_targets") != [target]:
            raise StageAInputError(f"label-prefix CFG mismatch at RVA 0x{starts[index]:x}")

    callback = _event(ordered[4], "indirect_call")
    if callback.get("target") != {"op": "reg", "name": "esi", "width": 32}:
        raise StageAInputError("label-prefix callback target is not the loaded register")
    label_event = _event(ordered[6], "external_call")
    stack_inputs = array_value(label_event.get("stack_inputs"), "label service stack inputs")
    if (
        not isinstance(label_event.get("dll"), str)
        or not label_event.get("dll")
        or not isinstance(label_event.get("symbol"), str)
        or not label_event.get("symbol")
        or label_event.get("ordinal") is not None
        or label_event.get("arguments") != []
        or [item.get("offset") for item in stack_inputs] != [0]
        or any(item.get("width") != 4 for item in stack_inputs)
    ):
        raise StageAInputError("label-prefix imported label service is malformed")

    label, static_image_sha256 = _static_c_string(context, label_address)
    bindings = [
        {
            "unit_id": str(unit["id"]),
            "rva_start": _rva(unit),
            "rva_end": int(unit["source"]["original"]["rva_end"]),
            "instruction_bytes_sha256": str(unit["source"]["instruction_bytes_sha256"]),
            "semantic_transfer_sha256": str(
                unit["source"]["semantic_export"]["semantic_transfer_sha256"]
            ),
        }
        for unit in ordered
    ]
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "opaque_value_label_prefix_v1",
        "component": {
            "id": str(context.component["id"]),
            "sha256": str(context.component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "static_image_sha256": static_image_sha256,
            "units": bindings,
        },
        "domain": {
            "kind": "total",
            "requires": (
                "readable entry value and stream context, writable frame, exact static "
                "callback and label locations, and declared services"
            ),
        },
        "abi": {
            "saved_registers": ["edi", "esi", "ebx"],
            "local_frame_bytes": local_frame_bytes,
            "entry_to_frame_delta": frame_delta,
            "context_entry_stack_offset": 4,
            "value_entry_stack_offset": 8,
            "value_words": 4,
            "local_value_offset": 48,
            "hidden_label_result_offset": hidden_result_offset,
            "mode": mode,
            "context_mask": context_mask,
        },
        "static": {
            "callback_slot": callback_slot,
            "label_address": label_address,
            "label_bytes": label.hex(),
        },
        "events": [
            {
                "kind": "indirect_call",
                "call_rva": int(ordered[4]["instructions"][-1]["rva_start"]),
                "return_rva": int(callback["return_rva"]),
                "observed_stack_inputs": [{"offset": 0, "width": 4}],
            },
            {
                "kind": "external_call",
                "dll": str(label_event["dll"]),
                "symbol": str(label_event["symbol"]),
                "call_rva": int(ordered[6]["instructions"][-1]["rva_start"]),
                "return_rva": int(label_event["return_rva"]),
                "observed_stack_inputs": [
                    {"offset": 0, "width": 4},
                    {"offset": 4, "width": 4},
                ],
            },
        ],
        "control": {"entry_rva": starts[0], "continuation_rva": int(label_event["return_rva"])},
        "behavior": {
            "event_order": ["indirect_call", str(label_event["symbol"])],
            "value": "copied unchanged into the continuation frame",
            "stream_context": "masked by the exact immediate",
            "label": "constructed from the exact static NUL-terminated bytes",
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("opaque_value_label_prefix_contract"),
        "opaque value label-prefix contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("opaque value label-prefix contract is stale")
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
        raise StageAInputError("label-prefix adapter does not have one entry")
    return files, adapter, matches[0]


def _c_string(value: bytes) -> str:
    return "".join(f'"\\x{byte:02x}"' for byte in value)


class OpaqueValueLabelPrefixProfile:
    name = "opaque_value_label_prefix_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        contract = _contract(interface_refinement)
        abi = object_value(contract["abi"], "label-prefix ABI")
        static = object_value(contract["static"], "label-prefix static data")
        frame_delta = int(abi["entry_to_frame_delta"])
        return (
            {
                "semantic_expression": {
                    "op": "sub32",
                    "args": [
                        {"op": "reg", "name": "esp", "width": 32},
                        {"op": "const", "value": frame_delta, "width": 32},
                    ],
                },
                "width": frame_delta + 24,
                "access": "read_write",
            },
            {
                "semantic_expression": {
                    "op": "const",
                    "value": int(static["callback_slot"]),
                    "width": 32,
                },
                "width": 4,
                "access": "read",
            },
        )

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="prepare_labeled_opaque_value_prefix",
            contract_field="opaque_value_label_prefix_contract",
            contract_filename="opaque-value-label-prefix-contract.json",
            contract_hash_binding="opaque_value_label_prefix_contract_sha256",
            contract=contract,
            activation_domain={"kind": "total"},
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
        abi = object_value(contract["abi"], "label-prefix ABI")
        static = object_value(contract["static"], "label-prefix static data")
        events = array_value(contract["events"], "label-prefix events")
        control = object_value(contract["control"], "label-prefix control")
        callback, label_event = events
        label = bytes.fromhex(str(static["label_bytes"]))
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = f'''#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

#define OPAQUE_LABEL_MODE UINT32_C({int(abi["mode"])})
#define OPAQUE_LABEL_CONTEXT_MASK UINT32_C(0x{int(abi["context_mask"]):08x})
#define OPAQUE_LABEL_TEXT {_c_string(label)}

typedef struct opaque_value4 {{ uint32_t words[4]; }} opaque_value4;
typedef struct labeled_opaque_value_prefix {{
  opaque_value4 value;
  opaque_value4 label;
  uint32_t stream;
  uint32_t stream_context;
}} labeled_opaque_value_prefix;
typedef struct opaque_label_services {{
  void *context;
  uint32_t (*open_stream)(void *context, uint32_t mode);
  opaque_value4 (*make_label)(void *context, const char *text);
}} opaque_label_services;

labeled_opaque_value_prefix prepare_labeled_opaque_value_prefix(
    opaque_label_services *services, uint32_t stream_context,
    opaque_value4 value);

#endif
'''
        portable = '''#include "implementation.h"

labeled_opaque_value_prefix prepare_labeled_opaque_value_prefix(
    opaque_label_services *services, uint32_t stream_context,
    opaque_value4 value) {
  labeled_opaque_value_prefix result;
  result.value = value;
  result.stream = services->open_stream(services->context, OPAQUE_LABEL_MODE);
  result.stream_context = stream_context & OPAQUE_LABEL_CONTEXT_MASK;
  result.label = services->make_label(services->context, OPAQUE_LABEL_TEXT);
  return result;
}
'''
        frame_delta = int(abi["entry_to_frame_delta"])
        local_frame = int(abi["local_frame_bytes"])
        hidden_offset = int(abi["hidden_label_result_offset"])
        context_sync = [
            line.replace("state->", "context->state->")
            for line in machine_eflags_sync_lines("  ")
        ]
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            "typedef struct label_context {",
            "  stage_b_runtime *runtime; stage_b_machine_state *state;",
            "  uint32_t frame_esp; stage_b_call_status status;",
            "} label_context;",
            "",
            "static uint32_t byte_parity(uint32_t value) {",
            "  value ^= value >> 4; value &= UINT32_C(0x0f);",
            "  return (UINT32_C(0x9669) >> value) & UINT32_C(1);",
            "}",
            "",
            "static void addition_flags(stage_b_machine_state *state, uint32_t left, uint32_t right, uint32_t result) {",
            "  state->cf = result < left;",
            "  state->of = ((~(left ^ right) & (left ^ result)) >> 31) & UINT32_C(1);",
            "  state->pf = byte_parity(result); state->sf = result >> 31; state->zf = result == 0U;",
            "}",
            "",
            "static void logical_and_flags(stage_b_machine_state *state, uint32_t result) {",
            "  state->cf = 0U; state->of = 0U; state->pf = byte_parity(result);",
            "  state->sf = result >> 31; state->zf = result == 0U;",
            "}",
            "",
            "static uint32_t open_stream(void *opaque, uint32_t mode) {",
            "  label_context *context = (label_context *)opaque; stage_b_machine_state output;",
            "  uint32_t target, fault = 0U; stage_b_stack_input stack_inputs[1]; stage_b_call_event event = {0};",
            "  if (context->status != STAGE_B_CALL_OK) return 0U;",
            f"  target = context->runtime->read(context->runtime->context, UINT32_C(0x{int(static['callback_slot']):08x}), 4U, &fault);",
            "  context->runtime->write(context->runtime->context, context->frame_esp, 4U, mode, &fault);",
            "  if (fault) { context->status = STAGE_B_CALL_MEMORY_FAULT; return 0U; }",
            "  context->state->esi = target;",
            "  stack_inputs[0] = (stage_b_stack_input){ 0U, 4U, mode };",
            "  event.kind = STAGE_B_CALL_INDIRECT; event.target_rva = target;",
            f"  event.instruction_rva = UINT32_C(0x{int(callback['call_rva']):08x});",
            f"  event.return_rva = UINT32_C(0x{int(callback['return_rva']):08x});",
            "  event.stack_inputs = stack_inputs; event.stack_input_count = 1U;",
            *context_sync,
            "  output = *context->state;",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status == STAGE_B_CALL_OK) {",
            "    *context->state = output;",
            "    context->state->edi = output.eax;",
            "  }",
            "  return output.eax;",
            "}",
            "",
            "static opaque_value4 make_label(void *opaque, const char *text) {",
            "  label_context *context = (label_context *)opaque; stage_b_machine_state output;",
            "  opaque_value4 result = {{0U, 0U, 0U, 0U}}; uint32_t fault = 0U, index;",
            "  stage_b_stack_input stack_inputs[2]; stage_b_call_event event = {0};",
            "  if (context->status != STAGE_B_CALL_OK) return result;",
            f"  if (text == 0 || text[0] != (char)0x{label[0]:02x}) {{ context->status = STAGE_B_CALL_UNIMPLEMENTED; return result; }}",
            f"  context->runtime->write(context->runtime->context, context->frame_esp + 4U, 4U, UINT32_C(0x{int(static['label_address']):08x}), &fault);",
            f"  context->state->eax = context->frame_esp + UINT32_C({hidden_offset});",
            f"  context->state->ebx &= UINT32_C(0x{int(abi['context_mask']):08x});",
            "  logical_and_flags(context->state, context->state->ebx);",
            "  context->runtime->write(context->runtime->context, context->frame_esp, 4U, context->state->eax, &fault);",
            "  if (fault) { context->status = STAGE_B_CALL_MEMORY_FAULT; return result; }",
            "  stack_inputs[0] = (stage_b_stack_input){ 0U, 4U, context->state->eax };",
            f"  stack_inputs[1] = (stage_b_stack_input){{ 4U, 4U, UINT32_C(0x{int(static['label_address']):08x}) }};",
            "  event.kind = STAGE_B_CALL_EXTERNAL_IMPORT;",
            f"  event.instruction_rva = UINT32_C(0x{int(label_event['call_rva']):08x});",
            f"  event.return_rva = UINT32_C(0x{int(label_event['return_rva']):08x});",
            f"  event.dll = \"{label_event['dll']}\"; event.symbol = \"{label_event['symbol']}\";",
            "  event.stack_inputs = stack_inputs; event.stack_input_count = 2U;",
            *context_sync,
            "  output = *context->state;",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status != STAGE_B_CALL_OK) return result;",
            "  *context->state = output;",
            f"  for (index = 0U; index < 4U; ++index) result.words[index] = context->runtime->read(context->runtime->context, context->frame_esp + UINT32_C({hidden_offset}) + 4U * index, 4U, &fault);",
            "  if (fault) context->status = STAGE_B_CALL_MEMORY_FAULT;",
            "  return result;",
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  uint32_t entry_esp, pushed_esp, frame_esp, context_pointer, stream_context, fault = 0U, index;",
            "  opaque_value4 value; labeled_opaque_value_prefix result; label_context context; opaque_label_services services;",
            "  if (rt == 0 || rt->read == 0 || rt->write == 0)",
            "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  entry_esp = state->esp;",
            "  rt->write(rt->context, entry_esp - 4U, 4U, state->edi, &fault);",
            "  rt->write(rt->context, entry_esp - 8U, 4U, state->esi, &fault);",
            "  rt->write(rt->context, entry_esp - 12U, 4U, state->ebx, &fault);",
            "  pushed_esp = entry_esp - 12U;",
            f"  frame_esp = pushed_esp + UINT32_C(0x{((-local_frame) & 0xFFFFFFFF):08x});",
            f"  addition_flags(state, pushed_esp, UINT32_C(0x{((-local_frame) & 0xFFFFFFFF):08x}), frame_esp);",
            "  state->esp = frame_esp;",
            "  context_pointer = rt->read(rt->context, entry_esp + 4U, 4U, &fault);",
            "  stream_context = rt->read(rt->context, context_pointer, 4U, &fault);",
            "  for (index = 0U; index < 4U; ++index) {",
            "    value.words[index] = rt->read(rt->context, entry_esp + 8U + 4U * index, 4U, &fault);",
            "    rt->write(rt->context, frame_esp + 48U + 4U * index, 4U, value.words[index], &fault);",
            "  }",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  state->eax = context_pointer; state->ebx = stream_context;",
            f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
            "  context = (label_context){ rt, state, frame_esp, STAGE_B_CALL_OK };",
            "  services = (opaque_label_services){ &context, open_stream, make_label };",
            "  result = prepare_labeled_opaque_value_prefix(&services, stream_context, value);",
            "  (void)result;",
            "  if (context.status != STAGE_B_CALL_OK)",
            "    return (stage_b_step_result){ context.status == STAGE_B_CALL_MEMORY_FAULT ? STAGE_B_MEMORY_FAULT : STAGE_B_EXTERNAL_FAULT, state->original_rva, 0U };",
            f"  return (stage_b_step_result){{ STAGE_B_FALLTHROUGH, UINT32_C(0x{int(control['continuation_rva']):08x}), 0U }};",
            "}",
            "",
        ]
        if frame_delta != local_frame + 12:
            raise StageAInputError("label-prefix frame contract is inconsistent")
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
        contract = _contract({"opaque_value_label_prefix_contract": prepared.contract})
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        abi = object_value(contract["abi"], "label-prefix ABI")
        static = object_value(contract["static"], "label-prefix static data")
        events = array_value(contract["events"], "label-prefix events")
        frame_delta = int(abi["entry_to_frame_delta"])
        hidden_offset = int(abi["hidden_label_result_offset"])
        esp = 0x70001000
        rows = []
        for index in range(10):
            context_pointer = 0x71000000 + index * 0x100
            stream_context = (0xA5A5A5A5 + index * 3) & 0xFFFFFFFF
            value_words = tuple(
                (0x10203040 * (word + 1) + index * 0x01010101) & 0xFFFFFFFF
                for word in range(4)
            )
            label_words = tuple(
                (value ^ (0x5A5A5A5A + index)) & 0xFFFFFFFF
                for value in value_words
            )
            frame = bytearray(frame_delta + 24)
            frame[frame_delta + 4 : frame_delta + 8] = context_pointer.to_bytes(4, "little")
            frame[frame_delta + 8 : frame_delta + 24] = b"".join(
                word.to_bytes(4, "little") for word in value_words
            )
            target = 0x72000000 + index * 0x100
            stream = 0x73000000 + index * 0x100
            rows.append(
                {
                    "id": f"case:opaque-value-label-prefix-{index}",
                    "registers": {
                        "eax": 0x01020304 + index,
                        "ebx": 0x11121314 + index,
                        "ecx": 0x21222324 + index,
                        "edx": 0x31323334 + index,
                        "esi": 0x41424344 + index,
                        "edi": 0x51525354 + index,
                        "ebp": 0x70004000,
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
                    "memory": [
                        {"address": esp - frame_delta, "bytes": bytes(frame).hex()},
                        {"address": context_pointer, "bytes": stream_context.to_bytes(4, "little").hex()},
                        {"address": int(static["callback_slot"]), "bytes": target.to_bytes(4, "little").hex()},
                    ],
                    "external_responses": [
                        {"eax": stream},
                        {
                            "eax": 0x81000000 + index,
                            "memory_writes": [
                                {
                                    "stack_pointer_offset": 0,
                                    "offset": 0,
                                    "bytes": b"".join(
                                        word.to_bytes(4, "little") for word in label_words
                                    ).hex(),
                                }
                            ],
                        },
                    ],
                    "external_response_seed": f"opaque-value-label-prefix-{index}",
                }
            )
        payload = {
            "format": "stage-b-reconstruction-cases-v1",
            "cluster_id": cluster["id"],
            "entry_unit_id": cluster["entry_unit_id"],
            "entry_rva": cluster["entry_rva"],
            "call_stack_observations": [
                {
                    "event_index": index,
                    "slots": event["observed_stack_inputs"],
                }
                for index, event in enumerate(events)
            ],
            "cases": rows,
        }
        payload["cases_sha256"] = _canonical_sha256(payload)
        write_json(root / str(files["cases"]), payload)

    def render_cbmc_harness(self, refinement: Mapping[str, Any]) -> str:
        symbol = str(refinement.get("portable_symbol") or "")
        contract = _contract(refinement)
        label = bytes.fromhex(str(contract["static"]["label_bytes"]))
        label_assertions = "\n".join(
            f'  __CPROVER_assert((unsigned char)text[{index}] == UINT8_C(0x{byte:02x}), "label byte {index}");'
            for index, byte in enumerate(label)
        )
        return f'''#include "implementation.h"
#include <stdint.h>

extern uint32_t nondet_u32(void);
typedef struct model {{
  uint32_t step, mode, stream, observed_context;
  opaque_value4 label, observed_value;
}} model;
static uint32_t open_stream(void *opaque, uint32_t mode) {{
  model *m = (model *)opaque;
  __CPROVER_assert(m->step == 0U, "stream opens first");
  m->step = 1U; m->mode = mode; return m->stream;
}}
static opaque_value4 make_label(void *opaque, const char *text) {{
  model *m = (model *)opaque;
  __CPROVER_assert(m->step == 1U, "label is second");
{label_assertions}
  __CPROVER_assert(text[{len(label)}] == '\\0', "label terminator");
  m->step = 2U; return m->label;
}}
int main(void) {{
  model m; opaque_label_services services; opaque_value4 value;
  labeled_opaque_value_prefix result; uint32_t context = nondet_u32();
  m.step = 0U; m.mode = 0U; m.stream = nondet_u32();
  value.words[0] = nondet_u32(); value.words[1] = nondet_u32();
  value.words[2] = nondet_u32(); value.words[3] = nondet_u32();
  m.label.words[0] = nondet_u32(); m.label.words[1] = nondet_u32();
  m.label.words[2] = nondet_u32(); m.label.words[3] = nondet_u32();
  services = (opaque_label_services){{ &m, open_stream, make_label }};
  result = {symbol}(&services, context, value);
  __CPROVER_assert(m.step == 2U, "complete service protocol");
  __CPROVER_assert(m.mode == OPAQUE_LABEL_MODE, "stream mode");
  __CPROVER_assert(result.stream == m.stream, "stream result");
  __CPROVER_assert(result.stream_context == (context & OPAQUE_LABEL_CONTEXT_MASK), "masked context");
  __CPROVER_assert(result.value.words[0] == value.words[0] && result.value.words[1] == value.words[1] && result.value.words[2] == value.words[2] && result.value.words[3] == value.words[3], "opaque value preserved");
  __CPROVER_assert(result.label.words[0] == m.label.words[0] && result.label.words[1] == m.label.words[1] && result.label.words[2] == m.label.words[2] && result.label.words[3] == m.label.words[3], "label result preserved");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {
            "complete_for_all_opaque_values_streams_contexts_and_label_results": True,
            "loops": 0,
        }

    def activation_scope_matches(
        self,
        *,
        activation_domain: Mapping[str, Any],
        evidence_scope: Mapping[str, Any],
    ) -> bool:
        return (
            activation_domain.get("kind") == "total"
            and evidence_scope.get(
                "complete_for_all_opaque_values_streams_contexts_and_label_results"
            )
            is True
        )


PROFILE = OpaqueValueLabelPrefixProfile()
