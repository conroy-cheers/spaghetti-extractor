"""Lift an opaque-value copy and output pipeline into portable C."""

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


_FORMAT = "stage-b-opaque-output-pipeline-contract-v1"


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
    raise StageAInputError(f"unsupported output-pipeline operand: {kind!r}")


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


def _event(
    unit: Mapping[str, Any],
    *,
    kind: str,
    offsets: Sequence[int],
) -> Mapping[str, Any]:
    semantics = object_value(unit.get("semantics"), "output-pipeline semantics")
    events = array_value(semantics.get("external_events"), "output-pipeline events")
    if len(events) != 1:
        raise StageAInputError("output-pipeline call must emit one external event")
    event = object_value(events[0], "output-pipeline event")
    stack_inputs = array_value(event.get("stack_inputs"), "output-pipeline stack inputs")
    instructions = array_value(unit.get("instructions"), "output-pipeline instructions")
    outcome = object_value(semantics.get("outcome"), "output-pipeline outcome")
    if (
        event.get("kind") != kind
        or [value.get("offset") for value in stack_inputs] != list(offsets)
        or any(value.get("width") != 4 for value in stack_inputs)
        or event.get("return_rva") != outcome.get("target_rva")
        or not instructions
        or instructions[-1].get("mnemonic") != "call"
    ):
        raise StageAInputError("output-pipeline event is outside this profile")
    if kind == "external_call":
        if (
            not isinstance(event.get("dll"), str)
            or not event.get("dll")
            or not isinstance(event.get("symbol"), str)
            or not event.get("symbol")
            or event.get("ordinal") is not None
            or event.get("arguments") != []
        ):
            raise StageAInputError("output-pipeline import identity is incomplete")
    return event


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("opaque output pipeline has no call dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("output-pipeline units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 8:
        raise StageAInputError("opaque output pipeline requires eight machine units")

    shapes = [_shape(unit) for unit in ordered]
    callback_operand = (
        shapes[0][1][1][0]
        if len(shapes[0]) == 2
        and shapes[0][1][0] == "call"
        and len(shapes[0][1][1]) == 1
        else ()
    )
    if (
        len(callback_operand) != 6
        or callback_operand[:4] != ("m", None, None, 1)
        or callback_operand[5] != 32
    ):
        raise StageAInputError("output callback is not one absolute dword slot")
    callback_slot = int(callback_operand[4])
    source_offset = int(shapes[1][0][1][1][4]) if len(shapes[1]) == 4 else -1
    result_offset = int(shapes[1][2][1][1][4]) if len(shapes[1]) == 4 else -1
    mode = int(shapes[0][0][1][1][1]) if len(shapes[0]) == 2 else -1
    dump_flags = int(shapes[4][2][1][1][1]) if len(shapes[4]) == 4 else -1
    if (
        source_offset < 24
        or result_offset < 24
        or source_offset % 4
        or result_offset % 4
        or abs(source_offset - result_offset) < 16
    ):
        raise StageAInputError("output-pipeline value slots overlap or are unaligned")
    if (
        len(shapes[0]) != 2
        or shapes[0][0] != ("mov", (_m(0), _i(mode)))
        or shapes[1]
        != (
            ("mov", (_r("edx"), _m(source_offset))),
            ("mov", (_r("esi"), _r("eax"))),
            ("lea", (_r("eax"), _m(result_offset))),
            ("mov", (_m(4), _r("edx"))),
        )
        or shapes[2]
        != (
            ("mov", (_r("edx"), _m(source_offset + 4))),
            ("mov", (_m(0), _r("eax"))),
            ("mov", (_m(8), _r("edx"))),
            ("mov", (_r("edx"), _m(source_offset + 8))),
        )
        or len(shapes[3]) != 4
        or shapes[3][:3]
        != (
            ("mov", (_m(12), _r("edx"))),
            ("mov", (_r("edx"), _m(source_offset + 12))),
            ("mov", (_m(16), _r("edx"))),
        )
        or shapes[3][3][0] != "call"
        or shapes[4]
        != (
            ("mov", (_r("eax"), _m(result_offset))),
            ("mov", (_m(16), _r("esi"))),
            ("mov", (_m(20), _i(dump_flags))),
            ("mov", (_m(0), _r("eax"))),
        )
        or shapes[5]
        != (
            ("mov", (_r("eax"), _m(result_offset + 4))),
            ("mov", (_m(4), _r("eax"))),
            ("mov", (_r("eax"), _m(result_offset + 8))),
            ("mov", (_m(8), _r("eax"))),
        )
        or len(shapes[6]) != 3
        or shapes[6][:2]
        != (
            ("mov", (_r("eax"), _m(result_offset + 12))),
            ("mov", (_m(12), _r("eax"))),
        )
        or shapes[6][2][0] != "call"
        or len(shapes[7]) != 1
        or shapes[7][0][0] != "jmp"
    ):
        raise StageAInputError("opaque output-pipeline instruction shape is unsupported")

    starts = [_rva(unit) for unit in ordered]
    for index, unit in enumerate(ordered[:-1]):
        control = object_value(unit.get("control"), "output-pipeline control")
        if control.get("kind") != "fallthrough" or control.get("direct_targets") != [
            starts[index + 1]
        ]:
            raise StageAInputError(
                f"output-pipeline CFG mismatch at RVA 0x{starts[index]:x}"
            )
    final_control = object_value(ordered[-1].get("control"), "pipeline continuation")
    final_targets = array_value(final_control.get("direct_targets"), "pipeline targets")
    if final_control.get("kind") != "jump" or len(final_targets) != 1:
        raise StageAInputError("output-pipeline continuation is not one direct jump")

    callback = _event(ordered[0], kind="indirect_call", offsets=(0,))
    target = object_value(callback.get("target"), "output callback target")
    address = object_value(target.get("address"), "output callback target address")
    if (
        target.get("op") != "load"
        or target.get("width") != 4
        or address
        != {"op": "const", "value": callback_slot, "width": 32}
    ):
        raise StageAInputError("output callback target is not the exact static slot")
    copy_event = _event(ordered[3], kind="external_call", offsets=(12, 16))
    dump_event = _event(ordered[6], kind="external_call", offsets=(12,))
    if (
        copy_event.get("dll") != dump_event.get("dll")
        or copy_event.get("symbol") == dump_event.get("symbol")
    ):
        raise StageAInputError("output-pipeline import protocol is ambiguous")

    bindings = [
        {
            "unit_id": str(unit["id"]),
            "rva_start": _rva(unit),
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
    events = (
        {
            "kind": "indirect_call",
            "call_rva": int(ordered[0]["instructions"][-1]["rva_start"]),
            "return_rva": int(callback["return_rva"]),
            "target_slot": callback_slot,
            "reported_stack_inputs": [0],
        },
        {
            "kind": "external_call",
            "dll": str(copy_event["dll"]),
            "symbol": str(copy_event["symbol"]),
            "call_rva": int(ordered[3]["instructions"][-1]["rva_start"]),
            "return_rva": int(copy_event["return_rva"]),
            "reported_stack_inputs": [12, 16],
        },
        {
            "kind": "external_call",
            "dll": str(dump_event["dll"]),
            "symbol": str(dump_event["symbol"]),
            "call_rva": int(ordered[6]["instructions"][-1]["rva_start"]),
            "return_rva": int(dump_event["return_rva"]),
            "reported_stack_inputs": [12],
        },
    )
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "opaque_output_pipeline_v1",
        "component": {
            "id": str(context.component["id"]),
            "sha256": str(context.component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "units": bindings,
        },
        "domain": {
            "kind": "total",
            "requires": (
                "readable static callback slot, readable source value, writable call "
                "frame, writable hidden result, and declared services"
            ),
        },
        "abi": {
            "source_value_stack_offset": source_offset,
            "hidden_copy_result_stack_offset": result_offset,
            "value_words": 4,
            "mode": mode,
            "dump_flags": dump_flags,
        },
        "events": list(events),
        "control": {
            "entry_rva": starts[0],
            "continuation_rva": int(final_targets[0]),
        },
        "behavior": {
            "event_order": ["indirect_call", str(copy_event["symbol"]), str(dump_event["symbol"])],
            "copy_result_source": "hidden output at entry ESP plus 112",
            "continuation": "direct jump after dump",
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("opaque_output_pipeline_contract"),
        "opaque output-pipeline contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("opaque output-pipeline contract is stale")
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
        raise StageAInputError("output-pipeline adapter does not have one entry")
    return files, adapter, matches[0]


class OpaqueOutputPipelineProfile:
    name = "opaque_output_pipeline_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        contract = _contract(interface_refinement)
        callback_slot = int(contract["events"][0]["target_slot"])
        return (
            {
                "semantic_expression": {"op": "reg", "name": "esp", "width": 32},
                "width": 128,
                "access": "read_write",
            },
            {
                "semantic_expression": {
                    "op": "const",
                    "value": callback_slot,
                    "width": 32,
                },
                "width": 4,
                "access": "read",
            },
        )

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="prepare_and_dump_opaque_output",
            contract_field="opaque_output_pipeline_contract",
            contract_filename="opaque-output-pipeline-contract.json",
            contract_hash_binding="opaque_output_pipeline_contract_sha256",
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
        abi = object_value(contract["abi"], "output-pipeline ABI")
        events = array_value(contract["events"], "output-pipeline events")
        control = object_value(contract["control"], "output-pipeline control")
        callback, copy_event, dump_event = events
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

typedef struct opaque_value4 {
  uint32_t words[4];
} opaque_value4;

typedef struct opaque_copy_result {
  opaque_value4 value;
  uint32_t stream;
} opaque_copy_result;

typedef struct opaque_output_services {
  void *context;
  uint32_t (*open_stream)(void *context, uint32_t mode);
  opaque_value4 (*load_source)(void *context);
  opaque_copy_result (*copy_value)(void *context, opaque_value4 value,
                                   uint32_t stream);
  void (*dump_value)(void *context, opaque_value4 value, uint32_t stream,
                     uint32_t flags);
} opaque_output_services;

void prepare_and_dump_opaque_output(opaque_output_services *services);

#endif
"""
        portable = """#include "implementation.h"

void prepare_and_dump_opaque_output(opaque_output_services *services) {
  uint32_t stream = services->open_stream(services->context, %dU);
  opaque_value4 source = services->load_source(services->context);
  opaque_copy_result copied =
      services->copy_value(services->context, source, stream);
  services->dump_value(services->context, copied.value, copied.stream,
                       %dU);
}
""" % (int(abi["mode"]), int(abi["dump_flags"]))
        context_eflags_sync = [
            line.replace("state->", "context->state->")
            for line in machine_eflags_sync_lines("  ")
        ]
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            "typedef struct output_context {",
            "  stage_b_runtime *runtime; stage_b_machine_state *state;",
            "  uint32_t entry_esp; stage_b_call_status status;",
            "} output_context;",
            "",
            "static uint32_t open_stream(void *opaque, uint32_t mode) {",
            "  output_context *context = (output_context *)opaque;",
            "  stage_b_machine_state output = *context->state; uint32_t fault = 0U;",
            "  uint32_t target; stage_b_stack_input stack_inputs[1]; stage_b_call_event event = {0};",
            "  if (context->status != STAGE_B_CALL_OK) return 0U;",
            "  context->runtime->write(context->runtime->context, context->entry_esp, 4U, mode, &fault);",
            f"  target = context->runtime->read(context->runtime->context, UINT32_C(0x{int(callback['target_slot']):08x}), 4U, &fault);",
            "  if (fault) { context->status = STAGE_B_CALL_MEMORY_FAULT; return 0U; }",
            "  stack_inputs[0] = (stage_b_stack_input){ 0U, 4U, mode };",
            "  event.kind = STAGE_B_CALL_INDIRECT;",
            f"  event.instruction_rva = UINT32_C(0x{int(callback['call_rva']):08x});",
            "  event.target_rva = target;",
            f"  event.return_rva = UINT32_C(0x{int(callback['return_rva']):08x});",
            "  event.stack_inputs = stack_inputs; event.stack_input_count = 1U;",
            *context_eflags_sync,
            f"  context->state->original_rva = UINT32_C(0x{entry_rva:08x});",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status == STAGE_B_CALL_OK) *context->state = output;",
            "  return output.eax;",
            "}",
            "",
            "static opaque_value4 load_source(void *opaque) {",
            "  output_context *context = (output_context *)opaque; opaque_value4 value = {{0U, 0U, 0U, 0U}};",
            "  uint32_t fault = 0U, index;",
            "  if (context->status != STAGE_B_CALL_OK) return value;",
            f"  for (index = 0U; index < 4U; ++index) value.words[index] = context->runtime->read(context->runtime->context, context->entry_esp + UINT32_C({int(abi['source_value_stack_offset'])}) + 4U * index, 4U, &fault);",
            "  if (fault) context->status = STAGE_B_CALL_MEMORY_FAULT;",
            "  return value;",
            "}",
            "",
            "static opaque_copy_result copy_value(void *opaque, opaque_value4 value, uint32_t stream) {",
            "  output_context *context = (output_context *)opaque; stage_b_machine_state output;",
            "  opaque_copy_result result = { {{0U, 0U, 0U, 0U}}, stream };",
            "  uint32_t fault = 0U, index; stage_b_stack_input stack_inputs[2]; stage_b_call_event event = {0};",
            "  if (context->status != STAGE_B_CALL_OK) return result;",
            "  context->state->edx = value.words[0]; context->state->esi = stream;",
            f"  context->state->eax = context->entry_esp + UINT32_C({int(abi['hidden_copy_result_stack_offset'])});",
            "  context->runtime->write(context->runtime->context, context->entry_esp + 4U, 4U, value.words[0], &fault);",
            "  context->state->edx = value.words[1];",
            "  context->runtime->write(context->runtime->context, context->entry_esp, 4U, context->state->eax, &fault);",
            "  context->runtime->write(context->runtime->context, context->entry_esp + 8U, 4U, value.words[1], &fault);",
            "  context->state->edx = value.words[2];",
            "  context->runtime->write(context->runtime->context, context->entry_esp + 12U, 4U, value.words[2], &fault);",
            "  context->state->edx = value.words[3];",
            "  context->runtime->write(context->runtime->context, context->entry_esp + 16U, 4U, value.words[3], &fault);",
            "  if (fault) { context->status = STAGE_B_CALL_MEMORY_FAULT; return result; }",
            "  stack_inputs[0] = (stage_b_stack_input){ 12U, 4U, value.words[2] };",
            "  stack_inputs[1] = (stage_b_stack_input){ 16U, 4U, value.words[3] };",
            "  event.kind = STAGE_B_CALL_EXTERNAL_IMPORT;",
            f"  event.instruction_rva = UINT32_C(0x{int(copy_event['call_rva']):08x});",
            f"  event.return_rva = UINT32_C(0x{int(copy_event['return_rva']):08x});",
            f"  event.dll = \"{copy_event['dll']}\"; event.symbol = \"{copy_event['symbol']}\";",
            "  event.stack_inputs = stack_inputs; event.stack_input_count = 2U;",
            *context_eflags_sync,
            f"  context->state->original_rva = UINT32_C(0x{int(copy_event['call_rva']) - 12:08x});",
            "  output = *context->state;",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status != STAGE_B_CALL_OK) return result;",
            "  *context->state = output; result.stream = context->state->esi;",
            f"  for (index = 0U; index < 4U; ++index) result.value.words[index] = context->runtime->read(context->runtime->context, context->entry_esp + UINT32_C({int(abi['hidden_copy_result_stack_offset'])}) + 4U * index, 4U, &fault);",
            "  if (fault) context->status = STAGE_B_CALL_MEMORY_FAULT;",
            "  return result;",
            "}",
            "",
            "static void dump_value(void *opaque, opaque_value4 value, uint32_t stream, uint32_t flags) {",
            "  output_context *context = (output_context *)opaque; stage_b_machine_state output;",
            "  uint32_t fault = 0U; stage_b_stack_input stack_inputs[1]; stage_b_call_event event = {0};",
            "  if (context->status != STAGE_B_CALL_OK) return;",
            "  context->state->eax = value.words[0];",
            "  context->runtime->write(context->runtime->context, context->entry_esp + 16U, 4U, stream, &fault);",
            "  context->runtime->write(context->runtime->context, context->entry_esp + 20U, 4U, flags, &fault);",
            "  context->runtime->write(context->runtime->context, context->entry_esp, 4U, value.words[0], &fault);",
            "  context->state->eax = value.words[1];",
            "  context->runtime->write(context->runtime->context, context->entry_esp + 4U, 4U, value.words[1], &fault);",
            "  context->state->eax = value.words[2];",
            "  context->runtime->write(context->runtime->context, context->entry_esp + 8U, 4U, value.words[2], &fault);",
            "  context->state->eax = value.words[3];",
            "  context->runtime->write(context->runtime->context, context->entry_esp + 12U, 4U, value.words[3], &fault);",
            "  if (fault) { context->status = STAGE_B_CALL_MEMORY_FAULT; return; }",
            "  stack_inputs[0] = (stage_b_stack_input){ 12U, 4U, value.words[3] };",
            "  event.kind = STAGE_B_CALL_EXTERNAL_IMPORT;",
            f"  event.instruction_rva = UINT32_C(0x{int(dump_event['call_rva']):08x});",
            f"  event.return_rva = UINT32_C(0x{int(dump_event['return_rva']):08x});",
            f"  event.dll = \"{dump_event['dll']}\"; event.symbol = \"{dump_event['symbol']}\";",
            "  event.stack_inputs = stack_inputs; event.stack_input_count = 1U;",
            *context_eflags_sync,
            f"  context->state->original_rva = UINT32_C(0x{int(dump_event['call_rva']) - 8:08x});",
            "  output = *context->state;",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status == STAGE_B_CALL_OK) *context->state = output;",
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  output_context context; opaque_output_services services;",
            "  if (rt == 0 || rt->read == 0 || rt->write == 0)",
            "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  context = (output_context){ rt, state, state->esp, STAGE_B_CALL_OK };",
            "  services = (opaque_output_services){ &context, open_stream, load_source, copy_value, dump_value };",
            "  prepare_and_dump_opaque_output(&services);",
            "  if (context.status != STAGE_B_CALL_OK)",
            "    return (stage_b_step_result){ context.status == STAGE_B_CALL_MEMORY_FAULT ? STAGE_B_MEMORY_FAULT : STAGE_B_EXTERNAL_FAULT, state->original_rva, 0U };",
            f"  return (stage_b_step_result){{ STAGE_B_JUMP, UINT32_C(0x{int(control['continuation_rva']):08x}), 0U }};",
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
        contract = _contract({"opaque_output_pipeline_contract": prepared.contract})
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        callback_slot = int(contract["events"][0]["target_slot"])
        esp = 0x70001000
        rows = []
        for index in range(10):
            source_words = tuple(
                (0x10203040 * (word + 1) + index * 0x01010101) & 0xFFFFFFFF
                for word in range(4)
            )
            copied_words = tuple(
                (value ^ (0xA5A5A5A5 + index)) & 0xFFFFFFFF
                for value in source_words
            )
            stack = bytearray(128)
            stack[80:96] = b"".join(
                value.to_bytes(4, "little") for value in source_words
            )
            stream = 0x71000000 + index * 0x100
            target = 0x72000000 + index * 0x100
            rows.append(
                {
                    "id": f"case:opaque-output-pipeline-{index}",
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
                        {"address": esp, "bytes": bytes(stack).hex()},
                        {
                            "address": callback_slot,
                            "bytes": target.to_bytes(4, "little").hex(),
                        },
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
                                        value.to_bytes(4, "little")
                                        for value in copied_words
                                    ).hex(),
                                }
                            ],
                        },
                        {"eax": 0x91000000 + index},
                    ],
                    "external_response_seed": f"opaque-output-pipeline-{index}",
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
        symbol = str(refinement.get("portable_symbol") or "")
        contract = _contract(refinement)
        abi = object_value(contract["abi"], "output-pipeline ABI")
        return f'''#include "implementation.h"
#include <stdint.h>

extern uint32_t nondet_u32(void);
typedef struct model {{
  uint32_t step, stream, stream_after_copy, open_mode, dump_flags;
  opaque_value4 source, copied, copy_input, dump_input;
}} model;
static uint32_t open_stream(void *opaque, uint32_t mode) {{
  model *m = (model *)opaque; __CPROVER_assert(m->step == 0U, "open first");
  m->step = 1U; m->open_mode = mode; return m->stream;
}}
static opaque_value4 load_source(void *opaque) {{
  model *m = (model *)opaque; __CPROVER_assert(m->step == 1U, "load second");
  m->step = 2U; return m->source;
}}
static opaque_copy_result copy_value(void *opaque, opaque_value4 value,
                                     uint32_t stream) {{
  model *m = (model *)opaque; opaque_copy_result result;
  __CPROVER_assert(m->step == 2U, "copy third");
  __CPROVER_assert(stream == m->stream, "copy stream");
  m->step = 3U; m->copy_input = value; result.value = m->copied;
  result.stream = m->stream_after_copy; return result;
}}
static void dump_value(void *opaque, opaque_value4 value, uint32_t stream,
                       uint32_t flags) {{
  model *m = (model *)opaque; __CPROVER_assert(m->step == 3U, "dump fourth");
  __CPROVER_assert(stream == m->stream_after_copy, "post-copy stream");
  m->step = 4U; m->dump_input = value; m->dump_flags = flags;
}}
int main(void) {{
  model m; opaque_output_services services;
  uint32_t index;
  m.step = 0U; m.stream = nondet_u32(); m.stream_after_copy = nondet_u32();
  for (index = 0U; index < 4U; ++index) {{
    m.source.words[index] = nondet_u32(); m.copied.words[index] = nondet_u32();
    m.copy_input.words[index] = 0U; m.dump_input.words[index] = 0U;
  }}
  services = (opaque_output_services){{ &m, open_stream, load_source, copy_value, dump_value }};
  {symbol}(&services);
  __CPROVER_assert(m.step == 4U, "complete protocol");
  __CPROVER_assert(m.open_mode == {int(abi['mode'])}U, "open mode");
  __CPROVER_assert(m.dump_flags == {int(abi['dump_flags'])}U, "dump flags");
  for (index = 0U; index < 4U; ++index) {{
    __CPROVER_assert(m.copy_input.words[index] == m.source.words[index], "copy input");
    __CPROVER_assert(m.dump_input.words[index] == m.copied.words[index], "dump input");
  }}
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 5

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {
            "complete_for_all_opaque_values_streams_and_service_results": True,
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
                "complete_for_all_opaque_values_streams_and_service_results"
            )
            is True
        )


PROFILE = OpaqueOutputPipelineProfile()
