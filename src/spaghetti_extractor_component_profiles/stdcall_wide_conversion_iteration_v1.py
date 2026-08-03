"""Lift one checked stdcall wide-to-byte conversion loop iteration."""

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


_FORMAT = "stage-b-stdcall-wide-conversion-iteration-contract-v1"


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    return sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()


def _rva(unit: Mapping[str, Any]) -> int:
    return int(object_value(unit.get("source"), "unit source")["original"]["rva_start"])


def _operand(value: Any) -> tuple[Any, ...]:
    operand = object_value(value, "wide-conversion operand")
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
    raise StageAInputError(f"unsupported wide-conversion operand kind: {kind!r}")


def _shape(unit: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        (
            str(instruction.get("mnemonic")),
            tuple(
                _operand(operand)
                for operand in array_value(
                    instruction.get("operands"), "wide-conversion operands"
                )
            ),
        )
        for instruction in array_value(
            unit.get("instructions"), "wide-conversion instructions"
        )
    )


def _r(name: str) -> tuple[Any, ...]:
    return ("r", name, 32)


def _i(value: int) -> tuple[Any, ...]:
    return ("i", value & 0xFFFFFFFF, 32)


def _m(
    base: str,
    displacement: int,
    *,
    index: str | None = None,
    scale: int = 1,
) -> tuple[Any, ...]:
    return ("m", base, index, scale, displacement, 32)


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("wide-conversion iteration has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("wide-conversion units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 5:
        raise StageAInputError("wide-conversion iteration requires five machine units")
    shapes = [_shape(unit) for unit in ordered]
    expected = (
        (
            ("mov", (_r("ecx"), _m("ebp", -28))),
            ("sub", (_r("esp"), _r("eax"))),
            ("lea", (_r("eax"), _m("esp", 47))),
            ("and", (_r("eax"), _i(0xFFFFFFF0))),
        ),
        (
            ("mov", (_m("ecx", 0, index="edi", scale=4), _r("eax"))),
            ("mov", (_m("esp", 28), _i(0))),
            ("mov", (_m("esp", 24), _i(0))),
            ("mov", (_m("esp", 20), _r("edx"))),
        ),
        (
            ("mov", (_m("esp", 16), _r("eax"))),
            ("mov", (_m("esp", 12), _i(0xFFFFFFFF))),
            ("mov", (_r("eax"), _m("ebx", 0, index="edi", scale=4))),
            ("add", (_r("edi"), _i(1))),
        ),
        (
            ("mov", (_m("esp", 4), _i(0))),
            ("mov", (_m("esp", 8), _r("eax"))),
            ("mov", (_m("esp", 0), _i(65001))),
            ("call", (_r("esi"),)),
        ),
        (
            ("sub", (_r("esp"), _i(32))),
            ("cmp", (_m("ebp", 8), _r("edi"))),
        ),
    )
    if tuple(shapes[:4]) != expected[:4] or shapes[4][:2] != expected[4]:
        raise StageAInputError(
            "wide-conversion iteration does not match the normalized stdcall loop shape"
        )
    if (
        len(shapes[4]) != 3
        or shapes[4][2][0] != "jne"
        or len(shapes[4][2][1]) != 1
        or shapes[4][2][1][0][0] != "i"
    ):
        raise StageAInputError("wide-conversion iteration has a malformed loop branch")

    rvas = [_rva(unit) for unit in ordered]
    for index, unit in enumerate(ordered[:4]):
        control = object_value(unit.get("control"), "wide-conversion control")
        if control.get("kind") != "fallthrough" or control.get("direct_targets") != [
            rvas[index + 1]
        ]:
            raise StageAInputError("wide-conversion fallthrough chain is malformed")
    final_control = object_value(ordered[4].get("control"), "wide-conversion branch")
    outcome = object_value(
        object_value(ordered[4].get("semantics"), "wide-conversion semantics").get(
            "outcome"
        ),
        "wide-conversion outcome",
    )
    if final_control.get("kind") != "branch" or outcome.get("kind") != "branch":
        raise StageAInputError("wide-conversion iteration has no terminal branch")
    loop_rva = int(outcome.get("true_target_rva", -1))
    done_rva = int(outcome.get("false_target_rva", -1))
    if set(final_control.get("direct_targets", [])) != {loop_rva, done_rva}:
        raise StageAInputError("wide-conversion branch targets disagree")

    call_semantics = object_value(ordered[3].get("semantics"), "call semantics")
    events = array_value(call_semantics.get("external_events"), "call events")
    call_instruction = array_value(ordered[3].get("instructions"), "call instructions")[-1]
    if len(events) != 1:
        raise StageAInputError("wide-conversion iteration requires one callback event")
    event = object_value(events[0], "wide-conversion callback")
    if (
        event.get("kind") != "indirect_call"
        or event.get("target") != {"op": "reg", "name": "esi", "width": 32}
        or event.get("return_rva") != rvas[4]
        or int(call_instruction.get("rva_end", -1)) != rvas[4]
    ):
        raise StageAInputError("wide-conversion callback boundary is malformed")

    boundary = object_value(context.component.get("machine_boundary"), "component boundary")
    counts = object_value(boundary.get("counts"), "component boundary counts")
    exits = array_value(boundary.get("exits"), "component exits")
    if (
        boundary.get("call_closure", {}).get("status") != "complete"
        or counts.get("entries") != 1
        or counts.get("exits") != 2
        or counts.get("external_events") != 1
        or counts.get("faults") != 0
        or any(exit_item.get("kind") != "direct_control" for exit_item in exits)
    ):
        raise StageAInputError("wide-conversion component boundary is not exact")

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
        "profile": "stdcall_wide_conversion_iteration_v1",
        "component": {
            "id": str(context.component["id"]),
            "sha256": str(context.component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "units": bindings,
        },
        "abi": {
            "code_page": 65001,
            "callback_register": "esi",
            "argument_bytes": 32,
            "stack_arguments": [
                "code_page",
                "flags",
                "source",
                "source_length",
                "destination",
                "destination_bytes",
                "default_character",
                "used_default_character",
            ],
            "source_length": -1,
            "destination_alignment": 16,
            "destination_bias": 47,
            "output_array_frame_offset": -28,
            "argument_count_frame_offset": 8,
        },
        "control": {
            "call_rva": int(call_instruction["rva_start"]),
            "return_rva": rvas[4],
            "loop_rva": loop_rva,
            "done_rva": done_rva,
        },
        "semantics": {
            "operation": "convert one indexed NUL-terminated wide argument to UTF-8",
            "destination_slot_written_before_call": True,
            "index_incremented_before_call": True,
            "continue_when_incremented_index_differs_from_argument_count": True,
            "external_stack_cleanup_bytes": 32,
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("stdcall_wide_conversion_iteration_contract"),
        "stdcall wide-conversion contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("stdcall wide-conversion contract is stale")
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
        raise StageAInputError("wide-conversion adapter does not have one entry")
    return files, adapter, symbols[0]


class StdcallWideConversionIterationProfile:
    name = "stdcall_wide_conversion_iteration_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        _contract(interface_refinement)
        return ()

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="convert_one_wide_argument",
            contract_field="stdcall_wide_conversion_iteration_contract",
            contract_filename="stdcall-wide-conversion-iteration-contract.json",
            contract_hash_binding="stdcall_wide_conversion_iteration_contract_sha256",
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
        abi = object_value(contract["abi"], "wide-conversion ABI")
        control = object_value(contract["control"], "wide-conversion control")
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = '''#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

#define WIDE_CONVERSION_CODE_PAGE UINT32_C(65001)
#define WIDE_CONVERSION_SOURCE_NUL_TERMINATED INT32_C(-1)

typedef struct wide_conversion_services {
  void *context;
  uint32_t (*convert)(void *context, uint32_t code_page, uint32_t flags,
      uint32_t source, int32_t source_length, uint32_t destination,
      uint32_t destination_bytes, uint32_t default_character,
      uint32_t used_default_character);
} wide_conversion_services;

typedef struct wide_conversion_result {
  uint32_t destination;
  uint32_t converted_units;
} wide_conversion_result;

wide_conversion_result convert_one_wide_argument(
    wide_conversion_services *services, uint32_t source,
    uint32_t destination, uint32_t destination_bytes);

#endif
'''
        portable = '''#include "implementation.h"

wide_conversion_result convert_one_wide_argument(
    wide_conversion_services *services, uint32_t source,
    uint32_t destination, uint32_t destination_bytes) {
  wide_conversion_result result;
  result.destination = destination;
  result.converted_units = services->convert(
      services->context, WIDE_CONVERSION_CODE_PAGE, 0U, source,
      WIDE_CONVERSION_SOURCE_NUL_TERMINATED, destination, destination_bytes,
      0U, 0U);
  return result;
}
'''
        sync = machine_eflags_sync_lines("  ")
        context_sync = [line.replace("state->", "context->state->") for line in sync]
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            "typedef struct conversion_context {",
            "  stage_b_runtime *runtime; stage_b_machine_state *state;",
            "  stage_b_call_status status; uint32_t call_esp;",
            "} conversion_context;",
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
            "static void addition_flags(stage_b_machine_state *state, uint32_t left, uint32_t right, uint32_t result) {",
            "  state->cf = result < left;",
            "  state->of = ((~(left ^ right) & (left ^ result)) >> 31) & UINT32_C(1);",
            "  state->pf = byte_parity(result); state->sf = result >> 31; state->zf = result == 0U;",
            "}",
            "",
            "static void logical_flags(stage_b_machine_state *state, uint32_t result) {",
            "  state->cf = 0U; state->of = 0U; state->pf = byte_parity(result);",
            "  state->sf = result >> 31; state->zf = result == 0U;",
            "}",
            "",
            "static uint32_t invoke_conversion(void *opaque, uint32_t code_page, uint32_t flags,",
            "    uint32_t source, int32_t source_length, uint32_t destination,",
            "    uint32_t destination_bytes, uint32_t default_character,",
            "    uint32_t used_default_character) {",
            "  conversion_context *context = (conversion_context *)opaque;",
            "  stage_b_machine_state output; stage_b_stack_input stack_inputs[8];",
            "  stage_b_call_event event = {0}; uint32_t fault = 0U;",
            "  if (context->status != STAGE_B_CALL_OK) return 0U;",
            "  context->runtime->write(context->runtime->context, context->call_esp + 0U, 4U, code_page, &fault);",
            "  context->runtime->write(context->runtime->context, context->call_esp + 4U, 4U, flags, &fault);",
            "  context->runtime->write(context->runtime->context, context->call_esp + 8U, 4U, source, &fault);",
            "  context->runtime->write(context->runtime->context, context->call_esp + 12U, 4U, (uint32_t)source_length, &fault);",
            "  context->runtime->write(context->runtime->context, context->call_esp + 16U, 4U, destination, &fault);",
            "  context->runtime->write(context->runtime->context, context->call_esp + 20U, 4U, destination_bytes, &fault);",
            "  context->runtime->write(context->runtime->context, context->call_esp + 24U, 4U, default_character, &fault);",
            "  context->runtime->write(context->runtime->context, context->call_esp + 28U, 4U, used_default_character, &fault);",
            "  if (fault) { context->status = STAGE_B_CALL_MEMORY_FAULT; return 0U; }",
            "  stack_inputs[0] = (stage_b_stack_input){ 0U, 4U, code_page };",
            "  stack_inputs[1] = (stage_b_stack_input){ 4U, 4U, flags };",
            "  stack_inputs[2] = (stage_b_stack_input){ 8U, 4U, source };",
            "  stack_inputs[3] = (stage_b_stack_input){ 12U, 4U, (uint32_t)source_length };",
            "  stack_inputs[4] = (stage_b_stack_input){ 16U, 4U, destination };",
            "  stack_inputs[5] = (stage_b_stack_input){ 20U, 4U, destination_bytes };",
            "  stack_inputs[6] = (stage_b_stack_input){ 24U, 4U, default_character };",
            "  stack_inputs[7] = (stage_b_stack_input){ 28U, 4U, used_default_character };",
            "  event.kind = STAGE_B_CALL_INDIRECT; event.target_rva = context->state->esi;",
            f"  event.instruction_rva = UINT32_C(0x{int(control['call_rva']):08x});",
            f"  event.return_rva = UINT32_C(0x{int(control['return_rva']):08x});",
            "  event.stack_inputs = stack_inputs; event.stack_input_count = 8U;",
            *context_sync,
            "  output = *context->state;",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status == STAGE_B_CALL_OK) *context->state = output;",
            "  return output.eax;",
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  uint32_t entry_esp, allocation, call_esp, destination, outputs, source;",
            "  uint32_t argument_count, old_index, difference, fault = 0U;",
            "  wide_conversion_result result; conversion_context context;",
            "  wide_conversion_services services;",
            "  if (rt == 0 || rt->read == 0 || rt->write == 0)",
            "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  entry_esp = state->esp; allocation = state->eax; old_index = state->edi;",
            "  outputs = rt->read(rt->context, state->ebp - UINT32_C(28), 4U, &fault);",
            "  call_esp = entry_esp - allocation;",
            "  destination = (call_esp + UINT32_C(47)) & UINT32_C(0xfffffff0);",
            "  state->ecx = outputs; state->esp = call_esp; state->eax = destination;",
            "  logical_flags(state, destination);",
            "  rt->write(rt->context, outputs + old_index * UINT32_C(4), 4U, destination, &fault);",
            "  source = rt->read(rt->context, state->ebx + old_index * UINT32_C(4), 4U, &fault);",
            "  state->eax = source; state->edi = old_index + UINT32_C(1);",
            "  addition_flags(state, old_index, UINT32_C(1), state->edi);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
            "  context = (conversion_context){ rt, state, STAGE_B_CALL_OK, call_esp };",
            "  services = (wide_conversion_services){ &context, invoke_conversion };",
            "  result = convert_one_wide_argument(&services, source, destination, state->edx);",
            "  if (context.status != STAGE_B_CALL_OK)",
            "    return (stage_b_step_result){ context.status == STAGE_B_CALL_MEMORY_FAULT ? STAGE_B_MEMORY_FAULT : STAGE_B_EXTERNAL_FAULT, state->original_rva, 0U };",
            "  if (result.destination != destination || result.converted_units != state->eax)",
            "    return (stage_b_step_result){ STAGE_B_UNIMPLEMENTED, state->original_rva, 0U };",
            f"  state->esp -= UINT32_C({int(abi['argument_bytes'])});",
            "  argument_count = rt->read(rt->context, state->ebp + UINT32_C(8), 4U, &fault);",
            "  difference = argument_count - state->edi;",
            "  subtraction_flags(state, argument_count, state->edi, difference);",
            *sync,
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            f"  return (stage_b_step_result){{ STAGE_B_BRANCH, argument_count != state->edi ? UINT32_C(0x{int(control['loop_rva']):08x}) : UINT32_C(0x{int(control['done_rva']):08x}), 0U }};",
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
            {"stdcall_wide_conversion_iteration_contract": prepared.contract}
        )
        abi = object_value(contract["abi"], "wide-conversion ABI")
        files = object_value(backend_workspace.get("files"), "backend files")
        rows = []
        for index in range(10):
            esp = 0x70002000 + index * 0x200
            ebp = 0x70010000 + index * 0x100
            allocation = 64 + (index % 4) * 16
            call_esp = (esp - allocation) & 0xFFFFFFFF
            output_array = 0x71000000 + index * 0x100
            source_array = 0x72000000 + index * 0x100
            old_index = index % 3
            argument_count = old_index + (1 if index % 2 else 2)
            source = 0x73000000 + index * 0x100
            converted = 1 + index * 3
            rows.append(
                {
                    "id": f"case:stdcall-wide-conversion-{index}",
                    "registers": {
                        "eax": allocation,
                        "ebx": source_array,
                        "ecx": 0x21222324 + index,
                        "edx": 48 + index * 7,
                        "esi": 0x74000000 + index * 0x100,
                        "edi": old_index,
                        "ebp": ebp,
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
                        {
                            "address": ebp - 28,
                            "bytes": output_array.to_bytes(4, "little").hex(),
                        },
                        {
                            "address": ebp + 8,
                            "bytes": argument_count.to_bytes(4, "little").hex(),
                        },
                        {
                            "address": source_array + old_index * 4,
                            "bytes": source.to_bytes(4, "little").hex(),
                        },
                    ],
                    "external_responses": [
                        {
                            "eax": converted,
                            "registers": {
                                "esp": (call_esp + int(abi["argument_bytes"]))
                                & 0xFFFFFFFF
                            },
                        }
                    ],
                    "external_response_seed": f"stdcall-wide-conversion-{index}",
                }
            )
        payload = {
            "format": "stage-b-reconstruction-cases-v1",
            "cluster_id": cluster["id"],
            "entry_unit_id": cluster["entry_unit_id"],
            "entry_rva": cluster["entry_rva"],
            "call_stack_observations": [
                {
                    "event_index": 0,
                    "slots": [
                        {"offset": offset, "width": 4}
                        for offset in range(0, int(abi["argument_bytes"]), 4)
                    ],
                }
            ],
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
typedef struct model {{
  uint32_t calls, source, destination, destination_bytes, result;
}} model;
static uint32_t convert(void *opaque, uint32_t code_page, uint32_t flags,
    uint32_t source, int32_t source_length, uint32_t destination,
    uint32_t destination_bytes, uint32_t default_character,
    uint32_t used_default_character) {{
  model *m = (model *)opaque;
  __CPROVER_assert(m->calls == 0U, "one conversion call");
  __CPROVER_assert(code_page == WIDE_CONVERSION_CODE_PAGE, "UTF-8 code page");
  __CPROVER_assert(flags == 0U, "zero conversion flags");
  __CPROVER_assert(source == m->source, "source forwarded");
  __CPROVER_assert(source_length == WIDE_CONVERSION_SOURCE_NUL_TERMINATED, "NUL-terminated source");
  __CPROVER_assert(destination == m->destination, "destination forwarded");
  __CPROVER_assert(destination_bytes == m->destination_bytes, "capacity forwarded");
  __CPROVER_assert(default_character == 0U, "no default character");
  __CPROVER_assert(used_default_character == 0U, "no default-character output");
  m->calls = 1U; return m->result;
}}
int main(void) {{
  model m; wide_conversion_services services; wide_conversion_result result;
  m.calls = 0U; m.source = nondet_u32(); m.destination = nondet_u32();
  m.destination_bytes = nondet_u32(); m.result = nondet_u32();
  services = (wide_conversion_services){{ &m, convert }};
  result = {symbol}(&services, m.source, m.destination, m.destination_bytes);
  __CPROVER_assert(m.calls == 1U, "conversion completed");
  __CPROVER_assert(result.destination == m.destination, "destination result");
  __CPROVER_assert(result.converted_units == m.result, "conversion result");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {
            "complete_for_all_sources_destinations_capacities_and_results": True,
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
                "complete_for_all_sources_destinations_capacities_and_results"
            )
            is True
        )


PROFILE = StdcallWideConversionIterationProfile()
