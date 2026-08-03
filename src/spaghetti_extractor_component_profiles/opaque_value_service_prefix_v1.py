"""Portable forwarding of a four-word opaque value to one machine service."""

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


_FORMAT = "stage-b-opaque-value-service-prefix-contract-v1"


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
    raise StageAInputError(f"unsupported opaque-value operand kind: {kind!r}")


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


def _i(value: int, width: int = 32) -> tuple[Any, ...]:
    return ("i", value, width)


def _m(base: str, displacement: int, width: int = 32) -> tuple[Any, ...]:
    return ("m", base, None, 1, displacement, width)


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("opaque-value service prefix has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("opaque-value units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 5:
        raise StageAInputError("opaque-value service prefix requires five machine units")

    entry_shape = _shape(ordered[0])
    if (
        len(entry_shape) != 4
        or entry_shape[:3]
        != (
            ("push", (_r("edi"),)),
            ("push", (_r("esi"),)),
            ("push", (_r("ebx"),)),
        )
        or entry_shape[3][0] != "sub"
        or entry_shape[3][1][0] != _r("esp")
        or entry_shape[3][1][1][0] != "i"
    ):
        raise StageAInputError("opaque-value entry frame is malformed")
    local_frame_bytes = int(entry_shape[3][1][1][1])
    if local_frame_bytes < 16 or local_frame_bytes % 4 != 0:
        raise StageAInputError("opaque-value local frame is not word aligned")
    frame_delta = local_frame_bytes + 12

    expected = (
        None,
        (
            ("mov", (_r("eax"), _m("esp", frame_delta + 8))),
            ("mov", (_r("ecx"), _m("esp", frame_delta + 12))),
            ("mov", (_r("edx"), _m("esp", frame_delta + 16))),
            ("mov", (_r("esi"), _m("esp", frame_delta + 8))),
        ),
        (
            ("mov", (_m("esp", 32), _r("eax"))),
            ("mov", (_r("eax"), _m("esp", frame_delta + 20))),
            ("mov", (_m("esp", 36), _r("ecx"))),
            ("mov", (_r("ebx"), _m("esp", frame_delta + 4))),
        ),
        (
            ("mov", (_m("esp", 40), _r("edx"))),
            ("mov", (_m("esp", 44), _r("eax"))),
            ("mov", (_m("esp", 0), _r("esi"))),
            ("mov", (_m("esp", 4), _r("ecx"))),
        ),
        None,
    )
    for index, shape in enumerate(expected):
        if shape is not None and _shape(ordered[index]) != shape:
            raise StageAInputError(
                f"opaque-value unit {index} has an unexpected instruction shape"
            )
    call_shape = _shape(ordered[4])
    if (
        len(call_shape) != 3
        or call_shape[0] != ("mov", (_m("esp", 8), _r("edx")))
        or call_shape[1] != ("mov", (_m("esp", 12), _r("eax")))
        or call_shape[2][0] != "call"
        or len(call_shape[2][1]) != 1
    ):
        raise StageAInputError("opaque-value service call frame is malformed")

    starts = [_rva(unit) for unit in ordered]
    for index, unit in enumerate(ordered):
        control = object_value(unit.get("control"), "opaque-value control")
        expected_target = starts[index + 1] if index + 1 < len(starts) else int(
            object_value(
                object_value(unit.get("semantics"), "call semantics").get("outcome"),
                "call outcome",
            )["target_rva"]
        )
        if control.get("kind") != "fallthrough" or control.get("direct_targets") != [
            expected_target
        ]:
            raise StageAInputError(
                f"opaque-value CFG mismatch at RVA 0x{_rva(unit):x}"
            )

    events = array_value(
        object_value(ordered[4].get("semantics"), "call semantics").get(
            "external_events"
        ),
        "opaque-value service events",
    )
    if len(events) != 1:
        raise StageAInputError("opaque-value prefix must emit one external event")
    event = object_value(events[0], "opaque-value service event")
    stack_inputs = array_value(event.get("stack_inputs"), "service stack inputs")
    if (
        event.get("kind") != "external_call"
        or not isinstance(event.get("dll"), str)
        or not event.get("dll")
        or not isinstance(event.get("symbol"), str)
        or not event.get("symbol")
        or event.get("ordinal") is not None
        or event.get("return_rva")
        != object_value(
            object_value(ordered[4].get("semantics"), "call semantics").get(
                "outcome"
            ),
            "call outcome",
        ).get("target_rva")
        or event.get("arguments") != []
        or [item.get("offset") for item in stack_inputs] != [8, 12]
        or any(item.get("width") != 4 for item in stack_inputs)
    ):
        raise StageAInputError("opaque-value event is outside the four-word profile")

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
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "opaque_value_service_prefix_v1",
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
            "requires": "readable entry arguments, writable stack, and the declared service",
        },
        "abi": {
            "value_words": 4,
            "value_entry_stack_offset": 8,
            "context_entry_stack_offset": 4,
            "saved_registers": ["edi", "esi", "ebx"],
            "local_frame_bytes": local_frame_bytes,
            "entry_to_call_stack_delta": frame_delta,
            "local_copy_offset": 32,
            "call_copy_offset": 0,
        },
        "external_event": {
            "dll": str(event["dll"]),
            "symbol": str(event["symbol"]),
            "call_rva": int(ordered[4]["instructions"][-1]["rva_start"]),
            "return_rva": int(event["return_rva"]),
            "reported_stack_inputs": [8, 12],
        },
        "behavior": {
            "service_calls": 1,
            "service_argument": "one exact copy of all four opaque value words",
            "result": "service result",
            "control": "fallthrough to the declared continuation",
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("opaque_value_service_prefix_contract"),
        "opaque-value service-prefix contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("opaque-value service-prefix contract is stale")
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
        raise StageAInputError("opaque-value adapter does not have one entry")
    return files, adapter, matches[0]


class OpaqueValueServicePrefixProfile:
    name = "opaque_value_service_prefix_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        del interface_refinement
        return (
            {
                "semantic_expression": {
                    "op": "add32",
                    "args": [
                        {"op": "reg", "name": "esp", "width": 32},
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
                "width": 20,
                "access": "read",
            },
            {
                "semantic_expression": {
                    "op": "sub32",
                    "args": [
                        {"op": "reg", "name": "esp", "width": 32},
                        {"op": "const", "value": 76, "width": 32},
                    ],
                },
                "width": 48,
                "access": "read_write",
            },
        )

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="classify_opaque_value",
            contract_field="opaque_value_service_prefix_contract",
            contract_filename="opaque-value-service-prefix-contract.json",
            contract_hash_binding="opaque_value_service_prefix_contract_sha256",
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
        abi = object_value(contract["abi"], "opaque-value ABI")
        event = object_value(contract["external_event"], "opaque-value event")
        local_frame = int(abi["local_frame_bytes"])
        frame_delta = int(abi["entry_to_call_stack_delta"])
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

typedef struct opaque_value4 {
  uint32_t words[4];
} opaque_value4;

typedef struct opaque_value_services {
  void *context;
  uint32_t (*classify)(void *context, opaque_value4 value);
} opaque_value_services;

uint32_t classify_opaque_value(opaque_value_services *services,
                               opaque_value4 value);

#endif
"""
        portable = """#include "implementation.h"

uint32_t classify_opaque_value(opaque_value_services *services,
                               opaque_value4 value) {
  return services->classify(services->context, value);
}
"""
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            "typedef struct opaque_value_context {",
            "  stage_b_runtime *runtime;",
            "  stage_b_machine_state *state;",
            "  stage_b_call_status status;",
            "} opaque_value_context;",
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
            "static uint32_t call_service(void *opaque, opaque_value4 value) {",
            "  opaque_value_context *context = (opaque_value_context *)opaque;",
            "  stage_b_machine_state output = *context->state;",
            "  const stage_b_stack_input stack_inputs[] = {",
            "    { 8U, 4U, value.words[2] }, { 12U, 4U, value.words[3] }",
            "  };",
            "  const stage_b_call_event event = {",
            f"    STAGE_B_CALL_EXTERNAL_IMPORT, UINT32_C(0x{int(event['call_rva']):08x}), 0U, 0U, UINT32_C(0x{int(event['return_rva']):08x}),",
            f'    "{event["dll"]}", "{event["symbol"]}", 0U, 0U, 0, 0U, stack_inputs, 2U',
            "  };",
            f"  context->state->original_rva = UINT32_C(0x{int(event['call_rva']) - 8:08x});",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status == STAGE_B_CALL_OK) *context->state = output;",
            "  return output.eax;",
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  uint32_t fault = 0U, entry_esp, pushed_esp, frame_esp, context_word;",
            "  opaque_value4 value; opaque_value_context context; opaque_value_services services;",
            "  uint32_t result;",
            "  if (rt == 0 || rt->read == 0 || rt->write == 0)",
            "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  entry_esp = state->esp;",
            "  rt->write(rt->context, entry_esp - UINT32_C(4), 4U, state->edi, &fault);",
            "  rt->write(rt->context, entry_esp - UINT32_C(8), 4U, state->esi, &fault);",
            "  rt->write(rt->context, entry_esp - UINT32_C(12), 4U, state->ebx, &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  pushed_esp = entry_esp - UINT32_C(12);",
            f"  frame_esp = pushed_esp - UINT32_C({local_frame});",
            f"  subtraction_flags(state, pushed_esp, UINT32_C({local_frame}), frame_esp);",
            "  state->esp = frame_esp;",
            "  context_word = rt->read(rt->context, entry_esp + UINT32_C(4), 4U, &fault);",
            "  value.words[0] = rt->read(rt->context, entry_esp + UINT32_C(8), 4U, &fault);",
            "  value.words[1] = rt->read(rt->context, entry_esp + UINT32_C(12), 4U, &fault);",
            "  value.words[2] = rt->read(rt->context, entry_esp + UINT32_C(16), 4U, &fault);",
            "  value.words[3] = rt->read(rt->context, entry_esp + UINT32_C(20), 4U, &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  state->eax = value.words[3]; state->ebx = context_word;",
            "  state->ecx = value.words[1]; state->edx = value.words[2];",
            "  state->esi = value.words[0];",
            "  rt->write(rt->context, frame_esp + UINT32_C(32), 4U, value.words[0], &fault);",
            "  rt->write(rt->context, frame_esp + UINT32_C(36), 4U, value.words[1], &fault);",
            "  rt->write(rt->context, frame_esp + UINT32_C(40), 4U, value.words[2], &fault);",
            "  rt->write(rt->context, frame_esp + UINT32_C(44), 4U, value.words[3], &fault);",
            "  rt->write(rt->context, frame_esp + UINT32_C(0), 4U, value.words[0], &fault);",
            "  rt->write(rt->context, frame_esp + UINT32_C(4), 4U, value.words[1], &fault);",
            "  rt->write(rt->context, frame_esp + UINT32_C(8), 4U, value.words[2], &fault);",
            "  rt->write(rt->context, frame_esp + UINT32_C(12), 4U, value.words[3], &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            *machine_eflags_sync_lines("  "),
            f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
            "  context = (opaque_value_context){ rt, state, STAGE_B_CALL_OK };",
            "  services = (opaque_value_services){ &context, call_service };",
            "  result = classify_opaque_value(&services, value);",
            "  if (context.status != STAGE_B_CALL_OK)",
            "    return (stage_b_step_result){ STAGE_B_EXTERNAL_FAULT, state->original_rva, 0U };",
            "  state->eax = result;",
            f"  return (stage_b_step_result){{ STAGE_B_FALLTHROUGH, UINT32_C(0x{int(event['return_rva']):08x}), 0U }};",
            "}",
            "",
        ]
        if frame_delta != local_frame + 12:
            raise StageAInputError("opaque-value frame contract is inconsistent")
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
        _contract({"opaque_value_service_prefix_contract": prepared.contract})
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        esp = 0x70001000
        probes = (
            ("zero", (0, 0, 0, 0), 0),
            ("kind-null", (0, 0, 0, 0), 1),
            ("kind-false", (1, 0, 0, 0), 2),
            ("kind-true", (2, 3, 4, 5), 3),
            ("kind-number", (0xFFFFFFFF, 1, 2, 3), 4),
            ("kind-string", (0x80000000, 0x7FFFFFFF, 6, 7), 5),
            ("kind-array", (0x11223344, 0x55667788, 8, 9), 6),
            ("kind-object", (0xA5A5A5A5, 0x5A5A5A5A, 10, 11), 7),
            ("max-result", (12, 13, 14, 15), 0xFFFFFFFF),
            ("high-result", (16, 17, 18, 19), 0x80000000),
        )
        rows = []
        for index, (label, words, response) in enumerate(probes):
            context_word = 0x71000000 + index * 0x100
            argument_bytes = context_word.to_bytes(4, "little") + b"".join(
                int(word).to_bytes(4, "little") for word in words
            )
            rows.append(
                {
                    "id": f"case:opaque-value-service-prefix-{label}",
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
                        {"address": esp + 4, "bytes": argument_bytes.hex()},
                    ],
                    "external_responses": [{"eax": response}],
                    "external_response_seed": f"opaque-value-{label}",
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
        _contract(refinement)
        return f'''#include "implementation.h"
#include <stdint.h>

extern uint32_t nondet_u32(void);
typedef struct model {{ opaque_value4 observed; uint32_t calls, response; }} model;
static uint32_t classify(void *opaque, opaque_value4 value) {{
  model *m = (model *)opaque; m->calls++; m->observed = value; return m->response;
}}
int main(void) {{
  opaque_value4 value = {{ {{ nondet_u32(), nondet_u32(), nondet_u32(), nondet_u32() }} }};
  model m = {{ {{ {{ 0U, 0U, 0U, 0U }} }}, 0U, nondet_u32() }};
  opaque_value_services services = {{ &m, classify }};
  uint32_t actual = {symbol}(&services, value);
  __CPROVER_assert(m.calls == 1U, "one service call");
  __CPROVER_assert(m.observed.words[0] == value.words[0], "word zero");
  __CPROVER_assert(m.observed.words[1] == value.words[1], "word one");
  __CPROVER_assert(m.observed.words[2] == value.words[2], "word two");
  __CPROVER_assert(m.observed.words[3] == value.words[3], "word three");
  __CPROVER_assert(actual == m.response, "service result");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {
            "complete_for_all_four_word_values_and_service_results": True,
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
                "complete_for_all_four_word_values_and_service_results"
            )
            is True
        )


PROFILE = OpaqueValueServicePrefixProfile()
