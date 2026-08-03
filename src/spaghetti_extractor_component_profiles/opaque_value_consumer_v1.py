"""Consume one four-word opaque value through an exact machine service."""

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


_FORMAT = "stage-b-opaque-value-consumer-contract-v1"


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
    raise StageAInputError(f"unsupported opaque-value consumer operand: {kind!r}")


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


def _m(base: str, displacement: int, width: int = 32) -> tuple[Any, ...]:
    return ("m", base, None, 1, displacement, width)


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("opaque-value consumer has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("opaque-value consumer units do not match membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) not in {3, 4}:
        raise StageAInputError("opaque-value consumer requires three or four units")

    release_entry = (
        ("mov", (_r("eax"), _m("esp", 80))),
        ("xor", (_r("esi"), _r("esi"))),
        ("mov", (_m("esp", 0), _r("eax"))),
        ("mov", (_r("eax"), _m("esp", 84))),
    )
    scalar_entry = (
        ("mov", (_r("eax"), _m("esp", 80))),
        ("mov", (_m("esp", 16), _r("edi"))),
        ("mov", (_m("esp", 0), _r("eax"))),
        ("mov", (_r("eax"), _m("esp", 84))),
    )
    if _shape(ordered[0]) == release_entry and len(ordered) == 4:
        variant = "value_only_jump"
        auxiliary_register = None
        zero_esi_before_call = True
    elif _shape(ordered[0]) == scalar_entry and len(ordered) == 3:
        variant = "value_and_u32_fallthrough"
        auxiliary_register = "edi"
        zero_esi_before_call = False
    else:
        raise StageAInputError("opaque-value consumer entry shape is unsupported")
    second_shape = (
        ("mov", (_m("esp", 4), _r("eax"))),
        ("mov", (_r("eax"), _m("esp", 88))),
        ("mov", (_m("esp", 8), _r("eax"))),
        ("mov", (_r("eax"), _m("esp", 92))),
    )
    if _shape(ordered[1]) != second_shape:
        raise StageAInputError("opaque-value consumer copy shape is unsupported")
    call_shape = _shape(ordered[2])
    if (
        len(call_shape) != 2
        or call_shape[0] != ("mov", (_m("esp", 12), _r("eax")))
        or call_shape[1][0] != "call"
        or len(call_shape[1][1]) != 1
    ):
        raise StageAInputError("opaque-value consumer call frame is malformed")
    starts = [_rva(unit) for unit in ordered]
    for index, unit in enumerate(ordered[:2]):
        control = object_value(unit.get("control"), "opaque-value consumer control")
        if control.get("kind") != "fallthrough" or control.get("direct_targets") != [
            starts[index + 1]
        ]:
            raise StageAInputError(
                f"opaque-value consumer CFG mismatch at RVA 0x{starts[index]:x}"
            )
    call_control = object_value(ordered[2].get("control"), "consumer call control")
    call_targets = array_value(call_control.get("direct_targets"), "call targets")
    if call_control.get("kind") != "fallthrough" or len(call_targets) != 1:
        raise StageAInputError("opaque-value consumer call has no continuation")
    call_return_rva = int(call_targets[0])
    if variant == "value_only_jump":
        if call_return_rva != starts[3]:
            raise StageAInputError("opaque-value consumer jump unit is disconnected")
        jump_shape = _shape(ordered[3])
        jump_control = object_value(ordered[3].get("control"), "consumer jump")
        targets = array_value(jump_control.get("direct_targets"), "jump targets")
        if (
            len(jump_shape) != 1
            or jump_shape[0][0] != "jmp"
            or jump_control.get("kind") != "jump"
            or len(targets) != 1
        ):
            raise StageAInputError("opaque-value consumer continuation is not a jump")
        continuation_rva = int(targets[0])
        control_kind = "jump"
    else:
        continuation_rva = call_return_rva
        control_kind = "fallthrough"

    events = array_value(
        object_value(ordered[2].get("semantics"), "consumer semantics").get(
            "external_events"
        ),
        "opaque-value consumer events",
    )
    if len(events) != 1:
        raise StageAInputError("opaque-value consumer must emit one external event")
    event = object_value(events[0], "opaque-value consumer event")
    stack_inputs = array_value(event.get("stack_inputs"), "consumer stack inputs")
    if (
        event.get("kind") != "external_call"
        or not isinstance(event.get("dll"), str)
        or not event.get("dll")
        or not isinstance(event.get("symbol"), str)
        or not event.get("symbol")
        or event.get("ordinal") is not None
        or event.get("arguments") != []
        or len(stack_inputs) != 1
        or stack_inputs[0].get("offset") != 12
        or stack_inputs[0].get("width") != 4
        or event.get("return_rva") != call_return_rva
    ):
        raise StageAInputError("opaque-value consumer event is outside this profile")

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
        "profile": "opaque_value_consumer_v1",
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
            "requires": "readable value words, writable call frame, and declared service",
        },
        "abi": {
            "value_words": 4,
            "value_stack_offset": 80,
            "call_copy_offset": 0,
            "variant": variant,
            "auxiliary_register": auxiliary_register,
            "auxiliary_call_stack_offset": (
                16 if auxiliary_register is not None else None
            ),
            "zero_esi_before_call": zero_esi_before_call,
        },
        "external_event": {
            "dll": str(event["dll"]),
            "symbol": str(event["symbol"]),
            "call_rva": int(ordered[2]["instructions"][-1]["rva_start"]),
            "return_rva": int(event["return_rva"]),
            "reported_stack_inputs": [12],
        },
        "behavior": {
            "service_calls": 1,
            "service_argument": "one exact copy of all four opaque value words",
            "result": "the exact external machine response",
            "control": control_kind,
            "continuation_rva": continuation_rva,
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("opaque_value_consumer_contract"),
        "opaque-value consumer contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("opaque-value consumer contract is stale")
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
        raise StageAInputError("opaque-value consumer adapter does not have one entry")
    return files, adapter, matches[0]


class OpaqueValueConsumerProfile:
    name = "opaque_value_consumer_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        del interface_refinement
        return (
            {
                "semantic_expression": {
                    "op": "reg",
                    "name": "esp",
                    "width": 32,
                },
                "width": 96,
                "access": "read_write",
            },
        )

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="consume_opaque_value",
            contract_field="opaque_value_consumer_contract",
            contract_filename="opaque-value-consumer-contract.json",
            contract_hash_binding="opaque_value_consumer_contract_sha256",
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
        event = object_value(contract["external_event"], "opaque-value consumer event")
        behavior = object_value(contract["behavior"], "opaque-value consumer behavior")
        abi = object_value(contract["abi"], "opaque-value consumer ABI")
        has_auxiliary = abi.get("auxiliary_register") == "edi"
        if abi.get("auxiliary_register") not in {None, "edi"}:
            raise StageAInputError("opaque-value consumer auxiliary binding is invalid")
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

typedef struct opaque_value4 {
  uint32_t words[4];
} opaque_value4;

typedef struct opaque_value_consumer_services {
  void *context;
  void (*consume)(void *context, opaque_value4 value, uint32_t auxiliary);
} opaque_value_consumer_services;

void consume_opaque_value(opaque_value_consumer_services *services,
                          opaque_value4 value, uint32_t auxiliary);

#endif
"""
        portable = """#include "implementation.h"

void consume_opaque_value(opaque_value_consumer_services *services,
                          opaque_value4 value, uint32_t auxiliary) {
  services->consume(services->context, value, auxiliary);
}
"""
        setup_lines = (
            [
                "  state->eax = value.words[0]; state->esi = 0U;",
                "  state->cf = 0U; state->of = 0U; state->pf = 1U; state->sf = 0U; state->zf = 1U;",
            ]
            if not has_auxiliary
            else [
                "  state->eax = value.words[0];",
                "  rt->write(rt->context, entry_esp + UINT32_C(16), 4U, auxiliary, &fault);",
            ]
        )
        control_constant = (
            "STAGE_B_JUMP"
            if behavior["control"] == "jump"
            else "STAGE_B_FALLTHROUGH"
        )
        local_declaration = (
            "  uint32_t auxiliary; opaque_value4 value;"
            if has_auxiliary
            else "  opaque_value4 value;"
        )
        auxiliary_read = ["  auxiliary = state->edi;"] if has_auxiliary else []
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            "typedef struct opaque_value_consumer_context {",
            "  stage_b_runtime *runtime;",
            "  stage_b_machine_state *state;",
            "  stage_b_call_status status;",
            "} opaque_value_consumer_context;",
            "",
            "static void consume_service(void *opaque, opaque_value4 value, uint32_t auxiliary) {",
            "  opaque_value_consumer_context *context = (opaque_value_consumer_context *)opaque;",
            "  (void)auxiliary;",
            "  stage_b_machine_state output = *context->state;",
            "  const stage_b_stack_input stack_inputs[] = { { 12U, 4U, value.words[3] } };",
            "  const stage_b_call_event event = {",
            f"    STAGE_B_CALL_EXTERNAL_IMPORT, UINT32_C(0x{int(event['call_rva']):08x}), 0U, 0U, UINT32_C(0x{int(event['return_rva']):08x}),",
            f'    "{event["dll"]}", "{event["symbol"]}", 0U, 0U, 0, 0U, stack_inputs, 1U',
            "  };",
            f"  context->state->original_rva = UINT32_C(0x{int(event['call_rva']) - 4:08x});",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status == STAGE_B_CALL_OK) *context->state = output;",
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  uint32_t fault = 0U, entry_esp;",
            local_declaration,
            "  opaque_value_consumer_context context;",
            "  opaque_value_consumer_services services;",
            "  if (rt == 0 || rt->read == 0 || rt->write == 0)",
            "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  entry_esp = state->esp;",
            "  value.words[0] = rt->read(rt->context, entry_esp + UINT32_C(80), 4U, &fault);",
            "  value.words[1] = rt->read(rt->context, entry_esp + UINT32_C(84), 4U, &fault);",
            "  value.words[2] = rt->read(rt->context, entry_esp + UINT32_C(88), 4U, &fault);",
            "  value.words[3] = rt->read(rt->context, entry_esp + UINT32_C(92), 4U, &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            *auxiliary_read,
            *setup_lines,
            "  rt->write(rt->context, entry_esp + UINT32_C(0), 4U, value.words[0], &fault);",
            "  state->eax = value.words[1];",
            "  rt->write(rt->context, entry_esp + UINT32_C(4), 4U, value.words[1], &fault);",
            "  state->eax = value.words[2];",
            "  rt->write(rt->context, entry_esp + UINT32_C(8), 4U, value.words[2], &fault);",
            "  state->eax = value.words[3];",
            "  rt->write(rt->context, entry_esp + UINT32_C(12), 4U, value.words[3], &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            *machine_eflags_sync_lines("  "),
            f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
            "  context = (opaque_value_consumer_context){ rt, state, STAGE_B_CALL_OK };",
            "  services = (opaque_value_consumer_services){ &context, consume_service };",
            f"  consume_opaque_value(&services, value, {'auxiliary' if has_auxiliary else '0U'});",
            "  if (context.status != STAGE_B_CALL_OK)",
            "    return (stage_b_step_result){ STAGE_B_EXTERNAL_FAULT, state->original_rva, 0U };",
            f"  return (stage_b_step_result){{ {control_constant}, UINT32_C(0x{int(behavior['continuation_rva']):08x}), 0U }};",
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
        _contract({"opaque_value_consumer_contract": prepared.contract})
        abi = object_value(prepared.contract["abi"], "opaque-value consumer ABI")
        has_auxiliary = abi.get("auxiliary_register") == "edi"
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        esp = 0x70001000
        probes = (
            ("zero", (0, 0, 0, 0)),
            ("small", (1, 2, 3, 4)),
            ("high", (0x80000000, 0x7FFFFFFF, 5, 6)),
            ("max", (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)),
            ("alternating", (0xAAAAAAAA, 0x55555555, 0xA5A5A5A5, 0x5A5A5A5A)),
            ("address-like", (0x401000, 0x40D058, 0x70002000, 0x71000000)),
            ("one-hot", (1, 0x100, 0x10000, 0x1000000)),
            ("descending", (4, 3, 2, 1)),
            ("mixed", (0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00)),
            ("boundary", (0x7FFFFFFF, 0x80000000, 0, 0xFFFFFFFF)),
        )
        rows = []
        for index, (label, words) in enumerate(probes):
            rows.append(
                {
                    "id": f"case:opaque-value-consumer-{label}",
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
                        {
                            "address": esp + 80,
                            "bytes": b"".join(
                                int(word).to_bytes(4, "little") for word in words
                            ).hex(),
                        }
                    ],
                    "external_responses": [{"eax": 0x81000000 + index}],
                    "external_response_seed": (
                        f"opaque-value-consumer-{'aux' if has_auxiliary else 'plain'}-{label}"
                    ),
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
typedef struct model {{ opaque_value4 observed; uint32_t auxiliary, calls; }} model;
static void consume(void *opaque, opaque_value4 value, uint32_t auxiliary) {{
  model *m = (model *)opaque; m->calls++; m->observed = value;
  m->auxiliary = auxiliary;
}}
int main(void) {{
  opaque_value4 value = {{ {{ nondet_u32(), nondet_u32(), nondet_u32(), nondet_u32() }} }};
  uint32_t auxiliary = nondet_u32();
  model m = {{ {{ {{ 0U, 0U, 0U, 0U }} }}, 0U, 0U }};
  opaque_value_consumer_services services = {{ &m, consume }};
  {symbol}(&services, value, auxiliary);
  __CPROVER_assert(m.calls == 1U, "one consumer call");
  __CPROVER_assert(m.observed.words[0] == value.words[0], "word zero");
  __CPROVER_assert(m.observed.words[1] == value.words[1], "word one");
  __CPROVER_assert(m.observed.words[2] == value.words[2], "word two");
  __CPROVER_assert(m.observed.words[3] == value.words[3], "word three");
  __CPROVER_assert(m.auxiliary == auxiliary, "auxiliary word");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {
            "complete_for_all_four_word_values_and_auxiliary_words": True,
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
                "complete_for_all_four_word_values_and_auxiliary_words"
            )
            is True
        )


PROFILE = OpaqueValueConsumerProfile()
