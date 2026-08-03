"""Lift a fixed PE word load or atomic exchange into portable C."""

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
    object_value,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import write_json


_FORMAT = "stage-b-static-atomic-word-contract-v1"


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
    if kind == "memory":
        return (
            "m",
            operand.get("base"),
            operand.get("index"),
            int(operand.get("scale", 1)),
            int(operand.get("displacement", 0)),
            int(operand.get("width_bits", 0)),
        )
    raise StageAInputError(f"unsupported static-word operand kind: {kind!r}")


def _shape(unit: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        (
            str(instruction.get("mnemonic")),
            tuple(
                _operand(operand)
                for operand in array_value(
                    instruction.get("operands"), "instruction operands"
                )
            ),
        )
        for instruction in array_value(unit.get("instructions"), "unit instructions")
    )


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("static atomic-word access has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    if len(context.units) != 1 or str(context.units[0].get("id")) not in member_ids:
        raise StageAInputError("static atomic-word access requires one exact machine unit")
    unit = context.units[0]
    if member_ids != [str(unit.get("id"))]:
        raise StageAInputError("static atomic-word membership is not exact")
    shape = _shape(unit)
    if (
        len(shape) == 2
        and shape[0][0] == "mov"
        and shape[0][1][0] == ("r", "eax", 32)
        and shape[0][1][1][:4] == ("m", None, None, 1)
        and shape[0][1][1][5] == 32
        and shape[1] == ("ret", ())
    ):
        operation = "load"
        slot_address = int(shape[0][1][1][4])
        portable_symbol = "load_invalid_parameter_handler"
    elif (
        len(shape) == 3
        and shape[0] == (
            "mov",
            (("r", "eax", 32), ("m", "esp", None, 1, 4, 32)),
        )
        and shape[1][0] == "xchg"
        and shape[1][1][0][:4] == ("m", None, None, 1)
        and shape[1][1][0][5] == 32
        and shape[1][1][1] == ("r", "eax", 32)
        and shape[2] == ("ret", ())
    ):
        operation = "exchange"
        slot_address = int(shape[1][1][0][4])
        portable_symbol = "exchange_invalid_parameter_handler"
    else:
        raise StageAInputError("static atomic-word machine lowering is unsupported")

    control = object_value(unit.get("control"), "static-word control")
    semantics = object_value(unit.get("semantics"), "static-word semantics")
    memory_events = array_value(semantics.get("memory_events"), "static-word events")
    if (
        control.get("kind") != "return"
        or control.get("direct_targets") != []
        or control.get("has_indirect_target") is not False
        or array_value(semantics.get("external_events"), "static-word calls")
        or object_value(
            semantics.get("instruction_effect_schedule"), "static-word schedule"
        ).get("status")
        != "complete"
    ):
        raise StageAInputError("static atomic-word control or semantics are incomplete")
    expected_events = 2 if operation == "load" else 4
    if len(memory_events) != expected_events:
        raise StageAInputError("static atomic-word memory event inventory is malformed")
    static_events = [
        event
        for event in memory_events
        if object_value(event.get("address"), "static-word event address")
        == {"op": "const", "value": slot_address, "width": 32}
    ]
    if operation == "load":
        expected_static_kinds = ["read"]
    else:
        expected_static_kinds = ["read", "write"]
    if [event.get("kind") for event in static_events] != expected_static_kinds or any(
        event.get("width") != 4 for event in static_events
    ):
        raise StageAInputError("static atomic-word effect is not bound to one word")

    source = object_value(unit.get("source"), "static-word source")
    semantic_export = object_value(
        source.get("semantic_export"), "static-word semantic export"
    )
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "static_atomic_word_v1",
        "component": {
            "id": str(context.component["id"]),
            "sha256": str(context.component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "unit": {
                "id": str(unit["id"]),
                "rva_start": _rva(unit),
                "rva_end": int(source["original"]["rva_end"]),
                "instruction_bytes_sha256": str(source["instruction_bytes_sha256"]),
                "semantic_transfer_sha256": str(
                    semantic_export["semantic_transfer_sha256"]
                ),
            },
        },
        "domain": {"kind": "total", "mapped_static_word": slot_address},
        "operation": operation,
        "slot_address": slot_address,
        "portable_symbol": portable_symbol,
        "abi": {
            "argument": None if operation == "load" else "stack[esp+4]",
            "result_register": "eax",
            "preserved_registers": ["ebx", "ecx", "edx", "esi", "edi", "ebp"],
            "preserved_flags": ["cf", "pf", "zf", "sf", "df", "of"],
            "stack_return_bytes": 4,
        },
        "behavior": {
            "load": "return the current slot word",
            "exchange": (
                None
                if operation == "load"
                else "atomically replace the slot word and return its prior value"
            ),
            "memory_order": "sequentially_consistent",
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("static_atomic_word_contract"), "static atomic-word contract"
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or contract.get("operation") not in {"load", "exchange"}
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("static atomic-word contract is stale")
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
        raise StageAInputError("static atomic-word adapter does not have one entry")
    return files, adapter, matches[0]


class StaticAtomicWordProfile:
    name = "static_atomic_word_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        logical = object_value(
            interface_refinement.get("logical_interface"), "logical interface"
        )
        objects = array_value(logical.get("objects"), "logical objects")
        static_objects = [
            object_value(value, "static logical object")
            for value in objects
            if isinstance(value, Mapping)
            and isinstance(value.get("base"), Mapping)
            and value["base"].get("op") == "const"
            and value["base"].get("width") == 32
        ]
        bases = {
            json.dumps(value["base"], sort_keys=True, separators=(",", ":"))
            for value in static_objects
        }
        if not static_objects or len(bases) != 1:
            raise StageAInputError("static atomic-word interface has no unique slot")
        slot = static_objects[0]
        permissions: set[str] = set()
        for static_object in static_objects:
            fields = array_value(
                static_object.get("fields"), "static logical object fields"
            )
            if len(fields) != 1 or fields[0].get("width") != 4:
                raise StageAInputError("static atomic-word logical slot is not one word")
            permissions.update(
                str(value)
                for value in array_value(fields[0].get("permissions"), "slot permissions")
            )
        return (
            {
                "semantic_expression": dict(slot["base"]),
                "width": 4,
                "access": "read_write" if "write" in permissions else "read",
            },
        )

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol=str(contract["portable_symbol"]),
            contract_field="static_atomic_word_contract",
            contract_filename="static-atomic-word-contract.json",
            contract_hash_binding="static_atomic_word_contract_sha256",
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
        operation = str(contract["operation"])
        slot = int(contract["slot_address"])
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

typedef struct static_word_services {
  void *context;
  uint32_t (*load_word)(void *context);
  uint32_t (*exchange_word)(void *context, uint32_t replacement);
} static_word_services;

uint32_t load_invalid_parameter_handler(static_word_services *services);
uint32_t exchange_invalid_parameter_handler(static_word_services *services,
                                            uint32_t replacement);

#endif
"""
        portable = (
            """#include "implementation.h"

uint32_t load_invalid_parameter_handler(static_word_services *services) {
  return services->load_word(services->context);
}
"""
            if operation == "load"
            else """#include "implementation.h"

uint32_t exchange_invalid_parameter_handler(static_word_services *services,
                                            uint32_t replacement) {
  return services->exchange_word(services->context, replacement);
}
"""
        )
        call = (
            "load_invalid_parameter_handler(&services)"
            if operation == "load"
            else "exchange_invalid_parameter_handler(&services, replacement)"
        )
        adapter = f'''#include "state-machine-runtime.h"
#include "implementation.h"

typedef struct static_word_context {{
  stage_b_runtime *runtime;
  uint32_t fault;
}} static_word_context;

static uint32_t load_word(void *opaque) {{
  static_word_context *context = (static_word_context *)opaque;
  return context->runtime->read(
      context->runtime->context, UINT32_C(0x{slot:08x}), UINT32_C(4),
      &context->fault);
}}

static uint32_t exchange_word(void *opaque, uint32_t replacement) {{
  static_word_context *context = (static_word_context *)opaque;
  uint32_t observed = 0U;
  stage_b_runtime_atomic_exchange(
      context->runtime, UINT32_C(0x{slot:08x}), UINT32_C(4), replacement,
      &observed, &context->fault);
  return observed;
}}

stage_b_step_result {adapter_symbol}(stage_b_runtime *rt,
                                     stage_b_machine_state *state) {{
  static_word_context context = {{ rt, 0U }};
  static_word_services services = {{ &context, load_word, exchange_word }};
  uint32_t return_target, result;{(' uint32_t replacement;' if operation == 'exchange' else '')}
  if (rt == 0 || rt->read == 0)
    return (stage_b_step_result){{ STAGE_B_MEMORY_FAULT, 0U, 0U }};
  state->original_rva = UINT32_C(0x{entry_rva:08x});
'''
        if operation == "exchange":
            adapter += """  replacement = rt->read(rt->context, state->esp + UINT32_C(4),
                         UINT32_C(4), &context.fault);
  if (context.fault)
    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };
"""
        adapter += f"  result = {call};\n"
        adapter += """  if (context.fault)
    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };
  return_target = rt->read(
      rt->context, state->esp, UINT32_C(4), &context.fault);
  if (context.fault)
    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };
  state->eax = result;
  state->esp += UINT32_C(4);
  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };
}
"""
        (root / str(files["portable_header"])).write_text(header, encoding="ascii")
        (root / str(files["portable_source"])).write_text(portable, encoding="ascii")
        adapter_path.write_text(adapter, encoding="ascii")

    def install_cases(
        self,
        *,
        root: Path,
        backend_workspace: Mapping[str, Any],
        cluster: Mapping[str, Any],
        prepared: PreparedComponentProfile,
    ) -> None:
        contract = prepared.contract
        operation = str(contract["operation"])
        slot = int(contract["slot_address"])
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        values = [
            0,
            1,
            0xFFFFFFFF,
            0x80000000,
            0x7FFFFFFF,
            0x00401000,
            0x12345678,
            0xA5A5A5A5,
            0x01020304,
            0xDEADBEEF,
        ]
        rows = []
        for index, initial in enumerate(values):
            esp = 0x70001000 + index * 0x20
            replacement = values[-1 - index]
            memory = [
                {"address": esp, "bytes": (0x12347000 + index).to_bytes(4, "little").hex()},
                {"address": slot, "bytes": initial.to_bytes(4, "little").hex()},
            ]
            if operation == "exchange":
                memory.append(
                    {
                        "address": esp + 4,
                        "bytes": replacement.to_bytes(4, "little").hex(),
                    }
                )
            rows.append(
                {
                    "id": f"case:static-atomic-word-{operation}-{index:02d}",
                    "registers": {
                        "eax": 0x81000000 + index,
                        "ebx": 0x82000000 + index,
                        "ecx": 0x83000000 + index,
                        "edx": 0x84000000 + index,
                        "esi": 0x85000000 + index,
                        "edi": 0x86000000 + index,
                        "ebp": 0x87000000 + index,
                        "esp": esp,
                    },
                    "flags": {
                        "cf": index & 1,
                        "pf": (index >> 1) & 1,
                        "zf": (index >> 2) & 1,
                        "sf": (index >> 3) & 1,
                        "df": (index + 1) & 1,
                        "of": (index >> 1) & 1,
                    },
                    "memory": memory,
                    "external_response_seed": f"static-atomic-word-{operation}-{index}",
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
        if not symbol:
            raise StageAInputError("static atomic-word refinement omits its symbol")
        operation = str(contract["operation"])
        invocation = (
            f"uint32_t result = {symbol}(&services);"
            if operation == "load"
            else f"uint32_t result = {symbol}(&services, replacement);"
        )
        operation_assertions = (
            '__CPROVER_assert(model.loads == 1U && model.exchanges == 0U, "one load");\n'
            '  __CPROVER_assert(model.word == initial, "load preserves slot");'
            if operation == "load"
            else '__CPROVER_assert(model.loads == 0U && model.exchanges == 1U, "one exchange");\n'
            '  __CPROVER_assert(model.word == replacement, "exchange stores replacement");'
        )
        return f'''#include "implementation.h"
#include <stdint.h>

extern uint32_t nondet_u32(void);

typedef struct word_model {{
  uint32_t word, loads, exchanges;
}} word_model;

static uint32_t load_word(void *opaque) {{
  word_model *model = (word_model *)opaque;
  ++model->loads;
  return model->word;
}}

static uint32_t exchange_word(void *opaque, uint32_t replacement) {{
  word_model *model = (word_model *)opaque;
  uint32_t prior = model->word;
  ++model->exchanges;
  model->word = replacement;
  return prior;
}}

int main(void) {{
  uint32_t initial = nondet_u32(), replacement = nondet_u32();
  word_model model = {{ initial, 0U, 0U }};
  static_word_services services = {{ &model, load_word, exchange_word }};
  {invocation}
  __CPROVER_assert(result == initial, "returns prior slot value");
  {operation_assertions}
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        contract = _contract(refinement)
        return {
            "complete_for_all_32_bit_slot_and_argument_values": True,
            "operation": contract["operation"],
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
            and evidence_scope.get("complete_for_all_32_bit_slot_and_argument_values")
            is True
            and evidence_scope.get("operation") in {"load", "exchange"}
        )


PROFILE = StaticAtomicWordProfile()
