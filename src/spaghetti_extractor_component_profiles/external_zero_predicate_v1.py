"""Portable wrapper for a three-argument imported result-zero predicate."""

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


_FORMAT = "stage-b-external-zero-predicate-contract-v1"


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()


def _rva(unit: Mapping[str, Any]) -> int:
    return int(object_value(unit.get("source"), "unit source")["original"]["rva_start"])


def _operand(value: Any) -> tuple[Any, ...]:
    operand = object_value(value, "instruction operand")
    kind = operand.get("kind")
    if kind == "register":
        return ("reg", str(operand.get("name")), int(operand.get("width_bits", 0)))
    if kind == "immediate":
        return (
            "imm",
            int(operand.get("value", 0)),
            int(operand.get("width_bits", 0)),
        )
    if kind == "memory":
        return (
            "mem",
            operand.get("base"),
            operand.get("index"),
            int(operand.get("scale", 1)),
            int(operand.get("displacement", 0)),
            int(operand.get("width_bits", 0)),
        )
    raise StageAInputError(f"unsupported imported predicate operand kind: {kind!r}")


def _shape(unit: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        (
            str(instruction.get("mnemonic")),
            tuple(_operand(operand) for operand in array_value(instruction.get("operands"), "instruction operands")),
        )
        for instruction in array_value(unit.get("instructions"), "unit instructions")
    )


def _reg(name: str, width: int = 32) -> tuple[Any, ...]:
    return ("reg", name, width)


def _imm(value: int, width: int = 32) -> tuple[Any, ...]:
    return ("imm", value, width)


def _mem(base: str, displacement: int, width: int = 32) -> tuple[Any, ...]:
    return ("mem", base, None, 1, displacement, width)


def _require_control(unit: Mapping[str, Any], kind: str, targets: Sequence[int]) -> None:
    control = object_value(unit.get("control"), "unit control")
    if control.get("kind") != kind or set(control.get("direct_targets", [])) != set(targets):
        raise StageAInputError(
            f"imported predicate control mismatch at RVA 0x{_rva(unit):x}"
        )


def _expression_is_stack_load(value: Any, offset: int) -> bool:
    expression = object_value(value, "external argument expression")
    if expression.get("op") != "load" or expression.get("width") != 4:
        return False
    address = object_value(expression.get("address"), "external argument address")
    if offset == 0:
        return address == {"name": "esp", "op": "reg", "width": 32}
    if address.get("op") != "add32":
        return False
    args = array_value(address.get("args"), "external argument address operands")
    return len(args) == 2 and {
        json.dumps(arg, sort_keys=True, separators=(",", ":")) for arg in args
    } == {
        json.dumps({"op": "const", "value": offset, "width": 32}, sort_keys=True, separators=(",", ":")),
        json.dumps({"name": "esp", "op": "reg", "width": 32}, sort_keys=True, separators=(",", ":")),
    }


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    member_ids = [str(value) for value in context.component["membership"]["resolved_unit_ids"]]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("imported predicate units do not match exact component membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 3:
        raise StageAInputError("imported predicate profile requires exactly three units")

    first_shape = _shape(ordered[0])
    if len(first_shape) != 4 or first_shape[0][0] != "sub":
        raise StageAInputError("imported predicate has no canonical stack-frame prologue")
    first_sub = first_shape[0][1]
    if len(first_sub) != 2 or first_sub[0] != _reg("esp") or first_sub[1][0] != "imm":
        raise StageAInputError("imported predicate stack adjustment is malformed")
    frame_bytes = int(first_sub[1][1])
    if frame_bytes < 12 or frame_bytes % 4 != 0:
        raise StageAInputError("imported predicate stack frame must be word aligned")
    if first_shape != (
        ("sub", (_reg("esp"), _imm(frame_bytes))),
        ("mov", (_reg("eax"), _mem("esp", frame_bytes + 12))),
        ("mov", (_mem("esp", 8), _reg("eax"))),
        ("mov", (_reg("eax"), _mem("esp", frame_bytes + 8))),
    ):
        raise StageAInputError("imported predicate first unit is not the reviewed wrapper shape")

    second_shape = _shape(ordered[1])
    expected_prefix = (
        ("mov", (_mem("esp", 4), _reg("eax"))),
        ("mov", (_reg("eax"), _mem("esp", frame_bytes + 4))),
        ("mov", (_mem("esp", 0), _reg("eax"))),
    )
    if (
        len(second_shape) != 4
        or second_shape[:3] != expected_prefix
        or second_shape[3][0] != "call"
        or len(second_shape[3][1]) != 1
        or second_shape[3][1][0][0] != "imm"
    ):
        raise StageAInputError("imported predicate call unit is not the reviewed wrapper shape")
    if _shape(ordered[2]) != (
        ("test", (_reg("eax"), _reg("eax"))),
        ("sete", (_reg("al", 8),)),
        ("add", (_reg("esp"), _imm(frame_bytes))),
        ("ret", ()),
    ):
        raise StageAInputError("imported predicate epilogue is not a result-zero predicate")

    starts = [_rva(unit) for unit in ordered]
    _require_control(ordered[0], "fallthrough", [starts[1]])
    _require_control(ordered[1], "fallthrough", [starts[2]])
    _require_control(ordered[2], "return", [])
    events = [
        event
        for unit in ordered
        for event in array_value(
            object_value(unit.get("semantics"), "unit semantics").get("external_events"),
            "unit external events",
        )
    ]
    if len(events) != 1:
        raise StageAInputError("imported predicate must contain one external event")
    event = object_value(events[0], "imported predicate external event")
    abi = object_value(event.get("abi_contract"), "imported predicate ABI contract")
    arguments = array_value(event.get("arguments"), "imported predicate arguments")
    if (
        event.get("kind") != "external_call"
        or not isinstance(event.get("dll"), str)
        or not event.get("dll")
        or not isinstance(event.get("symbol"), str)
        or not event.get("symbol")
        or event.get("ordinal") is not None
        or len(arguments) != 3
        or not all(_expression_is_stack_load(value, index * 4) for index, value in enumerate(arguments))
        or abi.get("argument_words") != 3
        or abi.get("disposition") != "returns"
        or abi.get("template") != "pe32-cdecl-v1"
        or abi.get("result_register_relations")
        != [{"register": "eax", "relation": "exact"}]
    ):
        raise StageAInputError("imported predicate external event is outside the exact cdecl profile")
    call_instruction = array_value(ordered[1].get("instructions"), "call-unit instructions")[-1]
    call_rva = int(call_instruction["rva_start"])
    return_rva = int(event.get("return_rva", -1))
    if return_rva != starts[2]:
        raise StageAInputError("imported predicate external return target is inconsistent")

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
    event_identity = {
        "kind": "external_call",
        "dll": str(event["dll"]),
        "symbol": str(event["symbol"]),
        "ordinal": None,
        "call_rva": call_rva,
        "return_rva": return_rva,
        "argument_count": 3,
        "abi_contract_sha256": _canonical_sha256(abi),
        "event_sha256": _canonical_sha256(event),
    }
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "external_zero_predicate_v1",
        "component": {
            "id": str(context.component["id"]),
            "sha256": str(context.component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "units": bindings,
            "external_event": event_identity,
        },
        "domain": {"kind": "total", "external_result": "arbitrary 32-bit value"},
        "semantics": {
            "service_calls": 1,
            "arguments": ["left", "right", "length"],
            "result": "one exactly when external EAX is zero, otherwise zero",
        },
        "machine_projection": {
            "eax": "external_eax_with_low_byte_replaced_by_zero_predicate",
            "esp_delta": 4,
            "other_registers": "external_call_response",
            "flags": "frame-destroying add result except DF from external response",
        },
        "stack_frame_bytes": frame_bytes,
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("external_zero_predicate_contract"),
        "external zero-predicate contract",
    )
    expected = contract.get("contract_sha256")
    core = dict(contract)
    core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("external zero-predicate contract is stale or malformed")
    return contract


def _adapter_parts(*, root: Path, backend_workspace: Mapping[str, Any]) -> tuple[Mapping[str, Any], Path, str]:
    files = object_value(backend_workspace.get("files"), "backend workspace files")
    adapter_path = root / str(files["machine_adapter_source"])
    matches = re.findall(
        r"stage_b_step_result\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        adapter_path.read_text(encoding="ascii"),
    )
    if len(matches) != 1:
        raise StageAInputError(f"component machine adapter has {len(matches)} replacement symbols")
    return files, adapter_path, matches[0]


def _c_string(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise StageAInputError(f"{description} is not a usable C string")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as error:
        raise StageAInputError(f"{description} must be ASCII") from error
    return json.dumps(value, ensure_ascii=True)


class ExternalZeroPredicateProfile:
    name = "external_zero_predicate_v1"

    def observable_memory(self, interface_refinement: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        del interface_refinement
        return ()

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        if context.component_dependencies:
            raise StageAInputError("external zero-predicate profile has no component dependencies")
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="memory_regions_equal",
            contract_field="external_zero_predicate_contract",
            contract_filename="external-zero-predicate-contract.json",
            contract_hash_binding="external_zero_predicate_contract_sha256",
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
        frame_bytes = int(contract["stack_frame_bytes"])
        event = object_value(contract["bindings"]["external_event"], "external event binding")
        dll = _c_string(event.get("dll"), "external DLL")
        symbol = _c_string(event.get("symbol"), "external symbol")
        call_rva = int(event["call_rva"])
        return_rva = int(event["return_rva"])
        files, adapter_path, adapter_symbol = _adapter_parts(root=root, backend_workspace=backend_workspace)
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

typedef struct reconstructed_compare_service {
  void *context;
  int32_t (*compare)(void *context, const uint8_t *left,
                     const uint8_t *right, uint32_t length);
} reconstructed_compare_service;

int memory_regions_equal(reconstructed_compare_service *service,
                         const uint8_t *left, const uint8_t *right,
                         uint32_t length);

#endif
"""
        portable = """#include "implementation.h"

int memory_regions_equal(reconstructed_compare_service *service,
                         const uint8_t *left, const uint8_t *right,
                         uint32_t length) {
  return service->compare(service->context, left, right, length) == 0;
}
"""
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            '',
            'typedef struct machine_compare_context {',
            '  stage_b_runtime *runtime;',
            '  stage_b_machine_state *state;',
            '  stage_b_call_status status;',
            '} machine_compare_context;',
            '',
            'static uint32_t byte_parity(uint32_t value) {',
            '  value ^= value >> 4;',
            '  value &= UINT32_C(0x0f);',
            '  return (UINT32_C(0x9669) >> value) & UINT32_C(1);',
            '}',
            '',
            'static int32_t invoke_compare(void *opaque, const uint8_t *left,',
            '                              const uint8_t *right, uint32_t length) {',
            '  machine_compare_context *context = (machine_compare_context *)opaque;',
            '  stage_b_machine_state output = *context->state;',
            '  const uint32_t arguments[] = {',
            '    (uint32_t)(uintptr_t)left, (uint32_t)(uintptr_t)right, length',
            '  };',
            '  const stage_b_stack_input stack_inputs[] = {',
            '    { 0U, 4U, (uint32_t)(uintptr_t)left },',
            '    { 4U, 4U, (uint32_t)(uintptr_t)right }',
            '  };',
            '  const stage_b_call_event event = {',
            f'    STAGE_B_CALL_EXTERNAL_IMPORT, UINT32_C(0x{call_rva:08x}), 0U, 0U,',
            f'    UINT32_C(0x{return_rva:08x}), {dll}, {symbol}, 0U, 0U,',
            '    arguments, 3U, stack_inputs, 2U',
            '  };',
            '  context->status = stage_b_invoke_call(',
            '      context->runtime, &event, context->state, &output);',
            '  if (context->status == STAGE_B_CALL_OK)',
            '    *context->state = output;',
            '  return (int32_t)output.eax;',
            '}',
            '',
            f'stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{',
            '  uint32_t fault = 0U, entry_esp, frame_esp, left, right, length;',
            '  uint32_t raw_result, predicate, add_result, return_target;',
            '  machine_compare_context context = { rt, state, STAGE_B_CALL_UNIMPLEMENTED };',
            '  reconstructed_compare_service service = { &context, invoke_compare };',
            '  if (rt == 0 || rt->read == 0 || rt->write == 0)',
            '    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
            '  entry_esp = state->esp;',
            '  left = rt->read(rt->context, entry_esp + UINT32_C(4), UINT32_C(4), &fault);',
            '  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
            '  right = rt->read(rt->context, entry_esp + UINT32_C(8), UINT32_C(4), &fault);',
            '  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
            '  length = rt->read(rt->context, entry_esp + UINT32_C(12), UINT32_C(4), &fault);',
            '  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
            f'  frame_esp = entry_esp - UINT32_C({frame_bytes});',
            '  state->esp = frame_esp;',
            f'  state->cf = entry_esp < UINT32_C({frame_bytes});',
            f'  state->of = (((entry_esp ^ UINT32_C({frame_bytes})) &',
            '                (entry_esp ^ frame_esp)) >> 31) & UINT32_C(1);',
            '  state->pf = byte_parity(frame_esp);',
            '  state->sf = frame_esp >> 31;',
            '  state->zf = frame_esp == 0U;',
            f'  state->original_rva = UINT32_C(0x{entry_rva:08x});',
            '  state->eax = right;',
            '  rt->write(rt->context, frame_esp + UINT32_C(8), UINT32_C(4), length, &fault);',
            '  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
            '  rt->write(rt->context, frame_esp + UINT32_C(4), UINT32_C(4), right, &fault);',
            '  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
            '  state->eax = left;',
            '  rt->write(rt->context, frame_esp, UINT32_C(4), left, &fault);',
            '  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
            '  predicate = (uint32_t)memory_regions_equal(',
            '      &service, (const uint8_t *)(uintptr_t)left,',
            '      (const uint8_t *)(uintptr_t)right, length);',
            '  if (context.status != STAGE_B_CALL_OK) {',
            '    stage_b_control_kind kind = context.status == STAGE_B_CALL_MEMORY_FAULT',
            '        ? STAGE_B_MEMORY_FAULT : STAGE_B_EXTERNAL_FAULT;',
            '    return (stage_b_step_result){ kind, state->original_rva, 0U };',
            '  }',
            '  raw_result = state->eax;',
            '  state->eax = (raw_result & UINT32_C(0xffffff00)) | (predicate & UINT32_C(0xff));',
            '  add_result = state->esp + UINT32_C(' + str(frame_bytes) + ');',
            '  state->cf = add_result < state->esp;',
            '  state->of = (((~(state->esp ^ UINT32_C(' + str(frame_bytes) + '))) &',
            '                (state->esp ^ add_result)) >> 31) & UINT32_C(1);',
            '  state->pf = byte_parity(add_result);',
            '  state->sf = add_result >> 31;',
            '  state->zf = add_result == 0U;',
            '  state->esp = add_result;',
            '  return_target = rt->read(rt->context, state->esp, UINT32_C(4), &fault);',
            '  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
            '  state->esp += UINT32_C(4);',
            *machine_eflags_sync_lines('  '),
            '  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };',
            '}',
            '',
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
        del prepared
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        esp = 0x70001000
        left = 0x70002000
        right = 0x70003000
        probes = [
            ("zero-length", b"", b"", 0),
            ("equal-one", b"a", b"a", 1),
            ("different-one", b"a", b"b", 1),
            ("equal-four", b"abcd", b"abcd", 4),
            ("different-four", b"abca", b"abcz", 4),
            ("embedded-zero", b"a\x00bc", b"a\x00bc", 4),
            ("high-bytes", b"\x80\xff\x01\x7f", b"\x80\xff\x01\x7f", 4),
            ("high-different", b"\xff\x00", b"\x7f\x00", 2),
            ("equal-eight", b"abcdefgh", b"abcdefgh", 8),
            ("different-eight", b"abcdefgx", b"abcdefgy", 8),
            ("same-address", b"01234567", None, 8),
            ("prefix-one", b"abcdefgh", b"azzzzzzz", 1),
            ("prefix-two", b"abcdefgh", b"abzzzzzz", 2),
            ("all-zero", b"\x00" * 16, b"\x00" * 16, 16),
            ("late-difference", b"a" * 15 + b"b", b"a" * 15 + b"c", 16),
            ("equal-sixteen", bytes(range(16)), bytes(range(16)), 16),
        ]
        rows = []
        for index, (label, left_bytes, right_bytes, length) in enumerate(probes):
            right_address = left if right_bytes is None else right
            memory = [
                {"address": esp, "bytes": "78563412"},
                {"address": esp + 4, "bytes": left.to_bytes(4, "little").hex()},
                {"address": esp + 8, "bytes": right_address.to_bytes(4, "little").hex()},
                {"address": esp + 12, "bytes": length.to_bytes(4, "little").hex()},
            ]
            if left_bytes:
                memory.append({"address": left, "bytes": left_bytes.hex()})
            if right_bytes:
                memory.append({"address": right, "bytes": right_bytes.hex()})
            rows.append(
                {
                    "id": f"case:external-zero-predicate-{label}",
                    "registers": {
                        "eax": 0x10203040 + index,
                        "ebx": 0x11223344,
                        "ecx": 0x55667788,
                        "edx": 0x89ABCDEF,
                        "esi": 0x12345678,
                        "edi": 0x87654321,
                        "ebp": 0x70004000,
                        "esp": esp,
                    },
                    "flags": {
                        "cf": index & 1,
                        "zf": (index >> 1) & 1,
                        "sf": (index >> 2) & 1,
                        "of": (index >> 3) & 1,
                        "pf": (index >> 4) & 1,
                        "df": (index >> 5) & 1,
                    },
                    "memory": memory,
                    "external_response_seed": f"external-zero-predicate-{label}",
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
        if not symbol:
            raise StageAInputError("component refinement omits its portable symbol")
        _contract(refinement)
        return f'''#include "implementation.h"
#include <stdint.h>

extern int32_t nondet_i32(void);

typedef struct observation {{
  const uint8_t *left;
  const uint8_t *right;
  uint32_t length;
  uint32_t calls;
  int32_t result;
}} observation;

static int32_t compare(void *opaque, const uint8_t *left,
                       const uint8_t *right, uint32_t length) {{
  observation *seen = (observation *)opaque;
  seen->left = left;
  seen->right = right;
  seen->length = length;
  seen->calls += 1U;
  return seen->result;
}}

int main(void) {{
  uint8_t left[1], right[1];
  observation seen = {{ 0, 0, 0U, 0U, nondet_i32() }};
  reconstructed_compare_service service = {{ &seen, compare }};
  int actual = {symbol}(&service, left, right, UINT32_C(0x89abcdef));
  __CPROVER_assert(seen.calls == 1U, "service called exactly once");
  __CPROVER_assert(seen.left == left && seen.right == right,
                   "pointer arguments preserved");
  __CPROVER_assert(seen.length == UINT32_C(0x89abcdef),
                   "length argument preserved");
  __CPROVER_assert(actual == (seen.result == 0), "zero-result predicate");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {"complete_for_all_32_bit_service_results": True, "loops": 0}

    def activation_scope_matches(
        self,
        *,
        activation_domain: Mapping[str, Any],
        evidence_scope: Mapping[str, Any],
    ) -> bool:
        return (
            activation_domain.get("kind") == "total"
            and evidence_scope.get("complete_for_all_32_bit_service_results") is True
        )


PROFILE = ExternalZeroPredicateProfile()
