"""Portable option-token matching over a mutable guest-memory cursor."""

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


_FORMAT = "stage-b-mutable-token-cursor-match-contract-v1"


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
    raise StageAInputError(f"unsupported token-cursor operand kind: {kind!r}")


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


def _m(base: str | None, displacement: int, width: int = 32) -> tuple[Any, ...]:
    return ("m", base, None, 1, displacement, width)


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("token-cursor units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 14:
        raise StageAInputError("token-cursor match requires fourteen machine units")
    starts = [_rva(unit) for unit in ordered]
    frame_bytes = 24
    expected_shapes = {
        0: (
            ("push", (_r("ebx"),)),
            ("mov", (_r("ebx"), _r("eax"))),
            ("sub", (_r("esp"), _i(frame_bytes))),
            ("mov", (_r("eax"), _m("esp", frame_bytes + 8))),
        ),
        1: (("test", (_r("eax"), _r("eax"))), ("je", (_i(0, 0),))),
        2: (
            ("xor", (_r("eax"), _r("eax"))),
            ("test", (_r("dl", 8), _r("dl", 8))),
            ("je", (_i(0, 0),)),
        ),
        3: (
            ("mov", (_r("ecx"), _m("ebx", 0))),
            ("cmp", (_m("ecx", 0, 8), _r("dl", 8))),
            ("je", (_i(0, 0),)),
        ),
        4: (
            ("add", (_r("esp"), _i(frame_bytes))),
            ("pop", (_r("ebx"),)),
            ("xor", (_r("edx"), _r("edx"))),
            ("xor", (_r("ecx"), _r("ecx"))),
        ),
        5: (("ret", ()),),
        7: (("test", (_r("eax"), _r("eax"))), ("je", (_i(0, 0),))),
        8: (
            ("add", (_r("esp"), _i(frame_bytes))),
            ("xor", (_r("eax"), _r("eax"))),
            ("pop", (_r("ebx"),)),
            ("xor", (_r("edx"), _r("edx"))),
        ),
        9: (("xor", (_r("ecx"), _r("ecx"))), ("ret", ())),
        10: (
            ("lea", (_r("eax"), _m("ecx", 1))),
            ("mov", (_m("ebx", 0), _r("eax"))),
            ("cmp", (_m("ecx", 1, 8), _i(0, 8))),
            ("jne", (_i(0, 0),)),
        ),
        11: (("mov", (_m("ebx", 0), _i(0))),),
        12: (
            ("add", (_r("esp"), _i(frame_bytes))),
            ("mov", (_r("eax"), _i(1))),
            ("pop", (_r("ebx"),)),
            ("xor", (_r("edx"), _r("edx"))),
        ),
        13: (("xor", (_r("ecx"), _r("ecx"))), ("ret", ())),
    }
    for index, expected in expected_shapes.items():
        observed = _shape(ordered[index])
        if any(
            expected_instruction[0] in {"je", "jne"}
            and observed_instruction[0] == expected_instruction[0]
            and len(observed_instruction[1]) == 1
            for expected_instruction, observed_instruction in zip(
                expected, observed, strict=False
            )
        ):
            normalized = tuple(
                (mnemonic, ((_i(0, 0),) if mnemonic in {"je", "jne"} else operands))
                for mnemonic, operands in observed
            )
        else:
            normalized = observed
        if normalized != expected:
            raise StageAInputError(
                f"token-cursor unit {index} has an unexpected instruction shape"
            )
    call_shape = _shape(ordered[6])
    if (
        len(call_shape) != 4
        or call_shape[0] != ("mov", (_m("esp", 4), _r("ecx")))
        or call_shape[1] != ("mov", (_r("eax"), _m("ebx", 0)))
        or call_shape[2] != ("mov", (_m("esp", 0), _r("eax")))
        or call_shape[3][0] != "call"
        or len(call_shape[3][1]) != 1
    ):
        raise StageAInputError("token-cursor comparison call is malformed")

    controls = [
        ("fallthrough", [starts[1]]),
        ("branch", [starts[2], starts[6]]),
        ("branch", [starts[3], starts[4]]),
        ("branch", [starts[4], starts[10]]),
        ("fallthrough", [starts[5]]),
        ("return", []),
        ("fallthrough", [starts[7]]),
        ("branch", [starts[8], starts[11]]),
        ("fallthrough", [starts[9]]),
        ("return", []),
        ("branch", [starts[11], starts[12]]),
        ("fallthrough", [starts[12]]),
        ("fallthrough", [starts[13]]),
        ("return", []),
    ]
    for unit, (kind, targets) in zip(ordered, controls, strict=True):
        control = object_value(unit.get("control"), "token-cursor control")
        if control.get("kind") != kind or set(control.get("direct_targets", [])) != set(
            targets
        ):
            raise StageAInputError(
                f"token-cursor CFG mismatch at RVA 0x{_rva(unit):x}"
            )

    events = array_value(
        object_value(ordered[6].get("semantics"), "comparison semantics").get(
            "external_events"
        ),
        "comparison events",
    )
    if len(events) != 1:
        raise StageAInputError("token-cursor comparison must emit one external event")
    event = object_value(events[0], "comparison event")
    stack_inputs = array_value(event.get("stack_inputs"), "comparison stack inputs")
    if (
        event.get("kind") != "external_call"
        or event.get("dll") != "msvcrt.dll"
        or event.get("symbol") != "strcmp"
        or event.get("return_rva") != starts[7]
        or [item.get("offset") for item in stack_inputs] != [0, 4]
        or any(item.get("width") != 4 for item in stack_inputs)
    ):
        raise StageAInputError("token-cursor comparison event is outside the profile")

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
        "profile": "mutable_token_cursor_match_v1",
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
            "requires": "declared readable memory, writable cursor slot, and comparison service",
        },
        "abi": {
            "cursor_slot_register": "eax",
            "short_name_register": "dl",
            "long_name_register": "ecx",
            "short_mode_stack_offset": 4,
            "frame_bytes": frame_bytes,
        },
        "comparison_event": {
            "dll": str(event["dll"]),
            "symbol": str(event["symbol"]),
            "call_rva": int(ordered[6]["instructions"][-1]["rva_start"]),
            "return_rva": starts[7],
        },
        "behavior": {
            "matched_result": 1,
            "unmatched_result": 0,
            "short_mode": "consume one matching byte and clear a terminal cursor",
            "long_mode": "clear the cursor when the comparison service returns zero",
        },
        "machine_projection": {
            "eax": "match_result",
            "ebx": "preserved",
            "ecx": 0,
            "edx": 0,
            "esp_delta": 4,
            "flags": {"cf": 0, "of": 0, "pf": 1, "sf": 0, "zf": 1},
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("mutable_token_cursor_match_contract"),
        "mutable token-cursor contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("mutable token-cursor contract is stale or malformed")
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
        raise StageAInputError("token-cursor adapter does not have one entry")
    return files, adapter, matches[0]


class MutableTokenCursorMatchProfile:
    name = "mutable_token_cursor_match_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        del interface_refinement
        return (
            {
                "semantic_expression": {
                    "op": "reg",
                    "name": "eax",
                    "width": 32,
                },
                "width": 4,
                "access": "read_write",
            },
            {
                "semantic_expression": {
                    "op": "sub32",
                    "args": [
                        {"op": "reg", "name": "esp", "width": 32},
                        {"op": "const", "value": 28, "width": 32},
                    ],
                },
                "width": 28,
                "access": "read_write",
            },
        )

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="match_token_cursor",
            contract_field="mutable_token_cursor_match_contract",
            contract_filename="mutable-token-cursor-match-contract.json",
            contract_hash_binding="mutable_token_cursor_match_contract_sha256",
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
        event = object_value(contract["comparison_event"], "comparison event")
        frame_bytes = int(contract["abi"]["frame_bytes"])
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

typedef struct token_cursor_services {
  void *context;
  uint32_t (*load_word)(void *context, uint32_t address);
  void (*store_word)(void *context, uint32_t address, uint32_t value);
  uint8_t (*load_byte)(void *context, uint32_t address);
  int32_t (*compare_strings)(void *context, uint32_t left, uint32_t right);
} token_cursor_services;

int match_token_cursor(token_cursor_services *services, uint32_t cursor_slot,
                       uint8_t short_name, uint32_t long_name,
                       uint32_t short_mode);

#endif
"""
        portable = """#include "implementation.h"

int match_token_cursor(token_cursor_services *services, uint32_t cursor_slot,
                       uint8_t short_name, uint32_t long_name,
                       uint32_t short_mode) {
  uint32_t cursor;
  uint32_t next;
  if (short_mode != 0U) {
    if (short_name == 0U)
      return 0;
    cursor = services->load_word(services->context, cursor_slot);
    if (services->load_byte(services->context, cursor) != short_name)
      return 0;
    next = cursor + UINT32_C(1);
    services->store_word(services->context, cursor_slot, next);
    if (services->load_byte(services->context, next) == 0U)
      services->store_word(services->context, cursor_slot, UINT32_C(0));
    return 1;
  }
  cursor = services->load_word(services->context, cursor_slot);
  if (services->compare_strings(services->context, cursor, long_name) != 0)
    return 0;
  services->store_word(services->context, cursor_slot, UINT32_C(0));
  return 1;
}
"""
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            "typedef struct token_cursor_context {",
            "  stage_b_runtime *runtime;",
            "  stage_b_machine_state *state;",
            "  stage_b_call_status status;",
            "  uint32_t memory_fault;",
            "  uint32_t frame_esp;",
            "} token_cursor_context;",
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
            "static uint32_t load_word(void *opaque, uint32_t address) {",
            "  token_cursor_context *context = (token_cursor_context *)opaque;",
            "  uint32_t fault = 0U;",
            "  uint32_t value = context->runtime->read(context->runtime->context, address, 4U, &fault);",
            "  if (fault) context->memory_fault = 1U;",
            "  return value;",
            "}",
            "",
            "static void store_word(void *opaque, uint32_t address, uint32_t value) {",
            "  token_cursor_context *context = (token_cursor_context *)opaque;",
            "  uint32_t fault = 0U;",
            "  context->runtime->write(context->runtime->context, address, 4U, value, &fault);",
            "  if (fault) context->memory_fault = 1U;",
            "}",
            "",
            "static uint8_t load_byte(void *opaque, uint32_t address) {",
            "  token_cursor_context *context = (token_cursor_context *)opaque;",
            "  uint32_t fault = 0U;",
            "  uint32_t value = context->runtime->read(context->runtime->context, address, 1U, &fault);",
            "  if (fault) context->memory_fault = 1U;",
            "  return (uint8_t)value;",
            "}",
            "",
            "static int32_t compare_strings(void *opaque, uint32_t left, uint32_t right) {",
            "  token_cursor_context *context = (token_cursor_context *)opaque;",
            "  stage_b_machine_state output = *context->state;",
            "  uint32_t fault = 0U;",
            "  const stage_b_stack_input stack_inputs[] = { { 0U, 4U, left }, { 4U, 4U, right } };",
            "  const stage_b_call_event event = {",
            f"    STAGE_B_CALL_EXTERNAL_IMPORT, UINT32_C(0x{int(event['call_rva']):08x}), 0U, 0U, UINT32_C(0x{int(event['return_rva']):08x}),",
            f'    "{event["dll"]}", "{event["symbol"]}", 0U, 0U, 0, 0U, stack_inputs, 2U',
            "  };",
            "  context->runtime->write(context->runtime->context, context->frame_esp + UINT32_C(4), 4U, right, &fault);",
            "  context->runtime->write(context->runtime->context, context->frame_esp, 4U, left, &fault);",
            "  if (fault) { context->memory_fault = 1U; return 0; }",
            "  context->state->eax = left;",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status == STAGE_B_CALL_OK) *context->state = output;",
            "  return (int32_t)output.eax;",
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  uint32_t fault = 0U, entry_esp, pushed_esp, frame_esp, return_target;",
            "  uint32_t cursor_slot, long_name, short_mode, result;",
            "  uint8_t short_name;",
            "  token_cursor_context context; token_cursor_services services;",
            "  if (rt == 0 || rt->read == 0 || rt->write == 0) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  entry_esp = state->esp; pushed_esp = entry_esp - UINT32_C(4);",
            f"  frame_esp = pushed_esp - UINT32_C({frame_bytes});",
            "  cursor_slot = state->eax; short_name = (uint8_t)state->edx; long_name = state->ecx;",
            "  short_mode = rt->read(rt->context, entry_esp + UINT32_C(4), 4U, &fault);",
            "  rt->write(rt->context, pushed_esp, 4U, state->ebx, &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  state->esp = frame_esp; state->ebx = cursor_slot; state->eax = short_mode;",
            f"  subtraction_flags(state, pushed_esp, UINT32_C({frame_bytes}), frame_esp);",
            "  state->cf = 0U; state->of = 0U; state->pf = byte_parity(short_mode);",
            "  state->sf = short_mode >> 31; state->zf = short_mode == 0U;",
            f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
            "  context = (token_cursor_context){ rt, state, STAGE_B_CALL_OK, 0U, frame_esp };",
            "  services = (token_cursor_services){ &context, load_word, store_word, load_byte, compare_strings };",
            "  result = (uint32_t)match_token_cursor(&services, cursor_slot, short_name, long_name, short_mode);",
            "  if (context.memory_fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            "  if (context.status != STAGE_B_CALL_OK) return (stage_b_step_result){ STAGE_B_EXTERNAL_FAULT, state->original_rva, 0U };",
            f"  state->esp = frame_esp + UINT32_C({frame_bytes});",
            "  state->ebx = rt->read(rt->context, state->esp, 4U, &fault); state->esp += UINT32_C(4);",
            "  return_target = rt->read(rt->context, state->esp, 4U, &fault); state->esp += UINT32_C(4);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            "  state->eax = result; state->ecx = 0U; state->edx = 0U;",
            "  state->cf = 0U; state->of = 0U; state->pf = 1U; state->sf = 0U; state->zf = 1U;",
            *machine_eflags_sync_lines("  "),
            "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };",
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
        del prepared
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        esp = 0x70001000
        cursor_slot = 0x70002000
        cursor = 0x70003000
        long_name = 0x70004000
        probes = [
            ("long-equal", 0, ord("x"), b"hello\0", b"hello\0", 0),
            ("long-positive", 0, ord("x"), b"hello\0", b"world\0", 1),
            ("long-negative", 0, ord("x"), b"world\0", b"hello\0", 0xFFFFFFFF),
            ("short-prefix", 1, ord("h"), b"hello\0", b"unused\0", None),
            ("short-terminal", 1, ord("h"), b"h\0", b"unused\0", None),
            ("short-mismatch", 1, ord("z"), b"hello\0", b"unused\0", None),
            ("short-disabled", 1, 0, b"hello\0", b"unused\0", None),
            ("short-noncanonical-mode", 0xFFFFFFFF, ord("h"), b"hi\0", b"unused\0", None),
            ("short-high-register-bits", 2, ord("h"), b"hmm\0", b"unused\0", None),
            ("long-empty", 0, ord("x"), b"\0", b"\0", 0),
        ]
        rows = []
        for index, (label, mode, short, text, long_text, response) in enumerate(
            probes
        ):
            edx = short | ((0xA5A500 + index) << 8)
            row = {
                "id": f"case:mutable-token-cursor-{label}",
                "registers": {
                    "eax": cursor_slot,
                    "ebx": 0x11223344 + index,
                    "ecx": long_name,
                    "edx": edx,
                    "esi": 0x12345678,
                    "edi": 0x87654321,
                    "ebp": 0x70005000,
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
                    {"address": esp, "bytes": "78563412"},
                    {"address": esp + 4, "bytes": mode.to_bytes(4, "little").hex()},
                    {"address": cursor_slot, "bytes": cursor.to_bytes(4, "little").hex()},
                    {"address": cursor, "bytes": text.hex()},
                    {"address": long_name, "bytes": long_text.hex()},
                ],
                "external_responses": ([] if response is None else [{"eax": response}]),
                "external_response_seed": f"mutable-token-cursor-{label}",
            }
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
typedef struct model {{
  uint32_t cursor_slot, cursor, long_name, compare_result;
  uint32_t load_word_calls, load_byte_calls, compare_calls, store_calls;
  uint32_t stored[2];
  uint8_t first, second;
}} model;
static uint32_t load_word(void *opaque, uint32_t address) {{ model *m=opaque; m->load_word_calls++; __CPROVER_assert(address==m->cursor_slot,"cursor slot read"); return m->cursor; }}
static void store_word(void *opaque, uint32_t address, uint32_t value) {{ model *m=opaque; __CPROVER_assert(address==m->cursor_slot,"cursor slot write"); __CPROVER_assert(m->store_calls<2U,"bounded stores"); m->stored[m->store_calls++]=value; }}
static uint8_t load_byte(void *opaque, uint32_t address) {{ model *m=opaque; uint32_t call=m->load_byte_calls++; if(call==0U){{__CPROVER_assert(address==m->cursor,"first byte address");return m->first;}} __CPROVER_assert(call==1U,"bounded byte reads"); __CPROVER_assert(address==m->cursor+1U,"second byte address"); return m->second; }}
static int32_t compare_strings(void *opaque, uint32_t left, uint32_t right) {{ model *m=opaque; m->compare_calls++; __CPROVER_assert(left==m->cursor,"comparison left"); __CPROVER_assert(right==m->long_name,"comparison right"); return (int32_t)m->compare_result; }}
int main(void) {{
  model m={{0}}; token_cursor_services services={{&m,load_word,store_word,load_byte,compare_strings}};
  uint32_t short_word=nondet_u32(), mode=nondet_u32(), actual, expected=0U;
  uint32_t expected_loads=0U, expected_reads=0U, expected_compares=0U, expected_stores=0U;
  m.cursor_slot=nondet_u32(); m.cursor=nondet_u32(); m.long_name=nondet_u32(); m.compare_result=nondet_u32(); m.first=(uint8_t)nondet_u32(); m.second=(uint8_t)nondet_u32();
  actual=(uint32_t){symbol}(&services,m.cursor_slot,(uint8_t)short_word,m.long_name,mode);
  if(mode!=0U) {{
    if((uint8_t)short_word!=0U) {{ expected_loads=1U; expected_reads=1U; if(m.first==(uint8_t)short_word) {{ expected=1U; expected_reads=2U; expected_stores=m.second==0U?2U:1U; }} }}
  }} else {{ expected_loads=1U; expected_compares=1U; if(m.compare_result==0U) {{ expected=1U; expected_stores=1U; }} }}
  __CPROVER_assert(actual==expected,"match result");
  __CPROVER_assert(m.load_word_calls==expected_loads,"word-read count");
  __CPROVER_assert(m.load_byte_calls==expected_reads,"byte-read count");
  __CPROVER_assert(m.compare_calls==expected_compares,"comparison count");
  __CPROVER_assert(m.store_calls==expected_stores,"cursor-write count");
  if(mode!=0U && expected==1U) {{ __CPROVER_assert(m.stored[0]==m.cursor+1U,"advanced cursor"); if(m.second==0U)__CPROVER_assert(m.stored[1]==0U,"terminal cursor"); }}
  if(mode==0U && expected==1U) __CPROVER_assert(m.stored[0]==0U,"matched long cursor");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {
            "complete_for_all_32_bit_inputs_and_service_results": True,
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
                "complete_for_all_32_bit_inputs_and_service_results"
            )
            is True
        )


PROFILE = MutableTokenCursorMatchProfile()
