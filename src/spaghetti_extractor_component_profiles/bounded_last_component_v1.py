"""Guarded portable last-path-component recovery for PE32 byte strings."""

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


_FORMAT = "stage-b-bounded-last-component-contract-v1"
_MAX_BYTES = 32


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
        return ("imm", None, int(operand.get("width_bits", 0)))
    if kind == "memory":
        return (
            "mem",
            operand.get("base"),
            operand.get("index"),
            int(operand.get("scale", 1)),
            int(operand.get("displacement", 0)),
            int(operand.get("width_bits", 0)),
        )
    raise StageAInputError(f"unsupported last-component operand kind: {kind!r}")


def _reg(name: str, width: int = 32) -> tuple[Any, ...]:
    return ("reg", name, width)


def _imm(width: int = 32) -> tuple[Any, ...]:
    return ("imm", None, width)


def _mem(
    base: str,
    displacement: int,
    width: int,
    *,
    index: str | None = None,
    scale: int = 1,
) -> tuple[Any, ...]:
    return ("mem", base, index, scale, displacement, width)


def _instruction_shape(unit: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        (
            str(instruction.get("mnemonic")),
            tuple(_operand(value) for value in array_value(instruction.get("operands"), "instruction operands")),
        )
        for instruction in array_value(unit.get("instructions"), "unit instructions")
    )


def _require_control(
    unit: Mapping[str, Any], kind: str, targets: Sequence[int]
) -> None:
    control = object_value(unit.get("control"), "unit control")
    if control.get("kind") != kind or set(control.get("direct_targets", [])) != set(targets):
        raise StageAInputError(
            f"last-component control mismatch at RVA 0x{_rva(unit):x}"
        )


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    component = context.component
    member_ids = [str(value) for value in component["membership"]["resolved_unit_ids"]]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError(
            "bounded last-component units do not match exact component membership"
        )
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 19:
        raise StageAInputError(
            "bounded last-component profile requires the canonical nineteen-unit loop"
        )
    expected = (
        (("push", (_reg("edi"),)), ("push", (_reg("esi"),)), ("push", (_reg("ebx"),)), ("mov", (_reg("edx"), _mem("esp", 16, 32)))),
        (("movzx", (_reg("eax"), _mem("edx", 0, 8))), ("mov", (_reg("ecx"), _reg("eax"))), ("or", (_reg("ecx"), _imm())), ("movsx", (_reg("ecx"), _reg("cl", 8)))),
        (("sub", (_reg("ecx"), _imm())), ("cmp", (_reg("ecx"), _imm())), ("ja", (_imm(),))),
        (("xor", (_reg("eax"), _reg("eax"))), ("cmp", (_mem("edx", 1, 8), _imm(8))), ("sete", (_reg("al", 8),)), ("lea", (_reg("edx"), _mem("edx", 0, 32, index="eax", scale=2)))),
        (("movzx", (_reg("eax"), _mem("edx", 0, 8))),),
        (("cmp", (_reg("al", 8), _imm(8))), ("jne", (_imm(),))),
        (("lea", (_reg("esi"), _mem("esi", 0, 32))),),
        (("movzx", (_reg("eax"), _mem("edx", 1, 8))), ("add", (_reg("edx"), _imm())), ("cmp", (_reg("al", 8), _imm(8))), ("je", (_imm(),))),
        (("cmp", (_reg("al", 8), _imm(8))), ("je", (_imm(),))),
        (("test", (_reg("al", 8), _reg("al", 8))), ("je", (_imm(),))),
        (("mov", (_reg("ebx"), _reg("edx"))), ("xor", (_reg("esi"), _reg("esi"))), ("xor", (_reg("edi"), _reg("edi"))), ("jmp", (_imm(),))),
        (("mov", (_reg("eax"), _reg("esi"))), ("test", (_reg("al", 8), _reg("al", 8))), ("cmovne", (_reg("esi"), _reg("edi"))), ("cmovne", (_reg("edx"), _reg("ebx")))),
        (("movzx", (_reg("eax"), _mem("ebx", 1, 8))), ("add", (_reg("ebx"), _imm())), ("test", (_reg("al", 8), _reg("al", 8))), ("je", (_imm(),))),
        (("cmp", (_reg("al", 8), _imm(8))), ("sete", (_reg("cl", 8),)), ("cmp", (_reg("al", 8), _imm(8))), ("sete", (_reg("al", 8),))),
        (("or", (_reg("cl", 8), _reg("al", 8))), ("je", (_imm(),))),
        (("movzx", (_reg("eax"), _mem("ebx", 1, 8))), ("add", (_reg("ebx"), _imm())), ("mov", (_reg("esi"), _reg("ecx"))), ("test", (_reg("al", 8), _reg("al", 8)))),
        (("jne", (_imm(),)),),
        (("pop", (_reg("ebx"),)), ("mov", (_reg("eax"), _reg("edx"))), ("pop", (_reg("esi"),)), ("pop", (_reg("edi"),))),
        (("xor", (_reg("edx"), _reg("edx"))), ("xor", (_reg("ecx"), _reg("ecx"))), ("ret", ())),
    )
    for index, (unit, shape) in enumerate(zip(ordered, expected, strict=True)):
        if _instruction_shape(unit) != shape:
            raise StageAInputError(
                f"last-component unit {index} does not match the normalized loop shape"
            )
    rvas = [_rva(unit) for unit in ordered]
    controls = (
        ("fallthrough", (rvas[1],)),
        ("fallthrough", (rvas[2],)),
        ("branch", (rvas[3], rvas[5])),
        ("fallthrough", (rvas[4],)),
        ("fallthrough", (rvas[5],)),
        ("branch", (rvas[6], rvas[8])),
        ("fallthrough", (rvas[7],)),
        ("branch", (rvas[7], rvas[8])),
        ("branch", (rvas[7], rvas[9])),
        ("branch", (rvas[10], rvas[17])),
        ("jump", (rvas[13],)),
        ("fallthrough", (rvas[12],)),
        ("branch", (rvas[13], rvas[17])),
        ("fallthrough", (rvas[14],)),
        ("branch", (rvas[11], rvas[15])),
        ("fallthrough", (rvas[16],)),
        ("branch", (rvas[13], rvas[17])),
        ("fallthrough", (rvas[18],)),
        ("return", ()),
    )
    for unit, (kind, targets) in zip(ordered, controls, strict=True):
        _require_control(unit, kind, targets)
    boundary = object_value(component.get("machine_boundary"), "component boundary")
    if (
        boundary.get("call_closure", {}).get("status") != "complete"
        or boundary.get("counts", {}).get("entries") != 1
        or boundary.get("counts", {}).get("exits") != 1
        or boundary.get("counts", {}).get("external_events") != 0
        or boundary.get("counts", {}).get("faults") != 0
        or boundary.get("exits", [{}])[0].get("kind") != "return"
    ):
        raise StageAInputError(
            "bounded last-component profile requires one closed, pure return region"
        )
    bindings = [
        {
            "unit_id": str(unit["id"]),
            "rva_start": _rva(unit),
            "rva_end": int(unit["source"]["original"]["rva_end"]),
            "instruction_bytes_sha256": str(unit["source"]["instruction_bytes_sha256"]),
            "semantic_transfer_sha256": (
                None
                if unit["source"].get("semantic_export") is None
                else str(unit["source"]["semantic_export"]["semantic_transfer_sha256"])
            ),
        }
        for unit in ordered
    ]
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "bounded_last_component_v1",
        "component": {
            "id": str(component["id"]),
            "sha256": str(component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "units": bindings,
        },
        "domain": {
            "kind": "guarded_partial",
            "max_bytes": _MAX_BYTES,
            "predicate": "input has a NUL byte below max_bytes",
            "outside_domain": "canonical_machine_ir",
        },
        "semantics": {
            "drive_prefix": "skip two bytes for ASCII alphabetic byte followed by colon",
            "separators": [47, 92],
            "leading_separators": "skipped",
            "trailing_separators": "do not replace the previous component",
            "result": "interior pointer to the final nonempty component",
        },
        "machine_projection": {
            "eax": "input_pointer_plus_result_offset",
            "ecx": 0,
            "edx": 0,
            "esp_delta": 4,
            "preserved_registers": ["ebx", "esi", "edi", "ebp"],
            "flags": {"cf": 0, "of": 0, "pf": 1, "sf": 0, "zf": 1, "df": "preserved"},
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("bounded_last_component_contract"),
        "bounded last-component contract",
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
        raise StageAInputError("bounded last-component contract is stale or malformed")
    return contract


def _adapter_parts(
    *, root: Path, backend_workspace: Mapping[str, Any]
) -> tuple[Mapping[str, Any], Path, str]:
    files = object_value(backend_workspace.get("files"), "backend workspace files")
    adapter_path = root / str(files["machine_adapter_source"])
    matches = re.findall(
        r"stage_b_step_result\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        adapter_path.read_text(encoding="ascii"),
    )
    if len(matches) != 1:
        raise StageAInputError(
            f"component machine adapter has {len(matches)} replacement symbols"
        )
    return files, adapter_path, matches[0]


def _expected_offset(data: bytes) -> int:
    index = 0
    if (
        len(data) >= 2
        and ((65 <= data[0] <= 90) or (97 <= data[0] <= 122))
        and data[1] == 58
    ):
        index = 2
    while data[index] in (47, 92):
        index += 1
    result = index
    scan = index
    while data[scan] != 0:
        if data[scan] in (47, 92):
            next_index = scan
            while data[next_index] in (47, 92):
                next_index += 1
            if data[next_index] == 0:
                break
            result = next_index
            scan = next_index
        else:
            scan += 1
    return result


class BoundedLastComponentProfile:
    name = "bounded_last_component_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        del interface_refinement
        return ()

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        if str(context.cluster.get("template") or "manual_contract") != "manual_contract":
            raise StageAInputError("bounded last-component profile requires a manual contract cluster")
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="last_path_component",
            contract_field="bounded_last_component_contract",
            contract_filename="bounded-last-component-contract.json",
            contract_hash_binding="bounded_last_component_contract_sha256",
            contract=contract,
            activation_domain={
                "kind": "guarded_partial",
                "max_bytes": _MAX_BYTES,
                "requires_readable_stack_argument": True,
                "requires_nul_within_bound": True,
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
        maximum = int(object_value(contract.get("domain"), "last-component domain")["max_bytes"])
        files, adapter_path, adapter_symbol = _adapter_parts(root=root, backend_workspace=backend_workspace)
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

const uint8_t *last_path_component(const uint8_t *path);

#endif
"""
        portable = """#include "implementation.h"

static int is_ascii_letter(uint8_t value) {
  return (value >= (uint8_t)'A' && value <= (uint8_t)'Z') ||
         (value >= (uint8_t)'a' && value <= (uint8_t)'z');
}

static int is_path_separator(uint8_t value) {
  return value == (uint8_t)'/' || value == (uint8_t)'\\\\';
}

const uint8_t *last_path_component(const uint8_t *path) {
  const uint8_t *cursor = path;
  const uint8_t *result;
  int saw_component_byte = 0;
  int separator_after_component = 0;

  if (is_ascii_letter(cursor[0]) && cursor[1] == (uint8_t)':')
    cursor += 2;
  result = cursor;
  while (*cursor != 0U) {
    if (is_path_separator(*cursor)) {
      if (!saw_component_byte)
        result = cursor + 1;
      else
        separator_after_component = 1;
    } else {
      if (separator_after_component)
        result = cursor;
      saw_component_byte = 1;
      separator_after_component = 0;
    }
    ++cursor;
  }
  return result;
}
"""
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            f"  uint8_t path[UINT32_C({maximum})] = {{ 0U }};",
            "  uint32_t fault = 0U, source, index, return_target, result_offset;",
            "  const uint8_t *result;",
            "  rt->write(rt->context, state->esp - UINT32_C(4), UINT32_C(4), state->edi, &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            "  rt->write(rt->context, state->esp - UINT32_C(8), UINT32_C(4), state->esi, &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            "  rt->write(rt->context, state->esp - UINT32_C(12), UINT32_C(4), state->ebx, &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            "  source = rt->read(rt->context, state->esp + UINT32_C(4), UINT32_C(4), &fault);",
            f"  if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
            f"  for (index = 0U; index < UINT32_C({maximum}); ++index) {{",
            "    path[index] = (uint8_t)rt->read(rt->context, source + index, UINT32_C(1), &fault);",
            f"    if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
            "    if (path[index] == 0U) break;",
            "  }",
            f"  if (index == UINT32_C({maximum})) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
            "  result = last_path_component(path);",
            "  result_offset = (uint32_t)(result - path);",
            "  return_target = rt->read(rt->context, state->esp, UINT32_C(4), &fault);",
            f"  if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
            f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
            "  state->eax = source + result_offset;",
            "  state->ecx = 0U;",
            "  state->edx = 0U;",
            "  state->esp += UINT32_C(4);",
            "  state->cf = 0U;",
            "  state->of = 0U;",
            "  state->pf = 1U;",
            "  state->sf = 0U;",
            "  state->zf = 1U;",
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
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        maximum = int(prepared.contract["domain"]["max_bytes"])
        values = [
            b"\0",
            b"hello\0",
            b"/hello\0",
            b"///hello\0",
            b"\\\\hello\0",
            b"a/b/c\0",
            b"a\\b/c\0",
            b"a/b/c///\0",
            b"/\0",
            b"C:\0",
            b"C:hello\0",
            b"C:/hello\0",
            b"C:\\a\\b\0",
            b"z://a/b\0",
            b"1:a/b\0",
            b"Aalpha/beta\0",
            b"a//b\\\\c\0",
            b"x" * (maximum - 1) + b"\0",
            b"x" * maximum + b"\0",
        ]
        esp = 0x70001000
        base = 0x70002000
        rows = []
        for index, value in enumerate(values):
            rows.append(
                {
                    "id": f"case:last-component-{index:02d}",
                    "registers": {
                        "eax": 0x10203040,
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
                    "memory": [
                        {"address": esp, "bytes": "78563412"},
                        {"address": esp + 4, "bytes": base.to_bytes(4, "little").hex()},
                        {"address": base, "bytes": value.hex()},
                    ],
                    "external_response_seed": f"last-component-{index:02d}",
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
        maximum = int(_contract(refinement)["domain"]["max_bytes"])
        assignments = "\n".join(
            f"  path[{index}] = (uint8_t)nondet_u32();" for index in range(maximum)
        )
        return f'''#include "implementation.h"
#include <stdbool.h>
#include <stdint.h>

extern uint32_t nondet_u32(void);

static bool letter(uint8_t value) {{
  return (value >= (uint8_t)'A' && value <= (uint8_t)'Z') ||
         (value >= (uint8_t)'a' && value <= (uint8_t)'z');
}}
static bool separator(uint8_t value) {{
  return value == (uint8_t)'/' || value == (uint8_t)'\\\\';
}}
static uint32_t expected_offset(const uint8_t *path) {{
  uint32_t cursor = 0U;
  uint32_t result;
  bool saw_component_byte = false;
  bool separator_after_component = false;
  if (letter(path[0]) && path[1] == (uint8_t)':') cursor = 2U;
  result = cursor;
  while (path[cursor] != 0U) {{
    if (separator(path[cursor])) {{
      if (!saw_component_byte) result = cursor + 1U;
      else separator_after_component = true;
    }} else {{
      if (separator_after_component) result = cursor;
      saw_component_byte = true;
      separator_after_component = false;
    }}
    ++cursor;
  }}
  return result;
}}
int main(void) {{
  uint8_t path[{maximum}];
  const uint8_t *result;
{assignments}
  __CPROVER_assume(path[{maximum - 1}] == 0U);
  result = {symbol}(path);
  __CPROVER_assert(result >= path && result < path + UINT32_C({maximum}),
                   "result remains in the input object");
  __CPROVER_assert((uint32_t)(result - path) == expected_offset(path),
                   "last path component offset");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        return int(_contract(refinement)["domain"]["max_bytes"]) + 2

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            "complete_for_nul_terminated_path_bytes_at_most": int(
                _contract(refinement)["domain"]["max_bytes"]
            ),
            "outside_domain": "decline_to_canonical_machine_ir",
        }

    def activation_scope_matches(
        self,
        *,
        activation_domain: Mapping[str, Any],
        evidence_scope: Mapping[str, Any],
    ) -> bool:
        return (
            evidence_scope.get("complete_for_nul_terminated_path_bytes_at_most")
            == activation_domain.get("max_bytes")
        )


PROFILE = BoundedLastComponentProfile()
