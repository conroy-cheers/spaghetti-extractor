"""Lift a bounded 16-bit string-length loop into portable C."""

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


_FORMAT = "stage-b-bounded-wide-string-length-contract-v1"
_MAX_ELEMENTS = 16


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
        return ("i", int(operand.get("width_bits", 0)))
    if kind == "memory":
        return (
            "m",
            operand.get("base"),
            operand.get("index"),
            int(operand.get("scale", 1)),
            int(operand.get("displacement", 0)),
            int(operand.get("width_bits", 0)),
        )
    raise StageAInputError(f"unsupported wide-string operand kind: {kind!r}")


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


def _require_outcome(
    unit: Mapping[str, Any],
    kind: str,
    *,
    target: int | None = None,
    true_target: int | None = None,
    false_target: int | None = None,
) -> None:
    semantics = object_value(unit.get("semantics"), "unit semantics")
    outcome = object_value(semantics.get("outcome"), "unit outcome")
    if outcome.get("kind") != kind:
        raise StageAInputError("wide-string control kind does not match its loop")
    if target is not None and outcome.get("target_rva") != target:
        raise StageAInputError("wide-string direct target does not match its loop")
    if true_target is not None and outcome.get("true_target_rva") != true_target:
        raise StageAInputError("wide-string true target does not match its loop")
    if false_target is not None and outcome.get("false_target_rva") != false_target:
        raise StageAInputError("wide-string false target does not match its loop")


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("wide-string length has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("wide-string units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 7:
        raise StageAInputError("wide-string profile requires its seven-unit loop")

    boundary = object_value(
        context.component.get("machine_boundary"), "component boundary"
    )
    counts = object_value(boundary.get("counts"), "component boundary counts")
    exits = array_value(boundary.get("exits"), "component exits")
    if (
        counts.get("entries") != 1
        or counts.get("exits") != 1
        or counts.get("external_events") != 0
        or counts.get("faults") != 0
        or len(exits) != 1
        or exits[0].get("kind") != "return"
        or array_value(boundary.get("internal_calls", []), "component calls")
        or object_value(boundary.get("call_closure"), "component call closure").get(
            "status"
        )
        != "complete"
    ):
        raise StageAInputError("wide-string profile requires one closed pure return")

    expected = (
        (
            ("mov", (("r", "edx", 32), ("m", "esp", None, 1, 8, 32))),
            ("mov", (("r", "ecx", 32), ("m", "esp", None, 1, 4, 32))),
            ("xor", (("r", "eax", 32), ("r", "eax", 32))),
            ("test", (("r", "edx", 32), ("r", "edx", 32))),
        ),
        (("jne", (("i", 32),)),),
        (("jmp", (("i", 32),)),),
        (
            ("add", (("r", "eax", 32), ("i", 32))),
            ("cmp", (("r", "edx", 32), ("r", "eax", 32))),
            ("je", (("i", 32),)),
        ),
        (
            (
                "cmp",
                (("m", "ecx", "eax", 2, 0, 16), ("i", 16)),
            ),
            ("jne", (("i", 32),)),
        ),
        (("mov", (("r", "edx", 32), ("r", "eax", 32))),),
        (
            ("mov", (("r", "eax", 32), ("r", "edx", 32))),
            ("xor", (("r", "edx", 32), ("r", "edx", 32))),
            ("xor", (("r", "ecx", 32), ("r", "ecx", 32))),
            ("ret", ()),
        ),
    )
    for index, (unit, wanted) in enumerate(zip(ordered, expected)):
        if _shape(unit) != wanted:
            raise StageAInputError(
                f"wide-string unit {index} does not match the checked loop shape"
            )
        semantics = object_value(unit.get("semantics"), "unit semantics")
        if array_value(semantics.get("external_events"), "unit external events"):
            raise StageAInputError("wide-string loop contains an external event")
        schedule = semantics.get("instruction_effect_schedule")
        if schedule is not None:
            schedule_object = object_value(schedule, "instruction effect schedule")
            if schedule_object.get("status") != "complete":
                raise StageAInputError("wide-string instruction replay is incomplete")
            for record in array_value(schedule_object.get("records"), "effect records"):
                effects = object_value(record.get("effects"), "instruction effects")
                if array_value(effects.get("call_effects"), "instruction calls"):
                    raise StageAInputError("wide-string loop contains a call")
    step_operands = array_value(
        array_value(ordered[3].get("instructions"), "step instructions")[0].get(
            "operands"
        ),
        "step operands",
    )
    terminator_operands = array_value(
        array_value(ordered[4].get("instructions"), "terminator instructions")[0].get(
            "operands"
        ),
        "terminator operands",
    )
    if (
        object_value(step_operands[1], "step immediate").get("value") != 1
        or object_value(terminator_operands[1], "terminator immediate").get("value")
        != 0
    ):
        raise StageAInputError("wide-string loop does not increment by one or test zero")

    rvas = [_rva(unit) for unit in ordered]
    _require_outcome(ordered[0], "fallthrough", target=rvas[1])
    _require_outcome(
        ordered[1], "branch", true_target=rvas[4], false_target=rvas[2]
    )
    _require_outcome(ordered[2], "jump", target=rvas[6])
    _require_outcome(
        ordered[3], "branch", true_target=rvas[6], false_target=rvas[4]
    )
    _require_outcome(
        ordered[4], "branch", true_target=rvas[3], false_target=rvas[5]
    )
    _require_outcome(ordered[5], "fallthrough", target=rvas[6])
    _require_outcome(ordered[6], "return")

    bindings = []
    for unit in ordered:
        source = object_value(unit.get("source"), "wide-string source")
        semantic_export = object_value(
            source.get("semantic_export"), "wide-string semantic export"
        )
        bindings.append(
            {
                "unit_id": str(unit["id"]),
                "rva_start": _rva(unit),
                "rva_end": int(source["original"]["rva_end"]),
                "instruction_bytes_sha256": str(source["instruction_bytes_sha256"]),
                "semantic_transfer_sha256": str(
                    semantic_export["semantic_transfer_sha256"]
                ),
            }
        )
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "bounded_wide_string_length_v1",
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
            "kind": "guarded_partial",
            "max_elements": _MAX_ELEMENTS,
            "element_width_bytes": 2,
            "outside_domain": "canonical_machine_ir",
        },
        "logical_interface": {
            "parameters": [
                {
                    "id": "elements",
                    "type": "const uint16_t *",
                    "machine": "stack_argument_0",
                },
                {
                    "id": "limit",
                    "type": "uint32_t",
                    "machine": "stack_argument_1",
                },
            ],
            "result": {"id": "length", "type": "uint32_t", "machine": "eax"},
        },
        "loop": {
            "invariant": [
                "0 <= index <= limit",
                "all 16-bit elements before index are nonzero",
            ],
            "variant": "limit - index",
        },
        "result": {
            "definition": "least zero 16-bit element index below limit, or limit",
            "memory_effect": "read_only_outside_private_call_frame",
        },
        "machine_projection": {
            "registers_written": ["eax", "ecx", "edx", "esp"],
            "preserved_registers": ["ebx", "esi", "edi", "ebp"],
            "constant_outputs": {
                "ecx": 0,
                "edx": 0,
                "cf": 0,
                "of": 0,
                "pf": 1,
                "sf": 0,
                "zf": 1,
            },
            "preserved_flags": ["df"],
            "stack_delta": 4,
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("bounded_wide_string_length_contract"),
        "bounded wide-string contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    domain = object_value(contract.get("domain"), "wide-string domain")
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or domain.get("element_width_bytes") != 2
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("bounded wide-string contract is stale")
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
        raise StageAInputError("wide-string adapter does not have one entry")
    return files, adapter, matches[0]


class BoundedWideStringLengthProfile:
    name = "bounded_wide_string_length_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        _ = interface_refinement
        return ()

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="bounded_wide_string_length",
            contract_field="bounded_wide_string_length_contract",
            contract_filename="bounded-wide-string-length-contract.json",
            contract_hash_binding="bounded_wide_string_length_contract_sha256",
            contract=contract,
            activation_domain={
                "kind": "guarded_partial",
                "max_elements": _MAX_ELEMENTS,
                "element_width_bytes": 2,
                "requires_readable_stack_frame": True,
                "requires_readable_element_prefix": True,
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
        maximum = int(object_value(contract.get("domain"), "domain")["max_elements"])
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

uint32_t bounded_wide_string_length(const uint16_t *elements, uint32_t limit);

#endif
"""
        portable = """#include "implementation.h"

uint32_t bounded_wide_string_length(const uint16_t *elements, uint32_t limit) {
  uint32_t index;
  for (index = 0U; index < limit; ++index) {
    if (elements[index] == 0U)
      break;
  }
  return index;
}
"""
        adapter = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            f"  uint16_t elements[UINT32_C({maximum})];",
            "  uint32_t fault = 0U, pointer, limit, length, index, return_target;",
            "  limit = rt->read(rt->context, state->esp + UINT32_C(8), UINT32_C(4), &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            f"  if (limit > UINT32_C({maximum}))",
            f"    return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
            "  pointer = rt->read(rt->context, state->esp + UINT32_C(4), UINT32_C(4), &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            "  for (index = 0U; index < limit; ++index) {",
            "    elements[index] = (uint16_t)rt->read(rt->context, pointer + index * UINT32_C(2), UINT32_C(2), &fault);",
            "    if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            "    if (elements[index] == 0U) break;",
            "  }",
            "  length = bounded_wide_string_length(elements, limit);",
            "  return_target = rt->read(rt->context, state->esp, UINT32_C(4), &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
            "  state->eax = length;",
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
        adapter_path.write_text("\n".join(adapter), encoding="ascii")

    def install_cases(
        self,
        *,
        root: Path,
        backend_workspace: Mapping[str, Any],
        cluster: Mapping[str, Any],
        prepared: PreparedComponentProfile,
    ) -> None:
        contract = prepared.contract
        maximum = int(object_value(contract.get("domain"), "domain")["max_elements"])
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        esp = 0x70001000
        pointer = 0x70002000
        rows = []
        for limit in range(maximum + 1):
            for zero_index in range(limit + 1):
                values = [
                    ((index * 811 + limit * 193 + zero_index * 71) % 0xFFFF) + 1
                    for index in range(max(limit, 1))
                ]
                label = "none"
                if zero_index < limit:
                    values[zero_index] = 0
                    label = f"{zero_index:02d}"
                encoded = b"".join(value.to_bytes(2, "little") for value in values)
                rows.append(
                    {
                        "id": f"case:bounded-wcsnlen-{limit:02d}-{label}",
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
                            "cf": 1,
                            "zf": 0,
                            "sf": 1,
                            "of": 1,
                            "pf": 0,
                            "df": (limit + zero_index) & 1,
                        },
                        "memory": [
                            {"address": esp, "bytes": "78563412"},
                            {
                                "address": esp + 4,
                                "bytes": pointer.to_bytes(4, "little").hex(),
                            },
                            {
                                "address": esp + 8,
                                "bytes": limit.to_bytes(4, "little").hex(),
                            },
                            {"address": pointer, "bytes": encoded.hex()},
                        ],
                        "external_response_seed": f"bounded-wcsnlen-{limit:02d}-{label}",
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
        maximum = int(object_value(contract.get("domain"), "domain")["max_elements"])
        symbol = str(refinement.get("portable_symbol") or "")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
            raise StageAInputError("wide-string refinement omits its portable symbol")
        assignments = "\n".join(
            f"  elements[{index}] = (uint16_t)nondet_u32();"
            for index in range(maximum)
        )
        return f'''#include "implementation.h"
#include <stdint.h>

extern uint32_t nondet_u32(void);

int main(void) {{
  uint16_t elements[{maximum}];
  uint32_t limit = nondet_u32();
  uint32_t expected = 0U;
{assignments}
  __CPROVER_assume(limit <= UINT32_C({maximum}));
  while (expected < limit && elements[expected] != 0U)
    ++expected;
  __CPROVER_assert({symbol}(elements, limit) == expected,
                   "bounded wide-string length");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        contract = _contract(refinement)
        maximum = int(object_value(contract.get("domain"), "domain")["max_elements"])
        return maximum + 2

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        contract = _contract(refinement)
        domain = object_value(contract.get("domain"), "wide-string domain")
        return {
            "complete_for_element_count_at_most": int(domain["max_elements"]),
            "element_width_bytes": int(domain["element_width_bytes"]),
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
            and activation_domain.get("max_elements")
            == evidence_scope.get("complete_for_element_count_at_most")
            and activation_domain.get("element_width_bytes")
            == evidence_scope.get("element_width_bytes")
            and evidence_scope.get("outside_domain")
            == "decline_to_canonical_machine_ir"
        )


PROFILE = BoundedWideStringLengthProfile()
