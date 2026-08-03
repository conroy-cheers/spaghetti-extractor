"""Guarded lexicographic byte comparison through a qualified scalar child."""

from __future__ import annotations

import copy
import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from spaghetti_extractor.artifact_formats import BOUNDED_PAIRWISE_BYTE_CONTRACT_FORMAT
from spaghetti_extractor.bounded_component_contract import (
    derive_bounded_pairwise_byte_compare_contract,
    validate_bounded_pairwise_byte_contract,
)
from spaghetti_extractor.component_profile import (
    ComponentProfileContext,
    PreparedComponentProfile,
    array_value,
    machine_eflags_sync_lines,
    object_value,
    render_scalar_piecewise_returns,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import write_json


_MAX_BYTES = 16


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("bounded_pairwise_byte_contract"),
        "bounded pairwise byte contract",
    )
    validate_bounded_pairwise_byte_contract(contract)
    if contract.get("format") != BOUNDED_PAIRWISE_BYTE_CONTRACT_FORMAT:
        raise StageAInputError(
            "bounded pairwise byte contract is not a usable static derivation"
        )
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


class BoundedPairwiseByteCompareProfile:
    name = "bounded_pairwise_byte_compare_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        del interface_refinement
        return ()

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        boundary = object_value(
            context.component.get("machine_boundary"), "component machine boundary"
        )
        exits = array_value(boundary.get("exits"), "component machine exits")
        calls = [item for item in exits if item.get("kind") == "internal_call"]
        returns = [item for item in exits if item.get("kind") == "return"]
        if (
            str(context.cluster.get("template") or "manual_contract")
            != "manual_contract"
            or boundary.get("call_closure", {}).get("status") != "complete"
            or boundary.get("counts", {}).get("entries") != 1
            or boundary.get("counts", {}).get("faults") != 0
            or len(calls) != 2
            or len(returns) != 1
            or len(context.component_dependencies) != 1
        ):
            raise StageAInputError(
                "bounded pairwise comparison requires two qualified scalar calls and one return"
            )
        contract = derive_bounded_pairwise_byte_compare_contract(
            component=context.component,
            units=context.units,
            machine_ir_sha256=context.machine_ir_sha256,
            max_bytes=_MAX_BYTES,
            component_dependency=context.component_dependencies[0],
        )
        return PreparedComponentProfile(
            portable_symbol="compare_pairwise_bytes",
            contract_field="bounded_pairwise_byte_contract",
            contract_filename="bounded-pairwise-byte-contract.json",
            contract_hash_binding="bounded_pairwise_byte_contract_sha256",
            contract=contract,
            activation_domain={
                "kind": "guarded_partial",
                "max_bytes": _MAX_BYTES,
                "requires_readable_stack_arguments": True,
                "decision_must_occur_within_bound": True,
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
        validate_bounded_pairwise_byte_contract(contract)
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        max_bytes = int(object_value(contract.get("domain"), "bounded pairwise domain")["max_bytes"])
        dependency = object_value(
            contract.get("component_call"), "bounded pairwise component call"
        )
        scalar_contract = object_value(
            dependency.get("finite_component_contract"),
            "bounded pairwise scalar contract",
        )
        normalize = render_scalar_piecewise_returns(
            contract=scalar_contract, output_path=("output",), indent="  "
        )
        needs_parity = "semantic_parity(" in normalize
        parity_helper = (
            """static inline uint32_t semantic_parity(uint32_t value) {
  value ^= value >> 4;
  value &= UINT32_C(0x0f);
  return (UINT32_C(0x9669) >> value) & UINT32_C(1);
}

"""
            if needs_parity
            else ""
        )
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

int32_t compare_pairwise_bytes(const uint8_t *left, const uint8_t *right);

#endif
"""
        portable = f"""#include "implementation.h"

{parity_helper}static uint32_t normalize_component_byte(uint32_t input) {{
{normalize}
}}

int32_t compare_pairwise_bytes(const uint8_t *left, const uint8_t *right) {{
  if (left == right)
    return 0;
  for (;;) {{
    uint32_t left_value = normalize_component_byte(*left);
    uint32_t right_value = normalize_component_byte(*right);
    if (left_value == 0U || left_value != right_value)
      return (int32_t)(uint32_t)(left_value - right_value);
    ++left;
    ++right;
  }}
}}
"""
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
        ]
        if needs_parity:
            adapter_lines.extend(parity_helper.rstrip().splitlines())
        adapter_lines.extend(
            [
                "static uint32_t adapter_normalize_component_byte(uint32_t input) {",
                normalize,
                "}",
                "",
                f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
                f"  uint8_t left_bytes[UINT32_C({max_bytes})] = {{ 0U }};",
                f"  uint8_t right_bytes[UINT32_C({max_bytes})] = {{ 0U }};",
                "  uint32_t fault = 0U, left, right, index, decided = 0U, return_target;",
                "  int32_t ordering;",
                "  left = rt->read(rt->context, state->esp + UINT32_C(4), UINT32_C(4), &fault);",
                f"  if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
                "  right = rt->read(rt->context, state->esp + UINT32_C(8), UINT32_C(4), &fault);",
                f"  if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
                "  if (left == right) {",
                "    ordering = 0;",
                "    decided = 1U;",
                "  } else {",
                f"    for (index = 0U; index < UINT32_C({max_bytes}); ++index) {{",
                "      uint32_t left_value, right_value;",
                "      left_bytes[index] = (uint8_t)rt->read(rt->context, left + index, UINT32_C(1), &fault);",
                f"      if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
                "      right_bytes[index] = (uint8_t)rt->read(rt->context, right + index, UINT32_C(1), &fault);",
                f"      if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
                "      left_value = adapter_normalize_component_byte(left_bytes[index]);",
                "      right_value = adapter_normalize_component_byte(right_bytes[index]);",
                "      if (left_value == 0U || left_value != right_value) {",
                "        decided = 1U;",
                "        break;",
                "      }",
                "    }",
                f"    if (!decided) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
                "    ordering = compare_pairwise_bytes(left_bytes, right_bytes);",
                "  }",
                "  return_target = rt->read(rt->context, state->esp, UINT32_C(4), &fault);",
                f"  if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
                f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
                "  state->eax = (uint32_t)ordering;",
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
        )
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
        contract = prepared.contract
        validate_bounded_pairwise_byte_contract(contract)
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        max_bytes = int(object_value(contract.get("domain"), "bounded pairwise domain")["max_bytes"])
        esp = 0x70001000
        left_pointer = 0x70002000
        right_pointer = 0x70003000
        probes: list[tuple[str, bytes | None, bytes | None, bool]] = [
            ("same-pointer", None, None, True),
            ("empty", b"\0", b"\0", False),
            ("empty-left", b"\0", b"a\0", False),
            ("empty-right", b"a\0", b"\0", False),
            ("case-equal", b"a\0", b"A\0", False),
            ("word-case-equal", b"abc\0", b"AbC\0", False),
            ("less", b"abc\0", b"abd\0", False),
            ("greater", b"abd\0", b"abc\0", False),
            ("high-equal", b"\x80\0", b"\x80\0", False),
            ("high-less", b"\x80\0", b"\x81\0", False),
        ]
        for index in range(max_bytes):
            prefix = b"a" * index
            probes.append((f"mismatch-{index:02d}", prefix + b"b\0", prefix + b"c\0", False))
            probes.append((f"left-zero-{index:02d}", prefix + b"\0", prefix + b"a\0", False))
        probes.append(
            (
                "fallback-after-bound",
                b"a" * max_bytes + b"b\0",
                b"a" * max_bytes + b"c\0",
                False,
            )
        )
        rows = []
        for index, (label, left_bytes, right_bytes, same_pointer) in enumerate(probes):
            left = left_pointer + index * 0x100
            right = left if same_pointer else right_pointer + index * 0x100
            memory = [
                {"address": esp, "bytes": "78563412"},
                {"address": esp + 4, "bytes": left.to_bytes(4, "little").hex()},
                {"address": esp + 8, "bytes": right.to_bytes(4, "little").hex()},
            ]
            if left_bytes is not None:
                memory.append({"address": left, "bytes": left_bytes.hex()})
            if right_bytes is not None and right != left:
                memory.append({"address": right, "bytes": right_bytes.hex()})
            rows.append(
                {
                    "id": f"case:bounded-pairwise-{label}",
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
                    "memory": memory,
                    "external_response_seed": f"bounded-pairwise-{label}",
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
        contract = _contract(refinement)
        maximum = int(object_value(contract.get("domain"), "bounded pairwise domain")["max_bytes"])
        dependency = object_value(
            contract.get("component_call"), "bounded pairwise component call"
        )
        scalar_contract = object_value(
            dependency.get("finite_component_contract"),
            "bounded pairwise scalar contract",
        )
        normalize_body = render_scalar_piecewise_returns(
            contract=scalar_contract, output_path=("output",), indent="  "
        )
        assignments = "\n".join(
            f"  left[{index}] = (uint8_t)nondet_u32();\n  right[{index}] = (uint8_t)nondet_u32();"
            for index in range(maximum)
        )
        body = f"""static inline uint32_t semantic_parity(uint32_t value) {{
  value ^= value >> 4;
  value &= UINT32_C(0x0f);
  return (UINT32_C(0x9669) >> value) & UINT32_C(1);
}}
static uint32_t expected_normalize(uint32_t input) {{
{normalize_body}
}}
int main(void) {{
  uint8_t left[{maximum}];
  uint8_t right[{maximum}];
  uint32_t index;
  int32_t expected = 0;
  bool decided = false;
{assignments}
  for (index = 0U; index < UINT32_C({maximum}); ++index) {{
    uint32_t left_value = expected_normalize(left[index]);
    uint32_t right_value = expected_normalize(right[index]);
    if (left_value == 0U || left_value != right_value) {{
      expected = (int32_t)(uint32_t)(left_value - right_value);
      decided = true;
      break;
    }}
  }}
  __CPROVER_assume(decided);
  __CPROVER_assert({symbol}(left, right) == expected,
                   "bounded pairwise comparison");
  __CPROVER_assert({symbol}(left, left) == 0,
                   "pairwise pointer identity");
  return 0;
}}
"""
        return (
            '#include "implementation.h"\n'
            "#include <stdbool.h>\n"
            "#include <stdint.h>\n\n"
            "extern uint32_t nondet_u32(void);\n"
            "extern int nondet_int(void);\n"
            + body
        )

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        return int(_contract(refinement)["domain"]["max_bytes"]) + 2

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            "complete_for_pairwise_decision_bytes_at_most": int(
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
            evidence_scope.get("complete_for_pairwise_decision_bytes_at_most")
            == activation_domain.get("max_bytes")
        )


PROFILE = BoundedPairwiseByteCompareProfile()
