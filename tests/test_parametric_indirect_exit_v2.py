from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
    IndirectExitBinding,
)
from spaghetti_extractor.machine_ir_authority_v2 import (
    build_machine_ir_authority_bindings,
    machine_ir_sha256,
    recompute_unit_binding,
)
from spaghetti_extractor.parametric_indirect_exit_v2 import (
    ParametricIndirectExitSummaryV2,
    build_parametric_indirect_exit_inventory_v2,
    validate_parametric_target_expression_v2,
)


PE_SHA256 = "3" * 64


def _unit() -> dict:
    return {
        "id": "unit:callee",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1001},
            "instruction_bytes_sha256": "4" * 64,
        },
        "instructions": [],
        "semantics": {
            "external_events": [],
            "faults": [],
            "outcome": {
                "kind": "indirect_jump",
                "instruction_rva": 0x1000,
                "target": {"op": "reg", "name": "eax", "width": 32},
            },
        },
    }


def _summary() -> ParametricIndirectExitSummaryV2:
    rows = [_unit()]
    binary = BinaryBinding(PE_SHA256, machine_ir_sha256(rows))
    exact = build_machine_ir_authority_bindings(
        rows, pe_sha256=PE_SHA256
    )
    exit_binding = IndirectExitBinding.parse(exact["indirect_exits"][0])
    return ParametricIndirectExitSummaryV2.complete(
        summary_unit=recompute_unit_binding(rows[0], binary=binary),
        exit_binding=exit_binding,
        target_expression={
            "op": "summary_input_register",
            "register": "eax",
        },
    )


def _interprocedural(row: dict, *, status: str = "complete") -> dict:
    return {
        "format": "stage-a-interprocedural-analysis-v2",
        "status": "incomplete",
        "call_summaries": {
            "summaries": [{
                "target_unit_id": "unit:callee",
                "parametric_indirect_exits": {
                    "status": status,
                    "exits": [row],
                },
            }],
        },
    }


class ParametricIndirectExitV2Tests(unittest.TestCase):
    def test_inventory_accepts_exact_typed_summary(self) -> None:
        summary = _summary()
        inventory = build_parametric_indirect_exit_inventory_v2(
            _interprocedural(summary.to_payload())
        )

        self.assertEqual(inventory["status"], "complete")
        self.assertEqual(inventory["counts"]["parametric_summaries"], 1)
        self.assertEqual(
            ParametricIndirectExitSummaryV2.parse(
                inventory["summaries"][0]
            ),
            summary,
        )

    def test_stale_summary_is_violated(self) -> None:
        payload = copy.deepcopy(_summary().to_payload())
        payload["target_expression"]["register"] = "ebx"

        inventory = build_parametric_indirect_exit_inventory_v2(
            _interprocedural(payload)
        )

        self.assertEqual(inventory["status"], "violated")
        self.assertEqual(
            inventory["issues"][0]["code"],
            "parametric_summary_row_corrupt",
        )

    def test_unbound_legacy_summary_is_incomplete(self) -> None:
        inventory = build_parametric_indirect_exit_inventory_v2(
            _interprocedural({
                "id": "legacy",
                "origin_exit_id": "exit",
                "status": "complete",
                "target_expression": {
                    "op": "summary_input_register",
                    "register": "eax",
                },
            })
        )

        self.assertEqual(inventory["status"], "incomplete")
        self.assertEqual(inventory["counts"]["parametric_summaries"], 0)

    def test_expression_budget_fails_closed(self) -> None:
        expression = {
            "op": "finite_alternatives",
            "values": [
                {"op": "constant", "value": value, "width": 32}
                for value in range(3)
            ],
        }
        with self.assertRaises(AuthorityDataError):
            validate_parametric_target_expression_v2(
                expression, finite_alternative_budget=2
            )


if __name__ == "__main__":
    unittest.main()
