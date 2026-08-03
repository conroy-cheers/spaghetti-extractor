from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.component_workspace import (
    _render_scalar_piecewise_returns,
)
from spaghetti_extractor.finite_component_contract import (
    derive_finite_scalar_contract,
)
from spaghetti_extractor.stage_binary import StageAInputError


class FiniteComponentContractTests(unittest.TestCase):
    def test_derives_total_ascii_lower_contract(self) -> None:
        contract = derive_finite_scalar_contract(
            component=_component(),
            units=_units(),
            machine_ir_sha256="machine-ir",
        )

        self.assertEqual(contract["profile"], "finite_acyclic_scalar_v1")
        self.assertEqual(contract["symbolic_checks"]["path_count"], 1)
        self.assertEqual(
            contract["machine_projection"]["registers_written"], ["eax"]
        )
        output = contract["paths"][0]["output"]
        self.assertEqual(output["op"], "ite")
        rendered = _render_scalar_piecewise_returns(
            contract=contract,
            output_path=("output",),
            indent="  ",
        )
        self.assertIn("input", rendered)
        self.assertIn("UINT32_C(0x00000020)", rendered)

    def test_rejects_non_interface_register_dependency(self) -> None:
        units = _units()
        units[0]["semantics"]["register_writes"][0]["value"] = {
            "op": "reg",
            "name": "ebx",
            "width": 32,
        }
        with self.assertRaisesRegex(StageAInputError, "non-interface inputs"):
            derive_finite_scalar_contract(
                component=_component(),
                units=units,
                machine_ir_sha256="machine-ir",
            )

    def test_rejects_component_cycle(self) -> None:
        units = _units()
        units[1]["semantics"]["outcome"] = {
            "kind": "jump",
            "target_rva": 0x1000,
        }
        with self.assertRaisesRegex(StageAInputError, "contains a cycle"):
            derive_finite_scalar_contract(
                component=_component(),
                units=units,
                machine_ir_sha256="machine-ir",
            )


def _component() -> dict:
    return {
        "id": "ascii-to-lower",
        "component_sha256": "component",
        "membership": {"resolved_unit_ids": ["unit:entry", "unit:return"]},
        "machine_boundary": {
            "counts": {
                "entries": 1,
                "exits": 1,
                "memory_events": 2,
                "memory_writes": 0,
                "external_events": 0,
                "faults": 0,
            },
            "entries": [{"kind": "control", "unit_id": "unit:entry"}],
            "exits": [{"kind": "return", "source_unit_id": "unit:return"}],
            "call_closure": {"status": "complete"},
            "internal_indirect_controls": [],
            "effects": {
                "memory_events": [
                    {"event": {"kind": "read"}},
                    {"event": {"kind": "read"}},
                ]
            },
        },
    }


def _units() -> list[dict]:
    stack_input = {
        "op": "load",
        "width": 4,
        "address": {
            "op": "add32",
            "args": [
                {"op": "const", "value": 4, "width": 32},
                {"op": "reg", "name": "esp", "width": 32},
            ],
        },
    }
    output = {
        "op": "ite",
        "args": [
            {
                "op": "ult32",
                "args": [
                    {
                        "op": "add32",
                        "args": [
                            {"op": "const", "value": -65, "width": 32},
                            copy.deepcopy(stack_input),
                        ],
                    },
                    {"op": "const", "value": 26, "width": 32},
                ],
            },
            {
                "op": "add32",
                "args": [
                    {"op": "const", "value": 32, "width": 32},
                    copy.deepcopy(stack_input),
                ],
            },
            copy.deepcopy(stack_input),
        ],
    }
    return [
        {
            "id": "unit:entry",
            "source": {"original": {"rva_start": 0x1000}},
            "semantics": {
                "register_writes": [{"register": "eax", "value": output}],
                "flag_writes": [],
                "outcome": {"kind": "fallthrough", "target_rva": 0x1010},
            },
        },
        {
            "id": "unit:return",
            "source": {"original": {"rva_start": 0x1010}},
            "semantics": {
                "register_writes": [
                    {
                        "register": "esp",
                        "value": {
                            "op": "add32",
                            "args": [
                                {"op": "const", "value": 4, "width": 32},
                                {"op": "reg", "name": "esp", "width": 32},
                            ],
                        },
                    }
                ],
                "flag_writes": [],
                "outcome": {"kind": "return"},
            },
        },
    ]


if __name__ == "__main__":
    unittest.main()
