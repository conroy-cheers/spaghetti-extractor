from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan, TransferPlanError

from spaghetti_extractor.components.interface_ir import (
    ProofKernelComponentInterface,
)
from spaghetti_extractor.components.semantic_contract import (
    ComponentSemanticContractError,
    load_transfer_v2_refinement_universe,
)
from spaghetti_extractor.components.semantic_paths import (
    SemanticPathError,
    build_operation_path_model,
)
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit,
    transfer_row,
    write_fixture_transfer_plan,
)


class CanonicalTransferRefinementTests(unittest.TestCase):
    @staticmethod
    def _scalar_interface() -> ProofKernelComponentInterface:
        return ProofKernelComponentInterface.parse(
            {
                "id": "increment",
                "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
                "state": [],
                "operations": [
                    {
                        "id": "run",
                        "kind": "operation",
                        "parameters": [{"id": "value", "type_id": "u32"}],
                        "results": [{"id": "result", "type_id": "u32"}],
                        "effect_ids": [],
                        "allowed_service_ids": [],
                        "pre_states": ["ready"],
                        "post_states": ["ready"],
                    }
                ],
                "effects": [],
                "services": [],
                "protocol": {"states": ["ready"], "initial_state": "ready"},
            }
        )

    @staticmethod
    def _scalar_operation(unit: dict[str, object]) -> dict[str, object]:
        return {
            "operation_id": "run",
            "entry_unit_ids": [unit["id"]],
            "exit_unit_ids": [unit["id"]],
            "parameters": [
                {
                    "id": "value",
                    "projection": {
                        "kind": "register",
                        "register": "eax",
                        "width": 32,
                        "at": "entry",
                    },
                }
            ],
            "results": [
                {
                    "id": "result",
                    "projection": {
                        "kind": "register",
                        "register": "eax",
                        "width": 32,
                        "at": "exit",
                    },
                }
            ],
            "state": [],
            "preserved_state_ids": [],
            "effects": [],
            "callback_operation_ids": [],
            "continuation_unit_ids": [],
            "units": [unit],
        }

    def test_refinement_loads_only_contract_selected_units(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = transfer_row()
            second = copy.deepcopy(first)
            second["id"] = "semantic-transfer:unreachable"
            second["original"] = {
                "rva_start": 0x2000,
                "rva_end": 0x2003,
                "size": 3,
            }
            machine = root / "machine-ir.jsonl"
            machine.write_text(
                "".join(
                    json.dumps(as_machine_ir_unit(row), sort_keys=True) + "\n"
                    for row in (first, second)
                ),
                encoding="utf-8",
            )
            plan = write_fixture_transfer_plan(machine)
            universe = load_transfer_v2_refinement_universe(
                transfer_plan=plan,
                required_unit_ids=[first["id"]],
            )
            rows = list(universe.units.values())
            projection_created = (root / "projection").exists()

        self.assertEqual([row["id"] for row in rows], [first["id"]])
        self.assertEqual(len(universe.transfer_payload["transfers"]), 2)
        self.assertFalse(projection_created)

    def test_selected_region_can_exclude_an_unlowered_unrelated_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = transfer_row()
            second = {**copy.deepcopy(first), "id": "semantic-transfer:unlowered", "status": "incomplete",
                "original": {"rva_start": 0x2000, "rva_end": 0x2003, "size": 3}}
            machine = root / "machine-ir.jsonl"
            machine.write_text("".join(json.dumps(as_machine_ir_unit(row)) + "\n" for row in (first, second)))
            path = write_fixture_transfer_plan(machine)
            original = json.loads(path.read_text())
            for phase in ("semantic_qualification", "semantic_lowering"):
                value = copy.deepcopy(original)
                value["semantic_blockers"][0]["failure_phase"] = phase
                value["plan_sha256"] = canonical_sha256_v3({k: v for k, v in value.items() if k != "plan_sha256"})
                path.write_text(json.dumps(value))
                universe = load_transfer_v2_refinement_universe(transfer_plan=path, required_unit_ids=[first["id"]])
                self.assertEqual(set(universe.units), {first["id"]})
                self.assertEqual(universe.transfer_payload["status"], "incomplete")
                with self.assertRaises(TransferPlanError):
                    load_executable_transfer_plan(path, require_complete=True)
                with self.assertRaises(ComponentSemanticContractError):
                    load_transfer_v2_refinement_universe(transfer_plan=path, required_unit_ids=[second["id"]])
            for field, replacement in (("transfer_id", first["id"]), ("transfer_id", "unknown"),
                                       ("failure_phase", "identity_validation"), ("rva_start", 0x1000)):
                with self.subTest(field=field, replacement=replacement):
                    value = copy.deepcopy(original)
                    value["semantic_blockers"][0][field] = replacement
                    value["plan_sha256"] = canonical_sha256_v3({k: v for k, v in value.items() if k != "plan_sha256"})
                    path.write_text(json.dumps(value))
                    with self.assertRaises(ComponentSemanticContractError):
                        load_transfer_v2_refinement_universe(transfer_plan=path, required_unit_ids=[first["id"]])
            second["original"] = {**first["original"]}
            machine.write_text("".join(json.dumps(as_machine_ir_unit(row)) + "\n" for row in (first, second)))
            overlap = write_fixture_transfer_plan(machine)
            with self.assertRaisesRegex(ComponentSemanticContractError, "overlapping"):
                load_transfer_v2_refinement_universe(transfer_plan=overlap, required_unit_ids=[first["id"]])

    def test_refinement_universe_keeps_transfer_v2_as_only_executable_body(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = transfer_row(
                expression={
                    "op": "sign_extend",
                    "args": [
                        {"op": "const", "value": 8, "width": 32},
                        {"op": "reg", "name": "eax", "width": 32},
                    ],
                }
            )
            row["outcome"] = {
                "kind": "branch",
                "condition": {
                    "op": "eq",
                    "args": [
                        {
                            "op": "sign_extend",
                            "args": [
                                {"op": "const", "value": 8, "width": 32},
                                {"op": "reg", "name": "eax", "width": 32},
                            ],
                        },
                        {"op": "const", "value": 0, "width": 32},
                    ],
                },
                "true_target_rva": 0x1000,
                "false_target_rva": 0x1000,
            }
            machine = root / "machine-ir.jsonl"
            machine.write_text(
                json.dumps(as_machine_ir_unit(row), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            plan = write_fixture_transfer_plan(machine)
            universe = load_transfer_v2_refinement_universe(
                transfer_plan=plan,
                required_unit_ids=[row["id"]],
            )
            unit = universe.units[row["id"]]

        semantics = unit["semantics"]
        self.assertNotIn("outcome", semantics)
        self.assertNotIn("edge_conditions", semantics)
        self.assertEqual(semantics["transfer_v2"]["terminator"]["op"], "outcome_branch")

    def test_component_path_model_executes_transfer_v2_directly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = transfer_row(
                expression={
                    "op": "sign_extend",
                    "args": [
                        {"op": "const", "value": 8, "width": 32},
                        {"op": "reg", "name": "eax", "width": 32},
                    ],
                }
            )
            row["outcome"] = {
                "kind": "return",
                "value": {"op": "reg", "name": "eax", "width": 32},
            }
            machine = root / "machine-ir.jsonl"
            machine.write_text(
                json.dumps(as_machine_ir_unit(row), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            plan = write_fixture_transfer_plan(machine)
            universe = load_transfer_v2_refinement_universe(
                transfer_plan=plan,
                required_unit_ids=[row["id"]],
            )
            unit = universe.units[row["id"]]
            self.assertNotIn("outcome", unit["semantics"])
            self.assertEqual(
                unit["semantics"]["transfer_v2"]["terminator"]["op"],
                "outcome_return",
            )
            interface = self._scalar_interface()
            model = build_operation_path_model(
                self._scalar_operation(unit),
                interface,
                [],
            )

        self.assertEqual(len(model["paths"]), 1)
        self.assertEqual(
            model["paths"][0]["results"]["result"],
            {
                "op": "sign_extend",
                "args": [8, {"op": "parameter", "name": "value"}],
            },
        )

    def test_instruction_local_undefined_flag_may_be_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = transfer_row(expression={"op": "reg", "name": "eax", "width": 32})
            row["outcome"] = {
                "kind": "return",
                "value": {"op": "reg", "name": "eax", "width": 32},
            }
            machine = root / "machine-ir.jsonl"
            machine.write_text(
                json.dumps(as_machine_ir_unit(row), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            plan = write_fixture_transfer_plan(machine)
            universe = load_transfer_v2_refinement_universe(
                transfer_plan=plan,
                required_unit_ids=[row["id"]],
            )
            unit = copy.deepcopy(universe.units[row["id"]])
            transfer = unit["semantics"]["transfer_v2"]
            expressions = transfer["expressions"]
            effects = transfer["effects"]
            undefined_id = len(expressions)
            false_id = undefined_id + 1
            expressions.extend(
                [
                    {
                        "id": undefined_id,
                        "op": "undefined_flag",
                        "operands": [],
                        "parameters": {
                            "aux": 0,
                            "identity": "fixture:of",
                            "immediate": 47,
                        },
                        "result_sort": "predicate",
                        "width_bits": 1,
                    },
                    {
                        "id": false_id,
                        "op": "false",
                        "operands": [],
                        "parameters": {"aux": 0, "identity": None, "immediate": 0},
                        "result_sort": "predicate",
                        "width_bits": 1,
                    },
                ]
            )
            effects.extend(
                [
                    {
                        "id": len(effects),
                        "op": "eval_word",
                        "operands": [undefined_id],
                        "parameters": {"aux": 0},
                    },
                    {
                        "id": len(effects) + 1,
                        "op": "set_flag",
                        "operands": [undefined_id],
                        "parameters": {"aux": 3},
                    },
                    {
                        "id": len(effects) + 2,
                        "op": "eval_word",
                        "operands": [false_id],
                        "parameters": {"aux": 0},
                    },
                    {
                        "id": len(effects) + 3,
                        "op": "set_flag",
                        "operands": [false_id],
                        "parameters": {"aux": 3},
                    },
                ]
            )
            model = build_operation_path_model(
                self._scalar_operation(unit), self._scalar_interface(), []
            )

        self.assertEqual(
            model["paths"][0]["results"]["result"],
            {"op": "parameter", "name": "value"},
        )

    def test_observable_undefined_machine_value_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = transfer_row(
                expression={
                    "op": "undefined_bv",
                    "id": "fixture:eax",
                    "reason": "fixture",
                }
            )
            row["outcome"] = {
                "kind": "return",
                "value": {"op": "reg", "name": "eax", "width": 32},
            }
            machine = root / "machine-ir.jsonl"
            machine.write_text(
                json.dumps(as_machine_ir_unit(row), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            plan = write_fixture_transfer_plan(machine)
            universe = load_transfer_v2_refinement_universe(
                transfer_plan=plan,
                required_unit_ids=[row["id"]],
            )
            unit = universe.units[row["id"]]
            with self.assertRaisesRegex(
                SemanticPathError, "unmapped machine values: machine_undefined"
            ):
                build_operation_path_model(
                    self._scalar_operation(unit), self._scalar_interface(), []
                )


if __name__ == "__main__":
    unittest.main()
