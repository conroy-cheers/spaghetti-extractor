from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.transfer.evaluator import (
    compare_observations,
    evaluate_transfer_plan_case,
    generated_differential_cases,
    inspect_transfer_plan,
    minimize_mismatch_case,
)
from spaghetti_extractor.transfer.model import TransferPlanError
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit as _test_machine_ir_unit,
    transfer_row as _row,
    write_fixture_transfer_plan as _write_transfer_plan,
)
from tests.unit.candidate.test_transfer_plan import _write_machine


class TransferPlanEvaluatorTests(unittest.TestCase):
    def _plan(self, root: Path) -> Path:
        machine = root / "machine-ir.jsonl"
        _write_machine(machine, [_test_machine_ir_unit(_row())])
        return _write_transfer_plan(machine)

    def test_v2_preserves_stable_undefined_identity_and_interprets_uses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row(expression={
                "op": "undefined_bv",
                "id": "fixture:undefined:eax",
                "reason": "fixture",
                "defined_value": {"op": "const", "value": 0, "width": 32},
            })
            _write_machine(machine, [_test_machine_ir_unit(row)])
            plan = _write_transfer_plan(machine)
            payload, transfers = load_executable_transfer_plan(
                plan, require_complete=True
            )
            undefined = next(
                node for node in transfers[0].nodes
                if node.op == "undefined_bv"
            )
            self.assertEqual(undefined.identity, "fixture:undefined:eax")
            analysis = payload["diagnostics"]["transfer_definedness"]
            self.assertEqual(analysis["status"], "complete")
            self.assertEqual(analysis["counts"]["undefined_nodes"], 1)
            self.assertEqual(
                analysis["slots"][0]["classification"], "behavior_relevant"
            )
            self.assertEqual(payload["counts"]["undefined_nodes"], 1)

    def test_host_evaluator_uses_canonical_width_value_sign_extend_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row(expression={
                "op": "sign_extend",
                "args": [
                    {"op": "const", "value": 8, "width": 32},
                    {"op": "const", "value": 0x80, "width": 32},
                ],
            })
            _write_machine(machine, [_test_machine_ir_unit(row)])
            observed = evaluate_transfer_plan_case(
                _write_transfer_plan(machine),
                {
                    "format": "spaghetti-extractor-transfer-evaluator-case-v1",
                    "id": "sign-extend-i8",
                    "entry_rva": 0x1000,
                    "state": {},
                    "memory": [],
                    "undefined_values": {},
                },
            )

        self.assertEqual(observed["state"]["registers"]["eax"], 0xFFFFFF80)

    def test_generated_cases_and_comparison_never_authorize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = self._plan(Path(temporary))
            cases = generated_differential_cases(plan)
            self.assertEqual(len(cases), 4)
            observed = evaluate_transfer_plan_case(plan, cases[0])
            comparison = compare_observations(observed, observed)
            self.assertEqual(comparison["status"], "match")
            self.assertEqual(comparison["authority"], "none; mismatch veto only")
            changed = json.loads(json.dumps(observed))
            changed["state"]["registers"]["eax"] ^= 1
            self.assertEqual(
                compare_observations(observed, changed)["status"], "mismatch"
            )
            view = inspect_transfer_plan(plan)
            self.assertEqual(view["authority"], "none; inspection only")
            self.assertEqual(view["units"][0]["id"], "semantic-transfer:fixture")

            def expected(case):
                return evaluate_transfer_plan_case(plan, case)

            def divergent(case):
                value = json.loads(json.dumps(expected(case)))
                value["result"]["value"] ^= 1
                return value

            noisy = json.loads(json.dumps(cases[0]))
            noisy["state"]["registers"]["eax"] = 123
            minimized = minimize_mismatch_case(noisy, expected, divergent)
            self.assertEqual(minimized["state"]["registers"]["eax"], 0)

    def test_stale_self_hash_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = self._plan(Path(temporary))
            payload = json.loads(plan.read_text(encoding="utf-8"))
            payload["entry_targets"] = []
            plan.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                TransferPlanError, "self hash is stale"
            ):
                load_executable_transfer_plan(plan)

    def test_typed_nodes_dense_ids_and_terminators_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = self._plan(Path(temporary))
            original = json.loads(plan.read_text(encoding="utf-8"))
            corruptions = (
                (
                    lambda value: value["transfers"][0]["expressions"][0].update(
                        {"id": 1}
                    ),
                    "dense ID",
                ),
                (
                    lambda value: value["transfers"][0]["expressions"][0].update(
                        {"result_sort": "predicate"}
                    ),
                    "type metadata",
                ),
                (
                    lambda value: value["transfers"][0]["terminator"].update(
                        {"op": "outcome_unknown"}
                    ),
                    "terminator operation",
                ),
            )
            for mutate, message in corruptions:
                with self.subTest(message=message):
                    payload = json.loads(json.dumps(original))
                    mutate(payload)
                    payload["plan_sha256"] = canonical_sha256_v3({
                        key: item
                        for key, item in payload.items()
                        if key != "plan_sha256"
                    })
                    plan.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(TransferPlanError, message):
                        load_executable_transfer_plan(plan)

    def test_transfer_plan_v1_has_no_compatibility_reader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = self._plan(Path(temporary))
            payload = json.loads(plan.read_text(encoding="utf-8"))
            payload["format"] = "spaghetti-extractor-executable-transfer-plan-v1"
            payload["plan_sha256"] = canonical_sha256_v3({
                key: item for key, item in payload.items() if key != "plan_sha256"
            })
            plan.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(TransferPlanError, "format is unsupported"):
                load_executable_transfer_plan(plan)

    def test_typed_byte_counts_are_not_raw_instruction_material(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            unit = _test_machine_ir_unit(_row())
            unit["abi_envelope"] = {
                "stack_cleanup": {"kind": "caller", "bytes": 0}
            }
            _write_machine(machine, [unit])
            payload, _ = load_executable_transfer_plan(
                _write_transfer_plan(machine), require_complete=True
            )
            self.assertEqual(payload["status"], "complete")

            unit["instructions"] = [{"bytes": "90"}]
            _write_machine(machine, [unit])
            with self.assertRaisesRegex(
                TransferPlanError, "raw instruction material"
            ):
                _write_transfer_plan(machine)


if __name__ == "__main__":
    unittest.main()
