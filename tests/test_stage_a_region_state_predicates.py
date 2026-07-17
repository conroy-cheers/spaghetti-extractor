import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.contract import _normalize_contract
from spaghetti_extractor.relational.executor import _run_lean_relational
from spaghetti_extractor.relational.lean.generation import (
    _lean_region_definition,
)
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES
from spaghetti_extractor.stage_binary import StageAInputError, _parse_stage_a_pe
from tests.stage_a_relational_support import StageARelationalTestBase


def _region(**updates):
    region = {
        "id": "entry",
        "numeric_id": 0,
        "root": True,
        "original": {"rva_start": 4096, "size": 4},
        "candidate": {"rva_start": 8192, "size": 4},
        "inputs": [],
        "outputs": [],
    }
    region.update(updates)
    return region


def _predicate(**updates):
    predicate = {
        "original": {
            "op": "equal",
            "left": {"op": "input_reg", "reg": "eax"},
            "right": {"op": "constant", "value": 0},
        },
        "candidate": {
            "op": "not",
            "value": {"op": "input_flag", "index": 6},
        },
    }
    predicate.update(updates)
    return predicate


class RegionStatePredicateSerializationTests(StageARelationalTestBase):
    def test_emits_paired_semantic_bool_expressions(self):
        source = _lean_region_definition(
            0,
            _region(state_predicates=[_predicate(source="contract")]),
        )

        self.assertIn(
            "predicates := [{ original := StageA.Formal.BoolExpr.equal "
            "(StageA.Formal.Expr.inputReg (StageA.Formal.Reg.eax)) "
            "(StageA.Formal.Expr.constant 0), candidate := "
            "StageA.Formal.BoolExpr.not "
            "(StageA.Formal.BoolExpr.inputFlag 6) }]",
            source,
        )
        self.assertNotIn("contract", source)

    def test_absent_field_is_omitted_and_present_empty_field_is_emitted(self):
        self.assertNotIn("predicates :=", _lean_region_definition(0, _region()))
        self.assertIn(
            "predicates := []",
            _lean_region_definition(0, _region(state_predicates=[])),
        )

    def test_malformed_rows_fail_closed(self):
        malformed = {
            "non_list": {"original": {}, "candidate": {}},
            "non_object_row": [None],
            "missing_candidate": [
                {"original": {"op": "bool_constant", "value": True}}
            ],
            "unexpected_field": [_predicate(label="not-source")],
            "non_string_source": [_predicate(source=7)],
            "non_object_expression": [_predicate(original=[])],
            "unsupported_bool_operation": [_predicate(original={"op": "unknown"})],
            "malformed_nested_expression": [
                _predicate(original={"op": "not", "value": []})
            ],
        }

        for name, state_predicates in malformed.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(StageAInputError, "state_predicates"):
                    _lean_region_definition(
                        0,
                        _region(state_predicates=state_predicates),
                    )

    @unittest.skipUnless(
        shutil.which("lean"),
        "Lean is required for literal replay",
    )
    def test_generated_region_literal_is_accepted_by_lean(self):
        definition = _lean_region_definition(
            0,
            _region(state_predicates=[_predicate()]),
        )
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src"
                / "spaghetti_extractor"
                / "lean"
                / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            (stage_a / "RegionStatePredicates.lean").write_text(
                "import StageA.Relational\n\n"
                "namespace StageA.RegionStatePredicates\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                + definition
                + "\n\n"
                "example : region0.inputInvariant.predicates.length = 1 := by decide\n\n"
                "end StageA.RegionStatePredicates\n",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir,
                bundle="RegionStatePredicates",
            )
            self.assertEqual(result["status"], "checked", result)

    def test_contract_normalization_preserves_only_valid_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = _parse_stage_a_pe(
                self._write_pe(root / "original.exe", b"\xc3")
            )
            candidate = _parse_stage_a_pe(
                self._write_pe(root / "candidate.exe", b"\xc3")
            )
            contract_path = self._write_contract(
                root / "relation.json",
                region_size=1,
            )
            base = json.loads(contract_path.read_text(encoding="utf-8"))
            predicates = [_predicate(source="contract")]
            base["regions"][0]["state_predicates"] = predicates

            normalized, issues = _normalize_contract(base, original, candidate)

            self.assertEqual(issues, [])
            self.assertEqual(
                normalized["regions"][0]["state_predicates"],
                predicates,
            )

            malformed = {
                "non_list": {},
                "non_object_row": [None],
                "missing_side": [{"original": {"op": "bool_constant"}}],
                "unexpected_field": [_predicate(label="invalid")],
                "non_string_source": [_predicate(source=1)],
                "non_object_expression": [_predicate(candidate=[])],
            }
            for name, rows in malformed.items():
                with self.subTest(name=name):
                    contract = json.loads(json.dumps(base))
                    contract["regions"][0]["state_predicates"] = rows
                    _normalized, row_issues = _normalize_contract(
                        contract,
                        original,
                        candidate,
                    )
                    self.assertTrue(
                        {
                            "malformed_region_state_predicates",
                            "malformed_region_state_predicate",
                        }
                        & {issue["category"] for issue in row_issues}
                    )


if __name__ == "__main__":
    unittest.main()
