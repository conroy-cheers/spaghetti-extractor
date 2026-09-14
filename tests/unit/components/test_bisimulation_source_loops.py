"""Finite internal C loops use checked progress, without synthetic proof APIs."""

import copy
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation import (
    BisimulationOperationV1, ComponentBisimulationError, scan_source_proof_markers,
)
from spaghetti_extractor.components.bisimulation_execution import (
    property_checker_command, _cbmc_cover_queries,
)
from tests.unit.components import test_bisimulation_refinement_integration as integration

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"),
           "resources": ("nix/jq/strong-contextual-proof.jq",)}


class SourceLoopTests(unittest.TestCase):
    def test_explicit_limit_admits_an_internal_loop_without_claiming_a_cut(self):
        operation = {"operation_id": "run", "syncs": [], "source_unwind_limit": 3}
        parsed = BisimulationOperationV1.parse(operation, "fixture")
        self.assertEqual(parsed.to_payload(), operation)
        source = "SPX_PROOF_BEGIN(run); for (unsigned k=0; k<2; ++k) { output[k]=input[k]; }"
        markers = scan_source_proof_markers(source, operation_id="run", expected_syncs=[],
                                            source_unwind_limit=parsed.source_unwind_limit)
        self.assertEqual((markers.loop_count, markers.annotated_loop_count), (1, 0))
        with self.assertRaisesRegex(ComponentBisimulationError, "unannotated"):
            scan_source_proof_markers(source, operation_id="run", expected_syncs=[])
        for invalid in (None, True, False, 0, -1, 65537, 3.0, "3"):
            with self.subTest(invalid=invalid), self.assertRaises(ComponentBisimulationError):
                BisimulationOperationV1.parse({**operation, "source_unwind_limit": invalid}, "fixture")

    def check_operation(self, mutation, limit):
        case = integration.BisimulationRefinementIntegrationTests()
        return case._check_acyclic_operation(mutation=mutation, source_unwind_limit=limit)

    def test_full_paired_engine_checks_an_ordinary_finite_loop(self):
        result = self.check_operation("finite_loop", 3)
        self.assertEqual(result["status"], "satisfied", result["issues"])
        commands = result["bindings"]["operation_models"][0]["obligation_models"][0]
        arguments = commands["property_checker_command"]["assertion_arguments"]
        self.assertEqual(arguments[arguments.index("--unwind") + 1], "3")
        self.assertIn("--no-self-loops-to-assumptions", arguments)

    def test_insufficient_limit_is_not_an_assumed_precondition(self):
        result = self.check_operation("finite_loop", 1)
        self.assertEqual(result["status"], "violated", result["issues"])

    def test_empty_divergent_loop_cannot_be_replaced_with_an_assumption(self):
        result = self.check_operation("diverge", 3)
        self.assertNotEqual(result["status"], "satisfied", result["issues"])
        self.assertTrue(any("unwind" in str(row) for row in result["issues"]), result["issues"])

    def test_jq_binds_limit_and_progress_policy_to_the_planned_operation(self):
        command = property_checker_command([], source_unwind_limit=3)
        queries = _cbmc_cover_queries(cbmc=Path("cbmc"), goto_model=Path("model.goto"),
            proof_function="main_relation", witness_functions=["witness"], source_unwind_limit=3)
        model = {"property_checker_command": command, "nonvacuity_checker_command": {
            "queries": [{"arguments": row["command"][2:]} for row in queries]}}
        system = {"proof_plan": {"operations": [{"operation_id": "run", "source": {
            "source_unwind_limit": 3}}]}, "proof": {"models": {"operation_models": [
                {"operation_id": "run", "obligation_models": [model]}]}}}
        module = Path(__file__).resolve().parents[3] / "nix/jq/strong-contextual-proof.jq"
        for mutation in (None, "limit", "null", "drop", "self_loop", "coverage"):
            value = copy.deepcopy(system)
            source = value["proof_plan"]["operations"][0]["source"]
            changed = value["proof"]["models"]["operation_models"][0]["obligation_models"][0]
            if mutation == "limit": source["source_unwind_limit"] = 4
            elif mutation == "null": source["source_unwind_limit"] = None
            elif mutation == "drop": source.clear()
            elif mutation == "self_loop":
                changed["property_checker_command"]["assertion_arguments"].remove("--no-self-loops-to-assumptions")
            elif mutation == "coverage":
                changed["nonvacuity_checker_command"]["queries"][0]["arguments"].remove("--no-self-loops-to-assumptions")
            checked = subprocess.run([shutil.which("jq"), "-e", module.read_text()+"\nspx_source_unwind_commands"],
                input=json.dumps(value), text=True, capture_output=True)
            self.assertEqual(checked.returncode, 0 if mutation is None else 1, checked.stderr)


if __name__ == "__main__":
    unittest.main()
