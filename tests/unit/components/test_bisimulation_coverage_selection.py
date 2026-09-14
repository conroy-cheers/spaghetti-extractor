"""A region's witness inventory is independent of other entries in its model."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_execution import _cbmc_cover_queries, property_checker_command
from spaghetti_extractor.components.bisimulation_reference_authority import reference_authority_unwind_arguments
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover
from tests.unit.components.test_bisimulation_reference_authority import authority_payload

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"),
           "resources": ("nix/jq/strong-contextual-proof.jq",)}


class CoverageSelectionTests(unittest.TestCase):
    def test_reference_bounds_bind_shard_calls_and_imported_instances_in_every_query(self):
        authority = authority_payload(locator="external_allocation")
        module = Path(__file__).resolve().parents[3] / "nix/jq/strong-contextual-proof.jq"
        for calls, inputs in ((1, 0), (1, 4), (5, 0)):
            capacity = calls + inputs
            arguments = reference_authority_unwind_arguments(authority, allocation_capacity=capacity)
            query, = _cbmc_cover_queries(cbmc=Path("cbmc"), goto_model=Path("model.goto"),
                proof_function="main", witness_functions=["witness"], reference_authority=authority,
                allocation_capacity=capacity)
            model = {"model_bounds": {"maximum_calls": calls},
                "property_checker_command": property_checker_command(arguments),
                "nonvacuity_checker_command": {"queries": [{"arguments": query["command"][2:]}]}}
            proof = {"models": {"reference_authority": authority, "operation_models": [{
                "maximum_input_allocations": inputs, "obligation_models": [model]}]}}
            for mutation in (None, "missing", "wrong", "duplicate", "extra", "changed_capacity"):
                changed = copy.deepcopy(proof)
                operation = changed["models"]["operation_models"][0]
                row = operation["obligation_models"][0]
                args = row["nonvacuity_checker_command"]["queries"][0]["arguments"]
                index = args.index("--unwindset")
                if mutation == "missing":
                    del args[index:index + 2]
                elif mutation == "wrong":
                    args[index + 1] = args[index + 1].replace(
                        f"resolve_reference.0:{capacity + 1}", "resolve_reference.0:99")
                elif mutation == "duplicate":
                    args += args[index:index + 2]
                elif mutation == "extra":
                    args[index + 1] += ",spx_proof_authority_unknown.0:99"
                elif mutation == "changed_capacity":
                    operation["maximum_input_allocations"] += 1
                result = subprocess.run([shutil.which("jq"), "-e",
                    module.read_text() + "\nspx_reference_unwind_commands"],
                    input=json.dumps(changed), capture_output=True, text=True, timeout=30)
                with self.subTest(calls=calls, inputs=inputs, mutation=mutation):
                    self.assertEqual(result.returncode, 0 if mutation is None else 1, result.stderr)

    def test_aggregate_ignores_other_entries_but_requires_every_requested_witness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "witness.c"
            source.write_text('''
void first(void) { __CPROVER_cover(1); }
void second(void) { __CPROVER_cover(1); }
void third(void) { __CPROVER_cover(1); }
void unrelated(void) { __CPROVER_cover(1); }
void other_entry(void) { unrelated(); }
int nondet(void);
int main(void) {
  int choice = nondet();
  if (choice == 0) first();
  if (choice == 1) second();
#ifndef MISSING_THIRD
  if (choice == 2) third();
#endif
  return 0;
}
''')
            for missing in (False, True):
                model = root / ("missing.goto" if missing else "complete.goto")
                compiled = subprocess.run([shutil.which("goto-cc"),
                    *(["-DMISSING_THIRD"] if missing else []), str(source), "-o", str(model)],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                query, = _cbmc_cover_queries(cbmc=Path(shutil.which("cbmc")), goto_model=model,
                    proof_function="main", witness_functions=["first", "second", "third"])
                result = run_cbmc_cover(command=query["command"],
                    expected_functions=query["expected_functions"], timeout_seconds=30)
                with self.subTest(missing=missing):
                    self.assertEqual(result["status"], "incomplete" if missing else "satisfied", result)
                if missing:
                    continue
                self.assertEqual(result["witnessed_functions"], ["first", "second", "third"])
                # Retain the former behavior as a regression witness: an
                # unreachable goal owned by another entry spoils the aggregate.
                old = [item for index, item in enumerate(query["command"])
                       if item != "--property" and query["command"][index - 1] != "--property"]
                result = run_cbmc_cover(command=old, expected_functions=query["expected_functions"],
                                       timeout_seconds=30)
                self.assertEqual(result["status"], "incomplete", result)

    def test_independent_reader_rejects_omitted_extra_and_repeated_goals(self):
        functions = ["first", "second", "third"]
        query, = _cbmc_cover_queries(cbmc=Path("cbmc"), goto_model=Path("model.goto"),
            proof_function="main", witness_functions=functions)
        model = {"witness_functions": functions, "nonvacuity_checker_command": {"queries": [
            {"functions": functions, "arguments": query["command"][2:]}]}}
        module = Path(__file__).resolve().parents[3] / "nix/jq/strong-contextual-proof.jq"
        for mutation in (None, "omitted", "extra", "repeat", "unselected"):
            changed = copy.deepcopy(model)
            args = changed["nonvacuity_checker_command"]["queries"][0]["arguments"]
            if mutation == "omitted":
                index = args.index("third.coverage.1")
                del args[index - 1:index + 1]
            elif mutation == "extra":
                args += ["--property", "unrelated.coverage.1"]
            elif mutation == "repeat":
                args += ["--property", "first.coverage.1"]
            elif mutation == "unselected":
                changed["witness_functions"].append("absent")
            proof = {"models": {"operation_models": [{"obligation_models": [changed]}]}}
            result = subprocess.run([shutil.which("jq"), "-e",
                module.read_text() + "\nspx_nonvacuity_goal_selection"],
                input=json.dumps(proof), capture_output=True, text=True, timeout=30)
            with self.subTest(mutation=mutation):
                self.assertEqual(result.returncode, 0 if mutation is None else 1, result.stderr)


if __name__ == "__main__":
    unittest.main()
