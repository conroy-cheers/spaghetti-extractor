"""Same-entry unwind reuse requires a completed proof and does not cover other entries."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_diagnostics import ProofQueryTimings
from spaghetti_extractor.components.bisimulation_execution import property_checker_command, _run_partitioned_properties

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"),
           "resources": ("nix/jq/strong-contextual-proof.jq",)}


class EntryUnwindingTests(unittest.TestCase):
    def check(self, source, descriptions):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "region.c"
            model = root / "model.goto"
            # Include a real memory access so the production safety inventory
            # has a slicing criterion even for an otherwise scalar example.
            path.write_text("static unsigned state;\nstatic void reset(unsigned *p) { *p=0U; }\n"
                "static void dispatch(void (*f)(unsigned *)) { f(&state); }\n" +
                source.replace("int main(void) {", "int main(void) { dispatch(reset);"))
            compiled = subprocess.run([shutil.which("goto-cc"), "--i386-win32", str(path), "-o", str(model)],
                capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = _run_partitioned_properties(cbmc=Path(shutil.which("cbmc")), goto_model=model,
                command=property_checker_command([]), proof_function="main",
                required_assertion_descriptions=sorted(descriptions), timeout_seconds=30,
                timings=ProofQueryTimings(model, {"scope":"unwind reuse fixture"}))
            rows = [json.loads(line) for line in (root / "query-timings.jsonl").read_text().splitlines()]
            return result, rows

    def test_entry_assertion_consumes_the_satisfied_unsliced_unwind_partition(self):
        result, rows = self.check('''
unsigned nondet(void) { unsigned value; __CPROVER_havoc_object(&value); return value; }
int main(void) {
  unsigned limit=nondet(), i=0U;
  __CPROVER_assume(limit<2U);
  while (i<limit) ++i;
  __CPROVER_assert(i==limit,"counter reaches its admitted limit");
}
''', ["counter reaches its admitted limit"])
        self.assertEqual(result["status"], "satisfied", result.get("detail"))
        unwind = next(row for row in rows if row["kind"] == "safety:unwinding")
        assertion = next(row for row in rows if row["kind"].startswith("assertion:"))
        self.assertEqual(unwind["status"], "satisfied")
        self.assertNotIn("--reachability-slice-fb", unwind["command"])
        self.assertIn("--no-unwinding-assertions", assertion["command"])
        self.assertLessEqual(unwind["started_after_seconds"] + unwind["elapsed_seconds"],
                             assertion["started_after_seconds"])

    def test_failed_unwinding_prevents_assertion_queries(self):
        result, rows = self.check('''
int main(void) {
  unsigned i=0U; while (i<3U) ++i;
  __CPROVER_assert(i==3U,"counter reaches its admitted limit");
}
''', ["counter reaches its admitted limit"])
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertFalse(any(row["kind"].startswith("assertion:") for row in rows))

    def test_focused_entry_keeps_unwind_checks_for_its_different_input_world(self):
        result, rows = self.check('''
static unsigned limit;
void spx_proof_typed_service_begin(void) {
  unsigned i=0U; while (i<limit) ++i;
  __CPROVER_assert(i==limit,"spx-bisimulation-typed-call-public-memory:0");
}
int main(void) { limit=1U; spx_proof_typed_service_begin(); }
void main_focus_typed_call_0(void) { limit=3U; spx_proof_typed_service_begin(); }
''', ["spx-bisimulation-typed-call-public-memory:0"])
        self.assertEqual(result["status"], "violated", result.get("detail"))
        unwind = next(row for row in rows if row["kind"] == "safety:unwinding")
        assertion = next(row for row in rows if row["kind"].startswith("assertion:"))
        self.assertEqual(unwind["status"], "satisfied")
        self.assertIn("main_focus_typed_call_0", assertion["command"])
        self.assertIn("--unwinding-assertions", assertion["command"])
        self.assertNotIn("--no-unwinding-assertions", assertion["command"])

    def test_jq_rejects_unbound_entry_query_options(self):
        proof = {"models":{"operation_models":[{"obligation_models":[
            {"property_checker_command":property_checker_command([])}]}]}}
        module = Path(__file__).resolve().parents[3] / "nix/jq/strong-contextual-proof.jq"
        for mutation in (None, "drop", "focused", "extra"):
            value = copy.deepcopy(proof)
            command = value["models"]["operation_models"][0]["obligation_models"][0]["property_checker_command"]
            if mutation == "drop": del command["entry_assertion_arguments"]
            elif mutation == "focused": command["assertion_arguments"] = command["entry_assertion_arguments"]
            elif mutation == "extra": command["entry_assertion_arguments"].append("--no-assertions")
            result = subprocess.run([shutil.which("jq"), "-e", module.read_text()+"\nspx_entry_unwinding_commands"],
                input=json.dumps(value), text=True, capture_output=True)
            self.assertEqual(result.returncode, 0 if mutation is None else 1, result.stderr)
