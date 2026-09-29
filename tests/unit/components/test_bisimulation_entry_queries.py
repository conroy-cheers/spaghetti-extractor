"""The same coverage observer supports entry safety and nonvacuity checks."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_harness import COVER_OBSERVER
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties, run_cbmc_cover


TESTKIT = {"fixtures": ("cbmc", "compiler")}


class EntryQueryObserverTests(unittest.TestCase):
    def check(self, *, definition=COVER_OBSERVER, cover=False, entry="check", stop=False):
        compiler, checker = (shutil.which(name) for name in ("goto-cc", "cbmc"))
        if compiler is None or checker is None:
            self.skipTest("CBMC compiler tools unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, model = root / "source.c", root / "model.goto"
            source.write_text(definition + "\nunsigned count;\n"
                "void witness(void) { __CPROVER_cover(++count == 1); }\n"
                "void check(void) { count=0; witness(); __CPROVER_assert(count==1, \"argument-effect\"); }\n"
                "void empty(void) { __CPROVER_assume(0); witness(); }\n")
            run = subprocess.run([compiler, "--i386-win32", str(source), "-o", str(model)],
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            command = [checker, str(model), "--json-ui", "--function", entry]
            if stop:
                command.append("--stop-on-fail")
            if cover:
                return run_cbmc_cover(command=[*command, "--cover", "cover"],
                    expected_functions=["witness"], timeout_seconds=10)
            return run_cbmc_properties(command=[*command, "--unwinding-assertions"], timeout_seconds=10)

    def test_observer_preserves_argument_effects_and_reachable_coverage(self):
        self.assertEqual(self.check()["status"], "satisfied")
        self.assertEqual(self.check(cover=True)["status"], "satisfied")

    def test_unreachable_observer_does_not_establish_nonvacuity(self):
        self.assertNotEqual(self.check(cover=True, entry="empty")["status"], "satisfied")

    def test_missing_body_is_incomplete_and_cannot_qualify(self):
        for stop in (False, True):
            with self.subTest(stop=stop):
                result = self.check(definition="void __CPROVER_cover(__CPROVER_bool condition);", stop=stop)
                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(result["code"], "cbmc_missing_function_body")
                self.assertIn("no body for callee __CPROVER_cover", result["detail"])

    def test_authored_assertion_with_missing_body_text_remains_a_mismatch(self):
        result = self.check(definition=COVER_OBSERVER + '\n'
            'void mismatch(void) { __CPROVER_assert(0, "no body for callee __CPROVER_cover"); }',
            entry="mismatch")
        self.assertEqual(result["status"], "violated")
        self.assertEqual(result["code"], "cbmc_counterexample")

    def test_missing_body_does_not_hide_an_independent_mismatch(self):
        result = self.check(definition='void unknown(void);\n'
            'void mismatch(void) { __CPROVER_assert(0, "known mismatch"); unknown(); }',
            entry="mismatch")
        self.assertEqual(result["status"], "violated")
        self.assertEqual(result["code"], "cbmc_counterexample")
