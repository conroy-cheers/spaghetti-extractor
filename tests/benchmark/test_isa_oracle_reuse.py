from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path

from spaghetti_extractor.isa_conformance import ReportQualification
from spaghetti_extractor.isa_conformance_lean import run_lean_isa_conformance
from spaghetti_extractor.isa_conformance_unicorn import run_unicorn_corpus
from tests.test_stage_a_isa_conformance_80386 import _import, _source_row


TESTKIT = {
    "capabilities": ["benchmark", "isa", "lean"],
    "fixtures": ["lean-isa-runner"],
}

MAX_WARM_PAIR_SECONDS = 10.0


class ISAOracleReuseBenchmark(unittest.TestCase):
    def test_shared_lean_runner_keeps_differential_pair_interactive(self) -> None:
        self.assertTrue(
            os.environ.get("SPAGHETTI_LEAN_KERNEL_CACHE"),
            "benchmark must consume the shared Nix Lean fixture",
        )
        started = time.monotonic()
        with tempfile.TemporaryDirectory() as temporary:
            imported = _import(Path(temporary), [_source_row()])
            lean = run_lean_isa_conformance(imported.corpus)
            unicorn = run_unicorn_corpus(imported.corpus)

        self.assertEqual(lean.qualification, ReportQualification.QUALIFIED, lean)
        self.assertEqual(unicorn.qualification, ReportQualification.QUALIFIED, unicorn)
        self.assertEqual(
            lean.observations[0].final_state,
            unicorn.observations[0].final_state,
        )
        self.assertLess(time.monotonic() - started, MAX_WARM_PAIR_SECONDS)


if __name__ == "__main__":
    unittest.main()
