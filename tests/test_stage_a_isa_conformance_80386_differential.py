from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.isa_conformance import ReportQualification
from spaghetti_extractor.isa_conformance_lean import run_lean_isa_conformance
from spaghetti_extractor.isa_conformance_unicorn import (
    run_unicorn_corpus,
    unicorn_available,
)
from tests.test_stage_a_isa_conformance_80386 import _import, _source_row


class StageAISAConformance80386DifferentialTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    @unittest.skipUnless(unicorn_available(), "Unicorn is required")
    def test_hardware_auxiliary_carry_vector_matches_lean_and_unicorn(self):
        with tempfile.TemporaryDirectory() as temporary:
            imported = _import(Path(temporary), [_source_row()])
            lean = run_lean_isa_conformance(imported.corpus)
            unicorn = run_unicorn_corpus(imported.corpus)

        self.assertEqual(lean.qualification, ReportQualification.QUALIFIED, lean)
        self.assertEqual(
            unicorn.qualification, ReportQualification.QUALIFIED, unicorn
        )
        self.assertEqual(
            lean.observations[0].final_state,
            unicorn.observations[0].final_state,
        )
        self.assertEqual(lean.observations[0].final_state.eflags & 0x10, 0x10)
        self.assertFalse(lean.trust.proof_authority)
        self.assertFalse(unicorn.trust.proof_authority)


if __name__ == "__main__":
    unittest.main()
