from __future__ import annotations

import shutil
import unittest

from spaghetti_extractor.isa_conformance import ReportQualification
from spaghetti_extractor.isa_conformance_lean import run_lean_isa_conformance
from spaghetti_extractor.isa_conformance_unicorn import (
    run_unicorn_corpus,
    unicorn_available,
)
from tests.test_stage_a_isa_conformance_unicorn import _corpus


class StageAISAConformanceDifferentialTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    @unittest.skipUnless(unicorn_available(), "Unicorn is required")
    def test_lean_and_unicorn_match_the_same_masked_haswell_case(self):
        corpus = _corpus()

        lean_report = run_lean_isa_conformance(corpus)
        unicorn_report = run_unicorn_corpus(corpus)

        self.assertEqual(
            lean_report.qualification, ReportQualification.QUALIFIED, lean_report
        )
        self.assertEqual(
            unicorn_report.qualification,
            ReportQualification.QUALIFIED,
            unicorn_report,
        )
        self.assertEqual(
            lean_report.observations[0].final_state,
            unicorn_report.observations[0].final_state,
        )
        self.assertFalse(lean_report.trust.proof_authority)
        self.assertFalse(unicorn_report.trust.proof_authority)


if __name__ == "__main__":
    unittest.main()
