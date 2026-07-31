from __future__ import annotations

import copy
from pathlib import Path
import shutil
import unittest

from spaghetti_extractor.isa_conformance import (
    ControlClass,
    ObservationStatus,
    ReportQualification,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_corpus,
)
from spaghetti_extractor.isa_conformance_lean import (
    _control_outcome,
    _generated_module,
    _generated_runner_module,
    run_lean_isa_conformance,
    run_lean_isa_conformance_with_forms,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.stage_binary import StageAInputError
from tests.test_stage_a_isa_conformance import _corpus


def _lean_supported_corpus():
    payload = _corpus()
    case = payload["cases"][0]
    case["instruction_bytes"] = [0xB8, 0x78, 0x56, 0x34, 0x12]
    case["expected"]["final_state"]["gprs"]["eax"] = 0x12345678
    case["expected"]["final_state"]["eip"] = 0x00401005
    masks = case["defined_outputs"]
    masks["fs"]["selector"] = 0
    for field in (
        "tag_word",
        "last_opcode",
        "instruction_pointer",
        "data_pointer",
    ):
        masks["x87"][field] = 0
    return payload


class StageAISAConformanceLeanTests(unittest.TestCase):
    def test_lean_compiler_rejects_a_nonpositive_command_timeout(self):
        with self.assertRaisesRegex(StageAInputError, "timeout must be positive"):
            _run_lean_relational(Path("."), command_timeout_seconds=0)

    def test_execution_runner_imports_the_checked_generated_module(self):
        self.assertEqual(
            _generated_runner_module(),
            "import StageA.GeneratedISAConformance\n",
        )

    def test_generated_module_classifies_but_does_not_execute_x87(self):
        payload = _lean_supported_corpus()
        x87_case = copy.deepcopy(payload["cases"][0])
        x87_case["id"] = "x87-load-one"
        x87_case["instruction_bytes"] = [0xD9, 0xE8]
        x87_case["expected"]["final_state"]["eip"] = 0x00401002
        payload["cases"].append(x87_case)
        corpus = parse_isa_conformance_corpus(payload)

        generated = _generated_module(
            list(corpus.cases), executable_case_ids={corpus.cases[0].id}
        )

        self.assertIn(
            'emitISAConformanceClassification "x87-load-one" .i686 '
            "[0xd9, 0xe8]",
            generated,
        )
        self.assertNotIn('emitISAConformanceCase "x87-load-one"', generated)
        self.assertNotIn("conformanceInput1", generated)
        self.assertIn("cpuProfile := .i686", generated)

        haswell_payload = _lean_supported_corpus()
        haswell_payload["cases"][0]["profile"]["cpu"] = "haswell"
        haswell_corpus = parse_isa_conformance_corpus(haswell_payload)
        haswell_generated = _generated_module(
            list(haswell_corpus.cases),
            executable_case_ids={haswell_corpus.cases[0].id},
        )
        self.assertIn("cpuProfile := .haswell", haswell_generated)

    def test_bulk_fill_control_is_a_fallthrough_observation(self):
        control, eip = _control_outcome(
            {"kind": "bulk_fill", "continuation_rva": 0x1234},
            0x400000,
        )
        self.assertEqual(control, ControlClass.FALLTHROUGH)
        self.assertEqual(eip, 0x401234)

    def test_relative_control_target_wraps_as_a_32_bit_eip(self):
        control, eip = _control_outcome(
            {"kind": "call", "target_rva": 0xFFFFD805},
            0x400000,
        )
        self.assertEqual(control, ControlClass.DIRECT_CALL)
        self.assertEqual(eip, 0x003FD805)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_authoritative_semantics_emit_a_mask_checked_veto_only_report(self):
        corpus = parse_isa_conformance_corpus(_lean_supported_corpus())

        report = run_lean_isa_conformance(corpus)

        self.assertEqual(report.qualification, ReportQualification.QUALIFIED)
        self.assertEqual(report.observations[0].status, ObservationStatus.MATCH)
        self.assertEqual(
            report.input_sha256, isa_conformance_corpus_sha256(corpus)
        )
        self.assertFalse(report.trust.proof_authority)
        self.assertFalse(report.trust.closes_stage_a_proof)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_negative_rel32_call_uses_modular_eip_arithmetic(self):
        payload = _lean_supported_corpus()
        case = payload["cases"][0]
        case["instruction_bytes"] = [0xE8, 0x00, 0xC8, 0xFF, 0xFF]
        case["expected"]["control"] = "direct_call"
        case["expected"]["final_state"]["eip"] = 0x003FD805
        case["expected"]["final_state"]["gprs"]["eax"] = case[
            "initial_state"
        ]["gprs"]["eax"]
        case["expected"]["final_state"]["gprs"]["esp"] -= 4

        report = run_lean_isa_conformance(
            parse_isa_conformance_corpus(payload)
        )

        self.assertEqual(report.qualification, ReportQualification.QUALIFIED)
        self.assertEqual(report.observations[0].status, ObservationStatus.MATCH)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_semantic_mismatch_vetoes_and_unqualified_x87_fails_closed(self):
        mismatch_payload = _lean_supported_corpus()
        mismatch_payload["cases"][0]["expected"]["final_state"]["gprs"]["eax"] = 3
        mismatch = run_lean_isa_conformance(
            parse_isa_conformance_corpus(mismatch_payload)
        )
        self.assertEqual(
            mismatch.input_sha256,
            isa_conformance_corpus_sha256(
                parse_isa_conformance_corpus(mismatch_payload)
            ),
        )
        self.assertEqual(mismatch.qualification, ReportQualification.VETOED)
        self.assertEqual(
            mismatch.observations[0].status, ObservationStatus.MISMATCH
        )

        mixed_payload = copy.deepcopy(_lean_supported_corpus())
        mixed_payload["cases"][0]["id"] = "supported-mov"
        x87_case = copy.deepcopy(mixed_payload["cases"][0])
        x87_case["id"] = "x87-load-one"
        x87_case["instruction_bytes"] = [0xD9, 0xE8]
        x87_case["expected"]["final_state"]["eip"] = 0x00401002
        mixed_payload["cases"].append(x87_case)
        mixed_corpus = parse_isa_conformance_corpus(mixed_payload)
        mixed, semantic_forms = run_lean_isa_conformance_with_forms(mixed_corpus)

        self.assertEqual(mixed.qualification, ReportQualification.UNQUALIFIED)
        self.assertEqual(mixed.observations[0].status, ObservationStatus.MATCH)
        self.assertEqual(mixed.observations[1].status, ObservationStatus.UNSUPPORTED)
        self.assertIn(
            "not yet concretely hardware-qualified",
            mixed.observations[1].detail,
        )
        self.assertEqual(set(semantic_forms), {"supported-mov", "x87-load-one"})
        self.assertIn("x87LoadConstant", semantic_forms["x87-load-one"])


if __name__ == "__main__":
    unittest.main()
