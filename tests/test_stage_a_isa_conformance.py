import copy
import unittest
from dataclasses import FrozenInstanceError, replace

from spaghetti_extractor.isa_conformance import (
    BackendObservation,
    ISA_CONFORMANCE_REPORT_FORMAT,
    ISAConformanceCorpus,
    ISAConformanceError,
    InstructionTestCase,
    ObservationStatus,
    ReportQualification,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_corpus,
    parse_isa_conformance_report,
    serialize_isa_conformance_corpus,
    serialize_isa_conformance_report,
)


GPRS = {
    "eax": 1,
    "ebx": 2,
    "ecx": 3,
    "edx": 4,
    "esi": 5,
    "edi": 6,
    "ebp": 0x70001000,
    "esp": 0x70000FF0,
}


def _x87(*, mask=False):
    fill = 0xFF if mask else 0
    return {
        "control_word": 0xFFFF if mask else 0x037F,
        "status_word": 0xFFFF if mask else 0,
        "tag_word": 0xFFFF,
        "last_opcode": 0x7FF if mask else 0,
        "instruction_pointer": 0xFFFFFFFF if mask else 0,
        "data_pointer": 0xFFFFFFFF if mask else 0,
        "registers": [[fill] * 10 for _ in range(8)],
    }


def _state(*, eip=0x00401000):
    return {
        "gprs": dict(GPRS),
        "eip": eip,
        "eflags": 0x202,
        "fs": {"selector": 0x3B, "base": 0x7FFDF000},
        "x87": _x87(),
    }


def _case(case_id="inc-eax"):
    expected_final_state = _state(eip=0x00401001)
    expected_final_state["gprs"]["eax"] = 2
    payload = {
        "id": case_id,
        "instruction_bytes": [0x40],
        "profile": {
            "architecture": "x86",
            "cpu": "i686",
            "execution_mode": "protected-32",
            "environment": "pe32",
            "features": ["x87"],
        },
        "image_base": 0x00400000,
        "initial_state": _state(),
        "memory": [
            {
                "address": 0x1000,
                "bytes": [0x10, 0x20, 0x30, 0x40],
                "permissions": "rw",
            },
            {
                "address": 0x2000,
                "bytes": [0xC3],
                "permissions": "rx",
            },
        ],
        "defined_outputs": {
            "gprs": {register: 0xFFFFFFFF for register in GPRS},
            "eip": 0xFFFFFFFF,
            "eflags": 0x8D5,
            "fs": {"selector": 0xFFFF, "base": 0xFFFFFFFF},
            "x87": _x87(mask=True),
            "memory": [{"address": 0x1000, "mask": [0xFF] * 4}],
        },
        "expected": {
            "final_state": expected_final_state,
            "memory": [
                {"address": 0x1000, "bytes": [0x10, 0x20, 0x30, 0x40]}
            ],
            "control": "fallthrough",
            "fault": "none",
        },
    }
    payload["defined_outputs"]["gprs"]["ecx"] = 0
    return payload


def _corpus():
    return {
        "format": "stage-a-isa-conformance-corpus-v1",
        "id": "pe32-instruction-core-v1",
        "cases": [_case()],
    }


def _zero_output_masks():
    return {
        "gprs": {register: 0 for register in GPRS},
        "eip": 0,
        "eflags": 0,
        "fs": {"selector": 0, "base": 0},
        "x87": {
            "control_word": 0,
            "status_word": 0,
            "tag_word": 0,
            "last_opcode": 0,
            "instruction_pointer": 0,
            "data_pointer": 0,
            "registers": [[0] * 10 for _ in range(8)],
        },
        "memory": [],
    }


def _observation(case_id="inc-eax"):
    final_state = _state(eip=0x00401001)
    final_state["gprs"]["eax"] = 2
    return {
        "case_id": case_id,
        "status": "match",
        "final_state": final_state,
        "memory": [{"address": 0x1000, "bytes": [0x10, 0x20, 0x30, 0x40]}],
        "actual": {"control": "fallthrough", "fault": "none"},
        "detail": "",
    }


def _report():
    return {
        "format": ISA_CONFORMANCE_REPORT_FORMAT,
        "corpus_id": "pe32-instruction-core-v1",
        "input_sha256": isa_conformance_corpus_sha256(
            parse_isa_conformance_corpus(_corpus())
        ),
        "backend": {"id": "reference-cpu", "kind": "oracle", "version": "1"},
        "qualification": "qualified",
        "observations": [_observation()],
        "counts": {
            "cases": 1,
            "matched": 1,
            "mismatched": 0,
            "unsupported": 0,
            "errors": 0,
        },
        "trust": {
            "role": "isa_conformance_evidence_only",
            "proof_authority": False,
            "closes_stage_a_proof": False,
        },
    }


class StageAISAConformanceTests(unittest.TestCase):
    def test_corpus_round_trip_is_typed_deterministic_and_immutable(self):
        payload = _corpus()
        corpus = parse_isa_conformance_corpus(payload)

        self.assertIsInstance(corpus, ISAConformanceCorpus)
        self.assertIsInstance(corpus.cases[0], InstructionTestCase)
        self.assertEqual(corpus.cases[0].instruction_bytes, b"\x40")
        self.assertEqual(serialize_isa_conformance_corpus(corpus), payload)
        self.assertEqual(ISAConformanceCorpus.parse(payload), corpus)
        self.assertEqual(corpus.to_payload(), payload)
        self.assertEqual(corpus.cases[0].to_payload(), payload["cases"][0])
        with self.assertRaises(FrozenInstanceError):
            corpus.id = "changed"

    def test_unknown_missing_and_non_pe32_profile_fields_are_rejected(self):
        unknown_top = _corpus()
        unknown_top["notes"] = []
        unknown_nested = _corpus()
        unknown_nested["cases"][0]["initial_state"]["mxcsr"] = 0
        missing_mask = _corpus()
        del missing_mask["cases"][0]["defined_outputs"]["eflags"]
        missing_expectation = _corpus()
        del missing_expectation["cases"][0]["expected"]["final_state"]
        wrong_mode = _corpus()
        wrong_mode["cases"][0]["profile"]["execution_mode"] = "long-64"
        ambiguous_eip = _corpus()
        ambiguous_eip["cases"][0]["image_base"] = 0x00500000

        for malformed in (
            unknown_top,
            unknown_nested,
            missing_mask,
            missing_expectation,
            wrong_mode,
            ambiguous_eip,
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ISAConformanceError):
                    parse_isa_conformance_corpus(malformed)

    def test_duplicate_case_ids_are_rejected(self):
        payload = _corpus()
        payload["cases"].append(copy.deepcopy(payload["cases"][0]))

        with self.assertRaisesRegex(ISAConformanceError, "duplicate case IDs"):
            parse_isa_conformance_corpus(payload)

    def test_invalid_byte_ranges_lengths_and_address_wrap_are_rejected(self):
        bad_instruction_byte = _corpus()
        bad_instruction_byte["cases"][0]["instruction_bytes"] = [256]
        too_long = _corpus()
        too_long["cases"][0]["instruction_bytes"] = [0x66] * 16
        bad_memory_byte = _corpus()
        bad_memory_byte["cases"][0]["memory"][0]["bytes"][0] = -1
        short_x87 = _corpus()
        short_x87["cases"][0]["initial_state"]["x87"]["registers"][0] = [0] * 9
        wrapping_region = _corpus()
        wrapping_region["cases"][0]["memory"] = [
            {"address": 0xFFFFFFFF, "bytes": [0, 1], "permissions": "r"}
        ]

        for malformed in (
            bad_instruction_byte,
            too_long,
            bad_memory_byte,
            short_x87,
            wrapping_region,
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ISAConformanceError):
                    parse_isa_conformance_corpus(malformed)

    def test_overlapping_mapped_memory_and_output_masks_are_rejected(self):
        overlapping_memory = _corpus()
        overlapping_memory["cases"][0]["memory"].append(
            {"address": 0x1003, "bytes": [0, 1], "permissions": "rw"}
        )
        overlapping_masks = _corpus()
        overlapping_masks["cases"][0]["defined_outputs"]["memory"].append(
            {"address": 0x1003, "mask": [0xFF, 0xFF]}
        )

        for malformed in (overlapping_memory, overlapping_masks):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(ISAConformanceError, "overlapping"):
                    parse_isa_conformance_corpus(malformed)

    def test_control_and_fault_classes_must_agree(self):
        fault_without_fault_control = _corpus()
        fault_without_fault_control["cases"][0]["expected"].update(
            control="fallthrough", fault="invalid_opcode"
        )
        fault_control_without_fault = _corpus()
        fault_control_without_fault["cases"][0]["expected"].update(
            control="fault", fault="none"
        )

        for malformed in (fault_without_fault_control, fault_control_without_fault):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ISAConformanceError):
                    parse_isa_conformance_corpus(malformed)

    def test_expected_values_and_masks_are_complete_and_consistent(self):
        missing_nonfault_state = _corpus()
        missing_nonfault_state["cases"][0]["expected"]["final_state"] = None
        missing_nonfault_state["cases"][0]["expected"]["memory"] = None
        mismatched_memory_inventory = _corpus()
        mismatched_memory_inventory["cases"][0]["expected"]["memory"][0][
            "address"
        ] = 0x1001

        for malformed in (missing_nonfault_state, mismatched_memory_inventory):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ISAConformanceError):
                    parse_isa_conformance_corpus(malformed)

        fault_case = _case("invalid-opcode")
        fault_case["instruction_bytes"] = [0x0F, 0x0B]
        fault_case["expected"].update(
            final_state=None,
            memory=None,
            control="fault",
            fault="invalid_opcode",
        )
        fault_case["defined_outputs"] = _zero_output_masks()
        fault_corpus = _corpus()
        fault_corpus["cases"] = [fault_case]

        parsed = parse_isa_conformance_corpus(fault_corpus)
        self.assertIsNone(parsed.cases[0].expected.final_state)
        self.assertIsNone(parsed.cases[0].expected.memory)

        fault_report = _report()
        fault_report["observations"][0].update(
            case_id="invalid-opcode",
            final_state=None,
            memory=None,
            actual={"control": "fault", "fault": "invalid_opcode"},
        )
        fault_report["input_sha256"] = isa_conformance_corpus_sha256(parsed)
        parsed_report = parse_isa_conformance_report(
            fault_report, corpus=parsed
        )
        self.assertEqual(
            parsed_report.qualification, ReportQualification.QUALIFIED
        )

        nonzero_fault_mask = copy.deepcopy(fault_corpus)
        nonzero_fault_mask["cases"][0]["defined_outputs"]["eflags"] = 1
        with self.assertRaisesRegex(ISAConformanceError, "zero state masks"):
            parse_isa_conformance_corpus(nonzero_fault_mask)

    def test_observations_require_every_output_field_or_explicit_nulls(self):
        complete = BackendObservation.parse(_observation())
        self.assertEqual(complete.status, ObservationStatus.MATCH)
        self.assertEqual(complete.to_payload(), _observation())

        missing_state = _observation()
        del missing_state["final_state"]
        null_state = _observation()
        null_state["final_state"] = None
        unsupported_with_outputs = _observation()
        unsupported_with_outputs["status"] = "unsupported"
        unsupported_without_detail = _observation()
        unsupported_without_detail.update(
            status="unsupported",
            final_state=None,
            memory=None,
            actual=None,
            detail="",
        )

        for malformed in (
            missing_state,
            null_state,
            unsupported_with_outputs,
            unsupported_without_detail,
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ISAConformanceError):
                    BackendObservation.parse(malformed)

    def test_masked_comparison_mechanically_verifies_match_and_mismatch(self):
        corpus = parse_isa_conformance_corpus(_corpus())

        masked_out_changes = _report()
        masked_out_changes["observations"][0]["final_state"]["gprs"]["ecx"] = (
            0xDEADBEEF
        )
        masked_out_changes["observations"][0]["final_state"]["eflags"] ^= 1 << 31
        parsed = parse_isa_conformance_report(masked_out_changes, corpus=corpus)
        self.assertEqual(parsed.qualification, ReportQualification.QUALIFIED)

        false_match = _report()
        false_match["observations"][0]["final_state"]["gprs"]["eax"] = 3
        false_memory_match = _report()
        false_memory_match["observations"][0]["memory"][0]["bytes"][0] ^= 1
        false_mismatch = _report()
        false_mismatch["observations"][0]["status"] = "mismatch"
        false_mismatch["qualification"] = "vetoed"
        false_mismatch["counts"].update(matched=0, mismatched=1)

        for malformed in (false_match, false_memory_match, false_mismatch):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(ISAConformanceError, "contradicts"):
                    parse_isa_conformance_report(malformed, corpus=corpus)

        real_mismatch = copy.deepcopy(false_mismatch)
        real_mismatch["observations"][0]["final_state"]["gprs"]["eax"] = 3
        parsed = parse_isa_conformance_report(real_mismatch, corpus=corpus)
        self.assertEqual(parsed.qualification, ReportQualification.VETOED)

    def test_report_round_trip_counts_qualification_and_coverage_fail_closed(self):
        corpus = parse_isa_conformance_corpus(_corpus())
        payload = _report()
        report = parse_isa_conformance_report(payload, corpus=corpus)

        self.assertEqual(report.qualification, ReportQualification.QUALIFIED)
        self.assertEqual(report.input_sha256, isa_conformance_corpus_sha256(corpus))
        self.assertFalse(report.trust.proof_authority)
        self.assertFalse(report.trust.closes_stage_a_proof)
        self.assertEqual(
            serialize_isa_conformance_report(report, corpus=corpus), payload
        )
        self.assertEqual(report.to_payload(corpus=corpus), payload)
        with self.assertRaisesRegex(ISAConformanceError, "corpus is required"):
            parse_isa_conformance_report(payload)

        wrong_counts = _report()
        wrong_counts["counts"]["matched"] = 0
        wrong_qualification = _report()
        wrong_qualification["qualification"] = "vetoed"
        duplicate = _report()
        duplicate["observations"].append(copy.deepcopy(duplicate["observations"][0]))
        duplicate["counts"].update(cases=2, matched=2)
        wrong_case = _report()
        wrong_case["observations"][0]["case_id"] = "not-in-corpus"

        for malformed in (wrong_counts, wrong_qualification, duplicate, wrong_case):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ISAConformanceError):
                    parse_isa_conformance_report(malformed, corpus=corpus)

        invalid_typed = replace(report, counts=replace(report.counts, matched=0))
        with self.assertRaises(ISAConformanceError):
            serialize_isa_conformance_report(invalid_typed, corpus=corpus)

    def test_report_digest_rejects_altered_payload_with_unchanged_ids(self):
        corpus = parse_isa_conformance_corpus(_corpus())
        payload = _report()

        altered_payload = _corpus()
        altered_payload["cases"][0]["memory"][0]["bytes"][0] ^= 1
        altered_corpus = parse_isa_conformance_corpus(altered_payload)

        self.assertEqual(altered_corpus.id, corpus.id)
        self.assertEqual(altered_corpus.cases[0].id, corpus.cases[0].id)
        with self.assertRaisesRegex(ISAConformanceError, "input_sha256"):
            parse_isa_conformance_report(payload, corpus=altered_corpus)

        missing_digest = _report()
        del missing_digest["input_sha256"]
        malformed_digest = _report()
        malformed_digest["input_sha256"] = "A" * 64
        old_schema = _report()
        old_schema["format"] = "stage-a-isa-conformance-report-v1"
        for malformed in (missing_digest, malformed_digest, old_schema):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ISAConformanceError):
                    parse_isa_conformance_report(malformed, corpus=corpus)

    def test_mismatch_vetoes_but_oracle_can_never_claim_proof_authority(self):
        corpus = parse_isa_conformance_corpus(_corpus())
        veto = _report()
        veto["observations"][0]["status"] = "mismatch"
        veto["observations"][0]["final_state"]["gprs"]["eax"] = 3
        veto["qualification"] = "vetoed"
        veto["counts"].update(matched=0, mismatched=1)
        parsed = parse_isa_conformance_report(veto, corpus=corpus)
        self.assertEqual(parsed.qualification, ReportQualification.VETOED)

        with self.assertRaisesRegex(ISAConformanceError, "corpus is required"):
            parse_isa_conformance_report(veto)

        unqualified = _report()
        unqualified["observations"][0].update(
            status="unsupported",
            final_state=None,
            memory=None,
            actual=None,
            detail="instruction extension unavailable",
        )
        unqualified["qualification"] = "unqualified"
        unqualified["counts"].update(matched=0, unsupported=1)
        parsed = parse_isa_conformance_report(unqualified)
        self.assertEqual(parsed.qualification, ReportQualification.UNQUALIFIED)

        authority = _report()
        authority["trust"]["proof_authority"] = True
        closes_proof = _report()
        closes_proof["trust"]["closes_stage_a_proof"] = True

        with self.assertRaisesRegex(
            ISAConformanceError, "oracle report cannot claim proof authority"
        ):
            parse_isa_conformance_report(authority, corpus=corpus)
        with self.assertRaisesRegex(
            ISAConformanceError, "oracle report cannot close a Stage A proof"
        ):
            parse_isa_conformance_report(closes_proof, corpus=corpus)


if __name__ == "__main__":
    unittest.main()
