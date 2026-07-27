from __future__ import annotations

import copy
from dataclasses import replace
import inspect
import unittest

from spaghetti_extractor import isa_conformance as conformance
from spaghetti_extractor import isa_corpus_generator as generator_module
from spaghetti_extractor.isa_catalog import parse_isa_form_catalog, parse_xed_instruction_catalog
from spaghetti_extractor.isa_conformance import (
    ControlClass,
    FaultClass,
    ISAConformanceCorpus,
    ISAConformanceError,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_report,
)
from spaghetti_extractor.isa_corpus_generator import (
    CoverageScenario,
    FS_BASE,
    ISACorpusGenerationError,
    RawConsensusStatus,
    compare_raw_executor_observations,
    generate_boundary_isa_corpus,
    generated_corpus_executor_input,
    generated_isa_corpus_sha256,
    parse_generated_isa_corpus,
    serialize_generated_isa_corpus,
)
from tests.test_stage_a_isa_catalog import (
    catalog_payload,
    defined_outputs,
    entry,
    xed_payload,
    xed_template,
)


def complete_catalog_payload() -> dict:
    payload = catalog_payload()
    payload["entries"] = [
        entry(
            "form-branch",
            {
                "class": "branch",
                "id": "effect-branch",
                "outcomes": [
                    {
                        "scenario": "not_taken",
                        "eflags_mask": 0x40,
                        "eflags_value": 0,
                        "control": "fallthrough",
                        "target_eip": None,
                    },
                    {
                        "scenario": "taken",
                        "eflags_mask": 0x40,
                        "eflags_value": 0x40,
                        "control": "direct_branch",
                        "target_eip": 0x401080,
                    },
                ],
            },
            instruction=[0x74, 0x7E],
        ),
        entry(
            "form-divide",
            {
                "class": "divide",
                "id": "effect-divide",
                "width_bits": 32,
                "signed": False,
                "dividend_high": "edx",
                "dividend_low": "eax",
                "divisor": "ecx",
            },
            instruction=[0xF7, 0xF1],
        ),
        entry(
            "form-memory",
            {
                "class": "memory",
                "id": "effect-memory",
                "width_bits": 32,
                "access": "read_write",
                "address": {
                    "base": "ebx",
                    "index": "ecx",
                    "scale": 4,
                    "displacement": 8,
                    "segment": "flat",
                },
            },
            instruction=[0x01, 0x44, 0x8B, 0x08],
        ),
        entry(
            "form-register",
            {
                "class": "register",
                "id": "effect-register",
                "width_bits": 32,
                "reads": ["eax"],
                "writes": ["eax"],
            },
            instruction=[0x40],
        ),
        entry(
            "form-x87",
            {
                "class": "x87",
                "id": "effect-x87",
                "stack_inputs": 2,
                "stack_outputs": 1,
            },
            instruction=[0xDE, 0xC1],
            features=["x87"],
        ),
    ]
    for row in payload["entries"]:
        row["defined_outputs"] = defined_outputs()
    return payload


def _cases_by_scenario(corpus) -> dict[CoverageScenario, object]:
    return {case.coverage_cell.scenario: case for case in corpus.cases}


def _report_payload(executor, backend_id: str, *, eax_delta: int = 1) -> dict:
    observations = []
    for case in executor.corpus.cases:
        final_state = replace(
            case.initial_state,
            gprs=replace(
                case.initial_state.gprs,
                eax=(case.initial_state.gprs.eax + eax_delta) & 0xFFFFFFFF,
            ),
        )
        observations.append(
            {
                "case_id": case.id,
                "status": "mismatch",
                "final_state": conformance._machine_state_payload(final_state),
                "memory": [
                    {"address": row.address, "bytes": list(row.data)}
                    for row in case.expected.memory
                ],
                "actual": {
                    "control": case.expected.control.value,
                    "fault": case.expected.fault.value,
                },
                "detail": "neutral expectation intentionally differs",
            }
        )
    return {
        "format": "stage-a-isa-conformance-report-v2",
        "corpus_id": executor.corpus.id,
        "input_sha256": isa_conformance_corpus_sha256(executor.corpus),
        "backend": {"id": backend_id, "kind": "emulator", "version": "fixture"},
        "qualification": "vetoed",
        "observations": observations,
        "counts": {
            "cases": len(observations),
            "matched": 0,
            "mismatched": len(observations),
            "unsupported": 0,
            "errors": 0,
        },
        "trust": {
            "role": "isa_conformance_evidence_only",
            "proof_authority": False,
            "closes_stage_a_proof": False,
        },
    }


class StageAISACorpusGeneratorTests(unittest.TestCase):
    def test_generation_is_canonical_deterministic_and_boundary_biased(self):
        catalog = parse_isa_form_catalog(complete_catalog_payload())
        first = generate_boundary_isa_corpus(catalog, seed=17)
        second = generate_boundary_isa_corpus(catalog, seed=17)
        changed_seed = generate_boundary_isa_corpus(catalog, seed=18)

        self.assertEqual(first, second)
        self.assertEqual(
            generated_isa_corpus_sha256(first),
            generated_isa_corpus_sha256(second),
        )
        self.assertNotEqual(
            generated_isa_corpus_sha256(first),
            generated_isa_corpus_sha256(changed_seed),
        )
        payload = serialize_generated_isa_corpus(first)
        self.assertEqual(parse_generated_isa_corpus(payload), first)
        self.assertEqual(len(first.cases), 17)

        cells = _cases_by_scenario(first)
        self.assertEqual(
            cells[CoverageScenario.REGISTER_ZERO].initial_state.gprs.eax, 0
        )
        self.assertEqual(
            cells[
                CoverageScenario.REGISTER_MAX_UNSIGNED
            ].initial_state.gprs.eax,
            0xFFFFFFFF,
        )
        self.assertEqual(
            cells[CoverageScenario.REGISTER_SIGN_BIT].initial_state.gprs.eax,
            0x80000000,
        )

    def test_write_only_register_form_uses_one_baseline_case(self):
        payload = catalog_payload()
        payload["entries"][0]["effects"][0]["reads"] = []

        corpus = generate_boundary_isa_corpus(
            parse_isa_form_catalog(payload), seed=17
        )

        self.assertEqual(len(corpus.cases), 1)
        self.assertEqual(
            corpus.cases[0].coverage_cell.scenario,
            CoverageScenario.REGISTER_ZERO,
        )
        self.assertEqual(corpus.cases[0].initial_state.fs.selector, 0)
        self.assertEqual(corpus.cases[0].initial_state.fs.base, 0)

    def test_fs_state_is_enabled_only_for_explicit_fs_memory_effects(self):
        payload = catalog_payload()
        payload["entries"][0] = entry(
            "form-fs-memory",
            {
                "class": "memory",
                "id": "effect-fs-read",
                "width_bits": 32,
                "access": "read",
                "address": {
                    "base": "eax",
                    "index": None,
                    "scale": 1,
                    "displacement": 0,
                    "segment": "fs",
                },
            },
        )

        corpus = generate_boundary_isa_corpus(
            parse_isa_form_catalog(payload), seed=17
        )

        self.assertTrue(corpus.cases)
        self.assertTrue(
            all(case.initial_state.fs.selector == 0x3B for case in corpus.cases)
        )
        self.assertTrue(
            all(case.initial_state.fs.base == FS_BASE for case in corpus.cases)
        )

    def test_generic_memory_branch_divide_and_x87_shapes_are_generated(self):
        corpus = generate_boundary_isa_corpus(
            parse_isa_form_catalog(complete_catalog_payload()), seed=3
        )
        cells = _cases_by_scenario(corpus)

        memory = cells[CoverageScenario.MEMORY_PAGE_EDGE]
        self.assertEqual(memory.memory[0].address & 0xFFF, 0xFFC)
        self.assertEqual(memory.memory[0].permissions, "rw")
        self.assertEqual(memory.defined_outputs.memory[0].mask, b"\xff" * 4)

        taken = cells[CoverageScenario.BRANCH_TAKEN]
        not_taken = cells[CoverageScenario.BRANCH_NOT_TAKEN]
        self.assertEqual(taken.expected.control, ControlClass.DIRECT_BRANCH)
        self.assertEqual(taken.initial_state.eflags & 0x40, 0x40)
        self.assertEqual(not_taken.expected.control, ControlClass.FALLTHROUGH)
        self.assertEqual(not_taken.initial_state.eflags & 0x40, 0)

        divide_zero = cells[CoverageScenario.DIVIDE_BY_ZERO]
        divide_overflow = cells[CoverageScenario.DIVIDE_QUOTIENT_OVERFLOW]
        divide_success = cells[CoverageScenario.DIVIDE_SUCCESS]
        self.assertEqual(divide_zero.initial_state.gprs.ecx, 0)
        self.assertEqual(divide_zero.expected.fault, FaultClass.DIVIDE_ERROR)
        self.assertEqual(divide_overflow.expected.fault, FaultClass.DIVIDE_ERROR)
        self.assertEqual(divide_success.initial_state.gprs.ecx, 3)
        self.assertEqual(divide_success.expected.fault, FaultClass.NONE)

        x87_zero = cells[CoverageScenario.X87_ZERO]
        x87_nan = cells[CoverageScenario.X87_NAN]
        self.assertEqual(x87_zero.profile.cpu, "i686")
        self.assertEqual(x87_zero.profile.features, ())
        self.assertEqual(x87_zero.coverage_cell.required_features, ("x87",))
        self.assertEqual(x87_zero.initial_state.x87.registers[0], bytes(10))
        self.assertEqual(
            x87_nan.initial_state.x87.registers[0],
            bytes.fromhex("00000000000000c0ff7f"),
        )
        self.assertNotEqual(x87_nan.initial_state.x87.tag_word, 0xFFFF)

    def test_generator_dispatches_on_effect_classes_not_instruction_names(self):
        source = inspect.getsource(generator_module)
        self.assertNotIn("iform", source.lower())
        self.assertNotIn("iclass", source.lower())

        payload = catalog_payload()
        payload["entries"][0]["form_id"] = "arbitrary-opaque-name"
        payload["entries"][0]["encoding_id"] = "equally-opaque-encoding"
        scenarios = {
            case.coverage_cell.scenario
            for case in generate_boundary_isa_corpus(
                parse_isa_form_catalog(payload)
            ).cases
        }
        self.assertEqual(scenarios, set(generator_module._register_scenarios()))

    def test_raw_xed_templates_and_conflicting_constraints_fail_closed(self):
        raw = parse_xed_instruction_catalog(xed_payload(xed_template(1)))
        with self.assertRaisesRegex(
            ISACorpusGenerationError, "require concrete encodings"
        ):
            generate_boundary_isa_corpus(raw)

        payload = catalog_payload()
        payload["entries"][0]["effects"] = [
            {
                "class": "memory",
                "id": "effect-memory",
                "width_bits": 32,
                "access": "read",
                "address": {
                    "base": "eax",
                    "index": None,
                    "scale": 1,
                    "displacement": 0,
                    "segment": "flat",
                },
            },
            {
                "class": "register",
                "id": "effect-register",
                "width_bits": 32,
                "reads": ["eax"],
                "writes": [],
            },
        ]
        with self.assertRaisesRegex(
            ISACorpusGenerationError, "conflicting state constraints"
        ):
            generate_boundary_isa_corpus(parse_isa_form_catalog(payload))

    def test_malformed_generated_artifacts_fail_closed(self):
        corpus = generate_boundary_isa_corpus(
            parse_isa_form_catalog(catalog_payload())
        )
        bad_case_id = serialize_generated_isa_corpus(corpus)
        bad_case_id["cases"][0]["id"] = "tampered"
        unknown = serialize_generated_isa_corpus(corpus)
        unknown["cases"][0]["surprise"] = True
        wrong_scenario = serialize_generated_isa_corpus(corpus)
        wrong_scenario["cases"][0]["coverage_cell"]["scenario"] = "x87_nan"

        for malformed in (bad_case_id, unknown, wrong_scenario):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ISAConformanceError):
                    parse_generated_isa_corpus(malformed)

    def test_end_to_end_executor_adapter_compares_raw_actuals_not_status(self):
        generated = generate_boundary_isa_corpus(
            parse_isa_form_catalog(catalog_payload()), seed=9
        )
        executor = generated_corpus_executor_input(generated)

        self.assertIsInstance(executor.corpus, ISAConformanceCorpus)
        self.assertTrue(executor.neutral_expectations)
        conformance.serialize_isa_conformance_corpus(executor.corpus)

        left = parse_isa_conformance_report(
            _report_payload(executor, "left"),
            corpus=executor.corpus,
        )
        right = parse_isa_conformance_report(
            _report_payload(executor, "right"),
            corpus=executor.corpus,
        )
        self.assertEqual(left.qualification.value, "vetoed")
        consensus = compare_raw_executor_observations(generated, left, right)
        self.assertTrue(
            all(row.status is RawConsensusStatus.AGREED for row in consensus.cases)
        )
        self.assertFalse(consensus.proof_authority)

        changed_payload = _report_payload(executor, "changed")
        changed_payload["observations"][0]["final_state"]["gprs"]["eax"] ^= 0x10
        changed = parse_isa_conformance_report(
            changed_payload, corpus=executor.corpus
        )
        disagreement = compare_raw_executor_observations(
            generated, left, changed
        )
        self.assertEqual(
            disagreement.cases[0].status, RawConsensusStatus.DISAGREED
        )


if __name__ == "__main__":
    unittest.main()
