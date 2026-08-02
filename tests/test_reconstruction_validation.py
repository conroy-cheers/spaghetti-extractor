from __future__ import annotations

import unittest

from spaghetti_extractor.reconstruction_validation import (
    VALIDATION_TRUST_BOUNDARY,
    ReconstructionValidationError,
    check_semantic_claim,
    check_straight_line_semantic_claim,
    enumerate_finite_indirect_dispatch_cases,
    synthesize_boundary_value_cases,
    synthesize_memory_case_descriptors,
    synthesize_reconstruction_validation,
)


def _reg(name: str, width: int = 32) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": width}


def _flag(name: str) -> dict[str, object]:
    return {"op": "flag", "name": name}


def _const(value: int, width: int = 32) -> dict[str, object]:
    return {"op": "const", "value": value, "width": width}


def _op(name: str, *args: object) -> dict[str, object]:
    return {"op": name, "args": list(args)}


class BoundaryValueSynthesisTests(unittest.TestCase):
    def test_constants_widths_and_branch_witnesses_are_deterministic(self) -> None:
        branch = _op("eq", _reg("eax"), _const(10))
        expressions = [
            _op("add32", _reg("eax"), _const(5)),
            branch,
            _flag("zf"),
        ]

        first = synthesize_boundary_value_cases(expressions)
        second = synthesize_boundary_value_cases(expressions)

        self.assertEqual(first, second)
        self.assertEqual(len({case["id"] for case in first}), len(first))
        assignments = [case["inputs"] for case in first]
        eax_values = {case["eax"] for case in assignments if case["zf"] == 0}
        self.assertTrue(
            {
                0,
                1,
                4,
                5,
                6,
                9,
                10,
                11,
                0x7FFFFFFF,
                0x80000000,
                0xFFFFFFFF,
            }
            <= eax_values
        )
        self.assertEqual({case["zf"] for case in assignments}, {0, 1})
        self.assertTrue(
            any("branch:" in cover and cover.endswith(":true") for case in first for cover in case["covers"])
        )
        self.assertTrue(
            any("branch:" in cover and cover.endswith(":false") for case in first for cover in case["covers"])
        )

    def test_combined_synthesis_is_stable_and_counts_every_family(self) -> None:
        kwargs = {
            "expressions": [_op("add32", _reg("eax"), _const(1))],
            "indirect_domains": [
                {
                    "input_name": "dispatch_index",
                    "domain": [
                        {"target_rva": 0x2000, "case_indices": [1, 0]},
                    ],
                }
            ],
            "memory_views": [
                {
                    "id": "view:buffer",
                    "base_expression": "input.esi",
                    "byte_length": 4,
                    "length_expression": None,
                    "access": "read_write",
                }
            ],
        }
        first = synthesize_reconstruction_validation(**kwargs).to_payload()
        second = synthesize_reconstruction_validation(**kwargs).to_payload()

        self.assertEqual(first, second)
        self.assertGreater(first["counts"]["boundary"], 0)
        self.assertEqual(first["counts"]["indirect_dispatch"], 2)
        self.assertEqual(first["counts"]["memory"], 3)
        self.assertEqual(first["trust_boundary"], VALIDATION_TRUST_BOUNDARY)


class IndirectDispatchSynthesisTests(unittest.TestCase):
    def test_checked_jump_table_domain_is_enumerated_exhaustively(self) -> None:
        domain = {
            "checked_jump_table_targets": [
                {
                    "target_rva": 0x3000,
                    "case_indices": [2, 0],
                    "function": "dispatch",
                },
                {"target_rva": 0x4000, "case_indices": [1]},
            ]
        }

        cases = enumerate_finite_indirect_dispatch_cases(
            domain, input_name="dispatch_index"
        )

        self.assertEqual([case["selector"] for case in cases], [0, 1, 2])
        self.assertEqual(
            [case["target"]["target_rva"] for case in cases],
            [0x3000, 0x4000, 0x3000],
        )
        self.assertEqual(
            [case["inputs"] for case in cases],
            [
                {"dispatch_index": 0},
                {"dispatch_index": 1},
                {"dispatch_index": 2},
            ],
        )

    def test_ambiguous_selector_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            ReconstructionValidationError, "maps to multiple targets"
        ):
            enumerate_finite_indirect_dispatch_cases(
                [
                    {"target_rva": 0x3000, "case_indices": [0]},
                    {"target_rva": 0x4000, "case_indices": [0]},
                ]
            )


class MemoryCaseSynthesisTests(unittest.TestCase):
    def test_valid_fault_exact_alias_and_partial_alias_descriptors(self) -> None:
        views = [
            {
                "id": "view:right",
                "base_expression": "input.edi",
                "byte_length": None,
                "length_expression": "input.ecx",
                "access": "write",
            },
            {
                "id": "view:left",
                "base_expression": "input.esi",
                "byte_length": 4,
                "length_expression": None,
                "access": "read",
            },
        ]

        cases = synthesize_memory_case_descriptors(views)
        reversed_cases = synthesize_memory_case_descriptors(list(reversed(views)))

        self.assertEqual(cases, reversed_cases)
        scenarios = [case["scenario"] for case in cases]
        self.assertEqual(scenarios.count("valid"), 2)
        self.assertEqual(scenarios.count("fault"), 4)
        self.assertEqual(scenarios.count("alias_exact"), 1)
        self.assertEqual(scenarios.count("alias_partial"), 1)
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        alias = next(case for case in cases if case["scenario"] == "alias_exact")
        self.assertEqual(alias["view_ids"], ["view:left", "view:right"])


class StraightLineSemanticClaimTests(unittest.TestCase):
    def test_identical_explicit_output_and_control_claim_is_qualified(self) -> None:
        output = _op("add32", _reg("eax"), _const(1))
        control = {
            "kind": "branch",
            "condition": _op("ult32", _reg("eax"), _const(8)),
            "true_target_rva": 0x2000,
            "false_target_rva": 0x2010,
        }

        result = check_straight_line_semantic_claim(
            {"eax": output},
            {"eax": output},
            reference_control=control,
            proposed_control=control,
        )

        self.assertEqual(result.status, "qualified")
        self.assertIsNone(result.counterexample_inputs)
        self.assertEqual(result.trust_boundary, VALIDATION_TRUST_BOUNDARY)

    def test_reversed_equality_mutation_is_violated(self) -> None:
        equality = _op("eq", _reg("eax"), _const(7))
        result = check_straight_line_semantic_claim(
            {},
            {},
            reference_control={"kind": "branch", "condition": equality},
            proposed_control={
                "kind": "branch",
                "condition": _op("not", equality),
            },
        )

        self.assertEqual(result.status, "violated")
        self.assertEqual(result.counterexample_inputs, {"eax": 0})
        self.assertEqual(result.differing_claims, ("control:condition",))

    def test_wrong_offset_and_value_mutations_are_violated(self) -> None:
        wrong_offset = check_straight_line_semantic_claim(
            {"esp": _op("add32", _reg("esp"), _const(4))},
            {"esp": _op("add32", _reg("esp"), _const(8))},
        )
        wrong_value = check_straight_line_semantic_claim(
            {"eax": _const(7)}, {"eax": _const(8)}
        )

        self.assertEqual(wrong_offset.status, "violated")
        self.assertEqual(wrong_offset.counterexample_inputs, {"esp": 0})
        self.assertEqual(wrong_value.status, "violated")
        self.assertEqual(wrong_value.counterexample_inputs, {})

    def test_nonwrapping_mutation_finds_uint32_wraparound_boundary(self) -> None:
        increment = _op("add32", _reg("eax"), _const(1))
        saturating_mutation = _op(
            "ite",
            _op("eq", _reg("eax"), _const(0xFFFFFFFF)),
            _const(0xFFFFFFFF),
            increment,
        )

        result = check_straight_line_semantic_claim(
            {"eax": increment}, {"eax": saturating_mutation}
        )

        self.assertEqual(result.status, "violated")
        self.assertEqual(result.counterexample_inputs, {"eax": 0xFFFFFFFF})
        self.assertEqual(result.differing_claims, ("output:eax",))

    def test_unsupported_operations_and_stateful_loads_fail_closed(self) -> None:
        unsupported = check_straight_line_semantic_claim(
            {"eax": _reg("eax")},
            {"eax": _op("rotate_left32", _reg("eax"), _const(1))},
        )
        stateful = check_straight_line_semantic_claim(
            {"eax": _reg("eax")},
            {
                "eax": {
                    "op": "load",
                    "address": _reg("esi"),
                    "width": 4,
                }
            },
        )

        self.assertEqual(unsupported.status, "incomplete")
        self.assertEqual(unsupported.reason_code, "unsupported_operation")
        self.assertIsNone(unsupported.counterexample_inputs)
        self.assertEqual(stateful.status, "incomplete")
        self.assertEqual(stateful.reason_code, "stateful_expression_unsupported")

    def test_bounded_helper_forms_translate_without_widening_the_claim(self) -> None:
        expressions = {
            "parity": _op("parity", 32, _reg("eax")),
            "shift_cf": {
                "op": "shift_cf",
                "args": ["shl", 32, _reg("eax"), _reg("ecx")],
            },
            "adc_carry": _op(
                "adc_carry",
                32,
                _reg("eax"),
                _reg("ebx"),
                _flag("cf"),
                _reg("edx"),
            ),
            "udiv_valid32": _op(
                "udiv_valid32", _reg("edx"), _reg("eax"), _reg("ecx")
            ),
        }

        for name, expression in expressions.items():
            with self.subTest(name=name):
                result = check_straight_line_semantic_claim(
                    {name: expression}, {name: expression}
                )
                self.assertEqual(result.status, "qualified")

    def test_arbitrary_c_text_is_outside_the_claim_boundary(self) -> None:
        result = check_semantic_claim(
            {"outputs": {"eax": _const(1)}, "c_source": "return 1;"},
            {"outputs": {"eax": _const(1)}},
        )

        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.reason_code, "claim_outside_trust_boundary")
        self.assertIn("arbitrary C source", result.trust_boundary)


if __name__ == "__main__":
    unittest.main()
