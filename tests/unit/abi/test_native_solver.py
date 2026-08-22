from __future__ import annotations

import unittest
from collections.abc import Iterable, Mapping
from typing import Any

import spaghetti_extractor_native as native
from spaghetti_extractor.abi.model import (
    AbiFactV1,
    AbiModelError,
    PE32_TARGET_V1,
    PhysicalAbiProfileV1,
    StackCleanupV1,
    VariadicPolicyV1,
    canonical_json_bytes,
)
from spaghetti_extractor.abi.native_solver import NativeAbiSolver
from spaghetti_extractor.abi.solver import (
    PHYSICAL_PROFILE_FIELDS,
    AbiEqualityConstraintV1,
    facts_from_profile,
    solve_abi_constraints,
)


def _profile(calling_convention: str = "cdecl") -> PhysicalAbiProfileV1:
    return PhysicalAbiProfileV1.create(
        target=PE32_TARGET_V1,
        calling_convention=calling_convention,
        arguments=(),
        results=(),
        stack_cleanup=StackCleanupV1("caller", None),
        variadic=VariadicPolicyV1("none", 0),
        preserved_state=("ebp", "ebx", "edi", "esi"),
    )


def _profile_facts(
    subject_id: str,
    *,
    calling_convention: str = "cdecl",
) -> tuple[AbiFactV1, ...]:
    return facts_from_profile(
        subject_id=subject_id,
        profile=_profile(calling_convention),
        evidence_ids=(f"evidence:{subject_id}",),
        dependency_ids=(f"dependency:{subject_id}",),
    )


def _profile_equalities(
    left: str,
    right: str,
) -> tuple[AbiEqualityConstraintV1, ...]:
    return tuple(
        AbiEqualityConstraintV1(
            left,
            field,
            right,
            field,
            (f"equality:{field}",),
        )
        for field in PHYSICAL_PROFILE_FIELDS
    )


def _reference_payloads(
    *,
    subjects: Mapping[str, str],
    facts: Iterable[AbiFactV1],
    equalities: Iterable[AbiEqualityConstraintV1] = (),
    max_alternatives: int = 16,
) -> list[dict[str, object]]:
    result = solve_abi_constraints(
        subjects=subjects,
        facts=facts,
        equalities=equalities,
        max_alternatives=max_alternatives,
    )
    return [
        fact.to_payload()
        for certificate in result.certificates
        for fact in certificate.facts
    ]


def _native_payloads(
    *,
    subjects: Mapping[str, str],
    facts: Iterable[AbiFactV1],
    equalities: Iterable[AbiEqualityConstraintV1] = (),
    max_alternatives: int = 16,
) -> list[dict[str, object]]:
    return [
        fact.to_payload()
        for fact in NativeAbiSolver(native).resolve_facts(
            subjects=subjects,
            facts=facts,
            equalities=equalities,
            max_alternatives=max_alternatives,
        )
    ]


def _fact_payload(
    *,
    subject_id: str = "subject:a",
    field: str = "calling_convention",
    status: str = "exact",
    values: Iterable[object] = ("cdecl",),
    evidence_ids: Iterable[str] = ("evidence:a",),
    dependency_ids: Iterable[str] = ("dependency:a",),
) -> dict[str, object]:
    return AbiFactV1.create(
        subject_id=subject_id,
        field=field,
        status=status,
        values=values,
        evidence_ids=evidence_ids,
        dependency_ids=dependency_ids,
    ).to_payload()


class NativeAbiSolverParityTests(unittest.TestCase):
    def test_propagation_matches_python_reference(self) -> None:
        subjects = {"subject:a": "function", "subject:b": "import"}
        facts = _profile_facts("subject:a")
        equalities = _profile_equalities("subject:a", "subject:b")
        self.assertEqual(
            _native_payloads(
                subjects=subjects,
                facts=facts,
                equalities=equalities,
            ),
            _reference_payloads(
                subjects=subjects,
                facts=facts,
                equalities=equalities,
            ),
        )

    def test_contradiction_matches_python_reference(self) -> None:
        subjects = {"subject:a": "function", "subject:b": "callback"}
        facts = (*_profile_facts("subject:a"), *_profile_facts(
            "subject:b", calling_convention="stdcall"
        ))
        equalities = _profile_equalities("subject:a", "subject:b")
        actual = _native_payloads(
            subjects=subjects,
            facts=facts,
            equalities=equalities,
        )
        self.assertEqual(
            actual,
            _reference_payloads(
                subjects=subjects,
                facts=facts,
                equalities=equalities,
            ),
        )
        self.assertEqual(
            [
                row["status"]
                for row in actual
                if row["field"] == "calling_convention"
            ],
            ["contradiction", "contradiction"],
        )

    def test_finite_alternative_intersection_matches_python(self) -> None:
        subjects = {"subject:a": "function", "subject:b": "import"}
        facts = tuple(
            fact
            for subject_id in subjects
            for fact in _profile_facts(subject_id)
            if fact.field != "calling_convention"
        ) + (
            AbiFactV1.create(
                subject_id="subject:a",
                field="calling_convention",
                status="alternatives",
                values=("cdecl", "stdcall"),
                evidence_ids=("evidence:alternatives-a",),
            ),
            AbiFactV1.create(
                subject_id="subject:b",
                field="calling_convention",
                status="alternatives",
                values=("cdecl", "fastcall"),
                evidence_ids=("evidence:alternatives-b",),
            ),
        )
        equalities = _profile_equalities("subject:a", "subject:b")
        actual = _native_payloads(
            subjects=subjects,
            facts=facts,
            equalities=equalities,
        )
        self.assertEqual(
            actual,
            _reference_payloads(
                subjects=subjects,
                facts=facts,
                equalities=equalities,
            ),
        )
        calling_conventions = [
            row for row in actual if row["field"] == "calling_convention"
        ]
        self.assertTrue(
            all(row["values"] == ["cdecl"] for row in calling_conventions)
        )

    def test_alternative_budget_matches_python_reference(self) -> None:
        subjects = {"subject:a": "function"}
        facts = tuple(
            fact
            for fact in _profile_facts("subject:a")
            if fact.field != "calling_convention"
        ) + (
            AbiFactV1.create(
                subject_id="subject:a",
                field="calling_convention",
                status="alternatives",
                values=("cdecl", "fastcall", "stdcall"),
                evidence_ids=("evidence:alternatives",),
            ),
        )
        actual = _native_payloads(
            subjects=subjects,
            facts=facts,
            max_alternatives=2,
        )
        self.assertEqual(
            actual,
            _reference_payloads(
                subjects=subjects,
                facts=facts,
                max_alternatives=2,
            ),
        )
        calling_convention = next(
            row for row in actual if row["field"] == "calling_convention"
        )
        self.assertEqual(calling_convention["status"], "unknown")
        self.assertEqual(calling_convention["values"], [])

    def test_finite_numeric_values_match_python_canonical_domains(self) -> None:
        subjects = {"subject:a": "function"}
        facts = (
            AbiFactV1.create(
                subject_id="subject:a",
                field="stack_alignment_bytes",
                status="alternatives",
                values=(4, 8),
                evidence_ids=("evidence:stack-alignment",),
            ),
        )
        required_fields = {
            "subject:a": ("calling_convention", "stack_alignment_bytes")
        }
        expected = [
            fact.to_payload()
            for certificate in solve_abi_constraints(
                subjects=subjects,
                facts=facts,
                required_fields=required_fields,
            ).certificates
            for fact in certificate.facts
        ]
        actual = [
            fact.to_payload()
            for fact in NativeAbiSolver(native).resolve_facts(
                subjects=subjects,
                facts=facts,
                required_fields=required_fields,
            )
        ]
        self.assertEqual(actual, expected)

    def test_native_output_is_deterministic_across_input_order(self) -> None:
        subjects = {"subject:b": "import", "subject:a": "function"}
        facts = _profile_facts("subject:a")
        equalities = _profile_equalities("subject:a", "subject:b")
        first = native.resolve_abi_equalities(
            subjects,
            [fact.to_payload() for fact in facts],
            [equality.to_payload() for equality in equalities],
        )
        second = native.resolve_abi_equalities(
            dict(reversed(tuple(subjects.items()))),
            [fact.to_payload() for fact in reversed(facts)],
            [equality.to_payload() for equality in reversed(equalities)],
        )
        self.assertEqual(first, second)
        self.assertEqual(
            canonical_json_bytes(first),
            canonical_json_bytes(second),
        )

    def test_adapter_rejects_conflicting_alternative_limit(self) -> None:
        with self.assertRaisesRegex(AbiModelError, "conflicts"):
            NativeAbiSolver(native).resolve_facts(
                subjects={"subject:a": "function"},
                facts=_profile_facts("subject:a"),
                max_alternatives=4,
                limits={"max_alternatives": 8},
            )

    def test_adapter_rejects_an_invalid_alternative_budget(self) -> None:
        with self.assertRaisesRegex(AbiModelError, "at least two"):
            NativeAbiSolver(native).resolve_facts(
                subjects={"subject:a": "function"},
                facts=_profile_facts("subject:a"),
                max_alternatives=1,
            )


class NativeAbiSolverValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.subjects = {"subject:a": "function"}
        self.fact = _fact_payload()

    def assert_malformed(
        self,
        subjects: object,
        facts: object,
        equalities: object,
        limits: object | None = None,
    ) -> None:
        with self.assertRaises(ValueError):
            native.resolve_abi_equalities(subjects, facts, equalities, limits)

    def test_rejects_malformed_subjects_and_fact_records(self) -> None:
        malformed: list[tuple[object, object]] = [
            ([], [self.fact]),
            ({"subject:a": "unsupported"}, [self.fact]),
            (self.subjects, (self.fact,)),
            (self.subjects, [{**self.fact, "unexpected": True}]),
            (self.subjects, [{**self.fact, "subject_id": "subject:missing"}]),
            (self.subjects, [{**self.fact, "status": "unsupported"}]),
            (self.subjects, [{**self.fact, "values": []}]),
            (
                self.subjects,
                [
                    {
                        **self.fact,
                        "status": "alternatives",
                        "values": ["stdcall", "cdecl"],
                    }
                ],
            ),
            (
                self.subjects,
                [{**self.fact, "evidence_ids": ["evidence:a", "evidence:a"]}],
            ),
            (self.subjects, [{**self.fact, "values": [{"not-json": {1, 2}}]}]),
            (self.subjects, [{**self.fact, "values": [float("nan")]}]),
        ]
        for subjects, facts in malformed:
            with self.subTest(subjects=subjects, facts=facts):
                self.assert_malformed(subjects, facts, [])

    def test_rejects_malformed_equalities(self) -> None:
        equality = AbiEqualityConstraintV1(
            "subject:a",
            "calling_convention",
            "subject:a",
            "calling_convention",
            ("equality:self",),
        ).to_payload()
        malformed: list[object] = [
            (equality,),
            [{**equality, "unexpected": True}],
            [{**equality, "left": {"subject_id": "subject:a"}}],
            [
                {
                    **equality,
                    "right": {
                        "subject_id": "subject:missing",
                        "field": "calling_convention",
                    },
                }
            ],
            [{**equality, "evidence_ids": ["z", "a"]}],
        ]
        for equalities in malformed:
            with self.subTest(equalities=equalities):
                self.assert_malformed(self.subjects, [self.fact], equalities)

    def test_rejects_excessively_deep_canonical_values(self) -> None:
        value: object = 0
        for _ in range(130):
            value = [value]
        with self.assertRaisesRegex(ValueError, "depth"):
            native.resolve_abi_equalities(
                self.subjects,
                [{**self.fact, "values": [value]}],
                [],
            )

    def test_rejects_malformed_limits(self) -> None:
        malformed: list[object] = [
            [],
            {"unknown_limit": 1},
            {"max_facts": True},
            {"max_facts": 0},
            {"max_alternatives": 1},
            {"max_string_bytes": 4_097},
        ]
        for limits in malformed:
            with self.subTest(limits=limits):
                self.assert_malformed(self.subjects, [self.fact], [], limits)

    def test_resource_bounds_fail_closed(self) -> None:
        second_subjects = {**self.subjects, "subject:b": "import"}
        cases: list[tuple[object, object, object, Mapping[str, int], str]] = [
            (
                second_subjects,
                [self.fact],
                [],
                {"max_subjects": 1},
                "max_subjects",
            ),
            (
                self.subjects,
                [self.fact, self.fact],
                [],
                {"max_facts": 1},
                "max_facts",
            ),
            (
                self.subjects,
                [
                    self.fact,
                    _fact_payload(field="stack_coordinate"),
                ],
                [],
                {"max_nodes": 1},
                "max_nodes",
            ),
            (
                self.subjects,
                [
                    _fact_payload(
                        status="alternatives",
                        values=("cdecl", "stdcall"),
                    )
                ],
                [],
                {"max_total_values": 1},
                "max_total_values",
            ),
            (
                self.subjects,
                [
                    _fact_payload(
                        evidence_ids=("evidence:a", "evidence:b"),
                    )
                ],
                [],
                {"max_links_per_record": 1},
                "max_links_per_record",
            ),
            (
                self.subjects,
                [self.fact],
                [],
                {"max_value_bytes": 4},
                "max_value_bytes",
            ),
            (
                self.subjects,
                [
                    self.fact,
                    _fact_payload(field="stack_coordinate"),
                ],
                [],
                {"max_output_facts": 1},
                "max_output_facts",
            ),
        ]
        for subjects, facts, equalities, limits, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    native.resolve_abi_equalities(
                        subjects,
                        facts,
                        equalities,
                        limits,
                    )


class _MalformedNativeModule:
    ABI_SOLVER_API_VERSION = 1

    @staticmethod
    def resolve_abi_equalities(*_args: Any) -> list[dict[str, object]]:
        return [{"status": "exact"}]


class NativeAbiSolverAdapterValidationTests(unittest.TestCase):
    def test_rejects_malformed_native_output(self) -> None:
        with self.assertRaisesRegex(AbiModelError, "malformed"):
            NativeAbiSolver(_MalformedNativeModule()).resolve_facts(
                subjects={"subject:a": "function"},
                facts=_profile_facts("subject:a"),
            )

    def test_rejects_an_unknown_native_api(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unsupported"):
            NativeAbiSolver(object())


if __name__ == "__main__":
    unittest.main()
