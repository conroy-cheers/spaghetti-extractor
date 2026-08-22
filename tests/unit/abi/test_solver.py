from __future__ import annotations

import unittest

from spaghetti_extractor.abi.model import (
    AbiFactV1,
    AbiModelError,
    ReviewedAbiAssumptionV1,
)
from spaghetti_extractor.abi.solver import (
    PHYSICAL_PROFILE_FIELDS,
    AbiEqualityConstraintV1,
    facts_from_profile,
    solve_abi_constraints,
)
from tests.unit.abi._support import (
    physical_profile,
    scalar_value,
    stack_location,
)


def without_field(
    facts: tuple[AbiFactV1, ...], field: str
) -> tuple[AbiFactV1, ...]:
    return tuple(fact for fact in facts if fact.field != field)


def fact_for(
    certificate_facts: tuple[AbiFactV1, ...], field: str
) -> AbiFactV1:
    return next(fact for fact in certificate_facts if fact.field == field)


class PythonAbiConstraintSolverTests(unittest.TestCase):
    def test_exact_facts_reconstruct_profile_and_bind_reviewed_assumptions(self) -> None:
        profile = physical_profile(
            arguments=(
                scalar_value(
                    "arg0",
                    stack_location(4),
                    role="callback",
                    callback_abi_id="callback-profile-v1",
                ),
            )
        )
        facts = facts_from_profile(
            subject_id="function.main",
            profile=profile,
            evidence_ids=("evidence.z", "evidence.a"),
            dependency_ids=("dependency.z", "dependency.a"),
        )

        result = solve_abi_constraints(
            subjects={"function.main": "function"},
            facts=reversed(facts),
            reviewed_assumptions=(
                "assumption.z",
                "assumption.a",
                "assumption.z",
            ),
        )
        repeated = solve_abi_constraints(
            subjects={"function.main": "function"},
            facts=facts,
            reviewed_assumptions=("assumption.a", "assumption.z"),
        )

        self.assertEqual(result.status, "complete")
        certificate = result.certificates[0]
        self.assertEqual(certificate.status, "complete")
        self.assertEqual(certificate.profile, profile)
        self.assertEqual(
            certificate.reviewed_assumption_ids,
            ("assumption.a", "assumption.z"),
        )
        self.assertEqual(
            certificate.dependency_ids, ("dependency.a", "dependency.z")
        )
        self.assertEqual(
            certificate.certificate_id,
            repeated.certificates[0].certificate_id,
        )
        self.assertEqual(result.facts_sha256, repeated.facts_sha256)
        self.assertEqual(result.constraint_sha256, repeated.constraint_sha256)

    def test_equality_propagates_an_exact_fact_between_subjects(self) -> None:
        profile = physical_profile()
        first_facts = facts_from_profile(
            subject_id="function.first",
            profile=profile,
            evidence_ids=("evidence.first",),
        )
        second_facts = without_field(
            facts_from_profile(
                subject_id="function.second",
                profile=profile,
                evidence_ids=("evidence.second",),
            ),
            "calling_convention",
        )
        equality = AbiEqualityConstraintV1(
            "function.first",
            "calling_convention",
            "function.second",
            "calling_convention",
            ("evidence.equality",),
        )

        result = solve_abi_constraints(
            subjects={
                "function.first": "function",
                "function.second": "function",
            },
            facts=first_facts + second_facts,
            equalities=(equality,),
        )

        self.assertEqual(result.status, "complete")
        propagated = fact_for(
            result.certificates[1].facts, "calling_convention"
        )
        self.assertEqual(propagated.status, "exact")
        self.assertEqual(propagated.values, ("cdecl",))
        self.assertEqual(
            propagated.evidence_ids,
            ("evidence.equality", "evidence.first"),
        )

    def test_transitive_equalities_retain_every_constraint_evidence_id(self) -> None:
        profile = physical_profile()
        all_facts: list[AbiFactV1] = []
        for subject_id in ("a", "b", "c"):
            subject_facts = facts_from_profile(
                subject_id=subject_id,
                profile=profile,
                evidence_ids=(f"evidence.{subject_id}",),
            )
            all_facts.extend(
                subject_facts
                if subject_id == "a"
                else without_field(subject_facts, "calling_convention")
            )
        equalities = (
            AbiEqualityConstraintV1(
                "b",
                "calling_convention",
                "c",
                "calling_convention",
                ("equality.b-c",),
            ),
            AbiEqualityConstraintV1(
                "c",
                "calling_convention",
                "a",
                "calling_convention",
                ("equality.c-a",),
            ),
        )

        result = solve_abi_constraints(
            subjects={"a": "function", "b": "function", "c": "function"},
            facts=all_facts,
            equalities=equalities,
        )

        self.assertEqual(result.status, "complete")
        for certificate in result.certificates:
            resolved = fact_for(certificate.facts, "calling_convention")
            self.assertEqual(
                resolved.evidence_ids,
                ("equality.b-c", "equality.c-a", "evidence.a"),
            )

    def test_reviewed_assumption_can_supply_a_missing_finite_fact(self) -> None:
        profile = physical_profile()
        facts = without_field(
            facts_from_profile(
                subject_id="function.main",
                profile=profile,
                evidence_ids=("evidence.profile",),
            ),
            "calling_convention",
        )
        assumed_fact = AbiFactV1.create(
            subject_id="function.main",
            field="calling_convention",
            status="exact",
            values=("cdecl",),
            evidence_ids=("evidence.review",),
        )
        assumption = ReviewedAbiAssumptionV1.create(
            subject_kind="function",
            subject_id="function.main",
            facts=(assumed_fact,),
            rationale="The decorated symbol and cleanup establish cdecl.",
            reviewer="reviewer.fixture",
        )

        result = solve_abi_constraints(
            subjects={"function.main": "function"},
            facts=facts,
            assumptions=(assumption,),
        )

        self.assertEqual(result.status, "complete")
        certificate = result.certificates[0]
        self.assertEqual(
            certificate.reviewed_assumption_ids, (assumption.assumption_id,)
        )
        convention = fact_for(certificate.facts, "calling_convention")
        self.assertEqual(convention.status, "exact")
        self.assertEqual(
            convention.evidence_ids,
            tuple(sorted((assumption.assumption_id, "evidence.review"))),
        )

    def test_reviewed_assumption_cannot_override_conflicting_evidence(self) -> None:
        profile = physical_profile()
        facts = facts_from_profile(
            subject_id="function.main",
            profile=profile,
            evidence_ids=("evidence.cdecl",),
        )
        assumed_fact = AbiFactV1.create(
            subject_id="function.main",
            field="calling_convention",
            status="exact",
            values=("stdcall",),
            evidence_ids=("evidence.review",),
        )
        assumption = ReviewedAbiAssumptionV1.create(
            subject_kind="function",
            subject_id="function.main",
            facts=(assumed_fact,),
            rationale="The reviewer selected stdcall.",
            reviewer="reviewer.fixture",
        )

        result = solve_abi_constraints(
            subjects={"function.main": "function"},
            facts=facts,
            assumptions=(assumption,),
        )

        self.assertEqual(result.status, "violated")
        certificate = result.certificates[0]
        self.assertEqual(
            certificate.reviewed_assumption_ids, (assumption.assumption_id,)
        )
        convention = fact_for(certificate.facts, "calling_convention")
        self.assertEqual(convention.status, "contradiction")
        self.assertEqual(
            convention.evidence_ids,
            tuple(
                sorted(
                    (
                        assumption.assumption_id,
                        "evidence.cdecl",
                        "evidence.review",
                    )
                )
            ),
        )

    def test_conflicting_exact_facts_produce_a_contradiction(self) -> None:
        profile = physical_profile()
        facts = facts_from_profile(
            subject_id="function.main",
            profile=profile,
            evidence_ids=("evidence.cdecl",),
        )
        conflict = AbiFactV1.create(
            subject_id="function.main",
            field="calling_convention",
            status="exact",
            values=("stdcall",),
            evidence_ids=("evidence.stdcall",),
        )

        result = solve_abi_constraints(
            subjects={"function.main": "function"},
            facts=facts + (conflict,),
        )

        self.assertEqual(result.status, "violated")
        certificate = result.certificates[0]
        self.assertIsNone(certificate.profile)
        convention = fact_for(certificate.facts, "calling_convention")
        self.assertEqual(convention.status, "contradiction")
        self.assertEqual(
            convention.evidence_ids,
            ("evidence.cdecl", "evidence.stdcall"),
        )
        self.assertEqual(certificate.issues[0]["code"], "abi_constraint_contradiction")

    def test_bounded_alternatives_remain_explicit(self) -> None:
        profile = physical_profile()
        base = without_field(
            facts_from_profile(
                subject_id="function.main",
                profile=profile,
                evidence_ids=("evidence.profile",),
            ),
            "calling_convention",
        )
        alternatives = AbiFactV1.create(
            subject_id="function.main",
            field="calling_convention",
            status="alternatives",
            values=("stdcall", "cdecl"),
            evidence_ids=("evidence.alternatives",),
        )

        result = solve_abi_constraints(
            subjects={"function.main": "function"},
            facts=base + (alternatives,),
            max_alternatives=2,
        )

        self.assertEqual(result.status, "incomplete")
        convention = fact_for(
            result.certificates[0].facts, "calling_convention"
        )
        self.assertEqual(convention.status, "alternatives")
        self.assertEqual(convention.values, ("cdecl", "stdcall"))
        self.assertEqual(result.certificates[0].issues[0]["code"], "abi_fact_ambiguous")

    def test_alternative_budget_overflow_does_not_widen_silently(self) -> None:
        profile = physical_profile()
        base = without_field(
            facts_from_profile(
                subject_id="function.main",
                profile=profile,
                evidence_ids=("evidence.profile",),
            ),
            "calling_convention",
        )
        alternatives = AbiFactV1.create(
            subject_id="function.main",
            field="calling_convention",
            status="alternatives",
            values=("stdcall", "fastcall", "cdecl"),
            evidence_ids=("evidence.alternatives",),
        )

        result = solve_abi_constraints(
            subjects={"function.main": "function"},
            facts=base + (alternatives,),
            max_alternatives=2,
        )

        convention = fact_for(
            result.certificates[0].facts, "calling_convention"
        )
        self.assertEqual(convention.status, "unknown")
        self.assertEqual(convention.values, ())
        self.assertEqual(
            result.certificates[0].issues[0]["code"],
            "abi_alternative_budget_exceeded",
        )

    def test_missing_required_fields_are_reported_individually(self) -> None:
        result = solve_abi_constraints(
            subjects={"import.printf": "import"},
            facts=(),
        )

        self.assertEqual(result.status, "incomplete")
        certificate = result.certificates[0]
        self.assertIsNone(certificate.profile)
        self.assertEqual(
            {fact.field for fact in certificate.facts},
            set(PHYSICAL_PROFILE_FIELDS),
        )
        self.assertTrue(all(fact.status == "unknown" for fact in certificate.facts))
        self.assertEqual(
            {issue["code"] for issue in certificate.issues},
            {"abi_required_fact_missing"},
        )

    def test_unknown_physical_fields_fail_at_the_solver_boundary(self) -> None:
        fact = AbiFactV1.create(
            subject_id="function.main",
            field="source_type",
            status="exact",
            values=("int",),
        )

        with self.assertRaisesRegex(AbiModelError, "unsupported field"):
            solve_abi_constraints(
                subjects={"function.main": "function"},
                facts=(fact,),
            )


if __name__ == "__main__":
    unittest.main()
