from __future__ import annotations

import json
import re
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_source_coverage import (
    INTERPRETER_MIXED_SOURCE_COVERAGE_DEFINITION,
    INTERPRETER_MIXED_SOURCE_COVERAGE_FORMAT,
    INTERPRETER_MIXED_SOURCE_COVERAGE_MODULE,
    INTERPRETER_MIXED_SOURCE_COVERAGE_PLAN_FILENAME,
    InterpreterMixedSourceCoverageGenerationError,
    InterpreterMixedSourceCoverageSpec,
    build_interpreter_mixed_source_coverage_plan,
    relational_interpreter_mixed_source_coverage_source,
    write_interpreter_mixed_source_coverage_bundle,
)


def _spec() -> InterpreterMixedSourceCoverageSpec:
    return InterpreterMixedSourceCoverageSpec(
        binding_module="StageA.SourceCoverageFixture",
        namespace="StageA.GeneratedRelational.InterpreterMixedSourceCoverage",
        parameter_name="requirements",
        parameter_type="StageA.SourceCoverageFixture.Requirements",
        context="requirements.context",
        authority="requirements.authority",
        launch="requirements.launch",
        root="requirements.root",
        reachability="requirements.reachability",
        candidate="requirements.candidate",
        candidate_authority="requirements.candidateAuthority",
        candidate_source_rvas="requirements.candidateSourceRvas",
        candidate_source_rvas_exact="requirements.candidateSourceRvasExact",
    )


class StageARelationalInterpreterMixedSourceCoverageTests(unittest.TestCase):
    def test_plan_is_explicitly_non_accepting(self) -> None:
        payload = build_interpreter_mixed_source_coverage_plan(_spec()).payload()

        self.assertEqual(
            payload["format"], INTERPRETER_MIXED_SOURCE_COVERAGE_FORMAT
        )
        self.assertIs(payload["acceptance_authority"], False)
        self.assertEqual(
            payload["scope"], "exact-original-semantic-source-coverage"
        )
        self.assertEqual(
            payload["checked_authority"],
            {
                "structure": "ExactOriginalSemanticSourceCoverage",
                "coverage_predicate": (
                    "exactOriginalSemanticSourceCoverageChecked"
                ),
                "candidate_source_rvas_equality": (
                    "requirements.candidateSourceRvasExact"
                ),
                "checked_field": "by decide +kernel",
            },
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            [
                "constructive_source_classification",
                "source_indexed_local_semantics",
                "mixed_component_composition",
                "whole_program_acceptance",
            ],
        )
        self.assertEqual(payload["failure_mode"], "incomplete")

    def test_source_emits_only_the_checked_coverage_binding(self) -> None:
        source = relational_interpreter_mixed_source_coverage_source(
            build_interpreter_mixed_source_coverage_plan(_spec())
        )

        for required in (
            "import StageA.RelationalInterpreterMixedConstructiveSourceClassifier",
            "import StageA.SourceCoverageFixture",
            "variable (requirements : StageA.SourceCoverageFixture.Requirements)",
            "def generatedExactOriginalSemanticSourceCoverage :",
            "ExactOriginalSemanticSourceCoverage requirements.context",
            "candidateSourceRvas := requirements.candidateSourceRvas",
            (
                "candidateSourceRvasExact := "
                "requirements.candidateSourceRvasExact"
            ),
            "checked := by decide +kernel",
            "#print axioms generatedExactOriginalSemanticSourceCoverage",
        ):
            self.assertIn(required, source)

        for forbidden in (
            r"\bsorry\b",
            r"\baxiom\b",
            r"\bnative_decide\b",
            r"\bunsafe\b",
            r"\bGNU\b",
            r"\bhello\b",
            r"\bjq\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_all_submitted_names_are_validated_fail_closed(self) -> None:
        base = _spec()
        malformed = {
            "binding_module": "StageA.Valid\naxiom injected : False",
            "namespace": "StageA.Generated; end StageA",
            "parameter_name": "requirements x",
            "parameter_type": "StageA.Requirements -> False",
            "context": "requirements.context; exact False.elim",
            "authority": "requirements.authority\n#eval 1",
            "launch": "(requirements.launch)",
            "root": "requirements.root -- comment",
            "reachability": "requirements reachability",
            "candidate": "requirements.candidate()",
            "candidate_authority": "requirements.candidateAuthority;",
            "candidate_source_rvas": "[1, 2, 3]",
            "candidate_source_rvas_exact": "by native_decide",
            "coverage_name": "sorry",
            "output_module": "../EscapedModule",
        }
        for field, value in malformed.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    InterpreterMixedSourceCoverageGenerationError,
                    "canonical",
                ):
                    build_interpreter_mixed_source_coverage_plan(
                        replace(base, **{field: value})
                    )

    def test_forbidden_tokens_are_rejected_inside_qualified_names(self) -> None:
        for value in (
            "requirements.sorry",
            "requirements.axiom",
            "requirements.native_decide",
            "requirements.unsafe",
        ):
            with self.subTest(value=value):
                with self.assertRaises(
                    InterpreterMixedSourceCoverageGenerationError
                ):
                    build_interpreter_mixed_source_coverage_plan(
                        replace(_spec(), context=value)
                    )

    def test_direct_plan_serialization_revalidates_its_spec(self) -> None:
        plan = build_interpreter_mixed_source_coverage_plan(_spec())
        malformed = replace(
            plan,
            spec=replace(
                plan.spec,
                candidate_source_rvas_exact="proof\naxiom injected : False",
            ),
        )

        with self.assertRaises(InterpreterMixedSourceCoverageGenerationError):
            malformed.payload()
        with self.assertRaises(InterpreterMixedSourceCoverageGenerationError):
            relational_interpreter_mixed_source_coverage_source(malformed)

    def test_bundle_is_reproducible_and_tracks_custom_module(self) -> None:
        spec = replace(
            _spec(),
            output_module="GeneratedAlternateSourceCoverage",
            coverage_name="generatedAlternateSourceCoverage",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            first_plan = write_interpreter_mixed_source_coverage_bundle(
                out=first, spec=spec
            )
            second_plan = write_interpreter_mixed_source_coverage_bundle(
                out=second, spec=spec
            )

            first_json = first / INTERPRETER_MIXED_SOURCE_COVERAGE_PLAN_FILENAME
            second_json = (
                second / INTERPRETER_MIXED_SOURCE_COVERAGE_PLAN_FILENAME
            )
            first_lean = first / "GeneratedAlternateSourceCoverage.lean"
            second_lean = second / "GeneratedAlternateSourceCoverage.lean"

            self.assertEqual(first_json.read_bytes(), second_json.read_bytes())
            self.assertEqual(first_lean.read_bytes(), second_lean.read_bytes())
            self.assertEqual(
                json.loads(first_json.read_text(encoding="utf-8")),
                first_plan.payload(),
            )
            self.assertEqual(first_plan.payload(), second_plan.payload())
            self.assertEqual(
                first_plan.payload()["result"]["definition"],
                (
                    "StageA.GeneratedRelational.InterpreterMixedSourceCoverage."
                    "generatedAlternateSourceCoverage"
                ),
            )
            self.assertNotIn(
                INTERPRETER_MIXED_SOURCE_COVERAGE_MODULE,
                first_lean.name,
            )
            self.assertNotIn(
                INTERPRETER_MIXED_SOURCE_COVERAGE_DEFINITION,
                first_lean.read_text(encoding="ascii"),
            )

    def test_plan_and_source_use_generic_terminology(self) -> None:
        plan = build_interpreter_mixed_source_coverage_plan(_spec())
        rendered = json.dumps(plan.payload(), sort_keys=True)
        source = relational_interpreter_mixed_source_coverage_source(plan)

        for text in (rendered, source):
            self.assertIsNone(
                re.search(r"\b(?:GNU|hello|jq)\b", text, re.IGNORECASE)
            )


if __name__ == "__main__":
    unittest.main()
