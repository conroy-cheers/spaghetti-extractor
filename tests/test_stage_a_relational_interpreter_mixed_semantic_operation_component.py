from __future__ import annotations

import dataclasses
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_semantic_operation_component import (
    INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE,
    InterpreterMixedSemanticOperationComponentGenerationError,
    InterpreterMixedSemanticOperationComponentSpec,
    MixedSemanticOperationComponentTerms,
    build_mixed_semantic_operation_component_plan,
    relational_interpreter_mixed_semantic_operation_component_source,
    write_mixed_semantic_operation_component_bundle,
)


def _spec(
    **changes: object,
) -> InterpreterMixedSemanticOperationComponentSpec:
    terms = MixedSemanticOperationComponentTerms(
        original_context="requirements.originalContext",
        original_authority="requirements.originalAuthority",
        launch="requirements.launch",
        original_root="requirements.originalRoot",
        reachability="requirements.reachability",
        original_program="requirements.originalProgram",
        candidate="requirements.candidate",
        candidate_authority="requirements.candidateAuthority",
        relation_contract="requirements.contract",
        invariant="requirements.invariant",
        compiled_program="requirements.program",
        kernel_abi="requirements.abi",
        kernel_dispatches="requirements.dispatches",
        classifier="requirements.classifier",
        source_binding_factory="requirements.sourceBindingFactory",
        semantic_evidence_factory="requirements.semanticEvidenceFactory",
        external_operation_evidence_factory=(
            "requirements.externalOperationEvidenceFactory"
        ),
    )
    base = InterpreterMixedSemanticOperationComponentSpec(
        binding_module="StageA.MixedSemanticOperationComponentFixture",
        namespace="StageA.Generated.MixedSemanticOperationComponent",
        terms=terms,
        parameter_name="requirements",
        parameter_type=(
            "StageA.MixedSemanticOperationComponentFixture.Requirements"
        ),
    )
    return dataclasses.replace(base, **changes)


class StageARelationalInterpreterMixedSemanticOperationComponentTests(
    unittest.TestCase
):
    def test_lean_bridge_retains_exact_effect_and_call_return_path(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterMixedSemanticOperationComponent.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "structure ExactOriginalSemanticTransferBinding",
            "structure CheckedOriginalSemanticOperationPath",
            "inductive CheckedOriginalDirectCallReturnCluster",
            "| directCallReturn",
            "def ExactOriginalSemanticKernelEffect.EndpointMatches",
            "originalEffectAfterExact",
            "structure CheckedMixedSemanticOperationEvidence",
            "structure MixedSemanticKernelOperationComponentCertificate",
            "exactOriginalEffect",
            "originalReplay",
            "originalPathShape",
            "decodedSemanticRefinement",
            "recordMacroStepExact",
            "toMixedKernelOperationComponentCertificate",
        ):
            self.assertIn(required, source)

        closure = source.split(
            "structure CheckedMixedSemanticOperationClosure", 1
        )[1].split(
            "structure CheckedMixedSemanticOperationEvidence", 1
        )[0]
        self.assertIn("originalReplay.observations", closure)
        self.assertIn("originalReplay.after replay.path.after", closure)
        self.assertNotIn("exactOriginalSemanticOperationAfter", source)
        for forbidden in (
            r"\bsorry\b",
            r"\badmit\b",
            r"\baxiom\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_generator_only_wires_checked_evidence(self) -> None:
        plan = build_mixed_semantic_operation_component_plan(_spec())
        source = relational_interpreter_mixed_semantic_operation_component_source(
            plan
        )

        for required in (
            "GeneratedSemanticOperationEvidenceFactory",
            "GeneratedExternalOperationEvidenceFactory",
            "beforeRelated",
            "classified",
            "generatedMixedSemanticOperationComponent",
            "generatedMixedExternalOperationComponent",
            "generatedSemanticChunkFactory",
            "generatedExternalOperationChunkFactory",
            "toMixedKernelOperationComponentCertificate",
        ):
            self.assertIn(required, source)
        for fabricated_assignment in (
            "request :=",
            "path :=",
            "fuel :=",
            "nativeEvents :=",
            "afterRelated :=",
        ):
            self.assertNotIn(fabricated_assignment, source)
        for forbidden in (
            r"\bsorry\b",
            r"\badmit\b",
            r"\baxiom\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
        ):
            self.assertNotRegex(source, forbidden)

        payload = plan.payload()
        self.assertFalse(payload["acceptance_authority"])
        residual = payload["residual_evidence"]
        self.assertTrue(
            any("direct-call-return shape" in item for item in residual)
        )
        self.assertTrue(
            any("semantic result" in item for item in residual)
        )

    def test_writer_is_deterministic(self) -> None:
        plan = build_mixed_semantic_operation_component_plan(_spec())
        expected_source = (
            relational_interpreter_mixed_semantic_operation_component_source(
                plan
            )
        )
        expected_payload = plan.payload()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_plan, first_lean = (
                write_mixed_semantic_operation_component_bundle(root, plan)
            )
            first_plan_bytes = first_plan.read_bytes()
            first_lean_bytes = first_lean.read_bytes()
            second_plan, second_lean = (
                write_mixed_semantic_operation_component_bundle(root, plan)
            )
            second_plan_bytes = second_plan.read_bytes()
            second_lean_bytes = second_lean.read_bytes()

        self.assertEqual(
            first_lean.name,
            f"{INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE}.lean",
        )
        self.assertEqual(first_plan_bytes, second_plan_bytes)
        self.assertEqual(first_lean_bytes, second_lean_bytes)
        self.assertEqual(
            json.loads(first_plan_bytes.decode("utf-8")), expected_payload
        )
        self.assertEqual(
            first_lean_bytes, expected_source.encode("utf-8")
        )

    def test_generator_rejects_malformed_names(self) -> None:
        base = _spec()
        bad_terms = dataclasses.replace(
            base.terms,
            semantic_evidence_factory="requirements.evidence; false",
        )
        for spec in (
            dataclasses.replace(base, binding_module="Bindings"),
            dataclasses.replace(base, namespace="StageA.Bad-Namespace"),
            dataclasses.replace(base, output_module="theorem"),
            dataclasses.replace(base, parameter_type=None),
            dataclasses.replace(base, terms=bad_terms),
        ):
            with self.subTest(spec=spec):
                with self.assertRaises(
                    InterpreterMixedSemanticOperationComponentGenerationError
                ):
                    build_mixed_semantic_operation_component_plan(spec)


if __name__ == "__main__":
    unittest.main()
