from __future__ import annotations

import json
import re
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_mixed_kernel_binding import (
    INTERPRETER_MIXED_KERNEL_BINDING_FORMAT,
    DiagnosticArtifact,
    InterpreterMixedKernelBindingGenerationError,
    InterpreterMixedKernelBindingSpec,
    REQUIRED_INHABITANTS,
    generate_interpreter_mixed_kernel_binding,
    load_interpreter_mixed_kernel_binding_spec,
    plan_interpreter_mixed_kernel_binding,
    relational_interpreter_mixed_kernel_binding_source,
    relational_interpreter_mixed_kernel_requirements_source,
    write_relational_interpreter_mixed_kernel_binding,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(r"depends on axioms: \[([^\]]*)\]", re.MULTILINE)


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


def _all_terms(prefix: str = "requirements") -> dict[str, str]:
    return {item.key: f"{prefix}.{item.key}" for item in REQUIRED_INHABITANTS}


def _complete_spec() -> InterpreterMixedKernelBindingSpec:
    return InterpreterMixedKernelBindingSpec(
        binding_module="StageA.GeneratedMixedKernelBindingRequirements",
        namespace="StageA.GeneratedRelational.MixedKernelBinding",
        output_module="GeneratedMixedKernelBinding",
        terms=_all_terms(),
        requirement_parameter="requirements",
        requirement_type=(
            "StageA.GeneratedRelational.MixedKernelBindingRequirements."
            "MixedKernelBindingRequirements"
        ),
    )


class StageARelationalInterpreterMixedKernelBindingTests(unittest.TestCase):
    def test_exact_authorities_are_independent_required_inhabitants(self) -> None:
        terms = _all_terms()
        del terms["original_authority"]
        del terms["candidate_authority"]
        plan = plan_interpreter_mixed_kernel_binding(
            InterpreterMixedKernelBindingSpec(
                binding_module="StageA.Bindings",
                namespace="StageA.Generated.Binding",
                terms=terms,
            )
        )

        self.assertFalse(plan.complete)
        unresolved = {item.key: item for item in plan.unresolved}
        self.assertEqual(
            set(unresolved), {"original_authority", "candidate_authority"}
        )
        self.assertIn("ExactOriginalDecodedAuthority", unresolved[
            "original_authority"
        ].lean_type)
        self.assertIn("ExactNativeCandidateAuthority", unresolved[
            "candidate_authority"
        ].lean_type)

    def test_launch_wrapper_and_universal_environment_family_are_required(self) -> None:
        terms = _all_terms()
        del terms["launch_wrapper_refinements"]
        del terms["environment_compositions"]
        plan = plan_interpreter_mixed_kernel_binding(
            InterpreterMixedKernelBindingSpec(
                binding_module="StageA.Bindings",
                namespace="StageA.Generated.Binding",
                terms=terms,
            )
        )

        self.assertFalse(plan.complete)
        unresolved = {item.key: item for item in plan.unresolved}
        self.assertEqual(
            set(unresolved),
            {"launch_wrapper_refinements", "environment_compositions"},
        )
        self.assertIn("forall originalEnvironment candidateEnvironment", unresolved[
            "launch_wrapper_refinements"
        ].lean_type)
        self.assertIn("MixedWorldChunkComposition", unresolved[
            "environment_compositions"
        ].lean_type)

    def test_incomplete_inventory_is_precise_deterministic_and_fail_closed(
        self,
    ) -> None:
        terms = _all_terms()
        del terms["invoke_call_refines"]
        del terms["external_boundary_chunk"]
        spec = InterpreterMixedKernelBindingSpec(
            binding_module="StageA.Bindings",
            namespace="StageA.Generated.Binding",
            terms=terms,
        )
        first = plan_interpreter_mixed_kernel_binding(spec)
        second = plan_interpreter_mixed_kernel_binding(spec)

        self.assertFalse(first.complete)
        self.assertEqual(first.to_json(), second.to_json())
        inventory = first.to_json()["unresolved_inhabitants"]
        self.assertEqual(
            [(item["category"], item["key"]) for item in inventory],
            [
                ("external_boundary_bridge", "external_boundary_chunk"),
                ("operation_refinement_invoke_call", "invoke_call_refines"),
            ],
        )
        self.assertIn("KernelOperationRefinesUsing", inventory[1]["lean_type"])
        self.assertFalse(first.to_json()["acceptance_authority"])
        self.assertEqual(
            first.to_json()["observation_trace_contract"],
            {
                "cardinality": "arbitrary_finite",
                "ordering": "exact_pointwise_order",
                "relation": "RelatedObservationLists",
                "proof_blocked_observations": "uninhabited",
            },
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stale = root / "StageA" / f"{spec.output_module}.lean"
            stale.parent.mkdir()
            stale.write_text("stale proof output\n", encoding="utf-8")
            written = write_relational_interpreter_mixed_kernel_binding(root, first)
            self.assertEqual([path.name for path in written], [
                "interpreter-mixed-kernel-binding-plan.json"
            ])
            self.assertFalse(stale.exists())

    def test_diagnostic_status_cannot_close_and_frontier_can_veto(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harmless = root / "harmless.json"
            harmless.write_text(
                json.dumps({"format": "fixture-v1", "status": "pass", "verdict": True}),
                encoding="utf-8",
            )
            spec = _complete_spec()
            plan = plan_interpreter_mixed_kernel_binding(
                replace(
                    spec,
                    diagnostic_artifacts=(
                        DiagnosticArtifact("compiled_kernel", harmless),
                    ),
                )
            )
            self.assertTrue(plan.complete)
            self.assertFalse(plan.to_json()["diagnostic_artifacts"][0][
                "status_is_proof_authority"
            ])

            blocked = root / "blocked.json"
            blocked.write_text(
                json.dumps(
                    {
                        "status": "ready",
                        "blockers": [
                            {
                                "reason_code": "unresolved_indirect_target",
                                "target_id": 17,
                                "source_rva": 4096,
                                "message": "target set is not closed",
                            }
                        ],
                        "counts": {"pending_local_proofs": 3},
                    }
                ),
                encoding="utf-8",
            )
            blocked_plan = plan_interpreter_mixed_kernel_binding(
                replace(
                    spec,
                    diagnostic_artifacts=(
                        DiagnosticArtifact("original_reachability", blocked),
                    ),
                )
            )

        self.assertFalse(blocked_plan.complete)
        inventory = blocked_plan.to_json()["unresolved_inhabitants"]
        self.assertEqual(len(inventory), 2)
        item = inventory[0]
        self.assertEqual(item["category"], "original_reachability")
        self.assertEqual(item["reason_code"], "upstream_blocker")
        self.assertEqual(item["location"], {"target_id": 17, "source_rva": 4096})
        self.assertEqual(inventory[1]["reason_code"], "upstream_unresolved_count")
        self.assertEqual(inventory[1]["location"], {"count": 3})

    def test_loader_rejects_authority_shaped_status_and_unknown_terms(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for payload in (
                {
                    "format": INTERPRETER_MIXED_KERNEL_BINDING_FORMAT,
                    "binding_module": "StageA.Bindings",
                    "namespace": "StageA.Generated.Binding",
                    "terms": {},
                    "verdict": "pass",
                },
                {
                    "format": INTERPRETER_MIXED_KERNEL_BINDING_FORMAT,
                    "binding_module": "StageA.Bindings",
                    "namespace": "StageA.Generated.Binding",
                    "terms": {"all_states_refine": "Bindings.claim"},
                },
                {
                    "format": (
                        "stage-a-relational-interpreter-mixed-kernel-binding-v1"
                    ),
                    "binding_module": "StageA.Bindings",
                    "namespace": "StageA.Generated.Binding",
                    "terms": {},
                },
            ):
                manifest = root / "manifest.json"
                manifest.write_text(json.dumps(payload), encoding="utf-8")
                with self.subTest(payload=payload):
                    with self.assertRaises(
                        InterpreterMixedKernelBindingGenerationError
                    ):
                        load_interpreter_mixed_kernel_binding_spec(manifest)

    def test_generator_persists_incomplete_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            out = root / "out"
            manifest.write_text(
                json.dumps(
                    {
                        "format": INTERPRETER_MIXED_KERNEL_BINDING_FORMAT,
                        "binding_module": "StageA.Bindings",
                        "namespace": "StageA.Generated.Binding",
                        "terms": {},
                    }
                ),
                encoding="utf-8",
            )
            plan = generate_interpreter_mixed_kernel_binding(manifest, out)
            persisted = json.loads(
                (out / "interpreter-mixed-kernel-binding-plan.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertFalse(plan.complete)
        self.assertEqual(
            persisted["counts"]["unresolved_inhabitants"],
            len(REQUIRED_INHABITANTS),
        )

    def test_complete_source_consumes_operation_proofs_and_emits_acceptance(
        self,
    ) -> None:
        plan = plan_interpreter_mixed_kernel_binding(_complete_spec())
        source = relational_interpreter_mixed_kernel_binding_source(plan)
        requirements_source = relational_interpreter_mixed_kernel_requirements_source(
            "StageA.GeneratedRelational.MixedKernelBindingRequirements"
        )

        self.assertTrue(plan.complete)
        self.assertIn("classify := requirements.classify_source", source)
        self.assertNotIn("MixedKernelObservationFamily", requirements_source)
        self.assertNotIn(".internal", requirements_source)
        self.assertNotIn(".external", requirements_source)
        for operation in (
            "programLookup",
            "interpreterStep",
            "runFunction",
            "invokeCall",
        ):
            self.assertIn(f"| {operation} =>", source)
        self.assertIn("combinedKernelDispatchRelation", source)
        self.assertIn("requirements.dispatch_family", source)
        self.assertEqual(
            source.count(
                "generatedKernelOperationRefinements requirements operation"
            ),
            2,
        )
        for generated in (
            "generatedCanonicalMixedRelationProfile",
            "generatedMixedKernelSourceClassifier",
            "generatedCheckedMixedKernelComponentCases",
            "generatedMixedWorldChunkComposition",
            "generatedSelectedMixedWorldAcceptanceCertificate",
            "generatedUniversalMixedWorldAcceptanceCertificate",
            "generatedMixedWorldProgramsEquivalent",
        ):
            self.assertIn(generated, source)
        self.assertIn(
            "CanonicalMixedWorldAcceptanceCertificate requirements.original_context",
            source,
        )
        self.assertIn("requirements.relation_core.contract", source)
        self.assertIn(
            "launchWrapperRefines := requirements.launch_wrapper_refinements",
            source,
        )
        self.assertIn("requirements.environment_compositions", source)
        self.assertIn(
            "certificates := fun originalEnvironment candidateEnvironment",
            source,
        )
        self.assertIn("canonicalMixedWorldProgramsEquivalent", source)
        self.assertIn(
            "intro originalEnvironment candidateEnvironment environmentRefines",
            source,
        )
        self.assertNotIn("terms['contract']", source)
        self.assertNotIn("$", requirements_source)
        self.assertNotIn("  profile :", requirements_source)
        for required in (
            "ExactOriginalDecodedAuthority original_context",
            "ExactNativeCandidateAuthority candidate_program",
            "ConcreteKernelABI candidate_program.pe candidate_program.imports",
            "CanonicalMixedRelationCore original_context original_authority",
            "MixedExternalFrameContract",
            "forall originalEnvironment candidateEnvironment, "
            "ExactOneToOneMixedExternalEnvironmentsRefine",
            "forall originalEnvironment candidateEnvironment, "
            "ExactOneToOneMixedExternalEnvironmentsRefine",
            "MixedWorldChunkComposition original_context original_authority",
        ):
            self.assertIn(required, requirements_source)
        for forbidden in (
            "StaticProofContext",
            "RelationalProductGraph",
            "ProductInvariantTable",
            "KernelABIRelation\n  dispatches",
            "environmentRefines : ExactOneToOneMixedExternalEnvironmentsRefine",
        ):
            self.assertNotIn(forbidden, requirements_source)
        for forbidden in (
            r"\bstatus\b",
            r"\bverdict\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bwholePath\b",
            r"\ballStatesRefine\b",
        ):
            self.assertNotRegex(source, forbidden)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_parameterized_complete_binding_compiles_without_custom_axioms(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedKernelComposition",
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedProfile",
            )
            (stage_a / "GeneratedMixedKernelBindingRequirements.lean").write_text(
                relational_interpreter_mixed_kernel_requirements_source(
                    "StageA.GeneratedRelational.MixedKernelBindingRequirements"
                ),
                encoding="utf-8",
            )
            plan = plan_interpreter_mixed_kernel_binding(_complete_spec())
            write_relational_interpreter_mixed_kernel_binding(root, plan)
            (stage_a / "GeneratedMixedKernelBindingAudit.lean").write_text(
                _MULTI_EVENT_AUDIT,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="GeneratedMixedKernelBindingAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


_MULTI_EVENT_AUDIT = r"""import StageA.GeneratedMixedKernelBinding

namespace StageA.GeneratedRelational.MixedKernelBindingAudit

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition

example (contract : MixedRelationContract)
    (originalObservations candidateObservations :
      List WorldRelationalObservable)
    (pointwise : RelatedObservationLists contract.eventObservationsRelated
      originalObservations candidateObservations) :
    CheckedMixedKernelObservations contract originalObservations
      candidateObservations := {
  pointwise
}

#print axioms StageA.GeneratedRelational.MixedKernelBinding.generatedMixedWorldProgramsEquivalent

end StageA.GeneratedRelational.MixedKernelBindingAudit
"""


if __name__ == "__main__":
    unittest.main()
