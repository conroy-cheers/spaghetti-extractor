from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor_target_gnu_hello.gnu_hello_acceptance_requirements import (
    GNU_HELLO_ACCEPTANCE_REQUIREMENTS_MANIFEST,
    GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS,
    GNU_HELLO_STATIC_REQUIREMENT_KEYS,
    GnuHelloAcceptanceRequirementsSpec,
    build_gnu_hello_acceptance_requirements_plan,
    gnu_hello_acceptance_requirements_source,
    write_gnu_hello_acceptance_requirements,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_kernel_binding import (
    REQUIRED_INHABITANTS,
)


class StageAGnuHelloAcceptanceRequirementsTests(unittest.TestCase):
    def test_static_and_dynamic_fields_partition_final_requirements(self) -> None:
        required = {requirement.key for requirement in REQUIRED_INHABITANTS}

        self.assertEqual(
            set(GNU_HELLO_STATIC_REQUIREMENT_KEYS)
            | set(GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS),
            required,
        )
        self.assertTrue(
            set(GNU_HELLO_STATIC_REQUIREMENT_KEYS).isdisjoint(
                GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS
            )
        )

    def test_source_constructs_closed_static_half_without_casts(self) -> None:
        plan = build_gnu_hello_acceptance_requirements_plan()
        source = gnu_hello_acceptance_requirements_source(plan)

        for field in GNU_HELLO_STATIC_REQUIREMENT_KEYS:
            self.assertRegex(source, rf"(?m)^  {field} :=")
        for field in GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS:
            self.assertRegex(source, rf"(?m)^  {field} : ")
            self.assertRegex(source, rf"(?m)^  {field} := evidence\.{field}$")

        for declaration in (
            "generatedOriginalProgram",
            "generatedProgramBinding",
            "generatedOriginalCallableBinding",
            "generatedCandidateAuthority",
            "generatedConcreteABI",
            "generatedRelationCore",
            "generatedRelationCoreContractExact",
            "generatedLaunchAnchorsComplete",
            "generatedCandidateRoot",
            "generatedRuntimeRulesHaveNoExternalOperations",
            "generatedInvariant",
            "generatedClassifySource",
            "generatedCandidateLaunchCalls",
            "generatedCandidateLaunchCallsExact",
            "generatedRequirements",
        ):
            self.assertIn(declaration, source)
        self.assertIn(".withCallable", source)
        self.assertIn("directExactCandidateNativeLaunchRootChecked_iff", source)
        self.assertIn("candidateNativeLaunchCallFrames?_exists", source)
        self.assertIn("constructiveSemanticRulesWithRootBoundary", source)
        self.assertIn(
            "constructiveSemanticRulesWithRootBoundary_hasNoExternalOperations",
            source,
        )
        self.assertIn(
            "import StageA.RelationalInterpreterMixedExternalComponent",
            source,
        )
        self.assertIn(
            "StageA.GeneratedRelational.GnuHelloConstructiveSourceRules.",
            source,
        )
        self.assertIn("generatedInterpreterStepEntry", source)
        self.assertIn(
            "constructiveMixedKernelRuntimeSourceClassifier", source
        )
        self.assertIn(
            "dispatch_family : RelationalWorld -> KernelOperationDispatchFamily",
            source,
        )
        for field in (
            "program_lookup_refines",
            "interpreter_step_refines",
            "run_function_refines",
            "invoke_call_refines",
        ):
            self.assertRegex(
                source,
                rf"(?m)^  {field} : forall world, KernelOperationRefinesUsing",
            )
        self.assertEqual(source.count("candidateWorldExact :"), 4)
        self.assertNotIn("generatedLaunchWorld", source)
        self.assertNotIn("HEq", source)
        self.assertNotIn("$", source)
        for forbidden in ("axiom", "sorry", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{forbidden}\b", source), forbidden)

    def test_manifest_is_diagnostic_and_lists_exact_typed_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = write_gnu_hello_acceptance_requirements(root)
            payload = json.loads(
                (root / GNU_HELLO_ACCEPTANCE_REQUIREMENTS_MANIFEST).read_text(
                    encoding="utf-8"
                )
            )
            generated = (
                root / "StageA" / f"{plan.spec.module_name}.lean"
            ).read_text(encoding="ascii")

        self.assertFalse(payload["acceptance_authority"])
        self.assertFalse(payload["report_authority"])
        self.assertTrue(payload["lean_check_required"])
        self.assertEqual(
            payload["constructed_static_fields"],
            list(GNU_HELLO_STATIC_REQUIREMENT_KEYS),
        )
        self.assertEqual(
            [row["field"] for row in payload["dynamic_evidence_fields"]],
            list(GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS),
        )
        self.assertTrue(
            all(row["lean_type"] for row in payload["dynamic_evidence_fields"])
        )
        self.assertIn("structure DynamicEvidence", generated)

    def test_rejects_non_pe32_candidate_root(self) -> None:
        with self.assertRaisesRegex(ValueError, "candidate_root_rva"):
            build_gnu_hello_acceptance_requirements_plan(
                GnuHelloAcceptanceRequirementsSpec(candidate_root_rva=2**32)
            )


if __name__ == "__main__":
    unittest.main()
