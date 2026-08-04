from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor_target_gnu_hello.gnu_hello_acceptance_requirements import (
    GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_mixed_acceptance import (
    GNU_HELLO_MIXED_ACCEPTANCE_MANIFEST,
    GNU_HELLO_MIXED_ACCEPTANCE_PROFILE,
    GNU_HELLO_MIXED_ACCEPTANCE_SOURCE_THEOREM,
    GnuHelloMixedAcceptanceGenerationError,
    build_gnu_hello_mixed_acceptance_plan,
    gnu_hello_mixed_acceptance_source,
    write_gnu_hello_mixed_acceptance,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_MODULE = (
    "spaghetti_extractor_target_gnu_hello.gnu_hello_mixed_acceptance"
)
_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(r"depends on axioms: \[([^\]]*)\]", re.MULTILINE)


def _copy_module_closure(
    source_root: Path, destination: Path, module: str
) -> None:
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


class StageAGnuHelloMixedAcceptanceTests(unittest.TestCase):
    def test_fixed_plan_reports_exact_uninhabited_dynamic_fields(self) -> None:
        plan = build_gnu_hello_mixed_acceptance_plan()

        self.assertFalse(plan.complete)
        self.assertEqual(
            [item.field for item in plan.missing],
            [
                "interpreter_step_refines",
                "run_function_refines",
                "invoke_call_refines",
                "launch_prefix",
                "semantic_chunk_factory",
                "external_boundary_chunk",
                "environment_compositions",
            ],
        )
        self.assertTrue(all(item.lean_type for item in plan.missing))
        self.assertIn(
            "KernelOperationRefinesUsing", plan.missing[0].lean_type
        )
        self.assertIn(
            "MixedWorldChunkComposition", plan.missing[-1].lean_type
        )
        blockers = {item.field: item.blocker for item in plan.missing}
        self.assertIn(
            "beforeRelated", blockers["external_boundary_chunk"]
        )
        self.assertIn(
            "targets 292, 2595, and 2792",
            blockers["environment_compositions"],
        )
        self.assertIn(
            "mixedWorldLaunchPrefixCertificateWithInvariantExtension",
            blockers["launch_prefix"],
        )
        self.assertNotIn("generatedLaunchWorld", str(plan.payload()))

    def test_writer_is_fail_closed_and_manifest_has_no_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stale = root / "StageA/GeneratedGnuHelloMixedAcceptance.lean"
            stale.parent.mkdir()
            stale.write_text("stale\n", encoding="ascii")

            plan = write_gnu_hello_mixed_acceptance(root)
            payload = json.loads(
                (root / GNU_HELLO_MIXED_ACCEPTANCE_MANIFEST).read_text(
                    encoding="utf-8"
                )
            )

        self.assertFalse(plan.complete)
        self.assertFalse(stale.exists())
        self.assertEqual(payload["status"], "incomplete")
        self.assertFalse(payload["acceptance_authority"])
        self.assertFalse(payload["proof_authority"])
        self.assertFalse(payload["report_authority"])
        self.assertFalse(payload["accepts_manifest"])
        self.assertFalse(payload["accepts_proof_inputs"])
        self.assertFalse(payload["accepts_lean_name_inputs"])
        self.assertEqual(
            payload["environment_scope"],
            "universal_carrier_parameters_and_paired_refinement",
        )
        self.assertEqual(
            payload["source_theorem_parameterization"],
            "forall parameters : Parameters",
        )
        self.assertTrue(payload["fixed_profile_wrapper_compatible"])
        self.assertEqual(
            payload["fixed_profile_wrapper_mode"],
            "universal_proof_free_carrier_family",
        )
        self.assertTrue(
            payload["requires_strengthened_runtime_indirect_invariant"]
        )
        self.assertEqual(
            payload["required_runtime_indirect_targets"], [292, 2595, 2792]
        )
        self.assertIsNone(payload["output_module"])
        self.assertIsNone(payload["source_theorem"])
        self.assertEqual(
            payload["available_checked_components"][
                "external_boundary_no_case_factory"
            ],
            "StageA.GeneratedRelational.GnuHelloExternalComponent."
            "generatedExternalBoundaryEvidenceFactory",
        )
        self.assertEqual(
            payload["available_checked_components"][
                "component_composition_constructor"
            ],
            "StageA.Relational.InterpreterMixedKernelComposition."
            "CheckedMixedKernelComponentCases."
            "toMixedWorldChunkComposition",
        )

    def test_incomplete_source_error_lists_types_not_premises(self) -> None:
        with self.assertRaisesRegex(
            GnuHelloMixedAcceptanceGenerationError,
            r"interpreter_step_refines : forall world, "
            r"KernelOperationRefinesUsing",
        ) as raised:
            gnu_hello_mixed_acceptance_source()

        message = str(raised.exception)
        self.assertIn("environment_compositions : forall", message)
        self.assertNotIn("status", message)
        self.assertNotIn("verdict", message)

    def test_fixed_operation_evidence_is_current_world_indexed(self) -> None:
        from spaghetti_extractor_target_gnu_hello.gnu_hello_mixed_acceptance import (
            _DYNAMIC_EVIDENCE_EXPRESSIONS,
            _FIXED_IMPORTS,
        )

        dispatch = _DYNAMIC_EVIDENCE_EXPRESSIONS["dispatch_family"]
        lookup = _DYNAMIC_EVIDENCE_EXPRESSIONS["program_lookup_refines"]
        self.assertIsNotNone(dispatch)
        self.assertIsNotNone(lookup)
        self.assertNotIn("generatedLaunchWorld", dispatch)
        self.assertIn(
            "checkedNativeWorldKernelOperationDispatchFamily", dispatch
        )
        self.assertIn("fun world =>", lookup)
        self.assertIn("generatedProgramLookupNativeWorldRefines", lookup)
        self.assertIn(
            "StageA.GeneratedRelationalInterpreterKernelProgramLookupNativeWorldBridge",
            _FIXED_IMPORTS,
        )

    def test_complete_architecture_is_closed_and_uses_generic_binding(
        self,
    ) -> None:
        concrete = {
            field: f"Concrete.generated{index}"
            for index, field in enumerate(
                GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS
            )
        }
        concrete["environment_compositions"] = (
            "Concrete.generatedEnvironmentCompositions_"
            "toMixedWorldChunkComposition_combinedExtension_"
            "withInvariantExtension"
        )
        concrete["launch_prefix"] = (
            "Concrete.generatedLaunchPrefix_"
            "mixedWorldLaunchPrefixCertificateWithInvariantExtension"
        )
        with patch(f"{_MODULE}._DYNAMIC_EVIDENCE_EXPRESSIONS", concrete):
            plan = build_gnu_hello_mixed_acceptance_plan()
            source = gnu_hello_mixed_acceptance_source()

        self.assertTrue(plan.complete)
        self.assertIn("structure Parameters where", source)
        self.assertIn(
            "def Parameters.acceptance (parameters : Parameters)", source
        )
        carrier = source.split("structure Parameters where", 1)[1].split(
            "def Parameters.acceptance", 1
        )[0]
        self.assertNotIn("Prop", carrier)
        for field in (
            "originalEnvironment : WorldExternalEnvironment",
            "originalProtocolEnvironment : WorldExternalProtocolEnvironment",
            "originalExternalCallSites : List ExternalCallSiteContract",
            "originalCallableEnvironment : OriginalCallableExternalEnvironment",
            "candidateEnvironment : NativeWorldEnvironment",
        ):
            self.assertIn(field, carrier)
        self.assertNotIn("def generatedParameters", source)
        self.assertIn(
            "Acceptance.generatedRequirements parameters.acceptance",
            source,
        )
        self.assertIn(
            "generatedCanonicalMixedRelationProfile\n    "
            "(generatedGNUHelloRequirements parameters)",
            source,
        )
        self.assertIn(
            "theorem generatedGNUHelloMixedWorldProgramsEquivalent :", source
        )
        self.assertIn("forall parameters : Parameters,", source)
        self.assertIn(
            "generatedMixedWorldProgramsEquivalent\n"
            "    (generatedGNUHelloRequirements parameters)",
            source,
        )
        self.assertIn(
            "CanonicalMixedWorldProgramsChunkObservationallyEquivalent\n"
            "        (candidatePE32CanonicalMixedRelationProfile parameters)",
            source,
        )
        self.assertNotIn("variable (evidence", source)
        self.assertNotIn("DynamicEvidence) :", source)
        self.assertNotIn("JSON", source)
        self.assertNotIn("result := fun _ event", source)
        self.assertNotIn("action := fun request", source)
        self.assertNotIn("action := fun _ event world", source)
        for field in GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS:
            self.assertRegex(source, rf"(?m)^  {field} := Concrete\.generated")
        for forbidden in ("axiom", "sorry", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{forbidden}\b", source))

    def test_strengthening_constructors_cannot_be_bypassed(self) -> None:
        concrete = {
            field: f"Concrete.generated{index}"
            for index, field in enumerate(
                GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS
            )
        }
        with patch(f"{_MODULE}._DYNAMIC_EVIDENCE_EXPRESSIONS", concrete):
            with self.assertRaisesRegex(
                GnuHelloMixedAcceptanceGenerationError,
                "toMixedWorldChunkComposition, combinedExtension, "
                "withInvariantExtension",
            ):
                build_gnu_hello_mixed_acceptance_plan()

        concrete["environment_compositions"] = (
            "Concrete.generated_toMixedWorldChunkComposition_"
            "combinedExtension_withInvariantExtension"
        )
        with patch(f"{_MODULE}._DYNAMIC_EVIDENCE_EXPRESSIONS", concrete):
            with self.assertRaisesRegex(
                GnuHelloMixedAcceptanceGenerationError,
                "mixedWorldLaunchPrefixCertificateWithInvariantExtension",
            ):
                build_gnu_hello_mixed_acceptance_plan()

    def test_exports_fixed_names_for_public_wrapper(self) -> None:
        self.assertEqual(
            GNU_HELLO_MIXED_ACCEPTANCE_PROFILE,
            "StageA.GeneratedRelational.GnuHelloMixedAcceptance."
            "candidatePE32CanonicalMixedRelationProfile",
        )
        self.assertEqual(
            GNU_HELLO_MIXED_ACCEPTANCE_SOURCE_THEOREM,
            "StageA.GeneratedRelational.GnuHelloMixedAcceptance."
            "generatedGNUHelloMixedWorldProgramsEquivalent",
        )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_no_case_and_generic_composition_kernel_interfaces(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in (
                "RelationalInterpreterMixedExternalComponent",
                "RelationalRuntimeIndirectComposition",
            ):
                _copy_module_closure(source_root, stage_a, module)
            (
                stage_a / "GnuHelloMixedAcceptanceKernelAudit.lean"
            ).write_text(_KERNEL_AUDIT_FIXTURE, encoding="ascii")
            result = _run_lean_relational(
                root, bundle="GnuHelloMixedAcceptanceKernelAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("native_decide.ax", output)
        for declaration in (
            "classifiedExactMixedExternalBoundaryEvidenceFactoryOfNoCases",
            "constructiveSemanticRulesWithRootBoundary_hasNoExternalOperations",
            "constructiveRuntimeExternalOperationComponentOfNoCases",
            "CheckedMixedKernelComponentCases.toMixedWorldChunkComposition",
            "MixedWorldChunkComposition.withInvariantExtension",
            "mixedWorldLaunchPrefixCertificateWithInvariantExtension",
            "combinedExtension",
            "combinedMixedInvariant",
            "combinedExtension_holds_at_root_of_checked",
        ):
            self.assertIn(declaration, output)

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip()
                for item in match.group(1).split(",")
                if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)

    def test_driver_accepts_only_output_path(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        driver = repo / "targets/gnu-hello/nix/gnu-hello-mixed-acceptance.py"
        process = subprocess.run(
            [
                sys.executable,
                str(driver),
                "--out",
                str(repo / ".tmp/gnu-mixed-acceptance-test"),
                "--source-theorem",
                "Injected.theorem",
            ],
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertNotEqual(process.returncode, 0)
        self.assertIn("unrecognized arguments", process.stderr)


_KERNEL_AUDIT_FIXTURE = r"""
import StageA.RelationalInterpreterMixedExternalComponent
import StageA.RelationalRuntimeIndirectComposition

namespace StageA.GnuHelloMixedAcceptanceKernelAudit

open StageA.Relational
open StageA.Relational.InterpreterMixedExternalComponent
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.MixedExecutionInvariantExtension
open StageA.Relational.RuntimeIndirectComposition

#check classifiedExactMixedExternalBoundaryEvidenceFactoryOfNoCases
#check constructiveSemanticRulesWithRootBoundary_hasNoExternalOperations
#check constructiveRuntimeExternalOperationComponentOfNoCases
#check CheckedMixedKernelComponentCases.toMixedWorldChunkComposition
#check MixedWorldChunkComposition.withInvariantExtension
#check mixedWorldLaunchPrefixCertificateWithInvariantExtension
#check combinedExtension
#check combinedMixedInvariant
#check combinedExtension_holds_at_root_of_checked

#print axioms classifiedExactMixedExternalBoundaryEvidenceFactoryOfNoCases
#print axioms constructiveSemanticRulesWithRootBoundary_hasNoExternalOperations
#print axioms constructiveRuntimeExternalOperationComponentOfNoCases
#print axioms CheckedMixedKernelComponentCases.toMixedWorldChunkComposition
#print axioms MixedWorldChunkComposition.withInvariantExtension
#print axioms mixedWorldLaunchPrefixCertificateWithInvariantExtension
#print axioms combinedExtension
#print axioms combinedMixedInvariant
#print axioms combinedExtension_holds_at_root_of_checked

end StageA.GnuHelloMixedAcceptanceKernelAudit
"""


if __name__ == "__main__":
    unittest.main()
