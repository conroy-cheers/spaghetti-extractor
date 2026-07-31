from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.gnu_hello_acceptance_requirements import (
    GNU_HELLO_CANDIDATE_ROOT_RVA as ACCEPTANCE_CANDIDATE_ROOT_RVA,
)
from spaghetti_extractor.relational.lean.gnu_hello_acceptance_requirements import (
    GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA as ACCEPTANCE_BOUNDARY_RVA,
)
from spaghetti_extractor.relational.lean.gnu_hello_external_component import (
    GNU_HELLO_CANDIDATE_ROOT_RVA,
    GNU_HELLO_EXTERNAL_COMPONENT_MANIFEST,
    GNU_HELLO_EXTERNAL_COMPONENT_MODULE,
    GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA,
    GnuHelloExternalComponentSpec,
    build_gnu_hello_external_component_plan,
    gnu_hello_external_component_source,
    write_gnu_hello_external_component,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


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


class StageAGnuHelloExternalComponentTests(unittest.TestCase):
    def test_generic_bridge_splices_exact_nonempty_operation_chunk(
        self,
    ) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterMixedBoundaryOperation.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "structure ExactMixedKernelBoundaryToOperationBridge",
            "operationBefore : NativeWorldExecution",
            "candidatePrefix : NonemptyRelatedPath candidate.transitionSystem",
            "boundaryBefore []",
            "certificate : MixedKernelOperationComponentCertificate",
            "sourceRva",
            "owner.operation owner.entryRva",
            "def ExactMixedKernelBoundaryToOperationBridge.toChunk",
            (
                "bridge.candidatePrefix.trans "
                "bridge.certificate.paths.candidatePath"
            ),
            "observationsChecked := bridge.certificate.paths.observationsChecked",
            "afterRelated := bridge.certificate.paths.afterRelated",
            "#print axioms ExactMixedKernelBoundaryToOperationBridge.toChunk",
        ):
            self.assertIn(required, source)
        for forbidden in (
            r"\bsorry\b",
            r"\badmit\b",
            r"\baxiom\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bstatus\b",
            r"\bverdict\b",
            r"\breport\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_generator_matches_acceptance_root_boundary_inventory(self) -> None:
        plan = build_gnu_hello_external_component_plan()
        source = gnu_hello_external_component_source(plan)
        payload = plan.payload()

        self.assertFalse(plan.complete)
        self.assertFalse(payload["complete"])
        self.assertFalse(payload["acceptance_authority"])
        self.assertFalse(payload["proof_authority"])
        self.assertEqual(
            GNU_HELLO_CANDIDATE_ROOT_RVA,
            ACCEPTANCE_CANDIDATE_ROOT_RVA,
        )
        self.assertEqual(
            GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA,
            ACCEPTANCE_BOUNDARY_RVA,
        )
        classification = payload["external_boundary_classification"]
        self.assertEqual(classification["separate_classifier_cases"], 1)
        self.assertEqual(
            classification["candidate_rva"],
            GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA,
        )
        self.assertEqual(classification["operation"], "interpreterStep")
        self.assertEqual(len(payload["remaining_premises"]), 1)
        self.assertEqual(len(payload["blocking_obligations"]), 1)

        for required in (
            "constructiveSemanticRulesWithRootBoundary",
            f"(candidateRootRva := {GNU_HELLO_CANDIDATE_ROOT_RVA})",
            str(GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA),
            "generatedInterpreterStepEntry",
            "constructiveMixedKernelRuntimeInvariant",
            "constructiveMixedKernelRuntimeSourceClassifier",
            "GeneratedRootBoundaryToOperationBridge",
            "GeneratedRootBoundaryToOperationBridgeFactory",
            "GeneratedExternalBoundaryChunkFactory",
            "beforeRelated",
            "classified",
            "ExactMixedKernelBoundaryToOperationBridge",
            "generatedExternalBoundaryChunkFactoryOfOperationBridge",
            ").toChunk",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "constructiveSemanticRulesWithLaunch_hasNoExternalBoundaries",
            "generatedExternalBoundaryCasesAbsent",
            "classifiedExactMixedExternalBoundaryEvidenceFactoryOfNoCases",
            "ExactNativeExternalDispatch",
            "ExactOriginalExternalDispatch",
            "originalPath :=",
            "candidatePath :=",
            r"\bsorry\b",
            r"\badmit\b",
            r"\baxiom\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bstatus\b",
            r"\bverdict\b",
            r"\breport\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_manifest_fails_closed_on_exact_missing_bridge(self) -> None:
        payload = build_gnu_hello_external_component_plan().payload()

        self.assertNotIn("status", payload)
        self.assertNotIn("failure_mode", payload)
        self.assertIn(
            "silent nonempty candidate path",
            payload["remaining_premises"][0],
        )
        self.assertIn(
            "MixedKernelOperationComponentCertificate",
            payload["remaining_premises"][0],
        )
        self.assertIn(
            str(GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA),
            payload["blocking_obligations"][0],
        )

    def test_writer_is_deterministic_and_manifest_is_diagnostic(self) -> None:
        spec = GnuHelloExternalComponentSpec()
        expected = gnu_hello_external_component_source(
            build_gnu_hello_external_component_plan(spec)
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = write_gnu_hello_external_component(root, spec)
            source_path = (
                root / "StageA" / f"{GNU_HELLO_EXTERNAL_COMPONENT_MODULE}.lean"
            )
            first_source = source_path.read_bytes()
            first_manifest = (
                root / GNU_HELLO_EXTERNAL_COMPONENT_MANIFEST
            ).read_bytes()
            second = write_gnu_hello_external_component(root, spec)
            second_source = source_path.read_bytes()
            second_manifest = (
                root / GNU_HELLO_EXTERNAL_COMPONENT_MANIFEST
            ).read_bytes()

        self.assertEqual(first, second)
        self.assertEqual(first_source, second_source)
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(first_source, expected.encode("ascii"))
        manifest = json.loads(first_manifest)
        self.assertFalse(manifest["complete"])
        self.assertFalse(manifest["acceptance_authority"])
        self.assertFalse(manifest["proof_authority"])

    def test_generator_rejects_malformed_inputs(self) -> None:
        base = GnuHelloExternalComponentSpec()
        for change in (
            {"module_name": "StageA.Bad"},
            {"namespace": "StageA.Bad-Namespace"},
            {"original_module": "GeneratedOriginal"},
            {"reachability": "StageA.notLocal"},
            {"candidate_root_rva": -1},
            {"runtime_boundary_rva": 2**32},
            {"runtime_boundary_rva": True},
        ):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    build_gnu_hello_external_component_plan(
                        dataclasses.replace(base, **change)
                    )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generic_bridge_kernel_checks_with_approved_axioms(self) -> None:
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
                "RelationalInterpreterMixedBoundaryOperation",
            )
            (
                stage_a
                / "RelationalInterpreterMixedBoundaryOperationAudit.lean"
            ).write_text(_GENERIC_AUDIT, encoding="ascii")
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterMixedBoundaryOperationAudit",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertIn(
            "ExactMixedKernelBoundaryToOperationBridge.toChunk",
            output,
        )
        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_component_kernel_checks_against_root_fixture(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        fixture_module = "StageA.GnuHelloExternalComponentFixture"
        fixture_namespace = "StageA.GnuHelloExternalComponentFixture"
        spec = dataclasses.replace(
            GnuHelloExternalComponentSpec(),
            original_module=fixture_module,
            original_namespace=f"{fixture_namespace}.Original",
            reachability_module=fixture_module,
            reachability_namespace=f"{fixture_namespace}.Reachability",
            source_bindings_module=fixture_module,
            source_bindings_namespace=f"{fixture_namespace}.SourceBindings",
            source_rules_module=fixture_module,
            source_rules_namespace=f"{fixture_namespace}.SourceRules",
            source_coverage_module=fixture_module,
            source_coverage_namespace=f"{fixture_namespace}.SourceCoverage",
            kernel_module=fixture_module,
            kernel_namespace=f"{fixture_namespace}.Kernel",
            candidate_root_rva=5152,
        )
        generated = gnu_hello_external_component_source(
            build_gnu_hello_external_component_plan(spec)
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedBoundaryOperation",
            )
            (stage_a / "GnuHelloExternalComponentFixture.lean").write_text(
                _GENERATED_FIXTURE_SOURCE,
                encoding="ascii",
            )
            (stage_a / f"{spec.module_name}.lean").write_text(
                generated,
                encoding="ascii",
            )
            (
                stage_a / "GnuHelloExternalComponentGeneratedAudit.lean"
            ).write_text(_GENERATED_AUDIT, encoding="ascii")
            kernel = _run_lean_relational(
                root,
                bundle="RelationalInterpreterMixedBoundaryOperation",
            )
            self.assertEqual(kernel["status"], "checked", kernel)
            outputs: list[str] = []
            lean = shutil.which("lean")
            assert lean is not None
            for module in (
                "GnuHelloExternalComponentFixture",
                spec.module_name,
                "GnuHelloExternalComponentGeneratedAudit",
            ):
                completed = subprocess.run(
                    [
                        lean,
                        "-o",
                        f"StageA/{module}.olean",
                        f"StageA/{module}.lean",
                    ],
                    cwd=root,
                    env={**os.environ, "LEAN_PATH": "."},
                    check=False,
                    capture_output=True,
                    text=True,
                )
                outputs.extend((completed.stdout, completed.stderr))
                self.assertEqual(
                    completed.returncode,
                    0,
                    "".join(outputs),
                )

        output = "".join(outputs)
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("native_decide.ax", output)


_GENERIC_AUDIT = r"""import StageA.RelationalInterpreterMixedBoundaryOperation

namespace StageA.Relational.InterpreterMixedBoundaryOperationAudit

open StageA.Relational.InterpreterMixedBoundaryOperation

#check ExactMixedKernelBoundaryToOperationBridge
#check ExactMixedKernelBoundaryToOperationBridge.toChunk
#print axioms ExactMixedKernelBoundaryToOperationBridge.toChunk

end StageA.Relational.InterpreterMixedBoundaryOperationAudit
"""


_GENERATED_FIXTURE_SOURCE = r"""import StageA.RelationalInterpreterMixedBoundaryOperation

open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

noncomputable section

namespace StageA.GnuHelloExternalComponentFixture

axiom originalContext : OriginalDecodedStaticContext
axiom originalAuthority : ExactOriginalDecodedAuthority originalContext
axiom launch : PE32ConsoleLaunchV2
axiom originalRoot :
  DirectExactOriginalDecodedLaunchRoot originalContext launch
axiom reachability :
  ExactOriginalDecodedReachability originalContext originalAuthority launch
    originalRoot

axiom candidatePe : PE32
axiom candidateImports : List PEImport

def candidateProgram (environment : NativeWorldEnvironment) :
    ExactNativeWorldProgram := {
  pe := candidatePe
  imports := candidateImports
  environment
}

axiom candidateAuthority (environment : NativeWorldEnvironment) :
  ExactNativeCandidateAuthority (candidateProgram environment)

def compiledProgram : CompiledKernelProgram := { functions := [] }
axiom stepEntry : ExactCandidateKernelEntry compiledProgram

namespace Original

def generatedOriginalStaticContext := originalContext
def generatedExactOriginalDecodedAuthority := originalAuthority
def generatedOriginalLaunch := launch
def generatedDirectExactOriginalDecodedLaunchRoot := originalRoot

end Original

namespace Reachability

def generatedExactOriginalDecodedStaticReachability := reachability

end Reachability

namespace SourceBindings

structure Requirements where
  candidateEnvironment : NativeWorldEnvironment

def Requirements.candidate (requirements : Requirements) :
    ExactNativeWorldProgram :=
  candidateProgram requirements.candidateEnvironment

def Requirements.candidateAuthority (requirements : Requirements) :
    ExactNativeCandidateAuthority requirements.candidate :=
  StageA.GnuHelloExternalComponentFixture.candidateAuthority
    requirements.candidateEnvironment

end SourceBindings

namespace SourceCoverage

axiom generatedExactOriginalSemanticSourceCoverage
    (requirements : SourceBindings.Requirements) :
    ExactOriginalSemanticSourceCoverage originalContext originalAuthority launch
      originalRoot reachability requirements.candidate
      requirements.candidateAuthority

end SourceCoverage

namespace Kernel

def generatedCompiledKernelProgram := compiledProgram

end Kernel

namespace SourceRules

def generatedInterpreterStepEntry := stepEntry

end SourceRules

end StageA.GnuHelloExternalComponentFixture
"""


_GENERATED_AUDIT = r"""import StageA.GeneratedGnuHelloExternalComponent

namespace StageA.GnuHelloExternalComponentGeneratedAudit

open StageA.GeneratedRelational.GnuHelloExternalComponent

#check generatedRuntimeRules
#check generatedRuntimeInvariant
#check generatedRuntimeClassifier
#check GeneratedRootBoundaryToOperationBridge
#check GeneratedRootBoundaryToOperationBridgeFactory
#check GeneratedExternalBoundaryChunkFactory
#check generatedExternalBoundaryChunkFactoryOfOperationBridge

#print axioms generatedRuntimeRules
#print axioms generatedRuntimeInvariant
#print axioms generatedRuntimeClassifier
#print axioms generatedExternalBoundaryChunkFactoryOfOperationBridge

end StageA.GnuHelloExternalComponentGeneratedAudit
"""


if __name__ == "__main__":
    unittest.main()
