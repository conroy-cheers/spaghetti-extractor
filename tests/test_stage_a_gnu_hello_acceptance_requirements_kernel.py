from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor_target_gnu_hello.gnu_hello_acceptance_requirements import (
    GnuHelloAcceptanceRequirementsSpec,
    build_gnu_hello_acceptance_requirements_plan,
    gnu_hello_acceptance_requirements_source,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAGnuHelloAcceptanceRequirementsKernelTests(unittest.TestCase):
    def test_generated_static_core_and_typed_dynamic_holes_elaborate(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        fixture_module = "StageA.GnuHelloAcceptanceFixture"
        spec = GnuHelloAcceptanceRequirementsSpec(
            candidate_root_rva=5152,
            original_module=fixture_module,
            reachability_module=fixture_module,
            original_carrier_module=fixture_module,
            callable_module=fixture_module,
            candidate_module=fixture_module,
            kernel_abi_module=fixture_module,
            kernel_module=fixture_module,
            core_bindings_module=fixture_module,
            core_module=fixture_module,
            source_bindings_module=fixture_module,
            source_rules_module=fixture_module,
            candidate_root_checked_term=(
                "StageA.GnuHelloAcceptanceFixture.candidateRootChecked"
            ),
            emit_axiom_audit=False,
        )
        generated = gnu_hello_acceptance_requirements_source(
            build_gnu_hello_acceptance_requirements_plan(spec)
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in (
                "RelationalInterpreterMixedKernelComposition",
                "RelationalInterpreterMixedProfile",
                "RelationalInterpreterMixedExternalComponent",
                "RelationalCallableExternalMixedBridge",
                "RelationalInterpreterNativeLaunch",
            ):
                _copy_module_closure(source_root, stage_a, module)
            (stage_a / "GnuHelloAcceptanceFixture.lean").write_text(
                _FIXTURE_SOURCE,
                encoding="ascii",
            )
            (
                stage_a / f"{spec.module_name}.lean"
            ).write_text(generated, encoding="ascii")
            (stage_a / "GnuHelloAcceptanceRequirementsKernel.lean").write_text(
                _KERNEL_SOURCE,
                encoding="ascii",
            )
            for module in (
                "RelationalInterpreterMixedKernelComposition",
                "RelationalInterpreterMixedProfile",
                "RelationalInterpreterMixedExternalComponent",
                "RelationalCallableExternalMixedBridge",
                "RelationalInterpreterNativeLaunch",
            ):
                result = _run_lean_relational(root, bundle=module)
                self.assertEqual(result["status"], "checked", result)

            outputs: list[str] = []
            lean = shutil.which("lean")
            assert lean is not None
            for module in (
                "GnuHelloAcceptanceFixture",
                spec.module_name,
                "GnuHelloAcceptanceRequirementsKernel",
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
                self.assertEqual(completed.returncode, 0, "".join(outputs))

        output = "".join(outputs)
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)


_FIXTURE_SOURCE = r"""import StageA.RelationalInterpreterMixedKernelComposition
import StageA.RelationalInterpreterMixedProfile
import StageA.RelationalCallableExternalMixedBridge
import StageA.RelationalInterpreterNativeLaunch

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalExecution
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

noncomputable section

namespace StageA.GnuHelloAcceptanceFixture

axiom originalContext : OriginalDecodedStaticContext
axiom originalAuthority : ExactOriginalDecodedAuthority originalContext
axiom carrierContext : StaticProofContext

def decodedProgram (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract) : DecodedWorldProgram := {
  candidate := false
  context := carrierContext
  regions := []
  externalCallSites
  environment
  protocolEnvironment
}

axiom originalProgramBinding
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract) :
    ExactMixedProgramBinding originalContext
      (decodedProgram environment protocolEnvironment externalCallSites)

def callableProgram : OriginalCallableProgram := {
  context := carrierContext
  resolverContracts := []
  capabilities := []
  resolvedABIContracts := []
  externalSites := []
}

axiom callableProgramValid : callableProgram.Valid
axiom launch : PE32ConsoleLaunchV2
axiom originalRoot :
  DirectExactOriginalDecodedLaunchRoot originalContext launch
axiom launchFrameCount :
  launch.frameOffsets.length = launch.continuationTargetIds.length
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

end StageA.GnuHelloAcceptanceFixture

open StageA.GnuHelloAcceptanceFixture

namespace StageA.GeneratedRelational.InterpreterMixedOriginal

def generatedOriginalStaticContext := originalContext
def generatedExactOriginalDecodedAuthority := originalAuthority
def generatedOriginalDecodedProgram := decodedProgram
def generatedOriginalLaunch := launch
def generatedDirectExactOriginalDecodedLaunchRoot := originalRoot
theorem generatedOriginalLaunchFrameCountChecked :
    generatedOriginalLaunch.frameOffsets.length =
      generatedOriginalLaunch.continuationTargetIds.length :=
  launchFrameCount

end StageA.GeneratedRelational.InterpreterMixedOriginal

namespace StageA.GeneratedRelational.InterpreterOriginalCarrierBinding

axiom generatedOriginalExactMixedProgramBinding
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract) :
    ExactMixedProgramBinding originalContext
      (decodedProgram environment protocolEnvironment externalCallSites)

end StageA.GeneratedRelational.InterpreterOriginalCarrierBinding

namespace StageA.GeneratedRelational.CallableExternalProgram

def originalCallableProgram := callableProgram
theorem originalCallableProgramValid : originalCallableProgram.Valid :=
  callableProgramValid

end StageA.GeneratedRelational.CallableExternalProgram

namespace StageA.GeneratedRelational.InterpreterMixedAuthority

def generatedCandidateNativeWorldProgram := candidateProgram
axiom generatedExactNativeCandidateAuthority
    (environment : NativeWorldEnvironment) :
    ExactNativeCandidateAuthority
      (generatedCandidateNativeWorldProgram environment)

end StageA.GeneratedRelational.InterpreterMixedAuthority

namespace StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability

def generatedExactOriginalDecodedStaticReachability := reachability

end StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability

namespace StageA.GeneratedRelational.InterpreterKernel

def generatedCompiledKernelProgram := compiledProgram

end StageA.GeneratedRelational.InterpreterKernel

namespace StageA.GeneratedRelational.InterpreterKernelABI

end StageA.GeneratedRelational.InterpreterKernelABI

namespace StageA.GeneratedRelational.GnuHelloCanonicalRelationCoreBindings

structure Requirements where
  originalEnvironment : WorldExternalEnvironment
  originalProtocolEnvironment : WorldExternalProtocolEnvironment
  originalExternalCallSites : List ExternalCallSiteContract
  candidateEnvironment : NativeWorldEnvironment

def Requirements.originalProgram (requirements : Requirements) :
    DecodedWorldProgram :=
  decodedProgram requirements.originalEnvironment
    requirements.originalProtocolEnvironment requirements.originalExternalCallSites

def Requirements.programBinding (requirements : Requirements) :
    ExactMixedProgramBinding originalContext requirements.originalProgram :=
  StageA.GeneratedRelational.InterpreterOriginalCarrierBinding.generatedOriginalExactMixedProgramBinding
    requirements.originalEnvironment requirements.originalProtocolEnvironment
    requirements.originalExternalCallSites

def Requirements.candidate (requirements : Requirements) :
    ExactNativeWorldProgram :=
  candidateProgram requirements.candidateEnvironment

def Requirements.candidateAuthority (requirements : Requirements) :
    ExactNativeCandidateAuthority requirements.candidate :=
  StageA.GeneratedRelational.InterpreterMixedAuthority.generatedExactNativeCandidateAuthority
    requirements.candidateEnvironment

axiom Requirements.concreteABI (requirements : Requirements) :
  ConcreteKernelABI requirements.candidate.pe requirements.candidate.imports
    requirements.candidateAuthority.relocations
    requirements.candidateAuthority.tableRva
    requirements.candidateAuthority.countRva
    requirements.candidateAuthority.semanticRecords

end StageA.GeneratedRelational.GnuHelloCanonicalRelationCoreBindings

namespace StageA.GeneratedRelational.GnuHelloCanonicalRelationCore

axiom generatedCanonicalMixedRelationCore
    (requirements :
      StageA.GeneratedRelational.GnuHelloCanonicalRelationCoreBindings.Requirements) :
    CanonicalMixedRelationCore originalContext originalAuthority
      requirements.originalProgram requirements.candidate
      requirements.candidateAuthority requirements.programBinding
      requirements.concreteABI reachability.targetIds

axiom generatedCanonicalMixedLaunchAnchorsComplete
    (requirements :
      StageA.GeneratedRelational.GnuHelloCanonicalRelationCoreBindings.Requirements) :
    MixedNativeLaunchAnchorsComplete requirements.candidate launch
      (generatedCanonicalMixedRelationCore requirements).anchors = true

end StageA.GeneratedRelational.GnuHelloCanonicalRelationCore

namespace StageA.GeneratedRelational.GnuHelloConstructiveSourceCoverageBindings

structure Requirements where
  candidateEnvironment : NativeWorldEnvironment

def Requirements.candidate (requirements : Requirements) :
    ExactNativeWorldProgram :=
  candidateProgram requirements.candidateEnvironment

def Requirements.candidateAuthority (requirements : Requirements) :
    ExactNativeCandidateAuthority requirements.candidate :=
  StageA.GeneratedRelational.InterpreterMixedAuthority.generatedExactNativeCandidateAuthority
    requirements.candidateEnvironment

end StageA.GeneratedRelational.GnuHelloConstructiveSourceCoverageBindings

namespace StageA.GeneratedRelational.InterpreterMixedSourceCoverage

axiom generatedExactOriginalSemanticSourceCoverage
    (requirements :
      StageA.GeneratedRelational.GnuHelloConstructiveSourceCoverageBindings.Requirements) :
    ExactOriginalSemanticSourceCoverage originalContext originalAuthority launch
      originalRoot reachability requirements.candidate
      requirements.candidateAuthority

end StageA.GeneratedRelational.InterpreterMixedSourceCoverage

namespace StageA.GeneratedRelational.GnuHelloConstructiveSourceRules

def generatedInterpreterStepEntry := stepEntry

axiom generatedInvariant
    (requirements :
      StageA.GeneratedRelational.GnuHelloConstructiveSourceCoverageBindings.Requirements)
    (contract : MixedRelationContract) :
    MixedExecutionInvariant reachability.targetIds contract

axiom generatedClassifier
    (requirements :
      StageA.GeneratedRelational.GnuHelloConstructiveSourceCoverageBindings.Requirements)
    (contract : MixedRelationContract) :
    forall originalBefore candidateBefore,
      (generatedInvariant requirements contract).holds
          originalBefore candidateBefore ->
        MixedKernelRelatedSourceCase originalContext originalAuthority launch
          originalRoot reachability requirements.candidate
          requirements.candidateAuthority compiledProgram 5152
          originalBefore candidateBefore

end StageA.GeneratedRelational.GnuHelloConstructiveSourceRules

namespace StageA.GnuHelloAcceptanceFixture

axiom candidateRootChecked (environment : NativeWorldEnvironment) :
  directExactCandidateNativeLaunchRootChecked (candidateProgram environment)
    launch 5152 = true

end StageA.GnuHelloAcceptanceFixture
"""


_KERNEL_SOURCE = r"""import StageA.GeneratedGnuHelloAcceptanceRequirements

namespace StageA.GnuHelloAcceptanceRequirementsKernel

#check StageA.GeneratedRelational.GnuHelloAcceptanceRequirements.generatedOriginalCallableBinding
#check StageA.GeneratedRelational.GnuHelloAcceptanceRequirements.generatedRelationCore
#check StageA.GeneratedRelational.GnuHelloAcceptanceRequirements.generatedCandidateRoot
#check StageA.GeneratedRelational.GnuHelloAcceptanceRequirements.generatedInvariant
#check StageA.GeneratedRelational.GnuHelloAcceptanceRequirements.generatedClassifySource
#check StageA.GeneratedRelational.GnuHelloAcceptanceRequirements.generatedCandidateLaunchCallsExact
#check StageA.GeneratedRelational.GnuHelloAcceptanceRequirements.DynamicEvidence
#check StageA.GeneratedRelational.GnuHelloAcceptanceRequirements.generatedRequirements

end StageA.GnuHelloAcceptanceRequirementsKernel
"""


if __name__ == "__main__":
    unittest.main()
