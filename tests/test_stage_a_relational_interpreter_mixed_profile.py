from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


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


class StageARelationalInterpreterMixedProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterMixedProfile.lean"
        ).read_text(encoding="utf-8")

    def test_profile_uses_one_sided_authorities_and_concrete_candidate_abi(self) -> None:
        self.assertIn("structure CanonicalMixedRelationCore", self.source)
        self.assertIn("ExactOriginalDecodedAuthority original", self.source)
        self.assertIn("ExactNativeCandidateAuthority candidate", self.source)
        self.assertIn("ConcreteKernelABI candidate.pe candidate.imports", self.source)
        self.assertIn("ExactMixedProgramBinding original originalProgram", self.source)
        for forbidden in (
            "(context : StaticProofContext)",
            "RelationalProductGraph",
            "ProductInvariantTable",
            "RelationalProductReachabilityEvidence",
            "OriginalCodeMapProjectionExact",
            "ExactMixedStaticContextBinding",
        ):
            self.assertNotIn(forbidden, self.source)

    def test_candidate_code_correspondence_is_a_small_checked_anchor_map(self) -> None:
        self.assertIn("structure MixedNativeCodeAnchor", self.source)
        self.assertIn("def MixedNativeLaunchAnchorsComplete", self.source)
        self.assertIn("candidatePELaunchRoots? candidate.pe", self.source)
        self.assertIn("launch.tlsCallbackTargetIds", self.source)
        self.assertIn("launchAnchorsComplete :", self.source)
        self.assertIn("original.sourceAtValid anchor.originalTargetId", self.source)
        self.assertIn("executableRva candidate.pe anchor.candidateRva", self.source)
        self.assertIn("(anchors.map (·.originalTargetId)).Nodup", self.source)
        self.assertIn("(anchors.map (·.candidateRva)).Nodup", self.source)
        self.assertNotIn("context.codeMap.get?", self.source)

    def test_runtime_and_value_relations_are_fixed_checked_definitions(self) -> None:
        contract_start = self.source.index("def CanonicalMixedRelationCore.contract")
        contract_end = self.source.index(
            "/-- Final relation policy.", contract_start
        )
        contract = self.source[contract_start:contract_end]
        for relation in (
            "CanonicalMixedWorldsRelated",
            "CanonicalMixedLaunchStatesRelated",
            "CanonicalMixedRuntimeStatesRelated",
            "CanonicalMixedValuesRelated",
            "CheckedMixedCallbackTargetsRelated",
        ):
            self.assertIn(relation, contract)
        self.assertIn("OriginalEngineStateHolds", self.source)
        self.assertIn("CanonicalMixedRuntimeValueTargets", self.source)
        self.assertNotIn("CanonicalMixedRelationExtension", self.source)

    def test_launch_relation_is_loader_state_not_prepopulated_engine_state(self) -> None:
        start = self.source.index("def CanonicalMixedLaunchStatesRelated")
        end = self.source.index(
            "/-- The native machine contains an exact engine encoding", start
        )
        launch_relation = self.source[start:end]
        self.assertIn("CanonicalMixedPE32ConsoleLaunchStatePair", launch_relation)
        self.assertNotIn("OriginalEngineStateHolds", launch_relation)
        for required in (
            "stackRangeId",
            "tebRangeId",
            "pebRangeId",
            "processParametersRangeId",
            "argvRangeId",
            "environmentRangeId",
            "tlsArrayRangeId",
            "CanonicalMixedImportAddressesMemoryHold",
            "CanonicalMixedTlsSlotsMemoryHold",
            "launchStatesRelated_iff",
        ):
            self.assertIn(required, self.source)

    def test_launch_wrapper_is_exact_nonempty_semantic_evidence(self) -> None:
        start = self.source.index("structure CanonicalMixedLaunchWrapperRefinement")
        end = self.source.index(
            "def decodedWorldProgramWithProtocolEnvironment", start
        )
        wrapper = self.source[start:end]
        self.assertIn("ExactNativeLaunchGraphCertificate", wrapper)
        self.assertIn("staticChecked : reflected.staticChecked", wrapper)
        self.assertIn(
            "routeReady : ReflectedNativeLaunchGraphRoute",
            wrapper,
        )
        self.assertIn("replayTotal : forall route", wrapper)
        self.assertIn("rootsEstablishRuntime : forall root", wrapper)
        self.assertIn("route.replay? candidate", wrapper)
        self.assertIn("contract.runtimeStatesRelated", wrapper)
        self.assertIn(
            "structure CanonicalMixedLaunchRootFrameFacts",
            wrapper,
        )
        self.assertIn("rootReady : forall root", wrapper)
        self.assertIn(
            "exactNativeLaunchGraphRuntime_rootsEstablishRuntime",
            wrapper,
        )
        self.assertIn(
            "CanonicalMixedLaunchWrapperRefinement.ofCheckedRuntime",
            wrapper,
        )
        self.assertIn(
            "structure ExactCanonicalMixedLaunchWrapperRefinementBinding",
            wrapper,
        )
        self.assertIn("reflectedExact : refinement.reflected", wrapper)
        self.assertIn(
            "ExactCanonicalMixedLaunchWrapperRefinementBinding.replayTotal",
            wrapper,
        )
        self.assertIn(
            "ExactCanonicalMixedLaunchWrapperRefinementBinding.rootsEstablishRuntime",
            wrapper,
        )
        self.assertIn(
            "ExactCanonicalMixedLaunchWrapperRefinementBinding.ofCheckedRuntime",
            wrapper,
        )
        self.assertNotIn("exists before", wrapper)

    def test_profile_requires_realizable_launch_and_universal_environment_refinement(
        self,
    ) -> None:
        self.assertIn("launchRealizable : MixedLaunchRealizable", self.source)
        self.assertIn(
            "launchWrapperRefines : forall originalEnvironment candidateEnvironment",
            self.source,
        )
        self.assertIn("CanonicalMixedLaunchWrapperRefinement", self.source)
        self.assertIn("externalFrames : MixedExternalFrameContract", self.source)
        self.assertIn(
            "certificates : forall originalEnvironment candidateEnvironment",
            self.source,
        )
        self.assertIn("ExactOneToOneMixedExternalEnvironmentsRefine", self.source)
        profile_start = self.source.index("structure CanonicalMixedRelationProfile")
        profile_end = self.source.index(
            "def CanonicalMixedRelationProfile.contract", profile_start
        )
        self.assertNotIn("environmentRefines :", self.source[profile_start:profile_end])

    def test_operation_dispatches_are_indexed_then_lifted_to_checked_union(self) -> None:
        self.assertIn("abbrev KernelOperationDispatchFamily", self.source)
        self.assertIn("def combinedKernelDispatchRelation", self.source)
        self.assertIn("exists operation, family operation", self.source)
        self.assertIn("kernelOperationRefinesUsing_combined", self.source)

    def test_final_acceptance_quantifies_environment_pairs_and_keeps_authorities(
        self,
    ) -> None:
        start = self.source.index("structure CanonicalMixedWorldAcceptanceCertificate")
        final_surface = self.source[start:]
        self.assertIn("profile.contract", final_surface)
        self.assertIn(
            "certificates : forall originalEnvironment candidateEnvironment",
            final_surface,
        )
        self.assertIn("decodedWorldProgramWithProtocolEnvironment", final_surface)
        self.assertIn("exactNativeWorldProgramWithEnvironment", final_surface)
        self.assertIn("MixedWorldAcceptanceCertificate original", final_surface)
        self.assertIn("canonicalMixedWorldProgramsEquivalent", final_surface)
        self.assertIn(
            "(originalEnvironment : WorldExternalProtocolEnvironment)",
            final_surface,
        )
        self.assertIn(
            "(candidateEnvironment : NativeWorldEnvironment)", final_surface
        )
        self.assertIn("certificate.certificates originalEnvironment", final_surface)

    def test_profile_has_no_unchecked_proof_escape_hatches(self) -> None:
        for forbidden in ("native_decide", "sorry", "axiom ", "opaque "):
            self.assertNotIn(forbidden, self.source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_profile_kernel_rejects_permissive_values_and_exposes_authority(
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
                source_root, stage_a, "RelationalInterpreterMixedProfile"
            )
            (stage_a / "RelationalInterpreterMixedProfileKernel.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterMixedProfileKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 6, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, RELATIONAL_APPROVED_AXIOMS, report)


_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterMixedProfile

namespace StageA.Relational.InterpreterMixedProfileKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedLaunchRefinement
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

example
    (checked : CheckedExactNativeLaunchGraph)
    (refinement :
      CanonicalMixedLaunchWrapperRefinement original candidate contract launch)
    (binding : ExactCanonicalMixedLaunchWrapperRefinementBinding checked original
      candidate contract launch refinement) :
    checked.certificate.staticChecked candidate.pe candidate.imports = true :=
  binding.staticChecked

#check ExactCanonicalMixedLaunchWrapperRefinementBinding.replayTotal
#check ExactCanonicalMixedLaunchWrapperRefinementBinding.rootsEstablishRuntime

example
    (runtime : ExactNativeLaunchGraphRuntime checked candidate)
    (frames : CanonicalMixedLaunchRootFrameFacts checked runtime original
      candidate contract launch) :
    ExactCanonicalMixedLaunchWrapperRefinementBinding checked original candidate
      contract launch
      (CanonicalMixedLaunchWrapperRefinement.ofCheckedRuntime runtime frames) :=
  ExactCanonicalMixedLaunchWrapperRefinementBinding.ofCheckedRuntime runtime
    frames

example
    (core : CanonicalMixedRelationCore original originalAuthority originalProgram
      candidate candidateAuthority programBinding abi reachability.targetIds)
    (launchAnchorsComplete : MixedNativeLaunchAnchorsComplete candidate launch
      core.anchors = true)
    (frames : MixedExternalFrameContract)
    (realizable : MixedLaunchRealizable original candidate core.contract)
    (wrapperRefines : forall originalEnvironment candidateEnvironment,
      ExactOneToOneMixedExternalEnvironmentsRefine
          (decodedWorldProgramWithProtocolEnvironment originalProgram
            originalEnvironment)
          (exactNativeWorldProgramWithEnvironment candidate candidateEnvironment)
          core.contract frames ->
        CanonicalMixedLaunchWrapperRefinement original
          (exactNativeWorldProgramWithEnvironment candidate candidateEnvironment)
          core.contract launch)
    (checked : CheckedExactNativeLaunchGraph)
    (_routeBinding : forall originalEnvironment candidateEnvironment
      (environmentRefines :
        ExactOneToOneMixedExternalEnvironmentsRefine
          (decodedWorldProgramWithProtocolEnvironment originalProgram
            originalEnvironment)
          (exactNativeWorldProgramWithEnvironment candidate candidateEnvironment)
          core.contract frames),
      ExactCanonicalMixedLaunchWrapperRefinementBinding checked original
        (exactNativeWorldProgramWithEnvironment candidate candidateEnvironment)
        core.contract launch
        (wrapperRefines originalEnvironment candidateEnvironment
          environmentRefines)) :
    CanonicalMixedRelationProfile original originalAuthority originalProgram
      candidate candidateAuthority programBinding abi launch originalRoot
      reachability := {
  core
  launchAnchorsComplete
  externalFrames := frames
  launchRealizable := realizable
  launchWrapperRefines := wrapperRefines
}

example (candidate : ExactNativeWorldProgram) (launch : PE32ConsoleLaunchV2)
    (roots : CandidatePELaunchRoots)
    (rootsExact : candidatePELaunchRoots? candidate.pe = some roots) :
    MixedNativeLaunchAnchorsComplete candidate launch [] = false := by
  simp [MixedNativeLaunchAnchorsComplete, rootsExact]

example
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability) :
    ExactOriginalDecodedAuthority original :=
  originalAuthority

example
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability) :
    ExactNativeCandidateAuthority candidate :=
  candidateAuthority

example (wrong : ExactOriginalDecodedAuthority otherOriginal) : True := by
  fail_if_success
    exact (wrong : ExactOriginalDecodedAuthority original)
  trivial

example (wrong : ExactNativeCandidateAuthority otherCandidate) : True := by
  fail_if_success
    exact (wrong : ExactNativeCandidateAuthority candidate)
  trivial

example
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability)
    (related : profile.contract.runtimeStatesRelated originalWorld candidateWorld
      originalState candidateState) :
    exists targetId source,
      targetId ∈ reachability.targetIds /\
        original.source? targetId = some source /\
        (OriginalEngineStateHolds abi.engineLayout abi.parameters.inputAddress
            source.target.rva originalState candidateState \/
          OriginalEngineStateHolds abi.engineLayout
            (abi.parameters.outputAddress abi.engineLayout)
            source.target.rva originalState candidateState) :=
  profile.runtimeStateRepresented related

example
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability)
    (related : profile.contract.launchStatesRelated originalWorld candidateWorld
      originalState candidateState) :
    Nonempty (CanonicalMixedPE32ConsoleLaunchStatePair original candidate
      profile.core.anchors profile.core.launchMemoryProfile originalWorld
      candidateWorld originalState candidateState) :=
  (profile.launchStatesRelated_iff originalWorld candidateWorld originalState
    candidateState).mp related

example (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram) :
    ¬ CanonicalMixedValuesRelated original candidate []
      RelationalWorld.empty RelationalWorld.empty (BitVec.ofNat 32 0)
        (BitVec.ofNat 32 1) := by
  simp [CanonicalMixedValuesRelated, CanonicalMixedWorldsRelated,
    CanonicalMixedRelationalWorldValid, CanonicalMixedWordPayloadRelated,
    wordRelated,
    CheckedMixedAnchorValuesRelated]

example
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability)
    (certificate : CanonicalMixedWorldAcceptanceCertificate original originalProgram
      candidate profile.contract profile.externalFrames launch) :
    CanonicalMixedWorldProgramsChunkObservationallyEquivalent profile := by
  intro originalEnvironment candidateEnvironment environmentRefines
  exact canonicalMixedWorldProgramsEquivalent profile certificate
    originalEnvironment candidateEnvironment environmentRefines

#print axioms CanonicalMixedRelationProfile.runtimeStateRepresented
#print axioms CanonicalMixedRelationProfile.launchStatesRelated_iff
#print axioms CanonicalMixedRelationProfile.callbackTargetMapped
#print axioms CanonicalMixedRelationProfile.mixedLaunchRealizable
#print axioms kernelOperationRefinesUsing_combined
#print axioms canonicalMixedWorldProgramsEquivalent
#print axioms canonicalMixedWorldProgramsEquivalent_trace

end StageA.Relational.InterpreterMixedProfileKernel
"""


if __name__ == "__main__":
    unittest.main()
