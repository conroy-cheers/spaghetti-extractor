from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


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


_FIXTURE = r'''import StageA.RelationalNativeSourceNestedAdmittedResponseFamily

namespace StageA.NativeSourceNestedCompilationKernel

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.NativeSource

example (compilation : ExactNativeCompilation)
    (nested : ExactNestedNativeCompilation compilation)
    (sourceFamily : CheckedNativeSourceLaunchFamily compilation.project)
    (launchRealizable : NestedNativeCompilationLaunchRealizable nested)
    (toolchainCorrect : CorrectPinnedNestedNativeSourceStackHypothesis compilation
      nested) :
    ExactRawOriginalPENestedCompiledArtifactLaunchFamilyEquivalence compilation
      nested :=
  compiledNestedArtifactLaunchFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    compilation nested sourceFamily launchRealizable toolchainCorrect

example {context : StaticProofContext}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    (responseFamily : CheckedWorldNativeAdmittedProtocolResponseFamily context
      classified ordinarySites compilation mixed frames)
    (completion : responseFamily.Completion)
    (toolchainCorrectAt : forall sourceEnvironment nativeEnvironment,
      responseFamily.Related sourceEnvironment nativeEnvironment ->
        CorrectPinnedNestedNativeSourceStackHypothesis
          (exactNativeCompilationAtResponseEnvironments compilation
            sourceEnvironment
            nativeEnvironment.ordinary)
          (exactNestedNativeCompilationAtResponseEnvironments compilation
            sourceEnvironment nativeEnvironment)) :
    ExactRawOriginalPENestedCompiledArtifactAdmittedEnvironmentFamilyEquivalence
      context classified ordinarySites compilation mixed frames
      responseFamily.Related :=
  compiledNestedArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    (responseFamily.toNestedAcceptance completion toolchainCorrectAt)

/-- Initial callback entry is a checked two-step original/native chunk. -/
example (original : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (originalBefore : WorldExecution)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNestedNativeExternalDispatch candidate)
    (originalDispatch : ExactOriginalExternalDispatch original originalBefore
      suspension callbacks)
    (boundaryRelated : contract.externalBoundariesRelated suspension
      dispatch.boundary)
    (suspensionsRelated : MixedNestedExternalSuspensionsRelated contract frames
      suspension callbacks dispatch.suspension dispatch.externalFrames)
    (environmentsRefine : ExactOneToOneMixedNestedExternalEnvironmentsRefine
      original candidate contract frames) :
    ExactMixedNestedExternalInteractionChunk original candidate contract frames
      originalBefore suspension callbacks dispatch :=
  exactMixedNestedExternalInteractionChunk original candidate contract frames
    originalBefore suspension callbacks dispatch originalDispatch boundaryRelated
    suspensionsRelated environmentsRefine

/-- Every later callback/return/termination protocol phase composes through
the same checked action relation. -/
example (original : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate)
    (suspensionsRelated : MixedNestedExternalSuspensionsRelated contract frames
      suspension callbacks boundary.suspension boundary.externalFrames)
    (environmentsRefine : ExactOneToOneMixedNestedExternalEnvironmentsRefine
      original candidate contract frames) :
    ExactMixedNestedExternalProtocolChunk original candidate contract frames
      suspension callbacks boundary :=
  exactMixedNestedExternalProtocolChunk original candidate contract frames
    suspension callbacks boundary suspensionsRelated environmentsRefine

/-- Returning from a callback restores the suspended protocol frame and moves
both sides to the same next phase. -/
example
    (original : ExactOriginalExternalCallbackReturnDispatch originalProgram)
    (candidate : ExactNestedNativeExternalCallbackReturnDispatch candidateProgram)
    (frameStacksRelated : MixedNestedExternalCallbackFramesRelated contract frames
      (original.frame :: original.outerFrames)
      (candidate.frame :: candidate.outerFrames))
    (worldsRelated : contract.worldsRelated original.world candidate.world)
    (statesRelated : contract.runtimeStatesRelated original.world candidate.world
      original.afterState candidate.afterState)
    (argumentsRelated : mixedValuesRelated
      (contract.valuesRelated original.world candidate.world)
      original.frame.suspension.arguments
      candidate.frame.suspension.event.arguments) :
    ExactMixedNestedExternalCallbackReturnChunk originalProgram candidateProgram
      contract frames original candidate :=
  exactMixedNestedExternalCallbackReturnChunk original candidate
    frameStacksRelated worldsRelated statesRelated argumentsRelated

/-- Termination is accepted only as a matched protocol action with related
successor worlds. -/
example (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (originalWorld candidateWorld : RelationalWorld)
    (worldsRelated : contract.worldsRelated originalWorld candidateWorld) :
    MixedNestedExternalEnvironmentActionsRelated candidate contract frames
      (.terminated originalWorld) (.terminated candidateWorld) :=
  worldsRelated

#print axioms compiledNestedArtifactEquivalentUnderPinnedNativeSourceStackHypothesis
#print axioms compiledNestedArtifactLaunchFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
#print axioms compiledNestedArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
#print axioms exactMixedNestedExternalInteractionChunk
#print axioms exactMixedNestedExternalProtocolChunk
#print axioms exactMixedNestedExternalCallbackReturnChunk

end StageA.NativeSourceNestedCompilationKernel
'''


class StageANativeSourceNestedCompilationKernelTests(unittest.TestCase):
    def test_nested_acceptance_and_callback_composition_are_checked(self) -> None:
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
                "RelationalNativeSourceNestedAdmittedResponseFamily",
            )
            (stage_a / "NativeSourceNestedCompilationKernel.lean").write_text(
                _FIXTURE, encoding="ascii"
            )
            checked = _run_lean_relational(
                root, bundle="NativeSourceNestedCompilationKernel"
            )
        self.assertEqual(checked["status"], "checked", checked)
        output = checked["stdout"] + checked["stderr"]
        inventories = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(inventories), 5, output)
        self.assertTrue(
            all(
                {name.strip() for name in inventory.split(",") if name.strip()}
                <= {"propext", "Classical.choice", "Quot.sound"}
                for inventory in inventories
            ),
            output,
        )


if __name__ == "__main__":
    unittest.main()
