from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_mixed_world_bridge import (
    InterpreterMixedWorldBridgeSpec,
    write_relational_interpreter_mixed_world_bridge,
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
class StageARelationalInterpreterMixedWorldBridgeGenerationKernelTests(
    unittest.TestCase
):
    def test_generated_assembly_typechecks_without_unapproved_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterMixedWorldBridge"
            )
            (stage_a / "Bindings.lean").write_text(_BINDINGS, encoding="utf-8")
            write_relational_interpreter_mixed_world_bridge(root, _SPEC)
            (stage_a / "MixedBridgeAudit.lean").write_text(
                _AUDIT, encoding="utf-8"
            )
            result = _run_lean_relational(root, bundle="MixedBridgeAudit")

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertIn("generatedMixedWorldProgramsEquivalent", output)


_SPEC = InterpreterMixedWorldBridgeSpec(
    binding_module="StageA.Bindings",
    namespace="StageA.Generated.MixedAcceptance",
    original_context="requirements.originalContext",
    original_program="requirements.originalProgram",
    candidate_program="requirements.candidateProgram",
    contract="requirements.contract",
    launch="requirements.launch",
    original_authority="requirements.originalAuthority",
    candidate_authority="requirements.candidateAuthority",
    program_binding="requirements.programBinding",
    original_root="requirements.originalRoot",
    reachability="requirements.reachability",
    candidate_root_rva="requirements.candidateRootRva",
    candidate_root="requirements.candidateRoot",
    launch_realizable="requirements.launchRealizable",
    invariant="requirements.invariant",
    candidate_launch_calls="requirements.candidateLaunchCalls",
    candidate_launch_calls_exact="requirements.candidateLaunchCallsExact",
    roots_related="requirements.rootsRelated",
    component="requirements.component",
    requirement_parameter="requirements",
    requirement_type="StageA.Bindings.RequiredTerms",
)

_BINDINGS = r"""import StageA.RelationalInterpreterMixedWorldBridge

namespace StageA.Bindings

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

structure RequiredTerms where
  originalContext : OriginalDecodedStaticContext
  originalProgram : DecodedWorldProgram
  candidateProgram : ExactNativeWorldProgram
  contract : MixedRelationContract
  launch : PE32ConsoleLaunchV2
  originalAuthority : ExactOriginalDecodedAuthority originalContext
  candidateAuthority : ExactNativeCandidateAuthority candidateProgram
  programBinding : ExactMixedProgramBinding originalContext originalProgram
  originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch
  reachability : ExactOriginalDecodedReachability originalContext
    originalAuthority launch originalRoot
  candidateRootRva : Nat
  candidateRoot : DirectExactCandidateNativeLaunchRoot candidateProgram launch
    candidateRootRva
  launchRealizable : MixedLaunchRealizable originalContext candidateProgram contract
  invariant : MixedExecutionInvariant reachability.targetIds contract
  candidateLaunchCalls : MachineState -> List NativeCallFrame
  candidateLaunchCallsExact : forall candidateState,
    candidateNativeLaunchCallFrames? candidateProgram launch candidateState =
      some (candidateLaunchCalls candidateState)
  rootsRelated : forall originalWorld candidateWorld originalState candidateState,
    MixedLaunchStatesRelated originalContext candidateProgram contract
        originalWorld candidateWorld originalState candidateState ->
      invariant.holds
        (.running launch.rootTargetId originalState
          launch.continuationTargetIds 0 originalWorld)
        (.running candidateRootRva 0 candidateState
          (candidateLaunchCalls candidateState) 0 [] candidateWorld)
  component : forall originalBefore candidateBefore,
    invariant.holds originalBefore candidateBefore ->
      MixedWorldComponentChunkRefinement originalProgram candidateProgram contract
        invariant originalBefore candidateBefore

end StageA.Bindings
"""

_AUDIT = r"""import StageA.GeneratedRelationalInterpreterMixedWorldBridge

namespace StageA.MixedBridgeAudit

#check StageA.Generated.MixedAcceptance.generatedMixedWorldProgramsEquivalent
#print axioms StageA.Generated.MixedAcceptance.generatedMixedWorldProgramsEquivalent
#check StageA.Generated.MixedAcceptance.generatedMixedWorldProgramsEquivalentTrace
#print axioms StageA.Generated.MixedAcceptance.generatedMixedWorldProgramsEquivalentTrace

end StageA.MixedBridgeAudit
"""


if __name__ == "__main__":
    unittest.main()
