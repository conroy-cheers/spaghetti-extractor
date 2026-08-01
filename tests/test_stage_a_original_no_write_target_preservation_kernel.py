from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


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


_KERNEL = r'''import StageA.RelationalOriginalNoWriteTargetPreservation

namespace StageA.OriginalNoWriteTargetPreservationKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalNoWriteTargetPreservation
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate

def noWriteEvidenceProducesExistingProvider
    {pe : PE32} {program : Program} {binding : ExactBinding pe program}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      context}
    {certificate : ActiveTargetTransitionCertificate binding}
    (evidence : CheckedOriginalNoWriteTargetEvidence context inventory
      certificate) :
    CheckedOriginalTargetPreservationProvider context inventory certificate :=
  evidence.toProvider

theorem noWriteProviderClosesExistingTargetFamily
    {pe : PE32} {program : Program} {binding : ExactBinding pe program}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      context}
    {certificate : ActiveTargetTransitionCertificate binding}
    (evidence : CheckedOriginalNoWriteTargetEvidence context inventory
      certificate) :
    OriginalCombinedTargetFamilyPreservation context inventory certificate :=
  evidence.toProvider.toFamilyPreservation

theorem emptyExactEffectsPreserveConcreteMemory
    {program : Program} {targetId : Nat}
    {checked : CheckedOriginalTargetEffect program targetId}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram context}
    {invocation : OriginalTargetInvocation targetId}
    {transition : CheckedOriginalTargetTransition checked context
      inventory.reachableTargets.targetIds invocation}
    (post : CheckedOriginalNoWritePost transition) :
    match transition.successor with
    | .running _ state _ _ _ => state.memory = invocation.state.memory
    | .callbackRunning _ state _ _ _ _ => state.memory = invocation.state.memory
    | .awaitingExternal suspension _ =>
        suspension.state.memory = invocation.state.memory
    | .returned state _ => state.memory = invocation.state.memory
    | .terminated _ | .fault _ => True :=
  post.memoryUnchanged

def dormantFrameSameWorldMemoryExact :=
  @DormantOriginalCallFrame.Holds.sameWorldOfMemoryEq

def checkedEffectsResume :=
  @CheckedOriginalNormalizedTransitionEffects.ofResume

def checkedEmptyProposalMeansNoWrites :=
  @normalizedWriteProposalsChecked_empty

def noWriteJumpControl :=
  @CheckedOriginalTargetControlEvidence.ofNoWriteJump

def noWriteBranchControl :=
  @CheckedOriginalTargetControlEvidence.ofNoWriteBranch

def inertLocalResumeProvenance :=
  @CheckedOriginalProvenancePostWitness.ofInertLocalResume

end StageA.OriginalNoWriteTargetPreservationKernel
'''

_AUDIT = r'''import StageA.OriginalNoWriteTargetPreservationKernel

#print axioms StageA.OriginalNoWriteTargetPreservationKernel.noWriteEvidenceProducesExistingProvider
#print axioms StageA.OriginalNoWriteTargetPreservationKernel.noWriteProviderClosesExistingTargetFamily
#print axioms StageA.OriginalNoWriteTargetPreservationKernel.emptyExactEffectsPreserveConcreteMemory
#print axioms StageA.OriginalNoWriteTargetPreservationKernel.dormantFrameSameWorldMemoryExact
#print axioms StageA.OriginalNoWriteTargetPreservationKernel.checkedEffectsResume
#print axioms StageA.OriginalNoWriteTargetPreservationKernel.checkedEmptyProposalMeansNoWrites
#print axioms StageA.OriginalNoWriteTargetPreservationKernel.noWriteJumpControl
#print axioms StageA.OriginalNoWriteTargetPreservationKernel.noWriteBranchControl
#print axioms StageA.OriginalNoWriteTargetPreservationKernel.inertLocalResumeProvenance
#print axioms StageA.Relational.OriginalNoWriteTargetPreservation.CheckedOriginalNoWritePost.toPreservationCase
#print axioms StageA.Relational.OriginalNoWriteTargetPreservation.CheckedOriginalNoWriteTargetEvidence.toProvider
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalNoWriteTargetPreservationKernelTests(unittest.TestCase):
    def test_generic_no_write_composition_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalNoWriteTargetPreservation.lean"
        ).read_text(encoding="utf-8")

        for forbidden in (
            r"^\s*axiom\b",
            r"^\s*opaque\b",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
            r"authorizing_lean_terms",
            r"status\s*==",
        ):
            self.assertNotRegex(module_text, forbidden)

        for required in (
            "OriginalNoWriteWorldFrame",
            "DormantOriginalCallFrame.Holds.sameWorldOfMemoryEq",
            "CheckedOriginalNormalizedTransitionEffects.ofResume",
            "normalizedWriteProposalsChecked_empty",
            "CheckedOriginalTargetControlEvidence.ofNoWriteJump",
            "CheckedOriginalTargetControlEvidence.ofNoWriteBranch",
            "CheckedOriginalProvenancePostWitness.ofInertLocalResume",
            "CheckedOriginalNoWritePost",
            "originalWritesEmpty",
            "CheckedOriginalNoWritePost.memoryUnchanged",
            "activeStaticWordsAndSuspendedHold",
            "unchangedProtectedMemory",
            "CheckedOriginalNoWritePost.staticWords",
            "CheckedOriginalNoWritePost.runtimeMemory",
            "CheckedOriginalNoWritePost.toPreservationCase",
            "CheckedOriginalNoWriteTargetEvidence",
            "CheckedOriginalNoWriteTargetEvidence.toProvider",
            "CheckedOriginalTargetPreservationProvider",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalNoWriteTargetPreservation",
            )
            (stage_a / "OriginalNoWriteTargetPreservationKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            (stage_a / "OriginalNoWriteTargetPreservationAudit.lean").write_text(
                _AUDIT,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalNoWriteTargetPreservationAudit",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 11, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
