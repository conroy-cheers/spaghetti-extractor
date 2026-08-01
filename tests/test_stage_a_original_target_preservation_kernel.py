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


_KERNEL = r'''import StageA.RelationalOriginalTargetPreservation

namespace StageA.OriginalTargetPreservationKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate

theorem structuredProviderClosesOneIndexedTarget
    {pe : PE32} {program : Program} {binding : ExactBinding pe program}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      context}
    {certificate : ActiveTargetTransitionCertificate binding}
    (provider : CheckedOriginalTargetPreservationProvider context inventory
      certificate) :
    OriginalCombinedTargetFamilyPreservation context inventory certificate :=
  provider.toFamilyPreservation

theorem normalizedSuccessorCannotHideBlocked
    (successor : OriginalNormalizedSuccessor) (reason : ExecutionBlock) :
    successor.execution ≠ .blocked reason :=
  successor.notBlocked reason

theorem protectedWordsRequireFinitePerSlotEvidence
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld afterWorld : RelationalWorld}
    {beforeMemory afterMemory : Memory}
    (update : OriginalProtectedMemoryUpdate context inventory beforeWorld
      afterWorld beforeMemory afterMemory)
    (before : inventory.HoldsIn context beforeWorld beforeMemory) :
    inventory.HoldsIn context afterWorld afterMemory :=
  update.preserves before

theorem indirectControlRetainsCanonicalResolution
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId : Nat} {state : MachineState} {targetWord : Word}
    (resolved : CheckedOriginalIndirectTargetResolution context targetIds
      sourceTargetId state targetWord) :
    resolved.resolved.targetId ∈ targetIds :=
  resolved.resolvedReachable

#print axioms structuredProviderClosesOneIndexedTarget
#print axioms normalizedSuccessorCannotHideBlocked
#print axioms protectedWordsRequireFinitePerSlotEvidence
#print axioms indirectControlRetainsCanonicalResolution

end StageA.OriginalTargetPreservationKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalTargetPreservationKernelTests(unittest.TestCase):
    def test_original_target_preservation_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalTargetPreservation.lean"
        ).read_text(encoding="utf-8")

        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
            r"authorizing_lean_terms",
            r"status\s*==",
            r"callUnmappedReturn\s*\([^)]*\)\s*:",
        ):
            self.assertNotRegex(module_text, forbidden)

        for required in (
            "CheckedOriginalTargetSemanticSource",
            "CheckedOriginalTargetEffect.ofOrdinary",
            "CheckedOriginalTargetEffect.ofX87",
            "SuccessfulTargetEffectComponents",
            "CheckedOriginalTargetEffect.peStep_eq_effect",
            "OriginalNormalizedSuccessor",
            "CheckedOriginalIndirectTargetResolution",
            "OriginalResolvedCodeTarget",
            "OriginalProtectedWordUpdate",
            "OriginalStaticWordWriteFrame",
            "OriginalValueFlowAtEvidence",
            "CheckedOriginalDecodedLocationTransfer",
            "OriginalCallFramePostEvidence",
            "OriginalRegisterTargetPostEvidence",
            "OriginalStackDynamicTargetPostEvidence",
            "activeRuntimeMemoryHolds",
            "runtimeMemory : OriginalRuntimeMemoryPartition.ExecutionHolds",
            "CheckedOriginalTargetPreservationProvider.toFamilyPreservation",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalTargetPreservation",
            )
            (stage_a / "OriginalTargetPreservationKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalTargetPreservationKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 4, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
