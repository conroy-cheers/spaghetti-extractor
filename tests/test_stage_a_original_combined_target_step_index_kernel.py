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


_KERNEL = r'''import StageA.RelationalOriginalCombinedTargetStepIndex

namespace StageA.OriginalCombinedTargetStepIndexKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate

theorem indexedFamiliesCloseTheExactInvariant
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      context}
    (index : OriginalCombinedTargetStepIndex binding context inventory)
    (external : OriginalCombinedAwaitingExternalPreservation context inventory) :
    CheckedOriginalCombinedExecutionInvariant sourceProgram.worldProgram context
      inventory :=
  originalCombinedInvariant_of_indexedTargets index external

theorem reachableTargetCannotBeOmitted
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      context}
    (index : OriginalCombinedTargetStepIndex binding context inventory)
    {targetId : Nat}
    (reachable : targetId ∈ inventory.reachableTargets.targetIds)
    (omitted : index.transitions.find? targetId = none) : False :=
  index.omittedTargetFalse reachable omitted

theorem duplicateTargetCertificatesRejected
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      context}
    (index : OriginalCombinedTargetStepIndex binding context inventory)
    (first second : ActiveTargetTransitionCertificate binding)
    (tail : List (ActiveTargetTransitionCertificate binding))
    (certificatesExact :
      index.transitions.certificates = first :: second :: tail)
    (sameTarget : first.targetId = second.targetId) : False := by
  have unique := index.targetIdsUnique
  rw [certificatesExact] at unique
  simp only [List.map_cons] at unique
  rw [sameTarget] at unique
  simp at unique

theorem checkedLookupRetainsExactCertificateMembership
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      context}
    (index : OriginalCombinedTargetStepIndex binding context inventory)
    {targetId : Nat}
    {certificate : ActiveTargetTransitionCertificate binding}
    (found : index.transitions.find? targetId = some certificate) :
    certificate ∈ index.transitions.certificates :=
  index.find?_member found

#print axioms indexedFamiliesCloseTheExactInvariant
#print axioms reachableTargetCannotBeOmitted
#print axioms duplicateTargetCertificatesRejected
#print axioms checkedLookupRetainsExactCertificateMembership

end StageA.OriginalCombinedTargetStepIndexKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalCombinedTargetStepIndexKernelTests(unittest.TestCase):
    def test_combined_target_step_index_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalCombinedTargetStepIndex.lean"
        ).read_text(encoding="utf-8")

        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
            r"ActiveTargetDomainCoverage",
            r"RuntimeClosure",
            r"authorizing_lean_terms",
            r"status\s*==",
        ):
            self.assertNotRegex(module_text, forbidden)

        for required in (
            "OriginalCombinedPostFamilies",
            "ActiveTargetTransitionIndex binding",
            "targetIdsExact",
            "targetIdsUnique",
            "OriginalCombinedTargetFamilyPreservation",
            "OriginalCombinedAwaitingExternalPreservation",
            "OriginalCombinedTargetStepIndex.omittedTargetFalse",
            "originalCombinedPostFamilies_of_indexedTargets",
            "originalCombinedStepFamilies_of_indexedTargets",
            "originalCombinedInvariant_of_indexedTargets",
            "inventory.blockedFalse",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalCombinedTargetStepIndex",
            )
            (stage_a / "OriginalCombinedTargetStepIndexKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalCombinedTargetStepIndexKernel",
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
