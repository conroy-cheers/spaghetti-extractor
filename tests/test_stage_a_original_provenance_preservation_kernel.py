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


_KERNEL = r'''import StageA.RelationalOriginalProvenancePreservation

namespace StageA.OriginalProvenancePreservationKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalProvenancePreservation
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld.InterpreterKernel

theorem normalizedEffectsYieldValueFlowPost
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    {targetId : Nat} {invocation : OriginalTargetInvocation targetId}
    {successor : OriginalNormalizedSuccessor}
    {effects : CheckedOriginalNormalizedTransitionEffects invocation.state
      successor}
    (witness : CheckedOriginalProvenancePostWitness inventory invocation successor
      effects)
    (before : inventory.Holds invocation.execution) :
    OriginalValueFlowPostInventoryEvidence program inventory.valueFlows successor :=
  witness.valueFlowPost before

theorem normalizedEffectsYieldRegisterTargetPost
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    {targetId : Nat} {invocation : OriginalTargetInvocation targetId}
    {successor : OriginalNormalizedSuccessor}
    {effects : CheckedOriginalNormalizedTransitionEffects invocation.state
      successor}
    (witness : CheckedOriginalProvenancePostWitness inventory invocation successor
      effects)
    (before : inventory.Holds invocation.execution)
    (requirement : OriginalRegisterTargetRequirement context)
    (member : requirement ∈ inventory.registerTargets) :
    OriginalRegisterTargetPostEvidence requirement successor :=
  witness.registerTargetPost before requirement member

theorem normalizedEffectsYieldStackDynamicPost
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    {targetId : Nat} {invocation : OriginalTargetInvocation targetId}
    {successor : OriginalNormalizedSuccessor}
    {effects : CheckedOriginalNormalizedTransitionEffects invocation.state
      successor}
    (witness : CheckedOriginalProvenancePostWitness inventory invocation successor
      effects)
    (before : inventory.Holds invocation.execution)
    (requirement : OriginalStackDynamicTargetRequirement context)
    (member : requirement ∈ inventory.stackDynamicTargets) :
    OriginalStackDynamicTargetPostEvidence requirement successor :=
  witness.stackDynamicTargetPost before requirement member

theorem exactTargetTransitionRetainsProvenanceFamilies
    {program : Program} {targetId : Nat}
    {checked : CheckedOriginalTargetEffect program targetId}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram context}
    {invocation : OriginalTargetInvocation targetId}
    {transition : CheckedOriginalTargetTransition checked context
      inventory.reachableTargets.targetIds invocation}
    (post : CheckedOriginalTargetProvenancePost transition)
    (before : inventory.Holds invocation.execution) :
    OriginalProvenancePostFamilies inventory transition.successor :=
  post.toPostFamilies before

#print axioms normalizedEffectsYieldValueFlowPost
#print axioms normalizedEffectsYieldRegisterTargetPost
#print axioms normalizedEffectsYieldStackDynamicPost
#print axioms exactTargetTransitionRetainsProvenanceFamilies

end StageA.OriginalProvenancePreservationKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalProvenancePreservationKernelTests(unittest.TestCase):
    def test_original_provenance_preservation_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalProvenancePreservation.lean"
        ).read_text(encoding="utf-8")

        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bopaque\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
            r"\bjq\b",
            r"authorizing_lean_terms",
            r"status\s*==",
        ):
            self.assertNotRegex(module_text, forbidden)

        for required in (
            "CheckedOriginalNormalizedTransitionEffects",
            "effectsChecked : effects.checked = true",
            "OriginalValueFlowEndpointTransfer",
            "OriginalRuntimeTargetWorldFrame",
            "OriginalRegisterValueFlowResolver",
            "OriginalStackDynamicValueFlowResolver",
            "CheckedOriginalProvenancePostWitness.valueFlowPost",
            "CheckedOriginalProvenancePostWitness.registerTargetPost",
            "CheckedOriginalProvenancePostWitness.stackDynamicTargetPost",
            "CheckedOriginalTargetProvenancePost",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalProvenancePreservation",
            )
            (stage_a / "OriginalProvenancePreservationKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalProvenancePreservationKernel",
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
