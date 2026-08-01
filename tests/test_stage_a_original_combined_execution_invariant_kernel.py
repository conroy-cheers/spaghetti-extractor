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


_KERNEL = r'''import StageA.RelationalOriginalCombinedExecutionInvariant

namespace StageA.OriginalCombinedExecutionInvariantKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.OriginalValueFlowExecutionInvariant
open StageA.Relational.RegisterIndirectControlAuthority

theorem familyProjectsExactReachability
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    (checked : CheckedOriginalCombinedExecutionInvariant program context
      inventory)
    (execution : WorldExecution)
    (holds : checked.toInvariantFamilyEvidence.invariant.holds execution) :
    OriginalExecutionReachable inventory.reachableTargets.targetIds execution :=
  checked.toInvariantFamilyEvidence.reachabilityProjection execution holds

theorem decomposedFamiliesRecoverSingleClosure
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    (families : CheckedOriginalCombinedExecutionStepFamilies program context
      inventory) :
    CheckedOriginalCombinedExecutionInvariant program context inventory :=
  families.toCheckedInvariant

theorem familyRetainsRegisterTargetMembership
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    (checked : CheckedOriginalCombinedExecutionInvariant program context
      inventory)
    (execution : WorldExecution)
    (holds : checked.toInvariantFamilyEvidence.invariant.holds execution)
    (requirement : OriginalRegisterTargetRequirement context)
    (member : requirement ∈ inventory.registerTargets) :
    requirement.Holds execution :=
  checked.registerTargetMember holds requirement member

theorem familyRetainsValueFlowFact
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    (checked : CheckedOriginalCombinedExecutionInvariant program context
      inventory)
    (execution : WorldExecution)
    (holds : checked.toInvariantFamilyEvidence.invariant.holds execution)
    (fact : OriginalFiniteValueFlowFact program.context)
    (member : fact ∈ inventory.valueFlows.facts) :
    fact.Holds execution :=
  inventory.valueFlowHolds holds fact member

theorem registerRequirementRetainsCheckedCertificate
    {context : OriginalDecodedStaticContext}
    (requirement : OriginalRegisterTargetRequirement context) :
    requirement.certificate.certificate.checked context = true :=
  requirement.certificate.checked

theorem registerSourceProjectsRuntimeTargetMembership
    {context : OriginalDecodedStaticContext}
    (requirement : OriginalRegisterTargetRequirement context)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (holds : requirement.Holds
      (.running targetId state calls eventIndex world))
    (atSource :
      targetId = requirement.certificate.certificate.site.sourceTargetId) :
    RuntimeTargetMember context world
      (state.registers.get requirement.certificate.certificate.register)
      requirement.certificate.certificate.inventory :=
  requirement.targetMemberAtRunningSource targetId state calls eventIndex world
    holds atSource

theorem familyRetainsStackDynamicTargetMembership
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    (checked : CheckedOriginalCombinedExecutionInvariant program context
      inventory)
    (execution : WorldExecution)
    (holds : checked.toInvariantFamilyEvidence.invariant.holds execution)
    (requirement : OriginalStackDynamicTargetRequirement context)
    (member : requirement ∈ inventory.stackDynamicTargets) :
    requirement.Holds execution :=
  checked.stackDynamicTargetMember holds requirement member

theorem missingStaticWordComponentRejectsCombined
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program context)
    (execution : WorldExecution)
    (missing : Not (inventory.staticWords.Holds program.context execution)) :
    Not (inventory.Holds execution) := by
  intro holds
  exact missing (inventory.staticWordsHold holds)

theorem missingRegisterComponentRejectsCombined
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program context)
    (execution : WorldExecution)
    (requirement : OriginalRegisterTargetRequirement context)
    (member : requirement ∈ inventory.registerTargets)
    (missing : Not (requirement.Holds execution)) :
    Not (inventory.Holds execution) := by
  intro holds
  exact missing (inventory.registerTargetHolds holds requirement member)

theorem missingValueFlowComponentRejectsCombined
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program context)
    (execution : WorldExecution)
    (fact : OriginalFiniteValueFlowFact program.context)
    (member : fact ∈ inventory.valueFlows.facts)
    (missing : Not (fact.Holds execution)) :
    Not (inventory.Holds execution) := by
  intro holds
  exact missing (inventory.valueFlowHolds holds fact member)

theorem missingStackDynamicComponentRejectsCombined
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program context)
    (execution : WorldExecution)
    (requirement : OriginalStackDynamicTargetRequirement context)
    (member : requirement ∈ inventory.stackDynamicTargets)
    (missing : Not (requirement.Holds execution)) :
    Not (inventory.Holds execution) := by
  intro holds
  exact missing (inventory.stackDynamicTargetHolds holds requirement member)

theorem blockedExecutionCannotEnterCombined
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program context)
    (reason : ExecutionBlock) :
    Not (inventory.Holds (.blocked reason)) :=
  inventory.blockedFalse reason

theorem mismatchedTransitionCannotUseWholeProgramClosure
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    (checked : CheckedOriginalCombinedExecutionInvariant program context
      inventory)
    (before after : WorldExecution)
    (beforeHolds : inventory.Holds before)
    (stepExact : (program.pe32TransitionSystem.step before).next = after)
    (afterNotReachable : Not
      (OriginalExecutionReachable inventory.reachableTargets.targetIds after)) :
    False := by
  have afterHolds := checked.stepClosed before beforeHolds
  rw [stepExact] at afterHolds
  exact afterNotReachable afterHolds.1

#print axioms familyProjectsExactReachability
#print axioms decomposedFamiliesRecoverSingleClosure
#print axioms familyRetainsRegisterTargetMembership
#print axioms familyRetainsValueFlowFact
#print axioms registerRequirementRetainsCheckedCertificate
#print axioms registerSourceProjectsRuntimeTargetMembership
#print axioms familyRetainsStackDynamicTargetMembership
#print axioms missingStaticWordComponentRejectsCombined
#print axioms missingRegisterComponentRejectsCombined
#print axioms missingValueFlowComponentRejectsCombined
#print axioms missingStackDynamicComponentRejectsCombined
#print axioms blockedExecutionCannotEnterCombined
#print axioms mismatchedTransitionCannotUseWholeProgramClosure

end StageA.OriginalCombinedExecutionInvariantKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalCombinedExecutionInvariantKernelTests(unittest.TestCase):
    def test_combined_original_execution_invariant_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalCombinedExecutionInvariant.lean"
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
        ):
            self.assertNotRegex(module_text, forbidden)
        for required in (
            "ExactOriginalReachableTargetInventory",
            "certificate : CheckedCertificate context",
            "OriginalRegisterTargetRequirement.Holds",
            "RuntimeTargetMember",
            "OriginalStackDynamicTargetRequirement.Holds",
            "OriginalResolvedCodeTarget",
            "OriginalCombinedExecutionInventory.Holds",
            "OriginalExecutionReachable",
            "OriginalStaticWordInventory",
            "OriginalRuntimeMemoryPartition.ExecutionHolds",
            "runtimeMemoryClosed",
            "OriginalCallFrameExecutionHolds",
            "OriginalValueFlowInventory",
            "OriginalCombinedExecutionInventory.blockedFalse",
            "CheckedOriginalCombinedExecutionInvariant",
            "CheckedOriginalCombinedExecutionStepFamilies",
            "CheckedOriginalCombinedExecutionStepFamilies.toCheckedInvariant",
            "CheckedOriginalCombinedExecutionInvariant.toOriginalInvariant",
            "CheckedOriginalCombinedExecutionInvariant.toInvariantFamilyEvidence",
        ):
            self.assertIn(required, module_text)
        self.assertNotIn("authority : CheckedAuthority context", module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalCombinedExecutionInvariant",
            )
            (stage_a / "OriginalCombinedExecutionInvariantKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalCombinedExecutionInvariantKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 10, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
