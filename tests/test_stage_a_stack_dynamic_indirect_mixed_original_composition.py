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


_KERNEL = r"""import StageA.RelationalStackDynamicIndirectMixedOriginalComposition

namespace StageA.StackDynamicIndirectMixedOriginalCompositionKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.NullableCodePointerTable
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition

theorem runningSourceUsesActualInvariant
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (sourceTargetId : Nat) (world : RelationalWorld) (state : MachineState)
    (calls : List Nat) (eventIndex : Nat) (candidate : NativeWorldExecution)
    (related : invariant.holds
      (.running sourceTargetId state calls eventIndex world) candidate) :
    sourceTargetId ∈ reachabilityTargetIds := by
  apply actualMixedOriginalStackDynamicSource_targetReachable invariant
  exact Or.inl ⟨calls, eventIndex, candidate, related⟩

theorem callbackSourceUsesActualInvariant
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (sourceTargetId : Nat) (world : RelationalWorld) (state : MachineState)
    (calls : List Nat) (eventIndex : Nat)
    (callbacks : List WorldExternalCallbackRuntime)
    (candidate : NativeWorldExecution)
    (related : invariant.holds
      (.callbackRunning sourceTargetId state calls eventIndex world callbacks)
      candidate) :
    sourceTargetId ∈ reachabilityTargetIds := by
  apply actualMixedOriginalStackDynamicSource_targetReachable invariant
  exact Or.inr ⟨calls, eventIndex, callbacks, candidate, related⟩

theorem finiteStackCompositionRetainsRuntimeEvidence
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    (authority : CheckedStackCarryAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (complete : CompleteStackCarryPremise context authority
      (ActualMixedOriginalStackDynamicSource invariant
        authority.static.claim.site.sourceTargetId))
    (world : RelationalWorld) (state : MachineState)
    (reached : ActualMixedOriginalStackDynamicSource invariant
      authority.static.claim.site.sourceTargetId world state) :
    exists target : MixedOriginalStackCarryTarget context authority world state,
      target.runtime.stackRange ∈ world.stackRanges := by
  rcases
    (StackCarryMixedOriginalComposition.finite complete).targetClosed reached
      with ⟨target⟩
  exact ⟨target, target.runtime.stackRangeMember⟩

theorem emptyIndexedIntervalRequiresUnreachable
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    (authority : CheckedEmptyIndexedSourceAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (complete : CompleteEmptyIndexedSourcePredecessorPremise authority
      (ActualMixedOriginalStackDynamicSource invariant
        authority.site.sourceTargetId)) :
    ActualMixedOriginalStackDynamicSourceUninhabited invariant
      authority.site.sourceTargetId :=
  (IndexedTableMixedOriginalComposition.emptyInterval
    complete).sourceUninhabited

theorem finiteDynamicCompositionRetainsWorldEvidence
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    (authority : CheckedDynamicCallbackAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (inventoryPopulated : DynamicCallbackInventoryPopulated authority)
    (complete : CompleteDynamicCallbackPremise context authority
      (ActualMixedOriginalStackDynamicSource invariant
        authority.static.claim.site.sourceTargetId))
    (world : RelationalWorld) (state : MachineState)
    (reached : ActualMixedOriginalStackDynamicSource invariant
      authority.static.claim.site.sourceTargetId world state) :
    exists target :
        MixedOriginalDynamicCallbackTarget context authority world state,
      target.runtime.dynamicRange ∈ world.dynamicRanges /\
        target.runtime.callback ∈ world.registeredCallbacks := by
  rcases
    (DynamicCallbackMixedOriginalComposition.finite
      inventoryPopulated complete).targetClosed reached with ⟨target⟩
  exact ⟨target, target.runtime.dynamicRangeMember,
    target.runtime.callbackMember⟩

theorem emptyDynamicInventoryRequiresUnreachable
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    (authority : CheckedDynamicCallbackAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (composition :
      DynamicCallbackMixedOriginalComposition authority invariant)
    (empty : authority.static.claim.allowedTargetIds = []) :
    ActualMixedOriginalStackDynamicSourceUninhabited invariant
      authority.static.claim.site.sourceTargetId :=
  sourceUninhabited_of_emptyDynamicCallbackInventory composition empty

theorem dynamicSourcePremiseUsesActualInvariant
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    (checkedSite : CheckedOriginalIndirectControlSite context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (complete : CompleteDynamicSourceUninhabitedPremise
      (ActualMixedOriginalStackDynamicSource invariant
        checkedSite.site.sourceTargetId)) :
    ActualMixedOriginalStackDynamicSourceUninhabited invariant
      checkedSite.site.sourceTargetId :=
  (DynamicSourceMixedOriginalComposition.mk complete).sourceUninhabited

#print axioms runningSourceUsesActualInvariant
#print axioms callbackSourceUsesActualInvariant
#print axioms finiteStackCompositionRetainsRuntimeEvidence
#print axioms emptyIndexedIntervalRequiresUnreachable
#print axioms finiteDynamicCompositionRetainsWorldEvidence
#print axioms emptyDynamicInventoryRequiresUnreachable
#print axioms dynamicSourcePremiseUsesActualInvariant

end StageA.StackDynamicIndirectMixedOriginalCompositionKernel
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAStackDynamicIndirectMixedOriginalCompositionTests(
    unittest.TestCase
):
    def test_generic_bridge_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        layer = (
            source_root
            / "RelationalStackDynamicIndirectMixedOriginalComposition.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)

        for required in (
            "ActualMixedOriginalStackDynamicSource",
            "CompleteStackCarryPremise",
            "CompleteEmptyIndexedSourcePredecessorPremise",
            "CompleteDynamicCallbackPremise",
            "CompleteDynamicSourceUninhabitedPremise",
            "StackRelocatedCodePointerRuntime",
            "DynamicCallbackControlRuntime",
            "OriginalSourceFactExecutionInvariant",
            "OriginalSourceFactMixedExecutionInvariant",
            "OriginalSourceFactProjection",
            "OriginalSourceFactMixedProjection",
            "originalSourceFact_of_originalProjection",
            "originalSourceFact_of_mixedProjection",
            "originalSourceFact_of_originalInvariant",
            "originalSourceFact_of_mixedInvariant",
            "completeStackCarryPremise_of_originalInvariant",
            "completeEmptyIndexedSourcePremise_of_originalInvariant",
            "completeDynamicCallbackPremise_of_originalInvariant",
            "sourceUninhabited",
        ):
            self.assertIn(required, layer)
        for forbidden in (
            "proposal_report",
            "report_status",
            "runtime_complete",
        ):
            self.assertNotIn(forbidden, layer.lower())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalStackDynamicIndirectMixedOriginalComposition",
            )
            kernel = (
                stage_a
                / "StackDynamicIndirectMixedOriginalCompositionKernel.lean"
            )
            kernel.write_text(_KERNEL, encoding="utf-8")
            result = _run_lean_relational(
                root,
                bundle="StackDynamicIndirectMixedOriginalCompositionKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertIn("emptyIndexedIntervalRequiresUnreachable", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 7, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
