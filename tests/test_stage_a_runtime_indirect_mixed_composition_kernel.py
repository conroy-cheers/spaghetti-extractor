from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_runtime_value_carry_kernel import _copy_module_closure


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARuntimeIndirectMixedCompositionKernelTests(unittest.TestCase):
    def test_generic_guarded_cut_and_aggregate_kernels_compile(self) -> None:
        source_root = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary) / "lean"
            stage_a = lean_dir / "StageA"
            stage_a.mkdir(parents=True)
            _copy_module_closure(
                source_root, stage_a, "RelationalRuntimeIndirectComposition"
            )
            (stage_a / "RuntimeIndirectCompositionKernel.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                lean_dir, bundle="RuntimeIndirectCompositionKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)


_KERNEL_FIXTURE = r"""import StageA.RelationalRuntimeIndirectComposition

namespace StageA.Relational.RuntimeIndirectCompositionKernel

open StageA.Relational
open StageA.Relational.GuardedRuntimeCut
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.RuntimeIndirectComposition
open StageA.Relational.RuntimeIndirectEffects
open StageA.Relational.RuntimeValueCarry
open StageA.Relational.RuntimeValueCarrySemantics
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition

def completeInventory : FrontierInventory := {
  frontiers := [
    { stableId := "stack", kind := .stackFinite, sourceTargetId := 10 },
    { stableId := "constructor", kind := .indexedGuarded, sourceTargetId := 20 },
    { stableId := "dynamic", kind := .dynamicGuarded, sourceTargetId := 30 }
  ]
}

def missingInventory : FrontierInventory := {
  frontiers := completeInventory.frontiers.dropLast
}

def duplicateIdInventory : FrontierInventory := {
  frontiers := [
    { stableId := "same", kind := .stackFinite, sourceTargetId := 10 },
    { stableId := "same", kind := .indexedGuarded, sourceTargetId := 20 },
    { stableId := "dynamic", kind := .dynamicGuarded, sourceTargetId := 30 }
  ]
}

example :
    completeInventory.checked "stack" "constructor" "dynamic" 10 20 30 =
      true := by decide +kernel
example :
    missingInventory.checked "stack" "constructor" "dynamic" 10 20 30 =
      false := by decide +kernel
example :
    duplicateIdInventory.checked "stack" "constructor" "dynamic" 10 20 30 =
      false := by decide +kernel

def sufficientStackWindow : StackWindowPair := {
  rangeId := 7
  originalRegister := .esp
  candidateRegister := .esp
  bytesBelow := 16
  bytesAbove := 48
}

example : stackWindowSlotChecked sufficientStackWindow .esp 32 = true := by
  decide +kernel

example : stackWindowSlotChecked sufficientStackWindow .esp 48 = false := by
  decide +kernel

example : stackWindowSlotChecked sufficientStackWindow .ebp 32 = false := by
  decide +kernel

example
    {context : OriginalDecodedStaticContext}
    {original : DecodedWorldProgram}
    {candidate : ExactNativeWorldProgram}
    {contract : MixedRelationContract}
    {reachabilityTargetIds : List Nat}
    (base : MixedExecutionInvariant reachabilityTargetIds contract)
    {stackAuthority : CheckedStackCarryAuthority context}
    {routeAuthority : CheckedRoute context}
    {constructorAuthority : CheckedEmptyIndexedSourceAuthority context}
    {constructorCut : CheckedCertificate context}
    {dynamicSite : CheckedOriginalIndirectControlSite context}
    {dynamicCut : CheckedCertificate context}
    (routeInvariant :
      CheckedRouteChunkInvariant context original candidate contract
        reachabilityTargetIds base routeAuthority)
    (constructorOperational :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base constructorCut)
    (dynamicOperational :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base dynamicCut)
    (inventory : FrontierInventory)
    (inventoryChecked :
      inventory.checked routeAuthority.route.stableId
        constructorCut.certificate.frontierId
        dynamicCut.certificate.frontierId
        stackAuthority.static.claim.site.sourceTargetId
        constructorAuthority.site.sourceTargetId
        dynamicSite.site.sourceTargetId = true)
    (constructorSourceExact :
      constructorCut.certificate.sourceTargetId =
        constructorAuthority.site.sourceTargetId)
    (dynamicSourceExact :
      dynamicCut.certificate.sourceTargetId =
        dynamicSite.site.sourceTargetId)
    (stackSeed :
      CheckedStackCarryRouteSeedValue context routeAuthority.graph
        routeAuthority.route stackAuthority routeAuthority.route.targetFact)
    (stackRangeProjection :
      StrengthenedOriginalSourceFactProjection
        (combinedExtension routeInvariant constructorOperational
          dynamicOperational)
        stackAuthority.static.claim.site.sourceTargetId
        (StackRangeSlotHolds stackSeed)) :
    Aggregate (stackAuthority := stackAuthority)
      (routeAuthority := routeAuthority)
      (constructorAuthority := constructorAuthority)
      (constructorCut := constructorCut)
      (dynamicSite := dynamicSite)
      (dynamicCut := dynamicCut)
      base routeInvariant constructorOperational dynamicOperational := {
  inventory
  inventoryChecked
  constructorSourceExact
  dynamicSourceExact
  stackSeed
  stackRangeProjection
}

#print axioms Aggregate.stackComposition
#print axioms Aggregate.constructorComposition
#print axioms Aggregate.dynamicComposition
#check CheckedMixedKernelSelectedInvariantClosure
#check CheckedMixedKernelSelectedInvariantClosure.strengthenedInvariant
#check CheckedMixedKernelSelectedInvariantClosure.toMixedWorldChunkComposition
#print axioms
  CheckedMixedKernelSelectedInvariantClosure.toMixedWorldChunkComposition
#check CheckedRouteTransferExecution
#check CheckedRouteTransferExecution.preservesOriginal
#check CheckedSelectedRouteTransferExecution
#check CheckedSelectedRouteTransferExecution.ofDecoded
#check CheckedSelectedRouteTransferExecution.ofDirectRegister
#check CheckedSelectedRouteTransferExecution.ofFiniteResult
#check CheckedSelectedRouteTransferExecution.ofDirectFrame
#check CheckedSelectedRouteTransferExecution.ofFiniteFrame
#check CheckedSelectedRouteTransferExecution.targetFactAt
#check finiteOriginCallerFrameStackRangeChecked
#check checkedFiniteOriginCallerFrameStackRangeWitness_of_checked
#check CheckedFiniteOriginCallerFrameStackRangeWitness.holds
#check CheckedRootedScannerSelectedSourceProjection
#check CheckedRootedScannerSelectedSourceProjection.sourceUninhabited
#print axioms CheckedRouteTransferExecution.preservesOriginal
#print axioms CheckedSelectedRouteTransferExecution.targetFactAt
#print axioms CheckedFiniteOriginCallerFrameStackRangeWitness.holds
#print axioms
  CheckedRootedScannerSelectedSourceProjection.sourceUninhabited
#print axioms completeWriteFootprintTrace_from_launch_is_zero

end StageA.Relational.RuntimeIndirectCompositionKernel
"""


if __name__ == "__main__":
    unittest.main()
