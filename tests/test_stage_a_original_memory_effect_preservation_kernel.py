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


_KERNEL = r'''import StageA.RelationalOriginalTargetMemoryPreservationInputs

namespace StageA.OriginalMemoryEffectPreservationKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalMemoryEffectPreservation
open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.OriginalTargetPreservation

theorem concreteFootprintsProduceProtectedUpdates
    {context : StaticProofContext} {beforeWorld afterWorld : RelationalWorld}
    {beforeMemory afterMemory : Memory}
    {requirement : OriginalStaticWordRequirement}
    (evidence : OriginalWordEffectEvidence context beforeWorld afterWorld
      beforeMemory afterMemory requirement) :
    OriginalProtectedWordUpdate context beforeWorld afterWorld beforeMemory
      afterMemory requirement :=
  evidence.toProtectedWordUpdate

theorem stackSpillUsesCheckedSymbolicFootprint
    (context : StaticProofContext) (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory afterMemory : Memory)
    (requirement : OriginalStaticWordRequirement)
    (input : MachineState) (base : NormalizedSymbolicBehavior)
    (address value : Expr) (concreteAddress : Word)
    (beforeMemoryExact : input.memory = beforeMemory)
    (afterMemoryExact : afterMemory =
      ((({ base with writes := [(address, value)] } :
          NormalizedSymbolicBehavior).eval input).nextMachineState input).memory)
    (addressExact : address.eval input = concreteAddress)
    (disjoint : wordOffsetsDisjoint requirement.slot.originalAddress
      concreteAddress = true)
    (originsPreserved : requirement.OriginsPreserved context beforeWorld
      afterWorld) :
    OriginalProtectedWordUpdate context beforeWorld afterWorld beforeMemory
      afterMemory requirement :=
  (OriginalWordEffectEvidence.symbolicSingleton context beforeWorld afterWorld
    beforeMemory afterMemory requirement input base address value concreteAddress
    beforeMemoryExact afterMemoryExact addressExact disjoint
    originsPreserved).toProtectedWordUpdate

theorem x87EffectsRequireCheckedByteFootprints
    {context : StaticProofContext} {beforeWorld afterWorld : RelationalWorld}
    {beforeMemory afterMemory : Memory}
    {requirement : OriginalStaticWordRequirement}
    (writes : List (Word × Word)) (effect : StageA.X87.MachineEffect)
    (afterMemoryExact : afterMemory = applyX87MemoryEffect
      (applyConcreteWrites beforeMemory writes) effect)
    (writesAvoid : WritesAvoidWord requirement.slot.originalAddress writes)
    (x87Avoid : X87MemoryEffectAvoidsWord
      requirement.slot.originalAddress effect)
    (originsPreserved : requirement.OriginsPreserved context beforeWorld
      afterWorld) :
    OriginalProtectedWordUpdate context beforeWorld afterWorld beforeMemory
      afterMemory requirement :=
  (OriginalWordEffectEvidence.x87Writes writes effect afterMemoryExact
    writesAvoid x87Avoid originsPreserved).toProtectedWordUpdate

theorem externalEffectsRequireConformanceAndFootprints
    {context : StaticProofContext} {contract : MachineImportCallContract}
    {event : WorldExternalEvent} {result : WorldExternalResult}
    {requirement : OriginalStaticWordRequirement}
    (conforms : machineCallResultConforms false context contract event result)
    (evidence : OriginalExternalWordEffectEvidence context contract event result
      requirement) :
    OriginalProtectedWordUpdate context event.world result.world
      event.state.memory result.state.memory requirement :=
  evidence.toProtectedWordUpdate conforms

theorem completeInventoryLiftsToReturnedPost
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld world : RelationalWorld} {beforeMemory : Memory}
    {state : MachineState}
    (evidence : OriginalMemoryEffectInventoryEvidence context inventory
      beforeWorld world beforeMemory state.memory) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
      (.returned state world) :=
  evidence.returnedPost

theorem completeInventoryLiftsToRunningPost
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld world : RelationalWorld} {beforeMemory : Memory}
    {targetId : Nat} {state : MachineState} {calls : List Nat}
    {eventIndex : Nat}
    (evidence : OriginalMemoryEffectInventoryEvidence context inventory
      beforeWorld world beforeMemory state.memory) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
      (.running targetId state calls eventIndex world) :=
  evidence.runningPost

theorem completeInventoryLiftsToCallbackPost
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld world : RelationalWorld} {beforeMemory : Memory}
    {targetId : Nat} {state : MachineState} {calls : List Nat}
    {eventIndex : Nat} {callbacks : List WorldExternalCallbackRuntime}
    (evidence : OriginalMemoryEffectInventoryEvidence context inventory
      beforeWorld world beforeMemory state.memory)
    (suspended : SuspendedOriginalStaticWordsHold context inventory callbacks) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
      (.callbackRunning targetId state calls eventIndex world callbacks) :=
  evidence.callbackRunningPost suspended

theorem completeInventoryLiftsToExternalBoundaryPost
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld : RelationalWorld} {beforeMemory : Memory}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    (evidence : OriginalMemoryEffectInventoryEvidence context inventory
      beforeWorld suspension.world beforeMemory suspension.state.memory)
    (suspended : SuspendedOriginalStaticWordsHold context inventory callbacks) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
      (.awaitingExternal suspension callbacks) :=
  evidence.awaitingExternalPost suspended

theorem terminalAndFaultPostsNeedNoMemoryClaim
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (beforeWorld world : RelationalWorld) (beforeMemory : Memory)
    (cause : ModeledFault) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
        (.terminated world) ∧
      OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
        (.fault cause) :=
  ⟨OriginalStaticWordPostEvidence.terminatedOfMemoryEffects context inventory
      beforeWorld world beforeMemory,
    OriginalStaticWordPostEvidence.faultOfMemoryEffects context inventory
      beforeWorld beforeMemory cause⟩

theorem productionTargetInputsYieldStaticWordPostEvidence
    {program : StageA.Relational.SourceWorld.InterpreterKernel.Program}
    {targetId : Nat}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {checked : CheckedOriginalTargetEffect program targetId}
    {invocation : OriginalTargetInvocation targetId}
    (inputs : CheckedOriginalTargetMemoryPreservationCase originalContext
      inventory checked invocation) :
    OriginalStaticWordPostEvidence program.worldProgram.context
      inventory.staticWords invocation.world invocation.state.memory
      inputs.transition.successor :=
  inputs.toPostEvidence

theorem productionExternalInputsPreserveProtectedMemory
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {contract : MachineImportCallContract}
    {event : WorldExternalEvent} {result : WorldExternalResult}
    (inputs : CheckedOriginalExternalMemoryPreservationInputs context inventory
      contract event result)
    (before : inventory.HoldsIn context event.world event.state.memory) :
    inventory.HoldsIn context result.world result.state.memory :=
  inputs.preserves before

#print axioms concreteFootprintsProduceProtectedUpdates
#print axioms stackSpillUsesCheckedSymbolicFootprint
#print axioms x87EffectsRequireCheckedByteFootprints
#print axioms externalEffectsRequireConformanceAndFootprints
#print axioms completeInventoryLiftsToReturnedPost
#print axioms completeInventoryLiftsToRunningPost
#print axioms completeInventoryLiftsToCallbackPost
#print axioms completeInventoryLiftsToExternalBoundaryPost
#print axioms terminalAndFaultPostsNeedNoMemoryClaim
#print axioms productionTargetInputsYieldStaticWordPostEvidence
#print axioms productionExternalInputsPreserveProtectedMemory

end StageA.OriginalMemoryEffectPreservationKernel
'''


_MISSING_PREMISES = r'''import StageA.RelationalOriginalTargetMemoryPreservationInputs

namespace StageA.OriginalMemoryEffectMissingPremises

open StageA.Formal StageA.Relational
open StageA.Relational.OriginalMemoryEffectPreservation
open StageA.Relational.OriginalStaticWordExecutionInvariant

theorem missingOriginPreservationCannotClose
    {context : StaticProofContext} {beforeWorld afterWorld : RelationalWorld}
    {beforeMemory afterMemory : Memory}
    {requirement : OriginalStaticWordRequirement}
    (writes : List (Word × Word))
    (afterMemoryExact : afterMemory = applyConcreteWrites beforeMemory writes)
    (avoids : WritesAvoidWord requirement.slot.originalAddress writes) :
    OriginalWordEffectEvidence context beforeWorld afterWorld beforeMemory
      afterMemory requirement := by
  exact OriginalWordEffectEvidence.concreteWrites writes afterMemoryExact avoids

end StageA.OriginalMemoryEffectMissingPremises
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalMemoryEffectPreservationKernelTests(unittest.TestCase):
    def test_generic_memory_effect_preservation_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        modules = (
            "RelationalOriginalMemoryEffectPreservation",
            "RelationalOriginalMemoryPostPreservation",
            "RelationalOriginalTargetMemoryPreservationInputs",
        )
        combined = "\n".join(
            (source_root / f"{module}.lean").read_text(encoding="utf-8")
            for module in modules
        )
        for forbidden in (
            r"^\s*axiom\b",
            r"^\s*opaque\b",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"authorizing_lean_terms",
            r"status\s*==",
        ):
            self.assertNotRegex(combined, forbidden)
        for required in (
            "OriginalWordEffectEvidence",
            "normalizedWritesAvoidWordChecked",
            "symbolicWrites",
            "symbolicSingleton",
            "checkedOrdinary",
            "checkedX87",
            "x87Writes",
            "OriginalExternalWordEffectEvidence",
            "OriginalMemoryEffectInventoryEvidence",
            "toProtectedMemoryUpdate",
            "awaitingExternalPost",
            "returnedPost",
            "terminatedOfMemoryEffects",
            "faultOfMemoryEffects",
            "CheckedOriginalTargetMemoryPreservationProvider",
            "CheckedOriginalExternalMemoryPreservationInputs",
            "OriginalTargetMemorySuccessorInputs",
        ):
            self.assertIn(required, combined)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalTargetMemoryPreservationInputs",
            )
            (stage_a / "OriginalMemoryEffectPreservationKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalMemoryEffectPreservationKernel",
            )
            (
                stage_a / "OriginalMemoryEffectMissingPremises.lean"
            ).write_text(_MISSING_PREMISES, encoding="utf-8")
            rejected = _run_lean_relational(
                root,
                bundle="OriginalMemoryEffectMissingPremises",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 11, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)
        self.assertEqual(rejected["status"], "failed", rejected)
        rejection_output = rejected["stdout"] + rejected["stderr"]
        self.assertIn("OriginsPreserved", rejection_output)


if __name__ == "__main__":
    unittest.main()
