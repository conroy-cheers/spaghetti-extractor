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


_KERNEL = r'''import StageA.RelationalOriginalValueFlowExecutionInvariant

namespace StageA.OriginalValueFlowExecutionInvariantKernel

open StageA.Formal StageA.Relational
open StageA.Relational.ControlValueProvenance
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.OriginalValueFlowExecutionInvariant
open StageA.Relational.RegisterIndirectControlAuthority

def generatedOriginalValueFlowFact0000
    (context : StaticProofContext)
    (originChecked :
      (StageA.Relational.ValueOriginAtom.staticCodeTarget 17 0).checked
        context = true) :
    OriginalFiniteValueFlowFact context := {
  id := 0
  targetIds := [291, 292]
  targetIdsNonempty := by decide +kernel
  targetIdsUnique := by decide +kernel
  location := .register .ebx
  locationChecked := by decide +kernel
  finiteAlternativeBudget := 1
  finiteAlternativeBudgetPositive := by decide +kernel
  alternatives := [.staticCodeTarget 17 0]
  alternativesNonempty := by decide +kernel
  alternativesUnique := by decide +kernel
  alternativesWithinBudget := by decide +kernel
  alternativesChecked := by
    intro origin member
    simp only [List.mem_singleton] at member
    subst origin
    exact originChecked
}

def generatedOriginalValueFlowFact0001
    (context : StaticProofContext)
    (originChecked :
      (StageA.Relational.ValueOriginAtom.staticCodeTarget 17 0).checked
        context = true) :
    OriginalFiniteValueFlowFact context := {
  id := 1
  targetIds := [293]
  targetIdsNonempty := by decide +kernel
  targetIdsUnique := by decide +kernel
  location := .frameWord .esp (.add 32)
  locationChecked := by decide +kernel
  finiteAlternativeBudget := 1
  finiteAlternativeBudgetPositive := by decide +kernel
  alternatives := [.staticCodeTarget 17 0]
  alternativesNonempty := by decide +kernel
  alternativesUnique := by decide +kernel
  alternativesWithinBudget := by decide +kernel
  alternativesChecked := by
    intro origin member
    simp only [List.mem_singleton] at member
    subst origin
    exact originChecked
}

def generatedOriginalValueFlowInventory
    (context : StaticProofContext)
    (originChecked :
      (StageA.Relational.ValueOriginAtom.staticCodeTarget 17 0).checked
        context = true) :
    OriginalValueFlowInventory context := {
  facts := [
    generatedOriginalValueFlowFact0000 context originChecked,
    generatedOriginalValueFlowFact0001 context originChecked
  ]
  factIdsUnique := by
    simp [generatedOriginalValueFlowFact0000,
      generatedOriginalValueFlowFact0001]
}

theorem generatedOriginalValueFlowFactsExact
    (context : StaticProofContext)
    (originChecked :
      (StageA.Relational.ValueOriginAtom.staticCodeTarget 17 0).checked
        context = true) :
    (generatedOriginalValueFlowInventory context originChecked).facts = [
      generatedOriginalValueFlowFact0000 context originChecked,
      generatedOriginalValueFlowFact0001 context originChecked
    ] := by
  rfl

theorem finiteFactProjectsAtRunning
    {context : StaticProofContext}
    (fact : OriginalFiniteValueFlowFact context)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (holds : fact.Holds (.running targetId state calls eventIndex world))
    (member : targetId ∈ fact.targetIds) :
    fact.HoldsAt state world :=
  fact.holdsAtRunning targetId state calls eventIndex world holds member

theorem decodedCopyRetainsConcreteOrigin
    {program : DecodedWorldProgram}
    (copy : CheckedOriginalDecodedCopyTransfer program)
    (state : MachineState) (world : RelationalWorld)
    (origin : ValueOriginAtom)
    (source : OriginalValueOriginAtomHolds program.context world
      (state.registers.get copy.sourceRegister) origin) :
    OriginalValueOriginAtomHolds program.context world
      (originalLocationValue (.register copy.targetRegister)
        ((copy.transfer.behavior.eval state).nextMachineState state)) origin :=
  copy.preservesOrigin state world origin source

theorem decodedLoadRetainsConcreteOrigin
    {program : DecodedWorldProgram}
    (load : CheckedOriginalDecodedLoadTransfer program)
    (state : MachineState) (world : RelationalWorld)
    (origin : ValueOriginAtom)
    (source : OriginalValueOriginAtomHolds program.context world
      (originalLocationValue load.sourceLocation state) origin) :
    OriginalValueOriginAtomHolds program.context world
      (originalLocationValue (.register load.targetRegister)
        ((load.transfer.behavior.eval state).nextMachineState state)) origin :=
  load.preservesOrigin state world origin source

theorem exactZeroExcludesNonzeroEdge
    {context : StaticProofContext}
    (fact : OriginalFiniteValueFlowFact context)
    (state : MachineState) (world : RelationalWorld)
    (singleton : fact.alternatives = [.exactBits 0])
    (holds : fact.HoldsAt state world)
    (nonzero : originalLocationValue fact.location state ≠
      BitVec.ofNat 32 0) : False :=
  fact.nonzeroBranchExcluded state world singleton holds nonzero

theorem staticOriginClosesStaticInventory
    {context : StaticProofContext}
    {originalContext : OriginalDecodedStaticContext} {targetId : Nat}
    (binding : OriginalStaticCodeOriginBinding context originalContext targetId)
    (world : RelationalWorld) (value : Word) (slotRva : Nat)
    (holds : OriginalValueOriginAtomHolds context world value
      (.staticCodeTarget targetId 0)) :
    RuntimeTargetMember originalContext world value
      (.relocatedWritableCode slotRva targetId) :=
  runtimeTargetMember_staticCode binding world value slotRva holds

theorem importOriginClosesImportInventory
    {context : StaticProofContext}
    (originalContext : OriginalDecodedStaticContext)
    (world : RelationalWorld) (value : Word)
    (iatRva : Nat) (identity : ExternalTarget)
    (iatExact : forall binding,
      binding ∈ world.importAddresses -> binding.imported = identity ->
        binding.originalIatRva = iatRva)
    (holds : OriginalValueOriginAtomHolds context world value
      (.importTarget identity)) :
    RuntimeTargetMember originalContext world value
      (.importedAddress iatRva identity) :=
  runtimeTargetMember_import originalContext world value iatRva identity
    iatExact holds

theorem resolverOriginClosesResolverInventory
    {context : StaticProofContext}
    (originalContext : OriginalDecodedStaticContext)
    (world : RelationalWorld) (value : Word)
    (queries : List ResolverQuery) (staticTargetIds : List Nat)
    (query : ResolverQuery) (queryMember : query ∈ queries)
    (resourceId : Nat) (queryResourceExact : query.resourceId = resourceId)
    (holds : OriginalValueOriginAtomHolds context world value
      (.opaqueResource resourceId)) :
    RuntimeTargetMember originalContext world value
      (.resolverResults queries staticTargetIds) :=
  runtimeTargetMember_resolverResource originalContext world value queries
    staticTargetIds query queryMember resourceId queryResourceExact holds

theorem callbackOriginClosesCallbackInventory
    {context : StaticProofContext}
    (originalContext : OriginalDecodedStaticContext)
    (world : RelationalWorld) (value : Word)
    (slotRva targetId : Nat) (targetIds : List Nat)
    (allowed : targetId ∈ targetIds)
    (target : OriginalCodeTarget)
    (targetFound : originalContext.codeMap.get? targetId = some target)
    (holds : OriginalValueOriginAtomHolds context world value
      (.registeredCallback targetId)) :
    RuntimeTargetMember originalContext world value
      (.registeredCallbackSlot slotRva targetIds) :=
  runtimeTargetMember_registeredCallback originalContext world value slotRva
    targetId targetIds allowed target targetFound holds

theorem nullableOriginClosesNullableInventory
    {context : StaticProofContext}
    {originalContext : OriginalDecodedStaticContext} {targetId : Nat}
    (binding : OriginalStaticCodeOriginBinding context originalContext targetId)
    (world : RelationalWorld) (value : Word)
    (startRva endRva : Nat) (entries : List (Option Nat)) (index : Nat)
    (indexBound : index < entries.length)
    (entry : entries[index]? = some (some targetId))
    (holds : OriginalValueOriginAtomHolds context world value
      (.staticCodeTarget targetId 0)) :
    RuntimeTargetMember originalContext world value
      (.nullableCodeTable startRva endRva entries) :=
  runtimeTargetMember_nullableTable binding world value startRva endRva entries
    index indexBound entry holds

theorem exactStepClosureIsTheOnlyInvariantAdapter
    {program : DecodedWorldProgram}
    {inventory : OriginalValueFlowInventory program.context}
    (checked : CheckedOriginalValueFlowExecutionInvariant program inventory)
    (before : WorldExecution) (holds : inventory.Holds before) :
    checked.toOriginalInvariant.holds
      (program.pe32TransitionSystem.step before).next :=
  checked.stepClosed before holds

#print axioms finiteFactProjectsAtRunning
#print axioms decodedCopyRetainsConcreteOrigin
#print axioms decodedLoadRetainsConcreteOrigin
#print axioms exactZeroExcludesNonzeroEdge
#print axioms staticOriginClosesStaticInventory
#print axioms importOriginClosesImportInventory
#print axioms resolverOriginClosesResolverInventory
#print axioms callbackOriginClosesCallbackInventory
#print axioms nullableOriginClosesNullableInventory
#print axioms exactStepClosureIsTheOnlyInvariantAdapter

end StageA.OriginalValueFlowExecutionInvariantKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalValueFlowExecutionInvariantKernelTests(unittest.TestCase):
    def test_original_value_flow_invariant_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalValueFlowExecutionInvariant.lean"
        ).read_text(encoding="utf-8")

        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
            r"RuntimeClosure",
            r"authorizing_lean_terms",
            r"status\s*==",
        ):
            self.assertNotRegex(module_text, forbidden)

        for required in (
            "ControlValueProvenance.Location",
            "OriginalValueOriginAtomHolds",
            "OriginalFiniteValueFlowFact.Holds",
            "CheckedOriginalDecodedCopyTransfer",
            "CheckedOriginalDecodedLoadTransfer",
            "OriginalValueFlowWorldFrame",
            "CheckedOriginalValueCallPreservation",
            "nonzeroBranchExcluded",
            "runtimeTargetMember_staticCode",
            "runtimeTargetMember_import",
            "runtimeTargetMember_resolverResource",
            "runtimeTargetMember_registeredCallback",
            "runtimeTargetMember_nullableTable",
            "CheckedOriginalValueFlowExecutionInvariant",
            "stepClosed",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalValueFlowExecutionInvariant",
            )
            (stage_a / "OriginalValueFlowExecutionInvariantKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalValueFlowExecutionInvariantKernel",
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
