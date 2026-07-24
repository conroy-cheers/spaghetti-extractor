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


_KERNEL = r"""import StageA.RelationalRegisterIndirectMixedOriginalComposition

namespace StageA.RegisterIndirectMixedOriginalCompositionKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.MixedExecutionInvariantExtension
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.RegisterIndirectMixedOriginalComposition

theorem runningSourceUsesActualInvariant
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (sourceTargetId : Nat) (world : RelationalWorld) (state : MachineState)
    (calls : List Nat) (eventIndex : Nat) (candidate : NativeWorldExecution)
    (related : invariant.holds
      (.running sourceTargetId state calls eventIndex world) candidate) :
    sourceTargetId ∈ reachabilityTargetIds := by
  apply actualMixedOriginalRegisterSource_targetReachable invariant
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
  apply actualMixedOriginalRegisterSource_targetReachable invariant
  exact Or.inr ⟨calls, eventIndex, callbacks, candidate, related⟩

theorem originalInvariantClosesConcretePath
    {program : DecodedWorldProgram}
    (invariant : OriginalWorldExecutionInvariant program)
    {before after : WorldExecution}
    {observations : List WorldRelationalObservable}
    (beforeHolds : invariant.holds before)
    (path : NonemptyRelatedPath program.pe32TransitionSystem
      before observations after) :
    invariant.holds after :=
  invariant.pathClosed beforeHolds path

theorem combinedInvariantProjectsMember
    {program : DecodedWorldProgram}
    (invariants : List (OriginalWorldExecutionInvariant program))
    (invariant : OriginalWorldExecutionInvariant program)
    (execution : WorldExecution)
    (member : invariant ∈ invariants)
    (holds :
      (OriginalWorldExecutionInvariant.all invariants).holds execution) :
    invariant.holds execution :=
  OriginalWorldExecutionInvariant.all_member holds invariant member

theorem executionInvariantBuildsRuntimePremise
    {context : OriginalDecodedStaticContext}
    {program : DecodedWorldProgram}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    (authority : CheckedAuthority context)
    (mixed : MixedExecutionInvariant reachabilityTargetIds contract)
    (executionInvariant :
      RegisterAuthorityExecutionInvariant program authority) :
    MixedRuntimeClosurePremise authority
      (strengthenMixedExecutionInvariant mixed
        executionInvariant.toOriginalInvariant) :=
  mixedRuntimeClosurePremise_of_originalInvariant executionInvariant

theorem finiteCompositionClosesActualSource
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    (authority : CheckedAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (inventoryPopulated :
      RuntimeInventoryPopulated authority.certificate.certificate.inventory)
    (runtime : MixedTargetMembershipPremise authority invariant)
    (world : RelationalWorld) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (candidate : NativeWorldExecution)
    (related : invariant.holds
      (.running authority.certificate.certificate.site.sourceTargetId
        state calls eventIndex world) candidate) :
    MixedOriginalRegisterTarget context world
      (state.registers.get authority.certificate.certificate.register) := by
  have reached : ActualMixedOriginalRegisterSource invariant
      authority.certificate.certificate.site.sourceTargetId world state :=
    Or.inl ⟨calls, eventIndex, candidate, related⟩
  rcases
    (RegisterIndirectMixedOriginalComposition.finite inventoryPopulated runtime)
      |>.targetClosed reached with
    ⟨_targetMember, classified⟩
  exact classified

theorem mixedExecutionInvariantBuildsTargetPremise
    {context : OriginalDecodedStaticContext}
    {original : DecodedWorldProgram}
    {candidate : ExactNativeWorldProgram}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    (authority : CheckedAuthority context)
    (mixed : MixedExecutionInvariant reachabilityTargetIds contract)
    (executionInvariant :
      RegisterAuthorityTargetMixedExecutionInvariant original candidate authority
        reachabilityTargetIds contract mixed) :
    MixedTargetMembershipPremise authority
      executionInvariant.toExtension.strengthen :=
  mixedTargetMembershipPremise_of_mixedInvariant executionInvariant

theorem runtimePremiseStillTransports
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    (authority : CheckedAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (runtime : MixedRuntimeClosurePremise authority invariant) :
    MixedTargetMembershipPremise authority invariant :=
  runtime.toTargetMembership

example {context : OriginalDecodedStaticContext} {world : RelationalWorld}
    {value : Word} {slotRva targetId : Nat}
    (member : RuntimeTargetMember context world value
      (.relocatedWritableCode slotRva targetId)) :
    MixedOriginalRegisterTarget context world value :=
  runtimeTargetMember_toMixedOriginalRegisterTarget member

example {context : OriginalDecodedStaticContext} {world : RelationalWorld}
    {value : Word} {iatRva : Nat} {imported : ExternalTarget}
    (member : RuntimeTargetMember context world value
      (.importedAddress iatRva imported)) :
    MixedOriginalRegisterTarget context world value :=
  runtimeTargetMember_toMixedOriginalRegisterTarget member

example {context : OriginalDecodedStaticContext} {world : RelationalWorld}
    {value : Word} {queries : List ResolverQuery} {targetIds : List Nat}
    (member : RuntimeTargetMember context world value
      (.resolverResults queries targetIds)) :
    MixedOriginalRegisterTarget context world value :=
  runtimeTargetMember_toMixedOriginalRegisterTarget member

example {context : OriginalDecodedStaticContext} {world : RelationalWorld}
    {value : Word} {slotRva : Nat} {targetIds : List Nat}
    (member : RuntimeTargetMember context world value
      (.registeredCallbackSlot slotRva targetIds)) :
    MixedOriginalRegisterTarget context world value :=
  runtimeTargetMember_toMixedOriginalRegisterTarget member

example {context : OriginalDecodedStaticContext} {world : RelationalWorld}
    {value : Word} {startRva endRva : Nat}
    {entries : List (Option Nat)}
    (member : RuntimeTargetMember context world value
      (.nullableCodeTable startRva endRva entries)) :
    MixedOriginalRegisterTarget context world value :=
  runtimeTargetMember_toMixedOriginalRegisterTarget member

example :
    RuntimeInventoryPopulated (.relocatedWritableCode 16 3) := by trivial

example (imported : ExternalTarget) :
    RuntimeInventoryPopulated (.importedAddress 20 imported) := by trivial

example (queries : List ResolverQuery) :
    RuntimeInventoryPopulated (.resolverResults queries []) := by trivial

example :
    RuntimeInventoryPopulated (.registeredCallbackSlot 24 [3]) := by
  simp [RuntimeInventoryPopulated]

example :
    RuntimeInventoryPopulated (.nullableCodeTable 32 40 [none, some 3]) := by
  simp [RuntimeInventoryPopulated, NullableTableRuntimePopulated]

example :
    ¬ RuntimeInventoryPopulated (.registeredCallbackSlot 24 []) := by
  simp [RuntimeInventoryPopulated]

example :
    ¬ RuntimeInventoryPopulated (.nullableCodeTable 32 40 [none, none]) := by
  simp [RuntimeInventoryPopulated, NullableTableRuntimePopulated]

theorem emptyCallbacksRequireUnreachable
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    (authority : CheckedAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (composition :
      RegisterIndirectMixedOriginalComposition authority invariant)
    (inventoryExact : authority.certificate.certificate.inventory =
      .registeredCallbackSlot 24 []) :
    ActualMixedOriginalRegisterSourceUninhabited invariant
      authority.certificate.certificate.site.sourceTargetId :=
  sourceUninhabited_of_emptyCallbackInventory composition inventoryExact

theorem targetlessTableRequiresUnreachable
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    (authority : CheckedAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (composition :
      RegisterIndirectMixedOriginalComposition authority invariant)
    (inventoryExact : authority.certificate.certificate.inventory =
      .nullableCodeTable 32 40 [none, none]) :
    ActualMixedOriginalRegisterSourceUninhabited invariant
      authority.certificate.certificate.site.sourceTargetId := by
  apply sourceUninhabited_of_targetlessNullableInventory composition
    inventoryExact
  simp [NullableTableRuntimePopulated]

#print axioms runningSourceUsesActualInvariant
#print axioms callbackSourceUsesActualInvariant
#print axioms originalInvariantClosesConcretePath
#print axioms combinedInvariantProjectsMember
#print axioms executionInvariantBuildsRuntimePremise
#print axioms mixedExecutionInvariantBuildsTargetPremise
#print axioms runtimePremiseStillTransports
#print axioms finiteCompositionClosesActualSource
#print axioms emptyCallbacksRequireUnreachable
#print axioms targetlessTableRequiresUnreachable

end StageA.RegisterIndirectMixedOriginalCompositionKernel
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARegisterIndirectMixedOriginalCompositionKernelTests(unittest.TestCase):
    def test_generic_runtime_bridge_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        layer = (
            source_root
            / "RelationalRegisterIndirectMixedOriginalComposition.lean"
        ).read_text(encoding="utf-8")
        invariant_layer = (
            source_root / "RelationalOriginalExecutionInvariant.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)
            self.assertIsNone(
                re.search(rf"\b{marker}\b", invariant_layer), marker
            )
        for expected in (
            "OriginalWorldExecutionInvariant",
            "pathClosed",
            "strengthenMixedExecutionInvariant",
            "strengthenMixedWorldChunkComposition",
        ):
            self.assertIn(expected, invariant_layer)
        for expected in (
            "RegisterAuthorityReachableAtSource",
            "RegisterAuthorityExecutionInvariant",
            "mixedRuntimeClosurePremise_of_originalInvariant",
        ):
            self.assertIn(expected, layer)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalRegisterIndirectMixedOriginalComposition",
            )
            kernel = (
                stage_a / "RegisterIndirectMixedOriginalCompositionKernel.lean"
            )
            kernel.write_text(_KERNEL, encoding="utf-8")
            result = _run_lean_relational(
                root,
                bundle="RegisterIndirectMixedOriginalCompositionKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 8, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
