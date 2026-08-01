from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageASourceOrdinaryTargetRoutingKernelTests(unittest.TestCase):
    def test_checked_ordinary_facts_assemble_without_new_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalSourceOrdinaryTargetRouting.lean"
        ).read_text(encoding="utf-8")
        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bhello\b",
        ):
            self.assertIsNone(re.search(forbidden, module_text, re.MULTILINE))
        self.assertIn("normalization", module_text)
        self.assertIn("regionExact", module_text)
        self.assertIn("machineImportContractsAt", module_text)
        self.assertIn("kindExact", module_text)
        self.assertIn("machineExact", module_text)
        self.assertIn("ExactOrdinaryTargetSemanticReplay", module_text)
        self.assertIn("ordinaryStepExact", module_text)
        self.assertIn("contractStepExact", module_text)
        replay_source = re.search(
            r"structure ExactOrdinaryTargetSemanticReplay.*?\n/-- Derive",
            module_text,
            re.DOTALL,
        )
        self.assertIsNotNone(replay_source)
        self.assertNotIn("TargetLocalEffectExact", replay_source.group(0))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalSourceOrdinaryTargetRouting",
            )
            (stage_a / "SourceOrdinaryTargetRoutingFixture.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="ascii",
            )
            result = _run_lean_relational(
                root,
                bundle="SourceOrdinaryTargetRoutingFixture",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("Classical.choice", output)
        self.assertIn(
            "CheckedOrdinaryTargetEffect.toSuccessfulTargetEffectComponents",
            output,
        )
        self.assertIn(
            "CheckedOrdinaryTargetEffect.toLocalEffectExact",
            output,
        )


_KERNEL_FIXTURE = r'''import StageA.RelationalSourceOrdinaryTargetRouting

namespace StageA.SourceOrdinaryTargetRoutingFixture

open StageA.Formal
open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterSemanticRefinement
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting

example {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    (binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region) (state : MachineState) :
    targetStep? program targetId state =
      ordinaryStepWithCalls? program targetId record state [] := by
  exact binding.targetStep_eq_ordinaryStepWithCalls state

example {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    (checked : CheckedOrdinaryTargetEffect binding decoded) :
    SuccessfulTargetEffectComponents program targetId := by
  exact checked.toSuccessfulTargetEffectComponents

example {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    (checked : CheckedOrdinaryTargetEffect binding decoded) :
    TargetLocalEffectExact program targetId := by
  exact checked.toLocalEffectExact

example {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    (replay : ExactOrdinaryTargetSemanticReplay binding) :
    CheckedOrdinaryTargetEffect binding replay.decoded := by
  exact replay.toCheckedOrdinaryTargetEffect

example (contract : MachineImportCallContract) (state : MachineState)
    (arguments : List Word) (continuation : Nat) :
    applyOrdinaryMachineImportContracts? [contract] state
        (.externalCall contract.imported arguments continuation) =
      some (.externalCall contract.imported
        (machineImportArgumentsAtState contract state) continuation) := by
  simp [applyOrdinaryMachineImportContracts?]

example (contract : MachineImportCallContract) (state : MachineState)
    (arguments : List Word)
    (offsetsValid : contract.stackArgumentOffsets.all
      (fun offset => offset + 8 <= 2 ^ 32) = true) :
    applyOrdinaryMachineImportContracts? [contract] state
        (.externalJump contract.imported arguments) =
      some (.externalJump contract.imported
        (contract.stackArgumentOffsets.map fun offset =>
          Memory.read32 state.memory
            (state.registers.esp + BitVec.ofNat 32 (offset + 4)))) := by
  have offsetsValid' : forall offset,
      List.Mem offset contract.stackArgumentOffsets -> offset + 8 <= 2 ^ 32 := by
    intro offset member
    have checked := List.all_eq_true.mp offsetsValid offset member
    simpa using checked
  have offsetsBounded : forall offset,
      List.Mem offset contract.stackArgumentOffsets -> offset <= 4294967288 := by
    intro offset member
    have := offsetsValid' offset member
    omega
  simp [applyOrdinaryMachineImportContracts?,
    machineImportThunkArgumentsAtState?]
  split <;> simp_all

#print axioms
  ExactOrdinaryTargetBinding.targetStep_eq_ordinaryStepWithCalls
#print axioms
  ExactOrdinaryTargetBinding.targetStepWithCalls_eq_ordinaryStepWithCalls
#print axioms ExactOrdinaryTargetBinding.recordMacroStepExact
#print axioms ExactOrdinaryTargetBinding.fusedInterpreterMachineExact
#print axioms formalFromInterpreter_fusedMachineExact
#print axioms ExactDecodedOrdinaryTargetEvaluator.decodedBehaviorExact
#print axioms ExactOrdinaryTargetSemanticReplay.toCheckedOrdinaryTargetEffect
#print axioms EvaluatedEffect.eq_of_kind_and_machine
#print axioms CheckedOrdinaryTargetEffect.toSuccessfulTargetEffectComponents
#print axioms CheckedOrdinaryTargetEffect.toLocalEffectExact

end StageA.SourceOrdinaryTargetRoutingFixture
'''


if __name__ == "__main__":
    unittest.main()
