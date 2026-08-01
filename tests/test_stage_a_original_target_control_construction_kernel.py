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


_KERNEL = r'''import StageA.RelationalOriginalTargetControlConstruction

namespace StageA.OriginalTargetControlConstructionKernel

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalTargetControlConstruction
open StageA.Relational.OriginalTargetControlPreservation
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting

def directNoWriteControlIsUniversal
    {pe : PE32} {program : Program} {targetId sourceRva nextTargetId : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram context}
    (checked : CheckedOrdinaryTargetEffect binding decoded)
    (adequate : program.worldProgram.InstructionSemanticsAdequate)
    (outcomeExact : forall calls,
      (decoded.normalized calls).outcome = .jump nextTargetId)
    (writesEmpty : forall calls, (decoded.normalized calls).writes = [])
    (reachable : nextTargetId ∈ inventory.reachableTargets.targetIds) :
    CheckedOriginalTargetControlEvidence context inventory
      (CheckedOriginalTargetEffect.ofOrdinary checked adequate) :=
  ordinaryNoWriteJumpControl checked adequate outcomeExact writesEmpty reachable

#print axioms directNoWriteControlIsUniversal
#print axioms ordinaryNoWriteBranchControl

end StageA.OriginalTargetControlConstructionKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalTargetControlConstructionKernelTests(unittest.TestCase):
    def test_direct_control_constructors_are_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalTargetControlConstruction.lean"
        ).read_text(encoding="utf-8")
        for forbidden in (
            r"^\s*axiom\b",
            r"^\s*opaque\b",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
        ):
            self.assertNotRegex(module_text, forbidden)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalTargetControlConstruction",
            )
            (stage_a / "OriginalTargetControlConstructionKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalTargetControlConstructionKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)


if __name__ == "__main__":
    unittest.main()
