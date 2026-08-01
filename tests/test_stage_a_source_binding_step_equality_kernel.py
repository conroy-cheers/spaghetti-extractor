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
class StageASourceBindingStepEqualityKernelTests(unittest.TestCase):
    def test_exact_binding_and_target_world_equalities_aggregate_soundly(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalSourceInterpreterKernel.lean"
        ).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"^\s*axiom\b", module_text, re.MULTILINE))
        self.assertNotIn("sorry", module_text)
        self.assertNotIn("unsafe", module_text)
        self.assertIn("BoundTargetSelection", module_text)
        self.assertIn("TargetWorldRoutingExact", module_text)
        self.assertIn("TargetLocalEffectExact", module_text)
        self.assertIn("toWorldRoutingExact", module_text)
        self.assertIn("ExactBoundTargetStepEquality", module_text)
        self.assertIn("ExactBindingDomainTargetStepCoverage", module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalSourceInterpreterKernel",
            )
            (stage_a / "SourceBindingStepEqualityKernelFixture.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="SourceBindingStepEqualityKernelFixture",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("Classical.choice", output)
        self.assertIn(
            "ExactBinding.programRecordKernelMatchesDecodedSemantics",
            output,
        )


_KERNEL_FIXTURE = r'''import StageA.RelationalSourceInterpreterKernel

namespace StageA.SourceBindingStepEqualityKernelFixture

open StageA.Formal
open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

example {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord}
    (sourceExact : sourceRvaForTarget? program targetId = some sourceRva)
    (classificationExact : x87Classified program sourceRva = some false)
    (lookupExact : lookupRecord? program.records sourceRva = some record)
    (recordMember : record ∈ program.records)
    (notX87 : sourceRva ∉ program.x87SourceRvas) :
    BoundTargetSelection program targetId := by
  exact .ordinary sourceRva record sourceExact classificationExact lookupExact
    recordMember notX87

example {program : Program} {targetId sourceRva : Nat}
    (sourceExact : sourceRvaForTarget? program targetId = some sourceRva)
    (classificationExact : x87Classified program sourceRva = some true)
    (classified : sourceRva ∈ program.x87SourceRvas) :
    BoundTargetSelection program targetId := by
  exact .x87 sourceRva sourceExact classificationExact classified

example {program : Program} {root : WorldExecution}
    (domain : CheckedExecutionDomain program.worldProgram root)
    {targetId : Nat} {state : MachineState} {calls : List Nat}
    {eventIndex : Nat} {world : RelationalWorld}
    (inDomain :
      domain.holds (.running targetId state calls eventIndex world)) :
    TargetActiveInDomain domain targetId := by
  exact Or.inl ⟨state, calls, eventIndex, world, inDomain⟩

example {pe : PE32} {program : Program}
    {binding : ExactBinding pe program} {targetId : Nat}
    (selection : BoundTargetSelection program targetId)
    (routing : TargetWorldRoutingExact program targetId) :
    ExactBoundTargetStepEquality binding targetId := by
  exact ExactBoundTargetStepEquality.ofSelectionAndRouting selection routing

example {program : Program} {targetId : Nat}
    (localExact : TargetLocalEffectExact program targetId) :
    TargetWorldRoutingExact program targetId := by
  exact localExact.toWorldRoutingExact

example {program : Program} {targetId : Nat}
    (components : SuccessfulTargetEffectComponents program targetId) :
    TargetLocalEffectExact program targetId := by
  exact components.toLocalEffectExact

example {pe : PE32} {program : Program}
    (binding : ExactBinding pe program) {root : WorldExecution}
    (domain : CheckedExecutionDomain program.worldProgram root)
    (coverage : ExactBindingDomainTargetStepCoverage binding domain) :
    ProgramRecordKernelMatchesDecodedSemantics program domain := by
  exact binding.programRecordKernelMatchesDecodedSemantics domain coverage

#print axioms SuccessfulTargetEffectComponents.toLocalEffectExact
#print axioms TargetLocalEffectExact.toWorldRoutingExact
#print axioms ExactBoundTargetStepEquality.ofSelectionAndRouting
#print axioms ExactBinding.programRecordKernelMatchesDecodedSemantics

end StageA.SourceBindingStepEqualityKernelFixture
'''


if __name__ == "__main__":
    unittest.main()
