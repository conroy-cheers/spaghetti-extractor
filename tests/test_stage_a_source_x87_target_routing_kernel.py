from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


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
class StageASourceX87TargetRoutingKernelTests(unittest.TestCase):
    def test_exact_x87_target_evidence_closes_local_and_world_routing(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalSourceX87TargetRouting.lean"
        ).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"^\s*axiom\b", module_text, re.MULTILINE))
        self.assertNotIn("sorry", module_text)
        self.assertNotIn("unsafe", module_text)
        self.assertNotIn("native_decide", module_text)
        self.assertIn("ExactX87SingletonScheduleFacts", module_text)
        self.assertIn("ExactX87SingletonTargetFacts", module_text)
        self.assertIn("toSuccessfulTargetEffectComponents", module_text)
        self.assertNotIn("ExactX87TargetSourceCarrier", module_text)
        self.assertNotIn("ExactDecodedX87TargetCarrier", module_text)
        self.assertNotIn("ExactX87TargetEffectRouting", module_text)
        target_body = module_text.split(
            "structure ExactX87SingletonTargetFacts", 1
        )[1].split(
            "theorem ExactX87SingletonTargetFacts.providerExact", 1
        )[0]
        self.assertNotIn("providerExact :", target_body)
        self.assertNotIn("forall state", target_body)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalSourceX87TargetRouting",
            )
            (stage_a / "SourceX87TargetRoutingKernelFixture.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="SourceX87TargetRoutingKernelFixture",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        observed_axioms = set(
            re.findall(r"(?:propext|Classical\.choice|Quot\.sound|sorryAx)", output)
        )
        self.assertLessEqual(observed_axioms, RELATIONAL_APPROVED_AXIOMS)
        self.assertIn("ExactX87SingletonTargetFacts.toLocalEffectExact", output)
        self.assertIn(
            "ExactX87SingletonTargetFacts.toSuccessfulTargetEffectComponents",
            output,
        )
        self.assertIn("ExactX87SingletonTargetFacts.toWorldRoutingExact", output)


_KERNEL_FIXTURE = r'''import StageA.RelationalSourceX87TargetRouting

namespace StageA.SourceX87TargetRoutingKernelFixture

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterX87
open StageA.Relational.SourceWorld.InterpreterKernel

example {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule) :
    BoundTargetSelection program targetId :=
  facts.toBoundTargetSelection

example {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule)
    (state : MachineState) :
    program.x87Provider.execute witness.schedule.sourceRva state =
      runExactInterpreter pe witness.schedule state :=
  facts.providerExact state

example {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule) :
    TargetLocalEffectExact program targetId :=
  facts.toLocalEffectExact

example {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule) :
    SuccessfulTargetEffectComponents program targetId :=
  facts.toSuccessfulTargetEffectComponents

example {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule) :
    TargetWorldRoutingExact program targetId :=
  facts.toWorldRoutingExact

#print axioms ExactX87SingletonScheduleFacts.stepRefines
#print axioms ExactX87SingletonScheduleFacts.runExactInterpreter_of_step
#print axioms executeSingletonCommand_isSome_of_decoded_and_continuation
#print axioms executeSingletonCommand_eq_with_outcome_of_continuations
#print axioms StageA.Relational.X87.executeSingletonCommand_outcome_of_continuation
#print axioms StageA.Relational.X87.executeSingletonCommand_effect_isSome
#print axioms executeX87Singleton_eq_exactStepResult
#print axioms TargetLocalEffectExact.toWorldRoutingExact
#print axioms ExactX87SingletonTargetFacts.providerExact
#print axioms ExactX87SingletonTargetFacts.decodedBehaviorExact
#print axioms ExactX87SingletonTargetFacts.toSuccessfulTargetEffectComponents
#print axioms ExactX87SingletonTargetFacts.toLocalEffectExact
#print axioms ExactX87SingletonTargetFacts.toWorldRoutingExact

end StageA.SourceX87TargetRoutingKernelFixture
'''


if __name__ == "__main__":
    unittest.main()
