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
class StageASourceInterpreterKernelTests(unittest.TestCase):
    def test_world_aware_record_kernel_and_exact_bindings_are_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalSourceInterpreterKernel",
            )
            (stage_a / "SourceInterpreterKernelFixture.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="SourceInterpreterKernelFixture",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertIn("decodedSemanticChunkComposition", output)
        self.assertIn("ExactBinding.kernelObservationallyEquivalent", output)
        self.assertIn("ExactBinding.ordinaryMacroStepExact", output)
        self.assertIn("ExactBinding.x87ProviderExact", output)


_KERNEL_FIXTURE = r"""import StageA.RelationalSourceInterpreterKernel

namespace StageA.SourceInterpreterKernelFixture

open StageA.Formal
open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

def emptyRecord (sourceRva : Nat) : ProgramRecord := {
  sourceRva
  wordNodes := []
  x87Nodes := []
  calls := []
  actions := []
}

example : lookupRecord? [emptyRecord 7] 7 = some (emptyRecord 7) := by
  native_decide

example : lookupRecord? [emptyRecord 7, emptyRecord 7] 7 = none := by
  native_decide

example : lookupRecord? [] 7 = none := by
  native_decide

example (program : Program) :
    x87Classified { program with x87SourceRvas := [7, 7] } 7 = none := by
  rfl

example (program : Program) (sourceRva : Nat) (state : MachineState)
    (unsupported : program.x87Provider.execute sourceRva state = none) :
    x87Step? program sourceRva state = none := by
  simp [x87Step?, unsupported]

example (program : DecodedWorldProgram)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain program root)
    (adequate : program.InstructionSemanticsAdequate)
    (admissible : DecodedSemanticStepsAdmissible program domain)
    : ChunkComposition program (decodedSemanticKernel program) root domain := by
  exact decodedSemanticChunkComposition program root domain adequate admissible

example (program : Program)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain program.worldProgram root)
    (adequate : program.worldProgram.InstructionSemanticsAdequate)
    (admissible : DecodedSemanticStepsAdmissible program.worldProgram domain)
    (stepMatches : ProgramRecordKernelMatchesDecodedSemantics program domain) :
    ExactOriginalPESourceKernelObservationallyEquivalent program.worldProgram
      program.kernel root domain := by
  exact programRecordKernelObservationallyEquivalentFromStepEquality program
    root domain adequate admissible stepMatches

example {program : Program}
    (binding : ExactBinding program.worldProgram.context.originalPe program)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain program.worldProgram root)
    (adequate : program.worldProgram.InstructionSemanticsAdequate)
    (admissible : DecodedSemanticStepsAdmissible program.worldProgram domain)
    (stepMatches : ProgramRecordKernelMatchesDecodedSemantics program domain) :
    ExactOriginalPESourceKernelObservationallyEquivalent program.worldProgram
      program.kernel root domain := by
  exact binding.kernelObservationallyEquivalent root domain adequate admissible
    stepMatches

example {pe : PE32} {program : Program} (binding : ExactBinding pe program)
    {record : ProgramRecord} (member : record ∈ program.records)
    (notX87 : record.sourceRva ∉ program.x87SourceRvas)
    (state : MachineState) :
    exists path transfer,
      path.record = record ∧ path.sourceRva = record.sourceRva ∧
        InterpreterNormalization.ExactProgramRecordNormalizationCertificate
          pe path transfer ∧
        record.interpret (localEnvironment state)
            (InterpreterTransfer.machineFromFormal state) =
          InterpreterNormalization.runExactNormalizedPath pe path
            (localEnvironment state) state := by
  exact binding.ordinaryMacroStepExact member notX87 state

example {pe : PE32} {program : Program} (binding : ExactBinding pe program)
    {sourceRva : Nat} (classified : sourceRva ∈ program.x87SourceRvas)
    (state : MachineState) :
    exists witness,
      witness ∈ binding.witnesses ∧ witness.schedule.sourceRva = sourceRva ∧
      program.x87Provider.execute sourceRva state =
        InterpreterX87.runExactInterpreter pe witness.schedule state := by
  exact binding.x87ProviderExact classified state

#print axioms decodedSemanticChunkComposition
#print axioms decodedSemanticKernelObservationallyEquivalent
#print axioms programRecordKernelObservationallyEquivalentFromStepEquality
#print axioms ExactBinding.kernelObservationallyEquivalent
#print axioms ExactBinding.ordinaryMacroStepExact
#print axioms ExactBinding.x87ProviderExact

end StageA.SourceInterpreterKernelFixture
"""


if __name__ == "__main__":
    unittest.main()
