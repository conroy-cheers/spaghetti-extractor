from __future__ import annotations

import re
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_import_image

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_native_launch import (
    NativeLaunchCertificateSpec,
    NativeLaunchCutpointSpec,
    NativeLaunchPathSpec,
    build_relational_interpreter_native_launch_plan,
    relational_interpreter_native_launch_source,
)


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


def _candidate_image() -> bytes:
    code = bytearray(b"\x90" * 0x40)
    code[0:5] = b"\xe9\x0b\x00\x00\x00"
    code[0x10] = 0xC3
    code[0x20] = 0xC3
    code[0x30:0x36] = b"\xff\x25" + struct.pack("<I", 0x402040)
    code[0x38:0x3A] = b"\xff\xe0"
    return pe32_import_image(bytes(code), symbol="Terminate")


def _spec() -> NativeLaunchCertificateSpec:
    return NativeLaunchCertificateSpec(
        cutpoints=(
            NativeLaunchCutpointSpec("dispatch", 0x1010),
            NativeLaunchCutpointSpec("return_wrapper", 0x1020),
            NativeLaunchCutpointSpec("termination_wrapper", 0x1030),
        ),
        paths=(
            NativeLaunchPathSpec(
                "entry", "stable_cutpoint", (0x1000,), destination_index=0
            ),
            NativeLaunchPathSpec(
                "stable_cutpoint", "returned", (0x1020,), source_index=1
            ),
            NativeLaunchPathSpec(
                "stable_cutpoint", "terminated", (0x1030,), source_index=2
            ),
        ),
    )


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARelationalInterpreterNativeLaunchKernelTests(unittest.TestCase):
    def test_reflection_derives_exact_native_path_without_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            candidate.write_bytes(_candidate_image())
            plan = build_relational_interpreter_native_launch_plan(
                candidate_pe=candidate, spec=_spec()
            )

            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterNativeLaunch"
            )
            generated = plan.spec.module_name
            (stage_a / f"{generated}.lean").write_text(
                relational_interpreter_native_launch_source(plan),
                encoding="utf-8",
            )
            (stage_a / "RelationalInterpreterNativeLaunchKernel.lean").write_text(
                _KERNEL_FIXTURE.format(generated=generated), encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterNativeLaunchKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertIn(
            "ReflectedNativeLaunchPathCertificate.replay?_sound", output
        )
        self.assertIn("entryPathRealized", output)


_KERNEL_FIXTURE = r"""import StageA.{generated}

namespace StageA.Relational.InterpreterNativeLaunchKernel

set_option maxRecDepth 1000000

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterNativeLaunch

def zeroWord : Word := BitVec.ofNat 32 0

def zeroRegisters : Registers Word := {{
  eax := zeroWord
  ebx := zeroWord
  ecx := zeroWord
  edx := zeroWord
  esi := zeroWord
  edi := zeroWord
  ebp := zeroWord
  esp := zeroWord
}}

def zeroMachine : MachineState := {{
  registers := zeroRegisters
  memory := fun _ => BitVec.ofNat 8 0
}}

def blockingEnvironment : NativeWorldEnvironment := {{
  action := fun _ _ _ => .blocked (.unclassifiedNativeFault 0)
}}

def generatedProgram : ExactNativeWorldProgram := {{
  pe := generatedNativeLaunchCandidatePe
  imports := generatedNativeLaunchImports
  environment := blockingEnvironment
}}

def entryBefore : NativeWorldExecution :=
  .running 0x1000 0 zeroMachine [] 0 [] RelationalWorld.empty

theorem entryReplayExists :
    (generatedNativeLaunchPath0000.replay? generatedProgram
      generatedNativeLaunchCutpoints entryBefore).isSome = true := by
  decide +kernel

theorem entryPathRealized :
    exists result,
      generatedNativeLaunchPath0000.replay? generatedProgram
          generatedNativeLaunchCutpoints entryBefore = some result /\
        NonemptyRelatedPath generatedProgram.transitionSystem entryBefore
          result.observations result.after := by
  have present := entryReplayExists
  cases replayed : generatedNativeLaunchPath0000.replay? generatedProgram
      generatedNativeLaunchCutpoints entryBefore with
  | none => simp [replayed] at present
  | some result =>
      refine ⟨result, rfl, ?_⟩
      exact (generatedNativeLaunchPath0000.replay?_sound generatedProgram
        generatedNativeLaunchCutpoints entryBefore result replayed).2.2

def unsupportedIndirect : KernelInstruction := {{
  rva := 0x1038
  bytes := [0xff, 0xe0]
}}

example : nativeWrapperInstructionSupported
    generatedNativeLaunchCandidatePe generatedNativeLaunchImports
      unsupportedIndirect = false := by
  decide +kernel

#check canonicalNativeLaunchRoots?
#check DirectExactCandidateNativeLaunchRoot
#check directExactCandidateNativeLaunchRootChecked_iff
#check DirectExactCandidateNativeLaunchRoot.resolvesFromCandidatePE
#check ExactNativeLaunchWrapperCertificate.staticChecked
#print axioms directExactCandidateNativeLaunchRootChecked_iff
#print axioms DirectExactCandidateNativeLaunchRoot.resolvesFromCandidatePE
#print axioms ReflectedNativeLaunchPathCertificate.replay?_sound
#print axioms ExactNativeLaunchWrapperCertificate.semanticSound
#print axioms generatedNativeLaunchCertificateStaticChecked
#print axioms entryPathRealized

end StageA.Relational.InterpreterNativeLaunchKernel
"""


if __name__ == "__main__":
    unittest.main()
