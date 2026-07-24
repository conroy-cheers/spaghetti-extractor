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


class StageARelationalInterpreterKernelBridgeTests(unittest.TestCase):
    def test_kernel_contains_no_unchecked_acceptance_construct(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernel.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertIsNone(
            re.search(
                r"\b(?:def|theorem|structure)\s+WholeProgramCertificate\b",
                source,
            )
        )
        self.assertIn("KernelArtifactBinding.Valid", source)
        self.assertIn("stepPE32Instruction", source)
        self.assertIn("MemoryAgreesOutside footprint", source)
        self.assertIn("CompiledKernelProgram.checked", source)
        self.assertIn("interpreterStepImplementsMacroStep", source)
        self.assertNotIn("abiTotal", source)
        self.assertNotIn("KernelABIRelation.Total", source)
        self.assertNotIn("NativeDispatchRefinement", source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_kernel_bridge_and_generic_primitives_compile(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernel"
            )
            (stage_a / "RelationalInterpreterKernelFixture.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


_FIXTURE = r"""import StageA.RelationalInterpreterKernel

namespace StageA.Relational.InterpreterKernelFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel

example : KernelSHA256.hex [97, 98, 99] =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" := by
  native_decide

example (footprint : CandidateFootprint) (memory : Memory) :
    MemoryAgreesOutside footprint memory memory :=
  MemoryAgreesOutside.refl footprint memory

example {footprint : CandidateFootprint} {first second third : Memory}
    (left : MemoryAgreesOutside footprint second first)
    (right : MemoryAgreesOutside footprint third second) :
    MemoryAgreesOutside footprint third first :=
  MemoryAgreesOutside.trans left right

example (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (before : NativeExecution) :
    NativeSteps pe imports environment before
      (stepNativeExecution pe imports environment before) :=
  NativeSteps.single pe imports environment before

example : KernelOperation.interpreterStep.role = KernelRole.interpreterStep :=
  rfl

example (environment : StageA.Relational.Interpreter.Environment)
    (state : StageA.Relational.Interpreter.InterpreterMachine) :
    abstractInterpreterStep [] environment 4096 state = none :=
  rfl

example (environment : StageA.Relational.Interpreter.Environment)
    (state : StageA.Relational.Interpreter.InterpreterMachine)
    (resolve : Word -> Option Nat) :
    AbstractRunFunction [] environment resolve 4096 state
      { status := .unimplemented, state := state } :=
  AbstractRunFunction.unavailable 4096 state rfl

example : AbstractKernelTransition (.programLookup [] 4096)
    (.programLookup none) :=
  AbstractKernelTransition.programLookup [] 4096

end StageA.Relational.InterpreterKernelFixture
"""
