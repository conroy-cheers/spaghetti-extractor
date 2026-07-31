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
class StageACanonicalMixedRelationCoreCallableKernelTests(unittest.TestCase):
    def test_callable_lift_is_kernel_checked_and_preserves_contract(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterMixedProfile"
            )
            (stage_a / "CanonicalMixedRelationCoreCallableKernel.lean").write_text(
                _KERNEL_SOURCE,
                encoding="ascii",
            )
            result = _run_lean_relational(
                root, bundle="CanonicalMixedRelationCoreCallableKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        reports = re.findall(
            r"depends on axioms:\s*\[([^]]*)\]", output, re.DOTALL
        )
        self.assertEqual(len(reports), 2, output)
        for report in reports:
            observed = {
                item.strip() for item in report.split(",") if item.strip()
            }
            self.assertLessEqual(observed, {"propext", "Quot.sound"})


_KERNEL_SOURCE = r"""import StageA.RelationalInterpreterMixedProfile

namespace StageA.CanonicalMixedRelationCoreCallableKernel

open StageA.Relational
open StageA.Relational.CallableExternalExecution
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

variable {original : OriginalDecodedStaticContext}
variable {originalAuthority : ExactOriginalDecodedAuthority original}
variable {originalProgram : DecodedWorldProgram}
variable {candidate : ExactNativeWorldProgram}
variable {candidateAuthority : ExactNativeCandidateAuthority candidate}
variable {programBinding : ExactMixedProgramBinding original originalProgram}
variable {abi : ConcreteKernelABI candidate.pe candidate.imports
  candidateAuthority.relocations candidateAuthority.tableRva
  candidateAuthority.countRva candidateAuthority.semanticRecords}
variable {reachableTargetIds : List Nat}

example
    (core : CanonicalMixedRelationCore original originalAuthority originalProgram
      candidate candidateAuthority programBinding abi reachableTargetIds)
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment) :
    CanonicalMixedRelationCore original originalAuthority
      (decodedWorldProgramWithCallable originalProgram program environment)
      candidate candidateAuthority
      (programBinding.withCallable program environment) abi reachableTargetIds :=
  core.withCallable program environment

example
    (core : CanonicalMixedRelationCore original originalAuthority originalProgram
      candidate candidateAuthority programBinding abi reachableTargetIds)
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment) :
    (core.withCallable program environment).contract = core.contract :=
  CanonicalMixedRelationCore.withCallable_contract core program environment

#print axioms CanonicalMixedRelationCore.withCallable
#print axioms CanonicalMixedRelationCore.withCallable_contract

end StageA.CanonicalMixedRelationCoreCallableKernel
"""


if __name__ == "__main__":
    unittest.main()
