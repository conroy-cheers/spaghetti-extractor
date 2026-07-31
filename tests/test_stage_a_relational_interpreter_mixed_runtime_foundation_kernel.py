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
class StageAMixedRuntimeFoundationKernelTests(unittest.TestCase):
    def test_runtime_foundation_is_kernel_checked(self) -> None:
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
                "RelationalInterpreterMixedRuntimeFoundation",
            )
            (stage_a / "MixedRuntimeFoundationKernel.lean").write_text(
                _KERNEL_SOURCE,
                encoding="ascii",
            )
            result = _run_lean_relational(
                root, bundle="MixedRuntimeFoundationKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)


_KERNEL_SOURCE = r"""import StageA.RelationalInterpreterMixedRuntimeFoundation

namespace StageA.MixedRuntimeFoundationKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedRuntimeFoundation
open StageA.Relational.InterpreterNativeWorld

variable {candidateImageBase : Nat}
variable {continuationTargetsRelated : Nat -> Nat -> Prop}

example
    (related : ExactMixedCallFramesRelated candidateImageBase
      continuationTargetsRelated originalCalls candidateCalls) :
    originalCalls.length = candidateCalls.length :=
  related.length_eq

example
    (related : ExactMixedCallFramesRelated candidateImageBase
      continuationTargetsRelated
      (targetId :: originalTail) (frame :: candidateTail)) :
    frame.returnAddress =
      BitVec.ofNat 32 (candidateImageBase + frame.continuationRva) :=
  related.head_return_address

example
    (related :
      (exactMixedExternalFrameContract candidateImageBase
        continuationTargetsRelated).callFramesRelated
          originalCalls callbacks candidateCalls) :
    callbacks = [] :=
  related.1

example
    (callbackReturnAddressesRelated : Word -> Word -> Prop)
    (related :
      (exactMixedNestedExternalFrameContract candidateImageBase
        continuationTargetsRelated
        callbackReturnAddressesRelated).callFramesRelated
          originalCalls callbacks candidateCalls) :
    ExactMixedCallFramesRelated candidateImageBase continuationTargetsRelated
      originalCalls candidateCalls :=
  related

#print axioms ExactMixedCallFramesRelated.length_eq
#print axioms ExactMixedCallFramesRelated.head_return_address
#check ExactMixedLaunchRootRelated
#print axioms ExactMixedLaunchRootRelated.originalReachable
#print axioms ExactMixedLaunchRootRelated.candidateProofOpen

end StageA.MixedRuntimeFoundationKernel
"""


if __name__ == "__main__":
    unittest.main()
