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


_KERNEL = r'''import StageA.RelationalOriginalRuntimeMemoryAccessChecker

namespace StageA.OriginalRuntimeMemoryAccessCheckerKernel

open StageA.Formal StageA.Relational
open StageA.Relational.OriginalRuntimeMemoryAccessChecker
open StageA.Relational.OriginalRuntimeMemoryPartition

def zeroWord : Word := BitVec.ofNat 32 0

def registersWithStack : Registers Word := {
  eax := BitVec.ofNat 32 0x3008
  ebx := zeroWord
  ecx := zeroWord
  edx := zeroWord
  esi := zeroWord
  edi := zeroWord
  ebp := BitVec.ofNat 32 0x1ff0
  esp := BitVec.ofNat 32 0x2000
}

def concreteState : MachineState := {
  registers := registersWithStack
  memory := fun _ => BitVec.ofNat 8 0
}

def stackRange : DynamicAddressRangePair := {
  id := 11
  originalBase := BitVec.ofNat 32 0x1000
  candidateBase := BitVec.ofNat 32 0x5000
  size := 0x1000
}

def dynamicRange : DynamicAddressRangePair := {
  id := 12
  originalBase := BitVec.ofNat 32 0x3000
  candidateBase := BitVec.ofNat 32 0x7000
  size := 0x100
}

def concreteWorld : RelationalWorld := {
  stackRanges := [stackRange]
  dynamicRanges := [dynamicRange]
}

def stackWrites : List (Expr × Expr) :=
  [(.sub (.inputReg .esp) (.constant 4), .constant 7)]

def stackReference : OriginalNormalizedWriteReference := {
  index := 0
  address := .sub (.inputReg .esp) (.constant 4)
  value := .constant 7
}

def stackCertificate : OriginalRuntimeAddressCertificate :=
  .stackAffine .esp (.sub 4) {
    kind := .stack
    index := 0
    id := 11
  }

def dynamicWrites : List (Expr × Expr) :=
  [(.add (.inputReg .eax) (.constant 12), .constant 9)]

def dynamicReference : OriginalNormalizedWriteReference := {
  index := 0
  address := .add (.inputReg .eax) (.constant 12)
  value := .constant 9
}

def dynamicCertificate : OriginalRuntimeAddressCertificate :=
  .dynamicAffine (.inputReg .eax) 8 (.add 12) {
    kind := .dynamic
    index := 0
    id := 12
  }

theorem stackAffineChecksExactly :
    originalNormalizedRuntimeWriteChecked concreteWorld concreteState
      stackWrites stackReference stackCertificate = true := by decide

theorem dynamicAffineChecksWithOrigin :
    originalNormalizedRuntimeWriteChecked concreteWorld concreteState
      dynamicWrites dynamicReference dynamicCertificate = true := by decide

theorem missingRangeFailsClosed :
    originalNormalizedRuntimeWriteChecked RelationalWorld.empty concreteState
      stackWrites stackReference stackCertificate = false := by decide

def checkedStackAccessProducesRangeWitness :
    OriginalRuntimeAccessWitness concreteWorld
      (stackReference.address.eval concreteState) 4 :=
  originalNormalizedRuntimeWriteChecked_toWitness concreteWorld concreteState
    stackWrites stackReference stackCertificate stackAffineChecksExactly

def checkedDynamicAccessProducesRangeWitness :
    OriginalRuntimeAccessWitness concreteWorld
      (dynamicReference.address.eval concreteState) 4 :=
  originalNormalizedRuntimeWriteChecked_toWitness concreteWorld concreteState
    dynamicWrites dynamicReference dynamicCertificate dynamicAffineChecksWithOrigin

theorem checkedRuntimeAccessAvoidsProtectedStatic
    (context : StaticProofContext)
    (partition : HoldsIn context concreteWorld)
    (wordAddress : Word)
    (wordValid : writableStaticWordInPe context.originalPe wordAddress = true) :
    OriginalAccessAvoidsWord wordAddress
      (stackReference.address.eval concreteState) 4 := by
  exact checkedStackAccessProducesRangeWitness.avoidsWritableStaticWord
    partition wordValid

theorem staticSlotRequiresRelatedPostUpdate
    {context : StaticProofContext} {state : MachineState}
    {writes : List (Expr × Expr)} {afterWorld : RelationalWorld}
    {afterMemory : Memory}
    (checked : CheckedOriginalNormalizedStaticRelatedWrite context state writes
      afterWorld afterMemory) :
    checked.requirement.Holds context afterWorld afterMemory :=
  checked.relatedUpdate

theorem exactEmptyInventoryChecks : noNormalizedWritesChecked [] = true := by
  decide

theorem nonemptyInventoryDoesNotCheck :
    noNormalizedWritesChecked stackWrites = false := by decide

#print axioms stackAffineChecksExactly
#print axioms dynamicAffineChecksWithOrigin
#print axioms missingRangeFailsClosed
#print axioms checkedStackAccessProducesRangeWitness
#print axioms checkedDynamicAccessProducesRangeWitness
#print axioms checkedRuntimeAccessAvoidsProtectedStatic
#print axioms staticSlotRequiresRelatedPostUpdate
#print axioms exactEmptyInventoryChecks
#print axioms nonemptyInventoryDoesNotCheck

end StageA.OriginalRuntimeMemoryAccessCheckerKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalRuntimeMemoryAccessCheckerKernelTests(unittest.TestCase):
    def test_runtime_memory_access_certificates_are_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalRuntimeMemoryAccessChecker.lean"
        ).read_text(encoding="utf-8")
        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
            r"authorizing_lean_terms",
            r"status\s*==",
            r"\|\s*unknown\b",
        ):
            self.assertNotRegex(module_text, forbidden)
        for required in (
            "OriginalNormalizedWriteReference",
            "OriginalRuntimeAddressCertificate",
            "originalNormalizedRuntimeWriteChecked_sound",
            "CheckedOriginalNormalizedRuntimeWrite",
            "CheckedOriginalNormalizedStaticRelatedWrite",
            "noNormalizedWritesChecked_sound",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalRuntimeMemoryAccessChecker",
            )
            (stage_a / "OriginalRuntimeMemoryAccessCheckerKernel.lean").write_text(
                _KERNEL, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="OriginalRuntimeMemoryAccessCheckerKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 7, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
