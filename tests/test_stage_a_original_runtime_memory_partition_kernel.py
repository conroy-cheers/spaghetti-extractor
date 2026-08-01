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
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(source.read_text(encoding="utf-8")))


_KERNEL = r'''import StageA.RelationalOriginalRuntimeMemoryPartition

namespace StageA.OriginalRuntimeMemoryPartitionKernel

open StageA.Formal StageA.Relational
open StageA.Relational.OriginalRuntimeMemoryPartition

theorem validWorldSuppliesPartition
    (context : StaticProofContext) (world : RelationalWorld)
    (valid : world.valid context = true) : HoldsIn context world :=
  holdsIn_of_worldValid context world valid

theorem checkedRuntimeWriteAvoidsStaticWord
    {context : StaticProofContext} {world : RelationalWorld}
    {writeAddress wordAddress : Word} {bytes : Nat}
    (partition : HoldsIn context world)
    (access : OriginalRuntimeAccessWitness world writeAddress bytes)
    (wordValid : writableStaticWordInPe context.originalPe wordAddress = true) :
    OriginalAccessAvoidsWord wordAddress writeAddress bytes :=
  access.avoidsWritableStaticWord partition wordValid

theorem internalResumePreservesEverySuspendedPartition
    (context : StaticProofContext)
    (callbacks : List WorldExternalCallbackRuntime)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (active : HoldsIn context world)
    (suspended : SuspendedHold context callbacks) :
    ExecutionHolds context
      (resumeWorldExecution callbacks targetId state calls eventIndex world) :=
  executionHolds_resume context callbacks targetId state calls eventIndex world
    active suspended

#print axioms validWorldSuppliesPartition
#print axioms checkedRuntimeWriteAvoidsStaticWord
#print axioms internalResumePreservesEverySuspendedPartition

end StageA.OriginalRuntimeMemoryPartitionKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalRuntimeMemoryPartitionKernelTests(unittest.TestCase):
    def test_runtime_memory_partition_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalRuntimeMemoryPartition.lean"
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
        ):
            self.assertNotRegex(module_text, forbidden)
        for required in (
            "OriginalByteSpanValid",
            "OriginalRuntimeAccessWitness",
            "OriginalProtectedImageWord",
            "SuspendedHold",
            "ExecutionHolds",
            "executionHolds_callbackEntry",
            "executionHolds_callbackReturn",
            "executionHolds_externalReturn",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalOriginalRuntimeMemoryPartition"
            )
            (stage_a / "OriginalRuntimeMemoryPartitionKernel.lean").write_text(
                _KERNEL, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="OriginalRuntimeMemoryPartitionKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 3, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
