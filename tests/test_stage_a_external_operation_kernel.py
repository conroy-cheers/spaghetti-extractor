from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


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
class StageAExternalOperationKernelTests(unittest.TestCase):
    def test_operation_profile_and_runtime_resolution_are_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        layer = (source_root / "RelationalExternalOperation.lean").read_text(
            encoding="utf-8"
        )
        for marker in ("native_decide", "sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalExternalOperation"
            )
            (stage_a / "ExternalOperationKernel.lean").write_text(
                _KERNEL_SOURCE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="ExternalOperationKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 2, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


_KERNEL_SOURCE = r"""import StageA.RelationalExternalOperation

open StageA.Relational.ExternalOperation

#check Profile.facts_of_checked
#check CheckedTargetResolution.objectTable
#check CheckedTargetResolution.directTable
#check CheckedTargetResolution.targetEvaluation
#check PairedTargetResolution.table
#check PairedTargetResolution.provenance
#check PairedTargetResolution.operationValid
#check EnvironmentRefines.paired
#check CheckedCallBoundary
#check PairedCallBoundary
#print axioms Profile.facts_of_checked
#print axioms CheckedTargetResolution.targetEvaluation
#print axioms PairedTargetResolution.operationValid
"""


if __name__ == "__main__":
    unittest.main()
