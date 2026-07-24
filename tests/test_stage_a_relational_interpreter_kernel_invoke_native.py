from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(r"depends on axioms: \[([^\]]*)\]", re.MULTILINE)


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


class StageARelationalInterpreterKernelInvokeNativeTests(unittest.TestCase):
    source = (
        Path(__file__).parents[1]
        / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelInvokeNative.lean"
    )

    def test_bridge_derives_all_arm_paths_without_final_assertion_fields(self) -> None:
        source = self.source.read_text(encoding="utf-8")
        for required in (
            "ExactComputedNativeWorldSegment.path",
            "runFunctionSubroutine_of_operation_refinement",
            "internalKernelDispatches_of_runFunctionRefinement",
            "exactExternalInstructionStep",
            "candidate.environment.action",
            "InvokeCallNativeExternalArmExecution.nativeWorldDispatches",
            "inventoryChecked : inventory.checked program candidate.pe",
            "resolverStepOne : resolverStep.fuel = 1",
            "InvokeCallNativeIndirectArmExecution.nativeWorldDispatches",
            "indirectKernelDispatches_of_runFunctionRefinement",
            "NativeWorldKernelDispatches",
        ):
            self.assertIn(required, source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        arm = source.split("structure InvokeCallNativeArmExecution", 1)[1].split(
            "theorem InvokeCallNativeArmExecution.nativeWorldDispatches", 1
        )[0]
        for forbidden in ("finalPath", "responseRelated", "memoryFrame"):
            self.assertNotIn(forbidden, arm)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_native_bridge_compiles_with_only_approved_axioms(self) -> None:
        source_root = self.source.parent
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelInvokeNative"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelInvokeNative"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


if __name__ == "__main__":
    unittest.main()
