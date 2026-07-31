from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(
    r"depends on axioms: \[([^\]]*)\]", re.MULTILINE
)


def _copy_module_closure(
    source_root: Path, destination: Path, module: str
) -> None:
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


class StageARelationalInterpreterMixedLaunchExactReplayGraphCheckerKernelTests(
    unittest.TestCase
):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_complete_control_inventory_compiles(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        module = (
            "RelationalInterpreterMixedLaunchExactReplayGraphChecker"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, module)
            result = _run_lean_relational(root, bundle=module)

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertIn(
            "checkedExactNativeLaunchControlInventory_supported", output
        )
        self.assertIn(
            "CheckedExactNativeLaunchReplayBundle.controlTargetsCovered",
            output,
        )
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip()
                for item in match.group(1).split(",")
                if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)

    def test_checker_covers_call_target_and_continuation(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterMixedLaunchExactReplayGraphChecker.lean"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "some [targetRva, continuationRva]",
            source,
        )
        for unsupported in (
            ".indirectCall",
            ".indirectJump",
            ".externalCall",
            ".externalJump",
        ):
            self.assertIn(unsupported, source)
        for forbidden in (
            r"\bsorry\b",
            r"\badmit\b",
            r"\baxiom\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
        ):
            self.assertNotRegex(source, forbidden)


if __name__ == "__main__":
    unittest.main()
