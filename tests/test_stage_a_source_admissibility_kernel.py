from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound"}


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
class StageASourceAdmissibilityKernelTests(unittest.TestCase):
    def test_checked_domain_excluding_blocks_is_admissible(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (source_root / "RelationalSourceAdmissibility.lean").read_text(
            encoding="utf-8"
        )
        self.assertIsNone(re.search(r"^\s*axiom\b", module_text, re.MULTILINE))
        self.assertNotIn("sorry", module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalSourceAdmissibility",
            )
            (stage_a / "SourceAdmissibilityKernelFixture.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="SourceAdmissibilityKernelFixture",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        inventories = _AXIOM_REPORT.findall(output)
        self.assertEqual(len(inventories), 2, output)
        self.assertTrue(
            all(
                {name.strip() for name in inventory.split(",")}
                == _APPROVED_AXIOMS
                for inventory in inventories
            ),
            output,
        )
        self.assertIn("stepWorldExecution_proofBlocked_implies_blocked", output)
        self.assertIn(
            "CheckedExecutionDomain.decodedSemanticStepsAdmissible_of_blocksExcluded",
            output,
        )


_KERNEL_FIXTURE = r"""import StageA.RelationalSourceAdmissibility

namespace StageA.SourceAdmissibilityKernelFixture

open StageA.Relational
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

example (program : DecodedWorldProgram) (execution : WorldExecution)
    (reason : ExecutionBlock)
    (observed : (stepWorldExecution program execution).observation =
      some (.proofBlocked reason)) :
    (stepWorldExecution program execution).next = .blocked reason := by
  exact stepWorldExecution_proofBlocked_implies_blocked program execution reason observed

example {program : DecodedWorldProgram} {root : WorldExecution}
    (domain : CheckedExecutionDomain program root)
    (adequate : program.InstructionSemanticsAdequate)
    (blocksExcluded : forall reason, ¬ domain.holds (.blocked reason)) :
    DecodedSemanticStepsAdmissible program domain := by
  exact domain.decodedSemanticStepsAdmissible_of_blocksExcluded adequate blocksExcluded

#print axioms stepWorldExecution_proofBlocked_implies_blocked
#print axioms CheckedExecutionDomain.decodedSemanticStepsAdmissible_of_blocksExcluded

end StageA.SourceAdmissibilityKernelFixture
"""


if __name__ == "__main__":
    unittest.main()
