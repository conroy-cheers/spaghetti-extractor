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


_API_FIXTURE = r"""import StageA.RelationalInternalDirectCallMixedOriginalIntegration

namespace StageA.FiniteDirectCallEvidenceAPIFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.InternalDirectCallMixedOriginalIntegration

noncomputable def derivedFiniteExecution
    {context : StaticProofContext}
    (evidence : CheckedDirectCallFiniteEvidence context)
    (source : RelatedDirectCallSource context evidence.authority.provenance.tree
      evidence.entry) :=
  evidence.finiteReturningExecutionForSource source

def derivedArgumentToStaticSlot
    {context : StaticProofContext}
    (evidence : CheckedDirectCallFiniteEvidence context)
    (actual : ActualDirectCallReturnExecution context
      evidence.authority.provenance.tree evidence.entry
      evidence.operational.originalProgram evidence.operational.candidateProgram) :=
  evidence.argumentToStaticSlot actual

#print axioms derivedFiniteExecution
#print axioms derivedArgumentToStaticSlot

end StageA.FiniteDirectCallEvidenceAPIFixture
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAFiniteDirectCallEvidenceKernelTests(unittest.TestCase):
    def test_operational_and_static_write_exports_compile(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInternalDirectCallMixedOriginalIntegration",
            )
            (stage_a / "FiniteDirectCallEvidenceAPIFixture.lean").write_text(
                _API_FIXTURE, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="FiniteDirectCallEvidenceAPIFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 2, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
