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
_MODULE = "RelationalInterpreterMixedDirectCallReplayAdapter"


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


class StageARelationalInterpreterMixedDirectCallReplayAdapterKernelTests(
    unittest.TestCase
):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_exact_summary_replay_adapter_compiles_and_is_audited(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, _MODULE)
            (stage_a / "MixedDirectCallReplayAdapterExamples.lean").write_text(
                _EXAMPLES,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="MixedDirectCallReplayAdapterExamples",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("native_decide.ax", output)
        for declaration in (
            "WorldCallRun.existsRunRelatedStepsExact",
            "ActualDirectCallReturnExecution.originalNonemptyRelatedPath",
            "ActualDirectCallReturnExecution.checkedOriginalReplay",
            "CheckedOriginalDirectCallReplay.cluster",
            "CheckedOriginalDirectCallReplay.pathShape",
            "exactDecodedReplay",
            "retainedEndpointAndObservations",
            "runningOrCallbackRunningShape",
        ):
            self.assertIn(declaration, output)

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip()
                for item in match.group(1).split(",")
                if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


_EXAMPLES = r"""import StageA.RelationalInterpreterMixedDirectCallReplayAdapter

namespace StageA.MixedDirectCallReplayAdapterExamples

open StageA.Relational
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.InterpreterMixedDirectCallReplayAdapter
open StageA.Relational.InterpreterMixedSemanticOperationComponent

theorem exactDecodedReplay
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram) :
    NonemptyRelatedPath originalProgram.pe32TransitionSystem
      actual.source.original.execution actual.originalObservations
      actual.originalExit.execution :=
  ActualDirectCallReturnExecution.originalNonemptyRelatedPath actual

noncomputable def retainedEndpointAndObservations
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram) :
    CheckedOriginalDirectCallReplay actual :=
  ActualDirectCallReturnExecution.checkedOriginalReplay actual

noncomputable def runningOrCallbackRunningShape
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    {actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram}
    (restored : CheckedOriginalDirectCallRuntimeContextRestored actual) :
    CheckedOriginalSemanticOperationPathShape originalProgram
      actual.source.original.execution
        (ActualDirectCallReturnExecution.checkedOriginalReplay actual).path :=
  (ActualDirectCallReturnExecution.checkedOriginalReplay actual).pathShape restored

#print axioms WorldCallRun.existsRunRelatedStepsExact
#print axioms ActualDirectCallReturnExecution.originalNonemptyRelatedPath
#print axioms ActualDirectCallReturnExecution.checkedOriginalReplay
#print axioms CheckedOriginalDirectCallReplay.cluster
#print axioms CheckedOriginalDirectCallReplay.pathShape
#print axioms exactDecodedReplay
#print axioms retainedEndpointAndObservations
#print axioms runningOrCallbackRunningShape

end StageA.MixedDirectCallReplayAdapterExamples
"""


if __name__ == "__main__":
    unittest.main()
