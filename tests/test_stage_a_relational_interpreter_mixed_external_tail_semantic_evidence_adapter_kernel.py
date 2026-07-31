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
_MODULE = "RelationalInterpreterMixedExternalTailSemanticEvidenceAdapter"


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


class StageAMixedExternalTailSemanticEvidenceAdapterKernelTests(
    unittest.TestCase
):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_adapter_compiles_with_only_approved_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, _MODULE)
            result = _run_lean_relational(root, bundle=_MODULE)

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("native_decide.ax", output)
        for declaration in (
            "externalTailSemanticCallTarget?",
            "checkedExternalTailEvent",
            "CheckedExternalTailOriginalExecution.replay",
            "CheckedExternalTailOriginalExecution.pathShape",
            "checkedExternalTailExecutionForSource",
            "CheckedExternalTailMixedSemanticOperationInput.toEvidence",
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

    def test_source_rejects_submitted_execution_authority(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / f"{_MODULE}.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "CheckedExternalTailStaticBinding",
            "transferOutcome",
            "pathTerminal",
            "machineImportCallContractById?",
            "ExactExternalTailOperationalCompleteness",
            "CheckedOriginalSemanticOperationPath.one",
            "resolveExternalCallSite",
            "resumeWorldExecution before.callbacks",
            "CheckedResponseExternalTrace",
            "candidateBefore.machine? = some candidateMachine",
            "CheckedCandidateKernelDispatchAtBefore",
            "CheckedMixedKernelObservations",
            "semanticResultAtOriginalExit",
            "input.afterRelated",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "submittedPath",
            "submittedEndpoint",
            "submittedObservations",
            "submittedStatus",
            "submittedCount",
            "native_decide",
            "sorry",
            "axiom ",
            "GNU",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
