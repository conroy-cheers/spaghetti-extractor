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


class StageARelationalInterpreterKernelSummaryTests(unittest.TestCase):
    def test_proof_core_exposes_all_fail_closed_summary_fields(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelSummary.lean"
        ).read_text(encoding="utf-8")

        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        for required in (
            "structure ProgramLookupTemplateParameters",
            "def programLookupTemplateBytes",
            "def programLookupTemplateBlockShapes",
            "def reflectProgramLookupTemplate?",
            "def programLookupTemplateChecked",
            "structure ProgramLookupTemplateCertificate",
            "structure KernelFunctionSummary",
            "candidateParsed",
            "templateCertificate",
            "tableParameterExact",
            "countParameterExact",
            "instructionDecodes",
            "ProgramTableCertificate",
            "structure ProgramLookupLoadedEntry",
            "sourceArgumentLoaded",
            "countLoaded",
            "tableLoaded",
            "frameDisjointFromTable",
            "structure ProgramLookupConcreteEntry",
            "requestRelated",
            "structure ProgramLookupConcreteABI",
            "requestEntry",
            "responseExit",
            "scratchContainsFrame",
            "BinarySearchInvariant",
            "view.low sourceRva state <= view.high sourceRva state",
            "view.high sourceRva state <= transferCount",
            "BinarySearchRank",
            "view.high sourceRva state - view.low sourceRva state",
            "rankDecreases",
            "inductive ReflectedProgramLookupTrace",
            "reflectedProgramLookupTrace_exists",
            "exactLookupResult",
            "abiReturnRegister",
            "after.registers.get .eax",
            "memoryFrame",
            "programLookupTemplateFrameMemory_agreesOutside",
            "templateChecked",
            "exactReflection",
            "instructionExecution",
            "ExactKernelCFGPath",
            "ProgramLookupTemplateDispatches",
        ):
            self.assertIn(required, source)
        summary_fields = source.split("structure KernelFunctionSummary", 1)[1].split(
            "/-- Sequential execution", 1
        )[0]
        self.assertNotIn("simulate", summary_fields)

    def test_refinement_is_constructed_from_summary_not_status(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelSummary.lean"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "KernelFunctionSummary.programLookupTemplateSimulate", source
        )
        self.assertIn(
            "KernelFunctionSummary.programLookupRefinesUsingTemplate", source
        )
        self.assertIn("KernelOperationRefinesUsing program abi", source)
        self.assertIn(
            "ProgramLookupTemplateCertificate.executionSummary", source
        )
        self.assertIn("ProgramLookupTemplateCertificate.sound", source)
        self.assertIn("ProgramLookupLoadedEntry", source)
        self.assertIn("runKernelBlockConcrete_composes", source)
        self.assertIn("executeInstruction_composes", source)
        self.assertNotIn("stage_b_program_lookup", source)
        self.assertNotIn("GNU", source)
        self.assertNotIn("pending_lean_proof", source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generic_summary_compiles_and_axiom_audit_is_clean(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelSummary"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelSummary"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        self.assertIn(
            "KernelFunctionSummary.programLookupRefinesUsingTemplate",
            result["stdout"],
        )
        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


if __name__ == "__main__":
    unittest.main()
