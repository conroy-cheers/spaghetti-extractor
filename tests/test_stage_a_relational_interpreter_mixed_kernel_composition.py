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


class StageARelationalInterpreterMixedKernelCompositionTests(unittest.TestCase):
    def test_composition_is_classifier_and_operation_driven(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterMixedKernelComposition.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "ExactOriginalSemanticSource",
            "lookupExact",
            "sourceExact",
            "reachable",
            "MixedKernelRelatedSourceCase",
            "launchDispatch",
            "semanticTransfer",
            "externalOperation",
            "externalBoundary",
            "MixedKernelSourceClassifier",
            "KernelOperationRefinesUsing",
            "AbstractKernelTransition",
            "NonemptyRelatedPath original.pe32TransitionSystem",
            "NonemptyRelatedPath candidate.transitionSystem",
            "CheckedMixedKernelObservations",
            "MixedKernelOperationComponentCertificate.operationApplied",
            "ExactNativeRunningWorldAtRva",
            "exactNativeRunningWorldAtRva",
            "CheckedMixedKernelComponentCases.component",
            "toMixedWorldChunkComposition",
        ):
            self.assertIn(required, source)

        source_case = source.split(
            "inductive MixedKernelRelatedSourceCase", 1
        )[1].split("structure MixedKernelSourceClassifier", 1)[0]
        self.assertNotRegex(source_case, r"\|\s+blocked\b")
        self.assertNotRegex(source_case, r"\|\s+unclassified\b")

        component_cases = source.split(
            "structure CheckedMixedKernelComponentCases", 1
        )[1].split("private def terminalReturnedComponent", 1)[0]
        self.assertIn(
            "dispatches : RelationalWorld -> KernelDispatchRelation",
            component_cases,
        )
        self.assertEqual(component_cases.count("candidateWorldExact"), 2)
        self.assertEqual(
            component_cases.count("(dispatches candidateWorld)"), 2
        )

        component = source.split(
            "def CheckedMixedKernelComponentCases.component", 1
        )[1].split(
            "def CheckedMixedKernelComponentCases.toMixedWorldChunkComposition",
            1,
        )[0]
        self.assertEqual(
            component.count(
                "exactNativeRunningWorldAtRva candidateAtEntry"
            ),
            2,
        )
        self.assertEqual(component.count("candidateRunning.worldExact"), 2)
        self.assertNotIn("generatedLaunchWorld", component)

        external_boundary_chunk = source.split(
            "externalBoundaryChunk :", 1
        )[1].split("private def terminalReturnedComponent", 1)[0]
        self.assertIn(
            "beforeRelated : invariant.holds originalBefore candidateBefore",
            external_boundary_chunk,
        )
        self.assertIn(
            "classifier.classifier.classify originalBefore candidateBefore",
            external_boundary_chunk,
        )
        self.assertIn(
            ".externalBoundary source candidateRva originalAtSource",
            external_boundary_chunk,
        )

        for forbidden in (
            r"\bverdict\b",
            r"\bstatus\b",
            r"\bwholePath\b",
            r"\ballStatesRefine\b",
            r"\bsorry\b",
            r"\bunsafe\b",
        ):
            self.assertNotRegex(source, forbidden)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_composition_compiles_with_only_approved_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedKernelComposition",
            )
            (stage_a / "RelationalInterpreterMixedKernelCompositionAudit.lean").write_text(
                _AUDIT_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterMixedKernelCompositionAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for theorem in (
            "CheckedMixedKernelObservations.related",
            "MixedKernelOperationComponentCertificate.operationApplied",
            "MixedKernelOperationComponentCertificate.toComponent",
            "CheckedMixedKernelComponentCases.component",
            "CheckedMixedKernelComponentCases.toMixedWorldChunkComposition",
        ):
            self.assertIn(theorem, output)

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


_AUDIT_FIXTURE = r"""import StageA.RelationalInterpreterMixedKernelComposition

namespace StageA.Relational.InterpreterMixedKernelCompositionAudit

open StageA.Relational.InterpreterMixedKernelComposition

#check ExactOriginalSemanticSource
#check MixedKernelRelatedSourceCase
#check MixedKernelSourceClassifier
#check ExactNativeRunningWorldAtRva
#check exactNativeRunningWorldAtRva
#check MixedKernelOperationComponentCertificate
#check CheckedMixedKernelComponentCases
#check CheckedMixedKernelComponentCases.component
#check CheckedMixedKernelComponentCases.toMixedWorldChunkComposition

#print axioms CheckedMixedKernelObservations.related
#print axioms MixedKernelOperationComponentCertificate.operationApplied
#print axioms MixedKernelOperationComponentCertificate.toComponent
#print axioms CheckedMixedKernelComponentCases.component
#print axioms CheckedMixedKernelComponentCases.toMixedWorldChunkComposition

end StageA.Relational.InterpreterMixedKernelCompositionAudit
"""


if __name__ == "__main__":
    unittest.main()
