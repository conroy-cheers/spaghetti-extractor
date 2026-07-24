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


class StageARelationalInterpreterMixedConstructiveSourceClassifierTests(
    unittest.TestCase
):
    def test_layer_is_constructive_exact_and_fail_closed(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterMixedConstructiveSourceClassifier.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "ConstructiveMixedKernelStateFacts",
            "exactOriginalSemanticSourceCoverageChecked",
            "ExactOriginalSemanticSourceCoverage",
            "ExactOriginalSemanticSourceCoverage.source",
            "ExactOriginalSemanticSourceCoverage.sources",
            "ExactOriginalSemanticSourceCoverage.sources_targetIds",
            "lookupProgramRecord_eq_some_of_mem_sourceRva",
            "ExactCandidateKernelEntry",
            "ConstructiveMixedKernelSourceEvidence",
            "ConstructiveMixedKernelSourceRule",
            "ConstructiveMixedKernelSourceRule.sourceTargetId",
            "constructiveSemanticRulesWithLaunch",
            "constructiveSemanticRulesWithLaunch_targetIds",
            "| launch",
            "| semanticTransfer",
            "| externalOperation",
            "| externalBoundary",
            "| returned",
            "| terminated",
            "| matchingFault",
            "ExactOriginalSemanticSource",
            "sourceIsRoot",
            "originalAtSource",
            "candidateAtRoot",
            "candidateAtEntry",
            "candidateAtSource",
            "entryExact",
            "evidence?",
            "constructiveMixedKernelActiveEvidence",
            "uniqueConstructiveMixedKernelActiveEvidence?",
            "constructiveMixedKernelSourceEvidence?",
            "toRelatedSourceCase",
            "constructiveMixedKernelInvariant",
            "ConstructiveMixedKernelStateFacts reachability.targetIds contract",
            ").isSome = true",
            "constructiveMixedKernelInvariant_holds",
            "constructiveMixedKernelSourceClassifier",
            "MixedKernelSourceClassifier",
        ):
            self.assertIn(required, source)

        evidence = source.split(
            "inductive ConstructiveMixedKernelSourceEvidence", 1
        )[1].split(
            "inductive ConstructiveMixedKernelSourceRule", 1
        )[0]
        for forbidden in (
            r"\|\s+blocked\b",
            r"\|\s+unclassified\b",
            r"\|\s+unknown\b",
            r"\|\s+other\b",
        ):
            self.assertNotRegex(evidence, forbidden)

        for forbidden in (
            r"\baxiom\b",
            r"\bsorry\b",
            r"\bnative_decide\b",
            r"\bstatus\b",
            r"\bverdict\b",
            r"\bGNU\b",
            r"\bhello\b",
            r"\bClassical\.choice\b",
        ):
            self.assertNotRegex(source, forbidden)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_layer_compiles_with_only_approved_axioms(self) -> None:
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
                "RelationalInterpreterMixedConstructiveSourceClassifier",
            )
            (
                stage_a
                / "RelationalInterpreterMixedConstructiveSourceClassifierAudit.lean"
            ).write_text(_AUDIT_FIXTURE, encoding="utf-8")
            result = _run_lean_relational(
                root,
                bundle=(
                    "RelationalInterpreterMixedConstructiveSourceClassifierAudit"
                ),
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for declaration in (
            "exactOriginalSemanticSourceCoverageChecked_sourceRva_mem",
            "lookupProgramRecord_eq_some_of_mem_sourceRva",
            "ExactOriginalSemanticSourceCoverage.source",
            "ExactOriginalSemanticSourceCoverage.sources_targetIds",
            "constructiveSemanticRulesWithLaunch_targetIds",
            "ConstructiveMixedKernelSourceRule.evidence?",
            "constructiveMixedKernelSourceEvidence?",
            "ConstructiveMixedKernelSourceEvidence.toRelatedSourceCase",
            "constructiveMixedKernelInvariant_holds",
            "constructiveMixedKernelSourceClassifier",
        ):
            self.assertIn(declaration, output)

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


_AUDIT_FIXTURE = r"""import StageA.RelationalInterpreterMixedConstructiveSourceClassifier

namespace StageA.Relational.InterpreterMixedConstructiveSourceClassifierAudit

open StageA.Relational.InterpreterMixedConstructiveSourceClassifier

#check ConstructiveMixedKernelStateFacts
#check exactOriginalSemanticSourceCoverageChecked
#check ExactOriginalSemanticSourceCoverage
#check ExactOriginalSemanticSourceCoverage.source
#check ExactOriginalSemanticSourceCoverage.sources
#check ExactOriginalSemanticSourceCoverage.sources_targetIds
#check lookupProgramRecord_eq_some_of_mem_sourceRva
#check ExactCandidateKernelEntry
#check ConstructiveMixedKernelSourceEvidence
#check ConstructiveMixedKernelSourceRule
#check ConstructiveMixedKernelSourceRule.sourceTargetId
#check constructiveSemanticRulesWithLaunch
#check constructiveSemanticRulesWithLaunch_targetIds
#check ConstructiveMixedKernelSourceEvidence.launch
#check ConstructiveMixedKernelSourceEvidence.semanticTransfer
#check ConstructiveMixedKernelSourceEvidence.externalOperation
#check ConstructiveMixedKernelSourceEvidence.externalBoundary
#check ConstructiveMixedKernelSourceEvidence.returned
#check ConstructiveMixedKernelSourceEvidence.terminated
#check ConstructiveMixedKernelSourceEvidence.matchingFault
#check ConstructiveMixedKernelSourceRule.evidence?
#check constructiveMixedKernelActiveEvidence
#check uniqueConstructiveMixedKernelActiveEvidence?
#check constructiveMixedKernelSourceEvidence?
#check ConstructiveMixedKernelSourceEvidence.toRelatedSourceCase
#check constructiveMixedKernelInvariant
#check constructiveMixedKernelInvariant_holds
#check constructiveMixedKernelSourceClassifier

#print axioms ConstructiveMixedKernelSourceRule.evidence?
#print axioms exactOriginalSemanticSourceCoverageChecked_sourceRva_mem
#print axioms lookupProgramRecord_eq_some_of_mem_sourceRva
#print axioms ExactOriginalSemanticSourceCoverage.source
#print axioms ExactOriginalSemanticSourceCoverage.sources_targetIds
#print axioms constructiveSemanticRulesWithLaunch_targetIds
#print axioms constructiveMixedKernelSourceEvidence?
#print axioms ConstructiveMixedKernelSourceEvidence.toRelatedSourceCase
#print axioms constructiveMixedKernelInvariant_holds
#print axioms constructiveMixedKernelSourceClassifier

end StageA.Relational.InterpreterMixedConstructiveSourceClassifierAudit
"""


if __name__ == "__main__":
    unittest.main()
