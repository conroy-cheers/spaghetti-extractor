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


class StageARelationalInterpreterMixedComponentCompositionTests(
    unittest.TestCase
):
    def test_layer_is_environment_parametric_and_fail_closed(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterMixedComponentComposition.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "CheckedKernelOperationRefinementFamily",
            "programLookupRefines",
            "interpreterStepRefines",
            "runFunctionRefines",
            "invokeCallRefines",
            "dispatchFamily",
            "combinedRefines",
            "EnvironmentParametricMixedComponentPremises",
            "MixedEnvironmentPairRefines",
            "CanonicalMixedLaunchChunkRemainingPremises",
            "CanonicalMixedLaunchComponentPremises",
            "CanonicalOriginalMixedLaunchExecution",
            "CanonicalCandidateMixedLaunchExecution",
            "classifier",
            "launchWrapperRefines",
            "launchChunk",
            "semanticChunkFactory",
            "externalOperationChunkFactory",
            "externalBoundaryChunk",
            "candidateLaunchCallsExact",
            "rootsRelated",
            "componentCases",
            "environmentComposition",
            "environmentCompositions",
        ):
            self.assertIn(required, source)

        for forbidden in (
            r"\bstatus\b",
            r"\bverdict\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\badmit\b",
            r"\ballStatesRefine\b",
            r"\bGNU\b",
            r"\bhello\b",
        ):
            self.assertNotRegex(source, forbidden)

        universal = source.split(
            "structure EnvironmentParametricMixedComponentPremises", 1
        )[1]
        self.assertIn(
            "forall originalEnvironment candidateEnvironment", universal
        )
        self.assertGreaterEqual(universal.count("environmentsRefine"), 7)

        remaining = source.split(
            "structure CanonicalMixedLaunchChunkRemainingPremises", 1
        )[1].split(
            "structure CanonicalMixedLaunchComponentPremises", 1
        )[0]
        for required in (
            "originalAfter : WorldExecution",
            "originalPath : NonemptyRelatedPath",
            "afterRelated : invariant.holds",
        ):
            self.assertIn(required, remaining)
        for redundant in (
            "candidatePath",
            "candidateObservations",
            "MixedKernelChunkPaths",
            "status",
        ):
            self.assertNotIn(redundant, remaining)

        launch_chunk = universal.split("launchChunk :", 1)[1].split(
            "semanticChunkFactory :", 1
        )[0]
        self.assertIn(
            "beforeRelated : invariant.holds originalBefore candidateBefore",
            launch_chunk,
        )
        self.assertIn("CanonicalMixedLaunchComponentPremises", launch_chunk)
        self.assertNotIn("MixedKernelChunkPaths", launch_chunk)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_layer_compiles_and_has_only_approved_axioms(self) -> None:
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
                "RelationalInterpreterMixedComponentComposition",
            )
            (
                stage_a
                / "RelationalInterpreterMixedComponentCompositionAudit.lean"
            ).write_text(_AUDIT_FIXTURE, encoding="utf-8")
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterMixedComponentCompositionAudit",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for theorem in (
            "CheckedKernelOperationRefinementFamily.refines",
            "CheckedKernelOperationRefinementFamily.combinedRefines",
            "EnvironmentParametricMixedComponentPremises.componentCases",
            "EnvironmentParametricMixedComponentPremises.environmentComposition",
            "EnvironmentParametricMixedComponentPremises.environmentCompositions",
        ):
            self.assertIn(theorem, output)

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


_AUDIT_FIXTURE = r"""import StageA.RelationalInterpreterMixedComponentComposition

namespace StageA.Relational.InterpreterMixedComponentCompositionAudit

open StageA.Relational.InterpreterMixedComponentComposition

#check CheckedKernelOperationRefinementFamily
#check CheckedKernelOperationRefinementFamily.dispatchFamily
#check CheckedKernelOperationRefinementFamily.refines
#check CheckedKernelOperationRefinementFamily.combinedRefines
#check CanonicalMixedLaunchChunkRemainingPremises
#check CanonicalMixedLaunchComponentPremises
#check CanonicalMixedLaunchWrapperRefinement.launchChunk_nonempty
#check CanonicalMixedLaunchWrapperRefinement.launchChunk
#check EnvironmentParametricMixedComponentPremises
#check EnvironmentParametricMixedComponentPremises.componentCases
#check EnvironmentParametricMixedComponentPremises.environmentComposition
#check EnvironmentParametricMixedComponentPremises.environmentCompositions

#print axioms CheckedKernelOperationRefinementFamily.refines
#print axioms CheckedKernelOperationRefinementFamily.combinedRefines
#print axioms CanonicalMixedLaunchWrapperRefinement.launchChunk_nonempty
#print axioms CanonicalMixedLaunchWrapperRefinement.launchChunk
#print axioms EnvironmentParametricMixedComponentPremises.componentCases
#print axioms EnvironmentParametricMixedComponentPremises.environmentComposition
#print axioms EnvironmentParametricMixedComponentPremises.environmentCompositions

end StageA.Relational.InterpreterMixedComponentCompositionAudit
"""


if __name__ == "__main__":
    unittest.main()
