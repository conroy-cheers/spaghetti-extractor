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
            "CheckedWorldKernelOperationRefinementFamily",
            "EnvironmentParametricMixedComponentPremises",
            "MixedEnvironmentPairRefines",
            "CanonicalMixedLaunchPrefixEndpoint",
            "CanonicalOriginalMixedLaunchExecution",
            "CanonicalCandidateMixedLaunchExecution",
            "canonicalMixedLaunchPrefixPaths_nonempty",
            "canonicalMixedLaunchPrefixCertificate",
            "classifier",
            "launchWrapperRefines",
            "launchPrefixEndpoint",
            "semanticChunkFactory",
            "externalOperationChunkFactory",
            "externalBoundaryChunk",
            "candidateLaunchCallsExact",
            "componentCases",
            "environmentComposition",
            "environmentLaunchPrefix",
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

        endpoint = source.split(
            "structure CanonicalMixedLaunchPrefixEndpoint", 1
        )[1].split(
            "theorem canonicalMixedLaunchPrefixPaths_nonempty", 1
        )[0]
        for required in (
            "afterRelated : forall",
            "invariant.holds",
            "MixedLaunchStatesRelated",
            "contract.runtimeStatesRelated",
            "result.observations = []",
        ):
            self.assertIn(required, endpoint)
        for redundant in (
            "originalPath",
            "MixedKernelChunkPaths",
            "status",
        ):
            self.assertNotIn(redundant, endpoint)

        launch_prefix = universal.split("launchPrefixEndpoint :", 1)[1].split(
            "semanticChunkFactory :", 1
        )[0]
        self.assertIn(
            "CanonicalMixedLaunchPrefixEndpoint",
            launch_prefix,
        )
        self.assertIn("launchWrapperRefines", launch_prefix)
        self.assertNotIn("MixedKernelChunkPaths", launch_prefix)
        self.assertNotIn("rootsRelated", universal)
        self.assertNotIn("launchChunk", universal)
        self.assertIn(
            "operations : CheckedWorldKernelOperationRefinementFamily",
            universal,
        )
        self.assertEqual(universal.count("candidateWorldExact"), 2)
        self.assertEqual(
            universal.count("operations.dispatchFamily candidateWorld"), 4
        )

        component = universal.split(
            "EnvironmentParametricMixedComponentPremises.componentCases", 1
        )[1].split(
            "EnvironmentParametricMixedComponentPremises.environmentComposition",
            1,
        )[0]
        self.assertEqual(
            component.count(
                "exactNativeRunningWorldAtRva candidateAtEntry"
            ),
            2,
        )
        self.assertEqual(
            component.count(
                "operations.combinedRefines candidateRunning.world operation"
            ),
            2,
        )
        self.assertNotIn("generatedLaunchWorld", component)

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
            "CheckedWorldKernelOperationRefinementFamily.combinedRefines",
            "EnvironmentParametricMixedComponentPremises.componentCases",
            "EnvironmentParametricMixedComponentPremises.environmentComposition",
            "EnvironmentParametricMixedComponentPremises.environmentLaunchPrefix",
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
#check CheckedWorldKernelOperationRefinementFamily
#check CheckedWorldKernelOperationRefinementFamily.dispatchFamily
#check CheckedWorldKernelOperationRefinementFamily.refines
#check CheckedWorldKernelOperationRefinementFamily.combinedRefines
#check CanonicalMixedLaunchPrefixEndpoint
#check canonicalMixedLaunchPrefixPaths_nonempty
#check canonicalMixedLaunchPrefixCertificate
#check EnvironmentParametricMixedComponentPremises
#check EnvironmentParametricMixedComponentPremises.componentCases
#check EnvironmentParametricMixedComponentPremises.environmentComposition
#check EnvironmentParametricMixedComponentPremises.environmentLaunchPrefix
#check EnvironmentParametricMixedComponentPremises.environmentCompositions

#print axioms CheckedKernelOperationRefinementFamily.refines
#print axioms CheckedKernelOperationRefinementFamily.combinedRefines
#print axioms CheckedWorldKernelOperationRefinementFamily.combinedRefines
#print axioms canonicalMixedLaunchPrefixPaths_nonempty
#print axioms canonicalMixedLaunchPrefixCertificate
#print axioms EnvironmentParametricMixedComponentPremises.componentCases
#print axioms EnvironmentParametricMixedComponentPremises.environmentComposition
#print axioms EnvironmentParametricMixedComponentPremises.environmentLaunchPrefix
#print axioms EnvironmentParametricMixedComponentPremises.environmentCompositions

end StageA.Relational.InterpreterMixedComponentCompositionAudit
"""


if __name__ == "__main__":
    unittest.main()
