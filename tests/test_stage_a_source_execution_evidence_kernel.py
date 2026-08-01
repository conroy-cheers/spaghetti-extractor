from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
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
class StageASourceExecutionEvidenceKernelTests(unittest.TestCase):
    def test_one_sided_evidence_composes_into_source_domain(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalSourceExecutionDomain.lean"
        ).read_text(encoding="utf-8")
        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"MixedExecutionInvariant",
            r"candidate[A-Z]",
        ):
            self.assertNotRegex(module_text, forbidden)
        for required in (
            "structure CheckedOriginalReachabilityEvidence",
            "targetRoundTrips : forall targetId",
            "CheckedOriginalReachabilityEvidence.withRefinements",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalSourceExecutionDomain"
            )
            (stage_a / "SourceExecutionEvidenceKernelFixture.lean").write_text(
                _KERNEL, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="SourceExecutionEvidenceKernelFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        inventories = _AXIOMS.findall(output)
        self.assertEqual(len(inventories), 4, output)
        self.assertTrue(
            all(
                {name.strip() for name in inventory.split(",")}
                == _APPROVED_AXIOMS
                for inventory in inventories
            ),
            output,
        )


_KERNEL = r'''import StageA.RelationalSourceExecutionDomain

namespace StageA.SourceExecutionEvidenceKernelFixture

open StageA.Relational
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.SourceWorld

def rooted
    {program : DecodedWorldProgram} {root : WorldExecution}
    (invariant : OriginalWorldExecutionInvariant program)
    (rootHolds : invariant.holds root) :
    RootedOriginalWorldExecutionInvariant program root := {
  invariant := invariant
  rootHolds := rootHolds
}

theorem combinedEvidencePreservesEveryStep
    {program : DecodedWorldProgram} {root before : WorldExecution}
    (evidence : CheckedOriginalExecutionEvidence program root)
    (holds : evidence.invariant.holds before) :
    evidence.invariant.holds
      (program.pe32TransitionSystem.step before).next :=
  evidence.invariant.stepClosed before holds

theorem combinedEvidenceProjectsRefinement
    {program : DecodedWorldProgram} {root execution : WorldExecution}
    (evidence : CheckedOriginalExecutionEvidence program root)
    (refinement : RootedOriginalWorldExecutionInvariant program root)
    (member : refinement ∈ evidence.refinements)
    (holds : evidence.invariant.holds execution) :
    refinement.invariant.holds execution :=
  evidence.refinementHolds holds refinement member

theorem combinedEvidenceBuildsCompleteDomainInput
    {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalExecutionEvidence program root) :
    evidence.toDomainCertificate.invariant.holds root :=
  evidence.toDomainCertificate.rootHolds

theorem rootedReachabilityBuildsCompleteDomainInput
    {program : DecodedWorldProgram} {root : WorldExecution}
    (reachability : CheckedOriginalReachabilityEvidence program root)
    (refinements : List
      (RootedOriginalWorldExecutionInvariant program root)) :
    (reachability.withRefinements refinements).toDomainCertificate.invariant.holds
      root :=
  (reachability.withRefinements refinements).toDomainCertificate.rootHolds

#print axioms combinedEvidencePreservesEveryStep
#print axioms combinedEvidenceProjectsRefinement
#print axioms combinedEvidenceBuildsCompleteDomainInput
#print axioms rootedReachabilityBuildsCompleteDomainInput

end StageA.SourceExecutionEvidenceKernelFixture
'''


if __name__ == "__main__":
    unittest.main()
