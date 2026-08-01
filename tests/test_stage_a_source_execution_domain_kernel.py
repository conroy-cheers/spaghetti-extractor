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
class StageASourceExecutionDomainKernelTests(unittest.TestCase):
    def test_invariant_conversion_requires_root_blocks_and_mapping(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalSourceExecutionDomain.lean"
        ).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"^\s*axiom\b", module_text, re.MULTILINE))
        self.assertNotIn("sorry", module_text)
        self.assertNotIn("unsafe", module_text)
        self.assertNotIn("native_decide", module_text)
        self.assertIn("rootHolds : invariant.holds root", module_text)
        self.assertIn("blocksExcluded : invariant.BlocksExcluded", module_text)
        self.assertIn("rawConcretizable : invariant.RawConcretizable", module_text)
        self.assertIn("CheckedOriginalInvariantFamilyEvidence", module_text)
        self.assertIn("reachabilityProjection", module_text)
        family_definition = re.search(
            r"structure CheckedOriginalInvariantFamilyEvidence\b(.*?)"
            r"\n\n/-- The reachability projection",
            module_text,
            re.DOTALL,
        )
        self.assertIsNotNone(family_definition)
        self.assertNotIn("stepClosed :", family_definition.group(1))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalSourceExecutionDomain",
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalSourceRawEIP",
            )
            (stage_a / "SourceExecutionDomainKernelFixture.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="SourceExecutionDomainKernelFixture",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        inventories = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(inventories), 7, output)
        self.assertTrue(
            all(
                {name.strip() for name in inventory.split(",")}
                == _APPROVED_AXIOMS
                for inventory in inventories
            ),
            output,
        )
        self.assertIn("toCheckedExecutionDomain", output)
        self.assertIn("rawEipSuccessorConcretizable", output)
        self.assertIn("decodedSemanticStepsAdmissible", output)


_KERNEL_FIXTURE = r'''import StageA.RelationalSourceExecutionDomain
import StageA.RelationalSourceRawEIP

namespace StageA.SourceExecutionDomainKernelFixture

open StageA.Relational
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

example {program : DecodedWorldProgram} {root : WorldExecution}
    (invariant : OriginalWorldExecutionInvariant program)
    (rootHolds : invariant.holds root) :
    CheckedExecutionDomain program root :=
  invariant.toCheckedExecutionDomain rootHolds

example {program : DecodedWorldProgram}
    (invariant : OriginalWorldExecutionInvariant program)
    (targetIds : List Nat) (targetIdsUnique : targetIds.Nodup)
    (reachabilityProjection : forall execution,
      invariant.holds execution -> OriginalExecutionReachable targetIds execution)
    (targetRoundTrips : forall targetId,
      targetId ∈ targetIds -> exists eip,
        program.canonicalRawEip? targetId = some eip /\
          program.resolveRawEip eip = some targetId) :
    CheckedOriginalInvariantFamilyEvidence program := {
  invariant := invariant
  targetIds := targetIds
  targetIdsUnique := targetIdsUnique
  reachabilityProjection := reachabilityProjection
  targetRoundTrips := targetRoundTrips
}

example {program : DecodedWorldProgram}
    (evidence : CheckedOriginalInvariantFamilyEvidence program) :
    evidence.invariant.BlocksExcluded :=
  evidence.blocksExcluded

example {program : DecodedWorldProgram}
    (evidence : CheckedOriginalInvariantFamilyEvidence program) :
    evidence.invariant.RawConcretizable :=
  evidence.rawConcretizable

example {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalInvariantFamilyEvidence program)
    (invariantAtLaunch : evidence.invariant.holds root) :
    CheckedExecutionDomain program root :=
  evidence.domainAtLaunch root invariantAtLaunch

example {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalInvariantFamilyEvidence program)
    (invariantAtLaunch : evidence.invariant.holds root)
    (reason : ExecutionBlock) :
    ¬(evidence.domainAtLaunch root invariantAtLaunch).holds (.blocked reason) :=
  (evidence.domainCertificateAtLaunch root invariantAtLaunch).domainBlocksExcluded
    reason

example {program : DecodedWorldProgram} {root : WorldExecution}
    (certificate : OriginalInvariantDomainCertificate program root) :
    forall execution, certificate.domain.holds execution ->
      OriginalExecutionProofOpen execution :=
  certificate.domainProofOpen

example {program : DecodedWorldProgram} {root : WorldExecution}
    (certificate : OriginalInvariantDomainCertificate program root) :
    forall logical raw,
      certificate.domain.holds logical ->
      logical.ConcretizesToRawEip program raw ->
      exists rawNext,
        (program.pe32TransitionSystem.step logical).next.ConcretizesToRawEip
          program rawNext :=
  certificate.rawEipSuccessorConcretizable

example {program : DecodedWorldProgram} {root : WorldExecution}
    (certificate : OriginalInvariantDomainCertificate program root) :
    RawEipLeftStepClosed program root certificate.domain :=
  certificate.rawEipSuccessorConcretizable

example {program : DecodedWorldProgram} {root : WorldExecution}
    (certificate : OriginalInvariantDomainCertificate program root)
    (adequate : program.InstructionSemanticsAdequate) :
    DecodedSemanticStepsAdmissible program certificate.domain :=
  certificate.decodedSemanticStepsAdmissible adequate

#print axioms OriginalWorldExecutionInvariant.toCheckedExecutionDomain
#print axioms OriginalWorldExecutionInvariant.proofOpen_of_blocksExcluded
#print axioms CheckedOriginalInvariantFamilyEvidence.blocksExcluded
#print axioms CheckedOriginalInvariantFamilyEvidence.rawConcretizable
#print axioms CheckedOriginalInvariantFamilyEvidence.domainAtLaunch_holds_iff
#print axioms OriginalInvariantDomainCertificate.rawEipSuccessorConcretizable
#print axioms OriginalInvariantDomainCertificate.decodedSemanticStepsAdmissible

end StageA.SourceExecutionDomainKernelFixture
'''


if __name__ == "__main__":
    unittest.main()
