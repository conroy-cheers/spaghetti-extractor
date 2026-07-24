from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.stack_fixed_code_pointer import (
    LeanStackAdjustment,
    LeanStackWindow,
    StackFixedCodePointerClaimSpec,
    StackFixedCodePointerGenerationError,
    StackFixedCodePointerLeanBinding,
    stack_fixed_code_pointer_source,
)


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


_FIXTURE = r"""import StageA.RelationalStackFixedCodePointer

namespace StageA.StackFixedCodePointerFixture

open StageA.Formal StageA.Relational

def fixturePe : PE32 := {
  bytes := .empty
  peOffset := 0
  entrypointRva := 4096
  imageBase := 4194304
  sectionAlignment := 4096
  fileAlignment := 512
  sizeOfImage := 12288
  sizeOfHeaders := 512
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}

def fixtureCodeMap : StaticCodeMap := {
  entries := .leaf [
    { id := 0, originalRva := 4096, candidateRva := 4352 },
    { id := 1, originalRva := 4608, candidateRva := 4608 }
  ]
  originalAddresses := .leaf [
    { targetId := 0, kind := .canonical },
    { targetId := 1, kind := .canonical }
  ]
  candidateAddresses := .leaf [
    { targetId := 0, kind := .canonical },
    { targetId := 1, kind := .canonical }
  ]
}

def fixtureContext : StaticProofContext := {
  originalPe := fixturePe
  candidatePe := fixturePe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap := fixtureCodeMap
  dataMap := { entries := #[], originalOrder := [], candidateOrder := [] }
  roots := []
  observations := {}
}

def sourceWindow : StackWindowPair := {
  rangeId := 4
  originalRegister := .esp
  candidateRegister := .ebp
  bytesBelow := 16
  bytesAbove := 64
}

def originalTarget : Expr :=
  .read32 ((StackAdjustment.add 32).expression .esp)

def candidateTarget : Expr :=
  .read32 ((StackAdjustment.add 32).expression .ebp)

def registers : Registers Expr := initialSymbolic.registers

def originalBehavior : NormalizedSymbolicBehavior := {
  registers
  x87 := initialSymbolicX87
  writes := [
    ((StackAdjustment.identity).expression .esp, .constant 17),
    ((StackAdjustment.add 8).expression .esp, .constant 34)
  ]
  flags := none
  outcome := .indirectCall originalTarget 1
}

def candidateBehavior : NormalizedSymbolicBehavior := {
  registers
  x87 := initialSymbolicX87
  writes := [
    ((StackAdjustment.add 4).expression .ebp, .constant 51)
  ]
  flags := none
  outcome := .indirectCall candidateTarget 1
}

def targetPredicate : PairedStatePredicate := {
  original := .equal originalTarget (.constant 4198400)
  candidate := .equal candidateTarget (.constant 4198656)
}

def sourceInvariant : StateInvariant := {
  registerRelations := []
  stackWindows := [sourceWindow]
  predicates := [targetPredicate]
}

def positiveClaim : StackSlotFixedCodePointerIndirectCallClaim := {
  stackRead := { window := sourceWindow, adjustment := .add 32 }
  targetId := 0
  originalTargetAddress := 4198400
  candidateTargetAddress := 4198656
  continuationTargetId := 1
  writes := {
    original := [.identity, .add 8]
    candidate := [.add 4]
  }
}

example : positiveClaim.targetPredicate = targetPredicate := by decide +kernel

example : positiveClaim.checked fixtureContext sourceInvariant originalBehavior
    candidateBehavior = true := by decide +kernel

example (world : RelationalWorld) (original candidate : MachineState)
    (related : StateRel fixtureContext world sourceInvariant original candidate) :
    StackSlotFixedCodePointerIndirectCallEvidence fixtureContext world
      originalBehavior candidateBehavior positiveClaim original candidate :=
  positiveClaim.evidence_of_checked fixtureContext world sourceInvariant
    originalBehavior candidateBehavior (by decide +kernel) original candidate related

def missingPredicateInvariant : StateInvariant := {
  registerRelations := []
  stackWindows := [sourceWindow]
}

example : positiveClaim.checked fixtureContext missingPredicateInvariant
    originalBehavior candidateBehavior = false := by decide +kernel

def outsideClaim : StackSlotFixedCodePointerIndirectCallClaim := {
  positiveClaim with stackRead := { window := sourceWindow, adjustment := .add 64 }
}

def outsideOriginalTarget : Expr :=
  .read32 ((StackAdjustment.add 64).expression .esp)

def outsideCandidateTarget : Expr :=
  .read32 ((StackAdjustment.add 64).expression .ebp)

def outsideOriginalBehavior : NormalizedSymbolicBehavior := {
  originalBehavior with outcome := .indirectCall outsideOriginalTarget 1
}

def outsideCandidateBehavior : NormalizedSymbolicBehavior := {
  candidateBehavior with outcome := .indirectCall outsideCandidateTarget 1
}

def outsideInvariant : StateInvariant := {
  registerRelations := []
  stackWindows := [sourceWindow]
  predicates := [outsideClaim.targetPredicate]
}

example : outsideClaim.checked fixtureContext outsideInvariant outsideOriginalBehavior
    outsideCandidateBehavior = false := by decide +kernel

def missingTargetClaim : StackSlotFixedCodePointerIndirectCallClaim := {
  positiveClaim with targetId := 2
}

def missingTargetInvariant : StateInvariant := {
  registerRelations := []
  stackWindows := [sourceWindow]
  predicates := [missingTargetClaim.targetPredicate]
}

example : missingTargetClaim.checked fixtureContext missingTargetInvariant
    originalBehavior candidateBehavior = false := by decide +kernel

def overlappingOriginalBehavior : NormalizedSymbolicBehavior := {
  originalBehavior with writes := [
    ((StackAdjustment.add 32).expression .esp, .constant 17)
  ]
}

def overlappingCandidateBehavior : NormalizedSymbolicBehavior := {
  candidateBehavior with writes := [
    ((StackAdjustment.add 32).expression .ebp, .constant 51)
  ]
}

def overlappingClaim : StackSlotFixedCodePointerIndirectCallClaim := {
  positiveClaim with writes := {
    original := [.add 32]
    candidate := [.add 32]
  }
}

example : overlappingClaim.checked fixtureContext sourceInvariant
    overlappingOriginalBehavior overlappingCandidateBehavior = false := by
  decide +kernel

def omittedWriteClaim : StackSlotFixedCodePointerIndirectCallClaim := {
  positiveClaim with writes := { original := [], candidate := [] }
}

example : omittedWriteClaim.checked fixtureContext sourceInvariant originalBehavior
    candidateBehavior = false := by decide +kernel

def wrongContinuationCandidate : NormalizedSymbolicBehavior := {
  candidateBehavior with outcome := .indirectCall candidateTarget 0
}

example : positiveClaim.checked fixtureContext sourceInvariant originalBehavior
    wrongContinuationCandidate = false := by decide +kernel

def missingContinuationClaim : StackSlotFixedCodePointerIndirectCallClaim := {
  positiveClaim with continuationTargetId := 3
}

def missingContinuationOriginal : NormalizedSymbolicBehavior := {
  originalBehavior with outcome := .indirectCall originalTarget 3
}

def missingContinuationCandidate : NormalizedSymbolicBehavior := {
  candidateBehavior with outcome := .indirectCall candidateTarget 3
}

example : missingContinuationClaim.checked fixtureContext sourceInvariant
    missingContinuationOriginal missingContinuationCandidate = false := by
  decide +kernel

end StageA.StackFixedCodePointerFixture
"""


class StageAStackFixedCodePointerTests(unittest.TestCase):
    def _spec(self) -> StackFixedCodePointerClaimSpec:
        return StackFixedCodePointerClaimSpec(
            definition_name="generatedClaim",
            window=LeanStackWindow(
                range_id=4,
                original_register="esp",
                candidate_register="ebp",
                bytes_below=16,
                bytes_above=64,
            ),
            read_adjustment=LeanStackAdjustment("add", 32),
            target_id=0,
            original_target_address=0x401000,
            candidate_target_address=0x401100,
            continuation_target_id=1,
            original_writes=(
                LeanStackAdjustment("identity"),
                LeanStackAdjustment("add", 8),
            ),
            candidate_writes=(LeanStackAdjustment("add", 4),),
        )

    def _binding(self) -> StackFixedCodePointerLeanBinding:
        return StackFixedCodePointerLeanBinding(
            dependency_module="StageA.StackFixedCodePointerFixture",
            namespace="StageA.Generated.StackFixedCodePointer",
            context_name="StageA.StackFixedCodePointerFixture.fixtureContext",
            source_invariant_name=(
                "StageA.StackFixedCodePointerFixture.sourceInvariant"
            ),
            original_behavior_name=(
                "StageA.StackFixedCodePointerFixture.originalBehavior"
            ),
            candidate_behavior_name=(
                "StageA.StackFixedCodePointerFixture.candidateBehavior"
            ),
        )

    def test_emitter_has_no_status_authority_or_unchecked_escape(self) -> None:
        source = stack_fixed_code_pointer_source(self._spec(), self._binding())
        self.assertIn("generatedClaim.checked", source)
        self.assertIn("decide +kernel", source)
        self.assertNotIn("acceptance_authority", source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_malformed_finite_specs_fail_before_emission(self) -> None:
        with self.assertRaisesRegex(
            StackFixedCodePointerGenerationError, "identity.*amount zero"
        ):
            LeanStackAdjustment("identity", 4).lean()
        with self.assertRaisesRegex(
            StackFixedCodePointerGenerationError, "IA-32.*register"
        ):
            LeanStackWindow(0, "rip", "esp", 0, 4).lean()
        bad = StackFixedCodePointerClaimSpec(
            **{**self._spec().__dict__, "original_target_address": 2**32}
        )
        with self.assertRaisesRegex(
            StackFixedCodePointerGenerationError, "unsigned PE32"
        ):
            bad.lean()

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_positive_and_fail_closed_claims_compile_in_lean(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
        )
        kernel_source = (
            source_root / "RelationalStackFixedCodePointer.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", kernel_source), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalStackFixedCodePointer"
            )
            (stage_a / "StackFixedCodePointerFixture.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            (stage_a / "GeneratedStackFixedCodePointer.lean").write_text(
                stack_fixed_code_pointer_source(self._spec(), self._binding()),
                encoding="utf-8",
            )
            (stage_a / "StackFixedCodePointerAudit.lean").write_text(
                """import StageA.GeneratedStackFixedCodePointer

namespace StageA.StackFixedCodePointerAudit

example : StageA.Generated.StackFixedCodePointer.generatedClaim.checked
    StageA.StackFixedCodePointerFixture.fixtureContext
    StageA.StackFixedCodePointerFixture.sourceInvariant
    StageA.StackFixedCodePointerFixture.originalBehavior
    StageA.StackFixedCodePointerFixture.candidateBehavior = true :=
  StageA.Generated.StackFixedCodePointer.generatedClaimChecked

#print axioms
  StageA.Relational.StackSlotFixedCodePointerIndirectCallClaim.evidence_of_checked

end StageA.StackFixedCodePointerAudit
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="StackFixedCodePointerAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 1, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
