from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.identity import (
    RELATIONAL_EXACT_IDENTITY_FORMAT,
    relational_exact_identity_source,
)
from test_stage_a_relational_identity_kernel import _IDENTITY_KERNEL_MODULES


_DIGEST = "0123456789abcdef" * 4


def _artifact() -> dict[str, Any]:
    return {
        "format": RELATIONAL_EXACT_IDENTITY_FORMAT,
        "source_module": "StageA.IdentityWorldFixture",
        "context": "StageA.IdentityWorldFixture.context",
        "launch": "StageA.IdentityWorldFixture.launch",
        "decoded_segment_ids": [0],
        "reachable_segment_ids": [0],
        "mappings_identity": "StageA.IdentityWorldFixture.mappingsIdentity",
        "decoded_segment_ids_bound": (
            "StageA.IdentityWorldFixture.decodedSegmentIdsBound"
        ),
        "pe32_region_semantics_identity": (
            "StageA.IdentityWorldFixture.regionSemanticsIdentity"
        ),
        "pe32_transition_system_identity": (
            "StageA.IdentityWorldFixture.transitionSystemIdentity"
        ),
        "original": {
            "pe_sha256": _DIGEST,
            "pe_bytes": "StageA.IdentityWorldFixture.peBytes",
            "program": "StageA.IdentityWorldFixture.originalProgram",
            "environment": "StageA.IdentityWorldFixture.environment",
            "protocol_environment": (
                "StageA.IdentityWorldFixture.protocolEnvironment"
            ),
        },
        "candidate": {
            "pe_sha256": _DIGEST,
            "pe_bytes": "StageA.IdentityWorldFixture.peBytes",
            "program": "StageA.IdentityWorldFixture.candidateProgram",
            "environment": "StageA.IdentityWorldFixture.environment",
            "protocol_environment": (
                "StageA.IdentityWorldFixture.protocolEnvironment"
            ),
        },
    }


_FIXTURE_SOURCE = """import StageA.RelationalIdentity

namespace StageA.IdentityWorldFixture

open StageA.Formal StageA.Relational

def peBytes : ByteTree := .empty

def pe : PE32 := {
  bytes := peBytes
  peOffset := 0
  entrypointRva := 0
  imageBase := 4194304
  sectionAlignment := 4096
  fileAlignment := 512
  sizeOfImage := 4096
  sizeOfHeaders := 512
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}

def context : StaticProofContext := {
  originalPe := pe
  candidatePe := pe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap := {
    entries := .empty
    originalAddresses := .empty
    candidateAddresses := .empty
  }
  dataMap := {
    entries := #[]
    originalOrder := []
    candidateOrder := []
  }
  roots := []
  observations := {}
}

def region : RegionRelation := {
  id := 0
  original := { start := 0, size := 0 }
  candidate := { start := 0, size := 0 }
  root := true
  inputs := []
  outputs := []
  targets := []
}

def environment : WorldExternalEnvironment := {
  result := fun _ event => { state := event.state, world := event.world }
}

def protocolEnvironment : WorldExternalProtocolEnvironment := {
  action := fun request =>
    .returned { state := request.state, world := request.world }
}

def originalProgram : DecodedWorldProgram := {
  candidate := false
  context
  regions := [region]
  externalCallSites := []
  environment
  protocolEnvironment
}

def candidateProgram : DecodedWorldProgram := {
  candidate := true
  context
  regions := [region]
  externalCallSites := []
  environment
  protocolEnvironment
}

def launch : PE32ConsoleLaunchV2 := {
  rootNodeId := 0
  rootTargetId := 0
  entryNodeId := 0
  entryTargetId := 0
  tlsCallbackNodeIds := []
  tlsCallbackTargetIds := []
  rootInvariant := { registerRelations := [] }
  frameOffsets := []
}

theorem mappingsIdentity : PE32WorldMappingsIdentical context := by
  refine ⟨rfl, rfl, rfl, rfl, ?_, ?_⟩
  · intro target member
    have : False := by
      simpa [context, FiniteIndex.toList] using member
    contradiction
  · intro target member
    have : False := by
      simpa [context] using member
    contradiction

theorem decodedSegmentIdsBound : originalProgram.regions.map (\u00b7.id) = [0] := by
  rfl

theorem originalRegionSemanticsNone (targetId : Nat) (state : MachineState) :
    pe32WorldRegionBehavior originalProgram targetId state = none := by
  simp [pe32WorldRegionBehavior, originalProgram, candidateProgram, regionById,
    region, pe, context, X87.spanStartsWithX87Command,
    X87.decodeSingletonCommand, spanBytes, executePE32SymbolicSpan,
    runPE32SymbolicSpanFuel, Span.stop, initialSymbolic,
    applyMachineImportCallContracts, evalBehavior, normalizeSymbolicBehavior,
    normalizeOutcomeExpr, normalizeCodeTarget]

theorem candidateRegionSemanticsNone (targetId : Nat) (state : MachineState) :
    pe32WorldRegionBehavior candidateProgram targetId state = none := by
  simp [pe32WorldRegionBehavior, originalProgram, candidateProgram, regionById,
    region, pe, context, X87.spanStartsWithX87Command,
    X87.decodeSingletonCommand, spanBytes, executePE32SymbolicSpan,
    runPE32SymbolicSpanFuel, Span.stop, initialSymbolic,
    applyMachineImportCallContracts, evalBehavior, normalizeSymbolicBehavior,
    normalizeOutcomeExpr, normalizeCodeTarget]

theorem regionSemanticsIdentity :
    pe32WorldRegionBehavior originalProgram =
      pe32WorldRegionBehavior candidateProgram := by
  funext targetId state
  rw [originalRegionSemanticsNone, candidateRegionSemanticsNone]

theorem transitionSystemIdentity :
    originalProgram.pe32TransitionSystem = candidateProgram.pe32TransitionSystem := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  congr 1
  funext execution
  cases execution with
  | running targetId state calls eventIndex world =>
      simp only [stepPE32WorldExecution]
      rw [originalRegionSemanticsNone, candidateRegionSemanticsNone]
  | callbackRunning targetId state calls eventIndex world callbacks =>
      simp only [stepPE32WorldExecution]
      rw [originalRegionSemanticsNone, candidateRegionSemanticsNone]
  | awaitingExternal suspension callbacks =>
      simp [stepPE32WorldExecution, stepWorldExternalSuspension,
        originalProgram, candidateProgram, protocolEnvironment]
  | returned state world => rfl
  | terminated world => rfl
  | fault cause => rfl
  | blocked reason => rfl

end StageA.IdentityWorldFixture
"""


class StageARelationalIdentityGenerationTests(unittest.TestCase):
    def test_emits_current_world_intermediate_without_acceptance_claim(self) -> None:
        source = relational_exact_identity_source(_artifact())

        self.assertIn("import StageA.RelationalIdentity", source)
        self.assertIn(
            "def exactIdentityEvidence : ExactPE32WorldIdentityEvidence", source
        )
        self.assertIn("pe32RegionSemanticsIdentical", source)
        self.assertIn("pe32TransitionSystemsIdentical", source)
        self.assertIn("ExactIdentityPE32CheckedFrontier", source)
        self.assertIn("exactIdentityReachableSegmentIds", source)
        self.assertIn("exactIdentityPE32WorldReflexivityIntermediate", source)
        for forbidden in (
            "WholeProgramCertificate",
            "PE32ProgramsObservationallyEquivalent",
            "pe32ProgramsEquivalent",
            "candidatePE32ProgramsEquivalent",
        ):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("status", source.lower())
        self.assertNotIn("jq", source.lower())
        self.assertNotIn("hello", source.lower())
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_empty_decoded_segment_table_cannot_be_labeled_acceptance(self) -> None:
        artifact = _artifact()
        artifact["decoded_segment_ids"] = []
        artifact["reachable_segment_ids"] = []

        with self.assertRaisesRegex(StageAInputError, "non-empty"):
            relational_exact_identity_source(artifact)

    def test_rejects_uncovered_reachable_or_injectable_artifacts(self) -> None:
        cases: list[tuple[str, dict[str, Any], str]] = []

        uncovered = _artifact()
        uncovered["reachable_segment_ids"] = [1]
        cases.append(("uncovered", uncovered, "absent from decoded"))

        duplicate = _artifact()
        duplicate["decoded_segment_ids"] = [0, 0]
        cases.append(("duplicate", duplicate, "duplicates"))

        bad_digest = _artifact()
        bad_digest["candidate"]["pe_sha256"] = "not-a-digest"
        cases.append(("digest", bad_digest, "canonical SHA-256"))

        injection = _artifact()
        injection["pe32_transition_system_identity"] = "proof; axiom forged : True"
        cases.append(("injection", injection, "qualified Lean identifier"))

        python_status = _artifact()
        python_status["status"] = "accepted"
        cases.append(("status", python_status, "unexpected fields: status"))

        for name, artifact, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(StageAInputError, message):
                    relational_exact_identity_source(artifact)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_generated_world_identity_intermediate_is_kernel_checked(self) -> None:
        result = self._run_generated(_artifact())

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_mismatched_hash_is_rejected_by_lean(self) -> None:
        artifact = _artifact()
        artifact["candidate"]["pe_sha256"] = "f" * 64

        result = self._run_generated(artifact)

        self.assertEqual(result["status"], "failed", result)
        output = result["stdout"] + result["stderr"]
        self.assertIn("exactIdentityOriginalPESha256", output)
        self.assertIn("exactIdentityCandidatePESha256", output)

    @staticmethod
    def _run_generated(artifact: dict[str, Any]) -> dict[str, Any]:
        source_root = (
            Path(__file__).parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
        )
        generated = relational_exact_identity_source(artifact)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in _IDENTITY_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean", stage_a / f"{module}.lean"
                )
            (stage_a / "IdentityWorldFixture.lean").write_text(
                _FIXTURE_SOURCE, encoding="utf-8"
            )
            (stage_a / "GeneratedRelationalIdentity.lean").write_text(
                generated, encoding="utf-8"
            )
            return _run_lean_relational(
                root, bundle="GeneratedRelationalIdentity"
            )


if __name__ == "__main__":
    unittest.main()
