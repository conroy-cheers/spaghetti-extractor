from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.external_tail_static_pointer_slot_composition import (
    ExternalImportIdentity,
    ExternalTailStaticPointerSlotStaticAuthorityBinding,
    external_tail_static_pointer_slot_static_authority_source,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_reachable_static_pointer_slot_kernel import (
    DATA_RVA,
    TEXT_RVA,
    _authority_source,
    _fixture_pe,
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


_API_FIXTURE = r"""import StageA.RelationalExternalTailStaticPointerSlotComposition

namespace StageA.ExternalTailStaticPointerSlotCompositionKernel

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalMixedBridge
open StageA.Relational.ExternalTailStaticPointerSlotComposition
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.ReachableStaticPointerSlot

theorem exactRequestPinsImportAndAbi
    {context : StaticProofContext}
    {originalContext : OriginalDecodedStaticContext}
    {certificate : Certificate}
    {spec : ExternalTailStaticPointerSlotSpec}
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) :
    checked.boundary.contract.imported = spec.imported /\
      checked.boundary.contract.stackArgumentOffsets = spec.stackArgumentOffsets /\
      checked.boundary.contract.stackResultDelta = spec.stackResultDelta /\
      checked.boundary.contract.preservedRegisters = spec.preservedRegisters /\
      checked.boundary.contract.clobberedRegisters = spec.clobberedRegisters /\
      certificate.slotRva = spec.slotRva /\
      checked.frameWrite.canonicalWord = spec.slotValue /\
      checked.argumentWord.originalOffset = spec.originalFrameArgumentOffset /\
      checked.argumentWord.candidateOffset = spec.candidateFrameArgumentOffset /\
      checked.callEntry.behavior.outcome =
        .call spec.wrapperTargetId spec.continuationTargetId := by
  exact ⟨checked.boundary.contractImport, checked.boundary.contractArguments,
    checked.boundary.contractStackResult, checked.boundary.contractPreserved,
    checked.boundary.contractClobbered,
    checked.staticAuthority.certificateSlot,
    checked.frameWrite.canonicalExact, checked.argumentWordOriginalOffset,
    checked.argumentWordCandidateOffset, checked.callEntry.outcomeExact⟩

theorem returningAuthorityRejectsProtocol
    {context : StaticProofContext}
    {originalContext : OriginalDecodedStaticContext}
    {certificate : Certificate}
    {spec : ExternalTailStaticPointerSlotSpec}
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec)
    (protocol : checked.boundary.contract.disposition = .protocol) : False := by
  rw [checked.contractReturns] at protocol
  cases protocol

theorem indirectIatTailRequiresValidatedWorld
    {program : DecodedWorldProgram}
    {point : OriginalRunningPoint}
    {behavior : RelationalBehavior}
    {imported : ExternalTarget}
    {arguments : List Word}
    {iatRva : Nat}
    (transfer : ExactOriginalImportedTailTransfer program point behavior imported
      arguments .iatIndirect (some iatRva)) :
    CallableWorldValidity program.context point.world :=
  transfer.indirectWorldValid

theorem terminatingAuthorityRejectsProtocol
    {context : StaticProofContext}
    {originalContext : OriginalDecodedStaticContext}
    {certificate : Certificate}
    {spec : ExternalTailStaticPointerSlotSpec}
    (checked : CheckedExternalTailStaticPointerSlotTermination context
      originalContext certificate spec)
    (protocol : checked.boundary.contract.disposition = .protocol) : False := by
  rw [checked.dispositionTerminates] at protocol
  cases protocol

def slot : Word := BitVec.ofNat 32 4096

def memory : Memory := fun _ => 0

def overlappingWrite : MachineCallMemoryFootprint := {
  access := .write
  baseArgument := 0
  offset := 0
  size := .fixed 4
}

/-- A concrete write footprint covering byte zero of the protected word cannot
inhabit the footprint frame required by the returning authority. -/
theorem overlappingFootprintRejected :
    ¬ ExternalWriteFootprintsAvoidWord [overlappingWrite] memory [slot] slot := by
  intro avoids
  have byteZero := avoids 0 (by decide)
  have contains : overlappingWrite.contains memory [slot] slot = true := by
    decide +kernel
  simp [ExternalWriteFootprintsAvoidWord, contains] at byteZero
  exact byteZero rfl

theorem returningMacroHasOneOriginalExternalEvent
    {context : StaticProofContext}
    {originalContext : OriginalDecodedStaticContext}
    {certificate : Certificate}
    {spec : ExternalTailStaticPointerSlotSpec}
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) :
    NonemptyRelatedPath checked.program.pe32TransitionSystem
      checked.source.execution [checked.boundary.observation] checked.after :=
  checked.worldExecutionPath

theorem terminatingMacroHasOneOriginalExternalEvent
    {context : StaticProofContext}
    {originalContext : OriginalDecodedStaticContext}
    {certificate : Certificate}
    {spec : ExternalTailStaticPointerSlotSpec}
    (checked : CheckedExternalTailStaticPointerSlotTermination context
      originalContext certificate spec) :
    NonemptyRelatedPath checked.program.pe32TransitionSystem
      checked.source.execution [checked.boundary.observation]
      (.terminated checked.boundaryPoint.world) :=
  checked.worldExecutionPath

#print axioms exactRequestPinsImportAndAbi
#print axioms returningAuthorityRejectsProtocol
#print axioms indirectIatTailRequiresValidatedWorld
#print axioms terminatingAuthorityRejectsProtocol
#print axioms overlappingFootprintRejected
#print axioms returningMacroHasOneOriginalExternalEvent
#print axioms terminatingMacroHasOneOriginalExternalEvent

end StageA.ExternalTailStaticPointerSlotCompositionKernel
"""

_PAIRED_CONTEXT = r"""
namespace StageA.GeneratedReachableSlotFixture

open StageA.Formal StageA.Relational

def pairedContext : StaticProofContext := {
  originalPe := originalContext.pe
  candidatePe := originalContext.pe
  originalImportCertificate := originalContext.importCertificate
  candidateImportCertificate := originalContext.importCertificate
  originalRelocations := originalContext.relocations
  candidateRelocations := originalContext.relocations
  codeMap := {
    entries := .leaf []
    originalAddresses := .leaf []
    candidateAddresses := .leaf []
  }
  dataMap := { entries := #[], originalOrder := [], candidateOrder := [] }
  roots := []
  observations := {}
  machineImportCallContracts := originalContext.machineImportCallContracts
}

end StageA.GeneratedReachableSlotFixture
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAExternalTailStaticPointerSlotCompositionKernelTests(
    unittest.TestCase
):
    def test_macro_layer_and_fail_closed_api_are_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        layer = (
            source_root
            / "RelationalExternalTailStaticPointerSlotComposition.lean"
        ).read_text(encoding="utf-8")
        self.assertNotIn("native_decide", layer)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalExternalTailStaticPointerSlotComposition",
            )
            fixture = (
                stage_a
                / "ExternalTailStaticPointerSlotCompositionKernel.lean"
            )
            fixture.write_text(_API_FIXTURE, encoding="utf-8")
            result = _run_lean_relational(
                root, bundle="ExternalTailStaticPointerSlotCompositionKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 5, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

    def test_generated_static_authority_is_a_kernel_checked_named_term(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        pe_bytes = _fixture_pe(code=b"\xc3\xc3\xc3\xc3")
        entries = ", ".join(
            f"{{ id := {index}, regionIndex := {index}, "
            f"rva := {TEXT_RVA + index} }}"
            for index in range(4)
        )
        addresses = ", ".join(
            f"{{ targetId := {index}, kind := .canonical }}"
            for index in range(4)
        )
        regions = ", ".join(
            f"{{ id := {index}, span := {{ start := {TEXT_RVA + index}, "
            "size := 1 }, root := true, targets := [] }"
            for index in range(4)
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalExternalTailStaticPointerSlotComposition",
            )
            pe_path = root / "fixture.exe"
            pe_path.write_bytes(pe_bytes)
            authority = _authority_source(
                pe_path,
                pe_bytes,
                4,
                entries=entries,
                addresses=addresses,
                regions=regions,
                check_size=4,
            )
            (stage_a / "GeneratedReachableSlotFixture.lean").write_text(
                authority + _PAIRED_CONTEXT,
                encoding="utf-8",
            )
            binding = ExternalTailStaticPointerSlotStaticAuthorityBinding(
                context_term=(
                    "StageA.GeneratedReachableSlotFixture.pairedContext"
                ),
                original_context_term=(
                    "StageA.GeneratedReachableSlotFixture.originalContext"
                ),
                original_decoded_authority_term=(
                    "StageA.GeneratedReachableSlotFixture.originalAuthority"
                ),
                source_target_id=0,
                wrapper_target_id=1,
                continuation_target_id=2,
                source_rva=TEXT_RVA,
                callsite_rva=TEXT_RVA,
                call_instruction_size=2,
                wrapper_rva=TEXT_RVA + 1,
                continuation_rva=TEXT_RVA + 2,
                route_kind="direct_import",
                iat_rva=None,
                slot_rva=DATA_RVA + 0x20,
                slot_target_id=3,
                slot_value=0x18000000 + TEXT_RVA + 3,
                site_id=7,
                machine_contract_id=11,
                imported=ExternalImportIdentity(
                    dll="kernel32.dll", symbol="ExitProcess"
                ),
                original_frame_argument_offset=4,
                candidate_frame_argument_offset=4,
                stack_argument_offsets=(0,),
                stack_result_delta=0,
                preserved_registers=("ebp", "ebx", "edi", "esi"),
                clobbered_registers=("eax", "ecx", "edx"),
                source_region_index=0,
                wrapper_region_index=1,
                continuation_region_index=2,
                imports=("StageA.GeneratedReachableSlotFixture",),
                namespace="StageA.Generated.ExternalTailStaticSlotKernel",
            )
            (
                stage_a / "GeneratedExternalTailStaticSlotKernel.lean"
            ).write_text(
                external_tail_static_pointer_slot_static_authority_source(
                    binding
                ),
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="GeneratedExternalTailStaticSlotKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)


if __name__ == "__main__":
    unittest.main()
