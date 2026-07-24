from __future__ import annotations

import re
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.common import _lean_byte_tree_definitions
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_IMAGE_BASE = 0x400000
_SECTION_RVA = 0x1000


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


def _u32s(*values: int) -> bytes:
    return struct.pack("<" + "I" * len(values), *values)


def _fixture_data() -> bytes:
    data = bytearray(0x300)
    pointers = (
        _IMAGE_BASE + 0x1040,
        _IMAGE_BASE + 0x1070,
        _IMAGE_BASE + 0x10A0,
        _IMAGE_BASE + 0x1100,
        _IMAGE_BASE + 0x1140,
    )
    data[0x00:0x28] = _u32s(0x1234, 1, 0, 3, 0, *pointers)
    data[0x40:0x64] = _u32s(0, 0, 0, 7, 0, 0, 0, 0, 0)
    data[0x70:0x94] = bytes(36)
    data[0xA0:0xC0] = _u32s(0, 1, 0, 0, 0, 0, 0, 0)
    data[0xC0:0xE0] = _u32s(6, 1, 0, 0, 0, 0, 0, 0)
    data[0xE0:0x100] = _u32s(22, 1, 0, 0, 0, 0, 0, 0)
    data[0x100:0x140] = bytes(64)
    data[0x140:0x16C] = bytes(44)
    data[0x180:0x184] = _u32s(1)
    data[0x200:0x214] = _u32s(
        0x1000,
        20,
        0x3014 | (0x3018 << 16),
        0x301C | (0x3020 << 16),
        0x3024,
    )
    return bytes(data)


def _fixture_source() -> str:
    tree = _lean_byte_tree_definitions("fixtureBytes", _fixture_data())
    return f"""import StageA.RelationalInterpreterKernelData

namespace StageA.Relational.InterpreterKernelDataFixture

open StageA.Formal
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelData

{tree}

def pe : PE32 := {{
  bytes := fixtureBytes
  peOffset := 0
  entrypointRva := 0
  imageBase := {_IMAGE_BASE}
  sectionAlignment := 4096
  fileAlignment := 512
  sizeOfImage := 8192
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0x1200
  relocationDirectorySize := 20
  sections := [{{
    virtualSize := 768
    virtualAddress := 4096
    rawSize := 768
    rawPointer := 0
    characteristics := 0x40000040
  }}]
}}

def relocations : List BaseRelocation := [
  {{ rva := 0x1014, kind := 3 }},
  {{ rva := 0x1018, kind := 3 }},
  {{ rva := 0x101c, kind := 3 }},
  {{ rva := 0x1020, kind := 3 }},
  {{ rva := 0x1024, kind := 3 }}
]

def expectedRecord : ProgramRecord := {{
  sourceRva := 0x1234
  wordNodes := [{{ op := 0, arity := 0, aux := 0, immediate := 7, args := [] }}]
  x87Nodes := []
  calls := []
  actions := [
    {{ op := 0, arity := 1, aux := 0, args := [0] }},
    {{ op := 6, arity := 1, aux := 0, args := [0] }},
    {{ op := 22, arity := 1, aux := 0, args := [0] }}
  ]
}}

def expectedEntry : CompiledProgramRecord := {{
  record := expectedRecord
  x87Replays := []
}}

def expectedDescriptor : TransferDescriptor := {{
  sourceRva := 0x1234
  wordCount := 1
  x87Count := 0
  actionCount := 3
  replayCount := 0
  wordPointer := {_IMAGE_BASE + 0x1040}
  x87Pointer := {_IMAGE_BASE + 0x1070}
  actionPointer := {_IMAGE_BASE + 0x10A0}
  callPointer := {_IMAGE_BASE + 0x1100}
  replayPointer := {_IMAGE_BASE + 0x1140}
}}

def decoded := decodeProgramTableRange pe [] 0x1000 0 1

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem relocationsLinearChecked :
    relocationInventoryLinearChecked relocations = true := by decide +kernel

theorem relocationsUnique : relocationInventoryUnique relocations = true :=
  relocationInventoryUnique_of_linearChecked relocations relocationsLinearChecked

theorem pointer1014 : relocationFieldPresent relocations 0x1014 = true := by
  decide +kernel

theorem pointer1018 : relocationFieldPresent relocations 0x1018 = true := by
  decide +kernel

theorem pointer101c : relocationFieldPresent relocations 0x101c = true := by
  decide +kernel

theorem pointer1020 : relocationFieldPresent relocations 0x1020 = true := by
  decide +kernel

theorem pointer1024 : relocationFieldPresent relocations 0x1024 = true := by
  decide +kernel

example : relocationInventoryLinearChecked [
    {{ rva := 0x1014, kind := 3 }},
    {{ rva := 0x1014, kind := 3 }}
  ] = false := by decide +kernel

example : relocationInventoryLinearChecked [
    {{ rva := 0x1018, kind := 3 }},
    {{ rva := 0x1014, kind := 3 }}
  ] = false := by decide +kernel

example : relocationInventoryLinearChecked [
    {{ rva := 0x1014, kind := 2 }}
  ] = false := by decide +kernel

example :
    ({{ relocatedPointerFields := [0x1010] }} : LayoutTrace).relocationFieldsChecked
      relocations = false := by decide +kernel

example :
    ({{ zeroPointerFields := [0x1014] }} : LayoutTrace).relocationFieldsChecked
      relocations = false := by decide +kernel

example : relocationFieldAbsent relocations 0x1014 = false := by
  decide +kernel

theorem descriptorDecoded :
    decodeTransferDescriptor pe [] 0x1000 0 = some expectedDescriptor := by
  decide +kernel

def mutatedDescriptor : TransferDescriptor :=
  {{ expectedDescriptor with sourceRva := 0x1235 }}

example : decide
    (decodeTransferDescriptor pe [] 0x1000 0 = some mutatedDescriptor) = false := by
  decide +kernel

def wordTrace : LayoutTrace := {{ relocatedPointerFields := [0x1014] }}
def x87Trace : LayoutTrace := {{ relocatedPointerFields := [0x1018] }}
def actionTrace : LayoutTrace := {{ relocatedPointerFields := [0x101c] }}
def callTrace : LayoutTrace := {{ relocatedPointerFields := [0x1020] }}
def replayTrace : LayoutTrace := {{ relocatedPointerFields := [0x1024] }}

theorem wordDecoded :
    decodeNodeArray pe [] 0x1014 expectedDescriptor.wordPointer
      expectedDescriptor.wordCount wordNodeSize maxWordNodes =
        .ok expectedRecord.wordNodes wordTrace := by
  decide +kernel

theorem x87Decoded :
    decodeNodeArray pe [] 0x1018 expectedDescriptor.x87Pointer
      expectedDescriptor.x87Count x87NodeSize maxX87Nodes =
        .ok expectedRecord.x87Nodes x87Trace := by
  decide +kernel

theorem actionsDecoded :
    decodeActionArray pe [] 0x101c expectedDescriptor.actionPointer
      expectedDescriptor.actionCount = .ok expectedRecord.actions actionTrace := by
  decide +kernel

theorem callsDecoded :
    decodeCallArray pe [] 0x1020 expectedDescriptor.callPointer
      (callCountFromActions expectedRecord.actions) =
        .ok expectedRecord.calls callTrace := by
  decide +kernel

theorem replaysDecoded :
    decodeX87ReplayArray pe [] 0x1024 expectedDescriptor.replayPointer
      expectedDescriptor.replayCount = .ok ([] : List RawX87Replay) replayTrace := by
  decide +kernel

def present (field : Nat)
    (checked : relocationFieldPresent relocations field = true) :
    LayoutTraceRelocationCertificate
      {{ relocatedPointerFields := [field] }} relocations := {{
  relocated := .cons checked .nil
  zero := .nil
}}

def wordCertificate : LayoutMExactCertificate
    (decodeNodeArray pe [] 0x1014 expectedDescriptor.wordPointer
      expectedDescriptor.wordCount wordNodeSize maxWordNodes)
    expectedRecord.wordNodes relocations := {{
  trace := wordTrace
  decodedExact := wordDecoded
  relocationFields := present 0x1014 pointer1014
}}

def x87Certificate : LayoutMExactCertificate
    (decodeNodeArray pe [] 0x1018 expectedDescriptor.x87Pointer
      expectedDescriptor.x87Count x87NodeSize maxX87Nodes)
    expectedRecord.x87Nodes relocations := {{
  trace := x87Trace
  decodedExact := x87Decoded
  relocationFields := present 0x1018 pointer1018
}}

def actionCertificate : LayoutMExactCertificate
    (decodeActionArray pe [] 0x101c expectedDescriptor.actionPointer
      expectedDescriptor.actionCount) expectedRecord.actions relocations := {{
  trace := actionTrace
  decodedExact := actionsDecoded
  relocationFields := present 0x101c pointer101c
}}

def callCertificate : LayoutMExactCertificate
    (decodeCallArray pe [] 0x1020 expectedDescriptor.callPointer
      (callCountFromActions expectedRecord.actions)) expectedRecord.calls
      relocations := {{
  trace := callTrace
  decodedExact := callsDecoded
  relocationFields := present 0x1020 pointer1020
}}

def replayCertificate : LayoutMExactCertificate
    (decodeX87ReplayArray pe [] 0x1024 expectedDescriptor.replayPointer
      expectedDescriptor.replayCount) ([] : List RawX87Replay) relocations := {{
  trace := replayTrace
  decodedExact := replaysDecoded
  relocationFields := present 0x1024 pointer1024
}}

def packedData : TransferCertificateData := {{
  descriptor := expectedDescriptor
  wordNodes := expectedRecord.wordNodes
  x87Nodes := expectedRecord.x87Nodes
  actions := expectedRecord.actions
  calls := expectedRecord.calls
  x87Replays := []
  wordTrace
  x87Trace
  actionTrace
  callTrace
  replayTrace
}}

def packedCertificate : TransferCertificatePack := {{
  startIndex := 0
  entries := (#[packedData] : Array TransferCertificateData)
}}

theorem packedDescriptorsChecked : packedCertificate.checked 1
    (transferDescriptorChecked pe [] 0x1000) = true := by decide +kernel

theorem packedWordsChecked : packedCertificate.checked 1
    (transferWordNodesChecked pe [] relocations 0x1000) = true := by decide +kernel

theorem packedX87sChecked : packedCertificate.checked 1
    (transferX87NodesChecked pe [] relocations 0x1000) = true := by decide +kernel

theorem packedActionsChecked : packedCertificate.checked 1
    (transferActionsChecked pe [] relocations 0x1000) = true := by decide +kernel

theorem packedCallsChecked : packedCertificate.checked 1
    (transferCallsChecked pe [] relocations 0x1000) = true := by decide +kernel

theorem packedReplaysChecked : packedCertificate.checked 1
    (transferX87ReplaysChecked pe [] relocations 0x1000) = true := by decide +kernel

noncomputable def packedExactCertificate := packedCertificate.exactCertificate 1
  pe [] relocations 0x1000 packedDescriptorsChecked packedWordsChecked
  packedX87sChecked packedActionsChecked packedCallsChecked packedReplaysChecked

def mutatedPackedData : TransferCertificateData :=
  {{ packedData with descriptor := mutatedDescriptor }}

def mutatedPackedCertificate : TransferCertificatePack := {{
  startIndex := 0
  entries := (#[mutatedPackedData] : Array TransferCertificateData)
}}

example : mutatedPackedCertificate.checked 1
    (transferDescriptorChecked pe [] 0x1000) = false := by decide +kernel

def entryTrace : LayoutTrace :=
  wordTrace.append (x87Trace.append
    (actionTrace.append (callTrace.append replayTrace)))

theorem entryDecoded :
    decodeTransferAt pe [] 0x1000 0 = .ok expectedEntry entryTrace := by
  exact decodeTransferAt_eq_of_components pe [] 0x1000 0 expectedDescriptor
    expectedRecord.wordNodes expectedRecord.x87Nodes expectedRecord.actions
    expectedRecord.calls [] wordTrace x87Trace actionTrace callTrace replayTrace
    descriptorDecoded (by decide) wordDecoded x87Decoded actionsDecoded callsDecoded
    replaysDecoded

def entryCertificate : LayoutMExactCertificate
    (decodeTransferAt pe [] 0x1000 0) expectedEntry relocations := {{
  trace := entryTrace
  decodedExact := entryDecoded
  relocationFields := wordCertificate.relocationFields.append
    (x87Certificate.relocationFields.append
      (actionCertificate.relocationFields.append
        (callCertificate.relocationFields.append replayCertificate.relocationFields)))
}}

def rangeTail : LayoutMExactCertificate
    (decodeManyAux (fun offset => decodeTransferAt pe [] 0x1000 offset) 1 0)
    [] relocations :=
  decodeManyAuxNilCertificate _ 1 relocations

def rangeMany : LayoutMExactCertificate
    (decodeMany 1 (fun offset => decodeTransferAt pe [] 0x1000 offset))
    [expectedEntry] relocations := by
  simpa [decodeMany] using decodeManyAuxConsCertificate
    (fun offset => decodeTransferAt pe [] 0x1000 offset) 0 0 relocations
    entryCertificate rangeTail

def rangeCertificate : LayoutMExactCertificate decoded [expectedEntry] relocations :=
  decodeProgramTableRangeCertificate pe [] 0x1000 0 1 [expectedEntry]
    relocations (by decide) rangeMany

theorem decodedValue : decoded.value? = some [expectedEntry] :=
  rangeCertificate.value?_eq

theorem decodedRelocations :
    (match decoded.trace? with
    | none => false
    | some trace => trace.relocationsChecked relocations) = true :=
  rangeCertificate.relocationsChecked relocationsLinearChecked relocationsUnique

example :
    (match decoded.trace? with
    | none => false
    | some trace => trace.relocationsChecked (relocations.drop 1)) = false := by
  decide +kernel

example : (decodeProgramTableRange pe [] 0x1001 0 1).value? = none := by
  decide +kernel

def shard : ProgramTableShardCertificate pe [] relocations 0x1000 := {{
  startIndex := 0
  entries := [expectedEntry]
  nonempty := by decide
  decoded := decodedValue
  relocationFieldsChecked := decodedRelocations
}}

def certificate : ProgramTableCertificate pe [] relocations
    0x1000 0x1180 [expectedRecord] := {{
  transferCount := 1
  countDecoded := by decide +kernel
  relocationsParsed := by decide
  shards := [shard]
  shardsCover := by decide +kernel
  semanticRecordsExact := by decide +kernel
  sourceRvasUnique := by decide
}}

example (sourceRva : Nat) :
    lookupProgramRecord [expectedRecord] sourceRva =
      lookupProgramRecord (decodedShardRecords certificate.shards) sourceRva :=
  certificate.semantic_lookup_is_compiled_lookup sourceRva

#print axioms ProgramTableCertificate.semantic_lookup_is_compiled_lookup

end StageA.Relational.InterpreterKernelDataFixture
"""


class StageARelationalInterpreterKernelDataTests(unittest.TestCase):
    def test_kernel_has_no_unchecked_acceptance_constructs(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelData.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertIn("decodeProgramTableRange", source)
        self.assertIn("decodeTransferDescriptor", source)
        self.assertIn("relocationInventoryLinearChecked", source)
        self.assertIn("relocationInventoryUnique_of_linearChecked", source)
        self.assertIn("RelocationPresenceCertificate", source)
        self.assertIn("RelocationAbsenceCertificate", source)
        self.assertIn("LayoutMExactCertificate", source)
        self.assertIn("TransferCertificateData", source)
        self.assertIn("TransferCertificatePack", source)
        self.assertIn("ImmutableByteCache", source)
        self.assertIn("read_eq_authoritative", source)
        self.assertIn("immutableRvaBytes_eq_slices", source)
        self.assertIn("RelocationRvaIndexCertificate", source)
        self.assertIn("contains_eq_present", source)
        self.assertIn("transferLocalCertificateChecked", source)
        self.assertIn("TransferCertificatePack.localExactCertificate", source)
        self.assertIn("transferCertificateListChecked", source)
        self.assertIn("transferCertificateExactOfChecked", source)
        self.assertIn("TransferCertificatePack.exactCertificate", source)
        self.assertIn("decodeTransferAt_eq_of_components", source)
        self.assertIn("decodeManyAuxConsCertificate", source)
        self.assertIn("trace.relocationsChecked relocations", source)
        self.assertIn("ProgramTableShardMetadataCertificate", source)
        self.assertIn("ProgramTableShardMetadataChain", source)
        self.assertIn(
            "ProgramTableShardMetadataChain.sourceRvasExact", source
        )
        self.assertIn("ProgramTableShardMetadataChain.coverage", source)
        self.assertIn("semantic_lookup_is_compiled_lookup", source)
        self.assertNotIn("valueAndRelocationFieldsChecked", source)
        self.assertNotIn("candidatePeSha256", source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_exact_layout_and_lookup_certificate_compile(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelData"
            )
            (stage_a / "RelationalInterpreterKernelDataFixture.lean").write_text(
                _fixture_source(), encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelDataFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
