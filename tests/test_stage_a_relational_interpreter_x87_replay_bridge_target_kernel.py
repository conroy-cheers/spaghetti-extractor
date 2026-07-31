from __future__ import annotations

import re
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_target import (
    X87_REPLAY_BRIDGE_TARGET_PACK_PREFIX,
    X87ReplayBridgeDescriptorPlan,
    X87ReplayBridgeFrameMappingPlan,
    X87ReplayBridgeTablePlan,
    X87ReplayBridgeTargetPlan,
    x87_replay_bridge_target_lean_sources,
)
from spaghetti_extractor.util import sha256_bytes


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


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


class StageAX87ReplayBridgeTargetKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for bridge checks")
    def test_static_inventory_and_nested_execution_interface_are_kernel_checked(
        self,
    ) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        module = "RelationalInterpreterX87ReplayBridgeTarget"
        source = (source_root / f"{module}.lean").read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertIn(
            "def nativeX87ReplayLogicalScratchBytes : Nat :=\n  2 * 4",
            source,
        )
        for field in (
            "targetBefore",
            "targetAfter",
            "activeBefore",
            "activeAfter",
            "parentBefore",
            "parentAfter",
            "exactCallStep",
            "exactBridgePath",
            "eventIndex",
            "events",
            "world",
            "externalFrames",
        ):
            self.assertIn(field, source)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, module)
            (stage_a / "X87ReplayBridgeTargetFixture.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            result = _run_lean_relational(root, bundle="X87ReplayBridgeTargetFixture")

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("Classical.choice", result["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for bridge checks")
    def test_generated_static_certificate_rechecks_bytes_and_relocations(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        image, plan = _synthetic_generated_plan()
        sources = x87_replay_bridge_target_lean_sources(
            plan,
            candidate_data_module="SyntheticX87ReplayCandidateDataBase",
            relocation_data_module="SyntheticX87ReplayCandidateRelocations",
            pack_size=1,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterX87ReplayBridgeTarget",
            )
            (stage_a / "SyntheticX87ReplayCandidateDataBase.lean").write_text(
                _synthetic_candidate_data_base_source(image), encoding="utf-8"
            )
            (stage_a / "SyntheticX87ReplayCandidateRelocations.lean").write_text(
                _synthetic_candidate_relocations_source(), encoding="utf-8"
            )
            for filename, source in sources.items():
                (stage_a / filename).write_text(source, encoding="utf-8")
            pack_result = _run_lean_relational(
                root,
                bundle=f"{X87_REPLAY_BRIDGE_TARGET_PACK_PREFIX}0000",
            )
            result = _run_lean_relational(
                root,
                bundle="GeneratedRelationalInterpreterX87ReplayBridgeTarget",
            )

        self.assertEqual(pack_result["status"], "checked", pack_result)
        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("Classical.choice", result["stdout"])


def _synthetic_generated_plan() -> tuple[bytes, X87ReplayBridgeTargetPlan]:
    image_base = 0x400000
    instruction = b"\xd9\xe8"
    instruction_digest = sha256_bytes(instruction)
    empty_digest = sha256_bytes(b"")
    image = bytearray(1400)
    bridge_target_rva = 4
    instruction_rva = bridge_target_rva + 52
    capture_rva = bridge_target_rva + 72
    active_frame_pointer_rva = 1240
    active_frame_va = image_base + active_frame_pointer_rva
    entry_body = bytes.fromhex(
        "89600cdd60148b40048b58048b48088b70108b78148b68188b601c"
        "ffb0f0000000ff308b500c589d909090"
    )
    capture_body = bytes.fromhex(
        "ddb0800000008b50088b0c24890a0f9242200f9a42300f9442240f984228"
        "0f90422c8b5c24048b48048b89f000000081e12af3ffff81e3d50c000009"
        "d9898af0000000"
        "90909090909090909090"
        "c74010000000008b600cfc5f5e5b5dc390909090"
    )
    body = bytearray(
        b"\x55\x53\x56\x57\xa1"
        + struct.pack("<I", active_frame_va)
        + entry_body
        + instruction
        + b"\x90" * (72 - 52 - len(instruction))
        + b"\x9c\x50\xa1"
        + struct.pack("<I", active_frame_va)
        + capture_body
    )
    assert len(body) == 176
    image[bridge_target_rva : bridge_target_rva + len(body)] = body
    instruction_path = instruction
    image[289:294] = b"\xa3" + struct.pack("<I", active_frame_va)
    image[294:297] = b"\x8b\x45\xe4"
    image[297:300] = b"\x8b\x40\x20"
    image[300:302] = b"\xff\xd0"
    image[302:308] = b"\x8b\x15" + struct.pack("<I", active_frame_va)
    struct.pack_into(
        "<IIIIIIIII",
        image,
        340,
        image_base,
        12,
        14,
        len(instruction),
        image_base + 400,
        image_base + 416,
        image_base + 481,
        image_base + 546,
        image_base + bridge_target_rva,
    )
    image[400:402] = instruction
    image[416:481] = instruction_digest.encode() + b"\0"
    image[481:546] = instruction_digest.encode() + b"\0"
    image[546:611] = empty_digest.encode() + b"\0"
    relocation_entries = [
        (3 << 12) | offset
        for offset in (9, 79, 290, 304, 356, 360, 364, 368, 372)
    ] + [0]
    struct.pack_into("<II10H", image, 800, 0, 28, *relocation_entries)
    descriptor = X87ReplayBridgeDescriptorPlan(
        id=0,
        descriptor_rva=340,
        image_base=image_base,
        rva_start=12,
        rva_end=14,
        instruction_bytes=instruction,
        instruction_bytes_sha256=instruction_digest,
        transfer_instruction_bytes_sha256=instruction_digest,
        contract_sha256=empty_digest,
        checked_decoder="StageA.Relational.X87.decodeSingletonCommand",
        checked_executor="StageA.Relational.X87.executeSingletonCommand",
        instruction_bytes_rva=400,
        instruction_digest_rva=416,
        transfer_digest_rva=481,
        contract_digest_rva=546,
        bridge_target_rva=bridge_target_rva,
        bridge_entry_bytes=b"\x55",
    )
    mapping = X87ReplayBridgeFrameMappingPlan(
        descriptor_id=0,
        bridge_target_rva=bridge_target_rva,
        instruction_rva=instruction_rva,
        capture_rva=capture_rva,
        return_rva=bridge_target_rva + 171,
        bridge_body_bytes=bytes(body),
        instruction_path_bytes=bytes(instruction_path),
    )
    table = X87ReplayBridgeTablePlan(
        table_rva=340,
        call_site_rva=300,
        call_instruction_bytes=b"\xff\xd0",
        continuation_rva=302,
        active_frame_pointer_rva=active_frame_pointer_rva,
        active_frame_store_rva=289,
        active_frame_store_bytes=image[289:294],
        descriptor_load_rva=294,
        descriptor_load_bytes=b"\x8b\x45\xe4",
        target_load_rva=297,
        target_load_bytes=b"\x8b\x40\x20",
        active_frame_load_rva=302,
        active_frame_load_bytes=image[302:308],
        descriptors=(descriptor,),
        frame_mappings=(mapping,),
    )
    return bytes(image), X87ReplayBridgeTargetPlan(
        candidate_path=Path("synthetic.exe"),
        candidate_sha256=sha256_bytes(image),
        candidate_size=len(image),
        build_manifest_sha256="00" * 32,
        native_engine_plan_sha256="11" * 32,
        requested_call_site_rva=300,
        table=table,
        issues=(),
    )


def _synthetic_candidate_data_base_source(image: bytes) -> str:
    rendered = ", ".join(str(value) for value in image)
    return f"""import StageA.RelationalInterpreterX87ReplayBridgeTarget

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal

def generatedInterpreterKernelCandidatePe : PE32 := {{
  bytes := ByteTree.ofBytes [{rendered}]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 1400
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 800
  relocationDirectorySize := 28
  sections := [{{
    virtualSize := 1200
    virtualAddress := 0
    rawSize := 1200
    rawPointer := 0
    characteristics := 0x60000020
  }}, {{
    virtualSize := 200
    virtualAddress := 1200
    rawSize := 200
    rawPointer := 1200
    characteristics := 0xc0000040
  }}]
}}

def generatedInterpreterKernelImports : List PEImport := []

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _synthetic_candidate_relocations_source() -> str:
    return """import StageA.SyntheticX87ReplayCandidateDataBase

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal

def generatedInterpreterKernelRelocations : List BaseRelocation := [
  { rva := 9, kind := 3 },
  { rva := 79, kind := 3 },
  { rva := 290, kind := 3 },
  { rva := 304, kind := 3 },
  { rva := 356, kind := 3 },
  { rva := 360, kind := 3 },
  { rva := 364, kind := 3 },
  { rva := 368, kind := 3 },
  { rva := 372, kind := 3 }
]

theorem generatedInterpreterKernelRelocationsParsed :
    parseRelocations generatedInterpreterKernelCandidatePe =
      some generatedInterpreterKernelRelocations := by
  decide +kernel

end StageA.GeneratedRelational.InterpreterKernelData
"""


_FIXTURE = r"""import StageA.RelationalInterpreterX87ReplayBridgeTarget

namespace StageA.Relational.InterpreterX87ReplayBridgeTargetFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterX87ReplayBridgeTarget

def target : CallbackTargetEntry := {
  id := 0
  entry := { rva := 4, bytes := [0xc3] }
}

def descriptor : NativeX87ReplayBridgeDescriptor := {
  id := 0
  descriptorRva := 32
  instructionBytesRva := 80
  instructionDigestRva := 96
  transferDigestRva := 161
  contractDigestRva := 226
  replay := {
    imageBase := 0x400000
    rvaStart := 12
    rvaEnd := 14
    instructionCount := 1
    instructionBytes := [0xd9, 0xe8]
    instructionBytesSha256 :=
      "852df74fff31b328b40e1bb1b4ad5d8baba06f81bef9371e7f0ddb597d97e8b4"
    transferInstructionBytesSha256 :=
      "852df74fff31b328b40e1bb1b4ad5d8baba06f81bef9371e7f0ddb597d97e8b4"
    contractSha256 :=
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    checkedDecoder := "StageA.Relational.X87.decodeSingletonCommand"
    checkedExecutor := "StageA.Relational.X87.executeSingletonCommand"
  }
  bridge := target
}

def table : NativeX87ReplayBridgeTable := {
  tableRva := 32
  activeFramePointerRva := 300
  activeFrameStoreInstruction := { rva := 0, bytes := [] }
  descriptorLoadInstruction := { rva := 0, bytes := [] }
  targetLoadInstruction := { rva := 0, bytes := [] }
  callInstruction := { rva := 0, bytes := [0xff, 0xd0] }
  activeFrameLoadInstruction := { rva := 2, bytes := [] }
  continuationRva := 2
  descriptors := [descriptor]
}

example : table.nativeTargetSet = {
    sourceRva := 0
    transfer := .call
    targets := [.internalRva 4]
  } := by
  rfl

example : table.targetCells.cells = [{
    id := 0
    cellRva := 64
    targetId := 0
  }] := by
  rfl

def emptyTargets : NativeIndirectTargetInventory := { targetSets := [] }

example : emptyTargets.targetSet? table.callInstruction.rva .call = none := by
  rfl

example (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop)
    (certificate : ExactNativeX87ReplayBridgeExecutionRefinement
      program table handler sourceInvariant) :
    program.indirectTargets.targetSet? table.callInstruction.rva .call =
      some table.nativeTargetSet :=
  certificate.targetInventory

example (program : ExactNestedNativeWorldProgram)
    (table : NativeX87ReplayBridgeTable)
    (handler : CandidateReplayHandler)
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    NonemptyRelatedPath program.transitionSystem run.before [] run.after :=
  run.exactEventFreePath

#print axioms ExactNativeX87ReplayBridgeStaticCertificate.descriptorChecked
#print axioms ExactNativeX87ReplayBridgeRun.exactEventFreePath
#print axioms ExactNativeX87ReplayBridgeExecutionRefinement.refinesSource

end StageA.Relational.InterpreterX87ReplayBridgeTargetFixture
"""


if __name__ == "__main__":
    unittest.main()
