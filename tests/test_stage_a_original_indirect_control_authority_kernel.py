from __future__ import annotations

import re
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_nullable_code_pointer_table import (
    DATA_RAW,
    DATA_RVA,
    IMAGE_BASE,
    TEXT_RAW,
    TEXT_RVA,
    _nullable_table_pe,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


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


def _lean_bytes(data: bytes) -> str:
    rows = [
        ", ".join(str(value) for value in data[offset : offset + 32])
        for offset in range(0, len(data), 32)
    ]
    return "[\n    " + ",\n    ".join(rows) + "\n  ]"


def _fixture_bytes() -> bytes:
    image = bytearray(_nullable_table_pe(
        words=(IMAGE_BASE + TEXT_RVA, 0),
        relocation_offsets=(0,),
    ))
    stack_call = bytes.fromhex("ff542420")
    indexed_call = b"\xff\x14\x9d" + struct.pack(
        "<I", IMAGE_BASE + DATA_RVA + 4
    )
    callback_call = bytes.fromhex("ff5304")
    image[TEXT_RAW : TEXT_RAW + len(stack_call)] = stack_call
    image[TEXT_RAW + 4] = 0xC3
    image[TEXT_RAW + 0x10 : TEXT_RAW + 0x10 + len(indexed_call)] = indexed_call
    image[TEXT_RAW + 0x17] = 0xC3
    image[TEXT_RAW + 0x20 : TEXT_RAW + 0x20 + len(callback_call)] = callback_call
    image[TEXT_RAW + 0x23] = 0xC3
    return bytes(image)


def _fixture_source() -> str:
    return f"""import StageA.RelationalOriginalIndirectControlAuthority

namespace StageA.OriginalIndirectControlAuthorityKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.NullableCodePointerTable
open StageA.Relational.OriginalIndirectControlAuthority

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def fixtureBytes : Bytes := {_lean_bytes(_fixture_bytes())}

def fallbackPe : PE32 := {{
  bytes := .empty
  peOffset := 0
  entrypointRva := {TEXT_RVA}
  imageBase := {IMAGE_BASE}
  sectionAlignment := 4096
  fileAlignment := 512
  sizeOfImage := 16384
  sizeOfHeaders := 512
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}}

def pe : PE32 := (parsePE32 fixtureBytes).getD fallbackPe

def codeMap : OriginalCodeMap := {{
  entries := .leaf [
    {{ id := 0, regionIndex := 0, rva := {TEXT_RVA} }},
    {{ id := 1, regionIndex := 1, rva := {TEXT_RVA + 4} }},
    {{ id := 2, regionIndex := 2, rva := {TEXT_RVA + 0x10} }},
    {{ id := 3, regionIndex := 3, rva := {TEXT_RVA + 0x17} }},
    {{ id := 4, regionIndex := 4, rva := {TEXT_RVA + 0x20} }},
    {{ id := 5, regionIndex := 5, rva := {TEXT_RVA + 0x23} }}
  ]
  addresses := .leaf [
    {{ targetId := 0, kind := .canonical }},
    {{ targetId := 1, kind := .canonical }},
    {{ targetId := 2, kind := .canonical }},
    {{ targetId := 3, kind := .canonical }},
    {{ targetId := 4, kind := .canonical }},
    {{ targetId := 5, kind := .canonical }}
  ]
}}

def regions : FiniteIndex OriginalDecodedRegion := .leaf [
  {{ id := 0, span := {{ start := {TEXT_RVA}, size := 4 }}, root := true,
    targets := [1] }},
  {{ id := 1, span := {{ start := {TEXT_RVA + 4}, size := 1 }}, root := false,
    targets := [] }},
  {{ id := 2, span := {{ start := {TEXT_RVA + 0x10}, size := 7 }}, root := true,
    targets := [3] }},
  {{ id := 3, span := {{ start := {TEXT_RVA + 0x17}, size := 1 }}, root := false,
    targets := [] }},
  {{ id := 4, span := {{ start := {TEXT_RVA + 0x20}, size := 3 }}, root := true,
    targets := [5] }},
  {{ id := 5, span := {{ start := {TEXT_RVA + 0x23}, size := 1 }}, root := false,
    targets := [] }}
]

def context : OriginalDecodedStaticContext := {{
  pe
  importCertificate := {{ descriptors := [] }}
  relocations := (parseRelocations pe).getD []
  codeMap
  regions
}}

def stackSite : OriginalIndirectControlSite := {{
  sourceTargetId := 0
  instructionRva := {TEXT_RVA}
  instructionBytes := [255, 84, 36, 32]
  target := .stackRead .esp (.add 32)
  transfer := .call 1
}}

example : stackSite.checked context = true := by decide +kernel
example : ({{ stackSite with instructionBytes := [255, 84, 36, 36] }}).checked
    context = false := by decide +kernel
example : ({{ stackSite with target := .stackRead .esp (.add 36) }}).checked
    context = false := by decide +kernel
example : ({{ stackSite with transfer := .call 3 }}).checked context = false := by
  decide +kernel

def seed : RelocatedCodePointerSeed := {{ slotRva := {DATA_RVA}, targetId := 0 }}
example : seed.checked context = true := by decide +kernel
example : ({{ seed with slotRva := {DATA_RVA + 4} }}).checked context = false := by
  decide +kernel

def tableSite : OriginalIndirectControlSite := {{
  sourceTargetId := 2
  instructionRva := {TEXT_RVA + 0x10}
  instructionBytes := [255, 20, 157,
    {(IMAGE_BASE + DATA_RVA + 4) & 0xff},
    {((IMAGE_BASE + DATA_RVA + 4) >> 8) & 0xff},
    {((IMAGE_BASE + DATA_RVA + 4) >> 16) & 0xff},
    {((IMAGE_BASE + DATA_RVA + 4) >> 24) & 0xff}]
  target := .indexedTable {IMAGE_BASE + DATA_RVA + 4} .ebx 4
  transfer := .call 3
}}

def tableCertificate : Certificate := {{
  peBytes := fixtureBytes
  contextId := 2
  dispatchRva := {TEXT_RVA + 0x10}
  tableRva := {DATA_RVA + 4}
  headerWords := []
  callerRange := .exact {{ startRva := {DATA_RVA + 4}, endRva := {DATA_RVA + 8} }}
  codeMap := .exact []
  nonNullTargetIds := .exact []
  edges := .exact []
  writers := .exact []
  aliases := .exact []
  loop := .exact {{
    lowerInclusive := 0
    upperExclusive := 1
    step := 1
    addressBaseRva := {DATA_RVA + 4}
    addressScale := 4
    alignment := 4
  }}
  guard := .exact .nonzero
}}

def tableClaim : NullableTableControlClaim := {{
  site := tableSite
  table := tableCertificate
}}

example : tableClaim.checked context = true := by decide +kernel
def wrongTableSite : OriginalIndirectControlSite := {{
  tableSite with target := .indexedTable {IMAGE_BASE + DATA_RVA} .ebx 4
}}
def wrongTableClaim : NullableTableControlClaim := {{
  tableClaim with site := wrongTableSite
}}
example : wrongTableClaim.checked context = false := by decide +kernel
example : tableCertificate.resolvedNonNullTargetIds = some [] := by decide +kernel

def callbackSite : OriginalIndirectControlSite := {{
  sourceTargetId := 4
  instructionRva := {TEXT_RVA + 0x20}
  instructionBytes := [255, 83, 4]
  target := .dynamicField .ebx 4
  transfer := .call 5
}}

def callbackClaim : DynamicCallbackControlClaim := {{
  site := callbackSite
  callbackFieldOffset := 4
  allowedTargetIds := [0]
}}

example : callbackClaim.checked context = true := by decide +kernel
example : ({{ callbackClaim with allowedTargetIds := [] }}).checked context = false := by
  decide +kernel
example : ({{ callbackClaim with allowedTargetIds := [0, 0] }}).checked context = false := by
  decide +kernel

#print axioms StackFixedControlRuntime.targetValue
#print axioms nullableTableSourceUnreachable_of_noTargets
#print axioms DynamicCallbackControlRuntime.targetValue

end StageA.OriginalIndirectControlAuthorityKernel
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalIndirectControlAuthorityKernelTests(unittest.TestCase):
    def test_exact_and_mutated_authorities_compile_in_lean(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalIndirectControlAuthority",
            )
            (stage_a / "OriginalIndirectControlAuthorityKernel.lean").write_text(
                _fixture_source(), encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="OriginalIndirectControlAuthorityKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 3, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
