from __future__ import annotations

import re
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_nullable_code_pointer_table import (
    DATA_RVA,
    IMAGE_BASE,
    TEXT_RAW,
    TEXT_RVA,
    _nullable_table_pe,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


def _lean_bytes(data: bytes) -> str:
    rows = [
        ", ".join(str(value) for value in data[offset : offset + 32])
        for offset in range(0, len(data), 32)
    ]
    return "[\n    " + ",\n    ".join(rows) + "\n  ]"


def _decoded_dispatch_bytes(*, sib: int = 0x9D, displacement: int = 0) -> bytes:
    image = bytearray(_nullable_table_pe(words=(0xFFFFFFFF, 0)))
    table_address = IMAGE_BASE + DATA_RVA + displacement
    image[TEXT_RAW + 0x10 : TEXT_RAW + 0x17] = (
        bytes((0xFF, 0x14, sib)) + struct.pack("<I", table_address)
    )
    image[TEXT_RAW + 0x17] = 0xC3
    return bytes(image)


def _exact_decode_fixture() -> str:
    table_address = IMAGE_BASE + DATA_RVA
    return f"""
def exactGoodBytes : Bytes := {_lean_bytes(_decoded_dispatch_bytes())}
def exactBadScaleBytes : Bytes := {_lean_bytes(_decoded_dispatch_bytes(sib=0x5D))}
def exactBadRegisterBytes : Bytes := {_lean_bytes(_decoded_dispatch_bytes(sib=0x85))}
def exactBadOffsetBytes : Bytes := {_lean_bytes(_decoded_dispatch_bytes(displacement=4))}

def exactDecodeMap : StaticCodeMap := {{
  entries := .leaf [
    {{ id := 0, originalRva := {TEXT_RVA + 0x10}, candidateRva := {TEXT_RVA + 0x10} }},
    {{ id := 1, originalRva := {TEXT_RVA + 0x17}, candidateRva := {TEXT_RVA + 0x17} }}
  ]
  originalAddresses := .leaf [
    {{ targetId := 0, kind := .canonical }},
    {{ targetId := 1, kind := .canonical }}
  ]
  candidateAddresses := .leaf [
    {{ targetId := 0, kind := .canonical }},
    {{ targetId := 1, kind := .canonical }}
  ]
}}

def exactDecodeRegion : PairedDecodedRegionRef := {{
  targetId := 0
  originalSpan := {{ start := {TEXT_RVA + 0x10}, size := 7 }}
  candidateSpan := {{ start := {TEXT_RVA + 0x10}, size := 7 }}
}}

def exactDecodeTable : BoundedImmutableCodePointerTableCallClaim := {{
  valueTargetId := 0
  tableOffset := 0
  originalBase := {table_address}
  candidateBase := {table_address}
  upperExclusive := 1
  originalIndexRegister := .ebx
  candidateIndexRegister := .ebx
  continuationTargetId := 1
  rows := [{{ index := 0, targetId := 0 }}]
}}

def exactDecodeBehaviorChecked (bytes : Bytes) : Option Bool := do
  let pe <- parsePE32 bytes
  let context : StaticProofContext := {{
    originalPe := pe
    candidatePe := pe
    originalImportCertificate := {{ descriptors := [] }}
    candidateImportCertificate := {{ descriptors := [] }}
    originalRelocations := []
    candidateRelocations := []
    codeMap := exactDecodeMap
    dataMap := {{ entries := #[], originalOrder := [], candidateOrder := [] }}
    roots := []
    observations := {{}}
  }}
  let decoded <- exactDecodeRegion.decode? context
  pure (exactDecodeTable.behaviorChecked decoded.original decoded.candidate)

example : exactDecodeBehaviorChecked exactGoodBytes = some true := by decide +kernel
example : exactDecodeBehaviorChecked exactBadScaleBytes = some false := by decide +kernel
example : exactDecodeBehaviorChecked exactBadRegisterBytes = some false := by decide +kernel
example : exactDecodeBehaviorChecked exactBadOffsetBytes = some false := by decide +kernel
"""


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


_KERNEL_FIXTURE = r"""import StageA.RelationalNullableCodePointerDispatch

namespace StageA.NullableCodePointerDispatchKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.NullableCodePointerTable
open StageA.Relational.NullableCodePointerDispatch

set_option maxRecDepth 1000000

def pe : PE32 := {
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

def codeMap : StaticCodeMap := {
  entries := .leaf [
    { id := 0, originalRva := 4096, candidateRva := 4096 },
    { id := 1, originalRva := 4112, candidateRva := 4112 },
    { id := 2, originalRva := 4128, candidateRva := 4128 },
    { id := 3, originalRva := 4144, candidateRva := 4144 },
    { id := 4, originalRva := 4160, candidateRva := 4160 },
    { id := 5, originalRva := 4176, candidateRva := 4176 },
    { id := 6, originalRva := 4192, candidateRva := 4192 }
  ]
  originalAddresses := .leaf [
    { targetId := 0, kind := .canonical },
    { targetId := 1, kind := .canonical },
    { targetId := 2, kind := .canonical },
    { targetId := 3, kind := .canonical },
    { targetId := 4, kind := .canonical },
    { targetId := 5, kind := .canonical },
    { targetId := 6, kind := .canonical }
  ]
  candidateAddresses := .leaf [
    { targetId := 0, kind := .canonical },
    { targetId := 1, kind := .canonical },
    { targetId := 2, kind := .canonical },
    { targetId := 3, kind := .canonical },
    { targetId := 4, kind := .canonical },
    { targetId := 5, kind := .canonical },
    { targetId := 6, kind := .canonical }
  ]
}

def context : StaticProofContext := {
  originalPe := pe
  candidatePe := pe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap
  dataMap := { entries := #[], originalOrder := [], candidateOrder := [] }
  roots := []
  observations := {}
}

def table : BoundedImmutableCodePointerTableCallClaim := {
  valueTargetId := 0
  tableOffset := 0
  originalBase := 4202496
  candidateBase := 4202496
  layout := .sentinelTerminatedReverseCount
  upperExclusive := 1
  originalIndexRegister := .ebx
  candidateIndexRegister := .ebx
  continuationTargetId := 5
  rows := []
}

def scanner : ReverseSentinelScannerClaim := {
  table
  originalScannerRegister := .eax
  candidateScannerRegister := .eax
  originalCountRegister := .ebx
  candidateCountRegister := .ebx
  originalLoadedRegister := .edx
  candidateLoadedRegister := .edx
  testTargetId := 1
  scannerTargetId := 0
  bridgeTargetId := 2
}

def finiteRowTable : BoundedImmutableCodePointerTableCallClaim := {
  table with
  layout := .zeroBasedBounded
  upperExclusive := 1
  rows := [{ index := 0, targetId := 6 }]
}

def finiteRowsCertificate : Certificate := {
  peBytes := []
  contextId := 4
  dispatchRva := 4160
  tableRva := 8192
  headerWords := []
  callerRange := .exact { startRva := 8192, endRva := 8196 }
  codeMap := .exact [{ targetId := 6, rva := 4192 }]
  nonNullTargetIds := .exact [6]
  edges := .exact [{ sourceContextId := 4, targetId := 6 }]
  writers := .unknown
  aliases := .unknown
  loop := .exact {
    lowerInclusive := 0
    upperExclusive := 1
    step := 1
    addressBaseRva := 8192
    addressScale := 4
    alignment := 4
  }
  guard := .exact .nonzero
}

example : tableCertificateRowsMatch finiteRowsCertificate finiteRowTable = true := by
  decide +kernel
example : tableCertificateRowsMatch finiteRowsCertificate
    ({ finiteRowTable with rows := [] }) = false := by decide +kernel
example : tableCertificateRowsMatch
    ({ finiteRowsCertificate with edges := .exact [] }) finiteRowTable = false := by
  decide +kernel

def certificate : Certificate := {
  peBytes := []
  contextId := 4
  dispatchRva := 4160
  tableRva := 8192
  headerWords := [4294967295]
  callerRange := .unknown
  codeMap := .unknown
  nonNullTargetIds := .unknown
  edges := .unknown
  writers := .unknown
  aliases := .unknown
  loop := .unknown
  guard := .unknown
}

def region (target rva size : Nat) : PairedDecodedRegionRef := {
  targetId := target
  originalSpan := { start := rva, size }
  candidateSpan := { start := rva, size }
}

def invariant : StateInvariant := { registerRelations := [] }

def binding : Claim := {
  tableCertificate := certificate
  tableCall := table
  scanner
  scannerSourceInvariant := invariant
  scannerPostInvariant := invariant
  scannerFinishedInvariant := invariant
  dispatchInvariant := invariant
  scannerRegion := region 0 4096 4
  testRegion := region 1 4112 4
  bridgeRegion := region 2 4128 4
  guardRegion := region 3 4144 4
  dispatchRegion := region 4 4160 4
  dispatchBypassTargetId := 6
  dispatchPredecessorIds := [3]
  originalDispatchBase := 4202496
  candidateDispatchBase := 4202496
  dispatchScale := 4
  dispatchIndexOffset := 0
}

__EXACT_DECODE_FIXTURE__

def originalPe : PE32 := (parsePE32 exactGoodBytes).getD pe

def originalCodeMap : OriginalCodeMap := {
  entries := .leaf [
    { id := 0, regionIndex := 0, rva := 4096 },
    { id := 1, regionIndex := 1, rva := 4112 },
    { id := 2, regionIndex := 2, rva := 4128 },
    { id := 3, regionIndex := 3, rva := 4144 },
    { id := 4, regionIndex := 4, rva := 4160 },
    { id := 5, regionIndex := 5, rva := 4176 },
    { id := 6, regionIndex := 6, rva := 4192 }
  ]
  addresses := .leaf [
    { targetId := 0, kind := .canonical },
    { targetId := 1, kind := .canonical },
    { targetId := 2, kind := .canonical },
    { targetId := 3, kind := .canonical },
    { targetId := 4, kind := .canonical },
    { targetId := 5, kind := .canonical },
    { targetId := 6, kind := .canonical }
  ]
}

def originalRegions : FiniteIndex OriginalDecodedRegion := .leaf [
  { id := 0, span := { start := 4096, size := 4 }, root := true,
    targets := [1] },
  { id := 1, span := { start := 4112, size := 4 }, root := false,
    targets := [0, 2] },
  { id := 2, span := { start := 4128, size := 4 }, root := false,
    targets := [3] },
  { id := 3, span := { start := 4144, size := 4 }, root := false,
    targets := [4, 6] },
  { id := 4, span := { start := 4160, size := 4 }, root := false,
    targets := [5] },
  { id := 5, span := { start := 4176, size := 4 }, root := false,
    targets := [4] },
  { id := 6, span := { start := 4192, size := 4 }, root := false,
    targets := [] }
]

def originalContext : OriginalDecodedStaticContext := {
  pe := originalPe
  importCertificate := { descriptors := [] }
  relocations := []
  codeMap := originalCodeMap
  regions := originalRegions
}

def originalRegionsExtraIncoming : FiniteIndex OriginalDecodedRegion := .leaf [
  { id := 0, span := { start := 4096, size := 4 }, root := true,
    targets := [1] },
  { id := 1, span := { start := 4112, size := 4 }, root := false,
    targets := [0, 2] },
  { id := 2, span := { start := 4128, size := 4 }, root := false,
    targets := [3] },
  { id := 3, span := { start := 4144, size := 4 }, root := false,
    targets := [4, 6] },
  { id := 4, span := { start := 4160, size := 4 }, root := false,
    targets := [5] },
  { id := 5, span := { start := 4176, size := 4 }, root := false,
    targets := [4] },
  { id := 6, span := { start := 4192, size := 4 }, root := false,
    targets := [4] }
]

def originalContextExtraIncoming : OriginalDecodedStaticContext := {
  originalContext with regions := originalRegionsExtraIncoming
}

def rootedCertificate : RootedSccCertificate := {
  rootTargetIds := [0]
  rootPathTargetIds := [0, 1, 2, 3, 4]
  forwardTargetIds := [4, 5]
  sccTargetIds := [4, 5]
  incomingEdges := [
    { sourceTargetId := 3, targetTargetId := 4 },
    { sourceTargetId := 5, targetTargetId := 4 },
    { sourceTargetId := 4, targetTargetId := 5 }
  ]
}

example : binding.bindingShapeChecked context = true := by decide +kernel
example : ({ binding with dispatchScale := 8 }).bindingShapeChecked context = false := by
  decide +kernel
example : ({ binding with dispatchIndexOffset := 1 }).bindingShapeChecked context = false := by
  decide +kernel
example : ({ binding with dispatchPredecessorIds := [] }).bindingShapeChecked context = false := by
  decide +kernel
example : ({ binding with dispatchPredecessorIds := [3, 2] }).bindingShapeChecked context = false := by
  decide +kernel
example : ({ binding with tableCertificate := ({ certificate with contextId := 5 }) }).bindingShapeChecked context = false := by
  decide +kernel
example : ({ binding with dispatchRegion := region 5 4176 4 }).bindingShapeChecked context = false := by
  decide +kernel
example : originalRootPathChecked originalContext 4
    rootedCertificate.rootPathTargetIds = true := by
  decide +kernel
example :
    rootedCertificate.rootTargetIds ==
      originalRootTargetIds originalContext := by
  decide +kernel
example :
    [0, 6] != originalRootTargetIds originalContext := by
  decide +kernel
example : originalRootPathChecked originalContext 4
    [0, 1, 3, 4] = false := by
  decide +kernel
example : originalSccChecked originalContext 4 [4, 5] = true := by
  decide +kernel
example : originalSccChecked originalContext 4 [4] = false := by
  decide +kernel
example : originalSccBoundaryChecked originalContext 4
    rootedCertificate.forwardTargetIds rootedCertificate.sccTargetIds
      rootedCertificate.incomingEdges = true := by
  decide +kernel
example : originalSccBoundaryChecked originalContextExtraIncoming 4
    rootedCertificate.forwardTargetIds rootedCertificate.sccTargetIds
      rootedCertificate.incomingEdges = false := by
  decide +kernel
example : rootedCertificate.incomingEdges =
    originalIncomingEdgesForTargets originalContext rootedCertificate.sccTargetIds := by
  decide +kernel
example :
    rootedCertificate.incomingEdges !=
      originalIncomingEdgesForTargets originalContextExtraIncoming
        rootedCertificate.sccTargetIds := by
  decide +kernel

def registers : Registers Expr := initialSymbolic.registers

def bridgeGood : DecodedRegionBehavior := {
  original := {
    registers := registers
    x87 := initialSymbolicX87
    writes := []
    flags := none
    outcome := .jump 3
  }
  candidate := {
    registers := registers
    x87 := initialSymbolicX87
    writes := []
    flags := none
    outcome := .jump 3
  }
}

def bridgeBadRegister : DecodedRegionBehavior := {
  bridgeGood with original := ({ bridgeGood.original with
    registers := registers.set .ebx (.inputReg .eax) })
}

example : bridgeBehaviorChecked scanner 3 bridgeGood = true := by decide +kernel
example : bridgeBehaviorChecked scanner 3 bridgeBadRegister = false := by decide +kernel
example : bridgeBehaviorChecked scanner 2 bridgeGood = false := by decide +kernel

def guardGood : DecodedRegionBehavior := {
  original := {
    registers := registers
    x87 := initialSymbolicX87
    writes := []
    flags := none
    outcome := .branch (registerNonzeroGuard .ebx) 4 6
  }
  candidate := {
    registers := registers
    x87 := initialSymbolicX87
    writes := []
    flags := none
    outcome := .branch (registerNonzeroGuard .ebx) 4 6
  }
}

def guardBadExpression : DecodedRegionBehavior := {
  guardGood with original := ({ guardGood.original with
    outcome := .branch (.equal (.inputReg .ebx) (.constant 0)) 4 6 })
}

def guardBadBypass : DecodedRegionBehavior := {
  guardGood with candidate := ({ guardGood.candidate with
    outcome := .branch (registerNonzeroGuard .ebx) 4 5 })
}

example : dispatchGuardBehaviorChecked scanner 4 guardGood = true := by decide +kernel
example : dispatchGuardBehaviorChecked scanner 4 guardBadExpression = false := by
  decide +kernel
example : dispatchGateBehaviorChecked scanner 4 6 guardGood = true := by
  decide +kernel
example : dispatchGateBehaviorChecked scanner 4 6 guardBadBypass = false := by
  decide +kernel
example : NormalizedOutcomeExpr.guardForTarget
    (.branch (registerNonzeroGuard .ebx) 4 4) 4 = none := by decide +kernel

def dispatchGood : DecodedRegionBehavior := {
  original := {
    registers := registers
    x87 := initialSymbolicX87
    writes := []
    flags := none
    outcome := .indirectCall table.originalTargetExpression 5
  }
  candidate := {
    registers := registers
    x87 := initialSymbolicX87
    writes := []
    flags := none
    outcome := .indirectCall table.candidateTargetExpression 5
  }
}

def dispatchBadExpression : DecodedRegionBehavior := {
  dispatchGood with original := ({ dispatchGood.original with
    outcome := .indirectCall (.read32 (.inputReg .eax)) 5 })
}

def dispatchBadContinuation : DecodedRegionBehavior := {
  dispatchGood with candidate := ({ dispatchGood.candidate with
    outcome := .indirectCall table.candidateTargetExpression 6 })
}

example : table.behaviorChecked dispatchGood.original dispatchGood.candidate = true := by
  decide +kernel
example : table.behaviorChecked dispatchBadExpression.original
    dispatchBadExpression.candidate = false := by decide +kernel
example : table.behaviorChecked dispatchBadContinuation.original
    dispatchBadContinuation.candidate = false := by decide +kernel

def testGood : DecodedRegionBehavior := {
  original := {
    registers := registers
    x87 := initialSymbolicX87
    writes := []
    flags := none
    outcome := .branch scanner.loopGuard 0 2
  }
  candidate := {
    registers := registers
    x87 := initialSymbolicX87
    writes := []
    flags := none
    outcome := .branch scanner.loopGuard 0 2
  }
}

def testBadEdge : DecodedRegionBehavior := {
  testGood with candidate := ({ testGood.candidate with
    outcome := .branch scanner.loopGuard 0 3 })
}

example : scanner.testBehaviorChecked testGood.original testGood.candidate = true := by
  decide +kernel
example : scanner.testBehaviorChecked testBadEdge.original testBadEdge.candidate = false := by
  decide +kernel

example (certificate : Certificate) (table : BoundedImmutableCodePointerTableCallClaim)
    (mismatch : ByteTree.ofBytes certificate.peBytes ≠ context.originalPe.bytes) :
    tableCertificateCheckedAgainst context certificate table = false := by
  simp [tableCertificateCheckedAgainst, mismatch]

example (context : StaticProofContext) (claim : Claim)
    (cluster : DecodedDispatchCluster)
    (empty : claim.tableCall.entryCount = 0)
    (checked : Claim.semanticChecked context claim cluster = true) :
    EmptyLocalDispatchClosed context claim cluster :=
  emptyLocalDispatchClosed_of_semantic_checked context claim cluster empty checked

example (context : StaticProofContext) (claim : Claim)
    (cluster : DecodedDispatchCluster)
    (actualReachable : RelationalWorld → MachineState → MachineState → Prop)
    (structurallyValid : context.StructurallyValid)
    (decoded : claim.cluster? context = some cluster)
    (checked : claim.checked context = true)
    (complete : claim.tableCall.entryCount = 0 →
      CompleteDispatchPredecessorPremise context claim cluster actualReachable) :
    ActualDecodedMixedDispatchClosure context claim cluster actualReachable :=
  actualDecodedMixedDispatchClosure_of_checked context claim cluster
    actualReachable structurallyValid decoded checked complete

#print axioms emptyLocalDispatchClosed_of_semantic_checked
#print axioms actualDispatchSourceUninhabited_of_complete_predecessors
#print axioms actualDecodedMixedDispatchClosure_of_checked
#print axioms sourceUninhabited_of_checkedRootedScc
#print axioms originalIndirectControlClosure_of_checkedRootedScc

end StageA.NullableCodePointerDispatchKernel
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageANullableCodePointerDispatchKernelTests(unittest.TestCase):
    source_root = (
        Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
    )

    def test_bridge_semantics_and_fail_closed_mutations_are_kernel_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                self.source_root,
                stage_a,
                "RelationalNullableCodePointerDispatch",
            )
            (stage_a / "NullableCodePointerDispatchKernel.lean").write_text(
                _KERNEL_FIXTURE.replace(
                    "__EXACT_DECODE_FIXTURE__", _exact_decode_fixture()
                ),
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="NullableCodePointerDispatchKernel"
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
