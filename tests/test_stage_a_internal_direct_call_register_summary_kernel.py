from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.internal_direct_call_register_summary import (
    INTERNAL_DIRECT_CALL_REGISTER_SUMMARY_LEAN_FILENAME,
    InternalDirectCallRegisterSummaryLeanBindings,
    LeanCalleeEdge,
    LeanExactRegionPair,
    LeanFiniteIndirectJumpDependency,
    LeanInternalDirectCallRegisterCertificate,
    LeanInternalDirectCallRegisterSummaryTree,
    LeanMachineImportDependency,
    LeanReturnInventoryEntry,
    LeanSpan,
    LeanStackEntryOffsetWitness,
    LeanStackSaveRestoreWitness,
    internal_direct_call_register_summary_module_dag,
    internal_direct_call_register_summary_source,
)
from tests.test_stage_a_internal_direct_call_register_summary import (
    nested_summary,
    push_pop_summary,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound"}
_FIXTURE_MODULE = "StageA.InternalDirectCallRegisterSummaryFixture"
_FIXTURE_NAMESPACE = "StageA.Generated.InternalDirectCallFixture"


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


def _pe_source(bytes_: list[int], *, imports_source: str = "def imports : List PEImport := []") -> str:
    byte_literal = ", ".join(hex(value) for value in bytes_)
    return f"""import StageA.RelationalInternalDirectCallRegisterSummary

namespace {_FIXTURE_NAMESPACE}

open StageA.Formal StageA.Relational
open StageA.Relational.StaticMachineImportContracts

def pe : PE32 := {{
  bytes := ByteTree.ofBytes [{byte_literal}]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := {len(bytes_)}
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{{
    virtualSize := {len(bytes_)}
    virtualAddress := 0
    rawSize := {len(bytes_)}
    rawPointer := 0
    characteristics := 0x60000020
  }}]
}}

{imports_source}

end {_FIXTURE_NAMESPACE}
"""


_NESTED_BYTES = [
    0xE8, 0x05, 0x00, 0x00, 0x00,
    0xC3,
    0x90, 0x90, 0x90, 0x90,
    0xE8, 0x05, 0x00, 0x00, 0x00,
    0xC3,
    0x90, 0x90, 0x90, 0x90,
    0xEB, 0x00,
    0xC3,
]

_PUSH_POP_BYTES = [
    0xE8, 0x05, 0x00, 0x00, 0x00,
    0xC3,
    0x90, 0x90, 0x90, 0x90,
    0x56, 0xEB, 0x00,
    0xBE, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x00,
    0x5E, 0xC3,
]

_FINITE_INDIRECT_BYTES = [
    0xE8, 0x05, 0x00, 0x00, 0x00,
    0xC3,
    0x90, 0x90, 0x90, 0x90,
    0xFF, 0x24, 0x85, 0x20, 0x00, 0x40, 0x00,
    0xEB, 0x09,
    0xEB, 0x07,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xC3,
    0x90, 0x90, 0x90,
    0x11, 0x00, 0x40, 0x00,
    0x13, 0x00, 0x40, 0x00,
]


def _region(region_id: int, start: int, size: int) -> LeanExactRegionPair:
    span = LeanSpan(start, size)
    return LeanExactRegionPair(region_id, span, span)


def _split_control_summary() -> tuple[
    LeanInternalDirectCallRegisterSummaryTree,
    list[int],
]:
    region_count = 65
    call = _region(0, 0, 5)
    continuation = _region(1, 5, 1)
    bytes_ = [
        0xE8, 0x05, 0x00, 0x00, 0x00,
        0xC3,
        0x90, 0x90, 0x90, 0x90,
    ]
    callee_regions = [_region(100, 10, 6)]
    edges = [LeanCalleeEdge(100, 101, "direct")]
    bytes_.extend((0x56, 0xE9, 0x00, 0x00, 0x00, 0x00))
    for index in range(1, region_count - 1):
        start = 16 + (index - 1) * 5
        region_id = 100 + index
        callee_regions.append(_region(region_id, start, 5))
        edges.append(LeanCalleeEdge(region_id, region_id + 1, "direct"))
        bytes_.extend((0xE9, 0x00, 0x00, 0x00, 0x00))
    returned = _region(
        100 + region_count - 1,
        16 + (region_count - 2) * 5,
        2,
    )
    callee_regions.append(returned)
    bytes_.extend((0x5E, 0xC3))
    certificate = LeanInternalDirectCallRegisterCertificate(
        summary_id=6,
        dependency_depth=0,
        caller=call,
        callsite=call,
        callee_entry=callee_regions[0],
        continuation=continuation,
        callee_regions=tuple(callee_regions),
        edges=tuple(edges),
        returns=(LeanReturnInventoryEntry(returned.region_id, 1),),
        requested_registers=("esi", "esp"),
        original_frame_bytes=4,
        candidate_frame_bytes=4,
        stack_witnesses=(
            LeanStackSaveRestoreWitness(
                "esi",
                callee_regions[0].region_id,
                (returned.region_id,),
                4,
                4,
                4,
                4,
            ),
        ),
    )
    return LeanInternalDirectCallRegisterSummaryTree(certificate), bytes_


def _ungrounded_summary() -> LeanInternalDirectCallRegisterSummaryTree:
    call = _region(0, 0, 5)
    outer_continuation = _region(1, 5, 1)
    imported_call = _region(10, 10, 6)
    callee_return = _region(11, 16, 1)
    dependency = LeanMachineImportDependency(
        7,
        10,
        11,
        f"{_FIXTURE_NAMESPACE}.required",
        f"{_FIXTURE_NAMESPACE}.required",
        f"{_FIXTURE_NAMESPACE}.signatures",
        f"{_FIXTURE_NAMESPACE}.signatures",
        f"{_FIXTURE_NAMESPACE}.boundary",
        f"{_FIXTURE_NAMESPACE}.boundary",
    )
    certificate = LeanInternalDirectCallRegisterCertificate(
        summary_id=4,
        dependency_depth=0,
        caller=call,
        callsite=call,
        callee_entry=imported_call,
        continuation=outer_continuation,
        callee_regions=(imported_call, callee_return),
        edges=(LeanCalleeEdge(10, 11, "machine_import", 7),),
        returns=(LeanReturnInventoryEntry(11, 1),),
        requested_registers=("esi",),
        machine_import_dependencies=(dependency,),
    )
    return LeanInternalDirectCallRegisterSummaryTree(certificate)


def _finite_indirect_summary() -> LeanInternalDirectCallRegisterSummaryTree:
    call = _region(0, 0, 5)
    outer_continuation = _region(1, 5, 1)
    dispatch = _region(10, 10, 7)
    first = _region(17, 17, 2)
    second = _region(19, 19, 2)
    returned = _region(28, 28, 1)
    dependency = LeanFiniteIndirectJumpDependency(
        dependency_id=10,
        source_region_id=10,
        original_table_base=0x400020,
        candidate_table_base=0x400020,
        upper_exclusive=2,
        original_index_expression={"op": "reg", "name": "eax"},
        candidate_index_expression={"op": "reg", "name": "eax"},
        entry_target_region_ids=(17, 19),
    )
    certificate = LeanInternalDirectCallRegisterCertificate(
        summary_id=5,
        dependency_depth=0,
        caller=call,
        callsite=call,
        callee_entry=dispatch,
        continuation=outer_continuation,
        callee_regions=(dispatch, first, second, returned),
        edges=(
            LeanCalleeEdge(10, 17, "finite_indirect", 10),
            LeanCalleeEdge(10, 19, "finite_indirect", 10),
            LeanCalleeEdge(17, 28, "direct"),
            LeanCalleeEdge(19, 28, "direct"),
        ),
        returns=(LeanReturnInventoryEntry(28, 1),),
        requested_registers=("esi",),
        finite_indirect_dependencies=(dependency,),
    )
    return LeanInternalDirectCallRegisterSummaryTree(certificate)


def _state_only_x87_summary() -> LeanInternalDirectCallRegisterSummaryTree:
    call = _region(0, 0, 5)
    continuation = _region(1, 5, 1)
    wait = _region(10, 10, 1)
    returned = _region(11, 11, 1)
    certificate = LeanInternalDirectCallRegisterCertificate(
        summary_id=7,
        dependency_depth=0,
        caller=call,
        callsite=call,
        callee_entry=wait,
        continuation=continuation,
        callee_regions=(wait, returned),
        edges=(LeanCalleeEdge(10, 11, "direct"),),
        returns=(LeanReturnInventoryEntry(11, 1),),
        requested_registers=("ebx", "esp"),
        stack_entry_offsets=(
            LeanStackEntryOffsetWitness(10, 0, 0),
            LeanStackEntryOffsetWitness(11, 0, 0),
        ),
    )
    return LeanInternalDirectCallRegisterSummaryTree(certificate)


_STATE_ONLY_X87_BYTES = [
    0xE8, 0x05, 0x00, 0x00, 0x00,
    0xC3,
    0x90, 0x90, 0x90, 0x90,
    0x9B,
    0xC3,
]


_UNGROUNDED_IMPORTS = """def fakeImport : PEImport := {
  dll := [0x66, 0x61, 0x6b, 0x65, 0x2e, 0x64, 0x6c, 0x6c]
  name := .symbol [0x66]
  iatRva := 0
}

def imports : List PEImport := [fakeImport]
def required : List ExternalTarget := [normalizeImport fakeImport]
def signature : StaticMachineImportSignature := {
  id := 7
  imported := normalizeImport fakeImport
  abi := .cdecl
  arity := .fixed 0
  disposition := .returns
  memoryEffect := .none
  worldEffect := .none
}
def signatures : List StaticMachineImportSignature := [signature]
def boundary : StaticMachineImportBoundary := {
  id := 7
  signatureId := 7
  instructionRva := 10
  executionSourceRva := 10
  continuationRva := 16
  argumentWords := 0
  route := .direct { start := 10, size := 6 }
}"""


_SEMANTIC_EXAMPLES = """import StageA.RelationalInternalDirectCallRegisterSummary

namespace StageA.Generated.InternalDirectCallRegisterSummarySemanticExamples

open StageA.Formal
open StageA.Relational.InternalDirectCallRegisterSummary

def saveBehavior : SymbolicBehavior := {
  initialSymbolic with
  registers := { initialSymbolic.registers with esp := stackSub 4 }
  writes := [(stackSub 4, .inputReg .esi)]
}

def restoreBehavior : SymbolicBehavior := {
  initialSymbolic with
  registers := {
    initialSymbolic.registers with
    esi := .read32 (stackAdd 0)
    esp := stackAdd 8
  }
  writes := []
  outcome := some (.returned (.read32 (stackAdd 4)))
}

def protectedWrite : Expr × Expr :=
  (.add (.inputReg .edx) (.constant 32), .inputReg .eax)

def restoreAfterWritesBehavior : SymbolicBehavior := {
  initialSymbolic with
  registers := {
    initialSymbolic.registers with
    esi := symbolicRead32FromWrites [protectedWrite] (stackAdd 0)
    esp := stackAdd 8
  }
  writes := [protectedWrite]
  outcome := some (.returned
    (symbolicRead32FromWrites [protectedWrite] (stackAdd 4)))
}

def tamperedRestoreAfterWritesBehavior : SymbolicBehavior := {
  restoreAfterWritesBehavior with
  registers := {
    restoreAfterWritesBehavior.registers with
    esi := symbolicRead32FromWrites [] (stackAdd 0)
  }
}

def bulkCopyBehavior : SymbolicBehavior := {
  initialSymbolic with
  outcome := some (.bulkCopy {
    destination := .inputReg .edi
    source := .inputReg .esi
    count := .constant 1
    direction := .equal (.constant 0) (.constant 1)
  } 1)
}

def nestedCallSaveBehavior : SymbolicBehavior := {
  initialSymbolic with
  registers := { initialSymbolic.registers with esp := stackSub 48 }
  writes := [
    (stackSub 4, .inputReg .esi),
    (stackSub 8, .inputReg .ebx),
    (stackSub 48, .constant 0x401000)
  ]
  outcome := some (.call 32 16 0x401000)
}

def unexplainedExtraStackBehavior : SymbolicBehavior := {
  nestedCallSaveBehavior with outcome := none
}

theorem saveBlockEval (state : MachineState) :
    (saveBehavior.eval state).memory =
      state.memory.write32 ((stackSub 4).eval state) state.registers.esi :=
  (stackSaveSideChecked_eval saveBehavior .esi 4 4 (by decide) state).2

theorem restoreBlockEval (state : MachineState) :
    (restoreBehavior.eval state).registers.get .esi =
      state.read32 (state.registers.esp +
        (0 - (BitVec.ofNat 32 4 + BitVec.ofNat 32 4294967292))) :=
  (stackRestoreSideChecked_eval restoreBehavior .esi 4294967292 4
    (by rfl) state).1

theorem restoreAfterWritesIsProtected :
    And
      (stackRestoreSideChecked restoreAfterWritesBehavior .esi 4294967292 4 = false)
      (stackRestoreAfterWritesSideChecked
        restoreAfterWritesBehavior .esi 4294967292 4 = true) := by
  decide

theorem tamperedRestoreAfterWritesRejected :
    stackRestoreAfterWritesSideChecked
      tamperedRestoreAfterWritesBehavior .esi 4294967292 4 = false := by
  decide

theorem stoppingMemoryEffectsAreProtected :
    And
      (behaviorHasInternalMemoryWrite bulkCopyBehavior = true)
      (behaviorHasInternalMemoryWrite initialSymbolic = false) := by
  decide

theorem terminalCallFrameIsAccountedFor :
    And
      (stackFrameSaveSideChecked nestedCallSaveBehavior .ebx 44 8 = true)
      (stackFrameSaveSideChecked unexplainedExtraStackBehavior .ebx 44 8 = false) := by
  decide

theorem identityPathEval (state : MachineState) :
    (runSymbolicBehaviorPath [initialSymbolic, initialSymbolic] state).registers.esi =
      state.registers.esi := by
  change (runSymbolicBehaviorPath [initialSymbolic, initialSymbolic] state).registers.get
      .esi = state.registers.get .esi
  apply runSymbolicBehaviorPath_identity_preserved
  intro behavior member
  simp at member
  subst behavior
  rfl

#print axioms saveBlockEval
#print axioms restoreBlockEval
#print axioms restoreAfterWritesIsProtected
#print axioms tamperedRestoreAfterWritesRejected
#print axioms stoppingMemoryEffectsAreProtected
#print axioms terminalCallFrameIsAccountedFor
#print axioms identityPathEval

end StageA.Generated.InternalDirectCallRegisterSummarySemanticExamples
"""


_FINITE_ORIGIN_ENTRY_MAPPING_EXAMPLES = """
import StageA.RelationalInternalDirectCallRegisterSummary

namespace StageA.Generated.FiniteOriginEntryMappingExamples

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

def pe : PE32 := {
  bytes := .empty
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 0x3000
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}

def targets : List CodeTargetPair := [
  { id := 0, regionIndex := 700, originalRva := 0x1000,
    candidateRva := 0x1000 },
  { id := 1, regionIndex := 701, originalRva := 0x1010,
    candidateRva := 0x1010 },
  { id := 2, regionIndex := 702, originalRva := 0x2000,
    candidateRva := 0x2000 }
]

def codeMap : StaticCodeMap := {
  entries := .leaf targets
  originalAddresses := .leaf [
    { targetId := 0, kind := .canonical },
    { targetId := 1, kind := .canonical },
    { targetId := 2, kind := .canonical }
  ]
  candidateAddresses := .leaf [
    { targetId := 0, kind := .canonical },
    { targetId := 1, kind := .canonical },
    { targetId := 2, kind := .canonical }
  ]
}

def contextWith (mapping : StaticCodeMap) : StaticProofContext := {
  originalPe := pe
  candidatePe := pe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap := mapping
  dataMap := { entries := #[], originalOrder := [], candidateOrder := [] }
  roots := []
  observations := {}
}

def context : StaticProofContext := contextWith codeMap

def region (id start size : Nat) : ExactRegionPair := {
  id
  original := { start, size }
  candidate := { start, size }
}

def certificate : Certificate := {
  summaryId := 41
  caller := region 0x1000 0x1000 5
  callsite := region 0x1000 0x1000 5
  calleeEntry := region 0x2000 0x2000 2
  continuation := region 0x1010 0x1010 1
  calleeRegions := [region 0x2000 0x2000 2]
  edges := []
  returns := []
  requestedRegisters := []
  entryKind := .finiteOriginCall 17 2
}

def authority : ValueProvenance.IndirectExitCertificate := {
  finiteAlternativeBudget := 1
  target := {
    original := .constant 0x402000
    candidate := .constant 0x402000
    source := .exactExpression
    origin := { alternatives := [.staticCodeTarget 2 0] }
  }
  destinations := [.internalCode 2]
  transfer := .call 1
}

def report : FiniteOriginCallEntryCheckReport :=
  certificate.finiteOriginCallEntryCheckReport
    (context := context) 0 2 1 authority pe pe [] []

example : report.sourceMapped = true := by decide
example : report.continuationMapped = true := by decide
example : report.calleeMapped = true := by decide

-- Target IDs index the canonical code map. Local region IDs and regionIndex
-- values are deliberately different domains and must not affect this lookup.
example : certificate.callsite.id = 0x1000 := by decide
example : (codeMap.get? 0).map (fun target => target.regionIndex) = some 700 := by
  decide

def missingTargetReport : FiniteOriginCallEntryCheckReport :=
  certificate.finiteOriginCallEntryCheckReport
    (context := context) 3 2 1 authority pe pe [] []

example : missingTargetReport.sourceMapped = false := by decide

def wrongRvaTargets : List CodeTargetPair := [
  { id := 0, regionIndex := 700, originalRva := 0x1001,
    candidateRva := 0x1000 },
  { id := 1, regionIndex := 701, originalRva := 0x1010,
    candidateRva := 0x1010 },
  { id := 2, regionIndex := 702, originalRva := 0x2000,
    candidateRva := 0x2000 }
]

def wrongRvaCodeMap : StaticCodeMap := {
  codeMap with
  entries := .leaf wrongRvaTargets
}

def wrongRvaReport : FiniteOriginCallEntryCheckReport :=
  certificate.finiteOriginCallEntryCheckReport
    (context := contextWith wrongRvaCodeMap) 0 2 1 authority pe pe [] []

example : wrongRvaReport.sourceMapped = false := by decide

#print axioms report
#print axioms missingTargetReport
#print axioms wrongRvaReport

end StageA.Generated.FiniteOriginEntryMappingExamples
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAInternalDirectCallRegisterSummaryKernelTests(unittest.TestCase):
    source_root = (
        Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
    )

    def _compile(
        self,
        summary: LeanInternalDirectCallRegisterSummaryTree,
        bytes_: list[int],
        *,
        expectation: str = "accepted",
        imports_source: str = "def imports : List PEImport := []",
    ) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                self.source_root,
                stage_a,
                "RelationalInternalDirectCallRegisterSummary",
            )
            (stage_a / "InternalDirectCallRegisterSummaryFixture.lean").write_text(
                _pe_source(bytes_, imports_source=imports_source),
                encoding="utf-8",
            )
            bindings = InternalDirectCallRegisterSummaryLeanBindings(
                original_pe=f"{_FIXTURE_NAMESPACE}.pe",
                candidate_pe=f"{_FIXTURE_NAMESPACE}.pe",
                original_imports=f"{_FIXTURE_NAMESPACE}.imports",
                candidate_imports=f"{_FIXTURE_NAMESPACE}.imports",
                imports=(_FIXTURE_MODULE,),
            )
            (stage_a / INTERNAL_DIRECT_CALL_REGISTER_SUMMARY_LEAN_FILENAME).write_text(
                internal_direct_call_register_summary_source(
                    summary, bindings, expectation=expectation
                ),
                encoding="utf-8",
            )
            return _run_lean_relational(
                root,
                bundle="GeneratedRelationalInternalDirectCallRegisterSummary",
            )

    def _assert_checked(self, result: dict, *, expect_axioms: bool) -> None:
        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        if expect_axioms:
            self.assertGreaterEqual(len(reports), 1, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

    def _compile_module_dag(
        self,
        summary: LeanInternalDirectCallRegisterSummaryTree,
        bytes_: list[int],
    ) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                self.source_root,
                stage_a,
                "RelationalInternalDirectCallRegisterSummary",
            )
            (stage_a / "InternalDirectCallRegisterSummaryFixture.lean").write_text(
                _pe_source(bytes_),
                encoding="utf-8",
            )
            bindings = InternalDirectCallRegisterSummaryLeanBindings(
                original_pe=f"{_FIXTURE_NAMESPACE}.pe",
                candidate_pe=f"{_FIXTURE_NAMESPACE}.pe",
                original_imports=f"{_FIXTURE_NAMESPACE}.imports",
                candidate_imports=f"{_FIXTURE_NAMESPACE}.imports",
                imports=(_FIXTURE_MODULE,),
            )
            dag = internal_direct_call_register_summary_module_dag(
                summary,
                bindings,
                root_namespace="StageA.Generated.ModuleDagRoot",
            )
            for module in dag.all_modules:
                relative = module.module.removeprefix("StageA.")
                (stage_a / f"{relative}.lean").write_text(
                    module.source,
                    encoding="utf-8",
                )
            bundle = "InternalDirectCallRegisterSummaryModuleDagRoot"
            (stage_a / f"{bundle}.lean").write_text(
                dag.root_source,
                encoding="utf-8",
            )
            return _run_lean_relational(root, bundle=bundle)

    def _compile_semantic_examples(self) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                self.source_root,
                stage_a,
                "RelationalInternalDirectCallRegisterSummary",
            )
            bundle = "InternalDirectCallRegisterSummarySemanticExamples"
            (stage_a / f"{bundle}.lean").write_text(
                _SEMANTIC_EXAMPLES,
                encoding="utf-8",
            )
            return _run_lean_relational(root, bundle=bundle)

    def _compile_finite_origin_entry_mapping_examples(self) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                self.source_root,
                stage_a,
                "RelationalInternalDirectCallRegisterSummary",
            )
            bundle = "FiniteOriginEntryMappingExamples"
            (stage_a / f"{bundle}.lean").write_text(
                _FINITE_ORIGIN_ENTRY_MAPPING_EXAMPLES,
                encoding="utf-8",
            )
            return _run_lean_relational(root, bundle=bundle)

    def test_reviewed_module_has_no_escape_hatches(self) -> None:
        source = (
            self.source_root / "RelationalInternalDirectCallRegisterSummary.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertNotIn("def Certificate.Preserves", source)
        self.assertNotIn("def SummaryTree.Preserves", source)
        self.assertNotIn("theorem SummaryTree.checked_sound", source)
        self.assertIn("theorem SummaryTree.checked_structuralEvidence", source)
        self.assertIn("theorem stackSaveSideChecked_eval", source)
        self.assertIn("theorem regionIdentitySideChecked_eval", source)
        self.assertIn("theorem stackRestoreSideChecked_eval", source)
        self.assertIn("theorem runSymbolicBehaviorPath_register_preserved", source)
        self.assertIn(
            "theorem Certificate.registerPreservedChecked_of_stackWitness",
            source,
        )
        self.assertIn(
            "theorem Certificate.preservationChecked_of_registers",
            source,
        )
        self.assertIn("structure SemanticIntegrationRequirements", source)
        self.assertIn("standaloneAcceptanceAuthority := false", source)
        self.assertIn("staticMachineImportProfilesValid", source)
        self.assertIn("regionBehaviorWithImports", source)
        self.assertIn("import StageA.RelationalX87StateOnlyDecode", source)
        self.assertNotIn("import StageA.RelationalX87Decode", source)

        x87_profile = (
            self.source_root / "RelationalX87StateOnlyDecode.lean"
        ).read_text(encoding="utf-8")
        self.assertIn("import StageA.Formal", x87_profile)
        self.assertNotIn("import StageA.RelationalX87Decode", x87_profile)
        self.assertNotIn("import StageA.RelationalX87", x87_profile)

    def test_cacheable_module_dag_compiles(self) -> None:
        result = self._compile_module_dag(nested_summary(), _NESTED_BYTES)
        self._assert_checked(result, expect_axioms=True)

    def test_split_control_module_dag_compiles(self) -> None:
        summary, bytes_ = _split_control_summary()
        result = self._compile_module_dag(summary, bytes_)
        self._assert_checked(result, expect_axioms=True)

    def test_semantic_block_and_path_lemmas_are_kernel_checked(self) -> None:
        result = self._compile_semantic_examples()
        self._assert_checked(result, expect_axioms=True)

    def test_finite_origin_entry_uses_canonical_target_ids_and_exact_rvas(
        self,
    ) -> None:
        result = self._compile_finite_origin_entry_mapping_examples()
        self._assert_checked(result, expect_axioms=False)

    def test_nested_direct_call_inventory_derives_structural_evidence(self) -> None:
        result = self._compile(nested_summary(), _NESTED_BYTES)
        self._assert_checked(result, expect_axioms=True)

    def test_push_pop_stack_witness_derives_structural_evidence(self) -> None:
        result = self._compile(push_pop_summary(), _PUSH_POP_BYTES)
        self._assert_checked(result, expect_axioms=True)

    def test_finite_indirect_table_and_edges_derive_structural_evidence(self) -> None:
        result = self._compile(_finite_indirect_summary(), _FINITE_INDIRECT_BYTES)
        self._assert_checked(result, expect_axioms=True)

    def test_state_only_x87_region_derives_structural_evidence(self) -> None:
        result = self._compile(_state_only_x87_summary(), _STATE_ONLY_X87_BYTES)
        self._assert_checked(result, expect_axioms=True)

    def test_truncated_x87_region_is_kernel_checked_rejection(self) -> None:
        mutated = list(_STATE_ONLY_X87_BYTES)
        mutated[10] = 0xD9
        result = self._compile(
            _state_only_x87_summary(), mutated, expectation="rejected"
        )
        self._assert_checked(result, expect_axioms=False)

    def test_finite_indirect_table_mutation_is_kernel_checked_rejection(self) -> None:
        mutated = list(_FINITE_INDIRECT_BYTES)
        mutated[32] = 0x13
        result = self._compile(
            _finite_indirect_summary(), mutated, expectation="rejected"
        )
        self._assert_checked(result, expect_axioms=False)

    def test_byte_mutation_is_kernel_checked_rejection(self) -> None:
        mutated = list(_NESTED_BYTES)
        mutated[1] = 0x06
        result = self._compile(
            nested_summary(), mutated, expectation="rejected"
        )
        self._assert_checked(result, expect_axioms=False)

    def test_omitted_edge_and_return_are_kernel_checked_rejections(self) -> None:
        valid = push_pop_summary()
        missing_edge = replace(valid.certificate, edges=valid.certificate.edges[:1])
        missing_return = replace(valid.certificate, returns=())
        for label, certificate in (
            ("edge", missing_edge),
            ("return", missing_return),
        ):
            with self.subTest(label=label):
                result = self._compile(
                    LeanInternalDirectCallRegisterSummaryTree(certificate),
                    _PUSH_POP_BYTES,
                    expectation="rejected",
                )
                self._assert_checked(result, expect_axioms=False)

    def test_wrong_stack_restore_is_kernel_checked_rejection(self) -> None:
        mutated = list(_PUSH_POP_BYTES)
        mutated[20] = 0x5F
        result = self._compile(
            push_pop_summary(), mutated, expectation="rejected"
        )
        self._assert_checked(result, expect_axioms=False)

    def test_unparsed_machine_contract_is_kernel_checked_rejection(self) -> None:
        bytes_ = [
            0xE8, 0x05, 0x00, 0x00, 0x00,
            0xC3,
            0x90, 0x90, 0x90, 0x90,
            0xFF, 0x15, 0x00, 0x00, 0x40, 0x00,
            0xC3,
        ]
        result = self._compile(
            _ungrounded_summary(),
            bytes_,
            expectation="rejected",
            imports_source=_UNGROUNDED_IMPORTS,
        )
        self._assert_checked(result, expect_axioms=False)


if __name__ == "__main__":
    unittest.main()
