from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


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


class StageARelationalInterpreterTransferKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_bridge_profile_digest_and_macro_step_are_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        source = (source_root / "RelationalInterpreterTransfer.lean").read_text(
            encoding="utf-8"
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterTransfer"
            )
            (stage_a / "RelationalInterpreterTransferKernel.lean").write_text(
                _FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterTransferKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


_FIXTURE = r"""import StageA.RelationalInterpreterTransfer

namespace StageA.RelationalInterpreterTransferKernel

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterTransfer

example : SHA256.hex [97, 98, 99] =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" := by
  native_decide

example : SHA256.hex [] =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" := by
  native_decide

def unchangedRegisters : Registers Expr := {
  eax := .inputReg .eax
  ebx := .inputReg .ebx
  ecx := .inputReg .ecx
  edx := .inputReg .edx
  esi := .inputReg .esi
  edi := .inputReg .edi
  ebp := .inputReg .ebp
  esp := .inputReg .esp
}

def target : CodeTargetPair := {
  id := 7
  originalRva := 4097
  candidateRva := 8193
}

def normalized : NormalizedSymbolicBehavior := {
  registers := unchangedRegisters
  x87 := initialSymbolic.x87
  writes := []
  flags := none
  outcome := .jump 7
}

def transfer : SemanticTransfer := {
  sourceRva := 4096
  wordNodes := []
  calls := []
  body := []
  outcome := .fallthrough 4097
}

def record : ProgramRecord := {
  sourceRva := 4096
  wordNodes := []
  x87Nodes := []
  calls := []
  actions := [{ op := 19, arity := 1, aux := 0, args := [4097] }]
}

def exported : ExportedSemanticTransfer := {
  identity := "fixture"
  contractSha256 := SHA256.hex []
  instructionBytesSha256 := SHA256.hex [144]
  transfer := transfer
}

example : record.decode = some transfer := by decide
example : transfer.checked = true := by decide
example : transferProfileSupported transfer = true := by decide
example : normalizedProfileSupported normalized = true := by decide
example : targetMapChecked [target] = true := by decide
example : targetMapChecked [target, { target with id := 8 }] = false := by decide
example : targetMapChecked [target, {
    id := 8
    originalRva := 4098
    candidateRva := 8194
    originalAliases := [{ rva := 4097, paddingIndex := 0 }]
  }] = false := by decide
example : exactMemoryEffectFreeProfile [0x90] = true := by decide
example : exactMemoryEffectFreeProfile [0x8b, 0x00] = false := by decide

def exactBytesPe : PE32 := {
  bytes := ByteTree.ofBytes [0x90, 0xc3]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 2
  sizeOfHeaders := 2
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}

example : exactRvaBytes exactBytesPe 0 2 = some [0x90, 0xc3] := by decide
example : exactRvaBytes exactBytesPe 1 2 = none := by decide

def zeroFillPe : PE32 := {
  exactBytesPe with
  bytes := ByteTree.ofBytes [0x90]
  sizeOfImage := 0x1002
  sizeOfHeaders := 0
  sections := [{
    virtualSize := 2
    virtualAddress := 0x1000
    rawSize := 1
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

example : spanBytes zeroFillPe { start := 0x1000, size := 2 } =
    some [0x90, 0] := by decide
example : exactRvaBytes zeroFillPe 0x1000 2 = none := by decide

theorem semanticAgreement : ObservationalAgreement [target] normalized transfer := by
  intro state environment
  let result : MacroResult := {
    state := machineFromFormal state
    events := []
    completion := .fallthrough 4097
  }
  refine ⟨result, rfl, ?_, ?_, rfl, rfl, rfl, rfl⟩
  · intro register
    cases register <;> rfl
  · intro flag
    cases flag <;> rfl

def branchNormalized : NormalizedSymbolicBehavior := {
  normalized with outcome := .branch (.inputFlag 0) 7 7
}

def undefinedTransfer : SemanticTransfer := {
  transfer with
  wordNodes := [{ op := .undefinedBv, aux := 0, immediate := 0, args := [] }]
  body := [.evalWord 0]
}

def branchTransfer : SemanticTransfer := {
  transfer with outcome := .branch 0 4097 4098
}

def x87Record : ProgramRecord := {
  record with x87Nodes := [{ op := 0, arity := 0, aux := 0, immediate := 0, args := [] }]
}

def secondTarget : CodeTargetPair := {
  id := 8
  originalRva := 4098
  candidateRva := 8194
}

def generalTransfer : SemanticTransfer := {
  sourceRva := 4096
  wordNodes := [
    { op := .register, aux := 7, immediate := 0, args := [] },
    { op := .load, aux := 4, immediate := 0, args := [0] },
    { op := .constant, aux := 0, immediate := 1, args := [] },
    { op := .undefinedBv, aux := 0, immediate := 73, args := [] },
    { op := .falseValue, aux := 0, immediate := 0, args := [] }
  ]
  calls := []
  body := [
    .evalWord 0, .evalWord 1, .evalWord 2, .evalWord 3, .evalWord 4,
    .memoryWrite 0 2 .dword, .divideIf 4, .repMovsd 0 0 2 4
  ]
  outcome := .branch 4 4097 4098
}

def generalFootprint : List FlatMemoryAccessSite := [
  ⟨1, some 0, some 1, .read .dword⟩,
  ⟨5, some 0, some 2, .write .dword⟩,
  ⟨7, some 0, some 0, .repMovsd⟩
]

def generalAliases : List FlatMemoryAliasWitness := [
  ⟨0, 1, .orderedMayAlias⟩,
  ⟨0, 2, .orderedMayAlias⟩,
  ⟨1, 2, .orderedMayAlias⟩
]

def generalTargets : List ControlTargetWitness := [⟨4097, 7⟩, ⟨4098, 8⟩]

def externalCall : SemanticCall := {
  kind := .external
  instructionRva := 4096
  callIndex := 0
  targetNode := none
  targetRva := 0
  returnRva := 4097
  dll := some "kernel32.dll"
  symbol := some "WriteFile"
  ordinal := none
  registerNodes := [0, 0, 0, 0, 0, 0, 0, 0]
  flagNodes := [0, 0, 0, 0, 0, 0]
  argumentNodes := []
  stackInputs := []
}

example : normalizedProfileSupported branchNormalized = false := by decide
example : transferProfileSupported undefinedTransfer = false := by decide
example : transferProfileSupported branchTransfer = false := by decide
example : x87Record.decode = none := by decide
example : exactDecodedInstructionProfile [0x8b, 0x00] = true := by decide
example : generalTransfer.checked = true := by decide
example : generalTransferProfileSupported generalTransfer = true := by decide
example : orderedFlatMemoryFootprint generalTransfer = generalFootprint := by decide
example : flatMemoryFootprintChecked generalTransfer generalFootprint = true := by decide
example : flatMemoryAliasInventoryChecked generalFootprint generalAliases = true := by decide
example : controlTargetInventoryChecked generalTransfer [target, secondTarget]
    generalTargets = true := by decide
example : undefinedSlotsChecked generalTransfer [73] = true := by decide
example : callBoundaryShapeChecked externalCall = true := by decide
example (condition : Word) :
    wordTruth condition = true ∨ wordTruth condition = false :=
  branchGuardsExhaustive condition

example (state : MachineState) :
    normalizedCompletionMatches [target] state (.call 7 7) .externalFault := by
  simp [normalizedCompletionMatches, normalizedCompletion,
    normalizedOutcomeDefersFinalState, faultCompletion, originalTargetRva, target]

example (state : MachineState) :
    normalizedCompletionMatches [target] state
      (.callUnmappedReturn 7) .externalJump := by
  simp [normalizedCompletionMatches, normalizedCompletion]

example (certificate : InterpreterTransferCertificate peBytes contractBytes
    instructionBytes pe span imports contracts targets decoded normalizedBehavior
    rawRecord exportedTransfer) :
    ObservationalAgreement targets normalizedBehavior exportedTransfer.transfer :=
  certificate.macroStepRefinesOriginal

#print axioms InterpreterTransferCertificate.macroStepRefinesOriginal
#print axioms InterpreterTransferCertificate.rawMacroStepRefinesOriginal
#print axioms GeneralInterpreterTransferCertificate.macroStepRefinesOriginal
#print axioms GeneralInterpreterTransferCertificate.macroStepProducesDecodedResult
#print axioms GeneralInterpreterTransferCertificate.rawMacroStepRefinesOriginal
#print axioms pairedFlatMemoryUpdatePreservesRelationalFamilies
#print axioms checkedReturnUsesRelationalRuntimeFrame
#print axioms checkedExternalCallResultsRelated
#print axioms semanticAgreement

end StageA.RelationalInterpreterTransferKernel
"""


if __name__ == "__main__":
    unittest.main()
