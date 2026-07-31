from __future__ import annotations

import copy
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_normalization import (
    relational_interpreter_normalization_bundle_sources,
)
from spaghetti_extractor.relational.lean.interpreter_semantic_refinement import (
    relational_interpreter_semantic_refinement_bundle_sources,
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


class StageARelationalInterpreterNormalizationKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_exact_arithmetic_path_and_mutation_rejection_are_kernel_checked(
        self,
    ) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        source = (source_root / "RelationalInterpreterNormalization.lean").read_text(
            encoding="utf-8"
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        exact_runner = source.split(
            "def executeExactDecodedInstruction?", 1
        )[1].split("def SemanticTransferRefinesExactPath", 1)[0]
        self.assertIn("instruction.decode? pe", exact_runner)
        self.assertIn("executeInstruction pe imports", exact_runner)
        self.assertNotIn("SemanticTransfer.execute", exact_runner)
        self.assertNotIn("path.record", exact_runner)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterSemanticRefinement"
            )
            (stage_a / "RelationalInterpreterNormalizationKernel.lean").write_text(
                _FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterNormalizationKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_generated_certificate_shard_builds_exact_acceptance_inventory(
        self,
    ) -> None:
        sources = relational_interpreter_normalization_bundle_sources(
            [_lea_row()],
            source_module="StageA.GeneratedNormalizationProgramFixture",
            pe_name="StageA.GeneratedRelational.originalPe",
            semantic_refinement_module="StageA.GeneratedNormalizationRefinementFixture",
            record_prefix="semanticInterpreterProgramRecord",
            transfer_prefix="semanticInterpreterTransfer",
            shard_size=1,
        )
        refinement_sources = relational_interpreter_semantic_refinement_bundle_sources(
            [_lea_row()],
            pe_module="StageA.GeneratedNormalizationProgramFixture",
            module_prefix="GeneratedNormalizationRefinementProof",
            shard_size=1,
        )
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterSemanticRefinement"
            )
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterAcceptance"
            )
            (stage_a / "RelationalInterpreterNormalizationKernel.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            (stage_a / "GeneratedNormalizationProgramFixture.lean").write_text(
                _PROGRAM_FIXTURE, encoding="utf-8"
            )
            data_module = "GeneratedInterpreterNormalizationShard0000Data"
            (stage_a / f"{data_module}.lean").write_text(
                sources[data_module], encoding="utf-8"
            )
            for module, source in refinement_sources.items():
                (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
            (
                stage_a / "GeneratedNormalizationRefinementFixture.lean"
            ).write_text(
                "import StageA.GeneratedNormalizationRefinementProofBundle\n",
                encoding="utf-8",
            )
            for module, source in sources.items():
                if module != data_module:
                    (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
            result = _run_lean_relational(
                root, bundle="GeneratedInterpreterNormalizationBundle"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_generated_fused_refinement_rejects_mutated_span_bytes(self) -> None:
        row = _lea_row()
        mutated = copy.deepcopy(row)
        mutated["instructions"][0]["bytes"] = "8d4002"  # type: ignore[index]
        mutated["instruction_bytes_sha256"] = sha256_bytes(
            bytes.fromhex("8d4002")
        )
        normalization_sources = relational_interpreter_normalization_bundle_sources(
            [row],
            source_module="StageA.GeneratedNormalizationProgramFixture",
            pe_name="StageA.GeneratedRelational.originalPe",
            semantic_refinement_module="StageA.GeneratedNormalizationRefinementFixture",
            record_prefix="semanticInterpreterProgramRecord",
            transfer_prefix="semanticInterpreterTransfer",
            shard_size=1,
        )
        refinement_sources = relational_interpreter_semantic_refinement_bundle_sources(
            [mutated],
            pe_module="StageA.GeneratedNormalizationProgramFixture",
            module_prefix="GeneratedNormalizationRefinementProof",
            shard_size=1,
        )
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterSemanticRefinement"
            )
            (stage_a / "RelationalInterpreterNormalizationKernel.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            (stage_a / "GeneratedNormalizationProgramFixture.lean").write_text(
                _PROGRAM_FIXTURE, encoding="utf-8"
            )
            data_module = "GeneratedInterpreterNormalizationShard0000Data"
            (stage_a / f"{data_module}.lean").write_text(
                normalization_sources[data_module], encoding="utf-8"
            )
            for module, source in refinement_sources.items():
                (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
            result = _run_lean_relational(
                root, bundle="GeneratedNormalizationRefinementProofBundle"
            )

        self.assertEqual(result["status"], "failed", result)
        self.assertIn("exactRvaBytes originalPe 4096 3", result["stdout"])
        self.assertIn("some [141, 64, 2]", result["stdout"])


def _lea_row() -> dict[str, object]:
    encoded = bytes.fromhex("8d4001")
    return {
        "stage_b_format": "stage-b-state-machine-transfer-v1",
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": "semantic-transfer:lea",
        "contract_sha256": "a" * 64,
        "instruction_bytes_sha256": sha256_bytes(encoded),
        "original": {"rva_start": 0x1000, "rva_end": 0x1003, "size": 3},
        "instructions": [
            {
                "rva": 0x1000,
                "size": 3,
                "bytes": "8d4001",
                "mnemonic": "lea",
                "op_str": "eax, [eax + 1]",
            }
        ],
        "ordered_events": [],
        "register_writes": [
            {
                "register": "eax",
                "value": {
                    "op": "add32",
                    "args": [
                        {"op": "reg", "name": "eax", "width": 32},
                        {"op": "const", "value": 1, "width": 32},
                    ],
                },
            }
        ],
        "flag_writes": [],
        "fpu_state": None,
        "outcome": {"kind": "fallthrough", "target_rva": 0x1003},
    }


_FIXTURE = r"""import StageA.RelationalInterpreterSemanticRefinement

namespace StageA.RelationalInterpreterNormalizationKernel

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterSemanticRefinement
open StageA.Relational.InterpreterTransfer

theorem updateObservedFlag (word : Word) (index : Nat)
    (inRange : index < 32) :
    updateFlag word index (some (word.extractLsb' index 1 == 1#1)) = word := by
  have maskEq : BitVec.ofNat 32 (2 ^ index) = BitVec.twoPow 32 index := by
    apply BitVec.eq_of_toNat_eq
    simp [BitVec.toNat_twoPow]
  apply BitVec.eq_of_getElem_eq
  intro query queryInRange
  by_cases observed : (word.extractLsb' index 1 == 1#1) = true
  · unfold updateFlag
    rw [maskEq]
    simp only [observed, if_true, BitVec.getElem_or queryInRange]
    by_cases same : query = index
    · subst query
      simp [BitVec.getElem_eq_extractLsb' word index inRange, observed]
    · simp [BitVec.getElem_twoPow queryInRange, same]
  · have observedFalse : (word.extractLsb' index 1 == 1#1) = false := by
      cases value : word.extractLsb' index 1 == 1#1 <;> simp_all
    unfold updateFlag
    rw [maskEq]
    simp only [observedFalse, if_false, BitVec.getElem_and queryInRange,
      BitVec.getElem_not queryInRange]
    by_cases same : query = index
    · subst query
      simp [BitVec.getElem_eq_extractLsb' word index inRange, observedFalse]
    · simp [BitVec.getElem_twoPow queryInRange, same]

theorem reconstructedInputFlags (word : Word) :
    updateFlag
      (updateFlag
        (updateFlag
          (updateFlag
            (updateFlag (updateFlag word 0
              (some (word.extractLsb' 0 1 == 1#1))) 2
              (some (word.extractLsb' 2 1 == 1#1))) 4 none) 6
            (some (word.extractLsb' 6 1 == 1#1))) 7
          (some (word.extractLsb' 7 1 == 1#1))) 11
        (some (word.extractLsb' 11 1 == 1#1)) = word := by
  rw [updateObservedFlag word 0 (by omega)]
  rw [updateObservedFlag word 2 (by omega)]
  change updateFlag
    (updateFlag (updateFlag word 6
      (some (word.extractLsb' 6 1 == 1#1))) 7
      (some (word.extractLsb' 7 1 == 1#1))) 11
      (some (word.extractLsb' 11 1 == 1#1)) = word
  rw [updateObservedFlag word 6 (by omega)]
  rw [updateObservedFlag word 7 (by omega)]
  rw [updateObservedFlag word 11 (by omega)]

def exactPe : PE32 := {
  bytes := ByteTree.ofBytes [0x8d, 0x40, 0x01]
  peOffset := 0
  entrypointRva := 0x1000
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 0x1003
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 3
    virtualAddress := 0x1000
    rawSize := 3
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def exactTransfer : SemanticTransfer := {
  sourceRva := 0x1000
  wordNodes := [
    { op := .register, aux := 0, immediate := 0, args := [] },
    { op := .constant, aux := 0, immediate := 1, args := [] },
    { op := .add32, aux := 0, immediate := 0, args := [0, 1] }
  ]
  calls := []
  body := [.evalWord 0, .evalWord 1, .evalWord 2, .setRegister .eax 2]
  outcome := .fallthrough 0x1003
}

def exactRecord : ProgramRecord := {
  sourceRva := 0x1000
  wordNodes := [
    { op := 1, arity := 0, aux := 0, immediate := 0, args := [] },
    { op := 0, arity := 0, aux := 0, immediate := 1, args := [] },
    { op := 15, arity := 2, aux := 0, immediate := 0, args := [0, 1] }
  ]
  x87Nodes := []
  calls := []
  actions := [
    { op := 0, arity := 1, aux := 0, args := [0] },
    { op := 0, arity := 1, aux := 0, args := [1] },
    { op := 0, arity := 1, aux := 0, args := [2] },
    { op := 6, arity := 1, aux := 0, args := [2] },
    { op := 19, arity := 1, aux := 0, args := [0x1003] }
  ]
}

def leaInstruction : ExactDecodedInstruction := {
  rva := 0x1000
  bytes := [0x8d, 0x40, 0x01]
}

def leaDecoded : DecodedInstruction := {
  instruction := .leaAddress .eax {
    base := some .eax
    index := none
    scaleShift := 0
    displacement := 1
  }
  size := 3
  trailing := []
}

def exactPath : ExactNormalizedTransferPath := {
  sourceRva := 0x1000
  stopRva := 0x1003
  chunks := [{
    span := { start := 0x1000, size := 3 }
    instructions := [leaInstruction]
  }]
  terminal := .fallthrough 0x1003
  orderedEffects := []
  record := exactRecord
}

def wrongArithmetic : SemanticTransfer := {
  exactTransfer with
  wordNodes := exactTransfer.wordNodes.set 1
    { op := .constant, aux := 0, immediate := 2, args := [] }
}

def wrongRecord : ProgramRecord := {
  exactRecord with
  wordNodes := exactRecord.wordNodes.set 1
    { op := 0, arity := 0, aux := 0, immediate := 2, args := [] }
}

def wrongPath : ExactNormalizedTransferPath := {
  exactPath with record := wrongRecord
}

example : exactPath.exactDecodeChecked exactPe = true := by native_decide
example : exactRecord.decode = some exactTransfer := by native_decide
example : diagnosticTransferShapeChecked exactPe exactPath exactTransfer = true := by
  native_decide
example : diagnosticTransferShapeChecked exactPe wrongPath wrongArithmetic = true := by
  native_decide

theorem exactSemanticRefinement :
    SemanticTransferRefinesExactPath exactPe exactPath exactTransfer := by
  intro state environment
  have pathChecked : exactPath.exactDecodeChecked exactPe = true := by decide
  have imports : parseImports exactPe = some [] := by decide
  have exactDecoded : leaInstruction.decode? exactPe = some leaDecoded := by decide
  rw [runExactNormalizedPath_of_checked exactPe exactPath [] pathChecked imports]
  change exactTransfer.execute environment (machineFromFormal state) =
    runExactDecodedInstructions exactPe [] exactPath environment 0
      [leaInstruction] state []
  simp only [runExactDecodedInstructions]
  simp only [executeExactDecodedInstruction?, exactDecoded]
  simp [exactTransfer, leaDecoded,
    exactInstructionMemoryEvents?, executeInstructionWithContext,
    executeInstruction,
    SemanticTransfer.execute, SemanticTransfer.executeBody,
    SemanticTransfer.executeAction, SemanticWordNode.evaluate,
    SemanticOutcome.complete, halted, evalPrimitive,
    RuntimeState.setWord, Register.ofIndex?, formalRegister,
    machineFromFormal, exactResult,
    concreteBehaviorNextMachineState, SymbolicBehavior.eval,
    initialSymbolic, initialSymbolicX87, Addressing.expression,
    Registers.set, Registers.get, Expr.addNormalized,
    StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
    StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
    StageA.Formal.applyWrites, reconstructedInputFlags,
    leaInstruction, readMemory, InterpreterMachine.setRegister]
  funext register
  cases register <;> rfl

set_option maxHeartbeats 2000000 in
theorem exactFusedMachineRefinement :
    ExactSemanticTransferFusedMachineRefinement exactPe []
      { start := 0x1000, size := 3 } exactTransfer := by
  intro targets state environment symbolic behavior result symbolicExact
    evaluated transferExact
  have exactBytes :
      exactRvaBytes exactPe 0x1000 3 = some [0x8d, 0x40, 0x01] := by
    decide +kernel
  have exactWindow :
      executableSpanInstructionWindow exactPe 0x1000 0x1003 =
        some [0x8d, 0x40, 0x01] := by
    decide +kernel
  have exactDecoded :
      decodeInstructionExact [0x8d, 0x40, 0x01] = some leaDecoded := by
    decide +kernel
  simp (config := { maxSteps := 4000000 })
    [executePE32SymbolicSpan, runPE32SymbolicSpanFuel,
      Span.stop, exactWindow, exactDecoded, leaDecoded,
      executeInstruction, executeInstructionWithContext,
      initialSymbolic, initialSymbolicX87, Addressing.expression,
      Registers.set, Registers.get, Expr.addNormalized] at symbolicExact
  subst symbolic
  unfold evalBehavior at evaluated
  generalize normalizedExact :
      normalizeSymbolicBehavior false targets _ = normalized at evaluated
  cases normalized with
  | none => simp at evaluated
  | some normalized =>
      injection evaluated with evaluated
      subst behavior
      simp (config := { maxSteps := 4000000 })
        [exactTransfer, SemanticTransfer.execute, SemanticTransfer.executeBody,
          SemanticTransfer.executeAction, SemanticWordNode.evaluate,
          SemanticOutcome.complete, halted, evalPrimitive, RuntimeState.setWord,
          Register.ofIndex?, formalRegister, machineFromFormal,
          InterpreterMachine.setRegister] at transferExact
      subst result
      obtain ⟨registersExact, x87Exact, writesExact, flagsExact⟩ :=
        normalizeSymbolicBehavior_fields false targets _ normalized
          normalizedExact
      simp [registersExact, x87Exact, writesExact, flagsExact,
        NormalizedSymbolicBehavior.eval,
        RelationalBehavior.nextMachineState, machineFromFormal,
        evalNormalizedRegisters, evalNormalizedX87, evalNormalizedWrites,
        evalNormalizedFlags, applyConcreteWrites,
        StageA.Formal.applyWrites, InterpreterTransfer.applyWrites,
        StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        reconstructedInputFlags]
      funext register
      cases register <;> rfl

example : ExactNormalizationCertificate exactPe exactPath exactTransfer := {
  diagnosticShape := by native_decide
  semanticRefinement := exactSemanticRefinement
}

theorem wrongArithmeticRejected :
    ¬ SemanticTransferRefinesExactPath exactPe exactPath wrongArithmetic := by
  intro alleged
  let state : MachineState := {
    registers := {
      eax := 10
      ebx := 0
      ecx := 0
      edx := 0
      esi := 0
      edi := 0
      ebp := 0
      esp := 0
    }
    memory := fun _ => 0
  }
  let environment : StageA.Relational.Interpreter.Environment := {
    undefinedValue := fun _ => 0
    invokeCall := fun _ machine => { status := .ok, state := machine }
  }
  have resultEquality := (alleged state environment).trans
    (exactSemanticRefinement state environment).symm
  have eaxEquality := congrArg
    (fun result => result.map (fun value => value.state.registers .eax))
    resultEquality
  have wrongEax :
      (wrongArithmetic.execute environment (machineFromFormal state)).map
          (fun value => value.state.registers .eax) = some 12 := by decide
  have exactEax :
      (exactTransfer.execute environment (machineFromFormal state)).map
          (fun value => value.state.registers .eax) = some 11 := by decide
  change
    (wrongArithmetic.execute environment (machineFromFormal state)).map
        (fun value => value.state.registers .eax) =
      (exactTransfer.execute environment (machineFromFormal state)).map
        (fun value => value.state.registers .eax) at eaxEquality
  rw [wrongEax, exactEax] at eaxEquality
  cases eaxEquality

#print axioms exactSemanticRefinement
#print axioms exactFusedMachineRefinement
#print axioms wrongArithmeticRejected
#print axioms ExactNormalizationCertificate.sound
#print axioms ExactProgramRecordNormalizationCertificate.rawMacroStep

end StageA.RelationalInterpreterNormalizationKernel
"""


_PROGRAM_FIXTURE = r"""import StageA.RelationalInterpreterNormalizationKernel

namespace StageA.GeneratedRelational

open StageA.Relational.Interpreter

def originalPe : StageA.Formal.PE32 :=
  StageA.RelationalInterpreterNormalizationKernel.exactPe

def semanticInterpreterProgramRecord0 : ProgramRecord :=
  StageA.RelationalInterpreterNormalizationKernel.exactRecord

def semanticInterpreterTransfer0 : SemanticTransfer := {
  sourceRva := 0x1000
  wordNodes := [
    { op := .register, aux := 0, immediate := 0, args := [] },
    { op := .constant, aux := 0, immediate := 1, args := [] },
    { op := .add32, aux := 0, immediate := 0, args := [0, 1] }
  ]
  calls := []
  body := [.evalWord 0, .evalWord 1, .evalWord 2, .setRegister .eax 2]
  outcome := .fallthrough 0x1003
}

def originalImports : List StageA.Formal.PEImport := []

theorem semanticInterpreterProgramRecord0Decoded :
    semanticInterpreterProgramRecord0.decode =
      some semanticInterpreterTransfer0 := by native_decide

theorem semanticInterpreterProgramRecord0TransferChecked :
    semanticInterpreterTransfer0.checked = true := by native_decide

end StageA.GeneratedRelational
"""


if __name__ == "__main__":
    unittest.main()
