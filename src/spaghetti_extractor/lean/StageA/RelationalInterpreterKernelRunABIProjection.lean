import StageA.RelationalInterpreterKernelABI
import StageA.RelationalInterpreterKernelOperationProjection

namespace StageA.Relational.InterpreterKernelRunABIProjection

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI

/-!
# Compact Run ABI projections

These operation-specific projections deliberately sit above the foundational
ABI and instruction-projection modules. Generated Run proofs consume the
opaque facts without making unrelated Step and Invoke proofs depend on them.
-/

/-- Compact cdecl entry projection for a Run request. -/
theorem ABIRequestFacts.runFunctionEntryEsp
    (facts : ABIRequestFacts abi
      (.runFunction requestRecords environment resolveCodeTarget sourceRva
        logical) state) :
    state.registers.esp =
      abi.parameters.entryEsp abi.engineLayout .runFunction := by
  exact facts.cdecl.1

/-- The third Run argument is the concrete engine input pointer. -/
theorem ABIRequestFacts.runFunctionInputWord
    (facts : ABIRequestFacts abi
      (.runFunction requestRecords environment resolveCodeTarget sourceRva
        logical) state) :
    Memory.read32 state.memory
        (abi.parameters.entryEsp abi.engineLayout .runFunction + word32 12) =
      abi.parameters.inputAddress := by
  have words := facts.cdecl.2.2.1
  have input := words.2.2.2.1
  change
    Memory.read32 state.memory
        (((abi.parameters.entryEsp abi.engineLayout .runFunction + word32 4) +
          word32 4) + word32 4) =
      abi.parameters.inputAddress at input
  calc
    Memory.read32 state.memory
        (abi.parameters.entryEsp abi.engineLayout .runFunction + word32 12) =
      Memory.read32 state.memory
        (((abi.parameters.entryEsp abi.engineLayout .runFunction + word32 4) +
          word32 4) + word32 4) := by
        congr 1
        rw [show word32 12 = word32 4 + word32 4 + word32 4 by decide]
        simp only [BitVec.add_assoc]
    _ = abi.parameters.inputAddress := input

/-- The fourth Run argument is the concrete engine output pointer. -/
theorem ABIRequestFacts.runFunctionOutputWord
    (facts : ABIRequestFacts abi
      (.runFunction requestRecords environment resolveCodeTarget sourceRva
        logical) state) :
    Memory.read32 state.memory
        (abi.parameters.entryEsp abi.engineLayout .runFunction + word32 16) =
      abi.parameters.outputAddress abi.engineLayout := by
  have words := facts.cdecl.2.2.1
  have output := words.2.2.2.2.1
  change
    Memory.read32 state.memory
        ((((abi.parameters.entryEsp abi.engineLayout .runFunction + word32 4) +
          word32 4) + word32 4) + word32 4) =
      abi.parameters.outputAddress abi.engineLayout at output
  calc
    Memory.read32 state.memory
        (abi.parameters.entryEsp abi.engineLayout .runFunction + word32 16) =
      Memory.read32 state.memory
        ((((abi.parameters.entryEsp abi.engineLayout .runFunction + word32 4) +
          word32 4) + word32 4) + word32 4) := by
        congr 1
        rw [show word32 16 =
          word32 4 + word32 4 + word32 4 + word32 4 by decide]
        simp only [BitVec.add_assoc]
    _ = abi.parameters.outputAddress abi.engineLayout := output

/-- Compact entry-state payload projection for a Run request. -/
theorem ABIRequestFacts.runFunctionEngineState
    (facts : ABIRequestFacts abi
      (.runFunction requestRecords environment resolveCodeTarget sourceRva
        logical) state) :
    EngineStateHolds abi.engineLayout abi.parameters.inputAddress
      logical sourceRva state := by
  exact facts.payload.2.2

#print axioms ABIRequestFacts.runFunctionEntryEsp
#print axioms ABIRequestFacts.runFunctionInputWord
#print axioms ABIRequestFacts.runFunctionOutputWord
#print axioms ABIRequestFacts.runFunctionEngineState

end StageA.Relational.InterpreterKernelRunABIProjection
