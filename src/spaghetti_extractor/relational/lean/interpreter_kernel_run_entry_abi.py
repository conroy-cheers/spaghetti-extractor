"""Generate the concrete ABI binding for a checked native Run entry route.

The generated module contains no trusted analysis.  It instantiates the
generic route and engine-copy theorems with the exact checked ABI artifact;
Lean still evaluates every decoded expression and footprint.
"""

from __future__ import annotations

from pathlib import Path


INTERPRETER_KERNEL_RUN_ENTRY_ABI_LEAN_MODULE = (
    "GeneratedRelationalInterpreterKernelRunEntryABI"
)
INTERPRETER_KERNEL_RUN_ENTRY_ABI_BASE_LEAN_MODULE = (
    "GeneratedRelationalInterpreterKernelRunEntryABIBase"
)


def _combined_run_entry_abi_lean_source() -> str:
    return """import StageA.GeneratedRelationalInterpreterKernelRunEntryRoute
import StageA.GeneratedRelationalInterpreterKernelRunEntryBehaviors
import StageA.GeneratedRelationalInterpreterKernelRunEntryProjectionBlock2
import StageA.GeneratedRelationalInterpreterKernelABIParameters
import StageA.RelationalInterpreterKernelOperationProjection
import StageA.RelationalInterpreterKernelRunABIProjection

namespace StageA.GeneratedRelational.InterpreterKernelRunEntryABI

open StageA.Formal StageA.Relational
open StageA.Relational.Engine
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelEngineCopy
open StageA.Relational.InterpreterKernelOperationMemoryRoute
open StageA.Relational.InterpreterKernelOperationPredicateRoute
open StageA.Relational.InterpreterKernelOperationProjection
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterKernelRunABIProjection
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelOperationCandidate
open StageA.GeneratedRelational.InterpreterKernelOperationInstantiation
open StageA.GeneratedRelational.InterpreterKernelRunEntryProjection

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

abbrev generatedRunLayout :=
  generatedInterpreterEngineLayout

abbrev generatedRunParameters :=
  generatedInterpreterKernelABIParameters

def generatedRunRequest
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat)
    (sourceRva : Nat) (logical : InterpreterMachine) :
    AbstractKernelRequest :=
  .runFunction records environment resolveCodeTarget sourceRva logical

def generatedRunWorkingStateAddress : Word :=
  generatedRunParameters.entryEsp generatedRunLayout .runFunction -
    word32 284

theorem generatedRunEntryABISourceRangeFits :
    generatedRunParameters.inputAddress.toNat +
        generatedRunLayout.stateSize <
      2 ^ 32 := by
  decide +kernel

/-- Exact operand projection for the checked Run prologue and the running
prefix of its first bulk-copy block.  Keeping this lemma independent of the
ABI and footprint certificates prevents downstream simplification from
replaying those large proof objects. -/
theorem generatedRunEntryDecodedBulkOperands
    (nativeEnvironment : NativeWorldEnvironment)
    (state : MachineState)
    (espExact :
      state.registers.esp =
        generatedRunParameters.entryEsp generatedRunLayout .runFunction)
    (inputWord :
      Memory.read32 state.memory
          (generatedRunParameters.entryEsp generatedRunLayout .runFunction +
            word32 12) =
        generatedRunParameters.inputAddress)
    (outputWord :
      Memory.read32 state.memory
          (generatedRunParameters.entryEsp generatedRunLayout .runFunction +
            word32 16) =
        generatedRunParameters.outputAddress generatedRunLayout)
    (directionClear : DirectionFlagClear state) :
    let bulkState :=
      (generatedRunEntryBlock2 nativeEnvironment).terminalState
        (runCheckedNativeOperationPredicateRoute
          (generatedRunEntryControlRoute nativeEnvironment) state)
    generatedRunEntryBulkCopyAndContinuation.1.source.eval bulkState =
        generatedRunParameters.inputAddress /\\
      generatedRunEntryBulkCopyAndContinuation.1.destination.eval bulkState =
        generatedRunWorkingStateAddress /\\
      generatedRunEntryBulkCopyAndContinuation.1.count.eval bulkState =
        word32 63 /\\
      generatedRunEntryBulkCopyAndContinuation.1.direction.eval bulkState =
        false := by
  let bulkState :=
    (generatedRunEntryBlock2 nativeEnvironment).terminalState
      (runCheckedNativeOperationPredicateRoute
        (generatedRunEntryControlRoute nativeEnvironment) state)
  have projected :=
    generatedRunEntryDecodedBulkOperandsProjection nativeEnvironment state
      (espExact.trans generatedRunEntryProjectionEntryEspExact)
      (by
        rw [generatedRunEntryProjectionInputWordAddress,
          ← generatedRunEntryProjectionEntryEspExact]
        exact inputWord.trans
          generatedRunEntryProjectionInputAddressExact)
      (by
        rw [generatedRunEntryProjectionOutputWordAddress,
          ← generatedRunEntryProjectionEntryEspExact]
        exact outputWord.trans
          generatedRunEntryProjectionOutputAddressExact)
      directionClear
  have workingAddressExact :
      generatedRunEntryProjectionWorkingAddress =
        generatedRunWorkingStateAddress := by
    exact
      (congrArg
        (fun address => address - word32 284)
        generatedRunEntryProjectionEntryEspExact.symm)
  exact bulkCopyInputRegistersEval
    generatedRunEntryBulkCopyAndContinuation.1 bulkState
    generatedRunParameters.inputAddress generatedRunWorkingStateAddress
    (word32 63) generatedRunEntryBulkCopyOperandsExact
    (projected.1.trans generatedRunEntryProjectionInputAddressExact.symm)
    (projected.2.1.trans workingAddressExact)
    projected.2.2.1 projected.2.2.2
  /-
  simp (config := { maxSteps := 1000000 })
    [generatedRunEntryControlRoute,
    generatedRunEntryStep0, generatedRunEntryStep1,
    generatedRunEntryBlock0, generatedRunEntryBlock1,
    generatedRunEntryBlock2,
    runCheckedNativeOperationPredicateRoute,
    CheckedNativeOperationPredicateBlockStep.targetState,
    CheckedNativeOperationBlock.terminalState,
    CheckedNativeOperationRunningTrace.after,
    CheckedNativeOperationRunningTrace.edges,
    runCheckedNativeOperationRunningTrace,
    CheckedNativeOperationRunningEdge.after,
    CheckedNativeOperationStoppedEdge.after,
    generatedRunEntryBulkCopyAndContinuation,
    generatedRunEntryBulkOutcome,
    generatedNativeOperationFunctionReplay0038Block0000Proof,
    generatedNativeOperationFunctionReplay0038Block0000RunningTrace,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0000Edge,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0001Edge,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0002Edge,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0003Edge,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0004Edge,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0005Edge,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0006Edge,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0007Edge,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0008Edge,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0009Edge,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0000BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0001BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0002BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0003BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0004BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0005BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0006BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0007BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0008BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0000Instruction0009BehaviorExact,
    generatedRunEntryBlock0Instruction0000MaterializedBehavior,
    generatedRunEntryBlock0Instruction0001MaterializedBehavior,
    generatedRunEntryBlock0Instruction0002MaterializedBehavior,
    generatedRunEntryBlock0Instruction0003MaterializedBehavior,
    generatedRunEntryBlock0Instruction0004MaterializedBehavior,
    generatedRunEntryBlock0Instruction0005MaterializedBehavior,
    generatedRunEntryBlock0Instruction0006MaterializedBehavior,
    generatedRunEntryBlock0Instruction0007MaterializedBehavior,
    generatedRunEntryBlock0Instruction0008MaterializedBehavior,
    generatedRunEntryBlock0Instruction0009MaterializedBehavior,
    generatedRunEntryBlock0Instruction0000MaterializedBehaviorExact,
    generatedRunEntryBlock0Instruction0001MaterializedBehaviorExact,
    generatedRunEntryBlock0Instruction0002MaterializedBehaviorExact,
    generatedRunEntryBlock0Instruction0003MaterializedBehaviorExact,
    generatedRunEntryBlock0Instruction0004MaterializedBehaviorExact,
    generatedRunEntryBlock0Instruction0005MaterializedBehaviorExact,
    generatedRunEntryBlock0Instruction0006MaterializedBehaviorExact,
    generatedRunEntryBlock0Instruction0007MaterializedBehaviorExact,
    generatedRunEntryBlock0Instruction0008MaterializedBehaviorExact,
    generatedRunEntryBlock0Instruction0009MaterializedBehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0001Proof,
    generatedNativeOperationFunctionReplay0038Block0001RunningTrace,
    generatedNativeOperationFunctionReplay0038Block0001Instruction0000Edge,
    generatedNativeOperationFunctionReplay0038Block0001Instruction0001Edge,
    generatedNativeOperationFunctionReplay0038Block0001Instruction0000BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0001Instruction0001BehaviorExact,
    generatedRunEntryBlock1Instruction0000MaterializedBehavior,
    generatedRunEntryBlock1Instruction0001MaterializedBehavior,
    generatedRunEntryBlock1Instruction0000MaterializedBehaviorExact,
    generatedRunEntryBlock1Instruction0001MaterializedBehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0003Proof,
    generatedNativeOperationFunctionReplay0038Block0003RunningTrace,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0000Edge,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0001Edge,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0002Edge,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0003Edge,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0004Edge,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0005Edge,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0006Edge,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0000BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0001BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0002BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0003BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0004BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0005BehaviorExact,
    generatedNativeOperationFunctionReplay0038Block0003Instruction0006BehaviorExact,
    generatedRunEntryBlock2Instruction0000MaterializedBehavior,
    generatedRunEntryBlock2Instruction0001MaterializedBehavior,
    generatedRunEntryBlock2Instruction0002MaterializedBehavior,
    generatedRunEntryBlock2Instruction0003MaterializedBehavior,
    generatedRunEntryBlock2Instruction0004MaterializedBehavior,
    generatedRunEntryBlock2Instruction0005MaterializedBehavior,
    generatedRunEntryBlock2Instruction0006MaterializedBehavior,
    generatedRunEntryBlock2Instruction0000MaterializedBehaviorExact,
    generatedRunEntryBlock2Instruction0001MaterializedBehaviorExact,
    generatedRunEntryBlock2Instruction0002MaterializedBehaviorExact,
    generatedRunEntryBlock2Instruction0003MaterializedBehaviorExact,
    generatedRunEntryBlock2Instruction0004MaterializedBehaviorExact,
    generatedRunEntryBlock2Instruction0005MaterializedBehaviorExact,
    generatedRunEntryBlock2Instruction0006MaterializedBehaviorExact,
    generatedRunWorkingStateAddress, generatedRunLayout,
    generatedRunParameters, DirectionFlagClear,
    KernelABIParameters.entryEsp, espExact, inputWord, directionClear]
  -/

/-- The concrete ABI instantiation is kept separate from the route artifact.
All dynamic footprint evidence is discharged by the exact generated route
certificate; callers cannot assume stack/engine disjointness. -/
theorem generatedRunEntryABIControlFacts
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation}
    {tableRva countRva : Nat} {records : List ProgramRecord}
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva records)
    (layoutExact : abi.engineLayout = generatedRunLayout)
    (parametersExact : abi.parameters = generatedRunParameters)
    (nativeEnvironment : NativeWorldEnvironment)
    (semanticEnvironment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (state : MachineState)
    (facts : ABIRequestFacts abi
      (generatedRunRequest records semanticEnvironment resolveCodeTarget
        sourceRva logical) state) :
    generatedRunEntrySelectorInvariant0.Holds
        ((generatedRunEntryBlock0 nativeEnvironment).terminalState state) /\\
      FrameWordPairDirectionProjection
        ((generatedRunEntryStep0 nativeEnvironment).targetState state)
        (generatedRunEntryProjectionEntryEsp - word32 316)
        (generatedRunEntryProjectionEntryEsp - word32 4)
        generatedRunEntryProjectionInputWordAddress
        generatedRunEntryProjectionInputAddress
        generatedRunEntryProjectionOutputWordAddress
        generatedRunEntryProjectionOutputAddress /\\
      generatedRunEntrySelectorInvariant1.Holds
        ((generatedRunEntryBlock1 nativeEnvironment).terminalState
          ((generatedRunEntryStep0 nativeEnvironment).targetState state)) /\\
      FrameWordPairDirectionProjection
        ((generatedRunEntryStep1 nativeEnvironment).targetState
          ((generatedRunEntryStep0 nativeEnvironment).targetState state))
        (generatedRunEntryProjectionEntryEsp - word32 316)
        (generatedRunEntryProjectionEntryEsp - word32 4)
        generatedRunEntryProjectionInputWordAddress
        generatedRunEntryProjectionInputAddress
        generatedRunEntryProjectionOutputWordAddress
        generatedRunEntryProjectionOutputAddress := by
  have espExact :
      state.registers.esp = generatedRunEntryProjectionEntryEsp := by
    exact
      (StageA.Relational.InterpreterKernelRunABIProjection.ABIRequestFacts.runFunctionEntryEsp
        facts).trans (by
          rw [layoutExact, parametersExact]
          exact generatedRunEntryProjectionEntryEspExact)
  have inputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionInputWordAddress =
        generatedRunEntryProjectionInputAddress := by
    rw [generatedRunEntryProjectionInputWordAddress,
      ← generatedRunEntryProjectionEntryEspExact]
    calc
      Memory.read32 state.memory
          (generatedRunParameters.entryEsp generatedRunLayout .runFunction +
            word32 12) =
          Memory.read32 state.memory
            (abi.parameters.entryEsp abi.engineLayout .runFunction +
              word32 12) := by rw [layoutExact, parametersExact]
      _ = abi.parameters.inputAddress :=
        StageA.Relational.InterpreterKernelRunABIProjection.ABIRequestFacts.runFunctionInputWord
          facts
      _ = generatedRunParameters.inputAddress := by rw [parametersExact]
      _ = generatedRunEntryProjectionInputAddress :=
        generatedRunEntryProjectionInputAddressExact
  have outputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionOutputWordAddress =
        generatedRunEntryProjectionOutputAddress := by
    rw [generatedRunEntryProjectionOutputWordAddress,
      ← generatedRunEntryProjectionEntryEspExact]
    calc
      Memory.read32 state.memory
          (generatedRunParameters.entryEsp generatedRunLayout .runFunction +
            word32 16) =
          Memory.read32 state.memory
            (abi.parameters.entryEsp abi.engineLayout .runFunction +
              word32 16) := by rw [layoutExact, parametersExact]
      _ = abi.parameters.outputAddress abi.engineLayout :=
        StageA.Relational.InterpreterKernelRunABIProjection.ABIRequestFacts.runFunctionOutputWord
          facts
      _ = generatedRunParameters.outputAddress generatedRunLayout := by
        rw [layoutExact, parametersExact]
      _ = generatedRunEntryProjectionOutputAddress :=
        generatedRunEntryProjectionOutputAddressExact
  have block0 :=
    generatedRunEntryProjectionBlock0ControlFacts nativeEnvironment state
      espExact inputWord outputWord facts.directionFlagClear
  have block1 :=
    generatedRunEntryProjectionBlock1ControlFacts nativeEnvironment
      ((generatedRunEntryStep0 nativeEnvironment).targetState state) block0.2
  exact And.intro block0.1
    (And.intro block0.2 (And.intro block1.1 block1.2))

theorem generatedRunEntryABIBulkSourceFacts
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation}
    {tableRva countRva : Nat} {records : List ProgramRecord}
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva records)
    (layoutExact : abi.engineLayout = generatedRunLayout)
    (parametersExact : abi.parameters = generatedRunParameters)
    (nativeEnvironment : NativeWorldEnvironment)
    (semanticEnvironment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (state : MachineState)
    (facts : ABIRequestFacts abi
      (generatedRunRequest records semanticEnvironment resolveCodeTarget
        sourceRva logical) state) :
    ForwardEngineBulkCopySourceFacts
      (generatedRunEntryBlock2 nativeEnvironment)
      generatedRunEntryBulkCopyAndContinuation.1
      generatedRunLayout
      generatedRunParameters.inputAddress
      generatedRunWorkingStateAddress
      logical sourceRva
      (runCheckedNativeOperationPredicateRoute
        (generatedRunEntryControlRoute nativeEnvironment) state) := by
  let bulkState :=
    (generatedRunEntryBlock2 nativeEnvironment).terminalState
      (runCheckedNativeOperationPredicateRoute
        (generatedRunEntryControlRoute nativeEnvironment) state)
  have directionClear := facts.directionFlagClear
  have espExact :
      state.registers.esp =
        generatedRunParameters.entryEsp generatedRunLayout .runFunction := by
    calc
      state.registers.esp =
          abi.parameters.entryEsp abi.engineLayout .runFunction :=
        StageA.Relational.InterpreterKernelRunABIProjection.ABIRequestFacts.runFunctionEntryEsp
          facts
      _ = generatedRunParameters.entryEsp generatedRunLayout .runFunction := by
        rw [layoutExact, parametersExact]
  have inputWord :
      Memory.read32 state.memory
          (generatedRunParameters.entryEsp generatedRunLayout .runFunction +
            word32 12) =
        generatedRunParameters.inputAddress := by
    calc
      Memory.read32 state.memory
          (generatedRunParameters.entryEsp generatedRunLayout .runFunction +
            word32 12) =
          Memory.read32 state.memory
            (abi.parameters.entryEsp abi.engineLayout .runFunction +
              word32 12) := by
        rw [layoutExact, parametersExact]
      _ = abi.parameters.inputAddress :=
        StageA.Relational.InterpreterKernelRunABIProjection.ABIRequestFacts.runFunctionInputWord
          facts
      _ = generatedRunParameters.inputAddress := by rw [parametersExact]
  have outputWord :
      Memory.read32 state.memory
          (generatedRunParameters.entryEsp generatedRunLayout .runFunction +
            word32 16) =
        generatedRunParameters.outputAddress generatedRunLayout := by
    calc
      Memory.read32 state.memory
          (generatedRunParameters.entryEsp generatedRunLayout .runFunction +
            word32 16) =
          Memory.read32 state.memory
            (abi.parameters.entryEsp abi.engineLayout .runFunction +
              word32 16) := by
        rw [layoutExact, parametersExact]
      _ = abi.parameters.outputAddress abi.engineLayout :=
        StageA.Relational.InterpreterKernelRunABIProjection.ABIRequestFacts.runFunctionOutputWord
          facts
      _ = generatedRunParameters.outputAddress generatedRunLayout := by
        rw [layoutExact, parametersExact]
  have projectedEspExact :
      state.registers.esp = generatedRunEntryProjectionEntryEsp :=
    espExact.trans generatedRunEntryProjectionEntryEspExact
  have projectedInputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionInputWordAddress =
        generatedRunEntryProjectionInputAddress := by
    rw [generatedRunEntryProjectionInputWordAddress,
      ← generatedRunEntryProjectionEntryEspExact]
    exact inputWord.trans generatedRunEntryProjectionInputAddressExact
  have projectedOutputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionOutputWordAddress =
        generatedRunEntryProjectionOutputAddress := by
    rw [generatedRunEntryProjectionOutputWordAddress,
      ← generatedRunEntryProjectionEntryEspExact]
    exact outputWord.trans generatedRunEntryProjectionOutputAddressExact
  have controlDisjoint :
      checkedNativeOperationPredicateRouteFootprintsDisjointAt
        (generatedRunEntryControlRoute nativeEnvironment)
        (CandidateWordRange generatedRunParameters.inputAddress
          generatedRunLayout.stateSize)
        state := by
    simpa only [generatedRunEntryProtectedRange,
      generatedRunEntryProjectionInputAddressExact,
      generatedRunEntryProjectionLayout, generatedRunLayout] using
        generatedRunEntryControlFootprintsDisjoint nativeEnvironment state
          projectedEspExact projectedInputWord projectedOutputWord
          directionClear
  have bulkDisjoint :
      checkedNativeOperationBlockFootprintsDisjointAt
        (generatedRunEntryBlock2 nativeEnvironment)
        (CandidateWordRange generatedRunParameters.inputAddress
          generatedRunLayout.stateSize)
        (runCheckedNativeOperationPredicateRoute
          (generatedRunEntryControlRoute nativeEnvironment) state) := by
    simpa only [generatedRunEntryProtectedRange,
      generatedRunEntryProjectionInputAddressExact,
      generatedRunEntryProjectionLayout, generatedRunLayout] using
        generatedRunEntryBulkFootprintsDisjoint nativeEnvironment
          (runCheckedNativeOperationPredicateRoute
            (generatedRunEntryControlRoute nativeEnvironment) state)
  have evaluated :
      generatedRunEntryBulkCopyAndContinuation.1.source.eval bulkState =
          generatedRunParameters.inputAddress /\\
        generatedRunEntryBulkCopyAndContinuation.1.destination.eval bulkState =
          generatedRunWorkingStateAddress /\\
        generatedRunEntryBulkCopyAndContinuation.1.count.eval bulkState =
          word32 63 /\\
        generatedRunEntryBulkCopyAndContinuation.1.direction.eval bulkState =
          false := by
    simpa [bulkState] using
      generatedRunEntryDecodedBulkOperands nativeEnvironment state
        espExact inputWord outputWord directionClear
  apply generatedRunEntryBulkSourceFactsOfEntry
  case entryHolds =>
    simpa only [layoutExact, parametersExact] using
      StageA.Relational.InterpreterKernelRunABIProjection.ABIRequestFacts.runFunctionEngineState
        facts
  case sourceRangeFits => exact generatedRunEntryABISourceRangeFits
  case controlDisjoint => exact controlDisjoint
  case bulkDisjoint => exact bulkDisjoint
  case sourceExact => exact evaluated.1.symm
  case destinationExact => exact evaluated.2.1.symm
  case directionExact => exact evaluated.2.2.2
  case destinationFits =>
    rw [evaluated.2.1, evaluated.2.2.1]
    decide +kernel
  case sourceFits =>
    rw [evaluated.1, evaluated.2.2.1]
    decide +kernel
  case disjoint =>
    rw [evaluated.1, evaluated.2.1, evaluated.2.2.1]
    decide +kernel
  case covers =>
    rw [evaluated.2.2.1]
    decide +kernel

/-- Exact native Run prologue execution derived only from checked ABI facts,
decoded control selectors, and the checked bulk-copy semantics. -/
theorem generatedRunEntryABIExactEnginePath
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation}
    {tableRva countRva : Nat} {records : List ProgramRecord}
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva records)
    (layoutExact : abi.engineLayout = generatedRunLayout)
    (parametersExact : abi.parameters = generatedRunParameters)
    (nativeEnvironment : NativeWorldEnvironment)
    (semanticEnvironment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (facts : ABIRequestFacts abi
      (generatedRunRequest records semanticEnvironment resolveCodeTarget
        sourceRva logical) state) :
    let afterBlock0 :=
      (generatedRunEntryStep0 nativeEnvironment).targetState state
    let afterControl :=
      (generatedRunEntryStep1 nativeEnvironment).targetState afterBlock0
    let bulk :=
      generatedRunEntryBulkEngineStep nativeEnvironment generatedRunLayout
        generatedRunParameters.inputAddress generatedRunWorkingStateAddress
        logical sourceRva
    NonemptyRelatedPath
        (generatedClosedKernelOperationNativeProgram
          nativeEnvironment).transitionSystem
        (.running
          (generatedRunEntryBlock0 nativeEnvironment).entryRva
          (generatedRunEntryBlock0 nativeEnvironment).entrySlot
          state calls eventIndex events world)
        []
        (.running
          (generatedRunEntryBlock3 nativeEnvironment).entryRva
          (generatedRunEntryBlock3 nativeEnvironment).entrySlot
          (bulk.targetState afterControl) calls eventIndex events world) /\\
      EngineStateHolds generatedRunLayout generatedRunWorkingStateAddress
        logical sourceRva (bulk.targetState afterControl) := by
  dsimp only
  have control :=
    generatedRunEntryABIControlFacts abi layoutExact parametersExact
      nativeEnvironment semanticEnvironment resolveCodeTarget sourceRva logical
      state facts
  have path0 :=
    (generatedRunEntryStep0 nativeEnvironment).executeOfControlInvariant
      state calls eventIndex events world generatedRunEntrySelectorInvariant0
      (generatedRunEntrySelectorInvariant0Checked nativeEnvironment) control.1
  let afterBlock0 :=
    (generatedRunEntryStep0 nativeEnvironment).targetState state
  have path1 :=
    (generatedRunEntryStep1 nativeEnvironment).executeOfControlInvariant
      afterBlock0 calls eventIndex events world
      generatedRunEntrySelectorInvariant1
      (generatedRunEntrySelectorInvariant1Checked nativeEnvironment)
      control.2.2.1
  let afterControl :=
    (generatedRunEntryStep1 nativeEnvironment).targetState afterBlock0
  have afterControlExact :
      afterControl =
        runCheckedNativeOperationPredicateRoute
          (generatedRunEntryControlRoute nativeEnvironment) state := by
    rfl
  have bulkFactsAtRoute :=
    generatedRunEntryABIBulkSourceFacts abi layoutExact parametersExact
      nativeEnvironment semanticEnvironment resolveCodeTarget sourceRva logical
      state facts
  have bulkFacts : ForwardEngineBulkCopySourceFacts
      (generatedRunEntryBlock2 nativeEnvironment)
      generatedRunEntryBulkCopyAndContinuation.1 generatedRunLayout
      generatedRunParameters.inputAddress generatedRunWorkingStateAddress
      logical sourceRva afterControl :=
    afterControlExact.symm ▸ bulkFactsAtRoute
  have bulkTerminal :
      generatedRunEntryBulkTerminalInvariant.Holds
        ((generatedRunEntryBlock2 nativeEnvironment).terminalState
          afterControl) := by
    rw [generatedRunEntryBulkTerminalInvariantTrivial]
    exact
      StageA.Relational.InterpreterKernelOperationCutpointChecker.trivialNativeOperationInvariant_holds
        _
  let bulk :=
    generatedRunEntryBulkEngineStep nativeEnvironment generatedRunLayout
      generatedRunParameters.inputAddress generatedRunWorkingStateAddress
      logical sourceRva
  have bulkTarget :
      EngineStateHolds generatedRunLayout generatedRunWorkingStateAddress
        logical sourceRva (bulk.targetState afterControl) := by
    exact
      checkedNativeOperationEffectfulBlockStep_targetEngineStateHolds_bulkCopyDwords_forward
        (generatedRunEntryBulkStep nativeEnvironment)
        generatedRunEntryBulkCopyAndContinuation.1
        generatedRunEntryBulkCopyAndContinuation.2
        generatedRunEntryBulkOutcomeIsCopy afterControl bulkFacts.holds
        bulkFacts.sourceExact bulkFacts.destinationExact
        bulkFacts.directionExact bulkFacts.destinationFits
        bulkFacts.sourceFits bulkFacts.disjoint bulkFacts.covers
  have bulkPath :=
    bulk.executeOfTerminalHolds afterControl calls eventIndex events world
      bulkTerminal bulkTarget
  exact And.intro (path0.trans (path1.trans bulkPath.1)) bulkPath.2

#print axioms generatedRunEntryABISourceRangeFits
#print axioms generatedRunEntryBulkCopyOperandsExact
#print axioms generatedRunEntryABIControlFacts
#print axioms generatedRunEntryDecodedBulkOperands
#print axioms generatedRunEntryABIBulkSourceFacts
#print axioms generatedRunEntryABIExactEnginePath

end StageA.GeneratedRelational.InterpreterKernelRunEntryABI
"""


_ABI_INSTANTIATION_MARKER = (
    "/-- The concrete ABI instantiation is kept separate from the route artifact."
)


def _split_run_entry_abi_source() -> tuple[str, str]:
    combined = _combined_run_entry_abi_lean_source()
    prefix, marker, suffix = combined.partition(_ABI_INSTANTIATION_MARKER)
    if not marker:
        raise AssertionError("Run entry ABI source split marker is missing")
    legacy_start = prefix.find(
        "  /-\n  simp (config := { maxSteps := 1000000 })"
    )
    if legacy_start >= 0:
        legacy_end = prefix.find("  -/\n", legacy_start)
        if legacy_end < 0:
            raise AssertionError("unterminated legacy Run entry ABI proof comment")
        prefix = prefix[:legacy_start] + prefix[legacy_end + len("  -/\n") :]
    theorem_body, prints, _end = (marker + suffix).partition(
        "#print axioms generatedRunEntryABISourceRangeFits"
    )
    if not prints:
        raise AssertionError("Run entry ABI axiom-audit marker is missing")
    return prefix.rstrip(), theorem_body.rstrip()


def run_entry_abi_base_lean_source() -> str:
    prefix, _theorem_body = _split_run_entry_abi_source()
    return (
        prefix
        + """

end StageA.GeneratedRelational.InterpreterKernelRunEntryABI
"""
    )


def run_entry_abi_lean_source() -> str:
    _prefix, theorem_body = _split_run_entry_abi_source()
    return f"""import StageA.{INTERPRETER_KERNEL_RUN_ENTRY_ABI_BASE_LEAN_MODULE}
import StageA.GeneratedRelationalInterpreterKernelRunEntryFootprints
import StageA.GeneratedRelationalInterpreterKernelRunOperation

namespace StageA.GeneratedRelational.InterpreterKernelRunEntryABI

open StageA.Formal StageA.Relational
open StageA.Relational.Engine
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelEngineCopy
open StageA.Relational.InterpreterKernelOperationMemoryRoute
open StageA.Relational.InterpreterKernelOperationPredicateRoute
open StageA.Relational.InterpreterKernelOperationProjection
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelOperationCandidate
open StageA.GeneratedRelational.InterpreterKernelOperationInstantiation
open StageA.GeneratedRelational.InterpreterKernelRun
open StageA.GeneratedRelational.InterpreterKernelRunEntryProjection
open StageA.GeneratedRelational.InterpreterKernelRunOperation

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{theorem_body}

/-- Bind the exact checked Run prologue to the generic Run-operation evidence
interface.  This constructor is deliberately downstream of both artifacts:
the operation interface does not depend on its candidate-specific producer. -/
noncomputable def generatedRunFunctionCheckedEntryAuthority
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word)
    (semantics : GeneratedRunFunctionCheckedLocalSemantics environment)
    (invariantExact :
      semantics.invariant = generatedRunFunctionLoopInvariant) :
    RunFunctionNativeCheckedEntryAuthority
      generatedCompiledKernelProgram generatedInterpreterKernelABIRelation
      semanticInterpreterProgramRecords
      (generatedClosedKernelOperationNativeProgram environment) world
      outerContinuationRva outerReturnAddress
      (generatedRunFunctionOperationStatic environment)
      semantics.toLocalSemantics := {{
  entry := by
    intro semanticEnvironment resolveCodeTarget sourceRva logical before
      requestRelated
    have facts : ABIRequestFacts generatedConcreteInterpreterKernelABI
        (generatedRunRequest semanticInterpreterProgramRecords
          semanticEnvironment resolveCodeTarget sourceRva logical) before := by
      simpa [generatedInterpreterKernelABIRelation, generatedRunRequest] using
        requestRelated
    have exactPath :=
      generatedRunEntryABIExactEnginePath
        generatedConcreteInterpreterKernelABI rfl rfl environment
        semanticEnvironment resolveCodeTarget sourceRva logical before
        [runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress]
        0 [] world facts
    let afterBlock0 :=
      (generatedRunEntryStep0 environment).targetState before
    let afterControl :=
      (generatedRunEntryStep1 environment).targetState afterBlock0
    let bulk :=
      generatedRunEntryBulkEngineStep environment generatedRunLayout
        generatedRunParameters.inputAddress generatedRunWorkingStateAddress
        logical sourceRva
    apply RunFunctionNativeEntryPhase.ofExactPath
    case path =>
      simpa [generatedRunFunctionOperationStatic,
        generatedRunFunctionOperationReflected, generatedRunFunctionTemplate,
        afterBlock0, afterControl, bulk] using exactPath.1
    case invariantHolds =>
      rw [invariantExact]
      simp only [generatedRunFunctionLoopInvariant]
      exact And.intro rfl (And.intro rfl exactPath.2)
}}

#print axioms generatedRunEntryABIBulkSourceFacts
#print axioms generatedRunEntryABIControlFacts
#print axioms generatedRunEntryABIExactEnginePath
#print axioms generatedRunFunctionCheckedEntryAuthority

end StageA.GeneratedRelational.InterpreterKernelRunEntryABI
"""


def write_run_entry_abi_bundle(out: Path | str) -> None:
    output = Path(out) / "StageA"
    output.mkdir(parents=True, exist_ok=True)
    (
        output
        / f"{INTERPRETER_KERNEL_RUN_ENTRY_ABI_BASE_LEAN_MODULE}.lean"
    ).write_text(
        run_entry_abi_base_lean_source(),
        encoding="utf-8",
    )
    (output / f"{INTERPRETER_KERNEL_RUN_ENTRY_ABI_LEAN_MODULE}.lean").write_text(
        run_entry_abi_lean_source(),
        encoding="utf-8",
    )


__all__ = [
    "INTERPRETER_KERNEL_RUN_ENTRY_ABI_LEAN_MODULE",
    "INTERPRETER_KERNEL_RUN_ENTRY_ABI_BASE_LEAN_MODULE",
    "run_entry_abi_base_lean_source",
    "run_entry_abi_lean_source",
    "write_run_entry_abi_bundle",
]
