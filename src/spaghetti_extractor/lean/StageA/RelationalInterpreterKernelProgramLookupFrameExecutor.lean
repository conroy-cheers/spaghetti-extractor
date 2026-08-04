import StageA.RelationalInterpreterKernelProgramLookupABIFrame
import StageA.RelationalInterpreterKernelProgramLookupNativeWorldBridge

namespace StageA.Relational.InterpreterKernelProgramLookupFrameExecutor

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelLookupNative
open StageA.Relational.InterpreterKernelOperationABIFrame
open StageA.Relational.InterpreterKernelProgramLookupABIFrame
open StageA.Relational.InterpreterKernelProgramLookupNativeWorldBridge
open StageA.Relational.InterpreterKernelSummary
open StageA.Relational.InterpreterNativeWorld

/-!
# Nested ProgramLookup executor

The checked local ProgramLookup semantics execute as a top-level native
subroutine.  This module replays those exact instructions below one caller
frame.  ProgramLookup is event-free, so the proof never assumes that an
external environment is stable under event-index changes: no external action
is selected along the accepted path.

The final three-instruction epilogue deliberately consumes the checked
instruction inventory as well as `ProgramLookupNativeLocalSemantics`.  The
local-semantics record says that three steps terminate, but does not by itself
exclude an earlier terminal step followed by terminal padding.  Exact
instruction evidence establishes `leave; xor edx, edx; ret` and makes the
caller-frame return constructive.
-/

/-- Extending the native call stack cannot affect an instruction whose exact
top-level successor is still running with the same event history. -/
theorem stepNativeExecution_running_appendCaller
    (candidate : ExactNativeWorldProgram)
    (environment : NativeEnvironment)
    (rva undefinedSlot : Nat) (state : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (nextRva nextUndefinedSlot : Nat) (nextState : MachineState)
    (nextCalls : List NativeCallFrame) (nextEventIndex : Nat)
    (caller : NativeCallFrame)
    (exact :
      stepNativeExecution candidate.pe candidate.imports environment
          (.running rva undefinedSlot state calls eventIndex []) =
        .running nextRva nextUndefinedSlot nextState nextCalls nextEventIndex []) :
    stepNativeExecution candidate.pe candidate.imports environment
        (.running rva undefinedSlot state (calls ++ [caller]) eventIndex []) =
      .running nextRva nextUndefinedSlot nextState
        (nextCalls ++ [caller]) nextEventIndex [] := by
  simp only [stepNativeExecution] at exact ⊢
  generalize machineExact :
    stepKernelPE32Instruction candidate.pe candidate.imports
      (.running rva undefinedSlot state) = stepped at exact ⊢
  cases stepped with
  | running decodedRva decodedSlot decodedState =>
      simp_all
  | fault =>
      simp at exact
  | stopped outcome decodedState =>
      cases outcome with
      | returned target =>
          simp only [nextNativeExecution] at exact ⊢
          cases calls with
          | nil => simp at exact
          | cons frame tail =>
              by_cases targetExact : target = frame.returnAddress <;>
                simp [targetExact] at exact ⊢
              simp_all
      | jump target =>
          simp [nextNativeExecution] at exact ⊢
          simp_all
      | branch condition taken fallthrough =>
          simp [nextNativeExecution] at exact ⊢
          simp_all
      | call target continuation returnAddress =>
          simp [nextNativeExecution] at exact
          rcases exact with
            ⟨rfl, rfl, rfl, nextCallsExact, rfl⟩
          subst nextCalls
          simp [nextNativeExecution, List.cons_append]
      | externalCall imported arguments continuation =>
          simp [nextNativeExecution] at exact
      | externalJump imported arguments =>
          simp only [nextNativeExecution] at exact
          cases calls <;> simp at exact
      | bulkCopy destination source count direction continuation =>
          simp [nextNativeExecution] at exact ⊢
          simp_all
      | bulkFill destination value count direction continuation =>
          simp [nextNativeExecution] at exact ⊢
          simp_all
      | bulkScan accumulator destination count direction continuation =>
          simp [nextNativeExecution] at exact ⊢
          simp_all
      | checkedContinue valid continuation =>
          cases valid <;> simp [nextNativeExecution] at exact ⊢
          simp_all
      | atomicCompareExchange address expected replacement continuation =>
          simp [nextNativeExecution] at exact ⊢
          simp_all
      | indirectCall target continuation returnAddress =>
          simp [nextNativeExecution] at exact
      | indirectJump target =>
          simp [nextNativeExecution] at exact

/-- Replay one event-free running native step under a caller frame in the exact
NativeWorld transition system.  The arbitrary world and its environment are
not inspected. -/
theorem stepNativeExecution_running_appendCaller_toNativeWorld
    (candidate : ExactNativeWorldProgram)
    (environment : NativeEnvironment)
    (world : RelationalWorld)
    (rva undefinedSlot : Nat) (state : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (nextRva nextUndefinedSlot : Nat) (nextState : MachineState)
    (nextCalls : List NativeCallFrame) (nextEventIndex : Nat)
    (caller : NativeCallFrame)
    (exact :
      stepNativeExecution candidate.pe candidate.imports environment
          (.running rva undefinedSlot state calls eventIndex []) =
        .running nextRva nextUndefinedSlot nextState nextCalls nextEventIndex []) :
    candidate.transitionSystem.step
        (.running rva undefinedSlot state (calls ++ [caller]) eventIndex [] world) = {
      next := .running nextRva nextUndefinedSlot nextState
        (nextCalls ++ [caller]) nextEventIndex [] world
      observation := none
    } := by
  exact stepNativeExecution_running_empty_to_nativeWorld candidate environment
    world rva undefinedSlot state (calls ++ [caller]) eventIndex
    nextRva nextUndefinedSlot nextState (nextCalls ++ [caller]) nextEventIndex
    (stepNativeExecution_running_appendCaller candidate environment rva
      undefinedSlot state calls eventIndex nextRva nextUndefinedSlot nextState
      nextCalls nextEventIndex caller exact)

/-- An event-free native fuel computation ending in a running state can be
replayed below a caller frame.  Terminal and external intermediate states are
ruled out by the exact running endpoint, not by a submitted path inventory. -/
theorem runProgramLookupNativeFuel_running_appendCaller_toNativeWorld
    (candidate : ExactNativeWorldProgram)
    (environment : NativeEnvironment)
    (world : RelationalWorld)
    (caller : NativeCallFrame)
    (fuel : Nat)
    (rva undefinedSlot : Nat) (state : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (nextRva nextUndefinedSlot : Nat) (nextState : MachineState)
    (nextCalls : List NativeCallFrame) (nextEventIndex : Nat)
    (exact :
      runProgramLookupNativeFuel candidate.pe candidate.imports environment fuel
          (.running rva undefinedSlot state calls eventIndex []) =
        .running nextRva nextUndefinedSlot nextState nextCalls nextEventIndex []) :
    runRelatedSteps candidate.transitionSystem fuel
        (.running rva undefinedSlot state (calls ++ [caller]) eventIndex [] world) =
      (.running nextRva nextUndefinedSlot nextState
        (nextCalls ++ [caller]) nextEventIndex [] world, []) := by
  induction fuel generalizing rva undefinedSlot state calls eventIndex with
  | zero =>
      simp only [runProgramLookupNativeFuel] at exact
      cases exact
      rfl
  | succ fuel induction =>
      simp only [runProgramLookupNativeFuel] at exact
      generalize middleExact :
        stepNativeExecution candidate.pe candidate.imports environment
          (.running rva undefinedSlot state calls eventIndex []) = middle at exact
      cases middle with
      | running middleRva middleUndefinedSlot middleState middleCalls
          middleEventIndex middleEvents =>
          have eventsLength :
              middleEvents.length <= 0 :=
            runProgramLookupNativeFuel_recordedEvents_length_mono candidate.pe
              candidate.imports environment fuel
              (.running middleRva middleUndefinedSlot middleState middleCalls
                middleEventIndex middleEvents)
              (.running nextRva nextUndefinedSlot nextState nextCalls
                nextEventIndex [])
              middleEvents [] rfl exact rfl
          have eventsEmpty : middleEvents = [] := by
            cases middleEvents with
            | nil => rfl
            | cons head tail => simp at eventsLength
          subst middleEvents
          have first :=
            stepNativeExecution_running_appendCaller_toNativeWorld candidate
              environment world rva undefinedSlot state calls eventIndex
              middleRva middleUndefinedSlot middleState middleCalls
              middleEventIndex caller middleExact
          have rest :=
            induction middleRva middleUndefinedSlot middleState middleCalls
              middleEventIndex exact
          simp only [runRelatedSteps]
          rw [first, rest]
          rfl
      | returned middleState middleEvents =>
          rw [runProgramLookupNativeFuel_returned] at exact
          contradiction
      | fault =>
          rw [runProgramLookupNativeFuel_fault] at exact
          contradiction
      | unsupportedIndirect targetRva target =>
          rw [runProgramLookupNativeFuel_unsupportedIndirect] at exact
          contradiction

/-- The exact checked `ret` consumes the supplied caller frame. -/
theorem ProgramLookupNativeInstructionInventory.stepRetUnderCallerExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState)
    (caller : NativeCallFrame) (eventIndex : Nat)
    (returnAddressLoaded :
      Memory.read32 state.memory state.registers.esp = caller.returnAddress) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 160) undefinedSlot state [caller]
          eventIndex []) =
      .running caller.continuationRva 0
        (programLookupNativeRetResult state) [] eventIndex [] := by
  rw [inventory.stepNativeAt imports environment 160 (by decide)]
  simp (config := { maxSteps := 200000 })
    [programLookupNativeRetResult, programLookupNativeInitialFlags,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, nextNativeExecution,
      executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.offset,
      Expr.addNormalized, symbolicRead32, exactWrite32WithDisjointTail?,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, programLookupNativeOrdinaryX87,
      returnAddressLoaded]

/-- Exact three-instruction nested epilogue. -/
theorem ProgramLookupNativeInstructionInventory.epilogueUnderCaller
    {candidate : ExactNativeWorldProgram}
    (inventory : ProgramLookupNativeInstructionInventory candidate.pe parameters)
    (world : RelationalWorld)
    (caller : NativeCallFrame)
    (sourceRva undefinedSlot : Nat)
    (before state : MachineState)
    (cutpoint : ProgramLookupNativeEpilogueCutpoint candidate.pe parameters
      records sourceRva before state)
    (returnAddressLoaded :
      Memory.read32 before.memory before.registers.esp = caller.returnAddress) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running (parameters.entryRva + 157) undefinedSlot state [caller] 0 []
        world)
      []
      (.running caller.continuationRva 0
        (programLookupNativeEpilogueResult undefinedSlot state) [] 0 [] world) := by
  let leaveState := programLookupNativeLeaveResult state
  let xorState :=
    programLookupNativeXorEdxResult (undefinedSlot + 1) leaveState
  have leaveNative :=
    inventory.stepLeaveExact candidate.imports
      programLookupIdentityNativeEnvironment undefinedSlot state []
  have leaveNested :=
    stepNativeExecution_running_appendCaller candidate
      programLookupIdentityNativeEnvironment
      (parameters.entryRva + 157) undefinedSlot state [] 0
      (parameters.entryRva + 158) (undefinedSlot + 1) leaveState [] 0 caller
      (by simpa [leaveState] using leaveNative)
  have leaveWorld :=
    stepNativeExecution_running_empty_to_nativeWorld candidate
      programLookupIdentityNativeEnvironment world
      (parameters.entryRva + 157) undefinedSlot state [caller] 0
      (parameters.entryRva + 158) (undefinedSlot + 1) leaveState [caller] 0
      leaveNested
  have xorNative :=
    inventory.stepXorEdxExact candidate.imports
      programLookupIdentityNativeEnvironment (undefinedSlot + 1) leaveState []
  have xorNested :=
    stepNativeExecution_running_appendCaller candidate
      programLookupIdentityNativeEnvironment
      (parameters.entryRva + 158) (undefinedSlot + 1) leaveState [] 0
      (parameters.entryRva + 160) (undefinedSlot + 1 + 1) xorState [] 0 caller
      (by simpa [xorState] using xorNative)
  have xorWorld :=
    stepNativeExecution_running_empty_to_nativeWorld candidate
      programLookupIdentityNativeEnvironment world
      (parameters.entryRva + 158) (undefinedSlot + 1) leaveState [caller] 0
      (parameters.entryRva + 160) (undefinedSlot + 1 + 1) xorState [caller] 0
      xorNested
  have retAddress :
      Memory.read32 xorState.memory xorState.registers.esp =
        caller.returnAddress := by
    rw [show xorState.memory = state.memory by
      rfl]
    rw [show xorState.registers.esp = before.registers.esp by
      simp only [xorState, leaveState, programLookupNativeXorEdxResult,
        programLookupNativeLeaveResult]
      rw [cutpoint.framePointerExact]
      unfold programLookupStackSub
      bv_decide]
    exact cutpoint.returnAddressPreserved.trans returnAddressLoaded
  have retNative :=
    stepRetUnderCallerExact inventory candidate.imports
      programLookupIdentityNativeEnvironment (undefinedSlot + 1 + 1) xorState
      caller 0 retAddress
  have retWorld :=
    stepNativeExecution_running_empty_to_nativeWorld candidate
      programLookupIdentityNativeEnvironment world
      (parameters.entryRva + 160) (undefinedSlot + 1 + 1) xorState [caller] 0
      caller.continuationRva 0 (programLookupNativeRetResult xorState) [] 0
      retNative
  refine ⟨3, by omega, ?_⟩
  simp only [runRelatedSteps]
  rw [leaveWorld, xorWorld, retWorld]
  rfl

/-- Generic nested ProgramLookup execution theorem.  The data-dependent prefix
comes only from exact local semantics; the final return is checked from exact
instruction bytes.  No submitted endpoint, observation inventory, status, or
count can authorize the result. -/
theorem
    programLookupNativeLocalSemantics_programLookupRefinesUsingFrameExecutor
    {candidate : ExactNativeWorldProgram}
    {function : KernelFunction}
    {relocations : List BaseRelocation}
    {tableOffset countOffset : Nat}
    {records : List ProgramRecord}
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI candidate.pe candidate.imports relocations
      tableOffset countOffset records)
    (certificate : ProgramLookupNativeTemplateCertificate abi.program candidate.pe
      candidate.imports function)
    (inventory : ProgramLookupNativeInstructionInventory candidate.pe
      certificate.template.parameters)
    (semantics : ProgramLookupNativeLocalSemantics candidate.pe candidate.imports
      programLookupIdentityNativeEnvironment records
        abi.tableCertificate.transferCount certificate)
    (tableExact : certificate.template.parameters.tableRva = tableOffset)
    (countExact : certificate.template.parameters.countRva = countOffset)
    (recordSourcesFit : programLookupRecordSourcesFit records = true)
    (entryRvaExact : abi.program.functionEntry? .programLookup =
      some certificate.template.parameters.entryRva)
    (world : RelationalWorld)
    (continuationRva : Nat) (returnAddress : Word)
    (returnAddressExact : returnAddress = frame.returnAddress) :
    KernelOperationRefinesUsing abi.program (frame.relation abi)
      (NativeWorldSubroutineDispatches candidate world continuationRva
        returnAddress) .programLookup := by
  let concreteABI :=
    programLookupNativeConcreteABIForFrame frame abi certificate tableExact
      countExact recordSourcesFit
  intro request before operationMatches requestRelated response transition
  cases request with
  | programLookup requestRecords sourceRva =>
      obtain ⟨recordsExact, ⟨entry⟩⟩ :=
        concreteABI.requestEntry requestRecords sourceRva before requestRelated
      subst requestRecords
      cases transition
      obtain ⟨resultIndex, trace⟩ :=
        reflectedProgramLookupTrace_exists records sourceRva 0
          abi.tableCertificate.transferCount (by
          rw [entry.loaded.transferCountExact]
          omega)
      obtain ⟨loopState, prologueExact, loopCutpoint⟩ :=
        semantics.prologue sourceRva before entry
      obtain ⟨loopFuel, resultSlot, resultState, loopExact, resultCutpoint⟩ :=
        programLookupNativeLocalSemantics_traceToLoopExitFuel
          (undefinedSlot := 0) semantics trace loopCutpoint
      obtain ⟨finishFuel, epilogueSlot, epilogueState, finishPositive,
        finishBound, finishExact, epilogueCutpoint⟩ :=
        semantics.finish sourceRva before resultState resultIndex resultSlot
          resultCutpoint trace
      let caller : NativeCallFrame := { continuationRva, returnAddress }
      let prefixFuel := 7 + loopFuel + finishFuel
      have prefixPositive : 0 < prefixFuel := by
        simp only [prefixFuel]
        omega
      have prefixExact :
          runProgramLookupNativeFuel candidate.pe candidate.imports
              programLookupIdentityNativeEnvironment prefixFuel
              (.running certificate.template.parameters.entryRva 0 before [] 0 []) =
            .running (certificate.template.parameters.entryRva + 157)
              epilogueSlot epilogueState [] 0 [] := by
        simp only [prefixFuel]
        rw [runProgramLookupNativeFuel_add, runProgramLookupNativeFuel_add,
          prologueExact, loopExact, finishExact]
      have prefixWorldExact :=
        runProgramLookupNativeFuel_running_appendCaller_toNativeWorld candidate
          programLookupIdentityNativeEnvironment world caller prefixFuel
          certificate.template.parameters.entryRva 0 before [] 0
          (certificate.template.parameters.entryRva + 157) epilogueSlot
          epilogueState [] 0 prefixExact
      have prefixPath :
          NonemptyRelatedPath candidate.transitionSystem
            (.running certificate.template.parameters.entryRva 0 before [caller]
              0 [] world)
            []
            (.running (certificate.template.parameters.entryRva + 157)
              epilogueSlot epilogueState [caller] 0 [] world) :=
        ⟨prefixFuel, prefixPositive, prefixWorldExact⟩
      have framedRequest :
          KernelOperationABIFrame.RequestFacts frame abi
            (.programLookup records sourceRva) before := by
        exact requestRelated
      have callerReturnLoaded :
          Memory.read32 before.memory before.registers.esp =
            caller.returnAddress := by
        have cdecl := framedRequest.cdecl
        rcases cdecl with
          ⟨operationExact, espExact, ebxExact, esiExact, ediExact, ebpExact,
            words, stackRange⟩
        simp only [KernelOperationABIFrame.requestArguments, WordsAt] at words
        change Memory.read32 before.memory before.registers.esp = returnAddress
        rw [espExact, returnAddressExact]
        exact words.1
      have epiloguePath :=
        StageA.Relational.InterpreterKernelProgramLookupFrameExecutor.ProgramLookupNativeInstructionInventory.epilogueUnderCaller
          inventory world caller sourceRva epilogueSlot before epilogueState
          epilogueCutpoint callerReturnLoaded
      let after :=
        programLookupNativeEpilogueResult epilogueSlot epilogueState
      have returnState :
          ProgramLookupNativeReturnState candidate.pe
            certificate.template.parameters records sourceRva before after := by
        exact epilogueCutpoint.result
      refine ⟨certificate.template.parameters.entryRva, after, [],
        entryRvaExact, ?_,
        concreteABI.responseExit sourceRva before after requestRelated
          returnState,
        ?_⟩
      · exact ⟨{
          afterWorld := world
          observations := []
          path := by
            simpa [caller, after] using prefixPath.trans epiloguePath
        }⟩
      · intro address outsideScratch
        apply returnState.memoryFrame address
        intro inFrame
        exact outsideScratch
          (concreteABI.scratchContainsFrame sourceRva before address
            requestRelated entry inFrame)
  | interpreterStep requestRecords requestEnvironment sourceRva logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | runFunction requestRecords requestEnvironment resolveCodeTarget sourceRva
      logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | invokeCall requestRecords requestEnvironment resolveCodeTarget event logical =>
      simp [AbstractKernelRequest.operation] at operationMatches

#print axioms stepNativeExecution_running_appendCaller
#print axioms runProgramLookupNativeFuel_running_appendCaller_toNativeWorld
#print axioms ProgramLookupNativeInstructionInventory.stepRetUnderCallerExact
#print axioms ProgramLookupNativeInstructionInventory.epilogueUnderCaller
#print axioms
  programLookupNativeLocalSemantics_programLookupRefinesUsingFrameExecutor

end StageA.Relational.InterpreterKernelProgramLookupFrameExecutor
