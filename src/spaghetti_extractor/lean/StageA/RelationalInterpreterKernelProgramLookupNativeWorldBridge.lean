import StageA.RelationalInterpreterKernelInvokeNative
import StageA.RelationalInterpreterKernelLookupNative
import StageA.RelationalInterpreterKernelOperationFrameParametric

namespace StageA.Relational.InterpreterKernelProgramLookupNativeWorldBridge

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelLookupNative
open StageA.Relational.InterpreterKernelLoop
open StageA.Relational.InterpreterKernelOperationFrameParametric
open StageA.Relational.InterpreterKernelSummary
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact ProgramLookup NativeWorld bridge

`programLookup` has an exact native proof below `NativeExecution`, while the
whole-program operation family executes below `NativeWorldExecution`.  This
module is the sole adapter between those two interfaces.  It keeps the
relational world as an explicit parameter and uses the generic checked
frame-context lifting theorem for nested calls.

The generated GNU binding supplies the exact ProgramLookup producer and its
checked path refinement.  It cannot supply an endpoint, erase the world, or
replace the ABI response and memory-frame facts selected by the operation
proof.
-/

def nativeExecutionRecordedEvents? :
    NativeExecution -> Option (List NativeExternalEvent)
  | .running _ _ _ _ _ events | .returned _ events => some events
  | .fault | .unsupportedIndirect _ _ => none

def programLookupIdentityNativeEnvironment : NativeEnvironment := {
  result := fun _ event => event.state
}

theorem stepNativeExecution_recordedEvents_length_mono
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (before after : NativeExecution) (beforeEvents afterEvents :
      List NativeExternalEvent)
    (beforeExact : nativeExecutionRecordedEvents? before = some beforeEvents)
    (stepExact : stepNativeExecution pe imports environment before = after)
    (afterExact : nativeExecutionRecordedEvents? after = some afterEvents) :
    beforeEvents.length <= afterEvents.length := by
  cases before with
  | returned state events =>
      simp [stepNativeExecution, nativeExecutionRecordedEvents?] at beforeExact stepExact
      subst beforeEvents
      subst after
      simp [nativeExecutionRecordedEvents?] at afterExact
      subst afterEvents
      exact Nat.le_refl _
  | fault =>
      simp [nativeExecutionRecordedEvents?] at beforeExact
  | unsupportedIndirect rva target =>
      simp [nativeExecutionRecordedEvents?] at beforeExact
  | running rva undefinedSlot state calls eventIndex events =>
      simp only [nativeExecutionRecordedEvents?, Option.some.injEq] at beforeExact
      subst beforeEvents
      simp only [stepNativeExecution] at stepExact
      generalize machineExact :
        stepKernelPE32Instruction pe imports
          (.running rva undefinedSlot state) = stepped at stepExact
      cases stepped with
      | running nextRva nextSlot nextState =>
          subst after
          simp [nativeExecutionRecordedEvents?] at afterExact
          subst afterEvents
          exact Nat.le_refl _
      | fault =>
          subst after
          simp [nativeExecutionRecordedEvents?] at afterExact
      | stopped outcome nextState =>
          cases outcome with
          | returned target =>
              simp only [nextNativeExecution] at stepExact
              cases calls with
              | nil =>
                  subst after
                  simp [nativeExecutionRecordedEvents?] at afterExact
                  subst afterEvents
                  exact Nat.le_refl _
              | cons frame tail =>
                  by_cases targetExact : target = frame.returnAddress
                  · simp [targetExact] at stepExact
                    subst after
                    simp [nativeExecutionRecordedEvents?] at afterExact
                    subst afterEvents
                    exact Nat.le_refl _
                  · simp [targetExact] at stepExact
                    subst after
                    simp [nativeExecutionRecordedEvents?] at afterExact
          | jump target =>
              simp only [nextNativeExecution] at stepExact
              subst after
              simp [nativeExecutionRecordedEvents?] at afterExact
              subst afterEvents
              exact Nat.le_refl _
          | branch condition taken fallthrough =>
              simp only [nextNativeExecution] at stepExact
              subst after
              simp [nativeExecutionRecordedEvents?] at afterExact
              subst afterEvents
              exact Nat.le_refl _
          | call target continuation returnAddress =>
              simp only [nextNativeExecution] at stepExact
              subst after
              simp [nativeExecutionRecordedEvents?] at afterExact
              subst afterEvents
              exact Nat.le_refl _
          | externalCall imported arguments continuation =>
              simp only [nextNativeExecution] at stepExact
              subst after
              simp [nativeExecutionRecordedEvents?] at afterExact
              subst afterEvents
              simp
          | externalJump imported arguments =>
              simp only [nextNativeExecution] at stepExact
              cases calls with
              | nil =>
                  subst after
                  simp [nativeExecutionRecordedEvents?] at afterExact
                  subst afterEvents
                  simp
              | cons frame tail =>
                  subst after
                  simp [nativeExecutionRecordedEvents?] at afterExact
                  subst afterEvents
                  simp
          | bulkCopy destination source count direction continuation =>
              simp only [nextNativeExecution] at stepExact
              subst after
              simp [nativeExecutionRecordedEvents?] at afterExact
              subst afterEvents
              exact Nat.le_refl _
          | bulkFill destination value count direction continuation =>
              simp only [nextNativeExecution] at stepExact
              subst after
              simp [nativeExecutionRecordedEvents?] at afterExact
              subst afterEvents
              exact Nat.le_refl _
          | bulkScan accumulator destination count direction continuation =>
              simp only [nextNativeExecution] at stepExact
              subst after
              simp [nativeExecutionRecordedEvents?] at afterExact
              subst afterEvents
              exact Nat.le_refl _
          | checkedContinue valid continuation =>
              simp only [nextNativeExecution] at stepExact
              cases valid with
              | false =>
                  subst after
                  simp [nativeExecutionRecordedEvents?] at afterExact
              | true =>
                  subst after
                  simp [nativeExecutionRecordedEvents?] at afterExact
                  subst afterEvents
                  exact Nat.le_refl _
          | atomicCompareExchange address expected replacement continuation =>
              simp only [nextNativeExecution] at stepExact
              subst after
              simp [nativeExecutionRecordedEvents?] at afterExact
              subst afterEvents
              exact Nat.le_refl _
          | indirectCall target continuation returnAddress =>
              simp only [nextNativeExecution] at stepExact
              subst after
              simp [nativeExecutionRecordedEvents?] at afterExact
          | indirectJump target =>
              simp only [nextNativeExecution] at stepExact
              subst after
              simp [nativeExecutionRecordedEvents?] at afterExact

@[simp] theorem runProgramLookupNativeFuel_fault
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (fuel : Nat) :
    runProgramLookupNativeFuel pe imports environment fuel .fault = .fault := by
  induction fuel with
  | zero => rfl
  | succ fuel induction =>
      simpa [runProgramLookupNativeFuel, stepNativeExecution] using induction

@[simp] theorem runProgramLookupNativeFuel_unsupportedIndirect
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (fuel rva : Nat) (target : Word) :
    runProgramLookupNativeFuel pe imports environment fuel
        (.unsupportedIndirect rva target) =
      .unsupportedIndirect rva target := by
  induction fuel with
  | zero => rfl
  | succ fuel induction =>
      simpa [runProgramLookupNativeFuel, stepNativeExecution] using induction

/-- An event-free native instruction whose exact result is still running has
the same state transition in the NativeWorld executor.  The relational world
is an explicit unchanged parameter; external and indirect outcomes cannot
satisfy the event-free native endpoint equation. -/
theorem stepNativeExecution_running_empty_to_nativeWorld
    (candidate : ExactNativeWorldProgram) (environment : NativeEnvironment)
    (world : RelationalWorld)
    (rva undefinedSlot : Nat) (state : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (nextRva nextUndefinedSlot : Nat) (nextState : MachineState)
    (nextCalls : List NativeCallFrame) (nextEventIndex : Nat)
    (exact :
      stepNativeExecution candidate.pe candidate.imports environment
          (.running rva undefinedSlot state calls eventIndex []) =
        .running nextRva nextUndefinedSlot nextState nextCalls nextEventIndex []) :
    candidate.transitionSystem.step
        (.running rva undefinedSlot state calls eventIndex [] world) = {
      next := .running nextRva nextUndefinedSlot nextState nextCalls
        nextEventIndex [] world
      observation := none
    } := by
  simp only [ExactNativeWorldProgram.transitionSystem,
    stepPE32NativeWorldExecution, stepNativeExecution] at exact ⊢
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
          simp only [nextNativeExecution] at exact
          simp only [transitionFromNativeWorldOutcome]
          cases calls with
          | nil => simp at exact
          | cons frame tail =>
              by_cases targetExact : target = frame.returnAddress <;>
                simp [targetExact] at exact ⊢
              simp_all
      | externalJump imported arguments =>
          simp only [nextNativeExecution] at exact
          cases calls <;> simp at exact
      | checkedContinue valid continuation =>
          simp only [nextNativeExecution] at exact
          cases valid <;> simp at exact ⊢
          simp_all [transitionFromNativeWorldOutcome]
      | externalCall imported arguments continuation =>
          simp [nextNativeExecution] at exact
      | indirectCall target continuation returnAddress =>
          simp [nextNativeExecution] at exact
      | indirectJump target =>
          simp [nextNativeExecution] at exact
      | jump target =>
          simp [nextNativeExecution] at exact
          simp [transitionFromNativeWorldOutcome, exact]
      | branch condition taken fallthrough =>
          simp [nextNativeExecution] at exact
          simp [transitionFromNativeWorldOutcome, exact]
      | call target continuation returnAddress =>
          simp [nextNativeExecution] at exact
          simp [transitionFromNativeWorldOutcome, exact]
      | bulkCopy destination source count direction continuation =>
          simp [nextNativeExecution] at exact
          simp [transitionFromNativeWorldOutcome, exact]
      | bulkFill destination value count direction continuation =>
          simp [nextNativeExecution] at exact
          simp [transitionFromNativeWorldOutcome, exact]
      | bulkScan accumulator destination count direction continuation =>
          simp [nextNativeExecution] at exact
          simp [transitionFromNativeWorldOutcome, exact]
      | atomicCompareExchange address expected replacement continuation =>
          simp [nextNativeExecution] at exact
          simp [transitionFromNativeWorldOutcome, exact]

/-- The only event-free native instruction that reaches a top-level return
produces the NativeWorld return observation while preserving the exact world. -/
theorem stepNativeExecution_returned_empty_to_nativeWorld
    (candidate : ExactNativeWorldProgram) (environment : NativeEnvironment)
    (world : RelationalWorld)
    (rva undefinedSlot : Nat) (state : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (after : MachineState)
    (exact :
      stepNativeExecution candidate.pe candidate.imports environment
          (.running rva undefinedSlot state calls eventIndex []) =
        .returned after []) :
    candidate.transitionSystem.step
        (.running rva undefinedSlot state calls eventIndex [] world) = {
      next := .returned after [] world
      observation := some (.returned world after.registers.eax)
    } := by
  simp only [ExactNativeWorldProgram.transitionSystem,
    stepPE32NativeWorldExecution, stepNativeExecution] at exact ⊢
  generalize machineExact :
    stepKernelPE32Instruction candidate.pe candidate.imports
      (.running rva undefinedSlot state) = stepped at exact ⊢
  cases stepped with
  | running decodedRva decodedSlot decodedState =>
      simp at exact
  | fault =>
      simp at exact
  | stopped outcome decodedState =>
      cases outcome with
      | returned target =>
          cases calls with
          | nil =>
              simp [nextNativeExecution] at exact
              simp [transitionFromNativeWorldOutcome, exact]
          | cons frame tail =>
              by_cases targetExact : target = frame.returnAddress <;>
                simp [nextNativeExecution, targetExact] at exact
      | externalJump imported arguments =>
          cases calls <;> simp [nextNativeExecution] at exact
      | checkedContinue valid continuation =>
          cases valid <;> simp [nextNativeExecution] at exact
      | externalCall imported arguments continuation =>
          simp [nextNativeExecution] at exact
      | indirectCall target continuation returnAddress =>
          simp [nextNativeExecution] at exact
      | indirectJump target =>
          simp [nextNativeExecution] at exact
      | jump target =>
          simp [nextNativeExecution] at exact
      | branch condition taken fallthrough =>
          simp [nextNativeExecution] at exact
      | call target continuation returnAddress =>
          simp [nextNativeExecution] at exact
      | bulkCopy destination source count direction continuation =>
          simp [nextNativeExecution] at exact
      | bulkFill destination value count direction continuation =>
          simp [nextNativeExecution] at exact
      | bulkScan accumulator destination count direction continuation =>
          simp [nextNativeExecution] at exact
      | atomicCompareExchange address expected replacement continuation =>
          simp [nextNativeExecution] at exact

theorem runProgramLookupNativeFuel_recordedEvents_length_mono
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (fuel : Nat) (before after : NativeExecution)
    (beforeEvents afterEvents : List NativeExternalEvent)
    (beforeExact : nativeExecutionRecordedEvents? before = some beforeEvents)
    (runExact :
      runProgramLookupNativeFuel pe imports environment fuel before = after)
    (afterExact : nativeExecutionRecordedEvents? after = some afterEvents) :
    beforeEvents.length <= afterEvents.length := by
  induction fuel generalizing before beforeEvents with
  | zero =>
      simp only [runProgramLookupNativeFuel] at runExact
      subst after
      rw [beforeExact] at afterExact
      injection afterExact with eventsExact
      subst afterEvents
      exact Nat.le_refl _
  | succ fuel induction =>
      simp only [runProgramLookupNativeFuel] at runExact
      generalize middleExact :
        stepNativeExecution pe imports environment before = middle at runExact
      cases middle with
      | running rva undefinedSlot state calls eventIndex middleEvents =>
          exact Nat.le_trans
            (stepNativeExecution_recordedEvents_length_mono pe imports
              environment before
              (.running rva undefinedSlot state calls eventIndex middleEvents)
              beforeEvents middleEvents beforeExact middleExact rfl)
            (induction
              (.running rva undefinedSlot state calls eventIndex middleEvents)
              middleEvents rfl runExact)
      | returned state middleEvents =>
          exact Nat.le_trans
            (stepNativeExecution_recordedEvents_length_mono pe imports
              environment before (.returned state middleEvents)
              beforeEvents middleEvents beforeExact middleExact rfl)
            (induction (.returned state middleEvents)
              middleEvents rfl runExact)
      | fault =>
          have afterFault : after = .fault :=
            runExact.symm.trans
              (runProgramLookupNativeFuel_fault pe imports environment fuel)
          rw [afterFault] at afterExact
          simp [nativeExecutionRecordedEvents?] at afterExact
      | unsupportedIndirect rva target =>
          have afterUnsupported : after = .unsupportedIndirect rva target :=
            runExact.symm.trans
              (runProgramLookupNativeFuel_unsupportedIndirect pe imports
                environment fuel rva target)
          rw [afterUnsupported] at afterExact
          simp [nativeExecutionRecordedEvents?] at afterExact

@[simp] theorem runProgramLookupNativeFuel_returned
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (fuel : Nat) (state : MachineState) (events : List NativeExternalEvent) :
    runProgramLookupNativeFuel pe imports environment fuel
        (.returned state events) =
      .returned state events := by
  induction fuel with
  | zero => rfl
  | succ fuel induction =>
      simpa [runProgramLookupNativeFuel, stepNativeExecution] using induction

@[simp] theorem runRelatedSteps_nativeWorld_returned
    (candidate : ExactNativeWorldProgram) (fuel : Nat)
    (state : MachineState) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    runRelatedSteps candidate.transitionSystem fuel
        (.returned state events world) =
      (.returned state events world, []) := by
  induction fuel with
  | zero => rfl
  | succ fuel induction =>
      simp only [runRelatedSteps, ExactNativeWorldProgram.transitionSystem,
        stepPE32NativeWorldExecution, Option.toList_none, List.nil_append]
      exact induction

/-- Replay an exact event-free native fuel equation in the world machine.
Every intermediate event list is proved empty from monotonicity, so the
arbitrary NativeWorld environment is never consulted.  The same input world
appears in the exact path and the returned endpoint. -/
theorem runProgramLookupNativeFuel_returned_empty_to_nativeWorld
    (candidate : ExactNativeWorldProgram) (environment : NativeEnvironment)
    (world : RelationalWorld) (fuel : Nat)
    (rva undefinedSlot : Nat) (state : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (after : MachineState)
    (exact :
      runProgramLookupNativeFuel candidate.pe candidate.imports environment fuel
          (.running rva undefinedSlot state calls eventIndex []) =
        .returned after []) :
    runRelatedSteps candidate.transitionSystem fuel
        (.running rva undefinedSlot state calls eventIndex [] world) =
      (.returned after [] world,
        [.returned world after.registers.eax]) := by
  induction fuel generalizing rva undefinedSlot state calls eventIndex with
  | zero =>
      simp [runProgramLookupNativeFuel] at exact
  | succ fuel induction =>
      simp only [runProgramLookupNativeFuel] at exact
      generalize middleExact :
        stepNativeExecution candidate.pe candidate.imports environment
          (.running rva undefinedSlot state calls eventIndex []) = middle at exact
      cases middle with
      | running nextRva nextUndefinedSlot nextState nextCalls nextEventIndex
          nextEvents =>
          have eventsLength :
              nextEvents.length <= 0 :=
            runProgramLookupNativeFuel_recordedEvents_length_mono
              candidate.pe candidate.imports environment fuel
              (.running nextRva nextUndefinedSlot nextState nextCalls
                nextEventIndex nextEvents)
              (.returned after []) nextEvents [] rfl exact rfl
          have eventsEmpty : nextEvents = [] :=
            by
              cases nextEvents with
              | nil => rfl
              | cons head tail => simp at eventsLength
          subst nextEvents
          have first :=
            stepNativeExecution_running_empty_to_nativeWorld candidate
              environment world rva undefinedSlot state calls eventIndex
              nextRva nextUndefinedSlot nextState nextCalls nextEventIndex
              middleExact
          have rest :=
            induction nextRva nextUndefinedSlot nextState nextCalls
              nextEventIndex exact
          simp only [runRelatedSteps]
          rw [first, rest]
          rfl
      | returned nextState nextEvents =>
          rw [runProgramLookupNativeFuel_returned] at exact
          cases exact
          have first :=
            stepNativeExecution_returned_empty_to_nativeWorld candidate
              environment world rva undefinedSlot state calls eventIndex after
              middleExact
          simp only [runRelatedSteps]
          rw [first, runRelatedSteps_nativeWorld_returned]
          rfl
      | fault =>
          rw [runProgramLookupNativeFuel_fault] at exact
          contradiction
      | unsupportedIndirect targetRva target =>
          rw [runProgramLookupNativeFuel_unsupportedIndirect] at exact
          contradiction

/-- Retain the exact fuel while composing the reflected binary-search trace.
Unlike `NativeSteps`, this form can be replayed by the NativeWorld executor
without selecting a new endpoint. -/
theorem programLookupNativeLocalSemantics_traceToLoopExitFuel
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {function : KernelFunction} {environment : NativeEnvironment}
    {records : List StageA.Relational.Interpreter.ProgramRecord}
    {transferCount sourceRva low high resultIndex undefinedSlot : Nat}
    {before state : MachineState}
    {certificate : ProgramLookupNativeTemplateCertificate program pe imports
      function}
    (semantics : ProgramLookupNativeLocalSemantics pe imports environment records
      transferCount certificate)
    (trace : ReflectedProgramLookupTrace records sourceRva low high resultIndex)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe
      certificate.template.parameters records transferCount sourceRva low high
      before state) :
    exists fuel resultSlot resultState,
      runProgramLookupNativeFuel pe imports environment fuel
          (.running (certificate.template.parameters.entryRva + 89)
            undefinedSlot state [] 0 []) =
        .running (certificate.template.parameters.entryRva + 89) resultSlot
          resultState [] 0 [] /\
      ProgramLookupNativeLoopCutpoint pe certificate.template.parameters records
        transferCount sourceRva resultIndex resultIndex before resultState := by
  induction trace generalizing state undefinedSlot with
  | done index invariant =>
      exact ⟨0, undefinedSlot, state, rfl, cutpoint⟩
  | lower low high midpoint resultIndex record invariantBefore notConverged
      midpointExact recordAt recordLess invariantAfter rankDecreases rest
      induction =>
      obtain ⟨nextState, chunkExact, nextCutpoint⟩ :=
        semantics.lowerIteration sourceRva before state low high midpoint record
          cutpoint undefinedSlot notConverged midpointExact recordAt recordLess
      obtain ⟨restFuel, resultSlot, resultState, restExact, resultCutpoint⟩ :=
        induction nextCutpoint
      refine ⟨25 + restFuel, resultSlot, resultState, ?_, resultCutpoint⟩
      rw [runProgramLookupNativeFuel_add, chunkExact, restExact]
  | upper low high midpoint resultIndex record invariantBefore notConverged
      midpointExact recordAt recordNotLess invariantAfter rankDecreases rest
      induction =>
      obtain ⟨nextState, chunkExact, nextCutpoint⟩ :=
        semantics.upperIteration sourceRva before state low high midpoint record
          cutpoint undefinedSlot notConverged midpointExact recordAt
          recordNotLess
      obtain ⟨restFuel, resultSlot, resultState, restExact, resultCutpoint⟩ :=
        induction nextCutpoint
      refine ⟨23 + restFuel, resultSlot, resultState, ?_, resultCutpoint⟩
      rw [runProgramLookupNativeFuel_add, chunkExact, restExact]

/-- Compose the exact local ProgramLookup laws into one positive fuel equation.
The final state remains an output of the checked instruction semantics. -/
theorem programLookupNativeLocalSemantics_constructsNativeFuel
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {function : KernelFunction} {environment : NativeEnvironment}
    {records : List StageA.Relational.Interpreter.ProgramRecord}
    {transferCount sourceRva resultIndex : Nat}
    {before : MachineState}
    {certificate : ProgramLookupNativeTemplateCertificate program pe imports
      function}
    (semantics : ProgramLookupNativeLocalSemantics pe imports environment records
      transferCount certificate)
    (entry : ProgramLookupNativeLoadedEntry pe certificate.template.parameters
      records transferCount sourceRva before)
    (trace : ReflectedProgramLookupTrace records sourceRva 0 transferCount
      resultIndex) :
    exists fuel after,
      0 < fuel /\
      runProgramLookupNativeFuel pe imports environment fuel
          (.running certificate.template.parameters.entryRva 0 before [] 0 []) =
        .returned after [] /\
      ProgramLookupNativeReturnState pe certificate.template.parameters records
        sourceRva before after := by
  obtain ⟨loopState, prologueExact, loopCutpoint⟩ :=
    semantics.prologue sourceRva before entry
  obtain ⟨loopFuel, resultSlot, resultState, loopExact, resultCutpoint⟩ :=
    programLookupNativeLocalSemantics_traceToLoopExitFuel semantics trace
      loopCutpoint
  obtain ⟨finishFuel, epilogueSlot, epilogueState, finishPositive, finishBound,
    finishExact, epilogueCutpoint⟩ :=
      semantics.finish sourceRva before resultState resultIndex resultSlot
        resultCutpoint trace
  obtain ⟨after, epilogueExact, returnState⟩ :=
    semantics.epilogue sourceRva before epilogueState epilogueSlot
      epilogueCutpoint
  refine ⟨7 + loopFuel + finishFuel + 3, after, by omega, ?_, returnState⟩
  rw [runProgramLookupNativeFuel_add, runProgramLookupNativeFuel_add,
    runProgramLookupNativeFuel_add, prologueExact, loopExact, finishExact,
    epilogueExact]

/-- The already-proved exact ProgramLookup semantics refine the NativeWorld
kernel dispatch for every relational world.  ProgramLookup is event-free, so
the arbitrary world environment is not assumed or evaluated. -/
theorem programLookupNativeLocalSemantics_programLookupRefinesUsingNativeWorld
    {program : CompiledKernelProgram} {function : KernelFunction}
    {candidate : ExactNativeWorldProgram} {abi : KernelABIRelation}
    {records : List StageA.Relational.Interpreter.ProgramRecord}
    {transferCount : Nat}
    {certificate : ProgramLookupNativeTemplateCertificate program candidate.pe
      candidate.imports function}
    (semantics : ProgramLookupNativeLocalSemantics candidate.pe
      candidate.imports programLookupIdentityNativeEnvironment records transferCount
      certificate)
    (concreteABI : ProgramLookupNativeConcreteABI candidate.pe abi records
      transferCount certificate)
    (entryRvaExact : program.functionEntry? .programLookup =
      some certificate.template.parameters.entryRva)
    (world : RelationalWorld) :
    KernelOperationRefinesUsing program abi
      (NativeWorldKernelDispatches candidate world) .programLookup := by
  intro request before operationMatches requestRelated response transition
  cases request with
  | programLookup requestRecords sourceRva =>
      obtain ⟨recordsExact, ⟨entry⟩⟩ :=
        concreteABI.requestEntry requestRecords sourceRva before requestRelated
      subst requestRecords
      cases transition
      obtain ⟨resultIndex, trace⟩ := reflectedProgramLookupTrace_exists records
        sourceRva 0 transferCount (by
          rw [entry.loaded.transferCountExact]
          omega)
      obtain ⟨fuel, after, fuelPositive, nativeExact, returnState⟩ :=
        programLookupNativeLocalSemantics_constructsNativeFuel semantics entry
          trace
      have worldExact :=
        runProgramLookupNativeFuel_returned_empty_to_nativeWorld candidate
          programLookupIdentityNativeEnvironment world fuel
          certificate.template.parameters.entryRva 0 before [] 0 after
          nativeExact
      refine ⟨certificate.template.parameters.entryRva, after, [],
        entryRvaExact, ?_,
        concreteABI.responseExit sourceRva before after requestRelated returnState,
        ?_⟩
      · exact ⟨world, [.returned world after.registers.eax],
          fuel, fuelPositive, worldExact⟩
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

/-- Erase only the producer metadata from a checked standalone path.  The
exact path, successor world, response state, and event list are unchanged. -/
theorem producerSelectedStandalone_to_nativeWorldKernelDispatches
    {candidate : ExactNativeWorldProgram}
    {context : NativeWorldFrameContext}
    {world : RelationalWorld}
    {entryRva : Nat} {before after : MachineState}
    {events : List NativeExternalEvent}
    (eventIndexZero : context.eventIndex = 0)
    (dispatch :
      ProducerSelectedStandaloneNativeWorldDispatches candidate context world
        entryRva before after events) :
    NativeWorldKernelDispatches candidate world entryRva before after events := by
  obtain ⟨selected⟩ := dispatch
  have pathExact :
      runRelatedSteps candidate.transitionSystem selected.selected.fuel
          (.running entryRva 0 before [] 0 [] world) =
        (.returned after events selected.afterWorld, selected.observations) := by
    simpa [reindexExactNativeWorldProgram, reindexNativeWorldEnvironment,
      eventIndexZero] using selected.selected.path.exact
  exact ⟨selected.afterWorld, selected.observations,
    selected.selected.fuel, selected.selected.path.positive,
    pathExact⟩

/-- A frame-parametric certificate also provides a top-level NativeWorld
operation theorem.  This projection is world-parametric: the same `world`
appears in the dispatch premise and exact candidate path. -/
theorem KernelOperationFrameParametricCertificate.refinesStandalone
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {operation : KernelOperation}
    (certificate : KernelOperationFrameParametricCertificate program abi
      candidate operation)
    (context : NativeWorldFrameContext) (eventIndexZero : context.eventIndex = 0)
    (world : RelationalWorld)
    (entry : KernelOperationFrameEntryAuthority abi operation context) :
    KernelOperationRefinesUsing program abi
      (NativeWorldKernelDispatches candidate world) operation := by
  intro request before operationMatches requestRelated response transition
  obtain ⟨entryRva, after, events, entryExact, dispatch, responseRelated,
      memoryFrame⟩ :=
    certificate.producer context world request before operationMatches
      requestRelated
      (entry request before operationMatches requestRelated)
      response transition
  exact ⟨entryRva, after, events, entryExact,
    producerSelectedStandalone_to_nativeWorldKernelDispatches eventIndexZero
      dispatch,
    responseRelated, memoryFrame⟩

/-- Exact nested dispatch selected by the generic frame-context theorem.
The caller frame, continuation, event prefix, and relational world are all
indices of the result rather than fields that generated code can overwrite. -/
theorem KernelOperationFrameParametricCertificate.refinesSubroutine
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {operation : KernelOperation}
    (certificate : KernelOperationFrameParametricCertificate program abi
      candidate operation)
    (world : RelationalWorld) (continuationRva : Nat)
    (returnAddress : Word)
    (entry : ∀ request before,
      request.operation = operation ->
      abi.requestRelated request before ->
      Memory.read32 before.memory before.registers.esp = returnAddress) :
    KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world continuationRva
        returnAddress) operation := by
  let context : NativeWorldFrameContext := {
    frame := { continuationRva, returnAddress }
    tail := []
    eventIndex := 0
    eventPrefix := []
  }
  have entryAuthority :
      KernelOperationFrameEntryAuthority abi operation context := by
    intro request before operationMatches requestRelated
    exact entry request before operationMatches requestRelated
  have refined := certificate.refinesInContext context world entryAuthority
  intro request before operationMatches requestRelated response transition
  obtain ⟨entryRva, after, events, entryExact, dispatch, responseRelated,
      memoryFrame⟩ :=
    refined request before operationMatches requestRelated response transition
  obtain ⟨result⟩ := dispatch
  refine ⟨entryRva, after, events, entryExact, ⟨{
    afterWorld := result.afterWorld
    observations := result.observations
    path := ?_
  }⟩, responseRelated, memoryFrame⟩
  simpa [FrameParametricNativeWorldResult, context,
    NativeWorldFrameContext.embed] using result.path

#print axioms producerSelectedStandalone_to_nativeWorldKernelDispatches
#print axioms stepNativeExecution_recordedEvents_length_mono
#print axioms runProgramLookupNativeFuel_recordedEvents_length_mono
#print axioms runProgramLookupNativeFuel_returned_empty_to_nativeWorld
#print axioms programLookupNativeLocalSemantics_traceToLoopExitFuel
#print axioms programLookupNativeLocalSemantics_constructsNativeFuel
#print axioms programLookupNativeLocalSemantics_programLookupRefinesUsingNativeWorld
#print axioms KernelOperationFrameParametricCertificate.refinesStandalone
#print axioms KernelOperationFrameParametricCertificate.refinesSubroutine

end StageA.Relational.InterpreterKernelProgramLookupNativeWorldBridge
