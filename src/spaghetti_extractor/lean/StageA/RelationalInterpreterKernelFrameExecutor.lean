import StageA.RelationalInterpreterKernelOperationFrameParametric

namespace StageA.Relational.InterpreterKernelFrameExecutor

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationFrameParametric
open StageA.Relational.InterpreterNativeWorld

/-!
Executor-level evidence for frame-parametric native operations.

The generic path lifting theorem intentionally leaves contextual one-step
refinement abstract.  This module derives that refinement from the exact native
transition function.  External effects are not assumed pure:

* imported calls have an explicit shifted-action equality, memory footprint,
  and world-update contract;
* resolved callable calls have a separate shifted-result equality, footprint,
  and world-update contract; and
* the caller return slot is outside every admitted external footprint.

Exact equality is needed for contextual execution of the same candidate.
Footprint and world-update facts are retained independently because equality
alone would not prove that an external result preserves the caller frame.
-/

def wordByteRange (base : Word) (bytes : Nat) : CandidateFootprint :=
  fun address =>
    exists offset, offset < bytes &&
      address = base + BitVec.ofNat 32 offset

def FrameFootprintDisjoint
    (returnSlot : Word) (footprint : CandidateFootprint) : Prop :=
  forall address, wordByteRange returnSlot 4 address -> Not (footprint address)

/-- Imported-call contract at one caller context.  The action equality relates
the local standalone index to the real caller index.  The remaining fields
check memory and world effects independently. -/
structure ImportedFrameEnvironmentContract
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext) where
  footprint : NativeExternalEvent -> CandidateFootprint
  worldUpdate :
    NativeExternalEvent -> RelationalWorld -> RelationalWorld -> Prop
  shiftedAction : forall localIndex event world,
    candidate.environment.action (context.eventIndex + localIndex) event world =
      candidate.environment.action localIndex event world
  returnedFrame : forall localIndex event world result,
    candidate.environment.action localIndex event world = .returned result ->
      MemoryAgreesOutside (footprint event) result.state.memory event.state.memory
  returnedWorld : forall localIndex event world result,
    candidate.environment.action localIndex event world = .returned result ->
      worldUpdate event world result.world
  terminatedWorld : forall localIndex event world successor,
    candidate.environment.action localIndex event world = .terminated successor ->
      worldUpdate event world successor

/-- Resolved-callable contract.  This is deliberately separate from imported
calls because the event identity and environment are different. -/
structure CallableFrameEnvironmentContract
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext) where
  footprint : ResolvedExternalEvent -> CandidateFootprint
  worldUpdate :
    ResolvedExternalEvent -> RelationalWorld -> RelationalWorld -> Prop
  shiftedResult : forall config,
    candidate.callableExternal = some config ->
      forall localIndex event,
        config.environment.result (context.eventIndex + localIndex) event =
          config.environment.result localIndex event
  resultFrame : forall config
      (_enabled : candidate.callableExternal = some config)
      localIndex event,
    MemoryAgreesOutside (footprint event)
      (config.environment.result localIndex event).state.memory
      event.state.memory
  resultWorld : forall config
      (_enabled : candidate.callableExternal = some config)
      localIndex event,
    worldUpdate event event.world
      (config.environment.result localIndex event).world

structure NativeWorldFrameExecutorEnvironmentContract
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext) where
  imported : ImportedFrameEnvironmentContract candidate context
  callable : CallableFrameEnvironmentContract candidate context

def emptyCandidateFootprint : CandidateFootprint := fun _ => false

theorem FrameFootprintDisjoint.empty (returnSlot : Word) :
    FrameFootprintDisjoint returnSlot emptyCandidateFootprint := by
  intro address inReturnSlot
  simp [emptyCandidateFootprint]

/-- A candidate with no resolved-callable executor has a vacuous callable
environment contract.  The disabled configuration is checked from the exact
program value; it is not inferred from an external status field. -/
def CallableFrameEnvironmentContract.ofDisabled
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (disabled : candidate.callableExternal = none) :
    CallableFrameEnvironmentContract candidate context := {
  footprint := fun _ => emptyCandidateFootprint
  worldUpdate := fun _ _ _ => True
  shiftedResult := by
    intro config enabled
    rw [disabled] at enabled
    contradiction
  resultFrame := by
    intro config enabled
    rw [disabled] at enabled
    contradiction
  resultWorld := by
    intro config enabled
    rw [disabled] at enabled
    contradiction
}

def NativeWorldFrameExecutorEnvironmentContract.ofDisabled
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (disabled : candidate.callableExternal = none)
    (imported : ImportedFrameEnvironmentContract candidate context) :
    NativeWorldFrameExecutorEnvironmentContract candidate context := {
  imported
  callable :=
    CallableFrameEnvironmentContract.ofDisabled candidate context disabled
}

theorem NativeWorldFrameCallableTailCompatibleAt.ofDisabled
    (candidate : ExactNativeWorldProgram)
    (execution : NativeWorldExecution)
    (disabled : candidate.callableExternal = none) :
    NativeWorldFrameCallableTailCompatibleAt candidate execution := by
  cases execution with
  | returned state events world => trivial
  | terminated events world => trivial
  | fault cause => trivial
  | blocked reason => trivial
  | running rva undefinedSlot state calls localIndex localEvents world =>
      cases calls with
      | cons frame tail => trivial
      | nil =>
          simp only [NativeWorldFrameCallableTailCompatibleAt]
          generalize stepExact :
            stepKernelPE32Instruction candidate.pe candidate.imports
              (.running rva undefinedSlot state) = stepped
          cases stepped with
          | running nextRva nextSlot nextState => trivial
          | fault => trivial
          | stopped outcome nextState =>
              cases outcome <;> simp [disabled]

def NativeWorldFrameExecutorEnvironmentContract.stable
    (contract : NativeWorldFrameExecutorEnvironmentContract candidate context) :
    NativeWorldFrameEnvironmentStable candidate context := {
  importedAction := contract.imported.shiftedAction
  callableResult := contract.callable.shiftedResult
}

theorem MemoryAgreesOutside.read32_of_frameFootprintDisjoint
    (frame : MemoryAgreesOutside footprint afterMemory beforeMemory)
    (returnSlot : Word)
    (disjoint : FrameFootprintDisjoint returnSlot footprint) :
    Memory.read32 afterMemory returnSlot =
      Memory.read32 beforeMemory returnSlot := by
  have byte0 : wordByteRange returnSlot 4 returnSlot := by
    apply Exists.intro 0
    simp
  have byte1 :
      wordByteRange returnSlot 4 (returnSlot + BitVec.ofNat 32 1) := by
    apply Exists.intro 1
    simp
  have byte2 :
      wordByteRange returnSlot 4 (returnSlot + BitVec.ofNat 32 2) := by
    apply Exists.intro 2
    simp
  have byte3 :
      wordByteRange returnSlot 4 (returnSlot + BitVec.ofNat 32 3) := by
    apply Exists.intro 3
    simp
  unfold Memory.read32
  rw [frame returnSlot (disjoint returnSlot byte0)]
  rw [frame (returnSlot + BitVec.ofNat 32 1)
    (disjoint _ byte1)]
  rw [frame (returnSlot + BitVec.ofNat 32 2)
    (disjoint _ byte2)]
  rw [frame (returnSlot + BitVec.ofNat 32 3)
    (disjoint _ byte3)]

/-- Imported results preserve the concrete caller return word and satisfy the
declared successor-world relation. -/
theorem ImportedFrameEnvironmentContract.returnedFrameAndWorld
    (contract : ImportedFrameEnvironmentContract candidate context)
    (returnSlot : Word)
    (disjoint : FrameFootprintDisjoint returnSlot (contract.footprint event))
    (actionExact :
      candidate.environment.action localIndex event world = .returned result) :
    Memory.read32 result.state.memory returnSlot =
        Memory.read32 event.state.memory returnSlot /\
      contract.worldUpdate event world result.world := by
  exact ⟨MemoryAgreesOutside.read32_of_frameFootprintDisjoint
    (contract.returnedFrame localIndex event world result actionExact)
    returnSlot disjoint,
    contract.returnedWorld localIndex event world result actionExact⟩

/-- Resolved-callable results use the same checked frame rule, but retain their
separate event and environment types. -/
theorem CallableFrameEnvironmentContract.resultFrameAndWorld
    (contract : CallableFrameEnvironmentContract candidate context)
    (enabled : candidate.callableExternal = some config)
    (returnSlot : Word)
    (disjoint : FrameFootprintDisjoint returnSlot (contract.footprint event)) :
    Memory.read32 (config.environment.result localIndex event).state.memory
        returnSlot =
        Memory.read32 event.state.memory returnSlot /\
      contract.worldUpdate event event.world
        (config.environment.result localIndex event).world := by
  exact ⟨MemoryAgreesOutside.read32_of_frameFootprintDisjoint
    (contract.resultFrame config enabled localIndex event) returnSlot disjoint,
    contract.resultWorld config enabled localIndex event⟩

theorem applyNativeWorldExternalAction_frame
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (continuation : Nat) (calls : List NativeCallFrame)
    (localIndex : Nat) (localEvents : List NativeExternalEvent)
    (event : NativeExternalEvent) (world : RelationalWorld)
    (stable : candidate.environment.action
        (context.eventIndex + localIndex) event world =
      candidate.environment.action localIndex event world) :
    (applyNativeWorldExternalAction continuation
      (calls ++ context.frame :: context.tail)
      (context.eventIndex + localIndex) (context.eventPrefix ++ localEvents)
      event world
      (candidate.environment.action (context.eventIndex + localIndex) event
        world)).next =
      context.embed
        (applyNativeWorldExternalAction continuation calls localIndex localEvents
          event world
          (candidate.environment.action localIndex event world)).next := by
  rw [stable]
  cases actionExact :
      candidate.environment.action localIndex event world <;>
    simp [applyNativeWorldExternalAction,
      NativeWorldFrameContext.embed, blockedNativeWorldTransition,
      List.append_assoc, Nat.add_assoc]

theorem applyNativeWorldExternalTailAction_frame
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (calls : List NativeCallFrame)
    (localIndex : Nat) (localEvents : List NativeExternalEvent)
    (event : NativeExternalEvent) (world : RelationalWorld)
    (indexExact : localIndex = localEvents.length)
    (stable : candidate.environment.action
        (context.eventIndex + localIndex) event world =
      candidate.environment.action localIndex event world) :
    (applyNativeWorldExternalTailAction
      (calls ++ context.frame :: context.tail)
      (context.eventIndex + localIndex) (context.eventPrefix ++ localEvents)
      event world
      (candidate.environment.action (context.eventIndex + localIndex) event
        world)).next =
      context.embed
        (applyNativeWorldExternalTailAction calls localIndex localEvents event
          world
          (candidate.environment.action localIndex event world)).next := by
  rw [stable]
  cases calls <;>
    cases actionExact :
      candidate.environment.action localIndex event world <;>
    simp [applyNativeWorldExternalTailAction,
      NativeWorldFrameContext.embed, blockedNativeWorldTransition,
      indexExact, List.append_assoc, Nat.add_assoc]

theorem applyNativeWorldResolvedCallableCall_frame
    (context : NativeWorldFrameContext)
    (config : NativeCallableExternalConfig)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (target : Word) (continuation : Nat) (state : MachineState)
    (calls : List NativeCallFrame)
    (localIndex : Nat) (localEvents : List NativeExternalEvent)
    (world : RelationalWorld)
    (stable : forall event,
      config.environment.result (context.eventIndex + localIndex) event =
        config.environment.result localIndex event) :
    (applyNativeWorldResolvedCallableCall config capability abi target
      continuation state (calls ++ context.frame :: context.tail)
      (context.eventIndex + localIndex) (context.eventPrefix ++ localEvents)
      world).next =
      context.embed
        (applyNativeWorldResolvedCallableCall config capability abi target
          continuation state calls localIndex localEvents world).next := by
  simp only [applyNativeWorldResolvedCallableCall]
  rw [stable]
  simp [NativeWorldFrameContext.embed, Nat.add_assoc]

theorem applyNativeWorldResolvedCallableTail_frame
    (context : NativeWorldFrameContext)
    (config : NativeCallableExternalConfig)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (target : Word) (state : MachineState)
    (frame : NativeCallFrame) (tail : List NativeCallFrame)
    (localIndex : Nat) (localEvents : List NativeExternalEvent)
    (world : RelationalWorld)
    (stable : forall event,
      config.environment.result (context.eventIndex + localIndex) event =
        config.environment.result localIndex event) :
    (applyNativeWorldResolvedCallableTail config capability abi target state
      ((frame :: tail) ++ context.frame :: context.tail)
      (context.eventIndex + localIndex) (context.eventPrefix ++ localEvents)
      world).next =
      context.embed
        (applyNativeWorldResolvedCallableTail config capability abi target state
          (frame :: tail) localIndex localEvents world).next := by
  simp only [applyNativeWorldResolvedCallableTail, List.cons_append]
  rw [stable]
  simp [NativeWorldFrameContext.embed, Nat.add_assoc]

/-- One exact native step respects the frame context.  Environment equality is
explicit; return compatibility is the only frame-sensitive branch of a direct
machine return. -/
theorem nativeWorldFrameStepRefinesAt_of_running
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (execution : NativeWorldExecution)
    (running : nativeWorldExecutionIsRunning execution)
    (eventIndexExact : nativeWorldExecutionEventIndexExact execution)
    (environment : NativeWorldFrameEnvironmentStable candidate context)
    (returnCompatible :
      NativeWorldFrameReturnCompatibleAt candidate context execution)
    (callableTailCompatible :
      NativeWorldFrameCallableTailCompatibleAt candidate execution) :
    NativeWorldFrameStepRefinesAt candidate context execution := by
  cases execution with
  | returned state events world => contradiction
  | terminated events world => contradiction
  | fault cause => contradiction
  | blocked reason => contradiction
  | running rva undefinedSlot state calls localIndex localEvents world =>
      have localIndexExact : localIndex = localEvents.length := by
        simpa [nativeWorldExecutionEventIndexExact] using eventIndexExact
      simp only [NativeWorldFrameStepRefinesAt,
        ExactNativeWorldProgram.transitionSystem,
        NativeWorldFrameContext.embed,
        stepPE32NativeWorldExecution]
      generalize stepExact :
        stepKernelPE32Instruction candidate.pe candidate.imports
          (.running rva undefinedSlot state) = stepped
      cases stepped with
      | running nextRva nextSlot nextState => rfl
      | fault => rfl
      | stopped outcome nextState =>
          cases outcome with
          | returned target =>
              cases calls with
              | nil =>
                  simp only [transitionFromNativeWorldOutcome,
                    List.nil_append]
                  have targetExact : target = context.frame.returnAddress := by
                    simpa [NativeWorldFrameReturnCompatibleAt, stepExact] using
                      returnCompatible
                  simp [targetExact, NativeWorldFrameContext.embed,
                    localIndexExact, List.append_assoc, Nat.add_assoc]
              | cons frame tail =>
                  simp only [transitionFromNativeWorldOutcome,
                    List.cons_append]
                  by_cases targetExact : target = frame.returnAddress
                  · simp [targetExact, NativeWorldFrameContext.embed]
                  · simp [targetExact, NativeWorldFrameContext.embed,
                      blockedNativeWorldTransition]
          | jump target => rfl
          | branch condition taken fallthrough => rfl
          | call target continuation returnAddress => rfl
          | externalCall imported arguments continuation =>
              exact applyNativeWorldExternalAction_frame candidate context
                continuation calls localIndex localEvents
                { imported, arguments, state := nextState } world
                (environment.importedAction localIndex
                  { imported, arguments, state := nextState } world)
          | externalJump imported arguments =>
              exact applyNativeWorldExternalTailAction_frame candidate context
                calls localIndex localEvents
                { imported, arguments, state := nextState } world localIndexExact
                (environment.importedAction localIndex
                  { imported, arguments, state := nextState } world)
          | bulkCopy destination source count direction continuation => rfl
          | checkedContinue valid continuation =>
              cases valid <;> rfl
          | atomicCompareExchange address expected replacement continuation =>
              rfl
          | indirectCall target continuation returnAddress =>
              simp only [transitionFromNativeWorldOutcome]
              split <;> rename_i allowed
              · rfl
              · cases callableExact : candidate.callableExternal with
                | none =>
                    cases targetExact :
                        exactNativeIndirectTargetRva? candidate.pe target <;>
                      simp [callableExact, targetExact,
                        NativeWorldFrameContext.embed,
                        blockedNativeWorldTransition]
                | some config =>
                    simp only [callableExact]
                    cases resolutionExact :
                        resolveNativeCallableIndirect candidate.pe config world
                          target .call with
                    | internal targetRva => rfl
                    | imported binding =>
                        cases importExact :
                            resolveWorldImportCall true config.context world target
                              nextState with
                        | none => rfl
                        | some result =>
                            exact applyNativeWorldExternalAction_frame candidate
                              context continuation calls localIndex localEvents
                              { imported := nativePEImportForBinding binding
                                arguments := result.2
                                state := nextState } world
                              (environment.importedAction localIndex
                                { imported := nativePEImportForBinding binding
                                  arguments := result.2
                                  state := nextState } world)
                    | callable capability abi resource =>
                        apply applyNativeWorldResolvedCallableCall_frame context
                          config capability abi target continuation nextState
                          calls localIndex localEvents world
                        intro event
                        exact environment.callableResult config callableExact
                          localIndex event
                    | invalidWorld => rfl
                    | unmapped => rfl
                    | invalidCallable => rfl
                    | ambiguous => rfl
          | indirectJump target =>
              simp only [transitionFromNativeWorldOutcome]
              split <;> rename_i allowed
              · rfl
              · cases callableExact : candidate.callableExternal with
                | none =>
                    cases targetExact :
                        exactNativeIndirectTargetRva? candidate.pe target <;>
                      simp [callableExact, targetExact,
                        NativeWorldFrameContext.embed,
                        blockedNativeWorldTransition]
                | some config =>
                    simp only [callableExact]
                    cases resolutionExact :
                        resolveNativeCallableIndirect candidate.pe config world
                          target .jump with
                    | internal targetRva => rfl
                    | imported binding =>
                        cases importExact :
                            resolveWorldImportCall true config.context world target
                              nextState with
                        | none => rfl
                        | some result =>
                            exact applyNativeWorldExternalTailAction_frame
                              candidate context calls localIndex localEvents
                              { imported := nativePEImportForBinding binding
                                arguments := result.2
                                state := nextState } world localIndexExact
                              (environment.importedAction localIndex
                                { imported := nativePEImportForBinding binding
                                  arguments := result.2
                                  state := nextState } world)
                    | callable capability abi resource =>
                        cases calls with
                        | nil =>
                            exfalso
                            simpa [NativeWorldFrameCallableTailCompatibleAt,
                              stepExact, allowed, callableExact,
                              resolutionExact] using callableTailCompatible
                        | cons frame tail =>
                            apply applyNativeWorldResolvedCallableTail_frame
                              context config capability abi target nextState
                              frame tail localIndex localEvents world
                            intro event
                            exact environment.callableResult config callableExact
                              localIndex event
                    | invalidWorld => rfl
                    | unmapped => rfl
                    | invalidCallable => rfl
                    | ambiguous => rfl

/-- Exact trace data emitted by the candidate executor.  `prefixRva` prevents
terminal stuttering without trusting a status field.  Return compatibility is
derived from the concrete stack slot and exact return decoder result. -/
structure NativeWorldFrameExecutorPathContract
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    {fuel : Nat}
    (path : StandaloneNativeWorldPath candidate before after observations fuel)
    where
  environment :
    NativeWorldFrameExecutorEnvironmentContract candidate context
  returnSlot : Word
  importedDisjoint : forall event,
    FrameFootprintDisjoint returnSlot (environment.imported.footprint event)
  callableDisjoint : forall event,
    FrameFootprintDisjoint returnSlot (environment.callable.footprint event)
  prefixRva : forall consumed, consumed < fuel ->
    exists rva,
      (runRelatedSteps candidate.transitionSystem consumed before).1.rva? =
        some rva
  eventIndexExact : forall consumed, consumed < fuel ->
    nativeWorldExecutionEventIndexExact
      (runRelatedSteps candidate.transitionSystem consumed before).1
  callableTailCompatible : forall consumed, consumed < fuel ->
    NativeWorldFrameCallableTailCompatibleAt candidate
      (runRelatedSteps candidate.transitionSystem consumed before).1
  emptyFrameStackSlot : forall consumed (beforeEnd : consumed < fuel)
      rva undefinedSlot state localIndex localEvents world,
    (runRelatedSteps candidate.transitionSystem consumed before).1 =
        .running rva undefinedSlot state [] localIndex localEvents world ->
      state.registers.esp = returnSlot /\
        Memory.read32 state.memory returnSlot = context.frame.returnAddress
  decodedReturnReadsStack : forall consumed (beforeEnd : consumed < fuel)
      rva undefinedSlot state localIndex localEvents world target afterState,
    (runRelatedSteps candidate.transitionSystem consumed before).1 =
        .running rva undefinedSlot state [] localIndex localEvents world ->
      stepKernelPE32Instruction candidate.pe candidate.imports
          (.running rva undefinedSlot state) =
        .stopped (.returned target) afterState ->
      target = Memory.read32 state.memory state.registers.esp

theorem nativeWorldExecutionIsRunning_of_rva
    (execution : NativeWorldExecution) (rva : Nat)
    (exact : execution.rva? = some rva) :
    nativeWorldExecutionIsRunning execution := by
  cases execution <;> simp_all [NativeWorldExecution.rva?,
    nativeWorldExecutionIsRunning]

theorem NativeWorldFrameExecutorPathContract.prefixesRunning
    {candidate : ExactNativeWorldProgram}
    {context : NativeWorldFrameContext}
    {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    {fuel : Nat}
    {path : StandaloneNativeWorldPath candidate before after observations fuel}
    (contract : NativeWorldFrameExecutorPathContract candidate context path)
    (consumed : Nat) (beforeEnd : consumed < fuel) :
    nativeWorldExecutionIsRunning
      (runRelatedSteps candidate.transitionSystem consumed before).1 := by
  obtain ⟨rva, exact⟩ := contract.prefixRva consumed beforeEnd
  exact nativeWorldExecutionIsRunning_of_rva _ rva exact

theorem NativeWorldFrameExecutorPathContract.returnCompatible
    {candidate : ExactNativeWorldProgram}
    {context : NativeWorldFrameContext}
    {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    {fuel : Nat}
    {path : StandaloneNativeWorldPath candidate before after observations fuel}
    (contract : NativeWorldFrameExecutorPathContract candidate context path)
    (consumed : Nat) (beforeEnd : consumed < fuel) :
    NativeWorldFrameReturnCompatibleAt candidate context
      (runRelatedSteps candidate.transitionSystem consumed before).1 := by
  generalize executionExact :
    (runRelatedSteps candidate.transitionSystem consumed before).1 = execution
  have executionRunning := contract.prefixesRunning consumed beforeEnd
  rw [executionExact] at executionRunning
  cases execution with
  | returned state events world => contradiction
  | terminated events world => contradiction
  | fault cause => contradiction
  | blocked reason => contradiction
  | running currentRva undefinedSlot state calls localIndex localEvents world =>
      cases calls with
      | nil =>
          simp only [NativeWorldFrameReturnCompatibleAt]
          generalize stepExact :
            stepKernelPE32Instruction candidate.pe candidate.imports
              (.running currentRva undefinedSlot state) = stepped
          cases stepped with
          | running nextRva nextSlot nextState => trivial
          | fault => trivial
          | stopped outcome afterState =>
              cases outcome with
              | returned target =>
                  obtain ⟨stackExact, returnWordExact⟩ :=
                    contract.emptyFrameStackSlot consumed beforeEnd currentRva
                      undefinedSlot state localIndex localEvents world
                      executionExact
                  have targetExact :=
                    contract.decodedReturnReadsStack consumed beforeEnd currentRva
                      undefinedSlot state localIndex localEvents world target
                      afterState executionExact stepExact
                  simpa [stackExact, returnWordExact] using targetExact
              | _ => trivial
      | cons frame tail =>
          trivial

def NativeWorldFrameExecutorPathContract.toPathRefinement
    {candidate : ExactNativeWorldProgram}
    {context : NativeWorldFrameContext}
    {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    {fuel : Nat}
    {path : StandaloneNativeWorldPath candidate before after observations fuel}
    (contract : NativeWorldFrameExecutorPathContract candidate context path) :
    NativeWorldFramePathRefinement candidate context path := {
  environmentStable := contract.environment.stable
  prefixesRunning := contract.prefixesRunning
  eventIndexExact := contract.eventIndexExact
  returnCompatible := contract.returnCompatible
  callableTailCompatible := contract.callableTailCompatible
  stepRefines := by
    intro consumed beforeEnd running eventIndexExact environment
      returnCompatible callableTailCompatible
    exact nativeWorldFrameStepRefinesAt_of_running candidate context _ running
      eventIndexExact environment returnCompatible callableTailCompatible
}

/-- Executor-qualified operation certificate.  This is the candidate-facing
layer: standalone operation refinement plus exact path contracts are enough
to obtain the frame-parametric operation certificate. -/
structure KernelOperationFrameExecutorCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram)
    (operation : KernelOperation) where
  standalone : forall world,
    KernelOperationRefinesUsing program abi
      (StandaloneNativeWorldDispatches candidate world) operation
  pathContract : forall context world entryRva before after events afterWorld
      observations fuel
      (path : StandaloneNativeWorldPath candidate
        (.running entryRva 0 before [] 0 [] world)
        (.returned after events afterWorld) observations fuel),
    NativeWorldFrameExecutorPathContract candidate context path

def KernelOperationFrameExecutorCertificate.toFrameParametric
    (certificate : KernelOperationFrameExecutorCertificate program abi
      candidate operation) :
    KernelOperationFrameParametricCertificate program abi candidate operation := {
  standalone := certificate.standalone
  contextRefinement := by
    intro context world entryRva before after events afterWorld observations fuel
      path
    exact (certificate.pathContract context world entryRva before after events
      afterWorld observations fuel path).toPathRefinement
}

#print axioms NativeWorldFrameCallableTailCompatibleAt.ofDisabled
#print axioms FrameFootprintDisjoint.empty
#print axioms ImportedFrameEnvironmentContract.returnedFrameAndWorld
#print axioms CallableFrameEnvironmentContract.resultFrameAndWorld
#print axioms nativeWorldFrameStepRefinesAt_of_running
#print axioms NativeWorldFrameExecutorPathContract.prefixesRunning
#print axioms NativeWorldFrameExecutorPathContract.returnCompatible
#print axioms NativeWorldFrameExecutorPathContract.toPathRefinement
#print axioms KernelOperationFrameExecutorCertificate.toFrameParametric

end StageA.Relational.InterpreterKernelFrameExecutor
