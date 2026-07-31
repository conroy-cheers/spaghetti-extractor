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
refinement abstract.  This module derives that refinement for the exact path
selected by the operation producer.  External effects are not assumed pure:

* imported calls run through the caller-indexed standalone environment and
  retain an explicit memory footprint and world-update contract;
* resolved callable calls have a separate shifted-result equality, footprint,
  and world-update contract; and
* the caller return slot is outside every admitted external footprint.

Imported action equality is definitional after reindexing, not a global
invariance premise.  Footprint and world-update facts are retained independently
because reindexing alone would not prove that an external result preserves the
caller frame.
-/

def wordByteRange (base : Word) (bytes : Nat) : CandidateFootprint :=
  fun address =>
    exists offset, offset < bytes &&
      address = base + BitVec.ofNat 32 offset

def FrameFootprintDisjoint
    (returnSlot : Word) (footprint : CandidateFootprint) : Prop :=
  forall address, wordByteRange returnSlot 4 address -> Not (footprint address)

/-- Imported-call contract at one caller context.  Actions are stated at their
real caller indices because the selected standalone program is reindexed from
that source. -/
structure ImportedFrameEnvironmentContract
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext) where
  footprint : NativeExternalEvent -> CandidateFootprint
  worldUpdate :
    NativeExternalEvent -> RelationalWorld -> RelationalWorld -> Prop
  returnedFrame : forall localIndex event world result,
    candidate.environment.action (context.eventIndex + localIndex) event world =
        .returned result ->
      MemoryAgreesOutside (footprint event) result.state.memory event.state.memory
  returnedWorld : forall localIndex event world result,
    candidate.environment.action (context.eventIndex + localIndex) event world =
        .returned result ->
      worldUpdate event world result.world
  terminatedWorld : forall localIndex event world successor,
    candidate.environment.action (context.eventIndex + localIndex) event world =
        .terminated successor ->
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
              cases outcome with
              | indirectJump target =>
                  cases descriptorExact :
                      candidate.indirectTargets.resolve? candidate.pe world rva
                        .jump target with
                  | none =>
                      simp [stepExact, descriptorExact]
                  | some descriptor =>
                      cases descriptor <;>
                        simp [stepExact, descriptorExact, disabled]
              | _ => trivial

def NativeWorldFrameExecutorEnvironmentContract.stable
    (contract : NativeWorldFrameExecutorEnvironmentContract candidate context) :
    NativeWorldFrameEnvironmentStable candidate context := {
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
      candidate.environment.action (context.eventIndex + localIndex) event
        world = .returned result) :
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
    (event : NativeExternalEvent) (world : RelationalWorld) :
    (applyNativeWorldExternalAction continuation
      (calls ++ context.frame :: context.tail)
      (context.eventIndex + localIndex) (context.eventPrefix ++ localEvents)
      event world
      (candidate.environment.action (context.eventIndex + localIndex) event
        world)).next =
      context.embed
        (applyNativeWorldExternalAction continuation calls localIndex localEvents
          event world
          ((reindexExactNativeWorldProgram candidate
            context.eventIndex).environment.action localIndex event world)).next := by
  simp only [reindexExactNativeWorldProgram,
    reindexNativeWorldEnvironment]
  cases actionExact :
      candidate.environment.action (context.eventIndex + localIndex) event
        world <;>
    simp [applyNativeWorldExternalAction,
      NativeWorldFrameContext.embed, blockedNativeWorldTransition,
      List.append_assoc, Nat.add_assoc]

theorem applyNativeWorldExternalTailAction_frame
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (calls : List NativeCallFrame)
    (localIndex : Nat) (localEvents : List NativeExternalEvent)
    (event : NativeExternalEvent) (world : RelationalWorld)
    (indexExact : localIndex = localEvents.length) :
    (applyNativeWorldExternalTailAction
      (calls ++ context.frame :: context.tail)
      (context.eventIndex + localIndex) (context.eventPrefix ++ localEvents)
      event world
      (candidate.environment.action (context.eventIndex + localIndex) event
        world)).next =
      context.embed
        (applyNativeWorldExternalTailAction calls localIndex localEvents event
          world
          ((reindexExactNativeWorldProgram candidate
            context.eventIndex).environment.action localIndex event world)).next := by
  simp only [reindexExactNativeWorldProgram,
    reindexNativeWorldEnvironment]
  cases calls <;>
    cases actionExact :
      candidate.environment.action (context.eventIndex + localIndex) event
        world <;>
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
        reindexExactNativeWorldProgram,
        reindexNativeWorldEnvironment,
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
          | externalJump imported arguments =>
              exact applyNativeWorldExternalTailAction_frame candidate context
                calls localIndex localEvents
                { imported, arguments, state := nextState } world localIndexExact
          | bulkCopy destination source count direction continuation => rfl
          | bulkFill destination value count direction continuation => rfl
          | checkedContinue valid continuation =>
              cases valid <;> rfl
          | atomicCompareExchange address expected replacement continuation =>
              rfl
          | indirectCall target continuation returnAddress =>
              simp only [transitionFromNativeWorldOutcome]
              generalize descriptorExact :
                  candidate.indirectTargets.resolve? candidate.pe world rva
                    .call target = descriptor
              cases descriptor with
              | none => rfl
              | some descriptor =>
                  cases descriptor with
                  | internalRva targetRva =>
                      simp only [List.cons_append]
                  | importBinding bindingId =>
                      cases callableExact : candidate.callableExternal with
                      | none =>
                          simp [callableExact, blockedNativeWorldTransition,
                            NativeWorldFrameContext.embed]
                      | some config =>
                          cases importExact :
                              resolveNativeImportBindingCall? config world
                                bindingId target nextState with
                          | none =>
                              simp [callableExact, importExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | some result =>
                              simp only [callableExact, importExact]
                              simpa only [List.cons_append] using
                                applyNativeWorldExternalAction_frame candidate
                                  context continuation calls localIndex localEvents
                                  { imported :=
                                      nativePEImportForBinding result.1
                                    arguments := result.2
                                    state := nextState } world
                  | callableResource resourceId =>
                      cases callableExact : candidate.callableExternal with
                      | none =>
                          simp [callableExact, blockedNativeWorldTransition,
                            NativeWorldFrameContext.embed]
                      | some config =>
                          cases resolutionExact :
                              resolveNativeCallableResource config world
                                resourceId target .call with
                          | callable capability abi resource =>
                              simp only [callableExact, resolutionExact]
                              simpa only [List.cons_append] using
                                applyNativeWorldResolvedCallableCall_frame context
                                  config capability abi target continuation
                                  nextState calls localIndex localEvents world
                                  (by
                                    intro event
                                    exact environment.callableResult config
                                      callableExact localIndex event)
                          | invalidWorld =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | unmapped =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | invalidCallable =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | ambiguous =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | internal targetId =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | imported binding =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
          | indirectJump target =>
              simp only [transitionFromNativeWorldOutcome]
              generalize descriptorExact :
                  candidate.indirectTargets.resolve? candidate.pe world rva
                    .jump target = descriptor
              cases descriptor with
              | none => rfl
              | some descriptor =>
                  cases descriptor with
                  | internalRva targetRva => rfl
                  | importBinding bindingId =>
                      cases callableExact : candidate.callableExternal with
                      | none =>
                          simp [callableExact, blockedNativeWorldTransition,
                            NativeWorldFrameContext.embed]
                      | some config =>
                          cases importExact :
                              resolveNativeImportBindingCall? config world
                                bindingId target nextState with
                          | none =>
                              simp [callableExact, importExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | some result =>
                              simp only [callableExact, importExact]
                              exact applyNativeWorldExternalTailAction_frame
                                candidate context calls localIndex localEvents
                                { imported := nativePEImportForBinding result.1
                                  arguments := result.2
                                  state := nextState } world localIndexExact
                  | callableResource resourceId =>
                      cases callableExact : candidate.callableExternal with
                      | none =>
                          simp [callableExact, blockedNativeWorldTransition,
                            NativeWorldFrameContext.embed]
                      | some config =>
                          cases resolutionExact :
                              resolveNativeCallableResource config world
                                resourceId target .jump with
                          | callable capability abi resource =>
                              simp only [callableExact, resolutionExact]
                              cases calls with
                              | nil =>
                                  exfalso
                                  simpa [
                                    NativeWorldFrameCallableTailCompatibleAt,
                                    stepExact, descriptorExact, callableExact,
                                    resolutionExact] using callableTailCompatible
                              | cons frame tail =>
                                  apply
                                    applyNativeWorldResolvedCallableTail_frame
                                      context config capability abi target
                                      nextState frame tail localIndex localEvents
                                      world
                                  intro event
                                  exact environment.callableResult config
                                    callableExact localIndex event
                          | invalidWorld =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | unmapped =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | invalidCallable =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | ambiguous =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | internal targetId =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]
                          | imported binding =>
                              simp [callableExact, resolutionExact,
                                blockedNativeWorldTransition,
                                NativeWorldFrameContext.embed]

/-- Executor evidence for the exact canonical path selected by the operation
producer.  Running prefixes, event-index exactness, and return compatibility
belong to `selected`; this contract supplies the remaining environment,
footprint, and callable-tail facts used to derive contextual refinement. -/
structure NativeWorldFrameExecutorPathContract
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    (selected : ProducerSelectedStandaloneNativeWorldPath candidate context
      before after observations) where
  environment :
    NativeWorldFrameExecutorEnvironmentContract candidate context
  returnSlot : Word
  importedDisjoint : forall event,
    FrameFootprintDisjoint returnSlot (environment.imported.footprint event)
  callableDisjoint : forall event,
    FrameFootprintDisjoint returnSlot (environment.callable.footprint event)
  callableTailCompatible : forall consumed, consumed < selected.fuel ->
    NativeWorldFrameCallableTailCompatibleAt candidate
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1

theorem NativeWorldFrameExecutorPathContract.prefixesRunning
    {candidate : ExactNativeWorldProgram}
    {context : NativeWorldFrameContext}
    {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    {selected : ProducerSelectedStandaloneNativeWorldPath candidate context
      before after observations}
    (_contract : NativeWorldFrameExecutorPathContract candidate context selected)
    (consumed : Nat) (beforeEnd : consumed < selected.fuel) :
    nativeWorldExecutionIsRunning
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1 :=
  selected.prefixesRunning consumed beforeEnd

theorem NativeWorldFrameExecutorPathContract.returnCompatible
    {candidate : ExactNativeWorldProgram}
    {context : NativeWorldFrameContext}
    {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    {selected : ProducerSelectedStandaloneNativeWorldPath candidate context
      before after observations}
    (_contract : NativeWorldFrameExecutorPathContract candidate context selected)
    (consumed : Nat) (beforeEnd : consumed < selected.fuel) :
    NativeWorldFrameReturnCompatibleAt candidate context
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1 :=
  selected.returnCompatible consumed beforeEnd

def NativeWorldFrameExecutorPathContract.toPathRefinement
    {candidate : ExactNativeWorldProgram}
    {context : NativeWorldFrameContext}
    {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    {selected : ProducerSelectedStandaloneNativeWorldPath candidate context
      before after observations}
    (contract : NativeWorldFrameExecutorPathContract candidate context selected) :
    NativeWorldFramePathRefinement candidate context selected := {
  environmentStable := contract.environment.stable
  callableTailCompatible := contract.callableTailCompatible
  stepRefines := by
    intro consumed beforeEnd running eventIndexExact environment
      returnCompatible callableTailCompatible
    exact nativeWorldFrameStepRefinesAt_of_running candidate context _ running
      eventIndexExact environment returnCompatible callableTailCompatible
}

/-- Executor-qualified operation certificate.  This is the candidate-facing
layer: a producer-selected operation path plus exact executor contracts are
enough to obtain the frame-parametric operation certificate. -/
structure KernelOperationFrameExecutorCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram)
    (operation : KernelOperation) where
  producer : forall context world,
    KernelOperationRefinesUsingWhen program abi
      (ProducerSelectedStandaloneNativeWorldDispatches candidate context world)
      operation context.entryCompatible
  pathContract : forall context world entryRva before after events afterWorld
      observations
      (selected : ProducerSelectedStandaloneNativeWorldPath candidate context
        (.running entryRva 0 before [] 0 [] world)
        (.returned after events afterWorld) observations),
    NativeWorldFrameExecutorPathContract candidate context selected

def KernelOperationFrameExecutorCertificate.toFrameParametric
    (certificate : KernelOperationFrameExecutorCertificate program abi
      candidate operation) :
    KernelOperationFrameParametricCertificate program abi candidate operation := {
  producer := certificate.producer
  selectedPathRefinement := by
    intro context world entryRva before after events afterWorld observations
      selected
    exact (certificate.pathContract context world entryRva before after events
      afterWorld observations selected).toPathRefinement
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
