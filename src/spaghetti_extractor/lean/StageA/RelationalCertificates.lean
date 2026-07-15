import StageA.RelationalCallbacks
import StageA.RelationalExecution

namespace StageA.Relational

open StageA.Formal

inductive WorldRelationalObservable where
  | external (world : RelationalWorld) (imported : ExternalTarget)
      (arguments : List Word)
  | returned (world : RelationalWorld)
  | callback (world : RelationalWorld) (targetId : Nat)
  | fault
deriving Repr, DecidableEq

def worldRelationalObservationsRelated (context : StaticProofContext) :
    Option WorldRelationalObservable -> Option WorldRelationalObservable -> Prop
  | none, none => True
  | some (.external originalWorld originalImport originalArguments),
      some (.external candidateWorld candidateImport candidateArguments) =>
      originalWorld = candidateWorld ∧ originalImport = candidateImport ∧
        externalCallArgumentsRelated context originalWorld
          originalArguments candidateArguments = true
  | some (.returned originalWorld), some (.returned candidateWorld) =>
      originalWorld = candidateWorld
  | some (.callback originalWorld originalTarget),
      some (.callback candidateWorld candidateTarget) =>
      originalWorld = candidateWorld ∧ originalTarget = candidateTarget
  | some .fault, some .fault => True
  | _, _ => False

structure DecodedWorldProgram where
  candidate : Bool
  context : StaticProofContext
  regions : List RegionRelation
  externalCallSites : List ExternalCallSiteContract
  environment : WorldExternalEnvironment
  protocolEnvironment : WorldExternalProtocolEnvironment := {
    action := fun request => .returned { state := request.state, world := request.world }
  }

def decodedWorldRegionBehavior (program : DecodedWorldProgram)
    (targetId : Nat) (state : MachineState) : Option RelationalBehavior := do
  let region <- regionById program.regions targetId
  let span := if program.candidate then region.candidate else region.original
  let pe := if program.candidate then
    program.context.candidatePe
  else
    program.context.originalPe
  let imports := if program.candidate then
    program.context.candidateImports
  else
    program.context.originalImports
  let behavior <- regionBehaviorWithMachineCallContracts pe imports
    program.context.machineImportCallContracts span
  evalBehavior program.candidate region.targets state behavior

def machineImportArgumentsAtState (contract : MachineImportCallContract)
    (state : MachineState) : List Word :=
  contract.stackArgumentOffsets.map fun offset =>
    Memory.read32 state.memory
      (state.registers.esp + BitVec.ofNat 32 offset)

def machineImportThunkArgumentsAtState? (contract : MachineImportCallContract)
    (state : MachineState) : Option (List Word) :=
  if contract.stackArgumentOffsets.all fun offset => offset + 8 <= 2^32 then
    some (contract.stackArgumentOffsets.map fun offset =>
      Memory.read32 state.memory
        (state.registers.esp + BitVec.ofNat 32 (offset + 4)))
  else
    none

def resolveWorldImportCall (candidate : Bool) (context : StaticProofContext)
    (world : RelationalWorld) (target : Word) (state : MachineState) :
    Option (Prod ExternalTarget (List Word)) := do
  let binding <- world.importAddresses.find? fun binding =>
    (if candidate then binding.candidateAddress else binding.originalAddress) == target
  let contract <- context.machineImportCallContracts.find? fun contract =>
    contract.imported == binding.imported
  let arguments <- machineImportThunkArgumentsAtState? contract state
  pure (binding.imported, arguments)

def resolveExternalCallSite (context : StaticProofContext)
    (sites : List ExternalCallSiteContract) (sourceTargetId : Nat)
    (continuationTargetId : Nat) (imported : ExternalTarget) : Option Nat := do
  let site <- sites.find? fun site =>
    site.sourceTargetId == sourceTargetId &&
      site.continuationTargetId == continuationTargetId &&
      match machineImportCallContractById? context site.machineContractId with
      | none => false
      | some contract => contract.imported == imported
  pure site.id

def resolvedExternalCallContract? (context : StaticProofContext)
    (sites : List ExternalCallSiteContract) (siteId : Nat) :
    Option MachineImportCallContract := do
  let site <- sites.find? fun site => site.id == siteId
  machineImportCallContractById? context site.machineContractId

structure WorldExternalSuspension where
  sourceTargetId : Nat
  siteId : Nat
  imported : ExternalTarget
  arguments : List Word
  continuationTargetId : Nat
  calls : List Nat
  eventIndex : Nat
  phaseIndex : Nat
  event : WorldExternalEvent
  state : MachineState
  world : RelationalWorld

structure WorldExternalCallbackRuntime where
  suspension : WorldExternalSuspension
  entry : WorldExternalCallbackAction

inductive WorldExecution where
  | running (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
  | returned (state : MachineState) (world : RelationalWorld)
  | terminated (world : RelationalWorld)
  | awaitingExternal (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime)
  | callbackRunning (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
  | fault

def WorldExternalSuspension.request
    (suspension : WorldExternalSuspension) : WorldExternalProtocolRequest := {
  eventIndex := suspension.eventIndex
  phaseIndex := suspension.phaseIndex
  event := suspension.event
  state := suspension.state
  world := suspension.world
}

def resumeWorldExecution (callbacks : List WorldExternalCallbackRuntime)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld) : WorldExecution :=
  match callbacks with
  | [] => .running targetId state calls eventIndex world
  | _ => .callbackRunning targetId state calls eventIndex world callbacks

def suspendWorldExternalProtocol (sourceTargetId siteId : Nat)
    (imported : ExternalTarget) (arguments : List Word)
    (continuationTargetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime) : WorldExecution :=
  let event : WorldExternalEvent := {
    siteId
    imported
    arguments
    state
    world
  }
  .awaitingExternal {
    sourceTargetId
    siteId
    imported
    arguments
    continuationTargetId
    calls
    eventIndex
    phaseIndex := 0
    event
    state
    world
  } callbacks

def transitionFromWorldOutcome (program : DecodedWorldProgram)
    (sourceTargetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime) :
    PureOutcome -> RelatedTransition WorldExecution WorldRelationalObservable
  | .returned target =>
      match calls with
      | [] =>
          match callbacks with
          | [] =>
              { next := .returned state world, observation := some (.returned world) }
          | callback :: outerCallbacks =>
              if target == callback.entry.returnAddress then
                { next := .awaitingExternal {
                    callback.suspension with
                    phaseIndex := callback.suspension.phaseIndex + 1
                    state
                    world
                  } outerCallbacks,
                  observation := none }
              else
                { next := .fault, observation := some .fault }
      | continuation :: tail =>
          match resolveMappedCodeTarget program.candidate
              (if program.candidate then program.context.candidatePe.imageBase
               else program.context.originalPe.imageBase)
              program.context.codeMap.entries.toList target with
          | some resolved =>
              if resolved == continuation then
                { next := resumeWorldExecution callbacks continuation state tail eventIndex world,
                  observation := none }
              else
                { next := .fault, observation := some .fault }
          | none => { next := .fault, observation := some .fault }
  | .jump target =>
      { next := resumeWorldExecution callbacks target state calls eventIndex world,
        observation := none }
  | .branch condition taken fallthrough =>
      { next := resumeWorldExecution callbacks (if condition then taken else fallthrough)
          state calls eventIndex world,
        observation := none }
  | .call target continuation =>
      { next := resumeWorldExecution callbacks target state (continuation :: calls)
          eventIndex world,
        observation := none }
  | .externalCall imported arguments continuation =>
      match resolveExternalCallSite program.context program.externalCallSites
          sourceTargetId continuation imported with
      | none => { next := .fault, observation := some .fault }
      | some siteId =>
          match resolvedExternalCallContract? program.context program.externalCallSites siteId with
          | none => { next := .fault, observation := some .fault }
          | some contract =>
              match contract.disposition with
              | .terminates =>
                  { next := .terminated world,
                    observation := some (.external world imported arguments) }
              | .protocol =>
                  { next := suspendWorldExternalProtocol sourceTargetId siteId imported
                      arguments continuation state calls eventIndex world callbacks,
                    observation := some (.external world imported arguments) }
              | .returns =>
                  let event : WorldExternalEvent := {
                    siteId
                    imported
                    arguments
                    state
                    world
                  }
                  let result := program.environment.result eventIndex event
                  { next := resumeWorldExecution callbacks continuation result.state calls
                      (eventIndex + 1) result.world,
                    observation := some (.external world imported arguments) }
  | .externalJump imported arguments =>
      match calls with
      | [] => { next := .fault, observation := some .fault }
      | continuation :: tail =>
          match resolveExternalCallSite program.context program.externalCallSites
              sourceTargetId continuation imported with
          | none => { next := .fault, observation := some .fault }
          | some siteId =>
              match resolvedExternalCallContract? program.context program.externalCallSites siteId with
              | none => { next := .fault, observation := some .fault }
              | some contract =>
                  match contract.disposition with
                  | .terminates =>
                      { next := .terminated world,
                        observation := some (.external world imported arguments) }
                  | .protocol =>
                      { next := suspendWorldExternalProtocol sourceTargetId siteId imported
                          arguments continuation (normalizeImportReturnSlotState state) tail
                          eventIndex world callbacks,
                        observation := some (.external world imported arguments) }
                  | .returns =>
                      let event : WorldExternalEvent := {
                        siteId
                        imported
                        arguments
                        state := normalizeImportReturnSlotState state
                        world
                      }
                      let result := program.environment.result eventIndex event
                      { next := resumeWorldExecution callbacks continuation result.state tail
                            (eventIndex + 1) result.world,
                        observation := some (.external world imported arguments) }
  | .bulkCopy destination source count direction continuation =>
      let memory := Memory.bulkCopyDwords state.memory destination source direction
        count.toNat
      { next := resumeWorldExecution callbacks continuation { state with memory } calls
          eventIndex world,
        observation := none }
  | .indirectCall target continuation =>
      match resolveMappedCodeTarget program.candidate
          (if program.candidate then program.context.candidatePe.imageBase
           else program.context.originalPe.imageBase)
          program.context.codeMap.entries.toList target with
      | some resolved =>
          { next := resumeWorldExecution callbacks resolved state (continuation :: calls)
              eventIndex world,
            observation := none }
      | none =>
          match resolveWorldImportCall program.candidate program.context world target state with
          | none => { next := .fault, observation := some .fault }
          | some (imported, arguments) =>
              match resolveExternalCallSite program.context program.externalCallSites
                  sourceTargetId continuation imported with
              | none => { next := .fault, observation := some .fault }
              | some siteId =>
                  match resolvedExternalCallContract? program.context
                      program.externalCallSites siteId with
                  | none => { next := .fault, observation := some .fault }
                  | some contract =>
                      match contract.disposition with
                      | .terminates =>
                          { next := .terminated world,
                            observation := some (.external world imported arguments) }
                      | .protocol =>
                          { next := suspendWorldExternalProtocol sourceTargetId siteId imported
                              arguments continuation (normalizeImportReturnSlotState state)
                              calls eventIndex world callbacks,
                            observation := some (.external world imported arguments) }
                      | .returns =>
                          let event : WorldExternalEvent := {
                            siteId
                            imported
                            arguments
                            state := normalizeImportReturnSlotState state
                            world
                          }
                          let result := program.environment.result eventIndex event
                          { next := resumeWorldExecution callbacks continuation result.state calls
                                (eventIndex + 1) result.world,
                            observation := some (.external world imported arguments) }
  | .indirectJump target =>
      match resolveMappedCodeTarget program.candidate
          (if program.candidate then program.context.candidatePe.imageBase
           else program.context.originalPe.imageBase)
          program.context.codeMap.entries.toList target with
      | some resolved =>
          { next := resumeWorldExecution callbacks resolved state calls eventIndex world,
            observation := none }
      | none =>
          match calls with
          | [] => { next := .fault, observation := some .fault }
          | continuation :: tail =>
              match resolveWorldImportCall program.candidate program.context world target state with
              | none => { next := .fault, observation := some .fault }
              | some (imported, arguments) =>
                  match resolveExternalCallSite program.context program.externalCallSites
                      sourceTargetId continuation imported with
                  | none => { next := .fault, observation := some .fault }
                  | some siteId =>
                      match resolvedExternalCallContract? program.context
                          program.externalCallSites siteId with
                      | none => { next := .fault, observation := some .fault }
                      | some contract =>
                          match contract.disposition with
                          | .terminates =>
                              { next := .terminated world,
                                observation := some (.external world imported arguments) }
                          | .protocol =>
                              { next := suspendWorldExternalProtocol sourceTargetId siteId imported
                                  arguments continuation (normalizeImportReturnSlotState state)
                                  tail eventIndex world callbacks,
                                observation := some (.external world imported arguments) }
                          | .returns =>
                              let event : WorldExternalEvent := {
                                siteId
                                imported
                                arguments
                                state := normalizeImportReturnSlotState state
                                world
                              }
                              let result := program.environment.result eventIndex event
                              { next := resumeWorldExecution callbacks continuation result.state tail
                                    (eventIndex + 1) result.world,
                                observation := some (.external world imported arguments) }
  | .checkedContinue valid continuation =>
      if valid then
        { next := resumeWorldExecution callbacks continuation state calls eventIndex world,
          observation := none }
      else
        { next := .fault, observation := some .fault }
  | .atomicCompareExchange address expected replacement continuation =>
      let memory := Memory.atomicCompareExchange state.memory address expected replacement
      { next := resumeWorldExecution callbacks continuation { state with memory } calls
          eventIndex world,
        observation := none }

def stepWorldExternalSuspension (program : DecodedWorldProgram)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime) :
    RelatedTransition WorldExecution WorldRelationalObservable :=
  match program.protocolEnvironment.action suspension.request with
  | .returned result =>
      { next := resumeWorldExecution callbacks suspension.continuationTargetId
          result.state suspension.calls (suspension.eventIndex + 1) result.world,
        observation := none }
  | .callback entry =>
      { next := .callbackRunning entry.targetId entry.state [] suspension.eventIndex
          entry.world ({ suspension, entry } :: callbacks),
        observation := some (.callback entry.world entry.targetId) }
  | .terminated world =>
      { next := .terminated world, observation := none }

def stepWorldExecution (program : DecodedWorldProgram) :
    WorldExecution -> RelatedTransition WorldExecution WorldRelationalObservable
  | .running targetId state calls eventIndex world =>
      match decodedWorldRegionBehavior program targetId state with
      | none => { next := .fault, observation := some .fault }
      | some behavior =>
          transitionFromWorldOutcome program targetId
            (behavior.nextMachineState state) calls eventIndex world [] behavior.outcome
  | .returned state world =>
      { next := .returned state world, observation := none }
  | .terminated world => { next := .terminated world, observation := none }
  | .awaitingExternal suspension callbacks =>
      stepWorldExternalSuspension program suspension callbacks
  | .callbackRunning targetId state calls eventIndex world callbacks =>
      match decodedWorldRegionBehavior program targetId state with
      | none => { next := .fault, observation := some .fault }
      | some behavior =>
          transitionFromWorldOutcome program targetId
            (behavior.nextMachineState state) calls eventIndex world callbacks
            behavior.outcome
  | .fault => { next := .fault, observation := none }

def DecodedWorldProgram.transitionSystem (program : DecodedWorldProgram) :
    RelatedTransitionSystem WorldExecution WorldRelationalObservable := {
  step := stepWorldExecution program
}

def RelationalRuntimeCallStackHolds (context : StaticProofContext)
    (original candidate : MachineState) :
    List RelationalRuntimeCallFrame -> List Nat -> List ReturnSlotOffsetPair -> Prop
  | [], [], [] => True
  | frame :: frames, continuation :: continuations, offsets :: remainingOffsets =>
      frame.continuationTargetId = continuation ∧
        frame.toRelationalCallFrame.valid context = true ∧
        frame.toRelationalCallFrame.resolves context = true ∧
        frame.memoryHolds original.memory candidate.memory ∧
        offsets.holds frame original.registers candidate.registers ∧
        RelationalRuntimeCallStackHolds context original candidate frames
          continuations remainingOffsets
  | _, _, _ => False

theorem RelationalRuntimeCallStackHolds.toMixed
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (offsets : List ReturnSlotOffsetPair)
    (holds : RelationalRuntimeCallStackHolds context original candidate
      frames continuations offsets) :
    RelationalMixedRuntimeStackHolds context world original candidate
      (frames.map RelationalRuntimeFrame.internal)
      (continuations.map RelationalRuntimeContinuation.internal) offsets := by
  induction frames generalizing continuations offsets with
  | nil =>
      cases continuations <;> cases offsets <;>
        simp_all [RelationalRuntimeCallStackHolds, RelationalMixedRuntimeStackHolds]
  | cons frame frames ih =>
      cases continuations with
      | nil => simp [RelationalRuntimeCallStackHolds] at holds
      | cons continuation continuations =>
          cases offsets with
          | nil => simp [RelationalRuntimeCallStackHolds] at holds
          | cons offset offsets =>
              simp only [RelationalRuntimeCallStackHolds] at holds
              simp only [List.map_cons, RelationalMixedRuntimeStackHolds,
                RelationalRuntimeFrame.continuationMatches,
                RelationalRuntimeFrame.valid, RelationalRuntimeFrame.memoryHolds,
                ReturnSlotOffsetPair.holdsRuntimeFrame_internal, Bool.and_eq_true]
              exact ⟨by simpa using holds.1, ⟨holds.2.1, holds.2.2.1⟩,
                holds.2.2.2.1, holds.2.2.2.2.1,
                ih continuations offsets holds.2.2.2.2.2⟩

theorem RelationalRuntimeCallStackHolds.afterInternal
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List ReturnSlotFrameTransferClaim)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (originalState candidateState : MachineState)
    (checked : claims.all fun claim =>
      claim.checked originalBehavior candidateBehavior)
    (holds : RelationalRuntimeCallStackHolds context originalState candidateState
      frames continuations (claims.map (fun claim => claim.transfer.source))) :
    RelationalRuntimeCallStackHolds context
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState)
      frames continuations (claims.map (fun claim => claim.transfer.target)) := by
  induction claims generalizing frames continuations with
  | nil =>
      cases frames <;> cases continuations <;>
        simp_all [RelationalRuntimeCallStackHolds]
  | cons claim claims ih =>
      cases frames with
      | nil =>
          cases continuations <;> simp_all [RelationalRuntimeCallStackHolds]
      | cons frame frames =>
          cases continuations with
          | nil => simp_all [RelationalRuntimeCallStackHolds]
          | cons continuation continuations =>
              simp only [List.all_cons, Bool.and_eq_true] at checked
              simp only [List.map_cons, RelationalRuntimeCallStackHolds] at holds ⊢
              have transferred := returnSlotFrameTransferHolds_of_checked
                originalBehavior candidateBehavior claim frame originalState
                candidateState checked.1 holds.2.2.2.2.1 holds.2.2.2.1
              exact ⟨holds.1, holds.2.1, holds.2.2.1, transferred.2,
                transferred.1,
                ih frames continuations checked.2 holds.2.2.2.2.2⟩

theorem RelationalRuntimeCallStackHolds.afterExternalCall
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (contract : MachineImportCallContract)
    (claims : List ExternalReturnSlotTransferClaim)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (originalState candidateState originalResult candidateResult : MachineState)
    (checked : claims.all fun claim =>
      claim.checked originalBehavior candidateBehavior contract)
    (holds : RelationalRuntimeCallStackHolds context originalState candidateState
      frames continuations (claims.map (fun claim => claim.source)))
    (originalAbi : machineCallAbiResultHolds contract
      ((originalBehavior.eval originalState).nextMachineState originalState)
      originalResult = true)
    (candidateAbi : machineCallAbiResultHolds contract
      ((candidateBehavior.eval candidateState).nextMachineState candidateState)
      candidateResult = true)
    (framesPreserved : ∀ frame : RelationalRuntimeCallFrame,
      frame.memoryHolds
          ((originalBehavior.eval originalState).nextMachineState originalState).memory
          ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory →
        frame.memoryHolds originalResult.memory candidateResult.memory) :
    RelationalRuntimeCallStackHolds context originalResult candidateResult
      frames continuations (claims.map (fun claim => claim.resultRule.target)) := by
  induction claims generalizing frames continuations with
  | nil =>
      cases frames <;> cases continuations <;>
        simp_all [RelationalRuntimeCallStackHolds]
  | cons claim claims ih =>
      cases frames with
      | nil =>
          cases continuations <;> simp_all [RelationalRuntimeCallStackHolds]
      | cons frame frames =>
          cases continuations with
          | nil => simp_all [RelationalRuntimeCallStackHolds]
          | cons continuation continuations =>
              simp only [List.all_cons, Bool.and_eq_true] at checked
              simp only [List.map_cons, RelationalRuntimeCallStackHolds] at holds ⊢
              have transferred := externalReturnSlotTransferHolds_of_checked
                originalBehavior candidateBehavior contract claim frame originalState
                candidateState originalResult candidateResult checked.1
                holds.2.2.2.2.1 holds.2.2.2.1 originalAbi candidateAbi
                (framesPreserved frame)
              exact ⟨holds.1, holds.2.1, holds.2.2.1, transferred.2,
                transferred.1,
                ih frames continuations checked.2 holds.2.2.2.2.2⟩

theorem RelationalRuntimeCallStackHolds.afterExternalJump
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (contract : MachineImportCallContract)
    (claims : List ExternalJumpReturnSlotTransferClaim)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (originalState candidateState originalResult candidateResult : MachineState)
    (checked : claims.all fun claim =>
      claim.checked originalBehavior candidateBehavior contract)
    (holds : RelationalRuntimeCallStackHolds context originalState candidateState
      frames continuations (claims.map (fun claim => claim.source)))
    (originalAbi : machineCallAbiResultHolds contract
      (normalizeImportReturnSlotState
        ((originalBehavior.eval originalState).nextMachineState originalState))
      originalResult = true)
    (candidateAbi : machineCallAbiResultHolds contract
      (normalizeImportReturnSlotState
        ((candidateBehavior.eval candidateState).nextMachineState candidateState))
      candidateResult = true)
    (framesPreserved : ∀ frame : RelationalRuntimeCallFrame,
      frame.memoryHolds
          (normalizeImportReturnSlotState
            ((originalBehavior.eval originalState).nextMachineState originalState)).memory
          (normalizeImportReturnSlotState
            ((candidateBehavior.eval candidateState).nextMachineState candidateState)).memory →
        frame.memoryHolds originalResult.memory candidateResult.memory) :
    RelationalRuntimeCallStackHolds context originalResult candidateResult
      frames continuations (claims.map (fun claim => claim.resultRule.target)) := by
  induction claims generalizing frames continuations with
  | nil =>
      cases frames <;> cases continuations <;>
        simp_all [RelationalRuntimeCallStackHolds]
  | cons claim claims ih =>
      cases frames with
      | nil =>
          cases continuations <;> simp_all [RelationalRuntimeCallStackHolds]
      | cons frame frames =>
          cases continuations with
          | nil => simp_all [RelationalRuntimeCallStackHolds]
          | cons continuation continuations =>
              simp only [List.all_cons, Bool.and_eq_true] at checked
              simp only [List.map_cons, RelationalRuntimeCallStackHolds] at holds ⊢
              have transferred := externalJumpReturnSlotTransferHolds_of_checked
                originalBehavior candidateBehavior contract claim frame originalState
                candidateState originalResult candidateResult checked.1
                holds.2.2.2.2.1 holds.2.2.2.1 originalAbi candidateAbi
                (framesPreserved frame)
              exact ⟨holds.1, holds.2.1, holds.2.2.1, transferred.2,
                transferred.1,
                ih frames continuations checked.2 holds.2.2.2.2.2⟩

def RelationalRuntimeCallTargetsReachable (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence) : List Nat -> Prop
  | [] => True
  | continuation :: continuations =>
      (exists nodeId node,
        graph.getNode? nodeId = some node ∧
          node.targetId = continuation ∧ reachability.contains nodeId = true) ∧
        RelationalRuntimeCallTargetsReachable graph reachability continuations

theorem RelationalRuntimeCallStackHolds.of_memory_eq
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (offsets : List ReturnSlotOffsetPair)
    (holds : RelationalRuntimeCallStackHolds context beforeOriginal beforeCandidate
      frames continuations offsets)
    (originalMemory : afterOriginal.memory = beforeOriginal.memory)
    (candidateMemory : afterCandidate.memory = beforeCandidate.memory)
    (originalRegisters : ∀ register,
      afterOriginal.registers.get register = beforeOriginal.registers.get register)
    (candidateRegisters : ∀ register,
      afterCandidate.registers.get register = beforeCandidate.registers.get register) :
    RelationalRuntimeCallStackHolds context afterOriginal afterCandidate
      frames continuations offsets := by
  induction frames generalizing continuations offsets with
  | nil =>
      cases continuations <;> cases offsets <;>
        simp_all [RelationalRuntimeCallStackHolds]
  | cons frame frames ih =>
      cases continuations with
      | nil => simp [RelationalRuntimeCallStackHolds] at holds
      | cons continuation continuations =>
          cases offsets with
          | nil => simp [RelationalRuntimeCallStackHolds] at holds
          | cons offset offsets =>
              simp only [RelationalRuntimeCallStackHolds] at holds ⊢
              exact ⟨holds.1, holds.2.1,
                holds.2.2.1,
                by simpa [RelationalRuntimeCallFrame.memoryHolds, originalMemory,
                  candidateMemory] using holds.2.2.2.1,
                by
                  unfold ReturnSlotOffsetPair.holds
                  rw [originalRegisters offset.originalRegister,
                    candidateRegisters offset.candidateRegister]
                  exact holds.2.2.2.2.1,
                ih continuations offsets holds.2.2.2.2.2⟩

structure ProductControlState where
  nodeId : Nat
  calls : List Nat
  frameOffsets : List ReturnSlotOffsetPair
deriving Repr, DecidableEq

structure ProductControlProfile where
  states : List ProductControlState
deriving Repr, DecidableEq

def ProductControlProfile.lookup (profile : ProductControlProfile)
    (nodeId : Nat) (calls : List Nat) : Option (List ReturnSlotOffsetPair) := do
  let state <- profile.states.find? fun state =>
    state.nodeId == nodeId && state.calls == calls
  pure state.frameOffsets

def ProductControlProfile.Allows (profile : ProductControlProfile)
    (nodeId : Nat) (calls : List Nat) (frameOffsets : List ReturnSlotOffsetPair) : Bool :=
  profile.states.contains { nodeId, calls, frameOffsets }

structure ProductInvariantTable where
  nodeInvariants : Array StateInvariant
  terminalInvariant : StateInvariant
deriving Repr, DecidableEq

def ProductInvariantTable.Valid (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable) : Prop :=
  invariants.nodeInvariants.size = graph.nodes.size

def RegionMatchesProductNode (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (nodeId : Nat) : Prop :=
  match graph.getNode? nodeId with
  | none => False
  | some node =>
      match context.codeMap.get? node.targetId, regionById regions node.targetId with
      | some target, some region =>
          region.id = node.targetId ∧ target.regionIndex = node.id ∧
            region.original.start = target.originalRva ∧
            region.candidate.start = target.candidateRva
      | _, _ => False

def RegionsMatchProductGraph (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation) : Prop :=
  forall nodeId, nodeId < graph.nodes.size ->
    RegionMatchesProductNode context graph regions nodeId

def WorldExecutionsRelated (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile) :
    WorldExecution -> WorldExecution -> Prop
  | .running originalTarget originalState originalCalls originalEventIndex originalWorld,
      .running candidateTarget candidateState candidateCalls candidateEventIndex
        candidateWorld =>
      originalTarget = candidateTarget ∧ originalCalls = candidateCalls ∧
        originalEventIndex = candidateEventIndex ∧ originalWorld = candidateWorld ∧
        exists nodeId node invariant frames frameOffsets,
          graph.getNode? nodeId = some node ∧ node.targetId = originalTarget ∧
            reachability.contains nodeId = true ∧
            invariants.nodeInvariants[nodeId]? = some invariant ∧
            control.Allows nodeId originalCalls frameOffsets = true ∧
            RelationalRuntimeCallStackHolds context originalState candidateState
              frames originalCalls frameOffsets ∧
            RelationalRuntimeCallTargetsReachable graph reachability originalCalls ∧
            StateRel context originalWorld invariant originalState candidateState
  | .returned originalState originalWorld,
      .returned candidateState candidateWorld =>
      originalWorld = candidateWorld ∧
        StateRel context originalWorld invariants.terminalInvariant
          originalState candidateState
  | .terminated originalWorld, .terminated candidateWorld =>
      originalWorld = candidateWorld
  | .fault, .fault => True
  | _, _ => False

def RelationalInternalExecutionEdgeRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable) (edgeId : Nat) : Prop :=
  match graph.getEdge? edgeId with
  | none => False
  | some edge =>
      match graph.getNode? edge.sourceNodeId, graph.getNode? edge.targetNodeId,
          regionById regions edge.sourceTargetId,
          invariants.nodeInvariants[edge.sourceNodeId]?,
          invariants.nodeInvariants[edge.targetNodeId]? with
      | some sourceNode, some targetNode, some region,
          some sourceInvariant, some targetInvariant =>
          exists segment,
            sourceNode.targetId = edge.sourceTargetId ∧
              targetNode.targetId = edge.targetTargetId ∧
              segment.originalSpan = region.original ∧
              segment.candidateSpan = region.candidate ∧
              segment.localCodeTargetIds = region.targets.map (fun target => target.id) ∧
              segment.localValueTargetIds = region.values.map (fun target => target.id) ∧
              RelationalProductEdgeRefinement context graph edgeId segment
                sourceInvariant targetInvariant
      | _, _, _, _, _ => False

def RelationalExternalExecutionEdgeRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable) (edgeId : Nat) : Prop :=
  match graph.getEdge? edgeId with
  | none => False
  | some edge =>
      match graph.getNode? edge.sourceNodeId, graph.getNode? edge.targetNodeId,
          regionById regions edge.sourceTargetId,
          invariants.nodeInvariants[edge.sourceNodeId]?,
          invariants.nodeInvariants[edge.targetNodeId]? with
      | some sourceNode, some targetNode, some region,
          some sourceInvariant, some targetInvariant =>
          exists site segment,
            sourceNode.targetId = edge.sourceTargetId ∧
              targetNode.targetId = edge.targetTargetId ∧
              site.sourceTargetId = edge.sourceTargetId ∧
              site.continuationTargetId = edge.targetTargetId ∧
              site.targetInvariant = targetInvariant ∧
              segment.originalSpan = region.original ∧
              segment.candidateSpan = region.candidate ∧
              segment.localCodeTargetIds = region.targets.map (fun target => target.id) ∧
              segment.localValueTargetIds = region.values.map (fun target => target.id) ∧
              site.staticValid context = true ∧
              RelationalExternalProductEdgeRefinement context graph edgeId site segment
                sourceInvariant
      | _, _, _, _, _ => False

def RelationalProductExecutionEdgeRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable) (edgeId : Nat) : Prop :=
  RelationalInternalExecutionEdgeRefined context graph regions invariants edgeId ∨
    RelationalExternalExecutionEdgeRefined context graph regions invariants edgeId

def ReachableProductExecutionEdgesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence) : Prop :=
  forall edgeId, edgeId < graph.edges.size ->
    match graph.getEdge? edgeId with
    | none => False
    | some edge =>
        reachability.contains edge.sourceNodeId = true ->
        edge.infeasible = false ->
        RelationalProductExecutionEdgeRefined context graph regions invariants edgeId

def AllListedRegionsMatchProductGraph (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation) :
    List Nat -> Prop
  | [] => True
  | nodeId :: nodeIds =>
      RegionMatchesProductNode context graph regions nodeId ∧
        AllListedRegionsMatchProductGraph context graph regions nodeIds

theorem allListedRegionsMatchProductGraph_append (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (left right : List Nat)
    (leftMatches : AllListedRegionsMatchProductGraph context graph regions left)
    (rightMatches : AllListedRegionsMatchProductGraph context graph regions right) :
    AllListedRegionsMatchProductGraph context graph regions (left ++ right) := by
  induction left with
  | nil => exact rightMatches
  | cons nodeId nodeIds ih =>
      exact ⟨leftMatches.1, ih leftMatches.2⟩

theorem allListedRegionsMatchProductGraph_of_mem (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (nodeIds : List Nat)
    (listed : AllListedRegionsMatchProductGraph context graph regions nodeIds) :
    forall nodeId, nodeId ∈ nodeIds ->
      RegionMatchesProductNode context graph regions nodeId := by
  induction nodeIds with
  | nil => simp
  | cons head tail ih =>
      intro nodeId member
      rcases listed with ⟨headMatches, tailMatches⟩
      simp only [List.mem_cons] at member
      cases member with
      | inl same => simpa [same] using headMatches
      | inr inTail => exact ih tailMatches nodeId inTail

theorem regionsMatchProductGraph_of_listed_range (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (listed : AllListedRegionsMatchProductGraph context graph regions
      (List.range graph.nodes.size)) :
    RegionsMatchProductGraph context graph regions := by
  intro nodeId before
  exact allListedRegionsMatchProductGraph_of_mem context graph regions
    (List.range graph.nodes.size) listed nodeId (List.mem_range.mpr before)

def AllListedProductExecutionEdgesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable) : List Nat -> Prop
  | [] => True
  | edgeId :: edgeIds =>
      RelationalProductExecutionEdgeRefined context graph regions invariants edgeId ∧
        AllListedProductExecutionEdgesRefined context graph regions invariants edgeIds

theorem allListedProductExecutionEdgesRefined_append
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (regions : List RegionRelation) (invariants : ProductInvariantTable)
    (left right : List Nat)
    (leftRefined : AllListedProductExecutionEdgesRefined context graph regions
      invariants left)
    (rightRefined : AllListedProductExecutionEdgesRefined context graph regions
      invariants right) :
    AllListedProductExecutionEdgesRefined context graph regions invariants
      (left ++ right) := by
  induction left with
  | nil => exact rightRefined
  | cons edgeId edgeIds ih =>
      exact ⟨leftRefined.1, ih leftRefined.2⟩

theorem allListedProductExecutionEdgesRefined_of_mem
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (regions : List RegionRelation) (invariants : ProductInvariantTable)
    (edgeIds : List Nat)
    (listed : AllListedProductExecutionEdgesRefined context graph regions
      invariants edgeIds) :
    forall edgeId, edgeId ∈ edgeIds ->
      RelationalProductExecutionEdgeRefined context graph regions invariants edgeId := by
  induction edgeIds with
  | nil => simp
  | cons head tail ih =>
      intro edgeId member
      rcases listed with ⟨headRefined, tailRefined⟩
      simp only [List.mem_cons] at member
      cases member with
      | inl same => simpa [same] using headRefined
      | inr inTail => exact ih tailRefined edgeId inTail

theorem reachableProductExecutionEdgesRefined_of_complete_evidence
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (regions : List RegionRelation) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (evidence : RelationalProductLocalEvidence)
    (complete : evidence.complete graph reachability = true)
    (listed : AllListedProductExecutionEdgesRefined context graph regions invariants
      evidence.refinedEdgeIds) :
    ReachableProductExecutionEdgesRefined context graph regions invariants
      reachability := by
  simp only [RelationalProductLocalEvidence.complete, Bool.and_eq_true,
    beq_iff_eq] at complete
  intro edgeId before
  cases edgeResult : graph.getEdge? edgeId with
  | none =>
      simp [RelationalProductGraph.getEdge?, before] at edgeResult
  | some edge =>
      simp only [edgeResult]
      intro sourceReachable feasible
      apply allListedProductExecutionEdgesRefined_of_mem context graph regions
        invariants evidence.refinedEdgeIds listed edgeId
      rw [complete.2]
      simp [RelationalProductReachabilityEvidence.reachableFeasibleEdgeIds,
        RelationalProductReachabilityEvidence.edgeReachableAndFeasible,
        before, edgeResult, sourceReachable, feasible]

def ProductStepRefinement (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (original candidate : DecodedWorldProgram) : Prop :=
  forall originalExecution candidateExecution,
    WorldExecutionsRelated context graph invariants reachability control
      originalExecution candidateExecution ->
    worldRelationalObservationsRelated context
        (original.transitionSystem.step originalExecution).observation
        (candidate.transitionSystem.step candidateExecution).observation ∧
      WorldExecutionsRelated context graph invariants reachability control
        (original.transitionSystem.step originalExecution).next
        (candidate.transitionSystem.step candidateExecution).next

def RunningProductNodeStepRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (original candidate : DecodedWorldProgram) (nodeId : Nat) : Prop :=
  match graph.getNode? nodeId, invariants.nodeInvariants[nodeId]? with
  | some node, some invariant =>
      forall frames calls frameOffsets eventIndex world originalState candidateState,
        control.Allows nodeId calls frameOffsets = true ->
        RelationalRuntimeCallStackHolds context originalState candidateState
          frames calls frameOffsets ->
        RelationalRuntimeCallTargetsReachable graph reachability calls ->
        StateRel context world invariant originalState candidateState ->
        worldRelationalObservationsRelated context
            (original.transitionSystem.step
              (.running node.targetId originalState calls eventIndex world)).observation
            (candidate.transitionSystem.step
              (.running node.targetId candidateState calls eventIndex world)).observation ∧
          WorldExecutionsRelated context graph invariants reachability control
            (original.transitionSystem.step
              (.running node.targetId originalState calls eventIndex world)).next
            (candidate.transitionSystem.step
              (.running node.targetId candidateState calls eventIndex world)).next
  | _, _ => False

def ReachableRunningProductNodesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (original candidate : DecodedWorldProgram) : Prop :=
  forall nodeId, nodeId < graph.nodes.size ->
    reachability.contains nodeId = true ->
    RunningProductNodeStepRefined context graph invariants reachability control
      original candidate nodeId

def AllListedRunningProductNodesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (original candidate : DecodedWorldProgram) : List Nat -> Prop
  | [] => True
  | nodeId :: nodeIds =>
      RunningProductNodeStepRefined context graph invariants reachability control
          original candidate nodeId ∧
        AllListedRunningProductNodesRefined context graph invariants reachability control
          original candidate nodeIds

theorem allListedRunningProductNodesRefined_append
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (original candidate : DecodedWorldProgram) (left right : List Nat)
    (leftRefined : AllListedRunningProductNodesRefined context graph invariants
      reachability control original candidate left)
    (rightRefined : AllListedRunningProductNodesRefined context graph invariants
      reachability control original candidate right) :
    AllListedRunningProductNodesRefined context graph invariants reachability control
      original candidate (left ++ right) := by
  induction left with
  | nil => exact rightRefined
  | cons nodeId nodeIds ih =>
      exact ⟨leftRefined.1, ih leftRefined.2⟩

theorem allListedRunningProductNodesRefined_of_mem
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (original candidate : DecodedWorldProgram) (nodeIds : List Nat)
    (listed : AllListedRunningProductNodesRefined context graph invariants
      reachability control original candidate nodeIds) :
    forall nodeId, nodeId ∈ nodeIds ->
      RunningProductNodeStepRefined context graph invariants reachability control
        original candidate nodeId := by
  induction nodeIds with
  | nil => simp
  | cons head tail ih =>
      intro nodeId member
      rcases listed with ⟨headRefined, tailRefined⟩
      simp only [List.mem_cons] at member
      cases member with
      | inl same => simpa [same] using headRefined
      | inr inTail => exact ih tailRefined nodeId inTail

theorem reachableRunningProductNodesRefined_of_complete_evidence
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (original candidate : DecodedWorldProgram)
    (evidence : RelationalProductLocalEvidence)
    (complete : evidence.complete graph reachability = true)
    (listed : AllListedRunningProductNodesRefined context graph invariants
      reachability control original candidate evidence.decodedNodeIds) :
    ReachableRunningProductNodesRefined context graph invariants reachability control
      original candidate := by
  simp only [RelationalProductLocalEvidence.complete, Bool.and_eq_true,
    beq_iff_eq] at complete
  intro nodeId before reachable
  apply allListedRunningProductNodesRefined_of_mem context graph invariants
    reachability control original candidate evidence.decodedNodeIds listed nodeId
  rw [complete.1]
  simp [RelationalProductReachabilityEvidence.reachableNodeIds, before, reachable]

theorem productStepRefinement_of_reachable_nodes (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (original candidate : DecodedWorldProgram)
    (running : ReachableRunningProductNodesRefined context graph invariants
      reachability control original candidate) :
    ProductStepRefinement context graph invariants reachability control original candidate := by
  intro originalExecution candidateExecution related
  cases originalExecution <;> cases candidateExecution
  case running.running originalTarget originalState originalCalls originalEventIndex
      originalWorld candidateTarget candidateState candidateCalls candidateEventIndex
      candidateWorld =>
      rcases related with
        ⟨targetEqual, callsEqual, eventEqual, worldEqual,
          nodeId, node, invariant, frames, frameOffsets, nodeFound, targetFound,
          reachable, invariantFound, controlAllowed, stackHolds, stackTargetsReachable,
          statesRelated⟩
      subst candidateTarget
      subst candidateCalls
      subst candidateEventIndex
      subst candidateWorld
      have nodeBefore : nodeId < graph.nodes.size := by
        exact Array.getElem?_eq_some_iff.mp nodeFound |>.1
      have nodeStep := running nodeId nodeBefore reachable
      unfold RunningProductNodeStepRefined at nodeStep
      rw [nodeFound, invariantFound] at nodeStep
      subst originalTarget
      exact nodeStep frames originalCalls frameOffsets originalEventIndex originalWorld
        originalState candidateState controlAllowed stackHolds stackTargetsReachable
        statesRelated
  case returned.returned originalState originalWorld candidateState candidateWorld =>
      rcases related with ⟨worldEqual, statesRelated⟩
      subst candidateWorld
      exact ⟨True.intro, ⟨rfl, statesRelated⟩⟩
  case terminated.terminated originalWorld candidateWorld =>
      subst candidateWorld
      exact ⟨True.intro, rfl⟩
  case fault.fault => exact ⟨True.intro, True.intro⟩
  all_goals simp [WorldExecutionsRelated] at related

structure PE32ConsoleLaunchV1 where
  rootNodeId : Nat
  rootTargetId : Nat
  rootInvariant : StateInvariant
deriving Repr, DecidableEq

def PE32ConsoleLaunchV1.Valid (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable) (launch : PE32ConsoleLaunchV1) : Prop :=
  exists node,
    graph.getNode? launch.rootNodeId = some node ∧
      node.targetId = launch.rootTargetId ∧ node.root = true ∧
      graph.rootNodeIds.contains launch.rootNodeId = true ∧
      invariants.nodeInvariants[launch.rootNodeId]? = some launch.rootInvariant

def PE32ConsoleLaunchV1.StatesRelated (context : StaticProofContext)
    (launch : PE32ConsoleLaunchV1) (world : RelationalWorld)
    (original candidate : MachineState) : Prop :=
  StateRel context world launch.rootInvariant original candidate

def PE32ProgramsObservationallyEquivalent (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (launch : PE32ConsoleLaunchV1)
    (original candidate : DecodedWorldProgram) : Prop :=
  exists executionRelation : WorldExecution -> WorldExecution -> Prop,
    (forall world originalState candidateState,
      launch.StatesRelated context world originalState candidateState ->
      executionRelation
        (.running launch.rootTargetId originalState [] 0 world)
        (.running launch.rootTargetId candidateState [] 0 world)) ∧
    RelationalWeakBisimulation original.transitionSystem candidate.transitionSystem
      executionRelation (worldRelationalObservationsRelated context)

structure WholeProgramCertificate (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV1)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment) where
  staticContextValid : context.StructurallyValid
  productGraphValid : graph.IndexedValid context
  regionsUseCanonicalContext : RegionsUseStaticContext context regions
  regionsMatchProductGraph : RegionsMatchProductGraph context graph regions
  invariantTableValid : invariants.Valid graph
  reachabilityClosed : reachability.SoundlyClosed context graph
  decodedControlComplete :
    ReachableProductNodesDecodedControlComplete context graph reachability
  reachableEdgesRefined : ReachableProductEdgesLocallyRefined context graph reachability
  reachableExecutionEdgesRefined :
    ReachableProductExecutionEdgesRefined context graph regions invariants reachability
  environmentsRefined : ExternalEnvironmentRefines context externalCallSites
    originalEnvironment candidateEnvironment
  launchValid : launch.Valid graph invariants
  launchControlAllowed : control.Allows launch.rootNodeId [] [] = true
  runningProductNodesRefined : ReachableRunningProductNodesRefined context graph
    invariants reachability control
    {
      candidate := false
      context
      regions
      externalCallSites
      environment := originalEnvironment
    }
    {
      candidate := true
      context
      regions
      externalCallSites
      environment := candidateEnvironment
    }

theorem pe32ProgramsEquivalent (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV1)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (certificate : WholeProgramCertificate context graph regions invariants reachability control
      externalCallSites launch originalEnvironment candidateEnvironment) :
    PE32ProgramsObservationallyEquivalent context graph invariants reachability control launch
      {
        candidate := false
        context
        regions
        externalCallSites
        environment := originalEnvironment
      }
      {
        candidate := true
        context
        regions
        externalCallSites
        environment := candidateEnvironment
      } := by
  let original : DecodedWorldProgram := {
    candidate := false
    context
    regions
    externalCallSites
    environment := originalEnvironment
  }
  let candidate : DecodedWorldProgram := {
    candidate := true
    context
    regions
    externalCallSites
    environment := candidateEnvironment
  }
  refine ⟨WorldExecutionsRelated context graph invariants reachability control, ?_, ?_⟩
  . intro world originalState candidateState related
    rcases certificate.launchValid with
      ⟨node, nodeFound, targetFound, rootFound, rootListed, invariantFound⟩
    refine ⟨rfl, rfl, rfl, rfl, launch.rootNodeId, node,
      launch.rootInvariant, [], [], nodeFound, targetFound, ?_, invariantFound,
      certificate.launchControlAllowed, ?_, ?_, related⟩
    . have allRoots := certificate.reachabilityClosed.2.1.2.1
      unfold RelationalProductReachabilityEvidence.rootsIncluded at allRoots
      exact List.all_eq_true.mp allRoots launch.rootNodeId
        (List.contains_iff_mem.mp rootListed)
    . simp [RelationalRuntimeCallStackHolds]
    . simp [RelationalRuntimeCallTargetsReachable]
  . exact productStepRefinement_of_reachable_nodes context graph invariants reachability
      control original candidate certificate.runningProductNodesRefined

def PE32ProgramsTraceRelated (context : StaticProofContext)
    (original candidate : DecodedWorldProgram)
    (executionRelation : WorldExecution -> WorldExecution -> Prop) :
    Nat -> WorldExecution -> WorldExecution -> Prop :=
  RelatedTrace original.transitionSystem candidate.transitionSystem executionRelation
    (worldRelationalObservationsRelated context)

theorem pe32ProgramsEquivalent_trace (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (launch : PE32ConsoleLaunchV1)
    (original candidate : DecodedWorldProgram)
    (equivalent : PE32ProgramsObservationallyEquivalent context graph invariants
      reachability control launch original candidate) :
    forall fuel world originalState candidateState,
      launch.StatesRelated context world originalState candidateState ->
      exists executionRelation,
        PE32ProgramsTraceRelated context original candidate executionRelation fuel
          (.running launch.rootTargetId originalState [] 0 world)
          (.running launch.rootTargetId candidateState [] 0 world) := by
  rcases equivalent with ⟨executionRelation, initial, bisimulation⟩
  intro fuel world originalState candidateState related
  refine ⟨executionRelation, ?_⟩
  exact relationalWeakBisimulation_trace original.transitionSystem
    candidate.transitionSystem executionRelation
    (worldRelationalObservationsRelated context) bisimulation fuel _ _
    (initial world originalState candidateState related)

end StageA.Relational
