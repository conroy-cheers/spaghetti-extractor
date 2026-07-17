import StageA.RelationalCallbacks
import StageA.RelationalExecution
import StageA.RelationalISAQualification
import StageA.RelationalImage
import StageA.RelationalLinkedFrames
import StageA.RelationalPEExecution

namespace StageA.Relational

open StageA.Formal

inductive ModeledFault where
  | checkedContinue
deriving Repr, DecidableEq

/-- A fail-closed proof frontier. These cases mean that Stage A cannot model
the concrete successor; they are not claims that the represented program
faulted. A blocked observation is intentionally unrelated to every observation,
including an identical block on the other side. -/
inductive ExecutionBlock where
  | unmappedEip (eip : Word)
  | missingRegionBehavior (targetId : Nat)
  | invalidCallbackReturn (observed expected : Word)
  | unmappedReturnTarget (target : Word)
  | mismatchedReturnTarget (resolved expected : Nat)
  | missingExternalSite (sourceTargetId continuationTargetId : Nat)
  | missingExternalContract (siteId : Nat)
  | missingRuntimeContinuation
  | unmappedIndirectControl (target : Word)
deriving Repr, DecidableEq

inductive WorldRelationalObservable where
  | external (world : RelationalWorld) (imported : ExternalTarget)
      (arguments : List Word)
  | returned (world : RelationalWorld) (result : Word)
  | callback (world : RelationalWorld) (targetId : Nat)
  | fault (cause : ModeledFault)
  | proofBlocked (reason : ExecutionBlock)
deriving Repr, DecidableEq

def worldRelationalObservationsRelated (context : StaticProofContext) :
    Option WorldRelationalObservable -> Option WorldRelationalObservable -> Prop
  | none, none => True
  | some (.external originalWorld originalImport originalArguments),
      some (.external candidateWorld candidateImport candidateArguments) =>
      originalWorld = candidateWorld ∧ originalImport = candidateImport ∧
        externalCallArgumentsRelated context originalWorld
          originalArguments candidateArguments = true
  | some (.returned originalWorld originalResult),
      some (.returned candidateWorld candidateResult) =>
      originalWorld = candidateWorld ∧ originalResult = candidateResult
  | some (.callback originalWorld originalTarget),
      some (.callback candidateWorld candidateTarget) =>
      originalWorld = candidateWorld ∧ originalTarget = candidateTarget
  | some (.fault originalCause), some (.fault candidateCause) =>
      originalCause = candidateCause
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

/-- Execute a cutpoint region by independently fetching each instruction from
the exact PE image, then apply the same machine-level import contract layer as
the compositional decoder. -/
def pe32WorldRegionBehavior (program : DecodedWorldProgram)
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
  let behavior <- executePE32SymbolicSpan pe imports span
  let behavior <- applyMachineImportCallContracts
    program.context.machineImportCallContracts behavior
  evalBehavior program.candidate region.targets state behavior

/-- The generated cutpoint model may be used in acceptance only when it agrees
pointwise with exact PE instruction fetching for every target and machine
state. -/
def DecodedWorldProgram.InstructionSemanticsAdequate
    (program : DecodedWorldProgram) : Prop :=
  ∀ targetId state,
    pe32WorldRegionBehavior program targetId state =
      decodedWorldRegionBehavior program targetId state

def DecodedWorldProgram.instructionSemanticsAdequateChecked
    (program : DecodedWorldProgram) : Bool :=
  let pe := if program.candidate then
    program.context.candidatePe
  else
    program.context.originalPe
  let imports := if program.candidate then
    program.context.candidateImports
  else
    program.context.originalImports
  program.regions.all fun region =>
    regionInstructionAdequateChecked pe imports
      (if program.candidate then region.candidate else region.original)

theorem DecodedWorldProgram.instructionSemanticsAdequate_of_checked
    (program : DecodedWorldProgram)
    (checked : program.instructionSemanticsAdequateChecked = true) :
    program.InstructionSemanticsAdequate := by
  intro targetId state
  cases regionResult : regionById program.regions targetId with
  | none =>
      simp [pe32WorldRegionBehavior, decodedWorldRegionBehavior, regionResult]
  | some region =>
      have regionMember : region ∈ program.regions := by
        have found := regionResult
        unfold regionById at found
        exact List.mem_of_find?_eq_some found
      cases candidateValue : program.candidate
      all_goals
        have allChecked := checked
        simp only [DecodedWorldProgram.instructionSemanticsAdequateChecked,
          candidateValue, Bool.false_eq_true, if_false, if_true,
          List.all_eq_true] at allChecked
        have regionChecked := allChecked region regionMember
        have adequate := regionInstructionAdequate_of_checked _ _ _ regionChecked
        rcases adequate with ⟨symbolic, executed, decoded⟩
        simp [pe32WorldRegionBehavior, decodedWorldRegionBehavior, regionResult,
          candidateValue, regionBehaviorWithMachineCallContracts, executed, decoded]

theorem DecodedWorldProgram.instructionSemanticsAdequate_of_regions
    (program : DecodedWorldProgram)
    (adequate : AllRegionInstructionAdequate
      (if program.candidate then program.context.candidatePe
        else program.context.originalPe)
      (if program.candidate then program.context.candidateImports
        else program.context.originalImports)
      program.candidate program.regions) :
    program.InstructionSemanticsAdequate := by
  intro targetId state
  cases regionResult : regionById program.regions targetId with
  | none =>
      simp [pe32WorldRegionBehavior, decodedWorldRegionBehavior, regionResult]
  | some region =>
      have regionMember : region ∈ program.regions := by
        have found := regionResult
        unfold regionById at found
        exact List.mem_of_find?_eq_some found
      have regionAdequate := allRegionInstructionAdequate_member
        (if program.candidate then program.context.candidatePe
          else program.context.originalPe)
        (if program.candidate then program.context.candidateImports
          else program.context.originalImports)
        program.candidate program.regions region adequate regionMember
      rcases regionAdequate with ⟨symbolic, executed, decoded⟩
      simp [pe32WorldRegionBehavior, decodedWorldRegionBehavior, regionResult,
        regionBehaviorWithMachineCallContracts, executed, decoded]

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
  site : ExternalCallSiteContract
  imported : ExternalTarget
  arguments : List Word
  continuationTargetId : Nat
  calls : List Nat
  eventIndex : Nat
  phaseIndex : Nat
  resumeInvariant : StateInvariant
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
  | fault (cause : ModeledFault)
  | blocked (reason : ExecutionBlock)

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

def blockedWorldTransition (reason : ExecutionBlock) :
    RelatedTransition WorldExecution WorldRelationalObservable :=
  { next := .blocked reason, observation := some (.proofBlocked reason) }

def suspendWorldExternalProtocol (program : DecodedWorldProgram)
    (sourceTargetId siteId : Nat)
    (imported : ExternalTarget) (arguments : List Word)
    (continuationTargetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime) : WorldExecution :=
  match program.externalCallSites.find? fun site => site.id == siteId with
  | none => .blocked (.missingExternalSite sourceTargetId continuationTargetId)
  | some site =>
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
        site
        imported
        arguments
        continuationTargetId
        calls
        eventIndex
        phaseIndex := 0
        resumeInvariant := site.boundaryInvariant
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
              { next := .returned state world,
                observation := some (.returned world state.registers.eax) }
          | callback :: outerCallbacks =>
              if target == callback.entry.returnAddress then
                { next := .awaitingExternal {
                    callback.suspension with
                    phaseIndex := callback.suspension.phaseIndex + 1
                    resumeInvariant := callback.entry.returnInvariant
                    state
                    world
                  } outerCallbacks,
                  observation := none }
              else
                blockedWorldTransition
                  (.invalidCallbackReturn target callback.entry.returnAddress)
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
                blockedWorldTransition (.mismatchedReturnTarget resolved continuation)
          | none => blockedWorldTransition (.unmappedReturnTarget target)
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
      | none => blockedWorldTransition (.missingExternalSite sourceTargetId continuation)
      | some siteId =>
          match resolvedExternalCallContract? program.context program.externalCallSites siteId with
          | none => blockedWorldTransition (.missingExternalContract siteId)
          | some contract =>
              match contract.disposition with
              | .terminates =>
                  { next := .terminated world,
                    observation := some (.external world imported arguments) }
              | .protocol =>
                  { next := suspendWorldExternalProtocol program sourceTargetId siteId imported
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
      | [] => blockedWorldTransition .missingRuntimeContinuation
      | continuation :: tail =>
          match resolveExternalCallSite program.context program.externalCallSites
              sourceTargetId continuation imported with
          | none => blockedWorldTransition (.missingExternalSite sourceTargetId continuation)
          | some siteId =>
              match resolvedExternalCallContract? program.context program.externalCallSites siteId with
              | none => blockedWorldTransition (.missingExternalContract siteId)
              | some contract =>
                  match contract.disposition with
                  | .terminates =>
                      { next := .terminated world,
                        observation := some (.external world imported arguments) }
                  | .protocol =>
                      { next := suspendWorldExternalProtocol program sourceTargetId siteId imported
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
          | none => blockedWorldTransition (.unmappedIndirectControl target)
          | some (imported, arguments) =>
              match resolveExternalCallSite program.context program.externalCallSites
                  sourceTargetId continuation imported with
              | none => blockedWorldTransition (.missingExternalSite sourceTargetId continuation)
              | some siteId =>
                  match resolvedExternalCallContract? program.context
                      program.externalCallSites siteId with
                  | none => blockedWorldTransition (.missingExternalContract siteId)
                  | some contract =>
                      match contract.disposition with
                      | .terminates =>
                          { next := .terminated world,
                            observation := some (.external world imported arguments) }
                      | .protocol =>
                          { next := suspendWorldExternalProtocol program sourceTargetId siteId imported
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
          | [] => blockedWorldTransition (.unmappedIndirectControl target)
          | continuation :: tail =>
              match resolveWorldImportCall program.candidate program.context world target state with
              | none => blockedWorldTransition (.unmappedIndirectControl target)
              | some (imported, arguments) =>
                  match resolveExternalCallSite program.context program.externalCallSites
                      sourceTargetId continuation imported with
                  | none => blockedWorldTransition (.missingExternalSite sourceTargetId continuation)
                  | some siteId =>
                      match resolvedExternalCallContract? program.context
                          program.externalCallSites siteId with
                      | none => blockedWorldTransition (.missingExternalContract siteId)
                      | some contract =>
                          match contract.disposition with
                          | .terminates =>
                              { next := .terminated world,
                                observation := some (.external world imported arguments) }
                          | .protocol =>
                              { next := suspendWorldExternalProtocol program sourceTargetId siteId imported
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
        { next := .fault .checkedContinue,
          observation := some (.fault .checkedContinue) }
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
      | none => blockedWorldTransition (.missingRegionBehavior targetId)
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
      | none => blockedWorldTransition (.missingRegionBehavior targetId)
      | some behavior =>
          transitionFromWorldOutcome program targetId
            (behavior.nextMachineState state) calls eventIndex world callbacks
            behavior.outcome
  | .fault cause => { next := .fault cause, observation := none }
  | .blocked reason => { next := .blocked reason, observation := none }

/-- Whole-program execution whose internal macro-steps are derived from exact
instruction fetches in the PE image. External transitions are shared with the
decoded proof model. -/
def stepPE32WorldExecution (program : DecodedWorldProgram) :
    WorldExecution -> RelatedTransition WorldExecution WorldRelationalObservable
  | .running targetId state calls eventIndex world =>
      match pe32WorldRegionBehavior program targetId state with
      | none => blockedWorldTransition (.missingRegionBehavior targetId)
      | some behavior =>
          transitionFromWorldOutcome program targetId
            (behavior.nextMachineState state) calls eventIndex world [] behavior.outcome
  | .returned state world =>
      { next := .returned state world, observation := none }
  | .terminated world => { next := .terminated world, observation := none }
  | .awaitingExternal suspension callbacks =>
      stepWorldExternalSuspension program suspension callbacks
  | .callbackRunning targetId state calls eventIndex world callbacks =>
      match pe32WorldRegionBehavior program targetId state with
      | none => blockedWorldTransition (.missingRegionBehavior targetId)
      | some behavior =>
          transitionFromWorldOutcome program targetId
            (behavior.nextMachineState state) calls eventIndex world callbacks
            behavior.outcome
  | .fault cause => { next := .fault cause, observation := none }
  | .blocked reason => { next := .blocked reason, observation := none }

theorem stepPE32WorldExecution_eq_stepWorldExecution
    (program : DecodedWorldProgram)
    (adequate : program.InstructionSemanticsAdequate) :
    stepPE32WorldExecution program = stepWorldExecution program := by
  funext execution
  cases execution with
  | running targetId state calls eventIndex world =>
      simp only [stepPE32WorldExecution, stepWorldExecution]
      rw [adequate targetId state]
  | returned state world => rfl
  | terminated world => rfl
  | awaitingExternal suspension callbacks => rfl
  | callbackRunning targetId state calls eventIndex world callbacks =>
      simp only [stepPE32WorldExecution, stepWorldExecution]
      rw [adequate targetId state]
  | fault cause => rfl
  | blocked reason => rfl

def DecodedWorldProgram.transitionSystem (program : DecodedWorldProgram) :
    RelatedTransitionSystem WorldExecution WorldRelationalObservable := {
  step := stepWorldExecution program
}

def DecodedWorldProgram.pe32TransitionSystem (program : DecodedWorldProgram) :
    RelatedTransitionSystem WorldExecution WorldRelationalObservable := {
  step := stepPE32WorldExecution program
}

theorem DecodedWorldProgram.pe32TransitionSystem_eq_transitionSystem
    (program : DecodedWorldProgram)
    (adequate : program.InstructionSemanticsAdequate) :
    program.pe32TransitionSystem = program.transitionSystem := by
  unfold DecodedWorldProgram.pe32TransitionSystem
    DecodedWorldProgram.transitionSystem
  rw [stepPE32WorldExecution_eq_stepWorldExecution program adequate]

def RelationalRuntimeCallStackHolds (context : StaticProofContext)
    (original candidate : MachineState) :
    List RelationalRuntimeCallFrame -> List Nat -> List ReturnSlotOffsetInventory -> Prop
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

/-- Preserved import relations carried by every checked runtime call-frame
inventory.  The concrete frame shape is checked by
`RelationalRuntimeCallStackHolds`; this predicate tracks only the relation facts
that must survive while those frames remain active. -/
def RelationalRuntimeCallImportsHold (world : RelationalWorld) :
    List ReturnSlotOffsetInventory -> Registers Word -> Registers Word -> Prop
  | [], _, _ => True
  | inventory :: inventories, originalRegisters, candidateRegisters =>
      inventory.preservedImportsHold world originalRegisters candidateRegisters = true ∧
        RelationalRuntimeCallImportsHold world inventories originalRegisters
          candidateRegisters

@[simp]
theorem RelationalRuntimeCallImportsHold.empty (world : RelationalWorld)
    (originalRegisters candidateRegisters : Registers Word) :
    RelationalRuntimeCallImportsHold world [] originalRegisters candidateRegisters := by
  trivial

theorem RelationalRuntimeCallImportsHold.cons (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory)
    (inventories : List ReturnSlotOffsetInventory)
    (originalRegisters candidateRegisters : Registers Word)
    (head : inventory.preservedImportsHold world originalRegisters
      candidateRegisters = true)
    (tail : RelationalRuntimeCallImportsHold world inventories originalRegisters
      candidateRegisters) :
    RelationalRuntimeCallImportsHold world (inventory :: inventories)
      originalRegisters candidateRegisters := by
  exact ⟨head, tail⟩

theorem RelationalRuntimeCallImportsHold.head (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory)
    (inventories : List ReturnSlotOffsetInventory)
    (originalRegisters candidateRegisters : Registers Word)
    (holds : RelationalRuntimeCallImportsHold world (inventory :: inventories)
      originalRegisters candidateRegisters) :
    inventory.preservedImportsHold world originalRegisters candidateRegisters = true := by
  exact holds.1

theorem RelationalRuntimeCallImportsHold.tail (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory)
    (inventories : List ReturnSlotOffsetInventory)
    (originalRegisters candidateRegisters : Registers Word)
    (holds : RelationalRuntimeCallImportsHold world (inventory :: inventories)
      originalRegisters candidateRegisters) :
    RelationalRuntimeCallImportsHold world inventories originalRegisters
      candidateRegisters := by
  exact holds.2

theorem RelationalRuntimeCallImportsHold.of_registers_eq
    (world : RelationalWorld)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : Registers Word)
    (inventories : List ReturnSlotOffsetInventory)
    (holds : RelationalRuntimeCallImportsHold world inventories beforeOriginal
      beforeCandidate)
    (originalRegisters : ∀ register,
      afterOriginal.get register = beforeOriginal.get register)
    (candidateRegisters : ∀ register,
      afterCandidate.get register = beforeCandidate.get register) :
    RelationalRuntimeCallImportsHold world inventories afterOriginal afterCandidate := by
  induction inventories with
  | nil => simp [RelationalRuntimeCallImportsHold]
  | cons inventory inventories ih =>
      simp only [RelationalRuntimeCallImportsHold] at holds ⊢
      refine And.intro ?_ (ih holds.2)
      unfold ReturnSlotOffsetInventory.preservedImportsHold
        importRegisterRelationsHold at holds ⊢
      simp only [List.all_eq_true] at holds ⊢
      intro relation relationMember
      have relationHolds := holds.1 relation relationMember
      unfold ImportRegisterRelation.holds at relationHolds ⊢
      simpa [originalRegisters relation.original,
        candidateRegisters relation.candidate] using relationHolds

def RelationalRuntimeCallRelationsHold (context : StaticProofContext)
    (world : RelationalWorld) :
    List ReturnSlotOffsetInventory -> Registers Word -> Registers Word -> Prop
  | [], _, _ => True
  | inventory :: inventories, originalRegisters, candidateRegisters =>
      inventory.preservedRelationsHold context world originalRegisters
          candidateRegisters = true ∧
        RelationalRuntimeCallRelationsHold context world inventories
          originalRegisters candidateRegisters

def RelationalRuntimeCallFactsHold (context : StaticProofContext)
    (world : RelationalWorld) (inventories : List ReturnSlotOffsetInventory)
    (originalRegisters candidateRegisters : Registers Word) : Prop :=
  RelationalRuntimeCallImportsHold world inventories originalRegisters
      candidateRegisters ∧
    RelationalRuntimeCallRelationsHold context world inventories originalRegisters
      candidateRegisters

@[simp]
theorem RelationalRuntimeCallFactsHold.empty (context : StaticProofContext)
    (world : RelationalWorld) (originalRegisters candidateRegisters : Registers Word) :
    RelationalRuntimeCallFactsHold context world [] originalRegisters
      candidateRegisters := by
  exact ⟨by trivial, by trivial⟩

theorem RelationalRuntimeCallFactsHold.cons (context : StaticProofContext)
    (world : RelationalWorld) (inventory : ReturnSlotOffsetInventory)
    (inventories : List ReturnSlotOffsetInventory)
    (originalRegisters candidateRegisters : Registers Word)
    (headImports : inventory.preservedImportsHold world originalRegisters
      candidateRegisters = true)
    (headRelations : inventory.preservedRelationsHold context world
      originalRegisters candidateRegisters = true)
    (tail : RelationalRuntimeCallFactsHold context world inventories
      originalRegisters candidateRegisters) :
    RelationalRuntimeCallFactsHold context world (inventory :: inventories)
      originalRegisters candidateRegisters := by
  exact ⟨⟨headImports, tail.1⟩, ⟨headRelations, tail.2⟩⟩

theorem RelationalRuntimeCallFactsHold.headImports (context : StaticProofContext)
    (world : RelationalWorld) (inventory : ReturnSlotOffsetInventory)
    (inventories : List ReturnSlotOffsetInventory)
    (originalRegisters candidateRegisters : Registers Word)
    (holds : RelationalRuntimeCallFactsHold context world
      (inventory :: inventories) originalRegisters candidateRegisters) :
    inventory.preservedImportsHold world originalRegisters candidateRegisters = true := by
  exact holds.1.1

theorem RelationalRuntimeCallFactsHold.headRelations (context : StaticProofContext)
    (world : RelationalWorld) (inventory : ReturnSlotOffsetInventory)
    (inventories : List ReturnSlotOffsetInventory)
    (originalRegisters candidateRegisters : Registers Word)
    (holds : RelationalRuntimeCallFactsHold context world
      (inventory :: inventories) originalRegisters candidateRegisters) :
    inventory.preservedRelationsHold context world originalRegisters
      candidateRegisters = true := by
  exact holds.2.1

theorem RelationalRuntimeCallFactsHold.tail (context : StaticProofContext)
    (world : RelationalWorld) (inventory : ReturnSlotOffsetInventory)
    (inventories : List ReturnSlotOffsetInventory)
    (originalRegisters candidateRegisters : Registers Word)
    (holds : RelationalRuntimeCallFactsHold context world
      (inventory :: inventories) originalRegisters candidateRegisters) :
    RelationalRuntimeCallFactsHold context world inventories originalRegisters
      candidateRegisters := by
  exact ⟨holds.1.2, holds.2.2⟩

theorem RelationalRuntimeCallRelationsHold.of_registers_eq
    (context : StaticProofContext) (world : RelationalWorld)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : Registers Word)
    (inventories : List ReturnSlotOffsetInventory)
    (holds : RelationalRuntimeCallRelationsHold context world inventories
      beforeOriginal beforeCandidate)
    (originalRegisters : ∀ register,
      afterOriginal.get register = beforeOriginal.get register)
    (candidateRegisters : ∀ register,
      afterCandidate.get register = beforeCandidate.get register) :
    RelationalRuntimeCallRelationsHold context world inventories afterOriginal
      afterCandidate := by
  induction inventories with
  | nil => trivial
  | cons inventory inventories ih =>
      simp only [RelationalRuntimeCallRelationsHold] at holds ⊢
      refine And.intro ?_ (ih holds.2)
      unfold ReturnSlotOffsetInventory.preservedRelationsHold
        registerRelationsHold at holds ⊢
      simp only [List.all_eq_true] at holds ⊢
      intro relation relationMember
      simpa [originalRegisters relation.original,
        candidateRegisters relation.candidate] using holds.1 relation relationMember

theorem RelationalRuntimeCallFactsHold.of_registers_eq
    (context : StaticProofContext) (world : RelationalWorld)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : Registers Word)
    (inventories : List ReturnSlotOffsetInventory)
    (holds : RelationalRuntimeCallFactsHold context world inventories
      beforeOriginal beforeCandidate)
    (originalRegisters : ∀ register,
      afterOriginal.get register = beforeOriginal.get register)
    (candidateRegisters : ∀ register,
      afterCandidate.get register = beforeCandidate.get register) :
    RelationalRuntimeCallFactsHold context world inventories afterOriginal
      afterCandidate := by
  exact ⟨RelationalRuntimeCallImportsHold.of_registers_eq world beforeOriginal
      beforeCandidate afterOriginal afterCandidate inventories holds.1
      originalRegisters candidateRegisters,
    RelationalRuntimeCallRelationsHold.of_registers_eq context world beforeOriginal
      beforeCandidate afterOriginal afterCandidate inventories holds.2
      originalRegisters candidateRegisters⟩

/-- A compact, replayed certificate that one active frame's import relations
remain valid across an internal paired step. -/
structure RelationalRuntimeCallImportTransferClaim where
  source : ReturnSlotOffsetInventory
  target : ReturnSlotOffsetInventory
deriving Repr, DecidableEq

def RelationalRuntimeCallImportTransferClaim.checked
    (claim : RelationalRuntimeCallImportTransferClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  claim.source.preservesImportsAcross originalBehavior candidateBehavior &&
    claim.target.checked &&
    claim.source.preservedImports == claim.target.preservedImports

def RelationalRuntimeCallImportTransferClaim.factsChecked
    (context : StaticProofContext)
    (claim : RelationalRuntimeCallImportTransferClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  claim.checked originalBehavior candidateBehavior &&
    claim.source.preservesRelationsAcross context originalBehavior candidateBehavior &&
    claim.target.preservedRelationsChecked context &&
    claim.source.preservedRelations == claim.target.preservedRelations

theorem RelationalRuntimeCallImportsHold.afterInternal
    (world : RelationalWorld)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List RelationalRuntimeCallImportTransferClaim)
    (originalState candidateState : MachineState)
    (checked : claims.all fun claim =>
      claim.checked originalBehavior candidateBehavior)
    (holds : RelationalRuntimeCallImportsHold world
      (claims.map (fun claim => claim.source)) originalState.registers
      candidateState.registers) :
    RelationalRuntimeCallImportsHold world
      (claims.map (fun claim => claim.target))
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers := by
  induction claims with
  | nil => simp
  | cons claim claims ih =>
      simp only [List.all_cons, Bool.and_eq_true] at checked
      simp only [List.map_cons, RelationalRuntimeCallImportsHold] at holds ⊢
      simp only [RelationalRuntimeCallImportTransferClaim.checked,
        Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with
        ⟨⟨⟨sourcePreserved, targetChecked⟩, preservedImportsExact⟩,
          remainingChecked⟩
      have sourceAfter :=
        ReturnSlotOffsetInventory.preservedImportsHold_after_of_checked
          claim.source world originalBehavior candidateBehavior originalState
          candidateState sourcePreserved holds.1
      have targetAfter : claim.target.preservedImportsHold world
          (originalBehavior.eval originalState).registers
          (candidateBehavior.eval candidateState).registers = true := by
        simpa only [ReturnSlotOffsetInventory.preservedImportsHold,
          preservedImportsExact] using sourceAfter
      exact ⟨targetAfter, ih remainingChecked holds.2⟩

theorem RelationalRuntimeCallRelationsHold.afterInternal
    (context : StaticProofContext) (world : RelationalWorld)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List RelationalRuntimeCallImportTransferClaim)
    (originalState candidateState : MachineState)
    (checked : claims.all fun claim =>
      claim.factsChecked context originalBehavior candidateBehavior)
    (holds : RelationalRuntimeCallRelationsHold context world
      (claims.map (fun claim => claim.source)) originalState.registers
      candidateState.registers) :
    RelationalRuntimeCallRelationsHold context world
      (claims.map (fun claim => claim.target))
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers := by
  induction claims with
  | nil => trivial
  | cons claim claims ih =>
      simp only [List.all_cons, Bool.and_eq_true] at checked
      simp only [List.map_cons, RelationalRuntimeCallRelationsHold] at holds ⊢
      simp only [RelationalRuntimeCallImportTransferClaim.factsChecked,
        Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with ⟨claimChecked, remainingChecked⟩
      rcases claimChecked with
        ⟨⟨⟨_importsChecked, sourcePreserved⟩, _targetChecked⟩,
          preservedRelationsExact⟩
      have sourceAfter :=
        ReturnSlotOffsetInventory.preservedRelationsHold_after_of_checked
          context claim.source world originalBehavior candidateBehavior originalState
          candidateState sourcePreserved holds.1
      have targetAfter : claim.target.preservedRelationsHold context world
          (originalBehavior.eval originalState).registers
          (candidateBehavior.eval candidateState).registers = true := by
        simpa only [ReturnSlotOffsetInventory.preservedRelationsHold,
          preservedRelationsExact] using sourceAfter
      exact ⟨targetAfter, ih remainingChecked holds.2⟩

theorem RelationalRuntimeCallFactsHold.afterInternal
    (context : StaticProofContext) (world : RelationalWorld)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List RelationalRuntimeCallImportTransferClaim)
    (originalState candidateState : MachineState)
    (checked : claims.all fun claim =>
      claim.factsChecked context originalBehavior candidateBehavior)
    (holds : RelationalRuntimeCallFactsHold context world
      (claims.map (fun claim => claim.source)) originalState.registers
      candidateState.registers) :
    RelationalRuntimeCallFactsHold context world
      (claims.map (fun claim => claim.target))
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers := by
  have importChecked : claims.all fun claim =>
      claim.checked originalBehavior candidateBehavior := by
    simp only [List.all_eq_true] at checked ⊢
    intro claim claimMember
    have factChecked := checked claim claimMember
    simp only [RelationalRuntimeCallImportTransferClaim.factsChecked,
      Bool.and_eq_true] at factChecked
    exact factChecked.1.1.1
  exact ⟨RelationalRuntimeCallImportsHold.afterInternal world originalBehavior
      candidateBehavior claims originalState candidateState importChecked holds.1,
    RelationalRuntimeCallRelationsHold.afterInternal context world originalBehavior
      candidateBehavior claims originalState candidateState checked holds.2⟩

def ReturnSlotOffsetInventory.preservesFactsAcrossExternal
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (inventory : ReturnSlotOffsetInventory) : Bool :=
  inventory.preservedImports.isEmpty &&
    inventory.preservedRelationsChecked context &&
    inventory.preservedRelations.all fun relation =>
      (ExternalRegisterRelationPreservationClaim.checked context contract {
        source := relation
        target := relation
      })

theorem ReturnSlotOffsetInventory.preservedRelationsHold_afterExternal
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (inventory : ReturnSlotOffsetInventory)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (checked : inventory.preservesFactsAcrossExternal context contract = true)
    (sourceHolds : inventory.preservedRelationsHold context originalEvent.world
      originalEvent.state.registers candidateEvent.state.registers = true)
    (pairConforms : ExactExternalCallPairConforms context contract
      originalEvent candidateEvent originalResult candidateResult) :
    inventory.preservedRelationsHold context originalResult.world
      originalResult.state.registers candidateResult.state.registers = true := by
  simp only [ReturnSlotOffsetInventory.preservesFactsAcrossExternal,
    Bool.and_eq_true, List.all_eq_true] at checked
  unfold ReturnSlotOffsetInventory.preservedRelationsHold
    registerRelationsHold at sourceHolds ⊢
  simp only [List.all_eq_true] at sourceHolds ⊢
  intro relation relationMember
  exact externalRegisterRelationPreservationHolds_of_checked context contract
    { source := relation, target := relation }
    originalEvent candidateEvent originalResult candidateResult
    (checked.2 relation relationMember) (sourceHolds relation relationMember)
    pairConforms

theorem ReturnSlotOffsetInventory.preservedRelationsHold_normalizeImportReturnSlot
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (inventory : ReturnSlotOffsetInventory) (world : RelationalWorld)
    (original candidate : MachineState)
    (checked : inventory.preservesFactsAcrossExternal context contract = true)
    (holds : inventory.preservedRelationsHold context world
      original.registers candidate.registers = true) :
    inventory.preservedRelationsHold context world
      (normalizeImportReturnSlotState original).registers
      (normalizeImportReturnSlotState candidate).registers = true := by
  simp only [ReturnSlotOffsetInventory.preservesFactsAcrossExternal,
    Bool.and_eq_true, List.all_eq_true] at checked
  unfold ReturnSlotOffsetInventory.preservedRelationsHold
    registerRelationsHold at holds ⊢
  simp only [List.all_eq_true] at holds ⊢
  intro relation relationMember
  have relationChecked := checked.2 relation relationMember
  simp only [ExternalRegisterRelationPreservationClaim.checked,
    Bool.and_eq_true, beq_iff_eq] at relationChecked
  have originalNotEsp := relationChecked.1.2
  have candidateNotEsp := relationChecked.2
  have relationHolds := holds relation relationMember
  cases originalRegister : relation.original <;>
    cases candidateRegister : relation.candidate <;>
    simp_all [normalizeImportReturnSlotState, StageA.Formal.Registers.get,
      StageA.Formal.Registers.set]

theorem RelationalRuntimeCallFactsHold.afterExternal
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (inventories : List ReturnSlotOffsetInventory)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (checked : inventories.all fun inventory =>
      inventory.preservesFactsAcrossExternal context contract)
    (holds : RelationalRuntimeCallFactsHold context originalEvent.world inventories
      originalEvent.state.registers candidateEvent.state.registers)
    (pairConforms : ExactExternalCallPairConforms context contract
      originalEvent candidateEvent originalResult candidateResult) :
    RelationalRuntimeCallFactsHold context originalResult.world inventories
      originalResult.state.registers candidateResult.state.registers := by
  induction inventories with
  | nil => exact RelationalRuntimeCallFactsHold.empty context originalResult.world _ _
  | cons inventory inventories ih =>
      simp only [List.all_cons, Bool.and_eq_true] at checked
      have headChecked := checked.1
      have importsEmpty : inventory.preservedImports = [] := by
        simp only [ReturnSlotOffsetInventory.preservesFactsAcrossExternal,
          Bool.and_eq_true] at headChecked
        simpa using headChecked.1.1
      have headRelations :=
        inventory.preservedRelationsHold_afterExternal context contract
          originalEvent candidateEvent originalResult candidateResult
          checked.1 holds.2.1 pairConforms
      have tailFacts := ih checked.2 ⟨holds.1.2, holds.2.2⟩
      exact RelationalRuntimeCallFactsHold.cons context originalResult.world
        inventory inventories _ _
        (by simp [ReturnSlotOffsetInventory.preservedImportsHold,
          importRegisterRelationsHold, importsEmpty])
        headRelations tailFacts

theorem RelationalRuntimeCallFactsHold.normalizeImportReturnSlot
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (inventories : List ReturnSlotOffsetInventory) (world : RelationalWorld)
    (original candidate : MachineState)
    (checked : inventories.all fun inventory =>
      inventory.preservesFactsAcrossExternal context contract)
    (holds : RelationalRuntimeCallFactsHold context world inventories
      original.registers candidate.registers) :
    RelationalRuntimeCallFactsHold context world inventories
      (normalizeImportReturnSlotState original).registers
      (normalizeImportReturnSlotState candidate).registers := by
  induction inventories with
  | nil => exact RelationalRuntimeCallFactsHold.empty context world _ _
  | cons inventory inventories ih =>
      simp only [List.all_cons, Bool.and_eq_true] at checked
      have headChecked := checked.1
      have importsEmpty : inventory.preservedImports = [] := by
        simp only [ReturnSlotOffsetInventory.preservesFactsAcrossExternal,
          Bool.and_eq_true] at headChecked
        simpa using headChecked.1.1
      have headRelations := inventory.preservedRelationsHold_normalizeImportReturnSlot
        context contract world original candidate checked.1 holds.2.1
      have tailFacts := ih checked.2 ⟨holds.1.2, holds.2.2⟩
      exact RelationalRuntimeCallFactsHold.cons context world inventory inventories _ _
        (by simp [ReturnSlotOffsetInventory.preservedImportsHold,
          importRegisterRelationsHold, importsEmpty])
        headRelations tailFacts

theorem RelationalRuntimeCallStackHolds.toMixed
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (offsets : List ReturnSlotOffsetInventory)
    (holds : RelationalRuntimeCallStackHolds context original candidate
      frames continuations offsets) :
    RelationalMixedRuntimeStackHolds context world original candidate
      (frames.map RelationalRuntimeFrame.internal)
      (continuations.map RelationalRuntimeContinuation.internal)
      (offsets.map ReturnSlotOffsetInventory.representative) := by
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
                holds.2.2.2.1,
                ReturnSlotOffsetInventory.representative_holds offset frame
                  original.registers candidate.registers holds.2.2.2.2.1,
                ih continuations offsets holds.2.2.2.2.2⟩

theorem RelationalRuntimeCallStackHolds.afterInternal
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List ReturnSlotFrameInventoryTransferClaim)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (originalState candidateState : MachineState)
    (checked : claims.all fun claim =>
      claim.checked context sourceInvariant originalBehavior candidateBehavior)
    (holds : RelationalRuntimeCallStackHolds context originalState candidateState
      frames continuations (claims.map (fun claim => claim.source)))
    (related : StateRel context world sourceInvariant originalState candidateState) :
    RelationalRuntimeCallStackHolds context
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState)
      frames continuations (claims.map (fun claim => claim.target)) := by
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
              have transferred := returnSlotFrameInventoryTransferHolds_of_checked
                context world sourceInvariant originalBehavior candidateBehavior claim
                frame originalState candidateState checked.1 holds.2.2.2.2.1
                holds.2.2.2.1 related
              exact ⟨holds.1, holds.2.1, holds.2.2.1, transferred.2,
                transferred.1,
                ih frames continuations checked.2 holds.2.2.2.2.2⟩

theorem RelationalRuntimeCallStackHolds.afterExternalCall
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (contract : MachineImportCallContract)
    (claims : List ExternalReturnSlotInventoryTransferClaim)
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
      frames continuations (claims.map (fun claim => claim.target)) := by
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
              have transferred := externalReturnSlotInventoryTransferHolds_of_checked
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
    (claims : List ExternalJumpReturnSlotInventoryTransferClaim)
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
      frames continuations (claims.map (fun claim => claim.target)) := by
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
              have transferred := externalJumpReturnSlotInventoryTransferHolds_of_checked
                originalBehavior candidateBehavior contract claim frame originalState
                candidateState originalResult candidateResult checked.1
                holds.2.2.2.2.1 holds.2.2.2.1 originalAbi candidateAbi
                (framesPreserved frame)
              exact ⟨holds.1, holds.2.1, holds.2.2.1, transferred.2,
                transferred.1,
                ih frames continuations checked.2 holds.2.2.2.2.2⟩

/-- Runtime return addresses must remain canonical mapped code targets. Whether
they are behaviorally reachable is checked when a return transition actually
selects one; a terminating callee may carry a syntactic return address that can
never execute.  The reachability argument is retained temporarily for generated
module API compatibility. -/
def RelationalRuntimeCallTargetsMapped (graph : RelationalProductGraph)
    (_reachability : RelationalProductReachabilityEvidence) : List Nat -> Prop
  | [] => True
  | continuation :: continuations =>
      (exists nodeId node,
        graph.getNode? nodeId = some node ∧
          node.targetId = continuation) ∧
        RelationalRuntimeCallTargetsMapped graph _reachability continuations

theorem RelationalRuntimeCallStackHolds.of_memory_eq
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (offsets : List ReturnSlotOffsetInventory)
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
                  refine ⟨holds.2.2.2.2.1.1, ?_⟩
                  intro location member
                  unfold ReturnSlotOffsetPair.holds
                  rw [originalRegisters location.originalRegister,
                    candidateRegisters location.candidateRegister]
                  exact holds.2.2.2.2.1.2 location member,
                ih continuations offsets holds.2.2.2.2.2⟩

structure ProductControlState where
  nodeId : Nat
  calls : List Nat
  frameOffsets : List ReturnSlotOffsetInventory
deriving Repr, DecidableEq

def ProductControlState.checked (state : ProductControlState) : Bool :=
  state.calls.length == state.frameOffsets.length &&
    state.frameOffsets.all ReturnSlotOffsetInventory.checked

structure ProductControlProfile where
  states : List ProductControlState
deriving Repr, DecidableEq

def ProductControlProfile.checked (profile : ProductControlProfile) : Bool :=
  profile.states.all ProductControlState.checked

def ProductControlProfile.lookup (profile : ProductControlProfile)
    (nodeId : Nat) (calls : List Nat) : Option (List ReturnSlotOffsetInventory) := do
  let state <- profile.states.find? fun state =>
    state.nodeId == nodeId && state.calls == calls
  pure state.frameOffsets

def ProductControlProfile.Allows (profile : ProductControlProfile)
    (nodeId : Nat) (calls : List Nat)
    (frameOffsets : List ReturnSlotOffsetInventory) : Bool :=
  let state : ProductControlState := { nodeId, calls, frameOffsets }
  profile.checked && profile.states.contains state

structure ProductInvariantTable where
  nodeInvariants : Array StateInvariant
  terminalInvariant : StateInvariant
deriving Repr, DecidableEq

def ProductInvariantTable.Valid (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable) : Prop :=
  invariants.nodeInvariants.size = graph.nodes.size

def WorldExternalSuspensionsRelated (context : StaticProofContext)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalSuspension) : Prop :=
  original.sourceTargetId = candidate.sourceTargetId ∧
    original.siteId = candidate.siteId ∧
    original.site = candidate.site ∧
    original.imported = candidate.imported ∧
    externalCallArgumentsRelated context original.world original.arguments
      candidate.arguments = true ∧
    original.continuationTargetId = candidate.continuationTargetId ∧
    original.calls = candidate.calls ∧
    original.eventIndex = candidate.eventIndex ∧
    original.phaseIndex = candidate.phaseIndex ∧
    original.resumeInvariant = candidate.resumeInvariant ∧
    original.world = candidate.world ∧
    StateRel context original.world original.resumeInvariant
      original.state candidate.state ∧
    ∃ site contract,
      site = original.site ∧ site ∈ sites ∧ site.id = original.siteId ∧
        site.sourceTargetId = original.sourceTargetId ∧
        site.continuationTargetId = original.continuationTargetId ∧
        machineImportCallContractById? context site.machineContractId = some contract ∧
        contract.imported = original.imported ∧ contract.disposition = .protocol ∧
        ExternalCallBoundaryRelated context site contract
          original.event candidate.event ∧
        (original.phaseIndex = 0 →
          original.resumeInvariant = site.boundaryInvariant ∧
            original.state = original.event.state ∧
            candidate.state = candidate.event.state ∧
            original.world = original.event.world ∧
            candidate.world = candidate.event.world)

theorem WorldExternalSuspensionsRelated.afterCallbackReturn
    (context : StaticProofContext) (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalCallbackRuntime)
    (world : RelationalWorld) (originalState candidateState : MachineState)
    (related : WorldExternalSuspensionsRelated context sites
      original.suspension candidate.suspension)
    (returnInvariant : original.entry.returnInvariant =
      candidate.entry.returnInvariant)
    (argumentsRelated : externalCallArgumentsRelated context world
      original.suspension.arguments candidate.suspension.arguments = true)
    (statesRelated : StateRel context world original.entry.returnInvariant
      originalState candidateState) :
    WorldExternalSuspensionsRelated context sites
      { original.suspension with
          phaseIndex := original.suspension.phaseIndex + 1
          resumeInvariant := original.entry.returnInvariant
          state := originalState
          world }
      { candidate.suspension with
          phaseIndex := candidate.suspension.phaseIndex + 1
          resumeInvariant := candidate.entry.returnInvariant
          state := candidateState
          world } := by
  rcases related with
    ⟨sourceEqual, siteIdEqual, siteEqual, importEqual, argumentsEqual,
      continuationEqual, callsEqual, eventEqual, phaseEqual, _resumeEqual,
      _worldEqual, _oldStatesRelated, site, contract, siteIdentity, siteMember,
      siteId, sourceTarget, continuationTarget, resolved, imported, disposition,
      boundary, _phaseZero⟩
  refine ⟨sourceEqual, siteIdEqual, siteEqual, importEqual, argumentsRelated,
    continuationEqual, callsEqual, eventEqual, ?_, returnInvariant, rfl,
    statesRelated, site, contract, siteIdentity, siteMember, siteId, sourceTarget,
    continuationTarget, resolved, imported, disposition, boundary, ?_⟩
  · exact congrArg (fun phase => phase + 1) phaseEqual
  · intro phaseZero
    exfalso
    exact Nat.add_one_ne_zero original.suspension.phaseIndex phaseZero

/-- Finite, checked product nodes that may execute while an external callback is active.

The profile includes callback entries and their callback-mode internal continuations. It is
part of the proof contract rather than inferred by declaring every reachable node eligible.
Protocol refinement must reject callback actions and resumptions outside this inventory. -/
structure ProtocolCallbackControlState where
  nodeId : Nat
  activeFrameOffset : ReturnSlotOffsetPair
  returnInvariant : StateInvariant
  outerFrameTransferRules : List ReturnSlotTransferRule := []
deriving Repr, DecidableEq

structure ProtocolCallbackTargetProfile where
  states : List ProtocolCallbackControlState := []
deriving Repr, DecidableEq

def ProtocolCallbackTargetProfile.contains
    (profile : ProtocolCallbackTargetProfile) (nodeId : Nat) : Bool :=
  profile.states.any fun state => state.nodeId == nodeId

def ProtocolCallbackTargetProfile.Allows
    (profile : ProtocolCallbackTargetProfile) (nodeId : Nat)
    (activeFrameOffset : ReturnSlotOffsetPair)
    (returnInvariant : StateInvariant) : Bool :=
  profile.states.any fun state =>
    state.nodeId == nodeId && state.activeFrameOffset == activeFrameOffset &&
      state.returnInvariant == returnInvariant

def ProtocolCallbackTargetProfile.transferRules?
    (profile : ProtocolCallbackTargetProfile) (nodeId : Nat) :
    Option (List ReturnSlotTransferRule) := do
  let state <- profile.states.find? fun state => state.nodeId == nodeId
  pure state.outerFrameTransferRules

def ProtocolCallbackTargetProfile.Valid
    (profile : ProtocolCallbackTargetProfile)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence) : Bool :=
  profile.states.all fun state =>
    (profile.states.filter fun other => other.nodeId == state.nodeId).length == 1 &&
      (graph.getNode? state.nodeId).isSome && reachability.contains state.nodeId &&
      state.outerFrameTransferRules.all fun rule =>
        (state.outerFrameTransferRules.filter fun other =>
          other.originalSourceRegister == rule.originalSourceRegister &&
            other.candidateSourceRegister == rule.candidateSourceRegister).length == 1

def WorldExternalCallbackRuntimePairRelated (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalCallbackRuntime) : Prop :=
  WorldExternalSuspensionsRelated context sites
      original.suspension candidate.suspension ∧
    ExternalCallbackActionsRelated context original.entry.entryInvariant
      original.suspension.world original.suspension.siteId
      original.suspension.eventIndex original.suspension.phaseIndex
      original.suspension.continuationTargetId original.entry candidate.entry ∧
    ∃ nodeId node,
      graph.getNode? nodeId = some node ∧
        callbackTargets.contains nodeId = true ∧
        callbackTargets.Allows nodeId ReturnSlotOffsetPair.zero
          original.entry.returnInvariant = true ∧
        node.targetId = original.entry.targetId ∧
        reachability.contains nodeId = true ∧
        invariants.nodeInvariants[nodeId]? = some original.entry.entryInvariant

def WorldExternalCallbackFramesHold (context : StaticProofContext)
    (world : RelationalWorld) (originalState candidateState : MachineState) :
    List WorldExternalCallbackRuntime -> List WorldExternalCallbackRuntime ->
      List ReturnSlotOffsetPair -> Prop
  | [], [], [] => True
  | original :: originals, candidate :: candidates, offset :: offsets =>
      ∃ callback : RegisteredCallbackPair,
        original.entry.targetId = callback.targetId ∧
          candidate.entry.targetId = callback.targetId ∧
          let frame := RelationalExternalCallbackFrame.ofActions
            original.suspension.siteId original.suspension.eventIndex
            original.suspension.phaseIndex original.suspension.continuationTargetId
            callback original.entry candidate.entry
          frame.valid context world = true ∧
            frame.memoryHolds originalState.memory candidateState.memory ∧
            externalCallArgumentsRelated context world
                original.suspension.arguments candidate.suspension.arguments = true ∧
            offset.holdsRuntimeFrame (.externalCallback frame)
              originalState.registers candidateState.registers ∧
            WorldExternalCallbackFramesHold context world originalState candidateState
              originals candidates offsets
  | _, _, _ => False

/-- Preserve an arbitrary nested callback-frame stack through one internal
machine step. Register movement is certified by a finite affine rule set and
memory preservation is explicit; neither callback depth nor concrete addresses
are baked into the theorem. -/
theorem WorldExternalCallbackFramesHold.afterInternal
    (context : StaticProofContext) (world : RelationalWorld)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (rules : List ReturnSlotTransferRule)
    (originalState candidateState : MachineState)
    (originalCallbacks candidateCallbacks : List WorldExternalCallbackRuntime)
    (sourceOffsets targetOffsets : List ReturnSlotOffsetPair)
    (checked : rules.all fun rule =>
      rule.checked originalBehavior candidateBehavior)
    (transferred : applyReturnSlotTransferRulesToList rules sourceOffsets =
      some targetOffsets)
    (originalMemory :
      ((originalBehavior.eval originalState).nextMachineState originalState).memory =
        originalState.memory)
    (candidateMemory :
      ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory =
        candidateState.memory)
    (holds : WorldExternalCallbackFramesHold context world originalState candidateState
      originalCallbacks candidateCallbacks sourceOffsets) :
    WorldExternalCallbackFramesHold context world
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState)
      originalCallbacks candidateCallbacks targetOffsets := by
  induction originalCallbacks generalizing candidateCallbacks sourceOffsets targetOffsets with
  | nil =>
      cases candidateCallbacks with
      | nil =>
          cases sourceOffsets with
          | nil =>
              simp only [applyReturnSlotTransferRulesToList,
                Option.some.injEq] at transferred
              subst targetOffsets
              simp [WorldExternalCallbackFramesHold]
          | cons source sources =>
              simp [WorldExternalCallbackFramesHold] at holds
      | cons candidate candidates =>
          simp [WorldExternalCallbackFramesHold] at holds
  | cons original originals ih =>
      cases candidateCallbacks with
      | nil => simp [WorldExternalCallbackFramesHold] at holds
      | cons candidate candidates =>
          cases sourceOffsets with
          | nil => simp [WorldExternalCallbackFramesHold] at holds
          | cons source sources =>
              simp only [applyReturnSlotTransferRulesToList] at transferred
              cases ruleResult : applyReturnSlotTransferRules rules source with
              | none => simp [ruleResult] at transferred
              | some target =>
                  cases tailResult : applyReturnSlotTransferRulesToList rules sources with
                  | none => simp [ruleResult, tailResult] at transferred
                  | some targets =>
                      rw [ruleResult, tailResult] at transferred
                      simp at transferred
                      subst targetOffsets
                      simp only [WorldExternalCallbackFramesHold] at holds ⊢
                      rcases holds with
                        ⟨callback, originalTarget, candidateTarget, frameValid,
                          frameMemory, argumentsHold, sourceHolds, tailHolds⟩
                      refine ⟨callback, originalTarget, candidateTarget, frameValid,
                        ?_, argumentsHold, ?_, ?_⟩
                      · simpa [originalMemory, candidateMemory] using frameMemory
                      · simpa [RelationalBehavior.nextMachineState] using
                          applyReturnSlotTransferRules_holdsRuntimeFrame_of_checked
                            originalBehavior candidateBehavior rules source target
                            (.externalCallback
                              (RelationalExternalCallbackFrame.ofActions
                                original.suspension.siteId
                                original.suspension.eventIndex
                                original.suspension.phaseIndex
                                original.suspension.continuationTargetId callback
                                original.entry candidate.entry))
                            originalState candidateState checked ruleResult sourceHolds
                      · exact ih candidates sources targets tailResult tailHolds

def WorldExternalCallbackContinuationFramesHold
    (context : StaticProofContext)
    (callbackTargets : ProtocolCallbackTargetProfile) (nodeId : Nat)
    (world : RelationalWorld) (originalState candidateState : MachineState) :
    List WorldExternalCallbackRuntime -> List WorldExternalCallbackRuntime -> Prop
  | [], [] => True
  | original :: originals, candidate :: candidates =>
      ∃ activeOffset outerOffsets transferredOuterOffsets transferRules,
        callbackTargets.Allows nodeId activeOffset original.entry.returnInvariant = true ∧
          callbackTargets.transferRules? nodeId = some transferRules ∧
          applyReturnSlotTransferRulesToList transferRules outerOffsets =
            some transferredOuterOffsets ∧
          WorldExternalCallbackFramesHold context world originalState candidateState
            (original :: originals) (candidate :: candidates)
            (activeOffset :: outerOffsets)
  | _, _ => False

def WorldExternalCallbackRuntimesRelated (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract) :
    List WorldExternalCallbackRuntime -> List WorldExternalCallbackRuntime -> Prop
  | [], [] => True
  | original :: originals, candidate :: candidates =>
      WorldExternalCallbackRuntimePairRelated context graph invariants reachability
          callbackTargets sites original candidate ∧
        WorldExternalCallbackRuntimesRelated context graph invariants reachability
          callbackTargets sites originals candidates
  | _, _ => False

theorem WorldExternalCallbackRuntimesRelated.length_eq
    (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (original candidate : List WorldExternalCallbackRuntime)
    (related : WorldExternalCallbackRuntimesRelated context graph invariants
      reachability callbackTargets sites original candidate) :
    original.length = candidate.length := by
  induction original generalizing candidate with
  | nil =>
      cases candidate <;>
        simp_all [WorldExternalCallbackRuntimesRelated]
  | cons runtime runtimes ih =>
      cases candidate with
      | nil => simp [WorldExternalCallbackRuntimesRelated] at related
      | cons candidate candidates =>
          simp only [WorldExternalCallbackRuntimesRelated] at related
          simpa using congrArg Nat.succ (ih candidates related.2)

def externalCallSitesExcludeProtocol (context : StaticProofContext)
    (sites : List ExternalCallSiteContract) : Bool :=
  sites.all fun site =>
    match machineImportCallContractById? context site.machineContractId with
    | some contract => contract.disposition != .protocol
    | none => false

theorem WorldExternalSuspensionsRelated.impossible_of_no_protocol_sites
    (context : StaticProofContext) (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalSuspension)
    (related : WorldExternalSuspensionsRelated context sites original candidate)
    (noProtocol : externalCallSitesExcludeProtocol context sites = true) : False := by
  rcases related with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, site, contract, _, member, _, _, _,
      resolved, _, disposition, _, _⟩
  simp only [externalCallSitesExcludeProtocol] at noProtocol
  have siteChecked := List.all_eq_true.mp noProtocol site member
  rw [resolved] at siteChecked
  change (contract.disposition != .protocol) = true at siteChecked
  rw [disposition] at siteChecked
  simp at siteChecked

theorem WorldExternalCallbackRuntimesRelated.impossible_of_no_protocol_sites
    (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (original candidate : List WorldExternalCallbackRuntime)
    (nonempty : original ≠ [])
    (related : WorldExternalCallbackRuntimesRelated context graph invariants
      reachability callbackTargets sites original candidate)
    (noProtocol : externalCallSitesExcludeProtocol context sites = true) : False := by
  cases original with
  | nil => exact nonempty rfl
  | cons original originals =>
      cases candidate with
      | nil => simp [WorldExternalCallbackRuntimesRelated] at related
      | cons candidate candidates =>
          exact WorldExternalSuspensionsRelated.impossible_of_no_protocol_sites
            context sites original.suspension candidate.suspension related.1.1 noProtocol

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
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract) :
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
            RelationalRuntimeCallFactsHold context originalWorld frameOffsets
              originalState.registers candidateState.registers ∧
            RelationalRuntimeCallTargetsMapped graph reachability originalCalls ∧
            StateRel context originalWorld invariant originalState candidateState
  | .returned originalState originalWorld,
      .returned candidateState candidateWorld =>
      originalWorld = candidateWorld ∧
        StateRel context originalWorld invariants.terminalInvariant
          originalState candidateState
  | .terminated originalWorld, .terminated candidateWorld =>
      originalWorld = candidateWorld
  | .awaitingExternal originalSuspension originalCallbacks,
      .awaitingExternal candidateSuspension candidateCallbacks =>
      WorldExternalSuspensionsRelated context sites originalSuspension
          candidateSuspension ∧
        WorldExternalCallbackRuntimesRelated context graph invariants reachability
          callbackTargets sites originalCallbacks candidateCallbacks ∧
        ∃ callbackFrameOffsets,
          WorldExternalCallbackFramesHold context originalSuspension.world
            originalSuspension.state candidateSuspension.state originalCallbacks
            candidateCallbacks callbackFrameOffsets
  | .callbackRunning originalTarget originalState originalCalls originalEventIndex
      originalWorld originalCallbacks,
      .callbackRunning candidateTarget candidateState candidateCalls candidateEventIndex
      candidateWorld candidateCallbacks =>
      originalTarget = candidateTarget ∧ originalCalls = candidateCalls ∧
        originalEventIndex = candidateEventIndex ∧ originalWorld = candidateWorld ∧
        originalCallbacks ≠ [] ∧
        exists nodeId node invariant frames frameOffsets,
          graph.getNode? nodeId = some node ∧
            callbackTargets.contains nodeId = true ∧
            node.targetId = originalTarget ∧
            reachability.contains nodeId = true ∧
            invariants.nodeInvariants[nodeId]? = some invariant ∧
            control.Allows nodeId originalCalls frameOffsets = true ∧
            RelationalRuntimeCallStackHolds context originalState candidateState
              frames originalCalls frameOffsets ∧
            RelationalRuntimeCallFactsHold context originalWorld frameOffsets
              originalState.registers candidateState.registers ∧
            RelationalRuntimeCallTargetsMapped graph reachability originalCalls ∧
            StateRel context originalWorld invariant originalState candidateState ∧
            WorldExternalCallbackRuntimesRelated context graph invariants reachability
              callbackTargets sites originalCallbacks candidateCallbacks ∧
            WorldExternalCallbackContinuationFramesHold context callbackTargets nodeId
              originalWorld originalState candidateState originalCallbacks candidateCallbacks
  | .fault originalCause, .fault candidateCause =>
      originalCause = candidateCause
  | _, _ => False

def WorldExternalProtocolActionsRelated (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (originalSuspension candidateSuspension : WorldExternalSuspension)
    (originalCallbacks candidateCallbacks : List WorldExternalCallbackRuntime) :
    WorldExternalProtocolAction -> WorldExternalProtocolAction -> Prop
  | .returned originalResult, .returned candidateResult =>
      originalResult.world = candidateResult.world ∧
        ∃ nodeId node frames frameOffsets,
          graph.getNode? nodeId = some node ∧
            (originalCallbacks = [] ∨ callbackTargets.contains nodeId = true) ∧
            node.targetId = originalSuspension.continuationTargetId ∧
            reachability.contains nodeId = true ∧
            invariants.nodeInvariants[nodeId]? =
              some originalSuspension.site.targetInvariant ∧
            control.Allows nodeId originalSuspension.calls frameOffsets = true ∧
            RelationalRuntimeCallStackHolds context originalResult.state
              candidateResult.state frames originalSuspension.calls frameOffsets ∧
            RelationalRuntimeCallFactsHold context originalResult.world frameOffsets
              originalResult.state.registers candidateResult.state.registers ∧
            RelationalRuntimeCallTargetsMapped graph reachability
              originalSuspension.calls ∧
            StateRel context originalResult.world
              originalSuspension.site.targetInvariant originalResult.state
              candidateResult.state ∧
            WorldExternalCallbackRuntimesRelated context graph invariants reachability
              callbackTargets sites originalCallbacks candidateCallbacks ∧
            WorldExternalCallbackContinuationFramesHold context callbackTargets nodeId
              originalResult.world originalResult.state candidateResult.state
              originalCallbacks candidateCallbacks
  | .callback originalEntry, .callback candidateEntry =>
      ExternalCallbackActionsRelated context originalEntry.entryInvariant
          originalSuspension.world originalSuspension.siteId
          originalSuspension.eventIndex originalSuspension.phaseIndex
          originalSuspension.continuationTargetId originalEntry candidateEntry ∧
        ∃ nodeId node,
          graph.getNode? nodeId = some node ∧
            callbackTargets.contains nodeId = true ∧
            callbackTargets.Allows nodeId ReturnSlotOffsetPair.zero
              originalEntry.returnInvariant = true ∧
            node.targetId = originalEntry.targetId ∧
            reachability.contains nodeId = true ∧
            invariants.nodeInvariants[nodeId]? = some originalEntry.entryInvariant ∧
            control.Allows nodeId [] [] = true ∧
            WorldExternalCallbackContinuationFramesHold context callbackTargets nodeId
              originalEntry.world originalEntry.state candidateEntry.state
              ({ suspension := originalSuspension, entry := originalEntry } ::
                originalCallbacks)
              ({ suspension := candidateSuspension, entry := candidateEntry } ::
                candidateCallbacks)
  | .terminated originalWorld, .terminated candidateWorld =>
      originalWorld = candidateWorld
  | _, _ => False

def WorldExternalProtocolEnvironmentsRefine (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalProtocolEnvironment) : Prop :=
  ∀ originalSuspension candidateSuspension originalCallbacks candidateCallbacks
      callbackFrameOffsets,
    WorldExternalSuspensionsRelated context sites originalSuspension
        candidateSuspension →
      WorldExternalCallbackRuntimesRelated context graph invariants reachability
        callbackTargets sites originalCallbacks candidateCallbacks →
      WorldExternalCallbackFramesHold context originalSuspension.world
        originalSuspension.state candidateSuspension.state originalCallbacks
        candidateCallbacks callbackFrameOffsets →
      WorldExternalProtocolActionsRelated context graph invariants reachability control
        callbackTargets sites originalSuspension candidateSuspension originalCallbacks
        candidateCallbacks
        (original.action originalSuspension.request)
        (candidate.action candidateSuspension.request)

theorem WorldExternalProtocolEnvironmentsRefine.of_no_protocol_sites
    (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (originalProtocol candidateProtocol : WorldExternalProtocolEnvironment)
    (noProtocol : externalCallSitesExcludeProtocol context sites = true) :
    WorldExternalProtocolEnvironmentsRefine context graph invariants reachability
      control callbackTargets sites originalProtocol candidateProtocol := by
  intro originalSuspension candidateSuspension originalCallbacks candidateCallbacks
    callbackFrameOffsets suspensionsRelated callbacksRelated callbackFramesHold
  exact False.elim
    (WorldExternalSuspensionsRelated.impossible_of_no_protocol_sites context sites
      originalSuspension candidateSuspension suspensionsRelated noProtocol)

theorem stepWorldExternalSuspension_related (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (original candidate : DecodedWorldProgram)
    (originalSuspension candidateSuspension : WorldExternalSuspension)
    (originalCallbacks candidateCallbacks : List WorldExternalCallbackRuntime)
    (suspensionsRelated : WorldExternalSuspensionsRelated context sites
      originalSuspension candidateSuspension)
    (callbacksRelated : WorldExternalCallbackRuntimesRelated context graph invariants
      reachability callbackTargets sites originalCallbacks candidateCallbacks)
    (callbackFrameOffsets : List ReturnSlotOffsetPair)
    (callbackFramesHold : WorldExternalCallbackFramesHold context
      originalSuspension.world originalSuspension.state candidateSuspension.state
      originalCallbacks candidateCallbacks callbackFrameOffsets)
    (actionsRelated : WorldExternalProtocolActionsRelated context graph invariants
      reachability control callbackTargets sites originalSuspension candidateSuspension
      originalCallbacks candidateCallbacks
      (original.protocolEnvironment.action originalSuspension.request)
      (candidate.protocolEnvironment.action candidateSuspension.request)) :
    worldRelationalObservationsRelated context
        (stepWorldExternalSuspension original originalSuspension
          originalCallbacks).observation
        (stepWorldExternalSuspension candidate candidateSuspension
          candidateCallbacks).observation ∧
      WorldExecutionsRelated context graph invariants reachability control callbackTargets sites
        (stepWorldExternalSuspension original originalSuspension
          originalCallbacks).next
        (stepWorldExternalSuspension candidate candidateSuspension
          candidateCallbacks).next := by
  have suspensionRelation := suspensionsRelated
  rcases suspensionsRelated with
    ⟨_, _, _, _, _, continuationEqual, callsEqual, eventEqual, _, _, _, _, _⟩
  cases originalAction : original.protocolEnvironment.action originalSuspension.request <;>
    cases candidateAction : candidate.protocolEnvironment.action candidateSuspension.request
  case returned.returned originalResult candidateResult =>
      simp only [originalAction, candidateAction, WorldExternalProtocolActionsRelated]
        at actionsRelated
      rcases actionsRelated with
        ⟨resultWorldEqual, nodeId, node, frames, frameOffsets, nodeFound,
          callbackContinuationAllowed, targetFound, reachable, invariantFound, controlAllowed,
          stackHolds, frameImportsHold, stackTargetsReachable, statesRelated,
          resultCallbacksRelated,
          resultCallbackFramesHold⟩
      unfold stepWorldExternalSuspension
      rw [originalAction, candidateAction]
      simp only
      cases originalCallbacks with
      | nil =>
          cases candidateCallbacks with
          | nil =>
              refine ⟨True.intro, continuationEqual, callsEqual, ?_,
                resultWorldEqual, nodeId, node, originalSuspension.site.targetInvariant,
                frames, frameOffsets, nodeFound, targetFound, reachable, invariantFound,
                controlAllowed, stackHolds, frameImportsHold,
                stackTargetsReachable, statesRelated⟩
              exact congrArg (fun index => index + 1) eventEqual
          | cons candidateCallback candidateCallbacks =>
              simp [WorldExternalCallbackRuntimesRelated] at callbacksRelated
      | cons originalCallback originalCallbacks =>
          have callbackTargetAllowed : callbackTargets.contains nodeId = true := by
            rcases callbackContinuationAllowed with impossible | allowed
            · simp at impossible
            · exact allowed
          cases candidateCallbacks with
          | nil =>
              simp [WorldExternalCallbackRuntimesRelated] at callbacksRelated
          | cons candidateCallback candidateCallbacks =>
              refine ⟨True.intro, continuationEqual, callsEqual, ?_,
                resultWorldEqual, (by simp), nodeId, node,
                originalSuspension.site.targetInvariant, frames, frameOffsets, nodeFound,
                callbackTargetAllowed, targetFound, reachable, invariantFound,
                controlAllowed, stackHolds, frameImportsHold,
                stackTargetsReachable, statesRelated, resultCallbacksRelated,
                resultCallbackFramesHold⟩
              exact congrArg (fun index => index + 1) eventEqual
  case callback.callback originalEntry candidateEntry =>
      simp only [originalAction, candidateAction, WorldExternalProtocolActionsRelated]
        at actionsRelated
      rcases actionsRelated with
        ⟨entryRelated, nodeId, node, nodeFound, callbackTargetAllowed,
          callbackControlAllowed, targetFound, reachable, invariantFound, controlAllowed,
          callbackContinuationFramesHold⟩
      have entryRelation := entryRelated
      rcases entryRelated with
        ⟨targetEqual, originalInvariant, candidateInvariant, _, _, _, _, entryWorldEqual,
          callback, originalCallbackTarget, callbackEntry⟩
      unfold stepWorldExternalSuspension
      rw [originalAction, candidateAction]
      simp only
      refine ⟨⟨entryWorldEqual, targetEqual⟩, targetEqual, rfl, eventEqual,
        entryWorldEqual, (by simp), nodeId, node, originalEntry.entryInvariant, [], [],
        nodeFound, callbackTargetAllowed, targetFound, reachable, invariantFound,
        controlAllowed, ?_, ?_,
        ?_, callbackEntry.2.2.2.2.2.2.2.2.2, ?_, ?_⟩
      · simp [RelationalRuntimeCallStackHolds]
      · simp [RelationalRuntimeCallFactsHold,
          RelationalRuntimeCallImportsHold, RelationalRuntimeCallRelationsHold]
      · simp [RelationalRuntimeCallTargetsMapped]
      · simp only [WorldExternalCallbackRuntimesRelated]
        exact ⟨⟨suspensionRelation, entryRelation,
          ⟨nodeId, node, nodeFound, callbackTargetAllowed, callbackControlAllowed,
            targetFound, reachable, invariantFound⟩⟩,
          callbacksRelated⟩
      · exact callbackContinuationFramesHold
  case terminated.terminated originalWorld candidateWorld =>
      simp only [originalAction, candidateAction, WorldExternalProtocolActionsRelated]
        at actionsRelated
      unfold stepWorldExternalSuspension
      rw [originalAction, candidateAction]
      exact ⟨True.intro, actionsRelated⟩
  all_goals
    simp [originalAction, candidateAction, WorldExternalProtocolActionsRelated]
      at actionsRelated

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
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) : Prop :=
  forall originalExecution candidateExecution,
    WorldExecutionsRelated context graph invariants reachability control
      callbackTargets original.externalCallSites
      originalExecution candidateExecution ->
    worldRelationalObservationsRelated context
        (original.transitionSystem.step originalExecution).observation
        (candidate.transitionSystem.step candidateExecution).observation ∧
      WorldExecutionsRelated context graph invariants reachability control
        callbackTargets original.externalCallSites
        (original.transitionSystem.step originalExecution).next
        (candidate.transitionSystem.step candidateExecution).next

def RunningProductNodeStepRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) (nodeId : Nat) : Prop :=
  match graph.getNode? nodeId, invariants.nodeInvariants[nodeId]? with
  | some node, some invariant =>
      forall frames calls frameOffsets eventIndex world originalState candidateState,
        control.Allows nodeId calls frameOffsets = true ->
        RelationalRuntimeCallStackHolds context originalState candidateState
          frames calls frameOffsets ->
        RelationalRuntimeCallFactsHold context world frameOffsets originalState.registers
          candidateState.registers ->
        RelationalRuntimeCallTargetsMapped graph reachability calls ->
        StateRel context world invariant originalState candidateState ->
        worldRelationalObservationsRelated context
            (original.transitionSystem.step
              (.running node.targetId originalState calls eventIndex world)).observation
            (candidate.transitionSystem.step
              (.running node.targetId candidateState calls eventIndex world)).observation ∧
          WorldExecutionsRelated context graph invariants reachability control
            callbackTargets original.externalCallSites
            (original.transitionSystem.step
              (.running node.targetId originalState calls eventIndex world)).next
            (candidate.transitionSystem.step
              (.running node.targetId candidateState calls eventIndex world)).next
  | _, _ => False

def CallbackRunningProductNodeStepRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) (nodeId : Nat) : Prop :=
  match graph.getNode? nodeId, invariants.nodeInvariants[nodeId]? with
  | some node, some invariant =>
      ∀ frames calls frameOffsets eventIndex world originalState candidateState
          originalCallbacks candidateCallbacks,
        control.Allows nodeId calls frameOffsets = true →
        RelationalRuntimeCallStackHolds context originalState candidateState
          frames calls frameOffsets →
        RelationalRuntimeCallFactsHold context world frameOffsets originalState.registers
          candidateState.registers →
        RelationalRuntimeCallTargetsMapped graph reachability calls →
        StateRel context world invariant originalState candidateState →
        originalCallbacks ≠ [] →
        WorldExternalCallbackRuntimesRelated context graph invariants reachability
          callbackTargets original.externalCallSites originalCallbacks candidateCallbacks →
        WorldExternalCallbackContinuationFramesHold context callbackTargets nodeId world
          originalState candidateState originalCallbacks candidateCallbacks →
        worldRelationalObservationsRelated context
            (original.transitionSystem.step
              (.callbackRunning node.targetId originalState calls eventIndex world
                originalCallbacks)).observation
            (candidate.transitionSystem.step
              (.callbackRunning node.targetId candidateState calls eventIndex world
                candidateCallbacks)).observation ∧
          WorldExecutionsRelated context graph invariants reachability control
            callbackTargets original.externalCallSites
            (original.transitionSystem.step
              (.callbackRunning node.targetId originalState calls eventIndex world
                originalCallbacks)).next
            (candidate.transitionSystem.step
              (.callbackRunning node.targetId candidateState calls eventIndex world
                candidateCallbacks)).next
  | _, _ => False

def ReachableRunningProductNodesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) : Prop :=
  forall nodeId, nodeId < graph.nodes.size ->
    reachability.contains nodeId = true ->
    RunningProductNodeStepRefined context graph invariants reachability control
      callbackTargets original candidate nodeId

def ReachableCallbackRunningProductNodesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) : Prop :=
  ∀ nodeId, nodeId < graph.nodes.size →
    callbackTargets.contains nodeId = true →
    CallbackRunningProductNodeStepRefined context graph invariants reachability control
      callbackTargets original candidate nodeId

theorem reachableCallbackRunningProductNodesRefined_of_no_protocol_sites
    (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram)
    (invariantTableValid : invariants.Valid graph)
    (noProtocol : externalCallSitesExcludeProtocol context
      original.externalCallSites = true) :
    ReachableCallbackRunningProductNodesRefined context graph invariants reachability
      control callbackTargets original candidate := by
  intro nodeId nodeBefore callbackTargetAllowed
  have invariantBefore : nodeId < invariants.nodeInvariants.size := by
    rw [invariantTableValid]
    exact nodeBefore
  let node := graph.nodes[nodeId]
  let invariant := invariants.nodeInvariants[nodeId]
  have nodeFound : graph.getNode? nodeId = some node := by
    simp [RelationalProductGraph.getNode?, node, nodeBefore]
  have invariantFound : invariants.nodeInvariants[nodeId]? = some invariant := by
    simp [invariant, invariantBefore]
  unfold CallbackRunningProductNodeStepRefined
  rw [nodeFound, invariantFound]
  intro frames calls frameOffsets eventIndex world originalState candidateState
    originalCallbacks candidateCallbacks controlAllowed stackHolds frameImportsHold
    stackTargetsReachable statesRelated callbacksNonempty callbacksRelated
    callbackFramesHold
  exact False.elim
    (WorldExternalCallbackRuntimesRelated.impossible_of_no_protocol_sites context
      graph invariants reachability callbackTargets original.externalCallSites
      originalCallbacks candidateCallbacks callbacksNonempty callbacksRelated noProtocol)

def AllListedRunningProductNodesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) : List Nat -> Prop
  | [] => True
  | nodeId :: nodeIds =>
      RunningProductNodeStepRefined context graph invariants reachability control
          callbackTargets original candidate nodeId ∧
        AllListedRunningProductNodesRefined context graph invariants reachability control
          callbackTargets original candidate nodeIds

theorem allListedRunningProductNodesRefined_append
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) (left right : List Nat)
    (leftRefined : AllListedRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate left)
    (rightRefined : AllListedRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate right) :
    AllListedRunningProductNodesRefined context graph invariants reachability control
      callbackTargets original candidate (left ++ right) := by
  induction left with
  | nil => exact rightRefined
  | cons nodeId nodeIds ih =>
      exact ⟨leftRefined.1, ih leftRefined.2⟩

theorem allListedRunningProductNodesRefined_of_mem
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) (nodeIds : List Nat)
    (listed : AllListedRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate nodeIds) :
    forall nodeId, nodeId ∈ nodeIds ->
      RunningProductNodeStepRefined context graph invariants reachability control
        callbackTargets original candidate nodeId := by
  induction nodeIds with
  | nil => simp
  | cons head tail ih =>
      intro nodeId member
      rcases listed with ⟨headRefined, tailRefined⟩
      simp only [List.mem_cons] at member
      cases member with
      | inl same => simpa [same] using headRefined
      | inr inTail => exact ih tailRefined nodeId inTail

def AllListedCallbackRunningProductNodesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) : List Nat -> Prop
  | [] => True
  | nodeId :: nodeIds =>
      CallbackRunningProductNodeStepRefined context graph invariants reachability control
          callbackTargets original candidate nodeId ∧
        AllListedCallbackRunningProductNodesRefined context graph invariants reachability
          control callbackTargets original candidate nodeIds

theorem allListedCallbackRunningProductNodesRefined_of_mem
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) (nodeIds : List Nat)
    (listed : AllListedCallbackRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate nodeIds) :
    ∀ nodeId, nodeId ∈ nodeIds →
      CallbackRunningProductNodeStepRefined context graph invariants reachability control
        callbackTargets original candidate nodeId := by
  induction nodeIds with
  | nil => simp
  | cons head tail ih =>
      intro nodeId member
      rcases listed with ⟨headRefined, tailRefined⟩
      simp only [List.mem_cons] at member
      cases member with
      | inl same => simpa [same] using headRefined
      | inr inTail => exact ih tailRefined nodeId inTail

theorem reachableCallbackRunningProductNodesRefined_of_listed_profile
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram)
    (listed : AllListedCallbackRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate
      (callbackTargets.states.map fun state => state.nodeId)) :
    ReachableCallbackRunningProductNodesRefined context graph invariants reachability
      control callbackTargets original candidate := by
  intro nodeId _nodeBefore allowed
  apply allListedCallbackRunningProductNodesRefined_of_mem context graph invariants
    reachability control callbackTargets original candidate
    (callbackTargets.states.map fun state => state.nodeId) listed nodeId
  simp only [ProtocolCallbackTargetProfile.contains, List.any_eq_true,
    beq_iff_eq] at allowed
  rcases allowed with ⟨state, member, stateNode⟩
  exact List.mem_map.mpr ⟨state, member, stateNode⟩

theorem reachableRunningProductNodesRefined_of_complete_evidence
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram)
    (evidence : RelationalProductLocalEvidence)
    (complete : evidence.complete graph reachability = true)
    (listed : AllListedRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate evidence.decodedNodeIds) :
    ReachableRunningProductNodesRefined context graph invariants reachability control
      callbackTargets original candidate := by
  simp only [RelationalProductLocalEvidence.complete, Bool.and_eq_true,
    beq_iff_eq] at complete
  intro nodeId before reachable
  apply allListedRunningProductNodesRefined_of_mem context graph invariants
    reachability control callbackTargets original candidate evidence.decodedNodeIds
    listed nodeId
  rw [complete.1]
  simp [RelationalProductReachabilityEvidence.reachableNodeIds, before, reachable]

theorem productStepRefinement_of_reachable_nodes (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram)
    (environmentRefines : ExternalEnvironmentRefines context
      original.externalCallSites original.environment candidate.environment)
    (protocolRefines : WorldExternalProtocolEnvironmentsRefine context graph invariants
      reachability control callbackTargets original.externalCallSites
      original.protocolEnvironment candidate.protocolEnvironment)
    (running : ReachableRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate)
    (callbackRunning : ReachableCallbackRunningProductNodesRefined context graph
      invariants reachability control callbackTargets original candidate) :
    ProductStepRefinement context graph invariants reachability control callbackTargets
      original candidate := by
  intro originalExecution candidateExecution related
  cases originalExecution <;> cases candidateExecution
  case running.running originalTarget originalState originalCalls originalEventIndex
      originalWorld candidateTarget candidateState candidateCalls candidateEventIndex
      candidateWorld =>
      rcases related with
        ⟨targetEqual, callsEqual, eventEqual, worldEqual,
          nodeId, node, invariant, frames, frameOffsets, nodeFound, targetFound,
          reachable, invariantFound, controlAllowed, stackHolds, frameImportsHold,
          stackTargetsReachable, statesRelated⟩
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
        originalState candidateState controlAllowed stackHolds frameImportsHold
        stackTargetsReachable statesRelated
  case returned.returned originalState originalWorld candidateState candidateWorld =>
      rcases related with ⟨worldEqual, statesRelated⟩
      subst candidateWorld
      exact ⟨True.intro, ⟨rfl, statesRelated⟩⟩
  case terminated.terminated originalWorld candidateWorld =>
      subst candidateWorld
      exact ⟨True.intro, rfl⟩
  case awaitingExternal.awaitingExternal originalSuspension originalCallbacks
      candidateSuspension candidateCallbacks =>
      rcases related with
        ⟨suspensionsRelated, callbacksRelated, callbackFrameOffsets,
          callbackFramesHold⟩
      exact stepWorldExternalSuspension_related context graph invariants reachability
        control callbackTargets original.externalCallSites original candidate originalSuspension
        candidateSuspension originalCallbacks candidateCallbacks suspensionsRelated
        callbacksRelated callbackFrameOffsets callbackFramesHold
        (protocolRefines originalSuspension candidateSuspension originalCallbacks
          candidateCallbacks callbackFrameOffsets suspensionsRelated callbacksRelated
          callbackFramesHold)
  case callbackRunning.callbackRunning originalTarget originalState originalCalls
      originalEventIndex originalWorld originalCallbacks candidateTarget candidateState
      candidateCalls candidateEventIndex candidateWorld candidateCallbacks =>
      rcases related with
        ⟨targetEqual, callsEqual, eventEqual, worldEqual, callbacksNonempty,
          nodeId, node, invariant, frames, frameOffsets, nodeFound,
          callbackTargetAllowed, targetFound, reachable, invariantFound, controlAllowed,
          stackHolds, frameImportsHold, stackTargetsReachable, statesRelated,
          callbacksRelated, callbackFramesHold⟩
      subst candidateTarget
      subst candidateCalls
      subst candidateEventIndex
      subst candidateWorld
      have nodeBefore : nodeId < graph.nodes.size := by
        exact Array.getElem?_eq_some_iff.mp nodeFound |>.1
      have nodeStep := callbackRunning nodeId nodeBefore callbackTargetAllowed
      unfold CallbackRunningProductNodeStepRefined at nodeStep
      rw [nodeFound, invariantFound] at nodeStep
      subst originalTarget
      exact nodeStep frames originalCalls frameOffsets originalEventIndex originalWorld
        originalState candidateState originalCallbacks candidateCallbacks
        controlAllowed stackHolds frameImportsHold stackTargetsReachable statesRelated
        callbacksNonempty callbacksRelated callbackFramesHold
  case fault.fault => exact ⟨True.intro, related⟩
  all_goals simp [WorldExecutionsRelated] at related

structure PE32ConsoleLaunchV1 where
  rootNodeId : Nat
  rootTargetId : Nat
  rootInvariant : StateInvariant
deriving Repr, DecidableEq

def PE32ConsoleLaunchV1.preEntryTlsAbsent
    (context : StaticProofContext) : Bool :=
  context.originalPe.tlsDirectoryRva == 0 &&
    context.originalPe.tlsDirectorySize == 0 &&
    context.candidatePe.tlsDirectoryRva == 0 &&
    context.candidatePe.tlsDirectorySize == 0

/-- The bounded console profile has exactly the entry surfaces it models.
DLL loader events and nonempty exports require a different launch profile;
malformed export metadata is rejected rather than treated as an empty table. -/
def PE32ConsoleImageEntrySurfaceValid (pe : PE32) : Bool :=
  !pe.isDll &&
    match parseExports pe with
    | some [] => true
    | _ => false

def PE32ConsoleEntrySurfacesValid (context : StaticProofContext) : Bool :=
  PE32ConsoleImageEntrySurfaceValid context.originalPe &&
    PE32ConsoleImageEntrySurfaceValid context.candidatePe

def importIatByteCovered (imports : List PEImport) (rva : Nat) : Bool :=
  imports.any fun imported =>
    imported.iatRva <= rva && rva < imported.iatRva + 4

/-- The bounded launch profile maps both images at their preferred bases. The
loader-populated IAT is checked separately through the relational world. -/
def PreferredBaseImageMemory (pe : PE32) (imports : List PEImport)
    (memory : Memory) : Prop :=
  forall rva expected,
    rva < pe.sizeOfImage ->
    importIatByteCovered imports rva = false ->
    rvaByte pe rva = some expected ->
    memory (BitVec.ofNat 32 (pe.imageBase + rva)) = BitVec.ofNat 8 expected

/-- Deterministic preferred-base memory used by launch-model certificates.
Loader-populated ranges are overlaid separately; this base contains exactly the
bytes supplied by `rvaByte` and zero elsewhere. -/
def preferredBaseImageMemory (pe : PE32) : Memory := fun address =>
  if pe.imageBase <= address.toNat then
    match rvaByte pe (address.toNat - pe.imageBase) with
    | some byte => BitVec.ofNat 8 byte
    | none => BitVec.ofNat 8 0
  else BitVec.ofNat 8 0

def preferredBaseImportWrites (candidate : Bool) (context : StaticProofContext)
    (world : RelationalWorld) : List (Word × Word) :=
  world.importAddresses.map fun binding =>
    if candidate then
      (BitVec.ofNat 32
          (context.candidatePe.imageBase + binding.candidateIatRva),
        binding.candidateAddress)
    else
      (BitVec.ofNat 32
          (context.originalPe.imageBase + binding.originalIatRva),
        binding.originalAddress)

/-- A concrete preferred-base image with the abstract loader's paired import
addresses written into its IAT.  The finite launch checkers below establish
the semantic properties of this proposed memory; construction alone grants no
proof authority. -/
def loaderPopulatedPreferredBaseMemory (candidate : Bool)
    (context : StaticProofContext) (world : RelationalWorld) : Memory :=
  applyConcreteWrites
    (preferredBaseImageMemory
      (if candidate then context.candidatePe else context.originalPe))
    (preferredBaseImportWrites candidate context world)

/-- Finite replay of `PreferredBaseImageMemory` for one concrete memory. -/
def preferredBaseImageMemoryChecked (pe : PE32) (imports : List PEImport)
    (memory : Memory) : Bool :=
  (List.range pe.sizeOfImage).all fun rva =>
    importIatByteCovered imports rva ||
      match rvaByte pe rva with
      | none => true
      | some expected =>
          memory (BitVec.ofNat 32 (pe.imageBase + rva)) ==
            BitVec.ofNat 8 expected

theorem preferredBaseImageMemory_of_checked (pe : PE32)
    (imports : List PEImport) (memory : Memory)
    (checked : preferredBaseImageMemoryChecked pe imports memory = true) :
    PreferredBaseImageMemory pe imports memory := by
  intro rva expected rvaBefore notIat byteRead
  simp only [preferredBaseImageMemoryChecked, List.all_eq_true] at checked
  have row := checked rva (List.mem_range.mpr rvaBefore)
  simp [notIat, byteRead] at row
  exact row

/-- Finite replay of immutable-image words.  `readImmutableImageWord` itself
checks that every admitted word is wholly contained in the image, so every
possible start belongs to this bounded inventory. -/
def immutableImageWordMemoryChecked (pe : PE32) (memory : Memory) : Bool :=
  match parseImports pe with
  | none => false
  | some imports =>
      (List.range pe.sizeOfImage).all fun rva =>
        match readImmutableImageWordWithImports pe imports
            (pe.imageBase + rva) 4 with
        | none => true
        | some expected =>
            Memory.read32 memory (BitVec.ofNat 32 (pe.imageBase + rva)) ==
              BitVec.ofNat 32 expected

theorem immutableImageWordMemory_of_checked (pe : PE32) (memory : Memory)
    (checked : immutableImageWordMemoryChecked pe memory = true) :
    ImmutableImageWordMemory pe memory := by
  intro absolute expected wordRead
  have bounds := readImmutableImageWord_bounds pe absolute 4 expected wordRead
  have rvaBefore : absolute - pe.imageBase < pe.sizeOfImage := by omega
  cases importsResult : parseImports pe with
  | none => simp [readImmutableImageWord, importsResult] at wordRead
  | some imports =>
    have rawRead : readImmutableImageWordWithImports pe imports absolute 4 =
        some expected := by
      simpa [readImmutableImageWord, importsResult] using wordRead
    simp only [immutableImageWordMemoryChecked, importsResult,
      List.all_eq_true] at checked
    have row := checked (absolute - pe.imageBase)
      (List.mem_range.mpr rvaBefore)
    have absoluteEq : pe.imageBase + (absolute - pe.imageBase) = absolute := by
      omega
    simp [absoluteEq, rawRead] at row
    exact row

def importAddressesMemoryHoldChecked (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory) : Bool :=
  world.importAddresses.all fun binding =>
    Memory.read32 original
        (BitVec.ofNat 32
          (context.originalPe.imageBase + binding.originalIatRva)) ==
      binding.originalAddress &&
    Memory.read32 candidate
        (BitVec.ofNat 32
          (context.candidatePe.imageBase + binding.candidateIatRva)) ==
      binding.candidateAddress

theorem importAddressesMemoryHold_of_checked (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory)
    (checked : importAddressesMemoryHoldChecked context world original candidate = true) :
    ImportAddressesMemoryHold context world original candidate := by
  intro binding member
  simp only [importAddressesMemoryHoldChecked, List.all_eq_true] at checked
  have row := checked binding member
  simpa only [ImportAddressPair.memoryHolds, Bool.and_eq_true, beq_iff_eq]
    using row

def stackRangesMemoryHoldChecked (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory) : Bool :=
  world.stackRanges.all fun range =>
    (List.range range.size).all fun offset =>
      if decide (offset + 4 <= range.size) && decide (offset % 4 = 0) then
        wordRelated context.originalPe.imageBase context.candidatePe.imageBase
          context.codeMap.entries.toList (context.relationalValueTargets world)
          (Memory.read32 original
            (range.originalBase + BitVec.ofNat 32 offset))
          (Memory.read32 candidate
            (range.candidateBase + BitVec.ofNat 32 offset))
      else true

theorem stackRangesMemoryHold_of_checked (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory)
    (checked : stackRangesMemoryHoldChecked context world original candidate = true) :
    StackRangesMemoryHold context world original candidate := by
  intro range rangeMember offset inside aligned
  simp only [stackRangesMemoryHoldChecked, List.all_eq_true] at checked
  have offsetBefore : offset < range.size := by omega
  have row := checked range rangeMember offset (List.mem_range.mpr offsetBefore)
  simp [inside, aligned] at row
  exact row

theorem preferredBaseImageMemory_maps_image (pe : PE32) (imports : List PEImport)
    (bounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    PreferredBaseImageMemory pe imports (preferredBaseImageMemory pe) := by
  intro rva expected rvaBefore _notIat byteRead
  have absoluteBefore : pe.imageBase + rva < 2 ^ 32 := by omega
  have addressNat :
      (BitVec.ofNat 32 (pe.imageBase + rva) : Word).toNat = pe.imageBase + rva := by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt absoluteBefore]
  simp [preferredBaseImageMemory, addressNat, byteRead]

theorem preferredBaseImageMemory_immutable (pe : PE32)
    (bounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (bytesValid : pe32ByteTreeValid pe.bytes = true) :
    ImmutableImageWordMemory pe (preferredBaseImageMemory pe) := by
  intro absolute expected checked
  have bounds := readImmutableImageWord_bounds pe absolute 4 expected checked
  have absoluteBefore : absolute < 2 ^ 32 := by omega
  have addressNat : (BitVec.ofNat 32 absolute : Word).toNat = absolute := by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt absoluteBefore]
  have readChecked :
      readRvaLittleEndian pe (absolute - pe.imageBase) 4 = some expected := by
    cases importsResult : parseImports pe with
    | none => simp [readImmutableImageWord, importsResult] at checked
    | some imports =>
      have rawChecked : readImmutableImageWordWithImports pe imports absolute 4 =
          some expected := by
        simpa [readImmutableImageWord, importsResult] using checked
      unfold readImmutableImageWordWithImports at rawChecked
      split at rawChecked
      · simp at rawChecked
      · dsimp only at rawChecked
        split at rawChecked
        · simp at rawChecked
        · split at rawChecked
          · simp at rawChecked
          · split at rawChecked
            · cases sectionResult : pe.sections.find? (fun sec =>
                  !sec.writable && sec.virtualAddress <= absolute - pe.imageBase &&
                    absolute - pe.imageBase + 4 <= sec.virtualAddress + sec.mappedSize) with
              | none => simp [sectionResult] at rawChecked
              | some sec => simpa [sectionResult] using rawChecked
            · simpa using rawChecked
  have rangeFour : List.range 4 = [0, 1, 2, 3] := by decide
  unfold readRvaLittleEndian at readChecked
  simp only [rangeFour, List.mapM_cons, List.mapM_nil] at readChecked
  cases byte0Result : rvaByte pe (absolute - pe.imageBase + 0) with
  | none =>
    have byte0Read : rvaByte pe (absolute - pe.imageBase) = none := by
      simpa using byte0Result
    simp [byte0Read] at readChecked
  | some byte0 =>
    have byte0Read : rvaByte pe (absolute - pe.imageBase) = some byte0 := by
      simpa using byte0Result
    cases byte1Result : rvaByte pe (absolute - pe.imageBase + 1) with
    | none => simp [byte0Read, byte1Result] at readChecked
    | some byte1 =>
      cases byte2Result : rvaByte pe (absolute - pe.imageBase + 2) with
      | none => simp [byte0Read, byte1Result, byte2Result] at readChecked
      | some byte2 =>
        cases byte3Result : rvaByte pe (absolute - pe.imageBase + 3) with
        | none =>
          simp [byte0Read, byte1Result, byte2Result, byte3Result] at readChecked
        | some byte3 =>
          have address1Before : absolute + 1 < 2 ^ 32 := by omega
          have address2Before : absolute + 2 < 2 ^ 32 := by omega
          have address3Before : absolute + 3 < 2 ^ 32 := by omega
          have address1Nat :
              ((BitVec.ofNat 32 absolute : Word) + BitVec.ofNat 32 1).toNat =
                absolute + 1 := by
            simp [BitVec.toNat_add, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt absoluteBefore, Nat.mod_eq_of_lt address1Before]
          have address2Nat :
              ((BitVec.ofNat 32 absolute : Word) + BitVec.ofNat 32 2).toNat =
                absolute + 2 := by
            simp [BitVec.toNat_add, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt absoluteBefore, Nat.mod_eq_of_lt address2Before]
          have address3Nat :
              ((BitVec.ofNat 32 absolute : Word) + BitVec.ofNat 32 3).toNat =
                absolute + 3 := by
            simp [BitVec.toNat_add, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt absoluteBefore, Nat.mod_eq_of_lt address3Before]
          have address1Base : pe.imageBase <= absolute + 1 := by omega
          have address2Base : pe.imageBase <= absolute + 2 := by omega
          have address3Base : pe.imageBase <= absolute + 3 := by omega
          have byte1Read :
              rvaByte pe (absolute + 1 - pe.imageBase) = some byte1 := by
            rw [show absolute + 1 - pe.imageBase =
              absolute - pe.imageBase + 1 by omega]
            exact byte1Result
          have byte2Read :
              rvaByte pe (absolute + 2 - pe.imageBase) = some byte2 := by
            rw [show absolute + 2 - pe.imageBase =
              absolute - pe.imageBase + 2 by omega]
            exact byte2Result
          have byte3Read :
              rvaByte pe (absolute + 3 - pe.imageBase) = some byte3 := by
            rw [show absolute + 3 - pe.imageBase =
              absolute - pe.imageBase + 3 by omega]
            exact byte3Result
          have memory0 : preferredBaseImageMemory pe (BitVec.ofNat 32 absolute) =
              BitVec.ofNat 8 byte0 := by
            simp [preferredBaseImageMemory, addressNat, bounds.1, byte0Read]
          have memory1 : preferredBaseImageMemory pe
                (BitVec.ofNat 32 absolute + BitVec.ofNat 32 1) =
              BitVec.ofNat 8 byte1 := by
            simp [preferredBaseImageMemory, address1Nat, address1Base, byte1Read]
          have memory2 : preferredBaseImageMemory pe
                (BitVec.ofNat 32 absolute + BitVec.ofNat 32 2) =
              BitVec.ofNat 8 byte2 := by
            simp [preferredBaseImageMemory, address2Nat, address2Base, byte2Read]
          have memory3 : preferredBaseImageMemory pe
                (BitVec.ofNat 32 absolute + BitVec.ofNat 32 3) =
              BitVec.ofNat 8 byte3 := by
            simp [preferredBaseImageMemory, address3Nat, address3Base, byte3Read]
          have byte0Bound := pe32ByteTreeValid_rvaByte_lt pe bytesValid byte0Read
          have byte1Bound := pe32ByteTreeValid_rvaByte_lt pe bytesValid byte1Result
          have byte2Bound := pe32ByteTreeValid_rvaByte_lt pe bytesValid byte2Result
          have byte3Bound := pe32ByteTreeValid_rvaByte_lt pe bytesValid byte3Result
          simp [byte0Read, byte1Result, byte2Result, byte3Result,
            littleEndianValue] at readChecked
          simp only [Memory.read32, memory0, memory1, memory2, memory3,
            BitVec.zeroExtend_eq_setWidth]
          rw [← readChecked]
          rw [fourBytesAssembleLittleEndian byte0 byte1 byte2 byte3
            byte0Bound byte1Bound byte2Bound byte3Bound]
          congr 1
          omega

def PE32ConsoleLaunchWorldV1.Valid (context : StaticProofContext)
    (world : RelationalWorld) : Prop :=
  world.valid context = true ∧
    world.stackRanges.length = 1 ∧
    world.dynamicRanges = [] ∧
    world.opaqueResources = [] ∧
    world.registeredCallbacks = [] ∧
    world.tlsState.lastError = BitVec.ofNat 32 0 ∧
    world.importAddressesStaticValid context = true ∧
    world.importAddressesComplete context = true

structure PE32ConsoleLaunchStateRel (context : StaticProofContext)
    (launch : PE32ConsoleLaunchV1) (world : RelationalWorld)
    (original candidate : MachineState) : Prop where
  worldValid : PE32ConsoleLaunchWorldV1.Valid context world
  originalImageMapped : PreferredBaseImageMemory context.originalPe
    context.originalImports original.memory
  candidateImageMapped : PreferredBaseImageMemory context.candidatePe
    context.candidateImports candidate.memory
  stateRel : StateRel context world launch.rootInvariant original candidate

def PE32ConsoleLaunchV1.Valid (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (launch : PE32ConsoleLaunchV1) : Prop :=
  PE32ConsoleEntrySurfacesValid context = true ∧
    PE32ConsoleLaunchV1.preEntryTlsAbsent context = true ∧
    ∃ node, graph.getNode? launch.rootNodeId = some node ∧
      node.targetId = launch.rootTargetId ∧ node.root = true ∧
      graph.rootNodeIds.contains launch.rootNodeId = true ∧
      invariants.nodeInvariants[launch.rootNodeId]? = some launch.rootInvariant ∧
      context.roots.contains {
        targetId := launch.rootTargetId
        kind := .entrypoint
      } = true ∧
      exactIdentityRegister invariants.terminalInvariant.registerRelations .eax = true ∧
      launch.rootInvariant.predicates.contains uninhabitedStatePredicate = false

def PE32ConsoleLaunchV1.StatesRelated (context : StaticProofContext)
    (launch : PE32ConsoleLaunchV1) (world : RelationalWorld)
    (original candidate : MachineState) : Prop :=
  PE32ConsoleLaunchStateRel context launch world original candidate

/-- A bounded PE32 console launch with the statically declared TLS callbacks
executed in image order before the entrypoint.  The callback sequence is
represented by ordinary checked runtime-call continuations, so callback bodies,
their internal calls, and their external observations use the same execution
and composition semantics as the rest of the program. -/
structure PE32ConsoleLaunchV2 where
  rootNodeId : Nat
  rootTargetId : Nat
  entryNodeId : Nat
  entryTargetId : Nat
  tlsCallbackNodeIds : List Nat
  tlsCallbackTargetIds : List Nat
  rootInvariant : StateInvariant
  frameOffsets : List ReturnSlotOffsetInventory
deriving Repr, DecidableEq

def PE32ConsoleLaunchV2.initialTargetId (launch : PE32ConsoleLaunchV2) : Nat :=
  launch.tlsCallbackTargetIds.head?.getD launch.entryTargetId

def PE32ConsoleLaunchV2.initialNodeId (launch : PE32ConsoleLaunchV2) : Nat :=
  launch.tlsCallbackNodeIds.head?.getD launch.entryNodeId

def PE32ConsoleLaunchV2.continuationTargetIds
    (launch : PE32ConsoleLaunchV2) : List Nat :=
  match launch.tlsCallbackTargetIds with
  | [] => []
  | _ :: callbacks => callbacks ++ [launch.entryTargetId]

def PE32ConsoleLaunchV2.callbackNodesValid (context : StaticProofContext)
    (graph : RelationalProductGraph) : List Nat -> List Nat -> Bool
  | [], [] => true
  | nodeId :: nodeIds, targetId :: targetIds =>
      match graph.getNode? nodeId with
      | none => false
      | some node =>
          node.targetId == targetId && node.root &&
            graph.rootNodeIds.contains nodeId &&
            context.roots.contains {
              targetId
              kind := .tlsInitializer
            } &&
            PE32ConsoleLaunchV2.callbackNodesValid context graph nodeIds targetIds
  | _, _ => false

def PE32ConsoleLaunchV2.initialFrameOffsetValid
    (launch : PE32ConsoleLaunchV2) : Bool :=
  match launch.tlsCallbackTargetIds, launch.frameOffsets with
  | [], [] => true
  | _ :: _, first :: _ => first.locations.contains ReturnSlotOffsetPair.zero
  | _, _ => false

def PE32ConsoleLaunchV2.Valid (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (launch : PE32ConsoleLaunchV2) : Prop :=
  PE32ConsoleEntrySurfacesValid context = true ∧
    launch.tlsCallbackTargetIds = context.tlsCallbackTargetIds ∧
    PE32ConsoleLaunchV2.callbackNodesValid context graph launch.tlsCallbackNodeIds
      launch.tlsCallbackTargetIds = true ∧
    launch.rootNodeId = launch.initialNodeId ∧
    launch.rootTargetId = launch.initialTargetId ∧
    launch.frameOffsets.length = launch.continuationTargetIds.length ∧
    launch.initialFrameOffsetValid = true ∧
    (∃ entryNode,
      graph.getNode? launch.entryNodeId = some entryNode ∧
        entryNode.targetId = launch.entryTargetId ∧ entryNode.root = true ∧
        graph.rootNodeIds.contains launch.entryNodeId = true ∧
        context.roots.contains {
          targetId := launch.entryTargetId
          kind := .entrypoint
        } = true) ∧
    (∃ rootNode,
      graph.getNode? launch.rootNodeId = some rootNode ∧
        rootNode.targetId = launch.rootTargetId ∧ rootNode.root = true ∧
        graph.rootNodeIds.contains launch.rootNodeId = true ∧
        invariants.nodeInvariants[launch.rootNodeId]? = some launch.rootInvariant) ∧
    exactIdentityRegister invariants.terminalInvariant.registerRelations .eax = true ∧
    launch.rootInvariant.predicates.contains uninhabitedStatePredicate = false

def PE32TlsProcessAttachArgumentsHold (context : StaticProofContext)
    (original candidate : MachineState) : List Nat ->
      List RelationalRuntimeCallFrame -> Prop
  | [], [] => True
  | _ :: targetIds, frame :: frames =>
      Memory.read32 original.memory
          (frame.originalStackAddress + BitVec.ofNat 32 4) =
            BitVec.ofNat 32 context.originalPe.imageBase ∧
        Memory.read32 candidate.memory
          (frame.candidateStackAddress + BitVec.ofNat 32 4) =
            BitVec.ofNat 32 context.candidatePe.imageBase ∧
        Memory.read32 original.memory
          (frame.originalStackAddress + BitVec.ofNat 32 8) = BitVec.ofNat 32 1 ∧
        Memory.read32 candidate.memory
          (frame.candidateStackAddress + BitVec.ofNat 32 8) = BitVec.ofNat 32 1 ∧
        Memory.read32 original.memory
          (frame.originalStackAddress + BitVec.ofNat 32 12) = BitVec.ofNat 32 0 ∧
        Memory.read32 candidate.memory
          (frame.candidateStackAddress + BitVec.ofNat 32 12) = BitVec.ofNat 32 0 ∧
        PE32TlsProcessAttachArgumentsHold context original candidate targetIds frames
  | _, _ => False

def PE32ConsoleLaunchStateRelV2 (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (launch : PE32ConsoleLaunchV2) (world : RelationalWorld)
    (original candidate : MachineState) : Prop :=
  ∃ frames : List RelationalRuntimeCallFrame,
    PE32ConsoleLaunchWorldV1.Valid context world ∧
      PreferredBaseImageMemory context.originalPe context.originalImports
        original.memory ∧
      PreferredBaseImageMemory context.candidatePe context.candidateImports
        candidate.memory ∧
      RelationalRuntimeCallStackHolds context original candidate frames
        launch.continuationTargetIds launch.frameOffsets ∧
      RelationalRuntimeCallFactsHold context world launch.frameOffsets
        original.registers candidate.registers ∧
      RelationalRuntimeCallTargetsMapped graph reachability
        launch.continuationTargetIds ∧
      PE32TlsProcessAttachArgumentsHold context original candidate
        launch.tlsCallbackTargetIds frames ∧
      StateRel context world launch.rootInvariant original candidate

def PE32ConsoleLaunchV2.StatesRelated (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (launch : PE32ConsoleLaunchV2) (world : RelationalWorld)
    (original candidate : MachineState) : Prop :=
  PE32ConsoleLaunchStateRelV2 context graph reachability launch world original candidate

/-- At least one concrete state pair must inhabit the launch relation.  This is
separate from structural launch validity so contradictory invariants cannot
make a whole-program theorem vacuous. -/
def PE32ConsoleLaunchV2.Realizable (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (launch : PE32ConsoleLaunchV2) : Prop :=
  exists world originalState candidateState,
    launch.StatesRelated context graph reachability world originalState candidateState

def PE32ProgramsObservationallyEquivalent (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (launch : PE32ConsoleLaunchV2)
    (original candidate : DecodedWorldProgram) : Prop :=
  launch.Realizable context graph reachability ∧
    exists executionRelation : WorldExecution -> WorldExecution -> Prop,
      (forall world originalState candidateState,
        launch.StatesRelated context graph reachability world originalState candidateState ->
        executionRelation
          (.running launch.rootTargetId originalState launch.continuationTargetIds 0 world)
          (.running launch.rootTargetId candidateState launch.continuationTargetIds 0 world)) ∧
      RelationalWeakBisimulation original.pe32TransitionSystem
        candidate.pe32TransitionSystem
        executionRelation (worldRelationalObservationsRelated context)

structure WholeProgramCertificate (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV2)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment) where
  imageBundle : ProofBundle
  executableImagesCovered : imageBundle.CoversStaticContext context regions
  originalCodeAliasesSemanticallyValid : context.codeMap.AliasesSemanticallyValid false
    context.originalPe context.originalImports
  candidateCodeAliasesSemanticallyValid : context.codeMap.AliasesSemanticallyValid true
    context.candidatePe context.candidateImports
  originalCodeAliasesInstructionSemanticallyValid :
    context.codeMap.AliasesInstructionSemanticallyValid false
      context.originalPe context.originalImports
  candidateCodeAliasesInstructionSemanticallyValid :
    context.codeMap.AliasesInstructionSemanticallyValid true
      context.candidatePe context.candidateImports
  staticContextValid : context.StructurallyValid
  productGraphValid : graph.IndexedValid context
  regionsUseCanonicalContext : RegionsUseStaticContext context regions
  regionsMatchProductGraph : RegionsMatchProductGraph context graph regions
  invariantTableValid : invariants.Valid graph
  callbackTargetsValid : callbackTargets.Valid graph reachability = true
  reachabilityClosed : reachability.SoundlyClosed context graph
  decodedControlComplete :
    ReachableProductNodesDecodedControlComplete context graph regions reachability
  reachableEdgesRefined : ReachableProductEdgesLocallyRefined context graph reachability
  reachableExecutionEdgesRefined :
    ReachableProductExecutionEdgesRefined context graph regions invariants reachability
  environmentsRefined : ExternalEnvironmentRefines context externalCallSites
    originalEnvironment candidateEnvironment
  protocolEnvironmentsRefined : WorldExternalProtocolEnvironmentsRefine context graph
    invariants reachability control callbackTargets externalCallSites
    originalProtocolEnvironment candidateProtocolEnvironment
  launchValid : launch.Valid context graph invariants
  launchRealizable : launch.Realizable context graph reachability
  launchControlAllowed : control.Allows launch.rootNodeId
    launch.continuationTargetIds launch.frameOffsets = true
  runningProductNodesRefined : ReachableRunningProductNodesRefined context graph
    invariants reachability control callbackTargets
    {
      candidate := false
      context
      regions
      externalCallSites
      environment := originalEnvironment
      protocolEnvironment := originalProtocolEnvironment
    }
    {
      candidate := true
      context
      regions
      externalCallSites
      environment := candidateEnvironment
      protocolEnvironment := candidateProtocolEnvironment
    }
  callbackRunningProductNodesRefined :
    ReachableCallbackRunningProductNodesRefined context graph invariants reachability
      control callbackTargets
      {
        candidate := false
        context
        regions
        externalCallSites
        environment := originalEnvironment
        protocolEnvironment := originalProtocolEnvironment
      }
      {
        candidate := true
        context
        regions
        externalCallSites
        environment := candidateEnvironment
        protocolEnvironment := candidateProtocolEnvironment
      }
  originalInstructionSemanticsAdequate :
    ({
      candidate := false
      context
      regions
      externalCallSites
      environment := originalEnvironment
      protocolEnvironment := originalProtocolEnvironment
    } : DecodedWorldProgram).InstructionSemanticsAdequate
  candidateInstructionSemanticsAdequate :
    ({
      candidate := true
      context
      regions
      externalCallSites
      environment := candidateEnvironment
      protocolEnvironment := candidateProtocolEnvironment
    } : DecodedWorldProgram).InstructionSemanticsAdequate

theorem pe32ProgramsEquivalent (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV2)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment)
    (certificate : WholeProgramCertificate context graph regions invariants reachability control
      callbackTargets externalCallSites launch originalEnvironment candidateEnvironment
      originalProtocolEnvironment candidateProtocolEnvironment) :
    PE32ProgramsObservationallyEquivalent context graph invariants reachability control launch
      {
        candidate := false
        context
        regions
        externalCallSites
        environment := originalEnvironment
        protocolEnvironment := originalProtocolEnvironment
      }
      {
        candidate := true
        context
        regions
        externalCallSites
        environment := candidateEnvironment
        protocolEnvironment := candidateProtocolEnvironment
      } := by
  let original : DecodedWorldProgram := {
    candidate := false
    context
    regions
    externalCallSites
    environment := originalEnvironment
    protocolEnvironment := originalProtocolEnvironment
  }
  let candidate : DecodedWorldProgram := {
    candidate := true
    context
    regions
    externalCallSites
    environment := candidateEnvironment
    protocolEnvironment := candidateProtocolEnvironment
  }
  refine ⟨certificate.launchRealizable,
    WorldExecutionsRelated context graph invariants reachability control
      callbackTargets externalCallSites, ?_, ?_⟩
  . intro world originalState candidateState related
    rcases related with
      ⟨frames, _worldValid, _originalImageMapped, _candidateImageMapped,
        stackHolds, frameImportsHold, frameTargetsReachable,
        _processAttachArgumentsHold, statesRelated⟩
    rcases certificate.launchValid.2.2.2.2.2.2.2.2.1 with
      ⟨node, nodeFound, targetFound, rootFound, rootListed, invariantFound⟩
    refine ⟨rfl, rfl, rfl, rfl, launch.rootNodeId, node,
      launch.rootInvariant, frames, launch.frameOffsets, nodeFound, targetFound, ?_,
      invariantFound, certificate.launchControlAllowed, stackHolds,
      frameImportsHold, frameTargetsReachable, statesRelated⟩
    . have allRoots := certificate.reachabilityClosed.2.1.2.1
      unfold RelationalProductReachabilityEvidence.rootsIncluded at allRoots
      exact List.all_eq_true.mp allRoots launch.rootNodeId
        (List.contains_iff_mem.mp rootListed)
  . exact productStepRefinement_of_reachable_nodes context graph invariants reachability
      control callbackTargets original candidate certificate.environmentsRefined
      certificate.protocolEnvironmentsRefined certificate.runningProductNodesRefined
      certificate.callbackRunningProductNodesRefined
      |> fun decodedBisimulation => by
        rw [original.pe32TransitionSystem_eq_transitionSystem
          certificate.originalInstructionSemanticsAdequate,
          candidate.pe32TransitionSystem_eq_transitionSystem
          certificate.candidateInstructionSemanticsAdequate]
        exact decodedBisimulation

def PE32ProgramsTraceRelated (context : StaticProofContext)
    (original candidate : DecodedWorldProgram)
    (executionRelation : WorldExecution -> WorldExecution -> Prop) :
    Nat -> WorldExecution -> WorldExecution -> Prop :=
  RelatedTrace original.pe32TransitionSystem candidate.pe32TransitionSystem
    executionRelation (worldRelationalObservationsRelated context)

theorem pe32ProgramsEquivalent_trace (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (launch : PE32ConsoleLaunchV2)
    (original candidate : DecodedWorldProgram)
    (equivalent : PE32ProgramsObservationallyEquivalent context graph invariants
      reachability control launch original candidate) :
    forall fuel world originalState candidateState,
      launch.StatesRelated context graph reachability world originalState candidateState ->
      exists executionRelation,
        PE32ProgramsTraceRelated context original candidate executionRelation fuel
          (.running launch.rootTargetId originalState launch.continuationTargetIds 0 world)
          (.running launch.rootTargetId candidateState launch.continuationTargetIds 0 world) := by
  rcases equivalent with ⟨_realizable, executionRelation, initial, bisimulation⟩
  intro fuel world originalState candidateState related
  refine ⟨executionRelation, ?_⟩
  exact relationalWeakBisimulation_trace original.pe32TransitionSystem
    candidate.pe32TransitionSystem executionRelation
    (worldRelationalObservationsRelated context) bisimulation fuel _ _
    (initial world originalState candidateState related)

theorem WholeProgramCertificate.launchStatesExist (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV2)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment)
    (certificate : WholeProgramCertificate context graph regions invariants reachability control
      callbackTargets externalCallSites launch originalEnvironment candidateEnvironment
      originalProtocolEnvironment candidateProtocolEnvironment) :
    exists world originalState candidateState,
      launch.StatesRelated context graph reachability world originalState candidateState :=
  certificate.launchRealizable

end StageA.Relational
