import StageA.RelationalCertificates
import StageA.RelationalCallableExternalExecution
import StageA.RelationalInterpreterKernel

namespace StageA.Relational.InterpreterNativeWorld

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.CallableExternalExecution
open StageA.Relational.InterpreterKernel

/-! # Exact native PE world execution

`DecodedWorldProgram` is indexed by the original/candidate product code map.
That is appropriate for structurally paired binaries, but not for a compiled
interpreter whose private dispatcher and helper blocks have no original-side
counterpart.  This module gives that candidate its own exact, raw-RVA
transition system.  Every native step still comes from
`stepKernelPE32Instruction` over the immutable candidate PE.

External calls are synchronous in the compatibility profile and remain observable.
Concrete indirect targets execute only when a checked per-site finite target
inventory permits the exact machine word and collision-aware classification
resolves it as candidate code, an import binding, or an opaque callable
resource.  Target-set completeness remains a separate composition obligation;
it cannot be inferred from one successful concrete resolution.

`ExactNestedNativeWorldProgram` is the callback-capable profile.  It introduces
an explicit external suspension and an authoritative stack of external callback
frames.  The ordinary machine call stack remains a flat list of exact return
addresses; external frames do not replace or reinterpret machine memory. -/

structure NativeWorldExternalCallbackAction where
  targetRva : Nat
  returnAddress : Word
  state : MachineState
  world : RelationalWorld

inductive NativeWorldExternalAction where
  | returned (result : WorldExternalResult)
  | callback (entry : NativeWorldExternalCallbackAction)
  | terminated (world : RelationalWorld)
  | blocked (reason : ExecutionBlock)

/-- Optional exact classifier and environment for opaque callable values.
The context binding is checked by the mixed certificate; an absent, invalid,
or ambiguous route remains proof-blocked. -/
structure NativeCallableExternalConfig where
  context : StaticProofContext
  capabilities : List CallableExternalCapability
  resolvedABIContracts : List ResolvedExternalABIContract
  environment : ResolvedExternalEnvironment

structure NativeCallableExternalConfig.BoundTo
    (config : NativeCallableExternalConfig) (pe : PE32)
    (imports : List PEImport) : Prop where
  peExact : config.context.candidatePe = pe
  importsExact : config.context.candidateImports = imports
  contextValid : config.context.StructurallyValid
  capabilityIds : callableCapabilityIdsUnique config.capabilities = true
  capabilityResourceIds :
    callableCapabilityResourceIdsUnique config.capabilities = true
  abiIds : resolvedExternalABIContractIdsUnique
    config.resolvedABIContracts = true
  abiRoutes : resolvedExternalABIRoutesUnique
    config.resolvedABIContracts = true
  abiShapes : config.resolvedABIContracts.all
    ResolvedExternalABIContract.shapeValid = true

inductive NativeIndirectTargetDescriptor where
  | internalRva (rva : Nat)
  | importBinding (bindingId : Nat)
  | callableResource (resourceId : Nat)
deriving Repr, DecidableEq

def NativeIndirectTargetDescriptor.resolve
    (pe : PE32) (world : RelationalWorld) :
    NativeIndirectTargetDescriptor -> Option Word
  | .internalRva rva =>
      if executableRva pe rva then
        some (BitVec.ofNat 32 (pe.imageBase + rva))
      else none
  | .importBinding bindingId => do
      let binding <- world.importAddresses.find? fun candidate =>
        candidate.id == bindingId
      some binding.candidateAddress
  | .callableResource resourceId => do
      let resource <- world.opaqueResources.find? fun candidate =>
        candidate.id == resourceId
      some resource.candidate

structure NativeIndirectTargetSet where
  sourceRva : Nat
  transfer : ResolvedExternalTransfer
  targets : List NativeIndirectTargetDescriptor
deriving Repr, DecidableEq

def NativeIndirectTargetSet.shapeValid
    (pe : PE32) (targetSet : NativeIndirectTargetSet) : Bool :=
  !targetSet.targets.isEmpty &&
    (targetSet.targets.all fun target =>
      (targetSet.targets.filter (· == target)).length == 1) &&
    targetSet.targets.all fun target =>
      match target with
      | .internalRva rva => executableRva pe rva
      | .importBinding _ | .callableResource _ => true

structure NativeIndirectTargetInventory where
  targetSets : List NativeIndirectTargetSet := []
deriving Repr, DecidableEq

def NativeIndirectTargetInventory.valid
    (pe : PE32) (inventory : NativeIndirectTargetInventory) : Bool :=
  inventory.targetSets.all fun targetSet =>
    targetSet.shapeValid pe &&
      (inventory.targetSets.filter fun other =>
        other.sourceRva == targetSet.sourceRva &&
          other.transfer == targetSet.transfer).length == 1

def NativeIndirectTargetInventory.targetSet?
    (inventory : NativeIndirectTargetInventory) (sourceRva : Nat)
    (transfer : ResolvedExternalTransfer) : Option NativeIndirectTargetSet :=
  match inventory.targetSets.filter fun targetSet =>
      targetSet.sourceRva == sourceRva && targetSet.transfer == transfer with
  | [targetSet] => some targetSet
  | _ => none

def NativeIndirectTargetInventory.allows
    (inventory : NativeIndirectTargetInventory) (pe : PE32)
    (world : RelationalWorld) (sourceRva : Nat)
    (transfer : ResolvedExternalTransfer) (target : Word) : Bool :=
  match inventory.targetSet? sourceRva transfer with
  | none => false
  | some targetSet =>
      (targetSet.targets.filter fun descriptor =>
        descriptor.resolve pe world == some target).length == 1

structure NativeWorldEnvironment where
  action : Nat -> NativeExternalEvent -> RelationalWorld ->
    NativeWorldExternalAction

inductive NativeWorldExecution where
  | running (rva undefinedSlot : Nat) (state : MachineState)
      (calls : List NativeCallFrame) (eventIndex : Nat)
      (events : List NativeExternalEvent) (world : RelationalWorld)
  | returned (state : MachineState) (events : List NativeExternalEvent)
      (world : RelationalWorld)
  | terminated (events : List NativeExternalEvent) (world : RelationalWorld)
  | fault (cause : ModeledFault)
  | blocked (reason : ExecutionBlock)

def blockedNativeWorldTransition (reason : ExecutionBlock) :
    RelatedTransition NativeWorldExecution WorldRelationalObservable :=
  { next := .blocked reason, observation := some (.proofBlocked reason) }

def NativeWorldExecution.rva? : NativeWorldExecution -> Option Nat
  | .running rva .. => some rva
  | _ => none

def NativeWorldExecution.machine? : NativeWorldExecution -> Option MachineState
  | .running _ _ state .. | .returned state .. => some state
  | _ => none

def applyNativeWorldExternalAction (continuation : Nat)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (event : NativeExternalEvent)
    (world : RelationalWorld) (action : NativeWorldExternalAction) :
    RelatedTransition NativeWorldExecution WorldRelationalObservable :=
  let observation : WorldRelationalObservable :=
    .external world (normalizeImport event.imported) event.arguments
  match action with
  | .returned result =>
      { next := .running continuation 0 result.state calls (eventIndex + 1)
          (events ++ [event]) result.world,
        observation := some observation }
  | .terminated successorWorld =>
      { next := .terminated (events ++ [event]) successorWorld,
        observation := some observation }
  | .callback _ => blockedNativeWorldTransition .missingRuntimeContinuation
  | .blocked reason => blockedNativeWorldTransition reason

def applyNativeWorldExternalTailAction
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (event : NativeExternalEvent)
    (world : RelationalWorld) (action : NativeWorldExternalAction) :
    RelatedTransition NativeWorldExecution WorldRelationalObservable :=
  let observation : WorldRelationalObservable :=
    .external world (normalizeImport event.imported) event.arguments
  match action with
  | .returned result =>
      match calls with
      | [] =>
          { next := .returned result.state (events ++ [event]) result.world,
            observation := some observation }
      | frame :: tail =>
          { next := .running frame.continuationRva 0 result.state tail
              (eventIndex + 1) (events ++ [event]) result.world,
            observation := some observation }
  | .terminated successorWorld =>
      { next := .terminated (events ++ [event]) successorWorld,
        observation := some observation }
  | .callback _ => blockedNativeWorldTransition .missingRuntimeContinuation
  | .blocked reason => blockedNativeWorldTransition reason

def nativeCandidateExecutableMatches (pe : PE32) (target : Word) : List Nat :=
  let absolute := target.toNat
  if absolute < pe.imageBase || pe.imageBase + pe.sizeOfImage <= absolute then
    []
  else
    let rva := absolute - pe.imageBase
    if executableRva pe rva then [rva] else []

def nativeCandidateImportMatches
    (world : RelationalWorld) (target : Word) : List ImportAddressPair :=
  world.importAddresses.filter fun binding =>
    binding.candidateAddress == target

def nativeCandidateResourceMatches
    (world : RelationalWorld) (target : Word) : List OpaqueResourcePair :=
  world.opaqueResources.filter fun resource => resource.candidate == target

/-- Collision-aware native indirect classification. Executable image
addresses, IAT bindings, and opaque callable resources are considered in one
decision, so no category can silently shadow another. -/
def resolveNativeCallableIndirect (pe : PE32)
    (config : NativeCallableExternalConfig) (world : RelationalWorld)
    (target : Word) (transfer : ResolvedExternalTransfer) :
    OriginalIndirectResolution :=
  if callableExternalWorldValid config.context world != true then
    .invalidWorld
  else
    classifyOriginalIndirectMatches
      (nativeCandidateExecutableMatches pe target)
      (nativeCandidateImportMatches world target)
      (nativeCandidateResourceMatches world target)
      config.capabilities config.resolvedABIContracts transfer

def nativePEImportForBinding (binding : ImportAddressPair) : PEImport := {
  dll := binding.imported.dll
  name := binding.imported.name
  iatRva := binding.candidateIatRva
}

def applyNativeWorldResolvedCallableCall
    (config : NativeCallableExternalConfig)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (target : Word) (continuation : Nat) (state : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) :
    RelatedTransition NativeWorldExecution WorldRelationalObservable :=
  let arguments := abi.argumentSources.map fun source => source.eval state
  let event : ResolvedExternalEvent := {
    capabilityId := capability.id
    resourceId := capability.resourceId
    abiContractId := abi.id
    transfer := .call
    target
    arguments
    state
    world
  }
  let result := config.environment.result eventIndex event
  let observation : CallableExternalObservation := {
    globalExternalIndex := eventIndex
    identity := .resolved capability.id capability.resourceId abi.id .call
    arguments
    world
  }
  { next := .running continuation 0 result.state calls (eventIndex + 1)
      events result.world,
    observation := some (.callableExternal observation) }

def applyNativeWorldResolvedCallableTail
    (config : NativeCallableExternalConfig)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (target : Word) (state : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) :
    RelatedTransition NativeWorldExecution WorldRelationalObservable :=
  match calls with
  | [] => blockedNativeWorldTransition .missingRuntimeContinuation
  | frame :: tail =>
      let arguments := abi.argumentSources.map fun source => source.eval state
      let event : ResolvedExternalEvent := {
        capabilityId := capability.id
        resourceId := capability.resourceId
        abiContractId := abi.id
        transfer := .jump
        target
        arguments
        state
        world
      }
      let result := config.environment.result eventIndex event
      let observation : CallableExternalObservation := {
        globalExternalIndex := eventIndex
        identity := .resolved capability.id capability.resourceId abi.id .jump
        arguments
        world
      }
      { next := .running frame.continuationRva 0 result.state tail
          (eventIndex + 1) events result.world,
        observation := some (.callableExternal observation) }

/-- Resolve a concrete indirect machine word only when it denotes an address
inside an executable section of the exact candidate image.  Completeness of
the permitted target set is proved separately by the composition certificate. -/
def exactNativeIndirectTargetRva? (pe : PE32) (target : Word) : Option Nat := do
  let absolute := target.toNat
  if absolute < pe.imageBase || pe.imageBase + pe.sizeOfImage <= absolute then
    none
  else
    let rva := absolute - pe.imageBase
    if executableRva pe rva then some rva else none

def transitionFromNativeWorldOutcome (pe : PE32)
    (environment : NativeWorldEnvironment)
    (callableExternal : Option NativeCallableExternalConfig)
    (indirectTargets : NativeIndirectTargetInventory)
    (sourceRva : Nat) (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) : ConcreteOutcome ->
      RelatedTransition NativeWorldExecution WorldRelationalObservable
  | .returned target =>
      match calls with
      | [] =>
          { next := .returned state events world,
            observation := some (.returned world state.registers.eax) }
      | frame :: tail =>
          if target == frame.returnAddress then
            { next := .running frame.continuationRva 0 state tail eventIndex
                events world,
              observation := none }
          else
            blockedNativeWorldTransition
              (.invalidNativeReturn target frame.returnAddress)
  | .jump target =>
      { next := .running target 0 state calls eventIndex events world,
        observation := none }
  | .branch condition taken fallthrough =>
      { next := .running (if condition then taken else fallthrough) 0 state
          calls eventIndex events world,
        observation := none }
  | .call target continuation returnAddress =>
      { next := .running target 0 state
          ({ continuationRva := continuation,
             returnAddress := BitVec.ofNat 32 returnAddress } :: calls)
          eventIndex events world,
        observation := none }
  | .externalCall imported arguments continuation =>
      let event : NativeExternalEvent := { imported, arguments, state }
      applyNativeWorldExternalAction continuation calls eventIndex events event
        world (environment.action eventIndex event world)
  | .externalJump imported arguments =>
      let event : NativeExternalEvent := { imported, arguments, state }
      applyNativeWorldExternalTailAction calls eventIndex events event world
        (environment.action eventIndex event world)
  | .bulkCopy destination source count direction continuation =>
      let memory := Memory.bulkCopyDwords state.memory destination source direction
        count.toNat
      { next := .running continuation 0 { state with memory } calls eventIndex
          events world,
        observation := none }
  | .checkedContinue valid continuation =>
      if valid then
        { next := .running continuation 0 state calls eventIndex events world,
          observation := none }
      else
        { next := .fault .checkedContinue,
          observation := some (.fault .checkedContinue) }
  | .atomicCompareExchange address expected replacement continuation =>
      let memory := Memory.atomicCompareExchange state.memory address expected
        replacement
      { next := .running continuation 0 { state with memory } calls eventIndex
          events world,
        observation := none }
  | .indirectCall target continuation returnAddress =>
      if indirectTargets.allows pe world sourceRva .call target != true then
        blockedNativeWorldTransition
          (.missingNativeIndirectTargetSet sourceRva target)
      else match callableExternal with
      | none =>
          match exactNativeIndirectTargetRva? pe target with
          | none => blockedNativeWorldTransition (.unmappedIndirectControl target)
          | some targetRva =>
              { next := .running targetRva 0 state
                  ({ continuationRva := continuation,
                     returnAddress := BitVec.ofNat 32 returnAddress } :: calls)
                  eventIndex events world,
                observation := none }
      | some config =>
          match resolveNativeCallableIndirect pe config world target .call with
          | .internal targetRva =>
              { next := .running targetRva 0 state
                  ({ continuationRva := continuation,
                     returnAddress := BitVec.ofNat 32 returnAddress } :: calls)
                  eventIndex events world,
                observation := none }
          | .imported binding =>
              match resolveWorldImportCall true config.context world target state with
              | none => blockedNativeWorldTransition
                  (.callableExternalUnavailable sourceRva target)
              | some (_imported, arguments) =>
                  let imported := nativePEImportForBinding binding
                  let event : NativeExternalEvent := { imported, arguments, state }
                  applyNativeWorldExternalAction continuation calls eventIndex events
                    event world (environment.action eventIndex event world)
          | .callable capability abi _resource =>
              applyNativeWorldResolvedCallableCall config capability abi target
                continuation state calls eventIndex events world
          | .invalidWorld | .unmapped | .invalidCallable | .ambiguous =>
              blockedNativeWorldTransition
                (.callableExternalUnavailable sourceRva target)
  | .indirectJump target =>
      if indirectTargets.allows pe world sourceRva .jump target != true then
        blockedNativeWorldTransition
          (.missingNativeIndirectTargetSet sourceRva target)
      else match callableExternal with
      | none =>
          match exactNativeIndirectTargetRva? pe target with
          | none => blockedNativeWorldTransition (.unmappedIndirectControl target)
          | some targetRva =>
              { next := .running targetRva 0 state calls eventIndex events world,
                observation := none }
      | some config =>
          match resolveNativeCallableIndirect pe config world target .jump with
          | .internal targetRva =>
              { next := .running targetRva 0 state calls eventIndex events world,
                observation := none }
          | .imported binding =>
              match resolveWorldImportCall true config.context world target state with
              | none => blockedNativeWorldTransition
                  (.callableExternalUnavailable sourceRva target)
              | some (_imported, arguments) =>
                  let imported := nativePEImportForBinding binding
                  let event : NativeExternalEvent := { imported, arguments, state }
                  applyNativeWorldExternalTailAction calls eventIndex events event world
                    (environment.action eventIndex event world)
          | .callable capability abi _resource =>
              applyNativeWorldResolvedCallableTail config capability abi target state
                calls eventIndex events world
          | .invalidWorld | .unmapped | .invalidCallable | .ambiguous =>
              blockedNativeWorldTransition
                (.callableExternalUnavailable sourceRva target)

/-- One exact candidate instruction step.  A decoder/executor fault without a
reviewed architectural fault class is a proof frontier, not a modeled fault. -/
def stepPE32NativeWorldExecution (pe : PE32) (imports : List PEImport)
    (environment : NativeWorldEnvironment)
    (callableExternal : Option NativeCallableExternalConfig := none)
    (indirectTargets : NativeIndirectTargetInventory := {}) :
    NativeWorldExecution ->
      RelatedTransition NativeWorldExecution WorldRelationalObservable
  | .running rva undefinedSlot state calls eventIndex events world =>
      match stepKernelPE32Instruction pe imports
          (.running rva undefinedSlot state) with
      | .running nextRva nextSlot nextState =>
          { next := .running nextRva nextSlot nextState calls eventIndex events
              world,
            observation := none }
      | .stopped outcome nextState =>
          transitionFromNativeWorldOutcome pe environment callableExternal
            indirectTargets rva nextState calls
            eventIndex events world outcome
      | .fault => blockedNativeWorldTransition (.unclassifiedNativeFault rva)
  | terminal@(.returned ..) => { next := terminal, observation := none }
  | terminal@(.terminated ..) => { next := terminal, observation := none }
  | terminal@(.fault ..) => { next := terminal, observation := none }
  | terminal@(.blocked ..) => { next := terminal, observation := none }

structure ExactNativeWorldProgram where
  pe : PE32
  imports : List PEImport
  environment : NativeWorldEnvironment
  callableExternal : Option NativeCallableExternalConfig := none
  indirectTargets : NativeIndirectTargetInventory := {}

def ExactNativeWorldProgram.transitionSystem (program : ExactNativeWorldProgram) :
    RelatedTransitionSystem NativeWorldExecution WorldRelationalObservable := {
  step := stepPE32NativeWorldExecution program.pe program.imports
    program.environment program.callableExternal program.indirectTargets
}

def NativeWorldDispatches (program : ExactNativeWorldProgram)
    (entryRva : Nat) (before : MachineState) (world : RelationalWorld)
    (after : MachineState) (events : List NativeExternalEvent)
    (afterWorld : RelationalWorld)
    (observations : List WorldRelationalObservable) : Prop :=
  NonemptyRelatedPath program.transitionSystem
    (.running entryRva 0 before [] 0 [] world) observations
    (.returned after events afterWorld)

theorem exactNativeWorldStepIsNonempty (program : ExactNativeWorldProgram)
    (before : NativeWorldExecution) :
    NonemptyRelatedPath program.transitionSystem before
      (program.transitionSystem.step before).observation.toList
      (program.transitionSystem.step before).next :=
  nonemptyRelatedPath_one program.transitionSystem before

#print axioms exactNativeWorldStepIsNonempty

/-! ## Nested external callbacks

The callback-capable semantics deliberately use a separate execution carrier.
This keeps the original synchronous profile fail closed while making the
external suspension, its phase, and every nested callback frame explicit. -/

structure NativeWorldExternalRequest where
  eventIndex : Nat
  phaseIndex : Nat
  event : NativeExternalEvent
  state : MachineState
  world : RelationalWorld

structure NativeWorldExternalSuspension where
  continuationRva : Nat
  calls : List NativeCallFrame
  eventIndex : Nat
  phaseIndex : Nat
  event : NativeExternalEvent
  state : MachineState
  events : List NativeExternalEvent
  world : RelationalWorld

def NativeWorldExternalSuspension.request
    (suspension : NativeWorldExternalSuspension) : NativeWorldExternalRequest := {
  eventIndex := suspension.eventIndex
  phaseIndex := suspension.phaseIndex
  event := suspension.event
  state := suspension.state
  world := suspension.world
}

structure NativeWorldExternalCallbackRuntime where
  suspension : NativeWorldExternalSuspension
  entry : NativeWorldExternalCallbackAction

inductive NestedNativeWorldExecution where
  | running (rva undefinedSlot : Nat) (state : MachineState)
      (calls : List NativeCallFrame) (eventIndex : Nat)
      (events : List NativeExternalEvent) (world : RelationalWorld)
      (externalFrames : List NativeWorldExternalCallbackRuntime)
  | awaitingExternal (suspension : NativeWorldExternalSuspension)
      (externalFrames : List NativeWorldExternalCallbackRuntime)
  | returned (state : MachineState) (events : List NativeExternalEvent)
      (world : RelationalWorld)
  | terminated (events : List NativeExternalEvent) (world : RelationalWorld)
  | fault (cause : ModeledFault)
  | blocked (reason : ExecutionBlock)

def NestedNativeWorldExecution.rva? : NestedNativeWorldExecution -> Option Nat
  | .running rva .. => some rva
  | _ => none

def NestedNativeWorldExecution.machine? :
    NestedNativeWorldExecution -> Option MachineState
  | .running _ _ state .. | .returned state .. => some state
  | .awaitingExternal suspension _ => some suspension.state
  | _ => none

def NestedNativeWorldExecution.world? :
    NestedNativeWorldExecution -> Option RelationalWorld
  | .running _ _ _ _ _ _ world _ | .returned _ _ world |
      .terminated _ world => some world
  | .awaitingExternal suspension _ => some suspension.world
  | .fault _ | .blocked _ => none

structure ExactNestedNativeWorldProgram extends ExactNativeWorldProgram where
  callbackTargetRvas : List Nat
  protocolAction : NativeWorldExternalRequest -> NativeWorldExternalAction

def ExactNestedNativeWorldProgram.base
    (program : ExactNestedNativeWorldProgram) : ExactNativeWorldProgram :=
  program.toExactNativeWorldProgram

def nestedNativeCallbackTargetAllowed
    (program : ExactNestedNativeWorldProgram) (targetRva : Nat) : Bool :=
  targetRva ∈ program.callbackTargetRvas && executableRva program.pe targetRva

def blockedNestedNativeWorldTransition (reason : ExecutionBlock) :
    RelatedTransition NestedNativeWorldExecution WorldRelationalObservable :=
  { next := .blocked reason, observation := some (.proofBlocked reason) }

def resumeNestedNativeWorldExecution
    (suspension : NativeWorldExternalSuspension)
    (externalFrames : List NativeWorldExternalCallbackRuntime)
    (result : WorldExternalResult) : NestedNativeWorldExecution :=
  .running suspension.continuationRva 0 result.state suspension.calls
    (suspension.eventIndex + 1) suspension.events result.world externalFrames

def applyNestedNativeWorldExternalAction
    (program : ExactNestedNativeWorldProgram)
    (suspension : NativeWorldExternalSuspension)
    (externalFrames : List NativeWorldExternalCallbackRuntime)
    (action : NativeWorldExternalAction) :
    RelatedTransition NestedNativeWorldExecution WorldRelationalObservable :=
  match action with
  | .returned result =>
      { next := resumeNestedNativeWorldExecution suspension externalFrames result,
        observation := none }
  | .callback entry =>
      if nestedNativeCallbackTargetAllowed program entry.targetRva then
        { next := .running entry.targetRva 0 entry.state [] suspension.eventIndex
            suspension.events entry.world ({ suspension, entry } :: externalFrames),
          observation := some (.callback entry.world entry.targetRva) }
      else
        blockedNestedNativeWorldTransition
          (.unmappedIndirectControl
            (BitVec.ofNat 32 (program.pe.imageBase + entry.targetRva)))
  | .terminated successorWorld =>
      { next := .terminated suspension.events successorWorld,
        observation := none }
  | .blocked reason => blockedNestedNativeWorldTransition reason

def suspendNestedNativeWorldExternalCall (continuation : Nat)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (event : NativeExternalEvent)
    (world : RelationalWorld)
    (externalFrames : List NativeWorldExternalCallbackRuntime) :
    RelatedTransition NestedNativeWorldExecution WorldRelationalObservable :=
  let suspension : NativeWorldExternalSuspension := {
    continuationRva := continuation
    calls
    eventIndex
    phaseIndex := 0
    event
    state := event.state
    events := events ++ [event]
    world
  }
  { next := .awaitingExternal suspension externalFrames,
    observation := some
      (.external world (normalizeImport event.imported) event.arguments) }

def suspendNestedNativeWorldExternalTailCall
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (event : NativeExternalEvent)
    (world : RelationalWorld)
    (externalFrames : List NativeWorldExternalCallbackRuntime) :
    RelatedTransition NestedNativeWorldExecution WorldRelationalObservable :=
  match calls with
  | [] => blockedNestedNativeWorldTransition .missingRuntimeContinuation
  | frame :: tail =>
      suspendNestedNativeWorldExternalCall frame.continuationRva tail eventIndex
        events event world externalFrames

def applyNestedNativeResolvedCallableCall
    (config : NativeCallableExternalConfig)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (target : Word) (continuation : Nat) (state : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld)
    (externalFrames : List NativeWorldExternalCallbackRuntime) :
    RelatedTransition NestedNativeWorldExecution WorldRelationalObservable :=
  let arguments := abi.argumentSources.map fun source => source.eval state
  let event : ResolvedExternalEvent := {
    capabilityId := capability.id
    resourceId := capability.resourceId
    abiContractId := abi.id
    transfer := .call
    target
    arguments
    state
    world
  }
  let result := config.environment.result eventIndex event
  let observation : CallableExternalObservation := {
    globalExternalIndex := eventIndex
    identity := .resolved capability.id capability.resourceId abi.id .call
    arguments
    world
  }
  { next := .running continuation 0 result.state calls (eventIndex + 1) events
      result.world externalFrames,
    observation := some (.callableExternal observation) }

def applyNestedNativeResolvedCallableTail
    (config : NativeCallableExternalConfig)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (target : Word) (state : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld)
    (externalFrames : List NativeWorldExternalCallbackRuntime) :
    RelatedTransition NestedNativeWorldExecution WorldRelationalObservable :=
  match calls with
  | [] => blockedNestedNativeWorldTransition .missingRuntimeContinuation
  | frame :: tail =>
      let arguments := abi.argumentSources.map fun source => source.eval state
      let event : ResolvedExternalEvent := {
        capabilityId := capability.id
        resourceId := capability.resourceId
        abiContractId := abi.id
        transfer := .jump
        target
        arguments
        state
        world
      }
      let result := config.environment.result eventIndex event
      let observation : CallableExternalObservation := {
        globalExternalIndex := eventIndex
        identity := .resolved capability.id capability.resourceId abi.id .jump
        arguments
        world
      }
      { next := .running frame.continuationRva 0 result.state tail
          (eventIndex + 1) events result.world externalFrames,
        observation := some (.callableExternal observation) }

def transitionFromNestedNativeWorldOutcome
    (program : ExactNestedNativeWorldProgram)
    (sourceRva : Nat) (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (externalFrames : List NativeWorldExternalCallbackRuntime) : ConcreteOutcome ->
      RelatedTransition NestedNativeWorldExecution WorldRelationalObservable
  | .returned target =>
      match calls with
      | frame :: tail =>
          if target == frame.returnAddress then
            { next := .running frame.continuationRva 0 state tail eventIndex events
                world externalFrames,
              observation := none }
          else
            blockedNestedNativeWorldTransition
              (.invalidNativeReturn target frame.returnAddress)
      | [] =>
          match externalFrames with
          | [] =>
              { next := .returned state events world,
                observation := some (.returned world state.registers.eax) }
          | frame :: tail =>
              if target == frame.entry.returnAddress then
                { next := .awaitingExternal {
                    frame.suspension with
                    phaseIndex := frame.suspension.phaseIndex + 1
                    state
                    events
                    world
                  } tail,
                  observation := none }
              else
                blockedNestedNativeWorldTransition
                  (.invalidCallbackReturn target frame.entry.returnAddress)
  | .jump target =>
      { next := .running target 0 state calls eventIndex events world externalFrames,
        observation := none }
  | .branch condition taken fallthrough =>
      { next := .running (if condition then taken else fallthrough) 0 state calls
          eventIndex events world externalFrames,
        observation := none }
  | .call target continuation returnAddress =>
      { next := .running target 0 state
          ({ continuationRva := continuation,
             returnAddress := BitVec.ofNat 32 returnAddress } :: calls)
          eventIndex events world externalFrames,
        observation := none }
  | .externalCall imported arguments continuation =>
      let event : NativeExternalEvent := { imported, arguments, state }
      suspendNestedNativeWorldExternalCall continuation calls eventIndex events
        event world externalFrames
  | .externalJump imported arguments =>
      let event : NativeExternalEvent := { imported, arguments, state }
      suspendNestedNativeWorldExternalTailCall calls eventIndex events event world
        externalFrames
  | .bulkCopy destination source count direction continuation =>
      let memory := Memory.bulkCopyDwords state.memory destination source direction
        count.toNat
      { next := .running continuation 0 { state with memory } calls eventIndex
          events world externalFrames,
        observation := none }
  | .checkedContinue valid continuation =>
      if valid then
        { next := .running continuation 0 state calls eventIndex events world
            externalFrames,
          observation := none }
      else
        { next := .fault .checkedContinue,
          observation := some (.fault .checkedContinue) }
  | .atomicCompareExchange address expected replacement continuation =>
      let memory := Memory.atomicCompareExchange state.memory address expected
        replacement
      { next := .running continuation 0 { state with memory } calls eventIndex
          events world externalFrames,
        observation := none }
  | .indirectCall target continuation returnAddress =>
      if program.indirectTargets.allows program.pe world sourceRva .call
          target != true then
        blockedNestedNativeWorldTransition
          (.missingNativeIndirectTargetSet sourceRva target)
      else match program.callableExternal with
      | none =>
          match exactNativeIndirectTargetRva? program.pe target with
          | none => blockedNestedNativeWorldTransition
              (.unmappedIndirectControl target)
          | some targetRva =>
              { next := .running targetRva 0 state
                  ({ continuationRva := continuation,
                     returnAddress := BitVec.ofNat 32 returnAddress } :: calls)
                  eventIndex events world externalFrames,
                observation := none }
      | some config =>
          match resolveNativeCallableIndirect program.pe config world target
              .call with
          | .internal targetRva =>
              { next := .running targetRva 0 state
                  ({ continuationRva := continuation,
                     returnAddress := BitVec.ofNat 32 returnAddress } :: calls)
                  eventIndex events world externalFrames,
                observation := none }
          | .imported binding =>
              match resolveWorldImportCall true config.context world target state with
              | none => blockedNestedNativeWorldTransition
                  (.callableExternalUnavailable sourceRva target)
              | some (_imported, arguments) =>
                  let nativeImport := nativePEImportForBinding binding
                  let event : NativeExternalEvent := {
                    imported := nativeImport
                    arguments
                    state
                  }
                  suspendNestedNativeWorldExternalCall continuation calls eventIndex
                    events event world externalFrames
          | .callable capability abi _resource =>
              applyNestedNativeResolvedCallableCall config capability abi target
                continuation state calls eventIndex events world externalFrames
          | .invalidWorld | .unmapped | .invalidCallable | .ambiguous =>
              blockedNestedNativeWorldTransition
                (.callableExternalUnavailable sourceRva target)
  | .indirectJump target =>
      if program.indirectTargets.allows program.pe world sourceRva .jump
          target != true then
        blockedNestedNativeWorldTransition
          (.missingNativeIndirectTargetSet sourceRva target)
      else match program.callableExternal with
      | none =>
          match exactNativeIndirectTargetRva? program.pe target with
          | none => blockedNestedNativeWorldTransition
              (.unmappedIndirectControl target)
          | some targetRva =>
              { next := .running targetRva 0 state calls eventIndex events world
                  externalFrames,
                observation := none }
      | some config =>
          match resolveNativeCallableIndirect program.pe config world target
              .jump with
          | .internal targetRva =>
              { next := .running targetRva 0 state calls eventIndex events world
                  externalFrames,
                observation := none }
          | .imported binding =>
              match resolveWorldImportCall true config.context world target state with
              | none => blockedNestedNativeWorldTransition
                  (.callableExternalUnavailable sourceRva target)
              | some (_imported, arguments) =>
                  let nativeImport := nativePEImportForBinding binding
                  let event : NativeExternalEvent := {
                    imported := nativeImport
                    arguments
                    state
                  }
                  suspendNestedNativeWorldExternalTailCall calls eventIndex events
                    event world externalFrames
          | .callable capability abi _resource =>
              applyNestedNativeResolvedCallableTail config capability abi target
                state calls eventIndex events world externalFrames
          | .invalidWorld | .unmapped | .invalidCallable | .ambiguous =>
              blockedNestedNativeWorldTransition
                (.callableExternalUnavailable sourceRva target)

def stepPE32NestedNativeWorldExecution
    (program : ExactNestedNativeWorldProgram) : NestedNativeWorldExecution ->
      RelatedTransition NestedNativeWorldExecution WorldRelationalObservable
  | .running rva undefinedSlot state calls eventIndex events world externalFrames =>
      match stepKernelPE32Instruction program.pe program.imports
          (.running rva undefinedSlot state) with
      | .running nextRva nextSlot nextState =>
          { next := .running nextRva nextSlot nextState calls eventIndex events
              world externalFrames,
            observation := none }
      | .stopped outcome nextState =>
          transitionFromNestedNativeWorldOutcome program rva nextState calls
            eventIndex events world externalFrames outcome
      | .fault => blockedNestedNativeWorldTransition (.unclassifiedNativeFault rva)
  | .awaitingExternal suspension externalFrames =>
      applyNestedNativeWorldExternalAction program suspension externalFrames
        (program.protocolAction suspension.request)
  | terminal@(.returned ..) => { next := terminal, observation := none }
  | terminal@(.terminated ..) => { next := terminal, observation := none }
  | terminal@(.fault ..) => { next := terminal, observation := none }
  | terminal@(.blocked ..) => { next := terminal, observation := none }

def ExactNestedNativeWorldProgram.transitionSystem
    (program : ExactNestedNativeWorldProgram) :
    RelatedTransitionSystem NestedNativeWorldExecution WorldRelationalObservable := {
  step := stepPE32NestedNativeWorldExecution program
}

theorem exactNestedNativeWorldStepIsNonempty
    (program : ExactNestedNativeWorldProgram)
    (before : NestedNativeWorldExecution) :
    NonemptyRelatedPath program.transitionSystem before
      (program.transitionSystem.step before).observation.toList
      (program.transitionSystem.step before).next :=
  nonemptyRelatedPath_one program.transitionSystem before

theorem nestedNativeCallbackReturnUnwinds
    (program : ExactNestedNativeWorldProgram)
    (sourceRva undefinedSlot : Nat) (before after : MachineState)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) (frame : NativeWorldExternalCallbackRuntime)
    (tail : List NativeWorldExternalCallbackRuntime)
    (decoded : stepKernelPE32Instruction program.pe program.imports
      (.running sourceRva undefinedSlot before) =
        .stopped (.returned frame.entry.returnAddress) after) :
    program.transitionSystem.step
        (.running sourceRva undefinedSlot before [] eventIndex events world
          (frame :: tail)) = {
      next := .awaitingExternal {
        frame.suspension with
        phaseIndex := frame.suspension.phaseIndex + 1
        state := after
        events
        world
      } tail
      observation := none
    } := by
  simp [ExactNestedNativeWorldProgram.transitionSystem,
    stepPE32NestedNativeWorldExecution, decoded,
    transitionFromNestedNativeWorldOutcome]

#print axioms exactNestedNativeWorldStepIsNonempty

end StageA.Relational.InterpreterNativeWorld
