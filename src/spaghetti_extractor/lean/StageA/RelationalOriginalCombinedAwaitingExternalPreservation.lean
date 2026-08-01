import StageA.RelationalOriginalCombinedTargetStepIndex

namespace StageA.Relational.OriginalCombinedAwaitingExternalPreservation

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.OriginalValueFlowExecutionInvariant
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.SourceWorld
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition

/-!
# Combined external-response preservation

This module turns explicit machine-level protocol response evidence into the
external preservation certificate consumed by the combined original execution
invariant.  Returned calls, callback entries, and termination have separate,
cacheable evidence records.  No response is admitted from an environment
status or from an unclassified world mutation.

An awaiting state is created by a `.protocol` machine contract.  Its eventual
return is checked with the same ABI, footprint, and world-effect contract after
projecting only the disposition to `.returns`; this permits reuse of the
existing machine-result and static-word frame theorems without treating the
initiating protocol call as an ordinary synchronous return.
-/

/-- The response phase of a protocol call has the initiating contract's exact
machine effects and a returning disposition. -/
def protocolReturnContract
    (contract : MachineImportCallContract) : MachineImportCallContract :=
  { contract with disposition := .returns }

@[simp]
theorem protocolReturnContract_disposition
    (contract : MachineImportCallContract) :
    (protocolReturnContract contract).disposition = .returns :=
  rfl

/-- Exact static binding of an awaiting execution to one checked protocol
contract.  The redundant suspension fields are all tied back to the canonical
site, event, and machine-contract indexes. -/
structure CheckedOriginalMachineProtocolBoundary
    (program : DecodedWorldProgram)
    (suspension : WorldExternalSuspension)
    (contract : MachineImportCallContract) : Prop where
  siteMember : suspension.site ∈ program.externalCallSites
  siteIdExact : suspension.site.id = suspension.siteId
  sourceTargetExact :
    suspension.site.sourceTargetId = suspension.sourceTargetId
  continuationTargetExact :
    suspension.site.continuationTargetId = suspension.continuationTargetId
  contractExact :
    resolvedExternalCallContract? program.context program.externalCallSites
        suspension.siteId = some contract
  importedExact : contract.imported = suspension.imported
  protocolDisposition : contract.disposition = .protocol
  eventSiteExact : suspension.event.siteId = suspension.siteId
  eventImportExact : suspension.event.imported = suspension.imported
  eventArgumentsExact : suspension.event.arguments = suspension.arguments

/-- One-sided callback entry framing.  It is the original-machine projection
of the well-bracketed callback model: the selected registered callback is
consumed, all non-resource world components are framed, the opaque return token
is checked, and the concrete stack contains that token. -/
structure OriginalProtocolCallbackMachineFrame
    (context : StaticProofContext)
    (suspension : WorldExternalSuspension)
    (entry : WorldExternalCallbackAction) where
  callback : RegisteredCallbackPair
  callbackStackExact :
    suspension.world.registeredCallbacks =
      callback :: entry.world.registeredCallbacks
  callbackTargetExact : entry.targetId = callback.targetId
  callbackValid : callback.valid context = true
  dynamicRangesExact :
    entry.world.dynamicRanges = suspension.world.dynamicRanges
  stackRangesExact : entry.world.stackRanges = suspension.world.stackRanges
  importAddressesExact :
    entry.world.importAddresses = suspension.world.importAddresses
  tlsStateExact : entry.world.tlsState = suspension.world.tlsState
  opaqueResourcesFramed : opaqueResourcesExtend suspension.world entry.world
  entryWorldValid : entry.world.valid context = true
  returnResource : OpaqueResourcePair
  returnResourceMember : returnResource ∈ entry.world.opaqueResources
  returnResourceIdExact : returnResource.id = entry.returnResourceId
  returnAddressExact : entry.returnAddress = returnResource.original
  returnAddressNonzero : entry.returnAddress ≠ BitVec.ofNat 32 0
  stackRange : DynamicAddressRangePair
  stackRangeMember : stackRange ∈ entry.world.stackRanges
  stackRangeIdExact : stackRange.id = entry.stackRangeId
  stackOffsetBounded : entry.stackOffset + 4 <= stackRange.size
  stackAddressExact :
    entry.state.registers.esp =
      stackRange.originalBase + BitVec.ofNat 32 entry.stackOffset
  returnSlotExact :
    Memory.read32 entry.state.memory entry.state.registers.esp =
      entry.returnAddress

theorem OriginalProtocolCallbackMachineFrame.known
    {context : StaticProofContext}
    {suspension : WorldExternalSuspension}
    {entry : WorldExternalCallbackAction}
    (frame : OriginalProtocolCallbackMachineFrame context suspension entry) :
    KnownCallbackRuntime context { suspension := suspension, entry := entry } := by
  refine ⟨frame.callback, ?_, frame.callbackTargetExact.symm,
    frame.callbackValid⟩
  rw [frame.callbackStackExact]
  exact List.mem_cons_self

/-- Returned protocol response evidence.  Every stateful family is explicit:
the ordinary machine contract checks ABI/memory/world effects, static words use
per-slot machine frames, dormant calls use per-frame preservation, value facts
retain both their concrete location and origin frame, and indirect source facts
must be re-established at the continuation. -/
structure OriginalCombinedReturnedProtocolResponse
    (program : DecodedWorldProgram)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (contract : MachineImportCallContract)
    (result : WorldExternalResult) where
  boundary : CheckedOriginalMachineProtocolBoundary program suspension contract
  actionExact :
    program.protocolEnvironment.action suspension.request = .returned result
  resultConforms : machineCallResultConforms false program.context
    (protocolReturnContract contract) suspension.currentEvent result
  staticWordFrames : forall requirement,
    requirement ∈ inventory.staticWords.requirements ->
      OriginalStaticWordMachineCallFrame program.context
        (protocolReturnContract contract) suspension.currentEvent result requirement
  callFramesPreserved : forall frame,
    DormantOriginalCallFrame.Holds program.context suspension.world
        suspension.state frame ->
      DormantOriginalCallFrame.Holds program.context result.world result.state
        frame
  valueLocationPreserved : forall fact,
    fact ∈ inventory.valueFlows.facts ->
      suspension.continuationTargetId ∈ fact.targetIds ->
        originalLocationValue fact.location result.state =
          originalLocationValue fact.location suspension.state
  valueOriginsPreserved : forall fact,
    fact ∈ inventory.valueFlows.facts ->
      suspension.continuationTargetId ∈ fact.targetIds ->
        OriginalValueFlowWorldFrame program.context suspension.world result.world
          fact.alternatives
  registerTargetAtContinuation : forall requirement,
    requirement ∈ inventory.registerTargets ->
      suspension.continuationTargetId =
          requirement.certificate.certificate.site.sourceTargetId ->
        RuntimeTargetMember originalContext result.world
          (result.state.registers.get
            requirement.certificate.certificate.register)
          requirement.certificate.certificate.inventory
  stackDynamicSourceAtContinuation : forall requirement,
    requirement ∈ inventory.stackDynamicTargets ->
      suspension.continuationTargetId = requirement.site.sourceTargetId ->
        requirement.sourceFact result.world result.state

theorem OriginalCombinedReturnedProtocolResponse.reachability
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {result : WorldExternalResult}
    (response : OriginalCombinedReturnedProtocolResponse program originalContext
      inventory suspension callbacks contract result)
    (holds : inventory.Holds (.awaitingExternal suspension callbacks)) :
    OriginalExecutionReachable inventory.reachableTargets.targetIds
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  have before := inventory.reachable holds
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension,
    response.actionExact]
  cases callbacks with
  | nil => exact ⟨before.2.1, before.2.2.1⟩
  | cons callback callbacks =>
      exact ⟨before.2.1, before.2.2.1, before.2.2.2⟩

theorem OriginalCombinedReturnedProtocolResponse.staticWords
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {result : WorldExternalResult}
    (response : OriginalCombinedReturnedProtocolResponse program originalContext
      inventory suspension callbacks contract result)
    (holds : inventory.Holds (.awaitingExternal suspension callbacks)) :
    inventory.staticWords.Holds program.context
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next :=
  inventory.staticWords.externalReturnedByMachineFrames program suspension
    callbacks result (protocolReturnContract contract) response.actionExact
    (inventory.staticWordsHold holds).1 response.resultConforms
    response.staticWordFrames
    (inventory.staticWordsHold holds).2

theorem OriginalCombinedReturnedProtocolResponse.callFrames
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {result : WorldExternalResult}
    (response : OriginalCombinedReturnedProtocolResponse program originalContext
      inventory suspension callbacks contract result)
    (holds : inventory.Holds (.awaitingExternal suspension callbacks)) :
    OriginalCallFrameExecutionHolds program.context
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  rcases inventory.callFramesHold holds with ⟨frames, active, suspended⟩
  refine ⟨frames, ?_⟩
  exact OriginalCallFrameExecutionInventory.externalReturned program suspension
    callbacks result frames.active frames.suspended response.actionExact active
    response.callFramesPreserved suspended

theorem OriginalCombinedReturnedProtocolResponse.valueFlows
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {result : WorldExternalResult}
    (response : OriginalCombinedReturnedProtocolResponse program originalContext
      inventory suspension callbacks contract result)
    (holds : inventory.Holds (.awaitingExternal suspension callbacks)) :
    inventory.valueFlows.Holds
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension,
    response.actionExact]
  cases callbacks with
  | nil =>
      intro fact member continuationMember
      exact fact.holdsAt_afterFrame suspension.state result.state
        suspension.world result.world
        (inventory.valueFlowHolds holds fact member (Or.inr continuationMember))
        (response.valueLocationPreserved fact member continuationMember)
        (response.valueOriginsPreserved fact member continuationMember)
  | cons callback callbacks =>
      intro fact member continuationMember
      exact fact.holdsAt_afterFrame suspension.state result.state
        suspension.world result.world
        (inventory.valueFlowHolds holds fact member (Or.inr continuationMember))
        (response.valueLocationPreserved fact member continuationMember)
        (response.valueOriginsPreserved fact member continuationMember)

theorem OriginalCombinedReturnedProtocolResponse.registerTargets
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {result : WorldExternalResult}
    (response : OriginalCombinedReturnedProtocolResponse program originalContext
      inventory suspension callbacks contract result) :
    OriginalRegisterTargetsHold inventory.registerTargets
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension,
    response.actionExact]
  cases callbacks <;> intro requirement member atSource <;>
    exact response.registerTargetAtContinuation requirement member atSource

theorem OriginalCombinedReturnedProtocolResponse.stackDynamicTargets
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {result : WorldExternalResult}
    (response : OriginalCombinedReturnedProtocolResponse program originalContext
      inventory suspension callbacks contract result) :
    OriginalStackDynamicTargetsHold inventory.stackDynamicTargets
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension,
    response.actionExact]
  cases callbacks <;> intro requirement member atSource <;>
    exact response.stackDynamicSourceAtContinuation requirement member atSource

def OriginalCombinedReturnedProtocolResponse.postFamilies
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {result : WorldExternalResult}
    (response : OriginalCombinedReturnedProtocolResponse program originalContext
      inventory suspension callbacks contract result)
    (holds : inventory.Holds (.awaitingExternal suspension callbacks)) :
    OriginalCombinedPostFamilies inventory
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := {
  reachability := response.reachability holds
  staticWords := response.staticWords holds
  callFrames := response.callFrames holds
  valueFlows := response.valueFlows holds
  registerTargets := response.registerTargets
  stackDynamicTargets := response.stackDynamicTargets
  runtimeMemory := by
    unfold DecodedWorldProgram.pe32TransitionSystem
    simp only [stepPE32WorldExecution, stepWorldExternalSuspension,
      response.actionExact]
    exact OriginalRuntimeMemoryPartition.executionHolds_externalReturn false
      program.context (protocolReturnContract contract) suspension.currentEvent result
      response.resultConforms callbacks suspension.continuationTargetId
      suspension.calls (suspension.eventIndex + 1)
      (inventory.runtimeMemoryHolds holds).2
}

/-- Callback response evidence.  Entry-world and return-stack effects are
checked by `machineFrame`; every source-indexed family is then established at
the exact callback entry target. -/
structure OriginalCombinedCallbackProtocolResponse
    (program : DecodedWorldProgram)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (contract : MachineImportCallContract)
    (entry : WorldExternalCallbackAction) where
  boundary : CheckedOriginalMachineProtocolBoundary program suspension contract
  actionExact :
    program.protocolEnvironment.action suspension.request = .callback entry
  machineFrame :
    OriginalProtocolCallbackMachineFrame program.context suspension entry
  entryTargetReachable : entry.targetId ∈ inventory.reachableTargets.targetIds
  staticWordsAtEntry :
    inventory.staticWords.HoldsIn program.context entry.world entry.state.memory
  valueFlowsAtEntry : forall fact,
    fact ∈ inventory.valueFlows.facts ->
      entry.targetId ∈ fact.targetIds -> fact.HoldsAt entry.state entry.world
  registerTargetAtEntry : forall requirement,
    requirement ∈ inventory.registerTargets ->
      entry.targetId =
          requirement.certificate.certificate.site.sourceTargetId ->
        RuntimeTargetMember originalContext entry.world
          (entry.state.registers.get
            requirement.certificate.certificate.register)
          requirement.certificate.certificate.inventory
  stackDynamicSourceAtEntry : forall requirement,
    requirement ∈ inventory.stackDynamicTargets ->
      entry.targetId = requirement.site.sourceTargetId ->
        requirement.sourceFact entry.world entry.state

theorem OriginalCombinedCallbackProtocolResponse.unknownCallbackFalse
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {entry : WorldExternalCallbackAction}
    (response : OriginalCombinedCallbackProtocolResponse program originalContext
      inventory suspension callbacks contract entry)
    (unknown : Not (KnownCallbackRuntime program.context
      { suspension := suspension, entry := entry })) : False :=
  unknown response.machineFrame.known

theorem OriginalCombinedCallbackProtocolResponse.reachability
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {entry : WorldExternalCallbackAction}
    (response : OriginalCombinedCallbackProtocolResponse program originalContext
      inventory suspension callbacks contract entry)
    (holds : inventory.Holds (.awaitingExternal suspension callbacks)) :
    OriginalExecutionReachable inventory.reachableTargets.targetIds
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  have before := inventory.reachable holds
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension,
    response.actionExact, OriginalExecutionReachable,
    originalCallbackTargetsReachable]
  exact ⟨response.entryTargetReachable, by simp,
    response.entryTargetReachable, before.2.2.2⟩

theorem OriginalCombinedCallbackProtocolResponse.staticWords
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {entry : WorldExternalCallbackAction}
    (response : OriginalCombinedCallbackProtocolResponse program originalContext
      inventory suspension callbacks contract entry)
    (holds : inventory.Holds (.awaitingExternal suspension callbacks)) :
    inventory.staticWords.Holds program.context
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next :=
  inventory.staticWords.externalCallbackEntry program suspension callbacks entry
    response.actionExact response.machineFrame.known response.staticWordsAtEntry
    (inventory.staticWordsHold holds).1 (inventory.staticWordsHold holds).2

theorem OriginalCombinedCallbackProtocolResponse.callFrames
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {entry : WorldExternalCallbackAction}
    (response : OriginalCombinedCallbackProtocolResponse program originalContext
      inventory suspension callbacks contract entry)
    (holds : inventory.Holds (.awaitingExternal suspension callbacks)) :
    OriginalCallFrameExecutionHolds program.context
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  rcases inventory.callFramesHold holds with ⟨frames, active, suspended⟩
  refine ⟨{ active := [], suspended := frames.active :: frames.suspended }, ?_⟩
  exact OriginalCallFrameExecutionInventory.externalCallbackEntry program
    suspension callbacks entry frames.active frames.suspended
    response.actionExact response.machineFrame.known active suspended

theorem OriginalCombinedCallbackProtocolResponse.valueFlows
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {entry : WorldExternalCallbackAction}
    (response : OriginalCombinedCallbackProtocolResponse program originalContext
      inventory suspension callbacks contract entry) :
    inventory.valueFlows.Holds
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension,
    response.actionExact]
  intro fact member targetMember
  exact response.valueFlowsAtEntry fact member targetMember

theorem OriginalCombinedCallbackProtocolResponse.registerTargets
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {entry : WorldExternalCallbackAction}
    (response : OriginalCombinedCallbackProtocolResponse program originalContext
      inventory suspension callbacks contract entry) :
    OriginalRegisterTargetsHold inventory.registerTargets
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension,
    response.actionExact]
  intro requirement member atSource
  exact response.registerTargetAtEntry requirement member atSource

theorem OriginalCombinedCallbackProtocolResponse.stackDynamicTargets
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {entry : WorldExternalCallbackAction}
    (response : OriginalCombinedCallbackProtocolResponse program originalContext
      inventory suspension callbacks contract entry) :
    OriginalStackDynamicTargetsHold inventory.stackDynamicTargets
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension,
    response.actionExact]
  intro requirement member atSource
  exact response.stackDynamicSourceAtEntry requirement member atSource

def OriginalCombinedCallbackProtocolResponse.postFamilies
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {entry : WorldExternalCallbackAction}
    (response : OriginalCombinedCallbackProtocolResponse program originalContext
      inventory suspension callbacks contract entry)
    (holds : inventory.Holds (.awaitingExternal suspension callbacks)) :
    OriginalCombinedPostFamilies inventory
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := {
  reachability := response.reachability holds
  staticWords := response.staticWords holds
  callFrames := response.callFrames holds
  valueFlows := response.valueFlows
  registerTargets := response.registerTargets
  stackDynamicTargets := response.stackDynamicTargets
  runtimeMemory := by
    unfold DecodedWorldProgram.pe32TransitionSystem
    simp only [stepPE32WorldExecution, stepWorldExternalSuspension,
      response.actionExact]
    exact OriginalRuntimeMemoryPartition.executionHolds_callbackEntry
      program.context suspension callbacks entry
      (inventory.runtimeMemoryHolds holds)
      response.machineFrame.entryWorldValid
}

/-- Termination still requires a classified protocol world effect.  Machine
state inventories disappear only because the authoritative execution has no
successor machine state, not because an arbitrary world mutation was accepted. -/
structure OriginalCombinedTerminatedProtocolResponse
    (program : DecodedWorldProgram)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (contract : MachineImportCallContract)
    (world : RelationalWorld) where
  boundary : CheckedOriginalMachineProtocolBoundary program suspension contract
  actionExact :
    program.protocolEnvironment.action suspension.request = .terminated world
  worldEffect : machineCallWorldEffectHolds false program.context
    contract.worldEffect suspension.arguments suspension.world world

def OriginalCombinedTerminatedProtocolResponse.postFamilies
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {world : RelationalWorld}
    (response : OriginalCombinedTerminatedProtocolResponse program
      originalContext inventory suspension callbacks contract world) :
    OriginalCombinedPostFamilies inventory
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension,
    response.actionExact]
  refine {
    reachability := trivial
    staticWords := trivial
    callFrames := ?_
    valueFlows := ?_
    registerTargets := ?_
    stackDynamicTargets := ?_
    runtimeMemory := ?_
  }
  · exact ⟨{}, rfl, rfl⟩
  · intro fact member
    trivial
  · intro requirement member
    trivial
  · intro requirement member
    trivial
  · exact OriginalRuntimeMemoryPartition.executionHolds_externalTermination
      program.context world response.worldEffect.1

/-- Exhaustive evidence for the three protocol actions.  There is no unknown
or unchecked constructor. -/
inductive OriginalCombinedMachineProtocolResponse
    (program : DecodedWorldProgram)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime) : Type where
  | returned (contract : MachineImportCallContract)
      (result : WorldExternalResult)
      (evidence : OriginalCombinedReturnedProtocolResponse program
        originalContext inventory suspension callbacks contract result)
  | callback (contract : MachineImportCallContract)
      (entry : WorldExternalCallbackAction)
      (evidence : OriginalCombinedCallbackProtocolResponse program
        originalContext inventory suspension callbacks contract entry)
  | terminated (contract : MachineImportCallContract)
      (world : RelationalWorld)
      (evidence : OriginalCombinedTerminatedProtocolResponse program
        originalContext inventory suspension callbacks contract world)

/-- Environment adapter boundary.  A producer must classify every admitted
awaiting state using one exact response proof. -/
structure CheckedOriginalCombinedMachineProtocolResponses
    (program : DecodedWorldProgram)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext) where
  classify : forall suspension callbacks,
    inventory.Holds (.awaitingExternal suspension callbacks) ->
      OriginalCombinedMachineProtocolResponse program originalContext inventory
        suspension callbacks

def CheckedOriginalCombinedMachineProtocolResponses.toAwaitingExternalPreservation
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    (responses : CheckedOriginalCombinedMachineProtocolResponses program
      originalContext inventory) :
    OriginalCombinedAwaitingExternalPreservation originalContext inventory where
  preserves suspension callbacks holds := by
    cases responses.classify suspension callbacks holds with
    | returned contract result evidence => exact evidence.postFamilies holds
    | callback contract entry evidence => exact evidence.postFamilies holds
    | terminated contract world evidence => exact evidence.postFamilies

#print axioms OriginalProtocolCallbackMachineFrame.known
#print axioms OriginalCombinedReturnedProtocolResponse.postFamilies
#print axioms OriginalCombinedCallbackProtocolResponse.unknownCallbackFalse
#print axioms OriginalCombinedCallbackProtocolResponse.postFamilies
#print axioms OriginalCombinedTerminatedProtocolResponse.postFamilies
#print axioms CheckedOriginalCombinedMachineProtocolResponses.toAwaitingExternalPreservation

end StageA.Relational.OriginalCombinedAwaitingExternalPreservation
