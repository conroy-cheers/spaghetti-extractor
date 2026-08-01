import StageA.RelationalOriginalMemoryPostPreservation

namespace StageA.Relational.OriginalMemoryEffectPreservation

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate

/-!
# Target-specific memory preservation inputs

This is the machine-checkable boundary for a production target-preservation
producer.  The generic memory layer cannot derive address disjointness or
world-origin stability from a write expression alone.  For every reachable
target and every admitted invocation, a producer must emit a case containing:

* the exact checked target transition and normalized successor;
* one `OriginalWordEffectEvidence` for every static-word requirement;
* for ordinary writes, the checked normalized write expressions, their exact
  evaluation, and disjointness or an explicit related replacement;
* for x87 writes, both the concrete-prefix footprint and the variable-width
  x87 byte footprint;
* for bulk, atomic, or other router-side memory changes, an exact unchanged
  read or explicit related replacement for every affected requirement;
* for external results, call conformance, bounded machine footprints, and
  world-origin preservation or explicit related replacements; and
* suspended static-word evidence at callback and awaiting-external boundaries.

Missing any item leaves the structures below uninhabited.  A generated target
count, status field, or bare declaration name cannot substitute for them.
-/

/-- Complete memory evidence for one normalized successor. -/
inductive OriginalTargetMemorySuccessorInputs
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (beforeWorld : RelationalWorld) (beforeMemory : Memory) :
    OriginalNormalizedSuccessor -> Prop where
  | running (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (effects : OriginalMemoryEffectInventoryEvidence context inventory
        beforeWorld world beforeMemory state.memory) :
      OriginalTargetMemorySuccessorInputs context inventory beforeWorld
        beforeMemory (.running targetId state calls eventIndex world)
  | callbackRunning (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
      (effects : OriginalMemoryEffectInventoryEvidence context inventory
        beforeWorld world beforeMemory state.memory)
      (suspended : SuspendedOriginalStaticWordsHold context inventory callbacks) :
      OriginalTargetMemorySuccessorInputs context inventory beforeWorld
        beforeMemory
        (.callbackRunning targetId state calls eventIndex world callbacks)
  | awaitingExternal (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime)
      (effects : OriginalMemoryEffectInventoryEvidence context inventory
        beforeWorld suspension.world beforeMemory suspension.state.memory)
      (suspended : SuspendedOriginalStaticWordsHold context inventory callbacks) :
      OriginalTargetMemorySuccessorInputs context inventory beforeWorld
        beforeMemory (.awaitingExternal suspension callbacks)
  | returned (state : MachineState) (world : RelationalWorld)
      (effects : OriginalMemoryEffectInventoryEvidence context inventory
        beforeWorld world beforeMemory state.memory) :
      OriginalTargetMemorySuccessorInputs context inventory beforeWorld
        beforeMemory (.returned state world)
  | terminated (world : RelationalWorld) :
      OriginalTargetMemorySuccessorInputs context inventory beforeWorld
        beforeMemory (.terminated world)
  | fault (cause : ModeledFault) :
      OriginalTargetMemorySuccessorInputs context inventory beforeWorld
        beforeMemory (.fault cause)

def OriginalTargetMemorySuccessorInputs.toPostEvidence
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld : RelationalWorld} {beforeMemory : Memory}
    {successor : OriginalNormalizedSuccessor}
    (inputs : OriginalTargetMemorySuccessorInputs context inventory beforeWorld
      beforeMemory successor) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
      successor := by
  cases inputs with
  | running _ _ _ _ _ effects => exact effects.runningPost
  | callbackRunning _ _ _ _ _ _ effects suspended =>
      exact effects.callbackRunningPost suspended
  | awaitingExternal _ _ effects suspended =>
      exact effects.awaitingExternalPost suspended
  | returned _ _ effects => exact effects.returnedPost
  | terminated world =>
      exact OriginalStaticWordPostEvidence.terminatedOfMemoryEffects context
        inventory beforeWorld world beforeMemory
  | fault cause =>
      exact OriginalStaticWordPostEvidence.faultOfMemoryEffects context inventory
        beforeWorld beforeMemory cause

/-- Memory-only production case for one exact target invocation. -/
structure CheckedOriginalTargetMemoryPreservationCase
    {program : Program} {targetId : Nat}
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext)
    (checked : CheckedOriginalTargetEffect program targetId)
    (invocation : OriginalTargetInvocation targetId) where
  transition : CheckedOriginalTargetTransition checked originalContext
    inventory.reachableTargets.targetIds invocation
  memory : OriginalTargetMemorySuccessorInputs program.worldProgram.context
    inventory.staticWords invocation.world invocation.state.memory
    transition.successor

def CheckedOriginalTargetMemoryPreservationCase.toPostEvidence
    {program : Program} {targetId : Nat}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {checked : CheckedOriginalTargetEffect program targetId}
    {invocation : OriginalTargetInvocation targetId}
    (inputs : CheckedOriginalTargetMemoryPreservationCase originalContext
      inventory checked invocation) :
    OriginalStaticWordPostEvidence program.worldProgram.context
      inventory.staticWords invocation.world invocation.state.memory
      inputs.transition.successor :=
  inputs.memory.toPostEvidence

/-- Shardable production interface.  A GNU adapter must emit one provider per
reachable transition-index certificate; the same interface is generic over the
binary, target count, and static-word inventory. -/
structure CheckedOriginalTargetMemoryPreservationProvider
    {pe : PE32} {program : Program} {binding : ExactBinding pe program}
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext)
    (certificate : ActiveTargetTransitionCertificate binding) where
  checked : CheckedOriginalTargetEffect program certificate.targetId
  cases : forall invocation : OriginalTargetInvocation certificate.targetId,
    inventory.Holds invocation.execution ->
      CheckedOriginalTargetMemoryPreservationCase originalContext inventory
        checked invocation

/-- Production input for one external result.  The contract conformance proof
binds the exact API result; `effects` must still cover every protected word. -/
structure CheckedOriginalExternalMemoryPreservationInputs
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (result : WorldExternalResult) : Prop where
  conforms : machineCallResultConforms false context contract event result
  effects : OriginalExternalMemoryInventoryEvidence context inventory contract
    event result

def CheckedOriginalExternalMemoryPreservationInputs.toProtectedMemoryUpdate
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {contract : MachineImportCallContract}
    {event : WorldExternalEvent} {result : WorldExternalResult}
    (inputs : CheckedOriginalExternalMemoryPreservationInputs context inventory
      contract event result) :
    OriginalProtectedMemoryUpdate context inventory event.world result.world
      event.state.memory result.state.memory :=
  inputs.effects.toProtectedMemoryUpdate inputs.conforms

theorem CheckedOriginalExternalMemoryPreservationInputs.preserves
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {contract : MachineImportCallContract}
    {event : WorldExternalEvent} {result : WorldExternalResult}
    (inputs : CheckedOriginalExternalMemoryPreservationInputs context inventory
      contract event result)
    (before : inventory.HoldsIn context event.world event.state.memory) :
    inventory.HoldsIn context result.world result.state.memory :=
  inputs.toProtectedMemoryUpdate.preserves before

end StageA.Relational.OriginalMemoryEffectPreservation
