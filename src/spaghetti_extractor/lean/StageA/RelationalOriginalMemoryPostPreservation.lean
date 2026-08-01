import StageA.RelationalOriginalMemoryEffectPreservation

namespace StageA.Relational.OriginalMemoryEffectPreservation

open StageA.Formal StageA.Relational
open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.OriginalTargetPreservation

/-!
# Lifting checked memory effects to normalized target post states

These constructors are deliberately thin.  Running, callback, awaiting, and
returned states require complete finite inventory evidence.  Termination and
fault need no memory premise because the invariant does not inspect memory in
those terminal states.
-/

def OriginalMemoryEffectInventoryEvidence.runningPost
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld world : RelationalWorld} {beforeMemory : Memory}
    {targetId : Nat} {state : MachineState} {calls : List Nat}
    {eventIndex : Nat}
    (evidence : OriginalMemoryEffectInventoryEvidence context inventory
      beforeWorld world beforeMemory state.memory) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
      (.running targetId state calls eventIndex world) :=
  .running targetId state calls eventIndex world
    evidence.toProtectedMemoryUpdate

def OriginalMemoryEffectInventoryEvidence.callbackRunningPost
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld world : RelationalWorld} {beforeMemory : Memory}
    {targetId : Nat} {state : MachineState} {calls : List Nat}
    {eventIndex : Nat} {callbacks : List WorldExternalCallbackRuntime}
    (evidence : OriginalMemoryEffectInventoryEvidence context inventory
      beforeWorld world beforeMemory state.memory)
    (suspended : SuspendedOriginalStaticWordsHold context inventory callbacks) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
      (.callbackRunning targetId state calls eventIndex world callbacks) :=
  .callbackRunning targetId state calls eventIndex world callbacks
    evidence.toProtectedMemoryUpdate suspended

def OriginalMemoryEffectInventoryEvidence.awaitingExternalPost
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld : RelationalWorld} {beforeMemory : Memory}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    (evidence : OriginalMemoryEffectInventoryEvidence context inventory
      beforeWorld suspension.world beforeMemory suspension.state.memory)
    (suspended : SuspendedOriginalStaticWordsHold context inventory callbacks) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
      (.awaitingExternal suspension callbacks) :=
  .awaitingExternal suspension callbacks evidence.toProtectedMemoryUpdate
    suspended

def OriginalMemoryEffectInventoryEvidence.returnedPost
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld world : RelationalWorld} {beforeMemory : Memory}
    {state : MachineState}
    (evidence : OriginalMemoryEffectInventoryEvidence context inventory
      beforeWorld world beforeMemory state.memory) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
      (.returned state world) :=
  .returned state world evidence.toProtectedMemoryUpdate

def OriginalStaticWordPostEvidence.terminatedOfMemoryEffects
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (beforeWorld world : RelationalWorld) (beforeMemory : Memory) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
      (.terminated world) :=
  .terminated world

def OriginalStaticWordPostEvidence.faultOfMemoryEffects
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (beforeWorld : RelationalWorld) (beforeMemory : Memory)
    (cause : ModeledFault) :
    OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
      (.fault cause) :=
  .fault cause

end StageA.Relational.OriginalMemoryEffectPreservation
