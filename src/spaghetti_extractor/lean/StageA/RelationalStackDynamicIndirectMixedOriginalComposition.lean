import StageA.RelationalInterpreterMixedWorldBridge
import StageA.RelationalOriginalStackDynamicControlClosure

namespace StageA.Relational.StackDynamicIndirectMixedOriginalComposition

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.NullableCodePointerTable
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.StackDynamicIndirectControl

/-!
# Stack and dynamic indirect-control mixed-original composition

Static stack, table, and dynamic-control certificates do not establish facts
about runtime memory.  This layer restricts their runtime premises to original
machine states admitted by a `MixedExecutionInvariant`.  No proposal status or
diagnostic result participates in the interface.

Only running and callback-running original executions are control sources.
Each finite result retains the concrete runtime witness from which stack-range,
dynamic-range, callback-membership, slot-bound, and exact-address evidence can
be recovered.
-/

/-- Original memory-indirect source states admitted by a mixed invariant. -/
def ActualMixedOriginalStackDynamicSource
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (sourceTargetId : Nat) (world : RelationalWorld)
    (state : MachineState) : Prop :=
  (exists calls eventIndex candidate,
    invariant.holds
      (.running sourceTargetId state calls eventIndex world) candidate) \/
  (exists calls eventIndex callbacks candidate,
    invariant.holds
      (.callbackRunning sourceTargetId state calls eventIndex world callbacks)
      candidate)

def ActualMixedOriginalStackDynamicSourceUninhabited
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (sourceTargetId : Nat) : Prop :=
  SourceUninhabited
    (ActualMixedOriginalStackDynamicSource invariant sourceTargetId)

theorem actualMixedOriginalStackDynamicSource_targetReachable
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (reached : ActualMixedOriginalStackDynamicSource invariant sourceTargetId
      world state) :
    sourceTargetId ∈ reachabilityTargetIds := by
  rcases reached with
    ⟨calls, eventIndex, candidate, related⟩ |
    ⟨calls, eventIndex, callbacks, candidate, related⟩
  · exact (invariant.originalReachable
      (.running sourceTargetId state calls eventIndex world) candidate related).1
  · exact (invariant.originalReachable
      (.callbackRunning sourceTargetId state calls eventIndex world callbacks)
      candidate related).1

/-! ## Stack-carried fixed code pointers -/

/-- A closed stack target retains the exact stack allocation, slot bounds,
memory value, and resolved original code-map entry. -/
structure MixedOriginalStackCarryTarget
    (context : OriginalDecodedStaticContext)
    (authority : CheckedStackCarryAuthority context)
    (world : RelationalWorld) (state : MachineState) where
  runtime :
    StackRelocatedCodePointerRuntime context authority.static.claim world state
  resolved :
    OriginalResolvedCodeTarget context authority.static.claim.site state
  targetIdExact :
    resolved.targetId = authority.static.claim.seed.targetId

/-- A stack-carried source is composable only through a complete runtime carry
premise over actual mixed states, or a proof that no such source state exists.
The finite inventory is the checked singleton seed in the authority. -/
inductive StackCarryMixedOriginalComposition
    (authority : CheckedStackCarryAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) :
    Prop where
  | unreachable
      (sourceUninhabited :
        ActualMixedOriginalStackDynamicSourceUninhabited invariant
          authority.static.claim.site.sourceTargetId)
  | finite
      (complete : CompleteStackCarryPremise context authority
        (ActualMixedOriginalStackDynamicSource invariant
          authority.static.claim.site.sourceTargetId))

theorem StackCarryMixedOriginalComposition.originalClosure
    {context : OriginalDecodedStaticContext}
    {authority : CheckedStackCarryAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    (composition : StackCarryMixedOriginalComposition authority invariant) :
    OriginalIndirectControlClosure context authority.static.claim.site
      (ActualMixedOriginalStackDynamicSource invariant
        authority.static.claim.site.sourceTargetId) := by
  cases composition with
  | unreachable sourceUninhabited =>
      exact .unreachable sourceUninhabited
  | finite complete =>
      exact stackCarryClosure_of_complete context authority _ complete

theorem StackCarryMixedOriginalComposition.targetClosed
    {context : OriginalDecodedStaticContext}
    {authority : CheckedStackCarryAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    (composition : StackCarryMixedOriginalComposition authority invariant)
    (reached : ActualMixedOriginalStackDynamicSource invariant
      authority.static.claim.site.sourceTargetId world state) :
    Nonempty (MixedOriginalStackCarryTarget context authority world state) := by
  cases composition with
  | unreachable sourceUninhabited =>
      exact False.elim (sourceUninhabited ⟨world, state, reached⟩)
  | finite complete =>
      have runtime := complete.everyReachableCarriesSeed world state reached
      obtain ⟨resolved, targetIdExact⟩ :=
        originalResolvedCodeTarget_of_checked context authority.static.claim.site
          state authority.static.claim.seed.targetId
          (authority.static.claim.seed.word context) runtime.targetValue
          authority.targetAddressChecked
      exact ⟨{
        runtime := runtime
        resolved := resolved
        targetIdExact := targetIdExact
      }⟩

/-! ## Indexed immutable table predecessors -/

/-- The currently supported indexed-table closure is deliberately narrow:
the exact checked loop interval is empty and every actual predecessor state
satisfies its runtime index bound.  Populated or unknown table inventories
cannot construct this certificate. -/
inductive IndexedTableMixedOriginalComposition
    (authority : CheckedIndexedTableAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) :
    Prop where
  | unreachable
      (sourceUninhabited :
        ActualMixedOriginalStackDynamicSourceUninhabited invariant
          authority.static.claim.site.sourceTargetId)
  | emptyInterval
      (loop : LoopFacts)
      (loopExact : authority.static.claim.table.loop = .exact loop)
      (empty : loop.lowerInclusive = loop.upperExclusive)
      (complete : CompleteIndexedTablePredecessorPremise authority
        (ActualMixedOriginalStackDynamicSource invariant
          authority.static.claim.site.sourceTargetId))

theorem IndexedTableMixedOriginalComposition.sourceUninhabited
    {context : OriginalDecodedStaticContext}
    {authority : CheckedIndexedTableAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    (composition : IndexedTableMixedOriginalComposition authority invariant) :
    ActualMixedOriginalStackDynamicSourceUninhabited invariant
      authority.static.claim.site.sourceTargetId := by
  cases composition with
  | unreachable sourceUninhabited => exact sourceUninhabited
  | emptyInterval loop loopExact empty complete =>
      rintro ⟨world, state, reached⟩
      exact authority.static.claim.noRuntimeIndex_of_emptyInterval loop loopExact
        empty state (complete.everyReachableIndexBound world state reached)

theorem IndexedTableMixedOriginalComposition.originalClosure
    {context : OriginalDecodedStaticContext}
    {authority : CheckedIndexedTableAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    (composition : IndexedTableMixedOriginalComposition authority invariant) :
    OriginalIndirectControlClosure context authority.static.claim.site
      (ActualMixedOriginalStackDynamicSource invariant
        authority.static.claim.site.sourceTargetId) :=
  .unreachable composition.sourceUninhabited

/-! ## Dynamic callback fields -/

def DynamicCallbackInventoryPopulated
    (authority : CheckedDynamicCallbackAuthority context) : Prop :=
  exists targetId, targetId ∈ authority.static.claim.allowedTargetIds

/-- A closed dynamic callback target retains allocation membership, callback
registration, field bounds and value, checked address resolution, and finite
target membership. -/
structure MixedOriginalDynamicCallbackTarget
    (context : OriginalDecodedStaticContext)
    (authority : CheckedDynamicCallbackAuthority context)
    (world : RelationalWorld) (state : MachineState) where
  runtime :
    DynamicCallbackControlRuntime context authority.static.claim world state
  callbackAddressChecked :
    dynamicCallbackAddressChecked context runtime.callback = true
  resolved :
    OriginalResolvedCodeTarget context authority.static.claim.site state
  targetIdExact : resolved.targetId = runtime.callback.targetId
  targetAllowed :
    resolved.targetId ∈ authority.static.claim.allowedTargetIds

/-- Dynamic callback composition rejects an empty target inventory even before
the runtime premise is considered.  Unknown proposal inventories cannot become
a checked authority and therefore cannot inhabit either finite constructor
argument. -/
inductive DynamicCallbackMixedOriginalComposition
    (authority : CheckedDynamicCallbackAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) :
    Prop where
  | unreachable
      (complete : CompleteDynamicSourceUninhabitedPremise
        (ActualMixedOriginalStackDynamicSource invariant
          authority.static.claim.site.sourceTargetId))
  | finite
      (inventoryPopulated : DynamicCallbackInventoryPopulated authority)
      (complete : CompleteDynamicCallbackPremise context authority
        (ActualMixedOriginalStackDynamicSource invariant
          authority.static.claim.site.sourceTargetId))

theorem DynamicCallbackMixedOriginalComposition.originalClosure
    {context : OriginalDecodedStaticContext}
    {authority : CheckedDynamicCallbackAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    (composition : DynamicCallbackMixedOriginalComposition authority invariant) :
    OriginalIndirectControlClosure context authority.static.claim.site
      (ActualMixedOriginalStackDynamicSource invariant
        authority.static.claim.site.sourceTargetId) := by
  cases composition with
  | unreachable complete =>
      exact .unreachable complete.sourceUninhabited
  | finite inventoryPopulated complete =>
      exact dynamicCallbackClosure_of_complete context authority _ complete

theorem DynamicCallbackMixedOriginalComposition.targetClosed
    {context : OriginalDecodedStaticContext}
    {authority : CheckedDynamicCallbackAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    (composition : DynamicCallbackMixedOriginalComposition authority invariant)
    (reached : ActualMixedOriginalStackDynamicSource invariant
      authority.static.claim.site.sourceTargetId world state) :
    Nonempty
      (MixedOriginalDynamicCallbackTarget context authority world state) := by
  cases composition with
  | unreachable complete =>
      exact False.elim
        (complete.sourceUninhabited ⟨world, state, reached⟩)
  | finite inventoryPopulated complete =>
      let runtime := complete.runtime world state reached
      have targetValue := runtime.targetValue
      have addressChecked :=
        complete.callbackAddressChecked world state reached
      obtain ⟨resolved, targetIdExact⟩ :=
        originalResolvedCodeTarget_of_checked context authority.static.claim.site
          state runtime.callback.targetId runtime.callback.originalAddress
          targetValue.1 addressChecked
      exact ⟨{
        runtime := runtime
        callbackAddressChecked := addressChecked
        resolved := resolved
        targetIdExact := targetIdExact
        targetAllowed := by simpa [targetIdExact] using targetValue.2
      }⟩

theorem sourceUninhabited_of_emptyDynamicCallbackInventory
    {context : OriginalDecodedStaticContext}
    {authority : CheckedDynamicCallbackAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    (composition : DynamicCallbackMixedOriginalComposition authority invariant)
    (inventoryEmpty : authority.static.claim.allowedTargetIds = []) :
    ActualMixedOriginalStackDynamicSourceUninhabited invariant
      authority.static.claim.site.sourceTargetId := by
  cases composition with
  | unreachable complete => exact complete.sourceUninhabited
  | finite inventoryPopulated complete =>
      simp [DynamicCallbackInventoryPopulated, inventoryEmpty] at inventoryPopulated

/-! ## Dynamic sources proved uninhabited

The source-uninhabited authority intentionally has no callback inventory.  It
is tied only to an exact checked indirect-control site and a complete
uninhabited-source premise over actual mixed states.
-/

structure DynamicSourceMixedOriginalComposition
    (checkedSite : CheckedOriginalIndirectControlSite context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) :
    Prop where
  complete : CompleteDynamicSourceUninhabitedPremise
    (ActualMixedOriginalStackDynamicSource invariant
      checkedSite.site.sourceTargetId)

theorem DynamicSourceMixedOriginalComposition.sourceUninhabited
    {context : OriginalDecodedStaticContext}
    {checkedSite : CheckedOriginalIndirectControlSite context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    (composition : DynamicSourceMixedOriginalComposition checkedSite invariant) :
    ActualMixedOriginalStackDynamicSourceUninhabited invariant
      checkedSite.site.sourceTargetId :=
  composition.complete.sourceUninhabited

theorem DynamicSourceMixedOriginalComposition.originalClosure
    {context : OriginalDecodedStaticContext}
    {checkedSite : CheckedOriginalIndirectControlSite context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    (composition : DynamicSourceMixedOriginalComposition checkedSite invariant) :
    OriginalIndirectControlClosure context checkedSite.site
      (ActualMixedOriginalStackDynamicSource invariant
        checkedSite.site.sourceTargetId) :=
  dynamicSourceClosure_of_uninhabited checkedSite _ composition.complete

#print axioms actualMixedOriginalStackDynamicSource_targetReachable
#print axioms StackCarryMixedOriginalComposition.targetClosed
#print axioms IndexedTableMixedOriginalComposition.sourceUninhabited
#print axioms DynamicCallbackMixedOriginalComposition.targetClosed
#print axioms sourceUninhabited_of_emptyDynamicCallbackInventory
#print axioms DynamicSourceMixedOriginalComposition.sourceUninhabited
#print axioms DynamicSourceMixedOriginalComposition.originalClosure

end StageA.Relational.StackDynamicIndirectMixedOriginalComposition
