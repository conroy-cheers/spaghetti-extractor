import StageA.RelationalInterpreterMixedWorldBridge
import StageA.RelationalMixedExecutionInvariantExtension
import StageA.RelationalOriginalExecutionInvariant
import StageA.RelationalOriginalStackDynamicControlClosure

namespace StageA.Relational.StackDynamicIndirectMixedOriginalComposition

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.MixedExecutionInvariantExtension
open StageA.Relational.NullableCodePointerTable
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalExecutionInvariant
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

/-! ## Generic source facts and inductive preservation -/

/-- A fact scoped to one original control source. It is vacuous at all other
execution states, and covers both ordinary and callback-running frames. -/
def OriginalSourceFactAt
    (sourceTargetId : Nat)
    (fact : RelationalWorld -> MachineState -> Prop) :
    WorldExecution -> Prop
  | .running targetId state _calls _eventIndex world =>
      targetId = sourceTargetId -> fact world state
  | .callbackRunning targetId state _calls _eventIndex world _callbacks =>
      targetId = sourceTargetId -> fact world state
  | _ => True

/-- Original-only preservation of one source fact by the exact decoded
transition system. The launch proof is supplied when this invariant is joined
to whole-program composition. -/
structure OriginalSourceFactExecutionInvariant
    (program : DecodedWorldProgram)
    (sourceTargetId : Nat)
    (fact : RelationalWorld -> MachineState -> Prop) : Prop where
  stepClosed : forall before,
    OriginalSourceFactAt sourceTargetId fact before ->
      OriginalSourceFactAt sourceTargetId fact
        (program.pe32TransitionSystem.step before).next

def OriginalSourceFactExecutionInvariant.toOriginalInvariant
    (invariant : OriginalSourceFactExecutionInvariant program sourceTargetId
      fact) :
    OriginalWorldExecutionInvariant program where
  holds := OriginalSourceFactAt sourceTargetId fact
  stepClosed := invariant.stepClosed

/-- Projection of one source fact from an arbitrary multi-cutpoint original
invariant. This is the interface used by finite abstract-interpretation
certificates whose predecessor facts jointly establish the source fact. -/
structure OriginalSourceFactProjection
    (invariant : OriginalWorldExecutionInvariant program)
    (sourceTargetId : Nat)
    (fact : RelationalWorld -> MachineState -> Prop) : Prop where
  project : forall execution,
    invariant.holds execution ->
      OriginalSourceFactAt sourceTargetId fact execution

def OriginalSourceFactExecutionInvariant.projection
    (invariant : OriginalSourceFactExecutionInvariant program sourceTargetId
      fact) :
    OriginalSourceFactProjection invariant.toOriginalInvariant sourceTargetId
      fact where
  project _ holds := holds

/-- Paired preservation of one source fact. This form is used when an internal
or external call is required to establish the successor fact. -/
structure OriginalSourceFactMixedExecutionInvariant
    (original : DecodedWorldProgram)
    (candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (reachabilityTargetIds : List Nat)
    (base : MixedExecutionInvariant reachabilityTargetIds contract)
    (sourceTargetId : Nat)
    (fact : RelationalWorld -> MachineState -> Prop) : Prop where
  chunkClosed : forall originalBefore candidateBefore,
    OriginalSourceFactAt sourceTargetId fact originalBefore ->
      (chunk : MixedWorldComponentChunkRefinement original candidate contract
        base originalBefore candidateBefore) ->
      OriginalSourceFactAt sourceTargetId fact chunk.originalAfter

def OriginalSourceFactMixedExecutionInvariant.toExtension
    (invariant : OriginalSourceFactMixedExecutionInvariant original candidate
      contract reachabilityTargetIds base sourceTargetId fact) :
    MixedWorldExecutionInvariantExtension original candidate contract
      reachabilityTargetIds base where
  holds originalExecution _candidateExecution :=
    OriginalSourceFactAt sourceTargetId fact originalExecution
  chunkClosed := invariant.chunkClosed

/-- Projection of one source fact from an arbitrary paired multi-cutpoint
invariant extension. -/
structure OriginalSourceFactMixedProjection
    (extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base)
    (sourceTargetId : Nat)
    (fact : RelationalWorld -> MachineState -> Prop) : Prop where
  project : forall originalExecution candidateExecution,
    extension.holds originalExecution candidateExecution ->
      OriginalSourceFactAt sourceTargetId fact originalExecution

def OriginalSourceFactMixedExecutionInvariant.projection
    (invariant : OriginalSourceFactMixedExecutionInvariant original candidate
      contract reachabilityTargetIds base sourceTargetId fact) :
    OriginalSourceFactMixedProjection invariant.toExtension sourceTargetId fact
    where
  project _ _ holds := holds

/-- Recover one source fact projected from an arbitrary original invariant. -/
theorem originalSourceFact_of_originalProjection
    {program : DecodedWorldProgram}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    {originalInvariant : OriginalWorldExecutionInvariant program}
    {sourceTargetId : Nat}
    {fact : RelationalWorld -> MachineState -> Prop}
    (projection :
      OriginalSourceFactProjection originalInvariant sourceTargetId fact)
    {world : RelationalWorld} {state : MachineState}
    (reached : ActualMixedOriginalStackDynamicSource
      (strengthenMixedExecutionInvariant mixed originalInvariant)
      sourceTargetId world state) :
    fact world state := by
  rcases reached with
    ⟨calls, eventIndex, candidateExecution, related⟩ |
    ⟨calls, eventIndex, callbacks, candidateExecution, related⟩
  · exact projection.project _ related.2 rfl
  · exact projection.project _ related.2 rfl

/-- Recover one source fact projected from an arbitrary paired invariant. -/
theorem originalSourceFact_of_mixedProjection
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {contract : MixedRelationContract}
    {reachabilityTargetIds : List Nat}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    {extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base}
    {sourceTargetId : Nat}
    {fact : RelationalWorld -> MachineState -> Prop}
    (projection :
      OriginalSourceFactMixedProjection extension sourceTargetId fact)
    {world : RelationalWorld} {state : MachineState}
    (reached : ActualMixedOriginalStackDynamicSource extension.strengthen
      sourceTargetId world state) :
    fact world state := by
  rcases reached with
    ⟨calls, eventIndex, candidateExecution, related⟩ |
    ⟨calls, eventIndex, callbacks, candidateExecution, related⟩
  · exact projection.project _ _ related.2 rfl
  · exact projection.project _ _ related.2 rfl

/-- Recover a source fact from an original-only invariant strengthened into the
actual mixed composition invariant. -/
theorem originalSourceFact_of_originalInvariant
    {program : DecodedWorldProgram}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    {sourceTargetId : Nat}
    {fact : RelationalWorld -> MachineState -> Prop}
    (executionInvariant :
      OriginalSourceFactExecutionInvariant program sourceTargetId fact)
    {world : RelationalWorld} {state : MachineState}
    (reached : ActualMixedOriginalStackDynamicSource
      (strengthenMixedExecutionInvariant mixed
        executionInvariant.toOriginalInvariant)
      sourceTargetId world state) :
    fact world state :=
  originalSourceFact_of_originalProjection executionInvariant.projection reached

/-- Recover a source fact from a paired chunk invariant strengthened into the
actual mixed composition invariant. -/
theorem originalSourceFact_of_mixedInvariant
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {contract : MixedRelationContract}
    {reachabilityTargetIds : List Nat}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    {sourceTargetId : Nat}
    {fact : RelationalWorld -> MachineState -> Prop}
    (executionInvariant :
      OriginalSourceFactMixedExecutionInvariant original candidate contract
        reachabilityTargetIds base sourceTargetId fact)
    {world : RelationalWorld} {state : MachineState}
    (reached : ActualMixedOriginalStackDynamicSource
      executionInvariant.toExtension.strengthen sourceTargetId world state) :
    fact world state :=
  originalSourceFact_of_mixedProjection executionInvariant.projection reached

theorem actualMixedOriginalStackDynamicSourceUninhabited_of_originalProjection
    {program : DecodedWorldProgram}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    {originalInvariant : OriginalWorldExecutionInvariant program}
    {sourceTargetId : Nat}
    (projection :
      OriginalSourceFactProjection originalInvariant sourceTargetId
        (fun _world _state => False)) :
    ActualMixedOriginalStackDynamicSourceUninhabited
      (strengthenMixedExecutionInvariant mixed originalInvariant)
      sourceTargetId := by
  rintro ⟨world, state, reached⟩
  exact originalSourceFact_of_originalProjection projection reached

theorem actualMixedOriginalStackDynamicSourceUninhabited_of_mixedProjection
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {contract : MixedRelationContract}
    {reachabilityTargetIds : List Nat}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    {extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base}
    {sourceTargetId : Nat}
    (projection :
      OriginalSourceFactMixedProjection extension sourceTargetId
        (fun _world _state => False)) :
    ActualMixedOriginalStackDynamicSourceUninhabited extension.strengthen
      sourceTargetId := by
  rintro ⟨world, state, reached⟩
  exact originalSourceFact_of_mixedProjection projection reached

/-- A false source fact is a checked proof that the source is absent from every
state admitted by the strengthened invariant. -/
theorem actualMixedOriginalStackDynamicSourceUninhabited_of_originalInvariant
    {program : DecodedWorldProgram}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    {sourceTargetId : Nat}
    (executionInvariant :
      OriginalSourceFactExecutionInvariant program sourceTargetId
        (fun _world _state => False)) :
    ActualMixedOriginalStackDynamicSourceUninhabited
      (strengthenMixedExecutionInvariant mixed
        executionInvariant.toOriginalInvariant)
      sourceTargetId :=
  actualMixedOriginalStackDynamicSourceUninhabited_of_originalProjection
    executionInvariant.projection

theorem actualMixedOriginalStackDynamicSourceUninhabited_of_mixedInvariant
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {contract : MixedRelationContract}
    {reachabilityTargetIds : List Nat}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    {sourceTargetId : Nat}
    (executionInvariant :
      OriginalSourceFactMixedExecutionInvariant original candidate contract
        reachabilityTargetIds base sourceTargetId
        (fun _world _state => False)) :
    ActualMixedOriginalStackDynamicSourceUninhabited
      executionInvariant.toExtension.strengthen sourceTargetId :=
  actualMixedOriginalStackDynamicSourceUninhabited_of_mixedProjection
    executionInvariant.projection

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

noncomputable def completeStackCarryPremise_of_originalProjection
    {program : DecodedWorldProgram}
    {authority : CheckedStackCarryAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    {originalInvariant : OriginalWorldExecutionInvariant program}
    (projection :
      OriginalSourceFactProjection originalInvariant
        authority.static.claim.site.sourceTargetId
        (fun world state =>
          Nonempty (StackRelocatedCodePointerRuntime context
            authority.static.claim world state))) :
    CompleteStackCarryPremise context authority
      (ActualMixedOriginalStackDynamicSource
        (strengthenMixedExecutionInvariant mixed originalInvariant)
        authority.static.claim.site.sourceTargetId) where
  everyReachableCarriesSeed _world _state reached :=
    Classical.choice
      (originalSourceFact_of_originalProjection projection reached)

noncomputable def completeStackCarryPremise_of_mixedProjection
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {authority : CheckedStackCarryAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    {extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base}
    (projection :
      OriginalSourceFactMixedProjection extension
        authority.static.claim.site.sourceTargetId
        (fun world state =>
          Nonempty (StackRelocatedCodePointerRuntime context
            authority.static.claim world state))) :
    CompleteStackCarryPremise context authority
      (ActualMixedOriginalStackDynamicSource extension.strengthen
        authority.static.claim.site.sourceTargetId) where
  everyReachableCarriesSeed _world _state reached :=
    Classical.choice
      (originalSourceFact_of_mixedProjection projection reached)

noncomputable def completeStackCarryPremise_of_originalInvariant
    {program : DecodedWorldProgram}
    {authority : CheckedStackCarryAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    (executionInvariant :
      OriginalSourceFactExecutionInvariant program
        authority.static.claim.site.sourceTargetId
        (fun world state =>
          Nonempty (StackRelocatedCodePointerRuntime context
            authority.static.claim world state))) :
    CompleteStackCarryPremise context authority
      (ActualMixedOriginalStackDynamicSource
        (strengthenMixedExecutionInvariant mixed
          executionInvariant.toOriginalInvariant)
        authority.static.claim.site.sourceTargetId) :=
  completeStackCarryPremise_of_originalProjection executionInvariant.projection

noncomputable def completeStackCarryPremise_of_mixedInvariant
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {authority : CheckedStackCarryAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    (executionInvariant :
      OriginalSourceFactMixedExecutionInvariant original candidate contract
        reachabilityTargetIds base
        authority.static.claim.site.sourceTargetId
        (fun world state =>
          Nonempty (StackRelocatedCodePointerRuntime context
            authority.static.claim world state))) :
    CompleteStackCarryPremise context authority
      (ActualMixedOriginalStackDynamicSource
        executionInvariant.toExtension.strengthen
        authority.static.claim.site.sourceTargetId) :=
  completeStackCarryPremise_of_mixedProjection executionInvariant.projection

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
    (authority : CheckedEmptyIndexedSourceAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) :
    Prop where
  | unreachable
      (sourceUninhabited :
        ActualMixedOriginalStackDynamicSourceUninhabited invariant
          authority.site.sourceTargetId)
  | emptyInterval
      (complete : CompleteEmptyIndexedSourcePredecessorPremise authority
        (ActualMixedOriginalStackDynamicSource invariant
          authority.site.sourceTargetId))

theorem completeEmptyIndexedSourcePremise_of_originalProjection
    {program : DecodedWorldProgram}
    {authority : CheckedEmptyIndexedSourceAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    {originalInvariant : OriginalWorldExecutionInvariant program}
    (projection :
      OriginalSourceFactProjection originalInvariant authority.site.sourceTargetId
        (fun _world state => authority.RuntimeIndexBound state)) :
    CompleteEmptyIndexedSourcePredecessorPremise authority
      (ActualMixedOriginalStackDynamicSource
        (strengthenMixedExecutionInvariant mixed originalInvariant)
        authority.site.sourceTargetId) where
  everyReachableIndexBound _world _state reached :=
    originalSourceFact_of_originalProjection projection reached

theorem completeEmptyIndexedSourcePremise_of_mixedProjection
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {authority : CheckedEmptyIndexedSourceAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    {extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base}
    (projection :
      OriginalSourceFactMixedProjection extension authority.site.sourceTargetId
        (fun _world state => authority.RuntimeIndexBound state)) :
    CompleteEmptyIndexedSourcePredecessorPremise authority
      (ActualMixedOriginalStackDynamicSource extension.strengthen
        authority.site.sourceTargetId) where
  everyReachableIndexBound _world _state reached :=
    originalSourceFact_of_mixedProjection projection reached

theorem completeEmptyIndexedSourcePremise_of_originalInvariant
    {program : DecodedWorldProgram}
    {authority : CheckedEmptyIndexedSourceAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    (executionInvariant :
      OriginalSourceFactExecutionInvariant program authority.site.sourceTargetId
        (fun _world state => authority.RuntimeIndexBound state)) :
    CompleteEmptyIndexedSourcePredecessorPremise authority
      (ActualMixedOriginalStackDynamicSource
        (strengthenMixedExecutionInvariant mixed
          executionInvariant.toOriginalInvariant)
        authority.site.sourceTargetId) :=
  completeEmptyIndexedSourcePremise_of_originalProjection
    executionInvariant.projection

theorem completeEmptyIndexedSourcePremise_of_mixedInvariant
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {authority : CheckedEmptyIndexedSourceAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    (executionInvariant :
      OriginalSourceFactMixedExecutionInvariant original candidate contract
        reachabilityTargetIds base authority.site.sourceTargetId
        (fun _world state => authority.RuntimeIndexBound state)) :
    CompleteEmptyIndexedSourcePredecessorPremise authority
      (ActualMixedOriginalStackDynamicSource
        executionInvariant.toExtension.strengthen authority.site.sourceTargetId)
    :=
  completeEmptyIndexedSourcePremise_of_mixedProjection
    executionInvariant.projection

theorem IndexedTableMixedOriginalComposition.sourceUninhabited
    {context : OriginalDecodedStaticContext}
    {authority : CheckedEmptyIndexedSourceAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    (composition : IndexedTableMixedOriginalComposition authority invariant) :
    ActualMixedOriginalStackDynamicSourceUninhabited invariant
      authority.site.sourceTargetId := by
  cases composition with
  | unreachable sourceUninhabited => exact sourceUninhabited
  | emptyInterval complete =>
      rintro ⟨world, state, reached⟩
      exact authority.noRuntimeIndex state
        (complete.everyReachableIndexBound world state reached)

theorem IndexedTableMixedOriginalComposition.originalClosure
    {context : OriginalDecodedStaticContext}
    {authority : CheckedEmptyIndexedSourceAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    (composition : IndexedTableMixedOriginalComposition authority invariant) :
    OriginalIndirectControlClosure context authority.site
      (ActualMixedOriginalStackDynamicSource invariant
        authority.site.sourceTargetId) :=
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

/-- The complete dynamic callback fact retained at one admitted source state. -/
structure DynamicCallbackSourceFact
    (context : OriginalDecodedStaticContext)
    (authority : CheckedDynamicCallbackAuthority context)
    (world : RelationalWorld) (state : MachineState) where
  runtime :
    DynamicCallbackControlRuntime context authority.static.claim world state
  callbackAddressChecked :
    dynamicCallbackAddressChecked context runtime.callback = true

noncomputable def completeDynamicCallbackPremise_of_originalProjection
    {program : DecodedWorldProgram}
    {authority : CheckedDynamicCallbackAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    {originalInvariant : OriginalWorldExecutionInvariant program}
    (projection :
      OriginalSourceFactProjection originalInvariant
        authority.static.claim.site.sourceTargetId
        (fun world state =>
          Nonempty (DynamicCallbackSourceFact context authority world state))) :
    CompleteDynamicCallbackPremise context authority
      (ActualMixedOriginalStackDynamicSource
        (strengthenMixedExecutionInvariant mixed originalInvariant)
        authority.static.claim.site.sourceTargetId) where
  runtime world state reached :=
    (Classical.choice
      (originalSourceFact_of_originalProjection projection reached)).runtime
  callbackAddressChecked world state reached := by
    exact
      (Classical.choice
        (originalSourceFact_of_originalProjection projection reached)
      ).callbackAddressChecked

noncomputable def completeDynamicCallbackPremise_of_mixedProjection
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {authority : CheckedDynamicCallbackAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    {extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base}
    (projection :
      OriginalSourceFactMixedProjection extension
        authority.static.claim.site.sourceTargetId
        (fun world state =>
          Nonempty (DynamicCallbackSourceFact context authority world state))) :
    CompleteDynamicCallbackPremise context authority
      (ActualMixedOriginalStackDynamicSource extension.strengthen
        authority.static.claim.site.sourceTargetId) where
  runtime world state reached :=
    (Classical.choice
      (originalSourceFact_of_mixedProjection projection reached)).runtime
  callbackAddressChecked world state reached := by
    exact
      (Classical.choice
        (originalSourceFact_of_mixedProjection projection reached)
      ).callbackAddressChecked

noncomputable def completeDynamicCallbackPremise_of_originalInvariant
    {program : DecodedWorldProgram}
    {authority : CheckedDynamicCallbackAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    (executionInvariant :
      OriginalSourceFactExecutionInvariant program
        authority.static.claim.site.sourceTargetId
        (fun world state =>
          Nonempty (DynamicCallbackSourceFact context authority world state))) :
    CompleteDynamicCallbackPremise context authority
      (ActualMixedOriginalStackDynamicSource
        (strengthenMixedExecutionInvariant mixed
          executionInvariant.toOriginalInvariant)
        authority.static.claim.site.sourceTargetId) :=
  completeDynamicCallbackPremise_of_originalProjection
    executionInvariant.projection

noncomputable def completeDynamicCallbackPremise_of_mixedInvariant
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {authority : CheckedDynamicCallbackAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    (executionInvariant :
      OriginalSourceFactMixedExecutionInvariant original candidate contract
        reachabilityTargetIds base
        authority.static.claim.site.sourceTargetId
        (fun world state =>
          Nonempty (DynamicCallbackSourceFact context authority world state))) :
    CompleteDynamicCallbackPremise context authority
      (ActualMixedOriginalStackDynamicSource
        executionInvariant.toExtension.strengthen
        authority.static.claim.site.sourceTargetId) :=
  completeDynamicCallbackPremise_of_mixedProjection
    executionInvariant.projection

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
#print axioms originalSourceFact_of_originalProjection
#print axioms originalSourceFact_of_mixedProjection
#print axioms originalSourceFact_of_originalInvariant
#print axioms originalSourceFact_of_mixedInvariant
#print axioms actualMixedOriginalStackDynamicSourceUninhabited_of_originalProjection
#print axioms actualMixedOriginalStackDynamicSourceUninhabited_of_mixedProjection
#print axioms actualMixedOriginalStackDynamicSourceUninhabited_of_originalInvariant
#print axioms actualMixedOriginalStackDynamicSourceUninhabited_of_mixedInvariant
#print axioms completeStackCarryPremise_of_originalProjection
#print axioms completeStackCarryPremise_of_mixedProjection
#print axioms completeStackCarryPremise_of_originalInvariant
#print axioms completeStackCarryPremise_of_mixedInvariant
#print axioms completeEmptyIndexedSourcePremise_of_originalProjection
#print axioms completeEmptyIndexedSourcePremise_of_mixedProjection
#print axioms completeEmptyIndexedSourcePremise_of_originalInvariant
#print axioms completeEmptyIndexedSourcePremise_of_mixedInvariant
#print axioms completeDynamicCallbackPremise_of_originalProjection
#print axioms completeDynamicCallbackPremise_of_mixedProjection
#print axioms completeDynamicCallbackPremise_of_originalInvariant
#print axioms completeDynamicCallbackPremise_of_mixedInvariant
#print axioms StackCarryMixedOriginalComposition.targetClosed
#print axioms IndexedTableMixedOriginalComposition.sourceUninhabited
#print axioms DynamicCallbackMixedOriginalComposition.targetClosed
#print axioms sourceUninhabited_of_emptyDynamicCallbackInventory
#print axioms DynamicSourceMixedOriginalComposition.sourceUninhabited
#print axioms DynamicSourceMixedOriginalComposition.originalClosure

end StageA.Relational.StackDynamicIndirectMixedOriginalComposition
