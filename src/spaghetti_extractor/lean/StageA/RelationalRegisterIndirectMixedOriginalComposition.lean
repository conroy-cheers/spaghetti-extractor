import StageA.RelationalRegisterIndirectControlAuthority
import StageA.RelationalOriginalExecutionInvariant
import StageA.RelationalMixedExecutionInvariantExtension

namespace StageA.Relational.RegisterIndirectMixedOriginalComposition

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.MixedExecutionInvariantExtension

/-!
# Register-indirect mixed-original composition

The register-indirect authority checks exact bytes and finite inventories, but
its runtime reachability predicate is deliberately abstract.  This module ties
that predicate to states admitted by an actual `MixedExecutionInvariant`.
Proposal reports and their status fields do not appear in this interface.

Only executable original states are sources: ordinary running states and
callback-running states.  Composition must either include every such state in
the authority's runtime relation or prove that no such state is reachable.
-/

/-- Original source states admitted by a mixed execution invariant. -/
def ActualMixedOriginalRegisterSource
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

def ActualMixedOriginalRegisterSourceUninhabited
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (sourceTargetId : Nat) : Prop :=
  ¬ exists world state,
    ActualMixedOriginalRegisterSource invariant sourceTargetId world state

/-- The original-only fact that a checked register authority needs at its
source.  It is vacuous away from the source target, but at the source it
requires the authority's semantic reachability predicate and the exact
instruction address. -/
def RegisterAuthorityReachableAtSource
    (authority : CheckedAuthority context) : WorldExecution -> Prop
  | .running targetId state _calls _eventIndex world =>
      targetId = authority.certificate.certificate.site.sourceTargetId ->
        exists sourceEip,
          authority.reachable world sourceEip state /\
            sourceEip.toNat =
              context.pe.imageBase +
                authority.certificate.certificate.site.instructionRva
  | .callbackRunning targetId state _calls _eventIndex world _callbacks =>
      targetId = authority.certificate.certificate.site.sourceTargetId ->
        exists sourceEip,
          authority.reachable world sourceEip state /\
            sourceEip.toNat =
              context.pe.imageBase +
                authority.certificate.certificate.site.instructionRva
  | _ => True

/-- A non-circular authority integration package.  The reachability fact must
hold at launch and be preserved by the exact decoded original transition.
`toOriginalInvariant` can therefore be conjoined with whole-program mixed
composition using `strengthenMixedWorldChunkComposition`. -/
structure RegisterAuthorityExecutionInvariant
    (program : DecodedWorldProgram)
    (authority : CheckedAuthority context) : Prop where
  stepClosed : forall before,
    RegisterAuthorityReachableAtSource authority before ->
      RegisterAuthorityReachableAtSource authority
        (program.pe32TransitionSystem.step before).next

def RegisterAuthorityExecutionInvariant.toOriginalInvariant
    {program : DecodedWorldProgram}
    {authority : CheckedAuthority context}
    (invariant : RegisterAuthorityExecutionInvariant program authority) :
    OriginalWorldExecutionInvariant program where
  holds := RegisterAuthorityReachableAtSource authority
  stepClosed := invariant.stepClosed

/-- Paired counterpart of `RegisterAuthorityExecutionInvariant`.  Its closure
proof may use both exact paths and their related external observations, which is
required when the target value is produced or preserved by a call. -/
structure RegisterAuthorityMixedExecutionInvariant
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (authority : CheckedAuthority context)
    (reachabilityTargetIds : List Nat)
    (contract : MixedRelationContract)
    (base : MixedExecutionInvariant reachabilityTargetIds contract) : Prop where
  chunkClosed : forall originalBefore candidateBefore,
    RegisterAuthorityReachableAtSource authority originalBefore ->
      (chunk : MixedWorldComponentChunkRefinement original candidate contract
        base originalBefore candidateBefore) ->
      RegisterAuthorityReachableAtSource authority chunk.originalAfter

def RegisterAuthorityMixedExecutionInvariant.toExtension
    (invariant : RegisterAuthorityMixedExecutionInvariant original candidate
      authority reachabilityTargetIds contract base) :
    MixedWorldExecutionInvariantExtension original candidate contract
      reachabilityTargetIds base where
  holds originalExecution _candidateExecution :=
    RegisterAuthorityReachableAtSource authority originalExecution
  chunkClosed := invariant.chunkClosed

/-- The semantically relevant source fact: when execution is at the checked
indirect site, the concrete register value belongs to its finite inventory.
Unlike `RegisterAuthorityReachableAtSource`, this does not retain historical
carry records after their preservation facts have been consumed. -/
def RegisterAuthorityTargetMemberAtSource
    (authority : CheckedAuthority context) :
    WorldExecution -> NativeWorldExecution -> Prop
  | .running targetId state _calls _eventIndex world, _candidate =>
      targetId = authority.certificate.certificate.site.sourceTargetId ->
        RuntimeTargetMember context world
          (state.registers.get authority.certificate.certificate.register)
          authority.certificate.certificate.inventory
  | .callbackRunning targetId state _calls _eventIndex world _callbacks,
      _candidate =>
      targetId = authority.certificate.certificate.site.sourceTargetId ->
        RuntimeTargetMember context world
          (state.registers.get authority.certificate.certificate.register)
          authority.certificate.certificate.inventory
  | _, _ => True

structure RegisterAuthorityTargetMixedExecutionInvariant
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (authority : CheckedAuthority context)
    (reachabilityTargetIds : List Nat)
    (contract : MixedRelationContract)
    (base : MixedExecutionInvariant reachabilityTargetIds contract) : Prop where
  chunkClosed : forall originalBefore candidateBefore,
    RegisterAuthorityTargetMemberAtSource authority originalBefore
        candidateBefore ->
      (chunk : MixedWorldComponentChunkRefinement original candidate contract
        base originalBefore candidateBefore) ->
      RegisterAuthorityTargetMemberAtSource authority chunk.originalAfter
        chunk.candidateAfter

def RegisterAuthorityTargetMixedExecutionInvariant.toExtension
    (invariant : RegisterAuthorityTargetMixedExecutionInvariant original candidate
      authority reachabilityTargetIds contract base) :
    MixedWorldExecutionInvariantExtension original candidate contract
      reachabilityTargetIds base where
  holds := RegisterAuthorityTargetMemberAtSource authority
  chunkClosed := invariant.chunkClosed

theorem actualMixedOriginalRegisterSource_targetReachable
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (reached : ActualMixedOriginalRegisterSource invariant sourceTargetId
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

/-- A nullable table has at least one concrete non-null target entry. -/
def NullableTableRuntimePopulated (entries : List (Option Nat)) : Prop :=
  exists targetId, some targetId ∈ entries

/-- Inventories whose static shape permits a runtime target.  Callback and
nullable-table inventories are the only checked forms that may otherwise carry
no targets. -/
def RuntimeInventoryPopulated : RegisterTargetInventory -> Prop
  | .registeredCallbackSlot _ targetIds =>
      exists targetId, targetId ∈ targetIds
  | .nullableCodeTable _ _ entries => NullableTableRuntimePopulated entries
  | _ => True

/-- Explicit inclusion of actual mixed-reachable source states in the runtime
relation owned by a checked register authority.  This is the semantic premise
that proposal generation cannot supply. -/
structure MixedRuntimeClosurePremise
    (authority : CheckedAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) :
    Prop where
  reachableIncluded :
    forall world state,
      ActualMixedOriginalRegisterSource invariant
          authority.certificate.certificate.site.sourceTargetId world state ->
        exists sourceEip,
          authority.reachable world sourceEip state /\
            sourceEip.toNat =
              context.pe.imageBase +
                authority.certificate.certificate.site.instructionRva

/-- Actual reached sources are included directly in the checked finite target
inventory.  This is the composition authority; `MixedRuntimeClosurePremise` is
retained only as a compatibility bridge for existing proofs. -/
structure MixedTargetMembershipPremise
    (authority : CheckedAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) :
    Prop where
  targetIncluded :
    forall world state,
      ActualMixedOriginalRegisterSource invariant
          authority.certificate.certificate.site.sourceTargetId world state ->
        RuntimeTargetMember context world
          (state.registers.get authority.certificate.certificate.register)
          authority.certificate.certificate.inventory

theorem mixedRuntimeClosurePremise_of_originalInvariant
    {context : OriginalDecodedStaticContext}
    {program : DecodedWorldProgram}
    {authority : CheckedAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    (executionInvariant :
      RegisterAuthorityExecutionInvariant program authority) :
    MixedRuntimeClosurePremise authority
      (strengthenMixedExecutionInvariant mixed
        executionInvariant.toOriginalInvariant) := by
  refine { reachableIncluded := ?_ }
  intro world state reached
  rcases reached with
    ⟨calls, eventIndex, candidate, related⟩ |
    ⟨calls, eventIndex, callbacks, candidate, related⟩
  · exact related.2 rfl
  · exact related.2 rfl

theorem mixedRuntimeClosurePremise_of_mixedInvariant
    {context : OriginalDecodedStaticContext}
    {original : DecodedWorldProgram}
    {candidate : ExactNativeWorldProgram}
    {authority : CheckedAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    (executionInvariant :
      RegisterAuthorityMixedExecutionInvariant original candidate authority
        reachabilityTargetIds contract base) :
    MixedRuntimeClosurePremise authority
      executionInvariant.toExtension.strengthen := by
  refine { reachableIncluded := ?_ }
  intro world state reached
  rcases reached with
    ⟨calls, eventIndex, candidateExecution, related⟩ |
    ⟨calls, eventIndex, callbacks, candidateExecution, related⟩
  · exact related.2 rfl
  · exact related.2 rfl

theorem MixedRuntimeClosurePremise.runtimeClosure
    {context : OriginalDecodedStaticContext}
    {authority : CheckedAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    (premise : MixedRuntimeClosurePremise authority invariant)
    (reached : ActualMixedOriginalRegisterSource invariant
      authority.certificate.certificate.site.sourceTargetId world state) :
    exists sourceEip,
      Nonempty (RuntimeClosure context authority.certificate.certificate
        world sourceEip state) := by
  rcases premise.reachableIncluded world state reached with
    ⟨sourceEip, authorityReachable, atSource⟩
  exact ⟨sourceEip,
    ⟨authority.runtime world sourceEip state authorityReachable atSource⟩⟩

theorem MixedRuntimeClosurePremise.toTargetMembership
    (premise : MixedRuntimeClosurePremise authority invariant) :
    MixedTargetMembershipPremise authority invariant := by
  refine { targetIncluded := ?_ }
  intro world state reached
  rcases premise.runtimeClosure reached with ⟨_sourceEip, ⟨closure⟩⟩
  exact closure.targetMember

theorem mixedTargetMembershipPremise_of_mixedInvariant
    {context : OriginalDecodedStaticContext}
    {original : DecodedWorldProgram}
    {candidate : ExactNativeWorldProgram}
    {authority : CheckedAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    (executionInvariant :
      RegisterAuthorityTargetMixedExecutionInvariant original candidate authority
        reachabilityTargetIds contract base) :
    MixedTargetMembershipPremise authority
      executionInvariant.toExtension.strengthen := by
  refine { targetIncluded := ?_ }
  intro world state reached
  rcases reached with
    ⟨calls, eventIndex, candidateExecution, related⟩ |
    ⟨calls, eventIndex, callbacks, candidateExecution, related⟩
  · exact related.2 rfl
  · exact related.2 rfl

/-- Composition-facing classification of every runtime target admitted by
`RuntimeClosure`.  Static internal targets remain tied to the exact original
code map; dynamic targets retain their concrete world membership. -/
inductive MixedOriginalRegisterTarget
    (context : OriginalDecodedStaticContext)
    (world : RelationalWorld) (value : Word) : Prop where
  | internalCode
      (allowedTargetIds : List Nat) (targetId : Nat)
      (allowed : targetId ∈ allowedTargetIds)
      (target : OriginalCodeTarget)
      (found : context.codeMap.get? targetId = some target)
      (valueExact :
        value = BitVec.ofNat 32 (context.pe.imageBase + target.rva))
  | importedAddress
      (iatRva : Nat) (imported : ExternalTarget) (binding : ImportAddressPair)
      (member : binding ∈ world.importAddresses)
      (identity : binding.imported = imported)
      (iatExact : binding.originalIatRva = iatRva)
      (valueExact : value = binding.originalAddress)
  | resolverResource
      (queries : List ResolverQuery) (query : ResolverQuery)
      (queryMember : query ∈ queries) (resource : OpaqueResourcePair)
      (member : resource ∈ world.opaqueResources)
      (resourceExact : resource.id = query.resourceId)
      (valueExact : value = resource.original)
  | registeredCallback
      (allowedTargetIds : List Nat) (callback : RegisteredCallbackPair)
      (member : callback ∈ world.registeredCallbacks)
      (allowed : callback.targetId ∈ allowedTargetIds)
      (target : OriginalCodeTarget)
      (found : context.codeMap.get? callback.targetId = some target)
      (valueExact : value = callback.originalAddress)
  | nullableTableEntry
      (startRva endRva : Nat) (entries : List (Option Nat))
      (index targetId : Nat) (target : OriginalCodeTarget)
      (indexBound : index < entries.length)
      (entry : entries[index]? = some (some targetId))
      (found : context.codeMap.get? targetId = some target)
      (valueExact :
        value = BitVec.ofNat 32 (context.pe.imageBase + target.rva))

theorem runtimeTargetMember_toMixedOriginalRegisterTarget
    {context : OriginalDecodedStaticContext}
    {world : RelationalWorld} {value : Word}
    {inventory : RegisterTargetInventory}
    (member : RuntimeTargetMember context world value inventory) :
    MixedOriginalRegisterTarget context world value := by
  cases member with
  | relocatedWritableCode slotRva targetId target found valueExact =>
      exact .internalCode [targetId] targetId (by simp) target found valueExact
  | importedAddress iatRva imported binding worldMember identity iatExact
      valueExact =>
      exact .importedAddress iatRva imported binding worldMember identity
        iatExact valueExact
  | resolverResult queries staticTargetIds query resource queryMember worldMember
      allowed valueExact =>
      exact .resolverResource queries query queryMember resource worldMember
        allowed valueExact
  | resolverStaticTarget queries staticTargetIds targetId target allowed found
      valueExact =>
      exact .internalCode staticTargetIds targetId allowed target found valueExact
  | registeredCallback slotRva targetIds callback worldMember allowed target found
      valueExact =>
      exact .registeredCallback targetIds callback worldMember allowed target found
        valueExact
  | nullableTable startRva endRva entries index targetId target indexBound entry
      found valueExact =>
      exact .nullableTableEntry startRva endRva entries index targetId target
        indexBound entry found valueExact

/-- A register-indirect source is composable only through a populated finite
inventory and a complete mixed-runtime premise, or through a proof that the
actual mixed source is unreachable. -/
inductive RegisterIndirectMixedOriginalComposition
    (authority : CheckedAuthority context)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) :
    Prop where
  | unreachable
      (sourceUninhabited :
        ActualMixedOriginalRegisterSourceUninhabited invariant
          authority.certificate.certificate.site.sourceTargetId)
  | finite
      (inventoryPopulated :
        RuntimeInventoryPopulated authority.certificate.certificate.inventory)
      (runtime : MixedTargetMembershipPremise authority invariant)

theorem RegisterIndirectMixedOriginalComposition.runtimeClosure
    {context : OriginalDecodedStaticContext}
    {authority : CheckedAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    (composition : RegisterIndirectMixedOriginalComposition authority invariant)
    (reached : ActualMixedOriginalRegisterSource invariant
      authority.certificate.certificate.site.sourceTargetId world state) :
    RuntimeTargetMember context world
      (state.registers.get authority.certificate.certificate.register)
      authority.certificate.certificate.inventory := by
  cases composition with
  | unreachable sourceUninhabited =>
      exact False.elim (sourceUninhabited ⟨world, state, reached⟩)
  | finite inventoryPopulated runtime =>
      exact runtime.targetIncluded world state reached

theorem RegisterIndirectMixedOriginalComposition.targetClosed
    {context : OriginalDecodedStaticContext}
    {authority : CheckedAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    (composition : RegisterIndirectMixedOriginalComposition authority invariant)
    (reached : ActualMixedOriginalRegisterSource invariant
      authority.certificate.certificate.site.sourceTargetId world state) :
    RuntimeTargetMember context world
          (state.registers.get authority.certificate.certificate.register)
          authority.certificate.certificate.inventory /\
      MixedOriginalRegisterTarget context world
          (state.registers.get authority.certificate.certificate.register) := by
  have member := composition.runtimeClosure reached
  exact ⟨member, runtimeTargetMember_toMixedOriginalRegisterTarget member⟩

/-- Empty callback target lists cannot inhabit the finite branch. -/
theorem sourceUninhabited_of_emptyCallbackInventory
    {context : OriginalDecodedStaticContext}
    {authority : CheckedAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {slotRva : Nat}
    (composition : RegisterIndirectMixedOriginalComposition authority invariant)
    (inventoryExact :
      authority.certificate.certificate.inventory =
        .registeredCallbackSlot slotRva []) :
    ActualMixedOriginalRegisterSourceUninhabited invariant
      authority.certificate.certificate.site.sourceTargetId := by
  cases composition with
  | unreachable sourceUninhabited => exact sourceUninhabited
  | finite inventoryPopulated runtime =>
      rw [inventoryExact] at inventoryPopulated
      simp [RuntimeInventoryPopulated] at inventoryPopulated

/-- A nullable table with no non-null entry cannot inhabit the finite branch. -/
theorem sourceUninhabited_of_targetlessNullableInventory
    {context : OriginalDecodedStaticContext}
    {authority : CheckedAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {startRva endRva : Nat} {entries : List (Option Nat)}
    (composition : RegisterIndirectMixedOriginalComposition authority invariant)
    (inventoryExact :
      authority.certificate.certificate.inventory =
        .nullableCodeTable startRva endRva entries)
    (targetless : ¬ NullableTableRuntimePopulated entries) :
    ActualMixedOriginalRegisterSourceUninhabited invariant
      authority.certificate.certificate.site.sourceTargetId := by
  cases composition with
  | unreachable sourceUninhabited => exact sourceUninhabited
  | finite inventoryPopulated runtime =>
      rw [inventoryExact] at inventoryPopulated
      exact False.elim (targetless inventoryPopulated)

theorem sourceUninhabited_of_emptyNullableInventory
    {context : OriginalDecodedStaticContext}
    {authority : CheckedAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {startRva endRva : Nat}
    (composition : RegisterIndirectMixedOriginalComposition authority invariant)
    (inventoryExact :
      authority.certificate.certificate.inventory =
        .nullableCodeTable startRva endRva []) :
    ActualMixedOriginalRegisterSourceUninhabited invariant
      authority.certificate.certificate.site.sourceTargetId := by
  apply sourceUninhabited_of_targetlessNullableInventory composition inventoryExact
  simp [NullableTableRuntimePopulated]

#print axioms actualMixedOriginalRegisterSource_targetReachable
#print axioms mixedRuntimeClosurePremise_of_originalInvariant
#print axioms MixedRuntimeClosurePremise.runtimeClosure
#print axioms mixedRuntimeClosurePremise_of_mixedInvariant
#print axioms mixedTargetMembershipPremise_of_mixedInvariant
#print axioms runtimeTargetMember_toMixedOriginalRegisterTarget
#print axioms RegisterIndirectMixedOriginalComposition.targetClosed
#print axioms sourceUninhabited_of_emptyCallbackInventory
#print axioms sourceUninhabited_of_targetlessNullableInventory

end StageA.Relational.RegisterIndirectMixedOriginalComposition
