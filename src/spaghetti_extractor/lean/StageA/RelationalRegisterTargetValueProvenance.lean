import StageA.RelationalCallableExternalValueProvenance
import StageA.RelationalRegisterIndirectMixedOriginalComposition

namespace StageA.Relational.RegisterTargetValueProvenance

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.CallableExternalValueProvenance
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.ValueProvenance

/-!
# Value provenance for finite register-target inventories

This module connects the shared paired value-origin language to the finite
original target inventories consumed by indirect-control composition.  It
contains no instruction recognizers: exact segment and external-call proofs
produce the origin witnesses, and these lemmas classify their original value.
-/

structure RegisterTargetWorldFrame
    (before after : RelationalWorld) : Prop where
  imports : forall binding, binding ∈ before.importAddresses ->
    binding ∈ after.importAddresses
  resources : forall resource, resource ∈ before.opaqueResources ->
    resource ∈ after.opaqueResources
  callbacks : forall callback, callback ∈ before.registeredCallbacks ->
    callback ∈ after.registeredCallbacks

def RegisterTargetWorldFrame.same (world : RelationalWorld) :
    RegisterTargetWorldFrame world world := {
  imports := fun _ member => member
  resources := fun _ member => member
  callbacks := fun _ member => member
}

structure CheckedImportedRegisterCallFrame
    (context : StaticProofContext)
    (contract : MachineImportCallContract)
    (relation : ImportRegisterRelation) : Prop where
  imported : contract.imported = relation.imported
  preservationChecked :
    ExternalImportRegisterPreservationClaim.checked contract {
      source := relation
      target := relation
    } = true

theorem CheckedImportedRegisterCallFrame.afterExternal
    (frame : CheckedImportedRegisterCallFrame context contract relation)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (sourceHolds : relation.holds originalEvent.world
      originalEvent.state.registers candidateEvent.state.registers = true)
    (pairConforms : ExactExternalCallPairConforms context contract
      originalEvent candidateEvent originalResult candidateResult) :
    relation.holds originalResult.world originalResult.state.registers
      candidateResult.state.registers = true := by
  exact externalImportRegisterPreservationHolds_of_checked context contract
    { source := relation, target := relation }
    originalEvent candidateEvent originalResult candidateResult
    frame.preservationChecked sourceHolds pairConforms

theorem CheckedImportedRegisterCallFrame.originalTargetMemberAfterExternal
    (frame : CheckedImportedRegisterCallFrame context contract relation)
    (originalContext :
      InterpreterMixedContext.OriginalDecodedStaticContext)
    (iatRva : Nat)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (iatExact : forall binding,
      binding ∈ originalResult.world.importAddresses ->
      binding.imported = relation.imported ->
      binding.originalIatRva = iatRva)
    (sourceHolds : relation.holds originalEvent.world
      originalEvent.state.registers candidateEvent.state.registers = true)
    (pairConforms : ExactExternalCallPairConforms context contract
      originalEvent candidateEvent originalResult candidateResult) :
    RuntimeTargetMember originalContext originalResult.world
      (originalResult.state.registers.get relation.original)
      (.importedAddress iatRva relation.imported) := by
  have targetHolds := frame.afterExternal originalEvent candidateEvent
    originalResult candidateResult sourceHolds pairConforms
  simp only [ImportRegisterRelation.holds, List.any_eq_true] at targetHolds
  rcases targetHolds with ⟨binding, member, checks⟩
  simp only [Bool.and_eq_true, beq_iff_eq] at checks
  rcases checks with ⟨⟨identity, originalExact⟩, _candidateExact⟩
  exact .importedAddress iatRva relation.imported binding member identity
    (iatExact binding member identity) originalExact

theorem _root_.StageA.Relational.RegisterIndirectControlAuthority.RuntimeTargetMember.worldFrame
    (frame : RegisterTargetWorldFrame before after)
    (member : RuntimeTargetMember context before value inventory) :
    RuntimeTargetMember context after value inventory := by
  cases member with
  | relocatedWritableCode slotRva targetId target found valueExact =>
      exact .relocatedWritableCode slotRva targetId target found valueExact
  | importedAddress iatRva imported binding bindingMember identity iatExact
      valueExact =>
      exact .importedAddress iatRva imported binding
        (frame.imports binding bindingMember) identity iatExact valueExact
  | resolverResult queries staticTargetIds query resource queryMember
      resourceMember allowed valueExact =>
      exact .resolverResult queries staticTargetIds query resource queryMember
        (frame.resources resource resourceMember) allowed valueExact
  | resolverStaticTarget queries staticTargetIds targetId target allowed found
      valueExact =>
      exact .resolverStaticTarget queries staticTargetIds targetId target allowed
        found valueExact
  | registeredCallback slotRva targetIds callback callbackMember allowed target
      found valueExact =>
      exact .registeredCallback slotRva targetIds callback
        (frame.callbacks callback callbackMember) allowed target found valueExact
  | nullableTable startRva endRva entries index targetId target indexBound entry
      found valueExact =>
      exact .nullableTable startRva endRva entries index targetId target indexBound
        entry found valueExact

theorem _root_.StageA.Relational.RegisterIndirectControlAuthority.RuntimeTargetMember.of_registerPreserved
    {before after : MachineState}
    (member : RuntimeTargetMember context world
      (before.registers.get register) inventory)
    (preserved :
      after.registers.get register = before.registers.get register) :
    RuntimeTargetMember context world
      (after.registers.get register) inventory := by
  rw [preserved]
  exact member

theorem _root_.StageA.Relational.RegisterIndirectControlAuthority.RuntimeTargetMember.of_registerAndWorldFrame
    {before after : MachineState}
    (member : RuntimeTargetMember context beforeWorld
      (before.registers.get register) inventory)
    (frame : RegisterTargetWorldFrame beforeWorld afterWorld)
    (preserved :
      after.registers.get register = before.registers.get register) :
    RuntimeTargetMember context afterWorld
      (after.registers.get register) inventory := by
  rw [preserved]
  exact member.worldFrame frame

theorem importOrigin_toRuntimeTargetMember
    (staticContext : StaticProofContext)
    (originalContext :
      InterpreterMixedContext.OriginalDecodedStaticContext)
    (world : RelationalWorld)
    (originalValue candidateValue : Word)
    (iatRva : Nat) (identity : ExternalTarget)
    (origin : ValueOriginAtom.Holds staticContext world originalValue
      candidateValue (.importTarget identity))
    (iatExact : forall binding,
      binding ∈ world.importAddresses ->
      binding.imported = identity ->
      binding.originalIatRva = iatRva) :
    RuntimeTargetMember originalContext world originalValue
      (.importedAddress iatRva identity) := by
  rcases origin with
    ⟨binding, member, bindingIdentity, originalExact, _candidateExact⟩
  exact .importedAddress iatRva identity binding member bindingIdentity
    (iatExact binding member bindingIdentity) originalExact

theorem callbackOrigin_toRuntimeTargetMember
    (staticContext : StaticProofContext)
    (originalContext :
      InterpreterMixedContext.OriginalDecodedStaticContext)
    (world : RelationalWorld)
    (originalValue candidateValue : Word)
    (slotRva targetId : Nat) (targetIds : List Nat)
    (origin : ValueOriginAtom.Holds staticContext world originalValue
      candidateValue (.registeredCallback targetId))
    (allowed : targetId ∈ targetIds)
    (target : OriginalCodeTarget)
    (found : originalContext.codeMap.get? targetId = some target) :
    RuntimeTargetMember originalContext world originalValue
      (.registeredCallbackSlot slotRva targetIds) := by
  rcases origin with
    ⟨callback, member, callbackTarget, originalExact, _candidateExact⟩
  exact .registeredCallback slotRva targetIds callback member
    (callbackTarget ▸ allowed) target
    (callbackTarget ▸ found) originalExact

theorem ResolverCapabilityResultRelated.runtimeTargetMember
    (staticContext : StaticProofContext)
    (originalContext :
      InterpreterMixedContext.OriginalDecodedStaticContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (related : ResolverCapabilityResultRelated staticContext site machine resolver
      capability originalEvent candidateEvent originalResult candidateResult)
    (nonzero : originalResult.state.registers.get resolver.resultRegister !=
      BitVec.ofNat 32 0)
    (queries : List ResolverQuery) (staticTargetIds : List Nat)
    (query : ResolverQuery) (queryMember : query ∈ queries)
    (resourceId : query.resourceId = capability.resourceId) :
    RuntimeTargetMember originalContext originalResult.world
      (originalResult.state.registers.get resolver.resultRegister)
      (.resolverResults queries staticTargetIds) := by
  rcases
      CallableExternalValueProvenance.ResolverCapabilityResultRelated.resultOriginHolds
        staticContext site machine resolver capability originalEvent candidateEvent
        originalResult candidateResult related nonzero with
    ⟨resource, member, resourceExact, originalExact, _candidateExact⟩
  exact .resolverResult queries staticTargetIds query resource queryMember member
    (resourceExact.trans resourceId.symm) originalExact

theorem ExactlyOneFreshCallableResourceIssued.registerTargetWorldFrame
    (context : StaticProofContext)
    (before after : RelationalWorld)
    (resource : OpaqueResourcePair)
    (issued : ExactlyOneFreshCallableResourceIssued context before after resource) :
    RegisterTargetWorldFrame before after := by
  refine {
    imports := ?_
    resources := ?_
    callbacks := ?_
  }
  · intro binding member
    rw [issued.2.2.2.1]
    exact member
  · intro prior member
    rw [issued.2.2.2.2.2.2]
    exact List.mem_append_left _ member
  · intro callback member
    rw [issued.2.2.2.2.1]
    exact member

#print axioms RuntimeTargetMember.worldFrame
#print axioms RuntimeTargetMember.of_registerAndWorldFrame
#print axioms CheckedImportedRegisterCallFrame.afterExternal
#print axioms CheckedImportedRegisterCallFrame.originalTargetMemberAfterExternal
#print axioms importOrigin_toRuntimeTargetMember
#print axioms callbackOrigin_toRuntimeTargetMember
#print axioms ResolverCapabilityResultRelated.runtimeTargetMember
#print axioms ExactlyOneFreshCallableResourceIssued.registerTargetWorldFrame

end StageA.Relational.RegisterTargetValueProvenance
