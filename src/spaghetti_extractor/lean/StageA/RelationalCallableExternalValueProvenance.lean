import StageA.RelationalCallableExternalCapability
import StageA.RelationalValueProvenance

namespace StageA.Relational.CallableExternalValueProvenance

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.ValueProvenance

/-! # Resolver results as ordinary value provenance

Callable resolver results use the same finite origin language as registers,
writable words, stack fields, and indirect exits.  This module is deliberately
a bridge: the lower capability layer proves resource issuance without
depending on provenance, while this layer gives the issued pair its common
`ValueOriginAtom` interpretation.
-/

def resolverResultValueClaim
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability) : PairedValueClaim := {
  original := .inputReg resolver.resultRegister
  candidate := .inputReg resolver.resultRegister
  source := .register resolver.resultRegister resolver.resultRegister
  origin := { alternatives := [.opaqueResource capability.resourceId] }
}

def resolverResultRegisterOriginRelation
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability) :
    RegisterValueOriginRelation := {
  original := resolver.resultRegister
  candidate := resolver.resultRegister
  finiteAlternativeBudget := 1
  origins := [.opaqueResource capability.resourceId]
}

/-- Resolver issuance extends only the opaque-resource inventory. Every value
origin valid before the call therefore remains valid in the successor world,
including pre-existing opaque resources. -/
theorem ExactlyOneFreshCallableResourceIssued.valueOriginsPreserved
    (context : StaticProofContext)
    (before after : RelationalWorld)
    (resource : OpaqueResourcePair)
    (issued : ExactlyOneFreshCallableResourceIssued context before after resource)
    (origins : List ValueOriginAtom) :
    ValueOriginsPreserved context before after origins := by
  intro origin _member original candidate holds
  cases origin with
  | exactBits _ | staticCodeTarget _ _ | staticDataLocation _ _ =>
      exact holds
  | importTarget identity =>
      rcases holds with
        ⟨binding, bindingMember, bindingIdentity, originalExact,
          candidateExact⟩
      refine ⟨binding, ?_, bindingIdentity, originalExact, candidateExact⟩
      rw [issued.2.2.2.1]
      exact bindingMember
  | stackFrameLocation rangeId offset =>
      rcases holds with
        ⟨range, rangeMember, rangeIdExact, offsetBound, originalExact,
          candidateExact⟩
      refine ⟨range, ?_, rangeIdExact, offsetBound, originalExact,
        candidateExact⟩
      rw [issued.2.2.1]
      exact rangeMember
  | dynamicRangeLocation rangeId offset =>
      rcases holds with
        ⟨range, rangeMember, rangeIdExact, offsetBound, originalExact,
          candidateExact⟩
      refine ⟨range, ?_, rangeIdExact, offsetBound, originalExact,
        candidateExact⟩
      rw [issued.2.1]
      exact rangeMember
  | opaqueResource resourceId =>
      rcases holds with
        ⟨prior, priorMember, priorId, originalExact, candidateExact⟩
      refine ⟨prior, ?_, priorId, originalExact, candidateExact⟩
      rw [issued.2.2.2.2.2.2]
      exact List.mem_append_left _ priorMember
  | registeredCallback targetId =>
      rcases holds with
        ⟨callback, callbackMember, callbackTarget, originalExact,
          candidateExact⟩
      refine ⟨callback, ?_, callbackTarget, originalExact, candidateExact⟩
      rw [issued.2.2.2.2.1]
      exact callbackMember

theorem resolverResultValueClaim_checked
    (context : StaticProofContext)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability) :
    (resolverResultValueClaim resolver capability).checked context 1 = true := by
  simp [resolverResultValueClaim, PairedValueClaim.checked, ValueSource.checked,
    ValueOrigin.checked, ValueOriginAtom.checked]
  rw [List.eraseDups_cons]
  rfl

theorem ResolverCapabilityResultRelated.resultOriginHolds
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (related : ResolverCapabilityResultRelated context site machine resolver
      capability originalEvent candidateEvent originalResult candidateResult)
    (nonzero : originalResult.state.registers.get resolver.resultRegister !=
      BitVec.ofNat 32 0) :
    ValueOriginAtom.Holds context originalResult.world
      (originalResult.state.registers.get resolver.resultRegister)
      (candidateResult.state.registers.get resolver.resultRegister)
      (.opaqueResource capability.resourceId) := by
  rcases related.resolvedResultPair context site machine resolver capability
      originalEvent candidateEvent originalResult candidateResult nonzero with
    ⟨resource, member, resourceId, originalValue, candidateValue⟩
  exact ⟨resource, member, resourceId, originalValue, candidateValue⟩

theorem ResolverCapabilityResultRelated.resultValueClaimHolds
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (related : ResolverCapabilityResultRelated context site machine resolver
      capability originalEvent candidateEvent originalResult candidateResult)
    (nonzero : originalResult.state.registers.get resolver.resultRegister !=
      BitVec.ofNat 32 0) :
    (resolverResultValueClaim resolver capability).Holds context
      originalResult.world originalResult.state candidateResult.state := by
  refine ⟨.opaqueResource capability.resourceId, by simp [resolverResultValueClaim],
    ?_⟩
  simpa [resolverResultValueClaim, Expr.eval] using
    resultOriginHolds context site machine resolver capability originalEvent
      candidateEvent originalResult candidateResult related nonzero

theorem ResolverCapabilityResultRelated.resultRegisterOriginHolds
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (related : ResolverCapabilityResultRelated context site machine resolver
      capability originalEvent candidateEvent originalResult candidateResult)
    (nonzero : originalResult.state.registers.get resolver.resultRegister !=
      BitVec.ofNat 32 0) :
    (resolverResultRegisterOriginRelation resolver capability).holds context
      originalResult.world originalResult.state.registers
      candidateResult.state.registers = true := by
  apply ValueProvenance.RegisterValueOriginRelation.holds_of_valueClaim
    context originalResult.world
    (resolverResultRegisterOriginRelation resolver capability)
    (resolverResultValueClaim resolver capability)
    originalResult.state candidateResult.state
  · rfl
  · rfl
  · rfl
  · exact resultValueClaimHolds context site machine resolver capability
      originalEvent candidateEvent originalResult candidateResult related nonzero

/-- Strengthen the resolver continuation with the exact callable origin that
the environment refinement produced. No other invariant component changes. -/
theorem ResolverCapabilityResultRelated.targetStateWithResultOrigin
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (related : ResolverCapabilityResultRelated context site machine resolver
      capability originalEvent candidateEvent originalResult candidateResult)
    (nonzero : originalResult.state.registers.get resolver.resultRegister !=
      BitVec.ofNat 32 0) :
    StateRel context originalResult.world
      (ValueProvenance.StateInvariant.withAdditionalRegisterValueOriginRelations
        site.targetInvariant
        [resolverResultRegisterOriginRelation resolver capability])
      originalResult.state candidateResult.state := by
  apply ValueProvenance.StateRel.withAdditionalRegisterValueOriginRelations
    context originalResult.world site.targetInvariant
    [resolverResultRegisterOriginRelation resolver capability]
    originalResult.state candidateResult.state related.targetState
  simp only [registerValueOriginRelationsHold, List.all_cons, List.all_nil,
    Bool.and_eq_true]
  exact ⟨resultRegisterOriginHolds context site machine resolver capability
    originalEvent candidateEvent originalResult candidateResult related nonzero,
    trivial⟩

theorem ResolverCapabilityResultRelated.resultFiniteRelationHolds
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (related : ResolverCapabilityResultRelated context site machine resolver
      capability originalEvent candidateEvent originalResult candidateResult)
    (nonzero : originalResult.state.registers.get resolver.resultRegister !=
      BitVec.ofNat 32 0)
    (finiteAlternativeBudget : Nat) (origins : List ValueOriginAtom)
    (member : .opaqueResource capability.resourceId ∈ origins) :
    (StaticWordRelationKind.finiteOrigins finiteAlternativeBudget origins).holds
        context originalResult.world
        (originalResult.state.registers.get resolver.resultRegister)
        (candidateResult.state.registers.get resolver.resultRegister) = true := by
  exact ValueOriginAtom.finiteRelationHolds_of_holds context originalResult.world
    _ _ finiteAlternativeBudget origins (.opaqueResource capability.resourceId)
    member
    (resultOriginHolds context site machine resolver capability originalEvent
      candidateEvent originalResult candidateResult related nonzero)

def ResolverCapabilityResultRelated.staticWordUpdate
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (related : ResolverCapabilityResultRelated context site machine resolver
      capability originalEvent candidateEvent originalResult candidateResult)
    (nonzero : originalResult.state.registers.get resolver.resultRegister !=
      BitVec.ofNat 32 0)
    (location : PairedStaticWordLocation context)
    (finiteAlternativeBudget : Nat) (origins : List ValueOriginAtom)
    (relation :
      location.slot.relation =
        .finiteOrigins finiteAlternativeBudget origins)
    (member : .opaqueResource capability.resourceId ∈ origins) :
    PairedStaticWordUpdate context originalResult.world := {
  location
  originalValue := originalResult.state.registers.get resolver.resultRegister
  candidateValue := candidateResult.state.registers.get resolver.resultRegister
  valuesRelated := by
    rw [relation]
    exact resultFiniteRelationHolds context site machine resolver capability
      originalEvent candidateEvent originalResult candidateResult related nonzero
      finiteAlternativeBudget origins member
}

/-- Preserve every authoritative memory family while a post-resolver internal
segment stores the callable result into a checked finite-origin static slot.
All non-memory state obligations and exact decoded writes remain explicit. -/
theorem ResolverCapabilityResultRelated.afterStaticWordUpdate
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (related : ResolverCapabilityResultRelated context site machine resolver
      capability originalEvent candidateEvent originalResult candidateResult)
    (nonzero : originalResult.state.registers.get resolver.resultRegister !=
      BitVec.ofNat 32 0)
    (targetInvariant : StateInvariant)
    (location : PairedStaticWordLocation context)
    (finiteAlternativeBudget : Nat) (origins : List ValueOriginAtom)
    (relation :
      location.slot.relation =
        .finiteOrigins finiteAlternativeBudget origins)
    (member : .opaqueResource capability.resourceId ∈ origins)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (contextValid : context.StructurallyValid)
    (originalWrites :
      originalBehavior.writes =
        [(location.originalAddress,
          originalResult.state.registers.get resolver.resultRegister)])
    (candidateWrites :
      candidateBehavior.writes =
        [(location.candidateAddress,
          candidateResult.state.registers.get resolver.resultRegister)])
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
    (registers : registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets originalResult.world)
      targetInvariant.registerRelations originalBehavior.registers
      candidateBehavior.registers = true)
    (bounds : boundsRelated targetInvariant.bounds originalBehavior.registers
      candidateBehavior.registers = true)
    (separations : addressSeparationsRelated targetInvariant.addressSeparations
      originalBehavior.registers candidateBehavior.registers = true)
    (stackWindows : stackWindowsRelated originalResult.world
      targetInvariant.stackWindows originalBehavior.registers
      candidateBehavior.registers = true)
    (x87 : (originalBehavior.nextMachineState originalResult.state).x87 =
      (candidateBehavior.nextMachineState candidateResult.state).x87)
    (flags : flagsRelated targetInvariant.flagBits originalBehavior.eflags
      candidateBehavior.eflags = true)
    (importRegisters : importRegisterRelationsHold originalResult.world
      targetInvariant.importRegisterRelations originalBehavior.registers
      candidateBehavior.registers = true)
    (originRegisters : registerValueOriginRelationsHold context
      originalResult.world targetInvariant.registerValueOriginRelations
      originalBehavior.registers candidateBehavior.registers = true)
    (memoryOrigins : memoryValueOriginRelationsHold context originalResult.world
      targetInvariant.memoryValueOriginRelations
      (originalBehavior.nextMachineState originalResult.state)
      (candidateBehavior.nextMachineState candidateResult.state) = true)
    (dynamicRegisters : activeDynamicRegisterRangeRelationsHold context
      originalResult.world targetInvariant.dynamicRegisterRangeRelations
      (originalBehavior.nextMachineState originalResult.state)
      (candidateBehavior.nextMachineState candidateResult.state) = true)
    (dynamicStacks : activeDynamicStackRangeRelationsHold context
      originalResult.world targetInvariant.dynamicStackRangeRelations
      (originalBehavior.nextMachineState originalResult.state)
      (candidateBehavior.nextMachineState candidateResult.state) = true)
    (predicates : pairedStatePredicatesHold targetInvariant.predicates
      (originalBehavior.nextMachineState originalResult.state)
      (candidateBehavior.nextMachineState candidateResult.state) = true) :
    StateRel context originalResult.world targetInvariant
      (originalBehavior.nextMachineState originalResult.state)
      (candidateBehavior.nextMachineState candidateResult.state) := by
  let update := staticWordUpdate context site machine resolver capability
    originalEvent candidateEvent originalResult candidateResult related nonzero
    location finiteAlternativeBudget origins relation member
  exact StateRel.afterPairedPreparedWordUpdatesEvaluation context
    originalResult.world site.targetInvariant targetInvariant originalResult.state
    candidateResult.state originalBehavior candidateBehavior
    [.staticWord update] contextValid related.targetState
    (by simpa [update, ResolverCapabilityResultRelated.staticWordUpdate,
      PairedPreparedWordUpdate.originalWrite,
      PairedStaticWordUpdate.originalWrite] using originalWrites)
    (by simpa [update, ResolverCapabilityResultRelated.staticWordUpdate,
      PairedPreparedWordUpdate.candidateWrite,
      PairedStaticWordUpdate.candidateWrite] using candidateWrites)
    originalNoX87 candidateNoX87 registers bounds separations stackWindows x87
    flags importRegisters originRegisters memoryOrigins dynamicRegisters dynamicStacks
    predicates

end StageA.Relational.CallableExternalValueProvenance
