import StageA.RelationalInterpreterOriginalCarrierBinding
import StageA.RelationalRegisterIndirectMixedOriginalComposition
import StageA.RelationalStackDynamicIndirectMixedOriginalComposition

namespace StageA.Relational.OriginalIndirectOperationalComposition

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.RegisterIndirectMixedOriginalComposition
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition

/-!
# Exact original indirect-control operational composition

The register and stack/dynamic composition layers prove runtime provenance for
an indirect target.  This module connects those witnesses to the exact decoded
original transition system.  It deliberately separates:

* an actual source admitted by `MixedExecutionInvariant`;
* a checked finite code target and its exact resolver result;
* rooted reachability of the selected target and call continuation; and
* the exact operational endpoint computed from the PE-backed decoder.

The last item is a typed equality over `pe32TransitionSystem.step`.  It cannot
be supplied by a report status, by a target inventory alone, or by the
`Classical.choice` predicate hidden inside an intermediate authority.
-/

/-- A concrete running or callback-running original execution admitted by the
actual mixed invariant.  Keeping the execution as an index prevents a target
authority from manufacturing an unrelated source state. -/
inductive ActualMixedOriginalOperationalSource
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (sourceTargetId : Nat) (world : RelationalWorld)
    (state : MachineState) : WorldExecution -> Prop where
  | running
      (calls : List Nat) (eventIndex : Nat)
      (candidate : InterpreterNativeWorld.NativeWorldExecution)
      (related : invariant.holds
        (.running sourceTargetId state calls eventIndex world) candidate) :
      ActualMixedOriginalOperationalSource invariant sourceTargetId world state
        (.running sourceTargetId state calls eventIndex world)
  | callbackRunning
      (calls : List Nat) (eventIndex : Nat)
      (callbacks : List WorldExternalCallbackRuntime)
      (candidate : InterpreterNativeWorld.NativeWorldExecution)
      (related : invariant.holds
        (.callbackRunning sourceTargetId state calls eventIndex world callbacks)
        candidate) :
      ActualMixedOriginalOperationalSource invariant sourceTargetId world state
        (.callbackRunning sourceTargetId state calls eventIndex world callbacks)

theorem ActualMixedOriginalOperationalSource.toRegisterSource
    (source : ActualMixedOriginalOperationalSource invariant sourceTargetId
      world state before) :
    ActualMixedOriginalRegisterSource invariant sourceTargetId world state := by
  cases source with
  | running calls eventIndex candidate related =>
      exact Or.inl ⟨calls, eventIndex, candidate, related⟩
  | callbackRunning calls eventIndex callbacks candidate related =>
      exact Or.inr ⟨calls, eventIndex, callbacks, candidate, related⟩

theorem ActualMixedOriginalOperationalSource.toStackDynamicSource
    (source : ActualMixedOriginalOperationalSource invariant sourceTargetId
      world state before) :
    ActualMixedOriginalStackDynamicSource invariant sourceTargetId world state := by
  cases source with
  | running calls eventIndex candidate related =>
      exact Or.inl ⟨calls, eventIndex, candidate, related⟩
  | callbackRunning calls eventIndex callbacks candidate related =>
      exact Or.inr ⟨calls, eventIndex, callbacks, candidate, related⟩

theorem operationalSource_of_registerSource
    (reached : ActualMixedOriginalRegisterSource invariant sourceTargetId
      world state) :
    exists before,
      ActualMixedOriginalOperationalSource invariant sourceTargetId world state
        before := by
  rcases reached with
    ⟨calls, eventIndex, candidate, related⟩ |
    ⟨calls, eventIndex, callbacks, candidate, related⟩
  · exact ⟨_, .running calls eventIndex candidate related⟩
  · exact ⟨_, .callbackRunning calls eventIndex callbacks candidate related⟩

theorem operationalSource_of_stackDynamicSource
    (reached : ActualMixedOriginalStackDynamicSource invariant sourceTargetId
      world state) :
    exists before,
      ActualMixedOriginalOperationalSource invariant sourceTargetId world state
        before := by
  rcases reached with
    ⟨calls, eventIndex, candidate, related⟩ |
    ⟨calls, eventIndex, callbacks, candidate, related⟩
  · exact ⟨_, .running calls eventIndex candidate related⟩
  · exact ⟨_, .callbackRunning calls eventIndex callbacks candidate related⟩

/-- Control-stack information carried directly by the checked indirect site. -/
inductive OriginalIndirectContinuationFacts
    (site : OriginalIndirectControlSite) : Prop where
  | call (continuationTargetId : Nat)
      (transferExact : site.transfer = .call continuationTargetId)
  | jump (transferExact : site.transfer = .jump)

theorem originalIndirectContinuationFacts
    (site : OriginalIndirectControlSite) :
    OriginalIndirectContinuationFacts site := by
  cases transfer : site.transfer with
  | call continuationTargetId =>
      exact .call continuationTargetId transfer
  | jump => exact .jump transfer

/-- Membership facts not implied by a finite target authority.  These are
needed to preserve `OriginalExecutionReachable` after the operational step. -/
structure OriginalIndirectReachabilityPremise
    (targetIds : List Nat) (site : OriginalIndirectControlSite)
    (targetId : Nat) : Prop where
  targetReachable : targetId ∈ targetIds
  continuationReachable :
    match site.transfer with
    | .call continuationTargetId => continuationTargetId ∈ targetIds
    | .jump => True

/-- A checked code-map entry and address match resolve uniquely through the
exact original code-map certificate. -/
theorem originalResolvedCodeTarget_resolves
    (authority : ExactOriginalDecodedAuthority context)
    (resolved : OriginalResolvedCodeTarget context site state) :
    context.codeMap.resolveRawEip context.pe.imageBase
        (site.target.expression.eval state) =
      some resolved.targetId := by
  have before := FiniteIndex.get?_eq_some_implies_lt_size
    context.codeMap.entries resolved.targetId resolved.target
    resolved.targetFound
  have roundTrip := authority.codeMap.target_round_trips
    resolved.targetId before
  simp only [OriginalCodeMap.targetRoundTripsAt, resolved.targetFound,
    Bool.and_eq_true] at roundTrip
  have targetExact := resolved.targetExact
  simp only [codeAddressMatches, Bool.or_eq_true] at targetExact
  rcases targetExact with canonical | alias
  · have addressExact := beq_iff_eq.mp canonical
    rw [addressExact]
    exact beq_iff_eq.mp roundTrip.1
  · simp only [List.any_eq_true] at alias
    obtain ⟨matchedAlias, member, addressMatch⟩ := alias
    have aliases := List.all_eq_true.mp roundTrip.2
    have resolves := aliases matchedAlias member
    rw [beq_iff_eq.mp addressMatch]
    exact beq_iff_eq.mp resolves

/-- Resolution through the legacy decoded carrier is a theorem consequence of
its exact one-sided binding, not an independently submitted map assertion. -/
theorem originalResolvedCodeTarget_resolvesInProgram
    (binding : ExactDecodedOriginalCarrierBinding context program)
    (authority : ExactOriginalDecodedAuthority context)
    (resolved : OriginalResolvedCodeTarget context site state) :
    program.context.codeMap.resolveRawEip program.candidate
        (if program.candidate then program.context.candidatePe.imageBase
         else program.context.originalPe.imageBase)
        (site.target.expression.eval state) =
      some resolved.targetId := by
  have contextResolved :=
    originalResolvedCodeTarget_resolves authority resolved
  have carrierResolved :=
    (binding.indexedIndirectResolutionBound
      (site.target.expression.eval state)).trans contextResolved
  simpa [binding.originalRole, binding.peBound] using carrierResolved

/-- Target facts required by the exact decoded-original dispatcher. -/
structure ExactOriginalInternalTargetFacts
    (context : OriginalDecodedStaticContext) (program : DecodedWorldProgram)
    (site : OriginalIndirectControlSite) (state : MachineState) where
  resolved : OriginalResolvedCodeTarget context site state
  contextResolution :
    context.codeMap.resolveRawEip context.pe.imageBase
        (site.target.expression.eval state) =
      some resolved.targetId
  programResolution :
    program.context.codeMap.resolveRawEip program.candidate
        (if program.candidate then program.context.candidatePe.imageBase
         else program.context.originalPe.imageBase)
        (site.target.expression.eval state) =
      some resolved.targetId

def exactOriginalInternalTargetFacts
    (binding : ExactDecodedOriginalCarrierBinding context program)
    (authority : ExactOriginalDecodedAuthority context)
    (resolved : OriginalResolvedCodeTarget context site state) :
    ExactOriginalInternalTargetFacts context program site state := {
  resolved
  contextResolution := originalResolvedCodeTarget_resolves authority resolved
  programResolution :=
    originalResolvedCodeTarget_resolvesInProgram binding authority resolved
}

/-- The exact expected internal-control successor for one decoded PE step.
`afterState` is the state computed by the decoded region semantics. -/
def exactOriginalInternalEndpoint
    (before : WorldExecution) (transfer : IndirectTransferKind)
    (targetId : Nat) (afterState : MachineState) :
    Option WorldExecution :=
  match before with
  | .running _ _ calls eventIndex world =>
      match transfer with
      | .call continuation =>
          some (.running targetId afterState (continuation :: calls)
            eventIndex world)
      | .jump =>
          some (.running targetId afterState calls eventIndex world)
  | .callbackRunning _ _ calls eventIndex world callbacks =>
      match transfer with
      | .call continuation =>
          some (.callbackRunning targetId afterState
            (continuation :: calls) eventIndex world callbacks)
      | .jump =>
          some (.callbackRunning targetId afterState calls eventIndex world
            callbacks)
  | _ => none

/-- The irreducible operational premise left after static target closure.  It
states the exact PE-backed decoder step and exact endpoint.  No weaker status,
inventory, or reachability assertion can construct this value. -/
structure ExactOriginalIndirectStepPremise
    (program : DecodedWorldProgram) (site : OriginalIndirectControlSite)
    (before : WorldExecution) (targetId : Nat)
    (afterState : MachineState) (after : WorldExecution) : Prop where
  endpointExact :
    exactOriginalInternalEndpoint before site.transfer targetId afterState =
      some after
  transitionExact :
    program.pe32TransitionSystem.step before = {
      next := after
      observation := none
    }

/-- An exact nonempty original operational chunk.  The path is derived from
the transition equality rather than submitted as evidence. -/
structure ExactOriginalIndirectOperationalChunk
    (program : DecodedWorldProgram) (site : OriginalIndirectControlSite)
    (before : WorldExecution) (targetId : Nat)
    (afterState : MachineState) (after : WorldExecution) : Prop where
  endpointExact :
    exactOriginalInternalEndpoint before site.transfer targetId afterState =
      some after
  path : NonemptyRelatedPath program.pe32TransitionSystem before [] after

theorem ExactOriginalIndirectStepPremise.toChunk
    (premise : ExactOriginalIndirectStepPremise program site before targetId
      afterState after) :
    ExactOriginalIndirectOperationalChunk program site before targetId
      afterState after := by
  refine {
    endpointExact := premise.endpointExact
    path := ?_
  }
  have one := nonemptyRelatedPath_one program.pe32TransitionSystem before
  rw [premise.transitionExact] at one
  simpa using one

/-- Complete internal-control evidence at one actual mixed source.  The target
and continuation are rooted, the selected address resolves through both exact
maps, and the operational path is the PE-backed decoder path. -/
structure ExactOriginalInternalOperationalClosure
    (context : OriginalDecodedStaticContext) (program : DecodedWorldProgram)
    (reachabilityTargetIds : List Nat) (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (site : OriginalIndirectControlSite) (world : RelationalWorld)
    (state : MachineState) (before : WorldExecution)
    (resolved : OriginalResolvedCodeTarget context site state)
    (afterState : MachineState) (after : WorldExecution) : Prop where
  source :
    ActualMixedOriginalOperationalSource invariant site.sourceTargetId world
      state before
  contextResolution :
    context.codeMap.resolveRawEip context.pe.imageBase
        (site.target.expression.eval state) =
      some resolved.targetId
  programResolution :
    program.context.codeMap.resolveRawEip program.candidate
        (if program.candidate then program.context.candidatePe.imageBase
         else program.context.originalPe.imageBase)
        (site.target.expression.eval state) =
      some resolved.targetId
  reachability :
    OriginalIndirectReachabilityPremise reachabilityTargetIds site
      resolved.targetId
  chunk :
    ExactOriginalIndirectOperationalChunk program site before resolved.targetId
      afterState after

theorem exactOriginalInternalOperationalClosure_of_step
    {context : OriginalDecodedStaticContext}
    {program : DecodedWorldProgram}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {site : OriginalIndirectControlSite}
    {world : RelationalWorld} {state : MachineState}
    {before : WorldExecution}
    {afterState : MachineState} {after : WorldExecution}
    (source : ActualMixedOriginalOperationalSource invariant
      site.sourceTargetId world state before)
    (binding : ExactDecodedOriginalCarrierBinding context program)
    (authority : ExactOriginalDecodedAuthority context)
    (resolved : OriginalResolvedCodeTarget context site state)
    (reachability : OriginalIndirectReachabilityPremise reachabilityTargetIds
      site resolved.targetId)
    (step : ExactOriginalIndirectStepPremise program site before
      resolved.targetId afterState after) :
    ExactOriginalInternalOperationalClosure context program
      reachabilityTargetIds contract invariant site world state before resolved
      afterState after := by
  exact {
    source
    contextResolution := originalResolvedCodeTarget_resolves authority resolved
    programResolution :=
      originalResolvedCodeTarget_resolvesInProgram binding authority resolved
    reachability
    chunk := step.toChunk
  }

/-- Canonical code addresses supplied by checked static inventories are exact
resolved targets. -/
def canonicalOriginalResolvedCodeTarget
    (context : OriginalDecodedStaticContext)
    (site : OriginalIndirectControlSite) (state : MachineState)
    (targetId : Nat) (target : OriginalCodeTarget)
    (found : context.codeMap.get? targetId = some target)
    (valueExact :
      site.target.expression.eval state =
        BitVec.ofNat 32 (context.pe.imageBase + target.rva)) :
    OriginalResolvedCodeTarget context site state := {
  targetId
  target
  targetFound := found
  targetExact := by
    unfold codeAddressMatches
    simp only [Bool.or_eq_true]
    exact Or.inl (beq_iff_eq.mpr valueExact)
}

/-- The current register certificate stores its target-shape check as a `BEq`
fact, but the shared IR does not expose a `LawfulBEq OriginalTargetExpression`
instance.  Until that checker is connected to an equality theorem, the exact
expression/value link remains an explicit typed premise. -/
structure RegisterTargetExpressionPremise
    (authority : CheckedAuthority context) (state : MachineState) : Prop where
  targetExpressionExact :
    authority.certificate.certificate.site.target.expression.eval state =
      state.registers.get authority.certificate.certificate.register

/-- A registered callback target still needs an address-to-code-map proof.
World membership and a target identifier alone do not establish this fact. -/
structure RegisterCallbackAddressFrontier
    (context : OriginalDecodedStaticContext)
    (site : OriginalIndirectControlSite) (state : MachineState) where
  callback : RegisteredCallbackPair
  targetId : Nat
  target : OriginalCodeTarget
  targetIdExact : targetId = callback.targetId
  targetFound : context.codeMap.get? targetId = some target
  targetExpressionExact :
    site.target.expression.eval state = callback.originalAddress

def RegisterCallbackAddressFrontier.AddressChecked
    (frontier : RegisterCallbackAddressFrontier context site state) : Prop :=
  codeAddressMatches context.pe.imageBase frontier.target.rva
    frontier.target.aliases frontier.callback.originalAddress = true

def RegisterCallbackAddressFrontier.resolve
    (frontier : RegisterCallbackAddressFrontier context site state)
    (checked : frontier.AddressChecked) :
    OriginalResolvedCodeTarget context site state := {
  targetId := frontier.targetId
  target := frontier.target
  targetFound := frontier.targetFound
  targetExact := by
    rw [frontier.targetExpressionExact]
    exact checked
}

/-- External register targets are kept separate from internal code targets.
They require the external-call/tail operational layer, not a fabricated code
map resolution. -/
inductive RegisterExternalOperationalFrontier
    (context : OriginalDecodedStaticContext) (world : RelationalWorld)
    (value : Word) : Prop where
  | imported
      (iatRva : Nat) (imported : ExternalTarget) (binding : ImportAddressPair)
      (member : binding ∈ world.importAddresses)
      (identity : binding.imported = imported)
      (iatExact : binding.originalIatRva = iatRva)
      (valueExact : value = binding.originalAddress)
  | resolver
      (queries : List ResolverQuery) (query : ResolverQuery)
      (queryMember : query ∈ queries) (resource : OpaqueResourcePair)
      (member : resource ∈ world.opaqueResources)
      (resourceExact : resource.id = query.resourceId)
      (valueExact : value = resource.original)

/-- Exhaustive operational classification of a checked register target. -/
inductive RegisterIndirectOperationalTarget
    (context : OriginalDecodedStaticContext)
    (authority : CheckedAuthority context)
    (world : RelationalWorld) (state : MachineState) : Prop where
  | internal
      (allowedTargetIds : List Nat)
      (resolved : OriginalResolvedCodeTarget context
        authority.certificate.certificate.site state)
      (allowed : resolved.targetId ∈ allowedTargetIds)
  | external
      (frontier : RegisterExternalOperationalFrontier context world
        (state.registers.get authority.certificate.certificate.register))
  | callbackAddress
      (frontier : RegisterCallbackAddressFrontier context
        authority.certificate.certificate.site state)

theorem RegisterIndirectMixedOriginalComposition.operationalTarget
    {context : OriginalDecodedStaticContext}
    {authority : CheckedAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    {before : WorldExecution}
    (composition : RegisterIndirectMixedOriginalComposition authority invariant)
    (source : ActualMixedOriginalOperationalSource invariant
      authority.certificate.certificate.site.sourceTargetId world state before)
    (expression : RegisterTargetExpressionPremise authority state) :
    RegisterIndirectOperationalTarget context authority world state := by
  have reached := source.toRegisterSource
  rcases composition.targetClosed reached with ⟨member, classified⟩
  have expressionExact := expression.targetExpressionExact
  cases classified with
  | internalCode allowedTargetIds targetId allowed target found valueExact =>
      exact @RegisterIndirectOperationalTarget.internal context authority world
        state allowedTargetIds
        (canonicalOriginalResolvedCodeTarget context
          authority.certificate.certificate.site state targetId target found
          (expressionExact.trans valueExact))
        allowed
  | importedAddress iatRva imported binding worldMember identity iatExact
      valueExact =>
      exact .external (.imported iatRva imported binding worldMember identity
        iatExact valueExact)
  | resolverResource queries query queryMember resource worldMember resourceExact
      valueExact =>
      exact .external (.resolver queries query queryMember resource worldMember
        resourceExact valueExact)
  | registeredCallback allowedTargetIds callback worldMember allowed target found
      valueExact =>
      exact .callbackAddress {
        callback
        targetId := callback.targetId
        target
        targetIdExact := rfl
        targetFound := found
        targetExpressionExact := expressionExact.trans valueExact
      }
  | nullableTableEntry startRva endRva entries index targetId target indexBound
      entry found valueExact =>
      exact @RegisterIndirectOperationalTarget.internal context authority world
        state [targetId]
        (canonicalOriginalResolvedCodeTarget context
          authority.certificate.certificate.site state targetId target found
          (expressionExact.trans valueExact))
        (by simp [canonicalOriginalResolvedCodeTarget])

/-- Stack-carried targets already contain a complete resolved code target. -/
theorem StackCarryMixedOriginalComposition.operationalTarget
    {context : OriginalDecodedStaticContext}
    {authority : CheckedStackCarryAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    {before : WorldExecution}
    (composition : StackCarryMixedOriginalComposition authority invariant)
    (source : ActualMixedOriginalOperationalSource invariant
      authority.static.claim.site.sourceTargetId world state before) :
    Nonempty
      (MixedOriginalStackCarryTarget context authority world state) := by
  have reached : ActualMixedOriginalStackDynamicSource invariant
      authority.static.claim.site.sourceTargetId world state :=
    source.toStackDynamicSource
  exact composition.targetClosed reached

theorem StackCarryMixedOriginalComposition.operationalClosure
    {context : OriginalDecodedStaticContext}
    {program : DecodedWorldProgram}
    {authority : CheckedStackCarryAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    {before : WorldExecution}
    (composition : StackCarryMixedOriginalComposition authority invariant)
    (source : ActualMixedOriginalOperationalSource invariant
      authority.static.claim.site.sourceTargetId world state before)
    (binding : ExactDecodedOriginalCarrierBinding context program)
    (reachability : forall resolved :
      OriginalResolvedCodeTarget context authority.static.claim.site state,
        OriginalIndirectReachabilityPremise reachabilityTargetIds
          authority.static.claim.site resolved.targetId)
    (step : forall resolved :
      OriginalResolvedCodeTarget context authority.static.claim.site state,
        exists afterState after,
          ExactOriginalIndirectStepPremise program authority.static.claim.site
            before resolved.targetId afterState after) :
    exists closed : MixedOriginalStackCarryTarget context authority world state,
      exists afterState after,
        ExactOriginalInternalOperationalClosure context program
          reachabilityTargetIds contract invariant authority.static.claim.site
          world state before closed.resolved afterState after := by
  rcases
      OriginalIndirectOperationalComposition.StackCarryMixedOriginalComposition.operationalTarget
        composition source with
    ⟨closed⟩
  rcases step closed.resolved with ⟨afterState, after, exactStep⟩
  exact ⟨closed, afterState, after,
    exactOriginalInternalOperationalClosure_of_step source binding
      authority.static.authority closed.resolved
      (reachability closed.resolved) exactStep⟩

/-- Dynamic callback targets likewise retain their checked allocation,
registration, field, address, and code-map witnesses. -/
theorem DynamicCallbackMixedOriginalComposition.operationalTarget
    {context : OriginalDecodedStaticContext}
    {authority : CheckedDynamicCallbackAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    {before : WorldExecution}
    (composition : DynamicCallbackMixedOriginalComposition authority invariant)
    (source : ActualMixedOriginalOperationalSource invariant
      authority.static.claim.site.sourceTargetId world state before) :
    Nonempty
      (MixedOriginalDynamicCallbackTarget context authority world state) := by
  have reached : ActualMixedOriginalStackDynamicSource invariant
      authority.static.claim.site.sourceTargetId world state :=
    source.toStackDynamicSource
  exact composition.targetClosed reached

theorem DynamicCallbackMixedOriginalComposition.operationalClosure
    {context : OriginalDecodedStaticContext}
    {program : DecodedWorldProgram}
    {authority : CheckedDynamicCallbackAuthority context}
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    {before : WorldExecution}
    (composition : DynamicCallbackMixedOriginalComposition authority invariant)
    (source : ActualMixedOriginalOperationalSource invariant
      authority.static.claim.site.sourceTargetId world state before)
    (binding : ExactDecodedOriginalCarrierBinding context program)
    (reachability : forall resolved :
      OriginalResolvedCodeTarget context authority.static.claim.site state,
        OriginalIndirectReachabilityPremise reachabilityTargetIds
          authority.static.claim.site resolved.targetId)
    (step : forall resolved :
      OriginalResolvedCodeTarget context authority.static.claim.site state,
        exists afterState after,
          ExactOriginalIndirectStepPremise program authority.static.claim.site
            before resolved.targetId afterState after) :
    exists closed : MixedOriginalDynamicCallbackTarget context authority world state,
      exists afterState after,
        ExactOriginalInternalOperationalClosure context program
          reachabilityTargetIds contract invariant authority.static.claim.site
          world state before closed.resolved afterState after := by
  rcases
      OriginalIndirectOperationalComposition.DynamicCallbackMixedOriginalComposition.operationalTarget
        composition source with
    ⟨closed⟩
  rcases step closed.resolved with ⟨afterState, after, exactStep⟩
  exact ⟨closed, afterState, after,
    exactOriginalInternalOperationalClosure_of_step source binding
      authority.static.authority closed.resolved
      (reachability closed.resolved) exactStep⟩

#print axioms originalResolvedCodeTarget_resolves
#print axioms originalResolvedCodeTarget_resolvesInProgram
#print axioms exactOriginalInternalTargetFacts
#print axioms ExactOriginalIndirectStepPremise.toChunk
#print axioms exactOriginalInternalOperationalClosure_of_step
#print axioms canonicalOriginalResolvedCodeTarget
#print axioms RegisterCallbackAddressFrontier.resolve
#print axioms RegisterIndirectMixedOriginalComposition.operationalTarget
#print axioms StackCarryMixedOriginalComposition.operationalTarget
#print axioms StackCarryMixedOriginalComposition.operationalClosure
#print axioms DynamicCallbackMixedOriginalComposition.operationalTarget
#print axioms DynamicCallbackMixedOriginalComposition.operationalClosure

end StageA.Relational.OriginalIndirectOperationalComposition
