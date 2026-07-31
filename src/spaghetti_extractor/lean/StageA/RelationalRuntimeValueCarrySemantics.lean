import StageA.RelationalRuntimeValueCarry
import StageA.RelationalInternalDirectCallMixedOriginalIntegration
import StageA.RelationalOriginalStackDynamicControlClosure
import StageA.RelationalIndirectExitAdapters
import StageA.RelationalOriginalExecutionInvariant
import StageA.RelationalStackDynamicIndirectMixedOriginalComposition

namespace StageA.Relational.RuntimeValueCarrySemantics

open StageA.Formal StageA.Relational
open StageA.Relational.IndirectExitAdapters
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.InternalDirectCallMixedOriginalIntegration
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.RuntimeValueCarry
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition
open StageA.Relational.StackDynamicIndirectControl
open StageA.Relational.ValueProvenance

/-!
# Semantic authorities for runtime value-carry routes

The compact route checker validates graph shape only. This module records the
semantic authorities that generated modules must consume before a transfer can
be treated as closed.
-/

/-! ## One inductive route invariant -/

def RouteFactsHoldAt
    (context : OriginalDecodedStaticContext) (route : Route) :
    WorldExecution -> Prop :=
  fun execution =>
    forall fact, fact ∈ route.facts ->
      OriginalSourceFactAt fact.targetId
        (fun _world state => route.FactHolds context fact state) execution

/-- One route invariant packages exact incoming-edge coverage and one
inductive proof over the authoritative PE transition system. Individual
transfer authorities are inputs to this proof, not parallel acceptance
mechanisms. -/
structure CheckedRouteExecutionInvariant
    (context : OriginalDecodedStaticContext) (program : DecodedWorldProgram)
    (authority : CheckedRoute context) : Prop where
  programBinding : ExactMixedProgramBinding context program
  stepClosed : forall before,
    RouteFactsHoldAt context authority.route before ->
      RouteFactsHoldAt context authority.route
        (program.pe32TransitionSystem.step before).next

def CheckedRouteExecutionInvariant.toOriginalInvariant
    (invariant : CheckedRouteExecutionInvariant context program authority) :
    OriginalWorldExecutionInvariant program where
  holds := RouteFactsHoldAt context authority.route
  stepClosed := invariant.stepClosed

def CheckedRouteExecutionInvariant.projection
    (invariant : CheckedRouteExecutionInvariant context program authority)
    (fact : Fact) (member : fact ∈ authority.route.facts) :
    OriginalSourceFactProjection invariant.toOriginalInvariant fact.targetId
      (fun _world state => authority.route.FactHolds context fact state) where
  project execution holds := holds fact member

/-! ## Exact decoded local transfers -/

/-- Symbolic value read from a location before a decoded region executes.
Frame words use the same byte-accurate assembled read as normalized writes. -/
def locationInputExpression : Location -> Expr
  | .inRegister register => .inputReg register
  | .inFrameWord register adjustment =>
      (adjustment.expression register).read32AfterWrites []

/-- Symbolic value read from a location after a normalized decoded region.
Frame-word transfer is intentionally accepted only when the base register is
unchanged. More general affine frame movement belongs in a separate checked
claim rather than an implicit approximation here. -/
def locationOutputExpression?
    (behavior : NormalizedSymbolicBehavior) : Location -> Option Expr
  | .inRegister register => some (behavior.registers.get register)
  | .inFrameWord register adjustment =>
      if behavior.registers.get register == .inputReg register then
        some ((adjustment.expression register).read32AfterWrites behavior.writes)
      else
        none

theorem locationInputExpression_eval
    (location : Location) (state : MachineState) :
    (locationInputExpression location).eval state = location.read state := by
  cases location with
  | inRegister register =>
      rfl
  | inFrameWord register adjustment =>
      simp [locationInputExpression, Location.read,
        Expr.eval_read32AfterWrites, applyConcreteWrites,
        evalNormalizedWrites]

theorem locationOutputExpression_eval
    (location : Location) (behavior : NormalizedSymbolicBehavior)
    (output : Expr)
    (found : locationOutputExpression? behavior location = some output)
    (state : MachineState) :
    output.eval state =
      location.read ((behavior.eval state).nextMachineState state) := by
  cases location with
  | inRegister register =>
      simp only [locationOutputExpression?, Option.some.injEq] at found
      subst output
      simp [Location.read, RelationalBehavior.nextMachineState,
        NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  | inFrameWord register adjustment =>
      simp only [locationOutputExpression?] at found
      split at found
      case isFalse unchanged =>
        contradiction
      case isTrue unchanged =>
        have registerExact :
            behavior.registers.get register = .inputReg register :=
          beq_iff_eq.mp unchanged
        simp only [Option.some.injEq] at found
        subst output
        simp [Location.read, RelationalBehavior.nextMachineState,
          NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get,
          registerExact, Expr.eval_read32AfterWrites, Expr.eval]

/-- One local decoded transfer whose exact normalized expression carries the
route value from the named source location to the named target location. -/
structure CheckedDecodedLocalRouteTransfer
    {carrierContext : StaticProofContext}
    (route : Route)
    (behavior : NormalizedSymbolicBehavior) where
  transfer : Transfer
  transferMember : transfer ∈ route.transfers
  sourceRegion : RegionRelation
  sourceTarget : CodeTargetPair
  decodedBehavior : SymbolicBehavior
  sourceTargetExact :
    carrierContext.codeMap.get? transfer.sourceTargetId = some sourceTarget
  sourceRegionExact :
    sourceRegion.id = transfer.sourceTargetId
  sourceRegionStartExact :
    sourceRegion.original.start = sourceTarget.originalRva
  decodedExact :
    regionBehaviorWithMachineCallContracts carrierContext.originalPe
      carrierContext.originalImports carrierContext.machineImportCallContracts
      sourceRegion.original = some decodedBehavior
  normalizedExact :
    normalizeSymbolicBehavior false sourceRegion.targets decodedBehavior =
      some behavior
  sourceLocationId : Nat
  sourceLocation : Location
  targetLocation : Location
  transferKind :
    transfer.kind = .decodedPreserve \/
      transfer.kind = .decodedRegisterToFrame
  transferSourceLocation :
    transfer.sourceLocationId = some sourceLocationId
  sourceLocationExact :
    route.location? sourceLocationId = some sourceLocation
  targetLocationExact :
    route.location? transfer.targetLocationId = some targetLocation
  outputExpression : Expr
  outputExpressionExact :
    locationOutputExpression? behavior targetLocation = some outputExpression
  valueExact :
    outputExpression = locationInputExpression sourceLocation

/-- The local symbolic certificate preserves the route's exact relocated code
value. This theorem is independent of GNU hello and is usable for any decoded
PE32 region whose normalized expression check succeeds. -/
theorem CheckedDecodedLocalRouteTransfer.preservesOriginal
    {carrierContext : StaticProofContext}
    {route : Route} {behavior : NormalizedSymbolicBehavior}
    (binding :
      CheckedDecodedLocalRouteTransfer (carrierContext := carrierContext)
        route behavior)
    (state : MachineState)
    (sourceFact :
      route.FactHolds context {
        targetId := binding.transfer.sourceTargetId
        locationId := binding.sourceLocationId
      } state) :
    route.FactHolds context {
      targetId := binding.transfer.targetTargetId
      locationId := binding.transfer.targetLocationId
    } ((behavior.eval state).nextMachineState state) := by
  rcases sourceFact with
    ⟨sourceLocation, target, sourceLocationExact, targetExact, valueMatches⟩
  have sourceLocationMatches : sourceLocation = binding.sourceLocation := by
    rw [binding.sourceLocationExact] at sourceLocationExact
    exact (Option.some.inj sourceLocationExact).symm
  subst sourceLocation
  refine ⟨binding.targetLocation, target, binding.targetLocationExact,
    targetExact, ?_⟩
  rw [← locationOutputExpression_eval binding.targetLocation behavior
      binding.outputExpression binding.outputExpressionExact state,
    binding.valueExact,
    locationInputExpression_eval binding.sourceLocation state]
  exact valueMatches

/-! ## Register values crossing exact internal calls -/

structure CheckedDirectCallRegisterRouteTransfer
    {carrierContext : StaticProofContext} (route : Route)
    (contract : CheckedDirectCallRegisterControlContract carrierContext) where
  transfer : Transfer
  transferMember : transfer ∈ route.transfers
  sourceLocationId : Nat
  sourceRegister : Reg
  transferKind : transfer.kind = .directCallRegisterPreserve
  transferSourceLocation :
    transfer.sourceLocationId = some sourceLocationId
  sourceLocationExact :
    route.location? sourceLocationId = some (.inRegister sourceRegister)
  targetLocationExact :
    route.location? transfer.targetLocationId =
      some (.inRegister sourceRegister)
  sourceTargetExact :
    contract.sourceTargetId = transfer.sourceTargetId
  continuationTargetExact :
    contract.continuationTargetId = transfer.targetTargetId
  registerRequested : sourceRegister ∈ contract.requestedRegisters

theorem CheckedDirectCallRegisterRouteTransfer.preservesOriginal
    {route : Route}
    {contract : CheckedDirectCallRegisterControlContract carrierContext}
    (binding : CheckedDirectCallRegisterRouteTransfer route contract)
    {entryBinding : ExactDirectCallEntryBinding carrierContext contract.tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution carrierContext contract.tree
      entryBinding originalProgram candidateProgram)
    (sourceFact :
      route.FactHolds originalContext {
        targetId := binding.transfer.sourceTargetId
        locationId := binding.sourceLocationId
      } actual.source.original.state) :
    route.FactHolds originalContext {
      targetId := binding.transfer.targetTargetId
      locationId := binding.transfer.targetLocationId
    } actual.originalExit.state := by
  rcases sourceFact with
    ⟨sourceLocation, target, sourceLocationExact, targetExact, valueMatches⟩
  rw [binding.sourceLocationExact] at sourceLocationExact
  have sourceLocationMatches :
      sourceLocation = .inRegister binding.sourceRegister :=
    (Option.some.inj sourceLocationExact).symm
  subst sourceLocation
  have preserved :=
    contract.preserves actual binding.sourceRegister
      binding.registerRequested
  refine ⟨.inRegister binding.sourceRegister, target,
    binding.targetLocationExact, targetExact, ?_⟩
  simpa [Location.read, preserved.1] using valueMatches

/-- The finite-origin call computes a checked static code target and returns
that exact value in the route's target register. The explicit context bridge
prevents a valid carrier theorem from being attached to a different original
PE or code-map target. -/
structure CheckedFiniteOriginCallResultRouteTransfer
    (originalContext : OriginalDecodedStaticContext)
    {carrierContext : StaticProofContext} (route : Route)
    (contract :
      CheckedFiniteOriginCallRegisterControlContract carrierContext) where
  transfer : Transfer
  transferMember : transfer ∈ route.transfers
  targetRegister : Reg
  transferKind : transfer.kind = .finiteOriginCallResult
  transferSourceLocation : transfer.sourceLocationId = none
  targetLocationExact :
    route.location? transfer.targetLocationId =
      some (.inRegister targetRegister)
  sourceTargetExact :
    contract.entry.sourceTargetId = transfer.sourceTargetId
  continuationTargetExact :
    contract.entry.continuationTargetId = transfer.targetTargetId
  targetRegisterExact : contract.targetRegister = targetRegister
  originExact :
    contract.entry.authority.certificate.target.origin = {
      alternatives := [.staticCodeTarget route.originTargetId 0]
    }
  originalPeExact :
    originalContext.pe = carrierContext.originalPe
  originalTarget : OriginalCodeTarget
  carrierTarget : CodeTargetPair
  originalTargetExact :
    originalContext.codeMap.get? route.originTargetId = some originalTarget
  carrierTargetExact :
    carrierContext.codeMap.get? route.originTargetId = some carrierTarget
  targetRvaExact : originalTarget.rva = carrierTarget.originalRva
  targetAliasesExact :
    originalTarget.aliases = carrierTarget.originalAliases

theorem CheckedFiniteOriginCallResultRouteTransfer.preservesOriginal
    {carrierContext : StaticProofContext}
    {route : Route}
    {contract :
      CheckedFiniteOriginCallRegisterControlContract carrierContext}
    (binding :
      CheckedFiniteOriginCallResultRouteTransfer originalContext route contract)
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualFiniteOriginCallReturnExecution contract.entry
      originalProgram candidateProgram) :
    route.FactHolds originalContext {
      targetId := binding.transfer.targetTargetId
      locationId := binding.transfer.targetLocationId
    } actual.originalExit.state := by
  have carried := contract.carriesTarget actual
  rw [binding.originExact] at carried
  rcases carried with ⟨atom, atomMember, atomHolds⟩
  simp only [List.mem_singleton] at atomMember
  subst atom
  rcases atomHolds with
    ⟨carrierTarget, carrierTargetExact, exactOffset | nonzeroOffset⟩
  · rcases exactOffset with
      ⟨_offsetZero, originalMatches, _candidateMatches⟩
    have carrierTargetMatches : carrierTarget = binding.carrierTarget := by
      rw [binding.carrierTargetExact] at carrierTargetExact
      exact (Option.some.inj carrierTargetExact).symm
    subst carrierTarget
    refine ⟨.inRegister binding.targetRegister, binding.originalTarget,
      binding.targetLocationExact, binding.originalTargetExact, ?_⟩
    rw [binding.targetRegisterExact] at originalMatches
    simpa [Location.read, binding.originalPeExact, binding.targetRvaExact,
      binding.targetAliasesExact] using originalMatches
  · exact (Nat.not_lt_zero _ nonzeroOffset.1).elim

/-- The finite-origin entry adapter used for a checked stack-fixed indirect
call. Keeping this constructor in the runtime-carry layer prevents generated
modules from replacing the generic provenance certificate with a report flag. -/
def checkedStackFiniteOriginCallEntryCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackSlotFixedCodePointerIndirectCallClaim)
    (legacyChecked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (stackFixedIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior :=
  checkedStackFixedIndirectCertificate context sourceInvariant
    originalBehavior candidateBehavior claim legacyChecked genericChecked

/-- A checked route transfer tied to one finite-origin caller-frame contract.
The contract's source, continuation, callee, and requested word are retained as
fields so generated data cannot splice a valid theorem onto a different edge. -/
structure CheckedFiniteOriginCallCallerFrameWordRouteTransfer
    {context : StaticProofContext} (route : Route)
    (contract : CheckedFiniteOriginCallCallerFrameWordControlContract context)
    where
  transfer : Transfer
  transferMember : transfer ∈ route.transfers
  sourceLocationId : Nat
  sourceLocation : Location
  targetLocation : Location
  callerFrameWordOffset : Nat
  transferKind : transfer.kind = .callFrameWordPreserve
  transferSourceLocation :
    transfer.sourceLocationId = some sourceLocationId
  sourceLocationExact :
    route.location? sourceLocationId = some sourceLocation
  targetLocationExact :
    route.location? transfer.targetLocationId = some targetLocation
  sourceLocationShape :
    sourceLocation = .inFrameWord .esp (.add callerFrameWordOffset)
  targetLocationShape :
    targetLocation = .inFrameWord .esp (.add callerFrameWordOffset)
  sourceTargetExact :
    contract.entry.sourceTargetId = transfer.sourceTargetId
  continuationTargetExact :
    contract.entry.continuationTargetId = transfer.targetTargetId
  requestedWord :
    ReturnSlotExactWordPair
  requestedWordExact :
    requestedWord = {
      originalOffset := callerFrameWordOffset
      candidateOffset := callerFrameWordOffset
    }
  requestedWordMember : requestedWord ∈ contract.requestedWords

/-- Apply a checked finite-origin caller-frame contract to the exact locations
named by a runtime value-carry transfer. -/
theorem CheckedFiniteOriginCallCallerFrameWordRouteTransfer.preservesOriginal
    {route : Route}
    {contract : CheckedFiniteOriginCallCallerFrameWordControlContract context}
    (binding :
      CheckedFiniteOriginCallCallerFrameWordRouteTransfer
        route contract)
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualFiniteOriginCallReturnExecution contract.entry
      originalProgram candidateProgram) :
    binding.targetLocation.read actual.originalExit.state =
      binding.sourceLocation.read actual.sourceOriginal.state := by
  have preserved :=
    contract.preserves actual binding.requestedWord
      binding.requestedWordMember
  rw [binding.requestedWordExact] at preserved
  rw [binding.sourceLocationShape, binding.targetLocationShape]
  simpa [Location.read, StackAdjustment.expression, Expr.eval] using preserved.1

/-- Exact direct-call counterpart of the finite-origin route transfer. -/
structure CheckedDirectCallCallerFrameWordRouteTransfer
    {context : StaticProofContext} (route : Route)
    (contract : CheckedDirectCallCallerFrameWordControlContract context)
    where
  transfer : Transfer
  transferMember : transfer ∈ route.transfers
  sourceLocationId : Nat
  sourceLocation : Location
  targetLocation : Location
  callerFrameWordOffset : Nat
  transferKind : transfer.kind = .callFrameWordPreserve
  transferSourceLocation :
    transfer.sourceLocationId = some sourceLocationId
  sourceLocationExact :
    route.location? sourceLocationId = some sourceLocation
  targetLocationExact :
    route.location? transfer.targetLocationId = some targetLocation
  sourceLocationShape :
    sourceLocation = .inFrameWord .esp (.add callerFrameWordOffset)
  targetLocationShape :
    targetLocation = .inFrameWord .esp (.add callerFrameWordOffset)
  sourceTargetExact :
    contract.sourceTargetId = transfer.sourceTargetId
  continuationTargetExact :
    contract.continuationTargetId = transfer.targetTargetId
  requestedWord : ReturnSlotExactWordPair
  requestedWordExact :
    requestedWord = {
      originalOffset := callerFrameWordOffset
      candidateOffset := callerFrameWordOffset
    }
  requestedWordMember : requestedWord ∈ contract.requestedWords

theorem CheckedDirectCallCallerFrameWordRouteTransfer.preservesOriginal
    {route : Route}
    {contract : CheckedDirectCallCallerFrameWordControlContract context}
    (binding :
      CheckedDirectCallCallerFrameWordRouteTransfer
        route contract)
    {entryBinding : ExactDirectCallEntryBinding context contract.tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context contract.tree
      entryBinding originalProgram candidateProgram) :
    binding.targetLocation.read actual.originalExit.state =
      binding.sourceLocation.read actual.source.original.state := by
  have preserved :=
    contract.preserves actual binding.requestedWord
      binding.requestedWordMember
  rw [binding.requestedWordExact] at preserved
  rw [binding.sourceLocationShape, binding.targetLocationShape]
  simpa [Location.read, StackAdjustment.expression, Expr.eval] using preserved.1

/-- The route proves the exact stack word value. This authority is stronger
than `Route.FactHolds`: it is tied to the checked relocated seed and cannot be
created from a route status or graph fact alone. -/
structure CheckedStackCarryRouteSeedValue
    (context : OriginalDecodedStaticContext) (graph : CutpointGraph)
    (route : Route) (authority : CheckedStackCarryAuthority context)
    (fact : Fact) where
  routeChecked : route.checked context graph = true
  factKnown : route.factKnown fact = true
  factTargetExact :
    fact.targetId = authority.static.claim.site.sourceTargetId
  originTargetExact :
    route.originTargetId = authority.static.claim.seed.targetId
  stackRegister : Reg
  adjustment : StackAdjustment
  locationExact :
    route.location? fact.locationId =
      some (.inFrameWord stackRegister adjustment)
  targetShape :
    authority.static.claim.site.target =
      .stackRead stackRegister adjustment
  valueExact :
    forall state, route.FactHolds context fact state ->
      Memory.read32 state.memory
          ((adjustment.expression stackRegister).eval state) =
        authority.static.claim.seed.word context

/-- A checked relocated seed has a unique canonical address because the seed
checker rejects aliases.  Therefore a route fact for the same origin and the
same stack location determines the exact seed word without a separate runtime
assumption. -/
noncomputable def checkedStackCarryRouteSeedValue_of_relocatedOrigin
    {context : OriginalDecodedStaticContext} {graph : CutpointGraph}
    {route : Route} {authority : CheckedStackCarryAuthority context}
    {fact : Fact}
    (routeChecked : route.checked context graph = true)
    (factKnown : route.factKnown fact = true)
    (factTargetExact :
      fact.targetId = authority.static.claim.site.sourceTargetId)
    (originTargetExact :
      route.originTargetId = authority.static.claim.seed.targetId)
    (stackRegister : Reg) (adjustment : StackAdjustment)
    (locationExact :
      route.location? fact.locationId =
        some (.inFrameWord stackRegister adjustment))
    (targetShape :
      authority.static.claim.site.target =
        .stackRead stackRegister adjustment) :
    CheckedStackCarryRouteSeedValue context graph route authority fact := {
  routeChecked
  factKnown
  factTargetExact
  originTargetExact
  stackRegister
  adjustment
  locationExact
  targetShape
  valueExact := by
    intro state factHolds
    rcases factHolds with
      ⟨location, target, factLocation, targetFound, addressMatches⟩
    rw [locationExact] at factLocation
    have locationShape :
        location = .inFrameWord stackRegister adjustment :=
      (Option.some.inj factLocation).symm
    subst location
    rw [originTargetExact] at targetFound
    have seedChecked : authority.static.claim.seed.checked context = true := by
      have checked := authority.static.checked
      unfold StackRelocatedCodePointerClaim.checked at checked
      simp only [Bool.and_eq_true] at checked
      exact checked.1.2
    unfold RelocatedCodePointerSeed.checked at seedChecked
    simp only [Bool.and_eq_true] at seedChecked
    have decodedSeed := seedChecked.2
    cases seedWord :
        readExactRvaU32 context.pe authority.static.claim.seed.slotRva with
    | none =>
        simp [seedWord] at decodedSeed
    | some word =>
        cases seedTarget :
            context.codeMap.get? authority.static.claim.seed.targetId with
        | none =>
            simp [seedWord, seedTarget] at decodedSeed
        | some canonicalTarget =>
            simp only [seedWord, seedTarget, Bool.and_eq_true] at decodedSeed
            have targetShape : target = canonicalTarget := by
              rw [seedTarget] at targetFound
              exact (Option.some.inj targetFound).symm
            subst target
            have aliasesEmpty : canonicalTarget.aliases = [] :=
              List.isEmpty_iff.mp decodedSeed.1.1.2
            simp only [codeAddressMatches, aliasesEmpty, List.any_nil,
              Bool.or_false, beq_iff_eq] at addressMatches
            unfold RelocatedCodePointerSeed.word
            rw [seedTarget]
            simpa [Location.read] using addressMatches
}

/-- Stack allocation membership and slot bounds remain a separate runtime
premise. A value-origin fact does not imply either property. -/
structure CompleteStackCarryRangeSlotPremise
    {context : OriginalDecodedStaticContext} {graph : CutpointGraph}
    {route : Route} {authority : CheckedStackCarryAuthority context}
    {fact : Fact}
    (binding :
      CheckedStackCarryRouteSeedValue context graph route authority fact)
    (reachable : ActualSourceReachability) where
  everyReachableSlotBound :
    forall world state, reachable world state ->
      exists stackRange : DynamicAddressRangePair,
        stackRange ∈ world.stackRanges /\
          stackRange.originalBase.toNat <=
            ((binding.adjustment.expression binding.stackRegister).eval
              state).toNat /\
          ((binding.adjustment.expression binding.stackRegister).eval
              state).toNat + 4 <=
            stackRange.originalBase.toNat + stackRange.size

/-- Close the original stack carry only after composition supplies both the
route's exact seed value and the independent range/slot-bound premise. -/
noncomputable def completeStackCarryPremise_of_checkedRoute
    {context : OriginalDecodedStaticContext} {graph : CutpointGraph}
    {route : Route} {authority : CheckedStackCarryAuthority context}
    {fact : Fact}
    (binding :
      CheckedStackCarryRouteSeedValue context graph route authority fact)
    (reachable : ActualSourceReachability)
    (factHolds :
      forall world state, reachable world state ->
        route.FactHolds context fact state)
    (rangeSlot :
      CompleteStackCarryRangeSlotPremise binding reachable) :
    CompleteStackCarryPremise context authority reachable where
  everyReachableCarriesSeed world state reached := by
    let stackRange := Classical.choose
      (rangeSlot.everyReachableSlotBound world state reached)
    have stackRangeSpec := Classical.choose_spec
      (rangeSlot.everyReachableSlotBound world state reached)
    exact {
      stackRegister := binding.stackRegister
      adjustment := binding.adjustment
      targetShape := binding.targetShape
      stackRange
      stackRangeMember := stackRangeSpec.1
      slotInRange := stackRangeSpec.2
      valueExact := binding.valueExact state (factHolds world state reached)
    }

#print axioms checkedStackFiniteOriginCallEntryCertificate
#print axioms CheckedDecodedLocalRouteTransfer.preservesOriginal
#print axioms CheckedDirectCallRegisterRouteTransfer.preservesOriginal
#print axioms CheckedFiniteOriginCallResultRouteTransfer.preservesOriginal
#print axioms CheckedFiniteOriginCallCallerFrameWordRouteTransfer.preservesOriginal
#print axioms CheckedDirectCallCallerFrameWordRouteTransfer.preservesOriginal
#print axioms checkedStackCarryRouteSeedValue_of_relocatedOrigin
#print axioms completeStackCarryPremise_of_checkedRoute

end StageA.Relational.RuntimeValueCarrySemantics
