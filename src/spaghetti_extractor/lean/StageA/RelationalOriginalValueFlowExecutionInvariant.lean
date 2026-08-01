import StageA.RelationalControlValueProvenance
import StageA.RelationalOriginalCallFrameExecutionInvariant
import StageA.RelationalRegisterIndirectControlAuthority

namespace StageA.Relational.OriginalValueFlowExecutionInvariant

open StageA.Formal StageA.Relational
open StageA.Relational.ControlValueProvenance
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.ValueProvenance

/-!
# One-sided original value-flow execution invariants

This module gives original-only value provenance one inductive home.  A fact
names a finite set of logical execution targets, one concrete control-value
location, and a bounded finite set of shared `ValueOriginAtom` witnesses.  It
is a predicate over the authoritative `WorldExecution`; it is not an analysis
history and does not contain a status or an assumed runtime closure.

Local propagation is tied to exact PE bytes through checked decoding and
normalization.  Calls use exact transition paths and explicit value/world
frames.  Program adapters still have to prove one exact `stepClosed` theorem
for their complete fact inventory.
-/

def originalLocationValue
    (location : ControlValueProvenance.Location) (state : MachineState) : Word :=
  location.inputExpr.eval state

/-- One finite value fact.  The checked fields prevent an empty or unbounded
origin disjunction from becoming a proof-level widening. -/
structure OriginalFiniteValueFlowFact (context : StaticProofContext) where
  id : Nat
  targetIds : List Nat
  targetIdsNonempty : targetIds ≠ []
  targetIdsUnique : targetIds.Nodup
  location : ControlValueProvenance.Location
  locationChecked : location.checked = true
  finiteAlternativeBudget : Nat
  finiteAlternativeBudgetPositive : 0 < finiteAlternativeBudget
  alternatives : List ValueOriginAtom
  alternativesNonempty : alternatives ≠ []
  alternativesUnique : alternatives.Nodup
  alternativesWithinBudget : alternatives.length <= finiteAlternativeBudget
  alternativesChecked : forall origin,
    origin ∈ alternatives -> origin.checked context = true

def OriginalFiniteValueFlowFact.HoldsAt
    {context : StaticProofContext}
    (fact : OriginalFiniteValueFlowFact context)
    (state : MachineState) (world : RelationalWorld) : Prop :=
  exists origin, origin ∈ fact.alternatives /\
    OriginalValueOriginAtomHolds context world
      (originalLocationValue fact.location state) origin

/-- Awaiting calls retain the value at the suspended machine state whenever
either endpoint of that external edge is named.  This keeps external return
transport explicit instead of dropping the fact while the call is pending. -/
def OriginalFiniteValueFlowFact.Holds
    {context : StaticProofContext}
    (fact : OriginalFiniteValueFlowFact context) : WorldExecution -> Prop
  | .running targetId state _calls _eventIndex world =>
      targetId ∈ fact.targetIds -> fact.HoldsAt state world
  | .callbackRunning targetId state _calls _eventIndex world _callbacks =>
      targetId ∈ fact.targetIds -> fact.HoldsAt state world
  | .awaitingExternal suspension _callbacks =>
      (suspension.sourceTargetId ∈ fact.targetIds \/
          suspension.continuationTargetId ∈ fact.targetIds) ->
        fact.HoldsAt suspension.state suspension.world
  | .returned _ _ | .terminated _ | .fault _ | .blocked _ => True

theorem OriginalFiniteValueFlowFact.holdsAtRunning
    {context : StaticProofContext}
    (fact : OriginalFiniteValueFlowFact context)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (holds : fact.Holds (.running targetId state calls eventIndex world))
    (targetMember : targetId ∈ fact.targetIds) :
    fact.HoldsAt state world :=
  holds targetMember

theorem OriginalFiniteValueFlowFact.holdsAtCallbackRunning
    {context : StaticProofContext}
    (fact : OriginalFiniteValueFlowFact context)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime)
    (holds : fact.Holds
      (.callbackRunning targetId state calls eventIndex world callbacks))
    (targetMember : targetId ∈ fact.targetIds) :
    fact.HoldsAt state world :=
  holds targetMember

theorem OriginalFiniteValueFlowFact.holdsAtAwaitingExternal
    {context : StaticProofContext}
    (fact : OriginalFiniteValueFlowFact context)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (holds : fact.Holds (.awaitingExternal suspension callbacks))
    (endpointMember : suspension.sourceTargetId ∈ fact.targetIds \/
      suspension.continuationTargetId ∈ fact.targetIds) :
    fact.HoldsAt suspension.state suspension.world :=
  holds endpointMember

structure OriginalValueFlowInventory (context : StaticProofContext) where
  facts : List (OriginalFiniteValueFlowFact context)
  factIdsUnique : (facts.map (fun fact => fact.id)).Nodup

def OriginalValueFlowInventory.Holds
    {context : StaticProofContext}
    (inventory : OriginalValueFlowInventory context)
    (execution : WorldExecution) : Prop :=
  forall fact, fact ∈ inventory.facts -> fact.Holds execution

theorem OriginalValueFlowInventory.factHolds
    {context : StaticProofContext}
    (inventory : OriginalValueFlowInventory context)
    {execution : WorldExecution}
    (holds : inventory.Holds execution)
    (fact : OriginalFiniteValueFlowFact context)
    (member : fact ∈ inventory.facts) :
    fact.Holds execution :=
  holds fact member

/-! ## Checked local decoded transfers -/

/-- Symbolic output at a control-value location after one normalized region.
Frame-relative output is accepted only when its base register is unchanged. -/
def originalLocationOutputExpression?
    (behavior : NormalizedSymbolicBehavior) :
    ControlValueProvenance.Location -> Option Expr
  | .register register => some (behavior.registers.get register)
  | .frameWord base adjustment =>
      if behavior.registers.get base == .inputReg base then
        some ((ControlValueProvenance.StackAdjustment.canonicalExpression
          adjustment base).read32AfterWrites behavior.writes)
      else
        none
  | .staticWord address =>
      some ((Expr.constant address).read32AfterWrites behavior.writes)

theorem originalLocationOutputExpression_eval
    (location : ControlValueProvenance.Location)
    (behavior : NormalizedSymbolicBehavior) (output : Expr)
    (found : originalLocationOutputExpression? behavior location = some output)
    (state : MachineState) :
    output.eval state =
      originalLocationValue location
        ((behavior.eval state).nextMachineState state) := by
  cases location with
  | register register =>
      simp only [originalLocationOutputExpression?, Option.some.injEq] at found
      subst output
      simp [originalLocationValue, ControlValueProvenance.Location.inputExpr,
        RelationalBehavior.nextMachineState, NormalizedSymbolicBehavior.eval,
        evalNormalizedRegisters_get, Expr.eval]
  | frameWord base adjustment =>
      simp only [originalLocationOutputExpression?] at found
      split at found
      case isFalse unchanged => contradiction
      case isTrue unchanged =>
        have registerExact :
            behavior.registers.get base = .inputReg base :=
          beq_iff_eq.mp unchanged
        have baseExact :
            (((behavior.eval state).nextMachineState state).registers.get base) =
              state.registers.get base := by
          change
            (evalNormalizedRegisters state behavior.registers).get base =
              state.registers.get base
          rw [evalNormalizedRegisters_get, registerExact]
          rfl
        have addressExact :
            (ControlValueProvenance.StackAdjustment.canonicalExpression
                adjustment base).eval
                ((behavior.eval state).nextMachineState state) =
              (ControlValueProvenance.StackAdjustment.canonicalExpression
                adjustment base).eval state := by
          cases adjustment with
          | identity =>
              simpa [ControlValueProvenance.StackAdjustment.canonicalExpression,
                Expr.eval] using baseExact
          | add amount =>
              simp [ControlValueProvenance.StackAdjustment.canonicalExpression,
                Expr.eval, baseExact]
          | subtract amount =>
              simp only [
                ControlValueProvenance.StackAdjustment.canonicalExpression]
              split <;> simp [Expr.eval, baseExact]
        simp only [Option.some.injEq] at found
        subst output
        rw [Expr.eval_read32AfterWrites]
        change
          Memory.read32
              (applyConcreteWrites state.memory
                (evalNormalizedWrites state behavior.writes))
              ((ControlValueProvenance.StackAdjustment.canonicalExpression
                adjustment base).eval state) =
            Memory.read32
              (((behavior.eval state).nextMachineState state).memory)
              ((ControlValueProvenance.StackAdjustment.canonicalExpression
                adjustment base).eval
                  ((behavior.eval state).nextMachineState state))
        rw [addressExact]
        rfl
  | staticWord address =>
      simp only [originalLocationOutputExpression?, Option.some.injEq] at found
      subst output
      simp [originalLocationValue, ControlValueProvenance.Location.inputExpr,
        RelationalBehavior.nextMachineState, NormalizedSymbolicBehavior.eval,
        Expr.eval_read32AfterWrites, Expr.eval]

/-- Exact decoded semantics for one local value transfer.  The source region
is a member of the submitted program, starts at the checked code-map target,
decodes from the exact original PE bytes, and normalizes to the behavior whose
output expression is compared with the source location expression. -/
structure CheckedOriginalDecodedLocationTransfer
    (program : DecodedWorldProgram)
    (sourceLocation targetLocation : ControlValueProvenance.Location) where
  originalSide : program.candidate = false
  sourceTargetId : Nat
  sourceRegion : RegionRelation
  sourceRegionMember : sourceRegion ∈ program.regions
  sourceTarget : CodeTargetPair
  sourceTargetExact :
    program.context.codeMap.get? sourceTargetId = some sourceTarget
  sourceRegionIdExact : sourceRegion.id = sourceTargetId
  sourceRegionStartExact :
    sourceRegion.original.start = sourceTarget.originalRva
  decodedBehavior : SymbolicBehavior
  decodedExact :
    regionBehaviorWithMachineCallContracts program.context.originalPe
      program.context.originalImports program.context.machineImportCallContracts
      sourceRegion.original = some decodedBehavior
  behavior : NormalizedSymbolicBehavior
  normalizedExact :
    normalizeSymbolicBehavior false sourceRegion.targets decodedBehavior =
      some behavior
  outputExpression : Expr
  outputExpressionExact :
    originalLocationOutputExpression? behavior targetLocation =
      some outputExpression
  valueExact : outputExpression = sourceLocation.inputExpr

theorem CheckedOriginalDecodedLocationTransfer.preservesOrigin
    {program : DecodedWorldProgram}
    {sourceLocation targetLocation : ControlValueProvenance.Location}
    (transfer : CheckedOriginalDecodedLocationTransfer program
      sourceLocation targetLocation)
    (state : MachineState) (world : RelationalWorld)
    (origin : ValueOriginAtom)
    (source : OriginalValueOriginAtomHolds program.context world
      (originalLocationValue sourceLocation state) origin) :
    OriginalValueOriginAtomHolds program.context world
      (originalLocationValue targetLocation
        ((transfer.behavior.eval state).nextMachineState state)) origin := by
  rw [<- originalLocationOutputExpression_eval targetLocation transfer.behavior
      transfer.outputExpression transfer.outputExpressionExact state,
    transfer.valueExact]
  exact source

/-- A decoded register copy is the register/register specialization of the
exact local transfer checker. -/
structure CheckedOriginalDecodedCopyTransfer
    (program : DecodedWorldProgram) where
  sourceRegister : Reg
  targetRegister : Reg
  transfer : CheckedOriginalDecodedLocationTransfer program
    (.register sourceRegister) (.register targetRegister)

/-- The source shape for a decoded load is proof-relevant: it must read a
frame or static word, never silently reinterpret another register copy. -/
inductive OriginalMemoryValueLocation :
    ControlValueProvenance.Location -> Prop where
  | frameWord (base : Reg) (adjustment : StackAdjustment) :
      OriginalMemoryValueLocation (.frameWord base adjustment)
  | staticWord (address : Nat) :
      OriginalMemoryValueLocation (.staticWord address)

structure CheckedOriginalDecodedLoadTransfer
    (program : DecodedWorldProgram) where
  sourceLocation : ControlValueProvenance.Location
  sourceIsMemory : OriginalMemoryValueLocation sourceLocation
  targetRegister : Reg
  transfer : CheckedOriginalDecodedLocationTransfer program sourceLocation
    (.register targetRegister)

theorem CheckedOriginalDecodedCopyTransfer.preservesOrigin
    {program : DecodedWorldProgram}
    (copy : CheckedOriginalDecodedCopyTransfer program)
    (state : MachineState) (world : RelationalWorld)
    (origin : ValueOriginAtom)
    (source : OriginalValueOriginAtomHolds program.context world
      (state.registers.get copy.sourceRegister) origin) :
    OriginalValueOriginAtomHolds program.context world
      (originalLocationValue (.register copy.targetRegister)
        ((copy.transfer.behavior.eval state).nextMachineState state)) origin := by
  exact copy.transfer.preservesOrigin state world origin source

theorem CheckedOriginalDecodedLoadTransfer.preservesOrigin
    {program : DecodedWorldProgram}
    (load : CheckedOriginalDecodedLoadTransfer program)
    (state : MachineState) (world : RelationalWorld)
    (origin : ValueOriginAtom)
    (source : OriginalValueOriginAtomHolds program.context world
      (originalLocationValue load.sourceLocation state) origin) :
    OriginalValueOriginAtomHolds program.context world
      (originalLocationValue (.register load.targetRegister)
        ((load.transfer.behavior.eval state).nextMachineState state)) origin := by
  exact load.transfer.preservesOrigin state world origin source

/-! ## World and call frames -/

/-- A frame transports precisely the listed origins between two worlds.  It
does not claim that unrelated resources, pointers, or callbacks are stable. -/
structure OriginalValueFlowWorldFrame
    (context : StaticProofContext) (before after : RelationalWorld)
    (origins : List ValueOriginAtom) : Prop where
  preserves : forall origin,
    origin ∈ origins ->
      OriginalValueOriginAtomPreserved context before after origin

theorem OriginalValueFlowWorldFrame.transport
    {context : StaticProofContext} {before after : RelationalWorld}
    {origins : List ValueOriginAtom}
    (frame : OriginalValueFlowWorldFrame context before after origins)
    (origin : ValueOriginAtom) (member : origin ∈ origins)
    (value : Word)
    (holds : OriginalValueOriginAtomHolds context before value origin) :
    OriginalValueOriginAtomHolds context after value origin :=
  frame.preserves origin member value holds

theorem OriginalFiniteValueFlowFact.holdsAt_afterFrame
    {context : StaticProofContext}
    (fact : OriginalFiniteValueFlowFact context)
    (beforeState afterState : MachineState)
    (beforeWorld afterWorld : RelationalWorld)
    (before : fact.HoldsAt beforeState beforeWorld)
    (valueExact : originalLocationValue fact.location afterState =
      originalLocationValue fact.location beforeState)
    (frame : OriginalValueFlowWorldFrame context beforeWorld afterWorld
      fact.alternatives) :
    fact.HoldsAt afterState afterWorld := by
  rcases before with ⟨origin, member, holds⟩
  refine ⟨origin, member, ?_⟩
  rw [valueExact]
  exact frame.transport origin member _ holds

/-- A call-preservation certificate is an exact nonempty path of the original
transition system plus a concrete value/world frame between its endpoints.
This covers internal calls, imported calls, and nested callbacks without
introducing a second call-specific provenance language. -/
structure CheckedOriginalValueCallPreservation
    (program : DecodedWorldProgram)
    (source target : OriginalFiniteValueFlowFact program.context) where
  sourceTargetId : Nat
  sourceState : MachineState
  sourceCalls : List Nat
  sourceEventIndex : Nat
  sourceWorld : RelationalWorld
  targetTargetId : Nat
  targetState : MachineState
  targetCalls : List Nat
  targetEventIndex : Nat
  targetWorld : RelationalWorld
  observations : List WorldRelationalObservable
  sourceTargetMember : sourceTargetId ∈ source.targetIds
  targetTargetMember : targetTargetId ∈ target.targetIds
  path : NonemptyRelatedPath program.pe32TransitionSystem
    (.running sourceTargetId sourceState sourceCalls sourceEventIndex sourceWorld)
    observations
    (.running targetTargetId targetState targetCalls targetEventIndex targetWorld)
  alternativesExact : target.alternatives = source.alternatives
  valueExact : originalLocationValue target.location targetState =
    originalLocationValue source.location sourceState
  worldFrame : OriginalValueFlowWorldFrame program.context sourceWorld targetWorld
    source.alternatives

theorem CheckedOriginalValueCallPreservation.preserves
    {program : DecodedWorldProgram}
    {source target : OriginalFiniteValueFlowFact program.context}
    (checked : CheckedOriginalValueCallPreservation program source target)
    (sourceHolds : source.Holds
      (.running checked.sourceTargetId checked.sourceState checked.sourceCalls
        checked.sourceEventIndex checked.sourceWorld)) :
    target.Holds
      (.running checked.targetTargetId checked.targetState checked.targetCalls
        checked.targetEventIndex checked.targetWorld) := by
  intro _targetMember
  have atSource := sourceHolds checked.sourceTargetMember
  rcases atSource with ⟨origin, member, holds⟩
  refine ⟨origin, ?_, ?_⟩
  · rw [checked.alternativesExact]
    exact member
  · rw [checked.valueExact]
    exact checked.worldFrame.transport origin member _ holds

/-! ## Exact-zero branch exclusion -/

theorem originalValueOriginExactBitsZero
    (context : StaticProofContext) (world : RelationalWorld) (value : Word)
    (holds : OriginalValueOriginAtomHolds context world value (.exactBits 0)) :
    value = BitVec.ofNat 32 0 := by
  rcases holds with ⟨companion, exact⟩
  exact exact.1

theorem OriginalFiniteValueFlowFact.exactBitsZero
    {context : StaticProofContext}
    (fact : OriginalFiniteValueFlowFact context)
    (state : MachineState) (world : RelationalWorld)
    (singleton : fact.alternatives = [.exactBits 0])
    (holds : fact.HoldsAt state world) :
    originalLocationValue fact.location state = BitVec.ofNat 32 0 := by
  rcases holds with ⟨origin, member, originHolds⟩
  rw [singleton] at member
  simp only [List.mem_singleton] at member
  subst origin
  exact originalValueOriginExactBitsZero context world _ originHolds

/-- A nonzero branch whose checked source fact is exactly zero is infeasible.
The caller may use this contradiction to exclude the decoded taken edge; no
reachability status or arbitrary branch assumption is consumed here. -/
theorem OriginalFiniteValueFlowFact.nonzeroBranchExcluded
    {context : StaticProofContext}
    (fact : OriginalFiniteValueFlowFact context)
    (state : MachineState) (world : RelationalWorld)
    (singleton : fact.alternatives = [.exactBits 0])
    (holds : fact.HoldsAt state world)
    (nonzero : originalLocationValue fact.location state ≠
      BitVec.ofNat 32 0) : False :=
  nonzero (fact.exactBitsZero state world singleton holds)

/-! ## Provenance-to-runtime-target bridges -/

/-- A checked bridge between the paired static code map used by provenance
and the original-only decoded map used by operational dispatch.  Canonical
origins deliberately reject aliases. -/
structure OriginalStaticCodeOriginBinding
    (context : StaticProofContext)
    (originalContext : OriginalDecodedStaticContext) (targetId : Nat) where
  originalImageBaseExact : originalContext.pe.imageBase = context.originalPe.imageBase
  pairedTarget : CodeTargetPair
  pairedTargetExact : context.codeMap.get? targetId = some pairedTarget
  pairedOriginalAliasesEmpty : pairedTarget.originalAliases = []
  originalTarget : OriginalCodeTarget
  originalTargetExact : originalContext.codeMap.get? targetId = some originalTarget
  targetRvaExact : originalTarget.rva = pairedTarget.originalRva

theorem OriginalStaticCodeOriginBinding.originalWordExact
    {context : StaticProofContext}
    {originalContext : OriginalDecodedStaticContext} {targetId : Nat}
    (binding : OriginalStaticCodeOriginBinding context originalContext targetId)
    (world : RelationalWorld) (value : Word)
    (holds : OriginalValueOriginAtomHolds context world value
      (.staticCodeTarget targetId 0)) :
    value = BitVec.ofNat 32
      (originalContext.pe.imageBase + binding.originalTarget.rva) := by
  rcases holds with
    ⟨companion, target, targetFound, exactOffset | nonzeroOffset⟩
  · have targetExact : target = binding.pairedTarget := by
      rw [binding.pairedTargetExact] at targetFound
      exact (Option.some.inj targetFound).symm
    subst target
    rcases exactOffset with ⟨_offsetZero, originalExact, _candidateExact⟩
    rw [binding.originalImageBaseExact, binding.targetRvaExact]
    simpa [codeAddressMatches, binding.pairedOriginalAliasesEmpty] using
      originalExact
  · exact (Nat.not_lt_zero _ nonzeroOffset.1).elim

theorem runtimeTargetMember_staticCode
    {context : StaticProofContext}
    {originalContext : OriginalDecodedStaticContext} {targetId : Nat}
    (binding : OriginalStaticCodeOriginBinding context originalContext targetId)
    (world : RelationalWorld) (value : Word) (slotRva : Nat)
    (holds : OriginalValueOriginAtomHolds context world value
      (.staticCodeTarget targetId 0)) :
    RuntimeTargetMember originalContext world value
      (.relocatedWritableCode slotRva targetId) :=
  .relocatedWritableCode slotRva targetId binding.originalTarget
    binding.originalTargetExact (binding.originalWordExact world value holds)

theorem runtimeTargetMember_resolverStaticCode
    {context : StaticProofContext}
    {originalContext : OriginalDecodedStaticContext} {targetId : Nat}
    (binding : OriginalStaticCodeOriginBinding context originalContext targetId)
    (world : RelationalWorld) (value : Word)
    (queries : List ResolverQuery) (staticTargetIds : List Nat)
    (allowed : targetId ∈ staticTargetIds)
    (holds : OriginalValueOriginAtomHolds context world value
      (.staticCodeTarget targetId 0)) :
    RuntimeTargetMember originalContext world value
      (.resolverResults queries staticTargetIds) :=
  .resolverStaticTarget queries staticTargetIds targetId binding.originalTarget
    allowed binding.originalTargetExact
    (binding.originalWordExact world value holds)

theorem runtimeTargetMember_import
    {context : StaticProofContext}
    (originalContext : OriginalDecodedStaticContext)
    (world : RelationalWorld) (value : Word)
    (iatRva : Nat) (identity : ExternalTarget)
    (iatExact : forall binding,
      binding ∈ world.importAddresses -> binding.imported = identity ->
        binding.originalIatRva = iatRva)
    (holds : OriginalValueOriginAtomHolds context world value
      (.importTarget identity)) :
    RuntimeTargetMember originalContext world value
      (.importedAddress iatRva identity) := by
  rcases holds with
    ⟨companion, binding, member, importedExact, valueExact, _candidateExact⟩
  exact .importedAddress iatRva identity binding member importedExact
    (iatExact binding member importedExact) valueExact

theorem runtimeTargetMember_resolverResource
    {context : StaticProofContext}
    (originalContext : OriginalDecodedStaticContext)
    (world : RelationalWorld) (value : Word)
    (queries : List ResolverQuery) (staticTargetIds : List Nat)
    (query : ResolverQuery) (queryMember : query ∈ queries)
    (resourceId : Nat) (queryResourceExact : query.resourceId = resourceId)
    (holds : OriginalValueOriginAtomHolds context world value
      (.opaqueResource resourceId)) :
    RuntimeTargetMember originalContext world value
      (.resolverResults queries staticTargetIds) := by
  rcases holds with
    ⟨companion, resource, member, resourceExact, valueExact, _candidateExact⟩
  exact .resolverResult queries staticTargetIds query resource queryMember member
    (resourceExact.trans queryResourceExact.symm) valueExact

theorem runtimeTargetMember_registeredCallback
    {context : StaticProofContext}
    (originalContext : OriginalDecodedStaticContext)
    (world : RelationalWorld) (value : Word)
    (slotRva targetId : Nat) (targetIds : List Nat)
    (allowed : targetId ∈ targetIds)
    (target : OriginalCodeTarget)
    (targetFound : originalContext.codeMap.get? targetId = some target)
    (holds : OriginalValueOriginAtomHolds context world value
      (.registeredCallback targetId)) :
    RuntimeTargetMember originalContext world value
      (.registeredCallbackSlot slotRva targetIds) := by
  rcases holds with
    ⟨companion, callback, member, callbackTargetExact, valueExact,
      _candidateExact⟩
  have callbackTarget : callback.targetId = targetId := callbackTargetExact
  exact .registeredCallback slotRva targetIds callback member
    (callbackTarget ▸ allowed) target
    (callbackTarget ▸ targetFound) valueExact

theorem runtimeTargetMember_nullableTable
    {context : StaticProofContext}
    {originalContext : OriginalDecodedStaticContext} {targetId : Nat}
    (binding : OriginalStaticCodeOriginBinding context originalContext targetId)
    (world : RelationalWorld) (value : Word)
    (startRva endRva : Nat) (entries : List (Option Nat)) (index : Nat)
    (indexBound : index < entries.length)
    (entry : entries[index]? = some (some targetId))
    (holds : OriginalValueOriginAtomHolds context world value
      (.staticCodeTarget targetId 0)) :
    RuntimeTargetMember originalContext world value
      (.nullableCodeTable startRva endRva entries) :=
  .nullableTable startRva endRva entries index targetId binding.originalTarget
    indexBound entry binding.originalTargetExact
    (binding.originalWordExact world value holds)

/-! ## Exact invariant boundary -/

/-- The only whole-execution constructor.  Local decoded transfers, branch
exclusions, call paths, and target bridges are inputs to this exact closure;
none can replace it with a generated verdict. -/
structure CheckedOriginalValueFlowExecutionInvariant
    (program : DecodedWorldProgram)
    (inventory : OriginalValueFlowInventory program.context) : Prop where
  stepClosed : forall before,
    inventory.Holds before ->
      inventory.Holds (program.pe32TransitionSystem.step before).next

def CheckedOriginalValueFlowExecutionInvariant.toOriginalInvariant
    {program : DecodedWorldProgram}
    {inventory : OriginalValueFlowInventory program.context}
    (checked : CheckedOriginalValueFlowExecutionInvariant program inventory) :
    OriginalWorldExecutionInvariant program where
  holds := inventory.Holds
  stepClosed := checked.stepClosed

@[simp]
theorem CheckedOriginalValueFlowExecutionInvariant.toOriginalInvariant_holds
    {program : DecodedWorldProgram}
    {inventory : OriginalValueFlowInventory program.context}
    (checked : CheckedOriginalValueFlowExecutionInvariant program inventory)
    (execution : WorldExecution) :
    checked.toOriginalInvariant.holds execution <-> inventory.Holds execution :=
  Iff.rfl

#print axioms CheckedOriginalDecodedLocationTransfer.preservesOrigin
#print axioms CheckedOriginalDecodedCopyTransfer.preservesOrigin
#print axioms CheckedOriginalDecodedLoadTransfer.preservesOrigin
#print axioms OriginalValueFlowWorldFrame.transport
#print axioms CheckedOriginalValueCallPreservation.preserves
#print axioms OriginalFiniteValueFlowFact.nonzeroBranchExcluded
#print axioms runtimeTargetMember_staticCode
#print axioms runtimeTargetMember_import
#print axioms runtimeTargetMember_resolverResource
#print axioms runtimeTargetMember_registeredCallback
#print axioms runtimeTargetMember_nullableTable
#print axioms CheckedOriginalValueFlowExecutionInvariant.toOriginalInvariant

end StageA.Relational.OriginalValueFlowExecutionInvariant
