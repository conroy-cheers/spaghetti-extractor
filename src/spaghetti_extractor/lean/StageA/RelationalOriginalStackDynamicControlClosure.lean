import StageA.RelationalStackDynamicIndirectControl

namespace StageA.Relational.OriginalStackDynamicControlClosure

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.NullableCodePointerTable
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.StackDynamicIndirectControl

/-! # Original stack and dynamic indirect-control closure

This layer separates exact static authority from the runtime fact needed to
close a memory-derived indirect control.  Static extraction may propose a
site, seed, table, or callback inventory, but only a premise over the actual
reachable machine states can authorize a finite target set or prove the source
uninhabited.
-/

/-- The states at one original control source that composition has proved
reachable.  The relation is deliberately supplied by whole-program
composition rather than reconstructed from report status fields. -/
abbrev ActualSourceReachability :=
  RelationalWorld -> MachineState -> Prop

def SourceUninhabited (reachable : ActualSourceReachability) : Prop :=
  ¬ ∃ world state, reachable world state

/-- A resolved target is tied to one canonical checked code-map entry.  Alias
addresses are accepted only when the exact code map lists them. -/
structure OriginalResolvedCodeTarget
    (context : OriginalDecodedStaticContext) (site : OriginalIndirectControlSite)
    (state : MachineState) where
  targetId : Nat
  target : OriginalCodeTarget
  targetFound : context.codeMap.get? targetId = some target
  targetExact :
    codeAddressMatches context.pe.imageBase target.rva target.aliases
      (site.target.expression.eval state) = true

/-- A finite closure is meaningful only for every state admitted by the
whole-program reachability invariant. -/
structure FiniteOriginalIndirectControlClosure
    (context : OriginalDecodedStaticContext) (site : OriginalIndirectControlSite)
    (reachable : ActualSourceReachability) where
  allowedTargetIds : List Nat
  allowedTargetsChecked :
    codeTargetInventoryChecked context allowedTargetIds = true
  everyReachableTarget :
    ∀ world state, reachable world state ->
      ∃ resolved : OriginalResolvedCodeTarget context site state,
        resolved.targetId ∈ allowedTargetIds

/-- A memory-derived source closes either because it is unreachable under the
checked rooted execution invariant or because every reachable target belongs
to a checked finite inventory. -/
inductive OriginalIndirectControlClosure
    (context : OriginalDecodedStaticContext) (site : OriginalIndirectControlSite)
    (reachable : ActualSourceReachability) : Prop where
  | unreachable :
      SourceUninhabited reachable ->
      OriginalIndirectControlClosure context site reachable
  | finite :
      FiniteOriginalIndirectControlClosure context site reachable ->
      OriginalIndirectControlClosure context site reachable

def originalTargetAddressChecked (context : OriginalDecodedStaticContext)
    (targetId : Nat) (address : Word) : Bool :=
  match context.codeMap.get? targetId with
  | none => false
  | some target =>
      codeAddressMatches context.pe.imageBase target.rva target.aliases address

theorem originalResolvedCodeTarget_of_checked
    (context : OriginalDecodedStaticContext) (site : OriginalIndirectControlSite)
    (state : MachineState) (targetId : Nat) (address : Word)
    (targetValue : site.target.expression.eval state = address)
    (checked : originalTargetAddressChecked context targetId address = true) :
    ∃ resolved : OriginalResolvedCodeTarget context site state,
      resolved.targetId = targetId := by
  unfold originalTargetAddressChecked at checked
  cases found : context.codeMap.get? targetId with
  | none => simp [found] at checked
  | some target =>
      simp only [found] at checked
      refine ⟨{
        targetId := targetId
        target := target
        targetFound := found
        targetExact := ?_
      }, rfl⟩
      simpa [targetValue] using checked

/-- Exact static authority for a stack-carried relocated code pointer. -/
structure CheckedStackCarryAuthority
    (context : OriginalDecodedStaticContext) where
  static : CheckedStackRelocatedCodePointerClaim context
  allowedTargetsChecked :
    codeTargetInventoryChecked context [static.claim.seed.targetId] = true
  targetAddressChecked :
    originalTargetAddressChecked context static.claim.seed.targetId
      (static.claim.seed.word context) = true

/-- This is the precise runtime/frame premise that static extraction cannot
invent.  It requires the stack allocation membership and exact slot value for
every reachable source state.  Call-frame preservation and non-aliasing are
therefore proved upstream, not assumed here. -/
structure CompleteStackCarryPremise
    (context : OriginalDecodedStaticContext)
    (authority : CheckedStackCarryAuthority context)
    (reachable : ActualSourceReachability) where
  everyReachableCarriesSeed :
    ∀ world state, reachable world state ->
      StackRelocatedCodePointerRuntime context authority.static.claim world state

theorem stackCarryClosure_of_complete
    (context : OriginalDecodedStaticContext)
    (authority : CheckedStackCarryAuthority context)
    (reachable : ActualSourceReachability)
    (complete : CompleteStackCarryPremise context authority reachable) :
    OriginalIndirectControlClosure context authority.static.claim.site reachable := by
  apply OriginalIndirectControlClosure.finite
  refine {
    allowedTargetIds := [authority.static.claim.seed.targetId]
    allowedTargetsChecked := authority.allowedTargetsChecked
    everyReachableTarget := ?_
  }
  intro world state reached
  have runtime := complete.everyReachableCarriesSeed world state reached
  have value := runtime.targetValue
  obtain ⟨resolved, targetIdExact⟩ :=
    originalResolvedCodeTarget_of_checked context authority.static.claim.site
      state authority.static.claim.seed.targetId
      (authority.static.claim.seed.word context) value
      authority.targetAddressChecked
  refine ⟨resolved, ?_⟩
  simpa [targetIdExact]

/-- Exact static authority for an indexed immutable table source. -/
structure CheckedIndexedTableAuthority
    (context : OriginalDecodedStaticContext) where
  static : CheckedIndexedImmutableTableClaim context

/-- Composition must derive the index bound from every complete decoded
predecessor.  In particular, an empty table certificate cannot make the source
unreachable without this premise. -/
structure CompleteIndexedTablePredecessorPremise
    (authority : CheckedIndexedTableAuthority context)
    (reachable : ActualSourceReachability) : Prop where
  everyReachableIndexBound :
    ∀ world state, reachable world state ->
      authority.static.claim.RuntimeIndexBound state

theorem indexedTableClosure_of_empty_checked_interval
    (authority : CheckedIndexedTableAuthority context)
    (reachable : ActualSourceReachability)
    (loop : LoopFacts)
    (loopExact : authority.static.claim.table.loop = .exact loop)
    (empty : loop.lowerInclusive = loop.upperExclusive)
    (complete : CompleteIndexedTablePredecessorPremise authority reachable) :
    OriginalIndirectControlClosure context authority.static.claim.site reachable := by
  apply OriginalIndirectControlClosure.unreachable
  rintro ⟨world, state, reached⟩
  exact authority.static.claim.noRuntimeIndex_of_emptyInterval loop loopExact
    empty state (complete.everyReachableIndexBound world state reached)

/-- Static authority for a dynamic callback-field source.  This checks the
exact instruction and finite code inventory, but not allocation membership,
registration, or the concrete field value. -/
structure CheckedDynamicCallbackAuthority
    (context : OriginalDecodedStaticContext) where
  static : CheckedDynamicCallbackControlClaim context

def dynamicCallbackAddressChecked
    (context : OriginalDecodedStaticContext)
    (callback : RegisteredCallbackPair) : Bool :=
  originalTargetAddressChecked context callback.targetId callback.originalAddress

/-- The dynamic-world premise is intentionally stronger than a field-shape
claim.  Every reachable state must carry the allocation range, registered
callback pair, field value, and a checked link from the callback address to
the exact original code map. -/
structure CompleteDynamicCallbackPremise
    (context : OriginalDecodedStaticContext)
    (authority : CheckedDynamicCallbackAuthority context)
    (reachable : ActualSourceReachability) where
  runtime :
    ∀ world state, reachable world state ->
      DynamicCallbackControlRuntime context authority.static.claim world state
  callbackAddressChecked :
    ∀ world state (reached : reachable world state),
      dynamicCallbackAddressChecked context
        (runtime world state reached).callback = true

theorem dynamicCallbackClosure_of_complete
    (context : OriginalDecodedStaticContext)
    (authority : CheckedDynamicCallbackAuthority context)
    (reachable : ActualSourceReachability)
    (complete : CompleteDynamicCallbackPremise context authority reachable) :
    OriginalIndirectControlClosure context authority.static.claim.site reachable := by
  apply OriginalIndirectControlClosure.finite
  refine {
    allowedTargetIds := authority.static.claim.allowedTargetIds
    allowedTargetsChecked := ?_
    everyReachableTarget := ?_
  }
  · have checked := authority.static.checked
    simp only [DynamicCallbackControlClaim.checked, Bool.and_eq_true] at checked
    exact checked.2
  · intro world state reached
    let runtime := complete.runtime world state reached
    have value := runtime.targetValue
    obtain ⟨resolved, targetIdExact⟩ :=
      originalResolvedCodeTarget_of_checked context authority.static.claim.site
        state runtime.callback.targetId runtime.callback.originalAddress value.1
        (complete.callbackAddressChecked world state reached)
    refine ⟨resolved, ?_⟩
    simpa [targetIdExact] using value.2

/-- If whole-program dataflow proves the dynamic registry source
uninhabited, no callback inventory is needed.  Typical proofs establish a
zero-initialized head slot, complete internal/external write framing, and a
nonzero branch guard at the source. -/
structure CompleteDynamicSourceUninhabitedPremise
    (reachable : ActualSourceReachability) : Prop where
  sourceUninhabited : SourceUninhabited reachable

theorem dynamicSourceClosure_of_uninhabited
    (checkedSite : CheckedOriginalIndirectControlSite context)
    (reachable : ActualSourceReachability)
    (complete : CompleteDynamicSourceUninhabitedPremise reachable) :
    OriginalIndirectControlClosure context checkedSite.site reachable :=
  .unreachable complete.sourceUninhabited

end StageA.Relational.OriginalStackDynamicControlClosure
