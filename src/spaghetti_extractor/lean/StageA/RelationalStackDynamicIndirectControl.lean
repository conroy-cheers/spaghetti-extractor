import StageA.RelationalOriginalIndirectControlAuthority

namespace StageA.Relational.StackDynamicIndirectControl

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.NullableCodePointerTable
open StageA.Relational.OriginalIndirectControlAuthority

/-! Checked static evidence and explicit runtime obligations for indirect
controls whose target is read through a stack slot, an indexed immutable
table, or a dynamic allocation. -/

/-- Static evidence for a stack-carried pointer whose value is seeded by one
relocation-backed code pointer. This deliberately does not assert that the
stack slot still contains the seed at runtime. -/
structure StackRelocatedCodePointerClaim where
  site : OriginalIndirectControlSite
  seed : RelocatedCodePointerSeed
deriving Repr, DecidableEq

def StackRelocatedCodePointerClaim.checked
    (context : OriginalDecodedStaticContext)
    (claim : StackRelocatedCodePointerClaim) : Bool :=
  claim.site.checked context && claim.seed.checked context &&
    match claim.site.target with
    | .stackRead _ _ => true
    | _ => false

structure CheckedStackRelocatedCodePointerClaim
    (context : OriginalDecodedStaticContext) where
  authority : ExactOriginalDecodedAuthority context
  claim : StackRelocatedCodePointerClaim
  checked : claim.checked context = true

/-- The runtime carry fact required to turn the checked static seed into an
indirect-control result. The stack range and concrete memory remain part of
the authoritative machine state. -/
structure StackRelocatedCodePointerRuntime
    (context : OriginalDecodedStaticContext)
    (claim : StackRelocatedCodePointerClaim)
    (world : RelationalWorld) (state : MachineState) where
  stackRegister : Reg
  adjustment : StackAdjustment
  targetShape : claim.site.target = .stackRead stackRegister adjustment
  stackRange : DynamicAddressRangePair
  stackRangeMember : stackRange ∈ world.stackRanges
  slotInRange : stackRange.originalBase.toNat <=
      ((adjustment.expression stackRegister).eval state).toNat ∧
    ((adjustment.expression stackRegister).eval state).toNat + 4 <=
      stackRange.originalBase.toNat + stackRange.size
  valueExact : Memory.read32 state.memory
      ((adjustment.expression stackRegister).eval state) = claim.seed.word context

theorem StackRelocatedCodePointerRuntime.targetValue
    (runtime : StackRelocatedCodePointerRuntime context claim world state) :
    claim.site.target.expression.eval state = claim.seed.word context := by
  rw [runtime.targetShape]
  change Memory.read32 state.memory
    ((runtime.adjustment.expression runtime.stackRegister).eval state) =
      claim.seed.word context
  exact runtime.valueExact

/-- An indexed immutable nullable table. `lowerInclusive` connects an SIB base
to a caller range that starts after one or more header words. -/
structure IndexedImmutableTableClaim where
  site : OriginalIndirectControlSite
  table : Certificate
  indexRegister : Reg
  lowerInclusive : Nat
deriving Repr, DecidableEq

def IndexedImmutableTableClaim.checked
    (context : OriginalDecodedStaticContext)
    (claim : IndexedImmutableTableClaim) : Bool :=
  ByteTree.ofBytes claim.table.peBytes == context.pe.bytes &&
    claim.site.checked context && claim.table.checked &&
    claim.table.contextId == claim.site.sourceTargetId &&
    claim.table.dispatchRva == claim.site.instructionRva &&
    match claim.site.target, claim.table.callerRange, claim.table.loop with
    | .indexedTable base register scale, .exact range, .exact loop =>
        register == claim.indexRegister &&
          loop.lowerInclusive == claim.lowerInclusive &&
          loop.addressScale == scale &&
          base + claim.lowerInclusive * scale ==
            context.pe.imageBase + range.startRva
    | _, _, _ => false

structure CheckedIndexedImmutableTableClaim
    (context : OriginalDecodedStaticContext) where
  authority : ExactOriginalDecodedAuthority context
  claim : IndexedImmutableTableClaim
  checked : claim.checked context = true

/-- Composition must establish this bound from predecessor semantics. It is
never inferred from the submitted table inventory. -/
def IndexedImmutableTableClaim.RuntimeIndexBound
    (claim : IndexedImmutableTableClaim) (state : MachineState) : Prop :=
  ∃ loop,
    claim.table.loop = .exact loop ∧
      loop.lowerInclusive <=
        (state.registers.get claim.indexRegister).toNat ∧
      (state.registers.get claim.indexRegister).toNat < loop.upperExclusive

/-- The product graph supplies this premise from complete decoded
predecessors and checked invariants.  It is deliberately separate from the
static table certificate. -/
def IndexedImmutableTableClaim.ReachabilityBound
    (claim : IndexedImmutableTableClaim)
    (actualReachable : MachineState → Prop) : Prop :=
  ∀ state, actualReachable state → claim.RuntimeIndexBound state

/-- A compact checked fact for the empty-table case. It deliberately projects
only the loop inventory instead of unfolding the PE-backed table checker. -/
def IndexedImmutableTableClaim.emptyInterval
    (claim : IndexedImmutableTableClaim) : Bool :=
  match claim.table.loop with
  | .exact loop => loop.lowerInclusive == loop.upperExclusive
  | .unknown => false

/-- The Boolean empty-interval witness is enough to refute every concrete
runtime index bound. -/
theorem IndexedImmutableTableClaim.noRuntimeIndex_of_emptyChecked
    (claim : IndexedImmutableTableClaim)
    (emptyChecked : claim.emptyInterval = true) :
    ∀ state, ¬ claim.RuntimeIndexBound state := by
  intro state bound
  rcases bound with ⟨runtimeLoop, runtimeExact, lower, upper⟩
  cases loopExact : claim.table.loop with
  | unknown =>
      simp [IndexedImmutableTableClaim.emptyInterval, loopExact] at emptyChecked
  | exact loop =>
      have empty : loop.lowerInclusive = loop.upperExclusive := by
        simpa [IndexedImmutableTableClaim.emptyInterval, loopExact] using
          emptyChecked
      rw [loopExact] at runtimeExact
      cases Knowledge.exact.inj runtimeExact
      omega

/-- An empty checked loop interval cannot reach its indexed call. This theorem
does not prove the predecessor bound; it makes that remaining obligation
precise and composable. -/
theorem IndexedImmutableTableClaim.noRuntimeIndex_of_emptyInterval
    (claim : IndexedImmutableTableClaim)
    (loop : LoopFacts)
    (loopExact : claim.table.loop = .exact loop)
    (empty : loop.lowerInclusive = loop.upperExclusive) :
    ∀ state, ¬ claim.RuntimeIndexBound state := by
  intro state bound
  rcases bound with ⟨actual, actualExact, lower, upper⟩
  rw [loopExact] at actualExact
  cases Knowledge.exact.inj actualExact
  omega

/-- Once composition establishes the runtime bound, an empty checked interval
removes the source from the reachable graph.  Static extraction alone cannot
instantiate `bound`. -/
theorem IndexedImmutableTableClaim.sourceUnreachable_of_emptyInterval
    (claim : IndexedImmutableTableClaim)
    (actualReachable : MachineState → Prop)
    (loop : LoopFacts)
    (loopExact : claim.table.loop = .exact loop)
    (empty : loop.lowerInclusive = loop.upperExclusive)
    (bound : claim.ReachabilityBound actualReachable) :
    ¬ ∃ state, actualReachable state := by
  rintro ⟨state, reachable⟩
  exact claim.noRuntimeIndex_of_emptyInterval loop loopExact empty state
    (bound state reachable)

/-- Keep one authoritative dynamic-callback runtime model.  The shared
original-indirect-control layer checks allocation membership, registration,
the allowed target inventory, and the exact field value. -/
abbrev DynamicCallbackFieldRuntime
    (context : OriginalDecodedStaticContext)
    (claim : DynamicCallbackControlClaim)
    (world : RelationalWorld) (state : MachineState) :=
  DynamicCallbackControlRuntime context claim world state

end StageA.Relational.StackDynamicIndirectControl
