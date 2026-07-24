import StageA.RelationalInterpreterMixedOriginal
import StageA.RelationalNullableCodePointerTable

namespace StageA.Relational.OriginalIndirectControlAuthority

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.InterpreterTransfer
open StageA.Relational.NullableCodePointerTable

/-! # One-sided original indirect-control authority

The structures in this module bind untrusted provenance proposals to exact PE
bytes and the decoded-original context. Static checking deliberately stops at
the runtime boundary: stack slots, dynamic nodes, import addresses, and
registered callbacks require explicit world/state premises before they can
authorize an indirect transfer.
-/

inductive IndirectTransferKind where
  | call (continuationTargetId : Nat)
  | jump
deriving Repr, DecidableEq, BEq

inductive OriginalTargetExpression where
  | register (register : Reg)
  | stackRead (register : Reg) (adjustment : StackAdjustment)
  | dynamicField (baseRegister : Reg) (offset : Nat)
  | indexedTable (baseAddress : Nat) (indexRegister : Reg) (scale : Nat)
deriving Repr, DecidableEq, BEq

def scaledIndexExpression (register : Reg) (scale : Nat) : Option Expr :=
  match scale with
  | 1 => some (.inputReg register)
  | 2 => some (.shiftLeft (.inputReg register) 1)
  | 4 => some (.shiftLeft (.inputReg register) 2)
  | 8 => some (.shiftLeft (.inputReg register) 3)
  | _ => none

def OriginalTargetExpression.addressExpression? :
    OriginalTargetExpression -> Option Expr
  | .register _ => none
  | .stackRead reg adjustment =>
      some (adjustment.expression reg)
  | .dynamicField reg offset =>
      some (.add (.inputReg reg) (.constant offset))
  | .indexedTable base reg scale => do
      let index <- scaledIndexExpression reg scale
      some (.add index (.constant base))

def OriginalTargetExpression.expression
    (target : OriginalTargetExpression) : Expr :=
  match target with
  | .register reg => .inputReg reg
  | .stackRead reg adjustment => .read32 (adjustment.expression reg)
  | .dynamicField reg offset =>
      .read32 (.add (.inputReg reg) (.constant offset))
  | .indexedTable base reg scale =>
      .read32 (.add (scaledIndexExpression reg scale |>.getD (.constant 0))
        (.constant base))

def OriginalTargetExpression.supported : OriginalTargetExpression -> Bool
  | .indexedTable _ reg scale =>
      (scaledIndexExpression reg scale).isSome
  | _ => true

def originalTargetPair? (context : OriginalDecodedStaticContext)
    (targetId : Nat) : Option CodeTargetPair := do
  let target <- context.codeMap.get? targetId
  pure {
    id := target.id
    regionIndex := target.regionIndex
    originalRva := target.rva
    candidateRva := target.rva
    originalAliases := target.aliases
    candidateAliases := target.aliases
  }

def originalTargetPairs? (context : OriginalDecodedStaticContext)
    (targetIds : List Nat) : Option (List CodeTargetPair) :=
  targetIds.mapM (originalTargetPair? context)

def normalizedOriginalBehavior?
    (context : OriginalDecodedStaticContext)
    (targetId : Nat) : Option NormalizedSymbolicBehavior := do
  let source <- context.source? targetId
  let behavior <- regionBehaviorWithMachineCallContracts context.pe
    context.imports context.machineImportCallContracts source.region.span
  let targets <- originalTargetPairs? context source.region.targets
  normalizeSymbolicBehavior false targets behavior

def indirectInstructionMatches (bytes : Bytes)
    (kind : IndirectTransferKind) : Bool :=
  match decodeInstructionExact bytes with
  | some { instruction := .callIndirect _, .. } =>
      match kind with | .call _ => true | .jump => false
  | some { instruction := .jumpIndirect _, .. } =>
      match kind with | .call _ => false | .jump => true
  | _ => false

structure OriginalIndirectControlSite where
  sourceTargetId : Nat
  instructionRva : Nat
  instructionBytes : Bytes
  target : OriginalTargetExpression
  transfer : IndirectTransferKind
deriving Repr, DecidableEq

def OriginalIndirectControlSite.expectedOutcome
    (site : OriginalIndirectControlSite) : NormalizedOutcomeExpr :=
  match site.transfer with
  | .call continuation => .indirectCall site.target.expression continuation
  | .jump => .indirectJump site.target.expression

/-- The source identity, exact instruction bytes, instruction class, decoded
region behavior, and continuation inventory must all agree. -/
def OriginalIndirectControlSite.checked
    (context : OriginalDecodedStaticContext)
    (site : OriginalIndirectControlSite) : Bool :=
  !site.instructionBytes.isEmpty &&
    site.target.supported &&
    exactRvaBytes context.pe site.instructionRva site.instructionBytes.length ==
      some site.instructionBytes &&
    indirectInstructionMatches site.instructionBytes site.transfer &&
    match context.source? site.sourceTargetId,
        normalizedOriginalBehavior? context site.sourceTargetId with
    | some source, some behavior =>
        source.region.span.start <= site.instructionRva &&
          site.instructionRva + site.instructionBytes.length <=
            source.region.span.start + source.region.span.size &&
          behavior.outcome == site.expectedOutcome &&
          match site.transfer with
          | .call continuation => (context.codeMap.get? continuation).isSome
          | .jump => true
    | _, _ => false

/-- A checked site cannot be detached from the exact decoded-original
authority that justified its context. -/
structure CheckedOriginalIndirectControlSite
    (context : OriginalDecodedStaticContext) where
  authority : ExactOriginalDecodedAuthority context
  site : OriginalIndirectControlSite
  checked : site.checked context = true

def relocationCountAt (relocations : List BaseRelocation) (rva : Nat) : Nat :=
  (relocations.filter fun relocation =>
    relocation.rva == rva && relocation.kind == 3).length

/-- A launch-time PE word containing one canonical internal code pointer.
Writable sections are allowed here; this is an initial seed, not a runtime
stability claim. -/
structure RelocatedCodePointerSeed where
  slotRva : Nat
  targetId : Nat
deriving Repr, DecidableEq, BEq

def RelocatedCodePointerSeed.checked
    (context : OriginalDecodedStaticContext)
    (seed : RelocatedCodePointerSeed) : Bool :=
  seed.slotRva % 4 == 0 && relocationCountAt context.relocations seed.slotRva == 1 &&
    match readExactRvaU32 context.pe seed.slotRva,
        context.codeMap.get? seed.targetId with
    | some word, some target =>
        target.id == seed.targetId && target.aliases.isEmpty &&
          rvaInExecutableSection context.pe target.rva &&
          word == context.pe.imageBase + target.rva
    | _, _ => false

def RelocatedCodePointerSeed.word
    (context : OriginalDecodedStaticContext)
    (seed : RelocatedCodePointerSeed) : Word :=
  match context.codeMap.get? seed.targetId with
  | some target => BitVec.ofNat 32 (context.pe.imageBase + target.rva)
  | none => BitVec.ofNat 32 0

structure CheckedRelocatedCodePointerSeed
    (context : OriginalDecodedStaticContext) where
  authority : ExactOriginalDecodedAuthority context
  seed : RelocatedCodePointerSeed
  checked : seed.checked context = true

/-- Runtime closure for a fixed stack code pointer. Membership and memory
contents are propositions over the concrete world/state, not Python status. -/
structure StackFixedControlRuntime
    (context : OriginalDecodedStaticContext)
    (site : OriginalIndirectControlSite)
    (seed : RelocatedCodePointerSeed)
    (world : RelationalWorld) (state : MachineState) where
  targetShape : ∃ adjustment, site.target = .stackRead .esp adjustment
  stackRange : DynamicAddressRangePair
  stackRangeMember : stackRange ∈ world.stackRanges
  slotAddress : Word
  slotAddressExact : site.target.addressExpression?.map (fun address =>
    address.eval state) = some slotAddress
  slotInRange : stackRange.originalBase.toNat <= slotAddress.toNat ∧
    slotAddress.toNat + 4 <= stackRange.originalBase.toNat + stackRange.size
  valueExact : Memory.read32 state.memory slotAddress = seed.word context

def targetIdAllowed (targetIds : List Nat) (targetId : Nat) : Bool :=
  !targetIds.isEmpty && targetIds.length == targetIds.eraseDups.length &&
    targetIds.contains targetId

structure StackFixedControlAuthority
    (context : OriginalDecodedStaticContext)
    (world : RelationalWorld) (state : MachineState) where
  site : OriginalIndirectControlSite
  seed : RelocatedCodePointerSeed
  siteChecked : site.checked context = true
  seedChecked : seed.checked context = true
  allowedTargetIds : List Nat
  allowedChecked : targetIdAllowed allowedTargetIds seed.targetId = true
  runtime : StackFixedControlRuntime context site seed world state

theorem StackFixedControlRuntime.targetValue
    (runtime : StackFixedControlRuntime context site seed world state) :
    site.target.expression.eval state = seed.word context := by
  rcases runtime.targetShape with ⟨adjustment, targetShape⟩
  have address : (adjustment.expression .esp).eval state = runtime.slotAddress := by
    have exact := runtime.slotAddressExact
    rw [targetShape] at exact
    simpa [OriginalTargetExpression.addressExpression?] using exact
  simpa [targetShape, OriginalTargetExpression.expression, Expr.eval, address]
    using runtime.valueExact

theorem StackFixedControlAuthority.targetClosed
    (control : StackFixedControlAuthority context world state) :
    control.site.target.expression.eval state = control.seed.word context ∧
      control.seed.targetId ∈ control.allowedTargetIds := by
  refine ⟨control.runtime.targetValue, ?_⟩
  have allowed := control.allowedChecked
  simp only [targetIdAllowed, Bool.and_eq_true] at allowed
  exact List.contains_iff_mem.mp allowed.2

structure NullableTableControlClaim where
  site : OriginalIndirectControlSite
  table : NullableCodePointerTable.Certificate
deriving Repr, DecidableEq

def NullableTableControlClaim.checked
    (context : OriginalDecodedStaticContext)
    (claim : NullableTableControlClaim) : Bool :=
  ByteTree.ofBytes claim.table.peBytes == context.pe.bytes &&
    claim.site.checked context && claim.table.checked &&
    match claim.site.target, claim.table.callerRange with
    | .indexedTable base _ scale, .exact range =>
        base == context.pe.imageBase + range.startRva && scale == 4
    | _, _ => false

structure CheckedNullableTableControlClaim
    (context : OriginalDecodedStaticContext) where
  authority : ExactOriginalDecodedAuthority context
  claim : NullableTableControlClaim
  checked : claim.checked context = true

def NullableTableAddressInRange (claim : NullableTableControlClaim)
    (state : MachineState) : Prop :=
  ∃ range pe address,
    claim.table.callerRange = .exact range ∧
      parsePE32 claim.table.peBytes = some pe ∧
      claim.site.target.addressExpression?.map (fun expression =>
        expression.eval state) = some address ∧
      pe.imageBase + range.startRva <= address.toNat ∧
      address.toNat < pe.imageBase + range.endRva

/-- Composition supplies this premise from the complete predecessor graph.
For an empty exact table range, the premise is contradictory. -/
def NullableTableReachabilityBound
    (claim : NullableTableControlClaim)
    (actualReachable : MachineState -> Prop) : Prop :=
  ∀ state, actualReachable state -> NullableTableAddressInRange claim state

/-- The composition/launch layer proves that every actually selected target
comes from the exact immutable table inventory. This premise is stronger than
an address-range hint: it includes the runtime immutable-image memory fact. -/
def NullableTableTargetBound
    (claim : NullableTableControlClaim)
    (actualReachable : MachineState -> Prop) : Prop :=
  ∀ state, actualReachable state ->
    ∃ targetIds targetId,
      claim.table.resolvedNonNullTargetIds = some targetIds ∧
        targetId ∈ targetIds

theorem nullableTableSourceUnreachable_of_noTargets
    (claim : NullableTableControlClaim)
    (actualReachable : MachineState -> Prop)
    (empty : claim.table.resolvedNonNullTargetIds = some [])
    (bound : NullableTableTargetBound claim actualReachable) :
    ¬ ∃ state, actualReachable state := by
  rintro ⟨state, reachable⟩
  rcases bound state reachable with ⟨targetIds, targetId, resolved, member⟩
  rw [empty] at resolved
  cases Option.some.inj resolved
  simpa using member

theorem nullableTableSourceUnreachable_of_emptyRange
    (claim : NullableTableControlClaim)
    (actualReachable : MachineState -> Prop)
    (range : RvaRange)
    (rangeExact : claim.table.callerRange = .exact range)
    (empty : range.startRva = range.endRva)
    (bound : NullableTableReachabilityBound claim actualReachable) :
    ¬ ∃ state, actualReachable state := by
  rintro ⟨state, reachable⟩
  rcases bound state reachable with
    ⟨actualRange, pe, address, actualRangeExact, _parsed, _address,
      lower, upper⟩
  rw [rangeExact] at actualRangeExact
  cases Knowledge.exact.inj actualRangeExact
  omega

structure SavedImportControlClaim where
  saveSourceTargetId : Nat
  restoreSourceTargetId : Nat
  site : OriginalIndirectControlSite
  binding : OriginalIATCallSiteBinding
  stackRegister : Reg
  stackAdjustment : StackAdjustment
  targetRegister : Reg
deriving Repr, DecidableEq

def SavedImportControlClaim.stackAddress
    (claim : SavedImportControlClaim) : Expr :=
  claim.stackAdjustment.expression claim.stackRegister

def SavedImportControlClaim.checked
    (context : OriginalDecodedStaticContext)
    (claim : SavedImportControlClaim) : Bool :=
  claim.binding.sourceTargetId == claim.saveSourceTargetId &&
    originalIATCallSiteBindingValid context claim.binding &&
    claim.site.target == .register claim.targetRegister &&
    claim.site.checked context &&
    match normalizedOriginalBehavior? context claim.saveSourceTargetId,
        normalizedOriginalBehavior? context claim.restoreSourceTargetId with
    | some save, some restore =>
        save.writes.contains (claim.stackAddress,
          .read32 (.constant claim.binding.iatVa)) &&
        restore.registers.get claim.targetRegister ==
          .read32 claim.stackAddress
    | _, _ => false

structure CheckedSavedImportControlClaim
    (context : OriginalDecodedStaticContext) where
  authority : ExactOriginalDecodedAuthority context
  claim : SavedImportControlClaim
  checked : claim.checked context = true

structure SavedImportControlRuntime
    (claim : SavedImportControlClaim)
    (world : RelationalWorld) (state : MachineState) where
  siteTargetExact : claim.site.target = .register claim.targetRegister
  stackRange : DynamicAddressRangePair
  stackRangeMember : stackRange ∈ world.stackRanges
  importAddress : ImportAddressPair
  importAddressMember : importAddress ∈ world.importAddresses
  identityExact : importAddress.imported = claim.binding.identity.normalizedTarget
  iatExact : importAddress.originalIatRva = claim.binding.iatRva
  slotInRange : stackRange.originalBase.toNat <=
      (claim.stackAddress.eval state).toNat ∧
    (claim.stackAddress.eval state).toNat + 4 <=
      stackRange.originalBase.toNat + stackRange.size
  valueExact : Memory.read32 state.memory (claim.stackAddress.eval state) =
    importAddress.originalAddress
  registerExact : state.registers.get claim.targetRegister =
    Memory.read32 state.memory (claim.stackAddress.eval state)

theorem SavedImportControlRuntime.targetValue
    (runtime : SavedImportControlRuntime claim world state) :
    claim.site.target.expression.eval state =
      runtime.importAddress.originalAddress := by
  rw [runtime.siteTargetExact]
  simp only [OriginalTargetExpression.expression, Expr.eval]
  rw [runtime.registerExact, runtime.valueExact]

structure DynamicCallbackControlClaim where
  site : OriginalIndirectControlSite
  callbackFieldOffset : Nat
  allowedTargetIds : List Nat
deriving Repr, DecidableEq

def codeTargetInventoryChecked (context : OriginalDecodedStaticContext)
    (targetIds : List Nat) : Bool :=
  !targetIds.isEmpty && targetIds.length == targetIds.eraseDups.length &&
    targetIds.all fun targetId =>
      match context.codeMap.get? targetId with
      | some target => target.id == targetId && target.aliases.isEmpty &&
          rvaInExecutableSection context.pe target.rva
      | none => false

def DynamicCallbackControlClaim.checked
    (context : OriginalDecodedStaticContext)
    (claim : DynamicCallbackControlClaim) : Bool :=
  claim.site.target == .dynamicField
      (match claim.site.target with
      | .dynamicField register _ => register
      | _ => .eax) claim.callbackFieldOffset &&
    claim.site.checked context &&
    codeTargetInventoryChecked context claim.allowedTargetIds

structure CheckedDynamicCallbackControlClaim
    (context : OriginalDecodedStaticContext) where
  authority : ExactOriginalDecodedAuthority context
  claim : DynamicCallbackControlClaim
  checked : claim.checked context = true

structure DynamicCallbackControlRuntime
    (context : OriginalDecodedStaticContext)
    (claim : DynamicCallbackControlClaim)
    (world : RelationalWorld) (state : MachineState) where
  targetShape : ∃ register,
    claim.site.target = .dynamicField register claim.callbackFieldOffset
  dynamicRange : DynamicAddressRangePair
  dynamicRangeMember : dynamicRange ∈ world.dynamicRanges
  callback : RegisteredCallbackPair
  callbackMember : callback ∈ world.registeredCallbacks
  callbackAllowed : callback.targetId ∈ claim.allowedTargetIds
  nodeAddress : Word
  nodeAddressExact :
    (match claim.site.target with
    | .dynamicField register _ => state.registers.get register
    | _ => BitVec.ofNat 32 0) = nodeAddress
  fieldInRange : dynamicRange.originalBase.toNat <= nodeAddress.toNat ∧
    nodeAddress.toNat + claim.callbackFieldOffset + 4 <=
      dynamicRange.originalBase.toNat + dynamicRange.size
  valueExact : Memory.read32 state.memory
      (nodeAddress + BitVec.ofNat 32 claim.callbackFieldOffset) =
    callback.originalAddress

theorem DynamicCallbackControlRuntime.targetValue
    (runtime : DynamicCallbackControlRuntime context claim world state) :
    claim.site.target.expression.eval state = runtime.callback.originalAddress ∧
      runtime.callback.targetId ∈ claim.allowedTargetIds := by
  refine ⟨?_, runtime.callbackAllowed⟩
  rcases runtime.targetShape with ⟨register, targetShape⟩
  have node : state.registers.get register = runtime.nodeAddress := by
    simpa [targetShape] using runtime.nodeAddressExact
  simpa [targetShape, OriginalTargetExpression.expression, Expr.eval, node]
    using runtime.valueExact

end StageA.Relational.OriginalIndirectControlAuthority
