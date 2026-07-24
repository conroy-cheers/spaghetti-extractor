import StageA.RelationalSegment

namespace StageA.Relational

open StageA.Formal

/-! # Relational value provenance and framed transition summaries

This module is the common proof vocabulary for values which cross control or
call boundaries.  Origins are propositions about concrete paired words, not
runtime tags.  Storage classes describe where an expression obtained a value;
they do not independently authorize the value's semantic origin.
-/

namespace ValueProvenance

inductive ValueSource where
  | exactExpression
  | register (original candidate : Reg)
  | immutableImageWord (originalAddress candidateAddress : Nat)
  | staticWord (slotId : Nat)
  | stackFrameWord (rangeId offset : Nat)
  | dynamicRangeWord (rangeId offset : Nat)
  | stackExpression (original candidate : Expr)
  | dynamicExpression (original candidate : Expr)
  | importAddress (identity : ExternalTarget)
deriving Repr, DecidableEq

abbrev ValueOriginAtom := StageA.Relational.ValueOriginAtom

/-- A bounded finite disjunction is represented directly as a duplicate-free
atom inventory.  There is no `unknown` constructor: failure to establish an
origin remains an incomplete proof obligation. -/
structure ValueOrigin where
  alternatives : List ValueOriginAtom
deriving Repr, DecidableEq

def importIdentityChecked
    (context : StaticProofContext) (identity : ExternalTarget) : Bool :=
  (context.originalImportCertificate.imports.any fun imported =>
    normalizeImport imported == identity) &&
  (context.candidateImportCertificate.imports.any fun imported =>
    normalizeImport imported == identity)

def ValueSource.checked (context : StaticProofContext) : ValueSource -> Bool
  | .staticWord slotId => (context.staticWordRelationSlotById slotId).isSome
  | .importAddress identity => importIdentityChecked context identity
  | _ => true

def _root_.StageA.Relational.ValueOriginAtom.checked
    (context : StaticProofContext)
    (origin : ValueOriginAtom) : Bool :=
  match origin with
  | .exactBits value => value < 2 ^ 32
  | .staticCodeTarget targetId offset =>
      match context.codeMap.get? targetId with
      | none => false
      | some target =>
          rvaInExecutableSection context.originalPe (target.originalRva + offset) &&
            rvaInExecutableSection context.candidatePe
              (target.candidateRva + offset)
  | .staticDataLocation targetId offset =>
      match context.dataMap.get? targetId with
      | none => false
      | some target => offset < max 1 target.mappedSize
  | .importTarget identity => importIdentityChecked context identity
  | .stackFrameLocation _ _ |
      .dynamicRangeLocation _ _ | .opaqueResource _ => true
  | .registeredCallback targetId => (context.codeMap.get? targetId).isSome

def ValueOrigin.checked (context : StaticProofContext)
    (finiteAlternativeBudget : Nat) (origin : ValueOrigin) : Bool :=
  finiteAlternativeBudget > 0 &&
    !origin.alternatives.isEmpty &&
    origin.alternatives.length <= finiteAlternativeBudget &&
    origin.alternatives.length == origin.alternatives.eraseDups.length &&
    origin.alternatives.all (ValueOriginAtom.checked context)

def _root_.StageA.Relational.ValueOriginAtom.Holds
    (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Word) :
    ValueOriginAtom -> Prop
  | .exactBits value =>
      original = BitVec.ofNat 32 value ∧ candidate = BitVec.ofNat 32 value
  | .staticCodeTarget targetId offset =>
      ∃ target,
        context.codeMap.get? targetId = some target ∧
          ((offset = 0 ∧
              codeAddressMatches context.originalPe.imageBase target.originalRva
                target.originalAliases original = true ∧
              codeAddressMatches context.candidatePe.imageBase target.candidateRva
                target.candidateAliases candidate = true) ∨
            (0 < offset ∧
              original = BitVec.ofNat 32
                (context.originalPe.imageBase + target.originalRva + offset) ∧
              candidate = BitVec.ofNat 32
                (context.candidatePe.imageBase + target.candidateRva + offset)))
  | .staticDataLocation targetId offset =>
      ∃ target,
        context.dataMap.get? targetId = some target ∧
          original = BitVec.ofNat 32 (target.originalValue + offset) ∧
          candidate = BitVec.ofNat 32 (target.candidateValue + offset)
  | .importTarget identity =>
      ∃ imported,
        imported ∈ world.importAddresses ∧ imported.imported = identity ∧
          original = imported.originalAddress ∧
          candidate = imported.candidateAddress
  | .stackFrameLocation rangeId offset =>
      ∃ range,
        range ∈ world.stackRanges ∧ range.id = rangeId ∧ offset < range.size ∧
          original = range.originalBase + BitVec.ofNat 32 offset ∧
          candidate = range.candidateBase + BitVec.ofNat 32 offset
  | .dynamicRangeLocation rangeId offset =>
      ∃ range,
        range ∈ world.dynamicRanges ∧ range.id = rangeId ∧ offset < range.size ∧
          original = range.originalBase + BitVec.ofNat 32 offset ∧
          candidate = range.candidateBase + BitVec.ofNat 32 offset
  | .opaqueResource resourceId =>
      ∃ resource,
        resource ∈ world.opaqueResources ∧ resource.id = resourceId ∧
          original = resource.original ∧ candidate = resource.candidate
  | .registeredCallback targetId =>
      ∃ callback,
        callback ∈ world.registeredCallbacks ∧ callback.targetId = targetId ∧
          original = callback.originalAddress ∧
          candidate = callback.candidateAddress

theorem _root_.StageA.Relational.ValueOriginAtom.matches_eq_true_iff
    (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Word)
    (atom : ValueOriginAtom) :
    atom.matches context world original candidate = true ↔
      atom.Holds context world original candidate := by
  cases atom with
  | exactBits value =>
      simp [ValueOriginAtom.matches, ValueOriginAtom.Holds]
  | staticCodeTarget targetId offset =>
      cases targetFound : context.codeMap.get? targetId with
      | none =>
          simp [ValueOriginAtom.matches, ValueOriginAtom.Holds, targetFound]
      | some target =>
          by_cases offsetZero : offset = 0
          · simp [ValueOriginAtom.matches, ValueOriginAtom.Holds, targetFound,
              offsetZero]
          · have offsetPositive : 0 < offset := Nat.pos_of_ne_zero offsetZero
            simp [ValueOriginAtom.matches, ValueOriginAtom.Holds, targetFound,
              offsetZero, offsetPositive]
  | staticDataLocation targetId offset =>
      cases targetFound : context.dataMap.get? targetId with
      | none =>
          simp [ValueOriginAtom.matches, ValueOriginAtom.Holds, targetFound]
      | some target =>
          simp [ValueOriginAtom.matches, ValueOriginAtom.Holds, targetFound,
            and_assoc]
  | importTarget identity =>
      simp [ValueOriginAtom.matches, ValueOriginAtom.Holds, and_assoc]
  | stackFrameLocation rangeId offset =>
      simp [ValueOriginAtom.matches, ValueOriginAtom.Holds, and_assoc]
  | dynamicRangeLocation rangeId offset =>
      simp [ValueOriginAtom.matches, ValueOriginAtom.Holds, and_assoc]
  | opaqueResource resourceId =>
      simp [ValueOriginAtom.matches, ValueOriginAtom.Holds, and_assoc]
  | registeredCallback targetId =>
      simp [ValueOriginAtom.matches, ValueOriginAtom.Holds, and_assoc]

def ValueOrigin.Holds (context : StaticProofContext)
    (world : RelationalWorld) (origin : ValueOrigin)
    (original candidate : Word) : Prop :=
  ∃ atom, atom ∈ origin.alternatives ∧
    atom.Holds context world original candidate

theorem ValueOrigin.holds_iff_any_matches
    (context : StaticProofContext)
    (world : RelationalWorld) (origin : ValueOrigin)
    (original candidate : Word) :
    origin.Holds context world original candidate ↔
      origin.alternatives.any
        (ValueOriginAtom.matches context world original candidate) = true := by
  simp [ValueOrigin.Holds, ValueOriginAtom.matches_eq_true_iff]

theorem ValueOriginAtom.finiteRelationHolds_of_holds
    (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Word)
    (finiteAlternativeBudget : Nat) (origins : List ValueOriginAtom)
    (atom : ValueOriginAtom) (member : atom ∈ origins)
    (holds : atom.Holds context world original candidate) :
    (StaticWordRelationKind.finiteOrigins finiteAlternativeBudget origins).holds
        context world original candidate = true := by
  simp only [StaticWordRelationKind.holds, List.any_eq_true]
  exact ⟨atom, member,
    (ValueOriginAtom.matches_eq_true_iff context world original candidate atom).mpr
      holds⟩

theorem ValueOrigin.holds_of_finiteRelationHolds
    (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Word)
    (finiteAlternativeBudget : Nat) (origin : ValueOrigin)
    (holds :
      (StaticWordRelationKind.finiteOrigins finiteAlternativeBudget
          origin.alternatives).holds context world original candidate = true) :
    origin.Holds context world original candidate := by
  exact
    (ValueOrigin.holds_iff_any_matches context world origin original candidate).mpr
      holds

structure PairedValueClaim where
  original : Expr
  candidate : Expr
  source : ValueSource
  origin : ValueOrigin
deriving Repr, DecidableEq

def PairedValueClaim.checked (context : StaticProofContext)
    (finiteAlternativeBudget : Nat) (claim : PairedValueClaim) : Bool :=
  claim.source.checked context &&
    claim.origin.checked context finiteAlternativeBudget

def PairedValueClaim.Holds (context : StaticProofContext)
    (world : RelationalWorld) (claim : PairedValueClaim)
    (originalState candidateState : MachineState) : Prop :=
  claim.origin.Holds context world
    (claim.original.eval originalState) (claim.candidate.eval candidateState)

inductive MemoryEffectKind where
  | read
  | write
deriving Repr, DecidableEq

/-- Effects are ordered.  A write carries the exact symbolic value; a read has
no value field because the load expression itself remains in the decoded
semantics. -/
structure PairedMemoryEffect where
  kind : MemoryEffectKind
  width : Nat
  originalAddress : Expr
  candidateAddress : Expr
  originalValue : Option Expr := none
  candidateValue : Option Expr := none
deriving Repr, DecidableEq

structure PairedRegisterEffect where
  originalRegister : Reg
  candidateRegister : Reg
  originalValue : Expr
  candidateValue : Expr
deriving Repr, DecidableEq

structure PairedFlagEffect where
  bit : Nat
  originalValue : BoolExpr
  candidateValue : BoolExpr
deriving Repr, DecidableEq

inductive StateComponentEffect where
  | preserve
  | relatedUpdate
deriving Repr, DecidableEq

inductive FaultEffect where
  | noFault
  | pairedFault (faultClass : Nat)
deriving Repr, DecidableEq

inductive FrameAction where
  | preserve
  | push (continuationTargetId : Nat)
  | pop (continuationTargetId : Nat)
  | replace (continuationTargetId : Nat)
  | enterExternal (siteId continuationTargetId : Nat)
  | returnExternal (siteId continuationTargetId : Nat)
deriving Repr, DecidableEq

structure TransitionEffects where
  memory : List PairedMemoryEffect
  registersWritten : List PairedRegisterEffect
  flagsWritten : List PairedFlagEffect
  frameAction : FrameAction
  externalSiteId : Option Nat := none
  x87 : StateComponentEffect := .preserve
  fsTls : StateComponentEffect := .preserve
  undefinedValues : StateComponentEffect := .preserve
  fault : FaultEffect := .noFault
deriving Repr, DecidableEq

def PairedMemoryEffect.shapeChecked (effect : PairedMemoryEffect) : Bool :=
  (effect.width == 1 || effect.width == 2 || effect.width == 4 ||
      effect.width == 8 || effect.width == 10) &&
    match effect.kind with
    | .read => effect.originalValue.isNone && effect.candidateValue.isNone
    | .write =>
        effect.originalValue.isSome && effect.candidateValue.isSome

def TransitionEffects.checked (effects : TransitionEffects) : Bool :=
  effects.memory.all PairedMemoryEffect.shapeChecked &&
    effects.flagsWritten.all fun effect => effect.bit < 32 &&
    (effects.flagsWritten.map (·.bit)).length ==
      (effects.flagsWritten.map (·.bit)).eraseDups.length &&
    (effects.registersWritten.map (·.originalRegister)).length ==
      (effects.registersWritten.map (·.originalRegister)).eraseDups.length &&
    (effects.registersWritten.map (·.candidateRegister)).length ==
      (effects.registersWritten.map (·.candidateRegister)).eraseDups.length &&
    match effects.frameAction, effects.externalSiteId with
    | .enterExternal siteId _, some observed
    | .returnExternal siteId _, some observed => siteId == observed
    | .enterExternal _ _, none | .returnExternal _ _, none => false
    | _, none => true
    | _, some _ => false

def PairedMemoryEffect.originalWrite? (effect : PairedMemoryEffect) :
    Option (Expr × Expr) :=
  match effect.kind, effect.originalValue with
  | .write, some value => some (effect.originalAddress, value)
  | _, _ => none

def PairedMemoryEffect.candidateWrite? (effect : PairedMemoryEffect) :
    Option (Expr × Expr) :=
  match effect.kind, effect.candidateValue with
  | .write, some value => some (effect.candidateAddress, value)
  | _, _ => none

def TransitionEffects.originalWrites (effects : TransitionEffects) :
    List (Expr × Expr) :=
  effects.memory.filterMap PairedMemoryEffect.originalWrite?

def TransitionEffects.candidateWrites (effects : TransitionEffects) :
    List (Expr × Expr) :=
  effects.memory.filterMap PairedMemoryEffect.candidateWrite?

def TransitionEffects.originalConcreteWrites (effects : TransitionEffects)
    (state : MachineState) : List (Word × Word) :=
  effects.originalWrites.map fun write =>
    (write.1.eval state, write.2.eval state)

def TransitionEffects.candidateConcreteWrites (effects : TransitionEffects)
    (state : MachineState) : List (Word × Word) :=
  effects.candidateWrites.map fun write =>
    (write.1.eval state, write.2.eval state)

/-- Exact decoded semantics remain authoritative.  This predicate prevents an
effect summary from silently omitting, reordering, or changing any write. -/
def TransitionEffects.WritesImplement
    (effects : TransitionEffects)
    (original candidate : NormalizedSymbolicBehavior) : Prop :=
  original.writes = effects.originalWrites ∧
    candidate.writes = effects.candidateWrites

/-- Runtime call/callback transitions use the same ordered write inventory as
internal symbolic segments.  Other architectural fields are re-established by
the target `StateRel`; the summary never grants an unlisted memory mutation. -/
def TransitionEffects.RuntimeMemoryImplements
    (effects : TransitionEffects)
    (originalBefore candidateBefore originalAfter candidateAfter : MachineState) : Prop :=
  originalAfter.memory =
      applyConcreteWrites originalBefore.memory
        (effects.originalConcreteWrites originalBefore) ∧
    candidateAfter.memory =
      applyConcreteWrites candidateBefore.memory
        (effects.candidateConcreteWrites candidateBefore)

def TransitionEffects.originalRegisterEffect?
    (effects : TransitionEffects) (register : Reg) :
    Option PairedRegisterEffect :=
  effects.registersWritten.find? fun effect =>
    effect.originalRegister == register

def TransitionEffects.candidateRegisterEffect?
    (effects : TransitionEffects) (register : Reg) :
    Option PairedRegisterEffect :=
  effects.registersWritten.find? fun effect =>
    effect.candidateRegister == register

/-- Exact runtime register semantics for a transition summary. Registers absent
from the write inventory are preserved; listed registers equal their symbolic
pre-state expressions. -/
def TransitionEffects.RuntimeRegistersImplement
    (effects : TransitionEffects)
    (originalBefore candidateBefore originalAfter candidateAfter : MachineState) :
    Prop :=
  (∀ register,
    match effects.originalRegisterEffect? register with
    | none =>
        originalAfter.registers.get register =
          originalBefore.registers.get register
    | some effect =>
        originalAfter.registers.get register =
          effect.originalValue.eval originalBefore) ∧
  (∀ register,
    match effects.candidateRegisterEffect? register with
    | none =>
        candidateAfter.registers.get register =
          candidateBefore.registers.get register
    | some effect =>
        candidateAfter.registers.get register =
          effect.candidateValue.eval candidateBefore)

theorem TransitionEffects.RuntimeRegistersImplement.originalPreserved
    (effects : TransitionEffects)
    (originalBefore candidateBefore originalAfter candidateAfter : MachineState)
    (register : Reg)
    (implemented : effects.RuntimeRegistersImplement originalBefore
      candidateBefore originalAfter candidateAfter)
    (missing : effects.originalRegisterEffect? register = none) :
    originalAfter.registers.get register =
      originalBefore.registers.get register := by
  simpa [missing] using implemented.1 register

theorem TransitionEffects.RuntimeRegistersImplement.candidatePreserved
    (effects : TransitionEffects)
    (originalBefore candidateBefore originalAfter candidateAfter : MachineState)
    (register : Reg)
    (implemented : effects.RuntimeRegistersImplement originalBefore
      candidateBefore originalAfter candidateAfter)
    (missing : effects.candidateRegisterEffect? register = none) :
    candidateAfter.registers.get register =
      candidateBefore.registers.get register := by
  simpa [missing] using implemented.2 register

/-- Transport one finite value-origin relation through an exact pair of
preserved registers. -/
theorem RegisterValueOriginRelation.holds_of_preserved
    (context : StaticProofContext) (world : RelationalWorld)
    (relation : RegisterValueOriginRelation)
    (originalBefore candidateBefore originalAfter candidateAfter : MachineState)
    (source :
      relation.holds context world originalBefore.registers
        candidateBefore.registers = true)
    (originalPreserved :
      originalAfter.registers.get relation.original =
        originalBefore.registers.get relation.original)
    (candidatePreserved :
      candidateAfter.registers.get relation.candidate =
        candidateBefore.registers.get relation.candidate) :
    relation.holds context world originalAfter.registers
      candidateAfter.registers = true := by
  simp only [RegisterValueOriginRelation.holds, List.any_eq_true] at source ⊢
  rcases source with ⟨origin, member, originMatches⟩
  exact ⟨origin, member, by
    simpa [originalPreserved, candidatePreserved] using originMatches⟩

/-- Introduce a register-origin relation from an exact result claim. -/
theorem RegisterValueOriginRelation.holds_of_valueClaim
    (context : StaticProofContext) (world : RelationalWorld)
    (relation : RegisterValueOriginRelation)
    (claim : PairedValueClaim)
    (original candidate : MachineState)
    (originalResult : claim.original = .inputReg relation.original)
    (candidateResult : claim.candidate = .inputReg relation.candidate)
    (origins : claim.origin.alternatives = relation.origins)
    (holds : claim.Holds context world original candidate) :
    relation.holds context world original.registers candidate.registers = true := by
  rcases holds with ⟨origin, member, originHolds⟩
  simp only [RegisterValueOriginRelation.holds, List.any_eq_true]
  refine ⟨origin, origins ▸ member, ?_⟩
  apply (ValueOriginAtom.matches_eq_true_iff context world
    (original.registers.get relation.original)
    (candidate.registers.get relation.candidate) origin).mpr
  simpa [PairedValueClaim.Holds, originalResult, candidateResult, Expr.eval] using
    originHolds

/-- Introduce a memory-origin relation after one exact paired 32-bit write. -/
theorem MemoryValueOriginRelation.holds_afterExactWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (relation : MemoryValueOriginRelation)
    (original candidate : MachineState)
    (originalBase candidateBase : Memory)
    (originalValue candidateValue : Word)
    (origin : ValueOriginAtom)
    (member : origin ∈ relation.origins)
    (originHolds :
      origin.Holds context world originalValue candidateValue)
    (originalMemory :
      original.memory = (originalBase.write32
        (relation.originalAddress.eval original) originalValue))
    (candidateMemory :
      candidate.memory = (candidateBase.write32
        (relation.candidateAddress.eval candidate) candidateValue))
    (originalFits :
      (relation.originalAddress.eval original).toNat + 4 <= 2 ^ 32)
    (candidateFits :
      (relation.candidateAddress.eval candidate).toNat + 4 <= 2 ^ 32) :
    relation.holds context world original candidate = true := by
  simp only [MemoryValueOriginRelation.holds, List.any_eq_true]
  refine ⟨origin, member, ?_⟩
  apply (ValueOriginAtom.matches_eq_true_iff context world
    (Memory.read32 original.memory (relation.originalAddress.eval original))
    (Memory.read32 candidate.memory (relation.candidateAddress.eval candidate))
    origin).mpr
  rw [originalMemory, candidateMemory,
    Memory.read32_write32_same_of_fits _ _ _ originalFits,
    Memory.read32_write32_same_of_fits _ _ _ candidateFits]
  exact originHolds

/-- Preserve a memory-origin relation through any transition that proves the
two observed words unchanged. Footprint and no-alias analyses discharge these
equalities without entering this generic value layer. -/
theorem MemoryValueOriginRelation.holds_of_read32_eq
    (context : StaticProofContext) (world : RelationalWorld)
    (relation : MemoryValueOriginRelation)
    (originalBefore candidateBefore originalAfter candidateAfter : MachineState)
    (source :
      relation.holds context world originalBefore candidateBefore = true)
    (originalRead :
      Memory.read32 originalAfter.memory
          (relation.originalAddress.eval originalAfter) =
        Memory.read32 originalBefore.memory
          (relation.originalAddress.eval originalBefore))
    (candidateRead :
      Memory.read32 candidateAfter.memory
          (relation.candidateAddress.eval candidateAfter) =
        Memory.read32 candidateBefore.memory
          (relation.candidateAddress.eval candidateBefore)) :
    relation.holds context world originalAfter candidateAfter = true := by
  simp only [MemoryValueOriginRelation.holds, List.any_eq_true] at source ⊢
  rcases source with ⟨origin, member, originMatches⟩
  exact ⟨origin, member, by
    simpa [originalRead, candidateRead] using originMatches⟩

/-- A world transition preserves a finite origin inventory when every concrete
origin witness valid before the transition remains valid afterward. -/
def ValueOriginsPreserved
    (context : StaticProofContext)
    (before after : RelationalWorld)
    (origins : List ValueOriginAtom) : Prop :=
  ∀ origin, origin ∈ origins ->
    ∀ original candidate,
      origin.Holds context before original candidate ->
        origin.Holds context after original candidate

theorem valueOriginsPreserved_sameWorld
    (context : StaticProofContext) (world : RelationalWorld)
    (origins : List ValueOriginAtom) :
    ValueOriginsPreserved context world world origins := by
  intro _origin _member _original _candidate holds
  exact holds

/-- Preserve one exact memory-origin witness while both the world and the
address expression may change. The supplied read equalities are discharged by
checked call-frame stack deltas and framed memory-effect proofs. -/
theorem MemoryValueOriginRelation.holds_of_rebased_read32_eq
    (context : StaticProofContext)
    (beforeWorld afterWorld : RelationalWorld)
    (beforeRelation afterRelation : MemoryValueOriginRelation)
    (originalBefore candidateBefore originalAfter candidateAfter : MachineState)
    (sameOrigins : beforeRelation.origins = afterRelation.origins)
    (originsPreserved :
      ValueOriginsPreserved context beforeWorld afterWorld
        beforeRelation.origins)
    (source :
      beforeRelation.holds context beforeWorld originalBefore candidateBefore =
        true)
    (originalRead :
      Memory.read32 originalAfter.memory
          (afterRelation.originalAddress.eval originalAfter) =
        Memory.read32 originalBefore.memory
          (beforeRelation.originalAddress.eval originalBefore))
    (candidateRead :
      Memory.read32 candidateAfter.memory
          (afterRelation.candidateAddress.eval candidateAfter) =
        Memory.read32 candidateBefore.memory
          (beforeRelation.candidateAddress.eval candidateBefore)) :
    afterRelation.holds context afterWorld originalAfter candidateAfter = true := by
  simp only [MemoryValueOriginRelation.holds, List.any_eq_true] at source ⊢
  rcases source with ⟨origin, member, originMatches⟩
  have sourceHolds :
      origin.Holds context beforeWorld
        (Memory.read32 originalBefore.memory
          (beforeRelation.originalAddress.eval originalBefore))
        (Memory.read32 candidateBefore.memory
          (beforeRelation.candidateAddress.eval candidateBefore)) :=
    (ValueOriginAtom.matches_eq_true_iff context beforeWorld _ _ origin).mp
      originMatches
  have targetHolds := originsPreserved origin member _ _ sourceHolds
  refine ⟨origin, sameOrigins ▸ member, ?_⟩
  apply (ValueOriginAtom.matches_eq_true_iff context afterWorld _ _ origin).mpr
  simpa [originalRead, candidateRead] using targetHolds

/-- Store a register-origin value into a paired memory word. -/
theorem MemoryValueOriginRelation.holds_afterExactWrite_of_registerOrigin
    (context : StaticProofContext) (world : RelationalWorld)
    (registerRelation : RegisterValueOriginRelation)
    (memoryRelation : MemoryValueOriginRelation)
    (sameOrigins : registerRelation.origins = memoryRelation.origins)
    (originalBefore candidateBefore originalAfter candidateAfter : MachineState)
    (registerHolds :
      registerRelation.holds context world originalBefore.registers
        candidateBefore.registers = true)
    (originalBase candidateBase : Memory)
    (originalMemory :
      originalAfter.memory = originalBase.write32
        (memoryRelation.originalAddress.eval originalAfter)
        (originalBefore.registers.get registerRelation.original))
    (candidateMemory :
      candidateAfter.memory = candidateBase.write32
        (memoryRelation.candidateAddress.eval candidateAfter)
        (candidateBefore.registers.get registerRelation.candidate))
    (originalFits :
      (memoryRelation.originalAddress.eval originalAfter).toNat + 4 <= 2 ^ 32)
    (candidateFits :
      (memoryRelation.candidateAddress.eval candidateAfter).toNat + 4 <= 2 ^ 32) :
    memoryRelation.holds context world originalAfter candidateAfter = true := by
  simp only [RegisterValueOriginRelation.holds, List.any_eq_true]
      at registerHolds
  rcases registerHolds with ⟨origin, member, originMatches⟩
  apply MemoryValueOriginRelation.holds_afterExactWrite context world
    memoryRelation originalAfter candidateAfter originalBase candidateBase
    (originalBefore.registers.get registerRelation.original)
    (candidateBefore.registers.get registerRelation.candidate)
    origin (sameOrigins ▸ member)
  · exact (ValueOriginAtom.matches_eq_true_iff context world
      (originalBefore.registers.get registerRelation.original)
      (candidateBefore.registers.get registerRelation.candidate) origin).mp
        originMatches
  · exact originalMemory
  · exact candidateMemory
  · exact originalFits
  · exact candidateFits

/-- Reload a paired memory-origin relation into a paired register relation. -/
theorem RegisterValueOriginRelation.holds_of_memoryLoad
    (context : StaticProofContext) (world : RelationalWorld)
    (registerRelation : RegisterValueOriginRelation)
    (memoryRelation : MemoryValueOriginRelation)
    (original candidate : MachineState)
    (sameOrigins : memoryRelation.origins = registerRelation.origins)
    (memoryHolds :
      memoryRelation.holds context world original candidate = true)
    (originalLoad :
      original.registers.get registerRelation.original =
        Memory.read32 original.memory
          (memoryRelation.originalAddress.eval original))
    (candidateLoad :
      candidate.registers.get registerRelation.candidate =
        Memory.read32 candidate.memory
          (memoryRelation.candidateAddress.eval candidate)) :
    registerRelation.holds context world original.registers
      candidate.registers = true := by
  simp only [MemoryValueOriginRelation.holds, List.any_eq_true] at memoryHolds
  rcases memoryHolds with ⟨origin, member, originMatches⟩
  simp only [RegisterValueOriginRelation.holds, List.any_eq_true]
  refine ⟨origin, sameOrigins ▸ member, ?_⟩
  simpa [originalLoad, candidateLoad] using originMatches

theorem registerValueOriginRelationsHold_append_of_holds
    (context : StaticProofContext) (world : RelationalWorld)
    (left right : List RegisterValueOriginRelation)
    (original candidate : PureState)
    (leftHolds :
      registerValueOriginRelationsHold context world left original candidate = true)
    (rightHolds :
      registerValueOriginRelationsHold context world right original candidate = true) :
    registerValueOriginRelationsHold context world (left ++ right)
      original candidate = true := by
  simp only [registerValueOriginRelationsHold, List.all_append, Bool.and_eq_true]
  exact ⟨leftHolds, rightHolds⟩

theorem memoryValueOriginRelationsHold_append_of_holds
    (context : StaticProofContext) (world : RelationalWorld)
    (left right : List MemoryValueOriginRelation)
    (original candidate : MachineState)
    (leftHolds :
      memoryValueOriginRelationsHold context world left original candidate = true)
    (rightHolds :
      memoryValueOriginRelationsHold context world right original candidate = true) :
    memoryValueOriginRelationsHold context world (left ++ right)
      original candidate = true := by
  simp only [memoryValueOriginRelationsHold, List.all_append, Bool.and_eq_true]
  exact ⟨leftHolds, rightHolds⟩

def StateInvariant.withAdditionalRegisterValueOriginRelations
    (invariant : StateInvariant)
    (relations : List RegisterValueOriginRelation) : StateInvariant :=
  { invariant with
    registerValueOriginRelations :=
      invariant.registerValueOriginRelations ++ relations }

def StateInvariant.withAdditionalMemoryValueOriginRelations
    (invariant : StateInvariant)
    (relations : List MemoryValueOriginRelation) : StateInvariant :=
  { invariant with
    memoryValueOriginRelations :=
      invariant.memoryValueOriginRelations ++ relations }

theorem StateRel.withAdditionalRegisterValueOriginRelations
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant)
    (relations : List RegisterValueOriginRelation)
    (original candidate : MachineState)
    (related : StateRel context world invariant original candidate)
    (additionalHold :
      registerValueOriginRelationsHold context world relations
        original.registers candidate.registers = true) :
    StateRel context world
      (ValueProvenance.StateInvariant.withAdditionalRegisterValueOriginRelations
        invariant relations)
      original candidate := by
  rcases related with
    ⟨worldValid, stackRangesValid, stackMemory, importsStatic, importsComplete,
      importsMemory, originalImmutable, candidateImmutable, core, trailing⟩
  rcases core with
    ⟨registers, bounds, separations, stackWindows, ordinaryMemory,
      dynamicMemory, undefinedValue, x87, flags, fsBase⟩
  rcases trailing with
    ⟨importRegisters, originRegisters, memoryOrigins, dynamicRegisters,
      dynamicStacks, predicates⟩
  have strengthenedOrigins := registerValueOriginRelationsHold_append_of_holds
    context world invariant.registerValueOriginRelations relations
    original.registers candidate.registers originRegisters additionalHold
  refine ⟨worldValid, stackRangesValid, stackMemory, importsStatic,
    importsComplete, importsMemory, originalImmutable, candidateImmutable, ?_, ?_⟩
  · refine ⟨registers, bounds, separations, stackWindows, ordinaryMemory,
      ?_, undefinedValue, x87, flags, fsBase⟩
    exact {
      staticPointerSlots := dynamicMemory.staticPointerSlots
      staticWordSlots := dynamicMemory.staticWordSlots
      active := {
        registerRanges := by
          simpa [StateInvariant.withAdditionalRegisterValueOriginRelations] using
            dynamicMemory.active.registerRanges
        stackRanges := by
          simpa [StateInvariant.withAdditionalRegisterValueOriginRelations] using
            dynamicMemory.active.stackRanges
      }
    }
  · refine ⟨importRegisters, strengthenedOrigins, ?_, ?_, ?_, ?_⟩
    · simpa [StateInvariant.withAdditionalRegisterValueOriginRelations] using
        memoryOrigins
    · simpa [StateInvariant.withAdditionalRegisterValueOriginRelations] using
        dynamicRegisters
    · simpa [StateInvariant.withAdditionalRegisterValueOriginRelations] using
        dynamicStacks
    · simpa [StateInvariant.withAdditionalRegisterValueOriginRelations] using
        predicates

theorem StateRel.withAdditionalMemoryValueOriginRelations
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant)
    (relations : List MemoryValueOriginRelation)
    (original candidate : MachineState)
    (related : StateRel context world invariant original candidate)
    (additionalHold :
      memoryValueOriginRelationsHold context world relations
        original candidate = true) :
    StateRel context world
      (ValueProvenance.StateInvariant.withAdditionalMemoryValueOriginRelations
        invariant relations)
      original candidate := by
  rcases related with
    ⟨worldValid, stackRangesValid, stackMemory, importsStatic, importsComplete,
      importsMemory, originalImmutable, candidateImmutable, core, trailing⟩
  rcases core with
    ⟨registers, bounds, separations, stackWindows, ordinaryMemory,
      dynamicMemory, undefinedValue, x87, flags, fsBase⟩
  rcases trailing with
    ⟨importRegisters, originRegisters, memoryOrigins, dynamicRegisters,
      dynamicStacks, predicates⟩
  have strengthenedOrigins := memoryValueOriginRelationsHold_append_of_holds
    context world invariant.memoryValueOriginRelations relations
    original candidate memoryOrigins additionalHold
  refine ⟨worldValid, stackRangesValid, stackMemory, importsStatic,
    importsComplete, importsMemory, originalImmutable, candidateImmutable, ?_, ?_⟩
  · refine ⟨registers, bounds, separations, stackWindows, ordinaryMemory,
      ?_, undefinedValue, x87, flags, fsBase⟩
    exact {
      staticPointerSlots := dynamicMemory.staticPointerSlots
      staticWordSlots := dynamicMemory.staticWordSlots
      active := {
        registerRanges := by
          simpa [StateInvariant.withAdditionalMemoryValueOriginRelations] using
            dynamicMemory.active.registerRanges
        stackRanges := by
          simpa [StateInvariant.withAdditionalMemoryValueOriginRelations] using
            dynamicMemory.active.stackRanges
      }
    }
  · refine ⟨importRegisters, ?_, strengthenedOrigins, ?_, ?_, ?_⟩
    · simpa [StateInvariant.withAdditionalMemoryValueOriginRelations] using
        originRegisters
    · simpa [StateInvariant.withAdditionalMemoryValueOriginRelations] using
        dynamicRegisters
    · simpa [StateInvariant.withAdditionalMemoryValueOriginRelations] using
        dynamicStacks
    · simpa [StateInvariant.withAdditionalMemoryValueOriginRelations] using
        predicates

/-- The common memory-framing certificate.  Its write list is both an exact
projection of decoded symbolic behavior and a checked classification accepted
by the flat-memory preservation kernel.  Read effects remain diagnostic until
an exact read-footprint checker is supplied; they never authorize a write. -/
structure PreparedWordFrameCertificate where
  effects : TransitionEffects
  preparedWrites : PairedPreparedWordWritesClaim
deriving Repr, DecidableEq

def PreparedWordFrameCertificate.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (certificate : PreparedWordFrameCertificate) : Bool :=
  certificate.effects.checked &&
    certificate.preparedWrites.checked context sourceInvariant &&
    certificate.effects.originalWrites ==
      certificate.preparedWrites.originalSymbolicWrites &&
    certificate.effects.candidateWrites ==
      certificate.preparedWrites.candidateSymbolicWrites

/-- A single framed-update interface for stack, writable static, dynamic, and
static-to-dynamic-pointer writes.  Decoded semantics establish the exact
ordered effects; the existing flat-memory theorem checks classification,
disjointness, and related updates.  Non-memory architectural relations stay
explicit and therefore cannot be widened by the summary. -/
theorem StateRel.afterPreparedWordFrame
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (certificate : PreparedWordFrameCertificate)
    (contextValid : context.StructurallyValid)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (certificateChecked :
      certificate.checked context sourceInvariant = true)
    (writesImplement :
      certificate.effects.WritesImplement originalBehavior candidateBehavior)
    (registers : registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) targetInvariant.registerRelations
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true)
    (bounds : boundsRelated targetInvariant.bounds
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true)
    (separations : addressSeparationsRelated targetInvariant.addressSeparations
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true)
    (stackWindows : stackWindowsRelated world targetInvariant.stackWindows
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true)
    (x87 :
      ((originalBehavior.eval originalState).nextMachineState originalState).x87 =
      ((candidateBehavior.eval candidateState).nextMachineState candidateState).x87)
    (flags : flagsRelated targetInvariant.flagBits
      (originalBehavior.eval originalState).eflags
      (candidateBehavior.eval candidateState).eflags = true)
    (importRegisters : importRegisterRelationsHold world
      targetInvariant.importRegisterRelations
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true)
    (originRegisters : registerValueOriginRelationsHold context world
      targetInvariant.registerValueOriginRelations
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true)
    (memoryOrigins : memoryValueOriginRelationsHold context world
      targetInvariant.memoryValueOriginRelations
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true)
    (dynamicRegisters : activeDynamicRegisterRangeRelationsHold context world
      targetInvariant.dynamicRegisterRangeRelations
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true)
    (dynamicStacks : activeDynamicStackRangeRelationsHold context world
      targetInvariant.dynamicStackRangeRelations
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true)
    (predicates : pairedStatePredicatesHold targetInvariant.predicates
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true) :
    StateRel context world targetInvariant
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) := by
  simp only [PreparedWordFrameCertificate.checked, Bool.and_eq_true,
    beq_iff_eq] at certificateChecked
  rcases certificateChecked with
    ⟨⟨⟨_effectsChecked, preparedChecked⟩, originalSummary⟩,
      candidateSummary⟩
  have originalSymbolic :
      originalBehavior.writes =
        certificate.preparedWrites.originalSymbolicWrites :=
    writesImplement.1.trans originalSummary
  have candidateSymbolic :
      candidateBehavior.writes =
        certificate.preparedWrites.candidateSymbolicWrites :=
    writesImplement.2.trans candidateSummary
  have originalWrites :
      (originalBehavior.eval originalState).writes =
        certificate.preparedWrites.originalWrites originalState := by
    simp [NormalizedSymbolicBehavior.eval, evalNormalizedWrites,
      originalSymbolic, PairedPreparedWordWritesClaim.originalSymbolicWrites,
      PairedPreparedWordWritesClaim.originalWrites]
  have candidateWrites :
      (candidateBehavior.eval candidateState).writes =
        certificate.preparedWrites.candidateWrites candidateState := by
    simp [NormalizedSymbolicBehavior.eval, evalNormalizedWrites,
      candidateSymbolic, PairedPreparedWordWritesClaim.candidateSymbolicWrites,
      PairedPreparedWordWritesClaim.candidateWrites]
  exact StateRel.afterPairedPreparedWordWritesEvaluation context world
    sourceInvariant targetInvariant originalState candidateState
    (originalBehavior.eval originalState) (candidateBehavior.eval candidateState)
    certificate.preparedWrites contextValid related preparedChecked
    originalWrites candidateWrites rfl rfl registers bounds separations
    stackWindows x87 flags importRegisters originRegisters memoryOrigins
    dynamicRegisters dynamicStacks predicates

inductive IndirectDestination where
  | internalCode (targetId : Nat)
  | imported (identity : ExternalTarget)
  /-- This is only a value-class destination.  A separate checked callable
  capability and ABI route must authorize executing the resource. -/
  | opaqueResource (resourceId : Nat)
deriving Repr, DecidableEq

inductive IndirectTransfer where
  | call (continuationTargetId : Nat)
  | jump
deriving Repr, DecidableEq

structure IndirectExitCertificate where
  finiteAlternativeBudget : Nat
  target : PairedValueClaim
  destinations : List IndirectDestination
  transfer : IndirectTransfer
deriving Repr, DecidableEq

def ValueOriginAtom.destination? : ValueOriginAtom -> Option IndirectDestination
  | .staticCodeTarget targetId 0 => some (.internalCode targetId)
  | .importTarget identity => some (.imported identity)
  | .opaqueResource resourceId => some (.opaqueResource resourceId)
  | .registeredCallback targetId => some (.internalCode targetId)
  | _ => none

def ValueOrigin.destinations? (origin : ValueOrigin) :
    Option (List IndirectDestination) :=
  origin.alternatives.mapM ValueOriginAtom.destination?

def IndirectExitCertificate.destinationShapeChecked
    (certificate : IndirectExitCertificate) : Bool :=
  match certificate.transfer with
  | .jump =>
      certificate.destinations.all fun destination =>
        match destination with
        | .internalCode _ | .opaqueResource _ => true
        | .imported _ => false
  | .call _ =>
      (certificate.destinations.all fun destination =>
        match destination with
        | .internalCode _ | .opaqueResource _ => true
        | .imported _ => false) ||
      match certificate.destinations with
      | [.imported _] => true
      | _ => false

def IndirectExitCertificate.checked
    (context : StaticProofContext) (certificate : IndirectExitCertificate) : Bool :=
  certificate.target.checked context certificate.finiteAlternativeBudget &&
    !certificate.destinations.isEmpty &&
    certificate.destinations.length ==
      certificate.destinations.eraseDups.length &&
    certificate.target.origin.destinations? == some certificate.destinations &&
    certificate.destinationShapeChecked &&
    certificate.destinations.all fun destination =>
      match destination with
      | .internalCode targetId => (context.codeMap.get? targetId).isSome
      | .imported identity => importIdentityChecked context identity
      | .opaqueResource _ => true

def IndirectExitCertificate.outcomeChecked
    (certificate : IndirectExitCertificate)
    (original candidate : NormalizedSymbolicBehavior) : Bool :=
  match certificate.transfer with
  | .call continuation =>
      original.outcome == .indirectCall certificate.target.original continuation &&
        candidate.outcome == .indirectCall certificate.target.candidate continuation
  | .jump =>
      original.outcome == .indirectJump certificate.target.original &&
        candidate.outcome == .indirectJump certificate.target.candidate

def IndirectDestination.Matches (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Word) :
    IndirectDestination -> Prop
  | .internalCode targetId =>
      ∃ target,
        context.codeMap.get? targetId = some target ∧
          codeAddressMatches context.originalPe.imageBase target.originalRva
            target.originalAliases original = true ∧
          codeAddressMatches context.candidatePe.imageBase target.candidateRva
            target.candidateAliases candidate = true
  | .imported identity =>
      ∃ imported,
        imported ∈ world.importAddresses ∧ imported.imported = identity ∧
          original = imported.originalAddress ∧
          candidate = imported.candidateAddress
  | .opaqueResource resourceId =>
      ∃ resource,
        resource ∈ world.opaqueResources ∧ resource.id = resourceId ∧
          original = resource.original ∧ candidate = resource.candidate

/-- This is the semantic member of an indirect-exit certificate.  Static
analysis proposes it; a decoded segment proof, invariant proof, or external
contract must establish it for every source-related state. -/
def IndirectExitCertificate.TargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (certificate : IndirectExitCertificate) : Prop :=
  ∀ world originalState candidateState,
    StateRel context world sourceInvariant originalState candidateState →
      certificate.target.Holds context world originalState candidateState ∧
        ∃ destination,
          destination ∈ certificate.destinations ∧
            destination.Matches context world
              (certificate.target.original.eval originalState)
              (certificate.target.candidate.eval candidateState)

structure CheckedIndirectExitCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (original candidate : NormalizedSymbolicBehavior) where
  certificate : IndirectExitCertificate
  staticChecked : certificate.checked context = true
  outcomeChecked : certificate.outcomeChecked original candidate = true
  targetEvaluation : certificate.TargetEvaluation context sourceInvariant

end ValueProvenance

end StageA.Relational
