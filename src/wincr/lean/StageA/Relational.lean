
import StageA.RelationalMachine
import Std.Tactic.BVDecide

namespace StageA.Relational

open StageA.Formal

theorem normalizeSymbolicBehavior_fields
    (candidate : Bool) (targets : List CodeTargetPair) (behavior : SymbolicBehavior)
    (normalized : NormalizedSymbolicBehavior)
    (result : normalizeSymbolicBehavior candidate targets behavior = some normalized) :
    normalized.registers = behavior.registers ∧
      normalized.x87 = behavior.x87 ∧
      normalized.writes = behavior.writes ∧
      normalized.flags = behavior.flags := by
  cases behaviorOutcome : behavior.outcome with
  | none => simp [normalizeSymbolicBehavior, behaviorOutcome] at result
  | some outcome =>
    cases outcomeNormalized : normalizeOutcomeExpr candidate targets outcome with
    | none => simp [normalizeSymbolicBehavior, behaviorOutcome, outcomeNormalized] at result
    | some normalizedOutcome =>
      simp [normalizeSymbolicBehavior, behaviorOutcome, outcomeNormalized] at result
      subst normalized
      exact ⟨rfl, rfl, rfl, rfl⟩

def NormalizedOutcomeExpr.eval (state : MachineState) : NormalizedOutcomeExpr -> PureOutcome
  | .returned target => .returned (target.eval state)
  | .jump target => .jump target
  | .branch condition taken fallthrough => .branch (condition.eval state) taken fallthrough
  | .call target continuation => .call target continuation
  | .externalCall imported arguments continuation =>
      .externalCall imported (arguments.map (Expr.eval state)) continuation
  | .externalJump imported arguments => .externalJump imported (arguments.map (Expr.eval state))
  | .bulkCopy destination source count direction continuation =>
      .bulkCopy (destination.eval state) (source.eval state) (count.eval state)
        (direction.eval state) continuation
  | .indirectCall target continuation => .indirectCall (target.eval state) continuation
  | .indirectJump target => .indirectJump (target.eval state)
  | .checkedContinue valid continuation => .checkedContinue (valid.eval state) continuation
  | .atomicCompareExchange address expected replacement continuation =>
      .atomicCompareExchange (address.eval state) (expected.eval state) (replacement.eval state) continuation

def evalNormalizedRegisters (state : MachineState) (registers : Registers Expr) : PureState := {
  eax := registers.eax.eval state
  ebx := registers.ebx.eval state
  ecx := registers.ecx.eval state
  edx := registers.edx.eval state
  esi := registers.esi.eval state
  edi := registers.edi.eval state
  ebp := registers.ebp.eval state
  esp := registers.esp.eval state
}

@[simp] theorem evalNormalizedRegisters_get (state : MachineState)
    (registers : Registers Expr) (register : Reg) :
    (evalNormalizedRegisters state registers).get register =
      (registers.get register).eval state := by
  cases register <;> rfl

def evalNormalizedX87 (state : MachineState) (x87 : SymbolicX87State) : ConcreteX87State := {
  stack := x87.stack.map fun value => value.eval state
  control := (x87.control.eval state).extractLsb' 0 16
  status := (x87.status.eval state).extractLsb' 0 16
}

def evalNormalizedWrites (state : MachineState) (writes : List (Expr × Expr)) :
    List (Word × Word) :=
  writes.map fun write => (write.1.eval state, write.2.eval state)

def evalNormalizedFlags (state : MachineState) (flags : Option FlagsExpr) : Word :=
  flags.map (FlagsExpr.eval state) |>.getD state.eflags

@[simp] theorem evalNormalizedFlags_some (state : MachineState) (flags : FlagsExpr) :
    evalNormalizedFlags state (some flags) = flags.eval state := rfl

@[simp] theorem evalNormalizedFlags_none (state : MachineState) :
    evalNormalizedFlags state none = state.eflags := rfl

def NormalizedSymbolicBehavior.eval (state : MachineState)
    (behavior : NormalizedSymbolicBehavior) : RelationalBehavior := {
  registers := evalNormalizedRegisters state behavior.registers
  x87 := evalNormalizedX87 state behavior.x87
  writes := evalNormalizedWrites state behavior.writes
  eflags := evalNormalizedFlags state behavior.flags
  outcome := behavior.outcome.eval state
}

@[simp] theorem NormalizedSymbolicBehavior.eval_registers (state : MachineState)
    (behavior : NormalizedSymbolicBehavior) :
    (behavior.eval state).registers = evalNormalizedRegisters state behavior.registers := rfl

@[simp] theorem NormalizedSymbolicBehavior.eval_x87 (state : MachineState)
    (behavior : NormalizedSymbolicBehavior) :
    (behavior.eval state).x87 = evalNormalizedX87 state behavior.x87 := rfl

@[simp] theorem NormalizedSymbolicBehavior.eval_writes (state : MachineState)
    (behavior : NormalizedSymbolicBehavior) :
    (behavior.eval state).writes = evalNormalizedWrites state behavior.writes := rfl

@[simp] theorem NormalizedSymbolicBehavior.eval_eflags (state : MachineState)
    (behavior : NormalizedSymbolicBehavior) :
    (behavior.eval state).eflags = evalNormalizedFlags state behavior.flags := rfl

@[simp] theorem NormalizedSymbolicBehavior.eval_outcome (state : MachineState)
    (behavior : NormalizedSymbolicBehavior) :
    (behavior.eval state).outcome = behavior.outcome.eval state := rfl

theorem NormalizedSymbolicBehavior.eval_flag_eq_of_some
    (behavior : NormalizedSymbolicBehavior) (flags : FlagsExpr)
    (original candidate : MachineState) (bit : Nat)
    (field : behavior.flags = some flags)
    (related : (flags.eval original).extractLsb' bit 1 =
      (flags.eval candidate).extractLsb' bit 1) :
    (behavior.eval original).eflags.extractLsb' bit 1 =
      (behavior.eval candidate).eflags.extractLsb' bit 1 := by
  simpa only [NormalizedSymbolicBehavior.eval_eflags, field, evalNormalizedFlags_some]
    using related

def codeAddressMatches (imageBase primaryRva : Nat) (aliases : List CodeAlias) (value : Word) : Bool :=
  value == BitVec.ofNat 32 (imageBase + primaryRva) ||
    aliases.any fun alias => value == BitVec.ofNat 32 (imageBase + alias.rva)

def codePointerRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (original candidate : Word) : Bool :=
  targets.any fun target =>
    codeAddressMatches originalImageBase target.originalRva target.originalAliases original &&
    codeAddressMatches candidateImageBase target.candidateRva target.candidateAliases candidate

def valueTargetContainsCandidate (target : ValueTargetPair) (address : Word) : Bool :=
  let base := BitVec.ofNat 32 target.candidateValue
  target.mappedSize > 0 && decide (base <= address) &&
    decide (address < base + BitVec.ofNat 32 target.mappedSize)

def normalizeDataAddress (targets : List ValueTargetPair) (candidateAddress : Word) : Word :=
  match targets.find? (valueTargetContainsCandidate · candidateAddress) with
  | some target =>
      BitVec.ofNat 32 target.originalValue +
        (candidateAddress - BitVec.ofNat 32 target.candidateValue)
  | none => candidateAddress

@[simp] theorem normalizeDataAddress_nil (address : Word) :
    normalizeDataAddress [] address = address := rfl

@[simp] theorem normalizeDataAddress_cons_zero (target : ValueTargetPair)
    (tail : List ValueTargetPair) (address : Word) (zero : target.mappedSize = 0) :
    normalizeDataAddress (target :: tail) address = normalizeDataAddress tail address := by
  simp [normalizeDataAddress, valueTargetContainsCandidate, zero]

theorem normalizeDataAddress_singleton_of_contains (target : ValueTargetPair)
    (address : Word) (contains : valueTargetContainsCandidate target address = true) :
    normalizeDataAddress [target] address =
      BitVec.ofNat 32 target.originalValue +
        (address - BitVec.ofNat 32 target.candidateValue) := by
  simp [normalizeDataAddress, contains]

def mappedValueRelated (targets : List ValueTargetPair) (original candidate : Word) : Bool :=
  targets.any fun target =>
    if target.mappedSize = 0 then
      original == BitVec.ofNat 32 target.originalValue &&
        candidate == BitVec.ofNat 32 target.candidateValue
    else
      (original == BitVec.ofNat 32 target.originalValue &&
        candidate == BitVec.ofNat 32 target.candidateValue) ||
        (valueTargetContainsCandidate target candidate &&
          original == BitVec.ofNat 32 target.originalValue +
            (candidate - BitVec.ofNat 32 target.candidateValue))

def wordRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Word) : Bool :=
  ((original == BitVec.ofNat 32 0) == (candidate == BitVec.ofNat 32 0)) &&
    (original == candidate ||
      codePointerRelated originalImageBase candidateImageBase targets original candidate ||
      mappedValueRelated values original candidate)

@[simp] theorem wordRelated_self (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair) (word : Word) :
    wordRelated originalImageBase candidateImageBase targets values word word = true := by
  simp [wordRelated]

theorem wordRelated_zero_equal {originalImageBase candidateImageBase : Nat}
    {targets : List CodeTargetPair} {values : List ValueTargetPair}
    {original candidate : Word}
    (related : wordRelated originalImageBase candidateImageBase targets values
      original candidate = true) :
    (original == BitVec.ofNat 32 0) = (candidate == BitVec.ofNat 32 0) := by
  simp [wordRelated] at related
  exact related.1

theorem codeTargetAddresses_wordRelated
    (context : StaticProofContext) (world : RelationalWorld)
    (targetId : Nat) (target : CodeTargetPair)
    (original candidate : Word)
    (targetFound : context.codeMap.get? targetId = some target)
    (originalMatches : codeAddressMatches context.originalPe.imageBase
      target.originalRva target.originalAliases original = true)
    (candidateMatches : codeAddressMatches context.candidatePe.imageBase
      target.candidateRva target.candidateAliases candidate = true)
    (zeroesAgree : (original == BitVec.ofNat 32 0) =
      (candidate == BitVec.ofNat 32 0)) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      original candidate = true := by
  have targetArrayMember : target ∈ context.codeMap.entries := by
    have indexed := Array.getElem?_eq_some_iff.mp targetFound
    rcases indexed with ⟨inside, indexed⟩
    have member := Array.getElem_mem inside
    rw [indexed] at member
    exact member
  have targetMember : target ∈ context.codeMap.entries.toList :=
    Array.mem_def.mp targetArrayMember
  have codeRelated : codePointerRelated context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      original candidate = true := by
    simp only [codePointerRelated, List.any_eq_true]
    refine ⟨target, targetMember, ?_⟩
    simp [originalMatches, candidateMatches]
  simp [wordRelated, zeroesAgree, codeRelated]

def codeTargetAddressPairMatches (context : StaticProofContext) (targetId : Nat)
    (original candidate : Word) : Bool :=
  match context.codeMap.get? targetId with
  | none => false
  | some target =>
      codeAddressMatches context.originalPe.imageBase target.originalRva
          target.originalAliases original &&
        codeAddressMatches context.candidatePe.imageBase target.candidateRva
          target.candidateAliases candidate

theorem codeTargetIdAddresses_wordRelated
    (context : StaticProofContext) (world : RelationalWorld)
    (targetId : Nat) (original candidate : Word)
    (matchEvidence : codeTargetAddressPairMatches context targetId original candidate = true)
    (zeroesAgree : (original == BitVec.ofNat 32 0) =
      (candidate == BitVec.ofNat 32 0)) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      original candidate = true := by
  unfold codeTargetAddressPairMatches at matchEvidence
  cases targetResult : context.codeMap.get? targetId with
  | none => simp [targetResult] at matchEvidence
  | some target =>
      simp only [targetResult, Bool.and_eq_true] at matchEvidence
      exact codeTargetAddresses_wordRelated context world targetId target original candidate
        targetResult matchEvidence.1 matchEvidence.2 zeroesAgree

def Memory.read32 (memory : Memory) (address : Word) : Word :=
  let b0 := BitVec.zeroExtend 32 (memory address)
  let b1 := (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 1))).shiftLeft 8
  let b2 := (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 2))).shiftLeft 16
  let b3 := (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 3))).shiftLeft 24
  b0 ||| b1 ||| b2 ||| b3

def DynamicWordRelation.holds (context : StaticProofContext)
    (world : RelationalWorld) (range : DynamicAddressRangePair)
    (relation : DynamicWordRelation) (original candidate : Memory) : Bool :=
  let originalWord := Memory.read32 original
    (range.originalBase + BitVec.ofNat 32 relation.offset)
  let candidateWord := Memory.read32 candidate
    (range.candidateBase + BitVec.ofNat 32 relation.offset)
  match relation.kind with
  | .relatedWord =>
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        originalWord candidateWord
  | .codePointer =>
      codePointerRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList originalWord candidateWord
  | .dataPointer =>
      mappedValueRelated (context.relationalValueTargets world)
        originalWord candidateWord
  | .nullableDynamicPointer =>
      (originalWord == BitVec.ofNat 32 0) &&
        (candidateWord == BitVec.ofNat 32 0) ||
      world.dynamicRanges.any fun target =>
        (originalWord == target.originalBase) &&
          (candidateWord == target.candidateBase) &&
          (!(target.originalBase == BitVec.ofNat 32 0)) &&
          (!(target.candidateBase == BitVec.ofNat 32 0)) &&
          range.wordRelations.all target.wordRelations.contains

def DynamicAddressRangePair.wordsHold (context : StaticProofContext)
    (world : RelationalWorld) (range : DynamicAddressRangePair)
    (original candidate : Memory) : Bool :=
  range.wordRelations.all fun relation =>
    relation.holds context world range original candidate

def DynamicRangesMemoryHold (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory) : Prop :=
  ∀ range, range ∈ world.dynamicRanges →
    range.wordsHold context world original candidate = true

def StaticDynamicPointerSlotPair.memoryHolds (world : RelationalWorld)
    (slot : StaticDynamicPointerSlotPair) (original candidate : Memory) : Bool :=
  let originalWord := Memory.read32 original slot.originalAddress
  let candidateWord := Memory.read32 candidate slot.candidateAddress
  (originalWord == BitVec.ofNat 32 0) &&
      (candidateWord == BitVec.ofNat 32 0) ||
    world.dynamicRanges.any fun target =>
      (originalWord == target.originalBase) &&
        (candidateWord == target.candidateBase) &&
        (!(target.originalBase == BitVec.ofNat 32 0)) &&
        (!(target.candidateBase == BitVec.ofNat 32 0)) &&
        slot.requiredWords.all target.wordRelations.contains

def StaticDynamicPointerSlotsMemoryHold (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory) : Prop :=
  ∀ slot, slot ∈ context.staticDynamicPointerSlots →
    slot.memoryHolds world original candidate = true

def RelationalDynamicMemoryHold (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory) : Prop :=
  DynamicRangesMemoryHold context world original candidate ∧
    StaticDynamicPointerSlotsMemoryHold context world original candidate

def ImmutableImageWordMemory (pe : PE32) (memory : Memory) : Prop :=
  ∀ absolute expected,
    readImmutableImageWord pe absolute 4 = some expected →
      Memory.read32 memory (BitVec.ofNat 32 absolute) = BitVec.ofNat 32 expected

theorem ImmutableImageWordMemory.read32_of_checked
    (pe : PE32) (memory : Memory) (absolute expected : Nat)
    (immutable : ImmutableImageWordMemory pe memory)
    (checked : readImmutableImageWord pe absolute 4 = some expected) :
    Memory.read32 memory (BitVec.ofNat 32 absolute) = BitVec.ofNat 32 expected :=
  immutable absolute expected checked

def ImportAddressPair.memoryHolds (context : StaticProofContext)
    (binding : ImportAddressPair) (original candidate : Memory) : Prop :=
  Memory.read32 original
      (BitVec.ofNat 32 (context.originalPe.imageBase + binding.originalIatRva)) =
        binding.originalAddress ∧
    Memory.read32 candidate
      (BitVec.ofNat 32 (context.candidatePe.imageBase + binding.candidateIatRva)) =
        binding.candidateAddress

def ImportAddressesMemoryHold (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory) : Prop :=
  ∀ binding, binding ∈ world.importAddresses →
    binding.memoryHolds context original candidate

def StackRangesMemoryHold (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory) : Prop :=
  ∀ range, range ∈ world.stackRanges → ∀ offset,
    offset + 4 <= range.size → offset % 4 = 0 →
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        (Memory.read32 original (range.originalBase + BitVec.ofNat 32 offset))
        (Memory.read32 candidate (range.candidateBase + BitVec.ofNat 32 offset)) = true

structure PairedStackWordLocation (world : RelationalWorld) where
  range : DynamicAddressRangePair
  offset : Nat
  rangeMember : range ∈ world.stackRanges
  inside : offset + 4 <= range.size
  aligned : offset % 4 = 0
  originalAddress : Word
  candidateAddress : Word
  originalAddressExact :
    originalAddress = range.originalBase + BitVec.ofNat 32 offset
  candidateAddressExact :
    candidateAddress = range.candidateBase + BitVec.ofNat 32 offset

def Write32AvoidsWord (wordAddress writeAddress : Word) : Prop :=
  ∀ wordByte, wordByte < 4 → ∀ writeByte, writeByte < 4 →
    wordAddress + BitVec.ofNat 32 wordByte ≠
      writeAddress + BitVec.ofNat 32 writeByte

def WritesAvoidWord (wordAddress : Word) (writes : List (Word × Word)) : Prop :=
  ∀ write, write ∈ writes → Write32AvoidsWord wordAddress write.1

theorem Memory.read32_write32_of_avoids (memory : Memory)
    (wordAddress writeAddress value : Word)
    (avoids : Write32AvoidsWord wordAddress writeAddress) :
    Memory.read32 (memory.write32 writeAddress value) wordAddress =
      Memory.read32 memory wordAddress := by
  have h00 : wordAddress ≠ writeAddress := by
    simpa using avoids 0 (by omega) 0 (by omega)
  have h01 : wordAddress ≠ writeAddress + BitVec.ofNat 32 1 := by
    simpa using avoids 0 (by omega) 1 (by omega)
  have h02 : wordAddress ≠ writeAddress + BitVec.ofNat 32 2 := by
    simpa using avoids 0 (by omega) 2 (by omega)
  have h03 : wordAddress ≠ writeAddress + BitVec.ofNat 32 3 := by
    simpa using avoids 0 (by omega) 3 (by omega)
  have h10 : wordAddress + BitVec.ofNat 32 1 ≠ writeAddress := by
    simpa using avoids 1 (by omega) 0 (by omega)
  have h11 : wordAddress + BitVec.ofNat 32 1 ≠
      writeAddress + BitVec.ofNat 32 1 := by
    simpa using avoids 1 (by omega) 1 (by omega)
  have h12 : wordAddress + BitVec.ofNat 32 1 ≠
      writeAddress + BitVec.ofNat 32 2 := by
    simpa using avoids 1 (by omega) 2 (by omega)
  have h13 : wordAddress + BitVec.ofNat 32 1 ≠
      writeAddress + BitVec.ofNat 32 3 := by
    simpa using avoids 1 (by omega) 3 (by omega)
  have h20 : wordAddress + BitVec.ofNat 32 2 ≠ writeAddress := by
    simpa using avoids 2 (by omega) 0 (by omega)
  have h21 : wordAddress + BitVec.ofNat 32 2 ≠
      writeAddress + BitVec.ofNat 32 1 := by
    simpa using avoids 2 (by omega) 1 (by omega)
  have h22 : wordAddress + BitVec.ofNat 32 2 ≠
      writeAddress + BitVec.ofNat 32 2 := by
    simpa using avoids 2 (by omega) 2 (by omega)
  have h23 : wordAddress + BitVec.ofNat 32 2 ≠
      writeAddress + BitVec.ofNat 32 3 := by
    simpa using avoids 2 (by omega) 3 (by omega)
  have h30 : wordAddress + BitVec.ofNat 32 3 ≠ writeAddress := by
    simpa using avoids 3 (by omega) 0 (by omega)
  have h31 : wordAddress + BitVec.ofNat 32 3 ≠
      writeAddress + BitVec.ofNat 32 1 := by
    simpa using avoids 3 (by omega) 1 (by omega)
  have h32 : wordAddress + BitVec.ofNat 32 3 ≠
      writeAddress + BitVec.ofNat 32 2 := by
    simpa using avoids 3 (by omega) 2 (by omega)
  have h33 : wordAddress + BitVec.ofNat 32 3 ≠
      writeAddress + BitVec.ofNat 32 3 := by
    simpa using avoids 3 (by omega) 3 (by omega)
  simp [Memory.read32, Memory.write32, h00, h01, h02, h03, h10, h11, h12, h13,
    h20, h21, h22, h23, h30, h31, h32, h33]

theorem Memory.read32_applyConcreteWrites_of_avoids (memory : Memory)
    (wordAddress : Word) (writes : List (Word × Word))
    (avoids : WritesAvoidWord wordAddress writes) :
    Memory.read32 (applyConcreteWrites memory writes) wordAddress =
      Memory.read32 memory wordAddress := by
  induction writes generalizing memory with
  | nil => rfl
  | cons write tail ih =>
      rw [show applyConcreteWrites memory (write :: tail) =
        applyConcreteWrites (memory.write32 write.1 write.2) tail by rfl]
      rw [ih (memory := memory.write32 write.1 write.2)]
      · exact Memory.read32_write32_of_avoids memory wordAddress write.1 write.2
          (avoids write (by simp))
      · intro tailWrite tailMember
        exact avoids tailWrite (by simp [tailMember])

theorem read8AfterWriteValue_eq_write32 (memory : Memory)
    (address writeAddress value : Word) :
    read8AfterWriteValue address writeAddress value
      (BitVec.zeroExtend 32 (memory address)) =
      BitVec.zeroExtend 32 ((memory.write32 writeAddress value) address) := by
  unfold read8AfterWriteValue Memory.write32
  by_cases h0 : address = writeAddress
  · simp [h0]
  · by_cases h1 : address = writeAddress + BitVec.ofNat 32 1
    · simp [h1]
    · by_cases h2 : address = writeAddress + BitVec.ofNat 32 2
      · simp [h2]
      · by_cases h3 : address = writeAddress + BitVec.ofNat 32 3
        · simp [h3]
        · simp [h0, h1, h2, h3]

def _root_.StageA.Formal.Expr.read8AfterWritesFrom (address prior : Expr) :
    List (Expr × Expr) → Expr
  | [] => prior
  | write :: tail =>
      read8AfterWritesFrom address
        (.read8AfterWrite address write.1 write.2 prior) tail

def _root_.StageA.Formal.Expr.read8AfterWrites
    (address : Expr) (writes : List (Expr × Expr)) : Expr :=
  address.read8AfterWritesFrom (.read8 address) writes

theorem _root_.StageA.Formal.Expr.eval_read8AfterWritesFrom (state : MachineState)
    (address prior : Expr) (writes : List (Expr × Expr)) (memory : Memory)
    (priorRead : prior.eval state =
      BitVec.zeroExtend 32 (memory (address.eval state))) :
    (address.read8AfterWritesFrom prior writes).eval state =
      BitVec.zeroExtend 32
        ((applyConcreteWrites memory (evalNormalizedWrites state writes))
          (address.eval state)) := by
  induction writes generalizing prior memory with
  | nil => simpa [Expr.read8AfterWritesFrom, applyConcreteWrites, evalNormalizedWrites]
  | cons write tail ih =>
      apply ih
      simpa [Expr.eval, priorRead] using
        read8AfterWriteValue_eq_write32 memory (address.eval state)
          (write.1.eval state) (write.2.eval state)

theorem _root_.StageA.Formal.Expr.eval_read8AfterWrites (state : MachineState)
    (address : Expr) (writes : List (Expr × Expr)) :
    (address.read8AfterWrites writes).eval state =
      BitVec.zeroExtend 32
        ((applyConcreteWrites state.memory (evalNormalizedWrites state writes))
          (address.eval state)) := by
  apply Expr.eval_read8AfterWritesFrom
  rfl

def _root_.StageA.Formal.Expr.read32AfterWrites
    (address : Expr) (writes : List (Expr × Expr)) : Expr :=
  let b0 := address.read8AfterWrites writes
  let b1 := .shiftLeft ((Expr.add address (Expr.constant 1)).read8AfterWrites writes) 8
  let b2 := .shiftLeft ((Expr.add address (Expr.constant 2)).read8AfterWrites writes) 16
  let b3 := .shiftLeft ((Expr.add address (Expr.constant 3)).read8AfterWrites writes) 24
  .bitOr (.bitOr b0 b1) (.bitOr b2 b3)

@[simp] theorem assembledMemoryRead32_eq (memory : Memory) (address : Word) :
    (BitVec.zeroExtend 32 (memory address) |||
        (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 1))).shiftLeft 8) |||
      ((BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 2))).shiftLeft 16 |||
        (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 3))).shiftLeft 24) =
      Memory.read32 memory address := by
  unfold Memory.read32
  symm
  apply BitVec.or_assoc

theorem _root_.StageA.Formal.Expr.eval_read32AfterWrites
    (state : MachineState) (address : Expr) (writes : List (Expr × Expr)) :
    (address.read32AfterWrites writes).eval state =
      Memory.read32
        (applyConcreteWrites state.memory (evalNormalizedWrites state writes))
        (address.eval state) := by
  simpa [Expr.read32AfterWrites, Expr.eval, Expr.eval_read8AfterWrites] using
    assembledMemoryRead32_eq
      (applyConcreteWrites state.memory (evalNormalizedWrites state writes))
      (address.eval state)

@[simp] theorem assembledMemoryRead32OfNat_eq (memory : Memory) (address : Nat) :
    (BitVec.zeroExtend 32 (memory (BitVec.ofNat 32 address)) |||
        (BitVec.zeroExtend 32 (memory (BitVec.ofNat 32 (address + 1)))).shiftLeft 8) |||
      ((BitVec.zeroExtend 32 (memory (BitVec.ofNat 32 (address + 2)))).shiftLeft 16 |||
        (BitVec.zeroExtend 32 (memory (BitVec.ofNat 32 (address + 3)))).shiftLeft 24) =
      Memory.read32 memory (BitVec.ofNat 32 address) := by
  simpa only [BitVec.ofNat_add] using
    assembledMemoryRead32_eq memory (BitVec.ofNat 32 address)

def _root_.StageA.Formal.Expr.constantRead32AfterWrites
    (address : Nat) (writes : List (Expr × Expr)) : Expr :=
  let b0 := (Expr.constant address).read8AfterWrites writes
  let b1 := .shiftLeft ((Expr.constant (address + 1)).read8AfterWrites writes) 8
  let b2 := .shiftLeft ((Expr.constant (address + 2)).read8AfterWrites writes) 16
  let b3 := .shiftLeft ((Expr.constant (address + 3)).read8AfterWrites writes) 24
  .bitOr (.bitOr b0 b1) (.bitOr b2 b3)

theorem _root_.StageA.Formal.Expr.eval_constantRead32AfterWrites
    (state : MachineState) (address : Nat) (writes : List (Expr × Expr)) :
    (Expr.constantRead32AfterWrites address writes).eval state =
      Memory.read32
        (applyConcreteWrites state.memory (evalNormalizedWrites state writes))
        (BitVec.ofNat 32 address) := by
  simpa [Expr.constantRead32AfterWrites, Expr.eval, Expr.eval_read8AfterWrites] using
    assembledMemoryRead32OfNat_eq
      (applyConcreteWrites state.memory (evalNormalizedWrites state writes)) address

@[simp] theorem machineStateRead32_eq_memoryRead32 (state : MachineState) (address : Word) :
    state.read32 address = Memory.read32 state.memory address := rfl

def valueRelocationWordStartCandidate (target : ValueTargetPair) (address : Word) : Bool :=
  target.relocationOffsets.any fun offset =>
    address == BitVec.ofNat 32 (target.candidateValue + offset)

def relocationWordStartCandidate (targets : List ValueTargetPair) (address : Word) : Bool :=
  targets.any fun target => valueRelocationWordStartCandidate target address

def valueRelocationByteCoveredCandidate (target : ValueTargetPair) (address : Word) : Bool :=
  target.relocationOffsets.any fun offset =>
    (List.range 4).any fun byteOffset =>
      address == BitVec.ofNat 32 (target.candidateValue + offset + byteOffset)

def relocationByteCoveredCandidate (targets : List ValueTargetPair) (address : Word) : Bool :=
  targets.any fun target => valueRelocationByteCoveredCandidate target address

def hasRelocationWords (targets : List ValueTargetPair) : Bool :=
  targets.any fun target => !target.relocationOffsets.isEmpty

def relocatedMemoryRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Memory) : Prop :=
  (∀ address,
      relocationByteCoveredCandidate values address = false →
        candidate address = original (normalizeDataAddress values address)) ∧
    (∀ address,
      relocationWordStartCandidate values address = true →
        wordRelated originalImageBase candidateImageBase targets values
          (Memory.read32 original (normalizeDataAddress values address))
          (Memory.read32 candidate address) = true)

def memoryRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Memory) : Prop :=
  if hasRelocationWords values then
    relocatedMemoryRelated originalImageBase candidateImageBase targets values original candidate
  else
    candidate = fun address => original (normalizeDataAddress values address)

theorem memoryRelated_without_relocations (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Memory) (none : hasRelocationWords values = false)
    (related : memoryRelated originalImageBase candidateImageBase targets values original candidate) :
    candidate = fun address => original (normalizeDataAddress values address) := by
  simpa [memoryRelated, none] using related

theorem memoryRelated_without_values_eq (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (original candidate : Memory)
    (related : memoryRelated originalImageBase candidateImageBase targets []
      original candidate) :
    original = candidate := by
  have candidateEqual := memoryRelated_without_relocations originalImageBase
    candidateImageBase targets [] original candidate (by rfl) related
  symm
  simpa using candidateEqual

theorem memoryRelated_with_relocations (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Memory) (some : hasRelocationWords values = true)
    (related : memoryRelated originalImageBase candidateImageBase targets values original candidate) :
    relocatedMemoryRelated originalImageBase candidateImageBase targets values original candidate := by
  simpa [memoryRelated, some] using related

theorem memoryRelated_after_no_writes (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Memory)
    (related : memoryRelated originalImageBase candidateImageBase targets values
      original candidate) :
    memoryRelated originalImageBase candidateImageBase targets values
      (applyConcreteWrites original []) (applyConcreteWrites candidate []) := by
  simpa [applyConcreteWrites] using related

theorem memoryRelated_without_values_after_identical_writes
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (original candidate : Memory)
    (writes : List (Word × Word))
    (related : memoryRelated originalImageBase candidateImageBase targets []
      original candidate) :
    memoryRelated originalImageBase candidateImageBase targets []
      (applyConcreteWrites original writes) (applyConcreteWrites candidate writes) := by
  have memoryEqual : candidate = original := by
    have exactMemory := memoryRelated_without_relocations originalImageBase
      candidateImageBase targets [] original candidate (by rfl) related
    funext address
    simpa using congrFun exactMemory address
  subst candidate
  simp [memoryRelated, hasRelocationWords]

def importIatByteCoveredOriginal (context : StaticProofContext)
    (world : RelationalWorld) (address : Word) : Bool :=
  world.importAddresses.any fun binding =>
    (List.range 4).any fun offset =>
      address == BitVec.ofNat 32
        (context.originalPe.imageBase + binding.originalIatRva + offset)

def importIatByteCoveredCandidate (context : StaticProofContext)
    (world : RelationalWorld) (address : Word) : Bool :=
  world.importAddresses.any fun binding =>
    (List.range 4).any fun offset =>
      address == BitVec.ofNat 32
        (context.candidatePe.imageBase + binding.candidateIatRva + offset)

def DynamicAddressRangePair.sideBase (candidate : Bool)
    (range : DynamicAddressRangePair) : Word :=
  if candidate then range.candidateBase else range.originalBase

def stackByteCoveredOn (candidate : Bool) (world : RelationalWorld)
    (address : Word) : Bool :=
  world.stackRanges.any fun range =>
    let base := range.sideBase candidate
    base.toNat <= address.toNat && address.toNat < base.toNat + range.size

def stackByteCoveredOriginal (world : RelationalWorld) (address : Word) : Bool :=
  stackByteCoveredOn false world address

def stackByteCoveredCandidate (world : RelationalWorld) (address : Word) : Bool :=
  stackByteCoveredOn true world address

theorem DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    (context : StaticProofContext) (candidate : Bool)
    (range : DynamicAddressRangePair)
    (valid : range.disjointFromImages context = true) :
    (range.sideBase candidate).toNat + range.size <= 2 ^ 32 := by
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at valid
  rcases valid with
    ⟨⟨⟨⟨_rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩,
      _originalDisjoint⟩, _candidateDisjoint⟩
  cases candidate <;>
    simp [DynamicAddressRangePair.sideBase, originalNoWrap, candidateNoWrap]

theorem stackByteCoveredOn_of_range_word_byte
    (context : StaticProofContext) (candidate : Bool)
    (world : RelationalWorld) (range : DynamicAddressRangePair)
    (rangeMember : range ∈ world.stackRanges)
    (rangeValid : range.disjointFromImages context = true)
    (offset byte : Nat) (inside : offset + 4 <= range.size)
    (byteBefore : byte < 4) :
    stackByteCoveredOn candidate world
      (range.sideBase candidate + BitVec.ofNat 32 offset + BitVec.ofNat 32 byte) =
        true := by
  have noWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context candidate range rangeValid
  have addressNat :
      (range.sideBase candidate + BitVec.ofNat 32 offset +
          BitVec.ofNat 32 byte).toNat =
        (range.sideBase candidate).toNat + offset + byte := by
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt (by omega : offset < 2 ^ 32),
      Nat.mod_eq_of_lt (by omega : byte < 2 ^ 32),
      Nat.mod_eq_of_lt (by omega :
        (range.sideBase candidate).toNat + offset < 2 ^ 32),
      Nat.mod_eq_of_lt (by omega :
        (range.sideBase candidate).toNat + offset + byte < 2 ^ 32)]
  simp only [stackByteCoveredOn, List.any_eq_true]
  refine ⟨range, rangeMember, ?_⟩
  simp only [addressNat, Bool.and_eq_true, decide_eq_true_eq]
  omega

theorem Memory.write32_apply_of_stackByteUncovered
    (context : StaticProofContext) (candidate : Bool)
    (world : RelationalWorld) (range : DynamicAddressRangePair)
    (rangeMember : range ∈ world.stackRanges)
    (rangeValid : range.disjointFromImages context = true)
    (offset : Nat) (inside : offset + 4 <= range.size)
    (memory : Memory) (value query : Word)
    (uncovered : stackByteCoveredOn candidate world query = false) :
    memory.write32 (range.sideBase candidate + BitVec.ofNat 32 offset) value query =
      memory query := by
  let writeAddress := range.sideBase candidate + BitVec.ofNat 32 offset
  have avoids (byte : Nat) (byteBefore : byte < 4) :
      query ≠ writeAddress + BitVec.ofNat 32 byte := by
    intro overlap
    have covered := stackByteCoveredOn_of_range_word_byte context candidate world
      range rangeMember rangeValid offset byte inside byteBefore
    change stackByteCoveredOn candidate world
      (writeAddress + BitVec.ofNat 32 byte) = true at covered
    rw [← overlap, uncovered] at covered
    contradiction
  have h0 := avoids 0 (by omega)
  have h1 := avoids 1 (by omega)
  have h2 := avoids 2 (by omega)
  have h3 := avoids 3 (by omega)
  have h0' : query ≠ range.sideBase candidate + BitVec.ofNat 32 offset := by
    simpa [writeAddress] using h0
  have h1' : query ≠ range.sideBase candidate + BitVec.ofNat 32 offset +
      BitVec.ofNat 32 1 := by simpa [writeAddress] using h1
  have h2' : query ≠ range.sideBase candidate + BitVec.ofNat 32 offset +
      BitVec.ofNat 32 2 := by simpa [writeAddress] using h2
  have h3' : query ≠ range.sideBase candidate + BitVec.ofNat 32 offset +
      BitVec.ofNat 32 3 := by simpa [writeAddress] using h3
  simp [Memory.write32, h0', h1', h2', h3']

theorem write32AvoidsWord_of_stackBytesUncovered
    (context : StaticProofContext) (candidate : Bool)
    (world : RelationalWorld) (range : DynamicAddressRangePair)
    (rangeMember : range ∈ world.stackRanges)
    (rangeValid : range.disjointFromImages context = true)
    (offset : Nat) (inside : offset + 4 <= range.size)
    (wordAddress : Word)
    (uncovered : ∀ byte, byte < 4 →
      stackByteCoveredOn candidate world
        (wordAddress + BitVec.ofNat 32 byte) = false) :
    Write32AvoidsWord wordAddress
      (range.sideBase candidate + BitVec.ofNat 32 offset) := by
  intro wordByte wordByteBefore writeByte writeByteBefore overlap
  have covered := stackByteCoveredOn_of_range_word_byte context candidate world
    range rangeMember rangeValid offset writeByte inside writeByteBefore
  rw [← overlap, uncovered wordByte wordByteBefore] at covered
  contradiction

theorem word_add_small_ne (address : Word) (left right : Nat)
    (fits : address.toNat + 4 <= 2 ^ 32)
    (leftBefore : left < 4) (rightBefore : right < 4)
    (different : left ≠ right) :
    address + BitVec.ofNat 32 left ≠ address + BitVec.ofNat 32 right := by
  intro equal
  have equalNat := congrArg BitVec.toNat equal
  simp [BitVec.toNat_add, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt (by omega : left < 2 ^ 32),
    Nat.mod_eq_of_lt (by omega : right < 2 ^ 32),
    Nat.mod_eq_of_lt (by omega : address.toNat + left < 2 ^ 32),
    Nat.mod_eq_of_lt (by omega : address.toNat + right < 2 ^ 32)] at equalNat
  omega

theorem word_add_ia32_twos_complement (value : Word) (amount : Nat)
    (amountFits : amount < 2 ^ 32) :
    value + BitVec.ofNat 32 (2 ^ 32 - amount) =
      value - BitVec.ofNat 32 amount := by
  rw [BitVec.sub_eq_add_neg]
  congr
  simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountFits]

@[simp] theorem word_add_ia32_minus_four (value : Word) :
    value + BitVec.ofNat 32 4294967292 = value - BitVec.ofNat 32 4 := by
  exact word_add_ia32_twos_complement value 4 (by omega)

theorem DynamicAddressRangePair.wordAddress_fits
    (context : StaticProofContext) (candidate : Bool)
    (range : DynamicAddressRangePair)
    (rangeValid : range.disjointFromImages context = true)
    (offset : Nat) (inside : offset + 4 <= range.size) :
    (range.sideBase candidate + BitVec.ofNat 32 offset).toNat + 4 <= 2 ^ 32 := by
  have noWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context candidate range rangeValid
  have offsetBefore : offset < 2 ^ 32 := by omega
  have addressBefore : (range.sideBase candidate).toNat + offset < 2 ^ 32 := by
    omega
  simp [BitVec.toNat_add, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt offsetBefore, Nat.mod_eq_of_lt addressBefore]
  omega

theorem stackRangeWordWriteAvoidsOtherWord
    (context : StaticProofContext) (candidate : Bool)
    (world : RelationalWorld)
    (rangesValid : world.stackRangesValid context = true)
    (writeRange queryRange : DynamicAddressRangePair)
    (writeRangeMember : writeRange ∈ world.stackRanges)
    (queryRangeMember : queryRange ∈ world.stackRanges)
    (writeOffset queryOffset : Nat)
    (writeInside : writeOffset + 4 <= writeRange.size)
    (queryInside : queryOffset + 4 <= queryRange.size)
    (writeAligned : writeOffset % 4 = 0)
    (queryAligned : queryOffset % 4 = 0)
    (different : queryRange ≠ writeRange ∨ queryOffset ≠ writeOffset) :
    Write32AvoidsWord
      (queryRange.sideBase candidate + BitVec.ofNat 32 queryOffset)
      (writeRange.sideBase candidate + BitVec.ofNat 32 writeOffset) := by
  simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
    List.all_eq_true] at rangesValid
  have idsUnique := rangesValid.1.1.1
  have writeValidRow := rangesValid.1.1.2 writeRange writeRangeMember
  have queryValidRow := rangesValid.1.1.2 queryRange queryRangeMember
  have writeRangeValid : writeRange.disjointFromImages context = true :=
    writeValidRow.1.1.1
  have queryRangeValid : queryRange.disjointFromImages context = true :=
    queryValidRow.1.1.1
  have writeNoWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context candidate writeRange writeRangeValid
  have queryNoWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context candidate queryRange queryRangeValid
  have rangesDisjoint :
      dynamicAddressRangesDisjointOn candidate world.stackRanges = true := by
    cases candidate
    · exact rangesValid.1.2
    · exact rangesValid.2
  intro queryByte queryByteBefore writeByte writeByteBefore overlap
  have overlapNat := congrArg BitVec.toNat overlap
  have writeOffsetBefore : writeOffset < 2 ^ 32 := by omega
  have queryOffsetBefore : queryOffset < 2 ^ 32 := by omega
  have writeByteSmall : writeByte < 2 ^ 32 := by omega
  have queryByteSmall : queryByte < 2 ^ 32 := by omega
  have writeBaseOffsetBefore :
      (writeRange.sideBase candidate).toNat + writeOffset < 2 ^ 32 := by omega
  have queryBaseOffsetBefore :
      (queryRange.sideBase candidate).toNat + queryOffset < 2 ^ 32 := by omega
  have writeAddressBefore :
      (writeRange.sideBase candidate).toNat + writeOffset + writeByte < 2 ^ 32 := by
    omega
  have queryAddressBefore :
      (queryRange.sideBase candidate).toNat + queryOffset + queryByte < 2 ^ 32 := by
    omega
  simp [BitVec.toNat_add, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt writeOffsetBefore,
    Nat.mod_eq_of_lt queryOffsetBefore,
    Nat.mod_eq_of_lt writeByteSmall,
    Nat.mod_eq_of_lt queryByteSmall,
    Nat.mod_eq_of_lt writeBaseOffsetBefore,
    Nat.mod_eq_of_lt queryBaseOffsetBefore,
    Nat.mod_eq_of_lt writeAddressBefore,
    Nat.mod_eq_of_lt queryAddressBefore] at overlapNat
  by_cases sameId : queryRange.id = writeRange.id
  · have sameRange := dynamicAddressRange_eq_of_same_id world.stackRanges idsUnique
      queryRange writeRange queryRangeMember writeRangeMember sameId
    subst queryRange
    simp only [ne_eq, not_true_eq_false, false_or] at different
    have separated : queryOffset + 4 <= writeOffset ∨
        writeOffset + 4 <= queryOffset := by
      omega
    omega
  · simp only [dynamicAddressRangesDisjointOn, List.all_eq_true] at rangesDisjoint
    have row := rangesDisjoint writeRange writeRangeMember queryRange queryRangeMember
    simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq] at row
    rcases row with idsEqual | separated
    · exact (sameId idsEqual.symm).elim
    · have separated' :
          (writeRange.sideBase candidate).toNat + writeRange.size <=
              (queryRange.sideBase candidate).toNat ∨
            (queryRange.sideBase candidate).toNat + queryRange.size <=
              (writeRange.sideBase candidate).toNat := by
        simpa [DynamicAddressRangePair.sideBase] using separated
      omega

theorem Memory.read32_write32_same_of_fits (memory : Memory)
    (address value : Word) (fits : address.toNat + 4 <= 2 ^ 32) :
    Memory.read32 (memory.write32 address value) address = value := by
  have h10 := word_add_small_ne address 1 0 fits (by omega) (by omega) (by omega)
  have h20 := word_add_small_ne address 2 0 fits (by omega) (by omega) (by omega)
  have h21 := word_add_small_ne address 2 1 fits (by omega) (by omega) (by omega)
  have h30 := word_add_small_ne address 3 0 fits (by omega) (by omega) (by omega)
  have h31 := word_add_small_ne address 3 1 fits (by omega) (by omega) (by omega)
  have h32 := word_add_small_ne address 3 2 fits (by omega) (by omega) (by omega)
  simp [Memory.read32, Memory.write32, h10, h20, h21, h30, h31, h32]
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  simp only [BitVec.getLsbD_or, BitVec.getLsbD_shiftLeft,
    BitVec.getLsbD_setWidth, BitVec.getLsbD_extractLsb']
  by_cases i0 : i < 8
  · have i16 : i < 16 := by omega
    have i24 : i < 24 := by omega
    simp [i0, i16, i24, hi]
  by_cases i1 : i < 16
  · have i24 : i < 24 := by omega
    have byte : i - 8 < 8 := by omega
    have width : i - 8 < 32 := by omega
    have index : 8 + (i - 8) = i := by omega
    simp [i0, i1, i24, hi, byte, width, index]
  by_cases i2 : i < 24
  · have firstOut : ¬i - 8 < 8 := by omega
    have byte : i - 16 < 8 := by omega
    have width8 : i - 8 < 32 := by omega
    have width16 : i - 16 < 32 := by omega
    have index : 16 + (i - 16) = i := by omega
    simp [i0, i1, i2, hi, firstOut, byte, width8, width16, index]
  · have firstOut : ¬i - 8 < 8 := by omega
    have secondOut : ¬i - 16 < 8 := by omega
    have byte : i - 24 < 8 := by omega
    have width8 : i - 8 < 32 := by omega
    have width16 : i - 16 < 32 := by omega
    have width24 : i - 24 < 32 := by omega
    have index : 24 + (i - 24) = i := by omega
    simp [i0, i1, i2, hi, firstOut, secondOut, byte,
      width8, width16, width24, index]

theorem StackRangesMemoryHold.afterPairedWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (rangesValid : world.stackRangesValid context = true)
    (related : StackRangesMemoryHold context world original candidate)
    (writeRange : DynamicAddressRangePair)
    (writeRangeMember : writeRange ∈ world.stackRanges)
    (writeOffset : Nat) (writeInside : writeOffset + 4 <= writeRange.size)
    (writeAligned : writeOffset % 4 = 0)
    (originalValue candidateValue : Word)
    (valuesRelated :
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        originalValue candidateValue = true) :
    StackRangesMemoryHold context world
      (original.write32
        (writeRange.originalBase + BitVec.ofNat 32 writeOffset) originalValue)
      (candidate.write32
        (writeRange.candidateBase + BitVec.ofNat 32 writeOffset) candidateValue) := by
  intro queryRange queryRangeMember queryOffset queryInside queryAligned
  have writeRangeValid : writeRange.disjointFromImages context = true := by
    simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact (rangesValid.1.1.2 writeRange writeRangeMember).1.1.1
  by_cases sameRange : queryRange = writeRange
  · subst queryRange
    by_cases sameOffset : queryOffset = writeOffset
    · subst queryOffset
      have originalFits := DynamicAddressRangePair.wordAddress_fits context false
        writeRange writeRangeValid writeOffset writeInside
      have candidateFits := DynamicAddressRangePair.wordAddress_fits context true
        writeRange writeRangeValid writeOffset writeInside
      rw [Memory.read32_write32_same_of_fits original
          (writeRange.originalBase + BitVec.ofNat 32 writeOffset)
          originalValue originalFits,
        Memory.read32_write32_same_of_fits candidate
          (writeRange.candidateBase + BitVec.ofNat 32 writeOffset)
          candidateValue candidateFits]
      exact valuesRelated
    · have originalAvoids := stackRangeWordWriteAvoidsOtherWord context false world
        rangesValid writeRange writeRange writeRangeMember writeRangeMember writeOffset
        queryOffset writeInside queryInside writeAligned queryAligned
        (Or.inr sameOffset)
      have candidateAvoids := stackRangeWordWriteAvoidsOtherWord context true world
        rangesValid writeRange writeRange writeRangeMember writeRangeMember writeOffset
        queryOffset writeInside queryInside writeAligned queryAligned
        (Or.inr sameOffset)
      have originalAvoids' : Write32AvoidsWord
          (writeRange.originalBase + BitVec.ofNat 32 queryOffset)
          (writeRange.originalBase + BitVec.ofNat 32 writeOffset) := by
        simpa [DynamicAddressRangePair.sideBase] using originalAvoids
      have candidateAvoids' : Write32AvoidsWord
          (writeRange.candidateBase + BitVec.ofNat 32 queryOffset)
          (writeRange.candidateBase + BitVec.ofNat 32 writeOffset) := by
        simpa [DynamicAddressRangePair.sideBase] using candidateAvoids
      rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids',
        Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids']
      exact related writeRange writeRangeMember queryOffset queryInside queryAligned
  · have originalAvoids := stackRangeWordWriteAvoidsOtherWord context false world
      rangesValid writeRange queryRange writeRangeMember queryRangeMember writeOffset
      queryOffset writeInside queryInside writeAligned queryAligned
      (Or.inl sameRange)
    have candidateAvoids := stackRangeWordWriteAvoidsOtherWord context true world
      rangesValid writeRange queryRange writeRangeMember queryRangeMember writeOffset
      queryOffset writeInside queryInside writeAligned queryAligned
      (Or.inl sameRange)
    have originalAvoids' : Write32AvoidsWord
        (queryRange.originalBase + BitVec.ofNat 32 queryOffset)
        (writeRange.originalBase + BitVec.ofNat 32 writeOffset) := by
      simpa [DynamicAddressRangePair.sideBase] using originalAvoids
    have candidateAvoids' : Write32AvoidsWord
        (queryRange.candidateBase + BitVec.ofNat 32 queryOffset)
        (writeRange.candidateBase + BitVec.ofNat 32 writeOffset) := by
      simpa [DynamicAddressRangePair.sideBase] using candidateAvoids
    rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids',
      Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids']
    exact related queryRange queryRangeMember queryOffset queryInside queryAligned

theorem stackRangeWordWriteAvoidsImageWord
    (rangeBase : Word) (rangeSize imageBase imageSize : Nat)
    (offset : Nat) (inside : offset + 4 <= rangeSize)
    (rangeNoWrap : rangeBase.toNat + rangeSize <= 2 ^ 32)
    (rangeDisjoint : rangeBase.toNat + rangeSize <= imageBase ∨
      imageBase + imageSize <= rangeBase.toNat)
    (wordAddress : Word)
    (wordLower : imageBase <= wordAddress.toNat)
    (wordUpper : wordAddress.toNat + 4 <= imageBase + imageSize)
    (wordFits : wordAddress.toNat + 4 <= 2 ^ 32) :
    Write32AvoidsWord wordAddress
      (rangeBase + BitVec.ofNat 32 offset) := by
  intro wordByte wordByteBefore writeByte writeByteBefore overlap
  have overlapNat := congrArg BitVec.toNat overlap
  have offsetBefore : offset < 2 ^ 32 := by omega
  have wordByteSmall : wordByte < 2 ^ 32 := by omega
  have writeByteSmall : writeByte < 2 ^ 32 := by omega
  have writeBaseOffsetBefore : rangeBase.toNat + offset < 2 ^ 32 := by omega
  have writeAddressBefore : rangeBase.toNat + offset + writeByte < 2 ^ 32 := by
    omega
  have wordAddressBefore : wordAddress.toNat + wordByte < 2 ^ 32 := by omega
  simp [BitVec.toNat_add, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt offsetBefore,
    Nat.mod_eq_of_lt wordByteSmall,
    Nat.mod_eq_of_lt writeByteSmall,
    Nat.mod_eq_of_lt writeBaseOffsetBefore,
    Nat.mod_eq_of_lt writeAddressBefore,
    Nat.mod_eq_of_lt wordAddressBefore] at overlapNat
  omega

theorem ImmutableImageWordMemory.afterStackWordWrite
    (pe : PE32) (memory : Memory)
    (rangeBase : Word) (rangeSize offset : Nat) (value : Word)
    (rangeNoWrap : rangeBase.toNat + rangeSize <= 2 ^ 32)
    (rangeDisjoint : rangeBase.toNat + rangeSize <= pe.imageBase ∨
      pe.imageBase + pe.sizeOfImage <= rangeBase.toNat)
    (inside : offset + 4 <= rangeSize)
    (immutable : ImmutableImageWordMemory pe memory) :
    ImmutableImageWordMemory pe
      (memory.write32 (rangeBase + BitVec.ofNat 32 offset) value) := by
  intro absolute expected checked
  have bounds := readImmutableImageWord_bounds pe absolute 4 expected checked
  have absoluteBefore : absolute < 2 ^ 32 := by omega
  have addressNat : (BitVec.ofNat 32 absolute : Word).toNat = absolute := by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt absoluteBefore]
  have avoids := stackRangeWordWriteAvoidsImageWord rangeBase rangeSize pe.imageBase
    pe.sizeOfImage offset inside rangeNoWrap rangeDisjoint
    (BitVec.ofNat 32 absolute) (by simpa [addressNat] using bounds.1)
    (by simpa [addressNat] using bounds.2.2) (by simpa [addressNat] using bounds.2.1)
  rw [Memory.read32_write32_of_avoids _ _ _ _ avoids]
  exact immutable absolute expected checked

theorem ImportAddressPair.originalIatWordBounds
    (context : StaticProofContext) (binding : ImportAddressPair)
    (valid : binding.staticValid context = true) :
    context.originalPe.imageBase <=
        context.originalPe.imageBase + binding.originalIatRva ∧
      context.originalPe.imageBase + binding.originalIatRva + 4 <=
        context.originalPe.imageBase + context.originalPe.sizeOfImage ∧
      context.originalPe.imageBase + binding.originalIatRva + 4 <= 2 ^ 32 := by
  unfold ImportAddressPair.staticValid at valid
  split at valid <;> simp_all
  omega

theorem ImportAddressPair.candidateIatWordBounds
    (context : StaticProofContext) (binding : ImportAddressPair)
    (valid : binding.staticValid context = true) :
    context.candidatePe.imageBase <=
        context.candidatePe.imageBase + binding.candidateIatRva ∧
      context.candidatePe.imageBase + binding.candidateIatRva + 4 <=
        context.candidatePe.imageBase + context.candidatePe.sizeOfImage ∧
      context.candidatePe.imageBase + binding.candidateIatRva + 4 <= 2 ^ 32 := by
  unfold ImportAddressPair.staticValid at valid
  split at valid <;> simp_all
  omega

theorem ImportAddressesMemoryHold.afterPairedStackWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (range : DynamicAddressRangePair) (rangeMember : range ∈ world.stackRanges)
    (rangeValid : range.disjointFromImages context = true)
    (offset : Nat) (inside : offset + 4 <= range.size)
    (originalValue candidateValue : Word)
    (importsStatic : world.importAddressesStaticValid context = true)
    (importsMemory : ImportAddressesMemoryHold context world original candidate) :
    ImportAddressesMemoryHold context world
      (original.write32 (range.originalBase + BitVec.ofNat 32 offset) originalValue)
      (candidate.write32 (range.candidateBase + BitVec.ofNat 32 offset)
        candidateValue) := by
  simp only [RelationalWorld.importAddressesStaticValid, Bool.and_eq_true,
    List.all_eq_true] at importsStatic
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeValid
  rcases rangeValid with
    ⟨⟨⟨⟨_rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  intro binding bindingMember
  have bindingValid := importsStatic.2 binding bindingMember
  have originalBounds := binding.originalIatWordBounds context bindingValid
  have candidateBounds := binding.candidateIatWordBounds context bindingValid
  have originalAbsoluteBefore :
      context.originalPe.imageBase + binding.originalIatRva < 2 ^ 32 := by omega
  have candidateAbsoluteBefore :
      context.candidatePe.imageBase + binding.candidateIatRva < 2 ^ 32 := by omega
  have originalAddressNat :
      (BitVec.ofNat 32
        (context.originalPe.imageBase + binding.originalIatRva) : Word).toNat =
          context.originalPe.imageBase + binding.originalIatRva := by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt originalAbsoluteBefore]
  have candidateAddressNat :
      (BitVec.ofNat 32
        (context.candidatePe.imageBase + binding.candidateIatRva) : Word).toNat =
          context.candidatePe.imageBase + binding.candidateIatRva := by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt candidateAbsoluteBefore]
  have originalAvoids := stackRangeWordWriteAvoidsImageWord range.originalBase
    range.size context.originalPe.imageBase context.originalPe.sizeOfImage offset
    inside originalNoWrap originalDisjoint
    (BitVec.ofNat 32 (context.originalPe.imageBase + binding.originalIatRva))
    (by simpa [originalAddressNat] using originalBounds.1)
    (by simpa [originalAddressNat] using originalBounds.2.1)
    (by simpa [originalAddressNat] using originalBounds.2.2)
  have candidateAvoids := stackRangeWordWriteAvoidsImageWord range.candidateBase
    range.size context.candidatePe.imageBase context.candidatePe.sizeOfImage offset
    inside candidateNoWrap candidateDisjoint
    (BitVec.ofNat 32 (context.candidatePe.imageBase + binding.candidateIatRva))
    (by simpa [candidateAddressNat] using candidateBounds.1)
    (by simpa [candidateAddressNat] using candidateBounds.2.1)
    (by simpa [candidateAddressNat] using candidateBounds.2.2)
  have prior := importsMemory binding bindingMember
  unfold ImportAddressPair.memoryHolds at prior ⊢
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact prior

theorem stackRangeWordWriteAvoidsDynamicRangeWord
    (context : StaticProofContext) (candidateSide : Bool)
    (world : RelationalWorld)
    (dynamicValid : world.dynamicRangesValid context = true)
    (stackRange dynamicRange : DynamicAddressRangePair)
    (stackMember : stackRange ∈ world.stackRanges)
    (dynamicMember : dynamicRange ∈ world.dynamicRanges)
    (stackValid : stackRange.disjointFromImages context = true)
    (stackOffset dynamicOffset : Nat)
    (stackInside : stackOffset + 4 <= stackRange.size)
    (dynamicInside : dynamicOffset + 4 <= dynamicRange.size) :
    Write32AvoidsWord
      (dynamicRange.sideBase candidateSide + BitVec.ofNat 32 dynamicOffset)
      (stackRange.sideBase candidateSide + BitVec.ofNat 32 stackOffset) := by
  simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
    List.all_eq_true] at dynamicValid
  have dynamicRangeValid := dynamicValid.1.1.1.1.1.2 dynamicRange dynamicMember
  have crossDisjoint : dynamicAddressRangesCrossDisjointOn candidateSide
      world.dynamicRanges world.stackRanges = true := by
    cases candidateSide
    · exact dynamicValid.1.2
    · exact dynamicValid.2
  simp only [dynamicAddressRangesCrossDisjointOn, List.all_eq_true] at crossDisjoint
  have separated := crossDisjoint dynamicRange dynamicMember stackRange stackMember
  simp only [Bool.or_eq_true, decide_eq_true_eq] at separated
  have separated' :
      (stackRange.sideBase candidateSide).toNat + stackRange.size <=
          (dynamicRange.sideBase candidateSide).toNat ∨
        (dynamicRange.sideBase candidateSide).toNat + dynamicRange.size <=
          (stackRange.sideBase candidateSide).toNat := by
    rcases separated with dynamicBefore | stackBefore
    · right
      simpa [DynamicAddressRangePair.sideBase] using dynamicBefore
    · left
      simpa [DynamicAddressRangePair.sideBase] using stackBefore
  have stackNoWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context candidateSide stackRange stackValid
  have dynamicNoWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context candidateSide dynamicRange dynamicRangeValid
  have dynamicOffsetBefore : dynamicOffset < 2 ^ 32 := by omega
  have dynamicAddressBefore :
      (dynamicRange.sideBase candidateSide).toNat + dynamicOffset < 2 ^ 32 := by
    omega
  have dynamicAddressNat :
      (dynamicRange.sideBase candidateSide + BitVec.ofNat 32 dynamicOffset).toNat =
        (dynamicRange.sideBase candidateSide).toNat + dynamicOffset := by
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt dynamicOffsetBefore,
      Nat.mod_eq_of_lt dynamicAddressBefore]
  apply stackRangeWordWriteAvoidsImageWord
    (stackRange.sideBase candidateSide) stackRange.size
    (dynamicRange.sideBase candidateSide).toNat dynamicRange.size stackOffset
    stackInside stackNoWrap separated'
    (dynamicRange.sideBase candidateSide + BitVec.ofNat 32 dynamicOffset)
  · simp [dynamicAddressNat]
  · simp [dynamicAddressNat]
    omega
  · simp [dynamicAddressNat]
    omega

theorem DynamicRangesMemoryHold.afterPairedStackWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (dynamicValid : world.dynamicRangesValid context = true)
    (stackRange : DynamicAddressRangePair)
    (stackMember : stackRange ∈ world.stackRanges)
    (stackValid : stackRange.disjointFromImages context = true)
    (stackOffset : Nat) (stackInside : stackOffset + 4 <= stackRange.size)
    (originalValue candidateValue : Word)
    (related : DynamicRangesMemoryHold context world original candidate) :
    DynamicRangesMemoryHold context world
      (original.write32
        (stackRange.originalBase + BitVec.ofNat 32 stackOffset) originalValue)
      (candidate.write32
        (stackRange.candidateBase + BitVec.ofNat 32 stackOffset) candidateValue) := by
  intro dynamicRange dynamicMember
  have dynamicValidForWords := dynamicValid
  simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
    List.all_eq_true] at dynamicValidForWords
  have wordRelationsValid :=
    dynamicValidForWords.1.1.1.1.2 dynamicRange dynamicMember
  simp only [DynamicAddressRangePair.wordRelationsValid, List.all_eq_true] at wordRelationsValid
  have prior := related dynamicRange dynamicMember
  simp only [DynamicAddressRangePair.wordsHold, List.all_eq_true] at prior ⊢
  intro relation relationMember
  have relationValid := wordRelationsValid relation relationMember
  simp only [Bool.and_eq_true, decide_eq_true_eq] at relationValid
  have relationInside := relationValid.1.1
  have originalAvoids := stackRangeWordWriteAvoidsDynamicRangeWord context false
    world dynamicValid stackRange dynamicRange stackMember dynamicMember stackValid
    stackOffset relation.offset stackInside relationInside
  have candidateAvoids := stackRangeWordWriteAvoidsDynamicRangeWord context true
    world dynamicValid stackRange dynamicRange stackMember dynamicMember stackValid
    stackOffset relation.offset stackInside relationInside
  have originalAvoids' : Write32AvoidsWord
      (dynamicRange.originalBase + BitVec.ofNat 32 relation.offset)
      (stackRange.originalBase + BitVec.ofNat 32 stackOffset) := by
    simpa [DynamicAddressRangePair.sideBase] using originalAvoids
  have candidateAvoids' : Write32AvoidsWord
      (dynamicRange.candidateBase + BitVec.ofNat 32 relation.offset)
      (stackRange.candidateBase + BitVec.ofNat 32 stackOffset) := by
    simpa [DynamicAddressRangePair.sideBase] using candidateAvoids
  have priorRelation := prior relation relationMember
  unfold DynamicWordRelation.holds at priorRelation ⊢
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids',
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids']
  exact priorRelation

theorem writableStaticWordInPe_bounds (pe : PE32) (address : Word)
    (writable : writableStaticWordInPe pe address = true) :
    pe.imageBase <= address.toNat ∧
      address.toNat + 4 <= pe.imageBase + pe.sizeOfImage ∧
      address.toNat + 4 <= 2 ^ 32 := by
  simp only [writableStaticWordInPe, Bool.and_eq_true,
    decide_eq_true_eq] at writable
  exact ⟨writable.1.1.1, writable.1.2, writable.1.1.2⟩

theorem StaticDynamicPointerSlotsMemoryHold.afterPairedStackWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (slotsValid : staticDynamicPointerSlotsValid context = true)
    (stackRange : DynamicAddressRangePair)
    (stackValid : stackRange.disjointFromImages context = true)
    (stackOffset : Nat) (stackInside : stackOffset + 4 <= stackRange.size)
    (originalValue candidateValue : Word)
    (related : StaticDynamicPointerSlotsMemoryHold context world original candidate) :
    StaticDynamicPointerSlotsMemoryHold context world
      (original.write32
        (stackRange.originalBase + BitVec.ofNat 32 stackOffset) originalValue)
      (candidate.write32
        (stackRange.candidateBase + BitVec.ofNat 32 stackOffset) candidateValue) := by
  simp only [staticDynamicPointerSlotsValid, Bool.and_eq_true,
    List.all_eq_true] at slotsValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at stackValid
  rcases stackValid with
    ⟨⟨⟨⟨_rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  intro slot slotMember
  have slotValid := slotsValid.2 slot slotMember
  simp only [StaticDynamicPointerSlotPair.valid, Bool.and_eq_true] at slotValid
  have originalWritable := slotValid.1.1.1.1.2
  have candidateWritable := slotValid.1.1.1.2
  have originalBounds := writableStaticWordInPe_bounds context.originalPe
    slot.originalAddress originalWritable
  have candidateBounds := writableStaticWordInPe_bounds context.candidatePe
    slot.candidateAddress candidateWritable
  have originalAvoids := stackRangeWordWriteAvoidsImageWord stackRange.originalBase
    stackRange.size context.originalPe.imageBase context.originalPe.sizeOfImage
    stackOffset stackInside originalNoWrap originalDisjoint slot.originalAddress
    originalBounds.1 originalBounds.2.1 originalBounds.2.2
  have candidateAvoids := stackRangeWordWriteAvoidsImageWord stackRange.candidateBase
    stackRange.size context.candidatePe.imageBase context.candidatePe.sizeOfImage
    stackOffset stackInside candidateNoWrap candidateDisjoint slot.candidateAddress
    candidateBounds.1 candidateBounds.2.1 candidateBounds.2.2
  have prior := related slot slotMember
  unfold StaticDynamicPointerSlotPair.memoryHolds at prior ⊢
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact prior

def staticDynamicPointerSlotByteCoveredOriginal (context : StaticProofContext)
    (address : Word) : Bool :=
  context.staticDynamicPointerSlots.any fun slot =>
    slot.originalAddress.toNat <= address.toNat &&
      address.toNat < slot.originalAddress.toNat + 4

def staticDynamicPointerSlotByteCoveredCandidate (context : StaticProofContext)
    (address : Word) : Bool :=
  context.staticDynamicPointerSlots.any fun slot =>
    slot.candidateAddress.toNat <= address.toNat &&
      address.toNat < slot.candidateAddress.toNat + 4

def ordinaryMemoryAddressExcluded (context : StaticProofContext)
    (world : RelationalWorld) (values : List ValueTargetPair)
    (candidateAddress : Word) : Bool :=
  importIatByteCoveredCandidate context world candidateAddress ||
    importIatByteCoveredOriginal context world
      (normalizeDataAddress values candidateAddress) ||
    stackByteCoveredCandidate world candidateAddress ||
    stackByteCoveredOriginal world (normalizeDataAddress values candidateAddress) ||
    staticDynamicPointerSlotByteCoveredCandidate context candidateAddress ||
    staticDynamicPointerSlotByteCoveredOriginal context
      (normalizeDataAddress values candidateAddress)

def ordinaryMemoryWordExcluded (context : StaticProofContext)
    (world : RelationalWorld) (values : List ValueTargetPair)
    (candidateAddress : Word) : Bool :=
  ((List.range 4).any fun offset =>
      ordinaryMemoryAddressExcluded context world values
        (candidateAddress + BitVec.ofNat 32 offset)) ||
    (List.range 4).any fun offset =>
      stackByteCoveredOriginal world
        (normalizeDataAddress values candidateAddress + BitVec.ofNat 32 offset)

def relocatedOrdinaryMemoryRelated (context : StaticProofContext)
    (world : RelationalWorld) (targets : List CodeTargetPair)
    (values : List ValueTargetPair) (original candidate : Memory) : Prop :=
  (∀ address,
      relocationByteCoveredCandidate values address = false →
        ordinaryMemoryAddressExcluded context world values address = false →
          candidate address = original (normalizeDataAddress values address)) ∧
    (∀ address,
      relocationWordStartCandidate values address = true →
        ordinaryMemoryWordExcluded context world values address = false →
          wordRelated context.originalPe.imageBase context.candidatePe.imageBase
            targets values
            (Memory.read32 original (normalizeDataAddress values address))
            (Memory.read32 candidate address) = true)

def ordinaryMemoryRelated (context : StaticProofContext)
    (world : RelationalWorld) (targets : List CodeTargetPair)
    (values : List ValueTargetPair) (original candidate : Memory) : Prop :=
  if hasRelocationWords values then
    relocatedOrdinaryMemoryRelated context world targets values original candidate
  else
      ∀ address,
      ordinaryMemoryAddressExcluded context world values address = false →
        candidate address = original (normalizeDataAddress values address)

structure RelationalMemoryFamiliesHold (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory) : Prop where
  stackRanges : StackRangesMemoryHold context world original candidate
  importAddresses : ImportAddressesMemoryHold context world original candidate
  originalImmutable : ImmutableImageWordMemory context.originalPe original
  candidateImmutable : ImmutableImageWordMemory context.candidatePe candidate
  ordinary : ordinaryMemoryRelated context world context.codeMap.entries.toList
    (context.relationalValueTargets world) original candidate
  dynamicRanges : DynamicRangesMemoryHold context world original candidate
  staticPointerSlots : StaticDynamicPointerSlotsMemoryHold context world original candidate

structure PairedMemoryUpdateFrame (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory) where
  originalWrites : List (Word × Word)
  candidateWrites : List (Word × Word)
  preservesStackRanges :
    StackRangesMemoryHold context world original candidate →
      StackRangesMemoryHold context world
        (applyConcreteWrites original originalWrites)
        (applyConcreteWrites candidate candidateWrites)
  preservesImportAddresses :
    ImportAddressesMemoryHold context world original candidate →
      ImportAddressesMemoryHold context world
        (applyConcreteWrites original originalWrites)
        (applyConcreteWrites candidate candidateWrites)
  preservesOriginalImmutable :
    ImmutableImageWordMemory context.originalPe original →
      ImmutableImageWordMemory context.originalPe
        (applyConcreteWrites original originalWrites)
  preservesCandidateImmutable :
    ImmutableImageWordMemory context.candidatePe candidate →
      ImmutableImageWordMemory context.candidatePe
        (applyConcreteWrites candidate candidateWrites)
  preservesOrdinary :
    ordinaryMemoryRelated context world context.codeMap.entries.toList
        (context.relationalValueTargets world) original candidate →
      ordinaryMemoryRelated context world context.codeMap.entries.toList
        (context.relationalValueTargets world)
        (applyConcreteWrites original originalWrites)
        (applyConcreteWrites candidate candidateWrites)
  preservesDynamicRanges :
    DynamicRangesMemoryHold context world original candidate →
      DynamicRangesMemoryHold context world
        (applyConcreteWrites original originalWrites)
        (applyConcreteWrites candidate candidateWrites)
  preservesStaticPointerSlots :
    StaticDynamicPointerSlotsMemoryHold context world original candidate →
      StaticDynamicPointerSlotsMemoryHold context world
        (applyConcreteWrites original originalWrites)
        (applyConcreteWrites candidate candidateWrites)

theorem RelationalMemoryFamiliesHold.afterPairedMemoryUpdate
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (frame : PairedMemoryUpdateFrame context world original candidate)
    (related : RelationalMemoryFamiliesHold context world original candidate) :
    RelationalMemoryFamiliesHold context world
      (applyConcreteWrites original frame.originalWrites)
      (applyConcreteWrites candidate frame.candidateWrites) := by
  exact {
    stackRanges := frame.preservesStackRanges related.stackRanges
    importAddresses := frame.preservesImportAddresses related.importAddresses
    originalImmutable :=
      frame.preservesOriginalImmutable related.originalImmutable
    candidateImmutable :=
      frame.preservesCandidateImmutable related.candidateImmutable
    ordinary := frame.preservesOrdinary related.ordinary
    dynamicRanges := frame.preservesDynamicRanges related.dynamicRanges
    staticPointerSlots :=
      frame.preservesStaticPointerSlots related.staticPointerSlots
  }

theorem stackByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (included : ordinaryMemoryAddressExcluded context world values
      candidateAddress = false) :
    stackByteCoveredCandidate world candidateAddress = false := by
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryMemoryAddressExcluded, covered] at included

theorem normalizedStackByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (included : ordinaryMemoryAddressExcluded context world values
      candidateAddress = false) :
    stackByteCoveredOriginal world
      (normalizeDataAddress values candidateAddress) = false := by
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryMemoryAddressExcluded, covered] at included

theorem stackByteCoveredCandidate_false_of_ordinaryMemoryWordIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (byte : Nat) (byteBefore : byte < 4)
    (included : ordinaryMemoryWordExcluded context world values
      candidateAddress = false) :
    stackByteCoveredCandidate world
      (candidateAddress + BitVec.ofNat 32 byte) = false := by
  simp only [ordinaryMemoryWordExcluded, Bool.or_eq_false_iff] at included
  have noOrdinaryExclusion := List.any_eq_false.mp included.1 byte
    (List.mem_range.mpr byteBefore)
  exact stackByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
    context world values (candidateAddress + BitVec.ofNat 32 byte)
    (Bool.eq_false_iff.mpr noOrdinaryExclusion)

theorem normalizedWordStackByteCoveredOriginal_false_of_ordinaryMemoryWordIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (byte : Nat) (byteBefore : byte < 4)
    (included : ordinaryMemoryWordExcluded context world values
      candidateAddress = false) :
    stackByteCoveredOriginal world
      (normalizeDataAddress values candidateAddress + BitVec.ofNat 32 byte) = false := by
  simp only [ordinaryMemoryWordExcluded, Bool.or_eq_false_iff] at included
  have noStackExclusion := List.any_eq_false.mp included.2 byte
    (List.mem_range.mpr byteBefore)
  exact Bool.eq_false_iff.mpr noStackExclusion

theorem ordinaryMemoryRelated_after_paired_stack_word_write
    (context : StaticProofContext) (world : RelationalWorld)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Memory)
    (range : DynamicAddressRangePair) (rangeMember : range ∈ world.stackRanges)
    (rangeValid : range.disjointFromImages context = true)
    (offset : Nat) (inside : offset + 4 <= range.size)
    (originalValue candidateValue : Word)
    (related : ordinaryMemoryRelated context world targets values original candidate) :
    ordinaryMemoryRelated context world targets values
      (original.write32 (range.originalBase + BitVec.ofNat 32 offset) originalValue)
      (candidate.write32 (range.candidateBase + BitVec.ofNat 32 offset)
        candidateValue) := by
  by_cases relocations : hasRelocationWords values = true
  · simp only [ordinaryMemoryRelated, relocations] at related ⊢
    rcases related with ⟨relatedBytes, relatedWords⟩
    constructor
    · intro address relocationIncluded ordinaryIncluded
      have candidateUncovered :=
        stackByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
          context world values address ordinaryIncluded
      have originalUncovered :=
        normalizedStackByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
          context world values address ordinaryIncluded
      have candidatePreserved := Memory.write32_apply_of_stackByteUncovered
        context true world range rangeMember rangeValid offset inside candidate
        candidateValue address candidateUncovered
      have originalPreserved := Memory.write32_apply_of_stackByteUncovered
        context false world range rangeMember rangeValid offset inside original
        originalValue (normalizeDataAddress values address) originalUncovered
      have candidatePreserved' :
          candidate.write32 (range.candidateBase + BitVec.ofNat 32 offset)
              candidateValue address = candidate address := by
        simpa [DynamicAddressRangePair.sideBase] using candidatePreserved
      have originalPreserved' :
          original.write32 (range.originalBase + BitVec.ofNat 32 offset)
              originalValue (normalizeDataAddress values address) =
            original (normalizeDataAddress values address) := by
        simpa [DynamicAddressRangePair.sideBase] using originalPreserved
      rw [candidatePreserved', originalPreserved']
      exact relatedBytes address relocationIncluded ordinaryIncluded
    · intro address relocationStart ordinaryIncluded
      have candidateAvoids := write32AvoidsWord_of_stackBytesUncovered context true
        world range rangeMember rangeValid offset inside address
        (fun byte byteBefore =>
          stackByteCoveredCandidate_false_of_ordinaryMemoryWordIncluded
            context world values address byte byteBefore ordinaryIncluded)
      have originalAvoids := write32AvoidsWord_of_stackBytesUncovered context false
        world range rangeMember rangeValid offset inside
        (normalizeDataAddress values address)
        (fun byte byteBefore =>
          normalizedWordStackByteCoveredOriginal_false_of_ordinaryMemoryWordIncluded
            context world values address byte byteBefore ordinaryIncluded)
      have candidateAvoids' : Write32AvoidsWord address
          (range.candidateBase + BitVec.ofNat 32 offset) := by
        simpa [DynamicAddressRangePair.sideBase] using candidateAvoids
      have originalAvoids' : Write32AvoidsWord (normalizeDataAddress values address)
          (range.originalBase + BitVec.ofNat 32 offset) := by
        simpa [DynamicAddressRangePair.sideBase] using originalAvoids
      rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids',
        Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids']
      exact relatedWords address relocationStart ordinaryIncluded
  · have noRelocations : hasRelocationWords values = false := by
      exact Bool.eq_false_iff.mpr relocations
    simp only [ordinaryMemoryRelated, noRelocations] at related ⊢
    intro address ordinaryIncluded
    have candidateUncovered :=
      stackByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
        context world values address ordinaryIncluded
    have originalUncovered :=
      normalizedStackByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
        context world values address ordinaryIncluded
    have candidatePreserved := Memory.write32_apply_of_stackByteUncovered
      context true world range rangeMember rangeValid offset inside candidate
      candidateValue address candidateUncovered
    have originalPreserved := Memory.write32_apply_of_stackByteUncovered
      context false world range rangeMember rangeValid offset inside original
      originalValue (normalizeDataAddress values address) originalUncovered
    have candidatePreserved' :
        candidate.write32 (range.candidateBase + BitVec.ofNat 32 offset)
            candidateValue address = candidate address := by
      simpa [DynamicAddressRangePair.sideBase] using candidatePreserved
    have originalPreserved' :
        original.write32 (range.originalBase + BitVec.ofNat 32 offset)
            originalValue (normalizeDataAddress values address) =
          original (normalizeDataAddress values address) := by
      simpa [DynamicAddressRangePair.sideBase] using originalPreserved
    rw [candidatePreserved', originalPreserved']
    exact related address ordinaryIncluded

theorem RelationalMemoryFamiliesHold.afterPairedStackWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (stackRangesValid : world.stackRangesValid context = true)
    (importsStatic : world.importAddressesStaticValid context = true)
    (dynamicRangesValid : world.dynamicRangesValid context = true)
    (staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (location : PairedStackWordLocation world)
    (locationValid : location.range.disjointFromImages context = true)
    (originalValue candidateValue : Word)
    (valuesRelated :
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        originalValue candidateValue = true)
    (related : RelationalMemoryFamiliesHold context world original candidate) :
    RelationalMemoryFamiliesHold context world
      (original.write32 location.originalAddress originalValue)
      (candidate.write32 location.candidateAddress candidateValue) := by
  have originalNoWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context false location.range locationValid
  have candidateNoWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context true location.range locationValid
  have locationDisjoint := locationValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at locationDisjoint
  have updated := RelationalMemoryFamiliesHold.afterPairedMemoryUpdate
    context world original candidate {
      originalWrites := [(location.originalAddress, originalValue)]
      candidateWrites := [(location.candidateAddress, candidateValue)]
      preservesStackRanges := by
        intro stackRanges
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StackRangesMemoryHold.afterPairedWordWrite context world original candidate
            stackRangesValid stackRanges location.range location.rangeMember
            location.offset location.inside location.aligned originalValue candidateValue
            valuesRelated
      preservesImportAddresses := by
        intro importAddresses
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          ImportAddressesMemoryHold.afterPairedStackWordWrite context world
            original candidate location.range location.rangeMember locationValid
            location.offset location.inside originalValue candidateValue importsStatic
            importAddresses
      preservesOriginalImmutable := by
        intro originalImmutable
        simpa [applyConcreteWrites, location.originalAddressExact] using
          ImmutableImageWordMemory.afterStackWordWrite context.originalPe original
            location.range.originalBase location.range.size location.offset originalValue
            originalNoWrap locationDisjoint.1.2 location.inside originalImmutable
      preservesCandidateImmutable := by
        intro candidateImmutable
        simpa [applyConcreteWrites, location.candidateAddressExact] using
          ImmutableImageWordMemory.afterStackWordWrite context.candidatePe candidate
            location.range.candidateBase location.range.size location.offset candidateValue
            candidateNoWrap locationDisjoint.2 location.inside candidateImmutable
      preservesOrdinary := by
        intro ordinary
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          ordinaryMemoryRelated_after_paired_stack_word_write context world
            context.codeMap.entries.toList (context.relationalValueTargets world)
            original candidate location.range location.rangeMember locationValid
            location.offset location.inside originalValue candidateValue ordinary
      preservesDynamicRanges := by
        intro dynamicRanges
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          DynamicRangesMemoryHold.afterPairedStackWordWrite context world original candidate
            dynamicRangesValid location.range location.rangeMember locationValid
            location.offset location.inside originalValue candidateValue dynamicRanges
      preservesStaticPointerSlots := by
        intro staticPointerSlots
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StaticDynamicPointerSlotsMemoryHold.afterPairedStackWordWrite context world
            original candidate staticPointerSlotsValid location.range locationValid
            location.offset location.inside originalValue candidateValue
            staticPointerSlots
    } related
  simpa [applyConcreteWrites] using updated

structure PairedStackWordUpdate (context : StaticProofContext)
    (world : RelationalWorld) where
  location : PairedStackWordLocation world
  locationValid : location.range.disjointFromImages context = true
  originalValue : Word
  candidateValue : Word
  valuesRelated :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      originalValue candidateValue = true

def PairedStackWordUpdate.originalWrite
    {context : StaticProofContext} {world : RelationalWorld}
    (update : PairedStackWordUpdate context world) : Word × Word :=
  (update.location.originalAddress, update.originalValue)

def PairedStackWordUpdate.candidateWrite
    {context : StaticProofContext} {world : RelationalWorld}
    (update : PairedStackWordUpdate context world) : Word × Word :=
  (update.location.candidateAddress, update.candidateValue)

theorem RelationalMemoryFamiliesHold.afterPairedStackWordUpdates
    (context : StaticProofContext) (world : RelationalWorld)
    (stackRangesValid : world.stackRangesValid context = true)
    (importsStatic : world.importAddressesStaticValid context = true)
    (dynamicRangesValid : world.dynamicRangesValid context = true)
    (staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (updates : List (PairedStackWordUpdate context world))
    (original candidate : Memory)
    (related : RelationalMemoryFamiliesHold context world original candidate) :
    RelationalMemoryFamiliesHold context world
      (applyConcreteWrites original (updates.map PairedStackWordUpdate.originalWrite))
      (applyConcreteWrites candidate (updates.map PairedStackWordUpdate.candidateWrite)) := by
  induction updates generalizing original candidate with
  | nil => simpa [applyConcreteWrites] using related
  | cons update rest induction =>
      have afterHead := RelationalMemoryFamiliesHold.afterPairedStackWordWrite
        context world original candidate stackRangesValid importsStatic
        dynamicRangesValid staticPointerSlotsValid update.location
        update.locationValid update.originalValue update.candidateValue
        update.valuesRelated related
      simpa [applyConcreteWrites, PairedStackWordUpdate.originalWrite,
        PairedStackWordUpdate.candidateWrite] using
        induction
          (original := original.write32 update.location.originalAddress
            update.originalValue)
          (candidate := candidate.write32 update.location.candidateAddress
            update.candidateValue)
          afterHead

theorem ordinaryMemoryRelated_after_no_writes
    (context : StaticProofContext) (world : RelationalWorld)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Memory)
    (related : ordinaryMemoryRelated context world targets values original candidate) :
    ordinaryMemoryRelated context world targets values
      (applyConcreteWrites original []) (applyConcreteWrites candidate []) := by
  simpa [applyConcreteWrites] using related

def ordinaryMemoryCandidateProjection (context : StaticProofContext)
    (world : RelationalWorld) (values : List ValueTargetPair)
    (original excludedValues : Memory) : Memory :=
  fun address =>
    if ordinaryMemoryAddressExcluded context world values address then
      excludedValues address
    else
      original (normalizeDataAddress values address)

theorem ordinaryMemoryRelated_projection_without_relocations
    (context : StaticProofContext) (world : RelationalWorld)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original excludedValues : Memory)
    (none : hasRelocationWords values = false) :
    ordinaryMemoryRelated context world targets values original
      (ordinaryMemoryCandidateProjection context world values original excludedValues) := by
  simp only [ordinaryMemoryRelated, none, ordinaryMemoryCandidateProjection]
  intro address notExcluded
  simp [notExcluded]

def writesRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair) :
    List (Word × Word) -> List (Word × Word) -> Bool
  | [], [] => true
  | original :: originalTail, candidate :: candidateTail =>
      (original.1 == candidate.1 || original.1 == normalizeDataAddress values candidate.1) &&
      wordRelated originalImageBase candidateImageBase targets values original.2 candidate.2 &&
      writesRelated originalImageBase candidateImageBase targets values originalTail candidateTail
  | _, _ => false

theorem writesRelated_self (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (writes : List (Word × Word)) :
    writesRelated originalImageBase candidateImageBase targets values writes writes = true := by
  induction writes with
  | nil => rfl
  | cons write tail ih =>
      simp [writesRelated, wordRelated, ih]

inductive MemoryObservationRelation where
  | exact
  | relatedWord
deriving Repr, DecidableEq

structure MemoryObservationRequirement where
  id : Nat
  relation : MemoryObservationRelation
  original : Expr
  candidate : Expr
deriving Repr, DecidableEq

def MemoryObservationRequirement.holds
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (requirement : MemoryObservationRequirement)
    (originalState candidateState : MachineState) : Bool :=
  let originalValue := requirement.original.eval originalState
  let candidateValue := requirement.candidate.eval candidateState
  match requirement.relation with
  | .exact => originalValue == candidateValue
  | .relatedWord =>
      wordRelated originalImageBase candidateImageBase targets values
        originalValue candidateValue

def memoryObservationContractHolds
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (requirements : List MemoryObservationRequirement)
    (originalState candidateState : MachineState) : Bool :=
  requirements.all fun requirement => requirement.holds originalImageBase
    candidateImageBase targets values originalState candidateState

@[simp] theorem memoryObservationContractHolds_nil
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (originalState candidateState : MachineState) :
    memoryObservationContractHolds originalImageBase candidateImageBase targets values []
      originalState candidateState = true := rfl

structure X87MemoryObservationRequirement where
  id : Nat
  original : X87Expr
  candidate : X87Expr
deriving Repr, DecidableEq

def X87MemoryObservationRequirement.holds
    (requirement : X87MemoryObservationRequirement)
    (originalState candidateState : MachineState) : Bool :=
  requirement.original.eval originalState == requirement.candidate.eval candidateState

def x87MemoryObservationContractHolds
    (requirements : List X87MemoryObservationRequirement)
    (originalState candidateState : MachineState) : Bool :=
  requirements.all fun requirement => requirement.holds originalState candidateState

@[simp] theorem x87MemoryObservationContractHolds_nil
    (originalState candidateState : MachineState) :
    x87MemoryObservationContractHolds [] originalState candidateState = true := rfl

def wordsRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair) :
    List Word -> List Word -> Bool
  | [], [] => true
  | original :: originalTail, candidate :: candidateTail =>
      wordRelated originalImageBase candidateImageBase targets values original candidate &&
        wordsRelated originalImageBase candidateImageBase targets values originalTail candidateTail
  | _, _ => false

theorem wordsRelated_self (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (words : List Word) :
    wordsRelated originalImageBase candidateImageBase targets values words words = true := by
  induction words with
  | nil => rfl
  | cons word tail ih => simp [wordsRelated, wordRelated, ih]

def outcomesRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair) :
    PureOutcome -> PureOutcome -> Bool
  | .returned original, .returned candidate =>
      wordRelated originalImageBase candidateImageBase targets values original candidate
  | .jump original, .jump candidate => original == candidate
  | .branch originalCondition originalTaken originalFallthrough,
      .branch candidateCondition candidateTaken candidateFallthrough =>
      originalCondition == candidateCondition && originalTaken == candidateTaken &&
        originalFallthrough == candidateFallthrough
  | .call originalTarget originalContinuation, .call candidateTarget candidateContinuation =>
      originalTarget == candidateTarget && originalContinuation == candidateContinuation
  | .externalCall originalImport originalArguments originalContinuation,
      .externalCall candidateImport candidateArguments candidateContinuation =>
      originalImport == candidateImport && originalContinuation == candidateContinuation &&
        wordsRelated originalImageBase candidateImageBase targets values
          originalArguments candidateArguments
  | .externalJump originalImport originalArguments,
      .externalJump candidateImport candidateArguments =>
      originalImport == candidateImport &&
        wordsRelated originalImageBase candidateImageBase targets values
          originalArguments candidateArguments
  | .bulkCopy originalDestination originalSource originalCount originalDirection originalContinuation,
      .bulkCopy candidateDestination candidateSource candidateCount candidateDirection candidateContinuation =>
      wordRelated originalImageBase candidateImageBase targets values
          originalDestination candidateDestination &&
        wordRelated originalImageBase candidateImageBase targets values originalSource candidateSource &&
        originalCount == candidateCount && originalDirection == candidateDirection &&
        originalContinuation == candidateContinuation
  | .indirectCall originalTarget originalContinuation,
      .indirectCall candidateTarget candidateContinuation =>
      wordRelated originalImageBase candidateImageBase targets values originalTarget candidateTarget &&
        originalContinuation == candidateContinuation
  | .indirectJump originalTarget, .indirectJump candidateTarget =>
      wordRelated originalImageBase candidateImageBase targets values originalTarget candidateTarget
  | .checkedContinue originalValid originalContinuation,
      .checkedContinue candidateValid candidateContinuation =>
      originalValid == candidateValid && originalContinuation == candidateContinuation
  | .atomicCompareExchange originalAddress originalExpected originalReplacement originalContinuation,
      .atomicCompareExchange candidateAddress candidateExpected candidateReplacement candidateContinuation =>
      wordRelated originalImageBase candidateImageBase targets values originalAddress candidateAddress &&
        wordRelated originalImageBase candidateImageBase targets values originalExpected candidateExpected &&
        wordRelated originalImageBase candidateImageBase targets values originalReplacement candidateReplacement &&
        originalContinuation == candidateContinuation
  | _, _ => false

theorem outcomesRelated_self (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (outcome : PureOutcome) :
    outcomesRelated originalImageBase candidateImageBase targets values outcome outcome = true := by
  cases outcome <;> simp [outcomesRelated, wordsRelated_self, wordRelated]

theorem outcomesRelated_normalized_branch_of_agreement
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (allowedFlags : List Nat) (condition : BoolExpr) (taken fallthrough : Nat)
    (original candidate : MachineState)
    (within : condition.flagsWithin allowedFlags = true)
    (agreement : MachineStateAgreement allowedFlags original candidate) :
    outcomesRelated originalImageBase candidateImageBase targets values
      ((NormalizedOutcomeExpr.branch condition taken fallthrough).eval original)
      ((NormalizedOutcomeExpr.branch condition taken fallthrough).eval candidate) = true := by
  have conditionEqual := BoolExpr.eval_eq_of_flagsWithin allowedFlags original candidate
    condition within agreement
  simp [NormalizedOutcomeExpr.eval, outcomesRelated, conditionEqual]

def evalOutcomePure (candidate : Bool) (targets : List CodeTargetPair)
    (state : PureState) : OutcomeExpr -> Option PureOutcome
  | .returned target => return .returned (← evalExprPure state target)
  | .jump targetRva => return .jump (← normalizeCodeTarget candidate targets targetRva)
  | .branch condition trueTargetRva falseTargetRva =>
      return .branch (← evalBoolExprPure state condition)
        (← normalizeCodeTarget candidate targets trueTargetRva)
        (← normalizeCodeTarget candidate targets falseTargetRva)
  | .call targetRva returnRva _ =>
      return .call (← normalizeCodeTarget candidate targets targetRva)
        (← normalizeCodeTarget candidate targets returnRva)
  | .externalCall imported arguments returnRva =>
      return .externalCall (normalizeImport imported) (← arguments.mapM (evalExprPure state))
        (← normalizeCodeTarget candidate targets returnRva)
  | .externalJump imported arguments =>
      return .externalJump (normalizeImport imported) (← arguments.mapM (evalExprPure state))
  | .bulkCopy copy continuationRva =>
      return .bulkCopy (← evalExprPure state copy.destination) (← evalExprPure state copy.source)
        (← evalExprPure state copy.count) (← evalBoolExprPure state copy.direction)
        (← normalizeCodeTarget candidate targets continuationRva)
  | .indirectCall target continuationRva _ =>
      return .indirectCall (← evalExprPure state target)
        (← normalizeCodeTarget candidate targets continuationRva)
  | .indirectJump target => return .indirectJump (← evalExprPure state target)
  | .checkedContinue valid continuationRva =>
      return .checkedContinue (← evalBoolExprPure state valid)
        (← normalizeCodeTarget candidate targets continuationRva)
  | .atomicCompareExchange address expected replacement continuationRva =>
      return .atomicCompareExchange (← evalExprPure state address) (← evalExprPure state expected)
        (← evalExprPure state replacement) (← normalizeCodeTarget candidate targets continuationRva)

def evalRegistersPure (expressions : Registers Expr) (state : PureState) : Option PureState := do
  pure {
    eax := ← evalExprPure state expressions.eax
    ebx := ← evalExprPure state expressions.ebx
    ecx := ← evalExprPure state expressions.ecx
    edx := ← evalExprPure state expressions.edx
    esi := ← evalExprPure state expressions.esi
    edi := ← evalExprPure state expressions.edi
    ebp := ← evalExprPure state expressions.ebp
    esp := ← evalExprPure state expressions.esp
  }

def evalBehaviorPure (candidate : Bool) (targets : List CodeTargetPair)
    (state : PureState) (behavior : SymbolicBehavior) : Option PureBehavior := do
  if !behavior.writes.isEmpty then none else
  let outcomeExpr ← behavior.outcome
  pure {
    registers := ← evalRegistersPure behavior.registers state
    outcome := ← evalOutcomePure candidate targets state outcomeExpr
  }

def evalOutcome (candidate : Bool) (targets : List CodeTargetPair)
    (state : MachineState) : OutcomeExpr -> Option PureOutcome
  | .returned target => return .returned (target.eval state)
  | .jump targetRva => return .jump (← normalizeCodeTarget candidate targets targetRva)
  | .branch condition trueTargetRva falseTargetRva =>
      return .branch (condition.eval state)
        (← normalizeCodeTarget candidate targets trueTargetRva)
        (← normalizeCodeTarget candidate targets falseTargetRva)
  | .call targetRva returnRva _ =>
      return .call (← normalizeCodeTarget candidate targets targetRva)
        (← normalizeCodeTarget candidate targets returnRva)
  | .externalCall imported arguments returnRva =>
      return .externalCall (normalizeImport imported) (arguments.map (Expr.eval state))
        (← normalizeCodeTarget candidate targets returnRva)
  | .externalJump imported arguments =>
      return .externalJump (normalizeImport imported) (arguments.map (Expr.eval state))
  | .bulkCopy copy continuationRva =>
      return .bulkCopy (copy.destination.eval state) (copy.source.eval state) (copy.count.eval state)
        (copy.direction.eval state) (← normalizeCodeTarget candidate targets continuationRva)
  | .indirectCall target continuationRva _ =>
      return .indirectCall (target.eval state) (← normalizeCodeTarget candidate targets continuationRva)
  | .indirectJump target => return .indirectJump (target.eval state)
  | .checkedContinue valid continuationRva =>
      return .checkedContinue (valid.eval state) (← normalizeCodeTarget candidate targets continuationRva)
  | .atomicCompareExchange address expected replacement continuationRva =>
      return .atomicCompareExchange (address.eval state) (expected.eval state) (replacement.eval state)
        (← normalizeCodeTarget candidate targets continuationRva)

def evalBehavior (candidate : Bool) (targets : List CodeTargetPair)
    (state : MachineState) (behavior : SymbolicBehavior) : Option RelationalBehavior := do
  return (← normalizeSymbolicBehavior candidate targets behavior).eval state

def evalBehaviorRegisters (candidate : Bool) (targets : List CodeTargetPair)
    (state : MachineState) (behavior : SymbolicBehavior) : Option PureState := do
  let normalized ← normalizeSymbolicBehavior candidate targets behavior
  return evalNormalizedRegisters state normalized.registers

def evalBehaviorX87 (candidate : Bool) (targets : List CodeTargetPair)
    (state : MachineState) (behavior : SymbolicBehavior) : Option ConcreteX87State := do
  let normalized ← normalizeSymbolicBehavior candidate targets behavior
  return evalNormalizedX87 state normalized.x87

def evalBehaviorWrites (candidate : Bool) (targets : List CodeTargetPair)
    (state : MachineState) (behavior : SymbolicBehavior) : Option (List (Word × Word)) := do
  let normalized ← normalizeSymbolicBehavior candidate targets behavior
  return evalNormalizedWrites state normalized.writes

def evalBehaviorFlags (candidate : Bool) (targets : List CodeTargetPair)
    (state : MachineState) (behavior : SymbolicBehavior) : Option Word := do
  let normalized ← normalizeSymbolicBehavior candidate targets behavior
  return evalNormalizedFlags state normalized.flags

def evalBehaviorOutcome (candidate : Bool) (targets : List CodeTargetPair)
    (state : MachineState) (behavior : SymbolicBehavior) : Option PureOutcome := do
  let normalized ← normalizeSymbolicBehavior candidate targets behavior
  return normalized.outcome.eval state

def pureRegionBehavior (pe : PE32) (span : Span) (candidate : Bool)
    (targets : List CodeTargetPair) (state : PureState) : Option PureBehavior := do
  let behavior ← regionBehavior pe span
  evalBehaviorPure candidate targets state behavior

structure RegisterPair where
  original : Reg
  candidate : Reg
deriving Repr, DecidableEq

inductive RegisterValueRelation where
  | exact
  | codePointer
  | dataPointer
  | relatedWord
deriving Repr, DecidableEq

structure RegisterRelationPair where
  original : Reg
  candidate : Reg
  relation : RegisterValueRelation
deriving Repr, DecidableEq

structure ImportRegisterRelation where
  original : Reg
  candidate : Reg
  imported : ExternalTarget
deriving Repr, DecidableEq

structure DynamicRegisterRangeRelation where
  original : Reg
  candidate : Reg
  originalOffset : Nat := 0
  candidateOffset : Nat := 0
  requiredWords : List DynamicWordRelation := []
deriving Repr, DecidableEq

def DynamicRegisterRangeRelation.holds (world : RelationalWorld)
    (relation : DynamicRegisterRangeRelation)
    (original candidate : PureState) : Bool :=
  world.dynamicRanges.any fun range =>
    original.get relation.original ==
        range.originalBase + BitVec.ofNat 32 relation.originalOffset &&
      candidate.get relation.candidate ==
        range.candidateBase + BitVec.ofNat 32 relation.candidateOffset &&
      relation.requiredWords.all range.wordRelations.contains

def dynamicRegisterRangeRelationsHold (world : RelationalWorld)
    (relations : List DynamicRegisterRangeRelation)
    (original candidate : PureState) : Bool :=
  relations.all fun relation => relation.holds world original candidate

def ImportRegisterRelation.holds (world : RelationalWorld)
    (relation : ImportRegisterRelation) (original candidate : PureState) : Bool :=
  world.importAddresses.any fun binding =>
    binding.imported == relation.imported &&
      original.get relation.original == binding.originalAddress &&
      candidate.get relation.candidate == binding.candidateAddress

def importRegisterRelationsHold (world : RelationalWorld)
    (relations : List ImportRegisterRelation)
    (original candidate : PureState) : Bool :=
  relations.all fun relation => relation.holds world original candidate

def RegisterValueRelation.holds
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (relation : RegisterValueRelation) (original candidate : Word) : Bool :=
  match relation with
  | .exact => original == candidate
  | .codePointer =>
      (original == BitVec.ofNat 32 0 && candidate == BitVec.ofNat 32 0) ||
        codePointerRelated originalImageBase candidateImageBase targets original candidate
  | .dataPointer =>
      (original == BitVec.ofNat 32 0 && candidate == BitVec.ofNat 32 0) ||
        mappedValueRelated values original candidate
  | .relatedWord =>
      wordRelated originalImageBase candidateImageBase targets values original candidate

theorem mappedValueRelated_append_left (values extra : List ValueTargetPair)
    (original candidate : Word)
    (related : mappedValueRelated values original candidate = true) :
    mappedValueRelated (values ++ extra) original candidate = true := by
  simp only [mappedValueRelated, List.any_append, Bool.or_eq_true]
  exact Or.inl (by simpa [mappedValueRelated] using related)

theorem RegisterValueRelation.holds_append_values
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values extra : List ValueTargetPair)
    (relation : RegisterValueRelation) (original candidate : Word)
    (related : relation.holds originalImageBase candidateImageBase targets values
      original candidate = true) :
    relation.holds originalImageBase candidateImageBase targets (values ++ extra)
      original candidate = true := by
  cases relation with
  | exact => simpa [RegisterValueRelation.holds] using related
  | codePointer => simpa [RegisterValueRelation.holds] using related
  | dataPointer =>
      simp only [RegisterValueRelation.holds, Bool.or_eq_true] at related ⊢
      exact related.elim Or.inl (fun mapped => Or.inr
        (mappedValueRelated_append_left values extra original candidate mapped))
  | relatedWord =>
      simp only [RegisterValueRelation.holds] at related ⊢
      unfold wordRelated at related ⊢
      by_cases equal : (original == candidate) = true
      · simp only [equal, Bool.true_or, Bool.or_true] at related ⊢
        exact related
      · by_cases code : (codePointerRelated originalImageBase candidateImageBase
            targets original candidate) = true
        · simp only [equal, code, Bool.false_or, Bool.true_or, Bool.or_true]
            at related ⊢
          exact related
        · simp only [equal, code, Bool.false_or, Bool.and_eq_true] at related ⊢
          exact ⟨related.1, mappedValueRelated_append_left values extra
            original candidate related.2⟩

def registerRelationsHold (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (relations : List RegisterRelationPair) (original candidate : PureState) : Bool :=
  relations.all fun relation => relation.relation.holds originalImageBase candidateImageBase
    targets values (original.get relation.original) (candidate.get relation.candidate)

def exactIdentityRegister (relations : List RegisterRelationPair) (register : Reg) : Bool :=
  relations.any fun relation =>
    relation.original == register && relation.candidate == register &&
      relation.relation == .exact

theorem registerRelationsHold_exact_identity
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (relations : List RegisterRelationPair) (original candidate : PureState)
    (register : Reg)
    (related : registerRelationsHold originalImageBase candidateImageBase targets values
      relations original candidate = true)
    (exact : exactIdentityRegister relations register = true) :
    original.get register = candidate.get register := by
  simp only [registerRelationsHold, List.all_eq_true] at related
  simp only [exactIdentityRegister, List.any_eq_true] at exact
  rcases exact with ⟨relation, member, checks⟩
  have holds := related relation member
  rcases relation with ⟨originalRegister, candidateRegister, relationKind⟩
  simp only [Bool.and_eq_true, beq_iff_eq] at checks
  rcases checks with ⟨⟨originalEqual, candidateEqual⟩, relationExact⟩
  rw [originalEqual, candidateEqual, relationExact] at holds
  simpa [RegisterValueRelation.holds] using holds

theorem registerRelationsHold_self_exact
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (relations : List RegisterRelationPair) (state : PureState)
    (exact : relations.all (fun relation => relation.relation == .exact) = true)
    (identity : relations.all (fun relation => relation.original == relation.candidate) = true) :
    registerRelationsHold originalImageBase candidateImageBase targets values
      relations state state = true := by
  simp only [registerRelationsHold, List.all_eq_true] at exact identity ⊢
  intro relation member
  have relationExact := exact relation member
  have registersEqual := identity relation member
  simp only [beq_iff_eq] at relationExact registersEqual
  rw [relationExact, registersEqual]
  simp [RegisterValueRelation.holds]

structure RegisterBoundPair where
  original : Reg
  candidate : Reg
  originalExpression : Option Expr := none
  candidateExpression : Option Expr := none
  upperExclusive : Nat
deriving Repr, DecidableEq

structure AddressSeparationPair where
  originalRegister : Reg
  candidateRegister : Reg
  originalOffset : Nat
  candidateOffset : Nat
  originalAddress : Nat
  candidateAddress : Nat
deriving Repr, DecidableEq

structure RegisterOffsetWrite where
  register : Reg
  offset : Nat
  value : Expr
deriving Repr, DecidableEq

structure StackWindowPair where
  rangeId : Nat
  originalRegister : Reg
  candidateRegister : Reg
  bytesBelow : Nat
  bytesAbove : Nat
deriving Repr, DecidableEq

def StackWindowPair.holds (world : RelationalWorld) (window : StackWindowPair)
    (original candidate : PureState) : Bool :=
  match world.stackRanges.find? (fun range => range.id == window.rangeId) with
  | none => false
  | some range =>
      (((((range.originalBase.toNat + window.bytesBelow <=
              (original.get window.originalRegister).toNat &&
            (original.get window.originalRegister).toNat + window.bytesAbove <=
              range.originalBase.toNat + range.size) &&
          range.candidateBase.toNat + window.bytesBelow <=
            (candidate.get window.candidateRegister).toNat) &&
        (candidate.get window.candidateRegister).toNat + window.bytesAbove <=
          range.candidateBase.toNat + range.size) &&
        (original.get window.originalRegister).toNat - range.originalBase.toNat ==
          (candidate.get window.candidateRegister).toNat - range.candidateBase.toNat) &&
        ((original.get window.originalRegister).toNat % 4 == 0 &&
          (candidate.get window.candidateRegister).toNat % 4 == 0))

def stackWindowsRelated (world : RelationalWorld) (windows : List StackWindowPair)
    (original candidate : PureState) : Bool :=
  windows.all fun window => window.holds world original candidate

theorem pairedStackWordLocation_below_window
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world original candidate = true)
    (enoughBelow : 4 <= window.bytesBelow) :
    ∃ location : PairedStackWordLocation world,
      location.originalAddress =
          original.get window.originalRegister - BitVec.ofNat 32 4 ∧
        location.candidateAddress =
          candidate.get window.candidateRegister - BitVec.ofNat 32 4 := by
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at windowHolds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at windowHolds
      rcases windowHolds with
        ⟨⟨⟨⟨⟨originalLower, originalUpper⟩, candidateLower⟩,
          candidateUpper⟩, pairedOffset⟩,
          ⟨originalRegisterAligned, candidateRegisterAligned⟩⟩
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at rangesValid
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have rangeValid := rangesValid.1.1.2 range rangeMember
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq] at rangeValid
      rcases rangeValid with
        ⟨⟨⟨disjoint, originalBaseAligned⟩, candidateBaseAligned⟩, _sizeAligned⟩
      rcases disjoint with
        ⟨⟨⟨⟨_rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩,
          _originalDisjoint⟩, _candidateDisjoint⟩
      let rangeOffset :=
        (original.get window.originalRegister).toNat - range.originalBase.toNat
      let wordOffset := rangeOffset - 4
      have originalAtOffset :
          (original.get window.originalRegister).toNat =
            range.originalBase.toNat + rangeOffset := by
        dsimp [rangeOffset]
        omega
      have candidateRangeOffset :
          (candidate.get window.candidateRegister).toNat -
              range.candidateBase.toNat = rangeOffset := by
        exact pairedOffset.symm
      have candidateAtOffset :
          (candidate.get window.candidateRegister).toNat =
            range.candidateBase.toNat + rangeOffset := by
        omega
      have rangeOffsetEnough : 4 <= rangeOffset := by
        dsimp [rangeOffset]
        omega
      have wordInside : wordOffset + 4 <= range.size := by
        dsimp [wordOffset]
        omega
      have rangeOffsetAligned : rangeOffset % 4 = 0 := by
        dsimp [rangeOffset]
        omega
      have wordAligned : wordOffset % 4 = 0 := by
        dsimp [wordOffset]
        omega
      have originalEnough : 4 <= (original.get window.originalRegister).toNat := by
        omega
      have candidateEnough : 4 <= (candidate.get window.candidateRegister).toNat := by
        omega
      have originalAddressExact :
          original.get window.originalRegister - BitVec.ofNat 32 4 =
            range.originalBase + BitVec.ofNat 32 wordOffset := by
        apply BitVec.eq_of_toNat_eq
        simp [BitVec.toNat_sub, BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt (by omega : wordOffset < 2 ^ 32),
          Nat.mod_eq_of_lt (by omega :
            range.originalBase.toNat + wordOffset < 2 ^ 32)]
        rw [originalAtOffset]
        omega
      have candidateAddressExact :
          candidate.get window.candidateRegister - BitVec.ofNat 32 4 =
            range.candidateBase + BitVec.ofNat 32 wordOffset := by
        apply BitVec.eq_of_toNat_eq
        simp [BitVec.toNat_sub, BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt (by omega : wordOffset < 2 ^ 32),
          Nat.mod_eq_of_lt (by omega :
            range.candidateBase.toNat + wordOffset < 2 ^ 32)]
        rw [candidateAtOffset]
        omega
      refine ⟨{
        range
        offset := wordOffset
        rangeMember
        inside := wordInside
        aligned := wordAligned
        originalAddress := original.get window.originalRegister - BitVec.ofNat 32 4
        candidateAddress := candidate.get window.candidateRegister - BitVec.ofNat 32 4
        originalAddressExact
        candidateAddressExact
      }, rfl, rfl⟩

theorem pairedStackWordLocation_above_window
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world original candidate = true)
    (amount : Nat) (amountAligned : amount % 4 = 0)
    (enoughAbove : amount + 4 <= window.bytesAbove) :
    ∃ location : PairedStackWordLocation world,
      location.originalAddress =
          original.get window.originalRegister + BitVec.ofNat 32 amount ∧
        location.candidateAddress =
          candidate.get window.candidateRegister + BitVec.ofNat 32 amount := by
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at windowHolds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at windowHolds
      rcases windowHolds with
        ⟨⟨⟨⟨⟨originalLower, originalUpper⟩, candidateLower⟩,
          candidateUpper⟩, pairedOffset⟩,
          ⟨originalRegisterAligned, candidateRegisterAligned⟩⟩
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at rangesValid
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have rangeValid := rangesValid.1.1.2 range rangeMember
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq] at rangeValid
      rcases rangeValid with
        ⟨⟨⟨disjoint, originalBaseAligned⟩, candidateBaseAligned⟩, _sizeAligned⟩
      rcases disjoint with
        ⟨⟨⟨⟨_rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩,
          _originalDisjoint⟩, _candidateDisjoint⟩
      let rangeOffset :=
        (original.get window.originalRegister).toNat - range.originalBase.toNat
      let wordOffset := rangeOffset + amount
      have originalAtOffset :
          (original.get window.originalRegister).toNat =
            range.originalBase.toNat + rangeOffset := by
        dsimp [rangeOffset]
        omega
      have candidateRangeOffset :
          (candidate.get window.candidateRegister).toNat -
              range.candidateBase.toNat = rangeOffset := by
        exact pairedOffset.symm
      have candidateAtOffset :
          (candidate.get window.candidateRegister).toNat =
            range.candidateBase.toNat + rangeOffset := by
        omega
      have wordInside : wordOffset + 4 <= range.size := by
        dsimp [wordOffset]
        omega
      have rangeOffsetAligned : rangeOffset % 4 = 0 := by
        dsimp [rangeOffset]
        omega
      have wordAligned : wordOffset % 4 = 0 := by
        dsimp [wordOffset]
        omega
      have amountBefore : amount < 2 ^ 32 := by omega
      have originalAddressBefore :
          (original.get window.originalRegister).toNat + amount < 2 ^ 32 := by
        omega
      have candidateAddressBefore :
          (candidate.get window.candidateRegister).toNat + amount < 2 ^ 32 := by
        omega
      have wordOffsetBefore : wordOffset < 2 ^ 32 := by
        dsimp [wordOffset]
        omega
      have originalBaseOffsetBefore :
          range.originalBase.toNat + wordOffset < 2 ^ 32 := by omega
      have candidateBaseOffsetBefore :
          range.candidateBase.toNat + wordOffset < 2 ^ 32 := by omega
      have originalAddressExact :
          original.get window.originalRegister + BitVec.ofNat 32 amount =
            range.originalBase + BitVec.ofNat 32 wordOffset := by
        apply BitVec.eq_of_toNat_eq
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt amountBefore,
          Nat.mod_eq_of_lt originalAddressBefore,
          Nat.mod_eq_of_lt wordOffsetBefore,
          Nat.mod_eq_of_lt originalBaseOffsetBefore]
        rw [originalAtOffset]
        omega
      have candidateAddressExact :
          candidate.get window.candidateRegister + BitVec.ofNat 32 amount =
            range.candidateBase + BitVec.ofNat 32 wordOffset := by
        apply BitVec.eq_of_toNat_eq
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt amountBefore,
          Nat.mod_eq_of_lt candidateAddressBefore,
          Nat.mod_eq_of_lt wordOffsetBefore,
          Nat.mod_eq_of_lt candidateBaseOffsetBefore]
        rw [candidateAtOffset]
        omega
      refine ⟨{
        range
        offset := wordOffset
        rangeMember
        inside := wordInside
        aligned := wordAligned
        originalAddress :=
          original.get window.originalRegister + BitVec.ofNat 32 amount
        candidateAddress :=
          candidate.get window.candidateRegister + BitVec.ofNat 32 amount
        originalAddressExact
        candidateAddressExact
      }, rfl, rfl⟩

structure StackAddressSeparationClaim where
  window : StackWindowPair
  separation : AddressSeparationPair
deriving Repr, DecidableEq

def addressInsidePe (pe : PE32) (address : Nat) : Bool :=
  pe.imageBase <= address && address < pe.imageBase + pe.sizeOfImage && address < 2^32

def RegisterOffsetWrite.address (write : RegisterOffsetWrite) : Expr :=
  if write.offset = 0 then .inputReg write.register
  else .add (.inputReg write.register) (.constant write.offset)

def RegisterOffsetWrite.toWrite (write : RegisterOffsetWrite) : Expr × Expr :=
  (write.address, write.value)

@[simp] theorem RegisterOffsetWrite.address_eval (write : RegisterOffsetWrite)
    (state : MachineState) :
    write.address.eval state =
      state.registers.get write.register + BitVec.ofNat 32 write.offset := by
  by_cases zero : write.offset = 0
  · simp [RegisterOffsetWrite.address, zero, Expr.eval]
  · simp [RegisterOffsetWrite.address, zero, Expr.eval]

def AddressSeparationPair.sideRegister (candidate : Bool)
    (separation : AddressSeparationPair) : Reg :=
  if candidate then separation.candidateRegister else separation.originalRegister

def AddressSeparationPair.sideOffset (candidate : Bool)
    (separation : AddressSeparationPair) : Nat :=
  if candidate then separation.candidateOffset else separation.originalOffset

def AddressSeparationPair.sideAddress (candidate : Bool)
    (separation : AddressSeparationPair) : Nat :=
  if candidate then separation.candidateAddress else separation.originalAddress

def AddressSeparationPair.matchesWriteByte (candidate : Bool)
    (separation : AddressSeparationPair) (wordAddress wordByte : Nat)
    (write : RegisterOffsetWrite) (writeByte : Nat) : Bool :=
  separation.sideRegister candidate == write.register &&
    separation.sideOffset candidate == write.offset + writeByte &&
    separation.sideAddress candidate == wordAddress + wordByte

def registerOffsetWriteSeparated (candidate : Bool)
    (separations : List AddressSeparationPair) (wordAddress : Nat)
    (write : RegisterOffsetWrite) : Bool :=
  (List.range 4).all fun wordByte =>
    (List.range 4).all fun writeByte =>
      separations.any fun separation =>
        separation.matchesWriteByte candidate wordAddress wordByte write writeByte

def registerOffsetWritesSeparated (candidate : Bool)
    (separations : List AddressSeparationPair) (wordAddress : Nat)
    (writes : List RegisterOffsetWrite) : Bool :=
  writes.all (registerOffsetWriteSeparated candidate separations wordAddress)

def registersRelated (pairs : List RegisterPair) (original candidate : PureState) : Bool :=
  pairs.all fun pair => original.get pair.original == candidate.get pair.candidate

def boundValue (state : PureState) (register : Reg) : Option Expr → Option Word
  | none => some (state.get register)
  | some expression => evalExprPure state expression

def boundsRelated (bounds : List RegisterBoundPair) (original candidate : PureState) : Bool :=
  bounds.all fun bound =>
    match boundValue original bound.original bound.originalExpression,
        boundValue candidate bound.candidate bound.candidateExpression with
    | some originalValue, some candidateValue =>
        decide (originalValue < BitVec.ofNat 32 bound.upperExclusive) &&
          decide (candidateValue < BitVec.ofNat 32 bound.upperExclusive)
    | _, _ => false

def addressSeparationsRelated (separations : List AddressSeparationPair)
    (original candidate : PureState) : Bool :=
  separations.all fun separation =>
    decide (
      original.get separation.originalRegister + BitVec.ofNat 32 separation.originalOffset ≠
        BitVec.ofNat 32 separation.originalAddress
    ) && decide (
      candidate.get separation.candidateRegister + BitVec.ofNat 32 separation.candidateOffset ≠
        BitVec.ofNat 32 separation.candidateAddress
    )

theorem addressSeparationsRelated_original (separations : List AddressSeparationPair)
    (original candidate : PureState)
    (related : addressSeparationsRelated separations original candidate = true) :
    separations.all (fun separation =>
      decide (original.get (separation.sideRegister false) +
        BitVec.ofNat 32 (separation.sideOffset false) ≠
          BitVec.ofNat 32 (separation.sideAddress false))) = true := by
  simp only [addressSeparationsRelated, List.all_eq_true] at related ⊢
  intro separation member
  have both := related separation member
  simp only [Bool.and_eq_true] at both
  simpa [AddressSeparationPair.sideRegister, AddressSeparationPair.sideOffset,
    AddressSeparationPair.sideAddress] using both.1

theorem addressSeparationsRelated_candidate (separations : List AddressSeparationPair)
    (original candidate : PureState)
    (related : addressSeparationsRelated separations original candidate = true) :
    separations.all (fun separation =>
      decide (candidate.get (separation.sideRegister true) +
        BitVec.ofNat 32 (separation.sideOffset true) ≠
          BitVec.ofNat 32 (separation.sideAddress true))) = true := by
  simp only [addressSeparationsRelated, List.all_eq_true] at related ⊢
  intro separation member
  have both := related separation member
  simp only [Bool.and_eq_true] at both
  simpa [AddressSeparationPair.sideRegister, AddressSeparationPair.sideOffset,
    AddressSeparationPair.sideAddress] using both.2

theorem addressSeparationsRelated_member
    {separations : List AddressSeparationPair} {original candidate : PureState}
    (separation : AddressSeparationPair) (member : separation ∈ separations)
    (related : addressSeparationsRelated separations original candidate = true) :
    decide (
      original.get separation.originalRegister +
          BitVec.ofNat 32 separation.originalOffset ≠
        BitVec.ofNat 32 separation.originalAddress
    ) = true ∧ decide (
      candidate.get separation.candidateRegister +
          BitVec.ofNat 32 separation.candidateOffset ≠
        BitVec.ofNat 32 separation.candidateAddress
  ) = true := by
  simp only [addressSeparationsRelated, List.all_eq_true] at related
  have both := related separation member
  simpa only [Bool.and_eq_true] using both

theorem registerOffsetWriteAvoidsWord_of_checked (candidate : Bool)
    (separations : List AddressSeparationPair) (wordAddress : Nat)
    (write : RegisterOffsetWrite) (state : MachineState)
    (sideRelated : separations.all (fun separation =>
      decide (state.registers.get (separation.sideRegister candidate) +
        BitVec.ofNat 32 (separation.sideOffset candidate) ≠
          BitVec.ofNat 32 (separation.sideAddress candidate))) = true)
    (checked : registerOffsetWriteSeparated candidate separations wordAddress write = true) :
    Write32AvoidsWord (BitVec.ofNat 32 wordAddress) (write.address.eval state) := by
  intro wordByte wordByteBefore writeByte writeByteBefore
  simp only [registerOffsetWriteSeparated, List.all_eq_true] at checked
  have wordChecked := checked wordByte (by simpa using wordByteBefore)
  have writeChecked := wordChecked writeByte (by simpa using writeByteBefore)
  simp only [List.any_eq_true] at writeChecked
  rcases writeChecked with ⟨separation, separationMember, matched⟩
  simp only [List.all_eq_true] at sideRelated
  have separated := sideRelated separation separationMember
  simp only [decide_eq_true_eq] at separated
  simp only [AddressSeparationPair.matchesWriteByte, Bool.and_eq_true,
    beq_iff_eq] at matched
  rcases matched with ⟨⟨register, offset⟩, address⟩
  simp only [RegisterOffsetWrite.address_eval]
  rw [register, offset, address] at separated
  intro overlap
  apply separated
  rw [BitVec.add_assoc] at overlap
  rw [← BitVec.ofNat_add, ← BitVec.ofNat_add] at overlap
  exact overlap.symm

theorem registerOffsetWritesAvoidWord_of_checked (candidate : Bool)
    (separations : List AddressSeparationPair) (wordAddress : Nat)
    (writes : List RegisterOffsetWrite) (state : MachineState)
    (sideRelated : separations.all (fun separation =>
      decide (state.registers.get (separation.sideRegister candidate) +
        BitVec.ofNat 32 (separation.sideOffset candidate) ≠
          BitVec.ofNat 32 (separation.sideAddress candidate))) = true)
    (checked : registerOffsetWritesSeparated candidate separations wordAddress writes = true) :
    WritesAvoidWord (BitVec.ofNat 32 wordAddress)
      (evalNormalizedWrites state (writes.map RegisterOffsetWrite.toWrite)) := by
  intro concreteWrite concreteMember
  simp only [evalNormalizedWrites, List.map_map] at concreteMember
  rcases List.mem_map.mp concreteMember with ⟨write, writeMember, rfl⟩
  simp only [registerOffsetWritesSeparated, List.all_eq_true] at checked
  exact registerOffsetWriteAvoidsWord_of_checked candidate separations wordAddress write state
    sideRelated (checked write writeMember)

def AddressSeparationPair.matchesConstantWriteByte (candidate : Bool)
    (separation : AddressSeparationPair) (register : Reg)
    (wordOffset wordByte writeAddress writeByte : Nat) : Bool :=
  separation.sideRegister candidate == register &&
    separation.sideOffset candidate == wordOffset + wordByte &&
    separation.sideAddress candidate == writeAddress + writeByte

def constantWriteSeparatedFromRegisterWord (candidate : Bool)
    (separations : List AddressSeparationPair) (register : Reg) (wordOffset : Nat)
    (write : Expr × Expr) : Bool :=
  match write.1 with
  | .constant writeAddress =>
      (List.range 4).all fun wordByte =>
        (List.range 4).all fun writeByte =>
          separations.any fun separation =>
            separation.matchesConstantWriteByte candidate register wordOffset wordByte
              writeAddress writeByte
  | _ => false

def constantWritesSeparatedFromRegisterWord (candidate : Bool)
    (separations : List AddressSeparationPair) (register : Reg) (wordOffset : Nat)
    (writes : List (Expr × Expr)) : Bool :=
  writes.all (constantWriteSeparatedFromRegisterWord candidate separations register wordOffset)

theorem constantWriteAvoidsRegisterWord_of_checked (candidate : Bool)
    (separations : List AddressSeparationPair) (register : Reg) (wordOffset : Nat)
    (write : Expr × Expr) (state : MachineState)
    (sideRelated : separations.all (fun separation =>
      decide (state.registers.get (separation.sideRegister candidate) +
        BitVec.ofNat 32 (separation.sideOffset candidate) ≠
          BitVec.ofNat 32 (separation.sideAddress candidate))) = true)
    (checked : constantWriteSeparatedFromRegisterWord candidate separations register
      wordOffset write = true) :
    Write32AvoidsWord
      (state.registers.get register + BitVec.ofNat 32 wordOffset)
      (write.1.eval state) := by
  rcases write with ⟨address, value⟩
  cases address <;> simp [constantWriteSeparatedFromRegisterWord] at checked
  case constant writeAddress =>
    intro wordByte wordByteBefore writeByte writeByteBefore
    have wordChecked := checked wordByte (by simpa using wordByteBefore)
    have writeChecked := wordChecked writeByte (by simpa using writeByteBefore)
    rcases writeChecked with ⟨separation, separationMember, matched⟩
    simp only [List.all_eq_true] at sideRelated
    have separated := sideRelated separation separationMember
    simp only [decide_eq_true_eq] at separated
    simp only [AddressSeparationPair.matchesConstantWriteByte, Bool.and_eq_true,
      beq_iff_eq] at matched
    rcases matched with ⟨⟨sideRegister, sideOffset⟩, sideAddress⟩
    rw [sideRegister, sideOffset, sideAddress] at separated
    simp only [Expr.eval]
    intro overlap
    apply separated
    rw [BitVec.add_assoc] at overlap
    rw [← BitVec.ofNat_add, ← BitVec.ofNat_add] at overlap
    exact overlap

theorem constantWritesAvoidRegisterWord_of_checked (candidate : Bool)
    (separations : List AddressSeparationPair) (register : Reg) (wordOffset : Nat)
    (writes : List (Expr × Expr)) (state : MachineState)
    (sideRelated : separations.all (fun separation =>
      decide (state.registers.get (separation.sideRegister candidate) +
        BitVec.ofNat 32 (separation.sideOffset candidate) ≠
          BitVec.ofNat 32 (separation.sideAddress candidate))) = true)
    (checked : constantWritesSeparatedFromRegisterWord candidate separations register
      wordOffset writes = true) :
    WritesAvoidWord
      (state.registers.get register + BitVec.ofNat 32 wordOffset)
      (evalNormalizedWrites state writes) := by
  intro concreteWrite concreteMember
  simp only [evalNormalizedWrites] at concreteMember
  rcases List.mem_map.mp concreteMember with ⟨write, writeMember, rfl⟩
  simp only [constantWritesSeparatedFromRegisterWord, List.all_eq_true] at checked
  exact constantWriteAvoidsRegisterWord_of_checked candidate separations register
    wordOffset write state sideRelated (checked write writeMember)

def flagsRelated (bits : List Nat) (original candidate : Word) : Bool :=
  bits.all fun bit => original.extractLsb' bit 1 == candidate.extractLsb' bit 1

@[simp] theorem flagsRelated_nil (original candidate : Word) :
    flagsRelated [] original candidate = true := rfl

theorem flagsRelated_cons_of_eq (bit : Nat) (bits : List Nat)
    (original candidate : Word)
    (head : original.extractLsb' bit 1 = candidate.extractLsb' bit 1)
    (tail : flagsRelated bits original candidate = true) :
    flagsRelated (bit :: bits) original candidate = true := by
  unfold flagsRelated at tail ⊢
  rw [List.all_cons, Bool.and_eq_true]
  exact ⟨beq_iff_eq.mpr head, tail⟩

theorem flagsRelated_of_contains (bits : List Nat) (original candidate : Word)
    (related : flagsRelated bits original candidate = true)
    (contains : bits.contains bit = true) :
    original.extractLsb' bit 1 = candidate.extractLsb' bit 1 := by
  simp [flagsRelated] at related
  exact related bit (by simpa using contains)

def registersRelatedValues (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (pairs : List RegisterPair) (original candidate : PureState) : Bool :=
  pairs.all fun pair => wordRelated originalImageBase candidateImageBase targets values
    (original.get pair.original) (candidate.get pair.candidate)

def RegisterPair.exactRelation (pair : RegisterPair) : RegisterRelationPair := {
  original := pair.original
  candidate := pair.candidate
  relation := .exact
}

def exactRegisterRelations : List RegisterPair -> List RegisterRelationPair
  | [] => []
  | pair :: pairs => pair.exactRelation :: exactRegisterRelations pairs

@[simp] theorem registerRelationsHold_exactRegisterRelations
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (pairs : List RegisterPair) (original candidate : PureState) :
    registerRelationsHold originalImageBase candidateImageBase targets values
      (exactRegisterRelations pairs) original candidate =
        registersRelated pairs original candidate := by
  induction pairs with
  | nil => rfl
  | cons pair pairs ih =>
      change
        (original.get pair.original == candidate.get pair.candidate &&
          registerRelationsHold originalImageBase candidateImageBase targets values
            (exactRegisterRelations pairs) original candidate) =
        (original.get pair.original == candidate.get pair.candidate &&
          registersRelated pairs original candidate)
      rw [ih]

structure StateInvariant where
  registerRelations : List RegisterRelationPair
  importRegisterRelations : List ImportRegisterRelation := []
  dynamicRegisterRangeRelations : List DynamicRegisterRangeRelation := []
  flagBits : List Nat := [0, 2, 6, 7, 10, 11]
  bounds : List RegisterBoundPair := []
  addressSeparations : List AddressSeparationPair := []
  stackWindows : List StackWindowPair := []
deriving Repr, DecidableEq

def StackAddressSeparationClaim.checked (originalPe candidatePe : PE32)
    (invariant : StateInvariant) (claim : StackAddressSeparationClaim) : Bool :=
  invariant.stackWindows.contains claim.window &&
    claim.window.originalRegister == claim.separation.originalRegister &&
    claim.window.candidateRegister == claim.separation.candidateRegister &&
    claim.separation.originalOffset < claim.window.bytesAbove &&
    claim.separation.candidateOffset < claim.window.bytesAbove &&
    addressInsidePe originalPe claim.separation.originalAddress &&
    addressInsidePe candidatePe claim.separation.candidateAddress

theorem stackAddressSeparation_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (claim : StackAddressSeparationClaim)
    (original candidate : PureState)
    (rangesValid : world.stackRangesValid context = true)
    (windowsRelated : stackWindowsRelated world invariant.stackWindows
      original candidate = true)
    (checked : claim.checked context.originalPe context.candidatePe invariant = true) :
    original.get claim.separation.originalRegister +
        BitVec.ofNat 32 claim.separation.originalOffset ≠
          BitVec.ofNat 32 claim.separation.originalAddress ∧
      candidate.get claim.separation.candidateRegister +
        BitVec.ofNat 32 claim.separation.candidateOffset ≠
          BitVec.ofNat 32 claim.separation.candidateAddress := by
  simp only [StackAddressSeparationClaim.checked, Bool.and_eq_true,
    beq_iff_eq, addressInsidePe, decide_eq_true_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨windowMember, originalRegister⟩, candidateRegister⟩,
      originalOffsetInside⟩, candidateOffsetInside⟩, originalAddressInside⟩,
      candidateAddressInside⟩
  rcases originalAddressInside with
    ⟨⟨originalAddressLower, originalAddressUpper⟩, originalAddressFits⟩
  rcases candidateAddressInside with
    ⟨⟨candidateAddressLower, candidateAddressUpper⟩, candidateAddressFits⟩
  simp only [stackWindowsRelated, List.all_eq_true] at windowsRelated
  have windowHolds := windowsRelated claim.window (by simpa using windowMember)
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == claim.window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at windowHolds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at windowHolds
      rcases windowHolds with
        ⟨⟨⟨⟨⟨originalLower, originalUpper⟩, candidateLower⟩,
          candidateUpper⟩, pairedOffset⟩,
          ⟨_originalAligned, _candidateAligned⟩⟩
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at rangesValid
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have rangeValid := rangesValid.1.1.2 range rangeMember
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq] at rangeValid
      rcases rangeValid with
        ⟨⟨⟨⟨rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩,
          originalDisjoint⟩, candidateDisjoint⟩
      constructor
      · rw [← originalRegister]
        intro overlap
        have asNat := congrArg BitVec.toNat overlap
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt (by omega : claim.separation.originalOffset < 2 ^ 32),
          Nat.mod_eq_of_lt (by omega : claim.separation.originalAddress < 2 ^ 32)] at asNat
        omega

      · rw [← candidateRegister]
        intro overlap
        have asNat := congrArg BitVec.toNat overlap
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt (by omega : claim.separation.candidateOffset < 2 ^ 32),
          Nat.mod_eq_of_lt (by omega : claim.separation.candidateAddress < 2 ^ 32)] at asNat
        omega

def stackAddressSeparationInventoryChecked (originalPe candidatePe : PE32)
    (invariant : StateInvariant) (claims : List StackAddressSeparationClaim) : Bool :=
  claims.all (fun claim => claim.checked originalPe candidatePe invariant) &&
    invariant.addressSeparations.all fun separation =>
      claims.any fun claim => claim.separation == separation

theorem addressSeparationsRelated_of_stack_windows
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (claims : List StackAddressSeparationClaim)
    (original candidate : PureState)
    (rangesValid : world.stackRangesValid context = true)
    (windowsRelated : stackWindowsRelated world invariant.stackWindows
      original candidate = true)
    (inventory : stackAddressSeparationInventoryChecked context.originalPe
      context.candidatePe invariant claims = true) :
    addressSeparationsRelated invariant.addressSeparations original candidate = true := by
  simp only [stackAddressSeparationInventoryChecked, Bool.and_eq_true] at inventory
  rcases inventory with ⟨claimsChecked, complete⟩
  simp only [List.all_eq_true] at claimsChecked complete
  simp only [addressSeparationsRelated, List.all_eq_true]
  intro separation separationMember
  have covered := complete separation separationMember
  simp only [List.any_eq_true, beq_iff_eq] at covered
  rcases covered with ⟨claim, claimMember, claimSeparation⟩
  have separated := stackAddressSeparation_of_checked context world invariant claim
    original candidate rangesValid windowsRelated (claimsChecked claim claimMember)
  rw [claimSeparation] at separated
  simpa only [Bool.and_eq_true, decide_eq_true_eq] using separated

theorem stackMemoryRead32Related_of_window
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : MachineState)
    (offset : Nat)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world original.registers candidate.registers = true)
    (stackMemory : StackRangesMemoryHold context world original.memory candidate.memory)
    (inside : offset + 4 <= window.bytesAbove) (aligned : offset % 4 = 0) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (Memory.read32 original.memory
        (original.registers.get window.originalRegister + BitVec.ofNat 32 offset))
      (Memory.read32 candidate.memory
        (candidate.registers.get window.candidateRegister + BitVec.ofNat 32 offset)) = true := by
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at windowHolds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at windowHolds
      rcases windowHolds with
        ⟨⟨⟨⟨⟨originalLower, originalUpper⟩, candidateLower⟩,
          candidateUpper⟩, pairedOffset⟩,
          ⟨originalAligned, candidateAligned⟩⟩
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at rangesValid
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have rangeValid := rangesValid.1.1.2 range rangeMember
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq] at rangeValid
      rcases rangeValid with
        ⟨⟨⟨disjoint, originalBaseAligned⟩, candidateBaseAligned⟩, _sizeAligned⟩
      rcases disjoint with
        ⟨⟨⟨⟨_rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩,
          _originalDisjoint⟩, _candidateDisjoint⟩
      let rangeOffset :=
        (original.registers.get window.originalRegister).toNat -
          range.originalBase.toNat
      have candidateRangeOffset :
          (candidate.registers.get window.candidateRegister).toNat -
              range.candidateBase.toNat = rangeOffset := by
        exact pairedOffset.symm
      have candidateRegisterAddress :
          (candidate.registers.get window.candidateRegister).toNat =
            range.candidateBase.toNat + rangeOffset := by
        omega
      have offsetInside : rangeOffset + offset + 4 <= range.size := by
        dsimp [rangeOffset]
        omega
      have rangeOffsetAligned : rangeOffset % 4 = 0 := by
        dsimp [rangeOffset]
        omega
      have combinedAligned : (rangeOffset + offset) % 4 = 0 := by omega
      have originalAddress :
          original.registers.get window.originalRegister + BitVec.ofNat 32 offset =
            range.originalBase + BitVec.ofNat 32 (rangeOffset + offset) := by
        apply BitVec.eq_of_toNat_eq
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt (by omega : offset < 2 ^ 32),
          Nat.mod_eq_of_lt (by omega : rangeOffset + offset < 2 ^ 32)]
        dsimp [rangeOffset]
        omega
      have candidateAddress :
          candidate.registers.get window.candidateRegister + BitVec.ofNat 32 offset =
            range.candidateBase + BitVec.ofNat 32 (rangeOffset + offset) := by
        apply BitVec.eq_of_toNat_eq
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt (by omega : offset < 2 ^ 32),
          Nat.mod_eq_of_lt (by omega : rangeOffset + offset < 2 ^ 32)]
        rw [candidateRegisterAddress]
        omega
      rw [originalAddress, candidateAddress]
      exact stackMemory range rangeMember (rangeOffset + offset) offsetInside
        combinedAligned

inductive StackAdjustment where
  | identity
  | add (amount : Nat)
  | subtract (amount : Nat)
deriving Repr, DecidableEq

def StackAdjustment.expression (adjustment : StackAdjustment) (register : Reg) : Expr :=
  match adjustment with
  | .identity => .inputReg register
  | .add amount => .add (.inputReg register) (.constant amount)
  | .subtract amount => .sub (.inputReg register) (.constant amount)

def StackAdjustment.expressionMatches (adjustment : StackAdjustment) (register : Reg)
    (expression : Expr) : Bool :=
  expression == adjustment.expression register ||
    match adjustment with
    | .subtract amount =>
        decide (amount < 2 ^ 32) &&
          expression == .add (.inputReg register) (.constant (2 ^ 32 - amount))
    | _ => false

theorem StackAdjustment.eval_expression_of_matches (adjustment : StackAdjustment)
    (register : Reg) (expression : Expr) (state : MachineState)
    (matchesExpression : adjustment.expressionMatches register expression = true) :
    expression.eval state = (adjustment.expression register).eval state := by
  cases adjustment with
  | identity =>
      simp only [StackAdjustment.expressionMatches, StackAdjustment.expression,
        Bool.or_false, beq_iff_eq] at matchesExpression
      simp [matchesExpression, StackAdjustment.expression]
  | add amount =>
      simp only [StackAdjustment.expressionMatches, StackAdjustment.expression,
        Bool.or_false, beq_iff_eq] at matchesExpression
      simp [matchesExpression, StackAdjustment.expression]
  | subtract amount =>
      simp only [StackAdjustment.expressionMatches, Bool.or_eq_true,
        Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at matchesExpression
      rcases matchesExpression with exactExpression | ⟨amountFits, twosComplementExpression⟩
      · rw [exactExpression]
      · rw [twosComplementExpression]
        simp only [StackAdjustment.expression, Expr.eval]
        exact word_add_ia32_twos_complement (state.registers.get register) amount amountFits

def StackAdjustment.requiredBelow (adjustment : StackAdjustment)
    (target : StackWindowPair) : Nat :=
  match adjustment with
  | .identity => target.bytesBelow
  | .add amount => target.bytesBelow - amount
  | .subtract amount => target.bytesBelow + amount

def StackAdjustment.requiredAbove (adjustment : StackAdjustment)
    (target : StackWindowPair) : Nat :=
  match adjustment with
  | .identity => target.bytesAbove
  | .add amount => target.bytesAbove + amount
  | .subtract amount => target.bytesAbove - amount

structure StackWindowAffineTransferClaim where
  source : StackWindowPair
  target : StackWindowPair
  adjustment : StackAdjustment
deriving Repr, DecidableEq

def StackWindowAffineTransferClaim.checked
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackWindowAffineTransferClaim) : Bool :=
  sourceInvariant.stackWindows.contains claim.source &&
    targetInvariant.stackWindows.contains claim.target &&
    claim.source.rangeId == claim.target.rangeId &&
    claim.source.originalRegister == claim.target.originalRegister &&
    claim.source.candidateRegister == claim.target.candidateRegister &&
    decide (claim.source.bytesBelow >= claim.adjustment.requiredBelow claim.target) &&
    decide (claim.source.bytesAbove >= claim.adjustment.requiredAbove claim.target) &&
    (match claim.adjustment with
      | .identity => true
      | .add amount =>
          (decide (claim.target.bytesAbove > 0) && decide (amount < 2 ^ 31)) &&
            decide (amount % 4 = 0)
      | .subtract amount =>
          decide (amount < 2 ^ 31) && decide (amount % 4 = 0)) &&
    claim.adjustment.expressionMatches claim.source.originalRegister
      (originalBehavior.registers.get claim.target.originalRegister) &&
    claim.adjustment.expressionMatches claim.source.candidateRegister
      (candidateBehavior.registers.get claim.target.candidateRegister)

theorem stackWindowAffineTransferHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackWindowAffineTransferClaim)
    (originalState candidateState : MachineState)
    (rangesValid : world.stackRangesValid context = true)
    (sourceRelated : stackWindowsRelated world sourceInvariant.stackWindows
      originalState.registers candidateState.registers = true)
    (checked : claim.checked sourceInvariant targetInvariant
      originalBehavior candidateBehavior = true) :
    claim.target.holds world (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [StackWindowAffineTransferClaim.checked, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨sourceMember, targetMember⟩, rangeId⟩,
      originalRegister⟩, candidateRegister⟩,
      enoughBelow⟩, enoughAbove⟩, adjustmentSafe⟩,
      originalExpression⟩, candidateExpression⟩
  simp only [stackWindowsRelated, List.all_eq_true] at sourceRelated
  have sourceHolds := sourceRelated claim.source (by simpa using sourceMember)
  have rangeId' := beq_iff_eq.mp rangeId
  have originalRegister' := beq_iff_eq.mp originalRegister
  have candidateRegister' := beq_iff_eq.mp candidateRegister
  rw [originalRegister'] at originalExpression
  rw [candidateRegister'] at candidateExpression
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == claim.target.rangeId) with
  | none =>
      have sourceRangeResult : world.stackRanges.find? (fun range =>
          range.id == claim.source.rangeId) = none := by
        simpa [rangeId'] using rangeResult
      simp [StackWindowPair.holds, sourceRangeResult] at sourceHolds
  | some range =>
      have sourceRangeResult : world.stackRanges.find? (fun item =>
          item.id == claim.source.rangeId) = some range := by
        simpa [rangeId'] using rangeResult
      simp only [StackWindowPair.holds, sourceRangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at sourceHolds
      rcases sourceHolds with
        ⟨⟨⟨⟨⟨originalLower, originalUpper⟩, candidateLower⟩,
          candidateUpper⟩, pairedOffset⟩,
          ⟨originalAligned, candidateAligned⟩⟩
      rw [originalRegister'] at originalLower originalUpper pairedOffset
      rw [originalRegister'] at originalAligned
      rw [candidateRegister'] at candidateLower candidateUpper pairedOffset
      rw [candidateRegister'] at candidateAligned
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at rangesValid
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have rangeValid := rangesValid.1.1.2 range rangeMember
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq] at rangeValid
      rcases rangeValid with
        ⟨⟨⟨⟨rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩, _⟩, _⟩
      have pairedLinear :
          (originalState.registers.get claim.target.originalRegister).toNat +
              range.candidateBase.toNat =
            (candidateState.registers.get claim.target.candidateRegister).toNat +
              range.originalBase.toNat := by
        omega
      simp only [StackWindowPair.holds, rangeResult,
        NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get]
      have originalExpression' := StackAdjustment.eval_expression_of_matches
        claim.adjustment claim.target.originalRegister
        (originalBehavior.registers.get claim.target.originalRegister) originalState
        originalExpression
      have candidateExpression' := StackAdjustment.eval_expression_of_matches
        claim.adjustment claim.target.candidateRegister
        (candidateBehavior.registers.get claim.target.candidateRegister) candidateState
        candidateExpression
      rw [originalExpression', candidateExpression']
      cases adjustmentResult : claim.adjustment with
      | identity =>
          simp only [StackAdjustment.expression, Expr.eval]
          simp only [StackAdjustment.requiredBelow, adjustmentResult] at enoughBelow
          simp only [StackAdjustment.requiredAbove, adjustmentResult] at enoughAbove
          simp only [Bool.and_eq_true, decide_eq_true_eq]
          refine ⟨⟨⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ⟨?_, ?_⟩⟩
          · omega
          · omega
          · omega
          · omega
          · simpa only [beq_iff_eq] using pairedOffset
          · exact beq_iff_eq.mpr originalAligned
          · exact beq_iff_eq.mpr candidateAligned
      | add amount =>
          simp only [StackAdjustment.expression, Expr.eval]
          simp only [StackAdjustment.requiredBelow, adjustmentResult] at enoughBelow
          simp only [StackAdjustment.requiredAbove, adjustmentResult] at enoughAbove
          simp only [adjustmentResult, Bool.and_eq_true, decide_eq_true_eq]
            at adjustmentSafe
          rcases adjustmentSafe with
            ⟨⟨targetNonempty, amountFits⟩, amountAligned⟩
          have originalAdjusted :
              (originalState.registers.get claim.target.originalRegister +
                BitVec.ofNat 32 amount).toNat =
                (originalState.registers.get claim.target.originalRegister).toNat + amount := by
            simp [BitVec.toNat_add, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt (by omega : amount < 2 ^ 32),
              Nat.mod_eq_of_lt (by omega :
                (originalState.registers.get claim.target.originalRegister).toNat +
                  amount < 2 ^ 32)]
          have candidateAdjusted :
              (candidateState.registers.get claim.target.candidateRegister +
                BitVec.ofNat 32 amount).toNat =
                (candidateState.registers.get claim.target.candidateRegister).toNat + amount := by
            simp [BitVec.toNat_add, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt (by omega : amount < 2 ^ 32),
              Nat.mod_eq_of_lt (by omega :
                (candidateState.registers.get claim.target.candidateRegister).toNat +
                  amount < 2 ^ 32)]
          simp only [Bool.and_eq_true, decide_eq_true_eq, originalAdjusted,
            candidateAdjusted]
          have originalTargetLower :
              range.originalBase.toNat + claim.target.bytesBelow <=
                (originalState.registers.get claim.target.originalRegister).toNat +
                  amount := by omega
          have originalTargetUpper :
              (originalState.registers.get claim.target.originalRegister).toNat +
                    amount + claim.target.bytesAbove <=
                range.originalBase.toNat + range.size := by omega
          have candidateTargetLower :
              range.candidateBase.toNat + claim.target.bytesBelow <=
                (candidateState.registers.get claim.target.candidateRegister).toNat +
                  amount := by omega
          have candidateTargetUpper :
              (candidateState.registers.get claim.target.candidateRegister).toNat +
                    amount + claim.target.bytesAbove <=
                range.candidateBase.toNat + range.size := by omega
          refine ⟨⟨⟨⟨⟨originalTargetLower, originalTargetUpper⟩,
            candidateTargetLower⟩, candidateTargetUpper⟩, ?_⟩, ⟨?_, ?_⟩⟩
          · simp only [beq_iff_eq]
            omega
          · apply beq_iff_eq.mpr
            exact Nat.dvd_iff_mod_eq_zero.mp
              (Nat.dvd_add (Nat.dvd_iff_mod_eq_zero.mpr originalAligned)
                (Nat.dvd_iff_mod_eq_zero.mpr amountAligned))
          · apply beq_iff_eq.mpr
            exact Nat.dvd_iff_mod_eq_zero.mp
              (Nat.dvd_add (Nat.dvd_iff_mod_eq_zero.mpr candidateAligned)
                (Nat.dvd_iff_mod_eq_zero.mpr amountAligned))
      | subtract amount =>
          simp only [StackAdjustment.expression, Expr.eval]
          simp only [StackAdjustment.requiredBelow, adjustmentResult] at enoughBelow
          simp only [StackAdjustment.requiredAbove, adjustmentResult] at enoughAbove
          simp only [adjustmentResult, Bool.and_eq_true, decide_eq_true_eq]
            at adjustmentSafe
          rcases adjustmentSafe with ⟨amountFits, amountAligned⟩
          have originalEnough :
              amount <= (originalState.registers.get claim.target.originalRegister).toNat := by
            omega
          have candidateEnough :
              amount <= (candidateState.registers.get claim.target.candidateRegister).toNat := by
            omega
          have originalAdjusted :
              (originalState.registers.get claim.target.originalRegister -
                BitVec.ofNat 32 amount).toNat =
                (originalState.registers.get claim.target.originalRegister).toNat - amount := by
            simp [BitVec.toNat_sub, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt (by omega : amount < 2 ^ 32)]
            omega
          have candidateAdjusted :
              (candidateState.registers.get claim.target.candidateRegister -
                BitVec.ofNat 32 amount).toNat =
                (candidateState.registers.get claim.target.candidateRegister).toNat - amount := by
            simp [BitVec.toNat_sub, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt (by omega : amount < 2 ^ 32)]
            omega
          simp only [Bool.and_eq_true, decide_eq_true_eq, originalAdjusted,
            candidateAdjusted]
          have originalTargetLower :
              range.originalBase.toNat + claim.target.bytesBelow <=
                (originalState.registers.get claim.target.originalRegister).toNat -
                  amount := by omega
          have originalTargetUpper :
              (originalState.registers.get claim.target.originalRegister).toNat -
                    amount + claim.target.bytesAbove <=
                range.originalBase.toNat + range.size := by omega
          have candidateTargetLower :
              range.candidateBase.toNat + claim.target.bytesBelow <=
                (candidateState.registers.get claim.target.candidateRegister).toNat -
                  amount := by omega
          have candidateTargetUpper :
              (candidateState.registers.get claim.target.candidateRegister).toNat -
                    amount + claim.target.bytesAbove <=
                range.candidateBase.toNat + range.size := by omega
          refine ⟨⟨⟨⟨⟨originalTargetLower, originalTargetUpper⟩,
            candidateTargetLower⟩, candidateTargetUpper⟩, ?_⟩, ⟨?_, ?_⟩⟩
          · simp only [beq_iff_eq]
            omega
          · apply beq_iff_eq.mpr
            exact Nat.dvd_iff_mod_eq_zero.mp
              (Nat.dvd_sub (Nat.dvd_iff_mod_eq_zero.mpr originalAligned)
                (Nat.dvd_iff_mod_eq_zero.mpr amountAligned))
          · apply beq_iff_eq.mpr
            exact Nat.dvd_iff_mod_eq_zero.mp
              (Nat.dvd_sub (Nat.dvd_iff_mod_eq_zero.mpr candidateAligned)
                (Nat.dvd_iff_mod_eq_zero.mpr amountAligned))

def stackWindowsAffineTransferChecked
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List StackWindowAffineTransferClaim) : Bool :=
  claims.map StackWindowAffineTransferClaim.target == targetInvariant.stackWindows &&
    claims.all (StackWindowAffineTransferClaim.checked sourceInvariant targetInvariant
      originalBehavior candidateBehavior)

theorem stackWindowsRelated_after_affine_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List StackWindowAffineTransferClaim)
    (originalState candidateState : MachineState)
    (rangesValid : world.stackRangesValid context = true)
    (sourceRelated : stackWindowsRelated world sourceInvariant.stackWindows
      originalState.registers candidateState.registers = true)
    (checked : stackWindowsAffineTransferChecked sourceInvariant targetInvariant
      originalBehavior candidateBehavior claims = true) :
    stackWindowsRelated world targetInvariant.stackWindows
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [stackWindowsAffineTransferChecked, Bool.and_eq_true] at checked
  have inventory := beq_iff_eq.mp checked.1
  rw [← inventory]
  simp only [stackWindowsRelated, List.all_eq_true, List.mem_map]
  intro target targetMember
  rcases targetMember with ⟨claim, claimMember, rfl⟩
  simp only [List.all_eq_true] at checked
  exact stackWindowAffineTransferHolds_of_checked context world sourceInvariant
    targetInvariant originalBehavior candidateBehavior claim originalState candidateState
    rangesValid sourceRelated (checked.2 claim claimMember)

def stackWindowsIdentityTransferChecked
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  targetInvariant.stackWindows.all fun window =>
    sourceInvariant.stackWindows.contains window &&
      originalBehavior.registers.get window.originalRegister ==
        .inputReg window.originalRegister &&
      candidateBehavior.registers.get window.candidateRegister ==
        .inputReg window.candidateRegister

theorem stackWindowsRelated_after_identity_of_checked
    (world : RelationalWorld) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalState candidateState : MachineState)
    (sourceRelated : stackWindowsRelated world sourceInvariant.stackWindows
      originalState.registers candidateState.registers = true)
    (checked : stackWindowsIdentityTransferChecked sourceInvariant targetInvariant
      originalBehavior candidateBehavior = true) :
    stackWindowsRelated world targetInvariant.stackWindows
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [stackWindowsIdentityTransferChecked, List.all_eq_true] at checked
  simp only [stackWindowsRelated, List.all_eq_true] at sourceRelated ⊢
  intro window windowMember
  have row := checked window windowMember
  simp only [Bool.and_eq_true, beq_iff_eq] at row
  rcases row with ⟨⟨sourceMember, originalIdentity⟩, candidateIdentity⟩
  have holds := sourceRelated window (by simpa using sourceMember)
  simp only [StackWindowPair.holds]
  cases rangeResult : world.stackRanges.find? (fun range => range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at holds
  | some range =>
      simp only [rangeResult]
      simp only [NormalizedSymbolicBehavior.eval_registers,
        evalNormalizedRegisters_get, originalIdentity, candidateIdentity, Expr.eval]
      simpa [StackWindowPair.holds, rangeResult] using holds

def StateRelCore (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (invariant : StateInvariant) (original candidate : MachineState) : Prop :=
  registerRelationsHold originalImageBase candidateImageBase targets values
      invariant.registerRelations original.registers candidate.registers = true ∧
    boundsRelated invariant.bounds original.registers candidate.registers = true ∧
    addressSeparationsRelated invariant.addressSeparations
      original.registers candidate.registers = true ∧
    memoryRelated originalImageBase candidateImageBase targets values
      original.memory candidate.memory ∧
    original.undefinedValue = candidate.undefinedValue ∧
    original.x87 = candidate.x87 ∧
    flagsRelated invariant.flagBits original.eflags candidate.eflags = true ∧
    original.fsBase = candidate.fsBase

def StateRelCoreWithImportMask (context : StaticProofContext)
    (world : RelationalWorld) (invariant : StateInvariant)
    (original candidate : MachineState) : Prop :=
  registerRelationsHold context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      invariant.registerRelations original.registers candidate.registers = true ∧
    boundsRelated invariant.bounds original.registers candidate.registers = true ∧
    addressSeparationsRelated invariant.addressSeparations
      original.registers candidate.registers = true ∧
    stackWindowsRelated world invariant.stackWindows
      original.registers candidate.registers = true ∧
    ordinaryMemoryRelated context world context.codeMap.entries.toList
      (context.relationalValueTargets world) original.memory candidate.memory ∧
    RelationalDynamicMemoryHold context world original.memory candidate.memory ∧
    original.undefinedValue = candidate.undefinedValue ∧
    original.x87 = candidate.x87 ∧
    flagsRelated invariant.flagBits original.eflags candidate.eflags = true ∧
    original.fsBase = candidate.fsBase

def StateRel (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState) : Prop :=
  world.valid context = true ∧
    world.stackRangesValid context = true ∧
    StackRangesMemoryHold context world original.memory candidate.memory ∧
    world.importAddressesStaticValid context = true ∧
    world.importAddressesComplete context = true ∧
    ImportAddressesMemoryHold context world original.memory candidate.memory ∧
    ImmutableImageWordMemory context.originalPe original.memory ∧
    ImmutableImageWordMemory context.candidatePe candidate.memory ∧
    StateRelCoreWithImportMask context world invariant original candidate ∧
    (importRegisterRelationsHold world invariant.importRegisterRelations
        original.registers candidate.registers = true ∧
      dynamicRegisterRangeRelationsHold world invariant.dynamicRegisterRangeRelations
        original.registers candidate.registers = true)

theorem evalInputRegisterOffset (state : MachineState) (register : Reg)
    (offset : Nat) :
    ((Expr.inputReg register).offset offset).eval state =
      state.registers.get register + BitVec.ofNat 32 offset := by
  cases offset <;> simp [Expr.offset, Expr.addNormalized, Expr.eval]

structure RegisterArgumentClaim where
  relation : RegisterRelationPair
  offset : Nat
deriving Repr, DecidableEq

def registerArgumentExpression (register : Reg) (offset : Nat) : Expr :=
  (Expr.inputReg register).offset offset

def RegisterArgumentClaim.checked (sourceInvariant : StateInvariant)
    (originalExpression candidateExpression : Expr)
    (claim : RegisterArgumentClaim) : Bool :=
  sourceInvariant.registerRelations.contains claim.relation &&
    (claim.relation.relation == .exact ||
      (claim.relation.relation == .relatedWord && claim.offset == 0)) &&
    originalExpression == registerArgumentExpression claim.relation.original claim.offset &&
    candidateExpression == registerArgumentExpression claim.relation.candidate claim.offset

theorem registerArgumentWordsRelated_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalExpression candidateExpression : Expr)
    (claim : RegisterArgumentClaim)
    (checked : claim.checked sourceInvariant originalExpression
      candidateExpression = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (originalExpression.eval originalState) (candidateExpression.eval candidateState) =
      true := by
  simp only [RegisterArgumentClaim.checked, Bool.and_eq_true, Bool.or_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨relationMember, supported⟩, originalExpressionExact⟩,
      candidateExpressionExact⟩
  rcases related with
    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable, _candidateImmutable,
      relatedCore, _importAndDynamicRegisters⟩
  have registerRelations := relatedCore.1
  simp only [registerRelationsHold, List.all_eq_true] at registerRelations
  have relationHolds := registerRelations claim.relation
    (by simpa using relationMember)
  change claim.relation.relation.holds context.originalPe.imageBase
    context.candidatePe.imageBase context.codeMap.entries.toList
    (context.relationalValueTargets world)
    (originalState.registers.get claim.relation.original)
    (candidateState.registers.get claim.relation.candidate) = true at relationHolds
  rw [originalExpressionExact, candidateExpressionExact]
  rcases supported with relationExact | ⟨relationRelated, offsetZero⟩
  · rw [relationExact] at relationHolds
    simp only [RegisterValueRelation.holds, beq_iff_eq] at relationHolds
    simp only [registerArgumentExpression, evalInputRegisterOffset]
    rw [relationHolds]
    exact wordRelated_self _ _ _ _ _
  · rw [relationRelated] at relationHolds
    simp only [RegisterValueRelation.holds] at relationHolds
    simpa [registerArgumentExpression, evalInputRegisterOffset, offsetZero] using
      relationHolds

theorem StateRel.ordinaryMemoryRelation
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
  ordinaryMemoryRelated context world context.codeMap.entries.toList
      (context.relationalValueTargets world) original.memory candidate.memory := by
  rcases related with ⟨_, _, _, _, _, _, _, _, core, _⟩
  exact core.2.2.2.2.1

theorem StateRel.dynamicRangesMemoryHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    DynamicRangesMemoryHold context world original.memory candidate.memory := by
  rcases related with ⟨_, _, _, _, _, _, _, _, core, _⟩
  exact core.2.2.2.2.2.1.1

theorem StateRel.staticDynamicPointerSlotsMemoryHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    StaticDynamicPointerSlotsMemoryHold context world
      original.memory candidate.memory := by
  rcases related with ⟨_, _, _, _, _, _, _, _, core, _⟩
  exact core.2.2.2.2.2.1.2

theorem StateRel.stackMemoryRead32Related
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (window : StackWindowPair) (offset : Nat)
    (related : StateRel context world invariant original candidate)
    (windowMember : window ∈ invariant.stackWindows)
    (inside : offset + 4 <= window.bytesAbove) (aligned : offset % 4 = 0) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (Memory.read32 original.memory
        (original.registers.get window.originalRegister + BitVec.ofNat 32 offset))
      (Memory.read32 candidate.memory
        (candidate.registers.get window.candidateRegister + BitVec.ofNat 32 offset)) = true := by
  rcases related with
    ⟨_, rangesValid, stackMemory, _, _, _, _, _, relatedCore, _⟩
  have windowsRelated := relatedCore.2.2.2.1
  simp only [stackWindowsRelated, List.all_eq_true] at windowsRelated
  exact stackMemoryRead32Related_of_window context world window original candidate offset
    rangesValid (windowsRelated window windowMember) stackMemory inside aligned

theorem registersRelatedValues_self_of_identity
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (pairs : List RegisterPair) (state : PureState)
    (identity : pairs.all (fun pair => pair.original == pair.candidate) = true) :
    registersRelatedValues originalImageBase candidateImageBase targets values
      pairs state state = true := by
  unfold registersRelatedValues at ⊢
  simp only [List.all_eq_true] at identity ⊢
  intro pair member
  have sameRegister := identity pair member
  simp only [beq_iff_eq] at sameRegister
  rw [sameRegister]
  apply wordRelated_self

def statesRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair)
    (flagInputs : List Nat)
    (bounds : List RegisterBoundPair) (separations : List AddressSeparationPair)
    (values : List ValueTargetPair)
    (pairs : List RegisterPair)
    (original candidate : MachineState) : Prop :=
  StateRelCore originalImageBase candidateImageBase targets values {
    registerRelations := exactRegisterRelations pairs
    flagBits := flagInputs
    bounds
    addressSeparations := separations
  } original candidate

def composableStatesRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair)
    (flagInputs : List Nat)
    (bounds : List RegisterBoundPair) (separations : List AddressSeparationPair)
    (values : List ValueTargetPair)
    (relations : List RegisterRelationPair)
    (original candidate : MachineState) : Prop :=
  StateRelCore originalImageBase candidateImageBase targets values {
    registerRelations := relations
    flagBits := flagInputs
    bounds
    addressSeparations := separations
  } original candidate

theorem registersRelated_implies_registersRelatedValues
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (pairs : List RegisterPair) (original candidate : PureState)
    (related : registersRelated pairs original candidate = true) :
    registersRelatedValues originalImageBase candidateImageBase targets values pairs
      original candidate = true := by
  unfold registersRelated at related
  unfold registersRelatedValues
  simp only [List.all_eq_true] at related ⊢
  intro pair member
  have equal := related pair member
  simp only [beq_iff_eq] at equal
  rw [equal]
  apply wordRelated_self

theorem statesRelated_implies_composable
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (flagInputs : List Nat)
    (bounds : List RegisterBoundPair) (separations : List AddressSeparationPair)
    (values : List ValueTargetPair) (pairs : List RegisterPair)
    (original candidate : MachineState)
    (related : statesRelated originalImageBase candidateImageBase targets flagInputs bounds
      separations values pairs original candidate) :
    composableStatesRelated originalImageBase candidateImageBase targets flagInputs bounds
      separations values (exactRegisterRelations pairs) original candidate := by
  unfold statesRelated StateRelCore at related
  unfold composableStatesRelated StateRelCore
  rcases related with ⟨registers, rest⟩
  exact ⟨registers, rest⟩

structure RegionRelation where
  id : Nat
  original : Span
  candidate : Span
  root : Bool
  inputs : List RegisterPair
  outputs : List RegisterPair
  inputRelations : List RegisterRelationPair := []
  outputRelations : List RegisterRelationPair := []
  inputImportRelations : List ImportRegisterRelation := []
  outputImportRelations : List ImportRegisterRelation := []
  inputDynamicRangeRelations : List DynamicRegisterRangeRelation := []
  outputDynamicRangeRelations : List DynamicRegisterRangeRelation := []
  bounds : List RegisterBoundPair := []
  addressSeparations : List AddressSeparationPair := []
  stackWindows : List StackWindowPair := []
  targets : List CodeTargetPair
  values : List ValueTargetPair := []
  flagInputs : List Nat := [0, 2, 6, 7, 10, 11]
  flagOutputs : List Nat := [0, 2, 6, 7, 10, 11]
deriving Repr, DecidableEq

def RegionRelation.inputInvariant (region : RegionRelation) : StateInvariant := {
  registerRelations := region.inputRelations
  importRegisterRelations := region.inputImportRelations
  dynamicRegisterRangeRelations := region.inputDynamicRangeRelations
  flagBits := region.flagInputs
  bounds := region.bounds
  addressSeparations := region.addressSeparations
  stackWindows := region.stackWindows
}

def RegionRelation.outputInvariant (region : RegionRelation) : StateInvariant := {
  registerRelations := region.outputRelations
  importRegisterRelations := region.outputImportRelations
  dynamicRegisterRangeRelations := region.outputDynamicRangeRelations
  flagBits := region.flagOutputs
}

def RegionInputStateRel (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation) (original candidate : MachineState) : Prop :=
  StateRel context world region.inputInvariant original candidate

def RegionOutputStateRel (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation) (original candidate : MachineState) : Prop :=
  StateRel context world region.outputInvariant original candidate

def regionById (regions : List RegionRelation) (id : Nat) : Option RegionRelation :=
  regions.find? fun region => region.id == id

def allCodeTargets (regions : List RegionRelation) : List CodeTargetPair :=
  regions.flatMap (·.targets)

def allValueTargets (regions : List RegionRelation) : List ValueTargetPair :=
  regions.flatMap (·.values)

def regionUsesStaticContext (context : StaticProofContext)
    (region : RegionRelation) : Bool :=
  region.targets.all (fun target => context.codeMap.get? target.id == some target) &&
    region.values.all (fun value => context.dataMap.get? value.id == some value)

def regionsUseStaticContext (context : StaticProofContext)
    (regions : List RegionRelation) : Bool :=
  regions.all (regionUsesStaticContext context)

def RegionsUseStaticContext (context : StaticProofContext)
    (regions : List RegionRelation) : Prop :=
  regionsUseStaticContext context regions = true

theorem regionsUseStaticContext_of_checked (context : StaticProofContext)
    (regions : List RegionRelation)
    (checked : regionsUseStaticContext context regions = true) :
    RegionsUseStaticContext context regions :=
  checked

def MemoryObservationTransitionClosed
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source : RegionRelation)
    (requirements : List MemoryObservationRequirement)
    (x87Requirements : List X87MemoryObservationRequirement)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Prop :=
  ∀ originalState candidateState,
    composableStatesRelated originalImageBase candidateImageBase targets
      source.flagInputs source.bounds source.addressSeparations values source.inputRelations
      originalState candidateState →
    memoryObservationContractHolds originalImageBase candidateImageBase targets
      values requirements
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true ∧
    x87MemoryObservationContractHolds x87Requirements
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true

def resolveMappedCodeTarget (candidate : Bool) (imageBase : Nat)
    (targets : List CodeTargetPair) (address : Word) : Option Nat :=
  (targets.find? fun target =>
    if candidate then
      codeAddressMatches imageBase target.candidateRva target.candidateAliases address
    else
      codeAddressMatches imageBase target.originalRva target.originalAliases address).map (·.id)

def decodedRegionBehavior (candidate : Bool) (pe : PE32) (imports : List PEImport)
    (regions : List RegionRelation) (id : Nat) (state : MachineState) :
    Option RelationalBehavior := do
  let region ← regionById regions id
  let span := if candidate then region.candidate else region.original
  let symbolic ← regionBehaviorWithImports pe imports span
  evalBehavior candidate region.targets state symbolic

def regionEquivalent (originalPe candidatePe : PE32) (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated originalPe.imageBase candidatePe.imageBase region.targets region.flagInputs
      region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
    match (regionBehavior originalPe region.original).bind
          (evalBehavior false region.targets originalState),
        (regionBehavior candidatePe region.candidate).bind
          (evalBehavior true region.targets candidateState) with
    | some originalBehavior, some candidateBehavior =>
        registersRelatedValues originalPe.imageBase candidatePe.imageBase region.targets region.values
          region.outputs originalBehavior.registers candidateBehavior.registers = true ∧
        originalBehavior.x87 = candidateBehavior.x87 ∧
        writesRelated originalPe.imageBase candidatePe.imageBase region.targets region.values
          originalBehavior.writes candidateBehavior.writes = true ∧
        flagsRelated region.flagOutputs originalBehavior.eflags candidateBehavior.eflags = true ∧
        outcomesRelated originalPe.imageBase candidatePe.imageBase region.targets region.values
          originalBehavior.outcome candidateBehavior.outcome = true
    | _, _ => False

def regionEquivalentWithImports (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (machineCallContracts : List MachineImportCallContract)
    (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated originalPe.imageBase candidatePe.imageBase region.targets region.flagInputs
      region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
    match (regionBehaviorWithMachineCallContracts originalPe originalImports
            machineCallContracts region.original).bind
          (evalBehavior false region.targets originalState),
        (regionBehaviorWithMachineCallContracts candidatePe candidateImports
            machineCallContracts region.candidate).bind
          (evalBehavior true region.targets candidateState) with
    | some originalBehavior, some candidateBehavior =>
        registersRelatedValues originalPe.imageBase candidatePe.imageBase region.targets region.values
          region.outputs originalBehavior.registers candidateBehavior.registers = true ∧
        originalBehavior.x87 = candidateBehavior.x87 ∧
        writesRelated originalPe.imageBase candidatePe.imageBase region.targets region.values
          originalBehavior.writes candidateBehavior.writes = true ∧
        flagsRelated region.flagOutputs originalBehavior.eflags candidateBehavior.eflags = true ∧
        outcomesRelated originalPe.imageBase candidatePe.imageBase region.targets region.values
          originalBehavior.outcome candidateBehavior.outcome = true
    | _, _ => False

def behaviorsEquivalent (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated originalImageBase candidateImageBase region.targets region.flagInputs
      region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
    match evalBehavior false region.targets originalState originalBehavior,
        evalBehavior true region.targets candidateState candidateBehavior with
    | some originalResult, some candidateResult =>
        registersRelatedValues originalImageBase candidateImageBase region.targets region.values
          region.outputs originalResult.registers candidateResult.registers = true ∧
        originalResult.x87 = candidateResult.x87 ∧
        writesRelated originalImageBase candidateImageBase region.targets region.values
          originalResult.writes candidateResult.writes = true ∧
        flagsRelated region.flagOutputs originalResult.eflags candidateResult.eflags = true ∧
        outcomesRelated originalImageBase candidateImageBase region.targets region.values
          originalResult.outcome candidateResult.outcome = true
    | _, _ => False

def behaviorRegistersEquivalent (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior) (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated originalImageBase candidateImageBase region.targets region.flagInputs
      region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
    registersRelatedValues originalImageBase candidateImageBase region.targets region.values
      region.outputs (evalNormalizedRegisters originalState originalBehavior.registers)
      (evalNormalizedRegisters candidateState candidateBehavior.registers) = true

def behaviorX87Equivalent (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior) (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated originalImageBase candidateImageBase region.targets region.flagInputs
      region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
    evalNormalizedX87 originalState originalBehavior.x87 =
      evalNormalizedX87 candidateState candidateBehavior.x87

def behaviorWritesEquivalent (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior) (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated originalImageBase candidateImageBase region.targets region.flagInputs
      region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
    writesRelated originalImageBase candidateImageBase region.targets region.values
      (evalNormalizedWrites originalState originalBehavior.writes)
      (evalNormalizedWrites candidateState candidateBehavior.writes) = true

def behaviorFlagsEquivalent (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior) (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated originalImageBase candidateImageBase region.targets region.flagInputs
      region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
    flagsRelated region.flagOutputs
      (evalNormalizedFlags originalState originalBehavior.flags)
      (evalNormalizedFlags candidateState candidateBehavior.flags) = true

theorem evalNormalizedFlags_extract_df (state : MachineState)
    (flags : Option FlagsExpr) :
    (evalNormalizedFlags state flags).extractLsb' 10 1 =
      state.eflags.extractLsb' 10 1 := by
  cases flags <;> simp [evalNormalizedFlags]

theorem behaviorFlagsEquivalent_df
    (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (region : RegionRelation)
    (outputs : region.flagOutputs = [10])
    (input : region.flagInputs.contains 10 = true) :
    behaviorFlagsEquivalent originalImageBase candidateImageBase
      originalBehavior candidateBehavior region := by
  unfold behaviorFlagsEquivalent
  intro originalState candidateState related
  unfold statesRelated StateRelCore at related
  rcases related with ⟨_, _, _, _, _, _, flagsRelatedAll, _⟩
  rw [outputs]
  apply flagsRelated_cons_of_eq
  · rw [evalNormalizedFlags_extract_df, evalNormalizedFlags_extract_df]
    exact flagsRelated_of_contains region.flagInputs originalState.eflags
      candidateState.eflags flagsRelatedAll input
  · apply flagsRelated_nil

def behaviorOutcomeEquivalent (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior) (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated originalImageBase candidateImageBase region.targets region.flagInputs
      region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
    match evalBehaviorOutcome false region.targets originalState originalBehavior,
        evalBehaviorOutcome true region.targets candidateState candidateBehavior with
    | some originalResult, some candidateResult =>
      outcomesRelated originalImageBase candidateImageBase region.targets region.values
          originalResult candidateResult = true
    | _, _ => False

theorem behaviorsEquivalent_of_components
    (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior) (region : RegionRelation)
    (registers : behaviorRegistersEquivalent originalImageBase candidateImageBase
      originalBehavior candidateBehavior region)
    (x87 : behaviorX87Equivalent originalImageBase candidateImageBase
      originalBehavior candidateBehavior region)
    (writes : behaviorWritesEquivalent originalImageBase candidateImageBase
      originalBehavior candidateBehavior region)
    (flags : behaviorFlagsEquivalent originalImageBase candidateImageBase
      originalBehavior candidateBehavior region)
    (outcome : behaviorOutcomeEquivalent originalImageBase candidateImageBase
      originalBehavior candidateBehavior region) :
    behaviorsEquivalent originalImageBase candidateImageBase originalBehavior candidateBehavior region := by
  intro originalState candidateState related
  have registers := registers originalState candidateState related
  have x87 := x87 originalState candidateState related
  have writes := writes originalState candidateState related
  have flags := flags originalState candidateState related
  have outcome := outcome originalState candidateState related
  cases originalNormalized : normalizeSymbolicBehavior false region.targets originalBehavior with
  | none => simp [evalBehaviorOutcome, originalNormalized] at outcome
  | some original =>
    cases candidateNormalized : normalizeSymbolicBehavior true region.targets candidateBehavior with
    | none => simp [evalBehaviorOutcome, candidateNormalized] at outcome
    | some candidate =>
      have originalFields := normalizeSymbolicBehavior_fields false region.targets originalBehavior
        original originalNormalized
      have candidateFields := normalizeSymbolicBehavior_fields true region.targets candidateBehavior
        candidate candidateNormalized
      unfold evalBehavior
      rw [originalNormalized, candidateNormalized]
      exact ⟨by simpa [originalFields.1, candidateFields.1] using registers,
        by simpa [originalFields.2.1, candidateFields.2.1] using x87,
        by simpa [originalFields.2.2.1, candidateFields.2.2.1] using writes,
        by simpa [originalFields.2.2.2, candidateFields.2.2.2] using flags,
        by simpa [behaviorOutcomeEquivalent, evalBehaviorOutcome, originalNormalized,
          candidateNormalized] using outcome⟩

theorem behaviorsEquivalent_of_normalized_components
    (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (normalizedBehavior : NormalizedSymbolicBehavior) (region : RegionRelation)
    (originalNormalized : normalizeSymbolicBehavior false region.targets originalBehavior =
      some normalizedBehavior)
    (candidateNormalized : normalizeSymbolicBehavior true region.targets candidateBehavior =
      some normalizedBehavior)
    (registers : ∀ originalState candidateState,
      statesRelated originalImageBase candidateImageBase region.targets region.flagInputs
        region.bounds region.addressSeparations region.values region.inputs
        originalState candidateState →
      registersRelatedValues originalImageBase candidateImageBase region.targets region.values
        region.outputs (normalizedBehavior.eval originalState).registers
        (normalizedBehavior.eval candidateState).registers = true)
    (x87 : ∀ originalState candidateState,
      statesRelated originalImageBase candidateImageBase region.targets region.flagInputs
        region.bounds region.addressSeparations region.values region.inputs
        originalState candidateState →
      (normalizedBehavior.eval originalState).x87 =
        (normalizedBehavior.eval candidateState).x87)
    (writes : ∀ originalState candidateState,
      statesRelated originalImageBase candidateImageBase region.targets region.flagInputs
        region.bounds region.addressSeparations region.values region.inputs
        originalState candidateState →
      writesRelated originalImageBase candidateImageBase region.targets region.values
        (normalizedBehavior.eval originalState).writes
        (normalizedBehavior.eval candidateState).writes = true)
    (flags : ∀ originalState candidateState,
      statesRelated originalImageBase candidateImageBase region.targets region.flagInputs
        region.bounds region.addressSeparations region.values region.inputs
        originalState candidateState →
      StageA.Relational.flagsRelated region.flagOutputs
        (normalizedBehavior.eval originalState).eflags
        (normalizedBehavior.eval candidateState).eflags = true)
    (outcome : ∀ originalState candidateState,
      statesRelated originalImageBase candidateImageBase region.targets region.flagInputs
        region.bounds region.addressSeparations region.values region.inputs
        originalState candidateState →
      outcomesRelated originalImageBase candidateImageBase region.targets region.values
        (normalizedBehavior.eval originalState).outcome
        (normalizedBehavior.eval candidateState).outcome = true) :
    behaviorsEquivalent originalImageBase candidateImageBase originalBehavior candidateBehavior region := by
  intro originalState candidateState related
  unfold evalBehavior
  rw [originalNormalized, candidateNormalized]
  exact ⟨registers originalState candidateState related,
    x87 originalState candidateState related,
    writes originalState candidateState related,
    flags originalState candidateState related,
    outcome originalState candidateState related⟩

theorem regionEquivalentWithImports_of_decoded (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (machineCallContracts : List MachineImportCallContract) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalDecoded : regionBehaviorWithMachineCallContracts originalPe originalImports
      machineCallContracts region.original = some originalBehavior)
    (candidateDecoded : regionBehaviorWithMachineCallContracts candidatePe candidateImports
      machineCallContracts region.candidate = some candidateBehavior)
    (equivalent : behaviorsEquivalent originalPe.imageBase candidatePe.imageBase
      originalBehavior candidateBehavior region) :
    regionEquivalentWithImports originalPe candidatePe originalImports candidateImports
      machineCallContracts region := by
  intro originalState candidateState related
  rw [originalDecoded, candidateDecoded]
  exact equivalent originalState candidateState related

inductive Observable where
  | external (imported : ExternalTarget)
  | returned
  | fault
deriving Repr, DecidableEq

inductive RelationalObservable where
  | external (imported : ExternalTarget) (arguments : List Word)
  | returned
  | fault
deriving Repr, DecidableEq

def PureOutcome.observation : PureOutcome -> Option Observable
  | .externalCall imported _ _ => some (.external imported)
  | .externalJump imported _ => some (.external imported)
  | .returned _ => some .returned
  | .checkedContinue false _ => some .fault
  | _ => none

def PureOutcome.nextLogicalTarget : PureOutcome -> Option Nat
  | .jump target => some target
  | .branch condition taken fallthrough => some (if condition then taken else fallthrough)
  | .call target _ => some target
  | .externalCall _ _ continuation => some continuation
  | .bulkCopy _ _ _ _ continuation => some continuation
  | .checkedContinue true continuation => some continuation
  | .atomicCompareExchange _ _ _ continuation => some continuation
  | _ => none

def stateInvariantsHold (predicates : List BoolExpr) (state : MachineState) : Bool :=
  predicates.all fun predicate => predicate.eval state

def NormalizedInvariantEdgeClosed
    (behavior : NormalizedSymbolicBehavior)
    (sourceInvariant targetInvariant : List BoolExpr) (target : Nat) : Prop :=
  ∀ state,
    stateInvariantsHold sourceInvariant state = true →
    (behavior.eval state).outcome.nextLogicalTarget = some target →
    stateInvariantsHold targetInvariant
      ((behavior.eval state).nextMachineState state) = true

def AllInvariantClaims : List Prop → Prop
  | [] => True
  | claim :: claims => claim ∧ AllInvariantClaims claims

structure InvariantTargetSpec where
  target : Nat
  predicate : BoolExpr
deriving Repr, DecidableEq

structure InvariantEdgeSpec where
  sourceIndex : Nat
  target : Nat
  predicate : BoolExpr
deriving Repr, DecidableEq

def NormalizedOutcomeExpr.staticTargets : NormalizedOutcomeExpr → List Nat
  | .jump target | .call target _ => [target]
  | .branch _ taken fallthrough =>
      if taken == fallthrough then [taken] else [taken, fallthrough]
  | .externalCall _ _ continuation | .bulkCopy _ _ _ _ continuation |
      .checkedContinue _ continuation | .atomicCompareExchange _ _ _ continuation =>
      [continuation]
  | .returned _ | .externalJump _ _ | .indirectCall _ _ | .indirectJump _ => []

def expectedInvariantEdgesForSource (sourceIndex : Nat)
    (outcome : NormalizedOutcomeExpr) (targets : List InvariantTargetSpec) :
    List InvariantEdgeSpec :=
  targets.filterMap fun target =>
    if outcome.staticTargets.contains target.target then
      some { sourceIndex, target := target.target, predicate := target.predicate }
    else
      none

def expectedInvariantEdges (sources : List (Nat × NormalizedOutcomeExpr))
    (targets : List InvariantTargetSpec) : List InvariantEdgeSpec :=
  sources.flatMap fun source => expectedInvariantEdgesForSource source.1 source.2 targets

def invariantEdgeInventoryClosed (sources : List (Nat × NormalizedOutcomeExpr))
    (targets : List InvariantTargetSpec) (claimed : List InvariantEdgeSpec) : Bool :=
  let expected := expectedInvariantEdges sources targets
  expected.all claimed.contains && claimed.all expected.contains

namespace InvariantWP

def trueExpr : BoolExpr := .equal (.constant 0) (.constant 0)

def _root_.StageA.Formal.BoolExpr.negateNormalized : BoolExpr → BoolExpr
  | .not value => value
  | value => .not value

@[simp] theorem BoolExpr.eval_negateNormalized (state : MachineState)
    (predicate : BoolExpr) :
    predicate.negateNormalized.eval state = !predicate.eval state := by
  cases predicate <;> simp [BoolExpr.negateNormalized, BoolExpr.eval]

def _root_.StageA.Formal.Expr.pureInvariant : Expr → Bool
  | .inputReg _ | .inputFsBase | .constant _ | .undefined _ => true
  | .add left right | .sub left right | .bitAnd left right | .bitXor left right |
      .shiftLeftBy left right | .shiftRightBy left right |
      .shiftArithmeticRightBy left right | .bitOr left right |
      .unsignedLessValue left right | .multiply left right |
      .multiplyHighUnsigned left right | .multiplyHighSigned left right =>
      left.pureInvariant && right.pureInvariant
  | .bitNot value | .extractByte value _ | .shiftLeft value _ | .shiftRight value _ |
      .bitValue value _ | .lowestSetBit value | .highestSetBit value =>
      value.pureInvariant
  | .ifEqual left right thenValue elseValue =>
      left.pureInvariant && right.pureInvariant && thenValue.pureInvariant &&
        elseValue.pureInvariant
  | .divideQuotient high low divisor | .divideRemainder high low divisor |
      .divisionValidValue high low divisor =>
      high.pureInvariant && low.pureInvariant && divisor.pureInvariant
  | .inputFlagValue _ | .inputX87Control | .inputX87Status | .read8 _ | .read32 _ |
      .read8AfterWrite _ _ _ _ | .x87Part _ _ | .x87CompareBit _ _ _ _ |
      .x87ExamineStatus _ _ => false

def _root_.StageA.Formal.Expr.exactInputs
    (relations : List RegisterRelationPair) : Expr → Bool
  | .inputReg register => exactIdentityRegister relations register
  | .inputFsBase | .constant _ | .undefined _ => true
  | .add left right | .sub left right | .bitAnd left right | .bitXor left right |
      .shiftLeftBy left right | .shiftRightBy left right |
      .shiftArithmeticRightBy left right | .bitOr left right |
      .unsignedLessValue left right | .multiply left right |
      .multiplyHighUnsigned left right | .multiplyHighSigned left right =>
      left.exactInputs relations && right.exactInputs relations
  | .bitNot value | .extractByte value _ | .shiftLeft value _ | .shiftRight value _ |
      .bitValue value _ | .lowestSetBit value | .highestSetBit value =>
      value.exactInputs relations
  | .ifEqual left right thenValue elseValue =>
      left.exactInputs relations && right.exactInputs relations &&
        thenValue.exactInputs relations && elseValue.exactInputs relations
  | .divideQuotient high low divisor | .divideRemainder high low divisor |
      .divisionValidValue high low divisor =>
      high.exactInputs relations && low.exactInputs relations &&
        divisor.exactInputs relations
  | .inputFlagValue _ | .inputX87Control | .inputX87Status | .read8 _ | .read32 _ |
      .read8AfterWrite _ _ _ _ | .x87Part _ _ | .x87CompareBit _ _ _ _ |
      .x87ExamineStatus _ _ => false

theorem _root_.StageA.Formal.Expr.eval_eq_of_exactInputs
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (relations : List RegisterRelationPair) (original candidate : MachineState)
    (expression : Expr)
    (registers : registerRelationsHold originalImageBase candidateImageBase targets values
      relations original.registers candidate.registers = true)
    (undefinedValue : original.undefinedValue = candidate.undefinedValue)
    (fsBase : original.fsBase = candidate.fsBase)
    (safe : expression.exactInputs relations = true) :
    expression.eval original = expression.eval candidate := by
  induction expression using Expr.rec (motive_2 := fun _ => True)
  case inputReg register =>
    exact registerRelationsHold_exact_identity originalImageBase candidateImageBase targets
      values relations original.registers candidate.registers register registers safe
  case inputFsBase => exact fsBase
  case undefined slot => simpa [Expr.eval] using congrFun undefinedValue slot
  case constant value => rfl
  case add left right leftSound rightSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case sub left right leftSound rightSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case bitAnd left right leftSound rightSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case bitXor left right leftSound rightSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case bitNot value sound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, sound safe]
  case extractByte value index sound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, sound safe]
  case shiftLeft value amount sound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, sound safe]
  case shiftRight value amount sound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, sound safe]
  case shiftLeftBy value amount valueSound amountSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, valueSound safe.1, amountSound safe.2]
  case shiftRightBy value amount valueSound amountSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, valueSound safe.1, amountSound safe.2]
  case shiftArithmeticRightBy value amount valueSound amountSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, valueSound safe.1, amountSound safe.2]
  case bitOr left right leftSound rightSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case ifEqual left right thenValue elseValue leftSound rightSound thenSound elseSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, leftSound safe.1.1.1, rightSound safe.1.1.2,
      thenSound safe.1.2, elseSound safe.2]
  case unsignedLessValue left right leftSound rightSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case bitValue value index sound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, sound safe]
  case multiply left right leftSound rightSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case multiplyHighUnsigned left right leftSound rightSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case multiplyHighSigned left right leftSound rightSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case divideQuotient high low divisor highSound lowSound divisorSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, highSound safe.1.1, lowSound safe.1.2, divisorSound safe.2]
  case divideRemainder high low divisor highSound lowSound divisorSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, highSound safe.1.1, lowSound safe.1.2, divisorSound safe.2]
  case divisionValidValue high low divisor highSound lowSound divisorSound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, highSound safe.1.1, lowSound safe.1.2, divisorSound safe.2]
  case lowestSetBit value sound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, sound safe]
  case highestSetBit value sound =>
    simp [Expr.exactInputs] at safe
    simp [Expr.eval, sound safe]
  case inputFlagValue => simp [Expr.exactInputs] at safe
  case inputX87Control => simp [Expr.exactInputs] at safe
  case inputX87Status => simp [Expr.exactInputs] at safe
  case read8 => simp [Expr.exactInputs] at safe
  case read32 => simp [Expr.exactInputs] at safe
  case read8AfterWrite => simp [Expr.exactInputs] at safe
  case x87Part => simp [Expr.exactInputs] at safe
  case x87CompareBit => simp [Expr.exactInputs] at safe
  case x87ExamineStatus => simp [Expr.exactInputs] at safe
  all_goals trivial

def _root_.StageA.Formal.Expr.exactMemoryInputs
    (relations : List RegisterRelationPair) : Expr → Bool
  | .inputReg register => exactIdentityRegister relations register
  | .inputFsBase | .constant _ | .undefined _ => true
  | .add left right | .sub left right | .bitAnd left right | .bitXor left right |
      .shiftLeftBy left right | .shiftRightBy left right |
      .shiftArithmeticRightBy left right | .bitOr left right |
      .unsignedLessValue left right | .multiply left right |
      .multiplyHighUnsigned left right | .multiplyHighSigned left right =>
      left.exactMemoryInputs relations && right.exactMemoryInputs relations
  | .bitNot value | .read8 value | .read32 value | .extractByte value _ |
      .shiftLeft value _ | .shiftRight value _ | .bitValue value _ |
      .lowestSetBit value | .highestSetBit value =>
      value.exactMemoryInputs relations
  | .read8AfterWrite address writeAddress writeValue prior |
      .ifEqual address writeAddress writeValue prior =>
      address.exactMemoryInputs relations && writeAddress.exactMemoryInputs relations &&
        writeValue.exactMemoryInputs relations && prior.exactMemoryInputs relations
  | .divideQuotient high low divisor | .divideRemainder high low divisor |
      .divisionValidValue high low divisor =>
      high.exactMemoryInputs relations && low.exactMemoryInputs relations &&
        divisor.exactMemoryInputs relations
  | .inputFlagValue _ | .inputX87Control | .inputX87Status |
      .x87Part _ _ | .x87CompareBit _ _ _ _ | .x87ExamineStatus _ _ => false

theorem _root_.StageA.Formal.Expr.eval_eq_of_exactMemoryInputs
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (relations : List RegisterRelationPair) (original candidate : MachineState)
    (expression : Expr)
    (registers : registerRelationsHold originalImageBase candidateImageBase targets values
      relations original.registers candidate.registers = true)
    (memory : original.memory = candidate.memory)
    (undefinedValue : original.undefinedValue = candidate.undefinedValue)
    (fsBase : original.fsBase = candidate.fsBase)
    (safe : expression.exactMemoryInputs relations = true) :
    expression.eval original = expression.eval candidate := by
  induction expression using Expr.rec (motive_2 := fun _ => True)
  case inputReg register =>
    exact registerRelationsHold_exact_identity originalImageBase candidateImageBase targets
      values relations original.registers candidate.registers register registers safe
  case inputFsBase => exact fsBase
  case undefined slot => simpa [Expr.eval] using congrFun undefinedValue slot
  case constant => rfl
  case add left right leftSound rightSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case sub left right leftSound rightSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case bitAnd left right leftSound rightSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case bitXor left right leftSound rightSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case bitNot value sound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, sound safe]
  case read8 address sound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, sound safe, memory]
  case read32 address sound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, MachineState.read32, sound safe, memory]
  case read8AfterWrite address writeAddress writeValue prior addressSound
      writeAddressSound writeValueSound priorSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, addressSound safe.1.1.1, writeAddressSound safe.1.1.2,
      writeValueSound safe.1.2, priorSound safe.2]
  case extractByte value index sound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, sound safe]
  case shiftLeft value amount sound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, sound safe]
  case shiftRight value amount sound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, sound safe]
  case shiftLeftBy value amount valueSound amountSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, valueSound safe.1, amountSound safe.2]
  case shiftRightBy value amount valueSound amountSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, valueSound safe.1, amountSound safe.2]
  case shiftArithmeticRightBy value amount valueSound amountSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, valueSound safe.1, amountSound safe.2]
  case bitOr left right leftSound rightSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case ifEqual left right thenValue elseValue leftSound rightSound thenSound elseSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, leftSound safe.1.1.1, rightSound safe.1.1.2,
      thenSound safe.1.2, elseSound safe.2]
  case unsignedLessValue left right leftSound rightSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case bitValue value index sound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, sound safe]
  case multiply left right leftSound rightSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case multiplyHighUnsigned left right leftSound rightSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case multiplyHighSigned left right leftSound rightSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, leftSound safe.1, rightSound safe.2]
  case divideQuotient high low divisor highSound lowSound divisorSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, highSound safe.1.1, lowSound safe.1.2, divisorSound safe.2]
  case divideRemainder high low divisor highSound lowSound divisorSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, highSound safe.1.1, lowSound safe.1.2, divisorSound safe.2]
  case divisionValidValue high low divisor highSound lowSound divisorSound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, highSound safe.1.1, lowSound safe.1.2, divisorSound safe.2]
  case lowestSetBit value sound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, sound safe]
  case highestSetBit value sound =>
    simp [Expr.exactMemoryInputs] at safe
    simp [Expr.eval, sound safe]
  case inputFlagValue => simp [Expr.exactMemoryInputs] at safe
  case inputX87Control => simp [Expr.exactMemoryInputs] at safe
  case inputX87Status => simp [Expr.exactMemoryInputs] at safe
  case x87Part => simp [Expr.exactMemoryInputs] at safe
  case x87CompareBit => simp [Expr.exactMemoryInputs] at safe
  case x87ExamineStatus => simp [Expr.exactMemoryInputs] at safe
  all_goals trivial

def registerValueRelationAcceptsExact : RegisterValueRelation → Bool
  | .exact | .relatedWord => true
  | .codePointer | .dataPointer => false

structure ExactRegisterOutputClaim where
  output : RegisterRelationPair
  expression : Expr
deriving Repr, DecidableEq

def ExactRegisterOutputClaim.checked (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactRegisterOutputClaim) : Bool :=
  registerValueRelationAcceptsExact claim.output.relation &&
    originalBehavior.registers.get claim.output.original == claim.expression &&
    candidateBehavior.registers.get claim.output.candidate == claim.expression &&
    claim.expression.exactInputs region.inputRelations

def ExactRegisterOutputClaim.Holds
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactRegisterOutputClaim) : Prop :=
  ∀ originalState candidateState,
    composableStatesRelated originalImageBase candidateImageBase targets
      region.flagInputs region.bounds region.addressSeparations values
      region.inputRelations originalState candidateState →
    claim.output.relation.holds originalImageBase candidateImageBase targets values
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true

theorem ExactRegisterOutputClaim.holds_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactRegisterOutputClaim)
    (checked : claim.checked region originalBehavior candidateBehavior = true) :
    claim.Holds originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior := by
  rcases claim with ⟨output, expression⟩
  rcases output with ⟨originalRegister, candidateRegister, relation⟩
  simp only [ExactRegisterOutputClaim.checked] at checked
  simp only [Bool.and_eq_true] at checked
  have relationSupported := checked.1.1.1
  have originalChecked := checked.1.1.2
  have candidateChecked := checked.1.2
  have safe := checked.2
  have originalExpression := beq_iff_eq.mp originalChecked
  have candidateExpression := beq_iff_eq.mp candidateChecked
  intro originalState candidateState related
  rcases related with ⟨registers, _, _, _, undefinedValue, _, _, fsBase⟩
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [originalExpression, candidateExpression]
  have valuesEqual := Expr.eval_eq_of_exactInputs originalImageBase candidateImageBase targets
    values region.inputRelations originalState candidateState expression registers
    undefinedValue fsBase safe
  cases relation <;> simp [registerValueRelationAcceptsExact] at relationSupported
  case exact => simpa [RegisterValueRelation.holds] using valuesEqual
  case relatedWord =>
    rw [valuesEqual]
    exact wordRelated_self originalImageBase candidateImageBase targets values _

structure ExactMemoryRegisterOutputClaim where
  output : RegisterRelationPair
  expression : Expr
deriving Repr, DecidableEq

def ExactMemoryRegisterOutputClaim.checked (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactMemoryRegisterOutputClaim) : Bool :=
  values == [] &&
    claim.output.relation == .exact &&
    originalBehavior.registers.get claim.output.original == claim.expression &&
    candidateBehavior.registers.get claim.output.candidate == claim.expression &&
    claim.expression.exactMemoryInputs region.inputRelations

def ExactMemoryRegisterOutputClaim.Holds
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactMemoryRegisterOutputClaim) : Prop :=
  ∀ originalState candidateState,
    composableStatesRelated originalImageBase candidateImageBase targets
      region.flagInputs region.bounds region.addressSeparations values
      region.inputRelations originalState candidateState →
    claim.output.relation.holds originalImageBase candidateImageBase targets values
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true

theorem ExactMemoryRegisterOutputClaim.holds_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactMemoryRegisterOutputClaim)
    (checked : claim.checked values region originalBehavior candidateBehavior = true) :
    claim.Holds originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior := by
  rcases claim with ⟨output, expression⟩
  rcases output with ⟨originalRegister, candidateRegister, relation⟩
  simp only [ExactMemoryRegisterOutputClaim.checked, Bool.and_eq_true] at checked
  have valuesChecked := checked.1.1.1.1
  have relationChecked := checked.1.1.1.2
  have originalChecked := checked.1.1.2
  have candidateChecked := checked.1.2
  have safe := checked.2
  have valuesEmpty := beq_iff_eq.mp valuesChecked
  have relationExact := beq_iff_eq.mp relationChecked
  have originalExpression := beq_iff_eq.mp originalChecked
  have candidateExpression := beq_iff_eq.mp candidateChecked
  intro originalState candidateState related
  rcases related with ⟨registers, _, _, memoryRelated, undefinedValue, _, _, fsBase⟩
  rw [valuesEmpty] at registers memoryRelated
  have memoryEqual := memoryRelated_without_values_eq originalImageBase candidateImageBase
    targets originalState.memory candidateState.memory memoryRelated
  have expressionEqual := Expr.eval_eq_of_exactMemoryInputs originalImageBase
    candidateImageBase targets [] region.inputRelations originalState candidateState
    expression registers memoryEqual undefinedValue fsBase safe
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [relationExact, originalExpression, candidateExpression]
  simpa [RegisterValueRelation.holds] using expressionEqual

def AllExactRegisterOutputClaims
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) :
    List ExactRegisterOutputClaim → Prop
  | [] => True
  | claim :: tail =>
      claim.Holds originalImageBase candidateImageBase targets values region
          originalBehavior candidateBehavior ∧
        AllExactRegisterOutputClaims originalImageBase candidateImageBase targets values region
          originalBehavior candidateBehavior tail

theorem allExactRegisterOutputClaims_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List ExactRegisterOutputClaim)
    (checked : claims.all (ExactRegisterOutputClaim.checked region
      originalBehavior candidateBehavior) = true) :
    AllExactRegisterOutputClaims originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior claims := by
  induction claims with
  | nil => trivial
  | cons claim tail ih =>
      simp only [List.all_cons, Bool.and_eq_true] at checked
      exact ⟨claim.holds_of_checked originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior checked.1, ih checked.2⟩

theorem registerRelationsHold_of_exact_output_claims
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List ExactRegisterOutputClaim)
    (checked : claims.all (ExactRegisterOutputClaim.checked region
      originalBehavior candidateBehavior) = true) :
    ∀ originalState candidateState,
      composableStatesRelated originalImageBase candidateImageBase targets
        region.flagInputs region.bounds region.addressSeparations values
        region.inputRelations originalState candidateState →
      registerRelationsHold originalImageBase candidateImageBase targets values
        (claims.map (fun claim => claim.output))
        (originalBehavior.eval originalState).registers
        (candidateBehavior.eval candidateState).registers = true := by
  intro originalState candidateState related
  induction claims with
  | nil => rfl
  | cons claim tail ih =>
      simp only [List.all_cons, Bool.and_eq_true] at checked
      unfold registerRelationsHold
      simp only [List.map_cons, List.all_cons, Bool.and_eq_true]
      exact ⟨claim.holds_of_checked originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior checked.1 originalState candidateState related,
        ih checked.2⟩

def ExactRegisterTransferClosed
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Prop :=
  ∀ originalState candidateState,
    composableStatesRelated originalImageBase candidateImageBase targets
      region.flagInputs region.bounds region.addressSeparations values
      region.inputRelations originalState candidateState →
    registerRelationsHold originalImageBase candidateImageBase targets values
      region.outputRelations
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true

theorem exactRegisterTransferClosed_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List ExactRegisterOutputClaim)
    (inventory : claims.map (fun claim => claim.output) = region.outputRelations)
    (checked : claims.all (ExactRegisterOutputClaim.checked region
      originalBehavior candidateBehavior) = true) :
    ExactRegisterTransferClosed originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior := by
  intro originalState candidateState related
  rw [← inventory]
  exact registerRelationsHold_of_exact_output_claims originalImageBase candidateImageBase
    targets values region originalBehavior candidateBehavior claims checked
    originalState candidateState related

structure IdentityRegisterOutputClaim where
  input : RegisterRelationPair
  output : RegisterRelationPair
deriving Repr, DecidableEq

def IdentityRegisterOutputClaim.checked (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : IdentityRegisterOutputClaim) : Bool :=
  region.inputRelations.contains claim.input &&
    claim.output.relation == claim.input.relation &&
    originalBehavior.registers.get claim.output.original == .inputReg claim.input.original &&
    candidateBehavior.registers.get claim.output.candidate == .inputReg claim.input.candidate

def IdentityRegisterOutputClaim.Holds
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : IdentityRegisterOutputClaim) : Prop :=
  ∀ originalState candidateState,
    composableStatesRelated originalImageBase candidateImageBase targets
      region.flagInputs region.bounds region.addressSeparations values
      region.inputRelations originalState candidateState →
    claim.output.relation.holds originalImageBase candidateImageBase targets values
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true

theorem IdentityRegisterOutputClaim.holds_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : IdentityRegisterOutputClaim)
    (checked : claim.checked region originalBehavior candidateBehavior = true) :
    claim.Holds originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior := by
  rcases claim with ⟨input, output⟩
  rcases input with ⟨inputOriginal, inputCandidate, inputRelation⟩
  rcases output with ⟨outputOriginal, outputCandidate, outputRelation⟩
  simp only [IdentityRegisterOutputClaim.checked, Bool.and_eq_true] at checked
  have inputMember := checked.1.1.1
  have relationChecked := checked.1.1.2
  have originalChecked := checked.1.2
  have candidateChecked := checked.2
  have relationEqual := beq_iff_eq.mp relationChecked
  have originalExpression := beq_iff_eq.mp originalChecked
  have candidateExpression := beq_iff_eq.mp candidateChecked
  intro originalState candidateState related
  have inputRelations := related.1
  simp only [registerRelationsHold, List.all_eq_true] at inputRelations
  have inputMember' :
      { original := inputOriginal, candidate := inputCandidate, relation := inputRelation } ∈
        region.inputRelations := by
    simpa using inputMember
  have inputRelated := inputRelations
    { original := inputOriginal, candidate := inputCandidate, relation := inputRelation }
    inputMember'
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [relationEqual, originalExpression, candidateExpression]
  simpa [Expr.eval] using inputRelated

structure ConstantRegisterOutputClaim where
  output : RegisterRelationPair
  originalValue : Nat
  candidateValue : Nat
deriving Repr, DecidableEq

def ConstantRegisterOutputClaim.checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ConstantRegisterOutputClaim) : Bool :=
  originalBehavior.registers.get claim.output.original == .constant claim.originalValue &&
    candidateBehavior.registers.get claim.output.candidate == .constant claim.candidateValue &&
    claim.output.relation.holds originalImageBase candidateImageBase targets values
      (BitVec.ofNat 32 claim.originalValue) (BitVec.ofNat 32 claim.candidateValue)

def ConstantRegisterOutputClaim.Holds
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ConstantRegisterOutputClaim) : Prop :=
  ∀ originalState candidateState,
    composableStatesRelated originalImageBase candidateImageBase targets
      region.flagInputs region.bounds region.addressSeparations values
      region.inputRelations originalState candidateState →
    claim.output.relation.holds originalImageBase candidateImageBase targets values
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true

theorem ConstantRegisterOutputClaim.holds_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ConstantRegisterOutputClaim)
    (checked : claim.checked originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior = true) :
    claim.Holds originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior := by
  rcases claim with ⟨output, originalValue, candidateValue⟩
  rcases output with ⟨outputOriginal, outputCandidate, outputRelation⟩
  simp only [ConstantRegisterOutputClaim.checked, Bool.and_eq_true] at checked
  have originalExpression := beq_iff_eq.mp checked.1.1
  have candidateExpression := beq_iff_eq.mp checked.1.2
  have valuesRelated := checked.2
  intro originalState candidateState _
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [originalExpression, candidateExpression]
  simpa [Expr.eval] using valuesRelated

def registerValueRelationAcceptsEqual : RegisterValueRelation → Bool
  | .exact | .relatedWord => true
  | .codePointer | .dataPointer => false

theorem RegisterValueRelation.holds_of_eq
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (relation : RegisterValueRelation) (original candidate : Word)
    (accepted : registerValueRelationAcceptsEqual relation = true)
    (equal : original = candidate) :
    relation.holds originalImageBase candidateImageBase targets values
      original candidate = true := by
  subst candidate
  cases relation <;> simp_all [registerValueRelationAcceptsEqual,
    RegisterValueRelation.holds, wordRelated_self]

structure StackRead32SubRegisterOutputClaim where
  output : RegisterRelationPair
  window : StackWindowPair
  offset : Nat
  subtract : Nat
deriving Repr, DecidableEq

def StackRead32SubRegisterOutputClaim.originalExpression
    (claim : StackRead32SubRegisterOutputClaim) : Expr :=
  .sub (.read32 (.add (.inputReg claim.window.originalRegister)
    (.constant claim.offset))) (.constant claim.subtract)

def StackRead32SubRegisterOutputClaim.candidateExpression
    (claim : StackRead32SubRegisterOutputClaim) : Expr :=
  .sub (.read32 (.add (.inputReg claim.window.candidateRegister)
    (.constant claim.offset))) (.constant claim.subtract)

def StackRead32SubRegisterOutputClaim.checked (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackRead32SubRegisterOutputClaim) : Bool :=
  claim.output.relation == .relatedWord && claim.subtract == 0 &&
    region.stackWindows.contains claim.window &&
    decide (claim.offset + 4 <= claim.window.bytesAbove) &&
    claim.offset % 4 == 0 &&
    originalBehavior.registers.get claim.output.original == claim.originalExpression &&
    candidateBehavior.registers.get claim.output.candidate == claim.candidateExpression

theorem StackRead32SubRegisterOutputClaim.holds_output_of_stateRel
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackRead32SubRegisterOutputClaim)
    (checked : claim.checked region originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    claim.output.relation.holds context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  simp only [StackRead32SubRegisterOutputClaim.checked, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨relationKind, subtractZero⟩, windowMember⟩, inside⟩,
      aligned⟩, originalChecked⟩, candidateChecked⟩
  have originalExpression := beq_iff_eq.mp originalChecked
  have candidateExpression := beq_iff_eq.mp candidateChecked
  have windowMember' : claim.window ∈ region.inputInvariant.stackWindows := by
    simpa [RegionRelation.inputInvariant] using windowMember
  have readRelated := StateRel.stackMemoryRead32Related context world
    region.inputInvariant originalState candidateState claim.window claim.offset related
    windowMember' inside (by simpa using aligned)
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [originalExpression, candidateExpression]
  simp only [StackRead32SubRegisterOutputClaim.originalExpression,
    StackRead32SubRegisterOutputClaim.candidateExpression, Expr.eval,
    machineStateRead32_eq_memoryRead32]
  have relationKind' := beq_iff_eq.mp relationKind
  have subtractZero' := beq_iff_eq.mp subtractZero
  rw [relationKind', subtractZero']
  simpa [RegisterValueRelation.holds] using readRelated

inductive RegisterOutputClaim where
  | exactExpression (claim : ExactRegisterOutputClaim)
  | exactMemory (claim : ExactMemoryRegisterOutputClaim)
  | identity (claim : IdentityRegisterOutputClaim)
  | constant (claim : ConstantRegisterOutputClaim)
  | stackRead32Sub (claim : StackRead32SubRegisterOutputClaim)
deriving Repr, DecidableEq

def RegisterOutputClaim.output : RegisterOutputClaim → RegisterRelationPair
  | .exactExpression claim => claim.output
  | .exactMemory claim => claim.output
  | .identity claim => claim.output
  | .constant claim => claim.output
  | .stackRead32Sub claim => claim.output

def RegisterOutputClaim.checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) :
    RegisterOutputClaim → Bool
  | .exactExpression claim => claim.checked region originalBehavior candidateBehavior
  | .exactMemory claim => claim.checked values region originalBehavior candidateBehavior
  | .identity claim => claim.checked region originalBehavior candidateBehavior
  | .constant claim => claim.checked originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior
  | .stackRead32Sub _ => false

def RegisterOutputClaim.Holds
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) :
    RegisterOutputClaim → Prop
  | .exactExpression claim =>
      claim.Holds originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior
  | .exactMemory claim =>
      claim.Holds originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior
  | .identity claim =>
      claim.Holds originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior
  | .constant claim =>
      claim.Holds originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior
  | .stackRead32Sub _ => False

theorem RegisterOutputClaim.holds_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : RegisterOutputClaim)
    (checked : claim.checked originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior = true) :
    claim.Holds originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior := by
  cases claim with
  | exactExpression claim =>
      exact claim.holds_of_checked originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior checked
  | exactMemory claim =>
      exact claim.holds_of_checked originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior checked
  | identity claim =>
      exact claim.holds_of_checked originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior checked
  | constant claim =>
      exact claim.holds_of_checked originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior checked
  | stackRead32Sub _ => simp [RegisterOutputClaim.checked] at checked

theorem RegisterOutputClaim.holds_output
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : RegisterOutputClaim)
    (holds : claim.Holds originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior)
    (originalState candidateState : MachineState)
    (related : composableStatesRelated originalImageBase candidateImageBase targets
      region.flagInputs region.bounds region.addressSeparations values
      region.inputRelations originalState candidateState) :
    claim.output.relation.holds originalImageBase candidateImageBase targets values
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  cases claim <;> try exact holds originalState candidateState related
  case stackRead32Sub => contradiction

def AllRegisterOutputClaims
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) :
    List RegisterOutputClaim → Prop
  | [] => True
  | claim :: tail =>
      claim.Holds originalImageBase candidateImageBase targets values region
          originalBehavior candidateBehavior ∧
        AllRegisterOutputClaims originalImageBase candidateImageBase targets values region
          originalBehavior candidateBehavior tail

theorem allRegisterOutputClaims_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List RegisterOutputClaim)
    (checked : claims.all (RegisterOutputClaim.checked originalImageBase candidateImageBase
      targets values region originalBehavior candidateBehavior) = true) :
    AllRegisterOutputClaims originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior claims := by
  induction claims with
  | nil => trivial
  | cons claim tail ih =>
      simp only [List.all_cons, Bool.and_eq_true] at checked
      exact ⟨claim.holds_of_checked originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior checked.1, ih checked.2⟩

def RegisterTransferClosed
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Prop :=
  ∀ originalState candidateState,
    composableStatesRelated originalImageBase candidateImageBase targets
      region.flagInputs region.bounds region.addressSeparations values
      region.inputRelations originalState candidateState →
    registerRelationsHold originalImageBase candidateImageBase targets values
      region.outputRelations
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true

theorem registerRelationsHold_of_output_claims
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List RegisterOutputClaim)
    (checked : claims.all (RegisterOutputClaim.checked originalImageBase candidateImageBase
      targets values region originalBehavior candidateBehavior) = true) :
    ∀ originalState candidateState,
      composableStatesRelated originalImageBase candidateImageBase targets
        region.flagInputs region.bounds region.addressSeparations values
        region.inputRelations originalState candidateState →
      registerRelationsHold originalImageBase candidateImageBase targets values
        (claims.map RegisterOutputClaim.output)
        (originalBehavior.eval originalState).registers
        (candidateBehavior.eval candidateState).registers = true := by
  intro originalState candidateState related
  induction claims with
  | nil => rfl
  | cons claim tail ih =>
      simp only [List.all_cons, Bool.and_eq_true] at checked
      unfold registerRelationsHold
      simp only [List.map_cons, List.all_cons, Bool.and_eq_true]
      have headHolds := claim.holds_of_checked originalImageBase candidateImageBase
        targets values region
        originalBehavior candidateBehavior checked.1
      exact ⟨claim.holds_output originalImageBase candidateImageBase targets values region
        originalBehavior candidateBehavior headHolds originalState candidateState related,
        ih checked.2⟩

theorem registerTransferClosed_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List RegisterOutputClaim)
    (inventory : claims.map RegisterOutputClaim.output = region.outputRelations)
    (checked : claims.all (RegisterOutputClaim.checked originalImageBase candidateImageBase
      targets values region originalBehavior candidateBehavior) = true) :
    RegisterTransferClosed originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior := by
  intro originalState candidateState related
  rw [← inventory]
  exact registerRelationsHold_of_output_claims originalImageBase candidateImageBase targets values
    region originalBehavior candidateBehavior claims checked originalState candidateState related

def RegisterOutputClaim.nonMemoryChecked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) :
    RegisterOutputClaim → Bool
  | .exactExpression claim => claim.checked region originalBehavior candidateBehavior
  | .exactMemory _ => false
  | .identity claim => claim.checked region originalBehavior candidateBehavior
  | .constant claim => claim.checked originalImageBase candidateImageBase targets values region
      originalBehavior candidateBehavior
  | .stackRead32Sub claim => claim.checked region originalBehavior candidateBehavior

theorem ExactRegisterOutputClaim.holds_output_of_stateRel
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactRegisterOutputClaim)
    (checked : claim.checked region originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    claim.output.relation.holds context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  rcases claim with ⟨output, expression⟩
  rcases output with ⟨originalRegister, candidateRegister, relation⟩
  simp only [ExactRegisterOutputClaim.checked, Bool.and_eq_true] at checked
  rcases checked with
    ⟨⟨⟨relationSupported, originalChecked⟩, candidateChecked⟩, safe⟩
  have originalExpression := beq_iff_eq.mp originalChecked
  have candidateExpression := beq_iff_eq.mp candidateChecked
  rcases related with
    ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
  rcases relatedCore with
    ⟨registers, _, _, _, _, _dynamicWords, undefinedValue, _, _, fsBase⟩
  simp only [RegionRelation.inputInvariant] at registers
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [originalExpression, candidateExpression]
  have valuesEqual := Expr.eval_eq_of_exactInputs context.originalPe.imageBase
    context.candidatePe.imageBase context.codeMap.entries.toList
    (context.relationalValueTargets world) region.inputRelations originalState candidateState
    expression registers undefinedValue fsBase safe
  cases relation <;> simp [registerValueRelationAcceptsExact] at relationSupported
  case exact => simpa [RegisterValueRelation.holds] using valuesEqual
  case relatedWord =>
    rw [valuesEqual]
    exact wordRelated_self context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world) _

theorem IdentityRegisterOutputClaim.holds_output_of_stateRel
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : IdentityRegisterOutputClaim)
    (checked : claim.checked region originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    claim.output.relation.holds context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  rcases claim with ⟨input, output⟩
  rcases input with ⟨inputOriginal, inputCandidate, inputRelation⟩
  rcases output with ⟨outputOriginal, outputCandidate, outputRelation⟩
  simp only [IdentityRegisterOutputClaim.checked, Bool.and_eq_true] at checked
  rcases checked with
    ⟨⟨⟨inputMember, relationChecked⟩, originalChecked⟩, candidateChecked⟩
  have relationEqual := beq_iff_eq.mp relationChecked
  have originalExpression := beq_iff_eq.mp originalChecked
  have candidateExpression := beq_iff_eq.mp candidateChecked
  rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
  have inputRelations := relatedCore.1
  simp only [RegionRelation.inputInvariant] at inputRelations
  simp only [registerRelationsHold, List.all_eq_true] at inputRelations
  have inputMember' :
      { original := inputOriginal, candidate := inputCandidate, relation := inputRelation } ∈
        region.inputRelations := by
    simpa using inputMember
  have inputRelated := inputRelations
    { original := inputOriginal, candidate := inputCandidate, relation := inputRelation }
    inputMember'
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [relationEqual, originalExpression, candidateExpression]
  simpa [Expr.eval] using inputRelated

theorem ConstantRegisterOutputClaim.holds_output_of_stateRel
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ConstantRegisterOutputClaim)
    (checked : claim.checked context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList context.dataMap.entries.toList region
      originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (_related : StateRel context world region.inputInvariant originalState candidateState) :
    claim.output.relation.holds context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  rcases claim with ⟨output, originalValue, candidateValue⟩
  rcases output with ⟨originalRegister, candidateRegister, outputRelation⟩
  simp only [ConstantRegisterOutputClaim.checked, Bool.and_eq_true] at checked
  rcases checked with ⟨⟨originalChecked, candidateChecked⟩, valuesRelated⟩
  have originalExpression := beq_iff_eq.mp originalChecked
  have candidateExpression := beq_iff_eq.mp candidateChecked
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [originalExpression, candidateExpression]
  apply RegisterValueRelation.holds_append_values
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList context.dataMap.entries.toList
    world.dynamicValueTargets outputRelation _ _
  simpa [Expr.eval] using valuesRelated

theorem registerRelationsHold_of_nonMemoryOutputClaims
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List RegisterOutputClaim)
    (checked : claims.all (RegisterOutputClaim.nonMemoryChecked
      context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList context.dataMap.entries.toList region
      originalBehavior candidateBehavior) = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    registerRelationsHold context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (claims.map RegisterOutputClaim.output)
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  induction claims with
  | nil => rfl
  | cons claim tail ih =>
      simp only [List.all_cons, Bool.and_eq_true] at checked
      unfold registerRelationsHold
      simp only [List.map_cons, List.all_cons, Bool.and_eq_true]
      cases claim with
      | exactExpression claim =>
          exact ⟨claim.holds_output_of_stateRel context world region originalBehavior
            candidateBehavior checked.1 originalState candidateState related,
            ih checked.2⟩
      | exactMemory claim =>
          simp [RegisterOutputClaim.nonMemoryChecked] at checked
      | identity claim =>
          exact ⟨claim.holds_output_of_stateRel context world region originalBehavior
            candidateBehavior checked.1 originalState candidateState related,
            ih checked.2⟩
      | constant claim =>
          exact ⟨claim.holds_output_of_stateRel context world region originalBehavior
            candidateBehavior checked.1 originalState candidateState related,
            ih checked.2⟩
      | stackRead32Sub claim =>
          exact ⟨claim.holds_output_of_stateRel context world region originalBehavior
            candidateBehavior checked.1 originalState candidateState related,
            ih checked.2⟩

theorem registerTransferUnderStateRel_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List RegisterOutputClaim)
    (inventory : claims.map RegisterOutputClaim.output = region.outputRelations)
    (checked : claims.all (RegisterOutputClaim.nonMemoryChecked
      context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList context.dataMap.entries.toList region
      originalBehavior candidateBehavior) = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    registerRelationsHold context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      region.outputRelations (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  rw [← inventory]
  exact registerRelationsHold_of_nonMemoryOutputClaims context world region
    originalBehavior candidateBehavior claims checked originalState candidateState related

def registerRelationListAllExact (relations : List RegisterRelationPair) : Bool :=
  relations.all fun relation => relation.relation == .exact

def _root_.StageA.Relational.NormalizedOutcomeExpr.registerRelationDirectTargets :
    NormalizedOutcomeExpr → List Nat
  | .jump target => [target]
  | .branch _ taken fallthrough => [taken, fallthrough]
  | .call target continuation => [target, continuation]
  | .externalCall _ _ continuation => [continuation]
  | .bulkCopy _ _ _ _ continuation => [continuation]
  | .indirectCall _ continuation => [continuation]
  | .checkedContinue _ continuation => [continuation]
  | .atomicCompareExchange _ _ _ continuation => [continuation]
  | .returned _ | .externalJump _ _ | .indirectJump _ => []

def _root_.StageA.Relational.NormalizedOutcomeExpr.externalContinuation :
    NormalizedOutcomeExpr → Option Nat
  | .externalCall _ _ continuation => some continuation
  | _ => none

def _root_.StageA.Relational.NormalizedOutcomeExpr.callTargetContinuation :
    NormalizedOutcomeExpr → Option (Nat × Nat)
  | .call target continuation => some (target, continuation)
  | _ => none

def _root_.StageA.Relational.NormalizedOutcomeExpr.isReturned :
    NormalizedOutcomeExpr → Bool
  | .returned _ => true
  | _ => false

def CallReturnEdgeShapeClosed (callee continuation : RegionRelation)
    (originalCaller candidateCaller originalReturn candidateReturn :
      NormalizedSymbolicBehavior) : Prop :=
  originalCaller.outcome.callTargetContinuation = some (callee.id, continuation.id) ∧
    candidateCaller.outcome.callTargetContinuation = some (callee.id, continuation.id) ∧
    originalReturn.outcome.isReturned = true ∧
    candidateReturn.outcome.isReturned = true

def callReturnEdgeShapeChecked (callee continuation : RegionRelation)
    (originalCaller candidateCaller originalReturn candidateReturn :
      NormalizedSymbolicBehavior) : Bool :=
  originalCaller.outcome.callTargetContinuation == some (callee.id, continuation.id) &&
    candidateCaller.outcome.callTargetContinuation == some (callee.id, continuation.id) &&
    originalReturn.outcome.isReturned && candidateReturn.outcome.isReturned

theorem callReturnEdgeShapeClosed_of_checked
    (callee continuation : RegionRelation)
    (originalCaller candidateCaller originalReturn candidateReturn :
      NormalizedSymbolicBehavior)
    (checked : callReturnEdgeShapeChecked callee continuation originalCaller
      candidateCaller originalReturn candidateReturn = true) :
    CallReturnEdgeShapeClosed callee continuation originalCaller candidateCaller
      originalReturn candidateReturn := by
  simp only [callReturnEdgeShapeChecked, Bool.and_eq_true, beq_iff_eq] at checked
  exact ⟨checked.1.1.1, checked.1.1.2, checked.1.2, checked.2⟩

def pe32ExternalRegisterPreserved : Reg → Bool
  | .ebx | .esi | .edi | .ebp | .esp => true
  | .eax | .ecx | .edx => false

def externalRegisterInputPolicyClosed (source : RegionRelation)
    (input : RegisterRelationPair) : Bool :=
  if pe32ExternalRegisterPreserved input.original &&
      pe32ExternalRegisterPreserved input.candidate then
    source.outputRelations.contains input
  else if !pe32ExternalRegisterPreserved input.original &&
      !pe32ExternalRegisterPreserved input.candidate then
    input.relation == .relatedWord
  else
    false

def externalRegisterPolicyClosed (source target : RegionRelation) : Bool :=
  target.inputRelations.all (externalRegisterInputPolicyClosed source)

def ExternalRegisterPolicyEdgeClosed (source target : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Prop :=
  originalBehavior.outcome.externalContinuation = some target.id ∧
    candidateBehavior.outcome.externalContinuation = some target.id ∧
    externalRegisterPolicyClosed source target = true

def externalRegisterPolicyEdgeChecked (source target : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  originalBehavior.outcome.externalContinuation == some target.id &&
    candidateBehavior.outcome.externalContinuation == some target.id &&
    externalRegisterPolicyClosed source target

theorem externalRegisterPolicyEdgeClosed_of_checked
    (source target : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (checked : externalRegisterPolicyEdgeChecked source target
      originalBehavior candidateBehavior = true) :
    ExternalRegisterPolicyEdgeClosed source target originalBehavior candidateBehavior := by
  simp only [externalRegisterPolicyEdgeChecked, Bool.and_eq_true, beq_iff_eq] at checked
  exact ⟨checked.1.1, checked.1.2, checked.2⟩

theorem registerRelationsHold_exact_change_context
    (sourceOriginalImageBase sourceCandidateImageBase : Nat)
    (sourceTargets : List CodeTargetPair) (sourceValues : List ValueTargetPair)
    (targetOriginalImageBase targetCandidateImageBase : Nat)
    (targetTargets : List CodeTargetPair) (targetValues : List ValueTargetPair)
    (relations : List RegisterRelationPair) (original candidate : PureState)
    (allExact : registerRelationListAllExact relations = true)
    (related : registerRelationsHold sourceOriginalImageBase sourceCandidateImageBase
      sourceTargets sourceValues relations original candidate = true) :
    registerRelationsHold targetOriginalImageBase targetCandidateImageBase targetTargets
      targetValues relations original candidate = true := by
  simp only [registerRelationListAllExact, registerRelationsHold,
    List.all_eq_true] at allExact related ⊢
  intro relation member
  have relationExact := allExact relation member
  have relationRelated := related relation member
  simp only [beq_iff_eq] at relationExact
  rw [relationExact] at relationRelated ⊢
  exact relationRelated

def ExactRegisterRelationEdgeClosed
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source target : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Prop :=
  originalBehavior.outcome.registerRelationDirectTargets.contains target.id = true ∧
    candidateBehavior.outcome.registerRelationDirectTargets.contains target.id = true ∧
    ∀ originalState candidateState,
      composableStatesRelated originalImageBase candidateImageBase targets
        source.flagInputs source.bounds source.addressSeparations values
        source.inputRelations originalState candidateState →
      registerRelationsHold originalImageBase candidateImageBase targets values
        target.inputRelations
        (originalBehavior.eval originalState).registers
        (candidateBehavior.eval candidateState).registers = true

theorem exactRegisterRelationEdgeClosed_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source target : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List ExactRegisterOutputClaim)
    (originalDirect :
      originalBehavior.outcome.registerRelationDirectTargets.contains target.id = true)
    (candidateDirect :
      candidateBehavior.outcome.registerRelationDirectTargets.contains target.id = true)
    (inventory : claims.map (fun claim => claim.output) = source.outputRelations)
    (composition : source.outputRelations = target.inputRelations)
    (targetExact : registerRelationListAllExact target.inputRelations = true)
    (checked : claims.all (ExactRegisterOutputClaim.checked source
      originalBehavior candidateBehavior) = true) :
    ExactRegisterRelationEdgeClosed originalImageBase candidateImageBase targets values source target
      originalBehavior candidateBehavior := by
  refine ⟨originalDirect, candidateDirect, ?_⟩
  intro originalState candidateState related
  have sourceRelated := exactRegisterTransferClosed_of_checked originalImageBase
    candidateImageBase targets values source originalBehavior candidateBehavior claims inventory checked
    originalState candidateState related
  rw [composition] at sourceRelated
  exact sourceRelated

structure ExactRegisterRelationPairEdgeClaim where
  sourceOutput : ExactRegisterOutputClaim
  targetInput : RegisterRelationPair
deriving Repr, DecidableEq

def ExactRegisterRelationPairEdgeClaim.checked
    (source target : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactRegisterRelationPairEdgeClaim) : Bool :=
  claim.sourceOutput.output.relation == .exact &&
    claim.sourceOutput.checked source originalBehavior candidateBehavior &&
    claim.sourceOutput.output.original == claim.targetInput.original &&
    claim.sourceOutput.output.candidate == claim.targetInput.candidate &&
    target.inputRelations.contains claim.targetInput &&
    registerValueRelationAcceptsExact claim.targetInput.relation

def ExactRegisterRelationPairEdgeClaim.Holds
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source target : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactRegisterRelationPairEdgeClaim) : Prop :=
  ∀ originalState candidateState,
    composableStatesRelated originalImageBase candidateImageBase targets
      source.flagInputs source.bounds source.addressSeparations values
      source.inputRelations originalState candidateState →
    claim.targetInput.relation.holds originalImageBase candidateImageBase
      targets values
      ((originalBehavior.eval originalState).registers.get claim.targetInput.original)
      ((candidateBehavior.eval candidateState).registers.get claim.targetInput.candidate) = true

theorem ExactRegisterRelationPairEdgeClaim.holds_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source target : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactRegisterRelationPairEdgeClaim)
    (checked : claim.checked source target originalBehavior candidateBehavior = true) :
    claim.Holds originalImageBase candidateImageBase targets values source target
      originalBehavior candidateBehavior := by
  rcases claim with ⟨sourceOutput, targetInput⟩
  rcases targetInput with ⟨targetOriginal, targetCandidate, targetKind⟩
  simp only [ExactRegisterRelationPairEdgeClaim.checked, Bool.and_eq_true] at checked
  have sourceExactChecked := checked.1.1.1.1.1
  have sourceChecked := checked.1.1.1.1.2
  have originalChecked := checked.1.1.1.2
  have candidateChecked := checked.1.1.2
  have targetSupported := checked.2
  have sourceExact := beq_iff_eq.mp sourceExactChecked
  have originalEqual := beq_iff_eq.mp originalChecked
  have candidateEqual := beq_iff_eq.mp candidateChecked
  have sourceHolds := ExactRegisterOutputClaim.holds_of_checked originalImageBase
    candidateImageBase targets values source originalBehavior candidateBehavior
    sourceOutput sourceChecked
  intro originalState candidateState related
  have valuesEqual := sourceHolds originalState candidateState related
  rw [sourceExact] at valuesEqual
  simp only [RegisterValueRelation.holds, beq_iff_eq] at valuesEqual
  rw [← originalEqual, ← candidateEqual]
  cases targetKind <;> simp [registerValueRelationAcceptsExact] at targetSupported
  case exact => simpa [RegisterValueRelation.holds] using valuesEqual
  case relatedWord =>
    rw [valuesEqual]
    exact wordRelated_self originalImageBase candidateImageBase targets values _

def ExactRegisterRelationPairEdgeClosed
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source target : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactRegisterRelationPairEdgeClaim) : Prop :=
  originalBehavior.outcome.registerRelationDirectTargets.contains target.id = true ∧
    candidateBehavior.outcome.registerRelationDirectTargets.contains target.id = true ∧
    claim.Holds originalImageBase candidateImageBase targets values source target
      originalBehavior candidateBehavior

theorem exactRegisterRelationPairEdgeClosed_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source target : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ExactRegisterRelationPairEdgeClaim)
    (originalDirect :
      originalBehavior.outcome.registerRelationDirectTargets.contains target.id = true)
    (candidateDirect :
      candidateBehavior.outcome.registerRelationDirectTargets.contains target.id = true)
    (checked : claim.checked source target originalBehavior candidateBehavior = true) :
    ExactRegisterRelationPairEdgeClosed originalImageBase candidateImageBase targets values
      source target
      originalBehavior candidateBehavior claim :=
  ⟨originalDirect, candidateDirect,
    claim.holds_of_checked originalImageBase candidateImageBase targets values source target
      originalBehavior candidateBehavior checked⟩

def _root_.StageA.Formal.BoolExpr.pureInvariant : BoolExpr → Bool
  | .equal left right | .unsignedLess left right =>
      left.pureInvariant && right.pureInvariant
  | .not value => value.pureInvariant
  | .and left right | .or left right | .xor left right =>
      left.pureInvariant && right.pureInvariant
  | .msb value | .bit value _ => value.pureInvariant
  | .inputFlag index => [0, 2, 6, 7, 10, 11].contains index
  | .divisionValid high low divisor =>
      high.pureInvariant && low.pureInvariant && divisor.pureInvariant

def _root_.StageA.Formal.Expr.substituteRegisters (registers : Registers Expr) : Expr → Expr
  | .inputReg register => registers.get register
  | .inputFlagValue bit => .inputFlagValue bit
  | .inputFsBase => .inputFsBase
  | .inputX87Control => .inputX87Control
  | .inputX87Status => .inputX87Status
  | .constant value => .constant value
  | .add left right => .add (left.substituteRegisters registers) (right.substituteRegisters registers)
  | .sub left right => .sub (left.substituteRegisters registers) (right.substituteRegisters registers)
  | .bitAnd left right =>
      .bitAnd (left.substituteRegisters registers) (right.substituteRegisters registers)
  | .bitXor left right =>
      .bitXor (left.substituteRegisters registers) (right.substituteRegisters registers)
  | .bitNot value => .bitNot (value.substituteRegisters registers)
  | .read8 address => .read8 (address.substituteRegisters registers)
  | .read32 address => .read32 (address.substituteRegisters registers)
  | .read8AfterWrite address writeAddress writeValue prior =>
      .read8AfterWrite (address.substituteRegisters registers)
        (writeAddress.substituteRegisters registers) (writeValue.substituteRegisters registers)
        (prior.substituteRegisters registers)
  | .extractByte value index => .extractByte (value.substituteRegisters registers) index
  | .shiftLeft value amount => .shiftLeft (value.substituteRegisters registers) amount
  | .shiftRight value amount => .shiftRight (value.substituteRegisters registers) amount
  | .shiftLeftBy value amount =>
      .shiftLeftBy (value.substituteRegisters registers) (amount.substituteRegisters registers)
  | .shiftRightBy value amount =>
      .shiftRightBy (value.substituteRegisters registers) (amount.substituteRegisters registers)
  | .shiftArithmeticRightBy value amount =>
      .shiftArithmeticRightBy (value.substituteRegisters registers)
        (amount.substituteRegisters registers)
  | .bitOr left right => .bitOr (left.substituteRegisters registers) (right.substituteRegisters registers)
  | .ifEqual left right thenValue elseValue =>
      .ifEqual (left.substituteRegisters registers) (right.substituteRegisters registers)
        (thenValue.substituteRegisters registers) (elseValue.substituteRegisters registers)
  | .unsignedLessValue left right =>
      .unsignedLessValue (left.substituteRegisters registers) (right.substituteRegisters registers)
  | .bitValue value index => .bitValue (value.substituteRegisters registers) index
  | .multiply left right =>
      .multiply (left.substituteRegisters registers) (right.substituteRegisters registers)
  | .multiplyHighUnsigned left right =>
      .multiplyHighUnsigned (left.substituteRegisters registers)
        (right.substituteRegisters registers)
  | .multiplyHighSigned left right =>
      .multiplyHighSigned (left.substituteRegisters registers)
        (right.substituteRegisters registers)
  | .divideQuotient high low divisor =>
      .divideQuotient (high.substituteRegisters registers) (low.substituteRegisters registers)
        (divisor.substituteRegisters registers)
  | .divideRemainder high low divisor =>
      .divideRemainder (high.substituteRegisters registers) (low.substituteRegisters registers)
        (divisor.substituteRegisters registers)
  | .divisionValidValue high low divisor =>
      .divisionValidValue (high.substituteRegisters registers) (low.substituteRegisters registers)
        (divisor.substituteRegisters registers)
  | .lowestSetBit value => .lowestSetBit (value.substituteRegisters registers)
  | .highestSetBit value => .highestSetBit (value.substituteRegisters registers)
  | .undefined slot => .undefined slot
  | .x87Part value part => .x87Part value part
  | .x87CompareBit left right control bit =>
      .x87CompareBit left right (control.substituteRegisters registers) bit
  | .x87ExamineStatus value status =>
      .x87ExamineStatus value (status.substituteRegisters registers)

def outputFlag (flags : Option FlagsExpr) (index : Nat) : BoolExpr :=
  match flags with
  | none => .inputFlag index
  | some value =>
      match index with
      | 0 => value.carry.getD (.inputFlag 0)
      | 2 => value.parity.getD (.inputFlag 2)
      | 6 => value.zero.getD (.inputFlag 6)
      | 7 => value.sign.getD (.inputFlag 7)
      | 11 => value.overflow.getD (.inputFlag 11)
      | other => .inputFlag other

theorem _root_.StageA.Formal.BoolExpr.eval_toWord
    (state : MachineState) (expression : BoolExpr) :
    expression.toWord.eval state =
      if expression.eval state then BitVec.ofNat 32 1 else BitVec.ofNat 32 0 := by
  induction expression <;> simp_all [BoolExpr.toWord, BoolExpr.eval, Expr.eval]
  case and left right leftSound rightSound =>
    cases leftValue : left.eval state <;> cases rightValue : right.eval state <;>
      simp_all
  case or left right leftSound rightSound =>
    cases leftValue : left.eval state <;> cases rightValue : right.eval state <;>
      simp_all
  case xor left right leftSound rightSound =>
    cases leftValue : left.eval state <;> cases rightValue : right.eval state <;>
      simp_all
  case divisionValid high low divisor =>
    split <;> simp_all

theorem outputFlag_eval (behavior : NormalizedSymbolicBehavior) (state : MachineState)
    (index : Nat) (safe : [0, 2, 6, 7, 10, 11].contains index = true) :
    (outputFlag behavior.flags index).eval state =
      BoolExpr.eval ((behavior.eval state).nextMachineState state) (.inputFlag index) := by
  simp only [BoolExpr.eval, RelationalBehavior.nextMachineState,
    NormalizedSymbolicBehavior.eval_eflags]
  rcases behavior with ⟨registers, x87, writes, flags, outcome⟩
  cases flags with
  | none => simp [outputFlag, evalNormalizedFlags, BoolExpr.eval]
  | some flags =>
      simp at safe
      rcases safe with safe | safe | safe | safe | safe | safe <;> subst index <;>
        simp [outputFlag, BoolExpr.eval, evalNormalizedFlags,
          StageA.Formal.FlagsExpr.eval_extract_cf,
          StageA.Formal.FlagsExpr.eval_extract_pf,
          StageA.Formal.FlagsExpr.eval_extract_zf,
          StageA.Formal.FlagsExpr.eval_extract_sf,
          StageA.Formal.FlagsExpr.eval_extract_df,
          StageA.Formal.FlagsExpr.eval_extract_of,
          StageA.Formal.evalFlagBit]
      all_goals split <;> simp_all [BoolExpr.eval]
      all_goals split <;> simp_all

def _root_.StageA.Formal.BoolExpr.substitute (registers : Registers Expr) (flags : Option FlagsExpr) :
    BoolExpr → BoolExpr
  | .equal left right =>
      .equal (left.substituteRegisters registers) (right.substituteRegisters registers)
  | .not value => .not (value.substitute registers flags)
  | .and left right => .and (left.substitute registers flags) (right.substitute registers flags)
  | .or left right => .or (left.substitute registers flags) (right.substitute registers flags)
  | .xor left right => .xor (left.substitute registers flags) (right.substitute registers flags)
  | .unsignedLess left right =>
      .unsignedLess (left.substituteRegisters registers) (right.substituteRegisters registers)
  | .msb value => .msb (value.substituteRegisters registers)
  | .bit value index => .bit (value.substituteRegisters registers) index
  | .inputFlag index => outputFlag flags index
  | .divisionValid high low divisor =>
      .divisionValid (high.substituteRegisters registers) (low.substituteRegisters registers)
        (divisor.substituteRegisters registers)

theorem Expr.eval_substituteRegisters (behavior : NormalizedSymbolicBehavior)
    (state : MachineState) (expression : Expr)
    (safe : expression.pureInvariant = true) :
    (expression.substituteRegisters behavior.registers).eval state =
      expression.eval ((behavior.eval state).nextMachineState state) := by
  induction expression using Expr.rec (motive_2 := fun _ => True) <;>
    simp_all [Expr.pureInvariant, Expr.substituteRegisters, Expr.eval,
      RelationalBehavior.nextMachineState, evalNormalizedRegisters_get]

def _root_.StageA.Formal.Expr.pullbackMemoryExpression
    (behavior : NormalizedSymbolicBehavior) : Expr → Option Expr
  | .inputReg register => some (behavior.registers.get register)
  | .inputFlagValue bit =>
      if [0, 2, 6, 7, 10, 11].contains bit then
        some ((outputFlag behavior.flags bit).toWord)
      else none
  | .inputFsBase => some .inputFsBase
  | .constant value => some (.constant value)
  | .undefined slot => some (.undefined slot)
  | .add left right => do
      return .add (← left.pullbackMemoryExpression behavior)
        (← right.pullbackMemoryExpression behavior)
  | .sub left right => do
      return .sub (← left.pullbackMemoryExpression behavior)
        (← right.pullbackMemoryExpression behavior)
  | .bitAnd left right => do
      return .bitAnd (← left.pullbackMemoryExpression behavior)
        (← right.pullbackMemoryExpression behavior)
  | .bitXor left right => do
      return .bitXor (← left.pullbackMemoryExpression behavior)
        (← right.pullbackMemoryExpression behavior)
  | .bitNot value => return .bitNot (← value.pullbackMemoryExpression behavior)
  | .read8 address => do
      return (← address.pullbackMemoryExpression behavior).read8AfterWrites behavior.writes
  | .read32 address => do
      return (← address.pullbackMemoryExpression behavior).read32AfterWrites behavior.writes
  | .read8AfterWrite address writeAddress writeValue prior => do
      return .read8AfterWrite
        (← address.pullbackMemoryExpression behavior)
        (← writeAddress.pullbackMemoryExpression behavior)
        (← writeValue.pullbackMemoryExpression behavior)
        (← prior.pullbackMemoryExpression behavior)
  | .extractByte value index =>
      return .extractByte (← value.pullbackMemoryExpression behavior) index
  | .shiftLeft value amount =>
      return .shiftLeft (← value.pullbackMemoryExpression behavior) amount
  | .shiftRight value amount =>
      return .shiftRight (← value.pullbackMemoryExpression behavior) amount
  | .shiftLeftBy value amount => do
      return .shiftLeftBy (← value.pullbackMemoryExpression behavior)
        (← amount.pullbackMemoryExpression behavior)
  | .shiftRightBy value amount => do
      return .shiftRightBy (← value.pullbackMemoryExpression behavior)
        (← amount.pullbackMemoryExpression behavior)
  | .shiftArithmeticRightBy value amount => do
      return .shiftArithmeticRightBy (← value.pullbackMemoryExpression behavior)
        (← amount.pullbackMemoryExpression behavior)
  | .bitOr left right => do
      return .bitOr (← left.pullbackMemoryExpression behavior)
        (← right.pullbackMemoryExpression behavior)
  | .ifEqual left right thenValue elseValue => do
      return .ifEqual
        (← left.pullbackMemoryExpression behavior)
        (← right.pullbackMemoryExpression behavior)
        (← thenValue.pullbackMemoryExpression behavior)
        (← elseValue.pullbackMemoryExpression behavior)
  | .unsignedLessValue left right => do
      return .unsignedLessValue (← left.pullbackMemoryExpression behavior)
        (← right.pullbackMemoryExpression behavior)
  | .bitValue value index =>
      return .bitValue (← value.pullbackMemoryExpression behavior) index
  | .multiply left right => do
      return .multiply (← left.pullbackMemoryExpression behavior)
        (← right.pullbackMemoryExpression behavior)
  | .multiplyHighUnsigned left right => do
      return .multiplyHighUnsigned (← left.pullbackMemoryExpression behavior)
        (← right.pullbackMemoryExpression behavior)
  | .multiplyHighSigned left right => do
      return .multiplyHighSigned (← left.pullbackMemoryExpression behavior)
        (← right.pullbackMemoryExpression behavior)
  | .divideQuotient high low divisor => do
      return .divideQuotient (← high.pullbackMemoryExpression behavior)
        (← low.pullbackMemoryExpression behavior)
        (← divisor.pullbackMemoryExpression behavior)
  | .divideRemainder high low divisor => do
      return .divideRemainder (← high.pullbackMemoryExpression behavior)
        (← low.pullbackMemoryExpression behavior)
        (← divisor.pullbackMemoryExpression behavior)
  | .divisionValidValue high low divisor => do
      return .divisionValidValue (← high.pullbackMemoryExpression behavior)
        (← low.pullbackMemoryExpression behavior)
        (← divisor.pullbackMemoryExpression behavior)
  | .lowestSetBit value =>
      return .lowestSetBit (← value.pullbackMemoryExpression behavior)
  | .highestSetBit value =>
      return .highestSetBit (← value.pullbackMemoryExpression behavior)
  | .inputX87Control | .inputX87Status |
      .x87Part _ _ | .x87CompareBit _ _ _ _ | .x87ExamineStatus _ _ => none

theorem _root_.StageA.Formal.Expr.eval_pullbackMemoryExpression
    (behavior : NormalizedSymbolicBehavior) (state : MachineState)
    (expression pulled : Expr)
    (checked : expression.pullbackMemoryExpression behavior = some pulled) :
    pulled.eval state = expression.eval ((behavior.eval state).nextMachineState state) := by
  induction expression using Expr.rec (motive_2 := fun _ => True) generalizing pulled
  all_goals try trivial
  case inputReg register =>
    simp [Expr.pullbackMemoryExpression] at checked
    subst pulled
    simpa [Expr.substituteRegisters] using
      Expr.eval_substituteRegisters behavior state (.inputReg register) (by rfl)
  case inputFlagValue bit =>
    simp only [Expr.pullbackMemoryExpression] at checked
    split at checked
    · rename_i safe
      simp at checked
      subst pulled
      rw [BoolExpr.eval_toWord, outputFlag_eval behavior state bit safe]
      rfl
    · simp_all
  case inputFsBase =>
    simp [Expr.pullbackMemoryExpression] at checked
    subst pulled
    rfl
  case constant value =>
    simp [Expr.pullbackMemoryExpression] at checked
    subst pulled
    rfl
  case undefined slot =>
    simp [Expr.pullbackMemoryExpression] at checked
    subst pulled
    rfl
  case add left right leftSound rightSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledLeft, leftChecked, pulledRight, rightChecked, rfl⟩
    simp [Expr.eval, leftSound pulledLeft leftChecked, rightSound pulledRight rightChecked]
  case sub left right leftSound rightSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledLeft, leftChecked, pulledRight, rightChecked, rfl⟩
    simp [Expr.eval, leftSound pulledLeft leftChecked, rightSound pulledRight rightChecked]
  case bitAnd left right leftSound rightSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledLeft, leftChecked, pulledRight, rightChecked, rfl⟩
    simp [Expr.eval, leftSound pulledLeft leftChecked, rightSound pulledRight rightChecked]
  case bitXor left right leftSound rightSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledLeft, leftChecked, pulledRight, rightChecked, rfl⟩
    simp [Expr.eval, leftSound pulledLeft leftChecked, rightSound pulledRight rightChecked]
  case bitNot value sound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledValue, valueChecked, rfl⟩
    simp [Expr.eval, sound pulledValue valueChecked]
  case read8 address addressSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledAddress, addressChecked, rfl⟩
    rw [Expr.eval_read8AfterWrites, addressSound pulledAddress addressChecked]
    rfl
  case read32 address addressSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledAddress, addressChecked, rfl⟩
    rw [Expr.eval_read32AfterWrites, addressSound pulledAddress addressChecked]
    rfl
  case read8AfterWrite address writeAddress writeValue prior addressSound
      writeAddressSound writeValueSound priorSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledAddress, addressChecked, pulledWriteAddress,
      writeAddressChecked, pulledWriteValue, writeValueChecked, pulledPrior,
      priorChecked, rfl⟩
    simp [Expr.eval, addressSound pulledAddress addressChecked,
      writeAddressSound pulledWriteAddress writeAddressChecked,
      writeValueSound pulledWriteValue writeValueChecked,
      priorSound pulledPrior priorChecked]
  case extractByte value index sound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledValue, valueChecked, rfl⟩
    simp [Expr.eval, sound pulledValue valueChecked]
  case shiftLeft value amount sound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledValue, valueChecked, rfl⟩
    simp [Expr.eval, sound pulledValue valueChecked]
  case shiftRight value amount sound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledValue, valueChecked, rfl⟩
    simp [Expr.eval, sound pulledValue valueChecked]
  case shiftLeftBy value amount valueSound amountSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledValue, valueChecked, pulledAmount, amountChecked, rfl⟩
    simp [Expr.eval, valueSound pulledValue valueChecked,
      amountSound pulledAmount amountChecked]
  case shiftRightBy value amount valueSound amountSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledValue, valueChecked, pulledAmount, amountChecked, rfl⟩
    simp [Expr.eval, valueSound pulledValue valueChecked,
      amountSound pulledAmount amountChecked]
  case shiftArithmeticRightBy value amount valueSound amountSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledValue, valueChecked, pulledAmount, amountChecked, rfl⟩
    simp [Expr.eval, valueSound pulledValue valueChecked,
      amountSound pulledAmount amountChecked]
  case bitOr left right leftSound rightSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledLeft, leftChecked, pulledRight, rightChecked, rfl⟩
    simp [Expr.eval, leftSound pulledLeft leftChecked, rightSound pulledRight rightChecked]
  case ifEqual left right thenValue elseValue leftSound rightSound thenSound elseSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledLeft, leftChecked, pulledRight, rightChecked,
      pulledThen, thenChecked, pulledElse, elseChecked, rfl⟩
    simp [Expr.eval, leftSound pulledLeft leftChecked, rightSound pulledRight rightChecked,
      thenSound pulledThen thenChecked, elseSound pulledElse elseChecked]
  case unsignedLessValue left right leftSound rightSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledLeft, leftChecked, pulledRight, rightChecked, rfl⟩
    simp [Expr.eval, leftSound pulledLeft leftChecked, rightSound pulledRight rightChecked]
  case bitValue value index sound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledValue, valueChecked, rfl⟩
    simp [Expr.eval, sound pulledValue valueChecked]
  case multiply left right leftSound rightSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledLeft, leftChecked, pulledRight, rightChecked, rfl⟩
    simp [Expr.eval, leftSound pulledLeft leftChecked, rightSound pulledRight rightChecked]
  case multiplyHighUnsigned left right leftSound rightSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledLeft, leftChecked, pulledRight, rightChecked, rfl⟩
    simp [Expr.eval, leftSound pulledLeft leftChecked, rightSound pulledRight rightChecked]
  case multiplyHighSigned left right leftSound rightSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledLeft, leftChecked, pulledRight, rightChecked, rfl⟩
    simp [Expr.eval, leftSound pulledLeft leftChecked, rightSound pulledRight rightChecked]
  case divideQuotient high low divisor highSound lowSound divisorSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledHigh, highChecked, pulledLow, lowChecked,
      pulledDivisor, divisorChecked, rfl⟩
    simp [Expr.eval, highSound pulledHigh highChecked, lowSound pulledLow lowChecked,
      divisorSound pulledDivisor divisorChecked]
  case divideRemainder high low divisor highSound lowSound divisorSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledHigh, highChecked, pulledLow, lowChecked,
      pulledDivisor, divisorChecked, rfl⟩
    simp [Expr.eval, highSound pulledHigh highChecked, lowSound pulledLow lowChecked,
      divisorSound pulledDivisor divisorChecked]
  case divisionValidValue high low divisor highSound lowSound divisorSound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledHigh, highChecked, pulledLow, lowChecked,
      pulledDivisor, divisorChecked, rfl⟩
    simp [Expr.eval, highSound pulledHigh highChecked, lowSound pulledLow lowChecked,
      divisorSound pulledDivisor divisorChecked]
  case lowestSetBit value sound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledValue, valueChecked, rfl⟩
    simp [Expr.eval, sound pulledValue valueChecked]
  case highestSetBit value sound =>
    simp [Expr.pullbackMemoryExpression, Option.bind_eq_some_iff] at checked
    rcases checked with ⟨pulledValue, valueChecked, rfl⟩
    simp [Expr.eval, sound pulledValue valueChecked]
  all_goals simp [Expr.pullbackMemoryExpression] at checked

def _root_.StageA.Formal.Expr.pullbackX87LoadControl
    (behavior : NormalizedSymbolicBehavior) : Expr → Option Expr
  | .inputX87Control => some behavior.x87.control
  | expression => expression.pullbackMemoryExpression behavior

theorem _root_.StageA.Formal.Expr.eval_pullbackX87LoadControl_low16
    (behavior : NormalizedSymbolicBehavior) (state : MachineState)
    (expression pulled : Expr)
    (checked : expression.pullbackX87LoadControl behavior = some pulled) :
    (pulled.eval state).extractLsb' 0 16 =
      (expression.eval ((behavior.eval state).nextMachineState state)).extractLsb' 0 16 := by
  cases expression <;> simp [Expr.pullbackX87LoadControl] at checked
  case inputX87Control =>
    subst pulled
    simp [Expr.eval, RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval, evalNormalizedX87]
    bv_decide
  all_goals
    have sound := Expr.eval_pullbackMemoryExpression behavior state _ pulled checked
    exact congrArg (fun value : Word => value.extractLsb' 0 16) sound

def _root_.StageA.Formal.Expr.pullbackMemoryRead
    (behavior : NormalizedSymbolicBehavior) : Expr → Option Expr
  | expression@(.read8 _) | expression@(.read32 _) |
      expression@(.read8AfterWrite _ _ _ _) =>
      expression.pullbackMemoryExpression behavior
  | _ => none

theorem _root_.StageA.Formal.Expr.eval_pullbackMemoryRead
    (behavior : NormalizedSymbolicBehavior) (state : MachineState)
    (expression pulled : Expr)
    (checked : expression.pullbackMemoryRead behavior = some pulled) :
    pulled.eval state = expression.eval ((behavior.eval state).nextMachineState state) := by
  cases expression <;> simp [Expr.pullbackMemoryRead] at checked
  all_goals exact Expr.eval_pullbackMemoryExpression behavior state _ pulled checked

mutual
def _root_.StageA.Formal.Expr.memoryReadObservations : Expr → List Expr
  | .inputReg _ | .inputFlagValue _ | .inputFsBase | .inputX87Control |
      .inputX87Status | .constant _ | .undefined _ => []
  | .add left right | .sub left right | .bitAnd left right | .bitXor left right |
      .shiftLeftBy left right | .shiftRightBy left right |
      .shiftArithmeticRightBy left right | .bitOr left right |
      .unsignedLessValue left right | .multiply left right |
      .multiplyHighUnsigned left right | .multiplyHighSigned left right =>
      left.memoryReadObservations ++ right.memoryReadObservations
  | .bitNot value | .extractByte value _ | .shiftLeft value _ | .shiftRight value _ |
      .bitValue value _ | .lowestSetBit value | .highestSetBit value =>
      value.memoryReadObservations
  | .read8 address =>
      .read8 address :: address.memoryReadObservations
  | .read32 address =>
      .read32 address :: address.memoryReadObservations
  | .read8AfterWrite address writeAddress writeValue prior =>
      .read8AfterWrite address writeAddress writeValue prior ::
        (address.memoryReadObservations ++ writeAddress.memoryReadObservations ++
          writeValue.memoryReadObservations)
  | .ifEqual left right thenValue elseValue =>
      left.memoryReadObservations ++ right.memoryReadObservations ++
        thenValue.memoryReadObservations ++ elseValue.memoryReadObservations
  | .divideQuotient high low divisor | .divideRemainder high low divisor |
      .divisionValidValue high low divisor =>
      high.memoryReadObservations ++ low.memoryReadObservations ++
        divisor.memoryReadObservations
  | .x87Part value _ => value.memoryReadObservations
  | .x87CompareBit left right control _ =>
      left.memoryReadObservations ++ right.memoryReadObservations ++
        control.memoryReadObservations
  | .x87ExamineStatus value status =>
      value.memoryReadObservations ++ status.memoryReadObservations

def _root_.StageA.Formal.X87Expr.memoryReadObservations : X87Expr → List Expr
  | .inputStack _ | .constant _ => []
  | .load _ address control =>
      address.memoryReadObservations ++ control.memoryReadObservations
  | .imageLoad _ _ control => control.memoryReadObservations
  | .unary _ value control | .store _ value control =>
      value.memoryReadObservations ++ control.memoryReadObservations
  | .binary _ left right control =>
      left.memoryReadObservations ++ right.memoryReadObservations ++
        control.memoryReadObservations
end

def _root_.StageA.Formal.BoolExpr.memoryReadObservations : BoolExpr → List Expr
  | .equal left right | .unsignedLess left right =>
      left.memoryReadObservations ++ right.memoryReadObservations
  | .not value => value.memoryReadObservations
  | .and left right | .or left right | .xor left right =>
      left.memoryReadObservations ++ right.memoryReadObservations
  | .msb value | .bit value _ => value.memoryReadObservations
  | .inputFlag _ => []
  | .divisionValid high low divisor =>
      high.memoryReadObservations ++ low.memoryReadObservations ++
        divisor.memoryReadObservations

def _root_.StageA.Formal.FlagsExpr.memoryReadObservations
    (flags : FlagsExpr) : List Expr :=
  [flags.zero, flags.carry, flags.sign, flags.overflow, flags.parity].flatMap
    fun value => match value with
      | none => []
      | some expression => expression.memoryReadObservations

def _root_.StageA.Formal.SymbolicX87State.memoryReadObservations
    (state : SymbolicX87State) : List Expr :=
  state.stack.flatMap X87Expr.memoryReadObservations ++
    state.control.memoryReadObservations ++ state.status.memoryReadObservations

def _root_.StageA.Relational.NormalizedOutcomeExpr.memoryReadObservations :
    NormalizedOutcomeExpr → List Expr
  | .returned target | .indirectJump target => target.memoryReadObservations
  | .jump _ | .call _ _ => []
  | .branch condition _ _ => condition.memoryReadObservations
  | .externalCall _ arguments _ | .externalJump _ arguments =>
      arguments.flatMap Expr.memoryReadObservations
  | .bulkCopy destination source count direction _ =>
      destination.memoryReadObservations ++ source.memoryReadObservations ++
        count.memoryReadObservations ++ direction.memoryReadObservations
  | .indirectCall target _ => target.memoryReadObservations
  | .checkedContinue valid _ => valid.memoryReadObservations
  | .atomicCompareExchange address expected replacement _ =>
      address.memoryReadObservations ++ expected.memoryReadObservations ++
        replacement.memoryReadObservations

def _root_.StageA.Relational.NormalizedOutcomeExpr.directTargets :
    NormalizedOutcomeExpr → List Nat
  | .jump target => [target]
  | .branch _ taken fallthrough => [taken, fallthrough]
  | .call target _ => [target]
  | .externalCall _ _ continuation | .bulkCopy _ _ _ _ continuation |
      .checkedContinue _ continuation | .atomicCompareExchange _ _ _ continuation =>
      [continuation]
  | _ => []

def _root_.StageA.Relational.NormalizedSymbolicBehavior.memoryReadObservations
    (behavior : NormalizedSymbolicBehavior) : List Expr :=
  [behavior.registers.eax, behavior.registers.ebx, behavior.registers.ecx,
      behavior.registers.edx, behavior.registers.esi, behavior.registers.edi,
      behavior.registers.ebp, behavior.registers.esp].flatMap
      Expr.memoryReadObservations ++
    behavior.x87.memoryReadObservations ++
    behavior.writes.flatMap (fun write =>
      write.1.memoryReadObservations ++ write.2.memoryReadObservations) ++
    (match behavior.flags with
      | none => []
      | some flags => flags.memoryReadObservations) ++
    behavior.outcome.memoryReadObservations

structure X87LoadObservation where
  format : X87LoadFormat
  address : Expr
  control : Expr
deriving Repr, DecidableEq

mutual
def _root_.StageA.Formal.Expr.x87LoadObservations : Expr → List X87LoadObservation
  | .inputReg _ | .inputFlagValue _ | .inputFsBase | .inputX87Control |
      .inputX87Status | .constant _ | .undefined _ => []
  | .add left right | .sub left right | .bitAnd left right | .bitXor left right |
      .shiftLeftBy left right | .shiftRightBy left right |
      .shiftArithmeticRightBy left right | .bitOr left right |
      .unsignedLessValue left right | .multiply left right |
      .multiplyHighUnsigned left right | .multiplyHighSigned left right =>
      left.x87LoadObservations ++ right.x87LoadObservations
  | .bitNot value | .read8 value | .read32 value | .extractByte value _ |
      .shiftLeft value _ | .shiftRight value _ | .bitValue value _ |
      .lowestSetBit value | .highestSetBit value => value.x87LoadObservations
  | .read8AfterWrite address writeAddress writeValue prior |
      .ifEqual address writeAddress writeValue prior =>
      address.x87LoadObservations ++ writeAddress.x87LoadObservations ++
        writeValue.x87LoadObservations ++ prior.x87LoadObservations
  | .divideQuotient high low divisor | .divideRemainder high low divisor |
      .divisionValidValue high low divisor =>
      high.x87LoadObservations ++ low.x87LoadObservations ++ divisor.x87LoadObservations
  | .x87Part value _ => value.x87LoadObservations
  | .x87CompareBit left right control _ =>
      left.x87LoadObservations ++ right.x87LoadObservations ++ control.x87LoadObservations
  | .x87ExamineStatus value status =>
      value.x87LoadObservations ++ status.x87LoadObservations

def _root_.StageA.Formal.X87Expr.x87LoadObservations :
    X87Expr → List X87LoadObservation
  | .inputStack _ | .constant _ => []
  | .load format address control =>
      { format := format, address := address, control := control } ::
        (address.x87LoadObservations ++ control.x87LoadObservations)
  | .imageLoad _ _ control => control.x87LoadObservations
  | .unary _ value control | .store _ value control =>
      value.x87LoadObservations ++ control.x87LoadObservations
  | .binary _ left right control =>
      left.x87LoadObservations ++ right.x87LoadObservations ++
        control.x87LoadObservations
end

def _root_.StageA.Formal.BoolExpr.x87LoadObservations :
    BoolExpr → List X87LoadObservation
  | .equal left right | .unsignedLess left right =>
      left.x87LoadObservations ++ right.x87LoadObservations
  | .not value => value.x87LoadObservations
  | .and left right | .or left right | .xor left right =>
      left.x87LoadObservations ++ right.x87LoadObservations
  | .msb value | .bit value _ => value.x87LoadObservations
  | .inputFlag _ => []
  | .divisionValid high low divisor =>
      high.x87LoadObservations ++ low.x87LoadObservations ++ divisor.x87LoadObservations

def _root_.StageA.Formal.FlagsExpr.x87LoadObservations
    (flags : FlagsExpr) : List X87LoadObservation :=
  [flags.zero, flags.carry, flags.sign, flags.overflow, flags.parity].flatMap
    fun value => match value with
      | none => []
      | some expression => expression.x87LoadObservations

def _root_.StageA.Formal.SymbolicX87State.x87LoadObservations
    (state : SymbolicX87State) : List X87LoadObservation :=
  state.stack.flatMap X87Expr.x87LoadObservations ++
    state.control.x87LoadObservations ++ state.status.x87LoadObservations

def _root_.StageA.Relational.NormalizedOutcomeExpr.x87LoadObservations :
    NormalizedOutcomeExpr → List X87LoadObservation
  | .returned target | .indirectJump target => target.x87LoadObservations
  | .jump _ | .call _ _ => []
  | .branch condition _ _ => condition.x87LoadObservations
  | .externalCall _ arguments _ | .externalJump _ arguments =>
      arguments.flatMap Expr.x87LoadObservations
  | .bulkCopy destination source count direction _ =>
      destination.x87LoadObservations ++ source.x87LoadObservations ++
        count.x87LoadObservations ++ direction.x87LoadObservations
  | .indirectCall target _ => target.x87LoadObservations
  | .checkedContinue valid _ => valid.x87LoadObservations
  | .atomicCompareExchange address expected replacement _ =>
      address.x87LoadObservations ++ expected.x87LoadObservations ++
        replacement.x87LoadObservations

def _root_.StageA.Relational.NormalizedSymbolicBehavior.x87LoadObservations
    (behavior : NormalizedSymbolicBehavior) : List X87LoadObservation :=
  [behavior.registers.eax, behavior.registers.ebx, behavior.registers.ecx,
      behavior.registers.edx, behavior.registers.esi, behavior.registers.edi,
      behavior.registers.ebp, behavior.registers.esp].flatMap
      Expr.x87LoadObservations ++
    behavior.x87.x87LoadObservations ++
    behavior.writes.flatMap (fun write =>
      write.1.x87LoadObservations ++ write.2.x87LoadObservations) ++
    (match behavior.flags with
      | none => []
      | some flags => flags.x87LoadObservations) ++
    behavior.outcome.x87LoadObservations

def X87LoadObservation.byteReads (observation : X87LoadObservation) : List Expr :=
  (List.range observation.format.byteWidth).map fun offset =>
    .read8 (.add observation.address (.constant offset))

def X87LoadObservation.PullbackClosed
    (source : NormalizedSymbolicBehavior) (observation : X87LoadObservation) : Prop :=
  (∃ pulledControl,
      observation.control.pullbackX87LoadControl source = some pulledControl) ∧
    ∀ read, read ∈ observation.byteReads →
      ∃ pulledRead, read.pullbackMemoryRead source = some pulledRead

def X87LoadObservation.pullbackChecked
    (source : NormalizedSymbolicBehavior) (observation : X87LoadObservation) : Bool :=
  (observation.control.pullbackX87LoadControl source).isSome &&
    observation.byteReads.all fun read => (read.pullbackMemoryRead source).isSome

theorem X87LoadObservation.pullbackClosed_of_checked
    (source : NormalizedSymbolicBehavior) (observation : X87LoadObservation)
    (checked : observation.pullbackChecked source = true) :
    observation.PullbackClosed source := by
  simp only [X87LoadObservation.pullbackChecked, Bool.and_eq_true] at checked
  rcases checked with ⟨controlChecked, readsChecked⟩
  constructor
  · cases result : observation.control.pullbackX87LoadControl source with
    | none => simp [result] at controlChecked
    | some pulled => exact ⟨pulled, rfl⟩
  · intro read member
    simp only [List.all_eq_true] at readsChecked
    have readChecked := readsChecked read member
    cases result : read.pullbackMemoryRead source with
    | none => simp [result] at readChecked
    | some pulled => exact ⟨pulled, rfl⟩

def X87LoadPullbackEdgeClosed (source target : NormalizedSymbolicBehavior)
    (targetId : Nat) : Prop :=
  source.outcome.directTargets.contains targetId = true ∧
    ∀ observation, observation ∈ target.x87LoadObservations →
      observation.PullbackClosed source

theorem x87LoadPullbackEdgeClosed_of_checked
    (source target : NormalizedSymbolicBehavior) (targetId : Nat)
    (edgeChecked : source.outcome.directTargets.contains targetId = true)
    (loadsChecked : target.x87LoadObservations.all
      (X87LoadObservation.pullbackChecked source) = true) :
    X87LoadPullbackEdgeClosed source target targetId := by
  constructor
  · exact edgeChecked
  · intro observation member
    simp only [List.all_eq_true] at loadsChecked
    exact observation.pullbackClosed_of_checked source (loadsChecked observation member)

structure ExactMemoryReadPullbackPairClaim where
  originalRead : Expr
  candidateRead : Expr
  pulled : Expr
deriving Repr, DecidableEq

def ExactMemoryReadPullbackPairClaim.checked
    (values : List ValueTargetPair)
    (source : RegionRelation)
    (originalSource candidateSource originalTarget candidateTarget : NormalizedSymbolicBehavior)
    (claim : ExactMemoryReadPullbackPairClaim) : Bool :=
  values == [] &&
    originalTarget.memoryReadObservations.contains claim.originalRead &&
    candidateTarget.memoryReadObservations.contains claim.candidateRead &&
    claim.originalRead.pullbackMemoryRead originalSource == some claim.pulled &&
    claim.candidateRead.pullbackMemoryRead candidateSource == some claim.pulled &&
    claim.pulled.exactMemoryInputs source.inputRelations

def ExactMemoryReadPullbackPairClaim.Holds
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source : RegionRelation)
    (originalSource candidateSource : NormalizedSymbolicBehavior)
    (claim : ExactMemoryReadPullbackPairClaim) : Prop :=
  ∀ originalState candidateState,
    composableStatesRelated originalImageBase candidateImageBase targets
      source.flagInputs source.bounds source.addressSeparations values
      source.inputRelations originalState candidateState →
    claim.originalRead.eval ((originalSource.eval originalState).nextMachineState originalState) =
      claim.candidateRead.eval ((candidateSource.eval candidateState).nextMachineState candidateState)

theorem ExactMemoryReadPullbackPairClaim.holds_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source : RegionRelation)
    (originalSource candidateSource originalTarget candidateTarget : NormalizedSymbolicBehavior)
    (claim : ExactMemoryReadPullbackPairClaim)
    (checked : claim.checked values source originalSource candidateSource
      originalTarget candidateTarget = true) :
    claim.Holds originalImageBase candidateImageBase targets values source
      originalSource candidateSource := by
  rcases claim with ⟨originalRead, candidateRead, pulled⟩
  simp only [ExactMemoryReadPullbackPairClaim.checked, Bool.and_eq_true] at checked
  have valuesChecked := checked.1.1.1.1.1
  have originalPullbackChecked := checked.1.1.2
  have candidatePullbackChecked := checked.1.2
  have safe := checked.2
  have valuesEmpty := beq_iff_eq.mp valuesChecked
  intro originalState candidateState related
  rcases related with ⟨registers, _, _, memoryRelated, undefinedValue, _, _, fsBase⟩
  rw [valuesEmpty] at registers memoryRelated
  have memoryEqual := memoryRelated_without_values_eq originalImageBase candidateImageBase
    targets originalState.memory candidateState.memory memoryRelated
  have pulledEqual := Expr.eval_eq_of_exactMemoryInputs originalImageBase candidateImageBase
    targets [] source.inputRelations originalState candidateState pulled registers
    memoryEqual undefinedValue fsBase safe
  have originalSound := Expr.eval_pullbackMemoryRead originalSource originalState
    originalRead pulled (beq_iff_eq.mp originalPullbackChecked)
  have candidateSound := Expr.eval_pullbackMemoryRead candidateSource candidateState
    candidateRead pulled (beq_iff_eq.mp candidatePullbackChecked)
  exact originalSound.symm.trans (pulledEqual.trans candidateSound)

def ExactMemoryReadPullbackPairClaim.requirement
    (claim : ExactMemoryReadPullbackPairClaim) : MemoryObservationRequirement := {
  id := 0
  relation := .exact
  original := claim.originalRead
  candidate := claim.candidateRead
}

theorem memoryObservationContractHolds_of_exact_pullback_pairs
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source : RegionRelation)
    (originalSource candidateSource originalTarget candidateTarget : NormalizedSymbolicBehavior)
    (claims : List ExactMemoryReadPullbackPairClaim)
    (checked : claims.all (ExactMemoryReadPullbackPairClaim.checked values source originalSource
      candidateSource originalTarget candidateTarget) = true) :
    ∀ originalState candidateState,
      composableStatesRelated originalImageBase candidateImageBase targets
        source.flagInputs source.bounds source.addressSeparations values
        source.inputRelations originalState candidateState →
      memoryObservationContractHolds originalImageBase candidateImageBase targets
        values (claims.map ExactMemoryReadPullbackPairClaim.requirement)
        ((originalSource.eval originalState).nextMachineState originalState)
        ((candidateSource.eval candidateState).nextMachineState candidateState) = true := by
  intro originalState candidateState related
  induction claims with
  | nil => rfl
  | cons claim tail ih =>
      simp only [List.all_cons, Bool.and_eq_true] at checked
      unfold memoryObservationContractHolds
      simp only [List.map_cons, List.all_cons, Bool.and_eq_true]
      have headEqual := claim.holds_of_checked originalImageBase candidateImageBase
        targets values source
        originalSource candidateSource originalTarget candidateTarget checked.1
        originalState candidateState related
      exact ⟨beq_iff_eq.mpr headEqual, ih checked.2⟩

theorem memoryObservationTransitionClosed_of_exact_pullback_pairs
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source target : RegionRelation)
    (originalSource candidateSource originalTarget candidateTarget : NormalizedSymbolicBehavior)
    (claims : List ExactMemoryReadPullbackPairClaim)
    (checked : claims.all (ExactMemoryReadPullbackPairClaim.checked values source originalSource
      candidateSource originalTarget candidateTarget) = true) :
    MemoryObservationTransitionClosed originalImageBase candidateImageBase targets values source
      (claims.map ExactMemoryReadPullbackPairClaim.requirement) []
      originalSource candidateSource := by
  intro originalState candidateState related
  constructor
  · exact memoryObservationContractHolds_of_exact_pullback_pairs originalImageBase
      candidateImageBase targets values source originalSource candidateSource
      originalTarget candidateTarget claims checked originalState candidateState related
  · rfl

def ExactMemoryReadPullbackPairEdgeClosed
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source target : RegionRelation)
    (originalSource candidateSource : NormalizedSymbolicBehavior)
    (claim : ExactMemoryReadPullbackPairClaim) : Prop :=
  originalSource.outcome.directTargets.contains target.id = true ∧
    candidateSource.outcome.directTargets.contains target.id = true ∧
    claim.Holds originalImageBase candidateImageBase targets values source
      originalSource candidateSource

theorem exactMemoryReadPullbackPairEdgeClosed_of_checked
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source target : RegionRelation)
    (originalSource candidateSource originalTarget candidateTarget : NormalizedSymbolicBehavior)
    (claim : ExactMemoryReadPullbackPairClaim)
    (originalDirect : originalSource.outcome.directTargets.contains target.id = true)
    (candidateDirect : candidateSource.outcome.directTargets.contains target.id = true)
    (checked : claim.checked values source originalSource candidateSource
      originalTarget candidateTarget = true) :
    ExactMemoryReadPullbackPairEdgeClosed originalImageBase candidateImageBase targets values
      source target
      originalSource candidateSource claim :=
  ⟨originalDirect, candidateDirect,
    claim.holds_of_checked originalImageBase candidateImageBase targets values source originalSource
      candidateSource originalTarget candidateTarget checked⟩

def MemoryReadPullbackEdgeClosed (source target : NormalizedSymbolicBehavior)
    (targetId : Nat) : Prop :=
  source.outcome.directTargets.contains targetId = true ∧
    ∀ read, read ∈ target.memoryReadObservations →
      ∃ pulled, read.pullbackMemoryRead source = some pulled

theorem memoryReadPullbackEdgeClosed_of_checked
    (source target : NormalizedSymbolicBehavior) (targetId : Nat)
    (edgeChecked : source.outcome.directTargets.contains targetId = true)
    (readsChecked : target.memoryReadObservations.all
      (fun read => (read.pullbackMemoryRead source).isSome) = true) :
    MemoryReadPullbackEdgeClosed source target targetId := by
  constructor
  · exact edgeChecked
  · intro read member
    simp only [List.all_eq_true] at readsChecked
    have checked := readsChecked read member
    cases result : read.pullbackMemoryRead source with
    | none => simp [result] at checked
    | some pulled => exact ⟨pulled, rfl⟩

theorem BoolExpr.eval_substitute (behavior : NormalizedSymbolicBehavior)
    (state : MachineState) (predicate : BoolExpr)
    (safe : predicate.pureInvariant = true) :
    (predicate.substitute behavior.registers behavior.flags).eval state =
      predicate.eval ((behavior.eval state).nextMachineState state) := by
  induction predicate <;>
    simp_all [BoolExpr.pureInvariant, BoolExpr.substitute, BoolExpr.eval,
      Expr.eval_substituteRegisters behavior state]
  case inputFlag index =>
    exact outputFlag_eval behavior state index (by simpa using safe)
  case divisionValid high low divisor =>
    have h := Expr.eval_substituteRegisters behavior state
      (.divisionValidValue high low divisor) (by simp_all [Expr.pureInvariant])
    simpa [Expr.substituteRegisters, Expr.eval] using
      congrArg (fun value => value == (1 : Word)) h

def _root_.StageA.Relational.NormalizedOutcomeExpr.edgeGuard
    (outcome : NormalizedOutcomeExpr)
    (target : Nat) : Option BoolExpr :=
  match outcome with
  | .jump destination | .call destination _ =>
      if destination == target then some trueExpr else none
  | .branch condition taken fallthrough =>
      if taken == target && fallthrough == target then some trueExpr
      else if taken == target then some condition
      else if fallthrough == target then some condition.negateNormalized
      else none
  | .bulkCopy _ _ _ _ continuation | .atomicCompareExchange _ _ _ continuation =>
      if continuation == target then some trueExpr else none
  | .checkedContinue valid continuation =>
      if continuation == target then some valid else none
  | _ => none

def edgeWeakestPrecondition (behavior : NormalizedSymbolicBehavior)
    (target : Nat) (predicate : BoolExpr) : Option BoolExpr := do
  let guard ← behavior.outcome.edgeGuard target
  let substituted := predicate.substitute behavior.registers behavior.flags
  pure (if guard == trueExpr then substituted else .or guard.negateNormalized substituted)

theorem edgeGuard_eval_of_selected (outcome : NormalizedOutcomeExpr)
    (state : MachineState) (target : Nat) (guard : BoolExpr)
    (found : outcome.edgeGuard target = some guard)
    (selected : (outcome.eval state).nextLogicalTarget = some target) :
    guard.eval state = true := by
  cases outcome with
  | branch condition taken fallthrough =>
      simp only [NormalizedOutcomeExpr.edgeGuard] at found
      split at found
      case isTrue both =>
        simp at found
        subst guard
        simp [trueExpr, BoolExpr.eval]
      case isFalse notBoth =>
        split at found
        case isTrue takenTarget =>
          simp at found
          subst guard
          simp_all [NormalizedOutcomeExpr.eval, PureOutcome.nextLogicalTarget]
        case isFalse notTaken =>
          split at found
          case isTrue fallthroughTarget =>
            simp at found
            subst guard
            rw [BoolExpr.eval_negateNormalized]
            cases conditionEval : condition.eval state with
            | false => rfl
            | true =>
                simp [NormalizedOutcomeExpr.eval, PureOutcome.nextLogicalTarget,
                  conditionEval] at selected
                simp [selected] at notTaken
          case isFalse notFallthrough => simp at found
  | checkedContinue valid continuation =>
      simp [NormalizedOutcomeExpr.edgeGuard] at found
      rcases found with ⟨_, rfl⟩
      cases h : valid.eval state <;>
        simp_all [NormalizedOutcomeExpr.eval, PureOutcome.nextLogicalTarget]
  | jump destination =>
      simp [NormalizedOutcomeExpr.edgeGuard] at found
      rcases found with ⟨_, rfl⟩
      simp [trueExpr, BoolExpr.eval]
  | call destination continuation =>
      simp [NormalizedOutcomeExpr.edgeGuard] at found
      rcases found with ⟨_, rfl⟩
      simp [trueExpr, BoolExpr.eval]
  | bulkCopy destination source count direction continuation =>
      simp [NormalizedOutcomeExpr.edgeGuard] at found
      rcases found with ⟨_, rfl⟩
      simp [trueExpr, BoolExpr.eval]
  | atomicCompareExchange address expected replacement continuation =>
      simp [NormalizedOutcomeExpr.edgeGuard] at found
      rcases found with ⟨_, rfl⟩
      simp [trueExpr, BoolExpr.eval]
  | returned | externalCall | externalJump | indirectCall | indirectJump =>
      simp [NormalizedOutcomeExpr.edgeGuard] at found

theorem edgeWeakestPrecondition_sound (behavior : NormalizedSymbolicBehavior)
    (state : MachineState) (target : Nat) (predicate precondition : BoolExpr)
    (safe : predicate.pureInvariant = true)
    (computed : edgeWeakestPrecondition behavior target predicate = some precondition)
    (holds : precondition.eval state = true)
    (selected : (behavior.eval state).outcome.nextLogicalTarget = some target) :
    predicate.eval ((behavior.eval state).nextMachineState state) = true := by
  unfold edgeWeakestPrecondition at computed
  cases guardFound : behavior.outcome.edgeGuard target with
  | none => simp [guardFound] at computed
  | some guard =>
      simp [guardFound] at computed
      split at computed
      case isTrue always =>
        subst precondition
        rw [← BoolExpr.eval_substitute behavior state predicate safe]
        exact holds
      case isFalse conditional =>
        subst precondition
        have guardTrue := edgeGuard_eval_of_selected behavior.outcome state target guard
          guardFound (by simpa using selected)
        simp [BoolExpr.eval, guardTrue] at holds
        rw [← BoolExpr.eval_substitute behavior state predicate safe]
        exact holds



def NormalizedInvariantPredicateEdgeClosed
    (behavior : NormalizedSymbolicBehavior) (sourceInvariant : List BoolExpr)
    (targetPredicate : BoolExpr) (target : Nat) : Prop :=
  ∀ state,
    stateInvariantsHold sourceInvariant state = true →
    (behavior.eval state).outcome.nextLogicalTarget = some target →
    targetPredicate.eval ((behavior.eval state).nextMachineState state) = true

theorem stateInvariantsHold_member (predicates : List BoolExpr)
    (predicate : BoolExpr) (state : MachineState)
    (member : predicate ∈ predicates)
    (holds : stateInvariantsHold predicates state = true) :
    predicate.eval state = true := by
  simp [stateInvariantsHold] at holds
  exact holds predicate member

theorem invariantPredicateEdgeClosed_of_wp
    (behavior : NormalizedSymbolicBehavior) (sourceInvariant : List BoolExpr)
    (targetPredicate precondition : BoolExpr) (target : Nat)
    (safe : targetPredicate.pureInvariant = true)
    (computed : edgeWeakestPrecondition behavior target targetPredicate = some precondition)
    (available : ∀ state, stateInvariantsHold sourceInvariant state = true →
      precondition.eval state = true) :
    NormalizedInvariantPredicateEdgeClosed behavior sourceInvariant targetPredicate target := by
  intro state source selected
  exact edgeWeakestPrecondition_sound behavior state target targetPredicate precondition safe
    computed (available state source) selected

theorem maskedSuccessorRangeTautology
    (value : Word) (mask limit threshold : Nat)
    (maskFits : mask < 2 ^ 32)
    (thresholdFits : threshold + 1 < 2 ^ 32)
    (bounded : value.toNat < limit)
    (preserves : ∀ input, input < limit → input &&& mask = input) :
    decide (value < BitVec.ofNat 32 threshold) = false ∧
        ¬(value - BitVec.ofNat 32 threshold) &&& BitVec.ofNat 32 mask = 0#32 ∨
      value < BitVec.ofNat 32 (threshold + 1) := by
  by_cases below : value.toNat < threshold + 1
  · right
    simpa [BitVec.lt_def, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt thresholdFits] using below
  · left
    constructor
    · simp [BitVec.lt_def, BitVec.toNat_ofNat,
        Nat.mod_eq_of_lt (by omega : threshold < 2 ^ 32)]
      omega
    · intro equalZero
      have asNat := congrArg BitVec.toNat equalZero
      simp [BitVec.toNat_and, BitVec.toNat_sub, BitVec.toNat_ofNat,
        Nat.mod_eq_of_lt maskFits,
        Nat.mod_eq_of_lt (by omega : threshold < 2 ^ 32)] at asNat
      have reduced :
          (2 ^ 32 - threshold + value.toNat) % 2 ^ 32 =
            value.toNat - threshold := by
        omega
      rw [reduced] at asNat
      have differenceBound : value.toNat - threshold < limit := by omega
      rw [preserves _ differenceBound] at asNat
      omega

def maskedSuccessorPredicate (base : Expr) (bits threshold : Nat) : BoolExpr :=
  let mask := 2 ^ bits - 1
  let masked := .bitAnd base (.constant mask)
  .or
    (.and
      (.not (.unsignedLess (.bitAnd masked (.constant mask))
        (.bitAnd (.constant threshold) (.constant mask))))
      (.not (.equal
        (.bitAnd (.bitAnd (.sub masked (.constant threshold)) (.constant mask))
          (.constant mask))
        (.constant 0))))
    (.unsignedLess masked (.constant (threshold + 1)))

theorem maskedSuccessorPredicate_eval (base : Expr) (bits threshold : Nat)
    (state : MachineState) (bitsAtMost : bits ≤ 32)
    (thresholdBound : threshold + 1 < 2 ^ bits) :
    (maskedSuccessorPredicate base bits threshold).eval state = true := by
  let mask := 2 ^ bits - 1
  let value : Word := base.eval state &&& BitVec.ofNat 32 mask
  have powerBound : 2 ^ bits ≤ 2 ^ 32 :=
    Nat.pow_le_pow_right (by omega) bitsAtMost
  have maskFits : mask < 2 ^ 32 := by unfold mask; omega
  have thresholdFits : threshold + 1 < 2 ^ 32 := by omega
  have valueBound : value.toNat < 2 ^ bits := by
    unfold value mask
    rw [BitVec.toNat_and, BitVec.toNat_ofNat]
    rw [Nat.mod_eq_of_lt (by omega : 2 ^ bits - 1 < 2 ^ 32)]
    exact Nat.and_lt_two_pow _ (by omega)
  have preserves : ∀ input, input < 2 ^ bits → input &&& mask = input := by
    intro input inputBound
    unfold mask
    exact Nat.and_two_pow_sub_one_of_lt_two_pow inputBound
  have thresholdMask :
      BitVec.ofNat 32 threshold &&& BitVec.ofNat 32 mask =
        BitVec.ofNat 32 threshold := by
    apply BitVec.eq_of_toNat_eq
    simp [BitVec.toNat_and, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt maskFits,
      Nat.mod_eq_of_lt (by omega : threshold < 2 ^ 32),
      preserves threshold (by omega)]
  have range := maskedSuccessorRangeTautology value mask (2 ^ bits) threshold
    maskFits thresholdFits valueBound preserves
  simpa [maskedSuccessorPredicate, BoolExpr.eval, Expr.eval, value, mask,
    BitVec.and_assoc, thresholdMask] using range

def successorRangePredicate (base : Expr) (threshold : Nat) : BoolExpr :=
  .or
    (.and
      (.not (.unsignedLess base (.constant threshold)))
      (.not (.equal (.sub base (.constant threshold)) (.constant 0))))
    (.unsignedLess base (.constant (threshold + 1)))

theorem successorRangePredicate_eval (base : Expr) (threshold : Nat)
    (state : MachineState) (thresholdFits : threshold + 1 < 2 ^ 32) :
    (successorRangePredicate base threshold).eval state = true := by
  simp [successorRangePredicate, BoolExpr.eval, Expr.eval,
    BitVec.lt_def, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt thresholdFits,
    Nat.mod_eq_of_lt (by omega : threshold < 2 ^ 32)]
  let value := base.eval state
  by_cases below : value.toNat < threshold + 1
  · right
    simpa [value] using below
  · left
    simp [value] at below
    constructor
    · omega
    · intro equalZero
      have asNat := congrArg BitVec.toNat equalZero
      simp [BitVec.toNat_sub, BitVec.toNat_ofNat,
        Nat.mod_eq_of_lt (by omega : threshold < 2 ^ 32)] at asNat
      have reduced :
          (2 ^ 32 - threshold + (base.eval state).toNat) % 2 ^ 32 =
            (base.eval state).toNat - threshold := by omega
      rw [reduced] at asNat
      omega


end InvariantWP

def PureOutcome.relationalObservation : PureOutcome -> Option RelationalObservable
  | .externalCall imported arguments _ => some (.external imported arguments)
  | .externalJump imported arguments => some (.external imported arguments)
  | .returned _ => some .returned
  | .checkedContinue valid _ => if valid then none else some .fault
  | _ => none

def relationalObservationsRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair) :
    Option RelationalObservable -> Option RelationalObservable -> Bool
  | none, none => true
  | some (.external originalImport originalArguments),
      some (.external candidateImport candidateArguments) =>
      originalImport == candidateImport &&
        wordsRelated originalImageBase candidateImageBase targets values
          originalArguments candidateArguments
  | some .returned, some .returned => true
  | some .fault, some .fault => true
  | _, _ => false

theorem relationalObservationsRelated_self (imageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (observation : Option RelationalObservable) :
    relationalObservationsRelated imageBase imageBase targets values
      observation observation = true := by
  cases observation with
  | none => rfl
  | some observation =>
      cases observation <;>
        simp [relationalObservationsRelated, wordsRelated_self]

theorem outcomesRelated_observation_eq
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : PureOutcome)
    (related : outcomesRelated originalImageBase candidateImageBase targets values
      original candidate = true) :
    original.observation = candidate.observation := by
  cases original <;> cases candidate <;>
    simp_all [outcomesRelated, PureOutcome.observation]

theorem outcomesRelated_nextLogicalTarget_eq
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : PureOutcome)
    (related : outcomesRelated originalImageBase candidateImageBase targets values
      original candidate = true) :
    original.nextLogicalTarget = candidate.nextLogicalTarget := by
  cases original <;> cases candidate <;>
    simp_all [outcomesRelated, PureOutcome.nextLogicalTarget]

theorem outcomesRelated_relationalObservation
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : PureOutcome)
    (related : outcomesRelated originalImageBase candidateImageBase targets values
      original candidate = true) :
    relationalObservationsRelated originalImageBase candidateImageBase targets values
      original.relationalObservation candidate.relationalObservation = true := by
  cases original <;> cases candidate <;>
    simp_all [outcomesRelated, PureOutcome.relationalObservation,
      relationalObservationsRelated]
  all_goals split <;> simp_all

structure Transition (state : Type) where
  next : state
  observation : Option Observable

structure TransitionSystem (state : Type) where
  step : state -> Transition state

def WeakBisimulation {originalState candidateState : Type}
    (original : TransitionSystem originalState) (candidate : TransitionSystem candidateState)
    (relation : originalState -> candidateState -> Prop) : Prop :=
  ∀ originalValue candidateValue,
    relation originalValue candidateValue ->
    (original.step originalValue).observation = (candidate.step candidateValue).observation ∧
    relation (original.step originalValue).next (candidate.step candidateValue).next

def trace {state : Type} (system : TransitionSystem state) : Nat -> state -> List Observable
  | 0, _ => []
  | fuel + 1, state =>
      let transition := system.step state
      transition.observation.toList ++ trace system fuel transition.next

theorem weakBisimulation_trace {originalState candidateState : Type}
    (original : TransitionSystem originalState) (candidate : TransitionSystem candidateState)
    (relation : originalState -> candidateState -> Prop)
    (bisimulation : WeakBisimulation original candidate relation) :
    ∀ fuel originalState candidateState,
      relation originalState candidateState ->
      trace original fuel originalState = trace candidate fuel candidateState := by
  intro fuel
  induction fuel with
  | zero => intro _ _ _; rfl
  | succ fuel ih =>
      intro originalState candidateState related
      have step := bisimulation originalState candidateState related
      change
        (original.step originalState).observation.toList ++
            trace original fuel (original.step originalState).next =
          (candidate.step candidateState).observation.toList ++
            trace candidate fuel (candidate.step candidateState).next
      rw [step.1]
      exact congrArg ((candidate.step candidateState).observation.toList ++ ·)
        (ih (original.step originalState).next (candidate.step candidateState).next step.2)

structure RelatedTransition (state observation : Type) where
  next : state
  observation : Option observation

structure RelatedTransitionSystem (state observation : Type) where
  step : state -> RelatedTransition state observation

def RelationalWeakBisimulation
    {originalState candidateState originalObservation candidateObservation : Type}
    (original : RelatedTransitionSystem originalState originalObservation)
    (candidate : RelatedTransitionSystem candidateState candidateObservation)
    (stateRelation : originalState -> candidateState -> Prop)
    (observationRelation : Option originalObservation -> Option candidateObservation -> Prop) : Prop :=
  ∀ originalValue candidateValue,
    stateRelation originalValue candidateValue ->
    observationRelation (original.step originalValue).observation
      (candidate.step candidateValue).observation ∧
    stateRelation (original.step originalValue).next (candidate.step candidateValue).next

def RelatedTrace
    {originalState candidateState originalObservation candidateObservation : Type}
    (original : RelatedTransitionSystem originalState originalObservation)
    (candidate : RelatedTransitionSystem candidateState candidateObservation)
    (stateRelation : originalState -> candidateState -> Prop)
    (observationRelation : Option originalObservation -> Option candidateObservation -> Prop) :
    Nat -> originalState -> candidateState -> Prop
  | 0, originalState, candidateState => stateRelation originalState candidateState
  | fuel + 1, originalState, candidateState =>
      observationRelation (original.step originalState).observation
          (candidate.step candidateState).observation ∧
        RelatedTrace original candidate stateRelation observationRelation fuel
          (original.step originalState).next (candidate.step candidateState).next

theorem relationalWeakBisimulation_trace
    {originalState candidateState originalObservation candidateObservation : Type}
    (original : RelatedTransitionSystem originalState originalObservation)
    (candidate : RelatedTransitionSystem candidateState candidateObservation)
    (stateRelation : originalState -> candidateState -> Prop)
    (observationRelation : Option originalObservation -> Option candidateObservation -> Prop)
    (bisimulation : RelationalWeakBisimulation original candidate stateRelation
      observationRelation) :
    ∀ fuel originalState candidateState,
      stateRelation originalState candidateState ->
      RelatedTrace original candidate stateRelation observationRelation fuel
        originalState candidateState := by
  intro fuel
  induction fuel with
  | zero =>
      intro originalState candidateState related
      exact related
  | succ fuel ih =>
      intro originalState candidateState related
      have step := bisimulation originalState candidateState related
      exact ⟨step.1, ih _ _ step.2⟩

def Memory.bulkCopyDwords (memory : Memory) (destination source : Word)
    (direction : Bool) : Nat -> Memory
  | 0 => memory
  | count + 1 =>
      let value := Memory.read32 memory source
      let nextMemory := memory.write32 destination value
      let distance := BitVec.ofNat 32 4
      let nextDestination := if direction then destination - distance else destination + distance
      let nextSource := if direction then source - distance else source + distance
      Memory.bulkCopyDwords nextMemory nextDestination nextSource direction count

def Memory.atomicCompareExchange (memory : Memory) (address expected replacement : Word) :
    Memory :=
  if Memory.read32 memory address == expected then
    memory.write32 address replacement
  else
    memory

structure RelationalExternalEvent where
  imported : ExternalTarget
  arguments : List Word
  state : MachineState

structure RelationalEnvironment where
  result : Nat -> RelationalExternalEvent -> MachineState

def RelationalEnvironmentsRegisterCompatible
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (regions : List RegionRelation)
    (original candidate : RelationalEnvironment) : Prop :=
  ∀ source target originalBehavior candidateBehavior eventIndex originalEvent candidateEvent,
    source ∈ regions → target ∈ regions →
    InvariantWP.ExternalRegisterPolicyEdgeClosed source target
      originalBehavior candidateBehavior →
    originalEvent.imported = candidateEvent.imported →
    wordsRelated originalImageBase candidateImageBase targets values
      originalEvent.arguments candidateEvent.arguments = true →
    registerRelationsHold originalImageBase candidateImageBase targets values
      target.inputRelations
      (original.result eventIndex originalEvent).registers
      (candidate.result eventIndex candidateEvent).registers = true

structure RelationalProgramSemantics where
  behavior : Nat -> MachineState -> Option RelationalBehavior
  resolveTarget : Word -> Option Nat
  resolveImportCall : Word -> MachineState -> Option (ExternalTarget × List Word)
  environment : RelationalEnvironment

def ImportAddressResolutionsValid (candidate : Bool) (world : RelationalWorld)
    (program : RelationalProgramSemantics) : Prop :=
  ∀ binding, binding ∈ world.importAddresses → ∀ state,
    ∃ arguments,
      program.resolveImportCall
        (if candidate then binding.candidateAddress else binding.originalAddress)
        state = some (binding.imported, arguments)

inductive RelationalExecution where
  | running (region : Nat) (state : MachineState) (calls : List Nat) (eventIndex : Nat)
  | returned (state : MachineState)
  | fault

def transitionFromOutcome (program : RelationalProgramSemantics)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat) :
    PureOutcome -> RelatedTransition RelationalExecution RelationalObservable
  | .returned target =>
      match calls with
      | [] => { next := .returned state, observation := some .returned }
      | continuation :: tail =>
          match program.resolveTarget target with
          | some resolved =>
              if resolved == continuation then
                { next := .running continuation state tail eventIndex, observation := none }
              else
                { next := .fault, observation := some .fault }
          | none => { next := .fault, observation := some .fault }
  | .jump target =>
      { next := .running target state calls eventIndex, observation := none }
  | .branch condition taken fallthrough =>
      { next := .running (if condition then taken else fallthrough) state calls eventIndex,
        observation := none }
  | .call target continuation =>
      { next := .running target state (continuation :: calls) eventIndex, observation := none }
  | .externalCall imported arguments continuation =>
      let event := { imported, arguments, state : RelationalExternalEvent }
      let result := program.environment.result eventIndex event
      { next := .running continuation result calls (eventIndex + 1),
        observation := some (.external imported arguments) }
  | .externalJump imported arguments =>
      let event := { imported, arguments, state : RelationalExternalEvent }
      let result := program.environment.result eventIndex event
      let next := match calls with
        | [] => RelationalExecution.returned result
        | continuation :: tail =>
            RelationalExecution.running continuation result tail (eventIndex + 1)
      { next, observation := some (.external imported arguments) }
  | .bulkCopy destination source count direction continuation =>
      let memory := Memory.bulkCopyDwords state.memory destination source direction count.toNat
      { next := .running continuation { state with memory } calls eventIndex,
        observation := none }
  | .indirectCall target continuation =>
      match program.resolveTarget target with
      | some resolved =>
          { next := .running resolved state (continuation :: calls) eventIndex,
            observation := none }
      | none =>
          match program.resolveImportCall target state with
          | some (imported, arguments) =>
              let event := { imported, arguments, state : RelationalExternalEvent }
              let result := program.environment.result eventIndex event
              { next := .running continuation result calls (eventIndex + 1),
                observation := some (.external imported arguments) }
          | none => { next := .fault, observation := some .fault }
  | .indirectJump target =>
      match program.resolveTarget target with
      | some resolved =>
          { next := .running resolved state calls eventIndex, observation := none }
      | none =>
          match program.resolveImportCall target state with
          | some (imported, arguments) =>
              let event := { imported, arguments, state : RelationalExternalEvent }
              let result := program.environment.result eventIndex event
              let next := match calls with
                | [] => RelationalExecution.returned result
                | continuation :: tail =>
                    RelationalExecution.running continuation result tail (eventIndex + 1)
              { next, observation := some (.external imported arguments) }
          | none => { next := .fault, observation := some .fault }
  | .checkedContinue valid continuation =>
      if valid then
        { next := .running continuation state calls eventIndex, observation := none }
      else
        { next := .fault, observation := some .fault }
  | .atomicCompareExchange address expected replacement continuation =>
      let memory := Memory.atomicCompareExchange state.memory address expected replacement
      { next := .running continuation { state with memory } calls eventIndex,
        observation := none }

def stepRelationalExecution (program : RelationalProgramSemantics) :
    RelationalExecution -> RelatedTransition RelationalExecution RelationalObservable
  | .running region state calls eventIndex =>
      match program.behavior region state with
      | none => { next := .fault, observation := some .fault }
      | some behavior =>
          transitionFromOutcome program (behavior.nextMachineState state) calls eventIndex
            behavior.outcome
  | .returned state => { next := .returned state, observation := none }
  | .fault => { next := .fault, observation := none }

def RelationalProgramSemantics.transitionSystem (program : RelationalProgramSemantics) :
    RelatedTransitionSystem RelationalExecution RelationalObservable := {
  step := stepRelationalExecution program
}

def decodedProgramSemantics (candidate : Bool) (pe : PE32) (imports : List PEImport)
    (regions : List RegionRelation) (environment : RelationalEnvironment) :
    RelationalProgramSemantics := {
  behavior := decodedRegionBehavior candidate pe imports regions
  resolveTarget := resolveMappedCodeTarget candidate pe.imageBase (allCodeTargets regions)
  resolveImportCall := fun _ _ => none
  environment
}

def regionMachineStatesRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (regions : List RegionRelation) (id : Nat)
    (original candidate : MachineState) : Prop :=
  match regionById regions id with
  | some region =>
      composableStatesRelated originalImageBase candidateImageBase targets
        region.flagInputs region.bounds region.addressSeparations values
        region.inputRelations original candidate
  | none => False

def executionsRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (regions : List RegionRelation)
    (terminalRelation : MachineState -> MachineState -> Prop) :
    RelationalExecution -> RelationalExecution -> Prop
  | .running originalRegion originalState originalCalls originalEventIndex,
      .running candidateRegion candidateState candidateCalls candidateEventIndex =>
      originalRegion = candidateRegion ∧ originalCalls = candidateCalls ∧
        originalEventIndex = candidateEventIndex ∧
        regionMachineStatesRelated originalImageBase candidateImageBase targets values regions
          originalRegion originalState candidateState
  | .returned originalState, .returned candidateState =>
      terminalRelation originalState candidateState
  | .fault, .fault => True
  | _, _ => False

def AllRunningTransitionsRelated
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop) : Prop :=
  ∀ region originalState candidateState calls eventIndex,
    regionMachineStatesRelated originalImageBase candidateImageBase targets values regions region
      originalState candidateState ->
    relationalObservationsRelated originalImageBase candidateImageBase targets values
        (stepRelationalExecution original
          (.running region originalState calls eventIndex)).observation
        (stepRelationalExecution candidate
          (.running region candidateState calls eventIndex)).observation = true ∧
      executionsRelated originalImageBase candidateImageBase targets values regions terminalRelation
        (stepRelationalExecution original
          (.running region originalState calls eventIndex)).next
        (stepRelationalExecution candidate
          (.running region candidateState calls eventIndex)).next

def RegionRunningTransitionRelated
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop)
    (region : RegionRelation) : Prop :=
  ∀ originalState candidateState calls eventIndex,
    composableStatesRelated originalImageBase candidateImageBase targets
      region.flagInputs region.bounds region.addressSeparations values
      region.inputRelations
      originalState candidateState ->
    relationalObservationsRelated originalImageBase candidateImageBase targets values
        (stepRelationalExecution original
          (.running region.id originalState calls eventIndex)).observation
        (stepRelationalExecution candidate
          (.running region.id candidateState calls eventIndex)).observation = true ∧
      executionsRelated originalImageBase candidateImageBase targets values regions terminalRelation
        (stepRelationalExecution original
          (.running region.id originalState calls eventIndex)).next
        (stepRelationalExecution candidate
          (.running region.id candidateState calls eventIndex)).next

def AllRegionRunningTransitionsRelated
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop) : Prop :=
  ∀ region, region ∈ regions ->
    RegionRunningTransitionRelated originalImageBase candidateImageBase regions targets values
      original candidate terminalRelation region

theorem allRunningTransitionsRelated_of_regions
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop)
    (checked : AllRegionRunningTransitionsRelated originalImageBase candidateImageBase
      regions targets values original candidate terminalRelation) :
    AllRunningTransitionsRelated originalImageBase candidateImageBase regions targets values
      original candidate terminalRelation := by
  intro id originalState candidateState calls eventIndex related
  unfold regionMachineStatesRelated at related
  cases found : regionById regions id with
  | none => simp [found] at related
  | some region =>
      have member : region ∈ regions := by
        unfold regionById at found
        exact List.mem_of_find?_eq_some found
      have idMatch : region.id = id := by
        unfold regionById at found
        have matched := List.find?_some found
        simpa only [beq_iff_eq] using matched
      subst id
      exact checked region member originalState candidateState calls eventIndex (by
        simpa [found] using related)

def WholeProgramBisimulation
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (executionRelation : RelationalExecution -> RelationalExecution -> Prop) : Prop :=
  RelationalWeakBisimulation original.transitionSystem candidate.transitionSystem
    executionRelation
    (fun originalObservation candidateObservation =>
      relationalObservationsRelated originalImageBase candidateImageBase targets values
        originalObservation candidateObservation = true)

theorem wholeProgramBisimulation_of_runningTransitions
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop)
    (running : AllRunningTransitionsRelated originalImageBase candidateImageBase regions
      targets values original candidate terminalRelation) :
    WholeProgramBisimulation originalImageBase candidateImageBase targets values
      original candidate
      (executionsRelated originalImageBase candidateImageBase targets values regions
        terminalRelation) := by
  intro originalExecution candidateExecution related
  cases originalExecution <;> cases candidateExecution <;>
    simp [executionsRelated] at related
  case running.running originalRegion originalState originalCalls originalEventIndex
      candidateRegion candidateState candidateCalls candidateEventIndex =>
    rcases related with ⟨regionEqual, callsEqual, eventIndexEqual, stateRelated⟩
    subst candidateRegion
    subst candidateCalls
    subst candidateEventIndex
    exact running originalRegion originalState candidateState originalCalls originalEventIndex
      stateRelated
  case returned.returned originalState candidateState =>
    exact ⟨rfl, related⟩
  case fault.fault =>
    exact ⟨rfl, trivial⟩

def WholeProgramTraceRelation
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (executionRelation : RelationalExecution -> RelationalExecution -> Prop) :
    Nat -> RelationalExecution -> RelationalExecution -> Prop :=
  RelatedTrace original.transitionSystem candidate.transitionSystem executionRelation
    (fun originalObservation candidateObservation =>
      relationalObservationsRelated originalImageBase candidateImageBase targets values
        originalObservation candidateObservation = true)

def WholeProgramObservationalEquivalence
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (initialRelation : MachineState -> MachineState -> Prop) : Prop :=
  ∃ executionRelation : RelationalExecution -> RelationalExecution -> Prop,
    (∀ entry originalState candidateState,
      initialRelation originalState candidateState ->
      executionRelation (.running entry originalState [] 0)
        (.running entry candidateState [] 0)) ∧
    WholeProgramBisimulation originalImageBase candidateImageBase targets values
      original candidate executionRelation

theorem wholeProgramObservationalEquivalence_self (imageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (program : RelationalProgramSemantics) :
    WholeProgramObservationalEquivalence imageBase imageBase targets values program program
      (fun original candidate => original = candidate) := by
  refine ⟨fun original candidate => original = candidate, ?_, ?_⟩
  · intro entry originalState candidateState related
    subst candidateState
    rfl
  · intro originalExecution candidateExecution related
    subst candidateExecution
    exact ⟨relationalObservationsRelated_self imageBase targets values _, rfl⟩

theorem wholeProgramObservationalEquivalence_trace
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (initialRelation : MachineState -> MachineState -> Prop)
    (equivalent : WholeProgramObservationalEquivalence originalImageBase candidateImageBase
      targets values original candidate initialRelation) :
    ∀ fuel entry originalState candidateState,
      initialRelation originalState candidateState ->
      ∃ executionRelation : RelationalExecution -> RelationalExecution -> Prop,
        WholeProgramTraceRelation originalImageBase candidateImageBase targets values
          original candidate executionRelation fuel
          (.running entry originalState [] 0) (.running entry candidateState [] 0) := by
  rcases equivalent with ⟨executionRelation, initial, bisimulation⟩
  intro fuel entry originalState candidateState related
  refine ⟨executionRelation, ?_⟩
  exact relationalWeakBisimulation_trace original.transitionSystem candidate.transitionSystem
    executionRelation
    (fun originalObservation candidateObservation =>
      relationalObservationsRelated originalImageBase candidateImageBase targets values
        originalObservation candidateObservation = true)
    bisimulation fuel _ _ (initial entry originalState candidateState related)

inductive IndexTree (α : Type) where
  | empty
  | leaf (value : α)
  | node (leftSize : Nat) (left right : IndexTree α)
deriving Repr, DecidableEq

namespace IndexTree

def size : IndexTree α -> Nat
  | .empty => 0
  | .leaf _ => 1
  | .node leftSize _ right => leftSize + right.size

def toList : IndexTree α -> List α
  | .empty => []
  | .leaf value => [value]
  | .node _ left right => left.toList ++ right.toList

def get? : IndexTree α -> Nat -> Option α
  | .empty, _ => none
  | .leaf value, 0 => some value
  | .leaf _, _ => none
  | .node leftSize left right, index =>
      if index < leftSize then left.get? index else right.get? (index - leftSize)

end IndexTree

structure SortedSpanCertificate where
  sorted : List Span := []
  sourceIndex : IndexTree Span := .empty
  sortedSourceIndices : List Nat := []
  sourceToSorted : IndexTree Nat := .empty
deriving Repr, DecidableEq

structure PaddingAliasCertificate where
  sorted : SortedSpanCertificate := {}
  runStops : IndexTree Nat := .empty
deriving Repr, DecidableEq

def sortedSpanEntriesValidAux (sourceIndex : IndexTree Span)
    (sourceToSorted : IndexTree Nat) :
    Nat -> List Span -> List Nat -> Bool
  | _, [], [] => true
  | ordinal, span :: spans, source :: sources =>
      sourceIndex.get? source == some span &&
        sourceToSorted.get? source == some ordinal &&
        sortedSpanEntriesValidAux sourceIndex sourceToSorted (ordinal + 1) spans sources
  | _, _, _ => false

def spansNondecreasing : List Span -> Bool
  | [] | [_] => true
  | left :: right :: tail =>
      left.start <= right.start && spansNondecreasing (right :: tail)

def sortedSpanCertificateValid (source : List Span)
    (certificate : SortedSpanCertificate) : Bool :=
  source == certificate.sourceIndex.toList &&
    certificate.sorted.length == source.length &&
    certificate.sortedSourceIndices.length == source.length &&
    certificate.sourceToSorted.size == source.length &&
    spansNondecreasing certificate.sorted &&
    sortedSpanEntriesValidAux certificate.sourceIndex certificate.sourceToSorted 0
      certificate.sorted certificate.sortedSourceIndices

def executableCoverageCertified (pe : PE32) (source : List Span)
    (certificate : SortedSpanCertificate) : Bool :=
  sortedSpanCertificateValid source certificate &&
    certificate.sorted.all (spanInExecutableSection pe) &&
    (pe.sections.filter (fun sec => sec.executable)).all (fun sec =>
      spansCoverFrom sec.virtualAddress (sec.virtualAddress + sec.mappedSize)
        (spansInSection sec certificate.sorted))

def paddingRunsValidAux (runStops : IndexTree Nat) : List Span -> List Nat -> Bool
  | [], [] => true
  | [span], [source] => runStops.get? source == some span.stop
  | span :: next :: spans, source :: nextSource :: sources =>
      span.stop <= next.start &&
        runStops.get? source ==
          (if span.stop == next.start then runStops.get? nextSource else some span.stop) &&
        paddingRunsValidAux runStops (next :: spans) (nextSource :: sources)
  | _, _ => false

def paddingAliasCertificateValid (padding : List Span)
    (certificate : PaddingAliasCertificate) : Bool :=
  sortedSpanCertificateValid padding certificate.sorted &&
    certificate.runStops.size == padding.length &&
    paddingRunsValidAux certificate.runStops certificate.sorted.sorted
      certificate.sorted.sortedSourceIndices

def codeAliasClosed (padding : IndexTree Span) (runStops : IndexTree Nat)
    (canonical : Nat) (alias : CodeAlias) : Bool :=
  match padding.get? alias.paddingIndex, runStops.get? alias.paddingIndex with
  | some span, some stop =>
      span.start == alias.rva && alias.rva < canonical && stop == canonical
  | _, _ => false

def targetAliasesCertified (regions : List RegionRelation)
    (original candidate : PaddingAliasCertificate) : Bool :=
  regions.all fun region => region.targets.all fun target =>
    target.originalAliases.all
      (codeAliasClosed original.sorted.sourceIndex original.runStops target.originalRva) &&
    target.candidateAliases.all
      (codeAliasClosed candidate.sorted.sourceIndex candidate.runStops target.candidateRva)

structure ProofBundle where
  originalBytes : ByteTree
  candidateBytes : ByteTree
  originalImports : ImportTableCertificate
  candidateImports : ImportTableCertificate
  machineImportCallContracts : List MachineImportCallContract := []
  regions : List RegionRelation
  regionIndex : IndexTree RegionRelation := .empty
  originalPadding : List Span
  candidatePadding : List Span
  originalCoverage : SortedSpanCertificate := {}
  candidateCoverage : SortedSpanCertificate := {}
  originalAliasCoverage : PaddingAliasCertificate := {}
  candidateAliasCoverage : PaddingAliasCertificate := {}
deriving Repr, DecidableEq

def parsedImages (bundle : ProofBundle) : Option (PE32 × PE32) := do
  pure (← parsePE32Tree bundle.originalBytes, ← parsePE32Tree bundle.candidateBytes)

def entryRegionMatches (originalPe candidatePe : PE32) (region : RegionRelation) : Bool :=
  region.root && region.original.start == originalPe.entrypointRva &&
    region.candidate.start == candidatePe.entrypointRva

def targetPairClosed (regions : IndexTree RegionRelation) (target : CodeTargetPair) : Bool :=
  match regions.get? target.regionIndex with
  | some region =>
      region.id == target.id && region.original.start == target.originalRva &&
        region.candidate.start == target.candidateRva
  | none => false

def targetCoverageClosed (index : IndexTree RegionRelation) (regions : List RegionRelation) : Bool :=
  regions.all fun region => region.targets.all (targetPairClosed index)

def paddingAliasValid (padding : List Span) (alias canonical : Nat) : Bool :=
  alias < canonical &&
    spansCoverFrom alias canonical (sortSpans (padding.filter fun span =>
      alias <= span.start && span.stop <= canonical))

def targetAliasesClosed (regions : List RegionRelation)
    (originalPadding candidatePadding : List Span) : Bool :=
  regions.all fun region => region.targets.all fun target =>
    target.originalAliases.all (fun alias =>
      paddingAliasValid originalPadding alias.rva target.originalRva) &&
    target.candidateAliases.all (fun alias =>
      paddingAliasValid candidatePadding alias.rva target.candidateRva)

def relocationContains (relocations : List BaseRelocation) (rva : Nat) : Bool :=
  relocations.any fun relocation => relocation.rva == rva && relocation.kind == 3

def relocationCount (relocations : List BaseRelocation) (rva : Nat) : Nat :=
  (relocations.filter fun relocation => relocation.rva == rva && relocation.kind == 3).length

def relocationOffsetsStrictlyIncreasing : List Nat -> Bool
  | [] | [_] => true
  | left :: right :: tail => left < right && relocationOffsetsStrictlyIncreasing (right :: tail)

def relocationOffsetsValid (object : ValueTargetPair) : Bool :=
  relocationOffsetsStrictlyIncreasing object.relocationOffsets &&
    object.relocationOffsets.all fun offset =>
      offset % 4 == 0 && offset + 4 <= object.mappedSize

def mappedObjectContentValidAux (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (object : ValueTargetPair) : Nat -> Nat -> Bool
  | _, 0 => false
  | offset, fuel + 1 =>
      if offset == object.mappedSize then true
      else if object.mappedSize < offset then false
      else
        let originalRva := object.originalValue - originalPe.imageBase + offset
        let candidateRva := object.candidateValue - candidatePe.imageBase + offset
        let declaredRelocated := object.relocationOffsets.contains offset
        let declaredCount := if declaredRelocated then 1 else 0
        if relocationCount originalRelocations originalRva != declaredCount ||
            relocationCount candidateRelocations candidateRva != declaredCount then false
        else if declaredRelocated then
          object.mappedSize - offset >= 4 &&
            match readRvaU32 originalPe originalRva, readRvaU32 candidatePe candidateRva with
            | some original, some candidate =>
                wordRelated originalPe.imageBase candidatePe.imageBase targets values
                  (BitVec.ofNat 32 original) (BitVec.ofNat 32 candidate) &&
                mappedObjectContentValidAux originalPe candidatePe originalRelocations
                  candidateRelocations targets values object (offset + 4) fuel
            | _, _ => false
        else
          rvaByte originalPe originalRva == rvaByte candidatePe candidateRva &&
            mappedObjectContentValidAux originalPe candidatePe originalRelocations
              candidateRelocations targets values object (offset + 1) fuel

def mappedObjectContentValid (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (object : ValueTargetPair) : Bool :=
  relocationOffsetsValid object &&
    (object.mappedSize == 0 || mappedObjectContentValidAux originalPe candidatePe
      originalRelocations candidateRelocations targets values object 0 (object.mappedSize + 1))

def valueTargetValid (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (target : ValueTargetPair) : Bool :=
  relocationContains originalRelocations target.originalRelocationRva &&
  relocationContains candidateRelocations target.candidateRelocationRva &&
  readRvaU32 originalPe target.originalRelocationRva == some target.originalValue &&
  readRvaU32 candidatePe target.candidateRelocationRva == some target.candidateValue &&
  (target.mappedSize == 0 ||
    (originalPe.imageBase <= target.originalValue &&
      candidatePe.imageBase <= target.candidateValue &&
      originalPe.sections.any (fun sec =>
        sec.virtualAddress <= target.originalValue - originalPe.imageBase &&
          target.originalValue - originalPe.imageBase + target.mappedSize <=
            sec.virtualAddress + sec.mappedSize) &&
      candidatePe.sections.any (fun sec =>
        sec.virtualAddress <= target.candidateValue - candidatePe.imageBase &&
          target.candidateValue - candidatePe.imageBase + target.mappedSize <=
            sec.virtualAddress + sec.mappedSize))) &&
  mappedObjectContentValid originalPe candidatePe originalRelocations candidateRelocations
    targets values target

def valueTargetPairCompatible (left right : ValueTargetPair) : Bool :=
  left.id == right.id || left.mappedSize == 0 || right.mappedSize == 0 ||
    ((left.originalValue + left.mappedSize <= right.originalValue ||
        right.originalValue + right.mappedSize <= left.originalValue) &&
      (left.candidateValue + left.mappedSize <= right.candidateValue ||
        right.candidateValue + right.mappedSize <= left.candidateValue)) ||
    left.originalValue + right.candidateValue ==
      right.originalValue + left.candidateValue

def valueTargetSpansCompatible (targets : List ValueTargetPair) : Bool :=
  targets.all fun left => targets.all (valueTargetPairCompatible left)

def valueRegionClosed (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (region : RegionRelation) : Bool :=
  valueTargetSpansCompatible region.values && region.values.all
    (valueTargetValid originalPe candidatePe originalRelocations candidateRelocations
      region.targets region.values)

def valueRegionsClosed (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (regions : List RegionRelation) : Bool :=
  regions.all (valueRegionClosed originalPe candidatePe originalRelocations candidateRelocations)

def AllMappedRelocationImageRelations (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (regions : List RegionRelation) : Prop :=
  ∀ region, region ∈ regions →
    ∀ object, object ∈ region.values →
      object.mappedSize > 0 → object.relocationOffsets ≠ [] →
        valueTargetValid originalPe candidatePe originalRelocations candidateRelocations
          region.targets region.values object = true

theorem allMappedRelocationImageRelations_of_valueRegionsClosed
    (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (regions : List RegionRelation)
    (checked : valueRegionsClosed originalPe candidatePe originalRelocations
      candidateRelocations regions = true) :
    AllMappedRelocationImageRelations originalPe candidatePe originalRelocations
      candidateRelocations regions := by
  intro region regionMember object objectMember _ _
  unfold valueRegionsClosed at checked
  simp only [List.all_eq_true] at checked
  have regionChecked := checked region regionMember
  unfold valueRegionClosed at regionChecked
  simp only [Bool.and_eq_true] at regionChecked
  have objectsChecked := regionChecked.2
  simp only [List.all_eq_true] at objectsChecked
  exact objectsChecked object objectMember

def valueTargetsClosed (originalPe candidatePe : PE32) (regions : List RegionRelation) : Bool :=
  match parseRelocations originalPe, parseRelocations candidatePe with
  | some originalRelocations, some candidateRelocations =>
      valueRegionsClosed originalPe candidatePe originalRelocations candidateRelocations regions
  | _, _ => false

def StaticProofContext.dataMappingsValid (context : StaticProofContext) : Bool :=
  context.dataMap.entries.toList.all
    (valueTargetValid context.originalPe context.candidatePe
      context.originalRelocations context.candidateRelocations
      context.codeMap.entries.toList context.dataMap.entries.toList)

def staticDataUsageWitnessValid (context : StaticProofContext)
    (regions : Array RegionRelation) (witnesses : Array Nat) : Bool :=
  witnesses.size == context.dataMap.entries.size &&
    (List.range context.dataMap.entries.size).all fun targetId =>
      match context.dataMap.get? targetId, witnesses[targetId]? with
      | some target, some regionId =>
          match regions[regionId]? with
          | some region => region.values.contains target
          | none => false
      | _, _ => false

def StaticDataUsageWitnessValid (context : StaticProofContext)
    (regions : Array RegionRelation) (witnesses : Array Nat) : Prop :=
  staticDataUsageWitnessValid context regions witnesses = true

theorem staticDataUsageWitnessValid_of_checked (context : StaticProofContext)
    (regions : Array RegionRelation) (witnesses : Array Nat)
    (checked : staticDataUsageWitnessValid context regions witnesses = true) :
    StaticDataUsageWitnessValid context regions witnesses :=
  checked

theorem valueTargetsClosed_of_parsed (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (regions : List RegionRelation)
    (originalParsed : parseRelocations originalPe = some originalRelocations)
    (candidateParsed : parseRelocations candidatePe = some candidateRelocations)
    (regionsChecked : valueRegionsClosed originalPe candidatePe originalRelocations
      candidateRelocations regions = true) :
    valueTargetsClosed originalPe candidatePe regions = true := by
  simp [valueTargetsClosed, originalParsed, candidateParsed, regionsChecked]

def insertRegisterPair (pairs : List RegisterPair) (pair : RegisterPair) : List RegisterPair :=
  if pairs.contains pair then pairs else pair :: pairs

def requiredInputPairsFrom (initial : List RegisterPair)
    (regions : List RegionRelation) : List RegisterPair :=
  regions.foldl (fun pairs region => region.inputs.foldl insertRegisterPair pairs) initial

def requiredInputPairs (regions : List RegionRelation) : List RegisterPair :=
  requiredInputPairsFrom [] regions

theorem requiredInputPairsFrom_append (initial : List RegisterPair)
    (left right : List RegionRelation) :
    requiredInputPairsFrom initial (left ++ right) =
      requiredInputPairsFrom (requiredInputPairsFrom initial left) right := by
  simp [requiredInputPairsFrom, List.foldl_append]

def relationCompositionClosed (regions : List RegionRelation) : Bool :=
  let required := requiredInputPairs regions
  regions.all fun source => required.all source.outputs.contains

def targetFlagRelationClosed (regions : IndexTree RegionRelation)
    (source : RegionRelation) (target : CodeTargetPair) : Bool :=
  match regions.get? target.regionIndex with
  | some destination => destination.flagInputs.all source.flagOutputs.contains
  | none => false

def flagRelationCompositionClosed (index : IndexTree RegionRelation)
    (regions : List RegionRelation) : Bool :=
  regions.all fun source => source.targets.all (targetFlagRelationClosed index source)

theorem relationCompositionClosed_of_certificate
    (regions : List RegionRelation) (required : List RegisterPair)
    (requiredChecked : requiredInputPairs regions = required)
    (outputsChecked : regions.all (fun source => required.all source.outputs.contains) = true) :
    relationCompositionClosed regions = true := by
  simp [relationCompositionClosed, requiredChecked, outputsChecked]

def imageStructureClosed (originalPe candidatePe : PE32) : Bool :=
  (executableEntrySection originalPe).isSome &&
    (executableEntrySection candidatePe).isSome

def regionStructureItemsClosed (originalPe candidatePe : PE32)
    (regions : List RegionRelation) : Bool :=
  regions.all (fun region =>
    spanInExecutableSection originalPe region.original &&
    spanInExecutableSection candidatePe region.candidate &&
    region.inputs.length > 0 && region.outputs.length > 0)

def regionStructureClosed (originalPe candidatePe : PE32)
    (regions : List RegionRelation) : Bool :=
  regions.length > 0 && regionStructureItemsClosed originalPe candidatePe regions

def regionIndexClosed (regions : List RegionRelation)
    (index : IndexTree RegionRelation) : Bool :=
  regions == index.toList

def paddingBytesClosed (pe : PE32) (padding : List Span) : Bool :=
  padding.all (paddingSpanValid pe)

def entryRootClosed (originalPe candidatePe : PE32)
    (regions : List RegionRelation) : Bool :=
  regions.any (entryRegionMatches originalPe candidatePe)

theorem listAllAppendTrue (predicate : α -> Bool) (left right : List α)
    (leftChecked : left.all predicate = true)
    (rightChecked : right.all predicate = true) :
    (left ++ right).all predicate = true := by
  simp [leftChecked, rightChecked]

def structuralEligible (bundle : ProofBundle) : Bool :=
  match parsedImages bundle with
  | none => false
  | some (originalPe, candidatePe) =>
      imageStructureClosed originalPe candidatePe &&
      regionIndexClosed bundle.regions bundle.regionIndex &&
      regionStructureClosed originalPe candidatePe bundle.regions &&
      executableCoverageCertified originalPe
        (bundle.regions.map (fun region => region.original) ++ bundle.originalPadding)
        bundle.originalCoverage &&
      executableCoverageCertified candidatePe
        (bundle.regions.map (fun region => region.candidate) ++ bundle.candidatePadding)
        bundle.candidateCoverage &&
      paddingBytesClosed originalPe bundle.originalPadding &&
      paddingBytesClosed candidatePe bundle.candidatePadding &&
      entryRootClosed originalPe candidatePe bundle.regions &&
      targetCoverageClosed bundle.regionIndex bundle.regions &&
      paddingAliasCertificateValid bundle.originalPadding bundle.originalAliasCoverage &&
      paddingAliasCertificateValid bundle.candidatePadding bundle.candidateAliasCoverage &&
      targetAliasesCertified bundle.regions bundle.originalAliasCoverage
        bundle.candidateAliasCoverage &&
      valueTargetsClosed originalPe candidatePe bundle.regions &&
      relationCompositionClosed bundle.regions &&
      flagRelationCompositionClosed bundle.regionIndex bundle.regions

theorem structuralEligible_of_checks (bundle : ProofBundle)
    (originalPe candidatePe : PE32)
    (originalParsed : parsePE32Tree bundle.originalBytes = some originalPe)
    (candidateParsed : parsePE32Tree bundle.candidateBytes = some candidatePe)
    (imagesChecked : imageStructureClosed originalPe candidatePe = true)
    (indexChecked : regionIndexClosed bundle.regions bundle.regionIndex = true)
    (regionsChecked : regionStructureClosed originalPe candidatePe bundle.regions = true)
    (originalCoverageChecked : executableCoverageCertified originalPe
      (bundle.regions.map (fun region => region.original) ++ bundle.originalPadding)
      bundle.originalCoverage = true)
    (candidateCoverageChecked : executableCoverageCertified candidatePe
      (bundle.regions.map (fun region => region.candidate) ++ bundle.candidatePadding)
      bundle.candidateCoverage = true)
    (originalPaddingChecked : paddingBytesClosed originalPe bundle.originalPadding = true)
    (candidatePaddingChecked : paddingBytesClosed candidatePe bundle.candidatePadding = true)
    (entryChecked : entryRootClosed originalPe candidatePe bundle.regions = true)
    (targetsChecked : targetCoverageClosed bundle.regionIndex bundle.regions = true)
    (originalAliasCoverageChecked :
      paddingAliasCertificateValid bundle.originalPadding bundle.originalAliasCoverage = true)
    (candidateAliasCoverageChecked :
      paddingAliasCertificateValid bundle.candidatePadding bundle.candidateAliasCoverage = true)
    (targetAliasesChecked : targetAliasesCertified bundle.regions
      bundle.originalAliasCoverage bundle.candidateAliasCoverage = true)
    (valuesChecked : valueTargetsClosed originalPe candidatePe bundle.regions = true)
    (compositionChecked : relationCompositionClosed bundle.regions = true)
    (flagCompositionChecked :
      flagRelationCompositionClosed bundle.regionIndex bundle.regions = true) :
    structuralEligible bundle = true := by
  unfold structuralEligible parsedImages
  rw [originalParsed, candidateParsed]
  simp [imagesChecked, indexChecked, regionsChecked, originalCoverageChecked,
    candidateCoverageChecked, originalPaddingChecked, candidatePaddingChecked,
    entryChecked, targetsChecked, originalAliasCoverageChecked,
    candidateAliasCoverageChecked, targetAliasesChecked, valuesChecked,
    compositionChecked, flagCompositionChecked]

def regionGoal (bundle : ProofBundle) (region : RegionRelation) : Prop :=
  match parsedImages bundle with
  | some (originalPe, candidatePe) =>
      regionEquivalentWithImports originalPe candidatePe bundle.originalImports.imports
        bundle.candidateImports.imports bundle.machineImportCallContracts region
  | none => False

def allRegionGoals (bundle : ProofBundle) : List RegionRelation -> Prop
  | [] => True
  | region :: tail => regionGoal bundle region ∧ allRegionGoals bundle tail

def allDirectRegionGoals (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (machineCallContracts : List MachineImportCallContract) : List RegionRelation -> Prop
  | [] => True
  | region :: tail =>
      regionEquivalentWithImports originalPe candidatePe originalImports candidateImports
          machineCallContracts region ∧
        allDirectRegionGoals originalPe candidatePe originalImports candidateImports
          machineCallContracts tail

theorem allDirectRegionGoals_append (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (machineCallContracts : List MachineImportCallContract) (left right : List RegionRelation)
    (leftChecked : allDirectRegionGoals originalPe candidatePe originalImports
      candidateImports machineCallContracts left)
    (rightChecked : allDirectRegionGoals originalPe candidatePe originalImports
      candidateImports machineCallContracts right) :
    allDirectRegionGoals originalPe candidatePe originalImports candidateImports
      machineCallContracts (left ++ right) := by
  induction left with
  | nil => simpa [allDirectRegionGoals] using rightChecked
  | cons region tail ih =>
      exact ⟨leftChecked.1, ih leftChecked.2⟩

theorem allRegionGoals_of_direct_for (bundle : ProofBundle)
    (originalPe candidatePe : PE32)
    (originalParsed : parsePE32Tree bundle.originalBytes = some originalPe)
    (candidateParsed : parsePE32Tree bundle.candidateBytes = some candidatePe) :
    ∀ regions,
      allDirectRegionGoals originalPe candidatePe bundle.originalImports.imports
        bundle.candidateImports.imports bundle.machineImportCallContracts regions ->
      allRegionGoals bundle regions := by
  intro regions
  induction regions with
  | nil => intro _; trivial
  | cons region tail ih =>
      intro direct
      constructor
      · unfold regionGoal parsedImages
        rw [originalParsed, candidateParsed]
        exact direct.1
      · exact ih direct.2

theorem allRegionGoals_of_direct (bundle : ProofBundle)
    (originalPe candidatePe : PE32)
    (originalParsed : parsePE32Tree bundle.originalBytes = some originalPe)
    (candidateParsed : parsePE32Tree bundle.candidateBytes = some candidatePe)
    (direct : allDirectRegionGoals originalPe candidatePe bundle.originalImports.imports
      bundle.candidateImports.imports bundle.machineImportCallContracts bundle.regions) :
    allRegionGoals bundle bundle.regions :=
  allRegionGoals_of_direct_for bundle originalPe candidatePe originalParsed candidateParsed
    bundle.regions direct

def importTablesCertified (bundle : ProofBundle) : Prop :=
  match parsedImages bundle with
  | some (originalPe, candidatePe) =>
      importTableValid originalPe bundle.originalImports = true ∧
        importTableValid candidatePe bundle.candidateImports = true
  | none => False

def RelationalImageCertificate (bundle : ProofBundle) : Prop :=
  structuralEligible bundle = true ∧
  importTablesCertified bundle ∧
  allRegionGoals bundle bundle.regions

theorem relationalImageCertificate_intro (bundle : ProofBundle)
    (structural : structuralEligible bundle = true)
    (imports : importTablesCertified bundle)
    (regions : allRegionGoals bundle bundle.regions) :
    RelationalImageCertificate bundle :=
  And.intro structural (And.intro imports regions)

end StageA.Relational
