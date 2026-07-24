
import StageA.RelationalMachine
import StageA.RelationalX87
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
  | .callUnmappedReturn target => .callUnmappedReturn target
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
  x87Fault := none
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

@[simp] theorem NormalizedSymbolicBehavior.eval_x87Effect (state : MachineState)
    (behavior : NormalizedSymbolicBehavior) :
    (behavior.eval state).x87Effect = none := rfl

@[simp] theorem NormalizedSymbolicBehavior.eval_x87Fault (state : MachineState)
    (behavior : NormalizedSymbolicBehavior) :
    (behavior.eval state).x87Fault = none := rfl

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

theorem NormalizedSymbolicBehavior.eval_flag_eq_of_some_field
    (behavior : NormalizedSymbolicBehavior) (flags : FlagsExpr)
    (value : Option BoolExpr) (original candidate : MachineState) (bit : Nat)
    (behaviorFlags : behavior.flags = some flags)
    (fieldEvaluation : forall state,
      (flags.eval state).extractLsb' bit 1 = evalFlagBit state bit value)
    (related : evalFlagBit original bit value = evalFlagBit candidate bit value) :
    (behavior.eval original).eflags.extractLsb' bit 1 =
      (behavior.eval candidate).eflags.extractLsb' bit 1 := by
  simp only [NormalizedSymbolicBehavior.eval_eflags, behaviorFlags,
    evalNormalizedFlags_some]
  rw [fieldEvaluation original, fieldEvaluation candidate]
  exact related

def codeAddressMatches (imageBase primaryRva : Nat) (aliases : List CodeAlias) (value : Word) : Bool :=
  value == BitVec.ofNat 32 (imageBase + primaryRva) ||
    aliases.any fun alias => value == BitVec.ofNat 32 (imageBase + alias.rva)

def codePointerRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (original candidate : Word) : Bool :=
  targets.any fun target =>
    codeAddressMatches originalImageBase target.originalRva target.originalAliases original &&
    codeAddressMatches candidateImageBase target.candidateRva target.candidateAliases candidate

def fixedCodePointerRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (targetId : Nat)
    (original candidate : Word) : Bool :=
  match targets[targetId]? with
  | none => false
  | some target =>
      target.id == targetId &&
        (codeAddressMatches originalImageBase target.originalRva target.originalAliases original &&
          codeAddressMatches candidateImageBase target.candidateRva target.candidateAliases candidate)

theorem fixedCodePointerRelated_codePointerRelated
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (targetId : Nat)
    (original candidate : Word)
    (fixed : fixedCodePointerRelated originalImageBase candidateImageBase targets targetId
      original candidate = true) :
    codePointerRelated originalImageBase candidateImageBase targets
      original candidate = true := by
  unfold fixedCodePointerRelated at fixed
  cases targetResult : targets[targetId]? with
  | none => simp [targetResult] at fixed
  | some target =>
      simp only [targetResult, Bool.and_eq_true] at fixed
      simp only [codePointerRelated, List.any_eq_true]
      refine ⟨target, List.mem_of_getElem? targetResult, ?_⟩
      simp only [Bool.and_eq_true]
      exact fixed.2

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

theorem normalizeDataAddress_eq_self_of_identity_targets
    (targets : List ValueTargetPair) (address : Word)
    (identity : forall target, target ∈ targets ->
      target.originalValue = target.candidateValue) :
    normalizeDataAddress targets address = address := by
  unfold normalizeDataAddress
  cases found : targets.find? (valueTargetContainsCandidate · address) with
  | none => rfl
  | some target =>
      have member : target ∈ targets := List.mem_of_find?_eq_some found
      change BitVec.ofNat 32 target.originalValue +
        (address - BitVec.ofNat 32 target.candidateValue) = address
      rw [identity target member]
      rw [BitVec.add_comm, BitVec.sub_add_cancel]

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
  have targetMember : target ∈ context.codeMap.entries.toList :=
    FiniteIndex.get?_eq_some_implies_mem_toList
      context.codeMap.entries targetId target targetFound
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
      target.id == targetId &&
        ((codeAddressMatches context.originalPe.imageBase target.originalRva
              target.originalAliases original &&
            codeAddressMatches context.candidatePe.imageBase target.candidateRva
              target.candidateAliases candidate) &&
          fixedCodePointerRelated context.originalPe.imageBase
            context.candidatePe.imageBase context.codeMap.entries.toList targetId
            original candidate)

theorem codeTargetAddressPairMatches_fixedCodePointerRelated
    (context : StaticProofContext) (targetId : Nat) (original candidate : Word)
    (matchEvidence :
      codeTargetAddressPairMatches context targetId original candidate = true) :
    fixedCodePointerRelated context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList targetId
      original candidate = true := by
  cases targetResult : context.codeMap.get? targetId with
  | none => simp [codeTargetAddressPairMatches, targetResult] at matchEvidence
  | some target =>
      simp only [codeTargetAddressPairMatches, targetResult, Bool.and_eq_true,
        beq_iff_eq] at matchEvidence
      exact matchEvidence.2.2

theorem codeTargetIdAddresses_codePointerRelated
    (context : StaticProofContext) (targetId : Nat) (original candidate : Word)
    (matchEvidence : codeTargetAddressPairMatches context targetId original candidate = true) :
    codePointerRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList original candidate = true := by
  cases targetResult : context.codeMap.get? targetId with
  | none => simp [codeTargetAddressPairMatches, targetResult] at matchEvidence
  | some target =>
      simp only [codeTargetAddressPairMatches, targetResult, Bool.and_eq_true,
        beq_iff_eq] at matchEvidence
      exact fixedCodePointerRelated_codePointerRelated
        context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList targetId original candidate
        matchEvidence.2.2

theorem codeTargetIdAddresses_wordRelated
    (context : StaticProofContext) (world : RelationalWorld)
    (targetId : Nat) (original candidate : Word)
    (matchEvidence : codeTargetAddressPairMatches context targetId original candidate = true)
    (zeroesAgree : (original == BitVec.ofNat 32 0) =
      (candidate == BitVec.ofNat 32 0)) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      original candidate = true := by
  have codeRelated := codeTargetIdAddresses_codePointerRelated context targetId
    original candidate matchEvidence
  simp [wordRelated, zeroesAgree, codeRelated]

def dataTargetAddressPairMatches (context : StaticProofContext) (targetId : Nat)
    (original candidate : Word) : Bool :=
  match context.dataMap.get? targetId with
  | none => false
  | some target =>
      original == BitVec.ofNat 32 target.originalValue &&
        candidate == BitVec.ofNat 32 target.candidateValue

theorem dataTargetIdAddresses_mappedValueRelated
    (context : StaticProofContext) (world : RelationalWorld)
    (targetId : Nat) (original candidate : Word)
    (matchEvidence : dataTargetAddressPairMatches context targetId original candidate = true) :
    mappedValueRelated (context.relationalValueTargets world) original candidate = true := by
  unfold dataTargetAddressPairMatches at matchEvidence
  cases targetResult : context.dataMap.get? targetId with
  | none => simp [targetResult] at matchEvidence
  | some target =>
      simp only [targetResult, Bool.and_eq_true, beq_iff_eq] at matchEvidence
      have targetArrayMember : target ∈ context.dataMap.entries := by
        have indexed := Array.getElem?_eq_some_iff.mp targetResult
        rcases indexed with ⟨inside, indexed⟩
        have member := Array.getElem_mem inside
        rw [indexed] at member
        exact member
      have targetMember : target ∈ context.dataMap.entries.toList :=
        Array.mem_def.mp targetArrayMember
      simp only [StaticProofContext.relationalValueTargets, mappedValueRelated,
        List.any_eq_true]
      refine ⟨target, List.mem_append_left _ (List.mem_append_left _ targetMember), ?_⟩
      by_cases zero : target.mappedSize = 0 <;>
        simp [zero, matchEvidence.1, matchEvidence.2]

theorem dataTargetIdAddresses_wordRelated
    (context : StaticProofContext) (world : RelationalWorld)
    (targetId : Nat) (original candidate : Word)
    (matchEvidence : dataTargetAddressPairMatches context targetId original candidate = true)
    (zeroesAgree : (original == BitVec.ofNat 32 0) =
      (candidate == BitVec.ofNat 32 0)) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      original candidate = true := by
  unfold dataTargetAddressPairMatches at matchEvidence
  cases targetResult : context.dataMap.get? targetId with
  | none => simp [targetResult] at matchEvidence
  | some target =>
      simp only [targetResult, Bool.and_eq_true] at matchEvidence
      have targetArrayMember : target ∈ context.dataMap.entries := by
        have indexed := Array.getElem?_eq_some_iff.mp targetResult
        rcases indexed with ⟨inside, indexed⟩
        have member := Array.getElem_mem inside
        rw [indexed] at member
        exact member
      have targetMember : target ∈ context.dataMap.entries.toList :=
        Array.mem_def.mp targetArrayMember
      have mapped : mappedValueRelated (context.relationalValueTargets world)
          original candidate = true := by
        simp only [StaticProofContext.relationalValueTargets, mappedValueRelated,
          List.any_eq_true]
        refine ⟨target, List.mem_append_left _ (List.mem_append_left _ targetMember), ?_⟩
        by_cases zero : target.mappedSize = 0 <;>
          simp [zero, matchEvidence.1, matchEvidence.2]
      simp [wordRelated, zeroesAgree, mapped]

def Memory.read32 (memory : Memory) (address : Word) : Word :=
  let b0 := BitVec.zeroExtend 32 (memory address)
  let b1 := (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 1))).shiftLeft 8
  let b2 := (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 2))).shiftLeft 16
  let b3 := (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 3))).shiftLeft 24
  b0 ||| b1 ||| b2 ||| b3

theorem fourBytesAssembleLittleEndian (byte0 byte1 byte2 byte3 : Nat)
    (byte0Bound : byte0 < 256) (byte1Bound : byte1 < 256)
    (byte2Bound : byte2 < 256) (byte3Bound : byte3 < 256) :
    BitVec.setWidth 32 (BitVec.ofNat 8 byte0) |||
          (BitVec.setWidth 32 (BitVec.ofNat 8 byte1)).shiftLeft 8 |||
        (BitVec.setWidth 32 (BitVec.ofNat 8 byte2)).shiftLeft 16 |||
      (BitVec.setWidth 32 (BitVec.ofNat 8 byte3)).shiftLeft 24 =
        BitVec.ofNat 32
          (byte0 + byte1 * 256 + byte2 * 65536 + byte3 * 16777216) := by
  apply BitVec.eq_of_toNat_eq
  simp only [BitVec.toNat_or, BitVec.shiftLeft, BitVec.toNat_setWidth,
    BitVec.toNat_ofNat, Nat.shiftLeft_eq]
  have pow8 : 2 ^ 8 = 256 := by decide
  have pow16 : 2 ^ 16 = 65536 := by decide
  have pow24 : 2 ^ 24 = 16777216 := by decide
  have pow32 : 2 ^ 32 = 4294967296 := by decide
  rw [pow8, pow16, pow24, pow32]
  have byte0Large : byte0 < 4294967296 := Nat.lt_trans byte0Bound (by decide)
  have byte1Large : byte1 < 4294967296 := Nat.lt_trans byte1Bound (by decide)
  have byte2Large : byte2 < 4294967296 := Nat.lt_trans byte2Bound (by decide)
  have byte3Large : byte3 < 4294967296 := Nat.lt_trans byte3Bound (by decide)
  have byte1Shift : byte1 * 256 < 4294967296 := by
    have scaled := Nat.mul_lt_mul_of_pos_right byte1Bound (by decide : 0 < 256)
    exact Nat.lt_trans scaled (by decide)
  have byte2Shift : byte2 * 65536 < 4294967296 := by
    have scaled := Nat.mul_lt_mul_of_pos_right byte2Bound (by decide : 0 < 65536)
    have product : 256 * 65536 = 16777216 := by decide
    rw [product] at scaled
    exact Nat.lt_trans scaled (by decide)
  have byte3Shift : byte3 * 16777216 < 4294967296 := by
    have scaled := Nat.mul_lt_mul_of_pos_right byte3Bound
      (by decide : 0 < 16777216)
    have product : 256 * 16777216 = 4294967296 := by decide
    rw [product] at scaled
    exact scaled
  have low16Bound : byte0 + byte1 * 256 < 65536 := by
    have byte1Next : byte1 + 1 <= 256 := by omega
    calc
      byte0 + byte1 * 256 < 256 + byte1 * 256 :=
        Nat.add_lt_add_right byte0Bound _
      _ = (byte1 + 1) * 256 := by simp [Nat.add_mul, Nat.add_comm]
      _ <= 256 * 256 := Nat.mul_le_mul_right 256 byte1Next
      _ = 65536 := by decide
  have low24Bound : byte0 + byte1 * 256 + byte2 * 65536 < 16777216 := by
    have byte2Next : byte2 + 1 <= 256 := by omega
    calc
      byte0 + byte1 * 256 + byte2 * 65536 < 65536 + byte2 * 65536 :=
        Nat.add_lt_add_right low16Bound _
      _ = (byte2 + 1) * 65536 := by simp [Nat.add_mul, Nat.add_comm]
      _ <= 256 * 65536 := Nat.mul_le_mul_right 65536 byte2Next
      _ = 16777216 := by decide
  have totalBound :
      byte0 + byte1 * 256 + byte2 * 65536 + byte3 * 16777216 < 4294967296 := by
    have byte3Next : byte3 + 1 <= 256 := by omega
    calc
      byte0 + byte1 * 256 + byte2 * 65536 + byte3 * 16777216 <
          16777216 + byte3 * 16777216 := Nat.add_lt_add_right low24Bound _
      _ = (byte3 + 1) * 16777216 := by simp [Nat.add_mul, Nat.add_comm]
      _ <= 256 * 16777216 := Nat.mul_le_mul_right 16777216 byte3Next
      _ = 4294967296 := by decide
  rw [Nat.mod_eq_of_lt byte0Bound, Nat.mod_eq_of_lt byte0Large,
    Nat.mod_eq_of_lt byte1Bound, Nat.mod_eq_of_lt byte1Large,
    Nat.mod_eq_of_lt byte1Shift, Nat.mod_eq_of_lt byte2Bound,
    Nat.mod_eq_of_lt byte2Large, Nat.mod_eq_of_lt byte2Shift,
    Nat.mod_eq_of_lt byte3Bound, Nat.mod_eq_of_lt byte3Large,
    Nat.mod_eq_of_lt byte3Shift, Nat.mod_eq_of_lt totalBound]
  have low16 : byte0 ||| byte1 * 256 = byte0 + byte1 * 256 := by
    calc
      byte0 ||| byte1 * 256 = byte1 * 256 ||| byte0 := Nat.or_comm _ _
      _ = byte1 * 256 + byte0 := by
        simpa [pow8, Nat.mul_comm] using
          (Nat.two_pow_add_eq_or_of_lt (i := 8) byte0Bound byte1).symm
      _ = byte0 + byte1 * 256 := Nat.add_comm _ _
  rw [low16]
  have low24 : (byte0 + byte1 * 256) ||| byte2 * 65536 =
      byte0 + byte1 * 256 + byte2 * 65536 := by
    calc
      (byte0 + byte1 * 256) ||| byte2 * 65536 =
          byte2 * 65536 ||| (byte0 + byte1 * 256) := Nat.or_comm _ _
      _ = byte2 * 65536 + (byte0 + byte1 * 256) := by
        simpa [pow16, Nat.mul_comm] using
          (Nat.two_pow_add_eq_or_of_lt (i := 16) low16Bound byte2).symm
      _ = byte0 + byte1 * 256 + byte2 * 65536 := by omega
  rw [low24]
  calc
    (byte0 + byte1 * 256 + byte2 * 65536) ||| byte3 * 16777216 =
        byte3 * 16777216 ||| (byte0 + byte1 * 256 + byte2 * 65536) :=
      Nat.or_comm _ _
    _ = byte3 * 16777216 + (byte0 + byte1 * 256 + byte2 * 65536) := by
      simpa [pow24, Nat.mul_comm] using
        (Nat.two_pow_add_eq_or_of_lt (i := 24) low24Bound byte3).symm
    _ = byte0 + byte1 * 256 + byte2 * 65536 + byte3 * 16777216 := by omega

@[simp] theorem Memory.read32_extractLsb8 (memory : Memory) (address : Word) :
    (Memory.read32 memory address).extractLsb' 0 8 = memory address := by
  unfold Memory.read32
  generalize memory address = byte0
  generalize memory (address + BitVec.ofNat 32 1) = byte1
  generalize memory (address + BitVec.ofNat 32 2) = byte2
  generalize memory (address + BitVec.ofNat 32 3) = byte3
  bv_decide

def DynamicWordRelationKind.valuesHold (context : StaticProofContext)
    (world : RelationalWorld) (owner : DynamicAddressRangePair)
    (kind : DynamicWordRelationKind) (originalWord candidateWord : Word) : Bool :=
  match kind with
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
          owner.wordRelations.all target.wordRelations.contains

def DynamicWordRelation.holds (context : StaticProofContext)
    (world : RelationalWorld) (range : DynamicAddressRangePair)
    (relation : DynamicWordRelation) (original candidate : Memory) : Bool :=
  let originalWord := Memory.read32 original
    (range.originalBase + BitVec.ofNat 32 relation.offset)
  let candidateWord := Memory.read32 candidate
    (range.candidateBase + BitVec.ofNat 32 relation.offset)
  relation.kind.valuesHold context world range originalWord candidateWord

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

def ValueOriginAtom.matches (context : StaticProofContext)
    (world : RelationalWorld) (originalWord candidateWord : Word) :
    ValueOriginAtom → Bool
  | .exactBits value =>
      originalWord == BitVec.ofNat 32 value &&
        candidateWord == BitVec.ofNat 32 value
  | .staticCodeTarget targetId offset =>
      match context.codeMap.get? targetId with
      | none => false
      | some target =>
          if offset == 0 then
            codeAddressMatches context.originalPe.imageBase
                target.originalRva target.originalAliases originalWord &&
              codeAddressMatches context.candidatePe.imageBase
                target.candidateRva target.candidateAliases candidateWord
          else
            originalWord == BitVec.ofNat 32
                (context.originalPe.imageBase + target.originalRva + offset) &&
              candidateWord == BitVec.ofNat 32
                (context.candidatePe.imageBase + target.candidateRva + offset)
  | .staticDataLocation targetId offset =>
      match context.dataMap.get? targetId with
      | none => false
      | some target =>
          originalWord == BitVec.ofNat 32 (target.originalValue + offset) &&
            candidateWord == BitVec.ofNat 32 (target.candidateValue + offset)
  | .importTarget identity =>
      world.importAddresses.any fun imported =>
        imported.imported == identity &&
          originalWord == imported.originalAddress &&
          candidateWord == imported.candidateAddress
  | .stackFrameLocation rangeId offset =>
      world.stackRanges.any fun range =>
        range.id == rangeId && offset < range.size &&
          originalWord == range.originalBase + BitVec.ofNat 32 offset &&
          candidateWord == range.candidateBase + BitVec.ofNat 32 offset
  | .dynamicRangeLocation rangeId offset =>
      world.dynamicRanges.any fun range =>
        range.id == rangeId && offset < range.size &&
          originalWord == range.originalBase + BitVec.ofNat 32 offset &&
          candidateWord == range.candidateBase + BitVec.ofNat 32 offset
  | .opaqueResource resourceId =>
      world.opaqueResources.any fun resource =>
        resource.id == resourceId &&
          originalWord == resource.original &&
          candidateWord == resource.candidate
  | .registeredCallback targetId =>
      world.registeredCallbacks.any fun callback =>
        callback.targetId == targetId &&
          originalWord == callback.originalAddress &&
          candidateWord == callback.candidateAddress

def StaticWordRelationKind.holds (context : StaticProofContext)
    (world : RelationalWorld) (relation : StaticWordRelationKind)
    (originalWord candidateWord : Word) : Bool :=
  match relation with
  | .exact => originalWord == candidateWord
  | .relatedWord =>
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        originalWord candidateWord
  | .codePointer =>
      (originalWord == BitVec.ofNat 32 0 && candidateWord == BitVec.ofNat 32 0) ||
        codePointerRelated context.originalPe.imageBase context.candidatePe.imageBase
          context.codeMap.entries.toList originalWord candidateWord
  | .fixedCodePointer targetId =>
      codeTargetAddressPairMatches context targetId originalWord candidateWord
  | .dataPointer =>
      (originalWord == BitVec.ofNat 32 0 && candidateWord == BitVec.ofNat 32 0) ||
        mappedValueRelated (context.relationalValueTargets world)
          originalWord candidateWord
  | .finiteOrigins _ origins =>
      origins.any (ValueOriginAtom.matches context world originalWord candidateWord)

def StaticWordRelationSlotPair.memoryHolds (context : StaticProofContext)
    (world : RelationalWorld) (slot : StaticWordRelationSlotPair)
    (original candidate : Memory) : Bool :=
  slot.relation.holds context world
    (Memory.read32 original slot.originalAddress)
    (Memory.read32 candidate slot.candidateAddress)

def StaticWordRelationSlotsMemoryHold (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory) : Prop :=
  ∀ slot, slot ∈ context.staticWordRelationSlots →
    slot.memoryHolds context world original candidate = true

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

theorem DynamicAddressRangePair.offsetAddressesWordRelated
    (context : StaticProofContext) (world : RelationalWorld)
    (range : DynamicAddressRangePair) (offset : Nat)
    (rangeMember : range ∈ world.stackRanges)
    (rangeValid : range.disjointFromImages context = true)
    (inside : offset < range.size) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (range.originalBase + BitVec.ofNat 32 offset)
      (range.candidateBase + BitVec.ofNat 32 offset) = true := by
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq] at rangeValid
  rcases rangeValid with
    ⟨⟨⟨⟨rangeShape, originalNoWrap⟩, candidateNoWrap⟩,
      _originalDisjoint⟩, _candidateDisjoint⟩
  rcases rangeShape with
    ⟨⟨rangeNonempty, originalBaseNonzero⟩, candidateBaseNonzero⟩
  have offsetBefore : offset < 2 ^ 32 := by omega
  have originalAddressBefore : range.originalBase.toNat + offset < 2 ^ 32 := by
    omega
  have candidateAddressBefore : range.candidateBase.toNat + offset < 2 ^ 32 := by
    omega
  have targetMember : range.valueTarget ∈ context.relationalValueTargets world := by
    simp only [StaticProofContext.relationalValueTargets,
      RelationalWorld.runtimeValueTargets, RelationalWorld.stackValueTargets,
      List.mem_append, List.mem_map]
    exact Or.inr (Or.inl (Or.inr ⟨range, rangeMember, rfl⟩))
  have candidateContained : valueTargetContainsCandidate range.valueTarget
      (range.candidateBase + BitVec.ofNat 32 offset) = true := by
    simp only [valueTargetContainsCandidate, DynamicAddressRangePair.valueTarget,
      Bool.and_eq_true, decide_eq_true_eq]
    refine ⟨⟨rangeNonempty, ?_⟩, ?_⟩
    · simp only [BitVec.le_def, BitVec.toNat_ofNat, BitVec.toNat_add]
      rw [Nat.mod_eq_of_lt offsetBefore,
        Nat.mod_eq_of_lt candidateAddressBefore]
      omega
    · simp only [BitVec.lt_def, BitVec.toNat_ofNat, BitVec.toNat_add]
      rw [Nat.mod_eq_of_lt (by omega : range.size < 2 ^ 32),
        Nat.mod_eq_of_lt range.candidateBase.isLt,
        Nat.mod_eq_of_lt candidateNoWrap,
        Nat.mod_eq_of_lt offsetBefore,
        Nat.mod_eq_of_lt candidateAddressBefore]
      omega
  have mapped : mappedValueRelated (context.relationalValueTargets world)
      (range.originalBase + BitVec.ofNat 32 offset)
      (range.candidateBase + BitVec.ofNat 32 offset) = true := by
    simp only [mappedValueRelated, List.any_eq_true]
    refine ⟨range.valueTarget, targetMember, ?_⟩
    simp only [DynamicAddressRangePair.valueTarget,
      if_neg (Nat.ne_of_gt rangeNonempty), Bool.or_eq_true,
      Bool.and_eq_true, beq_iff_eq]
    apply Or.inr
    refine ⟨candidateContained, ?_⟩
    have originalBaseRoundtrip :
        BitVec.ofNat 32 range.originalBase.toNat = range.originalBase := by
      apply BitVec.eq_of_toNat_eq
      simp
    have candidateBaseRoundtrip :
        BitVec.ofNat 32 range.candidateBase.toNat = range.candidateBase := by
      apply BitVec.eq_of_toNat_eq
      simp
    rw [originalBaseRoundtrip, candidateBaseRoundtrip]
    rw [BitVec.add_comm range.candidateBase,
      BitVec.add_sub_cancel]
  have originalNonzero :
      (range.originalBase + BitVec.ofNat 32 offset == BitVec.ofNat 32 0) = false := by
    apply beq_eq_false_iff_ne.mpr
    intro zero
    have zeroNat := congrArg BitVec.toNat zero
    simp only [BitVec.toNat_ofNat, BitVec.toNat_add] at zeroNat
    rw [Nat.mod_eq_of_lt offsetBefore,
      Nat.mod_eq_of_lt originalAddressBefore] at zeroNat
    have baseNonzero : range.originalBase ≠ BitVec.ofNat 32 0 := by
      apply beq_eq_false_iff_ne.mp
      simpa using originalBaseNonzero
    have basePositive : 0 < range.originalBase.toNat := by
      apply Nat.pos_of_ne_zero
      intro baseZero
      apply baseNonzero
      apply BitVec.eq_of_toNat_eq
      simpa [baseZero]
    omega
  have candidateNonzero :
      (range.candidateBase + BitVec.ofNat 32 offset == BitVec.ofNat 32 0) = false := by
    apply beq_eq_false_iff_ne.mpr
    intro zero
    have zeroNat := congrArg BitVec.toNat zero
    simp only [BitVec.toNat_ofNat, BitVec.toNat_add] at zeroNat
    rw [Nat.mod_eq_of_lt offsetBefore,
      Nat.mod_eq_of_lt candidateAddressBefore] at zeroNat
    have baseNonzero : range.candidateBase ≠ BitVec.ofNat 32 0 := by
      apply beq_eq_false_iff_ne.mp
      simpa using candidateBaseNonzero
    have basePositive : 0 < range.candidateBase.toNat := by
      apply Nat.pos_of_ne_zero
      intro baseZero
      apply baseNonzero
      apply BitVec.eq_of_toNat_eq
      simpa [baseZero]
    omega
  simp [wordRelated, originalNonzero, candidateNonzero, mapped]

theorem PairedStackWordLocation.addressesWordRelated
    (context : StaticProofContext) (world : RelationalWorld)
    (location : PairedStackWordLocation world)
    (rangeValid : location.range.disjointFromImages context = true) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      location.originalAddress location.candidateAddress = true := by
  rw [location.originalAddressExact, location.candidateAddressExact]
  have inside := location.inside
  exact location.range.offsetAddressesWordRelated context world location.offset
    location.rangeMember rangeValid (by omega)

structure PairedStaticWordLocation (context : StaticProofContext) where
  slot : StaticWordRelationSlotPair
  slotMember : slot ∈ context.staticWordRelationSlots
  originalAddress : Word
  candidateAddress : Word
  originalAddressExact : originalAddress = slot.originalAddress
  candidateAddressExact : candidateAddress = slot.candidateAddress

structure PairedStaticDynamicPointerLocation (context : StaticProofContext) where
  slot : StaticDynamicPointerSlotPair
  slotMember : slot ∈ context.staticDynamicPointerSlots
  originalAddress : Word
  candidateAddress : Word
  originalAddressExact : originalAddress = slot.originalAddress
  candidateAddressExact : candidateAddress = slot.candidateAddress

structure PairedDynamicWordLocation (world : RelationalWorld) where
  range : DynamicAddressRangePair
  relation : DynamicWordRelation
  rangeMember : range ∈ world.dynamicRanges
  relationMember : relation ∈ range.wordRelations
  originalAddress : Word
  candidateAddress : Word
  originalAddressExact :
    originalAddress = range.originalBase + BitVec.ofNat 32 relation.offset
  candidateAddressExact :
    candidateAddress = range.candidateBase + BitVec.ofNat 32 relation.offset

def Write32AvoidsWord (wordAddress writeAddress : Word) : Prop :=
  ∀ wordByte, wordByte < 4 → ∀ writeByte, writeByte < 4 →
    wordAddress + BitVec.ofNat 32 wordByte ≠
      writeAddress + BitVec.ofNat 32 writeByte

theorem Write32AvoidsWord.symm {left right : Word}
    (avoids : Write32AvoidsWord left right) :
    Write32AvoidsWord right left := by
  intro rightByte rightByteBefore leftByte leftByteBefore overlap
  exact avoids leftByte leftByteBefore rightByte rightByteBefore overlap.symm

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

def dynamicByteCoveredOn (candidate : Bool) (world : RelationalWorld)
    (address : Word) : Bool :=
  world.dynamicRanges.any fun range =>
    let base := range.sideBase candidate
    base.toNat <= address.toNat && address.toNat < base.toNat + range.size

def dynamicByteCoveredOriginal (world : RelationalWorld) (address : Word) : Bool :=
  dynamicByteCoveredOn false world address

def dynamicByteCoveredCandidate (world : RelationalWorld) (address : Word) : Bool :=
  dynamicByteCoveredOn true world address

theorem DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    (context : StaticProofContext) (candidate : Bool)
    (range : DynamicAddressRangePair)
    (valid : range.disjointFromImages context = true) :
    (range.sideBase candidate).toNat + range.size < 2 ^ 32 := by
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

theorem dynamicByteCoveredOn_of_range_word_byte
    (context : StaticProofContext) (candidate : Bool)
    (world : RelationalWorld) (range : DynamicAddressRangePair)
    (rangeMember : range ∈ world.dynamicRanges)
    (rangeValid : range.disjointFromImages context = true)
    (offset byte : Nat) (inside : offset + 4 <= range.size)
    (byteBefore : byte < 4) :
    dynamicByteCoveredOn candidate world
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
  simp only [dynamicByteCoveredOn, List.any_eq_true]
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

theorem Memory.write32_apply_of_dynamicByteUncovered
    (context : StaticProofContext) (candidate : Bool)
    (world : RelationalWorld) (range : DynamicAddressRangePair)
    (rangeMember : range ∈ world.dynamicRanges)
    (rangeValid : range.disjointFromImages context = true)
    (offset : Nat) (inside : offset + 4 <= range.size)
    (memory : Memory) (value query : Word)
    (uncovered : dynamicByteCoveredOn candidate world query = false) :
    memory.write32 (range.sideBase candidate + BitVec.ofNat 32 offset) value query =
      memory query := by
  let writeAddress := range.sideBase candidate + BitVec.ofNat 32 offset
  have avoids (byte : Nat) (byteBefore : byte < 4) :
      query ≠ writeAddress + BitVec.ofNat 32 byte := by
    intro overlap
    have covered := dynamicByteCoveredOn_of_range_word_byte context candidate world
      range rangeMember rangeValid offset byte inside byteBefore
    change dynamicByteCoveredOn candidate world
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

theorem write32AvoidsWord_of_dynamicBytesUncovered
    (context : StaticProofContext) (candidate : Bool)
    (world : RelationalWorld) (range : DynamicAddressRangePair)
    (rangeMember : range ∈ world.dynamicRanges)
    (rangeValid : range.disjointFromImages context = true)
    (offset : Nat) (inside : offset + 4 <= range.size)
    (wordAddress : Word)
    (uncovered : ∀ byte, byte < 4 →
      dynamicByteCoveredOn candidate world
        (wordAddress + BitVec.ofNat 32 byte) = false) :
    Write32AvoidsWord wordAddress
      (range.sideBase candidate + BitVec.ofNat 32 offset) := by
  intro wordByte wordByteBefore writeByte writeByteBefore overlap
  have covered := dynamicByteCoveredOn_of_range_word_byte context candidate world
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

theorem PairedStackWordLocation.addressesFit
    (context : StaticProofContext) (world : RelationalWorld)
    (location : PairedStackWordLocation world)
    (rangesValid : world.stackRangesValid context = true) :
    location.originalAddress.toNat + 4 <= 2 ^ 32 ∧
      location.candidateAddress.toNat + 4 <= 2 ^ 32 := by
  have validRows := rangesValid
  simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
    List.all_eq_true] at validRows
  have rangeRow := validRows.1.1.2 location.range location.rangeMember
  have rangeValid : location.range.disjointFromImages context = true :=
    rangeRow.1.1.1
  have originalNoWrap :
      location.range.originalBase.toNat + location.range.size < 2 ^ 32 := by
    simpa [DynamicAddressRangePair.sideBase] using
      DynamicAddressRangePair.sideBase_noWrap_of_disjoint
        context false location.range rangeValid
  have candidateNoWrap :
      location.range.candidateBase.toNat + location.range.size < 2 ^ 32 := by
    simpa [DynamicAddressRangePair.sideBase] using
      DynamicAddressRangePair.sideBase_noWrap_of_disjoint
        context true location.range rangeValid
  have inside := location.inside
  have offsetSmall : location.offset < 2 ^ 32 := by omega
  have originalAddressBefore :
      location.range.originalBase.toNat + location.offset < 2 ^ 32 := by omega
  have candidateAddressBefore :
      location.range.candidateBase.toNat + location.offset < 2 ^ 32 := by omega
  have originalAddressNat : location.originalAddress.toNat =
      location.range.originalBase.toNat + location.offset := by
    rw [location.originalAddressExact]
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt offsetSmall,
      Nat.mod_eq_of_lt originalAddressBefore]
  have candidateAddressNat : location.candidateAddress.toNat =
      location.range.candidateBase.toNat + location.offset := by
    rw [location.candidateAddressExact]
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt offsetSmall,
      Nat.mod_eq_of_lt candidateAddressBefore]
  constructor
  · rw [originalAddressNat]
    omega
  · rw [candidateAddressNat]
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

theorem dynamicRangeWordWriteAvoidsOtherWord
    (context : StaticProofContext) (candidate : Bool)
    (world : RelationalWorld)
    (rangesValid : world.dynamicRangesValid context = true)
    (writeRange queryRange : DynamicAddressRangePair)
    (writeRangeMember : writeRange ∈ world.dynamicRanges)
    (queryRangeMember : queryRange ∈ world.dynamicRanges)
    (writeRelation queryRelation : DynamicWordRelation)
    (writeRelationMember : writeRelation ∈ writeRange.wordRelations)
    (queryRelationMember : queryRelation ∈ queryRange.wordRelations)
    (different : queryRange ≠ writeRange ∨ queryRelation ≠ writeRelation) :
    Write32AvoidsWord
      (queryRange.sideBase candidate + BitVec.ofNat 32 queryRelation.offset)
      (writeRange.sideBase candidate + BitVec.ofNat 32 writeRelation.offset) := by
  simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
    List.all_eq_true] at rangesValid
  have idsUnique := rangesValid.1.1.1.1.1.1
  have writeValid := rangesValid.1.1.1.1.1.2 writeRange writeRangeMember
  have queryValid := rangesValid.1.1.1.1.1.2 queryRange queryRangeMember
  have writeWordsValid := rangesValid.1.1.1.1.2 writeRange writeRangeMember
  have queryWordsValid := rangesValid.1.1.1.1.2 queryRange queryRangeMember
  simp only [DynamicAddressRangePair.wordRelationsValid, List.all_eq_true]
    at writeWordsValid queryWordsValid
  have writeRelationValid := writeWordsValid writeRelation writeRelationMember
  have queryRelationValid := queryWordsValid queryRelation queryRelationMember
  simp only [DynamicAddressRangePair.wordRelationsValid, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at writeRelationValid queryRelationValid
  have writeInside := writeRelationValid.1
  have queryInside := queryRelationValid.1
  have writeNoWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context candidate writeRange writeValid
  have queryNoWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context candidate queryRange queryValid
  have rangesDisjoint :
      dynamicAddressRangesDisjointOn candidate world.dynamicRanges = true := by
    cases candidate
    · exact rangesValid.1.1.1.2
    · exact rangesValid.1.1.2
  intro queryByte queryByteBefore writeByte writeByteBefore overlap
  have overlapNat := congrArg BitVec.toNat overlap
  have writeOffsetBefore : writeRelation.offset < 2 ^ 32 := by omega
  have queryOffsetBefore : queryRelation.offset < 2 ^ 32 := by omega
  have writeByteSmall : writeByte < 2 ^ 32 := by omega
  have queryByteSmall : queryByte < 2 ^ 32 := by omega
  have writeBaseOffsetBefore :
      (writeRange.sideBase candidate).toNat + writeRelation.offset < 2 ^ 32 := by
    omega
  have queryBaseOffsetBefore :
      (queryRange.sideBase candidate).toNat + queryRelation.offset < 2 ^ 32 := by
    omega
  have writeAddressBefore :
      (writeRange.sideBase candidate).toNat + writeRelation.offset + writeByte <
        2 ^ 32 := by omega
  have queryAddressBefore :
      (queryRange.sideBase candidate).toNat + queryRelation.offset + queryByte <
        2 ^ 32 := by omega
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
  · have sameRange := dynamicAddressRange_eq_of_same_id world.dynamicRanges
      idsUnique queryRange writeRange queryRangeMember writeRangeMember sameId
    subst queryRange
    simp only [ne_eq, not_true_eq_false, false_or] at different
    have relationRow := queryRelationValid.2 writeRelation writeRelationMember
    simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq] at relationRow
    rcases relationRow with (sameRelation | queryBefore) | writeBefore
    · exact (different sameRelation.symm).elim
    · omega
    · omega
  · simp only [dynamicAddressRangesDisjointOn, List.all_eq_true]
      at rangesDisjoint
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
    (rangeNoWrap : rangeBase.toNat + rangeSize < 2 ^ 32)
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
    (rangeNoWrap : rangeBase.toNat + rangeSize < 2 ^ 32)
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

theorem ImportAddressesMemoryHold.afterPairedRangeWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (range : DynamicAddressRangePair)
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

theorem ImportAddressesMemoryHold.afterPairedStackWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (range : DynamicAddressRangePair) (_rangeMember : range ∈ world.stackRanges)
    (rangeValid : range.disjointFromImages context = true)
    (offset : Nat) (inside : offset + 4 <= range.size)
    (originalValue candidateValue : Word)
    (importsStatic : world.importAddressesStaticValid context = true)
    (importsMemory : ImportAddressesMemoryHold context world original candidate) :
    ImportAddressesMemoryHold context world
      (original.write32 (range.originalBase + BitVec.ofNat 32 offset) originalValue)
      (candidate.write32 (range.candidateBase + BitVec.ofNat 32 offset)
        candidateValue) :=
  ImportAddressesMemoryHold.afterPairedRangeWordWrite context world original candidate
    range rangeValid offset inside originalValue candidateValue importsStatic importsMemory

theorem ImportAddressesMemoryHold.afterPairedDynamicWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (range : DynamicAddressRangePair) (_rangeMember : range ∈ world.dynamicRanges)
    (rangeValid : range.disjointFromImages context = true)
    (offset : Nat) (inside : offset + 4 <= range.size)
    (originalValue candidateValue : Word)
    (importsStatic : world.importAddressesStaticValid context = true)
    (importsMemory : ImportAddressesMemoryHold context world original candidate) :
    ImportAddressesMemoryHold context world
      (original.write32 (range.originalBase + BitVec.ofNat 32 offset) originalValue)
      (candidate.write32 (range.candidateBase + BitVec.ofNat 32 offset)
        candidateValue) :=
  ImportAddressesMemoryHold.afterPairedRangeWordWrite context world original candidate
    range rangeValid offset inside originalValue candidateValue importsStatic importsMemory

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

theorem StackRangesMemoryHold.afterPairedDynamicWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (stackRangesValid : world.stackRangesValid context = true)
    (dynamicRangesValid : world.dynamicRangesValid context = true)
    (writeRange : DynamicAddressRangePair)
    (writeRangeMember : writeRange ∈ world.dynamicRanges)
    (writeRelation : DynamicWordRelation)
    (writeRelationMember : writeRelation ∈ writeRange.wordRelations)
    (originalValue candidateValue : Word)
    (related : StackRangesMemoryHold context world original candidate) :
    StackRangesMemoryHold context world
      (original.write32
        (writeRange.originalBase + BitVec.ofNat 32 writeRelation.offset)
        originalValue)
      (candidate.write32
        (writeRange.candidateBase + BitVec.ofNat 32 writeRelation.offset)
        candidateValue) := by
  have dynamicRangesShape := dynamicRangesValid
  simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
    List.all_eq_true] at dynamicRangesShape
  have writeRangeValid : writeRange.disjointFromImages context = true := by
    exact dynamicRangesShape.1.1.1.1.1.2 writeRange writeRangeMember
  have writeRelationsValid : writeRange.wordRelationsValid = true := by
    exact dynamicRangesShape.1.1.1.1.2 writeRange writeRangeMember
  simp only [DynamicAddressRangePair.wordRelationsValid, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at writeRelationsValid
  have writeInside := (writeRelationsValid writeRelation writeRelationMember).1
  intro stackRange stackRangeMember stackOffset stackInside stackAligned
  have stackRangeValid : stackRange.disjointFromImages context = true := by
    simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
      List.all_eq_true] at stackRangesValid
    exact (stackRangesValid.1.1.2 stackRange stackRangeMember).1.1.1
  have originalAvoids := (stackRangeWordWriteAvoidsDynamicRangeWord context false
    world dynamicRangesValid stackRange writeRange stackRangeMember writeRangeMember
    stackRangeValid stackOffset writeRelation.offset stackInside writeInside).symm
  have candidateAvoids := (stackRangeWordWriteAvoidsDynamicRangeWord context true
    world dynamicRangesValid stackRange writeRange stackRangeMember writeRangeMember
    stackRangeValid stackOffset writeRelation.offset stackInside writeInside).symm
  rw [Memory.read32_write32_of_avoids _ _ _ _
      (by simpa [DynamicAddressRangePair.sideBase] using originalAvoids),
    Memory.read32_write32_of_avoids _ _ _ _
      (by simpa [DynamicAddressRangePair.sideBase] using candidateAvoids)]
  exact related stackRange stackRangeMember stackOffset stackInside stackAligned

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
  have relationInside := relationValid.1
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

theorem DynamicRangesMemoryHold.afterPairedDynamicWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (rangesValid : world.dynamicRangesValid context = true)
    (writeRange : DynamicAddressRangePair)
    (writeRangeMember : writeRange ∈ world.dynamicRanges)
    (writeRelation : DynamicWordRelation)
    (writeRelationMember : writeRelation ∈ writeRange.wordRelations)
    (originalValue candidateValue : Word)
    (valuesRelated : writeRelation.kind.valuesHold context world writeRange
      originalValue candidateValue = true)
    (related : DynamicRangesMemoryHold context world original candidate) :
    DynamicRangesMemoryHold context world
      (original.write32
        (writeRange.originalBase + BitVec.ofNat 32 writeRelation.offset)
        originalValue)
      (candidate.write32
        (writeRange.candidateBase + BitVec.ofNat 32 writeRelation.offset)
        candidateValue) := by
  have writeRangeValid : writeRange.disjointFromImages context = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.1.2 writeRange writeRangeMember
  have writeRelationsValid : writeRange.wordRelationsValid = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.2 writeRange writeRangeMember
  simp only [DynamicAddressRangePair.wordRelationsValid, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at writeRelationsValid
  have writeInside := (writeRelationsValid writeRelation writeRelationMember).1
  have originalFits := DynamicAddressRangePair.wordAddress_fits context false
    writeRange writeRangeValid writeRelation.offset writeInside
  have candidateFits := DynamicAddressRangePair.wordAddress_fits context true
    writeRange writeRangeValid writeRelation.offset writeInside
  have originalFits' :
      (writeRange.originalBase + BitVec.ofNat 32 writeRelation.offset).toNat + 4 <=
        2 ^ 32 := by
    simpa [DynamicAddressRangePair.sideBase] using originalFits
  have candidateFits' :
      (writeRange.candidateBase + BitVec.ofNat 32 writeRelation.offset).toNat + 4 <=
        2 ^ 32 := by
    simpa [DynamicAddressRangePair.sideBase] using candidateFits
  intro queryRange queryRangeMember
  have prior := related queryRange queryRangeMember
  simp only [DynamicAddressRangePair.wordsHold, List.all_eq_true] at prior ⊢
  intro queryRelation queryRelationMember
  by_cases sameRange : queryRange = writeRange
  · subst queryRange
    by_cases sameRelation : queryRelation = writeRelation
    · subst queryRelation
      simp only [DynamicWordRelation.holds]
      rw [Memory.read32_write32_same_of_fits _ _ _ originalFits',
        Memory.read32_write32_same_of_fits _ _ _ candidateFits']
      exact valuesRelated
    · have originalAvoids := dynamicRangeWordWriteAvoidsOtherWord context false
        world rangesValid writeRange writeRange writeRangeMember writeRangeMember
        writeRelation queryRelation writeRelationMember queryRelationMember
        (Or.inr sameRelation)
      have candidateAvoids := dynamicRangeWordWriteAvoidsOtherWord context true
        world rangesValid writeRange writeRange writeRangeMember writeRangeMember
        writeRelation queryRelation writeRelationMember queryRelationMember
        (Or.inr sameRelation)
      unfold DynamicWordRelation.holds
      rw [Memory.read32_write32_of_avoids _ _ _ _
          (by simpa [DynamicAddressRangePair.sideBase] using originalAvoids),
        Memory.read32_write32_of_avoids _ _ _ _
          (by simpa [DynamicAddressRangePair.sideBase] using candidateAvoids)]
      exact prior queryRelation queryRelationMember
  · have originalAvoids := dynamicRangeWordWriteAvoidsOtherWord context false
      world rangesValid writeRange queryRange writeRangeMember queryRangeMember
      writeRelation queryRelation writeRelationMember queryRelationMember
      (Or.inl sameRange)
    have candidateAvoids := dynamicRangeWordWriteAvoidsOtherWord context true
      world rangesValid writeRange queryRange writeRangeMember queryRangeMember
      writeRelation queryRelation writeRelationMember queryRelationMember
      (Or.inl sameRange)
    unfold DynamicWordRelation.holds
    rw [Memory.read32_write32_of_avoids _ _ _ _
        (by simpa [DynamicAddressRangePair.sideBase] using originalAvoids),
      Memory.read32_write32_of_avoids _ _ _ _
        (by simpa [DynamicAddressRangePair.sideBase] using candidateAvoids)]
    exact prior queryRelation queryRelationMember

theorem writableStaticWordInPe_bounds (pe : PE32) (address : Word)
    (writable : writableStaticWordInPe pe address = true) :
    pe.imageBase <= address.toNat ∧
      address.toNat + 4 <= pe.imageBase + pe.sizeOfImage ∧
      address.toNat + 4 <= 2 ^ 32 := by
  simp only [writableStaticWordInPe, Bool.and_eq_true,
    decide_eq_true_eq] at writable
  exact ⟨writable.1.1.1, writable.1.2, writable.1.1.2⟩

theorem write32AvoidsWord_of_nat_disjoint
    (wordAddress writeAddress : Word)
    (wordFits : wordAddress.toNat + 4 <= 2 ^ 32)
    (writeFits : writeAddress.toNat + 4 <= 2 ^ 32)
    (disjoint : wordAddress.toNat + 4 <= writeAddress.toNat ∨
      writeAddress.toNat + 4 <= wordAddress.toNat) :
    Write32AvoidsWord wordAddress writeAddress := by
  intro wordByte wordByteBefore writeByte writeByteBefore overlap
  have overlapNat := congrArg BitVec.toNat overlap
  have wordByteSmall : wordByte < 2 ^ 32 := by omega
  have writeByteSmall : writeByte < 2 ^ 32 := by omega
  have wordAddressBefore : wordAddress.toNat + wordByte < 2 ^ 32 := by omega
  have writeAddressBefore : writeAddress.toNat + writeByte < 2 ^ 32 := by omega
  simp [BitVec.toNat_add, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt wordByteSmall, Nat.mod_eq_of_lt writeByteSmall,
    Nat.mod_eq_of_lt wordAddressBefore,
    Nat.mod_eq_of_lt writeAddressBefore] at overlapNat
  omega

theorem StaticWordRelationSlotPair.valid_of_member
    (context : StaticProofContext) (slot : StaticWordRelationSlotPair)
    (slotsValid : staticWordRelationSlotsValid context = true)
    (member : slot ∈ context.staticWordRelationSlots) :
    slot.valid context = true := by
  simp only [staticWordRelationSlotsValid, Bool.and_eq_true,
    List.all_eq_true] at slotsValid
  exact slotsValid.2 slot member

theorem StaticWordRelationSlotPair.originalBounds
    (context : StaticProofContext) (slot : StaticWordRelationSlotPair)
    (valid : slot.valid context = true) :
    context.originalPe.imageBase <= slot.originalAddress.toNat ∧
      slot.originalAddress.toNat + 4 <=
        context.originalPe.imageBase + context.originalPe.sizeOfImage ∧
      slot.originalAddress.toNat + 4 <= 2 ^ 32 := by
  simp only [StaticWordRelationSlotPair.valid, Bool.and_eq_true] at valid
  exact writableStaticWordInPe_bounds context.originalPe slot.originalAddress
    valid.1.1.1.1.1.1.2

theorem StaticWordRelationSlotPair.candidateBounds
    (context : StaticProofContext) (slot : StaticWordRelationSlotPair)
    (valid : slot.valid context = true) :
    context.candidatePe.imageBase <= slot.candidateAddress.toNat ∧
      slot.candidateAddress.toNat + 4 <=
        context.candidatePe.imageBase + context.candidatePe.sizeOfImage ∧
      slot.candidateAddress.toNat + 4 <= 2 ^ 32 := by
  simp only [StaticWordRelationSlotPair.valid, Bool.and_eq_true] at valid
  exact writableStaticWordInPe_bounds context.candidatePe slot.candidateAddress
    valid.1.1.1.1.1.2

theorem StaticWordRelationSlotsMemoryHold.afterPairedStaticWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (slotsValid : staticWordRelationSlotsValid context = true)
    (writeSlot : StaticWordRelationSlotPair)
    (writeMember : writeSlot ∈ context.staticWordRelationSlots)
    (originalValue candidateValue : Word)
    (valuesRelated : writeSlot.relation.holds context world
      originalValue candidateValue = true)
    (related : StaticWordRelationSlotsMemoryHold context world original candidate) :
    StaticWordRelationSlotsMemoryHold context world
      (original.write32 writeSlot.originalAddress originalValue)
      (candidate.write32 writeSlot.candidateAddress candidateValue) := by
  intro querySlot queryMember
  have slotsShape := slotsValid
  simp only [staticWordRelationSlotsValid, Bool.and_eq_true] at slotsShape
  by_cases sameSlot : querySlot = writeSlot
  · subst querySlot
    have writeValid := writeSlot.valid_of_member context slotsValid writeMember
    have originalFits := (writeSlot.originalBounds context writeValid).2.2
    have candidateFits := (writeSlot.candidateBounds context writeValid).2.2
    unfold StaticWordRelationSlotPair.memoryHolds
    rw [Memory.read32_write32_same_of_fits _ _ _ originalFits,
      Memory.read32_write32_same_of_fits _ _ _ candidateFits]
    exact valuesRelated
  · have unique : staticWordRelationSlotIdsUnique
        context.staticWordRelationSlots = true := by
      exact slotsShape.1.1.1.1.1
    have differentId : querySlot.id ≠ writeSlot.id := by
      intro sameId
      exact sameSlot (staticWordRelationSlot_eq_of_same_id
        context.staticWordRelationSlots unique querySlot writeSlot
        queryMember writeMember sameId)
    have separatedOriginal :
        querySlot.originalAddress.toNat + 4 <= writeSlot.originalAddress.toNat ∨
          writeSlot.originalAddress.toNat + 4 <=
            querySlot.originalAddress.toNat := by
      have disjoint : staticWordRelationSlotsDisjointOn false
          context.staticWordRelationSlots = true := by
        exact slotsShape.1.1.1.1.2
      simp only [staticWordRelationSlotsDisjointOn, List.all_eq_true] at disjoint
      have pair := disjoint querySlot queryMember writeSlot writeMember
      simp only [Bool.or_eq_true, decide_eq_true_eq, Bool.false_eq_true,
        if_false] at pair
      rcases pair with sameId | separated
      · exact False.elim (differentId (beq_iff_eq.mp sameId))
      · exact separated
    have separatedCandidate :
        querySlot.candidateAddress.toNat + 4 <= writeSlot.candidateAddress.toNat ∨
          writeSlot.candidateAddress.toNat + 4 <=
            querySlot.candidateAddress.toNat := by
      have disjoint : staticWordRelationSlotsDisjointOn true
          context.staticWordRelationSlots = true := by
        exact slotsShape.1.1.1.2
      simp only [staticWordRelationSlotsDisjointOn, List.all_eq_true] at disjoint
      have pair := disjoint querySlot queryMember writeSlot writeMember
      simp only [Bool.or_eq_true, decide_eq_true_eq, if_true] at pair
      rcases pair with sameId | separated
      · exact False.elim (differentId (beq_iff_eq.mp sameId))
      · exact separated
    have queryValid := querySlot.valid_of_member context slotsValid queryMember
    have writeValid := writeSlot.valid_of_member context slotsValid writeMember
    have originalAvoids := write32AvoidsWord_of_nat_disjoint
      querySlot.originalAddress writeSlot.originalAddress
      (querySlot.originalBounds context queryValid).2.2
      (writeSlot.originalBounds context writeValid).2.2 separatedOriginal
    have candidateAvoids := write32AvoidsWord_of_nat_disjoint
      querySlot.candidateAddress writeSlot.candidateAddress
      (querySlot.candidateBounds context queryValid).2.2
      (writeSlot.candidateBounds context writeValid).2.2 separatedCandidate
    have prior := related querySlot queryMember
    unfold StaticWordRelationSlotPair.memoryHolds at prior ⊢
    rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
      Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
    exact prior

theorem StackRangesMemoryHold.afterPairedStaticWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (rangesValid : world.stackRangesValid context = true)
    (slotsValid : staticWordRelationSlotsValid context = true)
    (writeSlot : StaticWordRelationSlotPair)
    (writeMember : writeSlot ∈ context.staticWordRelationSlots)
    (originalValue candidateValue : Word)
    (related : StackRangesMemoryHold context world original candidate) :
    StackRangesMemoryHold context world
      (original.write32 writeSlot.originalAddress originalValue)
      (candidate.write32 writeSlot.candidateAddress candidateValue) := by
  intro range rangeMember offset inside aligned
  have rangeValid : range.disjointFromImages context = true := by
    simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact (rangesValid.1.1.2 range rangeMember).1.1.1
  have writeValid := writeSlot.valid_of_member context slotsValid writeMember
  have originalBounds := writeSlot.originalBounds context writeValid
  have candidateBounds := writeSlot.candidateBounds context writeValid
  have rangeShape := rangeValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeShape
  rcases rangeShape with
    ⟨⟨⟨⟨_nonempty, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  have originalAvoids := (stackRangeWordWriteAvoidsImageWord
    range.originalBase range.size context.originalPe.imageBase
    context.originalPe.sizeOfImage offset inside originalNoWrap originalDisjoint
    writeSlot.originalAddress originalBounds.1 originalBounds.2.1
    originalBounds.2.2).symm
  have candidateAvoids := (stackRangeWordWriteAvoidsImageWord
    range.candidateBase range.size context.candidatePe.imageBase
    context.candidatePe.sizeOfImage offset inside candidateNoWrap candidateDisjoint
    writeSlot.candidateAddress candidateBounds.1 candidateBounds.2.1
    candidateBounds.2.2).symm
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact related range rangeMember offset inside aligned

theorem DynamicRangesMemoryHold.afterPairedStaticWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (rangesValid : world.dynamicRangesValid context = true)
    (slotsValid : staticWordRelationSlotsValid context = true)
    (writeSlot : StaticWordRelationSlotPair)
    (writeMember : writeSlot ∈ context.staticWordRelationSlots)
    (originalValue candidateValue : Word)
    (related : DynamicRangesMemoryHold context world original candidate) :
    DynamicRangesMemoryHold context world
      (original.write32 writeSlot.originalAddress originalValue)
      (candidate.write32 writeSlot.candidateAddress candidateValue) := by
  intro range rangeMember
  have rangeValid : range.disjointFromImages context = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.1.2 range rangeMember
  have wordRelationsValid : range.wordRelationsValid = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.2 range rangeMember
  have writeValid := writeSlot.valid_of_member context slotsValid writeMember
  have originalBounds := writeSlot.originalBounds context writeValid
  have candidateBounds := writeSlot.candidateBounds context writeValid
  have rangeShape := rangeValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeShape
  rcases rangeShape with
    ⟨⟨⟨⟨_nonempty, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  have prior := related range rangeMember
  simp only [DynamicAddressRangePair.wordsHold, List.all_eq_true] at prior ⊢
  simp only [DynamicAddressRangePair.wordRelationsValid,
    List.all_eq_true] at wordRelationsValid
  intro relation relationMember
  have relationShape := wordRelationsValid relation relationMember
  simp only [Bool.and_eq_true, decide_eq_true_eq] at relationShape
  have relationInside := relationShape.1
  have originalAvoids := (stackRangeWordWriteAvoidsImageWord
    range.originalBase range.size context.originalPe.imageBase
    context.originalPe.sizeOfImage relation.offset relationInside
    originalNoWrap originalDisjoint writeSlot.originalAddress
    originalBounds.1 originalBounds.2.1 originalBounds.2.2).symm
  have candidateAvoids := (stackRangeWordWriteAvoidsImageWord
    range.candidateBase range.size context.candidatePe.imageBase
    context.candidatePe.sizeOfImage relation.offset relationInside
    candidateNoWrap candidateDisjoint writeSlot.candidateAddress
    candidateBounds.1 candidateBounds.2.1 candidateBounds.2.2).symm
  have priorRelation := prior relation relationMember
  unfold DynamicWordRelation.holds at priorRelation ⊢
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact priorRelation

theorem StaticDynamicPointerSlotPair.originalBounds
    (context : StaticProofContext) (slot : StaticDynamicPointerSlotPair)
    (valid : slot.valid context = true) :
    context.originalPe.imageBase <= slot.originalAddress.toNat ∧
      slot.originalAddress.toNat + 4 <=
        context.originalPe.imageBase + context.originalPe.sizeOfImage ∧
      slot.originalAddress.toNat + 4 <= 2 ^ 32 := by
  simp only [StaticDynamicPointerSlotPair.valid, Bool.and_eq_true] at valid
  exact writableStaticWordInPe_bounds context.originalPe slot.originalAddress
    valid.1.1.1.1.1.1.2

theorem StaticDynamicPointerSlotPair.candidateBounds
    (context : StaticProofContext) (slot : StaticDynamicPointerSlotPair)
    (valid : slot.valid context = true) :
    context.candidatePe.imageBase <= slot.candidateAddress.toNat ∧
      slot.candidateAddress.toNat + 4 <=
        context.candidatePe.imageBase + context.candidatePe.sizeOfImage ∧
      slot.candidateAddress.toNat + 4 <= 2 ^ 32 := by
  simp only [StaticDynamicPointerSlotPair.valid, Bool.and_eq_true] at valid
  exact writableStaticWordInPe_bounds context.candidatePe slot.candidateAddress
    valid.1.1.1.1.1.2

theorem StaticDynamicPointerSlotPair.valid_of_member
    (context : StaticProofContext) (slot : StaticDynamicPointerSlotPair)
    (slotsValid : staticDynamicPointerSlotsValid context = true)
    (member : slot ∈ context.staticDynamicPointerSlots) :
    slot.valid context = true := by
  simp only [staticDynamicPointerSlotsValid, Bool.and_eq_true,
    List.all_eq_true] at slotsValid
  exact slotsValid.2 slot member

theorem StaticDynamicPointerSlotsMemoryHold.afterPairedStaticDynamicPointerWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (slotsValid : staticDynamicPointerSlotsValid context = true)
    (rangesValid : world.dynamicRangesValid context = true)
    (writeSlot : StaticDynamicPointerSlotPair)
    (writeMember : writeSlot ∈ context.staticDynamicPointerSlots)
    (range : DynamicAddressRangePair) (rangeMember : range ∈ world.dynamicRanges)
    (requiredWords : writeSlot.requiredWords.all range.wordRelations.contains = true)
    (related : StaticDynamicPointerSlotsMemoryHold context world original candidate) :
    StaticDynamicPointerSlotsMemoryHold context world
      (original.write32 writeSlot.originalAddress range.originalBase)
      (candidate.write32 writeSlot.candidateAddress range.candidateBase) := by
  intro querySlot queryMember
  have rangeValid : range.disjointFromImages context = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.1.2 range rangeMember
  have rangeShape := rangeValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true] at rangeShape
  have originalNonzero := rangeShape.1.1.1.1.1.2
  have candidateNonzero := rangeShape.1.1.1.1.2
  have slotsShape := slotsValid
  simp only [staticDynamicPointerSlotsValid, Bool.and_eq_true] at slotsShape
  by_cases sameSlot : querySlot = writeSlot
  · subst querySlot
    have writeValid := writeSlot.valid_of_member context slotsValid writeMember
    have originalFits := (writeSlot.originalBounds context writeValid).2.2
    have candidateFits := (writeSlot.candidateBounds context writeValid).2.2
    unfold StaticDynamicPointerSlotPair.memoryHolds
    rw [Memory.read32_write32_same_of_fits _ _ _ originalFits,
      Memory.read32_write32_same_of_fits _ _ _ candidateFits]
    simp only [Bool.or_eq_true, Bool.and_eq_true, List.any_eq_true, beq_iff_eq]
    apply Or.inr
    refine ⟨range, rangeMember, ?_⟩
    exact ⟨⟨⟨⟨rfl, rfl⟩, originalNonzero⟩,
      candidateNonzero⟩, requiredWords⟩
  · have unique : staticDynamicPointerSlotIdsUnique
        context.staticDynamicPointerSlots = true := slotsShape.1.1.1
    have differentId : querySlot.id ≠ writeSlot.id := by
      intro sameId
      exact sameSlot (staticDynamicPointerSlot_eq_of_same_id
        context.staticDynamicPointerSlots unique querySlot writeSlot
        queryMember writeMember sameId)
    have separatedOriginal :
        querySlot.originalAddress.toNat + 4 <= writeSlot.originalAddress.toNat ∨
          writeSlot.originalAddress.toNat + 4 <= querySlot.originalAddress.toNat := by
      have disjoint : staticDynamicPointerSlotsDisjointOn false
          context.staticDynamicPointerSlots = true := slotsShape.1.1.2
      simp only [staticDynamicPointerSlotsDisjointOn, List.all_eq_true] at disjoint
      have pair := disjoint querySlot queryMember writeSlot writeMember
      simp only [Bool.or_eq_true, decide_eq_true_eq, Bool.false_eq_true,
        if_false] at pair
      exact pair.resolve_left (fun same => differentId (beq_iff_eq.mp same))
    have separatedCandidate :
        querySlot.candidateAddress.toNat + 4 <= writeSlot.candidateAddress.toNat ∨
          writeSlot.candidateAddress.toNat + 4 <= querySlot.candidateAddress.toNat := by
      have disjoint : staticDynamicPointerSlotsDisjointOn true
          context.staticDynamicPointerSlots = true := slotsShape.1.2
      simp only [staticDynamicPointerSlotsDisjointOn, List.all_eq_true] at disjoint
      have pair := disjoint querySlot queryMember writeSlot writeMember
      simp only [Bool.or_eq_true, decide_eq_true_eq, if_true] at pair
      exact pair.resolve_left (fun same => differentId (beq_iff_eq.mp same))
    have queryValid := querySlot.valid_of_member context slotsValid queryMember
    have writeValid := writeSlot.valid_of_member context slotsValid writeMember
    have originalAvoids := write32AvoidsWord_of_nat_disjoint
      querySlot.originalAddress writeSlot.originalAddress
      (querySlot.originalBounds context queryValid).2.2
      (writeSlot.originalBounds context writeValid).2.2 separatedOriginal
    have candidateAvoids := write32AvoidsWord_of_nat_disjoint
      querySlot.candidateAddress writeSlot.candidateAddress
      (querySlot.candidateBounds context queryValid).2.2
      (writeSlot.candidateBounds context writeValid).2.2 separatedCandidate
    have prior := related querySlot queryMember
    unfold StaticDynamicPointerSlotPair.memoryHolds at prior ⊢
    rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
      Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
    exact prior

theorem StackRangesMemoryHold.afterPairedStaticDynamicPointerWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (rangesValid : world.stackRangesValid context = true)
    (slotsValid : staticDynamicPointerSlotsValid context = true)
    (writeSlot : StaticDynamicPointerSlotPair)
    (writeMember : writeSlot ∈ context.staticDynamicPointerSlots)
    (originalValue candidateValue : Word)
    (related : StackRangesMemoryHold context world original candidate) :
    StackRangesMemoryHold context world
      (original.write32 writeSlot.originalAddress originalValue)
      (candidate.write32 writeSlot.candidateAddress candidateValue) := by
  intro range rangeMember offset inside aligned
  have rangeValid : range.disjointFromImages context = true := by
    simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact (rangesValid.1.1.2 range rangeMember).1.1.1
  have writeValid := writeSlot.valid_of_member context slotsValid writeMember
  have originalBounds := writeSlot.originalBounds context writeValid
  have candidateBounds := writeSlot.candidateBounds context writeValid
  have rangeShape := rangeValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeShape
  rcases rangeShape with
    ⟨⟨⟨⟨_nonempty, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  have originalAvoids := (stackRangeWordWriteAvoidsImageWord
    range.originalBase range.size context.originalPe.imageBase
    context.originalPe.sizeOfImage offset inside originalNoWrap originalDisjoint
    writeSlot.originalAddress originalBounds.1 originalBounds.2.1
    originalBounds.2.2).symm
  have candidateAvoids := (stackRangeWordWriteAvoidsImageWord
    range.candidateBase range.size context.candidatePe.imageBase
    context.candidatePe.sizeOfImage offset inside candidateNoWrap candidateDisjoint
    writeSlot.candidateAddress candidateBounds.1 candidateBounds.2.1
    candidateBounds.2.2).symm
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact related range rangeMember offset inside aligned

theorem DynamicRangesMemoryHold.afterPairedStaticDynamicPointerWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (rangesValid : world.dynamicRangesValid context = true)
    (slotsValid : staticDynamicPointerSlotsValid context = true)
    (writeSlot : StaticDynamicPointerSlotPair)
    (writeMember : writeSlot ∈ context.staticDynamicPointerSlots)
    (originalValue candidateValue : Word)
    (related : DynamicRangesMemoryHold context world original candidate) :
    DynamicRangesMemoryHold context world
      (original.write32 writeSlot.originalAddress originalValue)
      (candidate.write32 writeSlot.candidateAddress candidateValue) := by
  intro range rangeMember
  have rangeValid : range.disjointFromImages context = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.1.2 range rangeMember
  have wordRelationsValid : range.wordRelationsValid = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.2 range rangeMember
  have writeValid := writeSlot.valid_of_member context slotsValid writeMember
  have originalBounds := writeSlot.originalBounds context writeValid
  have candidateBounds := writeSlot.candidateBounds context writeValid
  have rangeShape := rangeValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeShape
  rcases rangeShape with
    ⟨⟨⟨⟨_nonempty, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  have prior := related range rangeMember
  simp only [DynamicAddressRangePair.wordsHold, List.all_eq_true] at prior ⊢
  simp only [DynamicAddressRangePair.wordRelationsValid,
    List.all_eq_true] at wordRelationsValid
  intro relation relationMember
  have relationShape := wordRelationsValid relation relationMember
  simp only [Bool.and_eq_true, decide_eq_true_eq] at relationShape
  have originalAvoids := (stackRangeWordWriteAvoidsImageWord
    range.originalBase range.size context.originalPe.imageBase
    context.originalPe.sizeOfImage relation.offset relationShape.1
    originalNoWrap originalDisjoint writeSlot.originalAddress
    originalBounds.1 originalBounds.2.1 originalBounds.2.2).symm
  have candidateAvoids := (stackRangeWordWriteAvoidsImageWord
    range.candidateBase range.size context.candidatePe.imageBase
    context.candidatePe.sizeOfImage relation.offset relationShape.1
    candidateNoWrap candidateDisjoint writeSlot.candidateAddress
    candidateBounds.1 candidateBounds.2.1 candidateBounds.2.2).symm
  have priorRelation := prior relation relationMember
  unfold DynamicWordRelation.holds at priorRelation ⊢
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact priorRelation

theorem importIatWordWriteAvoidsStaticDynamicPointer
    (pe : PE32) (imports : List PEImport) (imported : PEImport)
    (iatRva : Nat) (slotAddress : Word)
    (importMember : imported ∈ imports)
    (sameIat : imported.iatRva = iatRva)
    (iatFits : pe.imageBase + iatRva + 4 <= 2 ^ 32)
    (slotFits : slotAddress.toNat + 4 <= 2 ^ 32)
    (notIat : staticWordOverlapsImportIat pe imports slotAddress = false) :
    Write32AvoidsWord (BitVec.ofNat 32 (pe.imageBase + iatRva)) slotAddress := by
  have predicateFalse := Bool.eq_false_iff.mpr
    (List.any_eq_false.mp notIat imported importMember)
  simp [sameIat] at predicateFalse
  have separated : slotAddress.toNat + 4 <= pe.imageBase + iatRva ∨
      pe.imageBase + iatRva + 4 <= slotAddress.toNat := by
    omega
  have iatBefore : pe.imageBase + iatRva < 2 ^ 32 := by omega
  have iatAddressNat :
      (BitVec.ofNat 32 (pe.imageBase + iatRva) : Word).toNat =
        pe.imageBase + iatRva := by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt iatBefore]
  exact write32AvoidsWord_of_nat_disjoint
    (BitVec.ofNat 32 (pe.imageBase + iatRva)) slotAddress
    (by simpa [iatAddressNat] using iatFits) slotFits
    (by simpa [iatAddressNat] using separated.elim Or.inr Or.inl)

theorem ImportAddressesMemoryHold.afterPairedStaticDynamicPointerWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (importsStatic : world.importAddressesStaticValid context = true)
    (slotsValid : staticDynamicPointerSlotsValid context = true)
    (writeSlot : StaticDynamicPointerSlotPair)
    (writeMember : writeSlot ∈ context.staticDynamicPointerSlots)
    (originalValue candidateValue : Word)
    (related : ImportAddressesMemoryHold context world original candidate) :
    ImportAddressesMemoryHold context world
      (original.write32 writeSlot.originalAddress originalValue)
      (candidate.write32 writeSlot.candidateAddress candidateValue) := by
  intro binding bindingMember
  have importsShape := importsStatic
  simp only [RelationalWorld.importAddressesStaticValid, Bool.and_eq_true,
    List.all_eq_true] at importsShape
  have bindingValid := importsShape.2 binding bindingMember
  have writeValid := writeSlot.valid_of_member context slotsValid writeMember
  have writeShape := writeValid
  simp only [StaticDynamicPointerSlotPair.valid, Bool.and_eq_true] at writeShape
  have originalNotIat := writeShape.1.1.1.1.2
  have candidateNotIat := writeShape.1.1.1.2
  rw [Bool.not_eq_true'] at originalNotIat candidateNotIat
  rcases binding.originalImportWitness context bindingValid with
    ⟨originalImport, originalImportMember, originalSameIat⟩
  rcases binding.candidateImportWitness context bindingValid with
    ⟨candidateImport, candidateImportMember, candidateSameIat⟩
  have originalAvoids := importIatWordWriteAvoidsStaticDynamicPointer
    context.originalPe context.originalImports originalImport binding.originalIatRva
    writeSlot.originalAddress originalImportMember originalSameIat
    (binding.originalIatWordBounds context bindingValid).2.2
    (writeSlot.originalBounds context writeValid).2.2 originalNotIat
  have candidateAvoids := importIatWordWriteAvoidsStaticDynamicPointer
    context.candidatePe context.candidateImports candidateImport binding.candidateIatRva
    writeSlot.candidateAddress candidateImportMember candidateSameIat
    (binding.candidateIatWordBounds context bindingValid).2.2
    (writeSlot.candidateBounds context writeValid).2.2 candidateNotIat
  have prior := related binding bindingMember
  unfold ImportAddressPair.memoryHolds at prior ⊢
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact prior

theorem StaticWordRelationSlotsMemoryHold.afterPairedStaticDynamicPointerWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (pointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (wordSlotsValid : staticWordRelationSlotsValid context = true)
    (writeSlot : StaticDynamicPointerSlotPair)
    (writeMember : writeSlot ∈ context.staticDynamicPointerSlots)
    (originalValue candidateValue : Word)
    (related : StaticWordRelationSlotsMemoryHold context world original candidate) :
    StaticWordRelationSlotsMemoryHold context world
      (original.write32 writeSlot.originalAddress originalValue)
      (candidate.write32 writeSlot.candidateAddress candidateValue) := by
  intro querySlot queryMember
  have pointerValid := writeSlot.valid_of_member context pointerSlotsValid writeMember
  have wordShape := wordSlotsValid
  simp only [staticWordRelationSlotsValid, Bool.and_eq_true,
    List.all_eq_true] at wordShape
  have queryValid := wordShape.2 querySlot queryMember
  have originalCross := wordShape.1.1.2
  have candidateCross := wordShape.1.2
  simp only [staticWordRelationSlotsCrossDisjointOn,
    List.all_eq_true] at originalCross candidateCross
  have originalSeparated := originalCross querySlot queryMember writeSlot writeMember
  have candidateSeparated := candidateCross querySlot queryMember writeSlot writeMember
  simp only [Bool.or_eq_true, decide_eq_true_eq, Bool.false_eq_true,
    if_false] at originalSeparated
  simp only [Bool.or_eq_true, decide_eq_true_eq, if_true] at candidateSeparated
  have originalAvoids := write32AvoidsWord_of_nat_disjoint
    querySlot.originalAddress writeSlot.originalAddress
    (querySlot.originalBounds context queryValid).2.2
    (writeSlot.originalBounds context pointerValid).2.2
    originalSeparated
  have candidateAvoids := write32AvoidsWord_of_nat_disjoint
    querySlot.candidateAddress writeSlot.candidateAddress
    (querySlot.candidateBounds context queryValid).2.2
    (writeSlot.candidateBounds context pointerValid).2.2
    candidateSeparated
  have prior := related querySlot queryMember
  unfold StaticWordRelationSlotPair.memoryHolds at prior ⊢
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact prior

theorem StaticDynamicPointerSlotsMemoryHold.afterPairedStaticWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (pointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (wordSlotsValid : staticWordRelationSlotsValid context = true)
    (writeSlot : StaticWordRelationSlotPair)
    (writeMember : writeSlot ∈ context.staticWordRelationSlots)
    (originalValue candidateValue : Word)
    (related : StaticDynamicPointerSlotsMemoryHold context world original candidate) :
    StaticDynamicPointerSlotsMemoryHold context world
      (original.write32 writeSlot.originalAddress originalValue)
      (candidate.write32 writeSlot.candidateAddress candidateValue) := by
  intro querySlot queryMember
  have pointerShape := pointerSlotsValid
  simp only [staticDynamicPointerSlotsValid, Bool.and_eq_true,
    List.all_eq_true] at pointerShape
  have queryValid := pointerShape.2 querySlot queryMember
  have writeValid := writeSlot.valid_of_member context wordSlotsValid writeMember
  have wordShape := wordSlotsValid
  simp only [staticWordRelationSlotsValid, Bool.and_eq_true] at wordShape
  have originalCross := wordShape.1.1.2
  have candidateCross := wordShape.1.2
  simp only [staticWordRelationSlotsCrossDisjointOn,
    List.all_eq_true] at originalCross candidateCross
  have originalSeparated := originalCross writeSlot writeMember querySlot queryMember
  have candidateSeparated := candidateCross writeSlot writeMember querySlot queryMember
  simp only [Bool.or_eq_true, decide_eq_true_eq, Bool.false_eq_true,
    if_false] at originalSeparated
  simp only [Bool.or_eq_true, decide_eq_true_eq, if_true] at candidateSeparated
  have originalAvoids := write32AvoidsWord_of_nat_disjoint
    querySlot.originalAddress writeSlot.originalAddress
    (querySlot.originalBounds context queryValid).2.2
    (writeSlot.originalBounds context writeValid).2.2
    (originalSeparated.elim Or.inr Or.inl)
  have candidateAvoids := write32AvoidsWord_of_nat_disjoint
    querySlot.candidateAddress writeSlot.candidateAddress
    (querySlot.candidateBounds context queryValid).2.2
    (writeSlot.candidateBounds context writeValid).2.2
    (candidateSeparated.elim Or.inr Or.inl)
  have prior := related querySlot queryMember
  unfold StaticDynamicPointerSlotPair.memoryHolds at prior ⊢
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact prior

theorem importIatWordWriteAvoidsStaticWord
    (pe : PE32) (imports : List PEImport) (imported : PEImport)
    (iatRva : Nat) (slotAddress : Word)
    (importMember : imported ∈ imports)
    (sameIat : imported.iatRva = iatRva)
    (iatFits : pe.imageBase + iatRva + 4 <= 2 ^ 32)
    (slotFits : slotAddress.toNat + 4 <= 2 ^ 32)
    (notIat : staticWordOverlapsImportIat pe imports slotAddress = false) :
    Write32AvoidsWord (BitVec.ofNat 32 (pe.imageBase + iatRva)) slotAddress := by
  have predicateFalse := Bool.eq_false_iff.mpr
    (List.any_eq_false.mp notIat imported importMember)
  simp [sameIat] at predicateFalse
  have separated : slotAddress.toNat + 4 <= pe.imageBase + iatRva ∨
      pe.imageBase + iatRva + 4 <= slotAddress.toNat := by
    omega
  have iatBefore : pe.imageBase + iatRva < 2 ^ 32 := by omega
  have iatAddressNat :
      (BitVec.ofNat 32 (pe.imageBase + iatRva) : Word).toNat =
        pe.imageBase + iatRva := by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt iatBefore]
  exact write32AvoidsWord_of_nat_disjoint
    (BitVec.ofNat 32 (pe.imageBase + iatRva)) slotAddress
    (by simpa [iatAddressNat] using iatFits) slotFits
    (by simpa [iatAddressNat] using separated.elim Or.inr Or.inl)

theorem ImportAddressesMemoryHold.afterPairedStaticWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (importsStatic : world.importAddressesStaticValid context = true)
    (slotsValid : staticWordRelationSlotsValid context = true)
    (writeSlot : StaticWordRelationSlotPair)
    (writeMember : writeSlot ∈ context.staticWordRelationSlots)
    (originalValue candidateValue : Word)
    (related : ImportAddressesMemoryHold context world original candidate) :
    ImportAddressesMemoryHold context world
      (original.write32 writeSlot.originalAddress originalValue)
      (candidate.write32 writeSlot.candidateAddress candidateValue) := by
  intro binding bindingMember
  have importsShape := importsStatic
  simp only [RelationalWorld.importAddressesStaticValid, Bool.and_eq_true,
    List.all_eq_true] at importsShape
  have bindingValid := importsShape.2 binding bindingMember
  have writeValid := writeSlot.valid_of_member context slotsValid writeMember
  have writeShape := writeValid
  simp only [StaticWordRelationSlotPair.valid, Bool.and_eq_true] at writeShape
  have originalNotIat := writeShape.1.1.1.1.2
  have candidateNotIat := writeShape.1.1.1.2
  rw [Bool.not_eq_true'] at originalNotIat candidateNotIat
  rcases binding.originalImportWitness context bindingValid with
    ⟨originalImport, originalImportMember, originalSameIat⟩
  rcases binding.candidateImportWitness context bindingValid with
    ⟨candidateImport, candidateImportMember, candidateSameIat⟩
  have originalAvoids := importIatWordWriteAvoidsStaticWord
    context.originalPe context.originalImports originalImport binding.originalIatRva
    writeSlot.originalAddress originalImportMember originalSameIat
    (binding.originalIatWordBounds context bindingValid).2.2
    (writeSlot.originalBounds context writeValid).2.2 originalNotIat
  have candidateAvoids := importIatWordWriteAvoidsStaticWord
    context.candidatePe context.candidateImports candidateImport binding.candidateIatRva
    writeSlot.candidateAddress candidateImportMember candidateSameIat
    (binding.candidateIatWordBounds context bindingValid).2.2
    (writeSlot.candidateBounds context writeValid).2.2 candidateNotIat
  have prior := related binding bindingMember
  unfold ImportAddressPair.memoryHolds at prior ⊢
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact prior

theorem staticWordWriteAvoidsImmutableImageWord
    (pe : PE32) (slotAddress : Word) (absolute expected : Nat)
    (slotFits : slotAddress.toNat + 4 <= 2 ^ 32)
    (notImmutable : staticWordOverlapsImmutableSection pe slotAddress = false)
    (checked : readImmutableImageWord pe absolute 4 = some expected) :
    Write32AvoidsWord (BitVec.ofNat 32 absolute) slotAddress := by
  have bounds := readImmutableImageWord_bounds pe absolute 4 expected checked
  have absoluteBefore : absolute < 2 ^ 32 := by omega
  have addressNat : (BitVec.ofNat 32 absolute : Word).toNat = absolute := by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt absoluteBefore]
  rcases readImmutableImageWord_region pe absolute 4 expected checked with
    header | sectionCase
  · have headerDisjoint :
        slotAddress.toNat + 4 <= pe.imageBase ∨
          pe.imageBase + pe.sizeOfHeaders <= slotAddress.toNat := by
      have noOverlap := notImmutable
      simp [staticWordOverlapsImmutableSection] at noOverlap
      omega
    have separated : absolute + 4 <= slotAddress.toNat ∨
        slotAddress.toNat + 4 <= absolute := by
      omega
    exact write32AvoidsWord_of_nat_disjoint (BitVec.ofNat 32 absolute)
      slotAddress (by simpa [addressNat] using bounds.2.1) slotFits
      (by simpa [addressNat] using separated)
  · rcases sectionCase with
      ⟨sec, sectionMember, immutable, sectionLower, sectionUpper⟩
    have noOverlap := notImmutable
    simp [staticWordOverlapsImmutableSection] at noOverlap
    have listFalse := noOverlap.2
    have separated : absolute + 4 <= slotAddress.toNat ∨
        slotAddress.toNat + 4 <= absolute := by
      by_cases beforeSectionEnd :
          slotAddress.toNat <
            pe.imageBase + sec.virtualAddress + sec.mappedSize
      · have slotBeforeSection :=
          listFalse sec sectionMember immutable beforeSectionEnd
        omega
      · omega
    exact write32AvoidsWord_of_nat_disjoint (BitVec.ofNat 32 absolute)
      slotAddress (by simpa [addressNat] using bounds.2.1) slotFits
      (by simpa [addressNat] using separated)

theorem ImmutableImageWordMemory.afterStaticWordWrite
    (pe : PE32) (memory : Memory) (slotAddress value : Word)
    (slotFits : slotAddress.toNat + 4 <= 2 ^ 32)
    (notImmutable : staticWordOverlapsImmutableSection pe slotAddress = false)
    (immutable : ImmutableImageWordMemory pe memory) :
    ImmutableImageWordMemory pe (memory.write32 slotAddress value) := by
  intro absolute expected checked
  have avoids := staticWordWriteAvoidsImmutableImageWord pe slotAddress
    absolute expected slotFits notImmutable checked
  rw [Memory.read32_write32_of_avoids _ _ _ _ avoids]
  exact immutable absolute expected checked

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
  have originalWritable := slotValid.1.1.1.1.1.1.2
  have candidateWritable := slotValid.1.1.1.1.1.2
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

theorem StaticWordRelationSlotsMemoryHold.afterPairedStackWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (slotsValid : staticWordRelationSlotsValid context = true)
    (stackRange : DynamicAddressRangePair)
    (stackValid : stackRange.disjointFromImages context = true)
    (stackOffset : Nat) (stackInside : stackOffset + 4 <= stackRange.size)
    (originalValue candidateValue : Word)
    (related : StaticWordRelationSlotsMemoryHold context world original candidate) :
    StaticWordRelationSlotsMemoryHold context world
      (original.write32
        (stackRange.originalBase + BitVec.ofNat 32 stackOffset) originalValue)
      (candidate.write32
        (stackRange.candidateBase + BitVec.ofNat 32 stackOffset) candidateValue) := by
  simp only [staticWordRelationSlotsValid, Bool.and_eq_true,
    List.all_eq_true] at slotsValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at stackValid
  rcases stackValid with
    ⟨⟨⟨⟨_rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  intro slot slotMember
  have slotValid := slotsValid.2 slot slotMember
  simp only [StaticWordRelationSlotPair.valid, Bool.and_eq_true] at slotValid
  have originalWritable := slotValid.1.1.1.1.1.1.2
  have candidateWritable := slotValid.1.1.1.1.1.2
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
  unfold StaticWordRelationSlotPair.memoryHolds at prior ⊢
  rw [Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact prior

def staticDynamicPointerSlotByteCoveredOn (candidate : Bool)
    (context : StaticProofContext) (address : Word) : Bool :=
  context.staticDynamicPointerSlots.any fun slot =>
    let base := if candidate then slot.candidateAddress else slot.originalAddress
    base.toNat <= address.toNat && address.toNat < base.toNat + 4

def staticDynamicPointerSlotByteCoveredOriginal (context : StaticProofContext)
    (address : Word) : Bool :=
  staticDynamicPointerSlotByteCoveredOn false context address

def staticDynamicPointerSlotByteCoveredCandidate (context : StaticProofContext)
    (address : Word) : Bool :=
  staticDynamicPointerSlotByteCoveredOn true context address

def staticWordRelationSlotByteCoveredOn (candidate : Bool)
    (context : StaticProofContext) (address : Word) : Bool :=
  context.staticWordRelationSlots.any fun slot =>
    let base := if candidate then slot.candidateAddress else slot.originalAddress
    base.toNat <= address.toNat && address.toNat < base.toNat + 4

def staticWordRelationSlotByteCoveredOriginal (context : StaticProofContext)
    (address : Word) : Bool :=
  staticWordRelationSlotByteCoveredOn false context address

def staticWordRelationSlotByteCoveredCandidate (context : StaticProofContext)
    (address : Word) : Bool :=
  staticWordRelationSlotByteCoveredOn true context address

/-- A byte is excluded as side-specific immutable image state only when an
existing `ImmutableImageWordMemory` obligation fixes a complete word that
contains it.  Looking for all four possible containing starts avoids weakening
the relation at section/header boundaries or for sub-word mapped fragments. -/
def immutableImageByteCoveredByWord (pe : PE32) (address : Word) : Bool :=
  (List.range 4).any fun offset =>
    offset <= address.toNat &&
      (readImmutableImageWord pe (address.toNat - offset) 4).isSome

/-- Ordinary equality does not govern a byte when either side is fixed by its
own immutable PE-image obligation. This admits one-sided section tails while
leaving any later read to the side-specific immutable-memory proof. -/
def pairedImmutableImageByteCovered (context : StaticProofContext)
    (values : List ValueTargetPair) (candidateAddress : Word) : Bool :=
  immutableImageByteCoveredByWord context.candidatePe candidateAddress ||
    immutableImageByteCoveredByWord context.originalPe
      (normalizeDataAddress values candidateAddress)

def ordinaryOriginalMemoryAddressExcluded (context : StaticProofContext)
    (world : RelationalWorld) (address : Word) : Bool :=
  importIatByteCoveredOriginal context world address ||
    stackByteCoveredOriginal world address ||
    dynamicByteCoveredOriginal world address ||
    staticDynamicPointerSlotByteCoveredOriginal context address ||
    staticWordRelationSlotByteCoveredOriginal context address

def ordinaryMemoryAddressExcluded (context : StaticProofContext)
    (world : RelationalWorld) (values : List ValueTargetPair)
    (candidateAddress : Word) : Bool :=
  importIatByteCoveredCandidate context world candidateAddress ||
    stackByteCoveredCandidate world candidateAddress ||
    dynamicByteCoveredCandidate world candidateAddress ||
    staticDynamicPointerSlotByteCoveredCandidate context candidateAddress ||
    staticWordRelationSlotByteCoveredCandidate context candidateAddress ||
    pairedImmutableImageByteCovered context values candidateAddress ||
    ordinaryOriginalMemoryAddressExcluded context world
      (normalizeDataAddress values candidateAddress)

def ordinaryMemoryWordExcluded (context : StaticProofContext)
    (world : RelationalWorld) (values : List ValueTargetPair)
    (candidateAddress : Word) : Bool :=
  ((List.range 4).any fun offset =>
      ordinaryMemoryAddressExcluded context world values
        (candidateAddress + BitVec.ofNat 32 offset)) ||
    (List.range 4).any fun offset =>
      ordinaryOriginalMemoryAddressExcluded context world
        (normalizeDataAddress values candidateAddress + BitVec.ofNat 32 offset)

theorem staticWordRelationSlotByteCoveredOn_of_slot_byte
    (context : StaticProofContext) (candidate : Bool)
    (slot : StaticWordRelationSlotPair)
    (member : slot ∈ context.staticWordRelationSlots)
    (valid : slot.valid context = true) (byte : Nat) (byteBefore : byte < 4) :
    staticWordRelationSlotByteCoveredOn candidate context
      ((if candidate then slot.candidateAddress else slot.originalAddress) +
        BitVec.ofNat 32 byte) = true := by
  have sideFits :
      (if candidate then slot.candidateAddress else slot.originalAddress).toNat + 4 <=
        2 ^ 32 := by
    cases candidate
    · simpa using (slot.originalBounds context valid).2.2
    · simpa using (slot.candidateBounds context valid).2.2
  have byteSmall : byte < 2 ^ 32 := by omega
  have addressBefore :
      (if candidate then slot.candidateAddress else slot.originalAddress).toNat +
          byte < 2 ^ 32 := by
    omega
  have addressNat :
      ((if candidate then slot.candidateAddress else slot.originalAddress) +
          BitVec.ofNat 32 byte).toNat =
        (if candidate then slot.candidateAddress else slot.originalAddress).toNat +
          byte := by
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt byteSmall, Nat.mod_eq_of_lt addressBefore]
  simp only [staticWordRelationSlotByteCoveredOn, List.any_eq_true]
  refine ⟨slot, member, ?_⟩
  simp only [addressNat, Bool.and_eq_true, decide_eq_true_eq]
  omega

theorem Memory.write32_apply_of_staticWordSlotByteUncovered
    (context : StaticProofContext) (candidate : Bool)
    (slot : StaticWordRelationSlotPair)
    (member : slot ∈ context.staticWordRelationSlots)
    (valid : slot.valid context = true)
    (memory : Memory) (value query : Word)
    (uncovered : staticWordRelationSlotByteCoveredOn candidate context query = false) :
    memory.write32
        (if candidate then slot.candidateAddress else slot.originalAddress) value query =
      memory query := by
  let writeAddress := if candidate then slot.candidateAddress else slot.originalAddress
  have avoids (byte : Nat) (byteBefore : byte < 4) :
      query ≠ writeAddress + BitVec.ofNat 32 byte := by
    intro overlap
    have covered := staticWordRelationSlotByteCoveredOn_of_slot_byte
      context candidate slot member valid byte byteBefore
    change staticWordRelationSlotByteCoveredOn candidate context
      (writeAddress + BitVec.ofNat 32 byte) = true at covered
    rw [← overlap, uncovered] at covered
    contradiction
  have h0 := avoids 0 (by omega)
  have h1 := avoids 1 (by omega)
  have h2 := avoids 2 (by omega)
  have h3 := avoids 3 (by omega)
  have h0' : query ≠
      (if candidate then slot.candidateAddress else slot.originalAddress) := by
    simpa [writeAddress] using h0
  have h1' : query ≠
      (if candidate then slot.candidateAddress else slot.originalAddress) +
        BitVec.ofNat 32 1 := by simpa [writeAddress] using h1
  have h2' : query ≠
      (if candidate then slot.candidateAddress else slot.originalAddress) +
        BitVec.ofNat 32 2 := by simpa [writeAddress] using h2
  have h3' : query ≠
      (if candidate then slot.candidateAddress else slot.originalAddress) +
        BitVec.ofNat 32 3 := by simpa [writeAddress] using h3
  simp [Memory.write32, h0', h1', h2', h3']

theorem write32AvoidsWord_of_staticWordSlotBytesUncovered
    (context : StaticProofContext) (candidate : Bool)
    (slot : StaticWordRelationSlotPair)
    (member : slot ∈ context.staticWordRelationSlots)
    (valid : slot.valid context = true) (wordAddress : Word)
    (uncovered : ∀ byte, byte < 4 →
      staticWordRelationSlotByteCoveredOn candidate context
        (wordAddress + BitVec.ofNat 32 byte) = false) :
    Write32AvoidsWord wordAddress
      (if candidate then slot.candidateAddress else slot.originalAddress) := by
  intro wordByte wordByteBefore writeByte writeByteBefore overlap
  have covered := staticWordRelationSlotByteCoveredOn_of_slot_byte
    context candidate slot member valid writeByte writeByteBefore
  rw [← overlap, uncovered wordByte wordByteBefore] at covered
  contradiction

theorem staticDynamicPointerSlotByteCoveredOn_of_slot_byte
    (context : StaticProofContext) (candidate : Bool)
    (slot : StaticDynamicPointerSlotPair)
    (member : slot ∈ context.staticDynamicPointerSlots)
    (valid : slot.valid context = true) (byte : Nat) (byteBefore : byte < 4) :
    staticDynamicPointerSlotByteCoveredOn candidate context
      ((if candidate then slot.candidateAddress else slot.originalAddress) +
        BitVec.ofNat 32 byte) = true := by
  have sideFits :
      (if candidate then slot.candidateAddress else slot.originalAddress).toNat + 4 <=
        2 ^ 32 := by
    cases candidate
    · simpa using (slot.originalBounds context valid).2.2
    · simpa using (slot.candidateBounds context valid).2.2
  have byteSmall : byte < 2 ^ 32 := by omega
  have addressBefore :
      (if candidate then slot.candidateAddress else slot.originalAddress).toNat +
          byte < 2 ^ 32 := by omega
  have addressNat :
      ((if candidate then slot.candidateAddress else slot.originalAddress) +
          BitVec.ofNat 32 byte).toNat =
        (if candidate then slot.candidateAddress else slot.originalAddress).toNat +
          byte := by
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt (by omega : byte < 2 ^ 32),
      Nat.mod_eq_of_lt addressBefore]
  simp only [staticDynamicPointerSlotByteCoveredOn, List.any_eq_true]
  refine ⟨slot, member, ?_⟩
  simp only [addressNat, Bool.and_eq_true, decide_eq_true_eq]
  omega

theorem Memory.write32_apply_of_staticDynamicPointerSlotByteUncovered
    (context : StaticProofContext) (candidate : Bool)
    (slot : StaticDynamicPointerSlotPair)
    (member : slot ∈ context.staticDynamicPointerSlots)
    (valid : slot.valid context = true)
    (memory : Memory) (value query : Word)
    (uncovered : staticDynamicPointerSlotByteCoveredOn candidate context query = false) :
    memory.write32
        (if candidate then slot.candidateAddress else slot.originalAddress) value query =
      memory query := by
  let writeAddress := if candidate then slot.candidateAddress else slot.originalAddress
  have avoids (byte : Nat) (byteBefore : byte < 4) :
      query ≠ writeAddress + BitVec.ofNat 32 byte := by
    intro overlap
    have covered := staticDynamicPointerSlotByteCoveredOn_of_slot_byte
      context candidate slot member valid byte byteBefore
    change staticDynamicPointerSlotByteCoveredOn candidate context
      (writeAddress + BitVec.ofNat 32 byte) = true at covered
    rw [← overlap, uncovered] at covered
    contradiction
  have h0 := avoids 0 (by omega)
  have h1 := avoids 1 (by omega)
  have h2 := avoids 2 (by omega)
  have h3 := avoids 3 (by omega)
  have h0' : query ≠
      (if candidate then slot.candidateAddress else slot.originalAddress) := by
    simpa [writeAddress] using h0
  have h1' : query ≠
      (if candidate then slot.candidateAddress else slot.originalAddress) +
        BitVec.ofNat 32 1 := by simpa [writeAddress] using h1
  have h2' : query ≠
      (if candidate then slot.candidateAddress else slot.originalAddress) +
        BitVec.ofNat 32 2 := by simpa [writeAddress] using h2
  have h3' : query ≠
      (if candidate then slot.candidateAddress else slot.originalAddress) +
        BitVec.ofNat 32 3 := by simpa [writeAddress] using h3
  simp [Memory.write32, h0', h1', h2', h3']

theorem write32AvoidsWord_of_staticDynamicPointerSlotBytesUncovered
    (context : StaticProofContext) (candidate : Bool)
    (slot : StaticDynamicPointerSlotPair)
    (member : slot ∈ context.staticDynamicPointerSlots)
    (valid : slot.valid context = true) (wordAddress : Word)
    (uncovered : ∀ byte, byte < 4 →
      staticDynamicPointerSlotByteCoveredOn candidate context
        (wordAddress + BitVec.ofNat 32 byte) = false) :
    Write32AvoidsWord wordAddress
      (if candidate then slot.candidateAddress else slot.originalAddress) := by
  intro wordByte wordByteBefore writeByte writeByteBefore overlap
  have covered := staticDynamicPointerSlotByteCoveredOn_of_slot_byte
    context candidate slot member valid writeByte writeByteBefore
  rw [← overlap, uncovered wordByte wordByteBefore] at covered
  contradiction

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

theorem ordinaryMemoryRelated_self_of_identity_targets
    (context : StaticProofContext) (world : RelationalWorld)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (memory : Memory)
    (identity : forall target, target ∈ values ->
      target.originalValue = target.candidateValue) :
    ordinaryMemoryRelated context world targets values memory memory := by
  unfold ordinaryMemoryRelated
  split
  · constructor
    · intro address _relocationByte _ordinary
      rw [normalizeDataAddress_eq_self_of_identity_targets values address identity]
    · intro address _relocationWord _ordinary
      rw [normalizeDataAddress_eq_self_of_identity_targets values address identity]
      exact wordRelated_self _ _ _ _ _
  · intro address _ordinary
    rw [normalizeDataAddress_eq_self_of_identity_targets values address identity]

structure RelationalMemoryFamiliesHold (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : Memory) : Prop where
  stackRanges : StackRangesMemoryHold context world original candidate
  importAddresses : ImportAddressesMemoryHold context world original candidate
  originalImmutable : ImmutableImageWordMemory context.originalPe original
  candidateImmutable : ImmutableImageWordMemory context.candidatePe candidate
  ordinary : ordinaryMemoryRelated context world context.codeMap.entries.toList
    (context.relationalValueTargets world) original candidate
  staticPointerSlots : StaticDynamicPointerSlotsMemoryHold context world original candidate
  staticWordSlots : StaticWordRelationSlotsMemoryHold context world original candidate

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
  preservesStaticPointerSlots :
    StaticDynamicPointerSlotsMemoryHold context world original candidate →
      StaticDynamicPointerSlotsMemoryHold context world
        (applyConcreteWrites original originalWrites)
        (applyConcreteWrites candidate candidateWrites)
  preservesStaticWordSlots :
    StaticWordRelationSlotsMemoryHold context world original candidate →
      StaticWordRelationSlotsMemoryHold context world
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
    staticPointerSlots :=
      frame.preservesStaticPointerSlots related.staticPointerSlots
    staticWordSlots := frame.preservesStaticWordSlots related.staticWordSlots
  }

theorem stackByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (included : ordinaryMemoryAddressExcluded context world values
      candidateAddress = false) :
    stackByteCoveredCandidate world candidateAddress = false := by
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryMemoryAddressExcluded, ordinaryOriginalMemoryAddressExcluded,
    covered] at included

theorem normalizedStackByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (included : ordinaryMemoryAddressExcluded context world values
      candidateAddress = false) :
    stackByteCoveredOriginal world
      (normalizeDataAddress values candidateAddress) = false := by
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryMemoryAddressExcluded, ordinaryOriginalMemoryAddressExcluded,
    covered] at included

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
  have noOriginalExclusion := Bool.eq_false_iff.mpr
    (List.any_eq_false.mp included.2 byte
      (List.mem_range.mpr byteBefore))
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryOriginalMemoryAddressExcluded, covered] at noOriginalExclusion

theorem dynamicByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (included : ordinaryMemoryAddressExcluded context world values
      candidateAddress = false) :
    dynamicByteCoveredCandidate world candidateAddress = false := by
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryMemoryAddressExcluded, ordinaryOriginalMemoryAddressExcluded,
    covered] at included

theorem normalizedDynamicByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (included : ordinaryMemoryAddressExcluded context world values
      candidateAddress = false) :
    dynamicByteCoveredOriginal world
      (normalizeDataAddress values candidateAddress) = false := by
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryMemoryAddressExcluded, ordinaryOriginalMemoryAddressExcluded,
    covered] at included

theorem dynamicByteCoveredCandidate_false_of_ordinaryMemoryWordIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (byte : Nat) (byteBefore : byte < 4)
    (included : ordinaryMemoryWordExcluded context world values
      candidateAddress = false) :
    dynamicByteCoveredCandidate world
      (candidateAddress + BitVec.ofNat 32 byte) = false := by
  simp only [ordinaryMemoryWordExcluded, Bool.or_eq_false_iff] at included
  have noOrdinaryExclusion := List.any_eq_false.mp included.1 byte
    (List.mem_range.mpr byteBefore)
  exact dynamicByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
    context world values (candidateAddress + BitVec.ofNat 32 byte)
    (Bool.eq_false_iff.mpr noOrdinaryExclusion)

theorem normalizedWordDynamicByteCoveredOriginal_false_of_ordinaryMemoryWordIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (byte : Nat) (byteBefore : byte < 4)
    (included : ordinaryMemoryWordExcluded context world values
      candidateAddress = false) :
    dynamicByteCoveredOriginal world
      (normalizeDataAddress values candidateAddress + BitVec.ofNat 32 byte) = false := by
  simp only [ordinaryMemoryWordExcluded, Bool.or_eq_false_iff] at included
  have noOriginalExclusion := Bool.eq_false_iff.mpr
    (List.any_eq_false.mp included.2 byte
      (List.mem_range.mpr byteBefore))
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryOriginalMemoryAddressExcluded, covered] at noOriginalExclusion

theorem staticDynamicPointerSlotByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (included : ordinaryMemoryAddressExcluded context world values
      candidateAddress = false) :
    staticDynamicPointerSlotByteCoveredCandidate context candidateAddress = false := by
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryMemoryAddressExcluded, covered] at included

theorem normalizedStaticDynamicPointerSlotByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (included : ordinaryMemoryAddressExcluded context world values
      candidateAddress = false) :
    staticDynamicPointerSlotByteCoveredOriginal context
      (normalizeDataAddress values candidateAddress) = false := by
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryMemoryAddressExcluded, ordinaryOriginalMemoryAddressExcluded,
    covered] at included

theorem staticDynamicPointerSlotByteCoveredCandidate_false_of_ordinaryMemoryWordIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (byte : Nat) (byteBefore : byte < 4)
    (included : ordinaryMemoryWordExcluded context world values
      candidateAddress = false) :
    staticDynamicPointerSlotByteCoveredCandidate context
      (candidateAddress + BitVec.ofNat 32 byte) = false := by
  simp only [ordinaryMemoryWordExcluded, Bool.or_eq_false_iff] at included
  have noOrdinaryExclusion := List.any_eq_false.mp included.1 byte
    (List.mem_range.mpr byteBefore)
  exact staticDynamicPointerSlotByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
    context world values (candidateAddress + BitVec.ofNat 32 byte)
    (Bool.eq_false_iff.mpr noOrdinaryExclusion)

theorem normalizedWordStaticDynamicPointerSlotByteCoveredOriginal_false_of_ordinaryMemoryWordIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (byte : Nat) (byteBefore : byte < 4)
    (included : ordinaryMemoryWordExcluded context world values
      candidateAddress = false) :
    staticDynamicPointerSlotByteCoveredOriginal context
      (normalizeDataAddress values candidateAddress + BitVec.ofNat 32 byte) = false := by
  simp only [ordinaryMemoryWordExcluded, Bool.or_eq_false_iff] at included
  have noOriginalExclusion := Bool.eq_false_iff.mpr
    (List.any_eq_false.mp included.2 byte
      (List.mem_range.mpr byteBefore))
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryOriginalMemoryAddressExcluded, covered] at noOriginalExclusion

theorem staticWordSlotByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (included : ordinaryMemoryAddressExcluded context world values
      candidateAddress = false) :
    staticWordRelationSlotByteCoveredCandidate context candidateAddress = false := by
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryMemoryAddressExcluded, covered] at included

theorem normalizedStaticWordSlotByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (included : ordinaryMemoryAddressExcluded context world values
      candidateAddress = false) :
    staticWordRelationSlotByteCoveredOriginal context
      (normalizeDataAddress values candidateAddress) = false := by
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryMemoryAddressExcluded, ordinaryOriginalMemoryAddressExcluded,
    covered] at included

theorem staticWordSlotByteCoveredCandidate_false_of_ordinaryMemoryWordIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (byte : Nat) (byteBefore : byte < 4)
    (included : ordinaryMemoryWordExcluded context world values
      candidateAddress = false) :
    staticWordRelationSlotByteCoveredCandidate context
      (candidateAddress + BitVec.ofNat 32 byte) = false := by
  simp only [ordinaryMemoryWordExcluded, Bool.or_eq_false_iff] at included
  have noOrdinaryExclusion := List.any_eq_false.mp included.1 byte
    (List.mem_range.mpr byteBefore)
  exact staticWordSlotByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
    context world values (candidateAddress + BitVec.ofNat 32 byte)
    (Bool.eq_false_iff.mpr noOrdinaryExclusion)

theorem normalizedWordStaticWordSlotByteCoveredOriginal_false_of_ordinaryMemoryWordIncluded
    (context : StaticProofContext) (world : RelationalWorld)
    (values : List ValueTargetPair) (candidateAddress : Word)
    (byte : Nat) (byteBefore : byte < 4)
    (included : ordinaryMemoryWordExcluded context world values
      candidateAddress = false) :
    staticWordRelationSlotByteCoveredOriginal context
      (normalizeDataAddress values candidateAddress + BitVec.ofNat 32 byte) = false := by
  simp only [ordinaryMemoryWordExcluded, Bool.or_eq_false_iff] at included
  have noOriginalExclusion := Bool.eq_false_iff.mpr
    (List.any_eq_false.mp included.2 byte
      (List.mem_range.mpr byteBefore))
  apply Bool.eq_false_iff.mpr
  intro covered
  simp [ordinaryOriginalMemoryAddressExcluded, covered] at noOriginalExclusion

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

theorem ordinaryMemoryRelated_after_paired_dynamic_word_write
    (context : StaticProofContext) (world : RelationalWorld)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Memory)
    (range : DynamicAddressRangePair) (rangeMember : range ∈ world.dynamicRanges)
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
        dynamicByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
          context world values address ordinaryIncluded
      have originalUncovered :=
        normalizedDynamicByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
          context world values address ordinaryIncluded
      have candidatePreserved := Memory.write32_apply_of_dynamicByteUncovered
        context true world range rangeMember rangeValid offset inside candidate
        candidateValue address candidateUncovered
      have originalPreserved := Memory.write32_apply_of_dynamicByteUncovered
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
      have candidateAvoids := write32AvoidsWord_of_dynamicBytesUncovered context true
        world range rangeMember rangeValid offset inside address
        (fun byte byteBefore =>
          dynamicByteCoveredCandidate_false_of_ordinaryMemoryWordIncluded
            context world values address byte byteBefore ordinaryIncluded)
      have originalAvoids := write32AvoidsWord_of_dynamicBytesUncovered context false
        world range rangeMember rangeValid offset inside
        (normalizeDataAddress values address)
        (fun byte byteBefore =>
          normalizedWordDynamicByteCoveredOriginal_false_of_ordinaryMemoryWordIncluded
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
      dynamicByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
        context world values address ordinaryIncluded
    have originalUncovered :=
      normalizedDynamicByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
        context world values address ordinaryIncluded
    have candidatePreserved := Memory.write32_apply_of_dynamicByteUncovered
      context true world range rangeMember rangeValid offset inside candidate
      candidateValue address candidateUncovered
    have originalPreserved := Memory.write32_apply_of_dynamicByteUncovered
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

theorem ordinaryMemoryRelated_after_paired_static_word_write
    (context : StaticProofContext) (world : RelationalWorld)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Memory)
    (slot : StaticWordRelationSlotPair)
    (slotMember : slot ∈ context.staticWordRelationSlots)
    (slotValid : slot.valid context = true)
    (originalValue candidateValue : Word)
    (related : ordinaryMemoryRelated context world targets values original candidate) :
    ordinaryMemoryRelated context world targets values
      (original.write32 slot.originalAddress originalValue)
      (candidate.write32 slot.candidateAddress candidateValue) := by
  by_cases relocations : hasRelocationWords values = true
  · simp only [ordinaryMemoryRelated, relocations] at related ⊢
    rcases related with ⟨relatedBytes, relatedWords⟩
    constructor
    · intro address relocationIncluded ordinaryIncluded
      have candidateUncovered :
          staticWordRelationSlotByteCoveredOn true context address = false := by
        simpa [staticWordRelationSlotByteCoveredCandidate] using
          staticWordSlotByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
            context world values address ordinaryIncluded
      have originalUncovered : staticWordRelationSlotByteCoveredOn false context
          (normalizeDataAddress values address) = false := by
        simpa [staticWordRelationSlotByteCoveredOriginal] using
          normalizedStaticWordSlotByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
            context world values address ordinaryIncluded
      have candidatePreserved :=
        Memory.write32_apply_of_staticWordSlotByteUncovered context true slot
          slotMember slotValid candidate candidateValue address candidateUncovered
      have originalPreserved :=
        Memory.write32_apply_of_staticWordSlotByteUncovered context false slot
          slotMember slotValid original originalValue
          (normalizeDataAddress values address) originalUncovered
      rw [show candidate.write32 slot.candidateAddress candidateValue address =
          candidate address by simpa using candidatePreserved,
        show original.write32 slot.originalAddress originalValue
            (normalizeDataAddress values address) =
          original (normalizeDataAddress values address) by
            simpa using originalPreserved]
      exact relatedBytes address relocationIncluded ordinaryIncluded
    · intro address relocationStart ordinaryIncluded
      have candidateAvoids :=
        write32AvoidsWord_of_staticWordSlotBytesUncovered context true slot
          slotMember slotValid address (fun byte byteBefore => by
            simpa [staticWordRelationSlotByteCoveredCandidate] using
              staticWordSlotByteCoveredCandidate_false_of_ordinaryMemoryWordIncluded
                context world values address byte byteBefore ordinaryIncluded)
      have originalAvoids :=
        write32AvoidsWord_of_staticWordSlotBytesUncovered context false slot
          slotMember slotValid (normalizeDataAddress values address)
          (fun byte byteBefore => by
            simpa [staticWordRelationSlotByteCoveredOriginal] using
              normalizedWordStaticWordSlotByteCoveredOriginal_false_of_ordinaryMemoryWordIncluded
                context world values address byte byteBefore ordinaryIncluded)
      rw [Memory.read32_write32_of_avoids _ _ _ _
          (by simpa using originalAvoids),
        Memory.read32_write32_of_avoids _ _ _ _
          (by simpa using candidateAvoids)]
      exact relatedWords address relocationStart ordinaryIncluded
  · have noRelocations : hasRelocationWords values = false :=
      Bool.eq_false_iff.mpr relocations
    simp only [ordinaryMemoryRelated, noRelocations] at related ⊢
    intro address ordinaryIncluded
    have candidateUncovered :
        staticWordRelationSlotByteCoveredOn true context address = false := by
      simpa [staticWordRelationSlotByteCoveredCandidate] using
        staticWordSlotByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
          context world values address ordinaryIncluded
    have originalUncovered : staticWordRelationSlotByteCoveredOn false context
        (normalizeDataAddress values address) = false := by
      simpa [staticWordRelationSlotByteCoveredOriginal] using
        normalizedStaticWordSlotByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
          context world values address ordinaryIncluded
    have candidatePreserved :=
      Memory.write32_apply_of_staticWordSlotByteUncovered context true slot
        slotMember slotValid candidate candidateValue address candidateUncovered
    have originalPreserved :=
      Memory.write32_apply_of_staticWordSlotByteUncovered context false slot
        slotMember slotValid original originalValue
        (normalizeDataAddress values address) originalUncovered
    rw [show candidate.write32 slot.candidateAddress candidateValue address =
        candidate address by simpa using candidatePreserved,
      show original.write32 slot.originalAddress originalValue
          (normalizeDataAddress values address) =
        original (normalizeDataAddress values address) by
          simpa using originalPreserved]
    exact related address ordinaryIncluded

theorem ordinaryMemoryRelated_after_paired_static_dynamic_pointer_write
    (context : StaticProofContext) (world : RelationalWorld)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Memory)
    (slot : StaticDynamicPointerSlotPair)
    (slotMember : slot ∈ context.staticDynamicPointerSlots)
    (slotValid : slot.valid context = true)
    (originalValue candidateValue : Word)
    (related : ordinaryMemoryRelated context world targets values original candidate) :
    ordinaryMemoryRelated context world targets values
      (original.write32 slot.originalAddress originalValue)
      (candidate.write32 slot.candidateAddress candidateValue) := by
  by_cases relocations : hasRelocationWords values = true
  · simp only [ordinaryMemoryRelated, relocations] at related ⊢
    rcases related with ⟨relatedBytes, relatedWords⟩
    constructor
    · intro address relocationIncluded ordinaryIncluded
      have candidateUncovered :
          staticDynamicPointerSlotByteCoveredOn true context address = false := by
        simpa [staticDynamicPointerSlotByteCoveredCandidate] using
          staticDynamicPointerSlotByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
            context world values address ordinaryIncluded
      have originalUncovered : staticDynamicPointerSlotByteCoveredOn false context
          (normalizeDataAddress values address) = false := by
        simpa [staticDynamicPointerSlotByteCoveredOriginal] using
          normalizedStaticDynamicPointerSlotByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
            context world values address ordinaryIncluded
      have candidatePreserved :=
        Memory.write32_apply_of_staticDynamicPointerSlotByteUncovered
          context true slot slotMember slotValid candidate candidateValue address
          candidateUncovered
      have originalPreserved :=
        Memory.write32_apply_of_staticDynamicPointerSlotByteUncovered
          context false slot slotMember slotValid original originalValue
          (normalizeDataAddress values address) originalUncovered
      rw [show candidate.write32 slot.candidateAddress candidateValue address =
          candidate address by simpa using candidatePreserved,
        show original.write32 slot.originalAddress originalValue
            (normalizeDataAddress values address) =
          original (normalizeDataAddress values address) by
            simpa using originalPreserved]
      exact relatedBytes address relocationIncluded ordinaryIncluded
    · intro address relocationStart ordinaryIncluded
      have candidateAvoids :=
        write32AvoidsWord_of_staticDynamicPointerSlotBytesUncovered
          context true slot slotMember slotValid address (fun byte byteBefore => by
            simpa [staticDynamicPointerSlotByteCoveredCandidate] using
              staticDynamicPointerSlotByteCoveredCandidate_false_of_ordinaryMemoryWordIncluded
                context world values address byte byteBefore ordinaryIncluded)
      have originalAvoids :=
        write32AvoidsWord_of_staticDynamicPointerSlotBytesUncovered
          context false slot slotMember slotValid
          (normalizeDataAddress values address) (fun byte byteBefore => by
            simpa [staticDynamicPointerSlotByteCoveredOriginal] using
              normalizedWordStaticDynamicPointerSlotByteCoveredOriginal_false_of_ordinaryMemoryWordIncluded
                context world values address byte byteBefore ordinaryIncluded)
      rw [Memory.read32_write32_of_avoids _ _ _ _ (by simpa using originalAvoids),
        Memory.read32_write32_of_avoids _ _ _ _ (by simpa using candidateAvoids)]
      exact relatedWords address relocationStart ordinaryIncluded
  · have noRelocations : hasRelocationWords values = false :=
      Bool.eq_false_iff.mpr relocations
    simp only [ordinaryMemoryRelated, noRelocations] at related ⊢
    intro address ordinaryIncluded
    have candidateUncovered :
        staticDynamicPointerSlotByteCoveredOn true context address = false := by
      simpa [staticDynamicPointerSlotByteCoveredCandidate] using
        staticDynamicPointerSlotByteCoveredCandidate_false_of_ordinaryMemoryAddressIncluded
          context world values address ordinaryIncluded
    have originalUncovered : staticDynamicPointerSlotByteCoveredOn false context
        (normalizeDataAddress values address) = false := by
      simpa [staticDynamicPointerSlotByteCoveredOriginal] using
        normalizedStaticDynamicPointerSlotByteCoveredOriginal_false_of_ordinaryMemoryAddressIncluded
          context world values address ordinaryIncluded
    have candidatePreserved :=
      Memory.write32_apply_of_staticDynamicPointerSlotByteUncovered
        context true slot slotMember slotValid candidate candidateValue address
        candidateUncovered
    have originalPreserved :=
      Memory.write32_apply_of_staticDynamicPointerSlotByteUncovered
        context false slot slotMember slotValid original originalValue
        (normalizeDataAddress values address) originalUncovered
    rw [show candidate.write32 slot.candidateAddress candidateValue address =
        candidate address by simpa using candidatePreserved,
      show original.write32 slot.originalAddress originalValue
          (normalizeDataAddress values address) =
        original (normalizeDataAddress values address) by simpa using originalPreserved]
    exact related address ordinaryIncluded

theorem RelationalMemoryFamiliesHold.afterPairedStackWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (stackRangesValid : world.stackRangesValid context = true)
    (importsStatic : world.importAddressesStaticValid context = true)
    (dynamicRangesValid : world.dynamicRangesValid context = true)
    (staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (staticWordSlotsValid : staticWordRelationSlotsValid context = true)
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
      preservesStaticPointerSlots := by
        intro staticPointerSlots
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StaticDynamicPointerSlotsMemoryHold.afterPairedStackWordWrite context world
            original candidate staticPointerSlotsValid location.range locationValid
            location.offset location.inside originalValue candidateValue
            staticPointerSlots
      preservesStaticWordSlots := by
        intro staticWordSlots
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StaticWordRelationSlotsMemoryHold.afterPairedStackWordWrite context world
            original candidate staticWordSlotsValid location.range locationValid
            location.offset location.inside originalValue candidateValue
            staticWordSlots
    } related
  simpa [applyConcreteWrites] using updated

theorem RelationalMemoryFamiliesHold.afterPairedDynamicWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (stackRangesValid : world.stackRangesValid context = true)
    (importsStatic : world.importAddressesStaticValid context = true)
    (dynamicRangesValid : world.dynamicRangesValid context = true)
    (staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (staticWordSlotsValid : staticWordRelationSlotsValid context = true)
    (location : PairedDynamicWordLocation world)
    (originalValue candidateValue : Word)
    (valuesRelated : location.relation.kind.valuesHold context world location.range
      originalValue candidateValue = true)
    (related : RelationalMemoryFamiliesHold context world original candidate) :
    RelationalMemoryFamiliesHold context world
      (original.write32 location.originalAddress originalValue)
      (candidate.write32 location.candidateAddress candidateValue) := by
  have dynamicRangesShape := dynamicRangesValid
  simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
    List.all_eq_true] at dynamicRangesShape
  have rangeValid : location.range.disjointFromImages context = true :=
    dynamicRangesShape.1.1.1.1.1.2 location.range location.rangeMember
  have relationsValid : location.range.wordRelationsValid = true :=
    dynamicRangesShape.1.1.1.1.2 location.range location.rangeMember
  simp only [DynamicAddressRangePair.wordRelationsValid, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at relationsValid
  have inside := (relationsValid location.relation location.relationMember).1
  have originalNoWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context false location.range rangeValid
  have candidateNoWrap := DynamicAddressRangePair.sideBase_noWrap_of_disjoint
    context true location.range rangeValid
  have rangeShape := rangeValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeShape
  have updated := RelationalMemoryFamiliesHold.afterPairedMemoryUpdate
    context world original candidate {
      originalWrites := [(location.originalAddress, originalValue)]
      candidateWrites := [(location.candidateAddress, candidateValue)]
      preservesStackRanges := by
        intro stackRanges
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StackRangesMemoryHold.afterPairedDynamicWordWrite context world
            original candidate stackRangesValid dynamicRangesValid location.range
            location.rangeMember location.relation location.relationMember
            originalValue candidateValue stackRanges
      preservesImportAddresses := by
        intro importAddresses
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          ImportAddressesMemoryHold.afterPairedDynamicWordWrite context world
            original candidate location.range location.rangeMember rangeValid
            location.relation.offset inside originalValue candidateValue importsStatic
            importAddresses
      preservesOriginalImmutable := by
        intro originalImmutable
        simpa [applyConcreteWrites, location.originalAddressExact] using
          ImmutableImageWordMemory.afterStackWordWrite context.originalPe original
            location.range.originalBase location.range.size location.relation.offset
            originalValue originalNoWrap rangeShape.1.2 inside originalImmutable
      preservesCandidateImmutable := by
        intro candidateImmutable
        simpa [applyConcreteWrites, location.candidateAddressExact] using
          ImmutableImageWordMemory.afterStackWordWrite context.candidatePe candidate
            location.range.candidateBase location.range.size location.relation.offset
            candidateValue candidateNoWrap rangeShape.2 inside candidateImmutable
      preservesOrdinary := by
        intro ordinary
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          ordinaryMemoryRelated_after_paired_dynamic_word_write context world
            context.codeMap.entries.toList (context.relationalValueTargets world)
            original candidate location.range location.rangeMember rangeValid
            location.relation.offset inside originalValue candidateValue ordinary
      preservesStaticPointerSlots := by
        intro staticPointerSlots
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StaticDynamicPointerSlotsMemoryHold.afterPairedStackWordWrite
            context world original candidate staticPointerSlotsValid location.range
            rangeValid location.relation.offset inside originalValue candidateValue
            staticPointerSlots
      preservesStaticWordSlots := by
        intro staticWordSlots
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StaticWordRelationSlotsMemoryHold.afterPairedStackWordWrite context world
            original candidate staticWordSlotsValid location.range rangeValid
            location.relation.offset inside originalValue candidateValue
            staticWordSlots
    } related
  simpa [applyConcreteWrites] using updated

theorem RelationalMemoryFamiliesHold.afterPairedStaticWordWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (stackRangesValid : world.stackRangesValid context = true)
    (importsStatic : world.importAddressesStaticValid context = true)
    (dynamicRangesValid : world.dynamicRangesValid context = true)
    (staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (staticWordSlotsValid : staticWordRelationSlotsValid context = true)
    (location : PairedStaticWordLocation context)
    (originalValue candidateValue : Word)
    (valuesRelated : location.slot.relation.holds context world
      originalValue candidateValue = true)
    (related : RelationalMemoryFamiliesHold context world original candidate) :
    RelationalMemoryFamiliesHold context world
      (original.write32 location.originalAddress originalValue)
      (candidate.write32 location.candidateAddress candidateValue) := by
  have slotValid := location.slot.valid_of_member context staticWordSlotsValid
    location.slotMember
  have slotShape := slotValid
  simp only [StaticWordRelationSlotPair.valid, Bool.and_eq_true] at slotShape
  have originalNotImmutable := slotShape.1.1.2
  have candidateNotImmutable := slotShape.1.2
  rw [Bool.not_eq_true'] at originalNotImmutable candidateNotImmutable
  have updated := RelationalMemoryFamiliesHold.afterPairedMemoryUpdate
    context world original candidate {
      originalWrites := [(location.originalAddress, originalValue)]
      candidateWrites := [(location.candidateAddress, candidateValue)]
      preservesStackRanges := by
        intro stackRanges
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StackRangesMemoryHold.afterPairedStaticWordWrite context world
            original candidate stackRangesValid staticWordSlotsValid location.slot
            location.slotMember originalValue candidateValue stackRanges
      preservesImportAddresses := by
        intro importAddresses
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          ImportAddressesMemoryHold.afterPairedStaticWordWrite context world
            original candidate importsStatic staticWordSlotsValid location.slot
            location.slotMember originalValue candidateValue importAddresses
      preservesOriginalImmutable := by
        intro originalImmutable
        simpa [applyConcreteWrites, location.originalAddressExact] using
          ImmutableImageWordMemory.afterStaticWordWrite context.originalPe original
            location.slot.originalAddress originalValue
            (location.slot.originalBounds context slotValid).2.2
            originalNotImmutable originalImmutable
      preservesCandidateImmutable := by
        intro candidateImmutable
        simpa [applyConcreteWrites, location.candidateAddressExact] using
          ImmutableImageWordMemory.afterStaticWordWrite context.candidatePe candidate
            location.slot.candidateAddress candidateValue
            (location.slot.candidateBounds context slotValid).2.2
            candidateNotImmutable candidateImmutable
      preservesOrdinary := by
        intro ordinary
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          ordinaryMemoryRelated_after_paired_static_word_write context world
            context.codeMap.entries.toList (context.relationalValueTargets world)
            original candidate location.slot location.slotMember slotValid
            originalValue candidateValue ordinary
      preservesStaticPointerSlots := by
        intro staticPointerSlots
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StaticDynamicPointerSlotsMemoryHold.afterPairedStaticWordWrite
            context world original candidate staticPointerSlotsValid
            staticWordSlotsValid location.slot location.slotMember
            originalValue candidateValue staticPointerSlots
      preservesStaticWordSlots := by
        intro staticWordSlots
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StaticWordRelationSlotsMemoryHold.afterPairedStaticWordWrite
            context world original candidate staticWordSlotsValid location.slot
            location.slotMember originalValue candidateValue valuesRelated
            staticWordSlots
    } related
  simpa [applyConcreteWrites] using updated

theorem RelationalMemoryFamiliesHold.afterPairedStaticDynamicPointerWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (stackRangesValid : world.stackRangesValid context = true)
    (importsStatic : world.importAddressesStaticValid context = true)
    (dynamicRangesValid : world.dynamicRangesValid context = true)
    (staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (staticWordSlotsValid : staticWordRelationSlotsValid context = true)
    (location : PairedStaticDynamicPointerLocation context)
    (range : DynamicAddressRangePair) (rangeMember : range ∈ world.dynamicRanges)
    (requiredWords : location.slot.requiredWords.all
      range.wordRelations.contains = true)
    (related : RelationalMemoryFamiliesHold context world original candidate) :
    RelationalMemoryFamiliesHold context world
      (original.write32 location.originalAddress range.originalBase)
      (candidate.write32 location.candidateAddress range.candidateBase) := by
  have slotValid := location.slot.valid_of_member context staticPointerSlotsValid
    location.slotMember
  have slotShape := slotValid
  simp only [StaticDynamicPointerSlotPair.valid, Bool.and_eq_true] at slotShape
  have originalNotImmutable := slotShape.1.1.2
  have candidateNotImmutable := slotShape.1.2
  rw [Bool.not_eq_true'] at originalNotImmutable candidateNotImmutable
  have updated := RelationalMemoryFamiliesHold.afterPairedMemoryUpdate
    context world original candidate {
      originalWrites := [(location.originalAddress, range.originalBase)]
      candidateWrites := [(location.candidateAddress, range.candidateBase)]
      preservesStackRanges := by
        intro stackRanges
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StackRangesMemoryHold.afterPairedStaticDynamicPointerWrite
            context world original candidate stackRangesValid
            staticPointerSlotsValid location.slot location.slotMember
            range.originalBase range.candidateBase stackRanges
      preservesImportAddresses := by
        intro importAddresses
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          ImportAddressesMemoryHold.afterPairedStaticDynamicPointerWrite
            context world original candidate importsStatic staticPointerSlotsValid
            location.slot location.slotMember range.originalBase range.candidateBase
            importAddresses
      preservesOriginalImmutable := by
        intro originalImmutable
        simpa [applyConcreteWrites, location.originalAddressExact] using
          ImmutableImageWordMemory.afterStaticWordWrite context.originalPe original
            location.slot.originalAddress range.originalBase
            (location.slot.originalBounds context slotValid).2.2
            originalNotImmutable originalImmutable
      preservesCandidateImmutable := by
        intro candidateImmutable
        simpa [applyConcreteWrites, location.candidateAddressExact] using
          ImmutableImageWordMemory.afterStaticWordWrite context.candidatePe candidate
            location.slot.candidateAddress range.candidateBase
            (location.slot.candidateBounds context slotValid).2.2
            candidateNotImmutable candidateImmutable
      preservesOrdinary := by
        intro ordinary
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          ordinaryMemoryRelated_after_paired_static_dynamic_pointer_write
            context world context.codeMap.entries.toList
            (context.relationalValueTargets world) original candidate
            location.slot location.slotMember slotValid range.originalBase
            range.candidateBase ordinary
      preservesStaticPointerSlots := by
        intro staticPointerSlots
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StaticDynamicPointerSlotsMemoryHold.afterPairedStaticDynamicPointerWrite
            context world original candidate staticPointerSlotsValid
            dynamicRangesValid location.slot location.slotMember range rangeMember
            requiredWords staticPointerSlots
      preservesStaticWordSlots := by
        intro staticWordSlots
        simpa [applyConcreteWrites, location.originalAddressExact,
          location.candidateAddressExact] using
          StaticWordRelationSlotsMemoryHold.afterPairedStaticDynamicPointerWrite
            context world original candidate staticPointerSlotsValid
            staticWordSlotsValid location.slot location.slotMember
            range.originalBase range.candidateBase staticWordSlots
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

structure PairedStaticWordUpdate (context : StaticProofContext)
    (world : RelationalWorld) where
  location : PairedStaticWordLocation context
  originalValue : Word
  candidateValue : Word
  valuesRelated : location.slot.relation.holds context world
    originalValue candidateValue = true

def PairedStaticWordUpdate.originalWrite
    {context : StaticProofContext} {world : RelationalWorld}
    (update : PairedStaticWordUpdate context world) : Word × Word :=
  (update.location.originalAddress, update.originalValue)

def PairedStaticWordUpdate.candidateWrite
    {context : StaticProofContext} {world : RelationalWorld}
    (update : PairedStaticWordUpdate context world) : Word × Word :=
  (update.location.candidateAddress, update.candidateValue)

structure PairedDynamicWordUpdate (context : StaticProofContext)
    (world : RelationalWorld) where
  location : PairedDynamicWordLocation world
  originalValue : Word
  candidateValue : Word
  valuesRelated : location.relation.kind.valuesHold context world location.range
    originalValue candidateValue = true

def PairedDynamicWordUpdate.originalWrite
    {context : StaticProofContext} {world : RelationalWorld}
    (update : PairedDynamicWordUpdate context world) : Word × Word :=
  (update.location.originalAddress, update.originalValue)

def PairedDynamicWordUpdate.candidateWrite
    {context : StaticProofContext} {world : RelationalWorld}
    (update : PairedDynamicWordUpdate context world) : Word × Word :=
  (update.location.candidateAddress, update.candidateValue)

structure PairedStaticDynamicPointerUpdate (context : StaticProofContext)
    (world : RelationalWorld) where
  location : PairedStaticDynamicPointerLocation context
  range : DynamicAddressRangePair
  rangeMember : range ∈ world.dynamicRanges
  requiredWords : location.slot.requiredWords.all range.wordRelations.contains = true

def PairedStaticDynamicPointerUpdate.originalWrite
    {context : StaticProofContext} {world : RelationalWorld}
    (update : PairedStaticDynamicPointerUpdate context world) : Word × Word :=
  (update.location.originalAddress, update.range.originalBase)

def PairedStaticDynamicPointerUpdate.candidateWrite
    {context : StaticProofContext} {world : RelationalWorld}
    (update : PairedStaticDynamicPointerUpdate context world) : Word × Word :=
  (update.location.candidateAddress, update.range.candidateBase)

inductive PairedPreparedWordUpdate (context : StaticProofContext)
    (world : RelationalWorld) where
  | stack (update : PairedStackWordUpdate context world)
  | staticWord (update : PairedStaticWordUpdate context world)
  | dynamicWord (update : PairedDynamicWordUpdate context world)
  | staticDynamicPointer (update : PairedStaticDynamicPointerUpdate context world)

inductive PreparedWordWriteKind where
  | stack
  | staticWord
  | dynamicWord
  | staticDynamicPointer
deriving Repr, DecidableEq

def PairedPreparedWordUpdate.kind
    {context : StaticProofContext} {world : RelationalWorld} :
    PairedPreparedWordUpdate context world -> PreparedWordWriteKind
  | .stack _ => .stack
  | .staticWord _ => .staticWord
  | .dynamicWord _ => .dynamicWord
  | .staticDynamicPointer _ => .staticDynamicPointer

def PairedPreparedWordUpdate.originalWrite
    {context : StaticProofContext} {world : RelationalWorld} :
    PairedPreparedWordUpdate context world -> Word × Word
  | .stack update => update.originalWrite
  | .staticWord update => update.originalWrite
  | .dynamicWord update => update.originalWrite
  | .staticDynamicPointer update => update.originalWrite

def PairedPreparedWordUpdate.candidateWrite
    {context : StaticProofContext} {world : RelationalWorld} :
    PairedPreparedWordUpdate context world -> Word × Word
  | .stack update => update.candidateWrite
  | .staticWord update => update.candidateWrite
  | .dynamicWord update => update.candidateWrite
  | .staticDynamicPointer update => update.candidateWrite

theorem PairedPreparedWordUpdate.avoidsStackLocation_of_nonStack
    (context : StaticProofContext) (world : RelationalWorld)
    (worldValid : world.valid context = true)
    (stackRangesValid : world.stackRangesValid context = true)
    (staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (staticWordSlotsValid : staticWordRelationSlotsValid context = true)
    (stackLocation : PairedStackWordLocation world)
    (stackLocationValid : stackLocation.range.disjointFromImages context = true)
    (update : PairedPreparedWordUpdate context world)
    (nonStack : (update.kind != .stack) = true) :
    Write32AvoidsWord stackLocation.originalAddress update.originalWrite.1 ∧
      Write32AvoidsWord stackLocation.candidateAddress update.candidateWrite.1 := by
  cases update with
  | stack update => simp [PairedPreparedWordUpdate.kind] at nonStack
  | staticWord update =>
      have slotValid := update.location.slot.valid_of_member context
        staticWordSlotsValid update.location.slotMember
      have originalBounds := update.location.slot.originalBounds context slotValid
      have candidateBounds := update.location.slot.candidateBounds context slotValid
      have stackShape := stackLocationValid
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq] at stackShape
      rcases stackShape with
        ⟨⟨⟨⟨_nonempty, originalNoWrap⟩, candidateNoWrap⟩,
          originalDisjoint⟩, candidateDisjoint⟩
      have originalAvoids := (stackRangeWordWriteAvoidsImageWord
        stackLocation.range.originalBase stackLocation.range.size
        context.originalPe.imageBase context.originalPe.sizeOfImage
        stackLocation.offset stackLocation.inside originalNoWrap originalDisjoint
        update.location.slot.originalAddress originalBounds.1 originalBounds.2.1
        originalBounds.2.2).symm
      have candidateAvoids := (stackRangeWordWriteAvoidsImageWord
        stackLocation.range.candidateBase stackLocation.range.size
        context.candidatePe.imageBase context.candidatePe.sizeOfImage
        stackLocation.offset stackLocation.inside candidateNoWrap candidateDisjoint
        update.location.slot.candidateAddress candidateBounds.1 candidateBounds.2.1
        candidateBounds.2.2).symm
      constructor
      · simpa [PairedPreparedWordUpdate.originalWrite,
          PairedStaticWordUpdate.originalWrite,
          stackLocation.originalAddressExact,
          update.location.originalAddressExact] using originalAvoids
      · simpa [PairedPreparedWordUpdate.candidateWrite,
          PairedStaticWordUpdate.candidateWrite,
          stackLocation.candidateAddressExact,
          update.location.candidateAddressExact] using candidateAvoids
  | dynamicWord update =>
      simp only [RelationalWorld.valid, Bool.and_eq_true] at worldValid
      have dynamicValid : world.dynamicRangesValid context = true :=
        worldValid.1.1.1.1
      have dynamicValidForWords := dynamicValid
      simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
        List.all_eq_true] at dynamicValidForWords
      have wordRelationsValid := dynamicValidForWords.1.1.1.1.2
        update.location.range update.location.rangeMember
      simp only [DynamicAddressRangePair.wordRelationsValid, List.all_eq_true,
        Bool.and_eq_true, decide_eq_true_eq] at wordRelationsValid
      have dynamicInside :=
        (wordRelationsValid update.location.relation
          update.location.relationMember).1
      have originalAvoids :=
        (stackRangeWordWriteAvoidsDynamicRangeWord context false world dynamicValid
          stackLocation.range update.location.range stackLocation.rangeMember
          update.location.rangeMember stackLocationValid stackLocation.offset
          update.location.relation.offset stackLocation.inside
          dynamicInside).symm
      have candidateAvoids :=
        (stackRangeWordWriteAvoidsDynamicRangeWord context true world dynamicValid
          stackLocation.range update.location.range stackLocation.rangeMember
          update.location.rangeMember stackLocationValid stackLocation.offset
          update.location.relation.offset stackLocation.inside
          dynamicInside).symm
      constructor
      · simpa [PairedPreparedWordUpdate.originalWrite,
          PairedDynamicWordUpdate.originalWrite,
          stackLocation.originalAddressExact,
          update.location.originalAddressExact,
          DynamicAddressRangePair.sideBase] using originalAvoids
      · simpa [PairedPreparedWordUpdate.candidateWrite,
          PairedDynamicWordUpdate.candidateWrite,
          stackLocation.candidateAddressExact,
          update.location.candidateAddressExact,
          DynamicAddressRangePair.sideBase] using candidateAvoids
  | staticDynamicPointer update =>
      have slotValid := update.location.slot.valid_of_member context
        staticPointerSlotsValid update.location.slotMember
      have originalBounds := update.location.slot.originalBounds context slotValid
      have candidateBounds := update.location.slot.candidateBounds context slotValid
      have stackShape := stackLocationValid
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq] at stackShape
      rcases stackShape with
        ⟨⟨⟨⟨_nonempty, originalNoWrap⟩, candidateNoWrap⟩,
          originalDisjoint⟩, candidateDisjoint⟩
      have originalAvoids := (stackRangeWordWriteAvoidsImageWord
        stackLocation.range.originalBase stackLocation.range.size
        context.originalPe.imageBase context.originalPe.sizeOfImage
        stackLocation.offset stackLocation.inside originalNoWrap originalDisjoint
        update.location.slot.originalAddress originalBounds.1 originalBounds.2.1
        originalBounds.2.2).symm
      have candidateAvoids := (stackRangeWordWriteAvoidsImageWord
        stackLocation.range.candidateBase stackLocation.range.size
        context.candidatePe.imageBase context.candidatePe.sizeOfImage
        stackLocation.offset stackLocation.inside candidateNoWrap candidateDisjoint
        update.location.slot.candidateAddress candidateBounds.1 candidateBounds.2.1
        candidateBounds.2.2).symm
      constructor
      · simpa [PairedPreparedWordUpdate.originalWrite,
          PairedStaticDynamicPointerUpdate.originalWrite,
          stackLocation.originalAddressExact,
          update.location.originalAddressExact] using originalAvoids
      · simpa [PairedPreparedWordUpdate.candidateWrite,
          PairedStaticDynamicPointerUpdate.candidateWrite,
          stackLocation.candidateAddressExact,
          update.location.candidateAddressExact] using candidateAvoids

theorem pairedPreparedWordUpdatesAvoidStackLocation_of_all_nonStack
    (context : StaticProofContext) (world : RelationalWorld)
    (worldValid : world.valid context = true)
    (stackRangesValid : world.stackRangesValid context = true)
    (staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (staticWordSlotsValid : staticWordRelationSlotsValid context = true)
    (stackLocation : PairedStackWordLocation world)
    (stackLocationValid : stackLocation.range.disjointFromImages context = true)
    (updates : List (PairedPreparedWordUpdate context world))
    (allNonStack : updates.all (fun update => update.kind != .stack) = true) :
    WritesAvoidWord stackLocation.originalAddress
        (updates.map PairedPreparedWordUpdate.originalWrite) ∧
      WritesAvoidWord stackLocation.candidateAddress
        (updates.map PairedPreparedWordUpdate.candidateWrite) := by
  constructor
  · intro write writeMember
    rcases List.mem_map.mp writeMember with ⟨update, updateMember, rfl⟩
    have nonStack := List.all_eq_true.mp allNonStack update updateMember
    exact (update.avoidsStackLocation_of_nonStack context world worldValid
      stackRangesValid staticPointerSlotsValid staticWordSlotsValid stackLocation
      stackLocationValid
      nonStack).1
  · intro write writeMember
    rcases List.mem_map.mp writeMember with ⟨update, updateMember, rfl⟩
    have nonStack := List.all_eq_true.mp allNonStack update updateMember
    exact (update.avoidsStackLocation_of_nonStack context world worldValid
      stackRangesValid staticPointerSlotsValid staticWordSlotsValid stackLocation
      stackLocationValid
      nonStack).2

theorem RelationalMemoryFamiliesHold.afterPairedStackWordUpdates
    (context : StaticProofContext) (world : RelationalWorld)
    (stackRangesValid : world.stackRangesValid context = true)
    (importsStatic : world.importAddressesStaticValid context = true)
    (dynamicRangesValid : world.dynamicRangesValid context = true)
    (staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (staticWordSlotsValid : staticWordRelationSlotsValid context = true)
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
        dynamicRangesValid staticPointerSlotsValid staticWordSlotsValid update.location
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

theorem RelationalMemoryFamiliesHold.afterPairedPreparedWordUpdates
    (context : StaticProofContext) (world : RelationalWorld)
    (stackRangesValid : world.stackRangesValid context = true)
    (importsStatic : world.importAddressesStaticValid context = true)
    (dynamicRangesValid : world.dynamicRangesValid context = true)
    (staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (staticWordSlotsValid : staticWordRelationSlotsValid context = true)
    (updates : List (PairedPreparedWordUpdate context world))
    (original candidate : Memory)
    (related : RelationalMemoryFamiliesHold context world original candidate) :
    RelationalMemoryFamiliesHold context world
      (applyConcreteWrites original
        (updates.map PairedPreparedWordUpdate.originalWrite))
      (applyConcreteWrites candidate
        (updates.map PairedPreparedWordUpdate.candidateWrite)) := by
  induction updates generalizing original candidate with
  | nil => simpa [applyConcreteWrites] using related
  | cons update rest induction =>
      cases update with
      | stack update =>
          have afterHead := RelationalMemoryFamiliesHold.afterPairedStackWordWrite
            context world original candidate stackRangesValid importsStatic
            dynamicRangesValid staticPointerSlotsValid staticWordSlotsValid
            update.location update.locationValid update.originalValue
            update.candidateValue update.valuesRelated related
          simpa [applyConcreteWrites, PairedPreparedWordUpdate.originalWrite,
            PairedPreparedWordUpdate.candidateWrite,
            PairedStackWordUpdate.originalWrite,
            PairedStackWordUpdate.candidateWrite] using
            induction
              (original := original.write32 update.location.originalAddress
                update.originalValue)
              (candidate := candidate.write32 update.location.candidateAddress
                update.candidateValue)
              afterHead
      | staticWord update =>
          have afterHead := RelationalMemoryFamiliesHold.afterPairedStaticWordWrite
            context world original candidate stackRangesValid importsStatic
            dynamicRangesValid staticPointerSlotsValid staticWordSlotsValid
            update.location update.originalValue update.candidateValue
            update.valuesRelated related
          simpa [applyConcreteWrites, PairedPreparedWordUpdate.originalWrite,
            PairedPreparedWordUpdate.candidateWrite,
            PairedStaticWordUpdate.originalWrite,
            PairedStaticWordUpdate.candidateWrite] using
            induction
              (original := original.write32 update.location.originalAddress
                update.originalValue)
              (candidate := candidate.write32 update.location.candidateAddress
                update.candidateValue)
              afterHead
      | dynamicWord update =>
          have afterHead := RelationalMemoryFamiliesHold.afterPairedDynamicWordWrite
            context world original candidate stackRangesValid importsStatic
            dynamicRangesValid staticPointerSlotsValid staticWordSlotsValid
            update.location update.originalValue update.candidateValue
            update.valuesRelated related
          simpa [applyConcreteWrites, PairedPreparedWordUpdate.originalWrite,
            PairedPreparedWordUpdate.candidateWrite,
            PairedDynamicWordUpdate.originalWrite,
            PairedDynamicWordUpdate.candidateWrite] using
            induction
              (original := original.write32 update.location.originalAddress
                update.originalValue)
              (candidate := candidate.write32 update.location.candidateAddress
                update.candidateValue)
              afterHead
      | staticDynamicPointer update =>
          have afterHead :=
            RelationalMemoryFamiliesHold.afterPairedStaticDynamicPointerWrite
              context world original candidate stackRangesValid importsStatic
              dynamicRangesValid staticPointerSlotsValid staticWordSlotsValid
              update.location update.range update.rangeMember update.requiredWords related
          simpa [applyConcreteWrites, PairedPreparedWordUpdate.originalWrite,
            PairedPreparedWordUpdate.candidateWrite,
            PairedStaticDynamicPointerUpdate.originalWrite,
            PairedStaticDynamicPointerUpdate.candidateWrite] using
            induction
              (original := original.write32 update.location.originalAddress
                update.range.originalBase)
              (candidate := candidate.write32 update.location.candidateAddress
                update.range.candidateBase)
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

def mappedValueTargetsIdentity (values : List ValueTargetPair) : Bool :=
  values.all fun target =>
    target.mappedSize == 0 || target.originalValue == target.candidateValue

theorem normalizeDataAddress_eq_self_of_mapped_identity
    (values : List ValueTargetPair) (address : Word)
    (identity : mappedValueTargetsIdentity values = true) :
    normalizeDataAddress values address = address := by
  unfold normalizeDataAddress
  cases found : values.find? (valueTargetContainsCandidate · address) with
  | none => rfl
  | some target =>
      have member : target ∈ values := List.mem_of_find?_eq_some found
      have contains : valueTargetContainsCandidate target address = true := by
        exact List.find?_some
          (p := fun target => valueTargetContainsCandidate target address) found
      have nonzero : target.mappedSize ≠ 0 := by
        simp only [valueTargetContainsCandidate, Bool.and_eq_true,
          decide_eq_true_eq] at contains
        omega
      simp only [mappedValueTargetsIdentity, List.all_eq_true] at identity
      have row := identity target member
      simp only [Bool.or_eq_true, beq_iff_eq] at row
      have valuesEqual : target.originalValue = target.candidateValue :=
        row.resolve_left nonzero
      change BitVec.ofNat 32 target.originalValue +
        (address - BitVec.ofNat 32 target.candidateValue) = address
      rw [valuesEqual, BitVec.add_comm, BitVec.sub_add_cancel]

theorem ordinaryMemoryRelated_projection_of_mapped_identity
    (context : StaticProofContext) (world : RelationalWorld)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original excludedValues : Memory)
    (identity : mappedValueTargetsIdentity values = true) :
    ordinaryMemoryRelated context world targets values original
      (ordinaryMemoryCandidateProjection context world values original excludedValues) := by
  unfold ordinaryMemoryRelated
  split
  · constructor
    · intro address _relocationByte notExcluded
      simp [ordinaryMemoryCandidateProjection, notExcluded,
        normalizeDataAddress_eq_self_of_mapped_identity values address identity]
    · intro address _relocationWord wordNotExcluded
      have byteIncluded (offset : Nat) (before : offset < 4) :
          ordinaryMemoryAddressExcluded context world values
            (address + BitVec.ofNat 32 offset) = false := by
        simp only [ordinaryMemoryWordExcluded, Bool.or_eq_false_iff]
          at wordNotExcluded
        exact Bool.eq_false_iff.mpr
          (List.any_eq_false.mp wordNotExcluded.1 offset
            (List.mem_range.mpr before))
      have projectedByte (offset : Nat) (before : offset < 4) :
          ordinaryMemoryCandidateProjection context world values original excludedValues
              (address + BitVec.ofNat 32 offset) =
            original (address + BitVec.ofNat 32 offset) := by
        simp [ordinaryMemoryCandidateProjection, byteIncluded offset before,
          normalizeDataAddress_eq_self_of_mapped_identity values
            (address + BitVec.ofNat 32 offset) identity]
      have projectedRead :
          Memory.read32
              (ordinaryMemoryCandidateProjection context world values original
                excludedValues) address =
            Memory.read32 original address := by
        unfold Memory.read32
        have h0 := projectedByte 0 (by omega)
        have h1 := projectedByte 1 (by omega)
        have h2 := projectedByte 2 (by omega)
        have h3 := projectedByte 3 (by omega)
        simp only [BitVec.add_zero] at h0
        rw [h0, h1, h2, h3]
      rw [normalizeDataAddress_eq_self_of_mapped_identity values address identity,
        projectedRead]
      exact wordRelated_self _ _ _ _ _
  · intro address notExcluded
    simp [ordinaryMemoryCandidateProjection, notExcluded,
      normalizeDataAddress_eq_self_of_mapped_identity values address identity]

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
      (if originalCondition then originalTaken else originalFallthrough) ==
        (if candidateCondition then candidateTaken else candidateFallthrough)
  | .call originalTarget originalContinuation, .call candidateTarget candidateContinuation =>
      originalTarget == candidateTarget && originalContinuation == candidateContinuation
  | .callUnmappedReturn originalTarget, .callUnmappedReturn candidateTarget =>
      originalTarget == candidateTarget
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

theorem outcomesRelated_normalized_indirectCall_of_agreement
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (allowedFlags : List Nat) (target : Expr) (continuation : Nat)
    (original candidate : MachineState)
    (within : target.flagsWithin allowedFlags = true)
    (agreement : MachineStateAgreement allowedFlags original candidate) :
    outcomesRelated originalImageBase candidateImageBase targets values
      ((NormalizedOutcomeExpr.indirectCall target continuation).eval original)
      ((NormalizedOutcomeExpr.indirectCall target continuation).eval candidate) = true := by
  have targetEqual := Expr.eval_eq_of_flagsWithin allowedFlags original candidate
    target within agreement
  simp [NormalizedOutcomeExpr.eval, outcomesRelated, targetEqual, wordRelated]

theorem normalizedBehaviorOutcomeRelated_indirectCall_of_agreement
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (allowedFlags : List Nat) (behavior : NormalizedSymbolicBehavior)
    (target : Expr) (continuation : Nat)
    (original candidate : MachineState)
    (outcome : behavior.outcome = .indirectCall target continuation)
    (within : target.flagsWithin allowedFlags = true)
    (agreement : MachineStateAgreement allowedFlags original candidate) :
    outcomesRelated originalImageBase candidateImageBase targets values
      (behavior.eval original).outcome (behavior.eval candidate).outcome = true := by
  rw [NormalizedSymbolicBehavior.eval_outcome,
    NormalizedSymbolicBehavior.eval_outcome, outcome]
  exact outcomesRelated_normalized_indirectCall_of_agreement
    originalImageBase candidateImageBase targets values allowedFlags target continuation
    original candidate within agreement

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

/-- Replay a previously checked normalization result without asking a
downstream proof to execute the symbolic normalizer again. -/
theorem evalBehavior_of_normalized (candidate : Bool)
    (targets : List CodeTargetPair) (state : MachineState)
    (behavior : SymbolicBehavior) (normalized : NormalizedSymbolicBehavior)
    (checked : normalizeSymbolicBehavior candidate targets behavior =
      some normalized) :
    evalBehavior candidate targets state behavior = some (normalized.eval state) := by
  unfold evalBehavior
  rw [checked]
  rfl

theorem evalBehavior_x87Effect_none (candidate : Bool)
    (targets : List CodeTargetPair) (state : MachineState)
    (behavior : SymbolicBehavior) (result : RelationalBehavior)
    (evaluated : evalBehavior candidate targets state behavior = some result) :
    result.x87Effect = none := by
  unfold evalBehavior at evaluated
  cases normalized : normalizeSymbolicBehavior candidate targets behavior with
  | none => simp [normalized] at evaluated
  | some value =>
      simp [normalized] at evaluated
      subst result
      rfl

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
  | fixedWord (value : Nat)
  | codePointer
  | fixedCodePointer (targetId : Nat)
  | dataPointer
  | relatedWord
deriving Repr, DecidableEq

structure RegisterRelationPair where
  original : Reg
  candidate : Reg
  relation : RegisterValueRelation
deriving Repr, DecidableEq

/-- A world-dependent register relation over the canonical value-origin
language.  Ordinary register relations remain world independent; this
inventory is for values such as resolver-issued callables, dynamic addresses,
and callbacks whose concrete words may differ between executions. -/
structure RegisterValueOriginRelation where
  original : Reg
  candidate : Reg
  finiteAlternativeBudget : Nat
  origins : List ValueOriginAtom
deriving Repr, DecidableEq

def RegisterValueOriginRelation.shapeChecked
    (relation : RegisterValueOriginRelation) : Bool :=
  relation.finiteAlternativeBudget > 0 &&
    !relation.origins.isEmpty &&
    relation.origins.length <= relation.finiteAlternativeBudget &&
    relation.origins.length == relation.origins.eraseDups.length

def RegisterValueOriginRelation.holds
    (context : StaticProofContext) (world : RelationalWorld)
    (relation : RegisterValueOriginRelation)
    (original candidate : PureState) : Bool :=
  relation.origins.any fun origin =>
    origin.matches context world (original.get relation.original)
      (candidate.get relation.candidate)

def registerValueOriginRelationsHold
    (context : StaticProofContext) (world : RelationalWorld)
    (relations : List RegisterValueOriginRelation)
    (original candidate : PureState) : Bool :=
  relations.all fun relation => relation.holds context world original candidate

theorem registerValueOriginRelationsHold_member
    (context : StaticProofContext) (world : RelationalWorld)
    (relations : List RegisterValueOriginRelation)
    (original candidate : PureState)
    (relation : RegisterValueOriginRelation)
    (holds : registerValueOriginRelationsHold context world relations
      original candidate = true)
    (member : relation ∈ relations) :
    relation.holds context world original candidate = true := by
  exact List.all_eq_true.mp holds relation member

/-- A value-origin relation attached to a concrete paired memory word.
Unlike storage-specific pointer mechanisms, this uses the same origin atoms as
registers and indirect exits.  Address expressions permit stack, static, and
dynamic locations without treating those storage classes as semantic types. -/
structure MemoryValueOriginRelation where
  originalAddress : Expr
  candidateAddress : Expr
  finiteAlternativeBudget : Nat
  origins : List ValueOriginAtom
deriving Repr, DecidableEq

def MemoryValueOriginRelation.shapeChecked
    (relation : MemoryValueOriginRelation) : Bool :=
  relation.finiteAlternativeBudget > 0 &&
    !relation.origins.isEmpty &&
    relation.origins.length <= relation.finiteAlternativeBudget &&
    relation.origins.length == relation.origins.eraseDups.length

def MemoryValueOriginRelation.holds
    (context : StaticProofContext) (world : RelationalWorld)
    (relation : MemoryValueOriginRelation)
    (original candidate : MachineState) : Bool :=
  relation.origins.any fun origin =>
    origin.matches context world
      (Memory.read32 original.memory
        (relation.originalAddress.eval original))
      (Memory.read32 candidate.memory
        (relation.candidateAddress.eval candidate))

def memoryValueOriginRelationsHold
    (context : StaticProofContext) (world : RelationalWorld)
    (relations : List MemoryValueOriginRelation)
    (original candidate : MachineState) : Bool :=
  relations.all fun relation => relation.holds context world original candidate

theorem memoryValueOriginRelationsHold_member
    (context : StaticProofContext) (world : RelationalWorld)
    (relations : List MemoryValueOriginRelation)
    (original candidate : MachineState)
    (relation : MemoryValueOriginRelation)
    (holds : memoryValueOriginRelationsHold context world relations
      original candidate = true)
    (member : relation ∈ relations) :
    relation.holds context world original candidate = true := by
  exact List.all_eq_true.mp holds relation member

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
  activeWords : List DynamicWordRelation := []
deriving Repr, DecidableEq

def DynamicRegisterRangeRelation.holds (world : RelationalWorld)
    (relation : DynamicRegisterRangeRelation)
    (original candidate : PureState) : Bool :=
  world.dynamicRanges.any fun range =>
    original.get relation.original ==
        range.originalBase + BitVec.ofNat 32 relation.originalOffset &&
      candidate.get relation.candidate ==
        range.candidateBase + BitVec.ofNat 32 relation.candidateOffset &&
      relation.requiredWords.all range.wordRelations.contains &&
      relation.activeWords.all relation.requiredWords.contains

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
  | .fixedWord value =>
      original == BitVec.ofNat 32 value && candidate == BitVec.ofNat 32 value
  | .codePointer =>
      (original == BitVec.ofNat 32 0 && candidate == BitVec.ofNat 32 0) ||
        codePointerRelated originalImageBase candidateImageBase targets original candidate
  | .fixedCodePointer targetId =>
      fixedCodePointerRelated originalImageBase candidateImageBase targets targetId
        original candidate
  | .dataPointer =>
      (original == BitVec.ofNat 32 0 && candidate == BitVec.ofNat 32 0) ||
        mappedValueRelated values original candidate
  | .relatedWord =>
      wordRelated originalImageBase candidateImageBase targets values original candidate

theorem RegisterValueRelation.fixedCodePointer_holds_codePointer
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (targetId : Nat) (original candidate : Word)
    (fixed : RegisterValueRelation.holds originalImageBase candidateImageBase targets values
      (.fixedCodePointer targetId) original candidate = true) :
    RegisterValueRelation.holds originalImageBase candidateImageBase targets values
      .codePointer original candidate = true := by
  simp only [RegisterValueRelation.holds, Bool.or_eq_true] at fixed ⊢
  exact Or.inr (fixedCodePointerRelated_codePointerRelated originalImageBase
    candidateImageBase targets targetId original candidate fixed)

theorem RegisterValueRelation.fixedWord_holds_exact
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (value : Nat) (original candidate : Word)
    (fixed : RegisterValueRelation.holds originalImageBase candidateImageBase targets values
      (.fixedWord value) original candidate = true) :
    RegisterValueRelation.holds originalImageBase candidateImageBase targets values
      .exact original candidate = true := by
  simp only [RegisterValueRelation.holds, Bool.and_eq_true, beq_iff_eq] at fixed ⊢
  exact fixed.1.trans fixed.2.symm

theorem DynamicRegisterRangeRelation.relatedWord_of_zero_offsets
    (context : StaticProofContext) (world : RelationalWorld)
    (relation : DynamicRegisterRangeRelation) (original candidate : PureState)
    (worldValid : world.valid context = true)
    (originalOffset : relation.originalOffset = 0)
    (candidateOffset : relation.candidateOffset = 0)
    (holds : relation.holds world original candidate = true) :
    RegisterValueRelation.holds context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) .relatedWord
      (original.get relation.original) (candidate.get relation.candidate) = true := by
  simp only [DynamicRegisterRangeRelation.holds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at holds
  rcases holds with
    ⟨range, rangeMember, ⟨⟨⟨originalRegister, candidateRegister⟩,
      _requiredWords⟩, _activeWords⟩⟩
  rw [originalOffset] at originalRegister
  rw [candidateOffset] at candidateRegister
  simp [BitVec.add_zero] at originalRegister candidateRegister
  simp only [RelationalWorld.valid, Bool.and_eq_true] at worldValid
  have dynamicValid : world.dynamicRangesValid context = true := worldValid.1.1.1.1
  simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
    List.all_eq_true] at dynamicValid
  have rangeValid := dynamicValid.1.1.1.1.1.2 range rangeMember
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true]
      at rangeValid
  have originalNonzero : range.originalBase ≠ BitVec.ofNat 32 0 := by
    simpa using rangeValid.1.1.1.1.1.2
  have candidateNonzero : range.candidateBase ≠ BitVec.ofNat 32 0 := by
    simpa using rangeValid.1.1.1.1.2
  have mapped : mappedValueRelated (context.relationalValueTargets world)
      range.originalBase range.candidateBase = true := by
    simp only [mappedValueRelated, List.any_eq_true]
    refine ⟨range.valueTarget, ?_, ?_⟩
    · simp only [StaticProofContext.relationalValueTargets,
        RelationalWorld.runtimeValueTargets,
        RelationalWorld.dynamicValueTargets, List.mem_append, List.mem_map]
      exact Or.inr (Or.inl (Or.inl ⟨range, rangeMember, rfl⟩))
    by_cases zero : range.size = 0
    · simp [DynamicAddressRangePair.valueTarget, zero]
    · simp [DynamicAddressRangePair.valueTarget, zero]
  rw [originalRegister, candidateRegister]
  have originalZeroFalse :
      (range.originalBase == BitVec.ofNat 32 0) = false :=
    beq_eq_false_iff_ne.mpr originalNonzero
  have candidateZeroFalse :
      (range.candidateBase == BitVec.ofNat 32 0) = false :=
    beq_eq_false_iff_ne.mpr candidateNonzero
  simp [RegisterValueRelation.holds, wordRelated, originalZeroFalse,
    candidateZeroFalse, mapped]

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
  | fixedWord value => simpa [RegisterValueRelation.holds] using related
  | codePointer => simpa [RegisterValueRelation.holds] using related
  | fixedCodePointer targetId => simpa [RegisterValueRelation.holds] using related
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

def RegisterValueRelation.impliesExact : RegisterValueRelation → Bool
  | .exact | .fixedWord _ => true
  | .codePointer | .fixedCodePointer _ | .dataPointer | .relatedWord => false

theorem RegisterValueRelation.holds_eq_of_impliesExact
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (relation : RegisterValueRelation) (original candidate : Word)
    (exactLike : relation.impliesExact = true)
    (related : relation.holds originalImageBase candidateImageBase targets values
      original candidate = true) :
    original = candidate := by
  cases relation <;>
    simp_all [RegisterValueRelation.impliesExact, RegisterValueRelation.holds]

def exactIdentityRegister (relations : List RegisterRelationPair) (register : Reg) : Bool :=
  relations.any fun relation =>
    relation.original == register && relation.candidate == register &&
      relation.relation.impliesExact

def exactRegisterPair (relations : List RegisterRelationPair)
    (originalRegister candidateRegister : Reg) : Bool :=
  relations.any fun relation =>
    relation.original == originalRegister && relation.candidate == candidateRegister &&
      relation.relation.impliesExact

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
  rw [originalEqual, candidateEqual] at holds
  cases relationKind <;>
    simp_all [RegisterValueRelation.impliesExact, RegisterValueRelation.holds]

theorem registerRelationsHold_exact_pair
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (relations : List RegisterRelationPair) (original candidate : PureState)
    (originalRegister candidateRegister : Reg)
    (related : registerRelationsHold originalImageBase candidateImageBase targets values
      relations original candidate = true)
    (exact : exactRegisterPair relations originalRegister candidateRegister = true) :
    original.get originalRegister = candidate.get candidateRegister := by
  simp only [registerRelationsHold, List.all_eq_true] at related
  simp only [exactRegisterPair, List.any_eq_true] at exact
  rcases exact with ⟨relation, member, checks⟩
  have holds := related relation member
  rcases relation with ⟨relationOriginal, relationCandidate, relationKind⟩
  simp only [Bool.and_eq_true, beq_iff_eq] at checks
  rcases checks with ⟨⟨originalEqual, candidateEqual⟩, relationExact⟩
  rw [originalEqual, candidateEqual] at holds
  cases relationKind <;>
    simp_all [RegisterValueRelation.impliesExact, RegisterValueRelation.holds]

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
  subtract : Bool := false
deriving Repr, DecidableEq

structure StackWindowPair where
  rangeId : Nat
  originalRegister : Reg
  candidateRegister : Reg
  bytesBelow : Nat
  bytesAbove : Nat
deriving Repr, DecidableEq

structure PairedExactMemoryRead where
  originalAddress : Expr
  candidateAddress : Expr
  bytes : Nat
deriving Repr, DecidableEq

def PairedExactMemoryRead.holds (read : PairedExactMemoryRead)
    (original candidate : MachineState) : Bool :=
  0 < read.bytes && read.bytes <= 10 &&
    original.readX87Word (read.originalAddress.eval original) read.bytes ==
      candidate.readX87Word (read.candidateAddress.eval candidate) read.bytes

structure PairedStatePredicate where
  original : BoolExpr
  candidate : BoolExpr
  exactMemoryReads : List PairedExactMemoryRead := []
deriving Repr, DecidableEq

def PairedStatePredicate.holds (predicate : PairedStatePredicate)
    (original candidate : MachineState) : Bool :=
  predicate.original.eval original && predicate.candidate.eval candidate &&
    predicate.exactMemoryReads.all fun read => read.holds original candidate

def pairedStatePredicatesHold (predicates : List PairedStatePredicate)
    (original candidate : MachineState) : Bool :=
  predicates.all fun predicate => predicate.holds original candidate

@[simp] theorem pairedStatePredicatesHold_nil (original candidate : MachineState) :
    pairedStatePredicatesHold [] original candidate = true := rfl

theorem pairedStatePredicatesHold_member
    (predicates : List PairedStatePredicate) (predicate : PairedStatePredicate)
    (original candidate : MachineState) (member : predicate ∈ predicates)
    (holds : pairedStatePredicatesHold predicates original candidate = true) :
    predicate.holds original candidate = true := by
  simp only [pairedStatePredicatesHold, List.all_eq_true] at holds
  exact holds predicate member

theorem PairedStatePredicate.exactMemoryReadHolds
    (predicate : PairedStatePredicate) (read : PairedExactMemoryRead)
    (original candidate : MachineState)
    (member : read ∈ predicate.exactMemoryReads)
    (holds : predicate.holds original candidate = true) :
    read.holds original candidate = true := by
  simp only [PairedStatePredicate.holds, Bool.and_eq_true,
    List.all_eq_true] at holds
  exact holds.2 read member

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

theorem StackWindowPair.relatedWord_of_holds
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (rangesValid : world.stackRangesValid context = true)
    (bytesAbovePositive : 0 < window.bytesAbove)
    (holds : window.holds world original candidate = true) :
    RegisterValueRelation.holds context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) .relatedWord
      (original.get window.originalRegister)
      (candidate.get window.candidateRegister) = true := by
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at holds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at holds
      rcases holds with
        ⟨⟨⟨⟨⟨originalLower, originalUpper⟩, candidateLower⟩,
          candidateUpper⟩, pairedOffset⟩, _alignment⟩
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at rangesValid
      have rangeValid := rangesValid.1.1.2 range rangeMember
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq] at rangeValid
      rcases rangeValid with
        ⟨⟨⟨disjoint, _originalBaseAligned⟩, _candidateBaseAligned⟩,
          _sizeAligned⟩
      rcases disjoint with
        ⟨⟨⟨⟨rangeStart, originalNoWrap⟩, candidateNoWrap⟩,
          _originalDisjoint⟩, _candidateDisjoint⟩
      have rangeNonempty : 0 < range.size := rangeStart.1.1
      have originalBaseNonzero :
          (range.originalBase == BitVec.ofNat 32 0) = false := by
        simpa using rangeStart.1.2
      have candidateBaseNonzero :
          (range.candidateBase == BitVec.ofNat 32 0) = false := by
        simpa using rangeStart.2
      let rangeOffset :=
        (original.get window.originalRegister).toNat - range.originalBase.toNat
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
      have originalBelowEnd :
          (original.get window.originalRegister).toNat <
            range.originalBase.toNat + range.size := by
        omega
      have candidateBelowEnd :
          (candidate.get window.candidateRegister).toNat <
            range.candidateBase.toNat + range.size := by
        omega
      have rangeOffsetInside : rangeOffset < range.size := by
        omega
      have originalAddressExact :
          original.get window.originalRegister =
            range.originalBase + BitVec.ofNat 32 rangeOffset := by
        apply BitVec.eq_of_toNat_eq
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt (by omega : rangeOffset < 2 ^ 32),
          Nat.mod_eq_of_lt (by omega :
            range.originalBase.toNat + rangeOffset < 2 ^ 32)]
        exact originalAtOffset
      have candidateAddressExact :
          candidate.get window.candidateRegister =
            range.candidateBase + BitVec.ofNat 32 rangeOffset := by
        apply BitVec.eq_of_toNat_eq
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt (by omega : rangeOffset < 2 ^ 32),
          Nat.mod_eq_of_lt (by omega :
            range.candidateBase.toNat + rangeOffset < 2 ^ 32)]
        exact candidateAtOffset
      have originalBaseRoundtrip :
          BitVec.ofNat 32 range.originalBase.toNat = range.originalBase := by
        apply BitVec.eq_of_toNat_eq
        simp [BitVec.toNat_ofNat]
      have candidateBaseRoundtrip :
          BitVec.ofNat 32 range.candidateBase.toNat = range.candidateBase := by
        apply BitVec.eq_of_toNat_eq
        simp [BitVec.toNat_ofNat]
      have candidateContained : valueTargetContainsCandidate range.valueTarget
          (candidate.get window.candidateRegister) = true := by
        simp only [valueTargetContainsCandidate, DynamicAddressRangePair.valueTarget]
        simp only [Bool.and_eq_true, decide_eq_true_eq]
        refine ⟨⟨rangeNonempty, ?_⟩, ?_⟩
        · rw [candidateBaseRoundtrip, candidateAddressExact]
          simp only [BitVec.le_def, BitVec.toNat_add, BitVec.toNat_ofNat]
          rw [Nat.mod_eq_of_lt (by omega : rangeOffset < 2 ^ 32)]
          rw [Nat.mod_eq_of_lt (by omega :
            range.candidateBase.toNat + rangeOffset < 2 ^ 32)]
          omega
        · rw [candidateBaseRoundtrip]
          simp only [BitVec.lt_def, BitVec.toNat_add, BitVec.toNat_ofNat]
          rw [Nat.mod_eq_of_lt (by omega : range.size < 2 ^ 32)]
          rw [Nat.mod_eq_of_lt candidateNoWrap]
          exact candidateBelowEnd
      have mapped : mappedValueRelated (context.relationalValueTargets world)
          (original.get window.originalRegister)
          (candidate.get window.candidateRegister) = true := by
        simp only [mappedValueRelated, List.any_eq_true]
        refine ⟨range.valueTarget, ?_, ?_⟩
        · simp only [StaticProofContext.relationalValueTargets,
            RelationalWorld.runtimeValueTargets,
            RelationalWorld.stackValueTargets, List.mem_append, List.mem_map]
          exact Or.inr (Or.inl (Or.inr ⟨range, rangeMember, rfl⟩))
        · simp only [DynamicAddressRangePair.valueTarget,
            if_neg (Nat.ne_of_gt rangeNonempty), Bool.or_eq_true,
            Bool.and_eq_true, beq_iff_eq]
          apply Or.inr
          refine ⟨candidateContained, ?_⟩
          rw [originalBaseRoundtrip, candidateBaseRoundtrip,
            originalAddressExact, candidateAddressExact,
            BitVec.add_comm range.candidateBase, BitVec.add_sub_cancel]
      have originalZeroFalse :
          (original.get window.originalRegister == BitVec.ofNat 32 0) = false := by
        apply beq_eq_false_iff_ne.mpr
        intro zero
        have zeroNat := congrArg BitVec.toNat zero
        simp only [BitVec.toNat_ofNat] at zeroNat
        have baseNonzero := beq_eq_false_iff_ne.mp originalBaseNonzero
        have basePositive : 0 < range.originalBase.toNat := by
          apply Nat.pos_of_ne_zero
          intro baseZero
          apply baseNonzero
          apply BitVec.eq_of_toNat_eq
          simpa [baseZero]
        omega
      have candidateZeroFalse :
          (candidate.get window.candidateRegister == BitVec.ofNat 32 0) = false := by
        apply beq_eq_false_iff_ne.mpr
        intro zero
        have zeroNat := congrArg BitVec.toNat zero
        simp only [BitVec.toNat_ofNat] at zeroNat
        have baseNonzero := beq_eq_false_iff_ne.mp candidateBaseNonzero
        have basePositive : 0 < range.candidateBase.toNat := by
          apply Nat.pos_of_ne_zero
          intro baseZero
          apply baseNonzero
          apply BitVec.eq_of_toNat_eq
          simpa [baseZero]
        omega
      simp [RegisterValueRelation.holds, wordRelated, originalZeroFalse,
        candidateZeroFalse, mapped]

def stackWindowsRelated (world : RelationalWorld) (windows : List StackWindowPair)
    (original candidate : PureState) : Bool :=
  windows.all fun window => window.holds world original candidate

def StackWindowPair.covers (source target : StackWindowPair) : Bool :=
  source.rangeId == target.rangeId &&
    source.originalRegister == target.originalRegister &&
    source.candidateRegister == target.candidateRegister &&
    target.bytesBelow <= source.bytesBelow &&
    target.bytesAbove <= source.bytesAbove

theorem StackWindowPair.holds_of_covers
    (world : RelationalWorld) (source target : StackWindowPair)
    (original candidate : PureState)
    (covered : source.covers target = true)
    (holds : source.holds world original candidate = true) :
    target.holds world original candidate = true := by
  rcases source with
    ⟨sourceRange, sourceOriginal, sourceCandidate, sourceBelow, sourceAbove⟩
  rcases target with
    ⟨targetRange, targetOriginal, targetCandidate, targetBelow, targetAbove⟩
  simp only [StackWindowPair.covers, Bool.and_eq_true, beq_iff_eq,
    decide_eq_true_eq] at covered
  rcases covered with
    ⟨⟨⟨⟨rangeEqual, originalEqual⟩, candidateEqual⟩, belowCovered⟩,
      aboveCovered⟩
  subst targetRange
  subst targetOriginal
  subst targetCandidate
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == sourceRange) with
  | none => simp [StackWindowPair.holds, rangeResult] at holds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at holds ⊢
      rcases holds with
        ⟨⟨⟨⟨⟨originalLower, originalUpper⟩, candidateLower⟩,
          candidateUpper⟩, pairedOffset⟩, alignment⟩
      exact ⟨⟨⟨⟨⟨by omega, by omega⟩, by omega⟩, by omega⟩,
        pairedOffset⟩, alignment⟩

def stackWindowsWeakeningChecked (source target : List StackWindowPair) : Bool :=
  target.all fun targetWindow =>
    source.any fun sourceWindow => sourceWindow.covers targetWindow

theorem stackWindowsRelated_of_weakening
    (world : RelationalWorld) (source target : List StackWindowPair)
    (original candidate : PureState)
    (checked : stackWindowsWeakeningChecked source target = true)
    (related : stackWindowsRelated world source original candidate = true) :
    stackWindowsRelated world target original candidate = true := by
  simp only [stackWindowsWeakeningChecked, List.all_eq_true] at checked
  simp only [stackWindowsRelated, List.all_eq_true] at related ⊢
  intro targetWindow targetMember
  have covered := checked targetWindow targetMember
  simp only [List.any_eq_true] at covered
  rcases covered with ⟨sourceWindow, sourceMember, windowCovered⟩
  exact sourceWindow.holds_of_covers world targetWindow original candidate
    windowCovered (related sourceWindow sourceMember)

structure DynamicStackRangeRelation where
  window : StackWindowPair
  stackOffset : Nat
  originalOffset : Nat := 0
  candidateOffset : Nat := 0
  requiredWords : List DynamicWordRelation := []
  activeWords : List DynamicWordRelation := []
deriving Repr, DecidableEq

def DynamicStackRangeRelation.holds (world : RelationalWorld)
    (relation : DynamicStackRangeRelation)
    (original candidate : MachineState) : Bool :=
  relation.window.holds world original.registers candidate.registers &&
    world.dynamicRanges.any fun range =>
      Memory.read32 original.memory
          (original.registers.get relation.window.originalRegister +
            BitVec.ofNat 32 relation.stackOffset) ==
          range.originalBase + BitVec.ofNat 32 relation.originalOffset &&
        Memory.read32 candidate.memory
          (candidate.registers.get relation.window.candidateRegister +
            BitVec.ofNat 32 relation.stackOffset) ==
          range.candidateBase + BitVec.ofNat 32 relation.candidateOffset &&
        relation.requiredWords.all range.wordRelations.contains &&
        relation.activeWords.all relation.requiredWords.contains

def dynamicStackRangeRelationsHold (world : RelationalWorld)
    (relations : List DynamicStackRangeRelation)
    (original candidate : MachineState) : Bool :=
  relations.all fun relation => relation.holds world original candidate

theorem pairedStackWordLocation_below_window_amount
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world original candidate = true)
    (amount : Nat) (amountAtLeastWord : 4 <= amount)
    (amountAligned : amount % 4 = 0)
    (enoughBelow : amount <= window.bytesBelow) :
    ∃ location : PairedStackWordLocation world,
      location.originalAddress =
          original.get window.originalRegister - BitVec.ofNat 32 amount ∧
        location.candidateAddress =
          candidate.get window.candidateRegister - BitVec.ofNat 32 amount := by
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
      let wordOffset := rangeOffset - amount
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
      have rangeOffsetEnough : amount <= rangeOffset := by
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
      have originalEnough : amount <=
          (original.get window.originalRegister).toNat := by
        omega
      have candidateEnough : amount <=
          (candidate.get window.candidateRegister).toNat := by
        omega
      have originalAddressExact :
          original.get window.originalRegister - BitVec.ofNat 32 amount =
            range.originalBase + BitVec.ofNat 32 wordOffset := by
        apply BitVec.eq_of_toNat_eq
        simp [BitVec.toNat_sub, BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt (by omega : wordOffset < 2 ^ 32),
          Nat.mod_eq_of_lt (by omega :
            range.originalBase.toNat + wordOffset < 2 ^ 32)]
        rw [originalAtOffset]
        omega
      have candidateAddressExact :
          candidate.get window.candidateRegister - BitVec.ofNat 32 amount =
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
        originalAddress := original.get window.originalRegister - BitVec.ofNat 32 amount
        candidateAddress := candidate.get window.candidateRegister - BitVec.ofNat 32 amount
        originalAddressExact
        candidateAddressExact
      }, rfl, rfl⟩

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
  exact pairedStackWordLocation_below_window_amount context world window original
    candidate rangesValid windowHolds 4 (by decide) (by decide) enoughBelow

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
  else if write.subtract then
    if write.offset < 2 ^ 32 then
      .sub (.inputReg write.register) (.constant (2 ^ 32 - write.offset))
    else .add (.inputReg write.register) (.constant write.offset)
  else .add (.inputReg write.register) (.constant write.offset)

def RegisterOffsetWrite.toWrite (write : RegisterOffsetWrite) : Expr × Expr :=
  (write.address, write.value)

@[simp] theorem RegisterOffsetWrite.address_eval (write : RegisterOffsetWrite)
    (state : MachineState) :
    write.address.eval state =
      state.registers.get write.register + BitVec.ofNat 32 write.offset := by
  by_cases zero : write.offset = 0
  · simp [RegisterOffsetWrite.address, zero, Expr.eval]
  · cases subtract : write.subtract
    · simp [RegisterOffsetWrite.address, zero, subtract, Expr.eval]
    · by_cases fits : write.offset < 2 ^ 32
      · simp only [RegisterOffsetWrite.address, zero, subtract, fits, if_false,
          if_true, Expr.eval]
        have complementFits : 2 ^ 32 - write.offset < 2 ^ 32 := by omega
        rw [← word_add_ia32_twos_complement
          (state.registers.get write.register) (2 ^ 32 - write.offset)
          complementFits]
        have complement : 2 ^ 32 - (2 ^ 32 - write.offset) = write.offset := by
          omega
        rw [complement]
      · simp [RegisterOffsetWrite.address, zero, subtract, fits, Expr.eval]

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
  registerValueOriginRelations : List RegisterValueOriginRelation := []
  memoryValueOriginRelations : List MemoryValueOriginRelation := []
  importRegisterRelations : List ImportRegisterRelation := []
  dynamicRegisterRangeRelations : List DynamicRegisterRangeRelation := []
  dynamicStackRangeRelations : List DynamicStackRangeRelation := []
  flagBits : List Nat := [0, 2, 4, 6, 7, 10, 11]
  bounds : List RegisterBoundPair := []
  addressSeparations : List AddressSeparationPair := []
  stackWindows : List StackWindowPair := []
  predicates : List PairedStatePredicate := []
deriving Repr, DecidableEq

structure StateInvariantWeakening
    (source target : StateInvariant) : Prop where
  registerRelations :
    target.registerRelations.all source.registerRelations.contains = true
  registerValueOriginRelations :
    target.registerValueOriginRelations.all
      source.registerValueOriginRelations.contains = true
  memoryValueOriginRelations :
    target.memoryValueOriginRelations.all
      source.memoryValueOriginRelations.contains = true
  importRegisterRelations :
    target.importRegisterRelations.all source.importRegisterRelations.contains = true
  dynamicRegisterRangeRelations :
    target.dynamicRegisterRangeRelations.all
      source.dynamicRegisterRangeRelations.contains = true
  dynamicStackRangeRelations :
    target.dynamicStackRangeRelations.all
      source.dynamicStackRangeRelations.contains = true
  flagBits : target.flagBits.all source.flagBits.contains = true
  bounds : target.bounds.all source.bounds.contains = true
  addressSeparations :
    target.addressSeparations.all source.addressSeparations.contains = true
  stackWindows :
    stackWindowsWeakeningChecked source.stackWindows target.stackWindows = true
  predicates : target.predicates.all source.predicates.contains = true

theorem listAll_of_contains
    {alpha : Type} [BEq alpha] [LawfulBEq alpha]
    (source target : List alpha) (predicate : alpha → Bool)
    (subset : target.all source.contains = true)
    (sourceHolds : source.all predicate = true) :
    target.all predicate = true := by
  simp only [List.all_eq_true] at subset sourceHolds ⊢
  intro value member
  exact sourceHolds value (List.contains_iff_mem.mp (subset value member))

def dynamicWordRequirementsHold (context : StaticProofContext)
    (world : RelationalWorld) (range : DynamicAddressRangePair)
    (requirements : List DynamicWordRelation)
    (original candidate : Memory) : Bool :=
  requirements.all fun requirement =>
    requirement.offset + 4 <= range.size &&
      requirement.holds context world range original candidate

theorem dynamicWordRequirementsHold_single_after_paired_write
    (context : StaticProofContext) (world : RelationalWorld)
    (range : DynamicAddressRangePair) (requirement : DynamicWordRelation)
    (original candidate : Memory) (originalValue candidateValue : Word)
    (rangeValid : range.disjointFromImages context = true)
    (inside : requirement.offset + 4 <= range.size)
    (valuesRelated : requirement.kind.valuesHold context world range
      originalValue candidateValue = true) :
    dynamicWordRequirementsHold context world range [requirement]
      (original.write32
        (range.originalBase + BitVec.ofNat 32 requirement.offset) originalValue)
      (candidate.write32
        (range.candidateBase + BitVec.ofNat 32 requirement.offset) candidateValue) = true := by
  have originalFits := DynamicAddressRangePair.wordAddress_fits context false
    range rangeValid requirement.offset inside
  have candidateFits := DynamicAddressRangePair.wordAddress_fits context true
    range rangeValid requirement.offset inside
  have originalFits' :
      (range.originalBase + BitVec.ofNat 32 requirement.offset).toNat + 4 <=
        2 ^ 32 := by
    simpa [DynamicAddressRangePair.sideBase] using originalFits
  have candidateFits' :
      (range.candidateBase + BitVec.ofNat 32 requirement.offset).toNat + 4 <=
        2 ^ 32 := by
    simpa [DynamicAddressRangePair.sideBase] using candidateFits
  simp only [dynamicWordRequirementsHold, List.all_cons, List.all_nil,
    Bool.and_true, Bool.and_eq_true]
  constructor
  · exact decide_eq_true inside
  · unfold DynamicWordRelation.holds
    rw [Memory.read32_write32_same_of_fits _ _ _ originalFits',
      Memory.read32_write32_same_of_fits _ _ _ candidateFits']
    exact valuesRelated

theorem dynamicWordRequirementsHold_mono
    (context : StaticProofContext) (world : RelationalWorld)
    (range : DynamicAddressRangePair)
    (sourceRequirements targetRequirements : List DynamicWordRelation)
    (original candidate : Memory)
    (subset : targetRequirements.all sourceRequirements.contains = true)
    (sourceHolds : dynamicWordRequirementsHold context world range
      sourceRequirements original candidate = true) :
    dynamicWordRequirementsHold context world range targetRequirements
      original candidate = true := by
  simp only [dynamicWordRequirementsHold, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at sourceHolds ⊢
  simp only [List.all_eq_true] at subset
  intro requirement member
  have sourceMember : requirement ∈ sourceRequirements :=
    List.contains_iff_mem.mp (subset requirement member)
  exact sourceHolds requirement sourceMember

theorem dynamicWordRequirementsHold_after_single_dynamic_write
    (context : StaticProofContext) (world : RelationalWorld)
    (range : DynamicAddressRangePair) (writeRelation : DynamicWordRelation)
    (sourceRequirements targetRequirements : List DynamicWordRelation)
    (original candidate : Memory) (originalValue candidateValue : Word)
    (rangesValid : world.dynamicRangesValid context = true)
    (rangeMember : range ∈ world.dynamicRanges)
    (writeMember : writeRelation ∈ range.wordRelations)
    (sourceAvailable : sourceRequirements.all range.wordRelations.contains = true)
    (targetCovered : (targetRequirements.all fun requirement =>
      requirement == writeRelation || sourceRequirements.contains requirement) = true)
    (sourceHolds : dynamicWordRequirementsHold context world range
      sourceRequirements original candidate = true)
    (valuesRelated : writeRelation.kind.valuesHold context world range
      originalValue candidateValue = true) :
    dynamicWordRequirementsHold context world range targetRequirements
      (original.write32
        (range.originalBase + BitVec.ofNat 32 writeRelation.offset) originalValue)
      (candidate.write32
        (range.candidateBase + BitVec.ofNat 32 writeRelation.offset) candidateValue) = true := by
  have rangeValid : range.disjointFromImages context = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.1.2 range rangeMember
  have relationsValid : range.wordRelationsValid = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.2 range rangeMember
  simp only [DynamicAddressRangePair.wordRelationsValid, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at relationsValid
  have writeInside := (relationsValid writeRelation writeMember).1
  have originalFits := DynamicAddressRangePair.wordAddress_fits context false
    range rangeValid writeRelation.offset writeInside
  have candidateFits := DynamicAddressRangePair.wordAddress_fits context true
    range rangeValid writeRelation.offset writeInside
  have originalFits' :
      (range.originalBase + BitVec.ofNat 32 writeRelation.offset).toNat + 4 <=
        2 ^ 32 := by
    simpa [DynamicAddressRangePair.sideBase] using originalFits
  have candidateFits' :
      (range.candidateBase + BitVec.ofNat 32 writeRelation.offset).toNat + 4 <=
        2 ^ 32 := by
    simpa [DynamicAddressRangePair.sideBase] using candidateFits
  simp only [dynamicWordRequirementsHold, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at sourceHolds ⊢
  simp only [List.all_eq_true, Bool.or_eq_true, beq_iff_eq] at targetCovered
  simp only [List.all_eq_true] at sourceAvailable
  intro requirement requirementMember
  by_cases same : requirement = writeRelation
  · subst requirement
    exact ⟨writeInside, by
      unfold DynamicWordRelation.holds
      rw [Memory.read32_write32_same_of_fits _ _ _ originalFits',
        Memory.read32_write32_same_of_fits _ _ _ candidateFits']
      exact valuesRelated⟩
  · have sourceContains : sourceRequirements.contains requirement = true := by
      rcases targetCovered requirement requirementMember with equal | contained
      · exact (same equal).elim
      · exact contained
    have sourceMember : requirement ∈ sourceRequirements :=
      List.contains_iff_mem.mp sourceContains
    have requirementInRange : requirement ∈ range.wordRelations :=
      List.contains_iff_mem.mp (sourceAvailable requirement sourceMember)
    have requirementInside := (relationsValid requirement requirementInRange).1
    have originalAvoids := dynamicRangeWordWriteAvoidsOtherWord context false
      world rangesValid range range rangeMember rangeMember writeRelation requirement
      writeMember requirementInRange (Or.inr same)
    have candidateAvoids := dynamicRangeWordWriteAvoidsOtherWord context true
      world rangesValid range range rangeMember rangeMember writeRelation requirement
      writeMember requirementInRange (Or.inr same)
    refine ⟨requirementInside, ?_⟩
    unfold DynamicWordRelation.holds
    rw [Memory.read32_write32_of_avoids _ _ _ _
        (by simpa [DynamicAddressRangePair.sideBase] using originalAvoids),
      Memory.read32_write32_of_avoids _ _ _ _
        (by simpa [DynamicAddressRangePair.sideBase] using candidateAvoids)]
    exact (sourceHolds requirement sourceMember).2

theorem dynamicWordRequirementsHold_after_stack_update
    (context : StaticProofContext) (world : RelationalWorld)
    (range : DynamicAddressRangePair) (requirements : List DynamicWordRelation)
    (original candidate : Memory) (update : PairedStackWordUpdate context world)
    (rangesValid : world.dynamicRangesValid context = true)
    (rangeMember : range ∈ world.dynamicRanges)
    (sourceHolds : dynamicWordRequirementsHold context world range requirements
      original candidate = true) :
    dynamicWordRequirementsHold context world range requirements
      (original.write32 update.location.originalAddress update.originalValue)
      (candidate.write32 update.location.candidateAddress update.candidateValue) = true := by
  simp only [dynamicWordRequirementsHold, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at sourceHolds ⊢
  intro relation relationMember
  have prior := sourceHolds relation relationMember
  have originalAvoids := stackRangeWordWriteAvoidsDynamicRangeWord context false
    world rangesValid update.location.range range update.location.rangeMember
    rangeMember update.locationValid update.location.offset relation.offset
    update.location.inside prior.1
  have candidateAvoids := stackRangeWordWriteAvoidsDynamicRangeWord context true
    world rangesValid update.location.range range update.location.rangeMember
    rangeMember update.locationValid update.location.offset relation.offset
    update.location.inside prior.1
  refine ⟨prior.1, ?_⟩
  unfold DynamicWordRelation.holds at prior ⊢
  rw [update.location.originalAddressExact, update.location.candidateAddressExact,
    Memory.read32_write32_of_avoids _ _ _ _
      (by simpa [DynamicAddressRangePair.sideBase] using originalAvoids),
    Memory.read32_write32_of_avoids _ _ _ _
      (by simpa [DynamicAddressRangePair.sideBase] using candidateAvoids)]
  exact prior.2

theorem dynamicWordRequirementsHold_after_static_word_update
    (context : StaticProofContext) (world : RelationalWorld)
    (range : DynamicAddressRangePair) (requirements : List DynamicWordRelation)
    (original candidate : Memory) (update : PairedStaticWordUpdate context world)
    (rangesValid : world.dynamicRangesValid context = true)
    (slotsValid : staticWordRelationSlotsValid context = true)
    (rangeMember : range ∈ world.dynamicRanges)
    (sourceHolds : dynamicWordRequirementsHold context world range requirements
      original candidate = true) :
    dynamicWordRequirementsHold context world range requirements
      (original.write32 update.location.originalAddress update.originalValue)
      (candidate.write32 update.location.candidateAddress update.candidateValue) = true := by
  have rangeValid : range.disjointFromImages context = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.1.2 range rangeMember
  have slotValid := update.location.slot.valid_of_member context slotsValid
    update.location.slotMember
  have originalBounds := update.location.slot.originalBounds context slotValid
  have candidateBounds := update.location.slot.candidateBounds context slotValid
  have rangeShape := rangeValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeShape
  rcases rangeShape with
    ⟨⟨⟨⟨_nonempty, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  simp only [dynamicWordRequirementsHold, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at sourceHolds ⊢
  intro relation relationMember
  have prior := sourceHolds relation relationMember
  have originalAvoids := (stackRangeWordWriteAvoidsImageWord
    range.originalBase range.size context.originalPe.imageBase
    context.originalPe.sizeOfImage relation.offset prior.1 originalNoWrap
    originalDisjoint update.location.slot.originalAddress originalBounds.1
    originalBounds.2.1 originalBounds.2.2).symm
  have candidateAvoids := (stackRangeWordWriteAvoidsImageWord
    range.candidateBase range.size context.candidatePe.imageBase
    context.candidatePe.sizeOfImage relation.offset prior.1 candidateNoWrap
    candidateDisjoint update.location.slot.candidateAddress candidateBounds.1
    candidateBounds.2.1 candidateBounds.2.2).symm
  refine ⟨prior.1, ?_⟩
  unfold DynamicWordRelation.holds at prior ⊢
  rw [update.location.originalAddressExact, update.location.candidateAddressExact,
    Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact prior.2

theorem dynamicWordRequirementsHold_after_static_pointer_update
    (context : StaticProofContext) (world : RelationalWorld)
    (range : DynamicAddressRangePair) (requirements : List DynamicWordRelation)
    (original candidate : Memory)
    (update : PairedStaticDynamicPointerUpdate context world)
    (rangesValid : world.dynamicRangesValid context = true)
    (slotsValid : staticDynamicPointerSlotsValid context = true)
    (rangeMember : range ∈ world.dynamicRanges)
    (sourceHolds : dynamicWordRequirementsHold context world range requirements
      original candidate = true) :
    dynamicWordRequirementsHold context world range requirements
      (original.write32 update.location.originalAddress update.range.originalBase)
      (candidate.write32 update.location.candidateAddress update.range.candidateBase) = true := by
  have rangeValid : range.disjointFromImages context = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.1.2 range rangeMember
  have slotValid := update.location.slot.valid_of_member context slotsValid
    update.location.slotMember
  have originalBounds := update.location.slot.originalBounds context slotValid
  have candidateBounds := update.location.slot.candidateBounds context slotValid
  have rangeShape := rangeValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeShape
  rcases rangeShape with
    ⟨⟨⟨⟨_nonempty, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  simp only [dynamicWordRequirementsHold, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at sourceHolds ⊢
  intro relation relationMember
  have prior := sourceHolds relation relationMember
  have originalAvoids := (stackRangeWordWriteAvoidsImageWord
    range.originalBase range.size context.originalPe.imageBase
    context.originalPe.sizeOfImage relation.offset prior.1 originalNoWrap
    originalDisjoint update.location.slot.originalAddress originalBounds.1
    originalBounds.2.1 originalBounds.2.2).symm
  have candidateAvoids := (stackRangeWordWriteAvoidsImageWord
    range.candidateBase range.size context.candidatePe.imageBase
    context.candidatePe.sizeOfImage relation.offset prior.1 candidateNoWrap
    candidateDisjoint update.location.slot.candidateAddress candidateBounds.1
    candidateBounds.2.1 candidateBounds.2.2).symm
  refine ⟨prior.1, ?_⟩
  unfold DynamicWordRelation.holds at prior ⊢
  rw [update.location.originalAddressExact, update.location.candidateAddressExact,
    Memory.read32_write32_of_avoids _ _ _ _ originalAvoids,
    Memory.read32_write32_of_avoids _ _ _ _ candidateAvoids]
  exact prior.2

theorem dynamicWordRequirementsHold_after_dynamic_update
    (context : StaticProofContext) (world : RelationalWorld)
    (range : DynamicAddressRangePair) (requirements : List DynamicWordRelation)
    (original candidate : Memory) (update : PairedDynamicWordUpdate context world)
    (rangesValid : world.dynamicRangesValid context = true)
    (rangeMember : range ∈ world.dynamicRanges)
    (requirementsAvailable : requirements.all range.wordRelations.contains = true)
    (sourceHolds : dynamicWordRequirementsHold context world range requirements
      original candidate = true) :
    dynamicWordRequirementsHold context world range requirements
      (original.write32 update.location.originalAddress update.originalValue)
      (candidate.write32 update.location.candidateAddress update.candidateValue) = true := by
  have writeRangeValid : update.location.range.disjointFromImages context = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.1.2 update.location.range
      update.location.rangeMember
  have writeRelationsValid : update.location.range.wordRelationsValid = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at rangesValid
    exact rangesValid.1.1.1.1.2 update.location.range
      update.location.rangeMember
  simp only [DynamicAddressRangePair.wordRelationsValid, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at writeRelationsValid
  have writeInside :=
    (writeRelationsValid update.location.relation
      update.location.relationMember).1
  have originalFits := DynamicAddressRangePair.wordAddress_fits context false
    update.location.range writeRangeValid update.location.relation.offset writeInside
  have candidateFits := DynamicAddressRangePair.wordAddress_fits context true
    update.location.range writeRangeValid update.location.relation.offset writeInside
  have originalFits' : update.location.originalAddress.toNat + 4 <= 2 ^ 32 := by
    rw [update.location.originalAddressExact]
    simpa [DynamicAddressRangePair.sideBase] using originalFits
  have candidateFits' : update.location.candidateAddress.toNat + 4 <= 2 ^ 32 := by
    rw [update.location.candidateAddressExact]
    simpa [DynamicAddressRangePair.sideBase] using candidateFits
  simp only [dynamicWordRequirementsHold, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at sourceHolds ⊢
  simp only [List.all_eq_true] at requirementsAvailable
  intro relation relationMember
  have prior := sourceHolds relation relationMember
  have relationInRange : relation ∈ range.wordRelations :=
    List.contains_iff_mem.mp (requirementsAvailable relation relationMember)
  by_cases sameRange : range = update.location.range
  · subst range
    by_cases sameRelation : relation = update.location.relation
    · subst relation
      refine ⟨writeInside, ?_⟩
      unfold DynamicWordRelation.holds
      rw [← update.location.originalAddressExact,
        ← update.location.candidateAddressExact,
        Memory.read32_write32_same_of_fits _ _ _ originalFits',
        Memory.read32_write32_same_of_fits _ _ _ candidateFits']
      exact update.valuesRelated
    · have originalAvoids := dynamicRangeWordWriteAvoidsOtherWord context false
        world rangesValid update.location.range update.location.range
        update.location.rangeMember update.location.rangeMember
        update.location.relation relation update.location.relationMember
        relationInRange (Or.inr sameRelation)
      have candidateAvoids := dynamicRangeWordWriteAvoidsOtherWord context true
        world rangesValid update.location.range update.location.range
        update.location.rangeMember update.location.rangeMember
        update.location.relation relation update.location.relationMember
        relationInRange (Or.inr sameRelation)
      refine ⟨prior.1, ?_⟩
      unfold DynamicWordRelation.holds at prior ⊢
      rw [Memory.read32_write32_of_avoids _ _ _ _
          (by simpa [update.location.originalAddressExact,
            DynamicAddressRangePair.sideBase] using originalAvoids),
        Memory.read32_write32_of_avoids _ _ _ _
          (by simpa [update.location.candidateAddressExact,
            DynamicAddressRangePair.sideBase] using candidateAvoids)]
      exact prior.2
  · have originalAvoids := dynamicRangeWordWriteAvoidsOtherWord context false
      world rangesValid update.location.range range update.location.rangeMember
      rangeMember update.location.relation relation update.location.relationMember
      relationInRange (Or.inl sameRange)
    have candidateAvoids := dynamicRangeWordWriteAvoidsOtherWord context true
      world rangesValid update.location.range range update.location.rangeMember
      rangeMember update.location.relation relation update.location.relationMember
      relationInRange (Or.inl sameRange)
    refine ⟨prior.1, ?_⟩
    unfold DynamicWordRelation.holds at prior ⊢
    rw [Memory.read32_write32_of_avoids _ _ _ _
        (by simpa [update.location.originalAddressExact,
          DynamicAddressRangePair.sideBase] using originalAvoids),
      Memory.read32_write32_of_avoids _ _ _ _
        (by simpa [update.location.candidateAddressExact,
          DynamicAddressRangePair.sideBase] using candidateAvoids)]
    exact prior.2

theorem dynamicWordRequirementsHold_after_prepared_updates
    (context : StaticProofContext) (world : RelationalWorld)
    (range : DynamicAddressRangePair) (requirements : List DynamicWordRelation)
    (original candidate : Memory)
    (updates : List (PairedPreparedWordUpdate context world))
    (rangesValid : world.dynamicRangesValid context = true)
    (staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true)
    (staticWordSlotsValid : staticWordRelationSlotsValid context = true)
    (rangeMember : range ∈ world.dynamicRanges)
    (requirementsAvailable : requirements.all range.wordRelations.contains = true)
    (sourceHolds : dynamicWordRequirementsHold context world range requirements
      original candidate = true) :
    dynamicWordRequirementsHold context world range requirements
      (applyConcreteWrites original
        (updates.map PairedPreparedWordUpdate.originalWrite))
      (applyConcreteWrites candidate
        (updates.map PairedPreparedWordUpdate.candidateWrite)) = true := by
  induction updates generalizing original candidate with
  | nil => simpa [applyConcreteWrites] using sourceHolds
  | cons update rest induction =>
      have afterHead : dynamicWordRequirementsHold context world range requirements
          (original.write32 update.originalWrite.1 update.originalWrite.2)
          (candidate.write32 update.candidateWrite.1 update.candidateWrite.2) = true := by
        cases update with
        | stack update =>
            simpa [PairedPreparedWordUpdate.originalWrite,
              PairedPreparedWordUpdate.candidateWrite,
              PairedStackWordUpdate.originalWrite,
              PairedStackWordUpdate.candidateWrite] using
              dynamicWordRequirementsHold_after_stack_update context world range
                requirements original candidate update rangesValid rangeMember sourceHolds
        | staticWord update =>
            simpa [PairedPreparedWordUpdate.originalWrite,
              PairedPreparedWordUpdate.candidateWrite,
              PairedStaticWordUpdate.originalWrite,
              PairedStaticWordUpdate.candidateWrite] using
              dynamicWordRequirementsHold_after_static_word_update context world range
                requirements original candidate update rangesValid staticWordSlotsValid
                rangeMember sourceHolds
        | dynamicWord update =>
            simpa [PairedPreparedWordUpdate.originalWrite,
              PairedPreparedWordUpdate.candidateWrite,
              PairedDynamicWordUpdate.originalWrite,
              PairedDynamicWordUpdate.candidateWrite] using
              dynamicWordRequirementsHold_after_dynamic_update context world range
                requirements original candidate update rangesValid rangeMember
                requirementsAvailable sourceHolds
        | staticDynamicPointer update =>
            simpa [PairedPreparedWordUpdate.originalWrite,
              PairedPreparedWordUpdate.candidateWrite,
              PairedStaticDynamicPointerUpdate.originalWrite,
              PairedStaticDynamicPointerUpdate.candidateWrite] using
              dynamicWordRequirementsHold_after_static_pointer_update context world
                range requirements original candidate update rangesValid
                staticPointerSlotsValid rangeMember sourceHolds
      simpa [applyConcreteWrites] using
        induction
          (original := original.write32 update.originalWrite.1 update.originalWrite.2)
          (candidate := candidate.write32 update.candidateWrite.1
            update.candidateWrite.2)
          afterHead

def DynamicRegisterRangeRelation.activeHolds (context : StaticProofContext)
    (world : RelationalWorld) (relation : DynamicRegisterRangeRelation)
    (original candidate : MachineState) : Bool :=
  world.dynamicRanges.any fun range =>
      original.registers.get relation.original ==
          range.originalBase + BitVec.ofNat 32 relation.originalOffset &&
        candidate.registers.get relation.candidate ==
          range.candidateBase + BitVec.ofNat 32 relation.candidateOffset &&
        relation.requiredWords.all range.wordRelations.contains &&
        relation.activeWords.all relation.requiredWords.contains &&
        dynamicWordRequirementsHold context world range relation.activeWords
          original.memory candidate.memory

def activeDynamicRegisterRangeRelationsHold (context : StaticProofContext)
    (world : RelationalWorld) (relations : List DynamicRegisterRangeRelation)
    (original candidate : MachineState) : Bool :=
  relations.all fun relation => relation.activeHolds context world original candidate

def DynamicStackRangeRelation.activeHolds (context : StaticProofContext)
    (world : RelationalWorld) (relation : DynamicStackRangeRelation)
    (original candidate : MachineState) : Bool :=
  relation.window.holds world original.registers candidate.registers &&
      world.dynamicRanges.any fun range =>
        Memory.read32 original.memory
            (original.registers.get relation.window.originalRegister +
              BitVec.ofNat 32 relation.stackOffset) ==
            range.originalBase + BitVec.ofNat 32 relation.originalOffset &&
          Memory.read32 candidate.memory
            (candidate.registers.get relation.window.candidateRegister +
              BitVec.ofNat 32 relation.stackOffset) ==
            range.candidateBase + BitVec.ofNat 32 relation.candidateOffset &&
          relation.requiredWords.all range.wordRelations.contains &&
          relation.activeWords.all relation.requiredWords.contains &&
          dynamicWordRequirementsHold context world range relation.activeWords
            original.memory candidate.memory

def activeDynamicStackRangeRelationsHold (context : StaticProofContext)
    (world : RelationalWorld) (relations : List DynamicStackRangeRelation)
    (original candidate : MachineState) : Bool :=
  relations.all fun relation => relation.activeHolds context world original candidate

theorem DynamicRegisterRangeRelation.holds_of_activeHolds
    (context : StaticProofContext) (world : RelationalWorld)
    (relation : DynamicRegisterRangeRelation) (original candidate : MachineState)
    (active : relation.activeHolds context world original candidate = true) :
    relation.holds world original.registers candidate.registers = true := by
  simp only [DynamicRegisterRangeRelation.activeHolds, List.any_eq_true,
    Bool.and_eq_true] at active
  rcases active with ⟨range, member, row⟩
  unfold DynamicRegisterRangeRelation.holds
  simp only [List.any_eq_true]
  refine ⟨range, member, ?_⟩
  simpa only [Bool.and_eq_true] using row.1

theorem DynamicRegisterRangeRelation.activeHolds_of_holds_empty
    (context : StaticProofContext) (world : RelationalWorld)
    (relation : DynamicRegisterRangeRelation) (original candidate : MachineState)
    (empty : relation.activeWords = [])
    (holds : relation.holds world original.registers candidate.registers = true) :
    relation.activeHolds context world original candidate = true := by
  unfold DynamicRegisterRangeRelation.holds at holds
  unfold DynamicRegisterRangeRelation.activeHolds
  rw [empty] at holds ⊢
  simpa [dynamicWordRequirementsHold] using holds

theorem DynamicStackRangeRelation.holds_of_activeHolds
    (context : StaticProofContext) (world : RelationalWorld)
    (relation : DynamicStackRangeRelation) (original candidate : MachineState)
    (active : relation.activeHolds context world original candidate = true) :
    relation.holds world original candidate = true := by
  simp only [DynamicStackRangeRelation.activeHolds, Bool.and_eq_true,
    List.any_eq_true] at active
  rcases active with ⟨window, range, member, row⟩
  unfold DynamicStackRangeRelation.holds
  simp only [Bool.and_eq_true, List.any_eq_true]
  refine ⟨window, range, member, ?_⟩
  simpa only [Bool.and_eq_true] using row.1

theorem dynamicRegisterRangeRelationsHold_of_active
    (context : StaticProofContext) (world : RelationalWorld)
    (relations : List DynamicRegisterRangeRelation)
    (original candidate : MachineState)
    (active : activeDynamicRegisterRangeRelationsHold context world relations
      original candidate = true) :
    dynamicRegisterRangeRelationsHold world relations original.registers
      candidate.registers = true := by
  simp only [activeDynamicRegisterRangeRelationsHold, List.all_eq_true] at active
  simp only [dynamicRegisterRangeRelationsHold, List.all_eq_true]
  intro relation member
  exact relation.holds_of_activeHolds context world original candidate
    (active relation member)

theorem dynamicStackRangeRelationsHold_of_active
    (context : StaticProofContext) (world : RelationalWorld)
    (relations : List DynamicStackRangeRelation)
    (original candidate : MachineState)
    (active : activeDynamicStackRangeRelationsHold context world relations
      original candidate = true) :
    dynamicStackRangeRelationsHold world relations original candidate = true := by
  simp only [activeDynamicStackRangeRelationsHold, List.all_eq_true] at active
  simp only [dynamicStackRangeRelationsHold, List.all_eq_true]
  intro relation member
  exact relation.holds_of_activeHolds context world original candidate
    (active relation member)

structure ActiveDynamicInvariantMemoryHold (context : StaticProofContext)
    (world : RelationalWorld) (invariant : StateInvariant)
    (original candidate : MachineState) : Prop where
  registerRanges : activeDynamicRegisterRangeRelationsHold context world
    invariant.dynamicRegisterRangeRelations original candidate = true
  stackRanges : activeDynamicStackRangeRelationsHold context world
    invariant.dynamicStackRangeRelations original candidate = true

structure RelationalDynamicMemoryHold (context : StaticProofContext)
    (world : RelationalWorld) (invariant : StateInvariant)
    (original candidate : MachineState) : Prop where
  staticPointerSlots : StaticDynamicPointerSlotsMemoryHold context world
    original.memory candidate.memory
  staticWordSlots : StaticWordRelationSlotsMemoryHold context world
    original.memory candidate.memory
  active : ActiveDynamicInvariantMemoryHold context world invariant original candidate

theorem dynamicWordRequirementsHold_of_global
    (context : StaticProofContext) (world : RelationalWorld)
    (range : DynamicAddressRangePair) (requirements : List DynamicWordRelation)
    (original candidate : Memory)
    (worldValid : world.valid context = true)
    (rangeMember : range ∈ world.dynamicRanges)
    (requirementsAvailable : requirements.all range.wordRelations.contains = true)
    (global : DynamicRangesMemoryHold context world original candidate) :
    dynamicWordRequirementsHold context world range requirements
      original candidate = true := by
  have dynamicValid : world.dynamicRangesValid context = true := by
    simp only [RelationalWorld.valid, Bool.and_eq_true] at worldValid
    exact worldValid.1.1.1.1
  have rangeRelationsValid : range.wordRelationsValid = true := by
    simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
      List.all_eq_true] at dynamicValid
    exact dynamicValid.1.1.1.1.2 range rangeMember
  simp only [DynamicAddressRangePair.wordRelationsValid, List.all_eq_true,
    Bool.and_eq_true] at rangeRelationsValid
  have rangeWords := global range rangeMember
  simp only [DynamicAddressRangePair.wordsHold, List.all_eq_true] at rangeWords
  simp only [dynamicWordRequirementsHold, List.all_eq_true,
    Bool.and_eq_true]
  intro requirement requirementMember
  have available : requirement ∈ range.wordRelations :=
    List.contains_iff_mem.mp
      (List.all_eq_true.mp requirementsAvailable requirement requirementMember)
  have valid := rangeRelationsValid requirement available
  exact ⟨valid.1, rangeWords requirement available⟩

theorem activeDynamicRegisterRangeRelationsHold_of_global
    (context : StaticProofContext) (world : RelationalWorld)
    (relations : List DynamicRegisterRangeRelation)
    (original candidate : MachineState)
    (worldValid : world.valid context = true)
    (locations : dynamicRegisterRangeRelationsHold world relations
      original.registers candidate.registers = true)
    (global : DynamicRangesMemoryHold context world
      original.memory candidate.memory) :
    activeDynamicRegisterRangeRelationsHold context world relations
      original candidate = true := by
  simp only [dynamicRegisterRangeRelationsHold, List.all_eq_true] at locations
  simp only [activeDynamicRegisterRangeRelationsHold, List.all_eq_true]
  intro relation relationMember
  have location := locations relation relationMember
  simp only [DynamicRegisterRangeRelation.holds, List.any_eq_true,
    Bool.and_eq_true] at location
  rcases location with
    ⟨range, rangeMember, ⟨⟨⟨originalAddress, candidateAddress⟩,
      requirements⟩, activeSubset⟩⟩
  have activeAvailable :
      relation.activeWords.all range.wordRelations.contains = true := by
    simp only [List.all_eq_true] at requirements activeSubset ⊢
    intro word wordMember
    have requiredMember : word ∈ relation.requiredWords :=
      List.contains_iff_mem.mp (activeSubset word wordMember)
    exact requirements word requiredMember
  unfold DynamicRegisterRangeRelation.activeHolds
  simp only [List.any_eq_true]
  refine ⟨range, rangeMember, ?_⟩
  simp only [Bool.and_eq_true]
  exact ⟨⟨⟨⟨originalAddress, candidateAddress⟩, requirements⟩,
      activeSubset⟩,
    dynamicWordRequirementsHold_of_global context world range
      relation.activeWords original.memory candidate.memory worldValid rangeMember
      activeAvailable global⟩

theorem activeDynamicStackRangeRelationsHold_of_global
    (context : StaticProofContext) (world : RelationalWorld)
    (relations : List DynamicStackRangeRelation)
    (original candidate : MachineState)
    (worldValid : world.valid context = true)
    (locations : dynamicStackRangeRelationsHold world relations
      original candidate = true)
    (global : DynamicRangesMemoryHold context world
      original.memory candidate.memory) :
    activeDynamicStackRangeRelationsHold context world relations
      original candidate = true := by
  simp only [dynamicStackRangeRelationsHold, List.all_eq_true] at locations
  simp only [activeDynamicStackRangeRelationsHold, List.all_eq_true]
  intro relation relationMember
  have location := locations relation relationMember
  simp only [DynamicStackRangeRelation.holds, Bool.and_eq_true,
    List.any_eq_true] at location
  rcases location with
    ⟨window, range, rangeMember,
      ⟨⟨⟨originalAddress, candidateAddress⟩, requirements⟩,
        activeSubset⟩⟩
  have activeAvailable :
      relation.activeWords.all range.wordRelations.contains = true := by
    simp only [List.all_eq_true] at requirements activeSubset ⊢
    intro word wordMember
    have requiredMember : word ∈ relation.requiredWords :=
      List.contains_iff_mem.mp (activeSubset word wordMember)
    exact requirements word requiredMember
  unfold DynamicStackRangeRelation.activeHolds
  simp only [Bool.and_eq_true]
  refine ⟨window, ?_⟩
  simp only [List.any_eq_true]
  refine ⟨range, rangeMember, ?_⟩
  simp only [Bool.and_eq_true]
  exact ⟨⟨⟨⟨originalAddress, candidateAddress⟩, requirements⟩,
      activeSubset⟩,
    dynamicWordRequirementsHold_of_global context world range
      relation.activeWords original.memory candidate.memory worldValid rangeMember
      activeAvailable global⟩

theorem ActiveDynamicInvariantMemoryHold.of_global
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (worldValid : world.valid context = true)
    (registerLocations : dynamicRegisterRangeRelationsHold world
      invariant.dynamicRegisterRangeRelations original.registers
      candidate.registers = true)
    (stackLocations : dynamicStackRangeRelationsHold world
      invariant.dynamicStackRangeRelations original candidate = true)
    (global : DynamicRangesMemoryHold context world
      original.memory candidate.memory) :
    ActiveDynamicInvariantMemoryHold context world invariant original candidate := {
  registerRanges := activeDynamicRegisterRangeRelationsHold_of_global
    context world invariant.dynamicRegisterRangeRelations original candidate
    worldValid registerLocations global
  stackRanges := activeDynamicStackRangeRelationsHold_of_global
    context world invariant.dynamicStackRangeRelations original candidate
    worldValid stackLocations global
}

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
    ⟨⟨⟨⟨⟨⟨⟨sourceMember, targetMember⟩, rangeId⟩,
      enoughBelow⟩, enoughAbove⟩, adjustmentSafe⟩,
      originalExpression⟩, candidateExpression⟩
  simp only [stackWindowsRelated, List.all_eq_true] at sourceRelated
  have sourceHolds := sourceRelated claim.source (by simpa using sourceMember)
  have rangeId' := beq_iff_eq.mp rangeId
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
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at rangesValid
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have rangeValid := rangesValid.1.1.2 range rangeMember
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq] at rangeValid
      rcases rangeValid with
        ⟨⟨⟨⟨rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩, _⟩, _⟩
      have pairedLinear :
          (originalState.registers.get claim.source.originalRegister).toNat +
              range.candidateBase.toNat =
            (candidateState.registers.get claim.source.candidateRegister).toNat +
              range.originalBase.toNat := by
        omega
      simp only [StackWindowPair.holds, rangeResult,
        NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get]
      have originalExpression' := StackAdjustment.eval_expression_of_matches
        claim.adjustment claim.source.originalRegister
        (originalBehavior.registers.get claim.target.originalRegister) originalState
        originalExpression
      have candidateExpression' := StackAdjustment.eval_expression_of_matches
        claim.adjustment claim.source.candidateRegister
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
              (originalState.registers.get claim.source.originalRegister +
                BitVec.ofNat 32 amount).toNat =
                (originalState.registers.get claim.source.originalRegister).toNat + amount := by
            simp [BitVec.toNat_add, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt (by omega : amount < 2 ^ 32),
              Nat.mod_eq_of_lt (by omega :
                (originalState.registers.get claim.source.originalRegister).toNat +
                  amount < 2 ^ 32)]
          have candidateAdjusted :
              (candidateState.registers.get claim.source.candidateRegister +
                BitVec.ofNat 32 amount).toNat =
                (candidateState.registers.get claim.source.candidateRegister).toNat + amount := by
            simp [BitVec.toNat_add, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt (by omega : amount < 2 ^ 32),
              Nat.mod_eq_of_lt (by omega :
                (candidateState.registers.get claim.source.candidateRegister).toNat +
                  amount < 2 ^ 32)]
          simp only [Bool.and_eq_true, decide_eq_true_eq, originalAdjusted,
            candidateAdjusted]
          have originalTargetLower :
              range.originalBase.toNat + claim.target.bytesBelow <=
                (originalState.registers.get claim.source.originalRegister).toNat +
                  amount := by omega
          have originalTargetUpper :
              (originalState.registers.get claim.source.originalRegister).toNat +
                    amount + claim.target.bytesAbove <=
                range.originalBase.toNat + range.size := by omega
          have candidateTargetLower :
              range.candidateBase.toNat + claim.target.bytesBelow <=
                (candidateState.registers.get claim.source.candidateRegister).toNat +
                  amount := by omega
          have candidateTargetUpper :
              (candidateState.registers.get claim.source.candidateRegister).toNat +
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
              amount <= (originalState.registers.get claim.source.originalRegister).toNat := by
            omega
          have candidateEnough :
              amount <= (candidateState.registers.get claim.source.candidateRegister).toNat := by
            omega
          have originalAdjusted :
              (originalState.registers.get claim.source.originalRegister -
                BitVec.ofNat 32 amount).toNat =
                (originalState.registers.get claim.source.originalRegister).toNat - amount := by
            simp [BitVec.toNat_sub, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt (by omega : amount < 2 ^ 32)]
            omega
          have candidateAdjusted :
              (candidateState.registers.get claim.source.candidateRegister -
                BitVec.ofNat 32 amount).toNat =
                (candidateState.registers.get claim.source.candidateRegister).toNat - amount := by
            simp [BitVec.toNat_sub, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt (by omega : amount < 2 ^ 32)]
            omega
          simp only [Bool.and_eq_true, decide_eq_true_eq, originalAdjusted,
            candidateAdjusted]
          have originalTargetLower :
              range.originalBase.toNat + claim.target.bytesBelow <=
                (originalState.registers.get claim.source.originalRegister).toNat -
                  amount := by omega
          have originalTargetUpper :
              (originalState.registers.get claim.source.originalRegister).toNat -
                    amount + claim.target.bytesAbove <=
                range.originalBase.toNat + range.size := by omega
          have candidateTargetLower :
              range.candidateBase.toNat + claim.target.bytesBelow <=
                (candidateState.registers.get claim.source.candidateRegister).toNat -
                  amount := by omega
          have candidateTargetUpper :
              (candidateState.registers.get claim.source.candidateRegister).toNat -
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

def MachineX87Exact (original candidate : MachineState) : Prop :=
  original.x87 = candidate.x87 ∧
    original.x87Physical = candidate.x87Physical ∧
    original.x87Semantics = candidate.x87Semantics

def x87AddressRelation (context : StaticProofContext)
    (world : RelationalWorld) : StageA.Relational.X87.AddressRelation := {
  code := fun original candidate =>
    original = candidate ∨
      codePointerRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList original candidate = true
  data := fun original candidate =>
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      original candidate = true
}

def MachineX87Related (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : MachineState) : Prop :=
  original.x87 = candidate.x87 ∧
    StageA.Relational.X87.StateRelated (x87AddressRelation context world)
      original.x87Physical candidate.x87Physical ∧
    original.x87Semantics = candidate.x87Semantics

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
    MachineX87Exact original candidate ∧
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
    RelationalDynamicMemoryHold context world invariant original candidate ∧
    original.undefinedValue = candidate.undefinedValue ∧
    MachineX87Related context world original candidate ∧
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
      registerValueOriginRelationsHold context world
        invariant.registerValueOriginRelations original.registers
        candidate.registers = true ∧
      memoryValueOriginRelationsHold context world
        invariant.memoryValueOriginRelations original candidate = true ∧
      dynamicRegisterRangeRelationsHold world invariant.dynamicRegisterRangeRelations
        original.registers candidate.registers = true ∧
      dynamicStackRangeRelationsHold world invariant.dynamicStackRangeRelations
        original candidate = true ∧
      pairedStatePredicatesHold invariant.predicates original candidate = true)

theorem StateRel.importAddressesStaticValid
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    world.importAddressesStaticValid context = true := by
  exact related.2.2.2.1

theorem StateRel.importAddressStaticValid
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate)
    (binding : ImportAddressPair) (member : binding ∈ world.importAddresses) :
    binding.staticValid context = true := by
  have importsStatic := related.importAddressesStaticValid context world invariant
  simp only [RelationalWorld.importAddressesStaticValid, Bool.and_eq_true]
    at importsStatic
  exact List.all_eq_true.mp importsStatic.2 binding member

theorem StateRel.weakenInvariant
    (context : StaticProofContext) (world : RelationalWorld)
    (source target : StateInvariant) (original candidate : MachineState)
    (weakening : StateInvariantWeakening source target)
    (related : StateRel context world source original candidate) :
    StateRel context world target original candidate := by
  rcases related with
    ⟨worldValid, stackRangesValid, stackMemory, importsStatic, importsComplete,
      importsMemory, originalImmutable, candidateImmutable, core, trailing⟩
  rcases core with
    ⟨registers, bounds, separations, stackWindows, ordinaryMemory,
      dynamicMemory, undefinedValue, x87, flags, fsBase⟩
  rcases trailing with
    ⟨importRegisters, originRegisters, memoryOrigins, dynamicRegisters,
      dynamicStacks, predicates⟩
  have targetRegisters :
      registerRelationsHold context.originalPe.imageBase
        context.candidatePe.imageBase context.codeMap.entries.toList
        (context.relationalValueTargets world) target.registerRelations
        original.registers candidate.registers = true :=
    listAll_of_contains source.registerRelations target.registerRelations _
      weakening.registerRelations registers
  have targetBounds :
      boundsRelated target.bounds original.registers candidate.registers = true :=
    listAll_of_contains source.bounds target.bounds _ weakening.bounds bounds
  have targetSeparations :
      addressSeparationsRelated target.addressSeparations
        original.registers candidate.registers = true :=
    listAll_of_contains source.addressSeparations target.addressSeparations _
      weakening.addressSeparations separations
  have targetStackWindows :
      stackWindowsRelated world target.stackWindows
        original.registers candidate.registers = true :=
    stackWindowsRelated_of_weakening world source.stackWindows target.stackWindows
      original.registers candidate.registers weakening.stackWindows stackWindows
  have targetActiveRegisters :
      activeDynamicRegisterRangeRelationsHold context world
        target.dynamicRegisterRangeRelations original candidate = true :=
    listAll_of_contains source.dynamicRegisterRangeRelations
      target.dynamicRegisterRangeRelations _ weakening.dynamicRegisterRangeRelations
      dynamicMemory.active.registerRanges
  have targetActiveStacks :
      activeDynamicStackRangeRelationsHold context world
        target.dynamicStackRangeRelations original candidate = true :=
    listAll_of_contains source.dynamicStackRangeRelations
      target.dynamicStackRangeRelations _ weakening.dynamicStackRangeRelations
      dynamicMemory.active.stackRanges
  have targetFlags :
      flagsRelated target.flagBits original.eflags candidate.eflags = true :=
    listAll_of_contains source.flagBits target.flagBits _ weakening.flagBits flags
  have targetImportRegisters :
      importRegisterRelationsHold world target.importRegisterRelations
        original.registers candidate.registers = true :=
    listAll_of_contains source.importRegisterRelations target.importRegisterRelations _
      weakening.importRegisterRelations importRegisters
  have targetOriginRegisters :
      registerValueOriginRelationsHold context world
        target.registerValueOriginRelations original.registers
        candidate.registers = true :=
    listAll_of_contains source.registerValueOriginRelations
      target.registerValueOriginRelations _
      weakening.registerValueOriginRelations originRegisters
  have targetMemoryOrigins :
      memoryValueOriginRelationsHold context world
        target.memoryValueOriginRelations original candidate = true :=
    listAll_of_contains source.memoryValueOriginRelations
      target.memoryValueOriginRelations _
      weakening.memoryValueOriginRelations memoryOrigins
  have targetDynamicRegisters :
      dynamicRegisterRangeRelationsHold world target.dynamicRegisterRangeRelations
        original.registers candidate.registers = true :=
    listAll_of_contains source.dynamicRegisterRangeRelations
      target.dynamicRegisterRangeRelations _ weakening.dynamicRegisterRangeRelations
      dynamicRegisters
  have targetDynamicStacks :
      dynamicStackRangeRelationsHold world target.dynamicStackRangeRelations
        original candidate = true :=
    listAll_of_contains source.dynamicStackRangeRelations
      target.dynamicStackRangeRelations _ weakening.dynamicStackRangeRelations
      dynamicStacks
  have targetPredicates :
      pairedStatePredicatesHold target.predicates original candidate = true :=
    listAll_of_contains source.predicates target.predicates _ weakening.predicates
      predicates
  refine ⟨worldValid, stackRangesValid, stackMemory, importsStatic,
    importsComplete, importsMemory, originalImmutable, candidateImmutable, ?_, ?_⟩
  · refine ⟨targetRegisters, targetBounds, targetSeparations,
      targetStackWindows, ordinaryMemory, ?_, undefinedValue, x87, targetFlags,
      fsBase⟩
    exact {
      staticPointerSlots := dynamicMemory.staticPointerSlots
      staticWordSlots := dynamicMemory.staticWordSlots
      active := {
        registerRanges := targetActiveRegisters
        stackRanges := targetActiveStacks
      }
    }
  · exact ⟨targetImportRegisters, targetOriginRegisters, targetMemoryOrigins,
      targetDynamicRegisters, targetDynamicStacks, targetPredicates⟩

theorem StateRel.machineX87Related
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    MachineX87Related context world original candidate := by
  rcases related with ⟨_, _, _, _, _, _, _, _, core, _⟩
  exact core.2.2.2.2.2.2.2.1

theorem StateRel.stackWindowsHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    stackWindowsRelated world invariant.stackWindows
      original.registers candidate.registers = true := by
  rcases related with ⟨_, _, _, _, _, _, _, _, core, _⟩
  exact core.2.2.2.1

theorem StateRel.stackRangesValid
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    world.stackRangesValid context = true :=
  related.2.1

theorem StateRel.dynamicRegisterRangesHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    dynamicRegisterRangeRelationsHold world invariant.dynamicRegisterRangeRelations
      original.registers candidate.registers = true :=
  related.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem StateRel.dynamicStackRangesHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    dynamicStackRangeRelationsHold world invariant.dynamicStackRangeRelations
      original candidate = true :=
  related.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem StateRel.predicatesHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    pairedStatePredicatesHold invariant.predicates original candidate = true :=
  related.2.2.2.2.2.2.2.2.2.2.2.2.2.2

theorem StateRel.registerValueOriginsHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    registerValueOriginRelationsHold context world
      invariant.registerValueOriginRelations original.registers
      candidate.registers = true :=
  related.2.2.2.2.2.2.2.2.2.2.1

theorem StateRel.memoryValueOriginsHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    memoryValueOriginRelationsHold context world
      invariant.memoryValueOriginRelations original candidate = true :=
  related.2.2.2.2.2.2.2.2.2.2.2.1

theorem StateRel.exactMemoryRead
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (predicate : PairedStatePredicate) (read : PairedExactMemoryRead)
    (predicateMember : predicate ∈ invariant.predicates)
    (readMember : read ∈ predicate.exactMemoryReads)
    (related : StateRel context world invariant original candidate) :
    original.readX87Word (read.originalAddress.eval original) read.bytes =
      candidate.readX87Word (read.candidateAddress.eval candidate) read.bytes := by
  have predicateHolds := pairedStatePredicatesHold_member invariant.predicates
    predicate original candidate predicateMember
    (related.predicatesHold context world invariant original candidate)
  have readHolds := predicate.exactMemoryReadHolds read original candidate
    readMember predicateHolds
  simp only [PairedExactMemoryRead.holds, Bool.and_eq_true, beq_iff_eq] at readHolds
  exact readHolds.2

theorem StateRel.activeDynamicRegisterRangesHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    activeDynamicRegisterRangeRelationsHold context world
      invariant.dynamicRegisterRangeRelations original candidate = true := by
  rcases related with ⟨_, _, _, _, _, _, _, _, core, _⟩
  exact core.2.2.2.2.2.1.active.registerRanges

theorem StateRel.activeDynamicStackRangesHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    activeDynamicStackRangeRelationsHold context world
      invariant.dynamicStackRangeRelations original candidate = true := by
  rcases related with ⟨_, _, _, _, _, _, _, _, core, _⟩
  exact core.2.2.2.2.2.1.active.stackRanges

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
    (claim.relation.relation.impliesExact ||
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
  rcases supported with relationExactLike | ⟨relationRelated, offsetZero⟩
  · have registersEqual := RegisterValueRelation.holds_eq_of_impliesExact
      context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      claim.relation.relation _ _ relationExactLike relationHolds
    simp only [registerArgumentExpression, evalInputRegisterOffset]
    rw [registersEqual]
    exact wordRelated_self _ _ _ _ _
  · rw [relationRelated] at relationHolds
    simp only [RegisterValueRelation.holds] at relationHolds
    simpa [registerArgumentExpression, evalInputRegisterOffset, offsetZero] using
      relationHolds

theorem registerArgumentWordsEqual_of_checked_exactLike
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalExpression candidateExpression : Expr)
    (claim : RegisterArgumentClaim)
    (checked : claim.checked sourceInvariant originalExpression
      candidateExpression = true)
    (exactLike : claim.relation.relation.impliesExact = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalExpression.eval originalState = candidateExpression.eval candidateState := by
  simp only [RegisterArgumentClaim.checked, Bool.and_eq_true, Bool.or_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨relationMember, _supported⟩, originalExpressionExact⟩,
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
  have registersEqual := RegisterValueRelation.holds_eq_of_impliesExact
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    claim.relation.relation _ _ exactLike relationHolds
  rw [originalExpressionExact, candidateExpressionExact]
  simp [registerArgumentExpression, evalInputRegisterOffset, registersEqual]

theorem registerArgumentWordsEqual_of_checked_exact
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalExpression candidateExpression : Expr)
    (claim : RegisterArgumentClaim)
    (checked : claim.checked sourceInvariant originalExpression
      candidateExpression = true)
    (exact : claim.relation.relation = .exact)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalExpression.eval originalState = candidateExpression.eval candidateState := by
  apply registerArgumentWordsEqual_of_checked_exactLike context world sourceInvariant
    originalExpression candidateExpression claim checked
  · simpa [exact, RegisterValueRelation.impliesExact]
  · exact related

theorem StateRel.ordinaryMemoryRelation
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
  ordinaryMemoryRelated context world context.codeMap.entries.toList
      (context.relationalValueTargets world) original.memory candidate.memory := by
  rcases related with ⟨_, _, _, _, _, _, _, _, core, _⟩
  exact core.2.2.2.2.1

theorem StateRel.originalImmutableImageWordMemory
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    ImmutableImageWordMemory context.originalPe original.memory := by
  rcases related with ⟨_, _, _, _, _, _, originalImmutable, _, _, _⟩
  exact originalImmutable

theorem StateRel.candidateImmutableImageWordMemory
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    ImmutableImageWordMemory context.candidatePe candidate.memory := by
  rcases related with ⟨_, _, _, _, _, _, _, candidateImmutable, _, _⟩
  exact candidateImmutable

theorem StateRel.staticDynamicPointerSlotsMemoryHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    StaticDynamicPointerSlotsMemoryHold context world
      original.memory candidate.memory := by
  rcases related with ⟨_, _, _, _, _, _, _, _, core, _⟩
  exact core.2.2.2.2.2.1.staticPointerSlots

theorem StateRel.staticWordRelationSlotsMemoryHold
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (related : StateRel context world invariant original candidate) :
    StaticWordRelationSlotsMemoryHold context world
      original.memory candidate.memory := by
  rcases related with ⟨_, _, _, _, _, _, _, _, core, _⟩
  exact core.2.2.2.2.2.1.staticWordSlots

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

theorem StateRel.stackMemoryRead32BelowRelated
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (window : StackWindowPair) (amount : Nat)
    (related : StateRel context world invariant original candidate)
    (windowMember : window ∈ invariant.stackWindows)
    (amountAtLeastWord : 4 <= amount) (inside : amount <= window.bytesBelow)
    (aligned : amount % 4 = 0) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (Memory.read32 original.memory
        (original.registers.get window.originalRegister - BitVec.ofNat 32 amount))
      (Memory.read32 candidate.memory
        (candidate.registers.get window.candidateRegister - BitVec.ofNat 32 amount)) =
      true := by
  rcases related with
    ⟨_, rangesValid, stackMemory, _, _, _, _, _, relatedCore, _⟩
  have windowsRelated := relatedCore.2.2.2.1
  simp only [stackWindowsRelated, List.all_eq_true] at windowsRelated
  have windowHolds := windowsRelated window windowMember
  obtain ⟨location, originalAddress, candidateAddress⟩ :=
    pairedStackWordLocation_below_window_amount context world window
      original.registers candidate.registers rangesValid windowHolds amount
      amountAtLeastWord aligned inside
  have wordsRelated := stackMemory location.range location.rangeMember
    location.offset location.inside location.aligned
  rw [← location.originalAddressExact, ← location.candidateAddressExact,
    originalAddress, candidateAddress] at wordsRelated
  exact wordsRelated

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
  inputValueOriginRelations : List RegisterValueOriginRelation := []
  outputValueOriginRelations : List RegisterValueOriginRelation := []
  inputMemoryValueOriginRelations : List MemoryValueOriginRelation := []
  outputMemoryValueOriginRelations : List MemoryValueOriginRelation := []
  inputImportRelations : List ImportRegisterRelation := []
  outputImportRelations : List ImportRegisterRelation := []
  inputDynamicRangeRelations : List DynamicRegisterRangeRelation := []
  outputDynamicRangeRelations : List DynamicRegisterRangeRelation := []
  inputDynamicStackRangeRelations : List DynamicStackRangeRelation := []
  outputDynamicStackRangeRelations : List DynamicStackRangeRelation := []
  bounds : List RegisterBoundPair := []
  addressSeparations : List AddressSeparationPair := []
  stackWindows : List StackWindowPair := []
  predicates : List PairedStatePredicate := []
  targets : List CodeTargetPair
  values : List ValueTargetPair := []
  flagInputs : List Nat := [0, 2, 4, 6, 7, 10, 11]
  flagOutputs : List Nat := [0, 2, 4, 6, 7, 10, 11]
deriving Repr, DecidableEq

def RegionRelation.inputInvariant (region : RegionRelation) : StateInvariant := {
  registerRelations := region.inputRelations
  registerValueOriginRelations := region.inputValueOriginRelations
  memoryValueOriginRelations := region.inputMemoryValueOriginRelations
  importRegisterRelations := region.inputImportRelations
  dynamicRegisterRangeRelations := region.inputDynamicRangeRelations
  dynamicStackRangeRelations := region.inputDynamicStackRangeRelations
  flagBits := region.flagInputs
  bounds := region.bounds
  addressSeparations := region.addressSeparations
  stackWindows := region.stackWindows
  predicates := region.predicates
}

def RegionRelation.outputInvariant (region : RegionRelation) : StateInvariant := {
  registerRelations := region.outputRelations
  registerValueOriginRelations := region.outputValueOriginRelations
  memoryValueOriginRelations := region.outputMemoryValueOriginRelations
  importRegisterRelations := region.outputImportRelations
  dynamicRegisterRangeRelations := region.outputDynamicRangeRelations
  dynamicStackRangeRelations := region.outputDynamicStackRangeRelations
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

theorem behaviorRegistersEquivalent_of_eval_eq
    (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (region : RegionRelation)
    (identity : region.outputs.all
      (fun pair => pair.original == pair.candidate) = true)
    (evaluated : forall originalState candidateState,
      statesRelated originalImageBase candidateImageBase region.targets
        region.flagInputs region.bounds region.addressSeparations region.values
        region.inputs originalState candidateState ->
      evalNormalizedRegisters originalState originalBehavior.registers =
        evalNormalizedRegisters candidateState candidateBehavior.registers) :
    behaviorRegistersEquivalent originalImageBase candidateImageBase
      originalBehavior candidateBehavior region := by
  intro originalState candidateState related
  rw [evaluated originalState candidateState related]
  exact registersRelatedValues_self_of_identity originalImageBase candidateImageBase
    region.targets region.values region.outputs _ identity

theorem behaviorFlagsEquivalent_of_output_bits
    (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (region : RegionRelation)
    (evaluated : forall originalState candidateState,
      statesRelated originalImageBase candidateImageBase region.targets
        region.flagInputs region.bounds region.addressSeparations region.values
        region.inputs originalState candidateState ->
      forall bit, bit ∈ region.flagOutputs ->
        (evalNormalizedFlags originalState originalBehavior.flags).extractLsb' bit 1 =
          (evalNormalizedFlags candidateState candidateBehavior.flags).extractLsb' bit 1) :
    behaviorFlagsEquivalent originalImageBase candidateImageBase
      originalBehavior candidateBehavior region := by
  intro originalState candidateState related
  unfold flagsRelated
  simp only [List.all_eq_true, beq_iff_eq]
  intro bit member
  exact evaluated originalState candidateState related bit member

theorem normalizedBehaviorRegistersRelated_of_eval_eq
    (originalImageBase candidateImageBase : Nat)
    (behavior : NormalizedSymbolicBehavior) (region : RegionRelation)
    (identity : region.outputs.all
      (fun pair => pair.original == pair.candidate) = true)
    (evaluated : forall originalState candidateState,
      statesRelated originalImageBase candidateImageBase region.targets
        region.flagInputs region.bounds region.addressSeparations region.values
        region.inputs originalState candidateState ->
      (behavior.eval originalState).registers =
        (behavior.eval candidateState).registers) :
    forall originalState candidateState,
      statesRelated originalImageBase candidateImageBase region.targets
        region.flagInputs region.bounds region.addressSeparations region.values
        region.inputs originalState candidateState ->
      registersRelatedValues originalImageBase candidateImageBase region.targets
        region.values region.outputs (behavior.eval originalState).registers
        (behavior.eval candidateState).registers = true := by
  intro originalState candidateState related
  rw [evaluated originalState candidateState related]
  exact registersRelatedValues_self_of_identity originalImageBase candidateImageBase
    region.targets region.values region.outputs _ identity

theorem normalizedBehaviorFlagsRelated_of_output_bits
    (originalImageBase candidateImageBase : Nat)
    (behavior : NormalizedSymbolicBehavior) (region : RegionRelation)
    (evaluated : forall originalState candidateState,
      statesRelated originalImageBase candidateImageBase region.targets
        region.flagInputs region.bounds region.addressSeparations region.values
        region.inputs originalState candidateState ->
      forall bit, bit ∈ region.flagOutputs ->
        (behavior.eval originalState).eflags.extractLsb' bit 1 =
          (behavior.eval candidateState).eflags.extractLsb' bit 1) :
    forall originalState candidateState,
      statesRelated originalImageBase candidateImageBase region.targets
        region.flagInputs region.bounds region.addressSeparations region.values
        region.inputs originalState candidateState ->
      flagsRelated region.flagOutputs (behavior.eval originalState).eflags
        (behavior.eval candidateState).eflags = true := by
  intro originalState candidateState related
  unfold flagsRelated
  simp only [List.all_eq_true, beq_iff_eq]
  intro bit member
  exact evaluated originalState candidateState related bit member

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

end StageA.Relational
