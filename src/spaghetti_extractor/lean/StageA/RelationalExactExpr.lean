import StageA.RelationalInvariant

namespace StageA.Relational

open StageA.Formal

def immutableImageWordsEqual (context : StaticProofContext) (address : Nat) : Bool :=
  match readImmutableImageWord context.originalPe address 4,
      readImmutableImageWord context.candidatePe address 4 with
  | some original, some candidate => original == candidate
  | _, _ => false

theorem immutableConstantRead32_eval_equal
    (context : StaticProofContext) (address : Nat)
    (original candidate : MachineState)
    (originalImmutable : ImmutableImageWordMemory context.originalPe original.memory)
    (candidateImmutable : ImmutableImageWordMemory context.candidatePe candidate.memory)
    (checked : immutableImageWordsEqual context address = true) :
    (.read32 (.constant address) : Expr).eval original =
      (.read32 (.constant address) : Expr).eval candidate := by
  unfold immutableImageWordsEqual at checked
  cases originalResult : readImmutableImageWord context.originalPe address 4 with
  | none => simp [originalResult] at checked
  | some originalValue =>
      cases candidateResult : readImmutableImageWord context.candidatePe address 4 with
      | none => simp [originalResult, candidateResult] at checked
      | some candidateValue =>
          simp only [originalResult, candidateResult, beq_iff_eq] at checked
          have originalRead := ImmutableImageWordMemory.read32_of_checked
            context.originalPe original.memory address originalValue
            originalImmutable originalResult
          have candidateRead := ImmutableImageWordMemory.read32_of_checked
            context.candidatePe candidate.memory address candidateValue
            candidateImmutable candidateResult
          simp only [Expr.eval, machineStateRead32_eq_memoryRead32]
          rw [originalRead, candidateRead, checked]

theorem immutableConstantRead8_eval_equal
    (context : StaticProofContext) (address : Nat)
    (original candidate : MachineState)
    (originalImmutable : ImmutableImageWordMemory context.originalPe original.memory)
    (candidateImmutable : ImmutableImageWordMemory context.candidatePe candidate.memory)
    (checked : immutableImageWordsEqual context address = true) :
    (.read8 (.constant address) : Expr).eval original =
      (.read8 (.constant address) : Expr).eval candidate := by
  unfold immutableImageWordsEqual at checked
  cases originalResult : readImmutableImageWord context.originalPe address 4 with
  | none => simp [originalResult] at checked
  | some originalValue =>
      cases candidateResult : readImmutableImageWord context.candidatePe address 4 with
      | none => simp [originalResult, candidateResult] at checked
      | some candidateValue =>
          simp only [originalResult, candidateResult, beq_iff_eq] at checked
          have originalRead := ImmutableImageWordMemory.read32_of_checked
            context.originalPe original.memory address originalValue
            originalImmutable originalResult
          have candidateRead := ImmutableImageWordMemory.read32_of_checked
            context.candidatePe candidate.memory address candidateValue
            candidateImmutable candidateResult
          have readsEqual : Memory.read32 original.memory (BitVec.ofNat 32 address) =
              Memory.read32 candidate.memory (BitVec.ofNat 32 address) := by
            rw [originalRead, candidateRead, checked]
          have lowEqual := congrArg (fun value : Word =>
            BitVec.zeroExtend 32 (value.extractLsb' 0 8)) readsEqual
          simpa [Expr.eval] using lowEqual

def immutableImageWordsPairedEqual (context : StaticProofContext)
    (originalAddress candidateAddress : Nat) : Bool :=
  match readImmutableImageWord context.originalPe originalAddress 4,
      readImmutableImageWord context.candidatePe candidateAddress 4 with
  | some original, some candidate => original == candidate
  | _, _ => false

theorem immutablePairedConstantRead32_eval_equal
    (context : StaticProofContext) (originalAddress candidateAddress : Nat)
    (original candidate : MachineState)
    (originalImmutable : ImmutableImageWordMemory context.originalPe original.memory)
    (candidateImmutable : ImmutableImageWordMemory context.candidatePe candidate.memory)
    (checked : immutableImageWordsPairedEqual context
      originalAddress candidateAddress = true) :
    (.read32 (.constant originalAddress) : Expr).eval original =
      (.read32 (.constant candidateAddress) : Expr).eval candidate := by
  unfold immutableImageWordsPairedEqual at checked
  cases originalResult : readImmutableImageWord context.originalPe originalAddress 4 with
  | none => simp [originalResult] at checked
  | some originalValue =>
      cases candidateResult :
          readImmutableImageWord context.candidatePe candidateAddress 4 with
      | none => simp [originalResult, candidateResult] at checked
      | some candidateValue =>
          simp only [originalResult, candidateResult, beq_iff_eq] at checked
          have originalRead := ImmutableImageWordMemory.read32_of_checked
            context.originalPe original.memory originalAddress originalValue
            originalImmutable originalResult
          have candidateRead := ImmutableImageWordMemory.read32_of_checked
            context.candidatePe candidate.memory candidateAddress candidateValue
            candidateImmutable candidateResult
          simp only [Expr.eval, machineStateRead32_eq_memoryRead32]
          rw [originalRead, candidateRead, checked]

theorem immutablePairedConstantRead8_eval_equal
    (context : StaticProofContext) (originalAddress candidateAddress : Nat)
    (original candidate : MachineState)
    (originalImmutable : ImmutableImageWordMemory context.originalPe original.memory)
    (candidateImmutable : ImmutableImageWordMemory context.candidatePe candidate.memory)
    (checked : immutableImageWordsPairedEqual context
      originalAddress candidateAddress = true) :
    (.read8 (.constant originalAddress) : Expr).eval original =
      (.read8 (.constant candidateAddress) : Expr).eval candidate := by
  have wordsEqual := immutablePairedConstantRead32_eval_equal context
    originalAddress candidateAddress original candidate originalImmutable
    candidateImmutable checked
  have lowEqual := congrArg (fun value : Word =>
    BitVec.zeroExtend 32 (value.extractLsb' 0 8)) wordsEqual
  simpa [Expr.eval, machineStateRead32_eq_memoryRead32] using lowEqual

theorem MachineState.readX87Word_four_extractLsb (state : MachineState)
    (address : Word) :
    (state.readX87Word address 4).extractLsb' 0 32 = state.read32 address := by
  apply BitVec.eq_of_getLsbD_eq
  intro index
  by_cases below8 : index < 8
  · have below16 : index < 16 := by omega
    have below24 : index < 24 := by omega
    have below32 : index < 32 := by omega
    have below80 : index < 80 := by omega
    simp [MachineState.readX87Word, MachineState.read32, List.range_succ,
      below8, below16, below24, below32, below80]
  by_cases below16 : index < 16
  · have atLeast8 : 8 ≤ index := by omega
    have below24 : index < 24 := by omega
    have below32 : index < 32 := by omega
    have below80 : index < 80 := by omega
    simp [MachineState.readX87Word, MachineState.read32, List.range_succ,
      BitVec.getLsbD_of_ge, below8, below16, below24, below32, below80,
      atLeast8]
  by_cases below24 : index < 24
  · have atLeast16 : 16 ≤ index := by omega
    have atLeast8 : 8 ≤ index := by omega
    have byte1Past : 8 ≤ index - 8 := by omega
    have below32 : index < 32 := by omega
    have below80 : index < 80 := by omega
    simp [MachineState.readX87Word, MachineState.read32, List.range_succ,
      BitVec.getLsbD_of_ge, below8, below16, below24, below32, below80,
      atLeast8, atLeast16, byte1Past]
  by_cases below32 : index < 32
  · have atLeast24 : 24 ≤ index := by omega
    have atLeast8 : 8 ≤ index := by omega
    have byte1Past : 8 ≤ index - 8 := by omega
    have byte2Past : 8 ≤ index - 16 := by omega
    have below80 : index < 80 := by omega
    simp [MachineState.readX87Word, MachineState.read32, List.range_succ,
      BitVec.getLsbD_of_ge, below8, below16, below24, below32, below80,
      atLeast8, atLeast24, byte1Past, byte2Past]
  · simp [BitVec.getLsbD_of_ge, below32]

def exactStaticWordSlotAddresses (context : StaticProofContext)
    (originalAddress candidateAddress : Nat) : Bool :=
  context.staticWordRelationSlots.any fun slot =>
    slot.originalAddress == BitVec.ofNat 32 originalAddress &&
      slot.candidateAddress == BitVec.ofNat 32 candidateAddress &&
      slot.relation == .exact

theorem exactStaticWordSlotRead32_eval_equal
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (originalAddress candidateAddress : Nat)
    (checked : exactStaticWordSlotAddresses context
      originalAddress candidateAddress = true)
    (related : StateRel context world invariant original candidate) :
    (.read32 (.constant originalAddress) : Expr).eval original =
      (.read32 (.constant candidateAddress) : Expr).eval candidate := by
  simp only [exactStaticWordSlotAddresses, List.any_eq_true] at checked
  rcases checked with ⟨slot, member, checks⟩
  simp only [Bool.and_eq_true, beq_iff_eq] at checks
  rcases checks with ⟨⟨originalAddressExact, candidateAddressExact⟩, relationExact⟩
  have slotsHold := StateRel.staticWordRelationSlotsMemoryHold
    context world invariant original candidate related
  have slotHolds := slotsHold slot member
  simp only [StaticWordRelationSlotPair.memoryHolds] at slotHolds
  rw [relationExact] at slotHolds
  simp only [StaticWordRelationKind.holds, beq_iff_eq] at slotHolds
  simp only [Expr.eval, machineStateRead32_eq_memoryRead32]
  rw [← originalAddressExact, ← candidateAddressExact]
  exact slotHolds

theorem exactStaticWordSlotRead8_eval_equal
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (originalAddress candidateAddress : Nat)
    (checked : exactStaticWordSlotAddresses context
      originalAddress candidateAddress = true)
    (related : StateRel context world invariant original candidate) :
    (.read8 (.constant originalAddress) : Expr).eval original =
      (.read8 (.constant candidateAddress) : Expr).eval candidate := by
  have wordsEqual := exactStaticWordSlotRead32_eval_equal context world invariant
    original candidate originalAddress candidateAddress checked related
  have lowEqual := congrArg (fun value : Word =>
    BitVec.zeroExtend 32 (value.extractLsb' 0 8)) wordsEqual
  simpa [Expr.eval, machineStateRead32_eq_memoryRead32] using lowEqual

def _root_.StageA.Formal.Expr.constantValue : Expr → Option Nat
  | .constant value => some value
  | _ => none

theorem _root_.StageA.Formal.Expr.eq_constant_of_constantValue
    (expression : Expr) (value : Nat)
    (checked : expression.constantValue = some value) :
    expression = .constant value := by
  cases expression <;> simp_all [Expr.constantValue]

def pairedConstantReadAddresses (context : StaticProofContext)
    (original candidate : Expr) : Bool :=
  match original.constantValue, candidate.constantValue with
  | some originalAddress, some candidateAddress =>
      immutableImageWordsPairedEqual context originalAddress candidateAddress ||
        exactStaticWordSlotAddresses context originalAddress candidateAddress
  | _, _ => false

theorem pairedConstantRead32_eval_equal
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (originalAddress candidateAddress : Expr)
    (checked : pairedConstantReadAddresses context
      originalAddress candidateAddress = true)
    (related : StateRel context world invariant original candidate) :
    (.read32 originalAddress : Expr).eval original =
      (.read32 candidateAddress : Expr).eval candidate := by
  unfold pairedConstantReadAddresses at checked
  cases originalResult : originalAddress.constantValue with
  | none => simp [originalResult] at checked
  | some originalValue =>
    cases candidateResult : candidateAddress.constantValue with
    | none => simp [originalResult, candidateResult] at checked
    | some candidateValue =>
      simp only [originalResult, candidateResult, Bool.or_eq_true] at checked
      have originalExact := Expr.eq_constant_of_constantValue
        originalAddress originalValue originalResult
      have candidateExact := Expr.eq_constant_of_constantValue
        candidateAddress candidateValue candidateResult
      rw [originalExact, candidateExact]
      rcases checked with immutable | slot
      · exact immutablePairedConstantRead32_eval_equal context _ _ original candidate
          (StateRel.originalImmutableImageWordMemory context world invariant
            original candidate related)
          (StateRel.candidateImmutableImageWordMemory context world invariant
            original candidate related) immutable
      · exact exactStaticWordSlotRead32_eval_equal context world invariant
          original candidate _ _ slot related

theorem pairedConstantRead8_eval_equal
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (originalAddress candidateAddress : Expr)
    (checked : pairedConstantReadAddresses context
      originalAddress candidateAddress = true)
    (related : StateRel context world invariant original candidate) :
    (.read8 originalAddress : Expr).eval original =
      (.read8 candidateAddress : Expr).eval candidate := by
  unfold pairedConstantReadAddresses at checked
  cases originalResult : originalAddress.constantValue with
  | none => simp [originalResult] at checked
  | some originalValue =>
    cases candidateResult : candidateAddress.constantValue with
    | none => simp [originalResult, candidateResult] at checked
    | some candidateValue =>
      simp only [originalResult, candidateResult, Bool.or_eq_true] at checked
      have originalExact := Expr.eq_constant_of_constantValue
        originalAddress originalValue originalResult
      have candidateExact := Expr.eq_constant_of_constantValue
        candidateAddress candidateValue candidateResult
      rw [originalExact, candidateExact]
      rcases checked with immutable | slot
      · exact immutablePairedConstantRead8_eval_equal context _ _ original candidate
          (StateRel.originalImmutableImageWordMemory context world invariant
            original candidate related)
          (StateRel.candidateImmutableImageWordMemory context world invariant
            original candidate related) immutable
      · exact exactStaticWordSlotRead8_eval_equal context world invariant
          original candidate _ _ slot related

def _root_.StageA.Formal.Expr.exactInputsOnly
    (context : StaticProofContext) (invariant : StateInvariant) : Expr -> Bool
  | .inputReg register => exactIdentityRegister invariant.registerRelations register
  | .inputFlagValue bit => invariant.flagBits.contains bit
  | .inputFsBase | .inputX87Control | .inputX87Status | .constant _ | .undefined _ => true
  | .add left right | .sub left right | .bitAnd left right | .bitXor left right |
      .shiftLeftBy left right | .shiftRightBy left right |
      .shiftArithmeticRightBy left right | .bitOr left right |
      .unsignedLessValue left right | .multiply left right |
      .multiplyHighUnsigned left right | .multiplyHighSigned left right =>
      left.exactInputsOnly context invariant && right.exactInputsOnly context invariant
  | .bitNot value | .extractByte value _ | .shiftLeft value _ | .shiftRight value _ |
      .bitValue value _ | .lowestSetBit value | .highestSetBit value =>
      value.exactInputsOnly context invariant
  | .ifEqual left right thenValue elseValue =>
      left.exactInputsOnly context invariant && right.exactInputsOnly context invariant &&
        thenValue.exactInputsOnly context invariant &&
        elseValue.exactInputsOnly context invariant
  | .divideQuotient high low divisor | .divideRemainder high low divisor |
      .divisionValidValue high low divisor =>
      high.exactInputsOnly context invariant && low.exactInputsOnly context invariant &&
        divisor.exactInputsOnly context invariant
  | .read8 (.constant address) | .read32 (.constant address) =>
      immutableImageWordsEqual context address
  | .read8 _ | .read32 _ | .read8AfterWrite _ _ _ _ | .x87Part _ _ |
      .x87CompareBit _ _ _ _ | .x87ExamineStatus _ _ => false

theorem _root_.StageA.Formal.Expr.eval_eq_of_exactInputsOnly
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (expression : Expr) (checked : expression.exactInputsOnly context invariant = true)
    (related : StateRel context world invariant original candidate) :
    expression.eval original = expression.eval candidate := by
  rcases related with
    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, originalImmutable, candidateImmutable,
      relatedCore, _importAndDynamicRegisters⟩
  rcases relatedCore with
    ⟨inputRegisters, _inputBounds, _inputSeparations, _inputStackWindows,
      _inputMemory, _inputDynamicMemory, inputUndefined, inputX87, inputFlags,
      inputFsBase⟩
  have inputLegacyX87 : original.x87 = candidate.x87 := inputX87.1
  have exactRegister : ∀ register,
      exactIdentityRegister invariant.registerRelations register = true →
        original.registers.get register = candidate.registers.get register := by
    intro register exact
    exact registerRelationsHold_exact_identity
      context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      invariant.registerRelations original.registers candidate.registers register
      inputRegisters exact
  have exactFlag : ∀ bit, invariant.flagBits.contains bit = true →
      original.eflags.extractLsb' bit 1 = candidate.eflags.extractLsb' bit 1 := by
    intro bit contains
    exact flagsRelated_of_contains invariant.flagBits original.eflags candidate.eflags
      inputFlags contains
  have evalAll : ∀ value : Expr, value.exactInputsOnly context invariant = true →
      value.eval original = value.eval candidate := by
    intro value
    apply Expr.rec
      (motive_1 := fun item => item.exactInputsOnly context invariant = true →
        item.eval original = item.eval candidate)
      (motive_2 := fun _ => True)
    case read32 =>
      intro address _ safe
      cases address <;> simp_all [Expr.exactInputsOnly]
      exact immutableConstantRead32_eval_equal context _ original candidate
        originalImmutable candidateImmutable safe
    case read8 =>
      intro address _ safe
      cases address <;> simp_all [Expr.exactInputsOnly]
      exact immutableConstantRead8_eval_equal context _ original candidate
        originalImmutable candidateImmutable safe
    all_goals simp_all [Expr.exactInputsOnly, Expr.eval, Bool.and_eq_true]
  exact evalAll expression checked

def _root_.StageA.Formal.Expr.pairedExactInputsOnly
    (context : StaticProofContext) (invariant : StateInvariant) : Expr → Expr → Bool
  | .inputReg original, .inputReg candidate =>
      exactRegisterPair invariant.registerRelations original candidate
  | .inputFlagValue original, .inputFlagValue candidate =>
      original == candidate && invariant.flagBits.contains original
  | .inputFsBase, .inputFsBase | .inputX87Control, .inputX87Control |
      .inputX87Status, .inputX87Status => true
  | .constant original, .constant candidate => original == candidate
  | .add originalLeft originalRight, .add candidateLeft candidateRight |
      .sub originalLeft originalRight, .sub candidateLeft candidateRight |
      .bitAnd originalLeft originalRight, .bitAnd candidateLeft candidateRight |
      .bitXor originalLeft originalRight, .bitXor candidateLeft candidateRight |
      .shiftLeftBy originalLeft originalRight, .shiftLeftBy candidateLeft candidateRight |
      .shiftRightBy originalLeft originalRight, .shiftRightBy candidateLeft candidateRight |
      .shiftArithmeticRightBy originalLeft originalRight,
        .shiftArithmeticRightBy candidateLeft candidateRight |
      .bitOr originalLeft originalRight, .bitOr candidateLeft candidateRight |
      .unsignedLessValue originalLeft originalRight,
        .unsignedLessValue candidateLeft candidateRight |
      .multiply originalLeft originalRight, .multiply candidateLeft candidateRight |
      .multiplyHighUnsigned originalLeft originalRight,
        .multiplyHighUnsigned candidateLeft candidateRight |
      .multiplyHighSigned originalLeft originalRight,
        .multiplyHighSigned candidateLeft candidateRight =>
      originalLeft.pairedExactInputsOnly context invariant candidateLeft &&
        originalRight.pairedExactInputsOnly context invariant candidateRight
  | .bitNot original, .bitNot candidate |
      .lowestSetBit original, .lowestSetBit candidate |
      .highestSetBit original, .highestSetBit candidate =>
      original.pairedExactInputsOnly context invariant candidate
  | .read8 originalAddress, .read8 candidateAddress |
      .read32 originalAddress, .read32 candidateAddress =>
      pairedConstantReadAddresses context originalAddress candidateAddress
  | .extractByte original originalIndex, .extractByte candidate candidateIndex |
      .shiftLeft original originalIndex, .shiftLeft candidate candidateIndex |
      .shiftRight original originalIndex, .shiftRight candidate candidateIndex |
      .bitValue original originalIndex, .bitValue candidate candidateIndex =>
      originalIndex == candidateIndex &&
        original.pairedExactInputsOnly context invariant candidate
  | .ifEqual originalLeft originalRight originalThen originalElse,
      .ifEqual candidateLeft candidateRight candidateThen candidateElse =>
      originalLeft.pairedExactInputsOnly context invariant candidateLeft &&
        originalRight.pairedExactInputsOnly context invariant candidateRight &&
        originalThen.pairedExactInputsOnly context invariant candidateThen &&
        originalElse.pairedExactInputsOnly context invariant candidateElse
  | .divideQuotient originalHigh originalLow originalDivisor,
      .divideQuotient candidateHigh candidateLow candidateDivisor |
      .divideRemainder originalHigh originalLow originalDivisor,
        .divideRemainder candidateHigh candidateLow candidateDivisor |
      .divisionValidValue originalHigh originalLow originalDivisor,
        .divisionValidValue candidateHigh candidateLow candidateDivisor =>
      originalHigh.pairedExactInputsOnly context invariant candidateHigh &&
        originalLow.pairedExactInputsOnly context invariant candidateLow &&
        originalDivisor.pairedExactInputsOnly context invariant candidateDivisor
  | .undefined original, .undefined candidate => original == candidate
  | original, candidate =>
      original == candidate && original.exactInputsOnly context invariant

/-
The direct boolean induction is retained as design history while generated
claims migrate to the explicit witness tree below.
theorem _root_.StageA.Formal.Expr.eval_eq_of_pairedExactInputsOnly
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (originalExpression candidateExpression : Expr)
    (checked : originalExpression.pairedExactInputsOnly context invariant
      candidateExpression = true)
    (related : StateRel context world invariant original candidate) :
    originalExpression.eval original = candidateExpression.eval candidate :=
  match originalExpression, candidateExpression with
  | .inputReg originalRegister, .inputReg candidateRegister => by
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      have inputRegisters := relatedCore.1
      exact registerRelationsHold_exact_pair
        context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        invariant.registerRelations original.registers candidate.registers
        originalRegister candidateRegister inputRegisters checked
  | .inputFlagValue originalBit, .inputFlagValue candidateBit => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with ⟨bitExact, member⟩
      subst candidateBit
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      have flagsExact := flagsRelated_of_contains invariant.flagBits
        original.eflags candidate.eflags relatedCore.2.2.2.2.2.2.2.2.1 member
      simp only [Expr.eval]
      rw [flagsExact]
  | .inputFsBase, .inputFsBase => by
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      simpa [Expr.eval] using relatedCore.2.2.2.2.2.2.2.2.2
  | .inputX87Control, .inputX87Control => by
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      simpa [Expr.eval] using congrArg (fun state : X87MachineState =>
        BitVec.zeroExtend 32 state.control)
        relatedCore.2.2.2.2.2.2.2.1.1
  | .inputX87Status, .inputX87Status => by
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      simpa [Expr.eval] using congrArg (fun state : X87MachineState =>
        BitVec.zeroExtend 32 state.status)
        relatedCore.2.2.2.2.2.2.2.1.1
  | .constant originalValue, .constant candidateValue => by
      simp only [Expr.pairedExactInputsOnly, beq_iff_eq] at checked
      subst candidateValue
      rfl
  | .add originalLeft originalRight, .add candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .sub originalLeft originalRight, .sub candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .bitAnd originalLeft originalRight, .bitAnd candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .bitXor originalLeft originalRight, .bitXor candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .shiftLeftBy originalLeft originalRight,
      .shiftLeftBy candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .shiftRightBy originalLeft originalRight,
      .shiftRightBy candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .shiftArithmeticRightBy originalLeft originalRight,
      .shiftArithmeticRightBy candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .bitOr originalLeft originalRight, .bitOr candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .unsignedLessValue originalLeft originalRight,
      .unsignedLessValue candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .multiply originalLeft originalRight, .multiply candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .multiplyHighUnsigned originalLeft originalRight,
      .multiplyHighUnsigned candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .multiplyHighSigned originalLeft originalRight,
      .multiplyHighSigned candidateLeft candidateRight => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft checked.1 related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight checked.2 related]
  | .bitNot originalValue, .bitNot candidateValue => by
      simp only [Expr.pairedExactInputsOnly, Expr.eval] at checked ⊢
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
        originalValue candidateValue checked related]
  | .lowestSetBit originalValue, .lowestSetBit candidateValue => by
      simp only [Expr.pairedExactInputsOnly, Expr.eval] at checked ⊢
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
        originalValue candidateValue checked related]
  | .highestSetBit originalValue, .highestSetBit candidateValue => by
      simp only [Expr.pairedExactInputsOnly, Expr.eval] at checked ⊢
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
        originalValue candidateValue checked related]
  | .read8 originalAddress, .read8 candidateAddress =>
      pairedConstantRead8_eval_equal context world invariant original candidate
        originalAddress candidateAddress checked related
  | .read32 originalAddress, .read32 candidateAddress =>
      pairedConstantRead32_eval_equal context world invariant original candidate
        originalAddress candidateAddress checked related
  | .extractByte originalValue originalIndex,
      .extractByte candidateValue candidateIndex => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with ⟨indexExact, valueExact⟩
      subst candidateIndex
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
        originalValue candidateValue valueExact related]
  | .shiftLeft originalValue originalAmount,
      .shiftLeft candidateValue candidateAmount => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with ⟨amountExact, valueExact⟩
      subst candidateAmount
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
        originalValue candidateValue valueExact related]
  | .shiftRight originalValue originalAmount,
      .shiftRight candidateValue candidateAmount => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with ⟨amountExact, valueExact⟩
      subst candidateAmount
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
        originalValue candidateValue valueExact related]
  | .bitValue originalValue originalIndex,
      .bitValue candidateValue candidateIndex => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with ⟨indexExact, valueExact⟩
      subst candidateIndex
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
        originalValue candidateValue valueExact related]
  | .ifEqual originalLeft originalRight originalThen originalElse,
      .ifEqual candidateLeft candidateRight candidateThen candidateElse => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      rcases checked with ⟨⟨⟨leftExact, rightExact⟩, thenExact⟩, elseExact⟩
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLeft candidateLeft leftExact related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalRight candidateRight rightExact related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalThen candidateThen thenExact related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalElse candidateElse elseExact related]
  | .divideQuotient originalHigh originalLow originalDivisor,
      .divideQuotient candidateHigh candidateLow candidateDivisor => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      rcases checked with ⟨⟨highExact, lowExact⟩, divisorExact⟩
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalHigh candidateHigh highExact related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLow candidateLow lowExact related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalDivisor candidateDivisor divisorExact related]
  | .divideRemainder originalHigh originalLow originalDivisor,
      .divideRemainder candidateHigh candidateLow candidateDivisor => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      rcases checked with ⟨⟨highExact, lowExact⟩, divisorExact⟩
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalHigh candidateHigh highExact related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLow candidateLow lowExact related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalDivisor candidateDivisor divisorExact related]
  | .divisionValidValue originalHigh originalLow originalDivisor,
      .divisionValidValue candidateHigh candidateLow candidateDivisor => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true] at checked
      rcases checked with ⟨⟨highExact, lowExact⟩, divisorExact⟩
      simp only [Expr.eval]
      rw [eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalHigh candidateHigh highExact related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalLow candidateLow lowExact related,
        eval_eq_of_pairedExactInputsOnly context world invariant original candidate
          originalDivisor candidateDivisor divisorExact related]
  | .undefined originalSlot, .undefined candidateSlot => by
      simp only [Expr.pairedExactInputsOnly, beq_iff_eq] at checked
      subst candidateSlot
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      simp only [Expr.eval]
      rw [relatedCore.2.2.2.2.2.2.1]
  | originalValue, candidateValue => by
      simp only [Expr.pairedExactInputsOnly, Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with ⟨expressionsExact, exactInputs⟩
      rw [← expressionsExact]
      exact Expr.eval_eq_of_exactInputsOnly context world invariant original candidate
        originalValue exactInputs related
termination_by originalExpression
-/

inductive PairedExactExprSide where
  | original
  | candidate
deriving Repr, DecidableEq

inductive PairedExactBinaryOp where
  | add | sub | bitAnd | bitXor | shiftLeftBy | shiftRightBy
  | shiftArithmeticRightBy | bitOr | unsignedLessValue | multiply
  | multiplyHighUnsigned | multiplyHighSigned
deriving Repr, DecidableEq

def PairedExactBinaryOp.expression
    (operation : PairedExactBinaryOp) (left right : Expr) : Expr :=
  match operation with
  | .add => .add left right
  | .sub => .sub left right
  | .bitAnd => .bitAnd left right
  | .bitXor => .bitXor left right
  | .shiftLeftBy => .shiftLeftBy left right
  | .shiftRightBy => .shiftRightBy left right
  | .shiftArithmeticRightBy => .shiftArithmeticRightBy left right
  | .bitOr => .bitOr left right
  | .unsignedLessValue => .unsignedLessValue left right
  | .multiply => .multiply left right
  | .multiplyHighUnsigned => .multiplyHighUnsigned left right
  | .multiplyHighSigned => .multiplyHighSigned left right

def PairedExactBinaryOp.value
    (operation : PairedExactBinaryOp) (left right : Word) : Word :=
  match operation with
  | .add => left + right
  | .sub => left - right
  | .bitAnd => left &&& right
  | .bitXor => left ^^^ right
  | .shiftLeftBy => left.shiftLeft (right.toNat % 32)
  | .shiftRightBy => left.ushiftRight (right.toNat % 32)
  | .shiftArithmeticRightBy => left.sshiftRight (right.toNat % 32)
  | .bitOr => left ||| right
  | .unsignedLessValue =>
      if left < right then BitVec.ofNat 32 1 else BitVec.ofNat 32 0
  | .multiply => left * right
  | .multiplyHighUnsigned =>
      let product := BitVec.zeroExtend 64 left * BitVec.zeroExtend 64 right
      product.extractLsb' 32 32
  | .multiplyHighSigned =>
      let product := BitVec.signExtend 64 left * BitVec.signExtend 64 right
      product.extractLsb' 32 32

inductive PairedExactUnaryOp where
  | bitNot | lowestSetBit | highestSetBit
deriving Repr, DecidableEq

def PairedExactUnaryOp.expression
    (operation : PairedExactUnaryOp) (value : Expr) : Expr :=
  match operation with
  | .bitNot => .bitNot value
  | .lowestSetBit => .lowestSetBit value
  | .highestSetBit => .highestSetBit value

def PairedExactUnaryOp.value
    (operation : PairedExactUnaryOp) (value : Word) : Word :=
  match operation with
  | .bitNot => ~~~value
  | .lowestSetBit => lowestSetBitValue value 0 32
  | .highestSetBit => highestSetBitValue value 31 32

inductive PairedExactIndexedOp where
  | extractByte | shiftLeft | shiftRight | bitValue
deriving Repr, DecidableEq

def PairedExactIndexedOp.expression
    (operation : PairedExactIndexedOp) (value : Expr) (index : Nat) : Expr :=
  match operation with
  | .extractByte => .extractByte value index
  | .shiftLeft => .shiftLeft value index
  | .shiftRight => .shiftRight value index
  | .bitValue => .bitValue value index

def PairedExactIndexedOp.value
    (operation : PairedExactIndexedOp) (value : Word) (index : Nat) : Word :=
  match operation with
  | .extractByte => BitVec.zeroExtend 32 (value.extractLsb' (index * 8) 8)
  | .shiftLeft => value.shiftLeft index
  | .shiftRight => value.ushiftRight index
  | .bitValue =>
      if Nat.testBit value.toNat index then BitVec.ofNat 32 1
      else BitVec.ofNat 32 0

inductive PairedExactTernaryOp where
  | divideQuotient | divideRemainder | divisionValidValue
deriving Repr, DecidableEq

def PairedExactTernaryOp.expression
    (operation : PairedExactTernaryOp) (high low divisor : Expr) : Expr :=
  match operation with
  | .divideQuotient => .divideQuotient high low divisor
  | .divideRemainder => .divideRemainder high low divisor
  | .divisionValidValue => .divisionValidValue high low divisor

inductive PairedStaticExprWitness where
  | constant (original candidate : Nat)
  | fixedInputReg (original candidate : Reg) (value : Nat)
  | binary (operation : PairedExactBinaryOp)
      (left right : PairedStaticExprWitness)
  | unary (operation : PairedExactUnaryOp) (value : PairedStaticExprWitness)
  | read32 (originalAddress candidateAddress : Nat)
  | indexed (operation : PairedExactIndexedOp) (index : Nat)
      (value : PairedStaticExprWitness)
deriving Repr, DecidableEq

def PairedStaticExprWitness.expression
    (side : PairedExactExprSide) : PairedStaticExprWitness → Expr
  | .constant original candidate =>
      .constant (match side with | .original => original | .candidate => candidate)
  | .fixedInputReg original candidate _ =>
      .inputReg (match side with | .original => original | .candidate => candidate)
  | .binary operation left right =>
      operation.expression (left.expression side) (right.expression side)
  | .unary operation value => operation.expression (value.expression side)
  | .read32 originalAddress candidateAddress =>
      .read32 (.constant (match side with
        | .original => originalAddress | .candidate => candidateAddress))
  | .indexed operation index value =>
      operation.expression (value.expression side) index

def PairedStaticExprWitness.value
    (context : StaticProofContext) (side : PairedExactExprSide) :
    PairedStaticExprWitness → Option Word
  | .constant original candidate => some (BitVec.ofNat 32
      (match side with | .original => original | .candidate => candidate))
  | .fixedInputReg _ _ value => some (BitVec.ofNat 32 value)
  | .binary operation left right => do
      let leftValue ← left.value context side
      let rightValue ← right.value context side
      some (operation.value leftValue rightValue)
  | .unary operation value => do
      let result ← value.value context side
      some (operation.value result)
  | .read32 originalAddress candidateAddress =>
      match side with
      | .original =>
          (readImmutableImageWord context.originalPe originalAddress 4).map
            (BitVec.ofNat 32)
      | .candidate =>
          (readImmutableImageWord context.candidatePe candidateAddress 4).map
            (BitVec.ofNat 32)
  | .indexed operation index value => do
      let result ← value.value context side
      some (operation.value result index)

def fixedRegisterPair (relations : List RegisterRelationPair)
    (originalRegister candidateRegister : Reg) (value : Nat) : Bool :=
  relations.any fun relation =>
    relation.original == originalRegister && relation.candidate == candidateRegister &&
      relation.relation == .fixedWord value

theorem registerRelationsHold_fixed_pair
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (relations : List RegisterRelationPair) (original candidate : PureState)
    (originalRegister candidateRegister : Reg) (value : Nat)
    (related : registerRelationsHold originalImageBase candidateImageBase targets values
      relations original candidate = true)
    (fixed : fixedRegisterPair relations originalRegister candidateRegister value = true) :
    original.get originalRegister = BitVec.ofNat 32 value ∧
      candidate.get candidateRegister = BitVec.ofNat 32 value := by
  simp only [registerRelationsHold, List.all_eq_true] at related
  simp only [fixedRegisterPair, List.any_eq_true] at fixed
  rcases fixed with ⟨relation, member, checks⟩
  have holds := related relation member
  rcases relation with ⟨relationOriginal, relationCandidate, relationKind⟩
  simp only [Bool.and_eq_true, beq_iff_eq] at checks
  rcases checks with
    ⟨⟨originalExact, candidateExact⟩, relationExact⟩
  subst relationOriginal
  subst relationCandidate
  subst relationKind
  simpa [RegisterValueRelation.holds] using holds

def PairedStaticExprWitness.checked (invariant : StateInvariant) :
    PairedStaticExprWitness → Bool
  | .constant _ _ | .read32 _ _ => true
  | .fixedInputReg original candidate value =>
      fixedRegisterPair invariant.registerRelations original candidate value
  | .binary _ left right => left.checked invariant && right.checked invariant
  | .unary _ value | .indexed _ _ value => value.checked invariant

theorem PairedStaticExprWitness.original_eval_eq_value
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (witness : PairedStaticExprWitness) (value : Word)
    (related : StateRel context world invariant original candidate)
    (checked : witness.checked invariant = true)
    (evaluates : witness.value context .original = some value) :
    (witness.expression .original).eval original = value := by
  induction witness generalizing value with
  | constant original candidate =>
      simpa [PairedStaticExprWitness.value,
        PairedStaticExprWitness.expression, Expr.eval] using evaluates
  | fixedInputReg originalRegister candidateRegister fixedValue =>
      simp only [PairedStaticExprWitness.value, Option.some.injEq] at evaluates
      subst value
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      have fixed := registerRelationsHold_fixed_pair
        context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        invariant.registerRelations original.registers candidate.registers
        originalRegister candidateRegister fixedValue relatedCore.1 checked
      simpa [PairedStaticExprWitness.value,
        PairedStaticExprWitness.expression, Expr.eval] using fixed.1
  | binary operation left right leftSound rightSound =>
      simp only [PairedStaticExprWitness.checked, Bool.and_eq_true] at checked
      cases leftResult : left.value context .original with
      | none => simp [PairedStaticExprWitness.value, leftResult] at evaluates
      | some leftValue =>
          cases rightResult : right.value context .original with
          | none =>
              simp [PairedStaticExprWitness.value, leftResult, rightResult] at evaluates
          | some rightValue =>
              simp [PairedStaticExprWitness.value, leftResult, rightResult] at evaluates
              subst value
              have leftEvaluates := leftSound leftValue checked.1 leftResult
              have rightEvaluates := rightSound rightValue checked.2 rightResult
              cases operation <;> simp_all [PairedStaticExprWitness.expression,
                PairedExactBinaryOp.expression, PairedExactBinaryOp.value, Expr.eval]
  | unary operation operand operandSound =>
      simp only [PairedStaticExprWitness.checked] at checked
      cases operandResult : operand.value context .original with
      | none => simp [PairedStaticExprWitness.value, operandResult] at evaluates
      | some operandValue =>
          simp [PairedStaticExprWitness.value, operandResult] at evaluates
          subst value
          have operandEvaluates := operandSound operandValue checked operandResult
          cases operation <;> simp_all [PairedStaticExprWitness.expression,
            PairedExactUnaryOp.expression, PairedExactUnaryOp.value, Expr.eval]
  | read32 originalAddress candidateAddress =>
      have immutable := StateRel.originalImmutableImageWordMemory
        context world invariant original candidate related
      cases readResult : readImmutableImageWord context.originalPe originalAddress 4 with
      | none => simp [PairedStaticExprWitness.value, readResult] at evaluates
      | some expected =>
          simp [PairedStaticExprWitness.value, readResult] at evaluates
          subst value
          have read := ImmutableImageWordMemory.read32_of_checked context.originalPe
            original.memory originalAddress expected immutable readResult
          simpa [PairedStaticExprWitness.expression, Expr.eval,
            machineStateRead32_eq_memoryRead32] using read
  | indexed operation index operand operandSound =>
      simp only [PairedStaticExprWitness.checked] at checked
      cases operandResult : operand.value context .original with
      | none => simp [PairedStaticExprWitness.value, operandResult] at evaluates
      | some operandValue =>
          simp [PairedStaticExprWitness.value, operandResult] at evaluates
          subst value
          have operandEvaluates := operandSound operandValue checked operandResult
          cases operation <;> simp_all [PairedStaticExprWitness.expression,
            PairedExactIndexedOp.expression, PairedExactIndexedOp.value, Expr.eval]

theorem PairedStaticExprWitness.candidate_eval_eq_value
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (witness : PairedStaticExprWitness) (value : Word)
    (related : StateRel context world invariant original candidate)
    (checked : witness.checked invariant = true)
    (evaluates : witness.value context .candidate = some value) :
    (witness.expression .candidate).eval candidate = value := by
  induction witness generalizing value with
  | constant original candidate =>
      simpa [PairedStaticExprWitness.value,
        PairedStaticExprWitness.expression, Expr.eval] using evaluates
  | fixedInputReg originalRegister candidateRegister fixedValue =>
      simp only [PairedStaticExprWitness.value, Option.some.injEq] at evaluates
      subst value
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      have fixed := registerRelationsHold_fixed_pair
        context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        invariant.registerRelations original.registers candidate.registers
        originalRegister candidateRegister fixedValue relatedCore.1 checked
      simpa [PairedStaticExprWitness.value,
        PairedStaticExprWitness.expression, Expr.eval] using fixed.2
  | binary operation left right leftSound rightSound =>
      simp only [PairedStaticExprWitness.checked, Bool.and_eq_true] at checked
      cases leftResult : left.value context .candidate with
      | none => simp [PairedStaticExprWitness.value, leftResult] at evaluates
      | some leftValue =>
          cases rightResult : right.value context .candidate with
          | none =>
              simp [PairedStaticExprWitness.value, leftResult, rightResult] at evaluates
          | some rightValue =>
              simp [PairedStaticExprWitness.value, leftResult, rightResult] at evaluates
              subst value
              have leftEvaluates := leftSound leftValue checked.1 leftResult
              have rightEvaluates := rightSound rightValue checked.2 rightResult
              cases operation <;> simp_all [PairedStaticExprWitness.expression,
                PairedExactBinaryOp.expression, PairedExactBinaryOp.value, Expr.eval]
  | unary operation operand operandSound =>
      simp only [PairedStaticExprWitness.checked] at checked
      cases operandResult : operand.value context .candidate with
      | none => simp [PairedStaticExprWitness.value, operandResult] at evaluates
      | some operandValue =>
          simp [PairedStaticExprWitness.value, operandResult] at evaluates
          subst value
          have operandEvaluates := operandSound operandValue checked operandResult
          cases operation <;> simp_all [PairedStaticExprWitness.expression,
            PairedExactUnaryOp.expression, PairedExactUnaryOp.value, Expr.eval]
  | read32 originalAddress candidateAddress =>
      have immutable := StateRel.candidateImmutableImageWordMemory
        context world invariant original candidate related
      cases readResult : readImmutableImageWord context.candidatePe candidateAddress 4 with
      | none => simp [PairedStaticExprWitness.value, readResult] at evaluates
      | some expected =>
          simp [PairedStaticExprWitness.value, readResult] at evaluates
          subst value
          have read := ImmutableImageWordMemory.read32_of_checked context.candidatePe
            candidate.memory candidateAddress expected immutable readResult
          simpa [PairedStaticExprWitness.expression, Expr.eval,
            machineStateRead32_eq_memoryRead32] using read
  | indexed operation index operand operandSound =>
      simp only [PairedStaticExprWitness.checked] at checked
      cases operandResult : operand.value context .candidate with
      | none => simp [PairedStaticExprWitness.value, operandResult] at evaluates
      | some operandValue =>
          simp [PairedStaticExprWitness.value, operandResult] at evaluates
          subst value
          have operandEvaluates := operandSound operandValue checked operandResult
          cases operation <;> simp_all [PairedStaticExprWitness.expression,
            PairedExactIndexedOp.expression, PairedExactIndexedOp.value, Expr.eval]

def pairedStackOffsetExpression (register : Reg) (amount : Nat) : Expr :=
  if amount == 0 then .inputReg register
  else .add (.inputReg register) (.constant amount)

@[simp] theorem pairedStackOffsetExpression_eval (state : MachineState)
    (register : Reg) (amount : Nat) :
    (pairedStackOffsetExpression register amount).eval state =
      state.registers.get register + BitVec.ofNat 32 amount := by
  by_cases zero : amount = 0
  · simp [pairedStackOffsetExpression, zero, Expr.eval]
  · simp [pairedStackOffsetExpression, zero, Expr.eval]

structure PairedStackSeparatedWrite where
  window : StackWindowPair
  amount : Nat
  originalValue : Expr
  candidateValue : Expr
deriving Repr, DecidableEq

def PairedStackSeparatedWrite.write (side : PairedExactExprSide)
    (write : PairedStackSeparatedWrite) : Expr × Expr :=
  match side with
  | .original =>
      (pairedStackOffsetExpression write.window.originalRegister write.amount,
        write.originalValue)
  | .candidate =>
      (pairedStackOffsetExpression write.window.candidateRegister write.amount,
        write.candidateValue)

def PairedStackSeparatedWrite.checked (invariant : StateInvariant)
    (write : PairedStackSeparatedWrite) : Bool :=
  invariant.stackWindows.contains write.window &&
    write.amount % 4 == 0 && write.amount + 4 <= write.window.bytesAbove

theorem PairedStackSeparatedWrite.avoidsStaticSlot_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (write : PairedStackSeparatedWrite) (slot : StaticWordRelationSlotPair)
    (checked : write.checked invariant = true)
    (slotValid : slot.valid context = true)
    (related : StateRel context world invariant original candidate) :
    Write32AvoidsWord slot.originalAddress
        ((write.write .original).1.eval original) ∧
      Write32AvoidsWord slot.candidateAddress
        ((write.write .candidate).1.eval candidate) := by
  simp only [PairedStackSeparatedWrite.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at checked
  rcases checked with ⟨⟨windowMember, amountAligned⟩, amountInside⟩
  have rangesValid := related.stackRangesValid context world invariant
  have windowsHold := related.stackWindowsHold context world invariant
  simp only [stackWindowsRelated, List.all_eq_true] at windowsHold
  have windowHolds := windowsHold write.window
    (List.contains_iff_mem.mp windowMember)
  rcases pairedStackWordLocation_above_window context world write.window
      original.registers candidate.registers rangesValid windowHolds write.amount
      amountAligned amountInside with
    ⟨location, originalLocation, candidateLocation⟩
  have rangeValid : location.range.disjointFromImages context = true := by
    have validRows := rangesValid
    simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
      List.all_eq_true] at validRows
    exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
  have rangeShape := rangeValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeShape
  rcases rangeShape with
    ⟨⟨⟨⟨_rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  have originalBounds := slot.originalBounds context slotValid
  have candidateBounds := slot.candidateBounds context slotValid
  have originalAvoids := stackRangeWordWriteAvoidsImageWord
    location.range.originalBase location.range.size context.originalPe.imageBase
    context.originalPe.sizeOfImage location.offset location.inside originalNoWrap
    originalDisjoint slot.originalAddress originalBounds.1 originalBounds.2.1
    originalBounds.2.2
  have candidateAvoids := stackRangeWordWriteAvoidsImageWord
    location.range.candidateBase location.range.size context.candidatePe.imageBase
    context.candidatePe.sizeOfImage location.offset location.inside candidateNoWrap
    candidateDisjoint slot.candidateAddress candidateBounds.1 candidateBounds.2.1
    candidateBounds.2.2
  rw [← location.originalAddressExact, originalLocation] at originalAvoids
  rw [← location.candidateAddressExact, candidateLocation] at candidateAvoids
  constructor
  · simpa [PairedStackSeparatedWrite.write]
      using originalAvoids
  · simpa [PairedStackSeparatedWrite.write]
      using candidateAvoids

inductive PairedExactExprWitness where
  | inputReg (original candidate : Reg)
  | inputFlagValue (bit : Nat)
  | inputFsBase
  | inputX87Control
  | inputX87Status
  | constant (value : Nat)
  | binary (operation : PairedExactBinaryOp)
      (left right : PairedExactExprWitness)
  | unary (operation : PairedExactUnaryOp) (value : PairedExactExprWitness)
  | read8 (originalAddress candidateAddress : Nat)
  | read32 (originalAddress candidateAddress : Nat)
  | statePredicateRead32 (predicate : PairedStatePredicate)
      (read : PairedExactMemoryRead)
  | read8At (address : PairedStaticExprWitness)
  | read32At (address : PairedStaticExprWitness)
  | stackSeparatedRead32 (originalAddress candidateAddress : Nat)
      (writes : List PairedStackSeparatedWrite)
  | indexed (operation : PairedExactIndexedOp) (index : Nat)
      (value : PairedExactExprWitness)
  | ifEqual (left right thenValue elseValue : PairedExactExprWitness)
  | ternary (operation : PairedExactTernaryOp)
      (high low divisor : PairedExactExprWitness)
  | undefined (slot : Nat)
deriving Repr, DecidableEq

def PairedExactExprWitness.expression
    (side : PairedExactExprSide) : PairedExactExprWitness → Expr
  | .inputReg original candidate =>
      .inputReg (match side with | .original => original | .candidate => candidate)
  | .inputFlagValue bit => .inputFlagValue bit
  | .inputFsBase => .inputFsBase
  | .inputX87Control => .inputX87Control
  | .inputX87Status => .inputX87Status
  | .constant value => .constant value
  | .binary operation left right =>
      operation.expression (left.expression side) (right.expression side)
  | .unary operation value => operation.expression (value.expression side)
  | .read8 originalAddress candidateAddress =>
      .read8 (.constant (match side with
        | .original => originalAddress | .candidate => candidateAddress))
  | .read32 originalAddress candidateAddress =>
      .read32 (.constant (match side with
        | .original => originalAddress | .candidate => candidateAddress))
  | .statePredicateRead32 _ read =>
      .read32 (match side with
        | .original => read.originalAddress | .candidate => read.candidateAddress)
  | .read8At address => .read8 (address.expression side)
  | .read32At address => .read32 (address.expression side)
  | .stackSeparatedRead32 originalAddress candidateAddress writes =>
      .constantRead32AfterWrites
        (match side with
          | .original => originalAddress | .candidate => candidateAddress)
        (writes.map (PairedStackSeparatedWrite.write side))
  | .indexed operation index value =>
      operation.expression (value.expression side) index
  | .ifEqual left right thenValue elseValue =>
      .ifEqual (left.expression side) (right.expression side)
        (thenValue.expression side) (elseValue.expression side)
  | .ternary operation high low divisor =>
      operation.expression (high.expression side) (low.expression side)
        (divisor.expression side)
  | .undefined slot => .undefined slot

def PairedExactExprWitness.checked
    (context : StaticProofContext) (invariant : StateInvariant) :
    PairedExactExprWitness → Bool
  | .inputReg original candidate =>
      exactRegisterPair invariant.registerRelations original candidate
  | .inputFlagValue bit => invariant.flagBits.contains bit
  | .inputFsBase | .inputX87Control | .inputX87Status | .constant _ |
      .undefined _ => true
  | .binary _ left right =>
      left.checked context invariant && right.checked context invariant
  | .unary _ value | .indexed _ _ value => value.checked context invariant
  | .read8 originalAddress candidateAddress |
      .read32 originalAddress candidateAddress =>
      immutableImageWordsPairedEqual context originalAddress candidateAddress ||
        exactStaticWordSlotAddresses context originalAddress candidateAddress
  | .statePredicateRead32 predicate read =>
      invariant.predicates.contains predicate &&
        predicate.exactMemoryReads.contains read && read.bytes == 4
  | .read8At address | .read32At address =>
      address.checked invariant &&
        match address.value context .original, address.value context .candidate with
        | some originalAddress, some candidateAddress =>
            immutableImageWordsPairedEqual context originalAddress.toNat
              candidateAddress.toNat
        | _, _ => false
  | .stackSeparatedRead32 originalAddress candidateAddress writes =>
      exactStaticWordSlotAddresses context originalAddress candidateAddress &&
        staticWordRelationSlotsValid context &&
        !writes.isEmpty && writes.length <= 16 &&
        writes.all (PairedStackSeparatedWrite.checked invariant)
  | .ifEqual left right thenValue elseValue =>
      left.checked context invariant && right.checked context invariant &&
        thenValue.checked context invariant && elseValue.checked context invariant
  | .ternary _ high low divisor =>
      high.checked context invariant && low.checked context invariant &&
        divisor.checked context invariant

theorem PairedExactExprWitness.eval_equal_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (witness : PairedExactExprWitness)
    (checked : witness.checked context invariant = true)
    (related : StateRel context world invariant original candidate) :
    (witness.expression .original).eval original =
      (witness.expression .candidate).eval candidate := by
  induction witness with
  | inputReg originalRegister candidateRegister =>
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      exact registerRelationsHold_exact_pair
        context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        invariant.registerRelations original.registers candidate.registers
        originalRegister candidateRegister relatedCore.1 checked
  | inputFlagValue bit =>
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      have flagsExact := flagsRelated_of_contains invariant.flagBits
        original.eflags candidate.eflags relatedCore.2.2.2.2.2.2.2.2.1 checked
      simp only [PairedExactExprWitness.expression, Expr.eval]
      rw [flagsExact]
  | inputFsBase =>
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      simpa [PairedExactExprWitness.expression, Expr.eval] using
        relatedCore.2.2.2.2.2.2.2.2.2
  | inputX87Control =>
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      simpa [PairedExactExprWitness.expression, Expr.eval] using congrArg
        (fun state : X87MachineState => BitVec.zeroExtend 32 state.control)
        relatedCore.2.2.2.2.2.2.2.1.1
  | inputX87Status =>
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      simpa [PairedExactExprWitness.expression, Expr.eval] using congrArg
        (fun state : X87MachineState => BitVec.zeroExtend 32 state.status)
        relatedCore.2.2.2.2.2.2.2.1.1
  | read8 originalAddress candidateAddress =>
      simp only [PairedExactExprWitness.checked, Bool.or_eq_true] at checked
      rcases checked with immutable | slot
      · exact immutablePairedConstantRead8_eval_equal context originalAddress
          candidateAddress original candidate
          (StateRel.originalImmutableImageWordMemory context world invariant
            original candidate related)
          (StateRel.candidateImmutableImageWordMemory context world invariant
            original candidate related) immutable
      · exact exactStaticWordSlotRead8_eval_equal context world invariant
          original candidate originalAddress candidateAddress slot related
  | read32 originalAddress candidateAddress =>
      simp only [PairedExactExprWitness.checked, Bool.or_eq_true] at checked
      rcases checked with immutable | slot
      · exact immutablePairedConstantRead32_eval_equal context originalAddress
          candidateAddress original candidate
          (StateRel.originalImmutableImageWordMemory context world invariant
            original candidate related)
          (StateRel.candidateImmutableImageWordMemory context world invariant
            original candidate related) immutable
      · exact exactStaticWordSlotRead32_eval_equal context world invariant
          original candidate originalAddress candidateAddress slot related
  | statePredicateRead32 predicate read =>
      simp only [PairedExactExprWitness.checked, Bool.and_eq_true,
        beq_iff_eq] at checked
      rcases checked with ⟨⟨predicateMember, readMember⟩, fourBytes⟩
      have wordsEqual := StateRel.exactMemoryRead context world invariant
        original candidate predicate read
        (List.contains_iff_mem.mp predicateMember)
        (List.contains_iff_mem.mp readMember) related
      rw [fourBytes] at wordsEqual
      have lowWordsEqual := congrArg
        (fun value : X87Word => value.extractLsb' 0 32) wordsEqual
      change
        (original.readX87Word (read.originalAddress.eval original) 4).extractLsb' 0 32 =
          (candidate.readX87Word (read.candidateAddress.eval candidate) 4).extractLsb' 0 32
        at lowWordsEqual
      rw [MachineState.readX87Word_four_extractLsb,
        MachineState.readX87Word_four_extractLsb] at lowWordsEqual
      simpa [PairedExactExprWitness.expression, Expr.eval, fourBytes]
        using lowWordsEqual
  | read8At address =>
      simp only [PairedExactExprWitness.checked, Bool.and_eq_true] at checked
      rcases checked with ⟨addressChecked, immutablePair⟩
      cases originalResult : address.value context .original with
      | none => simp [originalResult] at immutablePair
      | some originalValue =>
          cases candidateResult : address.value context .candidate with
          | none => simp [originalResult, candidateResult] at immutablePair
          | some candidateValue =>
              simp [originalResult, candidateResult] at immutablePair
              have originalAddress := address.original_eval_eq_value context world
                invariant original candidate originalValue related addressChecked
                originalResult
              have candidateAddress := address.candidate_eval_eq_value context world
                invariant original candidate candidateValue related addressChecked
                candidateResult
              have readEqual := immutablePairedConstantRead8_eval_equal context
                originalValue.toNat candidateValue.toNat original candidate
                (StateRel.originalImmutableImageWordMemory context world invariant
                  original candidate related)
                (StateRel.candidateImmutableImageWordMemory context world invariant
                  original candidate related) immutablePair
              simpa [PairedExactExprWitness.expression, Expr.eval, originalAddress,
                candidateAddress] using readEqual
  | read32At address =>
      simp only [PairedExactExprWitness.checked, Bool.and_eq_true] at checked
      rcases checked with ⟨addressChecked, immutablePair⟩
      cases originalResult : address.value context .original with
      | none => simp [originalResult] at immutablePair
      | some originalValue =>
          cases candidateResult : address.value context .candidate with
          | none => simp [originalResult, candidateResult] at immutablePair
          | some candidateValue =>
              simp [originalResult, candidateResult] at immutablePair
              have originalAddress := address.original_eval_eq_value context world
                invariant original candidate originalValue related addressChecked
                originalResult
              have candidateAddress := address.candidate_eval_eq_value context world
                invariant original candidate candidateValue related addressChecked
                candidateResult
              have readEqual := immutablePairedConstantRead32_eval_equal context
                originalValue.toNat candidateValue.toNat original candidate
                (StateRel.originalImmutableImageWordMemory context world invariant
                  original candidate related)
                (StateRel.candidateImmutableImageWordMemory context world invariant
                  original candidate related) immutablePair
              simpa [PairedExactExprWitness.expression, Expr.eval, originalAddress,
                candidateAddress] using readEqual
  | stackSeparatedRead32 originalAddress candidateAddress writes =>
      simp only [PairedExactExprWitness.checked, Bool.and_eq_true,
        decide_eq_true_eq] at checked
      rcases checked with
        ⟨⟨⟨⟨slotChecked, slotsValid⟩, _writesNonempty⟩, _writesBounded⟩,
          writesChecked⟩
      have initialEqual := exactStaticWordSlotRead32_eval_equal context world invariant
        original candidate originalAddress candidateAddress slotChecked related
      simp only [exactStaticWordSlotAddresses, List.any_eq_true] at slotChecked
      rcases slotChecked with ⟨slot, slotMember, slotShape⟩
      simp only [Bool.and_eq_true, beq_iff_eq] at slotShape
      rcases slotShape with
        ⟨⟨originalAddressExact, candidateAddressExact⟩, relationExact⟩
      have slotValid := slot.valid_of_member context slotsValid slotMember
      have originalAvoids : ∀ evaluatedWrite,
          evaluatedWrite ∈ evalNormalizedWrites original
            (writes.map (PairedStackSeparatedWrite.write .original)) →
          Write32AvoidsWord slot.originalAddress evaluatedWrite.1 := by
        intro evaluatedWrite evaluatedMember
        simp only [evalNormalizedWrites, List.mem_map] at evaluatedMember
        rcases evaluatedMember with ⟨writeExpr, writeExprMember, evaluatedExact⟩
        rcases writeExprMember with ⟨sourceWrite, sourceMember, writeExprExact⟩
        subst writeExpr
        subst evaluatedWrite
        simp only [List.all_eq_true] at writesChecked
        have sourceChecked := writesChecked sourceWrite sourceMember
        exact (sourceWrite.avoidsStaticSlot_of_checked context world invariant
          original candidate slot sourceChecked slotValid related).1
      have candidateAvoids : ∀ evaluatedWrite,
          evaluatedWrite ∈ evalNormalizedWrites candidate
            (writes.map (PairedStackSeparatedWrite.write .candidate)) →
          Write32AvoidsWord slot.candidateAddress evaluatedWrite.1 := by
        intro evaluatedWrite evaluatedMember
        simp only [evalNormalizedWrites, List.mem_map] at evaluatedMember
        rcases evaluatedMember with ⟨writeExpr, writeExprMember, evaluatedExact⟩
        rcases writeExprMember with ⟨sourceWrite, sourceMember, writeExprExact⟩
        subst writeExpr
        subst evaluatedWrite
        simp only [List.all_eq_true] at writesChecked
        have sourceChecked := writesChecked sourceWrite sourceMember
        exact (sourceWrite.avoidsStaticSlot_of_checked context world invariant
          original candidate slot sourceChecked slotValid related).2
      have originalStable := Memory.read32_applyConcreteWrites_of_avoids
        original.memory slot.originalAddress
        (evalNormalizedWrites original
          (writes.map (PairedStackSeparatedWrite.write .original))) originalAvoids
      have candidateStable := Memory.read32_applyConcreteWrites_of_avoids
        candidate.memory slot.candidateAddress
        (evalNormalizedWrites candidate
          (writes.map (PairedStackSeparatedWrite.write .candidate))) candidateAvoids
      simp only [PairedExactExprWitness.expression]
      rw [Expr.eval_constantRead32AfterWrites,
        Expr.eval_constantRead32AfterWrites]
      rw [← originalAddressExact, ← candidateAddressExact]
      rw [originalStable, candidateStable]
      rw [originalAddressExact, candidateAddressExact]
      simpa [Expr.eval, machineStateRead32_eq_memoryRead32] using initialEqual
  | undefined slot =>
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      simp only [PairedExactExprWitness.expression, Expr.eval]
      rw [relatedCore.2.2.2.2.2.2.1]
  | binary operation left right leftSound rightSound =>
      simp only [PairedExactExprWitness.checked, Bool.and_eq_true] at checked
      have leftEqual := leftSound checked.1
      have rightEqual := rightSound checked.2
      cases operation <;> simp_all [PairedExactExprWitness.expression,
        PairedExactBinaryOp.expression, Expr.eval]
  | unary operation value valueSound =>
      have valueEqual := valueSound checked
      cases operation <;> simp_all [PairedExactExprWitness.expression,
        PairedExactUnaryOp.expression, Expr.eval]
  | indexed operation index value valueSound =>
      have valueEqual := valueSound checked
      cases operation <;> simp_all [PairedExactExprWitness.expression,
        PairedExactIndexedOp.expression, Expr.eval]
  | ifEqual left right thenValue elseValue leftSound rightSound thenSound elseSound =>
      simp only [PairedExactExprWitness.checked, Bool.and_eq_true] at checked
      rcases checked with ⟨⟨⟨leftChecked, rightChecked⟩, thenChecked⟩,
        elseChecked⟩
      have leftEqual := leftSound leftChecked
      have rightEqual := rightSound rightChecked
      have thenEqual := thenSound thenChecked
      have elseEqual := elseSound elseChecked
      simp [PairedExactExprWitness.expression, Expr.eval, leftEqual, rightEqual,
        thenEqual, elseEqual]
  | ternary operation high low divisor highSound lowSound divisorSound =>
      simp only [PairedExactExprWitness.checked, Bool.and_eq_true] at checked
      rcases checked with ⟨⟨highChecked, lowChecked⟩, divisorChecked⟩
      have highEqual := highSound highChecked
      have lowEqual := lowSound lowChecked
      have divisorEqual := divisorSound divisorChecked
      cases operation <;> simp_all [PairedExactExprWitness.expression,
        PairedExactTernaryOp.expression, Expr.eval]
  | constant value => rfl

end StageA.Relational
