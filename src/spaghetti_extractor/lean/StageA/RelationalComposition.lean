import StageA.RelationalSegment

namespace StageA.Relational

open StageA.Formal

inductive RelationalProductEdgeKind where
  | jump
  | branchTaken
  | branchFallthrough
  | call
  | callReturn
  | bulkCopy
  | externalCall
  | checkedContinue
  | atomicCompareExchange
deriving Repr, DecidableEq

structure RelationalCallFrame where
  continuationTargetId : Nat
  originalReturnAddress : Word
  candidateReturnAddress : Word
deriving Repr, DecidableEq

structure RelationalRuntimeCallFrame extends RelationalCallFrame where
  originalStackAddress : Word
  candidateStackAddress : Word
deriving Repr, DecidableEq

def RelationalRuntimeCallFrame.memoryHolds (frame : RelationalRuntimeCallFrame)
    (original candidate : Memory) : Prop :=
  Memory.read32 original frame.originalStackAddress = frame.originalReturnAddress ∧
    Memory.read32 candidate frame.candidateStackAddress = frame.candidateReturnAddress

def RelationalCallFrame.valid (context : StaticProofContext)
    (frame : RelationalCallFrame) : Bool :=
  match context.codeMap.get? frame.continuationTargetId with
  | none => false
  | some continuation =>
      codeAddressMatches context.originalPe.imageBase continuation.originalRva
        continuation.originalAliases frame.originalReturnAddress &&
      codeAddressMatches context.candidatePe.imageBase continuation.candidateRva
        continuation.candidateAliases frame.candidateReturnAddress

def RelationalCallFrame.resolves (context : StaticProofContext)
    (frame : RelationalCallFrame) : Bool :=
  resolveMappedCodeTarget false context.originalPe.imageBase
        context.codeMap.entries.toList frame.originalReturnAddress ==
      some frame.continuationTargetId &&
    resolveMappedCodeTarget true context.candidatePe.imageBase
        context.codeMap.entries.toList frame.candidateReturnAddress ==
      some frame.continuationTargetId

structure DirectCallPushClaim where
  calleeTargetId : Nat
  continuationTargetId : Nat
  originalReturnAddress : Nat
  candidateReturnAddress : Nat
  originalStackAddress : Expr
  candidateStackAddress : Expr
deriving Repr, DecidableEq

def DirectCallPushClaim.frame (context : StaticProofContext)
    (claim : DirectCallPushClaim) : Option RelationalCallFrame := do
  let _continuation <- context.codeMap.get? claim.continuationTargetId
  pure {
    continuationTargetId := claim.continuationTargetId
    originalReturnAddress := BitVec.ofNat 32 claim.originalReturnAddress
    candidateReturnAddress := BitVec.ofNat 32 claim.candidateReturnAddress
  }

def DirectCallPushClaim.runtimeFrame (context : StaticProofContext)
    (claim : DirectCallPushClaim) (original candidate : MachineState) :
    Option RelationalRuntimeCallFrame := do
  let frame <- claim.frame context
  pure {
    toRelationalCallFrame := frame
    originalStackAddress := claim.originalStackAddress.eval original
    candidateStackAddress := claim.candidateStackAddress.eval candidate
  }

def DirectCallPushClaim.checked (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DirectCallPushClaim) : Bool :=
  match context.codeMap.get? claim.calleeTargetId, claim.frame context with
  | some _, some frame =>
      frame.valid context &&
      originalBehavior.outcome == .call claim.calleeTargetId claim.continuationTargetId &&
      candidateBehavior.outcome == .call claim.calleeTargetId claim.continuationTargetId &&
      originalBehavior.registers.esp == claim.originalStackAddress &&
      candidateBehavior.registers.esp == claim.candidateStackAddress &&
      originalBehavior.writes.reverse.head? == some
        (claim.originalStackAddress, .constant frame.originalReturnAddress.toNat) &&
      candidateBehavior.writes.reverse.head? == some
        (claim.candidateStackAddress, .constant frame.candidateReturnAddress.toNat)
  | _, _ => false

def DirectCallPushClosed (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DirectCallPushClaim) : Prop :=
  match context.codeMap.get? claim.calleeTargetId, claim.frame context with
  | some _, some frame =>
      (((((frame.valid context = true ∧
        originalBehavior.outcome = .call claim.calleeTargetId claim.continuationTargetId) ∧
        candidateBehavior.outcome = .call claim.calleeTargetId claim.continuationTargetId) ∧
        originalBehavior.registers.esp = claim.originalStackAddress) ∧
        candidateBehavior.registers.esp = claim.candidateStackAddress) ∧
        originalBehavior.writes.reverse.head? = some
          (claim.originalStackAddress, .constant frame.originalReturnAddress.toNat)) ∧
        candidateBehavior.writes.reverse.head? = some
          (claim.candidateStackAddress, .constant frame.candidateReturnAddress.toNat)
  | _, _ => False

theorem directCallPushClosed_of_checked (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DirectCallPushClaim)
    (checked : claim.checked context originalBehavior candidateBehavior = true) :
    DirectCallPushClosed context originalBehavior candidateBehavior claim := by
  unfold DirectCallPushClaim.checked at checked
  unfold DirectCallPushClosed
  cases calleeResult : context.codeMap.get? claim.calleeTargetId with
  | none => simp [calleeResult] at checked
  | some callee =>
      cases frameResult : claim.frame context with
      | none => simp [calleeResult, frameResult] at checked
      | some frame =>
          simp only [calleeResult, frameResult] at checked
          simpa only [Bool.and_eq_true, beq_iff_eq] using checked

structure IndirectCallPushClaim where
  continuationTargetId : Nat
  originalReturnAddress : Nat
  candidateReturnAddress : Nat
  originalStackAddress : Expr
  candidateStackAddress : Expr
deriving Repr, DecidableEq

def IndirectCallPushClaim.frame (context : StaticProofContext)
    (claim : IndirectCallPushClaim) : Option RelationalCallFrame := do
  let _continuation <- context.codeMap.get? claim.continuationTargetId
  pure {
    continuationTargetId := claim.continuationTargetId
    originalReturnAddress := BitVec.ofNat 32 claim.originalReturnAddress
    candidateReturnAddress := BitVec.ofNat 32 claim.candidateReturnAddress
  }

def IndirectCallPushClaim.runtimeFrame (context : StaticProofContext)
    (claim : IndirectCallPushClaim) (original candidate : MachineState) :
    Option RelationalRuntimeCallFrame := do
  let frame <- claim.frame context
  pure {
    toRelationalCallFrame := frame
    originalStackAddress := claim.originalStackAddress.eval original
    candidateStackAddress := claim.candidateStackAddress.eval candidate
  }

def indirectCallContinuationMatches (outcome : NormalizedOutcomeExpr)
    (continuationTargetId : Nat) : Bool :=
  match outcome with
  | .indirectCall _ continuation => continuation == continuationTargetId
  | _ => false

def IndirectCallPushClaim.checked (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : IndirectCallPushClaim) : Bool :=
  match claim.frame context with
  | some frame =>
      frame.valid context &&
      indirectCallContinuationMatches originalBehavior.outcome
        claim.continuationTargetId &&
      indirectCallContinuationMatches candidateBehavior.outcome
        claim.continuationTargetId &&
      originalBehavior.registers.esp == claim.originalStackAddress &&
      candidateBehavior.registers.esp == claim.candidateStackAddress &&
      originalBehavior.writes.reverse.head? == some
        (claim.originalStackAddress, .constant frame.originalReturnAddress.toNat) &&
      candidateBehavior.writes.reverse.head? == some
        (claim.candidateStackAddress, .constant frame.candidateReturnAddress.toNat)
  | none => false

def IndirectCallPushClosed (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : IndirectCallPushClaim) : Prop :=
  match claim.frame context with
  | some frame =>
      (((((frame.valid context = true ∧
        indirectCallContinuationMatches originalBehavior.outcome
          claim.continuationTargetId = true) ∧
        indirectCallContinuationMatches candidateBehavior.outcome
          claim.continuationTargetId = true) ∧
        originalBehavior.registers.esp = claim.originalStackAddress) ∧
        candidateBehavior.registers.esp = claim.candidateStackAddress) ∧
        originalBehavior.writes.reverse.head? = some
          (claim.originalStackAddress, .constant frame.originalReturnAddress.toNat)) ∧
        candidateBehavior.writes.reverse.head? = some
          (claim.candidateStackAddress, .constant frame.candidateReturnAddress.toNat)
  | none => False

theorem indirectCallPushClosed_of_checked (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : IndirectCallPushClaim)
    (checked : claim.checked context originalBehavior candidateBehavior = true) :
    IndirectCallPushClosed context originalBehavior candidateBehavior claim := by
  unfold IndirectCallPushClaim.checked at checked
  unfold IndirectCallPushClosed
  cases frameResult : claim.frame context with
  | none => simp [frameResult] at checked
  | some frame =>
      simp only [frameResult] at checked
      simpa only [Bool.and_eq_true, beq_iff_eq] using checked

def _root_.StageA.Formal.Expr.registerOffset? (register : Reg) : Expr → Option Word
  | .inputReg source =>
      if source == register then some (BitVec.ofNat 32 0) else none
  | .add left (.constant value) => do
      pure ((← left.registerOffset? register) + BitVec.ofNat 32 value)
  | .add (.constant value) right => do
      pure (BitVec.ofNat 32 value + (← right.registerOffset? register))
  | .sub left (.constant value) => do
      pure ((← left.registerOffset? register) - BitVec.ofNat 32 value)
  | _ => none

inductive RegisterOffsetWitness where
  | input
  | addRight (prior : RegisterOffsetWitness) (value : Nat)
  | addLeft (value : Nat) (prior : RegisterOffsetWitness)
  | subRight (prior : RegisterOffsetWitness) (value : Nat)
deriving Repr, DecidableEq

def RegisterOffsetWitness.expression (register : Reg) : RegisterOffsetWitness → Expr
  | .input => .inputReg register
  | .addRight prior value => .add (prior.expression register) (.constant value)
  | .addLeft value prior => .add (.constant value) (prior.expression register)
  | .subRight prior value => .sub (prior.expression register) (.constant value)

def RegisterOffsetWitness.offset : RegisterOffsetWitness → Word
  | .input => BitVec.ofNat 32 0
  | .addRight prior value => prior.offset + BitVec.ofNat 32 value
  | .addLeft value prior => BitVec.ofNat 32 value + prior.offset
  | .subRight prior value => prior.offset - BitVec.ofNat 32 value

theorem word_add_left_comm (left middle right : Word) :
    left + (middle + right) = middle + (left + right) := by
  rw [← BitVec.add_assoc, BitVec.add_comm left middle, BitVec.add_assoc]

theorem word_add_delta_sub (base delta offset : Word) :
    base + delta + (offset - delta) = base + offset := by
  rw [BitVec.add_assoc, BitVec.add_comm delta (offset - delta),
    BitVec.sub_add_cancel]

theorem RegisterOffsetWitness.eval_expression (witness : RegisterOffsetWitness)
    (register : Reg) (state : MachineState) :
    (witness.expression register).eval state =
      state.registers.get register + witness.offset := by
  induction witness <;>
    simp_all [RegisterOffsetWitness.expression, RegisterOffsetWitness.offset, Expr.eval,
      BitVec.sub_eq_add_neg, BitVec.add_assoc, word_add_left_comm]

structure ReturnSlotOffsetPair where
  originalRegister : Reg := .esp
  originalOffset : Word
  candidateRegister : Reg := .esp
  candidateOffset : Word
deriving Repr, DecidableEq

def ReturnSlotOffsetPair.holds (offsets : ReturnSlotOffsetPair)
    (frame : RelationalRuntimeCallFrame)
    (original candidate : Registers Word) : Prop :=
  original.get offsets.originalRegister + offsets.originalOffset =
      frame.originalStackAddress ∧
    candidate.get offsets.candidateRegister + offsets.candidateOffset =
      frame.candidateStackAddress

def ReturnSlotOffsetPair.zero : ReturnSlotOffsetPair := {
  originalRegister := .esp
  originalOffset := BitVec.ofNat 32 0
  candidateRegister := .esp
  candidateOffset := BitVec.ofNat 32 0
}

theorem directCallPushEntryReturnSlot_of_checked
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DirectCallPushClaim) (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.checked context originalBehavior candidateBehavior = true)
    (frameResult : claim.runtimeFrame context originalState candidateState = some frame) :
    ReturnSlotOffsetPair.zero.holds frame
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers := by
  have closed := directCallPushClosed_of_checked context originalBehavior candidateBehavior
    claim checked
  unfold DirectCallPushClosed at closed
  cases calleeResult : context.codeMap.get? claim.calleeTargetId with
  | none => simp [calleeResult] at closed
  | some callee =>
      cases baseFrameResult : claim.frame context with
      | none => simp [calleeResult, baseFrameResult] at closed
      | some baseFrame =>
          simp only [calleeResult, baseFrameResult] at closed
          have originalEsp := closed.1.1.1.2
          have candidateEsp := closed.1.1.2
          clear closed
          unfold DirectCallPushClaim.runtimeFrame at frameResult
          simp only [baseFrameResult, Option.bind_some] at frameResult
          cases frameResult
          constructor
          · simp only [ReturnSlotOffsetPair.zero, ReturnSlotOffsetPair.holds,
              NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
              BitVec.add_zero]
            change originalBehavior.registers.esp.eval originalState =
              claim.originalStackAddress.eval originalState
            rw [originalEsp]
          · simp only [ReturnSlotOffsetPair.zero, ReturnSlotOffsetPair.holds,
              NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
              BitVec.add_zero]
            change candidateBehavior.registers.esp.eval candidateState =
              claim.candidateStackAddress.eval candidateState
            rw [candidateEsp]

theorem indirectCallPushEntryReturnSlot_of_checked
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : IndirectCallPushClaim) (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.checked context originalBehavior candidateBehavior = true)
    (frameResult : claim.runtimeFrame context originalState candidateState = some frame) :
    ReturnSlotOffsetPair.zero.holds frame
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers := by
  have closed := indirectCallPushClosed_of_checked context originalBehavior
    candidateBehavior claim checked
  unfold IndirectCallPushClosed at closed
  cases baseFrameResult : claim.frame context with
  | none => simp [baseFrameResult] at closed
  | some baseFrame =>
      simp only [baseFrameResult] at closed
      have originalEsp := closed.1.1.1.2
      have candidateEsp := closed.1.1.2
      unfold IndirectCallPushClaim.runtimeFrame at frameResult
      simp only [baseFrameResult, Option.bind_some] at frameResult
      cases frameResult
      constructor
      · simp only [ReturnSlotOffsetPair.zero, ReturnSlotOffsetPair.holds,
          NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
          BitVec.add_zero]
        change originalBehavior.registers.esp.eval originalState =
          claim.originalStackAddress.eval originalState
        rw [originalEsp]
      · simp only [ReturnSlotOffsetPair.zero, ReturnSlotOffsetPair.holds,
          NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
          BitVec.add_zero]
        change candidateBehavior.registers.esp.eval candidateState =
          claim.candidateStackAddress.eval candidateState
        rw [candidateEsp]

structure ReturnSlotTransferClaim where
  source : ReturnSlotOffsetPair
  target : ReturnSlotOffsetPair
  originalOutput : RegisterOffsetWitness
  candidateOutput : RegisterOffsetWitness
deriving Repr, DecidableEq

def ReturnSlotTransferClaim.checked (originalBehavior candidateBehavior :
    NormalizedSymbolicBehavior) (claim : ReturnSlotTransferClaim) : Bool :=
  claim.originalOutput.expression claim.source.originalRegister ==
      originalBehavior.registers.get claim.target.originalRegister &&
    claim.candidateOutput.expression claim.source.candidateRegister ==
      candidateBehavior.registers.get claim.target.candidateRegister &&
    claim.originalOutput.offset + claim.target.originalOffset ==
      claim.source.originalOffset &&
    claim.candidateOutput.offset + claim.target.candidateOffset ==
      claim.source.candidateOffset

def ReturnSlotTransferClosed (originalBehavior candidateBehavior :
    NormalizedSymbolicBehavior) (claim : ReturnSlotTransferClaim) : Prop :=
  claim.originalOutput.expression claim.source.originalRegister =
      originalBehavior.registers.get claim.target.originalRegister ∧
    claim.candidateOutput.expression claim.source.candidateRegister =
      candidateBehavior.registers.get claim.target.candidateRegister ∧
    claim.originalOutput.offset + claim.target.originalOffset =
      claim.source.originalOffset ∧
    claim.candidateOutput.offset + claim.target.candidateOffset =
      claim.source.candidateOffset

theorem returnSlotTransferClosed_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotTransferClaim)
    (checked : claim.checked originalBehavior candidateBehavior = true) :
    ReturnSlotTransferClosed originalBehavior candidateBehavior claim := by
  simp only [ReturnSlotTransferClaim.checked, Bool.and_eq_true, beq_iff_eq] at checked
  exact ⟨checked.1.1.1, checked.1.1.2, checked.1.2, checked.2⟩

theorem returnSlotTransferHolds_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotTransferClaim) (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.checked originalBehavior candidateBehavior = true)
    (sourceHolds : claim.source.holds frame originalState.registers
      candidateState.registers) :
    claim.target.holds frame (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers := by
  have closed := returnSlotTransferClosed_of_checked originalBehavior candidateBehavior
    claim checked
  rcases closed with ⟨originalExpression, candidateExpression, originalOffset,
    candidateOffset⟩
  rcases sourceHolds with ⟨originalSource, candidateSource⟩
  constructor
  · simp only [NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get]
    change (originalBehavior.registers.get claim.target.originalRegister).eval originalState +
      claim.target.originalOffset = frame.originalStackAddress
    rw [← originalExpression, claim.originalOutput.eval_expression]
    calc
      originalState.registers.get claim.source.originalRegister +
          claim.originalOutput.offset +
          claim.target.originalOffset =
          originalState.registers.get claim.source.originalRegister +
            (claim.originalOutput.offset + claim.target.originalOffset) :=
        BitVec.add_assoc _ _ _
      _ = originalState.registers.get claim.source.originalRegister +
          claim.source.originalOffset := by
        rw [originalOffset]
      _ = frame.originalStackAddress := originalSource
  · simp only [NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get]
    change (candidateBehavior.registers.get claim.target.candidateRegister).eval
      candidateState +
      claim.target.candidateOffset = frame.candidateStackAddress
    rw [← candidateExpression, claim.candidateOutput.eval_expression]
    calc
      candidateState.registers.get claim.source.candidateRegister +
          claim.candidateOutput.offset +
          claim.target.candidateOffset =
          candidateState.registers.get claim.source.candidateRegister +
            (claim.candidateOutput.offset + claim.target.candidateOffset) :=
        BitVec.add_assoc _ _ _
      _ = candidateState.registers.get claim.source.candidateRegister +
          claim.source.candidateOffset := by
        rw [candidateOffset]
      _ = frame.candidateStackAddress := candidateSource

structure ReturnSlotTransferRule where
  originalSourceRegister : Reg
  candidateSourceRegister : Reg
  originalTargetRegister : Reg
  candidateTargetRegister : Reg
  originalOutput : RegisterOffsetWitness
  candidateOutput : RegisterOffsetWitness
  originalDelta : Word
  candidateDelta : Word
deriving Repr, DecidableEq

def ReturnSlotTransferRule.checked (originalBehavior candidateBehavior :
    NormalizedSymbolicBehavior) (rule : ReturnSlotTransferRule) : Bool :=
  rule.originalOutput.expression rule.originalSourceRegister ==
      originalBehavior.registers.get rule.originalTargetRegister &&
    rule.candidateOutput.expression rule.candidateSourceRegister ==
      candidateBehavior.registers.get rule.candidateTargetRegister &&
    rule.originalOutput.offset == rule.originalDelta &&
    rule.candidateOutput.offset == rule.candidateDelta

def ReturnSlotTransferRuleClosed (originalBehavior candidateBehavior :
    NormalizedSymbolicBehavior) (rule : ReturnSlotTransferRule) : Prop :=
  rule.originalOutput.expression rule.originalSourceRegister =
      originalBehavior.registers.get rule.originalTargetRegister ∧
    rule.candidateOutput.expression rule.candidateSourceRegister =
      candidateBehavior.registers.get rule.candidateTargetRegister ∧
    rule.originalOutput.offset = rule.originalDelta ∧
    rule.candidateOutput.offset = rule.candidateDelta

theorem returnSlotTransferRuleClosed_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (rule : ReturnSlotTransferRule)
    (checked : rule.checked originalBehavior candidateBehavior = true) :
    ReturnSlotTransferRuleClosed originalBehavior candidateBehavior rule := by
  simp only [ReturnSlotTransferRule.checked, Bool.and_eq_true, beq_iff_eq] at checked
  exact ⟨checked.1.1.1, checked.1.1.2, checked.1.2, checked.2⟩

def ReturnSlotTransferRule.apply (rule : ReturnSlotTransferRule)
    (source : ReturnSlotOffsetPair) : Option ReturnSlotOffsetPair :=
  if source.originalRegister == rule.originalSourceRegister &&
      source.candidateRegister == rule.candidateSourceRegister then
    some {
      originalRegister := rule.originalTargetRegister
      originalOffset := source.originalOffset - rule.originalDelta
      candidateRegister := rule.candidateTargetRegister
      candidateOffset := source.candidateOffset - rule.candidateDelta
    }
  else none

theorem returnSlotTransferRuleHolds_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (rule : ReturnSlotTransferRule) (source target : ReturnSlotOffsetPair)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (checked : rule.checked originalBehavior candidateBehavior = true)
    (applied : rule.apply source = some target)
    (sourceHolds : source.holds frame originalState.registers candidateState.registers) :
    target.holds frame (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers := by
  have closed := returnSlotTransferRuleClosed_of_checked originalBehavior
    candidateBehavior rule checked
  unfold ReturnSlotTransferRule.apply at applied
  split at applied
  next registersMatch =>
    simp only [Bool.and_eq_true, beq_iff_eq] at registersMatch
    cases applied
    rcases closed with ⟨originalExpression, candidateExpression,
      originalDelta, candidateDelta⟩
    rcases sourceHolds with ⟨originalSource, candidateSource⟩
    constructor
    · simp only [ReturnSlotOffsetPair.holds,
        NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get]
      rw [← originalExpression, rule.originalOutput.eval_expression,
        originalDelta, ← registersMatch.1]
      calc
        originalState.registers.get source.originalRegister + rule.originalDelta +
            (source.originalOffset - rule.originalDelta) =
            originalState.registers.get source.originalRegister +
              source.originalOffset := by
          exact word_add_delta_sub _ _ _
        _ = frame.originalStackAddress := originalSource
    · simp only [ReturnSlotOffsetPair.holds,
        NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get]
      rw [← candidateExpression, rule.candidateOutput.eval_expression,
        candidateDelta, ← registersMatch.2]
      calc
        candidateState.registers.get source.candidateRegister + rule.candidateDelta +
            (source.candidateOffset - rule.candidateDelta) =
            candidateState.registers.get source.candidateRegister +
              source.candidateOffset := by
          exact word_add_delta_sub _ _ _
        _ = frame.candidateStackAddress := candidateSource
  next registersMismatch => simp at applied

def wordOffsetsDisjoint (wordOffset writeOffset : Word) : Bool :=
  (List.range 4).all fun wordByte =>
    (List.range 4).all fun writeByte =>
      decide (wordOffset + BitVec.ofNat 32 wordByte ≠
        writeOffset + BitVec.ofNat 32 writeByte)

def registerOffsetWitnessesAvoidWord
    (register : Reg) (wordOffset : Word) :
    List RegisterOffsetWitness -> List (Expr × Expr) -> Bool
  | [], [] => true
  | witness :: witnesses, write :: writes =>
      witness.expression register == write.1 &&
        wordOffsetsDisjoint wordOffset witness.offset &&
        registerOffsetWitnessesAvoidWord register wordOffset witnesses writes
  | _, _ => false

def RegisterOffsetWitnessesAvoidWordClosed
    (register : Reg) (wordOffset : Word) :
    List RegisterOffsetWitness -> List (Expr × Expr) -> Prop
  | [], [] => True
  | witness :: witnesses, write :: writes =>
      witness.expression register = write.1 ∧
        wordOffsetsDisjoint wordOffset witness.offset = true ∧
        RegisterOffsetWitnessesAvoidWordClosed register wordOffset witnesses writes
  | _, _ => False

theorem registerOffsetWitnessesAvoidWordClosed_of_checked
    (register : Reg) (wordOffset : Word)
    (witnesses : List RegisterOffsetWitness) (writes : List (Expr × Expr))
    (checked : registerOffsetWitnessesAvoidWord register wordOffset
      witnesses writes = true) :
    RegisterOffsetWitnessesAvoidWordClosed register wordOffset witnesses writes := by
  induction witnesses generalizing writes with
  | nil => cases writes <;> simp_all [registerOffsetWitnessesAvoidWord,
      RegisterOffsetWitnessesAvoidWordClosed]
  | cons witness witnesses ih =>
      cases writes with
      | nil => simp [registerOffsetWitnessesAvoidWord] at checked
      | cons write writes =>
          simp only [registerOffsetWitnessesAvoidWord, Bool.and_eq_true,
            beq_iff_eq] at checked
          simp only [RegisterOffsetWitnessesAvoidWordClosed]
          exact ⟨checked.1.1, checked.1.2, ih writes checked.2⟩

theorem registerOffsetWitnessesAvoidWord_of_closed
    (register : Reg) (wordOffset : Word)
    (witnesses : List RegisterOffsetWitness) (writes : List (Expr × Expr))
    (state : MachineState)
    (closed : RegisterOffsetWitnessesAvoidWordClosed register wordOffset
      witnesses writes) :
    WritesAvoidWord
      (state.registers.get register + wordOffset)
      (evalNormalizedWrites state writes) := by
  induction witnesses generalizing writes with
  | nil =>
      cases writes with
      | nil => simp [evalNormalizedWrites, WritesAvoidWord]
      | cons write writes =>
          simp [RegisterOffsetWitnessesAvoidWordClosed] at closed
  | cons witness witnesses ih =>
      cases writes with
      | nil => simp [RegisterOffsetWitnessesAvoidWordClosed] at closed
      | cons write writes =>
          simp only [RegisterOffsetWitnessesAvoidWordClosed] at closed
          rcases closed with ⟨expression, disjoint, tailClosed⟩
          intro concreteWrite concreteMember
          simp only [evalNormalizedWrites, List.map_cons, List.mem_cons] at concreteMember
          rcases concreteMember with rfl | tailMember
          · intro wordByte wordByteBefore writeByte writeByteBefore overlap
            simp only [wordOffsetsDisjoint, List.all_eq_true] at disjoint
            have wordChecked := disjoint wordByte (by simpa using wordByteBefore)
            have writeChecked := wordChecked writeByte (by simpa using writeByteBefore)
            simp only [decide_eq_true_eq] at writeChecked
            apply writeChecked
            apply (BitVec.add_right_inj (state.registers.get register)).mp
            rw [← expression, witness.eval_expression] at overlap
            simpa only [BitVec.add_assoc] using overlap
          · exact ih writes tailClosed concreteWrite tailMember

structure ReturnSlotMemoryTransferClaim where
  offsets : ReturnSlotOffsetPair
  originalWrites : List RegisterOffsetWitness
  candidateWrites : List RegisterOffsetWitness
deriving Repr, DecidableEq

def ReturnSlotMemoryTransferClaim.checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotMemoryTransferClaim) : Bool :=
  registerOffsetWitnessesAvoidWord claim.offsets.originalRegister
      claim.offsets.originalOffset claim.originalWrites originalBehavior.writes &&
    registerOffsetWitnessesAvoidWord claim.offsets.candidateRegister
      claim.offsets.candidateOffset claim.candidateWrites candidateBehavior.writes

def ReturnSlotMemoryTransferClaimClosed
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotMemoryTransferClaim) : Prop :=
  RegisterOffsetWitnessesAvoidWordClosed claim.offsets.originalRegister
      claim.offsets.originalOffset claim.originalWrites originalBehavior.writes ∧
    RegisterOffsetWitnessesAvoidWordClosed claim.offsets.candidateRegister
      claim.offsets.candidateOffset claim.candidateWrites candidateBehavior.writes

theorem returnSlotMemoryTransferClaimClosed_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotMemoryTransferClaim)
    (checked : claim.checked originalBehavior candidateBehavior = true) :
    ReturnSlotMemoryTransferClaimClosed originalBehavior candidateBehavior claim := by
  simp only [ReturnSlotMemoryTransferClaim.checked, Bool.and_eq_true] at checked
  exact ⟨registerOffsetWitnessesAvoidWordClosed_of_checked _ _ _ _ checked.1,
    registerOffsetWitnessesAvoidWordClosed_of_checked _ _ _ _ checked.2⟩

theorem returnSlotMemoryTransferHolds_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotMemoryTransferClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (checked : claim.checked originalBehavior candidateBehavior = true)
    (offsetsHold : claim.offsets.holds frame originalState.registers
      candidateState.registers)
    (memoryHolds : frame.memoryHolds originalState.memory candidateState.memory) :
    frame.memoryHolds
      (applyConcreteWrites originalState.memory
        (evalNormalizedWrites originalState originalBehavior.writes))
      (applyConcreteWrites candidateState.memory
        (evalNormalizedWrites candidateState candidateBehavior.writes)) := by
  have closed := returnSlotMemoryTransferClaimClosed_of_checked
    originalBehavior candidateBehavior claim checked
  have originalAvoids := registerOffsetWitnessesAvoidWord_of_closed
    claim.offsets.originalRegister claim.offsets.originalOffset
    claim.originalWrites originalBehavior.writes originalState closed.1
  have candidateAvoids := registerOffsetWitnessesAvoidWord_of_closed
    claim.offsets.candidateRegister claim.offsets.candidateOffset
    claim.candidateWrites candidateBehavior.writes candidateState closed.2
  rcases offsetsHold with ⟨originalOffset, candidateOffset⟩
  rcases memoryHolds with ⟨originalMemory, candidateMemory⟩
  constructor
  · rw [← originalOffset]
    rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ originalAvoids]
    rw [originalOffset]
    exact originalMemory
  · rw [← candidateOffset]
    rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ candidateAvoids]
    rw [candidateOffset]
    exact candidateMemory

structure ReturnSlotFrameTransferClaim where
  transfer : ReturnSlotTransferClaim
  memory : ReturnSlotMemoryTransferClaim
deriving Repr, DecidableEq

def ReturnSlotFrameTransferClaim.checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotFrameTransferClaim) : Bool :=
  claim.memory.offsets == claim.transfer.source &&
    claim.transfer.checked originalBehavior candidateBehavior &&
    claim.memory.checked originalBehavior candidateBehavior

theorem returnSlotFrameTransferHolds_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotFrameTransferClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (checked : claim.checked originalBehavior candidateBehavior = true)
    (sourceOffsets : claim.transfer.source.holds frame originalState.registers
      candidateState.registers)
    (sourceMemory : frame.memoryHolds originalState.memory candidateState.memory) :
    claim.transfer.target.holds frame
        (originalBehavior.eval originalState).registers
        (candidateBehavior.eval candidateState).registers ∧
      frame.memoryHolds
        ((originalBehavior.eval originalState).nextMachineState originalState).memory
        ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory := by
  simp only [ReturnSlotFrameTransferClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with ⟨⟨memorySource, transferChecked⟩, memoryChecked⟩
  have offsets := returnSlotTransferHolds_of_checked originalBehavior
    candidateBehavior claim.transfer frame originalState candidateState
    transferChecked sourceOffsets
  have memory := returnSlotMemoryTransferHolds_of_checked originalBehavior
    candidateBehavior claim.memory frame originalState candidateState memoryChecked
    (by simpa [memorySource] using sourceOffsets) sourceMemory
  exact ⟨offsets, by
    simpa [RelationalBehavior.nextMachineState] using memory⟩

structure ReturnSlotCallSummaryClaim where
  source : ReturnSlotOffsetPair
  target : ReturnSlotOffsetPair
  originalCallEsp : RegisterOffsetWitness
  candidateCallEsp : RegisterOffsetWitness
  originalReturnSlot : RegisterOffsetWitness
  candidateReturnSlot : RegisterOffsetWitness
  originalReturnOutput : RegisterOffsetWitness
  candidateReturnOutput : RegisterOffsetWitness
  popBytes : Nat
deriving Repr, DecidableEq

def returnStackAddressMatches (behavior : NormalizedSymbolicBehavior)
    (address : Expr) : Bool :=
  behavior.outcome == .returned (.read32 address) ||
    behavior.outcome == .returned (address.read32AfterWrites behavior.writes)

def ReturnSlotCallSummaryClosed
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callClaim : DirectCallPushClaim) (claim : ReturnSlotCallSummaryClaim) : Prop :=
  ((((claim.source.originalRegister = .esp ∧
    claim.source.candidateRegister = .esp) ∧
    claim.target.originalRegister = .esp) ∧
    claim.target.candidateRegister = .esp) ∧
    claim.popBytes ≤ 65535) ∧
  claim.originalCallEsp.expression .esp = callClaim.originalStackAddress ∧
  claim.candidateCallEsp.expression .esp = callClaim.candidateStackAddress ∧
  returnStackAddressMatches originalReturnBehavior
    (claim.originalReturnSlot.expression .esp) = true ∧
  returnStackAddressMatches candidateReturnBehavior
    (claim.candidateReturnSlot.expression .esp) = true ∧
  claim.originalReturnOutput.expression .esp = originalReturnBehavior.registers.esp ∧
  claim.candidateReturnOutput.expression .esp = candidateReturnBehavior.registers.esp ∧
  claim.originalReturnOutput.offset =
    claim.originalReturnSlot.offset + BitVec.ofNat 32 (4 + claim.popBytes) ∧
  claim.candidateReturnOutput.offset =
    claim.candidateReturnSlot.offset + BitVec.ofNat 32 (4 + claim.popBytes) ∧
  claim.originalCallEsp.offset + BitVec.ofNat 32 (4 + claim.popBytes) +
    claim.target.originalOffset = claim.source.originalOffset ∧
  claim.candidateCallEsp.offset + BitVec.ofNat 32 (4 + claim.popBytes) +
    claim.target.candidateOffset = claim.source.candidateOffset

def ReturnSlotCallSummaryClaim.checked
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callClaim : DirectCallPushClaim) (claim : ReturnSlotCallSummaryClaim) : Bool :=
  claim.source.originalRegister == .esp &&
  claim.source.candidateRegister == .esp &&
  claim.target.originalRegister == .esp &&
  claim.target.candidateRegister == .esp &&
  decide (claim.popBytes ≤ 65535) &&
  (claim.originalCallEsp.expression .esp == callClaim.originalStackAddress &&
  (claim.candidateCallEsp.expression .esp == callClaim.candidateStackAddress &&
  (returnStackAddressMatches originalReturnBehavior
    (claim.originalReturnSlot.expression .esp) &&
  (returnStackAddressMatches candidateReturnBehavior
    (claim.candidateReturnSlot.expression .esp) &&
  (claim.originalReturnOutput.expression .esp == originalReturnBehavior.registers.esp &&
  (claim.candidateReturnOutput.expression .esp == candidateReturnBehavior.registers.esp &&
  (claim.originalReturnOutput.offset ==
    claim.originalReturnSlot.offset + BitVec.ofNat 32 (4 + claim.popBytes) &&
  (claim.candidateReturnOutput.offset ==
    claim.candidateReturnSlot.offset + BitVec.ofNat 32 (4 + claim.popBytes) &&
  (claim.originalCallEsp.offset + BitVec.ofNat 32 (4 + claim.popBytes) +
    claim.target.originalOffset == claim.source.originalOffset &&
  claim.candidateCallEsp.offset + BitVec.ofNat 32 (4 + claim.popBytes) +
    claim.target.candidateOffset == claim.source.candidateOffset)))))))))

theorem returnSlotCallSummaryClosed_of_checked
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callClaim : DirectCallPushClaim) (claim : ReturnSlotCallSummaryClaim)
    (checked : claim.checked originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior callClaim = true) :
    ReturnSlotCallSummaryClosed originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior callClaim claim := by
  unfold ReturnSlotCallSummaryClaim.checked at checked
  unfold ReturnSlotCallSummaryClosed
  simpa only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] using checked

theorem returnSlotCallSummaryHolds_of_checked
    (context : StaticProofContext)
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callClaim : DirectCallPushClaim) (claim : ReturnSlotCallSummaryClaim)
    (outerFrame nestedFrame : RelationalRuntimeCallFrame)
    (originalCallState candidateCallState originalReturnState candidateReturnState :
      MachineState)
    (checked : claim.checked originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior callClaim = true)
    (nestedFrameResult : callClaim.runtimeFrame context originalCallState
      candidateCallState = some nestedFrame)
    (outerSource : claim.source.holds outerFrame originalCallState.registers
      candidateCallState.registers)
    (nestedSlots : ({
        originalOffset := claim.originalReturnSlot.offset
        candidateOffset := claim.candidateReturnSlot.offset
      } : ReturnSlotOffsetPair).holds nestedFrame originalReturnState.registers
        candidateReturnState.registers) :
    claim.target.holds outerFrame
      (originalReturnBehavior.eval originalReturnState).registers
      (candidateReturnBehavior.eval candidateReturnState).registers := by
  have closed := returnSlotCallSummaryClosed_of_checked originalCallBehavior
    candidateCallBehavior originalReturnBehavior candidateReturnBehavior callClaim claim checked
  rcases closed with ⟨registersAndPop, originalCallExpression, candidateCallExpression,
    _originalReturnSlotExpression, _candidateReturnSlotExpression,
    originalReturnOutputExpression, candidateReturnOutputExpression,
    originalOutputOffset, candidateOutputOffset, originalSummaryOffset,
    candidateSummaryOffset⟩
  have originalSourceRegister := registersAndPop.1.1.1.1
  have candidateSourceRegister := registersAndPop.1.1.1.2
  have originalTargetRegister := registersAndPop.1.1.2
  have candidateTargetRegister := registersAndPop.1.2
  unfold ReturnSlotOffsetPair.holds at outerSource ⊢
  simp only [originalSourceRegister, candidateSourceRegister] at outerSource
  simp only [originalTargetRegister, candidateTargetRegister]
  rcases outerSource with ⟨originalOuter, candidateOuter⟩
  rcases nestedSlots with ⟨originalNested, candidateNested⟩
  unfold DirectCallPushClaim.runtimeFrame at nestedFrameResult
  cases baseFrameResult : callClaim.frame context with
  | none => simp [baseFrameResult] at nestedFrameResult
  | some baseFrame =>
      simp only [baseFrameResult] at nestedFrameResult
      cases nestedFrameResult
      constructor
      · simp only [NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get]
        change originalReturnBehavior.registers.esp.eval originalReturnState +
          claim.target.originalOffset = outerFrame.originalStackAddress
        rw [← originalReturnOutputExpression, claim.originalReturnOutput.eval_expression,
          originalOutputOffset]
        calc
          originalReturnState.registers.get .esp +
              (claim.originalReturnSlot.offset + BitVec.ofNat 32 (4 + claim.popBytes)) +
              claim.target.originalOffset =
              (originalReturnState.registers.get .esp +
                claim.originalReturnSlot.offset) + BitVec.ofNat 32 (4 + claim.popBytes) +
                claim.target.originalOffset := by
            exact congrArg (fun value => value + claim.target.originalOffset)
              (BitVec.add_assoc (originalReturnState.registers.get .esp)
                claim.originalReturnSlot.offset
                (BitVec.ofNat 32 (4 + claim.popBytes))).symm
          _ = callClaim.originalStackAddress.eval originalCallState +
                BitVec.ofNat 32 (4 + claim.popBytes) + claim.target.originalOffset := by
            rw [originalNested]
          _ = (claim.originalCallEsp.expression .esp).eval originalCallState +
                BitVec.ofNat 32 (4 + claim.popBytes) + claim.target.originalOffset := by
            rw [originalCallExpression]
          _ = (originalCallState.registers.get .esp + claim.originalCallEsp.offset) +
                BitVec.ofNat 32 (4 + claim.popBytes) + claim.target.originalOffset := by
            rw [claim.originalCallEsp.eval_expression]
          _ = originalCallState.registers.get .esp + claim.source.originalOffset := by
            rw [BitVec.add_assoc (originalCallState.registers.get .esp)
              claim.originalCallEsp.offset (BitVec.ofNat 32 (4 + claim.popBytes))]
            rw [BitVec.add_assoc (originalCallState.registers.get .esp)
              (claim.originalCallEsp.offset + BitVec.ofNat 32 (4 + claim.popBytes))
              claim.target.originalOffset]
            rw [originalSummaryOffset]
          _ = outerFrame.originalStackAddress := originalOuter
      · simp only [NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get]
        change candidateReturnBehavior.registers.esp.eval candidateReturnState +
          claim.target.candidateOffset = outerFrame.candidateStackAddress
        rw [← candidateReturnOutputExpression, claim.candidateReturnOutput.eval_expression,
          candidateOutputOffset]
        calc
          candidateReturnState.registers.get .esp +
              (claim.candidateReturnSlot.offset + BitVec.ofNat 32 (4 + claim.popBytes)) +
              claim.target.candidateOffset =
              (candidateReturnState.registers.get .esp +
                claim.candidateReturnSlot.offset) + BitVec.ofNat 32 (4 + claim.popBytes) +
                claim.target.candidateOffset := by
            exact congrArg (fun value => value + claim.target.candidateOffset)
              (BitVec.add_assoc (candidateReturnState.registers.get .esp)
                claim.candidateReturnSlot.offset
                (BitVec.ofNat 32 (4 + claim.popBytes))).symm
          _ = callClaim.candidateStackAddress.eval candidateCallState +
                BitVec.ofNat 32 (4 + claim.popBytes) + claim.target.candidateOffset := by
            rw [candidateNested]
          _ = (claim.candidateCallEsp.expression .esp).eval candidateCallState +
                BitVec.ofNat 32 (4 + claim.popBytes) + claim.target.candidateOffset := by
            rw [candidateCallExpression]
          _ = (candidateCallState.registers.get .esp + claim.candidateCallEsp.offset) +
                BitVec.ofNat 32 (4 + claim.popBytes) + claim.target.candidateOffset := by
            rw [claim.candidateCallEsp.eval_expression]
          _ = candidateCallState.registers.get .esp + claim.source.candidateOffset := by
            rw [BitVec.add_assoc (candidateCallState.registers.get .esp)
              claim.candidateCallEsp.offset (BitVec.ofNat 32 (4 + claim.popBytes))]
            rw [BitVec.add_assoc (candidateCallState.registers.get .esp)
              (claim.candidateCallEsp.offset + BitVec.ofNat 32 (4 + claim.popBytes))
              claim.target.candidateOffset]
            rw [candidateSummaryOffset]
          _ = outerFrame.candidateStackAddress := candidateOuter

structure ReturnPopClaim where
  originalStackAddress : Expr
  candidateStackAddress : Expr
  popBytes : Nat
deriving Repr, DecidableEq

def ReturnPopClaim.checked (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnPopClaim) : Bool :=
  claim.popBytes <= 65535 &&
    originalBehavior.outcome == .returned (.read32 claim.originalStackAddress) &&
    candidateBehavior.outcome == .returned (.read32 claim.candidateStackAddress) &&
    match claim.originalStackAddress.registerOffset? .esp,
        claim.candidateStackAddress.registerOffset? .esp,
        originalBehavior.registers.esp.registerOffset? .esp,
        candidateBehavior.registers.esp.registerOffset? .esp with
    | some originalSlot, some candidateSlot, some originalOutput, some candidateOutput =>
        originalOutput == originalSlot + BitVec.ofNat 32 (4 + claim.popBytes) &&
          candidateOutput == candidateSlot + BitVec.ofNat 32 (4 + claim.popBytes)
    | _, _, _, _ => false

def ReturnPopClosed (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnPopClaim) : Prop :=
  claim.popBytes <= 65535 ∧
    originalBehavior.outcome = .returned (.read32 claim.originalStackAddress) ∧
    candidateBehavior.outcome = .returned (.read32 claim.candidateStackAddress) ∧
    match claim.originalStackAddress.registerOffset? .esp,
        claim.candidateStackAddress.registerOffset? .esp,
        originalBehavior.registers.esp.registerOffset? .esp,
        candidateBehavior.registers.esp.registerOffset? .esp with
    | some originalSlot, some candidateSlot, some originalOutput, some candidateOutput =>
        originalOutput = originalSlot + BitVec.ofNat 32 (4 + claim.popBytes) ∧
          candidateOutput = candidateSlot + BitVec.ofNat 32 (4 + claim.popBytes)
    | _, _, _, _ => False

theorem returnPopClosed_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnPopClaim)
    (checked : claim.checked originalBehavior candidateBehavior = true) :
    ReturnPopClosed originalBehavior candidateBehavior claim := by
  unfold ReturnPopClaim.checked at checked
  unfold ReturnPopClosed
  simp only [Bool.and_eq_true, beq_iff_eq] at checked
  have popBytes := checked.1.1.1
  have originalOutcome := checked.1.1.2
  have candidateOutcome := checked.1.2
  have offsets := checked.2
  have popBytesProp : claim.popBytes ≤ 65535 := of_decide_eq_true popBytes
  refine ⟨popBytesProp, originalOutcome, candidateOutcome, ?_⟩
  cases originalSlotResult : claim.originalStackAddress.registerOffset? .esp with
  | none => simp [originalSlotResult] at offsets
  | some originalSlot =>
      cases candidateSlotResult : claim.candidateStackAddress.registerOffset? .esp with
      | none => simp [originalSlotResult, candidateSlotResult] at offsets
      | some candidateSlot =>
          cases originalOutputResult :
              originalBehavior.registers.esp.registerOffset? .esp with
          | none =>
              simp [originalSlotResult, candidateSlotResult, originalOutputResult] at offsets
          | some originalOutput =>
              cases candidateOutputResult :
                  candidateBehavior.registers.esp.registerOffset? .esp with
              | none =>
                  simp [originalSlotResult, candidateSlotResult, originalOutputResult,
                    candidateOutputResult] at offsets
              | some candidateOutput =>
                  simp only [originalSlotResult, candidateSlotResult, originalOutputResult,
                    candidateOutputResult, Bool.and_eq_true, beq_iff_eq] at offsets
                  exact offsets

def ReturnPopFrameInvariant (claim : ReturnPopClaim)
    (frame : RelationalRuntimeCallFrame) (original candidate : MachineState) : Prop :=
  claim.originalStackAddress.eval original = frame.originalStackAddress ∧
    claim.candidateStackAddress.eval candidate = frame.candidateStackAddress

structure ReturnPopFrameClaim where
  offsets : ReturnSlotOffsetPair
  originalSlot : RegisterOffsetWitness
  candidateSlot : RegisterOffsetWitness
deriving Repr, DecidableEq

def ReturnPopFrameClaim.checked (returnClaim : ReturnPopClaim)
    (claim : ReturnPopFrameClaim) : Bool :=
  claim.offsets.originalRegister == .esp &&
    claim.offsets.candidateRegister == .esp &&
  claim.originalSlot.expression .esp == returnClaim.originalStackAddress &&
    claim.candidateSlot.expression .esp == returnClaim.candidateStackAddress &&
    claim.originalSlot.offset == claim.offsets.originalOffset &&
    claim.candidateSlot.offset == claim.offsets.candidateOffset

def ReturnPopFrameClaimClosed (returnClaim : ReturnPopClaim)
    (claim : ReturnPopFrameClaim) : Prop :=
  claim.offsets.originalRegister = .esp ∧
    claim.offsets.candidateRegister = .esp ∧
  claim.originalSlot.expression .esp = returnClaim.originalStackAddress ∧
    claim.candidateSlot.expression .esp = returnClaim.candidateStackAddress ∧
    claim.originalSlot.offset = claim.offsets.originalOffset ∧
    claim.candidateSlot.offset = claim.offsets.candidateOffset

theorem returnPopFrameClaimClosed_of_checked
    (returnClaim : ReturnPopClaim) (claim : ReturnPopFrameClaim)
    (checked : claim.checked returnClaim = true) :
    ReturnPopFrameClaimClosed returnClaim claim := by
  simp only [ReturnPopFrameClaim.checked, Bool.and_eq_true, beq_iff_eq] at checked
  exact ⟨checked.1.1.1.1.1, checked.1.1.1.1.2, checked.1.1.1.2,
    checked.1.1.2, checked.1.2, checked.2⟩

theorem returnPopFrameInvariant_of_checked
    (returnClaim : ReturnPopClaim) (claim : ReturnPopFrameClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (checked : claim.checked returnClaim = true)
    (offsetsHold : claim.offsets.holds frame originalState.registers
      candidateState.registers) :
    ReturnPopFrameInvariant returnClaim frame originalState candidateState := by
  have closed := returnPopFrameClaimClosed_of_checked returnClaim claim checked
  rcases closed with ⟨originalRegister, candidateRegister, originalExpression,
    candidateExpression, originalOffset, candidateOffset⟩
  unfold ReturnSlotOffsetPair.holds at offsetsHold
  simp only [originalRegister, candidateRegister] at offsetsHold
  rcases offsetsHold with ⟨originalHolds, candidateHolds⟩
  constructor
  · rw [← originalExpression, claim.originalSlot.eval_expression]
    rw [originalOffset]
    exact originalHolds
  · rw [← candidateExpression, claim.candidateSlot.eval_expression]
    rw [candidateOffset]
    exact candidateHolds

theorem returnPopTargetsFrame_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnPopClaim) (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.checked originalBehavior candidateBehavior = true)
    (slotInvariant : ReturnPopFrameInvariant claim frame originalState candidateState)
    (memoryHolds : frame.memoryHolds originalState.memory candidateState.memory) :
    originalBehavior.outcome.eval originalState = .returned frame.originalReturnAddress ∧
      candidateBehavior.outcome.eval candidateState = .returned frame.candidateReturnAddress := by
  have closed := returnPopClosed_of_checked originalBehavior candidateBehavior claim checked
  rcases closed with ⟨_popBytes, originalOutcome, candidateOutcome, _offsets⟩
  rcases slotInvariant with ⟨originalSlot, candidateSlot⟩
  rcases memoryHolds with ⟨originalMemory, candidateMemory⟩
  constructor
  · rw [originalOutcome]
    simp only [NormalizedOutcomeExpr.eval, PureOutcome.returned.injEq, Expr.eval]
    rw [originalSlot]
    simpa only [machineStateRead32_eq_memoryRead32] using originalMemory
  · rw [candidateOutcome]
    simp only [NormalizedOutcomeExpr.eval, PureOutcome.returned.injEq, Expr.eval]
    rw [candidateSlot]
    simpa only [machineStateRead32_eq_memoryRead32] using candidateMemory

theorem returnPopTargetsRuntimeFrame_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (returnClaim : ReturnPopClaim) (frameClaim : ReturnPopFrameClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (returnChecked : returnClaim.checked originalBehavior candidateBehavior = true)
    (frameChecked : frameClaim.checked returnClaim = true)
    (offsetsHold : frameClaim.offsets.holds frame originalState.registers
      candidateState.registers)
    (memoryHolds : frame.memoryHolds originalState.memory candidateState.memory) :
    originalBehavior.outcome.eval originalState = .returned frame.originalReturnAddress ∧
      candidateBehavior.outcome.eval candidateState = .returned frame.candidateReturnAddress := by
  apply returnPopTargetsFrame_of_checked originalBehavior candidateBehavior returnClaim frame
    originalState candidateState returnChecked
  · exact returnPopFrameInvariant_of_checked returnClaim frameClaim frame originalState
      candidateState frameChecked offsetsHold
  · exact memoryHolds

structure ReturnPopAfterWritesClaim where
  originalStack : RegisterOffsetWitness
  candidateStack : RegisterOffsetWitness
  originalOutput : RegisterOffsetWitness
  candidateOutput : RegisterOffsetWitness
  popBytes : Nat
deriving Repr, DecidableEq

def ReturnPopAfterWritesClosed (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnPopAfterWritesClaim) : Prop :=
  claim.popBytes ≤ 65535 ∧
    originalBehavior.outcome = .returned
      ((claim.originalStack.expression .esp).read32AfterWrites originalBehavior.writes) ∧
    candidateBehavior.outcome = .returned
      ((claim.candidateStack.expression .esp).read32AfterWrites candidateBehavior.writes) ∧
    claim.originalOutput.expression .esp = originalBehavior.registers.esp ∧
    claim.candidateOutput.expression .esp = candidateBehavior.registers.esp ∧
    claim.originalOutput.offset =
      claim.originalStack.offset + BitVec.ofNat 32 (4 + claim.popBytes) ∧
    claim.candidateOutput.offset =
      claim.candidateStack.offset + BitVec.ofNat 32 (4 + claim.popBytes) ∧
    constantWritesSeparatedFromRegisterWord false sourceInvariant.addressSeparations
      .esp claim.originalStack.offset.toNat originalBehavior.writes = true ∧
    constantWritesSeparatedFromRegisterWord true sourceInvariant.addressSeparations
      .esp claim.candidateStack.offset.toNat candidateBehavior.writes = true

def ReturnPopAfterWritesClaim.checked (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnPopAfterWritesClaim) : Bool :=
  claim.popBytes <= 65535 &&
    (originalBehavior.outcome == .returned
      ((claim.originalStack.expression .esp).read32AfterWrites originalBehavior.writes) &&
    (candidateBehavior.outcome == .returned
      ((claim.candidateStack.expression .esp).read32AfterWrites candidateBehavior.writes) &&
    (claim.originalOutput.expression .esp == originalBehavior.registers.esp &&
    (claim.candidateOutput.expression .esp == candidateBehavior.registers.esp &&
    (claim.originalOutput.offset ==
      claim.originalStack.offset + BitVec.ofNat 32 (4 + claim.popBytes) &&
    (claim.candidateOutput.offset ==
      claim.candidateStack.offset + BitVec.ofNat 32 (4 + claim.popBytes) &&
    (constantWritesSeparatedFromRegisterWord false sourceInvariant.addressSeparations
      .esp claim.originalStack.offset.toNat originalBehavior.writes &&
    constantWritesSeparatedFromRegisterWord true sourceInvariant.addressSeparations
      .esp claim.candidateStack.offset.toNat candidateBehavior.writes)))))))

theorem returnPopAfterWritesClosed_of_checked (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnPopAfterWritesClaim)
    (checked : claim.checked sourceInvariant originalBehavior candidateBehavior = true) :
    ReturnPopAfterWritesClosed sourceInvariant originalBehavior candidateBehavior claim := by
  unfold ReturnPopAfterWritesClaim.checked at checked
  unfold ReturnPopAfterWritesClosed
  simpa only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] using checked

def ReturnPopAfterWritesFrameInvariant (claim : ReturnPopAfterWritesClaim)
    (frame : RelationalRuntimeCallFrame) (original candidate : MachineState) : Prop :=
  (claim.originalStack.expression .esp).eval original = frame.originalStackAddress ∧
    (claim.candidateStack.expression .esp).eval candidate = frame.candidateStackAddress

def ReturnPopFrameClaim.checkedAfterWrites (returnClaim : ReturnPopAfterWritesClaim)
    (claim : ReturnPopFrameClaim) : Bool :=
  claim.offsets.originalRegister == .esp &&
    claim.offsets.candidateRegister == .esp &&
  claim.originalSlot.expression .esp == returnClaim.originalStack.expression .esp &&
    claim.candidateSlot.expression .esp == returnClaim.candidateStack.expression .esp &&
    claim.originalSlot.offset == claim.offsets.originalOffset &&
    claim.candidateSlot.offset == claim.offsets.candidateOffset

def ReturnPopAfterWritesFrameClaimClosed (returnClaim : ReturnPopAfterWritesClaim)
    (claim : ReturnPopFrameClaim) : Prop :=
  claim.offsets.originalRegister = .esp ∧
    claim.offsets.candidateRegister = .esp ∧
  claim.originalSlot.expression .esp = returnClaim.originalStack.expression .esp ∧
    claim.candidateSlot.expression .esp = returnClaim.candidateStack.expression .esp ∧
    claim.originalSlot.offset = claim.offsets.originalOffset ∧
    claim.candidateSlot.offset = claim.offsets.candidateOffset

theorem returnPopAfterWritesFrameClaimClosed_of_checked
    (returnClaim : ReturnPopAfterWritesClaim) (claim : ReturnPopFrameClaim)
    (checked : claim.checkedAfterWrites returnClaim = true) :
    ReturnPopAfterWritesFrameClaimClosed returnClaim claim := by
  simp only [ReturnPopFrameClaim.checkedAfterWrites, Bool.and_eq_true,
    beq_iff_eq] at checked
  exact ⟨checked.1.1.1.1.1, checked.1.1.1.1.2, checked.1.1.1.2,
    checked.1.1.2, checked.1.2, checked.2⟩

theorem returnPopAfterWritesFrameInvariant_of_checked
    (returnClaim : ReturnPopAfterWritesClaim) (claim : ReturnPopFrameClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (checked : claim.checkedAfterWrites returnClaim = true)
    (offsetsHold : claim.offsets.holds frame originalState.registers
      candidateState.registers) :
    ReturnPopAfterWritesFrameInvariant returnClaim frame originalState candidateState := by
  have closed := returnPopAfterWritesFrameClaimClosed_of_checked returnClaim claim checked
  rcases closed with ⟨originalRegister, candidateRegister, originalExpression,
    candidateExpression, originalOffset, candidateOffset⟩
  unfold ReturnSlotOffsetPair.holds at offsetsHold
  simp only [originalRegister, candidateRegister] at offsetsHold
  rcases offsetsHold with ⟨originalHolds, candidateHolds⟩
  constructor
  · rw [← originalExpression, claim.originalSlot.eval_expression, originalOffset]
    exact originalHolds
  · rw [← candidateExpression, claim.candidateSlot.eval_expression, candidateOffset]
    exact candidateHolds

theorem returnPopAfterWritesTargetsRuntimeFrame_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (returnClaim : ReturnPopAfterWritesClaim) (frameClaim : ReturnPopFrameClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (returnChecked : returnClaim.checked sourceInvariant originalBehavior
      candidateBehavior = true)
    (frameChecked : frameClaim.checkedAfterWrites returnClaim = true)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (offsetsHold : frameClaim.offsets.holds frame originalState.registers
      candidateState.registers)
    (memoryHolds : frame.memoryHolds originalState.memory candidateState.memory) :
    originalBehavior.outcome.eval originalState = .returned frame.originalReturnAddress ∧
      candidateBehavior.outcome.eval candidateState = .returned frame.candidateReturnAddress := by
  have closed := returnPopAfterWritesClosed_of_checked sourceInvariant originalBehavior
    candidateBehavior returnClaim returnChecked
  rcases closed with
    ⟨_popBytes, originalOutcome, candidateOutcome, _originalOutput,
      _candidateOutput, _originalOffset, _candidateOffset, originalSeparated,
      candidateSeparated⟩
  have slotInvariant := returnPopAfterWritesFrameInvariant_of_checked returnClaim
    frameClaim frame originalState candidateState frameChecked offsetsHold
  rcases slotInvariant with ⟨originalSlot, candidateSlot⟩
  rcases memoryHolds with ⟨originalMemory, candidateMemory⟩
  rcases related with
    ⟨_worldStatic, _rangesValid, _stackMemory, _importsStatic, _importsComplete,
      _importsMemory, _originalImmutable, _candidateImmutable, relatedCore,
      _importRegisters⟩
  rcases relatedCore with
    ⟨_registers, _bounds, separations, _stackWindows, _memory, _undefined,
      _x87, _flags, _fsBase⟩
  have originalSide := addressSeparationsRelated_original
    sourceInvariant.addressSeparations originalState.registers candidateState.registers
    separations
  have candidateSide := addressSeparationsRelated_candidate
    sourceInvariant.addressSeparations originalState.registers candidateState.registers
    separations
  have originalAvoidsAtRegister := constantWritesAvoidRegisterWord_of_checked false
    sourceInvariant.addressSeparations .esp returnClaim.originalStack.offset.toNat
    originalBehavior.writes originalState originalSide originalSeparated
  have candidateAvoidsAtRegister := constantWritesAvoidRegisterWord_of_checked true
    sourceInvariant.addressSeparations .esp returnClaim.candidateStack.offset.toNat
    candidateBehavior.writes candidateState candidateSide candidateSeparated
  have originalAvoids : WritesAvoidWord
      ((returnClaim.originalStack.expression .esp).eval originalState)
      (evalNormalizedWrites originalState originalBehavior.writes) := by
    rw [returnClaim.originalStack.eval_expression]
    simpa using originalAvoidsAtRegister
  have candidateAvoids : WritesAvoidWord
      ((returnClaim.candidateStack.expression .esp).eval candidateState)
      (evalNormalizedWrites candidateState candidateBehavior.writes) := by
    rw [returnClaim.candidateStack.eval_expression]
    simpa using candidateAvoidsAtRegister
  constructor
  · rw [originalOutcome]
    simp only [NormalizedOutcomeExpr.eval, PureOutcome.returned.injEq]
    rw [Expr.eval_read32AfterWrites]
    rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ originalAvoids]
    rw [originalSlot]
    simpa only [machineStateRead32_eq_memoryRead32] using originalMemory
  · rw [candidateOutcome]
    simp only [NormalizedOutcomeExpr.eval, PureOutcome.returned.injEq]
    rw [Expr.eval_read32AfterWrites]
    rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ candidateAvoids]
    rw [candidateSlot]
    simpa only [machineStateRead32_eq_memoryRead32] using candidateMemory

structure RelationalProductNode where
  id : Nat
  targetId : Nat
  root : Bool
  outgoingEdgeIds : List Nat
deriving Repr, DecidableEq

def _root_.StageA.Formal.Expr.closedConstant? : Expr -> Option Word
  | .constant value => some (BitVec.ofNat 32 value)
  | .sub left right =>
      if left == right then some (BitVec.ofNat 32 0) else none
  | _ => none

theorem _root_.StageA.Formal.Expr.eval_of_closedConstant
    (expression : Expr) (value : Word)
    (checked : expression.closedConstant? = some value) (state : MachineState) :
    expression.eval state = value := by
  cases expression <;> simp_all [Expr.closedConstant?, Expr.eval]

def _root_.StageA.Formal.BoolExpr.closedConstant? : BoolExpr -> Option Bool
  | .equal left right =>
      if left == right then some true else do
        pure ((← left.closedConstant?) == (← right.closedConstant?))
  | .not value => do pure !(← value.closedConstant?)
  | _ => none

theorem _root_.StageA.Formal.BoolExpr.eval_of_closedConstant
    (expression : BoolExpr) (value : Bool)
    (checked : expression.closedConstant? = some value) (state : MachineState) :
    expression.eval state = value := by
  induction expression generalizing value with
  | equal left right =>
      by_cases same : left = right
      · subst right
        simpa [BoolExpr.closedConstant?, BoolExpr.eval] using checked
      · have different : (left == right) = false := beq_eq_false_iff_ne.mpr same
        cases leftResult : left.closedConstant? with
        | none => simp [BoolExpr.closedConstant?, different, leftResult] at checked
        | some leftValue =>
            cases rightResult : right.closedConstant? with
            | none =>
                simp [BoolExpr.closedConstant?, different, leftResult, rightResult] at checked
            | some rightValue =>
                have leftEval := left.eval_of_closedConstant leftValue leftResult state
                have rightEval := right.eval_of_closedConstant rightValue rightResult state
                simpa [BoolExpr.closedConstant?, different, leftResult, rightResult,
                  BoolExpr.eval, leftEval, rightEval] using checked
  | not expression ih =>
      cases result : expression.closedConstant? with
      | none => simp [BoolExpr.closedConstant?, result] at checked
      | some inner =>
          have evaluated := ih inner result
          simpa [BoolExpr.closedConstant?, result, BoolExpr.eval, evaluated] using checked
  | _ => simp [BoolExpr.closedConstant?] at checked

def _root_.StageA.Formal.BoolExpr.definitelyFalse (expression : BoolExpr) : Bool :=
  expression.closedConstant? == some false

theorem _root_.StageA.Formal.BoolExpr.eval_false_of_definitelyFalse
    (expression : BoolExpr) (checked : expression.definitelyFalse = true)
    (state : MachineState) : expression.eval state = false := by
  simp only [BoolExpr.definitelyFalse, beq_iff_eq] at checked
  exact expression.eval_of_closedConstant false checked state

structure RelationalProductEdge where
  id : Nat
  sourceNodeId : Nat
  targetNodeId : Nat
  sourceTargetId : Nat
  targetTargetId : Nat
  kind : RelationalProductEdgeKind
  originalGuard : BoolExpr
  candidateGuard : BoolExpr
  infeasible : Bool
deriving Repr, DecidableEq

structure RelationalProductGraph where
  nodes : Array RelationalProductNode
  edges : Array RelationalProductEdge
  rootNodeIds : List Nat
deriving Repr, DecidableEq

structure RelationalDecodedControlEdge where
  kind : RelationalProductEdgeKind
  targetTargetId : Nat
  guard : BoolExpr
deriving Repr, DecidableEq

def unconditionalProductGuard : BoolExpr :=
  .equal (.constant 0) (.constant 0)

def codeTargetProductGuard (imageBase : Nat) (targetExpression : Expr)
    (primaryRva : Nat) : List CodeAlias -> BoolExpr
  | [] => .equal targetExpression (.constant (imageBase + primaryRva))
  | alias :: aliases =>
      .or (.equal targetExpression (.constant (imageBase + alias.rva)))
        (codeTargetProductGuard imageBase targetExpression primaryRva aliases)

theorem codeTargetProductGuard_eval_true (imageBase : Nat) (targetExpression : Expr)
    (primaryRva : Nat) (aliases : List CodeAlias) (state : MachineState) :
    (codeTargetProductGuard imageBase targetExpression primaryRva aliases).eval state =
      true ↔
    codeAddressMatches imageBase primaryRva aliases (targetExpression.eval state) = true := by
  induction aliases with
  | nil =>
      simp [codeTargetProductGuard, codeAddressMatches, BoolExpr.eval, Expr.eval,
        beq_iff_eq]
  | cons alias aliases ih =>
      simp [codeTargetProductGuard, codeAddressMatches, BoolExpr.eval, Expr.eval, ih,
        beq_iff_eq, Bool.or_eq_true, or_assoc, or_comm, or_left_comm]

structure ImmutableIndirectCallTargetClaim where
  targetId : Nat
  continuationTargetId : Nat
  originalAddress : Nat
  candidateAddress : Nat
  originalAssembledRead : Bool
  candidateAssembledRead : Bool
  originalWrites : List RegisterOffsetWrite
  candidateWrites : List RegisterOffsetWrite
deriving Repr, DecidableEq

def immutableWordReadExpression (assembledRead : Bool) (address : Nat)
    (writes : List RegisterOffsetWrite) : Expr :=
  if assembledRead then
    .constantRead32AfterWrites address (writes.map RegisterOffsetWrite.toWrite)
  else
    .read32 (.constant address)

def mappedRelocationWordPair (context : StaticProofContext)
    (originalAddress candidateAddress : Nat) : Bool :=
  context.dataMap.entries.toList.any fun target =>
    target.originalValue <= originalAddress &&
      target.candidateValue <= candidateAddress &&
      originalAddress - target.originalValue ==
        candidateAddress - target.candidateValue &&
      target.relocationOffsets.contains (originalAddress - target.originalValue)

def ImmutableIndirectCallTargetClaim.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectCallTargetClaim) : Bool :=
  match context.codeMap.get? claim.targetId with
  | none => false
  | some target =>
      readImmutableImageWord context.originalPe claim.originalAddress 4 ==
          some (context.originalPe.imageBase + target.originalRva) &&
        readImmutableImageWord context.candidatePe claim.candidateAddress 4 ==
          some (context.candidatePe.imageBase + target.candidateRva) &&
        mappedRelocationWordPair context claim.originalAddress claim.candidateAddress &&
        originalBehavior.outcome == .indirectCall
          (immutableWordReadExpression claim.originalAssembledRead
            claim.originalAddress claim.originalWrites)
          claim.continuationTargetId &&
        candidateBehavior.outcome == .indirectCall
          (immutableWordReadExpression claim.candidateAssembledRead
            claim.candidateAddress claim.candidateWrites)
          claim.continuationTargetId &&
        registerOffsetWritesSeparated false sourceInvariant.addressSeparations
          claim.originalAddress claim.originalWrites &&
        registerOffsetWritesSeparated true sourceInvariant.addressSeparations
          claim.candidateAddress claim.candidateWrites

def ImmutableIndirectCallTargetsClosed
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectCallTargetClaim) : Prop :=
  match context.codeMap.get? claim.targetId with
  | none => False
  | some target =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
          originalBehavior.outcome.eval originalState = .indirectCall
              (BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva))
              claim.continuationTargetId ∧
            candidateBehavior.outcome.eval candidateState = .indirectCall
              (BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva))
              claim.continuationTargetId

theorem immutableIndirectCallTargetsClosed_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectCallTargetClaim)
    (checked : claim.checked context sourceInvariant originalBehavior candidateBehavior = true) :
    ImmutableIndirectCallTargetsClosed context sourceInvariant originalBehavior
      candidateBehavior claim := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
    simp [ImmutableIndirectCallTargetClaim.checked, targetResult] at checked
  | some target =>
    simp only [ImmutableIndirectCallTargetClaim.checked, targetResult] at checked
    simp only [ImmutableIndirectCallTargetsClosed, targetResult]
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    rcases checked with
      ⟨⟨⟨⟨⟨⟨originalImageWord, candidateImageWord⟩, _mappedWord⟩,
        originalOutcome⟩, candidateOutcome⟩, originalSeparated⟩,
        candidateSeparated⟩
    intro world originalState candidateState related
    rcases related with
      ⟨_worldStatic, _stackRangesValid, _stackMemory, _importsStatic,
        _importsComplete, _importsMemory, originalImmutable, candidateImmutable, relatedCore,
        _importRegisters⟩
    rcases relatedCore with
      ⟨_registers, _bounds, separations, _stackWindows, _memory, _undefined,
        _x87, _flags, _fsBase⟩
    have originalSide := addressSeparationsRelated_original
      sourceInvariant.addressSeparations originalState.registers candidateState.registers
      separations
    have candidateSide := addressSeparationsRelated_candidate
      sourceInvariant.addressSeparations originalState.registers candidateState.registers
      separations
    have originalAvoids := registerOffsetWritesAvoidWord_of_checked false
      sourceInvariant.addressSeparations claim.originalAddress claim.originalWrites
      originalState originalSide originalSeparated
    have candidateAvoids := registerOffsetWritesAvoidWord_of_checked true
      sourceInvariant.addressSeparations claim.candidateAddress claim.candidateWrites
      candidateState candidateSide candidateSeparated
    have originalTarget :
        (immutableWordReadExpression claim.originalAssembledRead
          claim.originalAddress claim.originalWrites).eval originalState =
            BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva) := by
      cases assembled : claim.originalAssembledRead with
      | false =>
        simp only [immutableWordReadExpression, assembled, if_false, Expr.eval,
          machineStateRead32_eq_memoryRead32]
        exact ImmutableImageWordMemory.read32_of_checked context.originalPe
          originalState.memory claim.originalAddress
          (context.originalPe.imageBase + target.originalRva) originalImmutable
          originalImageWord
      | true =>
        simp only [immutableWordReadExpression, assembled, if_true]
        rw [Expr.eval_constantRead32AfterWrites]
        rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ originalAvoids]
        exact ImmutableImageWordMemory.read32_of_checked context.originalPe
          originalState.memory claim.originalAddress
          (context.originalPe.imageBase + target.originalRva) originalImmutable
          originalImageWord
    have candidateTarget :
        (immutableWordReadExpression claim.candidateAssembledRead
          claim.candidateAddress claim.candidateWrites).eval candidateState =
            BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva) := by
      cases assembled : claim.candidateAssembledRead with
      | false =>
        simp only [immutableWordReadExpression, assembled, if_false, Expr.eval,
          machineStateRead32_eq_memoryRead32]
        exact ImmutableImageWordMemory.read32_of_checked context.candidatePe
          candidateState.memory claim.candidateAddress
          (context.candidatePe.imageBase + target.candidateRva) candidateImmutable
          candidateImageWord
      | true =>
        simp only [immutableWordReadExpression, assembled, if_true]
        rw [Expr.eval_constantRead32AfterWrites]
        rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ candidateAvoids]
        exact ImmutableImageWordMemory.read32_of_checked context.candidatePe
          candidateState.memory claim.candidateAddress
          (context.candidatePe.imageBase + target.candidateRva) candidateImmutable
          candidateImageWord
    constructor
    · rw [originalOutcome]
      simp [NormalizedOutcomeExpr.eval, originalTarget]
    · rw [candidateOutcome]
      simp [NormalizedOutcomeExpr.eval, candidateTarget]

structure ImmutableIndirectJumpTargetClaim where
  targetId : Nat
  originalAddress : Nat
  candidateAddress : Nat
  originalAssembledRead : Bool
  candidateAssembledRead : Bool
  originalWrites : List RegisterOffsetWrite
  candidateWrites : List RegisterOffsetWrite
deriving Repr, DecidableEq

def ImmutableIndirectJumpTargetClaim.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectJumpTargetClaim) : Bool :=
  match context.codeMap.get? claim.targetId with
  | none => false
  | some target =>
      readImmutableImageWord context.originalPe claim.originalAddress 4 ==
          some (context.originalPe.imageBase + target.originalRva) &&
        readImmutableImageWord context.candidatePe claim.candidateAddress 4 ==
          some (context.candidatePe.imageBase + target.candidateRva) &&
        mappedRelocationWordPair context claim.originalAddress claim.candidateAddress &&
        originalBehavior.outcome == .indirectJump
          (immutableWordReadExpression claim.originalAssembledRead
            claim.originalAddress claim.originalWrites) &&
        candidateBehavior.outcome == .indirectJump
          (immutableWordReadExpression claim.candidateAssembledRead
            claim.candidateAddress claim.candidateWrites) &&
        registerOffsetWritesSeparated false sourceInvariant.addressSeparations
          claim.originalAddress claim.originalWrites &&
        registerOffsetWritesSeparated true sourceInvariant.addressSeparations
          claim.candidateAddress claim.candidateWrites

def ImmutableIndirectJumpTargetsClosed
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectJumpTargetClaim) : Prop :=
  match context.codeMap.get? claim.targetId with
  | none => False
  | some target =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
          originalBehavior.outcome.eval originalState = .indirectJump
              (BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva)) ∧
            candidateBehavior.outcome.eval candidateState = .indirectJump
              (BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva))

theorem immutableIndirectJumpTargetsClosed_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectJumpTargetClaim)
    (checked : claim.checked context sourceInvariant originalBehavior candidateBehavior = true) :
    ImmutableIndirectJumpTargetsClosed context sourceInvariant originalBehavior
      candidateBehavior claim := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
    simp [ImmutableIndirectJumpTargetClaim.checked, targetResult] at checked
  | some target =>
    simp only [ImmutableIndirectJumpTargetClaim.checked, targetResult] at checked
    simp only [ImmutableIndirectJumpTargetsClosed, targetResult]
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    rcases checked with
      ⟨⟨⟨⟨⟨⟨originalImageWord, candidateImageWord⟩, _mappedWord⟩,
        originalOutcome⟩, candidateOutcome⟩, originalSeparated⟩,
        candidateSeparated⟩
    intro world originalState candidateState related
    rcases related with
      ⟨_worldStatic, _stackRangesValid, _stackMemory, _importsStatic,
        _importsComplete, _importsMemory, originalImmutable, candidateImmutable,
        relatedCore, _importRegisters⟩
    rcases relatedCore with
      ⟨_registers, _bounds, separations, _stackWindows, _memory, _undefined,
        _x87, _flags, _fsBase⟩
    have originalSide := addressSeparationsRelated_original
      sourceInvariant.addressSeparations originalState.registers candidateState.registers
      separations
    have candidateSide := addressSeparationsRelated_candidate
      sourceInvariant.addressSeparations originalState.registers candidateState.registers
      separations
    have originalAvoids := registerOffsetWritesAvoidWord_of_checked false
      sourceInvariant.addressSeparations claim.originalAddress claim.originalWrites
      originalState originalSide originalSeparated
    have candidateAvoids := registerOffsetWritesAvoidWord_of_checked true
      sourceInvariant.addressSeparations claim.candidateAddress claim.candidateWrites
      candidateState candidateSide candidateSeparated
    have originalTarget :
        (immutableWordReadExpression claim.originalAssembledRead
          claim.originalAddress claim.originalWrites).eval originalState =
            BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva) := by
      cases assembled : claim.originalAssembledRead with
      | false =>
        simp only [immutableWordReadExpression, assembled, if_false, Expr.eval,
          machineStateRead32_eq_memoryRead32]
        exact ImmutableImageWordMemory.read32_of_checked context.originalPe
          originalState.memory claim.originalAddress
          (context.originalPe.imageBase + target.originalRva) originalImmutable
          originalImageWord
      | true =>
        simp only [immutableWordReadExpression, assembled, if_true]
        rw [Expr.eval_constantRead32AfterWrites]
        rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ originalAvoids]
        exact ImmutableImageWordMemory.read32_of_checked context.originalPe
          originalState.memory claim.originalAddress
          (context.originalPe.imageBase + target.originalRva) originalImmutable
          originalImageWord
    have candidateTarget :
        (immutableWordReadExpression claim.candidateAssembledRead
          claim.candidateAddress claim.candidateWrites).eval candidateState =
            BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva) := by
      cases assembled : claim.candidateAssembledRead with
      | false =>
        simp only [immutableWordReadExpression, assembled, if_false, Expr.eval,
          machineStateRead32_eq_memoryRead32]
        exact ImmutableImageWordMemory.read32_of_checked context.candidatePe
          candidateState.memory claim.candidateAddress
          (context.candidatePe.imageBase + target.candidateRva) candidateImmutable
          candidateImageWord
      | true =>
        simp only [immutableWordReadExpression, assembled, if_true]
        rw [Expr.eval_constantRead32AfterWrites]
        rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ candidateAvoids]
        exact ImmutableImageWordMemory.read32_of_checked context.candidatePe
          candidateState.memory claim.candidateAddress
          (context.candidatePe.imageBase + target.candidateRva) candidateImmutable
          candidateImageWord
    constructor
    · rw [originalOutcome]
      simp [NormalizedOutcomeExpr.eval, originalTarget]
    · rw [candidateOutcome]
      simp [NormalizedOutcomeExpr.eval, candidateTarget]

structure DynamicRangeIndirectCallClaim where
  rangeRelation : DynamicRegisterRangeRelation
  wordOffset : Nat
  continuationTargetId : Nat
deriving Repr, DecidableEq

def DynamicRangeIndirectCallClaim.originalTargetExpression
    (claim : DynamicRangeIndirectCallClaim) : Expr :=
  .read32 (.add (.inputReg claim.rangeRelation.original)
    (.constant claim.wordOffset))

def DynamicRangeIndirectCallClaim.candidateTargetExpression
    (claim : DynamicRangeIndirectCallClaim) : Expr :=
  .read32 (.add (.inputReg claim.rangeRelation.candidate)
    (.constant claim.wordOffset))

def DynamicRangeIndirectCallClaim.codeWord
    (claim : DynamicRangeIndirectCallClaim) : DynamicWordRelation := {
  offset := claim.rangeRelation.originalOffset + claim.wordOffset
  kind := .codePointer
}

def DynamicRangeIndirectCallClaim.checked (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRangeIndirectCallClaim) : Bool :=
  sourceInvariant.dynamicRegisterRangeRelations.contains claim.rangeRelation &&
    claim.rangeRelation.originalOffset == claim.rangeRelation.candidateOffset &&
    claim.rangeRelation.requiredWords.contains claim.codeWord &&
    originalBehavior.outcome == .indirectCall
      (.read32 (.add (.inputReg claim.rangeRelation.original)
        (.constant claim.wordOffset))) claim.continuationTargetId &&
    candidateBehavior.outcome == .indirectCall
      (.read32 (.add (.inputReg claim.rangeRelation.candidate)
        (.constant claim.wordOffset))) claim.continuationTargetId

def DynamicRangeIndirectCallTargetsClosed (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRangeIndirectCallClaim) : Prop :=
  ∀ context world originalState candidateState,
    StateRel context world sourceInvariant originalState candidateState →
      ∃ originalTarget candidateTarget,
        originalBehavior.outcome.eval originalState =
            .indirectCall originalTarget claim.continuationTargetId ∧
          candidateBehavior.outcome.eval candidateState =
            .indirectCall candidateTarget claim.continuationTargetId ∧
          codePointerRelated context.originalPe.imageBase
            context.candidatePe.imageBase context.codeMap.entries.toList
            originalTarget candidateTarget = true

theorem codePointerRelated_exists_target (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (original candidate : Word)
    (related : codePointerRelated originalImageBase candidateImageBase targets
      original candidate = true) :
    ∃ target, target ∈ targets ∧
      codeAddressMatches originalImageBase target.originalRva target.originalAliases
        original = true ∧
      codeAddressMatches candidateImageBase target.candidateRva target.candidateAliases
        candidate = true := by
  simpa only [codePointerRelated, List.any_eq_true, Bool.and_eq_true] using related

def DynamicRangeIndirectCallFiniteTargetsClosed (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRangeIndirectCallClaim) : Prop :=
  ∀ context world originalState candidateState,
    StateRel context world sourceInvariant originalState candidateState →
      ∃ originalTarget candidateTarget target,
        originalBehavior.outcome.eval originalState =
            .indirectCall originalTarget claim.continuationTargetId ∧
          candidateBehavior.outcome.eval candidateState =
            .indirectCall candidateTarget claim.continuationTargetId ∧
          target ∈ context.codeMap.entries.toList ∧
          codeAddressMatches context.originalPe.imageBase target.originalRva
            target.originalAliases originalTarget = true ∧
          codeAddressMatches context.candidatePe.imageBase target.candidateRva
            target.candidateAliases candidateTarget = true

theorem dynamicRangeIndirectCallFiniteTargetsClosed_of_targetsClosed
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRangeIndirectCallClaim)
    (closed : DynamicRangeIndirectCallTargetsClosed sourceInvariant originalBehavior
      candidateBehavior claim) :
    DynamicRangeIndirectCallFiniteTargetsClosed sourceInvariant originalBehavior
      candidateBehavior claim := by
  intro context world originalState candidateState related
  rcases closed context world originalState candidateState related with
    ⟨originalTarget, candidateTarget, originalOutcome, candidateOutcome,
      targetsRelated⟩
  rcases codePointerRelated_exists_target context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList originalTarget
      candidateTarget targetsRelated with
    ⟨target, targetMember, originalMatches, candidateMatches⟩
  exact ⟨originalTarget, candidateTarget, target, originalOutcome, candidateOutcome,
    targetMember, originalMatches, candidateMatches⟩

theorem dynamicRangeIndirectCallTargetsClosed_of_checked
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRangeIndirectCallClaim)
    (checked : claim.checked sourceInvariant originalBehavior
      candidateBehavior = true) :
    DynamicRangeIndirectCallTargetsClosed sourceInvariant originalBehavior
      candidateBehavior claim := by
  simp only [DynamicRangeIndirectCallClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨relationMember, offsetsEqual⟩, codeWordRequired⟩,
      originalOutcome⟩, candidateOutcome⟩
  intro context world originalState candidateState related
  have dynamicMemory := StateRel.dynamicRangesMemoryHold context world
    sourceInvariant originalState candidateState related
  rcases related with
    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable,
      _candidateImmutable, _relatedCore, _importAndDynamicRegisters⟩
  have dynamicRegisters := _importAndDynamicRegisters.2
  simp only [dynamicRegisterRangeRelationsHold, List.all_eq_true]
      at dynamicRegisters
  have relationHolds := dynamicRegisters claim.rangeRelation
    (by simpa using relationMember)
  simp only [DynamicRegisterRangeRelation.holds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at relationHolds
  rcases relationHolds with
    ⟨range, rangeMember,
      ⟨⟨originalRegister, candidateRegister⟩, requiredWords⟩⟩
  simp only [List.all_eq_true] at requiredWords
  have codeWordMember := requiredWords claim.codeWord
    (by simpa using codeWordRequired)
  have rangeWords := dynamicMemory range rangeMember
  simp only [DynamicAddressRangePair.wordsHold, List.all_eq_true] at rangeWords
  have codeWordsRelated := rangeWords claim.codeWord (by simpa using codeWordMember)
  simp only [DynamicWordRelation.holds, DynamicRangeIndirectCallClaim.codeWord]
      at codeWordsRelated
  have candidateOffset :
      claim.rangeRelation.candidateOffset = claim.rangeRelation.originalOffset :=
    offsetsEqual.symm
  let originalTarget := Memory.read32 originalState.memory
    (range.originalBase + BitVec.ofNat 32
      (claim.rangeRelation.originalOffset + claim.wordOffset))
  let candidateTarget := Memory.read32 candidateState.memory
    (range.candidateBase + BitVec.ofNat 32
      (claim.rangeRelation.originalOffset + claim.wordOffset))
  refine ⟨originalTarget, candidateTarget, ?_, ?_, codeWordsRelated⟩
  · rw [originalOutcome]
    simp only [NormalizedOutcomeExpr.eval, Expr.eval,
      machineStateRead32_eq_memoryRead32]
    rw [originalRegister]
    simp only [originalTarget, BitVec.ofNat_add, BitVec.add_assoc]
  · rw [candidateOutcome]
    simp only [NormalizedOutcomeExpr.eval, Expr.eval,
      machineStateRead32_eq_memoryRead32]
    rw [candidateRegister, candidateOffset]
    simp only [candidateTarget, BitVec.ofNat_add, BitVec.add_assoc]

theorem dynamicRangeIndirectCallFiniteTargetsClosed_of_checked
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRangeIndirectCallClaim)
    (checked : claim.checked sourceInvariant originalBehavior candidateBehavior = true) :
    DynamicRangeIndirectCallFiniteTargetsClosed sourceInvariant originalBehavior
      candidateBehavior claim :=
  dynamicRangeIndirectCallFiniteTargetsClosed_of_targetsClosed sourceInvariant
    originalBehavior candidateBehavior claim
    (dynamicRangeIndirectCallTargetsClosed_of_checked sourceInvariant originalBehavior
      candidateBehavior claim checked)

structure ImportRegisterIndirectCallClaim where
  imported : ExternalTarget
  originalRegister : Reg
  candidateRegister : Reg
  continuationTargetId : Nat
deriving Repr, DecidableEq

def ImportRegisterIndirectCallClaim.relation
    (claim : ImportRegisterIndirectCallClaim) : ImportRegisterRelation := {
  original := claim.originalRegister
  candidate := claim.candidateRegister
  imported := claim.imported
}

def ImportRegisterIndirectCallClaim.checked
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterIndirectCallClaim) : Bool :=
  sourceInvariant.importRegisterRelations.contains claim.relation &&
    originalBehavior.outcome == .indirectCall
      (.inputReg claim.originalRegister) claim.continuationTargetId &&
    candidateBehavior.outcome == .indirectCall
      (.inputReg claim.candidateRegister) claim.continuationTargetId

def ImportRegisterIndirectCallTargetsClosed
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterIndirectCallClaim) : Prop :=
  ∀ context world originalState candidateState,
    StateRel context world sourceInvariant originalState candidateState →
      ∃ binding, binding ∈ world.importAddresses ∧
        binding.imported = claim.imported ∧
        originalBehavior.outcome.eval originalState = .indirectCall
          binding.originalAddress claim.continuationTargetId ∧
        candidateBehavior.outcome.eval candidateState = .indirectCall
          binding.candidateAddress claim.continuationTargetId

theorem importRegisterIndirectCallTargetsClosed_of_checked
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterIndirectCallClaim)
    (checked : claim.checked sourceInvariant originalBehavior candidateBehavior = true) :
    ImportRegisterIndirectCallTargetsClosed sourceInvariant originalBehavior
      candidateBehavior claim := by
  simp only [ImportRegisterIndirectCallClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with ⟨⟨relationMember, originalOutcome⟩, candidateOutcome⟩
  intro context world originalState candidateState related
  rcases related with
    ⟨_worldStatic, _stackRangesValid, _stackMemory, _importsStatic, _importsComplete,
      _importsMemory, _originalImmutable, _candidateImmutable, _relatedCore,
      importRegisters⟩
  have importRegistersOnly := importRegisters.1
  simp only [importRegisterRelationsHold, List.all_eq_true] at importRegistersOnly
  have relationHolds := importRegistersOnly claim.relation (by simpa using relationMember)
  simp only [ImportRegisterRelation.holds, List.any_eq_true] at relationHolds
  rcases relationHolds with ⟨binding, bindingMember, bindingChecks⟩
  simp only [Bool.and_eq_true, beq_iff_eq] at bindingChecks
  rcases bindingChecks with ⟨⟨imported, originalAddress⟩, candidateAddress⟩
  change originalState.registers.get claim.originalRegister = binding.originalAddress at originalAddress
  change candidateState.registers.get claim.candidateRegister = binding.candidateAddress at candidateAddress
  refine ⟨binding, bindingMember, imported, ?_, ?_⟩
  · rw [originalOutcome]
    simp only [NormalizedOutcomeExpr.eval, Expr.eval]
    rw [originalAddress]
  · rw [candidateOutcome]
    simp only [NormalizedOutcomeExpr.eval, Expr.eval]
    rw [candidateAddress]

structure ImportRegisterSeedClaim where
  imported : ExternalTarget
  originalRegister : Reg
  candidateRegister : Reg
  originalIatRva : Nat
  candidateIatRva : Nat
  assembledRead : Bool := false
  originalWrites : List RegisterOffsetWrite := []
  candidateWrites : List RegisterOffsetWrite := []
deriving Repr, DecidableEq

def ImportRegisterSeedClaim.relation
    (claim : ImportRegisterSeedClaim) : ImportRegisterRelation := {
  original := claim.originalRegister
  candidate := claim.candidateRegister
  imported := claim.imported
}

def ImportRegisterSeedClaim.expectedExpression (claim : ImportRegisterSeedClaim)
    (address : Nat) (writes : List RegisterOffsetWrite) : Expr :=
  if claim.assembledRead then
    .constantRead32AfterWrites address (writes.map RegisterOffsetWrite.toWrite)
  else
    .read32 (.constant address)

def ImportRegisterSeedClaim.checked
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterSeedClaim) : Bool :=
  match importAtIatRva originalImports claim.originalIatRva,
      importAtIatRva candidateImports claim.candidateIatRva with
  | some originalImport, some candidateImport =>
        normalizeImport originalImport == claim.imported &&
        normalizeImport candidateImport == claim.imported &&
        originalBehavior.registers.get claim.originalRegister ==
          claim.expectedExpression
            (originalPe.imageBase + claim.originalIatRva)
            claim.originalWrites &&
        candidateBehavior.registers.get claim.candidateRegister ==
          claim.expectedExpression
            (candidatePe.imageBase + claim.candidateIatRva)
            claim.candidateWrites &&
        registerOffsetWritesSeparated false sourceInvariant.addressSeparations
          (originalPe.imageBase + claim.originalIatRva) claim.originalWrites &&
        registerOffsetWritesSeparated true sourceInvariant.addressSeparations
          (candidatePe.imageBase + claim.candidateIatRva) claim.candidateWrites
  | _, _ => false

def ImportRegisterSeedClosed
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterSeedClaim) : Prop :=
  ∃ originalImport candidateImport,
    importAtIatRva originalImports claim.originalIatRva = some originalImport ∧
    importAtIatRva candidateImports claim.candidateIatRva = some candidateImport ∧
    normalizeImport originalImport = claim.imported ∧
    normalizeImport candidateImport = claim.imported ∧
    originalBehavior.registers.get claim.originalRegister =
      claim.expectedExpression
        (originalPe.imageBase + claim.originalIatRva) claim.originalWrites ∧
    candidateBehavior.registers.get claim.candidateRegister =
      claim.expectedExpression
        (candidatePe.imageBase + claim.candidateIatRva) claim.candidateWrites ∧
    registerOffsetWritesSeparated false sourceInvariant.addressSeparations
      (originalPe.imageBase + claim.originalIatRva) claim.originalWrites = true ∧
    registerOffsetWritesSeparated true sourceInvariant.addressSeparations
      (candidatePe.imageBase + claim.candidateIatRva) claim.candidateWrites = true

theorem importRegisterSeedClosed_of_checked
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterSeedClaim)
    (checked : claim.checked originalPe candidatePe originalImports candidateImports
      sourceInvariant originalBehavior candidateBehavior = true) :
    ImportRegisterSeedClosed originalPe candidatePe originalImports candidateImports
      sourceInvariant originalBehavior candidateBehavior claim := by
  unfold ImportRegisterSeedClaim.checked at checked
  unfold ImportRegisterSeedClosed
  cases originalResult : importAtIatRva originalImports claim.originalIatRva with
  | none => simp [originalResult] at checked
  | some originalImport =>
      cases candidateResult : importAtIatRva candidateImports claim.candidateIatRva with
      | none => simp [originalResult, candidateResult] at checked
      | some candidateImport =>
          simp only [originalResult, candidateResult, Bool.and_eq_true,
            beq_iff_eq] at checked
          rcases checked with ⟨⟨⟨⟨⟨originalImported, candidateImported⟩,
            originalRegister⟩, candidateRegister⟩, originalSeparated⟩,
            candidateSeparated⟩
          refine ⟨originalImport, candidateImport, ?_, ?_, originalImported,
            candidateImported, originalRegister, candidateRegister,
            originalSeparated, candidateSeparated⟩
          · simpa using originalResult
          · simpa using candidateResult

theorem importRegisterSeedOutputHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterSeedClaim)
    (checked : claim.checked context.originalPe context.candidatePe
      context.originalImports context.candidateImports sourceInvariant
      originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.relation.holds world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  rcases importRegisterSeedClosed_of_checked context.originalPe context.candidatePe
      context.originalImports context.candidateImports sourceInvariant
      originalBehavior candidateBehavior
      claim checked with
    ⟨originalImport, candidateImport, originalFound, candidateFound,
      originalIdentity, candidateIdentity, originalRegister, candidateRegister,
      originalSeparated, candidateSeparated⟩
  rcases related with
    ⟨_worldStatic, _stackRangesValid, _stackMemory, importsStatic, importsComplete,
      importsMemory, _originalImmutable, _candidateImmutable, relatedCore,
      _importRegisters⟩
  rcases relatedCore with
    ⟨_registers, _bounds, separations, _stackWindows, _memory, _undefined,
      _x87, _flags, _fsBase⟩
  have originalSide := addressSeparationsRelated_original
    sourceInvariant.addressSeparations originalState.registers candidateState.registers
    separations
  have candidateSide := addressSeparationsRelated_candidate
    sourceInvariant.addressSeparations originalState.registers candidateState.registers
    separations
  have originalAvoids := registerOffsetWritesAvoidWord_of_checked false
    sourceInvariant.addressSeparations
    (context.originalPe.imageBase + claim.originalIatRva) claim.originalWrites
    originalState originalSide originalSeparated
  have candidateAvoids := registerOffsetWritesAvoidWord_of_checked true
    sourceInvariant.addressSeparations
    (context.candidatePe.imageBase + claim.candidateIatRva) claim.candidateWrites
    candidateState candidateSide candidateSeparated
  have originalMember : originalImport ∈ context.originalImports := by
    unfold importAtIatRva at originalFound
    exact List.mem_of_find?_eq_some originalFound
  have originalFoundRva : originalImport.iatRva = claim.originalIatRva := by
    unfold importAtIatRva at originalFound
    have matched := List.find?_some originalFound
    simpa only [beq_iff_eq] using matched
  have candidateMember : candidateImport ∈ context.candidateImports := by
    unfold importAtIatRva at candidateFound
    exact List.mem_of_find?_eq_some candidateFound
  have candidateFoundRva : candidateImport.iatRva = claim.candidateIatRva := by
    unfold importAtIatRva at candidateFound
    have matched := List.find?_some candidateFound
    simpa only [beq_iff_eq] using matched
  simp only [RelationalWorld.importAddressesComplete, Bool.and_eq_true,
    List.all_eq_true] at importsComplete
  have originalCovered := importsComplete.1 originalImport originalMember
  have candidateCovered := importsComplete.2 candidateImport candidateMember
  simp only [List.any_eq_true, Bool.and_eq_true, beq_iff_eq] at originalCovered
  simp only [List.any_eq_true, Bool.and_eq_true, beq_iff_eq] at candidateCovered
  rcases originalCovered with
    ⟨originalBinding, originalBindingMember,
      originalBindingRva, originalBindingIdentity⟩
  rcases candidateCovered with
    ⟨candidateBinding, candidateBindingMember,
      candidateBindingRva, candidateBindingIdentity⟩
  simp only [RelationalWorld.importAddressesStaticValid, Bool.and_eq_true] at importsStatic
  rcases importsStatic with ⟨⟨⟨_idsUnique, _iatPairsUnique⟩, identitiesConsistent⟩,
    _bindingsStatic⟩
  simp only [importAddressIdentitiesConsistent, List.all_eq_true] at identitiesConsistent
  have bindingAddresses := identitiesConsistent originalBinding originalBindingMember
    candidateBinding candidateBindingMember
  have originalBindingImported : originalBinding.imported = claim.imported := by
    rw [originalBindingIdentity, originalIdentity]
  have candidateBindingImported : candidateBinding.imported = claim.imported := by
    rw [candidateBindingIdentity, candidateIdentity]
  have candidateAddressesEqual :
      candidateBinding.candidateAddress = originalBinding.candidateAddress := by
    have sameImported : candidateBinding.imported = originalBinding.imported := by
      rw [candidateBindingImported, originalBindingImported]
    have sameCheck : (candidateBinding.imported == originalBinding.imported) = true :=
      beq_iff_eq.mpr sameImported
    simp only [sameCheck, if_true, Bool.and_eq_true, beq_iff_eq] at bindingAddresses
    exact bindingAddresses.2
  have originalMemory := importsMemory originalBinding originalBindingMember
  have candidateMemory := importsMemory candidateBinding candidateBindingMember
  have originalRegisterValue :
      (originalBehavior.eval originalState).registers.get claim.originalRegister =
        originalBinding.originalAddress := by
    simp only [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, originalRegister]
    cases assembled : claim.assembledRead with
    | true =>
      simp only [ImportRegisterSeedClaim.expectedExpression, assembled, if_true]
      rw [Expr.eval_constantRead32AfterWrites]
      rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ originalAvoids]
      rw [← originalFoundRva, ← originalBindingRva, originalMemory.1]
    | false =>
      simp [ImportRegisterSeedClaim.expectedExpression, assembled, Expr.eval,
        machineStateRead32_eq_memoryRead32]
      rw [← originalFoundRva, ← originalBindingRva, originalMemory.1]
  have candidateRegisterValue :
      (candidateBehavior.eval candidateState).registers.get claim.candidateRegister =
        candidateBinding.candidateAddress := by
    simp only [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, candidateRegister]
    cases assembled : claim.assembledRead with
    | true =>
      simp only [ImportRegisterSeedClaim.expectedExpression, assembled, if_true]
      rw [Expr.eval_constantRead32AfterWrites]
      rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ candidateAvoids]
      rw [← candidateFoundRva, ← candidateBindingRva, candidateMemory.2]
    | false =>
      simp [ImportRegisterSeedClaim.expectedExpression, assembled, Expr.eval,
        machineStateRead32_eq_memoryRead32]
      rw [← candidateFoundRva, ← candidateBindingRva, candidateMemory.2]
  unfold ImportRegisterSeedClaim.relation ImportRegisterRelation.holds
  simp only [List.any_eq_true]
  refine ⟨originalBinding, originalBindingMember, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨originalBindingImported, ?_⟩, ?_⟩
  · exact originalRegisterValue
  · rw [candidateRegisterValue, candidateAddressesEqual]

structure ImportRegisterPreserveClaim where
  imported : ExternalTarget
  sourceOriginalRegister : Reg
  sourceCandidateRegister : Reg
  targetOriginalRegister : Reg
  targetCandidateRegister : Reg
deriving Repr, DecidableEq

def ImportRegisterPreserveClaim.sourceRelation
    (claim : ImportRegisterPreserveClaim) : ImportRegisterRelation := {
  original := claim.sourceOriginalRegister
  candidate := claim.sourceCandidateRegister
  imported := claim.imported
}

def ImportRegisterPreserveClaim.targetRelation
    (claim : ImportRegisterPreserveClaim) : ImportRegisterRelation := {
  original := claim.targetOriginalRegister
  candidate := claim.targetCandidateRegister
  imported := claim.imported
}

def ImportRegisterPreserveClaim.checked
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterPreserveClaim) : Bool :=
  sourceInvariant.importRegisterRelations.contains claim.sourceRelation &&
    targetInvariant.importRegisterRelations.contains claim.targetRelation &&
    originalBehavior.registers.get claim.targetOriginalRegister ==
      .inputReg claim.sourceOriginalRegister &&
    candidateBehavior.registers.get claim.targetCandidateRegister ==
      .inputReg claim.sourceCandidateRegister

theorem importRegisterPreserveOutputHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterPreserveClaim)
    (checked : claim.checked sourceInvariant targetInvariant originalBehavior
      candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.targetRelation.holds world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [ImportRegisterPreserveClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨sourceMember, _targetMember⟩, originalRegister⟩, candidateRegister⟩
  rcases related with
    ⟨_worldStatic, _stackRangesValid, _stackMemory, _importsStatic, _importsComplete,
      _importsMemory, _originalImmutable, _candidateImmutable, _relatedCore,
      importRegisters⟩
  have importRegistersOnly := importRegisters.1
  simp only [importRegisterRelationsHold, List.all_eq_true] at importRegistersOnly
  have sourceHolds := importRegistersOnly claim.sourceRelation (by simpa using sourceMember)
  simp only [ImportRegisterRelation.holds, List.any_eq_true] at sourceHolds
  rcases sourceHolds with ⟨binding, bindingMember, bindingChecks⟩
  simp only [Bool.and_eq_true, beq_iff_eq] at bindingChecks
  rcases bindingChecks with ⟨⟨imported, originalAddress⟩, candidateAddress⟩
  unfold ImportRegisterPreserveClaim.targetRelation ImportRegisterRelation.holds
  simp only [List.any_eq_true]
  refine ⟨binding, bindingMember, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨imported, ?_⟩, ?_⟩
  · simp only [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, originalRegister, Expr.eval]
    exact originalAddress
  · simp only [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, candidateRegister, Expr.eval]
    exact candidateAddress

structure DynamicRegisterRangePreserveClaim where
  sourceRelation : DynamicRegisterRangeRelation
  targetRelation : DynamicRegisterRangeRelation
deriving Repr, DecidableEq

def DynamicRegisterRangePreserveClaim.checked
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRegisterRangePreserveClaim) : Bool :=
  sourceInvariant.dynamicRegisterRangeRelations.contains claim.sourceRelation &&
    targetInvariant.dynamicRegisterRangeRelations.contains claim.targetRelation &&
    claim.sourceRelation.originalOffset == claim.targetRelation.originalOffset &&
    claim.sourceRelation.candidateOffset == claim.targetRelation.candidateOffset &&
    claim.targetRelation.requiredWords.all
      claim.sourceRelation.requiredWords.contains &&
    originalBehavior.registers.get claim.targetRelation.original ==
      .inputReg claim.sourceRelation.original &&
    candidateBehavior.registers.get claim.targetRelation.candidate ==
      .inputReg claim.sourceRelation.candidate

theorem dynamicRegisterRangePreserveOutputHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRegisterRangePreserveClaim)
    (checked : claim.checked sourceInvariant targetInvariant originalBehavior
      candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.targetRelation.holds world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [DynamicRegisterRangePreserveClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨sourceMember, _targetMember⟩, originalOffset⟩,
      candidateOffset⟩, requiredWordsSubset⟩, originalRegister⟩,
      candidateRegister⟩
  rcases related with
    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable,
      _candidateImmutable, _relatedCore, _importAndDynamicRegisters⟩
  have dynamicRegisters := _importAndDynamicRegisters.2
  simp only [dynamicRegisterRangeRelationsHold, List.all_eq_true]
      at dynamicRegisters
  have sourceHolds := dynamicRegisters claim.sourceRelation
    (by simpa using sourceMember)
  simp only [DynamicRegisterRangeRelation.holds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at sourceHolds
  rcases sourceHolds with
    ⟨range, rangeMember,
      ⟨⟨sourceOriginalRegister, sourceCandidateRegister⟩,
        sourceRequiredWords⟩⟩
  unfold DynamicRegisterRangeRelation.holds
  simp only [List.any_eq_true]
  refine ⟨range, rangeMember, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · simp only [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, originalRegister, Expr.eval]
    rw [← originalOffset]
    exact sourceOriginalRegister
  · simp only [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, candidateRegister, Expr.eval]
    rw [← candidateOffset]
    exact sourceCandidateRegister
  · simp only [List.all_eq_true] at sourceRequiredWords requiredWordsSubset ⊢
    intro word wordMember
    exact sourceRequiredWords word
      (by simpa using requiredWordsSubset word wordMember)

structure DynamicRangeArgumentClaim where
  rangeRelation : DynamicRegisterRangeRelation
  wordRelation : DynamicWordRelation
  originalReadOffset : Nat
  candidateReadOffset : Nat
deriving Repr, DecidableEq

def dynamicRangeArgumentExpression (register : Reg) (offset : Nat) : Expr :=
  .read32 ((Expr.inputReg register).offset offset)

def DynamicRangeArgumentClaim.checked (sourceInvariant : StateInvariant)
    (originalExpression candidateExpression : Expr)
    (claim : DynamicRangeArgumentClaim) : Bool :=
  sourceInvariant.dynamicRegisterRangeRelations.contains claim.rangeRelation &&
    claim.wordRelation.kind == .relatedWord &&
    claim.rangeRelation.requiredWords.contains claim.wordRelation &&
    claim.rangeRelation.originalOffset + claim.originalReadOffset ==
      claim.wordRelation.offset &&
    claim.rangeRelation.candidateOffset + claim.candidateReadOffset ==
      claim.wordRelation.offset &&
    originalExpression == dynamicRangeArgumentExpression
      claim.rangeRelation.original claim.originalReadOffset &&
    candidateExpression == dynamicRangeArgumentExpression
      claim.rangeRelation.candidate claim.candidateReadOffset

theorem dynamicRangeArgumentWordsRelated_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalExpression candidateExpression : Expr)
    (claim : DynamicRangeArgumentClaim)
    (checked : claim.checked sourceInvariant originalExpression
      candidateExpression = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (originalExpression.eval originalState) (candidateExpression.eval candidateState) =
      true := by
  simp only [DynamicRangeArgumentClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨sourceMember, wordKind⟩, wordMember⟩, originalWordOffset⟩,
      candidateWordOffset⟩, originalExpressionExact⟩, candidateExpressionExact⟩
  have dynamicRegisters := related.2.2.2.2.2.2.2.2.2.2
  simp only [dynamicRegisterRangeRelationsHold, List.all_eq_true]
      at dynamicRegisters
  have rangeHolds := dynamicRegisters claim.rangeRelation
    (by simpa using sourceMember)
  simp only [DynamicRegisterRangeRelation.holds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at rangeHolds
  rcases rangeHolds with
    ⟨range, rangeMember,
      ⟨⟨originalRegister, candidateRegister⟩, requiredWords⟩⟩
  simp only [List.all_eq_true] at requiredWords
  have wordInRequired : claim.wordRelation ∈ claim.rangeRelation.requiredWords := by
    simpa using wordMember
  have wordInRange : claim.wordRelation ∈ range.wordRelations := by
    have contained := requiredWords claim.wordRelation wordInRequired
    simpa using contained
  have dynamicMemory := related.dynamicRangesMemoryHold context world
    sourceInvariant originalState candidateState
  have wordsHold := dynamicMemory range rangeMember
  simp only [DynamicAddressRangePair.wordsHold, List.all_eq_true] at wordsHold
  have wordHolds := wordsHold claim.wordRelation wordInRange
  simp only [DynamicWordRelation.holds, wordKind] at wordHolds
  rw [originalExpressionExact, candidateExpressionExact]
  simp only [dynamicRangeArgumentExpression, Expr.eval,
    machineStateRead32_eq_memoryRead32, evalInputRegisterOffset]
  rw [originalRegister, candidateRegister]
  have originalAddress :
      range.originalBase + BitVec.ofNat 32 claim.rangeRelation.originalOffset +
          BitVec.ofNat 32 claim.originalReadOffset =
        range.originalBase + BitVec.ofNat 32 claim.wordRelation.offset := by
    rw [BitVec.add_assoc, ← BitVec.ofNat_add, originalWordOffset]
  have candidateAddress :
      range.candidateBase + BitVec.ofNat 32 claim.rangeRelation.candidateOffset +
          BitVec.ofNat 32 claim.candidateReadOffset =
        range.candidateBase + BitVec.ofNat 32 claim.wordRelation.offset := by
    rw [BitVec.add_assoc, ← BitVec.ofNat_add, candidateWordOffset]
  rw [originalAddress, candidateAddress]
  exact wordHolds

structure StackWindowArgumentClaim where
  window : StackWindowPair
  offset : Nat
  originalAssembledRead : Bool := false
  candidateAssembledRead : Bool := false
deriving Repr, DecidableEq

def stackWindowArgumentAddress (register : Reg) (offset : Nat) : Expr :=
  (Expr.inputReg register).offset offset

def stackWindowAssembledArgument (register : Reg) (offset : Nat) : Expr :=
  let byteAddress (byteOffset : Nat) :=
    stackWindowArgumentAddress register (offset + byteOffset)
  .bitOr
    (.bitOr (.read8 (byteAddress 0))
      (.shiftLeft (.read8 (byteAddress 1)) 8))
    (.bitOr (.shiftLeft (.read8 (byteAddress 2)) 16)
      (.shiftLeft (.read8 (byteAddress 3)) 24))

def StackWindowArgumentClaim.expectedExpression
    (claim : StackWindowArgumentClaim) (assembledRead : Bool)
    (register : Reg) : Expr :=
  let address := stackWindowArgumentAddress register claim.offset
  if assembledRead then stackWindowAssembledArgument register claim.offset
  else .read32 address

def StackWindowArgumentClaim.checked (sourceInvariant : StateInvariant)
    (originalExpression candidateExpression : Expr)
    (claim : StackWindowArgumentClaim) : Bool :=
  sourceInvariant.stackWindows.contains claim.window &&
    claim.offset + 4 <= claim.window.bytesAbove &&
    claim.offset % 4 == 0 &&
    originalExpression == claim.expectedExpression claim.originalAssembledRead
      claim.window.originalRegister &&
    candidateExpression == claim.expectedExpression claim.candidateAssembledRead
      claim.window.candidateRegister

theorem stackWindowArgumentWordsRelated_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalExpression candidateExpression : Expr)
    (claim : StackWindowArgumentClaim)
    (checked : claim.checked sourceInvariant originalExpression
      candidateExpression = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (originalExpression.eval originalState) (candidateExpression.eval candidateState) =
      true := by
  simp only [StackWindowArgumentClaim.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨windowMember, inside⟩, aligned⟩, originalExpressionExact⟩,
      candidateExpressionExact⟩
  have readsRelated := related.stackMemoryRead32Related context world sourceInvariant
    originalState candidateState claim.window claim.offset
      (by simpa using windowMember) inside (by simpa using aligned)
  have originalEvaluation :
      (claim.expectedExpression claim.originalAssembledRead
        claim.window.originalRegister).eval originalState =
      Memory.read32 originalState.memory
        (originalState.registers.get claim.window.originalRegister +
          BitVec.ofNat 32 claim.offset) := by
    cases assembled : claim.originalAssembledRead with
    | false =>
        simp [StackWindowArgumentClaim.expectedExpression, assembled,
          stackWindowArgumentAddress, Expr.eval, machineStateRead32_eq_memoryRead32,
          evalInputRegisterOffset]
    | true =>
        simp [StackWindowArgumentClaim.expectedExpression, assembled,
          stackWindowAssembledArgument, stackWindowArgumentAddress, Expr.eval,
          evalInputRegisterOffset, BitVec.ofNat_add]
        simpa only [BitVec.add_assoc] using
          assembledMemoryRead32_eq originalState.memory
            (originalState.registers.get claim.window.originalRegister +
              BitVec.ofNat 32 claim.offset)
  have candidateEvaluation :
      (claim.expectedExpression claim.candidateAssembledRead
        claim.window.candidateRegister).eval candidateState =
      Memory.read32 candidateState.memory
        (candidateState.registers.get claim.window.candidateRegister +
          BitVec.ofNat 32 claim.offset) := by
    cases assembled : claim.candidateAssembledRead with
    | false =>
        simp [StackWindowArgumentClaim.expectedExpression, assembled,
          stackWindowArgumentAddress, Expr.eval, machineStateRead32_eq_memoryRead32,
          evalInputRegisterOffset]
    | true =>
        simp [StackWindowArgumentClaim.expectedExpression, assembled,
          stackWindowAssembledArgument, stackWindowArgumentAddress, Expr.eval,
          evalInputRegisterOffset, BitVec.ofNat_add]
        simpa only [BitVec.add_assoc] using
          assembledMemoryRead32_eq candidateState.memory
            (candidateState.registers.get claim.window.candidateRegister +
              BitVec.ofNat 32 claim.offset)
  rw [originalExpressionExact, candidateExpressionExact, originalEvaluation,
    candidateEvaluation]
  exact readsRelated

def dynamicPointerReadExpression (register : Reg) (offset : Nat) : Expr :=
  .read32 (.add (.inputReg register) (.constant offset))

def dynamicPointerNonzeroGuard (register : Reg) (offset : Nat) : BoolExpr :=
  let value := dynamicPointerReadExpression register offset
  .not (.equal (.bitAnd value value) (.constant 0))

def staticDynamicPointerReadExpression (address : Word) : Expr :=
  .read32 (.constant address.toNat)

def staticDynamicPointerZeroGuard (address : Word) : BoolExpr :=
  let value := staticDynamicPointerReadExpression address
  .equal (.bitAnd value value) (.constant 0)

def staticDynamicPointerNonzeroGuard (address : Word) : BoolExpr :=
  .not (staticDynamicPointerZeroGuard address)

inductive StaticDynamicPointerGuardKind where
  | zero
  | nonzero
deriving Repr, DecidableEq

def StaticDynamicPointerGuardKind.expression
    (kind : StaticDynamicPointerGuardKind) (address : Word) : BoolExpr :=
  match kind with
  | .zero => staticDynamicPointerZeroGuard address
  | .nonzero => staticDynamicPointerNonzeroGuard address

structure StaticDynamicPointerGuardClaim where
  slot : StaticDynamicPointerSlotPair
  kind : StaticDynamicPointerGuardKind
deriving Repr, DecidableEq

def StaticDynamicPointerGuardClaim.checked (context : StaticProofContext)
    (originalGuard candidateGuard : BoolExpr)
    (claim : StaticDynamicPointerGuardClaim) : Bool :=
  context.staticDynamicPointerSlots.contains claim.slot &&
    originalGuard == claim.kind.expression claim.slot.originalAddress &&
    candidateGuard == claim.kind.expression claim.slot.candidateAddress

theorem staticDynamicPointerGuardsAgree_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalGuard candidateGuard : BoolExpr)
    (claim : StaticDynamicPointerGuardClaim)
    (checked : claim.checked context originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalGuard.eval originalState = candidateGuard.eval candidateState := by
  simp only [StaticDynamicPointerGuardClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with ⟨⟨slotMember, originalGuardExact⟩, candidateGuardExact⟩
  have slotsMemory := related.staticDynamicPointerSlotsMemoryHold context world
    sourceInvariant originalState candidateState
  have slotHolds := slotsMemory claim.slot (by simpa using slotMember)
  simp only [StaticDynamicPointerSlotPair.memoryHolds] at slotHolds
  simp at slotHolds
  have zeroIff :
      Memory.read32 originalState.memory claim.slot.originalAddress =
          BitVec.ofNat 32 0 ↔
        Memory.read32 candidateState.memory claim.slot.candidateAddress =
          BitVec.ofNat 32 0 := by
    rcases slotHolds with zeroWords | ⟨targetRange, _targetRangeMember,
        ⟨⟨⟨⟨originalTarget, candidateTarget⟩, originalTargetNonzero⟩,
          candidateTargetNonzero⟩, _targetHasShape⟩⟩
    · rw [zeroWords.1, zeroWords.2]
    · rw [originalTarget, candidateTarget]
      exact ⟨fun originalZero => (originalTargetNonzero originalZero).elim,
        fun candidateZero => (candidateTargetNonzero candidateZero).elim⟩
  rw [originalGuardExact, candidateGuardExact]
  cases claim.kind <;>
    simpa [StaticDynamicPointerGuardKind.expression,
      staticDynamicPointerZeroGuard, staticDynamicPointerNonzeroGuard,
      staticDynamicPointerReadExpression, BoolExpr.eval, Expr.eval,
      machineStateRead32_eq_memoryRead32] using zeroIff

structure StaticDynamicPointerZeroOutputClaim where
  slot : StaticDynamicPointerSlotPair
  output : RegisterRelationPair
deriving Repr, DecidableEq

def StaticDynamicPointerZeroOutputClaim.checked (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalGuard candidateGuard : BoolExpr)
    (claim : StaticDynamicPointerZeroOutputClaim) : Bool :=
  context.staticDynamicPointerSlots.contains claim.slot &&
    claim.output.relation == .relatedWord &&
    originalBehavior.registers.get claim.output.original ==
      staticDynamicPointerReadExpression claim.slot.originalAddress &&
    candidateBehavior.registers.get claim.output.candidate ==
      staticDynamicPointerReadExpression claim.slot.candidateAddress &&
    originalGuard == staticDynamicPointerZeroGuard claim.slot.originalAddress &&
    candidateGuard == staticDynamicPointerZeroGuard claim.slot.candidateAddress

def StaticDynamicPointerZeroOutputClaim.guardClaim
    (claim : StaticDynamicPointerZeroOutputClaim) :
    StaticDynamicPointerGuardClaim := {
  slot := claim.slot
  kind := .zero
}

theorem staticDynamicPointerZeroOutputRelated_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalGuard candidateGuard : BoolExpr)
    (claim : StaticDynamicPointerZeroOutputClaim)
    (checked : claim.checked context originalBehavior candidateBehavior
      originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (guardTrue : originalGuard.eval originalState = true) :
    claim.output.relation.holds context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) =
        true := by
  simp only [StaticDynamicPointerZeroOutputClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨slotMember, outputKind⟩, originalRegister⟩,
      candidateRegister⟩, originalGuardExact⟩, candidateGuardExact⟩
  have guardChecked : claim.guardClaim.checked context originalGuard candidateGuard =
      true := by
    simp only [StaticDynamicPointerGuardClaim.checked,
      StaticDynamicPointerZeroOutputClaim.guardClaim, Bool.and_eq_true,
      beq_iff_eq]
    exact ⟨⟨slotMember, by
      simpa [StaticDynamicPointerGuardKind.expression] using originalGuardExact⟩,
      by simpa [StaticDynamicPointerGuardKind.expression] using candidateGuardExact⟩
  have guardAgreement := staticDynamicPointerGuardsAgree_of_checked context world
    sourceInvariant originalGuard candidateGuard claim.guardClaim guardChecked
    originalState candidateState related
  have candidateGuardTrue : candidateGuard.eval candidateState = true := by
    rw [← guardAgreement]
    exact guardTrue
  have originalZero :
      Memory.read32 originalState.memory claim.slot.originalAddress =
        BitVec.ofNat 32 0 := by
    rw [originalGuardExact] at guardTrue
    simpa [staticDynamicPointerZeroGuard, staticDynamicPointerReadExpression,
      BoolExpr.eval, Expr.eval, machineStateRead32_eq_memoryRead32] using guardTrue
  have candidateZero :
      Memory.read32 candidateState.memory claim.slot.candidateAddress =
        BitVec.ofNat 32 0 := by
    rw [candidateGuardExact] at candidateGuardTrue
    simpa [staticDynamicPointerZeroGuard, staticDynamicPointerReadExpression,
      BoolExpr.eval, Expr.eval, machineStateRead32_eq_memoryRead32]
      using candidateGuardTrue
  rw [outputKind]
  simp only [NormalizedSymbolicBehavior.eval_registers,
    evalNormalizedRegisters_get, originalRegister, candidateRegister,
    staticDynamicPointerReadExpression, Expr.eval,
    machineStateRead32_eq_memoryRead32]
  simpa [RegisterValueRelation.holds, originalZero, candidateZero]

structure StaticDynamicPointerSeedClaim where
  slot : StaticDynamicPointerSlotPair
  targetRelation : DynamicRegisterRangeRelation
deriving Repr, DecidableEq

def StaticDynamicPointerSeedClaim.checked (context : StaticProofContext)
    (targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalGuard candidateGuard : BoolExpr)
    (claim : StaticDynamicPointerSeedClaim) : Bool :=
  context.staticDynamicPointerSlots.contains claim.slot &&
    targetInvariant.dynamicRegisterRangeRelations.contains claim.targetRelation &&
    claim.targetRelation.originalOffset == 0 &&
    claim.targetRelation.candidateOffset == 0 &&
    claim.targetRelation.requiredWords.all claim.slot.requiredWords.contains &&
    originalBehavior.registers.get claim.targetRelation.original ==
      staticDynamicPointerReadExpression claim.slot.originalAddress &&
    candidateBehavior.registers.get claim.targetRelation.candidate ==
      staticDynamicPointerReadExpression claim.slot.candidateAddress &&
    originalGuard == staticDynamicPointerNonzeroGuard claim.slot.originalAddress &&
    candidateGuard == staticDynamicPointerNonzeroGuard claim.slot.candidateAddress

def StaticDynamicPointerSeedClaim.guardClaim
    (claim : StaticDynamicPointerSeedClaim) : StaticDynamicPointerGuardClaim := {
  slot := claim.slot
  kind := .nonzero
}

theorem staticDynamicPointerSeedGuardsAgree_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalGuard candidateGuard : BoolExpr)
    (claim : StaticDynamicPointerSeedClaim)
    (checked : claim.checked context targetInvariant originalBehavior
      candidateBehavior originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalGuard.eval originalState = candidateGuard.eval candidateState := by
  apply staticDynamicPointerGuardsAgree_of_checked context world sourceInvariant
    originalGuard candidateGuard claim.guardClaim
  · simp only [StaticDynamicPointerGuardClaim.checked,
      StaticDynamicPointerSeedClaim.guardClaim, Bool.and_eq_true, beq_iff_eq]
    simp only [StaticDynamicPointerSeedClaim.checked, Bool.and_eq_true,
      beq_iff_eq] at checked
    rcases checked with
      ⟨⟨⟨⟨⟨⟨⟨⟨slotMember, _targetMember⟩, _targetOriginalOffset⟩,
        _targetCandidateOffset⟩, _targetWordsSubset⟩, _originalRegister⟩,
        _candidateRegister⟩, originalGuardExact⟩, candidateGuardExact⟩
    exact ⟨⟨slotMember, by
      simpa [StaticDynamicPointerGuardKind.expression] using originalGuardExact⟩,
      by simpa [StaticDynamicPointerGuardKind.expression] using candidateGuardExact⟩
  · exact related

theorem staticDynamicPointerSeedOutputHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalGuard candidateGuard : BoolExpr)
    (claim : StaticDynamicPointerSeedClaim)
    (checked : claim.checked context targetInvariant originalBehavior
      candidateBehavior originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (guardTrue : originalGuard.eval originalState = true) :
    claim.targetRelation.holds world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [StaticDynamicPointerSeedClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨⟨slotMember, _targetMember⟩, targetOriginalOffset⟩,
      targetCandidateOffset⟩, targetWordsSubset⟩, originalRegister⟩,
      candidateRegister⟩, originalGuardExact⟩, _candidateGuardExact⟩
  have slotsMemory := related.staticDynamicPointerSlotsMemoryHold context world
    sourceInvariant originalState candidateState
  have slotHolds := slotsMemory claim.slot (by simpa using slotMember)
  simp only [StaticDynamicPointerSlotPair.memoryHolds] at slotHolds
  have originalNonzero :
      Memory.read32 originalState.memory claim.slot.originalAddress ≠
        BitVec.ofNat 32 0 := by
    rw [originalGuardExact] at guardTrue
    intro originalZero
    simp [staticDynamicPointerNonzeroGuard, staticDynamicPointerZeroGuard,
      staticDynamicPointerReadExpression, BoolExpr.eval, Expr.eval,
      machineStateRead32_eq_memoryRead32, originalZero] at guardTrue
  simp at slotHolds
  rcases slotHolds with zeroWords | ⟨targetRange, targetRangeMember,
      ⟨⟨⟨⟨originalTarget, candidateTarget⟩, _originalTargetNonzero⟩,
        _candidateTargetNonzero⟩, targetHasShape⟩⟩
  · exact (originalNonzero zeroWords.1).elim
  · unfold DynamicRegisterRangeRelation.holds
    simp only [List.any_eq_true]
    refine ⟨targetRange, targetRangeMember, ?_⟩
    simp only [Bool.and_eq_true, beq_iff_eq]
    refine ⟨⟨?_, ?_⟩, ?_⟩
    · simp only [NormalizedSymbolicBehavior.eval_registers,
        evalNormalizedRegisters_get, originalRegister,
        staticDynamicPointerReadExpression, Expr.eval,
        machineStateRead32_eq_memoryRead32]
      simpa [targetOriginalOffset] using originalTarget
    · simp only [NormalizedSymbolicBehavior.eval_registers,
        evalNormalizedRegisters_get, candidateRegister,
        staticDynamicPointerReadExpression, Expr.eval,
        machineStateRead32_eq_memoryRead32]
      simpa [targetCandidateOffset] using candidateTarget
    · simp only [List.all_eq_true] at targetWordsSubset targetHasShape ⊢
      intro word wordMember
      have wordInSlot : word ∈ claim.slot.requiredWords := by
        simpa using targetWordsSubset word wordMember
      simpa using targetHasShape word wordInSlot

structure DynamicRegisterRangeNextClaim where
  sourceRelation : DynamicRegisterRangeRelation
  targetRelation : DynamicRegisterRangeRelation
  pointerOffset : Nat
deriving Repr, DecidableEq

def DynamicRegisterRangeNextClaim.pointerRelation
    (claim : DynamicRegisterRangeNextClaim) : DynamicWordRelation := {
  offset := claim.pointerOffset
  kind := .nullableDynamicPointer
}

def DynamicRegisterRangeNextClaim.checked
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalGuard candidateGuard : BoolExpr)
    (claim : DynamicRegisterRangeNextClaim) : Bool :=
  sourceInvariant.dynamicRegisterRangeRelations.contains claim.sourceRelation &&
    targetInvariant.dynamicRegisterRangeRelations.contains claim.targetRelation &&
    claim.sourceRelation.originalOffset == 0 &&
    claim.sourceRelation.candidateOffset == 0 &&
    claim.targetRelation.originalOffset == 0 &&
    claim.targetRelation.candidateOffset == 0 &&
    claim.sourceRelation.requiredWords.contains claim.pointerRelation &&
    claim.targetRelation.requiredWords.all
      claim.sourceRelation.requiredWords.contains &&
    originalBehavior.registers.get claim.targetRelation.original ==
      dynamicPointerReadExpression claim.sourceRelation.original claim.pointerOffset &&
    candidateBehavior.registers.get claim.targetRelation.candidate ==
      dynamicPointerReadExpression claim.sourceRelation.candidate claim.pointerOffset &&
    originalGuard ==
      dynamicPointerNonzeroGuard claim.sourceRelation.original claim.pointerOffset &&
    candidateGuard ==
      dynamicPointerNonzeroGuard claim.sourceRelation.candidate claim.pointerOffset

theorem dynamicRegisterRangeNextGuardsAgree_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalGuard candidateGuard : BoolExpr)
    (claim : DynamicRegisterRangeNextClaim)
    (checked : claim.checked sourceInvariant targetInvariant originalBehavior
      candidateBehavior originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalGuard.eval originalState = candidateGuard.eval candidateState := by
  simp only [DynamicRegisterRangeNextClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨sourceMember, _targetMember⟩, sourceOriginalOffset⟩,
      sourceCandidateOffset⟩, _targetOriginalOffset⟩, _targetCandidateOffset⟩,
      pointerMember⟩, _targetWordsSubset⟩, _originalRegister⟩,
      _candidateRegister⟩, originalGuardExact⟩, candidateGuardExact⟩
  rcases related with
    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable,
      _candidateImmutable, relatedCore, _importAndDynamicRegisters⟩
  have dynamicRegisters := _importAndDynamicRegisters.2
  simp only [dynamicRegisterRangeRelationsHold, List.all_eq_true]
      at dynamicRegisters
  have sourceHolds := dynamicRegisters claim.sourceRelation
    (by simpa using sourceMember)
  simp only [DynamicRegisterRangeRelation.holds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at sourceHolds
  rcases sourceHolds with
    ⟨sourceRange, sourceRangeMember,
      ⟨⟨sourceOriginalRegister, sourceCandidateRegister⟩,
        sourceRequiredWords⟩⟩
  rw [sourceOriginalOffset] at sourceOriginalRegister
  rw [sourceCandidateOffset] at sourceCandidateRegister
  simp [BitVec.add_zero] at sourceOriginalRegister sourceCandidateRegister
  have dynamicMemory := relatedCore.2.2.2.2.2.1.1
  have sourceWords := dynamicMemory sourceRange sourceRangeMember
  simp only [DynamicAddressRangePair.wordsHold, List.all_eq_true] at sourceWords
  have pointerInSource : claim.pointerRelation ∈ sourceRange.wordRelations := by
    simp only [List.all_eq_true] at sourceRequiredWords
    have contained := sourceRequiredWords claim.pointerRelation
      (by simpa using pointerMember)
    simpa using contained
  have pointerHolds := sourceWords claim.pointerRelation pointerInSource
  change
    ((Memory.read32 originalState.memory
          (sourceRange.originalBase + BitVec.ofNat 32 claim.pointerOffset) ==
        BitVec.ofNat 32 0) &&
      (Memory.read32 candidateState.memory
          (sourceRange.candidateBase + BitVec.ofNat 32 claim.pointerOffset) ==
        BitVec.ofNat 32 0) ||
      world.dynamicRanges.any fun target =>
        (Memory.read32 originalState.memory
            (sourceRange.originalBase + BitVec.ofNat 32 claim.pointerOffset) ==
          target.originalBase) &&
        (Memory.read32 candidateState.memory
            (sourceRange.candidateBase + BitVec.ofNat 32 claim.pointerOffset) ==
          target.candidateBase) &&
        (!(target.originalBase == BitVec.ofNat 32 0)) &&
        (!(target.candidateBase == BitVec.ofNat 32 0)) &&
        sourceRange.wordRelations.all target.wordRelations.contains) = true
      at pointerHolds
  simp at pointerHolds
  have zeroIff :
      Memory.read32 originalState.memory
          (sourceRange.originalBase + BitVec.ofNat 32 claim.pointerOffset) =
          BitVec.ofNat 32 0 ↔
        Memory.read32 candidateState.memory
          (sourceRange.candidateBase + BitVec.ofNat 32 claim.pointerOffset) =
          BitVec.ofNat 32 0 := by
    rcases pointerHolds with zeroWords | ⟨targetRange, _targetRangeMember,
        ⟨⟨⟨⟨originalTarget, candidateTarget⟩, originalTargetNonzero⟩,
          candidateTargetNonzero⟩, _targetHasShape⟩⟩
    · rw [zeroWords.1, zeroWords.2]
    · rw [originalTarget, candidateTarget]
      exact ⟨fun originalZero => (originalTargetNonzero originalZero).elim,
        fun candidateZero => (candidateTargetNonzero candidateZero).elim⟩
  rw [originalGuardExact, candidateGuardExact]
  simpa [dynamicPointerNonzeroGuard, dynamicPointerReadExpression,
    BoolExpr.eval, Expr.eval, machineStateRead32_eq_memoryRead32,
    sourceOriginalRegister, sourceCandidateRegister] using zeroIff

theorem dynamicRegisterRangeNextOutputHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalGuard candidateGuard : BoolExpr)
    (claim : DynamicRegisterRangeNextClaim)
    (checked : claim.checked sourceInvariant targetInvariant originalBehavior
      candidateBehavior originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (guardTrue : originalGuard.eval originalState = true) :
    claim.targetRelation.holds world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [DynamicRegisterRangeNextClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨sourceMember, _targetMember⟩, sourceOriginalOffset⟩,
      sourceCandidateOffset⟩, targetOriginalOffset⟩, targetCandidateOffset⟩,
      pointerMember⟩, targetWordsSubset⟩, originalRegister⟩,
      candidateRegister⟩, originalGuardExact⟩, _candidateGuardExact⟩
  have dynamicRegisters := related.2.2.2.2.2.2.2.2.2.2
  simp only [dynamicRegisterRangeRelationsHold, List.all_eq_true]
      at dynamicRegisters
  have sourceHolds := dynamicRegisters claim.sourceRelation
    (by simpa using sourceMember)
  simp only [DynamicRegisterRangeRelation.holds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at sourceHolds
  rcases sourceHolds with
    ⟨sourceRange, sourceRangeMember,
      ⟨⟨sourceOriginalRegister, sourceCandidateRegister⟩,
        sourceRequiredWords⟩⟩
  rw [sourceOriginalOffset] at sourceOriginalRegister
  rw [sourceCandidateOffset] at sourceCandidateRegister
  simp [BitVec.add_zero] at sourceOriginalRegister sourceCandidateRegister
  have dynamicMemory := related.dynamicRangesMemoryHold context world
    sourceInvariant originalState candidateState
  have sourceWords := dynamicMemory sourceRange sourceRangeMember
  simp only [DynamicAddressRangePair.wordsHold, List.all_eq_true] at sourceWords
  have pointerInSource : claim.pointerRelation ∈ sourceRange.wordRelations := by
    simp only [List.all_eq_true] at sourceRequiredWords
    have contained := sourceRequiredWords claim.pointerRelation
      (by simpa using pointerMember)
    simpa using contained
  have pointerHolds := sourceWords claim.pointerRelation pointerInSource
  change
    ((Memory.read32 originalState.memory
          (sourceRange.originalBase + BitVec.ofNat 32 claim.pointerOffset) ==
        BitVec.ofNat 32 0) &&
      (Memory.read32 candidateState.memory
          (sourceRange.candidateBase + BitVec.ofNat 32 claim.pointerOffset) ==
        BitVec.ofNat 32 0) ||
      world.dynamicRanges.any fun target =>
        (Memory.read32 originalState.memory
            (sourceRange.originalBase + BitVec.ofNat 32 claim.pointerOffset) ==
          target.originalBase) &&
        (Memory.read32 candidateState.memory
            (sourceRange.candidateBase + BitVec.ofNat 32 claim.pointerOffset) ==
          target.candidateBase) &&
        (!(target.originalBase == BitVec.ofNat 32 0)) &&
        (!(target.candidateBase == BitVec.ofNat 32 0)) &&
        sourceRange.wordRelations.all target.wordRelations.contains) = true
      at pointerHolds
  have originalNonzero :
      Memory.read32 originalState.memory
          (sourceRange.originalBase + BitVec.ofNat 32 claim.pointerOffset) ≠
        BitVec.ofNat 32 0 := by
    rw [originalGuardExact] at guardTrue
    intro originalZero
    simp [dynamicPointerNonzeroGuard, dynamicPointerReadExpression,
      BoolExpr.eval, Expr.eval, machineStateRead32_eq_memoryRead32,
      sourceOriginalRegister, originalZero] at guardTrue
  simp at pointerHolds
  rcases pointerHolds with zeroWords | ⟨targetRange, targetRangeMember,
      ⟨⟨⟨⟨originalTarget, candidateTarget⟩, _originalTargetNonzero⟩,
        _candidateTargetNonzero⟩, targetHasShape⟩⟩
  · exact (originalNonzero zeroWords.1).elim
  · unfold DynamicRegisterRangeRelation.holds
    simp only [List.any_eq_true]
    refine ⟨targetRange, targetRangeMember, ?_⟩
    simp only [Bool.and_eq_true, beq_iff_eq]
    refine ⟨⟨?_, ?_⟩, ?_⟩
    · simp only [NormalizedSymbolicBehavior.eval_registers,
        evalNormalizedRegisters_get, originalRegister,
        dynamicPointerReadExpression, Expr.eval,
        machineStateRead32_eq_memoryRead32]
      rw [sourceOriginalRegister, originalTarget, targetOriginalOffset]
      simp
    · simp only [NormalizedSymbolicBehavior.eval_registers,
        evalNormalizedRegisters_get, candidateRegister,
        dynamicPointerReadExpression, Expr.eval,
        machineStateRead32_eq_memoryRead32]
      rw [sourceCandidateRegister, candidateTarget, targetCandidateOffset]
      simp
    · simp only [List.all_eq_true] at sourceRequiredWords targetWordsSubset targetHasShape ⊢
      intro word wordMember
      have wordInSourceRequired : word ∈ claim.sourceRelation.requiredWords := by
        have contained := targetWordsSubset word wordMember
        simpa using contained
      have wordInSourceRange : word ∈ sourceRange.wordRelations := by
        have contained := sourceRequiredWords word wordInSourceRequired
        simpa using contained
      simpa using targetHasShape word wordInSourceRange

theorem dynamicRegisterRangeHolds_relatedWord_of_zero_offsets
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
    ⟨range, rangeMember, ⟨⟨originalRegister, candidateRegister⟩,
      _requiredWords⟩⟩
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
    unfold StaticProofContext.relationalValueTargets
    simp only [mappedValueRelated, List.any_append, Bool.or_eq_true]
    apply Or.inr
    unfold RelationalWorld.dynamicValueTargets
    simp only [List.any_map, List.any_eq_true]
    refine ⟨range, rangeMember, ?_⟩
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

def relatedWordZeroGuard (register : Reg) (negated : Bool) : BoolExpr :=
  let zero := BoolExpr.equal
    (.bitAnd (.inputReg register) (.inputReg register)) (.constant 0)
  if negated then .not zero else zero

def applyBoolNots : Nat -> BoolExpr -> BoolExpr
  | 0, expression => expression
  | count + 1, expression => .not (applyBoolNots count expression)

def _root_.StageA.Formal.BoolExpr.inputFlagsOnlyWithin
    (allowed : List Nat) : BoolExpr -> Bool
  | .inputFlag index => allowed.contains index
  | .not value => value.inputFlagsOnlyWithin allowed
  | .and left right | .or left right | .xor left right =>
      left.inputFlagsOnlyWithin allowed && right.inputFlagsOnlyWithin allowed
  | _ => false

theorem _root_.StageA.Formal.BoolExpr.eval_eq_of_inputFlagsOnlyWithin
    (allowed : List Nat) (original candidate : MachineState)
    (expression : BoolExpr)
    (within : expression.inputFlagsOnlyWithin allowed = true)
    (related : flagsRelated allowed original.eflags candidate.eflags = true) :
    expression.eval original = expression.eval candidate := by
  induction expression with
  | equal _ _ => simp [BoolExpr.inputFlagsOnlyWithin] at within
  | not value ih =>
      simp only [BoolExpr.inputFlagsOnlyWithin] at within
      simp only [BoolExpr.eval]
      rw [ih within]
  | and left right leftIH rightIH =>
      simp only [BoolExpr.inputFlagsOnlyWithin, Bool.and_eq_true] at within
      simp only [BoolExpr.eval]
      rw [leftIH within.1, rightIH within.2]
  | or left right leftIH rightIH =>
      simp only [BoolExpr.inputFlagsOnlyWithin, Bool.and_eq_true] at within
      simp only [BoolExpr.eval]
      rw [leftIH within.1, rightIH within.2]
  | xor left right leftIH rightIH =>
      simp only [BoolExpr.inputFlagsOnlyWithin, Bool.and_eq_true] at within
      simp only [BoolExpr.eval]
      rw [leftIH within.1, rightIH within.2]
  | unsignedLess _ _ => simp [BoolExpr.inputFlagsOnlyWithin] at within
  | msb _ => simp [BoolExpr.inputFlagsOnlyWithin] at within
  | bit _ _ => simp [BoolExpr.inputFlagsOnlyWithin] at within
  | inputFlag index =>
      have bitEqual := flagsRelated_of_contains allowed original.eflags
        candidate.eflags related within
      simp only [BoolExpr.eval]
      rw [bitEqual]
  | divisionValid _ _ _ => simp [BoolExpr.inputFlagsOnlyWithin] at within

structure InputFlagsGuardClaim where
  guard : BoolExpr
deriving Repr, DecidableEq

def InputFlagsGuardClaim.checked (sourceInvariant : StateInvariant)
    (originalGuard candidateGuard : BoolExpr)
    (claim : InputFlagsGuardClaim) : Bool :=
  claim.guard == originalGuard && claim.guard == candidateGuard &&
    claim.guard.inputFlagsOnlyWithin sourceInvariant.flagBits

theorem inputFlagsGuard_eval_equal_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (originalGuard candidateGuard : BoolExpr)
    (claim : InputFlagsGuardClaim)
    (checked : claim.checked sourceInvariant originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalGuard.eval originalState = candidateGuard.eval candidateState := by
  simp only [InputFlagsGuardClaim.checked, Bool.and_eq_true, beq_iff_eq] at checked
  rcases checked with
    ⟨⟨originalGuardExact, candidateGuardExact⟩, within⟩
  rcases related with
    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable, _candidateImmutable,
      relatedCore, _importAndDynamicRegisters⟩
  rcases relatedCore with
    ⟨_inputRegisters, _inputBounds, _inputSeparations, _inputStackWindows,
      _inputMemory, _inputDynamicMemory, _inputUndefined, _inputX87, inputFlags,
      _inputFsBase⟩
  rw [← originalGuardExact, ← candidateGuardExact]
  exact BoolExpr.eval_eq_of_inputFlagsOnlyWithin sourceInvariant.flagBits
    originalState candidateState claim.guard within inputFlags

def _root_.StageA.Formal.Expr.exactInputsOnly
    (invariant : StateInvariant) : Expr -> Bool
  | .inputReg register => exactIdentityRegister invariant.registerRelations register
  | .inputFlagValue bit => invariant.flagBits.contains bit
  | .inputFsBase | .inputX87Control | .inputX87Status | .constant _ | .undefined _ => true
  | .add left right | .sub left right | .bitAnd left right | .bitXor left right |
      .shiftLeftBy left right | .shiftRightBy left right |
      .shiftArithmeticRightBy left right | .bitOr left right |
      .unsignedLessValue left right | .multiply left right |
      .multiplyHighUnsigned left right | .multiplyHighSigned left right =>
      left.exactInputsOnly invariant && right.exactInputsOnly invariant
  | .bitNot value | .extractByte value _ | .shiftLeft value _ | .shiftRight value _ |
      .bitValue value _ | .lowestSetBit value | .highestSetBit value =>
      value.exactInputsOnly invariant
  | .ifEqual left right thenValue elseValue =>
      left.exactInputsOnly invariant && right.exactInputsOnly invariant &&
        thenValue.exactInputsOnly invariant && elseValue.exactInputsOnly invariant
  | .divideQuotient high low divisor | .divideRemainder high low divisor |
      .divisionValidValue high low divisor =>
      high.exactInputsOnly invariant && low.exactInputsOnly invariant &&
        divisor.exactInputsOnly invariant
  | .read8 _ | .read32 _ | .read8AfterWrite _ _ _ _ | .x87Part _ _ |
      .x87CompareBit _ _ _ _ | .x87ExamineStatus _ _ => false

theorem _root_.StageA.Formal.Expr.eval_eq_of_exactInputsOnly
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (expression : Expr) (checked : expression.exactInputsOnly invariant = true)
    (related : StateRel context world invariant original candidate) :
    expression.eval original = expression.eval candidate := by
  rcases related with
    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable, _candidateImmutable,
      relatedCore, _importAndDynamicRegisters⟩
  rcases relatedCore with
    ⟨inputRegisters, _inputBounds, _inputSeparations, _inputStackWindows,
      _inputMemory, _inputDynamicMemory, inputUndefined, inputX87, inputFlags,
      inputFsBase⟩
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
  have evalAll : ∀ value : Expr, value.exactInputsOnly invariant = true →
      value.eval original = value.eval candidate := by
    intro value
    apply Expr.rec
      (motive_1 := fun item => item.exactInputsOnly invariant = true →
        item.eval original = item.eval candidate)
      (motive_2 := fun _ => True) <;>
      simp_all [Expr.exactInputsOnly, Expr.eval, Bool.and_eq_true]
  exact evalAll expression checked

def _root_.StageA.Formal.BoolExpr.exactInputsOnly
    (invariant : StateInvariant) : BoolExpr -> Bool
  | .equal left right | .unsignedLess left right =>
      left.exactInputsOnly invariant && right.exactInputsOnly invariant
  | .not value => value.exactInputsOnly invariant
  | .and left right | .or left right | .xor left right =>
      left.exactInputsOnly invariant && right.exactInputsOnly invariant
  | .msb value | .bit value _ => value.exactInputsOnly invariant
  | .inputFlag bit => invariant.flagBits.contains bit
  | .divisionValid high low divisor =>
      high.exactInputsOnly invariant && low.exactInputsOnly invariant &&
        divisor.exactInputsOnly invariant

theorem _root_.StageA.Formal.BoolExpr.eval_eq_of_exactInputsOnly
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (expression : BoolExpr) (checked : expression.exactInputsOnly invariant = true)
    (related : StateRel context world invariant original candidate) :
    expression.eval original = expression.eval candidate := by
  have exactExpression := fun value safe =>
    Expr.eval_eq_of_exactInputsOnly context world invariant original candidate
      value safe related
  have exactFlag : ∀ bit, invariant.flagBits.contains bit = true →
      original.eflags.extractLsb' bit 1 = candidate.eflags.extractLsb' bit 1 := by
    intro bit contains
    rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
    exact flagsRelated_of_contains invariant.flagBits original.eflags candidate.eflags
      relatedCore.2.2.2.2.2.2.2.2.1 contains
  induction expression <;>
    simp_all [BoolExpr.exactInputsOnly, BoolExpr.eval, Bool.and_eq_true]
  case divisionValid high low divisor =>
    have evaluated := exactExpression (.divisionValidValue high low divisor) (by
      simpa [Expr.exactInputsOnly] using checked)
    exact congrArg (fun value => value == BitVec.ofNat 32 1) evaluated

structure ExactPureGuardClaim where
  guard : BoolExpr
deriving Repr, DecidableEq

def ExactPureGuardClaim.checked (sourceInvariant : StateInvariant)
    (originalGuard candidateGuard : BoolExpr) (claim : ExactPureGuardClaim) : Bool :=
  claim.guard == originalGuard && claim.guard == candidateGuard &&
    claim.guard.exactInputsOnly sourceInvariant

theorem exactPureGuard_eval_equal_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (originalGuard candidateGuard : BoolExpr)
    (claim : ExactPureGuardClaim)
    (checked : claim.checked sourceInvariant originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalGuard.eval originalState = candidateGuard.eval candidateState := by
  simp only [ExactPureGuardClaim.checked, Bool.and_eq_true, beq_iff_eq] at checked
  rcases checked with ⟨⟨originalExact, candidateExact⟩, exactInputs⟩
  rw [← originalExact, ← candidateExact]
  exact BoolExpr.eval_eq_of_exactInputsOnly context world sourceInvariant
    originalState candidateState claim.guard exactInputs related

def normalizedCarryIsInput : Option FlagsExpr -> Bool
  | none => true
  | some flags => flags.carry == some (.inputFlag 0)

def normalizedParityIsInput : Option FlagsExpr -> Bool
  | none => true
  | some flags => flags.parity == some (.inputFlag 2)

def normalizedZeroIsInput : Option FlagsExpr -> Bool
  | none => true
  | some flags => flags.zero == some (.inputFlag 6)

def normalizedSignIsInput : Option FlagsExpr -> Bool
  | none => true
  | some flags => flags.sign == some (.inputFlag 7)

def normalizedOverflowIsInput : Option FlagsExpr -> Bool
  | none => true
  | some flags => flags.overflow == some (.inputFlag 11)

theorem oneBitConditionalReconstructs (value : BitVec 1) :
    (if value == BitVec.ofNat 1 1 then BitVec.allOnes 1 else 0#1) = value := by
  have valueBound : value.toNat < 2 := by simpa using value.isLt
  by_cases zero : value.toNat = 0
  · have valueZero : value = 0#1 := by
      apply BitVec.eq_of_toNat_eq
      simpa [zero]
    subst value
    decide
  · have one : value.toNat = 1 := by omega
    have valueOne : value = BitVec.ofNat 1 1 := by
      apply BitVec.eq_of_toNat_eq
      simpa [one]
    subst value
    decide

theorem evalFlagBit_inputFlag (state : MachineState) (bit : Nat) :
    evalFlagBit state bit (some (.inputFlag bit)) =
      state.eflags.extractLsb' bit 1 := by
  simp only [evalFlagBit, BoolExpr.eval]
  exact oneBitConditionalReconstructs _

theorem evalNormalizedFlags_extract_cf_input_of_checked
    (state : MachineState) (flags : Option FlagsExpr)
    (checked : normalizedCarryIsInput flags = true) :
    (evalNormalizedFlags state flags).extractLsb' 0 1 =
      state.eflags.extractLsb' 0 1 := by
  cases flags with
  | none => rfl
  | some flags =>
      simp only [normalizedCarryIsInput, beq_iff_eq] at checked
      simp only [evalNormalizedFlags_some, FlagsExpr.eval_extract_cf, checked,
        evalFlagBit, BoolExpr.eval]
      exact oneBitConditionalReconstructs _

theorem evalNormalizedFlags_extract_pf_input_of_checked
    (state : MachineState) (flags : Option FlagsExpr)
    (checked : normalizedParityIsInput flags = true) :
    (evalNormalizedFlags state flags).extractLsb' 2 1 =
      state.eflags.extractLsb' 2 1 := by
  cases flags with
  | none => rfl
  | some flags =>
      simp only [normalizedParityIsInput, beq_iff_eq] at checked
      simp only [evalNormalizedFlags_some, FlagsExpr.eval_extract_pf, checked,
        evalFlagBit, BoolExpr.eval]
      exact oneBitConditionalReconstructs _

theorem evalNormalizedFlags_extract_zf_input_of_checked
    (state : MachineState) (flags : Option FlagsExpr)
    (checked : normalizedZeroIsInput flags = true) :
    (evalNormalizedFlags state flags).extractLsb' 6 1 =
      state.eflags.extractLsb' 6 1 := by
  cases flags with
  | none => rfl
  | some flags =>
      simp only [normalizedZeroIsInput, beq_iff_eq] at checked
      simp only [evalNormalizedFlags_some, FlagsExpr.eval_extract_zf, checked,
        evalFlagBit, BoolExpr.eval]
      exact oneBitConditionalReconstructs _

theorem evalNormalizedFlags_extract_sf_input_of_checked
    (state : MachineState) (flags : Option FlagsExpr)
    (checked : normalizedSignIsInput flags = true) :
    (evalNormalizedFlags state flags).extractLsb' 7 1 =
      state.eflags.extractLsb' 7 1 := by
  cases flags with
  | none => rfl
  | some flags =>
      simp only [normalizedSignIsInput, beq_iff_eq] at checked
      simp only [evalNormalizedFlags_some, FlagsExpr.eval_extract_sf, checked,
        evalFlagBit, BoolExpr.eval]
      exact oneBitConditionalReconstructs _

theorem evalNormalizedFlags_extract_of_input_of_checked
    (state : MachineState) (flags : Option FlagsExpr)
    (checked : normalizedOverflowIsInput flags = true) :
    (evalNormalizedFlags state flags).extractLsb' 11 1 =
      state.eflags.extractLsb' 11 1 := by
  cases flags with
  | none => rfl
  | some flags =>
      simp only [normalizedOverflowIsInput, beq_iff_eq] at checked
      simp only [evalNormalizedFlags_some, FlagsExpr.eval_extract_of, checked,
        evalFlagBit, BoolExpr.eval]
      exact oneBitConditionalReconstructs _

def stackWordZeroGuard (register : Reg) (offset : Nat) : BoolExpr :=
  let value : Expr := .read32 (.add (.inputReg register) (.constant offset))
  .equal (.bitAnd value value) (.constant 0)

def stackWordZeroGuardWithNots (register : Reg) (offset notCount : Nat) : BoolExpr :=
  applyBoolNots notCount (stackWordZeroGuard register offset)

structure StackWordZeroGuardClaim where
  window : StackWindowPair
  offset : Nat
  notCount : Nat
deriving Repr, DecidableEq

def StackWordZeroGuardClaim.checked (sourceInvariant : StateInvariant)
    (originalGuard candidateGuard : BoolExpr)
    (claim : StackWordZeroGuardClaim) : Bool :=
  (((sourceInvariant.stackWindows.contains claim.window &&
      decide (claim.offset % 4 = 0)) &&
      decide (claim.offset + 4 <= claim.window.bytesAbove)) &&
      originalGuard == stackWordZeroGuardWithNots
        claim.window.originalRegister claim.offset claim.notCount) &&
    candidateGuard == stackWordZeroGuardWithNots
      claim.window.candidateRegister claim.offset claim.notCount

def relatedWordZeroGuardWithNots (register : Reg) (notCount : Nat) : BoolExpr :=
  applyBoolNots notCount (relatedWordZeroGuard register false)

theorem applyBoolNots_eval_equal (count : Nat)
    (originalExpression candidateExpression : BoolExpr)
    (originalState candidateState : MachineState)
    (equal : originalExpression.eval originalState =
      candidateExpression.eval candidateState) :
    (applyBoolNots count originalExpression).eval originalState =
      (applyBoolNots count candidateExpression).eval candidateState := by
  induction count with
  | zero => exact equal
  | succ count ih =>
      simp only [applyBoolNots, BoolExpr.eval]
      rw [ih]

theorem stackWordZeroGuard_eval_equal_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (originalGuard candidateGuard : BoolExpr)
    (claim : StackWordZeroGuardClaim)
    (checked : claim.checked sourceInvariant originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalGuard.eval originalState = candidateGuard.eval candidateState := by
  simp only [StackWordZeroGuardClaim.checked, Bool.and_eq_true,
    decide_eq_true_eq, beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨windowMember, aligned⟩, inside⟩, originalGuardExact⟩,
      candidateGuardExact⟩
  have wordsRelated := StateRel.stackMemoryRead32Related context world sourceInvariant
    originalState candidateState claim.window claim.offset related
    (by simpa using windowMember) inside aligned
  have zeroEqual := wordRelated_zero_equal wordsRelated
  rw [originalGuardExact, candidateGuardExact]
  apply applyBoolNots_eval_equal claim.notCount
  simpa only [stackWordZeroGuard, BoolExpr.eval, Expr.eval,
    machineStateRead32_eq_memoryRead32, BitVec.and_self] using zeroEqual

theorem relatedWordZeroGuard_base_eval_of_true
    (register : Reg) (negated : Bool) (state : MachineState)
    (guardTrue : (relatedWordZeroGuard register negated).eval state = true) :
    (relatedWordZeroGuard register false).eval state =
      (if negated then false else true) := by
  cases negated with
  | false => simpa [relatedWordZeroGuard] using guardTrue
  | true =>
      change (!((relatedWordZeroGuard register false).eval state)) = true at guardTrue
      cases value : (relatedWordZeroGuard register false).eval state <;>
        simp_all

def normalizedBranchGuard (condition : BoolExpr) (taken : Bool) : BoolExpr :=
  if taken then condition else .not condition

theorem normalizedBranchCondition_eval_of_guard_true
    (condition guard : BoolExpr) (taken : Bool) (state : MachineState)
    (guardShape : guard = normalizedBranchGuard condition taken)
    (guardTrue : guard.eval state = true) :
    condition.eval state = taken := by
  rw [guardShape] at guardTrue
  cases taken with
  | false =>
      change (!(condition.eval state)) = true at guardTrue
      cases value : condition.eval state <;> simp_all
  | true => simpa [normalizedBranchGuard] using guardTrue

structure RelatedWordZeroGuardClaim where
  originalRegister : Reg
  candidateRegister : Reg
  valueRelation : RegisterValueRelation
  notCount : Nat
deriving Repr, DecidableEq

def RelatedWordZeroGuardClaim.relation
    (claim : RelatedWordZeroGuardClaim) : RegisterRelationPair := {
  original := claim.originalRegister
  candidate := claim.candidateRegister
  relation := claim.valueRelation
}

def RelatedWordZeroGuardClaim.checked (sourceInvariant : StateInvariant)
    (originalGuard candidateGuard : BoolExpr)
    (claim : RelatedWordZeroGuardClaim) : Bool :=
  sourceInvariant.registerRelations.contains claim.relation &&
    (claim.valueRelation == .exact || claim.valueRelation == .relatedWord) &&
    originalGuard == relatedWordZeroGuardWithNots claim.originalRegister claim.notCount &&
    candidateGuard == relatedWordZeroGuardWithNots claim.candidateRegister claim.notCount

theorem relatedWordZeroGuard_eval_equal_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (originalGuard candidateGuard : BoolExpr)
    (claim : RelatedWordZeroGuardClaim)
    (checked : claim.checked sourceInvariant originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalGuard.eval originalState = candidateGuard.eval candidateState := by
  simp only [RelatedWordZeroGuardClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨relationMember, supportedRelation⟩, originalGuardExact⟩,
      candidateGuardExact⟩
  rcases related with
    ⟨_worldStatic, _stackRangesValid, _stackMemory, _importsStatic, _importsComplete,
      _importsMemory, _originalImmutable, _candidateImmutable, relatedCore,
      _importRegisters⟩
  have registerRelations := relatedCore.1
  simp only [registerRelationsHold, List.all_eq_true] at registerRelations
  have relationHolds := registerRelations claim.relation (by simpa using relationMember)
  change RegisterValueRelation.holds context.originalPe.imageBase
    context.candidatePe.imageBase context.codeMap.entries.toList
    (context.relationalValueTargets world) claim.valueRelation
    (originalState.registers.get claim.originalRegister)
    (candidateState.registers.get claim.candidateRegister) = true at relationHolds
  have zeroIff :
      originalState.registers.get claim.originalRegister = BitVec.ofNat 32 0 ↔
        candidateState.registers.get claim.candidateRegister = BitVec.ofNat 32 0 := by
    cases relationKind : claim.valueRelation with
    | exact =>
        rw [relationKind] at relationHolds
        simp only [RegisterValueRelation.holds] at relationHolds
        have registersEqual := beq_iff_eq.mp relationHolds
        rw [registersEqual]
    | relatedWord =>
        rw [relationKind] at relationHolds
        simp only [RegisterValueRelation.holds] at relationHolds
        have zeroEqual := wordRelated_zero_equal relationHolds
        constructor
        · intro originalZero
          have originalCheck :
              (originalState.registers.get claim.originalRegister == BitVec.ofNat 32 0) =
                true := beq_iff_eq.mpr originalZero
          rw [zeroEqual] at originalCheck
          exact beq_iff_eq.mp originalCheck
        · intro candidateZero
          have candidateCheck :
              (candidateState.registers.get claim.candidateRegister == BitVec.ofNat 32 0) =
                true := beq_iff_eq.mpr candidateZero
          rw [← zeroEqual] at candidateCheck
          exact beq_iff_eq.mp candidateCheck
    | codePointer => simp [relationKind] at supportedRelation
    | dataPointer => simp [relationKind] at supportedRelation
  rw [originalGuardExact, candidateGuardExact]
  apply applyBoolNots_eval_equal claim.notCount
  simpa [relatedWordZeroGuard, BoolExpr.eval, Expr.eval] using zeroIff

def NormalizedOutcomeExpr.controlEdges? : NormalizedOutcomeExpr ->
    Option (List RelationalDecodedControlEdge)
  | .jump target => some [RelationalDecodedControlEdge.mk .jump target
      unconditionalProductGuard]
  | .branch condition taken fallthrough =>
      if taken = fallthrough then
        some [RelationalDecodedControlEdge.mk .jump taken unconditionalProductGuard]
      else
        some [RelationalDecodedControlEdge.mk .branchTaken taken condition,
          RelationalDecodedControlEdge.mk .branchFallthrough fallthrough (.not condition)]
  | .call target _ => some [RelationalDecodedControlEdge.mk .call target
      unconditionalProductGuard]
  | .externalCall _ _ continuation =>
      some [RelationalDecodedControlEdge.mk .externalCall continuation
        unconditionalProductGuard]
  | .bulkCopy _ _ _ _ continuation =>
      some [RelationalDecodedControlEdge.mk .bulkCopy continuation
        unconditionalProductGuard]
  | .atomicCompareExchange _ _ _ continuation =>
      some [RelationalDecodedControlEdge.mk .atomicCompareExchange continuation
        unconditionalProductGuard]
  | .returned _ | .externalJump _ _ => some []
  | .indirectCall _ _ | .indirectJump _ | .checkedContinue _ _ => none

def RelationalProductGraph.getNode? (graph : RelationalProductGraph)
    (nodeId : Nat) : Option RelationalProductNode :=
  graph.nodes[nodeId]?

def RelationalProductGraph.getEdge? (graph : RelationalProductGraph)
    (edgeId : Nat) : Option RelationalProductEdge :=
  graph.edges[edgeId]?

def RelationalProductGraph.resolveOutgoingControlEdges
    (graph : RelationalProductGraph) (candidate : Bool) : List Nat ->
    Option (List RelationalDecodedControlEdge)
  | [] => some []
  | edgeId :: edgeIds => do
      let edge <- graph.getEdge? edgeId
      let rest <- graph.resolveOutgoingControlEdges candidate edgeIds
      let guard := if candidate then edge.candidateGuard else edge.originalGuard
      pure (RelationalDecodedControlEdge.mk edge.kind edge.targetTargetId guard :: rest)

def normalizedControlEdges? (candidate : Bool) (targets : List CodeTargetPair)
    (behavior : SymbolicBehavior) : Option (List RelationalDecodedControlEdge) := do
  let normalized <- normalizeSymbolicBehavior candidate targets behavior
  normalized.outcome.controlEdges?

def decodedControlEdgesMatch (graph : RelationalProductGraph) (nodeId : Nat)
    (region : RegionRelation) (originalBehavior candidateBehavior : SymbolicBehavior) :
    Bool :=
  match graph.getNode? nodeId,
      normalizedControlEdges? false region.targets originalBehavior,
      normalizedControlEdges? true region.targets candidateBehavior with
  | some node, some originalEdges, some candidateEdges =>
      graph.resolveOutgoingControlEdges false node.outgoingEdgeIds == some originalEdges &&
        graph.resolveOutgoingControlEdges true node.outgoingEdgeIds == some candidateEdges
  | _, _, _ => false

def immutableIndirectCallEdgesMatch (graph : RelationalProductGraph) (nodeId : Nat)
    (claim : ImmutableIndirectCallTargetClaim) : Bool :=
  match graph.getNode? nodeId with
  | none => false
  | some node =>
      let expected := some [RelationalDecodedControlEdge.mk .call claim.targetId
        unconditionalProductGuard]
      graph.resolveOutgoingControlEdges false node.outgoingEdgeIds == expected &&
        graph.resolveOutgoingControlEdges true node.outgoingEdgeIds == expected

def immutableIndirectJumpEdgesMatch (graph : RelationalProductGraph) (nodeId : Nat)
    (claim : ImmutableIndirectJumpTargetClaim) : Bool :=
  match graph.getNode? nodeId with
  | none => false
  | some node =>
      let expected := some [RelationalDecodedControlEdge.mk .jump claim.targetId
        unconditionalProductGuard]
      graph.resolveOutgoingControlEdges false node.outgoingEdgeIds == expected &&
        graph.resolveOutgoingControlEdges true node.outgoingEdgeIds == expected

def importRegisterIndirectCallEdgesMatch (graph : RelationalProductGraph)
    (nodeId : Nat) (claim : ImportRegisterIndirectCallClaim) : Bool :=
  match graph.getNode? nodeId with
  | none => false
  | some node =>
      let expected := some [RelationalDecodedControlEdge.mk .externalCall
        claim.continuationTargetId unconditionalProductGuard]
      graph.resolveOutgoingControlEdges false node.outgoingEdgeIds == expected &&
        graph.resolveOutgoingControlEdges true node.outgoingEdgeIds == expected

def dynamicRangeIndirectCallEdgeAtMatches (graph : RelationalProductGraph)
    (nodeId : Nat) (context : StaticProofContext)
    (claim : DynamicRangeIndirectCallClaim) (firstEdgeId targetId : Nat) : Bool :=
  match graph.getNode? nodeId, context.codeMap.get? targetId,
      graph.getEdge? (firstEdgeId + targetId) with
  | some node, some target, some edge =>
      node.outgoingEdgeIds[targetId]? == some (firstEdgeId + targetId) &&
        edge.id == firstEdgeId + targetId &&
        edge.sourceNodeId == nodeId &&
        edge.targetNodeId == target.regionIndex &&
        edge.sourceTargetId == node.targetId &&
        edge.targetTargetId == target.id &&
        edge.kind == .call &&
        edge.originalGuard == codeTargetProductGuard context.originalPe.imageBase
          claim.originalTargetExpression target.originalRva target.originalAliases &&
        edge.candidateGuard == codeTargetProductGuard context.candidatePe.imageBase
          claim.candidateTargetExpression target.candidateRva target.candidateAliases &&
        !edge.infeasible
  | _, _, _ => false

def DynamicRangeIndirectCallEdgesMatch (graph : RelationalProductGraph)
    (nodeId : Nat) (context : StaticProofContext)
    (claim : DynamicRangeIndirectCallClaim) (firstEdgeId : Nat) : Prop :=
  match graph.getNode? nodeId with
  | none => False
  | some node =>
      node.outgoingEdgeIds.length = context.codeMap.entries.size ∧
        ∀ targetId, targetId < context.codeMap.entries.size ->
          dynamicRangeIndirectCallEdgeAtMatches graph nodeId context claim firstEdgeId
            targetId = true

def NodeDecodedControlEdgesComplete (graph : RelationalProductGraph) (nodeId : Nat)
    (originalPe candidatePe : PE32) (originalImports candidateImports : List PEImport)
    (machineCallContracts : List MachineImportCallContract)
    (region : RegionRelation) (originalBehavior candidateBehavior : SymbolicBehavior) :
    Prop :=
  regionBehaviorWithMachineCallContracts originalPe originalImports machineCallContracts
      region.original =
      some originalBehavior ∧
    regionBehaviorWithMachineCallContracts candidatePe candidateImports machineCallContracts
      region.candidate =
      some candidateBehavior ∧
    decodedControlEdgesMatch graph nodeId region originalBehavior candidateBehavior = true

def NodeImmutableIndirectCallEdgesComplete (graph : RelationalProductGraph)
    (nodeId : Nat) (context : StaticProofContext) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectCallTargetClaim) : Prop :=
  regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
      context.machineImportCallContracts region.original =
      some originalBehavior ∧
    regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
      context.machineImportCallContracts region.candidate =
      some candidateBehavior ∧
    normalizeSymbolicBehavior false region.targets originalBehavior =
      some originalNormalized ∧
    normalizeSymbolicBehavior true region.targets candidateBehavior =
      some candidateNormalized ∧
    immutableIndirectCallEdgesMatch graph nodeId claim = true ∧
    ImmutableIndirectCallTargetsClosed context region.inputInvariant originalNormalized
      candidateNormalized claim

def NodeImmutableIndirectJumpEdgesComplete (graph : RelationalProductGraph)
    (nodeId : Nat) (context : StaticProofContext) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectJumpTargetClaim) : Prop :=
  regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
      context.machineImportCallContracts region.original =
      some originalBehavior ∧
    regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
      context.machineImportCallContracts region.candidate =
      some candidateBehavior ∧
    normalizeSymbolicBehavior false region.targets originalBehavior =
      some originalNormalized ∧
    normalizeSymbolicBehavior true region.targets candidateBehavior =
      some candidateNormalized ∧
    immutableIndirectJumpEdgesMatch graph nodeId claim = true ∧
    ImmutableIndirectJumpTargetsClosed context region.inputInvariant originalNormalized
      candidateNormalized claim

def NodeImportRegisterIndirectCallEdgesComplete (graph : RelationalProductGraph)
    (nodeId : Nat) (context : StaticProofContext) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : ImportRegisterIndirectCallClaim) : Prop :=
  regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
      context.machineImportCallContracts region.original =
      some originalBehavior ∧
    regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
      context.machineImportCallContracts region.candidate =
      some candidateBehavior ∧
    normalizeSymbolicBehavior false region.targets originalBehavior =
      some originalNormalized ∧
    normalizeSymbolicBehavior true region.targets candidateBehavior =
      some candidateNormalized ∧
    importRegisterIndirectCallEdgesMatch graph nodeId claim = true ∧
    ImportRegisterIndirectCallTargetsClosed region.inputInvariant originalNormalized
      candidateNormalized claim

def NodeDynamicRangeIndirectCallEdgesComplete (graph : RelationalProductGraph)
    (nodeId : Nat) (context : StaticProofContext) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : DynamicRangeIndirectCallClaim) (firstEdgeId : Nat) : Prop :=
  regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
      context.machineImportCallContracts region.original =
      some originalBehavior ∧
    regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
      context.machineImportCallContracts region.candidate =
      some candidateBehavior ∧
    normalizeSymbolicBehavior false region.targets originalBehavior =
      some originalNormalized ∧
    normalizeSymbolicBehavior true region.targets candidateBehavior =
      some candidateNormalized ∧
    DynamicRangeIndirectCallEdgesMatch graph nodeId context claim firstEdgeId ∧
    DynamicRangeIndirectCallFiniteTargetsClosed region.inputInvariant originalNormalized
      candidateNormalized claim

def NodeControlEdgesComplete (graph : RelationalProductGraph) (nodeId : Nat)
    (context : StaticProofContext) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  NodeDecodedControlEdgesComplete graph nodeId context.originalPe context.candidatePe
      context.originalImports context.candidateImports context.machineImportCallContracts
      region originalBehavior
      candidateBehavior ∨
    (∃ originalNormalized candidateNormalized claim,
      NodeImmutableIndirectCallEdgesComplete graph nodeId context region originalBehavior
        candidateBehavior originalNormalized candidateNormalized claim) ∨
    (∃ originalNormalized candidateNormalized claim,
      NodeImportRegisterIndirectCallEdgesComplete graph nodeId context region originalBehavior
        candidateBehavior originalNormalized candidateNormalized claim) ∨
    (∃ originalNormalized candidateNormalized claim firstEdgeId,
      NodeDynamicRangeIndirectCallEdgesComplete graph nodeId context region originalBehavior
        candidateBehavior originalNormalized candidateNormalized claim firstEdgeId) ∨
    (∃ originalNormalized candidateNormalized claim,
      NodeImmutableIndirectJumpEdgesComplete graph nodeId context region originalBehavior
        candidateBehavior originalNormalized candidateNormalized claim)

def strictlyIncreasingNatsAux : Option Nat -> List Nat -> Bool
  | _, [] => true
  | previous, value :: values =>
      previous.all (· < value) && strictlyIncreasingNatsAux (some value) values

def strictlyIncreasingNats (values : List Nat) : Bool :=
  strictlyIncreasingNatsAux none values

structure RelationalDecodedControlEvidence where
  completeNodeIds : List Nat
deriving Repr, DecidableEq

def RelationalDecodedControlEvidence.valid (graph : RelationalProductGraph)
    (evidence : RelationalDecodedControlEvidence) : Bool :=
  strictlyIncreasingNats evidence.completeNodeIds &&
    evidence.completeNodeIds.all (· < graph.nodes.size)

def RelationalDecodedControlEvidence.complete (graph : RelationalProductGraph)
    (evidence : RelationalDecodedControlEvidence) : Bool :=
  evidence.completeNodeIds == List.range graph.nodes.size

def AllListedDecodedControlNodesComplete (graph : RelationalProductGraph)
    (context : StaticProofContext) : List Nat -> Prop
  | [] => True
  | nodeId :: nodeIds =>
      (∃ region originalBehavior candidateBehavior,
        NodeControlEdgesComplete graph nodeId context region originalBehavior
          candidateBehavior) ∧
      AllListedDecodedControlNodesComplete graph context nodeIds

def PartialDecodedControlCompletenessCertificate (graph : RelationalProductGraph)
    (context : StaticProofContext)
    (evidence : RelationalDecodedControlEvidence) : Prop :=
  evidence.valid graph = true ∧
    AllListedDecodedControlNodesComplete graph context evidence.completeNodeIds

def AllProductNodesDecodedControlComplete (graph : RelationalProductGraph)
    (context : StaticProofContext) : Prop :=
  ∀ nodeId, nodeId < graph.nodes.size ->
    ∃ region originalBehavior candidateBehavior,
      NodeControlEdgesComplete graph nodeId context region originalBehavior
        candidateBehavior

def RelationalProductGraph.nodeAtValid (context : StaticProofContext)
    (graph : RelationalProductGraph) (index : Nat) : Bool :=
  match graph.getNode? index with
  | none => false
  | some node =>
      match context.codeMap.get? node.targetId with
      | some target =>
          node.id == index && target.id == node.targetId &&
            target.regionIndex == node.id &&
            node.root == graph.rootNodeIds.contains node.id &&
            strictlyIncreasingNats node.outgoingEdgeIds &&
            node.outgoingEdgeIds.all fun edgeId =>
              match graph.getEdge? edgeId with
              | some edge => edge.sourceNodeId == node.id
              | none => false
      | none => false

def RelationalProductGraph.edgeAtValid (graph : RelationalProductGraph)
    (index : Nat) : Bool :=
  match graph.getEdge? index with
  | none => false
  | some edge =>
      match graph.getNode? edge.sourceNodeId, graph.getNode? edge.targetNodeId with
      | some source, some target =>
          edge.id == index && source.outgoingEdgeIds.contains edge.id &&
            edge.sourceTargetId == source.targetId &&
            edge.targetTargetId == target.targetId &&
            edge.infeasible ==
              (edge.originalGuard.definitelyFalse &&
                edge.candidateGuard.definitelyFalse)
      | _, _ => false

def RelationalProductGraph.resolveRootTargetIds (graph : RelationalProductGraph) :
    List Nat -> Option (List Nat)
  | [] => some []
  | nodeId :: nodeIds => do
      let node <- graph.getNode? nodeId
      let targets <- graph.resolveRootTargetIds nodeIds
      pure (node.targetId :: targets)

def RelationalProductGraph.rootsValid (context : StaticProofContext)
    (graph : RelationalProductGraph) : Bool :=
  strictlyIncreasingNats graph.rootNodeIds &&
    graph.resolveRootTargetIds graph.rootNodeIds ==
      some (context.roots.map (·.targetId))

def RelationalProductGraph.IndexedValid (context : StaticProofContext)
    (graph : RelationalProductGraph) : Prop :=
  (∀ index, index < graph.nodes.size -> graph.nodeAtValid context index = true) ∧
    (∀ index, index < graph.edges.size -> graph.edgeAtValid index = true) ∧
    graph.rootsValid context = true

structure RelationalProductEvidence where
  provedEdgeIds : List Nat
deriving Repr, DecidableEq

def RelationalProductEvidence.valid (graph : RelationalProductGraph)
    (evidence : RelationalProductEvidence) : Bool :=
  strictlyIncreasingNats evidence.provedEdgeIds &&
    evidence.provedEdgeIds.all (· < graph.edges.size)

def RelationalProductEvidence.complete (graph : RelationalProductGraph)
    (evidence : RelationalProductEvidence) : Bool :=
  evidence.provedEdgeIds == List.range graph.edges.size

def RelationalProductEdgeRefinement (context : StaticProofContext)
    (graph : RelationalProductGraph) (edgeId : Nat)
    (segment : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant) : Prop :=
  match graph.getEdge? edgeId with
  | none => False
  | some edge =>
      segment.sourceTargetId = edge.sourceTargetId ∧
        segment.exit = .internal edge.targetTargetId ∧
        RelationalSegmentRefinement context segment sourceInvariant targetInvariant

def AllProductEdgesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) : Prop :=
  ∀ edgeId, edgeId < graph.edges.size ->
    ∃ segment sourceInvariant targetInvariant,
      RelationalProductEdgeRefinement context graph edgeId segment
        sourceInvariant targetInvariant

def ListedProductEdgesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) : List Nat -> Prop
  | [] => True
  | edgeId :: edgeIds =>
      (∃ segment sourceInvariant targetInvariant,
        RelationalProductEdgeRefinement context graph edgeId segment
          sourceInvariant targetInvariant) ∧
      ListedProductEdgesRefined context graph edgeIds

def PartialProductEdgeRefinementCertificate (context : StaticProofContext)
    (graph : RelationalProductGraph) (evidence : RelationalProductEvidence) : Prop :=
  evidence.valid graph = true ∧
    ListedProductEdgesRefined context graph evidence.provedEdgeIds

structure CompleteProductEdgeRefinementCertificate
    (context : StaticProofContext) (graph : RelationalProductGraph) where
  structurallyValid : graph.IndexedValid context
  allEdgesRefined : AllProductEdgesRefined context graph

def UnconditionalProductNodeBehaviorCovered (context : StaticProofContext)
    (graph : RelationalProductGraph) (nodeId edgeId : Nat)
    (segment : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant) : Prop :=
  match graph.getNode? nodeId, graph.getEdge? edgeId with
  | some node, some edge =>
      node.outgoingEdgeIds = [edgeId] ∧
        edge.sourceNodeId = nodeId ∧
        edge.originalGuard = unconditionalProductGuard ∧
        edge.candidateGuard = unconditionalProductGuard ∧
        segment.originalGuard = unconditionalProductGuard ∧
        segment.candidateGuard = unconditionalProductGuard ∧
        RelationalProductEdgeRefinement context graph edgeId segment
          sourceInvariant targetInvariant
  | _, _ => False

structure RelationalProductCoverageEvidence where
  coveredNodeIds : List Nat
deriving Repr, DecidableEq

def RelationalProductCoverageEvidence.valid (graph : RelationalProductGraph)
    (evidence : RelationalProductCoverageEvidence) : Bool :=
  strictlyIncreasingNats evidence.coveredNodeIds &&
    evidence.coveredNodeIds.all (· < graph.nodes.size)

def AllCoveredProductNodes (context : StaticProofContext)
    (graph : RelationalProductGraph) : List Nat -> Prop
  | [] => True
  | nodeId :: nodeIds =>
      (∃ edgeId segment sourceInvariant targetInvariant,
        UnconditionalProductNodeBehaviorCovered context graph nodeId edgeId segment
          sourceInvariant targetInvariant) ∧
      AllCoveredProductNodes context graph nodeIds

def PartialProductNodeCoverageCertificate (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (evidence : RelationalProductCoverageEvidence) : Prop :=
  evidence.valid graph = true ∧
    AllCoveredProductNodes context graph evidence.coveredNodeIds

structure RelationalProductReachabilityEvidence where
  reachable : Array Bool
deriving Repr, DecidableEq

def RelationalProductReachabilityEvidence.contains
    (evidence : RelationalProductReachabilityEvidence) (nodeId : Nat) : Bool :=
  evidence.reachable[nodeId]?.getD false

def RelationalProductReachabilityEvidence.rootsIncluded
    (graph : RelationalProductGraph)
    (evidence : RelationalProductReachabilityEvidence) : Bool :=
  graph.rootNodeIds.all evidence.contains

def RelationalProductReachabilityEvidence.nodeClosedAt
    (graph : RelationalProductGraph)
    (evidence : RelationalProductReachabilityEvidence) (nodeId : Nat) : Bool :=
  if evidence.contains nodeId then
    match graph.getNode? nodeId with
    | none => false
    | some node =>
        node.outgoingEdgeIds.all fun edgeId =>
          match graph.getEdge? edgeId with
          | none => false
          | some edge => edge.infeasible || evidence.contains edge.targetNodeId
  else
    true

def RelationalProductReachabilityEvidence.Closed
    (graph : RelationalProductGraph)
    (evidence : RelationalProductReachabilityEvidence) : Prop :=
  evidence.reachable.size = graph.nodes.size ∧
    evidence.rootsIncluded graph = true ∧
    ∀ nodeId, nodeId < graph.nodes.size ->
      evidence.nodeClosedAt graph nodeId = true

def RelationalProductGraph.InfeasibleEdgesSound (graph : RelationalProductGraph) : Prop :=
  ∀ edgeId, edgeId < graph.edges.size ->
    match graph.getEdge? edgeId with
    | none => False
    | some edge => edge.infeasible = true ->
        ∀ originalState candidateState,
          edge.originalGuard.eval originalState = false ∧
            edge.candidateGuard.eval candidateState = false

theorem RelationalProductGraph.infeasibleEdgesSound_of_indexedValid
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (valid : graph.IndexedValid context) : graph.InfeasibleEdgesSound := by
  intro edgeId before
  have edgeValid := valid.2.1 edgeId before
  cases edgeResult : graph.getEdge? edgeId with
  | none =>
      simp [RelationalProductGraph.edgeAtValid, edgeResult] at edgeValid
  | some edge =>
      simp only [RelationalProductGraph.edgeAtValid, edgeResult] at edgeValid
      cases sourceResult : graph.getNode? edge.sourceNodeId with
      | none => simp [sourceResult] at edgeValid
      | some source =>
          cases targetResult : graph.getNode? edge.targetNodeId with
          | none => simp [sourceResult, targetResult] at edgeValid
          | some target =>
              simp only [sourceResult, targetResult, Bool.and_eq_true, beq_iff_eq]
                at edgeValid
              intro infeasible originalState candidateState
              have classified := edgeValid.2
              rw [infeasible] at classified
              simp only [Bool.true_eq, Bool.and_eq_true] at classified
              exact ⟨edge.originalGuard.eval_false_of_definitelyFalse classified.1
                  originalState,
                edge.candidateGuard.eval_false_of_definitelyFalse classified.2
                  candidateState⟩

def RelationalProductReachabilityEvidence.SoundlyClosed
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (evidence : RelationalProductReachabilityEvidence) : Prop :=
  graph.IndexedValid context ∧ evidence.Closed graph ∧ graph.InfeasibleEdgesSound

end StageA.Relational
