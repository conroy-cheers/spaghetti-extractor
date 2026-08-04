import StageA.RelationalValueProvenance

namespace StageA.Relational

open StageA.Formal
open StageA.Relational.ValueProvenance

inductive RelationalProductEdgeKind where
  | jump
  | branchTaken
  | branchFallthrough
  | call
  | callReturn
  | bulkCopy
  | bulkFill
  | bulkScan
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
  /-- Checked byte span beginning at each return-slot address.  This is proof
  metadata over flat memory, not a source-level stack object. -/
  protectedBytes : Nat := 4
deriving Repr, DecidableEq

structure CallPushStackClaim where
  originalStackAddress : Expr
  candidateStackAddress : Expr
deriving Repr, DecidableEq

def RelationalRuntimeCallFrame.memoryHolds (frame : RelationalRuntimeCallFrame)
    (original candidate : Memory) : Prop :=
  Memory.read32 original frame.originalStackAddress = frame.originalReturnAddress ∧
    Memory.read32 candidate frame.candidateStackAddress = frame.candidateReturnAddress

def RelationalRuntimeCallFrame.protectedRange
    (frame : RelationalRuntimeCallFrame) : DynamicAddressRangePair := {
  id := 0
  originalBase := frame.originalStackAddress
  candidateBase := frame.candidateStackAddress
  size := frame.protectedBytes
}

/-- The protected frame span is concrete, non-wrapping, and disjoint from both
PE images.  It is deliberately weaker than a source-level stack allocation:
its only role is to justify preservation of frame words across image writes. -/
def RelationalRuntimeCallFrame.protectedSpanValid
    (frame : RelationalRuntimeCallFrame) (context : StaticProofContext) : Bool :=
  frame.protectedBytes >= 4 &&
    frame.originalStackAddress.toNat + frame.protectedBytes < 2 ^ 32 &&
    frame.candidateStackAddress.toNat + frame.protectedBytes < 2 ^ 32 &&
    (frame.originalStackAddress.toNat + frame.protectedBytes <=
        context.originalPe.imageBase ||
      context.originalPe.imageBase + context.originalPe.sizeOfImage <=
        frame.originalStackAddress.toNat) &&
    (frame.candidateStackAddress.toNat + frame.protectedBytes <=
        context.candidatePe.imageBase ||
      context.candidatePe.imageBase + context.candidatePe.sizeOfImage <=
        frame.candidateStackAddress.toNat)

def RelationalCallFrame.valid (context : StaticProofContext)
    (frame : RelationalCallFrame) : Bool :=
  match context.codeMap.get? frame.continuationTargetId with
  | none => false
  | some continuation =>
      codeAddressMatches context.originalPe.imageBase continuation.originalRva
        continuation.originalAliases frame.originalReturnAddress &&
      codeAddressMatches context.candidatePe.imageBase continuation.candidateRva
        continuation.candidateAliases frame.candidateReturnAddress

def RelationalRuntimeCallFrame.valid (frame : RelationalRuntimeCallFrame)
    (context : StaticProofContext) : Bool :=
  frame.toRelationalCallFrame.valid context && frame.protectedSpanValid context

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

def DirectCallPushClaim.stackClaim (claim : DirectCallPushClaim) : CallPushStackClaim := {
  originalStackAddress := claim.originalStackAddress
  candidateStackAddress := claim.candidateStackAddress
}

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

/-- Strict call-cutpoint profile used when the decoded region contains only the
architectural return-address push.  Regions with argument stores or other
writes must use the general paired linked-memory transition instead. -/
def DirectCallPushClaim.singletonWriteChecked (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DirectCallPushClaim) : Bool :=
  match claim.frame context with
  | none => false
  | some frame =>
      claim.checked context originalBehavior candidateBehavior &&
        originalBehavior.writes == [
          (claim.originalStackAddress,
            .constant frame.originalReturnAddress.toNat)] &&
        candidateBehavior.writes == [
          (claim.candidateStackAddress,
            .constant frame.candidateReturnAddress.toNat)]

theorem DirectCallPushClaim.singletonWriteMemory_of_checked
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DirectCallPushClaim) (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.singletonWriteChecked context originalBehavior
      candidateBehavior = true)
    (frameResult : claim.runtimeFrame context originalState candidateState =
      some frame) :
    ((originalBehavior.eval originalState).nextMachineState originalState).memory =
        originalState.memory.write32 frame.originalStackAddress
          frame.originalReturnAddress ∧
      ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory =
        candidateState.memory.write32 frame.candidateStackAddress
          frame.candidateReturnAddress := by
  unfold DirectCallPushClaim.singletonWriteChecked at checked
  cases baseFrameResult : claim.frame context with
  | none => simp [baseFrameResult] at checked
  | some baseFrame =>
      simp only [baseFrameResult, Bool.and_eq_true, beq_iff_eq] at checked
      have originalWrites := checked.1.2
      have candidateWrites := checked.2
      unfold DirectCallPushClaim.runtimeFrame at frameResult
      simp only [baseFrameResult, Option.bind_some] at frameResult
      cases frameResult
      constructor <;>
        simp [RelationalBehavior.nextMachineState,
          NormalizedSymbolicBehavior.eval, evalNormalizedWrites, Expr.eval,
          originalWrites, candidateWrites, applyConcreteWrites,
          BitVec.ofNat_toNat]

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

def IndirectCallPushClaim.stackClaim (claim : IndirectCallPushClaim) : CallPushStackClaim := {
  originalStackAddress := claim.originalStackAddress
  candidateStackAddress := claim.candidateStackAddress
}

def IndirectCallPushClaim.asDirectRuntimeClaim
    (claim : IndirectCallPushClaim) : DirectCallPushClaim := {
  calleeTargetId := 0
  continuationTargetId := claim.continuationTargetId
  originalReturnAddress := claim.originalReturnAddress
  candidateReturnAddress := claim.candidateReturnAddress
  originalStackAddress := claim.originalStackAddress
  candidateStackAddress := claim.candidateStackAddress
}

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

def _root_.StageA.Formal.Expr.registerOffsetWitness?
    (register : Reg) : Expr -> Option RegisterOffsetWitness
  | .inputReg source =>
      if source == register then some .input else none
  | .add left (.constant value) => do
      pure (.addRight (← left.registerOffsetWitness? register) value)
  | .add (.constant value) right => do
      pure (.addLeft value (← right.registerOffsetWitness? register))
  | .sub left (.constant value) => do
      pure (.subRight (← left.registerOffsetWitness? register) value)
  | _ => none

def registerOffsetWriteWitnesses?
    (register : Reg) : List (Expr × Expr) -> Option (List RegisterOffsetWitness)
  | [] => some []
  | write :: writes => do
      pure ((← write.1.registerOffsetWitness? register) ::
        (← registerOffsetWriteWitnesses? register writes))

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

/-- A paired scalar word addressed relative to one live runtime frame.  These
facts carry machine-level call arguments and other frame-resident scalar state;
they are not recovered C parameter types. -/
structure ReturnSlotExactWordPair where
  originalOffset : Nat
  candidateOffset : Nat
deriving Repr, DecidableEq

/-- A checked selection of one scalar stack write that becomes an exact word in
the newly-created runtime call frame.  `before` and `after` identify the write
inside the exact decoded write sequence; every later stack write must be
disjoint so the selected value is still present when the callee starts. -/
structure DirectCallStackExactWordSeedClaim where
  before : List PairedStackWordWriteItem
  selected : PairedStackWordWriteItem
  after : List PairedStackWordWriteItem
  exactWord : ReturnSlotExactWordPair
deriving Repr, DecidableEq

def DirectCallStackWritesClaim.runtimeFrame (claim : DirectCallStackWritesClaim)
    (originalState candidateState : MachineState) : RelationalRuntimeCallFrame := {
  continuationTargetId := claim.continuationTargetId
  originalReturnAddress := BitVec.ofNat 32 claim.originalReturnAddress
  candidateReturnAddress := BitVec.ofNat 32 claim.candidateReturnAddress
  originalStackAddress :=
    originalState.registers.get claim.stackWrites.window.originalRegister -
      BitVec.ofNat 32 claim.stackAmount
  candidateStackAddress :=
    candidateState.registers.get claim.stackWrites.window.candidateRegister -
      BitVec.ofNat 32 claim.stackAmount
}

def DirectCallPreparedWritesClaim.runtimeFrame
    (claim : DirectCallPreparedWritesClaim)
    (originalState candidateState : MachineState) : RelationalRuntimeCallFrame := {
  continuationTargetId := claim.continuationTargetId
  originalReturnAddress := BitVec.ofNat 32 claim.originalReturnAddress
  candidateReturnAddress := BitVec.ofNat 32 claim.candidateReturnAddress
  originalStackAddress :=
    originalState.registers.get claim.returnWindow.originalRegister -
      BitVec.ofNat 32 claim.stackAmount
  candidateStackAddress :=
    candidateState.registers.get claim.returnWindow.candidateRegister -
      BitVec.ofNat 32 claim.stackAmount
}

structure DirectCallPreparedExactWordSeedClaim where
  before : List PairedPreparedWordWriteItem
  selected : PairedPreparedWordWriteItem
  after : List PairedPreparedWordWriteItem
  originalSelectedAddress : RegisterOffsetWitness
  candidateSelectedAddress : RegisterOffsetWitness
  originalAfterAddresses : List RegisterOffsetWitness
  candidateAfterAddresses : List RegisterOffsetWitness
  exactWord : ReturnSlotExactWordPair
deriving Repr, DecidableEq

def ReturnSlotExactWordPair.maxOffset : Nat := 65532

def ReturnSlotExactWordPair.checked (word : ReturnSlotExactWordPair) : Bool :=
  word.originalOffset <= ReturnSlotExactWordPair.maxOffset &&
    word.candidateOffset <= ReturnSlotExactWordPair.maxOffset

def DirectCallStackExactWordSeedClaim.checked
    (claim : DirectCallStackWritesClaim)
    (seed : DirectCallStackExactWordSeedClaim) : Bool :=
  claim.stackWrites.writes == seed.before ++ seed.selected :: seed.after &&
    seed.selected.value.staticRelationCompatible .exact &&
    seed.after.all (fun later => decide (
      seed.selected.amount + 4 <= later.amount ||
        later.amount + 4 <= seed.selected.amount)) &&
    seed.exactWord.originalOffset == claim.stackAmount + seed.selected.amount &&
    seed.exactWord.candidateOffset == claim.stackAmount + seed.selected.amount &&
    seed.exactWord.checked

def ReturnSlotExactWordPair.holds (word : ReturnSlotExactWordPair)
    (frame : RelationalRuntimeCallFrame) (original candidate : Memory) : Prop :=
  Memory.read32 original
      (frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset) =
    Memory.read32 candidate
      (frame.candidateStackAddress + BitVec.ofNat 32 word.candidateOffset)

theorem DirectCallStackExactWordSeedClaim.holds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : DirectCallStackWritesClaim)
    (seed : DirectCallStackExactWordSeedClaim)
    (originalState candidateState : MachineState)
    (claimChecked : claim.checked context sourceInvariant originalNormalized
      candidateNormalized = true)
    (seedChecked : seed.checked claim = true)
    (sourceWindowMember : claim.stackWrites.window ∈ sourceInvariant.stackWindows)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    seed.exactWord.holds (claim.runtimeFrame originalState candidateState)
      ((originalNormalized.eval originalState).nextMachineState originalState).memory
      ((candidateNormalized.eval candidateState).nextMachineState candidateState).memory := by
  have claimShape := claimChecked
  simp only [DirectCallStackWritesClaim.checked, Bool.and_eq_true] at claimShape
  have behaviorChecked := claimShape.2
  simp only [DirectCallStackWritesClaim.behaviorChecked, Bool.and_eq_true,
    beq_iff_eq] at behaviorChecked
  rcases behaviorChecked with
    ⟨⟨⟨⟨⟨_originalOutcome, _candidateOutcome⟩, _originalEsp⟩,
      _candidateEsp⟩, originalSymbolicWrites⟩, candidateSymbolicWrites⟩
  have originalWrites : (originalNormalized.eval originalState).writes =
      claim.originalWrites originalState := by
    simp [NormalizedSymbolicBehavior.eval, evalNormalizedWrites,
      DirectCallStackWritesClaim.originalWrites,
      DirectCallStackWritesClaim.originalSymbolicWrites,
      PairedStackWordWritesClaim.originalWrites,
      PairedStackWordWritesClaim.originalSymbolicWrites,
      Expr.eval, originalSymbolicWrites]
  have candidateWrites : (candidateNormalized.eval candidateState).writes =
      claim.candidateWrites candidateState := by
    simp [NormalizedSymbolicBehavior.eval, evalNormalizedWrites,
      DirectCallStackWritesClaim.candidateWrites,
      DirectCallStackWritesClaim.candidateSymbolicWrites,
      PairedStackWordWritesClaim.candidateWrites,
      PairedStackWordWritesClaim.candidateSymbolicWrites,
      Expr.eval, candidateSymbolicWrites]
  simp only [DirectCallStackExactWordSeedClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at seedChecked
  rcases seedChecked with
    ⟨⟨⟨⟨⟨writesExact, selectedExact⟩, afterDisjoint⟩,
      originalOffset⟩, candidateOffset⟩, _wordChecked⟩
  have selectedRead := claim.selectedExactWriteReadsBack context world
    sourceInvariant originalNormalized candidateNormalized seed.before seed.selected
    seed.after originalState candidateState (originalNormalized.eval originalState)
    (candidateNormalized.eval candidateState)
    claimChecked writesExact selectedExact afterDisjoint sourceWindowMember related
    (by simp) (by simp) originalWrites candidateWrites
  have originalFrameAddress :
      (claim.runtimeFrame originalState candidateState).originalStackAddress +
          BitVec.ofNat 32 seed.exactWord.originalOffset =
        originalState.registers.get claim.stackWrites.window.originalRegister +
          BitVec.ofNat 32 seed.selected.amount := by
    rw [originalOffset]
    simp only [DirectCallStackWritesClaim.runtimeFrame, BitVec.ofNat_add]
    rw [← BitVec.add_assoc, BitVec.sub_add_cancel]
  have candidateFrameAddress :
      (claim.runtimeFrame originalState candidateState).candidateStackAddress +
          BitVec.ofNat 32 seed.exactWord.candidateOffset =
        candidateState.registers.get claim.stackWrites.window.candidateRegister +
          BitVec.ofNat 32 seed.selected.amount := by
    rw [candidateOffset]
    simp only [DirectCallStackWritesClaim.runtimeFrame, BitVec.ofNat_add]
    rw [← BitVec.add_assoc, BitVec.sub_add_cancel]
  simpa only [ReturnSlotExactWordPair.holds, originalFrameAddress,
    candidateFrameAddress] using selectedRead

def ReturnSlotOffsetPair.shiftExactWord (offsets : ReturnSlotOffsetPair)
    (word : ReturnSlotExactWordPair) : ReturnSlotOffsetPair := {
  originalRegister := offsets.originalRegister
  originalOffset := offsets.originalOffset + BitVec.ofNat 32 word.originalOffset
  candidateRegister := offsets.candidateRegister
  candidateOffset := offsets.candidateOffset + BitVec.ofNat 32 word.candidateOffset
}

def ReturnSlotExactWordPair.shiftedFrame (word : ReturnSlotExactWordPair)
    (frame : RelationalRuntimeCallFrame) (value : Word) : RelationalRuntimeCallFrame := {
  continuationTargetId := frame.continuationTargetId
  originalReturnAddress := value
  candidateReturnAddress := value
  originalStackAddress :=
    frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset
  candidateStackAddress :=
    frame.candidateStackAddress + BitVec.ofNat 32 word.candidateOffset
}

theorem ReturnSlotOffsetPair.shiftExactWord_holds
    (offsets : ReturnSlotOffsetPair) (word : ReturnSlotExactWordPair)
    (frame : RelationalRuntimeCallFrame) (value : Word)
    (original candidate : Registers Word)
    (holds : offsets.holds frame original candidate) :
    (offsets.shiftExactWord word).holds (word.shiftedFrame frame value)
      original candidate := by
  rcases holds with ⟨originalHolds, candidateHolds⟩
  constructor
  · simpa [ReturnSlotOffsetPair.shiftExactWord,
      ReturnSlotExactWordPair.shiftedFrame, BitVec.add_assoc] using
      congrArg (fun address =>
        address + BitVec.ofNat 32 word.originalOffset) originalHolds
  · simpa [ReturnSlotOffsetPair.shiftExactWord,
      ReturnSlotExactWordPair.shiftedFrame, BitVec.add_assoc] using
      congrArg (fun address =>
        address + BitVec.ofNat 32 word.candidateOffset) candidateHolds

theorem ReturnSlotExactWordPair.shiftedFrame_memoryHolds
    (word : ReturnSlotExactWordPair) (frame : RelationalRuntimeCallFrame)
    (original candidate : Memory) (holds : word.holds frame original candidate) :
    (word.shiftedFrame frame
      (Memory.read32 original
        (frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset))).memoryHolds
      original candidate := by
  constructor
  · rfl
  · simpa [ReturnSlotExactWordPair.shiftedFrame] using holds.symm

theorem ReturnSlotExactWordPair.holds_of_shiftedFrame_memoryHolds
    (word : ReturnSlotExactWordPair) (frame : RelationalRuntimeCallFrame)
    (value : Word) (original candidate : Memory)
    (holds : (word.shiftedFrame frame value).memoryHolds original candidate) :
    word.holds frame original candidate := by
  exact holds.1.trans holds.2.symm

/-- A bounded set of simultaneously valid register-relative names for one
runtime return slot.  The names are proof witnesses for one concrete frame,
not alternative machine states. -/
structure ReturnSlotOffsetInventory where
  locations : List ReturnSlotOffsetPair
  exactWords : List ReturnSlotExactWordPair := []
  preservedImports : List ImportRegisterRelation := []
  preservedRelations : List RegisterRelationPair := []
deriving Repr, DecidableEq

def ReturnSlotOffsetInventory.maxLocations : Nat := 8

def ReturnSlotOffsetInventory.maxPreservedImports : Nat := 8

def ReturnSlotOffsetInventory.maxPreservedRelations : Nat := 8

def ReturnSlotOffsetInventory.maxExactWords : Nat := 16

def ReturnSlotOffsetInventory.checked (inventory : ReturnSlotOffsetInventory) : Bool :=
  !inventory.locations.isEmpty &&
    decide inventory.locations.Nodup &&
    inventory.locations.length <= ReturnSlotOffsetInventory.maxLocations &&
    decide inventory.exactWords.Nodup &&
    inventory.exactWords.length <= ReturnSlotOffsetInventory.maxExactWords &&
    inventory.exactWords.all ReturnSlotExactWordPair.checked &&
    decide inventory.preservedImports.Nodup &&
    inventory.preservedImports.length <= ReturnSlotOffsetInventory.maxPreservedImports &&
    decide inventory.preservedRelations.Nodup &&
    inventory.preservedRelations.length <= ReturnSlotOffsetInventory.maxPreservedRelations

def ReturnSlotOffsetInventory.preservedRelationsUnambiguous
    (inventory : ReturnSlotOffsetInventory) : Bool :=
  inventory.preservedRelations.all fun relation =>
    (inventory.preservedRelations.filter fun candidate =>
      candidate.original == relation.original).length == 1 &&
    (inventory.preservedRelations.filter fun candidate =>
      candidate.candidate == relation.candidate).length == 1

def RegisterValueRelation.staticTargetValid
    (context : StaticProofContext) : RegisterValueRelation -> Bool
  | .fixedCodePointer targetId => (context.codeMap.get? targetId).isSome
  | .exact | .fixedWord _ | .codePointer | .dataPointer | .relatedWord => true

def ReturnSlotOffsetInventory.preservedRelationsChecked
    (context : StaticProofContext) (inventory : ReturnSlotOffsetInventory) : Bool :=
  inventory.checked && inventory.preservedRelationsUnambiguous &&
    inventory.preservedRelations.all fun relation =>
      relation.relation.staticTargetValid context

def ReturnSlotOffsetInventory.holds (inventory : ReturnSlotOffsetInventory)
    (frame : RelationalRuntimeCallFrame) (original candidate : Registers Word) : Prop :=
  inventory.locations ≠ [] ∧
    ∀ location ∈ inventory.locations, location.holds frame original candidate

def ReturnSlotOffsetInventory.exactWordsHold
    (inventory : ReturnSlotOffsetInventory) (frame : RelationalRuntimeCallFrame)
    (original candidate : Memory) : Prop :=
  ∀ word ∈ inventory.exactWords, word.holds frame original candidate

def ReturnSlotOffsetInventory.exactWordsFit
    (inventory : ReturnSlotOffsetInventory)
    (frame : RelationalRuntimeCallFrame) : Bool :=
  inventory.exactWords.all fun word =>
    word.originalOffset + 4 <= frame.protectedBytes &&
      word.candidateOffset + 4 <= frame.protectedBytes

def ReturnSlotOffsetInventory.boundedExactWordsHold
    (inventory : ReturnSlotOffsetInventory) (frame : RelationalRuntimeCallFrame)
    (original candidate : Memory) : Prop :=
  inventory.exactWordsFit frame = true ∧
    inventory.exactWordsHold frame original candidate

theorem ReturnSlotOffsetInventory.exactWordFits_of_bounded
    (inventory : ReturnSlotOffsetInventory) (frame : RelationalRuntimeCallFrame)
    (original candidate : Memory) (word : ReturnSlotExactWordPair)
    (holds : inventory.boundedExactWordsHold frame original candidate)
    (member : word ∈ inventory.exactWords) :
    word.originalOffset + 4 <= frame.protectedBytes ∧
      word.candidateOffset + 4 <= frame.protectedBytes := by
  simp only [ReturnSlotOffsetInventory.boundedExactWordsHold,
    ReturnSlotOffsetInventory.exactWordsFit, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at holds
  exact holds.1 word member

theorem ReturnSlotOffsetInventory.exactWordsHold_member
    (inventory : ReturnSlotOffsetInventory) (frame : RelationalRuntimeCallFrame)
    (original candidate : Memory) (word : ReturnSlotExactWordPair)
    (holds : inventory.exactWordsHold frame original candidate)
    (member : word ∈ inventory.exactWords) :
    word.holds frame original candidate :=
  holds word member

inductive FrameExactExprWitness where
  | constant (value : Nat)
  | exactWordRead32 (location : ReturnSlotOffsetPair)
      (word : ReturnSlotExactWordPair)
      (originalAddress candidateAddress : RegisterOffsetWitness)
  | binary (operation : PairedExactBinaryOp)
      (left right : FrameExactExprWitness)
deriving Repr, DecidableEq

def FrameExactExprWitness.expression
    (side : PairedExactExprSide) : FrameExactExprWitness -> Expr
  | .constant value => .constant value
  | .exactWordRead32 location _ originalAddress candidateAddress =>
      match side with
      | .original => .read32 (originalAddress.expression location.originalRegister)
      | .candidate => .read32 (candidateAddress.expression location.candidateRegister)
  | .binary operation left right =>
      operation.expression (left.expression side) (right.expression side)

def FrameExactExprWitness.checked
    (inventory : ReturnSlotOffsetInventory) : FrameExactExprWitness -> Bool
  | .constant _ => true
  | .exactWordRead32 location word originalAddress candidateAddress =>
      inventory.locations.contains location && inventory.exactWords.contains word &&
        originalAddress.offset ==
          location.originalOffset + BitVec.ofNat 32 word.originalOffset &&
        candidateAddress.offset ==
          location.candidateOffset + BitVec.ofNat 32 word.candidateOffset
  | .binary _ left right =>
      left.checked inventory && right.checked inventory

theorem FrameExactExprWitness.eval_equal_of_checked
    (inventory : ReturnSlotOffsetInventory)
    (witness : FrameExactExprWitness)
    (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : witness.checked inventory = true)
    (locationsHold : inventory.holds frame originalState.registers
      candidateState.registers)
    (exactWordsHold : inventory.exactWordsHold frame originalState.memory
      candidateState.memory) :
    (witness.expression .original).eval originalState =
      (witness.expression .candidate).eval candidateState := by
  induction witness with
  | constant value => rfl
  | exactWordRead32 location word originalAddress candidateAddress =>
      simp only [FrameExactExprWitness.checked, Bool.and_eq_true,
        beq_iff_eq] at checked
      rcases checked with
        ⟨⟨⟨locationMember, wordMember⟩, originalOffset⟩, candidateOffset⟩
      have locationHolds := locationsHold.2 location
        (List.contains_iff_mem.mp locationMember)
      have wordHolds := exactWordsHold word
        (List.contains_iff_mem.mp wordMember)
      have originalAddressEval :
          (originalAddress.expression location.originalRegister).eval originalState =
            frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset := by
        rw [originalAddress.eval_expression, originalOffset]
        simpa [BitVec.add_assoc] using congrArg
          (fun address => address + BitVec.ofNat 32 word.originalOffset)
          locationHolds.1
      have candidateAddressEval :
          (candidateAddress.expression location.candidateRegister).eval candidateState =
            frame.candidateStackAddress + BitVec.ofNat 32 word.candidateOffset := by
        rw [candidateAddress.eval_expression, candidateOffset]
        simpa [BitVec.add_assoc] using congrArg
          (fun address => address + BitVec.ofNat 32 word.candidateOffset)
          locationHolds.2
      simpa [FrameExactExprWitness.expression, Expr.eval,
        machineStateRead32_eq_memoryRead32, originalAddressEval,
        candidateAddressEval, ReturnSlotExactWordPair.holds] using wordHolds
  | binary operation left right leftInduction rightInduction =>
      simp only [FrameExactExprWitness.checked, Bool.and_eq_true] at checked
      have leftEqual := leftInduction checked.1
      have rightEqual := rightInduction checked.2
      cases operation <;> simp_all [FrameExactExprWitness.expression,
        PairedExactBinaryOp.expression, Expr.eval]

structure FrameExactWordValueClaim where
  original : Expr
  candidate : Expr
  witness : FrameExactExprWitness
deriving Repr, DecidableEq

def FrameExactWordValueClaim.checked (inventory : ReturnSlotOffsetInventory)
    (claim : FrameExactWordValueClaim) : Bool :=
  claim.original == claim.witness.expression .original &&
    claim.candidate == claim.witness.expression .candidate &&
    claim.witness.checked inventory

theorem FrameExactWordValueClaim.related_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory) (claim : FrameExactWordValueClaim)
    (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.checked inventory = true)
    (locationsHold : inventory.holds frame originalState.registers
      candidateState.registers)
    (exactWordsHold : inventory.exactWordsHold frame originalState.memory
      candidateState.memory) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (claim.original.eval originalState) (claim.candidate.eval candidateState) = true := by
  simp only [FrameExactWordValueClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with ⟨⟨originalExpression, candidateExpression⟩,
    witnessChecked⟩
  have equal := claim.witness.eval_equal_of_checked inventory frame originalState
    candidateState witnessChecked locationsHold exactWordsHold
  rw [originalExpression, candidateExpression, equal]
  exact wordRelated_self _ _ _ _ _

structure FrameExactStackWordWriteItem where
  window : StackWindowPair
  amount : Nat
  value : FrameExactWordValueClaim
deriving Repr, DecidableEq

def FrameExactStackWordWriteItem.originalAddress
    (item : FrameExactStackWordWriteItem) : Expr :=
  pairedPreparedStackWordAddress item.window.originalRegister item.amount

def FrameExactStackWordWriteItem.candidateAddress
    (item : FrameExactStackWordWriteItem) : Expr :=
  pairedPreparedStackWordAddress item.window.candidateRegister item.amount

def FrameExactStackWordWriteItem.checked
    (sourceInvariant : StateInvariant) (inventory : ReturnSlotOffsetInventory)
    (item : FrameExactStackWordWriteItem) : Bool :=
  sourceInvariant.stackWindows.contains item.window &&
    match pairedStackWordAdjustment? item.amount with
    | none => false
    | some adjustment =>
        adjustment.stackWordChecked item.window && item.value.checked inventory

structure FrameExactStackWordWritesClaim where
  writes : List FrameExactStackWordWriteItem
deriving Repr, DecidableEq

def FrameExactStackWordWritesClaim.originalSymbolicWrites
    (claim : FrameExactStackWordWritesClaim) : List (Expr × Expr) :=
  claim.writes.map fun item => (item.originalAddress, item.value.original)

def FrameExactStackWordWritesClaim.candidateSymbolicWrites
    (claim : FrameExactStackWordWritesClaim) : List (Expr × Expr) :=
  claim.writes.map fun item => (item.candidateAddress, item.value.candidate)

def FrameExactStackWordWritesClaim.originalWrites
    (claim : FrameExactStackWordWritesClaim) (state : MachineState) :
    List (Word × Word) :=
  evalNormalizedWrites state claim.originalSymbolicWrites

def FrameExactStackWordWritesClaim.candidateWrites
    (claim : FrameExactStackWordWritesClaim) (state : MachineState) :
    List (Word × Word) :=
  evalNormalizedWrites state claim.candidateSymbolicWrites

def FrameExactStackWordWritesClaim.checked
    (sourceInvariant : StateInvariant) (inventory : ReturnSlotOffsetInventory)
    (claim : FrameExactStackWordWritesClaim) : Bool :=
  !claim.writes.isEmpty && inventory.checked &&
    claim.writes.all (FrameExactStackWordWriteItem.checked sourceInvariant inventory)

theorem frameExactStackWordUpdates_of_checkedItems
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (inventory : ReturnSlotOffsetInventory)
    (items : List FrameExactStackWordWriteItem)
    (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (rangesValid : world.stackRangesValid context = true)
    (itemsChecked : items.all
      (FrameExactStackWordWriteItem.checked sourceInvariant inventory) = true)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (locationsHold : inventory.holds frame originalState.registers
      candidateState.registers)
  (exactWordsHold : inventory.exactWordsHold frame originalState.memory
      candidateState.memory) :
    ∃ updates : List (PairedPreparedWordUpdate context world),
      (updates.map PairedPreparedWordUpdate.originalWrite =
          items.map fun item =>
            (item.originalAddress.eval originalState,
              item.value.original.eval originalState)) ∧
        (updates.map PairedPreparedWordUpdate.candidateWrite =
          items.map fun item =>
            (item.candidateAddress.eval candidateState,
              item.value.candidate.eval candidateState)) := by
  have relatedForWindows := related
  rcases relatedForWindows with
    ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
  rcases relatedCore with
    ⟨_, _, _, inputStackWindows, _, _, _, _, _, _⟩
  simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
  induction items with
  | nil => exact ⟨[], rfl, rfl⟩
  | cons item rest induction =>
      simp only [List.all_cons, Bool.and_eq_true] at itemsChecked
      have itemChecked := itemsChecked.1
      have restChecked := itemsChecked.2
      rcases induction restChecked with
        ⟨updates, originalUpdates, candidateUpdates⟩
      simp only [FrameExactStackWordWriteItem.checked, Bool.and_eq_true]
        at itemChecked
      have windowMember := itemChecked.1
      cases adjustmentResult : pairedStackWordAdjustment? item.amount with
      | none => simp [adjustmentResult] at itemChecked
      | some adjustment =>
          simp only [adjustmentResult, Bool.and_eq_true] at itemChecked
          have adjustmentChecked := itemChecked.2.1
          have valueChecked := itemChecked.2.2
          have windowHolds := inputStackWindows item.window
            (List.contains_iff_mem.mp windowMember)
          rcases pairedStackWordLocation_at_adjustment context world item.window
              originalState candidateState rangesValid windowHolds adjustment
              adjustmentChecked with
            ⟨location, originalLocation, candidateLocation⟩
          have locationValid : location.range.disjointFromImages context = true := by
            have validRows := rangesValid
            simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
              List.all_eq_true] at validRows
            exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
          have valuesRelated := item.value.related_of_checked context world inventory
            frame originalState candidateState valueChecked locationsHold exactWordsHold
          let stackUpdate : PairedStackWordUpdate context world := {
            location
            locationValid
            originalValue := item.value.original.eval originalState
            candidateValue := item.value.candidate.eval candidateState
            valuesRelated
          }
          let update : PairedPreparedWordUpdate context world := .stack stackUpdate
          have originalAddressEval := StackAdjustment.eval_expression_of_matches
            adjustment item.window.originalRegister item.originalAddress originalState
            (pairedPreparedStackWordAddress_matches_adjustment
              item.window.originalRegister item.amount adjustment adjustmentResult)
          have candidateAddressEval := StackAdjustment.eval_expression_of_matches
            adjustment item.window.candidateRegister item.candidateAddress candidateState
            (pairedPreparedStackWordAddress_matches_adjustment
              item.window.candidateRegister item.amount adjustment adjustmentResult)
          refine ⟨update :: updates, ?_, ?_⟩
          · simp only [List.map_cons]
            rw [originalUpdates]
            simp only [update, stackUpdate, PairedPreparedWordUpdate.originalWrite,
              PairedStackWordUpdate.originalWrite]
            rw [originalLocation, ← originalAddressEval]
          · simp only [List.map_cons]
            rw [candidateUpdates]
            simp only [update, stackUpdate, PairedPreparedWordUpdate.candidateWrite,
              PairedStackWordUpdate.candidateWrite]
            rw [candidateLocation, ← candidateAddressEval]

theorem StateRel.afterFrameExactStackWordWritesEvaluation
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (inventory : ReturnSlotOffsetInventory) (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (claim : FrameExactStackWordWritesClaim)
    (contextValid : context.StructurallyValid)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (claimChecked : claim.checked sourceInvariant inventory = true)
    (locationsHold : inventory.holds frame originalState.registers
      candidateState.registers)
    (exactWordsHold : inventory.exactWordsHold frame originalState.memory
      candidateState.memory)
    (originalWrites : originalBehavior.writes = claim.originalWrites originalState)
    (candidateWrites : candidateBehavior.writes = claim.candidateWrites candidateState)
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
    (registers : registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) targetInvariant.registerRelations
      originalBehavior.registers candidateBehavior.registers = true)
    (bounds : boundsRelated targetInvariant.bounds originalBehavior.registers
      candidateBehavior.registers = true)
    (separations : addressSeparationsRelated targetInvariant.addressSeparations
      originalBehavior.registers candidateBehavior.registers = true)
    (stackWindows : stackWindowsRelated world targetInvariant.stackWindows
      originalBehavior.registers candidateBehavior.registers = true)
    (x87 : (originalBehavior.nextMachineState originalState).x87 =
      (candidateBehavior.nextMachineState candidateState).x87)
    (flags : flagsRelated targetInvariant.flagBits originalBehavior.eflags
      candidateBehavior.eflags = true)
    (importRegisters : importRegisterRelationsHold world
      targetInvariant.importRegisterRelations originalBehavior.registers
      candidateBehavior.registers = true)
    (originRegisters : registerValueOriginRelationsHold context world
      targetInvariant.registerValueOriginRelations originalBehavior.registers
      candidateBehavior.registers = true)
    (memoryOrigins : memoryValueOriginRelationsHold context world
      targetInvariant.memoryValueOriginRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicRegisters : activeDynamicRegisterRangeRelationsHold context world
      targetInvariant.dynamicRegisterRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicStacks : activeDynamicStackRangeRelationsHold context world
      targetInvariant.dynamicStackRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (predicates : pairedStatePredicatesHold targetInvariant.predicates
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true) :
    StateRel context world targetInvariant
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) := by
  simp only [FrameExactStackWordWritesClaim.checked, Bool.and_eq_true]
    at claimChecked
  have itemsChecked := claimChecked.2
  have relatedForUpdates := related
  have relatedForFinal := related
  rcases related with
    ⟨worldValid, stackRangesValid, stackMemory, importsStatic, _importsComplete,
      importsMemory, originalImmutable, candidateImmutable, relatedCore,
      _inputImportRegisters⟩
  rcases relatedCore with
    ⟨_inputRegisters, _inputBounds, _inputSeparations, _inputStackWindows,
      inputMemory, inputDynamicMemory, _inputUndefined, _inputX87,
      _inputFlags, _inputFsBase⟩
  rcases frameExactStackWordUpdates_of_checkedItems context world sourceInvariant
      inventory claim.writes frame originalState candidateState stackRangesValid
      itemsChecked relatedForUpdates locationsHold exactWordsHold with
    ⟨updates, originalUpdateWrites, candidateUpdateWrites⟩
  have worldDynamicValid : world.dynamicRangesValid context = true := by
    simp only [RelationalWorld.valid, Bool.and_eq_true] at worldValid
    exact worldValid.1.1.1.1
  have staticSlotsValid : staticDynamicPointerSlotsValid context = true := by
    rcases contextValid with
      ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _, _⟩
    exact slotsValid
  have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
    rcases contextValid with
      ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _⟩
    exact slotsValid
  have memoryFamilies :=
    RelationalMemoryFamiliesHold.afterPairedPreparedWordUpdates context world
      stackRangesValid importsStatic worldDynamicValid staticSlotsValid
      staticWordSlotsValid updates originalState.memory candidateState.memory {
        stackRanges := stackMemory
        importAddresses := importsMemory
        originalImmutable := originalImmutable
        candidateImmutable := candidateImmutable
        ordinary := inputMemory
        staticPointerSlots := inputDynamicMemory.staticPointerSlots
        staticWordSlots := inputDynamicMemory.staticWordSlots
      }
  have originalUpdateWrites' :
      updates.map PairedPreparedWordUpdate.originalWrite =
        claim.originalWrites originalState := by
    simpa [FrameExactStackWordWritesClaim.originalWrites,
      FrameExactStackWordWritesClaim.originalSymbolicWrites,
      evalNormalizedWrites] using originalUpdateWrites
  have candidateUpdateWrites' :
      updates.map PairedPreparedWordUpdate.candidateWrite =
        claim.candidateWrites candidateState := by
    simpa [FrameExactStackWordWritesClaim.candidateWrites,
      FrameExactStackWordWritesClaim.candidateSymbolicWrites,
      evalNormalizedWrites] using candidateUpdateWrites
  rw [originalUpdateWrites', candidateUpdateWrites'] at memoryFamilies
  exact StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
    targetInvariant originalState candidateState originalBehavior candidateBehavior
    (claim.originalWrites originalState) (claim.candidateWrites candidateState)
    relatedForFinal originalWrites candidateWrites originalNoX87 candidateNoX87
    memoryFamilies registers bounds separations stackWindows x87 flags
    importRegisters originRegisters memoryOrigins dynamicRegisters dynamicStacks
    predicates

def ReturnSlotOffsetInventory.preservedImportsHold
    (inventory : ReturnSlotOffsetInventory) (world : RelationalWorld)
    (original candidate : Registers Word) : Bool :=
  importRegisterRelationsHold world inventory.preservedImports original candidate

def ReturnSlotOffsetInventory.preservedRelationsHold
    (context : StaticProofContext) (inventory : ReturnSlotOffsetInventory)
    (world : RelationalWorld) (original candidate : Registers Word) : Bool :=
  registerRelationsHold context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    inventory.preservedRelations original candidate

theorem registerRelationsHold_append_of_holds
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (left right : List RegisterRelationPair) (original candidate : Registers Word)
    (leftHolds : registerRelationsHold originalImageBase candidateImageBase targets
      values left original candidate = true)
    (rightHolds : registerRelationsHold originalImageBase candidateImageBase targets
      values right original candidate = true) :
    registerRelationsHold originalImageBase candidateImageBase targets values
      (left ++ right) original candidate = true := by
  simp only [registerRelationsHold, List.all_append, Bool.and_eq_true]
  exact ⟨leftHolds, rightHolds⟩

theorem importRegisterRelationsHold_append_of_holds
    (world : RelationalWorld) (left right : List ImportRegisterRelation)
    (original candidate : Registers Word)
    (leftHolds : importRegisterRelationsHold world left original candidate = true)
    (rightHolds : importRegisterRelationsHold world right original candidate = true) :
    importRegisterRelationsHold world (left ++ right) original candidate = true := by
  simp only [importRegisterRelationsHold, List.all_append, Bool.and_eq_true]
  exact ⟨leftHolds, rightHolds⟩

/-- Extend only the import-address component of an invariant.  This is used at
returning import cutpoints after checked runtime-frame facts have crossed the
exact machine-level environment transition. -/
def StateInvariant.withAdditionalImportRegisterRelations
    (invariant : StateInvariant) (relations : List ImportRegisterRelation) :
    StateInvariant :=
  { invariant with
    importRegisterRelations := invariant.importRegisterRelations ++ relations }

theorem StateRel.withAdditionalImportRegisterRelations
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (relations : List ImportRegisterRelation)
    (original candidate : MachineState)
    (related : StateRel context world invariant original candidate)
    (additionalHold : importRegisterRelationsHold world relations
      original.registers candidate.registers = true) :
    StateRel context world
      (invariant.withAdditionalImportRegisterRelations relations)
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
  have strengthenedImports := importRegisterRelationsHold_append_of_holds
    world invariant.importRegisterRelations relations original.registers
    candidate.registers importRegisters additionalHold
  refine ⟨worldValid, stackRangesValid, stackMemory, importsStatic,
    importsComplete, importsMemory, originalImmutable, candidateImmutable, ?_, ?_⟩
  · refine ⟨registers, bounds, separations, stackWindows, ordinaryMemory,
      ?_, undefinedValue, x87, flags, fsBase⟩
    exact {
      staticPointerSlots := dynamicMemory.staticPointerSlots
      staticWordSlots := dynamicMemory.staticWordSlots
      active := {
        registerRanges := by
          simpa [StateInvariant.withAdditionalImportRegisterRelations] using
            dynamicMemory.active.registerRanges
        stackRanges := by
          simpa [StateInvariant.withAdditionalImportRegisterRelations] using
            dynamicMemory.active.stackRanges
      }
    }
  · refine ⟨strengthenedImports, ?_, ?_, ?_, ?_, ?_⟩
    · simpa [StateInvariant.withAdditionalImportRegisterRelations] using
        originRegisters
    · simpa [StateInvariant.withAdditionalImportRegisterRelations] using
        memoryOrigins
    · simpa [StateInvariant.withAdditionalImportRegisterRelations] using
        dynamicRegisters
    · simpa [StateInvariant.withAdditionalImportRegisterRelations] using
        dynamicStacks
    · simpa [StateInvariant.withAdditionalImportRegisterRelations] using predicates

/-- Strengthen only the ordinary register component of an invariant.  Runtime
frame facts use this operation to enter the ordinary segment prover without
changing any of the memory, stack, flag, x87, or predicate assumptions. -/
def StateInvariant.withAdditionalRegisterRelations
    (invariant : StateInvariant) (relations : List RegisterRelationPair) :
    StateInvariant :=
  { invariant with
    registerRelations := invariant.registerRelations ++ relations }

/-- A frame-local register inventory may strengthen `StateRel` only after its
relations have been proved over the concrete machine registers. -/
theorem StateRel.withAdditionalRegisterRelations
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (relations : List RegisterRelationPair)
    (original candidate : MachineState)
    (related : StateRel context world invariant original candidate)
    (additionalHold : registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) relations original.registers
      candidate.registers = true) :
    StateRel context world
      (invariant.withAdditionalRegisterRelations relations) original candidate := by
  rcases related with
    ⟨worldValid, stackRangesValid, stackMemory, importsStatic, importsComplete,
      importsMemory, originalImmutable, candidateImmutable, core, trailing⟩
  rcases core with
    ⟨registers, bounds, separations, stackWindows, ordinaryMemory,
      dynamicMemory, undefinedValue, x87, flags, fsBase⟩
  have strengthenedRegisters := registerRelationsHold_append_of_holds
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    invariant.registerRelations relations original.registers candidate.registers
    registers additionalHold
  refine ⟨worldValid, stackRangesValid, stackMemory, importsStatic,
    importsComplete, importsMemory, originalImmutable, candidateImmutable, ?_, ?_⟩
  · refine ⟨strengthenedRegisters, bounds, separations, stackWindows,
      ordinaryMemory, ?_, undefinedValue, x87, flags, fsBase⟩
    exact {
      staticPointerSlots := dynamicMemory.staticPointerSlots
      staticWordSlots := dynamicMemory.staticWordSlots
      active := {
        registerRanges := by
          simpa [StateInvariant.withAdditionalRegisterRelations] using
            dynamicMemory.active.registerRanges
        stackRanges := by
          simpa [StateInvariant.withAdditionalRegisterRelations] using
            dynamicMemory.active.stackRanges
      }
    }
  · simpa [StateInvariant.withAdditionalRegisterRelations] using trailing

theorem registerRelationsHold_of_perm
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (source target : List RegisterRelationPair) (original candidate : Registers Word)
    (permutation : source.Perm target)
    (sourceHolds : registerRelationsHold originalImageBase candidateImageBase targets
      values source original candidate = true) :
    registerRelationsHold originalImageBase candidateImageBase targets values
      target original candidate = true := by
  simp only [registerRelationsHold, List.all_eq_true] at sourceHolds ⊢
  intro relation relationMember
  exact sourceHolds relation (permutation.mem_iff.mpr relationMember)

def ReturnSlotOffsetInventory.preservesImportsAcross
    (inventory : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  inventory.checked &&
    inventory.preservedImports.all fun relation =>
      originalBehavior.registers.get relation.original == .inputReg relation.original &&
        candidateBehavior.registers.get relation.candidate == .inputReg relation.candidate

def ReturnSlotOffsetInventory.preservesRelationsAcross
    (context : StaticProofContext) (inventory : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  inventory.preservedRelationsChecked context &&
    inventory.preservedRelations.all fun relation =>
      originalBehavior.registers.get relation.original == .inputReg relation.original &&
        candidateBehavior.registers.get relation.candidate == .inputReg relation.candidate

theorem ReturnSlotOffsetInventory.preservedRelationsHold_after_of_checked
    (context : StaticProofContext) (inventory : ReturnSlotOffsetInventory)
    (world : RelationalWorld)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalState candidateState : MachineState)
    (checked : inventory.preservesRelationsAcross context originalBehavior
      candidateBehavior = true)
    (holds : inventory.preservedRelationsHold context world originalState.registers
      candidateState.registers = true) :
    inventory.preservedRelationsHold context world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [ReturnSlotOffsetInventory.preservesRelationsAcross,
    Bool.and_eq_true] at checked
  have preserved := checked.2
  unfold ReturnSlotOffsetInventory.preservedRelationsHold at holds ⊢
  simp only [registerRelationsHold, List.all_eq_true] at holds preserved ⊢
  intro relation relationMember
  have relationHolds := holds relation relationMember
  have relationPreserved := preserved relation relationMember
  simp only [Bool.and_eq_true, beq_iff_eq] at relationPreserved
  rcases relationPreserved with ⟨originalRegister, candidateRegister⟩
  simpa [NormalizedSymbolicBehavior.eval_registers,
    evalNormalizedRegisters_get, originalRegister, candidateRegister, Expr.eval]
    using relationHolds

theorem ReturnSlotOffsetInventory.preservedImportsHold_after_of_checked
    (inventory : ReturnSlotOffsetInventory) (world : RelationalWorld)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalState candidateState : MachineState)
    (checked : inventory.preservesImportsAcross originalBehavior candidateBehavior = true)
    (holds : inventory.preservedImportsHold world originalState.registers
      candidateState.registers = true) :
    inventory.preservedImportsHold world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [ReturnSlotOffsetInventory.preservesImportsAcross, Bool.and_eq_true] at checked
  have preserved := checked.2
  unfold ReturnSlotOffsetInventory.preservedImportsHold at holds ⊢
  simp only [importRegisterRelationsHold, List.all_eq_true] at holds preserved ⊢
  intro relation relationMember
  have relationHolds := holds relation relationMember
  have relationPreserved := preserved relation relationMember
  simp only [Bool.and_eq_true, beq_iff_eq] at relationPreserved
  rcases relationPreserved with ⟨originalRegister, candidateRegister⟩
  simp only [ImportRegisterRelation.holds, List.any_eq_true] at relationHolds ⊢
  rcases relationHolds with ⟨binding, bindingMember, bindingChecks⟩
  refine ⟨binding, bindingMember, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq] at bindingChecks ⊢
  rcases bindingChecks with ⟨⟨imported, originalAddress⟩, candidateAddress⟩
  refine ⟨⟨imported, ?_⟩, ?_⟩
  · simp only [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, originalRegister, Expr.eval]
    exact originalAddress
  · simp only [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, candidateRegister, Expr.eval]
    exact candidateAddress

def ReturnSlotOffsetInventory.seedsPreservedImportsFrom
    (inventory : ReturnSlotOffsetInventory) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  inventory.preservesImportsAcross originalBehavior candidateBehavior &&
    inventory.preservedImports.all sourceInvariant.importRegisterRelations.contains

theorem ReturnSlotOffsetInventory.preservedImportsHold_after_stateRel_of_checked
    (context : StaticProofContext) (inventory : ReturnSlotOffsetInventory)
    (world : RelationalWorld) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalState candidateState : MachineState)
    (checked : inventory.seedsPreservedImportsFrom sourceInvariant
      originalBehavior candidateBehavior = true)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    inventory.preservedImportsHold world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [ReturnSlotOffsetInventory.seedsPreservedImportsFrom,
    Bool.and_eq_true] at checked
  rcases checked with ⟨preserves, sourceMembers⟩
  simp only [List.all_eq_true] at sourceMembers
  have sourceHolds : inventory.preservedImportsHold world originalState.registers
      candidateState.registers = true := by
    unfold ReturnSlotOffsetInventory.preservedImportsHold
      importRegisterRelationsHold
    simp only [List.all_eq_true]
    intro relation relationMember
    rcases related with
      ⟨_worldStatic, _stackRangesValid, _stackMemory, _importsStatic,
        _importsComplete, _importsMemory, _originalImmutable, _candidateImmutable,
        _relatedCore, importRegisters⟩
    have invariantHolds := importRegisters.1
    simp only [importRegisterRelationsHold, List.all_eq_true] at invariantHolds
    exact invariantHolds relation
      (by simpa using sourceMembers relation relationMember)
  exact inventory.preservedImportsHold_after_of_checked world originalBehavior
    candidateBehavior originalState candidateState preserves sourceHolds

def ReturnSlotOffsetInventory.seedsPreservedRelationsFromOutputClaims
    (context : StaticProofContext) (inventory : ReturnSlotOffsetInventory)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List InvariantWP.RegisterOutputClaim) : Bool :=
  inventory.preservedRelationsChecked context &&
    claims.map InvariantWP.RegisterOutputClaim.output ==
      inventory.preservedRelations &&
    claims.all (InvariantWP.RegisterOutputClaim.nonMemoryChecked context region
      originalBehavior candidateBehavior)

theorem ReturnSlotOffsetInventory.preservedRelationsHold_after_stateRel_of_outputClaims
    (context : StaticProofContext) (inventory : ReturnSlotOffsetInventory)
    (world : RelationalWorld) (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List InvariantWP.RegisterOutputClaim)
    (originalState candidateState : MachineState)
    (checked : inventory.seedsPreservedRelationsFromOutputClaims context region
      originalBehavior candidateBehavior claims = true)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    inventory.preservedRelationsHold context world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [ReturnSlotOffsetInventory.seedsPreservedRelationsFromOutputClaims,
    Bool.and_eq_true, beq_iff_eq] at checked
  rcases checked with ⟨⟨_inventoryChecked, inventoryExact⟩, claimsChecked⟩
  unfold ReturnSlotOffsetInventory.preservedRelationsHold
  rw [← inventoryExact]
  exact InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims context world region
    originalBehavior candidateBehavior claims claimsChecked originalState candidateState related

def ReturnSlotOffsetInventory.singleton (location : ReturnSlotOffsetPair) :
    ReturnSlotOffsetInventory := { locations := [location] }

def ReturnSlotOffsetInventory.zero : ReturnSlotOffsetInventory :=
  ReturnSlotOffsetInventory.singleton ReturnSlotOffsetPair.zero

theorem ReturnSlotOffsetInventory.checked_nonempty
    (inventory : ReturnSlotOffsetInventory) (checked : inventory.checked = true) :
    inventory.locations ≠ [] := by
  intro empty
  simp [ReturnSlotOffsetInventory.checked, empty] at checked

theorem ReturnSlotOffsetInventory.holds_member
    (inventory : ReturnSlotOffsetInventory) (frame : RelationalRuntimeCallFrame)
    (original candidate : Registers Word) (location : ReturnSlotOffsetPair)
    (holds : inventory.holds frame original candidate)
    (member : location ∈ inventory.locations) :
    location.holds frame original candidate :=
  holds.2 location member

theorem ReturnSlotOffsetInventory.singleton_holds
    (location : ReturnSlotOffsetPair) (frame : RelationalRuntimeCallFrame)
    (original candidate : Registers Word)
    (holds : location.holds frame original candidate) :
    (ReturnSlotOffsetInventory.singleton location).holds frame original candidate := by
  exact ⟨by simp [ReturnSlotOffsetInventory.singleton], by
    intro candidateLocation member
    simp only [ReturnSlotOffsetInventory.singleton, List.mem_singleton] at member
    simpa [member] using holds⟩

theorem ReturnSlotOffsetInventory.zero_holds
    (frame : RelationalRuntimeCallFrame) (original candidate : Registers Word)
    (holds : ReturnSlotOffsetPair.zero.holds frame original candidate) :
    ReturnSlotOffsetInventory.zero.holds frame original candidate :=
  ReturnSlotOffsetInventory.singleton_holds ReturnSlotOffsetPair.zero frame
    original candidate holds

def ReturnSlotOffsetInventory.representative
    (inventory : ReturnSlotOffsetInventory) : ReturnSlotOffsetPair :=
  inventory.locations.headD ReturnSlotOffsetPair.zero

theorem ReturnSlotOffsetInventory.representative_holds
    (inventory : ReturnSlotOffsetInventory) (frame : RelationalRuntimeCallFrame)
    (original candidate : Registers Word)
    (holds : inventory.holds frame original candidate) :
    inventory.representative.holds frame original candidate := by
  cases locationsResult : inventory.locations with
  | nil => exact False.elim (holds.1 locationsResult)
  | cons location locations =>
      simpa [ReturnSlotOffsetInventory.representative, locationsResult] using
        holds.2 location (by simp [locationsResult])

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

/-- A source-relative caller word and the corresponding callee-entry-relative
word.  Explicit affine witnesses bind the output ESP and every write address to
the normalized semantics; they are checked proof data rather than instruction
pattern assumptions. -/
structure CallerFrameWordEntryClaim where
  source : ReturnSlotExactWordPair
  entry : ReturnSlotExactWordPair
  originalStack : RegisterOffsetWitness
  candidateStack : RegisterOffsetWitness
  originalWrites : List RegisterOffsetWitness
  candidateWrites : List RegisterOffsetWitness
deriving Repr, DecidableEq

def CallerFrameWordEntryClaim.derive?
    (source entry : ReturnSlotExactWordPair)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) :
    Option CallerFrameWordEntryClaim := do
  let originalStack ←
    originalBehavior.registers.esp.registerOffsetWitness? .esp
  let candidateStack ←
    candidateBehavior.registers.esp.registerOffsetWitness? .esp
  let originalWrites ←
    registerOffsetWriteWitnesses? .esp originalBehavior.writes
  let candidateWrites ←
    registerOffsetWriteWitnesses? .esp candidateBehavior.writes
  pure {
    source
    entry
    originalStack
    candidateStack
    originalWrites
    candidateWrites
  }

def CallerFrameWordEntryClaim.sideChecked
    (claim : CallerFrameWordEntryClaim)
    (behavior : NormalizedSymbolicBehavior)
    (sourceOffset entryOffset : Nat)
    (stack : RegisterOffsetWitness)
    (writes : List RegisterOffsetWitness) : Bool :=
  sourceOffset <= ReturnSlotExactWordPair.maxOffset &&
    entryOffset <= ReturnSlotExactWordPair.maxOffset &&
    stack.expression .esp == behavior.registers.esp &&
    stack.offset + BitVec.ofNat 32 entryOffset ==
      BitVec.ofNat 32 sourceOffset &&
    registerOffsetWitnessesAvoidWord .esp
      (BitVec.ofNat 32 sourceOffset) writes behavior.writes

def CallerFrameWordEntryClaim.checked
    (claim : CallerFrameWordEntryClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  claim.sideChecked originalBehavior claim.source.originalOffset
      claim.entry.originalOffset claim.originalStack claim.originalWrites &&
    claim.sideChecked candidateBehavior claim.source.candidateOffset
      claim.entry.candidateOffset claim.candidateStack claim.candidateWrites

theorem CallerFrameWordEntryClaim.sideMemoryPreserved_of_checked
    (claim : CallerFrameWordEntryClaim)
    (behavior : NormalizedSymbolicBehavior)
    (sourceOffset entryOffset : Nat)
    (stack : RegisterOffsetWitness)
    (writes : List RegisterOffsetWitness)
    (state : MachineState)
    (checked : claim.sideChecked behavior sourceOffset entryOffset
      stack writes = true) :
    Memory.read32
        ((behavior.eval state).nextMachineState state).memory
        (((behavior.eval state).nextMachineState state).registers.esp +
          BitVec.ofNat 32 entryOffset) =
      Memory.read32 state.memory
        (state.registers.esp + BitVec.ofNat 32 sourceOffset) := by
  simp only [CallerFrameWordEntryClaim.sideChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  have stackExpression := checked.1.1.2
  have stackOffset := checked.1.2
  have writesChecked := checked.2
  have stackExpressionGet :
      stack.expression .esp = behavior.registers.get .esp := by
    simpa using stackExpression
  have addressExact :
      ((behavior.eval state).nextMachineState state).registers.esp +
          BitVec.ofNat 32 entryOffset =
        state.registers.esp + BitVec.ofNat 32 sourceOffset := by
    simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval]
    change (behavior.registers.get .esp).eval state +
        BitVec.ofNat 32 entryOffset =
      state.registers.get .esp + BitVec.ofNat 32 sourceOffset
    rw [← stackExpressionGet, stack.eval_expression, BitVec.add_assoc,
      stackOffset]
  rw [addressExact]
  simp only [RelationalBehavior.nextMachineState,
    NormalizedSymbolicBehavior.eval]
  exact Memory.read32_applyConcreteWrites_of_avoids _ _ _
    (registerOffsetWitnessesAvoidWord_of_closed .esp
      (BitVec.ofNat 32 sourceOffset) writes behavior.writes state
      (registerOffsetWitnessesAvoidWordClosed_of_checked .esp
        (BitVec.ofNat 32 sourceOffset) writes behavior.writes writesChecked))

theorem CallerFrameWordEntryClaim.memoryPreserved_of_checked
    (claim : CallerFrameWordEntryClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalState candidateState : MachineState)
    (checked : claim.checked originalBehavior candidateBehavior = true) :
    Memory.read32
          ((originalBehavior.eval originalState).nextMachineState
            originalState).memory
          (((originalBehavior.eval originalState).nextMachineState
              originalState).registers.esp +
            BitVec.ofNat 32 claim.entry.originalOffset) =
        Memory.read32 originalState.memory
          (originalState.registers.esp +
            BitVec.ofNat 32 claim.source.originalOffset) /\
      Memory.read32
          ((candidateBehavior.eval candidateState).nextMachineState
            candidateState).memory
          (((candidateBehavior.eval candidateState).nextMachineState
              candidateState).registers.esp +
            BitVec.ofNat 32 claim.entry.candidateOffset) =
        Memory.read32 candidateState.memory
          (candidateState.registers.esp +
            BitVec.ofNat 32 claim.source.candidateOffset) := by
  simp only [CallerFrameWordEntryClaim.checked, Bool.and_eq_true] at checked
  exact ⟨claim.sideMemoryPreserved_of_checked originalBehavior
      claim.source.originalOffset claim.entry.originalOffset
      claim.originalStack claim.originalWrites originalState checked.1,
    claim.sideMemoryPreserved_of_checked candidateBehavior
      claim.source.candidateOffset claim.entry.candidateOffset
      claim.candidateStack claim.candidateWrites candidateState checked.2⟩

def DirectCallPreparedExactWordSeedClaim.checked
    (claim : DirectCallPreparedWritesClaim)
    (seed : DirectCallPreparedExactWordSeedClaim) : Bool :=
  claim.preparedWrites.writes == seed.before ++ seed.selected :: seed.after &&
    match seed.selected with
    | .stack window _ value =>
        window == claim.returnWindow &&
          value.staticRelationCompatible .exact &&
          seed.originalSelectedAddress.expression window.originalRegister ==
            seed.selected.originalAddress &&
          seed.candidateSelectedAddress.expression window.candidateRegister ==
            seed.selected.candidateAddress &&
          registerOffsetWitnessesAvoidWord window.originalRegister
            seed.originalSelectedAddress.offset seed.originalAfterAddresses
            (seed.after.map fun item =>
              (item.originalAddress, item.value.original)) &&
          registerOffsetWitnessesAvoidWord window.candidateRegister
            seed.candidateSelectedAddress.offset seed.candidateAfterAddresses
            (seed.after.map fun item =>
              (item.candidateAddress, item.value.candidate)) &&
          wordOffsetsDisjoint seed.originalSelectedAddress.offset
            (BitVec.ofNat 32 (2 ^ 32 - claim.stackAmount)) &&
          wordOffsetsDisjoint seed.candidateSelectedAddress.offset
            (BitVec.ofNat 32 (2 ^ 32 - claim.stackAmount)) &&
          seed.originalSelectedAddress.offset ==
            BitVec.ofNat 32 (2 ^ 32 - claim.stackAmount) +
              BitVec.ofNat 32 seed.exactWord.originalOffset &&
          seed.candidateSelectedAddress.offset ==
            BitVec.ofNat 32 (2 ^ 32 - claim.stackAmount) +
              BitVec.ofNat 32 seed.exactWord.candidateOffset &&
          seed.exactWord.checked
    | _ => false

/-- A checked bridge from one exact active-frame word to a register output.
The address witnesses retain the exact decoded expression shape while their
offsets tie that expression to the frame-relative word.  Assembled reads also
carry one witness per decoded write so Lean can check that the word was not
overwritten before the read value was assembled. -/
structure FrameExactWordRegisterOutputClaim where
  sourceLocation : ReturnSlotOffsetPair
  word : ReturnSlotExactWordPair
  output : RegisterRelationPair
  originalAddress : RegisterOffsetWitness
  candidateAddress : RegisterOffsetWitness
  originalAssembledRead : Bool := false
  candidateAssembledRead : Bool := false
  originalInputAssembledRead : Bool := false
  candidateInputAssembledRead : Bool := false
  originalWriteWitnesses : List RegisterOffsetWitness := []
  candidateWriteWitnesses : List RegisterOffsetWitness := []
deriving Repr, DecidableEq

def frameExactWordInputAssembledRead
    (register : Reg) (address : RegisterOffsetWitness) : Expr :=
  let base := address.expression register
  .bitOr
    (.bitOr (.read8 base)
      (.shiftLeft (.read8 (.add base (.constant 1))) 8))
    (.bitOr (.shiftLeft (.read8 (.add base (.constant 2))) 16)
      (.shiftLeft (.read8 (.add base (.constant 3))) 24))

@[simp] theorem frameExactWordInputAssembledRead_eval
    (state : MachineState) (register : Reg)
    (address : RegisterOffsetWitness) :
    (frameExactWordInputAssembledRead register address).eval state =
      Memory.read32 state.memory ((address.expression register).eval state) := by
  simpa [frameExactWordInputAssembledRead, Expr.eval] using
    assembledMemoryRead32_eq state.memory ((address.expression register).eval state)

def FrameExactWordRegisterOutputClaim.expectedExpression
    (inputAssembled assembled : Bool)
    (register : Reg) (address : RegisterOffsetWitness)
    (behavior : NormalizedSymbolicBehavior) : Expr :=
  if inputAssembled then
    frameExactWordInputAssembledRead register address
  else if assembled then
    (address.expression register).read32AfterWrites behavior.writes
  else
    .read32 (address.expression register)

def FrameExactWordRegisterOutputClaim.checked
    (inventory : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FrameExactWordRegisterOutputClaim) : Bool :=
  inventory.checked &&
    inventory.locations.contains claim.sourceLocation &&
    inventory.exactWords.contains claim.word &&
    claim.output.relation == .exact &&
    claim.originalAddress.offset == claim.sourceLocation.originalOffset +
      BitVec.ofNat 32 claim.word.originalOffset &&
    claim.candidateAddress.offset == claim.sourceLocation.candidateOffset +
      BitVec.ofNat 32 claim.word.candidateOffset &&
    !(claim.originalInputAssembledRead && claim.originalAssembledRead) &&
    !(claim.candidateInputAssembledRead && claim.candidateAssembledRead) &&
    originalBehavior.registers.get claim.output.original ==
      FrameExactWordRegisterOutputClaim.expectedExpression
        claim.originalInputAssembledRead
        claim.originalAssembledRead
        claim.sourceLocation.originalRegister claim.originalAddress originalBehavior &&
    candidateBehavior.registers.get claim.output.candidate ==
      FrameExactWordRegisterOutputClaim.expectedExpression
        claim.candidateInputAssembledRead
        claim.candidateAssembledRead
        claim.sourceLocation.candidateRegister claim.candidateAddress candidateBehavior &&
    (!claim.originalAssembledRead ||
      registerOffsetWitnessesAvoidWord claim.sourceLocation.originalRegister
        claim.originalAddress.offset claim.originalWriteWitnesses
        originalBehavior.writes) &&
    (!claim.candidateAssembledRead ||
      registerOffsetWitnessesAvoidWord claim.sourceLocation.candidateRegister
        claim.candidateAddress.offset claim.candidateWriteWitnesses
        candidateBehavior.writes)

theorem FrameExactWordRegisterOutputClaim.holds_output_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FrameExactWordRegisterOutputClaim)
    (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.checked inventory originalBehavior candidateBehavior = true)
    (locationsHold : inventory.holds frame originalState.registers
      candidateState.registers)
    (exactWordsHold : inventory.exactWordsHold frame originalState.memory
      candidateState.memory) :
    claim.output.relation.holds context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  simp only [FrameExactWordRegisterOutputClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨_inventoryChecked, locationMember⟩, wordMember⟩,
      relationExact⟩, originalOffset⟩, candidateOffset⟩,
      _originalProfilesExclusive⟩, _candidateProfilesExclusive⟩,
      originalExpression⟩, candidateExpression⟩,
      originalAvoidsChecked⟩, candidateAvoidsChecked⟩
  have locationHolds := locationsHold.2 claim.sourceLocation
    (List.contains_iff_mem.mp locationMember)
  have wordHolds := exactWordsHold claim.word
    (List.contains_iff_mem.mp wordMember)
  have originalAddressEval :
      (claim.originalAddress.expression claim.sourceLocation.originalRegister).eval
          originalState =
        frame.originalStackAddress + BitVec.ofNat 32 claim.word.originalOffset := by
    rw [claim.originalAddress.eval_expression, originalOffset]
    simpa [BitVec.add_assoc] using congrArg
      (fun address => address + BitVec.ofNat 32 claim.word.originalOffset)
      locationHolds.1
  have candidateAddressEval :
      (claim.candidateAddress.expression claim.sourceLocation.candidateRegister).eval
          candidateState =
        frame.candidateStackAddress + BitVec.ofNat 32 claim.word.candidateOffset := by
    rw [claim.candidateAddress.eval_expression, candidateOffset]
    simpa [BitVec.add_assoc] using congrArg
      (fun address => address + BitVec.ofNat 32 claim.word.candidateOffset)
      locationHolds.2
  have originalAddressValue :
      originalState.registers.get claim.sourceLocation.originalRegister +
          claim.originalAddress.offset =
        frame.originalStackAddress + BitVec.ofNat 32 claim.word.originalOffset := by
    rw [← claim.originalAddress.eval_expression]
    exact originalAddressEval
  have candidateAddressValue :
      candidateState.registers.get claim.sourceLocation.candidateRegister +
          claim.candidateAddress.offset =
        frame.candidateStackAddress + BitVec.ofNat 32 claim.word.candidateOffset := by
    rw [← claim.candidateAddress.eval_expression]
    exact candidateAddressEval
  have originalRead :
      (FrameExactWordRegisterOutputClaim.expectedExpression
        claim.originalInputAssembledRead
        claim.originalAssembledRead
        claim.sourceLocation.originalRegister claim.originalAddress
        originalBehavior).eval originalState =
      Memory.read32 originalState.memory
        (frame.originalStackAddress + BitVec.ofNat 32 claim.word.originalOffset) := by
    cases inputAssembled : claim.originalInputAssembledRead with
    | true =>
        simp [FrameExactWordRegisterOutputClaim.expectedExpression,
          inputAssembled, originalAddressEval]
    | false =>
        cases assembled : claim.originalAssembledRead with
        | false =>
            simp [FrameExactWordRegisterOutputClaim.expectedExpression,
              inputAssembled, assembled, Expr.eval,
              machineStateRead32_eq_memoryRead32, originalAddressEval]
        | true =>
            have avoidsChecked : registerOffsetWitnessesAvoidWord
                claim.sourceLocation.originalRegister claim.originalAddress.offset
                claim.originalWriteWitnesses originalBehavior.writes = true := by
              simpa [assembled] using originalAvoidsChecked
            have avoids := registerOffsetWitnessesAvoidWord_of_closed
              claim.sourceLocation.originalRegister claim.originalAddress.offset
              claim.originalWriteWitnesses originalBehavior.writes originalState
              (registerOffsetWitnessesAvoidWordClosed_of_checked _ _ _ _ avoidsChecked)
            simp [FrameExactWordRegisterOutputClaim.expectedExpression,
              inputAssembled, assembled, Expr.eval_read32AfterWrites]
            rw [claim.originalAddress.eval_expression]
            rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids]
            rw [originalAddressValue]
  have candidateRead :
      (FrameExactWordRegisterOutputClaim.expectedExpression
        claim.candidateInputAssembledRead
        claim.candidateAssembledRead
        claim.sourceLocation.candidateRegister claim.candidateAddress
        candidateBehavior).eval candidateState =
      Memory.read32 candidateState.memory
        (frame.candidateStackAddress + BitVec.ofNat 32 claim.word.candidateOffset) := by
    cases inputAssembled : claim.candidateInputAssembledRead with
    | true =>
        simp [FrameExactWordRegisterOutputClaim.expectedExpression,
          inputAssembled, candidateAddressEval]
    | false =>
        cases assembled : claim.candidateAssembledRead with
        | false =>
            simp [FrameExactWordRegisterOutputClaim.expectedExpression,
              inputAssembled, assembled, Expr.eval,
              machineStateRead32_eq_memoryRead32, candidateAddressEval]
        | true =>
            have avoidsChecked : registerOffsetWitnessesAvoidWord
                claim.sourceLocation.candidateRegister claim.candidateAddress.offset
                claim.candidateWriteWitnesses candidateBehavior.writes = true := by
              simpa [assembled] using candidateAvoidsChecked
            have avoids := registerOffsetWitnessesAvoidWord_of_closed
              claim.sourceLocation.candidateRegister claim.candidateAddress.offset
              claim.candidateWriteWitnesses candidateBehavior.writes candidateState
              (registerOffsetWitnessesAvoidWordClosed_of_checked _ _ _ _ avoidsChecked)
            simp [FrameExactWordRegisterOutputClaim.expectedExpression,
              inputAssembled, assembled, Expr.eval_read32AfterWrites]
            rw [claim.candidateAddress.eval_expression]
            rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids]
            rw [candidateAddressValue]
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [relationExact, originalExpression, candidateExpression,
    originalRead, candidateRead]
  simpa [RegisterValueRelation.holds] using wordHolds

theorem frameExactWordRegisterOutputsHold_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List FrameExactWordRegisterOutputClaim)
    (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claims.all fun claim =>
      claim.checked inventory originalBehavior candidateBehavior)
    (locationsHold : inventory.holds frame originalState.registers
      candidateState.registers)
    (exactWordsHold : inventory.exactWordsHold frame originalState.memory
      candidateState.memory) :
    registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world)
      (claims.map FrameExactWordRegisterOutputClaim.output)
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [registerRelationsHold, List.all_eq_true, List.mem_map]
  intro output outputMember
  rcases outputMember with ⟨claim, claimMember, rfl⟩
  have claimChecked := List.all_eq_true.mp checked claim claimMember
  exact claim.holds_output_of_checked context world inventory originalBehavior
    candidateBehavior frame originalState candidateState claimChecked locationsHold
    exactWordsHold

def ReturnSlotOffsetInventory.seedsPreservedRelationsFromFrameWords
    (context : StaticProofContext) (source target : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (carried : List RegisterRelationPair)
    (claims : List FrameExactWordRegisterOutputClaim) : Bool :=
  source.preservedRelationsChecked context &&
    carried.all source.preservedRelations.contains &&
    carried.all (fun relation =>
      originalBehavior.registers.get relation.original == .inputReg relation.original &&
        candidateBehavior.registers.get relation.candidate == .inputReg relation.candidate) &&
    target.preservedRelationsChecked context &&
    target.preservedRelations == carried ++
      claims.map FrameExactWordRegisterOutputClaim.output &&
    claims.all fun claim =>
      claim.checked source originalBehavior candidateBehavior

theorem ReturnSlotOffsetInventory.preservedRelationsHold_after_frame_words
    (context : StaticProofContext) (world : RelationalWorld)
    (source target : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (carried : List RegisterRelationPair)
    (claims : List FrameExactWordRegisterOutputClaim)
    (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : source.seedsPreservedRelationsFromFrameWords context target
      originalBehavior candidateBehavior carried claims = true)
    (sourceFacts : source.preservedRelationsHold context world
      originalState.registers candidateState.registers = true)
    (locationsHold : source.holds frame originalState.registers
      candidateState.registers)
    (exactWordsHold : source.exactWordsHold frame originalState.memory
      candidateState.memory) :
    target.preservedRelationsHold context world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [ReturnSlotOffsetInventory.seedsPreservedRelationsFromFrameWords,
    Bool.and_eq_true, beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨_sourceChecked, carriedSubset⟩, carriedPreserved⟩,
      _targetChecked⟩, targetRelations⟩, claimsChecked⟩
  have carriedFacts : registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) carried originalState.registers
      candidateState.registers = true := by
    unfold ReturnSlotOffsetInventory.preservedRelationsHold at sourceFacts
    simp only [registerRelationsHold, List.all_eq_true] at sourceFacts ⊢
    intro relation relationMember
    have sourceMember := List.all_eq_true.mp carriedSubset relation relationMember
    exact sourceFacts relation (List.contains_iff_mem.mp sourceMember)
  have carriedNext : registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) carried
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
    simp only [registerRelationsHold, List.all_eq_true] at carriedFacts
    simp only [List.all_eq_true] at carriedPreserved
    simp only [registerRelationsHold, List.all_eq_true]
    intro relation relationMember
    have relationHolds := carriedFacts relation relationMember
    have relationPreserved := carriedPreserved relation relationMember
    simp only [Bool.and_eq_true, beq_iff_eq] at relationPreserved
    rcases relationPreserved with ⟨originalRegister, candidateRegister⟩
    simpa [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, originalRegister, candidateRegister, Expr.eval]
      using relationHolds
  have seeded := frameExactWordRegisterOutputsHold_of_checked context world source
    originalBehavior candidateBehavior claims frame originalState candidateState
    claimsChecked locationsHold exactWordsHold
  unfold ReturnSlotOffsetInventory.preservedRelationsHold at seeded ⊢
  rw [targetRelations]
  exact registerRelationsHold_append_of_holds
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    carried
    (claims.map FrameExactWordRegisterOutputClaim.output)
    (originalBehavior.eval originalState).registers
    (candidateBehavior.eval candidateState).registers carriedNext seeded

/-- The pure subset of an exact-expression witness that can be justified by
the register facts attached to an active runtime frame. Memory, flags, x87,
FS, undefined values, and static-image reads are deliberately rejected: those
inputs belong to `StateRel`, not to a frame-local register inventory. -/
def PairedExactExprWitness.registerFactsChecked
    (inventory : ReturnSlotOffsetInventory) : PairedExactExprWitness -> Bool
  | .inputReg original candidate =>
      exactRegisterPair inventory.preservedRelations original candidate
  | .constant _ => true
  | .binary _ left right =>
      left.registerFactsChecked inventory && right.registerFactsChecked inventory
  | .unary _ value | .indexed _ _ value => value.registerFactsChecked inventory
  | .ifEqual left right thenValue elseValue =>
      left.registerFactsChecked inventory && right.registerFactsChecked inventory &&
        thenValue.registerFactsChecked inventory &&
        elseValue.registerFactsChecked inventory
  | .ternary _ high low divisor =>
      high.registerFactsChecked inventory && low.registerFactsChecked inventory &&
        divisor.registerFactsChecked inventory
  | _ => false

theorem PairedExactExprWitness.eval_equal_of_registerFactsChecked
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory)
    (original candidate : MachineState) (witness : PairedExactExprWitness)
    (checked : witness.registerFactsChecked inventory = true)
    (factsHold : inventory.preservedRelationsHold context world
      original.registers candidate.registers = true) :
    (witness.expression .original).eval original =
      (witness.expression .candidate).eval candidate := by
  induction witness with
  | inputReg originalRegister candidateRegister =>
      exact registerRelationsHold_exact_pair
        context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        inventory.preservedRelations original.registers candidate.registers
        originalRegister candidateRegister factsHold checked
  | inputFlagValue bit => simp [PairedExactExprWitness.registerFactsChecked] at checked
  | inputFsBase => simp [PairedExactExprWitness.registerFactsChecked] at checked
  | inputX87Control => simp [PairedExactExprWitness.registerFactsChecked] at checked
  | inputX87Status => simp [PairedExactExprWitness.registerFactsChecked] at checked
  | read8 originalAddress candidateAddress =>
      simp [PairedExactExprWitness.registerFactsChecked] at checked
  | read32 originalAddress candidateAddress =>
      simp [PairedExactExprWitness.registerFactsChecked] at checked
  | statePredicateRead32 predicate read =>
      simp [PairedExactExprWitness.registerFactsChecked] at checked
  | read8At address => simp [PairedExactExprWitness.registerFactsChecked] at checked
  | read32At address => simp [PairedExactExprWitness.registerFactsChecked] at checked
  | stackSeparatedRead32 originalAddress candidateAddress writes =>
      simp [PairedExactExprWitness.registerFactsChecked] at checked
  | undefined slot => simp [PairedExactExprWitness.registerFactsChecked] at checked
  | binary operation left right leftSound rightSound =>
      simp only [PairedExactExprWitness.registerFactsChecked,
        Bool.and_eq_true] at checked
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
      simp only [PairedExactExprWitness.registerFactsChecked,
        Bool.and_eq_true] at checked
      rcases checked with
        ⟨⟨⟨leftChecked, rightChecked⟩, thenChecked⟩, elseChecked⟩
      have leftEqual := leftSound leftChecked
      have rightEqual := rightSound rightChecked
      have thenEqual := thenSound thenChecked
      have elseEqual := elseSound elseChecked
      simp [PairedExactExprWitness.expression, Expr.eval, leftEqual, rightEqual,
        thenEqual, elseEqual]
  | ternary operation high low divisor highSound lowSound divisorSound =>
      simp only [PairedExactExprWitness.registerFactsChecked,
        Bool.and_eq_true] at checked
      rcases checked with ⟨⟨highChecked, lowChecked⟩, divisorChecked⟩
      have highEqual := highSound highChecked
      have lowEqual := lowSound lowChecked
      have divisorEqual := divisorSound divisorChecked
      cases operation <;> simp_all [PairedExactExprWitness.expression,
        PairedExactTernaryOp.expression, Expr.eval]
  | constant value => rfl

/-- A frame-local register output justified by a paired pure expression over
the active frame's exact register facts.  This covers affine stack/register
updates without treating a solver result or Python proposal as proof. -/
structure FramePairedExpressionRegisterOutputClaim where
  output : RegisterRelationPair
  witness : PairedExactExprWitness
deriving Repr, DecidableEq

def FramePairedExpressionRegisterOutputClaim.checked
    (inventory : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FramePairedExpressionRegisterOutputClaim) : Bool :=
  InvariantWP.registerValueRelationAcceptsEqual claim.output.relation &&
    originalBehavior.registers.get claim.output.original ==
      claim.witness.expression .original &&
    candidateBehavior.registers.get claim.output.candidate ==
      claim.witness.expression .candidate &&
    claim.witness.registerFactsChecked inventory

theorem FramePairedExpressionRegisterOutputClaim.holds_output_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FramePairedExpressionRegisterOutputClaim)
    (originalState candidateState : MachineState)
    (checked : claim.checked inventory originalBehavior candidateBehavior = true)
    (factsHold : inventory.preservedRelationsHold context world
      originalState.registers candidateState.registers = true) :
    claim.output.relation.holds context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  simp only [FramePairedExpressionRegisterOutputClaim.checked,
    Bool.and_eq_true, beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨relationAcceptsEqual, originalExpression⟩, candidateExpression⟩,
      witnessChecked⟩
  have valuesEqual := claim.witness.eval_equal_of_registerFactsChecked
    context world inventory originalState candidateState witnessChecked factsHold
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [originalExpression, candidateExpression]
  exact InvariantWP.RegisterValueRelation.holds_of_eq
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    claim.output.relation _ _ relationAcceptsEqual valuesEqual

theorem framePairedExpressionRegisterOutputsHold_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List FramePairedExpressionRegisterOutputClaim)
    (originalState candidateState : MachineState)
    (checked : claims.all fun claim =>
      claim.checked inventory originalBehavior candidateBehavior)
    (factsHold : inventory.preservedRelationsHold context world
      originalState.registers candidateState.registers = true) :
    registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world)
      (claims.map FramePairedExpressionRegisterOutputClaim.output)
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [registerRelationsHold, List.all_eq_true, List.mem_map]
  intro output outputMember
  rcases outputMember with ⟨claim, claimMember, rfl⟩
  have claimChecked := List.all_eq_true.mp checked claim claimMember
  exact claim.holds_output_of_checked context world inventory originalBehavior
    candidateBehavior originalState candidateState claimChecked factsHold

def ReturnSlotOffsetInventory.seedsPreservedRelationsFromFrameEvidence
    (context : StaticProofContext) (source target : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (carried : List RegisterRelationPair)
    (wordClaims : List FrameExactWordRegisterOutputClaim)
    (expressionClaims : List FramePairedExpressionRegisterOutputClaim) : Bool :=
  source.preservedRelationsChecked context &&
    carried.all source.preservedRelations.contains &&
    carried.all (fun relation =>
      originalBehavior.registers.get relation.original == .inputReg relation.original &&
        candidateBehavior.registers.get relation.candidate == .inputReg relation.candidate) &&
    target.preservedRelationsChecked context &&
    target.preservedRelations == carried ++
      wordClaims.map FrameExactWordRegisterOutputClaim.output ++
      expressionClaims.map FramePairedExpressionRegisterOutputClaim.output &&
    (wordClaims.all fun claim =>
      claim.checked source originalBehavior candidateBehavior) &&
    expressionClaims.all fun claim =>
      claim.checked source originalBehavior candidateBehavior

theorem ReturnSlotOffsetInventory.preservedRelationsHold_after_frame_evidence
    (context : StaticProofContext) (world : RelationalWorld)
    (source target : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (carried : List RegisterRelationPair)
    (wordClaims : List FrameExactWordRegisterOutputClaim)
    (expressionClaims : List FramePairedExpressionRegisterOutputClaim)
    (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : source.seedsPreservedRelationsFromFrameEvidence context target
      originalBehavior candidateBehavior carried wordClaims expressionClaims = true)
    (sourceFacts : source.preservedRelationsHold context world
      originalState.registers candidateState.registers = true)
    (locationsHold : source.holds frame originalState.registers
      candidateState.registers)
    (exactWordsHold : source.exactWordsHold frame originalState.memory
      candidateState.memory) :
    target.preservedRelationsHold context world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [ReturnSlotOffsetInventory.seedsPreservedRelationsFromFrameEvidence,
    Bool.and_eq_true, beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨_sourceChecked, carriedSubset⟩, carriedPreserved⟩,
      _targetChecked⟩, targetRelations⟩, wordClaimsChecked⟩,
      expressionClaimsChecked⟩
  have carriedFacts : registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) carried originalState.registers
      candidateState.registers = true := by
    unfold ReturnSlotOffsetInventory.preservedRelationsHold at sourceFacts
    simp only [registerRelationsHold, List.all_eq_true] at sourceFacts ⊢
    intro relation relationMember
    have sourceMember := List.all_eq_true.mp carriedSubset relation relationMember
    exact sourceFacts relation (List.contains_iff_mem.mp sourceMember)
  have carriedNext : registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) carried
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
    simp only [registerRelationsHold, List.all_eq_true] at carriedFacts
    simp only [List.all_eq_true] at carriedPreserved
    simp only [registerRelationsHold, List.all_eq_true]
    intro relation relationMember
    have relationHolds := carriedFacts relation relationMember
    have relationPreserved := carriedPreserved relation relationMember
    simp only [Bool.and_eq_true, beq_iff_eq] at relationPreserved
    rcases relationPreserved with ⟨originalRegister, candidateRegister⟩
    simpa [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, originalRegister, candidateRegister, Expr.eval]
      using relationHolds
  have wordFacts := frameExactWordRegisterOutputsHold_of_checked context world source
    originalBehavior candidateBehavior wordClaims frame originalState candidateState
    wordClaimsChecked locationsHold exactWordsHold
  have expressionFacts := framePairedExpressionRegisterOutputsHold_of_checked
    context world source originalBehavior candidateBehavior expressionClaims
    originalState candidateState expressionClaimsChecked sourceFacts
  unfold ReturnSlotOffsetInventory.preservedRelationsHold at wordFacts expressionFacts ⊢
  rw [targetRelations]
  have carriedAndWords := registerRelationsHold_append_of_holds
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    carried (wordClaims.map FrameExactWordRegisterOutputClaim.output)
    (originalBehavior.eval originalState).registers
    (candidateBehavior.eval candidateState).registers carriedNext wordFacts
  exact registerRelationsHold_append_of_holds
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    (carried ++ wordClaims.map FrameExactWordRegisterOutputClaim.output)
    (expressionClaims.map FramePairedExpressionRegisterOutputClaim.output)
    (originalBehavior.eval originalState).registers
    (candidateBehavior.eval candidateState).registers carriedAndWords expressionFacts

structure FrameExactGuardClaim where
  originalGuard : BoolExpr
  candidateGuard : BoolExpr
  witness : PairedExactExprWitness
deriving Repr, DecidableEq

def FrameExactGuardClaim.checked (inventory : ReturnSlotOffsetInventory)
    (originalGuard candidateGuard : BoolExpr)
    (claim : FrameExactGuardClaim) : Bool :=
  claim.originalGuard == originalGuard && claim.candidateGuard == candidateGuard &&
    claim.witness.expression .original == claim.originalGuard.toWord &&
    claim.witness.expression .candidate == claim.candidateGuard.toWord &&
    claim.witness.registerFactsChecked inventory

theorem FrameExactGuardClaim.eval_equal_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory)
    (originalGuard candidateGuard : BoolExpr) (claim : FrameExactGuardClaim)
    (checked : claim.checked inventory originalGuard candidateGuard = true)
    (original candidate : MachineState)
    (factsHold : inventory.preservedRelationsHold context world
      original.registers candidate.registers = true) :
    originalGuard.eval original = candidateGuard.eval candidate := by
  simp only [FrameExactGuardClaim.checked, Bool.and_eq_true, beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨originalExact, candidateExact⟩, originalWitness⟩,
      candidateWitness⟩, witnessChecked⟩
  have wordsEqual := claim.witness.eval_equal_of_registerFactsChecked
    context world inventory original candidate witnessChecked factsHold
  rw [originalWitness, candidateWitness, BoolExpr.eval_toWord,
    BoolExpr.eval_toWord] at wordsEqual
  rw [← originalExact, ← candidateExact]
  cases originalResult : claim.originalGuard.eval original <;>
    cases candidateResult : claim.candidateGuard.eval candidate <;> simp_all

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

inductive ReturnSlotStackDirection where
  | above
  | below
deriving Repr, DecidableEq

structure ReturnSlotStackLocationClaim where
  window : StackWindowPair
  direction : ReturnSlotStackDirection
  amount : Nat
deriving Repr, DecidableEq

def ReturnSlotStackLocationClaim.checked (sourceInvariant : StateInvariant)
    (offsets : ReturnSlotOffsetPair) (claim : ReturnSlotStackLocationClaim) : Bool :=
  sourceInvariant.stackWindows.contains claim.window &&
    offsets.originalRegister == claim.window.originalRegister &&
    offsets.candidateRegister == claim.window.candidateRegister &&
    claim.amount % 4 == 0 &&
    match claim.direction with
    | .above =>
        offsets.originalOffset == BitVec.ofNat 32 claim.amount &&
          offsets.candidateOffset == BitVec.ofNat 32 claim.amount &&
          claim.amount + 4 <= claim.window.bytesAbove
    | .below =>
        offsets.originalOffset ==
            (0 : Word) - BitVec.ofNat 32 claim.amount &&
          offsets.candidateOffset ==
            (0 : Word) - BitVec.ofNat 32 claim.amount &&
          4 <= claim.amount && claim.amount <= claim.window.bytesBelow

def ReturnSlotStackLocationClaim.Closed (sourceInvariant : StateInvariant)
    (offsets : ReturnSlotOffsetPair) (claim : ReturnSlotStackLocationClaim) : Prop :=
  (((claim.window ∈ sourceInvariant.stackWindows ∧
    offsets.originalRegister = claim.window.originalRegister) ∧
    offsets.candidateRegister = claim.window.candidateRegister) ∧
    claim.amount % 4 = 0) ∧
    match claim.direction with
    | .above =>
        (offsets.originalOffset = BitVec.ofNat 32 claim.amount ∧
          offsets.candidateOffset = BitVec.ofNat 32 claim.amount) ∧
          claim.amount + 4 <= claim.window.bytesAbove
    | .below =>
        ((offsets.originalOffset =
            (0 : Word) - BitVec.ofNat 32 claim.amount ∧
          offsets.candidateOffset =
            (0 : Word) - BitVec.ofNat 32 claim.amount) ∧
          4 <= claim.amount) ∧ claim.amount <= claim.window.bytesBelow

theorem ReturnSlotStackLocationClaim.closed_of_checked
    (sourceInvariant : StateInvariant) (offsets : ReturnSlotOffsetPair)
    (claim : ReturnSlotStackLocationClaim)
    (checked : claim.checked sourceInvariant offsets = true) :
    claim.Closed sourceInvariant offsets := by
  unfold ReturnSlotStackLocationClaim.checked at checked
  unfold ReturnSlotStackLocationClaim.Closed
  simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq,
    List.contains_iff_mem] at checked ⊢
  cases direction : claim.direction <;> simp [direction] at checked ⊢ <;>
    exact checked

theorem ReturnSlotStackLocationClaim.location_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (offsets : ReturnSlotOffsetPair)
    (claim : ReturnSlotStackLocationClaim) (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.checked sourceInvariant offsets = true)
    (offsetsHold : offsets.holds frame originalState.registers
      candidateState.registers)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    ∃ location : PairedStackWordLocation world,
      location.originalAddress = frame.originalStackAddress ∧
        location.candidateAddress = frame.candidateStackAddress := by
  have closed := claim.closed_of_checked sourceInvariant offsets checked
  rcases closed with ⟨⟨⟨⟨windowMember, originalRegister⟩,
    candidateRegister⟩, amountAligned⟩, direction⟩
  rcases related with
    ⟨_worldValid, rangesValid, _stackMemory, _importsStatic, _importsComplete,
      _importsMemory, _originalImmutable, _candidateImmutable, relatedCore,
      _importAndDynamicRegisters⟩
  rcases relatedCore with
    ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,
      _inputMemory, _inputDynamicMemory, _inputUndefined, _inputX87,
      _inputFlags, _inputFsBase⟩
  simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
  have windowHolds := inputStackWindows claim.window windowMember
  rcases offsetsHold with ⟨originalOffsetHolds, candidateOffsetHolds⟩
  cases directionCase : claim.direction with
  | above =>
      simp [directionCase] at direction
      rcases direction with
        ⟨⟨originalOffset, candidateOffset⟩, enoughAbove⟩
      rcases pairedStackWordLocation_above_window context world claim.window
          originalState.registers candidateState.registers rangesValid windowHolds
          claim.amount amountAligned enoughAbove with
        ⟨location, originalLocation, candidateLocation⟩
      refine ⟨location, ?_, ?_⟩
      · rw [originalLocation, ← originalRegister, ← originalOffset]
        exact originalOffsetHolds
      · rw [candidateLocation, ← candidateRegister, ← candidateOffset]
        exact candidateOffsetHolds
  | below =>
      simp [directionCase] at direction
      rcases direction with
        ⟨⟨⟨originalOffset, candidateOffset⟩, amountAtLeastWord⟩,
          enoughBelow⟩
      rcases pairedStackWordLocation_below_window_amount context world claim.window
          originalState.registers candidateState.registers rangesValid windowHolds
          claim.amount amountAtLeastWord amountAligned enoughBelow with
        ⟨location, originalLocation, candidateLocation⟩
      refine ⟨location, ?_, ?_⟩
      · rw [originalLocation, ← originalRegister]
        calc
          originalState.registers.get offsets.originalRegister -
              BitVec.ofNat 32 claim.amount =
            originalState.registers.get offsets.originalRegister +
              offsets.originalOffset := by
                rw [originalOffset]
                simp [BitVec.sub_eq_add_neg]
          _ = frame.originalStackAddress := originalOffsetHolds
      · rw [candidateLocation, ← candidateRegister]
        calc
          candidateState.registers.get offsets.candidateRegister -
              BitVec.ofNat 32 claim.amount =
            candidateState.registers.get offsets.candidateRegister +
              offsets.candidateOffset := by
                rw [candidateOffset]
                simp [BitVec.sub_eq_add_neg]
          _ = frame.candidateStackAddress := candidateOffsetHolds

inductive PairedReturnSlotWriteWitness where
  | affine (original candidate : RegisterOffsetWitness)
  | staticWord (slotId : Nat)
deriving Repr, DecidableEq

def pairedReturnSlotWriteWitnessesChecked (context : StaticProofContext)
    (offsets : ReturnSlotOffsetPair) :
    List PairedReturnSlotWriteWitness -> List (Expr × Expr) ->
      List (Expr × Expr) -> Bool
  | [], [], [] => true
  | .affine originalWitness candidateWitness :: witnesses,
      originalWrite :: originalWrites, candidateWrite :: candidateWrites =>
      originalWitness.expression offsets.originalRegister == originalWrite.1 &&
        wordOffsetsDisjoint offsets.originalOffset originalWitness.offset &&
        candidateWitness.expression offsets.candidateRegister == candidateWrite.1 &&
        wordOffsetsDisjoint offsets.candidateOffset candidateWitness.offset &&
        pairedReturnSlotWriteWitnessesChecked context offsets witnesses
          originalWrites candidateWrites
  | .staticWord slotId :: witnesses,
      originalWrite :: originalWrites, candidateWrite :: candidateWrites =>
      match context.staticWordRelationSlotById slotId with
      | none => false
      | some slot =>
          slot.valid context &&
            originalWrite.1 == .constant slot.originalAddress.toNat &&
            candidateWrite.1 == .constant slot.candidateAddress.toNat &&
            pairedReturnSlotWriteWitnessesChecked context offsets witnesses
              originalWrites candidateWrites
  | _, _, _ => false

def PairedReturnSlotWriteWitnessesClosed (context : StaticProofContext)
    (offsets : ReturnSlotOffsetPair) :
    List PairedReturnSlotWriteWitness -> List (Expr × Expr) ->
      List (Expr × Expr) -> Prop
  | [], [], [] => True
  | .affine originalWitness candidateWitness :: witnesses,
      originalWrite :: originalWrites, candidateWrite :: candidateWrites =>
      originalWitness.expression offsets.originalRegister = originalWrite.1 ∧
        wordOffsetsDisjoint offsets.originalOffset originalWitness.offset = true ∧
        candidateWitness.expression offsets.candidateRegister = candidateWrite.1 ∧
        wordOffsetsDisjoint offsets.candidateOffset candidateWitness.offset = true ∧
        PairedReturnSlotWriteWitnessesClosed context offsets witnesses
          originalWrites candidateWrites
  | .staticWord slotId :: witnesses,
      originalWrite :: originalWrites, candidateWrite :: candidateWrites =>
      match context.staticWordRelationSlotById slotId with
      | none => False
      | some slot =>
          slot.valid context = true ∧
            originalWrite.1 = .constant slot.originalAddress.toNat ∧
            candidateWrite.1 = .constant slot.candidateAddress.toNat ∧
            PairedReturnSlotWriteWitnessesClosed context offsets witnesses
              originalWrites candidateWrites
  | _, _, _ => False

theorem pairedReturnSlotWriteWitnessesClosed_of_checked
    (context : StaticProofContext) (offsets : ReturnSlotOffsetPair)
    (witnesses : List PairedReturnSlotWriteWitness)
    (originalWrites candidateWrites : List (Expr × Expr))
    (checked : pairedReturnSlotWriteWitnessesChecked context offsets witnesses
      originalWrites candidateWrites = true) :
    PairedReturnSlotWriteWitnessesClosed context offsets witnesses
      originalWrites candidateWrites := by
  induction witnesses generalizing originalWrites candidateWrites with
  | nil =>
      cases originalWrites <;> cases candidateWrites <;>
        simp_all [pairedReturnSlotWriteWitnessesChecked,
          PairedReturnSlotWriteWitnessesClosed]
  | cons witness witnesses ih =>
      cases originalWrites with
      | nil => simp [pairedReturnSlotWriteWitnessesChecked] at checked
      | cons originalWrite originalWrites =>
          cases candidateWrites with
          | nil => simp [pairedReturnSlotWriteWitnessesChecked] at checked
          | cons candidateWrite candidateWrites =>
              cases witness with
              | affine originalWitness candidateWitness =>
                  simp only [pairedReturnSlotWriteWitnessesChecked,
                    Bool.and_eq_true, beq_iff_eq] at checked
                  simp only [PairedReturnSlotWriteWitnessesClosed]
                  exact ⟨checked.1.1.1.1, checked.1.1.1.2,
                    checked.1.1.2, checked.1.2,
                    ih originalWrites candidateWrites checked.2⟩
              | staticWord slotId =>
                  cases slotResult : context.staticWordRelationSlotById slotId with
                  | none =>
                      simp [pairedReturnSlotWriteWitnessesChecked, slotResult] at checked
                  | some slot =>
                      simp only [pairedReturnSlotWriteWitnessesChecked, slotResult,
                        Bool.and_eq_true, beq_iff_eq] at checked
                      simp only [PairedReturnSlotWriteWitnessesClosed, slotResult]
                      exact ⟨checked.1.1.1, checked.1.1.2, checked.1.2,
                        ih originalWrites candidateWrites checked.2⟩

theorem registerOffsetWitnessAvoidsWord
    (register : Reg) (wordOffset : Word) (witness : RegisterOffsetWitness)
    (write : Expr × Expr) (state : MachineState)
    (expression : witness.expression register = write.1)
    (disjoint : wordOffsetsDisjoint wordOffset witness.offset = true) :
    Write32AvoidsWord (state.registers.get register + wordOffset)
      (write.1.eval state) := by
  have closed : RegisterOffsetWitnessesAvoidWordClosed register wordOffset
      [witness] [write] := by
    simp [RegisterOffsetWitnessesAvoidWordClosed, expression, disjoint]
  have avoids := registerOffsetWitnessesAvoidWord_of_closed register wordOffset
    [witness] [write] state closed
  exact avoids (write.1.eval state, write.2.eval state) (by
    simp [evalNormalizedWrites])

theorem DirectCallPreparedExactWordSeedClaim.holds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : DirectCallPreparedWritesClaim)
    (seed : DirectCallPreparedExactWordSeedClaim)
    (originalState candidateState : MachineState)
    (claimChecked : claim.checked context sourceInvariant originalNormalized
      candidateNormalized = true)
    (seedChecked : seed.checked claim = true)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    seed.exactWord.holds (claim.runtimeFrame originalState candidateState)
      ((originalNormalized.eval originalState).nextMachineState originalState).memory
      ((candidateNormalized.eval candidateState).nextMachineState candidateState).memory := by
  simp only [DirectCallPreparedExactWordSeedClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at seedChecked
  rcases seedChecked with ⟨writesExact, seedChecked⟩
  simp only [DirectCallPreparedWritesClaim.checked, Bool.and_eq_true]
    at claimChecked
  have frameChecked := claimChecked.1.2
  simp only [DirectCallPreparedWritesClaim.frameChecked, Bool.and_eq_true,
    decide_eq_true_eq, beq_iff_eq] at frameChecked
  rcases frameChecked with
    ⟨⟨⟨⟨⟨⟨⟨_returnWindowMember, _stackAtLeast⟩, _stackAligned⟩,
      stackFits⟩, _enoughBelow⟩, _calleePresent⟩, _continuationPair⟩,
      _zeroAgreement⟩
  cases selectedShape : seed.selected with
  | stack window amount value =>
      rw [selectedShape] at seedChecked writesExact
      simp only [Bool.and_eq_true, beq_iff_eq] at seedChecked
      rcases seedChecked with
        ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨windowExact, valueExact⟩, originalExpression⟩,
          candidateExpression⟩, originalAfterChecked⟩, candidateAfterChecked⟩,
          originalPushDisjoint⟩, candidatePushDisjoint⟩,
          originalFrameOffset⟩, candidateFrameOffset⟩, _exactWordChecked⟩
      subst window
      have preparedChecked := claimChecked.1.1
      simp only [PairedPreparedWordWritesClaim.checked, Bool.and_eq_true]
        at preparedChecked
      have itemsChecked := preparedChecked.2
      simp only [List.all_eq_true] at itemsChecked
      have selectedMember :
          PairedPreparedWordWriteItem.stack claim.returnWindow amount value ∈
            claim.preparedWrites.writes := by
        rw [writesExact]
        simp
      have selectedChecked := itemsChecked _ selectedMember
      simp only [PairedPreparedWordWriteItem.checked, Bool.and_eq_true]
        at selectedChecked
      have returnWindowMember := selectedChecked.1
      cases adjustmentResult : pairedStackWordAdjustment? amount with
      | none => simp [adjustmentResult] at selectedChecked
      | some adjustment =>
          simp only [adjustmentResult, Bool.and_eq_true] at selectedChecked
          have adjustmentChecked := selectedChecked.2.1
          have valueChecked := selectedChecked.2.2
          have sourceWindows := StateRel.stackWindowsHold context world sourceInvariant
            originalState candidateState related
          simp only [stackWindowsRelated, List.all_eq_true] at sourceWindows
          have windowHolds := sourceWindows claim.returnWindow
            (List.contains_iff_mem.mp returnWindowMember)
          have rangesValid := StateRel.stackRangesValid context world sourceInvariant
            originalState candidateState related
          rcases pairedStackWordLocation_at_adjustment context world claim.returnWindow
              originalState candidateState rangesValid windowHolds adjustment
              adjustmentChecked with
            ⟨location, originalLocation, candidateLocation⟩
          have locationFits := location.addressesFit context world rangesValid
          have selectedValuesEqual := value.eval_equal_of_checked_exact
            context world sourceInvariant valueChecked valueExact originalState
            candidateState related
          have originalAfterClosed := registerOffsetWitnessesAvoidWordClosed_of_checked
            claim.returnWindow.originalRegister seed.originalSelectedAddress.offset
            seed.originalAfterAddresses
            (seed.after.map fun item =>
              (item.originalAddress, item.value.original)) originalAfterChecked
          have candidateAfterClosed := registerOffsetWitnessesAvoidWordClosed_of_checked
            claim.returnWindow.candidateRegister seed.candidateSelectedAddress.offset
            seed.candidateAfterAddresses
            (seed.after.map fun item =>
              (item.candidateAddress, item.value.candidate)) candidateAfterChecked
          have originalAfterAvoids := registerOffsetWitnessesAvoidWord_of_closed
            claim.returnWindow.originalRegister seed.originalSelectedAddress.offset
            seed.originalAfterAddresses
            (seed.after.map fun item =>
              (item.originalAddress, item.value.original)) originalState
            originalAfterClosed
          have candidateAfterAvoids := registerOffsetWitnessesAvoidWord_of_closed
            claim.returnWindow.candidateRegister seed.candidateSelectedAddress.offset
            seed.candidateAfterAddresses
            (seed.after.map fun item =>
              (item.candidateAddress, item.value.candidate)) candidateState
            candidateAfterClosed
          let originalPushWitness : RegisterOffsetWitness :=
            .addRight .input (2 ^ 32 - claim.stackAmount)
          let candidatePushWitness : RegisterOffsetWitness :=
            .addRight .input (2 ^ 32 - claim.stackAmount)
          have originalPushAvoids := registerOffsetWitnessAvoidsWord
            claim.returnWindow.originalRegister seed.originalSelectedAddress.offset
            originalPushWitness
            (claim.originalPushAddress, .constant claim.originalReturnAddress)
            originalState (by simp [originalPushWitness,
              RegisterOffsetWitness.expression,
              DirectCallPreparedWritesClaim.originalPushAddress])
            (by simpa [originalPushWitness, RegisterOffsetWitness.offset]
              using originalPushDisjoint)
          have candidatePushAvoids := registerOffsetWitnessAvoidsWord
            claim.returnWindow.candidateRegister seed.candidateSelectedAddress.offset
            candidatePushWitness
            (claim.candidatePushAddress, .constant claim.candidateReturnAddress)
            candidateState (by simp [candidatePushWitness,
              RegisterOffsetWitness.expression,
              DirectCallPreparedWritesClaim.candidatePushAddress])
            (by simpa [candidatePushWitness, RegisterOffsetWitness.offset]
              using candidatePushDisjoint)
          have originalLaterAvoids : WritesAvoidWord
              (seed.selected.originalAddress.eval originalState)
              ((seed.after.map fun item =>
                (item.originalAddress.eval originalState,
                  item.value.original.eval originalState)) ++
                [(claim.originalPushAddress.eval originalState,
                  BitVec.ofNat 32 claim.originalReturnAddress)]) := by
            rw [selectedShape, ← originalExpression,
              seed.originalSelectedAddress.eval_expression]
            intro write member
            simp only [List.mem_append, List.mem_singleton] at member
            rcases member with member | rfl
            · exact originalAfterAvoids write (by
                simpa [evalNormalizedWrites, Function.comp_apply] using member)
            · exact originalPushAvoids
          have candidateLaterAvoids : WritesAvoidWord
              (seed.selected.candidateAddress.eval candidateState)
              ((seed.after.map fun item =>
                (item.candidateAddress.eval candidateState,
                  item.value.candidate.eval candidateState)) ++
                [(claim.candidatePushAddress.eval candidateState,
                  BitVec.ofNat 32 claim.candidateReturnAddress)]) := by
            rw [selectedShape, ← candidateExpression,
              seed.candidateSelectedAddress.eval_expression]
            intro write member
            simp only [List.mem_append, List.mem_singleton] at member
            rcases member with member | rfl
            · exact candidateAfterAvoids write (by
                simpa [evalNormalizedWrites, Function.comp_apply] using member)
            · exact candidatePushAvoids
          have originalBehaviorWrites :
              (originalNormalized.eval originalState).writes =
                claim.originalWrites originalState := by
            have behaviorChecked := claimChecked.2
            simp only [DirectCallPreparedWritesClaim.behaviorChecked,
              Bool.and_eq_true, beq_iff_eq] at behaviorChecked
            rcases behaviorChecked with
              ⟨⟨⟨⟨⟨_originalOutcome, _candidateOutcome⟩, _originalEsp⟩,
                _candidateEsp⟩, originalSymbolicWrites⟩,
                _candidateSymbolicWrites⟩
            simp [NormalizedSymbolicBehavior.eval, evalNormalizedWrites,
              DirectCallPreparedWritesClaim.originalWrites,
              DirectCallPreparedWritesClaim.originalSymbolicWrites,
              PairedPreparedWordWritesClaim.originalWrites,
              PairedPreparedWordWritesClaim.originalSymbolicWrites,
              Expr.eval, originalSymbolicWrites]
          have candidateBehaviorWrites :
              (candidateNormalized.eval candidateState).writes =
                claim.candidateWrites candidateState := by
            have behaviorChecked := claimChecked.2
            simp only [DirectCallPreparedWritesClaim.behaviorChecked,
              Bool.and_eq_true, beq_iff_eq] at behaviorChecked
            rcases behaviorChecked with
              ⟨⟨⟨⟨⟨_originalOutcome, _candidateOutcome⟩, _originalEsp⟩,
                _candidateEsp⟩, _originalSymbolicWrites⟩,
                candidateSymbolicWrites⟩
            simp [NormalizedSymbolicBehavior.eval, evalNormalizedWrites,
              DirectCallPreparedWritesClaim.candidateWrites,
              DirectCallPreparedWritesClaim.candidateSymbolicWrites,
              PairedPreparedWordWritesClaim.candidateWrites,
              PairedPreparedWordWritesClaim.candidateSymbolicWrites,
              Expr.eval, candidateSymbolicWrites]
          let originalBeforeWrites := seed.before.map fun item =>
            (item.originalAddress.eval originalState,
              item.value.original.eval originalState)
          let candidateBeforeWrites := seed.before.map fun item =>
            (item.candidateAddress.eval candidateState,
              item.value.candidate.eval candidateState)
          let originalAfterWrites := seed.after.map fun item =>
            (item.originalAddress.eval originalState,
              item.value.original.eval originalState)
          let candidateAfterWrites := seed.after.map fun item =>
            (item.candidateAddress.eval candidateState,
              item.value.candidate.eval candidateState)
          let originalPush := (claim.originalPushAddress.eval originalState,
            BitVec.ofNat 32 claim.originalReturnAddress)
          let candidatePush := (claim.candidatePushAddress.eval candidateState,
            BitVec.ofNat 32 claim.candidateReturnAddress)
          have originalWritesShape : claim.originalWrites originalState =
              originalBeforeWrites ++
                (seed.selected.originalAddress.eval originalState,
                  seed.selected.value.original.eval originalState) ::
                (originalAfterWrites ++ [originalPush]) := by
            simp [DirectCallPreparedWritesClaim.originalWrites,
              PairedPreparedWordWritesClaim.originalWrites, writesExact,
              selectedShape, originalBeforeWrites, originalAfterWrites,
              originalPush, evalNormalizedWrites, Function.comp_apply]
          have candidateWritesShape : claim.candidateWrites candidateState =
              candidateBeforeWrites ++
                (seed.selected.candidateAddress.eval candidateState,
                  seed.selected.value.candidate.eval candidateState) ::
                (candidateAfterWrites ++ [candidatePush]) := by
            simp [DirectCallPreparedWritesClaim.candidateWrites,
              PairedPreparedWordWritesClaim.candidateWrites, writesExact,
              selectedShape, candidateBeforeWrites, candidateAfterWrites,
              candidatePush, evalNormalizedWrites, Function.comp_apply]
          have originalSelectedLocation : location.originalAddress =
              seed.selected.originalAddress.eval originalState := by
            rw [selectedShape]
            exact originalLocation.trans
              (StackAdjustment.eval_expression_of_matches adjustment
                claim.returnWindow.originalRegister
                (pairedPreparedStackWordAddress
                  claim.returnWindow.originalRegister amount) originalState
                (pairedPreparedStackWordAddress_matches_adjustment
                  claim.returnWindow.originalRegister amount adjustment
                  adjustmentResult)).symm
          have candidateSelectedLocation : location.candidateAddress =
              seed.selected.candidateAddress.eval candidateState := by
            rw [selectedShape]
            exact candidateLocation.trans
              (StackAdjustment.eval_expression_of_matches adjustment
                claim.returnWindow.candidateRegister
                (pairedPreparedStackWordAddress
                  claim.returnWindow.candidateRegister amount) candidateState
                (pairedPreparedStackWordAddress_matches_adjustment
                  claim.returnWindow.candidateRegister amount adjustment
                  adjustmentResult)).symm
          have originalSelectedFits :
              (seed.selected.originalAddress.eval originalState).toNat + 4 <=
                2 ^ 32 := by
            rw [← originalSelectedLocation]
            exact locationFits.1
          have candidateSelectedFits :
              (seed.selected.candidateAddress.eval candidateState).toNat + 4 <=
                2 ^ 32 := by
            rw [← candidateSelectedLocation]
            exact locationFits.2
          have originalRead :
              Memory.read32
                ((originalNormalized.eval originalState).nextMachineState
                  originalState).memory
                (seed.selected.originalAddress.eval originalState) =
              seed.selected.value.original.eval originalState := by
            rw [show
              ((originalNormalized.eval originalState).nextMachineState
                originalState).memory = applyConcreteWrites originalState.memory
                  (originalNormalized.eval originalState).writes by
                    simp [RelationalBehavior.nextMachineState]]
            rw [originalBehaviorWrites]
            rw [originalWritesShape]
            exact Memory.read32_applyConcreteWrites_selected originalState.memory
              originalBeforeWrites (originalAfterWrites ++ [originalPush]) _ _
              originalSelectedFits originalLaterAvoids
          have candidateRead :
              Memory.read32
                ((candidateNormalized.eval candidateState).nextMachineState
                  candidateState).memory
                (seed.selected.candidateAddress.eval candidateState) =
              seed.selected.value.candidate.eval candidateState := by
            rw [show
              ((candidateNormalized.eval candidateState).nextMachineState
                candidateState).memory = applyConcreteWrites candidateState.memory
                  (candidateNormalized.eval candidateState).writes by
                    simp [RelationalBehavior.nextMachineState]]
            rw [candidateBehaviorWrites]
            rw [candidateWritesShape]
            exact Memory.read32_applyConcreteWrites_selected candidateState.memory
              candidateBeforeWrites (candidateAfterWrites ++ [candidatePush]) _ _
              candidateSelectedFits candidateLaterAvoids
          have originalFrameAddress :
              (claim.runtimeFrame originalState candidateState).originalStackAddress +
                  BitVec.ofNat 32 seed.exactWord.originalOffset =
                seed.selected.originalAddress.eval originalState := by
            rw [selectedShape, ← originalExpression,
              seed.originalSelectedAddress.eval_expression, originalFrameOffset]
            simp only [DirectCallPreparedWritesClaim.runtimeFrame]
            rw [← BitVec.add_assoc,
              ← word_add_ia32_twos_complement
                (originalState.registers.get claim.returnWindow.originalRegister)
                claim.stackAmount stackFits]
          have candidateFrameAddress :
              (claim.runtimeFrame originalState candidateState).candidateStackAddress +
                  BitVec.ofNat 32 seed.exactWord.candidateOffset =
                seed.selected.candidateAddress.eval candidateState := by
            rw [selectedShape, ← candidateExpression,
              seed.candidateSelectedAddress.eval_expression, candidateFrameOffset]
            simp only [DirectCallPreparedWritesClaim.runtimeFrame]
            rw [← BitVec.add_assoc,
              ← word_add_ia32_twos_complement
                (candidateState.registers.get claim.returnWindow.candidateRegister)
                claim.stackAmount stackFits]
          simp only [ReturnSlotExactWordPair.holds, originalFrameAddress,
            candidateFrameAddress, originalRead, candidateRead]
          simpa [selectedShape] using selectedValuesEqual
  | staticWord slotId originalAddress candidateAddress value =>
      simp [DirectCallPreparedExactWordSeedClaim.checked, selectedShape] at seedChecked
  | dynamicWord source relation originalAmount candidateAmount value =>
      simp [DirectCallPreparedExactWordSeedClaim.checked, selectedShape] at seedChecked
  | staticDynamicPointer slotId originalAddress candidateAddress source value =>
      simp [DirectCallPreparedExactWordSeedClaim.checked, selectedShape] at seedChecked

theorem pairedStackWordLocation_avoids_static_slot
    (context : StaticProofContext) (world : RelationalWorld)
    (location : PairedStackWordLocation world)
    (slot : StaticWordRelationSlotPair)
    (rangeValid : location.range.disjointFromImages context = true)
    (slotValid : slot.valid context = true) :
    Write32AvoidsWord location.originalAddress slot.originalAddress ∧
      Write32AvoidsWord location.candidateAddress slot.candidateAddress := by
  have originalBounds := slot.originalBounds context slotValid
  have candidateBounds := slot.candidateBounds context slotValid
  have rangeShape := rangeValid
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeShape
  rcases rangeShape with
    ⟨⟨⟨⟨_rangeNonempty, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  constructor
  · rw [location.originalAddressExact]
    exact (stackRangeWordWriteAvoidsImageWord location.range.originalBase
      location.range.size context.originalPe.imageBase context.originalPe.sizeOfImage
      location.offset location.inside originalNoWrap originalDisjoint
      slot.originalAddress originalBounds.1 originalBounds.2.1
      originalBounds.2.2).symm
  · rw [location.candidateAddressExact]
    exact (stackRangeWordWriteAvoidsImageWord location.range.candidateBase
      location.range.size context.candidatePe.imageBase context.candidatePe.sizeOfImage
      location.offset location.inside candidateNoWrap candidateDisjoint
      slot.candidateAddress candidateBounds.1 candidateBounds.2.1
      candidateBounds.2.2).symm

theorem relationalRuntimeCallFrameOffset_avoids_static_slot
    (context : StaticProofContext) (frame : RelationalRuntimeCallFrame)
    (originalOffset candidateOffset : Nat)
    (slot : StaticWordRelationSlotPair)
    (spanValid : frame.protectedSpanValid context = true)
    (originalInside : originalOffset + 4 <= frame.protectedBytes)
    (candidateInside : candidateOffset + 4 <= frame.protectedBytes)
    (slotValid : slot.valid context = true) :
    Write32AvoidsWord
        (frame.originalStackAddress + BitVec.ofNat 32 originalOffset)
        slot.originalAddress ∧
      Write32AvoidsWord
        (frame.candidateStackAddress + BitVec.ofNat 32 candidateOffset)
        slot.candidateAddress := by
  have originalBounds := slot.originalBounds context slotValid
  have candidateBounds := slot.candidateBounds context slotValid
  have rangeShape := spanValid
  simp only [RelationalRuntimeCallFrame.protectedSpanValid,
    Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeShape
  rcases rangeShape with
    ⟨⟨⟨⟨_minimumSpan, originalNoWrap⟩, candidateNoWrap⟩,
      originalDisjoint⟩, candidateDisjoint⟩
  constructor
  · exact (stackRangeWordWriteAvoidsImageWord frame.originalStackAddress
      frame.protectedBytes context.originalPe.imageBase
      context.originalPe.sizeOfImage originalOffset originalInside originalNoWrap
      originalDisjoint slot.originalAddress originalBounds.1 originalBounds.2.1
      originalBounds.2.2).symm
  · exact (stackRangeWordWriteAvoidsImageWord frame.candidateStackAddress
      frame.protectedBytes context.candidatePe.imageBase
      context.candidatePe.sizeOfImage candidateOffset candidateInside candidateNoWrap
      candidateDisjoint slot.candidateAddress candidateBounds.1 candidateBounds.2.1
      candidateBounds.2.2).symm

theorem pairedReturnSlotWriteWitnessesAvoidWord_of_protectedFrame
    (context : StaticProofContext) (frame : RelationalRuntimeCallFrame)
    (offsets : ReturnSlotOffsetPair)
    (originalFrameOffset candidateFrameOffset : Nat)
    (witnesses : List PairedReturnSlotWriteWitness)
    (originalWrites candidateWrites : List (Expr × Expr))
    (originalState candidateState : MachineState)
    (spanValid : frame.protectedSpanValid context = true)
    (originalInside : originalFrameOffset + 4 <= frame.protectedBytes)
    (candidateInside : candidateFrameOffset + 4 <= frame.protectedBytes)
    (originalLocation :
      frame.originalStackAddress + BitVec.ofNat 32 originalFrameOffset =
        originalState.registers.get offsets.originalRegister + offsets.originalOffset)
    (candidateLocation :
      frame.candidateStackAddress + BitVec.ofNat 32 candidateFrameOffset =
        candidateState.registers.get offsets.candidateRegister + offsets.candidateOffset)
    (closed : PairedReturnSlotWriteWitnessesClosed context offsets witnesses
      originalWrites candidateWrites) :
    WritesAvoidWord
        (frame.originalStackAddress + BitVec.ofNat 32 originalFrameOffset)
        (evalNormalizedWrites originalState originalWrites) ∧
      WritesAvoidWord
        (frame.candidateStackAddress + BitVec.ofNat 32 candidateFrameOffset)
        (evalNormalizedWrites candidateState candidateWrites) := by
  induction witnesses generalizing originalWrites candidateWrites with
  | nil =>
      cases originalWrites <;> cases candidateWrites <;>
        simp_all [PairedReturnSlotWriteWitnessesClosed, evalNormalizedWrites,
          WritesAvoidWord]
  | cons witness witnesses ih =>
      cases originalWrites with
      | nil => simp [PairedReturnSlotWriteWitnessesClosed] at closed
      | cons originalWrite originalWrites =>
          cases candidateWrites with
          | nil => simp [PairedReturnSlotWriteWitnessesClosed] at closed
          | cons candidateWrite candidateWrites =>
              cases witness with
              | affine originalWitness candidateWitness =>
                  simp only [PairedReturnSlotWriteWitnessesClosed] at closed
                  rcases closed with
                    ⟨originalExpression, originalDisjoint, candidateExpression,
                      candidateDisjoint, tailClosed⟩
                  have originalHead := registerOffsetWitnessAvoidsWord
                    offsets.originalRegister offsets.originalOffset originalWitness
                    originalWrite originalState originalExpression originalDisjoint
                  have candidateHead := registerOffsetWitnessAvoidsWord
                    offsets.candidateRegister offsets.candidateOffset candidateWitness
                    candidateWrite candidateState candidateExpression candidateDisjoint
                  have tail := ih originalWrites candidateWrites tailClosed
                  constructor
                  · intro write writeMember
                    simp only [evalNormalizedWrites, List.map_cons,
                      List.mem_cons] at writeMember
                    rcases writeMember with rfl | member
                    · simpa [originalLocation] using originalHead
                    · exact tail.1 write member
                  · intro write writeMember
                    simp only [evalNormalizedWrites, List.map_cons,
                      List.mem_cons] at writeMember
                    rcases writeMember with rfl | member
                    · simpa [candidateLocation] using candidateHead
                    · exact tail.2 write member
              | staticWord slotId =>
                  cases slotResult : context.staticWordRelationSlotById slotId with
                  | none =>
                      simp [PairedReturnSlotWriteWitnessesClosed, slotResult] at closed
                  | some slot =>
                      simp only [PairedReturnSlotWriteWitnessesClosed,
                        slotResult] at closed
                      rcases closed with
                        ⟨slotValid, originalExpression, candidateExpression,
                          tailClosed⟩
                      have head := relationalRuntimeCallFrameOffset_avoids_static_slot
                        context frame originalFrameOffset candidateFrameOffset slot
                        spanValid originalInside candidateInside slotValid
                      have originalAddress : originalWrite.1.eval originalState =
                          slot.originalAddress := by
                        rw [originalExpression]
                        simp [Expr.eval]
                      have candidateAddress : candidateWrite.1.eval candidateState =
                          slot.candidateAddress := by
                        rw [candidateExpression]
                        simp [Expr.eval]
                      have tail := ih originalWrites candidateWrites tailClosed
                      constructor
                      · intro write writeMember
                        simp only [evalNormalizedWrites, List.map_cons,
                          List.mem_cons] at writeMember
                        rcases writeMember with rfl | member
                        · simpa [originalAddress] using head.1
                        · exact tail.1 write member
                      · intro write writeMember
                        simp only [evalNormalizedWrites, List.map_cons,
                          List.mem_cons] at writeMember
                        rcases writeMember with rfl | member
                        · simpa [candidateAddress] using head.2
                        · exact tail.2 write member

theorem pairedReturnSlotWriteWitnessesAvoidWord_of_closed
    (context : StaticProofContext) (world : RelationalWorld)
    (offsets : ReturnSlotOffsetPair)
    (witnesses : List PairedReturnSlotWriteWitness)
    (originalWrites candidateWrites : List (Expr × Expr))
    (location : PairedStackWordLocation world)
    (originalState candidateState : MachineState)
    (rangesValid : world.stackRangesValid context = true)
    (originalLocation : location.originalAddress =
      originalState.registers.get offsets.originalRegister + offsets.originalOffset)
    (candidateLocation : location.candidateAddress =
      candidateState.registers.get offsets.candidateRegister + offsets.candidateOffset)
    (closed : PairedReturnSlotWriteWitnessesClosed context offsets witnesses
      originalWrites candidateWrites) :
    WritesAvoidWord location.originalAddress
        (evalNormalizedWrites originalState originalWrites) ∧
      WritesAvoidWord location.candidateAddress
        (evalNormalizedWrites candidateState candidateWrites) := by
  induction witnesses generalizing originalWrites candidateWrites with
  | nil =>
      cases originalWrites <;> cases candidateWrites <;>
        simp_all [PairedReturnSlotWriteWitnessesClosed, evalNormalizedWrites,
          WritesAvoidWord]
  | cons witness witnesses ih =>
      cases originalWrites with
      | nil => simp [PairedReturnSlotWriteWitnessesClosed] at closed
      | cons originalWrite originalWrites =>
          cases candidateWrites with
          | nil => simp [PairedReturnSlotWriteWitnessesClosed] at closed
          | cons candidateWrite candidateWrites =>
              have rangeValid : location.range.disjointFromImages context = true := by
                simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
                  List.all_eq_true] at rangesValid
                exact (rangesValid.1.1.2 location.range location.rangeMember).1.1.1
              cases witness with
              | affine originalWitness candidateWitness =>
                  simp only [PairedReturnSlotWriteWitnessesClosed] at closed
                  rcases closed with
                    ⟨originalExpression, originalDisjoint, candidateExpression,
                      candidateDisjoint, tailClosed⟩
                  have originalHead := registerOffsetWitnessAvoidsWord
                    offsets.originalRegister offsets.originalOffset originalWitness
                    originalWrite originalState originalExpression originalDisjoint
                  have candidateHead := registerOffsetWitnessAvoidsWord
                    offsets.candidateRegister offsets.candidateOffset candidateWitness
                    candidateWrite candidateState candidateExpression candidateDisjoint
                  have tail := ih originalWrites candidateWrites tailClosed
                  constructor
                  · intro write writeMember
                    simp only [evalNormalizedWrites, List.map_cons,
                      List.mem_cons] at writeMember
                    rcases writeMember with rfl | member
                    · simpa [originalLocation] using originalHead
                    · exact tail.1 write member
                  · intro write writeMember
                    simp only [evalNormalizedWrites, List.map_cons,
                      List.mem_cons] at writeMember
                    rcases writeMember with rfl | member
                    · simpa [candidateLocation] using candidateHead
                    · exact tail.2 write member
              | staticWord slotId =>
                  cases slotResult : context.staticWordRelationSlotById slotId with
                  | none =>
                      simp [PairedReturnSlotWriteWitnessesClosed, slotResult] at closed
                  | some slot =>
                      simp only [PairedReturnSlotWriteWitnessesClosed, slotResult] at closed
                      rcases closed with
                        ⟨slotValid, originalExpression, candidateExpression,
                          tailClosed⟩
                      have head := pairedStackWordLocation_avoids_static_slot
                        context world location slot rangeValid slotValid
                      have originalAddress : originalWrite.1.eval originalState =
                          slot.originalAddress := by
                        rw [originalExpression]
                        simp [Expr.eval]
                      have candidateAddress : candidateWrite.1.eval candidateState =
                          slot.candidateAddress := by
                        rw [candidateExpression]
                        simp [Expr.eval]
                      have tail := ih originalWrites candidateWrites tailClosed
                      constructor
                      · intro write writeMember
                        simp only [evalNormalizedWrites, List.map_cons,
                          List.mem_cons] at writeMember
                        rcases writeMember with rfl | member
                        · simpa [originalAddress] using head.1
                        · exact tail.1 write member
                      · intro write writeMember
                        simp only [evalNormalizedWrites, List.map_cons,
                          List.mem_cons] at writeMember
                        rcases writeMember with rfl | member
                        · simpa [candidateAddress] using head.2
                        · exact tail.2 write member

structure ReturnSlotFramedMemoryTransferClaim where
  offsets : ReturnSlotOffsetPair
  location : ReturnSlotStackLocationClaim
  writes : List PairedReturnSlotWriteWitness
deriving Repr, DecidableEq

def ReturnSlotFramedMemoryTransferClaim.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotFramedMemoryTransferClaim) : Bool :=
  claim.location.checked sourceInvariant claim.offsets &&
    pairedReturnSlotWriteWitnessesChecked context claim.offsets claim.writes
      originalBehavior.writes candidateBehavior.writes

theorem returnSlotFramedMemoryTransferHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotFramedMemoryTransferClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (offsetsHold : claim.offsets.holds frame originalState.registers
      candidateState.registers)
    (memoryHolds : frame.memoryHolds originalState.memory candidateState.memory)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    frame.memoryHolds
      (applyConcreteWrites originalState.memory
        (evalNormalizedWrites originalState originalBehavior.writes))
      (applyConcreteWrites candidateState.memory
        (evalNormalizedWrites candidateState candidateBehavior.writes)) := by
  simp only [ReturnSlotFramedMemoryTransferClaim.checked,
    Bool.and_eq_true] at checked
  rcases claim.location.location_of_checked context world sourceInvariant
      claim.offsets frame originalState candidateState checked.1 offsetsHold related with
    ⟨location, originalLocation, candidateLocation⟩
  have closed := pairedReturnSlotWriteWitnessesClosed_of_checked context
    claim.offsets claim.writes originalBehavior.writes candidateBehavior.writes
    checked.2
  have rangesValid := related.2.1
  have avoids := pairedReturnSlotWriteWitnessesAvoidWord_of_closed context world
    claim.offsets claim.writes originalBehavior.writes candidateBehavior.writes
    location originalState candidateState rangesValid
    (by simpa [originalLocation] using offsetsHold.1.symm)
    (by simpa [candidateLocation] using offsetsHold.2.symm) closed
  rcases memoryHolds with ⟨originalMemory, candidateMemory⟩
  constructor
  · rw [← originalLocation]
    rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids.1]
    rw [originalLocation]
    exact originalMemory
  · rw [← candidateLocation]
    rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids.2]
    rw [candidateLocation]
    exact candidateMemory

structure ReturnSlotProtectedMemoryTransferClaim where
  offsets : ReturnSlotOffsetPair
  writes : List PairedReturnSlotWriteWitness
deriving Repr, DecidableEq

def ReturnSlotProtectedMemoryTransferClaim.checked
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotProtectedMemoryTransferClaim) : Bool :=
  pairedReturnSlotWriteWitnessesChecked context claim.offsets claim.writes
    originalBehavior.writes candidateBehavior.writes

theorem returnSlotProtectedMemoryTransferHolds_of_checked
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotProtectedMemoryTransferClaim)
    (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.checked context originalBehavior candidateBehavior = true)
    (offsetsHold : claim.offsets.holds frame originalState.registers
      candidateState.registers)
    (memoryHolds : frame.memoryHolds originalState.memory candidateState.memory)
    (spanValid : frame.protectedSpanValid context = true) :
    frame.memoryHolds
      (applyConcreteWrites originalState.memory
        (evalNormalizedWrites originalState originalBehavior.writes))
      (applyConcreteWrites candidateState.memory
        (evalNormalizedWrites candidateState candidateBehavior.writes)) := by
  have minimumSpan : 4 <= frame.protectedBytes := by
    have shape := spanValid
    simp only [RelationalRuntimeCallFrame.protectedSpanValid,
      Bool.and_eq_true, decide_eq_true_eq] at shape
    exact shape.1.1.1.1
  have closed := pairedReturnSlotWriteWitnessesClosed_of_checked context
    claim.offsets claim.writes originalBehavior.writes candidateBehavior.writes checked
  have avoids := pairedReturnSlotWriteWitnessesAvoidWord_of_protectedFrame
    context frame claim.offsets 0 0 claim.writes originalBehavior.writes
    candidateBehavior.writes originalState candidateState spanValid minimumSpan
    minimumSpan (by simpa using offsetsHold.1.symm)
    (by simpa using offsetsHold.2.symm) closed
  rcases memoryHolds with ⟨originalMemory, candidateMemory⟩
  constructor
  · have originalAvoids : WritesAvoidWord frame.originalStackAddress
        (evalNormalizedWrites originalState originalBehavior.writes) := by
      simpa using avoids.1
    rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ originalAvoids]
    exact originalMemory
  · have candidateAvoids : WritesAvoidWord frame.candidateStackAddress
        (evalNormalizedWrites candidateState candidateBehavior.writes) := by
      simpa using avoids.2
    rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ candidateAvoids]
    exact candidateMemory

inductive InternalReturnSlotMemoryTransferClaim where
  | affine (claim : ReturnSlotMemoryTransferClaim)
  | framed (claim : ReturnSlotFramedMemoryTransferClaim)
  | protectedSpan (claim : ReturnSlotProtectedMemoryTransferClaim)
deriving Repr, DecidableEq

def InternalReturnSlotMemoryTransferClaim.requirement
    (context : StaticProofContext) (frame : RelationalRuntimeCallFrame) :
    InternalReturnSlotMemoryTransferClaim -> Prop
  | .affine _ | .framed _ => True
  | .protectedSpan _ => frame.protectedSpanValid context = true

structure ReturnSlotFrameTransferClaim where
  transfer : ReturnSlotTransferClaim
  memory : InternalReturnSlotMemoryTransferClaim
deriving Repr, DecidableEq

def ReturnSlotFrameTransferClaim.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotFrameTransferClaim) : Bool :=
  claim.transfer.checked originalBehavior candidateBehavior &&
    match claim.memory with
    | .affine memory =>
        memory.offsets == claim.transfer.source &&
          memory.checked originalBehavior candidateBehavior
    | .framed memory =>
        memory.offsets == claim.transfer.source &&
          memory.checked context sourceInvariant originalBehavior candidateBehavior
    | .protectedSpan memory =>
        memory.offsets == claim.transfer.source &&
          memory.checked context originalBehavior candidateBehavior

theorem returnSlotFrameTransferHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotFrameTransferClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (sourceOffsets : claim.transfer.source.holds frame originalState.registers
      candidateState.registers)
    (sourceMemory : frame.memoryHolds originalState.memory candidateState.memory)
    (memoryRequirement : claim.memory.requirement context frame)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.transfer.target.holds frame
        (originalBehavior.eval originalState).registers
        (candidateBehavior.eval candidateState).registers ∧
      frame.memoryHolds
        ((originalBehavior.eval originalState).nextMachineState originalState).memory
        ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory := by
  simp only [ReturnSlotFrameTransferClaim.checked, Bool.and_eq_true] at checked
  rcases checked with ⟨transferChecked, memoryChecked⟩
  have offsets := returnSlotTransferHolds_of_checked originalBehavior
    candidateBehavior claim.transfer frame originalState candidateState
    transferChecked sourceOffsets
  have memory : frame.memoryHolds
      (applyConcreteWrites originalState.memory
        (evalNormalizedWrites originalState originalBehavior.writes))
      (applyConcreteWrites candidateState.memory
        (evalNormalizedWrites candidateState candidateBehavior.writes)) := by
    cases memoryCase : claim.memory with
    | affine memory =>
        simp only [memoryCase, Bool.and_eq_true, beq_iff_eq] at memoryChecked
        exact returnSlotMemoryTransferHolds_of_checked originalBehavior
          candidateBehavior memory frame originalState candidateState memoryChecked.2
          (by simpa [memoryChecked.1] using sourceOffsets) sourceMemory
    | framed memory =>
        simp only [memoryCase, Bool.and_eq_true, beq_iff_eq] at memoryChecked
        exact returnSlotFramedMemoryTransferHolds_of_checked context world
          sourceInvariant originalBehavior candidateBehavior memory frame originalState
          candidateState memoryChecked.2
          (by simpa [memoryChecked.1] using sourceOffsets) sourceMemory related
    | protectedSpan memory =>
        simp only [memoryCase, Bool.and_eq_true, beq_iff_eq] at memoryChecked
        exact returnSlotProtectedMemoryTransferHolds_of_checked context
          originalBehavior candidateBehavior memory frame originalState
          candidateState memoryChecked.2
          (by simpa [memoryChecked.1] using sourceOffsets) sourceMemory
          (by simpa [InternalReturnSlotMemoryTransferClaim.requirement,
            memoryCase] using memoryRequirement)
  exact ⟨offsets, by
    simpa [RelationalBehavior.nextMachineState] using memory⟩

/-- A checked preservation certificate for one exact scalar word carried by a
runtime frame.  It reuses the ordinary return-slot transfer checker on a
temporary frame shifted to the scalar word, so register movement and every
concrete write are justified by the same reviewed machinery. -/
structure ReturnSlotExactWordTransferClaim where
  word : ReturnSlotExactWordPair
  sourceBase : ReturnSlotOffsetPair
  targetBase : ReturnSlotOffsetPair
  transfer : ReturnSlotFrameTransferClaim
deriving Repr, DecidableEq

def ReturnSlotExactWordTransferClaim.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (source target : ReturnSlotOffsetInventory)
    (targetBases : List ReturnSlotOffsetPair)
    (claim : ReturnSlotExactWordTransferClaim) : Bool :=
  source.exactWords.contains claim.word &&
    target.exactWords.contains claim.word &&
    source.locations.contains claim.sourceBase &&
    targetBases.contains claim.targetBase &&
    claim.transfer.transfer.source == claim.sourceBase.shiftExactWord claim.word &&
    claim.transfer.transfer.target == claim.targetBase.shiftExactWord claim.word &&
    claim.transfer.checked context sourceInvariant originalBehavior candidateBehavior

theorem returnSlotExactWordTransferHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (source target : ReturnSlotOffsetInventory)
    (targetBases : List ReturnSlotOffsetPair)
    (claim : ReturnSlotExactWordTransferClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior source target targetBases = true)
    (sourceOffsets : source.holds frame originalState.registers
      candidateState.registers)
    (sourceExactWords : source.exactWordsHold frame originalState.memory
      candidateState.memory)
    (sourceProtected : frame.protectedSpanValid context = true)
    (sourceWordsFit : source.exactWordsFit frame = true)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.word.holds frame
      ((originalBehavior.eval originalState).nextMachineState originalState).memory
      ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory := by
  simp only [ReturnSlotExactWordTransferClaim.checked, Bool.and_eq_true,
    beq_iff_eq, List.contains_iff_mem] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨wordSource, wordTarget⟩, sourceBaseMember⟩,
      _targetBaseMember⟩, sourceShift⟩, targetShift⟩, transferChecked⟩
  have sourceBaseHolds := source.holds_member frame originalState.registers
    candidateState.registers claim.sourceBase sourceOffsets sourceBaseMember
  let value := Memory.read32 originalState.memory
    (frame.originalStackAddress + BitVec.ofNat 32 claim.word.originalOffset)
  let shiftedFrame := claim.word.shiftedFrame frame value
  have shiftedOffsets : claim.transfer.transfer.source.holds shiftedFrame
      originalState.registers candidateState.registers := by
    rw [sourceShift]
    exact claim.sourceBase.shiftExactWord_holds claim.word frame value
      originalState.registers candidateState.registers sourceBaseHolds
  have wordHolds := source.exactWordsHold_member frame originalState.memory
    candidateState.memory claim.word sourceExactWords wordSource
  have shiftedMemory : shiftedFrame.memoryHolds originalState.memory
      candidateState.memory := by
    exact claim.word.shiftedFrame_memoryHolds frame originalState.memory
      candidateState.memory wordHolds
  cases memoryCase : claim.transfer.memory with
  | affine memory =>
      have transferred := returnSlotFrameTransferHolds_of_checked context world
        sourceInvariant originalBehavior candidateBehavior claim.transfer shiftedFrame
        originalState candidateState transferChecked shiftedOffsets shiftedMemory
        (by simp [InternalReturnSlotMemoryTransferClaim.requirement, memoryCase]) related
      exact claim.word.holds_of_shiftedFrame_memoryHolds frame value
        ((originalBehavior.eval originalState).nextMachineState originalState).memory
        ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory
        transferred.2
  | framed memory =>
      have transferred := returnSlotFrameTransferHolds_of_checked context world
        sourceInvariant originalBehavior candidateBehavior claim.transfer shiftedFrame
        originalState candidateState transferChecked shiftedOffsets shiftedMemory
        (by simp [InternalReturnSlotMemoryTransferClaim.requirement, memoryCase]) related
      exact claim.word.holds_of_shiftedFrame_memoryHolds frame value
        ((originalBehavior.eval originalState).nextMachineState originalState).memory
        ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory
        transferred.2
  | protectedSpan memory =>
      have transferShape := transferChecked
      simp only [ReturnSlotFrameTransferClaim.checked, memoryCase,
        Bool.and_eq_true, beq_iff_eq] at transferShape
      have memoryOffsets := transferShape.2.1
      have memoryChecked := transferShape.2.2
      have closed := pairedReturnSlotWriteWitnessesClosed_of_checked context
        memory.offsets memory.writes originalBehavior.writes candidateBehavior.writes
        memoryChecked
      have wordFits : claim.word.originalOffset + 4 <= frame.protectedBytes ∧
          claim.word.candidateOffset + 4 <= frame.protectedBytes := by
        simp only [ReturnSlotOffsetInventory.exactWordsFit, List.all_eq_true,
          Bool.and_eq_true, decide_eq_true_eq] at sourceWordsFit
        exact sourceWordsFit claim.word wordSource
      have avoids := pairedReturnSlotWriteWitnessesAvoidWord_of_protectedFrame
        context frame memory.offsets claim.word.originalOffset
        claim.word.candidateOffset memory.writes originalBehavior.writes
        candidateBehavior.writes originalState candidateState sourceProtected
        wordFits.1 wordFits.2
        (by simpa [memoryOffsets, shiftedFrame,
          ReturnSlotExactWordPair.shiftedFrame] using shiftedOffsets.1.symm)
        (by simpa [memoryOffsets, shiftedFrame,
          ReturnSlotExactWordPair.shiftedFrame] using shiftedOffsets.2.symm)
        closed
      have memory : claim.word.holds frame
          (applyConcreteWrites originalState.memory
            (evalNormalizedWrites originalState originalBehavior.writes))
          (applyConcreteWrites candidateState.memory
            (evalNormalizedWrites candidateState candidateBehavior.writes)) := by
        unfold ReturnSlotExactWordPair.holds at wordHolds ⊢
        rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids.1,
          Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids.2]
        exact wordHolds
      simpa [RelationalBehavior.nextMachineState] using memory

/-- One edge may retain several checked names for a runtime return slot.  Every
retained target name must be justified by a concrete frame-transfer claim, and
each claim must start from a name already present in the source inventory. -/
structure ReturnSlotFrameInventoryTransferClaim where
  source : ReturnSlotOffsetInventory
  target : ReturnSlotOffsetInventory
  transfers : List ReturnSlotFrameTransferClaim
  exactWordTransfers : List ReturnSlotExactWordTransferClaim := []
deriving Repr, DecidableEq

def ReturnSlotFrameInventoryTransferClaim.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotFrameInventoryTransferClaim) : Bool :=
  claim.source.checked && claim.target.checked &&
    claim.transfers.all (fun transfer =>
      claim.source.locations.contains transfer.transfer.source) &&
    claim.transfers.map (fun transfer => transfer.transfer.target) ==
      claim.target.locations &&
    claim.transfers.all (fun transfer =>
      transfer.checked context sourceInvariant originalBehavior candidateBehavior) &&
    claim.exactWordTransfers.map (fun transfer => transfer.word) ==
      claim.target.exactWords &&
    claim.exactWordTransfers.all (fun transfer =>
      transfer.checked context sourceInvariant originalBehavior candidateBehavior
        claim.source claim.target claim.target.locations)

theorem returnSlotFrameInventoryTransferHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotFrameInventoryTransferClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (sourceOffsets : claim.source.holds frame originalState.registers
      candidateState.registers)
    (sourceMemory : frame.memoryHolds originalState.memory candidateState.memory)
    (sourceExactWords : claim.source.boundedExactWordsHold frame
      originalState.memory candidateState.memory)
    (sourceProtected : frame.protectedSpanValid context = true)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.target.holds frame
        (originalBehavior.eval originalState).registers
        (candidateBehavior.eval candidateState).registers ∧
      frame.memoryHolds
        ((originalBehavior.eval originalState).nextMachineState originalState).memory
        ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory ∧
      claim.target.boundedExactWordsHold frame
        ((originalBehavior.eval originalState).nextMachineState originalState).memory
        ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory := by
  simp only [ReturnSlotFrameInventoryTransferClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨sourceChecked, targetChecked⟩, sourcesListed⟩,
      targetsExact⟩, transfersChecked⟩, exactWordsExact⟩,
      exactTransfersChecked⟩
  have transferResult (transfer : ReturnSlotFrameTransferClaim)
      (member : transfer ∈ claim.transfers) :
      transfer.transfer.target.holds frame
          (originalBehavior.eval originalState).registers
          (candidateBehavior.eval candidateState).registers ∧
        frame.memoryHolds
          ((originalBehavior.eval originalState).nextMachineState originalState).memory
          ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory := by
    have sourceMember : transfer.transfer.source ∈ claim.source.locations :=
      List.contains_iff_mem.mp
        (List.all_eq_true.mp sourcesListed transfer member)
    exact returnSlotFrameTransferHolds_of_checked context world sourceInvariant
      originalBehavior candidateBehavior transfer frame originalState candidateState
      (List.all_eq_true.mp transfersChecked transfer member)
      (claim.source.holds_member frame originalState.registers candidateState.registers
        transfer.transfer.source sourceOffsets sourceMember)
      sourceMemory (by
        cases memoryCase : transfer.memory <;>
          simp [InternalReturnSlotMemoryTransferClaim.requirement, memoryCase,
            sourceProtected]) related
  have exactTransferResult (transfer : ReturnSlotExactWordTransferClaim)
      (member : transfer ∈ claim.exactWordTransfers) :
      transfer.word.holds frame
        ((originalBehavior.eval originalState).nextMachineState originalState).memory
        ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory := by
    exact returnSlotExactWordTransferHolds_of_checked context world sourceInvariant
      originalBehavior candidateBehavior claim.source claim.target
      claim.target.locations transfer frame originalState candidateState
      (List.all_eq_true.mp exactTransfersChecked transfer member)
      sourceOffsets sourceExactWords.2 sourceProtected sourceExactWords.1 related
  refine ⟨?_, ?_, ?_⟩
  · refine ⟨claim.target.checked_nonempty targetChecked, ?_⟩
    intro target targetMember
    have mappedMember : target ∈
        claim.transfers.map (fun transfer => transfer.transfer.target) := by
      rw [targetsExact]
      exact targetMember
    rcases List.mem_map.mp mappedMember with ⟨transfer, member, targetEqual⟩
    simpa [targetEqual] using (transferResult transfer member).1
  · cases transfersResult : claim.transfers with
    | nil =>
        have targetEmpty : claim.target.locations = [] := by
          rw [← targetsExact, transfersResult]
          rfl
        exact False.elim
          (claim.target.checked_nonempty targetChecked targetEmpty)
    | cons transfer transfers =>
        exact (transferResult transfer (by simp [transfersResult])).2
  · constructor
    · simp only [ReturnSlotOffsetInventory.exactWordsFit,
        List.all_eq_true, Bool.and_eq_true, decide_eq_true_eq]
      intro word wordMember
      have mappedMember : word ∈
          claim.exactWordTransfers.map (fun transfer => transfer.word) := by
        rw [exactWordsExact]
        exact wordMember
      rcases List.mem_map.mp mappedMember with ⟨transfer, member, wordEqual⟩
      have transferChecked := List.all_eq_true.mp exactTransfersChecked
        transfer member
      simp only [ReturnSlotExactWordTransferClaim.checked,
        Bool.and_eq_true, List.contains_iff_mem] at transferChecked
      have sourceMember := transferChecked.1.1.1.1.1.1
      simpa [wordEqual] using
        (claim.source.exactWordFits_of_bounded frame originalState.memory
          candidateState.memory transfer.word sourceExactWords sourceMember)
    · intro word wordMember
      have mappedMember : word ∈
          claim.exactWordTransfers.map (fun transfer => transfer.word) := by
        rw [exactWordsExact]
        exact wordMember
      rcases List.mem_map.mp mappedMember with ⟨transfer, member, wordEqual⟩
      simpa [wordEqual] using exactTransferResult transfer member

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

def ReturnSlotCallSummaryCoreClosed
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callStack : CallPushStackClaim) (claim : ReturnSlotCallSummaryClaim) : Prop :=
  ((((claim.source.originalRegister = .esp ∧
    claim.source.candidateRegister = .esp) ∧
    claim.target.originalRegister = .esp) ∧
    claim.target.candidateRegister = .esp) ∧
    claim.popBytes ≤ 65535) ∧
  claim.originalCallEsp.expression .esp = callStack.originalStackAddress ∧
  claim.candidateCallEsp.expression .esp = callStack.candidateStackAddress ∧
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

def ReturnSlotCallSummaryClaim.checkedCore
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callStack : CallPushStackClaim) (claim : ReturnSlotCallSummaryClaim) : Bool :=
  claim.source.originalRegister == .esp &&
  claim.source.candidateRegister == .esp &&
  claim.target.originalRegister == .esp &&
  claim.target.candidateRegister == .esp &&
  decide (claim.popBytes ≤ 65535) &&
  (claim.originalCallEsp.expression .esp == callStack.originalStackAddress &&
  (claim.candidateCallEsp.expression .esp == callStack.candidateStackAddress &&
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

def ReturnSlotCallSummaryClosed
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callClaim : DirectCallPushClaim) (claim : ReturnSlotCallSummaryClaim) : Prop :=
  ReturnSlotCallSummaryCoreClosed originalCallBehavior candidateCallBehavior
    originalReturnBehavior candidateReturnBehavior callClaim.stackClaim claim

def IndirectReturnSlotCallSummaryClosed
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callClaim : IndirectCallPushClaim) (claim : ReturnSlotCallSummaryClaim) : Prop :=
  ReturnSlotCallSummaryCoreClosed originalCallBehavior candidateCallBehavior
    originalReturnBehavior candidateReturnBehavior callClaim.stackClaim claim

def ReturnSlotCallSummaryClaim.checked
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callClaim : DirectCallPushClaim) (claim : ReturnSlotCallSummaryClaim) : Bool :=
  claim.checkedCore originalCallBehavior candidateCallBehavior
    originalReturnBehavior candidateReturnBehavior callClaim.stackClaim

def ReturnSlotCallSummaryClaim.checkedIndirect
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callClaim : IndirectCallPushClaim) (claim : ReturnSlotCallSummaryClaim) : Bool :=
  claim.checkedCore originalCallBehavior candidateCallBehavior
    originalReturnBehavior candidateReturnBehavior callClaim.stackClaim

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
  unfold ReturnSlotCallSummaryClaim.checkedCore at checked
  unfold ReturnSlotCallSummaryCoreClosed
  unfold DirectCallPushClaim.stackClaim
  simpa only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] using checked

theorem indirectReturnSlotCallSummaryClosed_of_checked
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callClaim : IndirectCallPushClaim) (claim : ReturnSlotCallSummaryClaim)
    (checked : claim.checkedIndirect originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior callClaim = true) :
    IndirectReturnSlotCallSummaryClosed originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior callClaim claim := by
  unfold ReturnSlotCallSummaryClaim.checkedIndirect at checked
  unfold IndirectReturnSlotCallSummaryClosed
  unfold ReturnSlotCallSummaryClaim.checkedCore at checked
  unfold ReturnSlotCallSummaryCoreClosed
  unfold IndirectCallPushClaim.stackClaim
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
  simp only [DirectCallPushClaim.stackClaim] at originalCallExpression
  simp only [DirectCallPushClaim.stackClaim] at candidateCallExpression
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

theorem indirectReturnSlotCallSummaryHolds_of_checked
    (context : StaticProofContext)
    (originalCallBehavior candidateCallBehavior
      originalReturnBehavior candidateReturnBehavior : NormalizedSymbolicBehavior)
    (callClaim : IndirectCallPushClaim) (claim : ReturnSlotCallSummaryClaim)
    (outerFrame nestedFrame : RelationalRuntimeCallFrame)
    (originalCallState candidateCallState originalReturnState candidateReturnState :
      MachineState)
    (checked : claim.checkedIndirect originalCallBehavior candidateCallBehavior
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
  apply returnSlotCallSummaryHolds_of_checked context originalCallBehavior
    candidateCallBehavior originalReturnBehavior candidateReturnBehavior
    callClaim.asDirectRuntimeClaim claim outerFrame nestedFrame originalCallState
    candidateCallState originalReturnState candidateReturnState
  · simpa [ReturnSlotCallSummaryClaim.checked,
      ReturnSlotCallSummaryClaim.checkedIndirect,
      IndirectCallPushClaim.asDirectRuntimeClaim,
      DirectCallPushClaim.stackClaim, IndirectCallPushClaim.stackClaim] using checked
  · simpa [IndirectCallPushClaim.runtimeFrame, DirectCallPushClaim.runtimeFrame,
      IndirectCallPushClaim.frame, DirectCallPushClaim.frame,
      IndirectCallPushClaim.asDirectRuntimeClaim] using nestedFrameResult
  · exact outerSource
  · exact nestedSlots

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
  /-- The candidate may reach the same paired target through the opposite
  branch arm. Target and guard equality remain independently checked. -/
  candidateKind : RelationalProductEdgeKind := kind
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
          ∃ originalTarget candidateTarget,
            originalBehavior.outcome.eval originalState = .indirectCall
                originalTarget claim.continuationTargetId ∧
              candidateBehavior.outcome.eval candidateState = .indirectCall
                candidateTarget claim.continuationTargetId ∧
              codeAddressMatches context.originalPe.imageBase target.originalRva
                target.originalAliases originalTarget = true ∧
              codeAddressMatches context.candidatePe.imageBase target.candidateRva
                target.candidateAliases candidateTarget = true

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
    refine ⟨BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva),
      BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva), ?_, ?_,
      ?_, ?_⟩
    · rw [originalOutcome]
      simp [NormalizedOutcomeExpr.eval, originalTarget]
    · rw [candidateOutcome]
      simp [NormalizedOutcomeExpr.eval, candidateTarget]
    · simp [codeAddressMatches]
    · simp [codeAddressMatches]

/-
A bounded immutable function-pointer table is a deliberately narrow indirect
call profile.  The checker below accepts only a direct IA-32 scaled-index
read, an exact paired index register, and a statically bounded, relocation-
backed table whose rows name canonical code-map entries.  The row inventory is
part of the checked certificate; no disassembly name or proposal status enters
the proposition.
-/
structure ImmutableCodePointerTableRow where
  index : Nat
  targetId : Nat
deriving Repr, DecidableEq

inductive ImmutableCodePointerTableLayout where
  | zeroBasedBounded
  | sentinelTerminatedReverseCount
deriving Repr, DecidableEq

structure BoundedImmutableCodePointerTableCallClaim where
  valueTargetId : Nat
  tableOffset : Nat
  originalBase : Nat
  candidateBase : Nat
  layout : ImmutableCodePointerTableLayout := .zeroBasedBounded
  upperExclusive : Nat
  originalIndexRegister : Reg
  candidateIndexRegister : Reg
  continuationTargetId : Nat
  rows : List ImmutableCodePointerTableRow
deriving Repr, DecidableEq

def ImmutableCodePointerTableLayout.lowerInclusive :
    ImmutableCodePointerTableLayout → Nat
  | .zeroBasedBounded => 0
  | .sentinelTerminatedReverseCount => 1

def BoundedImmutableCodePointerTableCallClaim.lowerInclusive
    (claim : BoundedImmutableCodePointerTableCallClaim) : Nat :=
  claim.layout.lowerInclusive

def BoundedImmutableCodePointerTableCallClaim.entryCount
    (claim : BoundedImmutableCodePointerTableCallClaim) : Nat :=
  claim.upperExclusive - claim.lowerInclusive

def BoundedImmutableCodePointerTableCallClaim.tableSpanWords
    (claim : BoundedImmutableCodePointerTableCallClaim) : Nat :=
  match claim.layout with
  | .zeroBasedBounded => claim.upperExclusive
  | .sentinelTerminatedReverseCount => claim.upperExclusive + 1

def BoundedImmutableCodePointerTableCallClaim.originalAddress
    (claim : BoundedImmutableCodePointerTableCallClaim) (index : Nat) : Nat :=
  claim.originalBase + index * 4

def BoundedImmutableCodePointerTableCallClaim.candidateAddress
    (claim : BoundedImmutableCodePointerTableCallClaim) (index : Nat) : Nat :=
  claim.candidateBase + index * 4

def BoundedImmutableCodePointerTableCallClaim.originalIndexExpression
    (claim : BoundedImmutableCodePointerTableCallClaim) : Expr :=
  .inputReg claim.originalIndexRegister

def BoundedImmutableCodePointerTableCallClaim.candidateIndexExpression
    (claim : BoundedImmutableCodePointerTableCallClaim) : Expr :=
  .inputReg claim.candidateIndexRegister

def immutableCodePointerTableAddressExpression (base : Nat) (index : Expr) : Expr :=
  .add (.shiftLeft index 2) (.constant base)

def immutableCodePointerTableTargetExpression (base : Nat) (index : Expr) : Expr :=
  .read32 (immutableCodePointerTableAddressExpression base index)

theorem immutableCodePointerTableAddressExpression_eval_of_index
    (base index : Nat) (expression : Expr) (state : MachineState)
    (evaluated : expression.eval state = BitVec.ofNat 32 index) :
    (immutableCodePointerTableAddressExpression base expression).eval state =
      BitVec.ofNat 32 (base + index * 4) := by
  simp only [immutableCodePointerTableAddressExpression, Expr.eval, evaluated]
  have shiftFour (value : BitVec 32) :
      value.shiftLeft 2 = value * BitVec.ofNat 32 4 := by
    bv_decide
  rw [shiftFour, ← BitVec.ofNat_mul, ← BitVec.ofNat_add]
  congr 1
  omega

def BoundedImmutableCodePointerTableCallClaim.originalTargetExpression
    (claim : BoundedImmutableCodePointerTableCallClaim) : Expr :=
  immutableCodePointerTableTargetExpression claim.originalBase
    claim.originalIndexExpression

def BoundedImmutableCodePointerTableCallClaim.candidateTargetExpression
    (claim : BoundedImmutableCodePointerTableCallClaim) : Expr :=
  immutableCodePointerTableTargetExpression claim.candidateBase
    claim.candidateIndexExpression

def immutableCodePointerTableRowGuard (candidate : Bool)
    (claim : BoundedImmutableCodePointerTableCallClaim)
    (row : ImmutableCodePointerTableRow) : BoolExpr :=
  .equal (if candidate then claim.candidateIndexExpression
    else claim.originalIndexExpression) (.constant row.index)

def BoundedImmutableCodePointerTableCallClaim.indexBound
    (claim : BoundedImmutableCodePointerTableCallClaim) : RegisterBoundPair := {
  original := claim.originalIndexRegister
  candidate := claim.candidateIndexRegister
  originalExpression := match claim.layout with
    | .zeroBasedBounded => none
    | .sentinelTerminatedReverseCount =>
        some (.sub (.inputReg claim.originalIndexRegister) (.constant 1))
  candidateExpression := match claim.layout with
    | .zeroBasedBounded => none
    | .sentinelTerminatedReverseCount =>
        some (.sub (.inputReg claim.candidateIndexRegister) (.constant 1))
  upperExclusive := claim.entryCount
}

theorem shiftedIndexBound_range (value : Word) (upperExclusive : Nat)
    (positive : 0 < upperExclusive)
    (fits : upperExclusive < 2 ^ 32)
    (bounded : decide (
      value - BitVec.ofNat 32 1 <
        BitVec.ofNat 32 (upperExclusive - 1)) = true) :
    1 <= value.toNat ∧ value.toNat < upperExclusive := by
  have valueFits : value.toNat < 2 ^ 32 := by simpa using value.isLt
  have entryFits : upperExclusive - 1 < 2 ^ 32 := by omega
  have boundedNat := of_decide_eq_true bounded
  simp only [BitVec.lt_def, BitVec.toNat_sub, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt entryFits] at boundedNat
  simp at boundedNat
  by_cases zero : value.toNat = 0
  · rw [zero] at boundedNat
    omega
  · have reduced :
        (2 ^ 32 - 1 + value.toNat) % 2 ^ 32 = value.toNat - 1 := by
      omega
    rw [reduced] at boundedNat
    omega

def pe32RelocationCountAt (relocations : List BaseRelocation) (rva : Nat) : Nat :=
  (relocations.filter fun relocation =>
    relocation.rva == rva && relocation.kind == 3).length

def pe32RelocationWordAt (relocations : List BaseRelocation) (rva : Nat) : Bool :=
  pe32RelocationCountAt relocations rva == 1

def BoundedImmutableCodePointerTableCallClaim.rowIndexValid
    (claim : BoundedImmutableCodePointerTableCallClaim) (index : Nat) : Bool :=
  decide (claim.lowerInclusive <= index && index < claim.upperExclusive)

def ImmutableCodePointerTableRow.checked (context : StaticProofContext)
    (claim : BoundedImmutableCodePointerTableCallClaim)
    (row : ImmutableCodePointerTableRow) : Bool :=
  match context.codeMap.get? row.targetId with
  | none => false
  | some target =>
      (claim.rowIndexValid row.index &&
        target.id == row.targetId &&
        rvaInExecutableSection context.originalPe target.originalRva &&
        rvaInExecutableSection context.candidatePe target.candidateRva &&
        !(context.originalPe.imageBase + target.originalRva == 0) &&
        !(context.candidatePe.imageBase + target.candidateRva == 0) &&
        decide (context.originalPe.imageBase + target.originalRva < 2 ^ 32) &&
        decide (context.candidatePe.imageBase + target.candidateRva < 2 ^ 32) &&
        claim.originalAddress row.index >= context.originalPe.imageBase &&
        claim.candidateAddress row.index >= context.candidatePe.imageBase &&
        pe32RelocationWordAt context.originalRelocations
          (claim.originalAddress row.index - context.originalPe.imageBase) &&
        pe32RelocationWordAt context.candidateRelocations
          (claim.candidateAddress row.index - context.candidatePe.imageBase)) &&
        (readImmutableImageWord context.originalPe
            (claim.originalAddress row.index) 4 ==
          some (context.originalPe.imageBase + target.originalRva)) &&
        readImmutableImageWord context.candidatePe
            (claim.candidateAddress row.index) 4 ==
          some (context.candidatePe.imageBase + target.candidateRva)

def immutableCodePointerTableRowsCover
    (claim : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  (List.range claim.entryCount).all fun offset =>
    claim.rows.any fun row => row.index == claim.lowerInclusive + offset

def immutableCodePointerTableRowsUnique
    (claim : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  claim.rows.all fun row =>
    (claim.rows.filter (fun other => other.index == row.index)).length == 1

def BoundedImmutableCodePointerTableCallClaim.boundaryChecked
    (context : StaticProofContext)
    (claim : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  match claim.layout with
  | .zeroBasedBounded => true
  | .sentinelTerminatedReverseCount =>
      claim.upperExclusive > 0 &&
        readImmutableImageWord context.originalPe claim.originalBase 4 ==
          some (2 ^ 32 - 1) &&
        readImmutableImageWord context.candidatePe claim.candidateBase 4 ==
          some (2 ^ 32 - 1) &&
        readImmutableImageWord context.originalPe
            (claim.originalAddress claim.upperExclusive) 4 == some 0 &&
        readImmutableImageWord context.candidatePe
            (claim.candidateAddress claim.upperExclusive) 4 == some 0 &&
        pe32RelocationCountAt context.originalRelocations
            (claim.originalBase - context.originalPe.imageBase) == 0 &&
        pe32RelocationCountAt context.candidateRelocations
            (claim.candidateBase - context.candidatePe.imageBase) == 0 &&
        pe32RelocationCountAt context.originalRelocations
            (claim.originalAddress claim.upperExclusive -
              context.originalPe.imageBase) == 0 &&
        pe32RelocationCountAt context.candidateRelocations
            (claim.candidateAddress claim.upperExclusive -
              context.candidatePe.imageBase) == 0

def BoundedImmutableCodePointerTableCallClaim.staticShapeChecked
    (context : StaticProofContext)
    (claim : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  immutableCodePointerTableRowsCover claim &&
    decide (claim.upperExclusive < 2 ^ 32) &&
    decide (0 < claim.upperExclusive) &&
    claim.boundaryChecked context &&
    match context.dataMap.get? claim.valueTargetId with
    | some table =>
        claim.rows.length == claim.entryCount &&
          immutableCodePointerTableRowsUnique claim &&
          table.id == claim.valueTargetId &&
          table.originalValue + claim.tableOffset == claim.originalBase &&
          table.candidateValue + claim.tableOffset == claim.candidateBase &&
          decide (claim.tableOffset + claim.tableSpanWords * 4 <= table.mappedSize) &&
          decide (claim.originalBase + claim.tableSpanWords * 4 <= 2 ^ 32) &&
          decide (claim.candidateBase + claim.tableSpanWords * 4 <= 2 ^ 32) &&
          (List.range claim.entryCount).all (fun offset =>
            table.relocationOffsets.contains
              (claim.tableOffset + (claim.lowerInclusive + offset) * 4)) &&
          (match claim.layout with
          | .zeroBasedBounded => true
          | .sentinelTerminatedReverseCount =>
              !(table.relocationOffsets.contains claim.tableOffset) &&
                !(table.relocationOffsets.contains
                  (claim.tableOffset + claim.upperExclusive * 4)))
    | none => false

def uninhabitedStatePredicate : PairedStatePredicate := {
  original := .equal (.constant 0) (.constant 1)
  candidate := .equal (.constant 0) (.constant 1)
}

def registerZeroStatePredicate (original candidate : Reg) : PairedStatePredicate := {
  original := .equal (.inputReg original) (.constant 0)
  candidate := .equal (.inputReg candidate) (.constant 0)
}

def registerNonzeroGuard (register : Reg) : BoolExpr :=
  .not (.equal (.bitAnd (.inputReg register) (.inputReg register)) (.constant 0))

structure RegisterZeroGuardContradictionClaim where
  originalRegister : Reg
  candidateRegister : Reg
deriving Repr, DecidableEq

def RegisterZeroGuardContradictionClaim.checked
    (edge : RelationalSegmentEdge) (sourceInvariant targetInvariant : StateInvariant)
    (claim : RegisterZeroGuardContradictionClaim) : Bool :=
  sourceInvariant.predicates.contains
      (registerZeroStatePredicate claim.originalRegister claim.candidateRegister) &&
    targetInvariant.predicates == [uninhabitedStatePredicate] &&
    edge.originalGuard == registerNonzeroGuard claim.originalRegister &&
    edge.candidateGuard == registerNonzeroGuard claim.candidateRegister

theorem segmentTransitionClosed_of_register_zero_guard_contradiction
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (claim : RegisterZeroGuardContradictionClaim)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (checked : claim.checked edge sourceInvariant targetInvariant = true) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  simp only [RegisterZeroGuardContradictionClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨sourcePredicateMember, _targetBottom⟩, originalGuardShape⟩,
      candidateGuardShape⟩
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  intro world originalState candidateState related
  have predicates := related.predicatesHold
  have zeroes := pairedStatePredicatesHold_member sourceInvariant.predicates
    (registerZeroStatePredicate claim.originalRegister claim.candidateRegister)
    originalState candidateState (List.contains_iff_mem.mp sourcePredicateMember)
    predicates
  simp only [registerZeroStatePredicate, PairedStatePredicate.holds,
    BoolExpr.eval, Expr.eval, Bool.and_eq_true, beq_iff_eq] at zeroes
  have originalZero := of_decide_eq_true zeroes.1.1
  have candidateZero := of_decide_eq_true zeroes.1.2
  rw [originalGuardShape, candidateGuardShape]
  have originalFalse :
      (registerNonzeroGuard claim.originalRegister).eval originalState = false := by
    simp [registerNonzeroGuard, BoolExpr.eval, Expr.eval, originalZero]
  have candidateFalse :
      (registerNonzeroGuard claim.candidateRegister).eval candidateState = false := by
    simp [registerNonzeroGuard, BoolExpr.eval, Expr.eval, candidateZero]
  refine ⟨originalFalse.trans candidateFalse.symm, ?_⟩
  intro guardTrue
  rw [originalFalse] at guardTrue
  contradiction

def BoundedImmutableCodePointerTableCallClaim.inputDomainChecked
    (sourceInvariant : StateInvariant)
    (claim : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  if claim.entryCount == 0 then
    sourceInvariant.predicates.contains uninhabitedStatePredicate
  else
    exactRegisterPair sourceInvariant.registerRelations
        claim.originalIndexRegister claim.candidateIndexRegister &&
      sourceInvariant.bounds.contains claim.indexBound

def BoundedImmutableCodePointerTableCallClaim.shapeChecked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (claim : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  claim.staticShapeChecked context &&
    claim.inputDomainChecked sourceInvariant &&
    match context.codeMap.get? claim.continuationTargetId with
    | some continuation => continuation.id == claim.continuationTargetId
    | none => false

def BoundedImmutableCodePointerTableCallClaim.rowsChecked
    (context : StaticProofContext)
    (claim : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  claim.rows.all (ImmutableCodePointerTableRow.checked context claim)

theorem immutableCodePointerTableRowReadsNonzero_of_checked
    (context : StaticProofContext)
    (claim : BoundedImmutableCodePointerTableCallClaim)
    (row : ImmutableCodePointerTableRow)
    (originalMemory candidateMemory : Memory)
    (originalImmutable : ImmutableImageWordMemory context.originalPe originalMemory)
    (candidateImmutable : ImmutableImageWordMemory context.candidatePe candidateMemory)
    (checked : row.checked context claim = true) :
    ∃ target,
      context.codeMap.get? row.targetId = some target ∧
      Memory.read32 originalMemory (BitVec.ofNat 32 (claim.originalAddress row.index)) =
        BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva) ∧
      Memory.read32 candidateMemory (BitVec.ofNat 32 (claim.candidateAddress row.index)) =
        BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva) ∧
      context.originalPe.imageBase + target.originalRva ≠ 0 ∧
      context.candidatePe.imageBase + target.candidateRva ≠ 0 ∧
      context.originalPe.imageBase + target.originalRva < 2 ^ 32 ∧
      context.candidatePe.imageBase + target.candidateRva < 2 ^ 32 := by
  cases targetResult : context.codeMap.get? row.targetId with
  | none => simp [ImmutableCodePointerTableRow.checked, targetResult] at checked
  | some target =>
      have checkedForNonzero := checked
      simp only [ImmutableCodePointerTableRow.checked, targetResult,
        Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with
        ⟨⟨staticRowChecked, originalImageWord⟩, candidateImageWord⟩
      have originalNonzero :
          context.originalPe.imageBase + target.originalRva ≠ 0 := by
        intro zero
        simp [ImmutableCodePointerTableRow.checked, targetResult, zero] at checkedForNonzero
      have candidateNonzero :
          context.candidatePe.imageBase + target.candidateRva ≠ 0 := by
        intro zero
        simp [ImmutableCodePointerTableRow.checked, targetResult, zero] at checkedForNonzero
      have originalFits :
          context.originalPe.imageBase + target.originalRva < 2 ^ 32 := by
        exact of_decide_eq_true staticRowChecked.1.1.1.1.1.2
      have candidateFits :
          context.candidatePe.imageBase + target.candidateRva < 2 ^ 32 := by
        exact of_decide_eq_true staticRowChecked.1.1.1.1.2
      exact ⟨target, rfl,
        ImmutableImageWordMemory.read32_of_checked context.originalPe originalMemory
          (claim.originalAddress row.index)
          (context.originalPe.imageBase + target.originalRva) originalImmutable
          originalImageWord,
        ImmutableImageWordMemory.read32_of_checked context.candidatePe candidateMemory
          (claim.candidateAddress row.index)
          (context.candidatePe.imageBase + target.candidateRva) candidateImmutable
          candidateImageWord,
        originalNonzero, candidateNonzero, originalFits, candidateFits⟩

def BoundedImmutableCodePointerTableCallClaim.behaviorChecked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  originalBehavior.outcome == .indirectCall claim.originalTargetExpression
      claim.continuationTargetId &&
    candidateBehavior.outcome == .indirectCall claim.candidateTargetExpression
      claim.continuationTargetId

def BoundedImmutableCodePointerTableCallClaim.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  claim.shapeChecked context sourceInvariant &&
    claim.rowsChecked context &&
    claim.behaviorChecked originalBehavior candidateBehavior

def BoundedImmutableCodePointerTableCallTargetsClosed
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableCodePointerTableCallClaim) : Prop :=
  context.StructurallyValid ∧
    ∀ world originalState candidateState,
      StateRel context world sourceInvariant originalState candidateState →
        ∃ row target originalTarget candidateTarget,
          row ∈ claim.rows ∧
            context.codeMap.get? row.targetId = some target ∧
            row.checked context claim = true ∧
            originalBehavior.outcome.eval originalState = .indirectCall
              originalTarget claim.continuationTargetId ∧
            candidateBehavior.outcome.eval candidateState = .indirectCall
              candidateTarget claim.continuationTargetId ∧
            (immutableCodePointerTableRowGuard false claim row).eval originalState = true ∧
            (immutableCodePointerTableRowGuard true claim row).eval candidateState = true ∧
            codeAddressMatches context.originalPe.imageBase target.originalRva
              target.originalAliases originalTarget = true ∧
            codeAddressMatches context.candidatePe.imageBase target.candidateRva
              target.candidateAliases candidateTarget = true

theorem boundedImmutableCodePointerTableCallTargetsClosed_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableCodePointerTableCallClaim)
    (structurallyValid : context.StructurallyValid)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true) :
    BoundedImmutableCodePointerTableCallTargetsClosed context sourceInvariant
      originalBehavior candidateBehavior claim := by
  refine ⟨structurallyValid, ?_⟩
  simp only [BoundedImmutableCodePointerTableCallClaim.checked,
    Bool.and_eq_true] at checked
  rcases checked with ⟨⟨shapeChecked, rowsChecked⟩, behaviorChecked⟩
  simp only [BoundedImmutableCodePointerTableCallClaim.behaviorChecked,
    Bool.and_eq_true, beq_iff_eq] at behaviorChecked
  rcases behaviorChecked with ⟨originalOutcome, candidateOutcome⟩
  simp only [BoundedImmutableCodePointerTableCallClaim.shapeChecked,
    Bool.and_eq_true] at shapeChecked
  rcases shapeChecked with
    ⟨⟨staticShapeChecked, inputDomainChecked⟩, continuationChecked⟩
  simp only [BoundedImmutableCodePointerTableCallClaim.staticShapeChecked,
    Bool.and_eq_true] at staticShapeChecked
  rcases staticShapeChecked with
    ⟨⟨⟨⟨rowsCover, upperExclusiveChecked⟩, upperExclusivePositive⟩,
      boundaryChecked⟩, tableShapeChecked⟩
  intro world originalState candidateState related
  cases emptyResult : claim.entryCount == 0 with
  | true =>
      have bottomMember :
          sourceInvariant.predicates.contains uninhabitedStatePredicate = true := by
        simpa [BoundedImmutableCodePointerTableCallClaim.inputDomainChecked,
          emptyResult] using inputDomainChecked
      have bottomHolds := pairedStatePredicatesHold_member
        sourceInvariant.predicates uninhabitedStatePredicate originalState
        candidateState (List.contains_iff_mem.mp bottomMember)
        related.predicatesHold
      simp [uninhabitedStatePredicate, PairedStatePredicate.holds,
        BoolExpr.eval, Expr.eval] at bottomHolds
  | false =>
    have inputDomain :
        exactRegisterPair sourceInvariant.registerRelations
            claim.originalIndexRegister claim.candidateIndexRegister = true ∧
          sourceInvariant.bounds.contains claim.indexBound = true := by
      simpa [BoundedImmutableCodePointerTableCallClaim.inputDomainChecked,
        emptyResult] using inputDomainChecked
    rcases inputDomain with ⟨exactIndices, boundMember⟩
    have entryCountNonzero : claim.entryCount ≠ 0 := by
      exact fun zero => by simp [zero] at emptyResult
    rcases related with
      ⟨worldValid, stackRangesValid, stackMemory, importsStatic, importsComplete,
        importsMemory, originalImmutable, candidateImmutable, relatedCore,
        importAndDynamicRegisters⟩
    have allBounds := relatedCore.2.1
    simp only [boundsRelated, List.all_eq_true] at allBounds
    have selectedBound := allBounds claim.indexBound
      (List.contains_iff_mem.mp boundMember)
    have upperExclusiveSmall : claim.upperExclusive < 2 ^ 32 :=
      of_decide_eq_true upperExclusiveChecked
    have upperExclusivePositiveNat : 0 < claim.upperExclusive :=
      of_decide_eq_true upperExclusivePositive
    have originalIndexRange :
        claim.lowerInclusive <=
            (originalState.registers.get claim.originalIndexRegister).toNat ∧
          (originalState.registers.get claim.originalIndexRegister).toNat <
            claim.upperExclusive := by
      cases layout : claim.layout with
      | zeroBasedBounded =>
          simp [BoundedImmutableCodePointerTableCallClaim.indexBound,
            BoundedImmutableCodePointerTableCallClaim.entryCount,
            BoundedImmutableCodePointerTableCallClaim.lowerInclusive, layout,
            ImmutableCodePointerTableLayout.lowerInclusive, boundValue,
            Bool.and_eq_true] at selectedBound
          have bounded := selectedBound.1
          have boundedNat :
              (originalState.registers.get claim.originalIndexRegister).toNat <
                claim.upperExclusive := by
            simpa [BitVec.lt_def, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt upperExclusiveSmall] using bounded
          constructor
          · simp [BoundedImmutableCodePointerTableCallClaim.lowerInclusive, layout,
              ImmutableCodePointerTableLayout.lowerInclusive]
          · exact boundedNat
      | sentinelTerminatedReverseCount =>
          simp [BoundedImmutableCodePointerTableCallClaim.indexBound,
            BoundedImmutableCodePointerTableCallClaim.entryCount,
            BoundedImmutableCodePointerTableCallClaim.lowerInclusive, layout,
            ImmutableCodePointerTableLayout.lowerInclusive, boundValue,
            evalExprPure, Bool.and_eq_true] at selectedBound
          simpa [BoundedImmutableCodePointerTableCallClaim.lowerInclusive, layout,
            ImmutableCodePointerTableLayout.lowerInclusive] using
            shiftedIndexBound_range
              (originalState.registers.get claim.originalIndexRegister)
              claim.upperExclusive upperExclusivePositiveNat upperExclusiveSmall
              (by simpa only [decide_eq_true_eq] using selectedBound.1)
    have entryCountPositive : 0 < claim.entryCount := by omega
    have indexEqual := registerRelationsHold_exact_pair
      context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      sourceInvariant.registerRelations originalState.registers candidateState.registers
      claim.originalIndexRegister claim.candidateIndexRegister relatedCore.1 exactIndices
    have originalIndexOffsetBound :
        (originalState.registers.get claim.originalIndexRegister).toNat -
            claim.lowerInclusive < claim.entryCount := by
      simp only [BoundedImmutableCodePointerTableCallClaim.entryCount]
      omega
    have rowExists : claim.rows.any (fun row =>
        row.index == (originalState.registers.get claim.originalIndexRegister).toNat) = true := by
      simp only [immutableCodePointerTableRowsCover, List.all_eq_true] at rowsCover
      have selected := rowsCover
        ((originalState.registers.get claim.originalIndexRegister).toNat -
          claim.lowerInclusive)
        (List.mem_range.mpr originalIndexOffsetBound)
      simp only [List.any_eq_true] at selected ⊢
      rcases selected with ⟨row, rowMember, rowIndex⟩
      refine ⟨row, rowMember, ?_⟩
      have rowIndexNat := beq_iff_eq.mp rowIndex
      apply beq_iff_eq.mpr
      rw [rowIndexNat]
      omega
    simp only [List.any_eq_true] at rowExists
    rcases rowExists with ⟨row, rowMember, rowIndexChecked⟩
    have rowIndex : row.index =
        (originalState.registers.get claim.originalIndexRegister).toNat :=
      beq_iff_eq.mp rowIndexChecked
    have rowChecked := rowsChecked
    simp only [BoundedImmutableCodePointerTableCallClaim.rowsChecked,
      List.all_eq_true] at rowChecked
    have checkedRow := rowChecked row rowMember
    cases targetResult : context.codeMap.get? row.targetId with
    | none =>
        simp [ImmutableCodePointerTableRow.checked, targetResult] at checkedRow
    | some target =>
      simp only [ImmutableCodePointerTableRow.checked, targetResult,
        Bool.and_eq_true, beq_iff_eq] at checkedRow
      rcases checkedRow with
        ⟨⟨_staticRowChecked, originalImageWord⟩, candidateImageWord⟩
      have originalIndexWord :
          originalState.registers.get claim.originalIndexRegister =
            BitVec.ofNat 32 row.index := by
        rw [rowIndex]
        simp
      have candidateIndexWord :
          candidateState.registers.get claim.candidateIndexRegister =
            BitVec.ofNat 32 row.index := by
        rw [← indexEqual, originalIndexWord]
      have originalAddressEvaluation :
          (immutableCodePointerTableAddressExpression claim.originalBase
            claim.originalIndexExpression).eval originalState =
              BitVec.ofNat 32 (claim.originalAddress row.index) := by
        simp only [immutableCodePointerTableAddressExpression,
          BoundedImmutableCodePointerTableCallClaim.originalIndexExpression,
          BoundedImmutableCodePointerTableCallClaim.originalAddress, Expr.eval,
          originalIndexWord]
        have shiftFour (value : BitVec 32) :
            value.shiftLeft 2 = value * BitVec.ofNat 32 4 := by
          bv_decide
        rw [shiftFour, ← BitVec.ofNat_mul, ← BitVec.ofNat_add]
        congr 1
        omega
      have candidateAddressEvaluation :
          (immutableCodePointerTableAddressExpression claim.candidateBase
            claim.candidateIndexExpression).eval candidateState =
              BitVec.ofNat 32 (claim.candidateAddress row.index) := by
        simp only [immutableCodePointerTableAddressExpression,
          BoundedImmutableCodePointerTableCallClaim.candidateIndexExpression,
          BoundedImmutableCodePointerTableCallClaim.candidateAddress, Expr.eval,
          candidateIndexWord]
        have shiftFour (value : BitVec 32) :
            value.shiftLeft 2 = value * BitVec.ofNat 32 4 := by
          bv_decide
        rw [shiftFour, ← BitVec.ofNat_mul, ← BitVec.ofNat_add]
        congr 1
        omega
      have originalTargetEvaluation :
          claim.originalTargetExpression.eval originalState =
            BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva) := by
        simp only [BoundedImmutableCodePointerTableCallClaim.originalTargetExpression,
          immutableCodePointerTableTargetExpression, Expr.eval,
          machineStateRead32_eq_memoryRead32, originalAddressEvaluation]
        exact ImmutableImageWordMemory.read32_of_checked context.originalPe
          originalState.memory (claim.originalAddress row.index)
          (context.originalPe.imageBase + target.originalRva) originalImmutable
          originalImageWord
      have candidateTargetEvaluation :
          claim.candidateTargetExpression.eval candidateState =
            BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva) := by
        simp only [BoundedImmutableCodePointerTableCallClaim.candidateTargetExpression,
          immutableCodePointerTableTargetExpression, Expr.eval,
          machineStateRead32_eq_memoryRead32, candidateAddressEvaluation]
        exact ImmutableImageWordMemory.read32_of_checked context.candidatePe
          candidateState.memory (claim.candidateAddress row.index)
          (context.candidatePe.imageBase + target.candidateRva) candidateImmutable
          candidateImageWord
      refine ⟨row, target,
        BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva),
        BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva),
        rowMember, targetResult, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · exact rowChecked row rowMember
      · rw [originalOutcome]
        simp [NormalizedOutcomeExpr.eval, originalTargetEvaluation]
      · rw [candidateOutcome]
        simp [NormalizedOutcomeExpr.eval, candidateTargetEvaluation]
      · simp [immutableCodePointerTableRowGuard,
          BoundedImmutableCodePointerTableCallClaim.originalIndexExpression,
          BoolExpr.eval, Expr.eval, originalIndexWord]
      · simp [immutableCodePointerTableRowGuard,
          BoundedImmutableCodePointerTableCallClaim.candidateIndexExpression,
          BoolExpr.eval, Expr.eval, candidateIndexWord]
      · simp [codeAddressMatches]
      · simp [codeAddressMatches]

/-
The bounded relocation-table jump profile shares the immutable table model
with the call profile, but keeps its own outcome and graph-edge certificate.
The submitted table inventory is only a compact witness: exact PE bytes,
HIGHLOW relocation counts, canonical targets, the source bound, and the
paired index expression are all recomputed below.
-/
structure BoundedImmutableRelocationTableJumpControlClaim where
  table : BoundedImmutableRelocationTableJumpClaim
  indexWitness : PairedExactExprWitness
  indexBound : RegisterBoundPair
deriving Repr, DecidableEq

/-- Total register-only expressions admitted as bounded table indices. -/
def tableJumpIndexInvariant : Expr → Bool
  | .inputReg _ | .constant _ => true
  | .add left right | .sub left right | .bitAnd left right | .bitXor left right |
      .shiftLeftBy left right | .shiftRightBy left right |
      .shiftArithmeticRightBy left right | .bitOr left right |
      .unsignedLessValue left right | .multiply left right =>
      tableJumpIndexInvariant left && tableJumpIndexInvariant right
  | .bitNot value | .extractByte value _ | .shiftLeft value _ | .shiftRight value _ |
      .bitValue value _ => tableJumpIndexInvariant value
  | _ => false

theorem evalExprPure_of_tableJumpIndexInvariant
    (state : MachineState) (expression : Expr)
    (safe : tableJumpIndexInvariant expression = true) :
    evalExprPure state.registers expression = some (expression.eval state) := by
  induction expression using Expr.rec (motive_2 := fun _ => True) <;>
    simp_all [tableJumpIndexInvariant, evalExprPure, Expr.eval]

def BoundedImmutableRelocationTableJumpControlClaim.relocationsChecked
    (context : StaticProofContext)
    (claim : BoundedImmutableRelocationTableJumpControlClaim) : Bool :=
  claim.table.originalBase >= context.originalPe.imageBase &&
    claim.table.candidateBase >= context.candidatePe.imageBase &&
    (List.range claim.table.upperExclusive).all fun index =>
      pe32RelocationWordAt context.originalRelocations
          (claim.table.originalBase + index * 4 - context.originalPe.imageBase) &&
        pe32RelocationWordAt context.candidateRelocations
          (claim.table.candidateBase + index * 4 - context.candidatePe.imageBase)

def BoundedImmutableRelocationTableJumpControlClaim.inputChecked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (claim : BoundedImmutableRelocationTableJumpControlClaim) : Bool :=
  sourceInvariant.bounds.contains claim.indexBound &&
    claim.indexBound.originalExpression == some claim.table.originalIndex &&
    claim.indexBound.candidateExpression == some claim.table.candidateIndex &&
    claim.indexBound.upperExclusive == claim.table.upperExclusive &&
    tableJumpIndexInvariant claim.table.originalIndex &&
    tableJumpIndexInvariant claim.table.candidateIndex &&
    claim.indexWitness.expression .original == claim.table.originalIndex &&
    claim.indexWitness.expression .candidate == claim.table.candidateIndex &&
    claim.indexWitness.checked context sourceInvariant

def BoundedImmutableRelocationTableJumpControlClaim.behaviorChecked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableRelocationTableJumpControlClaim) : Bool :=
  originalBehavior.outcome == .indirectJump
      (immutableCodePointerTableTargetExpression claim.table.originalBase
        claim.table.originalIndex) &&
    candidateBehavior.outcome == .indirectJump
      (immutableCodePointerTableTargetExpression claim.table.candidateBase
        claim.table.candidateIndex)

def BoundedImmutableRelocationTableJumpControlClaim.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableRelocationTableJumpControlClaim) : Bool :=
  claim.table.checked context.originalPe context.candidatePe
      context.codeMap.entries.toList context.dataMap.entries.toList &&
    decide (claim.table.upperExclusive < 2 ^ 32) &&
    claim.relocationsChecked context &&
    claim.inputChecked context sourceInvariant &&
    claim.behaviorChecked originalBehavior candidateBehavior

theorem codeTargetNatAddressMatches_word
    (candidate : Bool) (pe : PE32) (target : CodeTargetPair) (value : Nat)
    (checked : codeTargetNatAddressMatches candidate pe target value = true) :
    codeAddressMatches pe.imageBase
        (if candidate then target.candidateRva else target.originalRva)
        (if candidate then target.candidateAliases else target.originalAliases)
        (BitVec.ofNat 32 value) = true := by
  cases candidate <;>
    simp only [codeTargetNatAddressMatches, codeAddressMatches, if_false, if_true,
      Bool.or_eq_true, List.any_eq_true, beq_iff_eq] at checked ⊢
  · rcases checked with primary | ⟨alias, member, aliasAddress⟩
    · exact Or.inl (congrArg (BitVec.ofNat 32) primary)
    · exact Or.inr ⟨alias, member, congrArg (BitVec.ofNat 32) aliasAddress⟩
  · rcases checked with primary | ⟨alias, member, aliasAddress⟩
    · exact Or.inl (congrArg (BitVec.ofNat 32) primary)
    · exact Or.inr ⟨alias, member, congrArg (BitVec.ofNat 32) aliasAddress⟩

def BoundedImmutableRelocationTableJumpTargetsClosed
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableRelocationTableJumpControlClaim) : Prop :=
  context.StructurallyValid ∧
    ∀ world originalState candidateState,
      StateRel context world sourceInvariant originalState candidateState →
        ∃ targetId target originalTarget candidateTarget,
          targetId ∈ claim.table.finiteTargetIds ∧
            context.codeMap.entries.toList.find? (fun item => item.id == targetId) =
              some target ∧
            originalBehavior.outcome.eval originalState =
              .indirectJump originalTarget ∧
            candidateBehavior.outcome.eval candidateState =
              .indirectJump candidateTarget ∧
            (codeTargetProductGuard context.originalPe.imageBase
              (immutableCodePointerTableTargetExpression claim.table.originalBase
                claim.table.originalIndex)
              target.originalRva target.originalAliases).eval originalState = true ∧
            (codeTargetProductGuard context.candidatePe.imageBase
              (immutableCodePointerTableTargetExpression claim.table.candidateBase
                claim.table.candidateIndex)
              target.candidateRva target.candidateAliases).eval candidateState = true

theorem boundedImmutableRelocationTableJumpTargetsClosed_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableRelocationTableJumpControlClaim)
    (structurallyValid : context.StructurallyValid)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true) :
    BoundedImmutableRelocationTableJumpTargetsClosed context sourceInvariant
      originalBehavior candidateBehavior claim := by
  refine ⟨structurallyValid, ?_⟩
  simp only [BoundedImmutableRelocationTableJumpControlClaim.checked,
    Bool.and_eq_true, decide_eq_true_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨tableChecked, upperExclusiveSmall⟩, relocationsChecked⟩,
      inputChecked⟩, behaviorChecked⟩
  simp only [BoundedImmutableRelocationTableJumpControlClaim.inputChecked,
    Bool.and_eq_true, beq_iff_eq] at inputChecked
  rcases inputChecked with
    ⟨⟨⟨⟨⟨⟨⟨⟨boundMember, originalBoundExpression⟩,
      candidateBoundExpression⟩, boundUpperExclusive⟩, originalIndexSafe⟩,
      candidateIndexSafe⟩, originalWitnessExpression⟩,
      candidateWitnessExpression⟩, witnessChecked⟩
  simp only [BoundedImmutableRelocationTableJumpControlClaim.behaviorChecked,
    Bool.and_eq_true, beq_iff_eq] at behaviorChecked
  rcases behaviorChecked with ⟨originalOutcome, candidateOutcome⟩
  have entriesClosed :=
    boundedImmutableRelocationTableJumpEntriesClosed_of_checked
      context.originalPe context.candidatePe context.codeMap.entries.toList
      context.dataMap.entries.toList claim.table tableChecked
  intro world originalState candidateState related
  have indexEqual := claim.indexWitness.eval_equal_of_checked context world
    sourceInvariant originalState candidateState witnessChecked related
  rw [originalWitnessExpression, candidateWitnessExpression] at indexEqual
  have originalImmutable := StateRel.originalImmutableImageWordMemory
    context world sourceInvariant originalState candidateState related
  have candidateImmutable := StateRel.candidateImmutableImageWordMemory
    context world sourceInvariant originalState candidateState related
  rcases related with
    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable, _candidateImmutable,
      relatedCore, _importAndDynamicRegisters⟩
  have allBounds := relatedCore.2.1
  simp only [boundsRelated, List.all_eq_true] at allBounds
  have selectedBound := allBounds claim.indexBound
    (List.contains_iff_mem.mp boundMember)
  have originalBoundValue :
      boundValue originalState.registers claim.indexBound.original
          claim.indexBound.originalExpression =
        some (claim.table.originalIndex.eval originalState) := by
    rw [originalBoundExpression]
    simp only [boundValue]
    exact evalExprPure_of_tableJumpIndexInvariant originalState
      claim.table.originalIndex originalIndexSafe
  have candidateBoundValue :
      boundValue candidateState.registers claim.indexBound.candidate
          claim.indexBound.candidateExpression =
        some (claim.table.candidateIndex.eval candidateState) := by
    rw [candidateBoundExpression]
    simp only [boundValue]
    exact evalExprPure_of_tableJumpIndexInvariant candidateState
      claim.table.candidateIndex candidateIndexSafe
  rw [originalBoundValue, candidateBoundValue] at selectedBound
  rw [boundUpperExclusive] at selectedBound
  simp only [Bool.and_eq_true, decide_eq_true_eq] at selectedBound
  have originalIndexBound :
      (claim.table.originalIndex.eval originalState).toNat <
        claim.table.upperExclusive := by
    simpa [BitVec.lt_def, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt upperExclusiveSmall] using selectedBound.1
  let index := (claim.table.originalIndex.eval originalState).toNat
  have originalIndexWord : claim.table.originalIndex.eval originalState =
      BitVec.ofNat 32 index := by
    simp [index]
  have candidateIndexWord : claim.table.candidateIndex.eval candidateState =
      BitVec.ofNat 32 index := by
    rw [← indexEqual, originalIndexWord]
  have selectedEntry := entriesClosed index (by simpa [index] using originalIndexBound)
  unfold BoundedImmutableRelocationTableJumpClaim.entryValid at selectedEntry
  cases entryResult : claim.table.entryTargetIds[index]? with
  | none => simp [entryResult] at selectedEntry
  | some targetId =>
    cases targetResult : context.codeMap.entries.toList.find?
        (fun target => target.id == targetId) with
    | none => simp [entryResult, targetResult] at selectedEntry
    | some target =>
      simp only [entryResult, targetResult, Bool.and_eq_true] at selectedEntry
      rcases selectedEntry with
        ⟨⟨⟨finiteMember, originalEntryChecked⟩, candidateEntryChecked⟩,
          _offsetFits⟩
      unfold immutableCodeTargetEntryValid at originalEntryChecked
      unfold immutableCodeTargetEntryValid at candidateEntryChecked
      cases originalWordResult : readImmutableImageWord context.originalPe
          (claim.table.originalBase + index * 4) 4 with
      | none => simp [originalWordResult] at originalEntryChecked
      | some originalWord =>
        cases candidateWordResult : readImmutableImageWord context.candidatePe
            (claim.table.candidateBase + index * 4) 4 with
        | none => simp [candidateWordResult] at candidateEntryChecked
        | some candidateWord =>
          simp only [originalWordResult] at originalEntryChecked
          simp only [candidateWordResult] at candidateEntryChecked
          have originalAddressEvaluation :
              (immutableCodePointerTableAddressExpression claim.table.originalBase
                claim.table.originalIndex).eval originalState =
                  BitVec.ofNat 32 (claim.table.originalBase + index * 4) :=
            immutableCodePointerTableAddressExpression_eval_of_index
              claim.table.originalBase index claim.table.originalIndex originalState
              originalIndexWord
          have candidateAddressEvaluation :
              (immutableCodePointerTableAddressExpression claim.table.candidateBase
                claim.table.candidateIndex).eval candidateState =
                  BitVec.ofNat 32 (claim.table.candidateBase + index * 4) :=
            immutableCodePointerTableAddressExpression_eval_of_index
              claim.table.candidateBase index claim.table.candidateIndex candidateState
              candidateIndexWord
          have originalRead := ImmutableImageWordMemory.read32_of_checked
            context.originalPe originalState.memory
            (claim.table.originalBase + index * 4) originalWord originalImmutable
            originalWordResult
          have candidateRead := ImmutableImageWordMemory.read32_of_checked
            context.candidatePe candidateState.memory
            (claim.table.candidateBase + index * 4) candidateWord candidateImmutable
            candidateWordResult
          have originalTargetEvaluation :
              (immutableCodePointerTableTargetExpression claim.table.originalBase
                claim.table.originalIndex).eval originalState =
                BitVec.ofNat 32 originalWord := by
            simp only [immutableCodePointerTableTargetExpression, Expr.eval,
              machineStateRead32_eq_memoryRead32, originalAddressEvaluation]
            exact originalRead
          have candidateTargetEvaluation :
              (immutableCodePointerTableTargetExpression claim.table.candidateBase
                claim.table.candidateIndex).eval candidateState =
                BitVec.ofNat 32 candidateWord := by
            simp only [immutableCodePointerTableTargetExpression, Expr.eval,
              machineStateRead32_eq_memoryRead32, candidateAddressEvaluation]
            exact candidateRead
          have originalAddressMatches := codeTargetNatAddressMatches_word false
            context.originalPe target originalWord originalEntryChecked
          have candidateAddressMatches := codeTargetNatAddressMatches_word true
            context.candidatePe target candidateWord candidateEntryChecked
          refine ⟨targetId, target, BitVec.ofNat 32 originalWord,
            BitVec.ofNat 32 candidateWord, List.contains_iff_mem.mp finiteMember,
            targetResult, ?_, ?_, ?_, ?_⟩
          · rw [originalOutcome]
            simp [NormalizedOutcomeExpr.eval, originalTargetEvaluation]
          · rw [candidateOutcome]
            simp [NormalizedOutcomeExpr.eval, candidateTargetEvaluation]
          · rw [codeTargetProductGuard_eval_true, originalTargetEvaluation]
            simpa using originalAddressMatches
          · rw [codeTargetProductGuard_eval_true, candidateTargetEvaluation]
            simpa using candidateAddressMatches

/-
The reverse-sentinel scanner profile is the producer half of the bounded table
call profile above.  It checks one ordinary no-write block: copy the current
zero-based count, advance the cursor, load the next immutable table word, set
ZF from that word, and jump to a separate test block.  The resulting predicate
is deliberately compact; subsequent ordinary branch edges consume either its
nonzero/bounded arm or its zero/finished arm.
-/
structure ReverseSentinelScannerClaim where
  table : BoundedImmutableCodePointerTableCallClaim
  originalScannerRegister : Reg
  candidateScannerRegister : Reg
  originalCountRegister : Reg
  candidateCountRegister : Reg
  originalLoadedRegister : Reg
  candidateLoadedRegister : Reg
  testTargetId : Nat
  scannerTargetId : Nat
  bridgeTargetId : Nat
  zeroFlagBit : Nat := 6
deriving Repr, DecidableEq

def ReverseSentinelScannerClaim.sourceBound
    (claim : ReverseSentinelScannerClaim) : RegisterBoundPair := {
  original := claim.originalScannerRegister
  candidate := claim.candidateScannerRegister
  upperExclusive := claim.table.upperExclusive
}

def ReverseSentinelScannerClaim.originalNextIndex
    (claim : ReverseSentinelScannerClaim) : Expr :=
  .add (.inputReg claim.originalScannerRegister) (.constant 1)

def ReverseSentinelScannerClaim.candidateNextIndex
    (claim : ReverseSentinelScannerClaim) : Expr :=
  .add (.inputReg claim.candidateScannerRegister) (.constant 1)

def ReverseSentinelScannerClaim.originalLoadedExpression
    (claim : ReverseSentinelScannerClaim) : Expr :=
  immutableCodePointerTableTargetExpression claim.table.originalBase
    claim.originalNextIndex

def ReverseSentinelScannerClaim.candidateLoadedExpression
    (claim : ReverseSentinelScannerClaim) : Expr :=
  immutableCodePointerTableTargetExpression claim.table.candidateBase
    claim.candidateNextIndex

def reverseSentinelScannerPostExpression (scanner count : Reg)
    (upperExclusive entryCount zeroFlagBit : Nat) : BoolExpr :=
  .and
    (.equal (.add (.inputReg count) (.constant 1)) (.inputReg scanner))
    (.and
      (.not (.xor (.inputFlag zeroFlagBit)
        (.equal (.inputReg count) (.constant entryCount))))
      (.or
        (.and (.not (.inputFlag zeroFlagBit))
          (.unsignedLess (.inputReg scanner) (.constant upperExclusive)))
        (.and (.inputFlag zeroFlagBit)
          (.equal (.inputReg count) (.constant entryCount)))))

def ReverseSentinelScannerClaim.postPredicate
    (claim : ReverseSentinelScannerClaim) : PairedStatePredicate := {
  original := reverseSentinelScannerPostExpression
    claim.originalScannerRegister claim.originalCountRegister
    claim.table.upperExclusive claim.table.entryCount claim.zeroFlagBit
  candidate := reverseSentinelScannerPostExpression
    claim.candidateScannerRegister claim.candidateCountRegister
    claim.table.upperExclusive claim.table.entryCount claim.zeroFlagBit
}

def ReverseSentinelScannerClaim.loopGuard
    (claim : ReverseSentinelScannerClaim) : BoolExpr :=
  .not (.inputFlag claim.zeroFlagBit)

def ReverseSentinelScannerClaim.exitGuard
    (claim : ReverseSentinelScannerClaim) : BoolExpr :=
  .not claim.loopGuard

def ReverseSentinelScannerClaim.finishedPredicate
    (claim : ReverseSentinelScannerClaim) : PairedStatePredicate := {
  original := .equal (.inputReg claim.originalCountRegister)
    (.constant claim.table.entryCount)
  candidate := .equal (.inputReg claim.candidateCountRegister)
    (.constant claim.table.entryCount)
}

def normalizedFlagPreservesInput (bit : Nat) : Option BoolExpr -> Bool
  | none => true
  | some expression => expression == .inputFlag bit

def normalizedFlagsPreserveInputs : Option FlagsExpr -> Bool
  | none => true
  | some flags =>
      normalizedFlagPreservesInput 0 flags.carry &&
        normalizedFlagPreservesInput 2 flags.parity &&
        normalizedFlagPreservesInput 4 flags.auxiliary &&
        normalizedFlagPreservesInput 6 flags.zero &&
        normalizedFlagPreservesInput 7 flags.sign &&
        normalizedFlagPreservesInput 11 flags.overflow

def flagsZeroTestExpression (flags : Option FlagsExpr) (value : Expr) : Bool :=
  match flags with
  | some result =>
      result.zero == some (.equal value (.constant 0)) ||
        result.zero == some (.equal (.bitAnd value value) (.constant 0))
  | none => false

theorem bitAndSelfZeroTest_eval (state : MachineState) (value : Expr) :
    (BoolExpr.equal (.bitAnd value value) (.constant 0)).eval state =
      (BoolExpr.equal value (.constant 0)).eval state := by
  have bitAndSelf (word : Word) : word &&& word = word := by
    bv_decide
  simp [BoolExpr.eval, Expr.eval, bitAndSelf]

theorem inputFlagSix_after_normalizedBehavior_eq_zeroExpression
    (state : MachineState) (behavior : NormalizedSymbolicBehavior)
    (flags : FlagsExpr) (zeroExpression : BoolExpr)
    (flagsResult : behavior.flags = some flags)
    (checked : flags.zero = some zeroExpression) :
    (BoolExpr.inputFlag 6).eval
        ((behavior.eval state).nextMachineState state) =
      zeroExpression.eval state := by
  simp only [BoolExpr.eval, RelationalBehavior.nextMachineState,
    NormalizedSymbolicBehavior.eval_x87Effect,
    NormalizedSymbolicBehavior.eval_eflags, flagsResult,
    evalNormalizedFlags_some, FlagsExpr.eval_extract_zf, checked, evalFlagBit]
  cases evaluated : zeroExpression.eval state <;> simp [evaluated]

theorem inputFlagSix_after_normalizedBehavior_eq_zeroTest
    (state : MachineState) (behavior : NormalizedSymbolicBehavior) (value : Expr)
    (checked : flagsZeroTestExpression behavior.flags value = true) :
    (BoolExpr.inputFlag 6).eval
        ((behavior.eval state).nextMachineState state) =
      (BoolExpr.equal value (.constant 0)).eval state := by
  cases flagsResult : behavior.flags with
  | none => simp [flagsZeroTestExpression, flagsResult] at checked
  | some flags =>
      simp only [flagsZeroTestExpression, flagsResult, Bool.or_eq_true,
        beq_iff_eq] at checked
      rcases checked with checked | checked
      · exact inputFlagSix_after_normalizedBehavior_eq_zeroExpression state behavior flags
          (.equal value (.constant 0)) flagsResult checked
      · calc
          (BoolExpr.inputFlag 6).eval
                ((behavior.eval state).nextMachineState state) =
              (BoolExpr.equal (.bitAnd value value) (.constant 0)).eval state :=
            inputFlagSix_after_normalizedBehavior_eq_zeroExpression state behavior flags
              (.equal (.bitAnd value value) (.constant 0)) flagsResult checked
          _ = (BoolExpr.equal value (.constant 0)).eval state :=
            bitAndSelfZeroTest_eval state value

def ReverseSentinelScannerClaim.behaviorChecked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim) : Bool :=
  originalBehavior.registers.get claim.originalCountRegister ==
      .inputReg claim.originalScannerRegister &&
    candidateBehavior.registers.get claim.candidateCountRegister ==
      .inputReg claim.candidateScannerRegister &&
    originalBehavior.registers.get claim.originalScannerRegister ==
      claim.originalNextIndex &&
    candidateBehavior.registers.get claim.candidateScannerRegister ==
      claim.candidateNextIndex &&
    originalBehavior.registers.get claim.originalLoadedRegister ==
      claim.originalLoadedExpression &&
    candidateBehavior.registers.get claim.candidateLoadedRegister ==
      claim.candidateLoadedExpression &&
    originalBehavior.writes.isEmpty &&
    candidateBehavior.writes.isEmpty &&
    flagsZeroTestExpression originalBehavior.flags claim.originalLoadedExpression &&
    flagsZeroTestExpression candidateBehavior.flags claim.candidateLoadedExpression &&
    originalBehavior.outcome == .jump claim.testTargetId &&
    candidateBehavior.outcome == .jump claim.testTargetId

def ReverseSentinelScannerClaim.testBehaviorChecked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim) : Bool :=
  originalBehavior.registers.get claim.originalScannerRegister ==
      .inputReg claim.originalScannerRegister &&
    candidateBehavior.registers.get claim.candidateScannerRegister ==
      .inputReg claim.candidateScannerRegister &&
    originalBehavior.registers.get claim.originalCountRegister ==
      .inputReg claim.originalCountRegister &&
    candidateBehavior.registers.get claim.candidateCountRegister ==
      .inputReg claim.candidateCountRegister &&
    originalBehavior.writes.isEmpty &&
    candidateBehavior.writes.isEmpty &&
    normalizedFlagsPreserveInputs originalBehavior.flags &&
    normalizedFlagsPreserveInputs candidateBehavior.flags &&
    originalBehavior.outcome == .branch claim.loopGuard claim.scannerTargetId
      claim.bridgeTargetId &&
    candidateBehavior.outcome == .branch claim.loopGuard claim.scannerTargetId
      claim.bridgeTargetId

def ReverseSentinelScannerClaim.loopChecked (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim) : Bool :=
  sourceInvariant.predicates == [claim.postPredicate] &&
    exactRegisterPair sourceInvariant.registerRelations
      claim.originalScannerRegister claim.candidateScannerRegister &&
    targetInvariant.bounds == [claim.sourceBound] &&
    claim.zeroFlagBit == 6 &&
    claim.testBehaviorChecked originalBehavior candidateBehavior

def ReverseSentinelScannerClaim.exitChecked (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim) : Bool :=
  sourceInvariant.predicates == [claim.postPredicate] &&
    exactRegisterPair sourceInvariant.registerRelations
      claim.originalCountRegister claim.candidateCountRegister &&
    targetInvariant.predicates == [claim.finishedPredicate] &&
    claim.zeroFlagBit == 6 &&
    claim.testBehaviorChecked originalBehavior candidateBehavior

def ReverseSentinelScannerClaim.guardChecked (sourceInvariant : StateInvariant)
    (originalGuard candidateGuard : BoolExpr)
    (claim : ReverseSentinelScannerClaim) : Bool :=
  sourceInvariant.predicates == [claim.postPredicate] &&
    exactRegisterPair sourceInvariant.registerRelations
      claim.originalCountRegister claim.candidateCountRegister &&
    ((originalGuard == claim.loopGuard && candidateGuard == claim.loopGuard) ||
      (originalGuard == claim.exitGuard && candidateGuard == claim.exitGuard))

def ReverseSentinelScannerClaim.checked (context : StaticProofContext)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim) : Bool :=
  claim.table.layout == .sentinelTerminatedReverseCount &&
    claim.table.staticShapeChecked context &&
    claim.table.rowsChecked context &&
    exactRegisterPair sourceInvariant.registerRelations
      claim.originalScannerRegister claim.candidateScannerRegister &&
    sourceInvariant.bounds.contains claim.sourceBound &&
    targetInvariant.predicates == [claim.postPredicate] &&
    claim.zeroFlagBit == 6 &&
    claim.behaviorChecked originalBehavior candidateBehavior

def ReverseSentinelScannerPostconditionClosed (context : StaticProofContext)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim) : Prop :=
  ∀ world originalState candidateState,
    StateRel context world sourceInvariant originalState candidateState →
      pairedStatePredicatesHold targetInvariant.predicates
        ((originalBehavior.eval originalState).nextMachineState originalState)
        ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true

theorem reverseSentinelScannerLoadedContract_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (claim : ReverseSentinelScannerClaim)
    (layoutChecked : claim.table.layout = .sentinelTerminatedReverseCount)
    (staticShapeChecked : claim.table.staticShapeChecked context = true)
    (rowsChecked : claim.table.rowsChecked context = true)
    (exactScanners : exactRegisterPair sourceInvariant.registerRelations
      claim.originalScannerRegister claim.candidateScannerRegister = true)
    (boundMember : sourceInvariant.bounds.contains claim.sourceBound = true)
    (world : RelationalWorld) (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        (claim.originalLoadedExpression.eval originalState)
        (claim.candidateLoadedExpression.eval candidateState) = true ∧
      (claim.originalLoadedExpression.eval originalState = BitVec.ofNat 32 0 ↔
      (originalState.registers.get claim.originalScannerRegister).toNat =
        claim.table.entryCount) ∧
    (claim.candidateLoadedExpression.eval candidateState = BitVec.ofNat 32 0 ↔
      (candidateState.registers.get claim.candidateScannerRegister).toNat =
        claim.table.entryCount) := by
  simp only [BoundedImmutableCodePointerTableCallClaim.staticShapeChecked,
    Bool.and_eq_true] at staticShapeChecked
  rcases staticShapeChecked with
    ⟨⟨⟨⟨rowsCover, upperExclusiveChecked⟩, upperExclusivePositive⟩,
      boundaryChecked⟩, tableShapeChecked⟩
  have upperExclusiveSmall : claim.table.upperExclusive < 2 ^ 32 :=
    of_decide_eq_true upperExclusiveChecked
  have upperExclusivePositiveNat : 0 < claim.table.upperExclusive :=
    of_decide_eq_true upperExclusivePositive
  rcases related with
    ⟨worldValid, stackRangesValid, stackMemory, importsStatic, importsComplete,
      importsMemory, originalImmutable, candidateImmutable, relatedCore,
      importAndDynamicRegisters⟩
  have allBounds := relatedCore.2.1
  simp only [boundsRelated, List.all_eq_true] at allBounds
  have selectedBound := allBounds claim.sourceBound
    (List.contains_iff_mem.mp boundMember)
  simp only [ReverseSentinelScannerClaim.sourceBound, boundValue,
    Bool.and_eq_true] at selectedBound
  have originalBoundWord := of_decide_eq_true selectedBound.1
  have candidateBoundWord := of_decide_eq_true selectedBound.2
  have originalCursorBound :
      (originalState.registers.get claim.originalScannerRegister).toNat <
        claim.table.upperExclusive := by
    simpa [BitVec.lt_def, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt upperExclusiveSmall] using originalBoundWord
  have candidateCursorBound :
      (candidateState.registers.get claim.candidateScannerRegister).toNat <
        claim.table.upperExclusive := by
    simpa [BitVec.lt_def, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt upperExclusiveSmall] using candidateBoundWord
  have cursorEqual := registerRelationsHold_exact_pair
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    sourceInvariant.registerRelations originalState.registers candidateState.registers
    claim.originalScannerRegister claim.candidateScannerRegister relatedCore.1 exactScanners
  have cursorNatEqual :
      (originalState.registers.get claim.originalScannerRegister).toNat =
        (candidateState.registers.get claim.candidateScannerRegister).toNat := by
    exact congrArg BitVec.toNat cursorEqual
  have entryCountIdentity :
      claim.table.entryCount = claim.table.upperExclusive - 1 := by
    simp [BoundedImmutableCodePointerTableCallClaim.entryCount,
      BoundedImmutableCodePointerTableCallClaim.lowerInclusive, layoutChecked,
      ImmutableCodePointerTableLayout.lowerInclusive]
  have entryCountFits : claim.table.entryCount < 2 ^ 32 := by omega
  have entryIncrementWord :
      BitVec.ofNat 32 claim.table.entryCount + BitVec.ofNat 32 1 =
        BitVec.ofNat 32 (claim.table.entryCount + 1) := by
    rw [← BitVec.ofNat_add]
  have originalCursorWord :
      originalState.registers.get claim.originalScannerRegister =
        BitVec.ofNat 32
          (originalState.registers.get claim.originalScannerRegister).toNat := by
    simp
  have candidateCursorWord :
      candidateState.registers.get claim.candidateScannerRegister =
        BitVec.ofNat 32
          (candidateState.registers.get claim.candidateScannerRegister).toNat := by
    simp
  have originalNextIndexEvaluation :
      claim.originalNextIndex.eval originalState =
        BitVec.ofNat 32
          ((originalState.registers.get claim.originalScannerRegister).toNat + 1) := by
    simp only [ReverseSentinelScannerClaim.originalNextIndex, Expr.eval]
    calc
      originalState.registers.get claim.originalScannerRegister + BitVec.ofNat 32 1 =
          BitVec.ofNat 32
              (originalState.registers.get claim.originalScannerRegister).toNat +
            BitVec.ofNat 32 1 :=
        congrArg (fun value => value + BitVec.ofNat 32 1) originalCursorWord
      _ = BitVec.ofNat 32
          ((originalState.registers.get claim.originalScannerRegister).toNat + 1) := by
        rw [← BitVec.ofNat_add]
  have candidateNextIndexEvaluation :
      claim.candidateNextIndex.eval candidateState =
        BitVec.ofNat 32
          ((candidateState.registers.get claim.candidateScannerRegister).toNat + 1) := by
    simp only [ReverseSentinelScannerClaim.candidateNextIndex, Expr.eval]
    calc
      candidateState.registers.get claim.candidateScannerRegister + BitVec.ofNat 32 1 =
          BitVec.ofNat 32
              (candidateState.registers.get claim.candidateScannerRegister).toNat +
            BitVec.ofNat 32 1 :=
        congrArg (fun value => value + BitVec.ofNat 32 1) candidateCursorWord
      _ = BitVec.ofNat 32
          ((candidateState.registers.get claim.candidateScannerRegister).toNat + 1) := by
        rw [← BitVec.ofNat_add]
  by_cases interior :
      (originalState.registers.get claim.originalScannerRegister).toNat <
        claim.table.entryCount
  · simp only [immutableCodePointerTableRowsCover, List.all_eq_true] at rowsCover
    have selectedRow := rowsCover
      (originalState.registers.get claim.originalScannerRegister).toNat
      (List.mem_range.mpr interior)
    simp only [List.any_eq_true] at selectedRow
    rcases selectedRow with ⟨row, rowMember, rowIndexChecked⟩
    have rowIndex : row.index =
        (originalState.registers.get claim.originalScannerRegister).toNat + 1 := by
      have rowIndexNat := beq_iff_eq.mp rowIndexChecked
      simp [BoundedImmutableCodePointerTableCallClaim.lowerInclusive,
        layoutChecked, ImmutableCodePointerTableLayout.lowerInclusive] at rowIndexNat
      omega
    simp only [BoundedImmutableCodePointerTableCallClaim.rowsChecked,
      List.all_eq_true] at rowsChecked
    have rowReads := immutableCodePointerTableRowReadsNonzero_of_checked
      context claim.table row originalState.memory candidateState.memory
      originalImmutable candidateImmutable (rowsChecked row rowMember)
    rcases rowReads with
      ⟨target, targetResult, originalRead, candidateRead, originalNonzero,
        candidateNonzero, originalFits, candidateFits⟩
    have originalAddressEvaluation :=
      immutableCodePointerTableAddressExpression_eval_of_index
        claim.table.originalBase
        ((originalState.registers.get claim.originalScannerRegister).toNat + 1)
        claim.originalNextIndex originalState originalNextIndexEvaluation
    have candidateAddressEvaluation :=
      immutableCodePointerTableAddressExpression_eval_of_index
        claim.table.candidateBase
        ((candidateState.registers.get claim.candidateScannerRegister).toNat + 1)
        claim.candidateNextIndex candidateState candidateNextIndexEvaluation
    have originalLoaded : claim.originalLoadedExpression.eval originalState =
        BitVec.ofNat 32
          (context.originalPe.imageBase + target.originalRva) := by
      simp only [ReverseSentinelScannerClaim.originalLoadedExpression,
        immutableCodePointerTableTargetExpression, Expr.eval,
        machineStateRead32_eq_memoryRead32, originalAddressEvaluation]
      rw [← rowIndex]
      exact originalRead
    have candidateRowIndex : row.index =
        (candidateState.registers.get claim.candidateScannerRegister).toNat + 1 := by
      omega
    have candidateLoaded : claim.candidateLoadedExpression.eval candidateState =
        BitVec.ofNat 32
          (context.candidatePe.imageBase + target.candidateRva) := by
      simp only [ReverseSentinelScannerClaim.candidateLoadedExpression,
        immutableCodePointerTableTargetExpression, Expr.eval,
        machineStateRead32_eq_memoryRead32, candidateAddressEvaluation]
      rw [← candidateRowIndex]
      exact candidateRead
    have originalWordNonzero :
        BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva) ≠
          BitVec.ofNat 32 0 := by
      intro zero
      have naturalZero := congrArg BitVec.toNat zero
      simp only [BitVec.toNat_ofNat] at naturalZero
      rw [Nat.mod_eq_of_lt originalFits] at naturalZero
      have zeroNat : context.originalPe.imageBase + target.originalRva = 0 := by
        simpa only [Nat.zero_mod] using naturalZero
      exact originalNonzero zeroNat
    have candidateWordNonzero :
        BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva) ≠
          BitVec.ofNat 32 0 := by
      intro zero
      have naturalZero := congrArg BitVec.toNat zero
      simp only [BitVec.toNat_ofNat] at naturalZero
      rw [Nat.mod_eq_of_lt candidateFits] at naturalZero
      have zeroNat : context.candidatePe.imageBase + target.candidateRva = 0 := by
        simpa only [Nat.zero_mod] using naturalZero
      exact candidateNonzero zeroNat
    have originalZeroCheck :
        (BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva) ==
          BitVec.ofNat 32 0) = false :=
      beq_eq_false_iff_ne.mpr originalWordNonzero
    have candidateZeroCheck :
        (BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva) ==
          BitVec.ofNat 32 0) = false :=
      beq_eq_false_iff_ne.mpr candidateWordNonzero
    refine ⟨?_, ?_, ?_⟩
    · rw [originalLoaded, candidateLoaded]
      exact codeTargetAddresses_wordRelated context world row.targetId target
        (BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva))
        (BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva))
        targetResult (by simp [codeAddressMatches]) (by simp [codeAddressMatches])
        (by rw [originalZeroCheck, candidateZeroCheck])
    · constructor
      · intro zero
        exact (originalWordNonzero (originalLoaded.symm.trans zero)).elim
      · intro atTerminator
        omega
    · constructor
      · intro zero
        exact (candidateWordNonzero (candidateLoaded.symm.trans zero)).elim
      · intro atTerminator
        omega
  · have originalAtTerminator :
        (originalState.registers.get claim.originalScannerRegister).toNat =
          claim.table.entryCount := by
      omega
    have candidateAtTerminator :
        (candidateState.registers.get claim.candidateScannerRegister).toNat =
          claim.table.entryCount := by
      omega
    simp only [BoundedImmutableCodePointerTableCallClaim.boundaryChecked,
      layoutChecked, Bool.and_eq_true] at boundaryChecked
    have originalTerminator := beq_iff_eq.mp boundaryChecked.1.1.1.1.1.2
    have candidateTerminator := beq_iff_eq.mp boundaryChecked.1.1.1.1.2
    have originalAddressEvaluation :=
      immutableCodePointerTableAddressExpression_eval_of_index
        claim.table.originalBase claim.table.upperExclusive
        claim.originalNextIndex originalState (originalNextIndexEvaluation.trans (by
          congr 1
          omega))
    have candidateAddressEvaluation :=
      immutableCodePointerTableAddressExpression_eval_of_index
        claim.table.candidateBase claim.table.upperExclusive
        claim.candidateNextIndex candidateState (candidateNextIndexEvaluation.trans (by
          congr 1
          omega))
    have originalRead := ImmutableImageWordMemory.read32_of_checked
      context.originalPe originalState.memory
      (claim.table.originalAddress claim.table.upperExclusive) 0
      originalImmutable originalTerminator
    have candidateRead := ImmutableImageWordMemory.read32_of_checked
      context.candidatePe candidateState.memory
      (claim.table.candidateAddress claim.table.upperExclusive) 0
      candidateImmutable candidateTerminator
    have originalLoaded : claim.originalLoadedExpression.eval originalState =
        BitVec.ofNat 32 0 := by
      simp only [ReverseSentinelScannerClaim.originalLoadedExpression,
        immutableCodePointerTableTargetExpression, Expr.eval,
        machineStateRead32_eq_memoryRead32, originalAddressEvaluation]
      exact originalRead
    have candidateLoaded : claim.candidateLoadedExpression.eval candidateState =
        BitVec.ofNat 32 0 := by
      simp only [ReverseSentinelScannerClaim.candidateLoadedExpression,
        immutableCodePointerTableTargetExpression, Expr.eval,
        machineStateRead32_eq_memoryRead32, candidateAddressEvaluation]
      exact candidateRead
    refine ⟨?_, ⟨fun _ => originalAtTerminator, fun _ => originalLoaded⟩,
      ⟨fun _ => candidateAtTerminator, fun _ => candidateLoaded⟩⟩
    rw [originalLoaded, candidateLoaded]
    exact wordRelated_self context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (BitVec.ofNat 32 0)

theorem reverseSentinelScannerLoadedZeroExactlyAtTerminator_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (claim : ReverseSentinelScannerClaim)
    (layoutChecked : claim.table.layout = .sentinelTerminatedReverseCount)
    (staticShapeChecked : claim.table.staticShapeChecked context = true)
    (rowsChecked : claim.table.rowsChecked context = true)
    (exactScanners : exactRegisterPair sourceInvariant.registerRelations
      claim.originalScannerRegister claim.candidateScannerRegister = true)
    (boundMember : sourceInvariant.bounds.contains claim.sourceBound = true)
    (world : RelationalWorld) (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    (claim.originalLoadedExpression.eval originalState = BitVec.ofNat 32 0 ↔
      (originalState.registers.get claim.originalScannerRegister).toNat =
        claim.table.entryCount) ∧
    (claim.candidateLoadedExpression.eval candidateState = BitVec.ofNat 32 0 ↔
      (candidateState.registers.get claim.candidateScannerRegister).toNat =
        claim.table.entryCount) :=
  (reverseSentinelScannerLoadedContract_of_checked context sourceInvariant claim
    layoutChecked staticShapeChecked rowsChecked exactScanners boundMember world
    originalState candidateState related).2

theorem reverseSentinelScannerLoadedOutputRelated_of_checked
    (context : StaticProofContext) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim)
    (checked : claim.checked context sourceInvariant targetInvariant originalBehavior
      candidateBehavior = true)
    (world : RelationalWorld) (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    RegisterValueRelation.holds context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) .relatedWord
      ((originalBehavior.eval originalState).registers.get claim.originalLoadedRegister)
      ((candidateBehavior.eval candidateState).registers.get claim.candidateLoadedRegister) =
        true := by
  simp only [ReverseSentinelScannerClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨layoutChecked, staticShapeChecked⟩, rowsChecked⟩,
      exactScanners⟩, boundMember⟩, _targetPredicates⟩, _zeroFlagBit⟩,
      behaviorChecked⟩
  simp only [ReverseSentinelScannerClaim.behaviorChecked, Bool.and_eq_true,
    beq_iff_eq] at behaviorChecked
  rcases behaviorChecked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨_originalCountOutput,
      _candidateCountOutput⟩, _originalScannerOutput⟩, _candidateScannerOutput⟩,
      originalLoadedOutput⟩, candidateLoadedOutput⟩, _originalWritesEmpty⟩,
      _candidateWritesEmpty⟩, _originalZeroFlag⟩, _candidateZeroFlag⟩,
      _originalOutcome⟩, _candidateOutcome⟩
  have loadedRelated :=
    (reverseSentinelScannerLoadedContract_of_checked context sourceInvariant claim
      layoutChecked staticShapeChecked rowsChecked exactScanners boundMember world
      originalState candidateState related).1
  simp only [RegisterValueRelation.holds, NormalizedSymbolicBehavior.eval,
    evalNormalizedRegisters_get]
  rw [originalLoadedOutput, candidateLoadedOutput]
  exact loadedRelated

theorem reverseSentinelScannerZeroFlagRelated_of_checked
    (context : StaticProofContext) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim)
    (checked : claim.checked context sourceInvariant targetInvariant originalBehavior
      candidateBehavior = true)
    (world : RelationalWorld) (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    (evalNormalizedFlags originalState originalBehavior.flags).extractLsb' 6 1 =
      (evalNormalizedFlags candidateState candidateBehavior.flags).extractLsb' 6 1 := by
  simp only [ReverseSentinelScannerClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨layoutChecked, staticShapeChecked⟩, rowsChecked⟩,
      exactScanners⟩, boundMember⟩, _targetPredicates⟩, _zeroFlagBit⟩,
      behaviorChecked⟩
  simp only [ReverseSentinelScannerClaim.behaviorChecked, Bool.and_eq_true,
    beq_iff_eq] at behaviorChecked
  rcases behaviorChecked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨_originalCountOutput,
      _candidateCountOutput⟩, _originalScannerOutput⟩, _candidateScannerOutput⟩,
      _originalLoadedOutput⟩, _candidateLoadedOutput⟩, _originalWritesEmpty⟩,
      _candidateWritesEmpty⟩, originalZeroFlag⟩, candidateZeroFlag⟩,
      _originalOutcome⟩, _candidateOutcome⟩
  have loadedRelated :=
    (reverseSentinelScannerLoadedContract_of_checked context sourceInvariant claim
      layoutChecked staticShapeChecked rowsChecked exactScanners boundMember world
      originalState candidateState related).1
  have zeroesAgree := wordRelated_zero_equal loadedRelated
  have testsAgree :
      (BoolExpr.equal claim.originalLoadedExpression (.constant 0)).eval
          originalState =
        (BoolExpr.equal claim.candidateLoadedExpression (.constant 0)).eval
          candidateState := by
    change
      (claim.originalLoadedExpression.eval originalState == BitVec.ofNat 32 0) =
        (claim.candidateLoadedExpression.eval candidateState == BitVec.ofNat 32 0)
    exact zeroesAgree
  cases originalFlagsResult : originalBehavior.flags with
  | none => simp [flagsZeroTestExpression, originalFlagsResult] at originalZeroFlag
  | some originalFlags =>
      cases candidateFlagsResult : candidateBehavior.flags with
      | none => simp [flagsZeroTestExpression, candidateFlagsResult] at candidateZeroFlag
      | some candidateFlags =>
          simp only [flagsZeroTestExpression, originalFlagsResult,
            Bool.or_eq_true, beq_iff_eq] at originalZeroFlag
          simp only [flagsZeroTestExpression, candidateFlagsResult,
            Bool.or_eq_true, beq_iff_eq] at candidateZeroFlag
          rcases originalZeroFlag with originalZeroFlag | originalZeroFlag <;>
            rcases candidateZeroFlag with candidateZeroFlag | candidateZeroFlag <;>
            simp only [originalFlagsResult, candidateFlagsResult,
              evalNormalizedFlags_some, FlagsExpr.eval_extract_zf,
              originalZeroFlag, candidateZeroFlag, evalFlagBit,
              bitAndSelfZeroTest_eval] <;>
            rw [testsAgree]

theorem reverseSentinelScannerPostconditionClosed_of_checked
    (context : StaticProofContext) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim)
    (checked : claim.checked context sourceInvariant targetInvariant originalBehavior
      candidateBehavior = true) :
    ReverseSentinelScannerPostconditionClosed context sourceInvariant targetInvariant
      originalBehavior candidateBehavior claim := by
  simp only [ReverseSentinelScannerClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨layoutChecked, staticShapeChecked⟩, rowsChecked⟩,
      exactScanners⟩, boundMember⟩, targetPredicates⟩, zeroFlagBit⟩,
      behaviorChecked⟩
  simp only [ReverseSentinelScannerClaim.behaviorChecked, Bool.and_eq_true,
    beq_iff_eq] at behaviorChecked
  rcases behaviorChecked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨originalCountOutput,
      candidateCountOutput⟩, originalScannerOutput⟩, candidateScannerOutput⟩,
      originalLoadedOutput⟩, candidateLoadedOutput⟩, originalWritesEmpty⟩,
      candidateWritesEmpty⟩, originalZeroFlag⟩, candidateZeroFlag⟩,
      originalOutcome⟩, candidateOutcome⟩
  unfold ReverseSentinelScannerPostconditionClosed
  intro world originalState candidateState related
  have loadedZero :=
    reverseSentinelScannerLoadedZeroExactlyAtTerminator_of_checked
      context sourceInvariant claim layoutChecked staticShapeChecked rowsChecked
      exactScanners boundMember world originalState candidateState related
  have relatedForBounds := related
  rcases relatedForBounds with
    ⟨worldValid, stackRangesValid, stackMemory, importsStatic, importsComplete,
      importsMemory, originalImmutable, candidateImmutable, relatedCore,
      importAndDynamicRegisters⟩
  simp only [BoundedImmutableCodePointerTableCallClaim.staticShapeChecked,
    Bool.and_eq_true] at staticShapeChecked
  have upperExclusiveChecked := staticShapeChecked.1.1.1.2
  have upperExclusivePositive := staticShapeChecked.1.1.2
  have upperExclusiveSmall : claim.table.upperExclusive < 2 ^ 32 :=
    of_decide_eq_true upperExclusiveChecked
  have upperExclusivePositiveNat : 0 < claim.table.upperExclusive :=
    of_decide_eq_true upperExclusivePositive
  have allBounds := relatedCore.2.1
  simp only [boundsRelated, List.all_eq_true] at allBounds
  have selectedBound := allBounds claim.sourceBound
    (List.contains_iff_mem.mp boundMember)
  simp only [ReverseSentinelScannerClaim.sourceBound, boundValue,
    Bool.and_eq_true] at selectedBound
  have originalBoundWord := of_decide_eq_true selectedBound.1
  have candidateBoundWord := of_decide_eq_true selectedBound.2
  have originalCursorBound :
      (originalState.registers.get claim.originalScannerRegister).toNat <
        claim.table.upperExclusive := by
    simpa [BitVec.lt_def, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt upperExclusiveSmall] using originalBoundWord
  have candidateCursorBound :
      (candidateState.registers.get claim.candidateScannerRegister).toNat <
        claim.table.upperExclusive := by
    simpa [BitVec.lt_def, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt upperExclusiveSmall] using candidateBoundWord
  have entryCountIdentity :
      claim.table.entryCount = claim.table.upperExclusive - 1 := by
    simp [BoundedImmutableCodePointerTableCallClaim.entryCount,
      BoundedImmutableCodePointerTableCallClaim.lowerInclusive, layoutChecked,
      ImmutableCodePointerTableLayout.lowerInclusive]
  have entryCountFits : claim.table.entryCount < 2 ^ 32 := by omega
  have entryIncrementWord :
      BitVec.ofNat 32 claim.table.entryCount + BitVec.ofNat 32 1 =
        BitVec.ofNat 32 (claim.table.entryCount + 1) := by
    rw [← BitVec.ofNat_add]
  let originalResult := originalBehavior.eval originalState
  let candidateResult := candidateBehavior.eval candidateState
  let originalNext := originalResult.nextMachineState originalState
  let candidateNext := candidateResult.nextMachineState candidateState
  have originalCountValue :
      originalNext.registers.get claim.originalCountRegister =
        originalState.registers.get claim.originalScannerRegister := by
    simp [originalNext, originalResult, RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      originalCountOutput, Expr.eval]
  have candidateCountValue :
      candidateNext.registers.get claim.candidateCountRegister =
        candidateState.registers.get claim.candidateScannerRegister := by
    simp [candidateNext, candidateResult, RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      candidateCountOutput, Expr.eval]
  have originalScannerValue :
      originalNext.registers.get claim.originalScannerRegister =
        claim.originalNextIndex.eval originalState := by
    simp [originalNext, originalResult, RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      originalScannerOutput]
  have candidateScannerValue :
      candidateNext.registers.get claim.candidateScannerRegister =
        claim.candidateNextIndex.eval candidateState := by
    simp [candidateNext, candidateResult, RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      candidateScannerOutput]
  have originalFlagValue :=
    inputFlagSix_after_normalizedBehavior_eq_zeroTest originalState originalBehavior
      claim.originalLoadedExpression originalZeroFlag
  have candidateFlagValue :=
    inputFlagSix_after_normalizedBehavior_eq_zeroTest candidateState candidateBehavior
      claim.candidateLoadedExpression candidateZeroFlag
  have originalNextIndexEvaluation :
      claim.originalNextIndex.eval originalState =
        BitVec.ofNat 32
          ((originalState.registers.get claim.originalScannerRegister).toNat + 1) := by
    simp only [ReverseSentinelScannerClaim.originalNextIndex, Expr.eval]
    calc
      originalState.registers.get claim.originalScannerRegister + BitVec.ofNat 32 1 =
          BitVec.ofNat 32
              (originalState.registers.get claim.originalScannerRegister).toNat +
            BitVec.ofNat 32 1 := by
        congr 1
        simp
      _ = BitVec.ofNat 32
          ((originalState.registers.get claim.originalScannerRegister).toNat + 1) := by
        rw [← BitVec.ofNat_add]
  have originalIncrementWord :
      originalState.registers.get claim.originalScannerRegister + BitVec.ofNat 32 1 =
        BitVec.ofNat 32
          ((originalState.registers.get claim.originalScannerRegister).toNat + 1) := by
    simpa [ReverseSentinelScannerClaim.originalNextIndex, Expr.eval] using
      originalNextIndexEvaluation
  have originalFlagBitValue :
      (originalNext.eflags.extractLsb' 6 1 == BitVec.ofNat 1 1) =
        decide (claim.originalLoadedExpression.eval originalState =
          BitVec.ofNat 32 0) := by
    simpa only [BoolExpr.eval] using originalFlagValue
  have candidateNextIndexEvaluation :
      claim.candidateNextIndex.eval candidateState =
        BitVec.ofNat 32
          ((candidateState.registers.get claim.candidateScannerRegister).toNat + 1) := by
    simp only [ReverseSentinelScannerClaim.candidateNextIndex, Expr.eval]
    calc
      candidateState.registers.get claim.candidateScannerRegister + BitVec.ofNat 32 1 =
          BitVec.ofNat 32
              (candidateState.registers.get claim.candidateScannerRegister).toNat +
            BitVec.ofNat 32 1 := by
        congr 1
        simp
      _ = BitVec.ofNat 32
          ((candidateState.registers.get claim.candidateScannerRegister).toNat + 1) := by
        rw [← BitVec.ofNat_add]
  have candidateIncrementWord :
      candidateState.registers.get claim.candidateScannerRegister + BitVec.ofNat 32 1 =
        BitVec.ofNat 32
          ((candidateState.registers.get claim.candidateScannerRegister).toNat + 1) := by
    simpa [ReverseSentinelScannerClaim.candidateNextIndex, Expr.eval] using
      candidateNextIndexEvaluation
  have candidateFlagBitValue :
      (candidateNext.eflags.extractLsb' 6 1 == BitVec.ofNat 1 1) =
        decide (claim.candidateLoadedExpression.eval candidateState =
          BitVec.ofNat 32 0) := by
    simpa only [BoolExpr.eval] using candidateFlagValue
  rw [targetPredicates]
  simp only [pairedStatePredicatesHold, List.all_cons, List.all_nil, Bool.and_true,
    PairedStatePredicate.holds, Bool.and_eq_true]
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · change claim.postPredicate.original.eval originalNext = true
    rw [ReverseSentinelScannerClaim.postPredicate]
    simp only [reverseSentinelScannerPostExpression, BoolExpr.eval, Expr.eval]
    rw [zeroFlagBit]
    simp only [originalCountValue, originalScannerValue, originalNextIndexEvaluation]
    rw [originalFlagBitValue]
    by_cases atTerminator :
        (originalState.registers.get claim.originalScannerRegister).toNat =
          claim.table.entryCount
    · have loadedIsZero := loadedZero.1.mpr atTerminator
      have countWordAtTerminator :
          originalState.registers.get claim.originalScannerRegister =
            BitVec.ofNat 32 claim.table.entryCount := by
        calc
          originalState.registers.get claim.originalScannerRegister =
              BitVec.ofNat 32
                (originalState.registers.get claim.originalScannerRegister).toNat := by
            simp
          _ = BitVec.ofNat 32 claim.table.entryCount := congrArg _ atTerminator
      simp [loadedIsZero, atTerminator, originalIncrementWord,
        countWordAtTerminator, Nat.mod_eq_of_lt entryCountFits,
        entryIncrementWord]
    · have loadedNotZero : claim.originalLoadedExpression.eval originalState ≠
          BitVec.ofNat 32 0 := by
        exact fun zero => atTerminator (loadedZero.1.mp zero)
      have countWordNotTerminator :
          originalState.registers.get claim.originalScannerRegister ≠
            BitVec.ofNat 32 claim.table.entryCount := by
        intro equal
        apply atTerminator
        have equalNat := congrArg BitVec.toNat equal
        simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt entryCountFits] using equalNat
      have nextFits :
          (originalState.registers.get claim.originalScannerRegister).toNat + 1 <
            2 ^ 32 := by omega
      have nextBeforeTerminator :
          (originalState.registers.get claim.originalScannerRegister).toNat + 1 <
            claim.table.upperExclusive := by omega
      simp [loadedNotZero, BitVec.lt_def, BitVec.toNat_ofNat,
        Nat.mod_eq_of_lt nextFits, Nat.mod_eq_of_lt upperExclusiveSmall,
        nextBeforeTerminator, originalIncrementWord, countWordNotTerminator]
  · change claim.postPredicate.candidate.eval candidateNext = true
    rw [ReverseSentinelScannerClaim.postPredicate]
    simp only [reverseSentinelScannerPostExpression, BoolExpr.eval, Expr.eval]
    rw [zeroFlagBit]
    simp only [candidateCountValue, candidateScannerValue, candidateNextIndexEvaluation]
    rw [candidateFlagBitValue]
    by_cases atTerminator :
        (candidateState.registers.get claim.candidateScannerRegister).toNat =
          claim.table.entryCount
    · have loadedIsZero := loadedZero.2.mpr atTerminator
      have countWordAtTerminator :
          candidateState.registers.get claim.candidateScannerRegister =
            BitVec.ofNat 32 claim.table.entryCount := by
        calc
          candidateState.registers.get claim.candidateScannerRegister =
              BitVec.ofNat 32
                (candidateState.registers.get claim.candidateScannerRegister).toNat := by
            simp
          _ = BitVec.ofNat 32 claim.table.entryCount := congrArg _ atTerminator
      simp [loadedIsZero, atTerminator, candidateIncrementWord,
        countWordAtTerminator, Nat.mod_eq_of_lt entryCountFits,
        entryIncrementWord]
    · have loadedNotZero : claim.candidateLoadedExpression.eval candidateState ≠
          BitVec.ofNat 32 0 := by
        exact fun zero => atTerminator (loadedZero.2.mp zero)
      have countWordNotTerminator :
          candidateState.registers.get claim.candidateScannerRegister ≠
            BitVec.ofNat 32 claim.table.entryCount := by
        intro equal
        apply atTerminator
        have equalNat := congrArg BitVec.toNat equal
        simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt entryCountFits] using equalNat
      have nextFits :
          (candidateState.registers.get claim.candidateScannerRegister).toNat + 1 <
            2 ^ 32 := by omega
      have nextBeforeTerminator :
          (candidateState.registers.get claim.candidateScannerRegister).toNat + 1 <
            claim.table.upperExclusive := by omega
      simp [loadedNotZero, BitVec.lt_def, BitVec.toNat_ofNat,
        Nat.mod_eq_of_lt nextFits, Nat.mod_eq_of_lt upperExclusiveSmall,
        nextBeforeTerminator, candidateIncrementWord, countWordNotTerminator]
  · simp [ReverseSentinelScannerClaim.postPredicate]

theorem bool_eq_of_not_ne_eq_true (left right : Bool)
    (checked : (!(left != right)) = true) : left = right := by
  cases left <;> cases right <;> simp_all

def ReverseSentinelScannerGuardAgreementClosed (context : StaticProofContext)
    (sourceInvariant : StateInvariant) (originalGuard candidateGuard : BoolExpr)
    (claim : ReverseSentinelScannerClaim) : Prop :=
  ∀ world originalState candidateState,
    StateRel context world sourceInvariant originalState candidateState →
      originalGuard.eval originalState = candidateGuard.eval candidateState

theorem reverseSentinelScannerGuardsAgree_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalGuard candidateGuard : BoolExpr)
    (claim : ReverseSentinelScannerClaim)
    (checked : claim.guardChecked sourceInvariant originalGuard candidateGuard = true) :
    ReverseSentinelScannerGuardAgreementClosed context sourceInvariant
      originalGuard candidateGuard claim := by
  simp only [ReverseSentinelScannerClaim.guardChecked, Bool.and_eq_true,
    Bool.or_eq_true, beq_iff_eq] at checked
  rcases checked with ⟨⟨sourcePredicates, exactCounts⟩, guardShape⟩
  unfold ReverseSentinelScannerGuardAgreementClosed
  intro world originalState candidateState related
  have predicates := related.predicatesHold
  rw [sourcePredicates] at predicates
  simp only [pairedStatePredicatesHold, List.all_cons, List.all_nil,
    Bool.and_true, PairedStatePredicate.holds, Bool.and_eq_true] at predicates
  have originalPost := predicates.1.1
  have candidatePost := predicates.1.2
  simp only [ReverseSentinelScannerClaim.postPredicate,
    reverseSentinelScannerPostExpression, BoolExpr.eval, Expr.eval,
    Bool.and_eq_true, Bool.or_eq_true] at originalPost candidatePost
  have countEqual := registerRelationsHold_exact_pair
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    sourceInvariant.registerRelations originalState.registers candidateState.registers
    claim.originalCountRegister claim.candidateCountRegister
    related.2.2.2.2.2.2.2.2.1.1 exactCounts
  have countTestsEqual :
      (BoolExpr.equal (.inputReg claim.originalCountRegister)
          (.constant claim.table.entryCount)).eval originalState =
        (BoolExpr.equal (.inputReg claim.candidateCountRegister)
          (.constant claim.table.entryCount)).eval candidateState := by
    simp [BoolExpr.eval, Expr.eval, countEqual]
  have originalFlagMatchesCount :
      (BoolExpr.inputFlag claim.zeroFlagBit).eval originalState =
        (BoolExpr.equal (.inputReg claim.originalCountRegister)
          (.constant claim.table.entryCount)).eval originalState := by
    exact bool_eq_of_not_ne_eq_true _ _ originalPost.2.1
  have candidateFlagMatchesCount :
      (BoolExpr.inputFlag claim.zeroFlagBit).eval candidateState =
        (BoolExpr.equal (.inputReg claim.candidateCountRegister)
          (.constant claim.table.entryCount)).eval candidateState := by
    exact bool_eq_of_not_ne_eq_true _ _ candidatePost.2.1
  have flagsEqual :
      (BoolExpr.inputFlag claim.zeroFlagBit).eval originalState =
        (BoolExpr.inputFlag claim.zeroFlagBit).eval candidateState :=
    originalFlagMatchesCount.trans
      (countTestsEqual.trans candidateFlagMatchesCount.symm)
  rcases guardShape with loopShape | exitShape
  · rcases loopShape with ⟨originalShape, candidateShape⟩
    rw [originalShape, candidateShape]
    simpa only [ReverseSentinelScannerClaim.loopGuard, BoolExpr.eval] using
      congrArg Bool.not flagsEqual
  · rcases exitShape with ⟨originalShape, candidateShape⟩
    rw [originalShape, candidateShape]
    simpa only [ReverseSentinelScannerClaim.exitGuard,
      ReverseSentinelScannerClaim.loopGuard, BoolExpr.eval] using
      congrArg Bool.not (congrArg Bool.not flagsEqual)

def ReverseSentinelScannerLoopBoundClosed (context : StaticProofContext)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim) : Prop :=
  ∀ world originalState candidateState,
    StateRel context world sourceInvariant originalState candidateState →
      claim.loopGuard.eval originalState = true →
      boundsRelated targetInvariant.bounds
        (originalBehavior.eval originalState).registers
        (candidateBehavior.eval candidateState).registers = true

theorem reverseSentinelScannerLoopBoundClosed_of_checked
    (context : StaticProofContext) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim)
    (checked : claim.loopChecked sourceInvariant targetInvariant originalBehavior
      candidateBehavior = true) :
    ReverseSentinelScannerLoopBoundClosed context sourceInvariant targetInvariant
      originalBehavior candidateBehavior claim := by
  simp only [ReverseSentinelScannerClaim.loopChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨sourcePredicates, exactScanners⟩, targetBounds⟩, zeroFlagBit⟩,
      behaviorChecked⟩
  simp only [ReverseSentinelScannerClaim.testBehaviorChecked, Bool.and_eq_true,
    beq_iff_eq] at behaviorChecked
  rcases behaviorChecked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨originalScannerIdentity, candidateScannerIdentity⟩,
      _originalCountIdentity⟩, _candidateCountIdentity⟩, _originalWritesEmpty⟩,
      _candidateWritesEmpty⟩, _originalFlagsNone⟩, _candidateFlagsNone⟩,
      _originalOutcome⟩, _candidateOutcome⟩
  unfold ReverseSentinelScannerLoopBoundClosed
  intro world originalState candidateState related guardTrue
  have predicates := related.predicatesHold
  rw [sourcePredicates] at predicates
  simp only [pairedStatePredicatesHold, List.all_cons, List.all_nil,
    Bool.and_true, PairedStatePredicate.holds, Bool.and_eq_true] at predicates
  have originalPost := predicates.1.1
  simp only [ReverseSentinelScannerClaim.postPredicate,
    reverseSentinelScannerPostExpression, BoolExpr.eval, Expr.eval,
    Bool.and_eq_true, Bool.or_eq_true] at originalPost
  have originalFlagFalse :
      (BoolExpr.inputFlag claim.zeroFlagBit).eval originalState = false := by
    simpa [ReverseSentinelScannerClaim.loopGuard, BoolExpr.eval] using guardTrue
  have originalFlagFalseRaw :
      (originalState.eflags.extractLsb' claim.zeroFlagBit 1 ==
        BitVec.ofNat 1 1) = false := by
    simpa only [BoolExpr.eval] using originalFlagFalse
  have originalBound :
      decide (originalState.registers.get claim.originalScannerRegister <
        BitVec.ofNat 32 claim.table.upperExclusive) = true := by
    rcases originalPost.2.2 with nonzero | zero
    · exact nonzero.2
    · rw [originalFlagFalseRaw] at zero
      simp at zero
  have scannerEqual := registerRelationsHold_exact_pair
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    sourceInvariant.registerRelations originalState.registers candidateState.registers
    claim.originalScannerRegister claim.candidateScannerRegister
    related.2.2.2.2.2.2.2.2.1.1 exactScanners
  have originalResultScanner :
      (originalBehavior.eval originalState).registers.get
          claim.originalScannerRegister =
        originalState.registers.get claim.originalScannerRegister := by
    simp [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, originalScannerIdentity, Expr.eval]
  have candidateResultScanner :
      (candidateBehavior.eval candidateState).registers.get
          claim.candidateScannerRegister =
        candidateState.registers.get claim.candidateScannerRegister := by
    simp [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, candidateScannerIdentity, Expr.eval]
  rw [targetBounds]
  simp only [boundsRelated, List.all_cons, List.all_nil, Bool.and_true,
    ReverseSentinelScannerClaim.sourceBound, boundValue, originalResultScanner,
    candidateResultScanner, Bool.and_eq_true]
  exact ⟨originalBound, by simpa [← scannerEqual] using originalBound⟩

def ReverseSentinelScannerFinishedPostconditionClosed (context : StaticProofContext)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim) : Prop :=
  ∀ world originalState candidateState,
    StateRel context world sourceInvariant originalState candidateState →
      claim.exitGuard.eval originalState = true →
      pairedStatePredicatesHold targetInvariant.predicates
        ((originalBehavior.eval originalState).nextMachineState originalState)
        ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true

theorem reverseSentinelScannerFinishedPostconditionClosed_of_checked
    (context : StaticProofContext) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReverseSentinelScannerClaim)
    (checked : claim.exitChecked sourceInvariant targetInvariant originalBehavior
      candidateBehavior = true) :
    ReverseSentinelScannerFinishedPostconditionClosed context sourceInvariant targetInvariant
      originalBehavior candidateBehavior claim := by
  simp only [ReverseSentinelScannerClaim.exitChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨sourcePredicates, exactCounts⟩, targetPredicates⟩, zeroFlagBit⟩,
      behaviorChecked⟩
  simp only [ReverseSentinelScannerClaim.testBehaviorChecked, Bool.and_eq_true,
    beq_iff_eq] at behaviorChecked
  rcases behaviorChecked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨_originalScannerIdentity, _candidateScannerIdentity⟩,
      originalCountIdentity⟩, candidateCountIdentity⟩, _originalWritesEmpty⟩,
      _candidateWritesEmpty⟩, _originalFlagsNone⟩, _candidateFlagsNone⟩,
      _originalOutcome⟩, _candidateOutcome⟩
  unfold ReverseSentinelScannerFinishedPostconditionClosed
  intro world originalState candidateState related guardTrue
  have predicates := related.predicatesHold
  rw [sourcePredicates] at predicates
  simp only [pairedStatePredicatesHold, List.all_cons, List.all_nil,
    Bool.and_true, PairedStatePredicate.holds, Bool.and_eq_true] at predicates
  have originalPost := predicates.1.1
  simp only [ReverseSentinelScannerClaim.postPredicate,
    reverseSentinelScannerPostExpression, BoolExpr.eval, Expr.eval,
    Bool.and_eq_true, Bool.or_eq_true] at originalPost
  have originalFlagTrue :
      (BoolExpr.inputFlag claim.zeroFlagBit).eval originalState = true := by
    simpa [ReverseSentinelScannerClaim.exitGuard,
      ReverseSentinelScannerClaim.loopGuard, BoolExpr.eval] using guardTrue
  have originalFlagTrueRaw :
      (originalState.eflags.extractLsb' claim.zeroFlagBit 1 ==
        BitVec.ofNat 1 1) = true := by
    simpa only [BoolExpr.eval] using originalFlagTrue
  have originalFinished :
      decide (originalState.registers.get claim.originalCountRegister =
        BitVec.ofNat 32 claim.table.entryCount) = true := by
    rcases originalPost.2.2 with nonzero | zero
    · rw [originalFlagTrueRaw] at nonzero
      simp at nonzero
    · exact zero.2
  have countEqual := registerRelationsHold_exact_pair
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    sourceInvariant.registerRelations originalState.registers candidateState.registers
    claim.originalCountRegister claim.candidateCountRegister
    related.2.2.2.2.2.2.2.2.1.1 exactCounts
  have originalResultCount :
      (originalBehavior.eval originalState).registers.get
          claim.originalCountRegister =
        originalState.registers.get claim.originalCountRegister := by
    simp [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, originalCountIdentity, Expr.eval]
  have candidateResultCount :
      (candidateBehavior.eval candidateState).registers.get
          claim.candidateCountRegister =
        candidateState.registers.get claim.candidateCountRegister := by
    simp [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, candidateCountIdentity, Expr.eval]
  rw [targetPredicates]
  simp only [pairedStatePredicatesHold, List.all_cons, List.all_nil,
    Bool.and_true, PairedStatePredicate.holds,
    ReverseSentinelScannerClaim.finishedPredicate, BoolExpr.eval, Expr.eval,
    RelationalBehavior.nextMachineState, NormalizedSymbolicBehavior.eval_x87Effect,
    originalResultCount,
    candidateResultCount, Bool.and_eq_true]
  exact ⟨originalFinished, by simpa [← countEqual] using originalFinished⟩

structure StaticWordSlotIndirectCallTargetClaim where
  targetId : Nat
  continuationTargetId : Nat
  slot : StaticWordRelationSlotPair
  originalAddress : Nat
  candidateAddress : Nat
  originalAssembledRead : Bool
  candidateAssembledRead : Bool
  originalWrites : List RegisterOffsetWrite
  candidateWrites : List RegisterOffsetWrite
deriving Repr, DecidableEq

def StaticWordSlotIndirectCallTargetClaim.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectCallTargetClaim) : Bool :=
  match context.codeMap.get? claim.targetId with
  | none => false
  | some _ =>
      context.staticWordRelationSlots.contains claim.slot &&
        claim.slot.relation == .fixedCodePointer claim.targetId &&
        claim.slot.originalAddress == BitVec.ofNat 32 claim.originalAddress &&
        claim.slot.candidateAddress == BitVec.ofNat 32 claim.candidateAddress &&
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

def StaticWordSlotIndirectCallTargetsClosed
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectCallTargetClaim) : Prop :=
  match context.codeMap.get? claim.targetId with
  | none => False
  | some target =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
          ∃ originalTarget candidateTarget,
            originalBehavior.outcome.eval originalState = .indirectCall
                originalTarget claim.continuationTargetId ∧
              candidateBehavior.outcome.eval candidateState = .indirectCall
                candidateTarget claim.continuationTargetId ∧
              codeAddressMatches context.originalPe.imageBase target.originalRva
                target.originalAliases originalTarget = true ∧
              codeAddressMatches context.candidatePe.imageBase target.candidateRva
                target.candidateAliases candidateTarget = true

theorem staticWordSlotIndirectCallTargetsClosed_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectCallTargetClaim)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true) :
    StaticWordSlotIndirectCallTargetsClosed context sourceInvariant originalBehavior
      candidateBehavior claim := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp [StaticWordSlotIndirectCallTargetClaim.checked, targetResult] at checked
  | some target =>
      simp only [StaticWordSlotIndirectCallTargetClaim.checked, targetResult,
        Bool.and_eq_true, beq_iff_eq] at checked
      simp only [StaticWordSlotIndirectCallTargetsClosed, targetResult]
      rcases checked with
        ⟨⟨⟨⟨⟨⟨⟨slotMember, slotRelation⟩, originalAddress⟩,
          candidateAddress⟩, originalOutcome⟩, candidateOutcome⟩,
          originalSeparated⟩, candidateSeparated⟩
      intro world originalState candidateState related
      have slotsHold := related.staticWordRelationSlotsMemoryHold context world
        sourceInvariant originalState candidateState
      have slotHolds := slotsHold claim.slot
        (List.contains_iff_mem.mp slotMember)
      simp only [StaticWordRelationSlotPair.memoryHolds] at slotHolds
      rw [slotRelation] at slotHolds
      simp only [StaticWordRelationKind.holds, codeTargetAddressPairMatches,
        targetResult,
        Bool.and_eq_true] at slotHolds
      rcases related with
        ⟨_worldStatic, _stackRangesValid, _stackMemory, _importsStatic,
          _importsComplete, _importsMemory, _originalImmutable, _candidateImmutable,
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
      let originalTarget :=
        (immutableWordReadExpression claim.originalAssembledRead
          claim.originalAddress claim.originalWrites).eval originalState
      let candidateTarget :=
        (immutableWordReadExpression claim.candidateAssembledRead
          claim.candidateAddress claim.candidateWrites).eval candidateState
      have originalTargetRead :
          originalTarget = Memory.read32 originalState.memory claim.slot.originalAddress := by
        cases assembled : claim.originalAssembledRead with
        | false =>
            simp [originalTarget, immutableWordReadExpression, assembled, Expr.eval,
              machineStateRead32_eq_memoryRead32, originalAddress]
        | true =>
            simp only [originalTarget, immutableWordReadExpression, assembled, if_true]
            rw [Expr.eval_constantRead32AfterWrites]
            rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ originalAvoids]
            rw [originalAddress]
      have candidateTargetRead :
          candidateTarget = Memory.read32 candidateState.memory claim.slot.candidateAddress := by
        cases assembled : claim.candidateAssembledRead with
        | false =>
            simp [candidateTarget, immutableWordReadExpression, assembled, Expr.eval,
              machineStateRead32_eq_memoryRead32, candidateAddress]
        | true =>
            simp only [candidateTarget, immutableWordReadExpression, assembled, if_true]
            rw [Expr.eval_constantRead32AfterWrites]
            rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ candidateAvoids]
            rw [candidateAddress]
      refine ⟨originalTarget, candidateTarget, ?_, ?_, ?_, ?_⟩
      · rw [originalOutcome]
        simp only [NormalizedOutcomeExpr.eval]
        rfl
      · rw [candidateOutcome]
        simp only [NormalizedOutcomeExpr.eval]
        rfl
      · rw [originalTargetRead]
        exact slotHolds.2.1.1
      · rw [candidateTargetRead]
        exact slotHolds.2.1.2

def StaticWordSlotIndirectCallTargetClaim.toImmutable
    (claim : StaticWordSlotIndirectCallTargetClaim) : ImmutableIndirectCallTargetClaim := {
  targetId := claim.targetId
  continuationTargetId := claim.continuationTargetId
  originalAddress := claim.originalAddress
  candidateAddress := claim.candidateAddress
  originalAssembledRead := claim.originalAssembledRead
  candidateAssembledRead := claim.candidateAssembledRead
  originalWrites := claim.originalWrites
  candidateWrites := claim.candidateWrites
}

theorem immutableIndirectCallTargetsClosed_of_staticWordSlot
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectCallTargetClaim)
    (closed : StaticWordSlotIndirectCallTargetsClosed context sourceInvariant
      originalBehavior candidateBehavior claim) :
    ImmutableIndirectCallTargetsClosed context sourceInvariant originalBehavior
      candidateBehavior claim.toImmutable := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp only [StaticWordSlotIndirectCallTargetsClosed, targetResult] at closed
  | some target =>
      simp only [StaticWordSlotIndirectCallTargetsClosed, targetResult] at closed
      simp only [ImmutableIndirectCallTargetsClosed,
        StaticWordSlotIndirectCallTargetClaim.toImmutable, targetResult]
      exact closed

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

structure StaticWordSlotIndirectJumpTargetClaim where
  targetId : Nat
  slot : StaticWordRelationSlotPair
  originalAddress : Nat
  candidateAddress : Nat
  originalAssembledRead : Bool
  candidateAssembledRead : Bool
  originalWrites : List RegisterOffsetWrite
  candidateWrites : List RegisterOffsetWrite
deriving Repr, DecidableEq

def StaticWordSlotIndirectJumpTargetClaim.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectJumpTargetClaim) : Bool :=
  match context.codeMap.get? claim.targetId with
  | none => false
  | some target =>
      context.staticWordRelationSlots.contains claim.slot &&
        claim.slot.relation == .fixedCodePointer claim.targetId &&
        claim.slot.originalAddress == BitVec.ofNat 32 claim.originalAddress &&
        claim.slot.candidateAddress == BitVec.ofNat 32 claim.candidateAddress &&
        target.originalAliases == [] &&
        target.candidateAliases == [] &&
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

def StaticWordSlotIndirectJumpTargetsClosed
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectJumpTargetClaim) : Prop :=
  match context.codeMap.get? claim.targetId with
  | none => False
  | some target =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
          originalBehavior.outcome.eval originalState = .indirectJump
              (BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva)) ∧
            candidateBehavior.outcome.eval candidateState = .indirectJump
              (BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva))

theorem staticWordSlotIndirectJumpTargetsClosed_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectJumpTargetClaim)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true) :
    StaticWordSlotIndirectJumpTargetsClosed context sourceInvariant originalBehavior
      candidateBehavior claim := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp [StaticWordSlotIndirectJumpTargetClaim.checked, targetResult] at checked
  | some target =>
      simp only [StaticWordSlotIndirectJumpTargetClaim.checked, targetResult,
        Bool.and_eq_true, beq_iff_eq] at checked
      simp only [StaticWordSlotIndirectJumpTargetsClosed, targetResult]
      rcases checked with
        ⟨⟨⟨⟨⟨⟨⟨⟨⟨slotMember, slotRelation⟩, originalAddress⟩,
          candidateAddress⟩, originalAliases⟩, candidateAliases⟩,
          originalOutcome⟩, candidateOutcome⟩, originalSeparated⟩,
          candidateSeparated⟩
      intro world originalState candidateState related
      have slotsHold := related.staticWordRelationSlotsMemoryHold context world
        sourceInvariant originalState candidateState
      have slotHolds := slotsHold claim.slot
        (List.contains_iff_mem.mp slotMember)
      simp only [StaticWordRelationSlotPair.memoryHolds] at slotHolds
      rw [slotRelation] at slotHolds
      simp only [StaticWordRelationKind.holds, codeTargetAddressPairMatches,
        targetResult, Bool.and_eq_true] at slotHolds
      rcases related with
        ⟨_worldStatic, _stackRangesValid, _stackMemory, _importsStatic,
          _importsComplete, _importsMemory, _originalImmutable, _candidateImmutable,
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
      let originalTarget :=
        (immutableWordReadExpression claim.originalAssembledRead
          claim.originalAddress claim.originalWrites).eval originalState
      let candidateTarget :=
        (immutableWordReadExpression claim.candidateAssembledRead
          claim.candidateAddress claim.candidateWrites).eval candidateState
      have originalTargetRead :
          originalTarget = Memory.read32 originalState.memory claim.slot.originalAddress := by
        cases assembled : claim.originalAssembledRead with
        | false =>
            simp [originalTarget, immutableWordReadExpression, assembled, Expr.eval,
              machineStateRead32_eq_memoryRead32, originalAddress]
        | true =>
            simp only [originalTarget, immutableWordReadExpression, assembled, if_true]
            rw [Expr.eval_constantRead32AfterWrites]
            rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ originalAvoids]
            rw [originalAddress]
      have candidateTargetRead :
          candidateTarget = Memory.read32 candidateState.memory claim.slot.candidateAddress := by
        cases assembled : claim.candidateAssembledRead with
        | false =>
            simp [candidateTarget, immutableWordReadExpression, assembled, Expr.eval,
              machineStateRead32_eq_memoryRead32, candidateAddress]
        | true =>
            simp only [candidateTarget, immutableWordReadExpression, assembled, if_true]
            rw [Expr.eval_constantRead32AfterWrites]
            rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ candidateAvoids]
            rw [candidateAddress]
      have originalTargetExact :
          originalTarget = BitVec.ofNat 32
            (context.originalPe.imageBase + target.originalRva) := by
        rw [originalTargetRead]
        simpa [codeAddressMatches, originalAliases] using slotHolds.2.1.1
      have candidateTargetExact :
          candidateTarget = BitVec.ofNat 32
            (context.candidatePe.imageBase + target.candidateRva) := by
        rw [candidateTargetRead]
        simpa [codeAddressMatches, candidateAliases] using slotHolds.2.1.2
      constructor
      · rw [originalOutcome]
        simp only [NormalizedOutcomeExpr.eval, PureOutcome.indirectJump.injEq]
        simpa [originalTarget] using originalTargetExact
      · rw [candidateOutcome]
        simp only [NormalizedOutcomeExpr.eval, PureOutcome.indirectJump.injEq]
        simpa [candidateTarget] using candidateTargetExact

def StaticWordSlotIndirectJumpTargetClaim.toImmutable
    (claim : StaticWordSlotIndirectJumpTargetClaim) : ImmutableIndirectJumpTargetClaim := {
  targetId := claim.targetId
  originalAddress := claim.originalAddress
  candidateAddress := claim.candidateAddress
  originalAssembledRead := claim.originalAssembledRead
  candidateAssembledRead := claim.candidateAssembledRead
  originalWrites := claim.originalWrites
  candidateWrites := claim.candidateWrites
}

theorem immutableIndirectJumpTargetsClosed_of_staticWordSlot
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectJumpTargetClaim)
    (closed : StaticWordSlotIndirectJumpTargetsClosed context sourceInvariant
      originalBehavior candidateBehavior claim) :
    ImmutableIndirectJumpTargetsClosed context sourceInvariant originalBehavior
      candidateBehavior claim.toImmutable := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp only [StaticWordSlotIndirectJumpTargetsClosed, targetResult] at closed
  | some target =>
      simp only [StaticWordSlotIndirectJumpTargetsClosed, targetResult] at closed
      simp only [ImmutableIndirectJumpTargetsClosed,
        StaticWordSlotIndirectJumpTargetClaim.toImmutable, targetResult]
      exact closed

structure FixedCodeAddressIndirectJumpTargetClaim where
  targetId : Nat
  originalTarget : Nat
  candidateTarget : Nat
deriving Repr, DecidableEq

def FixedCodeAddressIndirectJumpTargetClaim.checked
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FixedCodeAddressIndirectJumpTargetClaim) : Bool :=
  match context.codeMap.get? claim.targetId with
  | none => false
  | some target =>
      claim.originalTarget == context.originalPe.imageBase + target.originalRva &&
        claim.candidateTarget == context.candidatePe.imageBase + target.candidateRva &&
        originalBehavior.outcome == .indirectJump
          (.constant claim.originalTarget) &&
        candidateBehavior.outcome == .indirectJump
          (.constant claim.candidateTarget)

def FixedCodeAddressIndirectJumpTargetsClosed
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FixedCodeAddressIndirectJumpTargetClaim) : Prop :=
  match context.codeMap.get? claim.targetId with
  | none => False
  | some target =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        originalBehavior.outcome.eval originalState = .indirectJump
            (BitVec.ofNat 32 (context.originalPe.imageBase + target.originalRva)) ∧
          candidateBehavior.outcome.eval candidateState = .indirectJump
            (BitVec.ofNat 32 (context.candidatePe.imageBase + target.candidateRva))

theorem fixedCodeAddressIndirectJumpTargetsClosed_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FixedCodeAddressIndirectJumpTargetClaim)
    (checked : claim.checked context originalBehavior candidateBehavior = true) :
    FixedCodeAddressIndirectJumpTargetsClosed context sourceInvariant originalBehavior
      candidateBehavior claim := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp [FixedCodeAddressIndirectJumpTargetClaim.checked, targetResult] at checked
  | some target =>
      simp only [FixedCodeAddressIndirectJumpTargetClaim.checked, targetResult,
        Bool.and_eq_true, beq_iff_eq] at checked
      simp only [FixedCodeAddressIndirectJumpTargetsClosed, targetResult]
      rcases checked with
        ⟨⟨⟨originalTarget, candidateTarget⟩, originalOutcome⟩, candidateOutcome⟩
      intro world originalState candidateState related
      rw [originalOutcome, candidateOutcome, originalTarget, candidateTarget]
      simp [NormalizedOutcomeExpr.eval, Expr.eval]

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
    claim.rangeRelation.activeWords.contains claim.codeWord &&
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
    ⟨⟨⟨⟨relationMember, offsetsEqual⟩, codeWordActive⟩,
      originalOutcome⟩, candidateOutcome⟩
  intro context world originalState candidateState related
  have dynamicRegisters := related.activeDynamicRegisterRangesHold context world
    sourceInvariant originalState candidateState
  simp only [activeDynamicRegisterRangeRelationsHold, List.all_eq_true]
      at dynamicRegisters
  have relationHolds := dynamicRegisters claim.rangeRelation
    (by simpa using relationMember)
  simp only [DynamicRegisterRangeRelation.activeHolds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at relationHolds
  rcases relationHolds with
    ⟨range, rangeMember,
      ⟨⟨⟨⟨originalRegister, candidateRegister⟩, _requiredWords⟩,
        _activeWordsSubset⟩, activeWordsHold⟩⟩
  simp only [dynamicWordRequirementsHold, List.all_eq_true,
    Bool.and_eq_true] at activeWordsHold
  have codeWordsRelated := (activeWordsHold claim.codeWord
    (by simpa using codeWordActive)).2
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
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterIndirectCallClaim) : Prop :=
  ∀ world originalState candidateState,
    StateRel context world sourceInvariant originalState candidateState →
      ∃ binding, binding ∈ world.importAddresses ∧
        binding.imported = claim.imported ∧
        originalBehavior.outcome.eval originalState = .indirectCall
          binding.originalAddress claim.continuationTargetId ∧
        candidateBehavior.outcome.eval candidateState = .indirectCall
          binding.candidateAddress claim.continuationTargetId

theorem importRegisterIndirectCallTargetsClosed_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterIndirectCallClaim)
    (checked : claim.checked sourceInvariant originalBehavior candidateBehavior = true) :
    ImportRegisterIndirectCallTargetsClosed context sourceInvariant originalBehavior
      candidateBehavior claim := by
  simp only [ImportRegisterIndirectCallClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with ⟨⟨relationMember, originalOutcome⟩, candidateOutcome⟩
  intro world originalState candidateState related
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

structure FixedCodePointerRegisterIndirectCallClaim where
  targetId : Nat
  originalRegister : Reg
  candidateRegister : Reg
  continuationTargetId : Nat
deriving Repr, DecidableEq

def FixedCodePointerRegisterIndirectCallClaim.relation
    (claim : FixedCodePointerRegisterIndirectCallClaim) : RegisterRelationPair := {
  original := claim.originalRegister
  candidate := claim.candidateRegister
  relation := .fixedCodePointer claim.targetId
}

def FixedCodePointerRegisterIndirectCallClaim.checked
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FixedCodePointerRegisterIndirectCallClaim) : Bool :=
  sourceInvariant.registerRelations.contains claim.relation &&
    originalBehavior.outcome == .indirectCall
      (.inputReg claim.originalRegister) claim.continuationTargetId &&
    candidateBehavior.outcome == .indirectCall
      (.inputReg claim.candidateRegister) claim.continuationTargetId

def FixedCodePointerRegisterIndirectCallTargetsClosed
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FixedCodePointerRegisterIndirectCallClaim) : Prop :=
  ∀ world originalState candidateState,
    StateRel context world sourceInvariant originalState candidateState →
      ∃ originalTarget candidateTarget,
        originalBehavior.outcome.eval originalState = .indirectCall
            originalTarget claim.continuationTargetId ∧
          candidateBehavior.outcome.eval candidateState = .indirectCall
            candidateTarget claim.continuationTargetId ∧
          fixedCodePointerRelated context.originalPe.imageBase
            context.candidatePe.imageBase context.codeMap.entries.toList
            claim.targetId originalTarget candidateTarget = true

theorem fixedCodePointerRegisterIndirectCallTargetsClosed_of_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FixedCodePointerRegisterIndirectCallClaim)
    (checked : claim.checked sourceInvariant originalBehavior candidateBehavior = true) :
    FixedCodePointerRegisterIndirectCallTargetsClosed context sourceInvariant
      originalBehavior candidateBehavior claim := by
  simp only [FixedCodePointerRegisterIndirectCallClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with ⟨⟨relationMember, originalOutcome⟩, candidateOutcome⟩
  intro world originalState candidateState related
  rcases related with
    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable, _candidateImmutable,
      relatedCore, _importAndDynamicRegisters⟩
  have registerRelations := relatedCore.1
  simp only [registerRelationsHold, List.all_eq_true] at registerRelations
  have relationHolds := registerRelations claim.relation
    (by simpa using relationMember)
  change fixedCodePointerRelated context.originalPe.imageBase
    context.candidatePe.imageBase context.codeMap.entries.toList claim.targetId
    (originalState.registers.get claim.originalRegister)
    (candidateState.registers.get claim.candidateRegister) = true at relationHolds
  refine ⟨originalState.registers.get claim.originalRegister,
    candidateState.registers.get claim.candidateRegister, ?_, ?_, relationHolds⟩
  · rw [originalOutcome]
    simp only [NormalizedOutcomeExpr.eval, Expr.eval]
  · rw [candidateOutcome]
    simp only [NormalizedOutcomeExpr.eval, Expr.eval]

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

def ImportRegisterSeedClaim.closesIndirectCall
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (callClaim : ImportRegisterIndirectCallClaim)
    (seedClaim : ImportRegisterSeedClaim) : Bool :=
  seedClaim.relation == callClaim.relation &&
    seedClaim.checked context.originalPe context.candidatePe
      context.originalImports context.candidateImports sourceInvariant
      originalBehavior candidateBehavior &&
    originalBehavior.outcome == .indirectCall
      (originalBehavior.registers.get seedClaim.originalRegister)
      callClaim.continuationTargetId &&
    candidateBehavior.outcome == .indirectCall
      (candidateBehavior.registers.get seedClaim.candidateRegister)
      callClaim.continuationTargetId

theorem importRegisterIndirectCallTargetsClosed_of_seed_checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (callClaim : ImportRegisterIndirectCallClaim)
    (seedClaim : ImportRegisterSeedClaim)
    (checked : seedClaim.closesIndirectCall context sourceInvariant
      originalBehavior candidateBehavior callClaim = true) :
    ImportRegisterIndirectCallTargetsClosed context sourceInvariant originalBehavior
      candidateBehavior callClaim := by
  simp only [ImportRegisterSeedClaim.closesIndirectCall, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨relationEqual, seedChecked⟩, originalOutcome⟩, candidateOutcome⟩
  have originalRegisterEqual :
      seedClaim.originalRegister = callClaim.originalRegister := by
    have fieldEqual := congrArg ImportRegisterRelation.original relationEqual
    simpa [ImportRegisterSeedClaim.relation,
      ImportRegisterIndirectCallClaim.relation] using fieldEqual
  have candidateRegisterEqual :
      seedClaim.candidateRegister = callClaim.candidateRegister := by
    have fieldEqual := congrArg ImportRegisterRelation.candidate relationEqual
    simpa [ImportRegisterSeedClaim.relation,
      ImportRegisterIndirectCallClaim.relation] using fieldEqual
  intro world originalState candidateState related
  have seedOutput := importRegisterSeedOutputHolds_of_checked context world
    sourceInvariant originalBehavior candidateBehavior seedClaim seedChecked
    originalState candidateState related
  rw [relationEqual] at seedOutput
  simp only [ImportRegisterRelation.holds, List.any_eq_true] at seedOutput
  rcases seedOutput with ⟨binding, bindingMember, bindingChecks⟩
  simp only [Bool.and_eq_true, beq_iff_eq] at bindingChecks
  rcases bindingChecks with
    ⟨⟨imported, originalAddress⟩, candidateAddress⟩
  refine ⟨binding, bindingMember, imported, ?_, ?_⟩
  · rw [originalOutcome]
    simp only [NormalizedOutcomeExpr.eval]
    have originalSeedAddress :
        (originalBehavior.eval originalState).registers.get
            seedClaim.originalRegister = binding.originalAddress := by
      rw [originalRegisterEqual]
      exact originalAddress
    have originalExprAddress :
        (originalBehavior.registers.get seedClaim.originalRegister).eval
            originalState = binding.originalAddress := by
      simpa only [NormalizedSymbolicBehavior.eval_registers,
        evalNormalizedRegisters_get] using originalSeedAddress
    rw [originalExprAddress]
  · rw [candidateOutcome]
    simp only [NormalizedOutcomeExpr.eval]
    have candidateSeedAddress :
        (candidateBehavior.eval candidateState).registers.get
            seedClaim.candidateRegister = binding.candidateAddress := by
      rw [candidateRegisterEqual]
      exact candidateAddress
    have candidateExprAddress :
        (candidateBehavior.registers.get seedClaim.candidateRegister).eval
            candidateState = binding.candidateAddress := by
      simpa only [NormalizedSymbolicBehavior.eval_registers,
        evalNormalizedRegisters_get] using candidateSeedAddress
    rw [candidateExprAddress]

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
    claim.targetRelation.activeWords.all
      claim.sourceRelation.activeWords.contains &&
    claim.targetRelation.activeWords.all
      claim.targetRelation.requiredWords.contains &&
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
    ⟨⟨⟨⟨⟨⟨⟨⟨sourceMember, _targetMember⟩, originalOffset⟩,
      candidateOffset⟩, requiredWordsSubset⟩, _activeWordsSubset⟩,
      targetActiveSubset⟩, originalRegister⟩, candidateRegister⟩
  rcases related with
    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable,
      _candidateImmutable, _relatedCore, _importAndDynamicRegisters⟩
  have dynamicRegisters := _importAndDynamicRegisters.2.2.2.1
  simp only [dynamicRegisterRangeRelationsHold, List.all_eq_true]
      at dynamicRegisters
  have sourceHolds := dynamicRegisters claim.sourceRelation
    (by simpa using sourceMember)
  simp only [DynamicRegisterRangeRelation.holds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at sourceHolds
  rcases sourceHolds with
    ⟨range, rangeMember,
      ⟨⟨⟨sourceOriginalRegister, sourceCandidateRegister⟩,
        sourceRequiredWords⟩, _sourceActiveSubset⟩⟩
  unfold DynamicRegisterRangeRelation.holds
  simp only [List.any_eq_true]
  refine ⟨range, rangeMember, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨⟨?_, ?_⟩, ?_⟩, targetActiveSubset⟩
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

theorem dynamicRegisterRangePreserveOutputActiveHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRegisterRangePreserveClaim)
    (checked : claim.checked sourceInvariant targetInvariant originalBehavior
      candidateBehavior = true)
    (originalWrites : originalBehavior.writes = [])
    (candidateWrites : candidateBehavior.writes = [])
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.targetRelation.activeHolds context world
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true := by
  simp only [DynamicRegisterRangePreserveClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨⟨sourceMember, _targetMember⟩, originalOffset⟩,
      candidateOffset⟩, requiredWordsSubset⟩, activeWordsSubset⟩,
      targetActiveSubset⟩, originalRegister⟩, candidateRegister⟩
  have sourceRelations := related.activeDynamicRegisterRangesHold context world
    sourceInvariant originalState candidateState
  simp only [activeDynamicRegisterRangeRelationsHold, List.all_eq_true]
      at sourceRelations
  have sourceHolds := sourceRelations claim.sourceRelation
    (by simpa using sourceMember)
  simp only [DynamicRegisterRangeRelation.activeHolds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at sourceHolds
  rcases sourceHolds with
    ⟨range, rangeMember,
      ⟨⟨⟨⟨sourceOriginalRegister, sourceCandidateRegister⟩,
        sourceRequiredWords⟩, sourceActiveSubset⟩, sourceWordsHold⟩⟩
  unfold DynamicRegisterRangeRelation.activeHolds
  simp only [List.any_eq_true]
  refine ⟨range, rangeMember, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, targetActiveSubset⟩, ?_⟩
  · simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_x87Effect,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      originalRegister, Expr.eval]
    rw [← originalOffset]
    exact sourceOriginalRegister
  · simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_x87Effect,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      candidateRegister, Expr.eval]
    rw [← candidateOffset]
    exact sourceCandidateRegister
  · simp only [List.all_eq_true] at sourceRequiredWords requiredWordsSubset ⊢
    intro word wordMember
    exact sourceRequiredWords word
      (by simpa using requiredWordsSubset word wordMember)
  · have targetWordsHold := dynamicWordRequirementsHold_mono context world range
        claim.sourceRelation.activeWords claim.targetRelation.activeWords
        originalState.memory candidateState.memory activeWordsSubset sourceWordsHold
    simpa [RelationalBehavior.nextMachineState, originalWrites, candidateWrites]
      using targetWordsHold

theorem dynamicRegisterRangePreparedPreserveOutputActiveHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (writesClaim : PairedPreparedWordWritesClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRegisterRangePreserveClaim)
    (contextValid : context.StructurallyValid)
    (claimChecked : claim.checked sourceInvariant targetInvariant originalBehavior
      candidateBehavior = true)
    (writesChecked : writesClaim.checked context sourceInvariant = true)
    (originalWrites : originalBehavior.writes = writesClaim.originalSymbolicWrites)
    (candidateWrites : candidateBehavior.writes = writesClaim.candidateSymbolicWrites)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.targetRelation.activeHolds context world
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true := by
  simp only [DynamicRegisterRangePreserveClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at claimChecked
  rcases claimChecked with
    ⟨⟨⟨⟨⟨⟨⟨⟨sourceMember, _targetMember⟩, originalOffset⟩,
      candidateOffset⟩, requiredWordsSubset⟩, activeWordsSubset⟩,
      targetActiveSubset⟩, originalRegister⟩, candidateRegister⟩
  have sourceRelations := related.activeDynamicRegisterRangesHold context world
    sourceInvariant originalState candidateState
  simp only [activeDynamicRegisterRangeRelationsHold, List.all_eq_true]
      at sourceRelations
  have sourceHolds := sourceRelations claim.sourceRelation
    (by simpa using sourceMember)
  simp only [DynamicRegisterRangeRelation.activeHolds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at sourceHolds
  rcases sourceHolds with
    ⟨range, rangeMember,
      ⟨⟨⟨⟨sourceOriginalRegister, sourceCandidateRegister⟩,
        sourceRequiredWords⟩, sourceActiveSubset⟩, sourceWordsHold⟩⟩
  have checkedRows := writesChecked
  simp only [PairedPreparedWordWritesClaim.checked, Bool.and_eq_true] at checkedRows
  have stackRangesValid : world.stackRangesValid context = true := related.2.1
  rcases pairedPreparedWordUpdates_of_checkedItems context world sourceInvariant
      writesClaim.writes originalState candidateState stackRangesValid checkedRows.2
      related with
    ⟨updates, originalUpdateWrites, candidateUpdateWrites, _updateKinds⟩
  have worldDynamicValid : world.dynamicRangesValid context = true := by
    have valid := related.1
    simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
    exact valid.1.1.1.1
  have staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true := by
    rcases contextValid with
      ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _⟩
    exact slotsValid
  have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
    rcases contextValid with
      ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
    exact slotsValid
  have targetWordsBefore := dynamicWordRequirementsHold_mono context world range
    claim.sourceRelation.activeWords claim.targetRelation.activeWords
    originalState.memory candidateState.memory activeWordsSubset sourceWordsHold
  have targetActiveAvailable : claim.targetRelation.activeWords.all
      range.wordRelations.contains = true := by
    simp only [List.all_eq_true] at sourceRequiredWords sourceActiveSubset activeWordsSubset ⊢
    intro word wordMember
    exact sourceRequiredWords word
      (List.contains_iff_mem.mp (sourceActiveSubset word
        (List.contains_iff_mem.mp (activeWordsSubset word wordMember))))
  have targetWords := dynamicWordRequirementsHold_after_prepared_updates
    context world range claim.targetRelation.activeWords originalState.memory
    candidateState.memory updates worldDynamicValid staticPointerSlotsValid
    staticWordSlotsValid rangeMember targetActiveAvailable targetWordsBefore
  rw [originalUpdateWrites, candidateUpdateWrites] at targetWords
  unfold DynamicRegisterRangeRelation.activeHolds
  simp only [List.any_eq_true]
  refine ⟨range, rangeMember, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, targetActiveSubset⟩, ?_⟩
  · simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_x87Effect,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      originalRegister, Expr.eval]
    rw [← originalOffset]
    exact sourceOriginalRegister
  · simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_x87Effect,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      candidateRegister, Expr.eval]
    rw [← candidateOffset]
    exact sourceCandidateRegister
  · simp only [List.all_eq_true] at sourceRequiredWords requiredWordsSubset ⊢
    intro word wordMember
    exact sourceRequiredWords word
      (by simpa using requiredWordsSubset word wordMember)
  · simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_writes]
    rw [originalWrites, candidateWrites]
    simpa [PairedPreparedWordWritesClaim.originalSymbolicWrites,
      PairedPreparedWordWritesClaim.candidateSymbolicWrites,
      PairedPreparedWordWritesClaim.originalWrites,
      PairedPreparedWordWritesClaim.candidateWrites, evalNormalizedWrites]
      using targetWords

structure DynamicRegisterRangeActivateClaim where
  sourceRelation : DynamicRegisterRangeRelation
  targetRelation : DynamicRegisterRangeRelation
  relation : DynamicWordRelation
  originalAmount : Nat
  candidateAmount : Nat
  value : PairedStackWordValueClaim
  suffix : List PairedPreparedWordWriteItem := []
deriving Repr, DecidableEq

def DynamicRegisterRangeActivateClaim.item
    (claim : DynamicRegisterRangeActivateClaim) : PairedPreparedWordWriteItem :=
  .dynamicWord claim.sourceRelation claim.relation claim.originalAmount
    claim.candidateAmount claim.value

def DynamicRegisterRangeActivateClaim.checked
    (context : StaticProofContext) (sourceInvariant targetInvariant : StateInvariant)
    (writesClaim : PairedPreparedWordWritesClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRegisterRangeActivateClaim) : Bool :=
  writesClaim.checked context sourceInvariant &&
    writesClaim.writes == claim.item :: claim.suffix &&
    originalBehavior.writes == writesClaim.originalSymbolicWrites &&
    candidateBehavior.writes == writesClaim.candidateSymbolicWrites &&
    sourceInvariant.dynamicRegisterRangeRelations.contains claim.sourceRelation &&
    targetInvariant.dynamicRegisterRangeRelations.contains claim.targetRelation &&
    claim.sourceRelation.originalOffset == claim.targetRelation.originalOffset &&
    claim.sourceRelation.candidateOffset == claim.targetRelation.candidateOffset &&
    claim.targetRelation.requiredWords.all
      claim.sourceRelation.requiredWords.contains &&
    (claim.targetRelation.activeWords.all fun word =>
      word == claim.relation || claim.sourceRelation.activeWords.contains word) &&
    claim.sourceRelation.activeWords.all claim.targetRelation.activeWords.contains &&
    claim.targetRelation.activeWords.contains claim.relation &&
    claim.targetRelation.activeWords.all
      claim.targetRelation.requiredWords.contains &&
    originalBehavior.registers.get claim.targetRelation.original ==
      .inputReg claim.sourceRelation.original &&
    candidateBehavior.registers.get claim.targetRelation.candidate ==
      .inputReg claim.sourceRelation.candidate

theorem dynamicRegisterRangeActivateOutputActiveHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (writesClaim : PairedPreparedWordWritesClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRegisterRangeActivateClaim)
    (checked : claim.checked context sourceInvariant targetInvariant writesClaim
      originalBehavior candidateBehavior = true)
    (contextValid : context.StructurallyValid)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.targetRelation.activeHolds context world
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true := by
  simp only [DynamicRegisterRangeActivateClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with ⟨checked, candidateRegister⟩
  rcases checked with ⟨checked, originalRegister⟩
  rcases checked with ⟨checked, targetActiveRequired⟩
  rcases checked with ⟨checked, targetContainsWrite⟩
  rcases checked with ⟨checked, _sourceActiveIncluded⟩
  rcases checked with ⟨checked, targetCovered⟩
  rcases checked with ⟨checked, requiredWordsSubset⟩
  rcases checked with ⟨checked, candidateOffset⟩
  rcases checked with ⟨checked, originalOffset⟩
  rcases checked with ⟨checked, _targetMember⟩
  rcases checked with ⟨checked, sourceMember⟩
  rcases checked with ⟨checked, candidateWrites⟩
  rcases checked with ⟨checked, originalWrites⟩
  rcases checked with ⟨writesChecked, writesExact⟩
  have checkedRows := writesChecked
  simp only [PairedPreparedWordWritesClaim.checked, Bool.and_eq_true] at checkedRows
  have allWritesChecked := checkedRows.2
  rw [writesExact] at allWritesChecked
  simp only [List.all_cons, Bool.and_eq_true] at allWritesChecked
  have itemChecked : claim.item.checked context sourceInvariant = true :=
    allWritesChecked.1
  have suffixChecked : claim.suffix.all
      (PairedPreparedWordWriteItem.checked context sourceInvariant) = true :=
    allWritesChecked.2
  simp only [DynamicRegisterRangeActivateClaim.item,
    PairedPreparedWordWriteItem.checked, Bool.and_eq_true, beq_iff_eq]
      at itemChecked
  rcases itemChecked with
    ⟨⟨⟨⟨⟨sourceMemberFromItem, relationMember⟩,
      originalRelationOffset⟩, candidateRelationOffset⟩, valueChecked⟩,
      valueCompatible⟩
  have sourceRelations := related.activeDynamicRegisterRangesHold context world
    sourceInvariant originalState candidateState
  simp only [activeDynamicRegisterRangeRelationsHold, List.all_eq_true]
      at sourceRelations
  have sourceHolds := sourceRelations claim.sourceRelation
    (by simpa using sourceMember)
  simp only [DynamicRegisterRangeRelation.activeHolds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at sourceHolds
  rcases sourceHolds with
    ⟨range, rangeMember,
      ⟨⟨⟨⟨sourceOriginalRegister, sourceCandidateRegister⟩,
        sourceRequiredWords⟩, sourceActiveSubset⟩, sourceWordsHold⟩⟩
  have relationInRange : claim.relation ∈ range.wordRelations := by
    simp only [List.all_eq_true] at sourceRequiredWords
    exact List.contains_iff_mem.mp
      (sourceRequiredWords claim.relation
        (List.contains_iff_mem.mp relationMember))
  have valuesRelated := claim.value.dynamicRelationHolds_of_checked context world
    sourceInvariant range claim.relation.kind valueChecked valueCompatible
    originalState candidateState related
  have worldDynamicValid : world.dynamicRangesValid context = true := by
    have worldValid := related.1
    simp only [RelationalWorld.valid, Bool.and_eq_true] at worldValid
    exact worldValid.1.1.1.1
  have staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true := by
    rcases contextValid with
      ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _⟩
    exact slotsValid
  have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
    rcases contextValid with
      ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
    exact slotsValid
  have sourceActiveAvailable : claim.sourceRelation.activeWords.all
      range.wordRelations.contains = true := by
    simp only [List.all_eq_true] at sourceRequiredWords sourceActiveSubset ⊢
    intro word wordMember
    exact sourceRequiredWords word
      (List.contains_iff_mem.mp (sourceActiveSubset word wordMember))
  have targetWordsHold := dynamicWordRequirementsHold_after_single_dynamic_write
    context world range claim.relation claim.sourceRelation.activeWords
    claim.targetRelation.activeWords originalState.memory candidateState.memory
    (claim.value.original.eval originalState)
    (claim.value.candidate.eval candidateState) worldDynamicValid rangeMember
    relationInRange sourceActiveAvailable targetCovered sourceWordsHold valuesRelated
  have stackRangesValid : world.stackRangesValid context = true := related.2.1
  rcases pairedPreparedWordUpdates_of_checkedItems context world sourceInvariant
      claim.suffix originalState candidateState stackRangesValid suffixChecked related with
    ⟨suffixUpdates, originalSuffixWrites, candidateSuffixWrites, _suffixKinds⟩
  have targetActiveAvailable : claim.targetRelation.activeWords.all
      range.wordRelations.contains = true := by
    simp only [List.all_eq_true, Bool.or_eq_true, beq_iff_eq]
        at targetCovered sourceRequiredWords sourceActiveSubset ⊢
    intro word wordMember
    rcases targetCovered word wordMember with same | sourceActive
    · subst word
      exact List.contains_iff_mem.mpr relationInRange
    · exact sourceRequiredWords word
        (List.contains_iff_mem.mp
          (sourceActiveSubset word (List.contains_iff_mem.mp sourceActive)))
  have targetWordsAfterSuffix := dynamicWordRequirementsHold_after_prepared_updates
    context world range claim.targetRelation.activeWords
    (originalState.memory.write32
      (range.originalBase + BitVec.ofNat 32 claim.relation.offset)
      (claim.value.original.eval originalState))
    (candidateState.memory.write32
      (range.candidateBase + BitVec.ofNat 32 claim.relation.offset)
      (claim.value.candidate.eval candidateState))
    suffixUpdates worldDynamicValid staticPointerSlotsValid staticWordSlotsValid
    rangeMember targetActiveAvailable targetWordsHold
  rw [originalSuffixWrites, candidateSuffixWrites] at targetWordsAfterSuffix
  unfold DynamicRegisterRangeRelation.activeHolds
  simp only [List.any_eq_true]
  refine ⟨range, rangeMember, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, targetActiveRequired⟩, ?_⟩
  · simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_x87Effect,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      originalRegister, Expr.eval]
    rw [← originalOffset]
    exact sourceOriginalRegister
  · simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_x87Effect,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      candidateRegister, Expr.eval]
    rw [← candidateOffset]
    exact sourceCandidateRegister
  · simp only [List.all_eq_true] at sourceRequiredWords requiredWordsSubset ⊢
    intro word wordMember
    exact sourceRequiredWords word
      (by simpa using requiredWordsSubset word wordMember)
  · simp only [PairedPreparedWordWritesClaim.originalSymbolicWrites,
      PairedPreparedWordWritesClaim.candidateSymbolicWrites] at originalWrites candidateWrites
    rw [writesExact] at originalWrites candidateWrites
    simp only [
      DynamicRegisterRangeActivateClaim.item,
      PairedPreparedWordWritesClaim.originalWrites,
      PairedPreparedWordWritesClaim.candidateWrites,
      PairedPreparedWordWriteItem.originalAddress,
      PairedPreparedWordWriteItem.candidateAddress,
      PairedPreparedWordWriteItem.value, List.map_cons]
        at originalWrites candidateWrites
    simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_x87Effect,
      NormalizedSymbolicBehavior.eval_writes]
    rw [originalWrites, candidateWrites]
    simp only [evalNormalizedWrites, List.map_cons, List.map_map,
      Function.comp_apply,
      applyConcreteWrites, List.foldl, pairedDynamicWordAddress_eval]
    rw [sourceOriginalRegister, sourceCandidateRegister]
    simp only [BitVec.add_assoc, ← BitVec.ofNat_add]
    rw [originalRelationOffset, candidateRelationOffset]
    exact targetWordsAfterSuffix

structure DynamicStackRangeReloadClaim where
  sourceRelation : DynamicStackRangeRelation
  targetRelation : DynamicRegisterRangeRelation
deriving Repr, DecidableEq

def DynamicStackRangeReloadClaim.originalExpression
    (claim : DynamicStackRangeReloadClaim) : Expr :=
  .read32 ((Expr.inputReg claim.sourceRelation.window.originalRegister).offset
    claim.sourceRelation.stackOffset)

def DynamicStackRangeReloadClaim.candidateExpression
    (claim : DynamicStackRangeReloadClaim) : Expr :=
  .read32 ((Expr.inputReg claim.sourceRelation.window.candidateRegister).offset
    claim.sourceRelation.stackOffset)

def DynamicStackRangeReloadClaim.checked
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicStackRangeReloadClaim) : Bool :=
  sourceInvariant.dynamicStackRangeRelations.contains claim.sourceRelation &&
    targetInvariant.dynamicRegisterRangeRelations.contains claim.targetRelation &&
    claim.targetRelation.originalOffset == claim.sourceRelation.originalOffset &&
    claim.targetRelation.candidateOffset == claim.sourceRelation.candidateOffset &&
    claim.targetRelation.requiredWords.all
      claim.sourceRelation.requiredWords.contains &&
    claim.targetRelation.activeWords.all
      claim.sourceRelation.activeWords.contains &&
    claim.targetRelation.activeWords.all
      claim.targetRelation.requiredWords.contains &&
    originalBehavior.registers.get claim.targetRelation.original ==
      claim.originalExpression &&
    candidateBehavior.registers.get claim.targetRelation.candidate ==
      claim.candidateExpression

theorem dynamicStackRangeReloadOutputHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicStackRangeReloadClaim)
    (checked : claim.checked sourceInvariant targetInvariant originalBehavior
      candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.targetRelation.holds world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  simp only [DynamicStackRangeReloadClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨⟨sourceMember, _targetMember⟩, originalOffset⟩,
      candidateOffset⟩, requiredWordsSubset⟩, _activeWordsSubset⟩,
      targetActiveSubset⟩, originalRegister⟩, candidateRegister⟩
  have dynamicStacks := related.dynamicStackRangesHold context world
    sourceInvariant originalState candidateState
  simp only [dynamicStackRangeRelationsHold, List.all_eq_true] at dynamicStacks
  have sourceHolds := dynamicStacks claim.sourceRelation
    (by simpa using sourceMember)
  simp only [DynamicStackRangeRelation.holds, Bool.and_eq_true,
    List.any_eq_true, beq_iff_eq] at sourceHolds
  rcases sourceHolds with
    ⟨_windowHolds, sourceRange, sourceRangeMember,
      ⟨⟨⟨originalRead, candidateRead⟩, sourceRequiredWords⟩,
        _sourceActiveSubset⟩⟩
  unfold DynamicRegisterRangeRelation.holds
  simp only [List.any_eq_true]
  refine ⟨sourceRange, sourceRangeMember, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨⟨?_, ?_⟩, ?_⟩, targetActiveSubset⟩
  · simp only [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, originalRegister,
      DynamicStackRangeReloadClaim.originalExpression, Expr.eval,
      evalInputRegisterOffset, machineStateRead32_eq_memoryRead32]
    rw [originalRead, originalOffset]
  · simp only [NormalizedSymbolicBehavior.eval_registers,
      evalNormalizedRegisters_get, candidateRegister,
      DynamicStackRangeReloadClaim.candidateExpression, Expr.eval,
      evalInputRegisterOffset, machineStateRead32_eq_memoryRead32]
    rw [candidateRead, candidateOffset]
  · simp only [List.all_eq_true] at sourceRequiredWords requiredWordsSubset ⊢
    intro word wordMember
    exact sourceRequiredWords word
      (by simpa using requiredWordsSubset word wordMember)

theorem dynamicStackRangeReloadOutputActiveHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicStackRangeReloadClaim)
    (checked : claim.checked sourceInvariant targetInvariant originalBehavior
      candidateBehavior = true)
    (originalWrites : originalBehavior.writes = [])
    (candidateWrites : candidateBehavior.writes = [])
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.targetRelation.activeHolds context world
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true := by
  simp only [DynamicStackRangeReloadClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨⟨sourceMember, _targetMember⟩, originalOffset⟩,
      candidateOffset⟩, requiredWordsSubset⟩, activeWordsSubset⟩,
      targetActiveSubset⟩, originalRegister⟩, candidateRegister⟩
  have sourceRelations := related.activeDynamicStackRangesHold context world
    sourceInvariant originalState candidateState
  simp only [activeDynamicStackRangeRelationsHold, List.all_eq_true]
      at sourceRelations
  have sourceHolds := sourceRelations claim.sourceRelation
    (by simpa using sourceMember)
  simp only [DynamicStackRangeRelation.activeHolds, Bool.and_eq_true,
    List.any_eq_true, beq_iff_eq] at sourceHolds
  rcases sourceHolds with
    ⟨_windowHolds, range, rangeMember,
      ⟨⟨⟨⟨originalRead, candidateRead⟩, sourceRequiredWords⟩,
        _sourceActiveSubset⟩, sourceWordsHold⟩⟩
  unfold DynamicRegisterRangeRelation.activeHolds
  simp only [List.any_eq_true]
  refine ⟨range, rangeMember, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, targetActiveSubset⟩, ?_⟩
  · simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_x87Effect,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      originalRegister, DynamicStackRangeReloadClaim.originalExpression,
      Expr.eval, evalInputRegisterOffset, machineStateRead32_eq_memoryRead32]
    rw [originalRead, originalOffset]
  · simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_x87Effect,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      candidateRegister, DynamicStackRangeReloadClaim.candidateExpression,
      Expr.eval, evalInputRegisterOffset, machineStateRead32_eq_memoryRead32]
    rw [candidateRead, candidateOffset]
  · simp only [List.all_eq_true] at sourceRequiredWords requiredWordsSubset ⊢
    intro word wordMember
    exact sourceRequiredWords word
      (by simpa using requiredWordsSubset word wordMember)
  · have targetWordsHold := dynamicWordRequirementsHold_mono context world range
        claim.sourceRelation.activeWords claim.targetRelation.activeWords
        originalState.memory candidateState.memory activeWordsSubset sourceWordsHold
    simpa [RelationalBehavior.nextMachineState, originalWrites, candidateWrites]
      using targetWordsHold

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
    claim.rangeRelation.activeWords.contains claim.wordRelation &&
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
  have dynamicRegisters := related.activeDynamicRegisterRangesHold context world
    sourceInvariant originalState candidateState
  simp only [activeDynamicRegisterRangeRelationsHold, List.all_eq_true]
      at dynamicRegisters
  have rangeHolds := dynamicRegisters claim.rangeRelation
    (by simpa using sourceMember)
  simp only [DynamicRegisterRangeRelation.activeHolds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at rangeHolds
  rcases rangeHolds with
    ⟨range, rangeMember,
      ⟨⟨⟨⟨originalRegister, candidateRegister⟩, _requiredWords⟩,
        _activeWordsSubset⟩, activeWordsHold⟩⟩
  simp only [dynamicWordRequirementsHold, List.all_eq_true,
    Bool.and_eq_true] at activeWordsHold
  have wordHolds := (activeWordsHold claim.wordRelation
    (by simpa using wordMember)).2
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
    claim.targetRelation.activeWords.isEmpty &&
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
      ⟨⟨⟨⟨⟨⟨⟨⟨⟨slotMember, _targetMember⟩, _targetOriginalOffset⟩,
        _targetCandidateOffset⟩, _targetWordsSubset⟩, _targetActiveSubset⟩,
        _originalRegister⟩, _candidateRegister⟩, originalGuardExact⟩,
        candidateGuardExact⟩
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
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨slotMember, _targetMember⟩, targetOriginalOffset⟩,
      targetCandidateOffset⟩, targetWordsSubset⟩, targetActiveEmpty⟩,
      originalRegister⟩, candidateRegister⟩, originalGuardExact⟩,
      _candidateGuardExact⟩
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
    refine ⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩
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
    · simp only [List.isEmpty_iff] at targetActiveEmpty
      simp [targetActiveEmpty]

theorem staticDynamicPointerSeedOutputActiveHolds_of_checked
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
    claim.targetRelation.activeHolds context world
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true := by
  have location := staticDynamicPointerSeedOutputHolds_of_checked context world
    sourceInvariant targetInvariant originalBehavior candidateBehavior originalGuard
    candidateGuard claim checked originalState candidateState related guardTrue
  have empty : claim.targetRelation.activeWords = [] := by
    simp only [StaticDynamicPointerSeedClaim.checked, Bool.and_eq_true,
      List.isEmpty_iff] at checked
    rcases checked with
      ⟨⟨⟨⟨⟨⟨⟨⟨⟨_slot, _target⟩, _originalOffset⟩,
        _candidateOffset⟩, _required⟩, activeEmpty⟩, _originalRegister⟩,
        _candidateRegister⟩, _originalGuard⟩, _candidateGuard⟩
    exact activeEmpty
  apply claim.targetRelation.activeHolds_of_holds_empty context world _ _ empty
  simpa [RelationalBehavior.nextMachineState] using location

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
    claim.sourceRelation.activeWords.contains claim.pointerRelation &&
    claim.targetRelation.requiredWords.all
      claim.sourceRelation.requiredWords.contains &&
    claim.targetRelation.activeWords.isEmpty &&
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
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨sourceMember, _targetMember⟩, sourceOriginalOffset⟩,
      sourceCandidateOffset⟩, _targetOriginalOffset⟩, _targetCandidateOffset⟩,
      pointerMember⟩, _targetWordsSubset⟩, _targetActiveEmpty⟩, _originalRegister⟩,
      _candidateRegister⟩, originalGuardExact⟩, candidateGuardExact⟩
  have activeRegisters := related.activeDynamicRegisterRangesHold context world
    sourceInvariant originalState candidateState
  simp only [activeDynamicRegisterRangeRelationsHold, List.all_eq_true]
      at activeRegisters
  have sourceHolds := activeRegisters claim.sourceRelation
    (by simpa using sourceMember)
  simp only [DynamicRegisterRangeRelation.activeHolds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at sourceHolds
  rcases sourceHolds with
    ⟨sourceRange, sourceRangeMember,
      ⟨⟨⟨⟨sourceOriginalRegister, sourceCandidateRegister⟩,
        sourceRequiredWords⟩, sourceActiveSubset⟩, activeWordsHold⟩⟩
  rw [sourceOriginalOffset] at sourceOriginalRegister
  rw [sourceCandidateOffset] at sourceCandidateRegister
  simp [BitVec.add_zero] at sourceOriginalRegister sourceCandidateRegister
  simp only [dynamicWordRequirementsHold, List.all_eq_true,
    Bool.and_eq_true] at activeWordsHold
  have pointerHolds := (activeWordsHold claim.pointerRelation
    (by simpa using pointerMember)).2
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
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨sourceMember, _targetMember⟩, sourceOriginalOffset⟩,
      sourceCandidateOffset⟩, targetOriginalOffset⟩, targetCandidateOffset⟩,
      pointerMember⟩, targetWordsSubset⟩, targetActiveEmpty⟩, originalRegister⟩,
      candidateRegister⟩, originalGuardExact⟩, _candidateGuardExact⟩
  have dynamicRegisters := related.activeDynamicRegisterRangesHold context world
    sourceInvariant originalState candidateState
  simp only [activeDynamicRegisterRangeRelationsHold, List.all_eq_true]
      at dynamicRegisters
  have sourceHolds := dynamicRegisters claim.sourceRelation
    (by simpa using sourceMember)
  simp only [DynamicRegisterRangeRelation.activeHolds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at sourceHolds
  rcases sourceHolds with
    ⟨sourceRange, sourceRangeMember,
      ⟨⟨⟨⟨sourceOriginalRegister, sourceCandidateRegister⟩,
        sourceRequiredWords⟩, sourceActiveSubset⟩, activeWordsHold⟩⟩
  rw [sourceOriginalOffset] at sourceOriginalRegister
  rw [sourceCandidateOffset] at sourceCandidateRegister
  simp [BitVec.add_zero] at sourceOriginalRegister sourceCandidateRegister
  simp only [dynamicWordRequirementsHold, List.all_eq_true,
    Bool.and_eq_true] at activeWordsHold
  have pointerHolds := (activeWordsHold claim.pointerRelation
    (by simpa using pointerMember)).2
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
    refine ⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩
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
    · simp only [List.isEmpty_iff] at targetActiveEmpty
      simp [targetActiveEmpty]

theorem dynamicRegisterRangeNextOutputActiveHolds_of_checked
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
    claim.targetRelation.activeHolds context world
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState) = true := by
  have location := dynamicRegisterRangeNextOutputHolds_of_checked context world
    sourceInvariant targetInvariant originalBehavior candidateBehavior originalGuard
    candidateGuard claim checked originalState candidateState related guardTrue
  have empty : claim.targetRelation.activeWords = [] := by
    simp only [DynamicRegisterRangeNextClaim.checked, Bool.and_eq_true,
      List.isEmpty_iff] at checked
    rcases checked with
      ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨_source, _target⟩, _sourceOriginal⟩,
        _sourceCandidate⟩, _targetOriginal⟩, _targetCandidate⟩,
        _pointer⟩, _required⟩, activeEmpty⟩, _originalRegister⟩,
        _candidateRegister⟩, _originalGuard⟩, _candidateGuard⟩
    exact activeEmpty
  apply claim.targetRelation.activeHolds_of_holds_empty context world _ _ empty
  simpa [RelationalBehavior.nextMachineState] using location

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

def _root_.StageA.Formal.BoolExpr.exactInputsOnly
    (context : StaticProofContext) (invariant : StateInvariant) : BoolExpr -> Bool
  | .equal left right | .unsignedLess left right =>
      left.exactInputsOnly context invariant && right.exactInputsOnly context invariant
  | .not value => value.exactInputsOnly context invariant
  | .and left right | .or left right | .xor left right =>
      left.exactInputsOnly context invariant && right.exactInputsOnly context invariant
  | .msb value | .bit value _ => value.exactInputsOnly context invariant
  | .inputFlag bit => invariant.flagBits.contains bit
  | .divisionValid high low divisor =>
      high.exactInputsOnly context invariant && low.exactInputsOnly context invariant &&
        divisor.exactInputsOnly context invariant

theorem _root_.StageA.Formal.BoolExpr.eval_eq_of_exactInputsOnly
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (expression : BoolExpr)
    (checked : expression.exactInputsOnly context invariant = true)
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

def ExactPureGuardClaim.checked (context : StaticProofContext)
    (sourceInvariant : StateInvariant)
    (originalGuard candidateGuard : BoolExpr) (claim : ExactPureGuardClaim) : Bool :=
  claim.guard == originalGuard && claim.guard == candidateGuard &&
    claim.guard.exactInputsOnly context sourceInvariant

theorem exactPureGuard_eval_equal_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (originalGuard candidateGuard : BoolExpr)
    (claim : ExactPureGuardClaim)
    (checked : claim.checked context sourceInvariant originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalGuard.eval originalState = candidateGuard.eval candidateState := by
  simp only [ExactPureGuardClaim.checked, Bool.and_eq_true, beq_iff_eq] at checked
  rcases checked with ⟨⟨originalExact, candidateExact⟩, exactInputs⟩
  rw [← originalExact, ← candidateExact]
  exact BoolExpr.eval_eq_of_exactInputsOnly context world sourceInvariant
    originalState candidateState claim.guard exactInputs related

structure PairedExactGuardClaim where
  originalGuard : BoolExpr
  candidateGuard : BoolExpr
  witness : PairedExactExprWitness
deriving Repr, DecidableEq

def PairedExactGuardClaim.checked (context : StaticProofContext)
    (sourceInvariant : StateInvariant)
    (originalGuard candidateGuard : BoolExpr)
    (claim : PairedExactGuardClaim) : Bool :=
  claim.originalGuard == originalGuard && claim.candidateGuard == candidateGuard &&
    claim.witness.expression .original == claim.originalGuard.toWord &&
    claim.witness.expression .candidate == claim.candidateGuard.toWord &&
    claim.witness.checked context sourceInvariant

theorem pairedExactGuard_eval_equal_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (originalGuard candidateGuard : BoolExpr)
    (claim : PairedExactGuardClaim)
    (checked : claim.checked context sourceInvariant
      originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalGuard.eval originalState = candidateGuard.eval candidateState := by
  simp only [PairedExactGuardClaim.checked, Bool.and_eq_true, beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨originalExact, candidateExact⟩, originalWitnessExact⟩,
      candidateWitnessExact⟩, witnessChecked⟩
  have wordsEqual := claim.witness.eval_equal_of_checked context world sourceInvariant
    originalState candidateState witnessChecked related
  rw [originalWitnessExact, candidateWitnessExact,
    BoolExpr.eval_toWord, BoolExpr.eval_toWord] at wordsEqual
  rw [← originalExact, ← candidateExact]
  cases originalResult : claim.originalGuard.eval originalState <;>
    cases candidateResult : claim.candidateGuard.eval candidateState <;> simp_all

def normalizedCarryIsInput : Option FlagsExpr -> Bool
  | none => true
  | some flags => flags.carry == some (.inputFlag 0)

def normalizedParityIsInput : Option FlagsExpr -> Bool
  | none => true
  | some flags => flags.parity == some (.inputFlag 2)

def normalizedAuxiliaryIsInput : Option FlagsExpr -> Bool
  | none => true
  | some flags => flags.auxiliary == some (.inputFlag 4)

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

theorem evalNormalizedFlags_extract_af_input_of_checked
    (state : MachineState) (flags : Option FlagsExpr)
    (checked : normalizedAuxiliaryIsInput flags = true) :
    (evalNormalizedFlags state flags).extractLsb' 4 1 =
      state.eflags.extractLsb' 4 1 := by
  cases flags with
  | none => rfl
  | some flags =>
      simp only [normalizedAuxiliaryIsInput, beq_iff_eq] at checked
      simp only [evalNormalizedFlags_some, FlagsExpr.eval_extract_af, checked,
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

def addressWordZeroGuard (address : Expr) (masked : Bool) : BoolExpr :=
  let value : Expr := .read32 address
  .equal (if masked then .bitAnd value value else value) (.constant 0)

def addressWordZeroGuardWithNots (address : Expr) (masked : Bool)
    (notCount : Nat) : BoolExpr :=
  applyBoolNots notCount (addressWordZeroGuard address masked)

structure StackWordZeroRelativeGuardClaim where
  window : StackWindowPair
  adjustment : StackAdjustment
  originalAddress : Expr
  candidateAddress : Expr
  masked : Bool
  notCount : Nat
deriving Repr, DecidableEq

def StackWordZeroRelativeGuardClaim.adjustmentChecked
    (claim : StackWordZeroRelativeGuardClaim) : Bool :=
  match claim.adjustment with
  | .identity => decide (4 <= claim.window.bytesAbove)
  | .add amount =>
      decide (amount + 4 <= claim.window.bytesAbove) && amount % 4 == 0
  | .subtract amount =>
      decide (4 <= amount) && decide (amount <= claim.window.bytesBelow) &&
        amount % 4 == 0

def StackWordZeroRelativeGuardClaim.checked (sourceInvariant : StateInvariant)
    (originalGuard candidateGuard : BoolExpr)
    (claim : StackWordZeroRelativeGuardClaim) : Bool :=
  sourceInvariant.stackWindows.contains claim.window &&
    claim.adjustmentChecked &&
    claim.adjustment.expressionMatches claim.window.originalRegister
      claim.originalAddress &&
    claim.adjustment.expressionMatches claim.window.candidateRegister
      claim.candidateAddress &&
    originalGuard == addressWordZeroGuardWithNots
      claim.originalAddress claim.masked claim.notCount &&
    candidateGuard == addressWordZeroGuardWithNots
      claim.candidateAddress claim.masked claim.notCount

theorem stackWordZeroRelativeGuard_eval_equal_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (originalGuard candidateGuard : BoolExpr)
    (claim : StackWordZeroRelativeGuardClaim)
    (checked : claim.checked sourceInvariant originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalGuard.eval originalState = candidateGuard.eval candidateState := by
  rcases claim with
    ⟨window, adjustment, originalAddress, candidateAddress, masked, notCount⟩
  simp only [StackWordZeroRelativeGuardClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨windowMember, adjustmentChecked⟩, originalAddressMatches⟩,
      candidateAddressMatches⟩, originalGuardExact⟩, candidateGuardExact⟩
  have originalAddressEval := adjustment.eval_expression_of_matches
    window.originalRegister originalAddress originalState originalAddressMatches
  have candidateAddressEval := adjustment.eval_expression_of_matches
    window.candidateRegister candidateAddress candidateState candidateAddressMatches
  have readsRelated :
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        (Memory.read32 originalState.memory
          ((adjustment.expression window.originalRegister).eval originalState))
        (Memory.read32 candidateState.memory
          ((adjustment.expression window.candidateRegister).eval candidateState)) =
        true := by
    cases adjustment with
    | identity =>
        simp only [StackWordZeroRelativeGuardClaim.adjustmentChecked,
          decide_eq_true_eq] at adjustmentChecked
        have read := StateRel.stackMemoryRead32Related context world sourceInvariant
          originalState candidateState window 0 related
          (List.contains_iff_mem.mp windowMember) adjustmentChecked (by decide)
        simpa [StackAdjustment.expression, Expr.eval] using read
    | add amount =>
        simp only [StackWordZeroRelativeGuardClaim.adjustmentChecked,
          Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at adjustmentChecked
        have read := StateRel.stackMemoryRead32Related context world sourceInvariant
          originalState candidateState window amount related
          (List.contains_iff_mem.mp windowMember) adjustmentChecked.1
          adjustmentChecked.2
        simpa [StackAdjustment.expression, Expr.eval] using read
    | subtract amount =>
        simp only [StackWordZeroRelativeGuardClaim.adjustmentChecked,
          Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at adjustmentChecked
        have read := StateRel.stackMemoryRead32BelowRelated context world
          sourceInvariant originalState candidateState window amount related
          (List.contains_iff_mem.mp windowMember) adjustmentChecked.1.1
          adjustmentChecked.1.2 adjustmentChecked.2
        simpa [StackAdjustment.expression, Expr.eval] using read
  have actualReadsRelated :
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        (Memory.read32 originalState.memory (originalAddress.eval originalState))
        (Memory.read32 candidateState.memory (candidateAddress.eval candidateState)) =
        true := by
    rw [originalAddressEval, candidateAddressEval]
    exact readsRelated
  have zeroEqual := wordRelated_zero_equal actualReadsRelated
  rw [originalGuardExact, candidateGuardExact]
  apply applyBoolNots_eval_equal notCount
  cases masked with
  | false =>
      simpa only [addressWordZeroGuard, BoolExpr.eval, Expr.eval, if_false,
        machineStateRead32_eq_memoryRead32] using zeroEqual
  | true =>
      simpa only [addressWordZeroGuard, BoolExpr.eval, Expr.eval, if_true,
        machineStateRead32_eq_memoryRead32, BitVec.and_self] using zeroEqual

structure StaticWordZeroGuardClaim where
  slot : StaticWordRelationSlotPair
  originalAddress : Nat
  candidateAddress : Nat
  masked : Bool
  notCount : Nat
deriving Repr, DecidableEq

def StaticWordZeroGuardClaim.checked (context : StaticProofContext)
    (originalGuard candidateGuard : BoolExpr)
    (claim : StaticWordZeroGuardClaim) : Bool :=
  context.staticWordRelationSlots.contains claim.slot &&
    claim.slot.originalAddress == BitVec.ofNat 32 claim.originalAddress &&
    claim.slot.candidateAddress == BitVec.ofNat 32 claim.candidateAddress &&
    (claim.slot.relation == .exact || claim.slot.relation == .relatedWord) &&
    originalGuard == addressWordZeroGuardWithNots
      (.constant claim.originalAddress) claim.masked claim.notCount &&
    candidateGuard == addressWordZeroGuardWithNots
      (.constant claim.candidateAddress) claim.masked claim.notCount

theorem staticWordZeroGuard_eval_equal_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (originalGuard candidateGuard : BoolExpr)
    (claim : StaticWordZeroGuardClaim)
    (checked : claim.checked context originalGuard candidateGuard = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    originalGuard.eval originalState = candidateGuard.eval candidateState := by
  simp only [StaticWordZeroGuardClaim.checked, Bool.and_eq_true,
    Bool.or_eq_true, beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨slotMember, originalAddress⟩, candidateAddress⟩,
      supportedRelation⟩, originalGuardExact⟩, candidateGuardExact⟩
  have slotsHold := related.staticWordRelationSlotsMemoryHold context world
    sourceInvariant originalState candidateState
  have slotHolds := slotsHold claim.slot (List.contains_iff_mem.mp slotMember)
  simp only [StaticWordRelationSlotPair.memoryHolds] at slotHolds
  have compatible : InvariantWP.staticWordRelationSupportsRegisterValueRelation
      claim.slot.relation .relatedWord = true := by
    rcases supportedRelation with exactRelation | relatedRelation
    · rw [exactRelation]
      decide
    · rw [relatedRelation]
      decide
  have readsRelated :=
    InvariantWP.StaticWordRelationKind.registerValueRelation_holds_of_holds context world
      claim.slot.relation .relatedWord _ _ compatible slotHolds
  simp only [RegisterValueRelation.holds] at readsRelated
  rw [originalAddress, candidateAddress] at readsRelated
  have zeroEqual := wordRelated_zero_equal readsRelated
  rw [originalGuardExact, candidateGuardExact]
  apply applyBoolNots_eval_equal claim.notCount
  cases claim.masked with
  | false =>
      simpa only [addressWordZeroGuard, BoolExpr.eval, Expr.eval, if_false,
        machineStateRead32_eq_memoryRead32] using zeroEqual
  | true =>
      simpa only [addressWordZeroGuard, BoolExpr.eval, Expr.eval, if_true,
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
  if taken then condition else
    match condition with
    | .not value => value
    | _ => .not condition

theorem normalizedBranchGuard_eval_of_condition
    (condition : BoolExpr) (taken : Bool) (state : MachineState)
    (conditionValue : condition.eval state = taken) :
    (normalizedBranchGuard condition taken).eval state = true := by
  cases taken with
  | true => simpa [normalizedBranchGuard] using conditionValue
  | false =>
      cases condition <;>
        simp [normalizedBranchGuard, BoolExpr.eval] at conditionValue ⊢
      all_goals try assumption
      case and left right =>
        cases leftValue : left.eval state <;>
          cases rightValue : right.eval state <;>
          simp_all

theorem normalizedBranchCondition_eval_of_guard_true
    (condition guard : BoolExpr) (taken : Bool) (state : MachineState)
    (guardShape : guard = normalizedBranchGuard condition taken)
    (guardTrue : guard.eval state = true) :
    condition.eval state = taken := by
  rw [guardShape] at guardTrue
  cases taken with
  | false =>
      by_cases isNot : ∃ value, condition = .not value
      · rcases isNot with ⟨value, rfl⟩
        change value.eval state = true at guardTrue
        simp [BoolExpr.eval, guardTrue]
      · have normalized :
            normalizedBranchGuard condition false = .not condition := by
          simp only [normalizedBranchGuard]
          cases condition <;> simp_all
        rw [normalized] at guardTrue
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
    (claim.valueRelation.impliesExact || claim.valueRelation == .relatedWord) &&
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
  simp only [RelatedWordZeroGuardClaim.checked, Bool.and_eq_true, Bool.or_eq_true,
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
    rcases supportedRelation with exactLike | relatedRelation
    · have registersEqual := RegisterValueRelation.holds_eq_of_impliesExact
        context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        claim.valueRelation _ _ exactLike relationHolds
      rw [registersEqual]
    · rw [relatedRelation] at relationHolds
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
        some [RelationalDecodedControlEdge.mk .branchTaken taken
            (normalizedBranchGuard condition true),
          RelationalDecodedControlEdge.mk .branchFallthrough fallthrough
            (normalizedBranchGuard condition false)]
  | .call target _ | .callUnmappedReturn target =>
      some [RelationalDecodedControlEdge.mk .call target
      unconditionalProductGuard]
  | .externalCall _ _ continuation =>
      some [RelationalDecodedControlEdge.mk .externalCall continuation
        unconditionalProductGuard]
  | .bulkCopy _ _ _ _ continuation =>
      some [RelationalDecodedControlEdge.mk .bulkCopy continuation
        unconditionalProductGuard]
  | .bulkFill _ _ _ _ continuation =>
      some [RelationalDecodedControlEdge.mk .bulkFill continuation
        unconditionalProductGuard]
  | .bulkScan _ _ _ _ continuation =>
      some [RelationalDecodedControlEdge.mk .bulkScan continuation
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
      let kind := if candidate then edge.candidateKind else edge.kind
      pure (RelationalDecodedControlEdge.mk kind edge.targetTargetId guard :: rest)

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
      match graph.resolveOutgoingControlEdges false node.outgoingEdgeIds,
          graph.resolveOutgoingControlEdges true node.outgoingEdgeIds with
      | some submittedOriginal, some submittedCandidate =>
          decide (submittedOriginal.Perm originalEdges) &&
            decide (submittedCandidate.Perm candidateEdges)
      | _, _ => false
  | _, _, _ => false

/-- Control closure for an x87 singleton is derived from the exact PE bytes and
the reviewed physical x87 decoder.  The ordinary symbolic decoder deliberately
does not assign x87 fault behavior, so it must not be used for this purpose. -/
def x87SingletonControlEdgesMatch (graph : RelationalProductGraph) (nodeId : Nat)
    (region : RegionRelation) : Bool :=
  match graph.getNode? nodeId,
      normalizeCodeTarget false region.targets region.original.stop,
      normalizeCodeTarget true region.targets region.candidate.stop with
  | some node, some originalContinuation, some candidateContinuation =>
      graph.resolveOutgoingControlEdges false node.outgoingEdgeIds ==
          some [RelationalDecodedControlEdge.mk .jump originalContinuation
            unconditionalProductGuard] &&
        graph.resolveOutgoingControlEdges true node.outgoingEdgeIds ==
          some [RelationalDecodedControlEdge.mk .jump candidateContinuation
            unconditionalProductGuard]
  | _, _, _ => false

def NodeX87SingletonControlEdgesComplete (graph : RelationalProductGraph)
    (nodeId : Nat) (context : StaticProofContext) (region : RegionRelation) : Prop :=
  (StageA.Relational.X87.decodeSingletonCommand context.originalPe
      region.original).isSome = true ∧
    StageA.Relational.X87.decodeSingletonCommand context.originalPe region.original =
      StageA.Relational.X87.decodeSingletonCommand context.candidatePe
        region.candidate ∧
    x87SingletonControlEdgesMatch graph nodeId region = true

def immutableIndirectCallEdgesMatch (graph : RelationalProductGraph) (nodeId : Nat)
    (claim : ImmutableIndirectCallTargetClaim) : Bool :=
  match graph.getNode? nodeId with
  | none => false
  | some node =>
      let expected := some [RelationalDecodedControlEdge.mk .call claim.targetId
        unconditionalProductGuard]
      graph.resolveOutgoingControlEdges false node.outgoingEdgeIds == expected &&
        graph.resolveOutgoingControlEdges true node.outgoingEdgeIds == expected

def indirectExitInternalEdge? (candidate : Bool)
    (context : StaticProofContext) (certificate : IndirectExitCertificate)
    (destination : IndirectDestination) :
    Option RelationalDecodedControlEdge := do
  let .internalCode targetId := destination | none
  let target <- context.codeMap.get? targetId
  let expression :=
    if candidate then certificate.target.candidate
    else certificate.target.original
  let imageBase :=
    if candidate then context.candidatePe.imageBase
    else context.originalPe.imageBase
  let primaryRva :=
    if candidate then target.candidateRva else target.originalRva
  let aliases :=
    if candidate then target.candidateAliases else target.originalAliases
  let guard :=
    if certificate.destinations.length == 1 then unconditionalProductGuard
    else codeTargetProductGuard imageBase expression primaryRva aliases
  let kind :=
    match certificate.transfer with
    | .call _ => RelationalProductEdgeKind.call
    | .jump => RelationalProductEdgeKind.jump
  pure (RelationalDecodedControlEdge.mk kind targetId guard)

/-- Project the destinations that remain inside either PE into the static
product graph.  Opaque callable destinations are external transitions rather
than code-map nodes.  In particular, an external tail resumes the top runtime
call frame, so inventing one fixed graph destination here would be unsound.

This projection is only the decoded intra-image control check.  Final
acceptance separately requires `RunningProductNodeStepRefined`, which must
discharge every opaque destination with exact external/call-frame semantics. -/
def indirectExitIntraProgramEdges? (candidate : Bool)
    (context : StaticProofContext) (certificate : IndirectExitCertificate) :
    List IndirectDestination -> Option (List RelationalDecodedControlEdge)
  | [] => some []
  | destination :: destinations => do
      let rest <- indirectExitIntraProgramEdges? candidate context certificate
        destinations
      match destination with
      | .internalCode _ => do
          let edge <- indirectExitInternalEdge? candidate context certificate
            destination
          pure (edge :: rest)
      | .opaqueResource _ => pure rest
      | .imported _ => none

def indirectExitExpectedEdges? (candidate : Bool)
    (context : StaticProofContext) (certificate : IndirectExitCertificate) :
    Option (List RelationalDecodedControlEdge) :=
  match certificate.destinations, certificate.transfer with
  | [.imported _], .call continuation =>
      some [RelationalDecodedControlEdge.mk .externalCall continuation
        unconditionalProductGuard]
  | destinations, _ =>
      indirectExitIntraProgramEdges? candidate context certificate destinations

/-- The submitted graph is compared with every intra-image edge derived from
the certificate's checked finite destination inventory.  Dynamic external
destinations are intentionally absent from the static graph and remain
mandatory obligations in reachable-node operational refinement. -/
def indirectExitEdgesMatch (graph : RelationalProductGraph) (nodeId : Nat)
    (context : StaticProofContext) (certificate : IndirectExitCertificate) : Bool :=
  match graph.getNode? nodeId,
      indirectExitExpectedEdges? false context certificate,
      indirectExitExpectedEdges? true context certificate with
  | some node, some originalExpected, some candidateExpected =>
      graph.resolveOutgoingControlEdges false node.outgoingEdgeIds ==
          some originalExpected &&
        graph.resolveOutgoingControlEdges true node.outgoingEdgeIds ==
          some candidateExpected
  | _, _, _ => false

def boundedImmutableCodePointerTableCallExpectedEdges (candidate : Bool)
    (claim : BoundedImmutableCodePointerTableCallClaim) :
    List RelationalDecodedControlEdge :=
  claim.rows.map fun row =>
    RelationalDecodedControlEdge.mk .call row.targetId
      (immutableCodePointerTableRowGuard candidate claim row)

def boundedImmutableCodePointerTableCallEdgesMatch
    (graph : RelationalProductGraph) (nodeId : Nat)
    (claim : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  match graph.getNode? nodeId with
  | none => false
  | some node =>
      graph.resolveOutgoingControlEdges false node.outgoingEdgeIds ==
          some (boundedImmutableCodePointerTableCallExpectedEdges false claim) &&
        graph.resolveOutgoingControlEdges true node.outgoingEdgeIds ==
          some (boundedImmutableCodePointerTableCallExpectedEdges true claim)

def boundedImmutableRelocationTableJumpExpectedEdges (candidate : Bool)
    (context : StaticProofContext)
    (claim : BoundedImmutableRelocationTableJumpControlClaim) :
    Option (List RelationalDecodedControlEdge) :=
  claim.table.finiteTargetIds.mapM fun targetId => do
    let target <- context.codeMap.entries.toList.find? (fun item => item.id == targetId)
    let imageBase := if candidate then context.candidatePe.imageBase
      else context.originalPe.imageBase
    let targetExpression := if candidate then
      immutableCodePointerTableTargetExpression claim.table.candidateBase
        claim.table.candidateIndex
    else
      immutableCodePointerTableTargetExpression claim.table.originalBase
        claim.table.originalIndex
    let primaryRva := if candidate then target.candidateRva else target.originalRva
    let aliases := if candidate then target.candidateAliases else target.originalAliases
    pure (RelationalDecodedControlEdge.mk .jump targetId
      (codeTargetProductGuard imageBase targetExpression primaryRva aliases))

def boundedImmutableRelocationTableJumpEdgesMatch
    (graph : RelationalProductGraph) (nodeId : Nat) (context : StaticProofContext)
    (claim : BoundedImmutableRelocationTableJumpControlClaim) : Bool :=
  match graph.getNode? nodeId,
      boundedImmutableRelocationTableJumpExpectedEdges false context claim,
      boundedImmutableRelocationTableJumpExpectedEdges true context claim with
  | some node, some originalExpected, some candidateExpected =>
      graph.resolveOutgoingControlEdges false node.outgoingEdgeIds ==
          some originalExpected &&
        graph.resolveOutgoingControlEdges true node.outgoingEdgeIds ==
          some candidateExpected
  | _, _, _ => false

def immutableIndirectJumpEdgesMatch (graph : RelationalProductGraph) (nodeId : Nat)
    (claim : ImmutableIndirectJumpTargetClaim) : Bool :=
  match graph.getNode? nodeId with
  | none => false
  | some node =>
      let expected := some [RelationalDecodedControlEdge.mk .jump claim.targetId
        unconditionalProductGuard]
      graph.resolveOutgoingControlEdges false node.outgoingEdgeIds == expected &&
        graph.resolveOutgoingControlEdges true node.outgoingEdgeIds == expected

def fixedCodeAddressIndirectJumpEdgesMatch (graph : RelationalProductGraph)
    (nodeId targetId : Nat) : Bool :=
  match graph.getNode? nodeId with
  | none => false
  | some node =>
      let expected := some [RelationalDecodedControlEdge.mk .jump targetId
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

def fixedCodePointerRegisterIndirectCallEdgesMatch (graph : RelationalProductGraph)
    (nodeId : Nat) (claim : FixedCodePointerRegisterIndirectCallClaim) : Bool :=
  match graph.getNode? nodeId with
  | none => false
  | some node =>
      let expected := some [RelationalDecodedControlEdge.mk .call claim.targetId
        unconditionalProductGuard]
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

def NodeIndirectExitEdgesComplete (graph : RelationalProductGraph)
    (nodeId : Nat) (context : StaticProofContext) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (checked : CheckedIndirectExitCertificate context region.inputInvariant
      originalNormalized candidateNormalized) : Prop :=
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
    indirectExitEdgesMatch graph nodeId context checked.certificate = true

theorem nodeIndirectExitEdgesComplete
    (graph : RelationalProductGraph) (nodeId : Nat)
    (context : StaticProofContext) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (checked : CheckedIndirectExitCertificate context region.inputInvariant
      originalNormalized candidateNormalized)
    (originalDecoded :
      regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
        context.machineImportCallContracts region.original = some originalBehavior)
    (candidateDecoded :
      regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
        context.machineImportCallContracts region.candidate = some candidateBehavior)
    (originalNormalizedChecked :
      normalizeSymbolicBehavior false region.targets originalBehavior =
        some originalNormalized)
    (candidateNormalizedChecked :
      normalizeSymbolicBehavior true region.targets candidateBehavior =
        some candidateNormalized)
    (edgesChecked :
      indirectExitEdgesMatch graph nodeId context checked.certificate = true) :
    NodeIndirectExitEdgesComplete graph nodeId context region originalBehavior
      candidateBehavior originalNormalized candidateNormalized checked :=
  ⟨originalDecoded, candidateDecoded, originalNormalizedChecked,
    candidateNormalizedChecked, edgesChecked⟩

def SourceInvariantUninhabited
    (context : StaticProofContext) (sourceInvariant : StateInvariant) : Prop :=
  ∀ world originalState candidateState,
    StateRel context world sourceInvariant originalState candidateState → False

theorem sourceInvariantUninhabited_of_contains
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (contains :
      sourceInvariant.predicates.contains uninhabitedStatePredicate = true) :
    SourceInvariantUninhabited context sourceInvariant := by
  intro world originalState candidateState related
  have bottomHolds := pairedStatePredicatesHold_member
    sourceInvariant.predicates uninhabitedStatePredicate originalState
      candidateState (List.contains_iff_mem.mp contains)
      related.predicatesHold
  simp [uninhabitedStatePredicate, PairedStatePredicate.holds,
    BoolExpr.eval, Expr.eval] at bottomHolds

def noOutgoingControlEdgesMatch
    (graph : RelationalProductGraph) (nodeId : Nat) : Bool :=
  match graph.getNode? nodeId with
  | none => false
  | some node =>
      graph.resolveOutgoingControlEdges false node.outgoingEdgeIds == some [] &&
        graph.resolveOutgoingControlEdges true node.outgoingEdgeIds == some []

def NodeUninhabitedControlEdgesComplete
    (graph : RelationalProductGraph) (nodeId : Nat)
    (context : StaticProofContext) (region : RegionRelation) : Prop :=
  SourceInvariantUninhabited context region.inputInvariant ∧
    noOutgoingControlEdgesMatch graph nodeId = true

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

def NodeBoundedImmutableCodePointerTableCallEdgesComplete
    (graph : RelationalProductGraph) (nodeId : Nat) (context : StaticProofContext)
    (region : RegionRelation) (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableCodePointerTableCallClaim) : Prop :=
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
    boundedImmutableCodePointerTableCallEdgesMatch graph nodeId claim = true ∧
    BoundedImmutableCodePointerTableCallTargetsClosed context region.inputInvariant
      originalNormalized candidateNormalized claim

theorem nodeBoundedImmutableCodePointerTableCallEdgesComplete_of_checked
    (graph : RelationalProductGraph) (nodeId : Nat) (context : StaticProofContext)
    (region : RegionRelation) (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableCodePointerTableCallClaim)
    (structurallyValid : context.StructurallyValid)
    (originalDecoded :
      regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
        context.machineImportCallContracts region.original = some originalBehavior)
    (candidateDecoded :
      regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
        context.machineImportCallContracts region.candidate = some candidateBehavior)
    (originalNormalizedChecked :
      normalizeSymbolicBehavior false region.targets originalBehavior =
        some originalNormalized)
    (candidateNormalizedChecked :
      normalizeSymbolicBehavior true region.targets candidateBehavior =
        some candidateNormalized)
    (claimChecked : claim.checked context region.inputInvariant originalNormalized
      candidateNormalized = true)
    (edgesChecked :
      boundedImmutableCodePointerTableCallEdgesMatch graph nodeId claim = true) :
    NodeBoundedImmutableCodePointerTableCallEdgesComplete graph nodeId context region
      originalBehavior candidateBehavior originalNormalized candidateNormalized claim := by
  refine ⟨originalDecoded, candidateDecoded, originalNormalizedChecked,
    candidateNormalizedChecked, edgesChecked, ?_⟩
  exact boundedImmutableCodePointerTableCallTargetsClosed_of_checked context
    region.inputInvariant originalNormalized candidateNormalized claim structurallyValid
    claimChecked

def NodeBoundedImmutableRelocationTableJumpEdgesComplete
    (graph : RelationalProductGraph) (nodeId : Nat) (context : StaticProofContext)
    (region : RegionRelation) (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableRelocationTableJumpControlClaim) : Prop :=
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
    boundedImmutableRelocationTableJumpEdgesMatch graph nodeId context claim = true ∧
    BoundedImmutableRelocationTableJumpTargetsClosed context region.inputInvariant
      originalNormalized candidateNormalized claim

theorem nodeBoundedImmutableRelocationTableJumpEdgesComplete_of_checked
    (graph : RelationalProductGraph) (nodeId : Nat) (context : StaticProofContext)
    (region : RegionRelation) (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableRelocationTableJumpControlClaim)
    (structurallyValid : context.StructurallyValid)
    (originalDecoded :
      regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
        context.machineImportCallContracts region.original = some originalBehavior)
    (candidateDecoded :
      regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
        context.machineImportCallContracts region.candidate = some candidateBehavior)
    (originalNormalizedChecked :
      normalizeSymbolicBehavior false region.targets originalBehavior =
        some originalNormalized)
    (candidateNormalizedChecked :
      normalizeSymbolicBehavior true region.targets candidateBehavior =
        some candidateNormalized)
    (claimChecked : claim.checked context region.inputInvariant originalNormalized
      candidateNormalized = true)
    (edgesChecked :
      boundedImmutableRelocationTableJumpEdgesMatch graph nodeId context claim = true) :
    NodeBoundedImmutableRelocationTableJumpEdgesComplete graph nodeId context region
      originalBehavior candidateBehavior originalNormalized candidateNormalized claim := by
  refine ⟨originalDecoded, candidateDecoded, originalNormalizedChecked,
    candidateNormalizedChecked, edgesChecked, ?_⟩
  exact boundedImmutableRelocationTableJumpTargetsClosed_of_checked context
    region.inputInvariant originalNormalized candidateNormalized claim structurallyValid
    claimChecked

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

def NodeFixedCodeAddressIndirectJumpEdgesComplete
    (graph : RelationalProductGraph) (nodeId : Nat) (context : StaticProofContext)
    (region : RegionRelation) (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : FixedCodeAddressIndirectJumpTargetClaim) : Prop :=
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
    fixedCodeAddressIndirectJumpEdgesMatch graph nodeId claim.targetId = true ∧
    FixedCodeAddressIndirectJumpTargetsClosed context region.inputInvariant
      originalNormalized candidateNormalized claim

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
    ImportRegisterIndirectCallTargetsClosed context region.inputInvariant originalNormalized
      candidateNormalized claim

def NodeFixedCodePointerRegisterIndirectCallEdgesComplete
    (graph : RelationalProductGraph) (nodeId : Nat) (context : StaticProofContext)
    (region : RegionRelation) (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : FixedCodePointerRegisterIndirectCallClaim) : Prop :=
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
    fixedCodePointerRegisterIndirectCallEdgesMatch graph nodeId claim = true ∧
    FixedCodePointerRegisterIndirectCallTargetsClosed context region.inputInvariant
      originalNormalized candidateNormalized claim

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
    NodeX87SingletonControlEdgesComplete graph nodeId context region ∨
    NodeUninhabitedControlEdgesComplete graph nodeId context region ∨
    (∃ originalNormalized candidateNormalized checked,
      NodeIndirectExitEdgesComplete graph nodeId context region originalBehavior
        candidateBehavior originalNormalized candidateNormalized checked)

theorem nodeControlEdgesComplete_of_checkedIndirectExit
    (graph : RelationalProductGraph) (nodeId : Nat)
    (context : StaticProofContext) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (checked : CheckedIndirectExitCertificate context region.inputInvariant
      originalNormalized candidateNormalized)
    (originalDecoded :
      regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
        context.machineImportCallContracts region.original = some originalBehavior)
    (candidateDecoded :
      regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
        context.machineImportCallContracts region.candidate = some candidateBehavior)
    (originalNormalizedChecked :
      normalizeSymbolicBehavior false region.targets originalBehavior =
        some originalNormalized)
    (candidateNormalizedChecked :
      normalizeSymbolicBehavior true region.targets candidateBehavior =
        some candidateNormalized)
    (edgesChecked :
      indirectExitEdgesMatch graph nodeId context checked.certificate = true) :
    NodeControlEdgesComplete graph nodeId context region originalBehavior
      candidateBehavior :=
  Or.inr (Or.inr (Or.inr ⟨originalNormalized, candidateNormalized, checked,
    nodeIndirectExitEdgesComplete graph nodeId context region originalBehavior
      candidateBehavior originalNormalized candidateNormalized checked
      originalDecoded candidateDecoded originalNormalizedChecked
      candidateNormalizedChecked edgesChecked⟩))

theorem nodeControlEdgesComplete_of_uninhabited
    (graph : RelationalProductGraph) (nodeId : Nat)
    (context : StaticProofContext) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (contains :
      region.inputInvariant.predicates.contains uninhabitedStatePredicate = true)
    (noOutgoing : noOutgoingControlEdgesMatch graph nodeId = true) :
    NodeControlEdgesComplete graph nodeId context region originalBehavior
      candidateBehavior :=
  Or.inr (Or.inr (Or.inl
    ⟨sourceInvariantUninhabited_of_contains context region.inputInvariant contains,
      noOutgoing⟩))

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
