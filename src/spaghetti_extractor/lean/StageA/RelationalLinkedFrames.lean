import StageA.RelationalComposition

namespace StageA.Relational

open StageA.Formal

theorem StackWindowPair.bytesBelow_le_registers_of_holds
    (world : RelationalWorld) (window : StackWindowPair)
    (original candidate : PureState)
    (holds : window.holds world original candidate = true) :
    window.bytesBelow <= (original.get window.originalRegister).toNat ∧
      window.bytesBelow <= (candidate.get window.candidateRegister).toNat := by
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at holds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        decide_eq_true_eq, beq_iff_eq] at holds
      exact ⟨by omega, by omega⟩

theorem StackWindowPair.registerWordFits_of_holds
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (rangesValid : world.stackRangesValid context = true)
    (holds : window.holds world original candidate = true)
    (wordAbove : 4 <= window.bytesAbove) :
    (original.get window.originalRegister).toNat + 4 <= 2 ^ 32 ∧
      (candidate.get window.candidateRegister).toNat + 4 <= 2 ^ 32 := by
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at holds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at holds
      have validRows := rangesValid
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at validRows
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have rangeValid : range.disjointFromImages context = true :=
        (validRows.1.1.2 range rangeMember).1.1.1
      have originalNoWrap :
          range.originalBase.toNat + range.size < 2 ^ 32 := by
        simpa [DynamicAddressRangePair.sideBase] using
          DynamicAddressRangePair.sideBase_noWrap_of_disjoint
            context false range rangeValid
      have candidateNoWrap :
          range.candidateBase.toNat + range.size < 2 ^ 32 := by
        simpa [DynamicAddressRangePair.sideBase] using
          DynamicAddressRangePair.sideBase_noWrap_of_disjoint
            context true range rangeValid
      exact ⟨by omega, by omega⟩

/-- Every word-sized nonnegative offset admitted by a checked stack window has
a non-wrapping concrete address on both sides. -/
theorem StackWindowPair.registerOffsetWordFits_of_holds
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (rangesValid : world.stackRangesValid context = true)
    (holds : window.holds world original candidate = true)
    (originalOffset candidateOffset : Nat)
    (originalInside : originalOffset + 4 <= window.bytesAbove)
    (candidateInside : candidateOffset + 4 <= window.bytesAbove) :
    (original.get window.originalRegister).toNat + originalOffset + 4 <= 2 ^ 32 ∧
      (candidate.get window.candidateRegister).toNat + candidateOffset + 4 <=
        2 ^ 32 := by
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at holds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at holds
      have validRows := rangesValid
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at validRows
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have rangeValid : range.disjointFromImages context = true :=
        (validRows.1.1.2 range rangeMember).1.1.1
      have originalNoWrap :
          range.originalBase.toNat + range.size < 2 ^ 32 := by
        simpa [DynamicAddressRangePair.sideBase] using
          DynamicAddressRangePair.sideBase_noWrap_of_disjoint
            context false range rangeValid
      have candidateNoWrap :
          range.candidateBase.toNat + range.size < 2 ^ 32 := by
        simpa [DynamicAddressRangePair.sideBase] using
          DynamicAddressRangePair.sideBase_noWrap_of_disjoint
            context true range rangeValid
      exact ⟨by omega, by omega⟩

theorem RelationalRuntimeCallFrame.protectedSpanValid_of_window_call
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (beforeOriginal beforeCandidate : PureState)
    (frame : RelationalRuntimeCallFrame) (amount : Nat)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world beforeOriginal beforeCandidate = true)
    (amountInside : amount <= window.bytesBelow)
    (amountSmall : amount < 2 ^ 32)
    (minimumSpan : 4 <= frame.protectedBytes)
    (spanInside : frame.protectedBytes <= amount + window.bytesAbove)
    (originalAddress : frame.originalStackAddress =
      beforeOriginal.get window.originalRegister - BitVec.ofNat 32 amount)
    (candidateAddress : frame.candidateStackAddress =
      beforeCandidate.get window.candidateRegister - BitVec.ofNat 32 amount) :
    frame.protectedSpanValid context = true := by
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at windowHolds
  | some range =>
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have validRows := rangesValid
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at validRows
      have rangeValid : range.disjointFromImages context = true :=
        (validRows.1.1.2 range rangeMember).1.1.1
      have rangeShape := rangeValid
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq] at rangeShape
      rcases rangeShape with
        ⟨⟨⟨⟨rangeNonempty, originalRangeNoWrap⟩,
          candidateRangeNoWrap⟩, originalRangeDisjoint⟩,
          candidateRangeDisjoint⟩
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at windowHolds
      rcases windowHolds with
        ⟨⟨⟨⟨⟨originalBelow, originalAbove⟩, candidateBelow⟩,
          candidateAbove⟩, _pairedOffset⟩, _aligned⟩
      have originalAmountLe : amount <=
          (beforeOriginal.get window.originalRegister).toNat := by omega
      have candidateAmountLe : amount <=
          (beforeCandidate.get window.candidateRegister).toNat := by omega
      have originalAddressNat : frame.originalStackAddress.toNat =
          (beforeOriginal.get window.originalRegister).toNat - amount := by
        rw [originalAddress, BitVec.toNat_sub_of_le]
        · simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]
        · rw [BitVec.le_def]
          simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]
      have candidateAddressNat : frame.candidateStackAddress.toNat =
          (beforeCandidate.get window.candidateRegister).toNat - amount := by
        rw [candidateAddress, BitVec.toNat_sub_of_le]
        · simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]
        · rw [BitVec.le_def]
          simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]
      unfold RelationalRuntimeCallFrame.protectedSpanValid
      simp only [Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq]
      refine ⟨⟨⟨⟨minimumSpan, ?_⟩, ?_⟩, ?_⟩, ?_⟩
      · rw [originalAddressNat]
        omega
      · rw [candidateAddressNat]
        omega
      · rcases originalRangeDisjoint with left | right
        · left
          rw [originalAddressNat]
          omega
        · right
          rw [originalAddressNat]
          omega
      · rcases candidateRangeDisjoint with left | right
        · left
          rw [candidateAddressNat]
          omega
        · right
          rw [candidateAddressNat]
          omega

/-- A checked link from an active inner return slot to its suspended parent.
The gaps are natural-number distances, so the relation also records stack
ordering and excludes modular wraparound. -/
structure RelationalRuntimeCallFrameLink where
  callSourceTargetId : Nat
  resumeNodeId : Nat := 0
  resumeTargetId : Nat := 0
  resumeContinuation : Nat := 0
  innerInventory : ReturnSlotOffsetInventory := ReturnSlotOffsetInventory.zero
  suspendedInventory : ReturnSlotOffsetInventory := ReturnSlotOffsetInventory.zero
  resumeInventory : ReturnSlotOffsetInventory := ReturnSlotOffsetInventory.zero
  originalGap : Nat
  candidateGap : Nat
deriving Repr, DecidableEq

def ReturnSlotOffsetPair.shiftByFrameGap (offsets : ReturnSlotOffsetPair)
    (originalGap candidateGap : Nat) : ReturnSlotOffsetPair := {
  originalRegister := offsets.originalRegister
  originalOffset := offsets.originalOffset + BitVec.ofNat 32 originalGap
  candidateRegister := offsets.candidateRegister
  candidateOffset := offsets.candidateOffset + BitVec.ofNat 32 candidateGap
}

def RelationalRuntimeCallFrameLink.checked
    (link : RelationalRuntimeCallFrameLink) : Bool :=
  link.innerInventory.checked && link.suspendedInventory.checked &&
    link.resumeInventory.checked &&
    link.suspendedInventory.locations == link.innerInventory.locations.map
      (fun offsets => offsets.shiftByFrameGap link.originalGap link.candidateGap) &&
    4 <= link.originalGap && link.originalGap < 2 ^ 32 &&
    4 <= link.candidateGap && link.candidateGap < 2 ^ 32

def RelationalRuntimeCallFrameLink.holds
    (link : RelationalRuntimeCallFrameLink)
    (inner outer : RelationalRuntimeCallFrame) : Prop :=
  link.checked = true ∧
    inner.continuationTargetId = link.resumeTargetId ∧
    inner.originalStackAddress.toNat + 4 <= 2 ^ 32 ∧
    inner.candidateStackAddress.toNat + 4 <= 2 ^ 32 ∧
    outer.originalStackAddress.toNat + 4 <= 2 ^ 32 ∧
    outer.candidateStackAddress.toNat + 4 <= 2 ^ 32 ∧
    (∀ word ∈ link.suspendedInventory.exactWords,
      outer.originalStackAddress.toNat + word.originalOffset + 4 <= 2 ^ 32 ∧
      outer.candidateStackAddress.toNat + word.candidateOffset + 4 <= 2 ^ 32) ∧
    (∀ word ∈ link.resumeInventory.exactWords,
      outer.originalStackAddress.toNat + word.originalOffset + 4 <= 2 ^ 32 ∧
      outer.candidateStackAddress.toNat + word.candidateOffset + 4 <= 2 ^ 32) ∧
    inner.originalStackAddress.toNat + link.originalGap =
      outer.originalStackAddress.toNat ∧
    inner.candidateStackAddress.toNat + link.candidateGap =
      outer.candidateStackAddress.toNat ∧
    outer.continuationTargetId = link.resumeContinuation

/-- Establish a checked frame link for an ordinary downward-growing IA-32
call.  Both runtime frames are named by ESP at their respective cutpoints; the
source stack window supplies the non-wrapping subtraction and address bounds.
Exact dormant scalar words are handled by richer call profiles, so this base
lemma intentionally requires empty exact-word inventories. -/
theorem RelationalRuntimeCallFrameLink.holds_of_esp_call
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : PureState)
    (inner outer : RelationalRuntimeCallFrame)
    (link : RelationalRuntimeCallFrameLink) (amount : Nat)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world beforeOriginal beforeCandidate = true)
    (windowRegisters : window.originalRegister = .esp ∧
      window.candidateRegister = .esp)
    (amountAtLeastWord : 4 <= amount)
    (amountInside : amount <= window.bytesBelow)
    (wordAbove : 4 <= window.bytesAbove)
    (amountSmall : amount < 2 ^ 32)
    (afterOriginalEsp : afterOriginal.esp =
      beforeOriginal.esp - BitVec.ofNat 32 amount)
    (afterCandidateEsp : afterCandidate.esp =
      beforeCandidate.esp - BitVec.ofNat 32 amount)
    (outerOffsets : ReturnSlotOffsetPair.zero.holds outer
      beforeOriginal beforeCandidate)
    (innerOffsets : ReturnSlotOffsetPair.zero.holds inner
      afterOriginal afterCandidate)
    (linkChecked : link.checked = true)
    (originalGap : link.originalGap = amount)
    (candidateGap : link.candidateGap = amount)
    (innerContinuation : inner.continuationTargetId = link.resumeTargetId)
    (outerContinuation : outer.continuationTargetId = link.resumeContinuation)
    (suspendedWords : link.suspendedInventory.exactWords = [])
    (resumeWords : link.resumeInventory.exactWords = []) :
    link.holds inner outer := by
  have enough := window.bytesBelow_le_registers_of_holds world beforeOriginal
    beforeCandidate windowHolds
  rw [windowRegisters.1, windowRegisters.2] at enough
  have enoughEsp : window.bytesBelow <= beforeOriginal.esp.toNat ∧
      window.bytesBelow <= beforeCandidate.esp.toNat := by
    simpa [StageA.Formal.Registers.get] using enough
  have outerFits := window.registerWordFits_of_holds context world beforeOriginal
    beforeCandidate rangesValid windowHolds wordAbove
  rw [windowRegisters.1, windowRegisters.2] at outerFits
  have outerFitsEsp : beforeOriginal.esp.toNat + 4 <= 2 ^ 32 ∧
      beforeCandidate.esp.toNat + 4 <= 2 ^ 32 := by
    simpa [StageA.Formal.Registers.get] using outerFits
  simp only [ReturnSlotOffsetPair.zero, ReturnSlotOffsetPair.holds,
    BitVec.add_zero] at outerOffsets innerOffsets
  have originalAmountLe : amount <= beforeOriginal.esp.toNat := by omega
  have candidateAmountLe : amount <= beforeCandidate.esp.toNat := by omega
  have originalInnerNat : inner.originalStackAddress.toNat =
      beforeOriginal.esp.toNat - amount := by
    rw [← innerOffsets.1]
    change afterOriginal.esp.toNat = beforeOriginal.esp.toNat - amount
    rw [afterOriginalEsp]
    change (beforeOriginal.esp - BitVec.ofNat 32 amount).toNat =
      beforeOriginal.esp.toNat - amount
    rw [BitVec.toNat_sub_of_le]
    · simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]
    · rw [BitVec.le_def]
      simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]
  have candidateInnerNat : inner.candidateStackAddress.toNat =
      beforeCandidate.esp.toNat - amount := by
    rw [← innerOffsets.2]
    change afterCandidate.esp.toNat = beforeCandidate.esp.toNat - amount
    rw [afterCandidateEsp]
    change (beforeCandidate.esp - BitVec.ofNat 32 amount).toNat =
      beforeCandidate.esp.toNat - amount
    rw [BitVec.toNat_sub_of_le]
    · simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]
    · rw [BitVec.le_def]
      simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]
  have originalOuterNat : outer.originalStackAddress.toNat =
      beforeOriginal.esp.toNat := by simpa using congrArg BitVec.toNat outerOffsets.1.symm
  have candidateOuterNat : outer.candidateStackAddress.toNat =
      beforeCandidate.esp.toNat := by simpa using congrArg BitVec.toNat outerOffsets.2.symm
  unfold RelationalRuntimeCallFrameLink.holds
  refine ⟨linkChecked, innerContinuation, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    outerContinuation⟩
  · rw [originalInnerNat]
    omega
  · rw [candidateInnerNat]
    omega
  · rw [originalOuterNat]
    exact outerFitsEsp.1
  · rw [candidateOuterNat]
    exact outerFitsEsp.2
  · simp [suspendedWords]
  · simp [resumeWords]
  · rw [originalGap, originalInnerNat, originalOuterNat]
    omega
  · rw [candidateGap, candidateInnerNat, candidateOuterNat]
    omega

/-- Establish a checked frame link when the original and candidate reserve
different, independently checked stack amounts.  The concrete stack window is
still authoritative on both sides; exact dormant words carry explicit address
bounds instead of being restricted to the empty inventory. -/
theorem RelationalRuntimeCallFrameLink.holds_of_paired_esp_call
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : PureState)
    (inner outer : RelationalRuntimeCallFrame)
    (link : RelationalRuntimeCallFrameLink)
    (originalAmount candidateAmount : Nat)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world beforeOriginal beforeCandidate = true)
    (windowRegisters : window.originalRegister = .esp ∧
      window.candidateRegister = .esp)
    (originalAmountAtLeastWord : 4 <= originalAmount)
    (candidateAmountAtLeastWord : 4 <= candidateAmount)
    (originalAmountInside : originalAmount <= window.bytesBelow)
    (candidateAmountInside : candidateAmount <= window.bytesBelow)
    (wordAbove : 4 <= window.bytesAbove)
    (originalAmountSmall : originalAmount < 2 ^ 32)
    (candidateAmountSmall : candidateAmount < 2 ^ 32)
    (afterOriginalEsp : afterOriginal.esp =
      beforeOriginal.esp - BitVec.ofNat 32 originalAmount)
    (afterCandidateEsp : afterCandidate.esp =
      beforeCandidate.esp - BitVec.ofNat 32 candidateAmount)
    (outerOffsets : ReturnSlotOffsetPair.zero.holds outer
      beforeOriginal beforeCandidate)
    (innerOffsets : ReturnSlotOffsetPair.zero.holds inner
      afterOriginal afterCandidate)
    (linkChecked : link.checked = true)
    (originalGap : link.originalGap = originalAmount)
    (candidateGap : link.candidateGap = candidateAmount)
    (innerContinuation : inner.continuationTargetId = link.resumeTargetId)
    (outerContinuation : outer.continuationTargetId = link.resumeContinuation)
    (suspendedWordsFit : ∀ word ∈ link.suspendedInventory.exactWords,
      outer.originalStackAddress.toNat + word.originalOffset + 4 <= 2 ^ 32 ∧
      outer.candidateStackAddress.toNat + word.candidateOffset + 4 <= 2 ^ 32)
    (resumeWordsFit : ∀ word ∈ link.resumeInventory.exactWords,
      outer.originalStackAddress.toNat + word.originalOffset + 4 <= 2 ^ 32 ∧
      outer.candidateStackAddress.toNat + word.candidateOffset + 4 <= 2 ^ 32) :
    link.holds inner outer := by
  have enough := window.bytesBelow_le_registers_of_holds world beforeOriginal
    beforeCandidate windowHolds
  rw [windowRegisters.1, windowRegisters.2] at enough
  have enoughEsp : window.bytesBelow <= beforeOriginal.esp.toNat ∧
      window.bytesBelow <= beforeCandidate.esp.toNat := by
    simpa [StageA.Formal.Registers.get] using enough
  have outerFits := window.registerWordFits_of_holds context world beforeOriginal
    beforeCandidate rangesValid windowHolds wordAbove
  rw [windowRegisters.1, windowRegisters.2] at outerFits
  have outerFitsEsp : beforeOriginal.esp.toNat + 4 <= 2 ^ 32 ∧
      beforeCandidate.esp.toNat + 4 <= 2 ^ 32 := by
    simpa [StageA.Formal.Registers.get] using outerFits
  simp only [ReturnSlotOffsetPair.zero, ReturnSlotOffsetPair.holds,
    BitVec.add_zero] at outerOffsets innerOffsets
  have originalAmountLe : originalAmount <= beforeOriginal.esp.toNat := by omega
  have candidateAmountLe : candidateAmount <= beforeCandidate.esp.toNat := by omega
  have originalInnerNat : inner.originalStackAddress.toNat =
      beforeOriginal.esp.toNat - originalAmount := by
    rw [← innerOffsets.1]
    change afterOriginal.esp.toNat = beforeOriginal.esp.toNat - originalAmount
    rw [afterOriginalEsp]
    change (beforeOriginal.esp - BitVec.ofNat 32 originalAmount).toNat =
      beforeOriginal.esp.toNat - originalAmount
    rw [BitVec.toNat_sub_of_le]
    · simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt originalAmountSmall]
    · rw [BitVec.le_def]
      simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt originalAmountSmall]
  have candidateInnerNat : inner.candidateStackAddress.toNat =
      beforeCandidate.esp.toNat - candidateAmount := by
    rw [← innerOffsets.2]
    change afterCandidate.esp.toNat = beforeCandidate.esp.toNat - candidateAmount
    rw [afterCandidateEsp]
    change (beforeCandidate.esp - BitVec.ofNat 32 candidateAmount).toNat =
      beforeCandidate.esp.toNat - candidateAmount
    rw [BitVec.toNat_sub_of_le]
    · simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt candidateAmountSmall]
    · rw [BitVec.le_def]
      simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt candidateAmountSmall]
  have originalOuterNat : outer.originalStackAddress.toNat =
      beforeOriginal.esp.toNat := by
    simpa using congrArg BitVec.toNat outerOffsets.1.symm
  have candidateOuterNat : outer.candidateStackAddress.toNat =
      beforeCandidate.esp.toNat := by
    simpa using congrArg BitVec.toNat outerOffsets.2.symm
  unfold RelationalRuntimeCallFrameLink.holds
  refine ⟨linkChecked, innerContinuation, ?_, ?_, ?_, ?_, suspendedWordsFit,
    resumeWordsFit, ?_, ?_, outerContinuation⟩
  · rw [originalInnerNat]
    omega
  · rw [candidateInnerNat]
    omega
  · rw [originalOuterNat]
    exact outerFitsEsp.1
  · rw [candidateOuterNat]
    exact outerFitsEsp.2
  · rw [originalGap, originalInnerNat, originalOuterNat]
    omega
  · rw [candidateGap, candidateInnerNat, candidateOuterNat]
    omega

/-- Affine caller-frame specialization of `holds_of_paired_esp_call`.  A caller
return slot may be above ESP at the call cutpoint, and each binary may reserve a
different amount.  The checked stack window discharges all non-wrapping address
arithmetic; the link still records concrete flat-memory addresses. -/
theorem RelationalRuntimeCallFrameLink.holds_of_paired_esp_call_offsets
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : PureState)
    (inner outer : RelationalRuntimeCallFrame)
    (link : RelationalRuntimeCallFrameLink)
    (originalAmount candidateAmount originalSourceOffset candidateSourceOffset : Nat)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world beforeOriginal beforeCandidate = true)
    (windowRegisters : window.originalRegister = .esp ∧
      window.candidateRegister = .esp)
    (originalAmountAtLeastWord : 4 <= originalAmount)
    (candidateAmountAtLeastWord : 4 <= candidateAmount)
    (originalAmountInside : originalAmount <= window.bytesBelow)
    (candidateAmountInside : candidateAmount <= window.bytesBelow)
    (originalSourceInside : originalSourceOffset + 4 <= window.bytesAbove)
    (candidateSourceInside : candidateSourceOffset + 4 <= window.bytesAbove)
    (originalAmountSmall : originalAmount < 2 ^ 32)
    (candidateAmountSmall : candidateAmount < 2 ^ 32)
    (afterOriginalEsp : afterOriginal.esp =
      beforeOriginal.esp - BitVec.ofNat 32 originalAmount)
    (afterCandidateEsp : afterCandidate.esp =
      beforeCandidate.esp - BitVec.ofNat 32 candidateAmount)
    (outerOriginalAddress : outer.originalStackAddress =
      beforeOriginal.esp + BitVec.ofNat 32 originalSourceOffset)
    (outerCandidateAddress : outer.candidateStackAddress =
      beforeCandidate.esp + BitVec.ofNat 32 candidateSourceOffset)
    (innerOffsets : ReturnSlotOffsetPair.zero.holds inner
      afterOriginal afterCandidate)
    (linkChecked : link.checked = true)
    (originalGap : link.originalGap = originalSourceOffset + originalAmount)
    (candidateGap : link.candidateGap = candidateSourceOffset + candidateAmount)
    (innerContinuation : inner.continuationTargetId = link.resumeTargetId)
    (outerContinuation : outer.continuationTargetId = link.resumeContinuation)
    (suspendedWordsFit : ∀ word ∈ link.suspendedInventory.exactWords,
      outer.originalStackAddress.toNat + word.originalOffset + 4 <= 2 ^ 32 ∧
      outer.candidateStackAddress.toNat + word.candidateOffset + 4 <= 2 ^ 32)
    (resumeWordsFit : ∀ word ∈ link.resumeInventory.exactWords,
      outer.originalStackAddress.toNat + word.originalOffset + 4 <= 2 ^ 32 ∧
      outer.candidateStackAddress.toNat + word.candidateOffset + 4 <= 2 ^ 32) :
    link.holds inner outer := by
  have enough := window.bytesBelow_le_registers_of_holds world beforeOriginal
    beforeCandidate windowHolds
  rw [windowRegisters.1, windowRegisters.2] at enough
  have enoughEsp : window.bytesBelow <= beforeOriginal.esp.toNat ∧
      window.bytesBelow <= beforeCandidate.esp.toNat := by
    simpa [StageA.Formal.Registers.get] using enough
  have offsetFits := window.registerOffsetWordFits_of_holds context world
    beforeOriginal beforeCandidate rangesValid windowHolds originalSourceOffset
    candidateSourceOffset originalSourceInside candidateSourceInside
  rw [windowRegisters.1, windowRegisters.2] at offsetFits
  have offsetFitsEsp :
      beforeOriginal.esp.toNat + originalSourceOffset + 4 <= 2 ^ 32 ∧
        beforeCandidate.esp.toNat + candidateSourceOffset + 4 <= 2 ^ 32 := by
    simpa [StageA.Formal.Registers.get] using offsetFits
  have originalAmountLe : originalAmount <= beforeOriginal.esp.toNat := by
    omega
  have candidateAmountLe : candidateAmount <= beforeCandidate.esp.toNat := by
    omega
  simp only [ReturnSlotOffsetPair.zero, ReturnSlotOffsetPair.holds,
    BitVec.add_zero] at innerOffsets
  have originalInnerNat : inner.originalStackAddress.toNat =
      beforeOriginal.esp.toNat - originalAmount := by
    rw [← innerOffsets.1]
    change afterOriginal.esp.toNat = beforeOriginal.esp.toNat - originalAmount
    rw [afterOriginalEsp, BitVec.toNat_sub_of_le]
    · simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt originalAmountSmall]
    · rw [BitVec.le_def]
      simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt originalAmountSmall]
  have candidateInnerNat : inner.candidateStackAddress.toNat =
      beforeCandidate.esp.toNat - candidateAmount := by
    rw [← innerOffsets.2]
    change afterCandidate.esp.toNat = beforeCandidate.esp.toNat - candidateAmount
    rw [afterCandidateEsp, BitVec.toNat_sub_of_le]
    · simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt candidateAmountSmall]
    · rw [BitVec.le_def]
      simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt candidateAmountSmall]
  have originalSourceSmall : originalSourceOffset < 2 ^ 32 := by omega
  have candidateSourceSmall : candidateSourceOffset < 2 ^ 32 := by omega
  have originalOuterNat : outer.originalStackAddress.toNat =
      beforeOriginal.esp.toNat + originalSourceOffset := by
    rw [outerOriginalAddress]
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt originalSourceSmall,
      Nat.mod_eq_of_lt (by omega :
        beforeOriginal.esp.toNat + originalSourceOffset < 2 ^ 32)]
  have candidateOuterNat : outer.candidateStackAddress.toNat =
      beforeCandidate.esp.toNat + candidateSourceOffset := by
    rw [outerCandidateAddress]
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt candidateSourceSmall,
      Nat.mod_eq_of_lt (by omega :
        beforeCandidate.esp.toNat + candidateSourceOffset < 2 ^ 32)]
  unfold RelationalRuntimeCallFrameLink.holds
  refine ⟨linkChecked, innerContinuation, ?_, ?_, ?_, ?_, suspendedWordsFit,
    resumeWordsFit, ?_, ?_, outerContinuation⟩
  · rw [originalInnerNat]
    omega
  · rw [candidateInnerNat]
    omega
  · rw [originalOuterNat]
    exact offsetFitsEsp.1
  · rw [candidateOuterNat]
    exact offsetFitsEsp.2
  · rw [originalGap, originalInnerNat, originalOuterNat]
    omega
  · rw [candidateGap, candidateInnerNat, candidateOuterNat]
    omega

theorem ReturnSlotOffsetPair.shiftByFrameGap_holds
    (offsets : ReturnSlotOffsetPair)
    (link : RelationalRuntimeCallFrameLink)
    (inner outer : RelationalRuntimeCallFrame)
    (original candidate : Registers Word)
    (linkHolds : link.holds inner outer)
    (offsetsHold : offsets.holds inner original candidate) :
    (offsets.shiftByFrameGap link.originalGap link.candidateGap).holds outer
      original candidate := by
  rcases offsetsHold with ⟨originalOffset, candidateOffset⟩
  have originalGapSmall : link.originalGap < 2 ^ 32 := by
    have checked := linkHolds.1
    simp only [RelationalRuntimeCallFrameLink.checked, Bool.and_eq_true,
      decide_eq_true_eq] at checked
    rcases checked with
      ⟨⟨⟨⟨⟨⟨⟨_innerChecked, _suspendedChecked⟩, _resumeChecked⟩,
        _locationsExact⟩, _originalMin⟩, originalMax⟩,
        _candidateMin⟩, _candidateMax⟩
    exact originalMax
  have candidateGapSmall : link.candidateGap < 2 ^ 32 := by
    have checked := linkHolds.1
    simp only [RelationalRuntimeCallFrameLink.checked, Bool.and_eq_true,
      decide_eq_true_eq] at checked
    rcases checked with
      ⟨⟨⟨⟨⟨⟨⟨_innerChecked, _suspendedChecked⟩, _resumeChecked⟩,
        _locationsExact⟩, _originalMin⟩, _originalMax⟩,
        _candidateMin⟩, candidateMax⟩
    exact candidateMax
  have originalGapNat := linkHolds.2.2.2.2.2.2.2.2.1
  have candidateGapNat := linkHolds.2.2.2.2.2.2.2.2.2.1
  have originalGapSumSmall :
      inner.originalStackAddress.toNat + link.originalGap < 2 ^ 32 := by
    rw [originalGapNat]
    exact outer.originalStackAddress.isLt
  have candidateGapSumSmall :
      inner.candidateStackAddress.toNat + link.candidateGap < 2 ^ 32 := by
    rw [candidateGapNat]
    exact outer.candidateStackAddress.isLt
  have originalFrameGap : inner.originalStackAddress +
      BitVec.ofNat 32 link.originalGap = outer.originalStackAddress := by
    apply BitVec.eq_of_toNat_eq
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt originalGapSmall,
      Nat.mod_eq_of_lt originalGapSumSmall]
    exact originalGapNat
  have candidateFrameGap : inner.candidateStackAddress +
      BitVec.ofNat 32 link.candidateGap = outer.candidateStackAddress := by
    apply BitVec.eq_of_toNat_eq
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt candidateGapSmall,
      Nat.mod_eq_of_lt candidateGapSumSmall]
    exact candidateGapNat
  constructor
  · simp only [ReturnSlotOffsetPair.shiftByFrameGap]
    rw [← BitVec.add_assoc, originalOffset, originalFrameGap]
  · simp only [ReturnSlotOffsetPair.shiftByFrameGap]
    rw [← BitVec.add_assoc, candidateOffset, candidateFrameGap]

theorem RelationalRuntimeCallFrameLink.suspendedInventoryHolds
    (link : RelationalRuntimeCallFrameLink)
    (inner outer : RelationalRuntimeCallFrame)
    (original candidate : Registers Word)
    (linkHolds : link.holds inner outer)
    (innerHolds : link.innerInventory.holds inner original candidate) :
    link.suspendedInventory.holds outer original candidate := by
  have checked := linkHolds.1
  simp only [RelationalRuntimeCallFrameLink.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨_innerChecked, _suspendedChecked⟩, _resumeChecked⟩,
      locationsExact⟩, _originalMin⟩, _originalMax⟩,
      _candidateMin⟩, _candidateMax⟩
  constructor
  · rw [locationsExact]
    cases locationsCase : link.innerInventory.locations with
    | nil => exact False.elim (innerHolds.1 locationsCase)
    | cons head tail => simp
  · intro location member
    rw [locationsExact] at member
    rcases List.mem_map.mp member with ⟨source, sourceMember, rfl⟩
    exact source.shiftByFrameGap_holds link inner outer original candidate linkHolds
      (innerHolds.2 source sourceMember)

/-- Frame validity and return-slot memory are inductive and independent of
the current register names for dormant frames. -/
def RelationalRuntimeCallFramesHold (context : StaticProofContext)
    (original candidate : MachineState) :
    List RelationalRuntimeCallFrame -> List Nat -> Prop
  | [], [] => True
  | frame :: frames, continuation :: continuations =>
      frame.continuationTargetId = continuation ∧
        frame.valid context = true ∧
        frame.toRelationalCallFrame.resolves context = true ∧
        frame.memoryHolds original.memory candidate.memory ∧
        RelationalRuntimeCallFramesHold context original candidate frames
          continuations
  | _, _ => False

theorem RelationalRuntimeCallFramesHold.length_eq
    (context : StaticProofContext) (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (holds : RelationalRuntimeCallFramesHold context original candidate
      frames continuations) :
    frames.length = continuations.length := by
  induction frames generalizing continuations with
  | nil =>
      cases continuations with
      | nil => rfl
      | cons continuation continuations => exact False.elim holds
  | cons frame frames induction =>
      cases continuations with
      | nil => exact False.elim holds
      | cons continuation continuations =>
          simp only [RelationalRuntimeCallFramesHold] at holds
          simp only [List.length_cons, Nat.succ.injEq]
          exact induction continuations holds.2.2.2.2

/-- There is one link between each adjacent pair of runtime frames. -/
def RelationalRuntimeCallFrameLinksHold (original candidate : Memory) :
    List RelationalRuntimeCallFrame ->
      List RelationalRuntimeCallFrameLink -> Prop
  | [], [] => True
  | [_], [] => True
  | inner :: outer :: frames, link :: links =>
      link.holds inner outer ∧
        link.suspendedInventory.boundedExactWordsHold outer original candidate ∧
        RelationalRuntimeCallFrameLinksHold original candidate
          (outer :: frames) links
  | _, _ => False

/-- The linked profile names only the active frame. Dormant frames retain
their concrete return-slot facts and checked ordering without accumulating
unbounded ESP-relative offsets during recursion. -/
def RelationalLinkedRuntimeCallStackHolds (context : StaticProofContext)
    (original candidate : MachineState) :
    List RelationalRuntimeCallFrame -> List Nat ->
      Option ReturnSlotOffsetInventory ->
      List RelationalRuntimeCallFrameLink -> Prop
  | [], [], none, [] => True
  | frame :: frames, continuation :: continuations, some active, links =>
      active.checked = true ∧
        active.holds frame original.registers candidate.registers ∧
        active.boundedExactWordsHold frame original.memory candidate.memory ∧
        RelationalRuntimeCallFramesHold context original candidate
          (frame :: frames) (continuation :: continuations) ∧
        RelationalRuntimeCallFrameLinksHold original.memory candidate.memory
          (frame :: frames) links
  | _, _, _, _ => False

theorem RelationalLinkedRuntimeCallStackHolds.length_eq
    (context : StaticProofContext) (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (active : Option ReturnSlotOffsetInventory)
    (links : List RelationalRuntimeCallFrameLink)
    (holds : RelationalLinkedRuntimeCallStackHolds context original candidate
      frames continuations active links) :
    frames.length = continuations.length := by
  cases frames with
  | nil =>
      cases continuations with
      | nil => rfl
      | cons continuation continuations => exact False.elim holds
  | cons frame frames =>
      cases continuations with
      | nil => exact False.elim holds
      | cons continuation continuations =>
          cases active with
          | none => exact False.elim holds
          | some inventory =>
              simp only [RelationalLinkedRuntimeCallStackHolds] at holds
              exact RelationalRuntimeCallFramesHold.length_eq context original
                candidate (frame :: frames) (continuation :: continuations)
                holds.2.2.2.1

theorem continuations_eq_nil_of_head?_eq_none
    (continuations : List Nat) (headNone : none = continuations.head?) :
    continuations = [] := by
  cases continuations with
  | nil => rfl
  | cons continuation continuations => nomatch headNone

theorem RelationalLinkedRuntimeCallStackHolds.empty_shape
    (context : StaticProofContext) (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame)
    (links : List RelationalRuntimeCallFrameLink)
    (holds : RelationalLinkedRuntimeCallStackHolds context original candidate
      frames [] none links) :
    frames = [] ∧ links = [] := by
  cases frames with
  | nil =>
      cases links with
      | nil => exact ⟨rfl, rfl⟩
      | cons link links => exact False.elim holds
  | cons frame frames => exact False.elim holds

/-- A finite control abstraction records only the current node and active
frame shape. The remaining continuation stack is checked inductively by
`RelationalLinkedRuntimeCallStackHolds`, so recursive depth does not create
new profile rows. -/
structure LinkedProductControlState where
  nodeId : Nat
  continuation : Option Nat
  active : Option ReturnSlotOffsetInventory
  minimumDepth : Nat := 0
deriving Repr, DecidableEq

def LinkedProductControlState.checked
    (state : LinkedProductControlState) : Bool :=
  match state.continuation, state.active with
  | none, none => state.minimumDepth == 0
  | some _, some inventory => 0 < state.minimumDepth && inventory.checked
  | _, _ => false

def LinkedProductControlState.matches
    (state : LinkedProductControlState) (nodeId : Nat)
    (continuation : Option Nat) (active : Option ReturnSlotOffsetInventory) : Bool :=
  state.nodeId == nodeId && state.continuation == continuation &&
    state.active == active

structure LinkedProductControlProfile where
  states : List LinkedProductControlState
  links : List RelationalRuntimeCallFrameLink := []
deriving Repr, DecidableEq

def LinkedProductControlProfile.checked
    (profile : LinkedProductControlProfile) : Bool :=
  profile.states.all LinkedProductControlState.checked &&
    profile.links.all (fun link =>
      link.checked && profile.states.any (fun state =>
        state.matches link.resumeNodeId (some link.resumeContinuation)
          (some link.resumeInventory) && state.minimumDepth <= 1)) &&
    decide profile.states.Nodup && decide profile.links.Nodup

def LinkedProductControlProfile.Allows
    (profile : LinkedProductControlProfile) (nodeId : Nat)
    (continuations : List Nat)
    (active : Option ReturnSlotOffsetInventory) : Bool :=
  profile.checked && profile.states.any (fun state =>
    state.matches nodeId continuations.head? active &&
      state.minimumDepth <= continuations.length)

theorem LinkedProductControlProfile.allowsOfListedState
    (profile : LinkedProductControlProfile)
    (state : LinkedProductControlState)
    (nodeId : Nat) (continuations : List Nat)
    (active : Option ReturnSlotOffsetInventory)
    (profileValid : profile.checked = true)
    (stateMember : state ∈ profile.states)
    (stateMatches : state.matches nodeId continuations.head? active = true)
    (depthEnough : state.minimumDepth <= continuations.length) :
    profile.Allows nodeId continuations active = true := by
  simp only [LinkedProductControlProfile.Allows, Bool.and_eq_true]
  refine ⟨profileValid, List.any_eq_true.mpr ⟨state, stateMember, ?_⟩⟩
  simp only [Bool.and_eq_true, decide_eq_true_eq]
  exact ⟨stateMatches, depthEnough⟩

def LinkedProductControlProfile.LinkAllowed
    (profile : LinkedProductControlProfile)
    (link : RelationalRuntimeCallFrameLink) : Bool :=
  profile.checked && profile.links.contains link

def LinkedProductControlProfile.excludesResumeTarget
    (profile : LinkedProductControlProfile) (targetId : Nat) : Bool :=
  profile.links.all fun link => decide (link.resumeTargetId ≠ targetId)

def LinkedProductControlProfile.LinksAllowed
    (profile : LinkedProductControlProfile)
    (links : List RelationalRuntimeCallFrameLink) : Prop :=
  profile.checked = true ∧
    ∀ link, link ∈ links → profile.links.contains link = true

/-- The whole-program execution relation depends on semantic authorization,
not on how a finite profile represents that authorization.  Exact profiles and
affine frame profiles both instantiate this interface while concrete runtime
frames remain authoritative in `RelationalLinkedRuntimeCallStackHolds`. -/
structure LinkedControlAuthority where
  allows : Nat -> List Nat -> Option ReturnSlotOffsetInventory -> Prop
  linksAllowed : List RelationalRuntimeCallFrameLink -> Prop

def LinkedProductControlProfile.authority
    (profile : LinkedProductControlProfile) : LinkedControlAuthority := {
  allows := fun nodeId continuations active =>
    profile.Allows nodeId continuations active = true
  linksAllowed := profile.LinksAllowed
}

/-- The generic authority interface intentionally stores propositions.  An
authority obtained from a finite checked profile remains decidable because its
authorization predicate is the profile's executable Boolean checker. -/
instance LinkedProductControlProfile.decidableAuthorityAllows
    (profile : LinkedProductControlProfile) (nodeId : Nat)
    (continuations : List Nat) (active : Option ReturnSlotOffsetInventory) :
    Decidable (profile.authority.allows nodeId continuations active) := by
  unfold LinkedProductControlProfile.authority
  infer_instance

instance : Coe LinkedProductControlProfile LinkedControlAuthority where
  coe := LinkedProductControlProfile.authority

theorem LinkedProductControlProfile.checked_of_allows
    (profile : LinkedProductControlProfile) (nodeId : Nat)
    (continuations : List Nat) (active : Option ReturnSlotOffsetInventory)
    (allowed : profile.Allows nodeId continuations active = true) :
    profile.checked = true := by
  simp only [LinkedProductControlProfile.Allows, Bool.and_eq_true] at allowed
  exact allowed.1

theorem LinkedProductControlProfile.active_checked_of_allows
    (profile : LinkedProductControlProfile) (nodeId : Nat)
    (continuations : List Nat) (active : ReturnSlotOffsetInventory)
    (allowed : profile.Allows nodeId continuations (some active) = true) :
    active.checked = true := by
  simp only [LinkedProductControlProfile.Allows, Bool.and_eq_true] at allowed
  have statesChecked :
      profile.states.all LinkedProductControlState.checked = true := by
    simp only [LinkedProductControlProfile.checked, Bool.and_eq_true] at allowed
    exact allowed.1.1.1.1
  rcases List.any_eq_true.mp allowed.2 with ⟨state, member, selectedMatch⟩
  simp only [LinkedProductControlState.matches, Bool.and_eq_true,
    beq_iff_eq] at selectedMatch
  have activeExact : state.active = some active := selectedMatch.1.2
  have selected := List.all_eq_true.mp statesChecked state member
  cases continuationExact : state.continuation with
  | none => simp [LinkedProductControlState.checked, continuationExact,
      activeExact] at selected
  | some continuation =>
      simp [LinkedProductControlState.checked, continuationExact,
        activeExact] at selected
      exact selected.2

@[simp]
theorem LinkedProductControlProfile.LinksAllowed.nil
    (profile : LinkedProductControlProfile)
    (checked : profile.checked = true) :
    profile.LinksAllowed [] := by
  exact ⟨checked, by simp⟩

theorem LinkedProductControlProfile.LinksAllowed.cons
    (profile : LinkedProductControlProfile)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (allowed : profile.LinkAllowed link = true)
    (tail : profile.LinksAllowed links) :
    profile.LinksAllowed (link :: links) := by
  simp only [LinkedProductControlProfile.LinkAllowed, Bool.and_eq_true] at allowed
  exact ⟨allowed.1, by
    intro selected member
    rcases List.mem_cons.mp member with same | inTail
    · simpa [same] using allowed.2
    · exact tail.2 selected inTail⟩

theorem LinkedProductControlProfile.LinksAllowed.tail
    (profile : LinkedProductControlProfile)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (allowed : profile.LinksAllowed (link :: links)) :
    profile.LinksAllowed links := by
  exact ⟨allowed.1, fun selected member => allowed.2 selected (by simp [member])⟩

theorem LinkedProductControlProfile.LinksAllowed.head
    (profile : LinkedProductControlProfile)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (allowed : profile.LinksAllowed (link :: links)) :
    profile.LinkAllowed link = true := by
  simp only [LinkedProductControlProfile.LinkAllowed, Bool.and_eq_true]
  exact ⟨allowed.1, allowed.2 link (by simp)⟩

/-- A return continuation selects one statically submitted frame-link shape.
The profile must prove uniqueness; sharing a continuation between incompatible
link contracts is therefore incomplete rather than guessed. -/
def LinkedProductControlProfile.selectsUniqueResumeLink
    (profile : LinkedProductControlProfile) (continuation : Nat)
    (expected : RelationalRuntimeCallFrameLink) : Bool :=
  profile.LinkAllowed expected && profile.links.all fun candidate =>
    decide (candidate.resumeTargetId = continuation → candidate = expected)

theorem LinkedProductControlProfile.selectedHeadLink_eq
    (profile : LinkedProductControlProfile) (continuation : Nat)
    (expected selected : RelationalRuntimeCallFrameLink)
    (inner outer : RelationalRuntimeCallFrame)
    (links : List RelationalRuntimeCallFrameLink)
    (unique : profile.selectsUniqueResumeLink continuation expected = true)
    (allowed : profile.LinksAllowed (selected :: links))
    (frameContinuation : inner.continuationTargetId = continuation)
    (selectedHolds : selected.holds inner outer) :
    selected = expected := by
  simp only [LinkedProductControlProfile.selectsUniqueResumeLink,
    Bool.and_eq_true] at unique
  have selectedListed : selected ∈ profile.links :=
    List.contains_iff_mem.mp (allowed.2 selected (by simp))
  have selectedRule := List.all_eq_true.mp unique.2 selected selectedListed
  simp only [decide_eq_true_eq] at selectedRule
  exact selectedRule (selectedHolds.2.1.symm.trans frameContinuation)

theorem LinkedProductControlProfile.LinksAllowed.eq_nil_of_profile_links
    (profile : LinkedProductControlProfile)
    (links : List RelationalRuntimeCallFrameLink)
    (profileLinksEmpty : profile.links = [])
    (allowed : profile.LinksAllowed links) :
    links = [] := by
  cases links with
  | nil => rfl
  | cons link links =>
      have listed := allowed.2 link (by simp)
      simp [profileLinksEmpty] at listed

def RelationalRuntimeCallFrameLink.profileChecked
    (link : RelationalRuntimeCallFrameLink)
    (profile : LinkedProductControlProfile) : Bool :=
  profile.LinkAllowed link && profile.states.any (fun state =>
    state.matches link.resumeNodeId (some link.resumeContinuation)
      (some link.resumeInventory) && state.minimumDepth <= 1)

theorem LinkedProductControlProfile.allowsResumeOfLink
    (profile : LinkedProductControlProfile)
    (link : RelationalRuntimeCallFrameLink)
    (inner outer : RelationalRuntimeCallFrame)
    (continuations : List Nat)
    (profileChecked : link.profileChecked profile = true)
    (linkHolds : link.holds inner outer) :
    profile.Allows link.resumeNodeId
      (outer.continuationTargetId :: continuations)
      (some link.resumeInventory) = true := by
  simp only [RelationalRuntimeCallFrameLink.profileChecked,
    Bool.and_eq_true] at profileChecked
  rcases profileChecked with ⟨linkAllowed, listed⟩
  simp only [LinkedProductControlProfile.LinkAllowed, Bool.and_eq_true] at linkAllowed
  rcases linkAllowed with ⟨profileValid, _linkListed⟩
  rcases linkHolds with
    ⟨_, _, _, _, _, _, _, _, _, _, continuationExact⟩
  rcases List.any_eq_true.mp listed with ⟨state, stateMember, stateMatches⟩
  simp only [LinkedProductControlProfile.Allows, Bool.and_eq_true]
  refine And.intro profileValid (List.any_eq_true.mpr ⟨state, stateMember, ?_⟩)
  simp only [Bool.and_eq_true, decide_eq_true_eq] at stateMatches ⊢
  exact ⟨by simpa [continuationExact] using stateMatches.1,
    Nat.le_trans stateMatches.2 (Nat.succ_le_succ (Nat.zero_le _))⟩

theorem RelationalRuntimeCallFramesHold.of_memory_eq
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (holds : RelationalRuntimeCallFramesHold context beforeOriginal
      beforeCandidate frames continuations)
    (originalMemory : afterOriginal.memory = beforeOriginal.memory)
    (candidateMemory : afterCandidate.memory = beforeCandidate.memory) :
    RelationalRuntimeCallFramesHold context afterOriginal afterCandidate
      frames continuations := by
  induction frames generalizing continuations with
  | nil =>
      cases continuations <;>
        simp_all [RelationalRuntimeCallFramesHold]
  | cons frame frames ih =>
      cases continuations with
      | nil => simp [RelationalRuntimeCallFramesHold] at holds
      | cons continuation continuations =>
          simp only [RelationalRuntimeCallFramesHold] at holds ⊢
          exact ⟨holds.1, holds.2.1, holds.2.2.1,
            by simpa [RelationalRuntimeCallFrame.memoryHolds, originalMemory,
              candidateMemory] using holds.2.2.2.1,
            ih continuations holds.2.2.2.2⟩

theorem RelationalRuntimeCallFramesHold.afterMemory
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (holds : RelationalRuntimeCallFramesHold context beforeOriginal
      beforeCandidate frames continuations)
    (framesPreserved : ∀ frame : RelationalRuntimeCallFrame,
      frame.memoryHolds beforeOriginal.memory beforeCandidate.memory →
        frame.memoryHolds afterOriginal.memory afterCandidate.memory) :
    RelationalRuntimeCallFramesHold context afterOriginal afterCandidate
      frames continuations := by
  induction frames generalizing continuations with
  | nil =>
      cases continuations <;>
        simp_all [RelationalRuntimeCallFramesHold]
  | cons frame frames ih =>
      cases continuations with
      | nil => simp [RelationalRuntimeCallFramesHold] at holds
      | cons continuation continuations =>
          simp only [RelationalRuntimeCallFramesHold] at holds ⊢
          exact ⟨holds.1, holds.2.1, holds.2.2.1,
            framesPreserved frame holds.2.2.2.1,
            ih continuations holds.2.2.2.2⟩

theorem RelationalRuntimeCallFrameLinksHold.afterMemory
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : Memory)
    (frames : List RelationalRuntimeCallFrame)
    (links : List RelationalRuntimeCallFrameLink)
    (holds : RelationalRuntimeCallFrameLinksHold beforeOriginal beforeCandidate
      frames links)
    (inventoriesPreserved : ∀ (frame : RelationalRuntimeCallFrame)
        (inventory : ReturnSlotOffsetInventory),
      inventory.boundedExactWordsHold frame beforeOriginal beforeCandidate →
        inventory.boundedExactWordsHold frame afterOriginal afterCandidate) :
    RelationalRuntimeCallFrameLinksHold afterOriginal afterCandidate frames links := by
  induction frames generalizing links with
  | nil =>
      cases links <;> simp_all [RelationalRuntimeCallFrameLinksHold]
  | cons frame frames ih =>
      cases frames with
      | nil =>
          cases links <;> simp_all [RelationalRuntimeCallFrameLinksHold]
      | cons outer frames =>
          cases links with
          | nil => simp [RelationalRuntimeCallFrameLinksHold] at holds
          | cons link links =>
              simp only [RelationalRuntimeCallFrameLinksHold] at holds ⊢
              exact ⟨holds.1,
                inventoriesPreserved outer link.suspendedInventory holds.2.1,
                ih links holds.2.2⟩

/-- Preserve a complete dormant frame/link tail across an arbitrary paired
memory transition.  The transition must preserve each concrete frame word and
each exact dormant inventory word; frame validity, target resolution, link
geometry, and exact-word bounds are static and therefore carry unchanged.
This induction is the common substrate for returning imports, callbacks, and
other external transitions that may change unrelated memory. -/
theorem RelationalRuntimeCallTailHolds.afterMemory
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (framesHold : RelationalRuntimeCallFramesHold context beforeOriginal
      beforeCandidate frames continuations)
    (linksHold : RelationalRuntimeCallFrameLinksHold beforeOriginal.memory
      beforeCandidate.memory frames links)
    (preserved : ∀ (frame : RelationalRuntimeCallFrame)
        (inventory : ReturnSlotOffsetInventory),
      frame.memoryHolds beforeOriginal.memory beforeCandidate.memory →
      inventory.exactWordsHold frame beforeOriginal.memory beforeCandidate.memory →
        frame.memoryHolds afterOriginal.memory afterCandidate.memory ∧
          inventory.exactWordsHold frame afterOriginal.memory afterCandidate.memory) :
    RelationalRuntimeCallFramesHold context afterOriginal afterCandidate
        frames continuations ∧
      RelationalRuntimeCallFrameLinksHold afterOriginal.memory afterCandidate.memory
        frames links := by
  induction frames generalizing continuations links with
  | nil =>
      cases continuations <;> cases links <;>
        simp_all [RelationalRuntimeCallFramesHold,
          RelationalRuntimeCallFrameLinksHold]
  | cons frame frames ih =>
      cases continuations with
      | nil => simp [RelationalRuntimeCallFramesHold] at framesHold
      | cons continuation continuations =>
          cases frames with
          | nil =>
              cases continuations with
              | cons next rest =>
                  simp [RelationalRuntimeCallFramesHold] at framesHold
              | nil =>
                  cases links with
                  | cons link links =>
                      simp [RelationalRuntimeCallFrameLinksHold] at linksHold
                  | nil =>
                      simp only [RelationalRuntimeCallFramesHold,
                        RelationalRuntimeCallFrameLinksHold] at framesHold ⊢
                      have frameAfter := preserved frame
                        ReturnSlotOffsetInventory.zero framesHold.2.2.2.1 (by
                          intro word member
                          simp [ReturnSlotOffsetInventory.zero,
                            ReturnSlotOffsetInventory.singleton] at member)
                      exact ⟨⟨framesHold.1, framesHold.2.1,
                        framesHold.2.2.1, frameAfter.1, True.intro⟩,
                        True.intro⟩
          | cons outer frames =>
              cases continuations with
              | nil => simp [RelationalRuntimeCallFramesHold] at framesHold
              | cons outerContinuation continuations =>
                  cases links with
                  | nil => simp [RelationalRuntimeCallFrameLinksHold] at linksHold
                  | cons link links =>
                      simp only [RelationalRuntimeCallFramesHold] at framesHold ⊢
                      simp only [RelationalRuntimeCallFrameLinksHold] at linksHold ⊢
                      have frameAfter := preserved frame
                        ReturnSlotOffsetInventory.zero framesHold.2.2.2.1 (by
                          intro word member
                          simp [ReturnSlotOffsetInventory.zero,
                            ReturnSlotOffsetInventory.singleton] at member)
                      have tailFrames := framesHold.2.2.2.2
                      have outerMemory := tailFrames.2.2.2.1
                      have suspendedAfter := preserved outer
                        link.suspendedInventory outerMemory linksHold.2.1.2
                      have tail := ih (outerContinuation :: continuations) links
                        framesHold.2.2.2.2 linksHold.2.2
                      exact ⟨
                        ⟨framesHold.1, framesHold.2.1, framesHold.2.2.1,
                          frameAfter.1, tail.1⟩,
                        ⟨linksHold.1, ⟨linksHold.2.1.1, suspendedAfter.2⟩,
                          tail.2⟩⟩

theorem RelationalRuntimeCallFrameLinksHold.of_memory_eq
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : Memory)
    (frames : List RelationalRuntimeCallFrame)
    (links : List RelationalRuntimeCallFrameLink)
    (holds : RelationalRuntimeCallFrameLinksHold beforeOriginal beforeCandidate
      frames links)
    (originalMemory : afterOriginal = beforeOriginal)
    (candidateMemory : afterCandidate = beforeCandidate) :
    RelationalRuntimeCallFrameLinksHold afterOriginal afterCandidate frames links := by
  subst afterOriginal
  subst afterCandidate
  exact holds

def RelationalRuntimeCallFrame.writesAvoid
    (frame : RelationalRuntimeCallFrame)
    (originalWrites candidateWrites : List (Word × Word)) : Prop :=
  WritesAvoidWord frame.originalStackAddress originalWrites ∧
    WritesAvoidWord frame.candidateStackAddress candidateWrites

def RelationalRuntimeCallFrame.strictlyBelow
    (inner outer : RelationalRuntimeCallFrame) : Prop :=
  inner.originalStackAddress.toNat + 4 <= outer.originalStackAddress.toNat ∧
    inner.candidateStackAddress.toNat + 4 <= outer.candidateStackAddress.toNat

theorem RelationalRuntimeCallFrameLink.strictlyBelow_of_holds
    (link : RelationalRuntimeCallFrameLink)
    (inner outer : RelationalRuntimeCallFrame)
    (holds : link.holds inner outer) :
    inner.strictlyBelow outer := by
  simp only [RelationalRuntimeCallFrameLink.holds] at holds
  have checked := holds.1
  simp only [RelationalRuntimeCallFrameLink.checked, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  exact ⟨by omega, by omega⟩

theorem RelationalRuntimeCallFrame.memoryHolds_afterInnerWrite
    (inner frame : RelationalRuntimeCallFrame)
    (original candidate : Memory) (originalValue candidateValue : Word)
    (innerOriginalFits : inner.originalStackAddress.toNat + 4 <= 2 ^ 32)
    (innerCandidateFits : inner.candidateStackAddress.toNat + 4 <= 2 ^ 32)
    (frameOriginalFits : frame.originalStackAddress.toNat + 4 <= 2 ^ 32)
    (frameCandidateFits : frame.candidateStackAddress.toNat + 4 <= 2 ^ 32)
    (below : inner.strictlyBelow frame)
    (holds : frame.memoryHolds original candidate) :
    frame.memoryHolds
      (original.write32 inner.originalStackAddress originalValue)
      (candidate.write32 inner.candidateStackAddress candidateValue) := by
  rcases holds with ⟨originalHolds, candidateHolds⟩
  constructor
  · rw [Memory.read32_write32_of_avoids]
    · exact originalHolds
    · exact write32AvoidsWord_of_nat_disjoint frame.originalStackAddress
        inner.originalStackAddress frameOriginalFits innerOriginalFits
        (Or.inr below.1)
  · rw [Memory.read32_write32_of_avoids]
    · exact candidateHolds
    · exact write32AvoidsWord_of_nat_disjoint frame.candidateStackAddress
        inner.candidateStackAddress frameCandidateFits innerCandidateFits
        (Or.inr below.2)

theorem ReturnSlotOffsetInventory.exactWordsHold_afterInnerWrite
    (inventory : ReturnSlotOffsetInventory)
    (inner frame : RelationalRuntimeCallFrame)
    (original candidate : Memory) (originalValue candidateValue : Word)
    (innerOriginalFits : inner.originalStackAddress.toNat + 4 <= 2 ^ 32)
    (innerCandidateFits : inner.candidateStackAddress.toNat + 4 <= 2 ^ 32)
    (below : inner.strictlyBelow frame)
    (wordsFit : ∀ word ∈ inventory.exactWords,
      frame.originalStackAddress.toNat + word.originalOffset + 4 <= 2 ^ 32 ∧
      frame.candidateStackAddress.toNat + word.candidateOffset + 4 <= 2 ^ 32)
    (holds : inventory.exactWordsHold frame original candidate) :
    inventory.exactWordsHold frame
      (original.write32 inner.originalStackAddress originalValue)
      (candidate.write32 inner.candidateStackAddress candidateValue) := by
  intro word member
  have fit := wordsFit word member
  have originalOffsetSmall : word.originalOffset < 2 ^ 32 := by omega
  have candidateOffsetSmall : word.candidateOffset < 2 ^ 32 := by omega
  have originalAddressNat :
      (frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset).toNat =
        frame.originalStackAddress.toNat + word.originalOffset := by
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt originalOffsetSmall,
      Nat.mod_eq_of_lt (by omega :
        frame.originalStackAddress.toNat + word.originalOffset < 2 ^ 32)]
  have candidateAddressNat :
      (frame.candidateStackAddress + BitVec.ofNat 32 word.candidateOffset).toNat =
        frame.candidateStackAddress.toNat + word.candidateOffset := by
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt candidateOffsetSmall,
      Nat.mod_eq_of_lt (by omega :
        frame.candidateStackAddress.toNat + word.candidateOffset < 2 ^ 32)]
  have prior := holds word member
  unfold ReturnSlotExactWordPair.holds at prior ⊢
  rw [Memory.read32_write32_of_avoids, Memory.read32_write32_of_avoids]
  · exact prior
  · apply write32AvoidsWord_of_nat_disjoint
    · simpa [candidateAddressNat] using fit.2
    · exact innerCandidateFits
    · right
      calc
        inner.candidateStackAddress.toNat + 4 <=
            frame.candidateStackAddress.toNat := below.2
        _ <= frame.candidateStackAddress.toNat + word.candidateOffset := by omega
        _ = (frame.candidateStackAddress +
            BitVec.ofNat 32 word.candidateOffset).toNat := candidateAddressNat.symm
  · apply write32AvoidsWord_of_nat_disjoint
    · simpa [originalAddressNat] using fit.1
    · exact innerOriginalFits
    · right
      calc
        inner.originalStackAddress.toNat + 4 <=
            frame.originalStackAddress.toNat := below.1
        _ <= frame.originalStackAddress.toNat + word.originalOffset := by omega
        _ = (frame.originalStackAddress +
            BitVec.ofNat 32 word.originalOffset).toNat := originalAddressNat.symm

private theorem relationalRuntimeCallStackTailHolds_afterInnerWrite_of_below
    (context : StaticProofContext)
    (original candidate : MachineState)
    (inner outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (outerContinuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (originalValue candidateValue : Word)
    (innerOriginalFits : inner.originalStackAddress.toNat + 4 <= 2 ^ 32)
    (innerCandidateFits : inner.candidateStackAddress.toNat + 4 <= 2 ^ 32)
    (outerOriginalFits : outer.originalStackAddress.toNat + 4 <= 2 ^ 32)
    (outerCandidateFits : outer.candidateStackAddress.toNat + 4 <= 2 ^ 32)
    (innerBelowOuter : inner.strictlyBelow outer)
    (framesHold : RelationalRuntimeCallFramesHold context original candidate
      (outer :: frames) (outerContinuation :: continuations))
    (linksHold : RelationalRuntimeCallFrameLinksHold original.memory candidate.memory
      (outer :: frames) links) :
    RelationalRuntimeCallFramesHold context
        { original with memory := (original.memory.write32
            inner.originalStackAddress originalValue) }
        { candidate with memory := (candidate.memory.write32
            inner.candidateStackAddress candidateValue) }
        (outer :: frames) (outerContinuation :: continuations) ∧
      RelationalRuntimeCallFrameLinksHold
        (original.memory.write32 inner.originalStackAddress originalValue)
        (candidate.memory.write32 inner.candidateStackAddress candidateValue)
        (outer :: frames) links := by
  induction frames generalizing continuations outer outerContinuation links
      outerOriginalFits outerCandidateFits innerBelowOuter with
  | nil =>
      cases continuations with
      | cons next rest =>
          simp [RelationalRuntimeCallFramesHold] at framesHold
      | nil =>
          cases links with
          | cons link links =>
              simp [RelationalRuntimeCallFrameLinksHold] at linksHold
          | nil =>
              simp only [RelationalRuntimeCallFramesHold,
                RelationalRuntimeCallFrameLinksHold] at framesHold ⊢
              exact ⟨⟨framesHold.1, framesHold.2.1, framesHold.2.2.1,
                RelationalRuntimeCallFrame.memoryHolds_afterInnerWrite inner outer
                  original.memory
                  candidate.memory originalValue candidateValue
                  innerOriginalFits innerCandidateFits outerOriginalFits
                  outerCandidateFits innerBelowOuter framesHold.2.2.2.1,
                True.intro⟩, True.intro⟩
  | cons next frames induction =>
      cases continuations with
      | nil => simp [RelationalRuntimeCallFramesHold] at framesHold
      | cons nextContinuation continuations =>
          cases links with
          | nil => simp [RelationalRuntimeCallFrameLinksHold] at linksHold
          | cons link links =>
              simp only [RelationalRuntimeCallFramesHold] at framesHold ⊢
              simp only [RelationalRuntimeCallFrameLinksHold] at linksHold ⊢
              have linkHolds := linksHold.1
              have nextOriginalFits := linkHolds.2.2.2.2.1
              have nextCandidateFits := linkHolds.2.2.2.2.2.1
              have outerBelowNext := link.strictlyBelow_of_holds outer next linkHolds
              have innerBelowNext : inner.strictlyBelow next := by
                have originalInnerBelow := innerBelowOuter.1
                have candidateInnerBelow := innerBelowOuter.2
                have originalOuterBelow := outerBelowNext.1
                have candidateOuterBelow := outerBelowNext.2
                exact ⟨by omega, by omega⟩
              have tail := induction
                (outer := next)
                (outerContinuation := nextContinuation)
                (continuations := continuations)
                (links := links)
                nextOriginalFits nextCandidateFits innerBelowNext
                framesHold.2.2.2.2 linksHold.2.2
              have suspendedAfter :
                  link.suspendedInventory.boundedExactWordsHold next
                    (original.memory.write32 inner.originalStackAddress originalValue)
                    (candidate.memory.write32 inner.candidateStackAddress
                      candidateValue) := ⟨linksHold.2.1.1,
                link.suspendedInventory.exactWordsHold_afterInnerWrite
                  inner next original.memory candidate.memory originalValue candidateValue
                  innerOriginalFits innerCandidateFits innerBelowNext
                  linkHolds.2.2.2.2.2.2.1 linksHold.2.1.2⟩
              exact ⟨
                ⟨framesHold.1, framesHold.2.1, framesHold.2.2.1,
                  RelationalRuntimeCallFrame.memoryHolds_afterInnerWrite inner outer
                    original.memory
                    candidate.memory originalValue candidateValue
                    innerOriginalFits innerCandidateFits outerOriginalFits
                    outerCandidateFits innerBelowOuter framesHold.2.2.2.1,
                  tail.1⟩,
                ⟨linkHolds, suspendedAfter, tail.2⟩⟩

theorem RelationalRuntimeCallStackTailHolds_afterInnerWrite
    (context : StaticProofContext)
    (original candidate : MachineState)
    (inner outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (outerContinuation : Nat) (continuations : List Nat)
    (newLink : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (originalValue candidateValue : Word)
    (newLinkHolds : newLink.holds inner outer)
    (framesHold : RelationalRuntimeCallFramesHold context original candidate
      (outer :: frames) (outerContinuation :: continuations))
    (linksHold : RelationalRuntimeCallFrameLinksHold original.memory candidate.memory
      (outer :: frames) links) :
    RelationalRuntimeCallFramesHold context
        { original with memory := (original.memory.write32
            inner.originalStackAddress originalValue) }
        { candidate with memory := (candidate.memory.write32
            inner.candidateStackAddress candidateValue) }
        (outer :: frames) (outerContinuation :: continuations) ∧
      RelationalRuntimeCallFrameLinksHold
        (original.memory.write32 inner.originalStackAddress originalValue)
        (candidate.memory.write32 inner.candidateStackAddress candidateValue)
        (outer :: frames) links := by
  exact relationalRuntimeCallStackTailHolds_afterInnerWrite_of_below context
    original candidate inner outer frames outerContinuation continuations links
    originalValue candidateValue
    newLinkHolds.2.2.1 newLinkHolds.2.2.2.1
    newLinkHolds.2.2.2.2.1 newLinkHolds.2.2.2.2.2.1
    (newLink.strictlyBelow_of_holds inner outer newLinkHolds)
    framesHold linksHold

theorem RelationalRuntimeCallFrame.memoryHolds_afterWrites
    (frame : RelationalRuntimeCallFrame)
    (original candidate : Memory)
    (originalWrites candidateWrites : List (Word × Word))
    (holds : frame.memoryHolds original candidate)
    (avoids : frame.writesAvoid originalWrites candidateWrites) :
    frame.memoryHolds
      (applyConcreteWrites original originalWrites)
      (applyConcreteWrites candidate candidateWrites) := by
  rcases holds with ⟨originalHolds, candidateHolds⟩
  constructor
  · rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids.1]
    exact originalHolds
  · rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids.2]
    exact candidateHolds

/-- A freshly pushed runtime frame owns the return words written at its two
concrete stack addresses.  The non-wrapping bounds are explicit because flat
IA-32 memory, rather than a source-level stack object, remains authoritative. -/
theorem RelationalRuntimeCallFrame.memoryHolds_afterOwnWrite
    (frame : RelationalRuntimeCallFrame) (original candidate : Memory)
    (originalFits : frame.originalStackAddress.toNat + 4 <= 2 ^ 32)
    (candidateFits : frame.candidateStackAddress.toNat + 4 <= 2 ^ 32) :
    frame.memoryHolds
      (original.write32 frame.originalStackAddress frame.originalReturnAddress)
      (candidate.write32 frame.candidateStackAddress frame.candidateReturnAddress) := by
  unfold RelationalRuntimeCallFrame.memoryHolds
  exact ⟨Memory.read32_write32_same_of_fits original
      frame.originalStackAddress frame.originalReturnAddress originalFits,
    Memory.read32_write32_same_of_fits candidate
      frame.candidateStackAddress frame.candidateReturnAddress candidateFits⟩

theorem RelationalRuntimeCallFramesHold.afterWrites
    (context : StaticProofContext)
    (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (originalWrites candidateWrites : List (Word × Word))
    (holds : RelationalRuntimeCallFramesHold context original candidate
      frames continuations)
    (avoids : ∀ frame, frame ∈ frames →
      frame.writesAvoid originalWrites candidateWrites) :
    RelationalRuntimeCallFramesHold context
      { original with memory := applyConcreteWrites original.memory originalWrites }
      { candidate with memory := applyConcreteWrites candidate.memory candidateWrites }
      frames continuations := by
  induction frames generalizing continuations with
  | nil =>
      cases continuations <;>
        simp_all [RelationalRuntimeCallFramesHold]
  | cons frame frames ih =>
      cases continuations with
      | nil => simp [RelationalRuntimeCallFramesHold] at holds
      | cons continuation continuations =>
          simp only [RelationalRuntimeCallFramesHold] at holds ⊢
          refine ⟨holds.1, holds.2.1, holds.2.2.1, ?_, ?_⟩
          · exact frame.memoryHolds_afterWrites original.memory candidate.memory
              originalWrites candidateWrites holds.2.2.2.1
              (avoids frame (by simp))
          · exact ih continuations holds.2.2.2.2
              (fun tailFrame member => avoids tailFrame (by simp [member]))

theorem RelationalLinkedRuntimeCallStackHolds.afterNoWrite
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (active : Option ReturnSlotOffsetInventory)
    (links : List RelationalRuntimeCallFrameLink)
    (holds : RelationalLinkedRuntimeCallStackHolds context beforeOriginal
      beforeCandidate frames continuations active links)
    (originalMemory : afterOriginal.memory = beforeOriginal.memory)
    (candidateMemory : afterCandidate.memory = beforeCandidate.memory)
    (originalRegisters : afterOriginal.registers = beforeOriginal.registers)
    (candidateRegisters : afterCandidate.registers = beforeCandidate.registers) :
    RelationalLinkedRuntimeCallStackHolds context afterOriginal afterCandidate
      frames continuations active links := by
  cases frames with
  | nil =>
      cases continuations <;> cases active <;> cases links <;>
        simp_all [RelationalLinkedRuntimeCallStackHolds]
  | cons frame frames =>
      cases continuations with
      | nil => simp [RelationalLinkedRuntimeCallStackHolds] at holds
      | cons continuation continuations =>
          cases active with
          | none => simp [RelationalLinkedRuntimeCallStackHolds] at holds
          | some inventory =>
              simp only [RelationalLinkedRuntimeCallStackHolds] at holds ⊢
              exact ⟨holds.1,
                by simpa [originalRegisters, candidateRegisters] using holds.2.1,
                by simpa [ReturnSlotOffsetInventory.boundedExactWordsHold,
                    ReturnSlotOffsetInventory.exactWordsHold,
                    originalMemory, candidateMemory] using holds.2.2.1,
                RelationalRuntimeCallFramesHold.of_memory_eq context
                  beforeOriginal beforeCandidate afterOriginal afterCandidate
                  (frame :: frames) (continuation :: continuations) holds.2.2.2.1
                  originalMemory candidateMemory,
                RelationalRuntimeCallFrameLinksHold.of_memory_eq
                  beforeOriginal.memory beforeCandidate.memory
                  afterOriginal.memory afterCandidate.memory
                  (frame :: frames) links holds.2.2.2.2
                  originalMemory candidateMemory⟩

theorem RelationalLinkedRuntimeCallStackHolds.afterActiveTransfer
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotFrameInventoryTransferClaim)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (holds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
      (some claim.source) links)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (originalMemory :
      ((originalBehavior.eval originalState).nextMachineState
        originalState).memory = originalState.memory)
    (candidateMemory :
      ((candidateBehavior.eval candidateState).nextMachineState
        candidateState).memory = candidateState.memory) :
    RelationalLinkedRuntimeCallStackHolds context
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState)
      (frame :: frames) (continuation :: continuations)
      (some claim.target) links := by
  simp only [RelationalLinkedRuntimeCallStackHolds] at holds ⊢
  have transferred := returnSlotFrameInventoryTransferHolds_of_checked
    context world sourceInvariant originalBehavior candidateBehavior claim frame
    originalState candidateState checked holds.2.1
    holds.2.2.2.1.2.2.2.1 holds.2.2.1
    (by
      have valid := holds.2.2.2.1.2.1
      simp only [RelationalRuntimeCallFrame.valid, Bool.and_eq_true] at valid
      exact valid.2) related
  have framesAfter := RelationalRuntimeCallFramesHold.of_memory_eq context
    originalState candidateState
    ((originalBehavior.eval originalState).nextMachineState originalState)
    ((candidateBehavior.eval candidateState).nextMachineState candidateState)
    (frame :: frames) (continuation :: continuations) holds.2.2.2.1
    originalMemory candidateMemory
  have linksAfter := RelationalRuntimeCallFrameLinksHold.of_memory_eq
    originalState.memory candidateState.memory
    (((originalBehavior.eval originalState).nextMachineState originalState).memory)
    (((candidateBehavior.eval candidateState).nextMachineState candidateState).memory)
    (frame :: frames) links holds.2.2.2.2 originalMemory candidateMemory
  simp only [ReturnSlotFrameInventoryTransferClaim.checked,
    Bool.and_eq_true, beq_iff_eq] at checked
  exact ⟨checked.1.1.1.1.1.2, transferred.1, transferred.2.2,
    framesAfter, linksAfter⟩

theorem RelationalLinkedRuntimeCallStackHolds.pushFirst
    (context : StaticProofContext) (original candidate : MachineState)
    (frame : RelationalRuntimeCallFrame) (continuation : Nat)
    (active : ReturnSlotOffsetInventory)
    (activeChecked : active.checked = true)
    (activeHolds : active.holds frame original.registers candidate.registers)
    (activeExactWords : active.boundedExactWordsHold frame original.memory
      candidate.memory)
    (continuationMatches : frame.continuationTargetId = continuation)
    (frameValid : frame.valid context = true)
    (frameResolves : frame.toRelationalCallFrame.resolves context = true)
    (frameMemory : frame.memoryHolds original.memory candidate.memory) :
    RelationalLinkedRuntimeCallStackHolds context original candidate
      [frame] [continuation] (some active) [] := by
  simp [RelationalLinkedRuntimeCallStackHolds,
    RelationalRuntimeCallFramesHold, RelationalRuntimeCallFrameLinksHold,
    activeChecked, activeHolds, activeExactWords, continuationMatches, frameValid,
    frameResolves, frameMemory]

theorem RelationalLinkedRuntimeCallStackHolds.pushNested
    (context : StaticProofContext) (original candidate : MachineState)
    (frame outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation outerContinuation : Nat) (continuations : List Nat)
    (active outerActive : ReturnSlotOffsetInventory)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (outerHolds : RelationalLinkedRuntimeCallStackHolds context original candidate
      (outer :: frames) (outerContinuation :: continuations)
      (some outerActive) links)
    (activeChecked : active.checked = true)
    (activeHolds : active.holds frame original.registers candidate.registers)
    (activeExactWords : active.boundedExactWordsHold frame original.memory
      candidate.memory)
    (continuationMatches : frame.continuationTargetId = continuation)
    (frameValid : frame.valid context = true)
    (frameResolves : frame.toRelationalCallFrame.resolves context = true)
    (frameMemory : frame.memoryHolds original.memory candidate.memory)
    (suspendedExactWords : link.suspendedInventory.boundedExactWordsHold outer
      original.memory candidate.memory)
    (linkHolds : link.holds frame outer) :
    RelationalLinkedRuntimeCallStackHolds context original candidate
      (frame :: outer :: frames)
      (continuation :: outerContinuation :: continuations)
      (some active) (link :: links) := by
  simp only [RelationalLinkedRuntimeCallStackHolds] at outerHolds ⊢
  simp only [RelationalRuntimeCallFramesHold,
    RelationalRuntimeCallFrameLinksHold] at outerHolds ⊢
  exact ⟨activeChecked, activeHolds, activeExactWords,
    ⟨continuationMatches, frameValid, frameResolves, frameMemory,
      outerHolds.2.2.2.1⟩,
    ⟨linkHolds, suspendedExactWords, outerHolds.2.2.2.2⟩⟩

theorem RelationalLinkedRuntimeCallStackHolds.pushNestedAfter
    (context : StaticProofContext)
    (afterOriginal afterCandidate : MachineState)
    (frame outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation outerContinuation : Nat) (continuations : List Nat)
    (active : ReturnSlotOffsetInventory)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (outerFramesAfter : RelationalRuntimeCallFramesHold context afterOriginal
      afterCandidate (outer :: frames) (outerContinuation :: continuations))
    (outerLinksAfter : RelationalRuntimeCallFrameLinksHold afterOriginal.memory
      afterCandidate.memory (outer :: frames) links)
    (activeChecked : active.checked = true)
    (activeHolds : active.holds frame afterOriginal.registers
      afterCandidate.registers)
    (activeExactWords : active.boundedExactWordsHold frame afterOriginal.memory
      afterCandidate.memory)
    (continuationMatches : frame.continuationTargetId = continuation)
    (frameValid : frame.valid context = true)
    (frameResolves : frame.toRelationalCallFrame.resolves context = true)
    (frameMemory : frame.memoryHolds afterOriginal.memory afterCandidate.memory)
    (suspendedExactWords : link.suspendedInventory.boundedExactWordsHold outer
      afterOriginal.memory afterCandidate.memory)
    (linkHolds : link.holds frame outer) :
    RelationalLinkedRuntimeCallStackHolds context afterOriginal afterCandidate
      (frame :: outer :: frames)
      (continuation :: outerContinuation :: continuations)
      (some active) (link :: links) := by
  simp only [RelationalLinkedRuntimeCallStackHolds,
    RelationalRuntimeCallFramesHold, RelationalRuntimeCallFrameLinksHold]
  exact ⟨activeChecked, activeHolds, activeExactWords,
    ⟨continuationMatches, frameValid, frameResolves, frameMemory,
      outerFramesAfter⟩,
    ⟨linkHolds, suspendedExactWords, outerLinksAfter⟩⟩

/-- Push a nested runtime frame after a call whose only concrete memory update
to the caller stack is the newly-created inner return slot.  The active caller
inventory is transferred by the ordinary checked frame claim, while every
dormant frame and link inventory is preserved by the linked-stack ordering
witnesses. -/
theorem RelationalLinkedRuntimeCallStackHolds.pushNestedAfterSingletonWrite
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (outerClaim : ReturnSlotFrameInventoryTransferClaim)
    (beforeOriginal beforeCandidate : MachineState)
    (inner outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuations : List Nat)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (before : RelationalLinkedRuntimeCallStackHolds context beforeOriginal
      beforeCandidate (outer :: frames)
      (link.resumeContinuation :: continuations) (some outerClaim.source) links)
    (claimChecked : outerClaim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (related : StateRel context world sourceInvariant beforeOriginal beforeCandidate)
    (linkHolds : link.holds inner outer)
    (suspendedMatches : outerClaim.target = link.suspendedInventory)
    (innerHolds : link.innerInventory.holds inner
      (originalBehavior.eval beforeOriginal).registers
      (candidateBehavior.eval beforeCandidate).registers)
    (innerExactWords : link.innerInventory.boundedExactWordsHold inner
      ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal).memory
      ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate).memory)
    (innerValid : inner.valid context = true)
    (innerResolves : inner.toRelationalCallFrame.resolves context = true)
    (innerMemory : inner.memoryHolds
      ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal).memory
      ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate).memory)
    (originalMemory :
      ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal).memory =
        beforeOriginal.memory.write32 inner.originalStackAddress
          inner.originalReturnAddress)
    (candidateMemory :
      ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate).memory =
        beforeCandidate.memory.write32 inner.candidateStackAddress
          inner.candidateReturnAddress) :
    RelationalLinkedRuntimeCallStackHolds context
      ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal)
      ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate)
      (inner :: outer :: frames)
      (link.resumeTargetId :: link.resumeContinuation :: continuations)
      (some link.innerInventory) (link :: links) := by
  simp only [RelationalLinkedRuntimeCallStackHolds] at before
  have transferred := returnSlotFrameInventoryTransferHolds_of_checked
    context world sourceInvariant originalBehavior candidateBehavior outerClaim outer
    beforeOriginal beforeCandidate claimChecked before.2.1
    before.2.2.2.1.2.2.2.1 before.2.2.1
    (by
      have valid := before.2.2.2.1.2.1
      simp only [RelationalRuntimeCallFrame.valid, Bool.and_eq_true] at valid
      exact valid.2) related
  have tailAfterWrite := RelationalRuntimeCallStackTailHolds_afterInnerWrite
    context beforeOriginal beforeCandidate inner outer frames link.resumeContinuation
    continuations link links inner.originalReturnAddress inner.candidateReturnAddress
    linkHolds before.2.2.2.1 before.2.2.2.2
  let writtenOriginal : MachineState := {
    beforeOriginal with memory := (beforeOriginal.memory.write32
      inner.originalStackAddress inner.originalReturnAddress)
  }
  let writtenCandidate : MachineState := {
    beforeCandidate with memory := (beforeCandidate.memory.write32
      inner.candidateStackAddress inner.candidateReturnAddress)
  }
  have outerFramesAfter := RelationalRuntimeCallFramesHold.of_memory_eq context
    writtenOriginal writtenCandidate
    ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal)
    ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate)
    (outer :: frames) (link.resumeContinuation :: continuations) tailAfterWrite.1
    (by simpa [writtenOriginal] using originalMemory)
    (by simpa [writtenCandidate] using candidateMemory)
  have outerLinksAfter := RelationalRuntimeCallFrameLinksHold.of_memory_eq
    writtenOriginal.memory writtenCandidate.memory
    ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal).memory
    ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate).memory
    (outer :: frames) links tailAfterWrite.2
    (by simpa [writtenOriginal] using originalMemory)
    (by simpa [writtenCandidate] using candidateMemory)
  have innerChecked : link.innerInventory.checked = true := by
    have checked := linkHolds.1
    simp only [RelationalRuntimeCallFrameLink.checked, Bool.and_eq_true] at checked
    exact checked.1.1.1.1.1.1.1
  have suspendedExactWords : link.suspendedInventory.boundedExactWordsHold outer
      ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal).memory
      ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate).memory := by
    rw [← suspendedMatches]
    exact transferred.2.2
  exact RelationalLinkedRuntimeCallStackHolds.pushNestedAfter context
    ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal)
    ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate)
    inner outer frames link.resumeTargetId link.resumeContinuation continuations
    link.innerInventory link links outerFramesAfter outerLinksAfter innerChecked
    innerHolds innerExactWords linkHolds.2.1 innerValid innerResolves innerMemory
    suspendedExactWords linkHolds

theorem RelationalLinkedRuntimeCallStackHolds.popNested
    (context : StaticProofContext) (original candidate : MachineState)
    (frame outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation outerContinuation : Nat) (continuations : List Nat)
    (active : ReturnSlotOffsetInventory)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (holds : RelationalLinkedRuntimeCallStackHolds context original candidate
      (frame :: outer :: frames)
      (continuation :: outerContinuation :: continuations)
      (some active) (link :: links))
    (resumeHolds : link.resumeInventory.holds outer original.registers
      candidate.registers)
    (resumeExactWords : link.resumeInventory.boundedExactWordsHold outer original.memory
      candidate.memory) :
    RelationalLinkedRuntimeCallStackHolds context original candidate
      (outer :: frames) (outerContinuation :: continuations)
      (some link.resumeInventory) links := by
  simp only [RelationalLinkedRuntimeCallStackHolds,
    RelationalRuntimeCallFramesHold,
    RelationalRuntimeCallFrameLinksHold] at holds ⊢
  have resumeChecked : link.resumeInventory.checked = true := by
    have linkChecked := holds.2.2.2.2.1.1
    simp only [RelationalRuntimeCallFrameLink.checked,
      Bool.and_eq_true] at linkChecked
    rcases linkChecked with
      ⟨⟨⟨⟨⟨⟨⟨_innerChecked, _suspendedChecked⟩, resumeChecked⟩,
        _locationsExact⟩, _originalMin⟩, _originalMax⟩,
        _candidateMin⟩, _candidateMax⟩
    exact resumeChecked
  exact ⟨resumeChecked, resumeHolds, resumeExactWords,
    holds.2.2.2.1.2.2.2.2, holds.2.2.2.2.2.2⟩

theorem RelationalLinkedRuntimeCallStackHolds.popNestedAfter
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frame outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation outerContinuation : Nat) (continuations : List Nat)
    (active : ReturnSlotOffsetInventory)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (before : RelationalLinkedRuntimeCallStackHolds context beforeOriginal
      beforeCandidate (frame :: outer :: frames)
      (continuation :: outerContinuation :: continuations)
      (some active) (link :: links))
    (outerFramesAfter : RelationalRuntimeCallFramesHold context afterOriginal
      afterCandidate (outer :: frames) (outerContinuation :: continuations))
    (outerLinksAfter : RelationalRuntimeCallFrameLinksHold afterOriginal.memory
      afterCandidate.memory (outer :: frames) links)
    (resumeHolds : link.resumeInventory.holds outer afterOriginal.registers
      afterCandidate.registers)
    (resumeExactWords : link.resumeInventory.boundedExactWordsHold outer
      afterOriginal.memory afterCandidate.memory) :
    RelationalLinkedRuntimeCallStackHolds context afterOriginal afterCandidate
      (outer :: frames) (outerContinuation :: continuations)
      (some link.resumeInventory) links := by
  simp only [RelationalLinkedRuntimeCallStackHolds,
    RelationalRuntimeCallFrameLinksHold] at before ⊢
  have resumeChecked : link.resumeInventory.checked = true := by
    have linkChecked := before.2.2.2.2.1.1
    simp only [RelationalRuntimeCallFrameLink.checked,
      Bool.and_eq_true] at linkChecked
    rcases linkChecked with
      ⟨⟨⟨⟨⟨⟨⟨_innerChecked, _suspendedChecked⟩, resumeChecked⟩,
        _locationsExact⟩, _originalMin⟩, _originalMax⟩,
        _candidateMin⟩, _candidateMax⟩
    exact resumeChecked
  exact ⟨resumeChecked, resumeHolds, resumeExactWords, outerFramesAfter,
    outerLinksAfter⟩

/-- Pop one checked linked frame after a no-write return.  The active inner
inventory names the suspended parent through the frame link; the submitted
transfer claim must restore exactly the link's resume inventory.  The dormant
tail is preserved without enumerating its depth. -/
theorem RelationalLinkedRuntimeCallStackHolds.popNestedAfterNoWriteTransfer
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (outerClaim : ReturnSlotFrameInventoryTransferClaim)
    (beforeOriginal beforeCandidate : MachineState)
    (inner outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation outerContinuation : Nat) (continuations : List Nat)
    (active : ReturnSlotOffsetInventory)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (before : RelationalLinkedRuntimeCallStackHolds context beforeOriginal
      beforeCandidate (inner :: outer :: frames)
      (continuation :: outerContinuation :: continuations)
      (some active) (link :: links))
    (claimChecked : outerClaim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (related : StateRel context world sourceInvariant beforeOriginal beforeCandidate)
    (activeMatches : active = link.innerInventory)
    (sourceMatches : outerClaim.source = link.suspendedInventory)
    (targetMatches : outerClaim.target = link.resumeInventory)
    (originalMemory :
      ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal).memory =
        beforeOriginal.memory)
    (candidateMemory :
      ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate).memory =
        beforeCandidate.memory) :
    RelationalLinkedRuntimeCallStackHolds context
      ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal)
      ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate)
      (outer :: frames) (outerContinuation :: continuations)
      (some link.resumeInventory) links := by
  simp only [RelationalLinkedRuntimeCallStackHolds] at before
  have linkHolds := before.2.2.2.2.1
  have activeHolds : link.innerInventory.holds inner beforeOriginal.registers
      beforeCandidate.registers := by
    rw [← activeMatches]
    exact before.2.1
  have suspendedHolds : link.suspendedInventory.holds outer
      beforeOriginal.registers beforeCandidate.registers :=
    link.suspendedInventoryHolds inner outer beforeOriginal.registers
      beforeCandidate.registers linkHolds activeHolds
  have outerFramesBefore : RelationalRuntimeCallFramesHold context beforeOriginal
      beforeCandidate (outer :: frames) (outerContinuation :: continuations) :=
    before.2.2.2.1.2.2.2.2
  have outerLinksBefore : RelationalRuntimeCallFrameLinksHold
      beforeOriginal.memory beforeCandidate.memory (outer :: frames) links :=
    before.2.2.2.2.2.2
  have transferred := returnSlotFrameInventoryTransferHolds_of_checked
    context world sourceInvariant originalBehavior candidateBehavior outerClaim outer
    beforeOriginal beforeCandidate claimChecked
    (by simpa [sourceMatches] using suspendedHolds)
    outerFramesBefore.2.2.2.1
    (by simpa [sourceMatches] using before.2.2.2.2.2.1)
    (by
      have valid := outerFramesBefore.2.1
      simp only [RelationalRuntimeCallFrame.valid, Bool.and_eq_true] at valid
      exact valid.2)
    related
  have outerFramesAfter := RelationalRuntimeCallFramesHold.of_memory_eq context
    beforeOriginal beforeCandidate
    ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal)
    ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate)
    (outer :: frames) (outerContinuation :: continuations)
    outerFramesBefore originalMemory candidateMemory
  have outerLinksAfter := RelationalRuntimeCallFrameLinksHold.of_memory_eq
    beforeOriginal.memory beforeCandidate.memory
    ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal).memory
    ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate).memory
    (outer :: frames) links outerLinksBefore originalMemory candidateMemory
  exact RelationalLinkedRuntimeCallStackHolds.popNestedAfter context
    beforeOriginal beforeCandidate
    ((originalBehavior.eval beforeOriginal).nextMachineState beforeOriginal)
    ((candidateBehavior.eval beforeCandidate).nextMachineState beforeCandidate)
    inner outer frames continuation outerContinuation continuations active link links
    (by simpa only [RelationalLinkedRuntimeCallStackHolds] using before)
    outerFramesAfter outerLinksAfter
    (by simpa [targetMatches] using transferred.1)
    (by simpa [targetMatches] using transferred.2.2)

/-- Once the last return frame is consumed, the linked-stack relation is empty
for any successor machine states.  No stale frame fact is carried past the
program return boundary. -/
theorem RelationalLinkedRuntimeCallStackHolds.popLastAfter
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frame : RelationalRuntimeCallFrame) (continuation : Nat)
    (active : ReturnSlotOffsetInventory)
    (_before : RelationalLinkedRuntimeCallStackHolds context beforeOriginal
      beforeCandidate [frame] [continuation] (some active) []) :
    RelationalLinkedRuntimeCallStackHolds context afterOriginal afterCandidate
      [] [] none [] := by
  simp [RelationalLinkedRuntimeCallStackHolds]

theorem RelationalLinkedRuntimeCallStackHolds.popLast
    (context : StaticProofContext) (original candidate : MachineState)
    (frame : RelationalRuntimeCallFrame) (continuation : Nat)
    (active : ReturnSlotOffsetInventory)
    (_holds : RelationalLinkedRuntimeCallStackHolds context original candidate
      [frame] [continuation] (some active) []) :
    RelationalLinkedRuntimeCallStackHolds context original candidate
      [] [] none [] := by
  simp [RelationalLinkedRuntimeCallStackHolds]

end StageA.Relational
