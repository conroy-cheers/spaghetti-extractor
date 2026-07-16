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

structure CallPushStackClaim where
  originalStackAddress : Expr
  candidateStackAddress : Expr
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

/-- A bounded set of simultaneously valid register-relative names for one
runtime return slot.  The names are proof witnesses for one concrete frame,
not alternative machine states. -/
structure ReturnSlotOffsetInventory where
  locations : List ReturnSlotOffsetPair
  preservedImports : List ImportRegisterRelation := []
deriving Repr, DecidableEq

def ReturnSlotOffsetInventory.maxLocations : Nat := 8

def ReturnSlotOffsetInventory.maxPreservedImports : Nat := 8

def ReturnSlotOffsetInventory.checked (inventory : ReturnSlotOffsetInventory) : Bool :=
  !inventory.locations.isEmpty &&
    decide inventory.locations.Nodup &&
    inventory.locations.length <= ReturnSlotOffsetInventory.maxLocations &&
    decide inventory.preservedImports.Nodup &&
    inventory.preservedImports.length <= ReturnSlotOffsetInventory.maxPreservedImports

def ReturnSlotOffsetInventory.holds (inventory : ReturnSlotOffsetInventory)
    (frame : RelationalRuntimeCallFrame) (original candidate : Registers Word) : Prop :=
  inventory.locations ≠ [] ∧
    ∀ location ∈ inventory.locations, location.holds frame original candidate

def ReturnSlotOffsetInventory.preservedImportsHold
    (inventory : ReturnSlotOffsetInventory) (world : RelationalWorld)
    (original candidate : Registers Word) : Bool :=
  importRegisterRelationsHold world inventory.preservedImports original candidate

def ReturnSlotOffsetInventory.preservesImportsAcross
    (inventory : ReturnSlotOffsetInventory)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  inventory.checked &&
    inventory.preservedImports.all fun relation =>
      originalBehavior.registers.get relation.original == .inputReg relation.original &&
        candidateBehavior.registers.get relation.candidate == .inputReg relation.candidate

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

inductive InternalReturnSlotMemoryTransferClaim where
  | affine (claim : ReturnSlotMemoryTransferClaim)
  | framed (claim : ReturnSlotFramedMemoryTransferClaim)
deriving Repr, DecidableEq

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
  exact ⟨offsets, by
    simpa [RelationalBehavior.nextMachineState] using memory⟩

/-- One edge may retain several checked names for a runtime return slot.  Every
retained target name must be justified by a concrete frame-transfer claim, and
each claim must start from a name already present in the source inventory. -/
structure ReturnSlotFrameInventoryTransferClaim where
  source : ReturnSlotOffsetInventory
  target : ReturnSlotOffsetInventory
  transfers : List ReturnSlotFrameTransferClaim
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
      transfer.checked context sourceInvariant originalBehavior candidateBehavior)

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
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.target.holds frame
        (originalBehavior.eval originalState).registers
        (candidateBehavior.eval candidateState).registers ∧
      frame.memoryHolds
        ((originalBehavior.eval originalState).nextMachineState originalState).memory
        ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory := by
  simp only [ReturnSlotFrameInventoryTransferClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨sourceChecked, targetChecked⟩, sourcesListed⟩, targetsExact⟩,
      transfersChecked⟩
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
      sourceMemory related
  constructor
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
      have targetListResult :
          context.codeMap.entries.toList[claim.targetId]? = some target := by
        simpa [StaticCodeMap.get?] using targetResult
      simp only [StaticWordRelationSlotPair.memoryHolds] at slotHolds
      rw [slotRelation] at slotHolds
      simp only [StaticWordRelationKind.holds, codeTargetAddressPairMatches,
        fixedCodePointerRelated, targetListResult,
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
        exact slotHolds.2.1
      · rw [candidateTargetRead]
        exact slotHolds.2.2

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
  have dynamicRegisters := _importAndDynamicRegisters.2.1
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
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      originalRegister, Expr.eval]
    rw [← originalOffset]
    exact sourceOriginalRegister
  · simp only [RelationalBehavior.nextMachineState,
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
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      originalRegister, Expr.eval]
    rw [← originalOffset]
    exact sourceOriginalRegister
  · simp only [RelationalBehavior.nextMachineState,
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
    writesClaim.writes == [claim.item] &&
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
  have itemChecked : claim.item.checked context sourceInvariant = true := by
    simp only [PairedPreparedWordWritesClaim.checked, Bool.and_eq_true] at writesChecked
    rw [writesExact] at writesChecked
    simpa using writesChecked.2
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
  unfold DynamicRegisterRangeRelation.activeHolds
  simp only [List.any_eq_true]
  refine ⟨range, rangeMember, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, targetActiveRequired⟩, ?_⟩
  · simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      originalRegister, Expr.eval]
    rw [← originalOffset]
    exact sourceOriginalRegister
  · simp only [RelationalBehavior.nextMachineState,
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
      PairedPreparedWordWriteItem.value, List.map_cons, List.map_nil]
        at originalWrites candidateWrites
    simp only [RelationalBehavior.nextMachineState,
      NormalizedSymbolicBehavior.eval_writes]
    rw [originalWrites, candidateWrites]
    simp only [evalNormalizedWrites, List.map_cons, List.map_nil,
      applyConcreteWrites, List.foldl, pairedDynamicWordAddress_eval]
    rw [sourceOriginalRegister, sourceCandidateRegister]
    simp only [BitVec.add_assoc, ← BitVec.ofNat_add]
    rw [originalRelationOffset, candidateRelationOffset]
    exact targetWordsHold

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
      NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      originalRegister, DynamicStackRangeReloadClaim.originalExpression,
      Expr.eval, evalInputRegisterOffset, machineStateRead32_eq_memoryRead32]
    rw [originalRead, originalOffset]
  · simp only [RelationalBehavior.nextMachineState,
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
    unfold StaticProofContext.relationalValueTargets
    simp only [mappedValueRelated, List.any_append, Bool.or_eq_true]
    apply Or.inr
    unfold RelationalWorld.runtimeValueTargets
    simp only [List.any_append, Bool.or_eq_true]
    apply Or.inl
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
        relatedCore.2.2.2.2.2.2.2.1
  | .inputX87Status, .inputX87Status => by
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      simpa [Expr.eval] using congrArg (fun state : X87MachineState =>
        BitVec.zeroExtend 32 state.status)
        relatedCore.2.2.2.2.2.2.2.1
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

theorem PairedStaticExprWitness.original_eval_eq_value
    (context : StaticProofContext) (state : MachineState)
    (witness : PairedStaticExprWitness) (value : Word)
    (immutable : ImmutableImageWordMemory context.originalPe state.memory)
    (evaluates : witness.value context .original = some value) :
    (witness.expression .original).eval state = value := by
  induction witness generalizing value with
  | constant original candidate =>
      simpa [PairedStaticExprWitness.value,
        PairedStaticExprWitness.expression, Expr.eval] using evaluates
  | binary operation left right leftSound rightSound =>
      cases leftResult : left.value context .original with
      | none => simp [PairedStaticExprWitness.value, leftResult] at evaluates
      | some leftValue =>
          cases rightResult : right.value context .original with
          | none =>
              simp [PairedStaticExprWitness.value, leftResult, rightResult] at evaluates
          | some rightValue =>
              simp [PairedStaticExprWitness.value, leftResult, rightResult] at evaluates
              subst value
              have leftEvaluates := leftSound leftValue leftResult
              have rightEvaluates := rightSound rightValue rightResult
              cases operation <;> simp_all [PairedStaticExprWitness.expression,
                PairedExactBinaryOp.expression, PairedExactBinaryOp.value, Expr.eval]
  | unary operation operand operandSound =>
      cases operandResult : operand.value context .original with
      | none => simp [PairedStaticExprWitness.value, operandResult] at evaluates
      | some operandValue =>
          simp [PairedStaticExprWitness.value, operandResult] at evaluates
          subst value
          have operandEvaluates := operandSound operandValue operandResult
          cases operation <;> simp_all [PairedStaticExprWitness.expression,
            PairedExactUnaryOp.expression, PairedExactUnaryOp.value, Expr.eval]
  | read32 originalAddress candidateAddress =>
      cases readResult : readImmutableImageWord context.originalPe originalAddress 4 with
      | none => simp [PairedStaticExprWitness.value, readResult] at evaluates
      | some expected =>
          simp [PairedStaticExprWitness.value, readResult] at evaluates
          subst value
          have read := ImmutableImageWordMemory.read32_of_checked context.originalPe
            state.memory originalAddress expected immutable readResult
          simpa [PairedStaticExprWitness.expression, Expr.eval,
            machineStateRead32_eq_memoryRead32] using read
  | indexed operation index operand operandSound =>
      cases operandResult : operand.value context .original with
      | none => simp [PairedStaticExprWitness.value, operandResult] at evaluates
      | some operandValue =>
          simp [PairedStaticExprWitness.value, operandResult] at evaluates
          subst value
          have operandEvaluates := operandSound operandValue operandResult
          cases operation <;> simp_all [PairedStaticExprWitness.expression,
            PairedExactIndexedOp.expression, PairedExactIndexedOp.value, Expr.eval]

theorem PairedStaticExprWitness.candidate_eval_eq_value
    (context : StaticProofContext) (state : MachineState)
    (witness : PairedStaticExprWitness) (value : Word)
    (immutable : ImmutableImageWordMemory context.candidatePe state.memory)
    (evaluates : witness.value context .candidate = some value) :
    (witness.expression .candidate).eval state = value := by
  induction witness generalizing value with
  | constant original candidate =>
      simpa [PairedStaticExprWitness.value,
        PairedStaticExprWitness.expression, Expr.eval] using evaluates
  | binary operation left right leftSound rightSound =>
      cases leftResult : left.value context .candidate with
      | none => simp [PairedStaticExprWitness.value, leftResult] at evaluates
      | some leftValue =>
          cases rightResult : right.value context .candidate with
          | none =>
              simp [PairedStaticExprWitness.value, leftResult, rightResult] at evaluates
          | some rightValue =>
              simp [PairedStaticExprWitness.value, leftResult, rightResult] at evaluates
              subst value
              have leftEvaluates := leftSound leftValue leftResult
              have rightEvaluates := rightSound rightValue rightResult
              cases operation <;> simp_all [PairedStaticExprWitness.expression,
                PairedExactBinaryOp.expression, PairedExactBinaryOp.value, Expr.eval]
  | unary operation operand operandSound =>
      cases operandResult : operand.value context .candidate with
      | none => simp [PairedStaticExprWitness.value, operandResult] at evaluates
      | some operandValue =>
          simp [PairedStaticExprWitness.value, operandResult] at evaluates
          subst value
          have operandEvaluates := operandSound operandValue operandResult
          cases operation <;> simp_all [PairedStaticExprWitness.expression,
            PairedExactUnaryOp.expression, PairedExactUnaryOp.value, Expr.eval]
  | read32 originalAddress candidateAddress =>
      cases readResult : readImmutableImageWord context.candidatePe candidateAddress 4 with
      | none => simp [PairedStaticExprWitness.value, readResult] at evaluates
      | some expected =>
          simp [PairedStaticExprWitness.value, readResult] at evaluates
          subst value
          have read := ImmutableImageWordMemory.read32_of_checked context.candidatePe
            state.memory candidateAddress expected immutable readResult
          simpa [PairedStaticExprWitness.expression, Expr.eval,
            machineStateRead32_eq_memoryRead32] using read
  | indexed operation index operand operandSound =>
      cases operandResult : operand.value context .candidate with
      | none => simp [PairedStaticExprWitness.value, operandResult] at evaluates
      | some operandValue =>
          simp [PairedStaticExprWitness.value, operandResult] at evaluates
          subst value
          have operandEvaluates := operandSound operandValue operandResult
          cases operation <;> simp_all [PairedStaticExprWitness.expression,
            PairedExactIndexedOp.expression, PairedExactIndexedOp.value, Expr.eval]

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
  | read8At (address : PairedStaticExprWitness)
  | read32At (address : PairedStaticExprWitness)
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
  | .read8At address => .read8 (address.expression side)
  | .read32At address => .read32 (address.expression side)
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
  | .read8At address | .read32At address =>
      match address.value context .original, address.value context .candidate with
      | some originalAddress, some candidateAddress =>
          immutableImageWordsPairedEqual context originalAddress.toNat
            candidateAddress.toNat
      | _, _ => false
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
        relatedCore.2.2.2.2.2.2.2.1
  | inputX87Status =>
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      simpa [PairedExactExprWitness.expression, Expr.eval] using congrArg
        (fun state : X87MachineState => BitVec.zeroExtend 32 state.status)
        relatedCore.2.2.2.2.2.2.2.1
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
  | read8At address =>
      simp only [PairedExactExprWitness.checked] at checked
      cases originalResult : address.value context .original with
      | none => simp [originalResult] at checked
      | some originalValue =>
          cases candidateResult : address.value context .candidate with
          | none => simp [originalResult, candidateResult] at checked
          | some candidateValue =>
              simp [originalResult, candidateResult] at checked
              have originalAddress := address.original_eval_eq_value context original
                originalValue
                (StateRel.originalImmutableImageWordMemory context world invariant
                  original candidate related) originalResult
              have candidateAddress := address.candidate_eval_eq_value context candidate
                candidateValue
                (StateRel.candidateImmutableImageWordMemory context world invariant
                  original candidate related) candidateResult
              have readEqual := immutablePairedConstantRead8_eval_equal context
                originalValue.toNat candidateValue.toNat original candidate
                (StateRel.originalImmutableImageWordMemory context world invariant
                  original candidate related)
                (StateRel.candidateImmutableImageWordMemory context world invariant
                  original candidate related) checked
              simpa [PairedExactExprWitness.expression, Expr.eval, originalAddress,
                candidateAddress] using readEqual
  | read32At address =>
      simp only [PairedExactExprWitness.checked] at checked
      cases originalResult : address.value context .original with
      | none => simp [originalResult] at checked
      | some originalValue =>
          cases candidateResult : address.value context .candidate with
          | none => simp [originalResult, candidateResult] at checked
          | some candidateValue =>
              simp [originalResult, candidateResult] at checked
              have originalAddress := address.original_eval_eq_value context original
                originalValue
                (StateRel.originalImmutableImageWordMemory context world invariant
                  original candidate related) originalResult
              have candidateAddress := address.candidate_eval_eq_value context candidate
                candidateValue
                (StateRel.candidateImmutableImageWordMemory context world invariant
                  original candidate related) candidateResult
              have readEqual := immutablePairedConstantRead32_eval_equal context
                originalValue.toNat candidateValue.toNat original candidate
                (StateRel.originalImmutableImageWordMemory context world invariant
                  original candidate related)
                (StateRel.candidateImmutableImageWordMemory context world invariant
                  original candidate related) checked
              simpa [PairedExactExprWitness.expression, Expr.eval, originalAddress,
                candidateAddress] using readEqual
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
    | fixedCodePointer _ => simp [relationKind] at supportedRelation
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
    (∃ originalNormalized candidateNormalized claim,
      NodeImmutableIndirectCallEdgesComplete graph nodeId context region originalBehavior
        candidateBehavior originalNormalized candidateNormalized claim) ∨
    (∃ originalNormalized candidateNormalized claim,
      NodeImportRegisterIndirectCallEdgesComplete graph nodeId context region originalBehavior
        candidateBehavior originalNormalized candidateNormalized claim) ∨
    (∃ originalNormalized candidateNormalized claim,
      NodeFixedCodePointerRegisterIndirectCallEdgesComplete graph nodeId context region
        originalBehavior candidateBehavior originalNormalized candidateNormalized claim) ∨
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
