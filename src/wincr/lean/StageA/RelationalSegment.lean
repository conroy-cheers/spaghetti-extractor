import StageA.Relational

namespace StageA.Relational

open StageA.Formal

inductive RelationalSegmentExit where
  | internal (targetId : Nat)
  | external (imported : ExternalTarget)
  | returned
  | fault
deriving Repr, DecidableEq

def PureOutcome.segmentExit : PureOutcome -> Option RelationalSegmentExit
  | .jump target => some (.internal target)
  | .branch condition taken fallthrough =>
      some (.internal (if condition then taken else fallthrough))
  | .call target _ => some (.internal target)
  | .externalCall imported _ _ | .externalJump imported _ =>
      some (.external imported)
  | .bulkCopy _ _ _ _ continuation | .checkedContinue true continuation |
      .atomicCompareExchange _ _ _ continuation => some (.internal continuation)
  | .returned _ => some .returned
  | .checkedContinue false _ => some .fault
  | .indirectCall _ _ | .indirectJump _ => none

def PureOutcome.segmentExitFor (context : StaticProofContext) (candidate : Bool) :
    PureOutcome -> Option RelationalSegmentExit
  | .indirectCall target _ | .indirectJump target => do
      let imageBase := if candidate then context.candidatePe.imageBase
        else context.originalPe.imageBase
      let targetId <- resolveMappedCodeTarget candidate imageBase
        context.codeMap.entries.toList target
      pure (.internal targetId)
  | outcome => outcome.segmentExit

structure RelationalSegmentEdge where
  sourceTargetId : Nat
  exit : RelationalSegmentExit
  originalSpan : Span
  candidateSpan : Span
  localCodeTargetIds : List Nat := []
  localValueTargetIds : List Nat := []
  originalGuard : BoolExpr := .equal (.constant 0) (.constant 0)
  candidateGuard : BoolExpr := .equal (.constant 0) (.constant 0)
deriving Repr, DecidableEq

def SegmentTransitionClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            match evalBehavior false localCodeTargets originalState originalBehavior,
                evalBehavior true localCodeTargets candidateState candidateBehavior with
            | some originalResult, some candidateResult =>
                originalResult.outcome.segmentExitFor context false = some edge.exit ∧
                  candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
                  outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                      localCodeTargets localValues
                      originalResult.outcome candidateResult.outcome = true ∧
                  match edge.exit with
                  | .internal _ =>
                      StateRel context world targetInvariant
                        (originalResult.nextMachineState originalState)
                        (candidateResult.nextMachineState candidateState)
                  | .external _ | .returned | .fault => True
            | _, _ => False)
  | _, _ => False

def NoWriteSegmentShapeClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = [] ∧ candidateResult.writes = [] ∧
                originalResult.outcome.segmentExitFor context false = some edge.exit ∧
                candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
                outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                  localCodeTargets localValues originalResult.outcome candidateResult.outcome = true)
  | _, _ => False

def DirectCallSegmentShapeClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (sourceWindow : StackWindowPair)
    (originalReturnAddress candidateReturnAddress : Word)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = [
                (originalState.registers.get sourceWindow.originalRegister -
                  BitVec.ofNat 32 4, originalReturnAddress)] ∧
              candidateResult.writes = [
                (candidateState.registers.get sourceWindow.candidateRegister -
                  BitVec.ofNat 32 4, candidateReturnAddress)] ∧
              originalResult.outcome.segmentExitFor context false = some edge.exit ∧
              candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
              outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                localCodeTargets localValues originalResult.outcome
                  candidateResult.outcome = true)
  | _, _ => False

inductive PairedStackWordValueWitness where
  | exactInputs
  | registerArgument (claim : RegisterArgumentClaim)
deriving Repr, DecidableEq

structure PairedStackWordValueClaim where
  original : Expr
  candidate : Expr
  witness : PairedStackWordValueWitness
deriving Repr, DecidableEq

def PairedStackWordValueClaim.checked (sourceInvariant : StateInvariant)
    (claim : PairedStackWordValueClaim) : Bool :=
  match claim.witness with
  | .exactInputs =>
      claim.original == claim.candidate &&
        claim.original.exactInputs sourceInvariant.registerRelations
  | .registerArgument registerClaim =>
      registerClaim.checked sourceInvariant claim.original claim.candidate

theorem PairedStackWordValueClaim.related_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (claim : PairedStackWordValueClaim)
    (checked : claim.checked sourceInvariant = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (claim.original.eval originalState) (claim.candidate.eval candidateState) = true := by
  rcases claim with ⟨originalValue, candidateValue, witness⟩
  cases witness with
  | exactInputs =>
      simp only [PairedStackWordValueClaim.checked, Bool.and_eq_true,
        beq_iff_eq] at checked
      have valuesEqual := checked.1
      have safe := checked.2
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      rcases relatedCore with
        ⟨registers, _, _, _, _, _dynamicWords, undefinedValue, _, _, fsBase⟩
      have evaluationsEqual := Expr.eval_eq_of_exactInputs
        context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        sourceInvariant.registerRelations originalState candidateState originalValue
        registers undefinedValue fsBase safe
      rw [← valuesEqual]
      rw [evaluationsEqual]
      exact wordRelated_self context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world) _
  | registerArgument registerClaim =>
      exact registerArgumentWordsRelated_of_checked context world sourceInvariant
        originalValue candidateValue registerClaim checked originalState candidateState related

structure PairedStackWordWriteClaim where
  window : StackWindowPair
  amount : Nat
  value : PairedStackWordValueClaim
deriving Repr, DecidableEq

def PairedStackWordWriteClaim.originalAddress
    (claim : PairedStackWordWriteClaim) : Expr :=
  .add (.inputReg claim.window.originalRegister) (.constant claim.amount)

def PairedStackWordWriteClaim.candidateAddress
    (claim : PairedStackWordWriteClaim) : Expr :=
  .add (.inputReg claim.window.candidateRegister) (.constant claim.amount)

def PairedStackWordWriteClaim.checked (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : PairedStackWordWriteClaim) : Bool :=
  claim.amount % 4 == 0 &&
    claim.amount + 4 <= claim.window.bytesAbove &&
    originalBehavior.writes == [(claim.originalAddress, claim.value.original)] &&
    candidateBehavior.writes == [(claim.candidateAddress, claim.value.candidate)] &&
    claim.value.checked sourceInvariant

def PairedStackWordWriteSegmentShapeClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (claim : PairedStackWordWriteClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = [
                (claim.originalAddress.eval originalState,
                  claim.value.original.eval originalState)] ∧
              candidateResult.writes = [
                (claim.candidateAddress.eval candidateState,
                  claim.value.candidate.eval candidateState)] ∧
              originalResult.outcome.segmentExitFor context false = some edge.exit ∧
              candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
              outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                localCodeTargets localValues originalResult.outcome
                  candidateResult.outcome = true)
  | _, _ => False

theorem PairedStackWordWriteClaim.valueRelated_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : PairedStackWordWriteClaim)
    (checked : claim.checked sourceInvariant originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (claim.value.original.eval originalState)
      (claim.value.candidate.eval candidateState) = true := by
  simp only [PairedStackWordWriteClaim.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at checked
  exact claim.value.related_of_checked context world sourceInvariant checked.2
    originalState candidateState related

def pairedStackWordAddress (register : Reg) (amount : Nat) : Expr :=
  if amount = 0 then .inputReg register
  else .add (.inputReg register) (.constant amount)

theorem pairedStackWordAddress_eval (register : Reg) (amount : Nat)
    (state : MachineState) :
    (pairedStackWordAddress register amount).eval state =
      state.registers.get register + BitVec.ofNat 32 amount := by
  by_cases zero : amount = 0
  · subst amount
    simp [pairedStackWordAddress, Expr.eval]
  · simp [pairedStackWordAddress, zero, Expr.eval]

structure PairedStackWordWriteItem where
  amount : Nat
  value : PairedStackWordValueClaim
deriving Repr, DecidableEq

def PairedStackWordWriteItem.originalAddress (window : StackWindowPair)
    (item : PairedStackWordWriteItem) : Expr :=
  pairedStackWordAddress window.originalRegister item.amount

def PairedStackWordWriteItem.candidateAddress (window : StackWindowPair)
    (item : PairedStackWordWriteItem) : Expr :=
  pairedStackWordAddress window.candidateRegister item.amount

def PairedStackWordWriteItem.checked (sourceInvariant : StateInvariant)
    (window : StackWindowPair) (item : PairedStackWordWriteItem) : Bool :=
  item.amount % 4 == 0 &&
    item.amount + 4 <= window.bytesAbove &&
    item.value.checked sourceInvariant

structure PairedStackWordWritesClaim where
  window : StackWindowPair
  writes : List PairedStackWordWriteItem
deriving Repr, DecidableEq

def PairedStackWordWritesClaim.originalSymbolicWrites
    (claim : PairedStackWordWritesClaim) : List (Expr × Expr) :=
  claim.writes.map fun item =>
    (item.originalAddress claim.window, item.value.original)

def PairedStackWordWritesClaim.candidateSymbolicWrites
    (claim : PairedStackWordWritesClaim) : List (Expr × Expr) :=
  claim.writes.map fun item =>
    (item.candidateAddress claim.window, item.value.candidate)

def PairedStackWordWritesClaim.originalWrites
    (claim : PairedStackWordWritesClaim) (state : MachineState) : List (Word × Word) :=
  claim.writes.map fun item =>
    ((item.originalAddress claim.window).eval state, item.value.original.eval state)

def PairedStackWordWritesClaim.candidateWrites
    (claim : PairedStackWordWritesClaim) (state : MachineState) : List (Word × Word) :=
  claim.writes.map fun item =>
    ((item.candidateAddress claim.window).eval state, item.value.candidate.eval state)

def PairedStackWordWritesClaim.checked (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : PairedStackWordWritesClaim) : Bool :=
  !claim.writes.isEmpty &&
    claim.writes.all (PairedStackWordWriteItem.checked sourceInvariant claim.window) &&
    originalBehavior.writes == claim.originalSymbolicWrites &&
    candidateBehavior.writes == claim.candidateSymbolicWrites

def PairedStackWordWritesSegmentShapeClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (claim : PairedStackWordWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = claim.originalWrites originalState ∧
              candidateResult.writes = claim.candidateWrites candidateState ∧
              originalResult.outcome.segmentExitFor context false = some edge.exit ∧
              candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
              outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                localCodeTargets localValues originalResult.outcome
                  candidateResult.outcome = true)
  | _, _ => False

theorem PairedStackWordWriteItem.valueRelated_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (window : StackWindowPair)
    (item : PairedStackWordWriteItem)
    (checked : item.checked sourceInvariant window = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (item.value.original.eval originalState)
      (item.value.candidate.eval candidateState) = true := by
  simp only [PairedStackWordWriteItem.checked, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  exact item.value.related_of_checked context world sourceInvariant checked.2
    originalState candidateState related

theorem pairedStackWordUpdates_of_checkedItems
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (window : StackWindowPair)
    (items : List PairedStackWordWriteItem)
    (originalState candidateState : MachineState)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world originalState.registers
      candidateState.registers = true)
    (itemsChecked :
      items.all (PairedStackWordWriteItem.checked sourceInvariant window) = true)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    ∃ updates : List (PairedStackWordUpdate context world),
      updates.map PairedStackWordUpdate.originalWrite =
          items.map (fun item =>
            ((item.originalAddress window).eval originalState,
              item.value.original.eval originalState)) ∧
        updates.map PairedStackWordUpdate.candidateWrite =
          items.map (fun item =>
            ((item.candidateAddress window).eval candidateState,
              item.value.candidate.eval candidateState)) := by
  induction items with
  | nil => exact ⟨[], rfl, rfl⟩
  | cons item rest induction =>
      simp only [List.all_cons, Bool.and_eq_true] at itemsChecked
      have itemChecked := itemsChecked.1
      have itemCheckedForValue := itemChecked
      have restChecked := itemsChecked.2
      simp only [PairedStackWordWriteItem.checked, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at itemChecked
      have amountAligned := itemChecked.1.1
      have enoughAbove := itemChecked.1.2
      rcases pairedStackWordLocation_above_window context world window
          originalState.registers candidateState.registers rangesValid windowHolds
          item.amount amountAligned enoughAbove with
        ⟨location, originalLocation, candidateLocation⟩
      have locationValid : location.range.disjointFromImages context = true := by
        have validRows := rangesValid
        simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
          List.all_eq_true] at validRows
        exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
      have valuesRelated := item.valueRelated_of_checked context world sourceInvariant
        window itemCheckedForValue originalState candidateState related
      rcases induction restChecked with ⟨updates, originalUpdates, candidateUpdates⟩
      let update : PairedStackWordUpdate context world := {
        location
        locationValid
        originalValue := item.value.original.eval originalState
        candidateValue := item.value.candidate.eval candidateState
        valuesRelated
      }
      refine ⟨update :: updates, ?_, ?_⟩
      · simp only [List.map_cons]
        rw [originalUpdates]
        congr 1
        simp [update, PairedStackWordUpdate.originalWrite,
          PairedStackWordWriteItem.originalAddress, pairedStackWordAddress_eval,
          originalLocation]
      · simp only [List.map_cons]
        rw [candidateUpdates]
        congr 1
        simp [update, PairedStackWordUpdate.candidateWrite,
          PairedStackWordWriteItem.candidateAddress, pairedStackWordAddress_eval,
          candidateLocation]

def NoWriteSegmentStateTransferClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds with
  | some localCodeTargets =>
      ∀ world originalState candidateState originalResult candidateResult,
        StateRel context world sourceInvariant originalState candidateState →
        evalBehavior false localCodeTargets originalState originalBehavior =
            some originalResult →
        evalBehavior true localCodeTargets candidateState candidateBehavior =
            some candidateResult →
        edge.originalGuard.eval originalState = true →
        registerRelationsHold context.originalPe.imageBase context.candidatePe.imageBase
              context.codeMap.entries.toList (context.relationalValueTargets world)
              targetInvariant.registerRelations originalResult.registers
              candidateResult.registers = true ∧
          boundsRelated targetInvariant.bounds originalResult.registers
              candidateResult.registers = true ∧
          addressSeparationsRelated targetInvariant.addressSeparations
              originalResult.registers candidateResult.registers = true ∧
          stackWindowsRelated world targetInvariant.stackWindows
              originalResult.registers candidateResult.registers = true ∧
          (originalResult.nextMachineState originalState).x87 =
              (candidateResult.nextMachineState candidateState).x87 ∧
          flagsRelated targetInvariant.flagBits originalResult.eflags
              candidateResult.eflags = true
  | none => False

def NoWriteSegmentImportTransferClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds with
  | some localCodeTargets =>
      ∀ world originalState candidateState originalResult candidateResult,
        StateRel context world sourceInvariant originalState candidateState →
        evalBehavior false localCodeTargets originalState originalBehavior =
            some originalResult →
        evalBehavior true localCodeTargets candidateState candidateBehavior =
            some candidateResult →
        importRegisterRelationsHold world targetInvariant.importRegisterRelations
          originalResult.registers candidateResult.registers = true
  | none => False

def NoWriteSegmentDynamicTransferClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds with
  | some localCodeTargets =>
      ∀ world originalState candidateState originalResult candidateResult,
        StateRel context world sourceInvariant originalState candidateState →
        evalBehavior false localCodeTargets originalState originalBehavior =
            some originalResult →
        evalBehavior true localCodeTargets candidateState candidateBehavior =
            some candidateResult →
        edge.originalGuard.eval originalState = true →
        dynamicRegisterRangeRelationsHold world
          targetInvariant.dynamicRegisterRangeRelations originalResult.registers
          candidateResult.registers = true
  | none => False

theorem pairedStackWordWriteReadsBack
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (sourceWindow : StackWindowPair)
    (originalValue candidateValue : Word)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (sourceWindowMember : sourceWindow ∈ sourceInvariant.stackWindows)
    (sourceWindowEnoughBelow : 4 <= sourceWindow.bytesBelow)
    (originalWrites : originalBehavior.writes = [
      (originalState.registers.get sourceWindow.originalRegister - BitVec.ofNat 32 4,
        originalValue)])
    (candidateWrites : candidateBehavior.writes = [
      (candidateState.registers.get sourceWindow.candidateRegister - BitVec.ofNat 32 4,
        candidateValue)]) :
    Memory.read32 (originalBehavior.nextMachineState originalState).memory
        (originalState.registers.get sourceWindow.originalRegister - BitVec.ofNat 32 4) =
          originalValue ∧
      Memory.read32 (candidateBehavior.nextMachineState candidateState).memory
        (candidateState.registers.get sourceWindow.candidateRegister - BitVec.ofNat 32 4) =
          candidateValue := by
  rcases related with
    ⟨_worldValid, stackRangesValid, _stackMemory, _importsStatic, _importsComplete,
      _importsMemory, _originalImmutable, _candidateImmutable, relatedCore,
      _inputImportRegisters⟩
  rcases relatedCore with
    ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,
      _inputMemory, _inputDynamicMemory, _inputUndefined, _inputX87, _inputFlags,
      _inputFsBase⟩
  simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
  have sourceWindowHolds := inputStackWindows sourceWindow sourceWindowMember
  rcases pairedStackWordLocation_below_window context world sourceWindow
      originalState.registers candidateState.registers stackRangesValid
      sourceWindowHolds sourceWindowEnoughBelow with
    ⟨location, originalLocation, candidateLocation⟩
  have locationValid : location.range.disjointFromImages context = true := by
    have validRows := stackRangesValid
    simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
      List.all_eq_true] at validRows
    exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
  have originalFits := DynamicAddressRangePair.wordAddress_fits context false
    location.range locationValid location.offset location.inside
  have candidateFits := DynamicAddressRangePair.wordAddress_fits context true
    location.range locationValid location.offset location.inside
  constructor
  · simp only [RelationalBehavior.nextMachineState, originalWrites,
      applyConcreteWrites, List.foldl]
    rw [originalLocation.symm.trans location.originalAddressExact]
    exact Memory.read32_write32_same_of_fits originalState.memory
      (location.range.originalBase + BitVec.ofNat 32 location.offset)
      originalValue originalFits
  · simp only [RelationalBehavior.nextMachineState, candidateWrites,
      applyConcreteWrites, List.foldl]
    rw [candidateLocation.symm.trans location.candidateAddressExact]
    exact Memory.read32_write32_same_of_fits candidateState.memory
      (location.range.candidateBase + BitVec.ofNat 32 location.offset)
      candidateValue candidateFits

theorem StateRel.afterNoWriteEvaluation
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (originalWrites : originalBehavior.writes = [])
    (candidateWrites : candidateBehavior.writes = [])
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
    (dynamicRegisters : dynamicRegisterRangeRelationsHold world
      targetInvariant.dynamicRegisterRangeRelations originalBehavior.registers
      candidateBehavior.registers = true) :
    StateRel context world targetInvariant
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) := by
  rcases related with
    ⟨worldStatic, stackRangesValid, stackMemory, importsStatic, importsComplete,
      importsMemory, originalImmutable, candidateImmutable, relatedCore,
      _inputImportRegisters⟩
  rcases relatedCore with
    ⟨_, _, _, _, inputMemory, inputDynamicWords, inputUndefined, _, _, inputFsBase⟩
  refine ⟨worldStatic, stackRangesValid, ?_, importsStatic, importsComplete,
    ?_, ?_, ?_, ?_, ?_⟩
  · simpa [RelationalBehavior.nextMachineState, originalWrites,
      candidateWrites] using stackMemory
  · simpa [RelationalBehavior.nextMachineState, originalWrites,
      candidateWrites] using importsMemory
  · simpa [RelationalBehavior.nextMachineState, originalWrites] using originalImmutable
  · simpa [RelationalBehavior.nextMachineState, candidateWrites] using candidateImmutable
  · refine ⟨registers, bounds, separations, stackWindows, ?_, ?_, ?_, x87, ?_, ?_⟩
    · simpa [RelationalBehavior.nextMachineState, originalWrites,
        candidateWrites] using
        ordinaryMemoryRelated_after_no_writes context world
          context.codeMap.entries.toList (context.relationalValueTargets world)
          originalState.memory candidateState.memory inputMemory
    · simpa [RelationalBehavior.nextMachineState, originalWrites,
        candidateWrites] using inputDynamicWords
    · simpa [RelationalBehavior.nextMachineState] using inputUndefined
    · simpa [RelationalBehavior.nextMachineState] using flags
    · simpa [RelationalBehavior.nextMachineState] using inputFsBase
  · exact ⟨by simpa [RelationalBehavior.nextMachineState] using importRegisters,
      by simpa [RelationalBehavior.nextMachineState] using dynamicRegisters⟩

theorem StateRel.afterPairedMemoryFamiliesUpdate
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (originalWrites candidateWrites : List (Word × Word))
    (related : StateRel context world sourceInvariant originalState candidateState)
    (originalWritesExact : originalBehavior.writes = originalWrites)
    (candidateWritesExact : candidateBehavior.writes = candidateWrites)
    (memoryFamilies : RelationalMemoryFamiliesHold context world
      (applyConcreteWrites originalState.memory originalWrites)
      (applyConcreteWrites candidateState.memory candidateWrites))
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
    (dynamicRegisters : dynamicRegisterRangeRelationsHold world
      targetInvariant.dynamicRegisterRangeRelations originalBehavior.registers
      candidateBehavior.registers = true) :
    StateRel context world targetInvariant
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) := by
  rcases related with
    ⟨worldStatic, stackRangesValid, _stackMemory, importsStatic, importsComplete,
      _importsMemory, _originalImmutable, _candidateImmutable, relatedCore,
      _inputImportRegisters⟩
  rcases relatedCore with
    ⟨_, _, _, _, _inputMemory, _inputDynamicWords, inputUndefined, _, _,
      inputFsBase⟩
  refine ⟨worldStatic, stackRangesValid, ?_, importsStatic, importsComplete,
    ?_, ?_, ?_, ?_, ?_⟩
  · simpa [RelationalBehavior.nextMachineState, originalWritesExact,
      candidateWritesExact] using memoryFamilies.stackRanges
  · simpa [RelationalBehavior.nextMachineState, originalWritesExact,
      candidateWritesExact] using memoryFamilies.importAddresses
  · simpa [RelationalBehavior.nextMachineState, originalWritesExact] using
      memoryFamilies.originalImmutable
  · simpa [RelationalBehavior.nextMachineState, candidateWritesExact] using
      memoryFamilies.candidateImmutable
  · refine ⟨registers, bounds, separations, stackWindows, ?_, ?_, ?_, x87, ?_, ?_⟩
    · simpa [RelationalBehavior.nextMachineState, originalWritesExact,
        candidateWritesExact] using memoryFamilies.ordinary
    · simpa [RelationalDynamicMemoryHold, RelationalBehavior.nextMachineState,
        originalWritesExact, candidateWritesExact] using
        And.intro memoryFamilies.dynamicRanges memoryFamilies.staticPointerSlots
    · simpa [RelationalBehavior.nextMachineState] using inputUndefined
    · simpa [RelationalBehavior.nextMachineState] using flags
    · simpa [RelationalBehavior.nextMachineState] using inputFsBase
  · exact ⟨by simpa [RelationalBehavior.nextMachineState] using importRegisters,
      by simpa [RelationalBehavior.nextMachineState] using dynamicRegisters⟩

theorem segmentTransitionClosed_of_no_write_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (shape : NoWriteSegmentShapeClosed context edge sourceInvariant
      originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold NoWriteSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  intro world originalState candidateState related
  have relatedForShape := related
  have relatedForTransfer := related
  have relatedForImports := related
  have relatedForDynamic := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨guardsAgree, shapeClosed⟩
  refine ⟨guardsAgree, ?_⟩
  intro guardTrue
  rcases shapeClosed guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval, originalWrites,
      candidateWrites, originalExit, candidateExit, outcomes⟩
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases relatedForTransfer with
        ⟨worldStatic, stackRangesValid, stackMemory, importsStatic, importsComplete,
          importsMemory, originalImmutable, candidateImmutable, relatedCore,
          _inputImportRegisters⟩
      rcases relatedCore with
        ⟨_, _, _, _, inputMemory, inputDynamicWords, inputUndefined, _, _,
          inputFsBase⟩
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      refine ⟨worldStatic, stackRangesValid, ?_, importsStatic, importsComplete,
        ?_, ?_, ?_, ?_, ?_⟩
      · simpa [RelationalBehavior.nextMachineState, originalWrites,
          candidateWrites] using stackMemory
      · simpa [RelationalBehavior.nextMachineState, originalWrites,
          candidateWrites] using importsMemory
      · simpa [RelationalBehavior.nextMachineState, originalWrites] using
          originalImmutable
      · simpa [RelationalBehavior.nextMachineState, candidateWrites] using
          candidateImmutable
      · refine ⟨registers, bounds, separations, stackWindows, ?_, ?_, ?_, x87, ?_, ?_⟩
        · simpa [RelationalBehavior.nextMachineState, originalWrites,
            candidateWrites] using
            ordinaryMemoryRelated_after_no_writes context world
              context.codeMap.entries.toList (context.relationalValueTargets world)
              originalState.memory candidateState.memory inputMemory
        · simpa [RelationalBehavior.nextMachineState, originalWrites,
            candidateWrites] using inputDynamicWords
        · simpa [RelationalBehavior.nextMachineState] using inputUndefined
        · simpa [RelationalBehavior.nextMachineState] using flags
        · simpa [RelationalBehavior.nextMachineState] using inputFsBase
      · constructor
        · simpa [RelationalBehavior.nextMachineState] using outputImports
        · simpa [RelationalBehavior.nextMachineState] using outputDynamic
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionClosed_of_direct_call_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (sourceWindow : StackWindowPair)
    (originalReturnAddress candidateReturnAddress : Word)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : sourceWindow ∈ sourceInvariant.stackWindows)
    (sourceWindowEnoughBelow : 4 <= sourceWindow.bytesBelow)
    (returnAddressesRelated : ∀ world,
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        originalReturnAddress candidateReturnAddress = true)
    (shape : DirectCallSegmentShapeClosed context edge sourceInvariant sourceWindow
      originalReturnAddress candidateReturnAddress originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold DirectCallSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  intro world originalState candidateState related
  have relatedForShape := related
  have relatedForTransfer := related
  have relatedForImports := related
  have relatedForDynamic := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨guardsAgree, shapeClosed⟩
  refine ⟨guardsAgree, ?_⟩
  intro guardTrue
  rcases shapeClosed guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval,
      originalWrites, candidateWrites, originalExit, candidateExit, outcomes⟩
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases relatedForTransfer with
        ⟨worldValid, stackRangesValid, stackMemory, importsStatic, _importsComplete,
          importsMemory, originalImmutable, candidateImmutable, relatedCore,
          _inputImportRegisters⟩
      rcases relatedCore with
        ⟨_, _, _, inputStackWindows, inputMemory, inputDynamicMemory,
          _inputUndefined, _, _, _inputFsBase⟩
      simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
      have sourceWindowHolds := inputStackWindows sourceWindow sourceWindowMember
      rcases pairedStackWordLocation_below_window context world sourceWindow
          originalState.registers candidateState.registers stackRangesValid
          sourceWindowHolds sourceWindowEnoughBelow with
        ⟨location, originalLocation, candidateLocation⟩
      have originalWriteAddress :
          originalState.registers.get sourceWindow.originalRegister - BitVec.ofNat 32 4 =
            location.range.originalBase + BitVec.ofNat 32 location.offset :=
        originalLocation.symm.trans location.originalAddressExact
      have candidateWriteAddress :
          candidateState.registers.get sourceWindow.candidateRegister - BitVec.ofNat 32 4 =
            location.range.candidateBase + BitVec.ofNat 32 location.offset :=
        candidateLocation.symm.trans location.candidateAddressExact
      have locationValid : location.range.disjointFromImages context = true := by
        have validRows := stackRangesValid
        simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
          List.all_eq_true] at validRows
        exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
      have worldDynamicValid : world.dynamicRangesValid context = true := by
        have valid := worldValid
        simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
        exact valid.1.1.1
      have staticSlotsValid : staticDynamicPointerSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
        exact slotsValid
      have outputMemoryFamilies :=
        RelationalMemoryFamiliesHold.afterPairedStackWordWrite context world
          originalState.memory candidateState.memory stackRangesValid importsStatic
          worldDynamicValid staticSlotsValid location locationValid originalReturnAddress
          candidateReturnAddress (returnAddressesRelated world) {
            stackRanges := stackMemory
            importAddresses := importsMemory
            originalImmutable := originalImmutable
            candidateImmutable := candidateImmutable
            ordinary := inputMemory
            dynamicRanges := inputDynamicMemory.1
            staticPointerSlots := inputDynamicMemory.2
          }
      rw [location.originalAddressExact, location.candidateAddressExact]
        at outputMemoryFamilies
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        [(originalState.registers.get sourceWindow.originalRegister - BitVec.ofNat 32 4,
          originalReturnAddress)]
        [(candidateState.registers.get sourceWindow.candidateRegister - BitVec.ofNat 32 4,
          candidateReturnAddress)] related originalWrites candidateWrites
      · simpa [applyConcreteWrites, originalWriteAddress, candidateWriteAddress] using
          outputMemoryFamilies
      · exact registers
      · exact bounds
      · exact separations
      · exact stackWindows
      · exact x87
      · exact flags
      · exact outputImports
      · exact outputDynamic
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionClosed_of_paired_stack_word_write_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedStackWordWriteClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : claim.window ∈ sourceInvariant.stackWindows)
    (claimChecked :
      claim.checked sourceInvariant originalNormalized candidateNormalized = true)
    (shape : PairedStackWordWriteSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold PairedStackWordWriteSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  have claimCheckedForValue := claimChecked
  simp only [PairedStackWordWriteClaim.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at claimChecked
  have amountAligned := claimChecked.1.1.1.1
  have enoughAbove := claimChecked.1.1.1.2
  intro world originalState candidateState related
  have relatedForShape := related
  have relatedForMemory := related
  have relatedForImports := related
  have relatedForDynamic := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨guardsAgree, shapeClosed⟩
  refine ⟨guardsAgree, ?_⟩
  intro guardTrue
  rcases shapeClosed guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval,
      originalWrites, candidateWrites, originalExit, candidateExit, outcomes⟩
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases relatedForMemory with
        ⟨worldValid, stackRangesValid, stackMemory, importsStatic, _importsComplete,
          importsMemory, originalImmutable, candidateImmutable, relatedCore,
          _inputImportRegisters⟩
      rcases relatedCore with
        ⟨_, _, _, inputStackWindows, inputMemory, inputDynamicMemory,
          _inputUndefined, _, _, _inputFsBase⟩
      simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
      have sourceWindowHolds := inputStackWindows claim.window sourceWindowMember
      rcases pairedStackWordLocation_above_window context world claim.window
          originalState.registers candidateState.registers stackRangesValid
          sourceWindowHolds claim.amount amountAligned enoughAbove with
        ⟨location, originalLocation, candidateLocation⟩
      have originalWriteAddress :
          claim.originalAddress.eval originalState =
            location.range.originalBase + BitVec.ofNat 32 location.offset := by
        simpa [PairedStackWordWriteClaim.originalAddress, Expr.eval] using
          originalLocation.symm.trans location.originalAddressExact
      have candidateWriteAddress :
          claim.candidateAddress.eval candidateState =
            location.range.candidateBase + BitVec.ofNat 32 location.offset := by
        simpa [PairedStackWordWriteClaim.candidateAddress, Expr.eval] using
          candidateLocation.symm.trans location.candidateAddressExact
      have locationValid : location.range.disjointFromImages context = true := by
        have validRows := stackRangesValid
        simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
          List.all_eq_true] at validRows
        exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
      have worldDynamicValid : world.dynamicRangesValid context = true := by
        have valid := worldValid
        simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
        exact valid.1.1.1
      have staticSlotsValid : staticDynamicPointerSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
        exact slotsValid
      have valuesRelated := claim.valueRelated_of_checked context world
        sourceInvariant originalNormalized candidateNormalized claimCheckedForValue
        originalState candidateState related
      have outputMemoryFamilies :=
        RelationalMemoryFamiliesHold.afterPairedStackWordWrite context world
          originalState.memory candidateState.memory stackRangesValid importsStatic
          worldDynamicValid staticSlotsValid location locationValid
          (claim.value.original.eval originalState)
          (claim.value.candidate.eval candidateState)
          valuesRelated {
            stackRanges := stackMemory
            importAddresses := importsMemory
            originalImmutable := originalImmutable
            candidateImmutable := candidateImmutable
            ordinary := inputMemory
            dynamicRanges := inputDynamicMemory.1
            staticPointerSlots := inputDynamicMemory.2
          }
      rw [location.originalAddressExact, location.candidateAddressExact]
        at outputMemoryFamilies
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        [(claim.originalAddress.eval originalState,
          claim.value.original.eval originalState)]
        [(claim.candidateAddress.eval candidateState,
          claim.value.candidate.eval candidateState)]
        related originalWrites candidateWrites
      · simpa [applyConcreteWrites, originalWriteAddress, candidateWriteAddress] using
          outputMemoryFamilies
      · exact registers
      · exact bounds
      · exact separations
      · exact stackWindows
      · exact x87
      · exact flags
      · exact outputImports
      · exact outputDynamic
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionClosed_of_paired_stack_word_writes_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedStackWordWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : claim.window ∈ sourceInvariant.stackWindows)
    (claimChecked :
      claim.checked sourceInvariant originalNormalized candidateNormalized = true)
    (shape : PairedStackWordWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold PairedStackWordWritesSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  simp only [PairedStackWordWritesClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at claimChecked
  have itemsChecked := claimChecked.1.1.2
  intro world originalState candidateState related
  have relatedForShape := related
  have relatedForMemory := related
  have relatedForImports := related
  have relatedForDynamic := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨guardsAgree, shapeClosed⟩
  refine ⟨guardsAgree, ?_⟩
  intro guardTrue
  rcases shapeClosed guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval,
      originalWrites, candidateWrites, originalExit, candidateExit, outcomes⟩
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases relatedForMemory with
        ⟨worldValid, stackRangesValid, stackMemory, importsStatic, _importsComplete,
          importsMemory, originalImmutable, candidateImmutable, relatedCore,
          _inputImportRegisters⟩
      rcases relatedCore with
        ⟨_, _, _, inputStackWindows, inputMemory, inputDynamicMemory,
          _inputUndefined, _, _, _inputFsBase⟩
      simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
      have sourceWindowHolds := inputStackWindows claim.window sourceWindowMember
      rcases pairedStackWordUpdates_of_checkedItems context world sourceInvariant
          claim.window claim.writes originalState candidateState stackRangesValid
          sourceWindowHolds itemsChecked related with
        ⟨updates, originalUpdateWrites, candidateUpdateWrites⟩
      change updates.map PairedStackWordUpdate.originalWrite =
        claim.originalWrites originalState at originalUpdateWrites
      change updates.map PairedStackWordUpdate.candidateWrite =
        claim.candidateWrites candidateState at candidateUpdateWrites
      have worldDynamicValid : world.dynamicRangesValid context = true := by
        have valid := worldValid
        simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
        exact valid.1.1.1
      have staticSlotsValid : staticDynamicPointerSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
        exact slotsValid
      have outputMemoryFamilies :=
        RelationalMemoryFamiliesHold.afterPairedStackWordUpdates context world
          stackRangesValid importsStatic worldDynamicValid staticSlotsValid updates
          originalState.memory candidateState.memory {
            stackRanges := stackMemory
            importAddresses := importsMemory
            originalImmutable := originalImmutable
            candidateImmutable := candidateImmutable
            ordinary := inputMemory
            dynamicRanges := inputDynamicMemory.1
            staticPointerSlots := inputDynamicMemory.2
          }
      rw [originalUpdateWrites, candidateUpdateWrites] at outputMemoryFamilies
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        (claim.originalWrites originalState) (claim.candidateWrites candidateState)
        related originalWrites candidateWrites outputMemoryFamilies registers bounds
        separations stackWindows x87 flags outputImports outputDynamic
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionClosed_of_direct_call
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (sourceWindow : StackWindowPair)
    (originalReturnAddress candidateReturnAddress : Word)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : sourceWindow ∈ sourceInvariant.stackWindows)
    (sourceWindowEnoughBelow : 4 <= sourceWindow.bytesBelow)
    (returnAddressesRelated : ∀ world,
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        originalReturnAddress candidateReturnAddress = true)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (shape : DirectCallSegmentShapeClosed context edge sourceInvariant sourceWindow
      originalReturnAddress candidateReturnAddress originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_direct_call_with_transfers context edge
    sourceInvariant targetInvariant sourceWindow originalReturnAddress
    candidateReturnAddress originalBehavior candidateBehavior localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved contextValid sourceWindowMember
    sourceWindowEnoughBelow returnAddressesRelated shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · unfold NoWriteSegmentDynamicTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval guardTrue
    simp [targetDynamicRelationsEmpty, dynamicRegisterRangeRelationsHold]

theorem segmentTransitionClosed_of_no_write_with_imports
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (shape : NoWriteSegmentShapeClosed context edge sourceInvariant
      originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = []) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_no_write_with_transfers context edge sourceInvariant
    targetInvariant originalBehavior candidateBehavior localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved shape stateTransfer importTransfer
  unfold NoWriteSegmentDynamicTransferClosed
  rw [localCodeTargetsResolved]
  intro world originalState candidateState originalResult candidateResult related
    originalEval candidateEval _guardTrue
  simp [targetDynamicRelationsEmpty, dynamicRegisterRangeRelationsHold]

theorem segmentTransitionClosed_of_no_write_with_dynamic
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (shape : NoWriteSegmentShapeClosed context edge sourceInvariant
      originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_no_write_with_transfers context edge sourceInvariant
    targetInvariant originalBehavior candidateBehavior localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · exact dynamicTransfer

theorem segmentTransitionClosed_of_no_write
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (shape : NoWriteSegmentShapeClosed context edge sourceInvariant
      originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_no_write_with_imports context edge sourceInvariant
    targetInvariant originalBehavior candidateBehavior localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved shape stateTransfer
  unfold NoWriteSegmentImportTransferClosed
  rw [localCodeTargetsResolved]
  intro world originalState candidateState originalResult candidateResult related
    originalEval candidateEval
  simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  exact targetDynamicRelationsEmpty

theorem segmentTransitionClosed_of_paired_stack_word_write
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedStackWordWriteClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : claim.window ∈ sourceInvariant.stackWindows)
    (claimChecked :
      claim.checked sourceInvariant originalNormalized candidateNormalized = true)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (shape : PairedStackWordWriteSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_paired_stack_word_write_with_transfers context edge
    sourceInvariant targetInvariant claim originalBehavior candidateBehavior
    originalNormalized candidateNormalized localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved contextValid sourceWindowMember
    claimChecked shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · unfold NoWriteSegmentDynamicTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval guardTrue
    simp [targetDynamicRelationsEmpty, dynamicRegisterRangeRelationsHold]

theorem segmentTransitionClosed_of_paired_stack_word_writes
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedStackWordWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : claim.window ∈ sourceInvariant.stackWindows)
    (claimChecked :
      claim.checked sourceInvariant originalNormalized candidateNormalized = true)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (shape : PairedStackWordWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_paired_stack_word_writes_with_transfers context edge
    sourceInvariant targetInvariant claim originalBehavior candidateBehavior
    originalNormalized candidateNormalized localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved contextValid sourceWindowMember
    claimChecked shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · unfold NoWriteSegmentDynamicTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval guardTrue
    simp [targetDynamicRelationsEmpty, dynamicRegisterRangeRelationsHold]

def RelationalSegmentRefinement (context : StaticProofContext)
    (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant) : Prop :=
  ∃ originalBehavior candidateBehavior,
    regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
      context.machineImportCallContracts edge.originalSpan = some originalBehavior ∧
    regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
      context.machineImportCallContracts edge.candidateSpan = some candidateBehavior ∧
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior

theorem relationalSegmentRefinement_of_decoded
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalDecoded : regionBehaviorWithMachineCallContracts context.originalPe
      context.originalImports context.machineImportCallContracts
      edge.originalSpan = some originalBehavior)
    (candidateDecoded : regionBehaviorWithMachineCallContracts context.candidatePe
      context.candidateImports context.machineImportCallContracts
      edge.candidateSpan = some candidateBehavior)
    (transition : SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior) :
    RelationalSegmentRefinement context edge sourceInvariant targetInvariant :=
  ⟨originalBehavior, candidateBehavior, originalDecoded, candidateDecoded, transition⟩

end StageA.Relational
