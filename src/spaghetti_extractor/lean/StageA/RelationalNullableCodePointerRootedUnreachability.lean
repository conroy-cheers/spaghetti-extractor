import StageA.RelationalNullableCodePointerDispatch

namespace StageA.Relational.NullableCodePointerRootedUnreachability

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.NullableCodePointerDispatch
open StageA.Relational.NullableCodePointerTable
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalStackDynamicControlClosure

/-!
# Exact decoded constructor-scanner exclusion

The nullable table checker proves that the reverse-sentinel table is empty.
This module checks the original constructor blocks which consume that table:

* select the reverse scanner from the immutable `-1` header;
* initialize the scanner cursor to zero;
* copy that cursor to the dispatch index and load the zero terminator;
* bridge to the dispatch gate without changing the index; and
* take the zero bypass instead of the indirect-call source.

All target identities are data in generated bindings.  The checker below
contains only the generic PE32 transfer shape.
-/

structure OriginalDecodedRegionRef where
  targetId : Nat
  span : Span
deriving Repr, DecidableEq

def originalCodeTargetPair
    (target : OriginalCodeTarget) : CodeTargetPair := {
  id := target.id
  regionIndex := target.regionIndex
  originalRva := target.rva
  candidateRva := target.rva
  originalAliases := target.aliases
  candidateAliases := target.aliases
}

def originalCodeTargetPairs?
    (context : OriginalDecodedStaticContext)
    (targetIds : List Nat) : Option (List CodeTargetPair) :=
  targetIds.mapM fun targetId => do
    let target <- context.codeMap.get? targetId
    pure (originalCodeTargetPair target)

/-- Replay one source directly from the original PE bytes.  The source span
and every normalized successor are tied to the one-sided decoded context. -/
def OriginalDecodedRegionRef.decode?
    (context : OriginalDecodedStaticContext)
    (region : OriginalDecodedRegionRef) :
    Option NormalizedSymbolicBehavior := do
  let source <- context.source? region.targetId
  if source.target.id != region.targetId ||
      source.region.id != region.targetId ||
      source.region.span != region.span then
    none
  else
    let targets <- originalCodeTargetPairs? context source.region.targets
    let behavior <- executePE32SymbolicSpan context.pe context.imports region.span
    let behavior <- applyMachineImportCallContracts
      context.machineImportCallContracts behavior
    normalizeSymbolicBehavior false targets behavior

structure OriginalScannerExecutionDecoded where
  selector : NormalizedSymbolicBehavior
  zero : NormalizedSymbolicBehavior
  scanner : NormalizedSymbolicBehavior
  bridge : NormalizedSymbolicBehavior
  gate : NormalizedSymbolicBehavior
deriving Repr, DecidableEq

structure OriginalScannerExecutionClaim where
  tableBase : Nat
  scannerRegister : Reg
  countRegister : Reg
  loadedRegister : Reg
  selectorRegion : OriginalDecodedRegionRef
  zeroRegion : OriginalDecodedRegionRef
  scannerRegion : OriginalDecodedRegionRef
  bridgeRegion : OriginalDecodedRegionRef
  gateRegion : OriginalDecodedRegionRef
  dispatchSourceTargetId : Nat
  dispatchBypassTargetId : Nat
deriving Repr, DecidableEq

def OriginalScannerExecutionClaim.headerExpression
    (claim : OriginalScannerExecutionClaim) : Expr :=
  .read32 (.constant claim.tableBase)

def OriginalScannerExecutionClaim.nextIndex
    (claim : OriginalScannerExecutionClaim) : Expr :=
  .add (.inputReg claim.scannerRegister) (.constant 1)

def OriginalScannerExecutionClaim.loadedExpression
    (claim : OriginalScannerExecutionClaim) : Expr :=
  immutableCodePointerTableTargetExpression claim.tableBase claim.nextIndex

def OriginalScannerExecutionClaim.decode?
    (context : OriginalDecodedStaticContext)
    (claim : OriginalScannerExecutionClaim) :
    Option OriginalScannerExecutionDecoded := do
  let selector <- claim.selectorRegion.decode? context
  let zero <- claim.zeroRegion.decode? context
  let scanner <- claim.scannerRegion.decode? context
  let bridge <- claim.bridgeRegion.decode? context
  let gate <- claim.gateRegion.decode? context
  pure { selector, zero, scanner, bridge, gate }

def zeroTestExpressionChecked (expression : BoolExpr) (value : Expr) : Bool :=
  expression == .equal value (.constant 0) ||
    expression == .equal (.bitAnd value value) (.constant 0)

def nonzeroTestExpressionChecked
    (expression : BoolExpr) (value : Expr) : Bool :=
  expression == .not (.equal value (.constant 0)) ||
    expression == .not
      (.equal (.bitAnd value value) (.constant 0))

def equalsConstantExpressionChecked
    (expression : BoolExpr) (value : Expr) (constant : Nat) : Bool :=
  expression == .equal value (.constant constant) ||
    expression == .equal
      (.sub value (.constant constant)) (.constant 0)

theorem zeroTestExpressionChecked_eval
    (expression : BoolExpr) (value : Expr)
    (checked : zeroTestExpressionChecked expression value = true)
    (state : MachineState) :
    expression.eval state =
      (BoolExpr.equal value (.constant 0)).eval state := by
  simp only [zeroTestExpressionChecked, Bool.or_eq_true, beq_iff_eq] at checked
  rcases checked with checked | checked
  · rw [checked]
  · rw [checked]
    simp [BoolExpr.eval, Expr.eval, BitVec.and_self]

theorem nonzeroTestExpressionChecked_eval
    (expression : BoolExpr) (value : Expr)
    (checked : nonzeroTestExpressionChecked expression value = true)
    (state : MachineState) :
    expression.eval state =
      (BoolExpr.not (.equal value (.constant 0))).eval state := by
  simp only [nonzeroTestExpressionChecked, Bool.or_eq_true,
    beq_iff_eq] at checked
  rcases checked with checked | checked
  · rw [checked]
  · rw [checked]
    simp [BoolExpr.eval, Expr.eval, BitVec.and_self]

theorem equalsConstantExpressionChecked_eval
    (expression : BoolExpr) (value : Expr) (constant : Nat)
    (checked :
      equalsConstantExpressionChecked expression value constant = true)
    (state : MachineState) :
    expression.eval state =
      (BoolExpr.equal value (.constant constant)).eval state := by
  simp only [equalsConstantExpressionChecked, Bool.or_eq_true,
    beq_iff_eq] at checked
  rcases checked with checked | checked
  · rw [checked]
  · rw [checked]
    simp only [BoolExpr.eval, Expr.eval]
    rw [Bool.eq_iff_iff, decide_eq_true_iff, decide_eq_true_iff]
    bv_omega

def selectedPureOutcomeTarget? : PureOutcome -> Option Nat
  | .jump target => some target
  | .branch condition taken fallthrough =>
      some (if condition then taken else fallthrough)
  | _ => none

theorem selectedTarget_of_guardForTarget_true
    (outcome : NormalizedOutcomeExpr) (state : MachineState)
    (target bypass : Nat) (guard : BoolExpr)
    (guardExact :
      NormalizedOutcomeExpr.guardForTarget outcome target = some guard)
    (bypassExact :
      NormalizedOutcomeExpr.bypassForTarget outcome target = some bypass)
    (taken : guard.eval state = true) :
    selectedPureOutcomeTarget? (outcome.eval state) = some target := by
  cases outcome <;>
    simp [NormalizedOutcomeExpr.guardForTarget] at guardExact
  case branch condition takenTarget fallthroughTarget =>
    simp only [NormalizedOutcomeExpr.bypassForTarget] at bypassExact
    split at guardExact
    case isTrue =>
      simp only [Option.some.injEq] at guardExact
      subst guard
      cases evaluated : condition.eval state <;>
        simp_all [NormalizedOutcomeExpr.eval, selectedPureOutcomeTarget?,
          BoolExpr.eval, evaluated]
    case isFalse =>
      split at guardExact
      case isTrue =>
        simp only [Option.some.injEq] at guardExact
        subst guard
        cases evaluated : condition.eval state <;>
        simp_all [NormalizedOutcomeExpr.eval, selectedPureOutcomeTarget?,
          BoolExpr.eval, evaluated]
      case isFalse =>
        simp at guardExact

theorem selectedTarget_of_guardForTarget_false
    (outcome : NormalizedOutcomeExpr) (state : MachineState)
    (target bypass : Nat) (guard : BoolExpr)
    (guardExact :
      NormalizedOutcomeExpr.guardForTarget outcome target = some guard)
    (bypassExact :
      NormalizedOutcomeExpr.bypassForTarget outcome target = some bypass)
    (notTaken : guard.eval state = false) :
    selectedPureOutcomeTarget? (outcome.eval state) = some bypass := by
  cases outcome <;>
    simp [NormalizedOutcomeExpr.guardForTarget] at guardExact
  case branch condition takenTarget fallthroughTarget =>
    simp only [NormalizedOutcomeExpr.bypassForTarget] at bypassExact
    split at guardExact
    case isTrue =>
      simp only [Option.some.injEq] at guardExact
      subst guard
      cases evaluated : condition.eval state <;>
        simp_all [NormalizedOutcomeExpr.eval, selectedPureOutcomeTarget?,
          BoolExpr.eval, evaluated]
    case isFalse =>
      split at guardExact
      case isTrue =>
        simp only [Option.some.injEq] at guardExact
        subst guard
        cases evaluated : condition.eval state <;>
        simp_all [NormalizedOutcomeExpr.eval, selectedPureOutcomeTarget?,
          BoolExpr.eval, evaluated]
      case isFalse =>
        simp at guardExact

def OriginalScannerExecutionClaim.selectorChecked
    (claim : OriginalScannerExecutionClaim)
    (behavior : NormalizedSymbolicBehavior) : Bool :=
  let loaded :=
    Expr.constantRead32AfterWrites claim.tableBase behavior.writes
  behavior.registers.get claim.countRegister == loaded &&
    (match NormalizedOutcomeExpr.guardForTarget behavior.outcome
        claim.zeroRegion.targetId with
      | some guard =>
          equalsConstantExpressionChecked guard loaded (2 ^ 32 - 1)
      | none => false) &&
    NormalizedOutcomeExpr.bypassForTarget behavior.outcome
        claim.zeroRegion.targetId ==
      some claim.gateRegion.targetId

def OriginalScannerExecutionClaim.zeroChecked
    (claim : OriginalScannerExecutionClaim)
    (behavior : NormalizedSymbolicBehavior) : Bool :=
  behavior.registers.get claim.scannerRegister == .constant 0 &&
    behavior.writes.isEmpty &&
    behavior.outcome == .jump claim.scannerRegion.targetId

def OriginalScannerExecutionClaim.scannerChecked
    (claim : OriginalScannerExecutionClaim)
    (behavior : NormalizedSymbolicBehavior) : Bool :=
  behavior.registers.get claim.countRegister ==
      .inputReg claim.scannerRegister &&
    behavior.registers.get claim.scannerRegister == claim.nextIndex &&
    behavior.registers.get claim.loadedRegister == claim.loadedExpression &&
    behavior.writes.isEmpty &&
    (match NormalizedOutcomeExpr.guardForTarget behavior.outcome
        claim.scannerRegion.targetId with
      | some guard =>
          nonzeroTestExpressionChecked guard claim.loadedExpression
      | none => false) &&
    NormalizedOutcomeExpr.bypassForTarget behavior.outcome
        claim.scannerRegion.targetId ==
      some claim.bridgeRegion.targetId

def OriginalScannerExecutionClaim.bridgeChecked
    (claim : OriginalScannerExecutionClaim)
    (behavior : NormalizedSymbolicBehavior) : Bool :=
  behavior.registers.get claim.countRegister ==
      .inputReg claim.countRegister &&
    behavior.writes.isEmpty &&
    behavior.outcome == .jump claim.gateRegion.targetId

def OriginalScannerExecutionClaim.gateChecked
    (claim : OriginalScannerExecutionClaim)
    (behavior : NormalizedSymbolicBehavior) : Bool :=
  behavior.registers.get claim.countRegister ==
      .inputReg claim.countRegister &&
    behavior.writes.isEmpty &&
    NormalizedOutcomeExpr.guardForTarget behavior.outcome
        claim.dispatchSourceTargetId ==
      some (registerNonzeroGuard claim.countRegister) &&
    NormalizedOutcomeExpr.bypassForTarget behavior.outcome
        claim.dispatchSourceTargetId ==
      some claim.dispatchBypassTargetId

def OriginalScannerExecutionClaim.topologyChecked
    (context : OriginalDecodedStaticContext)
    (claim : OriginalScannerExecutionClaim) : Bool :=
  NullableCodePointerTable.sameFiniteSet
      (originalSuccessorTargetIds context claim.selectorRegion.targetId)
      [claim.zeroRegion.targetId, claim.gateRegion.targetId] &&
    NullableCodePointerTable.sameFiniteSet
      (originalSuccessorTargetIds context claim.zeroRegion.targetId)
      [claim.scannerRegion.targetId] &&
    NullableCodePointerTable.sameFiniteSet
      (originalSuccessorTargetIds context claim.scannerRegion.targetId)
      [claim.scannerRegion.targetId, claim.bridgeRegion.targetId] &&
    NullableCodePointerTable.sameFiniteSet
      (originalSuccessorTargetIds context claim.bridgeRegion.targetId)
      [claim.gateRegion.targetId] &&
    NullableCodePointerTable.sameFiniteSet
      (originalSuccessorTargetIds context claim.gateRegion.targetId)
      [claim.dispatchSourceTargetId, claim.dispatchBypassTargetId] &&
    NullableCodePointerTable.sameFiniteSet
      (originalIncomingEdgesForTarget context claim.zeroRegion.targetId)
      [{
        sourceTargetId := claim.selectorRegion.targetId
        targetTargetId := claim.zeroRegion.targetId
      }] &&
    NullableCodePointerTable.sameFiniteSet
      (originalIncomingEdgesForTarget context claim.scannerRegion.targetId)
      [{
        sourceTargetId := claim.zeroRegion.targetId
        targetTargetId := claim.scannerRegion.targetId
      }, {
        sourceTargetId := claim.scannerRegion.targetId
        targetTargetId := claim.scannerRegion.targetId
      }] &&
    NullableCodePointerTable.sameFiniteSet
      (originalIncomingEdgesForTarget context claim.bridgeRegion.targetId)
      [{
        sourceTargetId := claim.scannerRegion.targetId
        targetTargetId := claim.bridgeRegion.targetId
      }] &&
    NullableCodePointerTable.sameFiniteSet
      (originalIncomingEdgesForTarget context claim.gateRegion.targetId)
      [{
        sourceTargetId := claim.selectorRegion.targetId
        targetTargetId := claim.gateRegion.targetId
      }, {
        sourceTargetId := claim.bridgeRegion.targetId
        targetTargetId := claim.gateRegion.targetId
      }]

def OriginalScannerExecutionClaim.identityChecked
    (context : OriginalDecodedStaticContext)
    (claim : OriginalScannerExecutionClaim) : Bool :=
  claim.selectorRegion.targetId != claim.zeroRegion.targetId &&
    claim.selectorRegion.targetId != claim.gateRegion.targetId &&
    claim.zeroRegion.targetId != claim.scannerRegion.targetId &&
    claim.scannerRegion.targetId != claim.bridgeRegion.targetId &&
    claim.bridgeRegion.targetId != claim.gateRegion.targetId &&
    claim.gateRegion.targetId != claim.dispatchSourceTargetId &&
    claim.dispatchSourceTargetId != claim.dispatchBypassTargetId &&
    readImmutableImageWord context.pe claim.tableBase 4 ==
      some (2 ^ 32 - 1) &&
    readImmutableImageWord context.pe (claim.tableBase + 4) 4 == some 0 &&
    claim.topologyChecked context

def OriginalScannerExecutionClaim.semanticChecked
    (claim : OriginalScannerExecutionClaim)
    (decoded : OriginalScannerExecutionDecoded) : Bool :=
  claim.selectorChecked decoded.selector &&
    claim.zeroChecked decoded.zero &&
    claim.scannerChecked decoded.scanner &&
    claim.bridgeChecked decoded.bridge &&
    claim.gateChecked decoded.gate

def OriginalScannerExecutionClaim.checked
    (context : OriginalDecodedStaticContext)
    (claim : OriginalScannerExecutionClaim) : Bool :=
  claim.identityChecked context &&
    match claim.decode? context with
    | some decoded => claim.semanticChecked decoded
    | none => false

structure CheckedOriginalScannerExecution
    (context : OriginalDecodedStaticContext) where
  decodedAuthority : ExactOriginalDecodedAuthority context
  claim : OriginalScannerExecutionClaim
  checked : claim.checked context = true

def scannerNext
    (behavior : NormalizedSymbolicBehavior)
    (state : MachineState) : MachineState :=
  (behavior.eval state).nextMachineState state

structure OriginalScannerExecutionResult
    (claim : OriginalScannerExecutionClaim)
    (decoded : OriginalScannerExecutionDecoded)
    (selectorState scannerEntryState : MachineState) : Prop where
  selectorTakesScanner :
    selectedPureOutcomeTarget? (decoded.selector.eval selectorState).outcome =
      some claim.zeroRegion.targetId
  zeroJumpsToScanner :
    selectedPureOutcomeTarget? ((decoded.zero.eval
      scannerEntryState).outcome) =
        some claim.scannerRegion.targetId
  scannerExits :
    let zeroState := scannerNext decoded.zero scannerEntryState
    selectedPureOutcomeTarget? (decoded.scanner.eval zeroState).outcome =
      some claim.bridgeRegion.targetId
  bridgeJumpsToGate :
    let zeroState := scannerNext decoded.zero scannerEntryState
    let scannerState := scannerNext decoded.scanner zeroState
    selectedPureOutcomeTarget? (decoded.bridge.eval scannerState).outcome =
      some claim.gateRegion.targetId
  gateCountZero :
    let zeroState := scannerNext decoded.zero scannerEntryState
    let scannerState := scannerNext decoded.scanner zeroState
    let gateState := scannerNext decoded.bridge scannerState
    gateState.registers.get claim.countRegister = BitVec.ofNat 32 0
  gateBypassesDispatch :
    let zeroState := scannerNext decoded.zero scannerEntryState
    let scannerState := scannerNext decoded.scanner zeroState
    let gateState := scannerNext decoded.bridge scannerState
    selectedPureOutcomeTarget? (decoded.gate.eval gateState).outcome =
      some claim.dispatchBypassTargetId

theorem scannerNext_memory_of_writes_empty
    (behavior : NormalizedSymbolicBehavior)
    (state : MachineState)
    (writesEmpty : behavior.writes.isEmpty = true) :
    (scannerNext behavior state).memory = state.memory := by
  simp only [scannerNext, RelationalBehavior.nextMachineState,
    NormalizedSymbolicBehavior.eval_x87Effect,
    NormalizedSymbolicBehavior.eval_writes]
  have writes : behavior.writes = [] := List.isEmpty_iff.mp writesEmpty
  simp [writes, evalNormalizedWrites, applyConcreteWrites]

theorem CheckedOriginalScannerExecution.executes
    (authority : CheckedOriginalScannerExecution context)
    (selectorState scannerEntryState : MachineState)
    (selectorImmutable :
      ImmutableImageWordMemory context.pe selectorState.memory)
    (scannerImmutable :
      ImmutableImageWordMemory context.pe scannerEntryState.memory)
    (selectorWritesAvoid : forall decoded,
      authority.claim.decode? context = some decoded ->
        WritesAvoidWord (BitVec.ofNat 32 authority.claim.tableBase)
          (evalNormalizedWrites selectorState decoded.selector.writes)) :
    ∃ decoded,
      authority.claim.decode? context = some decoded /\
        OriginalScannerExecutionResult authority.claim decoded selectorState
          scannerEntryState := by
  have authorityChecked := authority.checked
  unfold OriginalScannerExecutionClaim.checked at authorityChecked
  simp only [Bool.and_eq_true] at authorityChecked
  rcases authorityChecked with ⟨identityChecked, decodedChecked⟩
  cases decodedExact : authority.claim.decode? context with
  | none =>
      simp [decodedExact] at decodedChecked
  | some decoded =>
      refine ⟨decoded, rfl, ?_⟩
      simp only [decodedExact] at decodedChecked
      simp only [OriginalScannerExecutionClaim.semanticChecked,
        Bool.and_eq_true] at decodedChecked
      rcases decodedChecked with
        ⟨⟨⟨⟨selectorChecked, zeroChecked⟩, scannerChecked⟩,
          bridgeChecked⟩, gateChecked⟩
      simp only [OriginalScannerExecutionClaim.identityChecked,
        Bool.and_eq_true, beq_iff_eq] at identityChecked
      have headerWord := identityChecked.1.1.2
      have zeroWord := identityChecked.1.2
      simp only [OriginalScannerExecutionClaim.selectorChecked,
        Bool.and_eq_true, beq_iff_eq] at selectorChecked
      rcases selectorChecked with
        ⟨⟨selectorCount, selectorGuard⟩, selectorBypass⟩
      simp only [OriginalScannerExecutionClaim.zeroChecked,
        Bool.and_eq_true, beq_iff_eq] at zeroChecked
      rcases zeroChecked with
        ⟨⟨zeroScanner, zeroWrites⟩, zeroOutcome⟩
      simp only [OriginalScannerExecutionClaim.scannerChecked,
        Bool.and_eq_true, beq_iff_eq] at scannerChecked
      rcases scannerChecked with
        ⟨⟨⟨⟨⟨scannerCount, scannerCursor⟩, scannerLoaded⟩,
          scannerWrites⟩, scannerGuard⟩, scannerBypass⟩
      simp only [OriginalScannerExecutionClaim.bridgeChecked,
        Bool.and_eq_true, beq_iff_eq] at bridgeChecked
      rcases bridgeChecked with
        ⟨⟨bridgeCount, bridgeWrites⟩, bridgeOutcome⟩
      simp only [OriginalScannerExecutionClaim.gateChecked,
        Bool.and_eq_true, beq_iff_eq] at gateChecked
      rcases gateChecked with
        ⟨⟨⟨gateCount, gateWrites⟩, gateGuard⟩, gateBypass⟩
      let zeroState := scannerNext decoded.zero scannerEntryState
      let scannerState := scannerNext decoded.scanner zeroState
      let gateState := scannerNext decoded.bridge scannerState
      let selectorLoaded :=
        Expr.constantRead32AfterWrites authority.claim.tableBase
          decoded.selector.writes
      have headerRead :
          selectorLoaded.eval selectorState =
            BitVec.ofNat 32 (2 ^ 32 - 1) := by
        rw [show selectorLoaded =
          Expr.constantRead32AfterWrites authority.claim.tableBase
            decoded.selector.writes by rfl]
        rw [Expr.eval_constantRead32AfterWrites,
          Memory.read32_applyConcreteWrites_of_avoids selectorState.memory
            (BitVec.ofNat 32 authority.claim.tableBase)
            (evalNormalizedWrites selectorState decoded.selector.writes)
            (selectorWritesAvoid decoded decodedExact)]
        simpa [machineStateRead32_eq_memoryRead32] using
          ImmutableImageWordMemory.read32_of_checked context.pe
            selectorState.memory authority.claim.tableBase (2 ^ 32 - 1)
            selectorImmutable headerWord
      have selectorTakesScanner :
          selectedPureOutcomeTarget?
              (decoded.selector.eval selectorState).outcome =
            some authority.claim.zeroRegion.targetId := by
        cases selectorGuardExact :
            NormalizedOutcomeExpr.guardForTarget decoded.selector.outcome
              authority.claim.zeroRegion.targetId with
        | none =>
            simp [selectorGuardExact] at selectorGuard
        | some selectorGuardExpression =>
            have selectorGuardExpressionChecked :
                equalsConstantExpressionChecked selectorGuardExpression
                  selectorLoaded (2 ^ 32 - 1) = true := by
              simpa only [selectorLoaded, selectorGuardExact] using
                selectorGuard
            have selectorCondition :
                selectorGuardExpression.eval selectorState = true := by
              rw [equalsConstantExpressionChecked_eval
                selectorGuardExpression selectorLoaded (2 ^ 32 - 1)
                selectorGuardExpressionChecked selectorState]
              simp [BoolExpr.eval, Expr.eval, headerRead]
            exact selectedTarget_of_guardForTarget_true
              decoded.selector.outcome selectorState
              authority.claim.zeroRegion.targetId
              authority.claim.gateRegion.targetId selectorGuardExpression
              selectorGuardExact selectorBypass selectorCondition
      have zeroMemory : zeroState.memory = scannerEntryState.memory :=
        scannerNext_memory_of_writes_empty decoded.zero scannerEntryState
          zeroWrites
      have zeroCursor :
          zeroState.registers.get authority.claim.scannerRegister =
            BitVec.ofNat 32 0 := by
        simp [zeroState, scannerNext, RelationalBehavior.nextMachineState,
          NormalizedSymbolicBehavior.eval_registers,
          evalNormalizedRegisters_get, zeroScanner, Expr.eval]
      have scannerCountZero :
          scannerState.registers.get authority.claim.countRegister =
            BitVec.ofNat 32 0 := by
        simp [scannerState, scannerNext, RelationalBehavior.nextMachineState,
          NormalizedSymbolicBehavior.eval_registers,
          evalNormalizedRegisters_get, scannerCount, Expr.eval, zeroCursor]
      have nextIndex :
          authority.claim.nextIndex.eval zeroState = BitVec.ofNat 32 1 := by
        simp [OriginalScannerExecutionClaim.nextIndex, Expr.eval, zeroCursor]
      have loadedAddress :
          (immutableCodePointerTableAddressExpression authority.claim.tableBase
            authority.claim.nextIndex).eval zeroState =
            BitVec.ofNat 32 (authority.claim.tableBase + 4) := by
        simpa using immutableCodePointerTableAddressExpression_eval_of_index
          authority.claim.tableBase 1 authority.claim.nextIndex zeroState
          nextIndex
      have zeroImmutable :
          ImmutableImageWordMemory context.pe zeroState.memory := by
        rw [zeroMemory]
        exact scannerImmutable
      have loadedZero :
          authority.claim.loadedExpression.eval zeroState =
            BitVec.ofNat 32 0 := by
        simp only [OriginalScannerExecutionClaim.loadedExpression,
          immutableCodePointerTableTargetExpression, Expr.eval,
          machineStateRead32_eq_memoryRead32, loadedAddress]
        exact ImmutableImageWordMemory.read32_of_checked context.pe
          zeroState.memory (authority.claim.tableBase + 4) 0
          zeroImmutable zeroWord
      cases scannerGuardExact :
          NormalizedOutcomeExpr.guardForTarget decoded.scanner.outcome
            authority.claim.scannerRegion.targetId with
      | none =>
          simp [scannerGuardExact] at scannerGuard
      | some scannerGuardExpression =>
          have scannerGuardExpressionChecked :
              nonzeroTestExpressionChecked scannerGuardExpression
                authority.claim.loadedExpression = true := by
            simpa only [scannerGuardExact] using scannerGuard
          have scannerCondition :
              scannerGuardExpression.eval zeroState = false := by
            rw [nonzeroTestExpressionChecked_eval scannerGuardExpression
              authority.claim.loadedExpression scannerGuardExpressionChecked
              zeroState]
            simp [BoolExpr.eval, Expr.eval, loadedZero]
          have gateCountZero :
              gateState.registers.get authority.claim.countRegister =
                BitVec.ofNat 32 0 := by
            simp [gateState, scannerNext, RelationalBehavior.nextMachineState,
              NormalizedSymbolicBehavior.eval_registers,
              evalNormalizedRegisters_get, bridgeCount, Expr.eval,
              scannerCountZero]
          have gateCondition :
              (registerNonzeroGuard authority.claim.countRegister).eval
                gateState = false := by
            simp [registerNonzeroGuard, BoolExpr.eval, Expr.eval, gateCountZero]
          refine {
            selectorTakesScanner := selectorTakesScanner
            zeroJumpsToScanner := ?_
            scannerExits := ?_
            bridgeJumpsToGate := ?_
            gateCountZero := gateCountZero
            gateBypassesDispatch := ?_
          }
          · simp [NormalizedSymbolicBehavior.eval_outcome, zeroOutcome,
              NormalizedOutcomeExpr.eval, selectedPureOutcomeTarget?]
          · exact selectedTarget_of_guardForTarget_false
              decoded.scanner.outcome zeroState
              authority.claim.scannerRegion.targetId
              authority.claim.bridgeRegion.targetId scannerGuardExpression
              scannerGuardExact scannerBypass scannerCondition
          · simp [NormalizedSymbolicBehavior.eval_outcome, bridgeOutcome,
              NormalizedOutcomeExpr.eval, selectedPureOutcomeTarget?]
          · exact selectedTarget_of_guardForTarget_false
              decoded.gate.outcome gateState
              authority.claim.dispatchSourceTargetId
              authority.claim.dispatchBypassTargetId
              (registerNonzeroGuard authority.claim.countRegister)
              gateGuard gateBypass gateCondition

/-! ## SCC-wide operational induction -/

def scannerPhaseTargetIds
    (claim : OriginalScannerExecutionClaim) : List Nat :=
  [claim.zeroRegion.targetId, claim.scannerRegion.targetId,
    claim.bridgeRegion.targetId, claim.gateRegion.targetId]

def rootedSccScannerBoundaryChecked
    (certificate : RootedSccCertificate)
    (claim : OriginalScannerExecutionClaim) : Bool :=
  certificate.sccTargetIds.contains claim.dispatchSourceTargetId &&
    !certificate.sccTargetIds.contains claim.dispatchBypassTargetId &&
    !(scannerPhaseTargetIds claim).contains claim.dispatchBypassTargetId &&
    ((scannerPhaseTargetIds claim).all fun targetId =>
      !certificate.rootTargetIds.contains targetId) &&
    certificate.incomingEdges.all fun edge =>
      certificate.sccTargetIds.contains edge.sourceTargetId ||
        (edge.sourceTargetId == claim.gateRegion.targetId &&
          edge.targetTargetId == claim.dispatchSourceTargetId)

structure CheckedRootedScannerSccExecution
    (originalContext : OriginalDecodedStaticContext)
    (site : OriginalIndirectControlSite) where
  graph : CheckedRootedSccCertificate originalContext site
  scanner : CheckedOriginalScannerExecution originalContext
  sourceExact :
    scanner.claim.dispatchSourceTargetId = site.sourceTargetId
  boundaryChecked :
    rootedSccScannerBoundaryChecked graph.certificate scanner.claim = true

inductive RootedScannerOperationalReachable
    (authority :
      CheckedRootedScannerSccExecution originalContext site) : Nat -> Prop where
  | root targetId :
      targetId ∈ authority.graph.certificate.rootTargetIds ->
      RootedScannerOperationalReachable authority targetId
  | step sourceTargetId targetTargetId :
      RootedScannerOperationalReachable authority sourceTargetId ->
      ({ sourceTargetId, targetTargetId } : OriginalIncomingEdge) ∈
        originalIncomingEdgesForTargets originalContext [targetTargetId] ->
      targetTargetId ∉ scannerPhaseTargetIds authority.scanner.claim ->
      RootedScannerOperationalReachable authority targetTargetId
  | scannerPath
      (selectorState scannerEntryState : MachineState)
      (decoded : OriginalScannerExecutionDecoded) :
      RootedScannerOperationalReachable authority
        authority.scanner.claim.selectorRegion.targetId ->
      authority.scanner.claim.decode? originalContext = some decoded ->
      OriginalScannerExecutionResult authority.scanner.claim decoded
        selectorState scannerEntryState ->
      RootedScannerOperationalReachable authority
        authority.scanner.claim.dispatchBypassTargetId

theorem CheckedRootedScannerSccExecution.scannerBypassReachable
    (authority :
      CheckedRootedScannerSccExecution originalContext site)
    (selectorReachable :
      RootedScannerOperationalReachable authority
        authority.scanner.claim.selectorRegion.targetId)
    (selectorState scannerEntryState : MachineState)
    (selectorImmutable :
      ImmutableImageWordMemory originalContext.pe selectorState.memory)
    (scannerImmutable :
      ImmutableImageWordMemory originalContext.pe scannerEntryState.memory)
    (selectorWritesAvoid : forall decoded,
      authority.scanner.claim.decode? originalContext = some decoded ->
        WritesAvoidWord
          (BitVec.ofNat 32 authority.scanner.claim.tableBase)
          (evalNormalizedWrites selectorState decoded.selector.writes)) :
    RootedScannerOperationalReachable authority
      authority.scanner.claim.dispatchBypassTargetId := by
  rcases authority.scanner.executes selectorState scannerEntryState
      selectorImmutable scannerImmutable selectorWritesAvoid with
    ⟨decoded, decodedExact, execution⟩
  exact .scannerPath selectorState scannerEntryState decoded
    selectorReachable decodedExact execution

theorem CheckedRootedScannerSccExecution.phaseUnreachable
    (authority :
      CheckedRootedScannerSccExecution originalContext site)
    {targetId : Nat}
    (reachable : RootedScannerOperationalReachable authority targetId) :
    targetId ∉ scannerPhaseTargetIds authority.scanner.claim := by
  have boundaryChecked := authority.boundaryChecked
  simp only [rootedSccScannerBoundaryChecked, Bool.and_eq_true] at boundaryChecked
  have phaseBypassOutside := boundaryChecked.1.1.2
  have phaseRootsOutside := boundaryChecked.1.2
  simp only [List.all_eq_true] at phaseRootsOutside
  induction reachable with
  | root targetId rootMember =>
      intro phaseMember
      have excluded := phaseRootsOutside targetId phaseMember
      simp only [Bool.not_eq_true] at excluded
      have included :
          authority.graph.certificate.rootTargetIds.contains targetId = true :=
        List.contains_iff_mem.mpr rootMember
      rw [included] at excluded
      contradiction
  | step sourceTargetId targetTargetId _sourceReachable _edgeMember
      targetOutside _induction =>
      exact targetOutside
  | scannerPath selectorState scannerEntryState decoded _selectorReachable
      _decodedExact _execution _induction =>
      intro phaseMember
      have included :
          (scannerPhaseTargetIds authority.scanner.claim).contains
              authority.scanner.claim.dispatchBypassTargetId = true :=
        List.contains_iff_mem.mpr phaseMember
      rw [included] at phaseBypassOutside
      contradiction

theorem CheckedRootedScannerSccExecution.sccUnreachable
    (authority :
      CheckedRootedScannerSccExecution originalContext site)
    {targetId : Nat}
    (reachable : RootedScannerOperationalReachable authority targetId) :
    targetId ∉ authority.graph.certificate.sccTargetIds := by
  have boundaryChecked := authority.boundaryChecked
  simp only [rootedSccScannerBoundaryChecked, Bool.and_eq_true] at boundaryChecked
  have bypassOutside := boundaryChecked.1.1.1.2
  have boundary := boundaryChecked.2
  simp only [List.all_eq_true] at boundary
  have graphChecked := authority.graph.checked
  unfold RootedSccCertificate.checked at graphChecked
  simp only [Bool.and_eq_true] at graphChecked
  rcases graphChecked with
    ⟨⟨⟨⟨⟨_siteChecked, _rootsNonempty⟩, _rootsExact⟩,
      _rootPathChecked⟩, sccBoundary⟩, rootsOutside⟩
  induction reachable with
  | root targetId rootMember =>
      simp only [List.all_eq_true] at rootsOutside
      intro member
      have excluded := rootsOutside targetId member
      have included :
          authority.graph.certificate.rootTargetIds.contains targetId = true :=
        List.contains_iff_mem.mpr rootMember
      rw [included] at excluded
      contradiction
  | step sourceTargetId targetTargetId sourceReachable edgeMember
      _targetOutside induction =>
      intro targetInScc
      have incomingExact :
          authority.graph.certificate.incomingEdges =
            originalIncomingEdgesForTargets originalContext
              authority.graph.certificate.sccTargetIds := by
        simp only [originalSccBoundaryChecked, Bool.and_eq_true,
          beq_iff_eq] at sccBoundary
        exact sccBoundary.1.2
      have incomingMember :
          ({ sourceTargetId, targetTargetId } : OriginalIncomingEdge) ∈
            authority.graph.certificate.incomingEdges := by
        rw [incomingExact]
        simp only [originalIncomingEdgesForTargets, List.mem_flatMap]
        refine ⟨targetTargetId, targetInScc, ?_⟩
        simpa [originalIncomingEdgesForTargets] using edgeMember
      have classified := boundary _ incomingMember
      simp only [Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq] at classified
      rcases classified with sourceInScc | blocked
      · exact induction (List.contains_iff_mem.mp sourceInScc)
      · rw [blocked.1] at sourceReachable
        exact authority.phaseUnreachable sourceReachable
          (by simp [scannerPhaseTargetIds])
  | scannerPath selectorState scannerEntryState decoded _selectorReachable
      _decodedExact _execution _induction =>
      intro bypassInScc
      have included :
          authority.graph.certificate.sccTargetIds.contains
              authority.scanner.claim.dispatchBypassTargetId = true :=
        List.contains_iff_mem.mpr bypassInScc
      rw [included] at bypassOutside
      contradiction

theorem CheckedRootedScannerSccExecution.sourceUnreachable
    (authority :
      CheckedRootedScannerSccExecution originalContext site)
    (reachable : RootedScannerOperationalReachable authority
      site.sourceTargetId) :
    False := by
  have outside := authority.sccUnreachable reachable
  apply outside
  rw [← authority.sourceExact]
  have boundaryChecked := authority.boundaryChecked
  simp only [rootedSccScannerBoundaryChecked,
    Bool.and_eq_true] at boundaryChecked
  exact List.contains_iff_mem.mp boundaryChecked.1.1.1.1

#print axioms CheckedOriginalScannerExecution.executes
#print axioms CheckedRootedScannerSccExecution.sccUnreachable
#print axioms CheckedRootedScannerSccExecution.sourceUnreachable

end StageA.Relational.NullableCodePointerRootedUnreachability
