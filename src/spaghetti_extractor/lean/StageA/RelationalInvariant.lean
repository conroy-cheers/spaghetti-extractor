import StageA.Relational

namespace StageA.Relational

open StageA.Formal

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

structure ImmutableImageWordRegisterOutputClaim where
  output : RegisterRelationPair
  originalAddress : Nat
  candidateAddress : Nat
  originalValue : Nat
  candidateValue : Nat
deriving Repr, DecidableEq

def ImmutableImageWordRegisterOutputClaim.checked
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableImageWordRegisterOutputClaim) : Bool :=
  readImmutableImageWord context.originalPe claim.originalAddress 4 ==
      some claim.originalValue &&
    readImmutableImageWord context.candidatePe claim.candidateAddress 4 ==
      some claim.candidateValue &&
    claim.output.relation.holds context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      context.dataMap.entries.toList (BitVec.ofNat 32 claim.originalValue)
      (BitVec.ofNat 32 claim.candidateValue) &&
    originalBehavior.registers.get claim.output.original ==
      .read32 (.constant claim.originalAddress) &&
    candidateBehavior.registers.get claim.output.candidate ==
      .read32 (.constant claim.candidateAddress)

theorem ImmutableImageWordRegisterOutputClaim.holds_output_of_stateRel
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableImageWordRegisterOutputClaim)
    (checked : claim.checked context originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    claim.output.relation.holds context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  simp only [ImmutableImageWordRegisterOutputClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨originalWord, candidateWord⟩, staticRelated⟩,
      originalExpression⟩, candidateExpression⟩
  rcases related with
    ⟨_, _, _, _, _, _, originalImmutable, candidateImmutable, _, _⟩
  have originalRead := ImmutableImageWordMemory.read32_of_checked
    context.originalPe originalState.memory claim.originalAddress claim.originalValue
    originalImmutable originalWord
  have candidateRead := ImmutableImageWordMemory.read32_of_checked
    context.candidatePe candidateState.memory claim.candidateAddress claim.candidateValue
    candidateImmutable candidateWord
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [originalExpression, candidateExpression]
  simp only [Expr.eval, machineStateRead32_eq_memoryRead32]
  rw [originalRead, candidateRead]
  exact RegisterValueRelation.holds_append_values
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList context.dataMap.entries.toList
    world.runtimeValueTargets claim.output.relation _ _ staticRelated

def staticWordRelationSupportsRegisterValueRelation
    (source : StaticWordRelationKind) (target : RegisterValueRelation) : Bool :=
  match source, target with
  | .exact, .exact | .exact, .relatedWord | .relatedWord, .relatedWord |
      .codePointer, .codePointer | .dataPointer, .dataPointer => true
  | _, _ => false

theorem StaticWordRelationKind.registerValueRelation_holds_of_holds
    (context : StaticProofContext) (world : RelationalWorld)
    (source : StaticWordRelationKind) (target : RegisterValueRelation)
    (original candidate : Word)
    (compatible : staticWordRelationSupportsRegisterValueRelation source target = true)
    (holds : source.holds context world original candidate = true) :
    target.holds context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      original candidate = true := by
  cases source <;> cases target <;>
    simp_all [staticWordRelationSupportsRegisterValueRelation,
      StaticWordRelationKind.holds, RegisterValueRelation.holds, wordRelated_self]

structure StaticWordSlotRegisterOutputClaim where
  output : RegisterRelationPair
  slot : StaticWordRelationSlotPair
  originalAddress : Nat
  candidateAddress : Nat
deriving Repr, DecidableEq

def StaticWordSlotRegisterOutputClaim.checked
    (context : StaticProofContext)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotRegisterOutputClaim) : Bool :=
  context.staticWordRelationSlots.contains claim.slot &&
    claim.slot.originalAddress == BitVec.ofNat 32 claim.originalAddress &&
    claim.slot.candidateAddress == BitVec.ofNat 32 claim.candidateAddress &&
    staticWordRelationSupportsRegisterValueRelation claim.slot.relation
      claim.output.relation &&
    originalBehavior.registers.get claim.output.original ==
      .read32 (.constant claim.originalAddress) &&
    candidateBehavior.registers.get claim.output.candidate ==
      .read32 (.constant claim.candidateAddress)

theorem StaticWordSlotRegisterOutputClaim.holds_output_of_stateRel
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotRegisterOutputClaim)
    (checked : claim.checked context originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    claim.output.relation.holds context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  simp only [StaticWordSlotRegisterOutputClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨slotMember, originalAddress⟩, candidateAddress⟩, compatible⟩,
      originalExpression⟩, candidateExpression⟩
  have slotsHold := related.staticWordRelationSlotsMemoryHold context world
    region.inputInvariant originalState candidateState
  have slotHolds := slotsHold claim.slot
    (List.contains_iff_mem.mp slotMember)
  simp only [StaticWordRelationSlotPair.memoryHolds] at slotHolds
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [originalExpression, candidateExpression]
  simp only [Expr.eval, machineStateRead32_eq_memoryRead32]
  rw [← originalAddress, ← candidateAddress]
  exact StaticWordRelationKind.registerValueRelation_holds_of_holds context world
    claim.slot.relation claim.output.relation _ _ compatible slotHolds

structure StackRead32SubRegisterOutputClaim where
  output : RegisterRelationPair
  window : StackWindowPair
  offset : Nat
  subtract : Nat
  originalDirectRead : Bool := false
  candidateDirectRead : Bool := false
  originalDirectAddress : Bool := false
  candidateDirectAddress : Bool := false
deriving Repr, DecidableEq

def StackRead32SubRegisterOutputClaim.originalExpression
    (claim : StackRead32SubRegisterOutputClaim) : Expr :=
  let address : Expr := if claim.originalDirectAddress then
    .inputReg claim.window.originalRegister
  else
    .add (.inputReg claim.window.originalRegister) (.constant claim.offset)
  let read : Expr := .read32 address
  if claim.originalDirectRead then read else .sub read (.constant claim.subtract)

def StackRead32SubRegisterOutputClaim.candidateExpression
    (claim : StackRead32SubRegisterOutputClaim) : Expr :=
  let address : Expr := if claim.candidateDirectAddress then
    .inputReg claim.window.candidateRegister
  else
    .add (.inputReg claim.window.candidateRegister) (.constant claim.offset)
  let read : Expr := .read32 address
  if claim.candidateDirectRead then read else .sub read (.constant claim.subtract)

def StackRead32SubRegisterOutputClaim.checked (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackRead32SubRegisterOutputClaim) : Bool :=
  claim.output.relation == .relatedWord && claim.subtract == 0 &&
    region.stackWindows.contains claim.window &&
    decide (claim.offset + 4 <= claim.window.bytesAbove) &&
    claim.offset % 4 == 0 &&
    decide ((claim.originalDirectAddress = true ∨
      claim.candidateDirectAddress = true) → claim.offset = 0) &&
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
    ⟨⟨⟨⟨⟨⟨⟨relationKind, subtractZero⟩, windowMember⟩, inside⟩,
      aligned⟩, directAddressOffset⟩, originalChecked⟩, candidateChecked⟩
  have originalExpression := beq_iff_eq.mp originalChecked
  have candidateExpression := beq_iff_eq.mp candidateChecked
  have windowMember' : claim.window ∈ region.inputInvariant.stackWindows := by
    simpa [RegionRelation.inputInvariant] using windowMember
  have readRelated := StateRel.stackMemoryRead32Related context world
    region.inputInvariant originalState candidateState claim.window claim.offset related
    windowMember' inside (by simpa using aligned)
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [originalExpression, candidateExpression]
  have relationKind' := beq_iff_eq.mp relationKind
  have subtractZero' := beq_iff_eq.mp subtractZero
  rw [relationKind']
  cases originalDirectRead : claim.originalDirectRead <;>
    cases candidateDirectRead : claim.candidateDirectRead <;>
      cases originalDirectAddress : claim.originalDirectAddress <;>
        cases candidateDirectAddress : claim.candidateDirectAddress <;>
          simp_all [StackRead32SubRegisterOutputClaim.originalExpression,
            StackRead32SubRegisterOutputClaim.candidateExpression,
            originalDirectRead, candidateDirectRead, originalDirectAddress,
            candidateDirectAddress, Expr.eval, machineStateRead32_eq_memoryRead32,
            RegisterValueRelation.holds]

def stackRead32AtAdjustmentMatches (adjustment : StackAdjustment)
    (register : Reg) : Expr → Bool
  | .read32 address => adjustment.expressionMatches register address
  | _ => false

theorem stackRead32AtAdjustment_eval_of_matches
    (adjustment : StackAdjustment) (register : Reg) (expression : Expr)
    (state : MachineState)
    (matched : stackRead32AtAdjustmentMatches adjustment register expression = true) :
    expression.eval state = Memory.read32 state.memory
      ((adjustment.expression register).eval state) := by
  cases expression <;> simp [stackRead32AtAdjustmentMatches] at matched
  case read32 address =>
    simp only [Expr.eval, machineStateRead32_eq_memoryRead32]
    rw [adjustment.eval_expression_of_matches register address state matched]

structure StackRead32RelativeRegisterOutputClaim where
  output : RegisterRelationPair
  window : StackWindowPair
  adjustment : StackAdjustment
deriving Repr, DecidableEq

def StackRead32RelativeRegisterOutputClaim.adjustmentChecked
    (claim : StackRead32RelativeRegisterOutputClaim) : Bool :=
  match claim.adjustment with
  | .identity => decide (4 <= claim.window.bytesAbove)
  | .add amount =>
      decide (amount + 4 <= claim.window.bytesAbove) && amount % 4 == 0
  | .subtract amount =>
      decide (4 <= amount) && decide (amount <= claim.window.bytesBelow) &&
        amount % 4 == 0

def StackRead32RelativeRegisterOutputClaim.checked (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackRead32RelativeRegisterOutputClaim) : Bool :=
  claim.output.relation == .relatedWord &&
    region.stackWindows.contains claim.window && claim.adjustmentChecked &&
    stackRead32AtAdjustmentMatches claim.adjustment claim.window.originalRegister
      (originalBehavior.registers.get claim.output.original) &&
    stackRead32AtAdjustmentMatches claim.adjustment claim.window.candidateRegister
      (candidateBehavior.registers.get claim.output.candidate)

theorem StackRead32RelativeRegisterOutputClaim.holds_output_of_stateRel
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackRead32RelativeRegisterOutputClaim)
    (checked : claim.checked region originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    claim.output.relation.holds context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  rcases claim with ⟨output, window, adjustment⟩
  simp only [StackRead32RelativeRegisterOutputClaim.checked, Bool.and_eq_true]
      at checked
  rcases checked with
    ⟨⟨⟨⟨relationKind, windowMember⟩, adjustmentChecked⟩,
      originalMatches⟩, candidateMatches⟩
  have windowMember' : window ∈ region.inputInvariant.stackWindows := by
    simpa [RegionRelation.inputInvariant] using windowMember
  have originalEval := stackRead32AtAdjustment_eval_of_matches adjustment
    window.originalRegister
    (originalBehavior.registers.get output.original) originalState originalMatches
  have candidateEval := stackRead32AtAdjustment_eval_of_matches adjustment
    window.candidateRegister
    (candidateBehavior.registers.get output.candidate) candidateState candidateMatches
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
        simp only [StackRead32RelativeRegisterOutputClaim.adjustmentChecked,
          decide_eq_true_eq] at adjustmentChecked
        have read := StateRel.stackMemoryRead32Related context world
          region.inputInvariant originalState candidateState window 0 related
          windowMember' adjustmentChecked (by decide)
        simpa [StackAdjustment.expression, Expr.eval] using read
    | add amount =>
        simp only [StackRead32RelativeRegisterOutputClaim.adjustmentChecked,
          Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at adjustmentChecked
        have read := StateRel.stackMemoryRead32Related context world
          region.inputInvariant originalState candidateState window amount related
          windowMember' adjustmentChecked.1 adjustmentChecked.2
        simpa [StackAdjustment.expression, Expr.eval] using read
    | subtract amount =>
        simp only [StackRead32RelativeRegisterOutputClaim.adjustmentChecked,
          Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at adjustmentChecked
        have read := StateRel.stackMemoryRead32BelowRelated context world
          region.inputInvariant originalState candidateState window amount related
          windowMember' adjustmentChecked.1.1 adjustmentChecked.1.2
          adjustmentChecked.2
        simpa [StackAdjustment.expression, Expr.eval] using read
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [beq_iff_eq.mp relationKind, originalEval, candidateEval]
  simpa [RegisterValueRelation.holds] using readsRelated

structure StackWindowIdentityRegisterOutputClaim where
  output : RegisterRelationPair
  window : StackWindowPair
deriving Repr, DecidableEq

def StackWindowIdentityRegisterOutputClaim.checked (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackWindowIdentityRegisterOutputClaim) : Bool :=
  claim.output.relation == .relatedWord &&
    region.stackWindows.contains claim.window &&
    decide (0 < claim.window.bytesAbove) &&
    originalBehavior.registers.get claim.output.original ==
      .inputReg claim.window.originalRegister &&
    candidateBehavior.registers.get claim.output.candidate ==
      .inputReg claim.window.candidateRegister

theorem StackWindowIdentityRegisterOutputClaim.holds_output_of_stateRel
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackWindowIdentityRegisterOutputClaim)
    (checked : claim.checked region originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    claim.output.relation.holds context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  simp only [StackWindowIdentityRegisterOutputClaim.checked, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨relationKind, windowMember⟩, bytesAbovePositive⟩,
      originalExpression⟩, candidateExpression⟩
  have relationKind' := beq_iff_eq.mp relationKind
  have originalExpression' := beq_iff_eq.mp originalExpression
  have candidateExpression' := beq_iff_eq.mp candidateExpression
  have windowMember' : claim.window ∈ region.inputInvariant.stackWindows := by
    simpa [RegionRelation.inputInvariant] using windowMember
  rcases related with
    ⟨_worldValid, stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable,
      _candidateImmutable, relatedCore, _specialRegisters⟩
  rcases relatedCore with
    ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,
      _inputMemory, _inputDynamicMemory, _inputUndefined, _inputX87,
      _inputFlags, _inputFsBase⟩
  simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
  have windowHolds := inputStackWindows claim.window windowMember'
  have baseRelated := claim.window.relatedWord_of_holds context world
    originalState.registers candidateState.registers stackRangesValid
    bytesAbovePositive windowHolds
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [relationKind', originalExpression', candidateExpression']
  simpa [Expr.eval] using baseRelated

inductive RegisterOutputClaim where
  | exactExpression (claim : ExactRegisterOutputClaim)
  | exactMemory (claim : ExactMemoryRegisterOutputClaim)
  | identity (claim : IdentityRegisterOutputClaim)
  | constant (claim : ConstantRegisterOutputClaim)
  | immutableImageWord (claim : ImmutableImageWordRegisterOutputClaim)
  | staticWordSlot (claim : StaticWordSlotRegisterOutputClaim)
  | stackRead32Sub (claim : StackRead32SubRegisterOutputClaim)
  | stackRead32Relative (claim : StackRead32RelativeRegisterOutputClaim)
  | stackWindowIdentity (claim : StackWindowIdentityRegisterOutputClaim)
deriving Repr, DecidableEq

def RegisterOutputClaim.output : RegisterOutputClaim → RegisterRelationPair
  | .exactExpression claim => claim.output
  | .exactMemory claim => claim.output
  | .identity claim => claim.output
  | .constant claim => claim.output
  | .immutableImageWord claim => claim.output
  | .staticWordSlot claim => claim.output
  | .stackRead32Sub claim => claim.output
  | .stackRead32Relative claim => claim.output
  | .stackWindowIdentity claim => claim.output

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
  | .immutableImageWord _ => false
  | .staticWordSlot _ => false
  | .stackRead32Sub _ => false
  | .stackRead32Relative _ => false
  | .stackWindowIdentity _ => false

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
  | .immutableImageWord _ => False
  | .staticWordSlot _ => False
  | .stackRead32Sub _ => False
  | .stackRead32Relative _ => False
  | .stackWindowIdentity _ => False

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
  | immutableImageWord _ => simp [RegisterOutputClaim.checked] at checked
  | staticWordSlot _ => simp [RegisterOutputClaim.checked] at checked
  | stackRead32Sub _ => simp [RegisterOutputClaim.checked] at checked
  | stackRead32Relative _ => simp [RegisterOutputClaim.checked] at checked
  | stackWindowIdentity _ => simp [RegisterOutputClaim.checked] at checked

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
  case immutableImageWord => contradiction
  case staticWordSlot => contradiction
  case stackRead32Sub => contradiction
  case stackRead32Relative => contradiction
  case stackWindowIdentity => contradiction

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
    (context : StaticProofContext)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) :
    RegisterOutputClaim → Bool
  | .exactExpression claim => claim.checked region originalBehavior candidateBehavior
  | .exactMemory _ => false
  | .identity claim => claim.checked region originalBehavior candidateBehavior
  | .constant claim => claim.checked context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      context.dataMap.entries.toList region originalBehavior candidateBehavior
  | .immutableImageWord claim => claim.checked context originalBehavior candidateBehavior
  | .staticWordSlot claim => claim.checked context originalBehavior candidateBehavior
  | .stackRead32Sub claim => claim.checked region originalBehavior candidateBehavior
  | .stackRead32Relative claim => claim.checked region originalBehavior candidateBehavior
  | .stackWindowIdentity claim => claim.checked region originalBehavior candidateBehavior

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
    world.runtimeValueTargets outputRelation _ _
  simpa [Expr.eval] using valuesRelated

theorem registerRelationsHold_of_nonMemoryOutputClaims
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List RegisterOutputClaim)
    (checked : claims.all (RegisterOutputClaim.nonMemoryChecked context region
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
      | immutableImageWord claim =>
          exact ⟨claim.holds_output_of_stateRel context world region originalBehavior
            candidateBehavior checked.1 originalState candidateState related,
            ih checked.2⟩
      | staticWordSlot claim =>
          exact ⟨claim.holds_output_of_stateRel context world region originalBehavior
            candidateBehavior checked.1 originalState candidateState related,
            ih checked.2⟩
      | stackRead32Sub claim =>
          exact ⟨claim.holds_output_of_stateRel context world region originalBehavior
            candidateBehavior checked.1 originalState candidateState related,
            ih checked.2⟩
      | stackRead32Relative claim =>
          exact ⟨claim.holds_output_of_stateRel context world region originalBehavior
            candidateBehavior checked.1 originalState candidateState related,
            ih checked.2⟩
      | stackWindowIdentity claim =>
          exact ⟨claim.holds_output_of_stateRel context world region originalBehavior
            candidateBehavior checked.1 originalState candidateState related,
            ih checked.2⟩

theorem registerTransferUnderStateRel_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List RegisterOutputClaim)
    (inventory : claims.map RegisterOutputClaim.output = region.outputRelations)
    (checked : claims.all (RegisterOutputClaim.nonMemoryChecked context region
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

def machineCallResultRelationAsRegisterValueRelation :
    MachineCallResultRelationKind → RegisterValueRelation
  | .exact => .exact
  | .relatedWord => .relatedWord
  | .dynamicRangeBase _ _ _ _ => .relatedWord

def externalRegisterInputPolicyClosed (source : RegionRelation)
    (contract : MachineImportCallContract) (input : RegisterRelationPair) : Bool :=
  if input.original == .esp && input.candidate == .esp then
    source.outputRelations.contains input
  else if contract.preservedRegisters.contains input.original &&
      contract.preservedRegisters.contains input.candidate then
    source.outputRelations.contains input
  else if contract.clobberedRegisters.contains input.original &&
      contract.clobberedRegisters.contains input.candidate then
    match contract.resultRegisterRelations.filter
        (fun relation => relation.register == input.original) with
    | [] => input.relation == .relatedWord
    | [relation] =>
        input.candidate == relation.register &&
          input.relation ==
            machineCallResultRelationAsRegisterValueRelation relation.relation
    | _ => false
  else
    false

def externalRegisterPolicyClosed (source target : RegionRelation)
    (contract : MachineImportCallContract) : Bool :=
  target.inputRelations.all (externalRegisterInputPolicyClosed source contract)

def _root_.StageA.Relational.NormalizedOutcomeExpr.externalTarget? :
    NormalizedOutcomeExpr → Option ExternalTarget
  | .externalCall imported _ _ => some imported
  | _ => none

def ExternalRegisterPolicyEdgeClosed (source target : RegionRelation)
    (contract : MachineImportCallContract)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Prop :=
  contract.shapeValid = true ∧
    originalBehavior.outcome.externalTarget? = some contract.imported ∧
    candidateBehavior.outcome.externalTarget? = some contract.imported ∧
    originalBehavior.outcome.externalContinuation = some target.id ∧
    candidateBehavior.outcome.externalContinuation = some target.id ∧
    externalRegisterPolicyClosed source target contract = true

def externalRegisterPolicyEdgeChecked (source target : RegionRelation)
    (contract : MachineImportCallContract)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  contract.shapeValid &&
    originalBehavior.outcome.externalTarget? == some contract.imported &&
    candidateBehavior.outcome.externalTarget? == some contract.imported &&
    originalBehavior.outcome.externalContinuation == some target.id &&
    candidateBehavior.outcome.externalContinuation == some target.id &&
    externalRegisterPolicyClosed source target contract

theorem externalRegisterPolicyEdgeClosed_of_checked
    (source target : RegionRelation)
    (contract : MachineImportCallContract)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (checked : externalRegisterPolicyEdgeChecked source target contract
      originalBehavior candidateBehavior = true) :
    ExternalRegisterPolicyEdgeClosed source target contract originalBehavior
      candidateBehavior := by
  simpa [ExternalRegisterPolicyEdgeClosed, externalRegisterPolicyEdgeChecked,
    Bool.and_eq_true, beq_iff_eq, and_assoc] using checked

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

end StageA.Relational
