import StageA.Formal
import Std.Tactic.BVDecide

namespace StageA.Relational

open StageA.Formal

abbrev PureState := Registers Word

def evalExprPure (state : PureState) : Expr -> Option Word
  | .inputReg reg => some (state.get reg)
  | .inputFlagValue _ => none
  | .inputFsBase => none
  | .inputX87Control | .inputX87Status => none
  | .constant value => some (BitVec.ofNat 32 value)
  | .add left right => return (← evalExprPure state left) + (← evalExprPure state right)
  | .sub left right => return (← evalExprPure state left) - (← evalExprPure state right)
  | .bitAnd left right => return (← evalExprPure state left) &&& (← evalExprPure state right)
  | .bitXor left right => return (← evalExprPure state left) ^^^ (← evalExprPure state right)
  | .bitNot value => return ~~~(← evalExprPure state value)
  | .read8 _ | .read32 _ | .read8AfterWrite _ _ _ _ => none
  | .extractByte value index =>
      return BitVec.zeroExtend 32 ((← evalExprPure state value).extractLsb' (index * 8) 8)
  | .shiftLeft value amount => return (← evalExprPure state value).shiftLeft amount
  | .shiftRight value amount => return (← evalExprPure state value).ushiftRight amount
  | .shiftLeftBy value amount =>
      return (← evalExprPure state value).shiftLeft ((← evalExprPure state amount).toNat % 32)
  | .shiftRightBy value amount =>
      return (← evalExprPure state value).ushiftRight ((← evalExprPure state amount).toNat % 32)
  | .shiftArithmeticRightBy value amount =>
      return (← evalExprPure state value).sshiftRight ((← evalExprPure state amount).toNat % 32)
  | .bitOr left right => return (← evalExprPure state left) ||| (← evalExprPure state right)
  | .ifEqual left right thenValue elseValue => do
      if (← evalExprPure state left) = (← evalExprPure state right) then
        evalExprPure state thenValue
      else
        evalExprPure state elseValue
  | .unsignedLessValue left right =>
      return if (← evalExprPure state left) < (← evalExprPure state right) then 1 else 0
  | .bitValue value index =>
      return if Nat.testBit (← evalExprPure state value).toNat index then 1 else 0
  | .multiply left right => return (← evalExprPure state left) * (← evalExprPure state right)
  | .multiplyHighUnsigned left right => do
      let left ← evalExprPure state left
      let right ← evalExprPure state right
      let product := BitVec.zeroExtend 64 left * BitVec.zeroExtend 64 right
      return product.extractLsb' 32 32
  | .multiplyHighSigned left right => do
      let left ← evalExprPure state left
      let right ← evalExprPure state right
      let product := BitVec.signExtend 64 left * BitVec.signExtend 64 right
      return product.extractLsb' 32 32
  | .divideQuotient _ _ _ | .divideRemainder _ _ _ | .divisionValidValue _ _ _ => none
  | .lowestSetBit value => return lowestSetBitValue (← evalExprPure state value) 0 32
  | .highestSetBit value => return highestSetBitValue (← evalExprPure state value) 31 32
  | .undefined _ => none
  | .x87Part _ _ | .x87CompareBit _ _ _ _ | .x87ExamineStatus _ _ => none

def evalBoolExprPure (state : PureState) : BoolExpr -> Option Bool
  | .equal left right => return decide ((← evalExprPure state left) = (← evalExprPure state right))
  | .not value => return !(← evalBoolExprPure state value)
  | .and left right => return (← evalBoolExprPure state left) && (← evalBoolExprPure state right)
  | .or left right => return (← evalBoolExprPure state left) || (← evalBoolExprPure state right)
  | .xor left right => return (← evalBoolExprPure state left) != (← evalBoolExprPure state right)
  | .unsignedLess left right => return decide ((← evalExprPure state left) < (← evalExprPure state right))
  | .msb value => return Nat.testBit (← evalExprPure state value).toNat 31
  | .bit value index => return Nat.testBit (← evalExprPure state value).toNat index
  | .inputFlag _ => none
  | .divisionValid _ _ _ => none

structure CodeAlias where
  rva : Nat
  paddingIndex : Nat
deriving Repr, DecidableEq

structure CodeTargetPair where
  id : Nat
  regionIndex : Nat := 0
  originalRva : Nat
  candidateRva : Nat
  originalAliases : List CodeAlias := []
  candidateAliases : List CodeAlias := []
deriving Repr, DecidableEq

structure ValueTargetPair where
  id : Nat
  originalValue : Nat
  candidateValue : Nat
  originalRelocationRva : Nat
  candidateRelocationRva : Nat
  mappedSize : Nat := 0
deriving Repr, DecidableEq

def normalizeCodeTarget (candidate : Bool) (targets : List CodeTargetPair) (rva : Nat) : Option Nat :=
  (targets.find? fun target =>
    if candidate then target.candidateRva == rva || target.candidateAliases.any (·.rva == rva)
    else target.originalRva == rva || target.originalAliases.any (·.rva == rva)).map (·.id)

structure ExternalTarget where
  dll : Bytes
  name : ImportName
deriving Repr, DecidableEq

def normalizeImport (imported : PEImport) : ExternalTarget := {
  dll := imported.dll
  name := imported.name
}

inductive PureOutcome where
  | returned (target : Word)
  | jump (target : Nat)
  | branch (condition : Bool) (taken fallthrough : Nat)
  | call (target continuation : Nat)
  | externalCall (imported : ExternalTarget) (arguments : List Word) (continuation : Nat)
  | externalJump (imported : ExternalTarget) (arguments : List Word)
  | bulkCopy (destination source count : Word) (direction : Bool) (continuation : Nat)
  | indirectCall (target : Word) (continuation : Nat)
  | indirectJump (target : Word)
  | checkedContinue (valid : Bool) (continuation : Nat)
  | atomicCompareExchange (address expected replacement : Word) (continuation : Nat)
deriving Repr, DecidableEq

structure PureBehavior where
  registers : PureState
  outcome : PureOutcome
deriving Repr, DecidableEq

structure RelationalBehavior where
  registers : PureState
  x87 : ConcreteX87State
  writes : List (Word × Word)
  eflags : Word
  outcome : PureOutcome
deriving Repr, DecidableEq

inductive NormalizedOutcomeExpr where
  | returned (target : Expr)
  | jump (target : Nat)
  | branch (condition : BoolExpr) (taken fallthrough : Nat)
  | call (target continuation : Nat)
  | externalCall (imported : ExternalTarget) (arguments : List Expr) (continuation : Nat)
  | externalJump (imported : ExternalTarget) (arguments : List Expr)
  | bulkCopy (destination source count : Expr) (direction : BoolExpr) (continuation : Nat)
  | indirectCall (target : Expr) (continuation : Nat)
  | indirectJump (target : Expr)
  | checkedContinue (valid : BoolExpr) (continuation : Nat)
  | atomicCompareExchange (address expected replacement : Expr) (continuation : Nat)
deriving Repr, DecidableEq

structure NormalizedSymbolicBehavior where
  registers : Registers Expr
  x87 : SymbolicX87State
  writes : List (Expr × Expr)
  flags : Option FlagsExpr
  outcome : NormalizedOutcomeExpr
deriving Repr, DecidableEq

def normalizeOutcomeExpr (candidate : Bool) (targets : List CodeTargetPair) :
    OutcomeExpr -> Option NormalizedOutcomeExpr
  | .returned target => return .returned target
  | .jump targetRva => return .jump (← normalizeCodeTarget candidate targets targetRva)
  | .branch condition trueTargetRva falseTargetRva =>
      return .branch condition (← normalizeCodeTarget candidate targets trueTargetRva)
        (← normalizeCodeTarget candidate targets falseTargetRva)
  | .call targetRva returnRva _ =>
      return .call (← normalizeCodeTarget candidate targets targetRva)
        (← normalizeCodeTarget candidate targets returnRva)
  | .externalCall imported arguments returnRva =>
      return .externalCall (normalizeImport imported) arguments
        (← normalizeCodeTarget candidate targets returnRva)
  | .externalJump imported arguments =>
      return .externalJump (normalizeImport imported) arguments
  | .bulkCopy copy continuationRva =>
      return .bulkCopy copy.destination copy.source copy.count copy.direction
        (← normalizeCodeTarget candidate targets continuationRva)
  | .indirectCall target continuationRva _ =>
      return .indirectCall target (← normalizeCodeTarget candidate targets continuationRva)
  | .indirectJump target => return .indirectJump target
  | .checkedContinue valid continuationRva =>
      return .checkedContinue valid (← normalizeCodeTarget candidate targets continuationRva)
  | .atomicCompareExchange address expected replacement continuationRva =>
      return .atomicCompareExchange address expected replacement
        (← normalizeCodeTarget candidate targets continuationRva)

def normalizeSymbolicBehavior (candidate : Bool) (targets : List CodeTargetPair)
    (behavior : SymbolicBehavior) : Option NormalizedSymbolicBehavior := do
  let outcomeExpr ← behavior.outcome
  pure {
    registers := behavior.registers
    x87 := behavior.x87
    writes := behavior.writes
    flags := behavior.flags
    outcome := ← normalizeOutcomeExpr candidate targets outcomeExpr
  }

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

def NormalizedSymbolicBehavior.eval (state : MachineState)
    (behavior : NormalizedSymbolicBehavior) : RelationalBehavior := {
  registers := {
    eax := behavior.registers.eax.eval state
    ebx := behavior.registers.ebx.eval state
    ecx := behavior.registers.ecx.eval state
    edx := behavior.registers.edx.eval state
    esi := behavior.registers.esi.eval state
    edi := behavior.registers.edi.eval state
    ebp := behavior.registers.ebp.eval state
    esp := behavior.registers.esp.eval state
  }
  x87 := {
    stack := behavior.x87.stack.map fun value => value.eval state
    control := (behavior.x87.control.eval state).extractLsb' 0 16
    status := (behavior.x87.status.eval state).extractLsb' 0 16
  }
  writes := behavior.writes.map fun write => (write.1.eval state, write.2.eval state)
  eflags := behavior.flags.map (FlagsExpr.eval state) |>.getD state.eflags
  outcome := behavior.outcome.eval state
}

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
      valueTargetContainsCandidate target candidate &&
        original == BitVec.ofNat 32 target.originalValue +
          (candidate - BitVec.ofNat 32 target.candidateValue)

def memoryRelated (targets : List ValueTargetPair) (original candidate : Memory) : Prop :=
  candidate = fun address => original (normalizeDataAddress targets address)

def wordRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : Word) : Bool :=
  original == candidate ||
    codePointerRelated originalImageBase candidateImageBase targets original candidate ||
    mappedValueRelated values original candidate

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

def pureRegionBehavior (pe : PE32) (span : Span) (candidate : Bool)
    (targets : List CodeTargetPair) (state : PureState) : Option PureBehavior := do
  let behavior ← regionBehavior pe span
  evalBehaviorPure candidate targets state behavior

structure RegisterPair where
  original : Reg
  candidate : Reg
deriving Repr, DecidableEq

structure RegisterBoundPair where
  original : Reg
  candidate : Reg
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

def registersRelated (pairs : List RegisterPair) (original candidate : PureState) : Bool :=
  pairs.all fun pair => original.get pair.original == candidate.get pair.candidate

def boundsRelated (bounds : List RegisterBoundPair) (original candidate : PureState) : Bool :=
  bounds.all fun bound =>
    decide (original.get bound.original < BitVec.ofNat 32 bound.upperExclusive) &&
      decide (candidate.get bound.candidate < BitVec.ofNat 32 bound.upperExclusive)

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

def registersRelatedValues (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (pairs : List RegisterPair) (original candidate : PureState) : Bool :=
  pairs.all fun pair => wordRelated originalImageBase candidateImageBase targets values
    (original.get pair.original) (candidate.get pair.candidate)

def statesRelated (bounds : List RegisterBoundPair) (separations : List AddressSeparationPair)
    (values : List ValueTargetPair)
    (pairs : List RegisterPair)
    (original candidate : MachineState) : Prop :=
  registersRelated pairs original.registers candidate.registers = true ∧
    boundsRelated bounds original.registers candidate.registers = true ∧
    addressSeparationsRelated separations original.registers candidate.registers = true ∧
    memoryRelated values original.memory candidate.memory ∧
    original.undefinedValue = candidate.undefinedValue ∧
    original.x87 = candidate.x87 ∧
    original.eflags = candidate.eflags ∧
    original.fsBase = candidate.fsBase

structure RegionRelation where
  id : Nat
  original : Span
  candidate : Span
  root : Bool
  inputs : List RegisterPair
  outputs : List RegisterPair
  bounds : List RegisterBoundPair := []
  addressSeparations : List AddressSeparationPair := []
  targets : List CodeTargetPair
  values : List ValueTargetPair := []
deriving Repr, DecidableEq

def regionEquivalent (originalPe candidatePe : PE32) (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
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
        originalBehavior.eflags = candidateBehavior.eflags ∧
        outcomesRelated originalPe.imageBase candidatePe.imageBase region.targets region.values
          originalBehavior.outcome candidateBehavior.outcome = true
    | _, _ => False

def regionEquivalentWithImports (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
    match (regionBehaviorWithImports originalPe originalImports region.original).bind
          (evalBehavior false region.targets originalState),
        (regionBehaviorWithImports candidatePe candidateImports region.candidate).bind
          (evalBehavior true region.targets candidateState) with
    | some originalBehavior, some candidateBehavior =>
        registersRelatedValues originalPe.imageBase candidatePe.imageBase region.targets region.values
          region.outputs originalBehavior.registers candidateBehavior.registers = true ∧
        originalBehavior.x87 = candidateBehavior.x87 ∧
        writesRelated originalPe.imageBase candidatePe.imageBase region.targets region.values
          originalBehavior.writes candidateBehavior.writes = true ∧
        originalBehavior.eflags = candidateBehavior.eflags ∧
        outcomesRelated originalPe.imageBase candidatePe.imageBase region.targets region.values
          originalBehavior.outcome candidateBehavior.outcome = true
    | _, _ => False

def behaviorsEquivalent (originalImageBase candidateImageBase : Nat)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
    match evalBehavior false region.targets originalState originalBehavior,
        evalBehavior true region.targets candidateState candidateBehavior with
    | some originalResult, some candidateResult =>
        registersRelatedValues originalImageBase candidateImageBase region.targets region.values
          region.outputs originalResult.registers candidateResult.registers = true ∧
        originalResult.x87 = candidateResult.x87 ∧
        writesRelated originalImageBase candidateImageBase region.targets region.values
          originalResult.writes candidateResult.writes = true ∧
        originalResult.eflags = candidateResult.eflags ∧
        outcomesRelated originalImageBase candidateImageBase region.targets region.values
          originalResult.outcome candidateResult.outcome = true
    | _, _ => False

theorem regionEquivalentWithImports_of_decoded (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalDecoded : regionBehaviorWithImports originalPe originalImports region.original = some originalBehavior)
    (candidateDecoded : regionBehaviorWithImports candidatePe candidateImports region.candidate = some candidateBehavior)
    (equivalent : behaviorsEquivalent originalPe.imageBase candidatePe.imageBase
      originalBehavior candidateBehavior region) :
    regionEquivalentWithImports originalPe candidatePe originalImports candidateImports region := by
  intro originalState candidateState related
  rw [originalDecoded, candidateDecoded]
  exact equivalent originalState candidateState related

inductive Observable where
  | external (imported : ExternalTarget)
  | returned
  | fault
deriving Repr, DecidableEq

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
      region.original.start == target.originalRva &&
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
        let originalRelocated := relocationContains originalRelocations originalRva
        let candidateRelocated := relocationContains candidateRelocations candidateRva
        if originalRelocated != candidateRelocated then false
        else if originalRelocated then
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
  object.mappedSize == 0 || mappedObjectContentValidAux originalPe candidatePe
    originalRelocations candidateRelocations targets values object 0 (object.mappedSize + 1)

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

def valueTargetsClosed (originalPe candidatePe : PE32) (regions : List RegionRelation) : Bool :=
  match parseRelocations originalPe, parseRelocations candidatePe with
  | some originalRelocations, some candidateRelocations =>
      valueRegionsClosed originalPe candidatePe originalRelocations candidateRelocations regions
  | _, _ => false

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
      relationCompositionClosed bundle.regions

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
    (compositionChecked : relationCompositionClosed bundle.regions = true) :
    structuralEligible bundle = true := by
  unfold structuralEligible parsedImages
  rw [originalParsed, candidateParsed]
  simp [imagesChecked, indexChecked, regionsChecked, originalCoverageChecked,
    candidateCoverageChecked, originalPaddingChecked, candidatePaddingChecked,
    entryChecked, targetsChecked, originalAliasCoverageChecked,
    candidateAliasCoverageChecked, targetAliasesChecked, valuesChecked,
    compositionChecked]

def regionGoal (bundle : ProofBundle) (region : RegionRelation) : Prop :=
  match parsedImages bundle with
  | some (originalPe, candidatePe) =>
      regionEquivalentWithImports originalPe candidatePe bundle.originalImports.imports
        bundle.candidateImports.imports region
  | none => False

def allRegionGoals (bundle : ProofBundle) : List RegionRelation -> Prop
  | [] => True
  | region :: tail => regionGoal bundle region ∧ allRegionGoals bundle tail

def allDirectRegionGoals (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : List RegionRelation -> Prop
  | [] => True
  | region :: tail =>
      regionEquivalentWithImports originalPe candidatePe originalImports candidateImports region ∧
        allDirectRegionGoals originalPe candidatePe originalImports candidateImports tail

theorem allDirectRegionGoals_append (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) (left right : List RegionRelation)
    (leftChecked : allDirectRegionGoals originalPe candidatePe originalImports
      candidateImports left)
    (rightChecked : allDirectRegionGoals originalPe candidatePe originalImports
      candidateImports right) :
    allDirectRegionGoals originalPe candidatePe originalImports candidateImports
      (left ++ right) := by
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
        bundle.candidateImports.imports regions ->
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
      bundle.candidateImports.imports bundle.regions) :
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
