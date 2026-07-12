import StageA.Formal
import Lean.Data.Json
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
  relocationOffsets : List Nat := []
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

def applyConcreteWrites (memory : Memory) (writes : List (Word × Word)) : Memory :=
  writes.foldl (fun current write => current.write32 write.1 write.2) memory

def RelationalBehavior.nextMachineState
    (behavior : RelationalBehavior) (input : MachineState) : MachineState := {
  registers := behavior.registers
  memory := applyConcreteWrites input.memory behavior.writes
  undefinedValue := input.undefinedValue
  x87 := {
    stack := fun index =>
      (behavior.x87.stack.drop index).head?.getD (BitVec.ofNat 80 0)
    control := behavior.x87.control
    status := behavior.x87.status
    semantics := input.x87.semantics
  }
  eflags := behavior.eflags
  fsBase := input.fsBase
}

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

namespace SemanticIR

open Lean

def tagged (operation : String) (fields : List (String × Json) := []) : Json :=
  Json.mkObj (("op", operation) :: fields)

def array (values : List Json) : Json := .arr values.toArray

def optional (encode : α → Json) : Option α → Json
  | none => .null
  | some value => encode value

def bytes (value : Bytes) : Json := array (value.map fun byte => toJson byte)

def reg : Reg → Json
  | .eax => "eax"
  | .ebx => "ebx"
  | .ecx => "ecx"
  | .edx => "edx"
  | .esi => "esi"
  | .edi => "edi"
  | .ebp => "ebp"
  | .esp => "esp"

def x87LoadFormat : X87LoadFormat → Json
  | .float32 => "float32"
  | .float64 => "float64"
  | .float80 => "float80"
  | .int32 => "int32"

def x87StoreFormat : X87StoreFormat → Json
  | .float32 => "float32"
  | .float64 => "float64"
  | .float80 => "float80"
  | .int32 => "int32"

def x87UnaryOperation : X87UnaryOperation → Json
  | .negate => "negate"

def x87BinaryOperation : X87BinaryOperation → Json
  | .add => "add"
  | .multiply => "multiply"
  | .subtract => "subtract"
  | .reverseSubtract => "reverse_subtract"
  | .divide => "divide"
  | .reverseDivide => "reverse_divide"

mutual
  def expr : Expr → Json
    | .inputReg register => tagged "input_reg" [("reg", reg register)]
    | .inputFlagValue bit => tagged "input_flag_value" [("bit", toJson bit)]
    | .inputFsBase => tagged "input_fs_base"
    | .inputX87Control => tagged "input_x87_control"
    | .inputX87Status => tagged "input_x87_status"
    | .constant value => tagged "constant" [("value", toJson value)]
    | .add left right => tagged "add" [("left", expr left), ("right", expr right)]
    | .sub left right => tagged "sub" [("left", expr left), ("right", expr right)]
    | .bitAnd left right =>
        tagged "bit_and" [("left", expr left), ("right", expr right)]
    | .bitXor left right =>
        tagged "bit_xor" [("left", expr left), ("right", expr right)]
    | .bitNot value => tagged "bit_not" [("value", expr value)]
    | .read8 address => tagged "read8" [("address", expr address)]
    | .read32 address => tagged "read32" [("address", expr address)]
    | .read8AfterWrite address writeAddress writeValue prior =>
        tagged "read8_after_write" [
          ("address", expr address), ("write_address", expr writeAddress),
          ("write_value", expr writeValue), ("prior", expr prior)]
    | .extractByte value index =>
        tagged "extract_byte" [("value", expr value), ("index", toJson index)]
    | .shiftLeft value amount =>
        tagged "shift_left" [("value", expr value), ("amount", toJson amount)]
    | .shiftRight value amount =>
        tagged "shift_right" [("value", expr value), ("amount", toJson amount)]
    | .shiftLeftBy value amount =>
        tagged "shift_left_by" [("left", expr value), ("right", expr amount)]
    | .shiftRightBy value amount =>
        tagged "shift_right_by" [("left", expr value), ("right", expr amount)]
    | .shiftArithmeticRightBy value amount =>
        tagged "shift_arithmetic_right_by" [("left", expr value), ("right", expr amount)]
    | .bitOr left right =>
        tagged "bit_or" [("left", expr left), ("right", expr right)]
    | .ifEqual left right thenValue elseValue =>
        tagged "if_equal" [
          ("left", expr left), ("right", expr right),
          ("then", expr thenValue), ("else", expr elseValue)]
    | .unsignedLessValue left right =>
        tagged "unsigned_less_value" [("left", expr left), ("right", expr right)]
    | .bitValue value index =>
        tagged "bit_value" [("value", expr value), ("index", toJson index)]
    | .multiply left right =>
        tagged "multiply" [("left", expr left), ("right", expr right)]
    | .multiplyHighUnsigned left right =>
        tagged "multiply_high_unsigned" [("left", expr left), ("right", expr right)]
    | .multiplyHighSigned left right =>
        tagged "multiply_high_signed" [("left", expr left), ("right", expr right)]
    | .divideQuotient high low divisor =>
        tagged "divide_quotient" [
          ("high", expr high), ("low", expr low), ("divisor", expr divisor)]
    | .divideRemainder high low divisor =>
        tagged "divide_remainder" [
          ("high", expr high), ("low", expr low), ("divisor", expr divisor)]
    | .divisionValidValue high low divisor =>
        tagged "division_valid_value" [
          ("high", expr high), ("low", expr low), ("divisor", expr divisor)]
    | .lowestSetBit value => tagged "lowest_set_bit" [("value", expr value)]
    | .highestSetBit value => tagged "highest_set_bit" [("value", expr value)]
    | .undefined slot => tagged "undefined" [("slot", toJson slot)]
    | .x87Part value part =>
        tagged "x87_part" [("value", x87Expr value), ("part", toJson part)]
    | .x87CompareBit left right control bit =>
        tagged "x87_compare_bit" [
          ("left", x87Expr left), ("right", x87Expr right),
          ("control", expr control), ("bit", toJson bit)]
    | .x87ExamineStatus value status =>
        tagged "x87_examine_status" [("value", x87Expr value), ("status", expr status)]

  def x87Expr : X87Expr → Json
    | .inputStack index => tagged "input_stack" [("index", toJson index)]
    | .load format address control =>
        tagged "load" [
          ("format", x87LoadFormat format), ("address", expr address),
          ("control", expr control)]
    | .imageLoad format raw control =>
        tagged "image_load" [
          ("format", x87LoadFormat format), ("raw", toJson raw),
          ("control", expr control)]
    | .constant value => tagged "constant" [("value", toJson value)]
    | .unary operation value control =>
        tagged "unary" [
          ("operation", x87UnaryOperation operation), ("value", x87Expr value),
          ("control", expr control)]
    | .binary operation left right control =>
        tagged "binary" [
          ("operation", x87BinaryOperation operation), ("left", x87Expr left),
          ("right", x87Expr right), ("control", expr control)]
    | .store format value control =>
        tagged "store" [
          ("format", x87StoreFormat format), ("value", x87Expr value),
          ("control", expr control)]

end

def boolExpr : BoolExpr → Json
  | .equal left right => tagged "equal" [("left", expr left), ("right", expr right)]
  | .not value => tagged "not" [("value", boolExpr value)]
  | .and left right =>
      tagged "and" [("left", boolExpr left), ("right", boolExpr right)]
  | .or left right =>
      tagged "or" [("left", boolExpr left), ("right", boolExpr right)]
  | .xor left right =>
      tagged "xor" [("left", boolExpr left), ("right", boolExpr right)]
  | .unsignedLess left right =>
      tagged "unsigned_less" [("left", expr left), ("right", expr right)]
  | .msb value => tagged "msb" [("value", expr value)]
  | .bit value index => tagged "bit" [("value", expr value), ("index", toJson index)]
  | .inputFlag index => tagged "input_flag" [("index", toJson index)]
  | .divisionValid high low divisor =>
      tagged "division_valid" [
        ("high", expr high), ("low", expr low), ("divisor", expr divisor)]

def flags (value : FlagsExpr) : Json := Json.mkObj [
  ("zero", optional boolExpr value.zero),
  ("carry", optional boolExpr value.carry),
  ("sign", optional boolExpr value.sign),
  ("overflow", optional boolExpr value.overflow),
  ("parity", optional boolExpr value.parity)]

def importName : ImportName → Json
  | .symbol name => tagged "symbol" [("bytes", bytes name)]
  | .ordinal value => tagged "ordinal" [("value", toJson value)]

def externalTarget (target : ExternalTarget) : Json := Json.mkObj [
  ("dll", bytes target.dll), ("name", importName target.name)]

def normalizedOutcome : NormalizedOutcomeExpr → Json
  | .returned target => tagged "returned" [("target", expr target)]
  | .jump target => tagged "jump" [("target", toJson target)]
  | .branch condition taken fallthrough =>
      tagged "branch" [
        ("condition", boolExpr condition), ("taken", toJson taken),
        ("fallthrough", toJson fallthrough)]
  | .call target continuation =>
      tagged "call" [("target", toJson target), ("continuation", toJson continuation)]
  | .externalCall imported arguments continuation =>
      tagged "external_call" [
        ("import", externalTarget imported), ("arguments", array (arguments.map expr)),
        ("continuation", toJson continuation)]
  | .externalJump imported arguments =>
      tagged "external_jump" [
        ("import", externalTarget imported), ("arguments", array (arguments.map expr))]
  | .bulkCopy destination source count direction continuation =>
      tagged "bulk_copy" [
        ("destination", expr destination), ("source", expr source),
        ("count", expr count), ("direction", boolExpr direction),
        ("continuation", toJson continuation)]
  | .indirectCall target continuation =>
      tagged "indirect_call" [
        ("target", expr target), ("continuation", toJson continuation)]
  | .indirectJump target => tagged "indirect_jump" [("target", expr target)]
  | .checkedContinue valid continuation =>
      tagged "checked_continue" [
        ("valid", boolExpr valid), ("continuation", toJson continuation)]
  | .atomicCompareExchange address expected replacement continuation =>
      tagged "atomic_compare_exchange" [
        ("address", expr address), ("expected", expr expected),
        ("replacement", expr replacement), ("continuation", toJson continuation)]

def registers (value : Registers Expr) : Json := Json.mkObj [
  ("eax", expr value.eax), ("ebx", expr value.ebx),
  ("ecx", expr value.ecx), ("edx", expr value.edx),
  ("esi", expr value.esi), ("edi", expr value.edi),
  ("ebp", expr value.ebp), ("esp", expr value.esp)]

def x87 (value : SymbolicX87State) : Json := Json.mkObj [
  ("stack", array (value.stack.map x87Expr)),
  ("control", expr value.control), ("status", expr value.status)]

def write (value : Expr × Expr) : Json := Json.mkObj [
  ("address", expr value.1), ("value", expr value.2)]

def normalizedBehavior (value : NormalizedSymbolicBehavior) : Json := Json.mkObj [
  ("format", "stage-a-normalized-behavior-v1"),
  ("registers", registers value.registers),
  ("x87", x87 value.x87),
  ("writes", array (value.writes.map write)),
  ("flags", optional flags value.flags),
  ("outcome", normalizedOutcome value.outcome)]

def normalizedBehaviorString (value : NormalizedSymbolicBehavior) : String :=
  normalizedBehavior value |>.compress

end SemanticIR

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

def Memory.read32 (memory : Memory) (address : Word) : Word :=
  let b0 := BitVec.zeroExtend 32 (memory address)
  let b1 := (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 1))).shiftLeft 8
  let b2 := (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 2))).shiftLeft 16
  let b3 := (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 3))).shiftLeft 24
  b0 ||| b1 ||| b2 ||| b3

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
  registersRelated pairs original.registers candidate.registers = true ∧
    boundsRelated bounds original.registers candidate.registers = true ∧
    addressSeparationsRelated separations original.registers candidate.registers = true ∧
    memoryRelated originalImageBase candidateImageBase targets values
      original.memory candidate.memory ∧
    original.undefinedValue = candidate.undefinedValue ∧
    original.x87 = candidate.x87 ∧
    flagsRelated flagInputs original.eflags candidate.eflags = true ∧
    original.fsBase = candidate.fsBase

def composableStatesRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair)
    (flagInputs : List Nat)
    (bounds : List RegisterBoundPair) (separations : List AddressSeparationPair)
    (values : List ValueTargetPair)
    (pairs : List RegisterPair)
    (original candidate : MachineState) : Prop :=
  registersRelatedValues originalImageBase candidateImageBase targets values pairs
      original.registers candidate.registers = true ∧
    boundsRelated bounds original.registers candidate.registers = true ∧
    addressSeparationsRelated separations original.registers candidate.registers = true ∧
    memoryRelated originalImageBase candidateImageBase targets values
      original.memory candidate.memory ∧
    original.undefinedValue = candidate.undefinedValue ∧
    original.x87 = candidate.x87 ∧
    flagsRelated flagInputs original.eflags candidate.eflags = true ∧
    original.fsBase = candidate.fsBase

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
      separations values pairs original candidate := by
  rcases related with ⟨registers, rest⟩
  exact ⟨registersRelated_implies_registersRelatedValues originalImageBase candidateImageBase
    targets values pairs original.registers candidate.registers registers, rest⟩

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
  flagInputs : List Nat := [0, 2, 6, 7, 10, 11]
  flagOutputs : List Nat := [0, 2, 6, 7, 10, 11]
deriving Repr, DecidableEq

def regionById (regions : List RegionRelation) (id : Nat) : Option RegionRelation :=
  regions.find? fun region => region.id == id

def allCodeTargets (regions : List RegionRelation) : List CodeTargetPair :=
  regions.flatMap (·.targets)

def allValueTargets (regions : List RegionRelation) : List ValueTargetPair :=
  regions.flatMap (·.values)

def MemoryObservationTransitionClosed
    (originalImageBase candidateImageBase : Nat)
    (source : RegionRelation)
    (observationTargets : List CodeTargetPair)
    (observationValues : List ValueTargetPair)
    (requirements : List MemoryObservationRequirement)
    (x87Requirements : List X87MemoryObservationRequirement)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Prop :=
  ∀ originalState candidateState,
    composableStatesRelated originalImageBase candidateImageBase source.targets
      source.flagInputs source.bounds source.addressSeparations source.values source.inputs
      originalState candidateState →
    memoryObservationContractHolds originalImageBase candidateImageBase observationTargets
      observationValues requirements
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
    (originalImports candidateImports : List PEImport) (region : RegionRelation) : Prop :=
  ∀ originalState candidateState,
    statesRelated originalPe.imageBase candidatePe.imageBase region.targets region.flagInputs
      region.bounds region.addressSeparations region.values region.inputs originalState candidateState →
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
  unfold statesRelated at related
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

@[simp] theorem evalNormalizedRegisters_get (state : MachineState)
    (registers : Registers Expr) (register : Reg) :
    (evalNormalizedRegisters state registers).get register =
      (registers.get register).eval state := by
  cases register <;> rfl

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

def PureOutcome.relationalObservation : PureOutcome -> Option RelationalObservable
  | .externalCall imported arguments _ => some (.external imported arguments)
  | .externalJump imported arguments => some (.external imported arguments)
  | .returned _ => some .returned
  | .checkedContinue valid _ => if valid then none else some .fault
  | _ => none

def relationalObservationsRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair) :
    Option RelationalObservable -> Option RelationalObservable -> Bool
  | none, none => true
  | some (.external originalImport originalArguments),
      some (.external candidateImport candidateArguments) =>
      originalImport == candidateImport &&
        wordsRelated originalImageBase candidateImageBase targets values
          originalArguments candidateArguments
  | some .returned, some .returned => true
  | some .fault, some .fault => true
  | _, _ => false

theorem relationalObservationsRelated_self (imageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (observation : Option RelationalObservable) :
    relationalObservationsRelated imageBase imageBase targets values
      observation observation = true := by
  cases observation with
  | none => rfl
  | some observation =>
      cases observation <;>
        simp [relationalObservationsRelated, wordsRelated_self]

theorem outcomesRelated_observation_eq
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : PureOutcome)
    (related : outcomesRelated originalImageBase candidateImageBase targets values
      original candidate = true) :
    original.observation = candidate.observation := by
  cases original <;> cases candidate <;>
    simp_all [outcomesRelated, PureOutcome.observation]

theorem outcomesRelated_nextLogicalTarget_eq
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : PureOutcome)
    (related : outcomesRelated originalImageBase candidateImageBase targets values
      original candidate = true) :
    original.nextLogicalTarget = candidate.nextLogicalTarget := by
  cases original <;> cases candidate <;>
    simp_all [outcomesRelated, PureOutcome.nextLogicalTarget]

theorem outcomesRelated_relationalObservation
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : PureOutcome)
    (related : outcomesRelated originalImageBase candidateImageBase targets values
      original candidate = true) :
    relationalObservationsRelated originalImageBase candidateImageBase targets values
      original.relationalObservation candidate.relationalObservation = true := by
  cases original <;> cases candidate <;>
    simp_all [outcomesRelated, PureOutcome.relationalObservation,
      relationalObservationsRelated]
  all_goals split <;> simp_all

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

structure RelatedTransition (state observation : Type) where
  next : state
  observation : Option observation

structure RelatedTransitionSystem (state observation : Type) where
  step : state -> RelatedTransition state observation

def RelationalWeakBisimulation
    {originalState candidateState originalObservation candidateObservation : Type}
    (original : RelatedTransitionSystem originalState originalObservation)
    (candidate : RelatedTransitionSystem candidateState candidateObservation)
    (stateRelation : originalState -> candidateState -> Prop)
    (observationRelation : Option originalObservation -> Option candidateObservation -> Prop) : Prop :=
  ∀ originalValue candidateValue,
    stateRelation originalValue candidateValue ->
    observationRelation (original.step originalValue).observation
      (candidate.step candidateValue).observation ∧
    stateRelation (original.step originalValue).next (candidate.step candidateValue).next

def RelatedTrace
    {originalState candidateState originalObservation candidateObservation : Type}
    (original : RelatedTransitionSystem originalState originalObservation)
    (candidate : RelatedTransitionSystem candidateState candidateObservation)
    (stateRelation : originalState -> candidateState -> Prop)
    (observationRelation : Option originalObservation -> Option candidateObservation -> Prop) :
    Nat -> originalState -> candidateState -> Prop
  | 0, originalState, candidateState => stateRelation originalState candidateState
  | fuel + 1, originalState, candidateState =>
      observationRelation (original.step originalState).observation
          (candidate.step candidateState).observation ∧
        RelatedTrace original candidate stateRelation observationRelation fuel
          (original.step originalState).next (candidate.step candidateState).next

theorem relationalWeakBisimulation_trace
    {originalState candidateState originalObservation candidateObservation : Type}
    (original : RelatedTransitionSystem originalState originalObservation)
    (candidate : RelatedTransitionSystem candidateState candidateObservation)
    (stateRelation : originalState -> candidateState -> Prop)
    (observationRelation : Option originalObservation -> Option candidateObservation -> Prop)
    (bisimulation : RelationalWeakBisimulation original candidate stateRelation
      observationRelation) :
    ∀ fuel originalState candidateState,
      stateRelation originalState candidateState ->
      RelatedTrace original candidate stateRelation observationRelation fuel
        originalState candidateState := by
  intro fuel
  induction fuel with
  | zero =>
      intro originalState candidateState related
      exact related
  | succ fuel ih =>
      intro originalState candidateState related
      have step := bisimulation originalState candidateState related
      exact ⟨step.1, ih _ _ step.2⟩

def Memory.bulkCopyDwords (memory : Memory) (destination source : Word)
    (direction : Bool) : Nat -> Memory
  | 0 => memory
  | count + 1 =>
      let value := Memory.read32 memory source
      let nextMemory := memory.write32 destination value
      let distance := BitVec.ofNat 32 4
      let nextDestination := if direction then destination - distance else destination + distance
      let nextSource := if direction then source - distance else source + distance
      Memory.bulkCopyDwords nextMemory nextDestination nextSource direction count

def Memory.atomicCompareExchange (memory : Memory) (address expected replacement : Word) :
    Memory :=
  if Memory.read32 memory address == expected then
    memory.write32 address replacement
  else
    memory

structure RelationalExternalEvent where
  imported : ExternalTarget
  arguments : List Word
  state : MachineState

structure RelationalEnvironment where
  result : Nat -> RelationalExternalEvent -> MachineState

structure RelationalProgramSemantics where
  behavior : Nat -> MachineState -> Option RelationalBehavior
  resolveTarget : Word -> Option Nat
  environment : RelationalEnvironment

inductive RelationalExecution where
  | running (region : Nat) (state : MachineState) (calls : List Nat) (eventIndex : Nat)
  | returned (state : MachineState)
  | fault

def transitionFromOutcome (program : RelationalProgramSemantics)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat) :
    PureOutcome -> RelatedTransition RelationalExecution RelationalObservable
  | .returned target =>
      match calls with
      | [] => { next := .returned state, observation := some .returned }
      | continuation :: tail =>
          match program.resolveTarget target with
          | some resolved =>
              if resolved == continuation then
                { next := .running continuation state tail eventIndex, observation := none }
              else
                { next := .fault, observation := some .fault }
          | none => { next := .fault, observation := some .fault }
  | .jump target =>
      { next := .running target state calls eventIndex, observation := none }
  | .branch condition taken fallthrough =>
      { next := .running (if condition then taken else fallthrough) state calls eventIndex,
        observation := none }
  | .call target continuation =>
      { next := .running target state (continuation :: calls) eventIndex, observation := none }
  | .externalCall imported arguments continuation =>
      let event := { imported, arguments, state : RelationalExternalEvent }
      let result := program.environment.result eventIndex event
      { next := .running continuation result calls (eventIndex + 1),
        observation := some (.external imported arguments) }
  | .externalJump imported arguments =>
      let event := { imported, arguments, state : RelationalExternalEvent }
      let result := program.environment.result eventIndex event
      let next := match calls with
        | [] => RelationalExecution.returned result
        | continuation :: tail =>
            RelationalExecution.running continuation result tail (eventIndex + 1)
      { next, observation := some (.external imported arguments) }
  | .bulkCopy destination source count direction continuation =>
      let memory := Memory.bulkCopyDwords state.memory destination source direction count.toNat
      { next := .running continuation { state with memory } calls eventIndex,
        observation := none }
  | .indirectCall target continuation =>
      match program.resolveTarget target with
      | some resolved =>
          { next := .running resolved state (continuation :: calls) eventIndex,
            observation := none }
      | none => { next := .fault, observation := some .fault }
  | .indirectJump target =>
      match program.resolveTarget target with
      | some resolved =>
          { next := .running resolved state calls eventIndex, observation := none }
      | none => { next := .fault, observation := some .fault }
  | .checkedContinue valid continuation =>
      if valid then
        { next := .running continuation state calls eventIndex, observation := none }
      else
        { next := .fault, observation := some .fault }
  | .atomicCompareExchange address expected replacement continuation =>
      let memory := Memory.atomicCompareExchange state.memory address expected replacement
      { next := .running continuation { state with memory } calls eventIndex,
        observation := none }

def stepRelationalExecution (program : RelationalProgramSemantics) :
    RelationalExecution -> RelatedTransition RelationalExecution RelationalObservable
  | .running region state calls eventIndex =>
      match program.behavior region state with
      | none => { next := .fault, observation := some .fault }
      | some behavior =>
          transitionFromOutcome program (behavior.nextMachineState state) calls eventIndex
            behavior.outcome
  | .returned state => { next := .returned state, observation := none }
  | .fault => { next := .fault, observation := none }

def RelationalProgramSemantics.transitionSystem (program : RelationalProgramSemantics) :
    RelatedTransitionSystem RelationalExecution RelationalObservable := {
  step := stepRelationalExecution program
}

def decodedProgramSemantics (candidate : Bool) (pe : PE32) (imports : List PEImport)
    (regions : List RegionRelation) (environment : RelationalEnvironment) :
    RelationalProgramSemantics := {
  behavior := decodedRegionBehavior candidate pe imports regions
  resolveTarget := resolveMappedCodeTarget candidate pe.imageBase (allCodeTargets regions)
  environment
}

def regionMachineStatesRelated (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (id : Nat)
    (original candidate : MachineState) : Prop :=
  match regionById regions id with
  | some region =>
      composableStatesRelated originalImageBase candidateImageBase region.targets region.flagInputs
        region.bounds region.addressSeparations region.values region.inputs original candidate
  | none => False

def executionsRelated (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation)
    (terminalRelation : MachineState -> MachineState -> Prop) :
    RelationalExecution -> RelationalExecution -> Prop
  | .running originalRegion originalState originalCalls originalEventIndex,
      .running candidateRegion candidateState candidateCalls candidateEventIndex =>
      originalRegion = candidateRegion ∧ originalCalls = candidateCalls ∧
        originalEventIndex = candidateEventIndex ∧
        regionMachineStatesRelated originalImageBase candidateImageBase regions
          originalRegion originalState candidateState
  | .returned originalState, .returned candidateState =>
      terminalRelation originalState candidateState
  | .fault, .fault => True
  | _, _ => False

def AllRunningTransitionsRelated
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop) : Prop :=
  ∀ region originalState candidateState calls eventIndex,
    regionMachineStatesRelated originalImageBase candidateImageBase regions region
      originalState candidateState ->
    relationalObservationsRelated originalImageBase candidateImageBase targets values
        (stepRelationalExecution original
          (.running region originalState calls eventIndex)).observation
        (stepRelationalExecution candidate
          (.running region candidateState calls eventIndex)).observation = true ∧
      executionsRelated originalImageBase candidateImageBase regions terminalRelation
        (stepRelationalExecution original
          (.running region originalState calls eventIndex)).next
        (stepRelationalExecution candidate
          (.running region candidateState calls eventIndex)).next

def RegionRunningTransitionRelated
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop)
    (region : RegionRelation) : Prop :=
  ∀ originalState candidateState calls eventIndex,
    composableStatesRelated originalImageBase candidateImageBase region.targets region.flagInputs
      region.bounds region.addressSeparations region.values region.inputs
      originalState candidateState ->
    relationalObservationsRelated originalImageBase candidateImageBase targets values
        (stepRelationalExecution original
          (.running region.id originalState calls eventIndex)).observation
        (stepRelationalExecution candidate
          (.running region.id candidateState calls eventIndex)).observation = true ∧
      executionsRelated originalImageBase candidateImageBase regions terminalRelation
        (stepRelationalExecution original
          (.running region.id originalState calls eventIndex)).next
        (stepRelationalExecution candidate
          (.running region.id candidateState calls eventIndex)).next

def AllRegionRunningTransitionsRelated
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop) : Prop :=
  ∀ region, region ∈ regions ->
    RegionRunningTransitionRelated originalImageBase candidateImageBase regions targets values
      original candidate terminalRelation region

theorem allRunningTransitionsRelated_of_regions
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop)
    (checked : AllRegionRunningTransitionsRelated originalImageBase candidateImageBase
      regions targets values original candidate terminalRelation) :
    AllRunningTransitionsRelated originalImageBase candidateImageBase regions targets values
      original candidate terminalRelation := by
  intro id originalState candidateState calls eventIndex related
  unfold regionMachineStatesRelated at related
  cases found : regionById regions id with
  | none => simp [found] at related
  | some region =>
      have member : region ∈ regions := by
        unfold regionById at found
        exact List.mem_of_find?_eq_some found
      have idMatch : region.id = id := by
        unfold regionById at found
        have matched := List.find?_some found
        simpa only [beq_iff_eq] using matched
      subst id
      exact checked region member originalState candidateState calls eventIndex (by
        simpa [found] using related)

def WholeProgramBisimulation
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (executionRelation : RelationalExecution -> RelationalExecution -> Prop) : Prop :=
  RelationalWeakBisimulation original.transitionSystem candidate.transitionSystem
    executionRelation
    (fun originalObservation candidateObservation =>
      relationalObservationsRelated originalImageBase candidateImageBase targets values
        originalObservation candidateObservation = true)

theorem wholeProgramBisimulation_of_runningTransitions
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop)
    (running : AllRunningTransitionsRelated originalImageBase candidateImageBase regions
      targets values original candidate terminalRelation) :
    WholeProgramBisimulation originalImageBase candidateImageBase targets values
      original candidate
      (executionsRelated originalImageBase candidateImageBase regions terminalRelation) := by
  intro originalExecution candidateExecution related
  cases originalExecution <;> cases candidateExecution <;>
    simp [executionsRelated] at related
  case running.running originalRegion originalState originalCalls originalEventIndex
      candidateRegion candidateState candidateCalls candidateEventIndex =>
    rcases related with ⟨regionEqual, callsEqual, eventIndexEqual, stateRelated⟩
    subst candidateRegion
    subst candidateCalls
    subst candidateEventIndex
    exact running originalRegion originalState candidateState originalCalls originalEventIndex
      stateRelated
  case returned.returned originalState candidateState =>
    exact ⟨rfl, related⟩
  case fault.fault =>
    exact ⟨rfl, trivial⟩

def WholeProgramTraceRelation
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (executionRelation : RelationalExecution -> RelationalExecution -> Prop) :
    Nat -> RelationalExecution -> RelationalExecution -> Prop :=
  RelatedTrace original.transitionSystem candidate.transitionSystem executionRelation
    (fun originalObservation candidateObservation =>
      relationalObservationsRelated originalImageBase candidateImageBase targets values
        originalObservation candidateObservation = true)

def WholeProgramObservationalEquivalence
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (initialRelation : MachineState -> MachineState -> Prop) : Prop :=
  ∃ executionRelation : RelationalExecution -> RelationalExecution -> Prop,
    (∀ entry originalState candidateState,
      initialRelation originalState candidateState ->
      executionRelation (.running entry originalState [] 0)
        (.running entry candidateState [] 0)) ∧
    WholeProgramBisimulation originalImageBase candidateImageBase targets values
      original candidate executionRelation

theorem wholeProgramObservationalEquivalence_self (imageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (program : RelationalProgramSemantics) :
    WholeProgramObservationalEquivalence imageBase imageBase targets values program program
      (fun original candidate => original = candidate) := by
  refine ⟨fun original candidate => original = candidate, ?_, ?_⟩
  · intro entry originalState candidateState related
    subst candidateState
    rfl
  · intro originalExecution candidateExecution related
    subst candidateExecution
    exact ⟨relationalObservationsRelated_self imageBase targets values _, rfl⟩

theorem wholeProgramObservationalEquivalence_trace
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (initialRelation : MachineState -> MachineState -> Prop)
    (equivalent : WholeProgramObservationalEquivalence originalImageBase candidateImageBase
      targets values original candidate initialRelation) :
    ∀ fuel entry originalState candidateState,
      initialRelation originalState candidateState ->
      ∃ executionRelation : RelationalExecution -> RelationalExecution -> Prop,
        WholeProgramTraceRelation originalImageBase candidateImageBase targets values
          original candidate executionRelation fuel
          (.running entry originalState [] 0) (.running entry candidateState [] 0) := by
  rcases equivalent with ⟨executionRelation, initial, bisimulation⟩
  intro fuel entry originalState candidateState related
  refine ⟨executionRelation, ?_⟩
  exact relationalWeakBisimulation_trace original.transitionSystem candidate.transitionSystem
    executionRelation
    (fun originalObservation candidateObservation =>
      relationalObservationsRelated originalImageBase candidateImageBase targets values
        originalObservation candidateObservation = true)
    bisimulation fuel _ _ (initial entry originalState candidateState related)

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
      region.id == target.id && region.original.start == target.originalRva &&
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

def relocationCount (relocations : List BaseRelocation) (rva : Nat) : Nat :=
  (relocations.filter fun relocation => relocation.rva == rva && relocation.kind == 3).length

def relocationOffsetsStrictlyIncreasing : List Nat -> Bool
  | [] | [_] => true
  | left :: right :: tail => left < right && relocationOffsetsStrictlyIncreasing (right :: tail)

def relocationOffsetsValid (object : ValueTargetPair) : Bool :=
  relocationOffsetsStrictlyIncreasing object.relocationOffsets &&
    object.relocationOffsets.all fun offset =>
      offset % 4 == 0 && offset + 4 <= object.mappedSize

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
        let declaredRelocated := object.relocationOffsets.contains offset
        let declaredCount := if declaredRelocated then 1 else 0
        if relocationCount originalRelocations originalRva != declaredCount ||
            relocationCount candidateRelocations candidateRva != declaredCount then false
        else if declaredRelocated then
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
  relocationOffsetsValid object &&
    (object.mappedSize == 0 || mappedObjectContentValidAux originalPe candidatePe
      originalRelocations candidateRelocations targets values object 0 (object.mappedSize + 1))

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

def AllMappedRelocationImageRelations (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (regions : List RegionRelation) : Prop :=
  ∀ region, region ∈ regions →
    ∀ object, object ∈ region.values →
      object.mappedSize > 0 → object.relocationOffsets ≠ [] →
        valueTargetValid originalPe candidatePe originalRelocations candidateRelocations
          region.targets region.values object = true

theorem allMappedRelocationImageRelations_of_valueRegionsClosed
    (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (regions : List RegionRelation)
    (checked : valueRegionsClosed originalPe candidatePe originalRelocations
      candidateRelocations regions = true) :
    AllMappedRelocationImageRelations originalPe candidatePe originalRelocations
      candidateRelocations regions := by
  intro region regionMember object objectMember _ _
  unfold valueRegionsClosed at checked
  simp only [List.all_eq_true] at checked
  have regionChecked := checked region regionMember
  unfold valueRegionClosed at regionChecked
  simp only [Bool.and_eq_true] at regionChecked
  have objectsChecked := regionChecked.2
  simp only [List.all_eq_true] at objectsChecked
  exact objectsChecked object objectMember

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

def targetFlagRelationClosed (regions : IndexTree RegionRelation)
    (source : RegionRelation) (target : CodeTargetPair) : Bool :=
  match regions.get? target.regionIndex with
  | some destination => destination.flagInputs.all source.flagOutputs.contains
  | none => false

def flagRelationCompositionClosed (index : IndexTree RegionRelation)
    (regions : List RegionRelation) : Bool :=
  regions.all fun source => source.targets.all (targetFlagRelationClosed index source)

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
      relationCompositionClosed bundle.regions &&
      flagRelationCompositionClosed bundle.regionIndex bundle.regions

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
    (compositionChecked : relationCompositionClosed bundle.regions = true)
    (flagCompositionChecked :
      flagRelationCompositionClosed bundle.regionIndex bundle.regions = true) :
    structuralEligible bundle = true := by
  unfold structuralEligible parsedImages
  rw [originalParsed, candidateParsed]
  simp [imagesChecked, indexChecked, regionsChecked, originalCoverageChecked,
    candidateCoverageChecked, originalPaddingChecked, candidatePaddingChecked,
    entryChecked, targetsChecked, originalAliasCoverageChecked,
    candidateAliasCoverageChecked, targetAliasesChecked, valuesChecked,
    compositionChecked, flagCompositionChecked]

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
