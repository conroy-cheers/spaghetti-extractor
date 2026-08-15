import SpaghettiExtractor.ISA.PE32
import SpaghettiExtractor.ISA.X87

namespace SpaghettiExtractor.ISA.Formal

abbrev Word := BitVec 32
abbrev Memory := Word -> BitVec 8
abbrev X87Word := BitVec 80

inductive X87LoadFormat where
  | float32 | float64 | float80 | int32
deriving Repr, DecidableEq

def X87LoadFormat.byteWidth : X87LoadFormat -> Nat
  | .float32 | .int32 => 4
  | .float64 => 8
  | .float80 => 10

inductive X87StoreFormat where
  | float32 | float64 | float80 | int32 | int64
deriving Repr, DecidableEq

inductive X87UnaryOperation where
  | negate
  | sine
  | cosine
deriving Repr, DecidableEq

inductive X87BinaryOperation where
  | add | multiply | subtract | reverseSubtract | divide | reverseDivide
deriving Repr, DecidableEq

structure X87Semantics where
  load : X87LoadFormat -> X87Word -> BitVec 16 -> X87Word
  store : X87StoreFormat -> X87Word -> BitVec 16 -> X87Word
  unary : X87UnaryOperation -> X87Word -> BitVec 16 -> X87Word
  binary : X87BinaryOperation -> X87Word -> X87Word -> BitVec 16 -> X87Word
  compare : X87Word -> X87Word -> BitVec 16 -> BitVec 3
  examine : X87Word -> BitVec 16 -> BitVec 16

def defaultX87Semantics : X87Semantics := {
  load := fun _ value _ => value
  store := fun _ value _ => value
  unary := fun _ value _ => value
  binary := fun _ left _ _ => left
  compare := fun _ _ _ => BitVec.ofNat 3 0
  examine := fun _ status => status
}

structure X87MachineState where
  stack : Nat -> X87Word := fun _ => BitVec.ofNat 80 0
  control : BitVec 16 := BitVec.ofNat 16 0x037f
  status : BitVec 16 := BitVec.ofNat 16 0
  semantics : X87Semantics := defaultX87Semantics

inductive Reg where
  | eax | ebx | ecx | edx | esi | edi | ebp | esp
deriving Repr, DecidableEq

structure Registers (alpha : Type) where
  eax : alpha
  ebx : alpha
  ecx : alpha
  edx : alpha
  esi : alpha
  edi : alpha
  ebp : alpha
  esp : alpha
deriving Repr, DecidableEq

theorem Registers.eq_of_fields (original candidate : Registers alpha)
    (eax : original.eax = candidate.eax)
    (ebx : original.ebx = candidate.ebx)
    (ecx : original.ecx = candidate.ecx)
    (edx : original.edx = candidate.edx)
    (esi : original.esi = candidate.esi)
    (edi : original.edi = candidate.edi)
    (ebp : original.ebp = candidate.ebp)
    (esp : original.esp = candidate.esp) :
    original = candidate := by
  cases original
  cases candidate
  simp_all

def Registers.get (registers : Registers alpha) : Reg -> alpha
  | .eax => registers.eax
  | .ebx => registers.ebx
  | .ecx => registers.ecx
  | .edx => registers.edx
  | .esi => registers.esi
  | .edi => registers.edi
  | .ebp => registers.ebp
  | .esp => registers.esp

def Registers.set (registers : Registers alpha) (reg : Reg) (value : alpha) : Registers alpha :=
  match reg with
  | .eax => { registers with eax := value }
  | .ebx => { registers with ebx := value }
  | .ecx => { registers with ecx := value }
  | .edx => { registers with edx := value }
  | .esi => { registers with esi := value }
  | .edi => { registers with edi := value }
  | .ebp => { registers with ebp := value }
  | .esp => { registers with esp := value }

mutual
inductive Expr where
  | inputReg (reg : Reg)
  | inputFlagValue (bit : Nat)
  | inputFsBase
  | inputX87Control
  | inputX87Status
  | constant (value : Nat)
  | add (left right : Expr)
  | sub (left right : Expr)
  | bitAnd (left right : Expr)
  | bitXor (left right : Expr)
  | bitNot (value : Expr)
  | read8 (address : Expr)
  | read32 (address : Expr)
  | read8AfterWrite (address writeAddress writeValue prior : Expr)
  | extractByte (value : Expr) (index : Nat)
  | shiftLeft (value : Expr) (amount : Nat)
  | shiftRight (value : Expr) (amount : Nat)
  | shiftLeftBy (value amount : Expr)
  | shiftRightBy (value amount : Expr)
  | shiftArithmeticRightBy (value amount : Expr)
  | bitOr (left right : Expr)
  | ifEqual (left right thenValue elseValue : Expr)
  | unsignedLessValue (left right : Expr)
  | bitValue (value : Expr) (index : Nat)
  | multiply (left right : Expr)
  | multiplyHighUnsigned (left right : Expr)
  | multiplyHighSigned (left right : Expr)
  | divideQuotient (high low divisor : Expr)
  | divideRemainder (high low divisor : Expr)
  | divisionValidValue (high low divisor : Expr)
  | lowestSetBit (value : Expr)
  | highestSetBit (value : Expr)
  | undefined (slot : Nat)
  | x87Part (value : X87Expr) (part : Nat)
  | x87CompareBit (left right : X87Expr) (control : Expr) (bit : Nat)
  | x87ExamineStatus (value : X87Expr) (status : Expr)
deriving Repr, DecidableEq

inductive X87Expr where
  | inputStack (index : Nat)
  | load (format : X87LoadFormat) (address control : Expr)
  | imageLoad (format : X87LoadFormat) (raw : Nat) (control : Expr)
  | constant (value : Nat)
  | unary (operation : X87UnaryOperation) (value : X87Expr) (control : Expr)
  | binary (operation : X87BinaryOperation) (left right : X87Expr) (control : Expr)
  | store (format : X87StoreFormat) (value : X87Expr) (control : Expr)
deriving Repr, DecidableEq
end

mutual
def Expr.flagsWithin (allowed : List Nat) : Expr -> Bool
  | .inputReg _ | .inputFsBase | .inputX87Control | .inputX87Status | .constant _ |
      .undefined _ => true
  | .inputFlagValue bit => allowed.contains bit
  | .add left right | .sub left right | .bitAnd left right | .bitXor left right |
      .shiftLeftBy left right | .shiftRightBy left right |
      .shiftArithmeticRightBy left right | .bitOr left right |
      .unsignedLessValue left right | .multiply left right |
      .multiplyHighUnsigned left right | .multiplyHighSigned left right =>
      left.flagsWithin allowed && right.flagsWithin allowed
  | .bitNot value | .read8 value | .read32 value | .extractByte value _ |
      .shiftLeft value _ | .shiftRight value _ | .bitValue value _ |
      .lowestSetBit value | .highestSetBit value => value.flagsWithin allowed
  | .read8AfterWrite address writeAddress writeValue prior |
      .ifEqual address writeAddress writeValue prior =>
      address.flagsWithin allowed && writeAddress.flagsWithin allowed &&
        writeValue.flagsWithin allowed && prior.flagsWithin allowed
  | .divideQuotient high low divisor | .divideRemainder high low divisor |
      .divisionValidValue high low divisor =>
      high.flagsWithin allowed && low.flagsWithin allowed && divisor.flagsWithin allowed
  | .x87Part value _ => value.flagsWithin allowed
  | .x87CompareBit left right control _ =>
      left.flagsWithin allowed && right.flagsWithin allowed && control.flagsWithin allowed
  | .x87ExamineStatus value status =>
      value.flagsWithin allowed && status.flagsWithin allowed

def X87Expr.flagsWithin (allowed : List Nat) : X87Expr -> Bool
  | .inputStack _ | .constant _ => true
  | .load _ address control => address.flagsWithin allowed && control.flagsWithin allowed
  | .imageLoad _ _ control => control.flagsWithin allowed
  | .unary _ value control | .store _ value control =>
      value.flagsWithin allowed && control.flagsWithin allowed
  | .binary _ left right control =>
      left.flagsWithin allowed && right.flagsWithin allowed && control.flagsWithin allowed
end

def Expr.addNormalized (left right : Expr) : Expr :=
  match left, right with
  | expression, .constant 0 => expression
  | .constant 0, expression => expression
  | .constant a, .constant b => .constant ((a + b) % (2 ^ 32))
  | .add expression (.constant a), .constant b =>
      let offset := (a + b) % (2 ^ 32)
      if offset == 0 then expression else .add expression (.constant offset)
  | .sub expression (.constant a), .constant b =>
      let offset := (2 ^ 32 - a + b) % (2 ^ 32)
      if offset == 0 then expression else .add expression (.constant offset)
  | a, b => .add a b

def Expr.subNormalized (left right : Expr) : Expr :=
  match left, right with
  | expression, .constant 0 => expression
  | .constant a, .constant b => .constant ((a + 2 ^ 32 - b) % (2 ^ 32))
  | a, b => .sub a b

def Expr.xorNormalized (left right : Expr) : Expr :=
  if left == right then .constant 0 else .bitXor left right

def Expr.signExtendNormalized (value : Expr) (bits : Nat) : Expr :=
  let mask := 2 ^ bits - 1
  let highMask := 2 ^ 32 - 1 - mask
  .ifEqual (.bitValue value (bits - 1)) (.constant 1)
    (.bitOr (.bitAnd value (.constant mask)) (.constant highMask))
    (.bitAnd value (.constant mask))

structure MachineState where
  registers : Registers Word
  memory : Memory
  undefinedValue : Nat -> Word := fun _ => BitVec.ofNat 32 0
  x87 : X87MachineState := {}
  x87Physical : SpaghettiExtractor.ISA.X87.PhysicalState := SpaghettiExtractor.ISA.X87.initialPhysicalState
  x87Semantics : SpaghettiExtractor.ISA.X87.Semantics := SpaghettiExtractor.ISA.X87.defaultSemantics
  eflags : Word := BitVec.ofNat 32 0
  fsBase : Word := BitVec.ofNat 32 0

structure MachineStateAgreement (allowedFlags : List Nat)
    (original candidate : MachineState) : Prop where
  registers : original.registers = candidate.registers
  memory : original.memory = candidate.memory
  undefinedValue : original.undefinedValue = candidate.undefinedValue
  x87 : original.x87 = candidate.x87
  fsBase : original.fsBase = candidate.fsBase
  flags : ∀ bit, allowedFlags.contains bit = true →
    original.eflags.extractLsb' bit 1 = candidate.eflags.extractLsb' bit 1

def MachineState.read32 (state : MachineState) (address : Word) : Word :=
  let b0 := BitVec.zeroExtend 32 (state.memory address)
  let b1 := (BitVec.zeroExtend 32 (state.memory (address + BitVec.ofNat 32 1))).shiftLeft 8
  let b2 := (BitVec.zeroExtend 32 (state.memory (address + BitVec.ofNat 32 2))).shiftLeft 16
  let b3 := (BitVec.zeroExtend 32 (state.memory (address + BitVec.ofNat 32 3))).shiftLeft 24
  b0 ||| b1 ||| b2 ||| b3

def MachineState.readX87Word (state : MachineState) (address : Word) (size : Nat) : X87Word :=
  (List.range size).foldl (fun result index =>
    result ||| (BitVec.zeroExtend 80 (state.memory (address + BitVec.ofNat 32 index))).shiftLeft (index * 8))
    (BitVec.ofNat 80 0)

def lowestSetBitValue (value : Word) : Nat -> Nat -> Word
  | _, 0 => BitVec.ofNat 32 32
  | index, fuel + 1 =>
      if Nat.testBit value.toNat index then BitVec.ofNat 32 index
      else lowestSetBitValue value (index + 1) fuel

def highestSetBitValue (value : Word) : Nat -> Nat -> Word
  | _, 0 => BitVec.ofNat 32 0
  | index, fuel + 1 =>
      if Nat.testBit value.toNat index then BitVec.ofNat 32 index
      else highestSetBitValue value (index - 1) fuel

def read8AfterWriteValue (address writeAddress writeValue prior : Word) : Word :=
  if address = writeAddress then BitVec.zeroExtend 32 (writeValue.extractLsb' 0 8)
  else if address = writeAddress + BitVec.ofNat 32 1 then
    BitVec.zeroExtend 32 (writeValue.extractLsb' 8 8)
  else if address = writeAddress + BitVec.ofNat 32 2 then
    BitVec.zeroExtend 32 (writeValue.extractLsb' 16 8)
  else if address = writeAddress + BitVec.ofNat 32 3 then
    BitVec.zeroExtend 32 (writeValue.extractLsb' 24 8)
  else prior

mutual
def Expr.eval (state : MachineState) : Expr -> Word
  | .inputReg reg => state.registers.get reg
  | .inputFlagValue bit =>
      if state.eflags.extractLsb' bit 1 == BitVec.ofNat 1 1 then
        BitVec.ofNat 32 1
      else
        BitVec.ofNat 32 0
  | .inputFsBase => state.fsBase
  | .inputX87Control => BitVec.zeroExtend 32 state.x87.control
  | .inputX87Status => BitVec.zeroExtend 32 state.x87.status
  | .constant value => BitVec.ofNat 32 value
  | .add left right => left.eval state + right.eval state
  | .sub left right => left.eval state - right.eval state
  | .bitAnd left right => left.eval state &&& right.eval state
  | .bitXor left right => left.eval state ^^^ right.eval state
  | .bitNot value => ~~~(value.eval state)
  | .read8 address => BitVec.zeroExtend 32 (state.memory (address.eval state))
  | .read32 address => state.read32 (address.eval state)
  | .read8AfterWrite address writeAddress writeValue prior =>
      read8AfterWriteValue (address.eval state) (writeAddress.eval state)
        (writeValue.eval state) (prior.eval state)
  | .extractByte value index => BitVec.zeroExtend 32 ((value.eval state).extractLsb' (index * 8) 8)
  | .shiftLeft value amount => (value.eval state).shiftLeft amount
  | .shiftRight value amount => (value.eval state).ushiftRight amount
  | .shiftLeftBy value amount => (value.eval state).shiftLeft ((amount.eval state).toNat % 32)
  | .shiftRightBy value amount => (value.eval state).ushiftRight ((amount.eval state).toNat % 32)
  | .shiftArithmeticRightBy value amount => (value.eval state).sshiftRight ((amount.eval state).toNat % 32)
  | .bitOr left right => left.eval state ||| right.eval state
  | .ifEqual left right thenValue elseValue =>
      if left.eval state = right.eval state then thenValue.eval state else elseValue.eval state
  | .unsignedLessValue left right =>
      if left.eval state < right.eval state then BitVec.ofNat 32 1 else BitVec.ofNat 32 0
  | .bitValue value index =>
      if Nat.testBit (value.eval state).toNat index then BitVec.ofNat 32 1 else BitVec.ofNat 32 0
  | .multiply left right => left.eval state * right.eval state
  | .multiplyHighUnsigned left right =>
      let product := BitVec.zeroExtend 64 (left.eval state) * BitVec.zeroExtend 64 (right.eval state)
      product.extractLsb' 32 32
  | .multiplyHighSigned left right =>
      let product := BitVec.signExtend 64 (left.eval state) * BitVec.signExtend 64 (right.eval state)
      product.extractLsb' 32 32
  | .divideQuotient high low divisor =>
      let dividend := (BitVec.zeroExtend 64 (high.eval state)).shiftLeft 32 |||
        BitVec.zeroExtend 64 (low.eval state)
      let divisor := BitVec.zeroExtend 64 (divisor.eval state)
      (dividend / divisor).extractLsb' 0 32
  | .divideRemainder high low divisor =>
      let dividend := (BitVec.zeroExtend 64 (high.eval state)).shiftLeft 32 |||
        BitVec.zeroExtend 64 (low.eval state)
      let divisor := BitVec.zeroExtend 64 (divisor.eval state)
      (dividend % divisor).extractLsb' 0 32
  | .divisionValidValue high low divisor =>
      let divisorValue := divisor.eval state
      if divisorValue == BitVec.ofNat 32 0 then BitVec.ofNat 32 0 else
      let dividend := (BitVec.zeroExtend 64 (high.eval state)).shiftLeft 32 |||
        BitVec.zeroExtend 64 (low.eval state)
      let quotient := dividend / BitVec.zeroExtend 64 divisorValue
      if quotient < BitVec.ofNat 64 (2 ^ 32) then BitVec.ofNat 32 1 else BitVec.ofNat 32 0
  | .lowestSetBit value => lowestSetBitValue (value.eval state) 0 32
  | .highestSetBit value => highestSetBitValue (value.eval state) 31 32
  | .undefined slot => state.undefinedValue slot
  | .x87Part value part =>
      let evaluated := value.eval state
      if part == 2 then
        BitVec.zeroExtend 32 (evaluated.extractLsb' 64 16)
      else
        evaluated.extractLsb' (part * 32) 32
  | .x87CompareBit left right control bit =>
      let control := (control.eval state).extractLsb' 0 16
      let compared := state.x87.semantics.compare (left.eval state) (right.eval state) control
      if Nat.testBit compared.toNat bit then BitVec.ofNat 32 1 else BitVec.ofNat 32 0
  | .x87ExamineStatus value status =>
      BitVec.zeroExtend 32 (state.x87.semantics.examine (value.eval state)
        ((status.eval state).extractLsb' 0 16))

def X87Expr.eval (state : MachineState) : X87Expr -> X87Word
  | .inputStack index => state.x87.stack index
  | .load format address control =>
      state.x87.semantics.load format (state.readX87Word (address.eval state) format.byteWidth)
        ((control.eval state).extractLsb' 0 16)
  | .imageLoad format raw control =>
      state.x87.semantics.load format (BitVec.ofNat 80 raw)
        ((control.eval state).extractLsb' 0 16)
  | .constant value => BitVec.ofNat 80 value
  | .unary operation value control =>
      state.x87.semantics.unary operation (value.eval state) ((control.eval state).extractLsb' 0 16)
  | .binary operation left right control =>
      state.x87.semantics.binary operation (left.eval state) (right.eval state)
        ((control.eval state).extractLsb' 0 16)
  | .store format value control =>
      state.x87.semantics.store format (value.eval state) ((control.eval state).extractLsb' 0 16)
end

theorem Expr.eval_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (expression : Expr)
    (within : expression.flagsWithin allowed = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    expression.eval original = expression.eval candidate := by
  rcases agreement with ⟨registers, memory, undefinedValue, x87, fsBase, flags⟩
  have evalAll : ∀ value : Expr, value.flagsWithin allowed = true →
      value.eval original = value.eval candidate := by
    intro value
    apply Expr.rec
      (motive_1 := fun item => item.flagsWithin allowed = true →
        item.eval original = item.eval candidate)
      (motive_2 := fun item => item.flagsWithin allowed = true →
        item.eval original = item.eval candidate) <;>
      simp_all [Expr.flagsWithin, X87Expr.flagsWithin, Expr.eval, X87Expr.eval,
        MachineState.read32, MachineState.readX87Word]
  exact evalAll expression within

theorem X87Expr.eval_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (expression : X87Expr)
    (within : expression.flagsWithin allowed = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    expression.eval original = expression.eval candidate := by
  rcases agreement with ⟨registers, memory, undefinedValue, x87, fsBase, flags⟩
  have evalAll : ∀ value : X87Expr, value.flagsWithin allowed = true →
      value.eval original = value.eval candidate := by
    intro value
    apply X87Expr.rec
      (motive_1 := fun item => item.flagsWithin allowed = true →
        item.eval original = item.eval candidate)
      (motive_2 := fun item => item.flagsWithin allowed = true →
        item.eval original = item.eval candidate) <;>
      simp_all [Expr.flagsWithin, X87Expr.flagsWithin, Expr.eval, X87Expr.eval,
        MachineState.read32, MachineState.readX87Word]
  exact evalAll expression within

inductive BoolExpr where
  | equal (left right : Expr)
  | not (value : BoolExpr)
  | and (left right : BoolExpr)
  | or (left right : BoolExpr)
  | xor (left right : BoolExpr)
  | unsignedLess (left right : Expr)
  | msb (value : Expr)
  | bit (value : Expr) (index : Nat)
  | inputFlag (index : Nat)
  | divisionValid (high low divisor : Expr)
deriving Repr, DecidableEq

def BoolExpr.flagsWithin (allowed : List Nat) : BoolExpr -> Bool
  | .equal left right | .unsignedLess left right =>
      left.flagsWithin allowed && right.flagsWithin allowed
  | .not value => value.flagsWithin allowed
  | .and left right | .or left right | .xor left right =>
      left.flagsWithin allowed && right.flagsWithin allowed
  | .msb value => value.flagsWithin allowed
  | .bit value _ => value.flagsWithin allowed
  | .inputFlag index => allowed.contains index
  | .divisionValid high low divisor =>
      high.flagsWithin allowed && low.flagsWithin allowed && divisor.flagsWithin allowed

def BoolExpr.toWord : BoolExpr -> Expr
  | .equal left right => .ifEqual left right (.constant 1) (.constant 0)
  | .not value => .ifEqual value.toWord (.constant 0) (.constant 1) (.constant 0)
  | .and left right => .bitAnd left.toWord right.toWord
  | .or left right => .bitOr left.toWord right.toWord
  | .xor left right => .bitXor left.toWord right.toWord
  | .unsignedLess left right => .unsignedLessValue left right
  | .msb value => .bitValue value 31
  | .bit value index => .bitValue value index
  | .inputFlag flagIndex => .inputFlagValue flagIndex
  | .divisionValid high low divisor => .divisionValidValue high low divisor

def BoolExpr.eval (state : MachineState) : BoolExpr -> Bool
  | .equal left right => decide (left.eval state = right.eval state)
  | .not value => !(value.eval state)
  | .and left right => left.eval state && right.eval state
  | .or left right => left.eval state || right.eval state
  | .xor left right => left.eval state != right.eval state
  | .unsignedLess left right => decide (left.eval state < right.eval state)
  | .msb value => Nat.testBit (value.eval state).toNat 31
  | .bit value index => Nat.testBit (value.eval state).toNat index
  | .inputFlag flagIndex =>
      state.eflags.extractLsb' flagIndex 1 == BitVec.ofNat 1 1
  | .divisionValid high low divisor =>
      (Expr.divisionValidValue high low divisor).eval state == BitVec.ofNat 32 1

theorem BoolExpr.toWord_eval (state : MachineState) (expression : BoolExpr) :
    expression.toWord.eval state =
      if expression.eval state then BitVec.ofNat 32 1 else BitVec.ofNat 32 0 := by
  induction expression with
  | equal left right =>
      simp [BoolExpr.toWord, BoolExpr.eval, Expr.eval]
  | not value ih =>
      cases evaluated : value.eval state <;>
        simp [BoolExpr.toWord, BoolExpr.eval, Expr.eval, ih, evaluated]
  | and left right leftIH rightIH
  | or left right leftIH rightIH
  | xor left right leftIH rightIH =>
      cases leftEvaluated : left.eval state <;>
        cases rightEvaluated : right.eval state <;>
        simp [BoolExpr.toWord, BoolExpr.eval, Expr.eval, leftIH, rightIH,
          leftEvaluated, rightEvaluated]
  | unsignedLess left right =>
      simp [BoolExpr.toWord, BoolExpr.eval, Expr.eval]
  | msb value =>
      simp [BoolExpr.toWord, BoolExpr.eval, Expr.eval]
  | bit value index =>
      simp [BoolExpr.toWord, BoolExpr.eval, Expr.eval]
  | inputFlag index =>
      simp [BoolExpr.toWord, BoolExpr.eval, Expr.eval]
  | divisionValid high low divisor =>
      simp [BoolExpr.toWord, BoolExpr.eval, Expr.eval]
      split <;> simp_all

theorem BoolExpr.eval_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (expression : BoolExpr)
    (within : expression.flagsWithin allowed = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    expression.eval original = expression.eval candidate := by
  have evalExpr := fun value safe =>
    Expr.eval_eq_of_flagsWithin allowed original candidate value safe agreement
  have evalFlag := agreement.flags
  induction expression <;>
    simp_all [BoolExpr.flagsWithin, BoolExpr.eval]
  case divisionValid high low divisor =>
    have evaluated := evalExpr (.divisionValidValue high low divisor) (by
      simp [Expr.flagsWithin, *])
    exact congrArg (fun value => value == BitVec.ofNat 32 1) evaluated

/-- Agreement on every machine projection consumed by the symbolic expression
language. Physical x87 metadata and the parametric x87 command semantics are
deliberately absent because legacy expressions cannot observe them. -/
structure MachineExpressionAgreement (original candidate : MachineState) : Prop where
  registers : original.registers = candidate.registers
  memory : original.memory = candidate.memory
  undefinedValue : original.undefinedValue = candidate.undefinedValue
  x87 : original.x87 = candidate.x87
  eflags : original.eflags = candidate.eflags
  fsBase : original.fsBase = candidate.fsBase

theorem Expr.eval_eq_of_expressionAgreement (original candidate : MachineState)
    (agreement : MachineExpressionAgreement original candidate) :
    ∀ expression : Expr, expression.eval original = expression.eval candidate := by
  rcases agreement with ⟨registers, memory, undefinedValue, x87, eflags, fsBase⟩
  intro expression
  apply Expr.rec
    (motive_1 := fun item => item.eval original = item.eval candidate)
    (motive_2 := fun item => item.eval original = item.eval candidate) <;>
    simp_all [Expr.eval, X87Expr.eval, MachineState.read32,
      MachineState.readX87Word]

theorem X87Expr.eval_eq_of_expressionAgreement (original candidate : MachineState)
    (agreement : MachineExpressionAgreement original candidate) :
    ∀ expression : X87Expr, expression.eval original = expression.eval candidate := by
  rcases agreement with ⟨registers, memory, undefinedValue, x87, eflags, fsBase⟩
  intro expression
  apply X87Expr.rec
    (motive_1 := fun item => item.eval original = item.eval candidate)
    (motive_2 := fun item => item.eval original = item.eval candidate) <;>
    simp_all [Expr.eval, X87Expr.eval, MachineState.read32,
      MachineState.readX87Word]

theorem BoolExpr.eval_eq_of_expressionAgreement (original candidate : MachineState)
    (agreement : MachineExpressionAgreement original candidate) :
    ∀ expression : BoolExpr, expression.eval original = expression.eval candidate := by
  have evalExpr := Expr.eval_eq_of_expressionAgreement original candidate agreement
  have eflags := agreement.eflags
  intro expression
  induction expression <;> simp_all [BoolExpr.eval]

structure FlagsExpr where
  zero : Option BoolExpr
  carry : Option BoolExpr
  auxiliary : Option BoolExpr := none
  sign : Option BoolExpr
  overflow : Option BoolExpr
  parity : Option BoolExpr
deriving Repr, DecidableEq

def updateFlag (word : Word) (index : Nat) : Option Bool -> Word
  | none => word
  | some value =>
      if value then
        word ||| BitVec.ofNat 32 (2 ^ index)
      else
        word &&& ~~~(BitVec.ofNat 32 (2 ^ index))

def FlagsExpr.eval (state : MachineState) (flags : FlagsExpr) : Word :=
  let carry := updateFlag state.eflags 0 (flags.carry.map (BoolExpr.eval state))
  let parity := updateFlag carry 2 (flags.parity.map (BoolExpr.eval state))
  let auxiliary := updateFlag parity 4 (flags.auxiliary.map (BoolExpr.eval state))
  let zero := updateFlag auxiliary 6 (flags.zero.map (BoolExpr.eval state))
  let sign := updateFlag zero 7 (flags.sign.map (BoolExpr.eval state))
  updateFlag sign 11 (flags.overflow.map (BoolExpr.eval state))

structure RepneScasResult where
  destination : Word
  count : Word
  eflags : Word
deriving Repr, DecidableEq

def evenByteParityWord (value : Word) : Bool :=
  ((List.range 8).countP fun index => Nat.testBit value.toNat index) % 2 == 0

def subtractionByteEflags (initial left right : Word) : Word :=
  let mask := BitVec.ofNat 32 0xff
  let left := left &&& mask
  let right := right &&& mask
  let result := (left - right) &&& mask
  let leftSign := Nat.testBit left.toNat 7
  let rightSign := Nat.testBit right.toNat 7
  let resultSign := Nat.testBit result.toNat 7
  let auxiliary := Nat.testBit (left ^^^ right ^^^ result).toNat 4
  let carry := updateFlag initial 0 (some (left < right))
  let parity := updateFlag carry 2 (some (evenByteParityWord result))
  let auxiliary := updateFlag parity 4 (some auxiliary)
  let zero := updateFlag auxiliary 6 (some (result = BitVec.ofNat 32 0))
  let sign := updateFlag zero 7 (some resultSign)
  updateFlag sign 11 (some ((leftSign != rightSign) && (leftSign != resultSign)))

/-- Concrete flat-memory REPNE SCASB semantics.  The total memory argument is
the no-fault machine profile; fault-capable execution refines this kernel only
after each successful read has committed its iteration. -/
def repneScasByte (memory : Memory) (accumulator destination count eflags : Word)
    (direction : Bool) : Nat -> RepneScasResult
  | 0 => { destination, count, eflags }
  | fuel + 1 =>
      if count = BitVec.ofNat 32 0 then
        { destination, count, eflags }
      else
        let right := BitVec.zeroExtend 32 (memory destination)
        let nextEflags := subtractionByteEflags eflags accumulator right
        let step := if direction then BitVec.ofNat 32 0xffffffff else BitVec.ofNat 32 1
        let nextDestination := destination + step
        let nextCount := count - BitVec.ofNat 32 1
        if (accumulator &&& BitVec.ofNat 32 0xff) = right then
          { destination := nextDestination, count := nextCount, eflags := nextEflags }
        else
          repneScasByte memory accumulator nextDestination nextCount nextEflags
            direction fuel

theorem updateFlag_extract_preserved (word : Word) (updated observed : Nat)
    (value : Option Bool)
    (setMask : (BitVec.ofNat 32 (2 ^ updated)).extractLsb' observed 1 = 0#1)
    (clearMask : (~~~(BitVec.ofNat 32 (2 ^ updated))).extractLsb' observed 1 =
      BitVec.allOnes 1) :
    (updateFlag word updated value).extractLsb' observed 1 =
      word.extractLsb' observed 1 := by
  cases value with
  | none => rfl
  | some value =>
      cases value with
      | false =>
          change (word &&& ~~~(BitVec.ofNat 32 (2 ^ updated))).extractLsb' observed 1 = _
          rw [BitVec.extractLsb'_and, clearMask, BitVec.and_allOnes]
      | true =>
          change (word ||| BitVec.ofNat 32 (2 ^ updated)).extractLsb' observed 1 = _
          rw [BitVec.extractLsb'_or, setMask, BitVec.or_zero]

@[simp] theorem updateFlag_extract_df_cf (word : Word) (value : Option Bool) :
    (updateFlag word 0 value).extractLsb' 10 1 =
      word.extractLsb' 10 1 :=
  updateFlag_extract_preserved word 0 10 value (by decide) (by decide)

@[simp] theorem updateFlag_extract_df_pf (word : Word) (value : Option Bool) :
    (updateFlag word 2 value).extractLsb' 10 1 =
      word.extractLsb' 10 1 :=
  updateFlag_extract_preserved word 2 10 value (by decide) (by decide)

@[simp] theorem updateFlag_extract_df_af (word : Word) (value : Option Bool) :
    (updateFlag word 4 value).extractLsb' 10 1 =
      word.extractLsb' 10 1 :=
  updateFlag_extract_preserved word 4 10 value (by decide) (by decide)

@[simp] theorem updateFlag_extract_df_zf (word : Word) (value : Option Bool) :
    (updateFlag word 6 value).extractLsb' 10 1 =
      word.extractLsb' 10 1 :=
  updateFlag_extract_preserved word 6 10 value (by decide) (by decide)

@[simp] theorem updateFlag_extract_df_sf (word : Word) (value : Option Bool) :
    (updateFlag word 7 value).extractLsb' 10 1 =
      word.extractLsb' 10 1 :=
  updateFlag_extract_preserved word 7 10 value (by decide) (by decide)

@[simp] theorem updateFlag_extract_df_of (word : Word) (value : Option Bool) :
    (updateFlag word 11 value).extractLsb' 10 1 =
      word.extractLsb' 10 1 :=
  updateFlag_extract_preserved word 11 10 value (by decide) (by decide)

theorem updateFlag_extract_assigned (word : Word) (index : Nat) (value : Option Bool)
    (setMask : (BitVec.ofNat 32 (2 ^ index)).extractLsb' index 1 = BitVec.allOnes 1)
    (clearMask : (~~~(BitVec.ofNat 32 (2 ^ index))).extractLsb' index 1 = 0#1) :
    (updateFlag word index value).extractLsb' index 1 =
      match value with
      | none => word.extractLsb' index 1
      | some false => 0#1
      | some true => BitVec.allOnes 1 := by
  cases value with
  | none => rfl
  | some value =>
      cases value with
      | false =>
          change (word &&& ~~~(BitVec.ofNat 32 (2 ^ index))).extractLsb' index 1 = 0#1
          rw [BitVec.extractLsb'_and, clearMask, BitVec.and_zero]
      | true =>
          change (word ||| BitVec.ofNat 32 (2 ^ index)).extractLsb' index 1 =
            BitVec.allOnes 1
          rw [BitVec.extractLsb'_or, setMask, BitVec.or_allOnes]

def evalFlagBit (state : MachineState) (index : Nat) : Option BoolExpr -> BitVec 1
  | none => state.eflags.extractLsb' index 1
  | some value => if value.eval state then BitVec.allOnes 1 else 0#1

def flagValueWithin (allowed : List Nat) (index : Nat) : Option BoolExpr -> Bool
  | none => allowed.contains index
  | some value => value.flagsWithin allowed

theorem evalFlagBit_eq_of_flagsWithin (allowed : List Nat) (index : Nat)
    (original candidate : MachineState) (value : Option BoolExpr)
    (within : flagValueWithin allowed index value = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    evalFlagBit original index value = evalFlagBit candidate index value := by
  cases value with
  | none =>
      simpa [flagValueWithin, evalFlagBit] using agreement.flags index within
  | some expression =>
      have evaluated := BoolExpr.eval_eq_of_flagsWithin allowed original candidate
        expression within agreement
      simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_cf (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 0 1 = evalFlagBit state 0 flags.carry := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 0 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 0 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 0 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 0 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 0 _ (by decide) (by decide)]
  rw [updateFlag_extract_assigned _ 0 _ (by decide) (by decide)]
  cases carry : flags.carry with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_pf (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 2 1 = evalFlagBit state 2 flags.parity := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 2 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 2 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 2 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 2 _ (by decide) (by decide)]
  rw [updateFlag_extract_assigned _ 2 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 2 _ (by decide) (by decide)]
  cases parity : flags.parity with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_af (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 4 1 = evalFlagBit state 4 flags.auxiliary := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 4 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 4 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 4 _ (by decide) (by decide)]
  rw [updateFlag_extract_assigned _ 4 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 4 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 4 _ (by decide) (by decide)]
  cases auxiliary : flags.auxiliary with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_zf (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 6 1 = evalFlagBit state 6 flags.zero := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 6 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 6 _ (by decide) (by decide)]
  rw [updateFlag_extract_assigned _ 6 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 6 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 6 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 6 _ (by decide) (by decide)]
  cases zero : flags.zero with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_sf (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 7 1 = evalFlagBit state 7 flags.sign := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 7 _ (by decide) (by decide)]
  rw [updateFlag_extract_assigned _ 7 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 7 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 7 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 7 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 7 _ (by decide) (by decide)]
  cases sign : flags.sign with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_df (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 10 1 = state.eflags.extractLsb' 10 1 := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 10 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 10 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 10 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 10 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 10 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 10 _ (by decide) (by decide)]

@[simp] theorem FlagsExpr.eval_extract_of (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 11 1 = evalFlagBit state 11 flags.overflow := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_assigned _ 11 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 11 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 11 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 11 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 11 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 11 _ (by decide) (by decide)]
  cases overflow : flags.overflow with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

theorem FlagsExpr.eval_cf_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 0 flags.carry = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 0 1 = (flags.eval candidate).extractLsb' 0 1 := by
  simpa only [FlagsExpr.eval_extract_cf] using
    evalFlagBit_eq_of_flagsWithin allowed 0 original candidate flags.carry within agreement

theorem FlagsExpr.eval_pf_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 2 flags.parity = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 2 1 = (flags.eval candidate).extractLsb' 2 1 := by
  simpa only [FlagsExpr.eval_extract_pf] using
    evalFlagBit_eq_of_flagsWithin allowed 2 original candidate flags.parity within agreement

theorem FlagsExpr.eval_af_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 4 flags.auxiliary = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 4 1 = (flags.eval candidate).extractLsb' 4 1 := by
  simpa only [FlagsExpr.eval_extract_af] using
    evalFlagBit_eq_of_flagsWithin allowed 4 original candidate flags.auxiliary within agreement

theorem FlagsExpr.eval_zf_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 6 flags.zero = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 6 1 = (flags.eval candidate).extractLsb' 6 1 := by
  simpa only [FlagsExpr.eval_extract_zf] using
    evalFlagBit_eq_of_flagsWithin allowed 6 original candidate flags.zero within agreement

theorem FlagsExpr.eval_sf_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 7 flags.sign = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 7 1 = (flags.eval candidate).extractLsb' 7 1 := by
  simpa only [FlagsExpr.eval_extract_sf] using
    evalFlagBit_eq_of_flagsWithin allowed 7 original candidate flags.sign within agreement

theorem FlagsExpr.eval_df_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : allowed.contains 10 = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 10 1 = (flags.eval candidate).extractLsb' 10 1 := by
  simpa only [FlagsExpr.eval_extract_df] using agreement.flags 10 within

theorem FlagsExpr.eval_of_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 11 flags.overflow = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 11 1 = (flags.eval candidate).extractLsb' 11 1 := by
  simpa only [FlagsExpr.eval_extract_of] using
    evalFlagBit_eq_of_flagsWithin allowed 11 original candidate flags.overflow within agreement

structure SymbolicX87State where
  stack : List X87Expr
  control : Expr
  status : Expr
deriving Repr, DecidableEq

def initialSymbolicX87 : SymbolicX87State := {
  stack := (List.range 8).map X87Expr.inputStack
  control := .inputX87Control
  status := .inputX87Status
}

def SymbolicX87State.get (state : SymbolicX87State) (index : Nat) : Option X87Expr :=
  (state.stack.drop index).head?

def SymbolicX87State.set (state : SymbolicX87State) (index : Nat) (value : X87Expr) : Option SymbolicX87State :=
  if index < state.stack.length then
    some { state with stack := (state.stack.take index) ++ [value] ++ (state.stack.drop (index + 1)) }
  else
    none

def SymbolicX87State.push (state : SymbolicX87State) (value : X87Expr) : SymbolicX87State :=
  { state with stack := value :: state.stack }

def SymbolicX87State.pop (state : SymbolicX87State) : Option SymbolicX87State := do
  let _ <- state.stack.head?
  pure { state with stack := state.stack.drop 1 }

def parityExpression (result : Expr) : BoolExpr :=
  .not (.xor (.bit result 0)
    (.xor (.bit result 1)
      (.xor (.bit result 2)
        (.xor (.bit result 3)
          (.xor (.bit result 4)
            (.xor (.bit result 5) (.xor (.bit result 6) (.bit result 7))))))))

def auxiliaryCarryExpression (left right result : Expr) : BoolExpr :=
  .bit (.bitXor (.bitXor left right) result) 4

def subtractionFlags (left right result : Expr) : FlagsExpr := {
  zero := some (.equal result (.constant 0))
  carry := some (.unsignedLess left right)
  auxiliary := some (auxiliaryCarryExpression left right result)
  sign := some (.msb result)
  overflow := some (.and (.xor (.msb left) (.msb right)) (.xor (.msb left) (.msb result)))
  parity := some (parityExpression result)
}

def additionFlags (left right result : Expr) : FlagsExpr := {
  zero := some (.equal result (.constant 0))
  carry := some (.unsignedLess result left)
  auxiliary := some (auxiliaryCarryExpression left right result)
  sign := some (.msb result)
  overflow := some (.and (.not (.xor (.msb left) (.msb right))) (.xor (.msb left) (.msb result)))
  parity := some (parityExpression result)
}

def logicalFlags (undefinedSlot : Nat) (result : Expr) : FlagsExpr := {
  zero := some (.equal result (.constant 0))
  carry := some (.equal (.constant 0) (.constant 1))
  auxiliary := some (.bit (.undefined undefinedSlot) 0)
  sign := some (.msb result)
  overflow := some (.equal (.constant 0) (.constant 1))
  parity := some (parityExpression result)
}

def subtractionFlagsWidth (bits : Nat) (left right result : Expr) : FlagsExpr :=
  let mask := .constant (2 ^ bits - 1)
  let left := .bitAnd left mask
  let right := .bitAnd right mask
  let result := .bitAnd result mask
  {
    zero := some (.equal result (.constant 0))
    carry := some (.unsignedLess left right)
    auxiliary := some (auxiliaryCarryExpression left right result)
    sign := some (.bit result (bits - 1))
    overflow := some (.and (.xor (.bit left (bits - 1)) (.bit right (bits - 1)))
      (.xor (.bit left (bits - 1)) (.bit result (bits - 1))))
    parity := some (parityExpression result)
  }

def additionFlagsWidth (bits : Nat) (left right result : Expr) : FlagsExpr :=
  let mask := .constant (2 ^ bits - 1)
  let left := .bitAnd left mask
  let right := .bitAnd right mask
  let result := .bitAnd result mask
  {
    zero := some (.equal result (.constant 0))
    carry := some (.unsignedLess result left)
    auxiliary := some (auxiliaryCarryExpression left right result)
    sign := some (.bit result (bits - 1))
    overflow := some (.and (.not (.xor (.bit left (bits - 1)) (.bit right (bits - 1))))
      (.xor (.bit left (bits - 1)) (.bit result (bits - 1))))
    parity := some (parityExpression result)
  }

def logicalFlagsWidth (undefinedSlot bits : Nat) (result : Expr) : FlagsExpr :=
  let result := .bitAnd result (.constant (2 ^ bits - 1))
  {
    zero := some (.equal result (.constant 0))
    carry := some (.equal (.constant 0) (.constant 1))
    auxiliary := some (.bit (.undefined undefinedSlot) 0)
    sign := some (.bit result (bits - 1))
    overflow := some (.equal (.constant 0) (.constant 1))
    parity := some (parityExpression result)
  }

def undefinedArithmeticFlags (undefinedSlot : Nat) : FlagsExpr := {
  zero := some (.bit (.undefined undefinedSlot) 0)
  carry := some (.bit (.undefined undefinedSlot) 1)
  auxiliary := some (.bit (.undefined undefinedSlot) 2)
  sign := some (.bit (.undefined undefinedSlot) 3)
  overflow := some (.bit (.undefined undefinedSlot) 4)
  parity := some (.bit (.undefined undefinedSlot) 5)
}

def multiplicationFlags (undefinedSlot : Nat) (overflow : BoolExpr) : FlagsExpr := {
  zero := some (.bit (.undefined undefinedSlot) 0)
  carry := some overflow
  auxiliary := some (.bit (.undefined undefinedSlot) 1)
  sign := some (.bit (.undefined undefinedSlot) 2)
  overflow := some overflow
  parity := some (.bit (.undefined undefinedSlot) 3)
}

def adcFlags (left right result : Expr) (carryIn : BoolExpr) : FlagsExpr := {
  zero := some (.equal result (.constant 0))
  carry := some (.or (.unsignedLess result left) (.and carryIn (.equal result left)))
  auxiliary := some (auxiliaryCarryExpression left right result)
  sign := some (.msb result)
  overflow := some (.and (.not (.xor (.msb left) (.msb right))) (.xor (.msb left) (.msb result)))
  parity := some (parityExpression result)
}

def sbbFlags (left right result : Expr) (borrowIn : BoolExpr) : FlagsExpr := {
  zero := some (.equal result (.constant 0))
  carry := some (.or (.unsignedLess left right) (.and borrowIn (.equal left right)))
  auxiliary := some (auxiliaryCarryExpression left right result)
  sign := some (.msb result)
  overflow := some (.and (.xor (.msb left) (.msb right)) (.xor (.msb left) (.msb result)))
  parity := some (parityExpression result)
}

structure BulkCopyExpr where
  destination : Expr
  source : Expr
  count : Expr
  direction : BoolExpr
  elementBytes : Nat
deriving Repr, DecidableEq

structure BulkFillExpr where
  destination : Expr
  value : Expr
  count : Expr
  direction : BoolExpr
  elementBytes : Nat
deriving Repr, DecidableEq

structure BulkScanExpr where
  destination : Expr
  accumulator : Expr
  count : Expr
  direction : BoolExpr
deriving Repr, DecidableEq

inductive OutcomeExpr where
  | returned (target : Expr)
  | jump (targetRva : Nat)
  | branch (condition : BoolExpr) (trueTargetRva falseTargetRva : Nat)
  | call (targetRva returnRva returnAddress : Nat)
  | externalCall (imported : PEImport) (arguments : List Expr) (returnRva : Nat)
  | externalJump (imported : PEImport) (arguments : List Expr)
  | bulkCopy (copy : BulkCopyExpr) (continuationRva : Nat)
  | bulkFill (fill : BulkFillExpr) (continuationRva : Nat)
  | bulkScan (scan : BulkScanExpr) (continuationRva : Nat)
  | indirectCall (target : Expr) (continuationRva returnAddress : Nat)
  | indirectJump (target : Expr)
  | checkedContinue (valid : BoolExpr) (continuationRva : Nat)
  | atomicCompareExchange (address expected replacement : Expr) (continuationRva : Nat)
deriving Repr, DecidableEq

structure SymbolicBehavior where
  registers : Registers Expr
  x87 : SymbolicX87State
  writes : List (Expr × Expr)
  comparison : Option (Expr × Expr)
  flagsBase : Option Expr := none
  flags : Option FlagsExpr
  outcome : Option OutcomeExpr
deriving Repr, DecidableEq

structure ConcreteX87State where
  stack : List X87Word
  control : BitVec 16
  status : BitVec 16
deriving Repr, DecidableEq

inductive ConcreteOutcome where
  | returned (target : Word)
  | jump (targetRva : Nat)
  | branch (condition : Bool) (trueTargetRva falseTargetRva : Nat)
  | call (targetRva returnRva returnAddress : Nat)
  | externalCall (imported : PEImport) (arguments : List Word) (returnRva : Nat)
  | externalJump (imported : PEImport) (arguments : List Word)
  | bulkCopy (destination source count : Word) (direction : Bool)
      (elementBytes continuationRva : Nat)
  | bulkFill (destination value count : Word) (direction : Bool)
      (elementBytes continuationRva : Nat)
  | bulkScan (accumulator destination count : Word) (direction : Bool)
      (continuationRva : Nat)
  | indirectCall (target : Word) (continuationRva returnAddress : Nat)
  | indirectJump (target : Word)
  | checkedContinue (valid : Bool) (continuationRva : Nat)
  | atomicCompareExchange (address expected replacement : Word) (continuationRva : Nat)

structure ConcreteBehavior where
  registers : Registers Word
  x87 : ConcreteX87State
  memory : Memory
  eflags : Word
  outcome : Option ConcreteOutcome

def initialSymbolic : SymbolicBehavior := {
  registers := {
    eax := .inputReg .eax,
    ebx := .inputReg .ebx,
    ecx := .inputReg .ecx,
    edx := .inputReg .edx,
    esi := .inputReg .esi,
    edi := .inputReg .edi,
    ebp := .inputReg .ebp,
    esp := .inputReg .esp,
  },
  x87 := initialSymbolicX87,
  writes := [],
  comparison := none,
  flags := some {
    zero := some (.inputFlag 6)
    carry := some (.inputFlag 0)
    sign := some (.inputFlag 7)
    overflow := some (.inputFlag 11)
    parity := some (.inputFlag 2)
  },
  outcome := none,
}

def inputEflagsExpression : Expr :=
  (List.range 32).foldl
    (fun value index =>
      .bitOr value (.shiftLeft (.inputFlagValue index) index))
    (.constant 0)

private theorem conditionalUnit_getElem_zero (condition : Prop)
    [Decidable condition] :
    (if condition then BitVec.ofNat 32 1 else BitVec.ofNat 32 0)[0] =
      decide condition := by
  split <;> simp_all

private theorem conditionalUnit_getElem_ne_zero (condition : Prop)
    [Decidable condition] (index : Nat) (bounded : index < 32)
    (nonzero : index ≠ 0) :
    (if condition then BitVec.ofNat 32 1 else BitVec.ofNat 32 0)[index] =
      false := by
  split
  · rw [BitVec.getElem_eq_testBit_toNat]
    apply Bool.eq_false_iff.mpr
    intro bitSet
    exact nonzero
      (Nat.testBit_one_eq_true_iff_self_eq_zero.mp bitSet)
  · exact BitVec.getElem_zero_ofNat_zero index bounded

-- Reify the concrete EFLAGS word once in the stable machine kernel.  Symbolic
-- instruction proofs consume this theorem instead of re-evaluating the
-- 32-element expression fold.
set_option maxHeartbeats 1000000 in
@[simp] theorem inputEflagsExpression_eval (input : MachineState) :
    inputEflagsExpression.eval input = input.eflags := by
  have rangeExact :
      List.range 32 =
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
          16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31] := by
    decide
  apply BitVec.eq_of_getElem_eq
  intro index bounded
  have possible :
      index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 ∨
      index = 4 ∨ index = 5 ∨ index = 6 ∨ index = 7 ∨
      index = 8 ∨ index = 9 ∨ index = 10 ∨ index = 11 ∨
      index = 12 ∨ index = 13 ∨ index = 14 ∨ index = 15 ∨
      index = 16 ∨ index = 17 ∨ index = 18 ∨ index = 19 ∨
      index = 20 ∨ index = 21 ∨ index = 22 ∨ index = 23 ∨
      index = 24 ∨ index = 25 ∨ index = 26 ∨ index = 27 ∨
      index = 28 ∨ index = 29 ∨ index = 30 ∨ index = 31 := by
    omega
  rcases possible with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp [inputEflagsExpression, rangeExact, Expr.eval,
      conditionalUnit_getElem_zero, conditionalUnit_getElem_ne_zero,
      ← BitVec.getElem_eq_extractLsb']

@[simp] theorem inputEflagsExpression_eval_extract_df (state : MachineState) :
    (inputEflagsExpression.eval state).extractLsb' 10 1 =
      state.eflags.extractLsb' 10 1 := by
  simpa only [inputEflagsExpression_eval]

def updateFlagExpression (word : Expr) (index : Nat) :
    Option BoolExpr -> Expr
  | none => word
  | some value =>
      .bitOr
        (.bitAnd word (.constant (2 ^ 32 - 1 - 2 ^ index)))
        (.shiftLeft value.toWord index)

def FlagsExpr.applyToExpression (flags : FlagsExpr) (base : Expr) : Expr :=
  let carry := updateFlagExpression base 0 flags.carry
  let parity := updateFlagExpression carry 2 flags.parity
  let auxiliary := updateFlagExpression parity 4 flags.auxiliary
  let zero := updateFlagExpression auxiliary 6 flags.zero
  let sign := updateFlagExpression zero 7 flags.sign
  updateFlagExpression sign 11 flags.overflow

theorem updateFlagExpression_eval_extract_preserved
    (state : MachineState) (word : Expr) (updated observed : Nat)
    (value : Option BoolExpr)
    (clearMask :
      (BitVec.ofNat 32 (2 ^ 32 - 1 - 2 ^ updated)).extractLsb' observed 1 =
        BitVec.allOnes 1)
    (setMask :
      ((BitVec.ofNat 32 1).shiftLeft updated).extractLsb' observed 1 = 0#1) :
    ((updateFlagExpression word updated value).eval state).extractLsb' observed 1 =
      (word.eval state).extractLsb' observed 1 := by
  cases value with
  | none => rfl
  | some expression =>
      have setMask' :
          ((BitVec.ofNat 32 1) <<< updated).extractLsb' observed 1 = 0#1 := by
        simpa using setMask
      cases evaluated : expression.eval state <;>
        simp [updateFlagExpression, Expr.eval, BoolExpr.toWord_eval, evaluated,
          BitVec.extractLsb'_and, BitVec.extractLsb'_or, clearMask, setMask',
          BitVec.or_zero] <;> bv_decide

@[simp] theorem FlagsExpr.applyToExpression_eval_extract_df
    (state : MachineState) (flags : FlagsExpr) (base : Expr) :
    ((flags.applyToExpression base).eval state).extractLsb' 10 1 =
      (base.eval state).extractLsb' 10 1 := by
  unfold FlagsExpr.applyToExpression
  rw [updateFlagExpression_eval_extract_preserved _ _ 11 10 _
    (by decide) (by decide)]
  rw [updateFlagExpression_eval_extract_preserved _ _ 7 10 _
    (by decide) (by decide)]
  rw [updateFlagExpression_eval_extract_preserved _ _ 6 10 _
    (by decide) (by decide)]
  rw [updateFlagExpression_eval_extract_preserved _ _ 4 10 _
    (by decide) (by decide)]
  rw [updateFlagExpression_eval_extract_preserved _ _ 2 10 _
    (by decide) (by decide)]
  rw [updateFlagExpression_eval_extract_preserved _ _ 0 10 _
    (by decide) (by decide)]

theorem updateFlagExpression_eval_extract_assigned
    (state : MachineState) (word : Expr) (index : Nat)
    (value : BoolExpr)
    (clearMask :
      (BitVec.ofNat 32 (2 ^ 32 - 1 - 2 ^ index)).extractLsb' index 1 = 0#1)
    (setMask :
      ((BitVec.ofNat 32 1).shiftLeft index).extractLsb' index 1 =
        BitVec.allOnes 1) :
    ((updateFlagExpression word index (some value)).eval state).extractLsb' index 1 =
      if value.eval state then BitVec.ofNat 1 1 else BitVec.ofNat 1 0 := by
  have setMask' :
      ((BitVec.ofNat 32 1) <<< index).extractLsb' index 1 =
        BitVec.allOnes 1 := by
    simpa using setMask
  cases evaluated : value.eval state <;>
    simp [updateFlagExpression, Expr.eval, BoolExpr.toWord_eval, evaluated,
      BitVec.extractLsb'_and, BitVec.extractLsb'_or, clearMask, setMask',
      BitVec.and_zero, BitVec.zero_or]

theorem FlagsExpr.applyToExpression_extract_zero_of_assigned
    (state : MachineState) (flags : FlagsExpr) (base : Expr)
    (zeroValue : BoolExpr) (zeroExact : flags.zero = some zeroValue) :
    ((flags.applyToExpression base).eval state).extractLsb' 6 1 =
      if zeroValue.eval state then BitVec.ofNat 1 1 else BitVec.ofNat 1 0 := by
  unfold FlagsExpr.applyToExpression
  rw [updateFlagExpression_eval_extract_preserved _ _ 11 6 _
    (by decide) (by decide)]
  rw [updateFlagExpression_eval_extract_preserved _ _ 7 6 _
    (by decide) (by decide)]
  rw [zeroExact]
  rw [updateFlagExpression_eval_extract_assigned _ _ 6 _
    (by decide) (by decide)]

theorem subtractionFlags_applyToExpression_extract_zero
    (state : MachineState) (base left right result : Expr) :
    (((subtractionFlags left right result).applyToExpression base).eval state
      ).extractLsb' 6 1 =
      if result.eval state = BitVec.ofNat 32 0 then
        BitVec.ofNat 1 1
      else
        BitVec.ofNat 1 0 := by
  have assigned :=
    FlagsExpr.applyToExpression_extract_zero_of_assigned state
      (subtractionFlags left right result) base
      (.equal result (.constant 0)) rfl
  simpa [BoolExpr.eval, Expr.eval] using assigned

def SymbolicBehavior.eflagsExpression (behavior : SymbolicBehavior) : Expr :=
  let base := behavior.flagsBase.getD inputEflagsExpression
  behavior.flags.map (fun flags => flags.applyToExpression base) |>.getD base

@[simp] theorem SymbolicBehavior.eflagsExpression_eval_extract_df
    (state : MachineState) (behavior : SymbolicBehavior) :
    (behavior.eflagsExpression.eval state).extractLsb' 10 1 =
      ((behavior.flagsBase.getD inputEflagsExpression).eval state).extractLsb'
        10 1 := by
  unfold SymbolicBehavior.eflagsExpression
  cases behavior.flags <;> simp

@[simp] theorem initialSymbolic_eflagsExpression_eval_extract_df
    (state : MachineState) :
    (initialSymbolic.eflagsExpression.eval state).extractLsb' 10 1 =
      state.eflags.extractLsb' 10 1 := by
  simp [SymbolicBehavior.eflagsExpression, initialSymbolic]

def popFlagsCpl3Expression (current popped : Expr) : Expr :=
  let writableMask := 0x00244dd5
  let preservedMask := 2 ^ 32 - 1 - writableMask
  let updated :=
    .bitOr (.bitAnd popped (.constant writableMask))
      (.bitAnd current (.constant preservedMask))
  let currentIopl := .bitAnd (.shiftRight current 12) (.constant 3)
  let interrupt :=
    .ifEqual currentIopl (.constant 3)
      (.bitValue popped 9) (.bitValue current 9)
  let withInterrupt := updateFlagExpression updated 9
    (some (.equal interrupt (.constant 1)))
  .bitAnd withInterrupt (.constant 0xfffeffff)

def flagsFromWordExpression (word : Expr) : FlagsExpr := {
  carry := some (.bit word 0)
  parity := some (.bit word 2)
  auxiliary := some (.bit word 4)
  zero := some (.bit word 6)
  sign := some (.bit word 7)
  overflow := some (.bit word 11)
}

def Memory.write32 (memory : Memory) (address value : Word) : Memory :=
  fun query =>
    if query = address then value.extractLsb' 0 8
    else if query = address + BitVec.ofNat 32 1 then value.extractLsb' 8 8
    else if query = address + BitVec.ofNat 32 2 then value.extractLsb' 16 8
    else if query = address + BitVec.ofNat 32 3 then value.extractLsb' 24 8
    else memory query

def Memory.readElement (memory : Memory) (elementBytes : Nat)
    (address : Word) : Word :=
  let byte0 := BitVec.zeroExtend 32 (memory address)
  let byte1 := BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 1))
  match elementBytes with
  | 1 => byte0
  | 2 => byte0 ||| byte1.shiftLeft 8
  | _ =>
      let byte2 := BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 2))
      let byte3 := BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 3))
      byte0 ||| byte1.shiftLeft 8 ||| byte2.shiftLeft 16 ||| byte3.shiftLeft 24

def Memory.writeElement (memory : Memory) (elementBytes : Nat)
    (address value : Word) : Memory :=
  match elementBytes with
  | 1 => fun query =>
      if query = address then value.extractLsb' 0 8 else memory query
  | 2 => fun query =>
      if query = address then value.extractLsb' 0 8
      else if query = address + BitVec.ofNat 32 1 then value.extractLsb' 8 8
      else memory query
  | _ => memory.write32 address value

def Memory.bulkFillElements (memory : Memory) (elementBytes : Nat)
    (destination value : Word) (direction : Bool) : Nat -> Memory
  | 0 => memory
  | count + 1 =>
      let nextMemory := memory.writeElement elementBytes destination value
      let distance := BitVec.ofNat 32 elementBytes
      let nextDestination :=
        if direction then destination - distance else destination + distance
      Memory.bulkFillElements nextMemory elementBytes nextDestination value
        direction count

def Memory.bulkFillDwords (memory : Memory) (destination value : Word)
    (direction : Bool) : Nat -> Memory
  | count => memory.bulkFillElements 4 destination value direction count

def applyWrites (state : MachineState) (writes : List (Expr × Expr)) : Memory :=
  writes.foldl (fun memory write => memory.write32 (write.1.eval state) (write.2.eval state)) state.memory

def Expr.offset (address : Expr) (amount : Nat) : Expr :=
  Expr.addNormalized address (.constant amount)

def Expr.affineBaseOffset : Expr -> Expr × Nat
  | .add base (.constant offset) => (base, offset % (2 ^ 32))
  | .sub base (.constant offset) => (base, (2 ^ 32 - offset) % (2 ^ 32))
  | expression => (expression, 0)

def Expr.provablyUnequal (left right : Expr) : Bool :=
  let leftAffine := left.affineBaseOffset
  let rightAffine := right.affineBaseOffset
  leftAffine.1 == rightAffine.1 && leftAffine.2 != rightAffine.2

/-- Prove that two four-byte writes share no byte address.  The check only
accepts equal symbolic affine bases with distinct normalized offsets; every
other address relation remains unknown. -/
def wordWriteAddressesProvablyDisjoint (left right : Expr) : Bool :=
  (List.range 4).all fun leftOffset =>
    (List.range 4).all fun rightOffset =>
      (left.offset leftOffset).provablyUnequal (right.offset rightOffset)

/-- Find the latest exact-address word write when every subsequent write is
provably disjoint from that word. -/
def exactWrite32WithDisjointTail? (address : Expr) :
    List (Expr × Expr) -> Option Expr
  | [] => none
  | write :: tail =>
      match exactWrite32WithDisjointTail? address tail with
      | some value => some value
      | none =>
          if write.1 == address &&
              tail.all fun later =>
                wordWriteAddressesProvablyDisjoint address later.1 then
            some write.2
          else
            none

def symbolicRead8 (behavior : SymbolicBehavior) (address : Expr) : Expr :=
  behavior.writes.foldl (fun current write =>
    let offsets := [0, 1, 2, 3]
    match offsets.find? (fun index => address == write.1.offset index) with
    | some index => .extractByte write.2 index
    | none =>
        if offsets.all (fun index => address.provablyUnequal (write.1.offset index)) then current
        else .read8AfterWrite address write.1 write.2 current) (.read8 address)

def symbolicRead32 (behavior : SymbolicBehavior) (address : Expr) : Expr :=
  match exactWrite32WithDisjointTail? address behavior.writes with
  | some value => value
  | none =>
      if behavior.writes.all fun write =>
          wordWriteAddressesProvablyDisjoint address write.1 then
        .read32 address
      else
        let b0 := symbolicRead8 behavior address
        let b1 := .shiftLeft (symbolicRead8 behavior (address.offset 1)) 8
        let b2 := .shiftLeft (symbolicRead8 behavior (address.offset 2)) 16
        let b3 := .shiftLeft (symbolicRead8 behavior (address.offset 3)) 24
        .bitOr (.bitOr b0 b1) (.bitOr b2 b3)

def symbolicRead16 (behavior : SymbolicBehavior) (address : Expr) : Expr :=
  let b0 := symbolicRead8 behavior address
  let b1 := .shiftLeft (symbolicRead8 behavior (address.offset 1)) 8
  .bitOr b0 b1

/-- Append a completed word write in the total-memory static analysis profile.

An exact later word write fully overwrites earlier writes at the same symbolic
address.  Writing the initial word value restores memory only when every
retained write is provably disjoint.  Unknown overlap is kept explicit.  This
canonicalization preserves `SymbolicBehavior.eval`; it does not claim that
removed machine accesses have the same fault trace on a partial memory model. -/
def SymbolicBehavior.write32 (behavior : SymbolicBehavior) (address value : Expr) : SymbolicBehavior :=
  let retained := behavior.writes.filter fun write => write.1 != address
  if value == .read32 address &&
      retained.all fun write => wordWriteAddressesProvablyDisjoint address write.1 then
    { behavior with writes := retained }
  else
    { behavior with writes := retained ++ [(address, value)] }

def SymbolicBehavior.eval (behavior : SymbolicBehavior)
    (state : MachineState) : ConcreteBehavior :=
  let memory := applyWrites state behavior.writes
  {
  registers := {
    eax := behavior.registers.eax.eval state,
    ebx := behavior.registers.ebx.eval state,
    ecx := behavior.registers.ecx.eval state,
    edx := behavior.registers.edx.eval state,
    esi := behavior.registers.esi.eval state,
    edi := behavior.registers.edi.eval state,
    ebp := behavior.registers.ebp.eval state,
    esp := behavior.registers.esp.eval state,
  },
  x87 := {
    stack := behavior.x87.stack.map (X87Expr.eval state)
    control := (behavior.x87.control.eval state).extractLsb' 0 16
    status := (behavior.x87.status.eval state).extractLsb' 0 16
  },
  memory,
  eflags :=
    match behavior.flagsBase, behavior.flags with
    | none, none => state.eflags
    | none, some flags => flags.eval state
    | some base, none => base.eval state
    | some base, some flags => (flags.applyToExpression base).eval state
  outcome := behavior.outcome.map (fun outcome =>
    match outcome with
    | .returned target => .returned (target.eval state)
    | .jump targetRva => .jump targetRva
    | .branch condition trueTargetRva falseTargetRva =>
        .branch (condition.eval state) trueTargetRva falseTargetRva
    | .call targetRva returnRva returnAddress => .call targetRva returnRva returnAddress
    | .externalCall imported arguments returnRva =>
        .externalCall imported (arguments.map (Expr.eval state)) returnRva
    | .externalJump imported arguments =>
        .externalJump imported (arguments.map (Expr.eval state))
    | .bulkCopy copy continuationRva =>
        .bulkCopy (copy.destination.eval state) (copy.source.eval state) (copy.count.eval state)
          (copy.direction.eval state) copy.elementBytes continuationRva
    | .bulkFill fill continuationRva =>
        .bulkFill (fill.destination.eval state) (fill.value.eval state)
          (fill.count.eval state) (fill.direction.eval state) fill.elementBytes
          continuationRva
    | .bulkScan scan continuationRva =>
        .bulkScan (scan.accumulator.eval state) (scan.destination.eval state)
          (scan.count.eval state) (scan.direction.eval state) continuationRva
    | .indirectCall target continuationRva returnAddress =>
        .indirectCall (target.eval state) continuationRva returnAddress
    | .indirectJump target => .indirectJump (target.eval state)
    | .checkedContinue valid continuationRva => .checkedContinue (valid.eval state) continuationRva
    | .atomicCompareExchange address expected replacement continuationRva =>
        .atomicCompareExchange (address.eval state) (expected.eval state) (replacement.eval state)
          continuationRva),
  }


end SpaghettiExtractor.ISA.Formal
