import Std

namespace StageA.X87

abbrev Word := BitVec 80

inductive Tag where
  | valid
  | zero
  | special
deriving Repr, DecidableEq

inductive Slot where
  /-- Empty stack entries retain their physical register bits.  Real x87
  hardware changes the tag on pop but does not zero the register. -/
  | empty (value : Word)
  | occupied (tag : Tag) (value : Word)
deriving Repr, DecidableEq

inductive LoadFormat where
  | float32
  | float64
  | float80
  | int32
deriving Repr, DecidableEq

def LoadFormat.byteWidth : LoadFormat -> Nat
  | .float32 | .int32 => 4
  | .float64 => 8
  | .float80 => 10

inductive StoreFormat where
  | float32
  | float64
  | float80
  | int32
deriving Repr, DecidableEq

def StoreFormat.byteWidth : StoreFormat -> Nat
  | .float32 | .int32 => 4
  | .float64 => 8
  | .float80 => 10

inductive UnaryOperation where
  | negate
  | sine
  | cosine
deriving Repr, DecidableEq

inductive BinaryOperation where
  | add
  | multiply
  | subtract
  | reverseSubtract
  | divide
  | reverseDivide
deriving Repr, DecidableEq

inductive CompareMode where
  | ordered
  | unordered
deriving Repr, DecidableEq

inductive CompareDestination where
  | status
  | eflags
deriving Repr, DecidableEq

inductive RoundingMode where
  | controlWord
  | truncate
deriving Repr, DecidableEq

inductive WaitMode where
  | waiting
  | noWait
deriving Repr, DecidableEq

/-! ## Concrete binary floating-point core

The relational machine is allowed to quantify over an x87 implementation, but
ISA qualification needs an actual implementation to compare with independent
executors.  The definitions below operate on exact integer ratios and round
only at the architecturally prescribed destination precision.  They are kept
free of native `Float` operations so the result does not depend on the host
compiler or floating-point environment. -/

inductive Number where
  | finite (sign : Bool) (numerator denominator : Nat) (exponent : Int)
  | infinity (sign : Bool)
  | nan (sign : Bool) (significand : Nat)
deriving Repr, DecidableEq

structure NumericResult where
  value : Word
  invalid : Bool := false
  denormal : Bool := false
  divideByZero : Bool := false
  overflow : Bool := false
  underflow : Bool := false
  inexact : Bool := false
deriving Repr, DecidableEq

private def pow2 (amount : Nat) : Nat := 2 ^ amount

private def scaleRatio (numerator denominator : Nat) (shift : Int) : Nat × Nat :=
  match shift with
  | .ofNat amount => (numerator * pow2 amount, denominator)
  | .negSucc amount => (numerator, denominator * pow2 (amount + 1))

private def ratioAtLeastPow2 (numerator denominator : Nat) (power : Int) : Bool :=
  let scaled := scaleRatio numerator denominator (-power)
  scaled.1 >= scaled.2

private def ratioFloorLog2 (numerator denominator : Nat) : Int :=
  if numerator == 0 || denominator == 0 then 0 else
  let candidate := Int.ofNat (Nat.log2 numerator) - Int.ofNat (Nat.log2 denominator)
  if ratioAtLeastPow2 numerator denominator candidate then candidate
  else candidate - 1

private def roundingControl (control : BitVec 16) : Nat :=
  (control.toNat / pow2 10) % 4

private def precisionBits (control : BitVec 16) : Nat :=
  match (control.toNat / pow2 8) % 4 with
  | 0 => 24
  | 2 => 53
  | _ => 64

structure RoundedRatio where
  quotient : Nat
  inexact : Bool
deriving Repr, DecidableEq

private def roundRatio (sign : Bool) (rounding : Nat)
    (numerator denominator : Nat) : RoundedRatio :=
  if denominator == 0 then { quotient := 0, inexact := false } else
  let quotient := numerator / denominator
  let remainder := numerator % denominator
  let inexact := remainder != 0
  let increment :=
    if !inexact then false else
    match rounding with
    | 0 =>
        let doubled := remainder * 2
        doubled > denominator || (doubled == denominator && quotient % 2 == 1)
    | 1 => sign
    | 2 => !sign
    | _ => false
  { quotient := quotient + if increment then 1 else 0, inexact }

private def canonicalNaNSignificand : Nat := pow2 63 + pow2 62

private def quietNaNSignificand (significand : Nat) : Nat :=
  (significand % pow2 64) ||| canonicalNaNSignificand

private def decodeBinary (bits exponentBits fractionBits bias : Nat) : Number :=
  let sign := Nat.testBit bits (exponentBits + fractionBits)
  let exponentField := (bits / pow2 fractionBits) % pow2 exponentBits
  let fraction := bits % pow2 fractionBits
  let maximumExponent := pow2 exponentBits - 1
  if exponentField == maximumExponent then
    if fraction == 0 then .infinity sign
    else .nan sign (quietNaNSignificand (fraction * pow2 (63 - fractionBits)))
  else if exponentField == 0 then
    if fraction == 0 then .finite sign 0 1 0
    else .finite sign fraction 1 (1 - Int.ofNat bias - Int.ofNat fractionBits)
  else
    .finite sign (pow2 fractionBits + fraction) 1
      (Int.ofNat exponentField - Int.ofNat bias - Int.ofNat fractionBits)

def decodeWord (value : Word) : Number :=
  let bits := value.toNat
  let sign := Nat.testBit bits 79
  let exponentField := (bits / pow2 64) % pow2 15
  let significand := bits % pow2 64
  if exponentField == 0x7fff then
    if significand == pow2 63 then .infinity sign
    else .nan sign (quietNaNSignificand significand)
  else if exponentField == 0 then
    if significand == 0 then .finite sign 0 1 0
    else .finite sign significand 1 (-16445)
  else if significand < pow2 63 then
    .nan true canonicalNaNSignificand
  else
    .finite sign significand 1 (Int.ofNat exponentField - 16446)

private def signedIntegerNumber (bits width : Nat) : Number :=
  let sign := Nat.testBit bits (width - 1)
  let modulus := pow2 width
  let magnitude := if sign then modulus - bits % modulus else bits % modulus
  .finite sign magnitude 1 0

def loadNumber (format : LoadFormat) (raw : Word) : Number :=
  match format with
  | .float32 => decodeBinary (raw.toNat % pow2 32) 8 23 127
  | .float64 => decodeBinary (raw.toNat % pow2 64) 11 52 1023
  | .float80 => decodeWord raw
  | .int32 => signedIntegerNumber (raw.toNat % pow2 32) 32

private def finiteZero (sign : Bool) : Number := .finite sign 0 1 0

private def negateNumber : Number -> Number
  | .finite sign numerator denominator exponent =>
      .finite (!sign) numerator denominator exponent
  | .infinity sign => .infinity (!sign)
  | .nan sign significand => .nan (!sign) significand

private def propagatedNaN : Number -> Option Number
  | .nan sign significand => some (.nan sign (quietNaNSignificand significand))
  | _ => none

private def exactAdd (left right : Number) (subtract : Bool) : Number × Bool :=
  let right := if subtract then negateNumber right else right
  match left, right with
  | .nan sign significand, _ => (.nan sign (quietNaNSignificand significand), false)
  | _, .nan sign significand => (.nan sign (quietNaNSignificand significand), false)
  | .infinity leftSign, .infinity rightSign =>
      if leftSign == rightSign then (.infinity leftSign, false)
      else (.nan true canonicalNaNSignificand, true)
  | .infinity sign, .finite _ _ _ _ | .finite _ _ _ _, .infinity sign =>
      (.infinity sign, false)
  | .finite leftSign leftNumerator leftDenominator leftExponent,
      .finite rightSign rightNumerator rightDenominator rightExponent =>
    let commonExponent := min leftExponent rightExponent
    let leftShift := (leftExponent - commonExponent).toNat
    let rightShift := (rightExponent - commonExponent).toNat
    let leftMagnitude := leftNumerator * rightDenominator * pow2 leftShift
    let rightMagnitude := rightNumerator * leftDenominator * pow2 rightShift
    let denominator := leftDenominator * rightDenominator
    if leftSign == rightSign then
      (.finite leftSign (leftMagnitude + rightMagnitude) denominator commonExponent,
        false)
    else if leftMagnitude < rightMagnitude then
      (.finite rightSign (rightMagnitude - leftMagnitude) denominator commonExponent,
        false)
    else
      (.finite leftSign (leftMagnitude - rightMagnitude) denominator commonExponent,
        false)

private def exactMultiply (left right : Number) : Number × Bool :=
  match left, right with
  | .nan sign significand, _ => (.nan sign (quietNaNSignificand significand), false)
  | _, .nan sign significand => (.nan sign (quietNaNSignificand significand), false)
  | .infinity leftSign, .finite rightSign numerator _ _
  | .finite leftSign numerator _ _, .infinity rightSign =>
      if numerator == 0 then (.nan true canonicalNaNSignificand, true)
      else (.infinity (leftSign != rightSign), false)
  | .infinity leftSign, .infinity rightSign =>
      (.infinity (leftSign != rightSign), false)
  | .finite leftSign leftNumerator leftDenominator leftExponent,
      .finite rightSign rightNumerator rightDenominator rightExponent =>
    (.finite (leftSign != rightSign) (leftNumerator * rightNumerator)
      (leftDenominator * rightDenominator) (leftExponent + rightExponent), false)

private def exactDivide (left right : Number) : Number × Bool × Bool :=
  match left, right with
  | .nan sign significand, _ =>
      (.nan sign (quietNaNSignificand significand), false, false)
  | _, .nan sign significand =>
      (.nan sign (quietNaNSignificand significand), false, false)
  | .infinity _, .infinity _ => (.nan true canonicalNaNSignificand, true, false)
  | .infinity leftSign, .finite rightSign rightNumerator _ _ =>
      if rightNumerator == 0 then (.nan true canonicalNaNSignificand, true, false)
      else (.infinity (leftSign != rightSign), false, false)
  | .finite leftSign _ _ _, .infinity rightSign =>
      (finiteZero (leftSign != rightSign), false, false)
  | .finite leftSign leftNumerator leftDenominator leftExponent,
      .finite rightSign rightNumerator rightDenominator rightExponent =>
    if rightNumerator == 0 then
      if leftNumerator == 0 then (.nan true canonicalNaNSignificand, true, false)
      else (.infinity (leftSign != rightSign), false, true)
    else
      (.finite (leftSign != rightSign) (leftNumerator * rightDenominator)
        (leftDenominator * rightNumerator) (leftExponent - rightExponent),
        false, false)

private structure BinaryEncoding where
  bits : Nat
  overflow : Bool := false
  underflow : Bool := false
  inexact : Bool := false
deriving Repr, DecidableEq

private def overflowToInfinity (sign : Bool) (rounding : Nat) : Bool :=
  match rounding with
  | 0 => true
  | 1 => sign
  | 2 => !sign
  | _ => false

private def encodeFinite (sign : Bool) (numerator denominator : Nat)
    (exponent : Int) (precision exponentBits fractionBits bias : Nat)
    (rounding : Nat) : BinaryEncoding :=
  let signBits := if sign then pow2 (exponentBits + fractionBits) else 0
  if numerator == 0 then { bits := signBits } else
  let minimumExponent : Int := 1 - Int.ofNat bias
  let maximumExponent : Int := Int.ofNat (pow2 exponentBits - 2) - Int.ofNat bias
  let exactExponent := ratioFloorLog2 numerator denominator + exponent
  let roundedAt := fun (targetExponent : Int) =>
    let shift := exponent - targetExponent + Int.ofNat (precision - 1)
    let scaled := scaleRatio numerator denominator shift
    roundRatio sign rounding scaled.1 scaled.2
  if exactExponent > maximumExponent then
    let maximumField := pow2 exponentBits - 2
    let maximumFraction := pow2 fractionBits - 1
    if overflowToInfinity sign rounding then
      { bits := signBits + (pow2 exponentBits - 1) * pow2 fractionBits,
        overflow := true, inexact := true }
    else
      { bits := signBits + maximumField * pow2 fractionBits + maximumFraction,
        overflow := true, inexact := true }
  else if exactExponent < minimumExponent then
    let rounded := roundedAt minimumExponent
    let shiftToStorage := fractionBits + 1 - precision
    let stored := rounded.quotient * pow2 shiftToStorage
    if stored >= pow2 fractionBits then
      { bits := signBits + pow2 fractionBits,
        underflow := rounded.inexact, inexact := rounded.inexact }
    else
      { bits := signBits + stored,
        underflow := rounded.inexact, inexact := rounded.inexact }
  else
    let rounded := roundedAt exactExponent
    let carry := rounded.quotient >= pow2 precision
    let adjustedExponent := if carry then exactExponent + 1 else exactExponent
    let adjustedQuotient := if carry then rounded.quotient / 2 else rounded.quotient
    if adjustedExponent > maximumExponent then
      if overflowToInfinity sign rounding then
        { bits := signBits + (pow2 exponentBits - 1) * pow2 fractionBits,
          overflow := true, inexact := true }
      else
        { bits := signBits + (pow2 exponentBits - 2) * pow2 fractionBits +
            (pow2 fractionBits - 1), overflow := true, inexact := true }
    else
      let exponentField := (adjustedExponent + Int.ofNat bias).toNat
      let storageSignificand := adjustedQuotient * pow2 (fractionBits + 1 - precision)
      { bits := signBits + exponentField * pow2 fractionBits +
          (storageSignificand - pow2 fractionBits), inexact := rounded.inexact }

private def encodeX87 (number : Number) (control : BitVec 16) : NumericResult :=
  match number with
  | .nan sign significand =>
      { value := BitVec.ofNat 80
          ((if sign then pow2 79 else 0) + 0x7fff * pow2 64 +
            quietNaNSignificand significand) }
  | .infinity sign =>
      { value := BitVec.ofNat 80
          ((if sign then pow2 79 else 0) + 0x7fff * pow2 64 + pow2 63) }
  | .finite sign numerator denominator exponent =>
      let encoded := encodeFinite sign numerator denominator exponent
        (precisionBits control) 15 63 16383 (roundingControl control)
      { value := BitVec.ofNat 80 encoded.bits, overflow := encoded.overflow,
        underflow := encoded.underflow, inexact := encoded.inexact }

def concreteLoad (format : LoadFormat) (raw : Word)
    (control : BitVec 16) : NumericResult :=
  encodeX87 (loadNumber format raw) control

def concreteUnary (operation : UnaryOperation) (value : Word)
    (control : BitVec 16) : Option NumericResult :=
  match operation with
  | .negate => some (encodeX87 (negateNumber (decodeWord value)) control)
  | .sine | .cosine => none

def concreteBinary (operation : BinaryOperation) (left right : Word)
    (control : BitVec 16) : NumericResult :=
  let left := decodeWord left
  let right := decodeWord right
  let result : Number × Bool × Bool :=
    match operation with
    | .add => let result := exactAdd left right false; (result.1, result.2, false)
    | .subtract => let result := exactAdd left right true; (result.1, result.2, false)
    | .reverseSubtract => let result := exactAdd right left true; (result.1, result.2, false)
    | .multiply => let result := exactMultiply left right; (result.1, result.2, false)
    | .divide => exactDivide left right
    | .reverseDivide => exactDivide right left
  let encoded := encodeX87 result.1 control
  { encoded with invalid := result.2.1, divideByZero := result.2.2 }

private def encodeStoreFloat (number : Number) (control : BitVec 16)
    (exponentBits fractionBits bias : Nat) : NumericResult :=
  match number with
  | .nan sign significand =>
      let payload := (quietNaNSignificand significand / pow2 (63 - fractionBits)) %
        pow2 fractionBits
      { value := BitVec.ofNat 80 ((if sign then pow2 (exponentBits + fractionBits)
          else 0) + (pow2 exponentBits - 1) * pow2 fractionBits + payload) }
  | .infinity sign =>
      { value := BitVec.ofNat 80 ((if sign then pow2 (exponentBits + fractionBits)
          else 0) + (pow2 exponentBits - 1) * pow2 fractionBits) }
  | .finite sign numerator denominator exponent =>
      let encoded := encodeFinite sign numerator denominator exponent
        (fractionBits + 1) exponentBits fractionBits bias (roundingControl control)
      { value := BitVec.ofNat 80 encoded.bits, overflow := encoded.overflow,
        underflow := encoded.underflow, inexact := encoded.inexact }

private def encodeStoreInteger (number : Number) (control : BitVec 16)
    (width : Nat) : NumericResult :=
  match number with
  | .nan _ _ | .infinity _ =>
      { value := BitVec.ofNat 80 (pow2 (width - 1)), invalid := true }
  | .finite sign numerator denominator exponent =>
      let scaled := scaleRatio numerator denominator exponent
      let rounded := roundRatio sign (roundingControl control) scaled.1 scaled.2
      let limit := if sign then pow2 (width - 1) else pow2 (width - 1) - 1
      if rounded.quotient > limit then
        { value := BitVec.ofNat 80 (pow2 (width - 1)), invalid := true }
      else
        let bits := if sign && rounded.quotient != 0 then
          pow2 width - rounded.quotient else rounded.quotient
        { value := BitVec.ofNat 80 bits, inexact := rounded.inexact }

def concreteStore (format : StoreFormat) (value : Word)
    (control : BitVec 16) : NumericResult :=
  let number := decodeWord value
  match format with
  | .float32 => encodeStoreFloat number control 8 23 127
  | .float64 => encodeStoreFloat number control 11 52 1023
  | .float80 => { value }
  | .int32 => encodeStoreInteger number control 32

inductive Comparison where
  | less | equal | greater | unordered
deriving Repr, DecidableEq

private def compareFinite (leftSign : Bool) (leftNumerator leftDenominator : Nat)
    (leftExponent : Int) (rightSign : Bool)
    (rightNumerator rightDenominator : Nat) (rightExponent : Int) : Comparison :=
  if leftNumerator == 0 && rightNumerator == 0 then .equal
  else if leftSign != rightSign then if leftSign then .less else .greater
  else
    let commonExponent := min leftExponent rightExponent
    let leftMagnitude := leftNumerator * rightDenominator *
      pow2 (leftExponent - commonExponent).toNat
    let rightMagnitude := rightNumerator * leftDenominator *
      pow2 (rightExponent - commonExponent).toNat
    let order := if leftMagnitude < rightMagnitude then Comparison.less
      else if leftMagnitude > rightMagnitude then Comparison.greater else Comparison.equal
    if leftSign then match order with
      | .less => .greater | .greater => .less | value => value
    else order

def concreteCompare (left right : Word) : Comparison :=
  match decodeWord left, decodeWord right with
  | .nan _ _, _ | _, .nan _ _ => .unordered
  | .infinity leftSign, .infinity rightSign =>
      if leftSign == rightSign then .equal else if leftSign then .less else .greater
  | .infinity sign, _ => if sign then .less else .greater
  | _, .infinity sign => if sign then .greater else .less
  | .finite leftSign leftNumerator leftDenominator leftExponent,
      .finite rightSign rightNumerator rightDenominator rightExponent =>
      compareFinite leftSign leftNumerator leftDenominator leftExponent
        rightSign rightNumerator rightDenominator rightExponent

/-- Physical x87 state. Logical ST(i) access is derived from TOP in `status`;
it is not represented by shifting the eight physical slots. -/
structure PhysicalState where
  slots : Vector Slot 8
  control : BitVec 16
  status : BitVec 16
  pendingException : Bool
  lastOpcode : BitVec 11
  instructionPointer : BitVec 32
  codeSelector : BitVec 16
  dataPointer : BitVec 32
  dataSelector : BitVec 16
deriving Repr, DecidableEq

/-- Arithmetic state is separated from concrete instruction/data metadata so
the shared numerical semantics cannot distinguish relocated implementations. -/
structure CoreState where
  slots : Vector Slot 8
  control : BitVec 16
  status : BitVec 16
  pendingException : Bool
deriving Repr, DecidableEq

structure MetadataState where
  lastOpcode : BitVec 11
  instructionPointer : BitVec 32
  codeSelector : BitVec 16
  dataPointer : BitVec 32
  dataSelector : BitVec 16
deriving Repr, DecidableEq

def PhysicalState.core (state : PhysicalState) : CoreState := {
  slots := state.slots
  control := state.control
  status := state.status
  pendingException := state.pendingException
}

def PhysicalState.metadata (state : PhysicalState) : MetadataState := {
  lastOpcode := state.lastOpcode
  instructionPointer := state.instructionPointer
  codeSelector := state.codeSelector
  dataPointer := state.dataPointer
  dataSelector := state.dataSelector
}

def PhysicalState.withCoreAndMetadata (_state : PhysicalState)
    (core : CoreState) (metadata : MetadataState) : PhysicalState := {
  slots := core.slots
  control := core.control
  status := core.status
  pendingException := core.pendingException
  lastOpcode := metadata.lastOpcode
  instructionPointer := metadata.instructionPointer
  codeSelector := metadata.codeSelector
  dataPointer := metadata.dataPointer
  dataSelector := metadata.dataSelector
}

def initialPhysicalState : PhysicalState := {
  slots := Vector.replicate 8 (.empty (BitVec.ofNat 80 0))
  control := BitVec.ofNat 16 0x037f
  status := BitVec.ofNat 16 0
  pendingException := false
  lastOpcode := BitVec.ofNat 11 0
  instructionPointer := BitVec.ofNat 32 0
  codeSelector := BitVec.ofNat 16 0
  dataPointer := BitVec.ofNat 32 0
  dataSelector := BitVec.ofNat 16 0
}

def PhysicalState.top (state : PhysicalState) : Nat :=
  (state.status.toNat / (2 ^ 11)) % 8

def PhysicalState.physicalIndex (state : PhysicalState) (logical : Nat) : Fin 8 :=
  ⟨(state.top + logical) % 8, Nat.mod_lt _ (by decide)⟩

def PhysicalState.logicalSlot (state : PhysicalState) (logical : Nat) : Slot :=
  state.slots[state.physicalIndex logical]

inductive Command where
  | wait
  | initialize
  | loadStack (index : Nat)
  | loadConstant (value : Word)
  | exchange (index : Nat)
  | storeStack (index : Nat) (pop : Bool)
  | unary (operation : UnaryOperation)
  | binaryStack (operation : BinaryOperation)
      (destination source : Nat) (pop : Bool)
  | compareStack (mode : CompareMode) (destination : CompareDestination)
      (index : Nat) (pop : Bool)
  | compareMemory (mode : CompareMode) (format : LoadFormat) (pop : Bool)
  | loadMemory (format : LoadFormat)
  | storeMemory (format : StoreFormat) (rounding : RoundingMode) (pop : Bool)
  | binaryMemory (operation : BinaryOperation) (format : LoadFormat)
  | loadControl
  | storeControl
  | storeStatusAx
  | examine
deriving Repr, DecidableEq

/-- Raw machine inputs supplied by the checked instruction layer. Memory
addresses and access checks remain in the flat x86 machine model. -/
structure StepInput where
  operandBits : Word
  operandBytes : Nat
  opcode : BitVec 11
  instructionPointer : BitVec 32
  codeSelector : BitVec 16
  dataPointer : BitVec 32
  dataSelector : BitVec 16
deriving Repr, DecidableEq

structure OperandInput where
  bits : Word
  bytes : Nat
deriving Repr, DecidableEq

def StepInput.operand (input : StepInput) : OperandInput := {
  bits := input.operandBits
  bytes := input.operandBytes
}

inductive Fault where
  | floatingPoint
deriving Repr, DecidableEq

inductive StoreKind where
  | numeric (format : StoreFormat)
  | controlWord
deriving Repr, DecidableEq

def StoreKind.byteWidth : StoreKind -> Nat
  | .numeric format => format.byteWidth
  | .controlWord => 2

structure StoreResult where
  kind : StoreKind
  bits : Word
deriving Repr, DecidableEq

inductive RegisterTarget where
  | ax
deriving Repr, DecidableEq

structure RegisterResult where
  target : RegisterTarget
  value : BitVec 32
deriving Repr, DecidableEq

/-- Definedness is explicit so poison cannot silently flow into control,
addresses, observations, stores, returns, or fault selection. -/
structure Definedness where
  slotMasks : Vector Word 8
  statusMask : BitVec 16
  eflagsMask : BitVec 32
  storeMask : Word
  registerMask : BitVec 32
deriving Repr, DecidableEq

inductive MetadataProfile where
  /-- i386 through P6-compatible behavior: every non-control instruction
  records FOP and memory-operand instructions record FDP. -/
  | legacy
  /-- Later behavior without fopcode compatibility and with
  FDP_EXCPTN_ONLY: FOP/FDP update only for an incurred unmasked exception. -/
  | exceptionOnly
deriving Repr, DecidableEq

/-- Architecturally observable x87 output bits for one instruction. This is
separate from `Definedness`, which describes the internal replay result, so
reserved environment bits and instruction-specific undefined condition codes
cannot accidentally become conformance obligations. -/
structure ObservableDefinedness where
  controlMask : BitVec 16
  statusMask : BitVec 16
  tagMask : BitVec 16
  lastOpcodeMask : BitVec 11
  instructionPointerMask : BitVec 32
  dataPointerMask : BitVec 32
  slotMasks : Vector Word 8
deriving Repr, DecidableEq

structure Response where
  nextState : PhysicalState
  store : Option StoreResult
  register : Option RegisterResult
  eflagsValue : BitVec 32
  eflagsWriteMask : BitVec 32
  definedness : Definedness
  fault : Option Fault
deriving Repr, DecidableEq

structure CoreResponse where
  nextState : CoreState
  store : Option StoreResult
  register : Option RegisterResult
  eflagsValue : BitVec 32
  eflagsWriteMask : BitVec 32
  definedness : Definedness
  fault : Option Fault
deriving Repr, DecidableEq

def Command.expectedOperandBytes : Command -> Option Nat
  | .loadMemory format | .binaryMemory _ format | .compareMemory _ format _ =>
      some format.byteWidth
  | .loadControl => some 2
  | _ => none

def Command.expectedStoreKind : Command -> Option StoreKind
  | .storeMemory format _ _ => some (.numeric format)
  | .storeControl => some .controlWord
  | _ => none

def Command.expectedRegisterTarget : Command -> Option RegisterTarget
  | .storeStatusAx => some .ax
  | _ => none

def Command.eflagsWriteMask : Command -> BitVec 32
  | .compareStack _ .eflags _ _ => BitVec.ofNat 32 0x8d5
  | _ => BitVec.ofNat 32 0

def Command.usesMemoryOperand : Command -> Bool
  | .loadMemory _ | .storeMemory _ _ _ | .binaryMemory _ _ |
      .compareMemory _ _ _ |
      .loadControl | .storeControl => true
  | _ => false

private def statusMaskWithoutConditions : BitVec 16 :=
  BitVec.ofNat 16 0xb8ff

private def statusMaskWithC1 : BitVec 16 :=
  BitVec.ofNat 16 0xbaff

/-- Intel SDM Vol. 1 Table 8-1 defines C0/C1/C2/C3 per instruction
class. Exception flags, TOP, ES/SF, and B remain observable for all modeled
commands; undefined condition-code bits are excluded rather than assigned a
convenient implementation value. -/
def Command.observableStatusMask : Command -> BitVec 16
  | .initialize | .wait | .compareStack _ .status _ _ |
      .compareMemory _ _ _ | .examine => BitVec.ofNat 16 0xffff
  | .loadStack _ | .loadConstant _ | .exchange _ | .storeStack _ _ |
      .unary _ | .binaryStack _ _ _ _ | .compareStack _ .eflags _ _ |
      .loadMemory _ | .storeMemory _ _ _ | .binaryMemory _ _ =>
        statusMaskWithC1
  | .loadControl | .storeControl | .storeStatusAx =>
      statusMaskWithoutConditions

/-- The meaningful P6-and-later control-word fields are the exception masks,
precision control, rounding control, and the legacy infinity-control bit.
Reserved bits are deliberately not compared. -/
private def observableControlMask : BitVec 16 :=
  BitVec.ofNat 16 0x1f3f

private def PhysicalState.observableLogicalSlotMasks
    (state : PhysicalState) : Vector Word 8 :=
  Vector.ofFn fun logical => match state.logicalSlot logical.val with
    | .occupied _ _ => BitVec.ofNat 80 (pow2 80 - 1)
    | .empty _ => BitVec.ofNat 80 0

private def Command.observableDataPointerMask (command : Command)
    (profile : MetadataProfile) (incurredUnmaskedException : Bool) : BitVec 32 :=
  match command with
  | .loadControl | .storeControl | .storeStatusAx | .wait | .initialize =>
      BitVec.ofNat 32 0xffffffff
  | _ => match profile with
      | .legacy => if command.usesMemoryOperand then
          BitVec.ofNat 32 0xffffffff else BitVec.ofNat 32 0
      | .exceptionOnly =>
          if !incurredUnmaskedException then BitVec.ofNat 32 0xffffffff
          else if command.usesMemoryOperand then BitVec.ofNat 32 0xffffffff
          else BitVec.ofNat 32 0

def Command.observableDefinedness (command : Command)
    (profile : MetadataProfile) (incurredUnmaskedException : Bool)
    (nextState : PhysicalState) : ObservableDefinedness := {
  controlMask := observableControlMask
  statusMask := command.observableStatusMask
  tagMask := BitVec.ofNat 16 0xffff
  lastOpcodeMask := BitVec.ofNat 11 0x7ff
  instructionPointerMask := BitVec.ofNat 32 0xffffffff
  dataPointerMask := command.observableDataPointerMask profile
    incurredUnmaskedException
  slotMasks := nextState.observableLogicalSlotMasks
}

def Command.expectedWaitMode : Command -> WaitMode
  | .initialize | .storeControl | .storeStatusAx => .noWait
  | _ => .waiting

def Slot.value : Slot -> Word
  | .empty value | .occupied _ value => value

def Slot.tagBits : Slot -> Nat
  | .empty _ => 3
  | .occupied .valid _ => 0
  | .occupied .zero _ => 1
  | .occupied .special _ => 2

def tagForWord (value : Word) : Tag :=
  match decodeWord value with
  | .finite _ numerator _ _ => if numerator == 0 then .zero else .valid
  | .infinity _ | .nan _ _ => .special

def CoreState.top (state : CoreState) : Nat :=
  (state.status.toNat / pow2 11) % 8

def CoreState.physicalIndex (state : CoreState) (logical : Nat) : Fin 8 :=
  ⟨(state.top + logical) % 8, Nat.mod_lt _ (by decide)⟩

def CoreState.logicalSlot (state : CoreState) (logical : Nat) : Slot :=
  state.slots[state.physicalIndex logical]

private def statusWithTop (status : BitVec 16) (top : Nat) : BitVec 16 :=
  BitVec.ofNat 16 ((status.toNat &&& 0xc7ff) ||| ((top % 8) * pow2 11))

private def statusBit (status : BitVec 16) (bit : Nat) (enabled : Bool) : BitVec 16 :=
  let mask := pow2 bit
  BitVec.ofNat 16 (if enabled then status.toNat ||| mask else status.toNat &&& (0xffff ^^^ mask))

private def statusCondition (status : BitVec 16) (comparison : Comparison) : BitVec 16 :=
  let cleared := BitVec.ofNat 16 (status.toNat &&& (0xffff ^^^ (pow2 14 + pow2 10 + pow2 8)))
  match comparison with
  | .greater => cleared
  | .less => statusBit cleared 8 true
  | .equal => statusBit cleared 14 true
  | .unordered => statusBit (statusBit (statusBit cleared 14 true) 10 true) 8 true

private def exceptionMask (result : NumericResult) : Nat :=
  (if result.invalid then pow2 0 else 0) +
  (if result.denormal then pow2 1 else 0) +
  (if result.divideByZero then pow2 2 else 0) +
  (if result.overflow then pow2 3 else 0) +
  (if result.underflow then pow2 4 else 0) +
  (if result.inexact then pow2 5 else 0)

private def CoreState.recordNumeric (state : CoreState)
    (result : NumericResult) : CoreState :=
  let raised := exceptionMask result
  let status := BitVec.ofNat 16 (state.status.toNat ||| raised)
  let unmasked := raised &&& (0x3f ^^^ (state.control.toNat &&& 0x3f))
  let status := statusBit (statusBit status 7 (unmasked != 0)) 15 (unmasked != 0)
  { state with status, pendingException := state.pendingException || unmasked != 0 }

private def CoreState.setLogical (state : CoreState) (logical : Nat)
    (slot : Slot) : CoreState :=
  { state with slots := state.slots.set (state.physicalIndex logical) slot }

private def CoreState.push (state : CoreState) (value : Word) : CoreState :=
  let nextTop := (state.top + 7) % 8
  let physical : Fin 8 := ⟨nextTop, Nat.mod_lt _ (by decide)⟩
  let occupied := match state.slots[physical] with
    | .occupied _ _ => true
    | .empty _ => false
  let value := if occupied == true then BitVec.ofNat 80
    (pow2 79 + 0x7fff * pow2 64 + canonicalNaNSignificand) else value
  let slots := state.slots.set physical (.occupied (tagForWord value) value)
  let status := statusWithTop state.status nextTop
  let status := statusBit (statusBit status 6 occupied) 0 occupied
  { state with
    slots
    status
    pendingException := state.pendingException ||
      (occupied && !Nat.testBit state.control.toNat 0) }

private def CoreState.pop (state : CoreState) : CoreState :=
  let physical := state.physicalIndex 0
  let value := state.slots[physical].value
  let slots := state.slots.set physical (.empty value)
  { state with slots, status := statusWithTop state.status (state.top + 1) }

private def fullDefinedness (command : Command) : Definedness := {
  slotMasks := Vector.replicate 8 (BitVec.ofNat 80 (pow2 80 - 1))
  statusMask := BitVec.ofNat 16 0xffff
  eflagsMask := command.eflagsWriteMask
  storeMask := if command.expectedStoreKind.isSome then
    BitVec.ofNat 80 (pow2 80 - 1) else BitVec.ofNat 80 0
  registerMask := if command.expectedRegisterTarget.isSome then
    BitVec.ofNat 32 0xffffffff else BitVec.ofNat 32 0
}

private def response (command : Command) (state : CoreState)
    (store : Option StoreResult := none) (register : Option RegisterResult := none)
    (eflagsValue : BitVec 32 := 0) (fault : Option Fault := none) : CoreResponse := {
  nextState := state
  store
  register
  eflagsValue
  eflagsWriteMask := command.eflagsWriteMask
  definedness := fullDefinedness command
  fault
}

/-- Pure concrete execution for the modeled x87 command language.  Returning
`none` is a semantic capability boundary, never a successful placeholder. -/
def executeConcrete (command : Command) (waitMode : WaitMode)
    (state : CoreState) (input : OperandInput) : Option CoreResponse :=
  if command.expectedWaitMode != waitMode ||
      input.bytes != command.expectedOperandBytes.getD 0 then none else
  match command with
  | .wait =>
      some (response command state (fault := if state.pendingException then
        some .floatingPoint else none))
  | .initialize =>
      let slots := state.slots.map fun slot => .empty slot.value
      some (response command { state with
        slots
        control := BitVec.ofNat 16 0x037f
        status := BitVec.ofNat 16 0
        pendingException := false })
  | .loadStack index =>
      match state.logicalSlot index with
      | .occupied _ value => some (response command (state.push value))
      | .empty _ =>
          let invalid : NumericResult := {
            value := BitVec.ofNat 80
              (pow2 79 + 0x7fff * pow2 64 + canonicalNaNSignificand)
            invalid := true
          }
          some (response command ((state.recordNumeric invalid).push invalid.value))
  | .loadConstant value => some (response command (state.push value))
  | .exchange index =>
      let top := state.logicalSlot 0
      let other := state.logicalSlot index
      let next := (state.setLogical 0 other).setLogical index top
      some (response command next)
  | .storeStack index pop =>
      match state.logicalSlot 0 with
      | .empty _ => none
      | .occupied tag value =>
          let next := state.setLogical index (.occupied tag value)
          some (response command (if pop then next.pop else next))
  | .unary operation =>
      match state.logicalSlot 0 with
      | .empty _ => none
      | .occupied _ value => do
          let result <- concreteUnary operation value state.control
          let next := (state.recordNumeric result).setLogical 0
            (.occupied (tagForWord result.value) result.value)
          some (response command next)
  | .binaryStack operation destination source pop =>
      match state.logicalSlot destination, state.logicalSlot source with
      | .occupied _ left, .occupied _ right =>
          let result := concreteBinary operation left right state.control
          let next := (state.recordNumeric result).setLogical destination
            (.occupied (tagForWord result.value) result.value)
          some (response command (if pop then next.pop else next))
      | _, _ => none
  | .compareStack mode destination index pop =>
      match state.logicalSlot 0, state.logicalSlot index with
      | .occupied _ left, .occupied _ right =>
          let comparison := concreteCompare left right
          let invalid := comparison == .unordered && mode == .ordered
          let marker : NumericResult := { value := left, invalid }
          let next := state.recordNumeric marker
          let next := if destination == .status then
            { next with status := statusCondition next.status comparison } else next
          let next := if pop then next.pop else next
          let eflagsValue := match comparison with
            | .greater => BitVec.ofNat 32 0
            | .less => BitVec.ofNat 32 0x1
            | .equal => BitVec.ofNat 32 0x40
            | .unordered => BitVec.ofNat 32 0x45
          some (response command next (eflagsValue := eflagsValue))
      | _, _ => none
  | .compareMemory mode format pop =>
      match state.logicalSlot 0 with
      | .empty _ => none
      | .occupied _ left =>
          let loaded := concreteLoad format input.bits state.control
          let comparison := concreteCompare left loaded.value
          let invalid := comparison == .unordered && mode == .ordered
          let marker : NumericResult := { loaded with invalid := loaded.invalid || invalid }
          let next := state.recordNumeric marker
          let next := { next with status := statusCondition next.status comparison }
          some (response command (if pop then next.pop else next))
  | .loadMemory format =>
      let result := concreteLoad format input.bits state.control
      some (response command ((state.recordNumeric result).push result.value))
  | .storeMemory format _ pop =>
      match state.logicalSlot 0 with
      | .empty _ => none
      | .occupied _ value =>
          let result := concreteStore format value state.control
          let next := state.recordNumeric result
          let store : StoreResult := {
            kind := .numeric format
            bits := result.value
          }
          some (response command (if pop then next.pop else next) (some store))
  | .binaryMemory operation format =>
      match state.logicalSlot 0 with
      | .empty _ => none
      | .occupied _ left =>
          let loaded := concreteLoad format input.bits state.control
          let result := concreteBinary operation left loaded.value state.control
          let next := (state.recordNumeric result).setLogical 0
            (.occupied (tagForWord result.value) result.value)
          some (response command next)
  | .loadControl =>
      some (response command { state with control := input.bits.extractLsb' 0 16 })
  | .storeControl =>
      some (response command state (some {
        kind := .controlWord
        bits := BitVec.zeroExtend 80 state.control
      }))
  | .storeStatusAx =>
      some (response command state (register := some {
        target := .ax
        value := BitVec.zeroExtend 32 state.status
      }))
  | .examine =>
      let slot := state.logicalSlot 0
      let value := slot.value
      let sign := Nat.testBit value.toNat 79
      let classification := match slot with
        | .empty _ => 5
        | .occupied _ _ => match decodeWord value with
          | .nan _ _ => 1
          | .infinity _ => 3
          | .finite _ numerator _ exponent =>
              if numerator == 0 then 4 else if exponent <= -16445 then 6 else 2
      let status := state.status
      let status := statusBit (statusBit (statusBit status 14
        (Nat.testBit classification 2)) 10 (Nat.testBit classification 1)) 8
        (Nat.testBit classification 0)
      let status := statusBit status 9 sign
      some (response command { state with status })

structure MachineEffect where
  response : Response
  memoryAddress : Option (BitVec 32)
deriving Repr, DecidableEq

theorem Command.usesMemoryOperand_of_expectedStoreKind
    (command : Command) (kind : StoreKind)
    (expected : command.expectedStoreKind = some kind) :
    command.usesMemoryOperand = true := by
  cases command <;>
    simp [Command.expectedStoreKind, Command.usesMemoryOperand] at expected ⊢

def Command.waitModeValid (command : Command) (waitMode : WaitMode) : Prop :=
  waitMode = command.expectedWaitMode

def Command.waitModeChecked (command : Command) (waitMode : WaitMode) : Bool :=
  waitMode == command.expectedWaitMode

theorem Command.waitModeValid_of_checked (command : Command)
    (waitMode : WaitMode) (checked : command.waitModeChecked waitMode = true) :
    command.waitModeValid waitMode := by
  simpa [Command.waitModeChecked, Command.waitModeValid] using checked

theorem Command.waitModeChecked_of_valid (command : Command)
    (waitMode : WaitMode) (valid : command.waitModeValid waitMode) :
    command.waitModeChecked waitMode = true := by
  simpa [Command.waitModeChecked, Command.waitModeValid] using valid

inductive MetadataAction where
  | preserve
  | record
  | reset
deriving Repr, DecidableEq

/-- x87 environment-control instructions do not record themselves as the last
    arithmetic instruction. `FINIT` resets the saved environment, while the
    no-wait control/status operations and `FWAIT` leave it untouched. -/
def Command.metadataAction : Command -> MetadataAction
  | .loadControl | .storeControl | .storeStatusAx | .wait => .preserve
  | .initialize => .reset
  | _ => .record

def MetadataState.after (previous : MetadataState) (command : Command)
    (input : StepInput) (profile : MetadataProfile := .legacy)
    (incurredUnmaskedException : Bool := false) : MetadataState :=
  match command.metadataAction with
  | .preserve => previous
  | .reset => {
      lastOpcode := BitVec.ofNat 11 0
      instructionPointer := BitVec.ofNat 32 0
      codeSelector := BitVec.ofNat 16 0
      dataPointer := BitVec.ofNat 32 0
      dataSelector := BitVec.ofNat 16 0
    }
  | .record => {
      lastOpcode := match profile with
        | .legacy => input.opcode
        | .exceptionOnly => if incurredUnmaskedException then input.opcode
            else previous.lastOpcode
      instructionPointer := input.instructionPointer
      codeSelector := input.codeSelector
      dataPointer := if command.usesMemoryOperand &&
          (profile == .legacy || incurredUnmaskedException) then input.dataPointer
        else previous.dataPointer
      dataSelector := if command.usesMemoryOperand &&
          (profile == .legacy || incurredUnmaskedException) then input.dataSelector
        else previous.dataSelector
    }

def StepInput.validFor (input : StepInput) (command : Command) : Prop :=
  input.operandBytes = command.expectedOperandBytes.getD 0 ∧
    input.operandBits.toNat < 2 ^ (8 * input.operandBytes)

def OperandInput.validFor (input : OperandInput) (command : Command) : Prop :=
  input.bytes = command.expectedOperandBytes.getD 0 ∧
    input.bits.toNat < 2 ^ (8 * input.bytes)

theorem StepInput.operand_validFor (input : StepInput) (command : Command)
    (valid : input.validFor command) : input.operand.validFor command :=
  valid

def StoreResult.valid (store : StoreResult) : Prop :=
  store.bits.toNat < 2 ^ (8 * store.kind.byteWidth)

def StoreResult.checked (store : StoreResult) : Bool :=
  decide (store.bits.toNat < 2 ^ (8 * store.kind.byteWidth))

theorem StoreResult.valid_of_checked (store : StoreResult)
    (checked : store.checked = true) : store.valid := by
  simpa [StoreResult.checked, StoreResult.valid] using checked

def Response.structurallyValid (response : Response) (command : Command)
    (waitMode : WaitMode) : Prop :=
  response.store.map StoreResult.kind = command.expectedStoreKind ∧
  response.store.all StoreResult.checked = true ∧
  response.register.map RegisterResult.target = command.expectedRegisterTarget ∧
  response.eflagsWriteMask = command.eflagsWriteMask ∧
  response.definedness.eflagsMask = response.eflagsWriteMask ∧
  (response.store.isNone → response.definedness.storeMask = BitVec.ofNat 80 0) ∧
  (response.register.isNone →
    response.definedness.registerMask = BitVec.ofNat 32 0) ∧
  (response.fault.isSome → waitMode = .waiting) ∧
  (command = .wait → waitMode = .waiting)

def CoreResponse.structurallyValid (response : CoreResponse) (command : Command)
    (waitMode : WaitMode) : Prop :=
  response.store.map StoreResult.kind = command.expectedStoreKind ∧
  response.store.all StoreResult.checked = true ∧
  response.register.map RegisterResult.target = command.expectedRegisterTarget ∧
  response.eflagsWriteMask = command.eflagsWriteMask ∧
  response.definedness.eflagsMask = response.eflagsWriteMask ∧
  (response.store.isNone → response.definedness.storeMask = BitVec.ofNat 80 0) ∧
  (response.register.isNone →
    response.definedness.registerMask = BitVec.ofNat 32 0) ∧
  (response.fault.isSome → waitMode = .waiting) ∧
  (command = .wait → waitMode = .waiting)

def CoreResponse.toResponseFor (response : CoreResponse) (previous : PhysicalState)
    (command : Command) (input : StepInput) (profile : MetadataProfile) : Response := {
  nextState := previous.withCoreAndMetadata response.nextState
    (previous.metadata.after command input profile
      (!previous.pendingException && response.nextState.pendingException))
  store := response.store
  register := response.register
  eflagsValue := response.eflagsValue
  eflagsWriteMask := response.eflagsWriteMask
  definedness := response.definedness
  fault := response.fault
}

def CoreResponse.toResponse (response : CoreResponse) (previous : PhysicalState)
    (command : Command) (input : StepInput) : Response :=
  response.toResponseFor previous command input .legacy

theorem CoreResponse.toResponse_structurallyValid (response : CoreResponse)
    (previous : PhysicalState) (command : Command) (input : StepInput)
    (waitMode : WaitMode) (valid : response.structurallyValid command waitMode) :
    (response.toResponse previous command input).structurallyValid command waitMode :=
  by
    simpa [CoreResponse.toResponse, Response.structurallyValid,
      CoreResponse.structurallyValid] using valid

def StepInput.checkedFor (input : StepInput) (command : Command) : Bool :=
  input.operandBytes == command.expectedOperandBytes.getD 0 &&
    decide (input.operandBits.toNat < 2 ^ (8 * input.operandBytes))

theorem StepInput.validFor_of_checked (input : StepInput) (command : Command)
    (checked : input.checkedFor command = true) : input.validFor command := by
  simpa [StepInput.checkedFor, StepInput.validFor, Bool.and_eq_true] using checked

theorem StepInput.checkedFor_of_valid (input : StepInput) (command : Command)
    (valid : input.validFor command) : input.checkedFor command = true := by
  simpa [StepInput.checkedFor, StepInput.validFor, Bool.and_eq_true,
    decide_eq_true_eq] using valid

def Response.checkedFor (response : Response) (command : Command)
    (waitMode : WaitMode) : Bool :=
  decide (response.store.map StoreResult.kind = command.expectedStoreKind) &&
    (response.store.all StoreResult.checked &&
    (decide (response.register.map RegisterResult.target =
      command.expectedRegisterTarget) &&
    (decide (response.eflagsWriteMask = command.eflagsWriteMask) &&
    (decide (response.definedness.eflagsMask = response.eflagsWriteMask) &&
    (decide (response.store.isNone →
      response.definedness.storeMask = BitVec.ofNat 80 0) &&
    (decide (response.register.isNone →
      response.definedness.registerMask = BitVec.ofNat 32 0) &&
    (decide (response.fault.isSome → waitMode = .waiting) &&
      decide (command = .wait → waitMode = .waiting))))))))

theorem Response.structurallyValid_of_checked (response : Response)
    (command : Command) (waitMode : WaitMode)
    (checked : response.checkedFor command waitMode = true) :
    response.structurallyValid command waitMode := by
  simpa only [Response.checkedFor, Response.structurallyValid,
    Bool.and_eq_true, decide_eq_true_eq] using checked

theorem Response.checkedFor_of_structurallyValid (response : Response)
    (command : Command) (waitMode : WaitMode)
    (valid : response.structurallyValid command waitMode) :
    response.checkedFor command waitMode = true := by
  simpa only [Response.checkedFor, Response.structurallyValid,
    Bool.and_eq_true, decide_eq_true_eq] using valid

/-- Numeric behavior is parametric. Initial relational proofs require identical
commands and related raw inputs, then use congruence of this shared deterministic
step function. No placeholder IEEE-754 result is trusted. -/
structure Semantics where
  step : Command -> WaitMode -> CoreState -> OperandInput -> CoreResponse
  qualified : ∀ command waitMode state input,
    command.waitModeValid waitMode →
    input.validFor command →
      (step command waitMode state input).structurallyValid command waitMode

def Semantics.execute (semantics : Semantics) (command : Command)
    (waitMode : WaitMode) (state : PhysicalState) (input : StepInput) : Response :=
  (semantics.step command waitMode state.core input.operand).toResponse
    state command input

def Semantics.Complies (semantics : Semantics) : Prop :=
  ∀ command waitMode state input,
    command.waitModeValid waitMode →
    input.validFor command →
      (semantics.step command waitMode state input).structurallyValid command waitMode

theorem Semantics.complies (semantics : Semantics) : semantics.Complies :=
  semantics.qualified

theorem Semantics.step_congr (semantics : Semantics)
    {originalCommand candidateCommand : Command}
    {originalWait candidateWait : WaitMode}
    {originalState candidateState : CoreState}
    {originalInput candidateInput : OperandInput}
    (command : originalCommand = candidateCommand)
    (waitMode : originalWait = candidateWait)
    (state : originalState = candidateState)
    (input : originalInput = candidateInput) :
    semantics.step originalCommand originalWait originalState originalInput =
      semantics.step candidateCommand candidateWait candidateState candidateInput := by
  subst candidateCommand
  subst candidateWait
  subst candidateState
  subst candidateInput
  rfl

theorem Semantics.step_structurallyValid (semantics : Semantics)
    (complies : semantics.Complies) (command : Command) (waitMode : WaitMode)
    (state : CoreState) (input : OperandInput)
    (modeValid : command.waitModeValid waitMode)
    (valid : input.validFor command) :
    (semantics.step command waitMode state input).structurallyValid command waitMode :=
  complies command waitMode state input modeValid valid

theorem Semantics.execute_structurallyValid (semantics : Semantics)
    (complies : semantics.Complies) (command : Command) (waitMode : WaitMode)
    (state : PhysicalState) (input : StepInput)
    (modeValid : command.waitModeValid waitMode)
    (valid : input.validFor command) :
    (semantics.execute command waitMode state input).structurallyValid command waitMode := by
  apply CoreResponse.toResponse_structurallyValid
  exact semantics.step_structurallyValid complies command waitMode state.core
    input.operand modeValid (input.operand_validFor command valid)

def zeroDefinedness (command : Command) : Definedness := {
  slotMasks := Vector.replicate 8 (BitVec.ofNat 80 0)
  statusMask := BitVec.ofNat 16 0
  eflagsMask := command.eflagsWriteMask
  storeMask := BitVec.ofNat 80 0
  registerMask := BitVec.ofNat 32 0
}

/-- A deterministic constructor default, not an architectural x87 model.
Acceptance quantifies over the shared semantics carried by the program and
never treats this value as qualification evidence. -/
def defaultSemantics : Semantics := {
  step := fun command _ state _ => {
    nextState := state
    store := command.expectedStoreKind.map fun kind => {
      kind
      bits := BitVec.ofNat 80 0
    }
    register := command.expectedRegisterTarget.map fun target => {
      target
      value := BitVec.ofNat 32 0
    }
    eflagsValue := BitVec.ofNat 32 0
    eflagsWriteMask := command.eflagsWriteMask
    definedness := zeroDefinedness command
    fault := none
  }
  qualified := by
    intro command waitMode state input modeValid inputValid
    cases command <;>
      simp_all [CoreResponse.structurallyValid, zeroDefinedness,
        Command.expectedStoreKind, Command.expectedRegisterTarget,
        Command.eflagsWriteMask, Command.waitModeValid,
        Command.expectedWaitMode, StoreResult.checked]
    all_goals
      apply Nat.pow_pos
      decide
}

end StageA.X87
