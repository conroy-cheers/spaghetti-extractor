import StageA.Decode

namespace StageA.Formal

inductive InstructionResult where
  | next (state : SymbolicBehavior)
  | stop (state : SymbolicBehavior)

def lowestSetBitExpression (value : Expr) : Nat -> Nat -> Expr
  | _, 0 => .constant 32
  | index, fuel + 1 =>
      .ifEqual (.bitValue value index) (.constant 1) (.constant index)
        (lowestSetBitExpression value (index + 1) fuel)

def highestSetBitExpression (value : Expr) : Nat -> Nat -> Expr
  | _, 0 => .constant 0
  | index, fuel + 1 =>
      .ifEqual (.bitValue value index) (.constant 1) (.constant index)
        (highestSetBitExpression value (index - 1) fuel)

theorem eval_lowestSetBitExpression (state : MachineState) (value : Expr) (index fuel : Nat) :
    (lowestSetBitExpression value index fuel).eval state =
      lowestSetBitValue (value.eval state) index fuel := by
  induction fuel generalizing index with
  | zero => rfl
  | succ fuel inductionHypothesis =>
      simp only [lowestSetBitExpression, Expr.eval, lowestSetBitValue]
      split
      · rfl
      · exact inductionHypothesis (index + 1)

theorem eval_highestSetBitExpression (state : MachineState) (value : Expr) (index fuel : Nat) :
    (highestSetBitExpression value index fuel).eval state =
      highestSetBitValue (value.eval state) index fuel := by
  induction fuel generalizing index with
  | zero => rfl
  | succ fuel inductionHypothesis =>
      simp only [highestSetBitExpression, Expr.eval, highestSetBitValue]
      split
      · rfl
      · exact inductionHypothesis (index - 1)

theorem eval_lowestSetBit_compact (state : MachineState) (value : Expr) :
    (Expr.lowestSetBit value).eval state =
      (lowestSetBitExpression value 0 32).eval state := by
  rw [eval_lowestSetBitExpression]
  rfl

theorem eval_highestSetBit_compact (state : MachineState) (value : Expr) :
    (Expr.highestSetBit value).eval state =
      (highestSetBitExpression value 31 32).eval state := by
  rw [eval_highestSetBitExpression]
  rfl

structure SymbolicImageContext where
  imageBase : Nat
  immutableImageWord : Nat -> Nat -> Option Nat

def SymbolicImageContext.ofPE (pe : PE32) : SymbolicImageContext := {
  imageBase := pe.imageBase
  immutableImageWord := readImmutableImageWord pe
}

def x87LoadExpressionInContext (context : SymbolicImageContext)
    (format : X87LoadFormat)
    (address control : Expr) : X87Expr :=
  match address with
  | .constant absolute =>
      match context.immutableImageWord absolute format.byteWidth with
      | some raw => .imageLoad format raw control
      | none => .load format address control
  | _ => .load format address control

def x87LoadExpression (pe : PE32) (format : X87LoadFormat)
    (address control : Expr) : X87Expr :=
  x87LoadExpressionInContext (.ofPE pe) format address control

def ShiftCount.expression (state : SymbolicBehavior) : ShiftCount -> Expr
  | .immediate amount => .constant (amount % 32)
  | .cl => .bitAnd (state.registers.get .ecx) (.constant 0x1f)

def ShiftCount.isMaskedZero : ShiftCount -> Bool
  | .immediate amount => amount % 32 == 0
  | .cl => false

def selectBool (condition thenValue elseValue : BoolExpr) : BoolExpr :=
  .equal
    (.ifEqual condition.toWord (.constant 1)
      thenValue.toWord elseValue.toWord)
    (.constant 1)

def flagsForMaskedShift (bits : Nat) (amount result currentEflags : Expr)
    (carry overflowAtOne : BoolExpr) (undefinedSlot : Nat) : FlagsExpr :=
  let countIsZero := BoolExpr.equal amount (.constant 0)
  let countIsOne := BoolExpr.equal amount (.constant 1)
  let preserveAtZero (index : Nat) (updated : BoolExpr) :=
    selectBool countIsZero (.bit currentEflags index) updated
  let undefinedAuxiliary := BoolExpr.bit (.undefined undefinedSlot) 0
  let undefinedOverflow := BoolExpr.bit (.undefined undefinedSlot) 4
  {
    zero := some (preserveAtZero 6 (.equal result (.constant 0)))
    carry := some (preserveAtZero 0 carry)
    auxiliary := some (preserveAtZero 4 undefinedAuxiliary)
    sign := some (preserveAtZero 7 (.bit result (bits - 1)))
    overflow := some (preserveAtZero 11
      (selectBool countIsOne overflowAtOne undefinedOverflow))
    parity := some (preserveAtZero 2 (parityExpression result))
  }

def ordinaryShiftFlags (bits : Nat) (operation : ShiftOperation)
    (value result amount currentEflags : Expr)
    (undefinedSlot : Nat) : FlagsExpr :=
  let carryValue :=
    match operation with
    | .left =>
        .bitAnd
          (.shiftRightBy value
            (Expr.subNormalized (.constant bits) amount))
          (.constant 1)
    | .right | .arithmeticRight =>
        .bitAnd
          (.shiftRightBy value
            (Expr.subNormalized amount (.constant 1)))
          (.constant 1)
  let computedCarry := BoolExpr.equal carryValue (.constant 1)
  let carryDefined :=
    BoolExpr.not (.unsignedLess (.constant bits) amount)
  let carry :=
    selectBool carryDefined computedCarry
      (.bit (.undefined undefinedSlot) 1)
  let overflowAtOne :=
    match operation with
    | .left => .xor (.bit result (bits - 1)) computedCarry
    | .right => .bit value (bits - 1)
    | .arithmeticRight => .equal (.constant 0) (.constant 1)
  flagsForMaskedShift bits amount result currentEflags carry overflowAtOne
    undefinedSlot

def doubleShiftFlags (left : Bool) (destinationValue result amount
    currentEflags : Expr) (undefinedSlot : Nat) : FlagsExpr :=
  let carryValue :=
    if left then
      .bitAnd
        (.shiftRightBy destinationValue
          (Expr.subNormalized (.constant 32) amount))
        (.constant 1)
    else
      .bitAnd
        (.shiftRightBy destinationValue
          (Expr.subNormalized amount (.constant 1)))
        (.constant 1)
  let carry := BoolExpr.equal carryValue (.constant 1)
  let overflowAtOne :=
    if left then
      BoolExpr.xor (.msb result) carry
    else
      BoolExpr.xor (.msb destinationValue) (.msb result)
  flagsForMaskedShift 32 amount result currentEflags carry overflowAtOne
    undefinedSlot

def executeInstructionWithContext (context : SymbolicImageContext)
    (imports : List PEImport)
    (pc undefinedSlot : Nat) (decoded : DecodedInstruction)
    (state : SymbolicBehavior) : Option InstructionResult :=
  let nextRva := pc + decoded.size
  match decoded.instruction with
  | .nop => some (.next state)
  | .ret =>
      let stack := state.registers.esp
      let target := symbolicRead32 state stack
      some (.stop {
        state with
        registers := state.registers.set .esp (stack.offset 4)
        outcome := some (.returned target)
      })
  | .retPop bytes =>
      let stack := state.registers.esp
      let target := symbolicRead32 state stack
      some (.stop {
        state with
        registers := state.registers.set .esp (stack.offset (4 + bytes))
        outcome := some (.returned target)
      })
  | .movRegImm destination value =>
      some (.next { state with registers := state.registers.set destination (.constant value) })
  | .movRegReg destination source =>
      some (.next { state with registers := state.registers.set destination (state.registers.get source) })
  | .addZero destination =>
      let value := state.registers.get destination
      some (.next {
        state with
        comparison := some (value, .constant 0)
        flags := some (additionFlags value (.constant 0) value)
      })
  | .subZero destination =>
      let value := state.registers.get destination
      some (.next {
        state with
        comparison := some (value, .constant 0)
        flags := some (subtractionFlags value (.constant 0) value)
      })
  | .cmpImm source value =>
      let left := state.registers.get source
      let right := .constant value
      let result := Expr.subNormalized left right
      some (.next {
        state with
        comparison := some (left, right)
        flags := some (subtractionFlags left right result)
      })
  | .branchEqual inverted displacement => do
      let condition <-
        match state.flags with
        | some flags => flags.zero
        | none => state.comparison.map (fun comparison => .equal comparison.1 comparison.2)
      let condition := if inverted then .not condition else condition
      some (.stop { state with outcome := some (.branch condition (relativeTarget8 nextRva displacement) nextRva) })
  | .jumpRel8 displacement =>
      some (.stop { state with outcome := some (.jump (relativeTarget8 nextRva displacement)) })
  | .jumpRel32 displacement =>
      some (.stop { state with outcome := some (.jump (relativeTarget32 nextRva displacement)) })
  | .pushReg source =>
      let stack := state.registers.esp.offset (2 ^ 32 - 4)
      let state := state.write32 stack (state.registers.get source)
      some (.next { state with registers := state.registers.set .esp stack })
  | .pushFlags =>
      let stack := state.registers.esp.offset (2 ^ 32 - 4)
      let value := .bitAnd state.eflagsExpression (.constant 0xfffcffff)
      let state := state.write32 stack value
      some (.next { state with registers := state.registers.set .esp stack })
  | .pushAll =>
      let originalStack := state.registers.esp
      let eaxStack := originalStack.offset (2 ^ 32 - 4)
      let ecxStack := originalStack.offset (2 ^ 32 - 8)
      let edxStack := originalStack.offset (2 ^ 32 - 12)
      let ebxStack := originalStack.offset (2 ^ 32 - 16)
      let espStack := originalStack.offset (2 ^ 32 - 20)
      let ebpStack := originalStack.offset (2 ^ 32 - 24)
      let esiStack := originalStack.offset (2 ^ 32 - 28)
      let ediStack := originalStack.offset (2 ^ 32 - 32)
      let state := state.write32 eaxStack state.registers.eax
      let state := state.write32 ecxStack state.registers.ecx
      let state := state.write32 edxStack state.registers.edx
      let state := state.write32 ebxStack state.registers.ebx
      let state := state.write32 espStack originalStack
      let state := state.write32 ebpStack state.registers.ebp
      let state := state.write32 esiStack state.registers.esi
      let state := state.write32 ediStack state.registers.edi
      some (.next {
        state with registers := state.registers.set .esp ediStack
      })
  | .pushOperand source =>
      let value := readOperand32 state source
      let stack := state.registers.esp.offset (2 ^ 32 - 4)
      let state := state.write32 stack value
      some (.next { state with registers := state.registers.set .esp stack })
  | .movFs32 destination source =>
      let address := Expr.addNormalized (.inputFsBase) (source.expression state.registers)
      some (.next { state with registers := state.registers.set destination (symbolicRead32 state address) })
  | .movToFs32 destination source =>
      let address := Expr.addNormalized (.inputFsBase)
        (destination.expression state.registers)
      some (.next (state.write32 address (state.registers.get source)))
  | .popReg destination =>
      let value := symbolicRead32 state state.registers.esp
      let stack := state.registers.esp.offset 4
      some (.next { state with registers := (state.registers.set destination value).set .esp stack })
  | .popAll =>
      let stack := state.registers.esp
      let edi := symbolicRead32 state stack
      let esi := symbolicRead32 state (stack.offset 4)
      let ebp := symbolicRead32 state (stack.offset 8)
      let ebx := symbolicRead32 state (stack.offset 16)
      let edx := symbolicRead32 state (stack.offset 20)
      let ecx := symbolicRead32 state (stack.offset 24)
      let eax := symbolicRead32 state (stack.offset 28)
      some (.next {
        state with registers := {
          eax := eax
          ebx := ebx
          ecx := ecx
          edx := edx
          esi := esi
          edi := edi
          ebp := ebp
          esp := stack.offset 32
        }
      })
  | .popFlags =>
      let stack := state.registers.esp
      let popped := symbolicRead32 state stack
      let restored := popFlagsCpl3Expression state.eflagsExpression popped
      some (.next {
        state with
        registers := state.registers.set .esp (stack.offset 4)
        flagsBase := some restored
        flags := some (flagsFromWordExpression restored)
        comparison := none
      })
  | .clearCarry =>
      let base := Expr.bitAnd state.eflagsExpression (.constant 0xfffffffe)
      some (.next {
        state with
        flagsBase := some base
        flags := some (flagsFromWordExpression base)
        comparison := none
      })
  | .clearDirection =>
      let base := Expr.bitAnd state.eflagsExpression (.constant 0xfffffbff)
      some (.next {
        state with
        flagsBase := some base
        flags := some (flagsFromWordExpression base)
        comparison := none
      })
  | .setDirection =>
      let base := Expr.bitOr state.eflagsExpression (.constant 0x00000400)
      some (.next {
        state with
        flagsBase := some base
        flags := some (flagsFromWordExpression base)
        comparison := none
      })
  | .leave =>
      let stack := state.registers.ebp
      let value := symbolicRead32 state stack
      some (.next {
        state with
        registers := (state.registers.set .ebp value).set .esp (stack.offset 4)
      })
  | .lea destination base offset =>
      some (.next { state with registers := state.registers.set destination ((state.registers.get base).offset offset) })
  | .load32 destination base offset =>
      let value := symbolicRead32 state ((state.registers.get base).offset offset)
      some (.next { state with registers := state.registers.set destination value })
  | .store32 base offset source =>
      some (.next (state.write32 ((state.registers.get base).offset offset) (state.registers.get source)))
  | .zeroReg destination =>
      some (.next {
        state with
        registers := state.registers.set destination (.constant 0)
        comparison := some (.constant 0, .constant 0)
        flags := some (logicalFlags undefinedSlot (.constant 0))
      })
  | .callRel32 displacement =>
      let stack := state.registers.esp.offset (2 ^ 32 - 4)
      let state := state.write32 stack
        (.constant (context.imageBase + nextRva))
      some (.stop {
        state with
        registers := state.registers.set .esp stack
        outcome := some (.call (relativeTarget32 nextRva displacement) nextRva
          (context.imageBase + nextRva))
      })
  | .callImport absoluteAddress =>
      match importAtAbsoluteAddressFrom context.imageBase imports absoluteAddress with
      | some imported => some (.stop { state with outcome := some (.externalCall imported [] nextRva) })
      | none =>
          let target := symbolicRead32 state (.constant absoluteAddress)
          let stack := state.registers.esp.offset (2 ^ 32 - 4)
          let state := state.write32 stack
            (.constant (context.imageBase + nextRva))
          some (.stop {
            state with
            registers := state.registers.set .esp stack
            outcome := some (.indirectCall target nextRva
              (context.imageBase + nextRva))
          })
  | .jumpImport absoluteAddress =>
      match importAtAbsoluteAddressFrom context.imageBase imports absoluteAddress with
      | some imported => some (.stop { state with outcome := some (.externalJump imported []) })
      | none => some (.stop {
          state with outcome := some (.indirectJump (symbolicRead32 state (.constant absoluteAddress)))
        })
  | .movFromOperand destination source =>
      some (.next { state with registers := state.registers.set destination (readOperand32 state source) })
  | .movToOperand destination source => do
      let next <- writeOperand32 state destination (state.registers.get source)
      some (.next next)
  | .movImmediate destination value => do
      let next <- writeOperand32 state destination (.constant value)
      some (.next next)
  | .leaAddress destination source =>
      some (.next { state with registers := state.registers.set destination (source.expression state.registers) })
  | .binary operation destination source => do
      let left := readOperand32 state destination
      let right := readOperand32 state source
      let result :=
        match operation with
        | .add => Expr.addNormalized left right
        | .sub | .compare => Expr.subNormalized left right
        | .xor => Expr.xorNormalized left right
        | .and | .test => .bitAnd left right
        | .or => .bitOr left right
      let flags :=
        match operation with
        | .add => additionFlags left right result
        | .sub | .compare => subtractionFlags left right result
        | .xor | .and | .or | .test => logicalFlags undefinedSlot result
      let next <-
        match operation with
        | .compare | .test => some state
        | _ => writeOperand32 state destination result
      some (.next { next with flags := some flags })
  | .shift operation destination count =>
      match destination with
      | .immediate _ => none
      | .register _ | .memory _ => do
          if count.isMaskedZero then
            some (.next state)
          else
            let value := readOperand32 state destination
            let amount := count.expression state
            let result :=
              match operation with
              | .left => Expr.shiftLeftBy value amount
              | .right => Expr.shiftRightBy value amount
              | .arithmeticRight =>
                  Expr.shiftArithmeticRightBy value amount
            let currentEflags := state.eflagsExpression
            let next <- writeOperand32 state destination result
            let flags := ordinaryShiftFlags 32 operation value result amount
              currentEflags undefinedSlot
            some (.next {
              next with
              flagsBase := some currentEflags
              flags := some flags
              comparison := none
            })
  | .shiftWidth width operation destination count =>
      match destination with
      | .immediate _ => none
      | .register _ | .memory _ => do
          if count.isMaskedZero then
            some (.next state)
          else
            let bits := width.bits
            let mask := 2 ^ bits - 1
            let value := readOperandWidth width state destination
            let amount := count.expression state
            let shiftInput :=
              match operation with
              | .arithmeticRight => value.signExtendNormalized bits
              | .left | .right => value
            let rawResult :=
              match operation with
              | .left => Expr.shiftLeftBy shiftInput amount
              | .right => Expr.shiftRightBy shiftInput amount
              | .arithmeticRight =>
                  Expr.shiftArithmeticRightBy shiftInput amount
            let result := Expr.bitAnd rawResult (.constant mask)
            let currentEflags := state.eflagsExpression
            let next <- writeOperandWidth width state destination result
            let flags := ordinaryShiftFlags bits operation value result amount
              currentEflags undefinedSlot
            some (.next {
              next with
              flagsBase := some currentEflags
              flags := some flags
              comparison := none
            })
  | .shift8 operation destination count =>
      match destination with
      | .immediate _ => none
      | .register _ | .memory _ => do
          if count.isMaskedZero then
            some (.next state)
          else
            let value :=
              Expr.bitAnd (readOperand8 state destination) (.constant 0xff)
            let amount := count.expression state
            let shiftInput :=
              match operation with
              | .arithmeticRight => value.signExtendNormalized 8
              | .left | .right => value
            let rawResult :=
              match operation with
              | .left => Expr.shiftLeftBy shiftInput amount
              | .right => Expr.shiftRightBy shiftInput amount
              | .arithmeticRight =>
                  Expr.shiftArithmeticRightBy shiftInput amount
            let result := Expr.bitAnd rawResult (.constant 0xff)
            let currentEflags := state.eflagsExpression
            let next <- writeOperand8 state destination result
            let flags := ordinaryShiftFlags 8 operation value result amount
              currentEflags undefinedSlot
            some (.next {
              next with
              flagsBase := some currentEflags
              flags := some flags
              comparison := none
            })
  | .unary operation destination => do
      let value := readOperand32 state destination
      let result :=
        match operation with
        | .bitNot => .bitNot value
        | .negate => Expr.subNormalized (.constant 0) value
        | .increment => Expr.addNormalized value (.constant 1)
        | .decrement => Expr.subNormalized value (.constant 1)
      let next <- writeOperand32 state destination result
      match operation with
      | .bitNot => some (.next { next with flags := state.flags })
      | .negate =>
          some (.next {
            next with
            flags := some (subtractionFlags (.constant 0) value result)
          })
      | .increment =>
          let currentEflags := state.eflagsExpression
          some (.next {
            next with
            flagsBase := some currentEflags
            flags := some {
              additionFlags value (.constant 1) result with carry := none
            }
            comparison := none
          })
      | .decrement =>
          let currentEflags := state.eflagsExpression
          some (.next {
            next with
            flagsBase := some currentEflags
            flags := some {
              subtractionFlags value (.constant 1) result with carry := none
            }
            comparison := none
          })
  | .branchCondition condition displacement size => do
      let flags <- state.flags
      let condition <- conditionExpression flags condition
      let target := if size == 2 then relativeTarget8 nextRva displacement else relativeTarget32 nextRva displacement
      some (.stop {
        state with outcome := some (.branch condition target nextRva)
      })
  | .movZeroExtend destination source width =>
      let value :=
        match source, width with
        | .memory addressing, 8 => symbolicRead8 state (addressing.expression state.registers)
        | .memory addressing, 16 => symbolicRead16 state (addressing.expression state.registers)
        | .register reg, 8 => .bitAnd (state.registers.get reg) (.constant 0xff)
        | .register reg, 16 => .bitAnd (state.registers.get reg) (.constant 0xffff)
        | .immediate value, 8 => .constant (value % 256)
        | .immediate value, 16 => .constant (value % 65536)
        | _, _ => .constant 0
      some (.next { state with registers := state.registers.set destination value })
  | .movSignExtend destination source width =>
      let value :=
        match source, width with
        | .memory addressing, 8 => symbolicRead8 state (addressing.expression state.registers)
        | .memory addressing, 16 => symbolicRead16 state (addressing.expression state.registers)
        | .register reg, 8 => .bitAnd (state.registers.get reg) (.constant 0xff)
        | .register reg, 16 => .bitAnd (state.registers.get reg) (.constant 0xffff)
        | .immediate value, 8 => .constant (value % 256)
        | .immediate value, 16 => .constant (value % 65536)
        | _, _ => .constant 0
      some (.next { state with registers := state.registers.set destination (value.signExtendNormalized width) })
  | .movSignExtend8 destination source =>
      let value := (readOperand8 state source).signExtendNormalized 8
      some (.next { state with registers := state.registers.set destination value })
  | .movSignExtend8ToWord destination source => do
      let value := (readOperand8 state source).signExtendNormalized 8
      let next <- writeOperandWidth .word state (.register destination) value
      some (.next next)
  | .movFromOperandWidth width destination source =>
      let value := readOperandWidth width state source
      writeOperandWidth width state (.register destination) value |>.map InstructionResult.next
  | .movToOperandWidth width destination source =>
      let value := readOperandWidth width state (.register source)
      writeOperandWidth width state destination value |>.map InstructionResult.next
  | .movImmediateWidth width destination value =>
      writeOperandWidth width state destination (.constant value) |>.map InstructionResult.next
  | .binaryWidth width operation destination source => do
      let bits := width.bits
      let left := readOperandWidth width state destination
      let right := readOperandWidth width state source
      let rawResult :=
        match operation with
        | .add => Expr.addNormalized left right
        | .sub | .compare => Expr.subNormalized left right
        | .xor => Expr.xorNormalized left right
        | .and | .test => .bitAnd left right
        | .or => .bitOr left right
      let result := Expr.bitAnd rawResult (.constant (2 ^ bits - 1))
      let flags :=
        match operation with
        | .add => additionFlagsWidth bits left right result
        | .sub | .compare => subtractionFlagsWidth bits left right result
        | .xor | .and | .or | .test => logicalFlagsWidth undefinedSlot bits result
      let next <-
        match operation with
        | .compare | .test => some state
        | _ => writeOperandWidth width state destination result
      some (.next { next with flags := some flags })
  | .movFromOperand8 destination source =>
      some (.next (writeByteRegister state destination (readOperand8 state source)))
  | .movToOperand8 destination source =>
      writeOperand8 state destination (readByteRegister state source) |>.map InstructionResult.next
  | .movImmediate8 destination value =>
      writeOperand8 state destination (.constant value) |>.map InstructionResult.next
  | .binary8 operation destination source => do
      let left := readOperand8 state destination
      let right := readOperand8 state source
      let rawResult :=
        match operation with
        | .add => Expr.addNormalized left right
        | .sub | .compare => Expr.subNormalized left right
        | .xor => Expr.xorNormalized left right
        | .and | .test => .bitAnd left right
        | .or => .bitOr left right
      let result := Expr.bitAnd rawResult (.constant 0xff)
      let flags :=
        match operation with
        | .add => additionFlagsWidth 8 left right result
        | .sub | .compare => subtractionFlagsWidth 8 left right result
        | .xor | .and | .or | .test => logicalFlagsWidth undefinedSlot 8 result
      let next <-
        match operation with
        | .compare | .test => some state
        | _ => writeOperand8 state destination result
      some (.next { next with flags := some flags })
  | .conditionalMove condition destination source => do
      let flags <- state.flags
      let condition <- conditionExpression flags condition
      let selected := .ifEqual condition.toWord (.constant 1)
        (readOperand32 state source) (state.registers.get destination)
      some (.next { state with registers := state.registers.set destination selected })
  | .setCondition condition destination => do
      let flags <- state.flags
      let condition <- conditionExpression flags condition
      let value := .ifEqual condition.toWord (.constant 1)
        (.constant 1) (.constant 0)
      let next <- writeOperand8 state destination value
      some (.next next)
  | .exchange destination source => do
      let destinationValue := readOperand32 state destination
      let sourceValue := state.registers.get source
      let next <- writeOperand32 state destination sourceValue
      some (.next { next with registers := next.registers.set source destinationValue })
  | .convertWordToDword =>
      let value := (state.registers.get .eax).signExtendNormalized 16
      some (.next { state with registers := state.registers.set .eax value })
  | .convertDwordToQuad =>
      let value := .ifEqual (.bitValue (state.registers.get .eax) 31) (.constant 1)
        (.constant (2 ^ 32 - 1)) (.constant 0)
      some (.next { state with registers := state.registers.set .edx value })
  | .binaryCarry subtract destination source => do
      let flags <- state.flags
      let carryIn <- flags.carry
      let left := readOperand32 state destination
      let right := readOperand32 state source
      let carryValue := carryIn.toWord
      let result :=
        if subtract then
          Expr.subNormalized (Expr.subNormalized left right) carryValue
        else
          Expr.addNormalized (Expr.addNormalized left right) carryValue
      let next <- writeOperand32 state destination result
      let nextFlags := if subtract then sbbFlags left right result carryIn else adcFlags left right result carryIn
      some (.next { next with flags := some nextFlags })
  | .multiplyFull signed source =>
      let left := state.registers.get .eax
      let right := readOperand32 state source
      let low := Expr.multiply left right
      let high := if signed then Expr.multiplyHighSigned left right else Expr.multiplyHighUnsigned left right
      let signFill := Expr.ifEqual (.bitValue low 31) (.constant 1)
        (.constant (2 ^ 32 - 1)) (.constant 0)
      let expectedHigh := if signed then signFill else .constant 0
      let overflow := BoolExpr.not (.equal high expectedHigh)
      some (.next {
        state with
        registers := (state.registers.set .eax low).set .edx high
        flags := some (multiplicationFlags undefinedSlot overflow)
        comparison := none
      })
  | .multiplyLow destination source immediate =>
      let left := state.registers.get destination
      let right := immediate.map (fun value => Expr.constant value) |>.getD (readOperand32 state source)
      let left := if immediate.isSome then readOperand32 state source else left
      let result := Expr.multiply left right
      let high := Expr.multiplyHighSigned left right
      let signFill := Expr.ifEqual (.bitValue result 31) (.constant 1)
        (.constant (2 ^ 32 - 1)) (.constant 0)
      let overflow := BoolExpr.not (.equal high signFill)
      some (.next {
        state with
        registers := state.registers.set destination result
        flags := some (multiplicationFlags undefinedSlot overflow)
        comparison := none
      })
  | .doubleShift left destination source count =>
      match destination with
      | .immediate _ => none
      | .register _ | .memory _ => do
          if count.isMaskedZero then
            some (.next state)
          else
            let destinationValue := readOperand32 state destination
            let sourceValue := state.registers.get source
            let amount := count.expression state
            let inverse := Expr.subNormalized (.constant 32) amount
            let shifted :=
              if left then
                .bitOr (.shiftLeftBy destinationValue amount)
                  (.shiftRightBy sourceValue inverse)
              else
                .bitOr (.shiftRightBy destinationValue amount)
                  (.shiftLeftBy sourceValue inverse)
            let result := Expr.ifEqual amount (.constant 0)
              destinationValue shifted
            let currentEflags := state.eflagsExpression
            let next <- writeOperand32 state destination result
            let flags := doubleShiftFlags left destinationValue result amount
              currentEflags undefinedSlot
            some (.next {
              next with
              flagsBase := some currentEflags
              flags := some flags
              comparison := none
            })
  | .bitScan operation destination source =>
      let value := readOperand32 state source
      let zero := BoolExpr.equal value (.constant 0)
      let currentEflags := state.eflagsExpression
      let result :=
        match operation with
        | .forward =>
            .ifEqual value (.constant 0) (.undefined undefinedSlot)
              (.lowestSetBit value)
        | .reverse =>
            .ifEqual value (.constant 0) (.undefined undefinedSlot)
              (.highestSetBit value)
        | .trailingZeroCount _ => .lowestSetBit value
      let undefinedCarry := BoolExpr.bit (.undefined undefinedSlot) 0
      let undefinedParity := BoolExpr.bit (.undefined undefinedSlot) 1
      let undefinedAuxiliary := BoolExpr.bit (.undefined undefinedSlot) 2
      let undefinedSign := BoolExpr.bit (.undefined undefinedSlot) 3
      let undefinedOverflow := BoolExpr.bit (.undefined undefinedSlot) 4
      let flags : FlagsExpr :=
        match operation with
        | .forward | .reverse => {
            zero := some zero
            carry := some undefinedCarry
            auxiliary := some undefinedAuxiliary
            sign := some undefinedSign
            overflow := some undefinedOverflow
            parity := some undefinedParity
          }
        | .trailingZeroCount _ => {
            zero := some (.equal result (.constant 0))
            carry := some zero
            auxiliary := some undefinedAuxiliary
            sign := some undefinedSign
            overflow := some undefinedOverflow
            parity := some undefinedParity
          }
      some (.next {
        state with
        registers := state.registers.set destination result
        flagsBase := some currentEflags
        flags := some flags
        comparison := none
      })
  | .bitTestRegister base index =>
      let baseValue := state.registers.get base
      let bitIndex := .bitAnd (state.registers.get index) (.constant 0x1f)
      let selected := .bitAnd (.shiftRightBy baseValue bitIndex) (.constant 1)
      let flags : FlagsExpr := {
        carry := some (.equal selected (.constant 1))
        parity := some (.bit (.undefined undefinedSlot) 0)
        auxiliary := some (.bit (.undefined undefinedSlot) 1)
        zero := some (.bit (.undefined undefinedSlot) 2)
        sign := some (.bit (.undefined undefinedSlot) 3)
        overflow := some (.bit (.undefined undefinedSlot) 4)
      }
      some (.next { state with flags := some flags, comparison := none })
  | .x87LoadStack index => do
      let value <- state.x87.get index
      some (.next { state with x87 := state.x87.push value })
  | .x87LoadConstant value =>
      some (.next { state with x87 := state.x87.push (.constant value) })
  | .x87Exchange index => do
      let top <- state.x87.get 0
      let other <- state.x87.get index
      let exchanged <- state.x87.set 0 other >>= fun next => next.set index top
      some (.next { state with x87 := exchanged })
  | .x87StoreStack index pop => do
      let top <- state.x87.get 0
      let stored <- state.x87.set index top
      let nextX87 <- if pop then stored.pop else some stored
      some (.next { state with x87 := nextX87 })
  | .x87Unary operation => do
      let top <- state.x87.get 0
      let value := X87Expr.unary operation top state.x87.control
      let nextX87 <- state.x87.set 0 value
      some (.next { state with x87 := nextX87 })
  | .x87BinaryStack operation destination source pop => do
      let left <- state.x87.get destination
      let right <- state.x87.get source
      let value := X87Expr.binary operation left right state.x87.control
      let updated <- state.x87.set destination value
      let nextX87 <- if pop then updated.pop else some updated
      some (.next { state with x87 := nextX87 })
  | .x87CompareStack _ .status _ _ => none
  | .x87CompareStack _ .eflags index pop => do
      let left <- state.x87.get 0
      let right <- state.x87.get index
      let nextX87 <- if pop then state.x87.pop else some state.x87
      let falseFlag := BoolExpr.equal (.constant 0) (.constant 1)
      let flags : FlagsExpr := {
        zero := some (.equal (.x87CompareBit left right state.x87.control 2) (.constant 1))
        carry := some (.equal (.x87CompareBit left right state.x87.control 0) (.constant 1))
        auxiliary := some falseFlag
        sign := some falseFlag
        overflow := some falseFlag
        parity := some (.equal (.x87CompareBit left right state.x87.control 1) (.constant 1))
      }
      some (.next { state with x87 := nextX87, flags := some flags, comparison := none })
  | .x87CompareMemory _ _ _ _ => none
  | .x87LoadMemory format source =>
      let address := source.expression state.registers
      let value :=
        x87LoadExpressionInContext context format address state.x87.control
      some (.next { state with x87 := state.x87.push value })
  | .x87StoreMemory format destination pop => do
      let top <- state.x87.get 0
      let address := destination.expression state.registers
      let converted := X87Expr.store format top state.x87.control
      let next := state.write32 address (.x87Part converted 0)
      let next :=
        match format with
        | .float64 | .float80 | .int64 =>
            next.write32 (address.offset 4) (.x87Part converted 1)
        | .float32 | .int32 => next
      let destinationHigh : Operand32 := .memory {
        base := destination.base
        index := destination.index
        scaleShift := destination.scaleShift
        displacement := destination.displacement + 8
      }
      let next <-
        match format with
        | .float80 => writeOperandWidth .word next destinationHigh (Expr.x87Part converted 2)
        | .float32 => some next
        | .float64 => some next
        | .int32 => some next
        | .int64 => some next
      let nextX87 <- if pop then next.x87.pop else some next.x87
      some (.next { next with x87 := nextX87 })
  | .x87BinaryMemory operation format source => do
      let top <- state.x87.get 0
      let address := source.expression state.registers
      let right :=
        x87LoadExpressionInContext context format address state.x87.control
      let value := X87Expr.binary operation top right state.x87.control
      let nextX87 <- state.x87.set 0 value
      some (.next { state with x87 := nextX87 })
  | .x87LoadControl source =>
      let control := symbolicRead16 state (source.expression state.registers)
      some (.next { state with x87 := { state.x87 with control } })
  | .x87StoreControl destination => do
      let next <- writeOperandWidth .word state (.memory destination) state.x87.control
      some (.next next)
  | .x87SaveState _ | .x87RestoreState _ =>
      none
  | .x87Wait => none
  | .x87Initialize =>
      some (.next { state with x87 := {
        stack := []
        control := .constant 0x037f
        status := .constant 0
      } })
  | .x87StoreStatusAx => do
      let next <- writeOperandWidth .word state (.register .eax) state.x87.status
      some (.next next)
  | .x87Examine => do
      let top <- state.x87.get 0
      some (.next { state with x87 := {
        state.x87 with status := .x87ExamineStatus top state.x87.status
      } })
  | .moveBytes repeated | .moveWords repeated | .moveDwords repeated =>
      let elementBytes :=
        match decoded.instruction with
        | .moveBytes _ => 1
        | .moveWords _ => 2
        | .moveDwords _ => 4
        | _ => 0
      let destination := state.registers.edi
      let source := state.registers.esi
      let count := if repeated then state.registers.ecx else Expr.constant 1
      let direction := BoolExpr.bit state.eflagsExpression 10
      let distance := Expr.multiply count (.constant elementBytes)
      let nextDestination := .ifEqual direction.toWord (.constant 1)
        (Expr.subNormalized destination distance) (Expr.addNormalized destination distance)
      let nextSource := .ifEqual direction.toWord (.constant 1)
        (Expr.subNormalized source distance) (Expr.addNormalized source distance)
      let registers := (state.registers.set .edi nextDestination).set .esi nextSource
      let registers := if repeated then registers.set .ecx (.constant 0) else registers
      some (.stop {
        state with
        registers
        outcome := some (.bulkCopy {
          destination, source, count, direction, elementBytes
        } nextRva)
      })
  | .storeBytes repeated | .storeWords repeated | .storeDwords repeated =>
      let elementBytes :=
        match decoded.instruction with
        | .storeBytes _ => 1
        | .storeWords _ => 2
        | .storeDwords _ => 4
        | _ => 0
      let destination := state.registers.edi
      let value := state.registers.eax
      let count := if repeated then state.registers.ecx else Expr.constant 1
      let direction := BoolExpr.bit state.eflagsExpression 10
      let distance := Expr.multiply count (.constant elementBytes)
      let nextDestination := .ifEqual direction.toWord (.constant 1)
        (Expr.subNormalized destination distance)
        (Expr.addNormalized destination distance)
      let registers := state.registers.set .edi nextDestination
      let registers :=
        if repeated then registers.set .ecx (.constant 0) else registers
      some (.stop {
        state with
        registers
        outcome := some (.bulkFill {
          destination
          value
          count
          direction
          elementBytes
        } nextRva)
      })
  | .scanByteNotEqual =>
      let destination := state.registers.edi
      let accumulator := Expr.bitAnd state.registers.eax (.constant 0xff)
      let count := state.registers.ecx
      let direction := BoolExpr.bit state.eflagsExpression 10
      some (.stop {
        state with outcome := some (.bulkScan {
          destination
          accumulator
          count
          direction
        } nextRva)
      })
  | .callIndirect target =>
      let target := readOperand32 state target
      let stack := state.registers.esp.offset (2 ^ 32 - 4)
      let state := state.write32 stack
        (.constant (context.imageBase + nextRva))
      some (.stop {
        state with
        registers := state.registers.set .esp stack
        outcome := some (.indirectCall target nextRva
          (context.imageBase + nextRva))
      })
  | .jumpIndirect target =>
      some (.stop { state with outcome := some (.indirectJump (readOperand32 state target)) })
  | .divideUnsigned source =>
      let high := state.registers.edx
      let low := state.registers.eax
      let divisor := readOperand32 state source
      let valid := BoolExpr.divisionValid high low divisor
      let quotient := Expr.ifEqual valid.toWord (.constant 1)
        (.divideQuotient high low divisor) (.undefined undefinedSlot)
      let remainder := Expr.ifEqual valid.toWord (.constant 1)
        (.divideRemainder high low divisor) (.undefined (undefinedSlot + 1))
      some (.stop {
        state with
        registers := (state.registers.set .eax quotient).set .edx remainder
        flags := some (undefinedArithmeticFlags (undefinedSlot + 2))
        comparison := none
        outcome := some (.checkedContinue valid nextRva)
      })
  | .divideSigned source =>
      let high := state.registers.edx
      let low := state.registers.eax
      let divisor := readOperand32 state source
      let dividendNegative := BoolExpr.bit high 31
      let divisorNegative := BoolExpr.bit divisor 31
      let absoluteLow := Expr.ifEqual dividendNegative.toWord (.constant 1)
        (Expr.addNormalized (.bitNot low) (.constant 1)) low
      let lowCarry := Expr.ifEqual low (.constant 0) (.constant 1) (.constant 0)
      let absoluteHigh := Expr.ifEqual dividendNegative.toWord (.constant 1)
        (Expr.addNormalized (.bitNot high) lowCarry) high
      let absoluteDivisor := Expr.ifEqual divisorNegative.toWord (.constant 1)
        (Expr.subNormalized (.constant 0) divisor) divisor
      let quotientMagnitude := Expr.divideQuotient absoluteHigh absoluteLow absoluteDivisor
      let remainderMagnitude := Expr.divideRemainder absoluteHigh absoluteLow absoluteDivisor
      let quotientNegative := BoolExpr.xor dividendNegative divisorNegative
      let quotientBound := Expr.ifEqual quotientNegative.toWord (.constant 1)
        (.constant 0x80000001) (.constant 0x80000000)
      let valid := BoolExpr.and
        (.divisionValid absoluteHigh absoluteLow absoluteDivisor)
        (.unsignedLess quotientMagnitude quotientBound)
      let signedQuotient := Expr.ifEqual quotientNegative.toWord (.constant 1)
        (Expr.subNormalized (.constant 0) quotientMagnitude) quotientMagnitude
      let signedRemainder := Expr.ifEqual dividendNegative.toWord (.constant 1)
        (Expr.subNormalized (.constant 0) remainderMagnitude) remainderMagnitude
      let quotient := Expr.ifEqual valid.toWord (.constant 1)
        signedQuotient (.undefined undefinedSlot)
      let remainder := Expr.ifEqual valid.toWord (.constant 1)
        signedRemainder (.undefined (undefinedSlot + 1))
      some (.stop {
        state with
        registers := (state.registers.set .eax quotient).set .edx remainder
        flags := some (undefinedArithmeticFlags (undefinedSlot + 2))
        comparison := none
        outcome := some (.checkedContinue valid nextRva)
      })
  | .atomicCompareExchange destination source =>
      let address := destination.expression state.registers
      let expected := state.registers.eax
      let replacement := state.registers.get source
      let observed := symbolicRead32 state address
      let written := Expr.ifEqual expected observed replacement observed
      let next := state.write32 address written
      let accumulator := Expr.ifEqual expected observed expected observed
      let result := Expr.subNormalized expected observed
      some (.stop {
        next with
        registers := next.registers.set .eax accumulator
        flags := some (subtractionFlags expected observed result)
        comparison := some (expected, observed)
        outcome := some (.atomicCompareExchange address expected replacement nextRva)
      })

def executeInstruction (pe : PE32) (imports : List PEImport)
    (pc undefinedSlot : Nat) (decoded : DecodedInstruction)
    (state : SymbolicBehavior) : Option InstructionResult :=
  executeInstructionWithContext (.ofPE pe) imports pc undefinedSlot decoded state

end StageA.Formal
