import Lean
import StageA.Formal

namespace StageA.Formal

/-- The addressing distinctions used to group concrete decoder outputs for ISA
conformance. Concrete registers and displacements remain occurrence data; this
shape identifies the semantic implementation that must be qualified. -/
structure AddressingSemanticForm where
  hasBase : Bool
  hasIndex : Bool
  scaleShift : Nat
  hasDisplacement : Bool
deriving Repr, DecidableEq

def Addressing.semanticForm (addressing : Addressing) : AddressingSemanticForm := {
  hasBase := addressing.base.isSome
  hasIndex := addressing.index.isSome
  scaleShift := addressing.scaleShift
  hasDisplacement := addressing.displacement != 0
}

inductive Operand32SemanticForm where
  | register
  | memory (addressing : AddressingSemanticForm)
  | immediate
deriving Repr, DecidableEq

def Operand32.semanticForm : Operand32 -> Operand32SemanticForm
  | .register _ => .register
  | .memory addressing => .memory addressing.semanticForm
  | .immediate _ => .immediate

inductive Operand8SemanticForm where
  | register (high : Bool)
  | memory (addressing : AddressingSemanticForm)
  | immediate
deriving Repr, DecidableEq

def Operand8.semanticForm : Operand8 -> Operand8SemanticForm
  | Operand8.register source => .register source.high
  | Operand8.memory addressing => .memory addressing.semanticForm
  | Operand8.immediate _ => .immediate

/-- An exhaustive, Lean-owned classification of every reviewed instruction
constructor. It is intentionally more precise than a mnemonic: operand shapes,
widths, conditions, operations, and x87 formats select distinct forms. -/
inductive InstructionSemanticForm where
  | nop
  | ret
  | retPop
  | movRegImm
  | movRegReg
  | addZero
  | subZero
  | cmpImm
  | branchEqual (inverted : Bool)
  | jumpRel8
  | jumpRel32
  | pushReg
  | popReg
  | pushFlags
  | pushAll
  | popAll
  | popFlags
  | clearCarry
  | clearDirection
  | setDirection
  | leave
  | lea (hasOffset : Bool)
  | load32 (hasOffset : Bool)
  | store32 (hasOffset : Bool)
  | zeroReg
  | callRel32
  | callImport
  | jumpImport
  | movFromOperand (source : Operand32SemanticForm)
  | movToOperand (destination : Operand32SemanticForm)
  | movImmediate (destination : Operand32SemanticForm)
  | leaAddress (source : AddressingSemanticForm)
  | binary (operation : BinaryOperation)
      (destination source : Operand32SemanticForm)
  | shift (operation : ShiftOperation) (destination : Operand32SemanticForm)
      (count : ShiftCount)
  | shiftWidth (width : OperandWidth) (operation : ShiftOperation)
      (destination : Operand32SemanticForm) (count : ShiftCount)
  | shift8 (operation : ShiftOperation) (destination : Operand8SemanticForm)
      (count : ShiftCount)
  | unary (operation : UnaryOperation) (destination : Operand32SemanticForm)
  | branchCondition (condition : Condition) (size : Nat)
  | movZeroExtend (source : Operand32SemanticForm) (width : Nat)
  | movSignExtend (source : Operand32SemanticForm) (width : Nat)
  | movSignExtend8 (source : Operand8SemanticForm)
  | movSignExtend8ToWord (source : Operand8SemanticForm)
  | movFromOperandWidth (width : OperandWidth) (source : Operand32SemanticForm)
  | movToOperandWidth (width : OperandWidth)
      (destination : Operand32SemanticForm)
  | movImmediateWidth (width : OperandWidth)
      (destination : Operand32SemanticForm)
  | binaryWidth (width : OperandWidth) (operation : BinaryOperation)
      (destination source : Operand32SemanticForm)
  | movFromOperand8 (source : Operand8SemanticForm)
  | movToOperand8 (destination : Operand8SemanticForm)
  | movImmediate8 (destination : Operand8SemanticForm)
  | binary8 (operation : BinaryOperation)
      (destination source : Operand8SemanticForm)
  | conditionalMove (condition : Condition) (source : Operand32SemanticForm)
  | setCondition (condition : Condition) (destination : Operand8SemanticForm)
  | exchange (destination : Operand32SemanticForm)
  | convertWordToDword
  | convertDwordToQuad
  | binaryCarry (subtract : Bool) (destination source : Operand32SemanticForm)
  | multiplyFull (signed : Bool) (source : Operand32SemanticForm)
  | multiplyLow (source : Operand32SemanticForm) (hasImmediate : Bool)
  | doubleShift (left : Bool) (destination : Operand32SemanticForm)
      (count : ShiftCount)
  | bitScan (operation : BitScanOperation) (source : Operand32SemanticForm)
  | bitTestRegister
  | x87LoadStack
  | x87LoadConstant (value : Nat)
  | x87Exchange
  | x87StoreStack (pop : Bool)
  | x87Unary (operation : X87UnaryOperation)
  | x87BinaryStack (operation : X87BinaryOperation) (pop : Bool)
  | x87CompareStack (mode : StageA.X87.CompareMode)
      (destination : StageA.X87.CompareDestination) (pop : Bool)
  | x87LoadMemory (format : X87LoadFormat) (source : AddressingSemanticForm)
  | x87StoreMemory (format : X87StoreFormat)
      (destination : AddressingSemanticForm) (pop : Bool)
  | x87BinaryMemory (operation : X87BinaryOperation) (format : X87LoadFormat)
      (source : AddressingSemanticForm)
  | x87LoadControl (source : AddressingSemanticForm)
  | x87StoreControl (destination : AddressingSemanticForm)
  | x87SaveState (destination : AddressingSemanticForm)
  | x87RestoreState (source : AddressingSemanticForm)
  | x87Wait
  | x87Initialize
  | x87StoreStatusAx
  | x87Examine
  | moveDwords (repeated : Bool)
  | storeDwords (repeated : Bool)
  | scanByteNotEqual
  | callIndirect (target : Operand32SemanticForm)
  | jumpIndirect (target : Operand32SemanticForm)
  | pushOperand (source : Operand32SemanticForm)
  | movFs32 (source : AddressingSemanticForm)
  | divideUnsigned (source : Operand32SemanticForm)
  | divideSigned (source : Operand32SemanticForm)
  | atomicCompareExchange (destination : AddressingSemanticForm)
deriving Repr, DecidableEq

def Instruction.semanticForm : Instruction -> InstructionSemanticForm
  | .nop => .nop
  | .ret => .ret
  | .retPop _ => .retPop
  | .movRegImm _ _ => .movRegImm
  | .movRegReg _ _ => .movRegReg
  | .addZero _ => .addZero
  | .subZero _ => .subZero
  | .cmpImm _ _ => .cmpImm
  | .branchEqual inverted _ => .branchEqual inverted
  | .jumpRel8 _ => .jumpRel8
  | .jumpRel32 _ => .jumpRel32
  | .pushReg _ => .pushReg
  | .popReg _ => .popReg
  | .pushFlags => .pushFlags
  | .pushAll => .pushAll
  | .popAll => .popAll
  | .popFlags => .popFlags
  | .clearCarry => .clearCarry
  | .clearDirection => .clearDirection
  | .setDirection => .setDirection
  | .leave => .leave
  | .lea _ _ offset => .lea (offset != 0)
  | .load32 _ _ offset => .load32 (offset != 0)
  | .store32 _ offset _ => .store32 (offset != 0)
  | .zeroReg _ => .zeroReg
  | .callRel32 _ => .callRel32
  | .callImport _ => .callImport
  | .jumpImport _ => .jumpImport
  | .movFromOperand _ source => .movFromOperand source.semanticForm
  | .movToOperand destination _ => .movToOperand destination.semanticForm
  | .movImmediate destination _ => .movImmediate destination.semanticForm
  | .leaAddress _ source => .leaAddress source.semanticForm
  | .binary operation destination source =>
      .binary operation destination.semanticForm source.semanticForm
  | .shift operation destination count =>
      .shift operation destination.semanticForm count
  | .shiftWidth width operation destination count =>
      .shiftWidth width operation destination.semanticForm count
  | .shift8 operation destination count =>
      .shift8 operation destination.semanticForm count
  | .unary operation destination => .unary operation destination.semanticForm
  | .branchCondition condition _ size => .branchCondition condition size
  | .movZeroExtend _ source width => .movZeroExtend source.semanticForm width
  | .movSignExtend _ source width => .movSignExtend source.semanticForm width
  | .movSignExtend8 _ source => .movSignExtend8 source.semanticForm
  | .movSignExtend8ToWord _ source => .movSignExtend8ToWord source.semanticForm
  | .movFromOperandWidth width _ source =>
      .movFromOperandWidth width source.semanticForm
  | .movToOperandWidth width destination _ =>
      .movToOperandWidth width destination.semanticForm
  | .movImmediateWidth width destination _ =>
      .movImmediateWidth width destination.semanticForm
  | .binaryWidth width operation destination source =>
      .binaryWidth width operation destination.semanticForm source.semanticForm
  | .movFromOperand8 _ source => .movFromOperand8 source.semanticForm
  | .movToOperand8 destination _ => .movToOperand8 destination.semanticForm
  | .movImmediate8 destination _ => .movImmediate8 destination.semanticForm
  | .binary8 operation destination source =>
      .binary8 operation destination.semanticForm source.semanticForm
  | .conditionalMove condition _ source =>
      .conditionalMove condition source.semanticForm
  | .setCondition condition destination =>
      .setCondition condition destination.semanticForm
  | .exchange destination _ => .exchange destination.semanticForm
  | .convertWordToDword => .convertWordToDword
  | .convertDwordToQuad => .convertDwordToQuad
  | .binaryCarry subtract destination source =>
      .binaryCarry subtract destination.semanticForm source.semanticForm
  | .multiplyFull signed source => .multiplyFull signed source.semanticForm
  | .multiplyLow _ source immediate =>
      .multiplyLow source.semanticForm immediate.isSome
  | .doubleShift left destination _ count =>
      .doubleShift left destination.semanticForm count
  | .bitScan operation _ source => .bitScan operation source.semanticForm
  | .bitTestRegister _ _ => .bitTestRegister
  | .x87LoadStack _ => .x87LoadStack
  | .x87LoadConstant value => .x87LoadConstant value
  | .x87Exchange _ => .x87Exchange
  | .x87StoreStack _ pop => .x87StoreStack pop
  | .x87Unary operation => .x87Unary operation
  | .x87BinaryStack operation _ _ pop => .x87BinaryStack operation pop
  | .x87CompareStack mode destination _ pop =>
      .x87CompareStack mode destination pop
  | .x87LoadMemory format source => .x87LoadMemory format source.semanticForm
  | .x87StoreMemory format destination pop =>
      .x87StoreMemory format destination.semanticForm pop
  | .x87BinaryMemory operation format source =>
      .x87BinaryMemory operation format source.semanticForm
  | .x87LoadControl source => .x87LoadControl source.semanticForm
  | .x87StoreControl destination => .x87StoreControl destination.semanticForm
  | .x87SaveState destination => .x87SaveState destination.semanticForm
  | .x87RestoreState source => .x87RestoreState source.semanticForm
  | .x87Wait => .x87Wait
  | .x87Initialize => .x87Initialize
  | .x87StoreStatusAx => .x87StoreStatusAx
  | .x87Examine => .x87Examine
  | .moveDwords repeated => .moveDwords repeated
  | .storeDwords repeated => .storeDwords repeated
  | .scanByteNotEqual => .scanByteNotEqual
  | .callIndirect target => .callIndirect target.semanticForm
  | .jumpIndirect target => .jumpIndirect target.semanticForm
  | .pushOperand source => .pushOperand source.semanticForm
  | .movFs32 _ source => .movFs32 source.semanticForm
  | .divideUnsigned source => .divideUnsigned source.semanticForm
  | .divideSigned source => .divideSigned source.semanticForm
  | .atomicCompareExchange destination _ =>
      .atomicCompareExchange destination.semanticForm

end StageA.Formal
