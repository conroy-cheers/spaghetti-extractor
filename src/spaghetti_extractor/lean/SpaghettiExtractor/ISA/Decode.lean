import SpaghettiExtractor.ISA.Machine

namespace SpaghettiExtractor.ISA.Formal

def readImmediate32 (bytes : Bytes) : Option Nat :=
  readU32 bytes 0

def signExtendImmediate8 (byte : Nat) : Nat :=
  if byte < 128 then byte else 2 ^ 32 - (256 - byte)

def relativeTarget8 (nextRva byte : Nat) : Nat :=
  (nextRva + signExtendImmediate8 byte) % (2 ^ 32)

def relativeTarget32 (nextRva displacement : Nat) : Nat :=
  (nextRva + displacement) % (2 ^ 32)

structure Addressing where
  base : Option Reg
  index : Option Reg
  scaleShift : Nat
  displacement : Nat
deriving Repr, DecidableEq

inductive Operand32 where
  | register (reg : Reg)
  | memory (addressing : Addressing)
  | immediate (value : Nat)
deriving Repr, DecidableEq

inductive OperandWidth where
  | byte
  | word
deriving Repr, DecidableEq

def OperandWidth.bits : OperandWidth -> Nat
  | .byte => 8
  | .word => 16

structure ByteRegister where
  parent : Reg
  high : Bool
deriving Repr, DecidableEq

inductive Operand8 where
  | register (reg : ByteRegister)
  | memory (addressing : Addressing)
  | immediate (value : Nat)
deriving Repr, DecidableEq

inductive BinaryOperation where
  | add
  | sub
  | xor
  | and
  | or
  | compare
  | test
deriving Repr, DecidableEq

inductive Condition where
  | overflow
  | notOverflow
  | equal
  | notEqual
  | below
  | aboveOrEqual
  | belowOrEqual
  | above
  | sign
  | notSign
  | parity
  | notParity
  | less
  | greaterOrEqual
  | greater
  | lessOrEqual
deriving Repr, DecidableEq

def conditionOfCode : Nat -> Option Condition
  | 0x0 => some .overflow
  | 0x1 => some .notOverflow
  | 0x2 => some .below
  | 0x3 => some .aboveOrEqual
  | 0x4 => some .equal
  | 0x5 => some .notEqual
  | 0x6 => some .belowOrEqual
  | 0x7 => some .above
  | 0x8 => some .sign
  | 0x9 => some .notSign
  | 0xa => some .parity
  | 0xb => some .notParity
  | 0xc => some .less
  | 0xd => some .greaterOrEqual
  | 0xe => some .lessOrEqual
  | 0xf => some .greater
  | _ => none

inductive ShiftOperation where
  | left
  | right
  | arithmeticRight
deriving Repr, DecidableEq

inductive ShiftCount where
  | immediate (value : Nat)
  | cl
deriving Repr, DecidableEq

inductive X86CPUProfile where
  | i686
  | haswell
deriving Repr, DecidableEq

inductive BMI1Evidence where
  | haswell
deriving Repr, DecidableEq

def X86CPUProfile.bmi1Evidence? : X86CPUProfile -> Option BMI1Evidence
  | .i686 => none
  | .haswell => some .haswell

inductive BitScanOperation where
  | forward
  | reverse
  | trailingZeroCount (evidence : BMI1Evidence)
deriving Repr, DecidableEq

inductive UnaryOperation where
  | bitNot
  | negate
  | increment
  | decrement
deriving Repr, DecidableEq

inductive Instruction where
  | nop
  | ret
  | retPop (bytes : Nat)
  | movRegImm (destination : Reg) (value : Nat)
  | movRegReg (destination source : Reg)
  | addZero (destination : Reg)
  | subZero (destination : Reg)
  | cmpImm (source : Reg) (value : Nat)
  | branchEqual (inverted : Bool) (displacement : Nat)
  | jumpRel8 (displacement : Nat)
  | jumpRel32 (displacement : Nat)
  | pushReg (source : Reg)
  | popReg (destination : Reg)
  | pushFlags
  | pushAll
  | popAll
  | popFlags
  | clearCarry
  | clearDirection
  | setDirection
  | leave
  | lea (destination base : Reg) (offset : Nat)
  | load32 (destination base : Reg) (offset : Nat)
  | store32 (base : Reg) (offset : Nat) (source : Reg)
  | zeroReg (destination : Reg)
  | callRel32 (displacement : Nat)
  | callImport (absoluteAddress : Nat)
  | jumpImport (absoluteAddress : Nat)
  | movFromOperand (destination : Reg) (source : Operand32)
  | movToOperand (destination : Operand32) (source : Reg)
  | movImmediate (destination : Operand32) (value : Nat)
  | leaAddress (destination : Reg) (source : Addressing)
  | binary (operation : BinaryOperation) (destination source : Operand32)
  | shift (operation : ShiftOperation) (destination : Operand32) (count : ShiftCount)
  | shiftWidth (width : OperandWidth) (operation : ShiftOperation)
      (destination : Operand32) (count : ShiftCount)
  | shift8 (operation : ShiftOperation) (destination : Operand8) (count : ShiftCount)
  | unary (operation : UnaryOperation) (destination : Operand32)
  | branchCondition (condition : Condition) (displacement size : Nat)
  | movZeroExtend (destination : Reg) (source : Operand32) (width : Nat)
  | movSignExtend (destination : Reg) (source : Operand32) (width : Nat)
  | movSignExtend8 (destination : Reg) (source : Operand8)
  | movSignExtend8ToWord (destination : Reg) (source : Operand8)
  | movFromOperandWidth (width : OperandWidth) (destination : Reg) (source : Operand32)
  | movToOperandWidth (width : OperandWidth) (destination : Operand32) (source : Reg)
  | movImmediateWidth (width : OperandWidth) (destination : Operand32) (value : Nat)
  | binaryWidth (width : OperandWidth) (operation : BinaryOperation) (destination source : Operand32)
  | movFromOperand8 (destination : ByteRegister) (source : Operand8)
  | movToOperand8 (destination : Operand8) (source : ByteRegister)
  | movImmediate8 (destination : Operand8) (value : Nat)
  | binary8 (operation : BinaryOperation) (destination source : Operand8)
  | conditionalMove (condition : Condition) (destination : Reg) (source : Operand32)
  | setCondition (condition : Condition) (destination : Operand8)
  | exchange (destination : Operand32) (source : Reg)
  | convertWordToDword
  | convertDwordToQuad
  | binaryCarry (subtract : Bool) (destination source : Operand32)
  | multiplyFull (signed : Bool) (source : Operand32)
  | multiplyLow (destination : Reg) (source : Operand32) (immediate : Option Nat)
  | doubleShift (left : Bool) (destination : Operand32) (source : Reg) (count : ShiftCount)
  | bitScan (operation : BitScanOperation) (destination : Reg) (source : Operand32)
  | bitTestRegister (base index : Reg)
  | x87LoadStack (index : Nat)
  | x87LoadConstant (value : Nat)
  | x87Exchange (index : Nat)
  | x87StoreStack (index : Nat) (pop : Bool)
  | x87Unary (operation : X87UnaryOperation)
  | x87BinaryStack (operation : X87BinaryOperation) (destination source : Nat) (pop : Bool)
  | x87CompareStack (mode : SpaghettiExtractor.ISA.X87.CompareMode)
      (destination : SpaghettiExtractor.ISA.X87.CompareDestination) (index : Nat) (pop : Bool)
  | x87CompareMemory (mode : SpaghettiExtractor.ISA.X87.CompareMode)
      (format : X87LoadFormat) (source : Addressing) (pop : Bool)
  | x87LoadMemory (format : X87LoadFormat) (source : Addressing)
  | x87StoreMemory (format : X87StoreFormat) (destination : Addressing) (pop : Bool)
  | x87BinaryMemory (operation : X87BinaryOperation) (format : X87LoadFormat) (source : Addressing)
  | x87LoadControl (source : Addressing)
  | x87StoreControl (destination : Addressing)
  | x87SaveState (destination : Addressing)
  | x87RestoreState (source : Addressing)
  | x87Wait
  | x87Initialize
  | x87StoreStatusAx
  | x87Examine
  | moveBytes (repeated : Bool)
  | moveWords (repeated : Bool)
  | moveDwords (repeated : Bool)
  | storeBytes (repeated : Bool)
  | storeWords (repeated : Bool)
  | storeDwords (repeated : Bool)
  | scanByteNotEqual
  | callIndirect (target : Operand32)
  | jumpIndirect (target : Operand32)
  | pushOperand (source : Operand32)
  | movFs32 (destination : Reg) (source : Addressing)
  | movToFs32 (destination : Addressing) (source : Reg)
  | divideUnsigned (source : Operand32)
  | divideSigned (source : Operand32)
  | atomicCompareExchange (destination : Addressing) (source : Reg)
deriving Repr, DecidableEq

structure DecodedInstruction where
  instruction : Instruction
  size : Nat
  trailing : Bytes
deriving Repr, DecidableEq

def registerOfCode : Nat -> Option Reg
  | 0 => some .eax
  | 1 => some .ecx
  | 2 => some .edx
  | 3 => some .ebx
  | 4 => some .esp
  | 5 => some .ebp
  | 6 => some .esi
  | 7 => some .edi
  | _ => none

def byteRegisterOfCode : Nat -> Option ByteRegister
  | 0 => some { parent := .eax, high := false }
  | 1 => some { parent := .ecx, high := false }
  | 2 => some { parent := .edx, high := false }
  | 3 => some { parent := .ebx, high := false }
  | 4 => some { parent := .eax, high := true }
  | 5 => some { parent := .ecx, high := true }
  | 6 => some { parent := .edx, high := true }
  | 7 => some { parent := .ebx, high := true }
  | _ => none

def readDisplacement (mode : Nat) (bytes : Bytes) : Option (Nat × Nat × Bytes) :=
  match mode, bytes with
  | 0, _ => some (0, 0, bytes)
  | 1, byte :: tail => some (signExtendImmediate8 byte, 1, tail)
  | 2, b0 :: b1 :: b2 :: b3 :: tail => do
      let value <- readImmediate32 [b0, b1, b2, b3]
      pure (value, 4, tail)
  | _, _ => none

structure ParsedModRM where
  reg : Reg
  operand : Operand32
  size : Nat
  trailing : Bytes
deriving Repr, DecidableEq

def parseModRM (bytes : Bytes) : Option ParsedModRM := do
  let modrm <- bytes.head?
  let tail := bytes.drop 1
  let mode := modrm / 64
  let regCode := (modrm / 8) % 8
  let rmCode := modrm % 8
  let reg <- registerOfCode regCode
  if mode == 3 then
    let rm <- registerOfCode rmCode
    pure { reg, operand := .register rm, size := 1, trailing := tail }
  else if rmCode == 4 then
    let sib <- tail.head?
    let afterSib := tail.drop 1
    let scaleShift := sib / 64
    let indexCode := (sib / 8) % 8
    let baseCode := sib % 8
    let index <- if indexCode == 4 then pure none else (registerOfCode indexCode).map some
    let absoluteBase := mode == 0 && baseCode == 5
    let base <- if absoluteBase then pure none else (registerOfCode baseCode).map some
    let displacementMode := if absoluteBase then 2 else mode
    let (displacement, displacementSize, trailing) <- readDisplacement displacementMode afterSib
    pure {
      reg,
      operand := .memory { base, index, scaleShift, displacement },
      size := 2 + displacementSize,
      trailing,
    }
  else
    let absoluteBase := mode == 0 && rmCode == 5
    let base <- if absoluteBase then pure none else (registerOfCode rmCode).map some
    let displacementMode := if absoluteBase then 2 else mode
    let (displacement, displacementSize, trailing) <- readDisplacement displacementMode tail
    pure {
      reg,
      operand := .memory { base, index := none, scaleShift := 0, displacement },
      size := 1 + displacementSize,
      trailing,
    }

structure ParsedModRM8 where
  reg : ByteRegister
  operand : Operand8
  size : Nat
  trailing : Bytes
deriving Repr, DecidableEq

def parseModRM8 (bytes : Bytes) : Option ParsedModRM8 := do
  let modrm <- bytes.head?
  let tail := bytes.drop 1
  let mode := modrm / 64
  let regCode := (modrm / 8) % 8
  let rmCode := modrm % 8
  let reg <- byteRegisterOfCode regCode
  if mode == 3 then
    let rm <- byteRegisterOfCode rmCode
    pure { reg, operand := .register rm, size := 1, trailing := tail }
  else if rmCode == 4 then
    let sib <- tail.head?
    let afterSib := tail.drop 1
    let scaleShift := sib / 64
    let indexCode := (sib / 8) % 8
    let baseCode := sib % 8
    let index <- if indexCode == 4 then pure none else (registerOfCode indexCode).map some
    let absoluteBase := mode == 0 && baseCode == 5
    let base <- if absoluteBase then pure none else (registerOfCode baseCode).map some
    let displacementMode := if absoluteBase then 2 else mode
    let (displacement, displacementSize, trailing) <- readDisplacement displacementMode afterSib
    pure {
      reg,
      operand := .memory { base, index, scaleShift, displacement },
      size := 2 + displacementSize,
      trailing,
    }
  else
    let absoluteBase := mode == 0 && rmCode == 5
    let base <- if absoluteBase then pure none else (registerOfCode rmCode).map some
    let displacementMode := if absoluteBase then 2 else mode
    let (displacement, displacementSize, trailing) <- readDisplacement displacementMode tail
    pure {
      reg,
      operand := .memory { base, index := none, scaleShift := 0, displacement },
      size := 1 + displacementSize,
      trailing,
    }

def decodedModRM8 (instruction : ParsedModRM8 -> Option Instruction)
    (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM8 bytes
  let instruction <- instruction parsed
  pure { instruction, size := 1 + parsed.size, trailing := parsed.trailing }

def decodedModRM8Immediate8 (instruction : ParsedModRM8 -> Nat -> Option Instruction)
    (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM8 bytes
  let immediate <- parsed.trailing.head?
  let instruction <- instruction parsed immediate
  pure { instruction, size := 2 + parsed.size, trailing := parsed.trailing.drop 1 }

def decodedModRM (instruction : ParsedModRM -> Option Instruction) (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM bytes
  let instruction <- instruction parsed
  pure { instruction, size := 1 + parsed.size, trailing := parsed.trailing }

def decodedModRMImmediate8 (instruction : ParsedModRM -> Nat -> Option Instruction)
    (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM bytes
  let immediate <- parsed.trailing.head?
  let instruction <- instruction parsed (signExtendImmediate8 immediate)
  pure { instruction, size := 2 + parsed.size, trailing := parsed.trailing.drop 1 }

def decodedModRMImmediate32 (instruction : ParsedModRM -> Nat -> Option Instruction)
    (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM bytes
  let value <- readU32 parsed.trailing 0
  let instruction <- instruction parsed value
  pure { instruction, size := 5 + parsed.size, trailing := parsed.trailing.drop 4 }

def decodedModRMImmediate16 (instruction : ParsedModRM -> Nat -> Option Instruction)
    (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM bytes
  let value <- readU16 parsed.trailing 0
  let instruction <- instruction parsed value
  pure { instruction, size := 3 + parsed.size, trailing := parsed.trailing.drop 2 }

def addInstructionPrefix (decoded : DecodedInstruction) : DecodedInstruction :=
  { decoded with size := decoded.size + 1 }

def decodeX87MemoryInstruction (opcode : Nat) (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM bytes
  let address <-
    match parsed.operand with
    | .memory address => some address
    | .register _ | .immediate _ => none
  let instruction <-
    match opcode, parsed.reg with
    | 0xd9, .eax => some (.x87LoadMemory .float32 address)
    | 0xd9, .edx => some (.x87StoreMemory .float32 address false)
    | 0xd9, .ebx => some (.x87StoreMemory .float32 address true)
    | 0xd9, .ebp => some (.x87LoadControl address)
    | 0xd9, .edi => some (.x87StoreControl address)
    | 0xdd, .eax => some (.x87LoadMemory .float64 address)
    | 0xdd, .edx => some (.x87StoreMemory .float64 address false)
    | 0xdd, .ebx => some (.x87StoreMemory .float64 address true)
    | 0xdd, .esp => some (.x87RestoreState address)
    | 0xdd, .esi => some (.x87SaveState address)
    | 0xdf, .edi => some (.x87StoreMemory .int64 address true)
    | 0xdb, .eax => some (.x87LoadMemory .int32 address)
    | 0xdb, .edx => some (.x87StoreMemory .int32 address false)
    | 0xdb, .ebx => some (.x87StoreMemory .int32 address true)
    | 0xdb, .ebp => some (.x87LoadMemory .float80 address)
    | 0xdb, .edi => some (.x87StoreMemory .float80 address true)
    | 0xd8, .eax => some (.x87BinaryMemory .add .float32 address)
    | 0xd8, .ecx => some (.x87BinaryMemory .multiply .float32 address)
    | 0xd8, .edx => some (.x87CompareMemory .ordered .float32 address false)
    | 0xd8, .ebx => some (.x87CompareMemory .ordered .float32 address true)
    | 0xd8, .esp => some (.x87BinaryMemory .subtract .float32 address)
    | 0xd8, .ebp => some (.x87BinaryMemory .reverseSubtract .float32 address)
    | 0xd8, .esi => some (.x87BinaryMemory .divide .float32 address)
    | 0xd8, .edi => some (.x87BinaryMemory .reverseDivide .float32 address)
    | 0xdc, .eax => some (.x87BinaryMemory .add .float64 address)
    | 0xdc, .ecx => some (.x87BinaryMemory .multiply .float64 address)
    | 0xdc, .edx => some (.x87CompareMemory .ordered .float64 address false)
    | 0xdc, .ebx => some (.x87CompareMemory .ordered .float64 address true)
    | 0xdc, .esp => some (.x87BinaryMemory .subtract .float64 address)
    | 0xdc, .ebp => some (.x87BinaryMemory .reverseSubtract .float64 address)
    | 0xdc, .esi => some (.x87BinaryMemory .divide .float64 address)
    | 0xdc, .edi => some (.x87BinaryMemory .reverseDivide .float64 address)
    | 0xda, .eax => some (.x87BinaryMemory .add .int32 address)
    | 0xda, .ecx => some (.x87BinaryMemory .multiply .int32 address)
    | 0xda, .edx => some (.x87CompareMemory .ordered .int32 address false)
    | 0xda, .ebx => some (.x87CompareMemory .ordered .int32 address true)
    | 0xda, .esp => some (.x87BinaryMemory .subtract .int32 address)
    | 0xda, .ebp => some (.x87BinaryMemory .reverseSubtract .int32 address)
    | 0xda, .esi => some (.x87BinaryMemory .divide .int32 address)
    | 0xda, .edi => some (.x87BinaryMemory .reverseDivide .int32 address)
    | _, _ => none
  pure { instruction, size := 1 + parsed.size, trailing := parsed.trailing }

def decodeX87RegisterInstruction : Bytes -> Option DecodedInstruction
  | opcode :: modrm :: tail =>
      let decoded (instruction : Instruction) := some { instruction, size := 2, trailing := tail }
      if opcode == 0xd9 && 0xc0 <= modrm && modrm <= 0xc7 then
        decoded (.x87LoadStack (modrm - 0xc0))
      else if opcode == 0xd9 && 0xc8 <= modrm && modrm <= 0xcf then
        decoded (.x87Exchange (modrm - 0xc8))
      else if opcode == 0xd9 && modrm == 0xe0 then
        decoded (.x87Unary .negate)
      else if opcode == 0xd9 && modrm == 0xe1 then
        decoded (.x87Unary .absolute)
      else if opcode == 0xd9 && modrm == 0xfe then
        decoded (.x87Unary .sine)
      else if opcode == 0xd9 && modrm == 0xff then
        decoded (.x87Unary .cosine)
      else if opcode == 0xd9 && modrm == 0xe8 then
        decoded (.x87LoadConstant (0x3fff * (2 ^ 64) + (2 ^ 63)))
      else if opcode == 0xd9 && modrm == 0xee then
        decoded (.x87LoadConstant 0)
      else if opcode == 0xdd && 0xd0 <= modrm && modrm <= 0xd7 then
        decoded (.x87StoreStack (modrm - 0xd0) false)
      else if opcode == 0xdd && 0xd8 <= modrm && modrm <= 0xdf then
        decoded (.x87StoreStack (modrm - 0xd8) true)
      else if opcode == 0xd8 && 0xc0 <= modrm && modrm <= 0xc7 then
        decoded (.x87BinaryStack .add 0 (modrm - 0xc0) false)
      else if opcode == 0xd8 && 0xc8 <= modrm && modrm <= 0xcf then
        decoded (.x87BinaryStack .multiply 0 (modrm - 0xc8) false)
      else if opcode == 0xd8 && 0xf0 <= modrm && modrm <= 0xf7 then
        decoded (.x87BinaryStack .divide 0 (modrm - 0xf0) false)
      else if opcode == 0xd8 && 0xf8 <= modrm && modrm <= 0xff then
        decoded (.x87BinaryStack .reverseDivide 0 (modrm - 0xf8) false)
      else if opcode == 0xdc && 0xc8 <= modrm && modrm <= 0xcf then
        decoded (.x87BinaryStack .multiply (modrm - 0xc8) 0 false)
      else if opcode == 0xde && 0xc0 <= modrm && modrm <= 0xc7 then
        decoded (.x87BinaryStack .add (modrm - 0xc0) 0 true)
      else if opcode == 0xde && 0xc8 <= modrm && modrm <= 0xcf then
        decoded (.x87BinaryStack .multiply (modrm - 0xc8) 0 true)
      else if opcode == 0xde && 0xe0 <= modrm && modrm <= 0xe7 then
        decoded (.x87BinaryStack .reverseSubtract (modrm - 0xe0) 0 true)
      else if opcode == 0xde && 0xe8 <= modrm && modrm <= 0xef then
        decoded (.x87BinaryStack .subtract (modrm - 0xe8) 0 true)
      else if opcode == 0xd8 && 0xd0 <= modrm && modrm <= 0xd7 then
        decoded (.x87CompareStack .ordered .status (modrm % 8) false)
      else if opcode == 0xd8 && 0xd8 <= modrm && modrm <= 0xdf then
        decoded (.x87CompareStack .ordered .status (modrm % 8) true)
      else if opcode == 0xdd && 0xe0 <= modrm && modrm <= 0xe7 then
        decoded (.x87CompareStack .unordered .status (modrm % 8) false)
      else if opcode == 0xdd && 0xe8 <= modrm && modrm <= 0xef then
        decoded (.x87CompareStack .unordered .status (modrm % 8) true)
      else if opcode == 0xdb && 0xe8 <= modrm && modrm <= 0xef then
        decoded (.x87CompareStack .unordered .eflags (modrm % 8) false)
      else if opcode == 0xdb && 0xf0 <= modrm && modrm <= 0xf7 then
        decoded (.x87CompareStack .ordered .eflags (modrm % 8) false)
      else if opcode == 0xdf && 0xe8 <= modrm && modrm <= 0xef then
        decoded (.x87CompareStack .unordered .eflags (modrm % 8) true)
      else if opcode == 0xdf && 0xf0 <= modrm && modrm <= 0xf7 then
        decoded (.x87CompareStack .ordered .eflags (modrm % 8) true)
      else if opcode == 0xdb && modrm == 0xe3 then
        decoded .x87Initialize
      else if opcode == 0xdf && modrm == 0xe0 then
        decoded .x87StoreStatusAx
      else if opcode == 0xd9 && modrm == 0xe5 then
        decoded .x87Examine
      else
        decodeX87MemoryInstruction opcode (modrm :: tail)
  | _ => none

def decodeWordInstruction : Bytes -> Option DecodedInstruction
  | opcode :: tail =>
      if 0xb8 <= opcode && opcode <= 0xbf then do
        let destination <- registerOfCode (opcode - 0xb8)
        let value <- readU16 tail 0
        pure {
          instruction := .movImmediateWidth .word (.register destination) value
          size := 3
          trailing := tail.drop 2
        }
      else
        match opcode with
        | 0x0f =>
            match tail with
            | 0xbe :: bytes => do
                let parsed <- parseModRM bytes
                let byteParsed <- parseModRM8 bytes
                if parsed.size != byteParsed.size || parsed.trailing != byteParsed.trailing then
                  none
                else
                pure {
                  instruction := .movSignExtend8ToWord parsed.reg byteParsed.operand
                  size := 2 + parsed.size
                  trailing := parsed.trailing
                }
            | _ => none
        | 0x8b => decodedModRM (fun parsed => some (.movFromOperandWidth .word parsed.reg parsed.operand)) tail
        | 0x89 => decodedModRM (fun parsed => some (.movToOperandWidth .word parsed.operand parsed.reg)) tail
        | 0xc7 => decodedModRMImmediate16 (fun parsed value =>
            if parsed.reg == .eax then some (.movImmediateWidth .word parsed.operand value) else none) tail
        | 0x03 => decodedModRM (fun parsed =>
            some (.binaryWidth .word .add (.register parsed.reg) parsed.operand)) tail
        | 0x01 => decodedModRM (fun parsed =>
            some (.binaryWidth .word .add parsed.operand (.register parsed.reg))) tail
        | 0x0b => decodedModRM (fun parsed =>
            some (.binaryWidth .word .or (.register parsed.reg) parsed.operand)) tail
        | 0x09 => decodedModRM (fun parsed =>
            some (.binaryWidth .word .or parsed.operand (.register parsed.reg))) tail
        | 0x23 => decodedModRM (fun parsed =>
            some (.binaryWidth .word .and (.register parsed.reg) parsed.operand)) tail
        | 0x21 => decodedModRM (fun parsed =>
            some (.binaryWidth .word .and parsed.operand (.register parsed.reg))) tail
        | 0x3b => decodedModRM (fun parsed => some (.binaryWidth .word .compare (.register parsed.reg) parsed.operand)) tail
        | 0x2b => decodedModRM (fun parsed => some (.binaryWidth .word .sub (.register parsed.reg) parsed.operand)) tail
        | 0x29 => decodedModRM (fun parsed =>
            some (.binaryWidth .word .sub parsed.operand (.register parsed.reg))) tail
        | 0x33 => decodedModRM (fun parsed =>
            some (.binaryWidth .word .xor (.register parsed.reg) parsed.operand)) tail
        | 0x31 => decodedModRM (fun parsed =>
            some (.binaryWidth .word .xor parsed.operand (.register parsed.reg))) tail
        | 0x39 => decodedModRM (fun parsed => some (.binaryWidth .word .compare parsed.operand (.register parsed.reg))) tail
        | 0x85 => decodedModRM (fun parsed => some (.binaryWidth .word .test parsed.operand (.register parsed.reg))) tail
        | 0xf7 => decodedModRMImmediate16 (fun parsed value =>
            if parsed.reg == .eax then some (.binaryWidth .word .test parsed.operand (.immediate value)) else none) tail
        | 0x83 => decodedModRMImmediate8 (fun parsed value =>
            match parsed.reg with
            | .eax => some (.binaryWidth .word .add parsed.operand (.immediate value))
            | .ecx => some (.binaryWidth .word .or parsed.operand (.immediate value))
            | .esp => some (.binaryWidth .word .and parsed.operand (.immediate value))
            | .ebp => some (.binaryWidth .word .sub parsed.operand (.immediate value))
            | .esi => some (.binaryWidth .word .xor parsed.operand (.immediate value))
            | .edi => some (.binaryWidth .word .compare parsed.operand (.immediate value))
            | _ => none) tail
        | 0x81 => decodedModRMImmediate16 (fun parsed value =>
            match parsed.reg with
            | .eax => some (.binaryWidth .word .add parsed.operand (.immediate value))
            | .ecx => some (.binaryWidth .word .or parsed.operand (.immediate value))
            | .esp => some (.binaryWidth .word .and parsed.operand (.immediate value))
            | .ebp => some (.binaryWidth .word .sub parsed.operand (.immediate value))
            | .esi => some (.binaryWidth .word .xor parsed.operand (.immediate value))
            | .edi => some (.binaryWidth .word .compare parsed.operand (.immediate value))
            | _ => none) tail
        | 0xc1 => decodedModRMImmediate8 (fun parsed value =>
            match parsed.reg with
            | .esp => some (.shiftWidth .word .left parsed.operand (.immediate (value % 32)))
            | .ebp => some (.shiftWidth .word .right parsed.operand (.immediate (value % 32)))
            | .edi => some (.shiftWidth .word .arithmeticRight parsed.operand (.immediate (value % 32)))
            | _ => none) tail
        | 0xd1 => decodedModRM (fun parsed =>
            match parsed.reg with
            | .esp => some (.shiftWidth .word .left parsed.operand (.immediate 1))
            | .ebp => some (.shiftWidth .word .right parsed.operand (.immediate 1))
            | .edi => some (.shiftWidth .word .arithmeticRight parsed.operand (.immediate 1))
            | _ => none) tail
        | 0xd3 => decodedModRM (fun parsed =>
            match parsed.reg with
            | .esp => some (.shiftWidth .word .left parsed.operand .cl)
            | .ebp => some (.shiftWidth .word .right parsed.operand .cl)
            | .edi => some (.shiftWidth .word .arithmeticRight parsed.operand .cl)
            | _ => none) tail
        | 0x25 => do
            let value <- readU16 tail 0
            pure {
              instruction := .binaryWidth .word .and (.register .eax) (.immediate value)
              size := 3
              trailing := tail.drop 2
            }
        | 0x3d => do
            let value <- readU16 tail 0
            pure {
              instruction := .binaryWidth .word .compare (.register .eax) (.immediate value)
              size := 3
              trailing := tail.drop 2
            }
        | 0x2d => do
            let value <- readU16 tail 0
            pure {
              instruction := .binaryWidth .word .sub (.register .eax) (.immediate value)
              size := 3
              trailing := tail.drop 2
            }
        | _ => none
  | [] => none

def decodeGenericInstruction : Bytes -> Option DecodedInstruction
  | opcode :: tail =>
      if 0xb0 <= opcode && opcode <= 0xb7 then do
        let destination <- byteRegisterOfCode (opcode - 0xb0)
        let value <- tail.head?
        pure { instruction := .movImmediate8 (.register destination) value, size := 2, trailing := tail.drop 1 }
      else if 0xb8 <= opcode && opcode <= 0xbf then do
        let destination <- registerOfCode (opcode - 0xb8)
        let value <- readU32 tail 0
        pure { instruction := .movRegImm destination value, size := 5, trailing := tail.drop 4 }
      else if 0x40 <= opcode && opcode <= 0x47 then do
        let destination <- registerOfCode (opcode - 0x40)
        pure {
          instruction := .unary .increment (.register destination)
          size := 1
          trailing := tail
        }
      else if 0x48 <= opcode && opcode <= 0x4f then do
        let destination <- registerOfCode (opcode - 0x48)
        pure {
          instruction := .unary .decrement (.register destination)
          size := 1
          trailing := tail
        }
      else if 0x50 <= opcode && opcode <= 0x57 then do
        let source <- registerOfCode (opcode - 0x50)
        pure { instruction := .pushReg source, size := 1, trailing := tail }
      else if 0x58 <= opcode && opcode <= 0x5f then do
        let destination <- registerOfCode (opcode - 0x58)
        pure { instruction := .popReg destination, size := 1, trailing := tail }
      else if 0x91 <= opcode && opcode <= 0x97 then do
        let destination <- registerOfCode (opcode - 0x90)
        pure {
          instruction := .exchange (.register destination) .eax,
          size := 1,
          trailing := tail,
        }
      else if 0x70 <= opcode && opcode <= 0x7f then do
        let displacement <- tail.head?
        let condition <- conditionOfCode (opcode - 0x70)
        pure { instruction := .branchCondition condition displacement 2, size := 2, trailing := tail.drop 1 }
      else
        match opcode with
        | 0xa2 => do
            let address <- readU32 tail 0
            pure {
              instruction := .movToOperand8
                (.memory { base := none, index := none, scaleShift := 0, displacement := address })
                { parent := .eax, high := false }
              size := 5
              trailing := tail.drop 4
            }
        | 0xa1 => do
            let address <- readU32 tail 0
            pure {
              instruction := .movFromOperand .eax (.memory { base := none, index := none, scaleShift := 0, displacement := address }),
              size := 5,
              trailing := tail.drop 4,
            }
        | 0xa3 => do
            let address <- readU32 tail 0
            pure {
              instruction := .movToOperand (.memory { base := none, index := none, scaleShift := 0, displacement := address }) .eax,
              size := 5,
              trailing := tail.drop 4,
            }
        | 0x8b => decodedModRM (fun parsed => some (.movFromOperand parsed.reg parsed.operand)) tail
        | 0x89 => decodedModRM (fun parsed => some (.movToOperand parsed.operand parsed.reg)) tail
        | 0x8a => decodedModRM8 (fun parsed => some (.movFromOperand8 parsed.reg parsed.operand)) tail
        | 0x88 => decodedModRM8 (fun parsed => some (.movToOperand8 parsed.operand parsed.reg)) tail
        | 0xc6 => decodedModRM8Immediate8 (fun parsed value =>
            if parsed.reg == { parent := .eax, high := false } then some (.movImmediate8 parsed.operand value) else none) tail
        | 0x8d => decodedModRM (fun parsed =>
            match parsed.operand with
            | .memory address => some (.leaAddress parsed.reg address)
            | .register _ | .immediate _ => none) tail
        | 0x87 => decodedModRM (fun parsed => some (.exchange parsed.operand parsed.reg)) tail
        | 0x69 => decodedModRMImmediate32 (fun parsed value =>
            some (.multiplyLow parsed.reg parsed.operand (some value))) tail
        | 0x6b => decodedModRMImmediate8 (fun parsed value =>
            some (.multiplyLow parsed.reg parsed.operand (some value))) tail
        | 0x98 => some { instruction := .convertWordToDword, size := 1, trailing := tail }
        | 0x99 => some { instruction := .convertDwordToQuad, size := 1, trailing := tail }
        | 0x9c => some { instruction := .pushFlags, size := 1, trailing := tail }
        | 0x60 => some { instruction := .pushAll, size := 1, trailing := tail }
        | 0x61 => some { instruction := .popAll, size := 1, trailing := tail }
        | 0x9d => some { instruction := .popFlags, size := 1, trailing := tail }
        | 0xf8 => some { instruction := .clearCarry, size := 1, trailing := tail }
        | 0xfc => some { instruction := .clearDirection, size := 1, trailing := tail }
        | 0xfd => some { instruction := .setDirection, size := 1, trailing := tail }
        | 0x68 => do
            let value <- readU32 tail 0
            pure {
              instruction := .pushOperand (.immediate value)
              size := 5
              trailing := tail.drop 4
            }
        | 0x6a =>
            match tail with
            | value :: trailing => some {
                instruction := .pushOperand (.immediate (signExtendImmediate8 value))
                size := 2
                trailing
              }
            | [] => none
        | 0xc7 => decodedModRMImmediate32 (fun parsed value =>
            if parsed.reg == .eax then some (.movImmediate parsed.operand value) else none) tail
        | 0x03 => decodedModRM (fun parsed => some (.binary .add (.register parsed.reg) parsed.operand)) tail
        | 0x01 => decodedModRM (fun parsed => some (.binary .add parsed.operand (.register parsed.reg))) tail
        | 0x13 => decodedModRM (fun parsed => some (.binaryCarry false (.register parsed.reg) parsed.operand)) tail
        | 0x11 => decodedModRM (fun parsed => some (.binaryCarry false parsed.operand (.register parsed.reg))) tail
        | 0x1b => decodedModRM (fun parsed => some (.binaryCarry true (.register parsed.reg) parsed.operand)) tail
        | 0x19 => decodedModRM (fun parsed => some (.binaryCarry true parsed.operand (.register parsed.reg))) tail
        | 0x2b => decodedModRM (fun parsed => some (.binary .sub (.register parsed.reg) parsed.operand)) tail
        | 0x29 => decodedModRM (fun parsed => some (.binary .sub parsed.operand (.register parsed.reg))) tail
        | 0x33 => decodedModRM (fun parsed => some (.binary .xor (.register parsed.reg) parsed.operand)) tail
        | 0x31 => decodedModRM (fun parsed => some (.binary .xor parsed.operand (.register parsed.reg))) tail
        | 0x23 => decodedModRM (fun parsed => some (.binary .and (.register parsed.reg) parsed.operand)) tail
        | 0x21 => decodedModRM (fun parsed => some (.binary .and parsed.operand (.register parsed.reg))) tail
        | 0x0b => decodedModRM (fun parsed => some (.binary .or (.register parsed.reg) parsed.operand)) tail
        | 0x09 => decodedModRM (fun parsed => some (.binary .or parsed.operand (.register parsed.reg))) tail
        | 0x3b => decodedModRM (fun parsed => some (.binary .compare (.register parsed.reg) parsed.operand)) tail
        | 0x39 => decodedModRM (fun parsed => some (.binary .compare parsed.operand (.register parsed.reg))) tail
        | 0x85 => decodedModRM (fun parsed => some (.binary .test parsed.operand (.register parsed.reg))) tail
        | 0x84 => decodedModRM8 (fun parsed => some (.binary8 .test parsed.operand (.register parsed.reg))) tail
        | 0x00 => decodedModRM8 (fun parsed => some (.binary8 .add parsed.operand (.register parsed.reg))) tail
        | 0x02 => decodedModRM8 (fun parsed => some (.binary8 .add (.register parsed.reg) parsed.operand)) tail
        | 0x28 => decodedModRM8 (fun parsed => some (.binary8 .sub parsed.operand (.register parsed.reg))) tail
        | 0x2a => decodedModRM8 (fun parsed => some (.binary8 .sub (.register parsed.reg) parsed.operand)) tail
        | 0x08 => decodedModRM8 (fun parsed => some (.binary8 .or parsed.operand (.register parsed.reg))) tail
        | 0x3a => decodedModRM8 (fun parsed => some (.binary8 .compare (.register parsed.reg) parsed.operand)) tail
        | 0x38 => decodedModRM8 (fun parsed => some (.binary8 .compare parsed.operand (.register parsed.reg))) tail
        | 0x0a => decodedModRM8 (fun parsed => some (.binary8 .or (.register parsed.reg) parsed.operand)) tail
        | 0x20 => decodedModRM8 (fun parsed => some (.binary8 .and parsed.operand (.register parsed.reg))) tail
        | 0x22 => decodedModRM8 (fun parsed => some (.binary8 .and (.register parsed.reg) parsed.operand)) tail
        | 0x30 => decodedModRM8 (fun parsed => some (.binary8 .xor parsed.operand (.register parsed.reg))) tail
        | 0x32 => decodedModRM8 (fun parsed => some (.binary8 .xor (.register parsed.reg) parsed.operand)) tail
        | 0x80 => decodedModRM8Immediate8 (fun parsed value =>
            match parsed.reg with
            | { parent := .eax, high := false } => some (.binary8 .add parsed.operand (.immediate value))
            | { parent := .ecx, high := false } => some (.binary8 .or parsed.operand (.immediate value))
            | { parent := .eax, high := true } => some (.binary8 .and parsed.operand (.immediate value))
            | { parent := .ecx, high := true } => some (.binary8 .sub parsed.operand (.immediate value))
            | { parent := .edx, high := true } => some (.binary8 .xor parsed.operand (.immediate value))
            | { parent := .ebx, high := true } => some (.binary8 .compare parsed.operand (.immediate value))
            | _ => none) tail
        | 0x83 => decodedModRMImmediate8 (fun parsed value =>
            match parsed.reg with
            | .eax => some (.binary .add parsed.operand (.immediate value))
            | .ecx => some (.binary .or parsed.operand (.immediate value))
            | .edx => some (.binaryCarry false parsed.operand (.immediate value))
            | .ebx => some (.binaryCarry true parsed.operand (.immediate value))
            | .esp => some (.binary .and parsed.operand (.immediate value))
            | .ebp => some (.binary .sub parsed.operand (.immediate value))
            | .esi => some (.binary .xor parsed.operand (.immediate value))
            | .edi => some (.binary .compare parsed.operand (.immediate value))) tail
        | 0x81 => decodedModRMImmediate32 (fun parsed value =>
            match parsed.reg with
            | .eax => some (.binary .add parsed.operand (.immediate value))
            | .ecx => some (.binary .or parsed.operand (.immediate value))
            | .edx => some (.binaryCarry false parsed.operand (.immediate value))
            | .ebx => some (.binaryCarry true parsed.operand (.immediate value))
            | .esp => some (.binary .and parsed.operand (.immediate value))
            | .ebp => some (.binary .sub parsed.operand (.immediate value))
            | .esi => some (.binary .xor parsed.operand (.immediate value))
            | .edi => some (.binary .compare parsed.operand (.immediate value))) tail
        | 0x05 => do
            let value <- readU32 tail 0
            pure { instruction := .binary .add (.register .eax) (.immediate value), size := 5, trailing := tail.drop 4 }
        | 0x0d => do
            let value <- readU32 tail 0
            pure { instruction := .binary .or (.register .eax) (.immediate value), size := 5, trailing := tail.drop 4 }
        | 0x25 => do
            let value <- readU32 tail 0
            pure { instruction := .binary .and (.register .eax) (.immediate value), size := 5, trailing := tail.drop 4 }
        | 0x2d => do
            let value <- readU32 tail 0
            pure { instruction := .binary .sub (.register .eax) (.immediate value), size := 5, trailing := tail.drop 4 }
        | 0x35 => do
            let value <- readU32 tail 0
            pure { instruction := .binary .xor (.register .eax) (.immediate value), size := 5, trailing := tail.drop 4 }
        | 0xc1 => decodedModRMImmediate8 (fun parsed value =>
            match parsed.reg with
            | .esp => some (.shift .left parsed.operand (.immediate (value % 32)))
            | .ebp => some (.shift .right parsed.operand (.immediate (value % 32)))
            | .edi => some (.shift .arithmeticRight parsed.operand (.immediate (value % 32)))
            | _ => none) tail
        | 0xd1 => decodedModRM (fun parsed =>
            match parsed.reg with
            | .esp => some (.shift .left parsed.operand (.immediate 1))
            | .ebp => some (.shift .right parsed.operand (.immediate 1))
            | .edi => some (.shift .arithmeticRight parsed.operand (.immediate 1))
            | _ => none) tail
        | 0xd3 => decodedModRM (fun parsed =>
            match parsed.reg with
            | .esp => some (.shift .left parsed.operand .cl)
            | .ebp => some (.shift .right parsed.operand .cl)
            | .edi => some (.shift .arithmeticRight parsed.operand .cl)
            | _ => none) tail
        | 0xc0 => decodedModRM8Immediate8 (fun parsed value =>
            match parsed.reg with
            | { parent := .eax, high := true } =>
                some (.shift8 .left parsed.operand (.immediate (value % 32)))
            | { parent := .ecx, high := true } =>
                some (.shift8 .right parsed.operand (.immediate (value % 32)))
            | { parent := .ebx, high := true } =>
                some (.shift8 .arithmeticRight parsed.operand (.immediate (value % 32)))
            | _ => none) tail
        | 0xf6 => decodedModRM8Immediate8 (fun parsed value =>
            if parsed.reg == { parent := .eax, high := false } then
              some (.binary8 .test parsed.operand (.immediate value))
            else none) tail
        | 0xf7 => do
            let parsed <- parseModRM tail
            match parsed.reg with
            | .eax => do
                let value <- readU32 parsed.trailing 0
                pure {
                  instruction := .binary .test parsed.operand (.immediate value)
                  size := 5 + parsed.size
                  trailing := parsed.trailing.drop 4
                }
            | .edx => pure { instruction := .unary .bitNot parsed.operand, size := 1 + parsed.size, trailing := parsed.trailing }
            | .ebx => pure { instruction := .unary .negate parsed.operand, size := 1 + parsed.size, trailing := parsed.trailing }
            | .esp => pure { instruction := .multiplyFull false parsed.operand, size := 1 + parsed.size, trailing := parsed.trailing }
            | .ebp => pure { instruction := .multiplyFull true parsed.operand, size := 1 + parsed.size, trailing := parsed.trailing }
            | .esi => pure { instruction := .divideUnsigned parsed.operand, size := 1 + parsed.size, trailing := parsed.trailing }
            | .edi => pure { instruction := .divideSigned parsed.operand, size := 1 + parsed.size, trailing := parsed.trailing }
            | _ => none
        | 0xff => decodedModRM (fun parsed =>
            match parsed.reg with
            | .eax => some (.unary .increment parsed.operand)
            | .ecx => some (.unary .decrement parsed.operand)
            | .edx => some (.callIndirect parsed.operand)
            | .esp => some (.jumpIndirect parsed.operand)
            | .esi => some (.pushOperand parsed.operand)
            | _ => none) tail
        | 0xa8 =>
            match tail with
            | value :: trailing => some {
                instruction := .binary8 .test (.register { parent := .eax, high := false }) (.immediate value)
                size := 2
                trailing
              }
            | _ => none
        | 0xa9 => do
            let value <- readU32 tail 0
            pure {
              instruction := .binary .test (.register .eax) (.immediate value)
              size := 5
              trailing := tail.drop 4
            }
        | 0x3c =>
            match tail with
            | value :: trailing => some {
                instruction := .binary8 .compare (.register { parent := .eax, high := false }) (.immediate value)
                size := 2
                trailing
              }
            | _ => none
        | 0x24 =>
            match tail with
            | value :: trailing => some {
                instruction := .binary8 .and (.register { parent := .eax, high := false }) (.immediate value)
                size := 2
                trailing
              }
            | _ => none
        | 0x0c =>
            match tail with
            | value :: trailing => some {
                instruction := .binary8 .or (.register { parent := .eax, high := false }) (.immediate value)
                size := 2
                trailing
              }
            | _ => none
        | 0x34 =>
            match tail with
            | value :: trailing => some {
                instruction := .binary8 .xor
                  (.register { parent := .eax, high := false }) (.immediate value)
                size := 2
                trailing
              }
            | _ => none
        | 0x72 =>
            match tail with
            | displacement :: trailing => some { instruction := .branchCondition .below displacement 2, size := 2, trailing }
            | _ => none
        | 0x77 =>
            match tail with
            | displacement :: trailing => some { instruction := .branchCondition .above displacement 2, size := 2, trailing }
            | _ => none
        | 0x7f =>
            match tail with
            | displacement :: trailing => some { instruction := .branchCondition .greater displacement 2, size := 2, trailing }
            | _ => none
        | 0x73 =>
            match tail with
            | displacement :: trailing => some { instruction := .branchCondition .aboveOrEqual displacement 2, size := 2, trailing }
            | _ => none
        | 0x7e =>
            match tail with
            | displacement :: trailing => some { instruction := .branchCondition .lessOrEqual displacement 2, size := 2, trailing }
            | _ => none
        | _ => none
  | [] => none

def decodeInstructionForProfile
    (profile : X86CPUProfile) : Bytes -> Option DecodedInstruction
  | 0x90 :: tail => some { instruction := .nop, size := 1, trailing := tail }
  | 0x9b :: tail => some { instruction := .x87Wait, size := 1, trailing := tail }
  | 0xf3 :: 0xa4 :: tail => some { instruction := .moveBytes true, size := 2, trailing := tail }
  | 0xf3 :: 0xa5 :: tail => some { instruction := .moveDwords true, size := 2, trailing := tail }
  | 0xf3 :: 0xaa :: tail => some { instruction := .storeBytes true, size := 2, trailing := tail }
  | 0xf3 :: 0xab :: tail => some { instruction := .storeDwords true, size := 2, trailing := tail }
  | 0xf2 :: 0xae :: tail => some { instruction := .scanByteNotEqual, size := 2, trailing := tail }
  | 0xa4 :: tail => some { instruction := .moveBytes false, size := 1, trailing := tail }
  | 0xa5 :: tail => some { instruction := .moveDwords false, size := 1, trailing := tail }
  | 0xaa :: tail => some { instruction := .storeBytes false, size := 1, trailing := tail }
  | 0xab :: tail => some { instruction := .storeDwords false, size := 1, trailing := tail }
  | 0x66 :: 0xa5 :: tail => some { instruction := .moveWords false, size := 2, trailing := tail }
  | 0x66 :: 0xab :: tail => some { instruction := .storeWords false, size := 2, trailing := tail }
  | 0x64 :: 0x8b :: tail => do
      let parsed <- parseModRM tail
      let source <-
        match parsed.operand with
        | .memory source => some source
        | .register _ | .immediate _ => none
      pure {
        instruction := .movFs32 parsed.reg source
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0x64 :: 0x89 :: tail => do
      let parsed <- parseModRM tail
      let destination <-
        match parsed.operand with
        | .memory destination => some destination
        | .register _ | .immediate _ => none
      pure {
        instruction := .movToFs32 destination parsed.reg
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0x64 :: 0xa1 :: b0 :: b1 :: b2 :: b3 :: tail => do
      let address <- readImmediate32 [b0, b1, b2, b3]
      pure {
        instruction := .movFs32 .eax {
          base := none
          index := none
          scaleShift := 0
          displacement := address
        }
        size := 6
        trailing := tail
      }
  | 0xf0 :: 0x0f :: 0xb1 :: tail => do
      let parsed <- parseModRM tail
      let destination <-
        match parsed.operand with
        | .memory destination => some destination
        | .register _ | .immediate _ => none
      pure {
        instruction := .atomicCompareExchange destination parsed.reg
        size := 3 + parsed.size
        trailing := parsed.trailing
      }
  | 0x66 :: 0x90 :: tail => some { instruction := .nop, size := 2, trailing := tail }
  | 0x66 :: bytes => (decodeWordInstruction bytes).map addInstructionPrefix
  | 0x2e :: 0x8d :: 0x74 :: 0x26 :: 0x00 :: tail => some { instruction := .nop, size := 5, trailing := tail }
  | 0x2e :: 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail =>
      some { instruction := .nop, size := 8, trailing := tail }
  | 0x8d :: 0xb6 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail =>
      some { instruction := .nop, size := 6, trailing := tail }
  | 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail =>
      some { instruction := .nop, size := 7, trailing := tail }
  | 0xc3 :: tail => some { instruction := .ret, size := 1, trailing := tail }
  | 0xc9 :: tail => some { instruction := .leave, size := 1, trailing := tail }
  | 0xc2 :: b0 :: b1 :: tail => do
      let bytes <- readU16 [b0, b1] 0
      pure { instruction := .retPop bytes, size := 3, trailing := tail }
  | 0xb8 :: b0 :: b1 :: b2 :: b3 :: tail => do
      let value <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .movRegImm .eax value, size := 5, trailing := tail }
  | 0x89 :: 0xd8 :: tail => some { instruction := .movRegReg .eax .ebx, size := 2, trailing := tail }
  | 0x8d :: 0x03 :: tail => some { instruction := .lea .eax .ebx 0, size := 2, trailing := tail }
  | 0x89 :: 0xda :: tail => some { instruction := .movRegReg .edx .ebx, size := 2, trailing := tail }
  | 0x8d :: 0x13 :: tail => some { instruction := .lea .edx .ebx 0, size := 2, trailing := tail }
  | 0x83 :: 0xc0 :: 0x00 :: tail => some { instruction := .addZero .eax, size := 3, trailing := tail }
  | 0x83 :: 0xe8 :: 0x00 :: tail => some { instruction := .subZero .eax, size := 3, trailing := tail }
  | 0x83 :: 0xf8 :: immediate :: tail =>
      some { instruction := .cmpImm .eax (signExtendImmediate8 immediate), size := 3, trailing := tail }
  | 0x3d :: b0 :: b1 :: b2 :: b3 :: tail => do
      let value <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .cmpImm .eax value, size := 5, trailing := tail }
  | 0x74 :: displacement :: tail => some { instruction := .branchEqual false displacement, size := 2, trailing := tail }
  | 0x75 :: displacement :: tail => some { instruction := .branchEqual true displacement, size := 2, trailing := tail }
  | 0xeb :: displacement :: tail => some { instruction := .jumpRel8 displacement, size := 2, trailing := tail }
  | 0xe9 :: b0 :: b1 :: b2 :: b3 :: tail => do
      let displacement <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .jumpRel32 displacement, size := 5, trailing := tail }
  | 0xe8 :: b0 :: b1 :: b2 :: b3 :: tail => do
      let displacement <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .callRel32 displacement, size := 5, trailing := tail }
  | 0xff :: 0x15 :: b0 :: b1 :: b2 :: b3 :: tail => do
      let address <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .callImport address, size := 6, trailing := tail }
  | 0xff :: 0x25 :: b0 :: b1 :: b2 :: b3 :: tail => do
      let address <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .jumpImport address, size := 6, trailing := tail }
  | 0x50 :: tail => some { instruction := .pushReg .eax, size := 1, trailing := tail }
  | 0xff :: 0xf0 :: tail => some { instruction := .pushReg .eax, size := 2, trailing := tail }
  | 0x5b :: tail => some { instruction := .popReg .ebx, size := 1, trailing := tail }
  | 0x8f :: 0xc3 :: tail => some { instruction := .popReg .ebx, size := 2, trailing := tail }
  | 0x8d :: 0x57 :: 0x04 :: tail => some { instruction := .lea .edx .edi 4, size := 3, trailing := tail }
  | 0x8b :: 0x06 :: tail => some { instruction := .load32 .eax .esi 0, size := 2, trailing := tail }
  | 0x8b :: 0x46 :: 0x00 :: tail => some { instruction := .load32 .eax .esi 0, size := 3, trailing := tail }
  | 0x8b :: 0x03 :: tail => some { instruction := .load32 .eax .ebx 0, size := 2, trailing := tail }
  | 0x8b :: 0x43 :: 0x00 :: tail => some { instruction := .load32 .eax .ebx 0, size := 3, trailing := tail }
  | 0x8b :: 0x0b :: tail => some { instruction := .load32 .ecx .ebx 0, size := 2, trailing := tail }
  | 0x8b :: 0x4b :: 0x00 :: tail => some { instruction := .load32 .ecx .ebx 0, size := 3, trailing := tail }
  | 0x89 :: 0x02 :: tail => some { instruction := .store32 .edx 0 .eax, size := 2, trailing := tail }
  | 0x89 :: 0x47 :: 0x04 :: tail => some { instruction := .store32 .edi 4 .eax, size := 3, trailing := tail }
  | 0x89 :: 0x03 :: tail => some { instruction := .store32 .ebx 0 .eax, size := 2, trailing := tail }
  | 0x89 :: 0x43 :: 0x00 :: tail => some { instruction := .store32 .ebx 0 .eax, size := 3, trailing := tail }
  | 0x29 :: 0xc0 :: tail => some { instruction := .zeroReg .eax, size := 2, trailing := tail }
  | 0x31 :: 0xc0 :: tail => some { instruction := .zeroReg .eax, size := 2, trailing := tail }
  | 0x0f :: 0xb7 :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .movZeroExtend parsed.reg parsed.operand 16,
        size := 2 + parsed.size,
        trailing := parsed.trailing,
      }
  | 0x0f :: 0xb6 :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .movZeroExtend parsed.reg parsed.operand 8,
        size := 2 + parsed.size,
        trailing := parsed.trailing,
      }
  | 0x0f :: 0xbf :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .movSignExtend parsed.reg parsed.operand 16
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0x0f :: 0xbe :: tail => do
      let parsed <- parseModRM tail
      let byteParsed <- parseModRM8 tail
      if parsed.size != byteParsed.size || parsed.trailing != byteParsed.trailing then
        none
      else
      pure {
        instruction := .movSignExtend8 parsed.reg byteParsed.operand
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0x0f :: 0xa3 :: tail => do
      let parsed <- parseModRM tail
      let base <-
        match parsed.operand with
        | .register base => some base
        | .memory _ | .immediate _ => none
      pure {
        instruction := .bitTestRegister base parsed.reg
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0x0f :: 0xaf :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .multiplyLow parsed.reg parsed.operand none
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0x0f :: 0xbd :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .bitScan .reverse parsed.reg parsed.operand
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0xf3 :: 0x0f :: 0xbc :: tail => do
      let parsed <- parseModRM tail
      let operation :=
        match profile.bmi1Evidence? with
        | none => BitScanOperation.forward
        | some evidence => .trailingZeroCount evidence
      pure {
        instruction := .bitScan operation parsed.reg parsed.operand
        size := 3 + parsed.size
        trailing := parsed.trailing
      }
  | 0x0f :: opcode :: tail =>
      if opcode == 0xa4 || opcode == 0xac then do
        let parsed <- parseModRM tail
        let immediate <- parsed.trailing.head?
        pure {
          instruction := .doubleShift (opcode == 0xa4) parsed.operand parsed.reg (.immediate (immediate % 32))
          size := 3 + parsed.size
          trailing := parsed.trailing.drop 1
        }
      else if opcode == 0xa5 || opcode == 0xad then do
        let parsed <- parseModRM tail
        pure {
          instruction := .doubleShift (opcode == 0xa5) parsed.operand parsed.reg .cl
          size := 2 + parsed.size
          trailing := parsed.trailing
        }
      else if 0x40 <= opcode && opcode <= 0x4f then do
        let condition <- conditionOfCode (opcode - 0x40)
        let parsed <- parseModRM tail
        pure {
          instruction := .conditionalMove condition parsed.reg parsed.operand
          size := 2 + parsed.size
          trailing := parsed.trailing
        }
      else if 0x90 <= opcode && opcode <= 0x9f then do
        let condition <- conditionOfCode (opcode - 0x90)
        let parsed <- parseModRM8 tail
        pure {
          instruction := .setCondition condition parsed.operand
          size := 2 + parsed.size
          trailing := parsed.trailing
        }
      else if 0x80 <= opcode && opcode <= 0x8f then do
        let condition <- conditionOfCode (opcode - 0x80)
        let displacement <- readU32 tail 0
        pure {
          instruction := .branchCondition condition displacement 6
          size := 6
          trailing := tail.drop 4
        }
      else
        none
  | bytes =>
      match decodeX87RegisterInstruction bytes with
      | some decoded => some decoded
      | none => decodeGenericInstruction bytes

def decodeInstruction : Bytes -> Option DecodedInstruction :=
  decodeInstructionForProfile .i686

def importAtAbsoluteAddress (pe : PE32) (absoluteAddress : Nat) : Option PEImport := do
  if absoluteAddress < pe.imageBase then none else
  let imports <- parseImports pe
  imports.find? (fun imported => imported.iatRva == absoluteAddress - pe.imageBase)

def importAtAbsoluteAddressFrom (imageBase : Nat) (imports : List PEImport)
    (absoluteAddress : Nat) : Option PEImport := do
  if absoluteAddress < imageBase then none else
  imports.find? (fun imported => imported.iatRva == absoluteAddress - imageBase)

def zeroArgumentImport (imported : PEImport) : Bool :=
  match imported.name with
  | .ordinal _ => false
  | .symbol bytes =>
      (imported.dll == [0x4b, 0x45, 0x52, 0x4e, 0x45, 0x4c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c] &&
        bytes == [0x47, 0x65, 0x74, 0x54, 0x69, 0x63, 0x6b, 0x43, 0x6f, 0x75, 0x6e, 0x74]) ||
      bytes.reverse.take 2 == [0x30, 0x40]

def Addressing.expression (addressing : Addressing) (registers : Registers Expr) : Expr :=
  let base := addressing.base.map (Registers.get registers) |>.getD (.constant 0)
  let index := addressing.index.map (Registers.get registers) |>.getD (.constant 0)
  let index := if addressing.scaleShift == 0 then index else .shiftLeft index addressing.scaleShift
  Expr.addNormalized (Expr.addNormalized base index) (.constant addressing.displacement)

def readOperand32 (state : SymbolicBehavior) : Operand32 -> Expr
  | .register reg => state.registers.get reg
  | .memory addressing => symbolicRead32 state (addressing.expression state.registers)
  | .immediate value => .constant value

def writeOperand32 (state : SymbolicBehavior) (destination : Operand32) (value : Expr) : Option SymbolicBehavior :=
  match destination with
  | .register reg => some { state with registers := state.registers.set reg value }
  | .memory addressing => some (state.write32 (addressing.expression state.registers) value)
  | .immediate _ => none

def readOperandWidth (width : OperandWidth) (state : SymbolicBehavior) : Operand32 -> Expr
  | .register reg => .bitAnd (state.registers.get reg) (.constant (2 ^ width.bits - 1))
  | .memory addressing =>
      let address := addressing.expression state.registers
      match width with
      | .byte => symbolicRead8 state address
      | .word => symbolicRead16 state address
  | .immediate value => .constant (value % (2 ^ width.bits))

def writeOperandWidth (width : OperandWidth) (state : SymbolicBehavior)
    (destination : Operand32) (value : Expr) : Option SymbolicBehavior :=
  let mask := 2 ^ width.bits - 1
  let value := Expr.bitAnd value (.constant mask)
  match destination with
  | .register reg =>
      let preserved := .bitAnd (state.registers.get reg) (.constant (2 ^ 32 - 1 - mask))
      some { state with registers := state.registers.set reg (.bitOr preserved value) }
  | .memory addressing =>
      let address := addressing.expression state.registers
      let composed :=
        match width with
        | .byte =>
            .bitOr value
              (.bitOr (.shiftLeft (symbolicRead8 state (address.offset 1)) 8)
                (.bitOr (.shiftLeft (symbolicRead8 state (address.offset 2)) 16)
                  (.shiftLeft (symbolicRead8 state (address.offset 3)) 24)))
        | .word =>
            .bitOr value
              (.bitOr (.shiftLeft (symbolicRead8 state (address.offset 2)) 16)
                (.shiftLeft (symbolicRead8 state (address.offset 3)) 24))
      some (state.write32 address composed)
  | .immediate _ => none

def readByteRegister (state : SymbolicBehavior) (register : ByteRegister) : Expr :=
  let value := state.registers.get register.parent
  if register.high then
    .bitAnd (.shiftRight value 8) (.constant 0xff)
  else
    .bitAnd value (.constant 0xff)

def writeByteRegister (state : SymbolicBehavior) (register : ByteRegister) (value : Expr) : SymbolicBehavior :=
  let current := state.registers.get register.parent
  let value := .bitAnd value (.constant 0xff)
  let result :=
    if register.high then
      .bitOr (.bitAnd current (.constant 0xffff00ff)) (.shiftLeft value 8)
    else
      .bitOr (.bitAnd current (.constant 0xffffff00)) value
  { state with registers := state.registers.set register.parent result }

def readOperand8 (state : SymbolicBehavior) : Operand8 -> Expr
  | .register reg => readByteRegister state reg
  | .memory addressing => symbolicRead8 state (addressing.expression state.registers)
  | .immediate value => .constant (value % 256)

def writeOperand8 (state : SymbolicBehavior) (destination : Operand8) (value : Expr) : Option SymbolicBehavior :=
  let value := Expr.bitAnd value (.constant 0xff)
  match destination with
  | .register reg => some (writeByteRegister state reg value)
  | .memory addressing =>
      let address := addressing.expression state.registers
      let composed :=
        .bitOr value
          (.bitOr (.shiftLeft (symbolicRead8 state (address.offset 1)) 8)
            (.bitOr (.shiftLeft (symbolicRead8 state (address.offset 2)) 16)
              (.shiftLeft (symbolicRead8 state (address.offset 3)) 24)))
      some (state.write32 address composed)
  | .immediate _ => none

def conditionExpression (flags : FlagsExpr) : Condition -> Option BoolExpr
  | .overflow => flags.overflow
  | .notOverflow => flags.overflow.map BoolExpr.not
  | .equal => flags.zero
  | .notEqual => flags.zero.map BoolExpr.not
  | .below => flags.carry
  | .aboveOrEqual => flags.carry.map BoolExpr.not
  | .belowOrEqual => do
      let carry <- flags.carry
      let zero <- flags.zero
      pure (.or carry zero)
  | .above => do
      let carry <- flags.carry
      let zero <- flags.zero
      pure (.and (.not carry) (.not zero))
  | .sign => flags.sign
  | .notSign => flags.sign.map BoolExpr.not
  | .parity => flags.parity
  | .notParity => flags.parity.map BoolExpr.not
  | .less => do
      let sign <- flags.sign
      let overflow <- flags.overflow
      pure (.xor sign overflow)
  | .greaterOrEqual => do
      let sign <- flags.sign
      let overflow <- flags.overflow
      pure (.not (.xor sign overflow))
  | .greater => do
      let zero <- flags.zero
      let sign <- flags.sign
      let overflow <- flags.overflow
      pure (.and (.not zero) (.not (.xor sign overflow)))
  | .lessOrEqual => do
      let zero <- flags.zero
      let sign <- flags.sign
      let overflow <- flags.overflow
      pure (.or zero (.xor sign overflow))

def DecodedInstruction.consumesExactly
    (decoded : DecodedInstruction) (input : Bytes) : Bool :=
  decoded.size > 0 && decoded.size <= 15 && decoded.size <= input.length &&
    decoded.trailing == input.drop decoded.size

/-- Fail closed unless the decoder's size and trailing bytes form an exact,
nonempty IA-32 instruction prefix of the fetched bytes. -/
def decodeInstructionExact (input : Bytes) : Option DecodedInstruction := do
  let decoded <- decodeInstruction input
  if decoded.consumesExactly input then some decoded else none

def decodeInstructionExactForProfile
    (profile : X86CPUProfile) (input : Bytes) : Option DecodedInstruction := do
  let decoded <- decodeInstructionForProfile profile input
  if decoded.consumesExactly input then some decoded else none


end SpaghettiExtractor.ISA.Formal
