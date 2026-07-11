import Std

namespace StageA.Formal

abbrev Byte := Nat
abbrev Bytes := List Byte
abbrev Word := BitVec 32
abbrev Memory := Word -> BitVec 8

def readByte (bytes : Bytes) (offset : Nat) : Option Byte :=
  (bytes.drop offset).head?

def readU16 (bytes : Bytes) (offset : Nat) : Option Nat := do
  let b0 <- readByte bytes offset
  let b1 <- readByte bytes (offset + 1)
  if b0 < 256 && b1 < 256 then
    pure (b0 + b1 * 256)
  else
    none

def readU32 (bytes : Bytes) (offset : Nat) : Option Nat := do
  let lo <- readU16 bytes offset
  let hi <- readU16 bytes (offset + 2)
  pure (lo + hi * 65536)

structure Section where
  virtualSize : Nat
  virtualAddress : Nat
  rawSize : Nat
  rawPointer : Nat
  characteristics : Nat
deriving Repr, DecidableEq

def Section.mappedSize (sec : Section) : Nat :=
  if sec.virtualSize = 0 then sec.rawSize else sec.virtualSize

def Section.executable (sec : Section) : Bool :=
  Nat.testBit sec.characteristics 29

structure PE32 where
  bytes : Bytes
  peOffset : Nat
  entrypointRva : Nat
  imageBase : Nat
  sectionAlignment : Nat
  fileAlignment : Nat
  sizeOfImage : Nat
  importDirectoryRva : Nat
  importDirectorySize : Nat
  relocationDirectoryRva : Nat
  relocationDirectorySize : Nat
  sections : List Section
deriving Repr, DecidableEq

inductive ImportName where
  | symbol (bytes : Bytes)
  | ordinal (value : Nat)
deriving Repr, DecidableEq

structure PEImport where
  dll : Bytes
  name : ImportName
  iatRva : Nat
deriving Repr, DecidableEq

structure BaseRelocation where
  rva : Nat
  kind : Nat
deriving Repr, DecidableEq

def parseSection (bytes : Bytes) (offset : Nat) : Option Section := do
  let virtualSize <- readU32 bytes (offset + 8)
  let virtualAddress <- readU32 bytes (offset + 12)
  let rawSize <- readU32 bytes (offset + 16)
  let rawPointer <- readU32 bytes (offset + 20)
  let characteristics <- readU32 bytes (offset + 36)
  pure { virtualSize, virtualAddress, rawSize, rawPointer, characteristics }

def parseSections (bytes : Bytes) (offset count : Nat) : Option (List Section) :=
  match count with
  | 0 => some []
  | count + 1 => do
      let sec <- parseSection bytes offset
      let tail <- parseSections bytes (offset + 40) count
      pure (sec :: tail)

def parsePE32 (bytes : Bytes) : Option PE32 := do
  let mz0 <- readByte bytes 0
  let mz1 <- readByte bytes 1
  if mz0 != 0x4d || mz1 != 0x5a then none else
  let peOffset <- readU32 bytes 0x3c
  let p0 <- readByte bytes peOffset
  let p1 <- readByte bytes (peOffset + 1)
  let p2 <- readByte bytes (peOffset + 2)
  let p3 <- readByte bytes (peOffset + 3)
  if p0 != 0x50 || p1 != 0x45 || p2 != 0 || p3 != 0 then none else
  let machine <- readU16 bytes (peOffset + 4)
  let sectionCount <- readU16 bytes (peOffset + 6)
  let optionalSize <- readU16 bytes (peOffset + 20)
  let optionalOffset := peOffset + 24
  let magic <- readU16 bytes optionalOffset
  if machine != 0x14c || magic != 0x10b || optionalSize < 224 then none else
  let entrypointRva <- readU32 bytes (optionalOffset + 16)
  let imageBase <- readU32 bytes (optionalOffset + 28)
  let sectionAlignment <- readU32 bytes (optionalOffset + 32)
  let fileAlignment <- readU32 bytes (optionalOffset + 36)
  let sizeOfImage <- readU32 bytes (optionalOffset + 56)
  let importDirectoryRva <- readU32 bytes (optionalOffset + 104)
  let importDirectorySize <- readU32 bytes (optionalOffset + 108)
  let relocationDirectoryRva <- readU32 bytes (optionalOffset + 136)
  let relocationDirectorySize <- readU32 bytes (optionalOffset + 140)
  let sections <- parseSections bytes (optionalOffset + optionalSize) sectionCount
  pure {
    bytes,
    peOffset,
    entrypointRva,
    imageBase,
    sectionAlignment,
    fileAlignment,
    sizeOfImage,
    importDirectoryRva,
    importDirectorySize,
    relocationDirectoryRva,
    relocationDirectorySize,
    sections,
  }

def sectionBytes (pe : PE32) (sec : Section) : Option Bytes :=
  if sec.rawPointer + sec.rawSize > pe.bytes.length then
    none
  else if sec.mappedSize > sec.rawSize then
    let raw := (pe.bytes.drop sec.rawPointer).take sec.rawSize
    some (raw ++ List.replicate (sec.mappedSize - sec.rawSize) 0)
  else
    some ((pe.bytes.drop sec.rawPointer).take sec.mappedSize)

def rvaByte (pe : PE32) (rva : Nat) : Option Byte := do
  let sec <- pe.sections.find? (fun sec =>
    sec.virtualAddress <= rva && rva < sec.virtualAddress + sec.mappedSize)
  let bytes <- sectionBytes pe sec
  readByte bytes (rva - sec.virtualAddress)

def readRvaU16 (pe : PE32) (rva : Nat) : Option Nat := do
  let b0 <- rvaByte pe rva
  let b1 <- rvaByte pe (rva + 1)
  if b0 < 256 && b1 < 256 then pure (b0 + b1 * 256) else none

def readRvaU32 (pe : PE32) (rva : Nat) : Option Nat := do
  let lo <- readRvaU16 pe rva
  let hi <- readRvaU16 pe (rva + 2)
  pure (lo + hi * 65536)

def readCStringRva : PE32 -> Nat -> Nat -> Option Bytes
  | _, _, 0 => none
  | pe, rva, fuel + 1 => do
      let byte <- rvaByte pe rva
      if byte == 0 then
        pure []
      else if byte < 256 then
        let tail <- readCStringRva pe (rva + 1) fuel
        pure (byte :: tail)
      else
        none

def parseImportThunks : PE32 -> Bytes -> Nat -> Nat -> Nat -> Option (List PEImport)
  | _, _, _, _, 0 => none
  | pe, dll, lookupRva, iatRva, fuel + 1 => do
      let value <- readRvaU32 pe lookupRva
      if value == 0 then
        pure []
      else
        let name <-
          if Nat.testBit value 31 then
            pure (.ordinal (value % 65536))
          else do
            let _ <- readRvaU16 pe value
            let bytes <- readCStringRva pe (value + 2) 4096
            pure (.symbol bytes)
        let tail <- parseImportThunks pe dll (lookupRva + 4) (iatRva + 4) fuel
        pure ({ dll, name, iatRva } :: tail)

def parseImportDescriptors : PE32 -> Nat -> Nat -> Option (List PEImport)
  | _, _, 0 => none
  | pe, offset, fuel + 1 => do
      if offset + 20 > pe.importDirectorySize then none else
      let descriptorRva := pe.importDirectoryRva + offset
      let originalFirstThunk <- readRvaU32 pe descriptorRva
      let timestamp <- readRvaU32 pe (descriptorRva + 4)
      let forwarderChain <- readRvaU32 pe (descriptorRva + 8)
      let nameRva <- readRvaU32 pe (descriptorRva + 12)
      let firstThunk <- readRvaU32 pe (descriptorRva + 16)
      if originalFirstThunk == 0 && timestamp == 0 && forwarderChain == 0 && nameRva == 0 && firstThunk == 0 then
        pure []
      else if nameRva == 0 || firstThunk == 0 then
        none
      else
        let dll <- readCStringRva pe nameRva 4096
        let lookupRva := if originalFirstThunk == 0 then firstThunk else originalFirstThunk
        let imports <- parseImportThunks pe dll lookupRva firstThunk 65536
        let tail <- parseImportDescriptors pe (offset + 20) fuel
        pure (imports ++ tail)

def parseImports (pe : PE32) : Option (List PEImport) :=
  if pe.importDirectoryRva == 0 && pe.importDirectorySize == 0 then
    some []
  else if pe.importDirectoryRva == 0 || pe.importDirectorySize < 20 then
    none
  else
    parseImportDescriptors pe 0 (pe.importDirectorySize / 20 + 1)

def parseRelocationEntries (pe : PE32) (pageRva entriesRva count : Nat) : Option (List BaseRelocation) :=
  match count with
  | 0 => some []
  | count + 1 => do
      let value <- readRvaU16 pe entriesRva
      let kind := value / 4096
      let offset := value % 4096
      let tail <- parseRelocationEntries pe pageRva (entriesRva + 2) count
      if kind == 0 then
        pure tail
      else if kind == 3 then
        pure ({ rva := pageRva + offset, kind } :: tail)
      else
        none

def parseRelocationBlocks : PE32 -> Nat -> Nat -> Option (List BaseRelocation)
  | _, _, 0 => none
  | pe, offset, fuel + 1 => do
      if offset == pe.relocationDirectorySize then pure [] else
      if offset + 8 > pe.relocationDirectorySize then none else
      let blockRva := pe.relocationDirectoryRva + offset
      let pageRva <- readRvaU32 pe blockRva
      let blockSize <- readRvaU32 pe (blockRva + 4)
      if blockSize < 8 || blockSize % 2 != 0 || offset + blockSize > pe.relocationDirectorySize then none else
      let entries <- parseRelocationEntries pe pageRva (blockRva + 8) ((blockSize - 8) / 2)
      let tail <- parseRelocationBlocks pe (offset + blockSize) fuel
      pure (entries ++ tail)

def parseRelocations (pe : PE32) : Option (List BaseRelocation) :=
  if pe.relocationDirectoryRva == 0 && pe.relocationDirectorySize == 0 then
    some []
  else if pe.relocationDirectoryRva == 0 || pe.relocationDirectorySize < 8 then
    none
  else
    parseRelocationBlocks pe 0 (pe.relocationDirectorySize / 8 + 1)

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

inductive Expr where
  | inputReg (reg : Reg)
  | constant (value : Nat)
  | add (left right : Expr)
  | sub (left right : Expr)
  | bitAnd (left right : Expr)
  | bitXor (left right : Expr)
  | bitNot (value : Expr)
  | read8 (address : Expr)
  | read32 (address : Expr)
  | extractByte (value : Expr) (index : Nat)
  | shiftLeft (value : Expr) (amount : Nat)
  | shiftRight (value : Expr) (amount : Nat)
  | shiftLeftBy (value amount : Expr)
  | shiftRightBy (value amount : Expr)
  | shiftArithmeticRightBy (value amount : Expr)
  | bitOr (left right : Expr)
  | ifEqual (left right thenValue elseValue : Expr)
deriving Repr, DecidableEq

def Expr.addNormalized (left right : Expr) : Expr :=
  match left, right with
  | expression, .constant 0 => expression
  | .constant 0, expression => expression
  | .constant a, .constant b => .constant ((a + b) % (2 ^ 32))
  | a, b => .add a b

def Expr.subNormalized (left right : Expr) : Expr :=
  match left, right with
  | expression, .constant 0 => expression
  | .constant a, .constant b => .constant ((a + 2 ^ 32 - b) % (2 ^ 32))
  | a, b => .sub a b

def Expr.xorNormalized (left right : Expr) : Expr :=
  if left == right then .constant 0 else .bitXor left right

structure MachineState where
  registers : Registers Word
  memory : Memory

def MachineState.read32 (state : MachineState) (address : Word) : Word :=
  let b0 := BitVec.zeroExtend 32 (state.memory address)
  let b1 := (BitVec.zeroExtend 32 (state.memory (address + BitVec.ofNat 32 1))).shiftLeft 8
  let b2 := (BitVec.zeroExtend 32 (state.memory (address + BitVec.ofNat 32 2))).shiftLeft 16
  let b3 := (BitVec.zeroExtend 32 (state.memory (address + BitVec.ofNat 32 3))).shiftLeft 24
  b0 ||| b1 ||| b2 ||| b3

def Expr.eval (state : MachineState) : Expr -> Word
  | .inputReg reg => state.registers.get reg
  | .constant value => BitVec.ofNat 32 value
  | .add left right => left.eval state + right.eval state
  | .sub left right => left.eval state - right.eval state
  | .bitAnd left right => left.eval state &&& right.eval state
  | .bitXor left right => left.eval state ^^^ right.eval state
  | .bitNot value => ~~~(value.eval state)
  | .read8 address => BitVec.zeroExtend 32 (state.memory (address.eval state))
  | .read32 address => state.read32 (address.eval state)
  | .extractByte value index => BitVec.zeroExtend 32 ((value.eval state).extractLsb' (index * 8) 8)
  | .shiftLeft value amount => (value.eval state).shiftLeft amount
  | .shiftRight value amount => (value.eval state).ushiftRight amount
  | .shiftLeftBy value amount => (value.eval state).shiftLeft ((amount.eval state).toNat % 32)
  | .shiftRightBy value amount => (value.eval state).ushiftRight ((amount.eval state).toNat % 32)
  | .shiftArithmeticRightBy value amount => (value.eval state).sshiftRight ((amount.eval state).toNat % 32)
  | .bitOr left right => left.eval state ||| right.eval state
  | .ifEqual left right thenValue elseValue =>
      if left.eval state = right.eval state then thenValue.eval state else elseValue.eval state

inductive BoolExpr where
  | equal (left right : Expr)
  | not (value : BoolExpr)
  | and (left right : BoolExpr)
  | or (left right : BoolExpr)
  | xor (left right : BoolExpr)
  | unsignedLess (left right : Expr)
  | msb (value : Expr)
deriving Repr, DecidableEq

def BoolExpr.eval (state : MachineState) : BoolExpr -> Bool
  | .equal left right => decide (left.eval state = right.eval state)
  | .not value => !(value.eval state)
  | .and left right => left.eval state && right.eval state
  | .or left right => left.eval state || right.eval state
  | .xor left right => left.eval state != right.eval state
  | .unsignedLess left right => decide (left.eval state < right.eval state)
  | .msb value => Nat.testBit (value.eval state).toNat 31

structure FlagsExpr where
  zero : BoolExpr
  carry : BoolExpr
  sign : BoolExpr
  overflow : BoolExpr
deriving Repr, DecidableEq

def subtractionFlags (left right result : Expr) : FlagsExpr := {
  zero := .equal result (.constant 0)
  carry := .unsignedLess left right
  sign := .msb result
  overflow := .and (.xor (.msb left) (.msb right)) (.xor (.msb left) (.msb result))
}

def additionFlags (left right result : Expr) : FlagsExpr := {
  zero := .equal result (.constant 0)
  carry := .unsignedLess result left
  sign := .msb result
  overflow := .and (.not (.xor (.msb left) (.msb right))) (.xor (.msb left) (.msb result))
}

def logicalFlags (result : Expr) : FlagsExpr := {
  zero := .equal result (.constant 0)
  carry := .equal (.constant 0) (.constant 1)
  sign := .msb result
  overflow := .equal (.constant 0) (.constant 1)
}

inductive OutcomeExpr where
  | returned (target : Expr)
  | jump (targetRva : Nat)
  | branch (condition : BoolExpr) (trueTargetRva falseTargetRva : Nat)
  | call (targetRva returnRva returnAddress : Nat)
  | externalCall (imported : PEImport) (arguments : List Expr) (returnRva : Nat)
  | externalJump (imported : PEImport) (arguments : List Expr)
deriving Repr, DecidableEq

structure SymbolicBehavior where
  registers : Registers Expr
  writes : List (Expr × Expr)
  comparison : Option (Expr × Expr)
  flags : Option FlagsExpr
  outcome : Option OutcomeExpr
deriving Repr, DecidableEq

inductive ConcreteOutcome where
  | returned (target : Word)
  | jump (targetRva : Nat)
  | branch (condition : Bool) (trueTargetRva falseTargetRva : Nat)
  | call (targetRva returnRva returnAddress : Nat)
  | externalCall (imported : PEImport) (arguments : List Word) (returnRva : Nat)
  | externalJump (imported : PEImport) (arguments : List Word)

structure ConcreteBehavior where
  registers : Registers Word
  memory : Memory
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
  writes := [],
  comparison := none,
  flags := none,
  outcome := none,
}

def Memory.write32 (memory : Memory) (address value : Word) : Memory :=
  fun query =>
    if query = address then value.extractLsb' 0 8
    else if query = address + BitVec.ofNat 32 1 then value.extractLsb' 8 8
    else if query = address + BitVec.ofNat 32 2 then value.extractLsb' 16 8
    else if query = address + BitVec.ofNat 32 3 then value.extractLsb' 24 8
    else memory query

def applyWrites (state : MachineState) (writes : List (Expr × Expr)) : Memory :=
  writes.foldl (fun memory write => memory.write32 (write.1.eval state) (write.2.eval state)) state.memory

def Expr.offset (address : Expr) (amount : Nat) : Expr :=
  Expr.addNormalized address (.constant amount)

def symbolicRead8 (behavior : SymbolicBehavior) (address : Expr) : Expr :=
  behavior.writes.foldl (fun current write =>
    [0, 1, 2, 3].foldl (fun byte index =>
      .ifEqual address (write.1.offset index) (.extractByte write.2 index) byte) current) (.read8 address)

def symbolicRead32 (behavior : SymbolicBehavior) (address : Expr) : Expr :=
  let b0 := symbolicRead8 behavior address
  let b1 := .shiftLeft (symbolicRead8 behavior (address.offset 1)) 8
  let b2 := .shiftLeft (symbolicRead8 behavior (address.offset 2)) 16
  let b3 := .shiftLeft (symbolicRead8 behavior (address.offset 3)) 24
  .bitOr (.bitOr b0 b1) (.bitOr b2 b3)

def symbolicRead16 (behavior : SymbolicBehavior) (address : Expr) : Expr :=
  let b0 := symbolicRead8 behavior address
  let b1 := .shiftLeft (symbolicRead8 behavior (address.offset 1)) 8
  .bitOr b0 b1

def SymbolicBehavior.write32 (behavior : SymbolicBehavior) (address value : Expr) : SymbolicBehavior :=
  { behavior with writes := behavior.writes ++ [(address, value)] }

def SymbolicBehavior.eval (behavior : SymbolicBehavior) (state : MachineState) : ConcreteBehavior := {
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
  memory := applyWrites state behavior.writes,
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
        .externalJump imported (arguments.map (Expr.eval state))),
}

def readImmediate32 (bytes : Bytes) : Option Nat :=
  readU32 bytes 0

def signExtendImmediate8 (byte : Nat) : Nat :=
  if byte < 128 then byte else 2 ^ 32 - (256 - byte)

def relativeTarget8 (nextRva byte : Nat) : Nat :=
  if byte < 128 then nextRva + byte else nextRva - (256 - byte)

def relativeTarget32 (nextRva displacement : Nat) : Nat :=
  if displacement < 2 ^ 31 then nextRva + displacement else nextRva - (2 ^ 32 - displacement)

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
  | equal
  | notEqual
  | below
  | aboveOrEqual
  | above
  | greater
  | lessOrEqual
deriving Repr, DecidableEq

inductive ShiftOperation where
  | left
  | right
  | arithmeticRight
deriving Repr, DecidableEq

inductive ShiftCount where
  | immediate (value : Nat)
  | cl
deriving Repr, DecidableEq

inductive UnaryOperation where
  | bitNot
  | negate
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
  | unary (operation : UnaryOperation) (destination : Operand32)
  | branchCondition (condition : Condition) (displacement size : Nat)
  | movZeroExtend (destination : Reg) (source : Operand32) (width : Nat)
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

def decodeGenericInstruction : Bytes -> Option DecodedInstruction
  | opcode :: tail =>
      if 0xb8 <= opcode && opcode <= 0xbf then do
        let destination <- registerOfCode (opcode - 0xb8)
        let value <- readU32 tail 0
        pure { instruction := .movRegImm destination value, size := 5, trailing := tail.drop 4 }
      else if 0x50 <= opcode && opcode <= 0x57 then do
        let source <- registerOfCode (opcode - 0x50)
        pure { instruction := .pushReg source, size := 1, trailing := tail }
      else if 0x58 <= opcode && opcode <= 0x5f then do
        let destination <- registerOfCode (opcode - 0x58)
        pure { instruction := .popReg destination, size := 1, trailing := tail }
      else
        match opcode with
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
        | 0x8d => decodedModRM (fun parsed =>
            match parsed.operand with
            | .memory address => some (.leaAddress parsed.reg address)
            | .register _ | .immediate _ => none) tail
        | 0xc7 => decodedModRMImmediate32 (fun parsed value =>
            if parsed.reg == .eax then some (.movImmediate parsed.operand value) else none) tail
        | 0x03 => decodedModRM (fun parsed => some (.binary .add (.register parsed.reg) parsed.operand)) tail
        | 0x01 => decodedModRM (fun parsed => some (.binary .add parsed.operand (.register parsed.reg))) tail
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
        | 0x83 => decodedModRMImmediate8 (fun parsed value =>
            match parsed.reg with
            | .eax => some (.binary .add parsed.operand (.immediate value))
            | .ecx => some (.binary .or parsed.operand (.immediate value))
            | .esp => some (.binary .and parsed.operand (.immediate value))
            | .ebp => some (.binary .sub parsed.operand (.immediate value))
            | .esi => some (.binary .xor parsed.operand (.immediate value))
            | .edi => some (.binary .compare parsed.operand (.immediate value))
            | _ => none) tail
        | 0x81 => decodedModRMImmediate32 (fun parsed value =>
            match parsed.reg with
            | .eax => some (.binary .add parsed.operand (.immediate value))
            | .ecx => some (.binary .or parsed.operand (.immediate value))
            | .esp => some (.binary .and parsed.operand (.immediate value))
            | .ebp => some (.binary .sub parsed.operand (.immediate value))
            | .esi => some (.binary .xor parsed.operand (.immediate value))
            | .edi => some (.binary .compare parsed.operand (.immediate value))
            | _ => none) tail
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
        | 0xf7 => decodedModRM (fun parsed =>
            match parsed.reg with
            | .edx => some (.unary .bitNot parsed.operand)
            | .ebx => some (.unary .negate parsed.operand)
            | _ => none) tail
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

def decodeInstruction : Bytes -> Option DecodedInstruction
  | 0x90 :: tail => some { instruction := .nop, size := 1, trailing := tail }
  | 0x66 :: 0x90 :: tail => some { instruction := .nop, size := 2, trailing := tail }
  | 0x2e :: 0x8d :: 0x74 :: 0x26 :: 0x00 :: tail => some { instruction := .nop, size := 5, trailing := tail }
  | 0x2e :: 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail =>
      some { instruction := .nop, size := 8, trailing := tail }
  | 0x8d :: 0xb6 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail =>
      some { instruction := .nop, size := 6, trailing := tail }
  | 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail =>
      some { instruction := .nop, size := 7, trailing := tail }
  | 0xc3 :: tail => some { instruction := .ret, size := 1, trailing := tail }
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
  | 0x0f :: opcode :: b0 :: b1 :: b2 :: b3 :: tail => do
      let condition <-
        match opcode with
        | 0x84 => some Condition.equal
        | 0x85 => some Condition.notEqual
        | 0x82 => some Condition.below
        | 0x83 => some Condition.aboveOrEqual
        | 0x87 => some Condition.above
        | 0x8f => some Condition.greater
        | 0x8e => some Condition.lessOrEqual
        | _ => none
      let displacement <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .branchCondition condition displacement 6, size := 6, trailing := tail }
  | bytes => decodeGenericInstruction bytes

def importAtAbsoluteAddress (pe : PE32) (absoluteAddress : Nat) : Option PEImport := do
  if absoluteAddress < pe.imageBase then none else
  let imports <- parseImports pe
  imports.find? (fun imported => imported.iatRva == absoluteAddress - pe.imageBase)

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

def conditionExpression (flags : FlagsExpr) : Condition -> BoolExpr
  | .equal => flags.zero
  | .notEqual => .not flags.zero
  | .below => flags.carry
  | .aboveOrEqual => .not flags.carry
  | .above => .and (.not flags.carry) (.not flags.zero)
  | .greater => .and (.not flags.zero) (.not (.xor flags.sign flags.overflow))
  | .lessOrEqual => .or flags.zero (.xor flags.sign flags.overflow)

inductive InstructionResult where
  | next (state : SymbolicBehavior)
  | stop (state : SymbolicBehavior)

def executeInstruction (pe : PE32) (pc : Nat) (decoded : DecodedInstruction)
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
        | some flags => some flags.zero
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
  | .popReg destination =>
      let value := symbolicRead32 state state.registers.esp
      let stack := state.registers.esp.offset 4
      some (.next { state with registers := (state.registers.set destination value).set .esp stack })
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
        flags := some (logicalFlags (.constant 0))
      })
  | .callRel32 displacement =>
      let stack := state.registers.esp.offset (2 ^ 32 - 4)
      let state := state.write32 stack (.constant (pe.imageBase + nextRva))
      some (.stop {
        state with
        registers := state.registers.set .esp stack
        outcome := some (.call (relativeTarget32 nextRva displacement) nextRva (pe.imageBase + nextRva))
      })
  | .callImport absoluteAddress => do
      let imported <- importAtAbsoluteAddress pe absoluteAddress
      some (.stop { state with outcome := some (.externalCall imported [] nextRva) })
  | .jumpImport absoluteAddress => do
      let imported <- importAtAbsoluteAddress pe absoluteAddress
      some (.stop { state with outcome := some (.externalJump imported []) })
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
        | .xor | .and | .or | .test => logicalFlags result
      let next <-
        match operation with
        | .compare | .test => some state
        | _ => writeOperand32 state destination result
      some (.next { next with flags := some flags })
  | .shift operation destination count => do
      let value := readOperand32 state destination
      let amount :=
        match count with
        | .immediate amount => Expr.constant amount
        | .cl => .bitAnd (state.registers.get .ecx) (.constant 0x1f)
      let result :=
        match operation, count with
        | .left, .immediate amount => .shiftLeft value amount
        | .right, .immediate amount => .shiftRight value amount
        | .arithmeticRight, .immediate amount => .shiftArithmeticRightBy value (.constant amount)
        | .left, .cl => .shiftLeftBy value amount
        | .right, .cl => .shiftRightBy value amount
        | .arithmeticRight, .cl => .shiftArithmeticRightBy value amount
      let next <- writeOperand32 state destination result
      some (.next { next with flags := none, comparison := none })
  | .unary operation destination => do
      let value := readOperand32 state destination
      let result :=
        match operation with
        | .bitNot => .bitNot value
        | .negate => Expr.subNormalized (.constant 0) value
      let next <- writeOperand32 state destination result
      let flags :=
        match operation with
        | .bitNot => state.flags
        | .negate => some (subtractionFlags (.constant 0) value result)
      some (.next { next with flags })
  | .branchCondition condition displacement size => do
      let flags <- state.flags
      let target := if size == 2 then relativeTarget8 nextRva displacement else relativeTarget32 nextRva displacement
      some (.stop {
        state with outcome := some (.branch (conditionExpression flags condition) target nextRva)
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

def executeCode (pe : PE32) : Nat -> Nat -> Bytes -> SymbolicBehavior -> Option (SymbolicBehavior × Bytes)
  | 0, _, _, _ => none
  | fuel + 1, pc, bytes, state => do
      let decoded <- decodeInstruction bytes
      let result <- executeInstruction pe pc decoded state
      match result with
      | .next nextState => executeCode pe fuel (pc + decoded.size) decoded.trailing nextState
      | .stop finalState => pure (finalState, decoded.trailing)

def paddingByte (byte : Byte) : Bool :=
  byte == 0 || byte == 0x90

def paddingBytes : Bytes -> Bool
  | [] => true
  | 0x00 :: tail => paddingBytes tail
  | 0x90 :: tail => paddingBytes tail
  | 0x66 :: 0x90 :: tail => paddingBytes tail
  | 0x2e :: 0x8d :: 0x74 :: 0x26 :: 0x00 :: tail => paddingBytes tail
  | 0x2e :: 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail => paddingBytes tail
  | 0x8d :: 0xb6 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail => paddingBytes tail
  | 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail => paddingBytes tail
  | _ => false

def decodeEntryBehavior (pe : PE32) (bytes : Bytes) : Option SymbolicBehavior := do
  let (behavior, trailing) <- executeCode pe (bytes.length + 1) pe.entrypointRva bytes initialSymbolic
  if behavior.outcome.isSome && paddingBytes trailing then
    pure behavior
  else
    none

structure LoaderShape where
  entrypointRva : Nat
  imageBase : Nat
  sectionAlignment : Nat
  fileAlignment : Nat
  sizeOfImage : Nat
  executableVirtualAddress : Nat
  sections : List Section
  imports : List PEImport
  relocations : List BaseRelocation
deriving Repr, DecidableEq

def executableEntrySection (pe : PE32) : Option Section :=
  match pe.sections.filter (fun sec =>
    sec.executable && sec.virtualAddress <= pe.entrypointRva && pe.entrypointRva < sec.virtualAddress + sec.mappedSize) with
  | [sec] => some sec
  | _ => none

def loaderShape (pe : PE32) : Option LoaderShape := do
  let sec <- executableEntrySection pe
  let imports <- parseImports pe
  let relocations <- parseRelocations pe
  pure {
    entrypointRva := pe.entrypointRva,
    imageBase := pe.imageBase,
    sectionAlignment := pe.sectionAlignment,
    fileAlignment := pe.fileAlignment,
    sizeOfImage := pe.sizeOfImage,
    executableVirtualAddress := sec.virtualAddress,
    sections := pe.sections,
    imports,
    relocations,
  }

def imageBehavior (bytes : Bytes) : Option SymbolicBehavior := do
  let pe <- parsePE32 bytes
  let _ <- loaderShape pe
  let sec <- executableEntrySection pe
  let code <- sectionBytes pe sec
  decodeEntryBehavior pe (code.drop (pe.entrypointRva - sec.virtualAddress))

def runImage (bytes : Bytes) (state : MachineState) : Option ConcreteBehavior :=
  (imageBehavior bytes).map (fun behavior => behavior.eval state)

def StrongRefines (original candidate : Bytes) : Prop :=
  forall state, runImage candidate state = runImage original state

def bundleEligible (original candidate : Bytes) : Bool :=
  match parsePE32 original, parsePE32 candidate with
  | some originalPe, some candidatePe =>
      decide (loaderShape originalPe = loaderShape candidatePe) &&
      decide (imageBehavior candidate = imageBehavior original) &&
      (imageBehavior original).isSome
  | _, _ => false

def checkBundle (original candidate : Bytes) : Bool :=
  bundleEligible original candidate

theorem checkBundle_sound (original candidate : Bytes)
    (checked : checkBundle original candidate = true) :
    StrongRefines original candidate := by
  unfold checkBundle bundleEligible at checked
  split at checked <;> try contradiction
  rename_i originalPe candidatePe originalParsed candidateParsed
  simp only [Bool.and_eq_true, decide_eq_true_eq] at checked
  have behaviorEqual : imageBehavior candidate = imageBehavior original := checked.1.2
  intro state
  simp only [runImage, behaviorEqual]

structure Span where
  start : Nat
  size : Nat
deriving Repr, DecidableEq

def Span.stop (span : Span) : Nat :=
  span.start + span.size

structure RegionPair where
  original : Span
  candidate : Span
  root : Bool
deriving Repr, DecidableEq

structure ProofBundle where
  originalBytes : Bytes
  candidateBytes : Bytes
  regions : List RegionPair
  originalPadding : List Span
  candidatePadding : List Span
deriving Repr, DecidableEq

def spanBytes (pe : PE32) (span : Span) : Option Bytes := do
  let sec <- pe.sections.find? (fun sec =>
    sec.executable && sec.virtualAddress <= span.start && span.stop <= sec.virtualAddress + sec.mappedSize)
  let mapped <- sectionBytes pe sec
  let offset := span.start - sec.virtualAddress
  if offset + span.size <= mapped.length then
    pure ((mapped.drop offset).take span.size)
  else
    none

def regionBehavior (pe : PE32) (span : Span) : Option SymbolicBehavior := do
  let bytes <- spanBytes pe span
  let (behavior, trailing) <- executeCode pe (bytes.length + 1) span.start bytes initialSymbolic
  if behavior.outcome.isSome && trailing.isEmpty then pure behavior else none

inductive LogicalOutcomeExpr where
  | returned (target : Expr)
  | jump (targetRegion : Nat)
  | branch (condition : BoolExpr) (trueTargetRegion falseTargetRegion : Nat)
  | call (targetRegion returnRegion returnAddress : Nat)
  | externalCall (imported : PEImport) (arguments : List Expr) (returnRegion : Nat)
  | externalJump (imported : PEImport) (arguments : List Expr)
deriving Repr, DecidableEq

structure LogicalBehavior where
  registers : Registers Expr
  writes : List (Expr × Expr)
  outcome : LogicalOutcomeExpr
deriving Repr, DecidableEq

inductive LogicalConcreteOutcome where
  | returned (target : Word)
  | jump (targetRegion : Nat)
  | branch (condition : Bool) (trueTargetRegion falseTargetRegion : Nat)
  | call (targetRegion returnRegion returnAddress : Nat)
  | externalCall (imported : PEImport) (arguments : List Word) (returnRegion : Nat)
  | externalJump (imported : PEImport) (arguments : List Word)

structure LogicalConcreteBehavior where
  registers : Registers Word
  memory : Memory
  outcome : LogicalConcreteOutcome

def findRegionIndex (candidate : Bool) (targetRva : Nat) : List RegionPair -> Nat -> Option Nat
  | [], _ => none
  | region :: tail, index =>
      let start := if candidate then region.candidate.start else region.original.start
      if start == targetRva then some index else findRegionIndex candidate targetRva tail (index + 1)

def normalizeOutcome (regions : List RegionPair) (candidate : Bool) : OutcomeExpr -> Option LogicalOutcomeExpr
  | .returned target => some (.returned target)
  | .jump targetRva => do
      let target <- findRegionIndex candidate targetRva regions 0
      pure (.jump target)
  | .branch condition trueTargetRva falseTargetRva => do
      let trueTarget <- findRegionIndex candidate trueTargetRva regions 0
      let falseTarget <- findRegionIndex candidate falseTargetRva regions 0
      pure (.branch condition trueTarget falseTarget)
  | .call targetRva returnRva returnAddress => do
      let target <- findRegionIndex candidate targetRva regions 0
      let continuation <- findRegionIndex candidate returnRva regions 0
      pure (.call target continuation returnAddress)
  | .externalCall imported arguments returnRva => do
      let continuation <- findRegionIndex candidate returnRva regions 0
      pure (.externalCall imported arguments continuation)
  | .externalJump imported arguments =>
      pure (.externalJump imported arguments)

def normalizeBehavior (regions : List RegionPair) (candidate : Bool) (behavior : SymbolicBehavior) : Option LogicalBehavior := do
  let outcomeExpr <- behavior.outcome
  let outcome <- normalizeOutcome regions candidate outcomeExpr
  pure { registers := behavior.registers, writes := behavior.writes, outcome }

def originalRegionBehaviors (pe : PE32) (regions : List RegionPair) : List (Option LogicalBehavior) :=
  regions.map (fun region => (regionBehavior pe region.original).bind (normalizeBehavior regions false))

def candidateRegionBehaviors (pe : PE32) (regions : List RegionPair) : List (Option LogicalBehavior) :=
  regions.map (fun region => (regionBehavior pe region.candidate).bind (normalizeBehavior regions true))

def LogicalBehavior.eval (behavior : LogicalBehavior) (state : MachineState) : LogicalConcreteBehavior := {
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
  memory := applyWrites state behavior.writes,
  outcome := match behavior.outcome with
    | .returned target => .returned (target.eval state)
    | .jump targetRegion => .jump targetRegion
    | .branch condition trueTargetRegion falseTargetRegion =>
        .branch (condition.eval state) trueTargetRegion falseTargetRegion
    | .call targetRegion returnRegion returnAddress => .call targetRegion returnRegion returnAddress
    | .externalCall imported arguments returnRegion =>
        .externalCall imported (arguments.map (Expr.eval state)) returnRegion
    | .externalJump imported arguments =>
        .externalJump imported (arguments.map (Expr.eval state)),
}

def insertSpan (span : Span) : List Span -> List Span
  | [] => [span]
  | head :: tail =>
      if span.start <= head.start then span :: head :: tail else head :: insertSpan span tail

def sortSpans : List Span -> List Span
  | [] => []
  | head :: tail => insertSpan head (sortSpans tail)

def spansCoverFrom : Nat -> Nat -> List Span -> Bool
  | cursor, stop, [] => cursor == stop
  | cursor, stop, span :: tail =>
      span.size > 0 && span.start == cursor && span.stop <= stop && spansCoverFrom span.stop stop tail

def spansInSection (sec : Section) (spans : List Span) : List Span :=
  spans.filter (fun span => sec.virtualAddress <= span.start && span.stop <= sec.virtualAddress + sec.mappedSize)

def spanInExecutableSection (pe : PE32) (span : Span) : Bool :=
  pe.sections.any (fun sec =>
    sec.executable && span.size > 0 && sec.virtualAddress <= span.start && span.stop <= sec.virtualAddress + sec.mappedSize)

def executableCoverageClosed (pe : PE32) (spans : List Span) : Bool :=
  spans.all (spanInExecutableSection pe) &&
  (pe.sections.filter (fun sec => sec.executable)).all (fun sec =>
    spansCoverFrom sec.virtualAddress (sec.virtualAddress + sec.mappedSize) (sortSpans (spansInSection sec spans)))

def paddingSpanValid (pe : PE32) (span : Span) : Bool :=
  match spanBytes pe span with
  | some bytes => paddingBytes bytes
  | none => false

def entryRegionMatches (originalPe candidatePe : PE32) (region : RegionPair) : Bool :=
  region.root && region.original.start == originalPe.entrypointRva && region.candidate.start == candidatePe.entrypointRva

def rootCoverageClosed (originalPe candidatePe : PE32) (regions : List RegionPair) : Bool :=
  regions.any (entryRegionMatches originalPe candidatePe)

def proofBundleEligible (bundle : ProofBundle) : Bool :=
  match parsePE32 bundle.originalBytes, parsePE32 bundle.candidateBytes with
  | some originalPe, some candidatePe =>
      (loaderShape originalPe).isSome &&
      (loaderShape candidatePe).isSome &&
      decide (loaderShape originalPe = loaderShape candidatePe) &&
      (originalRegionBehaviors originalPe bundle.regions).all Option.isSome &&
      bundle.regions.length > 0 &&
      executableCoverageClosed originalPe (bundle.regions.map (fun region => region.original) ++ bundle.originalPadding) &&
      executableCoverageClosed candidatePe (bundle.regions.map (fun region => region.candidate) ++ bundle.candidatePadding) &&
      bundle.originalPadding.all (paddingSpanValid originalPe) &&
      bundle.candidatePadding.all (paddingSpanValid candidatePe) &&
      rootCoverageClosed originalPe candidatePe bundle.regions &&
      decide (candidateRegionBehaviors candidatePe bundle.regions = originalRegionBehaviors originalPe bundle.regions)
  | _, _ => false

def checkProofBundle (bundle : ProofBundle) : Bool :=
  proofBundleEligible bundle

def runLogicalRegions (pe : PE32) (regions : List RegionPair) (candidate : Bool)
    (state : MachineState) : List (Option LogicalConcreteBehavior) :=
  let behaviors := if candidate then candidateRegionBehaviors pe regions else originalRegionBehaviors pe regions
  behaviors.map (Option.map (fun behavior => behavior.eval state))

def StrongRefinesBundle (bundle : ProofBundle) : Prop :=
  forall originalPe candidatePe,
    parsePE32 bundle.originalBytes = some originalPe ->
    parsePE32 bundle.candidateBytes = some candidatePe ->
    forall state,
      runLogicalRegions candidatePe bundle.regions true state =
      runLogicalRegions originalPe bundle.regions false state

theorem checkProofBundle_sound (bundle : ProofBundle)
    (checked : checkProofBundle bundle = true) :
    StrongRefinesBundle bundle := by
  unfold checkProofBundle proofBundleEligible at checked
  split at checked <;> try contradiction
  rename_i parsedOriginal parsedCandidate originalParsed candidateParsed
  simp only [Bool.and_eq_true, decide_eq_true_eq] at checked
  have symbolicEqual :
      candidateRegionBehaviors parsedCandidate bundle.regions =
      originalRegionBehaviors parsedOriginal bundle.regions := checked.2
  intro originalPe candidatePe originalEq candidateEq state
  have originalPeEq : originalPe = parsedOriginal := by
    rw [originalParsed] at originalEq
    exact Option.some.inj originalEq.symm
  have candidatePeEq : candidatePe = parsedCandidate := by
    rw [candidateParsed] at candidateEq
    exact Option.some.inj candidateEq.symm
  subst originalPe
  subst candidatePe
  change
    List.map (Option.map (fun behavior => behavior.eval state))
        (candidateRegionBehaviors parsedCandidate bundle.regions) =
      List.map (Option.map (fun behavior => behavior.eval state))
        (originalRegionBehaviors parsedOriginal bundle.regions)
  exact congrArg (List.map (Option.map (fun behavior => behavior.eval state))) symbolicEqual

structure ExternalEvent where
  imported : PEImport
  state : MachineState

structure Environment where
  result : Nat -> ExternalEvent -> MachineState

def applyEnvironment (environment : Environment) (index : Nat) (event : ExternalEvent)
    : MachineState := environment.result index event

structure CallFrame where
  returnRegion : Nat
  returnAddress : Word

inductive Execution where
  | running (region : Nat) (state : MachineState) (calls : List CallFrame)
      (eventIndex : Nat) (events : List ExternalEvent)
  | returned (target : Word) (state : MachineState) (events : List ExternalEvent)
  | fault

def behaviorAt (behaviors : List (Option LogicalBehavior)) (index : Nat) : Option LogicalBehavior :=
  (behaviors.drop index).head?.join

def stepExecution (environment : Environment) (behaviors : List (Option LogicalBehavior)) : Execution -> Execution
  | .running region state calls eventIndex events =>
      match behaviorAt behaviors region with
      | none => .fault
      | some behavior =>
          let concrete := behavior.eval state
          let nextState : MachineState := { registers := concrete.registers, memory := concrete.memory }
          match concrete.outcome with
          | .returned target =>
              match calls with
              | [] => .returned target nextState events
              | frame :: tail =>
                  if target == frame.returnAddress then
                    .running frame.returnRegion nextState tail eventIndex events
                  else
                    .fault
          | .jump targetRegion => .running targetRegion nextState calls eventIndex events
          | .branch condition trueTargetRegion falseTargetRegion =>
              .running (if condition then trueTargetRegion else falseTargetRegion) nextState calls eventIndex events
          | .call targetRegion returnRegion returnAddress =>
              .running targetRegion nextState
                ({ returnRegion, returnAddress := BitVec.ofNat 32 returnAddress } :: calls) eventIndex events
          | .externalCall imported arguments returnRegion =>
              let _ := arguments
              let event := { imported, state := nextState }
              let result := applyEnvironment environment eventIndex event
              .running returnRegion result calls (eventIndex + 1) (events ++ [event])
          | .externalJump imported arguments =>
              let _ := arguments
              let event := { imported, state := nextState }
              let result := applyEnvironment environment eventIndex event
              match calls with
              | [] => .returned (BitVec.ofNat 32 0) result (events ++ [event])
              | frame :: tail =>
                  .running frame.returnRegion result tail (eventIndex + 1) (events ++ [event])
  | terminal => terminal

def executeFuel (environment : Environment) (behaviors : List (Option LogicalBehavior)) : Nat -> Execution -> Execution
  | 0, execution => execution
  | fuel + 1, execution => executeFuel environment behaviors fuel (stepExecution environment behaviors execution)

def entryRegionIndex (originalPe candidatePe : PE32) : List RegionPair -> Nat -> Option Nat
  | [], _ => none
  | region :: tail, index =>
      if entryRegionMatches originalPe candidatePe region then
        some index
      else
        entryRegionIndex originalPe candidatePe tail (index + 1)

theorem rootCoverage_entryRegionIndex_isSome (originalPe candidatePe : PE32)
    (regions : List RegionPair) (index : Nat)
    (closed : rootCoverageClosed originalPe candidatePe regions = true) :
    (entryRegionIndex originalPe candidatePe regions index).isSome = true := by
  induction regions generalizing index with
  | nil => simp [rootCoverageClosed] at closed
  | cons region tail ih =>
      unfold rootCoverageClosed at closed
      simp only [List.any_cons, Bool.or_eq_true] at closed
      unfold entryRegionIndex
      by_cases hmatch : entryRegionMatches originalPe candidatePe region = true
      · simp [hmatch]
      · simp [hmatch]
        apply ih
        exact closed.resolve_left hmatch

def StrongTraceRefines (bundle : ProofBundle) : Prop :=
  forall originalPe candidatePe,
    parsePE32 bundle.originalBytes = some originalPe ->
    parsePE32 bundle.candidateBytes = some candidatePe ->
    forall environment state fuel start,
      start < bundle.regions.length ->
      executeFuel environment (candidateRegionBehaviors candidatePe bundle.regions) fuel (.running start state [] 0 []) =
      executeFuel environment (originalRegionBehaviors originalPe bundle.regions) fuel (.running start state [] 0 [])

theorem checkProofBundle_trace_sound (bundle : ProofBundle)
    (checked : checkProofBundle bundle = true) :
    StrongTraceRefines bundle := by
  unfold checkProofBundle proofBundleEligible at checked
  split at checked <;> try contradiction
  rename_i parsedOriginal parsedCandidate originalParsed candidateParsed
  simp only [Bool.and_eq_true, decide_eq_true_eq] at checked
  have symbolicEqual :
      candidateRegionBehaviors parsedCandidate bundle.regions =
      originalRegionBehaviors parsedOriginal bundle.regions := checked.2
  intro originalPe candidatePe originalEq candidateEq environment state fuel start _
  have originalPeEq : originalPe = parsedOriginal := by
    rw [originalParsed] at originalEq
    exact Option.some.inj originalEq.symm
  have candidatePeEq : candidatePe = parsedCandidate := by
    rw [candidateParsed] at candidateEq
    exact Option.some.inj candidateEq.symm
  subst originalPe
  subst candidatePe
  rw [symbolicEqual]

def ExactImageStrongRefinement (bundle : ProofBundle) : Prop :=
  checkProofBundle bundle = true ∧ StrongRefinesBundle bundle ∧ StrongTraceRefines bundle

theorem checkProofBundle_guarantee (bundle : ProofBundle)
    (checked : checkProofBundle bundle = true) :
    ExactImageStrongRefinement bundle :=
  And.intro checked (And.intro (checkProofBundle_sound bundle checked) (checkProofBundle_trace_sound bundle checked))

end StageA.Formal
