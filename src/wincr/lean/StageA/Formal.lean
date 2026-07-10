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
  | read8 (address : Expr)
  | read32 (address : Expr)
  | extractByte (value : Expr) (index : Nat)
  | shiftLeft (value : Expr) (amount : Nat)
  | bitOr (left right : Expr)
  | ifEqual (left right thenValue elseValue : Expr)
deriving Repr, DecidableEq

def Expr.addNormalized (left right : Expr) : Expr :=
  match left, right with
  | expression, .constant 0 => expression
  | .constant 0, expression => expression
  | .constant a, .constant b => .constant ((a + b) % (2 ^ 32))
  | a, b => .add a b

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
  | .read8 address => BitVec.zeroExtend 32 (state.memory (address.eval state))
  | .read32 address => state.read32 (address.eval state)
  | .extractByte value index => BitVec.zeroExtend 32 ((value.eval state).extractLsb' (index * 8) 8)
  | .shiftLeft value amount => (value.eval state).shiftLeft amount
  | .bitOr left right => left.eval state ||| right.eval state
  | .ifEqual left right thenValue elseValue =>
      if left.eval state = right.eval state then thenValue.eval state else elseValue.eval state

inductive BoolExpr where
  | equal (left right : Expr)
  | not (value : BoolExpr)
deriving Repr, DecidableEq

def BoolExpr.eval (state : MachineState) : BoolExpr -> Bool
  | .equal left right => decide (left.eval state = right.eval state)
  | .not value => !(value.eval state)

inductive OutcomeExpr where
  | returned (target : Expr)
  | jump (targetRva : Nat)
  | branch (condition : BoolExpr) (trueTargetRva falseTargetRva : Nat)
deriving Repr, DecidableEq

structure SymbolicBehavior where
  registers : Registers Expr
  writes : List (Expr × Expr)
  comparison : Option (Expr × Expr)
  outcome : Option OutcomeExpr
deriving Repr, DecidableEq

inductive ConcreteOutcome where
  | returned (target : Word)
  | jump (targetRva : Nat)
  | branch (condition : Bool) (trueTargetRva falseTargetRva : Nat)

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
        .branch (condition.eval state) trueTargetRva falseTargetRva),
}

def readImmediate32 (bytes : Bytes) : Option Nat :=
  readU32 bytes 0

def signExtendImmediate8 (byte : Nat) : Nat :=
  if byte < 128 then byte else 2 ^ 32 - (256 - byte)

def relativeTarget8 (nextRva byte : Nat) : Nat :=
  if byte < 128 then nextRva + byte else nextRva - (256 - byte)

def executeCode : Nat -> Nat -> Bytes -> SymbolicBehavior -> Option (SymbolicBehavior × Bytes)
  | 0, _, _, _ => none
  | fuel + 1, pc, bytes, state =>
      match bytes with
      | [] => none
      | 0x90 :: tail => executeCode fuel (pc + 1) tail state
      | 0xc3 :: tail =>
          let stack := state.registers.esp
          let target := symbolicRead32 state stack
          let state := {
            state with
            registers := state.registers.set .esp (Expr.addNormalized stack (.constant 4))
            outcome := some (.returned target)
          }
          some (state, tail)
      | 0xb8 :: b0 :: b1 :: b2 :: b3 :: tail =>
          match readImmediate32 [b0, b1, b2, b3] with
          | none => none
          | some value =>
              executeCode fuel (pc + 5) tail { state with registers := state.registers.set .eax (.constant value) }
      | 0x89 :: 0xd8 :: tail =>
          executeCode fuel (pc + 2) tail { state with registers := state.registers.set .eax state.registers.ebx }
      | 0x8d :: 0x03 :: tail =>
          executeCode fuel (pc + 2) tail { state with registers := state.registers.set .eax state.registers.ebx }
      | 0x89 :: 0xda :: tail =>
          executeCode fuel (pc + 2) tail { state with registers := state.registers.set .edx state.registers.ebx }
      | 0x8d :: 0x13 :: tail =>
          executeCode fuel (pc + 2) tail { state with registers := state.registers.set .edx state.registers.ebx }
      | 0x83 :: 0xc0 :: 0x00 :: tail =>
          executeCode fuel (pc + 3) tail { state with comparison := some (state.registers.eax, .constant 0) }
      | 0x83 :: 0xe8 :: 0x00 :: tail =>
          executeCode fuel (pc + 3) tail { state with comparison := some (state.registers.eax, .constant 0) }
      | 0x83 :: 0xf8 :: immediate :: tail =>
          executeCode fuel (pc + 3) tail {
            state with comparison := some (state.registers.eax, .constant (signExtendImmediate8 immediate))
          }
      | 0x3d :: b0 :: b1 :: b2 :: b3 :: tail =>
          match readImmediate32 [b0, b1, b2, b3] with
          | none => none
          | some immediate =>
              executeCode fuel (pc + 5) tail {
                state with comparison := some (state.registers.eax, .constant immediate)
              }
      | 0x74 :: displacement :: tail =>
          match state.comparison with
          | none => none
          | some comparison =>
              let nextRva := pc + 2
              some ({ state with outcome := some (.branch (.equal comparison.1 comparison.2) (relativeTarget8 nextRva displacement) nextRva) }, tail)
      | 0x75 :: displacement :: tail =>
          match state.comparison with
          | none => none
          | some comparison =>
              let nextRva := pc + 2
              some ({ state with outcome := some (.branch (.not (.equal comparison.1 comparison.2)) (relativeTarget8 nextRva displacement) nextRva) }, tail)
      | 0xeb :: displacement :: tail =>
          let nextRva := pc + 2
          some ({ state with outcome := some (.jump (relativeTarget8 nextRva displacement)) }, tail)
      | 0x50 :: tail =>
          let stack := Expr.addNormalized state.registers.esp (.constant (2 ^ 32 - 4))
          let state := (state.write32 stack state.registers.eax)
          executeCode fuel (pc + 1) tail { state with registers := state.registers.set .esp stack }
      | 0xff :: 0xf0 :: tail =>
          let stack := Expr.addNormalized state.registers.esp (.constant (2 ^ 32 - 4))
          let state := (state.write32 stack state.registers.eax)
          executeCode fuel (pc + 2) tail { state with registers := state.registers.set .esp stack }
      | 0x5b :: tail =>
          let value := symbolicRead32 state state.registers.esp
          let stack := Expr.addNormalized state.registers.esp (.constant 4)
          let state := { state with registers := state.registers.set .ebx value }
          executeCode fuel (pc + 1) tail { state with registers := state.registers.set .esp stack }
      | 0x8f :: 0xc3 :: tail =>
          let value := symbolicRead32 state state.registers.esp
          let stack := Expr.addNormalized state.registers.esp (.constant 4)
          let state := { state with registers := state.registers.set .ebx value }
          executeCode fuel (pc + 2) tail { state with registers := state.registers.set .esp stack }
      | 0x8d :: 0x57 :: 0x04 :: tail =>
          let address := Expr.addNormalized state.registers.edi (.constant 4)
          executeCode fuel (pc + 3) tail { state with registers := state.registers.set .edx address }
      | 0x8b :: 0x06 :: tail =>
          let value := symbolicRead32 state state.registers.esi
          executeCode fuel (pc + 2) tail { state with registers := state.registers.set .eax value }
      | 0x8b :: 0x46 :: 0x00 :: tail =>
          let value := symbolicRead32 state state.registers.esi
          executeCode fuel (pc + 3) tail { state with registers := state.registers.set .eax value }
      | 0x8b :: 0x03 :: tail =>
          let value := symbolicRead32 state state.registers.ebx
          executeCode fuel (pc + 2) tail { state with registers := state.registers.set .eax value }
      | 0x8b :: 0x43 :: 0x00 :: tail =>
          let value := symbolicRead32 state state.registers.ebx
          executeCode fuel (pc + 3) tail { state with registers := state.registers.set .eax value }
      | 0x8b :: 0x0b :: tail =>
          let value := symbolicRead32 state state.registers.ebx
          executeCode fuel (pc + 2) tail { state with registers := state.registers.set .ecx value }
      | 0x8b :: 0x4b :: 0x00 :: tail =>
          let value := symbolicRead32 state state.registers.ebx
          executeCode fuel (pc + 3) tail { state with registers := state.registers.set .ecx value }
      | 0x89 :: 0x02 :: tail =>
          executeCode fuel (pc + 2) tail (state.write32 state.registers.edx state.registers.eax)
      | 0x89 :: 0x47 :: 0x04 :: tail =>
          let address := Expr.addNormalized state.registers.edi (.constant 4)
          executeCode fuel (pc + 3) tail (state.write32 address state.registers.eax)
      | 0x89 :: 0x03 :: tail =>
          executeCode fuel (pc + 2) tail (state.write32 state.registers.ebx state.registers.eax)
      | 0x89 :: 0x43 :: 0x00 :: tail =>
          executeCode fuel (pc + 3) tail (state.write32 state.registers.ebx state.registers.eax)
      | 0x29 :: 0xc0 :: tail =>
          executeCode fuel (pc + 2) tail {
            state with
            registers := state.registers.set .eax (.constant 0)
            comparison := some (.constant 0, .constant 0)
          }
      | 0x31 :: 0xc0 :: tail =>
          executeCode fuel (pc + 2) tail {
            state with
            registers := state.registers.set .eax (.constant 0)
            comparison := some (.constant 0, .constant 0)
          }
      | _ => none

def paddingByte (byte : Byte) : Bool :=
  byte == 0 || byte == 0x90

def paddingBytes : Bytes -> Bool
  | [] => true
  | 0x00 :: tail => paddingBytes tail
  | 0x90 :: tail => paddingBytes tail
  | 0x2e :: 0x8d :: 0x74 :: 0x26 :: 0x00 :: tail => paddingBytes tail
  | 0x2e :: 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail => paddingBytes tail
  | 0x8d :: 0xb6 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail => paddingBytes tail
  | 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail => paddingBytes tail
  | _ => false

def decodeEntryBehavior (bytes : Bytes) : Option SymbolicBehavior := do
  let (behavior, trailing) <- executeCode (bytes.length + 1) 0 bytes initialSymbolic
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
deriving Repr, DecidableEq

def executableEntrySection (pe : PE32) : Option Section :=
  match pe.sections.filter (fun sec => sec.executable) with
  | [sec] =>
      if sec.virtualAddress == pe.entrypointRva then some sec else none
  | _ => none

def loaderShape (pe : PE32) : Option LoaderShape := do
  let sec <- executableEntrySection pe
  if pe.importDirectoryRva != 0 || pe.importDirectorySize != 0 ||
      pe.relocationDirectoryRva != 0 || pe.relocationDirectorySize != 0 then
    none
  else
    pure {
      entrypointRva := pe.entrypointRva,
      imageBase := pe.imageBase,
      sectionAlignment := pe.sectionAlignment,
      fileAlignment := pe.fileAlignment,
      sizeOfImage := pe.sizeOfImage,
      executableVirtualAddress := sec.virtualAddress,
      sections := pe.sections,
    }

def imageBehavior (bytes : Bytes) : Option SymbolicBehavior := do
  let pe <- parsePE32 bytes
  let _ <- loaderShape pe
  let sec <- executableEntrySection pe
  let code <- sectionBytes pe sec
  decodeEntryBehavior code

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
  let (behavior, trailing) <- executeCode (bytes.length + 1) span.start bytes initialSymbolic
  if behavior.outcome.isSome && trailing.isEmpty then pure behavior else none

inductive LogicalOutcomeExpr where
  | returned (target : Expr)
  | jump (targetRegion : Nat)
  | branch (condition : BoolExpr) (trueTargetRegion falseTargetRegion : Nat)
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
        .branch (condition.eval state) trueTargetRegion falseTargetRegion,
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

inductive Execution where
  | running (region : Nat) (state : MachineState)
  | returned (target : Word) (state : MachineState)
  | fault

def behaviorAt (behaviors : List (Option LogicalBehavior)) (index : Nat) : Option LogicalBehavior :=
  (behaviors.drop index).head?.join

def stepExecution (behaviors : List (Option LogicalBehavior)) : Execution -> Execution
  | .running region state =>
      match behaviorAt behaviors region with
      | none => .fault
      | some behavior =>
          let concrete := behavior.eval state
          let nextState : MachineState := { registers := concrete.registers, memory := concrete.memory }
          match concrete.outcome with
          | .returned target => .returned target nextState
          | .jump targetRegion => .running targetRegion nextState
          | .branch condition trueTargetRegion falseTargetRegion =>
              .running (if condition then trueTargetRegion else falseTargetRegion) nextState
  | terminal => terminal

def executeFuel (behaviors : List (Option LogicalBehavior)) : Nat -> Execution -> Execution
  | 0, execution => execution
  | fuel + 1, execution => executeFuel behaviors fuel (stepExecution behaviors execution)

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
    forall state fuel start,
      start < bundle.regions.length ->
      executeFuel (candidateRegionBehaviors candidatePe bundle.regions) fuel (.running start state) =
      executeFuel (originalRegionBehaviors originalPe bundle.regions) fuel (.running start state)

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
  intro originalPe candidatePe originalEq candidateEq state fuel start _
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
