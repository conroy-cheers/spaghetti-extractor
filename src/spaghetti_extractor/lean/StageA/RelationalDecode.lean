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

def codeTargetNatAddressMatches (candidate : Bool) (pe : PE32)
    (target : CodeTargetPair) (value : Nat) : Bool :=
  let primary := if candidate then target.candidateRva else target.originalRva
  let aliases := if candidate then target.candidateAliases else target.originalAliases
  value == pe.imageBase + primary ||
    aliases.any fun alias => value == pe.imageBase + alias.rva

structure BoundedImmutableRelocationTableJumpClaim where
  valueTargetId : Nat
  tableOffset : Nat
  originalBase : Nat
  candidateBase : Nat
  upperExclusive : Nat
  originalIndex : Expr
  candidateIndex : Expr
  entryTargetIds : List Nat
  finiteTargetIds : List Nat
deriving Repr, DecidableEq

def immutableCodeTargetEntryValid (candidate : Bool) (pe : PE32)
    (target : CodeTargetPair) (address : Nat) : Bool :=
  match readImmutableImageWord pe address 4 with
  | none => false
  | some value => codeTargetNatAddressMatches candidate pe target value

def BoundedImmutableRelocationTableJumpClaim.entryValid
    (originalPe candidatePe : PE32) (targets : List CodeTargetPair)
    (claim : BoundedImmutableRelocationTableJumpClaim) (index : Nat) : Bool :=
  match claim.entryTargetIds[index]? with
  | none => false
  | some targetId =>
      match targets.find? (fun target => target.id == targetId) with
      | none => false
      | some target =>
          claim.finiteTargetIds.contains targetId &&
            immutableCodeTargetEntryValid false originalPe target
              (claim.originalBase + index * 4) &&
            immutableCodeTargetEntryValid true candidatePe target
              (claim.candidateBase + index * 4) &&
            claim.tableOffset + index * 4 < 2 ^ 32

def BoundedImmutableRelocationTableJumpClaim.shapeChecked
    (values : List ValueTargetPair)
    (claim : BoundedImmutableRelocationTableJumpClaim) : Bool :=
  match values.find? (fun value => value.id == claim.valueTargetId) with
  | none => false
  | some table =>
      claim.upperExclusive > 0 &&
        claim.entryTargetIds.length == claim.upperExclusive &&
        table.originalValue + claim.tableOffset == claim.originalBase &&
        table.candidateValue + claim.tableOffset == claim.candidateBase &&
        decide (claim.tableOffset + claim.upperExclusive * 4 <= table.mappedSize) &&
        (List.range claim.upperExclusive).all (fun index =>
          table.relocationOffsets.contains (claim.tableOffset + index * 4)) &&
        claim.finiteTargetIds.all (fun targetId =>
          (claim.entryTargetIds.filter (· == targetId)).length > 0) &&
        claim.entryTargetIds.all claim.finiteTargetIds.contains &&
        claim.finiteTargetIds.all (fun targetId =>
          (claim.finiteTargetIds.filter (· == targetId)).length == 1)

def BoundedImmutableRelocationTableJumpClaim.entriesChecked
    (originalPe candidatePe : PE32) (targets : List CodeTargetPair)
    (claim : BoundedImmutableRelocationTableJumpClaim) : Bool :=
  (List.range claim.upperExclusive).all
    (claim.entryValid originalPe candidatePe targets)

def BoundedImmutableRelocationTableJumpClaim.checked
    (originalPe candidatePe : PE32) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (claim : BoundedImmutableRelocationTableJumpClaim) : Bool :=
  claim.shapeChecked values &&
    claim.entriesChecked originalPe candidatePe targets

def BoundedImmutableRelocationTableJumpClaim.EntriesClosed
    (originalPe candidatePe : PE32) (targets : List CodeTargetPair)
    (claim : BoundedImmutableRelocationTableJumpClaim) : Prop :=
  ∀ index, index < claim.upperExclusive ->
    claim.entryValid originalPe candidatePe targets index = true

theorem boundedImmutableRelocationTableJumpEntriesClosed_of_checked
    (originalPe candidatePe : PE32) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (claim : BoundedImmutableRelocationTableJumpClaim)
    (checked : claim.checked originalPe candidatePe targets values = true) :
    claim.EntriesClosed originalPe candidatePe targets := by
  unfold BoundedImmutableRelocationTableJumpClaim.checked at checked
  simp only [Bool.and_eq_true] at checked
  unfold BoundedImmutableRelocationTableJumpClaim.entriesChecked at checked
  simp only [List.all_eq_true] at checked
  intro index bounded
  exact checked.2 index (List.mem_range.mpr bounded)

def normalizeCodeTarget (candidate : Bool) (targets : List CodeTargetPair) (rva : Nat) : Option Nat :=
  (targets.find? fun target =>
    if candidate then target.candidateRva == rva || target.candidateAliases.any (·.rva == rva)
    else target.originalRva == rva || target.originalAliases.any (·.rva == rva)).map (·.id)

structure ExternalTarget where
  dll : Bytes
  name : ImportName
deriving Repr, DecidableEq

def asciiLowerByte (byte : Byte) : Byte :=
  if 65 ≤ byte ∧ byte ≤ 90 then byte + 32 else byte

def normalizeDllName (dll : Bytes) : Bytes :=
  dll.map asciiLowerByte

def normalizeImport (imported : PEImport) : ExternalTarget := {
  dll := normalizeDllName imported.dll
  name := imported.name
}

inductive MachineCallMemoryAccess where
  | read
  | write
deriving Repr, DecidableEq

inductive MachineCallMemorySize where
  | fixed (bytes : Nat)
  | argument (index scale : Nat)
  | product (leftIndex rightIndex : Nat)
  | boundedTerminated (sourceArgument sourceOffset unitBytes : Nat)
      (sentinel : Bytes) (maxUnits : Nat)
  | argumentOrBoundedTerminated
      (lengthArgument terminatedValue sourceArgument sourceOffset unitBytes : Nat)
      (sentinel : Bytes) (maxUnits : Nat)
deriving Repr, DecidableEq

structure MachineCallMemoryFootprint where
  access : MachineCallMemoryAccess
  baseArgument : Nat
  offset : Nat
  size : MachineCallMemorySize
  nullable : Bool := false
deriving Repr, DecidableEq

inductive MachineCallMemoryEffect where
  | none
  | readOnly
  | argumentRanges
  | newDynamicRanges
  | relationalState
deriving Repr, DecidableEq

inductive MachineCallWorldEffect where
  | none
  | opaqueResources
  | dynamicRanges
  | dynamicRangeRelease (argumentIndex : Nat)
  | callbackRegistration (argumentIndex : Nat)
  | tlsState
deriving Repr, DecidableEq

inductive MachineCallDisposition where
  | returns
  | terminates
  | protocol
deriving Repr, DecidableEq

inductive MachineCallResultWordRelationKind where
  | relatedWord
  | codePointer
  | dataPointer
  | nullableDynamicPointer
deriving Repr, DecidableEq

structure MachineCallResultWordRelation where
  offset : Nat
  kind : MachineCallResultWordRelationKind
deriving Repr, DecidableEq

inductive MachineCallResultRelationKind where
  | exact
  | relatedWord
  | dynamicRangeBase (size : MachineCallMemorySize) (minimumSize : Nat)
      (requiredWords : List MachineCallResultWordRelation) (nullable : Bool := false)
deriving Repr, DecidableEq

structure MachineCallResultRegisterRelation where
  register : Reg
  relation : MachineCallResultRelationKind
deriving Repr, DecidableEq

structure MachineImportCallContract where
  id : Nat
  imported : ExternalTarget
  stackArgumentOffsets : List Nat
  stackResultDelta : Nat
  preservedRegisters : List Reg
  clobberedRegisters : List Reg
  resultRegisterRelations : List MachineCallResultRegisterRelation := []
  disposition : MachineCallDisposition := .returns
  memoryEffect : MachineCallMemoryEffect
  memoryFootprints : List MachineCallMemoryFootprint := []
  worldEffect : MachineCallWorldEffect
deriving Repr, DecidableEq

def machineCallAbiRegisters : List Reg :=
  [.eax, .ebx, .ecx, .edx, .esi, .edi, .ebp]

def MachineCallMemorySize.shapeValid
    (argumentCount : Nat) : MachineCallMemorySize -> Bool
  | .fixed bytes => 0 < bytes && bytes < 2^32
  | .argument index scale => index < argumentCount && 0 < scale && scale < 2^32
  | .product leftIndex rightIndex =>
      leftIndex < argumentCount && rightIndex < argumentCount
  | .boundedTerminated sourceArgument sourceOffset unitBytes sentinel maxUnits =>
      sourceArgument < argumentCount && sourceOffset < 2^32 &&
        0 < unitBytes && sentinel.length == unitBytes && 0 < maxUnits &&
        unitBytes * maxUnits < 2^32 &&
        sourceOffset + unitBytes * maxUnits <= 2^32
  | .argumentOrBoundedTerminated lengthArgument terminatedValue sourceArgument
      sourceOffset unitBytes sentinel maxUnits =>
      lengthArgument < argumentCount && terminatedValue < 2^32 &&
        sourceArgument < argumentCount && sourceOffset < 2^32 &&
        0 < unitBytes && sentinel.length == unitBytes && 0 < maxUnits &&
        unitBytes * maxUnits < 2^32 &&
        sourceOffset + unitBytes * maxUnits <= 2^32

def MachineCallMemorySize.resultShapeValid
    (argumentCount : Nat) : MachineCallMemorySize -> Bool
  | size@(.fixed _) | size@(.argument _ _) | size@(.product _ _) =>
      size.shapeValid argumentCount
  | .boundedTerminated _ _ _ _ _ | .argumentOrBoundedTerminated _ _ _ _ _ _ _ =>
      false

def MachineCallMemorySize.canMeetMinimum
    (minimumSize : Nat) : MachineCallMemorySize -> Bool
  | .fixed bytes => minimumSize <= bytes
  | .argument _ _ | .product _ _ => true
  | .boundedTerminated _ _ _ _ _ | .argumentOrBoundedTerminated _ _ _ _ _ _ _ =>
      false

def MachineCallMemoryFootprint.shapeValid
    (argumentCount : Nat) (footprint : MachineCallMemoryFootprint) : Bool :=
  footprint.baseArgument < argumentCount && footprint.offset < 2^32 &&
    footprint.size.shapeValid argumentCount

def MachineImportCallContract.memoryShapeValid
    (contract : MachineImportCallContract) : Bool :=
  (contract.memoryFootprints.all fun footprint =>
      footprint.shapeValid contract.stackArgumentOffsets.length &&
        (contract.memoryFootprints.filter (· == footprint)).length == 1) &&
    match contract.memoryEffect with
    | .none => contract.memoryFootprints.isEmpty
    | .readOnly =>
        contract.memoryFootprints.all (·.access == .read)
    | .argumentRanges =>
        !contract.memoryFootprints.isEmpty &&
          contract.memoryFootprints.any (·.access == .write)
    | .newDynamicRanges =>
        contract.memoryFootprints.isEmpty &&
          contract.worldEffect == .dynamicRanges &&
          contract.resultRegisterRelations.any fun relation =>
            match relation.relation with
            | .dynamicRangeBase _ _ _ _ => true
            | _ => false
    | .relationalState => contract.memoryFootprints.isEmpty

def MachineCallResultRelationKind.shapeValid
    (argumentCount : Nat) (worldEffect : MachineCallWorldEffect) :
    MachineCallResultRelationKind -> Bool
  | .exact | .relatedWord => true
  | .dynamicRangeBase size minimumSize requiredWords _nullable =>
      worldEffect == .dynamicRanges &&
        size.resultShapeValid argumentCount &&
        size.canMeetMinimum minimumSize &&
        minimumSize < 2^32 &&
        (requiredWords.all fun word =>
          word.offset + 4 <= minimumSize &&
            (requiredWords.filter
              (fun other => other.offset == word.offset)).length == 1)

def MachineImportCallContract.shapeValid
    (contract : MachineImportCallContract) : Bool :=
  (contract.stackArgumentOffsets.all fun offset =>
      offset % 4 == 0 && offset + 4 <= 2^32 &&
        (contract.stackArgumentOffsets.filter (· == offset)).length == 1) &&
    contract.stackResultDelta % 4 == 0 && contract.stackResultDelta < 2^32 &&
    (contract.preservedRegisters.all fun register =>
      register != .esp &&
        (contract.preservedRegisters.filter (· == register)).length == 1 &&
        !contract.clobberedRegisters.contains register) &&
    (contract.clobberedRegisters.all fun register =>
      register != .esp &&
        (contract.clobberedRegisters.filter (· == register)).length == 1 &&
        !contract.preservedRegisters.contains register) &&
    (contract.resultRegisterRelations.all fun relation =>
      relation.register != .esp &&
        contract.clobberedRegisters.contains relation.register &&
        (contract.resultRegisterRelations.filter
          (fun other => other.register == relation.register)).length == 1 &&
        relation.relation.shapeValid contract.stackArgumentOffsets.length
          contract.worldEffect) &&
    (machineCallAbiRegisters.all fun register =>
      contract.preservedRegisters.contains register ||
        contract.clobberedRegisters.contains register) &&
    contract.memoryShapeValid &&
    (match contract.worldEffect with
    | .dynamicRangeRelease argumentIndex | .callbackRegistration argumentIndex =>
        argumentIndex < contract.stackArgumentOffsets.length
    | _ => true) &&
    match contract.disposition with
    | .returns => true
    | .terminates =>
        contract.stackResultDelta == 0 &&
          contract.memoryEffect == .none &&
          contract.memoryFootprints.isEmpty &&
          contract.resultRegisterRelations.isEmpty &&
          contract.worldEffect == .none
    | .protocol =>
        contract.worldEffect == .none &&
          contract.memoryEffect != .relationalState

def MachineImportCallContract.matchesImport
    (contract : MachineImportCallContract) (imported : PEImport) : Bool :=
  contract.imported == normalizeImport imported

def wordWriteAddressesProvablyDisjoint (left right : Expr) : Bool :=
  (List.range 4).all fun leftOffset =>
    (List.range 4).all fun rightOffset =>
      (left.offset leftOffset).provablyUnequal (right.offset rightOffset)

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

def machineCallStackArgument (behavior : SymbolicBehavior) (offset : Nat) : Expr :=
  let address := behavior.registers.esp.offset offset
  match exactWrite32WithDisjointTail? address behavior.writes with
  | some value => value
  | none => symbolicRead32 behavior address

def MachineImportCallContract.arguments
    (contract : MachineImportCallContract) (behavior : SymbolicBehavior) : List Expr :=
  contract.stackArgumentOffsets.map fun offset =>
    machineCallStackArgument behavior offset

def MachineImportCallContract.thunkArguments?
    (contract : MachineImportCallContract) (behavior : SymbolicBehavior) :
    Option (List Expr) :=
  if contract.stackArgumentOffsets.all fun offset => offset + 8 <= 2^32 then
    some (contract.stackArgumentOffsets.map fun offset =>
      machineCallStackArgument behavior (offset + 4))
  else
    none

def ExternalTarget.syntheticImport (target : ExternalTarget) : PEImport := {
  dll := target.dll
  name := target.name
  iatRva := 0
}

def callPushBase? : Expr -> Option Expr
  | .add base (.constant offset) =>
      let restoredOffset := (offset + 4) % (2 ^ 32)
      if restoredOffset = 0 then some base
      else some (.add base (.constant restoredOffset))
  | .sub base (.constant offset) =>
      let restoredOffset := (2 ^ 32 - offset + 4) % (2 ^ 32)
      if restoredOffset = 0 then some base
      else some (.add base (.constant restoredOffset))
  | _ => none

def externalizeRegisterImportCall (contract : MachineImportCallContract)
    (dispatchRegister : Reg) (behavior : SymbolicBehavior) : Option SymbolicBehavior :=
  match behavior.outcome with
  | some (.indirectCall (.inputReg targetRegister) continuation returnAddress) =>
      if targetRegister != dispatchRegister then none else
      match behavior.writes.reverse with
      | [] => none
      | (returnSlot, returnValue) :: priorWrites =>
          if returnSlot != behavior.registers.esp ||
              returnValue != .constant returnAddress then none else
          match callPushBase? behavior.registers.esp with
          | none => none
          | some preCallEsp =>
              let restored : SymbolicBehavior := {
                behavior with
                registers := behavior.registers.set .esp preCallEsp
                writes := priorWrites.reverse
                outcome := none
              }
              some {
                restored with outcome := some (.externalCall contract.imported.syntheticImport
                  (contract.arguments restored) continuation)
              }
  | _ => none

def applyMachineImportCallContracts
    (contracts : List MachineImportCallContract)
    (behavior : SymbolicBehavior) : Option SymbolicBehavior :=
  match behavior.outcome with
  | some (.externalCall imported _ continuation) =>
      match contracts.filter (·.matchesImport imported) with
      | [] => some behavior
      | [contract] => some {
          behavior with outcome := some (.externalCall imported
            (contract.arguments behavior) continuation)
        }
      | _ => none
  | some (.externalJump imported _) =>
      match contracts.filter (·.matchesImport imported) with
      | [] => some behavior
      | [contract] => do
          let arguments <- contract.thunkArguments? behavior
          some {
            behavior with outcome := some (.externalJump imported arguments)
          }
      | _ => none
  | _ => some behavior

def regionBehaviorWithMachineCallContracts (pe : PE32) (imports : List PEImport)
    (contracts : List MachineImportCallContract) (span : Span) : Option SymbolicBehavior := do
  let behavior <- regionBehaviorWithImports pe imports span
  applyMachineImportCallContracts contracts behavior

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

-- STAGE_A_EXTRACTION_SEMANTICS_END

end StageA.Relational
