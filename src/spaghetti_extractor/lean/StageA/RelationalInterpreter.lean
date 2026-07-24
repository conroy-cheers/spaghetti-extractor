import StageA.Formal

namespace StageA.Relational.Interpreter

open StageA.Formal

inductive Register where
  | eax | ebx | ecx | edx | esi | edi | ebp | esp
deriving Repr, DecidableEq

def Register.ofIndex? : Nat -> Option Register
  | 0 => some .eax
  | 1 => some .ebx
  | 2 => some .ecx
  | 3 => some .edx
  | 4 => some .esi
  | 5 => some .edi
  | 6 => some .ebp
  | 7 => some .esp
  | _ => none

inductive Flag where
  | cf | zf | sf | ofl | pf | df
deriving Repr, DecidableEq

def Flag.ofIndex? : Nat -> Option Flag
  | 0 => some .cf
  | 1 => some .zf
  | 2 => some .sf
  | 3 => some .ofl
  | 4 => some .pf
  | 5 => some .df
  | _ => none

def Flag.eflagsBit : Flag -> Nat
  | .cf => 0
  | .zf => 6
  | .sf => 7
  | .ofl => 11
  | .pf => 2
  | .df => 10

inductive MemoryWidth where
  | byte | word | dword
deriving Repr, DecidableEq

def MemoryWidth.ofBytes? : Nat -> Option MemoryWidth
  | 1 => some .byte
  | 2 => some .word
  | 4 => some .dword
  | _ => none

def MemoryWidth.bytes : MemoryWidth -> Nat
  | .byte => 1
  | .word => 2
  | .dword => 4

/-- The stable non-x87 word-opcode prefix emitted by the Stage B backend. -/
inductive WordOpcode where
  | constant | register | flag | trueValue | falseValue
  | undefinedBv | undefinedFlag | callResponse | callFlag | load
  | sub32 | ult32 | equal | xorBool | equalBool
  | add32 | mul32 | xor32 | and32 | or32 | not32 | neg32
  | shl32 | lshr32 | sar | signExtend | ite | msb | boolNot
  | andBool | orBool | parity | boolToBit | addOverflow | subOverflow
  | imulLow32 | mulLow32 | imulHigh32 | mulHigh32 | imulOverflow
  | mulCarry | udivQuot32 | udivRem32 | udivValid32 | bsrIndex
  | tzcnt | sbbBorrow | sbbOverflow | shiftCf | shiftOf
deriving Repr, DecidableEq

def WordOpcode.ofNat? : Nat -> Option WordOpcode
  | 0 => some .constant
  | 1 => some .register
  | 2 => some .flag
  | 3 => some .trueValue
  | 4 => some .falseValue
  | 5 => some .undefinedBv
  | 6 => some .undefinedFlag
  | 7 => some .callResponse
  | 8 => some .callFlag
  | 9 => some .load
  | 10 => some .sub32
  | 11 => some .ult32
  | 12 => some .equal
  | 13 => some .xorBool
  | 14 => some .equalBool
  | 15 => some .add32
  | 16 => some .mul32
  | 17 => some .xor32
  | 18 => some .and32
  | 19 => some .or32
  | 20 => some .not32
  | 21 => some .neg32
  | 22 => some .shl32
  | 23 => some .lshr32
  | 24 => some .sar
  | 25 => some .signExtend
  | 26 => some .ite
  | 27 => some .msb
  | 28 => some .boolNot
  | 29 => some .andBool
  | 30 => some .orBool
  | 31 => some .parity
  | 32 => some .boolToBit
  | 33 => some .addOverflow
  | 34 => some .subOverflow
  | 35 => some .imulLow32
  | 36 => some .mulLow32
  | 37 => some .imulHigh32
  | 38 => some .mulHigh32
  | 39 => some .imulOverflow
  | 40 => some .mulCarry
  | 41 => some .udivQuot32
  | 42 => some .udivRem32
  | 43 => some .udivValid32
  | 44 => some .bsrIndex
  | 45 => some .tzcnt
  | 46 => some .sbbBorrow
  | 47 => some .sbbOverflow
  | 48 => some .shiftCf
  | 49 => some .shiftOf
  | _ => none

def arityBetween (arity minimum maximum : Nat) : Bool :=
  minimum <= arity && arity <= maximum

def isU32 (value : Nat) : Bool := value < 2 ^ 32

def WordOpcode.arityValid (op : WordOpcode) (arity : Nat) : Bool :=
  match op with
  | .constant | .register | .flag | .trueValue | .falseValue |
      .callResponse | .callFlag => arity == 0
  | .undefinedBv | .undefinedFlag => arity <= 1
  | .load | .not32 | .neg32 | .boolNot | .boolToBit => arity == 1
  | .sub32 | .ult32 | .equal | .xorBool | .equalBool | .shl32 | .lshr32 |
      .signExtend | .parity | .imulLow32 | .mulLow32 | .imulHigh32 |
      .mulHigh32 | .bsrIndex | .tzcnt | .shiftCf => arity == 2
  | .sar | .ite | .udivQuot32 | .udivRem32 | .udivValid32 | .shiftOf =>
      arity == 3
  | .add32 | .mul32 | .xor32 | .and32 | .or32 => arityBetween arity 2 4
  | .msb => arityBetween arity 1 2
  | .andBool | .orBool => arityBetween arity 1 5
  | .addOverflow | .subOverflow | .mulCarry => arity == 4
  | .imulOverflow | .sbbBorrow | .sbbOverflow => arity == 5

def validShiftAux (aux : Nat) : Bool :=
  let kind := aux / 256
  let width := aux % 256
  kind < 3 && (width == 8 || width == 16 || width == 32)

structure RawWordNode where
  op : Nat
  arity : Nat
  aux : Nat
  immediate : Nat
  args : List Nat
deriving Repr, DecidableEq

structure SemanticWordNode where
  op : WordOpcode
  aux : Nat
  immediate : Nat
  args : List Nat
deriving Repr, DecidableEq

def RawWordNode.decode (node : RawWordNode) : Option SemanticWordNode := do
  let op <- WordOpcode.ofNat? node.op
  if node.args.length != node.arity || !op.arityValid node.arity ||
      !isU32 node.immediate then none else
  let fieldsValid : Bool := match op with
    | .register | .callResponse => node.aux < 8
    | .flag | .callFlag => node.aux < 6
    | .load => (MemoryWidth.ofBytes? node.aux).isSome
    | .shiftCf | .shiftOf => validShiftAux node.aux
    | .constant | .undefinedBv | .undefinedFlag => node.aux == 0
    | _ => node.aux == 0 && node.immediate == 0
  if fieldsValid then some {
    op := op
    aux := node.aux
    immediate := node.immediate
    args := node.args
  } else none

inductive CallKind where
  | external | internal | indirect
deriving Repr, DecidableEq

def CallKind.ofNat? : Nat -> Option CallKind
  | 0 => some .external
  | 1 => some .internal
  | 2 => some .indirect
  | _ => none

structure RawStackInput where
  offset : Nat
  width : Nat
  valueNode : Nat
deriving Repr, DecidableEq

structure SemanticStackInput where
  offset : Nat
  width : MemoryWidth
  valueNode : Nat
deriving Repr, DecidableEq

def RawStackInput.decode (input : RawStackInput) : Option SemanticStackInput := do
  if !isU32 input.offset || !isU32 input.valueNode then none else
  let width <- MemoryWidth.ofBytes? input.width
  some { offset := input.offset, width := width, valueNode := input.valueNode }

structure RawCall where
  kind : Nat
  instructionRva : Nat
  callIndex : Nat
  targetNode : Option Nat
  targetRva : Nat
  returnRva : Nat
  dll : Option String
  symbol : Option String
  ordinal : Option Nat
  registerNodes : List Nat
  flagNodes : List Nat
  argumentNodes : List Nat
  stackInputs : List RawStackInput
deriving Repr, DecidableEq

structure SemanticCall where
  kind : CallKind
  instructionRva : Nat
  callIndex : Nat
  targetNode : Option Nat
  targetRva : Nat
  returnRva : Nat
  dll : Option String
  symbol : Option String
  ordinal : Option Nat
  registerNodes : List Nat
  flagNodes : List Nat
  argumentNodes : List Nat
  stackInputs : List SemanticStackInput
deriving Repr, DecidableEq

def RawCall.decode (call : RawCall) : Option SemanticCall := do
  let kind <- CallKind.ofNat? call.kind
  let stackInputs <- call.stackInputs.mapM RawStackInput.decode
  let targetShape := match kind, call.targetNode with
    | .indirect, some _ => true
    | .external, none | .internal, none => true
    | _, _ => false
  if call.registerNodes.length != 8 || call.flagNodes.length != 6 ||
      call.argumentNodes.length > 64 || stackInputs.length > 64 ||
      !targetShape || !isU32 call.instructionRva || !isU32 call.callIndex ||
      !isU32 call.targetRva || !isU32 call.returnRva ||
      !call.ordinal.all isU32 then none else
  some {
    kind := kind
    instructionRva := call.instructionRva
    callIndex := call.callIndex
    targetNode := call.targetNode
    targetRva := call.targetRva
    returnRva := call.returnRva
    dll := call.dll
    symbol := call.symbol
    ordinal := call.ordinal
    registerNodes := call.registerNodes
    flagNodes := call.flagNodes
    argumentNodes := call.argumentNodes
    stackInputs := stackInputs
  }

structure RawAction where
  op : Nat
  arity : Nat
  aux : Nat
  args : List Nat
deriving Repr, DecidableEq

inductive SemanticAction where
  | evalWord (node : Nat)
  | memoryWrite (address value : Nat) (width : MemoryWidth)
  | divideIf (condition : Nat)
  | call (call : Nat)
  | repMovsd (source destination count directionFlag : Nat)
  | setRegister (register : Register) (value : Nat)
  | setFlag (flag : Flag) (value : Nat)
  | syncEflags
deriving Repr, DecidableEq

inductive SemanticOutcome where
  | fallthrough (targetRva : Nat)
  | jump (targetRva : Nat)
  | branch (condition : Nat) (trueTargetRva falseTargetRva : Nat)
  | returned (value : Nat)
  | indirectJump (target : Nat)
  | externalJump
deriving Repr, DecidableEq

def RawAction.decodeBody (action : RawAction) : Option SemanticAction :=
  if action.args.length != action.arity || !isU32 action.aux ||
      !action.args.all isU32 then none else
  match action.op, action.args with
  | 0, [node] => if action.aux == 0 then some (.evalWord node) else none
  | 2, [address, value] => do
      let width <- MemoryWidth.ofBytes? action.aux
      some (.memoryWrite address value width)
  | 3, [condition] => if action.aux == 0 then some (.divideIf condition) else none
  | 4, [call] => if action.aux == 0 then some (.call call) else none
  | 5, [source, destination, count, direction] =>
      if action.aux == 0 then some (.repMovsd source destination count direction) else none
  | 6, [value] => do
      let register <- Register.ofIndex? action.aux
      some (.setRegister register value)
  | 7, [value] => do
      let flag <- Flag.ofIndex? action.aux
      some (.setFlag flag value)
  | 18, [] => if action.aux == 0 then some .syncEflags else none
  | _, _ => none

def RawAction.decodeOutcome (action : RawAction) : Option SemanticOutcome :=
  if action.args.length != action.arity || action.aux != 0 ||
      !action.args.all isU32 then none else
  match action.op, action.args with
  | 19, [target] => some (.fallthrough target)
  | 20, [target] => some (.jump target)
  | 21, [condition, trueTarget, falseTarget] =>
      some (.branch condition trueTarget falseTarget)
  | 22, [value] => some (.returned value)
  | 23, [target] => some (.indirectJump target)
  | 24, [] => some .externalJump
  | _, _ => none

structure SemanticTransfer where
  sourceRva : Nat
  wordNodes : List SemanticWordNode
  calls : List SemanticCall
  body : List SemanticAction
  outcome : SemanticOutcome
deriving Repr, DecidableEq

/-- Public Stage A identity carried next to the typed semantic transfer.  The
generator emits the two immutable hashes verbatim; this kernel proves the
program-record/transfer equality and leaves file hashing to the binary-binding
layer. -/
structure ExportedSemanticTransfer where
  identity : String
  contractSha256 : String
  instructionBytesSha256 : String
  transfer : SemanticTransfer
deriving Repr, DecidableEq

structure ProgramRecord where
  sourceRva : Nat
  wordNodes : List RawWordNode
  x87Nodes : List RawWordNode
  calls : List RawCall
  actions : List RawAction
deriving Repr, DecidableEq

def ProgramRecord.decode (record : ProgramRecord) : Option SemanticTransfer := do
  if !isU32 record.sourceRva || !record.x87Nodes.isEmpty ||
      record.wordNodes.length > 1024 then none else
  let wordNodes <- record.wordNodes.mapM RawWordNode.decode
  let calls <- record.calls.mapM RawCall.decode
  match record.actions.reverse with
  | [] => none
  | final :: reverseBody => do
      let body <- reverseBody.reverse.mapM RawAction.decodeBody
      let outcome <- final.decodeOutcome
      some {
        sourceRva := record.sourceRva
        wordNodes := wordNodes
        calls := calls
        body := body
        outcome := outcome
      }

def referencesBelow (limit : Nat) (references : List Nat) : Bool :=
  references.all fun reference => reference < limit

def SemanticTransfer.wordNodesBackwardChecked (transfer : SemanticTransfer) : Bool :=
  let rec loop (index : Nat) : List SemanticWordNode -> Bool
    | [] => true
    | node :: tail => referencesBelow index node.args && loop (index + 1) tail
  loop 0 transfer.wordNodes

def SemanticCall.references (call : SemanticCall) : List Nat :=
  call.targetNode.toList ++ call.registerNodes ++ call.flagNodes ++
    call.argumentNodes ++ call.stackInputs.map (fun input => input.valueNode)

def SemanticTransfer.callsStaticChecked (transfer : SemanticTransfer) : Bool :=
  decide (transfer.calls.map (fun call => call.callIndex)).Nodup &&
    transfer.calls.all fun call =>
      referencesBelow transfer.wordNodes.length call.references

structure ActionCheckState where
  ready : List Nat := []
  usedCalls : List Nat := []
  lastCallIndex : Option Nat := none
deriving Repr, DecidableEq

def ActionCheckState.referencesReady (state : ActionCheckState)
    (references : List Nat) : Bool :=
  references.all state.ready.contains

def SemanticTransfer.checkAction (transfer : SemanticTransfer)
    (state : ActionCheckState) : SemanticAction -> Option ActionCheckState
  | .evalWord nodeIndex => do
      if state.ready.contains nodeIndex then none else
      let node <- transfer.wordNodes[nodeIndex]?
      if !state.referencesReady node.args then none else
      let callReady := match node.op with
        | .callResponse | .callFlag => state.lastCallIndex == some node.immediate
        | _ => true
      if !callReady then none else
      some { state with ready := nodeIndex :: state.ready }
  | .memoryWrite address value _ =>
      if state.referencesReady [address, value] then some state else none
  | .repMovsd source destination count direction =>
      if state.referencesReady [source, destination, count, direction] then some state else none
  | .divideIf condition | .setRegister _ condition | .setFlag _ condition =>
      if state.referencesReady [condition] then some state else none
  | .call callIndex => do
      if state.usedCalls.contains callIndex then none else
      let call <- transfer.calls[callIndex]?
      if !state.referencesReady call.references then none else
      some {
        ready := state.ready
        usedCalls := callIndex :: state.usedCalls
        lastCallIndex := some call.callIndex
      }
  | .syncEflags => some state

def SemanticTransfer.checkBody (transfer : SemanticTransfer) : Option ActionCheckState :=
  transfer.body.foldlM transfer.checkAction {}

def SemanticTransfer.outcomeChecked (transfer : SemanticTransfer)
    (state : ActionCheckState) : Bool :=
  match transfer.outcome with
  | .fallthrough _ | .jump _ | .externalJump => true
  | .branch condition _ _ | .returned condition | .indirectJump condition =>
      state.referencesReady [condition]

def SemanticTransfer.checked (transfer : SemanticTransfer) : Bool :=
  transfer.wordNodesBackwardChecked && transfer.callsStaticChecked &&
    match transfer.checkBody with
    | none => false
    | some state =>
        transfer.outcomeChecked state &&
          state.ready.length == transfer.wordNodes.length &&
          state.usedCalls.length == transfer.calls.length

def ProgramRecord.checked (record : ProgramRecord) : Bool :=
  match record.decode with
  | none => false
  | some transfer => transfer.checked

/-- Structural validity is deliberately stated through successful typed
decoding plus the schedule checker.  Numeric opcodes outside the supported
prefix, x87 records, and malformed references therefore have no witness. -/
def ProgramRecord.StructurallyValid (record : ProgramRecord) : Prop :=
  exists transfer, record.decode = some transfer ∧ transfer.checked = true

theorem ProgramRecord.checked_iff_structurallyValid (record : ProgramRecord) :
    record.checked = true <-> record.StructurallyValid := by
  unfold ProgramRecord.checked ProgramRecord.StructurallyValid
  cases decoded : record.decode with
  | none => simp
  | some transfer => simp

theorem ProgramRecord.structurallyValid_of_checked (record : ProgramRecord)
    (checked : record.checked = true) : record.StructurallyValid :=
  (record.checked_iff_structurallyValid).mp checked

structure InterpreterMachine where
  registers : Register -> Word
  flags : Flag -> Word
  memory : Memory
  eflags : Word

def InterpreterMachine.setRegister (state : InterpreterMachine)
    (register : Register) (value : Word) : InterpreterMachine :=
  { state with registers := fun query => if query = register then value else state.registers query }

def InterpreterMachine.setFlag (state : InterpreterMachine)
    (flag : Flag) (value : Word) : InterpreterMachine :=
  { state with flags := fun query =>
      if query = flag then BitVec.ofNat 32 (value.toNat % 2) else state.flags query }

def writeMemoryByte (memory : Memory) (address : Word) (value : BitVec 8) : Memory :=
  fun query => if query = address then value else memory query

def readMemory (memory : Memory) (address : Word) : MemoryWidth -> Word
  | .byte => BitVec.zeroExtend 32 (memory address)
  | .word =>
      BitVec.zeroExtend 32 (memory address) |||
        (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 1))).shiftLeft 8
  | .dword =>
      BitVec.zeroExtend 32 (memory address) |||
        (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 1))).shiftLeft 8 |||
        (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 2))).shiftLeft 16 |||
        (BitVec.zeroExtend 32 (memory (address + BitVec.ofNat 32 3))).shiftLeft 24

def writeMemory (memory : Memory) (address value : Word) : MemoryWidth -> Memory
  | .byte => writeMemoryByte memory address (value.extractLsb' 0 8)
  | .word =>
      writeMemoryByte (writeMemoryByte memory address (value.extractLsb' 0 8))
        (address + BitVec.ofNat 32 1) (value.extractLsb' 8 8)
  | .dword =>
      writeMemoryByte (writeMemoryByte (writeMemoryByte
        (writeMemoryByte memory address (value.extractLsb' 0 8))
        (address + BitVec.ofNat 32 1) (value.extractLsb' 8 8))
        (address + BitVec.ofNat 32 2) (value.extractLsb' 16 8))
        (address + BitVec.ofNat 32 3) (value.extractLsb' 24 8)

def wordTruth (value : Word) : Bool := value != BitVec.ofNat 32 0

def boolWord (value : Bool) : Word :=
  BitVec.ofNat 32 (if value then 1 else 0)

def widthMask (width : Nat) : Word :=
  if width >= 32 then BitVec.ofNat 32 0xffffffff
  else BitVec.ofNat 32 (2 ^ width - 1)

def signExtendWord (width : Nat) (value : Word) : Word :=
  let masked := value &&& widthMask width
  if width = 0 || !Nat.testBit masked.toNat (width - 1) then masked
  else masked ||| ~~~(widthMask width)

def highestSetBit : Nat -> Nat -> Nat
  | _, 0 => 0
  | value, fuel + 1 =>
      if Nat.testBit value fuel then fuel else highestSetBit value fuel

def trailingZeroCount : Nat -> Nat -> Nat
  | _, 0 => 32
  | value, fuel + 1 =>
      let index := 32 - (fuel + 1)
      if Nat.testBit value index then index else trailingZeroCount value fuel

def evalPrimitive (op : WordOpcode) (aux : Nat) (values : List Word) : Word :=
  let zero := BitVec.ofNat 32 0
  let one := BitVec.ofNat 32 1
  match op, values with
  | .sub32, [left, right] => left - right
  | .ult32, [left, right] => boolWord (left < right)
  | .equal, [left, right] | .equalBool, [left, right] => boolWord (left = right)
  | .xorBool, [left, right] => boolWord (left != right)
  | .add32, values => values.foldl (fun result value => result + value) zero
  | .mul32, values => values.foldl (fun result value => result * value) one
  | .xor32, values => values.foldl (fun result value => result ^^^ value) zero
  | .and32, values => values.foldl (fun result value => result &&& value)
      (BitVec.ofNat 32 0xffffffff)
  | .or32, values => values.foldl (fun result value => result ||| value) zero
  | .not32, [value] => ~~~value
  | .neg32, [value] => zero - value
  | .shl32, [value, amount] => value.shiftLeft (amount.toNat % 32)
  | .lshr32, [value, amount] => value.ushiftRight (amount.toNat % 32)
  | .sar, [width, value, amount] =>
      (signExtendWord width.toNat value).sshiftRight (amount.toNat % 32) &&&
        widthMask width.toNat
  | .signExtend, [width, value] => signExtendWord width.toNat value
  | .ite, [condition, thenValue, elseValue] =>
      if wordTruth condition then thenValue else elseValue
  | .msb, [value] => boolWord (Nat.testBit value.toNat 31)
  | .msb, [width, value] => boolWord (width.toNat > 0 &&
      Nat.testBit value.toNat (width.toNat - 1))
  | .boolNot, [value] => boolWord (!wordTruth value)
  | .andBool, values => boolWord (values.all wordTruth)
  | .orBool, values => boolWord (values.any wordTruth)
  | .parity, [_, value] =>
      let setBits := (List.range 8).countP
        (fun index => Nat.testBit value.toNat index)
      boolWord (setBits % 2 == 0)
  | .boolToBit, [value] => boolWord (wordTruth value)
  | .addOverflow, [width, left, right, result] => boolWord
      (width.toNat > 0 &&
        (Nat.testBit left.toNat (width.toNat - 1) ==
          Nat.testBit right.toNat (width.toNat - 1)) &&
        (Nat.testBit left.toNat (width.toNat - 1) !=
          Nat.testBit result.toNat (width.toNat - 1)))
  | .subOverflow, [width, left, right, result] => boolWord
      (width.toNat > 0 &&
        (Nat.testBit left.toNat (width.toNat - 1) !=
          Nat.testBit right.toNat (width.toNat - 1)) &&
        (Nat.testBit left.toNat (width.toNat - 1) !=
          Nat.testBit result.toNat (width.toNat - 1)))
  | .imulLow32, [left, right] | .mulLow32, [left, right] => left * right
  | .imulHigh32, [left, right] =>
      let product := BitVec.signExtend 64 left * BitVec.signExtend 64 right
      product.extractLsb' 32 32
  | .mulHigh32, [left, right] =>
      let product := BitVec.zeroExtend 64 left * BitVec.zeroExtend 64 right
      product.extractLsb' 32 32
  | .imulOverflow, [_, _, _, low, high] =>
      boolWord (high != if Nat.testBit low.toNat 31 then BitVec.ofNat 32 0xffffffff else zero)
  | .mulCarry, [_, _, _, high] => boolWord (high != zero)
  | .udivQuot32, [high, low, divisor] =>
      if divisor = zero || high >= divisor then zero else
      let dividend := (BitVec.zeroExtend 64 high).shiftLeft 32 ||| BitVec.zeroExtend 64 low
      (dividend / BitVec.zeroExtend 64 divisor).extractLsb' 0 32
  | .udivRem32, [high, low, divisor] =>
      if divisor = zero || high >= divisor then zero else
      let dividend := (BitVec.zeroExtend 64 high).shiftLeft 32 ||| BitVec.zeroExtend 64 low
      (dividend % BitVec.zeroExtend 64 divisor).extractLsb' 0 32
  | .udivValid32, [high, _, divisor] => boolWord (divisor != zero && high < divisor)
  | .bsrIndex, [_, value] => BitVec.ofNat 32 (highestSetBit value.toNat 32)
  | .tzcnt, [_, value] => BitVec.ofNat 32 (trailingZeroCount value.toNat 32)
  | .sbbBorrow, [width, left, right, carry, _] =>
      let mask := widthMask width.toNat
      boolWord ((left &&& mask).toNat < (right &&& mask).toNat + carry.toNat % 2)
  | .sbbOverflow, [width, left, right, _, result] => boolWord
      (width.toNat > 0 &&
        (Nat.testBit left.toNat (width.toNat - 1) !=
          Nat.testBit right.toNat (width.toNat - 1)) &&
        (Nat.testBit left.toNat (width.toNat - 1) !=
          Nat.testBit result.toNat (width.toNat - 1)))
  | .shiftCf, [value, count] =>
      let kind := aux / 256
      let width := aux % 256
      let count := count.toNat % 32
      if count = 0 || count > width then zero else
      boolWord (Nat.testBit (value &&& widthMask width).toNat
        (if kind = 0 then width - count else count - 1))
  | .shiftOf, [value, count, result] =>
      let kind := aux / 256
      let width := aux % 256
      let count := count.toNat % 32
      if count != 1 || width = 0 then zero else
      if kind = 0 then boolWord
        (Nat.testBit result.toNat (width - 1) != Nat.testBit value.toNat (width - 1))
      else if kind = 1 then boolWord (Nat.testBit value.toNat (width - 1)) else zero
  | _, _ => zero

structure CallEvent where
  kind : CallKind
  instructionRva : Nat
  callIndex : Nat
  targetRva : Word
  returnRva : Nat
  dll : Option String
  symbol : Option String
  ordinal : Option Nat
  arguments : List Word
  stackInputs : List (Nat × MemoryWidth × Word)
deriving Repr, DecidableEq

inductive InterpreterEvent where
  | memoryRead (address : Word) (width : MemoryWidth) (value : Word)
  | memoryWrite (address : Word) (width : MemoryWidth) (value : Word)
  | call (event : CallEvent)
  | repMovsd (source destination count : Word) (direction : Bool)
deriving Repr, DecidableEq

inductive CallStatus where
  | ok | divideError | memoryFault | externalFault | unimplemented
deriving Repr, DecidableEq

structure CallResult where
  status : CallStatus
  state : InterpreterMachine

structure Environment where
  undefinedValue : Nat -> Word
  invokeCall : CallEvent -> InterpreterMachine -> CallResult

inductive Completion where
  | fallthrough (targetRva : Nat)
  | jump (targetRva : Nat)
  | branch (targetRva : Nat)
  | returned (value : Word)
  | indirectJump (target : Word)
  | externalJump
  | divideError | memoryFault | externalFault | unimplemented
deriving Repr, DecidableEq

structure MacroResult where
  state : InterpreterMachine
  events : List InterpreterEvent
  completion : Completion

structure RuntimeState where
  input : InterpreterMachine
  current : InterpreterMachine
  callOutput : InterpreterMachine
  words : Nat -> Option Word
  events : List InterpreterEvent

def RuntimeState.setWord (runtime : RuntimeState) (index : Nat) (value : Word) : RuntimeState :=
  { runtime with words := fun query => if query = index then some value else runtime.words query }

def SemanticWordNode.evaluate (environment : Environment) (runtime : RuntimeState)
    (node : SemanticWordNode) : Option Word := do
  let values <- node.args.mapM runtime.words
  match node.op with
  | .constant => some (BitVec.ofNat 32 node.immediate)
  | .register => (Register.ofIndex? node.aux).map runtime.input.registers
  | .flag => (Flag.ofIndex? node.aux).map runtime.input.flags
  | .trueValue => some (BitVec.ofNat 32 1)
  | .falseValue => some (BitVec.ofNat 32 0)
  | .undefinedBv | .undefinedFlag => some (environment.undefinedValue node.immediate)
  | .callResponse => (Register.ofIndex? node.aux).map runtime.callOutput.registers
  | .callFlag => (Flag.ofIndex? node.aux).map runtime.callOutput.flags
  | .load => do
      let width <- MemoryWidth.ofBytes? node.aux
      match values with
      | [address] => some (readMemory runtime.current.memory address width)
      | _ => none
  | op => some (evalPrimitive op node.aux values)

def valuesAt (runtime : RuntimeState) (references : List Nat) : Option (List Word) :=
  references.mapM runtime.words

def SemanticCall.event (call : SemanticCall) (runtime : RuntimeState) :
    Option (CallEvent × InterpreterMachine) := do
  let registers <- valuesAt runtime call.registerNodes
  let flags <- valuesAt runtime call.flagNodes
  let arguments <- valuesAt runtime call.argumentNodes
  let stackValues <- call.stackInputs.mapM fun input => do
    let value <- runtime.words input.valueNode
    some (input.offset, input.width, value)
  let targetRva <- match call.kind, call.targetNode with
    | .indirect, some target => runtime.words target
    | .external, none | .internal, none => some (BitVec.ofNat 32 call.targetRva)
    | _, _ => none
  let registersState := (List.zip [Register.eax, .ebx, .ecx, .edx, .esi, .edi, .ebp, .esp]
    registers).foldl (fun state item => state.setRegister item.1 item.2) runtime.current
  let inputState := (List.zip [Flag.cf, .zf, .sf, .ofl, .pf, .df] flags).foldl
    (fun state item => state.setFlag item.1 item.2) registersState
  let event : CallEvent := {
    kind := call.kind
    instructionRva := call.instructionRva
    callIndex := call.callIndex
    targetRva := targetRva
    returnRva := call.returnRva
    dll := call.dll
    symbol := call.symbol
    ordinal := call.ordinal
    arguments := arguments
    stackInputs := stackValues
  }
  some (event, inputState)

def repMovsd (state : InterpreterMachine) (source destination : Word)
    (direction : Bool) : Nat -> InterpreterMachine
  | 0 => state
  | count + 1 =>
      let value := readMemory state.memory source .dword
      let next := { state with memory := writeMemory state.memory destination value .dword }
      let step := if direction then BitVec.ofNat 32 0xfffffffc else BitVec.ofNat 32 4
      repMovsd next (source + step) (destination + step) direction count

def InterpreterMachine.syncEflags (state : InterpreterMachine) : InterpreterMachine :=
  let represented := BitVec.ofNat 32
    ((1 <<< 0) + (1 <<< 2) + (1 <<< 6) + (1 <<< 7) + (1 <<< 10) + (1 <<< 11))
  let flags := [Flag.cf, .pf, .zf, .sf, .df, .ofl].foldl
    (fun result flag => result |||
      (state.flags flag &&& BitVec.ofNat 32 1).shiftLeft flag.eflagsBit)
    (BitVec.ofNat 32 0)
  { state with eflags := (state.eflags &&& ~~~represented) ||| flags }

def halted (runtime : RuntimeState) (completion : Completion) : MacroResult := {
  state := runtime.current
  events := runtime.events
  completion := completion
}

def SemanticTransfer.executeAction (transfer : SemanticTransfer)
    (environment : Environment) (runtime : RuntimeState) :
    SemanticAction -> Option (Sum MacroResult RuntimeState)
  | .evalWord nodeIndex => do
      let node <- transfer.wordNodes[nodeIndex]?
      let value <- node.evaluate environment runtime
      let next := runtime.setWord nodeIndex value
      match node.op, node.args with
      | .load, [addressNode] => do
          let address <- runtime.words addressNode
          let width <- MemoryWidth.ofBytes? node.aux
          some (.inr { next with
            events := runtime.events ++ [.memoryRead address width value] })
      | _, _ => some (.inr next)
  | .memoryWrite address value width => do
      let address <- runtime.words address
      let value <- runtime.words value
      some (.inr { runtime with
        current := { runtime.current with
          memory := writeMemory runtime.current.memory address value width }
        events := runtime.events ++ [.memoryWrite address width value]
      })
  | .divideIf condition => do
      let condition <- runtime.words condition
      if wordTruth condition then some (.inl (halted runtime .divideError))
      else some (.inr runtime)
  | .call callIndex => do
      let call <- transfer.calls[callIndex]?
      let eventAndInput <- call.event runtime
      let event := eventAndInput.1
      let result := environment.invokeCall event eventAndInput.2
      let withResult := { runtime with
        current := result.state
        callOutput := result.state
        events := runtime.events ++ [.call event]
      }
      match result.status with
      | .ok => some (.inr withResult)
      | .divideError => some (.inl (halted withResult .divideError))
      | .memoryFault => some (.inl (halted withResult .memoryFault))
      | .externalFault => some (.inl (halted withResult .externalFault))
      | .unimplemented => some (.inl (halted withResult .unimplemented))
  | .repMovsd source destination count directionFlag => do
      let source <- runtime.words source
      let destination <- runtime.words destination
      let count <- runtime.words count
      let directionFlag <- runtime.words directionFlag
      let direction := wordTruth directionFlag
      let current := repMovsd runtime.current source destination direction count.toNat
      some (.inr { runtime with
        current := current
        events := runtime.events ++ [.repMovsd source destination count direction]
      })
  | .setRegister register value => do
      let value <- runtime.words value
      some (.inr { runtime with
        current := runtime.current.setRegister register value })
  | .setFlag flag value => do
      let value <- runtime.words value
      some (.inr { runtime with current := runtime.current.setFlag flag value })
  | .syncEflags => some (.inr { runtime with current := runtime.current.syncEflags })

def SemanticTransfer.executeBody (transfer : SemanticTransfer)
    (environment : Environment) : RuntimeState -> List SemanticAction ->
    Option (Sum MacroResult RuntimeState)
  | runtime, [] => some (.inr runtime)
  | runtime, action :: tail => do
      match <- transfer.executeAction environment runtime action with
      | .inl result => some (.inl result)
      | .inr next => transfer.executeBody environment next tail

def SemanticOutcome.complete (outcome : SemanticOutcome)
    (runtime : RuntimeState) : Option MacroResult := do
  let completion <- match outcome with
    | .fallthrough target => some (.fallthrough target)
    | .jump target => some (.jump target)
    | .branch condition trueTarget falseTarget => do
        let condition <- runtime.words condition
        some (.branch (if wordTruth condition then trueTarget else falseTarget))
    | .returned value => runtime.words value |>.map Completion.returned
    | .indirectJump target => runtime.words target |>.map Completion.indirectJump
    | .externalJump => some .externalJump
  some (halted runtime completion)

def SemanticTransfer.execute (transfer : SemanticTransfer)
    (environment : Environment) (state : InterpreterMachine) : Option MacroResult := do
  let initial : RuntimeState := {
    input := state
    current := state
    callOutput := state
    words := fun _ => none
    events := []
  }
  match <- transfer.executeBody environment initial transfer.body with
  | .inl result => some result
  | .inr runtime => transfer.outcome.complete runtime

def ProgramRecord.interpret (record : ProgramRecord)
    (environment : Environment) (state : InterpreterMachine) : Option MacroResult := do
  let transfer <- record.decode
  if !transfer.checked then none else
  transfer.execute environment state

/-- Once a raw record is structurally accepted and decodes to the exported
typed transfer, one interpreter macro-step is exactly that transfer's semantic
execution. -/
theorem ProgramRecord.macroStep_semantic_correspondence
    (record : ProgramRecord) (transfer : SemanticTransfer)
    (decoded : record.decode = some transfer) (checked : transfer.checked = true)
    (environment : Environment) (state : InterpreterMachine) :
    record.interpret environment state = transfer.execute environment state := by
  simp [ProgramRecord.interpret, decoded, checked]

theorem ProgramRecord.macroStep_exported_correspondence
    (record : ProgramRecord) (exported : ExportedSemanticTransfer)
    (decoded : record.decode = some exported.transfer)
    (checked : exported.transfer.checked = true)
    (environment : Environment) (state : InterpreterMachine) :
    record.interpret environment state =
      exported.transfer.execute environment state :=
  record.macroStep_semantic_correspondence exported.transfer decoded checked
    environment state

theorem ProgramRecord.checked_macroStep_semantic_correspondence
    (record : ProgramRecord) (checked : record.checked = true)
    (environment : Environment) (state : InterpreterMachine) :
    exists transfer,
      record.decode = some transfer ∧
      transfer.checked = true ∧
      record.interpret environment state = transfer.execute environment state := by
  rcases record.structurallyValid_of_checked checked with
    ⟨transfer, decoded, transferChecked⟩
  exact ⟨transfer, decoded, transferChecked,
    record.macroStep_semantic_correspondence transfer decoded transferChecked
      environment state⟩

end StageA.Relational.Interpreter
