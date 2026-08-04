import StageA.RelationalDecode
import StageA.RelationalInterpreter
import StageA.RelationalInterpreterMachineBridge
import StageA.RelationalEnvironment

namespace StageA.Relational.InterpreterTransfer

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterMachineBridge

abbrev formalRegister :=
  StageA.Relational.InterpreterMachineBridge.formalRegister

abbrev formalFlagBit :=
  StageA.Relational.InterpreterMachineBridge.formalFlagBit

def machineFromFormal (state : MachineState) : InterpreterMachine := {
  registers := fun register => state.registers.get (formalRegister register)
  flags := StageA.Relational.InterpreterMachineBridge.flagsFromEflags state.eflags
  memory := state.memory
  eflags := state.eflags
}

theorem machineFromFormal_eq_bridge (state : MachineState) :
    machineFromFormal state =
      StageA.Relational.InterpreterMachineBridge.machineFromFormal state := by
  rfl

/-! A small, reviewed SHA-256 implementation used only to bind immutable proof
artifacts.  The semantic theorem below is based on exact typed equality; hashes
are additional audit bindings and never replace decoding or semantic checks. -/

namespace SHA256

def modulus : Nat := 4294967296
def mask : Nat := 4294967295

def word (value : Nat) : Nat := value % modulus
def add (left right : Nat) : Nat := word (left + right)
def add4 (a b c d : Nat) : Nat := add (add a b) (add c d)
def add5 (a b c d e : Nat) : Nat := add (add4 a b c d) e
def xor (left right : Nat) : Nat := Nat.xor left right
def xor3 (a b c : Nat) : Nat := xor (xor a b) c
def band (left right : Nat) : Nat := left &&& right
def bnot (value : Nat) : Nat := xor value mask
def shr (value amount : Nat) : Nat := value >>> amount

def rotr (value amount : Nat) : Nat :=
  if amount = 0 then word value else
    word ((value >>> amount) ||| (value <<< (32 - amount)))

def choose (x y z : Nat) : Nat := xor (band x y) (band (bnot x) z)
def majority (x y z : Nat) : Nat := xor3 (band x y) (band x z) (band y z)
def bigSigma0 (x : Nat) : Nat := xor3 (rotr x 2) (rotr x 13) (rotr x 22)
def bigSigma1 (x : Nat) : Nat := xor3 (rotr x 6) (rotr x 11) (rotr x 25)
def smallSigma0 (x : Nat) : Nat := xor3 (rotr x 7) (rotr x 18) (shr x 3)
def smallSigma1 (x : Nat) : Nat := xor3 (rotr x 17) (rotr x 19) (shr x 10)

def constants : List Nat := [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def initial : List Nat := [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def u64be (value : Nat) : Bytes :=
  [(value >>> 56) % 256, (value >>> 48) % 256, (value >>> 40) % 256,
   (value >>> 32) % 256, (value >>> 24) % 256, (value >>> 16) % 256,
   (value >>> 8) % 256, value % 256]

def pad (bytes : Bytes) : Bytes :=
  let withMarker := bytes ++ [128]
  let zeroCount := (56 + 64 - withMarker.length % 64) % 64
  withMarker ++ List.replicate zeroCount 0 ++
    u64be ((bytes.length * 8) % 18446744073709551616)

def readWord (bytes : Bytes) (offset : Nat) : Nat :=
  ((bytes.getD offset 0) <<< 24) + ((bytes.getD (offset + 1) 0) <<< 16) +
    ((bytes.getD (offset + 2) 0) <<< 8) + bytes.getD (offset + 3) 0

def seedSchedule (chunk : Bytes) : List Nat :=
  (List.range 16).map fun index => readWord chunk (index * 4)

def extendSchedule : Nat -> List Nat -> List Nat
  | 0, words => words
  | fuel + 1, words =>
      let index := words.length
      let next := add4 (smallSigma1 (words.getD (index - 2) 0))
        (words.getD (index - 7) 0)
        (smallSigma0 (words.getD (index - 15) 0))
        (words.getD (index - 16) 0)
      extendSchedule fuel (words ++ [next])

structure RoundState where
  a : Nat
  b : Nat
  c : Nat
  d : Nat
  e : Nat
  f : Nat
  g : Nat
  h : Nat
deriving Repr, DecidableEq

def round (state : RoundState) (constant schedule : Nat) : RoundState :=
  let t1 := add5 state.h (bigSigma1 state.e)
    (choose state.e state.f state.g) constant schedule
  let t2 := add (bigSigma0 state.a) (majority state.a state.b state.c)
  { a := add t1 t2, b := state.a, c := state.b, d := state.c,
    e := add state.d t1, f := state.e, g := state.f, h := state.g }

def runRounds : List (Nat × Nat) -> RoundState -> RoundState
  | [], state => state
  | item :: tail, state => runRounds tail (round state item.1 item.2)

def compress (hash chunk : List Nat) : List Nat :=
  let start : RoundState := {
    a := hash.getD 0 0, b := hash.getD 1 0, c := hash.getD 2 0,
    d := hash.getD 3 0, e := hash.getD 4 0, f := hash.getD 5 0,
    g := hash.getD 6 0, h := hash.getD 7 0 }
  let schedule := extendSchedule 48 (seedSchedule chunk)
  let result := runRounds (List.zip constants schedule) start
  [add (hash.getD 0 0) result.a, add (hash.getD 1 0) result.b,
   add (hash.getD 2 0) result.c, add (hash.getD 3 0) result.d,
   add (hash.getD 4 0) result.e, add (hash.getD 5 0) result.f,
   add (hash.getD 6 0) result.g, add (hash.getD 7 0) result.h]

def chunks : Nat -> Bytes -> List Bytes
  | 0, _ => []
  | fuel + 1, bytes =>
      if bytes.isEmpty then [] else bytes.take 64 :: chunks fuel (bytes.drop 64)

def wordBytes (value : Nat) : Bytes :=
  [value >>> 24, (value >>> 16) % 256, (value >>> 8) % 256, value % 256]

def digest (bytes : Bytes) : Bytes :=
  let padded := pad bytes
  let final := (chunks (padded.length / 64 + 1) padded).foldl compress initial
  final.flatMap wordBytes

def hexDigit : Nat -> Char
  | 0 => '0' | 1 => '1' | 2 => '2' | 3 => '3'
  | 4 => '4' | 5 => '5' | 6 => '6' | 7 => '7'
  | 8 => '8' | 9 => '9' | 10 => 'a' | 11 => 'b'
  | 12 => 'c' | 13 => 'd' | 14 => 'e' | _ => 'f'

def hexByte (value : Nat) : List Char :=
  [hexDigit ((value / 16) % 16), hexDigit (value % 16)]

def hex (bytes : Bytes) : String :=
  String.ofList ((digest bytes).flatMap hexByte)

def inputValid (bytes : Bytes) : Bool := bytes.all (fun byte => byte < 256)

def checkedHex (bytes : Bytes) (claimed : String) : Bool :=
  inputValid bytes && hex bytes == claimed

end SHA256

def evalRegisters (state : MachineState) (registers : Registers Expr) :
    Register -> Word
  | .eax => registers.eax.eval state
  | .ebx => registers.ebx.eval state
  | .ecx => registers.ecx.eval state
  | .edx => registers.edx.eval state
  | .esi => registers.esi.eval state
  | .edi => registers.edi.eval state
  | .ebp => registers.ebp.eval state
  | .esp => registers.esp.eval state

def evalFlags (state : MachineState) (flags : Option FlagsExpr) : Word :=
  flags.map (FlagsExpr.eval state) |>.getD state.eflags

def evaluatedFlag (state : MachineState) (flags : Option FlagsExpr)
    (flag : Flag) : Word :=
  BitVec.zeroExtend 32
    ((evalFlags state flags).extractLsb' (formalFlagBit flag) 1)

def evalWrites (state : MachineState) (writes : List (Expr × Expr)) :
    List InterpreterEvent :=
  writes.map fun write =>
    .memoryWrite (write.1.eval state) .dword (write.2.eval state)

def applyWrites (state : MachineState) (writes : List (Expr × Expr)) : Memory :=
  writes.foldl (fun memory write =>
    writeMemory memory (write.1.eval state) (write.2.eval state) .dword)
    state.memory

inductive BridgeControl where
  | next (targetRva : Nat)
  | returned (value : Word)
  | indirectJump (target : Word)
deriving Repr, DecidableEq

def originalTargetRva (targets : List CodeTargetPair) (targetId : Nat) :
    Option Nat :=
  (targets.find? fun target => target.id == targetId).map (fun target => target.originalRva)

def originalTargetRvas (targets : List CodeTargetPair) : List Nat :=
  targets.flatMap fun target =>
    target.originalRva :: target.originalAliases.map (fun alias => alias.rva)

def candidateTargetRvas (targets : List CodeTargetPair) : List Nat :=
  targets.flatMap fun target =>
    target.candidateRva :: target.candidateAliases.map (fun alias => alias.rva)

def targetMapChecked (targets : List CodeTargetPair) : Bool :=
  decide (targets.map (fun target => target.id)).Nodup &&
    decide (originalTargetRvas targets).Nodup &&
    decide (candidateTargetRvas targets).Nodup &&
    (originalTargetRvas targets).all (fun rva => rva < 2 ^ 32) &&
    (candidateTargetRvas targets).all (fun rva => rva < 2 ^ 32)

def originalControl (targets : List CodeTargetPair) (state : MachineState) :
    NormalizedOutcomeExpr -> Option BridgeControl
  | .jump targetId => (originalTargetRva targets targetId).map BridgeControl.next
  | .returned value => some (.returned (value.eval state))
  | .indirectJump target => some (.indirectJump (target.eval state))
  | _ => none

def interpreterControl : Completion -> Option BridgeControl
  | .fallthrough target | .jump target => some (.next target)
  | .returned value => some (.returned value)
  | .indirectJump target => some (.indirectJump target)
  | _ => none

def expressionSupported : Expr -> Bool
  | .inputReg _ | .inputFlagValue _ | .constant _ => true
  | .add left right | .sub left right | .bitAnd left right |
      .bitXor left right | .bitOr left right | .multiply left right |
      .multiplyHighUnsigned left right | .multiplyHighSigned left right |
      .unsignedLessValue left right =>
      expressionSupported left && expressionSupported right
  | .bitNot value | .extractByte value _ | .shiftLeft value _ |
      .shiftRight value _ | .bitValue value _ | .lowestSetBit value |
      .highestSetBit value => expressionSupported value
  | .shiftLeftBy value amount | .shiftRightBy value amount |
      .shiftArithmeticRightBy value amount =>
      expressionSupported value && expressionSupported amount
  | .ifEqual left right thenValue elseValue =>
      expressionSupported left && expressionSupported right &&
        expressionSupported thenValue && expressionSupported elseValue
  | .divideQuotient high low divisor | .divideRemainder high low divisor |
      .divisionValidValue high low divisor =>
      expressionSupported high && expressionSupported low &&
        expressionSupported divisor
  | .inputFsBase | .inputX87Control | .inputX87Status | .read8 _ |
      .read32 _ | .read8AfterWrite _ _ _ _ | .undefined _ |
      .x87Part _ _ | .x87CompareBit _ _ _ _ | .x87ExamineStatus _ _ => false

def operand32MemoryFree : Operand32 -> Bool
  | .register _ | .immediate _ => true
  | .memory _ => false

def operand8MemoryFree : Operand8 -> Bool
  | .register _ | .immediate _ => true
  | .memory _ => false

/-- Exhaustive reviewed allowlist for instructions with no architectural data-
memory access. Instruction fetch is already bound by `spanBytes`. Stack,
string, import-thunk, x87, divide/faulting, and all memory-operand forms reject. -/
def instructionMemoryEffectFree : Instruction -> Bool
  | .nop | .movRegImm _ _ | .movRegReg _ _ | .addZero _ | .subZero _ |
      .cmpImm _ _ | .branchEqual _ _ | .jumpRel8 _ | .jumpRel32 _ |
      .lea _ _ _ | .zeroReg _ | .leaAddress _ _ | .branchCondition _ _ _ |
      .convertWordToDword | .convertDwordToQuad | .bitTestRegister _ _ |
      .clearCarry | .clearDirection | .setDirection => true
  | .movFromOperand _ source | .movZeroExtend _ source _ |
      .movSignExtend _ source _ | .movFromOperandWidth _ _ source |
      .conditionalMove _ _ source | .multiplyFull _ source |
      .multiplyLow _ source _ | .bitScan _ _ source |
      .jumpIndirect source => operand32MemoryFree source
  | .movToOperand destination _ | .movImmediate destination _ |
      .shift _ destination _ | .shiftWidth _ _ destination _ |
      .unary _ destination |
      .movToOperandWidth _ destination _ | .movImmediateWidth _ destination _ |
      .exchange destination _ | .doubleShift _ destination _ _ =>
      match destination with
      | .register _ => true
      | .memory _ | .immediate _ => false
  | .binary _ destination source | .binaryWidth _ _ destination source |
      .binaryCarry _ destination source =>
      match destination with
      | .register _ => operand32MemoryFree source
      | .memory _ | .immediate _ => false
  | .shift8 _ destination _ | .movToOperand8 destination _ |
      .movImmediate8 destination _ | .setCondition _ destination =>
      match destination with
      | .register _ => true
      | .memory _ | .immediate _ => false
  | .movSignExtend8 _ source | .movSignExtend8ToWord _ source |
      .movFromOperand8 _ source => operand8MemoryFree source
  | .binary8 _ destination source =>
      match destination with
      | .register _ => operand8MemoryFree source
      | .memory _ | .immediate _ => false
  | .ret | .retPop _ | .pushReg _ | .popReg _ | .pushFlags | .pushAll |
      .popAll | .popFlags | .leave | .load32 _ _ _ |
      .store32 _ _ _ | .callRel32 _ | .callImport _ | .jumpImport _ |
      .x87LoadStack _ | .x87LoadConstant _ | .x87Exchange _ |
      .x87StoreStack _ _ | .x87Unary _ | .x87BinaryStack _ _ _ _ |
      .x87CompareStack _ _ _ _ | .x87CompareMemory _ _ _ _ |
      .x87LoadMemory _ _ |
      .x87StoreMemory _ _ _ | .x87BinaryMemory _ _ _ |
      .x87LoadControl _ | .x87StoreControl _ | .x87SaveState _ |
      .x87RestoreState _ | .x87Wait | .x87Initialize |
      .x87StoreStatusAx | .x87Examine | .moveDwords _ | .storeDwords _ |
      .scanByteNotEqual |
      .callIndirect _ |
      .pushOperand _ | .movFs32 _ _ | .divideUnsigned _ | .divideSigned _ |
      .atomicCompareExchange _ _ => false

def memoryEffectFreeInstructionBytes : Nat -> Bytes -> Bool
  | 0, bytes => bytes.isEmpty
  | fuel + 1, [] => true
  | fuel + 1, bytes =>
      match decodeInstructionExact bytes with
      | none => false
      | some decoded =>
          instructionMemoryEffectFree decoded.instruction &&
            memoryEffectFreeInstructionBytes fuel decoded.trailing

def exactMemoryEffectFreeProfile (bytes : Bytes) : Bool :=
  !bytes.isEmpty && memoryEffectFreeInstructionBytes (bytes.length + 1) bytes

/-- Read a span only when every RVA is backed by one unambiguous file byte.
Unlike `spanBytes`, this rejects executable zero-fill and overlapping section
mappings, so the instruction digest is tied to exact original PE bytes. -/
def exactRvaBytes (pe : PE32) (rva size : Nat) : Option Bytes := do
  if !exactRvaSpan pe rva size then none else
  (List.range size).mapM fun offset => exactRvaByte pe (rva + offset)

def boolExpressionSupported : BoolExpr -> Bool
  | .equal left right | .unsignedLess left right =>
      expressionSupported left && expressionSupported right
  | .not value => boolExpressionSupported value
  | .and left right | .or left right | .xor left right =>
      boolExpressionSupported left && boolExpressionSupported right
  | .msb value | .bit value _ => expressionSupported value
  | .inputFlag _ => true
  | .divisionValid high low divisor =>
      expressionSupported high && expressionSupported low &&
        expressionSupported divisor

def optionBoolExpressionSupported : Option BoolExpr -> Bool
  | none => true
  | some expression => boolExpressionSupported expression

def registersSupported (registers : Registers Expr) : Bool :=
  [registers.eax, registers.ebx, registers.ecx, registers.edx,
   registers.esi, registers.edi, registers.ebp, registers.esp].all
    expressionSupported

def flagsSupported : Option FlagsExpr -> Bool
  | none => true
  | some flags =>
      flags.auxiliary.isNone &&
        [flags.zero, flags.carry, flags.sign, flags.overflow, flags.parity].all
          optionBoolExpressionSupported

def outcomeSupported : NormalizedOutcomeExpr -> Bool
  | .jump _ => true
  | .returned value | .indirectJump value => expressionSupported value
  | _ => false

def wordNodeSupported (node : SemanticWordNode) : Bool :=
  match node.op with
  | .undefinedBv | .undefinedFlag | .callResponse | .callFlag | .load => false
  | _ => true

def actionSupported : SemanticAction -> Bool
  | .evalWord _ | .setRegister _ _ | .setFlag _ _ | .syncEflags => true
  | .memoryWrite _ _ _ | .divideIf _ | .call _ |
      .repMovsd _ _ _ _ | .repStosd _ _ _ _ |
      .repMovs _ _ _ _ _ | .repStos _ _ _ _ _ |
      .repScas _ _ _ _ _ => false

def semanticOutcomeSupported : SemanticOutcome -> Bool
  | .fallthrough _ | .jump _ | .returned _ | .indirectJump _ => true
  | .branch _ _ _ | .externalJump => false

def normalizedProfileSupported (behavior : NormalizedSymbolicBehavior) : Bool :=
  registersSupported behavior.registers &&
    behavior.x87 == initialSymbolic.x87 &&
    behavior.writes.isEmpty &&
    flagsSupported behavior.flags && outcomeSupported behavior.outcome

def transferProfileSupported (transfer : SemanticTransfer) : Bool :=
  transfer.calls.isEmpty && transfer.wordNodes.all wordNodeSupported &&
    transfer.body.all actionSupported && semanticOutcomeSupported transfer.outcome

/-! The general bridge keeps the interpreter's exact sequential semantics.
Unlike the small profile above, memory, control, calls, faults, REP MOVSD and
undefined values are represented explicitly and become checked obligations. -/

def exactDecodedInstructionBytes : Nat -> Bytes -> Bool
  | 0, bytes => bytes.isEmpty
  | fuel + 1, [] => true
  | fuel + 1, bytes =>
      match decodeInstructionExact bytes with
      | none => false
      | some decoded => exactDecodedInstructionBytes fuel decoded.trailing

def exactDecodedInstructionProfile (bytes : Bytes) : Bool :=
  !bytes.isEmpty && exactDecodedInstructionBytes (bytes.length + 1) bytes

inductive FlatMemoryAccessKind where
  | read (width : MemoryWidth)
  | write (width : MemoryWidth)
  | repMovsd
  | repStosd
  | repMovs (width : MemoryWidth)
  | repStos (width : MemoryWidth)
  | repScas (width : MemoryWidth)
deriving Repr, DecidableEq

structure FlatMemoryAccessSite where
  actionIndex : Nat
  addressNode : Option Nat
  valueNode : Option Nat
  kind : FlatMemoryAccessKind
deriving Repr, DecidableEq

def memoryAccessSite (transfer : SemanticTransfer) (actionIndex : Nat) :
    SemanticAction -> List FlatMemoryAccessSite
  | .evalWord nodeIndex =>
      match transfer.wordNodes[nodeIndex]? with
      | some node =>
          match node.op, node.args, MemoryWidth.ofBytes? node.aux with
          | .load, [address], some width =>
              [⟨actionIndex, some address, some nodeIndex, .read width⟩]
          | _, _, _ => []
      | _ => []
  | .memoryWrite address value width =>
      [⟨actionIndex, some address, some value, .write width⟩]
  | .repMovsd source destination _ _ =>
      [⟨actionIndex, some source, some destination, .repMovsd⟩]
  | .repStosd destination value _ _ =>
      [⟨actionIndex, some destination, some value, .repStosd⟩]
  | .repMovs source destination _ _ width =>
      [⟨actionIndex, some source, some destination, .repMovs width⟩]
  | .repStos destination value _ _ width =>
      [⟨actionIndex, some destination, some value, .repStos width⟩]
  | .repScas accumulator destination _ _ width =>
      [⟨actionIndex, some destination, some accumulator, .repScas width⟩]
  | _ => []

def orderedFlatMemoryFootprintFrom (transfer : SemanticTransfer) :
    Nat -> List SemanticAction -> List FlatMemoryAccessSite
  | _, [] => []
  | index, action :: tail =>
      memoryAccessSite transfer index action ++
        orderedFlatMemoryFootprintFrom transfer (index + 1) tail

def orderedFlatMemoryFootprint (transfer : SemanticTransfer) :
    List FlatMemoryAccessSite :=
  orderedFlatMemoryFootprintFrom transfer 0 transfer.body

def flatMemoryFootprintChecked (transfer : SemanticTransfer)
    (submitted : List FlatMemoryAccessSite) : Bool :=
  submitted == orderedFlatMemoryFootprint transfer

inductive AliasDisposition where
  | exactAlias
  | checkedDisjoint
  | orderedMayAlias
deriving Repr, DecidableEq

structure FlatMemoryAliasWitness where
  left : Nat
  right : Nat
  disposition : AliasDisposition
deriving Repr, DecidableEq

def requiredAliasPairs (count : Nat) : List (Nat × Nat) :=
  (List.range count).flatMap fun left =>
    (List.range (count - (left + 1))).map fun offset =>
      (left, left + offset + 1)

def aliasWitnessStaticChecked (footprint : List FlatMemoryAccessSite)
    (witness : FlatMemoryAliasWitness) : Bool :=
  match footprint[witness.left]?, footprint[witness.right]? with
  | some left, some right =>
      witness.left < witness.right && match witness.disposition with
      | .exactAlias =>
          left.addressNode.isSome && left.addressNode == right.addressNode &&
            left.kind == right.kind
      | .checkedDisjoint =>
          left.addressNode.isSome && right.addressNode.isSome
      | .orderedMayAlias => true
  | _, _ => false

def flatMemoryAliasInventoryChecked (footprint : List FlatMemoryAccessSite)
    (witnesses : List FlatMemoryAliasWitness) : Bool :=
  witnesses.map (fun witness => (witness.left, witness.right)) ==
      requiredAliasPairs footprint.length &&
    witnesses.all (aliasWitnessStaticChecked footprint)

structure ConcreteFlatMemoryAccess where
  address : Word
  width : MemoryWidth
deriving Repr, DecidableEq

inductive ConcreteFlatMemoryEffect where
  | access (value : ConcreteFlatMemoryAccess)
  | repMovsd (source destination count : Word) (direction : Bool)
  | repStosd (destination value count : Word) (direction : Bool)
  | repMovs (source destination count : Word) (direction : Bool)
      (width : MemoryWidth)
  | repStos (destination value count : Word) (direction : Bool)
      (width : MemoryWidth)
  | repScas (accumulator destination count : Word) (direction : Bool)
      (width : MemoryWidth)
deriving Repr, DecidableEq

def concreteFlatMemoryEffect : InterpreterEvent -> Option ConcreteFlatMemoryEffect
  | .memoryRead address width _ | .memoryWrite address width _ =>
      some (.access { address, width })
  | .repMovsd source destination count direction =>
      some (.repMovsd source destination count direction)
  | .repStosd destination value count direction =>
      some (.repStosd destination value count direction)
  | .repMovs source destination count direction width =>
      some (.repMovs source destination count direction width)
  | .repStos destination value count direction width =>
      some (.repStos destination value count direction width)
  | .repScas accumulator destination count direction width =>
      some (.repScas accumulator destination count direction width)
  | .call _ => none

def concreteFlatMemoryEffects (events : List InterpreterEvent) :
    List ConcreteFlatMemoryEffect :=
  events.filterMap concreteFlatMemoryEffect

/-! `repStringSpan?` computes the exact half-open byte span touched by a
repeated string operation. The direction flag denotes decrementing traversal
when true. A zero count touches no memory and therefore has an empty span. -/
def repStringSpan? (destination count : Word) (direction : Bool)
    (width : MemoryWidth) : Option Span :=
  let destination := destination.toNat
  let count := count.toNat
  if count = 0 then
    some { start := destination, size := 0 }
  else
    let size := count * width.bytes
    if size > pe32AddressSpaceSize then none
    else if direction then
      let backwards := (count - 1) * width.bytes
      if destination < backwards then none
      else
        let start := destination - backwards
        if pe32SpanBounded start size then some { start, size } else none
    else if pe32SpanBounded destination size then
      some { start := destination, size }
    else none

def repStosdSpan? (destination count : Word) (direction : Bool) : Option Span :=
  repStringSpan? destination count direction .dword

/-- REP MOVSD traverses equal-sized source and destination spans in the same
direction. The two spans are checked independently because either side can
cross the flat PE32 address-space boundary. -/
def repMovsdSpans? (source destination count : Word)
    (direction : Bool) : Option (Span × Span) := do
  let sourceSpan <- repStosdSpan? source count direction
  let destinationSpan <- repStosdSpan? destination count direction
  pure (sourceSpan, destinationSpan)

def repMovsSpans? (source destination count : Word) (direction : Bool)
    (width : MemoryWidth) : Option (Span × Span) := do
  let sourceSpan <- repStringSpan? source count direction width
  let destinationSpan <- repStringSpan? destination count direction width
  pure (sourceSpan, destinationSpan)

def interpreterEventAccessDomainChecked (side : RelationalSide)
    (context : StaticProofContext) (world : RelationalWorld) :
    InterpreterEvent -> Bool
  | .memoryRead address width _ =>
      relationalAccessSpanChecked side context world .read address.toNat width.bytes
  | .memoryWrite address width _ =>
      relationalAccessSpanChecked side context world .write address.toNat width.bytes
  | .repStosd destination _ count direction =>
      match repStosdSpan? destination count direction with
      | some span =>
          span.size == 0 ||
            relationalAccessSpanChecked side context world .write span.start span.size
      | none => false
  | .repScas _ destination count direction width =>
      match repStringSpan? destination count direction width with
      | some span =>
          span.size == 0 ||
            relationalAccessSpanChecked side context world .read span.start span.size
      | none => false
  | .repMovsd source destination count direction =>
      match repMovsdSpans? source destination count direction with
      | some (sourceSpan, destinationSpan) =>
          (sourceSpan.size == 0 ||
            relationalAccessSpanChecked side context world .read
              sourceSpan.start sourceSpan.size) &&
          (destinationSpan.size == 0 ||
            relationalAccessSpanChecked side context world .write
              destinationSpan.start destinationSpan.size)
      | none => false
  | .repStos destination _ count direction width =>
      match repStringSpan? destination count direction width with
      | some span =>
          span.size == 0 ||
            relationalAccessSpanChecked side context world .write span.start span.size
      | none => false
  | .repMovs source destination count direction width =>
      match repMovsSpans? source destination count direction width with
      | some (sourceSpan, destinationSpan) =>
          (sourceSpan.size == 0 ||
            relationalAccessSpanChecked side context world .read
              sourceSpan.start sourceSpan.size) &&
          (destinationSpan.size == 0 ||
            relationalAccessSpanChecked side context world .write
              destinationSpan.start destinationSpan.size)
      | none => false
  /- A call event is not itself a flat-memory access. The paired external
  environment owns the callee's successor state, memory footprint, and fault
  refinement; treating the event as a memory access here would duplicate that
  authority. -/
  | .call _ => true

def interpreterEventsAccessDomainChecked (side : RelationalSide)
    (context : StaticProofContext) (world : RelationalWorld)
    (events : List InterpreterEvent) : Bool :=
  events.all (interpreterEventAccessDomainChecked side context world)

def InterpreterEventModeledAccessDomain (side : RelationalSide)
    (context : StaticProofContext) (world : RelationalWorld)
    (event : InterpreterEvent) : Prop :=
  interpreterEventAccessDomainChecked side context world event = true

theorem interpreterEventsAccessDomainChecked_sound
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (events : List InterpreterEvent)
    (checked : interpreterEventsAccessDomainChecked side context world events = true) :
    ∀ event ∈ events,
      InterpreterEventModeledAccessDomain side context world event := by
  intro event member
  simp only [interpreterEventsAccessDomainChecked, List.all_eq_true] at checked
  exact checked event member

/-! A certificate is parametric in the source-state relation and in the event
producer.  It proves only that all produced memory events are admitted by the
modeled PE/world domain.  The explicit launch assumption is the separate bridge
to concrete flat-segment and mapped-memory facts. -/
structure CheckedAccessDomainCertificate
    (StateRelation :
      RelationalWorld -> InterpreterMachine -> InterpreterMachine -> Prop)
    (context : StaticProofContext)
    (originalEvents candidateEvents :
      RelationalWorld -> InterpreterMachine -> InterpreterMachine ->
        List InterpreterEvent) : Prop where
  originalChecked :
    ∀ world original candidate,
      StateRelation world original candidate ->
        interpreterEventsAccessDomainChecked .original context world
          (originalEvents world original candidate) = true
  candidateChecked :
    ∀ world original candidate,
      StateRelation world original candidate ->
        interpreterEventsAccessDomainChecked .candidate context world
          (candidateEvents world original candidate) = true

theorem CheckedAccessDomainCertificate.originalModeled
    {StateRelation :
      RelationalWorld -> InterpreterMachine -> InterpreterMachine -> Prop}
    {context : StaticProofContext}
    {originalEvents candidateEvents :
      RelationalWorld -> InterpreterMachine -> InterpreterMachine ->
        List InterpreterEvent}
    (certificate : CheckedAccessDomainCertificate StateRelation context
      originalEvents candidateEvents)
    (world : RelationalWorld) (original candidate : InterpreterMachine)
    (related : StateRelation world original candidate) :
    ∀ event ∈ originalEvents world original candidate,
      InterpreterEventModeledAccessDomain .original context world event :=
  interpreterEventsAccessDomainChecked_sound _ _ _
    (originalEvents world original candidate)
    (certificate.originalChecked world original candidate related)

theorem CheckedAccessDomainCertificate.candidateModeled
    {StateRelation :
      RelationalWorld -> InterpreterMachine -> InterpreterMachine -> Prop}
    {context : StaticProofContext}
    {originalEvents candidateEvents :
      RelationalWorld -> InterpreterMachine -> InterpreterMachine ->
        List InterpreterEvent}
    (certificate : CheckedAccessDomainCertificate StateRelation context
      originalEvents candidateEvents)
    (world : RelationalWorld) (original candidate : InterpreterMachine)
    (related : StateRelation world original candidate) :
    ∀ event ∈ candidateEvents world original candidate,
      InterpreterEventModeledAccessDomain .candidate context world event :=
  interpreterEventsAccessDomainChecked_sound _ _ _
    (candidateEvents world original candidate)
    (certificate.candidateChecked world original candidate related)

def flatRangesDisjoint (left right : ConcreteFlatMemoryAccess) : Prop :=
  forall leftOffset, leftOffset < left.width.bytes ->
    forall rightOffset, rightOffset < right.width.bytes ->
      left.address + BitVec.ofNat 32 leftOffset !=
        right.address + BitVec.ofNat 32 rightOffset

def aliasWitnessHolds (effects : List ConcreteFlatMemoryEffect)
    (witness : FlatMemoryAliasWitness) : Prop :=
  match effects[witness.left]?, effects[witness.right]? with
  | some left, some right => match witness.disposition, left, right with
      | .exactAlias, .access left, .access right => left = right
      | .checkedDisjoint, .access left, .access right => flatRangesDisjoint left right
      | .orderedMayAlias, _, _ => True
      | _, _, _ => False
  | _, _ => False

def FlatMemoryAliasWitnessesSound (transfer : SemanticTransfer)
    (witnesses : List FlatMemoryAliasWitness) : Prop :=
  forall state environment result,
    transfer.execute environment state = some result ->
      forall witness, witness ∈ witnesses ->
        aliasWitnessHolds (concreteFlatMemoryEffects result.events) witness

def targetHasOriginalRva (target : CodeTargetPair) (rva : Nat) : Bool :=
  target.originalRva == rva ||
    target.originalAliases.any (fun alias => alias.rva == rva)

def originalTargetIdAt (targets : List CodeTargetPair) (rva : Nat) : Option Nat :=
  (targets.find? fun target => targetHasOriginalRva target rva).map
    (fun target => target.id)

structure ControlTargetWitness where
  originalRva : Nat
  targetId : Nat
deriving Repr, DecidableEq

def callDirectTargetRvas (call : SemanticCall) : List Nat :=
  let continuation := if call.returnRva == 0 then [] else [call.returnRva]
  match call.kind with
  | .internal => call.targetRva :: continuation
  | .external | .indirect => continuation

def outcomeDirectTargetRvas : SemanticOutcome -> List Nat
  | .fallthrough target | .jump target => [target]
  | .branch _ taken fallthrough => [taken, fallthrough]
  | .returned _ | .indirectJump _ | .externalJump => []

def requiredControlTargetRvas (transfer : SemanticTransfer) : List Nat :=
  (outcomeDirectTargetRvas transfer.outcome ++
    transfer.calls.flatMap callDirectTargetRvas).eraseDups

def controlTargetWitnessChecked (targets : List CodeTargetPair)
    (witness : ControlTargetWitness) : Bool :=
  originalTargetIdAt targets witness.originalRva == some witness.targetId

def controlTargetInventoryChecked (transfer : SemanticTransfer)
    (targets : List CodeTargetPair) (witnesses : List ControlTargetWitness) : Bool :=
  decide (witnesses.map (fun witness => witness.originalRva)).Nodup &&
    witnesses.all (controlTargetWitnessChecked targets) &&
    (requiredControlTargetRvas transfer).all (fun rva =>
      witnesses.any (fun witness => witness.originalRva == rva)) &&
    witnesses.all (fun witness =>
      (requiredControlTargetRvas transfer).contains witness.originalRva)

theorem branchGuardsExhaustive (condition : Word) :
    wordTruth condition = true ∨ wordTruth condition = false := by
  cases checked : wordTruth condition <;> simp [checked]

def callBoundaryShapeChecked (call : SemanticCall) : Bool :=
  call.registerNodes.length == 8 && call.flagNodes.length == 6 &&
    match call.kind with
    | .external =>
        call.targetNode.isNone && call.dll.isSome &&
          (call.symbol.isSome || call.ordinal.isSome)
    | .internal =>
        call.targetNode.isNone && call.dll.isNone && call.symbol.isNone &&
          call.ordinal.isNone && call.targetRva != 0
    | .indirect =>
        call.targetNode.isSome && call.dll.isNone && call.symbol.isNone &&
          call.ordinal.isNone

def allCallBoundariesShapeChecked (transfer : SemanticTransfer) : Bool :=
  transfer.calls.all callBoundaryShapeChecked

structure ExactCallBoundary where
  event : CallEvent
  state : InterpreterMachine

def initialRuntime (state : InterpreterMachine) : RuntimeState := {
  input := state
  current := state
  callOutput := state
  words := fun _ => none
  events := []
}

def callBoundaryAt (transfer : SemanticTransfer)
    (environment : StageA.Relational.Interpreter.Environment)
    (state : InterpreterMachine) (actionIndex : Nat) : Option ExactCallBoundary := do
  let action <- transfer.body[actionIndex]?
  let runtimeResult <- transfer.executeBody environment (initialRuntime state)
    (transfer.body.take actionIndex)
  let runtime <- match runtimeResult with
    | .inl _ => none
    | .inr runtime => some runtime
  let callIndex <- match action with
    | .call callIndex => some callIndex
    | _ => none
  let call <- transfer.calls[callIndex]?
  let boundary <- call.event runtime
  some { event := boundary.1, state := boundary.2 }

def ExactCallBoundaryAgreement (transfer : SemanticTransfer)
    (original : StageA.Relational.Interpreter.Environment -> InterpreterMachine ->
      Nat -> Option ExactCallBoundary) :
    Prop :=
  forall environment state actionIndex,
    original environment state actionIndex =
      callBoundaryAt transfer environment state actionIndex

def undefinedSlots (transfer : SemanticTransfer) : List Nat :=
  (transfer.wordNodes.filterMap fun node => match node.op with
    | .undefinedBv | .undefinedFlag => some node.immediate
    | _ => none).eraseDups

def undefinedSlotsChecked (transfer : SemanticTransfer) (slots : List Nat) : Bool :=
  slots == undefinedSlots transfer

def EnvironmentMatchesUndefinedValues (slots : List Nat) (state : MachineState)
    (environment : StageA.Relational.Interpreter.Environment) : Prop :=
  forall slot, slot ∈ slots -> environment.undefinedValue slot = state.undefinedValue slot

def UndefinedValueNoninterference (transfer : SemanticTransfer)
    (slots : List Nat) : Prop :=
  forall state environmentLeft environmentRight,
    environmentLeft.invokeCall = environmentRight.invokeCall ->
    (forall slot, slot ∈ slots ->
      environmentLeft.undefinedValue slot = environmentRight.undefinedValue slot) ->
    transfer.execute environmentLeft state = transfer.execute environmentRight state

abbrev OriginalMacroStep :=
  StageA.Relational.Interpreter.Environment -> MachineState -> Option MacroResult

def normalizedBoundaryMachine (state : MachineState)
    (normalized : NormalizedSymbolicBehavior) : InterpreterMachine := {
  registers := evalRegisters state normalized.registers
  flags := evaluatedFlag state normalized.flags
  memory := applyWrites state normalized.writes
  eflags := evalFlags state normalized.flags
}

def interpreterMachinesEqual (left right : InterpreterMachine) : Prop :=
  (forall register, left.registers register = right.registers register) ∧
    (forall flag, left.flags flag = right.flags flag) ∧
    left.memory = right.memory ∧ left.eflags = right.eflags

def normalizedCompletion (targets : List CodeTargetPair) (state : MachineState) :
    NormalizedOutcomeExpr -> Option Completion
  | .returned value => some (.returned (value.eval state))
  | .jump target => (originalTargetRva targets target).map Completion.jump
  | .branch condition taken fallthrough =>
      (originalTargetRva targets
        (if condition.eval state then taken else fallthrough)).map Completion.branch
  | .call _ continuation | .externalCall _ _ continuation |
      .bulkCopy _ _ _ _ continuation | .bulkFill _ _ _ _ continuation |
      .bulkScan _ _ _ _ continuation |
      .indirectCall _ continuation |
      .atomicCompareExchange _ _ _ continuation =>
      (originalTargetRva targets continuation).map Completion.fallthrough
  | .callUnmappedReturn _ => some .externalJump
  | .externalJump _ _ => some .externalJump
  | .indirectJump target => some (.indirectJump (target.eval state))
  | .checkedContinue valid continuation =>
      if valid.eval state then
        (originalTargetRva targets continuation).map Completion.fallthrough
      else some .divideError

def normalizedOutcomeDefersFinalState : NormalizedOutcomeExpr -> Bool
  | .call _ _ | .callUnmappedReturn _ | .externalCall _ _ _ |
      .externalJump _ _ |
      .bulkCopy _ _ _ _ _ | .bulkFill _ _ _ _ _ | .bulkScan _ _ _ _ _ |
      .indirectCall _ _ |
      .atomicCompareExchange _ _ _ _ => true
  | _ => false

def faultCompletion : Completion -> Bool
  | .divideError | .memoryFault | .externalFault | .unimplemented => true
  | _ => false

/-- A decoded call describes its successful continuation while the paired
environment is authoritative for call faults.  Treating a fault as a mismatch
would make the bridge unsoundly assume that every external or nested internal
call succeeds. -/
def normalizedCompletionMatches (targets : List CodeTargetPair)
    (state : MachineState) (outcome : NormalizedOutcomeExpr)
    (completion : Completion) : Prop :=
  match normalizedCompletion targets state outcome with
  | none => False
  | some expected =>
      completion = expected ∨
        (normalizedOutcomeDefersFinalState outcome = true ∧
          faultCompletion completion = true)

def callEventExternalTarget (event : CallEvent) : Option ExternalTarget := do
  let dll <- event.dll
  let name : ImportName <- match event.symbol, event.ordinal with
    | some symbol, none =>
        some (.symbol (symbol.toUTF8.toList.map fun byte => byte.toNat))
    | none, some ordinal => some (.ordinal ordinal)
    | _, _ => none
  some ⟨normalizeDllName (dll.toUTF8.toList.map fun byte => byte.toNat), name⟩

def callBoundaryMatchesNormalized (targets : List CodeTargetPair)
    (normalized : NormalizedSymbolicBehavior) (state : MachineState)
    (boundary : ExactCallBoundary) : Prop :=
  interpreterMachinesEqual boundary.state (normalizedBoundaryMachine state normalized) ∧
    match normalized.outcome with
    | .call target continuation =>
        boundary.event.kind = .internal ∧
          originalTargetRva targets target = some boundary.event.targetRva.toNat ∧
          originalTargetRva targets continuation = some boundary.event.returnRva
    | .callUnmappedReturn target =>
        boundary.event.kind = .internal ∧
          originalTargetRva targets target = some boundary.event.targetRva.toNat
    | .externalCall imported arguments continuation =>
        boundary.event.kind = .external ∧
          callEventExternalTarget boundary.event = some imported ∧
          boundary.event.arguments = arguments.map (Expr.eval state) ∧
          originalTargetRva targets continuation = some boundary.event.returnRva
    | .externalJump imported arguments =>
        boundary.event.kind = .external ∧
          callEventExternalTarget boundary.event = some imported ∧
          boundary.event.arguments = arguments.map (Expr.eval state) ∧
          boundary.event.returnRva = 0
    | .indirectCall target continuation =>
        boundary.event.kind = .indirect ∧
          boundary.event.targetRva = target.eval state ∧
          originalTargetRva targets continuation = some boundary.event.returnRva
    | _ => False

def DecodedCallBoundariesExact (targets : List CodeTargetPair)
    (normalized : NormalizedSymbolicBehavior)
    (boundaries : StageA.Relational.Interpreter.Environment ->
      InterpreterMachine -> Nat -> Option ExactCallBoundary) : Prop :=
  forall state environment actionIndex boundary,
    boundaries environment (machineFromFormal state) actionIndex = some boundary ->
      callBoundaryMatchesNormalized targets normalized state boundary

def OriginalMacroStepAgreesWithNormalized (targets : List CodeTargetPair)
    (normalized : NormalizedSymbolicBehavior) (original : OriginalMacroStep) : Prop :=
  forall state environment, exists result,
    original environment state = some result ∧
      normalizedCompletionMatches targets state normalized.outcome result.completion ∧
      (normalizedOutcomeDefersFinalState normalized.outcome = true ∨
        interpreterMachinesEqual result.state (normalizedBoundaryMachine state normalized))

def FullMacroAgreement (original : OriginalMacroStep) (transfer : SemanticTransfer)
    (slots : List Nat) : Prop :=
  forall state environment,
    EnvironmentMatchesUndefinedValues slots state environment ->
      transfer.execute environment (machineFromFormal state) = original environment state

/-- This relation is the non-Boolean proof obligation.  It compares every
register, every defined/preserved EFLAGS bit, final flat memory, control, and
the empty ordered external/data-memory event trace for all machine states.  The
exact-byte profile is what makes emptiness meaningful: it rejects every decoded
instruction with a data-memory access, plus calls, REP, faults, and multi-exit
transfers. -/
def ObservationalAgreement (targets : List CodeTargetPair)
    (normalized : NormalizedSymbolicBehavior)
    (transfer : SemanticTransfer) : Prop :=
  ∀ state (environment : StageA.Relational.Interpreter.Environment), ∃ result,
    transfer.execute environment (machineFromFormal state) = some result ∧
      (∀ register, result.state.registers register =
        evalRegisters state normalized.registers register) ∧
      (∀ flag, result.state.flags flag = evaluatedFlag state normalized.flags flag) ∧
      result.state.eflags = evalFlags state normalized.flags ∧
      result.state.memory = applyWrites state normalized.writes ∧
      result.events = evalWrites state normalized.writes ∧
      interpreterControl result.completion =
        originalControl targets state normalized.outcome

/-- Exact binary and decoder binding.  No hash or generated status can replace
these typed equalities. -/
structure ExactOriginalNormalizedBinding
    (peBytes : ByteTree) (instructionBytes : Bytes) (pe : PE32) (span : Span)
    (imports : List PEImport) (contracts : List MachineImportCallContract)
    (targets : List CodeTargetPair) (decoded : SymbolicBehavior)
    (normalized : NormalizedSymbolicBehavior) : Prop where
  peParsed : parsePE32Tree peBytes = some pe
  instructionBytesRead :
    exactRvaBytes pe span.start span.size = some instructionBytes
  decodedFromExactBytes :
    regionBehaviorWithMachineCallContracts pe imports contracts span = some decoded
  normalizedFromDecoded :
    normalizeSymbolicBehavior false targets decoded = some normalized
  canonicalTargets : targetMapChecked targets = true

/-- The raw Stage B record, its exact artifact identities, and the profile that
can currently be related without missing read traces or post-call semantics. -/
structure CheckedInterpreterRecordBinding
    (contractBytes instructionBytes : Bytes) (record : ProgramRecord)
    (exported : ExportedSemanticTransfer) : Prop where
  contractDigestChecked :
    SHA256.checkedHex contractBytes exported.contractSha256 = true
  instructionDigestChecked :
    SHA256.checkedHex instructionBytes exported.instructionBytesSha256 = true
  exactInstructionProfile : exactMemoryEffectFreeProfile instructionBytes = true
  rawRecordDecoded : record.decode = some exported.transfer
  transferChecked : exported.transfer.checked = true
  supportedProfile : transferProfileSupported exported.transfer = true

/-- A compact, cacheable intermediate certificate.  `semanticAgreement` is a
real universal Lean proposition and must be proved from the generated transfer;
Python cannot fill it with a status field.  This is intentionally not a whole-
program certificate. -/
structure InterpreterTransferCertificate
    (peBytes : ByteTree) (contractBytes instructionBytes : Bytes)
    (pe : PE32) (span : Span)
    (imports : List PEImport) (contracts : List MachineImportCallContract)
    (targets : List CodeTargetPair) (decoded : SymbolicBehavior)
    (normalized : NormalizedSymbolicBehavior) (record : ProgramRecord)
    (exported : ExportedSemanticTransfer) : Prop where
  original : ExactOriginalNormalizedBinding peBytes instructionBytes pe span
    imports contracts targets decoded normalized
  interpreter : CheckedInterpreterRecordBinding contractBytes instructionBytes
    record exported
  sourceRvaBound : exported.transfer.sourceRva = span.start
  normalizedSupported : normalizedProfileSupported normalized = true
  semanticAgreement : ObservationalAgreement targets normalized exported.transfer

/-- The reusable theorem consumed later by product-graph segment wiring. -/
theorem InterpreterTransferCertificate.macroStepRefinesOriginal
    {peBytes : ByteTree} {contractBytes instructionBytes : Bytes}
    {pe : PE32} {span : Span}
    {imports : List PEImport} {contracts : List MachineImportCallContract}
    {targets : List CodeTargetPair} {decoded : SymbolicBehavior}
    {normalized : NormalizedSymbolicBehavior} {record : ProgramRecord}
    {exported : ExportedSemanticTransfer}
    (certificate : InterpreterTransferCertificate peBytes contractBytes
      instructionBytes pe span imports contracts targets decoded normalized
      record exported) :
    ObservationalAgreement targets normalized exported.transfer :=
  certificate.semanticAgreement

theorem InterpreterTransferCertificate.rawMacroStepRefinesOriginal
    {peBytes : ByteTree} {contractBytes instructionBytes : Bytes}
    {pe : PE32} {span : Span}
    {imports : List PEImport} {contracts : List MachineImportCallContract}
    {targets : List CodeTargetPair} {decoded : SymbolicBehavior}
    {normalized : NormalizedSymbolicBehavior} {record : ProgramRecord}
    {exported : ExportedSemanticTransfer}
    (certificate : InterpreterTransferCertificate peBytes contractBytes
      instructionBytes pe span imports contracts targets decoded normalized
      record exported) (state : MachineState)
    (environment : StageA.Relational.Interpreter.Environment) :
    ∃ result,
      record.interpret environment (machineFromFormal state) = some result ∧
        (∀ register, result.state.registers register =
          evalRegisters state normalized.registers register) ∧
        (∀ flag, result.state.flags flag =
          evaluatedFlag state normalized.flags flag) ∧
        result.state.eflags = evalFlags state normalized.flags ∧
        result.state.memory = applyWrites state normalized.writes ∧
        result.events = evalWrites state normalized.writes ∧
        interpreterControl result.completion =
          originalControl targets state normalized.outcome := by
  rcases certificate.semanticAgreement state environment with
    ⟨result, executed, registers, flagValues, flags, memory, events, control⟩
  refine ⟨result, ?_, registers, flagValues, flags, memory, events, control⟩
  simpa [ProgramRecord.interpret, certificate.interpreter.rawRecordDecoded,
    certificate.interpreter.transferChecked] using executed

/-! General non-x87 transfer certificates.  These are intermediate segment
certificates, never whole-program acceptance.  The exact decoded original
macro-step and the equality proof are named Lean objects supplied by the
semantic-transfer proof graph; a Python status cannot construct either. -/

def generalTransferProfileSupported (transfer : SemanticTransfer) : Bool :=
  transfer.checked && allCallBoundariesShapeChecked transfer

structure CheckedGeneralInterpreterRecordBinding
    (contractBytes instructionBytes : Bytes) (record : ProgramRecord)
    (exported : ExportedSemanticTransfer)
    (footprint : List FlatMemoryAccessSite)
    (aliasWitnesses : List FlatMemoryAliasWitness) : Prop where
  contractDigestChecked :
    SHA256.checkedHex contractBytes exported.contractSha256 = true
  instructionDigestChecked :
    SHA256.checkedHex instructionBytes exported.instructionBytesSha256 = true
  exactInstructionProfile : exactDecodedInstructionProfile instructionBytes = true
  rawRecordDecoded : record.decode = some exported.transfer
  transferChecked : exported.transfer.checked = true
  supportedProfile : generalTransferProfileSupported exported.transfer = true
  exactFootprint : flatMemoryFootprintChecked exported.transfer footprint = true
  aliasInventory : flatMemoryAliasInventoryChecked footprint aliasWitnesses = true

def DynamicControlTargetsComplete (transfer : SemanticTransfer)
    (targets : List CodeTargetPair) (returnFrameTarget externalTarget : Word -> Prop) : Prop :=
  forall state environment result,
    transfer.execute environment state = some result ->
      (match result.completion with
       | .returned target =>
           (originalTargetIdAt targets target.toNat).isSome ∨ returnFrameTarget target
       | .indirectJump target =>
           (originalTargetIdAt targets target.toNat).isSome ∨ externalTarget target
       | _ => True) ∧
      forall event, event ∈ result.events -> match event with
      | .call call =>
          call.kind = .indirect ->
            (originalTargetIdAt targets call.targetRva.toNat).isSome ∨
              externalTarget call.targetRva
      | _ => True

/-- The exact macro-step implementation extracted from the original is passed
as data, but its authority comes only from `semanticAgreement`, a universal
Lean proof in the same certificate as the exact PE/decoder binding. -/
structure GeneralInterpreterTransferCertificate
    (peBytes : ByteTree) (contractBytes instructionBytes : Bytes)
    (pe : PE32) (span : Span)
    (imports : List PEImport) (contracts : List MachineImportCallContract)
    (targets : List CodeTargetPair) (decoded : SymbolicBehavior)
    (normalized : NormalizedSymbolicBehavior) (record : ProgramRecord)
    (exported : ExportedSemanticTransfer) (originalMacro : OriginalMacroStep)
    (originalCallBoundaries :
      StageA.Relational.Interpreter.Environment -> InterpreterMachine -> Nat ->
        Option ExactCallBoundary)
    (footprint : List FlatMemoryAccessSite)
    (aliasWitnesses : List FlatMemoryAliasWitness)
    (targetWitnesses : List ControlTargetWitness)
    (undefinedValueSlots : List Nat)
    (returnFrameTarget externalTarget : Word -> Prop) : Prop where
  original : ExactOriginalNormalizedBinding peBytes instructionBytes pe span
    imports contracts targets decoded normalized
  interpreter : CheckedGeneralInterpreterRecordBinding contractBytes instructionBytes
    record exported footprint aliasWitnesses
  sourceRvaBound : exported.transfer.sourceRva = span.start
  targetsExact :
    controlTargetInventoryChecked exported.transfer targets targetWitnesses = true
  callBoundariesExact :
    ExactCallBoundaryAgreement exported.transfer originalCallBoundaries
  callBoundariesDecoded :
    DecodedCallBoundariesExact targets normalized originalCallBoundaries
  aliasDisjointness :
    FlatMemoryAliasWitnessesSound exported.transfer aliasWitnesses
  undefinedInventory :
    undefinedSlotsChecked exported.transfer undefinedValueSlots = true
  undefinedNoninterference :
    UndefinedValueNoninterference exported.transfer undefinedValueSlots
  dynamicTargetsComplete :
    DynamicControlTargetsComplete exported.transfer targets returnFrameTarget
      externalTarget
  originalMacroDecoded :
    OriginalMacroStepAgreesWithNormalized targets normalized originalMacro
  semanticAgreement :
    FullMacroAgreement originalMacro exported.transfer undefinedValueSlots

theorem GeneralInterpreterTransferCertificate.macroStepRefinesOriginal
    {peBytes : ByteTree} {contractBytes instructionBytes : Bytes}
    {pe : PE32} {span : Span}
    {imports : List PEImport} {contracts : List MachineImportCallContract}
    {targets : List CodeTargetPair} {decoded : SymbolicBehavior}
    {normalized : NormalizedSymbolicBehavior} {record : ProgramRecord}
    {exported : ExportedSemanticTransfer} {originalMacro : OriginalMacroStep}
    {originalCallBoundaries :
      StageA.Relational.Interpreter.Environment -> InterpreterMachine -> Nat ->
        Option ExactCallBoundary}
    {footprint : List FlatMemoryAccessSite}
    {aliasWitnesses : List FlatMemoryAliasWitness}
    {targetWitnesses : List ControlTargetWitness}
    {undefinedValueSlots : List Nat}
    {returnFrameTarget externalTarget : Word -> Prop}
    (certificate : GeneralInterpreterTransferCertificate peBytes contractBytes
      instructionBytes pe span imports contracts targets decoded normalized record
      exported originalMacro originalCallBoundaries footprint aliasWitnesses
      targetWitnesses undefinedValueSlots returnFrameTarget externalTarget) :
    FullMacroAgreement originalMacro exported.transfer undefinedValueSlots :=
  certificate.semanticAgreement

theorem GeneralInterpreterTransferCertificate.macroStepProducesDecodedResult
    {peBytes : ByteTree} {contractBytes instructionBytes : Bytes}
    {pe : PE32} {span : Span}
    {imports : List PEImport} {contracts : List MachineImportCallContract}
    {targets : List CodeTargetPair} {decoded : SymbolicBehavior}
    {normalized : NormalizedSymbolicBehavior} {record : ProgramRecord}
    {exported : ExportedSemanticTransfer} {originalMacro : OriginalMacroStep}
    {originalCallBoundaries :
      StageA.Relational.Interpreter.Environment -> InterpreterMachine -> Nat ->
        Option ExactCallBoundary}
    {footprint : List FlatMemoryAccessSite}
    {aliasWitnesses : List FlatMemoryAliasWitness}
    {targetWitnesses : List ControlTargetWitness}
    {undefinedValueSlots : List Nat}
    {returnFrameTarget externalTarget : Word -> Prop}
    (certificate : GeneralInterpreterTransferCertificate peBytes contractBytes
      instructionBytes pe span imports contracts targets decoded normalized record
      exported originalMacro originalCallBoundaries footprint aliasWitnesses
      targetWitnesses undefinedValueSlots returnFrameTarget externalTarget)
    (state : MachineState)
    (environment : StageA.Relational.Interpreter.Environment)
    (undefinedValues :
      EnvironmentMatchesUndefinedValues undefinedValueSlots state environment) :
    exists result,
      exported.transfer.execute environment (machineFromFormal state) = some result ∧
        normalizedCompletionMatches targets state normalized.outcome result.completion ∧
        (normalizedOutcomeDefersFinalState normalized.outcome = true ∨
          interpreterMachinesEqual result.state
            (normalizedBoundaryMachine state normalized)) := by
  rcases certificate.originalMacroDecoded state environment with
    ⟨result, originalExecuted, completion, stateAgreement⟩
  refine ⟨result, ?_, completion, stateAgreement⟩
  rw [certificate.semanticAgreement state environment undefinedValues]
  exact originalExecuted

theorem GeneralInterpreterTransferCertificate.rawMacroStepRefinesOriginal
    {peBytes : ByteTree} {contractBytes instructionBytes : Bytes}
    {pe : PE32} {span : Span}
    {imports : List PEImport} {contracts : List MachineImportCallContract}
    {targets : List CodeTargetPair} {decoded : SymbolicBehavior}
    {normalized : NormalizedSymbolicBehavior} {record : ProgramRecord}
    {exported : ExportedSemanticTransfer} {originalMacro : OriginalMacroStep}
    {originalCallBoundaries :
      StageA.Relational.Interpreter.Environment -> InterpreterMachine -> Nat ->
        Option ExactCallBoundary}
    {footprint : List FlatMemoryAccessSite}
    {aliasWitnesses : List FlatMemoryAliasWitness}
    {targetWitnesses : List ControlTargetWitness}
    {undefinedValueSlots : List Nat}
    {returnFrameTarget externalTarget : Word -> Prop}
    (certificate : GeneralInterpreterTransferCertificate peBytes contractBytes
      instructionBytes pe span imports contracts targets decoded normalized record
      exported originalMacro originalCallBoundaries footprint aliasWitnesses
      targetWitnesses undefinedValueSlots returnFrameTarget externalTarget)
    (state : MachineState)
    (environment : StageA.Relational.Interpreter.Environment)
    (undefinedValues :
      EnvironmentMatchesUndefinedValues undefinedValueSlots state environment) :
    record.interpret environment (machineFromFormal state) =
      originalMacro environment state := by
  rw [ProgramRecord.macroStep_semantic_correspondence record exported.transfer
    certificate.interpreter.rawRecordDecoded certificate.interpreter.transferChecked]
  exact certificate.semanticAgreement state environment undefinedValues

/-- Reuse the reviewed relational frame theorem for any concrete paired write
footprint.  The bridge carries footprint and alias evidence; it does not clone
the stack/static/dynamic/import-memory preservation proof. -/
theorem pairedFlatMemoryUpdatePreservesRelationalFamilies
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory)
    (frame : PairedMemoryUpdateFrame context world original candidate)
    (related : RelationalMemoryFamiliesHold context world original candidate) :
    RelationalMemoryFamiliesHold context world
      (applyConcreteWrites original frame.originalWrites)
      (applyConcreteWrites candidate frame.candidateWrites) :=
  RelationalMemoryFamiliesHold.afterPairedMemoryUpdate
    context world original candidate frame related

/-- Runtime returns use the existing checked relational call-frame theorem. -/
theorem checkedReturnUsesRelationalRuntimeFrame
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (returnClaim : ReturnPopClaim) (frameClaim : ReturnPopFrameClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (returnChecked : returnClaim.checked originalBehavior candidateBehavior = true)
    (frameChecked : frameClaim.checked returnClaim = true)
    (offsetsHold : frameClaim.offsets.holds frame originalState.registers
      candidateState.registers)
    (memoryHolds : frame.memoryHolds originalState.memory candidateState.memory) :
    originalBehavior.outcome.eval originalState = .returned frame.originalReturnAddress ∧
      candidateBehavior.outcome.eval candidateState = .returned frame.candidateReturnAddress :=
  returnPopTargetsRuntimeFrame_of_checked originalBehavior candidateBehavior
    returnClaim frameClaim frame originalState candidateState returnChecked frameChecked
    offsetsHold memoryHolds

/-- External calls reuse the paired environment refinement theorem, including
ABI state, memory effects, world updates, and runtime-frame preservation. -/
theorem checkedExternalCallResultsRelated
    (context : StaticProofContext) (site : ExternalCallSiteContract)
    (contract : MachineImportCallContract)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (environmentRefines : ExternalEnvironmentRefinesAt context site contract
      originalEnvironment candidateEnvironment)
    (returns : contract.disposition = .returns)
    (eventIndex : Nat) (originalEvent candidateEvent : WorldExternalEvent)
    (boundary : ExternalCallBoundaryRelated context site contract
      originalEvent candidateEvent) :
    let originalResult := originalEnvironment.result eventIndex originalEvent
    let candidateResult := candidateEnvironment.result eventIndex candidateEvent
    originalResult.world = candidateResult.world ∧
      machineCallResultConforms false context contract originalEvent originalResult ∧
      machineCallResultConforms true context contract candidateEvent candidateResult ∧
      machineCallResultRegistersRelated context originalResult.world contract
        originalEvent.arguments originalResult.state candidateResult.state = true ∧
      StateRel context originalResult.world site.targetInvariant
        originalResult.state candidateResult.state ∧
      ExternalRuntimeFramesPreserved originalEvent candidateEvent
        originalResult candidateResult :=
  externalCallResultsRelated context site contract originalEnvironment
    candidateEnvironment environmentRefines returns eventIndex originalEvent
    candidateEvent boundary

end StageA.Relational.InterpreterTransfer
