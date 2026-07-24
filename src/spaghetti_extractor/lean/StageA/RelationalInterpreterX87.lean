import StageA.RelationalInterpreter
import StageA.RelationalInterpreterKernelData
import StageA.RelationalPEBytePacks
import StageA.RelationalPEExecution

namespace StageA.Relational.InterpreterX87

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelData

namespace ArtifactSHA256

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

end ArtifactSHA256

/-- Encode canonical JSON text inside Lean without elaborating one deeply
nested list constructor per byte.  Digest checks still bind the resulting
bytes, and `String.toUTF8` is deterministic across proof shards. -/
def utf8Bytes (value : String) : Bytes :=
  value.toUTF8.toList.map fun byte => byte.toNat

/-- Exact file-backed bytes; zero-fill and ambiguous section mappings are
rejected so no schedule digest can bind a synthetic decoder input. -/
def exactScheduleRvaBytes (pe : PE32) (rva size : Nat) : Option Bytes := do
  if !exactRvaSpan pe rva size then none else
  if rva < pe.sizeOfHeaders then
    pe.bytes.readBytes rva size
  else
    match pe.sections.filter (fun candidateSection =>
        candidateSection.virtualAddress <= rva &&
          size <= candidateSection.virtualAddress + candidateSection.mappedSize - rva) with
    | [candidateSection] =>
        pe.bytes.readBytes (candidateSection.rawPointer +
          (rva - candidateSection.virtualAddress))
          size
    | _ => none

/-- Section-backed schedule bytes use the generic pack reader once the RVA is
known to be past the PE headers.  Generated schedules discharge that small
metadata premise and reuse an independently cached pack equation. -/
theorem exactScheduleRvaBytes_eq_readExactSectionRvaSpan
    (pe : PE32) (rva size : Nat) (afterHeaders : pe.sizeOfHeaders <= rva) :
    exactScheduleRvaBytes pe rva size =
      PEBytePacks.readExactSectionRvaSpan pe rva size := by
  simp [exactScheduleRvaBytes, PEBytePacks.readExactSectionRvaSpan,
    PEBytePacks.sectionContainsExactRvaSpan, Nat.not_lt_of_ge afterHeaders]
  rfl

inductive InstructionClass where
  | ordinary
  | x87Singleton
deriving Repr, DecidableEq

def InstructionClass.ofNat? : Nat -> Option InstructionClass
  | 0 => some .ordinary
  | 1 => some .x87Singleton
  | _ => none

structure RawInstructionRecord where
  index : Nat
  kind : Nat
  span : Span
  bytes : Bytes
  bytesSha256 : String
  canonicalBytes : Bytes
  recordSha256 : String
  transferBytesSha256 : String
deriving Repr, DecidableEq

def RawInstructionRecord.decodeClass
    (record : RawInstructionRecord) : Option InstructionClass :=
  InstructionClass.ofNat? record.kind

def RawInstructionRecord.shapeChecked (record : RawInstructionRecord)
    (expectedIndex expectedRva : Nat) (transferDigest : String) : Bool :=
  record.index == expectedIndex && record.span.start == expectedRva &&
    record.span.size == record.bytes.length && !record.bytes.isEmpty &&
    record.transferBytesSha256 == transferDigest && record.decodeClass.isSome

def RawInstructionRecord.digestsChecked
    (record : RawInstructionRecord) : Bool :=
  ArtifactSHA256.checkedHex record.bytes record.bytesSha256 &&
    ArtifactSHA256.checkedHex record.canonicalBytes record.recordSha256

structure RawReplayAction where
  opcode : Nat
  replayIndex : Nat
  span : Span
  instructionBytes : Bytes
  instructionBytesSha256 : String
  transferBytesSha256 : String
  contractSha256 : String
deriving Repr, DecidableEq

def RawReplayAction.matches (action : RawReplayAction)
    (record : RawInstructionRecord) (expectedReplayIndex : Nat)
    (contractDigest transferDigest : String) : Bool :=
  action.opcode == 25 && action.replayIndex == expectedReplayIndex &&
    action.span == record.span && action.instructionBytes == record.bytes &&
    action.instructionBytesSha256 == record.bytesSha256 &&
    action.transferBytesSha256 == transferDigest &&
    action.contractSha256 == contractDigest

structure RawInstructionSchedule where
  sourceRva : Nat
  transferBytes : Bytes
  transferBytesSha256 : String
  contractCanonicalBytes : Bytes
  contractSha256 : String
  scheduleCanonicalBytes : Bytes
  scheduleSha256 : String
  records : List RawInstructionRecord
  replayActions : List RawReplayAction
deriving Repr, DecidableEq

private def checkRecords : List RawInstructionRecord -> List RawReplayAction ->
    Nat -> Nat -> Nat -> String -> String -> Bool
  | [], [], _, _, _, _, _ => true
  | record :: records, actions, expectedIndex, expectedRva, replayIndex,
      contractDigest, transferDigest =>
      record.shapeChecked expectedIndex expectedRva transferDigest &&
        match record.decodeClass with
        | some .ordinary =>
            checkRecords records actions (expectedIndex + 1) record.span.stop
              replayIndex contractDigest transferDigest
        | some .x87Singleton =>
            match actions with
            | action :: remaining =>
                action.matches record replayIndex contractDigest transferDigest &&
                  checkRecords records remaining (expectedIndex + 1)
                    record.span.stop (replayIndex + 1) contractDigest
                    transferDigest
            | [] => false
        | none => false
  | _, _, _, _, _, _, _ => false

private def bindReplayContracts (digest : String) : List RawReplayAction -> Bool
  | [] => true
  | action :: actions =>
      action.contractSha256 == digest && bindReplayContracts digest actions

def RawInstructionSchedule.digestsChecked
    (schedule : RawInstructionSchedule) : Bool :=
  ArtifactSHA256.checkedHex schedule.transferBytes schedule.transferBytesSha256 &&
    ArtifactSHA256.checkedHex schedule.contractCanonicalBytes schedule.contractSha256 &&
    ArtifactSHA256.checkedHex schedule.scheduleCanonicalBytes schedule.scheduleSha256 &&
    schedule.records.all RawInstructionRecord.digestsChecked

def RawInstructionSchedule.orderAndReplayChecked
    (schedule : RawInstructionSchedule) : Bool :=
  !schedule.records.isEmpty && !schedule.transferBytes.isEmpty &&
    schedule.records.flatMap (fun record => record.bytes) ==
      schedule.transferBytes &&
    checkRecords schedule.records schedule.replayActions 0 schedule.sourceRva 0
      schedule.contractSha256 schedule.transferBytesSha256 &&
    bindReplayContracts schedule.contractSha256 schedule.replayActions

def RawInstructionSchedule.basicChecked
    (schedule : RawInstructionSchedule) : Bool :=
  schedule.digestsChecked && schedule.orderAndReplayChecked

def RawInstructionRecord.exactPEChecked (pe : PE32)
    (record : RawInstructionRecord) : Bool :=
  exactScheduleRvaBytes pe record.span.start record.span.size == some record.bytes

def RawInstructionRecord.semanticClassChecked
    (record : RawInstructionRecord) : Bool :=
  match record.decodeClass with
  | none => false
  | some .ordinary =>
      match decodeInstructionExact record.bytes with
      | none => false
      | some decoded =>
          decoded.size == record.span.size &&
            (StageA.Relational.X87.instructionDescriptor?
              decoded.instruction).isNone
  | some .x87Singleton =>
      match StageA.Relational.X87.decodeCommandExact record.bytes with
      | none => false
      | some decoded => decoded.size == record.span.size

def RawInstructionSchedule.exactPEChecked (schedule : RawInstructionSchedule)
    (pe : PE32) : Bool :=
  exactScheduleRvaBytes pe schedule.sourceRva schedule.transferBytes.length ==
      some schedule.transferBytes

def RawInstructionSchedule.semanticClassesChecked
    (schedule : RawInstructionSchedule) (_pe : PE32) : Bool :=
  schedule.records.all RawInstructionRecord.semanticClassChecked

def RawInstructionRecord.ordinaryExecutableChecked (pe : PE32)
    (imports : List PEImport) (record : RawInstructionRecord) : Bool :=
  match record.decodeClass with
  | some .x87Singleton => true
  | some .ordinary =>
      match decodeInstructionExact record.bytes with
      | some decoded =>
          decoded.size == record.span.size &&
            (executeInstruction pe imports record.span.start record.index decoded
              initialSymbolic).isSome
      | none => false
  | none => false

def RawInstructionSchedule.ordinaryExecutableChecked
    (schedule : RawInstructionSchedule) (pe : PE32) : Bool :=
  match parseImports pe with
  | none => false
  | some imports =>
      schedule.records.all
        (RawInstructionRecord.ordinaryExecutableChecked pe imports)

/-- Import parsing is authoritative PE work and is cached separately from each
schedule.  This checker keeps only the local record execution reduction in the
schedule shard. -/
def RawInstructionSchedule.ordinaryExecutableWithImportsChecked
    (schedule : RawInstructionSchedule) (pe : PE32)
    (imports : List PEImport) : Bool :=
  schedule.records.all
    (RawInstructionRecord.ordinaryExecutableChecked pe imports)

theorem RawInstructionSchedule.ordinaryExecutableChecked_of_importsParsed
    (schedule : RawInstructionSchedule) (pe : PE32) (imports : List PEImport)
    (importsParsed : parseImports pe = some imports)
    (checked : schedule.ordinaryExecutableWithImportsChecked pe imports = true) :
    schedule.ordinaryExecutableChecked pe = true := by
  simpa [RawInstructionSchedule.ordinaryExecutableChecked,
    RawInstructionSchedule.ordinaryExecutableWithImportsChecked,
    importsParsed] using checked

def RawInstructionSchedule.replayOpcode25RecordChecked
    (schedule : RawInstructionSchedule) (record : RawInstructionRecord) : Bool :=
  match record.decodeClass with
  | some .ordinary => true
  | some .x87Singleton =>
      match schedule.replayActions.find? fun action => action.span == record.span with
      | none => false
      | some action =>
          action.opcode == 25 && action.span == record.span &&
            action.instructionBytes == record.bytes &&
            action.instructionBytesSha256 == record.bytesSha256 &&
            action.transferBytesSha256 == schedule.transferBytesSha256 &&
            action.contractSha256 == schedule.contractSha256
  | none => false

def RawInstructionSchedule.replayOpcode25Checked
    (schedule : RawInstructionSchedule) : Bool :=
  schedule.records.all schedule.replayOpcode25RecordChecked

structure CheckedInstructionSchedule (schedule : RawInstructionSchedule)
    (pe : PE32) : Prop where
  orderAndReplay : schedule.orderAndReplayChecked = true
  exactPEBytes : schedule.exactPEChecked pe = true
  semanticClasses : schedule.semanticClassesChecked pe = true

theorem CheckedInstructionSchedule.basicChecked
    {schedule : RawInstructionSchedule} {pe : PE32}
    (checked : CheckedInstructionSchedule schedule pe)
    (digests : schedule.digestsChecked = true) :
    schedule.basicChecked = true := by
  simp [RawInstructionSchedule.basicChecked, digests, checked.orderAndReplay]

inductive MemoryEffect where
  | read (address : Word) (bytes : Nat) (value : X87Word)
  | write (address : Word) (bytes : Nat) (value : X87Word)
deriving Repr, DecidableEq

inductive ScheduleFault where
  | x87 (fault : StageA.X87.Fault)
  | divideError
  | memoryFault
  | externalFault
  | unsupported
deriving Repr, DecidableEq

inductive StepControl where
  | fallthrough (targetRva : Nat)
  | stop (outcome : PureOutcome)
deriving Repr, DecidableEq

structure StepResult where
  state : MachineState
  memoryEffects : List MemoryEffect
  faults : List ScheduleFault
  control : StepControl
  calls : List CallEvent
  x87Response : Option StageA.X87.Response := none

def x87ReadEffects (descriptor : StageA.Relational.X87.DecodedCommand)
    (state : MachineState) : List MemoryEffect :=
  match descriptor.command.expectedOperandBytes,
      StageA.Relational.X87.commandDataAddress descriptor state with
  | some bytes, some address =>
      [.read address bytes (state.readX87Word address bytes)]
  | _, _ => []

def x87WriteEffects (effect : StageA.X87.MachineEffect) : List MemoryEffect :=
  match effect.response.store, effect.memoryAddress with
  | some store, some address =>
      [.write address store.kind.byteWidth store.bits]
  | _, _ => []

def singletonTarget (span : Span) : CodeTargetPair := {
  id := span.stop
  originalRva := span.stop
  candidateRva := span.stop
}

/-- Execute one exact x87 record through the acceptance-facing decoder and
physical executor. The local target maps the singleton continuation to its raw
RVA, which is the interpreter schedule's internal cutpoint identity. -/
def executeX87Singleton (pe : PE32) (record : RawInstructionRecord)
    (state : MachineState) : Option StepResult := do
  if record.decodeClass != some .x87Singleton then none else
  let descriptor <- StageA.Relational.X87.decodeSingletonCommand pe record.span
  let behavior <- StageA.Relational.X87.executeSingletonCommand false pe
    record.span [singletonTarget record.span] state
  let effect <- behavior.x87Effect
  if behavior.outcome != .jump record.span.stop then none else
  pure {
    state := behavior.nextMachineState state
    memoryEffects := x87ReadEffects descriptor state ++ x87WriteEffects effect
    faults := behavior.x87Fault.toList.map .x87
    control := .fallthrough record.span.stop
    calls := []
    x87Response := some effect.response
  }

def PhysicalX87FieldsEstablished (result : StepResult) : Prop :=
  match result.x87Response with
  | none => True
  | some response =>
      result.state.x87Physical.slots = response.nextState.slots ∧
      result.state.x87Physical.control = response.nextState.control ∧
      result.state.x87Physical.status = response.nextState.status ∧
      result.state.x87Physical.pendingException =
        response.nextState.pendingException ∧
      result.state.x87Physical.lastOpcode = response.nextState.lastOpcode ∧
      result.state.x87Physical.instructionPointer =
        response.nextState.instructionPointer ∧
      result.state.x87Physical.codeSelector =
        response.nextState.codeSelector ∧
      result.state.x87Physical.dataPointer = response.nextState.dataPointer ∧
      result.state.x87Physical.dataSelector = response.nextState.dataSelector

structure X87SingletonExecutionWitness (pe : PE32)
    (record : RawInstructionRecord) (input : MachineState)
    (result : StepResult) where
  descriptor : StageA.Relational.X87.DecodedCommand
  behavior : RelationalBehavior
  effect : StageA.X87.MachineEffect
  decoded : StageA.Relational.X87.decodeSingletonCommand pe record.span =
    some descriptor
  executed : StageA.Relational.X87.executeSingletonCommand false pe record.span
    [singletonTarget record.span] input = some behavior
  effectBound : behavior.x87Effect = some effect
  resultState : result.state = behavior.nextMachineState input
  orderedMemoryEffects : result.memoryEffects =
    x87ReadEffects descriptor input ++ x87WriteEffects effect
  exactFault : result.faults = behavior.x87Fault.toList.map .x87
  exactControl : result.control = .fallthrough record.span.stop
  noCalls : result.calls = []
  exactResponse : result.x87Response = some effect.response
  physicalFields : PhysicalX87FieldsEstablished result

def executeX87Singleton_witness (pe : PE32)
    (record : RawInstructionRecord) (input : MachineState)
    (result : StepResult)
    (executed : executeX87Singleton pe record input = some result) :
    X87SingletonExecutionWitness pe record input result := by
  unfold executeX87Singleton at executed
  split at executed <;> try contradiction
  rename_i classChecked
  cases decoded : StageA.Relational.X87.decodeSingletonCommand pe record.span with
  | none => simp [decoded] at executed
  | some descriptor =>
      simp only [decoded] at executed
      cases ran : StageA.Relational.X87.executeSingletonCommand false pe
          record.span [singletonTarget record.span] input with
      | none => simp [ran] at executed
      | some behavior =>
          simp only [ran] at executed
          cases effectFound : behavior.x87Effect with
          | none => simp [effectFound] at executed
          | some effect =>
              simp [effectFound] at executed
              rcases executed with ⟨controlChecked, executed⟩
              subst result
              refine {
                descriptor := descriptor
                behavior := behavior
                effect := effect
                decoded := decoded
                executed := ran
                effectBound := effectFound
                resultState := rfl
                orderedMemoryEffects := rfl
                exactFault := rfl
                exactControl := rfl
                noCalls := rfl
                exactResponse := rfl
                physicalFields := ?_
              }
              simp [PhysicalX87FieldsEstablished,
                RelationalBehavior.nextMachineState, effectFound]

structure ExecutionTrace where
  memoryEffects : List MemoryEffect := []
  faults : List ScheduleFault := []
  controls : List StepControl := []
  calls : List CallEvent := []

def ExecutionTrace.appendStep (trace : ExecutionTrace)
    (step : StepResult) : ExecutionTrace := {
  memoryEffects := trace.memoryEffects ++ step.memoryEffects
  faults := trace.faults ++ step.faults
  controls := trace.controls ++ [step.control]
  calls := trace.calls ++ step.calls
}

structure ScheduleResult where
  state : MachineState
  trace : ExecutionTrace

abbrev OrdinaryStep := RawInstructionRecord -> MachineState -> Option StepResult
abbrev ReplayStep := RawReplayAction -> MachineState -> Option StepResult

def machineStateAfterOrdinary (input : MachineState)
    (behavior : ConcreteBehavior) : MachineState := {
  registers := behavior.registers
  memory := behavior.memory
  undefinedValue := input.undefinedValue
  x87 := input.x87
  x87Physical := input.x87Physical
  x87Semantics := input.x87Semantics
  eflags := behavior.eflags
  fsBase := input.fsBase
}

def ordinaryMemoryEffects (input : MachineState)
    (behavior : SymbolicBehavior) : List MemoryEffect :=
  behavior.writes.map fun write =>
    .write (write.1.eval input) 4 (BitVec.zeroExtend 80 (write.2.eval input))

def pureOutcomeOfConcrete : ConcreteOutcome -> PureOutcome
  | .returned target => .returned target
  | .jump target => .jump target
  | .branch condition taken fallthrough =>
      .branch condition taken fallthrough
  | .call target continuation _ => .call target continuation
  | .externalCall imported arguments continuation =>
      .externalCall (normalizeImport imported) arguments continuation
  | .externalJump imported arguments =>
      .externalJump (normalizeImport imported) arguments
  | .bulkCopy destination source count direction continuation =>
      .bulkCopy destination source count direction continuation
  | .indirectCall target continuation _ => .indirectCall target continuation
  | .indirectJump target => .indirectJump target
  | .checkedContinue valid continuation => .checkedContinue valid continuation
  | .atomicCompareExchange address expected replacement continuation =>
      .atomicCompareExchange address expected replacement continuation

def ordinaryStepResult (record : RawInstructionRecord) (input : MachineState)
    (behavior : SymbolicBehavior) (stopped : Bool) : Option StepResult := do
  let concrete := behavior.eval input
  let control <- match concrete.outcome, stopped with
    | none, false => some (.fallthrough record.span.stop)
    | some outcome, _ => some (.stop (pureOutcomeOfConcrete outcome))
    | none, true => none
  pure {
    state := machineStateAfterOrdinary input concrete
    memoryEffects := ordinaryMemoryEffects input behavior
    faults := []
    control
    calls := []
  }

/-- Execute an ordinary schedule record from its exact bytes using the reviewed
IA-32 decoder and symbolic instruction semantics.  Physical x87 state is
framed because the classification check rejects x87 instructions here. -/
def executeOrdinarySingleton (pe : PE32) (record : RawInstructionRecord)
    (input : MachineState) : Option StepResult := do
  if record.decodeClass != some .ordinary then none else
  let imports <- parseImports pe
  let decoded <- decodeInstructionExact record.bytes
  if decoded.size != record.span.size then none else
  let result <- executeInstruction pe imports record.span.start record.index
    decoded initialSymbolic
  match result with
  | .next behavior => ordinaryStepResult record input behavior false
  | .stop behavior => ordinaryStepResult record input behavior true

def replayActionFor (schedule : RawInstructionSchedule)
    (record : RawInstructionRecord) : Option RawReplayAction :=
  schedule.replayActions.find? fun action => action.span == record.span

/-- Opcode 25 is the abstract interpreter's exact x87 replay operation.  It is
defined only when the immutable replay action is bound to this record and to
the enclosing transfer. -/
def executeReplayOpcode25 (pe : PE32) (schedule : RawInstructionSchedule)
    (record : RawInstructionRecord) (state : MachineState) : Option StepResult :=
  if schedule.replayOpcode25RecordChecked record then
    executeX87Singleton pe record state
  else
    none

def exactInterpreterStep (pe : PE32) (schedule : RawInstructionSchedule)
    (record : RawInstructionRecord) (state : MachineState) : Option StepResult :=
  match record.decodeClass with
  | some .ordinary => executeOrdinarySingleton pe record state
  | some .x87Singleton => executeReplayOpcode25 pe schedule record state
  | none => none

def authoritativeStep (pe : PE32) (ordinary : OrdinaryStep)
    (record : RawInstructionRecord) (state : MachineState) : Option StepResult :=
  match record.decodeClass with
  | some .ordinary => ordinary record state
  | some .x87Singleton => executeX87Singleton pe record state
  | none => none

def interpreterStep (schedule : RawInstructionSchedule)
    (ordinary : OrdinaryStep) (replay : ReplayStep)
    (record : RawInstructionRecord) (state : MachineState) : Option StepResult :=
  match record.decodeClass with
  | some .ordinary => ordinary record state
  | some .x87Singleton => do
      let action <- replayActionFor schedule record
      replay action state
  | none => none

def scheduledAuthoritativeStep (pe : PE32) (ordinary : OrdinaryStep)
    (schedule : RawInstructionSchedule) (record : RawInstructionRecord)
    (state : MachineState) : Option StepResult :=
  if record ∈ schedule.records then authoritativeStep pe ordinary record state
  else none

def scheduledInterpreterStep (ordinary : OrdinaryStep) (replay : ReplayStep)
    (schedule : RawInstructionSchedule) (record : RawInstructionRecord)
    (state : MachineState) : Option StepResult :=
  if record ∈ schedule.records then
    interpreterStep schedule ordinary replay record state
  else none

def runRecords (step : RawInstructionRecord -> MachineState -> Option StepResult) :
    List RawInstructionRecord -> MachineState -> ExecutionTrace ->
      Option ScheduleResult
  | [], state, trace => some { state, trace }
  | record :: records, state, trace => do
      let result <- step record state
      let trace := trace.appendStep result
      if !result.faults.isEmpty then
        if records.isEmpty then some { state := result.state, trace } else none
      else match records with
      | [] => some { state := result.state, trace }
      | next :: _ =>
          match result.control with
          | .fallthrough target =>
              if target == next.span.start then
                runRecords step records result.state trace
              else none
          | .stop _ => none

def runAuthoritative (pe : PE32) (ordinary : OrdinaryStep)
    (schedule : RawInstructionSchedule) (state : MachineState) :
    Option ScheduleResult :=
  runRecords (scheduledAuthoritativeStep pe ordinary schedule)
    schedule.records state {}

def runInterpreter (ordinary : OrdinaryStep) (replay : ReplayStep)
    (schedule : RawInstructionSchedule) (state : MachineState) :
    Option ScheduleResult :=
  runRecords (scheduledInterpreterStep ordinary replay schedule)
    schedule.records state {}

structure InterpreterX87ScheduleCertificate (pe : PE32)
    (schedule : RawInstructionSchedule) (authoritativeOrdinary : OrdinaryStep)
    (interpreterOrdinary : OrdinaryStep) (replay : ReplayStep) : Prop where
  scheduleChecked : CheckedInstructionSchedule schedule pe
  ordinaryRefines : forall record, record ∈ schedule.records ->
    record.decodeClass = some .ordinary -> forall state,
      authoritativeOrdinary record state = interpreterOrdinary record state
  replayPresent : forall record, record ∈ schedule.records ->
    record.decodeClass = some .x87Singleton ->
      exists action, replayActionFor schedule record = some action
  replayRefines : forall record, record ∈ schedule.records ->
    record.decodeClass = some .x87Singleton -> forall action,
      replayActionFor schedule record = some action -> forall state,
        executeX87Singleton pe record state = replay action state

theorem InterpreterX87ScheduleCertificate.stepRefines
    {pe : PE32} {schedule : RawInstructionSchedule}
    {authoritativeOrdinary interpreterOrdinary : OrdinaryStep}
    {replay : ReplayStep}
    (certificate : InterpreterX87ScheduleCertificate pe schedule
      authoritativeOrdinary interpreterOrdinary replay)
    (record : RawInstructionRecord) (member : record ∈ schedule.records)
    (state : MachineState) :
    authoritativeStep pe authoritativeOrdinary record state =
      interpreterStep schedule interpreterOrdinary replay record state := by
  unfold authoritativeStep interpreterStep
  cases decoded : record.decodeClass with
  | none => rfl
  | some kind =>
      cases kind with
      | ordinary =>
          exact certificate.ordinaryRefines record member decoded state
      | x87Singleton =>
          cases actionFound : replayActionFor schedule record with
          | none =>
              rcases certificate.replayPresent record member decoded with
                ⟨action, present⟩
              rw [actionFound] at present
              contradiction
          | some action =>
              simpa [actionFound] using certificate.replayRefines record member
                decoded action actionFound state

theorem InterpreterX87ScheduleCertificate.scheduledStepRefines
    {pe : PE32} {schedule : RawInstructionSchedule}
    {authoritativeOrdinary interpreterOrdinary : OrdinaryStep}
    {replay : ReplayStep}
    (certificate : InterpreterX87ScheduleCertificate pe schedule
      authoritativeOrdinary interpreterOrdinary replay)
    (record : RawInstructionRecord) (state : MachineState) :
    scheduledAuthoritativeStep pe authoritativeOrdinary schedule record state =
      scheduledInterpreterStep interpreterOrdinary replay schedule record state := by
  unfold scheduledAuthoritativeStep scheduledInterpreterStep
  by_cases member : record ∈ schedule.records
  · simp only [member, if_true]
    exact certificate.stepRefines record member state
  · simp [member]

theorem runRecords_congr (records : List RawInstructionRecord)
    (left right : RawInstructionRecord -> MachineState -> Option StepResult)
    (agreement : forall record state, left record state = right record state)
    (state : MachineState) (trace : ExecutionTrace) :
    runRecords left records state trace = runRecords right records state trace := by
  have equal : left = right := by
    funext record input
    exact agreement record input
  subst right
  rfl

theorem InterpreterX87ScheduleCertificate.macroStepRefines
    {pe : PE32} {schedule : RawInstructionSchedule}
    {authoritativeOrdinary interpreterOrdinary : OrdinaryStep}
    {replay : ReplayStep}
    (certificate : InterpreterX87ScheduleCertificate pe schedule
      authoritativeOrdinary interpreterOrdinary replay)
    (state : MachineState) :
    runAuthoritative pe authoritativeOrdinary schedule state =
      runInterpreter interpreterOrdinary replay schedule state := by
  apply runRecords_congr
  intro record input
  exact certificate.scheduledStepRefines record input

/-- A proof-producing exact schedule bridge.  Unlike the compatibility
certificate above, it has no caller-supplied semantic refinement fields: every
ordinary record executes through the reviewed IA-32 semantics and every x87
record executes through checked opcode-25 replay. -/
structure ExactInterpreterX87ScheduleCertificate (pe : PE32)
    (schedule : RawInstructionSchedule) : Prop where
  scheduleChecked : CheckedInstructionSchedule schedule pe
  ordinaryExecutable : schedule.ordinaryExecutableChecked pe = true
  replayOpcode25 : schedule.replayOpcode25Checked = true

def runExactAuthoritative (pe : PE32) (schedule : RawInstructionSchedule)
    (state : MachineState) : Option ScheduleResult :=
  runRecords (scheduledAuthoritativeStep pe (executeOrdinarySingleton pe)
    schedule) schedule.records state {}

def runExactInterpreter (pe : PE32) (schedule : RawInstructionSchedule)
    (state : MachineState) : Option ScheduleResult :=
  runRecords (fun record input =>
    if record ∈ schedule.records then exactInterpreterStep pe schedule record input
    else none) schedule.records state {}

theorem ExactInterpreterX87ScheduleCertificate.stepRefines
    {pe : PE32} {schedule : RawInstructionSchedule}
    (certificate : ExactInterpreterX87ScheduleCertificate pe schedule)
    (record : RawInstructionRecord) (member : record ∈ schedule.records)
    (state : MachineState) :
    authoritativeStep pe (executeOrdinarySingleton pe) record state =
      exactInterpreterStep pe schedule record state := by
  have replayChecked :=
    List.all_eq_true.mp certificate.replayOpcode25 record member
  unfold authoritativeStep exactInterpreterStep
  cases decoded : record.decodeClass with
  | none => rfl
  | some kind =>
      cases kind with
      | ordinary => rfl
      | x87Singleton =>
          simp only [executeReplayOpcode25, replayChecked, if_true]

theorem ExactInterpreterX87ScheduleCertificate.macroStepRefines
    {pe : PE32} {schedule : RawInstructionSchedule}
    (certificate : ExactInterpreterX87ScheduleCertificate pe schedule)
    (state : MachineState) :
    runExactAuthoritative pe schedule state =
      runExactInterpreter pe schedule state := by
  apply runRecords_congr
  intro record input
  unfold scheduledAuthoritativeStep
  by_cases member : record ∈ schedule.records
  · simp only [member, if_true]
    exact certificate.stepRefines record member input
  · simp [member]

structure ExactInterpreterX87ScheduleWitness (pe : PE32) where
  schedule : RawInstructionSchedule
  certificate : ExactInterpreterX87ScheduleCertificate pe schedule

/-- One explicitly inventoried opcode-25 action and its exact original x87
record.  Keeping this witness separate from the schedule certificate gives
large generated proofs a deterministic, location-addressable replay unit. -/
structure ExactInterpreterX87ReplayActionWitness (pe : PE32) where
  schedule : RawInstructionSchedule
  certificate : ExactInterpreterX87ScheduleCertificate pe schedule
  record : RawInstructionRecord
  action : RawReplayAction
  recordMember : record ∈ schedule.records
  actionMember : action ∈ schedule.replayActions
  recordClass : record.decodeClass = some .x87Singleton
  actionFound : replayActionFor schedule record = some action

theorem ExactInterpreterX87ReplayActionWitness.stepRefines
    {pe : PE32} (witness : ExactInterpreterX87ReplayActionWitness pe)
    (state : MachineState) :
    executeX87Singleton pe witness.record state =
      executeReplayOpcode25 pe witness.schedule witness.record state := by
  have checked := List.all_eq_true.mp witness.certificate.replayOpcode25
    witness.record witness.recordMember
  simp [executeReplayOpcode25, checked]

/-! ## Candidate replay binding

The original schedule proof above is deliberately independent of the Stage B
binary.  The definitions below connect that proof to replay descriptors parsed
from the immutable candidate PE program table.  Metadata equality alone is not
accepted as execution refinement: the candidate replay handler must also prove
the same state transformer for every input state. -/

def checkedX87DecoderName : String :=
  "StageA.Relational.X87.decodeSingletonCommand"

def checkedX87ExecutorName : String :=
  "StageA.Relational.X87.executeSingletonCommand"

def rawX87ReplayMatchesAction (replay : RawX87Replay)
    (originalImageBase : Nat) (action : RawReplayAction) : Bool :=
  replay.imageBase == originalImageBase && replay.rvaStart == action.span.start &&
    replay.rvaEnd == action.span.stop && replay.instructionCount == 1 &&
    replay.instructionBytes == action.instructionBytes &&
    replay.instructionBytesSha256 == action.instructionBytesSha256 &&
    replay.transferInstructionBytesSha256 == action.transferBytesSha256 &&
    replay.contractSha256 == action.contractSha256 &&
    replay.checkedDecoder == checkedX87DecoderName &&
    replay.checkedExecutor == checkedX87ExecutorName

def RawAction.opcode25Index? (action : RawAction) : Option Nat :=
  if action.op != 25 || action.arity != 1 || action.aux != 0 then none else
  match action.args with
  | [index] => some index
  | _ => none

def opcode25Indices (actions : List RawAction) : Option (List Nat) :=
  (actions.filter fun action => action.op == 25).mapM RawAction.opcode25Index?

def CandidateReplayRecordChecked (originalPe : PE32)
    (schedule : RawInstructionSchedule) (entry : CompiledProgramRecord) : Bool :=
  entry.record.sourceRva == schedule.sourceRva &&
    entry.x87Replays.length == schedule.replayActions.length &&
    (List.zip entry.x87Replays schedule.replayActions).all
      (fun pair => rawX87ReplayMatchesAction pair.1 originalPe.imageBase pair.2) &&
    opcode25Indices entry.record.actions ==
      some (List.range schedule.replayActions.length)

def replayRecordFor (schedule : RawInstructionSchedule)
    (replay : RawX87Replay) : Option RawInstructionRecord :=
  schedule.records.find? fun record =>
    record.span.start == replay.rvaStart && record.span.stop == replay.rvaEnd

def expectedCandidateReplay (originalPe : PE32)
    (schedule : RawInstructionSchedule) (replay : RawX87Replay)
    (state : MachineState) : Option StepResult := do
  let record <- replayRecordFor schedule replay
  executeX87Singleton originalPe record state

abbrev CandidateReplayHandler :=
  RawX87Replay -> MachineState -> Option StepResult

abbrev CandidateReplayExecutionRelation :=
  RawX87Replay -> MachineState -> StepResult -> Prop

/-- Canonical instruction record used by the reviewed candidate replay
semantics.  Only the exact span and x87 class are consumed by
`executeX87Singleton`; descriptor hashes and bytes are checked separately by
`CandidateReplayRecordChecked` against the original schedule. -/
def replayInstructionRecord (replay : RawX87Replay) :
  RawInstructionRecord := {
  index := 0
  kind := 1
  span := { start := replay.rvaStart, size := replay.rvaEnd - replay.rvaStart }
  bytes := replay.instructionBytes
  bytesSha256 := replay.instructionBytesSha256
  canonicalBytes := []
  recordSha256 := ""
  transferBytesSha256 := replay.transferInstructionBytesSha256
}

def candidateReplayDescriptorForAction (originalPe : PE32)
    (action : RawReplayAction) : RawX87Replay := {
  imageBase := originalPe.imageBase
  rvaStart := action.span.start
  rvaEnd := action.span.stop
  instructionCount := 1
  instructionBytes := action.instructionBytes
  instructionBytesSha256 := action.instructionBytesSha256
  transferInstructionBytesSha256 := action.transferBytesSha256
  contractSha256 := action.contractSha256
  checkedDecoder := checkedX87DecoderName
  checkedExecutor := checkedX87ExecutorName
}

/-- Reviewed semantics for the candidate replay callback.  This is a Lean
state transformer only.  It does not assert that the compiled C/assembly
bridge implements the transformer; `CompiledNativeReplayBridgeRefines` below
keeps that separate theorem explicit. -/
def reviewedExpectedCandidateReplay (originalPe : PE32) :
    CandidateReplayHandler :=
  fun replay state =>
    executeX87Singleton originalPe (replayInstructionRecord replay) state

def decodedCandidateEntries
    (certificate : ProgramTableCertificate candidatePe imports relocations
      tableRva countRva semanticRecords) : List CompiledProgramRecord :=
  certificate.shards.flatMap fun shard => shard.entries

/-- The remaining native-code theorem.  `executes` must be instantiated by
the exact candidate-PE execution proof for the compiled replay bridge.  Merely
choosing `reviewedExpectedCandidateReplay` as a Lean handler cannot construct
this proposition.  The theorem is deliberately restricted to descriptors
decoded from the certified candidate table; malformed values outside that
closed execution surface are irrelevant to whole-program acceptance. -/
def CompiledNativeReplayBridgeRefines
    (table : ProgramTableCertificate candidatePe imports relocations tableRva
      countRva semanticRecords)
    (executes : CandidateReplayExecutionRelation)
    (handler : CandidateReplayHandler) : Prop :=
  forall entry, entry ∈ decodedCandidateEntries table ->
    forall replay, replay ∈ entry.x87Replays -> forall state result,
      executes replay state result <-> handler replay state = some result

/-- One candidate table entry is tied to an exact original schedule and its
native replay handler has the reviewed x87 semantics for every machine state. -/
structure ExactCandidateX87ReplayBinding (originalPe : PE32)
    (schedule : RawInstructionSchedule) (entry : CompiledProgramRecord)
    (handler : CandidateReplayHandler) : Prop where
  originalSchedule : ExactInterpreterX87ScheduleCertificate originalPe schedule
  candidateMetadata : CandidateReplayRecordChecked originalPe schedule entry = true
  handlerRefines : forall replay, replay ∈ entry.x87Replays -> forall state,
    handler replay state = expectedCandidateReplay originalPe schedule replay state

theorem ExactCandidateX87ReplayBinding.replayRefines
    {originalPe : PE32} {schedule : RawInstructionSchedule}
    {entry : CompiledProgramRecord} {handler : CandidateReplayHandler}
    (binding : ExactCandidateX87ReplayBinding originalPe schedule entry handler)
    (replay : RawX87Replay) (member : replay ∈ entry.x87Replays)
    (state : MachineState) :
    handler replay state = expectedCandidateReplay originalPe schedule replay state :=
  binding.handlerRefines replay member state

def replayBearingCandidateEntries (entries : List CompiledProgramRecord) :
    List CompiledProgramRecord :=
  entries.filter fun entry => !entry.x87Replays.isEmpty

/-- Acceptance-facing inventory for the candidate replay lane.  `complete`
prevents omission of an original x87 schedule; `exact` prevents an extra
candidate replay-bearing entry from escaping comparison.  Membership in
`decodedCandidateEntries` means every candidate descriptor came from the exact
candidate PE bytes through `ProgramTableCertificate`. -/
structure ExactCandidateX87ReplayInventory (originalPe candidatePe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (tableRva countRva : Nat) (semanticRecords : List ProgramRecord)
    (originalWitnesses : List (ExactInterpreterX87ScheduleWitness originalPe))
    (table : ProgramTableCertificate candidatePe imports relocations tableRva
      countRva semanticRecords) (handler : CandidateReplayHandler) : Prop where
  complete : forall witness, witness ∈ originalWitnesses ->
    exists entry, entry ∈ decodedCandidateEntries table ∧
      ExactCandidateX87ReplayBinding originalPe witness.schedule entry handler
  exact : forall entry, entry ∈ decodedCandidateEntries table ->
    entry.x87Replays.isEmpty = false -> exists witness,
      witness ∈ originalWitnesses ∧
      ExactCandidateX87ReplayBinding originalPe witness.schedule entry handler

/-- A cacheable local inventory.  Generated modules align these certificates
with candidate program-table shards, so metadata proofs do not import the full
candidate PE/table aggregate. -/
structure ExactCandidateX87ReplayShard (originalPe candidatePe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (tableRva : Nat) (handler : CandidateReplayHandler) where
  tableShard : ProgramTableShardCertificate candidatePe imports relocations tableRva
  originalWitnesses : List (ExactInterpreterX87ScheduleWitness originalPe)
  /-- Only replay-bearing entries are retained here.  The two coverage fields
  prove this is exactly the replay-bearing subset of `tableShard.entries`. -/
  candidateEntries : List CompiledProgramRecord
  candidateEntriesSound : forall entry, entry ∈ candidateEntries ->
    entry ∈ tableShard.entries
  candidateEntriesComplete : forall entry, entry ∈ tableShard.entries ->
    entry.x87Replays.isEmpty = false -> entry ∈ candidateEntries
  complete : forall witness, witness ∈ originalWitnesses ->
    exists entry, entry ∈ candidateEntries ∧
      ExactCandidateX87ReplayBinding originalPe witness.schedule entry handler
  exact : forall entry, entry ∈ candidateEntries ->
    entry.x87Replays.isEmpty = false -> exists witness,
      witness ∈ originalWitnesses ∧
      ExactCandidateX87ReplayBinding originalPe witness.schedule entry handler

def candidateReplayShardOriginalWitnesses
    (shards : List (ExactCandidateX87ReplayShard originalPe candidatePe imports
      relocations tableRva handler)) :
    List (ExactInterpreterX87ScheduleWitness originalPe) :=
  shards.flatMap (fun shard => shard.originalWitnesses)

def candidateReplayShardEntries
    (shards : List (ExactCandidateX87ReplayShard originalPe candidatePe imports
      relocations tableRva handler)) :
    List CompiledProgramRecord :=
  shards.flatMap (fun shard => shard.candidateEntries)

def candidateReplayTableShards
    (shards : List (ExactCandidateX87ReplayShard originalPe candidatePe imports
      relocations tableRva handler)) :
    List (ProgramTableShardCertificate candidatePe imports relocations tableRva) :=
  shards.map (fun shard => shard.tableShard)

/-- Compose local replay/table shards into the acceptance-facing exact
inventory.  The two equalities are the only aggregate proof work: every local
semantic binding remains cached in its own shard. -/
def ExactCandidateX87ReplayInventory.ofShards
    {originalPe candidatePe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation} {tableRva countRva : Nat}
    {semanticRecords : List ProgramRecord}
    {originalWitnesses : List (ExactInterpreterX87ScheduleWitness originalPe)}
    {table : ProgramTableCertificate candidatePe imports relocations tableRva
      countRva semanticRecords} {handler : CandidateReplayHandler}
    (shards : List (ExactCandidateX87ReplayShard originalPe candidatePe imports
      relocations tableRva handler))
    (originalExact : originalWitnesses =
      candidateReplayShardOriginalWitnesses shards)
    (tableShardsExact : candidateReplayTableShards shards = table.shards) :
    ExactCandidateX87ReplayInventory originalPe candidatePe imports relocations
      tableRva countRva semanticRecords originalWitnesses table handler := {
  complete := by
    intro witness member
    have flattened : witness ∈ candidateReplayShardOriginalWitnesses shards := by
      rw [← originalExact]
      exact member
    rcases List.mem_flatMap.mp flattened with
      ⟨shard, shardMember, localMember⟩
    rcases shard.complete witness localMember with
      ⟨entry, entryMember, binding⟩
    refine ⟨entry, ?_, binding⟩
    unfold decodedCandidateEntries
    rw [← tableShardsExact]
    apply List.mem_flatMap.mpr
    refine ⟨shard.tableShard, ?_, shard.candidateEntriesSound entry entryMember⟩
    exact List.mem_map.mpr ⟨shard, shardMember, rfl⟩
  exact := by
    intro entry member replayPresent
    unfold decodedCandidateEntries at member
    rw [← tableShardsExact] at member
    rcases List.mem_flatMap.mp member with
      ⟨tableShard, tableShardMember, entryMember⟩
    rcases List.mem_map.mp tableShardMember with
      ⟨shard, shardMember, shardMatches⟩
    subst tableShard
    have localMember := shard.candidateEntriesComplete entry entryMember replayPresent
    rcases shard.exact entry localMember replayPresent with
      ⟨witness, witnessMember, binding⟩
    refine ⟨witness, ?_, binding⟩
    rw [originalExact]
    exact List.mem_flatMap.mpr ⟨shard, shardMember, witnessMember⟩
}

end StageA.Relational.InterpreterX87
