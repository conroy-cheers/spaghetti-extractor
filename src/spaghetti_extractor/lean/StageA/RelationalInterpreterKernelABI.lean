import StageA.RelationalCertificates
import StageA.RelationalInterpreterKernel
import StageA.RelationalInterpreterKernelData
import StageA.RelationalInterpreterKernelLoadedImage

namespace StageA.Relational.InterpreterKernelABI

open StageA.Formal StageA.Relational
open StageA.Relational.Engine StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelData

/-! A concrete i386 cdecl ABI for the four compiled-interpreter operations.
Static data is accepted only after Lean has re-read the candidate PE, parsed
its imports and relocations, decoded the engine-layout table, checked the
kernel CFG, and decoded the semantic program table.  The predicates below are
definitions over those witnesses; no operation-simulation proposition is an
input to this module. -/

/-! The engine layout is decoded again from exact immutable candidate bytes.
The binary format has no alignment field, so byte alignment is the only fact
derived here; `EngineLayout.checked` separately proves bounds, widths,
required-field coverage, uniqueness, and non-overlap. -/

def decodeEngineRegister? : Nat -> Option Reg
  | 0 => some .eax | 1 => some .ebx | 2 => some .ecx | 3 => some .edx
  | 4 => some .esi | 5 => some .edi | 6 => some .ebp | 7 => some .esp
  | _ => none

def decodeEngineField? (kind index : Nat) : Option EngineField :=
  match kind with
  | 1 => (decodeEngineRegister? index).map EngineField.register
  | 2 => if index == 0 then some .eflags else none
  | 3 => if index < 32 then some (.flag index) else none
  | 4 => some (.x87Stack index)
  | 5 => if index == 0 then some .x87Control else none
  | 6 => if index == 0 then some .x87Status else none
  | 7 => if index == 0 then some .fsBase else none
  | 8 => if index == 0 then some .originalRva else none
  | 9 => some (.x87Empty index)
  | 10 => some (.x87Tag index)
  | 11 => if index == 0 then some .x87PendingException else none
  | 12 => if index == 0 then some .x87LastOpcode else none
  | 13 => if index == 0 then some .x87InstructionPointer else none
  | 14 => if index == 0 then some .x87CodeSelector else none
  | 15 => if index == 0 then some .x87DataPointer else none
  | 16 => if index == 0 then some .x87DataSelector else none
  | _ => none

def decodeEngineFields (bytes : Bytes) : Nat -> Nat ->
    Option (List EngineFieldLayout)
  | _, 0 => some []
  | wordIndex, count + 1 => do
      let kind <- readArrayU32 bytes wordIndex
      let index <- readArrayU32 bytes (wordIndex + 1)
      let offset <- readArrayU32 bytes (wordIndex + 2)
      let size <- readArrayU32 bytes (wordIndex + 3)
      let field <- decodeEngineField? kind index
      if size != field.byteWidth then none else
      let tail <- decodeEngineFields bytes (wordIndex + 4) count
      pure ({ field, offset, alignment := 1 } :: tail)

def decodeEngineLayoutBytes (bytes : Bytes) : Option EngineLayout := do
  let magic <- readArrayU32 bytes 0
  let version <- readArrayU32 bytes 1
  let totalWords <- readArrayU32 bytes 2
  let headerWords <- readArrayU32 bytes 3
  let recordWords <- readArrayU32 bytes 4
  let fieldCount <- readArrayU32 bytes 5
  let stateSize <- readArrayU32 bytes 6
  let x87Slots <- readArrayU32 bytes 7
  let features <- readArrayU32 bytes 8
  let reserved <- readArrayU32 bytes 9
  if magic != 0x4c454253 || version != 2 || headerWords != 10 ||
      recordWords != 4 || fieldCount == 0 || fieldCount > 64 ||
      totalWords != 10 + fieldCount * 4 || bytes.length != totalWords * 4 ||
      stateSize == 0 || x87Slots == 0 || x87Slots > 32 ||
      features &&& 0xfffffff0 != 0 || reserved != 0 then none else
  let fields <- decodeEngineFields bytes 10 fieldCount
  pure { stateSize, x87StackSlots := x87Slots, fields }

def decodeEngineLayoutAt (pe : PE32) (imports : List PEImport)
    (span : Span) : Option EngineLayout := do
  let bytes <- immutableRvaBytes pe imports span.start span.size
  decodeEngineLayoutBytes bytes

/-! Canonical exported signatures.  Offsets are measured from ESP at callee
entry and therefore include the hardware return word. -/

inductive CDeclResultShape where
  | eaxWord
  | hiddenStruct (words : Nat)
deriving Repr, DecidableEq

structure KernelCDeclLayout where
  operation : KernelOperation
  argumentOffsets : List Nat
  result : CDeclResultShape
  returnStackBytes : Nat
  preservedRegisters : List Reg
  framePointer : Bool
deriving Repr, DecidableEq

def cdeclPreserved : List Reg := [.ebx, .esi, .edi, .ebp]

def kernelCDeclLayout : KernelOperation -> KernelCDeclLayout
  | .programLookup => {
      operation := .programLookup
      argumentOffsets := [4]
      result := .eaxWord
      returnStackBytes := 4
      preservedRegisters := cdeclPreserved
      framePointer := true
    }
  | .interpreterStep => {
      operation := .interpreterStep
      argumentOffsets := [4, 8, 12, 16]
      result := .hiddenStruct 3
      returnStackBytes := 4
      preservedRegisters := cdeclPreserved
      framePointer := true
    }
  | .runFunction => {
      operation := .runFunction
      argumentOffsets := [4, 8, 12, 16]
      result := .eaxWord
      returnStackBytes := 4
      preservedRegisters := cdeclPreserved
      framePointer := true
    }
  | .invokeCall => {
      operation := .invokeCall
      argumentOffsets := [4, 8, 12, 16]
      result := .eaxWord
      returnStackBytes := 4
      preservedRegisters := cdeclPreserved
      framePointer := true
    }

def operationIndex : KernelOperation -> Nat
  | .programLookup => 0 | .interpreterStep => 1
  | .runFunction => 2 | .invokeCall => 3

structure KernelABIParameters where
  engineLayoutSpan : Span
  writableWorkspace : Span
  stackReserve : Nat
deriving Repr, DecidableEq

def KernelABIParameters.fixedBytes (parameters : KernelABIParameters)
    (layout : EngineLayout) : Nat :=
  64 + layout.stateSize * 2 + 52 + 12

def KernelABIParameters.requiredBytes (parameters : KernelABIParameters)
    (layout : EngineLayout) : Nat :=
  parameters.fixedBytes layout + 4 * parameters.stackReserve

def KernelABIParameters.runtimeAddress (parameters : KernelABIParameters) : Word :=
  word32 parameters.writableWorkspace.start

def KernelABIParameters.inputAddress (parameters : KernelABIParameters) : Word :=
  word32 (parameters.writableWorkspace.start + 64)

def KernelABIParameters.outputAddress (parameters : KernelABIParameters)
    (layout : EngineLayout) : Word :=
  word32 (parameters.writableWorkspace.start + 64 + layout.stateSize)

def KernelABIParameters.eventAddress (parameters : KernelABIParameters)
    (layout : EngineLayout) : Word :=
  word32 (parameters.writableWorkspace.start + 64 + 2 * layout.stateSize)

def KernelABIParameters.resultAddress (parameters : KernelABIParameters)
    (layout : EngineLayout) : Word :=
  parameters.eventAddress layout + word32 52

def KernelABIParameters.stackStart (parameters : KernelABIParameters)
    (layout : EngineLayout) (operation : KernelOperation) : Nat :=
  parameters.writableWorkspace.start + parameters.fixedBytes layout +
    operationIndex operation * parameters.stackReserve

def KernelABIParameters.entryEsp (parameters : KernelABIParameters)
    (layout : EngineLayout) (operation : KernelOperation) : Word :=
  word32 (parameters.stackStart layout operation + parameters.stackReserve - 20)

def KernelABIParameters.returnAddress (parameters : KernelABIParameters)
    (pe : PE32) : Word :=
  word32 (pe.imageBase + pe.entrypointRva)

def requiredFunctionsHaveFrames (program : CompiledKernelProgram) : Bool :=
  program.functions.all fun function =>
    !function.role.required || function.frame.required

def KernelABIParameters.checked (parameters : KernelABIParameters)
    (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (program : CompiledKernelProgram)
    (layout : EngineLayout) (tableOffset countOffset transferCount : Nat) : Bool :=
  parseImports pe == some imports &&
    parseRelocations pe == some relocations &&
    relocationLayoutChecked pe relocations &&
    program.checked pe imports && requiredFunctionsHaveFrames program &&
    layout.checked &&
    decodeEngineLayoutAt pe imports parameters.engineLayoutSpan == some layout &&
    pe.imageBase + pe.sizeOfImage <= 2 ^ 32 &&
    executableRva pe pe.entrypointRva &&
    parameters.writableWorkspace.start % 16 == 0 &&
    parameters.stackReserve >= 4096 &&
    parameters.requiredBytes layout <= parameters.writableWorkspace.size &&
    parameters.writableWorkspace.stop <= 2 ^ 32 &&
    spanDisjoint parameters.writableWorkspace
      { start := pe.imageBase, size := pe.sizeOfImage } &&
    tableOffset % 4 == 0 && countOffset % 4 == 0 &&
    tableOffset + transferCount * transferRecordSize <= pe.sizeOfImage &&
    countOffset + 4 <= pe.sizeOfImage

structure ConcreteKernelABI
    (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableOffset countOffset : Nat)
    (semanticRecords : List ProgramRecord) where
  program : CompiledKernelProgram
  engineLayout : EngineLayout
  parameters : KernelABIParameters
  tableCertificate : ProgramTableCertificate pe imports relocations
    tableOffset countOffset semanticRecords
  staticChecked : parameters.checked pe imports relocations program engineLayout
    tableOffset countOffset tableCertificate.transferCount = true

def ConcreteKernelABI.tableSpan
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records) :
    Span :=
  { start := tableOffset,
    size := abi.tableCertificate.transferCount * transferRecordSize }

def ConcreteKernelABI.countSpan
    (_abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records) :
    Span :=
  { start := countOffset, size := 4 }

theorem shardCoverageEnd_exactLength
    (shards : List (ProgramTableShardCertificate pe imports relocations tableOffset))
    (cursor transferCount : Nat)
    (covered : shardCoverageEnd cursor shards = some transferCount) :
    transferCount = cursor + (decodedShardRecords shards).length := by
  induction shards generalizing cursor with
  | nil =>
      have exact := Option.some.inj covered.symm
      simpa [decodedShardRecords] using exact
  | cons shard tail induction =>
      simp only [shardCoverageEnd] at covered
      split at covered
      · contradiction
      · have tailExact := induction (cursor + shard.entries.length) covered
        simpa [decodedShardRecords, ProgramTableShardCertificate.records,
          Nat.add_assoc] using tailExact

theorem programTableCertificate_transferCount_eq_records_length
    (certificate : ProgramTableCertificate pe imports relocations tableOffset
      countOffset records) :
    certificate.transferCount = records.length := by
  have exactLength := shardCoverageEnd_exactLength certificate.shards 0
    certificate.transferCount certificate.shardsCover
  calc
    certificate.transferCount = (decodedShardRecords certificate.shards).length := by
      simpa using exactLength
    _ = records.length :=
      (congrArg List.length certificate.semanticRecordsExact).symm

structure LoadedOriginalProgramTable
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records)
    (memory : Memory) : Prop where
  tableSpan : LoadedSpanHolds pe relocations pe.imageBase abi.tableSpan memory
  countSpan : LoadedSpanHolds pe relocations pe.imageBase abi.countSpan memory
  countWord :
    Memory.read32 memory (word32 (pe.imageBase + countOffset)) =
      word32 abi.tableCertificate.transferCount
  sourceWords : forall index record,
    records[index]? = some record ->
      Memory.read32 memory
          (word32 (pe.imageBase + tableOffset + index * transferRecordSize)) =
        word32 record.sourceRva

/-! Concrete engine representation at the pointer passed through cdecl.  The
interpreter's architectural memory is serviced by runtime callbacks, so it is
not aliased into the engine allocation.  Code/data metadata addresses retain
their exact 32-bit values through the identity maps. -/

def engineRepAt (layout : EngineLayout) (base : Word)
    (semantics : StageA.X87.Semantics) : EngineRep := {
  layout
  engineBase := base
  memoryAddress := fun _ => none
  codeAddress := fun address => some address
  dataAddress := fun address => some address
  x87Semantics := semantics
}

def EngineStateHolds (layout : EngineLayout) (base : Word)
    (logical : InterpreterMachine) (sourceOffset : Nat)
    (candidate : MachineState) : Prop :=
  ∃ original,
    InterpreterMachineMatches logical original ∧
      StateRelated (engineRepAt layout base original.x87Semantics)
        (fun expected actual : Nat => expected = actual)
        sourceOffset sourceOffset original candidate

def OriginalEngineStateHolds (layout : EngineLayout) (base : Word)
    (sourceOffset : Nat) (original candidate : MachineState) : Prop :=
  StateRelated (engineRepAt layout base original.x87Semantics)
    (fun expected actual : Nat => expected = actual)
    sourceOffset sourceOffset original candidate

def WordsAt (memory : Memory) : Word -> List Word -> Prop
  | _, [] => True
  | address, value :: tail =>
      Memory.read32 memory address = value ∧
        WordsAt memory (address + word32 4) tail

def BytesAt (memory : Memory) : Word -> List (BitVec 8) -> Prop
  | _, [] => True
  | address, value :: tail =>
      memory address = value ∧ BytesAt memory (address + word32 1) tail

def asciiBytes (value : String) : List (BitVec 8) :=
  value.toList.map fun character => byte8 character.toNat

def CStringAt (memory : Memory) (address : Word) (value : String) : Prop :=
  BytesAt memory address (asciiBytes value ++ [byte8 0]) ∧
    ∀ character ∈ value.toList, character.toNat < 128

def callKindWord : CallKind -> Word
  | .external => word32 0 | .internal => word32 1 | .indirect => word32 2

def optionalCStringAt (workspace : Span) (memory : Memory)
    (pointer : Word) : Option String -> Prop
  | none => pointer = word32 0
  | some value =>
      pointer != word32 0 ∧
        addressRangeInSpan workspace pointer (value.toList.length + 1) ∧
        CStringAt memory pointer value

def optionalOrdinalWord : Option Nat -> Word × Word
  | none => (word32 0, word32 0)
  | some ordinal => (word32 ordinal, word32 1)

def stackInputWords (input : Nat × MemoryWidth × Word) : List Word :=
  [word32 input.1, word32 input.2.1.bytes, input.2.2]

def StackInputsAt (memory : Memory) : Word ->
    List (Nat × MemoryWidth × Word) -> Prop
  | _, [] => True
  | address, input :: tail =>
      WordsAt memory address (stackInputWords input) ∧
        StackInputsAt memory (address + word32 12) tail

def wordArrayAt (workspace : Span) (memory : Memory)
    (pointer : Word) (values : List Word) : Prop :=
  match values with
  | [] => pointer = word32 0
  | _ => pointer != word32 0 ∧
      addressRangeInSpan workspace pointer (values.length * 4) ∧
      WordsAt memory pointer values

def stackInputArrayAt (workspace : Span) (memory : Memory)
    (pointer : Word) (values : List (Nat × MemoryWidth × Word)) : Prop :=
  match values with
  | [] => pointer = word32 0
  | _ => pointer != word32 0 ∧
      addressRangeInSpan workspace pointer (values.length * 12) ∧
      StackInputsAt memory pointer values

def CallEventMemoryHolds (workspace : Span) (memory : Memory)
    (address : Word) (event : CallEvent) : Prop :=
  let dllPointer := Memory.read32 memory (address + word32 20)
  let symbolPointer := Memory.read32 memory (address + word32 24)
  let argumentPointer := Memory.read32 memory (address + word32 36)
  let stackPointer := Memory.read32 memory (address + word32 44)
  let ordinal := optionalOrdinalWord event.ordinal
  addressRangeInSpan workspace address 52 ∧
    Memory.read32 memory address = callKindWord event.kind ∧
    Memory.read32 memory (address + word32 4) = word32 event.instructionRva ∧
    Memory.read32 memory (address + word32 8) = word32 event.callIndex ∧
    Memory.read32 memory (address + word32 12) = event.targetRva ∧
    Memory.read32 memory (address + word32 16) = word32 event.returnRva ∧
    optionalCStringAt workspace memory dllPointer event.dll ∧
    optionalCStringAt workspace memory symbolPointer event.symbol ∧
    Memory.read32 memory (address + word32 28) = ordinal.1 ∧
    Memory.read32 memory (address + word32 32) = ordinal.2 ∧
    Memory.read32 memory (address + word32 40) = word32 event.arguments.length ∧
    wordArrayAt workspace memory argumentPointer event.arguments ∧
    Memory.read32 memory (address + word32 48) = word32 event.stackInputs.length ∧
    stackInputArrayAt workspace memory stackPointer event.stackInputs

def requestArguments
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records) :
    AbstractKernelRequest -> List Word
  | .programLookup _ sourceOffset => [word32 sourceOffset]
  | .interpreterStep _ _ sourceOffset _ =>
      [abi.parameters.resultAddress abi.engineLayout,
        abi.parameters.runtimeAddress,
        abi.parameters.inputAddress,
        word32 sourceOffset]
  | .runFunction _ _ _ sourceOffset _ =>
      [abi.parameters.runtimeAddress, word32 sourceOffset,
        abi.parameters.inputAddress,
        abi.parameters.outputAddress abi.engineLayout]
  | .invokeCall .. =>
      [abi.parameters.runtimeAddress,
        abi.parameters.eventAddress abi.engineLayout,
        abi.parameters.inputAddress,
        abi.parameters.outputAddress abi.engineLayout]

def preservedRegistersAreCanonical (state : MachineState) : Prop :=
  state.registers.ebx = word32 0 ∧ state.registers.esi = word32 0 ∧
    state.registers.edi = word32 0 ∧ state.registers.ebp = word32 0

def DirectionFlagClear (state : MachineState) : Prop :=
  state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0

def CDeclEntryFrameHolds
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records)
    (request : AbstractKernelRequest) (state : MachineState) : Prop :=
  let operation := request.operation
  let esp := abi.parameters.entryEsp abi.engineLayout operation
  state.registers.esp = esp ∧ preservedRegistersAreCanonical state ∧
    WordsAt state.memory esp
      (abi.parameters.returnAddress pe :: requestArguments abi request) ∧
    addressRangeInSpan abi.parameters.writableWorkspace
      (word32 (abi.parameters.stackStart abi.engineLayout operation))
      abi.parameters.stackReserve

def CDeclReturnFrameHolds
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records)
    (request : AbstractKernelRequest) (state : MachineState) : Prop :=
  let operation := request.operation
  let entryEsp := abi.parameters.entryEsp abi.engineLayout operation
  state.registers.esp = entryEsp + word32 4 ∧
    preservedRegistersAreCanonical state ∧
    WordsAt state.memory entryEsp
      (abi.parameters.returnAddress pe :: requestArguments abi request)

def RequestPayloadHolds
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records) :
    AbstractKernelRequest -> MachineState -> Prop
  | .programLookup requestRecords sourceOffset, _ =>
      requestRecords = records ∧ sourceOffset < 2 ^ 32
  | .interpreterStep requestRecords _ sourceOffset logical, state =>
      requestRecords = records ∧ sourceOffset < 2 ^ 32 ∧
        EngineStateHolds abi.engineLayout abi.parameters.inputAddress
          logical sourceOffset state
  | .runFunction requestRecords _ _ sourceOffset logical, state =>
      requestRecords = records ∧ sourceOffset < 2 ^ 32 ∧
        EngineStateHolds abi.engineLayout abi.parameters.inputAddress
          logical sourceOffset state
  | .invokeCall requestRecords _ _ event logical, state =>
      requestRecords = records ∧
        EngineStateHolds abi.engineLayout abi.parameters.inputAddress
          logical event.targetRva.toNat state ∧
        CallEventMemoryHolds abi.parameters.writableWorkspace state.memory
          (abi.parameters.eventAddress abi.engineLayout) event

structure ABIRequestFacts
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records)
    (request : AbstractKernelRequest) (state : MachineState) : Prop where
  cdecl : CDeclEntryFrameHolds abi request state
  directionFlagClear : DirectionFlagClear state
  candidateImage : LoadedCandidateImageMemory pe imports relocations state.memory
  originalProgramTable : LoadedOriginalProgramTable abi state.memory
  payload : RequestPayloadHolds abi request state

def completionWords : Completion -> List Word
  | .fallthrough target => [word32 0, word32 target, word32 0]
  | .jump target => [word32 1, word32 target, word32 0]
  | .branch target => [word32 2, word32 target, word32 0]
  | .returned value => [word32 3, word32 0, value]
  | .indirectJump target => [word32 4, word32 0, target]
  | .divideError => [word32 5, word32 0, word32 0]
  | .memoryFault => [word32 6, word32 0, word32 0]
  | .unimplemented => [word32 7, word32 0, word32 0]
  | .externalFault => [word32 8, word32 0, word32 0]
  | .externalJump => [word32 9, word32 0, word32 0]

def stepResultWords : Option MacroResult -> List Word
  | none => [word32 7, word32 0, word32 0]
  | some result => completionWords result.completion

def callStatusWord : CallStatus -> Word
  | .ok => word32 0 | .unimplemented => word32 1
  | .divideError => word32 2 | .memoryFault => word32 3
  | .externalFault => word32 4

def stringBytes (value : String) : Bytes :=
  value.toList.map Char.toNat

def ImportMatchesCallEvent (imported : PEImport) (event : CallEvent) : Prop :=
  event.kind = .external ∧
    (∃ dll, event.dll = some dll ∧ imported.dll = stringBytes dll) ∧
    match event.ordinal with
    | some ordinal => imported.name = .ordinal ordinal
    | none => ∃ symbol, event.symbol = some symbol ∧
        imported.name = .symbol (stringBytes symbol)

def NativeExternalEventShape (event : CallEvent)
    (native : NativeExternalEvent) : Prop :=
  ImportMatchesCallEvent native.imported event ∧
    native.arguments = event.arguments

def externalCallEvent? : InterpreterEvent -> Option CallEvent
  | .call event => if event.kind == .external then some event else none
  | _ => none

def externalCallEvents (events : List InterpreterEvent) : List CallEvent :=
  events.filterMap externalCallEvent?

def NativeEventListShape : List CallEvent -> List NativeExternalEvent -> Prop
  | [], [] => True
  | event :: eventTail, native :: nativeTail =>
      NativeExternalEventShape event native ∧
        NativeEventListShape eventTail nativeTail
  | _, _ => False

def programRecordPointer (records : List ProgramRecord) (imageBase tableOffset : Nat) :
    Nat -> Nat -> Word
  | _, 0 => word32 0
  | sourceOffset, fuel + 1 =>
      let index := records.length - (fuel + 1)
      match records[index]? with
      | some record =>
          if record.sourceRva == sourceOffset then
            word32 (imageBase + tableOffset + index * transferRecordSize)
          else programRecordPointer records imageBase tableOffset sourceOffset fuel
      | none => word32 0

def lookupResultPointer (records : List ProgramRecord)
    (imageBase tableOffset sourceOffset : Nat) : Word :=
  programRecordPointer records imageBase tableOffset sourceOffset records.length

def ResponsePayloadHolds
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records) :
    AbstractKernelRequest -> AbstractKernelResponse -> MachineState ->
      List NativeExternalEvent -> Prop
  | .programLookup _ sourceOffset, .programLookup _, state, nativeEvents =>
      state.registers.eax =
          lookupResultPointer records pe.imageBase tableOffset sourceOffset ∧
        nativeEvents = []
  | .interpreterStep _ _ sourceOffset _, .interpreterStep result,
      state, nativeEvents =>
      state.registers.eax = abi.parameters.resultAddress abi.engineLayout ∧
        WordsAt state.memory (abi.parameters.resultAddress abi.engineLayout)
          (stepResultWords result) ∧
        match result with
        | none => nativeEvents = []
        | some macroResult =>
            EngineStateHolds abi.engineLayout abi.parameters.inputAddress
              macroResult.state sourceOffset state ∧
            NativeEventListShape (externalCallEvents macroResult.events) nativeEvents
  | .runFunction _ _ _ sourceOffset _, .call result, state, nativeEvents =>
      state.registers.eax = callStatusWord result.status ∧
        EngineStateHolds abi.engineLayout
          (abi.parameters.outputAddress abi.engineLayout)
          result.state sourceOffset state ∧ nativeEvents = []
  | .invokeCall _ _ _ event _, .call result, state, nativeEvents =>
      state.registers.eax = callStatusWord result.status ∧
        EngineStateHolds abi.engineLayout
          (abi.parameters.outputAddress abi.engineLayout)
          result.state event.targetRva.toNat state ∧
        if event.kind == .external then
          ∃ native, nativeEvents = [native] ∧ NativeExternalEventShape event native
        else nativeEvents = []
  | _, _, _, _ => False

structure ABIResponseFacts
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (state : MachineState) (events : List NativeExternalEvent) : Prop where
  cdecl : CDeclReturnFrameHolds abi request state
  directionFlagClear : DirectionFlagClear state
  candidateImage : LoadedCandidateImageMemory pe imports relocations state.memory
  originalProgramTable : LoadedOriginalProgramTable abi state.memory
  payload : ResponsePayloadHolds abi request response state events

def ConcreteKernelABI.scratchFootprint
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records)
    (_request : AbstractKernelRequest) : CandidateFootprint :=
  addressInSpan abi.parameters.writableWorkspace

/-- The concrete relation exported to the existing kernel refinement surface.
Every field is computed from checked static data and canonical cdecl shapes. -/
def ConcreteKernelABI.relation
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records) :
    KernelABIRelation := {
  requestRelated := ABIRequestFacts abi
  responseRelated := ABIResponseFacts abi
  scratchFootprint := abi.scratchFootprint
}

def buildConcreteKernelABI?
    (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableOffset countOffset : Nat)
    (records : List ProgramRecord) (program : CompiledKernelProgram)
    (layout : EngineLayout) (parameters : KernelABIParameters)
    (tableCertificate : ProgramTableCertificate pe imports relocations
      tableOffset countOffset records) :
    Option (ConcreteKernelABI pe imports relocations tableOffset countOffset records) :=
  if checked : parameters.checked pe imports relocations program layout
      tableOffset countOffset tableCertificate.transferCount = true then
    some (ConcreteKernelABI.mk program layout parameters tableCertificate checked)
  else none

/-! Heterogeneous launch support.  This relation does not compare original
and candidate machines with the legacy product-machine state relation.  It
projects the original machine into the semantic interpreter request, proves
that exact original state is represented in the candidate engine allocation,
and independently retains the relational world and loaded candidate image. -/

def semanticMachine (state : MachineState) : InterpreterMachine := {
  registers := fun register =>
    match register with
    | .eax => state.registers.eax | .ebx => state.registers.ebx
    | .ecx => state.registers.ecx | .edx => state.registers.edx
    | .esi => state.registers.esi | .edi => state.registers.edi
    | .ebp => state.registers.ebp | .esp => state.registers.esp
  flags := fun flag => BitVec.zeroExtend 32
    (state.eflags.extractLsb' flag.eflagsBit 1)
  memory := state.memory
  eflags := state.eflags
}

theorem semanticMachine_matches (state : MachineState) :
    InterpreterMachineMatches (semanticMachine state) state := by
  constructor
  · intro register
    cases register <;> rfl
  constructor
  · rfl
  constructor
  · rfl
  · intro flag
    rfl

def RequestUsesOriginalMachine (records : List ProgramRecord)
    (original : MachineState) : AbstractKernelRequest -> Prop
  | .programLookup .. => False
  | .interpreterStep requestRecords _ _ logical =>
      requestRecords = records ∧ logical = semanticMachine original
  | .runFunction requestRecords _ _ _ logical =>
      requestRecords = records ∧ logical = semanticMachine original
  | .invokeCall requestRecords _ _ _ logical =>
      requestRecords = records ∧ logical = semanticMachine original

def OriginalRequestEngineHolds
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records)
    (request : AbstractKernelRequest) (original candidate : MachineState) : Prop :=
  match request with
  | .programLookup .. => False
  | .interpreterStep _ _ sourceOffset _ =>
      OriginalEngineStateHolds abi.engineLayout abi.parameters.inputAddress
        sourceOffset original candidate
  | .runFunction _ _ _ sourceOffset _ =>
      OriginalEngineStateHolds abi.engineLayout abi.parameters.inputAddress
        sourceOffset original candidate
  | .invokeCall _ _ _ event _ =>
      OriginalEngineStateHolds abi.engineLayout abi.parameters.inputAddress
        event.targetRva.toNat original candidate

structure CompiledInterpreterMixedLaunchRelation
    (context : StaticProofContext)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records)
    (request : AbstractKernelRequest) (world : RelationalWorld)
    (original candidate : MachineState) : Prop where
  candidatePE : pe = context.candidatePe
  candidateImports : imports = context.candidateImports
  worldValid : PE32ConsoleLaunchWorldV1.Valid context world
  semanticRequest : RequestUsesOriginalMachine records original request
  abiEntry : ABIRequestFacts abi request candidate
  exactOriginalEngine : OriginalRequestEngineHolds abi request original candidate

theorem CompiledInterpreterMixedLaunchRelation.requestRelated
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation} {tableOffset countOffset : Nat}
    {records : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records}
    {request : AbstractKernelRequest} {world : RelationalWorld}
    {original candidate : MachineState} {context : StaticProofContext}
    (launch : CompiledInterpreterMixedLaunchRelation context abi request world
      original candidate) :
    (ConcreteKernelABI.relation abi).requestRelated request candidate :=
  launch.abiEntry

theorem CompiledInterpreterMixedLaunchRelation.loadedOriginalProgramTable
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation} {tableOffset countOffset : Nat}
    {records : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records}
    {request : AbstractKernelRequest} {world : RelationalWorld}
    {original candidate : MachineState} {context : StaticProofContext}
    (launch : CompiledInterpreterMixedLaunchRelation context abi request world
      original candidate) :
    LoadedOriginalProgramTable abi candidate.memory :=
  launch.abiEntry.originalProgramTable

theorem CompiledInterpreterMixedLaunchRelation.loadedCandidateImage
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation} {tableOffset countOffset : Nat}
    {records : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records}
    {request : AbstractKernelRequest} {world : RelationalWorld}
    {original candidate : MachineState} {context : StaticProofContext}
    (launch : CompiledInterpreterMixedLaunchRelation context abi request world
      original candidate) :
    LoadedCandidateImageMemory pe imports relocations candidate.memory :=
  launch.abiEntry.candidateImage

theorem CompiledInterpreterMixedLaunchRelation.originalStateRepresented
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation} {tableOffset countOffset : Nat}
    {records : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset records}
    {request : AbstractKernelRequest} {world : RelationalWorld}
    {original candidate : MachineState} {context : StaticProofContext}
    (launch : CompiledInterpreterMixedLaunchRelation context abi request world
      original candidate) :
    OriginalRequestEngineHolds abi request original candidate :=
  launch.exactOriginalEngine

#print axioms semanticMachine_matches
#print axioms shardCoverageEnd_exactLength
#print axioms programTableCertificate_transferCount_eq_records_length
#print axioms CompiledInterpreterMixedLaunchRelation.requestRelated
#print axioms CompiledInterpreterMixedLaunchRelation.loadedOriginalProgramTable
#print axioms CompiledInterpreterMixedLaunchRelation.loadedCandidateImage
#print axioms CompiledInterpreterMixedLaunchRelation.originalStateRepresented

end StageA.Relational.InterpreterKernelABI
