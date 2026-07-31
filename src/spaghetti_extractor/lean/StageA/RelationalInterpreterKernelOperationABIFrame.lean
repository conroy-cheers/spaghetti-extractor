import StageA.RelationalInterpreterKernelABI
import StageA.RelationalInterpreterKernelSummary

namespace StageA.Relational.InterpreterKernelOperationABIFrame

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelSummary

/-!
# Per-call native ABI frames

`ConcreteKernelABI.relation` describes the canonical top-level launch frame.
Nested kernel operations use caller-owned stack locals for their state, event,
and result arguments.  Reusing the launch relation for those calls makes real
compiled call trees uninhabitable.

This module keeps every concrete address explicit and constructs a fixed
`KernelABIRelation` for one call.  The relation is still over flat machine
memory.  A frame is proof data, not a runtime object model, and all writable
addresses remain inside the statically checked workspace.
-/

structure KernelOperationABIFrame where
  operation : KernelOperation
  entryEsp : Word
  returnAddress : Word
  preservedEbx : Word
  preservedEsi : Word
  preservedEdi : Word
  preservedEbp : Word
  runtimeAddress : Word
  inputAddress : Word
  outputAddress : Word
  eventAddress : Word
  resultAddress : Word
  stackSpan : Span
deriving Repr, DecidableEq

/-- The finite stack interval touched by one compiled operation, measured
relative to its cdecl entry ESP.  This is generated from exact instruction
effects; it is not part of the abstract operation semantics. -/
structure KernelOperationABIStackUse where
  belowEntry : Nat
  atOrAboveEntry : Nat
deriving Repr, DecidableEq

/-- A checked operation stack interval must be non-wrapping and contained in
both the caller-owned stack reservation and the ABI writable workspace. -/
def KernelOperationABIStackUse.Fits
    (use : KernelOperationABIStackUse)
    (frame : KernelOperationABIFrame) (workspace : Span) : Prop :=
  use.belowEntry <= frame.entryEsp.toNat ∧
    frame.entryEsp.toNat + use.atOrAboveEntry <= 2 ^ 32 ∧
    addressRangeInSpan frame.stackSpan
      (frame.entryEsp - word32 use.belowEntry)
      (use.belowEntry + use.atOrAboveEntry) ∧
    addressRangeInSpan workspace
      (frame.entryEsp - word32 use.belowEntry)
      (use.belowEntry + use.atOrAboveEntry)

theorem KernelOperationABIStackUse.Fits.addressToNat
    (use : KernelOperationABIStackUse)
    (frame : KernelOperationABIFrame)
    (workspace : Span)
    (fits : use.Fits frame workspace)
    (offset : Nat)
    (offsetBefore : offset < use.belowEntry + use.atOrAboveEntry) :
    ((frame.entryEsp - word32 use.belowEntry) + word32 offset).toNat =
      frame.entryEsp.toNat - use.belowEntry + offset := by
  rcases fits with
    ⟨belowEntry, upperDoesNotWrap, _stackRange, _workspaceRange⟩
  have entryBound : frame.entryEsp.toNat < 2 ^ 32 :=
    frame.entryEsp.isLt
  have belowBound : use.belowEntry < 2 ^ 32 :=
    by omega
  have offsetBound : offset < 2 ^ 32 := by
    have totalBound :
        use.belowEntry + use.atOrAboveEntry <= 2 ^ 32 := by
      omega
    omega
  have belowWord :
      (word32 use.belowEntry).toNat = use.belowEntry := by
    simp [word32, BitVec.toNat_ofNat, Nat.mod_eq_of_lt belowBound]
  have offsetWord : (word32 offset).toNat = offset := by
    simp [word32, BitVec.toNat_ofNat, Nat.mod_eq_of_lt offsetBound]
  have belowWordLe : word32 use.belowEntry <= frame.entryEsp := by
    rw [BitVec.le_def, belowWord]
    exact belowEntry
  have noWrap :
      frame.entryEsp.toNat - use.belowEntry + offset < 2 ^ 32 := by
    omega
  rw [BitVec.toNat_add, BitVec.toNat_sub_of_le belowWordLe, belowWord,
    offsetWord]
  exact Nat.mod_eq_of_lt noWrap

theorem KernelOperationABIStackUse.Fits.addressBytesFit
    (use : KernelOperationABIStackUse)
    (frame : KernelOperationABIFrame)
    (workspace : Span)
    (fits : use.Fits frame workspace)
    (offset size : Nat)
    (inside : offset + size <= use.belowEntry + use.atOrAboveEntry) :
    ((frame.entryEsp - word32 use.belowEntry) + word32 offset).toNat +
        size <=
      2 ^ 32 := by
  by_cases sizeZero : size = 0
  · subst size
    have bounded :=
      ((frame.entryEsp - word32 use.belowEntry) + word32 offset).isLt
    simp only [Nat.add_zero]
    omega
  have offsetBefore :
      offset < use.belowEntry + use.atOrAboveEntry := by
    omega
  rw [fits.addressToNat use frame workspace offset offsetBefore]
  rcases fits with
    ⟨belowEntry, upperDoesNotWrap, _stackRange, _workspaceRange⟩
  omega

theorem KernelOperationABIStackUse.Fits.addressRangeInWorkspace
    (use : KernelOperationABIStackUse)
    (frame : KernelOperationABIFrame)
    (workspace : Span)
    (fits : use.Fits frame workspace)
    (offset size : Nat)
    (inside : offset + size <= use.belowEntry + use.atOrAboveEntry) :
    addressRangeInSpan workspace
      ((frame.entryEsp - word32 use.belowEntry) + word32 offset) size := by
  intro inner innerBefore
  have combinedBefore :
      offset + inner < use.belowEntry + use.atOrAboveEntry := by
    omega
  have combined :=
    fits.2.2.2 (offset + inner) combinedBefore
  simpa [BitVec.add_assoc, word32, ← BitVec.ofNat_add, Nat.add_assoc] using
    combined

def KernelOperationABIFrame.Valid
    (frame : KernelOperationABIFrame)
    (workspace : Span)
    (layout : StageA.Relational.Engine.EngineLayout) : Prop :=
  addressRangeInSpan workspace frame.entryEsp
      (4 * (kernelCDeclLayout frame.operation).argumentOffsets.length + 4) ∧
    addressRangeInSpan workspace (word32 frame.stackSpan.start)
      frame.stackSpan.size ∧
    frame.stackSpan.size >= 20 ∧
    match frame.operation with
    | .programLookup =>
        20 <= frame.entryEsp.toNat ∧
          ∀ address,
            programLookupFrameFootprint frame.entryEsp address ->
              addressInSpan workspace address
    | .interpreterStep =>
        addressRangeInSpan workspace frame.runtimeAddress 4 ∧
        addressRangeInSpan workspace frame.inputAddress
          (StageA.Relational.Engine.EngineLayout.stateSize layout) ∧
        addressRangeInSpan workspace frame.resultAddress 12
    | .runFunction =>
        addressRangeInSpan workspace frame.runtimeAddress 4 ∧
        addressRangeInSpan workspace frame.inputAddress
          (StageA.Relational.Engine.EngineLayout.stateSize layout) ∧
        addressRangeInSpan workspace frame.outputAddress
          (StageA.Relational.Engine.EngineLayout.stateSize layout)
    | .invokeCall =>
        addressRangeInSpan workspace frame.runtimeAddress 4 ∧
        addressRangeInSpan workspace frame.inputAddress
          (StageA.Relational.Engine.EngineLayout.stateSize layout) ∧
        addressRangeInSpan workspace frame.outputAddress
          (StageA.Relational.Engine.EngineLayout.stateSize layout) ∧
        addressRangeInSpan workspace frame.eventAddress 52

def KernelOperationABIFrame.requestArguments
    (frame : KernelOperationABIFrame) : AbstractKernelRequest -> List Word
  | .programLookup _ sourceOffset => [word32 sourceOffset]
  | .interpreterStep _ _ sourceOffset _ =>
      [frame.resultAddress, frame.runtimeAddress, frame.inputAddress,
        word32 sourceOffset]
  | .runFunction _ _ _ sourceOffset _ =>
      [frame.runtimeAddress, word32 sourceOffset, frame.inputAddress,
        frame.outputAddress]
  | .invokeCall .. =>
      [frame.runtimeAddress, frame.eventAddress, frame.inputAddress,
        frame.outputAddress]

/-- Recover the concrete ABI locations presented at a CDecl entry.  This is a
pure projection from flat machine state; validity and payload facts remain
separate checked obligations. -/
def kernelOperationABIFrameAt
    (workspace : Span) (operation : KernelOperation)
    (state : MachineState) : KernelOperationABIFrame :=
  let esp := state.registers.esp
  let argument (offset : Nat) := Memory.read32 state.memory (esp + word32 offset)
  let runtime := argument 4
  let input := argument 12
  let output := argument 16
  match operation with
  | .programLookup => {
      operation
      entryEsp := esp
      returnAddress := Memory.read32 state.memory esp
      preservedEbx := state.registers.ebx
      preservedEsi := state.registers.esi
      preservedEdi := state.registers.edi
      preservedEbp := state.registers.ebp
      runtimeAddress := word32 workspace.start
      inputAddress := word32 workspace.start
      outputAddress := word32 workspace.start
      eventAddress := word32 workspace.start
      resultAddress := word32 workspace.start
      stackSpan := workspace
    }
  | .interpreterStep => {
      operation
      entryEsp := esp
      returnAddress := Memory.read32 state.memory esp
      preservedEbx := state.registers.ebx
      preservedEsi := state.registers.esi
      preservedEdi := state.registers.edi
      preservedEbp := state.registers.ebp
      resultAddress := runtime
      runtimeAddress := argument 8
      inputAddress := input
      outputAddress := input
      eventAddress := input
      stackSpan := workspace
    }
  | .runFunction => {
      operation
      entryEsp := esp
      returnAddress := Memory.read32 state.memory esp
      preservedEbx := state.registers.ebx
      preservedEsi := state.registers.esi
      preservedEdi := state.registers.edi
      preservedEbp := state.registers.ebp
      runtimeAddress := runtime
      inputAddress := input
      outputAddress := output
      eventAddress := output
      resultAddress := output
      stackSpan := workspace
    }
  | .invokeCall => {
      operation
      entryEsp := esp
      returnAddress := Memory.read32 state.memory esp
      preservedEbx := state.registers.ebx
      preservedEsi := state.registers.esi
      preservedEdi := state.registers.edi
      preservedEbp := state.registers.ebp
      runtimeAddress := runtime
      eventAddress := argument 8
      inputAddress := input
      outputAddress := output
      resultAddress := output
      stackSpan := workspace
    }

/-- Recover a concrete ABI frame while retaining the caller's checked stack
reservation.  Nested calls execute inside the caller-owned stack span rather
than claiming the complete writable workspace as their stack. -/
def kernelOperationABIFrameAtInStackSpan
    (workspace stackSpan : Span) (operation : KernelOperation)
    (state : MachineState) : KernelOperationABIFrame :=
  { kernelOperationABIFrameAt workspace operation state with stackSpan }

@[simp] theorem kernelOperationABIFrameAt_entryEsp
    (workspace : Span) (operation : KernelOperation) (state : MachineState) :
    (kernelOperationABIFrameAt workspace operation state).entryEsp =
      state.registers.esp := by
  cases operation <;> rfl

@[simp] theorem kernelOperationABIFrameAtInStackSpan_entryEsp
    (workspace stackSpan : Span) (operation : KernelOperation)
    (state : MachineState) :
    (kernelOperationABIFrameAtInStackSpan workspace stackSpan operation state
      ).entryEsp = state.registers.esp := by
  cases operation <;> rfl

@[simp] theorem kernelOperationABIFrameAt_returnAddress
    (workspace : Span) (operation : KernelOperation) (state : MachineState) :
    (kernelOperationABIFrameAt workspace operation state).returnAddress =
      Memory.read32 state.memory state.registers.esp := by
  cases operation <;> rfl

@[simp] theorem kernelOperationABIFrameAtInStackSpan_returnAddress
    (workspace stackSpan : Span) (operation : KernelOperation)
    (state : MachineState) :
    (kernelOperationABIFrameAtInStackSpan workspace stackSpan operation state
      ).returnAddress =
      Memory.read32 state.memory state.registers.esp := by
  cases operation <;> rfl

@[simp] theorem kernelOperationABIFrameAtInStackSpan_stackSpan
    (workspace stackSpan : Span) (operation : KernelOperation)
    (state : MachineState) :
    (kernelOperationABIFrameAtInStackSpan workspace stackSpan operation state
      ).stackSpan = stackSpan := by
  rfl

def KernelOperationABIFrame.CDeclEntryHolds
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest) (state : MachineState) : Prop :=
  request.operation = frame.operation ∧
    state.registers.esp = frame.entryEsp ∧
    state.registers.ebx = frame.preservedEbx ∧
    state.registers.esi = frame.preservedEsi ∧
    state.registers.edi = frame.preservedEdi ∧
    state.registers.ebp = frame.preservedEbp ∧
    WordsAt state.memory frame.entryEsp
      (frame.returnAddress :: frame.requestArguments request) ∧
    addressRangeInSpan abi.parameters.writableWorkspace
      (word32 frame.stackSpan.start) frame.stackSpan.size

theorem kernelOperationABIFrameAt_cdeclEntryHolds
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest) (state : MachineState)
    (arguments :
      let frame := kernelOperationABIFrameAt
        abi.parameters.writableWorkspace request.operation state
      WordsAt state.memory frame.entryEsp
        (frame.returnAddress :: frame.requestArguments request))
    (stackRange :
      addressRangeInSpan abi.parameters.writableWorkspace
        (word32 abi.parameters.writableWorkspace.start)
        abi.parameters.writableWorkspace.size) :
    (kernelOperationABIFrameAt abi.parameters.writableWorkspace
      request.operation state).CDeclEntryHolds abi request state := by
  let frame := kernelOperationABIFrameAt
    abi.parameters.writableWorkspace request.operation state
  have words :
      WordsAt state.memory frame.entryEsp
        (frame.returnAddress :: frame.requestArguments request) := by
    simpa [frame] using arguments
  change
    request.operation = frame.operation ∧
      state.registers.esp = frame.entryEsp ∧
      state.registers.ebx = frame.preservedEbx ∧
      state.registers.esi = frame.preservedEsi ∧
      state.registers.edi = frame.preservedEdi ∧
      state.registers.ebp = frame.preservedEbp ∧
      WordsAt state.memory frame.entryEsp
        (frame.returnAddress :: frame.requestArguments request) ∧
      addressRangeInSpan abi.parameters.writableWorkspace
        (word32 frame.stackSpan.start) frame.stackSpan.size
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, words, ?_⟩ <;>
    cases request <;>
    simp [frame, AbstractKernelRequest.operation, kernelOperationABIFrameAt,
      stackRange]

def KernelOperationABIFrame.CDeclReturnHolds
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest) (state : MachineState) : Prop :=
  request.operation = frame.operation ∧
    state.registers.esp = frame.entryEsp + word32 4 ∧
    state.registers.ebx = frame.preservedEbx ∧
    state.registers.esi = frame.preservedEsi ∧
    state.registers.edi = frame.preservedEdi ∧
    state.registers.ebp = frame.preservedEbp ∧
    WordsAt state.memory frame.entryEsp
      (frame.returnAddress :: frame.requestArguments request)

def KernelOperationABIFrame.RequestPayloadHolds
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) :
    AbstractKernelRequest -> MachineState -> Prop
  | .programLookup requestRecords sourceOffset, _ =>
      requestRecords = records ∧ sourceOffset < 2 ^ 32
  | .interpreterStep requestRecords _ sourceOffset logical, state =>
      requestRecords = records ∧ sourceOffset < 2 ^ 32 ∧
        EngineStateHolds abi.engineLayout frame.inputAddress logical sourceOffset
          state
  | .runFunction requestRecords _ _ sourceOffset logical, state =>
      requestRecords = records ∧ sourceOffset < 2 ^ 32 ∧
        EngineStateHolds abi.engineLayout frame.inputAddress logical sourceOffset
          state
  | .invokeCall requestRecords _ _ event logical, state =>
      requestRecords = records ∧
        EngineStateHolds abi.engineLayout frame.inputAddress logical
          event.targetRva.toNat state ∧
        CallEventMemoryHolds abi.parameters.writableWorkspace state.memory
          frame.eventAddress event

structure KernelOperationABIFrame.RequestFacts
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest) (state : MachineState) : Prop where
  frameValid :
    frame.Valid abi.parameters.writableWorkspace abi.engineLayout
  cdecl : frame.CDeclEntryHolds abi request state
  directionFlagClear : DirectionFlagClear state
  candidateImage : LoadedCandidateImageMemory pe imports relocations state.memory
  originalProgramTable : LoadedOriginalProgramTable abi state.memory
  payload : frame.RequestPayloadHolds abi request state

/-- Request facts needed to execute a checked operation body. Frame validity
is retained by the enclosing call certificate; local composition consumes
this common projection for both launch frames and nested frames. -/
structure KernelOperationABIFrame.EntryFacts
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest) (state : MachineState) : Prop where
  frameValid :
    frame.Valid abi.parameters.writableWorkspace abi.engineLayout
  cdecl : frame.CDeclEntryHolds abi request state
  directionFlagClear : DirectionFlagClear state
  candidateImage : LoadedCandidateImageMemory pe imports relocations state.memory
  originalProgramTable : LoadedOriginalProgramTable abi state.memory
  payload : frame.RequestPayloadHolds abi request state

def KernelOperationABIFrame.RequestFacts.toEntryFacts
    (facts :
      KernelOperationABIFrame.RequestFacts frame abi request state) :
    KernelOperationABIFrame.EntryFacts frame abi request state := {
  frameValid := facts.frameValid
  cdecl := facts.cdecl
  directionFlagClear := facts.directionFlagClear
  candidateImage := facts.candidateImage
  originalProgramTable := facts.originalProgramTable
  payload := facts.payload
}

/-- Repackage checked entry facts for an operation theorem.  The two records
deliberately have identical fields: `EntryFacts` is the composition-facing
interface, while `RequestFacts` is retained by operation refinements. -/
def KernelOperationABIFrame.EntryFacts.toRequestFacts
    (facts :
      KernelOperationABIFrame.EntryFacts frame abi request state) :
    KernelOperationABIFrame.RequestFacts frame abi request state := {
  frameValid := facts.frameValid
  cdecl := facts.cdecl
  directionFlagClear := facts.directionFlagClear
  candidateImage := facts.candidateImage
  originalProgramTable := facts.originalProgramTable
  payload := facts.payload
}

/-- Checked recovery of the concrete cdecl frame carried by an abstract ABI
relation.  This is the common entry interface for top-level launch frames,
nested internal calls, imports, and callbacks.  The relation may choose a
different concrete frame for every request and state, but the returned frame
must satisfy the same flat-memory facts consumed by operation proofs. -/
structure KernelOperationABIEntryAuthority
    (relation : KernelABIRelation)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) : Prop where
  establish : ∀ request state,
    relation.requestRelated request state ->
      ∃ frame : KernelOperationABIFrame,
        frame.EntryFacts abi request state

/-- Entry authority paired with the exact finite stack interval required by a
compiled operation body.  This prevents a local proof from assuming that an
arbitrary valid cdecl frame has enough caller-owned space for its prologue,
spills, nested calls, and argument reads. -/
structure KernelOperationABIEntryStackAuthority
    (relation : KernelABIRelation)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (use : KernelOperationABIStackUse) : Prop where
  establish : ∀ request state,
    relation.requestRelated request state ->
      ∃ frame : KernelOperationABIFrame,
        frame.EntryFacts abi request state ∧
          use.Fits frame abi.parameters.writableWorkspace

def KernelOperationABIEntryStackAuthority.toEntryAuthority
    (authority :
      KernelOperationABIEntryStackAuthority relation abi use) :
    KernelOperationABIEntryAuthority relation abi := {
  establish := by
    intro request state related
    let established := authority.establish request state related
    exact ⟨established.choose, established.choose_spec.1⟩
}

def KernelOperationABIFrame.ResponsePayloadHolds
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) :
    AbstractKernelRequest -> AbstractKernelResponse -> MachineState ->
      List NativeExternalEvent -> Prop
  | .programLookup _ sourceOffset, .programLookup _, state, nativeEvents =>
      state.registers.eax =
          lookupResultPointer records pe.imageBase tableOffset sourceOffset ∧
        nativeEvents = []
  | .interpreterStep _ _ sourceOffset _, .interpreterStep result,
      state, nativeEvents =>
      state.registers.eax = frame.resultAddress ∧
        WordsAt state.memory frame.resultAddress (stepResultWords result) ∧
        match result with
        | none => nativeEvents = []
        | some macroResult =>
            EngineStateHolds abi.engineLayout frame.inputAddress
              macroResult.state sourceOffset state ∧
            NativeEventListShape (externalCallEvents macroResult.events)
              nativeEvents
  | .runFunction _ _ _ sourceOffset _, .call result, state, nativeEvents =>
      state.registers.eax = callStatusWord result.status ∧
        EngineStateHolds abi.engineLayout frame.outputAddress result.state
          sourceOffset state ∧
        nativeEvents = []
  | .invokeCall _ _ _ event _, .call result, state, nativeEvents =>
      state.registers.eax = callStatusWord result.status ∧
        EngineStateHolds abi.engineLayout frame.outputAddress result.state
          event.targetRva.toNat state ∧
        if event.kind == .external then
          ∃ native, nativeEvents = [native] ∧
            NativeExternalEventShape event native
        else nativeEvents = []
  | _, _, _, _ => False

structure KernelOperationABIFrame.ResponseFacts
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (state : MachineState) (events : List NativeExternalEvent) : Prop where
  frameValid :
    frame.Valid abi.parameters.writableWorkspace abi.engineLayout
  cdecl : frame.CDeclReturnHolds abi request state
  directionFlagClear : DirectionFlagClear state
  candidateImage : LoadedCandidateImageMemory pe imports relocations state.memory
  originalProgramTable : LoadedOriginalProgramTable abi state.memory
  payload : frame.ResponsePayloadHolds abi request response state events

def KernelOperationABIFrame.relation
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) :
    KernelABIRelation := {
  requestRelated := frame.RequestFacts abi
  responseRelated := frame.ResponseFacts abi
  scratchFootprint := fun _ => addressInSpan abi.parameters.writableWorkspace
}

/-- A fixed nested frame relation exposes exactly the frame whose request facts
authorized the call. -/
def framedKernelOperationABIEntryAuthority
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) :
    KernelOperationABIEntryAuthority (frame.relation abi) abi := {
  establish := by
    intro request state related
    change frame.RequestFacts abi request state at related
    exact ⟨frame, related.toEntryFacts⟩
}

/-- A fixed nested frame inherits its checked request facts from the frame
relation and supplies the independently checked operation stack interval. -/
def framedKernelOperationABIEntryStackAuthority
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (use : KernelOperationABIStackUse)
    (fits : use.Fits frame abi.parameters.writableWorkspace) :
    KernelOperationABIEntryStackAuthority (frame.relation abi) abi use := {
  establish := by
    intro request state related
    change frame.RequestFacts abi request state at related
    exact ⟨frame, related.toEntryFacts, fits⟩
}

def canonicalKernelOperationABIFrame
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (operation : KernelOperation) : KernelOperationABIFrame := {
  operation
  entryEsp := abi.parameters.entryEsp abi.engineLayout operation
  returnAddress := abi.parameters.returnAddress pe
  preservedEbx := word32 0
  preservedEsi := word32 0
  preservedEdi := word32 0
  preservedEbp := word32 0
  runtimeAddress := abi.parameters.runtimeAddress
  inputAddress := abi.parameters.inputAddress
  outputAddress := abi.parameters.outputAddress abi.engineLayout
  eventAddress := abi.parameters.eventAddress abi.engineLayout
  resultAddress := abi.parameters.resultAddress abi.engineLayout
  stackSpan := {
    start := abi.parameters.stackStart abi.engineLayout operation
    size := abi.parameters.stackReserve
  }
}

/-- The launch ABI is a specialization of the framed payload model.  This
theorem keeps the old top-level relation authoritative while nested operations
use explicit frames. -/
theorem canonicalFrame_requestPayload_iff
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest) (state : MachineState) :
    (canonicalKernelOperationABIFrame abi request.operation).RequestPayloadHolds
        abi request state
      ↔ RequestPayloadHolds abi request state := by
  cases request <;> rfl

theorem canonicalFrame_cdeclEntry_iff
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest) (state : MachineState) :
    (canonicalKernelOperationABIFrame abi request.operation).CDeclEntryHolds
        abi request state ↔
      CDeclEntryFrameHolds abi request state := by
  cases request <;>
    simp [KernelOperationABIFrame.CDeclEntryHolds,
      canonicalKernelOperationABIFrame, CDeclEntryFrameHolds,
      preservedRegistersAreCanonical, KernelOperationABIFrame.requestArguments,
      requestArguments]
  all_goals
    intro _entryEspExact
    constructor
    · intro holds
      rcases holds with
        ⟨ebx, esi, edi, ebp, words, stackRange⟩
      exact ⟨⟨ebx, esi, edi, ebp⟩, words, stackRange⟩
    · intro holds
      rcases holds with
        ⟨⟨ebx, esi, edi, ebp⟩, words, stackRange⟩
      exact ⟨ebx, esi, edi, ebp, words, stackRange⟩

def ABIRequestFacts.toCanonicalFrameEntryFacts
    (facts : ABIRequestFacts abi request state)
    (frameValid :
      (canonicalKernelOperationABIFrame abi request.operation).Valid
        abi.parameters.writableWorkspace abi.engineLayout) :
    (canonicalKernelOperationABIFrame abi request.operation).EntryFacts
      abi request state := {
  frameValid
  cdecl := (canonicalFrame_cdeclEntry_iff abi request state).mpr facts.cdecl
  directionFlagClear := facts.directionFlagClear
  candidateImage := facts.candidateImage
  originalProgramTable := facts.originalProgramTable
  payload := (canonicalFrame_requestPayload_iff abi request state).mpr
    facts.payload
}

/-- The canonical launch relation uses the deterministic operation frame.  Its
static validity is supplied separately so generated binaries can discharge the
closed address arithmetic once without changing the generic ABI theorem. -/
def concreteKernelOperationABIEntryAuthority
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (frameValid : ∀ operation,
      (canonicalKernelOperationABIFrame abi operation).Valid
        abi.parameters.writableWorkspace abi.engineLayout) :
    KernelOperationABIEntryAuthority abi.relation abi := {
  establish := by
    intro request state related
    change ABIRequestFacts abi request state at related
    exact ⟨canonicalKernelOperationABIFrame abi request.operation,
      ABIRequestFacts.toCanonicalFrameEntryFacts related
        (frameValid request.operation)⟩
}

/-- Canonical launch frames can be upgraded to stack-aware entry authority
once generated arithmetic checks the required interval for every operation. -/
def concreteKernelOperationABIEntryStackAuthority
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (use : KernelOperationABIStackUse)
    (frameValid : ∀ operation,
      (canonicalKernelOperationABIFrame abi operation).Valid
        abi.parameters.writableWorkspace abi.engineLayout)
    (fits : ∀ operation,
      use.Fits (canonicalKernelOperationABIFrame abi operation)
        abi.parameters.writableWorkspace) :
    KernelOperationABIEntryStackAuthority abi.relation abi use := {
  establish := by
    intro request state related
    change ABIRequestFacts abi request state at related
    exact ⟨canonicalKernelOperationABIFrame abi request.operation,
      ABIRequestFacts.toCanonicalFrameEntryFacts related
        (frameValid request.operation),
      fits request.operation⟩
}

theorem canonicalFrame_responsePayload_iff
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (state : MachineState) (events : List NativeExternalEvent) :
    KernelOperationABIFrame.ResponsePayloadHolds
        (canonicalKernelOperationABIFrame abi request.operation) abi request
        response state events ↔
      ResponsePayloadHolds abi request response state events := by
  cases request <;> cases response <;> rfl

#print axioms canonicalFrame_requestPayload_iff
#print axioms canonicalFrame_cdeclEntry_iff
#print axioms ABIRequestFacts.toCanonicalFrameEntryFacts
#print axioms framedKernelOperationABIEntryAuthority
#print axioms
  KernelOperationABIEntryStackAuthority.toEntryAuthority
#print axioms framedKernelOperationABIEntryStackAuthority
#print axioms concreteKernelOperationABIEntryAuthority
#print axioms concreteKernelOperationABIEntryStackAuthority
#print axioms canonicalFrame_responsePayload_iff

end StageA.Relational.InterpreterKernelOperationABIFrame
