import StageA.RelationalInterpreterKernelRunOperation
import StageA.RelationalInterpreterKernelStepOperation

namespace StageA.Relational.InterpreterKernelCdeclEpilogue

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked cdecl epilogues for kernel operations

This module closes the common `interpreterStep` / `runFunction` epilogue
frontier without accepting a final machine state.  A certificate gives a
finite exact execution equation up to the checked return instruction.  The
return transition, endpoint, observations, ABI response, and memory frame are
then definitions or theorems over the exact candidate executor.

The checker is operation-parametric.  It uses the selected function's exact
bytes and decoded plain `ret`; it contains no compiler, symbol-name, or
candidate-specific instruction rule.
-/

def decodedPlainCDeclReturn (decoded : DecodedInstruction) : Bool :=
  decoded.instruction == .ret

theorem decodedPlainCDeclReturn_eq_true_iff (decoded : DecodedInstruction) :
    decodedPlainCDeclReturn decoded = true ↔ decoded.instruction = .ret := by
  simp [decodedPlainCDeclReturn]

structure KernelCDeclEpilogueInventory where
  operation : KernelOperation
  epilogueRva : Nat
  returnRva : Nat
deriving Repr, DecidableEq

/-- Static data are accepted only when both cutpoints belong to the exact
checked operation function and the selected return decodes as plain cdecl
`ret`, rather than callee-pop `ret imm16`. -/
def KernelCDeclEpilogueInventory.checked
    (inventory : KernelCDeclEpilogueInventory)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (function : KernelFunction) : Bool :=
  function ∈ program.functions &&
    function.role == inventory.operation.role &&
    function.checked candidate.pe candidate.imports &&
    (function.instructionAt? inventory.epilogueRva).isSome &&
    function.frame.required &&
    function.frame.returnRvas.contains inventory.returnRva &&
    (function.decodedAt? candidate.pe inventory.returnRva).any
      decodedPlainCDeclReturn

structure CheckedKernelCDeclEpilogue
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (function : KernelFunction) where
  inventory : KernelCDeclEpilogueInventory
  checked : inventory.checked program candidate function = true

theorem CheckedKernelCDeclEpilogue.operationRole
    (static : CheckedKernelCDeclEpilogue program candidate function) :
    function.role = static.inventory.operation.role := by
  have checked := static.checked
  simp only [KernelCDeclEpilogueInventory.checked, Bool.and_eq_true] at checked
  simpa only [beq_iff_eq] using checked.1.1.1.1.1.2

theorem CheckedKernelCDeclEpilogue.returnDecoded
    (static : CheckedKernelCDeclEpilogue program candidate function) :
    ∃ decoded,
      function.decodedAt? candidate.pe static.inventory.returnRva =
          some decoded ∧
        decoded.instruction = .ret := by
  have checked := static.checked
  simp only [KernelCDeclEpilogueInventory.checked, Bool.and_eq_true] at checked
  have selected := checked.2
  cases decodedAt : function.decodedAt? candidate.pe static.inventory.returnRva with
  | none => simp [decodedAt] at selected
  | some decoded =>
      have plain : decodedPlainCDeclReturn decoded = true := by
        simpa [decodedAt] using selected
      have instructionExact :=
        (decodedPlainCDeclReturn_eq_true_iff decoded).mp plain
      exact ⟨decoded, rfl, instructionExact⟩

/-! ## Computed return execution -/

inductive CDeclReturnDisposition where
  | topLevel
  | caller (frame : NativeCallFrame) (tail : List NativeCallFrame)
deriving Repr, DecidableEq

def CDeclReturnDisposition.calls : CDeclReturnDisposition ->
    List NativeCallFrame
  | .topLevel => []
  | .caller frame tail => frame :: tail

def CDeclReturnDisposition.accepts
    (disposition : CDeclReturnDisposition) (returnAddress : Word) : Prop :=
  match disposition with
  | .topLevel => True
  | .caller frame _ => returnAddress = frame.returnAddress

def CDeclReturnDisposition.endpoint
    (disposition : CDeclReturnDisposition) (state : MachineState)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) : NativeWorldExecution :=
  match disposition with
  | .topLevel => .returned state events world
  | .caller frame tail =>
      .running frame.continuationRva 0 state tail eventIndex events world

def CDeclReturnDisposition.observations
    (disposition : CDeclReturnDisposition) (state : MachineState)
    (world : RelationalWorld) : List WorldRelationalObservable :=
  match disposition with
  | .topLevel => [.returned world state.registers.eax]
  | .caller _ _ => []

def exactCDeclReturn?
    (candidate : ExactNativeWorldProgram) (returnRva undefinedSlot : Nat)
    (state : MachineState) : Option (Word × MachineState) :=
  match stepKernelPE32Instruction candidate.pe candidate.imports
      (.running returnRva undefinedSlot state) with
  | .stopped (.returned target) after => some (target, after)
  | _ => none

def exactCDeclReturnedState
    (candidate : ExactNativeWorldProgram) (returnRva undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  match exactCDeclReturn? candidate returnRva undefinedSlot state with
  | some (_, after) => after
  | none => state

/-- The only dynamic execution equation ends at the return instruction.
`returnedState` below is computed by the exact decoder/executor and is not a
field of this structure. -/
structure ExactComputedCDeclEpilogue
    (candidate : ExactNativeWorldProgram)
    (static : CheckedKernelCDeclEpilogue program candidate function)
    (disposition : CDeclReturnDisposition)
    (before : MachineState) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) where
  prefixFuel : Nat
  returnUndefinedSlot : Nat
  returnBefore : MachineState
  prefixExact :
    runRelatedSteps candidate.transitionSystem prefixFuel
        (.running static.inventory.epilogueRva 0 before disposition.calls
          eventIndex events world) =
      (.running static.inventory.returnRva returnUndefinedSlot returnBefore
        disposition.calls eventIndex events world, [])
  decodedReturn :
    (exactCDeclReturn? candidate static.inventory.returnRva
      returnUndefinedSlot returnBefore).map Prod.fst =
        some (Memory.read32 returnBefore.memory returnBefore.registers.esp)
  returnTransitionExact : ∀ returnAddress,
    Memory.read32 returnBefore.memory returnBefore.registers.esp =
        returnAddress ->
      disposition.accepts returnAddress ->
      candidate.transitionSystem.step
          (.running static.inventory.returnRva returnUndefinedSlot returnBefore
            disposition.calls eventIndex events world) = {
        next := disposition.endpoint
          (exactCDeclReturnedState candidate static.inventory.returnRva
            returnUndefinedSlot returnBefore)
          eventIndex events world
        observation :=
          match disposition with
          | .topLevel =>
              some (.returned world
                (exactCDeclReturnedState candidate static.inventory.returnRva
                  returnUndefinedSlot returnBefore).registers.eax)
          | .caller _ _ => none
      }

def ExactComputedCDeclEpilogue.returnedState
    (execution : ExactComputedCDeclEpilogue candidate static disposition before
      eventIndex events world) : MachineState :=
  exactCDeclReturnedState candidate static.inventory.returnRva
    execution.returnUndefinedSlot execution.returnBefore

def ExactComputedCDeclEpilogue.start
    (_execution : ExactComputedCDeclEpilogue candidate static disposition before
      eventIndex events world) : NativeWorldExecution :=
  .running static.inventory.epilogueRva 0 before disposition.calls eventIndex
    events world

def ExactComputedCDeclEpilogue.after
    (execution : ExactComputedCDeclEpilogue candidate static disposition before
      eventIndex events world) : NativeWorldExecution :=
  disposition.endpoint execution.returnedState eventIndex events world

def ExactComputedCDeclEpilogue.observations
    (execution : ExactComputedCDeclEpilogue candidate static disposition before
      eventIndex events world) : List WorldRelationalObservable :=
  disposition.observations execution.returnedState world

private theorem exactCDeclReturn_step
    (execution : ExactComputedCDeclEpilogue candidate static disposition before
      eventIndex events world) :
    stepKernelPE32Instruction candidate.pe candidate.imports
        (.running static.inventory.returnRva execution.returnUndefinedSlot
          execution.returnBefore) =
      .stopped
        (.returned
          (Memory.read32 execution.returnBefore.memory
            execution.returnBefore.registers.esp))
        execution.returnedState := by
  have decodedReturn := execution.decodedReturn
  unfold ExactComputedCDeclEpilogue.returnedState exactCDeclReturnedState
  unfold exactCDeclReturn? at decodedReturn ⊢
  cases exact : stepKernelPE32Instruction candidate.pe candidate.imports
      (.running static.inventory.returnRva execution.returnUndefinedSlot
        execution.returnBefore) with
  | running nextRva nextSlot nextState =>
      simp [exact] at decodedReturn
  | fault =>
      simp [exact] at decodedReturn
  | stopped outcome nextState =>
      cases outcome <;> simp [exact] at decodedReturn ⊢
      case returned target =>
        exact decodedReturn

theorem ExactComputedCDeclEpilogue.runExact
    (execution : ExactComputedCDeclEpilogue candidate static disposition before
      eventIndex events world)
    (stackReturnWord :
      Memory.read32 execution.returnBefore.memory
          execution.returnBefore.registers.esp = returnAddress)
    (accepted : disposition.accepts returnAddress) :
    runRelatedSteps candidate.transitionSystem (execution.prefixFuel + 1)
        execution.start =
      (execution.after, execution.observations) := by
  rw [runRelatedSteps_add]
  simp only [ExactComputedCDeclEpilogue.start]
  rw [execution.prefixExact]
  simp only [runRelatedSteps]
  rw [execution.returnTransitionExact returnAddress stackReturnWord accepted]
  cases disposition <;> rfl

theorem ExactComputedCDeclEpilogue.path
    (execution : ExactComputedCDeclEpilogue candidate static disposition before
      eventIndex events world)
    (stackReturnWord :
      Memory.read32 execution.returnBefore.memory
          execution.returnBefore.registers.esp = returnAddress)
    (accepted : disposition.accepts returnAddress) :
    NonemptyRelatedPath candidate.transitionSystem execution.start
      execution.observations execution.after := by
  refine ⟨execution.prefixFuel + 1, Nat.zero_lt_succ _, ?_⟩
  exact execution.runExact stackReturnWord accepted

/-! ## Checked write footprint and caller-frame preservation -/

def wordByteAddresses (address : Word) : List Word :=
  [address, address + word32 1, address + word32 2, address + word32 3]

def wordsByteAddresses : Word -> List Word -> List Word
  | _, [] => []
  | address, _ :: tail =>
      wordByteAddresses address ++
        wordsByteAddresses (address + word32 4) tail

def cdeclCallerWords
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) (request : AbstractKernelRequest) : List Word :=
  abi.parameters.returnAddress pe :: requestArguments abi request

def cdeclCallerFrameBytes
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) (request : AbstractKernelRequest) : List Word :=
  wordsByteAddresses
    (abi.parameters.entryEsp abi.engineLayout request.operation)
    (cdeclCallerWords abi request)

structure CheckedCDeclWriteFootprint where
  bytes : List Word
deriving Repr, DecidableEq

def CheckedCDeclWriteFootprint.contains
    (footprint : CheckedCDeclWriteFootprint) : CandidateFootprint :=
  fun address => address ∈ footprint.bytes

def addressInSpanChecked (span : Span) (address : Word) : Bool :=
  span.start <= address.toNat &&
    address.toNat < span.stop &&
    span.stop <= 2 ^ 32

/-- Every admitted changed byte must be in the ABI workspace and outside the
concrete return-word/argument frame.  Unknown or overlapping bytes reject. -/
def CheckedCDeclWriteFootprint.checked
    (footprint : CheckedCDeclWriteFootprint)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) (request : AbstractKernelRequest) : Bool :=
  decide footprint.bytes.Nodup &&
    footprint.bytes.all fun address =>
      addressInSpanChecked abi.parameters.writableWorkspace address &&
        !(cdeclCallerFrameBytes abi request).contains address

theorem CheckedCDeclWriteFootprint.insideScratch
    (footprint : CheckedCDeclWriteFootprint)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) (request : AbstractKernelRequest)
    (checked : footprint.checked abi request = true) :
    ∀ address, footprint.contains address ->
      abi.scratchFootprint request address := by
  intro address member
  simp only [CheckedCDeclWriteFootprint.checked, Bool.and_eq_true] at checked
  have row := List.all_eq_true.mp checked.2 address member
  simp only [Bool.and_eq_true] at row
  change addressInSpan abi.parameters.writableWorkspace address
  have spanFacts := row.1
  simp only [addressInSpanChecked, Bool.and_eq_true, decide_eq_true_eq] at spanFacts
  exact ⟨spanFacts.1.1, spanFacts.1.2, spanFacts.2⟩

theorem CheckedCDeclWriteFootprint.disjointCallerFrame
    (footprint : CheckedCDeclWriteFootprint)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) (request : AbstractKernelRequest)
    (checked : footprint.checked abi request = true) :
    ∀ address, address ∈ cdeclCallerFrameBytes abi request ->
      ¬ footprint.contains address := by
  intro address callerByte footprintByte
  simp only [CheckedCDeclWriteFootprint.checked, Bool.and_eq_true] at checked
  have row := List.all_eq_true.mp checked.2 address footprintByte
  simp only [Bool.and_eq_true] at row
  have absent : (cdeclCallerFrameBytes abi request).contains address = false := by
    simpa using row.2
  have present : (cdeclCallerFrameBytes abi request).contains address = true := by
    simpa using callerByte
  rw [absent] at present
  contradiction

private theorem read32_eq_of_memoryFrame
    (frame : MemoryAgreesOutside footprint after before)
    (address : Word)
    (outside : ∀ byte, byte ∈ wordByteAddresses address ->
      ¬ footprint byte) :
    Memory.read32 after address = Memory.read32 before address := by
  unfold Memory.read32
  rw [frame address (outside address (by simp [wordByteAddresses]))]
  rw [frame (address + BitVec.ofNat 32 1)
    (outside _ (by simp [wordByteAddresses, word32]))]
  rw [frame (address + BitVec.ofNat 32 2)
    (outside _ (by simp [wordByteAddresses, word32]))]
  rw [frame (address + BitVec.ofNat 32 3)
    (outside _ (by simp [wordByteAddresses, word32]))]

theorem WordsAt.preserve_of_memoryFrame
    (frame : MemoryAgreesOutside footprint after before)
    (address : Word) (values : List Word)
    (outside : ∀ byte, byte ∈ wordsByteAddresses address values ->
      ¬ footprint byte)
    (holds : WordsAt before address values) :
    WordsAt after address values := by
  induction values generalizing address with
  | nil => trivial
  | cons value tail induction =>
      simp only [WordsAt] at holds ⊢
      constructor
      · rw [read32_eq_of_memoryFrame frame address]
        · exact holds.1
        · intro byte member
          exact outside byte (by
            simp only [wordsByteAddresses, List.mem_append]
            exact Or.inl member)
      · apply induction (address := address + word32 4)
        · intro byte member
          exact outside byte (by
            simp only [wordsByteAddresses, List.mem_append]
            exact Or.inr member)
        · exact holds.2

theorem MemoryAgreesOutside.widen
    (frame : MemoryAgreesOutside footprint after before)
    (inside : ∀ address, footprint address -> wider address) :
    MemoryAgreesOutside wider after before := by
  intro address outside
  apply frame address
  intro changed
  exact outside (inside address changed)

def CDeclPreservedRegisters (before after : MachineState) : Prop :=
  after.registers.ebx = before.registers.ebx ∧
    after.registers.esi = before.registers.esi ∧
    after.registers.edi = before.registers.edi ∧
    after.registers.ebp = before.registers.ebp

theorem CDeclPreservedRegisters.canonical
    (preserved : CDeclPreservedRegisters before after)
    (canonical : preservedRegistersAreCanonical before) :
    preservedRegistersAreCanonical after := by
  rcases preserved with ⟨ebx, esi, edi, ebp⟩
  rcases canonical with ⟨beforeEbx, beforeEsi, beforeEdi, beforeEbp⟩
  exact ⟨ebx.trans beforeEbx, esi.trans beforeEsi, edi.trans beforeEdi,
    ebp.trans beforeEbp⟩

/-! ## ABI response certificate -/

/-- All facts refer either to the cdecl entry or to `execution.returnedState`,
which is computed by exact execution.  There is no endpoint or status member.
The response payload is indexed by the typed abstract response, so in
particular a `runFunction` status cannot be selected independently. -/
structure CheckedCDeclEpilogueCertificate
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (candidate : ExactNativeWorldProgram)
    (static : CheckedKernelCDeclEpilogue program candidate function)
    (disposition : CDeclReturnDisposition)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (entryBefore epilogueBefore : MachineState) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) where
  operationExact : request.operation = static.inventory.operation
  entry : ABIRequestFacts abi request entryBefore
  execution : ExactComputedCDeclEpilogue candidate static disposition
    epilogueBefore eventIndex events world
  stackReturnWord :
    Memory.read32 execution.returnBefore.memory
        execution.returnBefore.registers.esp =
      abi.parameters.returnAddress pe
  returnAccepted :
    disposition.accepts (abi.parameters.returnAddress pe)
  preservedRegisters :
    CDeclPreservedRegisters entryBefore execution.returnedState
  stackPopped :
    execution.returnedState.registers.esp =
      entryBefore.registers.esp + word32 4
  footprint : CheckedCDeclWriteFootprint
  footprintChecked : footprint.checked abi request = true
  exactWriteFootprint :
    MemoryAgreesOutside footprint.contains execution.returnedState.memory
      entryBefore.memory
  candidateImagePreserved :
    LoadedCandidateImageMemory pe imports relocations
      execution.returnedState.memory
  originalProgramTablePreserved :
    LoadedOriginalProgramTable abi execution.returnedState.memory
  payload :
    ResponsePayloadHolds abi request response execution.returnedState events

theorem CheckedCDeclEpilogueCertificate.callerWordsPreserved
    (certificate : CheckedCDeclEpilogueCertificate abi candidate static
      disposition request response entryBefore epilogueBefore eventIndex events
      world) :
    WordsAt certificate.execution.returnedState.memory
      (abi.parameters.entryEsp abi.engineLayout request.operation)
      (cdeclCallerWords abi request) := by
  apply WordsAt.preserve_of_memoryFrame certificate.exactWriteFootprint
  · intro byte member
    exact certificate.footprint.disjointCallerFrame abi request
      certificate.footprintChecked byte member
  · exact certificate.entry.cdecl.2.2.1

theorem CheckedCDeclEpilogueCertificate.responseRelated
    (certificate : CheckedCDeclEpilogueCertificate abi candidate static
      disposition request response entryBefore epilogueBefore eventIndex events
      world) :
    abi.relation.responseRelated request response
      certificate.execution.returnedState events := by
  change ABIResponseFacts abi request response
    certificate.execution.returnedState events
  refine {
    cdecl := ?_
    candidateImage := certificate.candidateImagePreserved
    originalProgramTable := certificate.originalProgramTablePreserved
    payload := certificate.payload
  }
  change CDeclReturnFrameHolds abi request certificate.execution.returnedState
  refine ⟨?_, ?_, certificate.callerWordsPreserved⟩
  · rw [certificate.stackPopped, certificate.entry.cdecl.1]
  · exact certificate.preservedRegisters.canonical certificate.entry.cdecl.2.1

theorem CheckedCDeclEpilogueCertificate.memoryFrame
    (certificate : CheckedCDeclEpilogueCertificate abi candidate static
      disposition request response entryBefore epilogueBefore eventIndex events
      world) :
    MemoryAgreesOutside (abi.relation.scratchFootprint request)
      certificate.execution.returnedState.memory entryBefore.memory := by
  exact MemoryAgreesOutside.widen certificate.exactWriteFootprint
    (certificate.footprint.insideScratch abi request
      certificate.footprintChecked)

theorem CheckedCDeclEpilogueCertificate.path
    (certificate : CheckedCDeclEpilogueCertificate abi candidate static
      disposition request response entryBefore epilogueBefore eventIndex events
      world) :
    NonemptyRelatedPath candidate.transitionSystem certificate.execution.start
      certificate.execution.observations certificate.execution.after :=
  certificate.execution.path certificate.stackReturnWord
    certificate.returnAccepted

/-! ## Existing Step and Run frontier adapters -/

structure InterpreterStepCDeclEpilogueAdapter
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function) where
  operationExact : checked.inventory.operation = .interpreterStep
  cutpoint : InterpreterStepNativeCutpoint
  cutpointMember : cutpoint ∈ static.reflected.template.cutpoints
  cutpointEntry : cutpoint.entryRva = checked.inventory.epilogueRva
  cutpointEffect : cutpoint.effect = .return

def InterpreterStepCDeclEpilogueAdapter.phase
    (adapter : InterpreterStepCDeclEpilogueAdapter abi program candidate static
      checked)
    {environment : StageA.Relational.Interpreter.Environment}
    {sourceRva : Nat} {logical : InterpreterMachine} {before : MachineState}
    {world : RelationalWorld}
    {lookup : InterpreterStepNativeLookupPhase static.reflected.template candidate
      records sourceRva before world}
    (actions : InterpreterStepNativeActionPhase static.reflected.template
      candidate environment logical lookup)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (epilogueBefore : MachineState)
    (startExact : actions.afterActions =
      .running checked.inventory.epilogueRva 0 epilogueBefore
        CDeclReturnDisposition.topLevel.calls eventIndex events world)
    (certificate : CheckedCDeclEpilogueCertificate abi candidate checked
      .topLevel
      (.interpreterStep records environment sourceRva logical)
      (.interpreterStep actions.result) before epilogueBefore eventIndex events
      world)
    (fuelExact : adapter.cutpoint.instructionCount =
      certificate.execution.prefixFuel + 1) :
    InterpreterStepNativeEpiloguePhase static.reflected.template candidate
      abi.relation records environment sourceRva logical before actions := by
  let chunk : InterpreterStepNativeChunk static.reflected.template candidate
      actions.afterActions := {
    cutpoint := adapter.cutpoint
    cutpointMember := adapter.cutpointMember
    startsAt := by
      rw [startExact, adapter.cutpointEntry]
      rfl
    positive := by omega
  }
  have resultExact :
      chunk.result =
        (certificate.execution.after, certificate.execution.observations) := by
    unfold InterpreterStepNativeChunk.result
    rw [fuelExact, startExact]
    exact certificate.execution.runExact certificate.stackReturnWord
      certificate.returnAccepted
  have afterExact : chunk.after = certificate.execution.after :=
    congrArg Prod.fst resultExact
  have observationsExact :
      chunk.observations = certificate.execution.observations :=
    congrArg Prod.snd resultExact
  have destination : chunk.destinationChecked := by
    unfold InterpreterStepNativeChunk.destinationChecked
    rw [afterExact]
    simp only [ExactComputedCDeclEpilogue.after,
      CDeclReturnDisposition.endpoint, NativeWorldExecution.rva?]
    exact adapter.cutpointEffect
  refine {
    after := certificate.execution.returnedState
    nativeEvents := events
    afterWorld := world
    observations := certificate.execution.observations
    path := ?_
    responseRelated := certificate.responseRelated
    memoryFrame := certificate.memoryFrame
  }
  have chunkPath := InterpreterStepNativePath.chunk chunk destination
  rw [observationsExact, afterExact] at chunkPath
  simpa [ExactComputedCDeclEpilogue.after,
    CDeclReturnDisposition.endpoint] using chunkPath

structure RunFunctionCDeclEpilogueAdapter
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (static : RunFunctionNativeStaticBinding program candidate)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function) where
  operationExact : checked.inventory.operation = .runFunction
  fuelExact : Nat
  fuelIsEight : fuelExact = 8

def RunFunctionCDeclEpilogueAdapter.phase
    (adapter : RunFunctionCDeclEpilogueAdapter abi program candidate static checked)
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {result : CallResult}
    {before : MachineState} {world : RelationalWorld}
    {outerFrame : NativeCallFrame} {afterLoop : NativeWorldExecution}
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (epilogueBefore : MachineState)
    (startExact : afterLoop =
      .running checked.inventory.epilogueRva 0 epilogueBefore
        (CDeclReturnDisposition.caller outerFrame []).calls eventIndex events
        world)
    (eventIndexExact : eventIndex = events.length)
    (certificate : CheckedCDeclEpilogueCertificate abi candidate checked
      (.caller outerFrame [])
      (.runFunction records environment resolveCodeTarget sourceRva logical)
      (.call result) before epilogueBefore eventIndex events world)
    (fuelExact : certificate.execution.prefixFuel + 1 = adapter.fuelExact) :
    RunFunctionNativeEpiloguePhase candidate
      static.reflected.reflected.template abi.relation records environment
      resolveCodeTarget sourceRva logical result before outerFrame world
      afterLoop := by
  have totalFuel : certificate.execution.prefixFuel + 1 = 8 := by
    rw [fuelExact, adapter.fuelIsEight]
  let chunk : RunFunctionNativeChunk candidate afterLoop 8 := {
    positive := by omega
  }
  have resultExact :
      chunk.result =
        (certificate.execution.after, certificate.execution.observations) := by
    unfold RunFunctionNativeChunk.result
    rw [startExact, ← totalFuel]
    exact certificate.execution.runExact certificate.stackReturnWord
      certificate.returnAccepted
  have afterExact : chunk.after = certificate.execution.after :=
    congrArg Prod.fst resultExact
  have observationsExact :
      chunk.observations = certificate.execution.observations :=
    congrArg Prod.snd resultExact
  refine {
    chunk
    after := certificate.execution.returnedState
    nativeEvents := events
    afterWorld := world
    atCaller := ?_
    silent := ?_
    responseRelated := certificate.responseRelated
    memoryFrame := certificate.memoryFrame
  }
  · rw [afterExact]
    simp [ExactComputedCDeclEpilogue.after,
      CDeclReturnDisposition.endpoint, eventIndexExact]
  · rw [observationsExact]
    rfl

#print axioms CheckedKernelCDeclEpilogue.returnDecoded
#print axioms ExactComputedCDeclEpilogue.path
#print axioms CheckedCDeclEpilogueCertificate.callerWordsPreserved
#print axioms CheckedCDeclEpilogueCertificate.responseRelated
#print axioms CheckedCDeclEpilogueCertificate.memoryFrame
#print axioms InterpreterStepCDeclEpilogueAdapter.phase
#print axioms RunFunctionCDeclEpilogueAdapter.phase

end StageA.Relational.InterpreterKernelCdeclEpilogue
