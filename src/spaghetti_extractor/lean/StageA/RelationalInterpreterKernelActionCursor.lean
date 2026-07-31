import StageA.RelationalInterpreterKernelABI
import StageA.RelationalInterpreterKernelActionAlignment
import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterKernelActionCursor

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterKernelProgramTableProjection
open StageA.Relational.InterpreterNativeWorld

/-!
# Dynamic native Step action cursor

Static semantic/raw-action alignment is checked in
`RelationalInterpreterKernelActionAlignment`.  This module adds only the
compiler-frame and world state needed to prove one native Step loop iteration.
-/

/-- Compiler-specific frame locations are generated as 32-bit deltas from
EBP.  The proof core does not assume a particular compiler or fixed local
offset. -/
structure InterpreterStepActionFrameLayout where
  loopHeaderRva : Nat
  transferSlotDelta : Word
  actionIndexDelta : Word
  inputStateDelta : Word
  callOutputStateDelta : Word
  wordBufferDelta : Word
  memoryFaultDelta : Word
  semanticFaultDelta : Word
  runtimeArgumentDelta : Word
  stateArgumentDelta : Word
  sourceRvaArgumentDelta : Word

def InterpreterStepActionFrameLayout.address
    (_layout : InterpreterStepActionFrameLayout) (frameBase delta : Word) :
    Word :=
  frameBase + delta

/-- Every semantic word that has been evaluated is represented in the native
word buffer.  Unready entries intentionally impose no constraint. -/
def RuntimeWordsAt (memory : Memory) (base : Word)
    (runtime : RuntimeState) : Prop :=
  ∀ index value, runtime.words index = some value ->
    Memory.read32 memory (base + word32 (index * 4)) = value

/-- Native machine representation at the action-loop header. -/
structure InterpreterStepActionCursorHolds
    (layout : InterpreterStepActionFrameLayout)
    (engineLayout : StageA.Relational.Engine.EngineLayout)
    (sourceRva actionIndex : Nat)
    (runtime : RuntimeState) (native : MachineState) where
  frameBase : Word
  frameBaseExact : native.registers.ebp = frameBase
  transferPointer : Word
  transferSlot :
    Memory.read32 native.memory
        (layout.address frameBase layout.transferSlotDelta) =
      transferPointer
  actionIndexSlot :
    Memory.read32 native.memory
        (layout.address frameBase layout.actionIndexDelta) =
      word32 actionIndex
  runtimePointer : Word
  runtimeArgument :
    Memory.read32 native.memory
        (layout.address frameBase layout.runtimeArgumentDelta) =
      runtimePointer
  statePointer : Word
  stateArgument :
    Memory.read32 native.memory
        (layout.address frameBase layout.stateArgumentDelta) =
      statePointer
  sourceRvaArgument :
    Memory.read32 native.memory
        (layout.address frameBase layout.sourceRvaArgumentDelta) =
      word32 sourceRva
  inputState :
    EngineStateHolds engineLayout
      (layout.address frameBase layout.inputStateDelta) runtime.input sourceRva
      native
  currentState :
    EngineStateHolds engineLayout statePointer runtime.current sourceRva native
  callOutputState :
    EngineStateHolds engineLayout
      (layout.address frameBase layout.callOutputStateDelta) runtime.callOutput
      sourceRva native
  words :
    RuntimeWordsAt native.memory
      (layout.address frameBase layout.wordBufferDelta) runtime
  memoryFaultClear :
    Memory.read32 native.memory
        (layout.address frameBase layout.memoryFaultDelta) = word32 0
  semanticFaultClear :
    Memory.read32 native.memory
        (layout.address frameBase layout.semanticFaultDelta) = word32 0

/-- World-indexed action cursor.  Calls and x87 replay may update the native
event list and relational world, so those components remain explicit. -/
structure InterpreterStepNativeActionCursor
    (layout : InterpreterStepActionFrameLayout)
    (engineLayout : StageA.Relational.Engine.EngineLayout)
    (sourceRva actionIndex : Nat)
    (runtime : RuntimeState) (execution : NativeWorldExecution) where
  state : MachineState
  calls : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld
  executionExact :
    execution = .running layout.loopHeaderRva 0 state calls eventIndex events
      world
  holds :
    InterpreterStepActionCursorHolds layout engineLayout sourceRva actionIndex
      runtime state

/-- Body-action cursor with the dynamic native frame tied to the exact static
table entry. -/
structure InterpreterStepLoadedBodyCursor
    (layout : InterpreterStepActionFrameLayout)
    (engineLayout : StageA.Relational.Engine.EngineLayout)
    (pe : PE32) (tableRva index : Nat) (data : TransferCertificateData)
    (records : List ProgramRecord) (runtime : RuntimeState)
    (action : SemanticAction) (tail : List SemanticAction)
    (native : MachineState) where
  transfer :
    CheckedLoadedSemanticTransfer pe tableRva index data records native.memory
  body :
    CheckedRawBodyCursor data transfer.transfer (action :: tail)
  cursor :
    InterpreterStepActionCursorHolds layout engineLayout
      data.descriptor.sourceRva body.actionIndex runtime native
  transferPointerExact :
    cursor.transferPointer =
      word32 (pe.imageBase + tableRva + index * transferRecordSize)

theorem InterpreterStepLoadedBodyCursor.currentActionLoaded
    (cursor : InterpreterStepLoadedBodyCursor layout engineLayout pe tableRva
      index data records runtime action tail native) :
    LoadedRawActionAt pe
      (cursor.transfer.loaded.actionRva +
        cursor.body.actionIndex * actionSize)
      cursor.body.rawAction native.memory :=
  cursor.transfer.loadedBodyAction cursor.body

theorem InterpreterStepLoadedBodyCursor.currentActionDecodes
    (cursor : InterpreterStepLoadedBodyCursor layout engineLayout pe tableRva
      index data records runtime action tail native) :
    cursor.body.rawAction.decodeBody = some action :=
  cursor.body.currentSemanticAction

/-- Terminal-outcome cursor after the complete semantic body. -/
structure InterpreterStepLoadedOutcomeCursor
    (layout : InterpreterStepActionFrameLayout)
    (engineLayout : StageA.Relational.Engine.EngineLayout)
    (pe : PE32) (tableRva index : Nat) (data : TransferCertificateData)
    (records : List ProgramRecord) (runtime : RuntimeState)
    (native : MachineState) where
  transfer :
    CheckedLoadedSemanticTransfer pe tableRva index data records native.memory
  outcome : CheckedRawOutcomeCursor data transfer.transfer
  cursor :
    InterpreterStepActionCursorHolds layout engineLayout
      data.descriptor.sourceRva outcome.actionIndex runtime native
  transferPointerExact :
    cursor.transferPointer =
      word32 (pe.imageBase + tableRva + index * transferRecordSize)

theorem InterpreterStepLoadedOutcomeCursor.currentActionLoaded
    (cursor : InterpreterStepLoadedOutcomeCursor layout engineLayout pe
      tableRva index data records runtime native) :
    LoadedRawActionAt pe
      (cursor.transfer.loaded.actionRva +
        cursor.outcome.actionIndex * actionSize)
      cursor.outcome.rawOutcome native.memory :=
  cursor.transfer.loadedOutcomeAction cursor.outcome

#print axioms InterpreterStepLoadedBodyCursor.currentActionLoaded
#print axioms InterpreterStepLoadedOutcomeCursor.currentActionLoaded

end StageA.Relational.InterpreterKernelActionCursor
