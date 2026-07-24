import StageA.RelationalInterpreterX87ReplayBridgeTarget

namespace StageA.Relational.InterpreterX87ReplayBridgeRuntime

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterX87ReplayBridgeTarget
open StageA.Relational.Engine

/-! # Native x87 replay runtime certificates

The target module checks the descriptor table, bridge bodies, target cells, and
finite indirect-target inventory.  This module owns the remaining runtime trust
boundary.  In particular, replay operands that carry PE relocations are
re-checked here against both the original replay bytes and the exact candidate
PE.  Runtime certificates are indexed by the checked target binding; a report
status or an unindexed target address cannot construct one.
-/

structure NativeX87ReplayRelocatedOperand where
  descriptorId : Nat
  byteOffset : Nat
  originalOperandRva : Nat
  candidateOperandRva : Nat
  targetRva : Nat
deriving Repr, DecidableEq

inductive NativeX87ReplayOperandBinding where
  | none
  | relocated (operand : NativeX87ReplayRelocatedOperand)
deriving Repr, DecidableEq

def NativeX87ReplayOperandBinding.isRelocated :
    NativeX87ReplayOperandBinding -> Bool
  | .none => false
  | .relocated _ => true

def relocationCountInSpan (relocations : List BaseRelocation)
    (start size : Nat) : Nat :=
  relocations.countP fun relocation =>
    relocation.kind == 3 && start <= relocation.rva &&
      relocation.rva < start + size

def NativeX87ReplayRelocatedOperand.checked
    (operand : NativeX87ReplayRelocatedOperand)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (mapping : NativeX87ReplayBridgeFrameMapping)
    (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) : Bool :=
  operand.descriptorId == descriptor.id &&
    operand.byteOffset + 4 <= descriptor.replay.instructionBytes.length &&
    operand.originalOperandRva ==
      descriptor.replay.rvaStart + operand.byteOffset &&
    operand.candidateOperandRva == mapping.instructionRva + operand.byteOffset &&
    readStructU32 descriptor.replay.instructionBytes operand.byteOffset ==
      some (descriptor.replay.imageBase + operand.targetRva) &&
    readImmutableRvaU32 pe imports operand.candidateOperandRva ==
      some (pe.imageBase + operand.targetRva) &&
    callbackRelocationCount relocations operand.candidateOperandRva == 1

def NativeX87ReplayOperandBinding.checked
    (binding : NativeX87ReplayOperandBinding)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (mapping : NativeX87ReplayBridgeFrameMapping)
    (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) : Bool :=
  match binding with
  | .none =>
      relocationCountInSpan relocations mapping.instructionRva
        descriptor.replay.instructionBytes.length == 0
  | .relocated operand =>
      operand.checked descriptor mapping pe imports relocations &&
        relocationCountInSpan relocations mapping.instructionRva
          descriptor.replay.instructionBytes.length == 1

/-! The target checker intentionally validates semantic landmarks. Runtime
execution additionally needs complete template coverage, so the four variable
fields are checked separately and every remaining byte is compared here. -/

def nativeX87ReplayBridgeTemplateEntryPrefix : Bytes :=
  [0x55, 0x53, 0x56, 0x57, 0xa1]

def nativeX87ReplayBridgeTemplateEntryBody : Bytes :=
  [0x85, 0xc0, 0x74, 0x30, 0x89, 0x60, 0x0c, 0xdd, 0x60, 0x14,
   0x8b, 0x48, 0x04, 0x8b, 0x61, 0x1c, 0xff, 0xb1, 0xf0, 0x00,
   0x00, 0x00, 0xff, 0x31, 0xff, 0x71, 0x08, 0xff, 0x71, 0x0c,
   0xff, 0x71, 0x04, 0xff, 0x71, 0x1c, 0xff, 0x71, 0x18, 0xff,
   0x71, 0x10, 0xff, 0x71, 0x14, 0x61, 0x9d, 0xe9]

def nativeX87ReplayBridgeTemplateEntryTail : Bytes :=
  [0x5f, 0x5e, 0x5b, 0x5d, 0xc3, 0x9c, 0x60, 0xa1]

def nativeX87ReplayBridgeTemplateCaptureBranch : Bytes :=
  [0x85, 0xc0, 0x0f, 0x84]

def nativeX87ReplayBridgeTemplateCaptureBody : Bytes :=
  [0xdd, 0xb0, 0x80, 0x00, 0x00, 0x00, 0x8b, 0x50, 0x08, 0x8b,
   0x0c, 0x24, 0x89, 0x4a, 0x14, 0x8b, 0x4c, 0x24, 0x04, 0x89,
   0x4a, 0x10, 0x8b, 0x4c, 0x24, 0x08, 0x89, 0x4a, 0x18, 0x8b,
   0x4c, 0x24, 0x10, 0x89, 0x4a, 0x04, 0x8b, 0x4c, 0x24, 0x14,
   0x89, 0x4a, 0x0c, 0x8b, 0x4c, 0x24, 0x18, 0x89, 0x4a, 0x08,
   0x8b, 0x4c, 0x24, 0x1c, 0x89, 0x0a, 0x8d, 0x4c, 0x24, 0x24,
   0x89, 0x4a, 0x1c, 0x8b, 0x4c, 0x24, 0x20, 0x89, 0x8a, 0xf0,
   0x00, 0x00, 0x00, 0x8b, 0x4c, 0x24, 0x20, 0xc1, 0xe9, 0x00,
   0x83, 0xe1, 0x01, 0x89, 0x4a, 0x20, 0x8b, 0x4c, 0x24, 0x20,
   0xc1, 0xe9, 0x02, 0x83, 0xe1, 0x01, 0x89, 0x4a, 0x30, 0x8b,
   0x4c, 0x24, 0x20, 0xc1, 0xe9, 0x06, 0x83, 0xe1, 0x01, 0x89,
   0x4a, 0x24, 0x8b, 0x4c, 0x24, 0x20, 0xc1, 0xe9, 0x07, 0x83,
   0xe1, 0x01, 0x89, 0x4a, 0x28, 0x8b, 0x4c, 0x24, 0x20, 0xc1,
   0xe9, 0x0a, 0x83, 0xe1, 0x01, 0x89, 0x4a, 0x34, 0x8b, 0x4c,
   0x24, 0x20, 0xc1, 0xe9, 0x0b, 0x83, 0xe1, 0x01, 0x89, 0x4a,
   0x2c, 0xc7, 0x40, 0x10, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x60,
   0x0c, 0xfc, 0x5f, 0x5e, 0x5b, 0x5d, 0xc3]

def rel32JccAtTargets (bytes : Bytes) (offset : Nat)
    (condition : Byte) (nextRva targetRva : Nat) : Bool :=
  bytes[offset]? == some 0x0f &&
    bytes[offset + 1]? == some condition &&
    match readStructU32 bytes (offset + 2) with
    | some displacement => relativeTarget32 nextRva displacement == targetRva
    | none => false

structure NativeX87ReplayBridgeRuntimeLayout where
  failureRva : Nat
deriving Repr, DecidableEq

def NativeX87ReplayBridgeRuntimeLayout.checked
    (layout : NativeX87ReplayBridgeRuntimeLayout)
    (table : NativeX87ReplayBridgeTable)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (mapping : NativeX87ReplayBridgeFrameMapping)
    (pe : PE32) : Bool :=
  bytesAt mapping.bridgeBodyBytes
      nativeX87ReplayBridgeTemplateEntryPrefix 0 &&
    bytesAt mapping.bridgeBodyBytes
      nativeX87ReplayBridgeTemplateEntryBody 9 &&
    bytesAt mapping.bridgeBodyBytes
      nativeX87ReplayBridgeTemplateEntryTail 61 &&
    bytesAt mapping.bridgeBodyBytes
      nativeX87ReplayBridgeTemplateCaptureBranch 73 &&
    bytesAt mapping.bridgeBodyBytes
      nativeX87ReplayBridgeTemplateCaptureBody 81 &&
    readStructU32 mapping.bridgeBodyBytes
      nativeX87ReplayBridgeEntryActiveOperandOffset ==
        some (pe.imageBase + table.activeFramePointerRva) &&
    readStructU32 mapping.bridgeBodyBytes
      nativeX87ReplayBridgeCaptureActiveOperandOffset ==
        some (pe.imageBase + table.activeFramePointerRva) &&
    rel32AtTargets mapping.bridgeBodyBytes
      nativeX87ReplayBridgeEntryJumpOffset
      (mapping.bridgeTargetRva + nativeX87ReplayBridgeEntryJumpOffset + 5)
      mapping.instructionRva &&
    rel32JccAtTargets mapping.bridgeBodyBytes 75 0x84
      (mapping.bridgeTargetRva + 81) layout.failureRva &&
    executableRva pe layout.failureRva &&
    mapping.returnRva ==
      mapping.bridgeTargetRva + nativeX87ReplayBridgeReturnOffset &&
    mapping.instructionPathBytes.length ==
      descriptor.replay.instructionBytes.length + 5

structure ExactNativeX87ReplayRuntimeTarget
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)) where
  target : ExactNativeX87ReplayBridgeTargetBinding table pe imports relocations packs
  operand : NativeX87ReplayOperandBinding
  operandChecked :
    operand.checked target.descriptor target.frameMapping pe imports relocations = true
  layout : NativeX87ReplayBridgeRuntimeLayout
  layoutChecked :
    layout.checked table target.descriptor target.frameMapping pe = true

structure ExactNativeX87ReplayRuntimeInventory
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)) where
  staticCertificate :
    ExactNativeX87ReplayBridgeStaticCertificate
      table pe imports relocations packs
  static : ExactNativeX87ReplayBridgeTargetInventory table pe imports relocations packs
  targets : List
    (ExactNativeX87ReplayRuntimeTarget table pe imports relocations packs)
  targetsExact : targets.map (·.target) = static.bindings
  relocatedOperandCount : Nat
  relocatedOperandsExact :
    targets.countP (fun target => target.operand.isRelocated) =
      relocatedOperandCount

theorem ExactNativeX87ReplayRuntimeInventory.operandCheckedFor
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (_member : runtimeTarget ∈ inventory.targets) :
    runtimeTarget.operand.checked runtimeTarget.target.descriptor
      runtimeTarget.target.frameMapping pe imports relocations = true :=
  runtimeTarget.operandChecked

theorem ExactNativeX87ReplayRuntimeInventory.layoutCheckedFor
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (_member : runtimeTarget ∈ inventory.targets) :
    runtimeTarget.layout.checked table runtimeTarget.target.descriptor
      runtimeTarget.target.frameMapping pe = true :=
  runtimeTarget.layoutChecked

/-! ## Exact path projections

These lemmas expose the preservation facts already carried by an exact native
run.  They are intentionally derived from the exact `before`, `targetEntry`, and
`after` shapes, so generated certificates cannot restate them independently.
-/

theorem ExactNativeX87ReplayBridgeRun.callIsEventFree
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    (program.transitionSystem.step run.before).observation = none := by
  rw [run.exactCallStep]

theorem ExactNativeX87ReplayBridgeRun.preservesCallFrames
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    run.after = NestedNativeWorldExecution.running table.continuationRva 0
      run.returned run.calls run.eventIndex run.events run.world
      run.externalFrames :=
  run.afterShape

theorem ExactNativeX87ReplayBridgeRun.preservesExternalEventIndex
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    ∃ returned, run.after = NestedNativeWorldExecution.running
      table.continuationRva 0 returned run.calls run.eventIndex run.events
      run.world run.externalFrames :=
  ⟨run.returned, run.afterShape⟩

theorem ExactNativeX87ReplayBridgeRun.preservesExternalEvents
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    ∃ returned, run.after = NestedNativeWorldExecution.running
      table.continuationRva 0 returned run.calls run.eventIndex run.events
      run.world run.externalFrames :=
  ⟨run.returned, run.afterShape⟩

theorem ExactNativeX87ReplayBridgeRun.preservesRelationalWorld
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    ∃ returned, run.after = NestedNativeWorldExecution.running
      table.continuationRva 0 returned run.calls run.eventIndex run.events
      run.world run.externalFrames :=
  ⟨run.returned, run.afterShape⟩

theorem ExactNativeX87ReplayBridgeRun.preservesExternalCallbackFrames
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    ∃ returned, run.after = NestedNativeWorldExecution.running
      table.continuationRva 0 returned run.calls run.eventIndex run.events
      run.world run.externalFrames :=
  ⟨run.returned, run.afterShape⟩

theorem ExactNativeX87ReplayBridgeRun.targetCellPreserved
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    run.descriptor.bridgeCell.Holds program.pe run.descriptor.bridge run.caller ∧
      run.descriptor.bridgeCell.Holds program.pe run.descriptor.bridge
        run.returned :=
  ⟨run.frameEffect.targetBefore, run.frameEffect.targetAfter⟩

theorem ExactNativeX87ReplayBridgeRun.activeFramePreserved
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    Memory.read32 run.caller.memory
        (BitVec.ofNat 32
          (program.pe.imageBase + table.activeFramePointerRva)) =
        run.frameEffect.frameAddress ∧
      Memory.read32 run.returned.memory
        (BitVec.ofNat 32
          (program.pe.imageBase + table.activeFramePointerRva)) =
        run.frameEffect.frameAddress :=
  ⟨run.frameEffect.activeBefore, run.frameEffect.activeAfter⟩

theorem ExactNativeX87ReplayBridgeRun.parentFramePreserved
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    Memory.read32 run.caller.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameParentOffset) =
        run.frameEffect.parentAddress ∧
      Memory.read32 run.returned.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameParentOffset) =
        run.frameEffect.parentAddress :=
  ⟨run.frameEffect.parentBefore, run.frameEffect.parentAfter⟩

theorem ExactNativeX87ReplayBridgeRun.privateStackEstablished
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    Memory.read32 run.returned.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) !=
      BitVec.ofNat 32 0 :=
  run.frameEffect.privateStackEstablished

theorem ExactNativeX87ReplayBridgeRun.x87FramesCorrespond
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    Engine.readBytes run.caller.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameInputX87Offset)
        kernelX87FrameBytes =
        encodeKernelX87Frame run.logicalInput.x87Physical ∧
      Engine.readBytes run.returned.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
        kernelX87FrameBytes =
        encodeKernelX87Frame run.result.state.x87Physical :=
  ⟨run.frameEffect.inputX87Exact, run.frameEffect.outputX87Exact⟩

structure ExactNativeX87ReplayBridgeRuntimeClosure
    (run : ExactNativeX87ReplayBridgeRun program table handler) : Prop where
  exactIndirectCall :
    program.transitionSystem.step run.before = {
      next := run.targetEntry
      observation := none
    }
  eventFreeBridge :
    NonemptyRelatedPath program.transitionSystem
      run.targetEntry [] run.after
  eventFreeCallAndBridge :
    NonemptyRelatedPath program.transitionSystem run.before [] run.after
  handlerExact : handler run.descriptor.replay run.logicalInput = some run.result
  returnShape :
    run.after = NestedNativeWorldExecution.running table.continuationRva 0
      run.returned run.calls run.eventIndex run.events run.world
      run.externalFrames
  targetCell :
    run.descriptor.bridgeCell.Holds program.pe run.descriptor.bridge run.caller ∧
      run.descriptor.bridgeCell.Holds program.pe run.descriptor.bridge
        run.returned
  activeFrame :
    Memory.read32 run.caller.memory
        (BitVec.ofNat 32
          (program.pe.imageBase + table.activeFramePointerRva)) =
        run.frameEffect.frameAddress ∧
      Memory.read32 run.returned.memory
        (BitVec.ofNat 32
          (program.pe.imageBase + table.activeFramePointerRva)) =
        run.frameEffect.frameAddress
  parentFrame :
    Memory.read32 run.caller.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameParentOffset) =
        run.frameEffect.parentAddress ∧
      Memory.read32 run.returned.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameParentOffset) =
        run.frameEffect.parentAddress
  privateStack :
    Memory.read32 run.returned.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) !=
      BitVec.ofNat 32 0
  x87InputOutput :
    Engine.readBytes run.caller.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameInputX87Offset)
        kernelX87FrameBytes =
        encodeKernelX87Frame run.logicalInput.x87Physical ∧
      Engine.readBytes run.returned.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
        kernelX87FrameBytes =
        encodeKernelX87Frame run.result.state.x87Physical

theorem ExactNativeX87ReplayBridgeRun.runtimeClosure
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    ExactNativeX87ReplayBridgeRuntimeClosure run := {
  exactIndirectCall := run.exactCallStep
  eventFreeBridge := run.exactBridgePath
  eventFreeCallAndBridge := run.exactEventFreePath
  handlerExact := run.handlerResult
  returnShape := run.afterShape
  targetCell := ⟨run.frameEffect.targetBefore, run.frameEffect.targetAfter⟩
  activeFrame := ⟨run.frameEffect.activeBefore, run.frameEffect.activeAfter⟩
  parentFrame := ⟨run.frameEffect.parentBefore, run.frameEffect.parentAfter⟩
  privateStack := run.frameEffect.privateStackEstablished
  x87InputOutput :=
    ⟨run.frameEffect.inputX87Exact, run.frameEffect.outputX87Exact⟩
}

/-! ## Phase-split bridge execution

The compiled bridge has four control phases shared by every replay target:
entry/trampoline, the singleton x87 instruction, capture, and return.  Keeping
those phases in one target-indexed witness makes their composition reusable
without hiding the dynamic execution obligation behind a per-target
`RuntimeGoal`.
-/

/-- A finite nested-native segment whose endpoint and observations are computed
by the exact candidate transition function.  The certificate contains fuel
only; it cannot submit a path, endpoint, or observation list. -/
structure ExactComputedNestedNativeWorldSegment
    (program : ExactNestedNativeWorldProgram)
    (before : NestedNativeWorldExecution) where
  fuel : Nat
  positive : 0 < fuel

def ExactComputedNestedNativeWorldSegment.result
    {program : ExactNestedNativeWorldProgram}
    {before : NestedNativeWorldExecution}
    (segment : ExactComputedNestedNativeWorldSegment program before) :
    NestedNativeWorldExecution × List WorldRelationalObservable :=
  runRelatedSteps program.transitionSystem segment.fuel before

def ExactComputedNestedNativeWorldSegment.after
    {program : ExactNestedNativeWorldProgram}
    {before : NestedNativeWorldExecution}
    (segment : ExactComputedNestedNativeWorldSegment program before) :
    NestedNativeWorldExecution :=
  segment.result.1

def ExactComputedNestedNativeWorldSegment.observations
    {program : ExactNestedNativeWorldProgram}
    {before : NestedNativeWorldExecution}
    (segment : ExactComputedNestedNativeWorldSegment program before) :
    List WorldRelationalObservable :=
  segment.result.2

theorem ExactComputedNestedNativeWorldSegment.path
    {program : ExactNestedNativeWorldProgram}
    {before : NestedNativeWorldExecution}
    (segment : ExactComputedNestedNativeWorldSegment program before) :
    NonemptyRelatedPath program.transitionSystem before
      segment.observations segment.after :=
  ⟨segment.fuel, segment.positive, rfl⟩

theorem ExactComputedNestedNativeWorldSegment.oneStepExact
    {program : ExactNestedNativeWorldProgram}
    {before after : NestedNativeWorldExecution}
    (segment : ExactComputedNestedNativeWorldSegment program before)
    (one : segment.fuel = 1)
    (atTarget : segment.after = after)
    (silent : segment.observations = []) :
    program.transitionSystem.step before = {
      next := after
      observation := none
    } := by
  have runExact :
      runRelatedSteps program.transitionSystem 1 before = (after, []) := by
    rw [← one]
    change segment.result = (after, [])
    apply Prod.ext
    · exact atTarget
    · exact silent
  cases transition : program.transitionSystem.step before with
  | mk next observation =>
      simp [runRelatedSteps, transition] at runExact
      cases observation with
      | none => simp_all
      | some value => simp_all

/-- The smallest missing lower-layer theorem for the replay bridge.  Every
segment is reduced by `runRelatedSteps` over the exact candidate PE semantics;
the provider proves only the resulting phase endpoints, silence, handler
result, and existing typed frame/target predicates. -/
structure ExactNativeX87ReplayBridgeKernelReduction
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (caller logicalInput : MachineState) where
  result : StepResult
  handlerResult :
    handler runtimeTarget.target.descriptor.replay logicalInput = some result
  calleeEntry : MachineState
  instructionEntryState : MachineState
  captureEntryState : MachineState
  returnEntryState : MachineState
  returned : MachineState
  calls : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld
  externalFrames : List NativeWorldExternalCallbackRuntime
  sourceTarget : table.runtimeTargetHolds program.pe
    runtimeTarget.target.descriptor caller
  call : ExactComputedNestedNativeWorldSegment program
    (.running table.callInstruction.rva 0 caller calls
      eventIndex events world externalFrames)
  callOne : call.fuel = 1
  callAtTarget : call.after = .running
    runtimeTarget.target.descriptor.bridge.entry.rva 0 calleeEntry
    ({ continuationRva := table.continuationRva,
       returnAddress := BitVec.ofNat 32
         (program.pe.imageBase + table.continuationRva) } :: calls)
    eventIndex events world externalFrames
  callSilent : call.observations = []
  entry : ExactComputedNestedNativeWorldSegment program
    (.running runtimeTarget.target.descriptor.bridge.entry.rva 0 calleeEntry
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: calls)
      eventIndex events world externalFrames)
  entryAtInstruction : entry.after = .running
    runtimeTarget.target.frameMapping.instructionRva 0 instructionEntryState
    ({ continuationRva := table.continuationRva,
       returnAddress := BitVec.ofNat 32
         (program.pe.imageBase + table.continuationRva) } :: calls)
    eventIndex events world externalFrames
  entrySilent : entry.observations = []
  instruction : ExactComputedNestedNativeWorldSegment program
    (.running runtimeTarget.target.frameMapping.instructionRva 0
      instructionEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: calls)
      eventIndex events world externalFrames)
  instructionAtCapture : instruction.after = .running
    runtimeTarget.target.frameMapping.captureRva 0 captureEntryState
    ({ continuationRva := table.continuationRva,
       returnAddress := BitVec.ofNat 32
         (program.pe.imageBase + table.continuationRva) } :: calls)
    eventIndex events world externalFrames
  instructionSilent : instruction.observations = []
  capture : ExactComputedNestedNativeWorldSegment program
    (.running runtimeTarget.target.frameMapping.captureRva 0 captureEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: calls)
      eventIndex events world externalFrames)
  captureAtReturn : capture.after = .running
    runtimeTarget.target.frameMapping.returnRva 0 returnEntryState
    ({ continuationRva := table.continuationRva,
       returnAddress := BitVec.ofNat 32
         (program.pe.imageBase + table.continuationRva) } :: calls)
    eventIndex events world externalFrames
  captureSilent : capture.observations = []
  returnSegment : ExactComputedNestedNativeWorldSegment program
    (.running runtimeTarget.target.frameMapping.returnRva 0 returnEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: calls)
      eventIndex events world externalFrames)
  returnedAtContinuation : returnSegment.after = .running
    table.continuationRva 0 returned calls
    eventIndex events world externalFrames
  returnSilent : returnSegment.observations = []
  frameEffect : NativeX87ReplayNestedFrameEffect table program.pe
    runtimeTarget.target.descriptor caller returned logicalInput result

structure ExactNativeX87ReplayBridgeTemplateRun
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler) where
  logicalInput : MachineState
  result : StepResult
  handlerResult :
    handler runtimeTarget.target.descriptor.replay logicalInput = some result
  caller : MachineState
  calleeEntry : MachineState
  instructionEntryState : MachineState
  captureEntryState : MachineState
  returnEntryState : MachineState
  returned : MachineState
  calls : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld
  externalFrames : List NativeWorldExternalCallbackRuntime
  sourceTarget : table.runtimeTargetHolds program.pe
    runtimeTarget.target.descriptor caller
  before : NestedNativeWorldExecution
  targetEntry : NestedNativeWorldExecution
  instructionEntry : NestedNativeWorldExecution
  captureEntry : NestedNativeWorldExecution
  returnEntry : NestedNativeWorldExecution
  after : NestedNativeWorldExecution
  beforeShape : before = NestedNativeWorldExecution.running
    table.callInstruction.rva 0 caller calls
    eventIndex events world externalFrames
  targetShape : targetEntry = NestedNativeWorldExecution.running
    runtimeTarget.target.descriptor.bridge.entry.rva 0 calleeEntry
    ({ continuationRva := table.continuationRva,
       returnAddress := BitVec.ofNat 32
         (program.pe.imageBase + table.continuationRva) } :: calls)
    eventIndex events world externalFrames
  instructionEntryShape : instructionEntry =
    NestedNativeWorldExecution.running
      runtimeTarget.target.frameMapping.instructionRva 0
      instructionEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: calls)
      eventIndex events world externalFrames
  captureEntryShape : captureEntry = NestedNativeWorldExecution.running
    runtimeTarget.target.frameMapping.captureRva 0 captureEntryState
    ({ continuationRva := table.continuationRva,
       returnAddress := BitVec.ofNat 32
         (program.pe.imageBase + table.continuationRva) } :: calls)
    eventIndex events world externalFrames
  returnEntryShape : returnEntry = NestedNativeWorldExecution.running
    runtimeTarget.target.frameMapping.returnRva 0 returnEntryState
    ({ continuationRva := table.continuationRva,
       returnAddress := BitVec.ofNat 32
         (program.pe.imageBase + table.continuationRva) } :: calls)
    eventIndex events world externalFrames
  afterShape : after = NestedNativeWorldExecution.running
    table.continuationRva 0 returned calls
    eventIndex events world externalFrames
  exactCallStep : program.transitionSystem.step before = {
    next := targetEntry
    observation := none
  }
  entryTrampoline : NonemptyRelatedPath program.transitionSystem
    targetEntry [] instructionEntry
  x87Instruction : NonemptyRelatedPath program.transitionSystem
    instructionEntry [] captureEntry
  captureTrampoline : NonemptyRelatedPath program.transitionSystem
    captureEntry [] returnEntry
  returnToContinuation : NonemptyRelatedPath program.transitionSystem
    returnEntry [] after
  frameEffect : NativeX87ReplayNestedFrameEffect table program.pe
    runtimeTarget.target.descriptor caller returned logicalInput result

def ExactNativeX87ReplayBridgeKernelReduction.toTemplateRun
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {handler : CandidateReplayHandler}
    {caller logicalInput : MachineState}
    (reduction : ExactNativeX87ReplayBridgeKernelReduction
      runtimeTarget program handler caller logicalInput) :
    ExactNativeX87ReplayBridgeTemplateRun runtimeTarget program handler := by
  have entryPath := reduction.entry.path
  rw [reduction.entryAtInstruction, reduction.entrySilent] at entryPath
  have instructionPath := reduction.instruction.path
  rw [reduction.instructionAtCapture, reduction.instructionSilent] at instructionPath
  have capturePath := reduction.capture.path
  rw [reduction.captureAtReturn, reduction.captureSilent] at capturePath
  have returnPath := reduction.returnSegment.path
  rw [reduction.returnedAtContinuation, reduction.returnSilent] at returnPath
  exact {
    logicalInput := logicalInput
    result := reduction.result
    handlerResult := reduction.handlerResult
    caller := caller
    calleeEntry := reduction.calleeEntry
    instructionEntryState := reduction.instructionEntryState
    captureEntryState := reduction.captureEntryState
    returnEntryState := reduction.returnEntryState
    returned := reduction.returned
    calls := reduction.calls
    eventIndex := reduction.eventIndex
    events := reduction.events
    world := reduction.world
    externalFrames := reduction.externalFrames
    sourceTarget := reduction.sourceTarget
    before := .running table.callInstruction.rva 0 caller reduction.calls
      reduction.eventIndex reduction.events reduction.world
      reduction.externalFrames
    targetEntry := .running
      runtimeTarget.target.descriptor.bridge.entry.rva 0 reduction.calleeEntry
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: reduction.calls)
      reduction.eventIndex reduction.events reduction.world
      reduction.externalFrames
    instructionEntry := .running
      runtimeTarget.target.frameMapping.instructionRva 0
      reduction.instructionEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: reduction.calls)
      reduction.eventIndex reduction.events reduction.world
      reduction.externalFrames
    captureEntry := .running runtimeTarget.target.frameMapping.captureRva 0
      reduction.captureEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: reduction.calls)
      reduction.eventIndex reduction.events reduction.world
      reduction.externalFrames
    returnEntry := .running runtimeTarget.target.frameMapping.returnRva 0
      reduction.returnEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: reduction.calls)
      reduction.eventIndex reduction.events reduction.world
      reduction.externalFrames
    after := .running table.continuationRva 0 reduction.returned
      reduction.calls reduction.eventIndex reduction.events reduction.world
      reduction.externalFrames
    beforeShape := rfl
    targetShape := rfl
    instructionEntryShape := rfl
    captureEntryShape := rfl
    returnEntryShape := rfl
    afterShape := rfl
    exactCallStep := reduction.call.oneStepExact reduction.callOne
      reduction.callAtTarget reduction.callSilent
    entryTrampoline := entryPath
    x87Instruction := instructionPath
    captureTrampoline := capturePath
    returnToContinuation := returnPath
    frameEffect := reduction.frameEffect
  }

theorem ExactNativeX87ReplayBridgeTemplateRun.bridgePath
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {handler : CandidateReplayHandler}
    (run : ExactNativeX87ReplayBridgeTemplateRun
      runtimeTarget program handler) :
    NonemptyRelatedPath program.transitionSystem run.targetEntry [] run.after :=
  ((run.entryTrampoline.trans run.x87Instruction).trans
    run.captureTrampoline).trans run.returnToContinuation

def ExactNativeX87ReplayBridgeTemplateRun.toExactRun
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {handler : CandidateReplayHandler}
    (run : ExactNativeX87ReplayBridgeTemplateRun
      runtimeTarget program handler) :
    ExactNativeX87ReplayBridgeRun program table handler := {
  descriptor := runtimeTarget.target.descriptor
  descriptorMember := runtimeTarget.target.descriptorMember
  logicalInput := run.logicalInput
  result := run.result
  handlerResult := run.handlerResult
  caller := run.caller
  calleeEntry := run.calleeEntry
  returned := run.returned
  calls := run.calls
  eventIndex := run.eventIndex
  events := run.events
  world := run.world
  externalFrames := run.externalFrames
  sourceTarget := run.sourceTarget
  before := run.before
  targetEntry := run.targetEntry
  after := run.after
  beforeShape := run.beforeShape
  targetShape := run.targetShape
  afterShape := run.afterShape
  exactCallStep := run.exactCallStep
  exactBridgePath := run.bridgePath
  frameEffect := run.frameEffect
}

theorem ExactNativeX87ReplayBridgeTemplateRun.runtimeClosure
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {handler : CandidateReplayHandler}
    (run : ExactNativeX87ReplayBridgeTemplateRun
      runtimeTarget program handler) :
    ExactNativeX87ReplayBridgeRuntimeClosure run.toExactRun :=
  ExactNativeX87ReplayBridgeRun.runtimeClosure run.toExactRun

/-! ## One generic runtime theorem

The lower layer supplies exact transition reductions, not paths.  The generic
theorem computes each path from those reductions and closes the older
per-binding `RuntimeGoal` without emitting one proof per target.
-/

structure ExactNativeX87ReplayBridgeKernelExecution
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop) : Prop where
  reduce : ∀ runtimeTarget ∈ inventory.targets,
    ∀ caller logicalInput,
      sourceInvariant runtimeTarget.target.descriptor caller logicalInput ->
        Nonempty (ExactNativeX87ReplayBridgeKernelReduction
          runtimeTarget program handler caller logicalInput)

structure ExactNativeX87ReplayTemplateExecution
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop) : Prop where
  programPeExact : program.pe = pe
  programImportsExact : program.imports = imports
  targetInventory : program.indirectTargets.targetSet?
    table.callInstruction.rva .call = some table.nativeTargetSet
  kernelExecution : ExactNativeX87ReplayBridgeKernelExecution
    inventory program handler sourceInvariant

theorem ExactNativeX87ReplayTemplateExecution.runForTarget
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {handler : CandidateReplayHandler}
    {sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop}
    (certificate : ExactNativeX87ReplayTemplateExecution inventory
      program handler sourceInvariant)
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (member : runtimeTarget ∈ inventory.targets)
    (caller logicalInput : MachineState)
    (source : sourceInvariant runtimeTarget.target.descriptor
      caller logicalInput) :
    ∃ run : ExactNativeX87ReplayBridgeTemplateRun
        runtimeTarget program handler,
      run.caller = caller ∧ run.logicalInput = logicalInput := by
  rcases certificate.kernelExecution.reduce runtimeTarget member caller
      logicalInput source with ⟨reduction⟩
  refine ⟨reduction.toTemplateRun, ?_, ?_⟩
  · change caller = caller
    rfl
  · change logicalInput = logicalInput
    rfl

theorem ExactNativeX87ReplayTemplateExecution.runtimeGoal
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {handler : CandidateReplayHandler}
    {sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop}
    (certificate : ExactNativeX87ReplayTemplateExecution inventory
      program handler sourceInvariant)
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (member : runtimeTarget ∈ inventory.targets) :
    runtimeTarget.target.RuntimeGoal program handler sourceInvariant := by
  refine ⟨certificate.programPeExact, certificate.programImportsExact,
    certificate.targetInventory, ?_⟩
  intro caller logicalInput source
  rcases certificate.runForTarget runtimeTarget member caller logicalInput source with
    ⟨run, callerExact, logicalExact⟩
  exact ⟨run.toExactRun, rfl, callerExact, logicalExact⟩

theorem ExactNativeX87ReplayTemplateExecution.refinement
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {handler : CandidateReplayHandler}
    {sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop}
    (certificate : ExactNativeX87ReplayTemplateExecution inventory
      program handler sourceInvariant) :
    ExactNativeX87ReplayBridgeExecutionRefinement
      program table handler sourceInvariant := by
  have programPeExact := certificate.programPeExact
  have programImportsExact := certificate.programImportsExact
  subst pe
  subst imports
  refine {
    static := ⟨relocations, packs, inventory.staticCertificate⟩
    targetInventory := certificate.targetInventory
    runForSource := ?_
  }
  intro descriptor descriptorMember caller logicalInput source
  have descriptorExact :
      inventory.targets.map (fun target => target.target.descriptor) =
        table.descriptors := by
    calc
      inventory.targets.map (fun target => target.target.descriptor) =
          (inventory.targets.map (·.target)).map (·.descriptor) := by
            simp [List.map_map]
      _ = inventory.static.bindings.map (·.descriptor) := by
            rw [inventory.targetsExact]
      _ = table.descriptors := inventory.static.descriptorsExact
  rw [← descriptorExact] at descriptorMember
  rcases List.mem_map.mp descriptorMember with
    ⟨runtimeTarget, runtimeMember, targetDescriptor⟩
  have run := certificate.runForTarget runtimeTarget runtimeMember caller
    logicalInput (by simpa [targetDescriptor] using source)
  rcases run with ⟨execution, callerExact, logicalExact⟩
  exact ⟨execution.toExactRun, by simpa [targetDescriptor], callerExact,
    logicalExact⟩

#print axioms ExactNativeX87ReplayRuntimeInventory.operandCheckedFor
#print axioms ExactNativeX87ReplayBridgeRun.callIsEventFree
#print axioms ExactNativeX87ReplayBridgeRun.targetCellPreserved
#print axioms ExactNativeX87ReplayBridgeRun.runtimeClosure
#print axioms ExactComputedNestedNativeWorldSegment.oneStepExact
#print axioms ExactNativeX87ReplayBridgeKernelReduction.toTemplateRun
#print axioms ExactNativeX87ReplayBridgeTemplateRun.bridgePath
#print axioms ExactNativeX87ReplayTemplateExecution.runForTarget
#print axioms ExactNativeX87ReplayTemplateExecution.runtimeGoal

end StageA.Relational.InterpreterX87ReplayBridgeRuntime
