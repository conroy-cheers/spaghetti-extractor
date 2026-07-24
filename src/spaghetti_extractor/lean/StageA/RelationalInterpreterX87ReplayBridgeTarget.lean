import StageA.RelationalInterpreterKernelCallbackNativeWorldBridge
import StageA.RelationalInterpreterX87

namespace StageA.Relational.InterpreterX87ReplayBridgeTarget

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelCallbackNativeWorldBridge
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterX87
open StageA.Relational.Engine

/-! # Exact native x87 replay bridge targets

The compiled Stage B x87 replay helper selects an assembly bridge from an
immutable descriptor table and calls it indirectly.  This module checks that
table against exact candidate PE bytes and then describes the non-observable
nested native execution needed by whole-program composition.

Generated data is only a proposal.  `NativeX87ReplayBridgeDescriptor.checked`
re-reads every descriptor word, string, replay byte, relocation, and target
entry from the PE.  The dynamic certificate separately requires an exact
`NonemptyRelatedPath`; a successful static check cannot manufacture execution
or acceptance authority. -/

def nativeX87ReplayDescriptorSize : Nat := 36
def nativeX87ReplayBridgeFieldOffset : Nat := 32

def nativeX87FrameParentOffset : Nat := 0
def nativeX87FrameInputOffset : Nat := 4
def nativeX87FrameOutputOffset : Nat := 8
def nativeX87FramePrivateEspOffset : Nat := 12
def nativeX87FrameStatusOffset : Nat := 16
def nativeX87FrameInputX87Offset : Nat := 20
def nativeX87FrameOutputX87Offset : Nat := 128

def nativeX87ReplayBridgeBodySize : Nat := 248
def nativeX87ReplayBridgeCaptureOffset : Nat := 66
def nativeX87ReplayBridgeReturnOffset : Nat := 247
def nativeX87ReplayBridgeEntryJumpOffset : Nat := 56
def nativeX87ReplayBridgeEntryActiveOperandOffset : Nat := 5
def nativeX87ReplayBridgeCaptureActiveOperandOffset : Nat := 69

def readImmutableRvaU32 (pe : PE32) (imports : List PEImport)
    (rva : Nat) : Option Nat := do
  let bytes <- immutableRvaBytes pe imports rva 4
  readStructU32 bytes 0

def exactRelocatedImmutablePointer (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (fieldRva targetRva : Nat) : Bool :=
  fieldRva % 4 == 0 &&
    callbackRelocationCount relocations fieldRva == 1 &&
    readImmutableRvaU32 pe imports fieldRva ==
      some (pe.imageBase + targetRva)

def writableNonExecutableRvaRange (pe : PE32) (rva size : Nat) : Bool :=
  size > 0 && rva + size <= pe.sizeOfImage &&
    match pe.sections.filter fun sec =>
      sec.virtualAddress <= rva &&
        rva + size <= sec.virtualAddress + sec.mappedSize with
    | [sec] => sec.writable && !sec.executable
    | _ => false

def bytesAt (bytes expected : Bytes) (offset : Nat) : Bool :=
  (bytes.drop offset |>.take expected.length) == expected

def rel32AtTargets (bytes : Bytes) (offset nextRva targetRva : Nat) : Bool :=
  bytes[offset]? == some 0xe9 &&
    match readStructU32 bytes (offset + 1) with
    | some displacement => relativeTarget32 nextRva displacement == targetRva
    | none => false

structure NativeX87ReplayBridgeDescriptor where
  id : Nat
  descriptorRva : Nat
  instructionBytesRva : Nat
  instructionDigestRva : Nat
  transferDigestRva : Nat
  contractDigestRva : Nat
  replay : RawX87Replay
  bridge : CallbackTargetEntry
deriving Repr, DecidableEq

def NativeX87ReplayBridgeDescriptor.bridgeCell
    (descriptor : NativeX87ReplayBridgeDescriptor) :
    RelocationBackedCallbackTargetCell := {
  id := descriptor.id
  cellRva := descriptor.descriptorRva + nativeX87ReplayBridgeFieldOffset
  targetId := descriptor.bridge.id
}

def NativeX87ReplayBridgeDescriptor.checked
    (descriptor : NativeX87ReplayBridgeDescriptor) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation) : Bool :=
  descriptor.replay.instructionCount == 1 &&
    descriptor.replay.imageBase == pe.imageBase &&
    descriptor.replay.rvaEnd ==
      descriptor.replay.rvaStart + descriptor.replay.instructionBytes.length &&
    descriptor.replay.checkedDecoder == checkedX87DecoderName &&
    descriptor.replay.checkedExecutor == checkedX87ExecutorName &&
    ArtifactSHA256.checkedHex descriptor.replay.instructionBytes
      descriptor.replay.instructionBytesSha256 &&
    readImmutableRvaU32 pe imports descriptor.descriptorRva ==
      some descriptor.replay.imageBase &&
    readImmutableRvaU32 pe imports (descriptor.descriptorRva + 4) ==
      some descriptor.replay.rvaStart &&
    readImmutableRvaU32 pe imports (descriptor.descriptorRva + 8) ==
      some descriptor.replay.rvaEnd &&
    readImmutableRvaU32 pe imports (descriptor.descriptorRva + 12) ==
      some descriptor.replay.instructionBytes.length &&
    exactRelocatedImmutablePointer pe imports relocations
      (descriptor.descriptorRva + 16) descriptor.instructionBytesRva &&
    exactRelocatedImmutablePointer pe imports relocations
      (descriptor.descriptorRva + 20) descriptor.instructionDigestRva &&
    exactRelocatedImmutablePointer pe imports relocations
      (descriptor.descriptorRva + 24) descriptor.transferDigestRva &&
    exactRelocatedImmutablePointer pe imports relocations
      (descriptor.descriptorRva + 28) descriptor.contractDigestRva &&
    exactRelocatedImmutablePointer pe imports relocations
      (descriptor.descriptorRva + nativeX87ReplayBridgeFieldOffset)
      descriptor.bridge.entry.rva &&
    immutableRvaBytes pe imports descriptor.instructionBytesRva
      descriptor.replay.instructionBytes.length ==
        some descriptor.replay.instructionBytes &&
    readImmutableCString pe imports descriptor.instructionDigestRva ==
      some descriptor.replay.instructionBytesSha256 &&
    readImmutableCString pe imports descriptor.transferDigestRva ==
      some descriptor.replay.transferInstructionBytesSha256 &&
    readImmutableCString pe imports descriptor.contractDigestRva ==
      some descriptor.replay.contractSha256 &&
    descriptor.bridge.checked pe imports

structure NativeX87ReplayBridgeTable where
  tableRva : Nat
  activeFramePointerRva : Nat
  activeFrameStoreInstruction : KernelInstruction
  descriptorLoadInstruction : KernelInstruction
  targetLoadInstruction : KernelInstruction
  callInstruction : KernelInstruction
  activeFrameLoadInstruction : KernelInstruction
  continuationRva : Nat
  descriptors : List NativeX87ReplayBridgeDescriptor
deriving Repr, DecidableEq

/-- Exact static map from one descriptor target through the generated native
bridge frame, singleton x87 instruction path, capture path, and return.  This
does not assert execution: `checked` only re-reads the exact candidate PE and
validates the frame/control layout needed by the runtime refinement goal. -/
structure NativeX87ReplayBridgeFrameMapping where
  descriptorId : Nat
  bridgeTargetRva : Nat
  instructionRva : Nat
  captureRva : Nat
  returnRva : Nat
  bridgeBodyBytes : Bytes
  instructionPathBytes : Bytes
deriving Repr, DecidableEq

def NativeX87ReplayBridgeFrameMapping.checked
    (mapping : NativeX87ReplayBridgeFrameMapping)
    (activeFramePointerRva : Nat)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) : Bool :=
  mapping.descriptorId == descriptor.id &&
    mapping.bridgeTargetRva == descriptor.bridge.entry.rva &&
    mapping.captureRva ==
      mapping.bridgeTargetRva + nativeX87ReplayBridgeCaptureOffset &&
    mapping.returnRva ==
      mapping.bridgeTargetRva + nativeX87ReplayBridgeReturnOffset &&
    mapping.bridgeBodyBytes.length == nativeX87ReplayBridgeBodySize &&
    immutableRvaBytes pe imports mapping.bridgeTargetRva
      mapping.bridgeBodyBytes.length == some mapping.bridgeBodyBytes &&
    bytesAt mapping.bridgeBodyBytes [0x55, 0x53, 0x56, 0x57, 0xa1] 0 &&
    bytesAt mapping.bridgeBodyBytes [0x85, 0xc0, 0x74, 0x30] 9 &&
    bytesAt mapping.bridgeBodyBytes [0x89, 0x60,
      nativeX87FramePrivateEspOffset] 13 &&
    bytesAt mapping.bridgeBodyBytes [0xdd, 0x60,
      nativeX87FrameInputX87Offset] 16 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x48,
      nativeX87FrameInputOffset] 19 &&
    bytesAt mapping.bridgeBodyBytes [0x61, 0x9d] 54 &&
    rel32AtTargets mapping.bridgeBodyBytes nativeX87ReplayBridgeEntryJumpOffset
      (mapping.bridgeTargetRva + nativeX87ReplayBridgeEntryJumpOffset + 5)
      mapping.instructionRva &&
    bytesAt mapping.bridgeBodyBytes [0x5f, 0x5e, 0x5b, 0x5d, 0xc3] 61 &&
    bytesAt mapping.bridgeBodyBytes [0x9c, 0x60, 0xa1] 66 &&
    readStructU32 mapping.bridgeBodyBytes
      nativeX87ReplayBridgeEntryActiveOperandOffset ==
        some (pe.imageBase + activeFramePointerRva) &&
    readStructU32 mapping.bridgeBodyBytes
      nativeX87ReplayBridgeCaptureActiveOperandOffset ==
        some (pe.imageBase + activeFramePointerRva) &&
    callbackRelocationCount relocations
      (mapping.bridgeTargetRva +
        nativeX87ReplayBridgeEntryActiveOperandOffset) == 1 &&
    callbackRelocationCount relocations
      (mapping.bridgeTargetRva +
        nativeX87ReplayBridgeCaptureActiveOperandOffset) == 1 &&
    bytesAt mapping.bridgeBodyBytes [0xdd, 0xb0, 0x80, 0, 0, 0] 81 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x50,
      nativeX87FrameOutputOffset] 87 &&
    bytesAt mapping.bridgeBodyBytes [0xc7, 0x40,
      nativeX87FrameStatusOffset, 0, 0, 0, 0] 232 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x60,
      nativeX87FramePrivateEspOffset] 239 &&
    bytesAt mapping.bridgeBodyBytes [0xfc, 0x5f, 0x5e, 0x5b, 0x5d, 0xc3] 242 &&
    mapping.instructionPathBytes.length ==
      descriptor.replay.instructionBytes.length + 5 &&
    immutableRvaBytes pe imports mapping.instructionRva
      mapping.instructionPathBytes.length == some mapping.instructionPathBytes &&
    mapping.instructionPathBytes.take descriptor.replay.instructionBytes.length ==
      descriptor.replay.instructionBytes &&
    rel32AtTargets mapping.instructionPathBytes
      descriptor.replay.instructionBytes.length
      (mapping.instructionRva + descriptor.replay.instructionBytes.length + 5)
      mapping.captureRva

def NativeX87ReplayBridgeTable.targets
    (table : NativeX87ReplayBridgeTable) : CallbackTargetSet := {
  entries := table.descriptors.map (·.bridge)
}

def NativeX87ReplayBridgeTable.targetCells
    (table : NativeX87ReplayBridgeTable) :
    RelocationBackedCallbackTargetInventory := {
  cells := table.descriptors.map (·.bridgeCell)
}

def NativeX87ReplayBridgeTable.callSite
    (table : NativeX87ReplayBridgeTable) : KernelIndirectCallbackSite := {
  id := 0
  instruction := table.callInstruction
  continuationRva := table.continuationRva
  targetOperand := .register .eax
  abi := {
    argumentCount := 0
    argumentOffsets := []
    callerStackDelta := 0
    preservedRegisters := cdeclPreservedRegisters
    returnKind := .void
  }
  targets := table.targets
}

def NativeX87ReplayBridgeTable.nativeTargetSet
    (table : NativeX87ReplayBridgeTable) : NativeIndirectTargetSet := {
  sourceRva := table.callInstruction.rva
  transfer := .call
  targets := table.descriptors.map fun descriptor =>
    .internalRva descriptor.bridge.entry.rva
}

def NativeX87ReplayBridgeTable.nativeTargetInventory
    (table : NativeX87ReplayBridgeTable) : NativeIndirectTargetInventory := {
  targetSets := [table.nativeTargetSet]
}

def NativeX87ReplayBridgeTable.shapeChecked
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation) : Bool :=
  !table.descriptors.isEmpty &&
    writableNonExecutableRvaRange pe table.activeFramePointerRva 4 &&
    table.activeFrameStoreInstruction.rva +
        table.activeFrameStoreInstruction.bytes.length ==
      table.descriptorLoadInstruction.rva &&
    table.descriptorLoadInstruction.rva +
        table.descriptorLoadInstruction.bytes.length ==
      table.targetLoadInstruction.rva &&
    table.targetLoadInstruction.rva + table.targetLoadInstruction.bytes.length ==
      table.callInstruction.rva &&
    table.continuationRva ==
      table.callInstruction.rva + table.callInstruction.bytes.length &&
    table.activeFrameLoadInstruction.rva == table.continuationRva &&
    table.activeFrameStoreInstruction.bytes.length == 5 &&
    table.activeFrameStoreInstruction.bytes[0]? == some 0xa3 &&
    readStructU32 table.activeFrameStoreInstruction.bytes 1 ==
      some (pe.imageBase + table.activeFramePointerRva) &&
    callbackRelocationCount relocations
      (table.activeFrameStoreInstruction.rva + 1) == 1 &&
    table.descriptorLoadInstruction.bytes.length == 3 &&
    table.descriptorLoadInstruction.bytes[0]? == some 0x8b &&
    table.descriptorLoadInstruction.bytes[1]? == some 0x45 &&
    table.targetLoadInstruction.bytes == [0x8b, 0x40,
      nativeX87ReplayBridgeFieldOffset] &&
    table.callInstruction.bytes == [0xff, 0xd0] &&
    table.activeFrameLoadInstruction.bytes.length == 6 &&
    table.activeFrameLoadInstruction.bytes[0]? == some 0x8b &&
    table.activeFrameLoadInstruction.bytes[1]? == some 0x15 &&
    readStructU32 table.activeFrameLoadInstruction.bytes 2 ==
      some (pe.imageBase + table.activeFramePointerRva) &&
    callbackRelocationCount relocations
      (table.activeFrameLoadInstruction.rva + 2) == 1 &&
    decide (table.descriptors.map (·.id)).Nodup &&
    decide (table.descriptors.map (·.descriptorRva)).Nodup &&
    decide (table.descriptors.map (·.bridge.entry.rva)).Nodup &&
    (table.descriptors.zip (List.range table.descriptors.length)).all fun indexed =>
      indexed.1.id == indexed.2 &&
        indexed.1.descriptorRva ==
          table.tableRva + indexed.2 * nativeX87ReplayDescriptorSize &&
    table.activeFrameStoreInstruction.checked pe imports &&
    table.descriptorLoadInstruction.checked pe imports &&
    table.targetLoadInstruction.checked pe imports &&
    table.callSite.checked pe imports &&
    table.activeFrameLoadInstruction.checked pe imports &&
    table.nativeTargetInventory.valid pe

structure NativeX87ReplayBridgeDescriptorPack
    (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) where
  descriptors : List NativeX87ReplayBridgeDescriptor
  checked : descriptors.all (fun descriptor =>
    descriptor.checked pe imports relocations) = true

def nativeX87ReplayBridgePackDescriptors
    (packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)) :
    List NativeX87ReplayBridgeDescriptor :=
  packs.flatMap (·.descriptors)

/-- Static authority for the complete submitted descriptor layout.  The exact
relocation parse is a field so descriptor shards can reuse one parsed list;
each shard still checks its own exact PE bytes and all five pointer fields. -/
structure ExactNativeX87ReplayBridgeStaticCertificate
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)) :
    Prop where
  relocationsParsed : parseRelocations pe = some relocations
  packsExact : nativeX87ReplayBridgePackDescriptors packs = table.descriptors
  shapeChecked : table.shapeChecked pe imports relocations = true

theorem ExactNativeX87ReplayBridgeStaticCertificate.descriptorChecked
    (certificate : ExactNativeX87ReplayBridgeStaticCertificate table pe imports
      relocations packs)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (member : descriptor ∈ table.descriptors) :
    descriptor.checked pe imports relocations = true := by
  rw [← certificate.packsExact] at member
  rcases List.mem_flatMap.mp member with ⟨pack, _, descriptorMember⟩
  exact List.all_eq_true.mp pack.checked descriptor descriptorMember

/-- One named target term.  The PE index is the semantic identity: generated
source and Nix metadata also retain `candidateSha256`, but no theorem trusts a
digest label instead of re-reading the exact `pe` value. -/
structure ExactNativeX87ReplayBridgeTargetBinding
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)) where
  candidateSha256 : String
  candidateSize : Nat
  candidateSizeExact : candidateSize = pe.bytes.length
  digestShape : candidateSha256.length = 64
  static : ExactNativeX87ReplayBridgeStaticCertificate table pe imports
    relocations packs
  descriptor : NativeX87ReplayBridgeDescriptor
  descriptorMember : descriptor ∈ table.descriptors
  frameMapping : NativeX87ReplayBridgeFrameMapping
  frameMappingChecked :
    frameMapping.checked table.activeFramePointerRva descriptor pe imports
      relocations = true

structure ExactNativeX87ReplayBridgeTargetInventory
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)) where
  bindings : List (ExactNativeX87ReplayBridgeTargetBinding
    table pe imports relocations packs)
  descriptorsExact : bindings.map (·.descriptor) = table.descriptors
  candidateDigestExact :
    ∃ digest, bindings.all (fun binding =>
      binding.candidateSha256 == digest) = true

def NativeX87ReplayBridgeTable.runtimeTargetHolds
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (state : MachineState) : Prop :=
  descriptor ∈ table.descriptors ∧
    table.callSite.targetWord state = descriptor.bridge.address pe ∧
    descriptor.bridgeCell.Holds pe descriptor.bridge state

/-- Exact runtime effects of the generated nested x87 frame.  Both target-cell
equalities are required: a writable or otherwise unpreserved runtime target
cannot be promoted merely because its on-disk value was valid. -/
structure NativeX87ReplayNestedFrameEffect
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (caller returned logicalInput : MachineState) (result : StepResult) where
  frameAddress : Word
  parentAddress : Word
  inputAddress : Word
  outputAddress : Word
  targetBefore : descriptor.bridgeCell.Holds pe descriptor.bridge caller
  targetAfter : descriptor.bridgeCell.Holds pe descriptor.bridge returned
  activeBefore :
    Memory.read32 caller.memory
      (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) = frameAddress
  activeAfter :
    Memory.read32 returned.memory
      (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) = frameAddress
  parentBefore : Memory.read32 caller.memory
      (frameAddress + BitVec.ofNat 32 nativeX87FrameParentOffset) = parentAddress
  parentAfter : Memory.read32 returned.memory
      (frameAddress + BitVec.ofNat 32 nativeX87FrameParentOffset) = parentAddress
  inputPointer : Memory.read32 caller.memory
      (frameAddress + BitVec.ofNat 32 nativeX87FrameInputOffset) = inputAddress
  outputPointer : Memory.read32 caller.memory
      (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputOffset) = outputAddress
  privateStackEstablished : Memory.read32 returned.memory
      (frameAddress + BitVec.ofNat 32 nativeX87FramePrivateEspOffset) !=
        BitVec.ofNat 32 0
  statusSucceeded : Memory.read32 returned.memory
      (frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset) =
        BitVec.ofNat 32 0
  inputX87Exact : Engine.readBytes caller.memory
      (frameAddress + BitVec.ofNat 32 nativeX87FrameInputX87Offset)
      kernelX87FrameBytes = encodeKernelX87Frame logicalInput.x87Physical
  outputX87Exact : Engine.readBytes returned.memory
      (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
      kernelX87FrameBytes = encodeKernelX87Frame result.state.x87Physical

structure ExactNativeX87ReplayBridgeRun
    (program : ExactNestedNativeWorldProgram)
    (table : NativeX87ReplayBridgeTable)
    (handler : CandidateReplayHandler) where
  descriptor : NativeX87ReplayBridgeDescriptor
  descriptorMember : descriptor ∈ table.descriptors
  logicalInput : MachineState
  result : StepResult
  handlerResult : handler descriptor.replay logicalInput = some result
  caller : MachineState
  calleeEntry : MachineState
  returned : MachineState
  calls : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld
  externalFrames : List NativeWorldExternalCallbackRuntime
  sourceTarget : table.runtimeTargetHolds program.pe descriptor caller
  before : NestedNativeWorldExecution
  targetEntry : NestedNativeWorldExecution
  after : NestedNativeWorldExecution
  beforeShape : before = NestedNativeWorldExecution.running
    table.callInstruction.rva 0 caller calls
    eventIndex events world externalFrames
  targetShape : targetEntry = NestedNativeWorldExecution.running
    descriptor.bridge.entry.rva 0 calleeEntry
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
  exactBridgePath : NonemptyRelatedPath program.transitionSystem
    targetEntry [] after
  frameEffect : NativeX87ReplayNestedFrameEffect table program.pe descriptor
    caller returned logicalInput result

theorem ExactNativeX87ReplayBridgeRun.exactEventFreePath
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    NonemptyRelatedPath program.transitionSystem run.before [] run.after := by
  have first := exactNestedNativeWorldStepIsNonempty program run.before
  rw [run.exactCallStep] at first
  have callPath : NonemptyRelatedPath program.transitionSystem
      run.before [] run.targetEntry := by
    simpa using first
  exact callPath.trans run.exactBridgePath

structure ExactNativeX87ReplayBridgeExecutionRefinement
    (program : ExactNestedNativeWorldProgram)
    (table : NativeX87ReplayBridgeTable)
    (handler : CandidateReplayHandler)
    (sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop) : Prop where
  static : ∃ relocations packs,
    ExactNativeX87ReplayBridgeStaticCertificate table program.pe
      program.imports relocations packs
  targetInventory : program.indirectTargets.targetSet?
    table.callInstruction.rva .call = some table.nativeTargetSet
  runForSource : ∀ descriptor ∈ table.descriptors,
    ∀ caller logicalInput, sourceInvariant descriptor caller logicalInput ->
          ∃ run : ExactNativeX87ReplayBridgeRun program table handler,
        run.descriptor = descriptor ∧ run.caller = caller ∧
          run.logicalInput = logicalInput

/-- Per-target dynamic proof goal consumed by candidate operational authority.
Static target/frame evidence does not inhabit this proposition. -/
def ExactNativeX87ReplayBridgeTargetBinding.RuntimeGoal
    (binding : ExactNativeX87ReplayBridgeTargetBinding
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop) : Prop :=
  program.pe = pe ∧
    program.imports = imports ∧
    program.indirectTargets.targetSet? table.callInstruction.rva .call =
      some table.nativeTargetSet ∧
    ∀ caller logicalInput,
      sourceInvariant binding.descriptor caller logicalInput ->
        ∃ run : ExactNativeX87ReplayBridgeRun program table handler,
          run.descriptor = binding.descriptor ∧ run.caller = caller ∧
            run.logicalInput = logicalInput

theorem ExactNativeX87ReplayBridgeExecutionRefinement.refinesSource
    (certificate : ExactNativeX87ReplayBridgeExecutionRefinement
      program table handler sourceInvariant)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (member : descriptor ∈ table.descriptors)
    (caller logicalInput : MachineState)
    (source : sourceInvariant descriptor caller logicalInput) :
    ∃ run : ExactNativeX87ReplayBridgeRun program table handler,
      run.descriptor = descriptor ∧ run.caller = caller ∧
        run.logicalInput = logicalInput ∧
        NonemptyRelatedPath program.transitionSystem run.before [] run.after := by
  rcases certificate.runForSource descriptor member caller logicalInput source with
    ⟨run, descriptorExact, callerExact, logicalExact⟩
  exact ⟨run, descriptorExact, callerExact, logicalExact,
    run.exactEventFreePath⟩

#print axioms ExactNativeX87ReplayBridgeStaticCertificate.descriptorChecked
#print axioms ExactNativeX87ReplayBridgeRun.exactEventFreePath
#print axioms ExactNativeX87ReplayBridgeExecutionRefinement.refinesSource

end StageA.Relational.InterpreterX87ReplayBridgeTarget
