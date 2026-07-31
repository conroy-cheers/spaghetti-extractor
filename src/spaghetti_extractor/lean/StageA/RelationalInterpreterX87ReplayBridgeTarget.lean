import StageA.RelationalInterpreterKernelCallbackNativeWorldBridge
import StageA.RelationalInterpreterX87

namespace StageA.Relational.InterpreterX87ReplayBridgeTarget

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelCallbackNativeWorldBridge
open StageA.Relational.InterpreterKernelMixedReplay
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

def nativeX87ReplayBridgeBodySize : Nat := 176
def nativeX87ReplayBridgeInstructionOffset : Nat := 52
def nativeX87ReplayBridgeCaptureOffset : Nat := 72
def nativeX87ReplayBridgeReturnOffset : Nat := 171
def nativeX87ReplayBridgeEntryActiveOperandOffset : Nat := 5
def nativeX87ReplayBridgeCaptureActiveOperandOffset : Nat := 75

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
    mapping.instructionRva ==
      mapping.bridgeTargetRva + nativeX87ReplayBridgeInstructionOffset &&
    mapping.captureRva ==
      mapping.bridgeTargetRva + nativeX87ReplayBridgeCaptureOffset &&
    mapping.returnRva ==
      mapping.bridgeTargetRva + nativeX87ReplayBridgeReturnOffset &&
    mapping.bridgeBodyBytes.length == nativeX87ReplayBridgeBodySize &&
    immutableRvaBytes pe imports mapping.bridgeTargetRva
      mapping.bridgeBodyBytes.length == some mapping.bridgeBodyBytes &&
    bytesAt mapping.bridgeBodyBytes [0x55, 0x53, 0x56, 0x57, 0xa1] 0 &&
    bytesAt mapping.bridgeBodyBytes [0x89, 0x60,
      nativeX87FramePrivateEspOffset] 9 &&
    bytesAt mapping.bridgeBodyBytes [0xdd, 0x60,
      nativeX87FrameInputX87Offset] 12 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x40,
      nativeX87FrameInputOffset] 15 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x58, 0x04] 18 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x48, 0x08] 21 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x70, 0x10] 24 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x78, 0x14] 27 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x68, 0x18] 30 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x60, 0x1c] 33 &&
    bytesAt mapping.bridgeBodyBytes [0xff, 0xb0, 0xf0, 0, 0, 0] 36 &&
    bytesAt mapping.bridgeBodyBytes [0xff, 0x30] 42 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x50, 0x0c] 44 &&
    bytesAt mapping.bridgeBodyBytes [0x58, 0x9d, 0x90, 0x90, 0x90] 47 &&
    bytesAt mapping.bridgeBodyBytes descriptor.replay.instructionBytes
      nativeX87ReplayBridgeInstructionOffset &&
    nativeX87ReplayBridgeInstructionOffset +
        descriptor.replay.instructionBytes.length <=
      nativeX87ReplayBridgeCaptureOffset &&
    (mapping.bridgeBodyBytes.drop
        (nativeX87ReplayBridgeInstructionOffset +
          descriptor.replay.instructionBytes.length) |>.take
        (nativeX87ReplayBridgeCaptureOffset -
          nativeX87ReplayBridgeInstructionOffset -
          descriptor.replay.instructionBytes.length)) ==
      List.replicate
        (nativeX87ReplayBridgeCaptureOffset -
          nativeX87ReplayBridgeInstructionOffset -
          descriptor.replay.instructionBytes.length) 0x90 &&
    bytesAt mapping.bridgeBodyBytes [0x9c, 0x50, 0xa1] 72 &&
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
    bytesAt mapping.bridgeBodyBytes [0xdd, 0xb0, 0x80, 0, 0, 0] 79 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x50,
      nativeX87FrameOutputOffset] 85 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x0c, 0x24, 0x89, 0x0a] 88 &&
    bytesAt mapping.bridgeBodyBytes [0xc7, 0x40,
      nativeX87FrameStatusOffset, 0, 0, 0, 0] 156 &&
    bytesAt mapping.bridgeBodyBytes [0x8b, 0x60,
      nativeX87FramePrivateEspOffset] 163 &&
    bytesAt mapping.bridgeBodyBytes
      [0xfc, 0x5f, 0x5e, 0x5b, 0x5d, 0xc3, 0x90, 0x90, 0x90, 0x90] 166 &&
    mapping.instructionPathBytes.length ==
      descriptor.replay.instructionBytes.length &&
    immutableRvaBytes pe imports mapping.instructionRva
      mapping.instructionPathBytes.length == some mapping.instructionPathBytes &&
    mapping.instructionPathBytes == descriptor.replay.instructionBytes

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

def NativeX87ReplayBridgeTable.callChecked
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) : Bool :=
  KernelMixedReplayInstruction.specializedDecodersClear pe
      table.callInstruction &&
    table.descriptors.all (fun descriptor =>
      table.nativeTargetInventory.resolve? pe RelationalWorld.empty
          table.callInstruction.rva .call (descriptor.bridge.address pe) ==
        some (NativeIndirectTargetDescriptor.internalRva
          descriptor.bridge.entry.rva)) &&
    table.callSite.checked pe imports

def NativeX87ReplayBridgeTable.layoutChecked
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
    table.activeFrameLoadInstruction.checked pe imports &&
    table.nativeTargetInventory.valid pe

def NativeX87ReplayBridgeTable.shapeChecked
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation) : Bool :=
  table.callChecked pe imports &&
    table.layoutChecked pe imports relocations

theorem NativeX87ReplayBridgeTable.callSpecializedDecodersClear
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (checked : table.shapeChecked pe imports relocations = true) :
    KernelMixedReplayInstruction.specializedDecodersClear pe
      table.callInstruction = true := by
  unfold NativeX87ReplayBridgeTable.shapeChecked at checked
  unfold NativeX87ReplayBridgeTable.callChecked at checked
  simp only [Bool.and_eq_true] at checked
  exact checked.1.1.1

theorem NativeX87ReplayBridgeTable.resolveDescriptorTarget
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (checked : table.shapeChecked pe imports relocations = true)
    (member : descriptor ∈ table.descriptors) :
    table.nativeTargetInventory.resolve? pe RelationalWorld.empty
        table.callInstruction.rva .call (descriptor.bridge.address pe) =
      some (NativeIndirectTargetDescriptor.internalRva
        descriptor.bridge.entry.rva) := by
  unfold NativeX87ReplayBridgeTable.shapeChecked at checked
  unfold NativeX87ReplayBridgeTable.callChecked at checked
  simp only [Bool.and_eq_true] at checked
  have allResolved := checked.1.1.2
  exact beq_iff_eq.mp
    (List.all_eq_true.mp allResolved descriptor member)

theorem NativeX87ReplayBridgeTable.callSiteChecked
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (checked : table.shapeChecked pe imports relocations = true) :
    table.callSite.checked pe imports = true := by
  unfold NativeX87ReplayBridgeTable.shapeChecked at checked
  unfold NativeX87ReplayBridgeTable.callChecked at checked
  simp only [Bool.and_eq_true] at checked
  exact checked.1.2

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

/-- Address transport for one replay instruction.  Unlisted addresses are
identity-mapped; the instruction VA and each relocated operand target override
that identity mapping. -/
structure NativeX87ReplayAddressMap where
  originalImageBase : Nat
  originalInstructionRva : Nat
  candidateImageBase : Nat
  candidateInstructionRva : Nat
  relocatedDataAddresses : List (Word × Word)

def NativeX87ReplayAddressMap.relocateData
    (addresses : NativeX87ReplayAddressMap) (original : Word) : Word :=
  match addresses.relocatedDataAddresses.find? fun pair => pair.1 == original with
  | some pair => pair.2
  | none => original

def NativeX87ReplayAddressMap.relation
    (addresses : NativeX87ReplayAddressMap) :
    StageA.Relational.X87.AddressRelation := {
  code := fun original candidate =>
    candidate = if original == BitVec.ofNat 32
        (addresses.originalImageBase + addresses.originalInstructionRva)
      then BitVec.ofNat 32
        (addresses.candidateImageBase + addresses.candidateInstructionRva)
      else original
  data := fun original candidate =>
    candidate = addresses.relocateData original
}

def nativeX87ReplayFrameBytes : Nat :=
  nativeX87FrameOutputX87Offset + kernelX87FrameBytes

def nativeX87ReplayFrameFootprint (frameAddress : Word) :
    CandidateFootprint :=
  fun address => ∃ offset, offset < nativeX87ReplayFrameBytes ∧
    address = frameAddress + BitVec.ofNat 32 offset

def nativeX87ReplayByteRange (base : Word) (bytes : Nat) :
    CandidateFootprint :=
  fun address => ∃ offset, offset < bytes ∧
    address = base + BitVec.ofNat 32 offset

def nativeX87ReplayPrivateStackFootprint (caller : MachineState) :
    CandidateFootprint :=
  nativeX87ReplayByteRange
    (caller.registers.esp - BitVec.ofNat 32 20) 20

/-- The fixed bridge restores EAX and EFLAGS through two pushes below logical
ESP; all other registers are loaded directly from the engine state. -/
def nativeX87ReplayLogicalScratchBytes : Nat :=
  2 * 4

def nativeX87ReplayLogicalScratchFootprint (candidateInput : MachineState) :
    CandidateFootprint :=
  nativeX87ReplayByteRange
    (candidateInput.registers.esp -
      BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes)
    nativeX87ReplayLogicalScratchBytes

def nativeX87ReplayOperandFootprint
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (state : MachineState) : CandidateFootprint :=
  match StageA.Relational.X87.commandDataAddress descriptor state with
  | none => fun _ => False
  | some address =>
      let readBytes := descriptor.command.expectedOperandBytes.getD 0
      let writeBytes :=
        descriptor.command.expectedStoreKind.map (·.byteWidth) |>.getD 0
      nativeX87ReplayByteRange address (max readBytes writeBytes)

def CandidateFootprintDisjointFromImage
    (pe : PE32) (footprint : CandidateFootprint) : Prop :=
  ∀ address, footprint address ->
    ¬ (pe.imageBase ≤ address.toNat ∧
      address.toNat < pe.imageBase + pe.sizeOfImage)

def CandidateRepresentationDisjointFromImage
    (pe : PE32) (rep : EngineRep) : Prop :=
  ∀ address, CandidateAddressObserved rep address ->
    ¬ (pe.imageBase ≤ address.toNat ∧
      address.toNat < pe.imageBase + pe.sizeOfImage)

def nativeX87ReplayRuntimeCellFootprint
    (table : NativeX87ReplayBridgeTable) (candidatePe : PE32)
    (descriptor : NativeX87ReplayBridgeDescriptor) : CandidateFootprint :=
  fun address =>
    nativeX87ReplayByteRange
        (BitVec.ofNat 32
          (candidatePe.imageBase + table.activeFramePointerRva)) 4 address ∨
      nativeX87ReplayByteRange
        (descriptor.bridgeCell.address candidatePe) 4 address

/-- Canonical PE32 interpreter-state offsets used by the reviewed native x87
bridge ABI.  Keeping this executable makes source-frame admission reject a
layout whose C representation no longer matches the exact assembly bytes. -/
def nativeX87ReplayEngineFieldOffset? : EngineField -> Option Nat
  | .register .eax => some 0
  | .register .ebx => some 4
  | .register .ecx => some 8
  | .register .edx => some 12
  | .register .esi => some 16
  | .register .edi => some 20
  | .register .ebp => some 24
  | .register .esp => some 28
  | .flag 0 => some 32
  | .flag 6 => some 36
  | .flag 7 => some 40
  | .flag 11 => some 44
  | .flag 2 => some 48
  | .flag 10 => some 52
  | .x87Stack index => if index < 8 then some (56 + 20 * index) else none
  | .x87Empty index => if index < 8 then some (68 + 20 * index) else none
  | .x87Tag index => if index < 8 then some (72 + 20 * index) else none
  | .x87Control => some 216
  | .x87Status => some 218
  | .x87PendingException => some 220
  | .x87LastOpcode => some 222
  | .x87InstructionPointer => some 224
  | .x87CodeSelector => some 228
  | .x87DataPointer => some 232
  | .x87DataSelector => some 236
  | .eflags => some 240
  | .fsBase => some 244
  | .originalRva => some 248
  | _ => none

def nativeX87ReplayRequiredFlagFields : List EngineField :=
  [.flag 0, .flag 2, .flag 6, .flag 7, .flag 10, .flag 11]

def nativeX87ReplayEngineLayoutCompatible (layout : EngineLayout) : Bool :=
  layout.stateSize == 252 && layout.x87StackSlots == 8 &&
    (layout.fields.all fun entry =>
      nativeX87ReplayEngineFieldOffset? entry.field == some entry.offset) &&
    (nativeX87ReplayRequiredFlagFields.all fun field =>
      layout.fields.any fun entry => entry.field == field)

/-- A native frame contains a candidate physical x87 state.  Correctness is a
relation to the logical/original state, not raw equality of metadata pointers
whose instruction and data addresses may be relocated. -/
structure NativeX87ReplayEncodedFrame
    (addresses : NativeX87ReplayAddressMap)
    (logical candidate : StageA.X87.PhysicalState)
    (memory : Memory) (frameAddress : Word) : Prop where
  encoded : Engine.readBytes memory frameAddress kernelX87FrameBytes =
    encodeKernelX87Frame candidate
  related : StageA.Relational.X87.StateRelated addresses.relation
    logical candidate

/-- Concrete source admission for the nested replay call.  Unlike the legacy
caller-supplied invariant, this predicate carries the engine representation,
frame chain, exact dynamic call target, frame/engine disjointness, candidate
input encoding, and decoded command-input relation needed by execution. -/
structure NativeX87ReplayBridgeSourceFrameEvidence
    (table : NativeX87ReplayBridgeTable)
    (originalPe candidatePe : PE32)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (addresses : NativeX87ReplayAddressMap)
    (caller logicalInput : MachineState) where
  rep : EngineRep
  candidateInput : MachineState
  engineRelated : Engine.StateRelated rep
    (fun expected actual : Nat => expected = actual)
    descriptor.replay.rvaStart addresses.candidateInstructionRva
    logicalInput candidateInput
  engineAddressRelation :
    rep.x87AddressRelation = addresses.relation
  candidateMemory : candidateInput.memory = caller.memory
  callerSemantics : caller.x87Semantics = rep.x87Semantics
  layoutCompatible : nativeX87ReplayEngineLayoutCompatible rep.layout = true
  commandInput : X87SingletonCommandInputRelated addresses.relation originalPe
    candidatePe (replayInstructionRecord descriptor.replay)
    (replayInstructionRecordAt descriptor.replay addresses.candidateInstructionRva)
    logicalInput candidateInput
  frameAddress : Word
  frameAddressNonzero : frameAddress != BitVec.ofNat 32 0
  inputX87FrameAddressValid : kernelX87FrameAddressValid
    (frameAddress + BitVec.ofNat 32 nativeX87FrameInputX87Offset) = true
  outputX87FrameAddressValid : kernelX87FrameAddressValid
    (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset) = true
  parentAddress : Word
  inputAddress : Word
  outputAddress : Word
  inputOutputAlias : inputAddress = outputAddress
  engineBase : rep.engineBase = outputAddress
  memoryUnmapped : rep.memoryAddress = fun _ => none
  descriptorMember : descriptor ∈ table.descriptors
  callTarget : table.callSite.targetWord caller =
    descriptor.bridge.address candidatePe
  targetBefore : descriptor.bridgeCell.Holds candidatePe descriptor.bridge caller
  activeBefore : Memory.read32 caller.memory
      (BitVec.ofNat 32
        (candidatePe.imageBase + table.activeFramePointerRva)) = frameAddress
  parentBefore : Memory.read32 caller.memory
      (frameAddress + BitVec.ofNat 32 nativeX87FrameParentOffset) = parentAddress
  inputPointer : Memory.read32 caller.memory
      (frameAddress + BitVec.ofNat 32 nativeX87FrameInputOffset) = inputAddress
  outputPointer : Memory.read32 caller.memory
      (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputOffset) = outputAddress
  representationDisjointImage :
    CandidateRepresentationDisjointFromImage candidatePe rep
  stackDisjoint : FootprintDisjointFromRepresentation rep
    (nativeX87ReplayFrameFootprint frameAddress)
  frameDisjointImage : CandidateFootprintDisjointFromImage candidatePe
    (nativeX87ReplayFrameFootprint frameAddress)
  frameDisjointOperand : CandidateFootprintsDisjoint
    (nativeX87ReplayFrameFootprint frameAddress)
    (nativeX87ReplayOperandFootprint commandInput.candidateDescriptor
      candidateInput)
  privateStackPointerNonzero :
    caller.registers.esp - BitVec.ofNat 32 20 != BitVec.ofNat 32 0
  privateStackAddressValid :
    (caller.registers.esp - BitVec.ofNat 32 20).toNat + 20 <= 2 ^ 32
  privateStackDisjointFrame : CandidateFootprintsDisjoint
    (nativeX87ReplayPrivateStackFootprint caller)
    (nativeX87ReplayFrameFootprint frameAddress)
  privateStackDisjointRepresentation : FootprintDisjointFromRepresentation rep
    (nativeX87ReplayPrivateStackFootprint caller)
  privateStackDisjointOperand : CandidateFootprintsDisjoint
    (nativeX87ReplayPrivateStackFootprint caller)
    (nativeX87ReplayOperandFootprint commandInput.candidateDescriptor
      candidateInput)
  privateStackDisjointImage : CandidateFootprintDisjointFromImage candidatePe
    (nativeX87ReplayPrivateStackFootprint caller)
  logicalScratchDisjointFrame : CandidateFootprintsDisjoint
    (nativeX87ReplayLogicalScratchFootprint candidateInput)
    (nativeX87ReplayFrameFootprint frameAddress)
  logicalScratchAddressValid :
    (candidateInput.registers.esp -
        BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes).toNat +
      nativeX87ReplayLogicalScratchBytes <= 2 ^ 32
  logicalScratchDisjointPrivateStack : CandidateFootprintsDisjoint
    (nativeX87ReplayLogicalScratchFootprint candidateInput)
    (nativeX87ReplayPrivateStackFootprint caller)
  logicalScratchDisjointRepresentation :
    FootprintDisjointFromRepresentation rep
      (nativeX87ReplayLogicalScratchFootprint candidateInput)
  logicalScratchDisjointOperand : CandidateFootprintsDisjoint
    (nativeX87ReplayLogicalScratchFootprint candidateInput)
    (nativeX87ReplayOperandFootprint commandInput.candidateDescriptor
      candidateInput)
  logicalScratchDisjointImage : CandidateFootprintDisjointFromImage candidatePe
    (nativeX87ReplayLogicalScratchFootprint candidateInput)
  operandDisjointRepresentation : FootprintDisjointFromRepresentation rep
    (nativeX87ReplayOperandFootprint commandInput.candidateDescriptor
      candidateInput)
  operandDisjointRuntimeCells : CandidateFootprintsDisjoint
    (nativeX87ReplayOperandFootprint commandInput.candidateDescriptor
      candidateInput)
    (nativeX87ReplayRuntimeCellFootprint table candidatePe descriptor)
  inputCandidate : StageA.X87.PhysicalState
  inputFrame : NativeX87ReplayEncodedFrame addresses logicalInput.x87Physical
    inputCandidate caller.memory
    (frameAddress + BitVec.ofNat 32 nativeX87FrameInputX87Offset)
  inputCandidateRepresentable :
    KernelX87PhysicalStateRepresentable inputCandidate
  candidateX87 : candidateInput.x87Physical = inputCandidate
  faultFree :
    (logicalInput.x87Semantics.execute commandInput.originalDescriptor.command
      commandInput.originalDescriptor.waitMode logicalInput.x87Physical
      (StageA.Relational.X87.commandStepInput originalPe descriptor.replay.rvaStart
        commandInput.originalDescriptor logicalInput)).fault = none

/-- Proposition-level source-frame predicate.  Execution certificates retain
the evidence witness so its engine, frame, and input data can be consumed
constructively. -/
def NativeX87ReplayBridgeSourceFrame
    (table : NativeX87ReplayBridgeTable)
    (originalPe candidatePe : PE32)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (addresses : NativeX87ReplayAddressMap)
    (caller logicalInput : MachineState) : Prop :=
  Nonempty (NativeX87ReplayBridgeSourceFrameEvidence table originalPe candidatePe
    descriptor addresses caller logicalInput)

theorem NativeX87ReplayBridgeSourceFrameEvidence.runtimeTargetHolds
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe candidatePe
      descriptor addresses caller logicalInput) :
    table.runtimeTargetHolds candidatePe descriptor caller :=
  ⟨source.descriptorMember, source.callTarget, source.targetBefore⟩

theorem NativeX87ReplayBridgeSourceFrameEvidence.activeFrameNonzero
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe candidatePe
      descriptor addresses caller logicalInput) :
    Memory.read32 caller.memory
        (BitVec.ofNat 32
          (candidatePe.imageBase + table.activeFramePointerRva)) !=
      BitVec.ofNat 32 0 := by
  rw [source.activeBefore]
  exact source.frameAddressNonzero

/-- Read one present engine field at its canonical native ABI offset. -/
theorem NativeX87ReplayBridgeSourceFrameEvidence.readPresentFieldAtOffset
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe candidatePe
      descriptor addresses caller logicalInput)
    (entry : EngineFieldLayout) (offset : Nat)
    (member : entry ∈ source.rep.layout.fields)
    (canonical :
      nativeX87ReplayEngineFieldOffset? entry.field = some offset) :
    some (Engine.readBytes caller.memory
      (source.outputAddress + BitVec.ofNat 32 offset)
      entry.field.byteWidth) =
        source.rep.fieldBytes logicalInput descriptor.replay.rvaStart
          entry.field := by
  have layout := source.layoutCompatible
  unfold nativeX87ReplayEngineLayoutCompatible at layout
  simp only [Bool.and_eq_true] at layout
  have entryOffset := List.all_eq_true.mp layout.1.2 entry member
  simp only [canonical, beq_iff_eq, Option.some.injEq] at entryOffset
  have represented := source.engineRelated.fields entry member
  simpa [EngineFieldHolds, EngineFieldLayout.address, entryOffset,
    source.engineBase, source.candidateMemory] using represented

/-- Read one required engine field at the canonical native ABI offset.  Field
existence comes from `EngineRep.Valid`; the fixed offset comes from the checked
native layout.  This is the common authority used by bridge register, flag, and
metadata loads. -/
theorem NativeX87ReplayBridgeSourceFrameEvidence.readRequiredFieldAtOffset
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe candidatePe
      descriptor addresses caller logicalInput)
    (field : EngineField) (offset : Nat)
    (required : field ∈ source.rep.layout.requiredFields)
    (canonical : nativeX87ReplayEngineFieldOffset? field = some offset) :
    some (Engine.readBytes caller.memory
      (source.outputAddress + BitVec.ofNat 32 offset) field.byteWidth) =
        source.rep.fieldBytes logicalInput descriptor.replay.rvaStart field := by
  rcases source.engineRelated.repValid.1 with
    ⟨_stateSizePositive, _stateSizeBound, _fieldsNodup, _fieldsValid,
      _fieldsDisjoint, fieldsComplete⟩
  have fieldMapped := fieldsComplete field required
  rcases List.mem_map.mp fieldMapped with
    ⟨entry, entryMember, entryField⟩
  have represented := source.readPresentFieldAtOffset entry offset entryMember
    (by simpa [entryField] using canonical)
  simpa [entryField] using represented

/-- The native bridge's 32-bit loads consume the same little-endian encoding
used by `EngineRep.fieldBytes`. -/
theorem Memory.read32_eq_of_engineBytes4
    (memory : Memory) (address value : Word)
    (encoded : Engine.readBytes memory address 4 =
      Engine.encodeLittleEndian 4 value.toNat) :
    Memory.read32 memory address = value := by
  have byte0 := congrArg (fun bytes => bytes[0]!) encoded
  have byte1 := congrArg (fun bytes => bytes[1]!) encoded
  have byte2 := congrArg (fun bytes => bytes[2]!) encoded
  have byte3 := congrArg (fun bytes => bytes[3]!) encoded
  simp [Engine.readBytes, Engine.encodeLittleEndian] at byte0 byte1 byte2 byte3
  unfold Memory.read32
  dsimp only
  rw [byte0, byte1, byte2, byte3]
  let d0 := value.toNat % 256
  let d1 := value.toNat / 256 % 256
  let d2 := value.toNat / 65536 % 256
  let d3 := value.toNat / 16777216 % 256
  have d0Bound : d0 < 256 := Nat.mod_lt _ (by decide)
  have d1Bound : d1 < 256 := Nat.mod_lt _ (by decide)
  have d2Bound : d2 < 256 := Nat.mod_lt _ (by decide)
  have d3Bound : d3 < 256 := Nat.mod_lt _ (by decide)
  have byte0Exact :
      BitVec.ofNat 8 value.toNat = BitVec.ofNat 8 d0 := by
    apply BitVec.eq_of_toNat_eq
    simp [d0]
  have byte1Exact :
      BitVec.ofNat 8 (value.toNat / 256) = BitVec.ofNat 8 d1 := by
    apply BitVec.eq_of_toNat_eq
    simp [d1]
  have byte2Exact :
      BitVec.ofNat 8 (value.toNat / 65536) = BitVec.ofNat 8 d2 := by
    apply BitVec.eq_of_toNat_eq
    simp [d2]
  have byte3Exact :
      BitVec.ofNat 8 (value.toNat / 16777216) = BitVec.ofNat 8 d3 := by
    apply BitVec.eq_of_toNat_eq
    simp [d3]
  have byte0Width :
      BitVec.setWidth 8 value = BitVec.ofNat 8 d0 := by
    simpa using byte0Exact
  rw [byte0Width, byte1Exact, byte2Exact, byte3Exact,
    fourBytesAssembleLittleEndian d0 d1 d2 d3 d0Bound d1Bound d2Bound d3Bound]
  have valueBound : value.toNat < 4294967296 := by
    simpa using value.isLt
  have decomposition :
      d0 + d1 * 256 + d2 * 65536 + d3 * 16777216 = value.toNat := by
    dsimp [d0, d1, d2, d3]
    omega
  rw [decomposition]
  apply BitVec.eq_of_toNat_eq
  simp

theorem NativeX87ReplayBridgeSourceFrameEvidence.readRegisterAtOffset
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe candidatePe
      descriptor addresses caller logicalInput)
    (register : Reg) (offset : Nat)
    (canonical :
      nativeX87ReplayEngineFieldOffset? (.register register) = some offset) :
    Memory.read32 caller.memory
        (source.outputAddress + BitVec.ofNat 32 offset) =
      logicalInput.registers.get register := by
  have required :
      EngineField.register register ∈ source.rep.layout.requiredFields := by
    cases register <;>
      simp [EngineLayout.requiredFields, allRegisters]
  have represented := source.readRequiredFieldAtOffset
    (.register register) offset required canonical
  have encoded :
      Engine.readBytes caller.memory
          (source.outputAddress + BitVec.ofNat 32 offset) 4 =
        Engine.encodeLittleEndian 4
          (logicalInput.registers.get register).toNat := by
    simpa [EngineRep.fieldBytes, EngineField.byteWidth] using represented
  exact Memory.read32_eq_of_engineBytes4 _ _ _ encoded

theorem NativeX87ReplayBridgeSourceFrameEvidence.readInputRegisterAtOffset
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe candidatePe
      descriptor addresses caller logicalInput)
    (register : Reg) (offset : Nat)
    (canonical :
      nativeX87ReplayEngineFieldOffset? (.register register) = some offset) :
    Memory.read32 caller.memory
        (source.inputAddress + BitVec.ofNat 32 offset) =
      logicalInput.registers.get register := by
  rw [source.inputOutputAlias]
  exact source.readRegisterAtOffset register offset canonical

theorem NativeX87ReplayBridgeSourceFrameEvidence.readEflags
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe candidatePe
      descriptor addresses caller logicalInput) :
    Memory.read32 caller.memory
        (source.outputAddress + BitVec.ofNat 32 240) =
      logicalInput.eflags := by
  have required : EngineField.eflags ∈ source.rep.layout.requiredFields := by
    simp [EngineLayout.requiredFields]
  have represented := source.readRequiredFieldAtOffset
    .eflags 240 required (by decide)
  have encoded :
      Engine.readBytes caller.memory
          (source.outputAddress + BitVec.ofNat 32 240) 4 =
        Engine.encodeLittleEndian 4 logicalInput.eflags.toNat := by
    simpa [EngineRep.fieldBytes, EngineField.byteWidth] using represented
  exact Memory.read32_eq_of_engineBytes4 _ _ _ encoded

theorem NativeX87ReplayBridgeSourceFrameEvidence.readInputEflags
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe candidatePe
      descriptor addresses caller logicalInput) :
    Memory.read32 caller.memory
        (source.inputAddress + BitVec.ofNat 32 240) =
      logicalInput.eflags := by
  rw [source.inputOutputAlias]
  exact source.readEflags

theorem NativeX87ReplayBridgeSourceFrameEvidence.flagFieldPresent
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe candidatePe
      descriptor addresses caller logicalInput)
    (bit : Nat)
    (required : EngineField.flag bit ∈ nativeX87ReplayRequiredFlagFields) :
    ∃ entry ∈ source.rep.layout.fields, entry.field = .flag bit := by
  have layout := source.layoutCompatible
  unfold nativeX87ReplayEngineLayoutCompatible at layout
  simp only [Bool.and_eq_true] at layout
  have present :=
    List.all_eq_true.mp layout.2 (EngineField.flag bit) required
  simpa only [List.any_eq_true, beq_iff_eq] using present

theorem NativeX87ReplayBridgeSourceFrameEvidence.readFlagAtOffset
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe candidatePe
      descriptor addresses caller logicalInput)
    (bit offset : Nat)
    (required : EngineField.flag bit ∈ nativeX87ReplayRequiredFlagFields)
    (canonical :
      nativeX87ReplayEngineFieldOffset? (.flag bit) = some offset) :
    Memory.read32 caller.memory
        (source.outputAddress + BitVec.ofNat 32 offset) =
      BitVec.ofNat 32 (logicalInput.eflags.extractLsb' bit 1).toNat := by
  rcases source.flagFieldPresent bit required with
    ⟨entry, member, fieldExact⟩
  have represented := source.readPresentFieldAtOffset entry offset member
    (by simpa [fieldExact] using canonical)
  have encoded :
      Engine.readBytes caller.memory
          (source.outputAddress + BitVec.ofNat 32 offset) 4 =
        Engine.encodeLittleEndian 4
          (logicalInput.eflags.extractLsb' bit 1).toNat := by
    simpa [fieldExact, EngineRep.fieldBytes, EngineField.byteWidth] using
      represented
  have valueBound :
      (logicalInput.eflags.extractLsb' bit 1).toNat < 2 ^ 32 := by
    have oneBitBound := (logicalInput.eflags.extractLsb' bit 1).isLt
    omega
  have widened :
      (BitVec.ofNat 32
        (logicalInput.eflags.extractLsb' bit 1).toNat).toNat =
          (logicalInput.eflags.extractLsb' bit 1).toNat := by
    rw [BitVec.toNat_ofNat]
    exact Nat.mod_eq_of_lt valueBound
  apply Memory.read32_eq_of_engineBytes4 _ _ _
  simpa only [widened] using encoded

/-- Fields whose authoritative post-state representation is carried by the
separate FNSAVE image until the enclosing C wrapper unpacks it. -/
def nativeX87ReplaySeparateFrameField : EngineField -> Bool
  | .x87Stack _ | .x87Empty _ | .x87Tag _ | .x87Control | .x87Status |
      .x87PendingException | .x87LastOpcode | .x87InstructionPointer |
      .x87CodeSelector | .x87DataPointer | .x87DataSelector => true
  | _ => false

/-- Check the finite non-x87 engine-state projection written by the assembly
bridge.  This is executable evidence over the exact returned memory, not a
submitted post-state relation. -/
def nativeX87ReplayNonX87OutputChecked
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe pe
      descriptor addresses caller logicalInput)
    (returned logicalAfter : MachineState) : Bool :=
  source.rep.layout.fields.all fun entry =>
    nativeX87ReplaySeparateFrameField entry.field ||
      some (Engine.readBytes returned.memory
        (entry.address source.rep.engineBase) entry.field.byteWidth) ==
        source.rep.fieldBytes logicalAfter descriptor.replay.rvaStart entry.field

theorem nativeX87ReplayNonX87OutputChecked_sound
    (source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe pe
      descriptor addresses caller logicalInput)
    (returned logicalAfter : MachineState)
    (checked : nativeX87ReplayNonX87OutputChecked source returned logicalAfter =
      true)
    (entry : EngineFieldLayout) (member : entry ∈ source.rep.layout.fields)
    (separate : nativeX87ReplaySeparateFrameField entry.field = false) :
    EngineFieldHolds source.rep logicalAfter descriptor.replay.rvaStart
      returned.memory entry := by
  have entryChecked := List.all_eq_true.mp checked entry member
  simp [separate] at entryChecked
  exact entryChecked

/-- Related singleton memory observations use the checked replay data-address
map.  This finite relation covers reads and writes; helper-frame writes remain
outside the singleton effect inventory. -/
def nativeX87ReplayMemoryEffectRelated
    (addresses : NativeX87ReplayAddressMap) :
    MemoryEffect -> MemoryEffect -> Bool
  | .read originalAddress originalBytes originalValue,
      .read candidateAddress candidateBytes candidateValue =>
      candidateAddress == addresses.relocateData originalAddress &&
        candidateBytes == originalBytes && candidateValue == originalValue
  | .write originalAddress originalBytes originalValue,
      .write candidateAddress candidateBytes candidateValue =>
      candidateAddress == addresses.relocateData originalAddress &&
        candidateBytes == originalBytes && candidateValue == originalValue
  | _, _ => false

def nativeX87ReplayMemoryEffectsRelated
    (addresses : NativeX87ReplayAddressMap) :
    List MemoryEffect -> List MemoryEffect -> Bool
  | [], [] => true
  | original :: originalTail, candidate :: candidateTail =>
      nativeX87ReplayMemoryEffectRelated addresses original candidate &&
        nativeX87ReplayMemoryEffectsRelated addresses originalTail candidateTail
  | _, _ => false

/-- Executable specialization of the replay address relation for two complete
physical x87 states.  This avoids trusting a submitted `StateRelated` proof in
the fixed-template certificate. -/
def nativeX87ReplayPhysicalStatesRelatedChecked
    (addresses : NativeX87ReplayAddressMap)
    (original candidate : StageA.X87.PhysicalState) : Bool :=
  original.core == candidate.core &&
    original.lastOpcode == candidate.lastOpcode &&
    candidate.instructionPointer ==
      (if original.instructionPointer == BitVec.ofNat 32
          (addresses.originalImageBase + addresses.originalInstructionRva)
        then BitVec.ofNat 32
          (addresses.candidateImageBase + addresses.candidateInstructionRva)
        else original.instructionPointer) &&
    original.codeSelector == candidate.codeSelector &&
    candidate.dataPointer == addresses.relocateData original.dataPointer &&
    original.dataSelector == candidate.dataSelector

theorem nativeX87ReplayPhysicalStatesRelatedChecked_sound
    (addresses : NativeX87ReplayAddressMap)
    (original candidate : StageA.X87.PhysicalState)
    (checked : nativeX87ReplayPhysicalStatesRelatedChecked addresses original
      candidate = true) :
    StageA.Relational.X87.StateRelated addresses.relation original candidate := by
  simp only [nativeX87ReplayPhysicalStatesRelatedChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  refine ⟨checked.1.1.1.1.1, checked.1.1.1.1.2, ?_,
    checked.1.1.2, ?_, checked.2⟩
  · simpa [NativeX87ReplayAddressMap.relation] using checked.1.1.1.2
  · simpa [NativeX87ReplayAddressMap.relation] using checked.1.2

/-- The executable replay relation is complete for its proposition-level
specialization. This lets the generic relational x87 theorem construct the
checked evidence consumed by the fixed bridge instead of requiring a generated
Boolean-success assumption for every replay target. -/
theorem nativeX87ReplayPhysicalStatesRelatedChecked_complete
    (addresses : NativeX87ReplayAddressMap)
    (original candidate : StageA.X87.PhysicalState)
    (related :
      StageA.Relational.X87.StateRelated addresses.relation original candidate) :
    nativeX87ReplayPhysicalStatesRelatedChecked addresses original candidate =
      true := by
  rcases related with
    ⟨core, opcode, instruction, codeSelector, data, dataSelector⟩
  simp only [nativeX87ReplayPhysicalStatesRelatedChecked, Bool.and_eq_true,
    beq_iff_eq]
  refine ⟨⟨⟨⟨⟨core, opcode⟩, ?_⟩, codeSelector⟩, ?_⟩, dataSelector⟩
  · simpa [NativeX87ReplayAddressMap.relation] using instruction
  · simpa [NativeX87ReplayAddressMap.relation] using data

/-- Complete state relation available immediately after the nested assembly
bridge returns.  The enclosing C wrapper has not yet unpacked the FNSAVE image,
so x87 fields are related through `outputFrame`; all other engine fields are
checked directly in returned memory.  The interpreter profile has no directly
mapped architectural memory, and singleton memory effects are paired
explicitly. -/
structure NativeX87ReplayMixedPostStateRelated
    (table : NativeX87ReplayBridgeTable) (originalPe pe : PE32)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (addresses : NativeX87ReplayAddressMap)
    (caller returned logicalInput : MachineState)
    (result : StepResult) : Type where
  source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe pe descriptor
    addresses caller logicalInput
  candidateExecutionInput : MachineState
  candidateResult : StepResult
  candidatePhysicalInput :
    candidateExecutionInput.x87Physical = source.candidateInput.x87Physical
  candidateCommandInput :
    StageA.Relational.X87.commandStepInput pe addresses.candidateInstructionRva
        source.commandInput.candidateDescriptor candidateExecutionInput =
      StageA.Relational.X87.commandStepInput pe addresses.candidateInstructionRva
        source.commandInput.candidateDescriptor source.candidateInput
  layoutCompatible :
    nativeX87ReplayEngineLayoutCompatible source.rep.layout = true
  outputEngineBase : source.rep.engineBase = source.outputAddress
  architecturalMemoryUnmapped : source.rep.memoryAddress = fun _ => none
  faultFree : result.faults = [] ∧ candidateResult.faults = []
  nonX87Output :
    nativeX87ReplayNonX87OutputChecked source returned result.state = true
  memoryEffects :
    nativeX87ReplayMemoryEffectsRelated addresses result.memoryEffects
      candidateResult.memoryEffects = true
  physicalState :
    nativeX87ReplayPhysicalStatesRelatedChecked addresses
      result.state.x87Physical candidateResult.state.x87Physical = true
  logicalUndefinedValue :
    result.state.undefinedValue = logicalInput.undefinedValue
  candidateUndefinedValue :
    candidateResult.state.undefinedValue =
      candidateExecutionInput.undefinedValue
  logicalLegacyX87 : result.state.x87 = logicalInput.x87
  candidateLegacyX87 :
    candidateResult.state.x87 = candidateExecutionInput.x87
  logicalSemantics :
    result.state.x87Semantics = logicalInput.x87Semantics
  candidateSemantics :
    candidateResult.state.x87Semantics =
      candidateExecutionInput.x87Semantics
  sharedSemantics : logicalInput.x87Semantics = caller.x87Semantics
  logicalFsBase : result.state.fsBase = logicalInput.fsBase
  candidateFsBase :
    candidateResult.state.fsBase = candidateExecutionInput.fsBase
  outputFrame : NativeX87ReplayEncodedFrame addresses
    result.state.x87Physical candidateResult.state.x87Physical returned.memory
    (source.frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)

/-- Exact runtime effects of the generated nested x87 frame.  The output frame
is encoded as a candidate physical state and related to the logical replay
result under the explicit replay address map. -/
structure NativeX87ReplayNestedFrameEffect
    (table : NativeX87ReplayBridgeTable) (originalPe pe : PE32)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (addresses : NativeX87ReplayAddressMap)
    (caller returned logicalInput : MachineState) (result : StepResult) where
  source : NativeX87ReplayBridgeSourceFrameEvidence table originalPe pe descriptor
    addresses caller logicalInput
  targetAfter : descriptor.bridgeCell.Holds pe descriptor.bridge returned
  activeAfter :
    Memory.read32 returned.memory
      (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) =
        source.frameAddress
  parentAfter : Memory.read32 returned.memory
      (source.frameAddress + BitVec.ofNat 32 nativeX87FrameParentOffset) =
        source.parentAddress
  privateStackEstablished : Memory.read32 returned.memory
      (source.frameAddress + BitVec.ofNat 32 nativeX87FramePrivateEspOffset) !=
        BitVec.ofNat 32 0
  statusSucceeded : Memory.read32 returned.memory
      (source.frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset) =
        BitVec.ofNat 32 0
  outputCandidate : StageA.X87.PhysicalState
  outputFrame : NativeX87ReplayEncodedFrame addresses result.state.x87Physical
    outputCandidate returned.memory
    (source.frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
  mixedPost : NativeX87ReplayMixedPostStateRelated table originalPe pe descriptor
    addresses caller returned logicalInput result

def NativeX87ReplayNestedFrameEffect.frameAddress
    (effect : NativeX87ReplayNestedFrameEffect table originalPe pe descriptor
      addresses caller returned logicalInput result) : Word :=
  effect.source.frameAddress

def NativeX87ReplayNestedFrameEffect.parentAddress
    (effect : NativeX87ReplayNestedFrameEffect table originalPe pe descriptor
      addresses caller returned logicalInput result) : Word :=
  effect.source.parentAddress

structure ExactNativeX87ReplayBridgeRun
    (program : ExactNestedNativeWorldProgram)
    (table : NativeX87ReplayBridgeTable)
    (handler : CandidateReplayHandler) where
  originalPe : PE32
  descriptor : NativeX87ReplayBridgeDescriptor
  addresses : NativeX87ReplayAddressMap
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
  frameEffect : NativeX87ReplayNestedFrameEffect table originalPe program.pe
    descriptor addresses caller returned logicalInput result

theorem ExactNativeX87ReplayBridgeRun.sourceTarget
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    table.runtimeTargetHolds program.pe run.descriptor run.caller :=
  run.frameEffect.source.runtimeTargetHolds

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
  execution : ∃ (originalPe : PE32)
      (addresses : NativeX87ReplayBridgeDescriptor -> NativeX87ReplayAddressMap),
    (∀ descriptor ∈ table.descriptors,
      ∀ caller logicalInput, sourceInvariant descriptor caller logicalInput ->
        NativeX87ReplayBridgeSourceFrame table originalPe program.pe descriptor
          (addresses descriptor) caller logicalInput) ∧
    ∀ descriptor ∈ table.descriptors,
      ∀ caller logicalInput, sourceInvariant descriptor caller logicalInput ->
        ∃ run : ExactNativeX87ReplayBridgeRun program table handler,
          run.descriptor = descriptor ∧ run.caller = caller ∧
            run.logicalInput = logicalInput ∧ run.originalPe = originalPe ∧
            run.addresses = addresses descriptor

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
    ∃ originalPe addresses,
      (∀ caller logicalInput,
        sourceInvariant binding.descriptor caller logicalInput ->
          NativeX87ReplayBridgeSourceFrame table originalPe program.pe
            binding.descriptor addresses caller logicalInput) ∧
      ∀ caller logicalInput,
        sourceInvariant binding.descriptor caller logicalInput ->
          ∃ run : ExactNativeX87ReplayBridgeRun program table handler,
            run.descriptor = binding.descriptor ∧ run.caller = caller ∧
              run.logicalInput = logicalInput ∧ run.originalPe = originalPe ∧
              run.addresses = addresses

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
  rcases certificate.execution with
    ⟨_originalPe, _addresses, _sourceEntails, runForSource⟩
  rcases runForSource descriptor member caller logicalInput source with
    ⟨run, descriptorExact, callerExact, logicalExact, _, _⟩
  exact ⟨run, descriptorExact, callerExact, logicalExact,
    run.exactEventFreePath⟩

#print axioms ExactNativeX87ReplayBridgeStaticCertificate.descriptorChecked
#print axioms nativeX87ReplayPhysicalStatesRelatedChecked_complete
#print axioms ExactNativeX87ReplayBridgeRun.exactEventFreePath
#print axioms ExactNativeX87ReplayBridgeExecutionRefinement.refinesSource

end StageA.Relational.InterpreterX87ReplayBridgeTarget
