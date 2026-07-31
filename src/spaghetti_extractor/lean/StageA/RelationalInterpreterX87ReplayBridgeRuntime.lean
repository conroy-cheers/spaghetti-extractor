import StageA.RelationalInterpreterX87ReplayBridgeTarget
import StageA.RelationalInterpreterKernelMixedReplay

namespace StageA.Relational.InterpreterX87ReplayBridgeRuntime

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterKernelMixedReplay
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
  [0x89, 0x60, 0x0c, 0xdd, 0x60, 0x14, 0x8b, 0x40, 0x04, 0x8b,
   0x58, 0x04, 0x8b, 0x48, 0x08, 0x8b, 0x70, 0x10, 0x8b, 0x78,
   0x14, 0x8b, 0x68, 0x18, 0x8b, 0x60, 0x1c, 0xff, 0xb0, 0xf0,
   0x00, 0x00, 0x00, 0xff, 0x30, 0x8b, 0x50, 0x0c, 0x58, 0x9d,
   0x90, 0x90, 0x90]

def nativeX87ReplayBridgeTemplateCaptureBody : Bytes :=
  [0xdd, 0xb0, 0x80, 0x00, 0x00, 0x00, 0x8b, 0x50, 0x08, 0x8b,
   0x0c, 0x24, 0x89, 0x0a, 0x0f, 0x92, 0x42, 0x20, 0x0f, 0x9a,
   0x42, 0x30, 0x0f, 0x94, 0x42, 0x24, 0x0f, 0x98, 0x42, 0x28,
   0x0f, 0x90, 0x42, 0x2c, 0x8b, 0x5c, 0x24, 0x04, 0x8b, 0x48,
   0x04, 0x8b, 0x89, 0xf0, 0x00, 0x00, 0x00, 0x81, 0xe1, 0x2a,
   0xf3, 0xff, 0xff, 0x81, 0xe3, 0xd5, 0x0c, 0x00, 0x00, 0x09,
   0xd9, 0x89, 0x8a, 0xf0, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90,
   0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc7, 0x40, 0x10,
   0x00, 0x00, 0x00, 0x00, 0x8b, 0x60, 0x0c, 0xfc, 0x5f, 0x5e,
   0x5b, 0x5d, 0xc3, 0x90, 0x90, 0x90, 0x90]

structure NativeX87ReplayFixedTemplateSchedule where
  entryFuel : Nat
  entryFuelPositive : 0 < entryFuel
  instructionFuel : Nat
  instructionFuelPositive : 0 < instructionFuel
  captureFuel : Nat
  captureFuelPositive : 0 < captureFuel
  returnFuel : Nat
  returnFuelPositive : 0 < returnFuel

def nativeX87ReplayBridgeEntryScheduleSize : Nat :=
  nativeX87ReplayBridgeInstructionOffset

def nativeX87ReplayBridgeCaptureScheduleSize : Nat :=
  nativeX87ReplayBridgeReturnOffset - nativeX87ReplayBridgeCaptureOffset

def nativeX87ReplayOpcodeLead (opcode : Byte) : Bool :=
  opcode == 0x9b || (0xd8 <= opcode && opcode <= 0xdf)

/-- Decode one instruction boundary with the same fail-closed precedence used
by `stepKernelPE32Instruction`.  The returned size is accepted only when it
consumes a nonempty prefix of the submitted phase bytes. -/
def decodeNativeX87ReplayInstructionSize? (bytes : Bytes) : Option Nat :=
  let size? :=
    match decodeKernelX87FrameExact bytes with
    | some decoded => some decoded.size
    | none =>
        match StageA.Relational.X87.decodeCommandExact bytes with
        | some decoded => some decoded.size
        | none =>
            match bytes.head? with
            | some opcode =>
                if nativeX87ReplayOpcodeLead opcode then none
                else (decodeInstructionExact bytes).map
                  (fun decoded : DecodedInstruction => decoded.size)
            | none => none
  size?.bind fun size =>
    if size == 0 || bytes.length < size then none else some size

/-- Count a complete decoded instruction schedule.  Fuel bounds the decoder
itself; leftover or undecodable bytes make the schedule fail closed. -/
def decodeNativeX87ReplayScheduleFuel : Nat -> Bytes -> Option Nat
  | 0, [] => some 0
  | 0, _ :: _ => none
  | _ + 1, [] => some 0
  | fuel + 1, bytes => do
      let size <- decodeNativeX87ReplayInstructionSize? bytes
      let count <- decodeNativeX87ReplayScheduleFuel fuel (bytes.drop size)
      some (count + 1)

def decodeNativeX87ReplaySchedule? (bytes : Bytes) : Option Nat :=
  decodeNativeX87ReplayScheduleFuel (bytes.length + 1) bytes

/-- Recover all four phase fuels from exact candidate bytes.  No generated
transfer identity or GNU-specific rule participates in this construction. -/
def nativeX87ReplayFixedTemplateSchedule?
    (mapping : NativeX87ReplayBridgeFrameMapping) :
    Option NativeX87ReplayFixedTemplateSchedule := do
  let entryFuel <- decodeNativeX87ReplaySchedule?
    (mapping.bridgeBodyBytes.take nativeX87ReplayBridgeEntryScheduleSize)
  let instructionFuel <- decodeNativeX87ReplaySchedule?
    mapping.instructionPathBytes
  let captureFuel <- decodeNativeX87ReplaySchedule?
    ((mapping.bridgeBodyBytes.drop nativeX87ReplayBridgeCaptureOffset).take
      nativeX87ReplayBridgeCaptureScheduleSize)
  let returnFuel <- decodeNativeX87ReplaySchedule?
    ((mapping.bridgeBodyBytes.drop nativeX87ReplayBridgeReturnOffset).take 1)
  if positive : 0 < entryFuel ∧ 0 < instructionFuel ∧ 0 < captureFuel ∧
      0 < returnFuel then
    some {
      entryFuel
      entryFuelPositive := positive.1
      instructionFuel
      instructionFuelPositive := positive.2.1
      captureFuel
      captureFuelPositive := positive.2.2.1
      returnFuel
      returnFuelPositive := positive.2.2.2
    }
  else none

structure NativeX87ReplayFixedTemplateMixedReplay
    (pe : PE32) (imports : List PEImport) where
  entry : List (CheckedKernelMixedReplayInstruction pe imports)
  instruction : List (CheckedKernelMixedReplayInstruction pe imports)
  capture : List (CheckedKernelMixedReplayInstruction pe imports)
  returnPath : List (CheckedKernelMixedReplayInstruction pe imports)

/-- Bind every executable phase of the fixed replay bridge to exact candidate
PE bytes and checked mixed x86/x87 semantics.  This is the semantic authority
consumed by downstream bridge proofs; the legacy schedule above remains only a
compact fuel projection during migration. -/
def nativeX87ReplayFixedTemplateMixedReplay?
    (pe : PE32) (imports : List PEImport)
    (mapping : NativeX87ReplayBridgeFrameMapping) :
    Option (NativeX87ReplayFixedTemplateMixedReplay pe imports) := do
  let entry <- checkedKernelMixedReplaySpan? pe imports
    mapping.bridgeTargetRva nativeX87ReplayBridgeEntryScheduleSize
  let instruction <- checkedKernelMixedReplaySpan? pe imports
    mapping.instructionRva mapping.instructionPathBytes.length
  let capture <- checkedKernelMixedReplaySpan? pe imports
    (mapping.bridgeTargetRva + nativeX87ReplayBridgeCaptureOffset)
    nativeX87ReplayBridgeCaptureScheduleSize
  let returnPath <- checkedKernelMixedReplaySpan? pe imports
    mapping.returnRva 1
  if entry.isEmpty || instruction.isEmpty || capture.isEmpty ||
      returnPath.isEmpty then
    none
  else
    some { entry, instruction, capture, returnPath }

def nativeX87ReplayBridgeFixedTemplateChecked
    (table : NativeX87ReplayBridgeTable)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (mapping : NativeX87ReplayBridgeFrameMapping)
    (pe : PE32) : Bool :=
  bytesAt mapping.bridgeBodyBytes
      nativeX87ReplayBridgeTemplateEntryPrefix 0 &&
    bytesAt mapping.bridgeBodyBytes
      nativeX87ReplayBridgeTemplateEntryBody 9 &&
    bytesAt mapping.bridgeBodyBytes [0x9c, 0x50, 0xa1] 72 &&
    bytesAt mapping.bridgeBodyBytes
      nativeX87ReplayBridgeTemplateCaptureBody 79 &&
    readStructU32 mapping.bridgeBodyBytes
      nativeX87ReplayBridgeEntryActiveOperandOffset ==
        some (pe.imageBase + table.activeFramePointerRva) &&
    readStructU32 mapping.bridgeBodyBytes
      nativeX87ReplayBridgeCaptureActiveOperandOffset ==
        some (pe.imageBase + table.activeFramePointerRva) &&
    mapping.returnRva ==
      mapping.bridgeTargetRva + nativeX87ReplayBridgeReturnOffset &&
    mapping.instructionPathBytes.length ==
      descriptor.replay.instructionBytes.length

def nativeX87ReplayBridgeRuntimeChecked
    (table : NativeX87ReplayBridgeTable)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (mapping : NativeX87ReplayBridgeFrameMapping)
    (pe : PE32) (imports : List PEImport) : Bool :=
  nativeX87ReplayBridgeFixedTemplateChecked table descriptor mapping pe &&
    (nativeX87ReplayFixedTemplateSchedule? mapping).isSome &&
    (nativeX87ReplayFixedTemplateMixedReplay? pe imports mapping).isSome

structure ExactNativeX87ReplayRuntimeTarget
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)) where
  target : ExactNativeX87ReplayBridgeTargetBinding table pe imports relocations packs
  operand : NativeX87ReplayOperandBinding
  operandChecked :
    operand.checked target.descriptor target.frameMapping pe imports relocations = true
  layoutChecked :
    nativeX87ReplayBridgeRuntimeChecked table target.descriptor
      target.frameMapping pe imports = true

def NativeX87ReplayOperandBinding.dataAddressPairs
    (binding : NativeX87ReplayOperandBinding)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (pe : PE32) : List (Word × Word) :=
  match binding with
  | .none => []
  | .relocated operand => [(
      BitVec.ofNat 32 (descriptor.replay.imageBase + operand.targetRva),
      BitVec.ofNat 32 (pe.imageBase + operand.targetRva))]

def ExactNativeX87ReplayRuntimeTarget.addressMap
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) : NativeX87ReplayAddressMap := {
  originalImageBase := runtimeTarget.target.descriptor.replay.imageBase
  originalInstructionRva := runtimeTarget.target.descriptor.replay.rvaStart
  candidateImageBase := pe.imageBase
  candidateInstructionRva := runtimeTarget.target.frameMapping.instructionRva
  relocatedDataAddresses := runtimeTarget.operand.dataAddressPairs
    runtimeTarget.target.descriptor pe
}

/-- CPL3 `POPFD` may update ordinary status/control bits, preserves
non-writable privileged bits, preserves IF unless current IOPL is 3, and always
clears RF.  This executable source condition states exactly when loading the
logical EFLAGS word through the native bridge restores that same logical word.
The first conjunct is the reviewed instruction-semantic result; the remaining
conjuncts expose the architectural restrictions for diagnostics and downstream
source-frame construction. -/
def cpl3PopFlagsSourceFrameChecked
    (current : MachineState) (logicalEflags : Word) : Bool :=
  let restored :=
    (popFlagsCpl3Expression initialSymbolic.eflagsExpression
      (.constant logicalEflags.toNat)).eval current
  let privilegedMask := BitVec.ofNat 32 0xffdab02a
  let currentIopl :=
    (current.eflags >>> 12) &&& BitVec.ofNat 32 3
  restored == logicalEflags &&
    (logicalEflags &&& privilegedMask) ==
      (current.eflags &&& privilegedMask) &&
    (logicalEflags &&& BitVec.ofNat 32 0xfffcffff) == logicalEflags &&
    logicalEflags.extractLsb' 16 1 == BitVec.ofNat 1 0 &&
    (currentIopl == BitVec.ofNat 32 3 ||
      logicalEflags.extractLsb' 9 1 ==
        current.eflags.extractLsb' 9 1)

theorem cpl3PopFlagsSourceFrameChecked_restores
    (current : MachineState) (logicalEflags : Word)
    (checked : cpl3PopFlagsSourceFrameChecked current logicalEflags = true) :
    (popFlagsCpl3Expression initialSymbolic.eflagsExpression
      (.constant logicalEflags.toNat)).eval current = logicalEflags := by
  simp only [cpl3PopFlagsSourceFrameChecked, Bool.and_eq_true, beq_iff_eq] at checked
  exact checked.1.1.1.1

theorem cpl3PopFlagsSourceFrameChecked_privileged
    (current : MachineState) (logicalEflags : Word)
    (checked : cpl3PopFlagsSourceFrameChecked current logicalEflags = true) :
    logicalEflags &&& BitVec.ofNat 32 0xffdab02a =
      current.eflags &&& BitVec.ofNat 32 0xffdab02a := by
  simp only [cpl3PopFlagsSourceFrameChecked, Bool.and_eq_true, beq_iff_eq] at checked
  exact checked.1.1.1.2

theorem cpl3PopFlagsSourceFrameChecked_rf_clear
    (current : MachineState) (logicalEflags : Word)
    (checked : cpl3PopFlagsSourceFrameChecked current logicalEflags = true) :
    logicalEflags.extractLsb' 16 1 = BitVec.ofNat 1 0 := by
  simp only [cpl3PopFlagsSourceFrameChecked, Bool.and_eq_true, beq_iff_eq] at checked
  exact checked.1.2

theorem cpl3PopFlagsSourceFrameChecked_push_image
    (current : MachineState) (logicalEflags : Word)
    (checked : cpl3PopFlagsSourceFrameChecked current logicalEflags = true) :
    logicalEflags &&& BitVec.ofNat 32 0xfffcffff = logicalEflags := by
  simp only [cpl3PopFlagsSourceFrameChecked, Bool.and_eq_true, beq_iff_eq] at checked
  exact checked.1.1.2

theorem cpl3PopFlagsSourceFrameChecked_interrupt
    (current : MachineState) (logicalEflags : Word)
    (checked : cpl3PopFlagsSourceFrameChecked current logicalEflags = true) :
    (current.eflags >>> 12) &&& BitVec.ofNat 32 3 =
        BitVec.ofNat 32 3 ∨
      logicalEflags.extractLsb' 9 1 =
        current.eflags.extractLsb' 9 1 := by
  simp only [cpl3PopFlagsSourceFrameChecked, Bool.and_eq_true, beq_iff_eq,
    Bool.or_eq_true] at checked
  exact checked.2

structure ExactNativeX87ReplaySourceFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    extends NativeX87ReplayBridgeSourceFrameEvidence table originalPe pe
      runtimeTarget.target.descriptor runtimeTarget.addressMap caller logicalInput
    where
  candidateRegisters : candidateInput.registers = logicalInput.registers
  popFlagsCpl3 :
    cpl3PopFlagsSourceFrameChecked caller logicalInput.eflags = true
  replayScratchAddressValid :
    (logicalInput.registers.esp -
        BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes).toNat +
      nativeX87ReplayLogicalScratchBytes <= 2 ^ 32
  replayScratchDisjointFrame : CandidateFootprintsDisjoint
    (nativeX87ReplayLogicalScratchFootprint logicalInput)
    (nativeX87ReplayFrameFootprint frameAddress)
  replayScratchDisjointPrivateStack : CandidateFootprintsDisjoint
    (nativeX87ReplayLogicalScratchFootprint logicalInput)
    (nativeX87ReplayPrivateStackFootprint caller)
  replayScratchDisjointRepresentation :
    FootprintDisjointFromRepresentation rep
      (nativeX87ReplayLogicalScratchFootprint logicalInput)
  replayScratchDisjointOperand : CandidateFootprintsDisjoint
    (nativeX87ReplayLogicalScratchFootprint logicalInput)
    (nativeX87ReplayOperandFootprint commandInput.candidateDescriptor
      candidateInput)
  replayScratchDisjointImage : CandidateFootprintDisjointFromImage pe
    (nativeX87ReplayLogicalScratchFootprint logicalInput)

instance ExactNativeX87ReplaySourceFrame.instCoeSourceEvidence
    {table : NativeX87ReplayBridgeTable} {pe originalPe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List
      (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {caller logicalInput : MachineState} :
    Coe
      (ExactNativeX87ReplaySourceFrame runtimeTarget originalPe caller
        logicalInput)
      (NativeX87ReplayBridgeSourceFrameEvidence table originalPe pe
        runtimeTarget.target.descriptor runtimeTarget.addressMap caller
        logicalInput) where
  coe source := source.toNativeX87ReplayBridgeSourceFrameEvidence

def ExactNativeX87ReplaySourceFrameHolds
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState) : Prop :=
  Nonempty (ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
    caller logicalInput)

structure ExactNativeX87ReplayRuntimeInventory
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (imports : List PEImport) (relocations : List BaseRelocation)
    (packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)) where
  static : ExactNativeX87ReplayBridgeTargetInventory table pe imports relocations packs
  targets : List
    (ExactNativeX87ReplayRuntimeTarget table pe imports relocations packs)
  targetsExact : targets.map (·.target) = static.bindings
  relocatedOperandCount : Nat
  relocatedOperandsExact :
    targets.countP (fun target => target.operand.isRelocated) =
      relocatedOperandCount

/-- The generated semantic handler is fixed once for the complete checked
runtime inventory.  A report status or target-local handler cannot inhabit this
correspondence. -/
structure ExactNativeX87ReplayHandlerInventoryCorrespondence
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (originalPe : PE32) (handler : CandidateReplayHandler) : Prop where
  handlerExact : handler = reviewedExpectedCandidateReplay originalPe

theorem ExactNativeX87ReplayHandlerInventoryCorrespondence.execute
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {originalPe : PE32} {handler : CandidateReplayHandler}
    (correspondence : ExactNativeX87ReplayHandlerInventoryCorrespondence
      inventory originalPe handler)
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (_member : runtimeTarget ∈ inventory.targets)
    (state : MachineState) :
    handler runtimeTarget.target.descriptor.replay state =
      executeX87Singleton originalPe
        (replayInstructionRecord runtimeTarget.target.descriptor.replay) state := by
  rw [correspondence.handlerExact]
  rfl

theorem ExactNativeX87ReplayRuntimeInventory.targetForDescriptor
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (descriptor : NativeX87ReplayBridgeDescriptor)
    (member : descriptor ∈ table.descriptors) :
    ∃ runtimeTarget ∈ inventory.targets,
      runtimeTarget.target.descriptor = descriptor := by
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
  rw [← descriptorExact] at member
  rcases List.mem_map.mp member with
    ⟨runtimeTarget, runtimeMember, descriptorExact⟩
  exact ⟨runtimeTarget, runtimeMember, descriptorExact⟩

theorem ExactNativeX87ReplayRuntimeInventory.staticCertificateFor
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (_member : runtimeTarget ∈ inventory.targets) :
    ExactNativeX87ReplayBridgeStaticCertificate
      table pe imports relocations packs :=
  runtimeTarget.target.static

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
    nativeX87ReplayBridgeRuntimeChecked table runtimeTarget.target.descriptor
      runtimeTarget.target.frameMapping pe imports = true :=
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
  ⟨run.frameEffect.source.targetBefore, run.frameEffect.targetAfter⟩

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
  ⟨run.frameEffect.source.activeBefore, run.frameEffect.activeAfter⟩

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
  ⟨run.frameEffect.source.parentBefore, run.frameEffect.parentAfter⟩

theorem ExactNativeX87ReplayBridgeRun.privateStackEstablished
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    Memory.read32 run.returned.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) !=
      BitVec.ofNat 32 0 :=
  run.frameEffect.privateStackEstablished

theorem ExactNativeX87ReplayBridgeRun.x87FramesCorrespond
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    NativeX87ReplayEncodedFrame run.addresses run.logicalInput.x87Physical
        run.frameEffect.source.inputCandidate run.caller.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameInputX87Offset) ∧
      NativeX87ReplayEncodedFrame run.addresses
        run.result.state.x87Physical run.frameEffect.outputCandidate
        run.returned.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameOutputX87Offset) :=
  ⟨run.frameEffect.source.inputFrame, run.frameEffect.outputFrame⟩

theorem ExactNativeX87ReplayBridgeRun.mixedPostState
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    Nonempty (NativeX87ReplayMixedPostStateRelated table run.originalPe program.pe
      run.descriptor run.addresses run.caller run.returned run.logicalInput
      run.result) :=
  ⟨run.frameEffect.mixedPost⟩

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
    NativeX87ReplayEncodedFrame run.addresses run.logicalInput.x87Physical
        run.frameEffect.source.inputCandidate run.caller.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameInputX87Offset) ∧
      NativeX87ReplayEncodedFrame run.addresses
        run.result.state.x87Physical run.frameEffect.outputCandidate
        run.returned.memory
        (run.frameEffect.frameAddress +
          BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
  mixedPost :
    Nonempty (NativeX87ReplayMixedPostStateRelated table run.originalPe program.pe
      run.descriptor run.addresses run.caller run.returned run.logicalInput
      run.result)

theorem ExactNativeX87ReplayBridgeRun.runtimeClosure
    (run : ExactNativeX87ReplayBridgeRun program table handler) :
    ExactNativeX87ReplayBridgeRuntimeClosure run := {
  exactIndirectCall := run.exactCallStep
  eventFreeBridge := run.exactBridgePath
  eventFreeCallAndBridge := run.exactEventFreePath
  handlerExact := run.handlerResult
  returnShape := run.afterShape
  targetCell := ⟨run.frameEffect.source.targetBefore, run.frameEffect.targetAfter⟩
  activeFrame := ⟨run.frameEffect.source.activeBefore, run.frameEffect.activeAfter⟩
  parentFrame := ⟨run.frameEffect.source.parentBefore, run.frameEffect.parentAfter⟩
  privateStack := run.frameEffect.privateStackEstablished
  x87InputOutput :=
    ⟨run.frameEffect.source.inputFrame, run.frameEffect.outputFrame⟩
  mixedPost := ⟨run.frameEffect.mixedPost⟩
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
  originalPe : PE32
  result : StepResult
  handlerResult :
    handler runtimeTarget.target.descriptor.replay logicalInput = some result
  calleeEntry : MachineState
  instructionSlot : Nat
  instructionEntryState : MachineState
  captureSlot : Nat
  captureEntryState : MachineState
  returnSlot : Nat
  returnEntryState : MachineState
  returned : MachineState
  calls : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld
  externalFrames : List NativeWorldExternalCallbackRuntime
  sourceFrame : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
    caller logicalInput
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
    runtimeTarget.target.frameMapping.instructionRva instructionSlot
    instructionEntryState
    ({ continuationRva := table.continuationRva,
       returnAddress := BitVec.ofNat 32
         (program.pe.imageBase + table.continuationRva) } :: calls)
    eventIndex events world externalFrames
  entrySilent : entry.observations = []
  instruction : ExactComputedNestedNativeWorldSegment program
    (.running runtimeTarget.target.frameMapping.instructionRva instructionSlot
      instructionEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: calls)
      eventIndex events world externalFrames)
  instructionAtCapture : instruction.after = .running
    runtimeTarget.target.frameMapping.captureRva captureSlot captureEntryState
    ({ continuationRva := table.continuationRva,
       returnAddress := BitVec.ofNat 32
         (program.pe.imageBase + table.continuationRva) } :: calls)
    eventIndex events world externalFrames
  instructionSilent : instruction.observations = []
  capture : ExactComputedNestedNativeWorldSegment program
    (.running runtimeTarget.target.frameMapping.captureRva captureSlot
      captureEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: calls)
      eventIndex events world externalFrames)
  captureAtReturn : capture.after = .running
    runtimeTarget.target.frameMapping.returnRva returnSlot returnEntryState
    ({ continuationRva := table.continuationRva,
       returnAddress := BitVec.ofNat 32
         (program.pe.imageBase + table.continuationRva) } :: calls)
    eventIndex events world externalFrames
  captureSilent : capture.observations = []
  returnSegment : ExactComputedNestedNativeWorldSegment program
    (.running runtimeTarget.target.frameMapping.returnRva returnSlot
      returnEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: calls)
      eventIndex events world externalFrames)
  returnedAtContinuation : returnSegment.after = .running
    table.continuationRva 0 returned calls
    eventIndex events world externalFrames
  returnSilent : returnSegment.observations = []
  frameEffect : NativeX87ReplayNestedFrameEffect table originalPe program.pe
    runtimeTarget.target.descriptor runtimeTarget.addressMap caller returned
    logicalInput result

theorem ExactNativeX87ReplayBridgeKernelReduction.sourceTarget
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
    table.runtimeTargetHolds program.pe runtimeTarget.target.descriptor caller :=
  reduction.frameEffect.source.runtimeTargetHolds

theorem ExactNativeX87ReplayBridgeKernelReduction.mixedPostState
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
    Nonempty (NativeX87ReplayMixedPostStateRelated table reduction.originalPe
      program.pe runtimeTarget.target.descriptor runtimeTarget.addressMap caller
      reduction.returned logicalInput reduction.result) :=
  ⟨reduction.frameEffect.mixedPost⟩

structure ExactNativeX87ReplayBridgeTemplateRun
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler) where
  originalPe : PE32
  logicalInput : MachineState
  result : StepResult
  handlerResult :
    handler runtimeTarget.target.descriptor.replay logicalInput = some result
  caller : MachineState
  calleeEntry : MachineState
  instructionSlot : Nat
  instructionEntryState : MachineState
  captureSlot : Nat
  captureEntryState : MachineState
  returnSlot : Nat
  returnEntryState : MachineState
  returned : MachineState
  calls : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld
  externalFrames : List NativeWorldExternalCallbackRuntime
  sourceFrame : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
    caller logicalInput
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
      runtimeTarget.target.frameMapping.instructionRva instructionSlot
      instructionEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: calls)
      eventIndex events world externalFrames
  captureEntryShape : captureEntry = NestedNativeWorldExecution.running
    runtimeTarget.target.frameMapping.captureRva captureSlot captureEntryState
    ({ continuationRva := table.continuationRva,
       returnAddress := BitVec.ofNat 32
         (program.pe.imageBase + table.continuationRva) } :: calls)
    eventIndex events world externalFrames
  returnEntryShape : returnEntry = NestedNativeWorldExecution.running
    runtimeTarget.target.frameMapping.returnRva returnSlot returnEntryState
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
  frameEffect : NativeX87ReplayNestedFrameEffect table originalPe program.pe
    runtimeTarget.target.descriptor runtimeTarget.addressMap caller returned
    logicalInput result

theorem ExactNativeX87ReplayBridgeTemplateRun.sourceTarget
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {handler : CandidateReplayHandler}
    (run : ExactNativeX87ReplayBridgeTemplateRun
      runtimeTarget program handler) :
    table.runtimeTargetHolds program.pe runtimeTarget.target.descriptor run.caller :=
  run.frameEffect.source.runtimeTargetHolds

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
    originalPe := reduction.originalPe
    logicalInput := logicalInput
    result := reduction.result
    handlerResult := reduction.handlerResult
    caller := caller
    calleeEntry := reduction.calleeEntry
    instructionSlot := reduction.instructionSlot
    instructionEntryState := reduction.instructionEntryState
    captureSlot := reduction.captureSlot
    captureEntryState := reduction.captureEntryState
    returnSlot := reduction.returnSlot
    returnEntryState := reduction.returnEntryState
    returned := reduction.returned
    calls := reduction.calls
    eventIndex := reduction.eventIndex
    events := reduction.events
    world := reduction.world
    externalFrames := reduction.externalFrames
    sourceFrame := reduction.sourceFrame
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
      runtimeTarget.target.frameMapping.instructionRva reduction.instructionSlot
      reduction.instructionEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: reduction.calls)
      reduction.eventIndex reduction.events reduction.world
      reduction.externalFrames
    captureEntry := .running runtimeTarget.target.frameMapping.captureRva
      reduction.captureSlot
      reduction.captureEntryState
      ({ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) } :: reduction.calls)
      reduction.eventIndex reduction.events reduction.world
      reduction.externalFrames
    returnEntry := .running runtimeTarget.target.frameMapping.returnRva
      reduction.returnSlot
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
  originalPe := run.originalPe
  descriptor := runtimeTarget.target.descriptor
  addresses := runtimeTarget.addressMap
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
    (originalPe : PE32) (handler : CandidateReplayHandler) : Prop where
  reduce : ∀ runtimeTarget ∈ inventory.targets,
    ∀ caller logicalInput,
      ExactNativeX87ReplaySourceFrame runtimeTarget originalPe caller logicalInput ->
      Nonempty (ExactNativeX87ReplayBridgeKernelReduction
        runtimeTarget program handler caller logicalInput)

structure ExactNativeX87ReplayTemplateExecution
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (originalPe : PE32) (handler : CandidateReplayHandler) : Prop where
  programPeExact : program.pe = pe
  programImportsExact : program.imports = imports
  targetInventory : program.indirectTargets.targetSet?
    table.callInstruction.rva .call = some table.nativeTargetSet
  handlerInventory : ExactNativeX87ReplayHandlerInventoryCorrespondence
    inventory originalPe handler
  kernelExecution : ExactNativeX87ReplayBridgeKernelExecution
    inventory program originalPe handler

theorem ExactNativeX87ReplayTemplateExecution.runForTarget
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {originalPe : PE32}
    {handler : CandidateReplayHandler}
    (certificate : ExactNativeX87ReplayTemplateExecution inventory
      program originalPe handler)
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (member : runtimeTarget ∈ inventory.targets)
    (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
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

#print axioms ExactNativeX87ReplayRuntimeInventory.operandCheckedFor
#print axioms ExactNativeX87ReplayBridgeRun.callIsEventFree
#print axioms ExactNativeX87ReplayBridgeRun.targetCellPreserved
#print axioms ExactNativeX87ReplayBridgeRun.runtimeClosure
#print axioms ExactComputedNestedNativeWorldSegment.oneStepExact
#print axioms ExactNativeX87ReplayBridgeKernelReduction.toTemplateRun
#print axioms ExactNativeX87ReplayBridgeTemplateRun.bridgePath
#print axioms ExactNativeX87ReplayTemplateExecution.runForTarget

end StageA.Relational.InterpreterX87ReplayBridgeRuntime
